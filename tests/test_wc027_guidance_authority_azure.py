from __future__ import annotations

import pytest
from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError
from azure.data.tables import UpdateMode

from athena_context.contracts import GuidancePublicationRequestDeliveryBudget
from athena_context.guidance import GuidanceAuthorityActivationConflictError
from athena_context.guidance.azure import (
    AzureServiceBusGuidanceAuthorityTrigger,
    AzureTableGuidanceAuthorityActivationStore,
)
from test_wc027_guidance_authority_publisher import _publisher, _request

_DELIVERY_BUDGET = GuidancePublicationRequestDeliveryBudget.reviewed()


class _Entity(dict):
    def __init__(self, *args, etag: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.metadata = {"etag": etag}


class _Table:
    def __init__(self) -> None:
        self.entity = None
        self.create_conflict = False
        self.update_call = None

    def create_entity(self, *, entity):
        if self.create_conflict:
            raise ResourceExistsError("synthetic conflict")
        self.entity = _Entity(entity, etag='"etag-1"')
        return {"etag": '"etag-1"'}

    def update_entity(self, **kwargs):
        self.update_call = kwargs
        self.entity = _Entity(kwargs["entity"], etag='"etag-2"')
        return {"etag": '"etag-2"'}

    def get_entity(self, *, partition_key, row_key):
        assert partition_key == "wc027-guidance-authority"
        assert self.entity["RowKey"] == row_key
        return self.entity


class _Sender:
    def __init__(self) -> None:
        self.messages = []

    def send_messages(self, message) -> None:
        self.messages.append(message)


def _activation_and_binding():
    fixture, publisher, writer, _activation, trigger, _correlation, _incident = (
        _publisher()
    )
    request = _request(fixture)
    receipt = publisher.publish(request, now=request.evaluated_at)
    binding = trigger.calls[0][0]
    assert writer.payloads[receipt.binding_reference.name] == binding.canonical_bytes()
    return receipt.activation, binding


def _table_store(table: _Table) -> AzureTableGuidanceAuthorityActivationStore:
    store = object.__new__(AzureTableGuidanceAuthorityActivationStore)
    store._table = table
    store._partition_key = "wc027-guidance-authority"
    return store


def test_activation_table_create_read_and_etag_cas_are_exact() -> None:
    activation, _binding = _activation_and_binding()
    table = _Table()
    store = _table_store(table)

    created = store.compare_and_swap(activation, expected_etag=None)
    read = store.read_current(incident_id=activation.incident_id)
    updated = store.compare_and_swap(activation, expected_etag=created.etag)

    assert read == created
    assert updated.etag == '"etag-2"'
    assert table.update_call["mode"] is UpdateMode.REPLACE
    assert table.update_call["etag"] == '"etag-1"'
    assert table.update_call["match_condition"] is MatchConditions.IfNotModified


def test_activation_table_create_conflict_fails_closed() -> None:
    activation, _binding = _activation_and_binding()
    table = _Table()
    table.create_conflict = True
    store = _table_store(table)

    with pytest.raises(GuidanceAuthorityActivationConflictError):
        store.compare_and_swap(activation, expected_etag=None)


def test_binding_trigger_has_deterministic_identity_session_and_ttl() -> None:
    _activation, binding = _activation_and_binding()
    sender = _Sender()
    trigger = AzureServiceBusGuidanceAuthorityTrigger(sender)

    trigger.enqueue(
        binding,
        time_to_live_seconds=150,
        delivery_budget=_DELIVERY_BUDGET,
    )

    message = sender.messages[0]
    assert str(message.message_id) == binding.binding_id
    assert str(message.session_id) == (
        binding.incident_bound_request.incident_subject.incident_id
    )
    assert message.content_type == "application/json"
    assert int(message.time_to_live.total_seconds()) == 150
    assert message.application_properties["bindingDigest"] == binding.binding_digest
    for key, value in _DELIVERY_BUDGET.broker_properties().items():
        assert message.application_properties[key] == value


def test_binding_trigger_rejects_out_of_window_ttl_before_send() -> None:
    _activation, binding = _activation_and_binding()
    sender = _Sender()
    trigger = AzureServiceBusGuidanceAuthorityTrigger(sender)

    with pytest.raises(ValueError, match="TTL"):
        trigger.enqueue(
            binding,
            time_to_live_seconds=149,
            delivery_budget=_DELIVERY_BUDGET,
        )
    with pytest.raises(ValueError, match="TTL"):
        trigger.enqueue(
            binding,
            time_to_live_seconds=751,
            delivery_budget=_DELIVERY_BUDGET,
        )

    assert sender.messages == []
