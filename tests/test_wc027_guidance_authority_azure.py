from __future__ import annotations

from datetime import timedelta

import pytest
from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError, ServiceResponseError
from azure.data.tables import UpdateMode

from athena_context.contracts import GuidancePublicationRequestDeliveryBudget
from athena_context.guidance import GuidanceAuthorityActivationConflictError
from athena_context.guidance.azure import (
    AzureServiceBusGuidanceAuthorityTrigger,
    AzureTableGuidanceAuthorityActivationStore,
)
from test_wc026_correlation_contract import NOW
from test_wc027_guidance_authority_publisher import (
    _legacy_activation,
    _publisher,
    _request,
)

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
        self.update_then_fail = False

    def create_entity(self, *, entity):
        if self.create_conflict:
            raise ResourceExistsError("synthetic conflict")
        self.entity = _Entity(entity, etag='"etag-1"')
        return {"etag": '"etag-1"'}

    def update_entity(self, **kwargs):
        self.update_call = kwargs
        self.entity = _Entity(kwargs["entity"], etag='"etag-2"')
        if self.update_then_fail:
            self.update_then_fail = False
            raise ServiceResponseError("synthetic uncertain update")
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


def _activation_and_binding(*, legacy_deadline: bool = False):
    (
        fixture,
        publisher,
        writer,
        _activation,
        trigger,
        _correlation,
        _incident,
    ) = _publisher(
        correlation_expires_at=(
            NOW + timedelta(minutes=10)
            if legacy_deadline
            else NOW + timedelta(minutes=15)
        )
    )
    request = _request(
        fixture,
        bound_effective_deadline=not legacy_deadline,
    )
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
    activation_update_call = table.update_call
    materialized = store.mark_feed_materialized(
        activation,
        expected_etag=updated.etag,
    )

    assert read == created
    assert updated.etag == '"etag-2"'
    assert updated.trigger_delivery_status == "pending"
    assert materialized.trigger_delivery_status == "materialized"
    assert activation_update_call["mode"] is UpdateMode.REPLACE
    assert activation_update_call["etag"] == '"etag-1"'
    assert activation_update_call["match_condition"] is MatchConditions.IfNotModified
    assert table.update_call["etag"] == '"etag-2"'
    assert table.entity["triggerDeliveryStatus"] == "materialized"


def test_activation_materialization_recovers_an_uncertain_committed_update() -> None:
    activation, _binding = _activation_and_binding()
    table = _Table()
    store = _table_store(table)
    created = store.compare_and_swap(activation, expected_etag=None)
    table.update_then_fail = True

    materialized = store.mark_feed_materialized(
        activation,
        expected_etag=created.etag,
    )

    assert materialized.activation == activation
    assert materialized.trigger_delivery_status == "materialized"
    assert table.entity["triggerDeliveryStatus"] == "materialized"


@pytest.mark.parametrize(
    ("extended", "stored_status"),
    ((False, None), (False, "submitted"), (True, "submitted")),
)
def test_published_legacy_activation_row_is_recovered_as_pending(
    extended: bool,
    stored_status: str | None,
) -> None:
    activation, binding = _activation_and_binding(legacy_deadline=True)
    activation = _legacy_activation(activation, extended=extended)
    table = _Table()
    store = _table_store(table)
    entity = {
        "PartitionKey": "wc027-guidance-authority",
        "RowKey": activation.incident_id,
        "activationDigest": activation.activation_digest,
        "payload": activation.canonical_bytes().decode("utf-8"),
    }
    if stored_status is not None:
        entity["triggerDeliveryStatus"] = stored_status
    table.entity = _Entity(entity, etag='"etag-legacy"')

    recovered = store.read_current(incident_id=activation.incident_id)

    assert recovered is not None
    assert recovered.activation == activation
    assert recovered.trigger_delivery_status == "pending"
    assert activation.has_extended_delivery_binding is extended
    if extended:
        assert (
            activation.delivery_finish_before
            > binding.incident_bound_request.correlation_request.expires_at
        )
    else:
        assert (
            activation.delivery_finish_before
            <= binding.incident_bound_request.correlation_request.expires_at
        )


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
        time_to_live_seconds=120,
        delivery_budget=_DELIVERY_BUDGET,
    )

    message = sender.messages[0]
    assert str(message.message_id) == binding.binding_id
    assert str(message.session_id) == (
        binding.incident_bound_request.incident_subject.incident_id
    )
    assert message.content_type == "application/json"
    assert int(message.time_to_live.total_seconds()) == 120
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
            time_to_live_seconds=119,
            delivery_budget=_DELIVERY_BUDGET,
        )
    with pytest.raises(ValueError, match="TTL"):
        trigger.enqueue(
            binding,
            time_to_live_seconds=721,
            delivery_budget=_DELIVERY_BUDGET,
        )

    assert sender.messages == []
