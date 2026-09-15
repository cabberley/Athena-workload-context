from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

import athena_context.guidance.production as guidance_production
import athena_context.guidance.request_production as request_production
import athena_context.guidance.request_publication as request_publication
from athena_context.artifacts import ArtifactAlreadyExistsError
from athena_context.cli import build_parser
from athena_context.contracts import (
    GuidanceAuthorityPublicationRequest,
    IncidentBoundCorrelationRequest,
    PublishedRuntimeContextBinding,
    VersionPinnedBlobReference,
    sha256_hex,
)
from athena_context.guidance import (
    GuidanceAuthoritySourceNotReadyError,
    GuidancePublicationRequestDeliveryBudget,
    GuidancePublicationRequestProducer,
    guidance_publication_request_broker_properties,
    guidance_publication_request_outbox_path,
    parse_wc027_guidance_request_input,
    validate_guidance_publication_request_broker_metadata,
    validate_wc027_guidance_request_input_broker_metadata,
    verify_guidance_publication_request_outbox,
)
from athena_context.guidance.production import (
    Wc027GuidanceAuthorityPublisherConfiguration,
    run_wc027_guidance_authority_publisher_worker,
)
from athena_context.guidance.request_azure import (
    AzureServiceBusGuidancePublicationRequestSender,
)
from athena_context.guidance.request_production import (
    Wc027GuidancePublicationRequestProducerConfiguration,
    load_wc027_guidance_publication_request_producer_configuration,
    run_wc027_guidance_publication_request_producer_worker,
)
from test_wc026_correlation_contract import _request
from test_wc027_enrichment_feed_runtime import (
    _bicep_generated_publisher_configuration,
)
from test_wc027_incident_enrichment_publication import (
    _INCIDENT_LOGICAL_KEY_ID,
    _SIGNATURE,
    _fixture,
)
from test_wc027_incident_subject_contract import (
    _bound_request,
    _incident_state,
    _subject,
)

_REQUEST_KEY_ID = "synthetic-key://athena/wc027-guidance-request-rs256-v1"
_DELIVERY_BUDGET = GuidancePublicationRequestDeliveryBudget(
    publisher_keda_polling_interval_seconds=30,
    publisher_cold_start_seconds=30,
    publisher_connection_setup_seconds=30,
    publisher_processing_seconds=60,
    minimum_remaining_lifetime_seconds=150,
)


class _Signer:
    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def sign_preimage(self, preimage: bytes) -> str:
        self.calls.append(preimage)
        return _SIGNATURE


class _Verifier:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid
        self.calls: list[tuple[bytes, str]] = []

    def __call__(self, preimage: bytes, signature: str) -> bool:
        self.calls.append((preimage, signature))
        return self.valid and signature == _SIGNATURE


class _ContextAuthorityReader:
    def __init__(self, request: IncidentBoundCorrelationRequest) -> None:
        context = request.correlation_request.context_binding
        self.reference = (
            context.publication_authority_reference
            if isinstance(context, PublishedRuntimeContextBinding)
            else None
        )
        self.payload = (
            context.publication_authority.canonical_bytes()
            if isinstance(context, PublishedRuntimeContextBinding)
            else b"{}"
        )
        self.calls: list[VersionPinnedBlobReference] = []

    def read(self, reference: VersionPinnedBlobReference) -> bytes:
        self.calls.append(reference)
        assert self.reference is not None
        assert reference == self.reference
        return self.payload


class _IncidentAuthority:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.calls: list[str] = []
        self.unavailable_after: int | None = None

    def read_current_incident_state(self, *, incident_id: str):
        self.calls.append("current")
        if self.unavailable_after is not None and len(self.calls) > self.unavailable_after:
            return None
        return self.delegate.read_current_incident_state(incident_id=incident_id)

    def read_active_incident_index(self):
        self.calls.append("active")
        if self.unavailable_after is not None and len(self.calls) > self.unavailable_after:
            return None
        return self.delegate.read_active_incident_index()


class _Outbox:
    def __init__(self) -> None:
        self.calls = []
        self.payloads: dict[str, bytes] = {}
        self.references: dict[str, VersionPinnedBlobReference] = {}

    def create_or_recover(self, request):
        self.calls.append(request)
        previous = self.payloads.setdefault(request.blob_name, request.payload)
        if previous != request.payload:
            raise ArtifactAlreadyExistsError("synthetic occurrence slot conflict")
        return self.references.setdefault(
            request.blob_name,
            VersionPinnedBlobReference(
                name=request.blob_name,
                version="synthetic-outbox-version",
                contentDigest=request.hashes.payload_sha256,
            ),
        )


class _Sender:
    def __init__(
        self,
        *,
        fail_once_after_send: bool = False,
        on_open=None,
    ) -> None:
        self.calls = []
        self.open_calls = 0
        self.fail_once_after_send = fail_once_after_send
        self.on_open = on_open

    def open(self):
        self.open_calls += 1
        if self.on_open is not None:
            self.on_open()
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def enqueue(
        self,
        request,
        *,
        outbox_reference,
        time_to_live_seconds: int,
        delivery_budget,
    ) -> None:
        self.calls.append((request, outbox_reference, time_to_live_seconds, delivery_budget))
        if self.fail_once_after_send:
            self.fail_once_after_send = False
            raise RuntimeError("synthetic uncertain enqueue")


class _ServiceBusSender:
    def __init__(self) -> None:
        self.messages = []

    def send_messages(self, message) -> None:
        self.messages.append(message)


def _producer(
    *,
    request: IncidentBoundCorrelationRequest | None = None,
    incident_verifier: _Verifier | None = None,
    correlation_verifier: _Verifier | None = None,
    request_verifier: _Verifier | None = None,
    requested_actions=("investigationCheck",),
    incident_authority: _IncidentAuthority | None = None,
    context_reader: _ContextAuthorityReader | None = None,
    outbox: _Outbox | None = None,
    sender: _Sender | None = None,
    incident_key_vault_key_id: str | None = None,
    clock=None,
):
    fixture = _fixture()
    selected_request = request or fixture.guidance_binding.incident_bound_request
    selected_incident_authority = incident_authority or _IncidentAuthority(
        fixture.publication_reader
    )
    selected_context_reader = context_reader or _ContextAuthorityReader(selected_request)
    selected_outbox = outbox or _Outbox()
    selected_sender = sender or _Sender()
    signer = _Signer()
    request_signature_verifier = request_verifier or _Verifier()
    producer = GuidancePublicationRequestProducer(
        incident_key_id=_INCIDENT_LOGICAL_KEY_ID,
        incident_key_vault_key_id=(
            incident_key_vault_key_id
            or selected_request.incident_subject.incident_state_attestation.key_vault_key_id
        ),
        incident_signature_verifier=incident_verifier or _Verifier(),
        correlation_binding_key_id=(selected_request.binding_attestation.key_vault_key_id),
        correlation_binding_signature_verifier=(correlation_verifier or _Verifier()),
        request_key_id=_REQUEST_KEY_ID,
        request_signer=signer,
        request_signature_verifier=request_signature_verifier,
        incident_authority=selected_incident_authority,
        context_authority_reader=selected_context_reader,
        outbox=selected_outbox,
        sender=selected_sender,
        requested_actions=requested_actions,
        delivery_budget=_DELIVERY_BUDGET,
        clock=clock,
    )
    return (
        fixture,
        selected_request,
        producer,
        signer,
        request_signature_verifier,
        selected_incident_authority,
        selected_context_reader,
        selected_outbox,
        selected_sender,
    )


def _stable_evaluated_at(request, occurrence):
    context = request.correlation_request.context_binding
    assert isinstance(context, PublishedRuntimeContextBinding)
    return max(
        request.correlation_request.trusted_as_of,
        occurrence.published_at,
        context.publication_authority.published_at,
    )


def test_producer_builds_signs_persists_revalidates_and_enqueues_only_request() -> None:
    (
        fixture,
        request,
        producer,
        signer,
        request_verifier,
        incident_authority,
        context_reader,
        outbox,
        sender,
    ) = _producer()
    occurrence = fixture.incident_publication.occurrence
    evaluated_at = _stable_evaluated_at(request, occurrence)

    receipt = producer.produce(request, now=evaluated_at)

    publication_request = receipt.request
    assert publication_request.incident_bound_request == request
    assert publication_request.incident_occurrence == occurrence
    assert publication_request.evaluated_at == evaluated_at
    assert publication_request.expires_at == min(
        evaluated_at + timedelta(minutes=5),
        request.correlation_request.expires_at,
    )
    assert publication_request.requested_actions == ("investigationCheck",)
    assert publication_request.request_attestation.key_id == _REQUEST_KEY_ID
    assert len(signer.calls) == 1
    assert request_verifier.calls == [
        (
            signer.calls[0],
            publication_request.request_attestation.detached_signature,
        )
    ]
    assert incident_authority.calls == [
        "current",
        "active",
        "current",
        "active",
        "current",
        "active",
        "current",
        "active",
    ]
    assert len(context_reader.calls) == 2
    assert [item.blob_name for item in outbox.calls] == [
        guidance_publication_request_outbox_path(occurrence.occurrence_id)
    ]
    assert not any(
        "guidance-authority/" in item.blob_name or "guidance-bindings/" in item.blob_name
        for item in outbox.calls
    )
    assert len(sender.calls) == 1
    assert sender.open_calls == 1
    sent, sent_reference, ttl, delivery_budget = sender.calls[0]
    assert sent == publication_request
    assert sent_reference == receipt.outbox_reference
    assert delivery_budget == _DELIVERY_BUDGET
    assert ttl == int(
        (publication_request.expires_at - publication_request.evaluated_at).total_seconds()
    )


@pytest.mark.parametrize(
    "case",
    (
        "incident-signature",
        "correlation-signature",
        "incident-key",
        "draft",
        "stale",
    ),
)
def test_invalid_key_signature_draft_or_stale_input_has_zero_output_io(
    case: str,
) -> None:
    fixture = _fixture()
    base = fixture.guidance_binding.incident_bound_request
    kwargs = {}
    request = base
    now = _stable_evaluated_at(
        base,
        fixture.incident_publication.occurrence,
    )
    if case == "incident-signature":
        kwargs["incident_verifier"] = _Verifier(valid=False)
    elif case == "correlation-signature":
        kwargs["correlation_verifier"] = _Verifier(valid=False)
    elif case == "incident-key":
        kwargs["incident_key_vault_key_id"] = (
            "https://synthetic-wc027.vault.azure.net/keys/wrong/00000000000000000000000000000000"
        )
    elif case == "draft":
        draft = _request(binding_mode="draftPreview")
        request = _bound_request(
            subject=base.incident_subject,
            correlation_request=draft,
        )
        now = draft.trusted_as_of
    else:
        now = base.correlation_request.expires_at
    (
        _fixture_value,
        _request_value,
        producer,
        _signer,
        _request_verifier,
        _incident,
        _context,
        outbox,
        sender,
    ) = _producer(request=request, **kwargs)

    with pytest.raises(ValueError):
        producer.produce(request, now=now)

    assert outbox.calls == []
    assert sender.calls == []
    assert sender.open_calls == 0


def test_end_to_end_budget_below_minimum_has_zero_outbox_writes_and_sends() -> None:
    fixture = _fixture()
    request = fixture.guidance_binding.incident_bound_request
    evaluated_at = _stable_evaluated_at(
        request,
        fixture.incident_publication.occurrence,
    )
    expires_at = min(
        evaluated_at + timedelta(minutes=5),
        request.correlation_request.expires_at,
    )
    (
        _fixture_value,
        _request_value,
        producer,
        _signer,
        _request_verifier,
        _incident,
        _context,
        outbox,
        sender,
    ) = _producer(
        request=request,
        clock=lambda: expires_at - timedelta(seconds=149),
    )

    with pytest.raises(
        GuidanceAuthoritySourceNotReadyError,
        match="remaining lifetime required before persistence",
    ):
        producer.produce(request, now=evaluated_at)

    assert outbox.calls == []
    assert sender.calls == []


def test_end_to_end_budget_accepts_exact_minimum_before_persistence_and_send() -> None:
    fixture = _fixture()
    request = fixture.guidance_binding.incident_bound_request
    evaluated_at = _stable_evaluated_at(
        request,
        fixture.incident_publication.occurrence,
    )
    expires_at = min(
        evaluated_at + timedelta(minutes=5),
        request.correlation_request.expires_at,
    )
    operation_times = iter(
        (
            expires_at - timedelta(seconds=150),
            expires_at - timedelta(seconds=150),
        )
    )
    (
        _fixture_value,
        _request_value,
        producer,
        _signer,
        _request_verifier,
        _incident,
        _context,
        outbox,
        sender,
    ) = _producer(
        request=request,
        clock=lambda: next(operation_times),
    )

    receipt = producer.produce(request, now=evaluated_at)

    assert len(outbox.calls) == 1
    assert len(sender.calls) == 1
    assert sender.calls[0][0] == receipt.request
    assert sender.calls[0][2] == 150
    assert sender.calls[0][3] == _DELIVERY_BUDGET


def test_reviewed_delivery_budget_timeline_leaves_exact_processing_phase() -> None:
    expires_at = datetime(2026, 1, 1, 0, 5, tzinfo=UTC)
    enqueued_at = expires_at - _DELIVERY_BUDGET.minimum_remaining_lifetime
    after_keda_polling = enqueued_at + timedelta(
        seconds=_DELIVERY_BUDGET.publisher_keda_polling_interval_seconds
    )
    after_cold_start = after_keda_polling + timedelta(
        seconds=_DELIVERY_BUDGET.publisher_cold_start_seconds
    )
    after_connection_setup = after_cold_start + timedelta(
        seconds=_DELIVERY_BUDGET.publisher_connection_setup_seconds
    )

    assert expires_at - enqueued_at == timedelta(seconds=150)
    assert expires_at - after_connection_setup == (_DELIVERY_BUDGET.publisher_processing_budget)
    assert _DELIVERY_BUDGET.publisher_processing_budget == timedelta(seconds=60)


def test_end_to_end_budget_is_rechecked_immediately_before_enqueue() -> None:
    fixture = _fixture()
    request = fixture.guidance_binding.incident_bound_request
    evaluated_at = _stable_evaluated_at(
        request,
        fixture.incident_publication.occurrence,
    )
    expires_at = min(
        evaluated_at + timedelta(minutes=5),
        request.correlation_request.expires_at,
    )
    operation_times = iter(
        (
            expires_at - timedelta(seconds=150),
            expires_at - timedelta(seconds=149),
        )
    )
    events: list[str] = []
    selected_sender = _Sender(on_open=lambda: events.append("open"))

    def operation_clock():
        events.append("clock")
        return next(operation_times)

    (
        _fixture_value,
        _request_value,
        producer,
        _signer,
        _request_verifier,
        _incident,
        _context,
        outbox,
        sender,
    ) = _producer(
        request=request,
        sender=selected_sender,
        clock=operation_clock,
    )

    with pytest.raises(
        GuidanceAuthoritySourceNotReadyError,
        match="remaining lifetime required before enqueue",
    ):
        producer.produce(request, now=evaluated_at)

    assert len(outbox.calls) == 1
    assert sender.open_calls == 1
    assert sender.calls == []
    assert events == ["clock", "open", "clock"]


def test_current_occurrence_mismatch_has_zero_output_io() -> None:
    fixture = _fixture()
    base = fixture.guidance_binding.incident_bound_request
    state, attestation = _incident_state(
        updated_at=base.incident_subject.incident_state.updated_at - timedelta(seconds=1)
    )
    request = _bound_request(
        subject=_subject(state=state, attestation=attestation),
        correlation_request=base.correlation_request,
    )
    (
        _fixture_value,
        _request_value,
        producer,
        _signer,
        _request_verifier,
        _incident,
        _context,
        outbox,
        sender,
    ) = _producer(request=request)

    with pytest.raises(ValueError, match="current signed incident authority"):
        producer.produce(
            request,
            now=base.correlation_request.trusted_as_of,
        )

    assert outbox.calls == []
    assert sender.calls == []


def test_stable_lifecycle_index_incoherence_is_retryable() -> None:
    fixture = _fixture()
    index = fixture.publication_reader.active_index.index.model_copy(update={"incidents": ()})
    incoherent_index = type(fixture.publication_reader.active_index)(
        index=index,
        payload_sha256=sha256_hex(index.canonical_bytes()),
    )

    class _IncoherentAuthority:
        def read_current_incident_state(self, *, incident_id: str):
            return fixture.publication_reader.read_current_incident_state(incident_id=incident_id)

        def read_active_incident_index(self):
            return incoherent_index

    (
        _fixture_value,
        request,
        producer,
        _signer,
        _request_verifier,
        _incident,
        _context,
        outbox,
        sender,
    ) = _producer(incident_authority=_IncoherentAuthority())

    with pytest.raises(
        GuidanceAuthoritySourceNotReadyError,
        match="not coherent",
    ):
        producer.produce(
            request,
            now=_stable_evaluated_at(
                request,
                fixture.incident_publication.occurrence,
            ),
        )

    assert outbox.calls == []
    assert sender.calls == []


def test_context_authority_mismatch_has_zero_output_io() -> None:
    (
        fixture,
        request,
        producer,
        _signer,
        _request_verifier,
        _incident,
        context_reader,
        outbox,
        sender,
    ) = _producer()
    context_reader.payload = b"{}"

    with pytest.raises(ValueError, match="publication authority Blob bytes"):
        producer.produce(
            request,
            now=_stable_evaluated_at(
                request,
                fixture.incident_publication.occurrence,
            ),
        )

    assert outbox.calls == []
    assert sender.calls == []


def test_request_signer_must_verify_before_outbox_write() -> None:
    verifier = _Verifier(valid=False)
    (
        fixture,
        request,
        producer,
        signer,
        _request_verifier,
        _incident,
        _context,
        outbox,
        sender,
    ) = _producer(request_verifier=verifier)

    with pytest.raises(ValueError, match="failed immediate verification"):
        producer.produce(
            request,
            now=_stable_evaluated_at(
                request,
                fixture.incident_publication.occurrence,
            ),
        )

    assert len(signer.calls) == 1
    assert outbox.calls == []
    assert sender.calls == []


def test_oversized_request_is_rejected_before_signing_or_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        fixture,
        request,
        producer,
        signer,
        _verifier,
        _incident,
        _context,
        outbox,
        sender,
    ) = _producer()
    monkeypatch.setattr(
        request_publication,
        "MAX_GUIDANCE_AUTHORITY_PUBLICATION_REQUEST_BYTES",
        1,
    )

    with pytest.raises(ValueError, match="canonical bound"):
        producer.produce(
            request,
            now=_stable_evaluated_at(
                request,
                fixture.incident_publication.occurrence,
            ),
        )

    assert signer.calls == []
    assert outbox.calls == []
    assert sender.calls == []


def test_authority_is_revalidated_after_persistence_before_enqueue() -> None:
    fixture = _fixture()
    incident_authority = _IncidentAuthority(fixture.publication_reader)
    incident_authority.unavailable_after = 4
    (
        _fixture_value,
        request,
        producer,
        _signer,
        _request_verifier,
        _incident,
        _context,
        outbox,
        sender,
    ) = _producer(incident_authority=incident_authority)

    with pytest.raises(GuidanceAuthoritySourceNotReadyError):
        producer.produce(
            request,
            now=_stable_evaluated_at(
                request,
                fixture.incident_publication.occurrence,
            ),
        )

    assert len(outbox.calls) == 1
    assert sender.calls == []


def test_different_request_for_same_occurrence_conflicts_closed() -> None:
    shared_outbox = _Outbox()
    first_sender = _Sender()
    (
        fixture,
        request,
        first,
        _signer,
        _verifier,
        _incident,
        _context,
        _outbox,
        _sender,
    ) = _producer(outbox=shared_outbox, sender=first_sender)
    now = _stable_evaluated_at(
        request,
        fixture.incident_publication.occurrence,
    )
    first.produce(request, now=now)
    second_sender = _Sender()
    (
        _fixture_value,
        _request_value,
        second,
        _second_signer,
        _second_verifier,
        _second_incident,
        _second_context,
        _second_outbox,
        _second_sender,
    ) = _producer(
        request=request,
        outbox=shared_outbox,
        sender=second_sender,
        requested_actions=("confirmationCheck",),
    )

    with pytest.raises(ArtifactAlreadyExistsError):
        second.produce(request, now=now)

    assert len(first_sender.calls) == 1
    assert second_sender.calls == []
    assert len(shared_outbox.payloads) == 1


def test_uncertain_enqueue_retry_reuses_exact_request_and_outbox_identity() -> None:
    outbox = _Outbox()
    sender = _Sender(fail_once_after_send=True)
    (
        fixture,
        request,
        producer,
        _signer,
        _verifier,
        _incident,
        _context,
        _outbox,
        _sender,
    ) = _producer(outbox=outbox, sender=sender)
    now = _stable_evaluated_at(
        request,
        fixture.incident_publication.occurrence,
    )

    with pytest.raises(RuntimeError, match="uncertain"):
        producer.produce(request, now=now)
    recovered = producer.produce(request, now=now)

    assert len(outbox.calls) == 2
    assert outbox.calls[0].payload == outbox.calls[1].payload
    assert len(sender.calls) == 2
    assert sender.calls[0][0] == sender.calls[1][0] == recovered.request
    assert sender.calls[0][1] == sender.calls[1][1] == recovered.outbox_reference
    assert sender.calls[0][0].request_id == sender.calls[1][0].request_id


def test_exact_replay_and_concurrent_producers_converge_on_one_identity() -> None:
    shared_outbox = _Outbox()
    first_sender = _Sender()
    (
        fixture,
        request,
        first,
        _first_signer,
        _first_verifier,
        _first_incident,
        _first_context,
        _first_outbox,
        _first_sender,
    ) = _producer(outbox=shared_outbox, sender=first_sender)
    second_sender = _Sender()
    (
        _fixture_value,
        _request_value,
        second,
        _second_signer,
        _second_verifier,
        _second_incident,
        _second_context,
        _second_outbox,
        _second_sender,
    ) = _producer(
        request=request,
        outbox=shared_outbox,
        sender=second_sender,
    )
    now = _stable_evaluated_at(
        request,
        fixture.incident_publication.occurrence,
    )

    first_receipt = first.produce(request, now=now)
    second_receipt = second.produce(request, now=now)

    assert second_receipt == first_receipt
    assert shared_outbox.calls[0].payload == shared_outbox.calls[1].payload
    assert first_sender.calls[0][0] == second_sender.calls[0][0]
    assert first_sender.calls[0][0].request_id == (second_sender.calls[0][0].request_id)
    assert first_sender.calls[0][1] == second_sender.calls[0][1]


def test_broker_metadata_binds_request_occurrence_context_and_outbox() -> None:
    (
        fixture,
        request,
        producer,
        _signer,
        _verifier,
        _incident,
        _context,
        _outbox,
        _sender,
    ) = _producer()
    receipt = producer.produce(
        request,
        now=_stable_evaluated_at(
            request,
            fixture.incident_publication.occurrence,
        ),
    )
    raw_sender = _ServiceBusSender()
    adapter = AzureServiceBusGuidancePublicationRequestSender(raw_sender)

    adapter.enqueue(
        receipt.request,
        outbox_reference=receipt.outbox_reference,
        time_to_live_seconds=150,
        delivery_budget=_DELIVERY_BUDGET,
    )

    message = raw_sender.messages[0]
    assert str(message.message_id) == receipt.request.request_id
    assert str(message.session_id) == request.incident_subject.incident_id
    assert message.content_type == "application/json"
    assert int(message.time_to_live.total_seconds()) == 150
    assert message.application_properties == (
        guidance_publication_request_broker_properties(
            receipt.request,
            outbox_reference=receipt.outbox_reference,
            delivery_budget=_DELIVERY_BUDGET,
        )
    )
    assert (
        validate_guidance_publication_request_broker_metadata(
            message,
            receipt.request,
            expected_delivery_budget=_DELIVERY_BUDGET,
        )
        == receipt.outbox_reference
    )
    with pytest.raises(ValueError, match="delivery budget"):
        adapter.enqueue(
            receipt.request,
            outbox_reference=receipt.outbox_reference,
            time_to_live_seconds=149,
            delivery_budget=_DELIVERY_BUDGET,
        )
    assert len(raw_sender.messages) == 1
    valid_properties = dict(message.application_properties)
    message.application_properties["minimumRemainingLifetimeSeconds"] = 149
    with pytest.raises(ValueError, match="broker metadata"):
        validate_guidance_publication_request_broker_metadata(
            message,
            receipt.request,
            expected_delivery_budget=_DELIVERY_BUDGET,
        )
    message.application_properties = valid_properties

    class _OutboxReader:
        def __init__(self, payload: bytes) -> None:
            self.payload = payload
            self.calls = []

        def read(self, reference):
            self.calls.append(reference)
            return self.payload

    reader = _OutboxReader(receipt.request.canonical_bytes())
    verify_guidance_publication_request_outbox(
        receipt.request,
        outbox_reference=receipt.outbox_reference,
        outbox_reader=reader,
    )
    assert reader.calls == [receipt.outbox_reference]

    reader.payload = b"{}"
    with pytest.raises(ValueError, match="immutable outbox evidence"):
        verify_guidance_publication_request_outbox(
            receipt.request,
            outbox_reference=receipt.outbox_reference,
            outbox_reader=reader,
        )

    del message.application_properties["outboxBlobVersion"]
    with pytest.raises(ValueError, match="outbox version metadata"):
        validate_guidance_publication_request_broker_metadata(
            message,
            receipt.request,
            expected_delivery_budget=_DELIVERY_BUDGET,
        )


def test_input_parser_and_broker_metadata_are_exact() -> None:
    fixture = _fixture()
    request = fixture.guidance_binding.incident_bound_request
    payload = request.canonical_bytes()
    context = request.correlation_request.context_binding
    assert isinstance(context, PublishedRuntimeContextBinding)
    message = SimpleNamespace(
        content_type="application/json",
        message_id=request.request_id,
        session_id=request.incident_subject.incident_id,
        application_properties={
            "schemaVersion": ("athena.wc027IncidentBoundCorrelationRequest.v1"),
            "bindingDigest": request.binding_digest,
            "incidentSubjectDigest": request.incident_subject.subject_digest,
            "correlationRequestDigest": (request.correlation_request.request_digest),
            "contextAuthorityDigest": (context.publication_authority.authority_digest),
            "noAutoRemediation": True,
        },
    )

    assert parse_wc027_guidance_request_input(payload) == request
    validate_wc027_guidance_request_input_broker_metadata(message, request)
    with pytest.raises(ValueError, match="not canonical"):
        parse_wc027_guidance_request_input(payload + b"\n")
    message.application_properties["noAutoRemediation"] = False
    with pytest.raises(ValueError, match="broker metadata"):
        validate_wc027_guidance_request_input_broker_metadata(
            message,
            request,
        )


def _producer_configuration_payload() -> dict[str, object]:
    client_ids = [f"20000000-0000-0000-0000-{index:012d}" for index in range(9)]

    def identity_resource_id(index: int) -> str:
        return (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-athena-wc027/providers/Microsoft.ManagedIdentity/"
            f"userAssignedIdentities/wc027-guidance-request-{index}"
        )

    upstream_identity = {
        "identityClientId": client_ids[6],
        "identityResourceId": identity_resource_id(6),
    }
    incident_key_vault_id = (
        "https://athena-wc027.vault.azure.net/keys/incident/00000000000000000000000000000001"
    )
    correlation_key_vault_id = (
        "https://athena-wc027.vault.azure.net/keys/correlation/00000000000000000000000000000002"
    )
    request_key_vault_id = (
        "https://athena-wc027.vault.azure.net/keys/"
        "guidance-request/00000000000000000000000000000003"
    )
    return {
        "schemaVersion": ("athena.wc027GuidancePublicationRequestProducerConfiguration.v1"),
        "serviceBus": {
            "namespace": "athena-wc027.servicebus.windows.net",
            "inputQueueName": "wc027-guidance-publication-inputs",
            "outputQueueName": "wc027-guidance-authority-requests",
            "receiverIdentityClientId": client_ids[0],
            "receiverIdentityResourceId": identity_resource_id(0),
            "senderIdentityClientId": client_ids[1],
            "senderIdentityResourceId": identity_resource_id(1),
        },
        "incidentLifecycleAssets": {
            "blobEndpoint": "https://athenaincident.blob.core.windows.net",
            "containerName": "incident-assets",
            "identityClientId": client_ids[2],
            "identityResourceId": identity_resource_id(2),
        },
        "contextAuthoritySource": {
            "blobEndpoint": "https://athenacontext.blob.core.windows.net",
            "containerName": "context-authority",
            "identityClientId": client_ids[3],
            "identityResourceId": identity_resource_id(3),
        },
        "requestOutbox": {
            "blobEndpoint": "https://athenaoutbox.blob.core.windows.net",
            "containerName": "wc027-guidance-request-outbox",
            "readerIdentityClientId": client_ids[4],
            "readerIdentityResourceId": identity_resource_id(4),
            "writerIdentityClientId": client_ids[5],
            "writerIdentityResourceId": identity_resource_id(5),
        },
        "incidentKey": {
            "keyId": _INCIDENT_LOGICAL_KEY_ID,
            "keyVaultKeyId": incident_key_vault_id,
            "keyFingerprint": "sha256:" + "1" * 64,
            **upstream_identity,
        },
        "correlationBindingKey": {
            "keyId": correlation_key_vault_id,
            "keyVaultKeyId": correlation_key_vault_id,
            "keyFingerprint": "sha256:" + "2" * 64,
            **upstream_identity,
        },
        "requestSigningKey": {
            "keyId": _REQUEST_KEY_ID,
            "keyVaultKeyId": request_key_vault_id,
            "keyFingerprint": "sha256:" + "3" * 64,
            "signerIdentityClientId": client_ids[7],
            "signerIdentityResourceId": identity_resource_id(7),
            "verifierIdentityClientId": client_ids[8],
            "verifierIdentityResourceId": identity_resource_id(8),
        },
        "requestedActions": ["investigationCheck"],
        "deliveryBudget": {
            "publisherKedaPollingIntervalSeconds": 30,
            "publisherColdStartSeconds": 30,
            "publisherConnectionSetupSeconds": 30,
            "publisherProcessingSeconds": 60,
            "minimumRemainingLifetimeSeconds": 150,
        },
        "deploymentBinding": {
            "bindingEvidenceId": ("20000000-0000-0000-0000-000000000099"),
            "attachedIdentityResourceIds": [identity_resource_id(index) for index in range(9)],
            "rbacResourceIds": [
                "/subscriptions/00000000-0000-0000-0000-000000000000/"
                "providers/Microsoft.Authorization/roleDefinitions/"
                "20000000-0000-0000-0000-000000000098"
            ],
        },
    }


def test_production_configuration_is_strict_and_identity_separated() -> None:
    payload = _producer_configuration_payload()

    configuration = Wc027GuidancePublicationRequestProducerConfiguration.model_validate_json(
        json.dumps(payload)
    )

    assert configuration.receiver_identity_client_id != (configuration.sender_identity_client_id)
    assert configuration.request_signing_key.signer_identity_client_id != (
        configuration.request_signing_key.verifier_identity_client_id
    )
    assert configuration.incident_key.identity_client_id == (
        configuration.correlation_binding_key.identity_client_id
    )
    assert configuration.requested_actions == ("investigationCheck",)
    assert configuration.delivery_budget == _DELIVERY_BUDGET

    payload["unexpected"] = True
    with pytest.raises(ValueError, match="missing or unknown"):
        Wc027GuidancePublicationRequestProducerConfiguration.model_validate_json(
            json.dumps(payload)
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "io-reuse",
        "signer-verifier-reuse",
        "key-reuse",
        "physical-logical-key",
        "queue-drift",
        "delivery-budget",
    ),
)
def test_production_configuration_rejects_boundary_reuse(
    mutation: str,
) -> None:
    payload = _producer_configuration_payload()
    if mutation == "io-reuse":
        payload["serviceBus"]["senderIdentityClientId"] = payload[  # type: ignore[index]
            "serviceBus"
        ]["receiverIdentityClientId"]  # type: ignore[index]
        payload["serviceBus"]["senderIdentityResourceId"] = payload[  # type: ignore[index]
            "serviceBus"
        ]["receiverIdentityResourceId"]  # type: ignore[index]
    elif mutation == "signer-verifier-reuse":
        payload["requestSigningKey"]["verifierIdentityClientId"] = payload[  # type: ignore[index]
            "requestSigningKey"
        ]["signerIdentityClientId"]  # type: ignore[index]
        payload["requestSigningKey"]["verifierIdentityResourceId"] = payload[  # type: ignore[index]
            "requestSigningKey"
        ]["signerIdentityResourceId"]  # type: ignore[index]
    elif mutation == "key-reuse":
        payload["requestSigningKey"]["keyFingerprint"] = payload[  # type: ignore[index]
            "incidentKey"
        ]["keyFingerprint"]  # type: ignore[index]
    elif mutation == "physical-logical-key":
        payload["requestSigningKey"]["keyId"] = payload[  # type: ignore[index]
            "requestSigningKey"
        ]["keyVaultKeyId"]  # type: ignore[index]
    elif mutation == "delivery-budget":
        payload["deliveryBudget"]["minimumRemainingLifetimeSeconds"] = 149  # type: ignore[index]
    else:
        payload["serviceBus"]["outputQueueName"] = "other-output"  # type: ignore[index]

    with pytest.raises(ValueError):
        Wc027GuidancePublicationRequestProducerConfiguration.model_validate_json(
            json.dumps(payload)
        )


def test_publisher_configuration_cannot_be_loaded_as_request_producer() -> None:
    with pytest.raises(ValueError, match="missing or unknown"):
        load_wc027_guidance_publication_request_producer_configuration(
            path=None,
            environment_json=json.dumps(_bicep_generated_publisher_configuration()),
        )


def test_cli_exposes_only_the_production_request_worker_path() -> None:
    parser = build_parser()
    args = parser.parse_args(["wc027-guidance-publication-request-producer"])

    assert args.command == "wc027-guidance-publication-request-producer"
    with pytest.raises(SystemExit):
        parser.parse_args(["wc027-guidance-authority-submit"])


def test_request_body_digest_matches_outbox_evidence() -> None:
    (
        fixture,
        request,
        producer,
        _signer,
        _verifier,
        _incident,
        _context,
        _outbox,
        _sender,
    ) = _producer()
    receipt = producer.produce(
        request,
        now=_stable_evaluated_at(
            request,
            fixture.incident_publication.occurrence,
        ),
    )

    assert (
        GuidanceAuthorityPublicationRequest.model_validate_json(receipt.request.canonical_bytes())
        == receipt.request
    )
    assert receipt.outbox_reference.content_digest == sha256_hex(receipt.request.canonical_bytes())


def test_worker_abandons_budget_exhaustion_then_dead_letters_stale_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import azure.identity
    import azure.servicebus

    configuration = Wc027GuidancePublicationRequestProducerConfiguration.model_validate_json(
        json.dumps(_producer_configuration_payload())
    )
    fixture = _fixture()
    request = fixture.guidance_binding.incident_bound_request
    context = request.correlation_request.context_binding
    assert isinstance(context, PublishedRuntimeContextBinding)
    message = SimpleNamespace(
        body=request.canonical_bytes(),
        content_type="application/json",
        message_id=request.request_id,
        session_id=request.incident_subject.incident_id,
        application_properties={
            "schemaVersion": ("athena.wc027IncidentBoundCorrelationRequest.v1"),
            "bindingDigest": request.binding_digest,
            "incidentSubjectDigest": request.incident_subject.subject_digest,
            "correlationRequestDigest": (request.correlation_request.request_digest),
            "contextAuthorityDigest": (context.publication_authority.authority_digest),
            "noAutoRemediation": True,
        },
    )

    class _Credential:
        def __init__(self, *, client_id: str) -> None:
            self.client_id = client_id

    class _Receiver:
        def __init__(self) -> None:
            self.session = object()
            self.abandoned = []
            self.completed = []
            self.dead_lettered = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def receive_messages(self, **_kwargs):
            return [message]

        def abandon_message(self, selected) -> None:
            self.abandoned.append(selected)

        def complete_message(self, selected) -> None:
            self.completed.append(selected)

        def dead_letter_message(self, selected, **kwargs) -> None:
            self.dead_lettered.append((selected, kwargs))

    receiver = _Receiver()
    output_sender_opened = False

    class _Client:
        def __init__(self, *, credential, **_kwargs) -> None:
            self.credential = credential

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get_queue_receiver(self, **_kwargs):
            assert self.credential.client_id == configuration.receiver_identity_client_id
            return receiver

        def get_queue_sender(self, **_kwargs):
            nonlocal output_sender_opened
            output_sender_opened = True
            raise AssertionError("the output queue must not open before request production")

    class _LockRenewer:
        def __init__(self, **_kwargs) -> None:
            self.registered = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def register(self, *args, **kwargs) -> None:
            self.registered.append((args, kwargs))

    class _BudgetProducer:
        def __init__(self) -> None:
            self.calls = 0

        def produce(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                raise GuidanceAuthoritySourceNotReadyError(
                    "synthetic downstream remaining lifetime required"
                )
            raise ValueError("synthetic incident-bound correlation request is stale")

    budget_producer = _BudgetProducer()

    monkeypatch.setattr(
        azure.identity,
        "ManagedIdentityCredential",
        _Credential,
    )
    monkeypatch.setattr(azure.servicebus, "ServiceBusClient", _Client)
    monkeypatch.setattr(azure.servicebus, "AutoLockRenewer", _LockRenewer)
    monkeypatch.setattr(
        request_production,
        "build_wc027_guidance_publication_request_producer",
        lambda *_args, **_kwargs: budget_producer,
    )

    first_processed = run_wc027_guidance_publication_request_producer_worker(
        configuration=configuration,
        max_wait_time_seconds=1,
    )
    second_processed = run_wc027_guidance_publication_request_producer_worker(
        configuration=configuration,
        max_wait_time_seconds=1,
    )

    assert first_processed is False
    assert second_processed is False
    assert receiver.abandoned == [message]
    assert receiver.completed == []
    assert len(receiver.dead_lettered) == 1
    assert receiver.dead_lettered[0][0] is message
    assert receiver.dead_lettered[0][1]["reason"] == "AthenaWc027GuidanceRequestRejected"
    assert output_sender_opened is False


@pytest.mark.parametrize(
    (
        "metadata_mode",
        "outbox_payload",
        "remaining_seconds",
        "expected_outbox_reads",
        "should_complete",
    ),
    (
        ("missing", None, 300, 0, False),
        ("valid", b"{}", 300, 1, False),
        ("valid", None, 300, 1, True),
        ("valid", None, 60, 1, True),
        ("valid", None, 59, 0, False),
    ),
)
def test_publisher_worker_requires_exact_immutable_outbox_evidence(
    monkeypatch: pytest.MonkeyPatch,
    metadata_mode: str,
    outbox_payload: bytes | None,
    remaining_seconds: int,
    expected_outbox_reads: int,
    should_complete: bool,
) -> None:
    import azure.identity
    import azure.servicebus

    (
        fixture,
        incident_bound_request,
        producer,
        _signer,
        _request_verifier,
        _incident,
        _context,
        _outbox,
        _sender,
    ) = _producer()
    produced = producer.produce(
        incident_bound_request,
        now=_stable_evaluated_at(
            incident_bound_request,
            fixture.incident_publication.occurrence,
        ),
    )
    request = produced.request
    message = SimpleNamespace(
        body=(request.canonical_bytes(),),
        content_type="application/json",
        message_id=request.request_id,
        session_id=request.incident_bound_request.incident_subject.incident_id,
        application_properties=(
            guidance_publication_request_broker_properties(
                request,
                outbox_reference=produced.outbox_reference,
                delivery_budget=_DELIVERY_BUDGET,
            )
            if metadata_mode == "valid"
            else None
        ),
    )

    class _Credential:
        def __init__(self, *, client_id: str) -> None:
            self.client_id = client_id

    class _Receiver:
        def __init__(self) -> None:
            self.completed = []
            self.abandoned = []
            self.dead_lettered = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def receive_messages(self, **_kwargs):
            return [message]

        def complete_message(self, selected) -> None:
            self.completed.append(selected)

        def abandon_message(self, selected) -> None:
            self.abandoned.append(selected)

        def dead_letter_message(self, selected, **kwargs) -> None:
            self.dead_lettered.append((selected, kwargs))

    class _QueueSender:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    receiver = _Receiver()
    queue_sender = _QueueSender()

    class _Client:
        def __init__(self, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get_queue_receiver(self, **_kwargs):
            return receiver

        def get_queue_sender(self, **_kwargs):
            return queue_sender

    class _OutboxReader:
        def __init__(self) -> None:
            self.calls = []

        def read(self, reference):
            self.calls.append(reference)
            return request.canonical_bytes() if outbox_payload is None else outbox_payload

    class _Publisher:
        def __init__(self) -> None:
            self.calls = []

        def publish(self, selected, *, now) -> None:
            self.calls.append((selected, now))

    outbox_reader = _OutboxReader()
    publisher = _Publisher()
    events: list[str] = []
    parse_request = guidance_production.parse_guidance_authority_publication_request
    configuration = Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(
        json.dumps(_bicep_generated_publisher_configuration())
    )
    monkeypatch.setattr(
        azure.identity,
        "ManagedIdentityCredential",
        _Credential,
    )
    monkeypatch.setattr(azure.servicebus, "ServiceBusClient", _Client)
    monkeypatch.setattr(
        guidance_production,
        "_correlation_reader",
        lambda *_args, **_kwargs: outbox_reader,
    )
    monkeypatch.setattr(
        guidance_production,
        "build_wc027_guidance_authority_publisher",
        lambda *_args, **_kwargs: publisher,
    )
    monkeypatch.setattr(
        guidance_production,
        "parse_guidance_authority_publication_request",
        lambda payload: (events.append("parse"), parse_request(payload))[1],
    )
    clock_samples = iter((remaining_seconds, max(remaining_seconds - 1, 0)))

    def trusted_clock():
        events.append("clock")
        return request.expires_at - timedelta(seconds=next(clock_samples))

    monkeypatch.setattr(
        guidance_production,
        "_utc_now_milliseconds",
        trusted_clock,
    )

    processed = run_wc027_guidance_authority_publisher_worker(
        configuration=configuration,
        max_wait_time_seconds=1,
    )

    assert processed is should_complete
    if should_complete:
        assert receiver.completed == [message]
        assert receiver.dead_lettered == []
        assert len(publisher.calls) == 1
    else:
        assert receiver.completed == []
        assert len(receiver.dead_lettered) == 1
        assert publisher.calls == []
    assert len(outbox_reader.calls) == expected_outbox_reads
    assert events[:2] == ["clock", "parse"]


@pytest.mark.parametrize("failure_point", ("trigger", "completion"))
def test_publisher_worker_retries_service_bus_failure_without_duplicate_activation(
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    import azure.identity
    import azure.servicebus
    from azure.servicebus.exceptions import ServiceBusError

    (
        fixture,
        incident_bound_request,
        producer,
        _signer,
        _request_verifier,
        _incident,
        _context,
        _outbox,
        _sender,
    ) = _producer()
    produced = producer.produce(
        incident_bound_request,
        now=_stable_evaluated_at(
            incident_bound_request,
            fixture.incident_publication.occurrence,
        ),
    )
    request = produced.request
    message = SimpleNamespace(
        body=(request.canonical_bytes(),),
        content_type="application/json",
        message_id=request.request_id,
        session_id=request.incident_bound_request.incident_subject.incident_id,
        application_properties=guidance_publication_request_broker_properties(
            request,
            outbox_reference=produced.outbox_reference,
            delivery_budget=_DELIVERY_BUDGET,
        ),
        locked_until_utc=request.expires_at,
    )
    configuration = Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(
        json.dumps(_bicep_generated_publisher_configuration())
    )

    class _Credential:
        def __init__(self, *, client_id: str) -> None:
            self.client_id = client_id

    class _Receiver:
        def __init__(self) -> None:
            self.session = SimpleNamespace(locked_until_utc=request.expires_at)
            self.abandoned = []
            self.completed = []
            self.completion_attempts = 0
            self.dead_lettered = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def receive_messages(self, **_kwargs):
            return [message]

        def complete_message(self, selected) -> None:
            self.completion_attempts += 1
            if failure_point == "completion" and self.completion_attempts == 1:
                raise ServiceBusError("synthetic uncertain completion")
            self.completed.append(selected)

        def abandon_message(self, selected) -> None:
            self.abandoned.append(selected)

        def dead_letter_message(self, selected, **kwargs) -> None:
            self.dead_lettered.append((selected, kwargs))

    class _QueueSender:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    receiver = _Receiver()
    queue_sender = _QueueSender()

    class _Client:
        def __init__(self, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get_queue_receiver(self, **_kwargs):
            return receiver

        def get_queue_sender(self, **_kwargs):
            return queue_sender

    class _OutboxReader:
        def __init__(self) -> None:
            self.calls = []

        def read(self, reference):
            self.calls.append(reference)
            return request.canonical_bytes()

    class _ReplayPublisher:
        def __init__(self) -> None:
            self.calls = 0
            self.activation_ids: set[str] = set()

        def publish(self, selected, *, now) -> None:
            self.calls += 1
            self.activation_ids.add(selected.request_id)
            if failure_point == "trigger" and self.calls == 1:
                raise ServiceBusError("synthetic uncertain trigger send")

    outbox_reader = _OutboxReader()
    publisher = _ReplayPublisher()
    monkeypatch.setattr(azure.identity, "ManagedIdentityCredential", _Credential)
    monkeypatch.setattr(azure.servicebus, "ServiceBusClient", _Client)
    monkeypatch.setattr(
        guidance_production,
        "_correlation_reader",
        lambda *_args, **_kwargs: outbox_reader,
    )
    monkeypatch.setattr(
        guidance_production,
        "build_wc027_guidance_authority_publisher",
        lambda *_args, **_kwargs: publisher,
    )
    monkeypatch.setattr(
        guidance_production,
        "_utc_now_milliseconds",
        lambda: request.evaluated_at.astimezone(UTC),
    )

    first_processed = run_wc027_guidance_authority_publisher_worker(
        configuration=configuration,
        max_wait_time_seconds=1,
    )
    second_processed = run_wc027_guidance_authority_publisher_worker(
        configuration=configuration,
        max_wait_time_seconds=1,
    )

    assert first_processed is False
    assert second_processed is True
    assert receiver.abandoned == [message]
    assert receiver.completed == [message]
    assert receiver.dead_lettered == []
    assert publisher.calls == 2
    assert publisher.activation_ids == {request.request_id}
    assert outbox_reader.calls == [
        produced.outbox_reference,
        produced.outbox_reference,
    ]


def test_publisher_retry_does_not_abandon_an_expired_lock() -> None:
    abandoned = []
    lock_deadline = _fixture().guidance_binding.evaluated_at
    receiver = SimpleNamespace(
        session=SimpleNamespace(locked_until_utc=lock_deadline),
        abandon_message=lambda message: abandoned.append(message),
    )
    message = SimpleNamespace(locked_until_utc=lock_deadline)

    guidance_production._abandon_retryable_publisher_message(
        receiver,
        message,
        now=lock_deadline,
    )

    assert abandoned == []
