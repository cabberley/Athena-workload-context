from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import BaseModel, ValidationError

from athena_context.contracts import (
    GuidanceAuthorityPublicationRequest,
    GuidanceAuthorityPublicationRequestAttestation,
    PublishedGuidanceAuthorityActivation,
    VersionPinnedBlobReference,
    compute_artifact_digest,
)
from athena_context.guidance import (
    GuidanceAuthorityActivationConflictError,
    GuidanceAuthorityActivationSnapshot,
    GuidanceAuthorityPublisher,
    GuidanceAuthoritySourceNotReadyError,
)
from test_wc027_incident_enrichment_publication import (
    _SIGNATURE,
    _fixture,
    _Signer,
)

_REQUEST_KEY_ID = "synthetic-key://wc027/guidance-publication-request"
_BINDING_KEY_ID = "synthetic-key://wc027/guidance-authority-binding"
_INCIDENT_LOGICAL_KEY_ID = (
    "synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1"
)


def _json_value(value):
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _json_value(item)
            for key, item in value.items()
            if item is not None
        }
    return value


def _request(
    fixture,
    *,
    evaluated_at=None,
    lifetime: timedelta = timedelta(minutes=5),
) -> GuidanceAuthorityPublicationRequest:
    binding = fixture.guidance_binding
    correlation_request = binding.incident_bound_request.correlation_request
    evaluated_at = evaluated_at or binding.evaluated_at
    payload = {
        "schemaVersion": "athena.wc027GuidanceAuthorityPublicationRequest.v1",
        "incidentBoundRequest": binding.incident_bound_request,
        "incidentOccurrence": fixture.incident_publication.occurrence,
        "requestedActions": ("investigationCheck",),
        "evaluatedAt": evaluated_at,
        "expiresAt": min(
            evaluated_at + lifetime,
            correlation_request.expires_at,
        ),
    }
    attestation = GuidanceAuthorityPublicationRequestAttestation(
        schemaVersion=(
            "athena.wc027GuidanceAuthorityPublicationRequestAttestation.v1"
        ),
        signatureAlgorithm="RS256",
        keyId=_REQUEST_KEY_ID,
        signedPreimageDigest=compute_artifact_digest(_json_value(payload)),
        detachedSignature=_SIGNATURE,
    )
    complete = {**payload, "requestAttestation": attestation}
    digest = compute_artifact_digest(_json_value(complete))
    return GuidanceAuthorityPublicationRequest.model_validate(
        {
            **complete,
            "requestId": (
                f"guidance-publication-request-{digest.removeprefix('sha256:')[:32]}"
            ),
            "requestDigest": digest,
        }
    )


class _Correlation:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.calls = 0

    def correlate(self, request):
        self.calls += 1
        return self.delegate.correlate(request)

    def validate_result(self, result):
        return self.delegate.validate_result(result)


class _IncidentAuthority:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.calls = 0
        self.unavailable_after: int | None = None

    def read_current_incident_state(self, *, incident_id: str):
        self.calls += 1
        if self.unavailable_after is not None and self.calls > self.unavailable_after:
            return None
        return self.delegate.read_current_incident_state(incident_id=incident_id)

    def read_active_incident_index(self):
        self.calls += 1
        if self.unavailable_after is not None and self.calls > self.unavailable_after:
            return None
        return self.delegate.read_active_incident_index()


class _Writer:
    def __init__(self) -> None:
        self.calls = []
        self.payloads: dict[str, bytes] = {}
        self.references: dict[str, VersionPinnedBlobReference] = {}

    def create_or_recover(self, request):
        self.calls.append(request)
        previous = self.payloads.setdefault(request.blob_name, request.payload)
        if previous != request.payload:
            raise AssertionError("create-or-recover received different bytes")
        return self.references.setdefault(
            request.blob_name,
            VersionPinnedBlobReference(
                name=request.blob_name,
                version="synthetic-version-" + str(len(self.payloads)),
                contentDigest=request.hashes.payload_sha256,
            ),
        )


class _ActivationStore:
    def __init__(self) -> None:
        self.snapshot = None
        self.cas_calls = 0
        self.conflict = False

    def read_current(self, *, incident_id: str):
        if self.snapshot is not None:
            assert self.snapshot.activation.incident_id == incident_id
        return self.snapshot

    def compare_and_swap(self, activation, *, expected_etag):
        self.cas_calls += 1
        if self.conflict:
            raise GuidanceAuthorityActivationConflictError("synthetic conflict")
        if self.snapshot is not None:
            assert expected_etag == self.snapshot.etag
        else:
            assert expected_etag is None
        self.snapshot = GuidanceAuthorityActivationSnapshot(
            activation=activation,
            etag=f'"etag-{self.cas_calls}"',
        )
        return self.snapshot


class _Trigger:
    def __init__(self) -> None:
        self.calls = []

    def enqueue(self, binding, *, time_to_live_seconds: int) -> None:
        self.calls.append((binding, time_to_live_seconds))


def _publisher(*, verifier=None, incident_key_vault_key_id: str | None = None):
    fixture = _fixture()
    writer = _Writer()
    activation = _ActivationStore()
    trigger = _Trigger()
    correlation = _Correlation(fixture.correlation_service)
    incident = _IncidentAuthority(fixture.publication_reader)
    signature_verifier = verifier or (lambda _preimage, signature: signature == _SIGNATURE)
    publisher = GuidanceAuthorityPublisher(
        request_key_id=_REQUEST_KEY_ID,
        request_signature_verifier=signature_verifier,
        incident_key_id=_INCIDENT_LOGICAL_KEY_ID,
        incident_key_vault_key_id=incident_key_vault_key_id
        or (
            fixture.guidance_binding.incident_bound_request.incident_subject
            .incident_state_attestation.key_vault_key_id
        ),
        incident_signature_verifier=signature_verifier,
        correlation_binding_key_id=(
            fixture.guidance_binding.incident_bound_request.binding_attestation
            .key_vault_key_id
        ),
        correlation_binding_signature_verifier=signature_verifier,
        binding_key_id=_BINDING_KEY_ID,
        binding_signer=_Signer(),
        binding_signature_verifier=signature_verifier,
        correlation=correlation,
        incident_authority=incident,
        artifact_writer=writer,
        activation_store=activation,
        trigger=trigger,
    )
    return fixture, publisher, writer, activation, trigger, correlation, incident


def test_publisher_accepts_distinct_logical_and_physical_lifecycle_key_ids() -> None:
    fixture, publisher, writer, activation, trigger, _correlation, _incident = (
        _publisher()
    )
    request = _request(fixture)

    receipt = publisher.publish(request, now=request.evaluated_at)

    assert publisher.incident_key_id == _INCIDENT_LOGICAL_KEY_ID
    assert (
        publisher.incident_key_vault_key_id
        == request.incident_bound_request.incident_subject
        .incident_state_attestation.key_vault_key_id
    )
    assert receipt.binding_reference.name in writer.payloads
    assert activation.cas_calls == 1
    assert len(trigger.calls) == 1


def test_publisher_creates_signs_activates_and_enqueues_deterministically() -> None:
    fixture, publisher, writer, activation, trigger, correlation, incident = _publisher()
    request = _request(fixture)

    first = publisher.publish(request, now=request.evaluated_at)
    second = publisher.publish(request, now=request.evaluated_at)

    assert first.activation == second.activation
    assert first.replayed is False
    assert second.replayed is True
    assert activation.cas_calls == 1
    assert [item.blob_name for item in writer.calls] == [
        first.authority_reference.name,
        first.binding_reference.name,
        first.authority_reference.name,
        first.binding_reference.name,
    ]
    assert correlation.calls == 4
    assert incident.calls == 24
    assert [call[0].binding_id for call in trigger.calls] == [
        first.activation.binding_id,
        first.activation.binding_id,
    ]
    expected_ttl = int((request.expires_at - request.evaluated_at).total_seconds())
    assert [call[1] for call in trigger.calls] == [expected_ttl, expected_ttl]


def test_invalid_outer_signature_causes_zero_external_io() -> None:
    fixture, publisher, writer, activation, trigger, correlation, incident = _publisher(
        verifier=lambda _preimage, _signature: False
    )
    request = _request(fixture)

    with pytest.raises(ValueError, match="nested authority signature"):
        publisher.publish(request, now=request.evaluated_at)

    assert writer.calls == []
    assert activation.cas_calls == 0
    assert trigger.calls == []
    assert correlation.calls == 0
    assert incident.calls == 0


def test_mismatched_physical_lifecycle_key_causes_zero_external_io() -> None:
    fixture, publisher, writer, activation, trigger, correlation, incident = _publisher(
        incident_key_vault_key_id=(
            "https://athena-wc027.vault.azure.net/keys/"
            "different-lifecycle/00000000000000000000000000000000"
        )
    )
    request = _request(fixture)

    with pytest.raises(ValueError, match="nested authority signature"):
        publisher.publish(request, now=request.evaluated_at)

    assert writer.calls == []
    assert activation.cas_calls == 0
    assert trigger.calls == []
    assert correlation.calls == 0
    assert incident.calls == 0


def test_stale_request_causes_zero_external_io() -> None:
    fixture, publisher, writer, activation, trigger, correlation, incident = _publisher()
    request = _request(fixture)

    with pytest.raises(ValueError, match="stale"):
        publisher.publish(request, now=request.expires_at)

    assert writer.calls == []
    assert activation.cas_calls == 0
    assert trigger.calls == []
    assert correlation.calls == 0
    assert incident.calls == 0


def test_concurrent_activation_fails_closed_without_enqueue() -> None:
    fixture, publisher, _writer, activation, trigger, _correlation, _incident = _publisher()
    request = _request(fixture)
    activation.conflict = True

    with pytest.raises(GuidanceAuthorityActivationConflictError):
        publisher.publish(request, now=request.evaluated_at)

    assert trigger.calls == []


def test_source_change_before_activation_is_retryable_without_enqueue() -> None:
    fixture, publisher, _writer, activation, trigger, _correlation, incident = (
        _publisher()
    )
    request = _request(fixture)
    incident.unavailable_after = 4

    with pytest.raises(GuidanceAuthoritySourceNotReadyError):
        publisher.publish(request, now=request.evaluated_at)

    assert activation.cas_calls == 0
    assert trigger.calls == []


def test_expired_undelivered_activation_can_be_safely_replaced() -> None:
    fixture, publisher, _writer, activation, trigger, _correlation, _incident = (
        _publisher()
    )
    first_request = _request(fixture, lifetime=timedelta(seconds=1))
    first = publisher.publish(first_request, now=first_request.evaluated_at)
    fresh_request = _request(
        fixture,
        evaluated_at=first_request.expires_at,
        lifetime=timedelta(minutes=1),
    )

    second = publisher.publish(fresh_request, now=fresh_request.evaluated_at)

    assert second.activation != first.activation
    assert activation.cas_calls == 2
    assert len(trigger.calls) == 2


def test_request_is_strict_and_does_not_accept_caller_selected_outputs() -> None:
    fixture = _fixture()
    request = _request(fixture)
    payload = request.model_dump(mode="python", by_alias=True)
    payload["selectedRunbook"] = {"uri": "https://runbooks.invalid/unsafe"}

    with pytest.raises(ValidationError, match="Extra inputs"):
        GuidanceAuthorityPublicationRequest.model_validate(payload)


def test_request_expiry_cannot_outlive_nested_correlation_authority() -> None:
    fixture = _fixture()
    request = _request(fixture)
    payload = request.model_dump(
        mode="python",
        by_alias=True,
        exclude={"request_id", "request_digest", "request_attestation"},
    )
    payload["expiresAt"] = (
        request.incident_bound_request.correlation_request.expires_at
        + timedelta(milliseconds=1)
    )
    attestation = GuidanceAuthorityPublicationRequestAttestation(
        schemaVersion=(
            "athena.wc027GuidanceAuthorityPublicationRequestAttestation.v1"
        ),
        signatureAlgorithm="RS256",
        keyId=_REQUEST_KEY_ID,
        signedPreimageDigest=compute_artifact_digest(_json_value(payload)),
        detachedSignature=_SIGNATURE,
    )
    complete = {**payload, "requestAttestation": attestation}
    digest = compute_artifact_digest(_json_value(complete))

    with pytest.raises(ValidationError, match="bounded validity"):
        GuidanceAuthorityPublicationRequest.model_validate(
            {
                **complete,
                "requestId": (
                    "guidance-publication-request-"
                    f"{digest.removeprefix('sha256:')[:32]}"
                ),
                "requestDigest": digest,
            }
        )


def test_activation_model_rejects_non_binding_asset_path() -> None:
    fixture, publisher, _writer, _activation, _trigger, _correlation, _incident = (
        _publisher()
    )
    request = _request(fixture)
    receipt = publisher.publish(request, now=request.evaluated_at)
    payload = receipt.activation.model_dump(mode="python", by_alias=True)
    payload["bindingReference"] = VersionPinnedBlobReference(
        name="guidance-authority/wrong/authority.json",
        version=receipt.binding_reference.version,
        contentDigest=receipt.binding_reference.content_digest,
    )

    with pytest.raises(ValidationError, match="eligible binding"):
        PublishedGuidanceAuthorityActivation.model_validate(payload)
