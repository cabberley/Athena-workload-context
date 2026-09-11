from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from athena_context.contracts import (
    CorrelationRequest,
    IncidentBoundCorrelationRequest,
    IncidentBoundCorrelationRequestAttestation,
    IncidentCorrelationSubject,
    IncidentCorrelationSubjectAttestation,
    IncidentFinding,
    IncidentState,
    IncidentStateAttestation,
    VersionPinnedBlobReference,
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from test_wc026_correlation_contract import NOW, WEB_ID, _request


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items() if item is not None}
    return value


def _incident_state(
    *,
    affected_resource_id: str = WEB_ID,
    detected_at=None,
    updated_at=None,
    lifecycle: str = "active",
) -> tuple[IncidentState, IncidentStateAttestation]:
    selected_detected_at = detected_at or NOW - timedelta(minutes=5)
    selected_updated_at = updated_at or NOW - timedelta(minutes=4)
    incident_id = (
        "inc-"
        + sha256_hex(affected_resource_id.lower().encode("utf-8")).removeprefix("sha256:")[:12]
    )
    finding = IncidentFinding(
        clauseId="synthetic.wc027.health",
        verdict="fail",
        summary="Synthetic web role health transitioned to unhealthy.",
        evidenceRefs=("synthetic-evidence-ref",),
    )
    unsigned = {
        "schemaVersion": "athena.incidentState.v1",
        "incidentId": incident_id,
        "transitionId": "wc016-" + "1" * 64,
        "scenario": "webServerFailure",
        "lifecycle": lifecycle,
        "workloadRole": "web",
        "detectedAt": selected_detected_at,
        "updatedAt": selected_updated_at,
        "targetBinding": "sha256:" + "2" * 64,
        "availability": "warning" if lifecycle == "active" else "normal",
        "blastRadius": "web-tier" if lifecycle == "active" else "none",
        "operatorAttention": "required" if lifecycle == "active" else "normal",
        "findings": [finding.model_dump(mode="json", by_alias=True, exclude_none=True)],
        "reasoning": ["Synthetic health evidence requires operator review."],
        "notificationStatus": "pendingDispatch",
        "noAutoRemediation": True,
    }
    result_digest = sha256_hex(canonicalize_json(unsigned).encode("utf-8"))
    state_payload = {
        **unsigned,
        "findings": (finding,),
        "reasoning": ("Synthetic health evidence requires operator review.",),
    }
    state = IncidentState(
        **state_payload,
        resultDigest=result_digest,
    )
    attestation = IncidentStateAttestation(
        schemaVersion="athena.incidentStateAttestation.v1",
        resultDigest=result_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=(
            "https://synthetic-wc027.vault.azure.net/keys/"
            "incident-signing/0123456789abcdef0123456789abcdef"
        ),
        detachedSignature="c3ludGhldGlj",
    )
    return state, attestation


def _subject(
    *,
    revision: int = 1,
    affected_resource_id: str = WEB_ID,
    state: IncidentState | None = None,
    attestation: IncidentStateAttestation | None = None,
    state_name: str | None = None,
    state_content_digest: str | None = None,
    attestation_name: str | None = None,
    attestation_content_digest: str | None = None,
) -> IncidentCorrelationSubject:
    selected_state, selected_attestation = _incident_state(
        affected_resource_id=affected_resource_id
    )
    selected_state = state or selected_state
    selected_attestation = attestation or selected_attestation
    suffix = selected_state.result_digest.removeprefix("sha256:")
    prefix = f"incidents/{selected_state.incident_id}/versions/{suffix}"
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027IncidentCorrelationSubject.v1",
        "incidentId": selected_state.incident_id,
        "incidentTransitionId": selected_state.transition_id,
        "incidentRevision": revision,
        "affectedResourceId": affected_resource_id.lower(),
        "incidentState": selected_state,
        "incidentStateAttestation": selected_attestation,
        "incidentStateDigest": selected_state.result_digest,
        "stateReference": VersionPinnedBlobReference(
            name=state_name or f"{prefix}/state.json",
            version="2026-09-10T02:00:00.0000000Z",
            contentDigest=(state_content_digest or sha256_hex(selected_state.canonical_bytes())),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=attestation_name or f"{prefix}/attestation.json",
            version="2026-09-10T02:00:00.0000000Z",
            contentDigest=(
                attestation_content_digest or sha256_hex(selected_attestation.canonical_bytes())
            ),
        ),
    }
    subject_attestation = IncidentCorrelationSubjectAttestation(
        schemaVersion=("athena.wc027IncidentCorrelationSubjectAttestation.v1"),
        signatureAlgorithm="RS256",
        keyVaultKeyId=selected_attestation.key_vault_key_id,
        signedPreimageDigest=compute_artifact_digest(_json_value(payload)),
        detachedSignature="c3ludGhldGlj",
    )
    payload["subjectAttestation"] = subject_attestation
    digest = compute_artifact_digest(_json_value(payload))
    return IncidentCorrelationSubject(
        **payload,
        subjectId=(f"incident-subject-{digest.removeprefix('sha256:')[:32]}"),
        subjectDigest=digest,
    )


def _bound_request(
    *,
    subject: IncidentCorrelationSubject | None = None,
    correlation_request: CorrelationRequest | None = None,
) -> IncidentBoundCorrelationRequest:
    selected_subject = subject or _subject()
    selected_request = correlation_request or _request()
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027IncidentBoundCorrelationRequest.v1",
        "incidentSubject": selected_subject,
        "correlationRequest": selected_request,
        "correlationTransitionDigest": (selected_request.incident_anchor.transition_digest),
    }
    binding_attestation = IncidentBoundCorrelationRequestAttestation(
        schemaVersion=(
            "athena.wc027IncidentBoundCorrelationRequestAttestation.v1"
        ),
        signatureAlgorithm="RS256",
        keyVaultKeyId=(
            "https://synthetic-wc027.vault.azure.net/keys/"
            "correlation-binding/0123456789abcdef0123456789abcdef"
        ),
        signedPreimageDigest=compute_artifact_digest(_json_value(payload)),
        detachedSignature="c3ludGhldGlj",
    )
    payload["bindingAttestation"] = binding_attestation
    digest = compute_artifact_digest(_json_value(payload))
    return IncidentBoundCorrelationRequest(
        **payload,
        requestId=("incident-bound-request-" + digest.removeprefix("sha256:")[:32]),
        bindingDigest=digest,
    )


def _request_with_revision(
    request: CorrelationRequest,
    revision: int,
) -> CorrelationRequest:
    payload = request.model_dump(
        mode="python",
        by_alias=True,
        exclude={"request_id", "request_digest"},
    )
    payload["incidentRevision"] = revision
    digest = compute_artifact_digest(_json_value(payload))
    return CorrelationRequest(
        **payload,
        requestId=f"request-{digest.removeprefix('sha256:')[:32]}",
        requestDigest=digest,
    )


def test_incident_subject_and_binding_are_deterministic() -> None:
    subject = _subject()
    bound = _bound_request(subject=subject)

    assert (
        IncidentCorrelationSubject.model_validate_json(subject.model_dump_json(by_alias=True))
        == subject
    )
    assert (
        IncidentBoundCorrelationRequest.model_validate_json(bound.model_dump_json(by_alias=True))
        == bound
    )
    assert bound.correlation_request.schema_version == ("athena.wc026CorrelationRequest.v2")


@pytest.mark.parametrize(
    "override",
    [
        {"state_name": "incidents/inc-123456789abc/state.json"},
        {"attestation_name": "incidents/inc-123456789abc/attestation.json"},
        {"state_content_digest": "sha256:" + "a" * 64},
        {"attestation_content_digest": "sha256:" + "b" * 64},
    ],
)
def test_incident_subject_rejects_blob_substitution(
    override: dict[str, str],
) -> None:
    with pytest.raises(ValidationError, match="exact signed incident state"):
        _subject(**override)


def test_incident_subject_rejects_attestation_substitution() -> None:
    state, attestation = _incident_state()
    wrong = attestation.model_copy(update={"result_digest": "sha256:" + "f" * 64})

    with pytest.raises(ValidationError, match="exact signed incident state"):
        _subject(state=state, attestation=wrong)


def test_incident_subject_rejects_resource_and_state_cross_binding() -> None:
    state, attestation = _incident_state()
    other_resource = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/"
        "resourceGroups/rg-synthetic-wc027/providers/"
        "Microsoft.Compute/virtualMachines/synthetic-other-01"
    )

    with pytest.raises(ValidationError, match="exact signed incident state"):
        _subject(
            affected_resource_id=other_resource,
            state=state,
            attestation=attestation,
        )


def test_incident_subject_rejects_unsigned_occurrence_mutation() -> None:
    subject = _subject()
    payload = subject.model_dump(mode="python", by_alias=True)
    payload["incidentRevision"] = 2
    payload.pop("subjectId")
    payload.pop("subjectDigest")
    digest = compute_artifact_digest(_json_value(payload))

    with pytest.raises(ValidationError, match="exact signed incident state"):
        IncidentCorrelationSubject(
            **payload,
            subjectId=(f"incident-subject-{digest.removeprefix('sha256:')[:32]}"),
            subjectDigest=digest,
        )


@pytest.mark.parametrize(
    "subject",
    [
        _subject(revision=2),
        _subject(
            affected_resource_id=(
                "/subscriptions/00000000-0000-0000-0000-000000000000/"
                "resourceGroups/rg-synthetic-wc027/providers/"
                "Microsoft.Compute/virtualMachines/synthetic-other-01"
            )
        ),
    ],
)
def test_bound_request_rejects_incident_cross_binding(
    subject: IncidentCorrelationSubject,
) -> None:
    with pytest.raises(ValidationError, match="exact correlation request"):
        _bound_request(subject=subject)


def test_bound_request_rejects_future_incident_state() -> None:
    request = _request()
    state, attestation = _incident_state(
        updated_at=request.trusted_as_of + timedelta(milliseconds=1)
    )

    with pytest.raises(ValidationError, match="exact correlation request"):
        _bound_request(
            subject=_subject(state=state, attestation=attestation),
            correlation_request=request,
        )


def test_bound_request_rejects_stale_occurrence_and_lifecycle() -> None:
    request = _request()
    stale_state, stale_attestation = _incident_state(
        detected_at=request.incident_anchor.observed_start - timedelta(minutes=2),
        updated_at=request.incident_anchor.observed_start - timedelta(milliseconds=1),
    )
    with pytest.raises(ValidationError, match="exact correlation request"):
        _bound_request(
            subject=_subject(
                state=stale_state,
                attestation=stale_attestation,
            ),
            correlation_request=request,
        )

    resolved_state, resolved_attestation = _incident_state(lifecycle="resolved")
    with pytest.raises(ValidationError, match="exact correlation request"):
        _bound_request(
            subject=_subject(
                state=resolved_state,
                attestation=resolved_attestation,
            ),
            correlation_request=request,
        )


def test_bound_request_attestation_rejects_request_substitution() -> None:
    bound = _bound_request()
    payload = bound.model_dump(mode="python", by_alias=True)
    payload["correlationRequest"] = _request(binding_mode="draftPreview")
    payload.pop("requestId")
    payload.pop("bindingDigest")
    digest = compute_artifact_digest(_json_value(payload))

    with pytest.raises(ValidationError, match="exact correlation request"):
        IncidentBoundCorrelationRequest(
            **payload,
            requestId=(
                "incident-bound-request-"
                + digest.removeprefix("sha256:")[:32]
            ),
            bindingDigest=digest,
        )


def test_bound_request_attestation_rejects_revision_relabeling() -> None:
    bound = _bound_request()
    payload = bound.model_dump(mode="python", by_alias=True)
    payload["incidentSubject"] = _subject(revision=2)
    payload["correlationRequest"] = _request_with_revision(
        bound.correlation_request,
        2,
    )
    payload.pop("requestId")
    payload.pop("bindingDigest")
    digest = compute_artifact_digest(_json_value(payload))

    with pytest.raises(ValidationError, match="exact correlation request"):
        IncidentBoundCorrelationRequest(
            **payload,
            requestId=(
                "incident-bound-request-"
                + digest.removeprefix("sha256:")[:32]
            ),
            bindingDigest=digest,
        )


def test_bound_request_rejects_digest_id_and_extra_mutation() -> None:
    bound = _bound_request()
    payload = bound.model_dump(mode="python", by_alias=True)
    payload["bindingDigest"] = "sha256:" + "f" * 64
    with pytest.raises(ValidationError, match="bindingDigest"):
        IncidentBoundCorrelationRequest(**payload)

    payload = bound.model_dump(mode="python", by_alias=True)
    payload["requestId"] = "incident-bound-request-" + "f" * 32
    with pytest.raises(ValidationError, match="requestId"):
        IncidentBoundCorrelationRequest(**payload)

    payload = bound.model_dump(mode="python", by_alias=True)
    payload["correlationTransitionDigest"] = "sha256:" + "f" * 64
    payload.pop("requestId")
    payload.pop("bindingDigest")
    digest = compute_artifact_digest(_json_value(payload))
    with pytest.raises(ValidationError, match="exact correlation request"):
        IncidentBoundCorrelationRequest(
            **payload,
            requestId=("incident-bound-request-" + digest.removeprefix("sha256:")[:32]),
            bindingDigest=digest,
        )

    payload = bound.model_dump(mode="python", by_alias=True)
    payload["trusted"] = True
    with pytest.raises(ValidationError):
        IncidentBoundCorrelationRequest(**payload)
