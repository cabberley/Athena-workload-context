from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from athena_context.contracts import (
    GuidanceApplicability,
    GuidanceControlProvenance,
    HttpsGuidanceRunbookReference,
    NoRunbookGuidanceSelection,
    OpaqueGuidanceRunbookReference,
    PublishedGuidanceAuthority,
    PublishedGuidanceAuthorityBinding,
    PublishedGuidanceAuthorityBindingAttestation,
    PublishedRunbookGuidanceOption,
    SelectedRunbookGuidanceSelection,
    VersionPinnedBlobReference,
    compute_artifact_digest,
    sha256_hex,
)
from test_wc026_correlation import correlate_incident
from test_wc026_correlation_contract import (
    NOW,
    _change_pair,
    _hypothesis,
    _nsg_bundle,
    _report_for,
    _request,
)
from test_wc027_incident_subject_contract import _bound_request


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


def _applicability(
    **overrides: object,
) -> GuidanceApplicability:
    payload: dict[str, object] = {
        "causeCategories": ("networkSecurityChange",),
        "roleRefs": ("web",),
        "pathScope": "specificPaths",
        "pathIds": (_request().context_binding.dependency_paths[0].path_id,),
        "actions": ("investigationCheck",),
        "minimumConfidence": "Low",
    }
    payload.update(overrides)
    return GuidanceApplicability(**payload)


def _option(
    *,
    applicability: GuidanceApplicability | None = None,
    health: str = "effective",
    last_reviewed_at=None,
    expires_at=None,
    runbook_reference=None,
) -> PublishedRunbookGuidanceOption:
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027PublishedRunbookGuidanceOption.v2",
        "controlId": "synthetic-guidance-control",
        "provenance": GuidanceControlProvenance(
            manifestId="manifest-synthetic",
            manifestVersion="2026.09.10.1",
            profileId="production",
            clausePath="/controls/synthetic-guidance-control",
            ownerRef="synthetic-operator-owner",
        ),
        "applicability": applicability or _applicability(),
        "runbookReference": runbook_reference
        or HttpsGuidanceRunbookReference(
            referenceKind="https",
            uri="https://runbooks.invalid/synthetic/network-check",
            version="2026.09.11.1",
            contentDigest="sha256:" + "4" * 64,
        ),
        "controlHealth": health,
        "lastReviewedAt": last_reviewed_at or NOW - timedelta(days=1),
        "reviewExpiresAt": expires_at or NOW + timedelta(days=30),
        "executionAuthorizationRequired": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return PublishedRunbookGuidanceOption(
        **payload,
        optionId=f"guidance-option-{digest.removeprefix('sha256:')[:32]}",
        optionDigest=digest,
    )


def _authority(
    *,
    request=None,
    options: tuple[PublishedRunbookGuidanceOption, ...] = (),
    no_runbook_reasons=None,
) -> PublishedGuidanceAuthority:
    selected_request = request or _request()
    context = selected_request.context_binding
    selected_reasons = (
        ("noMatchingControl",)
        if no_runbook_reasons is None and not options
        else ()
        if no_runbook_reasons is None
        else no_runbook_reasons
    )
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027PublishedGuidanceAuthority.v2",
        "workloadId": context.workload_id,
        "manifestId": context.manifest_id,
        "manifestVersion": context.manifest_version,
        "manifestDigest": context.manifest_digest,
        "profileId": context.profile_id,
        "resolvedProfileDigest": context.resolved_profile_digest,
        "dependencyGraphDigest": context.dependency_graph_digest,
        "contextBindingDigest": context.binding_digest,
        "contextAuthority": context.publication_authority,
        "contextAuthorityReference": context.publication_authority_reference,
        "publicationRecordDigest": context.publication_authority.publication_record_digest,
        "auditHeadDigest": context.publication_authority.audit_head_digest,
        "publishedAt": context.publication_authority.published_at,
        "options": tuple(sorted(options, key=lambda item: item.option_id)),
        "noRunbookReasons": selected_reasons,
        "executionAuthorizationRequired": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return PublishedGuidanceAuthority(
        **payload,
        authorityId=f"guidance-authority-{digest.removeprefix('sha256:')[:32]}",
        authorityDigest=digest,
    )


def _no_runbook_selection(
    *,
    request=None,
    report=None,
    reason="noMatchingControl",
    requested_actions=("investigationCheck",),
) -> NoRunbookGuidanceSelection:
    selected_request = request or _request()
    selected_report = report or _report_for(
        selected_request,
        _hypothesis(citation=selected_request.evidence_index[0]),
    )
    hypothesis = selected_report.hypotheses[0]
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027GuidanceSelection.v2",
        "selectionKind": "noRunbook",
        "reason": reason,
        "affectedRoleRef": "web",
        "causeCategory": hypothesis.category,
        "affectedPathId": hypothesis.affected_path_id,
        "confidence": hypothesis.confidence,
        "requestedActions": requested_actions,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return NoRunbookGuidanceSelection(
        **payload,
        selectionId=f"guidance-selection-{digest.removeprefix('sha256:')[:32]}",
        selectionDigest=digest,
    )


def _selected_runbook(
    option: PublishedRunbookGuidanceOption,
    *,
    request=None,
    report=None,
    requested_actions=("investigationCheck",),
) -> SelectedRunbookGuidanceSelection:
    selected_request = request or _request()
    selected_report = report or _report_for(
        selected_request,
        _hypothesis(citation=selected_request.evidence_index[0]),
    )
    hypothesis = selected_report.hypotheses[0]
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027GuidanceSelection.v2",
        "selectionKind": "selectedRunbook",
        "optionId": option.option_id,
        "optionDigest": option.option_digest,
        "runbookReference": option.runbook_reference,
        "affectedRoleRef": "web",
        "causeCategory": hypothesis.category,
        "affectedPathId": hypothesis.affected_path_id,
        "confidence": hypothesis.confidence,
        "requestedActions": requested_actions,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return SelectedRunbookGuidanceSelection(
        **payload,
        selectionId=f"guidance-selection-{digest.removeprefix('sha256:')[:32]}",
        selectionDigest=digest,
    )


def _binding(
    *,
    request=None,
    report=None,
    authority: PublishedGuidanceAuthority | None = None,
    selection=None,
    requested_actions=("investigationCheck",),
    evaluated_at=None,
) -> PublishedGuidanceAuthorityBinding:
    selected_request = request or _request()
    selected_report = report or _report_for(
        selected_request,
        _hypothesis(citation=selected_request.evidence_index[0]),
    )
    selected_authority = authority or _authority(request=selected_request)
    selected_selection = selection or _no_runbook_selection(
        request=selected_request,
        report=selected_report,
    )
    authority_reference = VersionPinnedBlobReference(
        name=(f"guidance-authority/{selected_authority.authority_id}/authority.json"),
        version="2026-09-10T02:00:00.0000000Z",
        contentDigest=sha256_hex(selected_authority.canonical_bytes()),
    )
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027PublishedGuidanceAuthorityBinding.v2",
        "incidentBoundRequest": _bound_request(correlation_request=selected_request),
        "correlationReport": selected_report,
        "guidanceAuthority": selected_authority,
        "guidanceAuthorityReference": authority_reference,
        "requestedActions": requested_actions,
        "evaluatedAt": evaluated_at or selected_report.as_of,
        "selection": selected_selection,
    }
    attestation = PublishedGuidanceAuthorityBindingAttestation(
        schemaVersion=("athena.wc027PublishedGuidanceAuthorityBindingAttestation.v2"),
        signatureAlgorithm="RS256",
        keyVaultKeyId=(
            "https://synthetic-wc027.vault.azure.net/keys/"
            "guidance-binding/0123456789abcdef0123456789abcdef"
        ),
        signedPreimageDigest=compute_artifact_digest(_json_value(payload)),
        detachedSignature="c3ludGhldGlj",
    )
    payload["bindingAttestation"] = attestation
    digest = compute_artifact_digest(_json_value(payload))
    return PublishedGuidanceAuthorityBinding(
        **payload,
        bindingId=f"guidance-binding-{digest.removeprefix('sha256:')[:32]}",
        bindingDigest=digest,
    )


@pytest.mark.parametrize(
    "uri",
    [
        "http://runbooks.invalid/test",
        "https://user@runbooks.invalid/test",
        "https://runbooks.invalid/test?token=synthetic",
        "https://runbooks.invalid/test#fragment",
        "https://runbooks.invalid\\test",
        "https://runbooks.invalid/test path",
        "https://runbooks.invalid:99999/test",
    ],
)
def test_https_runbook_reference_rejects_unsafe_uri(uri: str) -> None:
    with pytest.raises(ValidationError, match="safe HTTPS"):
        HttpsGuidanceRunbookReference(
            referenceKind="https",
            uri=uri,
            version="2026.09.11.1",
            contentDigest="sha256:" + "4" * 64,
        )


def test_opaque_runbook_reference_requires_approved_scheme() -> None:
    assert OpaqueGuidanceRunbookReference(
        referenceKind="opaque",
        opaqueRef="urn:synthetic:runbook:network-check",
        version="2026.09.11.1",
        contentDigest="sha256:" + "5" * 64,
    )
    with pytest.raises(ValidationError, match="approved opaque"):
        OpaqueGuidanceRunbookReference(
            referenceKind="opaque",
            opaqueRef="https://runbooks.invalid/hidden",
            version="2026.09.11.1",
            contentDigest="sha256:" + "5" * 64,
        )
    with pytest.raises(ValidationError, match="approved opaque"):
        OpaqueGuidanceRunbookReference(
            referenceKind="opaque",
            opaqueRef="urn:",
            version="2026.09.11.1",
            contentDigest="sha256:" + "5" * 64,
        )


def test_applicability_fails_closed() -> None:
    with pytest.raises(ValidationError, match="specificPaths"):
        _applicability(pathIds=())
    with pytest.raises(ValidationError, match="prescriptive"):
        _applicability(
            actions=("manualResolutionOption",),
            minimumConfidence="Medium",
        )
    with pytest.raises(ValidationError, match="unknown causes"):
        _applicability(
            causeCategories=("unknown",),
            actions=("rollbackConsideration",),
            minimumConfidence="Confirmed",
        )
    with pytest.raises(ValidationError, match="roleRefs"):
        _applicability(roleRefs=("*",))
    with pytest.raises(ValidationError, match="pathIds"):
        _applicability(pathIds=("*",))


def test_option_and_zero_option_authority_are_deterministic() -> None:
    option = _option()
    authority = _authority(options=(option,))
    empty = _authority()

    assert authority.options == (option,)
    assert empty.options == ()
    assert (
        PublishedGuidanceAuthority.model_validate_json(authority.model_dump_json(by_alias=True))
        == authority
    )


def test_authority_requires_exact_publication_provenance() -> None:
    authority = _authority()
    payload = authority.model_dump(
        mode="python",
        by_alias=True,
        exclude={"authority_id", "authority_digest"},
    )
    payload["publicationRecordDigest"] = "sha256:" + "f" * 64
    digest = compute_artifact_digest(_json_value(payload))

    with pytest.raises(ValidationError, match="published context"):
        PublishedGuidanceAuthority(
            **payload,
            authorityId=(f"guidance-authority-{digest.removeprefix('sha256:')[:32]}"),
            authorityDigest=digest,
        )


def test_option_rejects_invalid_review_window() -> None:
    with pytest.raises(ValidationError, match="review expiry"):
        _option(expires_at=NOW - timedelta(days=2))
    with pytest.raises(ValidationError, match="published context"):
        _authority(options=(_option(last_reviewed_at=NOW + timedelta(minutes=1)),))


def test_no_runbook_binding_is_valid_and_strict() -> None:
    binding = _binding()

    assert isinstance(binding.selection, NoRunbookGuidanceSelection)
    assert (
        PublishedGuidanceAuthorityBinding.model_validate_json(
            binding.model_dump_json(by_alias=True)
        )
        == binding
    )

    payload = binding.model_dump(mode="python", by_alias=True)
    payload["guidanceAuthorityReference"] = VersionPinnedBlobReference(
        name="guidance-authority/wrong/authority.json",
        version=binding.guidance_authority_reference.version,
        contentDigest=binding.guidance_authority_reference.content_digest,
    )
    with pytest.raises(ValidationError, match="exact runtime inputs"):
        PublishedGuidanceAuthorityBinding(**payload)


def test_no_runbook_cannot_bypass_applicable_option() -> None:
    option = _option()
    authority = _authority(options=(option,))

    with pytest.raises(ValidationError, match="not justified"):
        _binding(authority=authority)


def test_no_runbook_reason_must_match_actual_failure() -> None:
    expired = _option(expires_at=NOW - timedelta(milliseconds=1))
    authority = _authority(options=(expired,))

    with pytest.raises(ValidationError, match="not justified"):
        _binding(authority=authority)


def test_selected_runbook_requires_effective_applicable_option() -> None:
    option = _option()
    authority = _authority(options=(option,))
    selected = _selected_runbook(option)
    binding = _binding(authority=authority, selection=selected)

    assert isinstance(binding.selection, SelectedRunbookGuidanceSelection)

    expired = _option(expires_at=NOW - timedelta(milliseconds=1))
    expired_authority = _authority(options=(expired,))
    with pytest.raises(ValidationError, match="selected runbook"):
        _binding(
            authority=expired_authority,
            selection=_selected_runbook(expired),
        )


def test_binding_rejects_backdated_or_expired_evaluation() -> None:
    request = _request()
    report = _report_for(
        request,
        _hypothesis(citation=request.evidence_index[0]),
    )
    with pytest.raises(ValidationError, match="must not precede"):
        _binding(
            request=request,
            report=report,
            evaluated_at=report.as_of - timedelta(milliseconds=1),
        )
    with pytest.raises(ValueError, match="outside its validity window"):
        _binding(
            request=request,
            report=report,
            evaluated_at=request.expires_at + timedelta(milliseconds=1),
        )


def test_prescriptive_guidance_rejects_material_competing_cause() -> None:
    artifact, handoff = _change_pair()
    bundle, _, _, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )
    report = correlate_incident(request)
    option = _option(
        applicability=_applicability(
            actions=("manualResolutionOption",),
            minimumConfidence="Confirmed",
        )
    )
    authority = _authority(request=request, options=(option,))
    selected = _selected_runbook(
        option,
        request=request,
        report=report,
        requested_actions=("manualResolutionOption",),
    )

    assert report.hypotheses[0].confidence == "Confirmed"
    assert any(item.confidence in {"Medium", "High", "Confirmed"} for item in report.hypotheses[1:])
    with pytest.raises(ValidationError, match="selected runbook"):
        _binding(
            request=request,
            report=report,
            authority=authority,
            selection=selected,
            requested_actions=("manualResolutionOption",),
        )

    no_runbook = _no_runbook_selection(
        request=request,
        report=report,
        reason="confidenceTooLow",
        requested_actions=("manualResolutionOption",),
    )
    binding = _binding(
        request=request,
        report=report,
        authority=authority,
        selection=no_runbook,
        requested_actions=("manualResolutionOption",),
    )
    assert isinstance(binding.selection, NoRunbookGuidanceSelection)


def test_draft_preview_report_cannot_bind_guidance_authority() -> None:
    request = _request(binding_mode="draftPreview")
    report = _report_for(
        request,
        _hypothesis(citation=request.evidence_index[0]),
    )

    with pytest.raises(ValueError, match="published runtime context"):
        _binding(
            request=request,
            report=report,
            authority=_authority(),
        )
