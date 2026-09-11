from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from athena_context.contracts import (
    CorrelationReport,
    GuidanceAffectedRoleImpact,
    GuidanceLegality,
    GuidanceRunbookLink,
    GuidanceStep,
    GuidanceTemplateParameter,
    GuidanceTimelineEntry,
    IncidentGuidance,
    IncidentGuidanceAssetReference,
    IncidentGuidanceAttestation,
    IncidentGuidanceSourceBinding,
    PublishedGuidanceAuthorityBinding,
    VersionPinnedBlobReference,
    build_guidance_legality,
    build_incident_guidance_source_binding,
    compute_artifact_digest,
    project_guidance_hypotheses,
    sha256_hex,
    validate_incident_guidance_assets,
    validate_incident_guidance_binding,
)
from test_wc026_correlation import correlate_incident
from test_wc026_correlation_contract import _change_pair, _nsg_bundle, _request
from test_wc027_guidance_authority_contract import (
    _applicability,
    _authority,
    _binding,
    _option,
    _selected_runbook,
)

_BINDING_KEY_ID = (
    "https://synthetic-wc027.vault.azure.net/keys/guidance-binding/0123456789abcdef0123456789abcdef"
)
_GUIDANCE_KEY_ID = (
    "https://synthetic-wc027.vault.azure.net/keys/guidance-signing/0123456789abcdef0123456789abcdef"
)


def _verify_signature(_: bytes, signature: str) -> bool:
    return signature == "c3ludGhldGlj"


def _validate_guidance(
    guidance: IncidentGuidance,
    binding: PublishedGuidanceAuthorityBinding,
) -> None:
    validate_incident_guidance_binding(
        guidance,
        binding,
        trusted_binding_key_id=_BINDING_KEY_ID,
        binding_signature_verifier=_verify_signature,
    )


def _validate_assets(
    reference: IncidentGuidanceAssetReference,
    guidance: IncidentGuidance,
    attestation: IncidentGuidanceAttestation,
) -> None:
    validate_incident_guidance_assets(
        reference,
        guidance,
        attestation,
        trusted_guidance_key_id=_GUIDANCE_KEY_ID,
        guidance_signature_verifier=_verify_signature,
    )


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


def _timeline_entry(
    binding: PublishedGuidanceAuthorityBinding,
) -> GuidanceTimelineEntry:
    citation = (
        binding.incident_bound_request.correlation_request.incident_anchor.current_state_evidence[0]
    )
    payload: dict[str, object] = {
        "timelineKind": "healthTransition",
        "observedStart": citation.observed_start,
        "observedEnd": citation.observed_end,
        "summaryCode": citation.summary_code,
        "evidenceIds": (citation.evidence_id,),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return GuidanceTimelineEntry(
        **payload,
        entryId=f"guidance-timeline-{digest.removeprefix('sha256:')[:32]}",
        entryDigest=digest,
    )


def _step(
    *,
    action_kind: str,
    parameters: tuple[GuidanceTemplateParameter, ...] | None = None,
    evidence_ids: tuple[str, ...] = (),
    provenance_clause_ref: str | None = None,
    option_id: str | None = None,
) -> GuidanceStep:
    prescriptive = action_kind in {
        "manualResolutionOption",
        "rollbackConsideration",
    }
    payload: dict[str, object] = {
        "actionKind": action_kind,
        "templateCode": {
            "confirmationCheck": "confirmEffectiveRule",
            "investigationCheck": "inspectNetworkPath",
            "manualResolutionOption": "reviewApprovedManualOption",
            "rollbackConsideration": "reviewRollbackAuthority",
            "recoveryValidation": "validateRecoverySignals",
            "escalation": "escalateHumanReview",
        }[action_kind],
        "parameters": parameters or (),
        "evidenceIds": tuple(sorted(evidence_ids)),
        "provenanceClauseRef": provenance_clause_ref,
        "optionId": option_id,
        "readOnly": not prescriptive,
        "requiresAuthorization": prescriptive,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return GuidanceStep(
        **payload,
        stepId=f"guidance-step-{digest.removeprefix('sha256:')[:32]}",
        stepDigest=digest,
    )


def _runbook_link(
    option,
) -> GuidanceRunbookLink:
    payload: dict[str, object] = {
        "optionId": option.option_id,
        "optionDigest": option.option_digest,
        "runbookReference": option.runbook_reference,
        "labelCode": "approvedOperatorRunbook",
        "referenceOnly": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return GuidanceRunbookLink(
        **payload,
        linkId=f"guidance-link-{digest.removeprefix('sha256:')[:32]}",
        linkDigest=digest,
    )


def _top_only_report(report: CorrelationReport) -> CorrelationReport:
    payload = report.model_dump(
        mode="python",
        by_alias=True,
        exclude={"report_id", "report_digest"},
    )
    payload["hypotheses"] = (report.hypotheses[0],)
    digest = compute_artifact_digest(_json_value(payload))
    return CorrelationReport(
        **payload,
        reportId=f"report-{digest.removeprefix('sha256:')[:32]}",
        reportDigest=digest,
    )


def _guidance(
    binding: PublishedGuidanceAuthorityBinding,
    *,
    confirmation_checks: tuple[GuidanceStep, ...] | None = None,
    investigation_steps: tuple[GuidanceStep, ...] | None = None,
    safe_manual_options: tuple[GuidanceStep, ...] = (),
    rollback_considerations: tuple[GuidanceStep, ...] = (),
    recovery_validation: tuple[GuidanceStep, ...] = (),
    escalation: tuple[GuidanceStep, ...] | None = None,
    runbook_links: tuple[GuidanceRunbookLink, ...] = (),
    legality: GuidanceLegality | None = None,
) -> IncidentGuidance:
    request = binding.incident_bound_request.correlation_request
    current_id = request.incident_anchor.current_state_evidence[0].evidence_id
    selected_confirmation = confirmation_checks or (
        _step(
            action_kind="confirmationCheck",
            evidence_ids=(current_id,),
        ),
    )
    selected_investigation = investigation_steps or (
        _step(
            action_kind="investigationCheck",
            evidence_ids=(current_id,),
        ),
    )
    selected_escalation = escalation or (
        _step(
            action_kind="escalation",
        ),
    )
    selected_legality = legality or build_guidance_legality(binding)
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027IncidentGuidance.v1",
        "algorithmId": "athena.wc027.incident-guidance.v1",
        "generatedAt": binding.evaluated_at,
        "sourceBinding": build_incident_guidance_source_binding(binding),
        "affectedRoleImpact": GuidanceAffectedRoleImpact(
            roleRef=binding.selection.affected_role_ref,
            profileId=binding.guidance_authority.profile_id,
            impactSeverity="limited",
            impactCode="roleDegraded",
        ),
        "timeline": (_timeline_entry(binding),),
        "hypotheses": project_guidance_hypotheses(binding.correlation_report),
        "confirmationChecks": tuple(sorted(selected_confirmation, key=lambda item: item.step_id)),
        "investigationSteps": tuple(sorted(selected_investigation, key=lambda item: item.step_id)),
        "safeManualOptions": tuple(sorted(safe_manual_options, key=lambda item: item.step_id)),
        "rollbackConsiderations": tuple(
            sorted(rollback_considerations, key=lambda item: item.step_id)
        ),
        "recoveryValidation": tuple(sorted(recovery_validation, key=lambda item: item.step_id)),
        "escalation": tuple(sorted(selected_escalation, key=lambda item: item.step_id)),
        "runbookLinks": tuple(sorted(runbook_links, key=lambda item: item.link_id)),
        "missingEvidence": tuple(
            sorted(
                {item.code for item in binding.correlation_report.hypotheses[0].missing_evidence}
            )
        ),
        "legality": selected_legality,
        "noAutoRemediation": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return IncidentGuidance(
        **payload,
        guidanceId=f"incident-guidance-{digest.removeprefix('sha256:')[:32]}",
        guidanceDigest=digest,
    )


def _assets(
    binding: PublishedGuidanceAuthorityBinding,
    guidance: IncidentGuidance,
) -> tuple[IncidentGuidanceAttestation, IncidentGuidanceAssetReference]:
    attestation = IncidentGuidanceAttestation(
        schemaVersion="athena.wc027IncidentGuidanceAttestation.v1",
        guidanceId=guidance.guidance_id,
        guidanceDigest=guidance.guidance_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=(_GUIDANCE_KEY_ID),
        signedPreimageDigest=sha256_hex(guidance.canonical_bytes()),
        detachedSignature="c3ludGhldGlj",
    )
    subject = binding.incident_bound_request.incident_subject
    prefix = (
        f"incidents/{subject.incident_id}/versions/"
        f"{subject.incident_state_digest.removeprefix('sha256:')}/"
        f"guidance/{guidance.guidance_id}"
    )
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027IncidentGuidanceAssetReference.v1",
        "incidentId": subject.incident_id,
        "incidentStateDigest": subject.incident_state_digest,
        "guidanceId": guidance.guidance_id,
        "guidanceDigest": guidance.guidance_digest,
        "guidanceReference": VersionPinnedBlobReference(
            name=f"{prefix}/guidance.json",
            version="2026-09-10T02:00:00.0000000Z",
            contentDigest=sha256_hex(guidance.canonical_bytes()),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{prefix}/attestation.json",
            version="2026-09-10T02:00:00.0000000Z",
            contentDigest=sha256_hex(attestation.canonical_bytes()),
        ),
    }
    digest = compute_artifact_digest(_json_value(payload))
    reference = IncidentGuidanceAssetReference(
        **payload,
        referenceId=f"guidance-asset-{digest.removeprefix('sha256:')[:32]}",
        referenceDigest=digest,
    )
    return attestation, reference


def test_no_runbook_guidance_round_trip_and_asset_binding() -> None:
    binding = _binding()
    guidance = _guidance(binding)
    attestation, reference = _assets(binding, guidance)

    _validate_guidance(guidance, binding)
    _validate_assets(reference, guidance, attestation)
    assert IncidentGuidance.model_validate_json(guidance.model_dump_json(by_alias=True)) == guidance
    assert guidance.safe_manual_options == ()
    assert guidance.runbook_links == ()

    bad_binding_payload = binding.model_dump(
        mode="python",
        by_alias=True,
        exclude={"binding_id", "binding_digest"},
    )
    bad_binding_payload["bindingAttestation"] = binding.binding_attestation.model_copy(
        update={"detached_signature": "Zm9yZ2Vk"}
    )
    bad_binding_digest = compute_artifact_digest(_json_value(bad_binding_payload))
    bad_binding = PublishedGuidanceAuthorityBinding(
        **bad_binding_payload,
        bindingId=(f"guidance-binding-{bad_binding_digest.removeprefix('sha256:')[:32]}"),
        bindingDigest=bad_binding_digest,
    )
    with pytest.raises(ValueError, match="binding signature"):
        _validate_guidance(guidance, bad_binding)

    bad_attestation = attestation.model_copy(update={"detached_signature": "Zm9yZ2Vk"})
    with pytest.raises(ValueError, match="exact content"):
        _validate_assets(reference, guidance, bad_attestation)


def test_lower_confidence_guidance_cannot_include_manual_actions() -> None:
    option = _option()
    binding = _binding(
        authority=_authority(options=(option,)),
        selection=_selected_runbook(option),
    )
    manual = _step(
        action_kind="manualResolutionOption",
        option_id=option.option_id,
        provenance_clause_ref=option.provenance.clause_path,
    )

    with pytest.raises(ValidationError, match="read-only"):
        _guidance(
            binding,
            safe_manual_options=(manual,),
        )

    no_runbook_binding = _binding()
    wrong_legality = build_guidance_legality(no_runbook_binding).model_copy(
        update={"selection_kind": "selectedRunbook"}
    )
    with pytest.raises(ValidationError, match="source selection"):
        _guidance(no_runbook_binding, legality=wrong_legality)


def test_guidance_template_parameters_reject_command_text() -> None:
    with pytest.raises(ValidationError, match="parameter is invalid"):
        GuidanceTemplateParameter(
            parameterKind="roleRef",
            value="az network nsg rule delete --name synthetic",
        )
    with pytest.raises(ValidationError, match="parameter is invalid"):
        GuidanceTemplateParameter(
            parameterKind="evidenceId",
            value="obs-short",
        )


def test_guidance_binding_rejects_report_and_evidence_substitution() -> None:
    binding = _binding()
    guidance = _guidance(binding)
    payload = guidance.model_dump(mode="python", by_alias=True)
    source_payload = guidance.source_binding.model_dump(
        mode="python",
        by_alias=True,
        exclude={"source_id", "source_digest"},
    )
    source_payload["correlationReportDigest"] = "sha256:" + "f" * 64
    source_digest = compute_artifact_digest(_json_value(source_payload))
    payload["sourceBinding"] = IncidentGuidanceSourceBinding(
        **source_payload,
        sourceId=(f"guidance-source-{source_digest.removeprefix('sha256:')[:32]}"),
        sourceDigest=source_digest,
    )
    payload.pop("guidanceId")
    payload.pop("guidanceDigest")
    digest = compute_artifact_digest(_json_value(payload))
    mutated = IncidentGuidance(
        **payload,
        guidanceId=f"incident-guidance-{digest.removeprefix('sha256:')[:32]}",
        guidanceDigest=digest,
    )
    with pytest.raises(ValueError, match="source binding"):
        _validate_guidance(mutated, binding)

    unknown_step = _step(
        action_kind="investigationCheck",
        evidence_ids=("obs-" + "f" * 32,),
    )
    invalid = _guidance(binding, investigation_steps=(unknown_step,))
    with pytest.raises(ValueError, match="outside the request"):
        _validate_guidance(invalid, binding)

    entry = _timeline_entry(binding)
    entry_payload = entry.model_dump(
        mode="python",
        by_alias=True,
        exclude={"entry_id", "entry_digest"},
    )
    entry_payload["summaryCode"] = "synthetic.fabricated-timeline"
    entry_digest = compute_artifact_digest(_json_value(entry_payload))
    fabricated_entry = GuidanceTimelineEntry(
        **entry_payload,
        entryId=(f"guidance-timeline-{entry_digest.removeprefix('sha256:')[:32]}"),
        entryDigest=entry_digest,
    )
    fabricated = _guidance(binding)
    guidance_payload = fabricated.model_dump(
        mode="python",
        by_alias=True,
        exclude={"guidance_id", "guidance_digest"},
    )
    guidance_payload["timeline"] = (fabricated_entry,)
    guidance_digest = compute_artifact_digest(_json_value(guidance_payload))
    fabricated = IncidentGuidance(
        **guidance_payload,
        guidanceId=(f"incident-guidance-{guidance_digest.removeprefix('sha256:')[:32]}"),
        guidanceDigest=guidance_digest,
    )
    with pytest.raises(ValueError, match="timeline claim"):
        _validate_guidance(fabricated, binding)

    wrong_impact = _guidance(binding)
    impact_payload = wrong_impact.model_dump(
        mode="python",
        by_alias=True,
        exclude={"guidance_id", "guidance_digest"},
    )
    impact_payload["affectedRoleImpact"] = GuidanceAffectedRoleImpact(
        roleRef="web",
        profileId="production",
        impactSeverity="critical",
        impactCode="dataTierUnavailable",
    )
    impact_digest = compute_artifact_digest(_json_value(impact_payload))
    wrong_impact = IncidentGuidance(
        **impact_payload,
        guidanceId=(f"incident-guidance-{impact_digest.removeprefix('sha256:')[:32]}"),
        guidanceDigest=impact_digest,
    )
    with pytest.raises(ValueError, match="role impact"):
        _validate_guidance(wrong_impact, binding)

    duplicate = _guidance(binding)
    duplicate_payload = duplicate.model_dump(
        mode="python",
        by_alias=True,
        exclude={"guidance_id", "guidance_digest"},
    )
    duplicate_payload["timeline"] = (
        duplicate.timeline[0],
        duplicate.timeline[0],
    )
    duplicate_digest = compute_artifact_digest(_json_value(duplicate_payload))
    with pytest.raises(ValidationError, match="entry IDs"):
        IncidentGuidance(
            **duplicate_payload,
            guidanceId=(f"incident-guidance-{duplicate_digest.removeprefix('sha256:')[:32]}"),
            guidanceDigest=duplicate_digest,
        )


def test_confirmed_selected_runbook_allows_human_only_option() -> None:
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
    report = _top_only_report(correlate_incident(request))
    option = _option(
        applicability=_applicability(
            actions=("manualResolutionOption",),
            minimumConfidence="Confirmed",
        )
    )
    authority = _authority(request=request, options=(option,))
    selection = _selected_runbook(
        option,
        request=request,
        report=report,
        requested_actions=("manualResolutionOption",),
    )
    binding = _binding(
        request=request,
        report=report,
        authority=authority,
        selection=selection,
        requested_actions=("manualResolutionOption",),
    )
    manual = _step(
        action_kind="manualResolutionOption",
        option_id=option.option_id,
        provenance_clause_ref=option.provenance.clause_path,
    )
    link = _runbook_link(option)
    legality = build_guidance_legality(binding)
    guidance = _guidance(
        binding,
        safe_manual_options=(manual,),
        runbook_links=(link,),
        legality=legality,
    )

    _validate_guidance(guidance, binding)
    assert guidance.no_auto_remediation is True
    assert guidance.safe_manual_options[0].requires_authorization is True

    wrong_clause = _step(
        action_kind="manualResolutionOption",
        option_id=option.option_id,
        provenance_clause_ref="/controls/unrelated",
    )
    wrong = _guidance(
        binding,
        safe_manual_options=(wrong_clause,),
        runbook_links=(link,),
        legality=legality,
    )
    with pytest.raises(ValueError, match="manual option"):
        _validate_guidance(wrong, binding)

    wrong_path = _step(
        action_kind="manualResolutionOption",
        option_id=option.option_id,
        provenance_clause_ref=option.provenance.clause_path,
        parameters=(
            GuidanceTemplateParameter(
                parameterKind="pathId",
                value="path-" + "f" * 32,
            ),
        ),
    )
    wrong = _guidance(
        binding,
        safe_manual_options=(wrong_path,),
        runbook_links=(link,),
        legality=legality,
    )
    with pytest.raises(ValueError, match="outside the binding"):
        _validate_guidance(wrong, binding)

    wrong_legality = legality.model_copy(update={"rollback_authorized": True})
    wrong = _guidance(
        binding,
        safe_manual_options=(manual,),
        runbook_links=(link,),
        legality=wrong_legality,
    )
    with pytest.raises(ValueError, match="legality"):
        _validate_guidance(wrong, binding)


def test_guidance_byte_budget_is_enforced() -> None:
    binding = _binding()
    oversized = tuple(
        _step(
            action_kind="investigationCheck",
            parameters=tuple(
                sorted(
                    (
                        GuidanceTemplateParameter(
                            parameterKind="evidenceId",
                            value=f"obs-{index:032x}",
                        ),
                        GuidanceTemplateParameter(
                            parameterKind="pathId",
                            value=f"path-{index:032x}",
                        ),
                        GuidanceTemplateParameter(
                            parameterKind="resourceId",
                            value=(
                                "/subscriptions/"
                                "00000000-0000-0000-0000-000000000000/"
                                "resourcegroups/rg-synthetic-guidance/providers/"
                                "microsoft.compute/virtualmachines/" + "x" * 350 + f"{index:02d}"
                            ),
                        ),
                        GuidanceTemplateParameter(
                            parameterKind="roleRef",
                            value="web",
                        ),
                    ),
                    key=lambda item: (item.parameter_kind, item.value),
                )
            ),
        )
        for index in range(64)
    )

    with pytest.raises(ValidationError, match="byte budget"):
        _guidance(binding, investigation_steps=oversized)


def test_guidance_asset_reference_rejects_substitution() -> None:
    binding = _binding()
    guidance = _guidance(binding)
    attestation, reference = _assets(binding, guidance)
    payload = reference.model_dump(mode="python", by_alias=True)
    payload["guidanceReference"] = reference.guidance_reference.model_copy(
        update={"content_digest": "sha256:" + "f" * 64}
    )
    payload.pop("referenceId")
    payload.pop("referenceDigest")
    digest = compute_artifact_digest(_json_value(payload))
    mutated = IncidentGuidanceAssetReference(
        **payload,
        referenceId=f"guidance-asset-{digest.removeprefix('sha256:')[:32]}",
        referenceDigest=digest,
    )

    with pytest.raises(ValueError, match="exact content"):
        _validate_assets(mutated, guidance, attestation)
