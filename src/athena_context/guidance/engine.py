from __future__ import annotations

from collections.abc import Iterable

from athena_context.contracts.common import compute_artifact_digest
from athena_context.contracts.correlation import CorrelationEvidenceCitation
from athena_context.contracts.guidance import (
    GuidanceActionKind,
    GuidanceRunbookLink,
    GuidanceStep,
    GuidanceTemplateCode,
    GuidanceTemplateParameter,
    GuidanceTimelineEntry,
    IncidentGuidance,
    NoRunbookGuidanceSelection,
    PublishedGuidanceAuthorityBinding,
    PublishedRunbookGuidanceOption,
    SelectedRunbookGuidanceSelection,
    build_guidance_affected_role_impact,
    build_guidance_legality,
    build_incident_guidance_source_binding,
    guidance_timeline_kind_for_evidence,
    project_guidance_hypotheses,
)

_CONFIRMATION_TEMPLATE: dict[str, GuidanceTemplateCode] = {
    "networkSecurityChange": "confirmEffectiveRule",
    "routingChange": "confirmEffectiveRule",
    "guestResourcePressure": "confirmBackendHealth",
    "guestServiceFailure": "confirmBackendHealth",
    "platformHealth": "confirmBackendHealth",
    "backendHealth": "confirmBackendHealth",
    "dependencyFailure": "confirmBackendHealth",
    "deploymentChange": "confirmBackendHealth",
    "unknown": "confirmBackendHealth",
}
_INVESTIGATION_TEMPLATES: dict[str, tuple[GuidanceTemplateCode, ...]] = {
    "networkSecurityChange": ("inspectNetworkPath", "inspectRecentChange"),
    "routingChange": ("inspectNetworkPath", "inspectRecentChange"),
    "guestResourcePressure": ("inspectGuestHealth",),
    "guestServiceFailure": ("inspectGuestHealth",),
    "platformHealth": ("inspectGuestHealth",),
    "backendHealth": ("inspectNetworkPath",),
    "dependencyFailure": ("inspectNetworkPath",),
    "deploymentChange": ("inspectRecentChange", "inspectGuestHealth"),
    "unknown": ("inspectGuestHealth",),
}
_MAX_STEP_EVIDENCE_IDS = 32


def build_incident_guidance(
    binding: PublishedGuidanceAuthorityBinding,
) -> IncidentGuidance:
    if type(binding) is not PublishedGuidanceAuthorityBinding:
        raise TypeError("binding must be an exact PublishedGuidanceAuthorityBinding")
    binding = PublishedGuidanceAuthorityBinding.model_validate_json(
        binding.model_dump_json(by_alias=True)
    )
    report = binding.correlation_report
    top = report.hypotheses[0]
    evidence_by_id = {
        item.evidence_id: item
        for item in binding.incident_bound_request.correlation_request.evidence_index
    }
    relevant_ids = _relevant_evidence_ids(binding)
    timeline = tuple(
        sorted(
            (_timeline_entry(binding, evidence_by_id[evidence_id]) for evidence_id in relevant_ids),
            key=lambda item: (item.observed_start, item.entry_id),
        )
    )
    if len(timeline) > 128:
        raise ValueError("incident guidance timeline exceeds its bound")

    confirmation = (
        _step(
            binding,
            action_kind="confirmationCheck",
            template_code=_CONFIRMATION_TEMPLATE[top.category],
            evidence_ids=_step_evidence_ids(binding),
        ),
    )
    investigation = tuple(
        _step(
            binding,
            action_kind="investigationCheck",
            template_code=template,
            evidence_ids=_step_evidence_ids(binding),
        )
        for template in _INVESTIGATION_TEMPLATES[top.category]
    )
    recovery_ids = _recovery_evidence_ids(binding)
    recovery = (
        (
            _step(
                binding,
                action_kind="recoveryValidation",
                template_code="validateRecoverySignals",
                evidence_ids=recovery_ids,
            ),
        )
        if recovery_ids
        else ()
    )
    legality = build_guidance_legality(binding)
    manual = (
        (
            _step(
                binding,
                action_kind="manualResolutionOption",
                template_code="reviewApprovedManualOption",
                option_id=_selected_option(binding).option_id,
                provenance_clause_ref=_selected_option(binding).provenance.clause_path,
            ),
        )
        if legality.manual_actions_authorized
        else ()
    )
    rollback = (
        (
            _step(
                binding,
                action_kind="rollbackConsideration",
                template_code="reviewRollbackAuthority",
                option_id=_selected_option(binding).option_id,
                provenance_clause_ref=_selected_option(binding).provenance.clause_path,
            ),
        )
        if legality.rollback_authorized
        else ()
    )
    runbook_links = (_runbook_link(binding),) if legality.runbook_reference_authorized else ()
    escalation_required = (
        isinstance(binding.selection, NoRunbookGuidanceSelection)
        or top.confidence in {"Unknown", "Low", "Medium"}
        or bool(top.missing_evidence)
        or "competingCause" in {item.code for item in top.contradictions}
        or any(item.confidence in {"Medium", "High", "Confirmed"} for item in report.hypotheses[1:])
    )
    escalation = (
        (
            _step(
                binding,
                action_kind="escalation",
                template_code="escalateHumanReview",
            ),
        )
        if escalation_required
        else ()
    )
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027IncidentGuidance.v1",
        "algorithmId": "athena.wc027.incident-guidance.v1",
        "generatedAt": binding.evaluated_at,
        "sourceBinding": build_incident_guidance_source_binding(binding),
        "affectedRoleImpact": build_guidance_affected_role_impact(binding),
        "timeline": timeline,
        "hypotheses": project_guidance_hypotheses(report),
        "confirmationChecks": _ordered_steps(confirmation),
        "investigationSteps": _ordered_steps(investigation),
        "safeManualOptions": _ordered_steps(manual),
        "rollbackConsiderations": _ordered_steps(rollback),
        "recoveryValidation": _ordered_steps(recovery),
        "escalation": _ordered_steps(escalation),
        "runbookLinks": tuple(sorted(runbook_links, key=lambda item: item.link_id)),
        "missingEvidence": tuple(
            sorted(
                {
                    item.code
                    for hypothesis in report.hypotheses
                    for item in hypothesis.missing_evidence
                }
            )
        ),
        "legality": legality,
        "noAutoRemediation": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return IncidentGuidance.model_validate(
        {
            **payload,
            "guidanceId": (f"incident-guidance-{digest.removeprefix('sha256:')[:32]}"),
            "guidanceDigest": digest,
        }
    )


def _json_value(value: object) -> object:
    if hasattr(value, "model_dump"):
        return value.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items() if item is not None}
    return value


def _relevant_evidence_ids(
    binding: PublishedGuidanceAuthorityBinding,
) -> tuple[str, ...]:
    request = binding.incident_bound_request.correlation_request
    report = binding.correlation_report
    coverage_ids = {item.coverage_id for item in request.monitoring_bundle.coverage}
    values = {
        item.evidence_id
        for item in (
            *request.incident_anchor.previous_state_evidence,
            *request.incident_anchor.current_state_evidence,
        )
    }
    values.update(
        item.evidence_id
        for hypothesis in report.hypotheses
        for item in hypothesis.supporting_evidence
        if item.evidence_id not in coverage_ids
    )
    values.update(_recovery_evidence_ids(binding))
    return tuple(sorted(values))


def _timeline_entry(
    binding: PublishedGuidanceAuthorityBinding,
    citation: CorrelationEvidenceCitation,
) -> GuidanceTimelineEntry:
    payload: dict[str, object] = {
        "timelineKind": guidance_timeline_kind_for_evidence(
            citation.evidence_id,
            binding,
        ),
        "observedStart": citation.observed_start,
        "observedEnd": citation.observed_end,
        "summaryCode": citation.summary_code,
        "evidenceIds": (citation.evidence_id,),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return GuidanceTimelineEntry.model_validate(
        {
            **payload,
            "entryId": (f"guidance-timeline-{digest.removeprefix('sha256:')[:32]}"),
            "entryDigest": digest,
        }
    )


def _step_evidence_ids(
    binding: PublishedGuidanceAuthorityBinding,
) -> tuple[str, ...]:
    request = binding.incident_bound_request.correlation_request
    top = binding.correlation_report.hypotheses[0]
    coverage_ids = {item.coverage_id for item in request.monitoring_bundle.coverage}
    values = {
        item.evidence_id for item in top.supporting_evidence if item.evidence_id not in coverage_ids
    }
    if not any(not _is_recovery_evidence(binding, evidence_id) for evidence_id in values):
        values.update(item.evidence_id for item in request.incident_anchor.current_state_evidence)
    ordered = tuple(sorted(values))
    if len(ordered) > _MAX_STEP_EVIDENCE_IDS:
        raise ValueError("guidance step evidence exceeds its bound")
    return ordered


def _is_recovery_evidence(
    binding: PublishedGuidanceAuthorityBinding,
    evidence_id: str,
) -> bool:
    request = binding.incident_bound_request.correlation_request
    state = binding.incident_bound_request.incident_subject.incident_state
    if state.lifecycle == "resolved" and evidence_id in {
        item.evidence_id for item in request.incident_anchor.current_state_evidence
    }:
        return True
    observation = next(
        (
            item
            for item in request.monitoring_bundle.observations
            if item.observation_id == evidence_id
        ),
        None,
    )
    return observation is not None and (
        getattr(observation, "state", None) == "recovered"
        or getattr(observation, "status", None) == "recovered"
    )


def _primary_evidence_id(
    binding: PublishedGuidanceAuthorityBinding,
    evidence_ids: tuple[str, ...],
    template_code: GuidanceTemplateCode,
) -> str | None:
    if not evidence_ids:
        return None
    citations = {
        item.evidence_id: item
        for item in binding.incident_bound_request.correlation_request.evidence_index
        if item.evidence_id in evidence_ids
    }
    if template_code == "validateRecoverySignals":
        recovery_ids = tuple(
            evidence_id
            for evidence_id in evidence_ids
            if _is_recovery_evidence(binding, evidence_id)
        )
        return max(
            recovery_ids or evidence_ids,
            key=lambda evidence_id: (
                citations[evidence_id].observed_end,
                citations[evidence_id].observed_start,
                evidence_id,
            ),
        )
    return min(
        evidence_ids,
        key=lambda evidence_id: (
            _is_recovery_evidence(binding, evidence_id),
            citations[evidence_id].observed_start,
            evidence_id,
        ),
    )


def _recovery_evidence_ids(
    binding: PublishedGuidanceAuthorityBinding,
) -> tuple[str, ...]:
    coverage_ids = {
        item.coverage_id
        for item in (binding.incident_bound_request.correlation_request.monitoring_bundle.coverage)
    }
    top = binding.correlation_report.hypotheses[0]
    values = tuple(
        sorted(
            {
                evidence_id
                for gate in top.gates
                if gate.code == "recoveryEvidence" and gate.satisfied
                for evidence_id in gate.evidence_ids
                if evidence_id not in coverage_ids
            }
        )
    )
    if len(values) > _MAX_STEP_EVIDENCE_IDS:
        raise ValueError("guidance recovery evidence exceeds its bound")
    return values


def _parameters(
    binding: PublishedGuidanceAuthorityBinding,
    template_code: GuidanceTemplateCode,
    evidence_ids: tuple[str, ...],
    option_id: str | None,
) -> tuple[GuidanceTemplateParameter, ...]:
    top = binding.correlation_report.hypotheses[0]
    values: list[GuidanceTemplateParameter] = []
    allowed = {
        "confirmEffectiveRule": {"resourceId", "pathId", "evidenceId"},
        "confirmBackendHealth": {"resourceId", "pathId", "evidenceId"},
        "inspectGuestHealth": {"resourceId", "evidenceId", "roleRef"},
        "inspectNetworkPath": {"resourceId", "pathId", "evidenceId", "roleRef"},
        "inspectRecentChange": {"resourceId", "evidenceId"},
        "reviewApprovedManualOption": {"optionId", "roleRef", "pathId"},
        "reviewRollbackAuthority": {"optionId", "roleRef"},
        "validateRecoverySignals": {"resourceId", "pathId", "evidenceId"},
        "escalateHumanReview": {"roleRef", "evidenceId"},
    }[template_code]
    if top.cause_resource_id is not None and "resourceId" in allowed:
        values.append(
            GuidanceTemplateParameter(
                parameterKind="resourceId",
                value=top.cause_resource_id,
            )
        )
    if top.affected_path_id is not None and "pathId" in allowed:
        values.append(
            GuidanceTemplateParameter(
                parameterKind="pathId",
                value=top.affected_path_id,
            )
        )
    primary_evidence_id = _primary_evidence_id(
        binding,
        evidence_ids,
        template_code,
    )
    if primary_evidence_id is not None and "evidenceId" in allowed:
        values.append(
            GuidanceTemplateParameter(
                parameterKind="evidenceId",
                value=primary_evidence_id,
            )
        )
    if "roleRef" in allowed:
        values.append(
            GuidanceTemplateParameter(
                parameterKind="roleRef",
                value=binding.selection.affected_role_ref,
            )
        )
    if option_id is not None and "optionId" in allowed:
        values.append(
            GuidanceTemplateParameter(
                parameterKind="optionId",
                value=option_id,
            )
        )
    return tuple(
        sorted(
            values,
            key=lambda item: (item.parameter_kind, item.value),
        )
    )


def _step(
    binding: PublishedGuidanceAuthorityBinding,
    *,
    action_kind: GuidanceActionKind,
    template_code: GuidanceTemplateCode,
    evidence_ids: tuple[str, ...] = (),
    option_id: str | None = None,
    provenance_clause_ref: str | None = None,
) -> GuidanceStep:
    payload: dict[str, object] = {
        "actionKind": action_kind,
        "templateCode": template_code,
        "parameters": _parameters(
            binding,
            template_code,
            evidence_ids,
            option_id,
        ),
        "evidenceIds": tuple(sorted(evidence_ids)),
        "provenanceClauseRef": provenance_clause_ref,
        "optionId": option_id,
        "readOnly": action_kind not in {"manualResolutionOption", "rollbackConsideration"},
        "requiresAuthorization": action_kind in {"manualResolutionOption", "rollbackConsideration"},
    }
    digest = compute_artifact_digest(_json_value(payload))
    return GuidanceStep.model_validate(
        {
            **payload,
            "stepId": (f"guidance-step-{digest.removeprefix('sha256:')[:32]}"),
            "stepDigest": digest,
        }
    )


def _selected_option(
    binding: PublishedGuidanceAuthorityBinding,
) -> PublishedRunbookGuidanceOption:
    if not isinstance(
        binding.selection,
        SelectedRunbookGuidanceSelection,
    ):
        raise ValueError("guidance binding does not select a runbook")
    return next(
        item
        for item in binding.guidance_authority.options
        if item.option_id == binding.selection.option_id
    )


def _runbook_link(
    binding: PublishedGuidanceAuthorityBinding,
) -> GuidanceRunbookLink:
    option = _selected_option(binding)
    payload: dict[str, object] = {
        "optionId": option.option_id,
        "optionDigest": option.option_digest,
        "runbookReference": option.runbook_reference,
        "labelCode": "approvedOperatorRunbook",
        "referenceOnly": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return GuidanceRunbookLink.model_validate(
        {
            **payload,
            "linkId": (f"guidance-link-{digest.removeprefix('sha256:')[:32]}"),
            "linkDigest": digest,
        }
    )


def _ordered_steps(
    steps: Iterable[GuidanceStep],
) -> tuple[GuidanceStep, ...]:
    return tuple(
        sorted(
            {item.step_id: item for item in steps}.values(),
            key=lambda item: item.step_id,
        )
    )


__all__ = ["build_incident_guidance"]
