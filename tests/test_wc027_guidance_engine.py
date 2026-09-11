from __future__ import annotations

import pytest

from athena_context.contracts import (
    CorrelationGate,
    GuidanceAffectedRoleImpact,
    NoRunbookGuidanceSelection,
    SelectedRunbookGuidanceSelection,
    sha256_hex,
    validate_incident_guidance_binding,
)
from athena_context.guidance import build_incident_guidance
from test_wc026_correlation import correlate_incident
from test_wc026_correlation_contract import (
    _bound_observation,
    _bundle,
    _change_pair,
    _dependency_path,
    _endpoint_health_observation,
    _hypothesis,
    _nsg_bundle,
    _report_for,
    _request,
)
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


def _verify_signature(_: bytes, signature: str) -> bool:
    return signature == "c3ludGhldGlj"


def _validate(guidance, binding) -> None:
    validate_incident_guidance_binding(
        guidance,
        binding,
        trusted_binding_key_id=_BINDING_KEY_ID,
        binding_signature_verifier=_verify_signature,
    )


def _top_only_report(report):
    from athena_context.contracts import CorrelationReport, compute_artifact_digest

    payload = report.model_dump(
        mode="python",
        by_alias=True,
        exclude={"report_id", "report_digest"},
    )
    payload["hypotheses"] = (report.hypotheses[0],)
    digest = compute_artifact_digest(
        {
            **payload,
            "hypotheses": [
                report.hypotheses[0].model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            ],
        }
    )
    return CorrelationReport(
        **payload,
        reportId=f"report-{digest.removeprefix('sha256:')[:32]}",
        reportDigest=digest,
    )


def test_no_runbook_low_guidance_is_deterministic_and_read_only() -> None:
    binding = _binding()

    first = build_incident_guidance(binding)
    second = build_incident_guidance(binding)

    assert first == second
    assert first.guidance_digest == second.guidance_digest
    assert isinstance(binding.selection, NoRunbookGuidanceSelection)
    assert first.safe_manual_options == ()
    assert first.rollback_considerations == ()
    assert first.runbook_links == ()
    assert first.escalation
    assert not any(item.summary_code.startswith("coverage.") for item in first.timeline)
    assert all(
        not parameter.value.startswith("coverage-")
        for collection in (
            first.confirmation_checks,
            first.investigation_steps,
        )
        for step in collection
        for parameter in step.parameters
        if parameter.parameter_kind == "evidenceId"
    )
    assert {item.template_code for item in first.confirmation_checks} == {"confirmEffectiveRule"}
    assert {item.template_code for item in first.investigation_steps} == {
        "inspectNetworkPath",
        "inspectRecentChange",
    }
    assert first.no_auto_remediation is True
    _validate(first, binding)


@pytest.mark.parametrize(
    ("category", "confirmation", "investigation"),
    [
        ("routingChange", "confirmEffectiveRule", {"inspectNetworkPath", "inspectRecentChange"}),
        ("guestResourcePressure", "confirmBackendHealth", {"inspectGuestHealth"}),
        ("guestServiceFailure", "confirmBackendHealth", {"inspectGuestHealth"}),
        ("platformHealth", "confirmBackendHealth", {"inspectGuestHealth"}),
        ("backendHealth", "confirmBackendHealth", {"inspectNetworkPath"}),
        ("dependencyFailure", "confirmBackendHealth", {"inspectNetworkPath"}),
        ("deploymentChange", "confirmBackendHealth", {"inspectRecentChange", "inspectGuestHealth"}),
        ("unknown", "confirmBackendHealth", {"inspectGuestHealth"}),
    ],
)
def test_category_template_mapping_is_stable(
    category: str,
    confirmation: str,
    investigation: set[str],
) -> None:
    request = _request()
    report = _report_for(
        request,
        _hypothesis(
            category=category,
            citation=request.evidence_index[0],
        ),
    )
    binding = _binding(request=request, report=report)

    guidance = build_incident_guidance(binding)

    assert {item.template_code for item in guidance.confirmation_checks} == {confirmation}
    assert {item.template_code for item in guidance.investigation_steps} == investigation
    _validate(guidance, binding)


def test_confirmed_selected_manual_option_is_human_only() -> None:
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
    binding = _binding(
        request=request,
        report=report,
        authority=_authority(request=request, options=(option,)),
        selection=_selected_runbook(
            option,
            request=request,
            report=report,
            requested_actions=("manualResolutionOption",),
        ),
        requested_actions=("manualResolutionOption",),
    )

    guidance = build_incident_guidance(binding)

    assert isinstance(binding.selection, SelectedRunbookGuidanceSelection)
    assert guidance.safe_manual_options
    assert guidance.safe_manual_options[0].requires_authorization is True
    assert guidance.safe_manual_options[0].read_only is False
    assert guidance.runbook_links
    assert guidance.no_auto_remediation is True
    _validate(guidance, binding)


def test_competing_cause_withholds_manual_actions() -> None:
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
    option = _option()
    binding = _binding(
        request=request,
        report=report,
        authority=_authority(request=request, options=(option,)),
        selection=_selected_runbook(option, request=request, report=report),
    )

    guidance = build_incident_guidance(binding)

    assert guidance.safe_manual_options == ()
    assert guidance.rollback_considerations == ()
    assert "competingCause" in guidance.legality.withheld_reasons
    assert guidance.escalation
    _validate(guidance, binding)


def test_recovery_evidence_adds_recovery_validation() -> None:
    base_bundle = _bundle()
    recovered = _bound_observation(
        observedStart=base_bundle.observed_end,
        observedEnd=base_bundle.observed_end,
        state="recovered",
        summaryCode="guest.heartbeat-recovered",
        sourceRootReference="azure-monitor-source:sha256:" + "8" * 64,
        sourceRecordReference="azure-monitor:sha256:" + "8" * 64,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, recovered),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )
    request = _request(bundle_override=bundle)
    report = correlate_incident(request)
    binding = _binding(request=request, report=report)

    guidance = build_incident_guidance(binding)

    assert guidance.recovery_validation
    assert recovered.observation_id in guidance.recovery_validation[0].evidence_ids
    assert any(item.timeline_kind == "recovery" for item in guidance.timeline)
    confirmation_evidence = next(
        item.value
        for item in guidance.confirmation_checks[0].parameters
        if item.parameter_kind == "evidenceId"
    )
    assert confirmation_evidence != recovered.observation_id
    _validate(guidance, binding)


def test_unsatisfied_recovery_gate_does_not_add_recovery_validation() -> None:
    request = _request()
    citation = request.evidence_index[0]
    report = _report_for(
        request,
        _hypothesis(
            citation=citation,
            gates=(
                CorrelationGate(
                    code="recoveryEvidence",
                    satisfied=False,
                    evidenceIds=(citation.evidence_id,),
                ),
            ),
        ),
    )
    binding = _binding(request=request, report=report)

    guidance = build_incident_guidance(binding)

    assert guidance.recovery_validation == ()
    _validate(guidance, binding)


def test_recovery_gate_coverage_is_not_presented_as_recovery_evidence() -> None:
    base_bundle = _bundle()
    recovered = _bound_observation(
        observedStart=base_bundle.observed_end,
        observedEnd=base_bundle.observed_end,
        state="recovered",
        summaryCode="guest.heartbeat-recovered",
        sourceRootReference="azure-monitor-source:sha256:" + "8" * 64,
        sourceRecordReference="azure-monitor:sha256:" + "8" * 64,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, recovered),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )
    request = _request(bundle_override=bundle)
    recovered_citation = next(
        item for item in request.evidence_index if item.evidence_id == recovered.observation_id
    )
    coverage_id = request.monitoring_bundle.coverage[0].coverage_id
    report = _report_for(
        request,
        _hypothesis(
            citation=recovered_citation,
            gates=(
                CorrelationGate(
                    code="recoveryEvidence",
                    satisfied=True,
                    evidenceIds=tuple(sorted((coverage_id, recovered.observation_id))),
                ),
            ),
        ),
    )
    binding = _binding(request=request, report=report)

    guidance = build_incident_guidance(binding)

    assert guidance.recovery_validation[0].evidence_ids == (recovered.observation_id,)
    assert not any(item.summary_code.startswith("coverage.") for item in guidance.timeline)
    _validate(guidance, binding)


def test_competing_hypothesis_recovery_is_not_attributed_to_top_cause() -> None:
    artifact, handoff = _change_pair()
    base_bundle, _, _, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
    )
    recovered = _endpoint_health_observation(
        path=_dependency_path(),
        observed_start=base_bundle.observed_end,
        observed_end=base_bundle.observed_end,
        status="recovered",
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, recovered),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )
    report = correlate_incident(request)
    assert not any(
        gate.code == "recoveryEvidence" and gate.satisfied for gate in report.hypotheses[0].gates
    )
    assert any(
        gate.code == "recoveryEvidence" and gate.satisfied
        for hypothesis in report.hypotheses[1:]
        for gate in hypothesis.gates
    )
    binding = _binding(request=request, report=report)

    guidance = build_incident_guidance(binding)

    assert guidance.recovery_validation == ()
    _validate(guidance, binding)


def test_role_impact_accepts_source_compatible_profile_identifier() -> None:
    impact = GuidanceAffectedRoleImpact(
        roleRef="web",
        profileId="production west",
        impactSeverity="limited",
        impactCode="roleDegraded",
    )

    assert impact.profile_id == "production west"


def test_guidance_rejects_unsupported_binding_type() -> None:
    with pytest.raises(TypeError, match="exact PublishedGuidanceAuthorityBinding"):
        build_incident_guidance(object())  # type: ignore[arg-type]
