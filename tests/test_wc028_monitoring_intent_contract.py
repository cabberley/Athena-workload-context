from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from athena_context.contracts import (
    ActivityLogMonitoringSignal,
    LogQueryMonitoringSignal,
    MetricMonitoringSignal,
    MonitoringIntentScope,
    PublishedMonitoringIntent,
    PublishedMonitoringIntentAssetReference,
    PublishedMonitoringIntentAttestation,
    PublishedMonitoringIntentControl,
    ResourceHealthMonitoringSignal,
    VersionPinnedBlobReference,
    build_published_monitoring_intent,
    compute_artifact_digest,
    sha256_hex,
    validate_monitoring_intent_activation_eligible,
    validate_published_monitoring_intent_assets,
    validate_published_monitoring_intent_context,
)
from test_wc026_correlation_contract import (
    DB_ID,
    WEB_ID,
    _context_binding,
    _dependency_path,
)

_KEY_ID = (
    "https://synthetic-wc028.vault.azure.net/keys/"
    "monitoring-intent/0123456789abcdef0123456789abcdef"
)
_SIGNATURE = "c3ludGhldGlj"


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


def _scope() -> MonitoringIntentScope:
    path = _dependency_path()
    payload: dict[str, object] = {
        "resourceIds": tuple(
            sorted(
                resource_id for resource_id in path.resource_ids if resource_id == WEB_ID.lower()
            )
        ),
        "pathIds": (path.path_id,),
        "roleRefs": tuple(sorted((path.source_role_ref, path.target_role_ref))),
    }
    return MonitoringIntentScope(
        **payload,
        scopeDigest=compute_artifact_digest(_json_value(payload)),
    )


def _metric_signal() -> MetricMonitoringSignal:
    return MetricMonitoringSignal(
        signalKind="metric",
        metricNamespace="Microsoft.Compute/virtualMachines",
        metricName="Percentage CPU",
        unit="percent",
        aggregation="average",
        operator="greaterThanOrEqual",
        threshold=90.0,
        evaluationWindowSeconds=300,
        frequencySeconds=60,
        dimensions=(),
    )


def _control(
    *,
    signal=None,
    dry_run_only: bool = False,
    source_clause_path: str = "/controls/cpu-pressure",
) -> PublishedMonitoringIntentControl:
    payload: dict[str, object] = {
        "sourceClausePath": source_clause_path,
        "ownerRef": "synthetic-platform-owner",
        "severity": 2,
        "missingDataBehavior": "reviewRequired",
        "actionBehavior": "none",
        "dryRunOnly": dry_run_only,
        "scope": _scope(),
        "signal": signal or _metric_signal(),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return PublishedMonitoringIntentControl(
        **payload,
        controlId=(f"monitoring-control-{digest.removeprefix('sha256:')[:32]}"),
        controlDigest=digest,
    )


def _intent(*, controls=None):
    context = _context_binding()
    selected_controls = (
        (_control(),)
        if controls is None
        else tuple(sorted(controls, key=lambda item: item.control_id))
    )
    return build_published_monitoring_intent(
        context,
        environment="production",
        controls=selected_controls,
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
    )


def _assets(intent):
    attestation = PublishedMonitoringIntentAttestation(
        schemaVersion=("athena.wc028PublishedMonitoringIntentAttestation.v1"),
        intentId=intent.intent_id,
        intentDigest=intent.intent_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=_KEY_ID,
        signedPreimageDigest=sha256_hex(intent.canonical_bytes()),
        detachedSignature=_SIGNATURE,
    )
    prefix = f"monitoring-intent/{intent.intent_id}"
    payload: dict[str, object] = {
        "schemaVersion": ("athena.wc028PublishedMonitoringIntentAssetReference.v1"),
        "intentId": intent.intent_id,
        "intentDigest": intent.intent_digest,
        "intentReference": VersionPinnedBlobReference(
            name=f"{prefix}/intent.json",
            version="2026-09-12T01:00:00.0000000Z",
            contentDigest=sha256_hex(intent.canonical_bytes()),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{prefix}/attestation.json",
            version="2026-09-12T01:00:01.0000000Z",
            contentDigest=sha256_hex(attestation.canonical_bytes()),
        ),
    }
    digest = compute_artifact_digest(_json_value(payload))
    reference = PublishedMonitoringIntentAssetReference(
        **payload,
        referenceId=(f"monitoring-intent-asset-{digest.removeprefix('sha256:')[:32]}"),
        referenceDigest=digest,
    )
    return reference, attestation


def _verify(_: bytes, signature: str) -> bool:
    return signature == _SIGNATURE


def test_published_monitoring_intent_round_trip_and_assets() -> None:
    intent = _intent()
    reference, attestation = _assets(intent)

    validate_published_monitoring_intent_assets(
        reference,
        intent,
        attestation,
        trusted_key_id=_KEY_ID,
        signature_verifier=_verify,
    )

    assert (
        PublishedMonitoringIntent.model_validate_json(intent.model_dump_json(by_alias=True))
        == intent
    )
    assert intent.no_auto_remediation is True
    context = _context_binding()
    validate_published_monitoring_intent_context(
        intent,
        context,
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
    )
    validate_monitoring_intent_activation_eligible(
        intent,
        context,
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
    )


def test_draft_context_and_stale_authority_are_rejected() -> None:
    with pytest.raises(TypeError, match="PublishedRuntimeContextBinding"):
        build_published_monitoring_intent(
            _context_binding(binding_mode="draftPreview"),  # type: ignore[arg-type]
            environment="development",
            controls=(_control(dry_run_only=True),),
            expected_active_context_authority_digest="sha256:" + "f" * 64,
        )

    context = _context_binding()
    with pytest.raises(ValueError, match="published profile ID"):
        build_published_monitoring_intent(
            context,
            environment="training",
            controls=(_control(),),
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
        )
    with pytest.raises(ValueError, match="currently active"):
        build_published_monitoring_intent(
            context,
            environment="production",
            controls=(_control(),),
            expected_active_context_authority_digest="sha256:" + "f" * 64,
        )


def test_control_scope_cannot_escape_published_context() -> None:
    control = _control()
    payload = control.scope.model_dump(
        mode="python",
        by_alias=True,
        exclude={"scope_digest"},
    )
    payload["resourceIds"] = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/"
        "resourcegroups/rg-outside/providers/microsoft.compute/"
        "virtualmachines/outside",
    )
    scope = MonitoringIntentScope(
        **payload,
        scopeDigest=compute_artifact_digest(_json_value(payload)),
    )
    control_payload = control.model_dump(
        mode="python",
        by_alias=True,
        exclude={"control_id", "control_digest"},
    )
    control_payload["scope"] = scope
    digest = compute_artifact_digest(_json_value(control_payload))
    escaped = PublishedMonitoringIntentControl(
        **control_payload,
        controlId=(f"monitoring-control-{digest.removeprefix('sha256:')[:32]}"),
        controlDigest=digest,
    )
    context = _context_binding()

    with pytest.raises(ValueError, match="selected published paths"):
        build_published_monitoring_intent(
            context,
            environment="production",
            controls=(escaped,),
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
        )

    valid_intent = _intent()
    intent_payload = valid_intent.model_dump(
        mode="python",
        by_alias=True,
        exclude={"intent_id", "intent_digest"},
    )
    intent_payload["controls"] = (escaped,)
    intent_digest = compute_artifact_digest(_json_value(intent_payload))
    forged = PublishedMonitoringIntent(
        **intent_payload,
        intentId=(f"monitoring-intent-{intent_digest.removeprefix('sha256:')[:32]}"),
        intentDigest=intent_digest,
    )
    with pytest.raises(ValueError, match="selected published paths"):
        validate_published_monitoring_intent_context(
            forged,
            context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
        )


def test_control_scope_must_be_coherent_with_selected_paths() -> None:
    path_a = _dependency_path()
    cache_id = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/"
        "resourcegroups/rg-synthetic-wc026/providers/microsoft.compute/"
        "virtualmachines/synthetic-cache-01"
    )
    path_b = _dependency_path(
        source_role_ref="web",
        target_role_ref="cache",
        relationship_id="relationship-web-cache",
        resource_ids=(WEB_ID.lower(), cache_id),
    )
    context = _context_binding(
        dependency_paths=tuple(sorted((path_a, path_b), key=lambda item: item.path_id))
    )
    scope_payload: dict[str, object] = {
        "resourceIds": (DB_ID.lower(),),
        "pathIds": (path_b.path_id,),
        "roleRefs": tuple(sorted((path_b.source_role_ref, path_b.target_role_ref))),
    }
    incoherent_scope = MonitoringIntentScope(
        **scope_payload,
        scopeDigest=compute_artifact_digest(_json_value(scope_payload)),
    )
    control_payload = _control().model_dump(
        mode="python",
        by_alias=True,
        exclude={"control_id", "control_digest"},
    )
    control_payload["scope"] = incoherent_scope
    digest = compute_artifact_digest(_json_value(control_payload))
    control = PublishedMonitoringIntentControl(
        **control_payload,
        controlId=(f"monitoring-control-{digest.removeprefix('sha256:')[:32]}"),
        controlDigest=digest,
    )

    with pytest.raises(ValueError, match="selected published paths"):
        build_published_monitoring_intent(
            context,
            environment="production",
            controls=(control,),
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
        )


def test_metric_control_requires_one_resource() -> None:
    path = _dependency_path()
    scope_payload: dict[str, object] = {
        "resourceIds": tuple(sorted((WEB_ID.lower(), DB_ID.lower()))),
        "pathIds": (path.path_id,),
        "roleRefs": tuple(sorted((path.source_role_ref, path.target_role_ref))),
    }
    scope = MonitoringIntentScope(
        **scope_payload,
        scopeDigest=compute_artifact_digest(_json_value(scope_payload)),
    )
    payload = _control().model_dump(
        mode="python",
        by_alias=True,
        exclude={"control_id", "control_digest"},
    )
    payload["scope"] = scope
    digest = compute_artifact_digest(_json_value(payload))
    control = PublishedMonitoringIntentControl(
        **payload,
        controlId=(f"monitoring-control-{digest.removeprefix('sha256:')[:32]}"),
        controlDigest=digest,
    )
    context = _context_binding()

    with pytest.raises(ValueError, match="exactly one resource"):
        build_published_monitoring_intent(
            context,
            environment="production",
            controls=(control,),
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
        )


def test_log_query_target_must_be_in_reviewed_scope() -> None:
    query = "Perf | summarize count()"
    signal = LogQueryMonitoringSignal(
        signalKind="logQuery",
        query=query,
        queryDigest=sha256_hex(query.encode("utf-8")),
        queryTargetResourceId=(
            "/subscriptions/11111111-2222-3333-4444-555555555555/"
            "resourcegroups/foreign/providers/microsoft.operationalinsights/"
            "workspaces/foreign"
        ),
        unit="count",
        aggregation="count",
        operator="greaterThan",
        threshold=0.0,
        evaluationWindowSeconds=300,
        frequencySeconds=60,
    )
    context = _context_binding()

    with pytest.raises(ValueError, match="outside the reviewed control scope"):
        build_published_monitoring_intent(
            context,
            environment="production",
            controls=(_control(signal=signal),),
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
        )


def test_monitoring_signals_require_all_explicit_values() -> None:
    scope_payload = _scope().model_dump(
        mode="python",
        by_alias=True,
        exclude={"scope_digest", "path_ids"},
    )
    with pytest.raises(ValidationError, match="pathIds"):
        MonitoringIntentScope(
            **scope_payload,
            scopeDigest="sha256:" + "0" * 64,
        )

    with pytest.raises(ValidationError, match="threshold"):
        MetricMonitoringSignal(
            signalKind="metric",
            metricNamespace="Microsoft.Compute/virtualMachines",
            metricName="Percentage CPU",
            unit="percent",
            aggregation="average",
            operator="greaterThan",
            evaluationWindowSeconds=300,
            frequencySeconds=60,
        )

    query = "Perf | summarize count()"
    with pytest.raises(ValidationError, match="queryDigest"):
        LogQueryMonitoringSignal(
            signalKind="logQuery",
            query=query,
            queryDigest="sha256:" + "f" * 64,
            queryTargetResourceId=WEB_ID.lower(),
            unit="count",
            aggregation="count",
            operator="greaterThan",
            threshold=0.0,
            evaluationWindowSeconds=300,
            frequencySeconds=60,
        )
    for cross_boundary_query in (
        'workspace("00000000-0000-0000-0000-000000000000").Perf',
        'workspace // comment\n("outside").Perf',
        'arg("").resources | count',
        'database("Other").Table | count',
        'resource("/subscriptions/outside").Heartbeat',
        'adx("outside").Table | count',
    ):
        with pytest.raises(ValidationError, match="workspace boundaries"):
            LogQueryMonitoringSignal(
                signalKind="logQuery",
                query=cross_boundary_query,
                queryDigest=sha256_hex(cross_boundary_query.encode("utf-8")),
                queryTargetResourceId=WEB_ID.lower(),
                unit="count",
                aggregation="count",
                operator="greaterThan",
                threshold=0.0,
                evaluationWindowSeconds=300,
                frequencySeconds=60,
            )

    assert ActivityLogMonitoringSignal(
        signalKind="activityLog",
        categories=("Administrative",),
        operationNames=("Microsoft.Compute/virtualMachines/write",),
        resultTypes=("Failed", "Succeeded"),
        levels=("Error", "Warning"),
    )
    assert ResourceHealthMonitoringSignal(
        signalKind="resourceHealth",
        eventStatuses=("Active", "Resolved"),
        currentStatuses=("Available",),
        previousStatuses=("Unavailable",),
        reasonTypes=("PlatformInitiated", "Unknown"),
    )
    with pytest.raises(ValidationError, match="Extra inputs"):
        ActivityLogMonitoringSignal(
            signalKind="activityLog",
            categories=("Administrative",),
            operationNames=("Microsoft.Compute/virtualMachines/write",),
            resultTypes=("Failed",),
            levels=("Error",),
            eventCountThreshold=1,
        )


def test_dry_run_intent_cannot_be_activated() -> None:
    intent = _intent(controls=(_control(dry_run_only=True),))
    context = _context_binding()

    with pytest.raises(ValueError, match="dry-run-only"):
        validate_monitoring_intent_activation_eligible(
            intent,
            context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
        )


def test_contracts_reject_extra_fields_and_substitution() -> None:
    intent = _intent()
    payload = intent.model_dump(mode="json", by_alias=True)
    payload["inferredDefault"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        PublishedMonitoringIntent.model_validate(payload)

    reference, attestation = _assets(intent)
    with pytest.raises(ValueError, match="exact content"):
        validate_published_monitoring_intent_assets(
            reference,
            intent,
            attestation,
            trusted_key_id=_KEY_ID,
            signature_verifier=lambda _payload, _signature: False,
        )


def test_monitoring_intent_byte_budget_rejects_large_query_set() -> None:
    controls = tuple(
        _control(
            signal=LogQueryMonitoringSignal(
                signalKind="logQuery",
                query=(f"Heartbeat | extend marker='{index}-" + "x" * 7450 + "'"),
                queryDigest=sha256_hex(
                    (f"Heartbeat | extend marker='{index}-" + "x" * 7450 + "'").encode("utf-8")
                ),
                queryTargetResourceId=WEB_ID.lower(),
                unit="count",
                aggregation="count",
                operator="greaterThan",
                threshold=0.0,
                evaluationWindowSeconds=300,
                frequencySeconds=60,
            ),
            source_clause_path=f"/controls/query-{index}",
        )
        for index in range(10)
    )

    with pytest.raises(ValueError, match="canonical byte budget"):
        _intent(controls=controls)
