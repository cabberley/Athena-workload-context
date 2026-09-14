from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel

import athena_context.wc029_acceptance_evidence as acceptance
from athena_context.contracts import (
    ChangeEvidenceArtifact,
    CorrelationReport,
    IncidentEnrichmentAttestation,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentEnrichmentManifest,
    IncidentFeedIndexV2,
    IncidentGuidance,
    IncidentGuidanceAssetReference,
    IncidentGuidanceAttestation,
    IncidentNotificationEnvelopeV2,
    IncidentNotificationV2,
    IncidentNotificationV2Attestation,
    IncidentState,
    IncidentStateAttestation,
    PublishedCorrelationReportAttestation,
    VersionPinnedBlobReference,
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.change_ingestion import (
    change_evidence_attestation_preimage,
)
from test_presentation_asset_gateway import _resolved_feed_v2_source_fixture
from test_wc024_monitoring_contract import _trusted_signed_handoff
from test_wc026_correlation_contract import _change_pair

_NOW = datetime(2026, 9, 14, 4, 0, tzinfo=UTC)
_SOURCE_COMMIT = "a" * 40
_TEMPLATE_DIGEST = "sha256:" + ("b" * 64)
_MANIFEST_DIGEST = "sha256:" + ("c" * 64)
_IMAGE = "synthetic.azurecr.io/athena/wc029-acceptance@sha256:" + ("d" * 64)
_PRINCIPAL_ID = "00000000-0000-0000-0000-000000000001"
_JOB_RESOURCE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-athena-wc029-synthetic/providers/Microsoft.App/"
    "jobs/athena-wc029-synthetic"
)
_TARGETS = {
    scenario_class: (
        "/subscriptions/00000000-0000-0000-0000-000000000000/"
        "resourceGroups/rg-athena-demo-workload/providers/Microsoft.Compute/"
        f"virtualMachines/{scenario_class}"
    )
    for scenario_class in acceptance.REQUIRED_SCENARIO_CLASSES
}
_SCENARIO_MODES = {
    scenario_class: (
        "incident-producing" if scenario_class == "web-tier-failure" else "correlation-only"
    )
    for scenario_class in acceptance.REQUIRED_SCENARIO_CLASSES
}


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    purpose: str
    key_id: str
    public_key: rsa.RSAPublicKey
    fingerprint: str


@dataclass(frozen=True, slots=True)
class IncidentAssets:
    active_state: IncidentState
    active_state_attestation: IncidentStateAttestation
    resolved_state: IncidentState
    resolved_state_attestation: IncidentStateAttestation
    report: CorrelationReport
    report_attestation: PublishedCorrelationReportAttestation
    guidance: IncidentGuidance
    guidance_attestation: IncidentGuidanceAttestation
    enrichment: IncidentEnrichmentManifest
    enrichment_attestation: IncidentEnrichmentAttestation
    active_feed: IncidentEnrichmentFeedPointer
    active_feed_attestation: IncidentEnrichmentFeedPointerAttestation
    resolved_feed: IncidentEnrichmentFeedPointer
    resolved_feed_attestation: IncidentEnrichmentFeedPointerAttestation
    active_notification: IncidentNotificationEnvelopeV2
    resolved_notification: IncidentNotificationEnvelopeV2
    keys: dict[str, KeyMaterial]


@dataclass(frozen=True, slots=True)
class BundleFixture:
    root: Path
    output: Path
    index: dict[str, Any]
    artifact_paths: dict[str, Path]
    keys: dict[str, KeyMaterial]


def _canonical_bytes(value: object) -> bytes:
    return (canonicalize_json(value) + "\n").encode("utf-8")


def _model_bytes(value: BaseModel) -> bytes:
    canonical = getattr(value, "canonical_bytes", None)
    if callable(canonical):
        return canonical()
    return _canonical_bytes(value.model_dump(mode="json", by_alias=True, exclude_none=True))


def _write(path: Path, value: object) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _model_bytes(value) if isinstance(value, BaseModel) else _canonical_bytes(value)
    path.write_bytes(payload)
    return payload


def _fingerprint(public_key: rsa.RSAPublicKey) -> str:
    return sha256_hex(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items() if item is not None}
    return value


def _public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _private_key_material(
    purpose: str,
    version_character: str,
) -> tuple[KeyMaterial, rsa.RSAPrivateKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    key_id = (
        f"https://athena-wc029-synthetic.vault.azure.net/keys/{purpose}/{version_character * 32}"
    )
    return (
        KeyMaterial(
            purpose=purpose,
            key_id=key_id,
            public_key=public_key,
            fingerprint=_fingerprint(public_key),
        ),
        private_key,
    )


def _schema_payloads(fixture: dict[str, Any]) -> dict[str, list[bytes]]:
    result: dict[str, list[bytes]] = {}
    for payload in fixture["reader"].versioned_content.values():
        try:
            schema_version = json.loads(payload).get("schemaVersion")
        except UnicodeDecodeError, json.JSONDecodeError:
            continue
        if isinstance(schema_version, str):
            result.setdefault(schema_version, []).append(payload)
    return result


def _one_model[Model: BaseModel](
    payloads: dict[str, list[bytes]],
    schema_version: str,
    model: type[Model],
) -> Model:
    values = payloads[schema_version]
    assert len(values) == 1
    return model.model_validate_json(values[0])


def _resolved_guidance_reference(
    state: IncidentState,
) -> IncidentGuidanceAssetReference:
    guidance_id = "incident-guidance-" + ("e" * 32)
    prefix = (
        f"incidents/{state.incident_id}/versions/"
        f"{state.result_digest.removeprefix('sha256:')}/guidance/{guidance_id}"
    )
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027IncidentGuidanceAssetReference.v1",
        "incidentId": state.incident_id,
        "incidentStateDigest": state.result_digest,
        "guidanceId": guidance_id,
        "guidanceDigest": "sha256:" + ("f" * 64),
        "guidanceReference": VersionPinnedBlobReference(
            name=f"{prefix}/guidance.json",
            version="resolved-guidance-version",
            contentDigest="sha256:" + ("1" * 64),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{prefix}/attestation.json",
            version="resolved-guidance-attestation-version",
            contentDigest="sha256:" + ("2" * 64),
        ),
    }
    digest = compute_artifact_digest(
        {
            key: (
                item.model_dump(mode="json", by_alias=True, exclude_none=True)
                if isinstance(item, BaseModel)
                else item
            )
            for key, item in payload.items()
        }
    )
    return IncidentGuidanceAssetReference(
        **payload,
        referenceId=f"guidance-asset-{digest.removeprefix('sha256:')[:32]}",
        referenceDigest=digest,
    )


def _notification(
    *,
    state: IncidentState,
    pointer: IncidentEnrichmentFeedPointer,
    feed_index: IncidentFeedIndexV2,
    feed_pointer_reference: VersionPinnedBlobReference,
    feed_pointer_attestation_reference: VersionPinnedBlobReference,
    guidance_reference: IncidentGuidanceAssetReference,
    key_id: str,
    private_key: rsa.RSAPrivateKey,
) -> IncidentNotificationEnvelopeV2:
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027IncidentNotification.v2",
        "incidentId": state.incident_id,
        "transitionId": state.transition_id,
        "lifecycle": state.lifecycle,
        "stateResultDigest": state.result_digest,
        "occurrenceDigest": pointer.occurrence_digest,
        "feedIndexDigest": sha256_hex(feed_index.canonical_bytes()),
        "feedPublishedAt": feed_index.published_at,
        "feedPointerReference": feed_pointer_reference,
        "feedPointerAttestationReference": feed_pointer_attestation_reference,
        "enrichmentAsset": pointer.enrichment_asset,
        "guidanceAsset": guidance_reference,
        "presentationUrl": (f"https://athena.synthetic.invalid/#incident-{state.incident_id}"),
        "message": "Synthetic verified incident notification.",
        "noAutoRemediation": True,
    }
    json_payload = {
        key: (
            item.model_dump(mode="json", by_alias=True, exclude_none=True)
            if isinstance(item, BaseModel)
            else item
        )
        for key, item in payload.items()
    }
    notification_digest = compute_artifact_digest(json_payload)
    identity_digest = compute_artifact_digest(
        {
            "schemaVersion": "athena.wc027IncidentNotificationIdentity.v1",
            "incidentId": state.incident_id,
            "transitionId": state.transition_id,
            "lifecycle": state.lifecycle,
            "stateResultDigest": state.result_digest,
            "occurrenceDigest": pointer.occurrence_digest,
            "guidanceAsset": guidance_reference.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
        }
    )
    notification = IncidentNotificationV2(
        **payload,
        notificationId="notify-v2-" + identity_digest.removeprefix("sha256:"),
        notificationDigest=notification_digest,
    )
    signature = (
        base64.urlsafe_b64encode(
            private_key.sign(
                notification.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    return IncidentNotificationEnvelopeV2(
        schemaVersion="athena.wc027IncidentNotificationEnvelope.v2",
        notification=notification,
        attestation=IncidentNotificationV2Attestation(
            schemaVersion="athena.wc027IncidentNotificationAttestation.v2",
            notificationId=notification.notification_id,
            notificationDigest=notification.notification_digest,
            signatureAlgorithm="RS256",
            keyVaultKeyId=key_id,
            signedPreimageDigest=sha256_hex(notification.canonical_bytes()),
            detachedSignature=signature,
        ),
    )


def _incident_assets() -> IncidentAssets:
    fixture = _resolved_feed_v2_source_fixture()
    payloads = _schema_payloads(fixture)
    states = [
        IncidentState.model_validate_json(payload)
        for payload in payloads["athena.incidentState.v1"]
    ]
    state_attestations = [
        IncidentStateAttestation.model_validate_json(payload)
        for payload in payloads["athena.incidentStateAttestation.v1"]
    ]
    active_state = next(item for item in states if item.lifecycle == "active")
    resolved_state = next(item for item in states if item.lifecycle == "resolved")
    active_state_attestation = next(
        item for item in state_attestations if item.result_digest == active_state.result_digest
    )
    resolved_state_attestation = next(
        item for item in state_attestations if item.result_digest == resolved_state.result_digest
    )
    report = _one_model(
        payloads,
        "athena.wc026CorrelationReport.v1",
        CorrelationReport,
    )
    report_attestation = _one_model(
        payloads,
        "athena.wc027PublishedCorrelationReportAttestation.v1",
        PublishedCorrelationReportAttestation,
    )
    guidance = _one_model(
        payloads,
        "athena.wc027IncidentGuidance.v1",
        IncidentGuidance,
    )
    guidance_attestation = _one_model(
        payloads,
        "athena.wc027IncidentGuidanceAttestation.v1",
        IncidentGuidanceAttestation,
    )
    enrichment = _one_model(
        payloads,
        "athena.wc027IncidentEnrichmentManifest.v1",
        IncidentEnrichmentManifest,
    )
    enrichment_attestation = _one_model(
        payloads,
        "athena.wc027IncidentEnrichmentAttestation.v1",
        IncidentEnrichmentAttestation,
    )
    feeds = [
        IncidentEnrichmentFeedPointer.model_validate_json(payload)
        for payload in payloads["athena.wc027IncidentEnrichmentFeedPointer.v2"]
    ]
    feed_attestations = [
        IncidentEnrichmentFeedPointerAttestation.model_validate_json(payload)
        for payload in payloads["athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"]
    ]
    active_feed = next(item for item in feeds if item.lifecycle == "active")
    resolved_feed = next(item for item in feeds if item.lifecycle == "resolved")
    active_feed_attestation = next(
        item for item in feed_attestations if item.pointer_id == active_feed.pointer_id
    )
    resolved_feed_attestation = next(
        item for item in feed_attestations if item.pointer_id == resolved_feed.pointer_id
    )
    active_entry = fixture["feed_index"].active[0]
    resolved_entry = fixture["feed_entry"]
    resolved_index = IncidentFeedIndexV2.model_validate_json(
        fixture["reader"].content["incidents/feed-v2.json"]
    )
    notification_key, notification_private = _private_key_material(
        "notification",
        "9",
    )
    active_notification = _notification(
        state=active_state,
        pointer=active_feed,
        feed_index=fixture["feed_index"],
        feed_pointer_reference=active_entry.feed_pointer_reference,
        feed_pointer_attestation_reference=(active_entry.feed_pointer_attestation_reference),
        guidance_reference=enrichment.guidance_asset,
        key_id=notification_key.key_id,
        private_key=notification_private,
    )
    resolved_notification = _notification(
        state=resolved_state,
        pointer=resolved_feed,
        feed_index=resolved_index,
        feed_pointer_reference=resolved_entry.feed_pointer_reference,
        feed_pointer_attestation_reference=(resolved_entry.feed_pointer_attestation_reference),
        guidance_reference=_resolved_guidance_reference(resolved_state),
        key_id=notification_key.key_id,
        private_key=notification_private,
    )
    keys = {
        "incident": KeyMaterial(
            purpose="incident",
            key_id=fixture["lifecycle_key_vault_key_id"],
            public_key=fixture["lifecycle_trust"].public_key,
            fingerprint=fixture["lifecycle_trust"].key_fingerprint,
        ),
        "report": KeyMaterial(
            purpose="report",
            key_id=fixture["report_trust"].key_id,
            public_key=fixture["report_trust"].public_key,
            fingerprint=fixture["report_trust"].key_fingerprint,
        ),
        "guidance": KeyMaterial(
            purpose="guidance",
            key_id=fixture["guidance_trust"].key_id,
            public_key=fixture["guidance_trust"].public_key,
            fingerprint=fixture["guidance_trust"].key_fingerprint,
        ),
        "enrichment": KeyMaterial(
            purpose="enrichment",
            key_id=fixture["enrichment_trust"].key_id,
            public_key=fixture["enrichment_trust"].public_key,
            fingerprint=fixture["enrichment_trust"].key_fingerprint,
        ),
        "feed": KeyMaterial(
            purpose="feed",
            key_id=fixture["feed_trust"].key_id,
            public_key=fixture["feed_trust"].public_key,
            fingerprint=fixture["feed_trust"].key_fingerprint,
        ),
        "notification": notification_key,
    }
    return IncidentAssets(
        active_state=active_state,
        active_state_attestation=active_state_attestation,
        resolved_state=resolved_state,
        resolved_state_attestation=resolved_state_attestation,
        report=report,
        report_attestation=report_attestation,
        guidance=guidance,
        guidance_attestation=guidance_attestation,
        enrichment=enrichment,
        enrichment_attestation=enrichment_attestation,
        active_feed=active_feed,
        active_feed_attestation=active_feed_attestation,
        resolved_feed=resolved_feed,
        resolved_feed_attestation=resolved_feed_attestation,
        active_notification=active_notification,
        resolved_notification=resolved_notification,
        keys=keys,
    )


def _signed_change() -> tuple[ChangeEvidenceArtifact, KeyMaterial]:
    source, _ = _change_pair()
    key, private_key = _private_key_material("change", "8")
    preimage = canonicalize_json(change_evidence_attestation_preimage(source.evidence)).encode(
        "utf-8"
    )
    signature = base64.b64encode(
        private_key.sign(
            preimage,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    ).decode("ascii")
    payload = source.model_dump(mode="python", by_alias=True)
    payload["attestation"] = {
        **source.attestation.model_dump(mode="python", by_alias=True),
        "keyVaultKeyId": key.key_id,
        "signedPreimageDigest": sha256_hex(preimage),
        "signature": signature,
    }
    return ChangeEvidenceArtifact.model_validate(payload), key


def _digest_bound_model[Model: BaseModel](
    model: type[Model],
    payload: dict[str, object],
    *,
    digest_field: str,
) -> Model:
    digest_payload = {key: value for key, value in payload.items() if value is not None}
    return model.model_validate(
        {
            **payload,
            digest_field: compute_artifact_digest(_json_value(digest_payload)),
        }
    )


def _job_execution(
    *,
    execution_id: str,
    scope: str,
    scenario_id: str | None = None,
    phase: str | None = None,
) -> acceptance.Wc029JobExecutionEvidence:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.JOB_EXECUTION_SCHEMA_VERSION,
        "scope": scope,
        "scenarioId": scenario_id,
        "phase": phase,
        "executionId": execution_id,
        "jobResourceId": _JOB_RESOURCE_ID,
        "sourceCommit": _SOURCE_COMMIT,
        "component": "acceptance",
        "image": _IMAGE,
        "startedAt": _NOW,
        "completedAt": _NOW + timedelta(minutes=1),
        "status": "Succeeded",
        "exitCode": 0,
    }
    return _digest_bound_model(
        acceptance.Wc029JobExecutionEvidence,
        payload,
        digest_field="executionDigest",
    )


def _job_readback(
    execution: acceptance.Wc029JobExecutionEvidence,
    *,
    result_artifacts: list[tuple[str, str]],
) -> acceptance.Wc029JobReadbackEvidence:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.JOB_READBACK_SCHEMA_VERSION,
        "scope": execution.scope,
        "scenarioId": execution.scenario_id,
        "phase": execution.phase,
        "executionId": execution.execution_id,
        "executionDigest": execution.execution_digest,
        "jobResourceId": execution.job_resource_id,
        "sourceCommit": execution.source_commit,
        "component": execution.component,
        "image": execution.image,
        "observedAt": execution.completed_at + timedelta(minutes=1),
        "provisioningState": "Succeeded",
        "status": "Succeeded",
        "resultArtifacts": tuple(
            {"artifactId": artifact_id, "contentSha256": digest}
            for artifact_id, digest in sorted(result_artifacts)
        ),
    }
    return _digest_bound_model(
        acceptance.Wc029JobReadbackEvidence,
        payload,
        digest_field="readbackDigest",
    )


def _scenario_plan(
    scenario_id: str,
    scenario_class: str,
    mode: str,
) -> acceptance.Wc029ScenarioPlanEvidence:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.SCENARIO_PLAN_SCHEMA_VERSION,
        "scenarioId": scenario_id,
        "scenarioClass": scenario_class,
        "evidenceMode": mode,
        "sourceCommit": _SOURCE_COMMIT,
        "targetResourceId": _TARGETS[scenario_class],
        "baselineStateDigest": "sha256:" + ("3" * 64),
        "mutationActionDigest": "sha256:" + ("4" * 64),
        "recoveryActionDigest": "sha256:" + ("5" * 64),
        "expectedSignalCodes": ("monitoring.synthetic", "recovery.synthetic"),
        "abortThresholds": (
            "no-concurrent-fault",
            "preserve-recovery-floor",
        ),
        "operatorApprovalDigest": "sha256:" + ("6" * 64),
    }
    return _digest_bound_model(
        acceptance.Wc029ScenarioPlanEvidence,
        payload,
        digest_field="planDigest",
    )


def _mutation(
    plan: acceptance.Wc029ScenarioPlanEvidence,
) -> acceptance.Wc029MutationReceipt:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.MUTATION_RECEIPT_SCHEMA_VERSION,
        "scenarioId": plan.scenario_id,
        "scenarioClass": plan.scenario_class,
        "planDigest": plan.plan_digest,
        "targetResourceId": plan.target_resource_id,
        "mutationActionDigest": plan.mutation_action_digest,
        "appliedAt": _NOW + timedelta(minutes=2),
        "completed": True,
    }
    return _digest_bound_model(
        acceptance.Wc029MutationReceipt,
        payload,
        digest_field="resultDigest",
    )


def _recovery_action(
    plan: acceptance.Wc029ScenarioPlanEvidence,
    mutation: acceptance.Wc029MutationReceipt,
) -> acceptance.Wc029RecoveryActionEvidence:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.RECOVERY_ACTION_SCHEMA_VERSION,
        "scenarioId": plan.scenario_id,
        "scenarioClass": plan.scenario_class,
        "planDigest": plan.plan_digest,
        "mutationReceiptDigest": mutation.result_digest,
        "targetResourceId": plan.target_resource_id,
        "recoveryActionDigest": plan.recovery_action_digest,
        "recoveredAt": _NOW + timedelta(minutes=5),
        "completed": True,
    }
    return _digest_bound_model(
        acceptance.Wc029RecoveryActionEvidence,
        payload,
        digest_field="resultDigest",
    )


def _manifest_citation(
    scenario_id: str,
    report: CorrelationReport,
    state: IncidentState,
) -> acceptance.Wc029ManifestCitationEvidence:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.MANIFEST_CITATION_SCHEMA_VERSION,
        "scenarioId": scenario_id,
        "manifestId": "synthetic-workload",
        "manifestVersion": "2026.09.14",
        "profileId": "production",
        "manifestDigest": _MANIFEST_DIGEST,
        "correlationReportId": report.report_id,
        "correlationReportDigest": report.report_digest,
        "incidentStateResultDigest": state.result_digest,
        "clauseIds": ("synthetic-availability",),
    }
    return _digest_bound_model(
        acceptance.Wc029ManifestCitationEvidence,
        payload,
        digest_field="citationDigest",
    )


def _recovery_proof(
    plan: acceptance.Wc029ScenarioPlanEvidence,
    mutation: acceptance.Wc029MutationReceipt,
    recovery: acceptance.Wc029RecoveryActionEvidence,
    *,
    evidence_ids: list[str],
) -> acceptance.Wc029RecoveryProof:
    return acceptance.Wc029RecoveryProof(
        schemaVersion=acceptance.RECOVERY_PROOF_SCHEMA_VERSION,
        scenarioId=plan.scenario_id,
        scenarioClass=plan.scenario_class,
        planDigest=plan.plan_digest,
        mutationReceiptDigest=mutation.result_digest,
        recoveryActionResultDigest=recovery.result_digest,
        targetResourceId=plan.target_resource_id,
        verifiedAt=_NOW + timedelta(minutes=10),
        healthy=True,
        residualMutationCount=0,
        baselineStateDigest=plan.baseline_state_digest,
        recoveredStateDigest=plan.baseline_state_digest,
        evidenceArtifactIds=tuple(sorted(evidence_ids)),
    )


def _queue_state(
    scope: str,
    *,
    scenario_id: str | None = None,
) -> acceptance.Wc029QueueStateEvidence:
    return acceptance.Wc029QueueStateEvidence(
        schemaVersion=acceptance.QUEUE_STATE_SCHEMA_VERSION,
        captureScope=scope,
        scenarioId=scenario_id,
        capturedAt=_NOW + timedelta(minutes=10),
        queues=(
            acceptance.Wc029QueueState(
                namespace="athena-wc029-synthetic.servicebus.windows.net",
                queueName="incident-notification-outbox",
                activeMessageCount=0,
                deadLetterMessageCount=0,
                transferDeadLetterMessageCount=0,
            ),
        ),
    )


def _probe(
    probe_id: str,
    path: str,
) -> acceptance.Wc029UrlProbeEvidence:
    return acceptance.Wc029UrlProbeEvidence(
        schemaVersion=acceptance.URL_PROBE_SCHEMA_VERSION,
        probeId=probe_id,
        endpointId="presentation",
        url="https://athena.synthetic.invalid" + path,
        observedAt=_NOW,
        statusCode=200,
        contentType="application/json",
        responseBodySha256="sha256:" + ("7" * 64),
        tlsVerified=True,
        approvedNetworkLocation=True,
    )


def _build_bundle(tmp_path: Path) -> BundleFixture:
    root = tmp_path / "evidence"
    output = tmp_path / "records"
    root.mkdir(parents=True)
    output.mkdir(parents=True)
    declarations: list[dict[str, object]] = []
    global_ids: list[str] = []
    artifact_paths: dict[str, Path] = {}
    artifact_digests: dict[str, str] = {}

    incident = _incident_assets()
    monitoring, _, monitoring_anchor, monitoring_record = _trusted_signed_handoff()
    change, change_key = _signed_change()
    monitoring_key = KeyMaterial(
        purpose="monitoring",
        key_id=monitoring_anchor.key_vault_key_id,
        public_key=monitoring_record.public_key,
        fingerprint=monitoring_anchor.public_key_fingerprint,
    )
    keys = {
        **incident.keys,
        "change": change_key,
        "monitoring": monitoring_key,
    }

    def add(
        artifact_id: str,
        evidence_class: str,
        value: object,
        *,
        global_evidence: bool = False,
        deployment_id: str | None = None,
        preflight_kind: str | None = None,
        queue_scope: str | None = None,
        signing_key_purpose: str | None = None,
        binds_artifact_id: str | None = None,
    ) -> str:
        path = root / "artifacts" / f"{artifact_id}.json"
        raw = _write(path, value)
        artifact_paths[artifact_id] = path
        artifact_digests[artifact_id] = sha256_hex(raw)
        declaration: dict[str, object] = {
            "artifactId": artifact_id,
            "evidenceClass": evidence_class,
            "path": path.relative_to(root).as_posix(),
        }
        expected_schema = acceptance._EXPECTED_SCHEMA_BY_CLASS[evidence_class]
        if expected_schema is not None:
            declaration["expectedSchemaVersion"] = expected_schema
        if deployment_id is not None:
            declaration["deploymentId"] = deployment_id
        if preflight_kind is not None:
            declaration["preflightKind"] = preflight_kind
        if queue_scope is not None:
            declaration["queueScope"] = queue_scope
        expected_purpose = acceptance._SIGNED_KEY_PURPOSE_BY_CLASS.get(evidence_class)
        selected_purpose = signing_key_purpose or expected_purpose
        if selected_purpose is not None:
            declaration["signingKeyPurpose"] = selected_purpose
        if binds_artifact_id is not None:
            declaration["bindsArtifactId"] = binds_artifact_id
        declarations.append(declaration)
        if global_evidence:
            global_ids.append(artifact_id)
        return artifact_id

    for purpose in sorted(keys):
        key = keys[purpose]
        add(
            f"key-{purpose}",
            "signing-public-key",
            acceptance.Wc029SigningPublicKeyEvidence(
                schemaVersion=acceptance.SIGNING_PUBLIC_KEY_SCHEMA_VERSION,
                purpose=purpose,
                keyVaultKeyId=key.key_id,
                publicKeyFingerprint=key.fingerprint,
                publicKeyPem=_public_key_pem(key.public_key),
            ),
            global_evidence=True,
            signing_key_purpose=purpose,
        )

    inventory = acceptance.Wc029VersionInventory(
        schemaVersion=acceptance.VERSION_INVENTORY_SCHEMA_VERSION,
        sourceCommit=_SOURCE_COMMIT,
        deployments=(
            acceptance.Wc029DeploymentVersion(
                deploymentId="foundation",
                deploymentName="wc029-foundation-synthetic",
                stage="foundation",
                templateSha256=_TEMPLATE_DIGEST,
            ),
        ),
        images=(
            acceptance.Wc029ImageVersion(
                component="acceptance",
                image=_IMAGE,
            ),
        ),
        endpoints=(
            acceptance.Wc029EndpointVersion(
                endpointId="presentation",
                origin="https://athena.synthetic.invalid",
                allowedPaths=("/healthz", "/runtime-manifest.json"),
            ),
        ),
        principalIds=(_PRINCIPAL_ID,),
        manifest=acceptance.Wc029ManifestVersion(
            manifestId="synthetic-workload",
            manifestVersion="2026.09.14",
            profileId="production",
            manifestDigest=_MANIFEST_DIGEST,
            publicationStatus="published",
        ),
        keys=tuple(
            acceptance.Wc029KeyVersion(
                purpose=purpose,
                keyVaultKeyId=keys[purpose].key_id,
                publicKeyFingerprint=keys[purpose].fingerprint,
                publicKeyArtifactId=f"key-{purpose}",
            )
            for purpose in sorted(keys)
        ),
    )
    add(
        "version-inventory",
        "version-inventory",
        inventory,
        global_evidence=True,
    )

    what_if = {"status": "Succeeded", "properties": {"changes": []}}
    what_if_id = add(
        "foundation-what-if",
        "deployment-what-if",
        what_if,
        global_evidence=True,
        deployment_id="foundation",
    )
    plan = acceptance.Wc029DeploymentPlanEvidence(
        schemaVersion="athena.wc029DeploymentPlan.v1",
        stage="foundation",
        sourceCommit=_SOURCE_COMMIT,
        subscriptionId="00000000-0000-0000-0000-000000000000",
        location="australiaeast",
        deploymentName="wc029-foundation-synthetic",
        templatePath="infra/wc013-live-acceptance/main.bicep",
        templateSha256=_TEMPLATE_DIGEST,
        orchestratorSha256="sha256:" + ("8" * 64),
        preflightSha256=acceptance._preflight_implementation_sha256(),
        baseParameterPath="C:/synthetic/wc029.parameters.json",
        baseParameterSha256="sha256:" + ("9" * 64),
        effectiveParameterPath="C:/synthetic/foundation.parameters.json",
        effectiveParameterSha256="sha256:" + ("a" * 64),
        whatIfPath="C:/synthetic/foundation.what-if.json",
        whatIfSha256=artifact_digests[what_if_id],
        allowedChangeResourceIds=(),
    )
    plan_id = add(
        "foundation-plan",
        "deployment-plan",
        plan,
        global_evidence=True,
        deployment_id="foundation",
    )
    outputs = {
        "acceptanceImage": _IMAGE,
        "presentationHttpsUrl": "https://athena.synthetic.invalid",
    }
    handoff = acceptance.Wc029DeploymentHandoffEvidence(
        schemaVersion="athena.wc029DeploymentHandoff.v1",
        stage="foundation",
        sourceCommit=_SOURCE_COMMIT,
        subscriptionId="00000000-0000-0000-0000-000000000000",
        deploymentName="wc029-foundation-synthetic",
        outputs=outputs,
        outputsSha256=sha256_hex(canonicalize_json(outputs)),
        parameterBindings={"location": "australiaeast"},
        parameterBindingsSha256=sha256_hex(canonicalize_json({"location": "australiaeast"})),
        planManifestSha256=artifact_digests[plan_id],
    )
    handoff_id = add(
        "foundation-output",
        "deployment-output",
        handoff,
        global_evidence=True,
        deployment_id="foundation",
        binds_artifact_id=plan_id,
    )
    readback = acceptance.Wc029DeploymentReadbackEvidence(
        schemaVersion=acceptance.DEPLOYMENT_READBACK_SCHEMA_VERSION,
        stage="foundation",
        sourceCommit=_SOURCE_COMMIT,
        subscriptionId=handoff.subscription_id,
        deploymentName=handoff.deployment_name,
        observedAt=_NOW,
        provisioningState="Succeeded",
        outputHandoffSha256=artifact_digests[handoff_id],
        outputs=outputs,
        outputsSha256=handoff.outputs_sha256,
    )
    readback_id = add(
        "foundation-readback",
        "deployment-readback",
        readback,
        global_evidence=True,
        deployment_id="foundation",
        binds_artifact_id=handoff_id,
    )

    effective_rbac = [
        {
            "principalId": _PRINCIPAL_ID,
            "roleDefinitionName": "Storage Blob Data Reader",
            "scope": (
                "/subscriptions/00000000-0000-0000-0000-000000000000/"
                "resourceGroups/rg-athena-wc029-synthetic/providers/"
                "Microsoft.Storage/storageAccounts/synthetic/blobServices/"
                "default/containers/evidence"
            ),
        }
    ]
    rbac_id = add(
        "effective-rbac",
        "effective-rbac",
        effective_rbac,
        global_evidence=True,
    )
    rbac_policy = {
        "allowedBroadAssignments": [],
        "separationRules": [
            {
                "principalId": _PRINCIPAL_ID,
                "forbiddenRoleNames": ["Contributor", "Reader"],
                "forbiddenScopePrefixes": [
                    "/subscriptions/00000000-0000-0000-0000-000000000000/"
                    "resourceGroups/rg-athena-demo-workload"
                ],
            }
        ],
    }
    policy_id = add(
        "rbac-policy",
        "rbac-policy",
        rbac_policy,
        global_evidence=True,
    )
    add(
        "what-if-preflight",
        "preflight-result",
        acceptance.Wc029PreflightResultEvidence(
            schemaVersion=acceptance.PREFLIGHT_RESULT_SCHEMA_VERSION,
            kind="what-if",
            deploymentId="foundation",
            inputArtifactId=what_if_id,
            inputSha256=artifact_digests[what_if_id],
            validatorSha256=acceptance._preflight_implementation_sha256(),
            safe=True,
            violations=(),
        ),
        global_evidence=True,
        preflight_kind="what-if",
    )
    add(
        "rbac-preflight",
        "preflight-result",
        acceptance.Wc029PreflightResultEvidence(
            schemaVersion=acceptance.PREFLIGHT_RESULT_SCHEMA_VERSION,
            kind="rbac",
            inputArtifactId=rbac_id,
            inputSha256=artifact_digests[rbac_id],
            policyArtifactId=policy_id,
            policySha256=artifact_digests[policy_id],
            validatorSha256=acceptance._preflight_implementation_sha256(),
            safe=True,
            violations=(),
        ),
        global_evidence=True,
        preflight_kind="rbac",
    )
    add(
        "queue-baseline",
        "queue-state",
        _queue_state("baseline"),
        global_evidence=True,
        queue_scope="baseline",
    )
    add(
        "queue-final",
        "queue-state",
        _queue_state("final"),
        global_evidence=True,
        queue_scope="final",
    )
    add(
        "probe-health",
        "url-probe",
        _probe("presentation-health", "/healthz"),
        global_evidence=True,
    )
    add(
        "probe-runtime-manifest",
        "url-probe",
        _probe("presentation-runtime-manifest", "/runtime-manifest.json"),
        global_evidence=True,
    )
    global_execution = _job_execution(
        execution_id="foundation-execution",
        scope="global",
    )
    global_execution_id = add(
        "global-job-execution",
        "job-execution",
        global_execution,
        global_evidence=True,
    )
    add(
        "global-job-readback",
        "job-readback",
        _job_readback(
            global_execution,
            result_artifacts=[
                (readback_id, artifact_digests[readback_id]),
            ],
        ),
        global_evidence=True,
        binds_artifact_id=global_execution_id,
    )

    scenarios: list[dict[str, object]] = []
    for scenario_class in acceptance.REQUIRED_SCENARIO_CLASSES:
        scenario_id = f"scenario-{scenario_class}"
        mode = _SCENARIO_MODES[scenario_class]
        phases: dict[str, list[str]] = {
            "plan": [],
            "apply": [],
            "observe": [],
            "recover": [],
            "verify": [],
        }

        def add_scenario(
            suffix: str,
            evidence_class: str,
            value: object,
            *,
            phase: str,
            queue_scope: str | None = None,
            binds_artifact_id: str | None = None,
            _scenario_id: str = scenario_id,
            _phases: dict[str, list[str]] = phases,
        ) -> str:
            artifact_id = add(
                f"{_scenario_id}-{suffix}",
                evidence_class,
                value,
                queue_scope=queue_scope,
                binds_artifact_id=binds_artifact_id,
            )
            _phases[phase].append(artifact_id)
            return artifact_id

        scenario_plan = _scenario_plan(scenario_id, scenario_class, mode)
        add_scenario("plan", "scenario-plan", scenario_plan, phase="plan")
        mutation = _mutation(scenario_plan)
        add_scenario("mutation", "mutation-receipt", mutation, phase="apply")
        monitoring_id = add_scenario(
            "monitoring",
            "monitoring-evidence",
            monitoring,
            phase="observe",
        )
        report_id = add_scenario(
            "report",
            "correlation-report",
            incident.report,
            phase="observe",
        )
        report_attestation_id = add_scenario(
            "report-attestation",
            "correlation-report-attestation",
            incident.report_attestation,
            phase="observe",
            binds_artifact_id=report_id,
        )
        if scenario_class == "nsg-connectivity-loss":
            add_scenario(
                "change",
                "change-evidence",
                change,
                phase="observe",
            )
        if mode == "correlation-only":
            add_scenario(
                "incident-omission",
                "incident-omission",
                acceptance.Wc029IncidentOmission(
                    schemaVersion=acceptance.INCIDENT_OMISSION_SCHEMA_VERSION,
                    scenarioId=scenario_id,
                    reasonCode="unsupported-incident-producer",
                    incidentEvidenceExpected=False,
                    incidentEvidenceObserved=False,
                    syntheticIncidentEvidenceCreated=False,
                    observedAt=_NOW,
                    detail=("Synthetic scenario has no reviewed incident producer."),
                ),
                phase="observe",
            )
        else:
            active_state_id = add_scenario(
                "incident-active",
                "incident-state-active",
                incident.active_state,
                phase="observe",
            )
            add_scenario(
                "incident-active-attestation",
                "incident-state-active-attestation",
                incident.active_state_attestation,
                phase="observe",
                binds_artifact_id=active_state_id,
            )
            add_scenario(
                "manifest-citation",
                "manifest-citation",
                _manifest_citation(
                    scenario_id,
                    incident.report,
                    incident.active_state,
                ),
                phase="observe",
            )
            guidance_id = add_scenario(
                "guidance",
                "guidance",
                incident.guidance,
                phase="observe",
            )
            add_scenario(
                "guidance-attestation",
                "guidance-attestation",
                incident.guidance_attestation,
                phase="observe",
                binds_artifact_id=guidance_id,
            )
            enrichment_id = add_scenario(
                "enrichment",
                "enrichment-manifest",
                incident.enrichment,
                phase="observe",
            )
            add_scenario(
                "enrichment-attestation",
                "enrichment-attestation",
                incident.enrichment_attestation,
                phase="observe",
                binds_artifact_id=enrichment_id,
            )
            active_feed_id = add_scenario(
                "feed-active",
                "feed-active",
                incident.active_feed,
                phase="observe",
            )
            add_scenario(
                "feed-active-attestation",
                "feed-active-attestation",
                incident.active_feed_attestation,
                phase="observe",
                binds_artifact_id=active_feed_id,
            )
            add_scenario(
                "notification-active",
                "notification-active",
                incident.active_notification,
                phase="observe",
            )

        recovery = _recovery_action(scenario_plan, mutation)
        recovery_id = add_scenario(
            "recovery-action",
            "recovery-action",
            recovery,
            phase="recover",
        )
        execution = _job_execution(
            execution_id=f"{scenario_id}-verify",
            scope="scenario",
            scenario_id=scenario_id,
            phase="verify",
        )
        execution_id = add_scenario(
            "verify-execution",
            "job-execution",
            execution,
            phase="verify",
        )
        readback_id = add_scenario(
            "verify-readback",
            "job-readback",
            _job_readback(
                execution,
                result_artifacts=[
                    (monitoring_id, artifact_digests[monitoring_id]),
                    (report_id, artifact_digests[report_id]),
                    (
                        report_attestation_id,
                        artifact_digests[report_attestation_id],
                    ),
                    (recovery_id, artifact_digests[recovery_id]),
                ],
            ),
            phase="verify",
            binds_artifact_id=execution_id,
        )
        proof_ids = [readback_id]
        if mode == "incident-producing":
            resolved_state_id = add_scenario(
                "incident-resolved",
                "incident-state-resolved",
                incident.resolved_state,
                phase="verify",
            )
            add_scenario(
                "incident-resolved-attestation",
                "incident-state-resolved-attestation",
                incident.resolved_state_attestation,
                phase="verify",
                binds_artifact_id=resolved_state_id,
            )
            resolved_feed_id = add_scenario(
                "feed-resolved",
                "feed-resolved",
                incident.resolved_feed,
                phase="verify",
            )
            add_scenario(
                "feed-resolved-attestation",
                "feed-resolved-attestation",
                incident.resolved_feed_attestation,
                phase="verify",
                binds_artifact_id=resolved_feed_id,
            )
            add_scenario(
                "notification-resolved",
                "notification-resolved",
                incident.resolved_notification,
                phase="verify",
            )
            queue_id = add_scenario(
                "queue",
                "queue-state",
                _queue_state("scenario-verify", scenario_id=scenario_id),
                phase="verify",
                queue_scope="scenario-verify",
            )
            proof_ids.append(queue_id)
        add_scenario(
            "recovery-proof",
            "recovery-proof",
            _recovery_proof(
                scenario_plan,
                mutation,
                recovery,
                evidence_ids=proof_ids,
            ),
            phase="verify",
        )
        scenarios.append(
            {
                "scenarioId": scenario_id,
                "scenarioClass": scenario_class,
                "evidenceMode": mode,
                "phases": phases,
            }
        )

    index = {
        "schemaVersion": acceptance.ACCEPTANCE_INDEX_SCHEMA_VERSION,
        "acceptanceId": "wc029-acceptance-synthetic-001",
        "versionInventoryArtifactId": "version-inventory",
        "artifacts": declarations,
        "globalArtifactIds": global_ids,
        "scenarios": scenarios,
    }
    _write(root / "acceptance-index.json", index)
    return BundleFixture(
        root=root,
        output=output,
        index=index,
        artifact_paths=artifact_paths,
        keys=keys,
    )


def _rewrite_index(bundle: BundleFixture) -> None:
    _write(bundle.root / "acceptance-index.json", bundle.index)


def _declaration(bundle: BundleFixture, artifact_id: str) -> dict[str, Any]:
    return next(item for item in bundle.index["artifacts"] if item["artifactId"] == artifact_id)


def _scenario(bundle: BundleFixture, scenario_class: str) -> dict[str, Any]:
    return next(
        item for item in bundle.index["scenarios"] if item["scenarioClass"] == scenario_class
    )


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_aggregate_builds_deterministic_content_addressed_record(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)

    first = acceptance.aggregate_acceptance_evidence(bundle.root)
    second = acceptance.aggregate_acceptance_evidence(bundle.root)

    assert first == second
    assert first.aggregate_digest == compute_artifact_digest(first._digest_payload())
    assert first.validation_mode == "offline-contract-digest-and-signature"
    assert first.azure_mutation_performed is False
    assert first.incident_evidence_synthesized is False
    assert first.version_inventory.source_commit == _SOURCE_COMMIT
    assert {item.evidence_mode for item in first.scenarios} == {
        "correlation-only",
        "incident-producing",
    }
    output = acceptance.write_acceptance_record(
        first,
        output_directory=bundle.output,
        evidence_root=bundle.root,
    )
    assert output.name.endswith(first.aggregate_digest.removeprefix("sha256:") + ".json")
    assert output.read_bytes() == first.canonical_bytes()


def test_cli_writes_record_and_reports_digest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _build_bundle(tmp_path)

    result = acceptance.main(
        [
            str(bundle.root),
            "--output-directory",
            str(bundle.output),
        ]
    )

    assert result == 0
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["complete"] is True
    assert rendered["aggregateDigest"].startswith("sha256:")
    assert Path(rendered["output"]).is_file()


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-scenario",
        "duplicate-artifact-id",
        "duplicate-path",
        "duplicate-version-inventory",
        "duplicate-recovery-proof",
        "unknown-reference",
        "duplicate-reference",
        "index-alias",
    ],
)
def test_index_rejects_missing_duplicate_and_aliased_inputs(
    tmp_path: Path,
    mutation: str,
) -> None:
    bundle = _build_bundle(tmp_path)
    if mutation == "missing-scenario":
        bundle.index["scenarios"].pop()
    elif mutation == "duplicate-artifact-id":
        bundle.index["artifacts"][1]["artifactId"] = bundle.index["artifacts"][0]["artifactId"]
    elif mutation == "duplicate-path":
        bundle.index["artifacts"][1]["path"] = bundle.index["artifacts"][0]["path"]
    elif mutation == "duplicate-version-inventory":
        duplicate = dict(_declaration(bundle, "version-inventory"))
        duplicate["artifactId"] = "version-inventory-copy"
        duplicate_path = bundle.root / "artifacts" / "version-inventory-copy.json"
        duplicate["path"] = duplicate_path.relative_to(bundle.root).as_posix()
        duplicate_path.write_bytes(bundle.artifact_paths["version-inventory"].read_bytes())
        bundle.index["artifacts"].append(duplicate)
        bundle.index["globalArtifactIds"].append("version-inventory-copy")
    elif mutation == "duplicate-recovery-proof":
        scenario = _scenario(bundle, "disk-capacity-pressure")
        source_id = "scenario-disk-capacity-pressure-recovery-proof"
        duplicate = dict(_declaration(bundle, source_id))
        duplicate["artifactId"] = "scenario-disk-capacity-pressure-proof-copy"
        duplicate_path = (
            bundle.root / "artifacts" / "scenario-disk-capacity-pressure-proof-copy.json"
        )
        duplicate["path"] = duplicate_path.relative_to(bundle.root).as_posix()
        duplicate_path.write_bytes(bundle.artifact_paths[source_id].read_bytes())
        bundle.index["artifacts"].append(duplicate)
        scenario["phases"]["verify"].append(duplicate["artifactId"])
    elif mutation == "unknown-reference":
        bundle.index["globalArtifactIds"][0] = "unknown-artifact"
    elif mutation == "duplicate-reference":
        bundle.index["globalArtifactIds"].append(bundle.index["globalArtifactIds"][0])
    else:
        _declaration(bundle, "version-inventory")["path"] = "acceptance-index.json"
    _rewrite_index(bundle)

    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        acceptance.aggregate_acceptance_evidence(bundle.root)


def test_rejects_missing_and_unlisted_files(tmp_path: Path) -> None:
    unlisted = _build_bundle(tmp_path / "unlisted")
    _write(unlisted.root / "artifacts" / "unlisted.json", {"unexpected": True})
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="unlisted"):
        acceptance.aggregate_acceptance_evidence(unlisted.root)

    missing = _build_bundle(tmp_path / "missing")
    missing.artifact_paths["global-job-readback"].unlink()
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="missing"):
        acceptance.aggregate_acceptance_evidence(missing.root)


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../escape.json",
        "/absolute.json",
        "artifacts\\escape.json",
        "artifacts/../escape.json",
        "artifacts/evidence.txt",
        "C:/escape.json",
    ],
)
def test_rejects_unsafe_paths(tmp_path: Path, unsafe_path: str) -> None:
    bundle = _build_bundle(tmp_path)
    _declaration(bundle, "global-job-readback")["path"] = unsafe_path
    _rewrite_index(bundle)

    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        acceptance.aggregate_acceptance_evidence(bundle.root)


def test_rejects_symlinked_evidence(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    target = bundle.artifact_paths["global-job-readback"]
    outside = tmp_path / "outside.json"
    _write(outside, {"synthetic": True})
    target.unlink()
    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="symbolic link|reparse point",
    ):
        acceptance.aggregate_acceptance_evidence(bundle.root)


def test_rejects_hardlinked_evidence(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    target = bundle.artifact_paths["global-job-readback"]
    alias = tmp_path / "hardlink-alias.json"
    try:
        os.link(target, alias)
    except OSError:
        pytest.skip("hard-link creation is unavailable")

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="singly linked",
    ):
        acceptance.aggregate_acceptance_evidence(bundle.root)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"{", "strict canonicalizable"),
        (b"\xff", "strict canonicalizable"),
        (b'{"value":1,"value":2}', "duplicate object key"),
        (b'{"value":NaN}', "invalid constant"),
    ],
)
def test_rejects_malformed_json(
    tmp_path: Path,
    payload: bytes,
    message: str,
) -> None:
    bundle = _build_bundle(tmp_path)
    bundle.artifact_paths["global-job-readback"].write_bytes(payload)

    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match=message):
        acceptance.aggregate_acceptance_evidence(bundle.root)


def test_rejects_unknown_or_noncanonical_contract_schema(tmp_path: Path) -> None:
    unknown = _build_bundle(tmp_path / "unknown")
    report = _read_json(unknown.artifact_paths["scenario-disk-capacity-pressure-report"])
    report["schemaVersion"] = "synthetic.unreviewed.v1"
    _write(
        unknown.artifact_paths["scenario-disk-capacity-pressure-report"],
        report,
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="wrong schemaVersion",
    ):
        acceptance.aggregate_acceptance_evidence(unknown.root)

    noncanonical = _build_bundle(tmp_path / "noncanonical")
    path = noncanonical.artifact_paths["foundation-plan"]
    path.write_text(
        json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=2),
        encoding="utf-8",
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="canonical contract bytes",
    ):
        acceptance.aggregate_acceptance_evidence(noncanonical.root)


def test_rejects_individual_and_aggregate_oversize_before_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    individual = _build_bundle(tmp_path / "individual")
    individual.artifact_paths["global-job-readback"].write_bytes(
        b'{"value":"' + (b"x" * acceptance.MAX_ARTIFACT_TRANSFER_BYTES) + b'"}'
    )
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="between 1 and"):
        acceptance.aggregate_acceptance_evidence(individual.root)

    aggregate = _build_bundle(tmp_path / "aggregate")
    monkeypatch.setattr(
        acceptance,
        "MAX_TOTAL_EVIDENCE_BYTES",
        sum(path.stat().st_size for path in aggregate.artifact_paths.values()) - 1,
    )
    called = False

    def fail_if_loaded(*_args: object, **_kwargs: object) -> acceptance._LoadedArtifact:
        nonlocal called
        called = True
        raise AssertionError("artifact loading should not begin")

    monkeypatch.setattr(acceptance, "_load_artifact", fail_if_loaded)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="total byte"):
        acceptance.aggregate_acceptance_evidence(aggregate.root)
    assert called is False


def test_rejects_failed_deployment_and_job_evidence(tmp_path: Path) -> None:
    deployment = _build_bundle(tmp_path / "deployment")
    readback = _read_json(deployment.artifact_paths["foundation-readback"])
    readback["provisioningState"] = "Failed"
    _write(deployment.artifact_paths["foundation-readback"], readback)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="violates"):
        acceptance.aggregate_acceptance_evidence(deployment.root)

    job = _build_bundle(tmp_path / "job")
    readback = _read_json(job.artifact_paths["global-job-readback"])
    readback["status"] = "Failed"
    _write(job.artifact_paths["global-job-readback"], readback)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="violates"):
        acceptance.aggregate_acceptance_evidence(job.root)


def test_rejects_rbac_gaps_and_failed_preflight(tmp_path: Path) -> None:
    missing_principal = _build_bundle(tmp_path / "principal")
    rbac = json.loads(
        missing_principal.artifact_paths["effective-rbac"].read_text(encoding="utf-8")
    )
    rbac[0]["principalId"] = "00000000-0000-0000-0000-000000000099"
    _write(missing_principal.artifact_paths["effective-rbac"], rbac)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        acceptance.aggregate_acceptance_evidence(missing_principal.root)

    violation = _build_bundle(tmp_path / "violation")
    rbac = json.loads(violation.artifact_paths["effective-rbac"].read_text(encoding="utf-8"))
    rbac[0]["roleDefinitionName"] = "Reader"
    rbac[0]["scope"] = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload"
    )
    _write(violation.artifact_paths["effective-rbac"], rbac)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        acceptance.aggregate_acceptance_evidence(violation.root)

    stale_result = _build_bundle(tmp_path / "result")
    result = _read_json(stale_result.artifact_paths["rbac-preflight"])
    result["inputSha256"] = "sha256:" + ("f" * 64)
    _write(stale_result.artifact_paths["rbac-preflight"], result)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="bind"):
        acceptance.aggregate_acceptance_evidence(stale_result.root)


def test_rejects_image_manifest_and_key_version_drift(tmp_path: Path) -> None:
    image = _build_bundle(tmp_path / "image")
    execution = _read_json(image.artifact_paths["global-job-execution"])
    execution["image"] = "synthetic.azurecr.io/athena/wc029-acceptance@sha256:" + ("f" * 64)
    payload = dict(execution)
    payload.pop("executionDigest")
    execution["executionDigest"] = compute_artifact_digest(payload)
    _write(image.artifact_paths["global-job-execution"], execution)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="inventoried"):
        acceptance.aggregate_acceptance_evidence(image.root)

    manifest = _build_bundle(tmp_path / "manifest")
    citation_path = manifest.artifact_paths["scenario-web-tier-failure-manifest-citation"]
    citation = _read_json(citation_path)
    citation["manifestDigest"] = "sha256:" + ("f" * 64)
    payload = dict(citation)
    payload.pop("citationDigest")
    citation["citationDigest"] = compute_artifact_digest(payload)
    _write(citation_path, citation)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="published"):
        acceptance.aggregate_acceptance_evidence(manifest.root)

    key = _build_bundle(tmp_path / "key")
    attestation_path = key.artifact_paths["scenario-web-tier-failure-guidance-attestation"]
    attestation = _read_json(attestation_path)
    attestation["keyVaultKeyId"] = key.keys["report"].key_id
    _write(attestation_path, attestation)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        acceptance.aggregate_acceptance_evidence(key.root)


def test_rejects_wrong_subject_digest_and_forged_signature(tmp_path: Path) -> None:
    digest = _build_bundle(tmp_path / "digest")
    path = digest.artifact_paths["scenario-web-tier-failure-guidance-attestation"]
    payload = _read_json(path)
    payload["signedPreimageDigest"] = "sha256:" + ("f" * 64)
    _write(path, payload)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        acceptance.aggregate_acceptance_evidence(digest.root)

    signature = _build_bundle(tmp_path / "signature")
    path = signature.artifact_paths["scenario-web-tier-failure-guidance-attestation"]
    payload = _read_json(path)
    payload["detachedSignature"] = "Zm9yZ2Vk"
    _write(path, payload)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="invalid RSA signature",
    ):
        acceptance.aggregate_acceptance_evidence(signature.root)


def test_correlation_only_requires_omission_and_forbids_incident_evidence(
    tmp_path: Path,
) -> None:
    missing = _build_bundle(tmp_path / "missing")
    scenario = _scenario(missing, "disk-capacity-pressure")
    omission_id = "scenario-disk-capacity-pressure-incident-omission"
    scenario["phases"]["observe"].remove(omission_id)
    missing.index["artifacts"] = [
        item for item in missing.index["artifacts"] if item["artifactId"] != omission_id
    ]
    missing.artifact_paths[omission_id].unlink()
    _rewrite_index(missing)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        acceptance.aggregate_acceptance_evidence(missing.root)

    forbidden = _build_bundle(tmp_path / "forbidden")
    scenario = _scenario(forbidden, "disk-capacity-pressure")
    source_id = "scenario-web-tier-failure-incident-active"
    copied_id = "scenario-disk-capacity-pressure-incident-active"
    source = forbidden.artifact_paths[source_id]
    destination = forbidden.root / "artifacts" / f"{copied_id}.json"
    destination.write_bytes(source.read_bytes())
    declaration = dict(_declaration(forbidden, source_id))
    declaration["artifactId"] = copied_id
    declaration["path"] = destination.relative_to(forbidden.root).as_posix()
    forbidden.index["artifacts"].append(declaration)
    scenario["phases"]["observe"].append(copied_id)
    _rewrite_index(forbidden)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        acceptance.aggregate_acceptance_evidence(forbidden.root)


def test_scenario_phase_chain_and_job_result_binding_fail_closed(
    tmp_path: Path,
) -> None:
    target = _build_bundle(tmp_path / "target")
    mutation_path = target.artifact_paths["scenario-disk-capacity-pressure-mutation"]
    mutation = _read_json(mutation_path)
    mutation["targetResourceId"] = _TARGETS["vm-failure"]
    payload = dict(mutation)
    payload.pop("resultDigest")
    mutation["resultDigest"] = compute_artifact_digest(payload)
    _write(mutation_path, mutation)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="phase receipts"):
        acceptance.aggregate_acceptance_evidence(target.root)

    result = _build_bundle(tmp_path / "result")
    readback_path = result.artifact_paths["scenario-disk-capacity-pressure-verify-readback"]
    readback = _read_json(readback_path)
    readback["resultArtifacts"][0]["contentSha256"] = "sha256:" + ("f" * 64)
    payload = dict(readback)
    payload.pop("readbackDigest")
    readback["readbackDigest"] = compute_artifact_digest(payload)
    _write(readback_path, readback)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="result artifact reference",
    ):
        acceptance.aggregate_acceptance_evidence(result.root)


def test_incident_chain_requires_resolved_state_and_queue_drain(
    tmp_path: Path,
) -> None:
    state = _build_bundle(tmp_path / "state")
    resolved_path = state.artifact_paths["scenario-web-tier-failure-incident-resolved"]
    resolved = _read_json(resolved_path)
    resolved["lifecycle"] = "active"
    _write(resolved_path, resolved)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        acceptance.aggregate_acceptance_evidence(state.root)

    queue = _build_bundle(tmp_path / "queue")
    queue_path = queue.artifact_paths["scenario-web-tier-failure-queue"]
    queue_payload = _read_json(queue_path)
    queue_payload["queues"][0]["deadLetterMessageCount"] = 1
    _write(queue_path, queue_payload)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="violates"):
        acceptance.aggregate_acceptance_evidence(queue.root)


@pytest.mark.parametrize(
    "url",
    [
        "https://unrelated.synthetic.invalid/healthz",
        "https://athena.synthetic.invalid/other",
        "https://athena.synthetic.invalid/healthz?sig=secret",
        "http://athena.synthetic.invalid/healthz",
        "https://user:secret@athena.synthetic.invalid/healthz",
    ],
)
def test_url_probes_are_bound_to_inventoried_safe_endpoints(
    tmp_path: Path,
    url: str,
) -> None:
    bundle = _build_bundle(tmp_path)
    path = bundle.artifact_paths["probe-health"]
    payload = _read_json(path)
    payload["url"] = url
    _write(path, payload)

    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        acceptance.aggregate_acceptance_evidence(bundle.root)


def test_unreadable_subtree_walk_error_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    real_walk = os.walk

    def failing_walk(
        path: Path,
        *,
        topdown: bool,
        followlinks: bool,
        onerror: Any,
    ) -> Any:
        onerror(PermissionError("synthetic unreadable subtree"))
        return real_walk(
            path,
            topdown=topdown,
            followlinks=followlinks,
            onerror=onerror,
        )

    monkeypatch.setattr(acceptance.os, "walk", failing_walk)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="unreadable subtree",
    ):
        acceptance.aggregate_acceptance_evidence(bundle.root)


def test_output_write_is_exclusive_and_cleans_failed_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    record = acceptance.aggregate_acceptance_evidence(bundle.root)

    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="outside"):
        acceptance.write_acceptance_record(
            record,
            output_directory=bundle.root,
            evidence_root=bundle.root,
        )

    first = acceptance.write_acceptance_record(
        record,
        output_directory=bundle.output,
        evidence_root=bundle.root,
    )
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="overwrite"):
        acceptance.write_acceptance_record(
            record,
            output_directory=bundle.output,
            evidence_root=bundle.root,
        )
    assert first.is_file()

    failed_output = tmp_path / "failed-records"
    failed_output.mkdir()

    def fail_link(_source: Path, _target: Path) -> None:
        raise OSError("synthetic publish failure")

    monkeypatch.setattr(acceptance.os, "link", fail_link)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="created exclusively",
    ):
        acceptance.write_acceptance_record(
            record,
            output_directory=failed_output,
            evidence_root=bundle.root,
        )
    assert list(failed_output.iterdir()) == []


def test_cli_failure_creates_no_record(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _build_bundle(tmp_path)
    bundle.artifact_paths["global-job-readback"].write_text("{", encoding="utf-8")

    result = acceptance.main(
        [
            str(bundle.root),
            "--output-directory",
            str(bundle.output),
        ]
    )

    assert result == 2
    assert json.loads(capsys.readouterr().err)["complete"] is False
    assert list(bundle.output.iterdir()) == []


def test_harness_has_no_azure_network_or_subprocess_execution_path() -> None:
    source = Path(acceptance.__file__).read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "azure.identity" not in source
    assert "azure.mgmt" not in source
    assert "DefaultAzureCredential" not in source
    assert "requests." not in source
    assert "httpx." not in source
    assert "urllib.request" not in source


def test_output_record_contains_only_relative_input_paths(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    record = acceptance.aggregate_acceptance_evidence(bundle.root)

    rendered = record.canonical_json()

    assert str(bundle.root) not in rendered
    assert all(not Path(item.path).is_absolute() for item in record.artifacts)
    assert record.source_index.path == "acceptance-index.json"
