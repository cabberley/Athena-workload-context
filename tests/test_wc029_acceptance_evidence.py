from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, replace
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
    IncidentEnrichmentAssetReference,
    IncidentEnrichmentAttestation,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentEnrichmentManifest,
    IncidentFeedAttestation,
    IncidentFeedEntryV2,
    IncidentFeedIndexAttestationV2,
    IncidentFeedIndexV2,
    IncidentFeedPointer,
    IncidentGuidance,
    IncidentGuidanceAssetReference,
    IncidentGuidanceAttestation,
    IncidentNotificationEnvelopeV2,
    IncidentNotificationV2,
    IncidentNotificationV2Attestation,
    IncidentState,
    IncidentStateAttestation,
    MonitoringEvidenceHandoff,
    PublishedContextAuthority,
    PublishedCorrelationReportAssetReference,
    PublishedCorrelationReportAttestation,
    PublishedCorrelationReportStatement,
    VersionPinnedBlobReference,
    build_incident_enrichment_feed_pointer,
    build_incident_feed_index_v2,
    build_incident_occurrence_receipt,
    canonicalize_json,
    compute_artifact_digest,
    incident_state_signature_preimage,
    sha256_hex,
)
from athena_context.contracts.change_ingestion import (
    change_evidence_attestation_preimage,
)
from athena_context.contracts.monitoring import monitoring_handoff_preimage
from test_presentation_asset_gateway import _resolved_feed_v2_source_fixture
from test_wc024_monitoring_contract import _trusted_signed_handoff
from test_wc026_correlation_contract import _change_pair

_NOW = datetime(2026, 9, 14, 4, 0, tzinfo=UTC)
_SCENARIO_BASE = datetime(2026, 9, 10, 1, 45, tzinfo=UTC)
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
    active_feed_index: IncidentFeedIndexV2
    active_feed_index_attestation: IncidentFeedIndexAttestationV2
    resolved_feed: IncidentEnrichmentFeedPointer
    resolved_feed_attestation: IncidentEnrichmentFeedPointerAttestation
    resolved_feed_index: IncidentFeedIndexV2
    resolved_feed_index_attestation: IncidentFeedIndexAttestationV2
    active_notification: IncidentNotificationEnvelopeV2
    resolved_notification: IncidentNotificationEnvelopeV2
    keys: dict[str, KeyMaterial]
    private_keys: dict[str, rsa.RSAPrivateKey]


@dataclass(frozen=True, slots=True)
class PublicationAssets:
    manifest: acceptance.Wc029PublishedManifestEvidence
    authority: acceptance.Wc029PublicationAuthorityEvidence
    attestation: acceptance.Wc029PublicationAuthorityAttestation
    key: KeyMaterial


@dataclass(frozen=True, slots=True)
class BundleFixture:
    root: Path
    output: Path
    index: dict[str, Any]
    artifact_paths: dict[str, Path]
    keys: dict[str, KeyMaterial]
    private_keys: dict[str, rsa.RSAPrivateKey]
    approved_inventory_sha256: str


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


def _publication_assets() -> tuple[PublicationAssets, rsa.RSAPrivateKey]:
    key, private_key = _private_key_material("context-authority", "a")
    manifest_document = {
        "manifestId": "manifest-synthetic",
        "manifestVersion": "2026.09.14.1",
        "profiles": {
            "production": {
                "profileId": "production",
                "status": "approved",
            }
        },
        "constraints": [
            {
                "clauseId": "synthetic-availability",
                "kind": "availability",
                "required": True,
            }
        ],
    }
    manifest_digest = compute_artifact_digest(manifest_document)
    clause_digest = compute_artifact_digest(manifest_document["constraints"][0])
    manifest = acceptance.Wc029PublishedManifestEvidence(
        schemaVersion=acceptance.PUBLISHED_MANIFEST_SCHEMA_VERSION,
        workloadId="synthetic-wc029",
        manifestId="manifest-synthetic",
        manifestVersion="2026.09.14.1",
        profileId="production",
        manifestDocument=manifest_document,
        citedClauses=(
            acceptance.Wc029PublishedClause(
                clauseId="synthetic-availability",
                jsonPointer="/constraints/0",
                clauseDigest=clause_digest,
            ),
        ),
        publicationRecordDigest="sha256:" + ("1" * 64),
        auditHeadDigest="sha256:" + ("2" * 64),
        publishedAt=_SCENARIO_BASE - timedelta(hours=1),
        manifestDigest=manifest_digest,
    )
    authority_payload: dict[str, object] = {
        "workloadId": manifest.workload_id,
        "manifestId": manifest.manifest_id,
        "manifestVersion": manifest.manifest_version,
        "manifestDigest": manifest.manifest_digest,
        "profileId": manifest.profile_id,
        "resolvedProfileDigest": "sha256:" + ("3" * 64),
        "dependencyGraphDigest": "sha256:" + ("4" * 64),
        "contextBindingPayloadDigest": "sha256:" + ("5" * 64),
        "publicationRecordDigest": manifest.publication_record_digest,
        "auditHeadDigest": manifest.audit_head_digest,
        "publishedAt": manifest.published_at,
    }
    authority_digest = compute_artifact_digest(_json_value(authority_payload))
    authority = PublishedContextAuthority(
        **authority_payload,
        authorityId=("publication-authority-" + authority_digest.removeprefix("sha256:")[:32]),
        authorityDigest=authority_digest,
    )
    authority_evidence = acceptance.Wc029PublicationAuthorityEvidence(
        schemaVersion=acceptance.PUBLICATION_AUTHORITY_SCHEMA_VERSION,
        authority=authority,
    )
    signature = (
        base64.urlsafe_b64encode(
            private_key.sign(
                authority.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    attestation = acceptance.Wc029PublicationAuthorityAttestation(
        schemaVersion=(acceptance.PUBLICATION_AUTHORITY_ATTESTATION_SCHEMA_VERSION),
        authorityId=authority.authority_id,
        authorityDigest=authority.authority_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=key.key_id,
        signedPreimageDigest=sha256_hex(authority.canonical_bytes()),
        detachedSignature=signature,
    )
    return (
        PublicationAssets(
            manifest=manifest,
            authority=authority_evidence,
            attestation=attestation,
            key=key,
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
        private_keys={},
    )


def _trusted_incident_assets(
    publication: PublicationAssets,
) -> IncidentAssets:
    fixture = _resolved_feed_v2_source_fixture()
    payloads = _schema_payloads(fixture)
    active_state = next(
        item
        for item in (
            IncidentState.model_validate_json(payload)
            for payload in payloads["athena.incidentState.v1"]
        )
        if item.lifecycle == "active"
    )
    report = _one_model(
        payloads,
        "athena.wc026CorrelationReport.v1",
        CorrelationReport,
    )
    old_report_attestation = _one_model(
        payloads,
        "athena.wc027PublishedCorrelationReportAttestation.v1",
        PublishedCorrelationReportAttestation,
    )
    guidance = _one_model(
        payloads,
        "athena.wc027IncidentGuidance.v1",
        IncidentGuidance,
    )
    old_enrichment = _one_model(
        payloads,
        "athena.wc027IncidentEnrichmentManifest.v1",
        IncidentEnrichmentManifest,
    )
    old_active_feed = next(
        item
        for item in (
            IncidentEnrichmentFeedPointer.model_validate_json(payload)
            for payload in payloads["athena.wc027IncidentEnrichmentFeedPointer.v2"]
        )
        if item.lifecycle == "active"
    )
    key_pairs = {
        purpose: _private_key_material(purpose, version)
        for purpose, version in (
            ("incident", "b"),
            ("report", "c"),
            ("guidance", "d"),
            ("enrichment", "e"),
            ("feed", "f"),
            ("notification", "1"),
        )
    }
    keys = {purpose: material for purpose, (material, _private) in key_pairs.items()}
    private_keys = {purpose: private for purpose, (_material, private) in key_pairs.items()}

    def sign(purpose: str, payload: bytes) -> str:
        return (
            base64.urlsafe_b64encode(
                private_keys[purpose].sign(
                    payload,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            )
            .decode("ascii")
            .rstrip("=")
        )

    active_state_attestation = IncidentStateAttestation(
        schemaVersion="athena.incidentStateAttestation.v1",
        resultDigest=active_state.result_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["incident"].key_id,
        detachedSignature=sign(
            "incident",
            incident_state_signature_preimage(active_state),
        ),
    )
    statement_payload = old_report_attestation.statement.model_dump(
        mode="python",
        by_alias=True,
        exclude={"statement_id", "statement_digest"},
    )
    statement_payload["authorityProofDigest"] = sha256_hex(
        publication.authority.authority.canonical_bytes()
    )
    statement_digest = compute_artifact_digest(_json_value(statement_payload))
    statement = PublishedCorrelationReportStatement(
        **statement_payload,
        statementId=("report-publication-" + statement_digest.removeprefix("sha256:")[:32]),
        statementDigest=statement_digest,
    )
    report_attestation = PublishedCorrelationReportAttestation(
        schemaVersion=("athena.wc027PublishedCorrelationReportAttestation.v1"),
        statement=statement,
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["report"].key_id,
        signedPreimageDigest=sha256_hex(statement.canonical_bytes()),
        detachedSignature=sign("report", statement.canonical_bytes()),
    )
    report_asset_payload = old_enrichment.correlation_report_asset.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    report_asset_payload.update(
        {
            "authorityProofDigest": statement.authority_proof_digest,
            "publicationStatementId": statement.statement_id,
            "publicationStatementDigest": statement.statement_digest,
            "attestationReference": (
                old_enrichment.correlation_report_asset.attestation_reference.model_copy(
                    update={"content_digest": sha256_hex(report_attestation.canonical_bytes())}
                )
            ),
        }
    )
    report_asset_digest = compute_artifact_digest(_json_value(report_asset_payload))
    report_asset = PublishedCorrelationReportAssetReference(
        **report_asset_payload,
        referenceId=("report-asset-" + report_asset_digest.removeprefix("sha256:")[:32]),
        referenceDigest=report_asset_digest,
    )
    guidance_attestation = IncidentGuidanceAttestation(
        schemaVersion="athena.wc027IncidentGuidanceAttestation.v1",
        guidanceId=guidance.guidance_id,
        guidanceDigest=guidance.guidance_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["guidance"].key_id,
        signedPreimageDigest=sha256_hex(guidance.canonical_bytes()),
        detachedSignature=sign("guidance", guidance.canonical_bytes()),
    )
    enrichment_payload = old_enrichment.model_dump(
        mode="python",
        by_alias=True,
        exclude={"enrichment_id", "manifest_digest"},
    )
    enrichment_payload["correlationReportAsset"] = report_asset
    enrichment_digest = compute_artifact_digest(_json_value(enrichment_payload))
    enrichment = IncidentEnrichmentManifest(
        **enrichment_payload,
        enrichmentId=("incident-enrichment-" + enrichment_digest.removeprefix("sha256:")[:32]),
        manifestDigest=enrichment_digest,
    )
    enrichment_attestation = IncidentEnrichmentAttestation(
        schemaVersion="athena.wc027IncidentEnrichmentAttestation.v1",
        enrichmentId=enrichment.enrichment_id,
        manifestDigest=enrichment.manifest_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["enrichment"].key_id,
        signedPreimageDigest=sha256_hex(enrichment.canonical_bytes()),
        detachedSignature=sign(
            "enrichment",
            enrichment.canonical_bytes(),
        ),
    )
    state_prefix = (
        f"incidents/{active_state.incident_id}/versions/"
        f"{active_state.result_digest.removeprefix('sha256:')}"
    )
    active_enrichment_prefix = f"{state_prefix}/enrichments/{enrichment.enrichment_id}"
    enrichment_asset_payload = old_active_feed.enrichment_asset.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    enrichment_asset_payload.update(
        {
            "enrichmentId": enrichment.enrichment_id,
            "manifestDigest": enrichment.manifest_digest,
            "manifestReference": VersionPinnedBlobReference(
                name=f"{active_enrichment_prefix}/manifest.json",
                version="active-enrichment-version",
                contentDigest=sha256_hex(enrichment.canonical_bytes()),
            ),
            "attestationReference": VersionPinnedBlobReference(
                name=f"{active_enrichment_prefix}/attestation.json",
                version="active-enrichment-attestation-version",
                contentDigest=sha256_hex(enrichment_attestation.canonical_bytes()),
            ),
        }
    )
    enrichment_asset_digest = compute_artifact_digest(_json_value(enrichment_asset_payload))
    active_enrichment_asset = IncidentEnrichmentAssetReference(
        **enrichment_asset_payload,
        referenceId=("enrichment-asset-" + enrichment_asset_digest.removeprefix("sha256:")[:32]),
        referenceDigest=enrichment_asset_digest,
    )
    active_feed_payload = old_active_feed.model_dump(
        mode="python",
        by_alias=True,
        exclude={"pointer_id", "pointer_digest"},
    )
    active_feed_payload["enrichmentAsset"] = active_enrichment_asset
    active_feed_digest = compute_artifact_digest(_json_value(active_feed_payload))
    active_feed = IncidentEnrichmentFeedPointer(
        **active_feed_payload,
        pointerId=("incident-feed-v2-pointer-" + active_feed_digest.removeprefix("sha256:")[:32]),
        pointerDigest=active_feed_digest,
    )
    active_feed_attestation = IncidentEnrichmentFeedPointerAttestation(
        schemaVersion=("athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"),
        pointerId=active_feed.pointer_id,
        pointerDigest=active_feed.pointer_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["feed"].key_id,
        signedPreimageDigest=sha256_hex(active_feed.canonical_bytes()),
        detachedSignature=sign("feed", active_feed.canonical_bytes()),
    )
    active_entry = IncidentFeedEntryV2(
        incidentId=active_state.incident_id,
        lifecycle="active",
        stateResultDigest=active_state.result_digest,
        updatedAt=active_state.updated_at,
        feedPointerReference=VersionPinnedBlobReference(
            name=f"{active_enrichment_prefix}/feed-pointer.json",
            version="active-feed-pointer-version",
            contentDigest=sha256_hex(active_feed.canonical_bytes()),
        ),
        feedPointerAttestationReference=VersionPinnedBlobReference(
            name=f"{active_enrichment_prefix}/feed-pointer-attestation.json",
            version="active-feed-pointer-attestation-version",
            contentDigest=sha256_hex(active_feed_attestation.canonical_bytes()),
        ),
    )
    active_feed_index = build_incident_feed_index_v2(
        active=(active_entry,),
        recently_resolved=(),
        resolved_retention_start=active_feed.published_at - timedelta(days=7),
        resolved_history_truncated=False,
        resolved_history_total_count=0,
        omitted_resolved_count=None,
        source_active_index_digest="sha256:" + ("6" * 64),
        key_id=keys["feed"].key_id,
        key_fingerprint=keys["feed"].fingerprint,
        published_at=active_feed.published_at + timedelta(seconds=1),
    )
    active_feed_index_attestation = IncidentFeedIndexAttestationV2(
        schemaVersion="athena.wc027IncidentFeedIndexAttestation.v2",
        indexDigest=sha256_hex(active_feed_index.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["feed"].key_id,
        detachedSignature=sign(
            "feed",
            active_feed_index.canonical_bytes(),
        ),
    )

    resolved_updated_at = max(
        active_feed_index.published_at,
        report.as_of,
    ) + timedelta(minutes=5)
    resolved_payload = active_state.model_dump(
        mode="python",
        by_alias=True,
        exclude={"result_digest"},
    )
    resolved_payload.update(
        {
            "lifecycle": "resolved",
            "updatedAt": resolved_updated_at,
            "availability": "normal",
            "blastRadius": "none",
            "operatorAttention": "normal",
            "notificationStatus": "pendingDispatch",
        }
    )
    resolved_result_digest = sha256_hex(
        canonicalize_json(_json_value(resolved_payload)).encode("utf-8")
    )
    resolved_state = IncidentState(
        **resolved_payload,
        resultDigest=resolved_result_digest,
    )
    resolved_state_attestation = IncidentStateAttestation(
        schemaVersion="athena.incidentStateAttestation.v1",
        resultDigest=resolved_state.result_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["incident"].key_id,
        detachedSignature=sign(
            "incident",
            incident_state_signature_preimage(resolved_state),
        ),
    )
    resolved_state_prefix = (
        f"incidents/{resolved_state.incident_id}/versions/"
        f"{resolved_state.result_digest.removeprefix('sha256:')}"
    )
    state_reference = VersionPinnedBlobReference(
        name=f"{resolved_state_prefix}/state.json",
        version="resolved-state-version",
        contentDigest=sha256_hex(resolved_state.canonical_bytes()),
    )
    state_attestation_reference = VersionPinnedBlobReference(
        name=f"{resolved_state_prefix}/attestation.json",
        version="resolved-state-attestation-version",
        contentDigest=sha256_hex(resolved_state_attestation.canonical_bytes()),
    )
    source_pointer = IncidentFeedPointer(
        schemaVersion="athena.incidentFeed.v1",
        incidentId=resolved_state.incident_id,
        statePath=f"./{state_reference.name}",
        stateSha256=state_reference.content_digest,
        attestationPath=f"./{state_attestation_reference.name}",
        attestationSha256=state_attestation_reference.content_digest,
        pointerAttestationPath=(f"./{resolved_state_prefix}/pointer-attestation.json"),
        keyId=keys["incident"].key_id,
        keyFingerprint=keys["incident"].fingerprint,
        publishedAt=resolved_state.updated_at + timedelta(seconds=1),
    )
    source_pointer_attestation = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=sha256_hex(source_pointer.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["incident"].key_id,
        detachedSignature=sign(
            "incident",
            source_pointer.canonical_bytes(),
        ),
    )
    occurrence = build_incident_occurrence_receipt(
        resolved_state,
        resolved_state_attestation,
        source_pointer,
        source_pointer_attestation,
        state_reference=state_reference,
        state_attestation_reference=state_attestation_reference,
        pointer_reference=VersionPinnedBlobReference(
            name=f"{resolved_state_prefix}/pointer.json",
            version="resolved-source-pointer-version",
            contentDigest=sha256_hex(source_pointer.canonical_bytes()),
        ),
        pointer_attestation_reference=VersionPinnedBlobReference(
            name=f"{resolved_state_prefix}/pointer-attestation.json",
            version="resolved-source-pointer-attestation-version",
            contentDigest=sha256_hex(source_pointer_attestation.canonical_bytes()),
        ),
    )
    resolved_enrichment_id = "incident-enrichment-" + ("7" * 32)
    resolved_enrichment_prefix = f"{resolved_state_prefix}/enrichments/{resolved_enrichment_id}"
    resolved_asset_payload: dict[str, object] = {
        "schemaVersion": ("athena.wc027IncidentEnrichmentAssetReference.v1"),
        "incidentId": resolved_state.incident_id,
        "incidentStateResultDigest": resolved_state.result_digest,
        "enrichmentId": resolved_enrichment_id,
        "manifestDigest": "sha256:" + ("8" * 64),
        "manifestReference": VersionPinnedBlobReference(
            name=f"{resolved_enrichment_prefix}/manifest.json",
            version="resolved-enrichment-version",
            contentDigest="sha256:" + ("9" * 64),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{resolved_enrichment_prefix}/attestation.json",
            version="resolved-enrichment-attestation-version",
            contentDigest="sha256:" + ("a" * 64),
        ),
    }
    resolved_asset_digest = compute_artifact_digest(_json_value(resolved_asset_payload))
    resolved_enrichment_asset = IncidentEnrichmentAssetReference(
        **resolved_asset_payload,
        referenceId=("enrichment-asset-" + resolved_asset_digest.removeprefix("sha256:")[:32]),
        referenceDigest=resolved_asset_digest,
    )
    resolved_feed = build_incident_enrichment_feed_pointer(
        occurrence,
        resolved_enrichment_asset,
        resolved_state,
        published_at=occurrence.published_at + timedelta(seconds=1),
    )
    resolved_feed_attestation = IncidentEnrichmentFeedPointerAttestation(
        schemaVersion=("athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"),
        pointerId=resolved_feed.pointer_id,
        pointerDigest=resolved_feed.pointer_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["feed"].key_id,
        signedPreimageDigest=sha256_hex(resolved_feed.canonical_bytes()),
        detachedSignature=sign("feed", resolved_feed.canonical_bytes()),
    )
    resolved_entry = IncidentFeedEntryV2(
        incidentId=resolved_state.incident_id,
        lifecycle="resolved",
        stateResultDigest=resolved_state.result_digest,
        updatedAt=resolved_state.updated_at,
        feedPointerReference=VersionPinnedBlobReference(
            name=f"{resolved_enrichment_prefix}/feed-pointer.json",
            version="resolved-feed-pointer-version",
            contentDigest=sha256_hex(resolved_feed.canonical_bytes()),
        ),
        feedPointerAttestationReference=VersionPinnedBlobReference(
            name=(f"{resolved_enrichment_prefix}/feed-pointer-attestation.json"),
            version="resolved-feed-pointer-attestation-version",
            contentDigest=sha256_hex(resolved_feed_attestation.canonical_bytes()),
        ),
    )
    resolved_feed_index = build_incident_feed_index_v2(
        active=(),
        recently_resolved=(resolved_entry,),
        resolved_retention_start=resolved_state.updated_at - timedelta(days=7),
        resolved_history_truncated=False,
        resolved_history_total_count=1,
        omitted_resolved_count=None,
        source_active_index_digest="sha256:" + ("b" * 64),
        key_id=keys["feed"].key_id,
        key_fingerprint=keys["feed"].fingerprint,
        published_at=resolved_feed.published_at + timedelta(seconds=1),
    )
    resolved_feed_index_attestation = IncidentFeedIndexAttestationV2(
        schemaVersion="athena.wc027IncidentFeedIndexAttestation.v2",
        indexDigest=sha256_hex(resolved_feed_index.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["feed"].key_id,
        detachedSignature=sign(
            "feed",
            resolved_feed_index.canonical_bytes(),
        ),
    )
    active_notification = _notification(
        state=active_state,
        pointer=active_feed,
        feed_index=active_feed_index,
        feed_pointer_reference=active_entry.feed_pointer_reference,
        feed_pointer_attestation_reference=(active_entry.feed_pointer_attestation_reference),
        guidance_reference=enrichment.guidance_asset,
        key_id=keys["notification"].key_id,
        private_key=private_keys["notification"],
    )
    resolved_notification = _notification(
        state=resolved_state,
        pointer=resolved_feed,
        feed_index=resolved_feed_index,
        feed_pointer_reference=resolved_entry.feed_pointer_reference,
        feed_pointer_attestation_reference=(resolved_entry.feed_pointer_attestation_reference),
        guidance_reference=_resolved_guidance_reference(resolved_state),
        key_id=keys["notification"].key_id,
        private_key=private_keys["notification"],
    )
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
        active_feed_index=active_feed_index,
        active_feed_index_attestation=active_feed_index_attestation,
        resolved_feed=resolved_feed,
        resolved_feed_attestation=resolved_feed_attestation,
        resolved_feed_index=resolved_feed_index,
        resolved_feed_index_attestation=(resolved_feed_index_attestation),
        active_notification=active_notification,
        resolved_notification=resolved_notification,
        keys=keys,
        private_keys=private_keys,
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


def _signed_monitoring(
    observed_at: datetime,
) -> tuple[
    MonitoringEvidenceHandoff,
    KeyMaterial,
    rsa.RSAPrivateKey,
]:
    source, _, _, _ = _trusted_signed_handoff()
    key, private_key = _private_key_material("monitoring", "2")
    payload = source.model_dump(
        mode="python",
        by_alias=True,
        exclude={"collector_attestation"},
    )
    payload["observedAt"] = observed_at
    preimage = monitoring_handoff_preimage(payload)
    preimage_bytes = canonicalize_json(preimage).encode("utf-8")
    signature = base64.b64encode(
        private_key.sign(
            preimage_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    ).decode("ascii")
    payload["collectorAttestation"] = {
        "signatureAlgorithm": "RS256",
        "trustAnchorRef": key.key_id,
        "signedPreimageDigest": compute_artifact_digest(preimage),
        "signature": signature,
    }
    return MonitoringEvidenceHandoff.model_validate(payload), key, private_key


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
    scenario_execution_id: str | None = None,
    scenario_plan_digest: str | None = None,
    input_digest: str = "sha256:" + ("f" * 64),
    phase: str | None = None,
    started_at: datetime = _NOW,
) -> acceptance.Wc029JobExecutionEvidence:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.JOB_EXECUTION_SCHEMA_VERSION,
        "scope": scope,
        "scenarioId": scenario_id,
        "scenarioExecutionId": scenario_execution_id,
        "scenarioPlanDigest": scenario_plan_digest,
        "inputDigest": input_digest,
        "phase": phase,
        "executionId": execution_id,
        "jobResourceId": _JOB_RESOURCE_ID,
        "sourceCommit": _SOURCE_COMMIT,
        "component": "acceptance",
        "image": _IMAGE,
        "startedAt": started_at,
        "completedAt": started_at + timedelta(minutes=1),
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
        "scenarioExecutionId": execution.scenario_execution_id,
        "scenarioPlanDigest": execution.scenario_plan_digest,
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
    scenario_execution_id: str,
    capability: acceptance.Wc029ScenarioCapability,
    *,
    baseline_state_artifact_id: str,
    baseline_state_digest: str,
    planned_at: datetime,
    monitoring_request_digest: str,
    correlation_request_digest: str,
    change_request_digest: str | None,
    verification_input_digest: str,
) -> acceptance.Wc029ScenarioPlanEvidence:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.SCENARIO_PLAN_SCHEMA_VERSION,
        "scenarioId": scenario_id,
        "scenarioExecutionId": scenario_execution_id,
        "scenarioClass": capability.scenario_class,
        "evidenceMode": capability.evidence_mode,
        "capabilityDigest": capability.capability_digest,
        "sourceCommit": _SOURCE_COMMIT,
        "targetResourceId": capability.target_resource_id,
        "baselineStateDigest": baseline_state_digest,
        "mutationActionDigest": capability.mutation_action_digest,
        "recoveryActionDigest": capability.recovery_action_digest,
        "monitoringRequestDigest": monitoring_request_digest,
        "correlationRequestDigest": correlation_request_digest,
        "changeRequestDigest": change_request_digest,
        "verificationInputDigest": verification_input_digest,
        "baselineStateArtifactId": baseline_state_artifact_id,
        "plannedAt": planned_at,
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
    *,
    applied_at: datetime,
) -> acceptance.Wc029MutationReceipt:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.MUTATION_RECEIPT_SCHEMA_VERSION,
        "scenarioId": plan.scenario_id,
        "scenarioExecutionId": plan.scenario_execution_id,
        "scenarioClass": plan.scenario_class,
        "planDigest": plan.plan_digest,
        "targetResourceId": plan.target_resource_id,
        "mutationActionDigest": plan.mutation_action_digest,
        "appliedAt": applied_at,
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
    *,
    recovered_at: datetime,
) -> acceptance.Wc029RecoveryActionEvidence:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.RECOVERY_ACTION_SCHEMA_VERSION,
        "scenarioId": plan.scenario_id,
        "scenarioExecutionId": plan.scenario_execution_id,
        "scenarioClass": plan.scenario_class,
        "planDigest": plan.plan_digest,
        "mutationReceiptDigest": mutation.result_digest,
        "targetResourceId": plan.target_resource_id,
        "recoveryActionDigest": plan.recovery_action_digest,
        "recoveredAt": recovered_at,
        "completed": True,
    }
    return _digest_bound_model(
        acceptance.Wc029RecoveryActionEvidence,
        payload,
        digest_field="resultDigest",
    )


def _manifest_citation(
    scenario_id: str,
    scenario_execution_id: str,
    publication: PublicationAssets,
    report: CorrelationReport,
    state: IncidentState,
) -> acceptance.Wc029ManifestCitationEvidence:
    payload: dict[str, object] = {
        "schemaVersion": acceptance.MANIFEST_CITATION_SCHEMA_VERSION,
        "scenarioId": scenario_id,
        "scenarioExecutionId": scenario_execution_id,
        "manifestId": publication.manifest.manifest_id,
        "manifestVersion": publication.manifest.manifest_version,
        "profileId": publication.manifest.profile_id,
        "manifestDigest": publication.manifest.manifest_digest,
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
    baseline_state_id: str,
    baseline_state_sha256: str,
    baseline_state_digest: str,
    recovered_state_id: str,
    recovered_state_sha256: str,
    recovered_state_digest: str,
    job_readback_id: str,
    job_readback_sha256: str,
    *,
    evidence_ids: list[str],
    verified_at: datetime,
) -> acceptance.Wc029RecoveryProof:
    return acceptance.Wc029RecoveryProof(
        schemaVersion=acceptance.RECOVERY_PROOF_SCHEMA_VERSION,
        scenarioId=plan.scenario_id,
        scenarioExecutionId=plan.scenario_execution_id,
        scenarioClass=plan.scenario_class,
        planDigest=plan.plan_digest,
        mutationReceiptDigest=mutation.result_digest,
        recoveryActionResultDigest=recovery.result_digest,
        targetResourceId=plan.target_resource_id,
        verifiedAt=verified_at,
        healthy=True,
        residualMutationCount=0,
        baselineState={
            "artifactId": baseline_state_id,
            "contentSha256": baseline_state_sha256,
        },
        recoveredState={
            "artifactId": recovered_state_id,
            "contentSha256": recovered_state_sha256,
        },
        baselineStateDigest=baseline_state_digest,
        recoveredStateDigest=recovered_state_digest,
        postRecoveryJobReadback={
            "artifactId": job_readback_id,
            "contentSha256": job_readback_sha256,
        },
        evidenceArtifactIds=tuple(sorted(evidence_ids)),
    )


def _queue_state(
    scope: str,
    *,
    scenario_id: str | None = None,
    scenario_execution_id: str | None = None,
    captured_at: datetime = _NOW + timedelta(minutes=10),
) -> acceptance.Wc029QueueStateEvidence:
    return acceptance.Wc029QueueStateEvidence(
        schemaVersion=acceptance.QUEUE_STATE_SCHEMA_VERSION,
        captureScope=scope,
        scenarioId=scenario_id,
        scenarioExecutionId=scenario_execution_id,
        capturedAt=captured_at,
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


def _scenario_capability(
    scenario_class: str,
    target_resource_id: str,
    *,
    incident_producing: bool,
) -> acceptance.Wc029ScenarioCapability:
    payload: dict[str, object] = {
        "scenarioClass": scenario_class,
        "targetResourceId": target_resource_id,
        "mutationActionDigest": sha256_hex(f"{scenario_class}:apply"),
        "recoveryActionDigest": sha256_hex(f"{scenario_class}:recover"),
        "incidentProducerSchemaVersion": (
            "athena.incidentState.v1" if incident_producing else None
        ),
    }
    return _digest_bound_model(
        acceptance.Wc029ScenarioCapability,
        payload,
        digest_field="capabilityDigest",
    )


def _resource_state(
    *,
    capture_kind: str,
    scenario_id: str,
    scenario_execution_id: str,
    scenario_class: str,
    target_resource_id: str,
    captured_at: datetime,
    state_document: dict[str, object],
    plan_digest: str | None = None,
    mutation_receipt_digest: str | None = None,
) -> acceptance.Wc029ResourceStateEvidence:
    state_digest = compute_artifact_digest(
        {
            "targetResourceId": target_resource_id.casefold().rstrip("/"),
            "stateDocument": state_document,
        }
    )
    return acceptance.Wc029ResourceStateEvidence(
        schemaVersion=acceptance.RESOURCE_STATE_SCHEMA_VERSION,
        captureKind=capture_kind,
        scenarioId=scenario_id,
        scenarioExecutionId=scenario_execution_id,
        scenarioClass=scenario_class,
        planDigest=plan_digest,
        mutationReceiptDigest=mutation_receipt_digest,
        targetResourceId=target_resource_id,
        capturedAt=captured_at,
        stateDocument=state_document,
        stateDigest=state_digest,
    )


def _scenario_input_digest(
    evidence_class: str,
    value: object,
    *,
    content_sha256: str,
    plan: acceptance.Wc029ScenarioPlanEvidence,
) -> str:
    if isinstance(value, acceptance.Wc029ScenarioPlanEvidence):
        return value.plan_digest
    if isinstance(value, acceptance.Wc029ResourceStateEvidence):
        return value.state_digest
    if isinstance(value, acceptance.Wc029MutationReceipt):
        return value.result_digest
    if isinstance(value, MonitoringEvidenceHandoff):
        return plan.monitoring_request_digest
    if isinstance(value, ChangeEvidenceArtifact):
        return value.evidence.source_digest
    if isinstance(value, CorrelationReport):
        return value.request_digest
    if isinstance(value, PublishedCorrelationReportAttestation):
        return value.statement.correlation_request_digest
    if isinstance(value, acceptance.Wc029IncidentOmission):
        return sha256_hex(
            canonicalize_json(
                value.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            )
        )
    if isinstance(value, IncidentState):
        return value.result_digest
    if isinstance(value, IncidentStateAttestation):
        return value.result_digest
    if isinstance(value, acceptance.Wc029ManifestCitationEvidence):
        return value.citation_digest
    if isinstance(value, IncidentGuidance):
        return value.guidance_digest
    if isinstance(value, IncidentGuidanceAttestation):
        return value.guidance_digest
    if isinstance(value, IncidentEnrichmentManifest):
        return value.manifest_digest
    if isinstance(value, IncidentEnrichmentAttestation):
        return value.manifest_digest
    if isinstance(value, IncidentEnrichmentFeedPointer):
        return value.pointer_digest
    if isinstance(value, IncidentEnrichmentFeedPointerAttestation):
        return value.pointer_digest
    if isinstance(value, IncidentFeedIndexV2):
        return sha256_hex(value.canonical_bytes())
    if isinstance(value, IncidentFeedIndexAttestationV2):
        return value.index_digest
    if isinstance(value, IncidentNotificationEnvelopeV2):
        return value.notification.notification_digest
    if isinstance(value, acceptance.Wc029RecoveryActionEvidence):
        return value.result_digest
    if isinstance(value, acceptance.Wc029JobExecutionEvidence):
        return value.input_digest
    if isinstance(value, acceptance.Wc029JobReadbackEvidence):
        return value.execution_digest
    if isinstance(value, acceptance.Wc029QueueStateEvidence):
        return sha256_hex(
            canonicalize_json(
                value.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            )
        )
    if isinstance(value, acceptance.Wc029RecoveryProof):
        return compute_artifact_digest(
            value.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        )
    raise AssertionError(f"no input digest fixture rule for {evidence_class}: {content_sha256}")


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


def _build_bundle(tmp_path: Path) -> BundleFixture:
    root = tmp_path / "evidence"
    output = tmp_path / "records"
    root.mkdir(parents=True)
    output.mkdir(parents=True)
    declarations: list[dict[str, object]] = []
    global_ids: list[str] = []
    artifact_paths: dict[str, Path] = {}
    artifact_digests: dict[str, str] = {}
    artifact_values: dict[str, object] = {}
    artifact_classes: dict[str, str] = {}

    publication, _ = _publication_assets()
    incident = _trusted_incident_assets(publication)
    change, change_key = _signed_change()
    monitoring, monitoring_key, monitoring_private = _signed_monitoring(
        incident.report.as_of - timedelta(minutes=6)
    )
    scenario_key, scenario_private = _private_key_material(
        "scenario-authority",
        "3",
    )
    keys = {
        **incident.keys,
        "change": change_key,
        "context-authority": publication.key,
        "monitoring": monitoring_key,
        "scenario-authority": scenario_key,
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
        artifact_values[artifact_id] = value
        artifact_classes[artifact_id] = evidence_class
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
        selected_purpose = signing_key_purpose or acceptance._SIGNED_KEY_PURPOSE_BY_CLASS.get(
            evidence_class
        )
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

    manifest_id = add(
        "published-manifest",
        "published-manifest",
        publication.manifest,
        global_evidence=True,
    )
    authority_id = add(
        "publication-authority",
        "publication-authority",
        publication.authority,
        global_evidence=True,
    )
    authority_attestation_id = add(
        "publication-authority-attestation",
        "publication-authority-attestation",
        publication.attestation,
        global_evidence=True,
        binds_artifact_id=authority_id,
    )

    capabilities = tuple(
        _scenario_capability(
            scenario_class,
            (
                change.evidence.target_resource_id
                if scenario_class == "nsg-connectivity-loss"
                else _TARGETS[scenario_class]
            ),
            incident_producing=scenario_class == "web-tier-failure",
        )
        for scenario_class in acceptance.REQUIRED_SCENARIO_CLASSES
    )
    boundary_payload: dict[str, object] = {
        "boundaryId": "runtime-workload-separation",
        "principalId": _PRINCIPAL_ID,
        "forbiddenRoleNames": ("Contributor", "Reader"),
        "forbiddenScopePrefixes": (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-athena-demo-workload",
        ),
    }
    rbac_boundary = _digest_bound_model(
        acceptance.Wc029RbacBoundary,
        boundary_payload,
        digest_field="boundaryDigest",
    )
    capability_payloads = [
        item.model_dump(mode="json", by_alias=True, exclude_none=True) for item in capabilities
    ]
    base_parameter_sha256 = "sha256:" + ("4" * 64)
    effective_parameter_sha256 = "sha256:" + ("5" * 64)
    deployment = acceptance.Wc029DeploymentVersion(
        deploymentId="foundation",
        deploymentName="wc029-foundation-synthetic",
        stage="foundation",
        subscriptionId="00000000-0000-0000-0000-000000000000",
        location="australiaeast",
        templatePath="infra/wc013-live-acceptance/main.bicep",
        templateSha256=_TEMPLATE_DIGEST,
        baseParameterSha256=base_parameter_sha256,
        effectiveParameterSha256=effective_parameter_sha256,
        parameterBindingsSha256=sha256_hex(canonicalize_json({"location": "australiaeast"})),
        upstreamHandoffs=(),
    )
    inventory = acceptance.Wc029VersionInventory(
        schemaVersion=acceptance.VERSION_INVENTORY_SCHEMA_VERSION,
        sourceCommit=_SOURCE_COMMIT,
        deployments=(deployment,),
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
        rbacBoundaries=(rbac_boundary,),
        capabilityDeploymentId="foundation",
        scenarioCapabilities=capabilities,
        manifest=acceptance.Wc029ManifestVersion(
            manifestId=publication.manifest.manifest_id,
            manifestVersion=publication.manifest.manifest_version,
            profileId=publication.manifest.profile_id,
            manifestDigest=publication.manifest.manifest_digest,
            publicationStatus="published",
            manifestArtifactId=manifest_id,
            manifestArtifactSha256=artifact_digests[manifest_id],
            citedClauseMapDigest=compute_artifact_digest(
                [
                    item.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    )
                    for item in publication.manifest.cited_clauses
                ]
            ),
            authorityArtifactId=authority_id,
            authorityAttestationArtifactId=authority_attestation_id,
            authorityDigest=publication.authority.authority.authority_digest,
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
    inventory_id = add(
        "version-inventory",
        "version-inventory",
        inventory,
        global_evidence=True,
    )
    approved_inventory_sha256 = artifact_digests[inventory_id]

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
        stage=deployment.stage,
        sourceCommit=_SOURCE_COMMIT,
        subscriptionId=deployment.subscription_id,
        location=deployment.location,
        deploymentName=deployment.deployment_name,
        templatePath=deployment.template_path,
        templateSha256=deployment.template_sha256,
        orchestratorSha256="sha256:" + ("6" * 64),
        preflightSha256=acceptance._preflight_implementation_sha256(),
        baseParameterPath="C:/synthetic/wc029.parameters.json",
        baseParameterSha256=deployment.base_parameter_sha256,
        effectiveParameterPath="C:/synthetic/foundation.parameters.json",
        effectiveParameterSha256=deployment.effective_parameter_sha256,
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
        "wc029ScenarioCapabilities": capability_payloads,
        "wc029ScenarioCapabilitiesDigest": compute_artifact_digest(capability_payloads),
    }
    handoff = acceptance.Wc029DeploymentHandoffEvidence(
        schemaVersion="athena.wc029DeploymentHandoff.v1",
        stage=deployment.stage,
        sourceCommit=_SOURCE_COMMIT,
        subscriptionId=deployment.subscription_id,
        deploymentName=deployment.deployment_name,
        outputs=outputs,
        outputsSha256=sha256_hex(canonicalize_json(outputs)),
        parameterBindings={"location": deployment.location},
        parameterBindingsSha256=sha256_hex(canonicalize_json({"location": deployment.location})),
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
        stage=deployment.stage,
        sourceCommit=_SOURCE_COMMIT,
        subscriptionId=deployment.subscription_id,
        location=deployment.location,
        deploymentName=deployment.deployment_name,
        templatePath=deployment.template_path,
        templateSha256=deployment.template_sha256,
        baseParameterSha256=deployment.base_parameter_sha256,
        effectiveParameterSha256=deployment.effective_parameter_sha256,
        parameterBindingsSha256=(deployment.parameter_bindings_sha256),
        upstreamHandoffs=(),
        observedAt=_SCENARIO_BASE - timedelta(hours=2),
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
                "principalId": rbac_boundary.principal_id,
                "forbiddenRoleNames": list(rbac_boundary.forbidden_role_names),
                "forbiddenScopePrefixes": list(rbac_boundary.forbidden_scope_prefixes),
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
        _queue_state(
            "baseline",
            captured_at=_SCENARIO_BASE - timedelta(hours=1),
        ),
        global_evidence=True,
        queue_scope="baseline",
    )
    add(
        "queue-final",
        "queue-state",
        _queue_state(
            "final",
            captured_at=_NOW + timedelta(minutes=10),
        ),
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

    capability_by_class = {item.scenario_class: item for item in capabilities}
    scenarios: list[dict[str, object]] = []
    for scenario_class in acceptance.REQUIRED_SCENARIO_CLASSES:
        capability = capability_by_class[scenario_class]
        scenario_id = f"scenario-{scenario_class}"
        scenario_execution_id = (
            "wc029-execution-" + sha256_hex(scenario_id).removeprefix("sha256:")[:32]
        )
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

        planned_at = incident.report.as_of - timedelta(minutes=12)
        baseline_id = f"{scenario_id}-baseline-state"
        state_document = {
            "powerState": "running",
            "temporaryMutationPresent": False,
            "targetResourceId": capability.target_resource_id,
        }
        baseline_state = _resource_state(
            capture_kind="baseline",
            scenario_id=scenario_id,
            scenario_execution_id=scenario_execution_id,
            scenario_class=scenario_class,
            target_resource_id=capability.target_resource_id,
            captured_at=planned_at,
            state_document=state_document,
        )
        add_scenario(
            "baseline-state",
            "baseline-state",
            baseline_state,
            phase="plan",
        )
        verification_input_digest = compute_artifact_digest(
            {
                "scenarioExecutionId": scenario_execution_id,
                "targetResourceId": capability.target_resource_id,
                "purpose": "post-recovery-verification",
            }
        )
        scenario_plan = _scenario_plan(
            scenario_id,
            scenario_execution_id,
            capability,
            baseline_state_artifact_id=baseline_id,
            baseline_state_digest=baseline_state.state_digest,
            planned_at=planned_at,
            monitoring_request_digest=acceptance._monitoring_request_digest(monitoring),
            correlation_request_digest=incident.report.request_digest,
            change_request_digest=(
                change.evidence.source_digest if scenario_class == "nsg-connectivity-loss" else None
            ),
            verification_input_digest=verification_input_digest,
        )
        add_scenario("plan", "scenario-plan", scenario_plan, phase="plan")
        mutation = _mutation(
            scenario_plan,
            applied_at=planned_at + timedelta(minutes=2),
        )
        add_scenario(
            "mutation",
            "mutation-receipt",
            mutation,
            phase="apply",
        )
        add_scenario(
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
        add_scenario(
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
        if capability.evidence_mode == "correlation-only":
            add_scenario(
                "incident-omission",
                "incident-omission",
                acceptance.Wc029IncidentOmission(
                    schemaVersion=acceptance.INCIDENT_OMISSION_SCHEMA_VERSION,
                    scenarioId=scenario_id,
                    scenarioExecutionId=scenario_execution_id,
                    reasonCode="unsupported-incident-producer",
                    incidentEvidenceExpected=False,
                    incidentEvidenceObserved=False,
                    syntheticIncidentEvidenceCreated=False,
                    observedAt=incident.report.as_of,
                    detail=("Synthetic scenario has no reviewed incident producer."),
                ),
                phase="observe",
            )
            observe_end = incident.report.as_of
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
                    scenario_execution_id,
                    publication,
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
            active_index_id = add_scenario(
                "feed-index-active",
                "feed-index-active",
                incident.active_feed_index,
                phase="observe",
            )
            add_scenario(
                "feed-index-active-attestation",
                "feed-index-active-attestation",
                incident.active_feed_index_attestation,
                phase="observe",
                binds_artifact_id=active_index_id,
            )
            add_scenario(
                "notification-active",
                "notification-active",
                incident.active_notification,
                phase="observe",
            )
            observe_end = max(
                incident.report.as_of,
                incident.active_feed_index.published_at,
            )

        recovery_at = observe_end + timedelta(minutes=1)
        recovery = _recovery_action(
            scenario_plan,
            mutation,
            recovered_at=recovery_at,
        )
        recovery_id = add_scenario(
            "recovery-action",
            "recovery-action",
            recovery,
            phase="recover",
        )
        recovered_at = (
            incident.resolved_state.updated_at
            if capability.evidence_mode == "incident-producing"
            else recovery_at + timedelta(minutes=1)
        )
        recovered_state = _resource_state(
            capture_kind="recovered",
            scenario_id=scenario_id,
            scenario_execution_id=scenario_execution_id,
            scenario_class=scenario_class,
            target_resource_id=capability.target_resource_id,
            captured_at=recovered_at,
            state_document=state_document,
            plan_digest=scenario_plan.plan_digest,
            mutation_receipt_digest=mutation.result_digest,
        )
        recovered_state_id = add_scenario(
            "recovered-state",
            "recovered-state",
            recovered_state,
            phase="verify",
        )
        verification_start = (
            max(recovered_at, incident.resolved_feed_index.published_at)
            if capability.evidence_mode == "incident-producing"
            else recovered_at
        ) + timedelta(minutes=1)
        execution = _job_execution(
            execution_id=f"{scenario_id}-verify",
            scope="scenario",
            scenario_id=scenario_id,
            scenario_execution_id=scenario_execution_id,
            scenario_plan_digest=scenario_plan.plan_digest,
            input_digest=verification_input_digest,
            phase="verify",
            started_at=verification_start,
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
                    (recovered_state_id, artifact_digests[recovered_state_id]),
                    (recovery_id, artifact_digests[recovery_id]),
                ],
            ),
            phase="verify",
            binds_artifact_id=execution_id,
        )
        proof_ids = [readback_id]
        if capability.evidence_mode == "incident-producing":
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
            resolved_index_id = add_scenario(
                "feed-index-resolved",
                "feed-index-resolved",
                incident.resolved_feed_index,
                phase="verify",
            )
            add_scenario(
                "feed-index-resolved-attestation",
                "feed-index-resolved-attestation",
                incident.resolved_feed_index_attestation,
                phase="verify",
                binds_artifact_id=resolved_index_id,
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
                _queue_state(
                    "scenario-verify",
                    scenario_id=scenario_id,
                    scenario_execution_id=scenario_execution_id,
                    captured_at=execution.completed_at + timedelta(minutes=2),
                ),
                phase="verify",
                queue_scope="scenario-verify",
            )
            proof_ids.append(queue_id)
        proof = _recovery_proof(
            scenario_plan,
            mutation,
            recovery,
            baseline_state_id=baseline_id,
            baseline_state_sha256=artifact_digests[baseline_id],
            baseline_state_digest=baseline_state.state_digest,
            recovered_state_id=recovered_state_id,
            recovered_state_sha256=artifact_digests[recovered_state_id],
            recovered_state_digest=recovered_state.state_digest,
            job_readback_id=readback_id,
            job_readback_sha256=artifact_digests[readback_id],
            evidence_ids=proof_ids,
            verified_at=execution.completed_at + timedelta(minutes=3),
        )
        add_scenario(
            "recovery-proof",
            "recovery-proof",
            proof,
            phase="verify",
        )

        observe_timestamps = [
            monitoring.observed_at,
            incident.report.as_of,
        ]
        if scenario_class == "nsg-connectivity-loss":
            observe_timestamps.extend(
                [
                    change.evidence.occurred_at,
                    change.evidence.received_at,
                ]
            )
        if capability.evidence_mode == "incident-producing":
            observe_timestamps.extend(
                [
                    incident.active_state.updated_at,
                    incident.guidance.generated_at,
                    incident.active_feed.published_at,
                    incident.active_feed_index.published_at,
                    incident.active_notification.notification.feed_published_at,
                ]
            )
        phase_windows = (
            acceptance.Wc029ScenarioPhaseWindow(
                phase="plan",
                startedAt=planned_at - timedelta(minutes=1),
                completedAt=planned_at + timedelta(minutes=1),
            ),
            acceptance.Wc029ScenarioPhaseWindow(
                phase="apply",
                startedAt=mutation.applied_at - timedelta(seconds=30),
                completedAt=mutation.applied_at + timedelta(seconds=30),
            ),
            acceptance.Wc029ScenarioPhaseWindow(
                phase="observe",
                startedAt=min(observe_timestamps) - timedelta(seconds=30),
                completedAt=max(observe_timestamps) + timedelta(seconds=30),
            ),
            acceptance.Wc029ScenarioPhaseWindow(
                phase="recover",
                startedAt=recovery.recovered_at - timedelta(seconds=20),
                completedAt=recovery.recovered_at + timedelta(seconds=20),
            ),
            acceptance.Wc029ScenarioPhaseWindow(
                phase="verify",
                startedAt=recovered_state.captured_at,
                completedAt=proof.verified_at + timedelta(minutes=1),
            ),
        )
        manifest_bindings = []
        phase_rank = {
            "plan": 0,
            "apply": 1,
            "observe": 2,
            "recover": 3,
            "verify": 4,
        }
        for phase, artifact_ids in phases.items():
            for artifact_id in artifact_ids:
                manifest_bindings.append(
                    acceptance.Wc029ScenarioArtifactBinding(
                        artifactId=artifact_id,
                        phase=phase,
                        contentSha256=artifact_digests[artifact_id],
                        inputDigest=_scenario_input_digest(
                            artifact_classes[artifact_id],
                            artifact_values[artifact_id],
                            content_sha256=artifact_digests[artifact_id],
                            plan=scenario_plan,
                        ),
                    )
                )
        manifest_bindings.sort(
            key=lambda item: (
                phase_rank[item.phase],
                item.artifact_id,
            )
        )
        execution_manifest_payload: dict[str, object] = {
            "schemaVersion": (acceptance.SCENARIO_EXECUTION_MANIFEST_SCHEMA_VERSION),
            "scenarioExecutionId": scenario_execution_id,
            "scenarioId": scenario_id,
            "scenarioClass": scenario_class,
            "evidenceMode": capability.evidence_mode,
            "capabilityDigest": capability.capability_digest,
            "sourceCommit": _SOURCE_COMMIT,
            "targetResourceId": capability.target_resource_id,
            "mutationActionDigest": capability.mutation_action_digest,
            "recoveryActionDigest": capability.recovery_action_digest,
            "monitoringRequestDigest": (scenario_plan.monitoring_request_digest),
            "correlationRequestDigest": (scenario_plan.correlation_request_digest),
            "changeRequestDigest": scenario_plan.change_request_digest,
            "verificationInputDigest": (scenario_plan.verification_input_digest),
            "planDigest": scenario_plan.plan_digest,
            "mutationReceiptDigest": mutation.result_digest,
            "recoveryActionResultDigest": recovery.result_digest,
            "phaseWindows": phase_windows,
            "artifacts": tuple(manifest_bindings),
        }
        execution_manifest = _digest_bound_model(
            acceptance.Wc029ScenarioExecutionManifest,
            execution_manifest_payload,
            digest_field="manifestDigest",
        )
        execution_manifest_id = add_scenario(
            "execution-manifest",
            "scenario-execution-manifest",
            execution_manifest,
            phase="verify",
        )
        execution_signature = (
            base64.urlsafe_b64encode(
                scenario_private.sign(
                    execution_manifest.canonical_bytes(),
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            )
            .decode("ascii")
            .rstrip("=")
        )
        add_scenario(
            "execution-attestation",
            "scenario-execution-attestation",
            acceptance.Wc029ScenarioExecutionAttestation(
                schemaVersion=(acceptance.SCENARIO_EXECUTION_ATTESTATION_SCHEMA_VERSION),
                scenarioExecutionId=scenario_execution_id,
                manifestDigest=execution_manifest.manifest_digest,
                signatureAlgorithm="RS256",
                keyVaultKeyId=scenario_key.key_id,
                signedPreimageDigest=sha256_hex(execution_manifest.canonical_bytes()),
                detachedSignature=execution_signature,
            ),
            phase="verify",
            binds_artifact_id=execution_manifest_id,
        )
        scenarios.append(
            {
                "scenarioId": scenario_id,
                "scenarioClass": scenario_class,
                "evidenceMode": capability.evidence_mode,
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
        private_keys={
            **incident.private_keys,
            "monitoring": monitoring_private,
            "scenario-authority": scenario_private,
        },
        approved_inventory_sha256=approved_inventory_sha256,
    )


def _rewrite_index(bundle: BundleFixture) -> None:
    _write(bundle.root / "acceptance-index.json", bundle.index)


def _aggregate(
    bundle: BundleFixture,
) -> acceptance.Wc029AcceptanceEvidenceRecord:
    return acceptance.aggregate_acceptance_evidence(
        bundle.root,
        approved_inventory_sha256=bundle.approved_inventory_sha256,
    )


def _cli_arguments(bundle: BundleFixture) -> list[str]:
    return [
        str(bundle.root),
        "--approved-inventory-sha256",
        bundle.approved_inventory_sha256,
        "--output-directory",
        str(bundle.output),
    ]


def _refresh_scenario_execution_binding(
    bundle: BundleFixture,
    scenario_class: str,
) -> None:
    scenario = _scenario(bundle, scenario_class)
    plan_id = next(
        artifact_id
        for artifact_id in scenario["phases"]["plan"]
        if _declaration(bundle, artifact_id)["evidenceClass"] == "scenario-plan"
    )
    plan = acceptance.Wc029ScenarioPlanEvidence.model_validate_json(
        bundle.artifact_paths[plan_id].read_bytes()
    )
    manifest_id = next(
        artifact_id
        for artifact_id in scenario["phases"]["verify"]
        if _declaration(bundle, artifact_id)["evidenceClass"] == "scenario-execution-manifest"
    )
    attestation_id = next(
        artifact_id
        for artifact_id in scenario["phases"]["verify"]
        if _declaration(bundle, artifact_id)["evidenceClass"] == "scenario-execution-attestation"
    )
    phase_rank = {
        "plan": 0,
        "apply": 1,
        "observe": 2,
        "recover": 3,
        "verify": 4,
    }
    bindings: list[acceptance.Wc029ScenarioArtifactBinding] = []
    for phase, artifact_ids in scenario["phases"].items():
        for artifact_id in artifact_ids:
            if artifact_id in {manifest_id, attestation_id}:
                continue
            path = bundle.artifact_paths[artifact_id]
            raw = path.read_bytes()
            parsed = json.loads(raw)
            schema_version = parsed.get("schemaVersion")
            model_type = acceptance._KNOWN_MODELS[schema_version]
            model = model_type.model_validate_json(raw)
            bindings.append(
                acceptance.Wc029ScenarioArtifactBinding(
                    artifactId=artifact_id,
                    phase=phase,
                    contentSha256=sha256_hex(raw),
                    inputDigest=_scenario_input_digest(
                        _declaration(bundle, artifact_id)["evidenceClass"],
                        model,
                        content_sha256=sha256_hex(raw),
                        plan=plan,
                    ),
                )
            )
    bindings.sort(
        key=lambda item: (
            phase_rank[item.phase],
            item.artifact_id,
        )
    )
    old_manifest = acceptance.Wc029ScenarioExecutionManifest.model_validate_json(
        bundle.artifact_paths[manifest_id].read_bytes()
    )
    payload = old_manifest.model_dump(
        mode="python",
        by_alias=True,
        exclude={"manifest_digest"},
    )
    payload["artifacts"] = tuple(bindings)
    manifest = _digest_bound_model(
        acceptance.Wc029ScenarioExecutionManifest,
        payload,
        digest_field="manifestDigest",
    )
    _write(bundle.artifact_paths[manifest_id], manifest)
    signature = (
        base64.urlsafe_b64encode(
            bundle.private_keys["scenario-authority"].sign(
                manifest.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    attestation = acceptance.Wc029ScenarioExecutionAttestation(
        schemaVersion=(acceptance.SCENARIO_EXECUTION_ATTESTATION_SCHEMA_VERSION),
        scenarioExecutionId=manifest.scenario_execution_id,
        manifestDigest=manifest.manifest_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=bundle.keys["scenario-authority"].key_id,
        signedPreimageDigest=sha256_hex(manifest.canonical_bytes()),
        detachedSignature=signature,
    )
    _write(bundle.artifact_paths[attestation_id], attestation)


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

    first = _aggregate(bundle)
    second = _aggregate(bundle)

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

    result = acceptance.main(_cli_arguments(bundle))

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
        _aggregate(bundle)


def test_rejects_missing_and_unlisted_files(tmp_path: Path) -> None:
    unlisted = _build_bundle(tmp_path / "unlisted")
    _write(unlisted.root / "artifacts" / "unlisted.json", {"unexpected": True})
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="unlisted"):
        _aggregate(unlisted)

    missing = _build_bundle(tmp_path / "missing")
    missing.artifact_paths["global-job-readback"].unlink()
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="missing"):
        _aggregate(missing)


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
        _aggregate(bundle)


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
        match="linked|singly linked|reparse point",
    ):
        _aggregate(bundle)


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
        _aggregate(bundle)


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
        _aggregate(bundle)


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
        _aggregate(unknown)

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
        _aggregate(noncanonical)


def test_rejects_individual_and_aggregate_oversize_before_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    individual = _build_bundle(tmp_path / "individual")
    individual.artifact_paths["global-job-readback"].write_bytes(
        b'{"value":"' + (b"x" * acceptance.MAX_ARTIFACT_TRANSFER_BYTES) + b'"}'
    )
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="between 1 and"):
        _aggregate(individual)

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
        _aggregate(aggregate)
    assert called is False


def test_rejects_failed_deployment_and_job_evidence(tmp_path: Path) -> None:
    deployment = _build_bundle(tmp_path / "deployment")
    readback = _read_json(deployment.artifact_paths["foundation-readback"])
    readback["provisioningState"] = "Failed"
    _write(deployment.artifact_paths["foundation-readback"], readback)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="violates"):
        _aggregate(deployment)

    job = _build_bundle(tmp_path / "job")
    readback = _read_json(job.artifact_paths["global-job-readback"])
    readback["status"] = "Failed"
    _write(job.artifact_paths["global-job-readback"], readback)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="violates"):
        _aggregate(job)


def test_rejects_rbac_gaps_and_failed_preflight(tmp_path: Path) -> None:
    missing_principal = _build_bundle(tmp_path / "principal")
    rbac = json.loads(
        missing_principal.artifact_paths["effective-rbac"].read_text(encoding="utf-8")
    )
    rbac[0]["principalId"] = "00000000-0000-0000-0000-000000000099"
    _write(missing_principal.artifact_paths["effective-rbac"], rbac)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        _aggregate(missing_principal)

    violation = _build_bundle(tmp_path / "violation")
    rbac = json.loads(violation.artifact_paths["effective-rbac"].read_text(encoding="utf-8"))
    rbac[0]["roleDefinitionName"] = "Reader"
    rbac[0]["scope"] = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload"
    )
    _write(violation.artifact_paths["effective-rbac"], rbac)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        _aggregate(violation)

    stale_result = _build_bundle(tmp_path / "result")
    result = _read_json(stale_result.artifact_paths["rbac-preflight"])
    result["inputSha256"] = "sha256:" + ("f" * 64)
    _write(stale_result.artifact_paths["rbac-preflight"], result)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="bind"):
        _aggregate(stale_result)


def test_rejects_image_manifest_and_key_version_drift(tmp_path: Path) -> None:
    image = _build_bundle(tmp_path / "image")
    execution = _read_json(image.artifact_paths["global-job-execution"])
    execution["image"] = "synthetic.azurecr.io/athena/wc029-acceptance@sha256:" + ("f" * 64)
    payload = dict(execution)
    payload.pop("executionDigest")
    execution["executionDigest"] = compute_artifact_digest(payload)
    _write(image.artifact_paths["global-job-execution"], execution)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="inventoried"):
        _aggregate(image)

    manifest = _build_bundle(tmp_path / "manifest")
    citation_path = manifest.artifact_paths["scenario-web-tier-failure-manifest-citation"]
    citation = _read_json(citation_path)
    citation["manifestDigest"] = "sha256:" + ("f" * 64)
    payload = dict(citation)
    payload.pop("citationDigest")
    citation["citationDigest"] = compute_artifact_digest(payload)
    _write(citation_path, citation)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="signed scenario binding|published",
    ):
        _aggregate(manifest)

    key = _build_bundle(tmp_path / "key")
    attestation_path = key.artifact_paths["scenario-web-tier-failure-guidance-attestation"]
    attestation = _read_json(attestation_path)
    attestation["keyVaultKeyId"] = key.keys["report"].key_id
    _write(attestation_path, attestation)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        _aggregate(key)


def test_rejects_wrong_subject_digest_and_forged_signature(tmp_path: Path) -> None:
    digest = _build_bundle(tmp_path / "digest")
    path = digest.artifact_paths["scenario-web-tier-failure-guidance-attestation"]
    payload = _read_json(path)
    payload["signedPreimageDigest"] = "sha256:" + ("f" * 64)
    _write(path, payload)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        _aggregate(digest)

    signature = _build_bundle(tmp_path / "signature")
    path = signature.artifact_paths["scenario-web-tier-failure-execution-attestation"]
    payload = _read_json(path)
    payload["detachedSignature"] = "Zm9yZ2Vk"
    _write(path, payload)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="invalid RSA signature",
    ):
        _aggregate(signature)


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
        _aggregate(missing)

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
        _aggregate(forbidden)


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
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="signed scenario binding|phase receipts",
    ):
        _aggregate(target)

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
        _aggregate(result)


def test_incident_chain_requires_resolved_state_and_queue_drain(
    tmp_path: Path,
) -> None:
    state = _build_bundle(tmp_path / "state")
    resolved_path = state.artifact_paths["scenario-web-tier-failure-incident-resolved"]
    resolved = _read_json(resolved_path)
    resolved["lifecycle"] = "active"
    _write(resolved_path, resolved)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        _aggregate(state)

    queue = _build_bundle(tmp_path / "queue")
    queue_path = queue.artifact_paths["scenario-web-tier-failure-queue"]
    queue_payload = _read_json(queue_path)
    queue_payload["queues"][0]["deadLetterMessageCount"] = 1
    _write(queue_path, queue_payload)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError, match="violates"):
        _aggregate(queue)


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
        _aggregate(bundle)


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
        _aggregate(bundle)


def test_output_write_is_exclusive_and_cleans_failed_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    record = _aggregate(bundle)

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

    result = acceptance.main(_cli_arguments(bundle))

    assert result == 2
    assert json.loads(capsys.readouterr().err)["complete"] is False
    assert list(bundle.output.iterdir()) == []


def test_out_of_band_inventory_digest_and_exact_key_versions_are_required(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="out-of-band approved digest",
    ):
        acceptance.aggregate_acceptance_evidence(
            bundle.root,
            approved_inventory_sha256="sha256:" + ("f" * 64),
        )

    key = bundle.keys["incident"]
    with pytest.raises(ValueError, match="exact versioned Key Vault"):
        acceptance.Wc029KeyVersion(
            purpose="incident",
            keyVaultKeyId=(
                "https://athena-wc029-synthetic.vault.azure.net/keys/incident/version-1"
            ),
            publicKeyFingerprint=key.fingerprint,
            publicKeyArtifactId="key-incident",
        )


def test_rbac_rejects_recursive_case_collisions_and_vacuous_boundaries(
    tmp_path: Path,
) -> None:
    collision = _build_bundle(tmp_path / "collision")
    collision.artifact_paths["rbac-policy"].write_bytes(
        (
            '{"allowedBroadAssignments":[],"separationRules":['
            '{"principalId":"'
            + _PRINCIPAL_ID
            + '","PrincipalId":"'
            + _PRINCIPAL_ID
            + '","forbiddenRoleNames":["Reader"],'
            '"forbiddenScopePrefixes":["/subscriptions/synthetic"]}]}'
        ).encode("utf-8")
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="case-insensitive duplicate",
    ):
        _aggregate(collision)

    vacuous = _build_bundle(tmp_path / "vacuous")
    policy_path = vacuous.artifact_paths["rbac-policy"]
    policy = _read_json(policy_path)
    policy["separationRules"][0]["forbiddenRoleNames"] = []
    _write(policy_path, policy)
    result_path = vacuous.artifact_paths["rbac-preflight"]
    result = _read_json(result_path)
    result["policySha256"] = sha256_hex(policy_path.read_bytes())
    _write(result_path, result)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="non-vacuous",
    ):
        _aggregate(vacuous)

    inventory = acceptance.Wc029VersionInventory.model_validate_json(
        vacuous.artifact_paths["version-inventory"].read_bytes()
    )
    incomplete = {
        "allowedBroadAssignments": [],
        "separationRules": [
            {
                "principalId": _PRINCIPAL_ID,
                "forbiddenRoleNames": ["Reader"],
                "forbiddenScopePrefixes": [
                    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/other"
                ],
            }
        ],
    }
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="every approved principal boundary",
    ):
        acceptance._validate_rbac_policy(
            incomplete,
            inventory=inventory,
        )


def test_scenario_mode_is_derived_and_stale_monitoring_is_rejected(
    tmp_path: Path,
) -> None:
    mode = _build_bundle(tmp_path / "mode")
    _scenario(mode, "disk-capacity-pressure")["evidenceMode"] = "incident-producing"
    _rewrite_index(mode)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="trusted deployed capability",
    ):
        _aggregate(mode)

    stale = _build_bundle(tmp_path / "stale")
    monitoring_id = "scenario-disk-capacity-pressure-monitoring"
    monitoring = MonitoringEvidenceHandoff.model_validate_json(
        stale.artifact_paths[monitoring_id].read_bytes()
    )
    payload = monitoring.model_dump(
        mode="python",
        by_alias=True,
        exclude={"collector_attestation"},
    )
    payload["observedAt"] = monitoring.observed_at - timedelta(days=2)
    preimage = monitoring_handoff_preimage(payload)
    preimage_bytes = canonicalize_json(preimage).encode("utf-8")
    payload["collectorAttestation"] = {
        "signatureAlgorithm": "RS256",
        "trustAnchorRef": stale.keys["monitoring"].key_id,
        "signedPreimageDigest": compute_artifact_digest(preimage),
        "signature": base64.b64encode(
            stale.private_keys["monitoring"].sign(
                preimage_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        ).decode("ascii"),
    }
    _write(
        stale.artifact_paths[monitoring_id],
        MonitoringEvidenceHandoff.model_validate(payload),
    )
    _refresh_scenario_execution_binding(
        stale,
        "disk-capacity-pressure",
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="outside the signed observe phase window",
    ):
        _aggregate(stale)

    unrelated = _build_bundle(tmp_path / "unrelated-report")
    scenario_class = "disk-capacity-pressure"
    report_id = f"scenario-{scenario_class}-report"
    report_attestation_id = f"scenario-{scenario_class}-report-attestation"
    report = CorrelationReport.model_validate_json(unrelated.artifact_paths[report_id].read_bytes())
    report_payload = report.model_dump(
        mode="python",
        by_alias=True,
        exclude={"report_id", "report_digest"},
    )
    report_payload["requestDigest"] = "sha256:" + ("e" * 64)
    report_digest = compute_artifact_digest(_json_value(report_payload))
    changed_report = CorrelationReport(
        **report_payload,
        reportId=("report-" + report_digest.removeprefix("sha256:")[:32]),
        reportDigest=report_digest,
    )
    _write(unrelated.artifact_paths[report_id], changed_report)
    old_attestation = PublishedCorrelationReportAttestation.model_validate_json(
        unrelated.artifact_paths[report_attestation_id].read_bytes()
    )
    statement_payload = old_attestation.statement.model_dump(
        mode="python",
        by_alias=True,
        exclude={"statement_id", "statement_digest"},
    )
    statement_payload.update(
        {
            "correlationRequestDigest": changed_report.request_digest,
            "reportId": changed_report.report_id,
            "reportDigest": changed_report.report_digest,
            "reportContentDigest": sha256_hex(changed_report.canonical_bytes()),
        }
    )
    statement_digest = compute_artifact_digest(_json_value(statement_payload))
    changed_statement = PublishedCorrelationReportStatement(
        **statement_payload,
        statementId=("report-publication-" + statement_digest.removeprefix("sha256:")[:32]),
        statementDigest=statement_digest,
    )
    changed_attestation = PublishedCorrelationReportAttestation(
        schemaVersion=("athena.wc027PublishedCorrelationReportAttestation.v1"),
        statement=changed_statement,
        signatureAlgorithm="RS256",
        keyVaultKeyId=unrelated.keys["report"].key_id,
        signedPreimageDigest=sha256_hex(changed_statement.canonical_bytes()),
        detachedSignature=base64.urlsafe_b64encode(
            unrelated.private_keys["report"].sign(
                changed_statement.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("="),
    )
    _write(
        unrelated.artifact_paths[report_attestation_id],
        changed_attestation,
    )
    _refresh_scenario_execution_binding(unrelated, scenario_class)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="published read-only result",
    ):
        _aggregate(unrelated)


def test_verification_job_must_start_after_recovery(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    scenario_class = "disk-capacity-pressure"
    execution_id = f"scenario-{scenario_class}-verify-execution"
    readback_id = f"scenario-{scenario_class}-verify-readback"
    proof_id = f"scenario-{scenario_class}-recovery-proof"
    recovery = acceptance.Wc029RecoveryActionEvidence.model_validate_json(
        bundle.artifact_paths[f"scenario-{scenario_class}-recovery-action"].read_bytes()
    )
    execution = _read_json(bundle.artifact_paths[execution_id])
    execution["startedAt"] = (
        (recovery.recovered_at - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    )
    execution["completedAt"] = (
        (recovery.recovered_at - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    )
    execution_payload = dict(execution)
    execution_payload.pop("executionDigest")
    execution["executionDigest"] = compute_artifact_digest(execution_payload)
    _write(bundle.artifact_paths[execution_id], execution)

    readback = _read_json(bundle.artifact_paths[readback_id])
    readback["executionDigest"] = execution["executionDigest"]
    readback["observedAt"] = (
        (recovery.recovered_at - timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    )
    readback_payload = dict(readback)
    readback_payload.pop("readbackDigest")
    readback["readbackDigest"] = compute_artifact_digest(readback_payload)
    _write(bundle.artifact_paths[readback_id], readback)

    proof = _read_json(bundle.artifact_paths[proof_id])
    proof["postRecoveryJobReadback"]["contentSha256"] = sha256_hex(
        bundle.artifact_paths[readback_id].read_bytes()
    )
    _write(bundle.artifact_paths[proof_id], proof)
    _refresh_scenario_execution_binding(bundle, scenario_class)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="post-recovery Job evidence|outside the signed verify",
    ):
        _aggregate(bundle)


def test_deployment_baseline_proof_and_final_queue_chronology_is_ordered(
    tmp_path: Path,
) -> None:
    deployment = _build_bundle(tmp_path / "deployment")
    readback_path = deployment.artifact_paths["foundation-readback"]
    readback = _read_json(readback_path)
    readback["observedAt"] = _NOW.isoformat().replace("+00:00", "Z")
    _write(readback_path, readback)
    global_job_path = deployment.artifact_paths["global-job-readback"]
    global_job = _read_json(global_job_path)
    for reference in global_job["resultArtifacts"]:
        if reference["artifactId"] == "foundation-readback":
            reference["contentSha256"] = sha256_hex(readback_path.read_bytes())
    global_job_payload = dict(global_job)
    global_job_payload.pop("readbackDigest")
    global_job["readbackDigest"] = compute_artifact_digest(global_job_payload)
    _write(global_job_path, global_job)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="global deployment, baseline, scenario, and final chronology",
    ):
        _aggregate(deployment)

    proof_order = _build_bundle(tmp_path / "proof")
    scenario_class = "disk-capacity-pressure"
    readback_id = f"scenario-{scenario_class}-verify-readback"
    proof_id = f"scenario-{scenario_class}-recovery-proof"
    job_readback = acceptance.Wc029JobReadbackEvidence.model_validate_json(
        proof_order.artifact_paths[readback_id].read_bytes()
    )
    proof_path = proof_order.artifact_paths[proof_id]
    proof = _read_json(proof_path)
    proof["verifiedAt"] = (
        (job_readback.observed_at - timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    )
    _write(proof_path, proof)
    _refresh_scenario_execution_binding(proof_order, scenario_class)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="post-recovery Job evidence",
    ):
        _aggregate(proof_order)

    final = _build_bundle(tmp_path / "final")
    final_path = final.artifact_paths["queue-final"]
    final_queue = _read_json(final_path)
    final_queue["capturedAt"] = _SCENARIO_BASE.isoformat().replace(
        "+00:00",
        "Z",
    )
    _write(final_path, final_queue)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="global deployment, baseline, scenario, and final chronology",
    ):
        _aggregate(final)


def test_recovery_state_is_recomputed_and_job_bound(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    scenario_class = "disk-capacity-pressure"
    recovered_id = f"scenario-{scenario_class}-recovered-state"
    readback_id = f"scenario-{scenario_class}-verify-readback"
    proof_id = f"scenario-{scenario_class}-recovery-proof"
    recovered = _read_json(bundle.artifact_paths[recovered_id])
    recovered["stateDocument"]["powerState"] = "stopped"
    recovered["stateDigest"] = compute_artifact_digest(
        {
            "targetResourceId": recovered["targetResourceId"].casefold(),
            "stateDocument": recovered["stateDocument"],
        }
    )
    _write(bundle.artifact_paths[recovered_id], recovered)

    readback = _read_json(bundle.artifact_paths[readback_id])
    for reference in readback["resultArtifacts"]:
        if reference["artifactId"] == recovered_id:
            reference["contentSha256"] = sha256_hex(
                bundle.artifact_paths[recovered_id].read_bytes()
            )
    readback_payload = dict(readback)
    readback_payload.pop("readbackDigest")
    readback["readbackDigest"] = compute_artifact_digest(readback_payload)
    _write(bundle.artifact_paths[readback_id], readback)

    proof = _read_json(bundle.artifact_paths[proof_id])
    proof["recoveredState"]["contentSha256"] = sha256_hex(
        bundle.artifact_paths[recovered_id].read_bytes()
    )
    proof["recoveredStateDigest"] = recovered["stateDigest"]
    proof["postRecoveryJobReadback"]["contentSha256"] = sha256_hex(
        bundle.artifact_paths[readback_id].read_bytes()
    )
    _write(bundle.artifact_paths[proof_id], proof)
    _refresh_scenario_execution_binding(bundle, scenario_class)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="phase receipts",
    ):
        _aggregate(bundle)

    missing_reference = _build_bundle(tmp_path / "missing-reference")
    readback_id = f"scenario-{scenario_class}-verify-readback"
    proof_id = f"scenario-{scenario_class}-recovery-proof"
    readback_path = missing_reference.artifact_paths[readback_id]
    readback = _read_json(readback_path)
    readback["resultArtifacts"] = [
        item
        for item in readback["resultArtifacts"]
        if item["artifactId"] != f"scenario-{scenario_class}-recovered-state"
    ]
    readback_payload = dict(readback)
    readback_payload.pop("readbackDigest")
    readback["readbackDigest"] = compute_artifact_digest(readback_payload)
    _write(readback_path, readback)
    proof_path = missing_reference.artifact_paths[proof_id]
    proof = _read_json(proof_path)
    proof["postRecoveryJobReadback"]["contentSha256"] = sha256_hex(readback_path.read_bytes())
    _write(proof_path, proof)
    _refresh_scenario_execution_binding(
        missing_reference,
        scenario_class,
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="post-recovery Job evidence",
    ):
        _aggregate(missing_reference)


def test_manifest_authority_feed_indexes_and_notification_closure_are_required(
    tmp_path: Path,
) -> None:
    clauses = _build_bundle(tmp_path / "clauses")
    manifest_path = clauses.artifact_paths["published-manifest"]
    manifest = _read_json(manifest_path)
    manifest["citedClauses"][0] = {
        "clauseId": "synthetic-availability",
        "jsonPointer": "/profiles/production",
        "clauseDigest": compute_artifact_digest(
            manifest["manifestDocument"]["profiles"]["production"]
        ),
    }
    _write(manifest_path, manifest)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="approved inventory|published manifest|violates",
    ):
        _aggregate(clauses)

    authority = _build_bundle(tmp_path / "authority")
    authority_path = authority.artifact_paths["publication-authority-attestation"]
    authority_payload = _read_json(authority_path)
    authority_payload["detachedSignature"] = "Zm9yZ2Vk"
    _write(authority_path, authority_payload)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="invalid RSA signature",
    ):
        _aggregate(authority)

    missing_index = _build_bundle(tmp_path / "missing-index")
    scenario = _scenario(missing_index, "web-tier-failure")
    feed_index_id = "scenario-web-tier-failure-feed-index-active"
    scenario["phases"]["observe"].remove(feed_index_id)
    missing_index.index["artifacts"] = [
        item for item in missing_index.index["artifacts"] if item["artifactId"] != feed_index_id
    ]
    missing_index.artifact_paths[feed_index_id].unlink()
    _rewrite_index(missing_index)
    with pytest.raises(acceptance.Wc029AcceptanceEvidenceError):
        _aggregate(missing_index)

    notification = _build_bundle(tmp_path / "notification")
    notification_id = "scenario-web-tier-failure-notification-active"
    envelope = IncidentNotificationEnvelopeV2.model_validate_json(
        notification.artifact_paths[notification_id].read_bytes()
    )
    notification_payload = envelope.notification.model_dump(
        mode="python",
        by_alias=True,
        exclude={"notification_digest"},
    )
    notification_payload["feedIndexDigest"] = "sha256:" + ("f" * 64)
    new_digest = compute_artifact_digest(
        _json_value(
            {key: value for key, value in notification_payload.items() if key != "notificationId"}
        )
    )
    changed_notification = IncidentNotificationV2(
        **notification_payload,
        notificationDigest=new_digest,
    )
    signature = (
        base64.urlsafe_b64encode(
            notification.private_keys["notification"].sign(
                changed_notification.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    changed_envelope = IncidentNotificationEnvelopeV2(
        schemaVersion="athena.wc027IncidentNotificationEnvelope.v2",
        notification=changed_notification,
        attestation=IncidentNotificationV2Attestation(
            schemaVersion=("athena.wc027IncidentNotificationAttestation.v2"),
            notificationId=changed_notification.notification_id,
            notificationDigest=changed_notification.notification_digest,
            signatureAlgorithm="RS256",
            keyVaultKeyId=notification.keys["notification"].key_id,
            signedPreimageDigest=sha256_hex(changed_notification.canonical_bytes()),
            detachedSignature=signature,
        ),
    )
    _write(notification.artifact_paths[notification_id], changed_envelope)
    _refresh_scenario_execution_binding(
        notification,
        "web-tier-failure",
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="signed incident assets do not form one chain",
    ):
        _aggregate(notification)

    occurrence = _build_bundle(tmp_path / "occurrence")
    notification_id = "scenario-web-tier-failure-notification-active"
    envelope = IncidentNotificationEnvelopeV2.model_validate_json(
        occurrence.artifact_paths[notification_id].read_bytes()
    )
    notification_payload = envelope.notification.model_dump(
        mode="python",
        by_alias=True,
        exclude={"notification_id", "notification_digest"},
    )
    notification_payload["occurrenceDigest"] = "sha256:" + ("e" * 64)
    notification_digest = compute_artifact_digest(_json_value(notification_payload))
    identity_digest = compute_artifact_digest(
        {
            "schemaVersion": ("athena.wc027IncidentNotificationIdentity.v1"),
            "incidentId": notification_payload["incidentId"],
            "transitionId": notification_payload["transitionId"],
            "lifecycle": notification_payload["lifecycle"],
            "stateResultDigest": notification_payload["stateResultDigest"],
            "occurrenceDigest": notification_payload["occurrenceDigest"],
            "guidanceAsset": _json_value(notification_payload["guidanceAsset"]),
        }
    )
    changed_notification = IncidentNotificationV2(
        **notification_payload,
        notificationId=("notify-v2-" + identity_digest.removeprefix("sha256:")),
        notificationDigest=notification_digest,
    )
    signature = (
        base64.urlsafe_b64encode(
            occurrence.private_keys["notification"].sign(
                changed_notification.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    _write(
        occurrence.artifact_paths[notification_id],
        IncidentNotificationEnvelopeV2(
            schemaVersion="athena.wc027IncidentNotificationEnvelope.v2",
            notification=changed_notification,
            attestation=IncidentNotificationV2Attestation(
                schemaVersion=("athena.wc027IncidentNotificationAttestation.v2"),
                notificationId=changed_notification.notification_id,
                notificationDigest=(changed_notification.notification_digest),
                signatureAlgorithm="RS256",
                keyVaultKeyId=occurrence.keys["notification"].key_id,
                signedPreimageDigest=sha256_hex(changed_notification.canonical_bytes()),
                detachedSignature=signature,
            ),
        ),
    )
    _refresh_scenario_execution_binding(
        occurrence,
        "web-tier-failure",
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="signed incident assets do not form one chain",
    ):
        _aggregate(occurrence)


def test_deployment_scope_parameters_handoffs_and_capabilities_are_trusted(
    tmp_path: Path,
) -> None:
    scope = _build_bundle(tmp_path / "scope")
    plan_path = scope.artifact_paths["foundation-plan"]
    plan = _read_json(plan_path)
    plan["subscriptionId"] = "00000000-0000-0000-0000-000000000099"
    _write(plan_path, plan)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="does not match inventory",
    ):
        _aggregate(scope)

    parameters = _build_bundle(tmp_path / "parameters")
    plan_path = parameters.artifact_paths["foundation-plan"]
    plan = _read_json(plan_path)
    plan["effectiveParameterSha256"] = "sha256:" + ("f" * 64)
    _write(plan_path, plan)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="does not match inventory",
    ):
        _aggregate(parameters)

    bindings = _build_bundle(tmp_path / "bindings")
    handoff_path = bindings.artifact_paths["foundation-output"]
    handoff = _read_json(handoff_path)
    handoff["parameterBindings"] = {
        "location": "wrong-region",
        "unexpected": True,
    }
    handoff["parameterBindingsSha256"] = sha256_hex(canonicalize_json(handoff["parameterBindings"]))
    _write(handoff_path, handoff)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="reviewed plan|successful output state",
    ):
        _aggregate(bindings)

    capabilities = _build_bundle(tmp_path / "capabilities")
    readback_path = capabilities.artifact_paths["foundation-readback"]
    readback = _read_json(readback_path)
    readback["outputs"].pop("wc029ScenarioCapabilities")
    readback["outputsSha256"] = sha256_hex(canonicalize_json(readback["outputs"]))
    _write(readback_path, readback)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="successful output state|scenario capabilities",
    ):
        _aggregate(capabilities)

    upstream = _build_bundle(tmp_path / "upstream")
    plan_path = upstream.artifact_paths["foundation-plan"]
    plan = _read_json(plan_path)
    plan["publisherHandoffPath"] = "C:/synthetic/wrong-stage.json"
    plan["publisherHandoffSha256"] = "sha256:" + ("e" * 64)
    _write(plan_path, plan)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="unapproved named handoffs",
    ):
        _aggregate(upstream)


def test_incident_state_digest_and_recursive_json_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication, _ = _publication_assets()
    state = _trusted_incident_assets(publication).active_state.model_copy(
        update={"result_digest": "sha256:" + ("f" * 64)}
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="signature preimage",
    ):
        acceptance._require_incident_state_digest(state)

    bundle = _build_bundle(tmp_path)
    nested: object = {"leaf": True}
    for _ in range(acceptance.MAX_JSON_DEPTH + 2):
        nested = {"nested": nested}
    bundle.artifact_paths["effective-rbac"].write_text(
        json.dumps(nested),
        encoding="utf-8",
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="parse-time depth",
    ):
        _aggregate(bundle)

    monkeypatch.setattr(
        acceptance.json,
        "loads",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RecursionError("synthetic recursion")),
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="strict canonicalizable",
    ):
        acceptance._parse_strict_json(b"{}", label="synthetic")


def test_private_snapshot_detects_parent_directory_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    real_scan = acceptance._scan_bundle_tree
    calls = 0

    def drifting_scan(
        root: Path,
    ) -> tuple[
        dict[str, acceptance._PathIdentity],
        dict[str, acceptance._PathIdentity],
    ]:
        nonlocal calls
        calls += 1
        directories, files = real_scan(root)
        if calls == 2:
            directories = dict(directories)
            directories["."] = replace(
                directories["."],
                modified_ns=directories["."].modified_ns + 1,
            )
        return directories, files

    monkeypatch.setattr(acceptance, "_scan_bundle_tree", drifting_scan)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="changed while the private snapshot",
    ):
        _aggregate(bundle)


def test_successful_publication_is_committed_before_staging_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    record = _aggregate(bundle)
    original_unlink = Path.unlink

    def fail_staging_cleanup(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> None:
        if path.name.startswith(".wc029-acceptance-") and path.suffix == ".tmp":
            raise OSError("synthetic cleanup failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_staging_cleanup)
    output = acceptance.write_acceptance_record(
        record,
        output_directory=bundle.output,
        evidence_root=bundle.root,
    )

    assert output.is_file()
    assert output.read_bytes() == record.canonical_bytes()


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
    record = _aggregate(bundle)

    rendered = record.canonical_json()

    assert str(bundle.root) not in rendered
    assert all(not Path(item.path).is_absolute() for item in record.artifacts)
    assert record.source_index.path == "acceptance-index.json"
