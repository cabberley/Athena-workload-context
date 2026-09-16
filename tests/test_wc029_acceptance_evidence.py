from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel

import athena_context.wc029_acceptance_evidence as acceptance
from athena_context.contracts import (
    CORRELATION_REQUEST_SCHEMA_VERSION,
    MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION,
    ActiveIncidentEntry,
    ActiveIncidentIndex,
    ActiveIncidentIndexAttestation,
    ChangeEvidenceArtifact,
    CorrelationReport,
    CorrelationRequest,
    DependencyPath,
    IncidentBoundCorrelationRequest,
    IncidentBoundCorrelationRequestAttestation,
    IncidentCorrelationSubject,
    IncidentCorrelationSubjectAttestation,
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
    IncidentGuidanceSourceBinding,
    IncidentNotificationEnvelopeV2,
    IncidentNotificationV2,
    IncidentNotificationV2Attestation,
    IncidentState,
    IncidentStateAttestation,
    MonitoringEvidenceBundle,
    MonitoringEvidenceHandoff,
    PublishedContextAuthority,
    PublishedCorrelationReportAssetReference,
    PublishedCorrelationReportAttestation,
    PublishedCorrelationReportStatement,
    PublishedRuntimeContextBinding,
    RootCauseHypothesis,
    VersionPinnedBlobReference,
    build_incident_enrichment_feed_pointer,
    build_incident_feed_index_v2,
    build_incident_occurrence_receipt,
    canonicalize_json,
    compute_artifact_digest,
    incident_state_signature_preimage,
    resolve_manifest_profile,
    sha256_hex,
    validate_incident_enrichment_assets,
    validate_incident_enrichment_manifest_binding,
    validate_incident_guidance_assets,
    validate_published_correlation_report_assets,
)
from athena_context.contracts.change_ingestion import (
    change_evidence_attestation_preimage,
)
from athena_context.contracts.monitoring import monitoring_handoff_preimage
from athena_context.fixtures import load_canonical_manifest
from athena_context.monitoring_collection import (
    CommittedMonitoringCollection,
    PreparedMonitoringCollection,
    build_collected_correlation_request,
)
from test_presentation_asset_gateway import _resolved_feed_v2_source_fixture
from test_wc024_monitoring_contract import _trusted_signed_handoff
from test_wc026_correlation_contract import (
    DB_ID,
    WEB_ID,
    _change_pair,
    _hypothesis,
    _report_for,
    _request,
)
from test_wc028_monitoring_collection import _execute as _execute_wc028_collection

_NOW = datetime(2026, 9, 14, 4, 0, tzinfo=UTC)
_SCENARIO_BASE = datetime(2026, 9, 10, 1, 45, tzinfo=UTC)
_SOURCE_COMMIT = "a" * 40
_TEMPLATE_DIGEST = "sha256:" + ("b" * 64)
_MANIFEST_DIGEST = "sha256:" + ("c" * 64)
_IMAGE = "synthetic.azurecr.io/athena/wc029-acceptance@sha256:" + ("d" * 64)
_PRINCIPAL_ID = "00000000-0000-0000-0000-000000000001"
_SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
_JOB_RESOURCE_GROUP = "rg-athena-wc029-synthetic"
_GLOBAL_JOB_RESOURCE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-athena-wc029-synthetic/providers/Microsoft.App/"
    "jobs/athena-wc029-global-synthetic"
)
_SCENARIO_JOB_RESOURCE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-athena-wc029-synthetic/providers/Microsoft.App/"
    "jobs/athena-wc029-scenario-synthetic"
)
_JOB_IDENTITY_RESOURCE_IDS = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-athena-wc029-synthetic/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/athena-wc029-job-synthetic",
)
_JOB_CAPTURE_ANCHOR_RESOURCE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-athena-wc029-synthetic/providers/Microsoft.Storage/"
    "storageAccounts/athenawc029synthetic/blobServices/default/containers/job-captures"
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
    correlation_request: CorrelationRequest
    incident_bound_request: IncidentBoundCorrelationRequest
    report: CorrelationReport
    report_attestation: PublishedCorrelationReportAttestation
    guidance: IncidentGuidance
    guidance_attestation: IncidentGuidanceAttestation
    enrichment: IncidentEnrichmentManifest
    enrichment_attestation: IncidentEnrichmentAttestation
    active_feed: IncidentEnrichmentFeedPointer
    active_feed_attestation: IncidentEnrichmentFeedPointerAttestation
    active_source_index: ActiveIncidentIndex
    active_source_index_attestation: ActiveIncidentIndexAttestation
    active_feed_index: IncidentFeedIndexV2
    active_feed_index_attestation: IncidentFeedIndexAttestationV2
    resolved_feed: IncidentEnrichmentFeedPointer
    resolved_feed_attestation: IncidentEnrichmentFeedPointerAttestation
    resolved_source_index: ActiveIncidentIndex
    resolved_source_index_attestation: ActiveIncidentIndexAttestation
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


def _rebind_report_assets(
    _source_report: CorrelationReport,
    source_attestation: PublishedCorrelationReportAttestation,
    *,
    correlation_request: CorrelationRequest,
    incident_bound_request: IncidentBoundCorrelationRequest | None = None,
    active_state: IncidentState,
    active_state_attestation: IncidentStateAttestation,
    authority: PublishedContextAuthority,
    key: KeyMaterial,
    private_key: rsa.RSAPrivateKey,
) -> tuple[CorrelationReport, PublishedCorrelationReportAttestation]:
    source_hypothesis = _hypothesis(citation=correlation_request.evidence_index[0])
    hypothesis_payload = source_hypothesis.model_dump(
        mode="python",
        by_alias=True,
        exclude={"hypothesis_id", "hypothesis_digest"},
    )
    hypothesis_payload["affectedPathId"] = correlation_request.context_binding.dependency_paths[
        0
    ].path_id
    hypothesis_digest = compute_artifact_digest(
        _json_value({key: value for key, value in hypothesis_payload.items() if key != "rank"})
    )
    hypothesis = RootCauseHypothesis(
        **hypothesis_payload,
        hypothesisId=("hyp-" + hypothesis_digest.removeprefix("sha256:")[:32]),
        hypothesisDigest=hypothesis_digest,
    )
    report = _report_for(
        correlation_request,
        hypothesis,
    )
    state_prefix = (
        f"incidents/{active_state.incident_id}/versions/"
        f"{active_state.result_digest.removeprefix('sha256:')}"
    )
    statement_payload = source_attestation.statement.model_dump(
        mode="python",
        by_alias=True,
        exclude={"statement_id", "statement_digest"},
    )
    statement_payload.update(
        {
            "incidentStateResultDigest": active_state.result_digest,
            "incidentStateReference": VersionPinnedBlobReference(
                name=f"{state_prefix}/state.json",
                version=source_attestation.statement.incident_state_reference.version,
                contentDigest=sha256_hex(active_state.canonical_bytes()),
            ),
            "incidentStateAttestationReference": VersionPinnedBlobReference(
                name=f"{state_prefix}/attestation.json",
                version=(source_attestation.statement.incident_state_attestation_reference.version),
                contentDigest=sha256_hex(active_state_attestation.canonical_bytes()),
            ),
            "correlationRequestDigest": report.request_digest,
            "correlationTransitionDigest": report.transition_digest,
            "reportId": report.report_id,
            "reportDigest": report.report_digest,
            "reportContentDigest": sha256_hex(report.canonical_bytes()),
            "authorityProofDigest": sha256_hex(authority.canonical_bytes()),
        }
    )
    if incident_bound_request is not None:
        subject = incident_bound_request.incident_subject
        statement_payload.update(
            {
                "incidentId": subject.incident_id,
                "incidentTransitionId": subject.incident_transition_id,
                "incidentRevision": subject.incident_revision,
                "incidentStateResultDigest": subject.incident_state_digest,
                "incidentStateReference": subject.state_reference,
                "incidentStateAttestationReference": (subject.attestation_reference),
                "incidentSubjectId": subject.subject_id,
                "incidentSubjectDigest": subject.subject_digest,
                "incidentBoundRequestId": incident_bound_request.request_id,
                "incidentBoundRequestDigest": (incident_bound_request.binding_digest),
            }
        )
    statement_digest = compute_artifact_digest(_json_value(statement_payload))
    statement = PublishedCorrelationReportStatement(
        **statement_payload,
        statementId=("report-publication-" + statement_digest.removeprefix("sha256:")[:32]),
        statementDigest=statement_digest,
    )
    attestation = PublishedCorrelationReportAttestation(
        schemaVersion=("athena.wc027PublishedCorrelationReportAttestation.v1"),
        statement=statement,
        signatureAlgorithm="RS256",
        keyVaultKeyId=key.key_id,
        signedPreimageDigest=sha256_hex(statement.canonical_bytes()),
        detachedSignature=(
            base64.urlsafe_b64encode(
                private_key.sign(
                    statement.canonical_bytes(),
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            )
            .decode("ascii")
            .rstrip("=")
        ),
    )
    return report, attestation


def _correlation_only_report_attestation(
    request: CorrelationRequest,
    report: CorrelationReport,
    authority: PublishedContextAuthority,
    *,
    key: KeyMaterial,
    private_key: rsa.RSAPrivateKey,
) -> acceptance.Wc029CorrelationOnlyReportAttestation:
    statement_payload: dict[str, object] = {
        "schemaVersion": "athena.wc029CorrelationOnlyReportStatement.v1",
        "purpose": "athena.wc029.publish-correlation-only-report",
        "correlationRequestId": request.request_id,
        "correlationRequestDigest": request.request_digest,
        "contextBindingDigest": request.context_binding.binding_digest,
        "reportId": report.report_id,
        "reportDigest": report.report_digest,
        "reportContentDigest": sha256_hex(report.canonical_bytes()),
        "authorityProofDigest": sha256_hex(authority.canonical_bytes()),
        "incidentProvenanceAbsent": True,
        "noAutoRemediation": True,
    }
    statement_digest = compute_artifact_digest(_json_value(statement_payload))
    statement = acceptance.Wc029CorrelationOnlyReportStatement(
        **statement_payload,
        statementId=("correlation-only-report-" + statement_digest.removeprefix("sha256:")[:32]),
        statementDigest=statement_digest,
    )
    return acceptance.Wc029CorrelationOnlyReportAttestation(
        schemaVersion=(acceptance.CORRELATION_ONLY_REPORT_ATTESTATION_SCHEMA_VERSION),
        statement=statement,
        signatureAlgorithm="RS256",
        keyVaultKeyId=key.key_id,
        signedPreimageDigest=sha256_hex(statement.canonical_bytes()),
        detachedSignature=(
            base64.urlsafe_b64encode(
                private_key.sign(
                    statement.canonical_bytes(),
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            )
            .decode("ascii")
            .rstrip("=")
        ),
    )


def _publication_assets() -> tuple[PublicationAssets, rsa.RSAPrivateKey]:
    key, private_key = _private_key_material("context-authority", "a")
    manifest_document = load_canonical_manifest()
    published_at = manifest_document.audit.published_at
    publication_record_digest = "sha256:" + ("1" * 64)
    audit_head_digest = "sha256:" + ("2" * 64)
    resolved_profile = resolve_manifest_profile(
        manifest_document,
        "production",
        as_of=published_at,
    )
    dependency_graph_digest = compute_artifact_digest(
        {
            "manifestId": manifest_document.manifest_id,
            "manifestVersion": manifest_document.manifest_version,
            "profileId": resolved_profile.profile_id,
            "relationships": [
                item.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
                for item in sorted(
                    resolved_profile.relationships,
                    key=lambda item: item.canonical_json(),
                )
            ],
        }
    )
    relationship = next(
        item
        for item in resolved_profile.relationships
        if item.relationship_id == "production-web-depends-db"
    )
    dependency_path_payload: dict[str, object] = {
        "pathClass": "declared",
        "sourceRoleRef": "web",
        "targetRoleRef": "database-primary",
        "relationshipIds": (relationship.relationship_id,),
        "resourceIds": tuple(sorted((DB_ID.lower(), WEB_ID.lower()))),
    }
    dependency_path_digest = compute_artifact_digest(_json_value(dependency_path_payload))
    dependency_path = DependencyPath(
        **dependency_path_payload,
        pathId=("path-" + dependency_path_digest.removeprefix("sha256:")[:32]),
        pathDigest=dependency_path_digest,
    )
    request_template = _request(dependency_paths=(dependency_path,))
    workload_id = request_template.monitoring_bundle.workload_id
    context_binding_payload: dict[str, object] = {
        "workloadId": workload_id,
        "manifestId": manifest_document.manifest_id,
        "manifestVersion": manifest_document.manifest_version,
        "manifestDigest": manifest_document.compatibility.artifact_digest,
        "profileId": resolved_profile.profile_id,
        "resolvedProfileDigest": resolved_profile.resolved_profile_digest,
        "dependencyGraphDigest": dependency_graph_digest,
        "dependencyPaths": (dependency_path,),
        "requiredCoverageScopeDigests": (
            request_template.monitoring_bundle.expected_coverage_scope_digests
        ),
    }
    context_binding_payload_digest = compute_artifact_digest(_json_value(context_binding_payload))
    authority_payload: dict[str, object] = {
        "workloadId": workload_id,
        "manifestId": manifest_document.manifest_id,
        "manifestVersion": manifest_document.manifest_version,
        "manifestDigest": manifest_document.compatibility.artifact_digest,
        "profileId": resolved_profile.profile_id,
        "resolvedProfileDigest": resolved_profile.resolved_profile_digest,
        "dependencyGraphDigest": dependency_graph_digest,
        "contextBindingPayloadDigest": context_binding_payload_digest,
        "publicationRecordDigest": publication_record_digest,
        "auditHeadDigest": audit_head_digest,
        "publishedAt": published_at,
    }
    authority_digest = compute_artifact_digest(_json_value(authority_payload))
    authority = PublishedContextAuthority(
        **authority_payload,
        authorityId=("publication-authority-" + authority_digest.removeprefix("sha256:")[:32]),
        authorityDigest=authority_digest,
    )
    authority_reference = VersionPinnedBlobReference(
        name=f"context-authority/{authority.authority_id}/authority.json",
        version="2026-09-10T00:45:00.0000000Z",
        contentDigest=sha256_hex(authority.canonical_bytes()),
    )
    context_binding_document: dict[str, object] = {
        **context_binding_payload,
        "bindingMode": "publishedRuntime",
        "publicationAuthority": authority,
        "publicationAuthorityReference": authority_reference,
        "previewOnly": False,
    }
    context_binding = PublishedRuntimeContextBinding(
        **context_binding_document,
        bindingDigest=compute_artifact_digest(_json_value(context_binding_document)),
    )
    profile_document = manifest_document.profiles["production"]
    cited_clauses = tuple(
        sorted(
            (
                *(
                    acceptance.Wc029PublishedClause(
                        clauseKind="constraint",
                        clauseId=clause.constraint_id,
                        jsonPointer=f"/profiles/production/constraints/{index}",
                        clauseDigest=compute_artifact_digest(
                            clause.model_dump(
                                mode="json",
                                by_alias=True,
                                exclude_none=True,
                            )
                        ),
                    )
                    for index, clause in enumerate(profile_document.constraints)
                ),
                *(
                    acceptance.Wc029PublishedClause(
                        clauseKind="control",
                        clauseId=control.control_id,
                        jsonPointer=f"/profiles/production/controls/{index}",
                        clauseDigest=compute_artifact_digest(
                            control.model_dump(
                                mode="json",
                                by_alias=True,
                                exclude_none=True,
                            )
                        ),
                    )
                    for index, control in enumerate(profile_document.controls)
                ),
            ),
            key=lambda item: item.clause_id,
        )
    )
    manifest = acceptance.Wc029PublishedManifestEvidence(
        schemaVersion=acceptance.PUBLISHED_MANIFEST_SCHEMA_VERSION,
        workloadId=workload_id,
        manifestId=manifest_document.manifest_id,
        manifestVersion=manifest_document.manifest_version,
        profileId=resolved_profile.profile_id,
        manifestDocument=manifest_document,
        contextBinding=context_binding,
        citedClauses=cited_clauses,
        publicationRecordDigest=publication_record_digest,
        auditHeadDigest=audit_head_digest,
        publishedAt=published_at,
        manifestDigest=manifest_document.compatibility.artifact_digest,
        resolvedProfileDigest=resolved_profile.resolved_profile_digest,
        dependencyGraphDigest=dependency_graph_digest,
        contextBindingPayloadDigest=context_binding_payload_digest,
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
    correlation_request: CorrelationRequest | None = None,
    *,
    monitoring_key: KeyMaterial | None = None,
    monitoring_private_key: rsa.RSAPrivateKey | None = None,
) -> IncidentAssets:
    fixture = _resolved_feed_v2_source_fixture()
    payloads = _schema_payloads(fixture)
    source_active_state = next(
        item
        for item in (
            IncidentState.model_validate_json(payload)
            for payload in payloads["athena.incidentState.v1"]
        )
        if item.lifecycle == "active"
    )
    source_report = _one_model(
        payloads,
        "athena.wc026CorrelationReport.v1",
        CorrelationReport,
    )
    old_report_attestation = _one_model(
        payloads,
        "athena.wc027PublishedCorrelationReportAttestation.v1",
        PublishedCorrelationReportAttestation,
    )
    source_guidance = _one_model(
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

    active_state_payload = source_active_state.model_dump(
        mode="python",
        by_alias=True,
        exclude={"result_digest"},
    )
    active_state_payload["findings"] = tuple(
        {
            **finding.model_dump(mode="python", by_alias=True),
            "clauseId": "web-zone-distribution",
        }
        for finding in source_active_state.findings
    )
    active_state = IncidentState(
        **active_state_payload,
        resultDigest=sha256_hex(
            canonicalize_json(_json_value(active_state_payload)).encode("utf-8")
        ),
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
    if correlation_request is None:
        if (monitoring_key is None) != (monitoring_private_key is None):
            raise ValueError("monitoring key and private key must be supplied together")
        if monitoring_key is None or monitoring_private_key is None:
            monitoring_key, monitoring_private_key = _private_key_material(
                "monitoring",
                "2",
            )
        correlation_request = _correlation_request_for_context(
            publication.manifest.context_binding,
            trusted_as_of=source_report.as_of,
            rule_catalog_digest=sha256_hex("web-tier-failure:rule-catalog"),
            monitoring_key=monitoring_key,
            monitoring_private_key=monitoring_private_key,
        )
    incident_bound_request = _incident_bound_request_for_state(
        correlation_request,
        active_state,
        active_state_attestation,
        incident_key=keys["incident"],
        incident_private_key=private_keys["incident"],
        report_key=keys["report"],
        report_private_key=private_keys["report"],
    )
    report, report_attestation = _rebind_report_assets(
        source_report,
        old_report_attestation,
        correlation_request=correlation_request,
        incident_bound_request=incident_bound_request,
        active_state=active_state,
        active_state_attestation=active_state_attestation,
        authority=publication.authority.authority,
        key=keys["report"],
        private_key=private_keys["report"],
    )
    source_binding_payload = source_guidance.source_binding.model_dump(
        mode="python",
        by_alias=True,
        exclude={"source_id", "source_digest"},
    )
    source_binding_payload.update(
        {
            "incidentSubjectId": (incident_bound_request.incident_subject.subject_id),
            "incidentSubjectDigest": (incident_bound_request.incident_subject.subject_digest),
            "incidentBoundRequestId": incident_bound_request.request_id,
            "incidentBoundRequestDigest": (incident_bound_request.binding_digest),
            "incidentStateDigest": active_state.result_digest,
            "correlationReportId": report.report_id,
            "correlationReportDigest": report.report_digest,
            "correlationRequestDigest": report.request_digest,
            "transitionDigest": report.transition_digest,
            "ruleCatalogDigest": report.rule_catalog_digest,
            "inputInventoryDigest": report.input_inventory_digest,
        }
    )
    source_binding_digest = compute_artifact_digest(_json_value(source_binding_payload))
    source_binding = IncidentGuidanceSourceBinding(
        **source_binding_payload,
        sourceId=("guidance-source-" + source_binding_digest.removeprefix("sha256:")[:32]),
        sourceDigest=source_binding_digest,
    )
    guidance_payload = source_guidance.model_dump(
        mode="python",
        by_alias=True,
        exclude={"guidance_id", "guidance_digest"},
    )
    guidance_payload["sourceBinding"] = source_binding
    guidance_digest = compute_artifact_digest(_json_value(guidance_payload))
    guidance = IncidentGuidance(
        **guidance_payload,
        guidanceId=("incident-guidance-" + guidance_digest.removeprefix("sha256:")[:32]),
        guidanceDigest=guidance_digest,
    )
    report_asset_payload = old_enrichment.correlation_report_asset.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    report_prefix = (
        f"incidents/{active_state.incident_id}/versions/"
        f"{active_state.result_digest.removeprefix('sha256:')}/"
        f"correlation-reports/{report.report_id}"
    )
    report_asset_payload.update(
        {
            "incidentStateResultDigest": active_state.result_digest,
            "incidentSubjectId": (incident_bound_request.incident_subject.subject_id),
            "incidentSubjectDigest": (incident_bound_request.incident_subject.subject_digest),
            "incidentBoundRequestId": incident_bound_request.request_id,
            "incidentBoundRequestDigest": (incident_bound_request.binding_digest),
            "correlationRequestDigest": report.request_digest,
            "correlationTransitionDigest": report.transition_digest,
            "reportId": report.report_id,
            "reportDigest": report.report_digest,
            "reportContentDigest": sha256_hex(report.canonical_bytes()),
            "authorityProofDigest": (report_attestation.statement.authority_proof_digest),
            "publicationStatementId": report_attestation.statement.statement_id,
            "publicationStatementDigest": (report_attestation.statement.statement_digest),
            "reportReference": VersionPinnedBlobReference(
                name=f"{report_prefix}/report.json",
                version=(old_enrichment.correlation_report_asset.report_reference.version),
                contentDigest=sha256_hex(report.canonical_bytes()),
            ),
            "attestationReference": VersionPinnedBlobReference(
                name=f"{report_prefix}/attestation.json",
                version=(old_enrichment.correlation_report_asset.attestation_reference.version),
                contentDigest=sha256_hex(report_attestation.canonical_bytes()),
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
    guidance_asset_payload = old_enrichment.guidance_asset.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    guidance_prefix = (
        f"incidents/{active_state.incident_id}/versions/"
        f"{active_state.result_digest.removeprefix('sha256:')}/"
        f"guidance/{guidance.guidance_id}"
    )
    guidance_asset_payload.update(
        {
            "incidentStateDigest": active_state.result_digest,
            "guidanceId": guidance.guidance_id,
            "guidanceDigest": guidance.guidance_digest,
            "guidanceReference": VersionPinnedBlobReference(
                name=f"{guidance_prefix}/guidance.json",
                version=old_enrichment.guidance_asset.guidance_reference.version,
                contentDigest=sha256_hex(guidance.canonical_bytes()),
            ),
            "attestationReference": VersionPinnedBlobReference(
                name=f"{guidance_prefix}/attestation.json",
                version=old_enrichment.guidance_asset.attestation_reference.version,
                contentDigest=sha256_hex(guidance_attestation.canonical_bytes()),
            ),
        }
    )
    guidance_asset_digest = compute_artifact_digest(_json_value(guidance_asset_payload))
    guidance_asset = IncidentGuidanceAssetReference(
        **guidance_asset_payload,
        referenceId=("guidance-asset-" + guidance_asset_digest.removeprefix("sha256:")[:32]),
        referenceDigest=guidance_asset_digest,
    )
    enrichment_payload = old_enrichment.model_dump(
        mode="python",
        by_alias=True,
        exclude={"enrichment_id", "manifest_digest"},
    )
    enrichment_payload.update(
        {
            "incidentStateResultDigest": active_state.result_digest,
            "incidentStateReference": (report_attestation.statement.incident_state_reference),
            "incidentStateAttestationReference": (
                report_attestation.statement.incident_state_attestation_reference
            ),
            "incidentSubjectId": (incident_bound_request.incident_subject.subject_id),
            "incidentSubjectDigest": (incident_bound_request.incident_subject.subject_digest),
            "incidentBoundRequestId": incident_bound_request.request_id,
            "incidentBoundRequestDigest": (incident_bound_request.binding_digest),
        }
    )
    enrichment_payload["correlationReportAsset"] = report_asset
    enrichment_payload["guidanceAsset"] = guidance_asset
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
    active_state_reference = VersionPinnedBlobReference(
        name=f"{state_prefix}/state.json",
        version="active-state-version",
        contentDigest=sha256_hex(active_state.canonical_bytes()),
    )
    active_state_attestation_reference = VersionPinnedBlobReference(
        name=f"{state_prefix}/attestation.json",
        version="active-state-attestation-version",
        contentDigest=sha256_hex(active_state_attestation.canonical_bytes()),
    )
    active_source_pointer = IncidentFeedPointer(
        schemaVersion="athena.incidentFeed.v1",
        incidentId=active_state.incident_id,
        statePath=f"./{active_state_reference.name}",
        stateSha256=active_state_reference.content_digest,
        attestationPath=f"./{active_state_attestation_reference.name}",
        attestationSha256=active_state_attestation_reference.content_digest,
        pointerAttestationPath=f"./{state_prefix}/pointer-attestation.json",
        keyId=keys["incident"].key_id,
        keyFingerprint=keys["incident"].fingerprint,
        publishedAt=active_state.updated_at + timedelta(seconds=1),
    )
    active_source_pointer_attestation = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=sha256_hex(active_source_pointer.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["incident"].key_id,
        detachedSignature=sign(
            "incident",
            active_source_pointer.canonical_bytes(),
        ),
    )
    active_occurrence = build_incident_occurrence_receipt(
        active_state,
        active_state_attestation,
        active_source_pointer,
        active_source_pointer_attestation,
        state_reference=active_state_reference,
        state_attestation_reference=active_state_attestation_reference,
        pointer_reference=VersionPinnedBlobReference(
            name=f"{state_prefix}/pointer.json",
            version="active-source-pointer-version",
            contentDigest=sha256_hex(active_source_pointer.canonical_bytes()),
        ),
        pointer_attestation_reference=VersionPinnedBlobReference(
            name=f"{state_prefix}/pointer-attestation.json",
            version="active-source-pointer-attestation-version",
            contentDigest=sha256_hex(active_source_pointer_attestation.canonical_bytes()),
        ),
    )
    active_enrichment_prefix = f"{state_prefix}/enrichments/{enrichment.enrichment_id}"
    enrichment_asset_payload = old_active_feed.enrichment_asset.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    enrichment_asset_payload.update(
        {
            "incidentStateResultDigest": active_state.result_digest,
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
    active_feed = build_incident_enrichment_feed_pointer(
        active_occurrence,
        active_enrichment_asset,
        active_state,
        published_at=active_occurrence.published_at + timedelta(seconds=1),
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
    active_source_index = ActiveIncidentIndex(
        schemaVersion="athena.activeIncidentIndex.v1",
        incidents=(
            ActiveIncidentEntry(
                incidentId=active_state.incident_id,
                scenario=active_state.scenario,
                lifecycle="active",
                workloadRole=active_state.workload_role,
                pointerPath=f"./{active_feed.source_pointer_reference.name}",
                pointerSha256=(active_feed.source_pointer_reference.content_digest),
                detectedAt=active_state.detected_at,
                updatedAt=active_state.updated_at,
            ),
        ),
        indexAttestationPath=("./incidents/index-attestations/" + ("c" * 64) + ".json"),
        keyId=keys["incident"].key_id,
        keyFingerprint=keys["incident"].fingerprint,
        publishedAt=active_feed.published_at,
    )
    active_source_index_attestation = ActiveIncidentIndexAttestation(
        schemaVersion="athena.activeIncidentIndexAttestation.v1",
        indexDigest=sha256_hex(active_source_index.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["incident"].key_id,
        detachedSignature=sign(
            "incident",
            active_source_index.canonical_bytes(),
        ),
    )
    active_feed_index = build_incident_feed_index_v2(
        active=(active_entry,),
        recently_resolved=(),
        resolved_retention_start=active_feed.published_at - timedelta(days=7),
        resolved_history_truncated=False,
        resolved_history_total_count=0,
        omitted_resolved_count=None,
        source_active_index_digest=sha256_hex(active_source_index.canonical_bytes()),
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
            "transitionId": (
                "wc016-"
                + sha256_hex(
                    f"{active_state.incident_id}:resolved:{resolved_updated_at.isoformat()}"
                ).removeprefix("sha256:")
            ),
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
    resolved_source_index = ActiveIncidentIndex(
        schemaVersion="athena.activeIncidentIndex.v1",
        incidents=(),
        indexAttestationPath=("./incidents/index-attestations/" + ("d" * 64) + ".json"),
        keyId=keys["incident"].key_id,
        keyFingerprint=keys["incident"].fingerprint,
        publishedAt=source_pointer.published_at,
    )
    resolved_source_index_attestation = ActiveIncidentIndexAttestation(
        schemaVersion="athena.activeIncidentIndexAttestation.v1",
        indexDigest=sha256_hex(resolved_source_index.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=keys["incident"].key_id,
        detachedSignature=sign(
            "incident",
            resolved_source_index.canonical_bytes(),
        ),
    )
    resolved_feed_index = build_incident_feed_index_v2(
        active=(),
        recently_resolved=(resolved_entry,),
        resolved_retention_start=resolved_state.updated_at - timedelta(days=7),
        resolved_history_truncated=False,
        resolved_history_total_count=1,
        omitted_resolved_count=None,
        source_active_index_digest=sha256_hex(resolved_source_index.canonical_bytes()),
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
        correlation_request=correlation_request,
        incident_bound_request=incident_bound_request,
        report=report,
        report_attestation=report_attestation,
        guidance=guidance,
        guidance_attestation=guidance_attestation,
        enrichment=enrichment,
        enrichment_attestation=enrichment_attestation,
        active_feed=active_feed,
        active_feed_attestation=active_feed_attestation,
        active_source_index=active_source_index,
        active_source_index_attestation=(active_source_index_attestation),
        active_feed_index=active_feed_index,
        active_feed_index_attestation=active_feed_index_attestation,
        resolved_feed=resolved_feed,
        resolved_feed_attestation=resolved_feed_attestation,
        resolved_source_index=resolved_source_index,
        resolved_source_index_attestation=(resolved_source_index_attestation),
        resolved_feed_index=resolved_feed_index,
        resolved_feed_index_attestation=(resolved_feed_index_attestation),
        active_notification=active_notification,
        resolved_notification=resolved_notification,
        keys=keys,
        private_keys=private_keys,
    )


def _signed_change(
    occurred_at: datetime | None = None,
) -> tuple[ChangeEvidenceArtifact, KeyMaterial]:
    source, _ = _change_pair(occurred_at=occurred_at)
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
    *,
    collection_id: str | None = None,
    key: KeyMaterial | None = None,
    private_key: rsa.RSAPrivateKey | None = None,
) -> tuple[
    MonitoringEvidenceHandoff,
    KeyMaterial,
    rsa.RSAPrivateKey,
]:
    source, _, _, _ = _trusted_signed_handoff()
    if (key is None) != (private_key is None):
        raise ValueError("monitoring key and private key must be supplied together")
    if key is None or private_key is None:
        key, private_key = _private_key_material("monitoring", "2")
    payload = source.model_dump(
        mode="python",
        by_alias=True,
        exclude={"collector_attestation"},
    )
    if collection_id is not None:
        payload["collectionId"] = collection_id
        payload["evidence"] = {
            **source.evidence.model_dump(mode="python", by_alias=True),
            "name": f"wc024-monitoring/{collection_id}/evidence.json",
        }
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


@lru_cache(maxsize=1)
def _wc028_request_template() -> tuple[
    PreparedMonitoringCollection,
    CorrelationRequest,
]:
    prepared, _committed, request, _commit = _execute_wc028_collection(direct_attribution=True)
    return prepared, request


def _correlation_request_for_context(
    context_binding: PublishedRuntimeContextBinding,
    *,
    trusted_as_of: datetime,
    rule_catalog_digest: str,
    monitoring_key: KeyMaterial,
    monitoring_private_key: rsa.RSAPrivateKey,
    stale_bundle: bool = False,
) -> CorrelationRequest:
    source = _request(
        dependency_paths=context_binding.dependency_paths,
        rule_catalog_digest=rule_catalog_digest,
    )
    real_prepared, real_request = _wc028_request_template()
    intent_reference = real_request.monitoring_bundle.monitoring_intent_reference
    if intent_reference is None:
        raise AssertionError("real WC-028 request must contain monitoring intent evidence")
    control_provenance = next(
        item.control_provenance
        for item in real_request.monitoring_bundle.observations
        if item.control_provenance is not None
    )
    interval_by_state = (
        {
            "healthy": (
                trusted_as_of - timedelta(minutes=14),
                trusted_as_of - timedelta(minutes=13),
            ),
            "unhealthy": (
                trusted_as_of - timedelta(minutes=12),
                trusted_as_of - timedelta(minutes=11),
            ),
        }
        if stale_bundle
        else {
            "healthy": (
                trusted_as_of - timedelta(minutes=8),
                trusted_as_of - timedelta(minutes=6),
            ),
            "unhealthy": (
                trusted_as_of - timedelta(minutes=5),
                trusted_as_of - timedelta(minutes=3),
            ),
        }
    )
    bundle_observed_start = min(item[0] for item in interval_by_state.values())
    bundle_observed_end = max(item[1] for item in interval_by_state.values())
    observations = []
    query_execution_digests: list[str] = []
    for observation in source.monitoring_bundle.observations:
        observed_start, observed_end = interval_by_state[observation.state]
        query_execution_digest = compute_artifact_digest(
            {
                "schemaVersion": "athena.wc028MonitoringQueryExecution.v1",
                "ruleCatalogDigest": rule_catalog_digest,
                "sourceObservationDigest": observation.observation_digest,
                "observedStart": observed_start,
                "observedEnd": observed_end,
            }
        )
        observation_payload = observation.model_dump(
            mode="python",
            by_alias=True,
            exclude={"observation_id", "observation_digest"},
        )
        observation_payload.update(
            {
                "observedStart": observed_start,
                "observedEnd": observed_end,
                "controlProvenance": control_provenance,
                "queryExecutionDigest": query_execution_digest,
            }
        )
        observation_digest = compute_artifact_digest(_json_value(observation_payload))
        observations.append(
            type(observation)(
                **observation_payload,
                observationId=("obs-" + observation_digest.removeprefix("sha256:")[:32]),
                observationDigest=observation_digest,
            )
        )
        query_execution_digests.append(query_execution_digest)
    observations = sorted(observations, key=lambda item: item.observation_id)

    coverage = source.monitoring_bundle.coverage[0]
    coverage_payload = coverage.model_dump(
        mode="python",
        by_alias=True,
        exclude={"coverage_id", "coverage_digest"},
    )
    coverage_payload.update(
        {
            "coverageStart": bundle_observed_start,
            "coverageEnd": bundle_observed_end,
            "controlProvenance": control_provenance,
            "queryExecutionDigests": tuple(sorted(query_execution_digests)),
        }
    )
    coverage_digest = compute_artifact_digest(_json_value(coverage_payload))
    current_coverage = type(coverage)(
        **coverage_payload,
        coverageId=("coverage-" + coverage_digest.removeprefix("sha256:")[:32]),
        coverageDigest=coverage_digest,
    )
    monitoring_bundle = MonitoringEvidenceBundle(
        schemaVersion=MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION,
        workloadId=source.monitoring_bundle.workload_id,
        monitoringContractDigest=source.monitoring_bundle.monitoring_contract_digest,
        monitoringIntentReference=intent_reference,
        collectedAt=trusted_as_of - timedelta(minutes=2),
        observedStart=bundle_observed_start,
        observedEnd=bundle_observed_end,
        observations=tuple(observations),
        coverage=(current_coverage,),
        expectedCoverageScopeDigests=(source.monitoring_bundle.expected_coverage_scope_digests),
    )
    monitoring_bundle_digest = sha256_hex(monitoring_bundle.canonical_bytes())
    collection_id = "wc024-" + monitoring_bundle_digest.removeprefix("sha256:")[:12]
    handoff_payload: dict[str, object] = {
        "schemaVersion": "athena.wc024MonitoringEvidenceHandoff.v1",
        "collectorContractDigest": monitoring_bundle.monitoring_contract_digest,
        "collectionId": collection_id,
        "observedAt": trusted_as_of - timedelta(minutes=1),
        "evidence": VersionPinnedBlobReference(
            name=f"wc024-monitoring/{collection_id}/evidence.json",
            version=source.monitoring_handoff.evidence.version,
            contentDigest=monitoring_bundle_digest,
        ).model_dump(mode="python", by_alias=True),
    }
    handoff_preimage = monitoring_handoff_preimage(handoff_payload)
    handoff_preimage_bytes = canonicalize_json(handoff_preimage).encode("utf-8")
    monitoring_handoff = MonitoringEvidenceHandoff(
        **handoff_payload,
        collectorAttestation={
            "signatureAlgorithm": "RS256",
            "trustAnchorRef": monitoring_key.key_id,
            "signedPreimageDigest": compute_artifact_digest(handoff_preimage),
            "signature": base64.b64encode(
                monitoring_private_key.sign(
                    handoff_preimage_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            ).decode("ascii"),
        },
    )
    previous = next(item for item in observations if item.state == "healthy")
    current = next(item for item in observations if item.state == "unhealthy")
    prepared = PreparedMonitoringCollection(
        intent_id=real_prepared.intent_id,
        intent_digest=real_prepared.intent_digest,
        context_binding_digest=context_binding.binding_digest,
        monitoring_intent_reference=real_prepared.monitoring_intent_reference,
        monitoring_bundle=monitoring_bundle,
        change_artifacts=source.change_artifacts,
        incident_resource_id=source.incident_anchor.affected_resource_id,
        previous_health_observation_id=previous.observation_id,
        current_health_observation_ids=(current.observation_id,),
        current_health_state="unhealthy",
    )
    committed = CommittedMonitoringCollection(
        monitoring_handoff=monitoring_handoff,
        change_handoffs=source.change_handoffs,
    )
    return build_collected_correlation_request(
        prepared,
        committed,
        context_binding=context_binding,
        incident_revision=source.incident_revision,
        issued_at=trusted_as_of - timedelta(minutes=11, seconds=30),
        trusted_as_of=trusted_as_of,
        expires_at=trusted_as_of + timedelta(seconds=20),
    )


def _incident_bound_request_for_state(
    request: CorrelationRequest,
    state: IncidentState,
    state_attestation: IncidentStateAttestation,
    *,
    incident_key: KeyMaterial,
    incident_private_key: rsa.RSAPrivateKey,
    report_key: KeyMaterial,
    report_private_key: rsa.RSAPrivateKey,
) -> IncidentBoundCorrelationRequest:
    state_prefix = (
        f"incidents/{state.incident_id}/versions/{state.result_digest.removeprefix('sha256:')}"
    )
    subject_payload: dict[str, object] = {
        "schemaVersion": "athena.wc027IncidentCorrelationSubject.v1",
        "incidentId": state.incident_id,
        "incidentTransitionId": state.transition_id,
        "incidentRevision": request.incident_revision,
        "affectedResourceId": request.incident_anchor.affected_resource_id,
        "incidentState": state,
        "incidentStateAttestation": state_attestation,
        "incidentStateDigest": state.result_digest,
        "stateReference": VersionPinnedBlobReference(
            name=f"{state_prefix}/state.json",
            version="active-state-version",
            contentDigest=sha256_hex(state.canonical_bytes()),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{state_prefix}/attestation.json",
            version="active-state-attestation-version",
            contentDigest=sha256_hex(state_attestation.canonical_bytes()),
        ),
    }
    subject_preimage = canonicalize_json(_json_value(subject_payload)).encode("utf-8")
    subject_payload["subjectAttestation"] = IncidentCorrelationSubjectAttestation(
        schemaVersion="athena.wc027IncidentCorrelationSubjectAttestation.v1",
        signatureAlgorithm="RS256",
        keyVaultKeyId=incident_key.key_id,
        signedPreimageDigest=sha256_hex(subject_preimage),
        detachedSignature=(
            base64.urlsafe_b64encode(
                incident_private_key.sign(
                    subject_preimage,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            )
            .decode("ascii")
            .rstrip("=")
        ),
    )
    subject_digest = compute_artifact_digest(_json_value(subject_payload))
    subject = IncidentCorrelationSubject(
        **subject_payload,
        subjectId=("incident-subject-" + subject_digest.removeprefix("sha256:")[:32]),
        subjectDigest=subject_digest,
    )
    binding_payload: dict[str, object] = {
        "schemaVersion": "athena.wc027IncidentBoundCorrelationRequest.v1",
        "incidentSubject": subject,
        "correlationRequest": request,
        "correlationTransitionDigest": (request.incident_anchor.transition_digest),
    }
    binding_preimage = canonicalize_json(_json_value(binding_payload)).encode("utf-8")
    binding_payload["bindingAttestation"] = IncidentBoundCorrelationRequestAttestation(
        schemaVersion=("athena.wc027IncidentBoundCorrelationRequestAttestation.v1"),
        signatureAlgorithm="RS256",
        keyVaultKeyId=report_key.key_id,
        signedPreimageDigest=sha256_hex(binding_preimage),
        detachedSignature=(
            base64.urlsafe_b64encode(
                report_private_key.sign(
                    binding_preimage,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            )
            .decode("ascii")
            .rstrip("=")
        ),
    )
    binding_digest = compute_artifact_digest(_json_value(binding_payload))
    return IncidentBoundCorrelationRequest(
        **binding_payload,
        requestId=("incident-bound-request-" + binding_digest.removeprefix("sha256:")[:32]),
        bindingDigest=binding_digest,
    )


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


def _job_versions() -> tuple[acceptance.Wc029JobVersion, ...]:
    return (
        acceptance.Wc029JobVersion(
            jobId="global-acceptance",
            purpose="global-acceptance",
            jobResourceId=_GLOBAL_JOB_RESOURCE_ID,
            subscriptionId=_SUBSCRIPTION_ID,
            resourceGroup=_JOB_RESOURCE_GROUP,
            component="acceptance",
            imageRepoDigest=_IMAGE,
            executionTemplateConfigurationSha256=sha256_hex(
                "global-acceptance:complete-execution-template-and-configuration"
            ),
            expectedAttachedIdentityResourceIds=_JOB_IDENTITY_RESOURCE_IDS,
            captureAnchorResourceId=_JOB_CAPTURE_ANCHOR_RESOURCE_ID,
        ),
        acceptance.Wc029JobVersion(
            jobId="scenario-recovery-verification",
            purpose="scenario-recovery-verification",
            jobResourceId=_SCENARIO_JOB_RESOURCE_ID,
            subscriptionId=_SUBSCRIPTION_ID,
            resourceGroup=_JOB_RESOURCE_GROUP,
            component="acceptance",
            imageRepoDigest=_IMAGE,
            executionTemplateConfigurationSha256=sha256_hex(
                "scenario-recovery:complete-execution-template-and-configuration"
            ),
            expectedAttachedIdentityResourceIds=_JOB_IDENTITY_RESOURCE_IDS,
            captureAnchorResourceId=_JOB_CAPTURE_ANCHOR_RESOURCE_ID,
        ),
    )


def _job_execution(
    *,
    execution_id: str,
    scope: str,
    job_version: acceptance.Wc029JobVersion | None = None,
    scenario_id: str | None = None,
    scenario_execution_id: str | None = None,
    scenario_plan_digest: str | None = None,
    input_digest: str = "sha256:" + ("f" * 64),
    phase: str | None = None,
    started_at: datetime = _NOW,
) -> acceptance.Wc029JobExecutionEvidence:
    if job_version is None:
        purpose = "global-acceptance" if scope == "global" else "scenario-recovery-verification"
        job_version = next(item for item in _job_versions() if item.purpose == purpose)
    payload: dict[str, object] = {
        "schemaVersion": acceptance.JOB_EXECUTION_SCHEMA_VERSION,
        "scope": scope,
        "jobInventoryId": job_version.job_id,
        "purpose": job_version.purpose,
        "scenarioId": scenario_id,
        "scenarioExecutionId": scenario_execution_id,
        "scenarioPlanDigest": scenario_plan_digest,
        "inputDigest": input_digest,
        "phase": phase,
        "executionId": execution_id,
        "jobResourceId": job_version.job_resource_id,
        "subscriptionId": job_version.subscription_id,
        "resourceGroup": job_version.resource_group,
        "sourceCommit": _SOURCE_COMMIT,
        "component": job_version.component,
        "image": job_version.image_repo_digest,
        "executionTemplateConfigurationSha256": (
            job_version.execution_template_configuration_sha256
        ),
        "attachedIdentityResourceIds": (job_version.expected_attached_identity_resource_ids),
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
        "jobInventoryId": execution.job_inventory_id,
        "purpose": execution.purpose,
        "scenarioId": execution.scenario_id,
        "scenarioExecutionId": execution.scenario_execution_id,
        "scenarioPlanDigest": execution.scenario_plan_digest,
        "phase": execution.phase,
        "executionId": execution.execution_id,
        "executionDigest": execution.execution_digest,
        "jobResourceId": execution.job_resource_id,
        "subscriptionId": execution.subscription_id,
        "resourceGroup": execution.resource_group,
        "sourceCommit": execution.source_commit,
        "component": execution.component,
        "image": execution.image,
        "executionTemplateConfigurationSha256": (execution.execution_template_configuration_sha256),
        "attachedIdentityResourceIds": execution.attached_identity_resource_ids,
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


def _job_platform_capture_attestation(
    execution: acceptance.Wc029JobExecutionEvidence,
    readback: acceptance.Wc029JobReadbackEvidence,
    *,
    execution_artifact_sha256: str,
    readback_artifact_sha256: str,
    capture_anchor_resource_id: str,
    key: KeyMaterial,
    private_key: rsa.RSAPrivateKey,
) -> acceptance.Wc029JobPlatformCaptureAttestation:
    capture_record_sha256 = compute_artifact_digest(
        {
            "provider": "Microsoft.App/jobs/executions",
            "executionId": execution.execution_id,
            "jobResourceId": execution.job_resource_id,
            "executionDigest": execution.execution_digest,
            "readbackDigest": readback.readback_digest,
        }
    )
    statement_payload: dict[str, object] = {
        "schemaVersion": acceptance.JOB_PLATFORM_CAPTURE_STATEMENT_SCHEMA_VERSION,
        "scope": "global",
        "jobInventoryId": execution.job_inventory_id,
        "purpose": execution.purpose,
        "executionId": execution.execution_id,
        "jobResourceId": execution.job_resource_id,
        "subscriptionId": execution.subscription_id,
        "resourceGroup": execution.resource_group,
        "component": execution.component,
        "imageRepoDigest": execution.image,
        "executionTemplateConfigurationSha256": (execution.execution_template_configuration_sha256),
        "attachedIdentityResourceIds": execution.attached_identity_resource_ids,
        "startedAt": execution.started_at,
        "completedAt": execution.completed_at,
        "platformExecutionStatus": execution.status,
        "platformExitCode": execution.exit_code,
        "executionDigest": execution.execution_digest,
        "executionArtifactSha256": execution_artifact_sha256,
        "readbackObservedAt": readback.observed_at,
        "platformProvisioningState": readback.provisioning_state,
        "platformReadbackStatus": readback.status,
        "readbackDigest": readback.readback_digest,
        "readbackArtifactSha256": readback_artifact_sha256,
        "captureAnchorResourceId": capture_anchor_resource_id,
        "captureRecordId": (
            "job-platform-capture-" + capture_record_sha256.removeprefix("sha256:")[:32]
        ),
        "captureRecordSha256": capture_record_sha256,
    }
    statement_digest = compute_artifact_digest(_json_value(statement_payload))
    statement = acceptance.Wc029JobPlatformCaptureStatement(
        **statement_payload,
        statementId=(
            "job-platform-capture-statement-" + statement_digest.removeprefix("sha256:")[:32]
        ),
        statementDigest=statement_digest,
    )
    signature = (
        base64.urlsafe_b64encode(
            private_key.sign(
                statement.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    return acceptance.Wc029JobPlatformCaptureAttestation(
        schemaVersion=acceptance.JOB_PLATFORM_CAPTURE_ATTESTATION_SCHEMA_VERSION,
        statement=statement,
        signatureAlgorithm="RS256",
        keyVaultKeyId=key.key_id,
        signedPreimageDigest=sha256_hex(statement.canonical_bytes()),
        detachedSignature=signature,
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
    monitoring_bundle_digest: str,
    correlation_context_binding_digest: str,
    change_request_digest: str | None,
    verification_input_digest: str,
) -> acceptance.Wc029ScenarioPlanEvidence:
    correlation_request_intent_nonce = sha256_hex(
        f"{scenario_execution_id}:correlation-request-intent"
    ).removeprefix("sha256:")[:32]
    correlation_request_intent_digest = compute_artifact_digest(
        {
            "scenarioId": scenario_id,
            "scenarioExecutionId": scenario_execution_id,
            "targetResourceId": capability.target_resource_id.casefold().rstrip("/"),
            "contextBindingDigest": correlation_context_binding_digest,
            "intentNonce": correlation_request_intent_nonce,
        }
    )
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
        "monitoringBundleDigest": monitoring_bundle_digest,
        "correlationContextBindingDigest": (correlation_context_binding_digest),
        "correlationRequestIntentNonce": correlation_request_intent_nonce,
        "correlationRequestIntentDigest": correlation_request_intent_digest,
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


def _incident_occurrence_continuity(
    *,
    scenario_id: str,
    scenario_execution_id: str,
    target_resource_id: str,
    request: CorrelationRequest,
    bound_request: IncidentBoundCorrelationRequest,
    active_state: IncidentState,
    active_state_content_sha256: str,
    active_state_attestation_content_sha256: str,
    active_occurrence_digest: str,
    resolved_state: IncidentState,
    resolved_state_content_sha256: str,
    resolved_state_attestation_content_sha256: str,
    resolved_occurrence_digest: str,
) -> acceptance.Wc029IncidentOccurrenceContinuity:
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc029IncidentOccurrenceContinuity.v1",
        "scenarioId": scenario_id,
        "scenarioExecutionId": scenario_execution_id,
        "incidentId": active_state.incident_id,
        "targetResourceId": target_resource_id,
        "correlationRequestId": request.request_id,
        "correlationRequestDigest": request.request_digest,
        "incidentSubjectId": bound_request.incident_subject.subject_id,
        "incidentSubjectDigest": bound_request.incident_subject.subject_digest,
        "incidentBoundRequestId": bound_request.request_id,
        "incidentBoundRequestDigest": bound_request.binding_digest,
        "targetBinding": active_state.target_binding,
        "workloadRole": active_state.workload_role,
        "detectedAt": active_state.detected_at,
        "activeTransitionId": active_state.transition_id,
        "activeStateResultDigest": active_state.result_digest,
        "activeStateContentSha256": active_state_content_sha256,
        "activeStateAttestationContentSha256": (active_state_attestation_content_sha256),
        "activeOccurrenceDigest": active_occurrence_digest,
        "resolvedTransitionId": resolved_state.transition_id,
        "resolvedStateResultDigest": resolved_state.result_digest,
        "resolvedStateContentSha256": resolved_state_content_sha256,
        "resolvedStateAttestationContentSha256": (resolved_state_attestation_content_sha256),
        "resolvedOccurrenceDigest": resolved_occurrence_digest,
        "resolvedPredecessorStateResultDigest": active_state.result_digest,
    }
    return _digest_bound_model(
        acceptance.Wc029IncidentOccurrenceContinuity,
        payload,
        digest_field="continuityDigest",
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
    active_state: IncidentState,
    resolved_state: IncidentState,
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
        "incidentStateResultDigest": active_state.result_digest,
        "clauseIds": tuple(
            sorted(
                {
                    finding.clause_id
                    for state in (active_state, resolved_state)
                    for finding in state.findings
                }
            )
        ),
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
    if isinstance(value, CorrelationRequest):
        return value.request_digest
    if isinstance(value, CorrelationReport):
        return value.request_digest
    if isinstance(value, PublishedCorrelationReportAttestation):
        return value.statement.correlation_request_digest
    if isinstance(value, acceptance.Wc029CorrelationOnlyReportAttestation):
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
    if isinstance(value, IncidentBoundCorrelationRequest):
        return value.binding_digest
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
    if isinstance(value, ActiveIncidentIndex):
        return sha256_hex(value.canonical_bytes())
    if isinstance(value, ActiveIncidentIndexAttestation):
        return value.index_digest
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
    monitoring_key, monitoring_private = _private_key_material(
        "monitoring",
        "2",
    )
    incident = _trusted_incident_assets(
        publication,
        monitoring_key=monitoring_key,
        monitoring_private_key=monitoring_private,
    )
    scenario_time_order = (
        "web-tier-failure",
        *(item for item in acceptance.REQUIRED_SCENARIO_CLASSES if item != "web-tier-failure"),
    )
    scenario_report_times = {
        scenario_class: incident.report.as_of + timedelta(hours=2 * index)
        for index, scenario_class in enumerate(scenario_time_order)
    }
    change, change_key = _signed_change(
        scenario_report_times["nsg-connectivity-loss"] - timedelta(minutes=2)
    )
    scenario_key, scenario_private = _private_key_material(
        "scenario-authority",
        "3",
    )
    job_capture_key, job_capture_private = _private_key_material(
        "job-capture",
        "4",
    )
    keys = {
        **incident.keys,
        "change": change_key,
        "context-authority": publication.key,
        "job-capture": job_capture_key,
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
            WEB_ID,
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
    deployment_specs = (
        (
            "change-ingestion",
            "wc029-change-ingestion-synthetic",
            "producer",
            "infra/wc025-change-ingestion/main.bicep",
        ),
        (
            "foundation",
            "wc029-live-acceptance-synthetic",
            "live-acceptance",
            "infra/wc013-live-acceptance/main.bicep",
        ),
        (
            "monitoring-connectivity",
            "wc029-monitoring-connectivity-synthetic",
            "foundation",
            "infra/wc024-monitoring-connectivity/main.bicep",
        ),
        (
            "monitoring-foundation",
            "wc029-monitoring-foundation-synthetic",
            "foundation",
            "infra/wc024-monitoring-foundation/main.bicep",
        ),
        (
            "monitoring-prerequisites",
            "wc029-monitoring-prerequisites-synthetic",
            "foundation",
            "infra/wc029-monitoring-prerequisites/main.bicep",
        ),
    )
    deployment_plans: dict[str, acceptance.Wc029DeploymentPlanEvidence] = {}
    deployment_what_ifs: dict[str, dict[str, object]] = {}
    deployments: list[acceptance.Wc029DeploymentVersion] = []
    for deployment_id, deployment_name, stage, template_path in deployment_specs:
        base_parameter_sha256 = sha256_hex(f"{deployment_id}:base-parameters")
        effective_parameter_sha256 = sha256_hex(f"{deployment_id}:effective-parameters")
        parameter_bindings = {
            "deploymentId": deployment_id,
            "location": "australiaeast",
        }
        parameter_bindings_sha256 = sha256_hex(canonicalize_json(parameter_bindings))
        what_if: dict[str, object] = {
            "status": "Succeeded",
            "properties": {"changes": []},
            "deploymentId": deployment_id,
        }
        orchestrator_sha256 = sha256_hex(f"{deployment_id}:orchestrator")
        template_sha256 = sha256_hex(template_path)
        trusted_plan = acceptance.Wc029DeploymentPlanEvidence(
            schemaVersion="athena.wc029DeploymentPlan.v1",
            stage=stage,
            sourceCommit=_SOURCE_COMMIT,
            subscriptionId="00000000-0000-0000-0000-000000000000",
            location="australiaeast",
            deploymentName=deployment_name,
            templatePath=template_path,
            templateSha256=template_sha256,
            orchestratorSha256=orchestrator_sha256,
            preflightSha256=acceptance._preflight_implementation_sha256(),
            baseParameterPath=f"C:/synthetic/{deployment_id}.base.parameters.json",
            baseParameterSha256=base_parameter_sha256,
            effectiveParameterPath=(f"C:/synthetic/{deployment_id}.effective.parameters.json"),
            effectiveParameterSha256=effective_parameter_sha256,
            whatIfPath=f"C:/synthetic/{deployment_id}.what-if.json",
            whatIfSha256=sha256_hex(_canonical_bytes(what_if)),
            allowedChangeResourceIds=(),
        )
        deployment_plans[deployment_id] = trusted_plan
        deployment_what_ifs[deployment_id] = what_if
        deployments.append(
            acceptance.Wc029DeploymentVersion(
                deploymentId=deployment_id,
                deploymentName=deployment_name,
                stage=stage,
                subscriptionId="00000000-0000-0000-0000-000000000000",
                location="australiaeast",
                templatePath=template_path,
                templateSha256=template_sha256,
                baseParameterSha256=base_parameter_sha256,
                effectiveParameterSha256=effective_parameter_sha256,
                parameterBindingsSha256=parameter_bindings_sha256,
                planArtifactId=f"{deployment_id}-plan",
                planArtifactSha256=sha256_hex(_model_bytes(trusted_plan)),
                orchestratorSha256=orchestrator_sha256,
                allowedChangeResourceIds=(),
                upstreamHandoffs=(),
            )
        )
    inventory = acceptance.Wc029VersionInventory(
        schemaVersion=acceptance.VERSION_INVENTORY_SCHEMA_VERSION,
        sourceCommit=_SOURCE_COMMIT,
        deployments=tuple(deployments),
        images=(
            acceptance.Wc029ImageVersion(
                component="acceptance",
                image=_IMAGE,
            ),
        ),
        jobs=_job_versions(),
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
            resolvedProfileDigest=(publication.manifest.resolved_profile_digest),
            dependencyGraphDigest=(publication.manifest.dependency_graph_digest),
            contextBindingPayloadDigest=(publication.manifest.context_binding_payload_digest),
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

    capability_readback_id = ""
    for deployment_index, deployment in enumerate(inventory.deployments):
        deployment_id = deployment.deployment_id
        what_if_id = add(
            f"{deployment_id}-what-if",
            "deployment-what-if",
            deployment_what_ifs[deployment_id],
            global_evidence=True,
            deployment_id=deployment_id,
        )
        plan_id = add(
            f"{deployment_id}-plan",
            "deployment-plan",
            deployment_plans[deployment_id],
            global_evidence=True,
            deployment_id=deployment_id,
        )
        outputs: dict[str, object] = {
            "deploymentRoot": deployment.template_path,
            "ready": True,
        }
        if deployment_id == inventory.capability_deployment_id:
            outputs.update(
                {
                    "acceptanceImage": _IMAGE,
                    "presentationHttpsUrl": "https://athena.synthetic.invalid",
                    "wc029ScenarioCapabilities": capability_payloads,
                    "wc029ScenarioCapabilitiesDigest": compute_artifact_digest(capability_payloads),
                }
            )
        parameter_bindings = {
            "deploymentId": deployment_id,
            "location": deployment.location,
        }
        handoff = acceptance.Wc029DeploymentHandoffEvidence(
            schemaVersion="athena.wc029DeploymentHandoff.v1",
            stage=deployment.stage,
            sourceCommit=_SOURCE_COMMIT,
            subscriptionId=deployment.subscription_id,
            resourceGroup=deployment.resource_group,
            deploymentName=deployment.deployment_name,
            outputs=outputs,
            outputsSha256=sha256_hex(canonicalize_json(outputs)),
            parameterBindings=parameter_bindings,
            parameterBindingsSha256=sha256_hex(canonicalize_json(parameter_bindings)),
            planManifestSha256=artifact_digests[plan_id],
        )
        handoff_id = add(
            f"{deployment_id}-output",
            "deployment-output",
            handoff,
            global_evidence=True,
            deployment_id=deployment_id,
            binds_artifact_id=plan_id,
        )
        readback = acceptance.Wc029DeploymentReadbackEvidence(
            schemaVersion=acceptance.DEPLOYMENT_READBACK_SCHEMA_VERSION,
            stage=deployment.stage,
            sourceCommit=_SOURCE_COMMIT,
            subscriptionId=deployment.subscription_id,
            resourceGroup=deployment.resource_group,
            location=deployment.location,
            deploymentName=deployment.deployment_name,
            templatePath=deployment.template_path,
            templateSha256=deployment.template_sha256,
            baseParameterSha256=deployment.base_parameter_sha256,
            effectiveParameterSha256=deployment.effective_parameter_sha256,
            parameterBindingsSha256=deployment.parameter_bindings_sha256,
            upstreamHandoffs=(),
            observedAt=(_SCENARIO_BASE - timedelta(hours=4) + timedelta(seconds=deployment_index)),
            provisioningState="Succeeded",
            outputHandoffSha256=artifact_digests[handoff_id],
            outputs=outputs,
            outputsSha256=handoff.outputs_sha256,
        )
        readback_id = add(
            f"{deployment_id}-readback",
            "deployment-readback",
            readback,
            global_evidence=True,
            deployment_id=deployment_id,
            binds_artifact_id=handoff_id,
        )
        if deployment_id == inventory.capability_deployment_id:
            capability_readback_id = readback_id
        add(
            (
                "what-if-preflight"
                if deployment_id == "foundation"
                else f"{deployment_id}-what-if-preflight"
            ),
            "preflight-result",
            acceptance.Wc029PreflightResultEvidence(
                schemaVersion=acceptance.PREFLIGHT_RESULT_SCHEMA_VERSION,
                kind="what-if",
                deploymentId=deployment_id,
                inputArtifactId=what_if_id,
                inputSha256=artifact_digests[what_if_id],
                validatorSha256=acceptance._preflight_implementation_sha256(),
                safe=True,
                violations=(),
            ),
            global_evidence=True,
            preflight_kind="what-if",
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
    global_job = next(item for item in inventory.jobs if item.purpose == "global-acceptance")
    global_execution = _job_execution(
        execution_id="foundation-execution",
        scope="global",
        job_version=global_job,
    )
    global_execution_id = add(
        "global-job-execution",
        "job-execution",
        global_execution,
        global_evidence=True,
    )
    global_readback = _job_readback(
        global_execution,
        result_artifacts=[
            (
                capability_readback_id,
                artifact_digests[capability_readback_id],
            ),
        ],
    )
    global_readback_id = add(
        "global-job-readback",
        "job-readback",
        global_readback,
        global_evidence=True,
        binds_artifact_id=global_execution_id,
    )
    add(
        "global-job-platform-attestation",
        "job-platform-attestation",
        _job_platform_capture_attestation(
            global_execution,
            global_readback,
            execution_artifact_sha256=artifact_digests[global_execution_id],
            readback_artifact_sha256=artifact_digests[global_readback_id],
            capture_anchor_resource_id=global_job.capture_anchor_resource_id,
            key=job_capture_key,
            private_key=job_capture_private,
        ),
        global_evidence=True,
        binds_artifact_id=global_readback_id,
    )

    capability_by_class = {item.scenario_class: item for item in capabilities}
    scenario_job = next(
        item for item in inventory.jobs if item.purpose == "scenario-recovery-verification"
    )
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

        if scenario_class == "web-tier-failure":
            scenario_request = incident.correlation_request
            scenario_report = incident.report
            scenario_report_attestation = incident.report_attestation
        else:
            scenario_request = _correlation_request_for_context(
                publication.manifest.context_binding,
                trusted_as_of=scenario_report_times[scenario_class],
                rule_catalog_digest=sha256_hex(f"{scenario_class}:rule-catalog"),
                monitoring_key=monitoring_key,
                monitoring_private_key=monitoring_private,
            )
            scenario_report, _ = _rebind_report_assets(
                incident.report,
                incident.report_attestation,
                correlation_request=scenario_request,
                active_state=incident.active_state,
                active_state_attestation=incident.active_state_attestation,
                authority=publication.authority.authority,
                key=incident.keys["report"],
                private_key=incident.private_keys["report"],
            )
            scenario_report_attestation = _correlation_only_report_attestation(
                scenario_request,
                scenario_report,
                publication.authority.authority,
                key=incident.keys["report"],
                private_key=incident.private_keys["report"],
            )
        monitoring = scenario_request.monitoring_handoff
        planned_at = scenario_report.as_of - timedelta(minutes=12)
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
        add_scenario(
            "correlation-request",
            "correlation-request",
            scenario_request,
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
            monitoring_bundle_digest=sha256_hex(
                scenario_request.monitoring_bundle.canonical_bytes()
            ),
            correlation_context_binding_digest=(scenario_request.context_binding.binding_digest),
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
            scenario_report,
            phase="observe",
        )
        add_scenario(
            "report-attestation",
            (
                "correlation-report-attestation"
                if capability.evidence_mode == "incident-producing"
                else "correlation-only-report-attestation"
            ),
            scenario_report_attestation,
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
        incident_occurrence_continuity: acceptance.Wc029IncidentOccurrenceContinuity | None = None
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
                    observedAt=scenario_report.as_of,
                    detail=("Synthetic scenario has no reviewed incident producer."),
                ),
                phase="observe",
            )
            observe_end = scenario_report.as_of
        else:
            add_scenario(
                "incident-bound-request",
                "incident-bound-request",
                incident.incident_bound_request,
                phase="observe",
            )
            active_state_id = add_scenario(
                "incident-active",
                "incident-state-active",
                incident.active_state,
                phase="observe",
            )
            active_state_attestation_id = add_scenario(
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
                    scenario_report,
                    incident.active_state,
                    incident.resolved_state,
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
            active_source_index_id = add_scenario(
                "source-index-active",
                "source-index-active",
                incident.active_source_index,
                phase="observe",
            )
            add_scenario(
                "source-index-active-attestation",
                "source-index-active-attestation",
                incident.active_source_index_attestation,
                phase="observe",
                binds_artifact_id=active_source_index_id,
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
                scenario_report.as_of,
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
            job_version=scenario_job,
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
            resolved_state_attestation_id = add_scenario(
                "incident-resolved-attestation",
                "incident-state-resolved-attestation",
                incident.resolved_state_attestation,
                phase="verify",
                binds_artifact_id=resolved_state_id,
            )
            incident_occurrence_continuity = _incident_occurrence_continuity(
                scenario_id=scenario_id,
                scenario_execution_id=scenario_execution_id,
                target_resource_id=capability.target_resource_id,
                request=scenario_request,
                bound_request=incident.incident_bound_request,
                active_state=incident.active_state,
                active_state_content_sha256=artifact_digests[active_state_id],
                active_state_attestation_content_sha256=(
                    artifact_digests[active_state_attestation_id]
                ),
                active_occurrence_digest=incident.active_feed.occurrence_digest,
                resolved_state=incident.resolved_state,
                resolved_state_content_sha256=artifact_digests[resolved_state_id],
                resolved_state_attestation_content_sha256=(
                    artifact_digests[resolved_state_attestation_id]
                ),
                resolved_occurrence_digest=incident.resolved_feed.occurrence_digest,
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
            resolved_source_index_id = add_scenario(
                "source-index-resolved",
                "source-index-resolved",
                incident.resolved_source_index,
                phase="verify",
            )
            add_scenario(
                "source-index-resolved-attestation",
                "source-index-resolved-attestation",
                incident.resolved_source_index_attestation,
                phase="verify",
                binds_artifact_id=resolved_source_index_id,
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
            scenario_request.monitoring_bundle.observed_start,
            scenario_request.monitoring_bundle.observed_end,
            scenario_request.monitoring_bundle.collected_at,
            monitoring.observed_at,
            scenario_report.as_of,
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
            "monitoringBundleDigest": scenario_plan.monitoring_bundle_digest,
            "correlationRequestDigest": scenario_request.request_digest,
            "changeRequestDigest": scenario_plan.change_request_digest,
            "verificationInputDigest": (scenario_plan.verification_input_digest),
            "planDigest": scenario_plan.plan_digest,
            "mutationReceiptDigest": mutation.result_digest,
            "recoveryActionResultDigest": recovery.result_digest,
            "incidentOccurrenceContinuity": incident_occurrence_continuity,
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
            "job-capture": job_capture_private,
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


def _refresh_global_job_capture_attestation(
    bundle: BundleFixture,
    *,
    capture_anchor_resource_id: str | None = None,
) -> None:
    execution_id = "global-job-execution"
    readback_id = "global-job-readback"
    attestation_id = "global-job-platform-attestation"
    execution = acceptance.Wc029JobExecutionEvidence.model_validate_json(
        bundle.artifact_paths[execution_id].read_bytes()
    )
    readback = acceptance.Wc029JobReadbackEvidence.model_validate_json(
        bundle.artifact_paths[readback_id].read_bytes()
    )
    inventory = acceptance.Wc029VersionInventory.model_validate_json(
        bundle.artifact_paths["version-inventory"].read_bytes()
    )
    approved_job = next(
        item for item in inventory.jobs if item.job_id == execution.job_inventory_id
    )
    attestation = _job_platform_capture_attestation(
        execution,
        readback,
        execution_artifact_sha256=sha256_hex(bundle.artifact_paths[execution_id].read_bytes()),
        readback_artifact_sha256=sha256_hex(bundle.artifact_paths[readback_id].read_bytes()),
        capture_anchor_resource_id=(
            capture_anchor_resource_id or approved_job.capture_anchor_resource_id
        ),
        key=bundle.keys["job-capture"],
        private_key=bundle.private_keys["job-capture"],
    )
    _write(bundle.artifact_paths[attestation_id], attestation)


def _rewrite_global_job_chain(
    bundle: BundleFixture,
    updates: dict[str, object],
    *,
    capture_anchor_resource_id: str | None = None,
) -> None:
    execution_path = bundle.artifact_paths["global-job-execution"]
    execution = _read_json(execution_path)
    execution.update(updates)
    execution_payload = dict(execution)
    execution_payload.pop("executionDigest")
    execution["executionDigest"] = compute_artifact_digest(execution_payload)
    _write(execution_path, execution)

    readback_path = bundle.artifact_paths["global-job-readback"]
    readback = _read_json(readback_path)
    for field in (
        "jobInventoryId",
        "purpose",
        "executionId",
        "jobResourceId",
        "subscriptionId",
        "resourceGroup",
        "sourceCommit",
        "component",
        "image",
        "executionTemplateConfigurationSha256",
        "attachedIdentityResourceIds",
    ):
        readback[field] = execution[field]
    readback["executionDigest"] = execution["executionDigest"]
    readback_payload = dict(readback)
    readback_payload.pop("readbackDigest")
    readback["readbackDigest"] = compute_artifact_digest(readback_payload)
    _write(readback_path, readback)
    _refresh_global_job_capture_attestation(
        bundle,
        capture_anchor_resource_id=capture_anchor_resource_id,
    )


def _refresh_incident_occurrence_continuity(
    bundle: BundleFixture,
    scenario_class: str = "web-tier-failure",
) -> None:
    prefix = f"scenario-{scenario_class}"
    plan = acceptance.Wc029ScenarioPlanEvidence.model_validate_json(
        bundle.artifact_paths[f"{prefix}-plan"].read_bytes()
    )
    request = CorrelationRequest.model_validate_json(
        bundle.artifact_paths[f"{prefix}-correlation-request"].read_bytes()
    )
    bound_request = IncidentBoundCorrelationRequest.model_validate_json(
        bundle.artifact_paths[f"{prefix}-incident-bound-request"].read_bytes()
    )
    active_state_path = bundle.artifact_paths[f"{prefix}-incident-active"]
    active_attestation_path = bundle.artifact_paths[f"{prefix}-incident-active-attestation"]
    resolved_state_path = bundle.artifact_paths[f"{prefix}-incident-resolved"]
    resolved_attestation_path = bundle.artifact_paths[f"{prefix}-incident-resolved-attestation"]
    active_state = IncidentState.model_validate_json(active_state_path.read_bytes())
    resolved_state = IncidentState.model_validate_json(resolved_state_path.read_bytes())
    active_feed = IncidentEnrichmentFeedPointer.model_validate_json(
        bundle.artifact_paths[f"{prefix}-feed-active"].read_bytes()
    )
    resolved_feed = IncidentEnrichmentFeedPointer.model_validate_json(
        bundle.artifact_paths[f"{prefix}-feed-resolved"].read_bytes()
    )
    continuity = _incident_occurrence_continuity(
        scenario_id=prefix,
        scenario_execution_id=plan.scenario_execution_id,
        target_resource_id=plan.target_resource_id,
        request=request,
        bound_request=bound_request,
        active_state=active_state,
        active_state_content_sha256=sha256_hex(active_state_path.read_bytes()),
        active_state_attestation_content_sha256=sha256_hex(active_attestation_path.read_bytes()),
        active_occurrence_digest=active_feed.occurrence_digest,
        resolved_state=resolved_state,
        resolved_state_content_sha256=sha256_hex(resolved_state_path.read_bytes()),
        resolved_state_attestation_content_sha256=sha256_hex(
            resolved_attestation_path.read_bytes()
        ),
        resolved_occurrence_digest=resolved_feed.occurrence_digest,
    )
    manifest_path = bundle.artifact_paths[f"{prefix}-execution-manifest"]
    manifest = acceptance.Wc029ScenarioExecutionManifest.model_validate_json(
        manifest_path.read_bytes()
    )
    payload = manifest.model_dump(
        mode="python",
        by_alias=True,
        exclude={"manifest_digest"},
    )
    payload["incidentOccurrenceContinuity"] = continuity
    _write(
        manifest_path,
        _digest_bound_model(
            acceptance.Wc029ScenarioExecutionManifest,
            payload,
            digest_field="manifestDigest",
        ),
    )
    _refresh_scenario_execution_binding(bundle, scenario_class)


def _rewrite_signed_incident_continuity(
    bundle: BundleFixture,
    updates: dict[str, object],
) -> None:
    scenario_class = "web-tier-failure"
    manifest_path = bundle.artifact_paths[f"scenario-{scenario_class}-execution-manifest"]
    manifest = acceptance.Wc029ScenarioExecutionManifest.model_validate_json(
        manifest_path.read_bytes()
    )
    assert manifest.incident_occurrence_continuity is not None
    continuity_payload = manifest.incident_occurrence_continuity.model_dump(
        mode="python",
        by_alias=True,
        exclude={"continuity_digest"},
    )
    continuity_payload.update(updates)
    continuity = _digest_bound_model(
        acceptance.Wc029IncidentOccurrenceContinuity,
        continuity_payload,
        digest_field="continuityDigest",
    )
    manifest_payload = manifest.model_dump(
        mode="python",
        by_alias=True,
        exclude={"manifest_digest"},
    )
    manifest_payload["incidentOccurrenceContinuity"] = continuity
    _write(
        manifest_path,
        _digest_bound_model(
            acceptance.Wc029ScenarioExecutionManifest,
            manifest_payload,
            digest_field="manifestDigest",
        ),
    )
    _refresh_scenario_execution_binding(bundle, scenario_class)


def _rewrite_feed_source_digest(
    bundle: BundleFixture,
    *,
    lifecycle: str,
    reference_field: str,
) -> None:
    prefix = "scenario-web-tier-failure"
    pointer_path = bundle.artifact_paths[f"{prefix}-feed-{lifecycle}"]
    pointer_payload = _read_json(pointer_path)
    reference = pointer_payload[reference_field]
    assert isinstance(reference, dict)
    reference["contentDigest"] = "sha256:" + ("e" * 64)
    pointer_payload.pop("pointerId")
    pointer_payload.pop("pointerDigest")
    pointer_digest = compute_artifact_digest(pointer_payload)
    pointer = IncidentEnrichmentFeedPointer(
        **pointer_payload,
        pointerId=("incident-feed-v2-pointer-" + pointer_digest.removeprefix("sha256:")[:32]),
        pointerDigest=pointer_digest,
    )
    _write(pointer_path, pointer)

    attestation_path = bundle.artifact_paths[f"{prefix}-feed-{lifecycle}-attestation"]
    signature = (
        base64.urlsafe_b64encode(
            bundle.private_keys["feed"].sign(
                pointer.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    _write(
        attestation_path,
        IncidentEnrichmentFeedPointerAttestation(
            schemaVersion=("athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"),
            pointerId=pointer.pointer_id,
            pointerDigest=pointer.pointer_digest,
            signatureAlgorithm="RS256",
            keyVaultKeyId=bundle.keys["feed"].key_id,
            signedPreimageDigest=sha256_hex(pointer.canonical_bytes()),
            detachedSignature=signature,
        ),
    )
    _refresh_scenario_execution_binding(bundle, "web-tier-failure")


def _rewrite_resolved_occurrence_digest_as_active(
    bundle: BundleFixture,
) -> None:
    prefix = "scenario-web-tier-failure"
    active_pointer = IncidentEnrichmentFeedPointer.model_validate_json(
        bundle.artifact_paths[f"{prefix}-feed-active"].read_bytes()
    )
    resolved_pointer_path = bundle.artifact_paths[f"{prefix}-feed-resolved"]
    resolved_pointer = IncidentEnrichmentFeedPointer.model_validate_json(
        resolved_pointer_path.read_bytes()
    )
    pointer_payload = resolved_pointer.model_dump(
        mode="python",
        by_alias=True,
        exclude={"pointer_id", "pointer_digest"},
    )
    pointer_payload["occurrenceDigest"] = active_pointer.occurrence_digest
    pointer_digest = compute_artifact_digest(_json_value(pointer_payload))
    resolved_pointer = IncidentEnrichmentFeedPointer(
        **pointer_payload,
        pointerId=("incident-feed-v2-pointer-" + pointer_digest.removeprefix("sha256:")[:32]),
        pointerDigest=pointer_digest,
    )
    resolved_pointer_raw = _write(resolved_pointer_path, resolved_pointer)

    resolved_pointer_attestation_path = bundle.artifact_paths[f"{prefix}-feed-resolved-attestation"]
    resolved_pointer_signature = (
        base64.urlsafe_b64encode(
            bundle.private_keys["feed"].sign(
                resolved_pointer.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    resolved_pointer_attestation = IncidentEnrichmentFeedPointerAttestation(
        schemaVersion=("athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"),
        pointerId=resolved_pointer.pointer_id,
        pointerDigest=resolved_pointer.pointer_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=bundle.keys["feed"].key_id,
        signedPreimageDigest=sha256_hex(resolved_pointer.canonical_bytes()),
        detachedSignature=resolved_pointer_signature,
    )
    resolved_pointer_attestation_raw = _write(
        resolved_pointer_attestation_path,
        resolved_pointer_attestation,
    )

    resolved_index_path = bundle.artifact_paths[f"{prefix}-feed-index-resolved"]
    old_index = IncidentFeedIndexV2.model_validate_json(resolved_index_path.read_bytes())
    old_entry = old_index.recently_resolved[0]
    resolved_entry = old_entry.model_copy(
        update={
            "feed_pointer_reference": old_entry.feed_pointer_reference.model_copy(
                update={"content_digest": sha256_hex(resolved_pointer_raw)}
            ),
            "feed_pointer_attestation_reference": (
                old_entry.feed_pointer_attestation_reference.model_copy(
                    update={"content_digest": sha256_hex(resolved_pointer_attestation_raw)}
                )
            ),
        }
    )
    resolved_index = build_incident_feed_index_v2(
        active=old_index.active,
        recently_resolved=(resolved_entry,),
        resolved_retention_start=old_index.resolved_retention_start,
        resolved_history_truncated=old_index.resolved_history_truncated,
        resolved_history_total_count=old_index.resolved_history_total_count,
        omitted_resolved_count=old_index.omitted_resolved_count,
        source_active_index_digest=old_index.source_active_index_digest,
        key_id=old_index.key_id,
        key_fingerprint=old_index.key_fingerprint,
        published_at=old_index.published_at,
    )
    resolved_index_raw = _write(resolved_index_path, resolved_index)

    resolved_index_attestation_path = bundle.artifact_paths[
        f"{prefix}-feed-index-resolved-attestation"
    ]
    resolved_index_signature = (
        base64.urlsafe_b64encode(
            bundle.private_keys["feed"].sign(
                resolved_index.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    resolved_index_attestation = IncidentFeedIndexAttestationV2(
        schemaVersion="athena.wc027IncidentFeedIndexAttestation.v2",
        indexDigest=sha256_hex(resolved_index.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=bundle.keys["feed"].key_id,
        detachedSignature=resolved_index_signature,
    )
    resolved_index_attestation_raw = _write(
        resolved_index_attestation_path,
        resolved_index_attestation,
    )

    resolved_state = IncidentState.model_validate_json(
        bundle.artifact_paths[f"{prefix}-incident-resolved"].read_bytes()
    )
    resolved_notification = _notification(
        state=resolved_state,
        pointer=resolved_pointer,
        feed_index=resolved_index,
        feed_pointer_reference=resolved_entry.feed_pointer_reference,
        feed_pointer_attestation_reference=(resolved_entry.feed_pointer_attestation_reference),
        guidance_reference=_resolved_guidance_reference(resolved_state),
        key_id=bundle.keys["notification"].key_id,
        private_key=bundle.private_keys["notification"],
    )
    resolved_notification_path = bundle.artifact_paths[f"{prefix}-notification-resolved"]
    resolved_notification_raw = _write(
        resolved_notification_path,
        resolved_notification,
    )

    manifest_path = bundle.artifact_paths[f"{prefix}-execution-manifest"]
    manifest = _read_json(manifest_path)
    continuity = manifest["incidentOccurrenceContinuity"]
    assert isinstance(continuity, dict)
    continuity["resolvedOccurrenceDigest"] = active_pointer.occurrence_digest
    continuity.pop("continuityDigest")
    continuity["continuityDigest"] = compute_artifact_digest(continuity)
    binding_updates = {
        f"{prefix}-feed-resolved": (
            sha256_hex(resolved_pointer_raw),
            resolved_pointer.pointer_digest,
        ),
        f"{prefix}-feed-resolved-attestation": (
            sha256_hex(resolved_pointer_attestation_raw),
            resolved_pointer.pointer_digest,
        ),
        f"{prefix}-feed-index-resolved": (
            sha256_hex(resolved_index_raw),
            sha256_hex(resolved_index.canonical_bytes()),
        ),
        f"{prefix}-feed-index-resolved-attestation": (
            sha256_hex(resolved_index_attestation_raw),
            resolved_index_attestation.index_digest,
        ),
        f"{prefix}-notification-resolved": (
            sha256_hex(resolved_notification_raw),
            resolved_notification.notification.notification_digest,
        ),
    }
    bindings = manifest["artifacts"]
    assert isinstance(bindings, list)
    for binding in bindings:
        assert isinstance(binding, dict)
        update = binding_updates.get(binding["artifactId"])
        if update is not None:
            binding["contentSha256"], binding["inputDigest"] = update
    manifest.pop("manifestDigest")
    manifest["manifestDigest"] = compute_artifact_digest(manifest)
    manifest_raw = _write(manifest_path, manifest)

    manifest_signature = (
        base64.urlsafe_b64encode(
            bundle.private_keys["scenario-authority"].sign(
                manifest_raw,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    _write(
        bundle.artifact_paths[f"{prefix}-execution-attestation"],
        acceptance.Wc029ScenarioExecutionAttestation(
            schemaVersion=(acceptance.SCENARIO_EXECUTION_ATTESTATION_SCHEMA_VERSION),
            scenarioExecutionId=manifest["scenarioExecutionId"],
            manifestDigest=manifest["manifestDigest"],
            signatureAlgorithm="RS256",
            keyVaultKeyId=bundle.keys["scenario-authority"].key_id,
            signedPreimageDigest=sha256_hex(manifest_raw),
            detachedSignature=manifest_signature,
        ),
    )


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


def test_unknown_binding_references_fail_as_bounded_domain_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _build_bundle(tmp_path)
    declaration = _declaration(
        bundle,
        "scenario-disk-capacity-pressure-report-attestation",
    )
    declaration["bindsArtifactId"] = "missing-report-artifact"
    _rewrite_index(bundle)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="acceptance index failed closed validation",
    ):
        _aggregate(bundle)

    assert acceptance.main(_cli_arguments(bundle)) == 2
    error = capsys.readouterr().err
    assert "acceptance index failed closed validation" in error
    assert "KeyError" not in error
    assert "Traceback" not in error


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


def test_global_job_requires_trusted_platform_capture_attestation(
    tmp_path: Path,
) -> None:
    missing = _build_bundle(tmp_path / "missing")
    attestation_id = "global-job-platform-attestation"
    missing.index["globalArtifactIds"].remove(attestation_id)
    missing.index["artifacts"] = [
        item for item in missing.index["artifacts"] if item["artifactId"] != attestation_id
    ]
    missing.artifact_paths[attestation_id].unlink()
    _rewrite_index(missing)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="acceptance index failed closed validation",
    ):
        _aggregate(missing)

    fabricated = _build_bundle(tmp_path / "fabricated")
    execution_path = fabricated.artifact_paths["global-job-execution"]
    execution = _read_json(execution_path)
    execution["executionId"] = "caller-fabricated-succeeded"
    execution_payload = dict(execution)
    execution_payload.pop("executionDigest")
    execution["executionDigest"] = compute_artifact_digest(execution_payload)
    _write(execution_path, execution)
    readback_path = fabricated.artifact_paths["global-job-readback"]
    readback = _read_json(readback_path)
    readback["executionId"] = execution["executionId"]
    readback["executionDigest"] = execution["executionDigest"]
    readback_payload = dict(readback)
    readback_payload.pop("readbackDigest")
    readback["readbackDigest"] = compute_artifact_digest(readback_payload)
    _write(readback_path, readback)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="platform capture attestation",
    ):
        _aggregate(fabricated)


@pytest.mark.parametrize(
    ("updates", "capture_anchor_resource_id"),
    [
        (
            {
                "jobResourceId": (
                    "/subscriptions/00000000-0000-0000-0000-000000000000/"
                    "resourceGroups/rg-athena-wc029-synthetic/providers/"
                    "Microsoft.App/jobs/unrelated-synthetic"
                )
            },
            None,
        ),
        (
            {"executionTemplateConfigurationSha256": ("sha256:" + ("f" * 64))},
            None,
        ),
        (
            {
                "attachedIdentityResourceIds": [
                    (
                        "/subscriptions/00000000-0000-0000-0000-000000000000/"
                        "resourceGroups/rg-athena-wc029-synthetic/providers/"
                        "Microsoft.ManagedIdentity/userAssignedIdentities/"
                        "unrelated-synthetic"
                    )
                ]
            },
            None,
        ),
        (
            {
                "jobResourceId": (
                    "/subscriptions/11111111-1111-1111-1111-111111111111/"
                    "resourceGroups/rg-athena-wc029-synthetic/providers/"
                    "Microsoft.App/jobs/athena-wc029-global-synthetic"
                ),
                "subscriptionId": "11111111-1111-1111-1111-111111111111",
                "attachedIdentityResourceIds": [
                    (
                        "/subscriptions/11111111-1111-1111-1111-111111111111/"
                        "resourceGroups/rg-athena-wc029-synthetic/providers/"
                        "Microsoft.ManagedIdentity/userAssignedIdentities/"
                        "athena-wc029-job-synthetic"
                    )
                ],
            },
            (
                "/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/rg-athena-wc029-synthetic/providers/"
                "Microsoft.Storage/storageAccounts/athenawc029synthetic/"
                "blobServices/default/containers/job-captures"
            ),
        ),
    ],
)
def test_job_evidence_matches_exact_approved_resource_configuration_and_identity(
    tmp_path: Path,
    updates: dict[str, object],
    capture_anchor_resource_id: str | None,
) -> None:
    bundle = _build_bundle(tmp_path)
    _rewrite_global_job_chain(
        bundle,
        updates,
        capture_anchor_resource_id=capture_anchor_resource_id,
    )

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="exact inventoried Job|exact approved Job inventory",
    ):
        _aggregate(bundle)


def test_job_inventory_rejects_non_identity_attached_resources() -> None:
    approved = _job_versions()[0]
    payload = approved.model_dump(
        mode="python",
        by_alias=True,
    )
    payload["expectedAttachedIdentityResourceIds"] = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/"
        "resourceGroups/rg-athena-wc029-synthetic/providers/Microsoft.Storage/"
        "storageAccounts/not-an-identity",
    )

    with pytest.raises(ValueError, match="expected attached Job identities"):
        acceptance.Wc029JobVersion.model_validate(payload)


def test_scenario_job_rejects_unapproved_job_with_resigned_manifest(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    scenario_class = "disk-capacity-pressure"
    execution_path = bundle.artifact_paths[f"scenario-{scenario_class}-verify-execution"]
    execution = _read_json(execution_path)
    execution["jobResourceId"] = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/"
        "resourceGroups/rg-athena-wc029-synthetic/providers/Microsoft.App/"
        "jobs/unrelated-scenario-synthetic"
    )
    execution_payload = dict(execution)
    execution_payload.pop("executionDigest")
    execution["executionDigest"] = compute_artifact_digest(execution_payload)
    _write(execution_path, execution)

    readback_path = bundle.artifact_paths[f"scenario-{scenario_class}-verify-readback"]
    readback = _read_json(readback_path)
    readback["jobResourceId"] = execution["jobResourceId"]
    readback["executionDigest"] = execution["executionDigest"]
    readback_payload = dict(readback)
    readback_payload.pop("readbackDigest")
    readback["readbackDigest"] = compute_artifact_digest(readback_payload)
    _write(readback_path, readback)
    _refresh_scenario_execution_binding(bundle, scenario_class)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="exact approved Job inventory",
    ):
        _aggregate(bundle)


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
    "coordinate",
    [
        "targetBinding",
        "workloadRole",
        "detectedAt",
    ],
)
def test_incident_states_reject_cross_occurrence_coordinate_splicing(
    tmp_path: Path,
    coordinate: str,
) -> None:
    bundle = _build_bundle(tmp_path)
    prefix = "scenario-web-tier-failure"
    active_state = IncidentState.model_validate_json(
        bundle.artifact_paths[f"{prefix}-incident-active"].read_bytes()
    )
    resolved_path = bundle.artifact_paths[f"{prefix}-incident-resolved"]
    resolved_payload = _read_json(resolved_path)
    if coordinate == "targetBinding":
        resolved_payload[coordinate] = "sha256:" + ("f" * 64)
    elif coordinate == "workloadRole":
        resolved_payload[coordinate] = "load-balancer"
    else:
        resolved_payload[coordinate] = (
            (active_state.detected_at + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        )
    resolved_payload.pop("resultDigest")
    resolved_payload["resultDigest"] = sha256_hex(
        canonicalize_json(resolved_payload).encode("utf-8")
    )
    resolved_state = IncidentState.model_validate_json(_canonical_bytes(resolved_payload))
    _write(resolved_path, resolved_state)
    signature = (
        base64.urlsafe_b64encode(
            bundle.private_keys["incident"].sign(
                incident_state_signature_preimage(resolved_state),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    _write(
        bundle.artifact_paths[f"{prefix}-incident-resolved-attestation"],
        IncidentStateAttestation(
            schemaVersion="athena.incidentStateAttestation.v1",
            resultDigest=resolved_state.result_digest,
            signatureAlgorithm="RS256",
            keyVaultKeyId=bundle.keys["incident"].key_id,
            detachedSignature=signature,
        ),
    )
    _refresh_incident_occurrence_continuity(bundle)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="immutable occurrence coordinates",
    ):
        _aggregate(bundle)


@pytest.mark.parametrize(
    "updates",
    [
        {
            "activeStateResultDigest": "sha256:" + ("e" * 64),
            "resolvedPredecessorStateResultDigest": "sha256:" + ("e" * 64),
        },
        {
            "incidentBoundRequestDigest": "sha256:" + ("e" * 64),
        },
        {
            "incidentSubjectDigest": "sha256:" + ("e" * 64),
        },
    ],
)
def test_signed_incident_continuity_rejects_predecessor_and_context_splicing(
    tmp_path: Path,
    updates: dict[str, object],
) -> None:
    bundle = _build_bundle(tmp_path)
    _rewrite_signed_incident_continuity(bundle, updates)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="signed incident occurrence continuity",
    ):
        _aggregate(bundle)


def test_active_and_resolved_occurrence_receipts_must_be_distinct(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    _rewrite_resolved_occurrence_digest_as_active(bundle)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="scenario-web-tier-failure-execution-manifest violates",
    ):
        _aggregate(bundle)


@pytest.mark.parametrize(
    ("lifecycle", "reference_field"),
    [
        ("active", "sourceStateReference"),
        ("active", "sourceStateAttestationReference"),
        ("resolved", "sourceStateReference"),
        ("resolved", "sourceStateAttestationReference"),
    ],
)
def test_feed_source_references_bind_exact_captured_state_and_attestation_bytes(
    tmp_path: Path,
    lifecycle: str,
    reference_field: str,
) -> None:
    bundle = _build_bundle(tmp_path)
    _rewrite_feed_source_digest(
        bundle,
        lifecycle=lifecycle,
        reference_field=reference_field,
    )

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="feed source-state references",
    ):
        _aggregate(bundle)


def test_shared_feed_pointer_validation_and_exact_state_chronology(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    calls: list[str] = []
    real_validator = acceptance.validate_incident_enrichment_feed_pointer_assets

    def tracked_validator(
        entry: IncidentFeedEntryV2,
        pointer: IncidentEnrichmentFeedPointer,
        attestation: IncidentEnrichmentFeedPointerAttestation,
        *,
        trusted_key_id: str,
        signature_verifier: Any,
    ) -> None:
        calls.append(pointer.lifecycle)
        real_validator(
            entry,
            pointer,
            attestation,
            trusted_key_id=trusted_key_id,
            signature_verifier=signature_verifier,
        )

    monkeypatch.setattr(
        acceptance,
        "validate_incident_enrichment_feed_pointer_assets",
        tracked_validator,
    )
    _aggregate(bundle)
    assert calls == ["active", "resolved"]

    prefix = "scenario-web-tier-failure"
    cases = (
        (
            "active",
            IncidentState.model_validate_json(
                bundle.artifact_paths[f"{prefix}-incident-active"].read_bytes()
            ),
            IncidentEnrichmentFeedPointer.model_validate_json(
                bundle.artifact_paths[f"{prefix}-feed-active"].read_bytes()
            ),
            IncidentFeedIndexV2.model_validate_json(
                bundle.artifact_paths[f"{prefix}-feed-index-active"].read_bytes()
            ),
        ),
        (
            "resolved",
            IncidentState.model_validate_json(
                bundle.artifact_paths[f"{prefix}-incident-resolved"].read_bytes()
            ),
            IncidentEnrichmentFeedPointer.model_validate_json(
                bundle.artifact_paths[f"{prefix}-feed-resolved"].read_bytes()
            ),
            IncidentFeedIndexV2.model_validate_json(
                bundle.artifact_paths[f"{prefix}-feed-index-resolved"].read_bytes()
            ),
        ),
    )
    for lifecycle, state, pointer, feed_index in cases:
        entry = feed_index.active[0] if lifecycle == "active" else feed_index.recently_resolved[0]
        acceptance._validate_feed_state_timing(
            state,
            pointer,
            entry,
            feed_index,
            label=lifecycle,
        )
        invalid_cases = (
            (
                pointer.model_copy(
                    update={"state_updated_at": state.updated_at + timedelta(seconds=1)}
                ),
                entry,
                feed_index,
            ),
            (
                pointer,
                entry.model_copy(update={"updated_at": state.updated_at + timedelta(seconds=1)}),
                feed_index,
            ),
            (
                pointer.model_copy(update={"published_at": state.updated_at}),
                entry,
                feed_index,
            ),
            (
                pointer,
                entry,
                feed_index.model_copy(update={"published_at": pointer.published_at}),
            ),
        )
        for invalid_pointer, invalid_entry, invalid_index in invalid_cases:
            with pytest.raises(
                acceptance.Wc029AcceptanceEvidenceError,
                match=f"{lifecycle} feed state",
            ):
                acceptance._validate_feed_state_timing(
                    state,
                    invalid_pointer,
                    invalid_entry,
                    invalid_index,
                    label=lifecycle,
                )


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
    real_scandir = os.scandir

    def failing_scandir(path: os.PathLike[str] | str) -> Any:
        if Path(path) == bundle.root:
            raise PermissionError("synthetic unreadable subtree")
        return real_scandir(path)

    monkeypatch.setattr(acceptance.os, "scandir", failing_scandir)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="unreadable subtree",
    ):
        _aggregate(bundle)


@pytest.mark.parametrize("error_type", [FileNotFoundError, PermissionError])
def test_scan_to_pin_os_errors_close_all_partial_handles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[OSError],
) -> None:
    bundle = _build_bundle(tmp_path)
    real_open_directory = acceptance._open_pinned_directory
    real_open_file = acceptance._open_pinned_file
    directory_pins: list[acceptance._PinnedDirectoryHandle] = []
    file_pins: list[acceptance._PinnedFileHandle] = []

    def tracked_open_directory(
        path: Path,
        expected: acceptance._PathIdentity,
        *,
        parent: acceptance._PinnedDirectoryHandle | None = None,
        name: str | None = None,
    ) -> acceptance._PinnedDirectoryHandle:
        pin = real_open_directory(
            path,
            expected,
            parent=parent,
            name=name,
        )
        directory_pins.append(pin)
        return pin

    def racing_open_file(
        path: Path,
        expected: acceptance._PathIdentity,
        *,
        parent: acceptance._PinnedDirectoryHandle,
        label: str,
    ) -> acceptance._PinnedFileHandle:
        if file_pins:
            raise error_type("synthetic scan-to-pin race")
        pin = real_open_file(
            path,
            expected,
            parent=parent,
            label=label,
        )
        file_pins.append(pin)
        return pin

    monkeypatch.setattr(
        acceptance,
        "_open_pinned_directory",
        tracked_open_directory,
    )
    monkeypatch.setattr(acceptance, "_open_pinned_file", racing_open_file)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="pinned filesystem operation",
    ):
        _aggregate(bundle)

    assert file_pins
    assert all(pin.descriptor == -1 for pin in file_pins)
    assert directory_pins
    assert all(pin.descriptor is None and pin.windows_handle is None for pin in directory_pins)


def test_identity_permission_error_closes_partial_file_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    real_close = acceptance.os.close
    closed_descriptors: list[int] = []

    def tracked_close(descriptor: int) -> None:
        closed_descriptors.append(descriptor)
        real_close(descriptor)

    def fail_identity(_descriptor: int) -> acceptance._PathIdentity:
        raise PermissionError("synthetic inaccessible identity")

    monkeypatch.setattr(acceptance.os, "close", tracked_close)
    monkeypatch.setattr(acceptance, "_pinned_file_identity", fail_identity)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="opened and pinned safely",
    ):
        _aggregate(bundle)

    assert closed_descriptors


def test_cli_stat_file_not_found_is_bounded_exit_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _build_bundle(tmp_path)
    real_lstat = Path.lstat

    def missing_root(path: Path) -> os.stat_result:
        if path == bundle.root:
            raise FileNotFoundError("synthetic root rename")
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", missing_root)
    result = acceptance.main(_cli_arguments(bundle))

    assert result == 2
    assert json.loads(capsys.readouterr().err)["complete"] is False
    assert list(bundle.output.iterdir()) == []


def test_output_pin_failure_closes_already_acquired_root_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    record = _aggregate(bundle)
    stable_root = acceptance._stable_directory_path(
        bundle.root,
        label="evidence root",
    )
    stable_output = acceptance._stable_directory_path(
        bundle.output,
        label="output directory",
    )
    real_open_directory = acceptance._open_pinned_directory
    opened: list[acceptance._PinnedDirectoryHandle] = []

    def stable_path(
        path: Path,
        *,
        label: str,
    ) -> tuple[Path, acceptance._PathIdentity]:
        del label
        return stable_root if Path(path) == bundle.root else stable_output

    def fail_output_pin(
        path: Path,
        expected: acceptance._PathIdentity,
        *,
        parent: acceptance._PinnedDirectoryHandle | None = None,
        name: str | None = None,
    ) -> acceptance._PinnedDirectoryHandle:
        if opened:
            raise PermissionError("synthetic output pin failure")
        pin = real_open_directory(
            path,
            expected,
            parent=parent,
            name=name,
        )
        opened.append(pin)
        return pin

    monkeypatch.setattr(acceptance, "_stable_directory_path", stable_path)
    monkeypatch.setattr(
        acceptance,
        "_open_pinned_directory",
        fail_output_pin,
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="filesystem operation failed closed",
    ):
        acceptance.write_acceptance_record(
            record,
            output_directory=bundle.output,
            evidence_root=bundle.root,
        )

    assert len(opened) == 1
    assert opened[0].descriptor is None
    assert opened[0].windows_handle is None
    assert list(bundle.output.iterdir()) == []


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

    def fail_link(*_args: object, **_kwargs: object) -> None:
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


def test_publication_links_the_held_staging_inode_across_path_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    record = _aggregate(bundle)
    real_link = acceptance._link_pinned_staging_file
    race_attempted = False
    replacement_blocked = False

    def replace_path_before_link(
        staging_pin: acceptance._PinnedFileHandle,
        *,
        staging_name: str,
        filename: str,
        output_root: Path,
        output_pin: acceptance._PinnedDirectoryHandle,
    ) -> None:
        nonlocal race_attempted, replacement_blocked
        race_attempted = True
        staging_path = output_root / staging_name
        try:
            staging_path.unlink()
            staging_path.write_bytes(b'{"attackerControlled":true}\n')
        except OSError:
            replacement_blocked = True
        real_link(
            staging_pin,
            staging_name=staging_name,
            filename=filename,
            output_root=output_root,
            output_pin=output_pin,
        )

    monkeypatch.setattr(
        acceptance,
        "_link_pinned_staging_file",
        replace_path_before_link,
    )
    if os.name == "nt":
        output = acceptance.write_acceptance_record(
            record,
            output_directory=bundle.output,
            evidence_root=bundle.root,
        )
        assert replacement_blocked
        assert output.read_bytes() == record.canonical_bytes()
    else:
        with pytest.raises(
            acceptance.Wc029AcceptanceEvidenceError,
            match="platform cannot publish|held staging descriptor could not be linked",
        ):
            acceptance.write_acceptance_record(
                record,
                output_directory=bundle.output,
                evidence_root=bundle.root,
            )
        assert not replacement_blocked
        assert list(bundle.output.iterdir()) == []
    assert race_attempted


def test_failed_final_inode_verification_removes_poisoned_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    record = _aggregate(bundle)
    real_identity = acceptance._stable_regular_file_identity

    def mismatched_final_identity(
        path: Path,
        *,
        label: str,
        required_link_count: int,
    ) -> acceptance._PathIdentity:
        identity = real_identity(
            path,
            label=label,
            required_link_count=required_link_count,
        )
        if label == "published acceptance record":
            return replace(identity, inode=identity.inode + 1)
        return identity

    monkeypatch.setattr(
        acceptance,
        "_stable_regular_file_identity",
        mismatched_final_identity,
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="not the held verified staging inode",
    ):
        acceptance.write_acceptance_record(
            record,
            output_directory=bundle.output,
            evidence_root=bundle.root,
        )

    assert list(bundle.output.iterdir()) == []


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


@pytest.mark.parametrize(
    "index_value",
    [
        "../acceptance-index.json",
        "/absolute-index.json",
        "C:/absolute-index.json",
        "nested\\acceptance-index.json",
        "índice.json",
        "\udcff.json",
    ],
)
def test_index_argument_validation_is_bounded_exit_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    index_value: str,
) -> None:
    bundle = _build_bundle(tmp_path)
    arguments = [*_cli_arguments(bundle), "--index", index_value]

    result = acceptance.main(arguments)

    assert result == 2
    error = json.loads(capsys.readouterr().err)
    assert error == {
        "complete": False,
        "error": ("acceptance index path is not a bounded portable relative JSON file"),
    }
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


@pytest.mark.parametrize(
    ("collection", "field"),
    (
        ("deployments", "baseParameterSha256"),
        ("deployments", "effectiveParameterSha256"),
        ("deployments", "orchestratorSha256"),
        ("scenarioCapabilities", "mutationActionDigest"),
        ("scenarioCapabilities", "recoveryActionDigest"),
    ),
)
def test_external_trust_pins_reject_zero_digests(
    tmp_path: Path,
    collection: str,
    field: str,
) -> None:
    bundle = _build_bundle(tmp_path / f"{collection}-{field}")
    inventory_path = bundle.artifact_paths["version-inventory"]
    inventory = _read_json(inventory_path)
    inventory[collection][0][field] = "sha256:" + ("0" * 64)
    _write(inventory_path, inventory)
    bundle = replace(
        bundle,
        approved_inventory_sha256=sha256_hex(inventory_path.read_bytes()),
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="externally forbidden zero digest",
    ):
        _aggregate(bundle)


def test_scenario_action_trust_pins_reject_zero_digest(
    tmp_path: Path,
) -> None:
    scenario = _build_bundle(tmp_path)
    plan_path = scenario.artifact_paths["scenario-disk-capacity-pressure-plan"]
    plan = _read_json(plan_path)
    plan["mutationActionDigest"] = "sha256:" + ("0" * 64)
    _write(plan_path, plan)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="externally forbidden zero digest",
    ):
        _aggregate(scenario)


def test_nested_external_context_pins_reject_zero_digest(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    manifest_path = bundle.artifact_paths["published-manifest"]
    manifest = _read_json(manifest_path)
    manifest["contextBinding"]["requiredCoverageScopeDigests"][0] = "sha256:" + ("0" * 64)
    _write(manifest_path, manifest)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="externally forbidden zero digest",
    ):
        _aggregate(bundle)


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


def test_rbac_bundle_cannot_allow_its_own_broad_assignment(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    broad_scope = "/subscriptions/00000000-0000-0000-0000-000000000000"
    rbac_path = bundle.artifact_paths["effective-rbac"]
    assignments = json.loads(rbac_path.read_text(encoding="utf-8"))
    assert isinstance(assignments, list)
    assignments.append(
        {
            "principalId": _PRINCIPAL_ID,
            "roleDefinitionName": "Owner",
            "scope": broad_scope,
        }
    )
    _write(rbac_path, assignments)

    policy_path = bundle.artifact_paths["rbac-policy"]
    policy = _read_json(policy_path)
    policy["allowedBroadAssignments"] = [
        {
            "principalId": _PRINCIPAL_ID,
            "roleDefinitionName": "Owner",
            "scope": broad_scope,
        }
    ]
    _write(policy_path, policy)

    receipt_path = bundle.artifact_paths["rbac-preflight"]
    receipt = _read_json(receipt_path)
    receipt["inputSha256"] = sha256_hex(rbac_path.read_bytes())
    receipt["policySha256"] = sha256_hex(policy_path.read_bytes())
    _write(receipt_path, receipt)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="broad-assignment allowances must be empty",
    ):
        _aggregate(bundle)


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
        match="stale, replayed, or not bound",
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
    request = CorrelationRequest.model_validate_json(
        unrelated.artifact_paths[f"scenario-{scenario_class}-correlation-request"].read_bytes()
    )
    authority = acceptance.Wc029PublicationAuthorityEvidence.model_validate_json(
        unrelated.artifact_paths["publication-authority"].read_bytes()
    ).authority
    changed_attestation = _correlation_only_report_attestation(
        request,
        changed_report,
        authority,
        key=unrelated.keys["report"],
        private_key=unrelated.private_keys["report"],
    )
    _write(
        unrelated.artifact_paths[report_attestation_id],
        changed_attestation,
    )
    _refresh_scenario_execution_binding(unrelated, scenario_class)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="does not bind the exact captured request",
    ):
        _aggregate(unrelated)


def test_report_and_attestation_require_the_accepted_context_binding(
    tmp_path: Path,
) -> None:
    context_mismatch = _build_bundle(tmp_path / "context")
    scenario_class = "disk-capacity-pressure"
    report_id = f"scenario-{scenario_class}-report"
    attestation_id = f"scenario-{scenario_class}-report-attestation"
    report = CorrelationReport.model_validate_json(
        context_mismatch.artifact_paths[report_id].read_bytes()
    )
    request = CorrelationRequest.model_validate_json(
        context_mismatch.artifact_paths[
            f"scenario-{scenario_class}-correlation-request"
        ].read_bytes()
    )
    attestation = acceptance.Wc029CorrelationOnlyReportAttestation.model_validate_json(
        context_mismatch.artifact_paths[attestation_id].read_bytes()
    )
    authority = acceptance.Wc029PublicationAuthorityEvidence.model_validate_json(
        context_mismatch.artifact_paths["publication-authority"].read_bytes()
    ).authority
    report_payload = report.model_dump(
        mode="python",
        by_alias=True,
        exclude={"report_id", "report_digest"},
    )
    report_payload["contextBindingDigest"] = "sha256:" + ("f" * 64)
    report_digest = compute_artifact_digest(_json_value(report_payload))
    changed_report = CorrelationReport(
        **report_payload,
        reportId=("report-" + report_digest.removeprefix("sha256:")[:32]),
        reportDigest=report_digest,
    )
    changed_attestation = _correlation_only_report_attestation(
        request,
        changed_report,
        authority,
        key=context_mismatch.keys["report"],
        private_key=context_mismatch.private_keys["report"],
    )
    _write(context_mismatch.artifact_paths[report_id], changed_report)
    _write(
        context_mismatch.artifact_paths[attestation_id],
        changed_attestation,
    )
    _refresh_scenario_execution_binding(context_mismatch, scenario_class)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="does not bind the exact captured request",
    ):
        _aggregate(context_mismatch)

    published_manifest = acceptance.Wc029PublishedManifestEvidence.model_validate_json(
        context_mismatch.artifact_paths["published-manifest"].read_bytes()
    )
    plan = acceptance.Wc029ScenarioPlanEvidence.model_validate_json(
        context_mismatch.artifact_paths["scenario-disk-capacity-pressure-plan"].read_bytes()
    )
    inventory = acceptance.Wc029VersionInventory.model_validate_json(
        context_mismatch.artifact_paths["version-inventory"].read_bytes()
    )
    capability = next(
        item for item in inventory.scenario_capabilities if item.scenario_class == scenario_class
    )
    execution_manifest = acceptance.Wc029ScenarioExecutionManifest.model_validate_json(
        context_mismatch.artifact_paths[
            "scenario-disk-capacity-pressure-execution-manifest"
        ].read_bytes()
    )
    active_state = IncidentState.model_validate_json(
        context_mismatch.artifact_paths["scenario-web-tier-failure-incident-active"].read_bytes()
    )
    active_state_attestation = IncidentStateAttestation.model_validate_json(
        context_mismatch.artifact_paths[
            "scenario-web-tier-failure-incident-active-attestation"
        ].read_bytes()
    )
    wrong_context = _request(
        dependency_paths=published_manifest.context_binding.dependency_paths
    ).context_binding
    assert isinstance(wrong_context, PublishedRuntimeContextBinding)
    wrong_request = _correlation_request_for_context(
        wrong_context,
        trusted_as_of=request.trusted_as_of,
        rule_catalog_digest=request.rule_catalog_digest,
        monitoring_key=context_mismatch.keys["monitoring"],
        monitoring_private_key=context_mismatch.private_keys["monitoring"],
    )
    incident_attestation = PublishedCorrelationReportAttestation.model_validate_json(
        context_mismatch.artifact_paths["scenario-web-tier-failure-report-attestation"].read_bytes()
    )
    wrong_report, _ = _rebind_report_assets(
        report,
        incident_attestation,
        correlation_request=wrong_request,
        active_state=active_state,
        active_state_attestation=active_state_attestation,
        authority=authority,
        key=context_mismatch.keys["report"],
        private_key=context_mismatch.private_keys["report"],
    )
    wrong_correlation_only_attestation = _correlation_only_report_attestation(
        wrong_request,
        wrong_report,
        authority,
        key=context_mismatch.keys["report"],
        private_key=context_mismatch.private_keys["report"],
    )
    wrong_plan_payload = plan.model_dump(
        mode="python",
        by_alias=True,
        exclude={"plan_digest"},
    )
    wrong_plan_payload["correlationContextBindingDigest"] = (
        wrong_request.context_binding.binding_digest
    )
    wrong_plan_payload["correlationRequestIntentDigest"] = compute_artifact_digest(
        {
            "scenarioId": plan.scenario_id,
            "scenarioExecutionId": plan.scenario_execution_id,
            "targetResourceId": plan.target_resource_id.casefold().rstrip("/"),
            "contextBindingDigest": (wrong_request.context_binding.binding_digest),
            "intentNonce": plan.correlation_request_intent_nonce,
        }
    )
    wrong_plan = _digest_bound_model(
        acceptance.Wc029ScenarioPlanEvidence,
        wrong_plan_payload,
        digest_field="planDigest",
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="captured correlation request context",
    ):
        acceptance._validate_correlation_request_context(
            wrong_request,
            wrong_report,
            wrong_correlation_only_attestation,
            wrong_request.monitoring_handoff,
            published_manifest,
            authority,
            wrong_plan,
            capability,
            execution_manifest,
        )

    smuggled = _build_bundle(tmp_path / "smuggled")
    smuggled_path = smuggled.artifact_paths[attestation_id]
    smuggled_attestation = _read_json(smuggled_path)
    smuggled_attestation["statement"]["incidentId"] = "inc-000000000000"
    _write(smuggled_path, smuggled_attestation)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="report-attestation.*violates",
    ):
        _aggregate(smuggled)

    incident_mismatch = _build_bundle(tmp_path / "incident")
    scenario_class = "web-tier-failure"
    attestation_id = f"scenario-{scenario_class}-report-attestation"
    attestation = PublishedCorrelationReportAttestation.model_validate_json(
        incident_mismatch.artifact_paths[attestation_id].read_bytes()
    )
    statement_payload = attestation.statement.model_dump(
        mode="python",
        by_alias=True,
        exclude={"statement_id", "statement_digest"},
    )
    statement_payload["incidentRevision"] += 1
    statement_digest = compute_artifact_digest(_json_value(statement_payload))
    statement = PublishedCorrelationReportStatement(
        **statement_payload,
        statementId=("report-publication-" + statement_digest.removeprefix("sha256:")[:32]),
        statementDigest=statement_digest,
    )
    changed_attestation = PublishedCorrelationReportAttestation(
        schemaVersion="athena.wc027PublishedCorrelationReportAttestation.v1",
        statement=statement,
        signatureAlgorithm="RS256",
        keyVaultKeyId=incident_mismatch.keys["report"].key_id,
        signedPreimageDigest=sha256_hex(statement.canonical_bytes()),
        detachedSignature=(
            base64.urlsafe_b64encode(
                incident_mismatch.private_keys["report"].sign(
                    statement.canonical_bytes(),
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            )
            .decode("ascii")
            .rstrip("=")
        ),
    )
    _write(
        incident_mismatch.artifact_paths[attestation_id],
        changed_attestation,
    )
    _refresh_scenario_execution_binding(incident_mismatch, scenario_class)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="statement does not match exact captured provenance",
    ):
        _aggregate(incident_mismatch)


def test_acceptance_uses_exact_current_wc028_correlation_contract() -> None:
    _prepared, _committed, real_request, _commit = _execute_wc028_collection(
        direct_attribution=True
    )
    publication, _private_key = _publication_assets()
    incident = _trusted_incident_assets(
        publication,
        correlation_request=real_request,
    )

    assert real_request.schema_version == CORRELATION_REQUEST_SCHEMA_VERSION
    assert (
        acceptance._EXPECTED_SCHEMA_BY_CLASS["correlation-request"]
        == CORRELATION_REQUEST_SCHEMA_VERSION
    )
    assert acceptance._require_current_correlation_request(
        real_request
    ) == CorrelationRequest.model_validate_json(real_request.canonical_bytes())
    assert acceptance._require_current_incident_bound_request(
        incident.incident_bound_request
    ) == IncidentBoundCorrelationRequest.model_validate_json(
        incident.incident_bound_request.canonical_bytes()
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="exact production schema",
    ):
        acceptance._require_current_correlation_request(_request())


def test_monitoring_bundle_freshness_rejects_fresh_wrapper_around_stale_bytes(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    scenario_class = "disk-capacity-pressure"
    prefix = f"scenario-{scenario_class}"
    request = CorrelationRequest.model_validate_json(
        bundle.artifact_paths[f"{prefix}-correlation-request"].read_bytes()
    )
    mutation = acceptance.Wc029MutationReceipt.model_validate_json(
        bundle.artifact_paths[f"{prefix}-mutation"].read_bytes()
    )
    manifest = acceptance.Wc029ScenarioExecutionManifest.model_validate_json(
        bundle.artifact_paths[f"{prefix}-execution-manifest"].read_bytes()
    )
    stale_request = _correlation_request_for_context(
        request.context_binding,
        trusted_as_of=request.trusted_as_of,
        rule_catalog_digest=request.rule_catalog_digest,
        monitoring_key=bundle.keys["monitoring"],
        monitoring_private_key=bundle.private_keys["monitoring"],
        stale_bundle=True,
    )

    assert stale_request.monitoring_bundle.observed_end < mutation.applied_at
    assert stale_request.monitoring_handoff.observed_at > mutation.applied_at
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="stale, replayed, or not bound",
    ):
        acceptance._validate_monitoring_freshness(
            stale_request,
            stale_request.monitoring_handoff,
            mutation,
            manifest,
        )


def test_monitoring_bundle_and_collector_times_are_inside_signed_observe_phase(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    scenario_class = "disk-capacity-pressure"
    prefix = f"scenario-{scenario_class}"
    request = CorrelationRequest.model_validate_json(
        bundle.artifact_paths[f"{prefix}-correlation-request"].read_bytes()
    )
    mutation = acceptance.Wc029MutationReceipt.model_validate_json(
        bundle.artifact_paths[f"{prefix}-mutation"].read_bytes()
    )
    manifest = acceptance.Wc029ScenarioExecutionManifest.model_validate_json(
        bundle.artifact_paths[f"{prefix}-execution-manifest"].read_bytes()
    )
    collected_at = request.monitoring_bundle.collected_at
    assert collected_at is not None
    observe_index = 2
    cases = (
        (
            "monitoring bundle observed start",
            {"started_at": request.monitoring_bundle.observed_start + timedelta(seconds=1)},
        ),
        (
            "monitoring bundle observed end",
            {"completed_at": request.monitoring_bundle.observed_end - timedelta(seconds=1)},
        ),
        (
            "monitoring bundle collection",
            {"completed_at": collected_at - timedelta(seconds=1)},
        ),
        (
            "monitoring collector handoff",
            {"completed_at": request.monitoring_handoff.observed_at - timedelta(seconds=1)},
        ),
    )
    for label, update in cases:
        windows = list(manifest.phase_windows)
        windows[observe_index] = windows[observe_index].model_copy(update=update)
        out_of_phase = manifest.model_copy(update={"phase_windows": tuple(windows)})
        with pytest.raises(
            acceptance.Wc029AcceptanceEvidenceError,
            match=label,
        ):
            acceptance._validate_monitoring_freshness(
                request,
                request.monitoring_handoff,
                mutation,
                out_of_phase,
            )


def test_correlation_request_target_intent_and_phase_timing_are_bound(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path / "binding")
    scenario_class = "disk-capacity-pressure"
    request = CorrelationRequest.model_validate_json(
        bundle.artifact_paths[f"scenario-{scenario_class}-correlation-request"].read_bytes()
    )
    plan = acceptance.Wc029ScenarioPlanEvidence.model_validate_json(
        bundle.artifact_paths[f"scenario-{scenario_class}-plan"].read_bytes()
    )
    inventory = acceptance.Wc029VersionInventory.model_validate_json(
        bundle.artifact_paths["version-inventory"].read_bytes()
    )
    capability = next(
        item for item in inventory.scenario_capabilities if item.scenario_class == scenario_class
    )
    execution_manifest = acceptance.Wc029ScenarioExecutionManifest.model_validate_json(
        bundle.artifact_paths[f"scenario-{scenario_class}-execution-manifest"].read_bytes()
    )
    other_target = _TARGETS[scenario_class]
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="precommitted scenario target",
    ):
        acceptance._validate_correlation_request_plan_binding(
            request,
            plan.model_copy(update={"target_resource_id": other_target}),
            capability.model_copy(update={"target_resource_id": other_target}),
            execution_manifest,
        )

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="precommitted scenario target",
    ):
        acceptance._validate_correlation_request_plan_binding(
            request.model_copy(update={"issued_at": plan.planned_at - timedelta(seconds=1)}),
            plan,
            capability,
            execution_manifest,
        )

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="precommitted scenario target",
    ):
        acceptance._validate_correlation_request_plan_binding(
            request.model_copy(update={"issued_at": plan.planned_at}),
            plan,
            capability,
            execution_manifest,
        )

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="outside the signed observe phase window",
    ):
        acceptance._validate_correlation_request_plan_binding(
            request.model_copy(
                update={"expires_at": (execution_manifest.phase_windows[3].started_at)}
            ),
            plan,
            capability,
            execution_manifest,
        )

    intent = _build_bundle(tmp_path / "intent")
    plan_path = intent.artifact_paths[f"scenario-{scenario_class}-plan"]
    plan_document = _read_json(plan_path)
    plan_document["correlationRequestIntentNonce"] = "f" * 32
    _write(plan_path, plan_document)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="scenario-disk-capacity-pressure-plan.*violates",
    ):
        _aggregate(intent)


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
    _refresh_global_job_capture_attestation(deployment)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="global deployment, baseline, scenario, and final chronology",
    ):
        _aggregate(deployment)

    every_readback = _build_bundle(tmp_path / "every-readback")
    readback_path = every_readback.artifact_paths["monitoring-foundation-readback"]
    readback = _read_json(readback_path)
    baseline_queue = _read_json(every_readback.artifact_paths["queue-baseline"])
    readback["observedAt"] = baseline_queue["capturedAt"]
    _write(readback_path, readback)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="global deployment, baseline, scenario, and final chronology",
    ):
        _aggregate(every_readback)

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


def test_inventory_requires_every_authoritative_deployment_root(
    tmp_path: Path,
) -> None:
    missing = _build_bundle(tmp_path / "missing")
    inventory_path = missing.artifact_paths["version-inventory"]
    inventory = _read_json(inventory_path)
    inventory["deployments"].pop()
    _write(inventory_path, inventory)
    missing = replace(
        missing,
        approved_inventory_sha256=sha256_hex(inventory_path.read_bytes()),
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="version-inventory.*violates",
    ):
        _aggregate(missing)

    substituted = _build_bundle(tmp_path / "substituted")
    inventory_path = substituted.artifact_paths["version-inventory"]
    inventory = _read_json(inventory_path)
    inventory["deployments"][0]["templatePath"] = "infra/unreviewed/main.bicep"
    _write(inventory_path, inventory)
    substituted = replace(
        substituted,
        approved_inventory_sha256=sha256_hex(inventory_path.read_bytes()),
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="version-inventory.*violates",
    ):
        _aggregate(substituted)


@pytest.mark.parametrize(
    ("field", "unreviewed_value"),
    (
        (
            "allowedChangeResourceIds",
            [
                (
                    "/subscriptions/00000000-0000-0000-0000-000000000000/"
                    "resourceGroups/rg-unreviewed/providers/Microsoft.Compute/"
                    "virtualMachines/unreviewed"
                )
            ],
        ),
        ("orchestratorSha256", "sha256:" + ("f" * 64)),
    ),
)
def test_unreviewed_plan_cannot_reach_what_if_evaluation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    unreviewed_value: object,
) -> None:
    bundle = _build_bundle(tmp_path)
    plan_path = bundle.artifact_paths["foundation-plan"]
    plan = _read_json(plan_path)
    plan[field] = unreviewed_value
    _write(plan_path, plan)
    evaluator_called = False

    def unexpected_evaluator(
        _document: object,
        *,
        allowed_change_ids: frozenset[str],
    ) -> tuple[object, ...]:
        nonlocal evaluator_called
        evaluator_called = True
        return ()

    monkeypatch.setattr(acceptance, "evaluate_what_if", unexpected_evaluator)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="deployment plan foundation does not match inventory",
    ):
        _aggregate(bundle)

    assert not evaluator_called


def test_trusted_inventory_requires_exact_plan_pin_before_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    inventory_path = bundle.artifact_paths["version-inventory"]
    inventory = _read_json(inventory_path)
    inventory["deployments"][0].pop("planArtifactSha256")
    _write(inventory_path, inventory)
    bundle = replace(
        bundle,
        approved_inventory_sha256=sha256_hex(inventory_path.read_bytes()),
    )
    evaluator_called = False

    def unexpected_evaluator(
        _document: object,
        *,
        allowed_change_ids: frozenset[str],
    ) -> tuple[object, ...]:
        nonlocal evaluator_called
        evaluator_called = True
        return ()

    monkeypatch.setattr(acceptance, "evaluate_what_if", unexpected_evaluator)

    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="version-inventory.*violates",
    ):
        _aggregate(bundle)

    assert not evaluator_called


def test_published_manifest_requires_canonical_profile_and_derived_digests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_resolver = acceptance.resolve_manifest_profile
    complete_graph_calls = 0

    def complete_graph_resolver(
        manifest_document: object,
        profile_id: str,
        *,
        as_of: datetime,
        _validate_complete_graph: bool = True,
    ) -> object:
        nonlocal complete_graph_calls
        complete_graph_calls += 1
        assert _validate_complete_graph
        return real_resolver(
            manifest_document,
            profile_id,
            as_of=as_of,
            _validate_complete_graph=_validate_complete_graph,
        )

    monkeypatch.setattr(
        acceptance,
        "resolve_manifest_profile",
        complete_graph_resolver,
    )
    _aggregate(_build_bundle(tmp_path / "complete-graph"))
    assert complete_graph_calls > 0

    non_semver = _build_bundle(tmp_path / "non-semver")
    manifest_path = non_semver.artifact_paths["published-manifest"]
    manifest = _read_json(manifest_path)
    manifest["manifestVersion"] = "2026.09.14.1"
    manifest["manifestDocument"]["manifestVersion"] = "2026.09.14.1"
    _write(manifest_path, manifest)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="published-manifest.*violates",
    ):
        _aggregate(non_semver)

    profile = _build_bundle(tmp_path / "profile")
    manifest_path = profile.artifact_paths["published-manifest"]
    manifest = _read_json(manifest_path)
    manifest["profileId"] = "unapproved-profile"
    _write(manifest_path, manifest)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="published-manifest.*violates",
    ):
        _aggregate(profile)

    for field in (
        "resolvedProfileDigest",
        "dependencyGraphDigest",
        "contextBindingPayloadDigest",
    ):
        derived_digest = _build_bundle(tmp_path / field)
        manifest_path = derived_digest.artifact_paths["published-manifest"]
        manifest = _read_json(manifest_path)
        manifest[field] = "sha256:" + ("f" * 64)
        _write(manifest_path, manifest)
        with pytest.raises(
            acceptance.Wc029AcceptanceEvidenceError,
            match="published-manifest.*violates",
        ):
            _aggregate(derived_digest)

    clause_membership = _build_bundle(tmp_path / "clause-membership")
    manifest_path = clause_membership.artifact_paths["published-manifest"]
    manifest = _read_json(manifest_path)
    constraint = next(
        item for item in manifest["citedClauses"] if item["clauseKind"] == "constraint"
    )
    constraint["clauseKind"] = "control"
    _write(manifest_path, manifest)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="published-manifest.*violates",
    ):
        _aggregate(clause_membership)

    partial_map = _build_bundle(tmp_path / "partial-map")
    manifest_path = partial_map.artifact_paths["published-manifest"]
    manifest = _read_json(manifest_path)
    manifest["citedClauses"].pop()
    _write(manifest_path, manifest)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="published-manifest.*violates",
    ):
        _aggregate(partial_map)

    shadowed_clause = _build_bundle(tmp_path / "shadowed-clause")
    manifest_path = shadowed_clause.artifact_paths["published-manifest"]
    manifest = _read_json(manifest_path)
    root_clause = manifest["manifestDocument"]["constraints"][0]
    manifest["citedClauses"][0] = {
        "clauseKind": "constraint",
        "clauseId": root_clause["constraintId"],
        "jsonPointer": "/constraints/0",
        "clauseDigest": compute_artifact_digest(root_clause),
    }
    _write(manifest_path, manifest)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="published-manifest.*violates",
    ):
        _aggregate(shadowed_clause)

    authority_binding = _build_bundle(tmp_path / "authority-binding")
    manifest_path = authority_binding.artifact_paths["published-manifest"]
    manifest = _read_json(manifest_path)
    context_binding = manifest["contextBinding"]
    context_binding["requiredCoverageScopeDigests"] = ["sha256:" + ("e" * 64)]
    binding_payload = dict(context_binding)
    binding_payload.pop("bindingDigest")
    context_binding["bindingDigest"] = compute_artifact_digest(binding_payload)
    _write(manifest_path, manifest)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="published-manifest.*violates",
    ):
        _aggregate(authority_binding)


def test_incident_findings_require_exact_effective_manifest_coverage() -> None:
    publication, _ = _publication_assets()
    incident = _trusted_incident_assets(publication)
    citation = _manifest_citation(
        "scenario-web-tier-failure",
        ("wc029-execution-" + sha256_hex("scenario-web-tier-failure").removeprefix("sha256:")[:32]),
        publication,
        incident.report,
        incident.active_state,
        incident.resolved_state,
    )
    unknown_state = incident.active_state.model_copy(
        update={
            "findings": tuple(
                finding.model_copy(update={"clause_id": "unrelated-unapproved-clause"})
                for finding in incident.active_state.findings
            )
        }
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="not covered by the exact effective manifest clauses",
    ):
        acceptance._validate_incident_manifest_coverage(
            publication.manifest,
            citation,
            unknown_state,
            incident.resolved_state,
        )

    unrelated_citation = citation.model_copy(update={"clause_ids": ("db-singleton-supported",)})
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="not covered by the exact effective manifest clauses",
    ):
        acceptance._validate_incident_manifest_coverage(
            publication.manifest,
            unrelated_citation,
            incident.active_state,
            incident.resolved_state,
        )


def test_enrichment_manifest_uses_exact_shared_binding_validation(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    scenario_prefix = "scenario-web-tier-failure"
    enrichment = IncidentEnrichmentManifest.model_validate_json(
        bundle.artifact_paths[f"{scenario_prefix}-enrichment"].read_bytes()
    )
    bound_request = IncidentBoundCorrelationRequest.model_validate_json(
        bundle.artifact_paths[f"{scenario_prefix}-incident-bound-request"].read_bytes()
    )
    report = CorrelationReport.model_validate_json(
        bundle.artifact_paths[f"{scenario_prefix}-report"].read_bytes()
    )
    guidance = IncidentGuidance.model_validate_json(
        bundle.artifact_paths[f"{scenario_prefix}-guidance"].read_bytes()
    )
    report_attestation = PublishedCorrelationReportAttestation.model_validate_json(
        bundle.artifact_paths[f"{scenario_prefix}-report-attestation"].read_bytes()
    )
    guidance_attestation = IncidentGuidanceAttestation.model_validate_json(
        bundle.artifact_paths[f"{scenario_prefix}-guidance-attestation"].read_bytes()
    )
    enrichment_attestation = IncidentEnrichmentAttestation.model_validate_json(
        bundle.artifact_paths[f"{scenario_prefix}-enrichment-attestation"].read_bytes()
    )
    active_feed = IncidentEnrichmentFeedPointer.model_validate_json(
        bundle.artifact_paths[f"{scenario_prefix}-feed-active"].read_bytes()
    )

    def rebuild_manifest(
        *,
        incident_revision: int | None = None,
        state_reference: VersionPinnedBlobReference | None = None,
        publication_statement_digest: str | None = None,
    ) -> IncidentEnrichmentManifest:
        report_asset_payload = enrichment.correlation_report_asset.model_dump(
            mode="python",
            by_alias=True,
            exclude={"reference_id", "reference_digest"},
        )
        if incident_revision is not None:
            report_asset_payload["incidentRevision"] = incident_revision
        if publication_statement_digest is not None:
            report_asset_payload["publicationStatementDigest"] = publication_statement_digest
        report_asset_digest = compute_artifact_digest(_json_value(report_asset_payload))
        report_asset = PublishedCorrelationReportAssetReference(
            **report_asset_payload,
            referenceId=("report-asset-" + report_asset_digest.removeprefix("sha256:")[:32]),
            referenceDigest=report_asset_digest,
        )
        manifest_payload = enrichment.model_dump(
            mode="python",
            by_alias=True,
            exclude={"enrichment_id", "manifest_digest"},
        )
        manifest_payload["correlationReportAsset"] = report_asset
        if incident_revision is not None:
            manifest_payload["incidentRevision"] = incident_revision
        if state_reference is not None:
            manifest_payload["incidentStateReference"] = state_reference
        manifest_digest = compute_artifact_digest(_json_value(manifest_payload))
        return IncidentEnrichmentManifest(
            **manifest_payload,
            enrichmentId=("incident-enrichment-" + manifest_digest.removeprefix("sha256:")[:32]),
            manifestDigest=manifest_digest,
        )

    wrong_revision = rebuild_manifest(incident_revision=enrichment.incident_revision + 1)
    wrong_reference = rebuild_manifest(
        state_reference=enrichment.incident_state_reference.model_copy(
            update={"version": "substituted-state-version"}
        )
    )
    wrong_statement = rebuild_manifest(publication_statement_digest="sha256:" + ("f" * 64))
    for mutated in (
        wrong_revision,
        wrong_reference,
        wrong_statement,
    ):
        with pytest.raises(
            ValueError,
            match="does not match exact assets",
        ):
            validate_incident_enrichment_manifest_binding(
                mutated,
                bound_request,
                report,
                guidance,
            )

    report_reference_payload = enrichment.correlation_report_asset.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    report_reference_payload["attestationReference"] = (
        enrichment.correlation_report_asset.attestation_reference.model_copy(
            update={"content_digest": "sha256:" + ("f" * 64)}
        )
    )
    report_reference_digest = compute_artifact_digest(_json_value(report_reference_payload))
    wrong_report_reference = PublishedCorrelationReportAssetReference(
        **report_reference_payload,
        referenceId=("report-asset-" + report_reference_digest.removeprefix("sha256:")[:32]),
        referenceDigest=report_reference_digest,
    )
    with pytest.raises(ValueError, match="do not match exact content"):
        validate_published_correlation_report_assets(
            wrong_report_reference,
            report,
            report_attestation,
            bound_request,
            expected_authority_proof_digest=(
                bound_request.correlation_request.context_binding.publication_authority_reference.content_digest
            ),
            trusted_report_key_id=bundle.keys["report"].key_id,
            report_signature_verifier=acceptance._signature_verifier(
                bundle.keys["report"].public_key
            ),
        )

    guidance_reference_payload = enrichment.guidance_asset.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    guidance_reference_payload["attestationReference"] = (
        enrichment.guidance_asset.attestation_reference.model_copy(
            update={"content_digest": "sha256:" + ("e" * 64)}
        )
    )
    guidance_reference_digest = compute_artifact_digest(_json_value(guidance_reference_payload))
    wrong_guidance_reference = IncidentGuidanceAssetReference(
        **guidance_reference_payload,
        referenceId=("guidance-asset-" + guidance_reference_digest.removeprefix("sha256:")[:32]),
        referenceDigest=guidance_reference_digest,
    )
    with pytest.raises(ValueError, match="do not match exact content"):
        validate_incident_guidance_assets(
            wrong_guidance_reference,
            guidance,
            guidance_attestation,
            trusted_guidance_key_id=bundle.keys["guidance"].key_id,
            guidance_signature_verifier=acceptance._signature_verifier(
                bundle.keys["guidance"].public_key
            ),
        )

    enrichment_reference_payload = active_feed.enrichment_asset.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    enrichment_reference_payload["attestationReference"] = (
        active_feed.enrichment_asset.attestation_reference.model_copy(
            update={"content_digest": "sha256:" + ("d" * 64)}
        )
    )
    enrichment_reference_digest = compute_artifact_digest(_json_value(enrichment_reference_payload))
    wrong_enrichment_reference = IncidentEnrichmentAssetReference(
        **enrichment_reference_payload,
        referenceId=(
            "enrichment-asset-" + enrichment_reference_digest.removeprefix("sha256:")[:32]
        ),
        referenceDigest=enrichment_reference_digest,
    )
    with pytest.raises(ValueError, match="do not match exact content"):
        validate_incident_enrichment_assets(
            wrong_enrichment_reference,
            enrichment,
            enrichment_attestation,
            trusted_enrichment_key_id=bundle.keys["enrichment"].key_id,
            enrichment_signature_verifier=acceptance._signature_verifier(
                bundle.keys["enrichment"].public_key
            ),
        )


def test_v2_feed_indexes_require_signed_authoritative_v1_sources(
    tmp_path: Path,
) -> None:
    missing = _build_bundle(tmp_path / "missing")
    scenario = _scenario(missing, "web-tier-failure")
    missing_ids = {
        "scenario-web-tier-failure-source-index-active",
        "scenario-web-tier-failure-source-index-active-attestation",
    }
    scenario["phases"]["observe"] = [
        artifact_id
        for artifact_id in scenario["phases"]["observe"]
        if artifact_id not in missing_ids
    ]
    missing.index["artifacts"] = [
        item for item in missing.index["artifacts"] if item["artifactId"] not in missing_ids
    ]
    for artifact_id in missing_ids:
        missing.artifact_paths[artifact_id].unlink()
    _rewrite_index(missing)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="acceptance index failed closed validation",
    ):
        _aggregate(missing)

    substituted = _build_bundle(tmp_path / "substituted")
    source_id = "scenario-web-tier-failure-source-index-active"
    attestation_id = f"{source_id}-attestation"
    source_path = substituted.artifact_paths[source_id]
    source = ActiveIncidentIndex.model_validate_json(source_path.read_bytes())
    changed_source = source.model_copy(
        update={"published_at": source.published_at + timedelta(seconds=1)}
    )
    _write(source_path, changed_source)
    signature = (
        base64.urlsafe_b64encode(
            substituted.private_keys["incident"].sign(
                changed_source.canonical_bytes(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    _write(
        substituted.artifact_paths[attestation_id],
        ActiveIncidentIndexAttestation(
            schemaVersion="athena.activeIncidentIndexAttestation.v1",
            indexDigest=sha256_hex(changed_source.canonical_bytes()),
            signatureAlgorithm="RS256",
            keyVaultKeyId=substituted.keys["incident"].key_id,
            detachedSignature=signature,
        ),
    )
    _refresh_scenario_execution_binding(
        substituted,
        "web-tier-failure",
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="v2 feed indexes do not bind authoritative v1 source indexes",
    ):
        _aggregate(substituted)


def test_private_snapshot_blocks_or_detects_restored_mtime_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _build_bundle(tmp_path)
    victim = bundle.artifact_paths["global-job-readback"]
    original = victim.read_bytes()
    original_stat = victim.stat()
    replacement = bytes([original[0] ^ 1]) + original[1:]
    assert len(replacement) == len(original)
    real_read = acceptance._read_pinned_file
    race_attempted = False
    write_blocked = False
    delete_blocked = False

    def race_before_first_read(
        pinned: acceptance._PinnedFileHandle,
        *,
        maximum_bytes: int,
        label: str,
    ) -> bytes:
        nonlocal delete_blocked, race_attempted, write_blocked
        if not race_attempted:
            race_attempted = True
            if os.name == "nt":
                try:
                    with victim.open("r+b", buffering=0):
                        pass
                except OSError:
                    write_blocked = True
                try:
                    victim.unlink()
                except OSError:
                    delete_blocked = True
            else:
                with victim.open("r+b", buffering=0) as stream:
                    stream.write(replacement)
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.seek(0)
                    stream.write(original)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.utime(
                    victim,
                    ns=(
                        original_stat.st_atime_ns,
                        original_stat.st_mtime_ns,
                    ),
                )
        return real_read(
            pinned,
            maximum_bytes=maximum_bytes,
            label=label,
        )

    monkeypatch.setattr(
        acceptance,
        "_read_pinned_file",
        race_before_first_read,
    )

    if os.name == "nt":
        _aggregate(bundle)
        assert write_blocked
        assert delete_blocked
    else:
        with pytest.raises(
            acceptance.Wc029AcceptanceEvidenceError,
            match="changed while its pinned handle|identity changed",
        ):
            _aggregate(bundle)
        assert not write_blocked

    assert race_attempted
    assert victim.read_bytes() == original
    assert victim.stat().st_size == original_stat.st_size
    assert victim.stat().st_mtime_ns == original_stat.st_mtime_ns


def test_snapshot_rejects_directory_handle_exhaustion_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = _build_bundle(tmp_path / "scandir")

    def unexpected_walk(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("os.walk must not enumerate the evidence tree")

    monkeypatch.setattr(acceptance.os, "walk", unexpected_walk)
    _aggregate(valid)

    directory_count = _build_bundle(tmp_path / "directory-count")
    for index in range(acceptance.MAX_EVIDENCE_DIRECTORIES):
        (directory_count.root / f"empty-{index:03d}").mkdir()
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="directory-count bound",
    ):
        _aggregate(directory_count)

    traversal_depth = _build_bundle(tmp_path / "depth")
    current = traversal_depth.root
    for index in range(acceptance.MAX_EVIDENCE_PATH_DEPTH + 1):
        current /= f"d{index}"
        current.mkdir()
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="traversal-depth bound",
    ):
        _aggregate(traversal_depth)

    relative_length = _build_bundle(tmp_path / "relative-length")
    current = relative_length.root
    for index in range(4):
        current /= f"{index}-" + ("x" * 170)
        current.mkdir()
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="relative path exceeds its length bound",
    ):
        _aggregate(relative_length)

    total_characters = _build_bundle(tmp_path / "total-characters")
    for index in range(100):
        (total_characters.root / (f"{index:03d}-" + ("x" * 170))).mkdir()
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="total path-character bound",
    ):
        _aggregate(total_characters)


def test_signed_manifest_artifact_ids_are_globally_unique_across_phases(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    manifest = acceptance.Wc029ScenarioExecutionManifest.model_validate_json(
        bundle.artifact_paths["scenario-disk-capacity-pressure-execution-manifest"].read_bytes()
    )
    artifacts = list(manifest.artifacts)
    plan_binding = next(item for item in artifacts if item.phase == "plan")
    apply_index = next(index for index, item in enumerate(artifacts) if item.phase == "apply")
    artifacts[apply_index] = artifacts[apply_index].model_copy(
        update={"artifact_id": plan_binding.artifact_id}
    )
    payload = manifest.model_dump(
        mode="python",
        by_alias=True,
        exclude={"manifest_digest"},
    )
    payload["artifacts"] = tuple(artifacts)

    with pytest.raises(ValueError, match="unique and sorted"):
        _digest_bound_model(
            acceptance.Wc029ScenarioExecutionManifest,
            payload,
            digest_field="manifestDigest",
        )


def test_phase_windows_and_lifecycle_timestamps_are_strictly_ordered(
    tmp_path: Path,
) -> None:
    zero_duration = _build_bundle(tmp_path / "zero-duration")
    scenario = _scenario(zero_duration, "disk-capacity-pressure")
    manifest_id = next(
        artifact_id
        for artifact_id in scenario["phases"]["verify"]
        if _declaration(zero_duration, artifact_id)["evidenceClass"]
        == "scenario-execution-manifest"
    )
    manifest_path = zero_duration.artifact_paths[manifest_id]
    manifest = _read_json(manifest_path)
    manifest["phaseWindows"][0]["completedAt"] = manifest["phaseWindows"][0]["startedAt"]
    _write(manifest_path, manifest)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="execution-manifest.*violates",
    ):
        _aggregate(zero_duration)

    adjacent = _build_bundle(tmp_path / "adjacent")
    scenario = _scenario(adjacent, "disk-capacity-pressure")
    manifest_id = next(
        artifact_id
        for artifact_id in scenario["phases"]["verify"]
        if _declaration(adjacent, artifact_id)["evidenceClass"] == "scenario-execution-manifest"
    )
    manifest_path = adjacent.artifact_paths[manifest_id]
    manifest = _read_json(manifest_path)
    manifest["phaseWindows"][0]["completedAt"] = manifest["phaseWindows"][1]["startedAt"]
    _write(manifest_path, manifest)
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="execution-manifest.*violates",
    ):
        _aggregate(adjacent)

    equal_lifecycle = _build_bundle(tmp_path / "equal-lifecycle")
    scenario_class = "disk-capacity-pressure"
    recovered_id = f"scenario-{scenario_class}-recovered-state"
    execution_id = f"scenario-{scenario_class}-verify-execution"
    readback_id = f"scenario-{scenario_class}-verify-readback"
    proof_id = f"scenario-{scenario_class}-recovery-proof"
    recovered_state = acceptance.Wc029ResourceStateEvidence.model_validate_json(
        equal_lifecycle.artifact_paths[recovered_id].read_bytes()
    )
    execution_path = equal_lifecycle.artifact_paths[execution_id]
    execution = _read_json(execution_path)
    execution["startedAt"] = recovered_state.captured_at.isoformat().replace("+00:00", "Z")
    execution_payload = dict(execution)
    execution_payload.pop("executionDigest")
    execution["executionDigest"] = compute_artifact_digest(execution_payload)
    _write(execution_path, execution)

    readback_path = equal_lifecycle.artifact_paths[readback_id]
    readback = _read_json(readback_path)
    readback["executionDigest"] = execution["executionDigest"]
    readback_payload = dict(readback)
    readback_payload.pop("readbackDigest")
    readback["readbackDigest"] = compute_artifact_digest(readback_payload)
    _write(readback_path, readback)

    proof_path = equal_lifecycle.artifact_paths[proof_id]
    proof = _read_json(proof_path)
    proof["postRecoveryJobReadback"]["contentSha256"] = sha256_hex(readback_path.read_bytes())
    _write(proof_path, proof)
    _refresh_scenario_execution_binding(
        equal_lifecycle,
        scenario_class,
    )
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="chronology is not strictly ordered",
    ):
        _aggregate(equal_lifecycle)


def test_scenario_execution_intervals_and_request_identities_are_global(
    tmp_path: Path,
) -> None:
    overlap = _build_bundle(tmp_path)
    web_manifest = acceptance.Wc029ScenarioExecutionManifest.model_validate_json(
        overlap.artifact_paths["scenario-web-tier-failure-execution-manifest"].read_bytes()
    )
    backend_manifest_path = overlap.artifact_paths[
        "scenario-backend-degradation-execution-manifest"
    ]
    backend_manifest = _read_json(backend_manifest_path)
    backend_manifest["phaseWindows"][0]["startedAt"] = (
        (web_manifest.phase_windows[-1].completed_at - timedelta(seconds=1))
        .isoformat()
        .replace("+00:00", "Z")
    )
    backend_manifest.pop("manifestDigest")
    backend_manifest["phaseWindows"] = tuple(backend_manifest["phaseWindows"])
    backend_manifest["artifacts"] = tuple(backend_manifest["artifacts"])
    _write(
        backend_manifest_path,
        _digest_bound_model(
            acceptance.Wc029ScenarioExecutionManifest,
            backend_manifest,
            digest_field="manifestDigest",
        ),
    )
    _refresh_scenario_execution_binding(overlap, "backend-degradation")
    with pytest.raises(
        acceptance.Wc029AcceptanceEvidenceError,
        match="execution intervals must not overlap",
    ):
        _aggregate(overlap)

    first_start = datetime(2026, 9, 10, 0, 0, tzinfo=UTC)
    intervals = (
        (first_start, first_start + timedelta(minutes=1), "scenario-a"),
        (
            first_start + timedelta(minutes=2),
            first_start + timedelta(minutes=3),
            "scenario-b",
        ),
    )
    backend_monitoring = MonitoringEvidenceHandoff.model_validate_json(
        overlap.artifact_paths["scenario-backend-degradation-monitoring"].read_bytes()
    )
    disk_monitoring = MonitoringEvidenceHandoff.model_validate_json(
        overlap.artifact_paths["scenario-disk-capacity-pressure-monitoring"].read_bytes()
    )
    assert backend_monitoring.collection_id != disk_monitoring.collection_id
    assert acceptance._monitoring_request_digest(
        backend_monitoring
    ) != acceptance._monitoring_request_digest(disk_monitoring)
    shifted_monitoring = backend_monitoring.model_copy(
        update={"observed_at": (backend_monitoring.observed_at + timedelta(seconds=1))}
    )
    changed_attestation_monitoring = backend_monitoring.model_copy(
        update={
            "collector_attestation": (
                backend_monitoring.collector_attestation.model_copy(
                    update={"signature": base64.b64encode(b"different-signature").decode("ascii")}
                )
            )
        }
    )
    assert acceptance._monitoring_request_digest(
        backend_monitoring
    ) != acceptance._monitoring_request_digest(shifted_monitoring)
    assert acceptance._monitoring_request_digest(
        backend_monitoring
    ) != acceptance._monitoring_request_digest(changed_attestation_monitoring)
    for label in (
        "scenario execution IDs",
        "correlation request digests",
        "monitoring handoff digests",
        "monitoring collection IDs",
        "monitoring bundle/evidence digests",
    ):
        with pytest.raises(
            acceptance.Wc029AcceptanceEvidenceError,
            match=f"unique {label}",
        ):
            acceptance._validate_scenario_execution_set(
                intervals,
                ((label, ("duplicate", "duplicate")),),
            )


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
