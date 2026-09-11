from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from athena_context.contracts.common import compute_artifact_digest, sha256_hex
from athena_context.contracts.correlation import (
    CORRELATION_MAX_CANONICAL_BYTES,
    CorrelationReport,
    IncidentBoundCorrelationRequest,
    PublishedRuntimeContextBinding,
    validate_runtime_correlation_report,
)
from athena_context.contracts.guidance import (
    IncidentGuidance,
    IncidentGuidanceAssetReference,
    IncidentGuidanceSourceBinding,
)
from athena_context.contracts.models import AthenaBaseModel, Sha256Digest
from athena_context.contracts.operational_phase import VersionPinnedBlobReference

MAX_PUBLISHED_CORRELATION_REPORT_BYTES = CORRELATION_MAX_CANONICAL_BYTES
MAX_PUBLISHED_CORRELATION_REPORT_STATEMENT_BYTES = 8 * 1024
MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES = 64 * 1024
MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES = 16 * 1024
MAX_INCIDENT_ENRICHMENT_REFERENCE_BYTES = 16 * 1024


class _StrictIncidentEnrichmentModel(AthenaBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


def _expected_digest(
    model: AthenaBaseModel,
    *,
    excluded_fields: set[str],
) -> Sha256Digest:
    return compute_artifact_digest(
        model.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude=excluded_fields,
        )
    )


def _state_prefix(incident_id: str, state_result_digest: str) -> str:
    suffix = state_result_digest.removeprefix("sha256:")
    return f"incidents/{incident_id}/versions/{suffix}"


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


def _require_canonical_size(
    model: _StrictIncidentEnrichmentModel,
    *,
    maximum_bytes: int,
    name: str,
) -> None:
    if len(model.canonical_bytes()) > maximum_bytes:
        raise ValueError(f"{name} exceeds its canonical byte budget")


class PublishedCorrelationReportStatement(_StrictIncidentEnrichmentModel):
    schema_version: Literal["athena.wc027PublishedCorrelationReportStatement.v1"] = Field(
        alias="schemaVersion"
    )
    statement_id: str = Field(
        alias="statementId",
        pattern=r"^report-publication-[a-f0-9]{32}$",
    )
    purpose: Literal["athena.wc027.publish-correlation-report"]
    incident_id: str = Field(
        alias="incidentId",
        pattern=r"^inc-[a-f0-9]{12}$",
    )
    incident_transition_id: str = Field(
        alias="incidentTransitionId",
        pattern=r"^wc016-[a-f0-9]{64}$",
    )
    incident_revision: int = Field(alias="incidentRevision", ge=1)
    incident_state_result_digest: Sha256Digest = Field(alias="incidentStateResultDigest")
    incident_state_reference: VersionPinnedBlobReference = Field(alias="incidentStateReference")
    incident_state_attestation_reference: VersionPinnedBlobReference = Field(
        alias="incidentStateAttestationReference"
    )
    incident_subject_id: str = Field(
        alias="incidentSubjectId",
        pattern=r"^incident-subject-[a-f0-9]{32}$",
    )
    incident_subject_digest: Sha256Digest = Field(alias="incidentSubjectDigest")
    incident_bound_request_id: str = Field(
        alias="incidentBoundRequestId",
        pattern=r"^incident-bound-request-[a-f0-9]{32}$",
    )
    incident_bound_request_digest: Sha256Digest = Field(alias="incidentBoundRequestDigest")
    correlation_request_digest: Sha256Digest = Field(alias="correlationRequestDigest")
    correlation_transition_digest: Sha256Digest = Field(alias="correlationTransitionDigest")
    report_id: str = Field(
        alias="reportId",
        pattern=r"^report-[a-f0-9]{32}$",
    )
    report_digest: Sha256Digest = Field(alias="reportDigest")
    report_content_digest: Sha256Digest = Field(alias="reportContentDigest")
    authority_proof_digest: Sha256Digest = Field(alias="authorityProofDigest")
    no_auto_remediation: Literal[True] = Field(
        default=True,
        alias="noAutoRemediation",
    )
    statement_digest: Sha256Digest = Field(alias="statementDigest")

    @model_validator(mode="after")
    def validate_statement(self) -> PublishedCorrelationReportStatement:
        prefix = _state_prefix(
            self.incident_id,
            self.incident_state_result_digest,
        )
        if (
            self.incident_state_reference.name != f"{prefix}/state.json"
            or self.incident_state_attestation_reference.name != f"{prefix}/attestation.json"
        ):
            raise ValueError("report publication state paths are invalid")
        expected = _expected_digest(
            self,
            excluded_fields={"statement_id", "statement_digest"},
        )
        if self.statement_digest != expected:
            raise ValueError("statementDigest does not bind report publication statement")
        if self.statement_id != f"report-publication-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("statementId is not digest-bound")
        _require_canonical_size(
            self,
            maximum_bytes=MAX_PUBLISHED_CORRELATION_REPORT_STATEMENT_BYTES,
            name="report publication statement",
        )
        return self


class PublishedCorrelationReportAttestation(_StrictIncidentEnrichmentModel):
    schema_version: Literal["athena.wc027PublishedCorrelationReportAttestation.v1"] = Field(
        alias="schemaVersion"
    )
    statement: PublishedCorrelationReportStatement
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        min_length=1,
        max_length=512,
    )
    signed_preimage_digest: Sha256Digest = Field(alias="signedPreimageDigest")
    detached_signature: str = Field(
        alias="detachedSignature",
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=1,
        max_length=8192,
    )

    @model_validator(mode="after")
    def validate_attestation(self) -> PublishedCorrelationReportAttestation:
        if self.signed_preimage_digest != sha256_hex(self.statement.canonical_bytes()):
            raise ValueError("signedPreimageDigest does not bind report publication statement")
        _require_canonical_size(
            self,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
            name="report publication attestation",
        )
        return self


class PublishedCorrelationReportAssetReference(_StrictIncidentEnrichmentModel):
    schema_version: Literal["athena.wc027PublishedCorrelationReportAssetReference.v1"] = Field(
        alias="schemaVersion"
    )
    reference_id: str = Field(
        alias="referenceId",
        pattern=r"^report-asset-[a-f0-9]{32}$",
    )
    incident_id: str = Field(
        alias="incidentId",
        pattern=r"^inc-[a-f0-9]{12}$",
    )
    incident_transition_id: str = Field(
        alias="incidentTransitionId",
        pattern=r"^wc016-[a-f0-9]{64}$",
    )
    incident_revision: int = Field(alias="incidentRevision", ge=1)
    incident_state_result_digest: Sha256Digest = Field(alias="incidentStateResultDigest")
    incident_subject_id: str = Field(
        alias="incidentSubjectId",
        pattern=r"^incident-subject-[a-f0-9]{32}$",
    )
    incident_subject_digest: Sha256Digest = Field(alias="incidentSubjectDigest")
    incident_bound_request_id: str = Field(
        alias="incidentBoundRequestId",
        pattern=r"^incident-bound-request-[a-f0-9]{32}$",
    )
    incident_bound_request_digest: Sha256Digest = Field(alias="incidentBoundRequestDigest")
    correlation_request_digest: Sha256Digest = Field(alias="correlationRequestDigest")
    correlation_transition_digest: Sha256Digest = Field(alias="correlationTransitionDigest")
    report_id: str = Field(
        alias="reportId",
        pattern=r"^report-[a-f0-9]{32}$",
    )
    report_digest: Sha256Digest = Field(alias="reportDigest")
    report_content_digest: Sha256Digest = Field(alias="reportContentDigest")
    authority_proof_digest: Sha256Digest = Field(alias="authorityProofDigest")
    publication_statement_id: str = Field(
        alias="publicationStatementId",
        pattern=r"^report-publication-[a-f0-9]{32}$",
    )
    publication_statement_digest: Sha256Digest = Field(alias="publicationStatementDigest")
    report_reference: VersionPinnedBlobReference = Field(alias="reportReference")
    attestation_reference: VersionPinnedBlobReference = Field(alias="attestationReference")
    reference_digest: Sha256Digest = Field(alias="referenceDigest")

    @model_validator(mode="after")
    def validate_reference(
        self,
    ) -> PublishedCorrelationReportAssetReference:
        state_prefix = _state_prefix(
            self.incident_id,
            self.incident_state_result_digest,
        )
        prefix = f"{state_prefix}/correlation-reports/{self.report_id}"
        if (
            self.report_reference.name != f"{prefix}/report.json"
            or self.attestation_reference.name != f"{prefix}/attestation.json"
            or self.report_reference.content_digest != self.report_content_digest
        ):
            raise ValueError("correlation report asset paths are invalid")
        expected = _expected_digest(
            self,
            excluded_fields={"reference_id", "reference_digest"},
        )
        if self.reference_digest != expected:
            raise ValueError("referenceDigest does not bind correlation report assets")
        if self.reference_id != f"report-asset-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("referenceId is not digest-bound")
        _require_canonical_size(
            self,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_REFERENCE_BYTES,
            name="correlation report asset reference",
        )
        return self


class IncidentEnrichmentManifest(_StrictIncidentEnrichmentModel):
    schema_version: Literal["athena.wc027IncidentEnrichmentManifest.v1"] = Field(
        alias="schemaVersion"
    )
    enrichment_id: str = Field(
        alias="enrichmentId",
        pattern=r"^incident-enrichment-[a-f0-9]{32}$",
    )
    incident_id: str = Field(
        alias="incidentId",
        pattern=r"^inc-[a-f0-9]{12}$",
    )
    incident_transition_id: str = Field(
        alias="incidentTransitionId",
        pattern=r"^wc016-[a-f0-9]{64}$",
    )
    incident_revision: int = Field(alias="incidentRevision", ge=1)
    incident_state_result_digest: Sha256Digest = Field(alias="incidentStateResultDigest")
    incident_state_reference: VersionPinnedBlobReference = Field(alias="incidentStateReference")
    incident_state_attestation_reference: VersionPinnedBlobReference = Field(
        alias="incidentStateAttestationReference"
    )
    incident_subject_id: str = Field(
        alias="incidentSubjectId",
        pattern=r"^incident-subject-[a-f0-9]{32}$",
    )
    incident_subject_digest: Sha256Digest = Field(alias="incidentSubjectDigest")
    incident_bound_request_id: str = Field(
        alias="incidentBoundRequestId",
        pattern=r"^incident-bound-request-[a-f0-9]{32}$",
    )
    incident_bound_request_digest: Sha256Digest = Field(alias="incidentBoundRequestDigest")
    correlation_report_asset: PublishedCorrelationReportAssetReference = Field(
        alias="correlationReportAsset"
    )
    guidance_asset: IncidentGuidanceAssetReference = Field(alias="guidanceAsset")
    guidance_source_binding: IncidentGuidanceSourceBinding = Field(alias="guidanceSourceBinding")
    no_auto_remediation: Literal[True] = Field(
        default=True,
        alias="noAutoRemediation",
    )
    manifest_digest: Sha256Digest = Field(alias="manifestDigest")

    @model_validator(mode="after")
    def validate_manifest(self) -> IncidentEnrichmentManifest:
        prefix = _state_prefix(
            self.incident_id,
            self.incident_state_result_digest,
        )
        report = self.correlation_report_asset
        guidance = self.guidance_asset
        source = self.guidance_source_binding
        if (
            self.incident_state_reference.name != f"{prefix}/state.json"
            or self.incident_state_attestation_reference.name != f"{prefix}/attestation.json"
            or report.incident_id != self.incident_id
            or report.incident_transition_id != self.incident_transition_id
            or report.incident_revision != self.incident_revision
            or report.incident_state_result_digest != self.incident_state_result_digest
            or report.incident_subject_id != self.incident_subject_id
            or report.incident_subject_digest != self.incident_subject_digest
            or report.incident_bound_request_id != self.incident_bound_request_id
            or report.incident_bound_request_digest != self.incident_bound_request_digest
            or guidance.incident_id != self.incident_id
            or guidance.incident_state_digest != self.incident_state_result_digest
            or source.incident_id != self.incident_id
            or source.incident_revision != self.incident_revision
            or source.incident_state_digest != self.incident_state_result_digest
            or source.incident_subject_id != self.incident_subject_id
            or source.incident_subject_digest != self.incident_subject_digest
            or source.incident_bound_request_id != self.incident_bound_request_id
            or source.incident_bound_request_digest != self.incident_bound_request_digest
            or source.correlation_report_id != report.report_id
            or source.correlation_report_digest != report.report_digest
            or source.correlation_request_digest != report.correlation_request_digest
            or source.transition_digest != report.correlation_transition_digest
        ):
            raise ValueError("incident enrichment does not bind one exact occurrence")
        expected = _expected_digest(
            self,
            excluded_fields={"enrichment_id", "manifest_digest"},
        )
        if self.manifest_digest != expected:
            raise ValueError("manifestDigest does not bind incident enrichment")
        if self.enrichment_id != f"incident-enrichment-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("enrichmentId is not digest-bound")
        _require_canonical_size(
            self,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES,
            name="incident enrichment manifest",
        )
        return self


class IncidentEnrichmentAttestation(_StrictIncidentEnrichmentModel):
    schema_version: Literal["athena.wc027IncidentEnrichmentAttestation.v1"] = Field(
        alias="schemaVersion"
    )
    enrichment_id: str = Field(
        alias="enrichmentId",
        pattern=r"^incident-enrichment-[a-f0-9]{32}$",
    )
    manifest_digest: Sha256Digest = Field(alias="manifestDigest")
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        min_length=1,
        max_length=512,
    )
    signed_preimage_digest: Sha256Digest = Field(alias="signedPreimageDigest")
    detached_signature: str = Field(
        alias="detachedSignature",
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=1,
        max_length=8192,
    )

    @model_validator(mode="after")
    def validate_attestation(self) -> IncidentEnrichmentAttestation:
        _require_canonical_size(
            self,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
            name="incident enrichment attestation",
        )
        return self


class IncidentEnrichmentAssetReference(_StrictIncidentEnrichmentModel):
    schema_version: Literal["athena.wc027IncidentEnrichmentAssetReference.v1"] = Field(
        alias="schemaVersion"
    )
    reference_id: str = Field(
        alias="referenceId",
        pattern=r"^enrichment-asset-[a-f0-9]{32}$",
    )
    incident_id: str = Field(
        alias="incidentId",
        pattern=r"^inc-[a-f0-9]{12}$",
    )
    incident_state_result_digest: Sha256Digest = Field(alias="incidentStateResultDigest")
    enrichment_id: str = Field(
        alias="enrichmentId",
        pattern=r"^incident-enrichment-[a-f0-9]{32}$",
    )
    manifest_digest: Sha256Digest = Field(alias="manifestDigest")
    manifest_reference: VersionPinnedBlobReference = Field(alias="manifestReference")
    attestation_reference: VersionPinnedBlobReference = Field(alias="attestationReference")
    reference_digest: Sha256Digest = Field(alias="referenceDigest")

    @model_validator(mode="after")
    def validate_reference(self) -> IncidentEnrichmentAssetReference:
        state_prefix = _state_prefix(
            self.incident_id,
            self.incident_state_result_digest,
        )
        prefix = f"{state_prefix}/enrichments/{self.enrichment_id}"
        if (
            self.manifest_reference.name != f"{prefix}/manifest.json"
            or self.attestation_reference.name != f"{prefix}/attestation.json"
        ):
            raise ValueError("incident enrichment asset paths are invalid")
        expected = _expected_digest(
            self,
            excluded_fields={"reference_id", "reference_digest"},
        )
        if self.reference_digest != expected:
            raise ValueError("referenceDigest does not bind incident enrichment assets")
        if self.reference_id != f"enrichment-asset-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("referenceId is not digest-bound")
        _require_canonical_size(
            self,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_REFERENCE_BYTES,
            name="incident enrichment asset reference",
        )
        return self


def build_published_correlation_report_statement(
    incident_bound_request: IncidentBoundCorrelationRequest,
    report: CorrelationReport,
    *,
    authority_proof_digest: Sha256Digest,
) -> PublishedCorrelationReportStatement:
    incident_bound_request = IncidentBoundCorrelationRequest.model_validate_json(
        incident_bound_request.model_dump_json(by_alias=True)
    )
    report = CorrelationReport.model_validate_json(report.model_dump_json(by_alias=True))
    request = incident_bound_request.correlation_request
    validate_runtime_correlation_report(
        report,
        request,
        evaluated_at=report.as_of,
    )
    if len(report.canonical_bytes()) > MAX_PUBLISHED_CORRELATION_REPORT_BYTES:
        raise ValueError(
            "published correlation report exceeds its canonical byte budget"
        )
    context = request.context_binding
    if not isinstance(context, PublishedRuntimeContextBinding):
        raise ValueError("report publication requires published runtime context")
    if authority_proof_digest != context.publication_authority_reference.content_digest:
        raise ValueError("authority proof does not match published runtime context")
    subject = incident_bound_request.incident_subject
    payload: dict[str, object] = {
        "schemaVersion": ("athena.wc027PublishedCorrelationReportStatement.v1"),
        "purpose": "athena.wc027.publish-correlation-report",
        "incidentId": subject.incident_id,
        "incidentTransitionId": subject.incident_transition_id,
        "incidentRevision": subject.incident_revision,
        "incidentStateResultDigest": subject.incident_state_digest,
        "incidentStateReference": subject.state_reference,
        "incidentStateAttestationReference": subject.attestation_reference,
        "incidentSubjectId": subject.subject_id,
        "incidentSubjectDigest": subject.subject_digest,
        "incidentBoundRequestId": incident_bound_request.request_id,
        "incidentBoundRequestDigest": incident_bound_request.binding_digest,
        "correlationRequestDigest": report.request_digest,
        "correlationTransitionDigest": report.transition_digest,
        "reportId": report.report_id,
        "reportDigest": report.report_digest,
        "reportContentDigest": sha256_hex(report.canonical_bytes()),
        "authorityProofDigest": authority_proof_digest,
        "noAutoRemediation": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return PublishedCorrelationReportStatement.model_validate(
        {
            **payload,
            "statementId": (f"report-publication-{digest.removeprefix('sha256:')[:32]}"),
            "statementDigest": digest,
        }
    )


def build_incident_enrichment_manifest(
    incident_bound_request: IncidentBoundCorrelationRequest,
    correlation_report_asset: PublishedCorrelationReportAssetReference,
    report: CorrelationReport,
    guidance_asset: IncidentGuidanceAssetReference,
    guidance: IncidentGuidance,
) -> IncidentEnrichmentManifest:
    incident_bound_request = IncidentBoundCorrelationRequest.model_validate_json(
        incident_bound_request.model_dump_json(by_alias=True)
    )
    correlation_report_asset = PublishedCorrelationReportAssetReference.model_validate_json(
        correlation_report_asset.model_dump_json(by_alias=True)
    )
    report = CorrelationReport.model_validate_json(report.model_dump_json(by_alias=True))
    guidance_asset = IncidentGuidanceAssetReference.model_validate_json(
        guidance_asset.model_dump_json(by_alias=True)
    )
    guidance = IncidentGuidance.model_validate_json(guidance.model_dump_json(by_alias=True))
    subject = incident_bound_request.incident_subject
    context = incident_bound_request.correlation_request.context_binding
    if not isinstance(context, PublishedRuntimeContextBinding):
        raise ValueError("incident enrichment requires published runtime context")
    authority_proof_digest = context.publication_authority_reference.content_digest
    statement = build_published_correlation_report_statement(
        incident_bound_request,
        report,
        authority_proof_digest=authority_proof_digest,
    )
    if (
        correlation_report_asset.report_id != report.report_id
        or correlation_report_asset.report_digest != report.report_digest
        or correlation_report_asset.report_content_digest
        != statement.report_content_digest
        or correlation_report_asset.correlation_request_digest
        != statement.correlation_request_digest
        or correlation_report_asset.correlation_transition_digest
        != statement.correlation_transition_digest
        or correlation_report_asset.authority_proof_digest
        != statement.authority_proof_digest
        or correlation_report_asset.publication_statement_id
        != statement.statement_id
        or correlation_report_asset.publication_statement_digest
        != statement.statement_digest
    ):
        raise ValueError("correlation report asset does not match exact report")
    if (
        guidance_asset.guidance_id != guidance.guidance_id
        or guidance_asset.guidance_digest != guidance.guidance_digest
        or guidance_asset.guidance_reference.content_digest
        != sha256_hex(guidance.canonical_bytes())
    ):
        raise ValueError("guidance asset does not match exact guidance")
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027IncidentEnrichmentManifest.v1",
        "incidentId": subject.incident_id,
        "incidentTransitionId": subject.incident_transition_id,
        "incidentRevision": subject.incident_revision,
        "incidentStateResultDigest": subject.incident_state_digest,
        "incidentStateReference": subject.state_reference,
        "incidentStateAttestationReference": subject.attestation_reference,
        "incidentSubjectId": subject.subject_id,
        "incidentSubjectDigest": subject.subject_digest,
        "incidentBoundRequestId": incident_bound_request.request_id,
        "incidentBoundRequestDigest": incident_bound_request.binding_digest,
        "correlationReportAsset": correlation_report_asset,
        "guidanceAsset": guidance_asset,
        "guidanceSourceBinding": guidance.source_binding,
        "noAutoRemediation": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return IncidentEnrichmentManifest.model_validate(
        {
            **payload,
            "enrichmentId": (f"incident-enrichment-{digest.removeprefix('sha256:')[:32]}"),
            "manifestDigest": digest,
        }
    )


def validate_published_correlation_report_assets(
    reference: PublishedCorrelationReportAssetReference,
    report: CorrelationReport,
    attestation: PublishedCorrelationReportAttestation,
    incident_bound_request: IncidentBoundCorrelationRequest,
    *,
    expected_authority_proof_digest: Sha256Digest,
    trusted_report_key_id: str,
    report_signature_verifier: Callable[[bytes, str], bool],
) -> None:
    reference = PublishedCorrelationReportAssetReference.model_validate_json(
        reference.model_dump_json(by_alias=True)
    )
    report = CorrelationReport.model_validate_json(report.model_dump_json(by_alias=True))
    attestation = PublishedCorrelationReportAttestation.model_validate_json(
        attestation.model_dump_json(by_alias=True)
    )
    incident_bound_request = IncidentBoundCorrelationRequest.model_validate_json(
        incident_bound_request.model_dump_json(by_alias=True)
    )
    report_bytes = report.canonical_bytes()
    if len(report_bytes) > MAX_PUBLISHED_CORRELATION_REPORT_BYTES:
        raise ValueError("published correlation report exceeds its canonical byte budget")
    expected_statement = build_published_correlation_report_statement(
        incident_bound_request,
        report,
        authority_proof_digest=expected_authority_proof_digest,
    )
    statement = attestation.statement
    if (
        statement != expected_statement
        or reference.incident_id != statement.incident_id
        or reference.incident_transition_id != statement.incident_transition_id
        or reference.incident_revision != statement.incident_revision
        or reference.incident_state_result_digest != statement.incident_state_result_digest
        or reference.incident_subject_id != statement.incident_subject_id
        or reference.incident_subject_digest != statement.incident_subject_digest
        or reference.incident_bound_request_id != statement.incident_bound_request_id
        or reference.incident_bound_request_digest != statement.incident_bound_request_digest
        or reference.correlation_request_digest != statement.correlation_request_digest
        or reference.correlation_transition_digest != statement.correlation_transition_digest
        or reference.report_id != report.report_id
        or reference.report_digest != report.report_digest
        or reference.report_content_digest != statement.report_content_digest
        or reference.authority_proof_digest != statement.authority_proof_digest
        or reference.publication_statement_id != statement.statement_id
        or reference.publication_statement_digest != statement.statement_digest
        or reference.report_reference.content_digest != sha256_hex(report_bytes)
        or attestation.key_vault_key_id != trusted_report_key_id
        or report_signature_verifier(
            statement.canonical_bytes(),
            attestation.detached_signature,
        )
        is not True
        or reference.attestation_reference.content_digest
        != sha256_hex(attestation.canonical_bytes())
    ):
        raise ValueError("published correlation report assets do not match exact content")


def validate_incident_enrichment_manifest_binding(
    manifest: IncidentEnrichmentManifest,
    incident_bound_request: IncidentBoundCorrelationRequest,
    report: CorrelationReport,
    guidance: IncidentGuidance,
) -> None:
    manifest = IncidentEnrichmentManifest.model_validate_json(
        manifest.model_dump_json(by_alias=True)
    )
    incident_bound_request = IncidentBoundCorrelationRequest.model_validate_json(
        incident_bound_request.model_dump_json(by_alias=True)
    )
    report = CorrelationReport.model_validate_json(report.model_dump_json(by_alias=True))
    guidance = IncidentGuidance.model_validate_json(guidance.model_dump_json(by_alias=True))
    validate_runtime_correlation_report(
        report,
        incident_bound_request.correlation_request,
        evaluated_at=guidance.generated_at,
    )
    if len(report.canonical_bytes()) > MAX_PUBLISHED_CORRELATION_REPORT_BYTES:
        raise ValueError("published correlation report exceeds its canonical byte budget")
    subject = incident_bound_request.incident_subject
    report_asset = manifest.correlation_report_asset
    guidance_asset = manifest.guidance_asset
    context = incident_bound_request.correlation_request.context_binding
    if not isinstance(context, PublishedRuntimeContextBinding):
        raise ValueError("incident enrichment requires published runtime context")
    statement = build_published_correlation_report_statement(
        incident_bound_request,
        report,
        authority_proof_digest=(
            context.publication_authority_reference.content_digest
        ),
    )
    if (
        manifest.incident_id != subject.incident_id
        or manifest.incident_transition_id != subject.incident_transition_id
        or manifest.incident_revision != subject.incident_revision
        or manifest.incident_state_result_digest != subject.incident_state_digest
        or manifest.incident_state_reference != subject.state_reference
        or manifest.incident_state_attestation_reference != subject.attestation_reference
        or manifest.incident_subject_id != subject.subject_id
        or manifest.incident_subject_digest != subject.subject_digest
        or manifest.incident_bound_request_id != incident_bound_request.request_id
        or manifest.incident_bound_request_digest != incident_bound_request.binding_digest
        or report_asset.report_id != report.report_id
        or report_asset.report_digest != report.report_digest
        or report_asset.report_content_digest != sha256_hex(report.canonical_bytes())
        or report_asset.correlation_request_digest != report.request_digest
        or report_asset.correlation_transition_digest != report.transition_digest
        or report_asset.authority_proof_digest
        != context.publication_authority_reference.content_digest
        or report_asset.publication_statement_id != statement.statement_id
        or report_asset.publication_statement_digest
        != statement.statement_digest
        or guidance_asset.guidance_id != guidance.guidance_id
        or guidance_asset.guidance_digest != guidance.guidance_digest
        or guidance_asset.guidance_reference.content_digest
        != sha256_hex(guidance.canonical_bytes())
        or manifest.guidance_source_binding != guidance.source_binding
    ):
        raise ValueError("incident enrichment manifest does not match exact assets")


def validate_incident_enrichment_assets(
    reference: IncidentEnrichmentAssetReference,
    manifest: IncidentEnrichmentManifest,
    attestation: IncidentEnrichmentAttestation,
    *,
    trusted_enrichment_key_id: str,
    enrichment_signature_verifier: Callable[[bytes, str], bool],
) -> None:
    reference = IncidentEnrichmentAssetReference.model_validate_json(
        reference.model_dump_json(by_alias=True)
    )
    manifest = IncidentEnrichmentManifest.model_validate_json(
        manifest.model_dump_json(by_alias=True)
    )
    attestation = IncidentEnrichmentAttestation.model_validate_json(
        attestation.model_dump_json(by_alias=True)
    )
    manifest_bytes = manifest.canonical_bytes()
    if (
        reference.incident_id != manifest.incident_id
        or reference.incident_state_result_digest != manifest.incident_state_result_digest
        or reference.enrichment_id != manifest.enrichment_id
        or reference.manifest_digest != manifest.manifest_digest
        or reference.manifest_reference.content_digest != sha256_hex(manifest_bytes)
        or attestation.enrichment_id != manifest.enrichment_id
        or attestation.manifest_digest != manifest.manifest_digest
        or attestation.key_vault_key_id != trusted_enrichment_key_id
        or attestation.signed_preimage_digest != sha256_hex(manifest_bytes)
        or enrichment_signature_verifier(
            manifest_bytes,
            attestation.detached_signature,
        )
        is not True
        or reference.attestation_reference.content_digest
        != sha256_hex(attestation.canonical_bytes())
    ):
        raise ValueError("incident enrichment assets do not match exact content")


__all__ = [
    "MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES",
    "MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES",
    "MAX_INCIDENT_ENRICHMENT_REFERENCE_BYTES",
    "MAX_PUBLISHED_CORRELATION_REPORT_BYTES",
    "MAX_PUBLISHED_CORRELATION_REPORT_STATEMENT_BYTES",
    "IncidentEnrichmentAssetReference",
    "IncidentEnrichmentAttestation",
    "IncidentEnrichmentManifest",
    "PublishedCorrelationReportAssetReference",
    "PublishedCorrelationReportAttestation",
    "PublishedCorrelationReportStatement",
    "build_incident_enrichment_manifest",
    "build_published_correlation_report_statement",
    "validate_incident_enrichment_assets",
    "validate_incident_enrichment_manifest_binding",
    "validate_published_correlation_report_assets",
]
