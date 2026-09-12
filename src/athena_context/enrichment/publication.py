from __future__ import annotations

import base64
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel

from athena_context.artifacts import (
    ArtifactMetadataHashes,
    ArtifactReadRequest,
    ArtifactWriteRequest,
    VersionPinnedArtifactReaderPort,
)
from athena_context.contracts import (
    MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
    MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES,
    MAX_INCIDENT_GUIDANCE_BYTES,
    MAX_PUBLISHED_CORRELATION_REPORT_BYTES,
    CorrelationReport,
    IncidentBoundCorrelationRequest,
    IncidentEnrichmentAssetReference,
    IncidentEnrichmentAttestation,
    IncidentEnrichmentManifest,
    IncidentFeedAttestation,
    IncidentFeedPointer,
    IncidentGuidance,
    IncidentGuidanceAssetReference,
    IncidentGuidanceAttestation,
    IncidentOccurrenceReceipt,
    IncidentState,
    IncidentStateAttestation,
    NoRunbookGuidanceSelection,
    PublishedCorrelationReportAssetReference,
    PublishedCorrelationReportAttestation,
    PublishedGuidanceAuthorityBinding,
    PublishedRuntimeContextBinding,
    VersionPinnedBlobReference,
    build_incident_enrichment_manifest,
    build_incident_occurrence_receipt,
    build_published_correlation_report_statement,
    canonicalize_json,
    compute_artifact_digest,
    incident_pointer_signature_preimage,
    incident_state_signature_preimage,
    sha256_hex,
    validate_incident_enrichment_assets,
    validate_incident_enrichment_manifest_binding,
    validate_incident_guidance_assets,
    validate_incident_guidance_binding,
    validate_published_correlation_report_assets,
)
from athena_context.correlation import (
    CorrelationService,
    VerifiedCorrelationReport,
)
from athena_context.guidance import build_incident_guidance
from athena_context.presentation import PresentationSigner
from athena_context.presentation_assets import (
    ActiveIncidentIndexSnapshot,
    CurrentIncidentStateSnapshot,
    IncidentPublicationReceipt,
)

SignatureVerifier = Callable[[bytes, str], bool]


class IncidentEnrichmentArtifactWriterPort(Protocol):
    def create_or_recover(
        self,
        request: ArtifactWriteRequest,
    ) -> VersionPinnedBlobReference: ...


class IncidentPublicationReaderPort(Protocol):
    def read_active_incident_index(
        self,
    ) -> ActiveIncidentIndexSnapshot | None: ...

    def read_current_incident_state(
        self,
        *,
        incident_id: str,
    ) -> CurrentIncidentStateSnapshot | None: ...


@dataclass(frozen=True, slots=True)
class IncidentEnrichmentPublicationReceipt:
    occurrence: IncidentOccurrenceReceipt
    correlation_report_asset: PublishedCorrelationReportAssetReference
    guidance_asset: IncidentGuidanceAssetReference
    enrichment_asset: IncidentEnrichmentAssetReference

    def __post_init__(self) -> None:
        if (
            self.correlation_report_asset.incident_id != self.occurrence.incident_id
            or self.guidance_asset.incident_id != self.occurrence.incident_id
            or self.enrichment_asset.incident_id != self.occurrence.incident_id
            or self.correlation_report_asset.incident_state_result_digest
            != self.occurrence.state_result_digest
            or self.guidance_asset.incident_state_digest != self.occurrence.state_result_digest
            or self.enrichment_asset.incident_state_result_digest
            != self.occurrence.state_result_digest
        ):
            raise ValueError("incident enrichment receipt does not bind one occurrence")


@dataclass(frozen=True, slots=True)
class IncidentEnrichmentPublicationService:
    correlation_service: CorrelationService
    incident_reader: VersionPinnedArtifactReaderPort
    incident_publication_reader: IncidentPublicationReaderPort
    guidance_authority_reader: VersionPinnedArtifactReaderPort
    artifact_writer: IncidentEnrichmentArtifactWriterPort
    incident_key_id: str
    incident_key_fingerprint: str
    incident_signature_verifier: SignatureVerifier
    correlation_binding_key_id: str
    correlation_binding_signature_verifier: SignatureVerifier
    guidance_binding_key_id: str
    guidance_binding_signature_verifier: SignatureVerifier
    report_key_id: str
    report_signer: PresentationSigner
    report_signature_verifier: SignatureVerifier
    guidance_key_id: str
    guidance_signer: PresentationSigner
    guidance_signature_verifier: SignatureVerifier
    enrichment_key_id: str
    enrichment_signer: PresentationSigner
    enrichment_signature_verifier: SignatureVerifier

    def __post_init__(self) -> None:
        if type(self.correlation_service) is not CorrelationService:
            raise TypeError("incident enrichment requires the exact CorrelationService instance")
        key_ids = (
            self.incident_key_id,
            self.correlation_binding_key_id,
            self.guidance_binding_key_id,
            self.report_key_id,
            self.guidance_key_id,
            self.enrichment_key_id,
        )
        if any(type(value) is not str or not value for value in key_ids):
            raise ValueError("incident enrichment key IDs must be non-empty strings")
        if (
            len(
                {
                    self.report_key_id,
                    self.guidance_key_id,
                    self.enrichment_key_id,
                }
            )
            != 3
        ):
            raise ValueError("report, guidance, and enrichment signing keys must be distinct")
        if (
            type(self.incident_key_fingerprint) is not str
            or re.fullmatch(
                r"sha256:[a-f0-9]{64}",
                self.incident_key_fingerprint,
            )
            is None
        ):
            raise ValueError("incident key fingerprint is invalid")

    def publish(
        self,
        *,
        incident_publication: IncidentPublicationReceipt,
        verified_report: VerifiedCorrelationReport,
        guidance_binding: PublishedGuidanceAuthorityBinding,
    ) -> IncidentEnrichmentPublicationReceipt:
        if type(incident_publication) is not IncidentPublicationReceipt:
            raise TypeError("incident_publication must be an exact IncidentPublicationReceipt")
        if type(verified_report) is not VerifiedCorrelationReport:
            raise TypeError("verified_report must be an exact VerifiedCorrelationReport")
        if type(guidance_binding) is not PublishedGuidanceAuthorityBinding:
            raise TypeError("guidance_binding must be an exact PublishedGuidanceAuthorityBinding")
        guidance_binding = PublishedGuidanceAuthorityBinding.model_validate_json(
            guidance_binding.model_dump_json(by_alias=True)
        )
        occurrence = incident_publication.occurrence
        if occurrence is None:
            raise ValueError("incident enrichment requires a coherent occurrence receipt")
        occurrence = IncidentOccurrenceReceipt.model_validate_json(
            occurrence.model_dump_json(by_alias=True)
        )
        (
            state,
            state_attestation,
            pointer,
            pointer_attestation,
        ) = self._verify_occurrence(incident_publication, occurrence)
        self._verify_current_publication(
            incident_publication,
            occurrence=occurrence,
            state=state,
        )
        request = guidance_binding.incident_bound_request
        self._verify_incident_request(
            request,
            occurrence=occurrence,
            state=state,
            state_attestation=state_attestation,
        )
        report = self.correlation_service.validate_result(verified_report)
        context = request.correlation_request.context_binding
        if not isinstance(context, PublishedRuntimeContextBinding):
            raise ValueError("incident enrichment requires published runtime context")
        authority_proof_digest = context.publication_authority_reference.content_digest
        if (
            verified_report.authority_proof_digest != authority_proof_digest
            or report != guidance_binding.correlation_report
        ):
            raise ValueError("verified report does not match the guidance authority binding")
        authority_bytes = self._read_exact(
            self.guidance_authority_reader,
            guidance_binding.guidance_authority_reference,
        )
        if authority_bytes != guidance_binding.guidance_authority.canonical_bytes():
            raise ValueError("guidance authority does not match its immutable version")
        self._verify_guidance_binding_signature(guidance_binding)
        if not isinstance(
            guidance_binding.selection,
            NoRunbookGuidanceSelection,
        ):
            raise ValueError(
                "selected-runbook publication requires verified immutable runbook bytes"
            )
        guidance = build_incident_guidance(guidance_binding)
        guidance_bytes = guidance.canonical_bytes()
        if IncidentGuidance.model_validate_json(guidance_bytes).canonical_bytes() != guidance_bytes:
            raise ValueError("generated incident guidance is not canonical")
        validate_incident_guidance_binding(
            guidance,
            guidance_binding,
            trusted_binding_key_id=self.guidance_binding_key_id,
            binding_signature_verifier=(self.guidance_binding_signature_verifier),
        )

        report_attestation = self._build_report_attestation(
            request,
            report,
            authority_proof_digest=authority_proof_digest,
        )
        guidance_attestation = self._build_guidance_attestation(guidance)
        preflight_report_asset = self._build_report_reference(
            request,
            report,
            report_attestation,
            authority_proof_digest=authority_proof_digest,
            report_version="preflight",
            attestation_version="preflight",
        )
        preflight_guidance_asset = self._build_guidance_reference(
            guidance,
            guidance_attestation,
            guidance_version="preflight",
            attestation_version="preflight",
        )
        validate_published_correlation_report_assets(
            preflight_report_asset,
            report,
            report_attestation,
            request,
            expected_authority_proof_digest=authority_proof_digest,
            trusted_report_key_id=self.report_key_id,
            report_signature_verifier=self.report_signature_verifier,
        )
        validate_incident_guidance_assets(
            preflight_guidance_asset,
            guidance,
            guidance_attestation,
            trusted_guidance_key_id=self.guidance_key_id,
            guidance_signature_verifier=self.guidance_signature_verifier,
        )
        preflight_manifest = build_incident_enrichment_manifest(
            request,
            preflight_report_asset,
            report,
            preflight_guidance_asset,
            guidance,
        )
        preflight_attestation = self._build_enrichment_attestation(preflight_manifest)
        validate_incident_enrichment_manifest_binding(
            preflight_manifest,
            request,
            report,
            guidance,
        )
        validate_incident_enrichment_assets(
            self._build_enrichment_reference(
                preflight_manifest,
                preflight_attestation,
                manifest_version="preflight",
                attestation_version="preflight",
            ),
            preflight_manifest,
            preflight_attestation,
            trusted_enrichment_key_id=self.enrichment_key_id,
            enrichment_signature_verifier=(self.enrichment_signature_verifier),
        )

        report_reference = self._write_asset(
            _artifact_request(
                _report_path(request, report),
                report.canonical_bytes(),
                maximum_bytes=MAX_PUBLISHED_CORRELATION_REPORT_BYTES,
            )
        )
        report_attestation_reference = self._write_asset(
            _artifact_request(
                _report_attestation_path(request, report),
                report_attestation.canonical_bytes(),
                maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
            )
        )
        report_asset = self._build_report_reference(
            request,
            report,
            report_attestation,
            authority_proof_digest=authority_proof_digest,
            report_version=report_reference.version,
            attestation_version=report_attestation_reference.version,
        )
        validate_published_correlation_report_assets(
            report_asset,
            report,
            report_attestation,
            request,
            expected_authority_proof_digest=authority_proof_digest,
            trusted_report_key_id=self.report_key_id,
            report_signature_verifier=self.report_signature_verifier,
        )

        guidance_reference = self._write_asset(
            _artifact_request(
                _guidance_path(guidance),
                guidance_bytes,
                maximum_bytes=MAX_INCIDENT_GUIDANCE_BYTES,
            )
        )
        guidance_attestation_reference = self._write_asset(
            _artifact_request(
                _guidance_attestation_path(guidance),
                guidance_attestation.canonical_bytes(),
                maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
            )
        )
        guidance_asset = self._build_guidance_reference(
            guidance,
            guidance_attestation,
            guidance_version=guidance_reference.version,
            attestation_version=guidance_attestation_reference.version,
        )
        validate_incident_guidance_assets(
            guidance_asset,
            guidance,
            guidance_attestation,
            trusted_guidance_key_id=self.guidance_key_id,
            guidance_signature_verifier=self.guidance_signature_verifier,
        )

        manifest = build_incident_enrichment_manifest(
            request,
            report_asset,
            report,
            guidance_asset,
            guidance,
        )
        validate_incident_enrichment_manifest_binding(
            manifest,
            request,
            report,
            guidance,
        )
        enrichment_attestation = self._build_enrichment_attestation(manifest)
        manifest_reference = self._write_asset(
            _artifact_request(
                _manifest_path(manifest),
                manifest.canonical_bytes(),
                maximum_bytes=MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES,
            )
        )
        enrichment_attestation_reference = self._write_asset(
            _artifact_request(
                _enrichment_attestation_path(manifest),
                enrichment_attestation.canonical_bytes(),
                maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
            )
        )
        enrichment_asset = self._build_enrichment_reference(
            manifest,
            enrichment_attestation,
            manifest_version=manifest_reference.version,
            attestation_version=enrichment_attestation_reference.version,
        )
        validate_incident_enrichment_assets(
            enrichment_asset,
            manifest,
            enrichment_attestation,
            trusted_enrichment_key_id=self.enrichment_key_id,
            enrichment_signature_verifier=(self.enrichment_signature_verifier),
        )
        return IncidentEnrichmentPublicationReceipt(
            occurrence=occurrence,
            correlation_report_asset=report_asset,
            guidance_asset=guidance_asset,
            enrichment_asset=enrichment_asset,
        )

    def _verify_occurrence(
        self,
        publication: IncidentPublicationReceipt,
        occurrence: IncidentOccurrenceReceipt,
    ) -> tuple[
        IncidentState,
        IncidentStateAttestation,
        IncidentFeedPointer,
        IncidentFeedAttestation,
    ]:
        state_bytes = self._read_exact(
            self.incident_reader,
            occurrence.state_reference,
        )
        state_attestation_bytes = self._read_exact(
            self.incident_reader,
            occurrence.state_attestation_reference,
        )
        pointer_bytes = self._read_exact(
            self.incident_reader,
            occurrence.pointer_reference,
        )
        pointer_attestation_bytes = self._read_exact(
            self.incident_reader,
            occurrence.pointer_attestation_reference,
        )
        state = IncidentState.model_validate_json(state_bytes)
        state_attestation = IncidentStateAttestation.model_validate_json(state_attestation_bytes)
        pointer = IncidentFeedPointer.model_validate_json(pointer_bytes)
        pointer_attestation = IncidentFeedAttestation.model_validate_json(pointer_attestation_bytes)
        rebuilt = build_incident_occurrence_receipt(
            state,
            state_attestation,
            pointer,
            pointer_attestation,
            state_reference=occurrence.state_reference,
            state_attestation_reference=(occurrence.state_attestation_reference),
            pointer_reference=occurrence.pointer_reference,
            pointer_attestation_reference=(occurrence.pointer_attestation_reference),
        )
        state_preimage = incident_state_signature_preimage(state)
        pointer_preimage = incident_pointer_signature_preimage(pointer)
        if (
            rebuilt != occurrence
            or publication.incident_id != occurrence.incident_id
            or publication.pointer_sha256 != occurrence.pointer_reference.content_digest
            or state_bytes != state.canonical_bytes()
            or state_attestation_bytes != state_attestation.canonical_bytes()
            or pointer_bytes != pointer.canonical_bytes()
            or pointer_attestation_bytes != pointer_attestation.canonical_bytes()
            or state_attestation.key_vault_key_id != self.incident_key_id
            or pointer.key_id != self.incident_key_id
            or pointer.key_fingerprint != self.incident_key_fingerprint
            or pointer_attestation.key_vault_key_id != self.incident_key_id
            or self.incident_signature_verifier(
                state_preimage,
                state_attestation.detached_signature,
            )
            is not True
            or self.incident_signature_verifier(
                pointer_preimage,
                pointer_attestation.detached_signature,
            )
            is not True
        ):
            raise ValueError("incident occurrence is not a trusted coherent publication")
        return state, state_attestation, pointer, pointer_attestation

    def _verify_current_publication(
        self,
        publication: IncidentPublicationReceipt,
        *,
        occurrence: IncidentOccurrenceReceipt,
        state: IncidentState,
    ) -> None:
        current = self.incident_publication_reader.read_current_incident_state(
            incident_id=occurrence.incident_id
        )
        active_index = self.incident_publication_reader.read_active_incident_index()
        if (
            current is None
            or current.occurrence is None
            or active_index is None
            or current.state != state
            or current.occurrence != occurrence
            or current.pointer_sha256 != publication.pointer_sha256
            or active_index.payload_sha256 != publication.active_index_sha256
        ):
            raise ValueError("incident publication is not current and active-index coherent")
        entry = next(
            (
                item
                for item in active_index.index.incidents
                if item.incident_id == occurrence.incident_id
            ),
            None,
        )
        if state.lifecycle == "active":
            if (
                entry is None
                or entry.lifecycle != "active"
                or entry.scenario != state.scenario
                or entry.workload_role != state.workload_role
                or entry.pointer_path != f"./{occurrence.pointer_reference.name}"
                or entry.pointer_sha256 != publication.pointer_sha256
                or entry.detected_at != state.detected_at
                or entry.updated_at != state.updated_at
            ):
                raise ValueError("active incident publication is not index coherent")
        elif entry is not None:
            raise ValueError("resolved incident publication remains in the active index")

    def _verify_incident_request(
        self,
        request: IncidentBoundCorrelationRequest,
        *,
        occurrence: IncidentOccurrenceReceipt,
        state: IncidentState,
        state_attestation: IncidentStateAttestation,
    ) -> None:
        subject = request.incident_subject
        subject_preimage = subject.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={
                "subject_id",
                "subject_digest",
                "subject_attestation",
            },
        )
        request_preimage = request.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={
                "request_id",
                "binding_digest",
                "binding_attestation",
            },
        )
        if (
            subject.incident_state != state
            or subject.incident_state_attestation != state_attestation
            or subject.state_reference != occurrence.state_reference
            or subject.attestation_reference != occurrence.state_attestation_reference
            or subject.subject_attestation.key_vault_key_id != self.incident_key_id
            or self.incident_signature_verifier(
                canonicalize_json(subject_preimage).encode("utf-8"),
                subject.subject_attestation.detached_signature,
            )
            is not True
            or request.binding_attestation.key_vault_key_id != self.correlation_binding_key_id
            or self.correlation_binding_signature_verifier(
                canonicalize_json(request_preimage).encode("utf-8"),
                request.binding_attestation.detached_signature,
            )
            is not True
        ):
            raise ValueError("incident-bound correlation request is not trusted")

    def _verify_guidance_binding_signature(
        self,
        binding: PublishedGuidanceAuthorityBinding,
    ) -> None:
        preimage = binding.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={
                "binding_id",
                "binding_digest",
                "binding_attestation",
            },
        )
        if (
            binding.binding_attestation.key_vault_key_id != self.guidance_binding_key_id
            or self.guidance_binding_signature_verifier(
                canonicalize_json(preimage).encode("utf-8"),
                binding.binding_attestation.detached_signature,
            )
            is not True
        ):
            raise ValueError("guidance authority binding signature is invalid")

    @staticmethod
    def _read_exact(
        reader: VersionPinnedArtifactReaderPort,
        reference: VersionPinnedBlobReference,
    ) -> bytes:
        result = reader.read(
            ArtifactReadRequest(
                blob_name=reference.name,
                version_id=reference.version,
                expected_payload_sha256=reference.content_digest,
            )
        )
        if (
            result.blob_name != reference.name
            or result.version_id != reference.version
            or result.payload_sha256 != reference.content_digest
            or sha256_hex(result.payload) != reference.content_digest
        ):
            raise ValueError("exact-version reader returned a mismatched artifact")
        return result.payload

    def _write_asset(
        self,
        request: ArtifactWriteRequest,
    ) -> VersionPinnedBlobReference:
        reference = self.artifact_writer.create_or_recover(request)
        if (
            type(reference) is not VersionPinnedBlobReference
            or reference.name != request.blob_name
            or reference.content_digest != request.hashes.payload_sha256
        ):
            raise ValueError("incident enrichment writer returned a mismatched reference")
        return reference

    def _build_report_attestation(
        self,
        request: IncidentBoundCorrelationRequest,
        report: CorrelationReport,
        *,
        authority_proof_digest: str,
    ) -> PublishedCorrelationReportAttestation:
        statement = build_published_correlation_report_statement(
            request,
            report,
            authority_proof_digest=authority_proof_digest,
        )
        statement_bytes = statement.canonical_bytes()
        return PublishedCorrelationReportAttestation(
            schemaVersion=("athena.wc027PublishedCorrelationReportAttestation.v1"),
            statement=statement,
            signatureAlgorithm="RS256",
            keyVaultKeyId=self.report_key_id,
            signedPreimageDigest=sha256_hex(statement_bytes),
            detachedSignature=self._sign_and_verify(
                statement_bytes,
                signer=self.report_signer,
                verifier=self.report_signature_verifier,
                name="correlation report",
            ),
        )

    def _build_guidance_attestation(
        self,
        guidance: IncidentGuidance,
    ) -> IncidentGuidanceAttestation:
        guidance_bytes = guidance.canonical_bytes()
        return IncidentGuidanceAttestation(
            schemaVersion="athena.wc027IncidentGuidanceAttestation.v1",
            guidanceId=guidance.guidance_id,
            guidanceDigest=guidance.guidance_digest,
            signatureAlgorithm="RS256",
            keyVaultKeyId=self.guidance_key_id,
            signedPreimageDigest=sha256_hex(guidance_bytes),
            detachedSignature=self._sign_and_verify(
                guidance_bytes,
                signer=self.guidance_signer,
                verifier=self.guidance_signature_verifier,
                name="incident guidance",
            ),
        )

    def _build_enrichment_attestation(
        self,
        manifest: IncidentEnrichmentManifest,
    ) -> IncidentEnrichmentAttestation:
        manifest_bytes = manifest.canonical_bytes()
        return IncidentEnrichmentAttestation(
            schemaVersion="athena.wc027IncidentEnrichmentAttestation.v1",
            enrichmentId=manifest.enrichment_id,
            manifestDigest=manifest.manifest_digest,
            signatureAlgorithm="RS256",
            keyVaultKeyId=self.enrichment_key_id,
            signedPreimageDigest=sha256_hex(manifest_bytes),
            detachedSignature=self._sign_and_verify(
                manifest_bytes,
                signer=self.enrichment_signer,
                verifier=self.enrichment_signature_verifier,
                name="incident enrichment",
            ),
        )

    @staticmethod
    def _sign_and_verify(
        preimage: bytes,
        *,
        signer: PresentationSigner,
        verifier: SignatureVerifier,
        name: str,
    ) -> str:
        signature = _base64url_signature(signer.sign_preimage(preimage))
        if verifier(preimage, signature) is not True:
            raise ValueError(f"{name} signer failed immediate verification")
        return signature

    @staticmethod
    def _build_report_reference(
        request: IncidentBoundCorrelationRequest,
        report: CorrelationReport,
        attestation: PublishedCorrelationReportAttestation,
        *,
        authority_proof_digest: str,
        report_version: str,
        attestation_version: str,
    ) -> PublishedCorrelationReportAssetReference:
        statement = attestation.statement
        report_bytes = report.canonical_bytes()
        payload: dict[str, object] = {
            "schemaVersion": ("athena.wc027PublishedCorrelationReportAssetReference.v1"),
            "incidentId": statement.incident_id,
            "incidentTransitionId": statement.incident_transition_id,
            "incidentRevision": statement.incident_revision,
            "incidentStateResultDigest": (statement.incident_state_result_digest),
            "incidentSubjectId": statement.incident_subject_id,
            "incidentSubjectDigest": statement.incident_subject_digest,
            "incidentBoundRequestId": statement.incident_bound_request_id,
            "incidentBoundRequestDigest": (statement.incident_bound_request_digest),
            "correlationRequestDigest": statement.correlation_request_digest,
            "correlationTransitionDigest": (statement.correlation_transition_digest),
            "reportId": statement.report_id,
            "reportDigest": statement.report_digest,
            "reportContentDigest": sha256_hex(report_bytes),
            "authorityProofDigest": authority_proof_digest,
            "publicationStatementId": statement.statement_id,
            "publicationStatementDigest": statement.statement_digest,
            "reportReference": VersionPinnedBlobReference(
                name=_report_path(request, report),
                version=report_version,
                contentDigest=sha256_hex(report_bytes),
            ),
            "attestationReference": VersionPinnedBlobReference(
                name=_report_attestation_path(request, report),
                version=attestation_version,
                contentDigest=sha256_hex(attestation.canonical_bytes()),
            ),
        }
        digest = compute_artifact_digest(_json_value(payload))
        return PublishedCorrelationReportAssetReference.model_validate(
            {
                **payload,
                "referenceId": (f"report-asset-{digest.removeprefix('sha256:')[:32]}"),
                "referenceDigest": digest,
            }
        )

    @staticmethod
    def _build_guidance_reference(
        guidance: IncidentGuidance,
        attestation: IncidentGuidanceAttestation,
        *,
        guidance_version: str,
        attestation_version: str,
    ) -> IncidentGuidanceAssetReference:
        payload: dict[str, object] = {
            "schemaVersion": ("athena.wc027IncidentGuidanceAssetReference.v1"),
            "incidentId": guidance.source_binding.incident_id,
            "incidentStateDigest": (guidance.source_binding.incident_state_digest),
            "guidanceId": guidance.guidance_id,
            "guidanceDigest": guidance.guidance_digest,
            "guidanceReference": VersionPinnedBlobReference(
                name=_guidance_path(guidance),
                version=guidance_version,
                contentDigest=sha256_hex(guidance.canonical_bytes()),
            ),
            "attestationReference": VersionPinnedBlobReference(
                name=_guidance_attestation_path(guidance),
                version=attestation_version,
                contentDigest=sha256_hex(attestation.canonical_bytes()),
            ),
        }
        digest = compute_artifact_digest(_json_value(payload))
        return IncidentGuidanceAssetReference.model_validate(
            {
                **payload,
                "referenceId": (f"guidance-asset-{digest.removeprefix('sha256:')[:32]}"),
                "referenceDigest": digest,
            }
        )

    @staticmethod
    def _build_enrichment_reference(
        manifest: IncidentEnrichmentManifest,
        attestation: IncidentEnrichmentAttestation,
        *,
        manifest_version: str,
        attestation_version: str,
    ) -> IncidentEnrichmentAssetReference:
        payload: dict[str, object] = {
            "schemaVersion": ("athena.wc027IncidentEnrichmentAssetReference.v1"),
            "incidentId": manifest.incident_id,
            "incidentStateResultDigest": (manifest.incident_state_result_digest),
            "enrichmentId": manifest.enrichment_id,
            "manifestDigest": manifest.manifest_digest,
            "manifestReference": VersionPinnedBlobReference(
                name=_manifest_path(manifest),
                version=manifest_version,
                contentDigest=sha256_hex(manifest.canonical_bytes()),
            ),
            "attestationReference": VersionPinnedBlobReference(
                name=_enrichment_attestation_path(manifest),
                version=attestation_version,
                contentDigest=sha256_hex(attestation.canonical_bytes()),
            ),
        }
        digest = compute_artifact_digest(_json_value(payload))
        return IncidentEnrichmentAssetReference.model_validate(
            {
                **payload,
                "referenceId": (f"enrichment-asset-{digest.removeprefix('sha256:')[:32]}"),
                "referenceDigest": digest,
            }
        )


def _base64url_signature(value: str) -> str:
    try:
        signature = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("incident enrichment signer returned invalid base64") from exc
    if not signature:
        raise ValueError("incident enrichment signer returned an empty signature")
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


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


def _artifact_request(
    blob_name: str,
    payload: bytes,
    *,
    maximum_bytes: int,
) -> ArtifactWriteRequest:
    return ArtifactWriteRequest(
        blob_name=blob_name,
        payload=payload,
        content_type="application/json",
        hashes=ArtifactMetadataHashes(
            payload_sha256=sha256_hex(payload),
        ),
        maximum_payload_bytes=maximum_bytes,
    )


def _state_prefix(
    request: IncidentBoundCorrelationRequest,
) -> str:
    subject = request.incident_subject
    return (
        f"incidents/{subject.incident_id}/versions/"
        f"{subject.incident_state_digest.removeprefix('sha256:')}"
    )


def _report_path(
    request: IncidentBoundCorrelationRequest,
    report: CorrelationReport,
) -> str:
    return f"{_state_prefix(request)}/correlation-reports/{report.report_id}/report.json"


def _report_attestation_path(
    request: IncidentBoundCorrelationRequest,
    report: CorrelationReport,
) -> str:
    return f"{_state_prefix(request)}/correlation-reports/{report.report_id}/attestation.json"


def _guidance_path(guidance: IncidentGuidance) -> str:
    return (
        f"incidents/{guidance.source_binding.incident_id}/versions/"
        f"{guidance.source_binding.incident_state_digest.removeprefix('sha256:')}/"
        f"guidance/{guidance.guidance_id}/guidance.json"
    )


def _guidance_attestation_path(guidance: IncidentGuidance) -> str:
    return _guidance_path(guidance).removesuffix("/guidance.json") + "/attestation.json"


def _manifest_path(manifest: IncidentEnrichmentManifest) -> str:
    return (
        f"incidents/{manifest.incident_id}/versions/"
        f"{manifest.incident_state_result_digest.removeprefix('sha256:')}/"
        f"enrichments/{manifest.enrichment_id}/manifest.json"
    )


def _enrichment_attestation_path(
    manifest: IncidentEnrichmentManifest,
) -> str:
    return _manifest_path(manifest).removesuffix("/manifest.json") + "/attestation.json"


__all__ = [
    "IncidentEnrichmentArtifactWriterPort",
    "IncidentEnrichmentPublicationReceipt",
    "IncidentEnrichmentPublicationService",
    "IncidentPublicationReaderPort",
]
