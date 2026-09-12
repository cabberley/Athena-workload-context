from __future__ import annotations

from dataclasses import dataclass

import pytest

from athena_context.artifacts import (
    ArtifactAlreadyExistsError,
    ArtifactMetadataHashes,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactWriteRequest,
)
from athena_context.azure_adapters import (
    AzureBlobCreateOnlyArtifactWriter,
    AzureBlobVersionPinnedArtifactReader,
)
from athena_context.contracts import (
    VersionPinnedBlobReference,
    build_incident_occurrence_receipt,
    sha256_hex,
)
from athena_context.correlation import VerifiedCorrelationReport
from athena_context.correlation.verification import _report_receipt
from athena_context.enrichment import (
    AzureBlobIncidentEnrichmentArtifactWriter,
    IncidentEnrichmentPublicationService,
)
from athena_context.eventing import build_incident_publication
from athena_context.presentation_assets import (
    ActiveIncidentIndexSnapshot,
    CurrentIncidentStateSnapshot,
    IncidentPublicationReceipt,
)
from test_wc026_correlation import _test_service
from test_wc026_correlation_contract import _request
from test_wc027_guidance_authority_contract import (
    _authority,
    _binding,
    _option,
    _selected_runbook,
)

_SIGNATURE = "c3ludGhldGlj"
_INCIDENT_KEY_FINGERPRINT = "sha256:" + "2" * 64
_REPORT_KEY_ID = (
    "https://synthetic-wc027.vault.azure.net/keys/"
    "report-publication/0123456789abcdef0123456789abcdef"
)
_GUIDANCE_KEY_ID = (
    "https://synthetic-wc027.vault.azure.net/keys/guidance-signing/0123456789abcdef0123456789abcdef"
)
_ENRICHMENT_KEY_ID = (
    "https://synthetic-wc027.vault.azure.net/keys/"
    "incident-enrichment/0123456789abcdef0123456789abcdef"
)


class _Signer:
    def sign_preimage(self, _canonical_preimage: bytes) -> str:
        return _SIGNATURE


def _verify_signature(_preimage: bytes, signature: str) -> bool:
    return signature == _SIGNATURE


class _Reader:
    def __init__(
        self,
        payloads: dict[tuple[str, str], bytes],
    ) -> None:
        self.payloads = payloads
        self.calls: list[ArtifactReadRequest] = []

    def read(self, request: ArtifactReadRequest) -> ArtifactReadResult:
        self.calls.append(request)
        payload = self.payloads[(request.blob_name, request.version_id)]
        return ArtifactReadResult(
            container_name="incident-assets",
            blob_name=request.blob_name,
            version_id=request.version_id,
            payload=payload,
            size_bytes=len(payload),
            content_type="application/json",
            payload_sha256=request.expected_payload_sha256,
        )


class _Store:
    def __init__(
        self,
        *,
        conflict_first: bool = False,
        mismatch_first: bool = False,
    ) -> None:
        self.values: dict[str, tuple[bytes, str, str]] = {}
        self.calls: list[ArtifactWriteRequest] = []
        self.conflict_first = conflict_first
        self.mismatch_first = mismatch_first

    def create_or_recover(
        self,
        request: ArtifactWriteRequest,
    ) -> VersionPinnedBlobReference:
        self.calls.append(request)
        if self.conflict_first and len(self.calls) == 1:
            raise ArtifactAlreadyExistsError("synthetic conflicting immutable content")
        if self.mismatch_first and len(self.calls) == 1:
            return VersionPinnedBlobReference(
                name=request.blob_name + "-wrong",
                version="synthetic-version-001",
                contentDigest=request.hashes.payload_sha256,
            )
        existing = self.values.get(request.blob_name)
        if existing is not None:
            payload, version, digest = existing
            if payload != request.payload or digest != request.hashes.payload_sha256:
                raise ArtifactAlreadyExistsError("synthetic conflicting immutable content")
            return VersionPinnedBlobReference(
                name=request.blob_name,
                version=version,
                contentDigest=digest,
            )
        version = f"synthetic-version-{len(self.values) + 1:03d}"
        self.values[request.blob_name] = (
            request.payload,
            version,
            request.hashes.payload_sha256,
        )
        return VersionPinnedBlobReference(
            name=request.blob_name,
            version=version,
            contentDigest=request.hashes.payload_sha256,
        )


@dataclass(frozen=True, slots=True)
class _PublicationReader:
    current: CurrentIncidentStateSnapshot
    active_index: ActiveIncidentIndexSnapshot

    def read_current_incident_state(
        self,
        *,
        incident_id: str,
    ) -> CurrentIncidentStateSnapshot | None:
        return self.current if self.current.state.incident_id == incident_id else None

    def read_active_incident_index(
        self,
    ) -> ActiveIncidentIndexSnapshot | None:
        return self.active_index


@dataclass(frozen=True, slots=True)
class _Fixture:
    correlation_service: object
    verified_report: object
    guidance_binding: object
    incident_publication: IncidentPublicationReceipt
    incident_reader: _Reader
    publication_reader: _PublicationReader
    authority_reader: _Reader


def _fixture(*, selected_runbook: bool = False) -> _Fixture:
    if selected_runbook:
        option = _option()
        guidance_binding = _binding(
            authority=_authority(options=(option,)),
            selection=_selected_runbook(option),
        )
        correlation_request = guidance_binding.incident_bound_request.correlation_request
        correlation_service = _test_service(correlation_request)
        authority_proof_digest = (
            correlation_request.context_binding.publication_authority_reference.content_digest
        )
        verified_report = VerifiedCorrelationReport(
            report=guidance_binding.correlation_report,
            authority_proof_digest=authority_proof_digest,
            verification_receipt=_report_receipt(
                guidance_binding.correlation_report,
                authority_proof_digest,
                b"0123456789abcdef0123456789abcdef",
            ),
        )
    else:
        correlation_request = _request()
        correlation_service = _test_service(correlation_request)
        verified_report = correlation_service.correlate(correlation_request)
        guidance_binding = _binding(
            request=correlation_request,
            report=verified_report.report,
        )
    subject = guidance_binding.incident_bound_request.incident_subject
    state = subject.incident_state
    state_attestation = subject.incident_state_attestation
    publication = build_incident_publication(
        state,
        state_attestation,
        published_at=guidance_binding.evaluated_at,
        key_id=state_attestation.key_vault_key_id,
        key_fingerprint=_INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    pointer_reference = VersionPinnedBlobReference(
        name=publication.pointer_asset.blob_name,
        version="synthetic-pointer-version",
        contentDigest=publication.pointer_asset.payload_sha256,
    )
    pointer_attestation_reference = VersionPinnedBlobReference(
        name=publication.pointer_attestation_asset.blob_name,
        version="synthetic-pointer-attestation-version",
        contentDigest=(publication.pointer_attestation_asset.payload_sha256),
    )
    occurrence = build_incident_occurrence_receipt(
        state,
        state_attestation,
        publication.pointer,
        publication.pointer_attestation,
        state_reference=subject.state_reference,
        state_attestation_reference=subject.attestation_reference,
        pointer_reference=pointer_reference,
        pointer_attestation_reference=pointer_attestation_reference,
    )
    incident_publication = IncidentPublicationReceipt(
        incident_id=state.incident_id,
        pointer_sha256=publication.pointer_asset.payload_sha256,
        active_index_sha256=(publication.active_index_asset.payload_sha256),
        occurrence=occurrence,
    )
    incident_reader = _Reader(
        {
            (
                subject.state_reference.name,
                subject.state_reference.version,
            ): state.canonical_bytes(),
            (
                subject.attestation_reference.name,
                subject.attestation_reference.version,
            ): state_attestation.canonical_bytes(),
            (
                pointer_reference.name,
                pointer_reference.version,
            ): publication.pointer.canonical_bytes(),
            (
                pointer_attestation_reference.name,
                pointer_attestation_reference.version,
            ): publication.pointer_attestation.canonical_bytes(),
        }
    )
    publication_reader = _PublicationReader(
        current=CurrentIncidentStateSnapshot(
            state=state,
            pointer=publication.pointer,
            pointer_sha256=publication.pointer_asset.payload_sha256,
            occurrence=occurrence,
        ),
        active_index=ActiveIncidentIndexSnapshot(
            index=publication.active_index,
            payload_sha256=publication.active_index_asset.payload_sha256,
        ),
    )
    authority_reference = guidance_binding.guidance_authority_reference
    authority_reader = _Reader(
        {
            (
                authority_reference.name,
                authority_reference.version,
            ): guidance_binding.guidance_authority.canonical_bytes(),
        }
    )
    return _Fixture(
        correlation_service=correlation_service,
        verified_report=verified_report,
        guidance_binding=guidance_binding,
        incident_publication=incident_publication,
        incident_reader=incident_reader,
        publication_reader=publication_reader,
        authority_reader=authority_reader,
    )


def _publication_service(
    fixture: _Fixture,
    store: _Store,
    *,
    incident_verifier=_verify_signature,
    report_verifier=_verify_signature,
) -> IncidentEnrichmentPublicationService:
    binding = fixture.guidance_binding
    request = binding.incident_bound_request
    return IncidentEnrichmentPublicationService(
        correlation_service=fixture.correlation_service,
        incident_reader=fixture.incident_reader,
        incident_publication_reader=fixture.publication_reader,
        guidance_authority_reader=fixture.authority_reader,
        artifact_writer=store,
        incident_key_id=(request.incident_subject.incident_state_attestation.key_vault_key_id),
        incident_key_fingerprint=_INCIDENT_KEY_FINGERPRINT,
        incident_signature_verifier=incident_verifier,
        correlation_binding_key_id=(request.binding_attestation.key_vault_key_id),
        correlation_binding_signature_verifier=_verify_signature,
        guidance_binding_key_id=(binding.binding_attestation.key_vault_key_id),
        guidance_binding_signature_verifier=_verify_signature,
        report_key_id=_REPORT_KEY_ID,
        report_signer=_Signer(),
        report_signature_verifier=report_verifier,
        guidance_key_id=_GUIDANCE_KEY_ID,
        guidance_signer=_Signer(),
        guidance_signature_verifier=_verify_signature,
        enrichment_key_id=_ENRICHMENT_KEY_ID,
        enrichment_signer=_Signer(),
        enrichment_signature_verifier=_verify_signature,
    )


def _publish(
    fixture: _Fixture,
    store: _Store,
    **service_overrides,
):
    service = _publication_service(
        fixture,
        store,
        **service_overrides,
    )
    return service.publish(
        incident_publication=fixture.incident_publication,
        verified_report=fixture.verified_report,
        guidance_binding=fixture.guidance_binding,
    )


def test_publication_writes_six_assets_and_commits_with_final_attestation() -> None:
    fixture = _fixture()
    store = _Store()

    receipt = _publish(fixture, store)

    names = [request.blob_name for request in store.calls]
    assert len(names) == 6
    assert names[0].endswith("/report.json")
    assert names[1].endswith(
        "/correlation-reports/" + names[0].split("/")[-2] + "/attestation.json"
    )
    assert names[2].endswith("/guidance.json")
    assert names[3].endswith("/guidance/" + names[2].split("/")[-2] + "/attestation.json")
    assert names[4].endswith("/manifest.json")
    assert names[5] == names[4].removesuffix("/manifest.json") + "/attestation.json"
    assert receipt.enrichment_asset.attestation_reference.name == names[-1]
    assert receipt.occurrence == fixture.incident_publication.occurrence


def test_publication_retry_recovers_same_versions_and_receipt() -> None:
    fixture = _fixture()
    store = _Store()

    first = _publish(fixture, store)
    second = _publish(fixture, store)

    assert second == first
    assert len(store.values) == 6
    assert len(store.calls) == 12


def test_untrusted_occurrence_fails_before_any_write() -> None:
    fixture = _fixture()
    store = _Store()

    with pytest.raises(ValueError, match="trusted coherent publication"):
        _publish(
            fixture,
            store,
            incident_verifier=lambda _preimage, _signature: False,
        )

    assert store.calls == []


def test_forged_receipt_cannot_claim_active_index_coherence() -> None:
    fixture = _fixture()
    store = _Store()
    forged = IncidentPublicationReceipt(
        incident_id=fixture.incident_publication.incident_id,
        pointer_sha256=fixture.incident_publication.pointer_sha256,
        active_index_sha256="sha256:" + "f" * 64,
        occurrence=fixture.incident_publication.occurrence,
    )
    service = _publication_service(fixture, store)

    with pytest.raises(ValueError, match="active-index coherent"):
        service.publish(
            incident_publication=forged,
            verified_report=fixture.verified_report,
            guidance_binding=fixture.guidance_binding,
        )

    assert store.calls == []


def test_source_byte_substitution_fails_before_any_write() -> None:
    fixture = _fixture()
    store = _Store()
    state_reference = (
        fixture.guidance_binding.incident_bound_request.incident_subject.state_reference
    )
    fixture.incident_reader.payloads[(state_reference.name, state_reference.version)] = b"{}\n"

    with pytest.raises(ValueError, match="exact-version reader"):
        _publish(fixture, store)

    assert store.calls == []


def test_selected_runbook_fails_before_any_write() -> None:
    fixture = _fixture(selected_runbook=True)
    store = _Store()

    with pytest.raises(
        ValueError,
        match="selected-runbook publication",
    ):
        _publish(fixture, store)

    assert store.calls == []


def test_generated_signature_must_self_verify_before_any_write() -> None:
    fixture = _fixture()
    store = _Store()

    with pytest.raises(ValueError, match="failed immediate verification"):
        _publish(
            fixture,
            store,
            report_verifier=lambda _preimage, _signature: False,
        )

    assert store.calls == []


def test_conflicting_immutable_bytes_fail_closed() -> None:
    fixture = _fixture()
    store = _Store(conflict_first=True)

    with pytest.raises(ArtifactAlreadyExistsError):
        _publish(fixture, store)

    assert len(store.calls) == 1


def test_writer_reference_mismatch_fails_closed() -> None:
    fixture = _fixture()
    store = _Store(mismatch_first=True)

    with pytest.raises(ValueError, match="mismatched reference"):
        _publish(fixture, store)

    assert len(store.calls) == 1


def test_azure_store_recovers_exact_current_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = object.__new__(AzureBlobCreateOnlyArtifactWriter)
    reader = object.__new__(AzureBlobVersionPinnedArtifactReader)
    adapter = object.__new__(AzureBlobIncidentEnrichmentArtifactWriter)
    adapter._writer = writer
    adapter._reader = reader
    payload = b'{"synthetic":true}\n'
    digest = sha256_hex(payload)
    request = ArtifactWriteRequest(
        blob_name=(
            "incidents/inc-0123456789ab/versions/"
            + "1" * 64
            + "/correlation-reports/report-"
            + "2" * 32
            + "/report.json"
        ),
        payload=payload,
        content_type="application/json",
        hashes=ArtifactMetadataHashes(payload_sha256=digest),
    )
    current = ArtifactReadResult(
        container_name="incident-assets",
        blob_name=request.blob_name,
        version_id="synthetic-recovered-version",
        payload=payload,
        size_bytes=len(payload),
        content_type="application/json",
        payload_sha256=digest,
    )
    monkeypatch.setattr(
        AzureBlobCreateOnlyArtifactWriter,
        "create",
        lambda _self, _request: (_ for _ in ()).throw(
            ArtifactAlreadyExistsError("synthetic duplicate")
        ),
    )
    monkeypatch.setattr(
        AzureBlobVersionPinnedArtifactReader,
        "read_current",
        lambda _self, _request: current,
    )
    monkeypatch.setattr(
        AzureBlobVersionPinnedArtifactReader,
        "read",
        lambda _self, _request: current,
    )

    reference = adapter.create_or_recover(request)

    assert reference == VersionPinnedBlobReference(
        name=request.blob_name,
        version=current.version_id,
        contentDigest=digest,
    )


def test_azure_store_rejects_paths_outside_enrichment_boundary() -> None:
    adapter = object.__new__(AzureBlobIncidentEnrichmentArtifactWriter)
    adapter._writer = object.__new__(AzureBlobCreateOnlyArtifactWriter)
    adapter._reader = object.__new__(AzureBlobVersionPinnedArtifactReader)
    payload = b"{}\n"
    request = ArtifactWriteRequest(
        blob_name="incidents/active.json",
        payload=payload,
        content_type="application/json",
        hashes=ArtifactMetadataHashes(
            payload_sha256=sha256_hex(payload),
        ),
    )

    with pytest.raises(ValueError, match="outside"):
        adapter.create_or_recover(request)
