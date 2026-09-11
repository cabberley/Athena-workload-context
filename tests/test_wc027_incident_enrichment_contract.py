from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from athena_context.contracts import (
    MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES,
    MAX_PUBLISHED_CORRELATION_REPORT_BYTES,
    IncidentEnrichmentAssetReference,
    IncidentEnrichmentAttestation,
    IncidentEnrichmentManifest,
    IncidentGuidanceAssetReference,
    IncidentGuidanceAttestation,
    PublishedCorrelationReportAssetReference,
    PublishedCorrelationReportAttestation,
    VersionPinnedBlobReference,
    build_incident_enrichment_manifest,
    build_published_correlation_report_statement,
    compute_artifact_digest,
    sha256_hex,
    validate_incident_enrichment_assets,
    validate_incident_enrichment_manifest_binding,
    validate_incident_guidance_assets,
    validate_published_correlation_report_assets,
)
from athena_context.guidance import build_incident_guidance
from test_wc026_correlation import _verified, correlate_incident
from test_wc026_correlation_contract import (
    WEB_ID,
    _bound_observation,
    _bundle,
    _dependency_path,
    _hypothesis,
    _report_for,
    _request,
)
from test_wc027_guidance_authority_contract import _binding

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


def _verify_signature(_: bytes, signature: str) -> bool:
    return signature == _SIGNATURE


def _report_assets(binding):
    bound_request = binding.incident_bound_request
    report = binding.correlation_report
    context = bound_request.correlation_request.context_binding
    authority_proof_digest = context.publication_authority_reference.content_digest
    statement = build_published_correlation_report_statement(
        bound_request,
        report,
        authority_proof_digest=authority_proof_digest,
    )
    attestation = PublishedCorrelationReportAttestation(
        schemaVersion=("athena.wc027PublishedCorrelationReportAttestation.v1"),
        statement=statement,
        signatureAlgorithm="RS256",
        keyVaultKeyId=_REPORT_KEY_ID,
        signedPreimageDigest=sha256_hex(statement.canonical_bytes()),
        detachedSignature=_SIGNATURE,
    )
    state_suffix = statement.incident_state_result_digest.removeprefix("sha256:")
    prefix = (
        f"incidents/{statement.incident_id}/versions/{state_suffix}/"
        f"correlation-reports/{report.report_id}"
    )
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
        "reportId": report.report_id,
        "reportDigest": report.report_digest,
        "reportContentDigest": sha256_hex(report.canonical_bytes()),
        "authorityProofDigest": authority_proof_digest,
        "publicationStatementId": statement.statement_id,
        "publicationStatementDigest": statement.statement_digest,
        "reportReference": VersionPinnedBlobReference(
            name=f"{prefix}/report.json",
            version="2026-09-11T16:00:00.0000000Z",
            contentDigest=sha256_hex(report.canonical_bytes()),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{prefix}/attestation.json",
            version="2026-09-11T16:00:01.0000000Z",
            contentDigest=sha256_hex(attestation.canonical_bytes()),
        ),
    }
    digest = compute_artifact_digest(_json_value(payload))
    reference = PublishedCorrelationReportAssetReference(
        **payload,
        referenceId=f"report-asset-{digest.removeprefix('sha256:')[:32]}",
        referenceDigest=digest,
    )
    return reference, report, attestation, authority_proof_digest


def _guidance_assets(binding):
    guidance = build_incident_guidance(binding)
    attestation = IncidentGuidanceAttestation(
        schemaVersion="athena.wc027IncidentGuidanceAttestation.v1",
        guidanceId=guidance.guidance_id,
        guidanceDigest=guidance.guidance_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=_GUIDANCE_KEY_ID,
        signedPreimageDigest=sha256_hex(guidance.canonical_bytes()),
        detachedSignature=_SIGNATURE,
    )
    state_suffix = guidance.source_binding.incident_state_digest.removeprefix("sha256:")
    prefix = (
        f"incidents/{guidance.source_binding.incident_id}/versions/"
        f"{state_suffix}/guidance/{guidance.guidance_id}"
    )
    payload: dict[str, object] = {
        "schemaVersion": ("athena.wc027IncidentGuidanceAssetReference.v1"),
        "incidentId": guidance.source_binding.incident_id,
        "incidentStateDigest": (guidance.source_binding.incident_state_digest),
        "guidanceId": guidance.guidance_id,
        "guidanceDigest": guidance.guidance_digest,
        "guidanceReference": VersionPinnedBlobReference(
            name=f"{prefix}/guidance.json",
            version="2026-09-11T16:00:02.0000000Z",
            contentDigest=sha256_hex(guidance.canonical_bytes()),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{prefix}/attestation.json",
            version="2026-09-11T16:00:03.0000000Z",
            contentDigest=sha256_hex(attestation.canonical_bytes()),
        ),
    }
    digest = compute_artifact_digest(_json_value(payload))
    reference = IncidentGuidanceAssetReference(
        **payload,
        referenceId=f"guidance-asset-{digest.removeprefix('sha256:')[:32]}",
        referenceDigest=digest,
    )
    return reference, guidance, attestation


def _enrichment_assets(binding):
    report_reference, report, report_attestation, proof_digest = _report_assets(binding)
    guidance_reference, guidance, guidance_attestation = _guidance_assets(binding)
    manifest = build_incident_enrichment_manifest(
        binding.incident_bound_request,
        report_reference,
        report,
        guidance_reference,
        guidance,
    )
    attestation = IncidentEnrichmentAttestation(
        schemaVersion="athena.wc027IncidentEnrichmentAttestation.v1",
        enrichmentId=manifest.enrichment_id,
        manifestDigest=manifest.manifest_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=_ENRICHMENT_KEY_ID,
        signedPreimageDigest=sha256_hex(manifest.canonical_bytes()),
        detachedSignature=_SIGNATURE,
    )
    state_suffix = manifest.incident_state_result_digest.removeprefix("sha256:")
    prefix = (
        f"incidents/{manifest.incident_id}/versions/{state_suffix}/"
        f"enrichments/{manifest.enrichment_id}"
    )
    payload: dict[str, object] = {
        "schemaVersion": ("athena.wc027IncidentEnrichmentAssetReference.v1"),
        "incidentId": manifest.incident_id,
        "incidentStateResultDigest": (manifest.incident_state_result_digest),
        "enrichmentId": manifest.enrichment_id,
        "manifestDigest": manifest.manifest_digest,
        "manifestReference": VersionPinnedBlobReference(
            name=f"{prefix}/manifest.json",
            version="2026-09-11T16:00:04.0000000Z",
            contentDigest=sha256_hex(manifest.canonical_bytes()),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{prefix}/attestation.json",
            version="2026-09-11T16:00:05.0000000Z",
            contentDigest=sha256_hex(attestation.canonical_bytes()),
        ),
    }
    digest = compute_artifact_digest(_json_value(payload))
    reference = IncidentEnrichmentAssetReference(
        **payload,
        referenceId=(f"enrichment-asset-{digest.removeprefix('sha256:')[:32]}"),
        referenceDigest=digest,
    )
    return {
        "report_reference": report_reference,
        "report": report,
        "report_attestation": report_attestation,
        "authority_proof_digest": proof_digest,
        "guidance_reference": guidance_reference,
        "guidance": guidance,
        "guidance_attestation": guidance_attestation,
        "manifest": manifest,
        "attestation": attestation,
        "reference": reference,
    }


def _validate_all(binding, assets) -> None:
    validate_published_correlation_report_assets(
        assets["report_reference"],
        assets["report"],
        assets["report_attestation"],
        binding.incident_bound_request,
        expected_authority_proof_digest=assets["authority_proof_digest"],
        trusted_report_key_id=_REPORT_KEY_ID,
        report_signature_verifier=_verify_signature,
    )
    validate_incident_guidance_assets(
        assets["guidance_reference"],
        assets["guidance"],
        assets["guidance_attestation"],
        trusted_guidance_key_id=_GUIDANCE_KEY_ID,
        guidance_signature_verifier=_verify_signature,
    )
    validate_incident_enrichment_manifest_binding(
        assets["manifest"],
        binding.incident_bound_request,
        assets["report"],
        assets["guidance"],
    )
    validate_incident_enrichment_assets(
        assets["reference"],
        assets["manifest"],
        assets["attestation"],
        trusted_enrichment_key_id=_ENRICHMENT_KEY_ID,
        enrichment_signature_verifier=_verify_signature,
    )


def _with_reference_digest(model_type, payload, prefix):
    digest = compute_artifact_digest(_json_value(payload))
    return model_type(
        **payload,
        referenceId=f"{prefix}-{digest.removeprefix('sha256:')[:32]}",
        referenceDigest=digest,
    )


def test_incident_enrichment_assets_round_trip_and_bind_exact_inputs() -> None:
    binding = _binding()
    assets = _enrichment_assets(binding)

    _validate_all(binding, assets)

    assert len(assets["report"].canonical_bytes()) <= (MAX_PUBLISHED_CORRELATION_REPORT_BYTES)
    assert len(assets["manifest"].canonical_bytes()) <= (MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES)
    assert assets["manifest"].no_auto_remediation is True
    assert (
        IncidentEnrichmentManifest.model_validate_json(
            assets["manifest"].model_dump_json(by_alias=True)
        )
        == assets["manifest"]
    )


def test_enrichment_contracts_reject_unknown_fields() -> None:
    manifest = _enrichment_assets(_binding())["manifest"]
    payload = manifest.model_dump(mode="json", by_alias=True)
    payload["unexpected"] = True

    with pytest.raises(ValidationError, match="Extra inputs"):
        IncidentEnrichmentManifest.model_validate(payload)


def test_report_asset_rejects_report_substitution() -> None:
    binding = _binding()
    assets = _enrichment_assets(binding)
    request = _request()
    substituted_report = _report_for(
        request,
        _hypothesis(
            category="guestServiceFailure",
            citation=request.evidence_index[0],
        ),
    )

    with pytest.raises(
        ValueError,
        match="published correlation report assets",
    ):
        validate_published_correlation_report_assets(
            assets["report_reference"],
            substituted_report,
            assets["report_attestation"],
            binding.incident_bound_request,
            expected_authority_proof_digest=(assets["authority_proof_digest"]),
            trusted_report_key_id=_REPORT_KEY_ID,
            report_signature_verifier=_verify_signature,
        )


def test_report_asset_rejects_authority_or_signature_substitution() -> None:
    binding = _binding()
    assets = _enrichment_assets(binding)

    with pytest.raises(
        ValueError,
        match="authority proof",
    ):
        validate_published_correlation_report_assets(
            assets["report_reference"],
            assets["report"],
            assets["report_attestation"],
            binding.incident_bound_request,
            expected_authority_proof_digest="sha256:" + "f" * 64,
            trusted_report_key_id=_REPORT_KEY_ID,
            report_signature_verifier=_verify_signature,
        )
    with pytest.raises(
        ValueError,
        match="published correlation report assets",
    ):
        validate_published_correlation_report_assets(
            assets["report_reference"],
            assets["report"],
            assets["report_attestation"],
            binding.incident_bound_request,
            expected_authority_proof_digest=(assets["authority_proof_digest"]),
            trusted_report_key_id=_REPORT_KEY_ID,
            report_signature_verifier=lambda _payload, _signature: False,
        )


def test_report_statement_rejects_forged_authority_proof() -> None:
    binding = _binding()

    with pytest.raises(ValueError, match="authority proof"):
        build_published_correlation_report_statement(
            binding.incident_bound_request,
            binding.correlation_report,
            authority_proof_digest="sha256:" + "f" * 64,
        )


def test_report_reference_rejects_wrong_occurrence_path() -> None:
    reference = _enrichment_assets(_binding())["report_reference"]
    payload = reference.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    payload["reportReference"] = VersionPinnedBlobReference(
        name=reference.report_reference.name.replace(
            "/correlation-reports/",
            "/wrong/",
        ),
        version=reference.report_reference.version,
        contentDigest=reference.report_reference.content_digest,
    )

    with pytest.raises(ValidationError, match="asset paths"):
        _with_reference_digest(
            PublishedCorrelationReportAssetReference,
            payload,
            "report-asset",
        )


def test_manifest_rejects_guidance_from_another_report() -> None:
    binding = _binding()
    assets = _enrichment_assets(binding)
    request = _request()
    other_report = _report_for(
        request,
        _hypothesis(
            category="guestServiceFailure",
            citation=request.evidence_index[0],
        ),
    )
    other_binding = _binding(request=request, report=other_report)
    _, other_guidance, _ = _guidance_assets(other_binding)

    with pytest.raises(
        ValueError,
        match="manifest does not match exact assets",
    ):
        validate_incident_enrichment_manifest_binding(
            assets["manifest"],
            binding.incident_bound_request,
            assets["report"],
            other_guidance,
        )


def test_manifest_builder_rejects_another_guidance_for_same_occurrence() -> None:
    binding = _binding()
    assets = _enrichment_assets(binding)
    other_binding = _binding(
        request=binding.incident_bound_request.correlation_request,
        report=binding.correlation_report,
        evaluated_at=binding.evaluated_at + timedelta(seconds=1),
    )
    other_reference, _, _ = _guidance_assets(other_binding)

    with pytest.raises(ValueError, match="guidance asset"):
        build_incident_enrichment_manifest(
            binding.incident_bound_request,
            assets["report_reference"],
            assets["report"],
            other_reference,
            assets["guidance"],
        )


def test_manifest_rejects_cross_occurrence_reference() -> None:
    binding = _binding()
    assets = _enrichment_assets(binding)
    reference = assets["report_reference"]
    payload = reference.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    other_incident = "inc-" + "1" * 12
    suffix = reference.incident_state_result_digest.removeprefix("sha256:")
    prefix = (
        f"incidents/{other_incident}/versions/{suffix}/correlation-reports/{reference.report_id}"
    )
    payload["incidentId"] = other_incident
    payload["reportReference"] = VersionPinnedBlobReference(
        name=f"{prefix}/report.json",
        version=reference.report_reference.version,
        contentDigest=reference.report_reference.content_digest,
    )
    payload["attestationReference"] = VersionPinnedBlobReference(
        name=f"{prefix}/attestation.json",
        version=reference.attestation_reference.version,
        contentDigest=reference.attestation_reference.content_digest,
    )
    substituted = _with_reference_digest(
        PublishedCorrelationReportAssetReference,
        payload,
        "report-asset",
    )

    with pytest.raises(
        ValidationError,
        match="one exact occurrence",
    ):
        build_incident_enrichment_manifest(
            binding.incident_bound_request,
            substituted,
            assets["report"],
            assets["guidance_reference"],
            assets["guidance"],
        )


def test_enrichment_asset_rejects_manifest_or_signature_substitution() -> None:
    binding = _binding()
    assets = _enrichment_assets(binding)

    with pytest.raises(
        ValueError,
        match="incident enrichment assets",
    ):
        validate_incident_enrichment_assets(
            assets["reference"],
            assets["manifest"],
            assets["attestation"],
            trusted_enrichment_key_id=_ENRICHMENT_KEY_ID,
            enrichment_signature_verifier=lambda _payload, _signature: False,
        )

    reference = assets["reference"]
    payload = reference.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    payload["manifestReference"] = VersionPinnedBlobReference(
        name=reference.manifest_reference.name,
        version="different-version",
        contentDigest="sha256:" + "f" * 64,
    )
    substituted = _with_reference_digest(
        IncidentEnrichmentAssetReference,
        payload,
        "enrichment-asset",
    )
    with pytest.raises(
        ValueError,
        match="incident enrichment assets",
    ):
        validate_incident_enrichment_assets(
            substituted,
            assets["manifest"],
            assets["attestation"],
            trusted_enrichment_key_id=_ENRICHMENT_KEY_ID,
            enrichment_signature_verifier=_verify_signature,
        )


def test_report_limit_matches_bounded_wc026_transfer_boundary() -> None:
    assert MAX_PUBLISHED_CORRELATION_REPORT_BYTES == 8 * 1024 * 1024


def test_maximum_hypothesis_report_can_exceed_256_kib_but_fits_limit() -> None:
    base_bundle = _bundle()
    extra_resource_ids = tuple(
        (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-synthetic-wc026/providers/Microsoft.Compute/"
            f"virtualMachines/synthetic-extra-{index:03d}-{'x' * 1000}"
        ).lower()
        for index in range(70)
    )
    extra_observations = tuple(
        _bound_observation(
            subjectResourceId=resource_id,
            signal="cpuSaturation",
            summaryCode="guest.cpu-saturation",
            sourceRecordReference=(f"azure-monitor:sha256:{index:064x}"),
        )
        for index, resource_id in enumerate(extra_resource_ids)
    )
    paths = tuple(
        sorted(
            (
                _dependency_path(),
                *(
                    _dependency_path(
                        source_role_ref="web",
                        target_role_ref=f"extra-{index:03d}",
                        relationship_id=(f"relationship-web-extra-{index:03d}"),
                        resource_ids=(WEB_ID.lower(), resource_id),
                    )
                    for index, resource_id in enumerate(extra_resource_ids)
                ),
            ),
            key=lambda item: item.path_id,
        )
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, *extra_observations),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )

    report = correlate_incident(
        _verified(
            _request(
                bundle_override=bundle,
                dependency_paths=paths,
            )
        )
    )
    report_size = len(report.canonical_bytes())

    assert len(report.hypotheses) == 64
    assert report_size > 256 * 1024
    assert report_size <= MAX_PUBLISHED_CORRELATION_REPORT_BYTES
