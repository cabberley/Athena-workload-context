from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from athena_context.api import (
    ManagedIdentityPrivateMcpInvoker,
    OperatorTrustedWc008ConfigurationPort,
    PrivateMcpEvidenceTransport,
    Wc009EvidenceClientAdapter,
)
from athena_context.artifacts import ArtifactMetadataHashes, ArtifactWriteRequest
from athena_context.azure_adapters import (
    AzureBlobCreateOnlyArtifactWriter,
    AzureTableAttemptReplayGuard,
    DefaultAzureCredentialTrustedIngestionSigner,
    KeyVaultTrustedKeyResolver,
)
from athena_context.contracts import EvidenceGapRecord, VersionPinnedBlobReference, sha256_hex
from athena_context.evidence import EvidenceCollectionCommand
from athena_context.live_acceptance import (
    PreparedWc013LiveAcceptance,
    Wc013LiveAcceptanceError,
    prepare_wc013_live_acceptance,
)
from athena_context.precollected_evidence import (
    Wc013CollectedEvidenceArtifact,
    Wc013CollectedEvidenceHandoff,
    build_collected_evidence_artifact,
    wc013_plan_digest,
)


@dataclass(frozen=True, slots=True)
class Wc013EvidenceCollectorJobResult:
    artifact: Wc013CollectedEvidenceArtifact
    handoff: Wc013CollectedEvidenceHandoff


def _require_collector_runtime_environment(
    prepared: PreparedWc013LiveAcceptance,
    environment: Mapping[str, str],
) -> None:
    expected = {
        "AZURE_CLIENT_ID": prepared.plan.evidence_identity_client_id,
        "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID": (
            prepared.plan.evidence_identity_client_id
        ),
        "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST": (
            prepared.plan.wc007_pinned_authority_digest
        ),
        "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": (
            prepared.plan.wc008_pinned_assertion_digest
        ),
    }
    mismatches = [
        name for name, expected_value in expected.items() if environment.get(name) != expected_value
    ]
    if mismatches:
        raise Wc013LiveAcceptanceError(
            "collector runtime environment does not match the reviewed plan: "
            + ", ".join(sorted(mismatches))
        )


def collect_prepared_wc013_evidence(
    prepared: PreparedWc013LiveAcceptance,
) -> Wc013CollectedEvidenceArtifact:
    plan = prepared.plan
    try:
        key_resolver = KeyVaultTrustedKeyResolver(
            expected_record=prepared.trusted_key_record,
            managed_identity_client_id=plan.evidence_identity_client_id,
        )
        if key_resolver(prepared.trusted_key_anchor) is None:
            raise Wc013LiveAcceptanceError(
                "the exact versioned collector signing key could not be resolved"
            )
        configuration_port = OperatorTrustedWc008ConfigurationPort(
            assertion=prepared.assertion,
            pinned_assertion_digest=prepared.assertion.assertion_digest,
            operator_approval=prepared.operator_approval,
        )
        verified_configuration = configuration_port.load_verified()
        transport = PrivateMcpEvidenceTransport(
            deployment_configuration=verified_configuration,
            invoker=ManagedIdentityPrivateMcpInvoker(
                deployment_configuration=verified_configuration,
                audience=plan.azure_mcp_audience,
                managed_identity_client_id=plan.evidence_identity_client_id,
            ),
        )
        client = Wc009EvidenceClientAdapter(
            transport=transport,
            signer=DefaultAzureCredentialTrustedIngestionSigner(
                trusted_key_anchor=prepared.trusted_key_anchor,
                signing_identity_client_id=plan.evidence_identity_client_id,
                evidence_identity_client_id=plan.evidence_identity_client_id,
            ),
            replay_guard=AzureTableAttemptReplayGuard(
                endpoint=plan.replay.table_endpoint,
                table_name=plan.replay.table_name,
                partition_key=plan.replay.partition_key,
                managed_identity_client_id=plan.evidence_identity_client_id,
            ),
            clock=_SystemClock(),
            trust_configuration=prepared.collector_trust,
            key_resolver=key_resolver,
            trusted_key_anchor=prepared.trusted_key_anchor,
        )
        command = plan.evaluation_command
        collected = client.collect(
            EvidenceCollectionCommand(
                attemptId=command.attempt_id,
                evidenceScope=command.authorized_scope,
                authorizedScopes=(command.authorized_scope,),
                bounds=command.bounds,
            )
        )
        if (
            collected.collector_attempt.attempt_type != "successResponse"
            or not collected.evidence_records
            or any(
                isinstance(record, EvidenceGapRecord)
                for record in collected.evidence_records
            )
            or collected.envelope is None
        ):
            raise Wc013LiveAcceptanceError(
                "isolated collector did not produce a complete trusted response"
            )
        return build_collected_evidence_artifact(
            plan_digest=wc013_plan_digest(plan),
            collected=collected,
        )
    except Wc013LiveAcceptanceError:
        raise
    except Exception as exc:
        raise Wc013LiveAcceptanceError(
            "isolated WC-013 evidence collection failed closed "
            f"({type(exc).__name__})"
        ) from exc


def run_wc013_evidence_collector_job(
    plan_path: Path,
    *,
    artifact_blob_endpoint: str,
    artifact_container_name: str,
    environment: Mapping[str, str] | None = None,
) -> Wc013EvidenceCollectorJobResult:
    prepared = prepare_wc013_live_acceptance(plan_path)
    runtime_environment = environment if environment is not None else os.environ
    _require_collector_runtime_environment(prepared, runtime_environment)
    artifact = collect_prepared_wc013_evidence(prepared)
    payload = artifact.canonical_json().encode("utf-8")
    try:
        writer = AzureBlobCreateOnlyArtifactWriter(
            blob_endpoint=artifact_blob_endpoint,
            container_name=artifact_container_name,
            managed_identity_client_id=prepared.plan.evidence_identity_client_id,
        )
        blob_name = (
            f"wc013-evidence/{prepared.plan.evaluation_command.attempt_id}/"
            "collected-evidence.json"
        )
        receipt = writer.create(
            ArtifactWriteRequest(
                blob_name=blob_name,
                payload=payload,
                content_type="application/json",
                hashes=ArtifactMetadataHashes(payload_sha256=sha256_hex(payload)),
            )
        )
        reference = VersionPinnedBlobReference(
            name=receipt.blob_name,
            version=receipt.version_id,
            contentDigest=receipt.payload_sha256,
        )
        handoff = Wc013CollectedEvidenceHandoff(
            schemaVersion="athena.wc013CollectedEvidenceHandoff.v1",
            planDigest=artifact.plan_digest,
            attemptId=artifact.collection_request.attempt_id,
            evidence=reference,
        )
    except Exception as exc:
        raise Wc013LiveAcceptanceError(
            "isolated collector artifact publication failed closed "
            f"({type(exc).__name__})"
        ) from exc
    return Wc013EvidenceCollectorJobResult(
        artifact=artifact,
        handoff=handoff,
    )


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


__all__ = [
    "Wc013EvidenceCollectorJobResult",
    "collect_prepared_wc013_evidence",
    "run_wc013_evidence_collector_job",
]
