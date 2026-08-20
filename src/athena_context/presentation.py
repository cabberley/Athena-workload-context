from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from typing import Protocol

from athena_context.api.evaluation_domain import DemoEvaluationResult
from athena_context.binding.verification import (
    TrustedSnapshotVerifier,
    VerifiedCohortSnapshot,
    require_current_verified_snapshot,
    verify_cohort_snapshot,
)
from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.manifest import ManifestFinding
from athena_context.contracts.models import (
    EvidenceItemRef,
    EvidenceSnapshot,
    ResourceEvidenceRecord,
)
from athena_context.contracts.presentation import (
    ARGUS_PRESENTATION_SCHEMA_VERSION,
    ATHENA_WEB_NODE_FAULT_SCENARIO_ID,
    SYNTHETIC_WORKLOAD_NAME,
    ArgusPresentationPayload,
    ArgusPresentationPhase,
    DemoFaultRunReceipt,
    PresentationAttestation,
    presentation_phase_predicted_issue,
    presentation_phase_recommended_action,
    presentation_phase_summary,
)

type TrustedDemoEvaluationVerifier = Callable[
    [DemoEvaluationResult],
    DemoEvaluationResult,
]


class PresentationSigner(Protocol):
    def sign_preimage(self, canonical_preimage: bytes) -> str: ...


class PresentationSignatureVerifier(Protocol):
    def verify_preimage(
        self,
        canonical_preimage: bytes,
        signature: bytes,
    ) -> bool: ...


_VERIFIED_RESULT_MARKER = object()
_ZERO_DIGEST = "sha256:" + "0" * 64
_WEB_RESOURCE_TYPE = "microsoft.compute/virtualmachines"
_WEB_ROLE = "web-service"
_WEB_OPERATIONAL_CLAUSE_ID = "web-service-operational-state"


@dataclass(frozen=True, slots=True, init=False)
class VerifiedDemoEvaluationResult:
    """Nominal capability for one exact trusted result and snapshot."""

    result: DemoEvaluationResult
    verified_snapshot: VerifiedCohortSnapshot
    _verification_marker: object


def _require_exact_finding_bindings(result: DemoEvaluationResult) -> None:
    snapshot = result.snapshot
    publication = result.publication
    if result.result_digest != compute_artifact_digest(result._digest_payload()):
        raise AthenaValidationError(
            "evaluation result digest no longer matches its canonical payload"
        )
    allowed_references = {
        reference.canonical_json() for reference in snapshot.evidence_refs
    }
    if not snapshot.collected_at <= publication.published_at <= result.evaluated_at:
        raise AthenaValidationError(
            "evaluation publication time is not bound to the source snapshot"
        )
    for finding in result.findings:
        if (
            finding.manifest_id != publication.manifest_id
            or finding.manifest_version != publication.manifest_version
            or finding.profile_id != publication.profile_id
            or finding.resolved_profile_digest
            != publication.resolved_profile_digest
        ):
            raise AthenaValidationError(
                "evaluation finding metadata does not match its publication"
            )
        if any(
            reference.canonical_json() not in allowed_references
            for reference in finding.evidence_refs
        ):
            raise AthenaValidationError(
                "evaluation finding cites evidence outside its exact snapshot"
            )


def verify_demo_evaluation_result(
    result: DemoEvaluationResult,
    *,
    result_verifier: TrustedDemoEvaluationVerifier,
    snapshot_verifier: TrustedSnapshotVerifier,
) -> VerifiedDemoEvaluationResult:
    """Verify exact result and snapshot identities before presentation projection."""

    if result_verifier(result) is not result:
        raise AthenaValidationError(
            "trusted result verifier must return the exact supplied result"
        )
    verified_snapshot = verify_cohort_snapshot(
        result.snapshot,
        as_of=result.evaluated_at,
        verifier=snapshot_verifier,
    )
    if verified_snapshot.snapshot is not result.snapshot:
        raise AthenaValidationError(
            "verified snapshot capability does not match the evaluation result"
        )
    _require_exact_finding_bindings(result)
    capability = object.__new__(VerifiedDemoEvaluationResult)
    object.__setattr__(capability, "result", result)
    object.__setattr__(capability, "verified_snapshot", verified_snapshot)
    object.__setattr__(
        capability,
        "_verification_marker",
        _VERIFIED_RESULT_MARKER,
    )
    return capability


def _require_verified_result(
    verified: VerifiedDemoEvaluationResult,
) -> DemoEvaluationResult:
    if not isinstance(verified, VerifiedDemoEvaluationResult) or (
        getattr(verified, "_verification_marker", None)
        is not _VERIFIED_RESULT_MARKER
    ):
        raise AthenaValidationError(
            "ARGUS projection requires a VerifiedDemoEvaluationResult capability"
        )
    result = verified.result
    if (
        verified.verified_snapshot.snapshot is not result.snapshot
        or verified.verified_snapshot.artifact_digest
        != result.snapshot.compatibility.artifact_digest
        or verified.verified_snapshot.semantic_digest
        != result.snapshot.compatibility.semantic_digest
        or verified.verified_snapshot.verified_at != result.evaluated_at
    ):
        raise AthenaValidationError(
            "verified evaluation result changed after trusted verification"
        )
    if (
        require_current_verified_snapshot(
            verified.verified_snapshot,
            as_of=result.evaluated_at,
        )
        is not result.snapshot
    ):
        raise AthenaValidationError(
            "verified snapshot capability no longer matches the evaluation result"
        )
    _require_exact_finding_bindings(result)
    return result


def _synthetic_identifier(kind: str, value: str) -> str:
    digest = sha256_hex(
        (
            ATHENA_WEB_NODE_FAULT_SCENARIO_ID
            + "\x00"
            + kind
            + "\x00"
            + value
        ).encode("utf-8")
    )
    return f"synthetic-{kind}-{digest.removeprefix('sha256:')}"


def _resource_group_and_name(resource_id: str) -> tuple[str, str]:
    parts = resource_id.strip("/").split("/")
    folded = [part.casefold() for part in parts]
    try:
        resource_group_index = folded.index("resourcegroups") + 1
        provider_index = folded.index("providers") + 1
    except ValueError as exc:
        raise AthenaValidationError(
            "web resource evidence contains a malformed Azure resource ID"
        ) from exc
    if (
        resource_group_index >= len(parts)
        or provider_index + 2 >= len(parts)
        or provider_index + 3 != len(parts)
        or folded[provider_index] != "microsoft.compute"
        or folded[provider_index + 1] != "virtualmachines"
    ):
        raise AthenaValidationError(
            "web resource evidence must identify an Azure virtual machine"
        )
    return parts[resource_group_index], parts[provider_index + 2]


def _web_records(snapshot: EvidenceSnapshot) -> tuple[ResourceEvidenceRecord, ...]:
    records = tuple(
        sorted(
            (
                record
                for record in snapshot.evidence_records
                if isinstance(record, ResourceEvidenceRecord)
                and record.resource_type.casefold() == _WEB_RESOURCE_TYPE
                and record.tags.workload_role == _WEB_ROLE
            ),
            key=lambda record: record.resource_id.casefold(),
        )
    )
    if len(records) < 2:
        raise AthenaValidationError(
            "athena-web-node-fault.v1 requires at least two web-service VM records"
        )
    return records


def _operational_finding(
    result: DemoEvaluationResult,
    web_records: tuple[ResourceEvidenceRecord, ...],
) -> ManifestFinding:
    findings = tuple(
        finding
        for finding in result.findings
        if finding.finding_kind == "operationalState"
    )
    if len(findings) != 1:
        raise AthenaValidationError(
            "presentation requires exactly one operationalState finding"
        )
    finding = findings[0]
    if (
        finding.clause_id != _WEB_OPERATIONAL_CLAUSE_ID
        or finding.risk_acceptance_ref is not None
        or finding.governance_scope.manifest_id != finding.manifest_id
        or finding.governance_scope.profile_id != finding.profile_id
        or finding.governance_scope.clause_path
        != f"/constraints/{_WEB_OPERATIONAL_CLAUSE_ID}"
    ):
        raise AthenaValidationError(
            "operationalState finding is not the exact web-service clause"
        )
    canonical_finding_refs = [
        reference.canonical_json() for reference in finding.evidence_refs
    ]
    if len(canonical_finding_refs) != len(set(canonical_finding_refs)):
        raise AthenaValidationError(
            "operationalState finding evidence references must be unique"
        )
    snapshot = result.snapshot
    allowed_references = {
        reference.canonical_json(): reference for reference in snapshot.evidence_refs
    }
    records_by_digest: dict[str, list[ResourceEvidenceRecord]] = {}
    for record in snapshot.evidence_records:
        if isinstance(record, ResourceEvidenceRecord):
            records_by_digest.setdefault(record.item_digest, []).append(record)

    cited_digests: set[str] = set()
    for reference in finding.evidence_refs:
        if not isinstance(reference, EvidenceItemRef):
            raise AthenaValidationError(
                "operationalState finding must not cite evidence gaps"
            )
        resolved = allowed_references.get(reference.canonical_json())
        if resolved is None:
            raise AthenaValidationError(
                "operationalState finding citation does not resolve in the snapshot"
            )
        matching_records = records_by_digest.get(reference.item_digest, [])
        if len(matching_records) != 1:
            raise AthenaValidationError(
                "operationalState finding citation is ambiguous or unresolved"
            )
        cited_digests.add(matching_records[0].item_digest)

    expected_digests = {record.item_digest for record in web_records}
    if cited_digests != expected_digests:
        raise AthenaValidationError(
            "operationalState finding must cite every exact web-service VM record"
        )
    return finding


def _validate_receipt_and_phase(
    *,
    result: DemoEvaluationResult,
    receipt: DemoFaultRunReceipt,
    phase: ArgusPresentationPhase,
    web_records: tuple[ResourceEvidenceRecord, ...],
    finding: ManifestFinding,
) -> tuple[int, int]:
    snapshot = result.snapshot
    receipt_window = snapshot.expires_at - snapshot.collected_at
    if (
        receipt.completed_at > snapshot.collected_at
        or receipt.started_at < snapshot.collected_at - receipt_window
    ):
        raise AthenaValidationError(
            "fault receipt completion is outside the source snapshot freshness window"
        )

    source_by_name: dict[str, ResourceEvidenceRecord] = {}
    source_resource_groups: set[str] = set()
    for record in web_records:
        resource_group, name = _resource_group_and_name(record.resource_id)
        normalized_name = name.casefold()
        if normalized_name in source_by_name:
            raise AthenaValidationError(
                "web-service VM names must be unique within the source snapshot"
            )
        source_by_name[normalized_name] = record
        source_resource_groups.add(resource_group.casefold())
    if len(source_resource_groups) != 1:
        raise AthenaValidationError(
            "athena-web-node-fault.v1 web-service VMs must share one resource group"
        )
    if source_resource_groups != {receipt.resource_group.casefold()}:
        raise AthenaValidationError(
            "fault receipt resourceGroup does not match the source snapshot"
        )
    if set(source_by_name) != {
        name.casefold() for name in receipt.eligible_web_vm_names
    }:
        raise AthenaValidationError(
            "fault receipt eligibleWebVmNames do not match the source snapshot"
        )
    target = source_by_name.get(receipt.target_vm_name.casefold())
    if target is None or target.resource_id.casefold() != (
        receipt.target_vm_resource_id.casefold()
    ):
        raise AthenaValidationError(
            "fault receipt target does not match the exact source VM record"
        )

    states = [record.state for record in web_records]
    if any(state == "unknown" for state in states):
        raise AthenaValidationError(
            "unknown web-service operational state cannot be presented"
        )
    running_nodes = states.count("running")
    faulted_nodes = states.count("stopped") + states.count("deallocated")
    if running_nodes + faulted_nodes != len(states):
        raise AthenaValidationError(
            "unsupported web-service operational state cannot be presented"
        )

    if phase == "baseline":
        if (
            receipt.action != "status"
            or receipt.after_power_state != "PowerState/running"
            or running_nodes != len(states)
            or faulted_nodes
            or finding.verdict != "pass"
        ):
            raise AthenaValidationError(
                "baseline receipt, source state, and operational finding do not agree"
            )
    elif phase == "faulted":
        if (
            receipt.action != "inject"
            or receipt.after_power_state
            not in {"PowerState/stopped", "PowerState/deallocated"}
            or target.state not in {"stopped", "deallocated"}
            or receipt.after_power_state != f"PowerState/{target.state}"
            or running_nodes < 1
            or faulted_nodes != 1
            or finding.verdict != "observation"
        ):
            raise AthenaValidationError(
                "faulted receipt, source state, and operational finding do not agree"
            )
    elif (
        receipt.action != "reset"
        or receipt.after_power_state != "PowerState/running"
        or target.state != "running"
        or running_nodes != len(states)
        or faulted_nodes
        or finding.verdict != "pass"
    ):
        raise AthenaValidationError(
            "recovered receipt, source state, and operational finding do not agree"
        )
    return running_nodes, faulted_nodes


def project_argus_presentation(
    verified: VerifiedDemoEvaluationResult,
    *,
    receipt: DemoFaultRunReceipt,
    phase: ArgusPresentationPhase,
    synthetic_key_id: str,
) -> ArgusPresentationPayload:
    """Project verified Athena evidence into the frozen synthetic-safe ARGUS shape."""

    result = _require_verified_result(verified)
    web_records = _web_records(result.snapshot)
    finding = _operational_finding(result, web_records)
    running_nodes, faulted_nodes = _validate_receipt_and_phase(
        result=result,
        receipt=receipt,
        phase=phase,
        web_records=web_records,
        finding=finding,
    )

    if phase == "baseline":
        service_state = "healthy"
        presentation_verdict = "pass"
        risk_level = "normal"
        fault_run: dict[str, str] | None = None
    elif phase == "faulted":
        service_state = "degraded-redundancy"
        presentation_verdict = "fail"
        risk_level = "warning"
        fault_run = {
            "faultRunId": _synthetic_identifier(
                "fault-run",
                receipt.fault_run_id,
            ),
            "targetVmName": _synthetic_identifier(
                "vm",
                receipt.target_vm_resource_id.casefold(),
            ),
            "afterPowerState": "stopped",
        }
    else:
        service_state = "recovered"
        presentation_verdict = "resolved"
        risk_level = "normal"
        fault_run = {
            "faultRunId": _synthetic_identifier(
                "fault-run",
                receipt.fault_run_id,
            ),
            "targetVmName": _synthetic_identifier(
                "vm",
                receipt.target_vm_resource_id.casefold(),
            ),
            "afterPowerState": "running",
        }

    evidence_refs = {
        _synthetic_identifier("evidence", reference.canonical_json())
        for reference in finding.evidence_refs
    }
    if phase != "baseline":
        evidence_refs.add(
            _synthetic_identifier("evidence", receipt.canonical_json())
        )

    publication = result.publication
    snapshot = result.snapshot
    payload: dict[str, object] = {
        "schemaVersion": ARGUS_PRESENTATION_SCHEMA_VERSION,
        "scenarioId": ATHENA_WEB_NODE_FAULT_SCENARIO_ID,
        "phase": phase,
        "workload": {
            "name": SYNTHETIC_WORKLOAD_NAME,
            "manifestId": _synthetic_identifier(
                "manifest",
                publication.manifest_id,
            ),
            "manifestVersion": publication.manifest_version,
            "profileId": _synthetic_identifier(
                "profile",
                publication.profile_id,
            ),
            "resourceGroup": _synthetic_identifier(
                "rg",
                receipt.resource_group.casefold(),
            ),
        },
        "athena": {
            "snapshotId": _synthetic_identifier(
                "snapshot",
                snapshot.snapshot_id,
            ),
            "artifactDigest": snapshot.compatibility.artifact_digest,
            "semanticDigest": snapshot.compatibility.semantic_digest,
            "resultDigest": _ZERO_DIGEST,
            "signatureAlgorithm": "RS256",
            "keyVaultKeyId": synthetic_key_id,
        },
        "runtimeState": {
            "webTier": {
                "expectedNodes": len(web_records),
                "runningNodes": running_nodes,
                "faultedNodes": faulted_nodes,
                "serviceState": service_state,
            }
        },
        "findings": [
            {
                "clauseId": _synthetic_identifier(
                    "clause",
                    finding.clause_id,
                ),
                "verdict": presentation_verdict,
                "summary": presentation_phase_summary(phase),
                "evidenceRefs": sorted(evidence_refs),
            }
        ],
        "argus": {
            "riskLevel": risk_level,
            "predictedIssue": presentation_phase_predicted_issue(phase),
            "recommendedAction": presentation_phase_recommended_action(phase),
        },
    }
    if fault_run is not None:
        payload["faultRun"] = fault_run

    digest_preimage = deepcopy(payload)
    athena = digest_preimage["athena"]
    if not isinstance(athena, dict):
        raise AthenaValidationError("presentation athena metadata is required")
    athena.pop("resultDigest")
    payload_athena = payload["athena"]
    if not isinstance(payload_athena, dict):
        raise AthenaValidationError("presentation athena metadata is required")
    payload_athena["resultDigest"] = sha256_hex(
        canonicalize_json(digest_preimage).encode("utf-8")
    )
    return ArgusPresentationPayload.model_validate_json(
        canonicalize_json(payload)
    )


def _decode_signature(value: str) -> bytes:
    if not value:
        raise AthenaValidationError("presentation signature must not be empty")
    if any(
        character
        not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise AthenaValidationError(
            "presentation signer returned invalid base64 signature bytes"
        )
    try:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(
            value.replace("-", "+").replace("_", "/") + padding,
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise AthenaValidationError(
            "presentation signer returned invalid base64 signature bytes"
        ) from exc


def _base64url_signature(value: str) -> str:
    if not value:
        raise AthenaValidationError("presentation signature must not be empty")
    try:
        signature = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AthenaValidationError(
            "presentation signer returned invalid base64 signature bytes"
        ) from exc
    if not signature:
        raise AthenaValidationError("presentation signature must not be empty")
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def attest_argus_presentation(
    payload: ArgusPresentationPayload,
    *,
    signer: PresentationSigner,
) -> PresentationAttestation:
    detached_signature = _base64url_signature(
        signer.sign_preimage(payload.canonical_preimage())
    )
    return PresentationAttestation(
        schemaVersion="athena.argus.presentationAttestation.v1",
        resultDigest=payload.athena.result_digest,
        signatureAlgorithm=payload.athena.signature_algorithm,
        keyVaultKeyId=payload.athena.key_vault_key_id,
        detachedSignature=detached_signature,
    )


def verify_presentation_attestation(
    payload: ArgusPresentationPayload,
    attestation: PresentationAttestation,
    *,
    verifier: PresentationSignatureVerifier,
) -> bool:
    try:
        preimage = payload.canonical_preimage()
        if (
            payload.athena.result_digest != sha256_hex(preimage)
            or attestation.result_digest != payload.athena.result_digest
            or attestation.signature_algorithm
            != payload.athena.signature_algorithm
            or attestation.key_vault_key_id
            != payload.athena.key_vault_key_id
        ):
            return False
        return verifier.verify_preimage(
            preimage,
            _decode_signature(attestation.detached_signature),
        )
    except (AthenaValidationError, ValueError, TypeError):
        return False


def argus_signed_envelope(
    payload: ArgusPresentationPayload,
    attestation: PresentationAttestation,
) -> dict[str, object]:
    if (
        attestation.result_digest != payload.athena.result_digest
        or attestation.signature_algorithm != payload.athena.signature_algorithm
        or attestation.key_vault_key_id != payload.athena.key_vault_key_id
    ):
        raise AthenaValidationError(
            "presentation attestation metadata does not match its payload"
        )
    return {
        "payload": payload.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "detachedSignature": attestation.detached_signature,
    }


__all__ = [
    "PresentationSignatureVerifier",
    "PresentationSigner",
    "TrustedDemoEvaluationVerifier",
    "VerifiedDemoEvaluationResult",
    "argus_signed_envelope",
    "attest_argus_presentation",
    "project_argus_presentation",
    "verify_demo_evaluation_result",
    "verify_presentation_attestation",
]
