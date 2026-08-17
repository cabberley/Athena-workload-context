from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from athena_context.contracts.common import AthenaValidationError, compute_artifact_digest
from athena_context.contracts.models import (
    EvidenceSnapshot,
    compute_authorized_scopes_digest,
    compute_collector_attempt_set_digest,
    compute_evidence_record_set_digest,
    compute_evidence_reference_set_digest,
    compute_evidence_snapshot_artifact_digest,
    compute_evidence_snapshot_semantic_digest,
    compute_snapshot_attestation_preimage_digest,
)

type TrustedSnapshotVerifier = Callable[[EvidenceSnapshot, datetime], EvidenceSnapshot]
_VERIFIED_SNAPSHOT_MARKER = object()


@dataclass(frozen=True, slots=True, init=False)
class VerifiedCohortSnapshot:
    """Capability produced only after trusted snapshot evaluation succeeds."""

    snapshot: EvidenceSnapshot
    verified_at: datetime
    artifact_digest: str
    semantic_digest: str
    _verification_marker: object


def _require_utc_milliseconds(value: datetime) -> None:
    if (
        value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
        or value.microsecond % 1000
    ):
        raise AthenaValidationError(
            "snapshot verification time must be UTC with millisecond precision"
        )


def _validate_snapshot_components(snapshot: EvidenceSnapshot) -> None:
    artifact_digest = compute_evidence_snapshot_artifact_digest(snapshot)
    semantic_digest = compute_evidence_snapshot_semantic_digest(snapshot)
    if (
        snapshot.compatibility.artifact_digest != artifact_digest
        or snapshot.compatibility.semantic_digest != semantic_digest
    ):
        raise AthenaValidationError("snapshot canonical digests do not match its records")

    attestation = snapshot.snapshot_attestation
    identity_digests = sorted(
        identity.identity_evidence_digest for identity in snapshot.identity_evidence
    )
    if (
        attestation.artifact_kind != snapshot.compatibility.artifact_kind
        or attestation.schema_version != snapshot.compatibility.schema_version
        or attestation.semantic_contract_version
        != snapshot.compatibility.semantic_contract_version
        or attestation.policy_contract_version != snapshot.compatibility.policy_contract_version
        or attestation.snapshot_id != snapshot.snapshot_id
        or attestation.artifact_digest != artifact_digest
        or attestation.semantic_digest != semantic_digest
        or attestation.collected_at != snapshot.collected_at
        or attestation.expires_at != snapshot.expires_at
        or attestation.identity_evidence_digests != identity_digests
        or attestation.identity_evidence_set_digest
        != compute_artifact_digest(identity_digests)
        or attestation.authorized_scopes_digest
        != compute_authorized_scopes_digest(snapshot)
        or attestation.collector_attempt_set_digest
        != compute_collector_attempt_set_digest(snapshot)
        or attestation.evidence_record_set_digest
        != compute_evidence_record_set_digest(snapshot)
        or attestation.evidence_reference_set_digest
        != compute_evidence_reference_set_digest(snapshot)
        or attestation.signed_preimage_digest
        != compute_snapshot_attestation_preimage_digest(attestation)
    ):
        raise AthenaValidationError(
            "snapshot attestation does not match the recomputed snapshot components"
        )


def verify_cohort_snapshot(
    snapshot: EvidenceSnapshot,
    *,
    as_of: datetime,
    verifier: TrustedSnapshotVerifier,
) -> VerifiedCohortSnapshot:
    """Verify one exact snapshot and return the capability required by proposal APIs."""

    _require_utc_milliseconds(as_of)
    _validate_snapshot_components(snapshot)
    verified = verifier(snapshot, as_of)
    if verified is not snapshot:
        raise AthenaValidationError("trusted verifier must return the exact supplied snapshot")
    _validate_snapshot_components(snapshot)
    if as_of < snapshot.collected_at or as_of >= snapshot.expires_at:
        raise AthenaValidationError("verified snapshot is stale at as_of")
    capability = object.__new__(VerifiedCohortSnapshot)
    object.__setattr__(capability, "snapshot", snapshot)
    object.__setattr__(capability, "verified_at", as_of)
    object.__setattr__(
        capability,
        "artifact_digest",
        snapshot.compatibility.artifact_digest,
    )
    object.__setattr__(
        capability,
        "semantic_digest",
        snapshot.compatibility.semantic_digest,
    )
    object.__setattr__(
        capability,
        "_verification_marker",
        _VERIFIED_SNAPSHOT_MARKER,
    )
    return capability


def require_current_verified_snapshot(
    verified: VerifiedCohortSnapshot,
    *,
    as_of: datetime,
) -> EvidenceSnapshot:
    _require_utc_milliseconds(as_of)
    if not isinstance(verified, VerifiedCohortSnapshot) or (
        getattr(verified, "_verification_marker", None) is not _VERIFIED_SNAPSHOT_MARKER
    ):
        raise AthenaValidationError(
            "propose_cohorts requires a VerifiedCohortSnapshot capability"
        )
    if verified.verified_at != as_of:
        raise AthenaValidationError("verified snapshot is bound to a different as_of")
    snapshot = verified.snapshot
    _validate_snapshot_components(snapshot)
    if (
        verified.artifact_digest != snapshot.compatibility.artifact_digest
        or verified.semantic_digest != snapshot.compatibility.semantic_digest
    ):
        raise AthenaValidationError("snapshot changed after trusted verification")
    return snapshot


__all__ = [
    "TrustedSnapshotVerifier",
    "VerifiedCohortSnapshot",
    "verify_cohort_snapshot",
]
