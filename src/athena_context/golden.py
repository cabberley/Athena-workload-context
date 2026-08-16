from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal, cast

from athena_context.contracts import (
    AthenaValidationError,
    EvidenceContextVerifier,
    EvidenceItemRef,
    EvidenceRecord,
    EvidenceReferenceContext,
    EvidenceSnapshot,
    ManifestFinding,
    NamePredicateSelector,
    ResolvedManifestProfile,
    ResourceEvidenceRecord,
    ResourceProofFact,
    RoleBindingProof,
    canonicalize_json,
    compute_artifact_digest,
    compute_evidence_reference_set_digest,
    resolve_manifest_profile,
    verified_snapshot_context_verifier,
)
from athena_context.contracts.common import normalize_nfc_text
from athena_context.contracts.manifest import (
    FindingVerdict,
    ManifestFindingKind,
    ProofFact,
)
from athena_context.fixtures import FixtureBundle, make_canonical_fixture_from_resources
from athena_context.policy import evaluate_manifest_profile

type GoldenProfileId = Literal["production", "development", "training"]
type GoldenOracleStatus = Literal["complete", "pending"]

GOLDEN_PROOF_AS_OF: Final = datetime(2025, 6, 1, 12, 0, tzinfo=UTC)
WC002_MANIFEST_ID: Final = "wl-athena-wc002-canonical"
WC002_MANIFEST_VERSION: Final = "1.0.0"
WC002_MANIFEST_ARTIFACT_DIGEST: Final = (
    "sha256:b6623ba1d2102223b27597f9ae64c1a83769fa4665fb86d9580492ff0bc25ab6"
)
WC002_MANIFEST_SEMANTIC_DIGEST: Final = (
    "sha256:4cb99758a49d39da2191ddaa583cd00b43c504d1cf0dad3b636fcda9468e7ec0"
)
WC002_SNAPSHOT_ID: Final = "snap-111111111111"
WC002_SNAPSHOT_ARTIFACT_DIGEST: Final = (
    "sha256:eebe798248175c34217cda5d602ee7c6341aa312a1305c9879291b45345dfad2"
)
WC002_SNAPSHOT_SEMANTIC_DIGEST: Final = WC002_SNAPSHOT_ARTIFACT_DIGEST
GOLDEN_PROFILE_IDS: Final[tuple[GoldenProfileId, ...]] = (
    "production",
    "development",
    "training",
)
GOLDEN_VERDICT_MATRIX: Final[
    tuple[
        tuple[
            str,
            tuple[
                FindingVerdict | None,
                FindingVerdict | None,
                FindingVerdict | None,
            ],
        ],
        ...,
    ]
] = (
    (
        "db-singleton-supported",
        ("expectedConstraint", "expectedConstraint", "expectedConstraint"),
    ),
    (
        "db-zone-loss-spof",
        ("acceptedResidualRisk", "observation", "acceptedResidualRisk"),
    ),
    (
        "db-zone-loss-acceptance",
        ("acceptedResidualRisk", "observation", "acceptedResidualRisk"),
    ),
    ("worker-db-zone-colocation", ("pass", "pass", "pass")),
    ("web-zone-distribution", ("pass", "pass", None)),
)

_GOLDEN_CLAUSE_IDS = tuple(row[0] for row in GOLDEN_VERDICT_MATRIX)
_FINDING_KIND_BY_CLAUSE: Final[dict[str, ManifestFindingKind]] = {
    "db-singleton-supported": "technologyConstraint",
    "db-zone-loss-spof": "actualSpof",
    "db-zone-loss-acceptance": "riskAcceptance",
    "worker-db-zone-colocation": "architectureConstraint",
    "web-zone-distribution": "architectureConstraint",
}
_EVIDENCE_ROLES_BY_CLAUSE: Final[dict[str, tuple[str, ...]]] = {
    "db-singleton-supported": ("database-primary",),
    "db-zone-loss-spof": ("database-primary",),
    "db-zone-loss-acceptance": ("database-primary",),
    "worker-db-zone-colocation": ("worker", "database-primary"),
    "web-zone-distribution": ("web",),
}
_RISK_ACCEPTANCE_BY_PROFILE: Final[dict[GoldenProfileId, str | None]] = {
    "production": "ra-db-zone-loss-production",
    "development": None,
    "training": "ra-db-zone-loss-training",
}


class GoldenProofMismatchError(AthenaValidationError):
    """Raised when verified canonical inputs do not match the golden oracle."""


@dataclass(frozen=True, slots=True)
class GoldenPendingDecision:
    """An observed outcome whose expected oracle verdict is not yet approved."""

    profile_id: GoldenProfileId
    clause_id: str
    observed_verdict: FindingVerdict
    reason: str

    def to_payload(self) -> dict[str, str]:
        return {
            "profileId": self.profile_id,
            "clauseId": self.clause_id,
            "observedVerdict": self.observed_verdict,
            "reason": self.reason,
        }


def _utc_millisecond(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class GoldenProfileResult:
    """Immutable release-evidence projection of one authoritative profile evaluation."""

    profile_id: GoldenProfileId
    resolved_profile_digest: str
    snapshot_artifact_digest: str
    snapshot_semantic_digest: str
    evidence_refs: tuple[str, ...]
    verdicts: tuple[tuple[str, FindingVerdict], ...]
    findings: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "profileId": self.profile_id,
            "resolvedProfileDigest": self.resolved_profile_digest,
            "snapshotArtifactDigest": self.snapshot_artifact_digest,
            "snapshotSemanticDigest": self.snapshot_semantic_digest,
            "evidenceRefs": [json.loads(reference) for reference in self.evidence_refs],
            "verdicts": dict(self.verdicts),
            "findings": [json.loads(finding) for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class GoldenProofResult:
    """Deterministic, canonicalizable evidence artifact for the three-profile proof."""

    as_of: datetime
    manifest_id: str
    manifest_version: str
    manifest_artifact_digest: str
    manifest_semantic_digest: str
    snapshot_id: str
    snapshot_artifact_digest: str
    snapshot_semantic_digest: str
    snapshot_evidence_reference_set_digest: str
    profiles: tuple[GoldenProfileResult, ...]
    pending_decisions: tuple[GoldenPendingDecision, ...]

    @property
    def oracle_status(self) -> GoldenOracleStatus:
        return "pending" if self.pending_decisions else "complete"

    def _digest_payload(self) -> dict[str, object]:
        return {
            "artifactKind": "athenaGoldenProof",
            "artifactVersion": "1.0.0",
            "oracleStatus": self.oracle_status,
            "asOf": _utc_millisecond(self.as_of),
            "manifestId": self.manifest_id,
            "manifestVersion": self.manifest_version,
            "manifestArtifactDigest": self.manifest_artifact_digest,
            "manifestSemanticDigest": self.manifest_semantic_digest,
            "snapshotId": self.snapshot_id,
            "snapshotArtifactDigest": self.snapshot_artifact_digest,
            "snapshotSemanticDigest": self.snapshot_semantic_digest,
            "snapshotEvidenceReferenceSetDigest": self.snapshot_evidence_reference_set_digest,
            "profiles": [profile.to_payload() for profile in self.profiles],
            "pendingDecisions": [decision.to_payload() for decision in self.pending_decisions],
        }

    @property
    def proof_digest(self) -> str:
        return compute_artifact_digest(self._digest_payload())

    def to_payload(self) -> dict[str, object]:
        return {**self._digest_payload(), "proofDigest": self.proof_digest}

    def canonical_json(self) -> str:
        return canonicalize_json(self.to_payload())

    def render_text(self) -> str:
        """Render a deterministic Markdown summary for release evidence."""

        verdicts_by_profile = {
            profile.profile_id: dict(profile.verdicts) for profile in self.profiles
        }
        lines = [
            "# Athena golden proof",
            "",
            f"- Oracle status: `{self.oracle_status}`",
            f"- Proof digest: `{self.proof_digest}`",
            f"- Manifest artifact digest: `{self.manifest_artifact_digest}`",
            f"- Manifest semantic digest: `{self.manifest_semantic_digest}`",
            f"- Snapshot: `{self.snapshot_id}`",
            f"- Snapshot artifact digest: `{self.snapshot_artifact_digest}`",
            f"- Snapshot semantic digest: `{self.snapshot_semantic_digest}`",
            "",
            "| Clause | Production | Development | Training |",
            "|---|---|---|---|",
        ]
        pending_cells = {
            (decision.profile_id, decision.clause_id): decision
            for decision in self.pending_decisions
        }
        for clause_id in _GOLDEN_CLAUSE_IDS:
            cells = [clause_id]
            for profile_id in GOLDEN_PROFILE_IDS:
                pending = pending_cells.get((profile_id, clause_id))
                cells.append(
                    f"pending (observed: {pending.observed_verdict})"
                    if pending is not None
                    else verdicts_by_profile[profile_id][clause_id]
                )
            lines.append("| " + " | ".join(cells) + " |")
        if self.pending_decisions:
            lines.extend(("", "## Pending oracle decisions", ""))
            lines.extend(
                f"- `{decision.profile_id}/{decision.clause_id}`: "
                f"{decision.reason} (observed `{decision.observed_verdict}`)"
                for decision in self.pending_decisions
            )
        return "\n".join(lines)


def _normalized(value: str) -> str:
    return normalize_nfc_text(value).casefold()


def _ordered_resource_ids(resource_ids: list[str]) -> tuple[str, ...]:
    return tuple(sorted(resource_ids, key=_normalized))


def _resource_name(resource_id: str) -> str:
    resource_name = resource_id.rstrip("/").rsplit("/", 1)[-1]
    if not resource_name:
        raise AthenaValidationError("canonical resource id has no resource name")
    return resource_name


def _selector_matches(
    selector: NamePredicateSelector,
    record: ResourceEvidenceRecord,
) -> bool:
    name = _resource_name(record.resource_id).casefold()
    return (selector.prefix is None or name.startswith(selector.prefix.casefold())) and (
        selector.suffix is None or name.endswith(selector.suffix.casefold())
    )


def _select_role_resources(
    profile: ResolvedManifestProfile,
    snapshot: EvidenceSnapshot,
) -> dict[str, tuple[ResourceEvidenceRecord, ...]]:
    records = tuple(
        record for record in snapshot.evidence_records if isinstance(record, ResourceEvidenceRecord)
    )
    selected_by_role: dict[str, tuple[ResourceEvidenceRecord, ...]] = {}
    memberships: dict[str, list[str]] = {}
    for role in sorted(profile.roles, key=lambda item: _normalized(item.role_id)):
        if len(role.selectors) != 1 or not isinstance(role.selectors[0], NamePredicateSelector):
            raise AthenaValidationError(
                "golden proof requires one verified namePredicate selector per role"
            )
        selector = role.selectors[0]
        selected = tuple(
            sorted(
                (record for record in records if _selector_matches(selector, record)),
                key=lambda record: _normalized(record.resource_id),
            )
        )
        if len(selected) > selector.max_matches:
            raise AthenaValidationError(f"role selector exceeded maxMatches: {role.role_id}")
        selected_by_role[role.role_id] = selected
        for record in selected:
            memberships.setdefault(_normalized(record.resource_id), []).append(role.role_id)

    ambiguous = {
        resource_id: role_ids for resource_id, role_ids in memberships.items() if len(role_ids) != 1
    }
    if ambiguous:
        raise AthenaValidationError("canonical role selectors produced ambiguous bindings")
    if set(memberships) != {_normalized(record.resource_id) for record in records}:
        raise AthenaValidationError("canonical snapshot contains an unbound resource")
    return selected_by_role


def _reference_by_item_digest(snapshot: EvidenceSnapshot) -> dict[str, EvidenceItemRef]:
    references: dict[str, EvidenceItemRef] = {}
    for reference in snapshot.evidence_refs:
        if not isinstance(reference, EvidenceItemRef):
            continue
        if reference.item_digest in references:
            raise AthenaValidationError("canonical snapshot has duplicate item evidence references")
        references[reference.item_digest] = reference
    return references


def _build_evidence_context(
    profile: ResolvedManifestProfile,
    snapshot: EvidenceSnapshot,
) -> EvidenceReferenceContext:
    selected_by_role = _select_role_resources(profile, snapshot)
    references = _reference_by_item_digest(snapshot)
    resources: list[ResourceProofFact] = []
    bindings: list[RoleBindingProof] = []
    for role_ref in sorted(selected_by_role, key=_normalized):
        selected = selected_by_role[role_ref]
        selected_ids = [record.resource_id for record in selected]
        for record in selected:
            reference = references.get(record.item_digest)
            if reference is None:
                raise AthenaValidationError("canonical resource record has no evidence reference")
            resources.append(
                ResourceProofFact(
                    resourceId=record.resource_id,
                    roleRef=role_ref,
                    availabilityZone=record.availability_zone or "unknown",
                    state="complete",
                    proofSource="observed",
                    evidenceRef=reference,
                )
            )
        ordered_ids = _ordered_resource_ids(selected_ids)
        bindings.append(
            RoleBindingProof(
                roleRef=role_ref,
                selectedResourceIds=list(ordered_ids),
                selectorResultDigest=compute_artifact_digest(list(ordered_ids)),
                state="complete",
            )
        )

    return EvidenceReferenceContext(
        snapshotId=snapshot.snapshot_id,
        snapshotArtifactDigest=snapshot.compatibility.artifact_digest,
        snapshotSemanticDigest=snapshot.compatibility.semantic_digest,
        collectedAt=snapshot.collected_at,
        expiresAt=snapshot.expires_at,
        authorizedScopes=snapshot.authorized_scopes,
        manifestId=profile.manifest_id,
        profileId=profile.profile_id,
        resolvedProfileDigest=profile.resolved_profile_digest,
        resources=resources,
        roleBindings=bindings,
    )


def _make_context_verifier(
    bundle: FixtureBundle,
    profile: ResolvedManifestProfile,
    *,
    as_of: datetime,
) -> EvidenceContextVerifier:
    expected_by_role = _select_role_resources(profile, bundle.canonical_snapshot)

    def fact_validator(fact: ProofFact, record: EvidenceRecord) -> bool:
        if not isinstance(fact, ResourceProofFact) or not isinstance(
            record, ResourceEvidenceRecord
        ):
            return False
        selected = expected_by_role.get(fact.role_ref)
        return (
            selected is not None
            and fact.state == "complete"
            and fact.proof_source == "observed"
            and any(
                _normalized(candidate.resource_id) == _normalized(record.resource_id)
                for candidate in selected
            )
        )

    def role_binding_validator(
        binding: RoleBindingProof,
        verified_snapshot: EvidenceSnapshot,
    ) -> bool:
        selected_by_role = _select_role_resources(profile, verified_snapshot)
        selected = selected_by_role.get(binding.role_ref)
        if selected is None or binding.state != "complete":
            return False
        expected_ids = _ordered_resource_ids([record.resource_id for record in selected])
        return tuple(
            binding.selected_resource_ids
        ) == expected_ids and binding.selector_result_digest == compute_artifact_digest(
            list(expected_ids)
        )

    return verified_snapshot_context_verifier(
        bundle.canonical_snapshot,
        as_of=as_of,
        expected_artifact_digest=bundle.snapshot_artifact_digest,
        publication_resolver=bundle.publication_resolver,
        identity_evidence=bundle.canonical_snapshot.identity_evidence,
        key_resolver=bundle.key_resolver,
        trusted_key_anchor=bundle.trusted_key_anchor,
        envelope_resolver=bundle.envelope_resolver,
        fact_validator=fact_validator,
        role_binding_validator=role_binding_validator,
    )


def _canonical_references(evidence: EvidenceReferenceContext) -> tuple[str, ...]:
    return tuple(sorted(resource.evidence_ref.canonical_json() for resource in evidence.resources))


def _finding_references(
    findings: dict[str, ManifestFinding],
) -> dict[str, tuple[str, ...]]:
    return {
        clause_id: tuple(reference.canonical_json() for reference in finding.evidence_refs)
        for clause_id, finding in findings.items()
    }


def _validate_approved_wc002_fixture(bundle: FixtureBundle) -> None:
    manifest = bundle.canonical_manifest
    snapshot = bundle.canonical_snapshot
    observed = (
        manifest.manifest_id,
        manifest.manifest_version,
        manifest.compatibility.artifact_digest,
        manifest.compatibility.semantic_digest,
        manifest.compute_artifact_digest_value(),
        manifest.compute_semantic_digest_value(),
        bundle.manifest_digest,
        snapshot.snapshot_id,
        snapshot.compatibility.artifact_digest,
        snapshot.compatibility.semantic_digest,
        bundle.snapshot_artifact_digest,
        bundle.snapshot_semantic_digest,
    )
    approved = (
        WC002_MANIFEST_ID,
        WC002_MANIFEST_VERSION,
        WC002_MANIFEST_ARTIFACT_DIGEST,
        WC002_MANIFEST_SEMANTIC_DIGEST,
        WC002_MANIFEST_ARTIFACT_DIGEST,
        WC002_MANIFEST_SEMANTIC_DIGEST,
        WC002_MANIFEST_ARTIFACT_DIGEST,
        WC002_SNAPSHOT_ID,
        WC002_SNAPSHOT_ARTIFACT_DIGEST,
        WC002_SNAPSHOT_SEMANTIC_DIGEST,
        WC002_SNAPSHOT_ARTIFACT_DIGEST,
        WC002_SNAPSHOT_SEMANTIC_DIGEST,
    )
    if observed != approved:
        raise GoldenProofMismatchError(
            "fixture does not match the approved immutable WC-002 identities and digests"
        )


def _expected_verdict(
    profile_id: GoldenProfileId,
    clause_id: str,
) -> FindingVerdict | None:
    profile_index = GOLDEN_PROFILE_IDS.index(profile_id)
    return next(
        verdicts[profile_index]
        for candidate_clause_id, verdicts in GOLDEN_VERDICT_MATRIX
        if candidate_clause_id == clause_id
    )


def _expected_evidence_references(
    evidence: EvidenceReferenceContext,
    clause_id: str,
) -> tuple[str, ...]:
    expected_roles = {_normalized(role_ref) for role_ref in _EVIDENCE_ROLES_BY_CLAUSE[clause_id]}
    return tuple(
        sorted(
            resource.evidence_ref.canonical_json()
            for resource in evidence.resources
            if _normalized(resource.role_ref) in expected_roles
        )
    )


def _validate_finding_projection(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    findings: dict[str, ManifestFinding],
) -> tuple[GoldenPendingDecision, ...]:
    profile_id = cast(GoldenProfileId, profile.profile_id)
    if set(findings) != set(_GOLDEN_CLAUSE_IDS):
        raise GoldenProofMismatchError(
            f"{profile_id} finding clauses do not match the golden oracle"
        )

    pending: list[GoldenPendingDecision] = []
    for clause_id in _GOLDEN_CLAUSE_IDS:
        finding = findings[clause_id]
        expected_verdict = _expected_verdict(profile_id, clause_id)
        expected_risk_acceptance = (
            _RISK_ACCEPTANCE_BY_PROFILE[profile_id]
            if clause_id in {"db-zone-loss-spof", "db-zone-loss-acceptance"}
            else None
        )
        expected_scope = {
            "governanceScopeType": "clause",
            "manifestId": WC002_MANIFEST_ID,
            "profileId": profile_id,
            "clausePath": f"/constraints/{clause_id}",
            "ownerRef": "ops-owner",
        }
        observed_references = tuple(
            reference.canonical_json() for reference in finding.evidence_refs
        )
        expected_references = _expected_evidence_references(evidence, clause_id)
        exact_projection_matches = (
            finding.clause_id == clause_id
            and finding.finding_kind == _FINDING_KIND_BY_CLAUSE[clause_id]
            and finding.manifest_id == WC002_MANIFEST_ID
            and finding.manifest_version == WC002_MANIFEST_VERSION
            and finding.profile_id == profile_id
            and finding.resolved_profile_digest == profile.resolved_profile_digest
            and finding.governance_scope.model_dump(mode="json", by_alias=True, exclude_none=True)
            == expected_scope
            and observed_references == expected_references
            and finding.risk_acceptance_ref == expected_risk_acceptance
        )
        if not exact_projection_matches:
            raise GoldenProofMismatchError(
                f"{profile_id}/{clause_id} finding projection does not match the golden oracle"
            )
        if expected_verdict is None:
            pending.append(
                GoldenPendingDecision(
                    profile_id=profile_id,
                    clause_id=clause_id,
                    observed_verdict=finding.verdict,
                    reason=(
                        "expected verdict awaits a decision because immutable WC-002 "
                        "contains web zones 1, 2, and 3 and Training requires 3"
                    ),
                )
            )
        elif finding.verdict != expected_verdict:
            raise GoldenProofMismatchError(
                f"{profile_id}/{clause_id} verdict does not match the golden oracle"
            )
    return tuple(pending)


def run_golden_proof(
    *,
    fixture: FixtureBundle | None = None,
    as_of: datetime = GOLDEN_PROOF_AS_OF,
) -> GoldenProofResult:
    """Verify and evaluate the packaged canonical snapshot against the exact oracle."""

    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise AthenaValidationError("golden proof as_of must be timezone-aware")
    bundle = fixture if fixture is not None else make_canonical_fixture_from_resources()
    _validate_approved_wc002_fixture(bundle)
    manifest = bundle.canonical_manifest
    snapshot = bundle.canonical_snapshot

    immutable_snapshot = snapshot.canonical_json()
    profile_results: list[GoldenProfileResult] = []
    pending_decisions: list[GoldenPendingDecision] = []
    baseline_context_references: tuple[str, ...] | None = None
    baseline_finding_references: dict[str, tuple[str, ...]] | None = None

    for profile_id in GOLDEN_PROFILE_IDS:
        profile = resolve_manifest_profile(manifest, profile_id, as_of=as_of)
        evidence = _build_evidence_context(profile, snapshot)
        verifier = _make_context_verifier(bundle, profile, as_of=as_of)
        findings = evaluate_manifest_profile(
            profile,
            evidence,
            as_of=as_of,
            verify_evidence_context=verifier,
        )
        pending_decisions.extend(_validate_finding_projection(profile, evidence, findings))
        actual = tuple((clause_id, findings[clause_id].verdict) for clause_id in _GOLDEN_CLAUSE_IDS)

        context_references = _canonical_references(evidence)
        finding_references = _finding_references(findings)
        if baseline_context_references is None:
            baseline_context_references = context_references
            baseline_finding_references = finding_references
        elif (
            context_references != baseline_context_references
            or finding_references != baseline_finding_references
        ):
            raise GoldenProofMismatchError(
                "profiles did not reuse exactly the same evidence references"
            )
        if snapshot.canonical_json() != immutable_snapshot:
            raise GoldenProofMismatchError("canonical snapshot changed during golden evaluation")

        profile_results.append(
            GoldenProfileResult(
                profile_id=cast(GoldenProfileId, profile_id),
                resolved_profile_digest=profile.resolved_profile_digest,
                snapshot_artifact_digest=evidence.snapshot_artifact_digest,
                snapshot_semantic_digest=evidence.snapshot_semantic_digest,
                evidence_refs=context_references,
                verdicts=actual,
                findings=tuple(
                    findings[clause_id].canonical_json() for clause_id in _GOLDEN_CLAUSE_IDS
                ),
            )
        )

    return GoldenProofResult(
        as_of=as_of,
        manifest_id=manifest.manifest_id,
        manifest_version=manifest.manifest_version,
        manifest_artifact_digest=manifest.compatibility.artifact_digest,
        manifest_semantic_digest=manifest.compatibility.semantic_digest,
        snapshot_id=snapshot.snapshot_id,
        snapshot_artifact_digest=snapshot.compatibility.artifact_digest,
        snapshot_semantic_digest=snapshot.compatibility.semantic_digest,
        snapshot_evidence_reference_set_digest=compute_evidence_reference_set_digest(snapshot),
        profiles=tuple(profile_results),
        pending_decisions=tuple(pending_decisions),
    )


__all__ = [
    "GOLDEN_PROFILE_IDS",
    "GOLDEN_PROOF_AS_OF",
    "GOLDEN_VERDICT_MATRIX",
    "WC002_MANIFEST_ARTIFACT_DIGEST",
    "WC002_MANIFEST_ID",
    "WC002_MANIFEST_SEMANTIC_DIGEST",
    "WC002_MANIFEST_VERSION",
    "WC002_SNAPSHOT_ARTIFACT_DIGEST",
    "WC002_SNAPSHOT_ID",
    "WC002_SNAPSHOT_SEMANTIC_DIGEST",
    "GoldenPendingDecision",
    "GoldenProfileResult",
    "GoldenProofMismatchError",
    "GoldenProofResult",
    "run_golden_proof",
]
