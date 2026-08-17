from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from athena_context.contracts.common import AthenaValidationError, normalize_nfc_text
from athena_context.contracts.manifest import ManifestRole, ManifestSelector
from athena_context.contracts.models import AthenaBaseModel, EvidenceItemRef, UtcDateTime

type ConfidenceBand = Literal["high", "medium", "low", "conflicting"]
type ReviewDisposition = Literal["bulkHumanReview", "humanResolution"]
type SignalType = Literal[
    "approvedTags",
    "namePredicate",
    "resourceType",
    "vmScaleSet",
    "loadBalancerBackend",
    "subnet",
    "image",
    "deploymentProvenance",
    "provenance",
    "observedCommunication",
]
type ConflictCode = Literal[
    "ambiguousRole",
    "conflictingSignal",
    "crossEnvironment",
    "duplicateResourceId",
    "evidenceGap",
    "invalidEvidenceReference",
    "missingEvidence",
    "noEligibleMembers",
    "outOfScope",
    "overMaxMatches",
    "selectorPreviewMismatch",
    "snapshotDigestMismatch",
    "staleEvidence",
]
type RejectionReason = Literal[
    "ambiguousRole",
    "conflictingRoleEvidence",
    "crossEnvironment",
    "differentCohortSignal",
    "duplicateResourceId",
    "invalidEvidenceReference",
    "missingEnvironment",
    "missingRoleEvidence",
    "outOfProfileScope",
    "outOfSnapshotScope",
    "overMaxMatches",
    "staleEvidence",
]


class SelectorEvaluation(AthenaBaseModel):
    selector: ManifestSelector
    status: Literal["matched", "noMatches", "overMaxMatches"]
    matched_resource_ids: list[str] = Field(
        ..., alias="matchedResourceIds", max_length=30000
    )
    rejected_resource_ids: list[str] = Field(
        ..., alias="rejectedResourceIds", max_length=30000
    )
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)
    max_match_violations: list[str] = Field(
        default_factory=list, alias="maxMatchViolations", max_length=100
    )
    selector_result_digest: str = Field(
        ..., alias="selectorResultDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )

    @property
    def usable(self) -> bool:
        return self.status == "matched"


class SelectorPreview(AthenaBaseModel):
    selector: ManifestSelector
    matched_resource_ids: list[str] = Field(
        ..., alias="matchedResourceIds", max_length=1000
    )
    selector_result_digest: str = Field(
        ..., alias="selectorResultDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)


class ProposalScope(AthenaBaseModel):
    manifest_id: str = Field(..., alias="manifestId", min_length=1, max_length=128)
    manifest_version: str = Field(..., alias="manifestVersion", min_length=1, max_length=128)
    profile_id: str = Field(..., alias="profileId", min_length=1, max_length=128)
    profile_type: Literal[
        "production",
        "development",
        "training",
        "test",
        "disasterRecovery",
        "sandbox",
    ] = Field(..., alias="profileType")
    resolved_profile_digest: str = Field(
        ..., alias="resolvedProfileDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )


class ProposalSnapshot(AthenaBaseModel):
    snapshot_id: str = Field(..., alias="snapshotId", min_length=1, max_length=128)
    artifact_digest: str = Field(
        ..., alias="artifactDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    semantic_digest: str = Field(
        ..., alias="semanticDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    collected_at: UtcDateTime = Field(..., alias="collectedAt")
    expires_at: UtcDateTime = Field(..., alias="expiresAt")


class SupportingEvidence(AthenaBaseModel):
    signal_type: SignalType = Field(..., alias="signalType")
    signal_value: str = Field(..., alias="signalValue", min_length=1, max_length=2000)
    member_resource_ids: list[str] = Field(
        ..., alias="memberResourceIds", min_length=1, max_length=30000
    )
    evidence_refs: list[EvidenceItemRef] = Field(
        ..., alias="evidenceRefs", min_length=1, max_length=30000
    )


class DissentingEvidence(AthenaBaseModel):
    resource_id: str = Field(..., alias="resourceId", min_length=1, max_length=2048)
    signal_type: SignalType = Field(..., alias="signalType")
    expected_value: str = Field(..., alias="expectedValue", min_length=1, max_length=2000)
    observed_value: str | None = Field(
        default=None, alias="observedValue", min_length=1, max_length=2000
    )
    reason: str = Field(..., min_length=1, max_length=500)
    evidence_refs: list[EvidenceItemRef] = Field(
        default_factory=list, alias="evidenceRefs", max_length=100
    )


class RejectedCandidate(AthenaBaseModel):
    resource_id: str = Field(..., alias="resourceId", min_length=1, max_length=2048)
    reasons: list[RejectionReason] = Field(..., min_length=1, max_length=20)
    evidence_refs: list[EvidenceItemRef] = Field(
        default_factory=list, alias="evidenceRefs", max_length=100
    )


class ProposalConflict(AthenaBaseModel):
    code: ConflictCode
    detail: str = Field(..., min_length=1, max_length=1000)
    resource_ids: list[str] = Field(
        default_factory=list, alias="resourceIds", max_length=30000
    )
    role_refs: list[str] = Field(default_factory=list, alias="roleRefs", max_length=200)


class CohortProposal(AthenaBaseModel):
    proposal_id: str = Field(
        ..., alias="proposalId", pattern=r"^proposal-[a-f0-9]{16}$"
    )
    scope: ProposalScope
    role: ManifestRole
    members: list[str] = Field(..., max_length=1000)
    confidence: float = Field(..., ge=0.0, le=1.0)
    confidence_band: ConfidenceBand = Field(..., alias="confidenceBand")
    supporting_evidence: list[SupportingEvidence] = Field(
        default_factory=list, alias="supportingEvidence", max_length=100
    )
    dissent: list[DissentingEvidence] = Field(default_factory=list, max_length=30000)
    rejected_candidates: list[RejectedCandidate] = Field(
        default_factory=list, alias="rejectedCandidates", max_length=30000
    )
    conflicts: list[ProposalConflict] = Field(default_factory=list, max_length=1000)
    selector_preview: SelectorPreview | None = Field(default=None, alias="selectorPreview")
    snapshot: ProposalSnapshot
    disposition: ReviewDisposition
    requires_human_review: Literal[True] = Field(True, alias="requiresHumanReview")
    bulk_review_eligible: bool = Field(..., alias="bulkReviewEligible")
    publication_allowed: Literal[False] = Field(False, alias="publicationAllowed")
    manifest_mutated: Literal[False] = Field(False, alias="manifestMutated")

    @field_validator("members")
    @classmethod
    def validate_members(cls, values: list[str]) -> list[str]:
        normalized = [normalize_nfc_text(value).casefold() for value in values]
        if values != sorted(normalized) or len(normalized) != len(set(normalized)):
            raise AthenaValidationError(
                "proposal members must be unique normalized resource IDs in sorted order"
            )
        return values

    @model_validator(mode="after")
    def validate_review_invariants(self) -> CohortProposal:
        high = self.confidence_band == "high"
        if self.bulk_review_eligible != high:
            raise AthenaValidationError("only high-confidence proposals are bulk-review eligible")
        expected_disposition = "bulkHumanReview" if high else "humanResolution"
        if self.disposition != expected_disposition:
            raise AthenaValidationError("proposal disposition does not match confidence band")
        if high and (self.conflicts or self.dissent or self.selector_preview is None):
            raise AthenaValidationError(
                "high-confidence proposals require a bounded preview without dissent or conflicts"
            )
        if (
            (self.confidence_band == "high" and self.confidence < 0.8)
            or (
                self.confidence_band == "medium"
                and not 0.6 <= self.confidence < 0.8
            )
            or (self.confidence_band == "low" and self.confidence >= 0.6)
            or (self.confidence_band == "conflicting" and self.confidence >= 0.6)
        ):
            raise AthenaValidationError("proposal confidence does not match its confidence band")
        if self.selector_preview is not None and (
            self.selector_preview.matched_resource_ids != self.members
        ):
            raise AthenaValidationError("selector preview must resolve to exactly the cohort")
        if self.selector_preview is not None and (
            self.selector_preview.max_matches != self.selector_preview.selector.max_matches
        ):
            raise AthenaValidationError("selector preview maxMatches values must agree")
        for evidence in self.supporting_evidence:
            if evidence.member_resource_ids != self.members:
                raise AthenaValidationError(
                    "supporting evidence must cite the complete proposed cohort"
                )
        if any(item.resource_id not in self.members for item in self.dissent):
            raise AthenaValidationError("dissent must identify a proposed cohort member")
        if any(item.resource_id in self.members for item in self.rejected_candidates):
            raise AthenaValidationError("a cohort member cannot also be a rejected candidate")
        if self.role.role_id.casefold() in {""}:
            raise AthenaValidationError("proposal role must be present")
        return self


class CohortProposalBatch(AthenaBaseModel):
    scope: ProposalScope
    snapshot: ProposalSnapshot
    evaluated_at: UtcDateTime = Field(..., alias="evaluatedAt")
    input_digest: str = Field(
        ..., alias="inputDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    proposal_set_digest: str = Field(
        ..., alias="proposalSetDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    proposals: list[CohortProposal] = Field(..., max_length=30000)
    conflicts: list[ProposalConflict] = Field(default_factory=list, max_length=1000)
    requires_human_review: Literal[True] = Field(True, alias="requiresHumanReview")
    publication_allowed: Literal[False] = Field(False, alias="publicationAllowed")
    manifest_mutated: Literal[False] = Field(False, alias="manifestMutated")

    @model_validator(mode="after")
    def validate_exclusive_membership(self) -> CohortProposalBatch:
        memberships: dict[str, str] = {}
        for proposal in self.proposals:
            for resource_id in proposal.members:
                if resource_id in memberships:
                    raise AthenaValidationError(
                        "a normalized resource ID cannot belong to multiple cohort proposals"
                    )
                memberships[resource_id] = proposal.proposal_id
        return self


__all__ = [
    "CohortProposal",
    "CohortProposalBatch",
    "ConfidenceBand",
    "ConflictCode",
    "DissentingEvidence",
    "ProposalConflict",
    "ProposalScope",
    "ProposalSnapshot",
    "RejectedCandidate",
    "RejectionReason",
    "ReviewDisposition",
    "SelectorEvaluation",
    "SelectorPreview",
    "SignalType",
    "SupportingEvidence",
]
