from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from athena_context.api.cohort_domain import (
    CohortDraftBinding,
    CohortReviewCandidate,
    ProfileType,
    normalized_identifier,
)
from athena_context.api.domain import Actor, ApiModel, WorkloadIdentifier
from athena_context.binding.domain import ProposalScope, ProposalSnapshot
from athena_context.contracts.common import normalize_nfc_text

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"


class CohortDecisionKind(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    SPLIT = "split"
    MERGE = "merge"


class CohortDecisionRequest(ApiModel):
    """Exact WC-012 review binding accepted by the authoritative writer."""

    action: CohortDecisionKind = Field(strict=False)
    manifest_id: WorkloadIdentifier
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    draft_id: str = Field(pattern=_ID_PATTERN)
    expected_revision: int = Field(ge=1, le=9_007_199_254_740_991)
    expected_digest: str = Field(pattern=_DIGEST_PATTERN)
    scope: ProposalScope
    proposal_set_digest: str = Field(pattern=_DIGEST_PATTERN)
    proposal_ids: list[str] = Field(min_length=1, max_length=200)
    snapshot_artifact_digest: str = Field(pattern=_DIGEST_PATTERN)
    candidate: CohortReviewCandidate | None = None
    rationale: str = Field(min_length=1, max_length=2000)

    @field_validator("proposal_ids")
    @classmethod
    def validate_proposal_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if len(value) != 25 or not value.startswith("proposal-"):
                raise ValueError("proposal_ids must contain WC-010 proposal identifiers")
            suffix = value.removeprefix("proposal-")
            if len(suffix) != 16 or any(
                character not in "0123456789abcdef" for character in suffix
            ):
                raise ValueError("proposal_ids must contain WC-010 proposal identifiers")
        normalized = [normalized_identifier(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("proposal_ids must be unique after normalization")
        return values

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, value: str) -> str:
        normalized = normalize_nfc_text(value)
        if normalized != value or value != value.strip():
            raise ValueError(
                "rationale must be NFC-normalized without surrounding whitespace"
            )
        return value

    @model_validator(mode="after")
    def validate_action_binding(self) -> CohortDecisionRequest:
        if (
            self.scope.manifest_id != self.manifest_id
            or self.scope.manifest_version != self.manifest_version
            or self.scope.profile_id != self.profile_id
        ):
            raise ValueError("scope must exactly match the requested workload and profile")
        if self.action is CohortDecisionKind.REJECT:
            if self.candidate is not None:
                raise ValueError("reject must not claim an apply candidate")
        elif self.candidate is None:
            raise ValueError("approve, split, and merge require an exact candidate")
        elif self.candidate.action != self.action.value:
            raise ValueError("candidate action must exactly match the decision action")
        if (
            self.action in {
                CohortDecisionKind.APPROVE,
                CohortDecisionKind.SPLIT,
            }
            and len(self.proposal_ids) != 1
        ):
            raise ValueError(f"{self.action.value} requires exactly one proposal_id")
        if self.action is CohortDecisionKind.MERGE and len(self.proposal_ids) < 2:
            raise ValueError("merge requires at least two proposal_ids")
        return self


class CohortProposalSetVersion(ApiModel):
    """Immutable authority identity for one selected proposal-set version.

    The batch input digest is retained on the decision record for audit, but is
    intentionally absent here because it includes the proposal evaluation time.
    """

    manifest_id: WorkloadIdentifier
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    resolved_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    source_draft: CohortDraftBinding
    proposal_set_digest: str = Field(pattern=_DIGEST_PATTERN)
    snapshot_artifact_digest: str = Field(pattern=_DIGEST_PATTERN)
    source_proposal_ids: list[str] = Field(
        alias="sourceProposalIds",
        min_length=1,
        max_length=200,
    )

    @field_validator("source_proposal_ids")
    @classmethod
    def validate_canonical_proposal_set(cls, values: list[str]) -> list[str]:
        canonical = sorted(normalized_identifier(value) for value in values)
        if values != canonical or len(canonical) != len(set(canonical)):
            raise ValueError(
                "source_proposal_ids must be a canonical unique proposal set"
            )
        return values


class CohortDecisionAudit(ApiModel):
    audit_id: str = Field(alias="auditId", pattern=_ID_PATTERN)
    action: Literal["cohort_decision_recorded"] = Field(
        default="cohort_decision_recorded",
    )
    decision_id: str = Field(alias="decisionId", pattern=_ID_PATTERN)
    actor: Actor
    occurred_at: AwareDatetime = Field(alias="occurredAt")
    source_revision: int = Field(alias="sourceRevision", ge=1)
    resulting_revision: int | None = Field(
        default=None,
        alias="resultingRevision",
        ge=1,
    )
    draft_mutated: bool = Field(alias="draftMutated")


class CohortDecisionRecord(ApiModel):
    decision_id: str = Field(alias="decisionId", pattern=_ID_PATTERN)
    decision: CohortDecisionKind
    manifest_id: WorkloadIdentifier = Field(alias="manifestId")
    manifest_version: str = Field(alias="manifestVersion", pattern=_VERSION_PATTERN)
    profile_id: str = Field(alias="profileId", pattern=_ID_PATTERN)
    profile_type: ProfileType = Field(alias="profileType")
    resolved_profile_digest: str = Field(
        alias="resolvedProfileDigest",
        pattern=_DIGEST_PATTERN,
    )
    source_draft: CohortDraftBinding = Field(alias="sourceDraft")
    applied_draft: CohortDraftBinding | None = Field(default=None, alias="appliedDraft")
    batch_input_digest: str = Field(alias="batchInputDigest", pattern=_DIGEST_PATTERN)
    proposal_set_digest: str = Field(
        alias="proposalSetDigest",
        pattern=_DIGEST_PATTERN,
    )
    source_proposal_ids: list[str] = Field(
        alias="sourceProposalIds",
        min_length=1,
        max_length=200,
    )
    source_role_refs: list[str] = Field(
        alias="sourceRoleRefs",
        min_length=1,
        max_length=200,
    )
    snapshot: ProposalSnapshot
    candidate_id: str | None = Field(
        default=None,
        alias="candidateId",
        pattern=_ID_PATTERN,
    )
    candidate_digest: str | None = Field(
        default=None,
        alias="candidateDigest",
        pattern=_DIGEST_PATTERN,
    )
    rationale: str = Field(min_length=1, max_length=2000)
    decided_by: Actor = Field(alias="decidedBy")
    decided_at: AwareDatetime = Field(alias="decidedAt")
    audit: CohortDecisionAudit
    publication_allowed: Literal[False] = Field(False, alias="publicationAllowed")
    role_metadata_mutated: Literal[False] = Field(False, alias="roleMetadataMutated")

    @model_validator(mode="after")
    def validate_outcome(self) -> CohortDecisionRecord:
        rejected = self.decision is CohortDecisionKind.REJECT
        if rejected != (self.applied_draft is None):
            raise ValueError("only reject decisions may omit an applied draft")
        if rejected != (self.candidate_id is None):
            raise ValueError("only reject decisions may omit a candidate")
        if rejected != (self.candidate_digest is None):
            raise ValueError("only reject decisions may omit a candidate digest")
        if (
            self.audit.decision_id != self.decision_id
            or self.audit.actor != self.decided_by
            or self.audit.occurred_at != self.decided_at
            or self.audit.source_revision != self.source_draft.revision
            or self.audit.draft_mutated is rejected
            or self.audit.resulting_revision
            != (None if self.applied_draft is None else self.applied_draft.revision)
        ):
            raise ValueError("cohort decision audit binding is inconsistent")
        return self

    def proposal_set_version(self) -> CohortProposalSetVersion:
        return CohortProposalSetVersion(
            manifest_id=self.manifest_id,
            manifest_version=self.manifest_version,
            profile_id=self.profile_id,
            resolved_profile_digest=self.resolved_profile_digest,
            source_draft=self.source_draft,
            proposal_set_digest=self.proposal_set_digest,
            snapshot_artifact_digest=self.snapshot.artifact_digest,
            sourceProposalIds=sorted(
                normalized_identifier(proposal_id)
                for proposal_id in self.source_proposal_ids
            ),
        )


class CohortDecisionReceipt(ApiModel):
    actor_id: str = Field(pattern=_ID_PATTERN)
    idempotency_key: str = Field(pattern=_ID_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    response_json: str = Field(min_length=2)


class CohortDecisionDraftResult(ApiModel):
    draft_id: str = Field(alias="draftId", pattern=_ID_PATTERN)
    revision: int = Field(ge=1, le=9_007_199_254_740_991)
    manifest_digest: str = Field(alias="manifestDigest", pattern=_DIGEST_PATTERN)


class CohortDecisionResponse(ApiModel):
    """Exact durable-decision shape consumed by the WC-012 typed port."""

    decision_id: str = Field(alias="decisionId", pattern=_ID_PATTERN)
    action: CohortDecisionKind
    source_draft: CohortDraftBinding = Field(alias="sourceDraft")
    scope: ProposalScope
    proposal_ids: list[str] = Field(alias="proposalIds", min_length=1, max_length=200)
    proposal_set_digest: str = Field(
        alias="proposalSetDigest",
        pattern=_DIGEST_PATTERN,
    )
    snapshot_artifact_digest: str = Field(
        alias="snapshotArtifactDigest",
        pattern=_DIGEST_PATTERN,
    )
    candidate_id: str | None = Field(
        default=None,
        alias="candidateId",
        pattern=_ID_PATTERN,
    )
    rationale: str = Field(min_length=1, max_length=2000)
    state: Literal["applied", "rejected"]
    decided_by: str = Field(alias="decidedBy", pattern=_ID_PATTERN)
    decided_at: AwareDatetime = Field(alias="decidedAt")
    draft_result: CohortDecisionDraftResult | None = Field(
        default=None,
        alias="draftResult",
    )
    publication_allowed: Literal[False] = Field(False, alias="publicationAllowed")


def decision_response(record: CohortDecisionRecord) -> CohortDecisionResponse:
    return CohortDecisionResponse(
        decisionId=record.decision_id,
        action=record.decision,
        sourceDraft=record.source_draft,
        scope=ProposalScope(
            manifestId=record.manifest_id,
            manifestVersion=record.manifest_version,
            profileId=record.profile_id,
            profileType=record.profile_type,
            resolvedProfileDigest=record.resolved_profile_digest,
        ),
        proposalIds=record.source_proposal_ids,
        proposalSetDigest=record.proposal_set_digest,
        snapshotArtifactDigest=record.snapshot.artifact_digest,
        candidateId=record.candidate_id,
        rationale=record.rationale,
        state=(
            "rejected"
            if record.decision is CohortDecisionKind.REJECT
            else "applied"
        ),
        decidedBy=record.decided_by.actor_id,
        decidedAt=record.decided_at,
        draftResult=(
            None
            if record.applied_draft is None
            else CohortDecisionDraftResult(
                draftId=record.applied_draft.draft_id,
                revision=record.applied_draft.revision,
                manifestDigest=record.applied_draft.manifest_digest,
            )
        ),
        publicationAllowed=False,
    )


__all__ = [
    "CohortDecisionAudit",
    "CohortDecisionKind",
    "CohortDecisionReceipt",
    "CohortDecisionRecord",
    "CohortDecisionRequest",
    "CohortDecisionResponse",
    "CohortProposalSetVersion",
    "decision_response",
]
