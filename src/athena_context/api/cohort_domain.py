from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from athena_context.api.domain import ApiModel, WorkloadIdentifier
from athena_context.binding.domain import (
    CohortProposalBatch,
    ProposalScope,
    ProposalSnapshot,
    SelectorPreview,
)
from athena_context.contracts.common import normalize_nfc_text
from athena_context.contracts.manifest import ManifestRole
from athena_context.contracts.models import EvidenceSnapshot

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"

type ProfileType = Literal[
    "production",
    "development",
    "training",
    "test",
    "disasterRecovery",
    "sandbox",
]
type CohortPreviewAction = Literal["split", "merge"]


def normalized_identifier(value: str) -> str:
    return normalize_nfc_text(value).casefold()


class CohortDraftBinding(ApiModel):
    draft_id: str = Field(alias="draftId", pattern=_ID_PATTERN)
    revision: int = Field(ge=1, le=9_007_199_254_740_991)
    manifest_digest: str = Field(alias="manifestDigest", pattern=_DIGEST_PATTERN)


class CohortProposalQuery(ApiModel):
    manifest_id: WorkloadIdentifier
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    draft_id: str = Field(pattern=_ID_PATTERN)
    expected_revision: int = Field(ge=1, le=9_007_199_254_740_991)
    expected_digest: str = Field(pattern=_DIGEST_PATTERN)


class CohortEvidenceBinding(ApiModel):
    manifest_id: WorkloadIdentifier
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    profile_type: ProfileType
    resolved_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    draft_id: str = Field(pattern=_ID_PATTERN)
    draft_revision: int = Field(ge=1, le=9_007_199_254_740_991)
    draft_digest: str = Field(pattern=_DIGEST_PATTERN)


class StoredEvidenceSnapshot(ApiModel):
    binding: CohortEvidenceBinding
    snapshot: EvidenceSnapshot


class CohortBatchCacheKey(ApiModel):
    evidence_binding: CohortEvidenceBinding
    snapshot_artifact_digest: str = Field(pattern=_DIGEST_PATTERN)


class CohortProposalBatchResponse(CohortProposalBatch):
    source_draft: CohortDraftBinding = Field(..., alias="sourceDraft")


class CohortReviewPreviewRequest(ApiModel):
    action: CohortPreviewAction
    manifest_id: WorkloadIdentifier
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    draft_id: str = Field(pattern=_ID_PATTERN)
    expected_revision: int = Field(ge=1, le=9_007_199_254_740_991)
    expected_digest: str = Field(pattern=_DIGEST_PATTERN)
    proposal_ids: list[str] = Field(min_length=1, max_length=200)
    source_role_refs: list[str] = Field(min_length=1, max_length=200)
    proposal_set_digest: str = Field(pattern=_DIGEST_PATTERN)
    snapshot_artifact_digest: str = Field(pattern=_DIGEST_PATTERN)
    resolution: str = Field(min_length=12, max_length=2000)

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

    @field_validator("source_role_refs")
    @classmethod
    def validate_role_refs(cls, values: list[str]) -> list[str]:
        normalized = [normalized_identifier(value) for value in values]
        if any(not value or len(value) > 128 for value in values):
            raise ValueError("source_role_refs contains an invalid role reference")
        if len(normalized) != len(set(normalized)):
            raise ValueError("source_role_refs must be unique after normalization")
        return values

    @field_validator("resolution")
    @classmethod
    def validate_resolution(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("resolution must not contain surrounding whitespace")
        return value

    @model_validator(mode="after")
    def validate_action_sources(self) -> CohortReviewPreviewRequest:
        if self.action == "split" and len(self.proposal_ids) != 1:
            raise ValueError("split requires exactly one proposal_id")
        if self.action == "merge" and len(self.proposal_ids) < 2:
            raise ValueError("merge requires at least two proposal_ids")
        return self

    def proposal_query(self) -> CohortProposalQuery:
        return CohortProposalQuery(
            manifest_id=self.manifest_id,
            manifest_version=self.manifest_version,
            profile_id=self.profile_id,
            draft_id=self.draft_id,
            expected_revision=self.expected_revision,
            expected_digest=self.expected_digest,
        )


class CohortRoleUpdate(ApiModel):
    role: ManifestRole
    selector_previews: list[SelectorPreview] = Field(
        alias="selectorPreviews",
        min_length=1,
        max_length=20,
    )
    member_count: int = Field(alias="memberCount", ge=1, le=1000)

    @model_validator(mode="after")
    def validate_selectors(self) -> CohortRoleUpdate:
        if len(self.role.selectors) != len(self.selector_previews):
            raise ValueError("role selectors must exactly match selector previews")
        for selector, preview in zip(
            self.role.selectors,
            self.selector_previews,
            strict=True,
        ):
            if selector != preview.selector:
                raise ValueError("role selectors must exactly match selector previews")
            if (
                preview.max_matches != len(preview.matched_resource_ids)
                or preview.selector.max_matches != preview.max_matches
            ):
                raise ValueError("selector maxMatches must exactly equal its member count")
        return self


class CohortReviewCandidate(ApiModel):
    candidate_id: str = Field(alias="candidateId", pattern=_ID_PATTERN)
    action: CohortPreviewAction
    source_draft: CohortDraftBinding = Field(alias="sourceDraft")
    scope: ProposalScope
    source_proposal_ids: list[str] = Field(
        alias="sourceProposalIds",
        min_length=1,
        max_length=200,
    )
    proposal_set_digest: str = Field(alias="proposalSetDigest", pattern=_DIGEST_PATTERN)
    snapshot: ProposalSnapshot
    role_updates: list[CohortRoleUpdate] = Field(
        alias="roleUpdates",
        min_length=1,
        max_length=200,
    )
    replace_role_refs: list[str] = Field(
        alias="replaceRoleRefs",
        min_length=1,
        max_length=200,
    )
    resolution: str = Field(min_length=12, max_length=2000)
    generated_at: AwareDatetime = Field(alias="generatedAt")
    expires_at: AwareDatetime = Field(alias="expiresAt")
    requires_human_review: Literal[True] = Field(True, alias="requiresHumanReview")
    publication_allowed: Literal[False] = Field(False, alias="publicationAllowed")
    manifest_mutated: Literal[False] = Field(False, alias="manifestMutated")


class CohortPreviewReceipt(ApiModel):
    actor_id: str = Field(pattern=_ID_PATTERN)
    idempotency_key: str = Field(pattern=_ID_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    evidence_binding: CohortEvidenceBinding
    candidate: CohortReviewCandidate


__all__ = [
    "CohortBatchCacheKey",
    "CohortDraftBinding",
    "CohortEvidenceBinding",
    "CohortPreviewReceipt",
    "CohortProposalBatchResponse",
    "CohortProposalQuery",
    "CohortReviewCandidate",
    "CohortReviewPreviewRequest",
    "CohortRoleUpdate",
    "ProfileType",
    "StoredEvidenceSnapshot",
    "normalized_identifier",
]
