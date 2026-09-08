from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from athena_context.api.cohort_domain import (
    CohortDraftBinding,
    CohortReviewCandidate,
    ProfileType,
    canonical_proposal_ids,
    normalized_identifier,
)
from athena_context.api.domain import (
    Actor,
    ApiModel,
    ReplaceDraftCommand,
    WorkloadIdentifier,
)
from athena_context.binding.domain import ProposalScope, ProposalSnapshot
from athena_context.contracts.common import (
    compute_artifact_digest,
    normalize_nfc_text,
)
from athena_context.contracts.manifest import (
    ManifestRole,
    is_guarded_selector_replacement_narrower,
)

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"


class CohortDecisionKind(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    SPLIT = "split"
    MERGE = "merge"


class CohortDecisionApplyBinding(ApiModel):
    """Immutable provenance and selector binding for one intended apply."""

    decision_id: str
    decision: CohortDecisionKind
    decided_at: AwareDatetime
    actor: Actor
    candidate_id: str
    candidate_digest: str
    manifest_id: str
    manifest_version: str
    profile_id: str
    resolved_profile_digest: str
    source_draft: CohortDraftBinding
    current_draft: CohortDraftBinding
    resulting_draft: CohortDraftBinding
    proposal_ids: list[str]
    proposal_set_digest: str
    snapshot_artifact_digest: str
    target_role_id: str
    inherited_role_digest: str
    replacement_role_digest: str
    replacement_selector_provenance_digest: str = Field(
        pattern=_DIGEST_PATTERN,
    )
    retained_replacement_role_digests: tuple[tuple[str, str, str], ...]
    replacement_manifest_digest: str

    @field_validator("proposal_ids")
    @classmethod
    def validate_proposal_ids(cls, values: list[str]) -> list[str]:
        canonical = canonical_proposal_ids(values)
        if values != canonical:
            raise ValueError("apply proposal_ids must use canonical proposal order")
        return values


class CohortDecisionApplyAuthorization(ApiModel):
    """Persisted approval required before the draft transaction may mutate."""

    status: Literal["approved"] = "approved"
    binding: CohortDecisionApplyBinding
    mutation_digest: str = Field(
        alias="mutationDigest",
        pattern=_DIGEST_PATTERN,
    )

    @classmethod
    def issue(
        cls,
        binding: CohortDecisionApplyBinding,
        command: ReplaceDraftCommand,
    ) -> CohortDecisionApplyAuthorization:
        return cls(
            binding=binding,
            mutationDigest=compute_artifact_digest(
                {
                    "operation": "cohort_decision_apply",
                    "status": "approved",
                    "binding": binding.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    ),
                    "command": command.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    ),
                }
            ),
        )

    def authorizes(self, command: ReplaceDraftCommand) -> bool:
        expected = type(self).issue(self.binding, command)
        return self.status == "approved" and self.mutation_digest == (
            expected.mutation_digest
        )


def _selector_binding_permits(
    binding: CohortDecisionApplyBinding,
    *,
    manifest_id: str,
    manifest_version: str,
    profile_id: str,
    inherited_role: ManifestRole,
    replacement_role: ManifestRole,
) -> bool:
    """Evaluate selector policy data without making it mutation authority."""

    inherited_digest = compute_artifact_digest(
        inherited_role.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    )
    replacement_digest = compute_artifact_digest(
        replacement_role.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    )
    exact_candidate = (
        binding.decision
        in {
            CohortDecisionKind.SPLIT,
            CohortDecisionKind.MERGE,
        }
        and normalized_identifier(inherited_role.role_id)
        == normalized_identifier(binding.target_role_id)
        and normalized_identifier(replacement_role.role_id)
        == normalized_identifier(binding.target_role_id)
        and inherited_digest == binding.inherited_role_digest
        and replacement_digest == binding.replacement_role_digest
    )
    retained_from_current_draft = (
        normalized_identifier(profile_id),
        normalized_identifier(replacement_role.role_id),
        replacement_digest,
    ) in binding.retained_replacement_role_digests
    return (
        binding.decision
        in {
            CohortDecisionKind.APPROVE,
            CohortDecisionKind.SPLIT,
            CohortDecisionKind.MERGE,
        }
        and normalized_identifier(manifest_id)
        == normalized_identifier(binding.manifest_id)
        and manifest_version == binding.manifest_version
        and normalized_identifier(profile_id)
        == normalized_identifier(binding.profile_id)
        and (exact_candidate or retained_from_current_draft)
        and is_guarded_selector_replacement_narrower(
            inherited_role.selectors,
            replacement_role.selectors,
        )
    )


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
        return canonical_proposal_ids(values)

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


class CohortRejectionAuthority(ApiModel):
    """Partition-independent role/selector and member rejection authority."""

    selector_role_fingerprint: str = Field(
        alias="selectorRoleFingerprint",
        pattern=_DIGEST_PATTERN,
    )
    member_fingerprints: list[str] = Field(
        alias="memberFingerprints",
        min_length=1,
        max_length=1000,
    )

    @field_validator("member_fingerprints")
    @classmethod
    def validate_member_fingerprints(
        cls,
        values: list[str],
    ) -> list[str]:
        if (
            values != sorted(values)
            or len(values) != len(set(values))
            or any(
                not value.startswith("sha256:")
                or len(value) != 71
                or any(
                    character not in "0123456789abcdef"
                    for character in value[7:]
                )
                for value in values
            )
        ):
            raise ValueError(
                "member_fingerprints must be canonical unique digests"
            )
        return values


def rejection_authorities_overlap(
    left: list[CohortRejectionAuthority],
    right: list[CohortRejectionAuthority],
) -> bool:
    """Return whether two selections cover any member under the same authority."""

    right_members = {
        authority.selector_role_fingerprint: set(
            authority.member_fingerprints
        )
        for authority in right
    }
    return any(
        set(authority.member_fingerprints).intersection(
            right_members.get(authority.selector_role_fingerprint, set())
        )
        for authority in left
    )


class CohortProposalSetVersion(ApiModel):
    """Exact stale-apply binding plus stable authority fingerprints.

    The batch input digest is retained on the decision record for audit, but is
    intentionally absent here because it includes proposal evaluation time.
    Exact batch, snapshot, profile, and source-draft coordinates remain stale
    application bindings. Rejection and overlap arbitration uses only the
    normalized workload/profile and selector/role/member fingerprints.
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
    source_rejection_authorities: list[CohortRejectionAuthority] = Field(
        alias="sourceRejectionAuthorities",
        min_length=1,
        max_length=200,
    )

    @field_validator("source_proposal_ids")
    @classmethod
    def validate_canonical_proposal_set(cls, values: list[str]) -> list[str]:
        canonical = canonical_proposal_ids(values)
        if values != canonical:
            raise ValueError(
                "source_proposal_ids must be a canonical unique proposal set"
            )
        return values

    @field_validator("source_rejection_authorities")
    @classmethod
    def validate_canonical_rejection_authorities(
        cls,
        values: list[CohortRejectionAuthority],
    ) -> list[CohortRejectionAuthority]:
        fingerprints = [
            authority.selector_role_fingerprint
            for authority in values
        ]
        if (
            fingerprints != sorted(fingerprints)
            or len(fingerprints) != len(set(fingerprints))
        ):
            raise ValueError(
                "source_rejection_authorities must use canonical unique "
                "selector/role fingerprints"
            )
        return values

    @model_validator(mode="after")
    def validate_authority_members(self) -> CohortProposalSetVersion:
        member_fingerprints = [
            member
            for authority in self.source_rejection_authorities
            for member in authority.member_fingerprints
        ]
        if (
            len(member_fingerprints) > 1000
            or len(member_fingerprints) != len(set(member_fingerprints))
        ):
            raise ValueError(
                "selected rejection authority members must be globally unique "
                "and bounded"
            )
        return self

    def authority_overlap_identity(
        self,
    ) -> tuple[str, str]:
        """Return stable workload/profile scope for rejection arbitration."""

        return (
            normalized_identifier(self.manifest_id),
            normalized_identifier(self.profile_id),
        )

    def batch_overlap_identity(
        self,
    ) -> tuple[str, str, str, str, str, str]:
        """Return exact immutable batch coordinates for non-reject decisions."""

        return (
            normalized_identifier(self.manifest_id),
            self.manifest_version,
            normalized_identifier(self.profile_id),
            self.resolved_profile_digest,
            self.proposal_set_digest,
            self.snapshot_artifact_digest,
        )

    def authority_selected_identity(self) -> tuple[str, ...]:
        """Return exact batch scope and canonical selected proposal IDs."""

        return (
            *self.batch_overlap_identity(),
            *self.source_proposal_ids,
        )


class CohortDecisionAudit(ApiModel):
    audit_id: str = Field(alias="auditId", pattern=_ID_PATTERN)
    action: Literal["cohort_decision_recorded"] = Field(
        default="cohort_decision_recorded",
    )
    decision_id: str = Field(alias="decisionId", pattern=_ID_PATTERN)
    actor: Actor
    occurred_at: AwareDatetime = Field(alias="occurredAt")
    source_revision: int = Field(alias="sourceRevision", ge=1)
    source_proposal_ids: list[str] = Field(
        alias="sourceProposalIds",
        min_length=1,
        max_length=200,
    )
    resulting_revision: int | None = Field(
        default=None,
        alias="resultingRevision",
        ge=1,
    )
    draft_mutated: bool = Field(alias="draftMutated")

    @field_validator("source_proposal_ids")
    @classmethod
    def validate_source_proposal_ids(cls, values: list[str]) -> list[str]:
        canonical = canonical_proposal_ids(values)
        if values != canonical:
            raise ValueError("audit sourceProposalIds must use canonical proposal order")
        return values


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
    source_rejection_authorities: list[CohortRejectionAuthority] = Field(
        alias="sourceRejectionAuthorities",
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
    apply_authorization: CohortDecisionApplyAuthorization | None = Field(
        default=None,
        alias="applyAuthorization",
    )
    rationale: str = Field(min_length=1, max_length=2000)
    decided_by: Actor = Field(alias="decidedBy")
    decided_at: AwareDatetime = Field(alias="decidedAt")
    audit: CohortDecisionAudit
    publication_allowed: Literal[False] = Field(False, alias="publicationAllowed")
    role_metadata_mutated: Literal[False] = Field(False, alias="roleMetadataMutated")

    @field_validator("source_proposal_ids")
    @classmethod
    def validate_source_proposal_ids(cls, values: list[str]) -> list[str]:
        canonical = canonical_proposal_ids(values)
        if values != canonical:
            raise ValueError("sourceProposalIds must use canonical proposal order")
        return values

    @field_validator("source_rejection_authorities")
    @classmethod
    def validate_source_rejection_authorities(
        cls,
        values: list[CohortRejectionAuthority],
    ) -> list[CohortRejectionAuthority]:
        fingerprints = [
            authority.selector_role_fingerprint
            for authority in values
        ]
        if (
            fingerprints != sorted(fingerprints)
            or len(fingerprints) != len(set(fingerprints))
        ):
            raise ValueError(
                "sourceRejectionAuthorities must use canonical unique "
                "selector/role fingerprints"
            )
        return values

    @model_validator(mode="after")
    def validate_outcome(self) -> CohortDecisionRecord:
        rejected = self.decision is CohortDecisionKind.REJECT
        member_fingerprints = [
            member
            for authority in self.source_rejection_authorities
            for member in authority.member_fingerprints
        ]
        if (
            len(member_fingerprints) > 1000
            or len(member_fingerprints) != len(set(member_fingerprints))
        ):
            raise ValueError(
                "selected rejection authority members must be globally unique "
                "and bounded"
            )
        if rejected != (self.applied_draft is None):
            raise ValueError("only reject decisions may omit an applied draft")
        if rejected != (self.candidate_id is None):
            raise ValueError("only reject decisions may omit a candidate")
        if rejected != (self.candidate_digest is None):
            raise ValueError("only reject decisions may omit a candidate digest")
        if rejected != (self.apply_authorization is None):
            raise ValueError("only reject decisions may omit apply authorization")
        if self.apply_authorization is not None:
            binding = self.apply_authorization.binding
            if (
                binding.decision_id != self.decision_id
                or binding.decision is not self.decision
                or binding.decided_at != self.decided_at
                or binding.actor != self.decided_by
                or binding.candidate_id != self.candidate_id
                or binding.candidate_digest != self.candidate_digest
                or binding.manifest_id != self.manifest_id
                or binding.manifest_version != self.manifest_version
                or normalized_identifier(binding.profile_id)
                != normalized_identifier(self.profile_id)
                or binding.resolved_profile_digest
                != self.resolved_profile_digest
                or binding.source_draft != self.source_draft
                or binding.resulting_draft != self.applied_draft
                or binding.proposal_ids != self.source_proposal_ids
                or binding.proposal_set_digest != self.proposal_set_digest
                or binding.snapshot_artifact_digest
                != self.snapshot.artifact_digest
                or normalized_identifier(binding.target_role_id)
                not in {
                    normalized_identifier(role_ref)
                    for role_ref in self.source_role_refs
                }
            ):
                raise ValueError(
                    "cohort apply authorization is inconsistent with its decision"
                )
        if (
            self.audit.decision_id != self.decision_id
            or self.audit.actor != self.decided_by
            or self.audit.occurred_at != self.decided_at
            or self.audit.source_revision != self.source_draft.revision
            or self.audit.source_proposal_ids != self.source_proposal_ids
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
            sourceProposalIds=self.source_proposal_ids,
            sourceRejectionAuthorities=self.source_rejection_authorities,
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
    "CohortRejectionAuthority",
    "decision_response",
    "rejection_authorities_overlap",
]
