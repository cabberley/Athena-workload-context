from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from athena_context.contracts.manifest import CanonicalWorkloadManifest

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"


def ensure_concrete_workload_id(value: str) -> str:
    if value == "*":
        raise ValueError("'*' is reserved for typed all-workloads grant scope")
    if re.fullmatch(_ID_PATTERN, value) is None:
        raise ValueError(
            "workload identifier must use route-safe ASCII letters, digits, '.', '_', or '-'"
        )
    return value


type WorkloadIdentifier = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128),
    AfterValidator(ensure_concrete_workload_id),
    Field(
        json_schema_extra={
            "not": {"const": "*"},
            "pattern": _ID_PATTERN,
        }
    ),
]


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ActorKind(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"


class Actor(ApiModel):
    actor_id: str = Field(pattern=_ID_PATTERN)
    kind: ActorKind


class AuthenticationMethod(StrEnum):
    ENTRA_JWT = "entra_jwt"
    TEST = "test"


class VerifiedAuthentication(ApiModel):
    """Identity produced only after an authentication adapter verifies credentials."""

    actor: Actor
    subject_id: str = Field(min_length=1, max_length=256)
    issuer: str = Field(min_length=1, max_length=512)
    audience: str = Field(min_length=1, max_length=256)
    method: AuthenticationMethod


class Role(StrEnum):
    PROPOSER = "proposer"
    REVIEWER = "reviewer"
    APPROVER = "approver"
    PUBLISHER = "publisher"
    READER = "reader"
    AUDITOR = "auditor"
    OPERATIONAL_CONTEXT_ISSUER = "operational_context_issuer"


class Permission(StrEnum):
    CREATE_DRAFT = "create_draft"
    READ = "read"
    LIST = "list"
    UPDATE_DRAFT = "update_draft"
    VALIDATE = "validate"
    SUBMIT = "submit"
    REVIEW = "review"
    APPROVE = "approve"
    PUBLISH = "publish"
    SUPERSEDE = "supersede"
    AUDIT = "audit"
    ISSUE_OPERATIONAL_CONTEXT = "issue_operational_context"


class AllWorkloadsGrantScope(ApiModel):
    scope_type: Literal["all_workloads"] = "all_workloads"


class WorkloadGrantScope(ApiModel):
    scope_type: Literal["workload"] = "workload"
    workload_id: WorkloadIdentifier


type GrantScope = Annotated[
    AllWorkloadsGrantScope | WorkloadGrantScope,
    Field(discriminator="scope_type"),
]


class RoleGrant(ApiModel):
    actor_id: str = Field(pattern=_ID_PATTERN)
    role: Role
    scope: GrantScope = Field(default_factory=AllWorkloadsGrantScope)


class DraftState(StrEnum):
    DRAFT = "draft"
    VALIDATED = "validated"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    PUBLISHED = "published"
    SUPERSEDED = "superseded"


class AuditAction(StrEnum):
    DRAFT_CREATED = "draft_created"
    DRAFT_REPLACED = "draft_replaced"
    DRAFT_VALIDATED = "draft_validated"
    REVIEW_SUBMITTED = "review_submitted"
    REVIEW_RECORDED = "review_recorded"
    DRAFT_APPROVED = "draft_approved"
    VERSION_PUBLISHED = "version_published"
    VERSION_SUPERSEDED = "version_superseded"
    DEMO_EVALUATION_APPROVAL_CREATED = "demo_evaluation_approval_created"
    DEMO_EVALUATION_APPROVAL_REVOKED = "demo_evaluation_approval_revoked"
    COHORT_DECISION_RECORDED = "cohort_decision_recorded"


class ValidationRecord(ApiModel):
    validated_by: Actor
    validated_at: AwareDatetime
    validated_revision: int = Field(ge=1)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)


class ReviewSubmission(ApiModel):
    submitted_by: Actor
    submitted_at: AwareDatetime
    submitted_revision: int = Field(ge=1)
    publication_candidate_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)


class PublicationCandidate(ApiModel):
    finalized_by: Actor
    finalized_at: AwareDatetime
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    semantic_digest: str = Field(pattern=_DIGEST_PATTERN)
    approval_status: Literal["approved"]


class ReviewDecisionKind(StrEnum):
    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"


class ReviewDecision(ApiModel):
    decision_id: str = Field(pattern=_ID_PATTERN)
    decision: ReviewDecisionKind
    reviewed_by: Actor
    reviewed_at: AwareDatetime
    reviewed_revision: int = Field(ge=1)
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    comments: str = Field(min_length=3, max_length=2000)
    rejected_fields: list[str] = Field(default_factory=list, max_length=100)
    required_corrections: list[str] = Field(
        default_factory=list,
        max_length=100,
    )


class ApprovalDecision(ApiModel):
    decision_id: str = Field(pattern=_ID_PATTERN)
    approved_by: Actor
    approved_at: AwareDatetime
    approved_revision: int = Field(ge=1)
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    review_decision_id: str | None = Field(
        default=None,
        pattern=_ID_PATTERN,
    )
    operational_context_receipt_id: str | None = Field(
        default=None,
        pattern=_ID_PATTERN,
    )
    reason: str = Field(min_length=3, max_length=500)


class DraftRecord(ApiModel):
    draft_id: str = Field(pattern=_ID_PATTERN)
    manifest_id: WorkloadIdentifier
    state: DraftState
    revision: int = Field(ge=1)
    manifest: CanonicalWorkloadManifest
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    previous_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    rollback_source_version: str | None = Field(
        default=None,
        pattern=_VERSION_PATTERN,
    )
    created_by: Actor
    created_at: AwareDatetime
    updated_by: Actor
    updated_at: AwareDatetime
    reason: str = Field(min_length=3, max_length=500)
    validation: ValidationRecord | None = None
    review: ReviewSubmission | None = None
    publication_candidate: PublicationCandidate | None = None
    review_decisions: list[ReviewDecision] = Field(
        default_factory=list,
        max_length=100,
    )
    approval: ApprovalDecision | None = None


class PublishedManifest(ApiModel):
    manifest_id: WorkloadIdentifier
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    manifest: CanonicalWorkloadManifest
    source_draft_id: str = Field(pattern=_ID_PATTERN)
    source_draft_revision: int = Field(ge=1)
    previous_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    approval: ApprovalDecision
    published_by: Actor
    published_at: AwareDatetime
    publication_authorized_by: Actor
    publication_authorized_at: AwareDatetime
    operational_context_receipt_id: str | None = Field(
        default=None,
        pattern=_ID_PATTERN,
    )
    reason: str = Field(min_length=3, max_length=500)


class Supersession(ApiModel):
    manifest_id: WorkloadIdentifier
    superseded_version: str = Field(pattern=_VERSION_PATTERN)
    replacement_version: str = Field(pattern=_VERSION_PATTERN)
    superseded_by: Actor
    superseded_at: AwareDatetime
    reason: str = Field(min_length=3, max_length=500)


class PublishedManifestView(ApiModel):
    published: PublishedManifest
    supersession: Supersession | None


class PendingAuditEvent(ApiModel):
    occurred_at: AwareDatetime
    actor: Actor
    action: AuditAction
    manifest_id: WorkloadIdentifier
    draft_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    revision: int | None = Field(default=None, ge=1)
    previous_revision: int | None = Field(default=None, ge=1)
    manifest_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    previous_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    replacement_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    publication_actor: Actor | None = None
    publication_timestamp: AwareDatetime | None = None
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)


class AuditEvent(PendingAuditEvent):
    sequence: int = Field(ge=1)
    event_id: str = Field(pattern=r"^audit-[0-9]{8}$")
    previous_event_digest: str | None = Field(
        default=None,
        pattern=_DIGEST_PATTERN,
    )
    event_digest: str = Field(pattern=_DIGEST_PATTERN)


class MutationTarget(ApiModel):
    draft_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    manifest_id: WorkloadIdentifier | None = None
    manifest_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)

    @model_validator(mode="after")
    def validate_target(self) -> MutationTarget:
        if self.draft_id is None and self.manifest_id is None:
            raise ValueError("mutation target requires a draft_id or manifest_id")
        if self.manifest_version is not None and self.manifest_id is None:
            raise ValueError("manifest_version target requires manifest_id")
        return self


class MutationReceipt(ApiModel):
    actor_id: str = Field(pattern=_ID_PATTERN)
    idempotency_key: str = Field(pattern=_ID_PATTERN)
    operation: str = Field(min_length=1, max_length=64)
    target: MutationTarget
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    response_type: str = Field(min_length=1, max_length=128)
    response_json: str = Field(min_length=2)


class CreateDraftCommand(ApiModel):
    draft_id: str = Field(pattern=_ID_PATTERN)
    manifest: CanonicalWorkloadManifest
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    previous_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    rollback_source_version: str | None = Field(
        default=None,
        pattern=_VERSION_PATTERN,
    )
    reason: str = Field(min_length=3, max_length=500)

    @model_validator(mode="after")
    def validate_manifest_id(self) -> CreateDraftCommand:
        ensure_concrete_workload_id(self.manifest.manifest_id)
        if self.rollback_source_version is not None:
            if self.previous_version is None:
                raise ValueError(
                    "rollback_source_version requires the active previous_version"
                )
            if self.rollback_source_version == self.previous_version:
                raise ValueError(
                    "rollback_source_version must identify an older version"
                )
        return self


class ReplaceDraftCommand(ApiModel):
    expected_revision: int = Field(ge=1)
    expected_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    expected_digest: str = Field(pattern=_DIGEST_PATTERN)
    replacement_manifest: CanonicalWorkloadManifest
    replacement_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)

    @model_validator(mode="after")
    def validate_manifest_id(self) -> ReplaceDraftCommand:
        ensure_concrete_workload_id(self.replacement_manifest.manifest_id)
        return self


class TransitionCommand(ApiModel):
    expected_revision: int = Field(ge=1)
    expected_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    expected_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)


class ReviewCommand(TransitionCommand):
    decision: ReviewDecisionKind = Field(strict=False)
    comments: str = Field(min_length=3, max_length=2000)
    rejected_fields: list[str] = Field(default_factory=list, max_length=100)
    required_corrections: list[str] = Field(
        default_factory=list,
        max_length=100,
    )

    @model_validator(mode="after")
    def validate_review_details(self) -> ReviewCommand:
        if len(self.rejected_fields) != len(set(self.rejected_fields)):
            raise ValueError("rejected_fields must be unique")
        if len(self.required_corrections) != len(
            set(self.required_corrections)
        ):
            raise ValueError("required_corrections must be unique")
        if any(
            not field.startswith("/") or len(field) > 512
            for field in self.rejected_fields
        ):
            raise ValueError(
                "rejected_fields must be bounded JSON pointer paths"
            )
        if any(
            not correction.strip()
            or correction != correction.strip()
            or len(correction) > 500
            for correction in self.required_corrections
        ):
            raise ValueError(
                "required_corrections must be bounded trimmed text"
            )
        if (
            self.decision is ReviewDecisionKind.APPROVED
            and (self.rejected_fields or self.required_corrections)
        ):
            raise ValueError(
                "approved reviews cannot declare rejected fields or corrections"
            )
        if (
            self.decision is ReviewDecisionKind.CHANGES_REQUESTED
            and not self.required_corrections
        ):
            raise ValueError(
                "changes_requested reviews require explicit corrections"
            )
        return self


class ApproveCommand(TransitionCommand):
    operational_context_receipt_id: str = Field(pattern=_ID_PATTERN)


class PublishCommand(TransitionCommand):
    approval_id: str = Field(pattern=_ID_PATTERN)
    operational_context_receipt_id: str = Field(pattern=_ID_PATTERN)


class SupersedeCommand(ApiModel):
    expected_revision: int = Field(ge=1)
    expected_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    expected_digest: str = Field(pattern=_DIGEST_PATTERN)
    replacement_version: str = Field(pattern=_VERSION_PATTERN)
    replacement_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)


class VersionComparison(ApiModel):
    manifest_id: WorkloadIdentifier
    from_version: str = Field(pattern=_VERSION_PATTERN)
    to_version: str = Field(pattern=_VERSION_PATTERN)
    from_digest: str = Field(pattern=_DIGEST_PATTERN)
    to_digest: str = Field(pattern=_DIGEST_PATTERN)
    equivalent: bool
    changed_paths: list[str]


class ResolvedProfileAuthority(ApiModel):
    manifest_id: WorkloadIdentifier
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    resolved_profile_digest: str = Field(pattern=_DIGEST_PATTERN)


def ensure_timestamp(value: datetime) -> datetime:
    """Validate and normalize an injected timestamp without consulting wall-clock time."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("injected clock must return a timezone-aware timestamp")
    if value.microsecond % 1000:
        raise ValueError("injected clock timestamp must have millisecond precision")
    return value.astimezone(UTC)
