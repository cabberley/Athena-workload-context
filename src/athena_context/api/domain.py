from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from athena_context.contracts.manifest import CanonicalWorkloadManifest

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ActorKind(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"


class Actor(ApiModel):
    actor_id: str = Field(pattern=_ID_PATTERN)
    kind: ActorKind


class Role(StrEnum):
    PROPOSER = "proposer"
    REVIEWER = "reviewer"
    APPROVER = "approver"
    PUBLISHER = "publisher"
    READER = "reader"
    AUDITOR = "auditor"


class Permission(StrEnum):
    CREATE_DRAFT = "create_draft"
    READ = "read"
    LIST = "list"
    UPDATE_DRAFT = "update_draft"
    VALIDATE = "validate"
    SUBMIT = "submit"
    APPROVE = "approve"
    PUBLISH = "publish"
    SUPERSEDE = "supersede"
    AUDIT = "audit"


class RoleGrant(ApiModel):
    actor_id: str = Field(pattern=_ID_PATTERN)
    role: Role
    manifest_id: str = Field(default="*", min_length=1, max_length=128)


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
    DRAFT_APPROVED = "draft_approved"
    VERSION_PUBLISHED = "version_published"
    VERSION_SUPERSEDED = "version_superseded"


class ValidationRecord(ApiModel):
    validated_by: Actor
    validated_at: AwareDatetime
    validated_revision: int = Field(ge=1)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)


class ReviewSubmission(ApiModel):
    submitted_by: Actor
    submitted_at: AwareDatetime
    submitted_revision: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=500)


class ApprovalDecision(ApiModel):
    decision_id: str = Field(pattern=_ID_PATTERN)
    approved_by: Actor
    approved_at: AwareDatetime
    approved_revision: int = Field(ge=1)
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)


class DraftRecord(ApiModel):
    draft_id: str = Field(pattern=_ID_PATTERN)
    manifest_id: str = Field(min_length=1, max_length=128)
    state: DraftState
    revision: int = Field(ge=1)
    manifest: CanonicalWorkloadManifest
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    previous_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    created_by: Actor
    created_at: AwareDatetime
    updated_by: Actor
    updated_at: AwareDatetime
    reason: str = Field(min_length=3, max_length=500)
    validation: ValidationRecord | None = None
    review: ReviewSubmission | None = None
    approval: ApprovalDecision | None = None


class PublishedManifest(ApiModel):
    manifest_id: str = Field(min_length=1, max_length=128)
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    manifest: CanonicalWorkloadManifest
    source_draft_id: str = Field(pattern=_ID_PATTERN)
    source_draft_revision: int = Field(ge=1)
    previous_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    approval: ApprovalDecision
    published_by: Actor
    published_at: AwareDatetime
    reason: str = Field(min_length=3, max_length=500)


class Supersession(ApiModel):
    manifest_id: str = Field(min_length=1, max_length=128)
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
    manifest_id: str = Field(min_length=1, max_length=128)
    draft_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    revision: int | None = Field(default=None, ge=1)
    previous_revision: int | None = Field(default=None, ge=1)
    manifest_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    previous_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    replacement_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)


class AuditEvent(PendingAuditEvent):
    sequence: int = Field(ge=1)
    event_id: str = Field(pattern=r"^audit-[0-9]{8}$")


class MutationReceipt(ApiModel):
    actor_id: str = Field(pattern=_ID_PATTERN)
    idempotency_key: str = Field(pattern=_ID_PATTERN)
    operation: str = Field(min_length=1, max_length=64)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    response_type: str = Field(min_length=1, max_length=128)
    response_json: str = Field(min_length=2)


class CreateDraftCommand(ApiModel):
    draft_id: str = Field(pattern=_ID_PATTERN)
    manifest: CanonicalWorkloadManifest
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    previous_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    reason: str = Field(min_length=3, max_length=500)


class ReplaceDraftCommand(ApiModel):
    expected_revision: int = Field(ge=1)
    expected_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    expected_digest: str = Field(pattern=_DIGEST_PATTERN)
    replacement_manifest: CanonicalWorkloadManifest
    replacement_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)


class TransitionCommand(ApiModel):
    expected_revision: int = Field(ge=1)
    expected_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    expected_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)


class PublishCommand(TransitionCommand):
    approval_id: str = Field(pattern=_ID_PATTERN)


class SupersedeCommand(ApiModel):
    expected_revision: int = Field(ge=1)
    expected_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    expected_digest: str = Field(pattern=_DIGEST_PATTERN)
    replacement_version: str = Field(pattern=_VERSION_PATTERN)
    replacement_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)


class VersionComparison(ApiModel):
    manifest_id: str
    from_version: str = Field(pattern=_VERSION_PATTERN)
    to_version: str = Field(pattern=_VERSION_PATTERN)
    from_digest: str = Field(pattern=_DIGEST_PATTERN)
    to_digest: str = Field(pattern=_DIGEST_PATTERN)
    equivalent: bool
    changed_paths: list[str]


def ensure_timestamp(value: datetime) -> datetime:
    """Validate and normalize an injected timestamp without consulting wall-clock time."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("injected clock must return a timezone-aware timestamp")
    if value.microsecond % 1000:
        raise ValueError("injected clock timestamp must have millisecond precision")
    return value.astimezone(UTC)
