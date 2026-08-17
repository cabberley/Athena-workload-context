from __future__ import annotations

from datetime import datetime, timedelta

from athena_context.api.authorization import authorize_role_grants
from athena_context.api.domain import (
    Actor,
    Permission,
    PublishedManifest,
    PublishedManifestView,
    RoleGrant,
)
from athena_context.api.errors import (
    AmbiguousLookupError,
    DemoEvaluationApprovalError,
    EvaluationFailedClosedError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_context import (
    resolve_active_manifest_profile,
    validate_demo_evaluation_approval,
    validate_published_context_binding,
)
from athena_context.api.evaluation_domain import (
    AuthorizationGrantToken,
    DemoEvaluationApproval,
    DemoEvaluationCommand,
    EvaluationAuthorityToken,
    PublishedContextSelection,
    ResolvedPublishedContext,
    build_published_context_authority_token,
)
from athena_context.api.evaluation_ports import (
    EvaluationArtifactPreparation,
    EvaluationAuthorityTransactionPort,
    EvaluationAuthorityUnitOfWorkPort,
    EvaluationCommitAuthorityCondition,
    EvaluationTemporalValidity,
    EvaluationTrustedKeyAuthority,
    StoredEvaluation,
)
from athena_context.api.ports import ContextTransactionPort
from athena_context.contracts import (
    AthenaValidationError,
    CanonicalWorkloadManifest,
    EvidenceSnapshot,
    ResolvedManifestProfile,
    TrustedKeyAnchor,
    resolve_manifest_profile,
)
from athena_context.contracts.common import normalize_nfc_text
from athena_context.contracts.manifest import EvidenceFreshnessProof


def build_evaluation_temporal_validity(
    snapshot: EvidenceSnapshot,
    *,
    approval: DemoEvaluationApproval,
    resolved_profile: ResolvedManifestProfile,
    manifest: CanonicalWorkloadManifest,
    as_of: datetime,
) -> EvaluationTemporalValidity:
    """Derive every insertion-time predicate from transaction-local authority."""

    profiles_by_id = {
        normalize_nfc_text(profile.profile_id).casefold(): profile
        for profile in manifest.profiles.values()
    }
    lineage_profiles = [
        profiles_by_id[normalize_nfc_text(profile_id).casefold()]
        for profile_id in resolved_profile.inheritance_chain
    ]
    active_overrides = [
        override
        for profile in lineage_profiles
        for override in profile.weakening_overrides
        if override.accepted_at <= as_of < override.expires_at
    ]
    exception_expiries = [
        relationship.expires_at
        for relationship in resolved_profile.relationships
        if hasattr(relationship, "expires_at")
    ]
    governance_starts = [
        override.accepted_at for override in active_overrides
    ]
    governance_expiries = [
        *(override.expires_at for override in active_overrides),
        *exception_expiries,
    ]
    risk_starts = [
        acceptance.accepted_at
        for acceptance in resolved_profile.risk_acceptances
    ]
    risk_expiries = [
        acceptance.expires_at
        for acceptance in resolved_profile.risk_acceptances
    ]
    freshness_deadlines = [
        snapshot.collected_at
        + timedelta(seconds=proof.maximum_age_seconds)
        for constraint in resolved_profile.constraints
        if isinstance(
            proof := constraint.proof_requirement,
            EvidenceFreshnessProof,
        )
    ]
    return EvaluationTemporalValidity(
        approval_active_from=approval.approved_at,
        approval_expires_at=approval.expires_at,
        snapshot_active_from=snapshot.collected_at,
        snapshot_expires_at=snapshot.expires_at,
        governance_active_from=(
            max(governance_starts) if governance_starts else None
        ),
        governance_expires_at=(
            min(governance_expiries) if governance_expiries else None
        ),
        risk_active_from=max(risk_starts) if risk_starts else None,
        risk_expires_at=min(risk_expiries) if risk_expiries else None,
        evidence_fresh_until=(
            min(freshness_deadlines) if freshness_deadlines else None
        ),
    )


class TransactionEvaluationAuthorityUnitOfWork:
    """Narrow authority view over one actual Context API transaction."""

    def __init__(
        self,
        *,
        context_transaction: ContextTransactionPort,
        evaluation_transaction: EvaluationAuthorityTransactionPort,
        reader_actor: Actor,
    ) -> None:
        self._context_transaction = context_transaction
        self._evaluation_transaction = evaluation_transaction
        self._reader_actor = reader_actor

    def resolve_context(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> tuple[ResolvedPublishedContext, AuthorizationGrantToken]:
        tx = self._context_transaction
        if selection.manifest_version is None:
            reader_authorization = self.authorize(
                self._reader_actor,
                Permission.LIST,
                selection.manifest_id,
            )
            active = [
                item
                for item in tx.list_published(manifest_id=selection.manifest_id)
                if tx.get_supersession(
                    item.manifest_id,
                    item.manifest_version,
                )
                is None
            ]
            if not active:
                raise ResourceNotFoundError(
                    "published manifest has no active version"
                )
            if len(active) != 1:
                raise AmbiguousLookupError(
                    "published manifest has multiple active versions"
                )
            published = active[0]
        else:
            published = self._require_published(
                tx,
                selection.manifest_id,
                selection.manifest_version,
            )
            reader_authorization = self.authorize(
                self._reader_actor,
                Permission.READ,
                selection.manifest_id,
            )
        view = PublishedManifestView(
            published=published,
            supersession=tx.get_supersession(
                published.manifest_id,
                published.manifest_version,
            ),
        )
        profile = resolve_manifest_profile(
            published.manifest,
            selection.profile_id,
            as_of=as_of,
        )
        return (
            ResolvedPublishedContext(
                view=view,
                profile=profile,
                authority_token=build_published_context_authority_token(
                    view,
                    profile,
                    requested_manifest_version=selection.manifest_version,
                ),
            ),
            reader_authorization,
        )

    def resolve_approval(
        self,
        decision_id: str,
    ) -> DemoEvaluationApproval | None:
        return self._evaluation_transaction.get_demo_evaluation_approval(
            decision_id
        )

    def put_approval(
        self,
        approval: DemoEvaluationApproval,
        *,
        expected_revision: int | None,
    ) -> None:
        self._evaluation_transaction.put_demo_evaluation_approval(
            approval,
            expected_revision=expected_revision,
        )

    def authorize(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str,
    ) -> AuthorizationGrantToken:
        grants, revision = self._evaluation_transaction.get_evaluation_grants()
        return authorize_role_grants(
            actor,
            permission,
            manifest_id,
            grants=grants,
            grant_revision=revision,
        )

    def get_grants(self) -> tuple[tuple[RoleGrant, ...], int]:
        return self._evaluation_transaction.get_evaluation_grants()

    def replace_grants(
        self,
        grants: tuple[RoleGrant, ...],
        *,
        expected_revision: int,
    ) -> int:
        return self._evaluation_transaction.replace_evaluation_grants(
            grants,
            expected_revision=expected_revision,
        )

    def load_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> StoredEvaluation | None:
        return self._evaluation_transaction.get_evaluation_receipt(
            actor_id,
            idempotency_key,
        )

    def load_artifact(self, snapshot_id: str) -> StoredEvaluation | None:
        return self._evaluation_transaction.get_evaluation_artifact(snapshot_id)

    def resolve_trusted_key(
        self,
        trusted_key_anchor: TrustedKeyAnchor,
    ) -> EvaluationTrustedKeyAuthority | None:
        return self._evaluation_transaction.get_demo_evaluation_trusted_key(
            trusted_key_anchor
        )

    def put_trusted_key(
        self,
        authority: EvaluationTrustedKeyAuthority,
        *,
        expected_revision: int,
    ) -> None:
        self._evaluation_transaction.put_demo_evaluation_trusted_key(
            authority,
            expected_revision=expected_revision,
        )

    def insert_evaluation_conditionally(
        self,
        condition: EvaluationCommitAuthorityCondition,
        artifact_preparation: EvaluationArtifactPreparation,
    ) -> StoredEvaluation:
        return self._evaluation_transaction.put_evaluation_conditionally(
            condition,
            artifact_preparation,
        )

    def list_evaluations(self) -> tuple[StoredEvaluation, ...]:
        return self._evaluation_transaction.list_evaluations()

    @staticmethod
    def _require_published(
        tx: ContextTransactionPort,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifest:
        published = tx.get_published(manifest_id, manifest_version)
        if published is None:
            raise ResourceNotFoundError(
                f"manifest version {manifest_id}/{manifest_version} was not found"
            )
        return published


def validate_trusted_key_authority(
    authority: EvaluationTrustedKeyAuthority,
    *,
    trusted_key_anchor: TrustedKeyAnchor,
    as_of: datetime,
) -> None:
    record = authority.record
    if (
        record.anchor != trusted_key_anchor
        or not record.enabled
        or record.activated_at > as_of
        or (
            record.retired_at is not None
            and record.retired_at <= as_of
        )
        or (
            record.expires_at is not None
            and record.expires_at <= as_of
        )
        or (
            authority.revoked_at is not None
            and authority.revoked_at <= as_of
        )
    ):
        raise EvaluationFailedClosedError(
            "trusted signing key is disabled, retired, expired, revoked, "
            "or not active at publication time"
        )


def validate_loaded_evaluation_authority(
    *,
    actor: Actor,
    command: DemoEvaluationCommand,
    approval: DemoEvaluationApproval,
    resolved: ResolvedPublishedContext,
    authorization: AuthorizationGrantToken,
    context_reader_authorization: AuthorizationGrantToken,
    as_of: datetime,
    private_mcp_endpoint: str,
    evidence_identity_object_id: str,
    trusted_key: EvaluationTrustedKeyAuthority,
    trusted_key_anchor: TrustedKeyAnchor,
    expected_authority: EvaluationAuthorityToken | None,
) -> tuple[
    DemoEvaluationApproval,
    ResolvedPublishedContext,
    EvaluationAuthorityToken,
]:
    """Purely validate one transaction-local complete authority snapshot."""

    validate_demo_evaluation_approval(
        actor,
        command,
        approval,
        as_of=as_of,
        private_mcp_endpoint=private_mcp_endpoint,
        evidence_identity_object_id=evidence_identity_object_id,
    )
    validate_trusted_key_authority(
        trusted_key,
        trusted_key_anchor=trusted_key_anchor,
        as_of=as_of,
    )
    selection = PublishedContextSelection(
        manifest_id=command.manifest_id,
        manifest_version=command.manifest_version,
        profile_id=command.profile_id,
    )
    if expected_authority is not None:
        expected_selection_mode = (
            "uniqueActiveVersion"
            if command.manifest_version is None
            else "exactVersion"
        )
        if expected_authority.context.selection_mode != expected_selection_mode:
            raise EvaluationFailedClosedError(
                "published context authority token changed selection mode"
            )
    try:
        if resolved.view.supersession is not None:
            raise AthenaValidationError(
                "superseded context cannot authorize evaluation"
            )
        profile = resolve_active_manifest_profile(
            resolved.view.published.manifest,
            selection.profile_id,
            as_of=as_of,
        )
    except (AthenaValidationError, ValueError) as exc:
        raise EvaluationFailedClosedError(
            "published context/profile is missing, ambiguous, a superseded "
            "context, or has inactive governance"
        ) from exc
    current_context = ResolvedPublishedContext(
        view=resolved.view,
        profile=profile,
        authority_token=build_published_context_authority_token(
            resolved.view,
            profile,
            requested_manifest_version=selection.manifest_version,
        ),
    )
    validate_published_context_binding(command, approval, current_context)
    authority = EvaluationAuthorityToken(
        context=current_context.authority_token,
        approval=approval.authority_token(),
        authorization=authorization,
        context_reader_authorization=context_reader_authorization,
        trusted_key=trusted_key.authority_token(),
    )
    if expected_authority is not None and authority != expected_authority:
        raise EvaluationFailedClosedError(
            "evaluation authority revision changed before publication"
        )
    return approval, current_context, authority


def resolve_transaction_evaluation_authority(
    unit_of_work: EvaluationAuthorityUnitOfWorkPort,
    *,
    actor: Actor,
    command: DemoEvaluationCommand,
    as_of: datetime,
    private_mcp_endpoint: str,
    evidence_identity_object_id: str,
    trusted_key_anchor: TrustedKeyAnchor,
    expected_authority: EvaluationAuthorityToken | None = None,
) -> tuple[
    DemoEvaluationApproval,
    ResolvedPublishedContext,
    EvaluationAuthorityToken,
]:
    """Resolve and validate every authority from one transaction-local state."""

    authorization = unit_of_work.authorize(
        actor,
        Permission.PUBLISH,
        command.manifest_id,
    )
    approval = unit_of_work.resolve_approval(command.approval_decision_id)
    if approval is None:
        raise DemoEvaluationApprovalError(
            "trusted demo evaluation approval decision was not found"
        )
    selection = PublishedContextSelection(
        manifest_id=command.manifest_id,
        manifest_version=command.manifest_version,
        profile_id=command.profile_id,
    )
    try:
        resolved, reader_authorization = unit_of_work.resolve_context(
            selection,
            as_of=as_of,
        )
    except (
        AmbiguousLookupError,
        AthenaValidationError,
        ResourceNotFoundError,
        ValueError,
    ) as exc:
        raise EvaluationFailedClosedError(
            "published context/profile is missing, ambiguous, a superseded "
            "context, or has inactive governance"
        ) from exc
    trusted_key = unit_of_work.resolve_trusted_key(trusted_key_anchor)
    if trusted_key is None:
        raise EvaluationFailedClosedError(
            "authoritative demo evaluation signing key was not found"
        )
    return validate_loaded_evaluation_authority(
        actor=actor,
        command=command,
        approval=approval,
        resolved=resolved,
        authorization=authorization,
        context_reader_authorization=reader_authorization,
        as_of=as_of,
        private_mcp_endpoint=private_mcp_endpoint,
        evidence_identity_object_id=evidence_identity_object_id,
        trusted_key=trusted_key,
        trusted_key_anchor=trusted_key_anchor,
        expected_authority=expected_authority,
    )
