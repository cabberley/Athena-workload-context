from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from athena_context.api.cohort_decision_domain import (
    CohortDecisionApplyAuthorization,
    CohortDecisionApplyBinding,
    CohortDecisionAudit,
    CohortDecisionKind,
    CohortDecisionReceipt,
    CohortDecisionRecord,
    CohortDecisionRequest,
    CohortProposalSetVersion,
    _selector_binding_permits,
)
from athena_context.api.cohort_decision_ports import (
    CohortDecisionStorePort,
    CohortDecisionTransactionPort,
)
from athena_context.api.cohort_domain import (
    CohortDraftBinding,
    CohortProposalQuery,
    CohortReviewCandidate,
    CohortRoleUpdate,
    normalized_identifier,
)
from athena_context.api.cohort_ports import (
    CohortCandidateRepositoryPort,
    ExplicitWorkloadAuthorizationPort,
)
from athena_context.api.cohort_service import (
    CohortProposalService,
    ResolvedCohortReview,
)
from athena_context.api.domain import (
    Actor,
    ActorKind,
    AuditAction,
    DraftRecord,
    DraftState,
    PendingAuditEvent,
    Permission,
    ReplaceDraftCommand,
    ensure_timestamp,
)
from athena_context.api.errors import (
    AuthorizationError,
    CohortBoundaryError,
    CohortContractError,
    CohortDecisionConflictError,
    DigestMismatchError,
    IdempotencyConflictError,
    InvalidTransitionError,
    PersistenceConflictError,
    RejectedProposalSetError,
    ResourceNotFoundError,
    StaleEvidenceSnapshotError,
    StaleRevisionError,
    VersionMismatchError,
)
from athena_context.api.ports import ClockPort
from athena_context.api.selector_provenance import (
    role_selector_provenance_digest,
)
from athena_context.api.service import ContextService
from athena_context.binding import evaluate_selector, normalize_resource_id
from athena_context.binding.domain import CohortProposal, ProposalScope, SelectorPreview
from athena_context.contracts.common import AthenaValidationError, compute_artifact_digest
from athena_context.contracts.manifest import (
    CanonicalWorkloadManifest,
    ManifestRole,
    ResolvedManifestProfile,
    _resolve_manifest_profile_for_cohort_decision,
    canonicalize_manifest_payload,
    is_guarded_selector_replacement_narrower,
    resolve_manifest_profile,
)
from athena_context.contracts.models import ResourceEvidenceRecord

_MAX_DECISIONS = 200


@dataclass(frozen=True, slots=True)
class _CandidateSelectorValidator:
    """Non-authoritative resolver adapter for pre-persistence validation."""

    binding: CohortDecisionApplyBinding

    def permits_selector_identity_replacement(
        self,
        *,
        manifest_id: str,
        manifest_version: str,
        profile_id: str,
        inherited_role: ManifestRole,
        replacement_role: ManifestRole,
    ) -> bool:
        return _selector_binding_permits(
            self.binding,
            manifest_id=manifest_id,
            manifest_version=manifest_version,
            profile_id=profile_id,
            inherited_role=inherited_role,
            replacement_role=replacement_role,
        )


def _authority_projection(role: ManifestRole) -> dict[str, Any]:
    return {
        "roleId": normalized_identifier(role.role_id),
        "kind": role.kind,
        "cardinality": role.cardinality.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "ownerRef": role.owner_ref,
        "status": role.status,
    }


class CohortDecisionService:
    """Persist human cohort decisions and atomically apply selector-only drafts."""

    def __init__(
        self,
        *,
        store: CohortDecisionStorePort,
        authorization: ExplicitWorkloadAuthorizationPort,
        clock: ClockPort,
        context_service: ContextService,
        proposal_service: CohortProposalService,
        candidate_repository: CohortCandidateRepositoryPort,
    ) -> None:
        self._store = store
        self._authorization = authorization
        self._clock = clock
        self._context_service = context_service
        self._proposal_service = proposal_service
        self._candidate_repository = candidate_repository

    def decide(
        self,
        actor: Actor,
        idempotency_key: str,
        request: CohortDecisionRequest,
    ) -> CohortDecisionRecord:
        self._require_human(actor)
        self._authorization.require_explicit(
            actor,
            Permission.UPDATE_DRAFT,
            request.manifest_id,
        )
        command = request.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        request_digest = compute_artifact_digest(
            {
                "operation": "cohort_decision",
                "actorId": actor.actor_id,
                "command": command,
            }
        )
        replay = self._get_replay(
            actor,
            idempotency_key,
            request_digest,
            request.manifest_id,
        )
        if replay is not None:
            return replay

        version = self._proposal_set_version(request)
        with self._store.transaction() as tx:
            receipt = tx.get_cohort_decision_receipt(
                actor.actor_id,
                idempotency_key,
            )
            if receipt is not None:
                return self._replay_from_receipt(
                    receipt,
                    request_digest=request_digest,
                    manifest_id=request.manifest_id,
                )
            self._arbitrate_overlap(
                request,
                tx.list_overlapping_cohort_decisions(version),
            )

        decision_seed = request_digest.removeprefix("sha256:")[:32]
        decision_id = f"cohort-decision-{decision_seed}"

        with self._store.transaction() as tx:
            receipt = tx.get_cohort_decision_receipt(
                actor.actor_id,
                idempotency_key,
            )
            if receipt is not None:
                return self._replay_from_receipt(
                    receipt,
                    request_digest=request_digest,
                    manifest_id=request.manifest_id,
                )

            self._arbitrate_overlap(
                request,
                tx.list_overlapping_cohort_decisions(version),
            )

            decided_at = ensure_timestamp(self._clock.now())
            resolved = self._proposal_service.resolve_for_decision(
                actor,
                CohortProposalQuery(
                    manifest_id=request.manifest_id,
                    manifest_version=request.manifest_version,
                    profile_id=request.profile_id,
                    draft_id=request.draft_id,
                    expected_revision=request.expected_revision,
                    expected_digest=request.expected_digest,
                ),
                scope=request.scope,
                as_of=decided_at,
            )
            proposals = self._validate_request_binding(request, resolved)
            if decided_at >= resolved.snapshot.expires_at:
                raise StaleEvidenceSnapshotError(
                    "the exact decision snapshot expired before atomic apply"
                )
            candidate = self._resolve_candidate(
                actor,
                request,
                resolved,
                proposals,
                decided_at=decided_at,
            )
            current = self._require_current_draft(tx, request, version)
            self._validate_candidate(
                request,
                resolved,
                proposals,
                candidate,
                decided_at=decided_at,
            )
            candidate_digest: str | None = None
            apply_command: ReplaceDraftCommand | None = None
            apply_authorization: CohortDecisionApplyAuthorization | None = None
            if candidate is not None:
                candidate_digest = compute_artifact_digest(
                    candidate.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    )
                )
                reason = (
                    f"Applied cohort {request.action.value} decision {decision_id}; "
                    "selector-only draft update. Full rationale retained in decision."
                )
                apply_command, apply_authorization = self._selector_only_replacement(
                    current,
                    request,
                    candidate,
                    proposals,
                    actor=actor,
                    decision_id=decision_id,
                    candidate_digest=candidate_digest,
                    decided_at=decided_at,
                    reason=reason,
                )
            applied_binding = (
                None
                if apply_authorization is None
                else apply_authorization.binding.resulting_draft
            )
            audit_event = tx.append_audit(
                PendingAuditEvent(
                    occurred_at=decided_at,
                    actor=actor,
                    action=AuditAction.COHORT_DECISION_RECORDED,
                    manifest_id=request.manifest_id,
                    draft_id=request.draft_id,
                    revision=(
                        current.revision
                        if applied_binding is None
                        else applied_binding.revision
                    ),
                    previous_revision=(
                        current.revision
                        if applied_binding is not None
                        else None
                    ),
                    manifest_version=request.manifest_version,
                    previous_version=current.previous_version,
                    manifest_digest=(
                        current.manifest_digest
                        if applied_binding is None
                        else applied_binding.manifest_digest
                    ),
                    reason=(
                        f"Recorded cohort {request.action.value} decision "
                        f"{decision_id}; full rationale retained in decision record."
                    ),
                )
            )
            record = self._record(
                actor=actor,
                request=request,
                resolved=resolved,
                decision_id=decision_id,
                decided_at=decided_at,
                candidate=candidate,
                candidate_digest=candidate_digest,
                applied_binding=applied_binding,
                apply_authorization=apply_authorization,
                audit_id=audit_event.event_id,
            )
            tx.put_cohort_decision(record)
            if apply_command is not None:
                applied = self._context_service.replace_draft_in_transaction(
                    tx,
                    actor=actor,
                    draft_id=request.draft_id,
                    command=apply_command,
                    occurred_at=decided_at,
                    cohort_decision_id=decision_id,
                )
                if (
                    applied_binding is None
                    or applied.draft_id != applied_binding.draft_id
                    or applied.revision != applied_binding.revision
                    or applied.manifest_digest
                    != applied_binding.manifest_digest
                ):
                    raise PersistenceConflictError(
                        "atomic cohort decision result differs from its "
                        "persisted apply authorization"
                    )
            tx.put_cohort_decision_receipt(
                CohortDecisionReceipt(
                    actor_id=actor.actor_id,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    response_json=record.model_dump_json(
                        by_alias=True,
                        exclude_none=True,
                    ),
                )
            )
            return record

    def get(
        self,
        actor: Actor,
        *,
        manifest_id: str,
        decision_id: str,
    ) -> CohortDecisionRecord:
        self._require_human(actor)
        self._authorization.require_explicit(actor, Permission.READ, manifest_id)
        with self._store.transaction() as tx:
            decision = tx.get_cohort_decision(manifest_id, decision_id)
        if decision is None:
            raise ResourceNotFoundError(
                f"cohort decision {decision_id!r} was not found in this workload"
            )
        return decision

    def list_decisions(
        self,
        actor: Actor,
        *,
        manifest_id: str,
        scope: ProposalScope,
        source_draft: CohortDraftBinding,
        proposal_ids: list[str],
        proposal_set_digest: str,
        snapshot_artifact_digest: str,
        limit: int = _MAX_DECISIONS,
    ) -> list[CohortDecisionRecord]:
        self._require_human(actor)
        if scope.manifest_id != manifest_id:
            raise CohortContractError(
                "decision list scope does not match the authorized workload"
            )
        self._authorization.require_explicit(actor, Permission.LIST, manifest_id)
        with self._store.transaction() as tx:
            decisions = tx.list_cohort_decisions(
                manifest_id=manifest_id,
                profile_id=scope.profile_id,
                draft_id=source_draft.draft_id,
                proposal_set_digest=proposal_set_digest,
            )
        requested_proposals = set(proposal_ids)
        return [
            decision
            for decision in decisions
            if decision.manifest_version == scope.manifest_version
            and decision.profile_type == scope.profile_type
            and decision.resolved_profile_digest == scope.resolved_profile_digest
            and decision.source_draft == source_draft
            and decision.snapshot.artifact_digest == snapshot_artifact_digest
            and requested_proposals.intersection(decision.source_proposal_ids)
        ][:limit]

    @staticmethod
    def _require_human(actor: Actor) -> None:
        if actor.kind is not ActorKind.HUMAN:
            raise AuthorizationError(
                "cohort decision APIs require a verified human actor"
            )

    def _get_replay(
        self,
        actor: Actor,
        idempotency_key: str,
        request_digest: str,
        manifest_id: str,
    ) -> CohortDecisionRecord | None:
        with self._store.transaction() as tx:
            receipt = tx.get_cohort_decision_receipt(
                actor.actor_id,
                idempotency_key,
            )
        if receipt is None:
            return None
        return self._replay_from_receipt(
            receipt,
            request_digest=request_digest,
            manifest_id=manifest_id,
        )

    @staticmethod
    def _replay_from_receipt(
        receipt: CohortDecisionReceipt,
        *,
        request_digest: str,
        manifest_id: str,
    ) -> CohortDecisionRecord:
        if receipt.request_digest != request_digest:
            raise IdempotencyConflictError(
                "idempotency key was used for a different cohort decision"
            )
        try:
            record = CohortDecisionRecord.model_validate_json(receipt.response_json)
        except ValidationError as exc:
            raise PersistenceConflictError(
                "stored cohort decision receipt is invalid"
            ) from exc
        if record.manifest_id != manifest_id:
            raise IdempotencyConflictError(
                "idempotency receipt escaped its workload scope"
            )
        return record

    @staticmethod
    def _proposal_set_version(
        request: CohortDecisionRequest,
    ) -> CohortProposalSetVersion:
        return CohortProposalSetVersion(
            manifest_id=request.manifest_id,
            manifest_version=request.manifest_version,
            profile_id=request.profile_id,
            resolved_profile_digest=request.scope.resolved_profile_digest,
            source_draft=CohortDraftBinding(
                draftId=request.draft_id,
                revision=request.expected_revision,
                manifestDigest=request.expected_digest,
            ),
            proposal_set_digest=request.proposal_set_digest,
            snapshot_artifact_digest=request.snapshot_artifact_digest,
            sourceProposalIds=request.proposal_ids,
        )

    @staticmethod
    def _arbitrate_overlap(
        request: CohortDecisionRequest,
        existing: list[CohortDecisionRecord],
    ) -> None:
        if not existing:
            return
        if request.action is not CohortDecisionKind.REJECT and any(
            decision.decision is CohortDecisionKind.REJECT
            for decision in existing
        ):
            raise RejectedProposalSetError(
                "a durable reject permanently blocks apply for an "
                "overlapping selected proposal"
            )
        raise CohortDecisionConflictError(
            "an overlapping selected proposal already has an "
            "authoritative decision"
        )

    @staticmethod
    def _validate_request_binding(
        request: CohortDecisionRequest,
        resolved: ResolvedCohortReview,
    ) -> list[CohortProposal]:
        batch = resolved.batch
        if (
            request.scope != batch.scope
            or request.proposal_set_digest != batch.proposal_set_digest
            or request.snapshot_artifact_digest != batch.snapshot.artifact_digest
            or batch.source_draft.draft_id != request.draft_id
            or batch.source_draft.revision != request.expected_revision
            or batch.source_draft.manifest_digest != request.expected_digest
        ):
            raise CohortContractError(
                "decision bindings do not match the exact batch, profile, snapshot, "
                "or source draft"
            )
        by_id = {proposal.proposal_id: proposal for proposal in batch.proposals}
        try:
            proposals = [by_id[proposal_id] for proposal_id in request.proposal_ids]
        except KeyError as exc:
            raise CohortContractError(
                "decision references a proposal outside the exact batch"
            ) from exc
        source_roles = {
            normalized_identifier(proposal.role.role_id) for proposal in proposals
        }
        if (
            request.action is not CohortDecisionKind.REJECT
            and len(source_roles) != 1
        ):
            raise CohortContractError(
                "approve, split, and merge require one exact source role"
            )
        return proposals

    def _resolve_candidate(
        self,
        actor: Actor,
        request: CohortDecisionRequest,
        resolved: ResolvedCohortReview,
        proposals: list[CohortProposal],
        *,
        decided_at: datetime,
    ) -> CohortReviewCandidate | None:
        if request.action is CohortDecisionKind.REJECT:
            return None
        submitted = request.candidate
        if submitted is None:
            raise CohortContractError("apply decision is missing its candidate")
        if request.action is CohortDecisionKind.APPROVE:
            proposal = proposals[0]
            preview = proposal.selector_preview
            expected_id = f"review-{proposal.proposal_id}"
            if submitted.candidate_id != expected_id or preview is None:
                raise CohortContractError(
                    "approve requires the exact WC-012 direct review candidate"
                )
            role = proposal.role.model_copy(update={"selectors": [preview.selector]})
            expected = CohortReviewCandidate(
                candidateId=expected_id,
                action="approve",
                sourceDraft=resolved.batch.source_draft,
                scope=resolved.batch.scope,
                sourceProposalIds=request.proposal_ids,
                proposalSetDigest=request.proposal_set_digest,
                snapshot=resolved.batch.snapshot,
                roleUpdates=[
                    CohortRoleUpdate(
                        role=role,
                        selectorPreviews=[preview],
                        memberCount=len(proposal.members),
                    )
                ],
                replaceRoleRefs=[proposal.role.role_id],
                resolution=request.rationale,
                generatedAt=resolved.batch.evaluated_at,
                expiresAt=resolved.snapshot.expires_at,
                requiresHumanReview=True,
                publicationAllowed=False,
                manifestMutated=False,
            )
            if submitted != expected:
                raise CohortContractError(
                    "approve candidate does not match the exact WC-012 proposal"
                )
            return submitted
        stored = self._candidate_repository.get_candidate(
            actor.actor_id,
            submitted.candidate_id,
        )
        if (
            stored is None
            or stored.actor_id != actor.actor_id
            or stored.evidence_binding != resolved.evidence_binding
            or stored.candidate != submitted
        ):
            raise CohortContractError(
                "decision candidate was not generated for the exact evidence binding"
            )
        candidate = stored.candidate
        if candidate.generated_at > decided_at:
            raise CohortContractError("decision candidate was generated in the future")
        return candidate

    @staticmethod
    def _source_union(proposals: list[CohortProposal]) -> set[str]:
        members: set[str] = set()
        for proposal in proposals:
            for member in proposal.members:
                try:
                    normalized = normalize_resource_id(member)
                except AthenaValidationError as exc:
                    raise CohortContractError(
                        "source proposal contains an invalid Azure resource ID"
                    ) from exc
                if normalized in members:
                    raise CohortContractError(
                        "source proposals contain overlapping normalized members"
                    )
                members.add(normalized)
        if not members or len(members) > 1000:
            raise CohortBoundaryError(
                "decision source union must contain between 1 and 1,000 members"
            )
        return members

    @classmethod
    def _validate_candidate(
        cls,
        request: CohortDecisionRequest,
        resolved: ResolvedCohortReview,
        proposals: list[CohortProposal],
        candidate: CohortReviewCandidate | None,
        *,
        decided_at: datetime,
    ) -> None:
        source_union = cls._source_union(proposals)
        if candidate is None:
            if request.action is not CohortDecisionKind.REJECT:
                raise CohortContractError("apply decision has no exact candidate")
            return
        resources = [
            record
            for record in resolved.snapshot.evidence_records
            if isinstance(record, ResourceEvidenceRecord)
        ]
        baseline = proposals[0].role
        candidate_union: set[str] = set()
        for update in candidate.role_updates:
            if _authority_projection(update.role) != _authority_projection(baseline):
                raise CohortContractError(
                    "candidate attempted to alter role kind, cardinality, owner, or status"
                )
            if request.action in {
                CohortDecisionKind.SPLIT,
                CohortDecisionKind.MERGE,
            } and not is_guarded_selector_replacement_narrower(
                baseline.selectors,
                update.role.selectors,
            ):
                raise CohortContractError(
                    "split or merge candidate is not a guarded exact selector replacement"
                )
            update_union: set[str] = set()
            for preview in update.selector_previews:
                members = cls._revalidate_preview(preview, resources)
                if update_union.intersection(members) or candidate_union.intersection(
                    members
                ):
                    raise CohortContractError(
                        "candidate selector memberships are not a disjoint union"
                    )
                update_union.update(members)
                candidate_union.update(members)
            if update.member_count != len(update_union):
                raise CohortContractError("candidate memberCount is not exact")
        role_refs = {normalized_identifier(baseline.role_id)}
        if (
            candidate.action != request.action.value
            or request.candidate != candidate
            or candidate.source_draft != resolved.batch.source_draft
            or candidate.scope != resolved.batch.scope
            or candidate.source_proposal_ids != request.proposal_ids
            or candidate.proposal_set_digest != request.proposal_set_digest
            or candidate.snapshot != resolved.batch.snapshot
            or candidate.resolution != request.rationale
            or candidate.expires_at != resolved.snapshot.expires_at
            or candidate.expires_at <= decided_at
            or {
                normalized_identifier(role_ref)
                for role_ref in candidate.replace_role_refs
            }
            != role_refs
            or {
                normalized_identifier(update.role.role_id)
                for update in candidate.role_updates
            }
            != role_refs
            or len(candidate.role_updates) != 1
            or len(candidate.replace_role_refs) != 1
            or candidate_union != source_union
            or not candidate.requires_human_review
            or candidate.publication_allowed
            or candidate.manifest_mutated
        ):
            raise CohortContractError(
                "candidate is not exactly bound to the selected proposal union"
            )

    @staticmethod
    def _revalidate_preview(
        preview: SelectorPreview,
        resources: list[ResourceEvidenceRecord],
    ) -> set[str]:
        try:
            evaluated = evaluate_selector(preview.selector, resources)
            members = {
                normalize_resource_id(item)
                for item in preview.matched_resource_ids
            }
            evaluated_members = {
                normalize_resource_id(item)
                for item in evaluated.matched_resource_ids
            }
        except AthenaValidationError as exc:
            raise CohortContractError(
                "candidate selector cannot be re-evaluated against the exact snapshot"
            ) from exc
        if (
            not members
            or len(members) > 1000
            or len(members) != len(preview.matched_resource_ids)
            or preview.max_matches != len(members)
            or preview.selector.max_matches != len(members)
            or evaluated.status != "matched"
            or evaluated.max_match_violations
            or evaluated_members != members
            or evaluated.selector_result_digest != preview.selector_result_digest
        ):
            raise CohortContractError(
                "candidate selector union, count, digest, or maxMatches is inexact"
            )
        return members

    @staticmethod
    def _require_current_draft(
        tx: CohortDecisionTransactionPort,
        request: CohortDecisionRequest,
        version: CohortProposalSetVersion,
    ) -> DraftRecord:
        draft = tx.get_draft(request.draft_id)
        if draft is None:
            raise ResourceNotFoundError(f"draft {request.draft_id!r} was not found")
        if draft.manifest_id != request.manifest_id:
            raise VersionMismatchError("draft belongs to a different workload")
        if draft.manifest.manifest_version != request.manifest_version:
            raise VersionMismatchError(
                "expected manifest version does not match the draft"
            )
        if draft.state is not DraftState.DRAFT:
            raise InvalidTransitionError(
                "cohort decisions require an active draft state"
            )
        if (
            draft.manifest.compute_artifact_digest_value()
            != draft.manifest_digest
        ):
            raise DigestMismatchError("draft manifest digest is not canonical")
        source = version.source_draft
        if draft.revision == source.revision:
            if draft.manifest_digest != source.manifest_digest:
                raise DigestMismatchError(
                    "expected manifest digest does not match the draft"
                )
            return draft
        if draft.revision < source.revision:
            raise StaleRevisionError(
                f"expected draft revision {source.revision}, "
                f"found {draft.revision}"
            )

        binding = version.model_dump_json(
            by_alias=True,
            exclude_none=True,
            exclude={"source_proposal_ids"},
        )
        applied_by_revision: dict[int, CohortDecisionRecord] = {}
        for decision in tx.list_cohort_decisions(
            manifest_id=request.manifest_id,
            profile_id=request.profile_id,
            draft_id=request.draft_id,
            proposal_set_digest=request.proposal_set_digest,
        ):
            decision_binding = decision.proposal_set_version().model_dump_json(
                by_alias=True,
                exclude_none=True,
                exclude={"source_proposal_ids"},
            )
            applied = decision.applied_draft
            if decision_binding != binding or applied is None:
                continue
            if (
                applied.draft_id != source.draft_id
                or applied.revision <= source.revision
                or applied.revision in applied_by_revision
            ):
                raise StaleRevisionError(
                    "cohort decision apply history is not a valid revision chain"
                )
            applied_by_revision[applied.revision] = decision

        expected_digest = source.manifest_digest
        expected_revision = source.revision + 1
        for revision in sorted(applied_by_revision):
            applied_decision = applied_by_revision[revision]
            if (
                revision != expected_revision
                or revision > draft.revision
                or applied_decision.applied_draft is None
            ):
                raise StaleRevisionError(
                    "draft advanced outside this immutable cohort decision batch"
                )
            expected_digest = applied_decision.applied_draft.manifest_digest
            expected_revision += 1
        if (
            expected_revision != draft.revision + 1
            or draft.manifest_digest != expected_digest
        ):
            raise StaleRevisionError(
                "draft digest does not match the atomic cohort decision apply chain"
            )
        return draft

    @staticmethod
    def _selector_only_replacement(
        current: DraftRecord,
        request: CohortDecisionRequest,
        candidate: CohortReviewCandidate,
        proposals: list[CohortProposal],
        *,
        actor: Actor,
        decision_id: str,
        candidate_digest: str,
        decided_at: datetime,
        reason: str,
    ) -> tuple[
        ReplaceDraftCommand,
        CohortDecisionApplyAuthorization,
    ]:
        payload = current.manifest.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        requested_profile = normalized_identifier(request.profile_id)
        profile_match = next(
            (
                (key, profile)
                for key, profile in current.manifest.profiles.items()
                if normalized_identifier(profile.profile_id) == requested_profile
            ),
            None,
        )
        if profile_match is None:
            raise CohortContractError(
                "candidate profile is not present in the exact draft"
            )
        profile_key, _profile = profile_match
        update = candidate.role_updates[0]
        target = normalized_identifier(update.role.role_id)
        source_role = proposals[0].role
        applied_role = CohortDecisionService._materialize_local_role_override(
            update.role,
            baseline=source_role,
            candidate=candidate,
        )
        profile_payload = payload["profiles"].get(profile_key)
        if not isinstance(profile_payload, dict):
            raise CohortContractError("requested profile payload is invalid")
        local_roles = profile_payload.get("roles")
        if not isinstance(local_roles, list):
            raise CohortContractError("requested profile roles are invalid")
        profile_payload["roles"] = [
            role
            for role in local_roles
            if isinstance(role, dict)
            and normalized_identifier(str(role.get("roleId", ""))) != target
        ]
        profile_payload["roles"].append(
            applied_role.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
        try:
            replacement = CanonicalWorkloadManifest.model_validate(
                canonicalize_manifest_payload(payload)
            )
            command = ReplaceDraftCommand(
                expected_revision=current.revision,
                expected_manifest_version=request.manifest_version,
                expected_digest=current.manifest_digest,
                replacement_manifest=replacement,
                replacement_digest=replacement.compatibility.artifact_digest,
                reason=reason,
            )
            binding = CohortDecisionApplyBinding(
                decision_id=decision_id,
                decision=request.action,
                decided_at=decided_at,
                actor=actor,
                candidate_id=candidate.candidate_id,
                candidate_digest=candidate_digest,
                manifest_id=request.manifest_id,
                manifest_version=request.manifest_version,
                profile_id=request.profile_id,
                resolved_profile_digest=request.scope.resolved_profile_digest,
                source_draft=CohortDraftBinding(
                    draftId=request.draft_id,
                    revision=request.expected_revision,
                    manifestDigest=request.expected_digest,
                ),
                current_draft=CohortDraftBinding(
                    draftId=current.draft_id,
                    revision=current.revision,
                    manifestDigest=current.manifest_digest,
                ),
                resulting_draft=CohortDraftBinding(
                    draftId=current.draft_id,
                    revision=current.revision + 1,
                    manifestDigest=replacement.compatibility.artifact_digest,
                ),
                proposal_ids=request.proposal_ids,
                proposal_set_digest=request.proposal_set_digest,
                snapshot_artifact_digest=request.snapshot_artifact_digest,
                target_role_id=update.role.role_id,
                inherited_role_digest=compute_artifact_digest(
                    source_role.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    )
                ),
                replacement_role_digest=compute_artifact_digest(
                    applied_role.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    )
                ),
                replacement_selector_provenance_digest=(
                    role_selector_provenance_digest(
                        applied_role,
                        profile_id=request.profile_id,
                    )
                ),
                retained_replacement_role_digests=tuple(
                    sorted(
                        (
                            normalized_identifier(profile.profile_id),
                            normalized_identifier(role.role_id),
                            compute_artifact_digest(
                                role.model_dump(
                                    mode="json",
                                    by_alias=True,
                                    exclude_none=True,
                                )
                            ),
                        )
                        for profile in current.manifest.profiles.values()
                        for role in profile.roles
                    )
                ),
                replacement_manifest_digest=(
                    replacement.compatibility.artifact_digest
                ),
            )
            apply_authorization = CohortDecisionApplyAuthorization.issue(
                binding,
                command,
            )
            selector_validator = _CandidateSelectorValidator(binding)
            before_profiles = CohortDecisionService._resolve_all_profiles(
                current.manifest,
                as_of=decided_at,
                selector_validator=selector_validator,
            )
            target_before = before_profiles.get(requested_profile)
            if target_before is None:
                raise CohortContractError(
                    "requested profile changed before selector materialization"
                )
            target_before_role = next(
                (
                    role
                    for role in target_before.roles
                    if normalized_identifier(role.role_id) == target
                ),
                None,
            )
            if target_before_role != source_role:
                raise CohortContractError(
                    "requested role changed outside this disjoint decision apply chain"
                )
            after_profiles = CohortDecisionService._resolve_all_profiles(
                replacement,
                as_of=decided_at,
                selector_validator=selector_validator,
            )
        except (AthenaValidationError, ValidationError, ValueError) as exc:
            raise CohortContractError(
                "local selector override violates canonical or weakening governance rules"
            ) from exc
        if replacement.roles != current.manifest.roles:
            raise CohortContractError(
                "profile-scoped decision attempted to mutate global roles"
            )
        if set(before_profiles) != set(after_profiles):
            raise CohortContractError(
                "profile-scoped decision changed the resolved profile set"
            )
        for profile_id, before_profile in before_profiles.items():
            if profile_id == requested_profile:
                continue
            after_profile = after_profiles[profile_id]
            if (
                before_profile.compatibility.semantic_digest
                != after_profile.compatibility.semantic_digest
                or before_profile.resolved_profile_digest
                != after_profile.resolved_profile_digest
                or before_profile.roles != after_profile.roles
                or before_profile != after_profile
            ):
                raise CohortContractError(
                    "local selector override changed a non-target profile"
                )

        target_after = after_profiles[requested_profile]
        before_roles = {
            normalized_identifier(role.role_id): role
            for role in target_before.roles
        }
        after_roles = {
            normalized_identifier(role.role_id): role
            for role in target_after.roles
        }
        if (
            set(before_roles) != set(after_roles)
            or target not in after_roles
            or after_roles[target] != applied_role
            or any(
                before_roles[role_id] != after_roles[role_id]
                for role_id in before_roles
                if role_id != target
            )
        ):
            raise CohortContractError(
                "candidate attempted an update outside the exact role selectors"
            )
        if after_roles[target].selectors != update.role.selectors:
            raise CohortContractError(
                "local override does not contain the exact approved candidate selectors"
            )
        before = target_before.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        after = target_after.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        for profile_payload in (before, after):
            profile_payload.pop("roles", None)
            profile_payload.pop("compatibility", None)
            profile_payload.pop("resolvedProfileDigest", None)
        if before != after:
            raise CohortContractError(
                "candidate attempted to mutate non-role profile metadata"
            )
        return command, apply_authorization

    @staticmethod
    def _resolve_all_profiles(
        manifest: CanonicalWorkloadManifest,
        *,
        as_of: datetime,
        selector_validator: _CandidateSelectorValidator | None = None,
    ) -> dict[str, ResolvedManifestProfile]:
        return {
            normalized_identifier(profile.profile_id): (
                resolve_manifest_profile(
                    manifest,
                    profile.profile_id,
                    as_of=as_of,
                )
                if selector_validator is None
                else _resolve_manifest_profile_for_cohort_decision(
                    manifest,
                    profile.profile_id,
                    as_of=as_of,
                    selector_capability=selector_validator,
                )
            )
            for profile in manifest.profiles.values()
        }

    @staticmethod
    def _materialize_local_role_override(
        role: ManifestRole,
        *,
        baseline: ManifestRole,
        candidate: CohortReviewCandidate,
    ) -> ManifestRole:
        """Require the approved role to be an exact canonical local override."""

        update = candidate.role_updates[0]
        if update.role != role:
            raise CohortContractError(
                "candidate role update does not match its approved role"
            )
        if _authority_projection(baseline) != _authority_projection(role):
            raise CohortContractError(
                "local override attempted to change role authority metadata"
            )
        return role

    @staticmethod
    def _record(
        *,
        actor: Actor,
        request: CohortDecisionRequest,
        resolved: ResolvedCohortReview,
        decision_id: str,
        decided_at: datetime,
        candidate: CohortReviewCandidate | None,
        candidate_digest: str | None,
        applied_binding: CohortDraftBinding | None,
        apply_authorization: CohortDecisionApplyAuthorization | None,
        audit_id: str,
    ) -> CohortDecisionRecord:
        return CohortDecisionRecord(
            decisionId=decision_id,
            decision=request.action,
            manifestId=request.manifest_id,
            manifestVersion=request.manifest_version,
            profileId=request.profile_id,
            profileType=resolved.batch.scope.profile_type,
            resolvedProfileDigest=request.scope.resolved_profile_digest,
            sourceDraft=resolved.batch.source_draft,
            appliedDraft=applied_binding,
            batchInputDigest=resolved.batch.input_digest,
            proposalSetDigest=request.proposal_set_digest,
            sourceProposalIds=request.proposal_ids,
            sourceRoleRefs=list(
                dict.fromkeys(
                    proposal.role.role_id
                    for proposal in resolved.batch.proposals
                    if proposal.proposal_id in request.proposal_ids
                )
            ),
            snapshot=resolved.batch.snapshot,
            candidateId=None if candidate is None else candidate.candidate_id,
            candidateDigest=candidate_digest,
            applyAuthorization=apply_authorization,
            rationale=request.rationale,
            decidedBy=actor,
            decidedAt=decided_at,
            audit=CohortDecisionAudit(
                auditId=audit_id,
                decisionId=decision_id,
                actor=actor,
                occurredAt=decided_at,
                sourceRevision=request.expected_revision,
                sourceProposalIds=request.proposal_ids,
                resultingRevision=(
                    None
                    if applied_binding is None
                    else applied_binding.revision
                ),
                draftMutated=applied_binding is not None,
            ),
            publicationAllowed=False,
            roleMetadataMutated=False,
        )


__all__ = ["CohortDecisionService"]
