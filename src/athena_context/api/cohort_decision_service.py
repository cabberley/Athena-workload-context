from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import TypeAdapter, ValidationError

from athena_context.api.cohort_decision_domain import (
    CohortDecisionAudit,
    CohortDecisionKind,
    CohortDecisionReceipt,
    CohortDecisionRecord,
    CohortDecisionRequest,
    CohortProposalSetVersion,
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
from athena_context.api.service import ContextService
from athena_context.binding import evaluate_selector, normalize_resource_id
from athena_context.binding.domain import CohortProposal, ProposalScope, SelectorPreview
from athena_context.contracts.common import AthenaValidationError, compute_artifact_digest
from athena_context.contracts.manifest import (
    AtomicSelector,
    CanonicalWorkloadManifest,
    CompositeAllSelector,
    ManifestRole,
    canonicalize_manifest_payload,
    resolve_manifest_profile,
)
from athena_context.contracts.models import ResourceEvidenceRecord

_MAX_DECISIONS = 200
_ATOMIC_SELECTOR_ADAPTER: TypeAdapter[AtomicSelector] = TypeAdapter(AtomicSelector)


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


def _selector_projection(role: ManifestRole) -> dict[str, dict[str, Any]]:
    projected: dict[str, dict[str, Any]] = {}
    for selector in role.selectors:
        payload = selector.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        children = payload.get("children")
        if isinstance(children, list):
            payload["children"] = sorted(
                children,
                key=lambda child: normalized_identifier(
                    str(child.get("selectorId", ""))
                )
                if isinstance(child, dict)
                else "",
            )
        projected[normalized_identifier(selector.selector_id)] = payload
    return projected


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
        request_digest = compute_artifact_digest(
            {
                "operation": "cohort_decision",
                "actorId": actor.actor_id,
                "command": request.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                ),
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
        )
        proposals = self._validate_request_binding(request, resolved)
        decided_at = ensure_timestamp(self._clock.now())
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
        version = self._proposal_set_version(request, resolved)
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

            existing = tx.get_cohort_decision_for_version(version)
            if existing is not None:
                if (
                    existing.decision is CohortDecisionKind.REJECT
                    and request.action is not CohortDecisionKind.REJECT
                ):
                    raise RejectedProposalSetError(
                        "a durable reject permanently blocks apply for this "
                        "proposal-set version"
                    )
                raise CohortDecisionConflictError(
                    "the proposal-set version already has an authoritative decision"
                )

            current = self._require_current_draft(tx, request)
            self._validate_candidate(
                request,
                resolved,
                proposals,
                candidate,
                decided_at=decided_at,
            )
            applied: DraftRecord | None = None
            candidate_digest: str | None = None
            if candidate is not None:
                replacement = self._selector_only_replacement(
                    current,
                    request,
                    resolved,
                    candidate,
                    decided_at=decided_at,
                )
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
                applied = self._context_service.replace_draft_in_transaction(
                    tx,
                    actor=actor,
                    draft_id=request.draft_id,
                    command=ReplaceDraftCommand(
                        expected_revision=request.expected_revision,
                        expected_manifest_version=request.manifest_version,
                        expected_digest=request.expected_digest,
                        replacement_manifest=replacement,
                        replacement_digest=replacement.compatibility.artifact_digest,
                        reason=reason,
                    ),
                    occurred_at=decided_at,
                )

            audit_draft = applied or current
            audit_event = tx.append_audit(
                PendingAuditEvent(
                    occurred_at=decided_at,
                    actor=actor,
                    action=AuditAction.COHORT_DECISION_RECORDED,
                    manifest_id=request.manifest_id,
                    draft_id=request.draft_id,
                    revision=audit_draft.revision,
                    previous_revision=(
                        current.revision if applied is not None else None
                    ),
                    manifest_version=request.manifest_version,
                    previous_version=current.previous_version,
                    manifest_digest=audit_draft.manifest_digest,
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
                applied=applied,
                audit_id=audit_event.event_id,
            )
            tx.put_cohort_decision(record)
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
        resolved: ResolvedCohortReview,
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
            batch_input_digest=resolved.batch.input_digest,
            proposal_set_digest=request.proposal_set_digest,
            snapshot_artifact_digest=request.snapshot_artifact_digest,
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
        stored = self._candidate_repository.get_candidate(submitted.candidate_id)
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
    ) -> DraftRecord:
        draft = tx.get_draft(request.draft_id)
        if draft is None:
            raise ResourceNotFoundError(f"draft {request.draft_id!r} was not found")
        if draft.manifest_id != request.manifest_id:
            raise VersionMismatchError("draft belongs to a different workload")
        if draft.revision != request.expected_revision:
            raise StaleRevisionError(
                f"expected draft revision {request.expected_revision}, "
                f"found {draft.revision}"
            )
        if draft.manifest.manifest_version != request.manifest_version:
            raise VersionMismatchError(
                "expected manifest version does not match the draft"
            )
        if draft.manifest_digest != request.expected_digest:
            raise DigestMismatchError(
                "expected manifest digest does not match the draft"
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
        return draft

    @staticmethod
    def _selector_only_replacement(
        current: DraftRecord,
        request: CohortDecisionRequest,
        resolved: ResolvedCohortReview,
        candidate: CohortReviewCandidate,
        *,
        decided_at: datetime,
    ) -> CanonicalWorkloadManifest:
        payload = current.manifest.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        profile_key = next(
            (
                key
                for key, profile in current.manifest.profiles.items()
                if profile.profile_id == request.profile_id
            ),
            None,
        )
        if profile_key is None:
            raise CohortContractError(
                "candidate profile is not present in the exact draft"
            )
        update = candidate.role_updates[0]
        target = normalized_identifier(update.role.role_id)
        applied_role = update.role
        if request.action in {
            CohortDecisionKind.SPLIT,
            CohortDecisionKind.MERGE,
        }:
            applied_role = CohortDecisionService._scoped_partition_role(
                update.role,
                resolved=resolved,
                candidate=candidate,
            )
        declaration_roles: list[Any] | None = None
        profiles_by_id = {
            normalized_identifier(profile.profile_id): (key, profile)
            for key, profile in current.manifest.profiles.items()
        }
        declaration_profile = current.manifest.profiles[profile_key]
        while True:
            if any(
                normalized_identifier(role.role_id) == target
                for role in declaration_profile.roles
            ):
                profile_payload = payload["profiles"][profile_key]
                if isinstance(profile_payload, dict):
                    candidate_roles = profile_payload.get("roles")
                    if isinstance(candidate_roles, list):
                        declaration_roles = candidate_roles
                break
            if declaration_profile.extends is None:
                break
            parent = profiles_by_id.get(
                normalized_identifier(declaration_profile.extends)
            )
            if parent is None:
                break
            profile_key, declaration_profile = parent
        if declaration_roles is None and any(
            normalized_identifier(role.role_id) == target
            for role in current.manifest.roles
        ):
            root_roles = payload.get("roles")
            if isinstance(root_roles, list):
                declaration_roles = root_roles
        if declaration_roles is None:
            raise CohortContractError(
                "candidate source role has no exact manifest declaration"
            )
        declaration_roles[:] = [
            role
            for role in declaration_roles
            if isinstance(role, dict)
            and normalized_identifier(str(role.get("roleId", ""))) != target
        ]
        declaration_roles.append(
            applied_role.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        )
        try:
            replacement = CanonicalWorkloadManifest.model_validate(
                canonicalize_manifest_payload(payload)
            )
            replacement_profile = resolve_manifest_profile(
                replacement,
                request.profile_id,
                as_of=decided_at,
            )
        except (AthenaValidationError, ValidationError, ValueError) as exc:
            raise CohortContractError(
                "selector-only candidate cannot form a canonical WC-007 draft"
            ) from exc
        before_roles = {
            normalized_identifier(role.role_id): role
            for role in resolved.profile.roles
        }
        after_roles = {
            normalized_identifier(role.role_id): role
            for role in replacement_profile.roles
        }
        if (
            set(before_roles) != set(after_roles)
            or target not in after_roles
            or _authority_projection(after_roles[target])
            != _authority_projection(applied_role)
            or _selector_projection(after_roles[target])
            != _selector_projection(applied_role)
            or any(
                before_roles[role_id] != after_roles[role_id]
                for role_id in before_roles
                if role_id != target
            )
        ):
            raise CohortContractError(
                "candidate attempted an update outside the exact role selectors"
            )
        before = resolved.profile.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        after = replacement_profile.model_dump(
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
        return replacement

    @staticmethod
    def _scoped_partition_role(
        role: ManifestRole,
        *,
        resolved: ResolvedCohortReview,
        candidate: CohortReviewCandidate,
    ) -> ManifestRole:
        """Conjoin transformed partitions with their declared selector scope."""

        baseline = next(
            (
                item
                for item in resolved.profile.roles
                if normalized_identifier(item.role_id)
                == normalized_identifier(role.role_id)
            ),
            None,
        )
        if baseline is None:
            raise CohortContractError("split role has no exact declared baseline")
        resources = [
            record
            for record in resolved.snapshot.evidence_records
            if isinstance(record, ResourceEvidenceRecord)
        ]
        source_members = {
            normalize_resource_id(member)
            for update in candidate.role_updates
            for preview in update.selector_previews
            for member in preview.matched_resource_ids
        }
        scope_selector = None
        for selector in baseline.selectors:
            if selector.selector_type in {"compositeAll", "compositeAny"}:
                continue
            try:
                evaluated = evaluate_selector(selector, resources)
                matched = {
                    normalize_resource_id(member)
                    for member in evaluated.matched_resource_ids
                }
            except AthenaValidationError:
                continue
            if source_members.issubset(matched):
                scope_selector = selector
                break
        if scope_selector is None:
            raise CohortContractError(
                "split partitions cannot retain the exact declared selector scope"
            )

        seed = compute_artifact_digest(
            {
                "candidateId": candidate.candidate_id,
                "roleId": role.role_id,
            }
        )[7:23]
        selectors: list[CompositeAllSelector] = []
        for index, preview in enumerate(
            candidate.role_updates[0].selector_previews,
            start=1,
        ):
            if preview.selector.selector_type in {"compositeAll", "compositeAny"}:
                raise CohortContractError(
                    "split member selector cannot be nested as a scope guard"
                )
            scope_payload = scope_selector.model_dump(
                mode="python",
                by_alias=True,
                exclude_none=True,
            )
            scope_payload["selectorId"] = f"scope-{index}-{seed}"
            member_payload = preview.selector.model_dump(
                mode="python",
                by_alias=True,
                exclude_none=True,
            )
            member_payload["selectorId"] = f"members-{index}-{seed}"
            try:
                scoped = CompositeAllSelector(
                    selectorType="compositeAll",
                    selectorId=preview.selector.selector_id,
                    children=[
                        _ATOMIC_SELECTOR_ADAPTER.validate_python(scope_payload),
                        _ATOMIC_SELECTOR_ADAPTER.validate_python(member_payload),
                    ],
                    maxMatches=preview.max_matches,
                )
                evaluated = evaluate_selector(scoped, resources)
                expected = {
                    normalize_resource_id(member)
                    for member in preview.matched_resource_ids
                }
                actual = {
                    normalize_resource_id(member)
                    for member in evaluated.matched_resource_ids
                }
            except (AthenaValidationError, ValidationError) as exc:
                raise CohortContractError(
                    "split partition cannot retain exact selector scope"
                ) from exc
            if (
                actual != expected
                or evaluated.max_match_violations
                or evaluated.status != "matched"
                or scoped.max_matches != len(actual)
            ):
                raise CohortContractError(
                    "scoped split selector does not preserve exact membership"
                )
            selectors.append(scoped)
        return role.model_copy(update={"selectors": selectors})

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
        applied: DraftRecord | None,
        audit_id: str,
    ) -> CohortDecisionRecord:
        applied_binding = (
            None
            if applied is None
            else CohortDraftBinding(
                draftId=applied.draft_id,
                revision=applied.revision,
                manifestDigest=applied.manifest_digest,
            )
        )
        return CohortDecisionRecord(
            decisionId=decision_id,
            decision=request.action,
            manifestId=request.manifest_id,
            manifestVersion=request.manifest_version,
            profileId=request.profile_id,
            profileType=resolved.profile.profile_type,
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
            rationale=request.rationale,
            decidedBy=actor,
            decidedAt=decided_at,
            audit=CohortDecisionAudit(
                auditId=audit_id,
                decisionId=decision_id,
                actor=actor,
                occurredAt=decided_at,
                sourceRevision=request.expected_revision,
                resultingRevision=None if applied is None else applied.revision,
                draftMutated=applied is not None,
            ),
            publicationAllowed=False,
            roleMetadataMutated=False,
        )


__all__ = ["CohortDecisionService"]
