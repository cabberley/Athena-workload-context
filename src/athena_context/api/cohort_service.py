from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import ceil
from typing import Any

from pydantic import TypeAdapter, ValidationError

from athena_context.api.cohort_domain import (
    CohortBatchCacheKey,
    CohortDraftBinding,
    CohortEvidenceBinding,
    CohortPreviewReceipt,
    CohortProposalBatchResponse,
    CohortProposalQuery,
    CohortReviewCandidate,
    CohortReviewPreviewRequest,
    CohortRoleUpdate,
    normalized_identifier,
)
from athena_context.api.cohort_ports import (
    CohortPreviewReceiptPort,
    CohortProposalCachePort,
    EvidenceSnapshotRepositoryPort,
    ExplicitWorkloadAuthorizationPort,
    TrustedEvidenceSnapshotVerifierPort,
)
from athena_context.api.domain import (
    Actor,
    ActorKind,
    DraftRecord,
    DraftState,
    Permission,
    ensure_timestamp,
)
from athena_context.api.errors import (
    AuthorizationError,
    CohortBoundaryError,
    CohortContractError,
    CohortProfileMismatchError,
    DigestMismatchError,
    EvidenceSnapshotMismatchError,
    IdempotencyConflictError,
    InvalidTransitionError,
    ResourceNotFoundError,
    StaleEvidenceSnapshotError,
    StaleRevisionError,
    VersionMismatchError,
)
from athena_context.api.ports import ClockPort, ContextStorePort
from athena_context.binding import (
    VerifiedCohortSnapshot,
    evaluate_selector,
    normalize_resource_id,
    propose_cohorts,
    verify_cohort_snapshot,
)
from athena_context.binding.domain import (
    CohortProposal,
    CohortProposalBatch,
    ProposalScope,
    SelectorPreview,
)
from athena_context.contracts.common import AthenaValidationError, compute_artifact_digest
from athena_context.contracts.manifest import (
    ManifestRole,
    ManifestSelector,
    ResolvedManifestProfile,
    ResourceIdListSelector,
    resolve_manifest_profile,
)
from athena_context.contracts.models import EvidenceSnapshot, ResourceEvidenceRecord

_SELECTOR_ADAPTER: TypeAdapter[ManifestSelector] = TypeAdapter(ManifestSelector)
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_PROPOSALS = 200
_MAX_CONFLICTS = 1000
_MAX_EVIDENCE_RECORDS = 2000
_MAX_EVIDENCE_REFS = 2000
_MAX_IDENTITY_EVIDENCE = 100
_MAX_COLLECTOR_ATTEMPTS = 100


@dataclass(frozen=True, slots=True)
class _ResolvedCohortContext:
    draft: DraftRecord
    profile: ResolvedManifestProfile
    evidence_binding: CohortEvidenceBinding
    snapshot: EvidenceSnapshot
    verified_snapshot: VerifiedCohortSnapshot
    as_of: datetime

    @property
    def cache_key(self) -> CohortBatchCacheKey:
        return CohortBatchCacheKey(
            evidence_binding=self.evidence_binding,
            snapshot_artifact_digest=self.snapshot.compatibility.artifact_digest,
        )


@dataclass(frozen=True, slots=True)
class ResolvedCohortReview:
    evidence_binding: CohortEvidenceBinding
    snapshot: EvidenceSnapshot
    batch: CohortProposalBatchResponse
    as_of: datetime


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


def _resource_records(snapshot: EvidenceSnapshot) -> list[ResourceEvidenceRecord]:
    return [
        record
        for record in snapshot.evidence_records
        if isinstance(record, ResourceEvidenceRecord)
    ]


class CohortProposalService:
    """Authenticated, draft-bound orchestration over WC-010 proposal logic."""

    def __init__(
        self,
        *,
        context_store: ContextStorePort,
        authorization: ExplicitWorkloadAuthorizationPort,
        clock: ClockPort,
        snapshot_repository: EvidenceSnapshotRepositoryPort,
        snapshot_verifier: TrustedEvidenceSnapshotVerifierPort,
        proposal_cache: CohortProposalCachePort,
        preview_receipts: CohortPreviewReceiptPort,
    ) -> None:
        self._context_store = context_store
        self._authorization = authorization
        self._clock = clock
        self._snapshot_repository = snapshot_repository
        self._snapshot_verifier = snapshot_verifier
        self._proposal_cache = proposal_cache
        self._preview_receipts = preview_receipts

    def get_proposals(
        self,
        actor: Actor,
        query: CohortProposalQuery,
    ) -> CohortProposalBatchResponse:
        resolved = self._resolve_context(actor, query)
        cached = self._proposal_cache.get_batch(resolved.cache_key)
        if cached is not None:
            self._validate_batch_binding(cached, resolved)
            self._enforce_batch_bounds(cached)
            self._ensure_current_draft(query)
            return cached

        try:
            batch = propose_cohorts(
                resolved.profile,
                resolved.verified_snapshot,
                as_of=resolved.as_of,
            )
        except AthenaValidationError as exc:
            raise EvidenceSnapshotMismatchError(
                "the verified snapshot could not produce an exact cohort proposal batch"
            ) from exc
        response = CohortProposalBatchResponse.model_validate(
            {
                "sourceDraft": {
                    "draftId": resolved.draft.draft_id,
                    "revision": resolved.draft.revision,
                    "manifestDigest": resolved.draft.manifest_digest,
                },
                **batch.model_dump(mode="python", by_alias=True, exclude_none=True),
            }
        )
        response = self._bind_direct_review_selector_ids(
            response,
            _resource_records(resolved.snapshot),
        )
        self._validate_batch_binding(response, resolved)
        self._enforce_batch_bounds(response)
        self._ensure_current_draft(query)
        stored = self._proposal_cache.put_batch_if_absent(resolved.cache_key, response)
        self._validate_batch_binding(stored, resolved)
        self._enforce_batch_bounds(stored)
        return stored

    @classmethod
    def _bind_direct_review_selector_ids(
        cls,
        batch: CohortProposalBatchResponse,
        resources: list[ResourceEvidenceRecord],
    ) -> CohortProposalBatchResponse:
        """Make safe direct-review selectors final before the human sees them."""

        proposals: list[CohortProposal] = []
        changed = False
        for proposal in batch.proposals:
            preview = proposal.selector_preview
            if preview is None:
                proposals.append(proposal)
                continue
            expected_members = {
                normalize_resource_id(member)
                for member in preview.matched_resource_ids
            }
            matches: list[ManifestSelector] = []
            for selector in proposal.role.selectors:
                if selector.selector_type != preview.selector.selector_type:
                    continue
                try:
                    result = evaluate_selector(selector, resources)
                except AthenaValidationError:
                    continue
                members = {
                    normalize_resource_id(member)
                    for member in result.matched_resource_ids
                }
                if members == expected_members:
                    matches.append(selector)
            if len(matches) != 1:
                proposals.append(proposal)
                continue
            selector_payload = preview.selector.model_dump(
                mode="python",
                by_alias=True,
                exclude_none=True,
            )
            selector_payload["selectorId"] = matches[0].selector_id
            try:
                selector = _SELECTOR_ADAPTER.validate_python(selector_payload)
                final_preview = cls._evaluate_exact_preview(selector, resources)
            except (AthenaValidationError, ValidationError) as exc:
                raise CohortContractError(
                    "direct review selector cannot be finalized before approval"
                ) from exc
            if final_preview.matched_resource_ids != preview.matched_resource_ids:
                raise CohortContractError(
                    "final direct review selector changed the proposed cohort"
                )
            proposals.append(
                proposal.model_copy(
                    update={"selector_preview": final_preview},
                    deep=True,
                )
            )
            changed = changed or final_preview != preview
        if not changed:
            return batch
        payload = batch.model_dump(
            mode="python",
            by_alias=True,
            exclude_none=True,
        )
        payload["proposals"] = proposals
        payload["proposalSetDigest"] = compute_artifact_digest(
            [
                proposal.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
                for proposal in proposals
            ]
        )
        return CohortProposalBatchResponse.model_validate(payload)

    def preview(
        self,
        actor: Actor,
        idempotency_key: str,
        request: CohortReviewPreviewRequest,
    ) -> CohortReviewCandidate:
        resolved = self._resolve_context(actor, request.proposal_query())
        batch = self._proposal_cache.get_batch(resolved.cache_key)
        if batch is None:
            raise CohortContractError(
                "the exact proposal batch must be loaded before requesting a preview"
            )
        self._validate_batch_binding(batch, resolved)
        self._enforce_batch_bounds(batch)
        if (
            request.proposal_set_digest != batch.proposal_set_digest
            or request.snapshot_artifact_digest
            != resolved.snapshot.compatibility.artifact_digest
        ):
            raise EvidenceSnapshotMismatchError(
                "preview bindings do not match the exact proposal batch and snapshot"
            )

        request_digest = compute_artifact_digest(
            {
                "operation": "cohort_preview",
                "actorId": actor.actor_id,
                "command": request.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                ),
            }
        )
        existing = self._preview_receipts.get_preview_receipt(
            actor.actor_id,
            idempotency_key,
        )
        if existing is not None:
            self._require_matching_receipt(
                existing,
                request_digest=request_digest,
                binding=resolved.evidence_binding,
            )
            proposals = self._select_proposals(batch, request)
            self._validate_candidate(existing.candidate, request, batch, proposals)
            self._enforce_candidate_bounds(existing.candidate)
            return existing.candidate

        proposals = self._select_proposals(batch, request)
        candidate = self._build_candidate(
            request,
            batch,
            proposals,
            resolved,
        )
        self._validate_candidate(candidate, request, batch, proposals)
        self._enforce_candidate_bounds(candidate)
        self._ensure_current_draft(request.proposal_query())
        receipt = CohortPreviewReceipt(
            actor_id=actor.actor_id,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            evidence_binding=resolved.evidence_binding,
            candidate=candidate,
        )
        stored = self._preview_receipts.put_preview_receipt_if_absent(receipt)
        self._require_matching_receipt(
            stored,
            request_digest=request_digest,
            binding=resolved.evidence_binding,
        )
        self._validate_candidate(stored.candidate, request, batch, proposals)
        self._enforce_candidate_bounds(stored.candidate)
        return stored.candidate

    def resolve_for_decision(
        self,
        actor: Actor,
        query: CohortProposalQuery,
        *,
        scope: ProposalScope,
    ) -> ResolvedCohortReview:
        """Revalidate the exact immutable batch and trusted snapshot for a decision."""

        if actor.kind is not ActorKind.HUMAN:
            raise AuthorizationError(
                "cohort proposal APIs require a verified human actor"
            )
        self._authorization.require_explicit(
            actor,
            Permission.READ,
            query.manifest_id,
        )
        if (
            scope.manifest_id != query.manifest_id
            or scope.manifest_version != query.manifest_version
            or scope.profile_id != query.profile_id
        ):
            raise CohortProfileMismatchError(
                "the immutable decision scope does not match its source draft binding"
            )
        as_of = ensure_timestamp(self._clock.now())
        binding = CohortEvidenceBinding(
            manifest_id=query.manifest_id,
            manifest_version=query.manifest_version,
            profile_id=query.profile_id,
            profile_type=scope.profile_type,
            resolved_profile_digest=scope.resolved_profile_digest,
            draft_id=query.draft_id,
            draft_revision=query.expected_revision,
            draft_digest=query.expected_digest,
        )
        snapshot = self._resolve_verified_snapshot(binding, as_of=as_of).snapshot
        batch = self._proposal_cache.get_batch(
            CohortBatchCacheKey(
                evidence_binding=binding,
                snapshot_artifact_digest=(
                    snapshot.compatibility.artifact_digest
                ),
            )
        )
        if batch is None:
            raise CohortContractError(
                "the exact proposal batch must be loaded before recording a decision"
            )
        self._validate_decision_batch_binding(
            batch,
            binding=binding,
            snapshot=snapshot,
        )
        self._enforce_batch_bounds(batch)
        return ResolvedCohortReview(
            evidence_binding=binding,
            snapshot=snapshot,
            batch=batch,
            as_of=as_of,
        )

    def _resolve_verified_snapshot(
        self,
        binding: CohortEvidenceBinding,
        *,
        as_of: datetime,
    ) -> VerifiedCohortSnapshot:
        stored = self._snapshot_repository.get_snapshot(binding)
        if stored is None:
            raise ResourceNotFoundError(
                "no trusted evidence snapshot exists for the exact draft "
                "and profile binding"
            )
        if stored.binding != binding:
            raise EvidenceSnapshotMismatchError(
                "snapshot repository returned a cross-binding result"
            )
        self._enforce_snapshot_bounds(stored.snapshot)
        try:
            verified = verify_cohort_snapshot(
                stored.snapshot,
                as_of=as_of,
                verifier=lambda snapshot, verified_at: self._snapshot_verifier.verify(
                    snapshot,
                    as_of=verified_at,
                ),
            )
        except AthenaValidationError as exc:
            if as_of >= stored.snapshot.expires_at:
                raise StaleEvidenceSnapshotError(
                    "the trusted evidence snapshot has expired"
                ) from exc
            raise EvidenceSnapshotMismatchError(
                "trusted evidence snapshot cryptographic verification failed"
            ) from exc
        except (RuntimeError, ValueError) as exc:
            raise EvidenceSnapshotMismatchError(
                "trusted evidence snapshot cryptographic verification failed"
            ) from exc
        snapshot = verified.snapshot
        if as_of < snapshot.collected_at or as_of >= snapshot.expires_at:
            raise StaleEvidenceSnapshotError("the trusted evidence snapshot is stale")
        return verified

    def _resolve_context(
        self,
        actor: Actor,
        query: CohortProposalQuery,
    ) -> _ResolvedCohortContext:
        if actor.kind is not ActorKind.HUMAN:
            raise AuthorizationError("cohort proposal APIs require a verified human actor")
        self._authorization.require_explicit(actor, Permission.READ, query.manifest_id)
        as_of = ensure_timestamp(self._clock.now())
        with self._context_store.transaction() as tx:
            draft = tx.get_draft(query.draft_id)
        if draft is None:
            raise ResourceNotFoundError(f"draft {query.draft_id!r} was not found")
        self._ensure_query_matches_draft(query, draft)
        if draft.state is not DraftState.DRAFT:
            raise InvalidTransitionError("cohort proposals require an active draft state")
        if (
            draft.manifest.compatibility.artifact_digest
            != draft.manifest.compute_artifact_digest_value()
            or draft.manifest_digest != draft.manifest.compatibility.artifact_digest
        ):
            raise DigestMismatchError("draft manifest digest is not canonical")
        try:
            profile = resolve_manifest_profile(
                draft.manifest,
                query.profile_id,
                as_of=as_of,
            )
        except AthenaValidationError as exc:
            raise CohortProfileMismatchError(
                "the requested profile does not resolve from the exact draft"
            ) from exc
        if (
            profile.profile_id != query.profile_id
            or profile.manifest_id != query.manifest_id
            or profile.manifest_version != query.manifest_version
        ):
            raise CohortProfileMismatchError(
                "the resolved profile does not exactly match the request binding"
            )
        binding = CohortEvidenceBinding(
            manifest_id=query.manifest_id,
            manifest_version=query.manifest_version,
            profile_id=query.profile_id,
            profile_type=profile.profile_type,
            resolved_profile_digest=profile.resolved_profile_digest,
            draft_id=query.draft_id,
            draft_revision=query.expected_revision,
            draft_digest=query.expected_digest,
        )
        verified = self._resolve_verified_snapshot(binding, as_of=as_of)
        snapshot = verified.snapshot
        profile_scopes = {
            scope.canonical_json() for scope in profile.allowed_evidence_scopes
        }
        snapshot_scopes = {
            scope.canonical_json() for scope in snapshot.authorized_scopes
        }
        if profile_scopes != snapshot_scopes:
            raise EvidenceSnapshotMismatchError(
                "snapshot authorization scopes do not exactly match the resolved profile"
            )
        return _ResolvedCohortContext(
            draft=draft,
            profile=profile,
            evidence_binding=binding,
            snapshot=snapshot,
            verified_snapshot=verified,
            as_of=as_of,
        )

    @staticmethod
    def _ensure_query_matches_draft(
        query: CohortProposalQuery,
        draft: DraftRecord,
    ) -> None:
        if draft.manifest_id != query.manifest_id:
            raise VersionMismatchError("draft belongs to a different workload")
        if draft.revision != query.expected_revision:
            raise StaleRevisionError(
                f"expected draft revision {query.expected_revision}, found {draft.revision}"
            )
        if draft.manifest.manifest_version != query.manifest_version:
            raise VersionMismatchError("expected manifest version does not match the draft")
        if draft.manifest_digest != query.expected_digest:
            raise DigestMismatchError("expected manifest digest does not match the draft")

    def _ensure_current_draft(self, query: CohortProposalQuery) -> None:
        with self._context_store.transaction() as tx:
            current = tx.get_draft(query.draft_id)
        if current is None:
            raise ResourceNotFoundError(f"draft {query.draft_id!r} was not found")
        self._ensure_query_matches_draft(query, current)
        if current.state is not DraftState.DRAFT:
            raise InvalidTransitionError("cohort proposal source draft is no longer active")

    @staticmethod
    def _validate_batch_binding(
        batch: CohortProposalBatchResponse,
        resolved: _ResolvedCohortContext,
    ) -> None:
        scope = batch.scope
        snapshot = batch.snapshot
        source = batch.source_draft
        if (
            source.draft_id != resolved.draft.draft_id
            or source.revision != resolved.draft.revision
            or source.manifest_digest != resolved.draft.manifest_digest
            or scope.manifest_id != resolved.profile.manifest_id
            or scope.manifest_version != resolved.profile.manifest_version
            or scope.profile_id != resolved.profile.profile_id
            or scope.profile_type != resolved.profile.profile_type
            or scope.resolved_profile_digest
            != resolved.profile.resolved_profile_digest
            or snapshot.snapshot_id != resolved.snapshot.snapshot_id
            or snapshot.artifact_digest
            != resolved.snapshot.compatibility.artifact_digest
            or snapshot.semantic_digest
            != resolved.snapshot.compatibility.semantic_digest
            or snapshot.collected_at != resolved.snapshot.collected_at
            or snapshot.expires_at != resolved.snapshot.expires_at
        ):
            raise EvidenceSnapshotMismatchError(
                "cohort proposal batch escaped its draft, profile, or snapshot binding"
            )
        if any(
            proposal.scope != scope or proposal.snapshot != snapshot
            for proposal in batch.proposals
        ):
            raise CohortContractError(
                "cohort proposal batch contains a cross-profile or cross-snapshot result"
            )

    @staticmethod
    def _validate_decision_batch_binding(
        batch: CohortProposalBatchResponse,
        *,
        binding: CohortEvidenceBinding,
        snapshot: EvidenceSnapshot,
    ) -> None:
        """Validate an immutable source batch without requiring the mutable draft head."""

        scope = batch.scope
        batch_snapshot = batch.snapshot
        source = batch.source_draft
        if (
            source.draft_id != binding.draft_id
            or source.revision != binding.draft_revision
            or source.manifest_digest != binding.draft_digest
            or scope.manifest_id != binding.manifest_id
            or scope.manifest_version != binding.manifest_version
            or scope.profile_id != binding.profile_id
            or scope.profile_type != binding.profile_type
            or scope.resolved_profile_digest != binding.resolved_profile_digest
            or batch_snapshot.snapshot_id != snapshot.snapshot_id
            or batch_snapshot.artifact_digest
            != snapshot.compatibility.artifact_digest
            or batch_snapshot.semantic_digest
            != snapshot.compatibility.semantic_digest
            or batch_snapshot.collected_at != snapshot.collected_at
            or batch_snapshot.expires_at != snapshot.expires_at
        ):
            raise EvidenceSnapshotMismatchError(
                "cohort proposal batch escaped its immutable decision binding"
            )
        if any(
            proposal.scope != scope or proposal.snapshot != batch_snapshot
            for proposal in batch.proposals
        ):
            raise CohortContractError(
                "cohort proposal batch contains a cross-profile or cross-snapshot result"
            )

    @staticmethod
    def _enforce_snapshot_bounds(snapshot: EvidenceSnapshot) -> None:
        if (
            len(snapshot.evidence_records) > _MAX_EVIDENCE_RECORDS
            or len(snapshot.evidence_refs) > _MAX_EVIDENCE_REFS
            or len(snapshot.identity_evidence) > _MAX_IDENTITY_EVIDENCE
            or len(snapshot.collector_attempts) > _MAX_COLLECTOR_ATTEMPTS
        ):
            raise CohortBoundaryError("trusted evidence snapshot exceeds cohort API bounds")

    @staticmethod
    def _enforce_batch_bounds(batch: CohortProposalBatchResponse) -> None:
        if len(batch.proposals) > _MAX_PROPOSALS or len(batch.conflicts) > _MAX_CONFLICTS:
            raise CohortBoundaryError("cohort proposal response exceeds adapter bounds")
        all_conflicts = [*batch.conflicts]
        for proposal in batch.proposals:
            all_conflicts.extend(proposal.conflicts)
            if (
                len(proposal.members) > 1000
                or len(proposal.dissent) > 1000
                or len(proposal.rejected_candidates) > 1000
                or len(proposal.conflicts) > _MAX_CONFLICTS
                or any(
                    len(evidence.evidence_refs) > 1000
                    for evidence in proposal.supporting_evidence
                )
                or any(len(item.evidence_refs) > 1000 for item in proposal.dissent)
                or any(
                    len(item.evidence_refs) > 1000
                    for item in proposal.rejected_candidates
                )
            ):
                raise CohortBoundaryError("cohort proposal evidence exceeds adapter bounds")
        if any(
            len(conflict.resource_ids) > 1000 or len(conflict.role_refs) > 200
            for conflict in all_conflicts
        ):
            raise CohortBoundaryError("cohort conflict response exceeds adapter bounds")
        if any(conflict.code == "overMaxMatches" for conflict in all_conflicts):
            raise CohortContractError("a cohort selector exceeded maxMatches")
        encoded = batch.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
        if len(encoded) > _MAX_RESPONSE_BYTES:
            raise CohortBoundaryError("cohort proposal response exceeds 8 MiB")

    @staticmethod
    def _select_proposals(
        batch: CohortProposalBatchResponse,
        request: CohortReviewPreviewRequest,
    ) -> list[CohortProposal]:
        by_id = {proposal.proposal_id: proposal for proposal in batch.proposals}
        try:
            proposals = [by_id[proposal_id] for proposal_id in request.proposal_ids]
        except KeyError as exc:
            raise CohortContractError(
                "preview references a proposal outside the exact cached batch"
            ) from exc
        role_refs = {
            normalized_identifier(proposal.role.role_id) for proposal in proposals
        }
        requested_role_refs = {
            normalized_identifier(role_ref) for role_ref in request.source_role_refs
        }
        if role_refs != requested_role_refs:
            raise CohortContractError(
                "source_role_refs do not exactly match the selected proposals"
            )
        if len(role_refs) != 1:
            raise CohortContractError("split and merge require one exact source role")
        if request.action == "merge" and len(proposals) > 20:
            raise CohortBoundaryError("merge exceeds the maximum of 20 bounded selectors")
        baseline = proposals[0].role
        if any(
            _authority_projection(proposal.role) != _authority_projection(baseline)
            for proposal in proposals
        ):
            raise CohortContractError(
                "selected proposals disagree on immutable role authority metadata"
            )
        if request.action == "split" and len(proposals[0].members) < 2:
            raise CohortContractError("split requires at least two source members")
        return proposals

    def _build_candidate(
        self,
        request: CohortReviewPreviewRequest,
        batch: CohortProposalBatchResponse,
        proposals: list[CohortProposal],
        resolved: _ResolvedCohortContext,
    ) -> CohortReviewCandidate:
        source_members = self._source_union(proposals)
        if len(source_members) > 1000:
            raise CohortBoundaryError("preview source union exceeds 1,000 members")
        resources = _resource_records(resolved.snapshot)
        if request.action == "split":
            previews = self._split_previews(
                source_members,
                request=request,
                resources=resources,
            )
        else:
            previews = self._merge_previews(
                proposals,
                request=request,
                resources=resources,
            )
        baseline = proposals[0].role
        role_payload = baseline.model_dump(
            mode="python",
            by_alias=True,
            exclude_none=True,
        )
        role_payload["selectors"] = [preview.selector for preview in previews]
        try:
            role = ManifestRole.model_validate(role_payload)
        except (AthenaValidationError, ValidationError) as exc:
            raise CohortContractError(
                "candidate selectors cannot form one bounded role update"
            ) from exc
        update = CohortRoleUpdate(
            role=role,
            selectorPreviews=previews,
            memberCount=len(source_members),
        )
        candidate_seed = compute_artifact_digest(
            {
                "action": request.action,
                "draftId": request.draft_id,
                "draftRevision": request.expected_revision,
                "proposalSetDigest": request.proposal_set_digest,
                "snapshotArtifactDigest": request.snapshot_artifact_digest,
                "proposalIds": request.proposal_ids,
                "sourceRoleRefs": request.source_role_refs,
                "resolution": request.resolution,
            }
        )
        return CohortReviewCandidate(
            candidateId=f"candidate-{request.action}-{candidate_seed[7:31]}",
            action=request.action,
            sourceDraft=CohortDraftBinding(
                draftId=request.draft_id,
                revision=request.expected_revision,
                manifestDigest=request.expected_digest,
            ),
            scope=batch.scope,
            sourceProposalIds=request.proposal_ids,
            proposalSetDigest=request.proposal_set_digest,
            snapshot=batch.snapshot,
            roleUpdates=[update],
            replaceRoleRefs=[baseline.role_id],
            resolution=request.resolution,
            generatedAt=resolved.as_of,
            expiresAt=resolved.snapshot.expires_at,
            requiresHumanReview=True,
            publicationAllowed=False,
            manifestMutated=False,
        )

    @staticmethod
    def _source_union(proposals: list[CohortProposal]) -> list[str]:
        normalized_members: dict[str, str] = {}
        for proposal in proposals:
            for member in proposal.members:
                try:
                    normalized = normalize_resource_id(member)
                except AthenaValidationError as exc:
                    raise CohortContractError(
                        "selected proposal contains an invalid Azure resource ID"
                    ) from exc
                if normalized in normalized_members:
                    raise CohortContractError(
                        "selected proposals contain overlapping normalized members"
                    )
                normalized_members[normalized] = normalized
        return sorted(normalized_members)

    @staticmethod
    def _split_previews(
        members: list[str],
        *,
        request: CohortReviewPreviewRequest,
        resources: list[ResourceEvidenceRecord],
    ) -> list[SelectorPreview]:
        partition_count = max(2, ceil(len(members) / 200))
        base_size, remainder = divmod(len(members), partition_count)
        partitions: list[list[str]] = []
        offset = 0
        for index in range(partition_count):
            size = base_size + (1 if index < remainder else 0)
            partition = members[offset : offset + size]
            offset += size
            if not partition or len(partition) > 200:
                raise CohortBoundaryError("split cannot be represented by bounded selectors")
            partitions.append(partition)
        seed = compute_artifact_digest(
            {
                "proposalSetDigest": request.proposal_set_digest,
                "proposalIds": request.proposal_ids,
                "members": members,
            }
        )[7:23]
        previews: list[SelectorPreview] = []
        for index, partition in enumerate(partitions, start=1):
            selector = ResourceIdListSelector(
                selectorType="resourceIdList",
                selectorId=f"preview-split-{index}-{seed}",
                resourceIds=partition,
                maxMatches=len(partition),
            )
            previews.append(
                CohortProposalService._evaluate_exact_preview(selector, resources)
            )
        return previews

    @staticmethod
    def _merge_previews(
        proposals: list[CohortProposal],
        *,
        request: CohortReviewPreviewRequest,
        resources: list[ResourceEvidenceRecord],
    ) -> list[SelectorPreview]:
        seed = compute_artifact_digest(
            {
                "proposalSetDigest": request.proposal_set_digest,
                "proposalIds": request.proposal_ids,
            }
        )[7:23]
        previews: list[SelectorPreview] = []
        for index, proposal in enumerate(proposals, start=1):
            source = proposal.selector_preview
            if source is None:
                raise CohortContractError(
                    "merge requires bounded selector previews for every source proposal"
                )
            selector_payload = source.selector.model_dump(
                mode="python",
                by_alias=True,
                exclude_none=True,
            )
            selector_payload["selectorId"] = f"preview-merge-{index}-{seed}"
            selector = _SELECTOR_ADAPTER.validate_python(selector_payload)
            preview = CohortProposalService._evaluate_exact_preview(
                selector,
                resources,
            )
            if preview.matched_resource_ids != proposal.members:
                raise CohortContractError(
                    "merge selector no longer resolves to its exact source proposal"
                )
            previews.append(preview)
        return previews

    @staticmethod
    def _evaluate_exact_preview(
        selector: ManifestSelector,
        resources: list[ResourceEvidenceRecord],
    ) -> SelectorPreview:
        try:
            result = evaluate_selector(selector, resources)
        except AthenaValidationError as exc:
            raise CohortContractError(
                "candidate selector could not be evaluated against the exact snapshot"
            ) from exc
        if (
            result.status != "matched"
            or result.max_match_violations
            or len(result.matched_resource_ids) != selector.max_matches
        ):
            raise CohortContractError(
                "candidate selector result is empty, inexact, or over maxMatches"
            )
        return SelectorPreview(
            selector=selector,
            matchedResourceIds=result.matched_resource_ids,
            selectorResultDigest=result.selector_result_digest,
            maxMatches=selector.max_matches,
        )

    @staticmethod
    def _validate_candidate(
        candidate: CohortReviewCandidate,
        request: CohortReviewPreviewRequest,
        batch: CohortProposalBatch,
        proposals: list[CohortProposal],
    ) -> None:
        source_union = set(CohortProposalService._source_union(proposals))
        preview_union: set[str] = set()
        baseline = proposals[0].role
        for update in candidate.role_updates:
            if _authority_projection(update.role) != _authority_projection(baseline):
                raise CohortContractError(
                    "preview attempted to alter role kind, cardinality, owner, or status"
                )
            update_union: set[str] = set()
            for preview in update.selector_previews:
                members = {normalize_resource_id(item) for item in preview.matched_resource_ids}
                if (
                    update_union.intersection(members)
                    or preview_union.intersection(members)
                    or preview.max_matches != len(members)
                    or preview.selector.max_matches != len(members)
                ):
                    raise CohortContractError(
                        "candidate selectors overlap or have inexact maxMatches"
                    )
                update_union.update(members)
                preview_union.update(members)
            if update.member_count != len(update_union):
                raise CohortContractError("candidate memberCount is not exact")
        expected_role_refs = {normalized_identifier(baseline.role_id)}
        if (
            candidate.action != request.action
            or candidate.source_proposal_ids != request.proposal_ids
            or candidate.proposal_set_digest != batch.proposal_set_digest
            or candidate.snapshot != batch.snapshot
            or candidate.scope != batch.scope
            or candidate.resolution != request.resolution
            or {
                normalized_identifier(role_ref)
                for role_ref in candidate.replace_role_refs
            }
            != expected_role_refs
            or {
                normalized_identifier(update.role.role_id)
                for update in candidate.role_updates
            }
            != expected_role_refs
            or len(candidate.role_updates) != 1
            or len(candidate.replace_role_refs) != 1
            or preview_union != source_union
            or not candidate.requires_human_review
            or candidate.publication_allowed
            or candidate.manifest_mutated
        ):
            raise CohortContractError(
                "candidate is not exactly bound or attempted to acquire authority"
            )

    @staticmethod
    def _enforce_candidate_bounds(candidate: CohortReviewCandidate) -> None:
        encoded = candidate.model_dump_json(
            by_alias=True,
            exclude_none=True,
        ).encode("utf-8")
        if len(encoded) > _MAX_RESPONSE_BYTES:
            raise CohortBoundaryError("cohort preview response exceeds 8 MiB")

    @staticmethod
    def _require_matching_receipt(
        receipt: CohortPreviewReceipt,
        *,
        request_digest: str,
        binding: CohortEvidenceBinding,
    ) -> None:
        if (
            receipt.request_digest != request_digest
            or receipt.evidence_binding != binding
        ):
            raise IdempotencyConflictError(
                "idempotency key was used for a different cohort environment or request"
            )


__all__ = ["CohortProposalService", "ResolvedCohortReview"]
