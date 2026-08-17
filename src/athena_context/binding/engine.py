from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from pydantic import TypeAdapter

from athena_context.binding.domain import (
    CohortProposal,
    CohortProposalBatch,
    ConfidenceBand,
    ConflictCode,
    DissentingEvidence,
    ProposalConflict,
    ProposalScope,
    ProposalSnapshot,
    RejectedCandidate,
    RejectionReason,
    SelectorPreview,
    SignalType,
    SupportingEvidence,
)
from athena_context.binding.selectors import evaluate_selector, normalize_resource_id
from athena_context.binding.verification import (
    VerifiedCohortSnapshot,
    require_current_verified_snapshot,
)
from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    compute_artifact_digest,
)
from athena_context.contracts.manifest import (
    CompositeAllSelector,
    CompositeAnySelector,
    ImageSelector,
    LoadBalancerBackendSelector,
    ManifestRole,
    ManifestSelector,
    NamePredicateSelector,
    ProvenanceSelector,
    ResolvedManifestProfile,
    ResourceIdListSelector,
    ResourceTypeSelector,
    SubnetSelector,
    TagEquals,
    TagPredicateSelector,
    VmssSelector,
    validate_resolved_manifest_profile,
)
from athena_context.contracts.models import (
    EvidenceGapRecord,
    EvidenceItemRef,
    EvidenceReference,
    EvidenceResourceRef,
    EvidenceScope,
    EvidenceSnapshot,
    LogAnalyticsWorkspaceScope,
    ObservedRelationshipEvidenceRecord,
    ResourceEvidenceRecord,
    ResourceGroupScope,
    ResourceIdScope,
    ServiceHealthRegionScope,
    SubscriptionScope,
)

_SELECTOR_ADAPTER: TypeAdapter[ManifestSelector] = TypeAdapter(ManifestSelector)


@dataclass(slots=True)
class _EvidenceIndex:
    resources: dict[str, ResourceEvidenceRecord]
    all_resources: list[ResourceEvidenceRecord]
    resource_refs: dict[str, EvidenceItemRef]
    communications: dict[str, list[tuple[str, EvidenceItemRef]]]
    rejection_reasons: dict[str, set[RejectionReason]]
    conflicts: list[ProposalConflict]


def _scope_prefix(
    scope: EvidenceScope,
    *,
    tenant_id: str,
) -> tuple[str, ...] | None:
    scope_tenant = getattr(scope, "tenant_id", None)
    if scope_tenant is not None and str(scope_tenant).casefold() != tenant_id.casefold():
        return None
    if isinstance(scope, SubscriptionScope):
        return ("subscriptions", scope.subscription_id.casefold())
    if isinstance(scope, ResourceGroupScope):
        return (
            "subscriptions",
            scope.subscription_id.casefold(),
            "resourcegroups",
            scope.resource_group_name.casefold(),
        )
    if isinstance(scope, ResourceIdScope):
        return tuple(part.casefold() for part in scope.resource_id.split("/") if part)
    if isinstance(scope, LogAnalyticsWorkspaceScope):
        return (
            "subscriptions",
            scope.subscription_id.casefold(),
            "resourcegroups",
            scope.resource_group_name.casefold(),
            "providers",
            "microsoft.operationalinsights",
            "workspaces",
            scope.workspace_name.casefold(),
        )
    if isinstance(scope, ServiceHealthRegionScope):
        return None
    return None


def _resource_in_scopes(
    resource_id: str,
    scopes: Iterable[EvidenceScope],
    *,
    tenant_id: str,
) -> bool:
    scope_list = list(scopes)
    parts = tuple(part.casefold() for part in resource_id.split("/") if part)
    tenant_bound_prefixes = [
        prefix
        for scope in scope_list
        if not isinstance(scope, ResourceIdScope)
        and (prefix := _scope_prefix(scope, tenant_id=tenant_id)) is not None
    ]
    for scope in scope_list:
        prefix = _scope_prefix(scope, tenant_id=tenant_id)
        if prefix is None or len(prefix) > len(parts) or parts[: len(prefix)] != prefix:
            continue
        if not isinstance(scope, ResourceIdScope):
            return True
        if any(
            len(parent) <= len(prefix) and prefix[: len(parent)] == parent
            for parent in tenant_bound_prefixes
        ):
            return True
    return False


def _scopes_overlap(
    left: EvidenceScope,
    right: EvidenceScope,
    *,
    tenant_id: str,
) -> bool:
    left_prefix = _scope_prefix(left, tenant_id=tenant_id)
    right_prefix = _scope_prefix(right, tenant_id=tenant_id)
    if left_prefix is None or right_prefix is None:
        return False
    if isinstance(left, ResourceIdScope) and isinstance(right, ResourceIdScope):
        return False
    shortest = min(len(left_prefix), len(right_prefix))
    return left_prefix[:shortest] == right_prefix[:shortest]


def _expected_environment(profile_type: str) -> str:
    return "disaster-recovery" if profile_type == "disasterRecovery" else profile_type


def _resource_group_name(resource_id: str) -> str | None:
    parts = resource_id.split("/")
    for index, part in enumerate(parts):
        if part.casefold() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1].casefold()
    return None


def _expected_workload_role(role: ManifestRole) -> str:
    return {
        "singletonDatabase": "database",
        "databaseReplica": "database",
        "worker": "worker",
        "webService": "web-service",
        "loadBalancer": "load-balancer",
        "integrationEndpoint": "integration",
        "storage": "storage",
        "network": "network",
        "identity": "identity",
        "observability": "observability",
        "externalDependency": "external-dependency",
    }[role.kind]


def _snapshot_details(snapshot: EvidenceSnapshot) -> ProposalSnapshot:
    return ProposalSnapshot(
        snapshotId=snapshot.snapshot_id,
        artifactDigest=snapshot.compatibility.artifact_digest,
        semanticDigest=snapshot.compatibility.semantic_digest,
        collectedAt=snapshot.collected_at,
        expiresAt=snapshot.expires_at,
    )


def _proposal_scope(profile: ResolvedManifestProfile) -> ProposalScope:
    return ProposalScope(
        manifestId=profile.manifest_id,
        manifestVersion=profile.manifest_version,
        profileId=profile.profile_id,
        profileType=profile.profile_type,
        resolvedProfileDigest=profile.resolved_profile_digest,
    )


def _detached_item_ref(ref: EvidenceItemRef) -> EvidenceReference:
    return EvidenceItemRef.model_validate(
        ref.model_dump(mode="python", by_alias=True, exclude_none=False)
    )


def _unique_refs(refs: Iterable[EvidenceItemRef]) -> list[EvidenceReference]:
    by_canonical = {ref.canonical_json(): ref for ref in refs}
    return [_detached_item_ref(by_canonical[key]) for key in sorted(by_canonical)]


def _conflict(
    code: ConflictCode,
    detail: str,
    *,
    resource_ids: Iterable[str] = (),
    role_refs: Iterable[str] = (),
) -> ProposalConflict:
    return ProposalConflict(
        code=code,
        detail=detail,
        resourceIds=sorted(set(resource_ids)),
        roleRefs=sorted(set(role_refs), key=str.casefold),
    )


def _reference_matches_snapshot(ref: EvidenceItemRef, snapshot: EvidenceSnapshot) -> bool:
    return (
        ref.snapshot_id == snapshot.snapshot_id
        and ref.snapshot_artifact_digest == snapshot.compatibility.artifact_digest
        and ref.snapshot_semantic_digest == snapshot.compatibility.semantic_digest
        and snapshot.collected_at <= ref.collector_attempt_at < snapshot.expires_at
    )


def _reference_matches_record(
    ref: EvidenceItemRef,
    record: ResourceEvidenceRecord | ObservedRelationshipEvidenceRecord,
    snapshot: EvidenceSnapshot,
) -> bool:
    provenance = record.provenance
    return (
        _reference_matches_snapshot(ref, snapshot)
        and ref.item_digest == record.item_digest
        and ref.collector_attempt_id == provenance.collector_attempt_id
        and ref.collector_attempt_digest == record.collector_attempt_digest
        and ref.collector_tool_name == provenance.tool_name
        and ref.collector_tool_version == provenance.tool_version
        and ref.collector_identity_evidence_ref == record.collector_identity_evidence_ref
        and provenance.source_response_digest is not None
        and provenance.source_response_pointer is not None
        and ref.source_response_digest == provenance.source_response_digest
        and ref.source_response_pointer == provenance.source_response_pointer
    )


def _relationship_resources(
    record: ObservedRelationshipEvidenceRecord,
) -> list[tuple[str, str]]:
    relationship = record.relationship
    result: list[tuple[str, str]] = []
    if isinstance(relationship.source, EvidenceResourceRef):
        result.append(("out", normalize_resource_id(relationship.source.resource_id)))
    if isinstance(relationship.target, EvidenceResourceRef):
        result.append(("in", normalize_resource_id(relationship.target.resource_id)))
    return result


def _communication_signature(
    record: ObservedRelationshipEvidenceRecord,
    resource_id: str,
) -> str:
    relationship = record.relationship
    source_id = (
        normalize_resource_id(relationship.source.resource_id)
        if isinstance(relationship.source, EvidenceResourceRef)
        else relationship.source.canonical_json()
    )
    target_id = (
        normalize_resource_id(relationship.target.resource_id)
        if isinstance(relationship.target, EvidenceResourceRef)
        else relationship.target.canonical_json()
    )
    if source_id == resource_id:
        return f"out:{relationship.kind}:{target_id}"
    return f"in:{relationship.kind}:{source_id}"


def _build_evidence_index(
    profile: ResolvedManifestProfile,
    snapshot: EvidenceSnapshot,
    *,
    as_of: datetime,
) -> _EvidenceIndex:
    conflicts: list[ProposalConflict] = []
    rejection_reasons: dict[str, set[RejectionReason]] = defaultdict(set)
    records_by_id: dict[str, list[ResourceEvidenceRecord]] = defaultdict(list)
    relationships: list[ObservedRelationshipEvidenceRecord] = []
    relevant_gap = False
    for record in snapshot.evidence_records:
        if isinstance(record, ResourceEvidenceRecord):
            resource_id = normalize_resource_id(record.resource_id)
            records_by_id[resource_id].append(record)
        elif isinstance(record, ObservedRelationshipEvidenceRecord):
            relationships.append(record)
        elif isinstance(record, EvidenceGapRecord) and any(
            _scopes_overlap(
                record.evidence_scope,
                scope,
                tenant_id=snapshot.collector.tenant_id,
            )
            for scope in profile.allowed_evidence_scopes
        ):
            relevant_gap = True

    if relevant_gap:
        conflicts.append(
            _conflict(
                "evidenceGap",
                "the snapshot contains a resource evidence gap overlapping the profile scope",
            )
        )

    resources: dict[str, ResourceEvidenceRecord] = {}
    for resource_id, records in records_by_id.items():
        if len(records) != 1:
            rejection_reasons[resource_id].add("duplicateResourceId")
            conflicts.append(
                _conflict(
                    "duplicateResourceId",
                    "multiple records normalize to the same Azure resource ID",
                    resource_ids=[resource_id],
                )
            )
        else:
            resources[resource_id] = records[0]

    item_refs_by_digest: dict[str, list[EvidenceItemRef]] = defaultdict(list)
    for ref in snapshot.evidence_refs:
        if isinstance(ref, EvidenceItemRef):
            item_refs_by_digest[ref.item_digest].append(ref)

    resource_refs: dict[str, EvidenceItemRef] = {}
    expected_environment = _expected_environment(profile.profile_type)
    for resource_id, record in resources.items():
        refs = [
            ref
            for ref in item_refs_by_digest.get(record.item_digest, [])
            if _reference_matches_record(ref, record, snapshot)
        ]
        if len(refs) != 1:
            rejection_reasons[resource_id].add("invalidEvidenceReference")
            conflicts.append(
                _conflict(
                    "invalidEvidenceReference",
                    "resource record does not resolve to exactly one bound EvidenceItemRef",
                    resource_ids=[resource_id],
                )
            )
        else:
            resource_refs[resource_id] = refs[0]
        if not _resource_in_scopes(
            resource_id,
            profile.allowed_evidence_scopes,
            tenant_id=snapshot.collector.tenant_id,
        ):
            rejection_reasons[resource_id].add("outOfProfileScope")
        if not _resource_in_scopes(
            resource_id,
            snapshot.authorized_scopes,
            tenant_id=snapshot.collector.tenant_id,
        ):
            rejection_reasons[resource_id].add("outOfSnapshotScope")
        if record.tags.environment is None:
            rejection_reasons[resource_id].add("missingEnvironment")
        elif record.tags.environment.casefold() != expected_environment.casefold():
            rejection_reasons[resource_id].add("crossEnvironment")

    communications: dict[str, list[tuple[str, EvidenceItemRef]]] = defaultdict(list)
    for record in relationships:
        refs = [
            ref
            for ref in item_refs_by_digest.get(record.item_digest, [])
            if _reference_matches_record(ref, record, snapshot)
        ]
        if (
            len(refs) != 1
            or record.relationship.observed_at > as_of
            or not (
                snapshot.collected_at
                <= record.relationship.observed_at
                < snapshot.expires_at
            )
        ):
            continue
        for _, resource_id in _relationship_resources(record):
            if resource_id in resources:
                communications[resource_id].append(
                    (_communication_signature(record, resource_id), refs[0])
                )

    return _EvidenceIndex(
        resources=resources,
        all_resources=list(resources.values()),
        resource_refs=resource_refs,
        communications=communications,
        rejection_reasons=rejection_reasons,
        conflicts=conflicts,
    )


def _vmss_anchor(resource_id: str) -> str | None:
    parts = resource_id.split("/")
    lowered = [part.casefold() for part in parts]
    for index in range(len(parts) - 4):
        if (
            lowered[index] == "providers"
            and lowered[index + 1] == "microsoft.compute"
            and lowered[index + 2] == "virtualmachinescalesets"
            and lowered[index + 4] == "virtualmachines"
        ):
            return normalize_resource_id("/".join(parts[: index + 4]))
    return None


def _candidate_groups(candidates: list[str]) -> list[tuple[str, list[str]]]:
    if not candidates:
        return [("none", [])]
    anchors = {resource_id: _vmss_anchor(resource_id) for resource_id in candidates}
    if all(anchor is not None for anchor in anchors.values()):
        groups: dict[str, list[str]] = defaultdict(list)
        for resource_id, anchor in anchors.items():
            if anchor is not None:
                groups[anchor].append(resource_id)
        return [
            (key, sorted(members))
            for key, members in sorted(groups.items(), key=lambda item: item[0])
        ]
    return [("unanchored", sorted(candidates))]


def _selector_signal_type(selector: ManifestSelector) -> SignalType:
    if isinstance(selector, NamePredicateSelector):
        return "namePredicate"
    if isinstance(selector, ResourceTypeSelector):
        return "resourceType"
    if isinstance(selector, VmssSelector):
        return "vmScaleSet"
    if isinstance(selector, LoadBalancerBackendSelector):
        return "loadBalancerBackend"
    if isinstance(selector, SubnetSelector):
        return "subnet"
    if isinstance(selector, ImageSelector):
        return "image"
    if isinstance(selector, ProvenanceSelector):
        return "provenance"
    if isinstance(selector, TagPredicateSelector):
        return "approvedTags"
    if isinstance(selector, ResourceIdListSelector):
        return "resourceType"
    return "resourceType"


def _selector_atoms(selector: ManifestSelector) -> list[ManifestSelector]:
    if isinstance(selector, (CompositeAllSelector, CompositeAnySelector)):
        return [*selector.children]
    return [selector]


def _clone_atomic(
    selector: ManifestSelector,
    *,
    selector_id: str,
    max_matches: int,
) -> ManifestSelector:
    payload = selector.model_dump(mode="json", by_alias=True, exclude_none=True)
    payload["selectorId"] = selector_id
    payload["maxMatches"] = max_matches
    return _SELECTOR_ADAPTER.validate_python(payload)


def _preview_candidates(
    role: ManifestRole,
    profile: ResolvedManifestProfile,
    members: list[str],
    index: _EvidenceIndex,
) -> list[ManifestSelector]:
    total_bound = max(1, min(1000, len(index.resources)))
    candidates: list[ManifestSelector] = []
    sequence = 0

    for selector in role.selectors:
        for atom in _selector_atoms(selector):
            evaluation = evaluate_selector(
                atom,
                list(index.resources.values()),
            )
            if set(members).issubset(evaluation.matched_resource_ids):
                sequence += 1
                candidates.append(
                    _clone_atomic(
                        atom,
                        selector_id=f"preview-{sequence}",
                        max_matches=total_bound,
                    )
                )

    vmss_anchors = {_vmss_anchor(resource_id) for resource_id in members}
    if len(vmss_anchors) == 1 and None not in vmss_anchors:
        sequence += 1
        candidates.append(
            VmssSelector(
                selectorType="vmScaleSet",
                selectorId=f"preview-{sequence}",
                scaleSetResourceId=cast(str, next(iter(vmss_anchors))),
                instanceIds=[],
                maxMatches=total_bound,
            )
        )

    expected_environment = _expected_environment(profile.profile_type)
    expected_role = _expected_workload_role(role)
    if all(
        index.resources[resource_id].tags.environment == expected_environment
        and index.resources[resource_id].tags.workload_role == expected_role
        for resource_id in members
    ):
        sequence += 1
        candidates.append(
            TagPredicateSelector(
                selectorType="tagPredicate",
                selectorId=f"preview-{sequence}",
                predicates=[
                    TagEquals(key="environment", value=expected_environment),
                    TagEquals(key="workloadRole", value=expected_role),
                ],
                maxMatches=total_bound,
            )
        )

    resource_types = {index.resources[item].resource_type for item in members}
    locations = {index.resources[item].location for item in members}
    resource_groups = {
        group
        for item in members
        if (group := _resource_group_name(index.resources[item].resource_id)) is not None
    }
    all_have_resource_groups = len(resource_groups) == 1 and all(
        _resource_group_name(index.resources[item].resource_id) is not None
        for item in members
    )
    if len(resource_types) == len(locations) == 1 and all_have_resource_groups:
        sequence += 1
        candidates.append(
            ResourceTypeSelector(
                selectorType="resourceType",
                selectorId=f"preview-{sequence}",
                resourceType=next(iter(resource_types)),
                locations=[next(iter(locations))],
                resourceGroups=[next(iter(resource_groups))],
                maxMatches=total_bound,
            )
        )

    provenance = {
        (
            index.resources[item].provenance.tool_name,
            index.resources[item].provenance.tool_version,
            index.resources[item].collector_identity_evidence_ref,
        )
        for item in members
    }
    if len(provenance) == 1:
        tool, version, identity = next(iter(provenance))
        sequence += 1
        candidates.append(
            ProvenanceSelector(
                selectorType="provenance",
                selectorId=f"preview-{sequence}",
                collectorToolName=tool,
                collectorToolVersion=version,
                identityEvidenceRef=identity,
                maxMatches=total_bound,
            )
        )

    unique: dict[str, ManifestSelector] = {}
    for candidate in candidates:
        fingerprint = candidate.model_dump(
            mode="json",
            by_alias=True,
            exclude={"selector_id", "max_matches"},
            exclude_none=True,
        )
        unique.setdefault(canonicalize_json(fingerprint), candidate)
    return list(unique.values())


def _build_selector_preview(
    role: ManifestRole,
    profile: ResolvedManifestProfile,
    members: list[str],
    index: _EvidenceIndex,
) -> SelectorPreview | None:
    if not members or len(members) > 1000:
        return None
    member_set = set(members)
    evaluated: list[tuple[ManifestSelector, set[str]]] = []
    for candidate in _preview_candidates(role, profile, members, index):
        result = evaluate_selector(
            candidate,
            index.all_resources,
        )
        matched = set(result.matched_resource_ids)
        if not result.max_match_violations and member_set.issubset(matched):
            evaluated.append((candidate, matched))
    evaluated.sort(
        key=lambda item: (
            len(item[1]),
            item[0].selector_type,
            item[0].canonical_json(),
        )
    )

    chosen: list[ManifestSelector] = []
    intersection = set(normalize_resource_id(item.resource_id) for item in index.all_resources)
    if intersection == member_set and evaluated:
        chosen.append(evaluated[0][0])
    else:
        for candidate, matched in evaluated:
            narrowed = intersection.intersection(matched)
            if narrowed == intersection:
                continue
            chosen.append(candidate)
            intersection = narrowed
            if intersection == member_set or len(chosen) == 10:
                break

    if intersection != member_set and len(members) <= 200:
        selector: ManifestSelector = ResourceIdListSelector(
            selectorType="resourceIdList",
            selectorId="preview-resource-ids",
            resourceIds=members,
            maxMatches=len(members),
        )
    elif intersection == member_set and len(chosen) == 1:
        selector = _clone_atomic(
            chosen[0],
            selector_id="preview-cohort",
            max_matches=len(members),
        )
    elif intersection == member_set and 1 < len(chosen) <= 10:
        children = [
            cast(
                Any,
                _clone_atomic(
                    candidate,
                    selector_id=f"preview-child-{index_value + 1}",
                    max_matches=max(1, min(1000, len(index.resources))),
                ),
            )
            for index_value, candidate in enumerate(chosen)
        ]
        selector = CompositeAllSelector(
            selectorType="compositeAll",
            selectorId="preview-cohort",
            children=children,
            maxMatches=len(members),
        )
    else:
        return None

    result = evaluate_selector(selector, index.all_resources)
    if result.status != "matched" or result.matched_resource_ids != members:
        return None
    return SelectorPreview(
        selector=selector,
        matchedResourceIds=result.matched_resource_ids,
        selectorResultDigest=result.selector_result_digest,
        maxMatches=selector.max_matches,
    )


def _support_and_dissent(
    role: ManifestRole,
    profile: ResolvedManifestProfile,
    members: list[str],
    index: _EvidenceIndex,
    selector_results: list[Any],
) -> tuple[list[SupportingEvidence], list[DissentingEvidence]]:
    supporting: list[SupportingEvidence] = []
    dissent: list[DissentingEvidence] = []
    member_refs = _unique_refs(index.resource_refs[item] for item in members)

    for selector, result in zip(role.selectors, selector_results, strict=True):
        if result.status == "matched" and set(members).issubset(result.matched_resource_ids):
            supporting.append(
                SupportingEvidence(
                    signalType=_selector_signal_type(selector),
                    signalValue=selector.canonical_json(),
                    memberResourceIds=members,
                    evidenceRefs=member_refs,
                )
            )

    vmss_anchors = {_vmss_anchor(resource_id) for resource_id in members}
    if len(vmss_anchors) == 1 and None not in vmss_anchors:
        supporting.append(
            SupportingEvidence(
                signalType="vmScaleSet",
                signalValue=cast(str, next(iter(vmss_anchors))),
                memberResourceIds=members,
                evidenceRefs=member_refs,
            )
        )

    expected_environment = _expected_environment(profile.profile_type)
    expected_role = _expected_workload_role(role)
    if all(
        index.resources[item].tags.environment == expected_environment
        and index.resources[item].tags.workload_role == expected_role
        for item in members
    ):
        supporting.append(
            SupportingEvidence(
                signalType="approvedTags",
                signalValue=f"environment={expected_environment};workloadRole={expected_role}",
                memberResourceIds=members,
                evidenceRefs=member_refs,
            )
        )
    else:
        for resource_id in members:
            record = index.resources[resource_id]
            if (
                record.tags.environment != expected_environment
                or record.tags.workload_role != expected_role
            ):
                dissent.append(
                    DissentingEvidence(
                        resourceId=resource_id,
                        signalType="approvedTags",
                        expectedValue=(
                            f"environment={expected_environment};workloadRole={expected_role}"
                        ),
                        observedValue=(
                            f"environment={record.tags.environment};"
                            f"workloadRole={record.tags.workload_role}"
                        ),
                        reason="approved tags do not fully corroborate the proposed role",
                        evidenceRefs=[
                            _detached_item_ref(index.resource_refs[resource_id])
                        ],
                    )
                )

    communication_sets = [
        {signature for signature, _ in index.communications.get(resource_id, [])}
        for resource_id in members
    ]
    if communication_sets and all(communication_sets):
        common_communications = set.intersection(*communication_sets)
        if common_communications:
            refs = [
                ref
                for resource_id in members
                for signature, ref in index.communications.get(resource_id, [])
                if signature in common_communications
            ]
            supporting.append(
                SupportingEvidence(
                    signalType="observedCommunication",
                    signalValue=canonicalize_json(sorted(common_communications)),
                    memberResourceIds=members,
                    evidenceRefs=_unique_refs(refs),
                )
            )
        else:
            for resource_id in members:
                dissent.append(
                    DissentingEvidence(
                        resourceId=resource_id,
                        signalType="observedCommunication",
                        expectedValue="a communication signature shared by the cohort",
                        observedValue=canonicalize_json(
                            sorted(
                                signature
                                for signature, _ in index.communications.get(resource_id, [])
                            )
                        ),
                        reason="observed communication behavior differs across cohort members",
                        evidenceRefs=_unique_refs(
                            ref for _, ref in index.communications.get(resource_id, [])
                        ),
                    )
                )
    elif any(communication_sets):
        for resource_id, signatures in zip(members, communication_sets, strict=True):
            if not signatures:
                dissent.append(
                    DissentingEvidence(
                        resourceId=resource_id,
                        signalType="observedCommunication",
                        expectedValue="canonical observed communication evidence",
                        observedValue=None,
                        reason="communication evidence is missing for this cohort member",
                        evidenceRefs=[],
                    )
                )

    supporting.sort(key=lambda item: (item.signal_type, item.signal_value))
    dissent.sort(key=lambda item: (item.resource_id, item.signal_type, item.reason))
    return supporting, dissent


def _confidence(
    supporting: Sequence[SupportingEvidence],
    dissent: Sequence[DissentingEvidence],
    conflicts: Sequence[ProposalConflict],
    members: Sequence[str],
    preview: SelectorPreview | None,
) -> tuple[float, ConfidenceBand]:
    if not members:
        return 0.0, "low"
    independent_source_sets: list[set[str]] = []
    for evidence in supporting:
        source_set = {
            ref.item_digest
            for ref in evidence.evidence_refs
            if isinstance(ref, EvidenceItemRef)
        }
        if source_set and not any(
            source_set.intersection(existing) for existing in independent_source_sets
        ):
            independent_source_sets.append(source_set)
    independent_sources = len(independent_source_sets)
    score = {0: 0.2, 1: 0.45, 2: 0.65, 3: 0.82, 4: 0.9}.get(
        min(independent_sources, 4),
        0.95,
    )
    if dissent or conflicts or preview is None:
        return min(score, 0.59), "conflicting"
    if score >= 0.8:
        return score, "high"
    if score >= 0.6:
        return score, "medium"
    return score, "low"


def _proposal_id(
    profile: ResolvedManifestProfile,
    snapshot: EvidenceSnapshot,
    role: ManifestRole,
    members: Sequence[str],
    anchor: str,
) -> str:
    digest = compute_artifact_digest(
        {
            "profileDigest": profile.resolved_profile_digest,
            "snapshotSemanticDigest": snapshot.compatibility.semantic_digest,
            "roleRef": role.role_id.casefold(),
            "members": list(members),
            "anchor": anchor,
        }
    )
    return "proposal-" + digest.removeprefix("sha256:")[:16]


def _detached_role(role: ManifestRole) -> ManifestRole:
    """Reconstruct proposal intent so review edits cannot alias approved intent."""

    return ManifestRole.model_validate(
        role.model_dump(mode="python", by_alias=True, exclude_none=False)
    )


def _request_digest(
    profile: ResolvedManifestProfile,
    snapshot: EvidenceSnapshot,
    as_of: datetime,
) -> str:
    return compute_artifact_digest(
        {
            "profileDigest": profile.resolved_profile_digest,
            "snapshotId": snapshot.snapshot_id,
            "snapshotArtifactDigest": snapshot.compatibility.artifact_digest,
            "snapshotSemanticDigest": snapshot.compatibility.semantic_digest,
            "evaluatedAt": as_of,
            "evidenceRecords": sorted(
                [
                    record.record_type,
                    record.item_digest,
                ]
                for record in snapshot.evidence_records
            ),
            "evidenceRefs": sorted(ref.canonical_json() for ref in snapshot.evidence_refs),
        }
    )


def propose_cohorts(
    profile: ResolvedManifestProfile,
    verified_snapshot: VerifiedCohortSnapshot,
    *,
    as_of: datetime,
) -> CohortProposalBatch:
    """Build review-only proposals from an exactly verified canonical snapshot."""

    if as_of.tzinfo is None or as_of.microsecond % 1000:
        raise AthenaValidationError(
            "as_of must be timezone-aware and exactly representable in milliseconds"
        )
    if as_of.utcoffset() != UTC.utcoffset(as_of):
        raise AthenaValidationError("as_of must use UTC")
    validate_resolved_manifest_profile(profile, as_of=as_of)
    snapshot = require_current_verified_snapshot(verified_snapshot, as_of=as_of)
    roles = sorted(
        (role for role in profile.roles if role.status == "approved"),
        key=lambda item: item.role_id.casefold(),
    )
    role_by_id = {role.role_id.casefold(): role for role in roles}
    if len(role_by_id) != len(roles):
        raise AthenaValidationError("resolved profile contains duplicate normalized role IDs")

    index = _build_evidence_index(profile, snapshot, as_of=as_of)
    selector_results: dict[str, list[Any]] = {}
    selector_roles_by_resource: dict[str, set[str]] = defaultdict(set)
    role_over_max: dict[str, list[str]] = {}
    for role in roles:
        role_key = role.role_id.casefold()
        results = [
            evaluate_selector(
                selector,
                list(index.resources.values()),
            )
            for selector in role.selectors
        ]
        selector_results[role_key] = results
        violations = sorted(
            {
                selector_id
                for result in results
                for selector_id in result.max_match_violations
            }
        )
        if violations:
            role_over_max[role_key] = violations
        for result in results:
            for resource_id in result.matched_resource_ids:
                selector_roles_by_resource[resource_id].add(role_key)

    candidates_by_role: dict[str, list[str]] = defaultdict(list)
    related_roles: dict[str, set[str]] = defaultdict(set)
    resource_role_reasons: dict[str, set[RejectionReason]] = defaultdict(set)
    for resource_id, record in index.resources.items():
        selector_roles = selector_roles_by_resource.get(resource_id, set())
        tagged_roles = {
            role.role_id.casefold()
            for role in roles
            if record.tags.workload_role == _expected_workload_role(role)
        }
        related_roles[resource_id].update(selector_roles | tagged_roles)
        if selector_roles and tagged_roles:
            possible_roles = selector_roles.intersection(tagged_roles)
            if not possible_roles:
                resource_role_reasons[resource_id].add("conflictingRoleEvidence")
                continue
        elif selector_roles:
            possible_roles = set(selector_roles)
        else:
            possible_roles = set(tagged_roles)

        if not possible_roles:
            resource_role_reasons[resource_id].add("missingRoleEvidence")
            continue
        if len(possible_roles) != 1:
            resource_role_reasons[resource_id].add("ambiguousRole")
            continue
        role_key = next(iter(possible_roles))
        if role_key in role_over_max:
            resource_role_reasons[resource_id].add("overMaxMatches")
            continue
        if index.rejection_reasons.get(resource_id):
            continue
        candidates_by_role[role_key].append(resource_id)

    ambiguous_resources = sorted(
        resource_id
        for resource_id, reasons in resource_role_reasons.items()
        if "ambiguousRole" in reasons or "conflictingRoleEvidence" in reasons
    )
    unbound_resources = sorted(
        resource_id
        for resource_id, reasons in resource_role_reasons.items()
        if "missingRoleEvidence" in reasons
    )
    batch_conflicts = list(index.conflicts)
    if unbound_resources:
        batch_conflicts.append(
            _conflict(
                "missingEvidence",
                "one or more in-scope resources have no exact role evidence",
                resource_ids=unbound_resources,
            )
        )
    if ambiguous_resources:
        batch_conflicts.append(
            _conflict(
                "ambiguousRole",
                "one or more resources have ambiguous or conflicting exact-role evidence",
                resource_ids=ambiguous_resources,
                role_refs={
                    role_id
                    for resource_id in ambiguous_resources
                    for role_id in related_roles[resource_id]
                },
            )
        )

    scope = _proposal_scope(profile)
    snapshot_details = _snapshot_details(snapshot)
    proposals: list[CohortProposal] = []
    for role in roles:
        role_key = role.role_id.casefold()
        groups = _candidate_groups(sorted(candidates_by_role.get(role_key, [])))
        for anchor, members in groups:
            conflicts = list(index.conflicts)
            if unbound_resources:
                conflicts.append(
                    _conflict(
                        "missingEvidence",
                        "the scoped estate contains resources with no exact role evidence",
                        resource_ids=unbound_resources,
                    )
                )
            if role_key in role_over_max:
                conflicts.append(
                    _conflict(
                        "overMaxMatches",
                        "an approved role selector exceeded maxMatches",
                        role_refs=[role.role_id],
                    )
                )
            supporting: list[SupportingEvidence] = []
            dissent: list[DissentingEvidence] = []
            if members:
                supporting, dissent = _support_and_dissent(
                    role,
                    profile,
                    members,
                    index,
                    selector_results[role_key],
                )
            if dissent:
                conflicts.append(
                    _conflict(
                        "conflictingSignal",
                        "cohort evidence contains missing or dissenting signals",
                        resource_ids={item.resource_id for item in dissent},
                        role_refs=[role.role_id],
                    )
                )
            if not members:
                conflicts.append(
                    _conflict(
                        "noEligibleMembers",
                        "no resources have exclusive, in-scope evidence for this role",
                        role_refs=[role.role_id],
                    )
                )

            preview = _build_selector_preview(role, profile, members, index)
            if members and preview is None:
                conflicts.append(
                    _conflict(
                        "selectorPreviewMismatch",
                        "no bounded ManifestSelector preview resolves to exactly this cohort",
                        resource_ids=members,
                        role_refs=[role.role_id],
                    )
                )

            rejected: list[RejectedCandidate] = []
            for resource_id in sorted(index.resources):
                reasons: set[RejectionReason] = set()
                if role_key in related_roles.get(resource_id, set()):
                    reasons.update(index.rejection_reasons.get(resource_id, set()))
                    reasons.update(resource_role_reasons.get(resource_id, set()))
                    if (
                        resource_id in candidates_by_role.get(role_key, [])
                        and resource_id not in members
                    ):
                        reasons.add("differentCohortSignal")
                if role_key in role_over_max and role_key in related_roles.get(resource_id, set()):
                    reasons.add("overMaxMatches")
                if reasons:
                    ref = index.resource_refs.get(resource_id)
                    rejected.append(
                        RejectedCandidate(
                            resourceId=resource_id,
                            reasons=sorted(reasons),
                            evidenceRefs=(
                                [_detached_item_ref(ref)] if ref is not None else []
                            ),
                        )
                    )

            rejected_reason_set = {
                reason for candidate in rejected for reason in candidate.reasons
            }
            if "crossEnvironment" in rejected_reason_set:
                conflicts.append(
                    _conflict(
                        "crossEnvironment",
                        "a role candidate carries a different environment tag",
                        resource_ids={
                            item.resource_id
                            for item in rejected
                            if "crossEnvironment" in item.reasons
                        },
                        role_refs=[role.role_id],
                    )
                )
            if {
                "outOfProfileScope",
                "outOfSnapshotScope",
            }.intersection(rejected_reason_set):
                conflicts.append(
                    _conflict(
                        "outOfScope",
                        "a role candidate is outside the profile or authorized snapshot scope",
                        resource_ids={
                            item.resource_id
                            for item in rejected
                            if {
                                "outOfProfileScope",
                                "outOfSnapshotScope",
                            }.intersection(item.reasons)
                        },
                        role_refs=[role.role_id],
                    )
                )
            if "missingEnvironment" in rejected_reason_set:
                conflicts.append(
                    _conflict(
                        "missingEvidence",
                        "a role candidate has no approved environment tag",
                        resource_ids={
                            item.resource_id
                            for item in rejected
                            if "missingEnvironment" in item.reasons
                        },
                        role_refs=[role.role_id],
                    )
                )
            if {
                "ambiguousRole",
                "conflictingRoleEvidence",
            }.intersection(rejected_reason_set):
                conflicts.append(
                    _conflict(
                        "ambiguousRole",
                        "a role candidate has ambiguous or conflicting exact-role evidence",
                        resource_ids={
                            item.resource_id
                            for item in rejected
                            if {
                                "ambiguousRole",
                                "conflictingRoleEvidence",
                            }.intersection(item.reasons)
                        },
                        role_refs=[role.role_id],
                    )
                )

            confidence, band = _confidence(
                supporting,
                dissent,
                conflicts,
                members,
                preview,
            )
            high = band == "high"
            proposals.append(
                CohortProposal(
                    proposalId=_proposal_id(profile, snapshot, role, members, anchor),
                    scope=scope,
                    role=_detached_role(role),
                    members=members,
                    confidence=confidence,
                    confidenceBand=band,
                    supportingEvidence=supporting,
                    dissent=dissent,
                    rejectedCandidates=rejected,
                    conflicts=sorted(
                        conflicts,
                        key=lambda item: (
                            item.code,
                            item.detail,
                            canonicalize_json(item.resource_ids),
                        ),
                    ),
                    selectorPreview=preview,
                    snapshot=snapshot_details,
                    disposition="bulkHumanReview" if high else "humanResolution",
                    bulkReviewEligible=high,
                    requiresHumanReview=True,
                    publicationAllowed=False,
                    manifestMutated=False,
                )
            )

    proposals.sort(key=lambda item: (item.role.role_id.casefold(), item.proposal_id))
    input_digest = _request_digest(profile, snapshot, as_of)
    proposal_set_digest = compute_artifact_digest(
        [
            proposal.model_dump(mode="json", by_alias=True, exclude_none=True)
            for proposal in proposals
        ]
    )
    return CohortProposalBatch(
        scope=scope,
        snapshot=snapshot_details,
        evaluatedAt=as_of,
        inputDigest=input_digest,
        proposalSetDigest=proposal_set_digest,
        proposals=proposals,
        conflicts=sorted(
            batch_conflicts,
            key=lambda item: (
                item.code,
                item.detail,
                canonicalize_json(item.resource_ids),
            ),
        ),
        requiresHumanReview=True,
        publicationAllowed=False,
        manifestMutated=False,
    )


__all__ = ["propose_cohorts"]
