from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Literal, cast, get_args

from athena_context.binding.domain import (
    CohortSignalEvidence,
    ImageSignalEvidence,
    LoadBalancerBackendSignalEvidence,
    SelectorEvaluation,
    SubnetSignalEvidence,
    VmssSignalEvidence,
)
from athena_context.binding.normalization import normalize_resource_id
from athena_context.contracts.common import (
    AthenaValidationError,
    compute_artifact_digest,
    normalize_nfc_text,
)
from athena_context.contracts.manifest import (
    CompositeAllSelector,
    CompositeAnySelector,
    ImageSelector,
    LoadBalancerBackendSelector,
    ManifestSelector,
    NamePredicateSelector,
    ProvenanceSelector,
    ResourceIdListSelector,
    ResourceTypeSelector,
    SubnetSelector,
    TagPredicateSelector,
    VmssSelector,
)
from athena_context.contracts.models import ResourceEvidenceRecord

_RUNTIME_VARIANTS = (
    ResourceIdListSelector,
    TagPredicateSelector,
    NamePredicateSelector,
    ResourceTypeSelector,
    VmssSelector,
    LoadBalancerBackendSelector,
    SubnetSelector,
    ImageSelector,
    ProvenanceSelector,
    CompositeAllSelector,
    CompositeAnySelector,
)


def selector_runtime_variants() -> frozenset[str]:
    """Return the selector discriminators covered by the deterministic runtime."""

    return frozenset(
        cast(str, get_args(selector_type.model_fields["selector_type"].annotation)[0])
        for selector_type in _RUNTIME_VARIANTS
    )


def _comparison_text(value: str) -> str:
    return normalize_nfc_text(value).casefold()


def _resource_name(resource_id: str) -> str:
    return resource_id.rsplit("/", 1)[-1]


def _resource_group(resource_id: str) -> str | None:
    parts = resource_id.split("/")
    for index, part in enumerate(parts):
        if part.casefold() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1]
    return None


def _signals_by_resource(
    signals: Iterable[CohortSignalEvidence],
    resource_ids: set[str],
) -> dict[str, list[CohortSignalEvidence]]:
    indexed: dict[str, list[CohortSignalEvidence]] = defaultdict(list)
    for signal in signals:
        normalized_id = normalize_resource_id(signal.resource_id)
        if normalized_id not in resource_ids:
            raise AthenaValidationError(
                "selector signal resourceId must resolve to exactly one supplied resource"
            )
        indexed[normalized_id].append(signal)
    return indexed


def _tag_matches(selector: TagPredicateSelector, resource: ResourceEvidenceRecord) -> bool:
    tags = resource.tags.model_dump(mode="json", by_alias=True, exclude_none=True)
    normalized_tags = {
        _comparison_text(str(key)): _comparison_text(str(value))
        for key, value in tags.items()
    }
    return all(
        normalized_tags.get(_comparison_text(predicate.key))
        == _comparison_text(predicate.value)
        for predicate in selector.predicates
    )


def _signal_matches(
    selector: ManifestSelector,
    signal: CohortSignalEvidence,
) -> bool:
    if isinstance(selector, VmssSelector) and isinstance(signal, VmssSignalEvidence):
        scale_set_matches = _comparison_text(signal.scale_set_resource_id) == _comparison_text(
            selector.scale_set_resource_id
        )
        instance_matches = not selector.instance_ids or (
            signal.instance_id is not None
            and _comparison_text(signal.instance_id)
            in {_comparison_text(item) for item in selector.instance_ids}
        )
        return scale_set_matches and instance_matches
    if isinstance(selector, LoadBalancerBackendSelector) and isinstance(
        signal, LoadBalancerBackendSignalEvidence
    ):
        return (
            _comparison_text(signal.load_balancer_resource_id)
            == _comparison_text(selector.load_balancer_resource_id)
            and _comparison_text(signal.backend_pool_name)
            == _comparison_text(selector.backend_pool_name)
        )
    if isinstance(selector, SubnetSelector) and isinstance(signal, SubnetSignalEvidence):
        return _comparison_text(signal.subnet_resource_id) == _comparison_text(
            selector.subnet_resource_id
        )
    if isinstance(selector, ImageSelector) and isinstance(signal, ImageSignalEvidence):
        return (
            _comparison_text(signal.publisher) == _comparison_text(selector.publisher)
            and _comparison_text(signal.offer) == _comparison_text(selector.offer)
            and _comparison_text(signal.sku) == _comparison_text(selector.sku)
            and (
                selector.version is None
                or (
                    signal.version is not None
                    and _comparison_text(signal.version) == _comparison_text(selector.version)
                )
            )
        )
    return False


def _atomic_matches(
    selector: ManifestSelector,
    resources: dict[str, ResourceEvidenceRecord],
    signals: dict[str, list[CohortSignalEvidence]],
) -> set[str]:
    if isinstance(selector, ResourceIdListSelector):
        selected = {_comparison_text(item) for item in selector.resource_ids}
        return set(resources).intersection(selected)
    if isinstance(selector, TagPredicateSelector):
        return {
            resource_id
            for resource_id, resource in resources.items()
            if _tag_matches(selector, resource)
        }
    if isinstance(selector, NamePredicateSelector):
        prefix = _comparison_text(selector.prefix) if selector.prefix is not None else None
        suffix = _comparison_text(selector.suffix) if selector.suffix is not None else None
        return {
            resource_id
            for resource_id in resources
            if (
                prefix is None
                or _comparison_text(_resource_name(resource_id)).startswith(prefix)
            )
            and (
                suffix is None
                or _comparison_text(_resource_name(resource_id)).endswith(suffix)
            )
        }
    if isinstance(selector, ResourceTypeSelector):
        locations = {_comparison_text(item) for item in selector.locations}
        resource_groups = {_comparison_text(item) for item in selector.resource_groups}
        return {
            resource_id
            for resource_id, resource in resources.items()
            if _comparison_text(resource.resource_type)
            == _comparison_text(selector.resource_type)
            and (not locations or _comparison_text(resource.location) in locations)
            and (
                not resource_groups
                or (
                    (group := _resource_group(resource.resource_id)) is not None
                    and _comparison_text(group) in resource_groups
                )
            )
        }
    if isinstance(
        selector,
        (VmssSelector, LoadBalancerBackendSelector, SubnetSelector, ImageSelector),
    ):
        return {
            resource_id
            for resource_id, resource_signals in signals.items()
            if any(_signal_matches(selector, signal) for signal in resource_signals)
        }
    if isinstance(selector, ProvenanceSelector):
        return {
            resource_id
            for resource_id, resource in resources.items()
            if _comparison_text(resource.provenance.tool_name)
            == _comparison_text(selector.collector_tool_name)
            and _comparison_text(resource.provenance.tool_version)
            == _comparison_text(selector.collector_tool_version)
            and _comparison_text(resource.collector_identity_evidence_ref)
            == _comparison_text(selector.identity_evidence_ref)
        }
    raise AthenaValidationError(
        f"selector runtime is missing variant {selector.selector_type!r}"
    )


def evaluate_selector(
    selector: ManifestSelector,
    resources: Sequence[ResourceEvidenceRecord],
    *,
    signals: Sequence[CohortSignalEvidence] = (),
) -> SelectorEvaluation:
    """Evaluate a frozen manifest selector and enforce every nested maxMatches bound."""

    resources_by_id: dict[str, ResourceEvidenceRecord] = {}
    for resource in resources:
        normalized_id = normalize_resource_id(resource.resource_id)
        if normalized_id in resources_by_id:
            raise AthenaValidationError(
                "selector input contains duplicate normalized Azure resource IDs"
            )
        resources_by_id[normalized_id] = resource
    signals_by_id = _signals_by_resource(signals, set(resources_by_id))

    def evaluate(current: ManifestSelector) -> tuple[set[str], list[str]]:
        violations: list[str] = []
        if isinstance(current, CompositeAllSelector):
            child_results = [evaluate(child) for child in current.children]
            matches = (
                set.intersection(*(result for result, _ in child_results))
                if child_results
                else set()
            )
            for _, child_violations in child_results:
                violations.extend(child_violations)
        elif isinstance(current, CompositeAnySelector):
            child_results = [evaluate(child) for child in current.children]
            matches = set().union(*(result for result, _ in child_results))
            for _, child_violations in child_results:
                violations.extend(child_violations)
        else:
            matches = _atomic_matches(current, resources_by_id, signals_by_id)
        if len(matches) > current.max_matches:
            violations.append(current.selector_id)
        return matches, violations

    matched, max_violations = evaluate(selector)
    matched_ids = sorted(matched)
    rejected_ids = sorted(set(resources_by_id).difference(matched))
    unique_violations = sorted(set(max_violations), key=str.casefold)
    status: Literal["matched", "noMatches", "overMaxMatches"]
    if unique_violations:
        status = "overMaxMatches"
    elif matched_ids:
        status = "matched"
    else:
        status = "noMatches"
    digest = compute_artifact_digest(
        {
            "selector": selector.model_dump(mode="json", by_alias=True, exclude_none=True),
            "matchedResourceIds": matched_ids,
            "maxMatchViolations": unique_violations,
        }
    )
    return SelectorEvaluation(
        selector=selector,
        status=status,
        matchedResourceIds=matched_ids,
        rejectedResourceIds=rejected_ids,
        maxMatches=selector.max_matches,
        maxMatchViolations=unique_violations,
        selectorResultDigest=digest,
    )


__all__ = [
    "evaluate_selector",
    "normalize_resource_id",
    "selector_runtime_variants",
]
