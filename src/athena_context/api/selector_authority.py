from __future__ import annotations

from dataclasses import dataclass

from athena_context.api.cohort_decision_domain import (
    CohortDecisionApplyBinding,
    _selector_binding_permits,
)
from athena_context.api.domain import DraftRecord, PublishedManifest
from athena_context.api.errors import PersistenceConflictError
from athena_context.api.ports import ContextTransactionPort
from athena_context.api.selector_provenance import (
    DraftSelectorPredecessorBinding,
    manifest_selector_provenance,
    selector_provenance_digest,
)
from athena_context.contracts.common import compute_artifact_digest
from athena_context.contracts.manifest import ManifestRole


@dataclass(frozen=True, slots=True)
class PersistedSelectorAuthority:
    """Resolver capability derived only from immutable applied decisions."""

    bindings: tuple[CohortDecisionApplyBinding, ...]
    effective_manifest_version: str

    def permits_selector_identity_replacement(
        self,
        *,
        manifest_id: str,
        manifest_version: str,
        profile_id: str,
        inherited_role: ManifestRole,
        replacement_role: ManifestRole,
    ) -> bool:
        if manifest_version != self.effective_manifest_version:
            return False
        return any(
            _selector_binding_permits(
                binding,
                manifest_id=manifest_id,
                manifest_version=binding.manifest_version,
                profile_id=profile_id,
                inherited_role=inherited_role,
                replacement_role=replacement_role,
            )
            for binding in self.bindings
        )


def _applied_bindings(
    tx: ContextTransactionPort,
    *,
    manifest_id: str,
    draft_id: str,
    maximum_revision: int,
) -> tuple[CohortDecisionApplyBinding, ...]:
    bindings: list[CohortDecisionApplyBinding] = []
    for decision in tx.list_cohort_decisions(
        manifest_id=manifest_id,
        draft_id=draft_id,
    ):
        authorization = decision.apply_authorization
        applied = decision.applied_draft
        if authorization is None and applied is None:
            continue
        if authorization is None or applied is None:
            raise PersistenceConflictError(
                "selector authority decision application is incomplete"
            )
        binding = authorization.binding
        if (
            authorization.status != "approved"
            or decision.decision_id != binding.decision_id
            or decision.decision != binding.decision
            or decision.manifest_id != manifest_id
            or binding.manifest_id != manifest_id
            or decision.manifest_version != binding.manifest_version
            or decision.source_draft.draft_id != draft_id
            or binding.source_draft.draft_id != draft_id
            or binding.current_draft.draft_id != draft_id
            or binding.resulting_draft.draft_id != draft_id
            or applied != binding.resulting_draft
        ):
            raise PersistenceConflictError(
                "selector authority decision binding is inconsistent"
            )
        if applied.revision <= maximum_revision:
            bindings.append(binding)
    return tuple(bindings)


def _version_key(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return (int(major), int(minor), int(patch))


def selector_authority_digest(
    bindings: tuple[CohortDecisionApplyBinding, ...],
) -> str:
    """Digest the exact immutable decision authority carried across lineage."""

    return compute_artifact_digest(
        [
            binding.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
            for binding in sorted(
                bindings,
                key=lambda item: (
                    _version_key(item.manifest_version),
                    item.resulting_draft.revision,
                    item.decision_id,
                ),
            )
        ]
    )


def _deduplicate_bindings(
    bindings: tuple[CohortDecisionApplyBinding, ...],
) -> tuple[CohortDecisionApplyBinding, ...]:
    unique: dict[str, CohortDecisionApplyBinding] = {}
    for binding in bindings:
        existing = unique.get(binding.decision_id)
        if existing is not None and existing != binding:
            raise PersistenceConflictError(
                "selector authority lineage contains conflicting decision bindings"
            )
        unique[binding.decision_id] = binding
    return tuple(
        sorted(
            unique.values(),
            key=lambda binding: (
                _version_key(binding.manifest_version),
                binding.resulting_draft.revision,
                binding.decision_id,
            ),
        )
    )


def _validate_published_lineage_entry(
    tx: ContextTransactionPort,
    published: PublishedManifest,
) -> None:
    stored = tx.get_published(
        published.manifest_id,
        published.manifest_version,
    )
    source = tx.get_draft(published.source_draft_id)
    if (
        stored is None
        or stored != published
        or published.manifest_id != published.manifest.manifest_id
        or published.manifest_version
        != published.manifest.manifest_version
        or published.manifest_digest
        != published.manifest.compatibility.artifact_digest
        or source is None
        or source.manifest_id != published.manifest_id
        or source.manifest.manifest_id != published.manifest_id
        or source.manifest.manifest_version
        != published.manifest_version
        or source.manifest_digest != published.manifest_digest
        or source.manifest != published.manifest
        or source.revision < published.source_draft_revision
        or source.previous_version != published.previous_version
    ):
        raise PersistenceConflictError(
            "published selector authority lineage is inconsistent"
        )


def validate_draft_selector_predecessor_binding(
    tx: ContextTransactionPort,
    *,
    successor: DraftRecord,
    binding: DraftSelectorPredecessorBinding,
) -> DraftRecord:
    """Validate one exact unpublished-draft authority edge."""

    stored_successor = tx.get_draft(successor.draft_id)
    successor_baseline = tx.get_draft_selector_baseline(
        successor.draft_id
    )
    predecessor = tx.get_draft(binding.predecessor_draft_id)
    predecessor_baseline = tx.get_draft_selector_baseline(
        binding.predecessor_draft_id
    )
    if (
        stored_successor is None
        or stored_successor != successor
        or successor.previous_version is not None
        or successor_baseline is None
        or binding.successor_draft_id != successor.draft_id
        or binding.manifest_id != successor.manifest_id
        or binding.manifest_id != successor.manifest.manifest_id
        or binding.successor_manifest_version
        != successor.manifest.manifest_version
        or binding.successor_source_manifest_digest
        != successor_baseline.source_manifest_digest
        or binding.successor_selector_provenance_digest
        != successor_baseline.selector_provenance_digest
        or binding.predecessor_selector_authority_digest
        != successor_baseline.inherited_selector_authority_digest
        or successor_baseline.draft_id != successor.draft_id
        or successor_baseline.manifest_id != successor.manifest_id
        or successor_baseline.manifest_version
        != successor.manifest.manifest_version
        or successor_baseline.captured_by != binding.bound_by
        or successor_baseline.captured_at != binding.bound_at
        or successor.created_by != binding.bound_by
        or successor.created_at != binding.bound_at
        or predecessor is None
        or predecessor_baseline is None
        or predecessor.draft_id != binding.predecessor_draft_id
        or predecessor.manifest_id != binding.manifest_id
        or predecessor.manifest.manifest_id != binding.manifest_id
        or predecessor.manifest.manifest_version
        != binding.predecessor_manifest_version
        or predecessor.revision != binding.predecessor_revision
        or predecessor.manifest_digest
        != binding.predecessor_manifest_digest
        or predecessor.manifest.compatibility.artifact_digest
        != binding.predecessor_manifest_digest
        or selector_provenance_digest(
            manifest_selector_provenance(predecessor.manifest)
        )
        != binding.predecessor_selector_provenance_digest
        or predecessor_baseline.draft_id != predecessor.draft_id
        or predecessor_baseline.manifest_id != binding.manifest_id
        or predecessor_baseline.manifest_version
        != binding.predecessor_manifest_version
        or predecessor_baseline.source_manifest_digest
        != binding.predecessor_baseline_source_manifest_digest
        or predecessor_baseline.selector_provenance_digest
        != binding.predecessor_baseline_selector_provenance_digest
        or _version_key(binding.predecessor_manifest_version)
        >= _version_key(binding.successor_manifest_version)
    ):
        raise PersistenceConflictError(
            "draft selector authority predecessor binding is inconsistent"
        )
    return predecessor


def _draft_lineage_bindings(
    tx: ContextTransactionPort,
    *,
    current: DraftRecord,
    visited: frozenset[tuple[str, str, str]],
    maximum_revision: int | None = None,
) -> tuple[CohortDecisionApplyBinding, ...]:
    key = ("draft", current.manifest_id, current.draft_id)
    if key in visited:
        raise PersistenceConflictError(
            "draft selector authority lineage contains a cycle"
        )
    stored = tx.get_draft(current.draft_id)
    baseline = tx.get_draft_selector_baseline(current.draft_id)
    if (
        stored is None
        or stored != current
        or current.manifest_id != current.manifest.manifest_id
        or baseline is None
        or baseline.draft_id != current.draft_id
        or baseline.manifest_id != current.manifest_id
        or baseline.manifest_version
        != current.manifest.manifest_version
    ):
        raise PersistenceConflictError(
            "draft selector authority lineage is inconsistent"
        )

    binding = tx.get_draft_selector_predecessor_binding(current.draft_id)
    if binding is not None and current.previous_version is not None:
        raise PersistenceConflictError(
            "draft selector authority has conflicting predecessor kinds"
        )

    inherited: tuple[CohortDecisionApplyBinding, ...] = ()
    next_visited = visited | {key}
    if binding is not None:
        predecessor = validate_draft_selector_predecessor_binding(
            tx,
            successor=current,
            binding=binding,
        )
        inherited = _draft_lineage_bindings(
            tx,
            current=predecessor,
            visited=next_visited,
            maximum_revision=binding.predecessor_revision,
        )
        if selector_authority_digest(inherited) != (
            binding.predecessor_selector_authority_digest
        ):
            raise PersistenceConflictError(
                "draft selector predecessor authority is inconsistent"
            )
    elif current.previous_version is not None:
        previous = tx.get_published(
            current.manifest_id,
            current.previous_version,
        )
        if (
            previous is None
            or previous.manifest_id != current.manifest_id
            or previous.manifest_version != current.previous_version
            or _version_key(previous.manifest_version)
            >= _version_key(current.manifest.manifest_version)
        ):
            raise PersistenceConflictError(
                "draft selector authority predecessor is invalid"
            )
        inherited = _published_lineage_bindings(
            tx,
            published=previous,
            visited=next_visited,
        )

    inherited_digest = (
        None
        if not inherited
        else selector_authority_digest(inherited)
    )
    if baseline.inherited_selector_authority_digest != inherited_digest:
        raise PersistenceConflictError(
            "draft inherited selector authority is missing or inconsistent"
        )

    direct = _applied_bindings(
        tx,
        manifest_id=current.manifest_id,
        draft_id=current.draft_id,
        maximum_revision=(
            current.revision
            if maximum_revision is None
            else maximum_revision
        ),
    )
    return _deduplicate_bindings((*inherited, *direct))


def _published_lineage_bindings(
    tx: ContextTransactionPort,
    *,
    published: PublishedManifest,
    visited: frozenset[tuple[str, str, str]],
) -> tuple[CohortDecisionApplyBinding, ...]:
    key = ("published", published.manifest_id, published.manifest_version)
    if key in visited:
        raise PersistenceConflictError(
            "published selector authority lineage contains a cycle"
        )
    _validate_published_lineage_entry(tx, published)
    source = tx.get_draft(published.source_draft_id)
    if source is None:
        raise PersistenceConflictError(
            "published selector authority source draft is missing"
        )
    return _draft_lineage_bindings(
        tx,
        current=source,
        visited=visited | {key},
        maximum_revision=published.source_draft_revision,
    )


def persisted_selector_authority_for_published(
    tx: ContextTransactionPort,
    *,
    published: PublishedManifest,
    effective_manifest_version: str,
) -> PersistedSelectorAuthority | None:
    """Recover exact selector provenance carried by a published version."""

    bindings = _published_lineage_bindings(
        tx,
        published=published,
        visited=frozenset(),
    )
    if not bindings:
        return None
    return PersistedSelectorAuthority(
        bindings=bindings,
        effective_manifest_version=effective_manifest_version,
    )


def persisted_selector_authority_for_draft(
    tx: ContextTransactionPort,
    *,
    current: DraftRecord,
) -> PersistedSelectorAuthority | None:
    """Recover current and inherited published selector provenance for a draft."""

    bindings = _draft_lineage_bindings(
        tx,
        current=current,
        visited=frozenset(),
    )
    if not bindings:
        return None
    return PersistedSelectorAuthority(
        bindings=bindings,
        effective_manifest_version=current.manifest.manifest_version,
    )


__all__ = [
    "PersistedSelectorAuthority",
    "persisted_selector_authority_for_draft",
    "persisted_selector_authority_for_published",
    "selector_authority_digest",
    "validate_draft_selector_predecessor_binding",
]
