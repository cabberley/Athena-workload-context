from __future__ import annotations

from dataclasses import dataclass

from athena_context.api.cohort_decision_domain import (
    CohortDecisionApplyBinding,
    _selector_binding_permits,
)
from athena_context.api.domain import DraftRecord, PublishedManifest
from athena_context.api.errors import PersistenceConflictError
from athena_context.api.ports import ContextTransactionPort
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


def _published_lineage_bindings(
    tx: ContextTransactionPort,
    *,
    published: PublishedManifest,
    visited: frozenset[tuple[str, str]],
) -> tuple[CohortDecisionApplyBinding, ...]:
    key = (published.manifest_id, published.manifest_version)
    if key in visited:
        raise PersistenceConflictError(
            "published selector authority lineage contains a cycle"
        )
    _validate_published_lineage_entry(tx, published)

    inherited: tuple[CohortDecisionApplyBinding, ...] = ()
    if published.previous_version is not None:
        previous = tx.get_published(
            published.manifest_id,
            published.previous_version,
        )
        if (
            previous is None
            or previous.manifest_id != published.manifest_id
            or previous.manifest_version != published.previous_version
            or _version_key(previous.manifest_version)
            >= _version_key(published.manifest_version)
        ):
            raise PersistenceConflictError(
                "published selector authority predecessor is invalid"
            )
        inherited = _published_lineage_bindings(
            tx,
            published=previous,
            visited=visited | {key},
        )

    direct = _applied_bindings(
        tx,
        manifest_id=published.manifest_id,
        draft_id=published.source_draft_id,
        maximum_revision=published.source_draft_revision,
    )
    return _deduplicate_bindings((*inherited, *direct))


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

    bindings = list(
        _applied_bindings(
            tx,
            manifest_id=current.manifest_id,
            draft_id=current.draft_id,
            maximum_revision=current.revision,
        )
    )
    if current.previous_version is not None:
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
        inherited = persisted_selector_authority_for_published(
            tx,
            published=previous,
            effective_manifest_version=(
                current.manifest.manifest_version
            ),
        )
        if inherited is not None:
            bindings.extend(inherited.bindings)
    if not bindings:
        return None
    return PersistedSelectorAuthority(
        bindings=_deduplicate_bindings(tuple(bindings)),
        effective_manifest_version=current.manifest.manifest_version,
    )


__all__ = [
    "PersistedSelectorAuthority",
    "persisted_selector_authority_for_draft",
    "persisted_selector_authority_for_published",
]
