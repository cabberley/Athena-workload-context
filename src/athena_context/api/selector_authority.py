from __future__ import annotations

from dataclasses import dataclass

from athena_context.api.cohort_decision_domain import (
    CohortDecisionApplyBinding,
    _selector_binding_permits,
)
from athena_context.api.domain import DraftRecord, PublishedManifest
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
    return tuple(
        decision.apply_authorization.binding
        for decision in tx.list_cohort_decisions(
            manifest_id=manifest_id,
            draft_id=draft_id,
        )
        if decision.apply_authorization is not None
        and decision.applied_draft is not None
        and decision.apply_authorization.status == "approved"
        and decision.applied_draft.draft_id == draft_id
        and decision.applied_draft.revision <= maximum_revision
    )


def persisted_selector_authority_for_published(
    tx: ContextTransactionPort,
    *,
    published: PublishedManifest,
    effective_manifest_version: str,
) -> PersistedSelectorAuthority | None:
    """Recover exact selector provenance carried by a published version."""

    bindings = _applied_bindings(
        tx,
        manifest_id=published.manifest_id,
        draft_id=published.source_draft_id,
        maximum_revision=published.source_draft_revision,
    )
    if not bindings:
        return None
    return PersistedSelectorAuthority(
        bindings=tuple(
            sorted(
                bindings,
                key=lambda binding: (
                    binding.resulting_draft.revision,
                    binding.decision_id,
                ),
            )
        ),
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
        if previous is not None:
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
    unique = {
        binding.decision_id: binding
        for binding in bindings
    }
    return PersistedSelectorAuthority(
        bindings=tuple(
            sorted(
                unique.values(),
                key=lambda binding: (
                    binding.resulting_draft.revision,
                    binding.decision_id,
                ),
            )
        ),
        effective_manifest_version=current.manifest.manifest_version,
    )


__all__ = [
    "PersistedSelectorAuthority",
    "persisted_selector_authority_for_draft",
    "persisted_selector_authority_for_published",
]
