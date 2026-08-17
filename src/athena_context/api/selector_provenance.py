from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from athena_context.api.cohort_domain import normalized_identifier
from athena_context.api.domain import Actor, ApiModel, DraftRecord, WorkloadIdentifier
from athena_context.contracts.common import compute_artifact_digest
from athena_context.contracts.manifest import (
    AtomicSelector,
    CanonicalWorkloadManifest,
    CompositeAllSelector,
    CompositeAnySelector,
    ManifestRole,
    ManifestSelector,
    ResolvedManifestProfile,
)

_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"

type SelectorRoleKey = tuple[Literal["global", "profile"], str | None, str]


class SelectorProvenanceEntry(ApiModel):
    """One immutable selector identity at its exact manifest location."""

    location: Literal["global", "profile"]
    profile_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    role_id: str = Field(pattern=_ID_PATTERN)
    selector_path: tuple[str, ...] = Field(min_length=1, max_length=11)
    selector_id: str = Field(pattern=_ID_PATTERN)
    selector_variant: str = Field(min_length=1, max_length=64)
    semantic_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_location(self) -> SelectorProvenanceEntry:
        if (self.location == "global") != (self.profile_id is None):
            raise ValueError("global selector provenance must omit profile_id")
        if self.selector_path[-1] != self.selector_id:
            raise ValueError("selector provenance path must end at selector_id")
        return self


def _entry_key(
    entry: SelectorProvenanceEntry,
) -> tuple[str, str, str, tuple[str, ...], str, str]:
    return (
        entry.location,
        entry.profile_id or "",
        entry.role_id,
        entry.selector_path,
        entry.selector_variant,
        entry.semantic_digest,
    )


def selector_provenance_digest(
    entries: tuple[SelectorProvenanceEntry, ...],
) -> str:
    return compute_artifact_digest(
        [
            entry.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
            for entry in entries
        ]
    )


class DraftSelectorBaseline(ApiModel):
    """Immutable selector baseline captured before a draft can be mutated."""

    draft_id: str = Field(pattern=_ID_PATTERN)
    manifest_id: WorkloadIdentifier
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    source_manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    selector_provenance_digest: str = Field(pattern=_DIGEST_PATTERN)
    entries: tuple[SelectorProvenanceEntry, ...]
    captured_by: Actor
    captured_at: AwareDatetime

    @model_validator(mode="after")
    def validate_provenance(self) -> DraftSelectorBaseline:
        if self.entries != tuple(sorted(self.entries, key=_entry_key)):
            raise ValueError("selector baseline entries must use canonical order")
        if self.selector_provenance_digest != selector_provenance_digest(
            self.entries
        ):
            raise ValueError("selector baseline digest does not match its entries")
        return self

    @classmethod
    def capture(
        cls,
        *,
        draft_id: str,
        manifest: CanonicalWorkloadManifest,
        manifest_digest: str,
        actor: Actor,
        captured_at: datetime,
    ) -> DraftSelectorBaseline:
        entries = manifest_selector_provenance(manifest)
        return cls(
            draft_id=draft_id,
            manifest_id=manifest.manifest_id,
            manifest_version=manifest.manifest_version,
            source_manifest_digest=manifest_digest,
            selector_provenance_digest=selector_provenance_digest(entries),
            entries=entries,
            captured_by=actor,
            captured_at=captured_at,
        )


class DraftSelectorPredecessorBinding(ApiModel):
    """Immutable edge to exact unpublished selector authority."""

    successor_draft_id: str = Field(pattern=_ID_PATTERN)
    manifest_id: WorkloadIdentifier
    successor_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    successor_source_manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    successor_selector_provenance_digest: str = Field(pattern=_DIGEST_PATTERN)
    predecessor_draft_id: str = Field(pattern=_ID_PATTERN)
    predecessor_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    predecessor_revision: int = Field(ge=1)
    predecessor_manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    predecessor_selector_provenance_digest: str = Field(pattern=_DIGEST_PATTERN)
    predecessor_baseline_source_manifest_digest: str = Field(
        pattern=_DIGEST_PATTERN
    )
    predecessor_baseline_selector_provenance_digest: str = Field(
        pattern=_DIGEST_PATTERN
    )
    bound_by: Actor
    bound_at: AwareDatetime

    @model_validator(mode="after")
    def validate_lineage(self) -> DraftSelectorPredecessorBinding:
        if self.successor_draft_id == self.predecessor_draft_id:
            raise ValueError("selector predecessor cannot reference its own draft")
        predecessor = tuple(
            int(part) for part in self.predecessor_manifest_version.split(".")
        )
        successor = tuple(
            int(part) for part in self.successor_manifest_version.split(".")
        )
        if predecessor >= successor:
            raise ValueError(
                "selector predecessor version must be lower than successor"
            )
        return self

    @classmethod
    def capture(
        cls,
        *,
        successor_draft_id: str,
        successor_manifest: CanonicalWorkloadManifest,
        successor_manifest_digest: str,
        predecessor: DraftRecord,
        predecessor_baseline: DraftSelectorBaseline,
        actor: Actor,
        bound_at: datetime,
    ) -> DraftSelectorPredecessorBinding:
        successor_entries = manifest_selector_provenance(successor_manifest)
        predecessor_entries = manifest_selector_provenance(
            predecessor.manifest
        )
        return cls(
            successor_draft_id=successor_draft_id,
            manifest_id=successor_manifest.manifest_id,
            successor_manifest_version=successor_manifest.manifest_version,
            successor_source_manifest_digest=successor_manifest_digest,
            successor_selector_provenance_digest=selector_provenance_digest(
                successor_entries
            ),
            predecessor_draft_id=predecessor.draft_id,
            predecessor_manifest_version=(
                predecessor.manifest.manifest_version
            ),
            predecessor_revision=predecessor.revision,
            predecessor_manifest_digest=predecessor.manifest_digest,
            predecessor_selector_provenance_digest=(
                selector_provenance_digest(predecessor_entries)
            ),
            predecessor_baseline_source_manifest_digest=(
                predecessor_baseline.source_manifest_digest
            ),
            predecessor_baseline_selector_provenance_digest=(
                predecessor_baseline.selector_provenance_digest
            ),
            bound_by=actor,
            bound_at=bound_at,
        )


def _selector_entries(
    selector: ManifestSelector | AtomicSelector,
    *,
    location: Literal["global", "profile"],
    profile_id: str | None,
    role_id: str,
    parent_path: tuple[str, ...],
) -> list[SelectorProvenanceEntry]:
    selector_id = normalized_identifier(selector.selector_id)
    selector_path = (*parent_path, selector_id)
    entries = [
        SelectorProvenanceEntry(
            location=location,
            profile_id=profile_id,
            role_id=role_id,
            selector_path=selector_path,
            selector_id=selector_id,
            selector_variant=selector.selector_type,
            semantic_digest=compute_artifact_digest(
                selector.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            ),
        )
    ]
    if isinstance(selector, (CompositeAllSelector, CompositeAnySelector)):
        for child in selector.children:
            entries.extend(
                _selector_entries(
                    child,
                    location=location,
                    profile_id=profile_id,
                    role_id=role_id,
                    parent_path=selector_path,
                )
            )
    return entries


def role_selector_provenance(
    role: ManifestRole,
    *,
    location: Literal["global", "profile"],
    profile_id: str | None,
) -> tuple[SelectorProvenanceEntry, ...]:
    normalized_profile = (
        None if profile_id is None else normalized_identifier(profile_id)
    )
    role_id = normalized_identifier(role.role_id)
    entries: list[SelectorProvenanceEntry] = []
    for selector in role.selectors:
        entries.extend(
            _selector_entries(
                selector,
                location=location,
                profile_id=normalized_profile,
                role_id=role_id,
                parent_path=(),
            )
        )
    return tuple(sorted(entries, key=_entry_key))


def role_selector_provenance_digest(
    role: ManifestRole,
    *,
    profile_id: str,
) -> str:
    return selector_provenance_digest(
        role_selector_provenance(
            role,
            location="profile",
            profile_id=profile_id,
        )
    )


def manifest_selector_provenance(
    manifest: CanonicalWorkloadManifest,
) -> tuple[SelectorProvenanceEntry, ...]:
    entries: list[SelectorProvenanceEntry] = []
    for role in manifest.roles:
        entries.extend(
            role_selector_provenance(
                role,
                location="global",
                profile_id=None,
            )
        )
    for profile in manifest.profiles.values():
        for role in profile.roles:
            entries.extend(
                role_selector_provenance(
                    role,
                    location="profile",
                    profile_id=profile.profile_id,
                )
            )
    return tuple(sorted(entries, key=_entry_key))


def resolved_profile_selector_provenance(
    profile: ResolvedManifestProfile,
) -> tuple[SelectorProvenanceEntry, ...]:
    """Capture the selectors a profile actually resolves, not only its declarations."""

    entries: list[SelectorProvenanceEntry] = []
    for role in profile.roles:
        entries.extend(
            role_selector_provenance(
                role,
                location="profile",
                profile_id=profile.profile_id,
            )
        )
    return tuple(sorted(entries, key=_entry_key))


def selector_role_digests(
    entries: tuple[SelectorProvenanceEntry, ...],
) -> dict[SelectorRoleKey, str]:
    grouped: dict[
        SelectorRoleKey,
        list[SelectorProvenanceEntry],
    ] = defaultdict(list)
    for entry in entries:
        grouped[(entry.location, entry.profile_id, entry.role_id)].append(entry)
    return {
        key: selector_provenance_digest(
            tuple(sorted(role_entries, key=_entry_key))
        )
        for key, role_entries in grouped.items()
    }


__all__ = [
    "DraftSelectorBaseline",
    "DraftSelectorPredecessorBinding",
    "SelectorProvenanceEntry",
    "SelectorRoleKey",
    "manifest_selector_provenance",
    "resolved_profile_selector_provenance",
    "role_selector_provenance_digest",
    "selector_provenance_digest",
    "selector_role_digests",
]
