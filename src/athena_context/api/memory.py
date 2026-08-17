from __future__ import annotations

from threading import RLock
from types import TracebackType
from typing import Literal

from athena_context.api.domain import (
    AuditEvent,
    DraftRecord,
    DraftState,
    MutationReceipt,
    PendingAuditEvent,
    PublishedManifest,
    Supersession,
)
from athena_context.api.errors import (
    AlreadySupersededError,
    DuplicateDraftError,
    DuplicateVersionError,
    IdempotencyConflictError,
    ResourceNotFoundError,
    StaleRevisionError,
)
from athena_context.api.ports import ContextTransactionPort


def _version_key(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return (int(major), int(minor), int(patch))


class InMemoryContextStore:
    """Transactional, deterministic in-memory implementation of the storage port."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._drafts: dict[str, DraftRecord] = {}
        self._published: dict[tuple[str, str], PublishedManifest] = {}
        self._supersessions: dict[tuple[str, str], Supersession] = {}
        self._audit: list[AuditEvent] = []
        self._receipts: dict[tuple[str, str], MutationReceipt] = {}

    def transaction(self) -> _MemoryTransaction:
        return _MemoryTransaction(self)


class _MemoryTransaction(ContextTransactionPort):
    def __init__(self, store: InMemoryContextStore) -> None:
        self._store = store
        self._drafts: dict[str, DraftRecord] = {}
        self._published: dict[tuple[str, str], PublishedManifest] = {}
        self._supersessions: dict[tuple[str, str], Supersession] = {}
        self._audit: list[AuditEvent] = []
        self._receipts: dict[tuple[str, str], MutationReceipt] = {}

    def __enter__(self) -> _MemoryTransaction:
        self._store._lock.acquire()
        self._drafts = dict(self._store._drafts)
        self._published = dict(self._store._published)
        self._supersessions = dict(self._store._supersessions)
        self._audit = list(self._store._audit)
        self._receipts = dict(self._store._receipts)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        try:
            if exc_type is None:
                self._store._drafts = self._drafts
                self._store._published = self._published
                self._store._supersessions = self._supersessions
                self._store._audit = self._audit
                self._store._receipts = self._receipts
        finally:
            self._store._lock.release()
        return False

    def get_draft(self, draft_id: str) -> DraftRecord | None:
        draft = self._drafts.get(draft_id)
        return None if draft is None else draft.model_copy(deep=True)

    def list_drafts(
        self,
        *,
        manifest_id: str | None = None,
        state: DraftState | None = None,
    ) -> list[DraftRecord]:
        matches = sorted(
            (
                draft
                for draft in self._drafts.values()
                if (manifest_id is None or draft.manifest_id == manifest_id)
                and (state is None or draft.state is state)
            ),
            key=lambda draft: draft.draft_id,
        )
        return [draft.model_copy(deep=True) for draft in matches]

    def put_draft(
        self,
        draft: DraftRecord,
        *,
        expected_revision: int | None,
    ) -> None:
        current = self._drafts.get(draft.draft_id)
        if expected_revision is None:
            if current is not None:
                raise DuplicateDraftError(f"draft {draft.draft_id!r} already exists")
        elif current is None:
            raise ResourceNotFoundError(f"draft {draft.draft_id!r} was not found")
        elif current.revision != expected_revision:
            raise StaleRevisionError(
                f"expected draft revision {expected_revision}, found {current.revision}"
            )
        self._drafts[draft.draft_id] = draft.model_copy(deep=True)

    def get_published(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifest | None:
        published = self._published.get((manifest_id, manifest_version))
        return None if published is None else published.model_copy(deep=True)

    def list_published(self, *, manifest_id: str | None = None) -> list[PublishedManifest]:
        matches = sorted(
            (
                item
                for item in self._published.values()
                if manifest_id is None or item.manifest_id == manifest_id
            ),
            key=lambda item: (item.manifest_id, _version_key(item.manifest_version)),
        )
        return [item.model_copy(deep=True) for item in matches]

    def put_published(self, published: PublishedManifest) -> None:
        key = (published.manifest_id, published.manifest_version)
        if key in self._published:
            raise DuplicateVersionError(
                f"manifest version {published.manifest_id}/{published.manifest_version} exists"
            )
        self._published[key] = published.model_copy(deep=True)

    def get_supersession(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> Supersession | None:
        supersession = self._supersessions.get((manifest_id, manifest_version))
        return None if supersession is None else supersession.model_copy(deep=True)

    def put_supersession(self, supersession: Supersession) -> None:
        key = (supersession.manifest_id, supersession.superseded_version)
        if key in self._supersessions:
            raise AlreadySupersededError(
                f"manifest version {supersession.superseded_version} is already superseded"
            )
        self._supersessions[key] = supersession.model_copy(deep=True)

    def append_audit(self, event: PendingAuditEvent) -> AuditEvent:
        sequence = len(self._audit) + 1
        stored = AuditEvent(
            **event.model_dump(),
            sequence=sequence,
            event_id=f"audit-{sequence:08d}",
        )
        self._audit.append(stored.model_copy(deep=True))
        return stored

    def list_audit(self, *, manifest_id: str) -> list[AuditEvent]:
        return [
            event.model_copy(deep=True)
            for event in self._audit
            if event.manifest_id == manifest_id
        ]

    def get_receipt(self, actor_id: str, idempotency_key: str) -> MutationReceipt | None:
        receipt = self._receipts.get((actor_id, idempotency_key))
        return None if receipt is None else receipt.model_copy(deep=True)

    def put_receipt(self, receipt: MutationReceipt) -> None:
        key = (receipt.actor_id, receipt.idempotency_key)
        if key in self._receipts:
            raise IdempotencyConflictError("idempotency key has already been recorded")
        self._receipts[key] = receipt.model_copy(deep=True)
