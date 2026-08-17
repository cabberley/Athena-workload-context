from __future__ import annotations

from threading import RLock
from typing import Literal

from athena_context.api.errors import (
    DuplicateVersionError,
    IdempotencyConflictError,
)
from athena_context.api.evaluation_domain import (
    AuthorizedSnapshotPublication,
    DemoEvaluationResult,
)
from athena_context.api.evaluation_ports import StoredEvaluation
from athena_context.contracts import (
    EvidenceSnapshot,
    SnapshotPublicationRecord,
)


class InMemoryEvaluationArtifactStore:
    """Atomic deterministic adapter storing canonical strings behind the typed port."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._receipts: dict[tuple[str, str], StoredEvaluation] = {}
        self._artifacts: dict[str, StoredEvaluation] = {}

    def load_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> StoredEvaluation | None:
        with self._lock:
            return self._receipts.get((actor_id, idempotency_key))

    def commit(self, artifact: StoredEvaluation) -> None:
        result = DemoEvaluationResult.model_validate_json(artifact.result_json)
        snapshot = EvidenceSnapshot.model_validate_json(artifact.snapshot_json)
        publication = AuthorizedSnapshotPublication.model_validate_json(
            artifact.publication_json
        )
        if (
            result.snapshot.canonical_json() != snapshot.canonical_json()
            or result.publication != publication
            or result.publication.snapshot_id != artifact.snapshot_id
        ):
            raise ValueError("stored evaluation components are not canonically identical")
        receipt_key = (artifact.actor_id, artifact.idempotency_key)
        with self._lock:
            if receipt_key in self._receipts:
                raise IdempotencyConflictError(
                    "idempotency key was concurrently committed"
                )
            if artifact.snapshot_id in self._artifacts:
                raise DuplicateVersionError(
                    f"evidence snapshot {artifact.snapshot_id!r} is already published"
                )
            self._artifacts[artifact.snapshot_id] = artifact
            self._receipts[receipt_key] = artifact

    def resolve_publication(
        self,
        snapshot_id: str,
    ) -> SnapshotPublicationRecord | None:
        with self._lock:
            artifact = self._artifacts.get(snapshot_id)
        if artifact is None:
            return None
        publication = AuthorizedSnapshotPublication.model_validate_json(
            artifact.publication_json
        )
        return publication.registry_record()

    def resolve_result(self, snapshot_id: str) -> DemoEvaluationResult | None:
        with self._lock:
            artifact = self._artifacts.get(snapshot_id)
        if artifact is None:
            return None
        return DemoEvaluationResult.model_validate_json(artifact.result_json)

    def resolve_envelope(
        self,
        attempt_id: str,
        kind: Literal["response", "failure"],
        digest: str,
    ) -> object | None:
        with self._lock:
            matches = [
                artifact
                for artifact in self._artifacts.values()
                if artifact.envelope_attempt_id == attempt_id
                and artifact.envelope.kind == kind
                and artifact.envelope.digest == digest
            ]
        if len(matches) != 1:
            return None
        return matches[0].envelope.payload()

    @property
    def publication_count(self) -> int:
        with self._lock:
            return len(self._artifacts)


__all__ = ["InMemoryEvaluationArtifactStore"]
