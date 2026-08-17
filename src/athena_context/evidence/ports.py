from __future__ import annotations

from datetime import datetime
from typing import Protocol

from athena_context.contracts import CollectorIdentityEvidence
from athena_context.evidence.models import (
    EvidenceTransportRequest,
    McpTransportOutcome,
    TrustedIngestionBinding,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class SyncEvidenceTransport(Protocol):
    def invoke(self, request: EvidenceTransportRequest) -> McpTransportOutcome: ...


class AsyncEvidenceTransport(Protocol):
    async def invoke(self, request: EvidenceTransportRequest) -> McpTransportOutcome: ...


class SyncTrustedIngestionSigner(Protocol):
    def bind_attempt(self, binding: TrustedIngestionBinding) -> CollectorIdentityEvidence: ...


class AsyncTrustedIngestionSigner(Protocol):
    async def bind_attempt(
        self, binding: TrustedIngestionBinding
    ) -> CollectorIdentityEvidence: ...


class SyncAttemptReplayGuard(Protocol):
    def reserve(self, attempt_id: str, request_digest: str) -> bool: ...


class AsyncAttemptReplayGuard(Protocol):
    async def reserve(self, attempt_id: str, request_digest: str) -> bool: ...


__all__ = [
    "AsyncAttemptReplayGuard",
    "AsyncEvidenceTransport",
    "AsyncTrustedIngestionSigner",
    "Clock",
    "SyncAttemptReplayGuard",
    "SyncEvidenceTransport",
    "SyncTrustedIngestionSigner",
]
