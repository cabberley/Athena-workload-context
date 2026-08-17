from __future__ import annotations

from datetime import timedelta

from athena_context.contracts import TrustedKeyAnchor, TrustedKeyResolver
from athena_context.evidence.models import (
    CollectedEvidence,
    CollectorTrustConfiguration,
    EvidenceCollectionCommand,
    McpTimeoutNoResponse,
    McpTransportOutcome,
    ReplayDetectedError,
    TrustedIngestionBinding,
)
from athena_context.evidence.ports import (
    AsyncAttemptReplayGuard,
    AsyncEvidenceTransport,
    AsyncTrustedIngestionSigner,
    Clock,
    SyncAttemptReplayGuard,
    SyncEvidenceTransport,
    SyncTrustedIngestionSigner,
)
from athena_context.evidence.validation import (
    preflight_outcome,
    prepare_transport_request,
    project_transport_outcome,
    validate_trusted_identity,
)


class SyncEvidenceClient:
    def __init__(
        self,
        *,
        transport: SyncEvidenceTransport,
        signer: SyncTrustedIngestionSigner,
        replay_guard: SyncAttemptReplayGuard,
        clock: Clock,
        trust_configuration: CollectorTrustConfiguration,
        key_resolver: TrustedKeyResolver,
        trusted_key_anchor: TrustedKeyAnchor,
    ) -> None:
        self._transport = transport
        self._signer = signer
        self._replay_guard = replay_guard
        self._clock = clock
        self._trust_configuration = trust_configuration
        self._key_resolver = key_resolver
        self._trusted_key_anchor = trusted_key_anchor

    def collect(self, command: EvidenceCollectionCommand) -> CollectedEvidence:
        started_at = self._clock.now()
        request = prepare_transport_request(
            command,
            self._trust_configuration,
            attempt_started_at=started_at,
        )
        if not self._replay_guard.reserve(request.attempt_id, request.request_digest):
            raise ReplayDetectedError("attempt id or request digest has already been reserved")
        preflight = preflight_outcome(request)
        outcome: McpTransportOutcome
        if preflight is None:
            try:
                outcome = self._transport.invoke(request)
            except TimeoutError:
                deadline = started_at + timedelta(
                    milliseconds=request.bounds.timeout_milliseconds
                )
                timed_out_at = self._clock.now()
                if timed_out_at <= deadline:
                    timed_out_at = deadline + timedelta(seconds=1)
                outcome = McpTimeoutNoResponse(
                    deadline_at=deadline,
                    timed_out_at=timed_out_at,
                )
        else:
            outcome = preflight
        validated_at = self._clock.now()
        if isinstance(outcome, McpTimeoutNoResponse) and outcome.timed_out_at > validated_at:
            validated_at = outcome.timed_out_at
        projection = project_transport_outcome(
            request,
            outcome,
            validated_at=validated_at,
        )
        binding = TrustedIngestionBinding(
            request=request,
            collector_attempt=projection.collector_attempt,
            trust_configuration=self._trust_configuration,
            as_of=validated_at,
        )
        identity = self._signer.bind_attempt(binding)
        validate_trusted_identity(
            identity,
            projection,
            self._trust_configuration,
            key_resolver=self._key_resolver,
            trusted_key_anchor=self._trusted_key_anchor,
            as_of=validated_at,
        )
        return CollectedEvidence(
            request=request,
            collector_attempt=projection.collector_attempt,
            evidence_records=projection.evidence_records,
            collector_identity_evidence=identity,
            envelope=projection.envelope,
        )


class AsyncEvidenceClient:
    def __init__(
        self,
        *,
        transport: AsyncEvidenceTransport,
        signer: AsyncTrustedIngestionSigner,
        replay_guard: AsyncAttemptReplayGuard,
        clock: Clock,
        trust_configuration: CollectorTrustConfiguration,
        key_resolver: TrustedKeyResolver,
        trusted_key_anchor: TrustedKeyAnchor,
    ) -> None:
        self._transport = transport
        self._signer = signer
        self._replay_guard = replay_guard
        self._clock = clock
        self._trust_configuration = trust_configuration
        self._key_resolver = key_resolver
        self._trusted_key_anchor = trusted_key_anchor

    async def collect(self, command: EvidenceCollectionCommand) -> CollectedEvidence:
        started_at = self._clock.now()
        request = prepare_transport_request(
            command,
            self._trust_configuration,
            attempt_started_at=started_at,
        )
        if not await self._replay_guard.reserve(
            request.attempt_id, request.request_digest
        ):
            raise ReplayDetectedError("attempt id or request digest has already been reserved")
        preflight = preflight_outcome(request)
        outcome: McpTransportOutcome
        if preflight is None:
            try:
                outcome = await self._transport.invoke(request)
            except TimeoutError:
                deadline = started_at + timedelta(
                    milliseconds=request.bounds.timeout_milliseconds
                )
                timed_out_at = self._clock.now()
                if timed_out_at <= deadline:
                    timed_out_at = deadline + timedelta(seconds=1)
                outcome = McpTimeoutNoResponse(
                    deadline_at=deadline,
                    timed_out_at=timed_out_at,
                )
        else:
            outcome = preflight
        validated_at = self._clock.now()
        if isinstance(outcome, McpTimeoutNoResponse) and outcome.timed_out_at > validated_at:
            validated_at = outcome.timed_out_at
        projection = project_transport_outcome(
            request,
            outcome,
            validated_at=validated_at,
        )
        binding = TrustedIngestionBinding(
            request=request,
            collector_attempt=projection.collector_attempt,
            trust_configuration=self._trust_configuration,
            as_of=validated_at,
        )
        identity = await self._signer.bind_attempt(binding)
        validate_trusted_identity(
            identity,
            projection,
            self._trust_configuration,
            key_resolver=self._key_resolver,
            trusted_key_anchor=self._trusted_key_anchor,
            as_of=validated_at,
        )
        return CollectedEvidence(
            request=request,
            collector_attempt=projection.collector_attempt,
            evidence_records=projection.evidence_records,
            collector_identity_evidence=identity,
            envelope=projection.envelope,
        )


__all__ = ["AsyncEvidenceClient", "SyncEvidenceClient"]
