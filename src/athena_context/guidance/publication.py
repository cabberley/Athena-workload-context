from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from math import ceil
from typing import Protocol

from pydantic import BaseModel, ValidationError

from athena_context.artifacts import (
    MAX_ARTIFACT_TRANSFER_BYTES,
    ArtifactMetadataHashes,
    ArtifactWriteRequest,
)
from athena_context.contracts import (
    MAX_GUIDANCE_AUTHORITY_ACTIVATION_BYTES,
    MAX_GUIDANCE_AUTHORITY_BINDING_BYTES,
    MAX_GUIDANCE_AUTHORITY_PUBLICATION_REQUEST_BYTES,
    CorrelationReport,
    CorrelationRequest,
    GuidanceAuthorityPublicationRequest,
    GuidancePublicationRequestDeliveryBudget,
    IncidentBoundCorrelationRequest,
    IncidentOccurrenceReceipt,
    NoRunbookGuidanceSelection,
    PublishedGuidanceAuthority,
    PublishedGuidanceAuthorityActivation,
    PublishedGuidanceAuthorityActivationAttestation,
    PublishedGuidanceAuthorityBinding,
    PublishedGuidanceAuthorityBindingAttestation,
    PublishedRuntimeContextBinding,
    UtcDateTime,
    VersionPinnedBlobReference,
    compute_artifact_digest,
    guidance_authority_activation_signature_preimage,
    guidance_authority_binding_signature_preimage,
    guidance_authority_publication_request_signature_preimage,
    incident_bound_correlation_request_signature_preimage,
    incident_correlation_subject_signature_preimage,
    incident_state_signature_preimage,
    sha256_hex,
)
from athena_context.correlation import VerifiedCorrelationReport
from athena_context.presentation import PresentationSigner
from athena_context.presentation_assets import (
    ActiveIncidentIndexSnapshot,
    CurrentIncidentStateSnapshot,
)

SignatureVerifier = Callable[[bytes, str], bool]


class GuidanceAuthorityArtifactWriterPort(Protocol):
    def create_or_recover(
        self,
        request: ArtifactWriteRequest,
    ) -> VersionPinnedBlobReference: ...

    def read_reference(
        self,
        reference: VersionPinnedBlobReference,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class GuidanceAuthorityActivationSnapshot:
    activation: PublishedGuidanceAuthorityActivation
    etag: str

    def __post_init__(self) -> None:
        if type(self.etag) is not str or not self.etag:
            raise ValueError("activation etag must be a non-empty opaque value")


class GuidanceAuthorityActivationStorePort(Protocol):
    def read_current(
        self,
        *,
        incident_id: str,
    ) -> GuidanceAuthorityActivationSnapshot | None: ...

    def compare_and_swap(
        self,
        activation: PublishedGuidanceAuthorityActivation,
        *,
        expected_etag: str | None,
    ) -> GuidanceAuthorityActivationSnapshot: ...


class GuidanceAuthorityTriggerPort(Protocol):
    def enqueue(
        self,
        binding: PublishedGuidanceAuthorityBinding,
        *,
        time_to_live_seconds: int,
        delivery_budget: GuidancePublicationRequestDeliveryBudget,
    ) -> None: ...


class GuidanceAuthorityCorrelationPort(Protocol):
    def correlate(self, request: CorrelationRequest) -> VerifiedCorrelationReport: ...

    def validate_result(self, result: VerifiedCorrelationReport) -> CorrelationReport: ...


class GuidanceAuthorityIncidentReaderPort(Protocol):
    def read_active_incident_index(self) -> ActiveIncidentIndexSnapshot | None: ...

    def read_current_incident_state(
        self,
        *,
        incident_id: str,
    ) -> CurrentIncidentStateSnapshot | None: ...


@dataclass(frozen=True, slots=True)
class GuidanceIncidentAuthoritySnapshot:
    current: CurrentIncidentStateSnapshot
    active: ActiveIncidentIndexSnapshot


def verify_incident_bound_request_signatures(
    request: IncidentBoundCorrelationRequest,
    *,
    incident_key_vault_key_id: str,
    incident_signature_verifier: SignatureVerifier,
    correlation_binding_key_id: str,
    correlation_binding_signature_verifier: SignatureVerifier,
) -> None:
    """Verify all nested signatures before any guidance output write."""

    if type(request) is not IncidentBoundCorrelationRequest:
        raise TypeError(
            "request must be an exact IncidentBoundCorrelationRequest"
        )
    request = IncidentBoundCorrelationRequest.model_validate_json(
        request.canonical_bytes()
    )
    subject = request.incident_subject
    state = subject.incident_state
    if (
        type(incident_key_vault_key_id) is not str
        or not incident_key_vault_key_id
        or type(correlation_binding_key_id) is not str
        or not correlation_binding_key_id
        or subject.incident_state_attestation.key_vault_key_id
        != incident_key_vault_key_id
        or subject.incident_state_attestation.result_digest
        != state.result_digest
        or incident_signature_verifier(
            incident_state_signature_preimage(state),
            subject.incident_state_attestation.detached_signature,
        )
        is not True
        or subject.subject_attestation.key_vault_key_id
        != incident_key_vault_key_id
        or incident_signature_verifier(
            incident_correlation_subject_signature_preimage(subject),
            subject.subject_attestation.detached_signature,
        )
        is not True
        or request.binding_attestation.key_vault_key_id
        != correlation_binding_key_id
        or correlation_binding_signature_verifier(
            incident_bound_correlation_request_signature_preimage(request),
            request.binding_attestation.detached_signature,
        )
        is not True
    ):
        raise ValueError("nested authority signature is invalid")


def read_current_guidance_incident_authority(
    request: IncidentBoundCorrelationRequest,
    *,
    incident_key_id: str,
    incident_authority: GuidanceAuthorityIncidentReaderPort,
    expected_occurrence: IncidentOccurrenceReceipt | None = None,
) -> GuidanceIncidentAuthoritySnapshot:
    """Read and bind the current signed occurrence and active incident index."""

    if type(request) is not IncidentBoundCorrelationRequest:
        raise TypeError(
            "request must be an exact IncidentBoundCorrelationRequest"
        )
    if type(incident_key_id) is not str or not incident_key_id:
        raise ValueError("incident logical key ID is invalid")
    if (
        expected_occurrence is not None
        and type(expected_occurrence) is not IncidentOccurrenceReceipt
    ):
        raise TypeError(
            "expected_occurrence must be an exact IncidentOccurrenceReceipt"
        )
    subject = request.incident_subject
    current = incident_authority.read_current_incident_state(
        incident_id=subject.incident_id
    )
    active = incident_authority.read_active_incident_index()
    confirmed_current = incident_authority.read_current_incident_state(
        incident_id=subject.incident_id
    )
    confirmed_active = incident_authority.read_active_incident_index()
    if (
        current is None
        or current.occurrence is None
        or active is None
        or confirmed_current is None
        or confirmed_current.occurrence is None
        or confirmed_active is None
    ):
        raise GuidanceAuthoritySourceNotReadyError(
            "current signed incident occurrence is unavailable"
        )
    if current != confirmed_current or active != confirmed_active:
        raise GuidanceAuthoritySourceNotReadyError(
            "signed incident authority changed during snapshot read"
        )
    occurrence = current.occurrence
    entry = next(
        (
            item
            for item in active.index.incidents
            if item.incident_id == subject.incident_id
        ),
        None,
    )
    if (
        current.state != subject.incident_state
        or current.pointer.incident_id != subject.incident_id
        or current.pointer.key_id != incident_key_id
        or active.index.key_id != incident_key_id
        or occurrence.incident_id != subject.incident_id
        or occurrence.transition_id != subject.incident_transition_id
        or occurrence.state_result_digest != subject.incident_state_digest
        or occurrence.state_reference != subject.state_reference
        or occurrence.state_attestation_reference
        != subject.attestation_reference
        or (
            expected_occurrence is not None
            and occurrence != expected_occurrence
        )
    ):
        raise ValueError(
            "incident request is stale for current signed incident authority"
        )
    if (
        current.pointer.key_fingerprint != active.index.key_fingerprint
        or current.pointer_sha256
        != occurrence.pointer_reference.content_digest
        or entry is None
        or entry.lifecycle != "active"
        or entry.pointer_path != f"./{occurrence.pointer_reference.name}"
        or entry.pointer_sha256 != current.pointer_sha256
    ):
        raise GuidanceAuthoritySourceNotReadyError(
            "current incident pointer and active index are not coherent"
        )
    return GuidanceIncidentAuthoritySnapshot(
        current=current,
        active=active,
    )


def require_unchanged_guidance_incident_authority(
    request: IncidentBoundCorrelationRequest,
    *,
    expected: GuidanceIncidentAuthoritySnapshot,
    incident_key_id: str,
    incident_authority: GuidanceAuthorityIncidentReaderPort,
    expected_occurrence: IncidentOccurrenceReceipt | None = None,
) -> None:
    if type(expected) is not GuidanceIncidentAuthoritySnapshot:
        raise TypeError(
            "expected must be an exact GuidanceIncidentAuthoritySnapshot"
        )
    current = read_current_guidance_incident_authority(
        request,
        incident_key_id=incident_key_id,
        incident_authority=incident_authority,
        expected_occurrence=expected_occurrence,
    )
    if current != expected:
        raise GuidanceAuthoritySourceNotReadyError(
            "signed incident authority changed during guidance publication"
        )


class GuidanceAuthorityActivationConflictError(RuntimeError):
    """The active guidance authority changed during compare-and-swap."""


class GuidanceAuthoritySourceNotReadyError(RuntimeError):
    """A required signed source changed or was temporarily unavailable."""


def parse_guidance_authority_publication_request(
    payload: bytes,
) -> GuidanceAuthorityPublicationRequest:
    if (
        type(payload) is not bytes
        or not 1 <= len(payload) <= MAX_GUIDANCE_AUTHORITY_PUBLICATION_REQUEST_BYTES
    ):
        raise ValueError("guidance publication request is outside its byte bound")
    try:
        request = GuidanceAuthorityPublicationRequest.model_validate_json(payload)
    except (ValidationError, ValueError) as exc:
        raise ValueError("guidance publication request is invalid") from exc
    if payload != request.canonical_bytes():
        raise ValueError("guidance publication request bytes are not canonical")
    return request


@dataclass(frozen=True, slots=True)
class GuidanceAuthorityPublicationReceipt:
    request_id: str
    authority_reference: VersionPinnedBlobReference
    binding_reference: VersionPinnedBlobReference
    activation: PublishedGuidanceAuthorityActivation
    replayed: bool


@dataclass(frozen=True, slots=True)
class GuidanceAuthorityPublisher:
    request_key_id: str
    request_signature_verifier: SignatureVerifier
    incident_key_id: str
    incident_key_vault_key_id: str
    incident_signature_verifier: SignatureVerifier
    correlation_binding_key_id: str
    correlation_binding_signature_verifier: SignatureVerifier
    binding_key_id: str
    binding_signer: PresentationSigner
    binding_signature_verifier: SignatureVerifier
    correlation: GuidanceAuthorityCorrelationPort
    incident_authority: GuidanceAuthorityIncidentReaderPort
    artifact_writer: GuidanceAuthorityArtifactWriterPort
    activation_store: GuidanceAuthorityActivationStorePort
    trigger: GuidanceAuthorityTriggerPort
    delivery_budget: GuidancePublicationRequestDeliveryBudget
    clock: Callable[[], datetime] | None = None

    def __post_init__(self) -> None:
        key_ids = (
            self.request_key_id,
            self.incident_key_id,
            self.correlation_binding_key_id,
            self.binding_key_id,
        )
        if any(
            type(item) is not str or not item
            for item in (*key_ids, self.incident_key_vault_key_id)
        ):
            raise ValueError("guidance publisher key IDs must be non-empty strings")
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("guidance publisher trust-domain key IDs must be distinct")
        if (
            type(self.delivery_budget)
            is not GuidancePublicationRequestDeliveryBudget
        ):
            raise TypeError(
                "delivery_budget must be an exact "
                "GuidancePublicationRequestDeliveryBudget"
            )

    def publish(
        self,
        request: GuidanceAuthorityPublicationRequest,
        *,
        now: UtcDateTime,
    ) -> GuidanceAuthorityPublicationReceipt:
        if type(request) is not GuidanceAuthorityPublicationRequest:
            raise TypeError(
                "request must be an exact GuidanceAuthorityPublicationRequest"
            )
        request = GuidanceAuthorityPublicationRequest.model_validate_json(
            request.canonical_bytes()
        )
        if (
            len(request.canonical_bytes())
            > MAX_GUIDANCE_AUTHORITY_PUBLICATION_REQUEST_BYTES
        ):
            raise ValueError("guidance publication request exceeds its byte bound")
        if now < request.evaluated_at or now >= request.expires_at:
            raise ValueError("guidance publication request is stale")

        self._verify_request_signatures(request)

        current, active = self._read_current_authority(request)
        self._require_remaining_window(
            request,
            at=now,
            required=timedelta(
                seconds=self.delivery_budget.publisher_processing_seconds
            ),
            phase="publisher processing",
        )
        verified = self.correlation.correlate(
            request.incident_bound_request.correlation_request
        )
        report = self.correlation.validate_result(verified)

        authority = _build_zero_option_authority(request)
        authority_reference = self._write_json(
            f"guidance-authority/{authority.authority_id}/authority.json",
            authority.canonical_bytes(),
        )
        binding = self._build_binding(
            request,
            report=report,
            authority=authority,
            authority_reference=authority_reference,
        )
        binding_reference = self._write_json(
            f"guidance-bindings/{binding.binding_id}/binding.json",
            binding.canonical_bytes(),
        )
        activation = self._build_activation(
            request,
            current=current,
            binding=binding,
            binding_reference=binding_reference,
        )

        self._require_unchanged_authority(request, current=current, active=active)
        second = self.correlation.correlate(
            request.incident_bound_request.correlation_request
        )
        if self.correlation.validate_result(second) != report:
            raise GuidanceAuthoritySourceNotReadyError(
                "correlation authority changed before activation"
            )

        operation_now = self._operation_time(now)
        if operation_now >= request.expires_at:
            raise ValueError("guidance publication request expired before activation")
        previous = self.activation_store.read_current(
            incident_id=current.state.incident_id
        )
        replayed = False
        if (
            previous is not None
            and previous.activation != activation
            and previous.activation.incident_state_digest
            == activation.incident_state_digest
            and previous.activation.expires_at > operation_now
        ):
            raise GuidanceAuthorityActivationConflictError(
                "a different guidance authority is already active for this occurrence"
            )
        if previous is not None and previous.activation == activation:
            committed = previous
            replayed = True
        else:
            self._require_unchanged_authority(
                request,
                current=current,
                active=active,
            )
            try:
                committed = self.activation_store.compare_and_swap(
                    activation,
                    expected_etag=None if previous is None else previous.etag,
                )
            except GuidanceAuthorityActivationConflictError:
                concurrent = self.activation_store.read_current(
                    incident_id=current.state.incident_id
                )
                if concurrent is None or concurrent.activation != activation:
                    raise
                committed = concurrent
                replayed = True
        if committed.activation != activation:
            raise GuidanceAuthorityActivationConflictError(
                "activation store committed a different guidance authority"
            )

        final_activation = self.activation_store.read_current(
            incident_id=current.state.incident_id
        )
        if final_activation is None or final_activation.activation != activation:
            raise GuidanceAuthorityActivationConflictError(
                "guidance authority activation changed after commit"
            )
        self._enqueue_committed_trigger(
            activation,
            binding,
            at=self._operation_time(operation_now),
        )
        return GuidanceAuthorityPublicationReceipt(
            request_id=request.request_id,
            authority_reference=authority_reference,
            binding_reference=binding_reference,
            activation=activation,
            replayed=replayed,
        )

    def recover_trigger_delivery(
        self,
        request: GuidanceAuthorityPublicationRequest,
        *,
        now: UtcDateTime,
    ) -> bool:
        if type(request) is not GuidanceAuthorityPublicationRequest:
            raise TypeError(
                "request must be an exact GuidanceAuthorityPublicationRequest"
            )
        request = GuidanceAuthorityPublicationRequest.model_validate_json(
            request.canonical_bytes()
        )
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
            or now.microsecond % 1000
        ):
            raise ValueError(
                "guidance publisher recovery time must be millisecond UTC"
            )
        self._verify_request_signatures(request)
        snapshot = self.activation_store.read_current(
            incident_id=request.incident_bound_request.incident_subject.incident_id
        )
        if snapshot is None or not self._activation_commits_request(
            snapshot.activation,
            request,
        ):
            return False
        binding = self._read_committed_binding(
            snapshot.activation,
            request=request,
        )
        self._enqueue_committed_trigger(
            snapshot.activation,
            binding,
            at=now,
        )
        return True

    def _read_committed_binding(
        self,
        activation: PublishedGuidanceAuthorityActivation,
        *,
        request: GuidanceAuthorityPublicationRequest,
    ) -> PublishedGuidanceAuthorityBinding:
        payload = self.artifact_writer.read_reference(
            activation.binding_reference
        )
        try:
            binding = PublishedGuidanceAuthorityBinding.model_validate_json(
                payload
            )
        except (ValidationError, ValueError) as exc:
            raise ValueError(
                "committed guidance binding outbox is invalid"
            ) from exc
        if (
            payload != binding.canonical_bytes()
            or binding.incident_bound_request
            != request.incident_bound_request
            or binding.requested_actions != request.requested_actions
            or binding.evaluated_at != request.evaluated_at
            or binding.binding_attestation.key_id != self.binding_key_id
            or self.binding_signature_verifier(
                guidance_authority_binding_signature_preimage(binding),
                binding.binding_attestation.detached_signature,
            )
            is not True
        ):
            raise ValueError(
                "committed guidance binding outbox is not canonical or trusted"
            )
        return binding

    def _enqueue_committed_trigger(
        self,
        activation: PublishedGuidanceAuthorityActivation,
        binding: PublishedGuidanceAuthorityBinding,
        *,
        at: datetime,
    ) -> None:
        if at > activation.trigger_delivery_deadline:
            raise GuidanceAuthoritySourceNotReadyError(
                "committed guidance trigger recovery deadline expired"
            )
        verify_guidance_authority_activation(
            activation,
            binding,
            trusted_key_id=self.binding_key_id,
            signature_verifier=self.binding_signature_verifier,
            expected_delivery_budget=self.delivery_budget,
            verified_at=at,
        )
        remaining = activation.expires_at - at
        if remaining < self.delivery_budget.feed_minimum_remaining_lifetime:
            raise GuidanceAuthoritySourceNotReadyError(
                "committed guidance trigger lacks the reviewed feed window"
            )
        self.trigger.enqueue(
            binding,
            time_to_live_seconds=ceil(remaining.total_seconds()),
            delivery_budget=self.delivery_budget,
        )

    def _activation_commits_request(
        self,
        activation: PublishedGuidanceAuthorityActivation,
        request: GuidanceAuthorityPublicationRequest,
    ) -> bool:
        return (
            activation.incident_id
            == request.incident_bound_request.incident_subject.incident_id
            and activation.incident_state_digest
            == request.incident_bound_request.incident_subject.incident_state.result_digest
            and activation.occurrence_digest
            == request.incident_occurrence.occurrence_digest
            and activation.publication_request_id == request.request_id
            and activation.publication_request_digest == request.request_digest
            and activation.activated_at == request.evaluated_at
            and activation.publication_request_expires_at
            == request.expires_at
            and activation.delivery_budget == self.delivery_budget
            and activation.trigger_message_id == activation.binding_id
            and activation.activation_attestation.key_id == self.binding_key_id
            and self.binding_signature_verifier(
                guidance_authority_activation_signature_preimage(activation),
                activation.activation_attestation.detached_signature,
            )
            is True
        )

    @staticmethod
    def _require_remaining_window(
        request: GuidanceAuthorityPublicationRequest,
        *,
        at: datetime,
        required: timedelta,
        phase: str,
    ) -> timedelta:
        remaining = request.expires_at - at
        if remaining < required:
            raise GuidanceAuthoritySourceNotReadyError(
                f"guidance publication request lacks the reviewed {phase} window"
            )
        return remaining

    def _operation_time(self, fallback: UtcDateTime) -> datetime:
        current = fallback if self.clock is None else self.clock()
        if (
            not isinstance(current, datetime)
            or current.tzinfo is None
            or current.utcoffset() != timedelta(0)
            or current.microsecond % 1000
        ):
            raise ValueError("guidance publisher clock must return millisecond UTC")
        return current

    def _verify_request_signatures(
        self,
        request: GuidanceAuthorityPublicationRequest,
    ) -> None:
        if (
            request.request_attestation.key_id != self.request_key_id
            or self.request_signature_verifier(
                guidance_authority_publication_request_signature_preimage(
                    request
                ),
                request.request_attestation.detached_signature,
            )
            is not True
        ):
            raise ValueError(
                "guidance publication request or nested authority signature is invalid"
            )
        verify_incident_bound_request_signatures(
            request.incident_bound_request,
            incident_key_vault_key_id=self.incident_key_vault_key_id,
            incident_signature_verifier=self.incident_signature_verifier,
            correlation_binding_key_id=self.correlation_binding_key_id,
            correlation_binding_signature_verifier=(
                self.correlation_binding_signature_verifier
            ),
        )

    def _read_incident_authority_snapshot(
        self,
        request: GuidanceAuthorityPublicationRequest,
    ) -> GuidanceIncidentAuthoritySnapshot:
        return read_current_guidance_incident_authority(
            request.incident_bound_request,
            incident_key_id=self.incident_key_id,
            incident_authority=self.incident_authority,
            expected_occurrence=request.incident_occurrence,
        )

    def _read_current_authority(
        self,
        request: GuidanceAuthorityPublicationRequest,
    ) -> tuple[CurrentIncidentStateSnapshot, ActiveIncidentIndexSnapshot]:
        snapshot = self._read_incident_authority_snapshot(request)
        return snapshot.current, snapshot.active

    def _require_unchanged_authority(
        self,
        request: GuidanceAuthorityPublicationRequest,
        *,
        current: CurrentIncidentStateSnapshot,
        active: ActiveIncidentIndexSnapshot,
    ) -> None:
        require_unchanged_guidance_incident_authority(
            request.incident_bound_request,
            expected=GuidanceIncidentAuthoritySnapshot(
                current=current,
                active=active,
            ),
            incident_key_id=self.incident_key_id,
            incident_authority=self.incident_authority,
            expected_occurrence=request.incident_occurrence,
        )

    def _build_binding(
        self,
        request: GuidanceAuthorityPublicationRequest,
        *,
        report: CorrelationReport,
        authority: PublishedGuidanceAuthority,
        authority_reference: VersionPinnedBlobReference,
    ) -> PublishedGuidanceAuthorityBinding:
        top = report.hypotheses[0]
        selection_payload: dict[str, object] = {
            "schemaVersion": "athena.wc027GuidanceSelection.v2",
            "selectionKind": "noRunbook",
            "reason": "noMatchingControl",
            "affectedRoleRef": (
                request.incident_bound_request.incident_subject.incident_state.workload_role
            ),
            "causeCategory": top.category,
            "affectedPathId": top.affected_path_id,
            "confidence": top.confidence,
            "requestedActions": request.requested_actions,
        }
        selection_digest = compute_artifact_digest(_json_payload(selection_payload))
        selection = NoRunbookGuidanceSelection.model_validate(
            {
                **selection_payload,
                "selectionId": (
                    "guidance-selection-"
                    f"{selection_digest.removeprefix('sha256:')[:32]}"
                ),
                "selectionDigest": selection_digest,
            }
        )
        unsigned_payload: dict[str, object] = {
            "schemaVersion": "athena.wc027PublishedGuidanceAuthorityBinding.v2",
            "incidentBoundRequest": request.incident_bound_request,
            "correlationReport": report,
            "guidanceAuthority": authority,
            "guidanceAuthorityReference": authority_reference,
            "requestedActions": request.requested_actions,
            "evaluatedAt": request.evaluated_at,
            "selection": selection,
        }
        preimage_digest = compute_artifact_digest(_json_payload(unsigned_payload))
        preimage = _canonical_payload(unsigned_payload)
        signature = normalize_guidance_detached_signature(
            self.binding_signer.sign_preimage(preimage)
        )
        if self.binding_signature_verifier(preimage, signature) is not True:
            raise ValueError("guidance authority binding signer failed verification")
        attestation = PublishedGuidanceAuthorityBindingAttestation.model_validate(
            {
                "schemaVersion": (
                    "athena.wc027PublishedGuidanceAuthorityBindingAttestation.v2"
                ),
                "signatureAlgorithm": "RS256",
                "keyId": self.binding_key_id,
                "signedPreimageDigest": preimage_digest,
                "detachedSignature": signature,
            }
        )
        payload = {**unsigned_payload, "bindingAttestation": attestation}
        digest = compute_artifact_digest(_json_payload(payload))
        binding = PublishedGuidanceAuthorityBinding.model_validate(
            {
                **payload,
                "bindingId": (
                    f"guidance-binding-{digest.removeprefix('sha256:')[:32]}"
                ),
                "bindingDigest": digest,
            }
        )
        if (
            len(binding.canonical_bytes()) > MAX_GUIDANCE_AUTHORITY_BINDING_BYTES
            or guidance_authority_binding_signature_preimage(binding) != preimage
        ):
            raise ValueError("guidance authority binding exceeds its byte bound")
        return binding

    def _build_activation(
        self,
        request: GuidanceAuthorityPublicationRequest,
        *,
        current: CurrentIncidentStateSnapshot,
        binding: PublishedGuidanceAuthorityBinding,
        binding_reference: VersionPinnedBlobReference,
    ) -> PublishedGuidanceAuthorityActivation:
        occurrence = current.occurrence
        if occurrence is None:
            raise ValueError("current signed incident occurrence is unavailable")
        unsigned_payload: dict[str, object] = {
            "schemaVersion": (
                "athena.wc027PublishedGuidanceAuthorityActivation.v1"
            ),
            "incidentId": current.state.incident_id,
            "incidentStateDigest": current.state.result_digest,
            "occurrenceDigest": occurrence.occurrence_digest,
            "publicationRequestId": request.request_id,
            "publicationRequestDigest": request.request_digest,
            "bindingId": binding.binding_id,
            "bindingDigest": binding.binding_digest,
            "bindingReference": binding_reference,
            "triggerMessageId": binding.binding_id,
            "deliveryBudget": self.delivery_budget,
            "activatedAt": request.evaluated_at,
            "publicationRequestExpiresAt": request.expires_at,
            "triggerDeliveryDeadline": (
                request.expires_at + self.delivery_budget.feed_trigger_recovery
            ),
            "expiresAt": (
                request.expires_at
                + self.delivery_budget.feed_trigger_recovery
                + self.delivery_budget.feed_minimum_remaining_lifetime
            ),
        }
        preimage = _canonical_payload(unsigned_payload)
        signature = normalize_guidance_detached_signature(
            self.binding_signer.sign_preimage(preimage)
        )
        if self.binding_signature_verifier(preimage, signature) is not True:
            raise ValueError("guidance activation signer failed verification")
        attestation = PublishedGuidanceAuthorityActivationAttestation(
            schemaVersion=(
                "athena.wc027PublishedGuidanceAuthorityActivationAttestation.v1"
            ),
            signatureAlgorithm="RS256",
            keyId=self.binding_key_id,
            signedPreimageDigest=compute_artifact_digest(
                _json_payload(unsigned_payload)
            ),
            detachedSignature=signature,
        )
        payload = {**unsigned_payload, "activationAttestation": attestation}
        digest = compute_artifact_digest(_json_payload(payload))
        activation = PublishedGuidanceAuthorityActivation.model_validate(
            {
                **payload,
                "activationId": (
                    f"guidance-activation-{digest.removeprefix('sha256:')[:32]}"
                ),
                "activationDigest": digest,
            }
        )
        if (
            len(activation.canonical_bytes())
            > MAX_GUIDANCE_AUTHORITY_ACTIVATION_BYTES
            or guidance_authority_activation_signature_preimage(activation)
            != preimage
        ):
            raise ValueError("guidance activation exceeds its byte bound")
        return activation

    def _write_json(
        self,
        blob_name: str,
        payload: bytes,
    ) -> VersionPinnedBlobReference:
        reference = self.artifact_writer.create_or_recover(
            ArtifactWriteRequest(
                blob_name=blob_name,
                payload=payload,
                content_type="application/json",
                hashes=ArtifactMetadataHashes(payload_sha256=sha256_hex(payload)),
                maximum_payload_bytes=MAX_ARTIFACT_TRANSFER_BYTES,
            )
        )
        if (
            reference.name != blob_name
            or reference.content_digest != sha256_hex(payload)
        ):
            raise ValueError("guidance artifact writer returned a mismatched reference")
        return reference


def _build_zero_option_authority(
    request: GuidanceAuthorityPublicationRequest,
) -> PublishedGuidanceAuthority:
    context = request.incident_bound_request.correlation_request.context_binding
    if not isinstance(context, PublishedRuntimeContextBinding):
        raise ValueError("guidance authority requires published runtime context")
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc027PublishedGuidanceAuthority.v2",
        "workloadId": context.workload_id,
        "manifestId": context.manifest_id,
        "manifestVersion": context.manifest_version,
        "manifestDigest": context.manifest_digest,
        "profileId": context.profile_id,
        "resolvedProfileDigest": context.resolved_profile_digest,
        "dependencyGraphDigest": context.dependency_graph_digest,
        "contextBindingDigest": context.binding_digest,
        "contextAuthority": context.publication_authority,
        "contextAuthorityReference": context.publication_authority_reference,
        "publicationRecordDigest": (
            context.publication_authority.publication_record_digest
        ),
        "auditHeadDigest": context.publication_authority.audit_head_digest,
        "publishedAt": context.publication_authority.published_at,
        "options": (),
        "noRunbookReasons": ("noMatchingControl",),
        "executionAuthorizationRequired": True,
    }
    digest = compute_artifact_digest(_json_payload(payload))
    return PublishedGuidanceAuthority.model_validate(
        {
            **payload,
            "authorityId": (
                f"guidance-authority-{digest.removeprefix('sha256:')[:32]}"
            ),
            "authorityDigest": digest,
        }
    )


def _canonical_payload(payload: dict[str, object]) -> bytes:
    from athena_context.contracts import canonicalize_json

    return canonicalize_json(_json_payload(payload)).encode("utf-8")


def _json_payload(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_payload(item) for item in value]
    if isinstance(value, list):
        return [_json_payload(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _json_payload(item)
            for key, item in value.items()
            if item is not None
        }
    return value


def normalize_guidance_detached_signature(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError, binascii.Error):
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (TypeError, ValueError, binascii.Error) as exc:
            raise ValueError("signer returned a malformed detached signature") from exc
    if not raw:
        raise ValueError("signer returned an empty detached signature")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def verify_guidance_authority_activation(
    activation: PublishedGuidanceAuthorityActivation,
    binding: PublishedGuidanceAuthorityBinding,
    *,
    trusted_key_id: str,
    signature_verifier: SignatureVerifier,
    expected_delivery_budget: GuidancePublicationRequestDeliveryBudget,
    verified_at: datetime,
) -> None:
    activation = PublishedGuidanceAuthorityActivation.model_validate_json(
        activation.canonical_bytes()
    )
    if (
        activation.activation_attestation.key_id != trusted_key_id
        or activation.incident_id
        != binding.incident_bound_request.incident_subject.incident_id
        or activation.incident_state_digest
        != binding.incident_bound_request.incident_subject.incident_state_digest
        or activation.binding_id != binding.binding_id
        or activation.trigger_message_id != binding.binding_id
        or activation.delivery_budget != expected_delivery_budget
        or activation.binding_digest != binding.binding_digest
        or activation.binding_reference.name
        != f"guidance-bindings/{binding.binding_id}/binding.json"
        or activation.binding_reference.content_digest
        != sha256_hex(binding.canonical_bytes())
        or verified_at < activation.activated_at
        or verified_at >= activation.expires_at
        or signature_verifier(
            guidance_authority_activation_signature_preimage(activation),
            activation.activation_attestation.detached_signature,
        )
        is not True
    ):
        raise ValueError("guidance authority activation is invalid or stale")


__all__ = [
    "GuidanceAuthorityActivationConflictError",
    "GuidanceAuthorityActivationSnapshot",
    "GuidanceIncidentAuthoritySnapshot",
    "GuidanceAuthorityPublisher",
    "GuidanceAuthorityPublicationReceipt",
    "GuidanceAuthoritySourceNotReadyError",
    "normalize_guidance_detached_signature",
    "parse_guidance_authority_publication_request",
    "read_current_guidance_incident_authority",
    "require_unchanged_guidance_incident_authority",
    "verify_incident_bound_request_signatures",
    "verify_guidance_authority_activation",
]
