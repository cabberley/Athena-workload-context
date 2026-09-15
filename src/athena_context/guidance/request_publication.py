from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ValidationError

from athena_context.artifacts import (
    ArtifactMetadataHashes,
    ArtifactWriteRequest,
)
from athena_context.contracts import (
    CORRELATION_MAX_CANONICAL_BYTES,
    MAX_GUIDANCE_AUTHORITY_PUBLICATION_REQUEST_BYTES,
    GuidanceActionKind,
    GuidanceAuthorityPublicationRequest,
    GuidanceAuthorityPublicationRequestAttestation,
    IncidentBoundCorrelationRequest,
    PublishedContextAuthority,
    PublishedRuntimeContextBinding,
    UtcDateTime,
    VersionPinnedBlobReference,
    compute_artifact_digest,
    guidance_authority_publication_request_signature_preimage,
    sha256_hex,
)
from athena_context.correlation import (
    ImmutableArtifactReader,
    verify_published_context_authority,
)
from athena_context.guidance.publication import (
    GuidanceAuthorityIncidentReaderPort,
    GuidanceAuthoritySourceNotReadyError,
    GuidanceIncidentAuthoritySnapshot,
    SignatureVerifier,
    normalize_guidance_detached_signature,
    read_current_guidance_incident_authority,
    require_unchanged_guidance_incident_authority,
    verify_incident_bound_request_signatures,
)
from athena_context.presentation import PresentationSigner

MAX_WC027_GUIDANCE_REQUEST_INPUT_BYTES = CORRELATION_MAX_CANONICAL_BYTES
WC027_GUIDANCE_REQUEST_INPUT_SCHEMA_VERSION = "athena.wc027IncidentBoundCorrelationRequest.v1"
WC027_GUIDANCE_PUBLICATION_REQUEST_SCHEMA_VERSION = (
    "athena.wc027GuidanceAuthorityPublicationRequest.v1"
)
_REQUEST_OUTBOX_PREFIX = "guidance-publication-requests"
_MAX_DETACHED_SIGNATURE_CHARS = 8192
_MAX_PUBLICATION_REQUEST_LIFETIME = timedelta(minutes=5)
WC027_GUIDANCE_PUBLISHER_KEDA_POLLING_INTERVAL_SECONDS = 30
WC027_GUIDANCE_PUBLISHER_COLD_START_SECONDS = 30
WC027_GUIDANCE_PUBLISHER_CONNECTION_SETUP_SECONDS = 30
WC027_GUIDANCE_PUBLISHER_PROCESSING_SECONDS = 60
WC027_GUIDANCE_MINIMUM_REMAINING_LIFETIME_SECONDS = (
    WC027_GUIDANCE_PUBLISHER_KEDA_POLLING_INTERVAL_SECONDS
    + WC027_GUIDANCE_PUBLISHER_COLD_START_SECONDS
    + WC027_GUIDANCE_PUBLISHER_CONNECTION_SETUP_SECONDS
    + WC027_GUIDANCE_PUBLISHER_PROCESSING_SECONDS
)
_ALLOWED_REQUESTED_ACTIONS = frozenset(
    {
        "investigationCheck",
        "confirmationCheck",
        "manualResolutionOption",
        "rollbackConsideration",
        "recoveryValidation",
        "escalation",
    }
)
type BrokerPropertyValue = int | float | bytes | bool | str | UUID


@dataclass(frozen=True, slots=True)
class GuidancePublicationRequestDeliveryBudget:
    publisher_keda_polling_interval_seconds: int
    publisher_cold_start_seconds: int
    publisher_connection_setup_seconds: int
    publisher_processing_seconds: int
    minimum_remaining_lifetime_seconds: int

    @classmethod
    def model_validate(
        cls,
        value: object,
    ) -> GuidancePublicationRequestDeliveryBudget:
        if type(value) is not dict or set(value) != {
            "publisherKedaPollingIntervalSeconds",
            "publisherColdStartSeconds",
            "publisherConnectionSetupSeconds",
            "publisherProcessingSeconds",
            "minimumRemainingLifetimeSeconds",
        }:
            raise ValueError("guidance publication delivery budget fields are invalid")
        values = (
            value["publisherKedaPollingIntervalSeconds"],
            value["publisherColdStartSeconds"],
            value["publisherConnectionSetupSeconds"],
            value["publisherProcessingSeconds"],
            value["minimumRemainingLifetimeSeconds"],
        )
        if any(type(item) is not int for item in values):
            raise ValueError("guidance publication delivery budget values must be integers")
        return cls(
            publisher_keda_polling_interval_seconds=values[0],
            publisher_cold_start_seconds=values[1],
            publisher_connection_setup_seconds=values[2],
            publisher_processing_seconds=values[3],
            minimum_remaining_lifetime_seconds=values[4],
        )

    def __post_init__(self) -> None:
        if (
            self.publisher_keda_polling_interval_seconds
            != WC027_GUIDANCE_PUBLISHER_KEDA_POLLING_INTERVAL_SECONDS
            or self.publisher_cold_start_seconds != WC027_GUIDANCE_PUBLISHER_COLD_START_SECONDS
            or self.publisher_connection_setup_seconds
            != WC027_GUIDANCE_PUBLISHER_CONNECTION_SETUP_SECONDS
            or self.publisher_processing_seconds != WC027_GUIDANCE_PUBLISHER_PROCESSING_SECONDS
            or self.minimum_remaining_lifetime_seconds
            != WC027_GUIDANCE_MINIMUM_REMAINING_LIFETIME_SECONDS
            or self.minimum_remaining_lifetime_seconds
            != self.publisher_keda_polling_interval_seconds
            + self.publisher_cold_start_seconds
            + self.publisher_connection_setup_seconds
            + self.publisher_processing_seconds
        ):
            raise ValueError(
                "guidance publication delivery budget does not match the reviewed "
                "publisher KEDA polling, cold-start, connection-setup, and processing allowances"
            )

    @property
    def minimum_remaining_lifetime(self) -> timedelta:
        return timedelta(seconds=self.minimum_remaining_lifetime_seconds)

    @property
    def publisher_processing_budget(self) -> timedelta:
        return timedelta(seconds=self.publisher_processing_seconds)

    def broker_properties(self) -> dict[str, int]:
        return {
            "publisherKedaPollingIntervalSeconds": self.publisher_keda_polling_interval_seconds,
            "publisherColdStartSeconds": self.publisher_cold_start_seconds,
            "publisherConnectionSetupSeconds": self.publisher_connection_setup_seconds,
            "publisherProcessingSeconds": self.publisher_processing_seconds,
            "minimumRemainingLifetimeSeconds": self.minimum_remaining_lifetime_seconds,
        }


class GuidancePublicationRequestOutboxPort(Protocol):
    def create_or_recover(
        self,
        request: ArtifactWriteRequest,
    ) -> VersionPinnedBlobReference: ...


class GuidancePublicationRequestSenderSessionPort(Protocol):
    def enqueue(
        self,
        request: GuidanceAuthorityPublicationRequest,
        *,
        outbox_reference: VersionPinnedBlobReference,
        time_to_live_seconds: int,
        delivery_budget: GuidancePublicationRequestDeliveryBudget,
    ) -> None: ...


class GuidancePublicationRequestSenderPort(Protocol):
    def open(
        self,
    ) -> AbstractContextManager[GuidancePublicationRequestSenderSessionPort]: ...


@dataclass(frozen=True, slots=True)
class GuidancePublicationRequestReceipt:
    request: GuidanceAuthorityPublicationRequest
    outbox_reference: VersionPinnedBlobReference

    def __post_init__(self) -> None:
        payload = self.request.canonical_bytes()
        if self.outbox_reference.name != guidance_publication_request_outbox_path(
            self.request.incident_occurrence.occurrence_id
        ) or self.outbox_reference.content_digest != sha256_hex(payload):
            raise ValueError(
                "guidance publication request receipt does not bind its outbox evidence"
            )


@dataclass(frozen=True, slots=True)
class GuidancePublicationRequestProducer:
    incident_key_id: str
    incident_key_vault_key_id: str
    incident_signature_verifier: SignatureVerifier
    correlation_binding_key_id: str
    correlation_binding_signature_verifier: SignatureVerifier
    request_key_id: str
    request_signer: PresentationSigner
    request_signature_verifier: SignatureVerifier
    incident_authority: GuidanceAuthorityIncidentReaderPort
    context_authority_reader: ImmutableArtifactReader
    outbox: GuidancePublicationRequestOutboxPort
    sender: GuidancePublicationRequestSenderPort
    requested_actions: tuple[GuidanceActionKind, ...]
    delivery_budget: GuidancePublicationRequestDeliveryBudget
    clock: Callable[[], datetime] | None = None

    def __post_init__(self) -> None:
        key_ids = (
            self.incident_key_id,
            self.incident_key_vault_key_id,
            self.correlation_binding_key_id,
            self.request_key_id,
        )
        if any(type(item) is not str or not item for item in key_ids):
            raise ValueError("guidance publication request producer key IDs must be non-empty")
        if type(self.delivery_budget) is not GuidancePublicationRequestDeliveryBudget:
            raise TypeError(
                "delivery_budget must be an exact GuidancePublicationRequestDeliveryBudget"
            )
        if self.request_key_id in {
            self.incident_key_id,
            self.incident_key_vault_key_id,
            self.correlation_binding_key_id,
        } or self.request_key_id.casefold().startswith("https://"):
            raise ValueError("guidance publication request key must use a distinct trust domain")
        actions = self.requested_actions
        if (
            type(actions) is not tuple
            or not 1 <= len(actions) <= 16
            or actions != tuple(sorted(actions))
            or len(set(actions)) != len(actions)
            or not set(actions).issubset(_ALLOWED_REQUESTED_ACTIONS)
        ):
            raise ValueError("requested actions must be sorted unique governed guidance categories")

    def produce(
        self,
        request: IncidentBoundCorrelationRequest,
        *,
        now: UtcDateTime,
    ) -> GuidancePublicationRequestReceipt:
        if type(request) is not IncidentBoundCorrelationRequest:
            raise TypeError("request must be an exact IncidentBoundCorrelationRequest")
        request = IncidentBoundCorrelationRequest.model_validate_json(request.canonical_bytes())
        _require_millisecond_utc(now, name="now")
        correlation_request = request.correlation_request
        if now < correlation_request.issued_at or now >= correlation_request.expires_at:
            raise ValueError("incident-bound correlation request is stale")
        if not isinstance(
            correlation_request.context_binding,
            PublishedRuntimeContextBinding,
        ):
            raise ValueError("guidance publication requests require published runtime context")

        verify_incident_bound_request_signatures(
            request,
            incident_key_vault_key_id=self.incident_key_vault_key_id,
            incident_signature_verifier=self.incident_signature_verifier,
            correlation_binding_key_id=self.correlation_binding_key_id,
            correlation_binding_signature_verifier=(self.correlation_binding_signature_verifier),
        )
        incident_snapshot = read_current_guidance_incident_authority(
            request,
            incident_key_id=self.incident_key_id,
            incident_authority=self.incident_authority,
        )
        context_authority = verify_published_context_authority(
            correlation_request.context_binding,
            authority_reader=self.context_authority_reader,
        )
        publication_request = self._build_request(
            request,
            incident_snapshot=incident_snapshot,
            context_authority=context_authority,
            now=now,
        )
        payload = publication_request.canonical_bytes()
        persistence_now = self._operation_time(now)
        self._require_remaining_delivery_budget(
            publication_request,
            at=persistence_now,
            phase="persistence",
        )
        outbox_reference = self.outbox.create_or_recover(
            ArtifactWriteRequest(
                blob_name=guidance_publication_request_outbox_path(
                    publication_request.incident_occurrence.occurrence_id
                ),
                payload=payload,
                content_type="application/json",
                hashes=ArtifactMetadataHashes(payload_sha256=sha256_hex(payload)),
                maximum_payload_bytes=(MAX_GUIDANCE_AUTHORITY_PUBLICATION_REQUEST_BYTES),
            )
        )
        if (
            type(outbox_reference) is not VersionPinnedBlobReference
            or outbox_reference.name
            != guidance_publication_request_outbox_path(
                publication_request.incident_occurrence.occurrence_id
            )
            or outbox_reference.content_digest != sha256_hex(payload)
        ):
            raise ValueError("guidance publication request outbox returned a mismatched reference")

        require_unchanged_guidance_incident_authority(
            request,
            expected=incident_snapshot,
            incident_key_id=self.incident_key_id,
            incident_authority=self.incident_authority,
        )
        revalidated_context = verify_published_context_authority(
            correlation_request.context_binding,
            authority_reader=self.context_authority_reader,
        )
        if revalidated_context != context_authority:
            raise GuidanceAuthoritySourceNotReadyError(
                "published context authority changed after request persistence"
            )

        with self.sender.open() as sender:
            operation_now = self._operation_time(persistence_now)
            remaining = self._require_remaining_delivery_budget(
                publication_request,
                at=operation_now,
                phase="enqueue",
            )
            remaining_seconds = int(remaining.total_seconds())
            sender.enqueue(
                publication_request,
                outbox_reference=outbox_reference,
                time_to_live_seconds=remaining_seconds,
                delivery_budget=self.delivery_budget,
            )
        return GuidancePublicationRequestReceipt(
            request=publication_request,
            outbox_reference=outbox_reference,
        )

    def _build_request(
        self,
        request: IncidentBoundCorrelationRequest,
        *,
        incident_snapshot: GuidanceIncidentAuthoritySnapshot,
        context_authority: PublishedContextAuthority,
        now: UtcDateTime,
    ) -> GuidanceAuthorityPublicationRequest:
        occurrence = incident_snapshot.current.occurrence
        if occurrence is None:
            raise GuidanceAuthoritySourceNotReadyError(
                "current signed incident occurrence is unavailable"
            )
        correlation_request = request.correlation_request
        evaluated_at = max(
            correlation_request.trusted_as_of,
            occurrence.published_at,
            context_authority.published_at,
        )
        expires_at = min(
            evaluated_at + timedelta(minutes=5),
            correlation_request.expires_at,
        )
        if (
            evaluated_at < correlation_request.issued_at
            or evaluated_at > now
            or expires_at <= evaluated_at
            or now >= expires_at
        ):
            raise ValueError("stable signed inputs cannot form a fresh guidance request window")
        unsigned_payload: dict[str, object] = {
            "schemaVersion": WC027_GUIDANCE_PUBLICATION_REQUEST_SCHEMA_VERSION,
            "incidentBoundRequest": request,
            "incidentOccurrence": occurrence,
            "requestedActions": self.requested_actions,
            "evaluatedAt": evaluated_at,
            "expiresAt": expires_at,
        }
        preimage = _canonical_payload(unsigned_payload)
        maximum_attestation = {
            "schemaVersion": ("athena.wc027GuidanceAuthorityPublicationRequestAttestation.v1"),
            "signatureAlgorithm": "RS256",
            "keyId": self.request_key_id,
            "signedPreimageDigest": compute_artifact_digest(_json_payload(unsigned_payload)),
            "detachedSignature": "A" * _MAX_DETACHED_SIGNATURE_CHARS,
        }
        maximum_envelope = {
            **unsigned_payload,
            "requestAttestation": maximum_attestation,
            "requestId": "guidance-publication-request-" + "0" * 32,
            "requestDigest": "sha256:" + "0" * 64,
        }
        if (
            len(_canonical_payload(maximum_envelope))
            > MAX_GUIDANCE_AUTHORITY_PUBLICATION_REQUEST_BYTES
        ):
            raise ValueError("guidance publication request exceeds its canonical bound")
        signature = normalize_guidance_detached_signature(
            self.request_signer.sign_preimage(preimage)
        )
        if self.request_signature_verifier(preimage, signature) is not True:
            raise ValueError("guidance publication request signer failed immediate verification")
        attestation = GuidanceAuthorityPublicationRequestAttestation(
            schemaVersion=("athena.wc027GuidanceAuthorityPublicationRequestAttestation.v1"),
            signatureAlgorithm="RS256",
            keyId=self.request_key_id,
            signedPreimageDigest=compute_artifact_digest(_json_payload(unsigned_payload)),
            detachedSignature=signature,
        )
        complete = {
            **unsigned_payload,
            "requestAttestation": attestation,
        }
        digest = compute_artifact_digest(_json_payload(complete))
        publication_request = GuidanceAuthorityPublicationRequest.model_validate(
            {
                **complete,
                "requestId": (
                    f"guidance-publication-request-{digest.removeprefix('sha256:')[:32]}"
                ),
                "requestDigest": digest,
            }
        )
        if (
            len(publication_request.canonical_bytes())
            > MAX_GUIDANCE_AUTHORITY_PUBLICATION_REQUEST_BYTES
            or guidance_authority_publication_request_signature_preimage(publication_request)
            != preimage
        ):
            raise ValueError("guidance publication request exceeds its canonical bound")
        return publication_request

    def _operation_time(self, fallback: UtcDateTime) -> datetime:
        current = fallback if self.clock is None else self.clock()
        _require_millisecond_utc(current, name="producer clock")
        return current

    def _require_remaining_delivery_budget(
        self,
        request: GuidanceAuthorityPublicationRequest,
        *,
        at: datetime,
        phase: str,
    ) -> timedelta:
        remaining = request.expires_at - at
        if not (
            self.delivery_budget.minimum_remaining_lifetime
            <= remaining
            <= _MAX_PUBLICATION_REQUEST_LIFETIME
        ):
            raise GuidanceAuthoritySourceNotReadyError(
                "guidance publication request lacks the reviewed downstream "
                f"remaining lifetime required before {phase}"
            )
        return remaining


def parse_wc027_guidance_request_input(
    payload: bytes,
) -> IncidentBoundCorrelationRequest:
    if (
        type(payload) is not bytes
        or not 1 <= len(payload) <= MAX_WC027_GUIDANCE_REQUEST_INPUT_BYTES
    ):
        raise ValueError("WC-027 guidance request input is outside its byte bound")
    try:
        request = IncidentBoundCorrelationRequest.model_validate_json(payload)
    except (ValidationError, ValueError) as exc:
        raise ValueError("WC-027 guidance request input is invalid") from exc
    if payload != request.canonical_bytes():
        raise ValueError("WC-027 guidance request input bytes are not canonical")
    return request


def guidance_publication_request_outbox_path(occurrence_id: str) -> str:
    if (
        type(occurrence_id) is not str
        or not occurrence_id.startswith("incident-occurrence-")
        or len(occurrence_id) != len("incident-occurrence-") + 32
        or any(
            character not in "0123456789abcdef"
            for character in occurrence_id.removeprefix("incident-occurrence-")
        )
    ):
        raise ValueError("occurrence_id is invalid")
    return f"{_REQUEST_OUTBOX_PREFIX}/{occurrence_id}/request.json"


def guidance_publication_request_broker_properties(
    request: GuidanceAuthorityPublicationRequest,
    *,
    outbox_reference: VersionPinnedBlobReference,
    delivery_budget: GuidancePublicationRequestDeliveryBudget,
) -> dict[str | bytes, BrokerPropertyValue]:
    if type(request) is not GuidanceAuthorityPublicationRequest:
        raise TypeError("request must be an exact GuidanceAuthorityPublicationRequest")
    if type(outbox_reference) is not VersionPinnedBlobReference:
        raise TypeError("outbox_reference must be an exact VersionPinnedBlobReference")
    if type(delivery_budget) is not GuidancePublicationRequestDeliveryBudget:
        raise TypeError("delivery_budget must be an exact GuidancePublicationRequestDeliveryBudget")
    expected_name = guidance_publication_request_outbox_path(
        request.incident_occurrence.occurrence_id
    )
    content_digest = sha256_hex(request.canonical_bytes())
    if outbox_reference.name != expected_name or outbox_reference.content_digest != content_digest:
        raise ValueError("outbox reference does not bind the exact publication request")
    context = request.incident_bound_request.correlation_request.context_binding
    if not isinstance(context, PublishedRuntimeContextBinding):
        raise ValueError("guidance publication request requires published runtime context")
    properties: dict[str | bytes, BrokerPropertyValue] = {
        "schemaVersion": request.schema_version,
        "requestDigest": request.request_digest,
        "incidentBoundRequestId": request.incident_bound_request.request_id,
        "incidentBoundRequestDigest": (request.incident_bound_request.binding_digest),
        "occurrenceId": request.incident_occurrence.occurrence_id,
        "occurrenceDigest": request.incident_occurrence.occurrence_digest,
        "incidentStateDigest": (
            request.incident_bound_request.incident_subject.incident_state_digest
        ),
        "contextAuthorityDigest": context.publication_authority.authority_digest,
        "outboxBlobName": outbox_reference.name,
        "outboxBlobVersion": outbox_reference.version,
        "outboxContentDigest": outbox_reference.content_digest,
        "noAutoRemediation": True,
    }
    properties.update(delivery_budget.broker_properties())
    return properties


def validate_guidance_publication_request_broker_metadata(
    message: object,
    request: GuidanceAuthorityPublicationRequest,
    *,
    expected_delivery_budget: GuidancePublicationRequestDeliveryBudget,
) -> VersionPinnedBlobReference:
    if type(expected_delivery_budget) is not GuidancePublicationRequestDeliveryBudget:
        raise TypeError(
            "expected_delivery_budget must be an exact GuidancePublicationRequestDeliveryBudget"
        )
    properties = getattr(message, "application_properties", None)
    if type(properties) is not dict:
        raise ValueError("guidance publication request broker metadata is missing")
    normalized = {
        (key.decode("utf-8") if isinstance(key, bytes) else str(key)): (
            value.decode("utf-8") if isinstance(value, bytes) else value
        )
        for key, value in properties.items()
    }
    expected_name = guidance_publication_request_outbox_path(
        request.incident_occurrence.occurrence_id
    )
    version = normalized.get("outboxBlobVersion")
    if type(version) is not str or not 1 <= len(version) <= 256:
        raise ValueError("guidance publication request outbox version metadata is invalid")
    reference = VersionPinnedBlobReference(
        name=expected_name,
        version=version,
        contentDigest=sha256_hex(request.canonical_bytes()),
    )
    if (
        getattr(message, "content_type", None) != "application/json"
        or str(getattr(message, "message_id", "")) != request.request_id
        or str(getattr(message, "session_id", ""))
        != request.incident_bound_request.incident_subject.incident_id
        or normalized
        != guidance_publication_request_broker_properties(
            request,
            outbox_reference=reference,
            delivery_budget=expected_delivery_budget,
        )
    ):
        raise ValueError("guidance publication request broker metadata is invalid")
    return reference


def verify_guidance_publication_request_outbox(
    request: GuidanceAuthorityPublicationRequest,
    *,
    outbox_reference: VersionPinnedBlobReference,
    outbox_reader: ImmutableArtifactReader,
) -> None:
    if type(request) is not GuidanceAuthorityPublicationRequest:
        raise TypeError("request must be an exact GuidanceAuthorityPublicationRequest")
    if type(outbox_reference) is not VersionPinnedBlobReference:
        raise TypeError("outbox_reference must be an exact VersionPinnedBlobReference")
    if not hasattr(outbox_reader, "read"):
        raise TypeError("outbox_reader must support exact immutable reads")
    canonical = request.canonical_bytes()
    if outbox_reference.name != guidance_publication_request_outbox_path(
        request.incident_occurrence.occurrence_id
    ) or outbox_reference.content_digest != sha256_hex(canonical):
        raise ValueError("outbox reference does not bind the exact publication request")
    persisted = outbox_reader.read(outbox_reference)
    if (
        type(persisted) is not bytes
        or persisted != canonical
        or sha256_hex(persisted) != outbox_reference.content_digest
    ):
        raise ValueError("guidance publication request does not match immutable outbox evidence")


def validate_wc027_guidance_request_input_broker_metadata(
    message: object,
    request: IncidentBoundCorrelationRequest,
) -> None:
    properties = getattr(message, "application_properties", None)
    if type(properties) is not dict:
        raise ValueError("WC-027 guidance request input metadata is missing")
    normalized = {
        (key.decode("utf-8") if isinstance(key, bytes) else str(key)): (
            value.decode("utf-8") if isinstance(value, bytes) else value
        )
        for key, value in properties.items()
    }
    context = request.correlation_request.context_binding
    context_authority_digest = (
        context.publication_authority.authority_digest
        if isinstance(context, PublishedRuntimeContextBinding)
        else ""
    )
    if (
        getattr(message, "content_type", None) != "application/json"
        or str(getattr(message, "message_id", "")) != request.request_id
        or str(getattr(message, "session_id", "")) != request.incident_subject.incident_id
        or normalized
        != {
            "schemaVersion": WC027_GUIDANCE_REQUEST_INPUT_SCHEMA_VERSION,
            "bindingDigest": request.binding_digest,
            "incidentSubjectDigest": request.incident_subject.subject_digest,
            "correlationRequestDigest": (request.correlation_request.request_digest),
            "contextAuthorityDigest": context_authority_digest,
            "noAutoRemediation": True,
        }
    ):
        raise ValueError("WC-027 guidance request input broker metadata is invalid")


def _require_millisecond_utc(value: datetime, *, name: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond % 1000
    ):
        raise ValueError(f"{name} must be a UTC timestamp with millisecond precision")


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
        return {str(key): _json_payload(item) for key, item in value.items() if item is not None}
    return value


__all__ = [
    "GuidancePublicationRequestDeliveryBudget",
    "GuidancePublicationRequestOutboxPort",
    "GuidancePublicationRequestProducer",
    "GuidancePublicationRequestReceipt",
    "GuidancePublicationRequestSenderPort",
    "GuidancePublicationRequestSenderSessionPort",
    "MAX_WC027_GUIDANCE_REQUEST_INPUT_BYTES",
    "WC027_GUIDANCE_PUBLICATION_REQUEST_SCHEMA_VERSION",
    "WC027_GUIDANCE_REQUEST_INPUT_SCHEMA_VERSION",
    "WC027_GUIDANCE_MINIMUM_REMAINING_LIFETIME_SECONDS",
    "WC027_GUIDANCE_PUBLISHER_COLD_START_SECONDS",
    "WC027_GUIDANCE_PUBLISHER_CONNECTION_SETUP_SECONDS",
    "WC027_GUIDANCE_PUBLISHER_KEDA_POLLING_INTERVAL_SECONDS",
    "WC027_GUIDANCE_PUBLISHER_PROCESSING_SECONDS",
    "guidance_publication_request_broker_properties",
    "guidance_publication_request_outbox_path",
    "parse_wc027_guidance_request_input",
    "validate_guidance_publication_request_broker_metadata",
    "validate_wc027_guidance_request_input_broker_metadata",
    "verify_guidance_publication_request_outbox",
]
