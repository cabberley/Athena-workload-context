from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from pydantic import ValidationError

from athena_context.contracts import (
    CorrelationRequest,
    GuidancePublicationRequestDeliveryBudget,
    IncidentNotificationEnvelopeV2,
    PublishedGuidanceAuthorityActivation,
    PublishedGuidanceAuthorityBinding,
    UtcDateTime,
    canonicalize_json,
)
from athena_context.correlation import VerifiedCorrelationReport
from athena_context.enrichment.feed_pipeline import (
    IncidentEnrichmentFeedPublicationReceipt,
)
from athena_context.enrichment.publication import (
    IncidentEnrichmentPublicationReceipt,
)
from athena_context.guidance.publication import (
    GuidanceAuthorityActivationConflictError,
    GuidanceAuthorityActivationSnapshot,
    guidance_authority_effective_finish_before,
    verify_guidance_authority_activation,
)
from athena_context.presentation_assets import (
    ActiveIncidentIndexSnapshot,
    CurrentIncidentStateSnapshot,
    IncidentPublicationReceipt,
)

MAX_WC027_ENRICHMENT_TRIGGER_BYTES = 12 * 1024 * 1024
WC027_ENRICHMENT_TRIGGER_SCHEMA_VERSION = (
    "athena.wc027PublishedGuidanceAuthorityBinding.v2"
)
SignatureVerifier = Callable[[bytes, str], bool]


class CorrelationRuntimePort(Protocol):
    def correlate(self, request: CorrelationRequest) -> VerifiedCorrelationReport: ...


class IncidentPublicationAuthorityReaderPort(Protocol):
    def read_active_incident_index(self) -> ActiveIncidentIndexSnapshot | None: ...

    def read_current_incident_state(
        self,
        *,
        incident_id: str,
    ) -> CurrentIncidentStateSnapshot | None: ...


class GuidanceAuthorityActivationPort(Protocol):
    def read_current(
        self,
        *,
        incident_id: str,
    ) -> GuidanceAuthorityActivationSnapshot | None: ...

    def mark_feed_materialized(
        self,
        activation: PublishedGuidanceAuthorityActivation,
        *,
        expected_etag: str,
    ) -> GuidanceAuthorityActivationSnapshot: ...


class IncidentEnrichmentPublicationPort(Protocol):
    def publish(
        self,
        *,
        incident_publication: IncidentPublicationReceipt,
        verified_report: VerifiedCorrelationReport,
        guidance_binding: PublishedGuidanceAuthorityBinding,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> IncidentEnrichmentPublicationReceipt: ...


class IncidentEnrichmentFeedPublicationPort(Protocol):
    def publish(
        self,
        enrichment_publication: IncidentEnrichmentPublicationReceipt,
        *,
        published_at: UtcDateTime,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> IncidentEnrichmentFeedPublicationReceipt: ...


class NotificationV2PublicationPort(Protocol):
    def publish(
        self,
        *,
        incident_id: str,
        verified_at: datetime,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> IncidentNotificationEnvelopeV2: ...


class Wc027EnrichmentSourceNotReadyError(RuntimeError):
    """A signed trigger is valid but its current incident authority is not ready."""


@dataclass(frozen=True, slots=True)
class Wc027EnrichmentFeedRuntimeReceipt:
    binding_id: str
    enrichment_feed_publication: IncidentEnrichmentFeedPublicationReceipt
    notification: IncidentNotificationEnvelopeV2

    def __post_init__(self) -> None:
        incident_id = (
            self.enrichment_feed_publication.enrichment_publication.occurrence.incident_id
        )
        if self.notification.notification.incident_id != incident_id:
            raise ValueError("runtime receipt does not bind one incident")


@dataclass(frozen=True, slots=True)
class Wc027EnrichmentFeedRuntime:
    guidance_binding_key_id: str
    guidance_binding_signature_verifier: SignatureVerifier
    correlation: CorrelationRuntimePort
    incident_authority: IncidentPublicationAuthorityReaderPort
    guidance_activation: GuidanceAuthorityActivationPort
    enrichment_publication: IncidentEnrichmentPublicationPort
    feed_publication: IncidentEnrichmentFeedPublicationPort
    notification_publication: NotificationV2PublicationPort
    delivery_budget: GuidancePublicationRequestDeliveryBudget
    clock: Callable[[], datetime] | None = None

    def __post_init__(self) -> None:
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
        binding: PublishedGuidanceAuthorityBinding,
        *,
        published_at: UtcDateTime,
    ) -> Wc027EnrichmentFeedRuntimeReceipt:
        if type(binding) is not PublishedGuidanceAuthorityBinding:
            raise TypeError(
                "binding must be an exact PublishedGuidanceAuthorityBinding"
            )
        binding = PublishedGuidanceAuthorityBinding.model_validate_json(
            binding.canonical_bytes()
        )
        verify_wc027_guidance_binding_signature(
            binding,
            trusted_key_id=self.guidance_binding_key_id,
            signature_verifier=self.guidance_binding_signature_verifier,
        )
        _require_canonical_timestamp(published_at)
        request = binding.incident_bound_request
        incident_id = request.incident_subject.incident_id
        current = self.incident_authority.read_current_incident_state(
            incident_id=incident_id
        )
        active_index = self.incident_authority.read_active_incident_index()
        if current is None or current.occurrence is None or active_index is None:
            raise Wc027EnrichmentSourceNotReadyError(
                "current incident occurrence and active index are required"
            )
        activation = self.guidance_activation.read_current(
            incident_id=incident_id
        )
        if activation is None:
            raise Wc027EnrichmentSourceNotReadyError(
                "current guidance authority activation is required"
            )
        effective_finish_before = guidance_authority_effective_finish_before(
            activation.activation,
            binding,
        )
        verify_guidance_authority_activation(
            activation.activation,
            binding,
            trusted_key_id=self.guidance_binding_key_id,
            signature_verifier=self.guidance_binding_signature_verifier,
            expected_delivery_budget=self.delivery_budget,
            verified_at=published_at,
        )
        if effective_finish_before - published_at < self.delivery_budget.feed_processing_budget:
            raise Wc027EnrichmentSourceNotReadyError(
                "guidance activation lacks the reviewed feed processing window"
            )
        subject = request.incident_subject
        if (
            current.state != subject.incident_state
            or current.occurrence.state_reference != subject.state_reference
            or current.occurrence.state_attestation_reference
            != subject.attestation_reference
            or current.occurrence.occurrence_digest
            != activation.activation.occurrence_digest
        ):
            raise ValueError(
                "signed guidance binding is stale for the current incident occurrence"
            )
        incident_publication = IncidentPublicationReceipt(
            incident_id=incident_id,
            pointer_sha256=current.pointer_sha256,
            active_index_sha256=active_index.payload_sha256,
            occurrence=current.occurrence,
        )
        verified_report = self.correlation.correlate(request.correlation_request)

        def before_irreversible_write() -> None:
            self._require_irreversible_write_window(
                effective_finish_before,
                fallback=published_at,
            )

        enrichment = self.enrichment_publication.publish(
            incident_publication=incident_publication,
            verified_report=verified_report,
            guidance_binding=binding,
            before_irreversible_write=before_irreversible_write,
        )
        feed = self.feed_publication.publish(
            enrichment,
            published_at=published_at,
            before_irreversible_write=before_irreversible_write,
        )
        notification = self.notification_publication.publish(
            incident_id=incident_id,
            verified_at=published_at,
            before_irreversible_write=before_irreversible_write,
        )
        before_irreversible_write()
        self._mark_feed_materialized(activation)
        return Wc027EnrichmentFeedRuntimeReceipt(
            binding_id=binding.binding_id,
            enrichment_feed_publication=feed,
            notification=notification,
        )

    def _mark_feed_materialized(
        self,
        snapshot: GuidanceAuthorityActivationSnapshot,
    ) -> GuidanceAuthorityActivationSnapshot:
        if snapshot.trigger_delivery_status == "materialized":
            return snapshot
        try:
            return self.guidance_activation.mark_feed_materialized(
                snapshot.activation,
                expected_etag=snapshot.etag,
            )
        except GuidanceAuthorityActivationConflictError:
            current = self.guidance_activation.read_current(
                incident_id=snapshot.activation.incident_id
            )
            if (
                current is None
                or current.activation != snapshot.activation
                or current.trigger_delivery_status != "materialized"
            ):
                raise
            return current

    def _require_irreversible_write_window(
        self,
        finish_before: datetime,
        *,
        fallback: datetime,
    ) -> None:
        current = fallback if self.clock is None else self.clock()
        _require_canonical_timestamp(current)
        if (
            finish_before - current
            < self.delivery_budget.feed_irreversible_write_margin
        ):
            raise Wc027EnrichmentSourceNotReadyError(
                "guidance activation lacks the reviewed irreversible-write margin"
            )


def parse_wc027_enrichment_trigger(
    payload: bytes,
) -> PublishedGuidanceAuthorityBinding:
    if (
        type(payload) is not bytes
        or not 1 <= len(payload) <= MAX_WC027_ENRICHMENT_TRIGGER_BYTES
    ):
        raise ValueError("WC-027 enrichment trigger is outside its byte bound")
    try:
        binding = PublishedGuidanceAuthorityBinding.model_validate_json(payload)
    except (ValidationError, ValueError) as exc:
        raise ValueError("WC-027 enrichment trigger is invalid") from exc
    if payload != binding.canonical_bytes():
        raise ValueError("WC-027 enrichment trigger bytes are not canonical")
    return binding


def verify_wc027_guidance_binding_signature(
    binding: PublishedGuidanceAuthorityBinding,
    *,
    trusted_key_id: str,
    signature_verifier: SignatureVerifier,
) -> None:
    if type(binding) is not PublishedGuidanceAuthorityBinding:
        raise TypeError("binding must be an exact PublishedGuidanceAuthorityBinding")
    if type(trusted_key_id) is not str or not trusted_key_id:
        raise ValueError("guidance binding trusted key ID is invalid")
    preimage = binding.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={
            "binding_id",
            "binding_digest",
            "binding_attestation",
        },
    )
    if (
        binding.binding_attestation.key_id != trusted_key_id
        or signature_verifier(
            canonicalize_json(preimage).encode("utf-8"),
            binding.binding_attestation.detached_signature,
        )
        is not True
    ):
        raise ValueError("guidance authority binding signature is invalid")


def validate_wc027_enrichment_broker_metadata(
    message: object,
    binding: PublishedGuidanceAuthorityBinding,
    *,
    expected_delivery_budget: GuidancePublicationRequestDeliveryBudget,
) -> None:
    properties = getattr(message, "application_properties", None)
    if type(properties) is not dict:
        raise ValueError("WC-027 enrichment trigger metadata is missing")
    normalized = {
        (
            key.decode("utf-8")
            if isinstance(key, bytes)
            else str(key)
        ): (
            value.decode("utf-8")
            if isinstance(value, bytes)
            else value
        )
        for key, value in properties.items()
    }
    expected_properties: dict[str, object] = {
        "schemaVersion": WC027_ENRICHMENT_TRIGGER_SCHEMA_VERSION,
        "bindingDigest": binding.binding_digest,
    }
    legacy_properties = dict(expected_properties)
    expected_properties.update(expected_delivery_budget.broker_properties())
    if (
        getattr(message, "content_type", None) != "application/json"
        or str(getattr(message, "message_id", "")) != binding.binding_id
        or str(getattr(message, "session_id", ""))
        != binding.incident_bound_request.incident_subject.incident_id
        or normalized not in (legacy_properties, expected_properties)
    ):
        raise ValueError("WC-027 enrichment trigger broker metadata is invalid")


def _require_canonical_timestamp(value: UtcDateTime) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
        or value.microsecond % 1000
    ):
        raise ValueError(
            "published_at must be a UTC timestamp with millisecond precision"
        )


def utc_now_millisecond() -> UtcDateTime:
    current = datetime.now(UTC)
    return current.replace(microsecond=(current.microsecond // 1000) * 1000)


__all__ = [
    "MAX_WC027_ENRICHMENT_TRIGGER_BYTES",
    "WC027_ENRICHMENT_TRIGGER_SCHEMA_VERSION",
    "Wc027EnrichmentFeedRuntime",
    "Wc027EnrichmentFeedRuntimeReceipt",
    "Wc027EnrichmentSourceNotReadyError",
    "parse_wc027_enrichment_trigger",
    "utc_now_millisecond",
    "validate_wc027_enrichment_broker_metadata",
    "verify_wc027_guidance_binding_signature",
]
