from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, cast
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel

from athena_context.contracts import (
    ActiveIncidentIndex,
    ActiveIncidentIndexAttestation,
    CorrelationReport,
    IncidentEnrichmentAttestation,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentEnrichmentManifest,
    IncidentFeedAttestation,
    IncidentFeedIndexAttestationV2,
    IncidentFeedIndexV2,
    IncidentFeedPointer,
    IncidentGuidance,
    IncidentGuidanceAttestation,
    IncidentNotificationEnvelopeV2,
    IncidentNotificationV2,
    IncidentNotificationV2Attestation,
    IncidentOccurrenceReceipt,
    IncidentState,
    IncidentStateAttestation,
    PublishedCorrelationReportAttestation,
    build_incident_occurrence_receipt,
    compute_artifact_digest,
    incident_pointer_signature_preimage,
    incident_state_signature_preimage,
    sha256_hex,
    validate_incident_enrichment_assets,
    validate_incident_enrichment_feed_pointer_assets,
    validate_incident_feed_index_assets,
    validate_incident_guidance_assets,
)
from athena_context.contracts.guidance import MAX_INCIDENT_GUIDANCE_BYTES
from athena_context.contracts.incident_enrichment import (
    MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
    MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES,
    MAX_PUBLISHED_CORRELATION_REPORT_BYTES,
)
from athena_context.contracts.incident_feed_v2 import (
    MAX_INCIDENT_FEED_V2_BYTES,
    MAX_INCIDENT_FEED_V2_POINTER_BYTES,
)
from athena_context.presentation import PresentationSigner
from athena_context.presentation_assets import (
    MAX_INCIDENT_FEED_POINTER_BYTES,
    MAX_INCIDENT_STATE_BYTES,
    MAX_PRESENTATION_ATTESTATION_BYTES,
    PresentationAssetReaderPort,
    PresentationAssetUnavailableError,
)

SignatureVerifier = Callable[[bytes, str], bool]
_MAX_FEED_AGE = timedelta(minutes=15)
_MAX_CLOCK_SKEW = timedelta(minutes=1)


class NotificationV2SourceNotReadyError(RuntimeError):
    """The signed feed has not caught up to the current v1 occurrence yet."""


class NotificationV2OutboxPort(Protocol):
    def enqueue_v2(self, envelope: IncidentNotificationEnvelopeV2) -> None: ...


class _CanonicalBytesModel(Protocol):
    def canonical_bytes(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class NotificationV2Trust:
    lifecycle_key_id: str
    lifecycle_key_vault_key_id: str
    lifecycle_key_fingerprint: str
    lifecycle_signature_verifier: SignatureVerifier
    feed_key_id: str
    feed_key_fingerprint: str
    feed_signature_verifier: SignatureVerifier
    report_key_id: str
    report_signature_verifier: SignatureVerifier
    guidance_key_id: str
    guidance_signature_verifier: SignatureVerifier
    enrichment_key_id: str
    enrichment_signature_verifier: SignatureVerifier

    def __post_init__(self) -> None:
        key_ids = (
            self.lifecycle_key_id,
            self.feed_key_id,
            self.report_key_id,
            self.guidance_key_id,
            self.enrichment_key_id,
        )
        if any(type(value) is not str or not value for value in key_ids):
            raise ValueError("notification v2 trust key IDs must be non-empty")
        if (
            type(self.lifecycle_key_vault_key_id) is not str
            or not self.lifecycle_key_vault_key_id
        ):
            raise ValueError(
                "notification v2 lifecycle Key Vault key ID must be non-empty"
            )
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("notification v2 trust domains must use distinct keys")


@dataclass(frozen=True, slots=True)
class NotificationV2SourceVerifier:
    reader: PresentationAssetReaderPort
    trust: NotificationV2Trust
    presentation_base_url: str

    def __post_init__(self) -> None:
        _incident_presentation_url(
            self.presentation_base_url,
            incident_id="inc-000000000000",
        )

    def build(
        self,
        *,
        incident_id: str,
        verified_at: datetime,
    ) -> IncidentNotificationV2:
        if type(verified_at) is not datetime:
            raise TypeError("verified_at must be a datetime")
        active_index = self._read_current_model(
            "incidents/active.json",
            MAX_INCIDENT_FEED_V2_BYTES,
            ActiveIncidentIndex,
        )
        active_attestation = self._read_current_model(
            active_index.index_attestation_path.removeprefix("./"),
            MAX_PRESENTATION_ATTESTATION_BYTES,
            ActiveIncidentIndexAttestation,
        )
        self._verify_active_index(active_index, active_attestation, verified_at=verified_at)

        try:
            feed_index = self._read_current_model(
                "incidents/feed-v2.json",
                MAX_INCIDENT_FEED_V2_BYTES,
                IncidentFeedIndexV2,
            )
            feed_attestation = self._read_current_model(
                feed_index.index_attestation_path.removeprefix("./"),
                MAX_PRESENTATION_ATTESTATION_BYTES,
                IncidentFeedIndexAttestationV2,
            )
        except PresentationAssetUnavailableError as exc:
            raise NotificationV2SourceNotReadyError(
                "incident feed v2 is not published yet"
            ) from exc
        active_index_digest = sha256_hex(active_index.canonical_bytes())
        validate_incident_feed_index_assets(
            feed_index,
            feed_attestation,
            trusted_key_id=self.trust.feed_key_id,
            trusted_key_fingerprint=self.trust.feed_key_fingerprint,
            expected_source_active_index_digest=feed_index.source_active_index_digest,
            not_older_than=feed_index.published_at,
            signature_verifier=self.trust.feed_signature_verifier,
        )
        if feed_index.published_at > verified_at + _MAX_CLOCK_SKEW:
            raise ValueError("incident feed v2 is from the future")
        if feed_index.source_active_index_digest != active_index_digest:
            raise NotificationV2SourceNotReadyError(
                "incident feed v2 has not caught up to current v1 authority"
            )
        if feed_index.published_at < verified_at - _MAX_FEED_AGE:
            raise ValueError("incident feed v2 is stale")
        entries = tuple(
            item
            for item in (*feed_index.active, *feed_index.recently_resolved)
            if item.incident_id == incident_id
        )
        if not entries:
            raise NotificationV2SourceNotReadyError(
                "incident is not available in the current verified feed v2"
            )
        if len(entries) != 1:
            raise ValueError("incident is not uniquely discoverable in verified feed v2")
        entry = entries[0]
        feed_pointer = self._read_version_model(
            entry.feed_pointer_reference,
            MAX_INCIDENT_FEED_V2_POINTER_BYTES,
            IncidentEnrichmentFeedPointer,
        )
        feed_pointer_attestation = self._read_version_model(
            entry.feed_pointer_attestation_reference,
            MAX_PRESENTATION_ATTESTATION_BYTES,
            IncidentEnrichmentFeedPointerAttestation,
        )
        validate_incident_enrichment_feed_pointer_assets(
            entry,
            feed_pointer,
            feed_pointer_attestation,
            trusted_key_id=self.trust.feed_key_id,
            signature_verifier=self.trust.feed_signature_verifier,
        )
        state, occurrence = self._verify_occurrence(
            feed_pointer,
            active_index=active_index,
        )
        manifest, guidance = self._verify_enrichment(feed_pointer, state=state)
        if (
            entry.lifecycle != state.lifecycle
            or entry.state_result_digest != state.result_digest
            or entry.updated_at != state.updated_at
            or feed_pointer.published_at > feed_index.published_at
            or guidance.generated_at < state.updated_at
        ):
            raise ValueError("notification source chronology or lifecycle is invalid")

        presentation_url = _incident_presentation_url(
            self.presentation_base_url,
            incident_id=state.incident_id,
        )
        message = render_teams_notification_v2(
            state,
            guidance,
            presentation_url=presentation_url,
        )
        payload: dict[str, object] = {
            "schemaVersion": "athena.wc027IncidentNotification.v2",
            "incidentId": state.incident_id,
            "transitionId": state.transition_id,
            "lifecycle": state.lifecycle,
            "stateResultDigest": state.result_digest,
            "occurrenceDigest": occurrence.occurrence_digest,
            "feedIndexDigest": sha256_hex(feed_index.canonical_bytes()),
            "feedPublishedAt": feed_index.published_at,
            "feedPointerReference": entry.feed_pointer_reference,
            "feedPointerAttestationReference": (
                entry.feed_pointer_attestation_reference
            ),
            "enrichmentAsset": feed_pointer.enrichment_asset,
            "guidanceAsset": manifest.guidance_asset,
            "presentationUrl": presentation_url,
            "message": message,
            "noAutoRemediation": True,
        }
        notification_digest = compute_artifact_digest(_json_value(payload))
        identity_digest = compute_artifact_digest(
            {
                "schemaVersion": "athena.wc027IncidentNotificationIdentity.v1",
                "incidentId": state.incident_id,
                "transitionId": state.transition_id,
                "lifecycle": state.lifecycle,
                "stateResultDigest": state.result_digest,
                "occurrenceDigest": occurrence.occurrence_digest,
                "guidanceAsset": _json_value(manifest.guidance_asset),
            }
        )
        return IncidentNotificationV2.model_validate(
            {
                **payload,
                "notificationId": (
                    f"notify-v2-{identity_digest.removeprefix('sha256:')}"
                ),
                "notificationDigest": notification_digest,
            }
        )

    def verify_current(
        self,
        notification: IncidentNotificationV2,
        *,
        verified_at: datetime,
    ) -> None:
        expected = self.build(
            incident_id=notification.incident_id,
            verified_at=verified_at,
        )
        if (
            expected.notification_id != notification.notification_id
            or expected.incident_id != notification.incident_id
            or expected.transition_id != notification.transition_id
            or expected.lifecycle != notification.lifecycle
            or expected.state_result_digest != notification.state_result_digest
            or expected.occurrence_digest != notification.occurrence_digest
            or expected.feed_pointer_reference != notification.feed_pointer_reference
            or expected.feed_pointer_attestation_reference
            != notification.feed_pointer_attestation_reference
            or expected.enrichment_asset != notification.enrichment_asset
            or expected.guidance_asset != notification.guidance_asset
            or expected.presentation_url != notification.presentation_url
            or expected.message != notification.message
        ):
            raise ValueError(
                "notification v2 no longer matches the current verified lifecycle"
            )

    def _verify_active_index(
        self,
        index: ActiveIncidentIndex,
        attestation: ActiveIncidentIndexAttestation,
        *,
        verified_at: datetime,
    ) -> None:
        payload = index.canonical_bytes()
        if (
            index.key_id != self.trust.lifecycle_key_id
            or index.key_fingerprint != self.trust.lifecycle_key_fingerprint
            or index.published_at < verified_at - _MAX_FEED_AGE
            or index.published_at > verified_at + _MAX_CLOCK_SKEW
            or attestation.index_digest != sha256_hex(payload)
            or attestation.key_vault_key_id
            != self.trust.lifecycle_key_vault_key_id
            or self.trust.lifecycle_signature_verifier(
                payload,
                attestation.detached_signature,
            )
            is not True
        ):
            raise ValueError("active incident authority is stale or untrusted")

    def _verify_occurrence(
        self,
        feed_pointer: IncidentEnrichmentFeedPointer,
        *,
        active_index: ActiveIncidentIndex,
    ) -> tuple[IncidentState, IncidentOccurrenceReceipt]:
        state = self._read_version_model(
            feed_pointer.source_state_reference,
            MAX_INCIDENT_STATE_BYTES,
            IncidentState,
        )
        state_attestation = self._read_version_model(
            feed_pointer.source_state_attestation_reference,
            MAX_PRESENTATION_ATTESTATION_BYTES,
            IncidentStateAttestation,
        )
        pointer = self._read_version_model(
            feed_pointer.source_pointer_reference,
            MAX_INCIDENT_FEED_POINTER_BYTES,
            IncidentFeedPointer,
        )
        pointer_attestation = self._read_version_model(
            feed_pointer.source_pointer_attestation_reference,
            MAX_PRESENTATION_ATTESTATION_BYTES,
            IncidentFeedAttestation,
        )
        occurrence = build_incident_occurrence_receipt(
            state,
            state_attestation,
            pointer,
            pointer_attestation,
            state_reference=feed_pointer.source_state_reference,
            state_attestation_reference=(
                feed_pointer.source_state_attestation_reference
            ),
            pointer_reference=feed_pointer.source_pointer_reference,
            pointer_attestation_reference=(
                feed_pointer.source_pointer_attestation_reference
            ),
        )
        active_entry = next(
            (
                item
                for item in active_index.incidents
                if item.incident_id == state.incident_id
            ),
            None,
        )
        if (
            occurrence.occurrence_digest != feed_pointer.occurrence_digest
            or state.result_digest != feed_pointer.state_result_digest
            or state.lifecycle != feed_pointer.lifecycle
            or state_attestation.key_vault_key_id
            != self.trust.lifecycle_key_vault_key_id
            or pointer.key_id != self.trust.lifecycle_key_id
            or pointer.key_fingerprint != self.trust.lifecycle_key_fingerprint
            or pointer_attestation.key_vault_key_id
            != self.trust.lifecycle_key_vault_key_id
            or self.trust.lifecycle_signature_verifier(
                incident_state_signature_preimage(state),
                state_attestation.detached_signature,
            )
            is not True
            or self.trust.lifecycle_signature_verifier(
                incident_pointer_signature_preimage(pointer),
                pointer_attestation.detached_signature,
            )
            is not True
        ):
            raise ValueError("notification occurrence is stale, tampered, or untrusted")
        if state.lifecycle == "active":
            if (
                active_entry is None
                or active_entry.pointer_path
                != f"./{feed_pointer.source_pointer_reference.name}"
                or active_entry.pointer_sha256
                != feed_pointer.source_pointer_reference.content_digest
                or active_entry.updated_at != state.updated_at
            ):
                raise ValueError("active notification is not v1-authority coherent")
        elif active_entry is not None:
            raise ValueError("resolved notification remains active in v1 authority")
        return state, occurrence

    def _verify_enrichment(
        self,
        feed_pointer: IncidentEnrichmentFeedPointer,
        *,
        state: IncidentState,
    ) -> tuple[IncidentEnrichmentManifest, IncidentGuidance]:
        enrichment = feed_pointer.enrichment_asset
        manifest = self._read_version_model(
            enrichment.manifest_reference,
            MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES,
            IncidentEnrichmentManifest,
        )
        enrichment_attestation = self._read_version_model(
            enrichment.attestation_reference,
            MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
            IncidentEnrichmentAttestation,
        )
        validate_incident_enrichment_assets(
            enrichment,
            manifest,
            enrichment_attestation,
            trusted_enrichment_key_id=self.trust.enrichment_key_id,
            enrichment_signature_verifier=self.trust.enrichment_signature_verifier,
        )
        guidance_asset = manifest.guidance_asset
        guidance = self._read_version_model(
            guidance_asset.guidance_reference,
            MAX_INCIDENT_GUIDANCE_BYTES,
            IncidentGuidance,
        )
        guidance_attestation = self._read_version_model(
            guidance_asset.attestation_reference,
            MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
            IncidentGuidanceAttestation,
        )
        validate_incident_guidance_assets(
            guidance_asset,
            guidance,
            guidance_attestation,
            trusted_guidance_key_id=self.trust.guidance_key_id,
            guidance_signature_verifier=self.trust.guidance_signature_verifier,
        )
        report_asset = manifest.correlation_report_asset
        report = self._read_version_model(
            report_asset.report_reference,
            MAX_PUBLISHED_CORRELATION_REPORT_BYTES,
            CorrelationReport,
        )
        report_attestation = self._read_version_model(
            report_asset.attestation_reference,
            MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
            PublishedCorrelationReportAttestation,
        )
        statement = report_attestation.statement
        if (
            manifest.incident_state_reference
            != feed_pointer.source_state_reference
            or manifest.incident_state_attestation_reference
            != feed_pointer.source_state_attestation_reference
            or manifest.incident_transition_id != state.transition_id
            or statement.incident_state_reference
            != feed_pointer.source_state_reference
            or statement.incident_state_attestation_reference
            != feed_pointer.source_state_attestation_reference
            or statement.incident_transition_id != state.transition_id
            or report_asset.report_content_digest != sha256_hex(report.canonical_bytes())
            or report_asset.attestation_reference.content_digest
            != sha256_hex(report_attestation.canonical_bytes())
            or report_attestation.key_vault_key_id != self.trust.report_key_id
            or report_attestation.signed_preimage_digest
            != sha256_hex(statement.canonical_bytes())
            or self.trust.report_signature_verifier(
                statement.canonical_bytes(),
                report_attestation.detached_signature,
            )
            is not True
            or report_asset.publication_statement_id != statement.statement_id
            or report_asset.publication_statement_digest
            != statement.statement_digest
            or report_asset.report_id != report.report_id
            or report_asset.report_digest != report.report_digest
            or report_asset.incident_id != statement.incident_id
            or report_asset.incident_transition_id
            != statement.incident_transition_id
            or report_asset.incident_revision != statement.incident_revision
            or report_asset.incident_state_result_digest
            != statement.incident_state_result_digest
            or report_asset.incident_subject_id != statement.incident_subject_id
            or report_asset.incident_subject_digest
            != statement.incident_subject_digest
            or report_asset.incident_bound_request_id
            != statement.incident_bound_request_id
            or report_asset.incident_bound_request_digest
            != statement.incident_bound_request_digest
            or report_asset.correlation_request_digest
            != statement.correlation_request_digest
            or report_asset.correlation_transition_digest
            != statement.correlation_transition_digest
            or report_asset.authority_proof_digest
            != statement.authority_proof_digest
            or statement.report_id != report.report_id
            or statement.report_digest != report.report_digest
            or statement.incident_id != manifest.incident_id
            or statement.incident_revision != manifest.incident_revision
            or statement.incident_state_result_digest
            != manifest.incident_state_result_digest
            or guidance.source_binding.incident_id != manifest.incident_id
            or guidance.source_binding.incident_revision
            != manifest.incident_revision
            or guidance.source_binding.incident_state_digest
            != manifest.incident_state_result_digest
            or guidance.source_binding.correlation_report_id != report.report_id
            or guidance.source_binding.correlation_report_digest
            != report.report_digest
            or manifest.guidance_asset != guidance_asset
        ):
            raise ValueError("notification enrichment, report, or guidance is untrusted")
        return manifest, guidance

    def _read_current_model[
        ModelT: BaseModel
    ](
        self,
        name: str,
        maximum_bytes: int,
        model_type: type[ModelT],
    ) -> ModelT:
        result = self.reader.read_current(
            blob_name=name,
            maximum_bytes=maximum_bytes,
        )
        value = model_type.model_validate_json(result.payload)
        if (
            result.blob_name != name
            or result.payload_sha256 != sha256_hex(result.payload)
            or cast(_CanonicalBytesModel, value).canonical_bytes() != result.payload
        ):
            raise ValueError("current notification source asset is not canonical")
        return value

    def _read_version_model[
        ModelT: BaseModel
    ](
        self,
        reference: object,
        maximum_bytes: int,
        model_type: type[ModelT],
    ) -> ModelT:
        from athena_context.contracts import VersionPinnedBlobReference

        if not isinstance(reference, VersionPinnedBlobReference):
            raise TypeError("notification source reference is invalid")
        result = self.reader.read_version(
            blob_name=reference.name,
            version_id=reference.version,
            expected_payload_sha256=reference.content_digest,
            maximum_bytes=maximum_bytes,
        )
        value = model_type.model_validate_json(result.payload)
        if (
            result.blob_name != reference.name
            or result.payload_sha256 != reference.content_digest
            or sha256_hex(result.payload) != reference.content_digest
            or cast(_CanonicalBytesModel, value).canonical_bytes() != result.payload
        ):
            raise ValueError("version-pinned notification source asset is invalid")
        return value


@dataclass(frozen=True, slots=True)
class NotificationV2PublicationService(NotificationV2SourceVerifier):
    notification_key_id: str
    notification_signer: PresentationSigner
    notification_signature_verifier: SignatureVerifier
    outbox: NotificationV2OutboxPort

    def __post_init__(self) -> None:
        super().__post_init__()
        source_key_ids = (
            self.trust.lifecycle_key_id,
            self.trust.feed_key_id,
            self.trust.report_key_id,
            self.trust.guidance_key_id,
            self.trust.enrichment_key_id,
        )
        if (
            not self.notification_key_id
            or self.notification_key_id in source_key_ids
        ):
            raise ValueError(
                "notification v2 signing authority must be distinct from source authorities"
            )

    def publish(
        self,
        *,
        incident_id: str,
        verified_at: datetime,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> IncidentNotificationEnvelopeV2:
        notification = self.build(
            incident_id=incident_id,
            verified_at=verified_at,
        )
        notification_bytes = notification.canonical_bytes()
        signature = _base64url_signature(
            self.notification_signer.sign_preimage(notification_bytes)
        )
        if self.notification_signature_verifier(notification_bytes, signature) is not True:
            raise ValueError("notification v2 signer failed immediate verification")
        envelope = IncidentNotificationEnvelopeV2(
            schemaVersion="athena.wc027IncidentNotificationEnvelope.v2",
            notification=notification,
            attestation=IncidentNotificationV2Attestation(
                schemaVersion="athena.wc027IncidentNotificationAttestation.v2",
                notificationId=notification.notification_id,
                notificationDigest=notification.notification_digest,
                signatureAlgorithm="RS256",
                keyVaultKeyId=self.notification_key_id,
                signedPreimageDigest=sha256_hex(notification_bytes),
                detachedSignature=signature,
            ),
        )
        if before_irreversible_write is not None:
            before_irreversible_write()
        self.outbox.enqueue_v2(envelope)
        return envelope


def render_teams_notification_v2(
    state: IncidentState,
    guidance: IncidentGuidance,
    *,
    presentation_url: str,
) -> str:
    if state.lifecycle not in {"active", "resolved"}:
        raise ValueError("notification v2 requires an active or resolved occurrence")
    if (
        guidance.source_binding.incident_id != state.incident_id
        or guidance.source_binding.incident_state_digest != state.result_digest
    ):
        raise ValueError("notification guidance does not bind the incident occurrence")
    status = state.lifecycle.upper()
    hypothesis = guidance.hypotheses[0]
    impact = guidance.affected_role_impact
    return (
        f"Athena incident {status}: {state.scenario}\n"
        f"Role/impact: {impact.role_ref} · {impact.impact_severity}\n"
        f"Leading hypothesis: {hypothesis.category} ({hypothesis.confidence})\n"
        f"Review verified guidance: {presentation_url}\n\n"
        "Athena did not perform remediation.\n\n"
        "Sent by Kanga, my AI sidekick 🦘"
    )


def verify_notification_v2_envelope(
    envelope: IncidentNotificationEnvelopeV2,
    *,
    trusted_key_id: str,
    signature_verifier: SignatureVerifier,
) -> IncidentNotificationV2:
    envelope = IncidentNotificationEnvelopeV2.model_validate_json(
        envelope.model_dump_json(by_alias=True)
    )
    notification = envelope.notification
    if (
        envelope.attestation.key_vault_key_id != trusted_key_id
        or signature_verifier(
            notification.canonical_bytes(),
            envelope.attestation.detached_signature,
        )
        is not True
    ):
        raise ValueError("notification v2 envelope signature is untrusted")
    return notification


def _incident_presentation_url(base_url: str, *, incident_id: str) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("presentation base URL is invalid")
    path = parsed.path.rstrip("/") + "/"
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            path,
            "",
            f"incident-{incident_id}",
        )
    )


def _base64url_signature(value: str) -> str:
    try:
        signature = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("notification signer returned invalid base64") from exc
    if not signature:
        raise ValueError("notification signer returned an empty signature")
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _json_value(item)
            for key, item in value.items()
            if item is not None
        }
    return value


__all__ = [
    "NotificationV2OutboxPort",
    "NotificationV2PublicationService",
    "NotificationV2SourceNotReadyError",
    "NotificationV2SourceVerifier",
    "NotificationV2Trust",
    "render_teams_notification_v2",
    "verify_notification_v2_envelope",
]
