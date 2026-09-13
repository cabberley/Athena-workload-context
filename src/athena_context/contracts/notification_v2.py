from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, model_validator

from athena_context.contracts.common import (
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.guidance import IncidentGuidanceAssetReference
from athena_context.contracts.incident_enrichment import (
    IncidentEnrichmentAssetReference,
)
from athena_context.contracts.models import AthenaBaseModel, Sha256Digest, UtcDateTime
from athena_context.contracts.operational_phase import VersionPinnedBlobReference

MAX_INCIDENT_NOTIFICATION_V2_BYTES = 16 * 1024


def _notification_identity_digest(notification: IncidentNotificationV2) -> Sha256Digest:
    return compute_artifact_digest(
        {
            "schemaVersion": "athena.wc027IncidentNotificationIdentity.v1",
            "incidentId": notification.incident_id,
            "transitionId": notification.transition_id,
            "lifecycle": notification.lifecycle,
            "stateResultDigest": notification.state_result_digest,
            "occurrenceDigest": notification.occurrence_digest,
            "guidanceAsset": notification.guidance_asset.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
        }
    )


class _StrictNotificationV2Model(AthenaBaseModel):
    model_config = ConfigDict(
        alias_generator=None,
        populate_by_name=True,
        extra="forbid",
        frozen=True,
        strict=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


class IncidentNotificationV2(_StrictNotificationV2Model):
    schema_version: Literal["athena.wc027IncidentNotification.v2"] = Field(
        alias="schemaVersion"
    )
    notification_id: str = Field(
        alias="notificationId",
        pattern=r"^notify-v2-[a-f0-9]{64}$",
    )
    incident_id: str = Field(alias="incidentId", pattern=r"^inc-[a-f0-9]{12}$")
    transition_id: str = Field(
        alias="transitionId",
        pattern=r"^wc016-[a-f0-9]{64}$",
    )
    lifecycle: Literal["active", "resolved"]
    state_result_digest: Sha256Digest = Field(alias="stateResultDigest")
    occurrence_digest: Sha256Digest = Field(alias="occurrenceDigest")
    feed_index_digest: Sha256Digest = Field(alias="feedIndexDigest")
    feed_published_at: UtcDateTime = Field(alias="feedPublishedAt")
    feed_pointer_reference: VersionPinnedBlobReference = Field(
        alias="feedPointerReference"
    )
    feed_pointer_attestation_reference: VersionPinnedBlobReference = Field(
        alias="feedPointerAttestationReference"
    )
    enrichment_asset: IncidentEnrichmentAssetReference = Field(alias="enrichmentAsset")
    guidance_asset: IncidentGuidanceAssetReference = Field(alias="guidanceAsset")
    presentation_url: str = Field(alias="presentationUrl", min_length=1, max_length=2048)
    message: str = Field(min_length=1, max_length=2048)
    no_auto_remediation: Literal[True] = Field(
        default=True,
        alias="noAutoRemediation",
    )
    notification_digest: Sha256Digest = Field(alias="notificationDigest")

    @model_validator(mode="after")
    def validate_notification(self) -> IncidentNotificationV2:
        parsed_url = urlsplit(self.presentation_url)
        expected_fragment = f"incident-{self.incident_id}"
        if (
            parsed_url.scheme != "https"
            or parsed_url.hostname is None
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment != expected_fragment
            or self.enrichment_asset.incident_id != self.incident_id
            or self.enrichment_asset.incident_state_result_digest
            != self.state_result_digest
            or self.guidance_asset.incident_id != self.incident_id
            or self.guidance_asset.incident_state_digest != self.state_result_digest
            or self.enrichment_asset.manifest_reference.name.removesuffix(
                "/manifest.json"
            )
            != self.feed_pointer_reference.name.removesuffix("/feed-pointer.json")
        ):
            raise ValueError("notification v2 does not bind one incident presentation")
        preimage = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"notification_id", "notification_digest"},
        )
        expected = compute_artifact_digest(preimage)
        if self.notification_digest != expected:
            raise ValueError("notificationDigest does not bind notification v2")
        identity_digest = _notification_identity_digest(self)
        if self.notification_id != (
            f"notify-v2-{identity_digest.removeprefix('sha256:')}"
        ):
            raise ValueError("notificationId is not occurrence and guidance bound")
        if len(self.canonical_bytes()) > MAX_INCIDENT_NOTIFICATION_V2_BYTES:
            raise ValueError("notification v2 exceeds its byte budget")
        return self


class IncidentNotificationV2Attestation(_StrictNotificationV2Model):
    schema_version: Literal["athena.wc027IncidentNotificationAttestation.v2"] = Field(
        alias="schemaVersion"
    )
    notification_id: str = Field(
        alias="notificationId",
        pattern=r"^notify-v2-[a-f0-9]{64}$",
    )
    notification_digest: Sha256Digest = Field(alias="notificationDigest")
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(alias="keyVaultKeyId", min_length=1, max_length=512)
    signed_preimage_digest: Sha256Digest = Field(alias="signedPreimageDigest")
    detached_signature: str = Field(
        alias="detachedSignature",
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=1,
        max_length=8192,
    )


class IncidentNotificationEnvelopeV2(_StrictNotificationV2Model):
    schema_version: Literal["athena.wc027IncidentNotificationEnvelope.v2"] = Field(
        alias="schemaVersion"
    )
    notification: IncidentNotificationV2
    attestation: IncidentNotificationV2Attestation

    @model_validator(mode="after")
    def validate_envelope(self) -> IncidentNotificationEnvelopeV2:
        if (
            self.attestation.notification_id != self.notification.notification_id
            or self.attestation.notification_digest
            != self.notification.notification_digest
            or self.attestation.signed_preimage_digest
            != sha256_hex(self.notification.canonical_bytes())
        ):
            raise ValueError("notification v2 attestation does not bind its payload")
        if len(self.canonical_bytes()) > MAX_INCIDENT_NOTIFICATION_V2_BYTES:
            raise ValueError("notification v2 envelope exceeds its byte budget")
        return self


__all__ = [
    "MAX_INCIDENT_NOTIFICATION_V2_BYTES",
    "IncidentNotificationEnvelopeV2",
    "IncidentNotificationV2",
    "IncidentNotificationV2Attestation",
]
