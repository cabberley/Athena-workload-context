from __future__ import annotations

import base64
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ValidationError

from athena_context.contracts import (
    IncidentEnrichmentFeedPointer,
    IncidentNotificationEnvelopeV2,
    IncidentNotificationV2,
    compute_artifact_digest,
)
from athena_context.eventing.notification_v2 import (
    NotificationV2PublicationService,
    NotificationV2Trust,
    render_teams_notification_v2,
)
from athena_context.eventing.runtime import (
    AzureServiceBusNotificationOutbox,
    _dispatch_notification_message,
    _validate_notification_broker_metadata,
)
from test_presentation_asset_gateway import _feed_v2_gateway_fixture
from test_wc016_eventing import (
    _NotificationReceiver,
    _NotificationResponse,
    _NotificationStore,
)


class _Signer:
    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self.private_key = private_key

    def sign_preimage(self, canonical_preimage: bytes) -> str:
        signature = self.private_key.sign(
            canonical_preimage,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("ascii")


class _Outbox:
    def __init__(self) -> None:
        self.envelopes: list[IncidentNotificationEnvelopeV2] = []

    def enqueue_v2(self, envelope: IncidentNotificationEnvelopeV2) -> None:
        self.envelopes.append(envelope)


def _verifier(public_key: rsa.RSAPublicKey):
    def verify(payload: bytes, signature: str) -> bool:
        padding_length = (-len(signature)) % 4
        try:
            decoded = base64.urlsafe_b64decode(signature + "=" * padding_length)
            public_key.verify(
                decoded,
                payload,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except (InvalidSignature, ValueError):
            return False
        return True

    return verify


def _service():
    fixture = _feed_v2_gateway_fixture()
    outbox = _Outbox()
    feed_trust = fixture["feed_trust"]
    report_trust = fixture["app"]._incident_report_trust
    assert report_trust is not None
    service = NotificationV2PublicationService(
        reader=fixture["reader"],
        trust=NotificationV2Trust(
            lifecycle_key_id=fixture["lifecycle_trust"].key_id,
            lifecycle_key_fingerprint=(
                fixture["lifecycle_trust"].key_fingerprint
            ),
            lifecycle_signature_verifier=_verifier(
                fixture["lifecycle_trust"].public_key
            ),
            feed_key_id=feed_trust.key_id,
            feed_key_fingerprint=feed_trust.key_fingerprint,
            feed_signature_verifier=_verifier(feed_trust.public_key),
            report_key_id=report_trust.key_id,
            report_signature_verifier=_verifier(report_trust.public_key),
            guidance_key_id=fixture["guidance_trust"].key_id,
            guidance_signature_verifier=_verifier(
                fixture["guidance_trust"].public_key
            ),
            enrichment_key_id=fixture["enrichment_trust"].key_id,
            enrichment_signature_verifier=_verifier(
                fixture["enrichment_trust"].public_key
            ),
        ),
        notification_key_id=feed_trust.key_id,
        notification_signer=_Signer(fixture["feed_private"]),
        notification_signature_verifier=_verifier(feed_trust.public_key),
        presentation_base_url="https://athena.synthetic.example",
        outbox=outbox,
    )
    return fixture, service, outbox


def test_notification_v2_binds_verified_assets_and_incident_deep_link() -> None:
    fixture, service, outbox = _service()

    envelope = service.publish(
        incident_id=fixture["state"].incident_id,
        verified_at=fixture["feed_index"].published_at,
    )

    notification = envelope.notification
    assert outbox.envelopes == [envelope]
    assert notification.lifecycle == "active"
    assert notification.presentation_url == (
        "https://athena.synthetic.example/#incident-"
        + fixture["state"].incident_id
    )
    pointer_reference = fixture["feed_entry"].feed_pointer_reference
    pointer = IncidentEnrichmentFeedPointer.model_validate_json(
        fixture["reader"].versioned_content[
            (pointer_reference.name, pointer_reference.version)
        ]
    )
    assert notification.enrichment_asset == pointer.enrichment_asset
    assert "Leading hypothesis:" in notification.message
    assert "Athena did not perform remediation." in notification.message
    assert len(notification.message) < 512


@pytest.mark.parametrize(
    "asset",
    ["occurrence", "guidance", "manifest", "feed-pointer"],
)
def test_notification_v2_fails_closed_for_tampered_versioned_assets(
    asset: str,
) -> None:
    fixture, service, _outbox = _service()
    reader = fixture["reader"]
    entry = fixture["feed_entry"]
    guidance_reference = fixture["guidance_reference"].guidance_reference
    state_reference = fixture["state_reference"]
    feed_pointer_reference = entry.feed_pointer_reference
    feed_pointer = reader.versioned_content[
        (feed_pointer_reference.name, feed_pointer_reference.version)
    ]
    if asset == "occurrence":
        reference = state_reference
    elif asset == "guidance":
        reference = guidance_reference
    elif asset == "manifest":
        parsed_pointer = IncidentEnrichmentFeedPointer.model_validate_json(
            feed_pointer
        )
        reference = parsed_pointer.enrichment_asset.manifest_reference
    else:
        reference = feed_pointer_reference
    reader.versioned_content[(reference.name, reference.version)] = (
        feed_pointer[:-1] + b" "
        if asset == "feed-pointer"
        else b'{"tampered":true}\n'
    )

    with pytest.raises((RuntimeError, ValidationError, ValueError)):
        service.publish(
            incident_id=fixture["state"].incident_id,
            verified_at=fixture["feed_index"].published_at,
        )


def test_notification_v2_rejects_stale_or_untrusted_feed() -> None:
    fixture, service, _outbox = _service()

    with pytest.raises(ValueError, match="stale|match"):
        service.publish(
            incident_id=fixture["state"].incident_id,
            verified_at=fixture["feed_index"].published_at + timedelta(minutes=16),
        )

    service = replace(
        service,
        trust=replace(
            service.trust,
            feed_signature_verifier=lambda _payload, _signature: False,
        ),
    )
    with pytest.raises(ValueError, match="feed v2 index assets"):
        service.publish(
            incident_id=fixture["state"].incident_id,
            verified_at=fixture["feed_index"].published_at,
        )


def test_notification_v2_rejects_resolved_entry_still_active_in_v1() -> None:
    fixture, service, _outbox = _service()
    entry = fixture["feed_index"].active[0].model_copy(update={"lifecycle": "resolved"})
    feed_index = fixture["feed_index"].model_copy(
        update={"active": (), "recently_resolved": (entry,)}
    )
    fixture["reader"].content["incidents/feed-v2.json"] = feed_index.canonical_bytes()

    with pytest.raises((ValidationError, ValueError)):
        service.publish(
            incident_id=fixture["state"].incident_id,
            verified_at=fixture["feed_index"].published_at,
        )


def test_notification_v2_deep_link_is_digest_bound() -> None:
    fixture, service, _outbox = _service()
    envelope = service.publish(
        incident_id=fixture["state"].incident_id,
        verified_at=fixture["feed_index"].published_at,
    )
    values = envelope.notification.model_dump(mode="json", by_alias=True)
    values["presentationUrl"] = "https://athena.synthetic.example/#incident-inc-ffffffffffff"
    values["notificationDigest"] = compute_artifact_digest(
        {
            key: value
            for key, value in values.items()
            if key not in {"notificationId", "notificationDigest"}
        }
    )
    values["notificationId"] = (
        "notify-v2-" + values["notificationDigest"].removeprefix("sha256:")
    )
    with pytest.raises(ValidationError, match="one incident presentation"):
        IncidentNotificationV2.model_validate(values)


def test_notification_v2_outbox_preserves_order_and_dispatch_is_idempotent() -> None:
    fixture, service, _outbox = _service()
    envelope = service.publish(
        incident_id=fixture["state"].incident_id,
        verified_at=fixture["feed_index"].published_at,
    )

    class _Message:
        def __init__(self, body: bytes, **kwargs: object) -> None:
            self._body = body
            self.body = body
            for key, value in kwargs.items():
                setattr(self, key, value)

        def __bytes__(self) -> bytes:
            return self._body

    class _Sender:
        def __init__(self) -> None:
            self.messages: list[object] = []

        def send_messages(self, message: object) -> None:
            self.messages.append(message)

    sender = _Sender()
    outbox = AzureServiceBusNotificationOutbox(sender, message_factory=_Message)
    outbox.enqueue_v2(envelope)
    outbox.enqueue_v2(envelope)
    first, replay = sender.messages
    assert first.session_id == replay.session_id == fixture["state"].incident_id
    assert first.message_id == replay.message_id == envelope.notification.notification_id
    _validate_notification_broker_metadata(first, envelope.notification)

    store = _NotificationStore()
    first_receiver = _NotificationReceiver()
    replay_receiver = _NotificationReceiver()
    verifier = _verifier(fixture["feed_trust"].public_key)
    arguments = {
        "credential": SimpleNamespace(
            get_token=lambda _scope: SimpleNamespace(token="synthetic-token")
        ),
        "webhook_url": (
            "https://example.logic.azure.com/workflows/synthetic/triggers/manual/"
            "paths/invoke?api-version=2019-05-01"
        ),
        "delivery_store": store,
        "trusted_notification_v2_key_id": fixture["feed_trust"].key_id,
        "notification_v2_signature_verifier": verifier,
    }
    with patch(
        "athena_context.eventing.runtime.urlopen",
        return_value=_NotificationResponse(),
    ) as request:
        assert _dispatch_notification_message(
            message=first,
            receiver=first_receiver,
            **arguments,
        )
        assert _dispatch_notification_message(
            message=replay,
            receiver=replay_receiver,
            **arguments,
        )

    assert request.call_count == 1
    assert first_receiver.completed == 1
    assert replay_receiver.completed == 1
    assert store.state == "delivered"


def test_transient_server_failure_resets_delivery_for_retry() -> None:
    fixture, service, _outbox = _service()
    envelope = service.publish(
        incident_id=fixture["state"].incident_id,
        verified_at=fixture["feed_index"].published_at,
    )
    message = SimpleNamespace(
        body=envelope.canonical_bytes(),
        content_type="application/json",
        message_id=envelope.notification.notification_id,
        session_id=envelope.notification.incident_id,
        application_properties={
            "schemaVersion": "athena.wc027IncidentNotificationEnvelope.v2",
            "lifecycle": envelope.notification.lifecycle,
            "transitionId": envelope.notification.transition_id,
            "stateResultDigest": envelope.notification.state_result_digest,
        },
    )
    receiver = _NotificationReceiver()
    store = _NotificationStore()

    from urllib.error import HTTPError

    with patch(
        "athena_context.eventing.runtime.urlopen",
        side_effect=HTTPError(
            url="https://example.logic.azure.com",
            code=503,
            msg="synthetic unavailable",
            hdrs=None,
            fp=None,
        ),
    ):
        assert not _dispatch_notification_message(
            message=message,
            receiver=receiver,
            credential=SimpleNamespace(
                get_token=lambda _scope: SimpleNamespace(token="synthetic-token")
            ),
            webhook_url=(
                "https://example.logic.azure.com/workflows/synthetic/triggers/manual/"
                "paths/invoke?api-version=2019-05-01"
            ),
            delivery_store=store,
            trusted_notification_v2_key_id=fixture["feed_trust"].key_id,
            notification_v2_signature_verifier=_verifier(
                fixture["feed_trust"].public_key
            ),
        )

    assert store.state == "reserved"
    assert receiver.abandoned == 1
    assert receiver.dead_letter_reasons == []


def test_resolved_teams_rendering_remains_non_remediating() -> None:
    fixture, service, _outbox = _service()
    envelope = service.publish(
        incident_id=fixture["state"].incident_id,
        verified_at=fixture["feed_index"].published_at,
    )
    state = fixture["state"].model_copy(update={"lifecycle": "resolved"})
    guidance = fixture["guidance"].model_copy(
        update={
            "source_binding": fixture["guidance"].source_binding.model_copy(
                update={"incident_state_digest": state.result_digest}
            )
        }
    )

    message = render_teams_notification_v2(
        state,
        guidance,
        presentation_url=envelope.notification.presentation_url,
    )

    assert "incident RESOLVED" in message
    assert "did not perform remediation" in message
    assert "Review verified guidance:" in message
