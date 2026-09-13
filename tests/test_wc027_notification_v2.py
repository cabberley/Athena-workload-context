from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ValidationError

from athena_context.contracts import (
    ActiveIncidentIndex,
    ActiveIncidentIndexAttestation,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentManifest,
    IncidentFeedIndexAttestationV2,
    IncidentNotificationEnvelopeV2,
    IncidentNotificationV2,
    build_incident_feed_index_v2,
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.eventing.notification_v2 import (
    NotificationV2PublicationService,
    NotificationV2SourceNotReadyError,
    NotificationV2SourceVerifier,
    NotificationV2Trust,
    render_teams_notification_v2,
)
from athena_context.eventing.runtime import (
    AzureServiceBusNotificationOutbox,
    _dispatch_notification_message,
    _validate_notification_broker_metadata,
    run_incident_orchestrator_worker,
    run_notification_dispatcher_worker,
)
from test_presentation_asset_gateway import _feed_v2_gateway_fixture
from test_wc016_eventing import (
    NOW,
    ROLES,
    _detector_request,
    _notification_message,
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


def _service(*, lifecycle_key_id: str | None = None):
    fixture = _feed_v2_gateway_fixture(lifecycle_key_id=lifecycle_key_id)
    outbox = _Outbox()
    notification_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    notification_public = notification_private.public_key()
    notification_key_id = "synthetic-key://notification"
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
        notification_key_id=notification_key_id,
        notification_signer=_Signer(notification_private),
        notification_signature_verifier=_verifier(notification_public),
        presentation_base_url="https://athena.synthetic.example",
        outbox=outbox,
    )
    fixture["notification_key_id"] = notification_key_id
    fixture["notification_public"] = notification_public
    return fixture, service, outbox


def _refresh_active_authority(
    fixture: dict[str, Any],
    *,
    published_at: datetime,
) -> ActiveIncidentIndex:
    active_index = ActiveIncidentIndex.model_validate_json(
        fixture["reader"].content["incidents/active.json"]
    )
    index_seed = canonicalize_json(
        {
            "incidents": [
                entry.model_dump(mode="json", by_alias=True)
                for entry in active_index.incidents
            ],
            "keyId": active_index.key_id,
            "keyFingerprint": active_index.key_fingerprint,
            "publishedAt": published_at,
        }
    )
    refreshed = ActiveIncidentIndex(
        schemaVersion="athena.activeIncidentIndex.v1",
        incidents=active_index.incidents,
        indexAttestationPath=(
            "./incidents/index-attestations/"
            + sha256_hex(index_seed).removeprefix("sha256:")
            + ".json"
        ),
        keyId=active_index.key_id,
        keyFingerprint=active_index.key_fingerprint,
        publishedAt=published_at,
    )
    signature = _Signer(fixture["lifecycle_private"]).sign_preimage(
        refreshed.canonical_bytes()
    )
    signature = base64.urlsafe_b64encode(base64.b64decode(signature)).decode(
        "ascii"
    ).rstrip("=")
    attestation = ActiveIncidentIndexAttestation(
        schemaVersion="athena.activeIncidentIndexAttestation.v1",
        indexDigest=sha256_hex(refreshed.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=active_index.key_id,
        detachedSignature=signature,
    )
    fixture["reader"].content["incidents/active.json"] = refreshed.canonical_bytes()
    fixture["reader"].content[
        refreshed.index_attestation_path.removeprefix("./")
    ] = attestation.canonical_bytes()
    return refreshed


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


def test_notification_v2_trusts_existing_wc016_lifecycle_logical_key_id() -> None:
    lifecycle_key_id = (
        "synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1"
    )
    fixture, service, outbox = _service(lifecycle_key_id=lifecycle_key_id)

    envelope = service.publish(
        incident_id=fixture["state"].incident_id,
        verified_at=fixture["feed_index"].published_at,
    )

    assert fixture["lifecycle_trust"].key_id == lifecycle_key_id
    assert service.trust.lifecycle_key_id == lifecycle_key_id
    assert envelope.notification.incident_id == fixture["state"].incident_id
    assert outbox.envelopes == [envelope]


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
    verifier = _verifier(fixture["notification_public"])
    arguments = {
        "credential": SimpleNamespace(
            get_token=lambda _scope: SimpleNamespace(token="synthetic-token")
        ),
        "webhook_url": (
            "https://example.logic.azure.com/workflows/synthetic/triggers/manual/"
            "paths/invoke?api-version=2019-05-01"
        ),
        "delivery_store": store,
        "trusted_notification_v2_key_id": fixture["notification_key_id"],
        "notification_v2_signature_verifier": verifier,
        "notification_v2_source_verifier": service,
        "now": fixture["feed_index"].published_at,
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


def test_dispatcher_renews_the_session_lock_during_delivery() -> None:
    message = object()

    class _Context:
        def __init__(self, value: object) -> None:
            self.value = value

        def __enter__(self) -> object:
            return self.value

        def __exit__(self, *_args: object) -> None:
            return None

    class _Receiver:
        def __init__(self) -> None:
            self.session = object()

        def receive_messages(self, **_kwargs: object) -> list[object]:
            return [message]

    class _Client:
        def __init__(self, receiver: _Receiver) -> None:
            self.receiver = receiver

        def get_queue_receiver(self, **_kwargs: object) -> _Context:
            return _Context(self.receiver)

    class _LockRenewer(_Context):
        def __init__(self) -> None:
            super().__init__(self)
            self.registrations: list[tuple[object, object, int]] = []
            self.active = False
            self.closed = False

        def __enter__(self) -> _LockRenewer:
            self.active = True
            return self

        def __exit__(self, *_args: object) -> None:
            self.active = False
            self.closed = True

        def register(
            self,
            receiver: object,
            session: object,
            *,
            max_lock_renewal_duration: int,
        ) -> None:
            self.registrations.append(
                (receiver, session, max_lock_renewal_duration)
            )

    receiver = _Receiver()
    lock_renewer = _LockRenewer()

    def dispatch_while_locked(**_kwargs: object) -> bool:
        assert lock_renewer.active
        return True

    with (
        patch("azure.identity.ManagedIdentityCredential"),
        patch(
            "azure.servicebus.AutoLockRenewer",
            return_value=lock_renewer,
        ) as auto_lock_renewer,
        patch(
            "azure.servicebus.ServiceBusClient",
            return_value=_Context(_Client(receiver)),
        ),
        patch("athena_context.eventing.runtime.AzureTableNotificationDeliveryStore"),
        patch(
            "athena_context.eventing.runtime._dispatch_notification_message",
            side_effect=dispatch_while_locked,
        ) as dispatch,
    ):
        assert run_notification_dispatcher_worker(
            fully_qualified_namespace="synthetic.servicebus.windows.net",
            notification_queue_name="notifications",
            managed_identity_client_id="00000000-0000-0000-0000-000000000001",
            webhook_url=(
                "https://synthetic.logic.azure.com/workflows/test"
                "?api-version=2019-05-01"
            ),
            notification_state_table_endpoint=(
                "https://synthetic.table.core.windows.net"
            ),
            notification_state_table_name="NotificationState",
            notification_state_partition_key="synthetic",
        )

    assert lock_renewer.registrations == [(receiver, receiver.session, 300)]
    assert lock_renewer.closed
    auto_lock_renewer.assert_called_once_with(max_workers=1)
    dispatch.assert_called_once()


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
            trusted_notification_v2_key_id=fixture["notification_key_id"],
            notification_v2_signature_verifier=_verifier(
                fixture["notification_public"]
            ),
            notification_v2_source_verifier=service,
            now=fixture["feed_index"].published_at,
        )

    assert store.state == "reserved"
    assert receiver.abandoned == 1
    assert receiver.dead_letter_reasons == []


def test_v2_enabled_dispatch_rejects_unsigned_v1_without_delivery() -> None:
    _notification, message = _notification_message()
    receiver = _NotificationReceiver()
    store = _NotificationStore()

    with patch("athena_context.eventing.runtime.urlopen") as request:
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
            trusted_notification_v2_key_id="synthetic-key://notification",
            notification_v2_signature_verifier=lambda _payload, _signature: True,
            notification_v2_source_verifier=SimpleNamespace(
                verify_current=lambda _notification, verified_at: None
            ),
        )

    request.assert_not_called()
    assert receiver.dead_letter_reasons == ["AthenaNotificationRejected"]


def test_deployed_orchestrator_path_uses_v2_without_enqueuing_v1() -> None:
    request = _detector_request(next(iter(ROLES)), healthy=False)
    message = SimpleNamespace(
        body=request.canonical_bytes(),
        content_type="application/json",
        message_id=request.idempotency_key,
        session_id=request.incident_id,
        application_properties={
            "schemaVersion": "athena.incidentReassessmentRequest.v1",
            "scenario": request.scenario,
            "lifecycle": request.lifecycle,
        },
    )

    class _Context:
        def __init__(self, value: object) -> None:
            self.value = value

        def __enter__(self) -> object:
            return self.value

        def __exit__(self, *_args: object) -> None:
            return None

    class _Receiver:
        def __init__(self) -> None:
            self.completed = 0
            self.abandoned = 0
            self.session = object()

        def receive_messages(self, **_kwargs: object) -> list[object]:
            return [message]

        def complete_message(self, _message: object) -> None:
            self.completed += 1

        def abandon_message(self, _message: object) -> None:
            self.abandoned += 1

    class _LockRenewer(_Context):
        def __init__(self) -> None:
            super().__init__(self)
            self.registrations: list[tuple[object, object, int]] = []
            self.active = False

        def __enter__(self) -> _LockRenewer:
            self.active = True
            return self

        def __exit__(self, *_args: object) -> None:
            self.active = False

        def register(
            self,
            receiver: object,
            session: object,
            *,
            max_lock_renewal_duration: int,
        ) -> None:
            self.registrations.append(
                (receiver, session, max_lock_renewal_duration)
            )

    class _Client:
        def __init__(self, receiver: _Receiver) -> None:
            self.receiver = receiver
            self.sender = SimpleNamespace()

        def get_queue_receiver(self, **_kwargs: object) -> _Context:
            return _Context(self.receiver)

        def get_queue_sender(self, **_kwargs: object) -> _Context:
            return _Context(self.sender)

    receiver = _Receiver()
    client = _Client(receiver)
    lock_renewer = _LockRenewer()
    published: list[tuple[str, object]] = []
    publish_attempts = 0

    def publish(*, incident_id: str, verified_at: object) -> None:
        nonlocal publish_attempts
        assert lock_renewer.active
        publish_attempts += 1
        if publish_attempts == 1:
            raise NotificationV2SourceNotReadyError("synthetic feed lag")
        published.append((incident_id, verified_at))

    publication_service = SimpleNamespace(publish=publish)
    fixture, _service_instance, _outbox = _service()

    def reassess(*_args: object, **kwargs: object) -> tuple[object, object]:
        assert lock_renewer.active
        assert kwargs["notifications"] is None
        return fixture["state"], object()

    with (
        patch("azure.identity.ManagedIdentityCredential"),
        patch("azure.servicebus.AutoLockRenewer", return_value=lock_renewer),
        patch("azure.servicebus.ServiceBusClient", return_value=_Context(client)),
        patch("athena_context.eventing.runtime.KeyVaultRsaSigner"),
        patch("athena_context.eventing.runtime.AzureBlobIncidentAssetPublisher"),
        patch("athena_context.eventing.runtime.ApprovedLiveReassessmentAdapter"),
        patch(
            "athena_context.eventing.runtime.run_incident_reassessment",
            side_effect=reassess,
        ),
        patch("athena_context.eventing.runtime.sleep") as retry_wait,
        patch("athena_context.eventing.runtime._now_utc_millisecond", return_value=NOW),
    ):
        assert run_incident_orchestrator_worker(
            fully_qualified_namespace="synthetic.servicebus.windows.net",
            reassessment_queue_name="reassessment",
            notification_queue_name="notifications",
            managed_identity_client_id="00000000-0000-0000-0000-000000000001",
            approved_resource_roles=ROLES,
            blob_endpoint="https://synthetic.blob.core.windows.net",
            presentation_url="https://athena.synthetic.example",
            key_vault_key_id=(
                "https://synthetic.vault.azure.net/keys/lifecycle/"
                "0123456789abcdef0123456789abcdef"
            ),
            signing_key_id="synthetic-key://lifecycle",
            signing_key_fingerprint="sha256:" + "1" * 64,
            notification_v2_publication_service=publication_service,
        )

    assert receiver.completed == 1
    assert receiver.abandoned == 0
    assert lock_renewer.registrations == [(receiver, receiver.session, 300)]
    retry_wait.assert_called_once_with(30)
    assert published == [(fixture["state"].incident_id, NOW)]


def test_dispatch_rejects_stale_v2_before_reserving_or_posting() -> None:
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

    with patch("athena_context.eventing.runtime.urlopen") as request:
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
            trusted_notification_v2_key_id=fixture["notification_key_id"],
            notification_v2_signature_verifier=_verifier(
                fixture["notification_public"]
            ),
            notification_v2_source_verifier=service,
            now=fixture["feed_index"].published_at + timedelta(minutes=16),
        )

    request.assert_not_called()
    assert receiver.dead_letter_reasons == ["AthenaNotificationRejected"]
    assert store.state is None


def test_dispatch_revalidates_current_lifecycle_before_posting() -> None:
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
    source_verifier = SimpleNamespace(
        verify_current=lambda _notification, verified_at: (_ for _ in ()).throw(
            ValueError("notification no longer matches resolved current state")
        )
    )

    with patch("athena_context.eventing.runtime.urlopen") as request:
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
            trusted_notification_v2_key_id=fixture["notification_key_id"],
            notification_v2_signature_verifier=_verifier(
                fixture["notification_public"]
            ),
            notification_v2_source_verifier=source_verifier,
            now=fixture["feed_index"].published_at,
        )

    request.assert_not_called()
    assert receiver.dead_letter_reasons == ["AthenaNotificationRejected"]
    assert store.state is None


def test_dispatch_retries_when_feed_v2_has_not_caught_up() -> None:
    fixture, service, _outbox = _service()
    envelope = service.publish(
        incident_id=fixture["state"].incident_id,
        verified_at=fixture["feed_index"].published_at,
    )
    refreshed_active = _refresh_active_authority(
        fixture,
        published_at=fixture["feed_index"].published_at + timedelta(minutes=16),
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
    verification_attempts = 0

    def verify_current(*_args: object, **_kwargs: object) -> None:
        nonlocal verification_attempts
        verification_attempts += 1
        service.verify_current(*_args, **_kwargs)

    source_verifier = SimpleNamespace(verify_current=verify_current)

    with (
        patch("athena_context.eventing.runtime.urlopen") as request,
        patch("athena_context.eventing.runtime.sleep") as retry_wait,
    ):
        assert not _dispatch_notification_message(
            message=message,
            receiver=receiver,
            credential=SimpleNamespace(
                get_token=lambda _scope: SimpleNamespace(token="synthetic-token")
            ),
            webhook_url=(
                "https://synthetic.logic.azure.com/workflows/test"
                "?api-version=2019-05-01"
            ),
            delivery_store=store,
            trusted_notification_v2_key_id=service.notification_key_id,
            notification_v2_signature_verifier=(
                service.notification_signature_verifier
            ),
            notification_v2_source_verifier=source_verifier,
            now=refreshed_active.published_at,
        )

    request.assert_not_called()
    assert receiver.completed == 0
    assert receiver.abandoned == 1
    assert receiver.dead_letter_reasons == []
    assert store.state is None
    assert verification_attempts == 6
    assert retry_wait.call_count == 5


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


def test_notification_signing_authority_must_not_reuse_a_source_key() -> None:
    fixture = _feed_v2_gateway_fixture()
    feed_trust = fixture["feed_trust"]
    report_trust = fixture["app"]._incident_report_trust
    assert report_trust is not None

    with pytest.raises(ValueError, match="distinct from source authorities"):
        NotificationV2PublicationService(
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
            outbox=_Outbox(),
        )


def test_feed_refresh_keeps_stable_notification_identity() -> None:
    fixture, service, _outbox = _service()
    original = service.publish(
        incident_id=fixture["state"].incident_id,
        verified_at=fixture["feed_index"].published_at,
    )
    current = fixture["feed_index"]
    refreshed_at = current.published_at + timedelta(minutes=1)
    refreshed = build_incident_feed_index_v2(
        active=current.active,
        recently_resolved=current.recently_resolved,
        resolved_retention_start=current.resolved_retention_start,
        resolved_history_truncated=current.resolved_history_truncated,
        resolved_history_total_count=current.resolved_history_total_count,
        omitted_resolved_count=current.omitted_resolved_count,
        source_active_index_digest=current.source_active_index_digest,
        key_id=current.key_id,
        key_fingerprint=current.key_fingerprint,
        published_at=refreshed_at,
    )
    signature = _Signer(fixture["feed_private"]).sign_preimage(
        refreshed.canonical_bytes()
    )
    signature = base64.urlsafe_b64encode(base64.b64decode(signature)).decode(
        "ascii"
    ).rstrip("=")
    attestation = IncidentFeedIndexAttestationV2(
        schemaVersion="athena.wc027IncidentFeedIndexAttestation.v2",
        indexDigest=sha256_hex(refreshed.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=fixture["feed_trust"].key_id,
        detachedSignature=signature,
    )
    fixture["reader"].content["incidents/feed-v2.json"] = refreshed.canonical_bytes()
    fixture["reader"].content[
        refreshed.index_attestation_path.removeprefix("./")
    ] = attestation.canonical_bytes()

    service.verify_current(
        original.notification,
        verified_at=refreshed_at,
    )
    immutable_authority_substitutions = (
        {"lifecycle": "resolved"},
        {"occurrence_digest": "sha256:" + "0" * 64},
        {
            "guidance_asset": original.notification.guidance_asset.model_copy(
                update={"guidance_digest": "sha256:" + "0" * 64}
            )
        },
    )
    for substitution in immutable_authority_substitutions:
        with pytest.raises(ValueError, match="current verified lifecycle"):
            service.verify_current(
                original.notification.model_copy(update=substitution),
                verified_at=refreshed_at,
            )
    replay = service.publish(
        incident_id=fixture["state"].incident_id,
        verified_at=refreshed_at,
    )

    assert (
        replay.notification.notification_id
        == original.notification.notification_id
    )
    assert (
        replay.notification.notification_digest
        != original.notification.notification_digest
    )


def test_feed_lag_is_retryable_after_v1_authority_advances() -> None:
    fixture, service, _outbox = _service()
    current = fixture["feed_index"]
    refreshed_active = _refresh_active_authority(
        fixture,
        published_at=current.published_at + timedelta(minutes=16),
    )

    with pytest.raises(NotificationV2SourceNotReadyError, match="caught up"):
        service.publish(
            incident_id=fixture["state"].incident_id,
            verified_at=refreshed_active.published_at,
        )


def test_manifest_state_version_reference_must_match_feed_pointer() -> None:
    fixture, service, _outbox = _service()
    reference = fixture["feed_entry"].feed_pointer_reference
    feed_pointer = IncidentEnrichmentFeedPointer.model_validate_json(
        fixture["reader"].versioned_content[(reference.name, reference.version)]
    )
    manifest_reference = feed_pointer.enrichment_asset.manifest_reference
    manifest = IncidentEnrichmentManifest.model_validate_json(
        fixture["reader"].versioned_content[
            (manifest_reference.name, manifest_reference.version)
        ]
    )
    mismatched = manifest.model_copy(
        update={
            "incident_state_reference": (
                manifest.incident_state_reference.model_copy(
                    update={"version": "different-version"}
                )
            )
        }
    )
    original_read = NotificationV2SourceVerifier._read_version_model

    def read_model(
        verifier: NotificationV2SourceVerifier,
        source_reference: object,
        maximum_bytes: int,
        model_type: type[object],
    ) -> object:
        if model_type is IncidentEnrichmentManifest:
            return mismatched
        return original_read(
            verifier,
            source_reference,
            maximum_bytes,
            model_type,
        )

    with (
        patch(
            "athena_context.eventing.notification_v2."
            "validate_incident_enrichment_assets"
        ),
        patch.object(
            NotificationV2SourceVerifier,
            "_read_version_model",
            new=read_model,
        ),
        pytest.raises(ValueError, match="enrichment, report, or guidance"),
    ):
        service.publish(
            incident_id=fixture["state"].incident_id,
            verified_at=fixture["feed_index"].published_at,
        )
