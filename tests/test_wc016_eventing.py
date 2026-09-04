from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from athena_context.azure_adapters import AzureBlobPresentationAssetPublisher
from athena_context.cli import build_parser
from athena_context.contracts.eventing import (
    IncidentFinding,
    NormalizedMonitorEvent,
    VerifiedReassessmentResult,
)
from athena_context.eventing import (
    EventNormalizationError,
    EventRoutingError,
    ManagedIdentityReassessmentClient,
    build_incident_publication,
    build_reassessment_request,
    build_signed_incident_state,
    notification_message,
    process_raw_event_message,
    run_incident_reassessment,
)
from athena_context.eventing import (
    normalize_monitor_event as _normalize_monitor_event,
)
from athena_context.presentation_assets import (
    IncidentPublicationRequest,
    PresentationAssetAlreadyExistsError,
)

SUBSCRIPTION_ID = "a6add389-9978-47ac-ab1e-a09212e321d4"
RESOURCE_GROUP = "rg-athena-demo-workload"
DB_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
    "/providers/Microsoft.Compute/virtualMachines/athena-db-01"
)
WEB_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
    "/providers/Microsoft.Compute/virtualMachines/athena-web-01"
)
LB_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
    "/providers/Microsoft.Network/loadBalancers/athena-lb"
)
NOW = datetime(2026, 9, 4, 3, 40, 1, tzinfo=UTC)
LB_RULE = "synthetic-load-balancer-vip-availability"


def normalize_monitor_event(
    value: object,
    *,
    received_at: datetime,
) -> NormalizedMonitorEvent:
    return _normalize_monitor_event(
        value,
        received_at=received_at,
        approved_metric_alert_rules=(LB_RULE,),
    )


def _activity_event(resource_id: str, operation: str) -> dict[str, object]:
    return {
        "id": "synthetic-event-001",
        "eventType": "Microsoft.Resources.ResourceWriteSuccess",
        "subject": resource_id,
        "eventTime": "2026-09-04T03:40:00Z",
        "data": {
            "resourceUri": resource_id,
            "resourceProvider": "Microsoft.Compute",
            "operationName": operation,
            "status": "Succeeded",
            "category": "Administrative",
        },
    }


def _load_balancer_alert(condition: str = "Fired") -> dict[str, object]:
    return {
        "schemaId": "azureMonitorCommonAlertSchema",
        "data": {
            "essentials": {
                "alertId": "synthetic-alert-001",
                "signalType": "Metric",
                "monitorCondition": condition,
                "severity": "Sev1",
                "alertRule": LB_RULE,
                "alertTargetIDs": [LB_ID],
                "firedDateTime": "2026-09-04T03:40:00Z",
                "resolvedDateTime": "2026-09-04T03:40:00Z",
            }
        },
    }


def _resource_health_event(status: str) -> dict[str, object]:
    event = _activity_event(WEB_ID, "Microsoft.Resourcehealth/healthevent/Updated/action")
    data = event["data"]
    assert isinstance(data, dict)
    data["category"] = "ResourceHealth"
    data["currentHealthStatus"] = status
    data["level"] = status
    return event


@pytest.mark.parametrize(
    ("resource_id", "operation", "role", "scenario"),
    [
        (
            DB_ID,
            "Microsoft.Compute/virtualMachines/deallocate/action",
            "database-primary",
            "singletonDatabaseFailure",
        ),
        (
            WEB_ID,
            "Microsoft.Compute/virtualMachines/powerOff/action",
            "web",
            "webServerFailure",
        ),
    ],
)
def test_activity_events_route_only_through_approved_workload_roles(
    resource_id: str,
    operation: str,
    role: str,
    scenario: str,
) -> None:
    event = normalize_monitor_event(
        _activity_event(resource_id, operation),
        received_at=NOW,
    )

    request = build_reassessment_request(
        event,
        approved_resource_roles={resource_id.lower(): role},  # type: ignore[dict-item]
    )

    assert event.lifecycle == "activated"
    assert request.scenario == scenario
    assert request.workload_role == role
    assert request.no_auto_remediation is True


def test_load_balancer_metric_alert_routes_to_ingress_failure_reassessment() -> None:
    event = normalize_monitor_event(_load_balancer_alert(), received_at=NOW)

    request = build_reassessment_request(
        event,
        approved_resource_roles={LB_ID.lower(): "load-balancer"},
    )

    assert event.signal_kind == "metricAlert"
    assert event.lifecycle == "activated"
    assert request.scenario == "loadBalancerFailure"


def test_resolved_alert_preserves_incident_identity_for_recovery_reassessment() -> None:
    active = normalize_monitor_event(_load_balancer_alert("Fired"), received_at=NOW)
    resolved = normalize_monitor_event(_load_balancer_alert("Resolved"), received_at=NOW)

    active_request = build_reassessment_request(
        active,
        approved_resource_roles={LB_ID.lower(): "load-balancer"},
    )
    resolved_request = build_reassessment_request(
        resolved,
        approved_resource_roles={LB_ID.lower(): "load-balancer"},
    )

    assert resolved.lifecycle == "resolved"
    assert active_request.incident_id == resolved_request.incident_id
    assert active_request.idempotency_key != resolved_request.idempotency_key


def test_resolved_alert_uses_resolution_time_for_freshness() -> None:
    alert = _load_balancer_alert("Resolved")
    data = alert["data"]
    assert isinstance(data, dict)
    essentials = data["essentials"]
    assert isinstance(essentials, dict)
    essentials["firedDateTime"] = "2026-09-04T03:20:00Z"
    essentials["resolvedDateTime"] = "2026-09-04T03:40:00Z"

    event = normalize_monitor_event(alert, received_at=NOW)

    assert event.observed_at == datetime(2026, 9, 4, 3, 40, tzinfo=UTC)
    assert event.lifecycle == "resolved"


def test_unrelated_metric_alert_is_not_treated_as_availability_failure() -> None:
    alert = _load_balancer_alert()
    data = alert["data"]
    assert isinstance(data, dict)
    essentials = data["essentials"]
    assert isinstance(essentials, dict)
    essentials["alertRule"] = "synthetic-load-balancer-cpu-high"

    with pytest.raises(EventNormalizationError, match="approved workload availability"):
        normalize_monitor_event(alert, received_at=NOW)


def test_duplicate_envelope_produces_the_same_service_bus_deduplication_key() -> None:
    first = normalize_monitor_event(_activity_event(DB_ID, "deallocate"), received_at=NOW)
    second = normalize_monitor_event(_activity_event(DB_ID, "deallocate"), received_at=NOW)

    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.deduplication_key == second.deduplication_key


def test_unbound_vm_fails_closed_instead_of_guessing_from_its_name() -> None:
    event = normalize_monitor_event(
        _activity_event(DB_ID, "deallocate"),
        received_at=NOW,
    )

    with pytest.raises(EventRoutingError, match="approved workload role"):
        build_reassessment_request(event, approved_resource_roles={})


def test_load_balancer_activity_write_is_not_accepted_as_health_evidence() -> None:
    event = _activity_event(LB_ID, "Microsoft.Network/loadBalancers/write")
    data = event["data"]
    assert isinstance(data, dict)
    data["resourceProvider"] = "Microsoft.Network"

    normalized = normalize_monitor_event(event, received_at=NOW)

    with pytest.raises(EventRoutingError, match="not actionable"):
        build_reassessment_request(
            normalized,
            approved_resource_roles={LB_ID.lower(): "load-balancer"},
        )


def test_common_alert_rejects_multiple_targets_and_unsafe_broad_payloads() -> None:
    alert = _load_balancer_alert()
    data = alert["data"]
    assert isinstance(data, dict)
    essentials = data["essentials"]
    assert isinstance(essentials, dict)
    essentials["alertTargetIDs"] = [LB_ID, WEB_ID]

    with pytest.raises(EventNormalizationError, match="exactly one"):
        normalize_monitor_event(alert, received_at=NOW)


@pytest.mark.parametrize(
    ("status", "expected_lifecycle"),
    [("Unavailable", "activated"), ("Available", "resolved")],
)
def test_resource_health_status_uses_exact_tokens(
    status: str,
    expected_lifecycle: str,
) -> None:
    event = normalize_monitor_event(_resource_health_event(status), received_at=NOW)

    assert event.signal_kind == "resourceHealth"
    assert event.lifecycle == expected_lifecycle


def test_event_older_than_reassessment_window_fails_closed() -> None:
    with pytest.raises(EventNormalizationError, match="contract is invalid"):
        normalize_monitor_event(
            _activity_event(DB_ID, "deallocate"),
            received_at=NOW + timedelta(minutes=10, seconds=1),
        )


class _Signer:
    def sign_preimage(self, canonical_preimage: bytes) -> str:
        assert canonical_preimage.startswith(b"{")
        return "c3ludGhldGljLXNpZ25hdHVyZQ=="


def _database_publication(published_at: datetime) -> IncidentPublicationRequest:
    event = normalize_monitor_event(
        _activity_event(DB_ID, "deallocate"),
        received_at=NOW,
    )
    request = build_reassessment_request(
        event,
        approved_resource_roles={DB_ID.lower(): "database-primary"},
    )
    state, attestation = build_signed_incident_state(
        request,
        detected_at=NOW,
        updated_at=NOW,
        target_binding="sha256:" + "1" * 64,
        reassessment_verified_healthy=False,
        findings=(
            IncidentFinding(
                clauseId="synthetic-database-operational-state",
                verdict="fail",
                summary="The singleton database is unavailable.",
                evidenceRefs=("synthetic-evidence-001",),
            ),
        ),
        reasoning=("Approved context identifies a singleton database dependency.",),
        signer=_Signer(),
        signing_key_id="synthetic-key://athena-argus-demo/rs256-v1",
    )
    return build_incident_publication(
        state,
        attestation,
        published_at=published_at,
        key_id="synthetic-key://athena-argus-demo/rs256-v1",
        key_fingerprint="sha256:" + "2" * 64,
        signer=_Signer(),
    )


@pytest.mark.parametrize(
    ("role", "scenario", "availability", "blast_radius"),
    [
        ("database-primary", "singletonDatabaseFailure", "critical", "whole-workload"),
        ("web", "webServerFailure", "warning", "web-tier"),
        ("load-balancer", "loadBalancerFailure", "critical", "ingress-edge"),
    ],
)
def test_signed_active_incident_impact_is_scenario_specific(
    role: str,
    scenario: str,
    availability: str,
    blast_radius: str,
) -> None:
    resource_id = {"database-primary": DB_ID, "web": WEB_ID, "load-balancer": LB_ID}[role]
    event = normalize_monitor_event(
        _load_balancer_alert()
        if role == "load-balancer"
        else _activity_event(resource_id, "deallocate"),
        received_at=NOW,
    )
    request = build_reassessment_request(
        event,
        approved_resource_roles={resource_id.lower(): role},  # type: ignore[dict-item]
    )

    state, attestation = build_signed_incident_state(
        request,
        detected_at=NOW,
        updated_at=NOW,
        target_binding="sha256:" + "1" * 64,
        reassessment_verified_healthy=False,
        findings=(
            IncidentFinding(
                clauseId=f"synthetic-{scenario}",
                verdict="fail",
                summary="The approved synthetic role is unavailable.",
                evidenceRefs=("synthetic-evidence-001",),
            ),
        ),
        reasoning=(
            "Azure reported an unavailable resource.",
            "Approved workload context bound the resource to this role.",
        ),
        signer=_Signer(),
        signing_key_id="synthetic-key://athena-argus-demo/rs256-v1",
    )

    assert state.availability == availability
    assert state.blast_radius == blast_radius
    assert state.notification_status == "pending"
    assert attestation.result_digest == state.result_digest
    assert notification_message(
        state,
        presentation_url="https://athena.invalid",
    ).startswith("Athena incident ACTIVE")
    publication = build_incident_publication(
        state,
        attestation,
        published_at=NOW,
        key_id="synthetic-key://athena-argus-demo/rs256-v1",
        key_fingerprint="sha256:" + "2" * 64,
        signer=_Signer(),
    )
    assert publication.pointer.state_path.startswith(
        f"./incidents/{state.incident_id}/"
    )
    assert publication.state.payload_sha256 == publication.pointer.state_sha256
    assert attestation.detached_signature == "c3ludGhldGljLXNpZ25hdHVyZQ"


class _Message:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.completed = False
        self.abandoned = False
        self.dead_letter_reason: str | None = None

    @property
    def body(self) -> bytes:
        return self._body

    def complete(self) -> None:
        self.completed = True

    def abandon(self) -> None:
        self.abandoned = True

    def dead_letter(self, *, reason: str) -> None:
        self.dead_letter_reason = reason


class _Sender:
    def __init__(self) -> None:
        self.sent: list[tuple[object, str, str]] = []

    def send(self, request: object, *, message_id: str, session_id: str) -> None:
        self.sent.append((request, message_id, session_id))


def test_service_bus_message_is_completed_only_after_context_bound_request_send() -> None:
    import json

    message = _Message(json.dumps(_activity_event(WEB_ID, "powerOff")).encode())
    sender = _Sender()

    request = process_raw_event_message(
        message,
        sender=sender,  # type: ignore[arg-type]
        approved_resource_roles={WEB_ID.lower(): "web"},
        received_at=NOW,
    )

    assert request is not None
    assert request.trigger_event.target_resource_id == WEB_ID.lower()
    assert message.completed is True
    assert len(sender.sent) == 1
    assert sender.sent[0][1] == request.idempotency_key
    assert sender.sent[0][2] == request.incident_id


def test_invalid_service_bus_message_is_dead_lettered_without_side_effects() -> None:
    message = _Message(b'{"schemaId":"unsupported"}')
    sender = _Sender()

    request = process_raw_event_message(
        message,
        sender=sender,  # type: ignore[arg-type]
        approved_resource_roles={WEB_ID.lower(): "web"},
        received_at=NOW,
    )

    assert request is None
    assert message.completed is False
    assert message.dead_letter_reason is not None
    assert sender.sent == []


def test_event_processor_cli_requires_private_service_bus_and_role_bindings() -> None:
    args = build_parser().parse_args(
        [
            "wc016-event-processor",
            "--service-bus-namespace",
            "athena-events.servicebus.windows.net",
            "--managed-identity-client-id",
            "11111111-1111-1111-1111-111111111111",
            "--approved-resource-roles",
            "approved-resource-roles.json",
            "--approved-alert-rules",
            "approved-alert-rules.json",
        ]
    )

    assert args.raw_queue == "raw-monitor-events"
    assert args.reassessment_queue == "incident-reassessment-requests"


def test_incident_orchestrator_cli_requires_reassessment_and_signing_boundaries() -> None:
    args = build_parser().parse_args(
        [
            "wc016-incident-orchestrator",
            "--service-bus-namespace",
            "athena-events.servicebus.windows.net",
            "--managed-identity-client-id",
            "11111111-1111-1111-1111-111111111111",
            "--reassessment-endpoint",
            "https://athena-reassessment.internal/reassess",
            "--reassessment-audience",
            "api://22222222-2222-2222-2222-222222222222",
            "--blob-endpoint",
            "https://athena.blob.core.windows.net",
            "--presentation-url",
            "https://athena.invalid",
            "--key-vault-key-id",
            "https://athena.vault.azure.net/keys/presentation/0123456789abcdef",
            "--signing-key-id",
            "synthetic-key://athena-argus-demo/rs256-v1",
            "--signing-key-fingerprint",
            "sha256:" + "2" * 64,
        ]
    )

    assert args.reassessment_queue == "incident-reassessment-requests"
    assert args.notification_queue == "incident-notification-outbox"


class _Reassessment:
    def __init__(self, result: VerifiedReassessmentResult) -> None:
        self.result = result

    def reassess(self, request: object) -> VerifiedReassessmentResult:
        return self.result


class _Publisher:
    def __init__(self) -> None:
        self.requests: list[object] = []

    def publish_incident(self, request: object) -> object:
        from athena_context.presentation_assets import IncidentPublicationReceipt

        self.requests.append(request)
        return IncidentPublicationReceipt(
            incident_id="inc-aabbccddeeff",
            pointer_sha256="sha256:" + "3" * 64,
        )


class _Notifications:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def enqueue(self, *, incident_id: str, lifecycle: str, message: str) -> None:
        self.messages.append(message)


def test_orchestrator_publishes_then_enqueues_verified_incident_notification() -> None:
    event = normalize_monitor_event(
        _activity_event(DB_ID, "deallocate"),
        received_at=NOW,
    )
    request = build_reassessment_request(
        event,
        approved_resource_roles={DB_ID.lower(): "database-primary"},
    )
    finding = IncidentFinding(
        clauseId="synthetic-database-operational-state",
        verdict="fail",
        summary="The singleton database is unavailable.",
        evidenceRefs=("synthetic-evidence-001",),
    )
    result = VerifiedReassessmentResult(
        schemaVersion="athena.incidentReassessmentResult.v1",
        requestId=request.request_id,
        snapshotId="synthetic-snapshot-001",
        targetBinding="sha256:" + "1" * 64,
        verifiedHealthy=False,
        findings=(finding,),
        reasoning=("Approved context identifies a singleton database dependency.",),
    )
    publisher = _Publisher()
    notifications = _Notifications()

    state, _ = run_incident_reassessment(
        request,
        detected_at=NOW,
        updated_at=NOW,
        published_at=NOW,
        presentation_url="https://athena.invalid",
        signing_key_id="synthetic-key://athena-argus-demo/rs256-v1",
        signing_key_fingerprint="sha256:" + "2" * 64,
        reassessment=_Reassessment(result),
        signer=_Signer(),
        publisher=publisher,  # type: ignore[arg-type]
        notifications=notifications,
    )

    assert state.lifecycle == "active"
    assert len(publisher.requests) == 1
    assert len(notifications.messages) == 1


class _DownloadedPointer:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.properties = type("_Properties", (), {"etag": '"current-etag"'})()

    def readall(self) -> bytes:
        return self._payload


class _Blob:
    def __init__(self, current_payload: bytes | None = None) -> None:
        self.current_payload = current_payload
        self.uploads: list[dict[str, object]] = []

    def upload_blob(self, _payload: bytes, **kwargs: object) -> None:
        self.uploads.append(kwargs)

    def download_blob(self, **_kwargs: object) -> _DownloadedPointer:
        assert self.current_payload is not None
        return _DownloadedPointer(self.current_payload)


class _Container:
    def __init__(self, current_payload: bytes) -> None:
        self.blobs: dict[str, _Blob] = {
            "incidents/current.json": _Blob(current_payload),
        }

    def get_blob_client(self, name: str) -> _Blob:
        return self.blobs.setdefault(name, _Blob())


def _publisher_with_current(
    pointer_payload: bytes,
) -> tuple[AzureBlobPresentationAssetPublisher, _Container]:
    publisher = AzureBlobPresentationAssetPublisher.__new__(
        AzureBlobPresentationAssetPublisher
    )
    container = _Container(pointer_payload)
    publisher._container = container
    return publisher, container


def test_incident_pointer_rejects_non_monotonic_publication() -> None:
    publication = _database_publication(NOW)
    publisher, container = _publisher_with_current(
        publication.pointer.canonical_bytes()
    )

    with pytest.raises(
        PresentationAssetAlreadyExistsError,
        match="not newer",
    ):
        publisher.publish_incident(publication)
    attestation_blob = publication.pointer.pointer_attestation_path.removeprefix("./")
    assert container.blobs[attestation_blob].uploads[0]["overwrite"] is False


def test_incident_pointer_update_uses_current_etag_compare_and_swap() -> None:
    publication = _database_publication(NOW)
    older_pointer = publication.pointer.model_copy(
        update={"published_at": NOW - timedelta(seconds=1)}
    )
    publisher, container = _publisher_with_current(older_pointer.canonical_bytes())

    publisher.publish_incident(publication)

    pointer_upload = container.blobs["incidents/current.json"].uploads[-1]
    assert pointer_upload["etag"] == '"current-etag"'
    assert pointer_upload["overwrite"] is True


def test_reassessment_client_sends_managed_identity_bearer_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = normalize_monitor_event(
        _activity_event(DB_ID, "deallocate"),
        received_at=NOW,
    )
    request = build_reassessment_request(
        event,
        approved_resource_roles={DB_ID.lower(): "database-primary"},
    )
    result = VerifiedReassessmentResult(
        schemaVersion="athena.incidentReassessmentResult.v1",
        requestId=request.request_id,
        snapshotId="synthetic-snapshot-001",
        targetBinding="sha256:" + "1" * 64,
        verifiedHealthy=False,
        findings=(
            IncidentFinding(
                clauseId="synthetic-database-operational-state",
                verdict="fail",
                summary="The singleton database is unavailable.",
                evidenceRefs=("synthetic-evidence-001",),
            ),
        ),
        reasoning=("Approved context identifies a singleton database dependency.",),
    )
    captured: list[object] = []

    class _Credential:
        def get_token(self, scope: str) -> object:
            assert scope == "api://synthetic/.default"
            return type("_Token", (), {"token": "synthetic-token"})()

    class _Response:
        status = 200

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _maximum: int) -> bytes:
            return result.canonical_bytes()

    def _urlopen(http_request: object, *, timeout: int) -> _Response:
        assert timeout == 30
        captured.append(http_request)
        return _Response()

    monkeypatch.setattr("athena_context.eventing.runtime.urlopen", _urlopen)
    client = ManagedIdentityReassessmentClient.__new__(
        ManagedIdentityReassessmentClient
    )
    client._endpoint = "https://athena.invalid/reassess"
    client._scope = "api://synthetic/.default"
    client._credential = _Credential()

    assert client.reassess(request) == result
    assert captured[0].get_header("Authorization") == "Bearer synthetic-token"  # type: ignore[attr-defined]
