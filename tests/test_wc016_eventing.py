from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError
from pydantic import ValidationError

import athena_context.eventing.detector as detector_module
import athena_context.eventing.runtime as runtime_module
from athena_context.azure_adapters import AzureBlobIncidentAssetPublisher
from athena_context.cli import build_parser
from athena_context.contracts import (
    VersionPinnedBlobReference,
    build_incident_occurrence_receipt,
    sha256_hex,
)
from athena_context.contracts.eventing import (
    ActiveIncidentIndex,
    IncidentFeedAttestation,
    IncidentFeedPointer,
    IncidentFinding,
    IncidentNotification,
    IncidentState,
    IncidentStateAttestation,
)
from athena_context.eventing import (
    ApprovedLiveReassessmentAdapter,
    EventNormalizationError,
    EventRoutingError,
    InMemorySignalStateStore,
    SignalDetectionError,
    build_active_incident_index_heartbeat,
    build_incident_publication,
    build_reassessment_request,
    build_signed_incident_state,
    detect_signal_requests,
    normalize_monitor_event,
    notification_message,
    run_active_incident_index_heartbeat,
    run_incident_reassessment,
)
from athena_context.eventing.detector import ManagedIdentityArmJsonReader
from athena_context.eventing.runtime import (
    AzureServiceBusNotificationOutbox,
    AzureTableNotificationDeliveryStore,
    NotificationDeliveryClaim,
    _dispatch_notification_message,
    _notification_http_error_is_permanent,
    _validate_notification_broker_metadata,
    _validate_reassessment_age,
    _validate_reassessment_broker_metadata,
)
from athena_context.presentation_assets import (
    MAX_INCIDENT_FEED_POINTER_BYTES,
    MAX_INCIDENT_STATE_BYTES,
    MAX_PRESENTATION_ATTESTATION_BYTES,
    ActiveIncidentIndexSnapshot,
    CurrentIncidentStateSnapshot,
    IncidentPublicationReceipt,
    PresentationAsset,
    PresentationAssetAlreadyExistsError,
    PresentationAssetUnavailableError,
    _issue_incident_publication_receipt,
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
ROLES = {
    DB_ID.lower(): "database-primary",
    WEB_ID.lower(): "web",
    LB_ID.lower(): "load-balancer",
}
NOW = datetime(2026, 9, 4, 3, 40, tzinfo=UTC)
DETECTOR_RULES = (
    "wc016-scheduled-database-primary-power-state",
    "wc016-scheduled-web-power-state",
    "wc016-scheduled-load-balancer-availability",
)
INCIDENT_KEY_ID = "synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1"
INCIDENT_KEY_FINGERPRINT = "sha256:" + "2" * 64


def _activity_event(
    resource_id: str,
    operation: str,
    *,
    observed_at: datetime = NOW,
) -> dict[str, object]:
    return {
        "id": f"synthetic-{operation}-001",
        "eventType": "Microsoft.Resources.ResourceWriteSuccess",
        "subject": resource_id,
        "eventTime": observed_at.isoformat().replace("+00:00", "Z"),
        "data": {
            "resourceUri": resource_id,
            "resourceProvider": "Microsoft.Compute",
            "operationName": operation,
            "status": "Succeeded",
            "category": "Administrative",
        },
    }


def _request(
    resource_id: str,
    operation: str,
    *,
    observed_at: datetime = NOW,
):
    event = normalize_monitor_event(
        _activity_event(resource_id, operation, observed_at=observed_at),
        received_at=observed_at,
    )
    return build_reassessment_request(event, approved_resource_roles=ROLES)


def _detector_request(
    resource_id: str,
    *,
    healthy: bool,
    observed_at: datetime = NOW,
):
    role = ROLES[resource_id.lower()]
    rule_name = (
        f"wc016-scheduled-{role}-power-state"
        if role in {"database-primary", "web"}
        else "wc016-scheduled-load-balancer-availability"
    )
    timestamp = observed_at.isoformat().replace("+00:00", "Z")
    event = normalize_monitor_event(
        {
            "schemaId": "azureMonitorCommonAlertSchema",
            "data": {
                "essentials": {
                    "alertId": f"synthetic-{role}-{timestamp}",
                    "signalType": "Metric",
                    "monitorCondition": "Resolved" if healthy else "Fired",
                    "severity": "Sev1",
                    "alertRule": rule_name,
                    "alertTargetIDs": [resource_id],
                    "firedDateTime": timestamp,
                    "resolvedDateTime": timestamp,
                }
            },
        },
        received_at=observed_at,
        approved_metric_alert_rules=DETECTOR_RULES,
    )
    return build_reassessment_request(event, approved_resource_roles=ROLES)


class _Signer:
    def sign_preimage(self, canonical_preimage: bytes) -> str:
        assert canonical_preimage.startswith(b"{")
        return "c3ludGhldGljLXNpZ25hdHVyZQ=="


class _Sender:
    def __init__(self) -> None:
        self.sent: list[tuple[object, str, str]] = []

    def send(self, request: object, *, message_id: str, session_id: str) -> None:
        self.sent.append((request, message_id, session_id))


class _ArmReader:
    def __init__(self) -> None:
        self.db_power_state = "PowerState/running"
        self.web_power_state = "PowerState/running"
        self.vip_average = 100.0
        self.dip_average = 100.0
        self.calls: list[str] = []

    def get_json(
        self,
        resource_id: str,
        *,
        query: dict[str, str],
    ) -> dict[str, object]:
        assert "api-version" in query
        self.calls.append(resource_id)
        if resource_id == DB_ID.lower() + "/instanceView":
            return {"statuses": [{"code": self.db_power_state}]}
        if resource_id == WEB_ID.lower() + "/instanceView":
            return {"statuses": [{"code": self.web_power_state}]}
        assert resource_id == LB_ID.lower() + "/providers/microsoft.insights/metrics"
        return {
            "value": [
                {
                    "name": {"value": "VipAvailability"},
                    "timeseries": [{"data": [{"average": self.vip_average}]}],
                },
                {
                    "name": {"value": "DipAvailability"},
                    "timeseries": [{"data": [{"average": self.dip_average}]}],
                },
            ]
        }


def test_managed_identity_arm_reader_accepts_only_reviewed_operation_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[object] = []

    class _Response:
        status = 200

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        @staticmethod
        def read(_maximum_bytes: int) -> bytes:
            return b"{}"

    def open_request(request: object, *, timeout: int) -> _Response:
        assert timeout == 30
        requests.append(request)
        return _Response()

    monkeypatch.setattr(detector_module, "urlopen", open_request)
    reader = object.__new__(ManagedIdentityArmJsonReader)
    reader._credential = SimpleNamespace(  # type: ignore[attr-defined]
        get_token=lambda scope: SimpleNamespace(
            token="synthetic-token" if scope.endswith("/.default") else ""
        )
    )
    assert (
        reader.get_json(
            DB_ID.lower() + "/instanceView",
            query={"api-version": "2024-11-01"},
        )
        == {}
    )
    assert (
        reader.get_json(
            LB_ID.lower() + "/providers/microsoft.insights/metrics",
            query={
                "api-version": "2023-10-01",
                "metricnames": "VipAvailability,DipAvailability",
                "metricnamespace": "Microsoft.Network/loadBalancers",
                "timespan": "2026-09-04T03:35:00Z/2026-09-04T03:40:00Z",
                "interval": "PT1M",
                "aggregation": "Average",
                "AutoAdjustTimegrain": "false",
                "ValidateDimensions": "true",
            },
        )
        == {}
    )

    parsed = [urlsplit(request.full_url) for request in requests]
    assert [item.path for item in parsed] == [
        DB_ID.lower() + "/instanceView",
        LB_ID.lower() + "/providers/microsoft.insights/metrics",
    ]
    assert parse_qs(parsed[0].query) == {"api-version": ["2024-11-01"]}
    assert parse_qs(parsed[1].query)["api-version"] == ["2023-10-01"]


@pytest.mark.parametrize(
    ("path", "query"),
    [
        (DB_ID, {"api-version": "2024-11-01"}),
        (DB_ID + "/instanceview", {"api-version": "2024-11-01"}),
        (DB_ID + "/instanceView/extra", {"api-version": "2024-11-01"}),
        (DB_ID + "/instanceView", {"api-version": "2023-09-01"}),
        (
            LB_ID + "/providers/microsoft.insights/metrics",
            {
                "api-version": "2023-10-01",
                "metricnames": "VipAvailability,DipAvailability",
                "metricnamespace": "Microsoft.Network/loadBalancers",
                "timespan": "2026-09-04T03:35:00Z/2026-09-04T03:40:00Z",
                "interval": "PT1M",
                "aggregation": "Average",
                "AutoAdjustTimegrain": "false",
                "ValidateDimensions": "true",
                "extra": "rejected",
            },
        ),
        (
            LB_ID + "/providers/microsoft.insights/metrics",
            {
                "api-version": "2023-10-01",
                "metricnames": "VipAvailability,DipAvailability",
                "metricnamespace": "Microsoft.Network/loadBalancers",
                "timespan": "2026-09-04T02:35:00Z/2026-09-04T03:40:00Z",
                "interval": "PT1M",
                "aggregation": "Average",
                "AutoAdjustTimegrain": "false",
                "ValidateDimensions": "true",
            },
        ),
    ],
)
def test_managed_identity_arm_reader_rejects_unreviewed_operations_before_http(
    path: str,
    query: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        detector_module,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("HTTP must not be attempted"),
    )
    reader = object.__new__(ManagedIdentityArmJsonReader)
    reader._credential = SimpleNamespace(  # type: ignore[attr-defined]
        get_token=lambda _scope: pytest.fail("token must not be requested")
    )

    with pytest.raises(SignalDetectionError, match="ARM|reviewed|allowlisted"):
        reader.get_json(path, query=query)


def test_request_contract_rederives_all_security_critical_fields() -> None:
    request = _request(WEB_ID, "Microsoft.Compute/virtualMachines/powerOff/action")

    assert request.workload_role == "web"
    assert request.scenario == "webServerFailure"
    assert request.idempotency_key.removeprefix("wc016-") == (
        request.trigger_event.deduplication_key.removeprefix("sha256:")
    )
    with pytest.raises(ValidationError, match="deterministically bound"):
        request.model_copy(update={"scenario": "singletonDatabaseFailure"}).model_validate(
            request.model_copy(update={"scenario": "singletonDatabaseFailure"}).model_dump(
                by_alias=True
            )
        )


def test_unbound_or_malformed_queue_hint_fails_closed() -> None:
    event = normalize_monitor_event(
        _activity_event(DB_ID, "deallocate"),
        received_at=NOW,
    )
    with pytest.raises(EventRoutingError, match="approved workload role"):
        build_reassessment_request(event, approved_resource_roles={})

    payload = event.model_dump(mode="python", by_alias=True)
    payload["resourceGroupName"] = "other-rg"
    with pytest.raises(ValidationError, match="scope fields"):
        type(event).model_validate(payload)


def test_unapproved_metric_alert_is_rejected_at_normalization() -> None:
    alert = {
        "schemaId": "azureMonitorCommonAlertSchema",
        "data": {
            "essentials": {
                "alertId": "synthetic-alert",
                "signalType": "Metric",
                "monitorCondition": "Fired",
                "severity": "Sev1",
                "alertRule": "unapproved-rule",
                "alertTargetIDs": [LB_ID],
                "firedDateTime": "2026-09-04T03:40:00Z",
                "resolvedDateTime": "2026-09-04T03:40:00Z",
            }
        },
    }
    with pytest.raises(EventNormalizationError, match="approved workload availability"):
        normalize_monitor_event(
            alert,
            received_at=NOW,
            approved_metric_alert_rules=DETECTOR_RULES,
        )


def test_detector_uses_dedicated_state_and_stable_pending_transition() -> None:
    reader = _ArmReader()
    reader.web_power_state = "PowerState/stopped"
    sender = _Sender()

    class _FailCommitOnce(InMemorySignalStateStore):
        failed = False

        def complete_transition(
            self,
            *,
            resource_id: str,
            request_id: str,
            observed_at: datetime,
        ) -> None:
            if not self.failed:
                self.failed = True
                raise SignalDetectionError("synthetic state failure")
            super().complete_transition(
                resource_id=resource_id,
                request_id=request_id,
                observed_at=observed_at,
            )

    state = _FailCommitOnce()
    with pytest.raises(SignalDetectionError, match="synthetic state failure"):
        detect_signal_requests(
            reader=reader,
            state_store=state,
            sender=sender,
            approved_resource_roles=ROLES,
            approved_metric_alert_rules=DETECTOR_RULES,
            observed_at=NOW,
        )
    first_request, first_message_id, first_session_id = sender.sent[0]

    reader.calls.clear()
    retried = detect_signal_requests(
        reader=reader,
        state_store=state,
        sender=sender,
        approved_resource_roles=ROLES,
        approved_metric_alert_rules=DETECTOR_RULES,
        observed_at=NOW + timedelta(minutes=1),
    )

    assert retried == (first_request,)
    assert sender.sent[1][1:] == (first_message_id, first_session_id)
    assert first_message_id == retried[0].idempotency_key
    assert first_session_id == retried[0].incident_id
    assert WEB_ID.lower() + "/instanceView" not in reader.calls


def test_dip_availability_degradation_is_not_load_balancer_failure() -> None:
    reader = _ArmReader()
    reader.dip_average = 75.0

    assert (
        detect_signal_requests(
            reader=reader,
            state_store=InMemorySignalStateStore(),
            sender=_Sender(),
            approved_resource_roles=ROLES,
            approved_metric_alert_rules=DETECTOR_RULES,
            observed_at=NOW,
        )
        == ()
    )

    reader.vip_average = 0.0
    requests = detect_signal_requests(
        reader=reader,
        state_store=InMemorySignalStateStore(),
        sender=_Sender(),
        approved_resource_roles=ROLES,
        approved_metric_alert_rules=DETECTOR_RULES,
        observed_at=NOW,
    )
    assert [request.scenario for request in requests] == ["loadBalancerFailure"]


def test_orchestrator_requeries_live_state_independently_of_hint_lifecycle() -> None:
    request = _detector_request(WEB_ID, healthy=False)
    reader = _ArmReader()
    reader.web_power_state = "PowerState/stopped"
    adapter = ApprovedLiveReassessmentAdapter(
        reader=reader,
        approved_resource_roles=ROLES,
        clock=lambda: NOW,
    )

    result = adapter.reassess(request)

    assert result.verified_healthy is False
    assert result.reasoning[0].endswith("untrusted reassessment hint.")
    assert reader.calls == [WEB_ID.lower() + "/instanceView"]

    reader.web_power_state = "PowerState/running"
    reconciled = adapter.reassess(request)
    assert reconciled.verified_healthy is True


def test_orchestrator_rejects_non_detector_hint_source_before_live_read() -> None:
    request = _request(WEB_ID, "powerOff")
    reader = _ArmReader()
    adapter = ApprovedLiveReassessmentAdapter(
        reader=reader,
        approved_resource_roles=ROLES,
        clock=lambda: NOW,
    )

    with pytest.raises(ValueError, match="deterministic rederivation"):
        adapter.reassess(request)
    assert reader.calls == []


def test_reassessment_queue_age_allows_outage_reconciliation_but_not_history() -> None:
    delayed = _detector_request(
        WEB_ID,
        healthy=False,
        observed_at=NOW - timedelta(minutes=30),
    )
    _validate_reassessment_age(delayed, now=NOW)

    historical = _detector_request(
        WEB_ID,
        healthy=False,
        observed_at=NOW - timedelta(days=2),
    )
    with pytest.raises(ValueError, match="one-day queue lifetime"):
        _validate_reassessment_age(historical, now=NOW)


def _state_and_attestation(resource_id: str, operation: str, healthy: bool):
    request = _request(resource_id, operation)
    state, attestation = build_signed_incident_state(
        request,
        detected_at=NOW,
        updated_at=NOW,
        target_binding="sha256:" + "1" * 64,
        reassessment_verified_healthy=healthy,
        findings=(
            IncidentFinding(
                clauseId="synthetic-operational-state",
                verdict="resolved" if healthy else "fail",
                summary="The approved synthetic resource state was verified.",
                evidenceRefs=("synthetic-evidence-001",),
            ),
        ),
        reasoning=("Current state was independently verified.",),
        signer=_Signer(),
        signing_key_id=INCIDENT_KEY_ID,
    )
    return request, state, attestation


def test_per_incident_pointers_and_active_index_preserve_other_incidents() -> None:
    _, db_state, db_attestation = _state_and_attestation(DB_ID, "deallocate", False)
    db_publication = build_incident_publication(
        db_state,
        db_attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    db_snapshot = ActiveIncidentIndexSnapshot(
        index=db_publication.active_index,
        payload_sha256=db_publication.active_index_asset.payload_sha256,
    )
    _, web_state, web_attestation = _state_and_attestation(WEB_ID, "powerOff", False)
    web_publication = build_incident_publication(
        web_state,
        web_attestation,
        published_at=NOW + timedelta(milliseconds=1),
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
        active_index_snapshot=db_snapshot,
    )

    assert web_publication.pointer_asset.blob_name.endswith("/pointer.json")
    assert "/versions/" in web_publication.pointer_asset.blob_name
    assert (
        web_publication.current_pointer_asset.blob_name
        == f"incidents/{web_state.incident_id}/current.json"
    )
    assert [entry.incident_id for entry in web_publication.active_index.incidents] == sorted(
        [db_state.incident_id, web_state.incident_id]
    )

    web_snapshot = ActiveIncidentIndexSnapshot(
        index=web_publication.active_index,
        payload_sha256=web_publication.active_index_asset.payload_sha256,
    )
    _, resolved_db_state, resolved_db_attestation = _state_and_attestation(DB_ID, "start", True)
    resolved_publication = build_incident_publication(
        resolved_db_state,
        resolved_db_attestation,
        published_at=NOW + timedelta(milliseconds=2),
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
        active_index_snapshot=web_snapshot,
    )

    assert [entry.incident_id for entry in resolved_publication.active_index.incidents] == [
        web_state.incident_id
    ]


def test_active_incident_index_heartbeat_bootstraps_and_refreshes_without_state_changes() -> None:
    empty = build_active_incident_index_heartbeat(
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
        active_index_snapshot=None,
    )

    assert empty.active_index.incidents == ()
    assert empty.active_index.published_at == NOW
    assert empty.previous_active_index_sha256 is None

    _, state, attestation = _state_and_attestation(DB_ID, "deallocate", False)
    active = build_incident_publication(
        state,
        attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    snapshot = ActiveIncidentIndexSnapshot(
        index=active.active_index,
        payload_sha256=active.active_index_asset.payload_sha256,
    )
    refreshed = build_active_incident_index_heartbeat(
        published_at=NOW + timedelta(minutes=5),
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
        active_index_snapshot=snapshot,
    )

    assert refreshed.active_index.incidents == snapshot.index.incidents
    assert refreshed.active_index.published_at == NOW + timedelta(minutes=5)
    assert refreshed.active_index.index_attestation_path != snapshot.index.index_attestation_path
    assert refreshed.previous_active_index_sha256 == snapshot.payload_sha256


def test_concurrent_publication_cas_loss_cannot_replace_indexed_pointer() -> None:
    _, db_state, db_attestation = _state_and_attestation(DB_ID, "deallocate", False)
    _, web_state, web_attestation = _state_and_attestation(WEB_ID, "powerOff", False)
    winner = build_incident_publication(
        db_state,
        db_attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    loser = build_incident_publication(
        web_state,
        web_attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    uploaded = {
        asset.blob_name: asset.payload
        for asset in (
            winner.state,
            winner.attestation,
            winner.pointer_asset,
            winner.pointer_attestation_asset,
            loser.state,
            loser.attestation,
            loser.pointer_asset,
            loser.pointer_attestation_asset,
        )
    }
    winner_entry = winner.active_index.incidents[0]

    assert winner.pointer_asset.blob_name != loser.pointer_asset.blob_name
    assert winner_entry.pointer_path == f"./{winner.pointer_asset.blob_name}"
    assert uploaded[winner_entry.pointer_path.removeprefix("./")] == (winner.pointer_asset.payload)
    assert sha256_hex(uploaded[winner_entry.pointer_path.removeprefix("./")]) == (
        winner_entry.pointer_sha256
    )


def test_incident_publication_rejects_index_occurrence_mismatch() -> None:
    _, state, attestation = _state_and_attestation(
        DB_ID,
        "deallocate",
        False,
    )
    publication = build_incident_publication(
        state,
        attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    empty_index = build_active_incident_index_heartbeat(
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
        active_index_snapshot=None,
    )

    with pytest.raises(ValueError, match="does not match the occurrence"):
        replace(
            publication,
            active_index=empty_index.active_index,
            active_index_attestation=(empty_index.active_index_attestation),
            active_index_asset=empty_index.active_index_asset,
            active_index_attestation_asset=(empty_index.active_index_attestation_asset),
        )


def test_blob_publisher_translates_conditional_write_conflicts() -> None:
    asset = PresentationAsset(
        blob_name="incidents/active.json",
        payload=b"{}",
        payload_sha256=sha256_hex(b"{}"),
        maximum_bytes=MAX_INCIDENT_STATE_BYTES,
    )

    class _CreateConflictBlob:
        @staticmethod
        def upload_blob(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise ResourceExistsError("synthetic create conflict")

    with pytest.raises(
        PresentationAssetAlreadyExistsError,
        match="created concurrently",
    ):
        AzureBlobIncidentAssetPublisher._upload_missing_mutable(
            _CreateConflictBlob(),
            asset,
        )

    class _ReplaceConflictBlob:
        @staticmethod
        def upload_blob(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise ResourceModifiedError("synthetic replace conflict")

    current = SimpleNamespace(properties=SimpleNamespace(etag='"synthetic-etag"'))
    with pytest.raises(
        PresentationAssetAlreadyExistsError,
        match="conditional publication",
    ):
        AzureBlobIncidentAssetPublisher._replace_mutable(
            _ReplaceConflictBlob(),
            asset,
            current,
        )


def test_incident_publisher_returns_version_pinned_occurrence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, state, attestation = _state_and_attestation(
        DB_ID,
        "deallocate",
        False,
    )
    publication = build_incident_publication(
        state,
        attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    publisher = object.__new__(AzureBlobIncidentAssetPublisher)
    publisher._signing_key_id = INCIDENT_KEY_ID
    publisher._signing_key_fingerprint = INCIDENT_KEY_FINGERPRINT

    def upload(
        _self: object,
        asset: PresentationAsset,
    ) -> VersionPinnedBlobReference:
        return VersionPinnedBlobReference(
            name=asset.blob_name,
            version=f"version-{sha256_hex(asset.blob_name)[:16]}",
            contentDigest=asset.payload_sha256,
        )

    monkeypatch.setattr(
        AzureBlobIncidentAssetPublisher,
        "_upload_immutable",
        upload,
    )
    monkeypatch.setattr(
        AzureBlobIncidentAssetPublisher,
        "_publish_current_pointer",
        lambda _self, _request: None,
    )
    monkeypatch.setattr(
        AzureBlobIncidentAssetPublisher,
        "_publish_active_index",
        lambda _self, _request: None,
    )

    receipt = publisher.publish_incident(publication)

    assert receipt.occurrence is not None
    assert receipt.occurrence.incident_id == state.incident_id
    assert receipt.occurrence.pointer_reference.content_digest == receipt.pointer_sha256


def test_immutable_upload_requires_version_id() -> None:
    asset = PresentationAsset(
        blob_name=("incidents/inc-000000000000/versions/" + "0" * 64 + "/state.json"),
        payload=b"{}",
        payload_sha256=sha256_hex(b"{}"),
        maximum_bytes=MAX_INCIDENT_STATE_BYTES,
    )

    class _Downloader:
        properties = SimpleNamespace(
            content_settings=SimpleNamespace(content_type="application/json"),
            metadata={"payload_sha256": asset.payload_sha256},
            version_id=None,
        )

        @staticmethod
        def readall() -> bytes:
            return asset.payload

    class _Blob:
        @staticmethod
        def upload_blob(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {}

        @staticmethod
        def download_blob(**_kwargs: object) -> _Downloader:
            return _Downloader()

    class _Container:
        @staticmethod
        def get_blob_client(_name: str) -> _Blob:
            return _Blob()

    publisher = object.__new__(AzureBlobIncidentAssetPublisher)
    publisher._container = _Container()

    with pytest.raises(
        PresentationAssetAlreadyExistsError,
        match="unversioned",
    ):
        publisher._upload_immutable(asset)


def test_incident_publisher_reads_bounded_trusted_current_state() -> None:
    _, state, attestation = _state_and_attestation(DB_ID, "deallocate", False)
    publication = build_incident_publication(
        state,
        attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    assets = {
        publication.current_pointer_asset.blob_name: (
            publication.current_pointer_asset.payload,
            publication.current_pointer_asset.payload_sha256,
        ),
        publication.pointer_asset.blob_name: (
            publication.pointer_asset.payload,
            publication.pointer_asset.payload_sha256,
        ),
        publication.pointer_attestation_asset.blob_name: (
            publication.pointer_attestation_asset.payload,
            publication.pointer_attestation_asset.payload_sha256,
        ),
        publication.state.blob_name: (
            publication.state.payload,
            publication.state.payload_sha256,
        ),
        publication.attestation.blob_name: (
            publication.attestation.payload,
            publication.attestation.payload_sha256,
        ),
    }
    requested_lengths: dict[str, int] = {}

    class _Blob:
        def __init__(self, name: str) -> None:
            self.name = name

        def download_blob(
            self,
            *,
            offset: int,
            length: int,
            max_concurrency: int,
        ) -> object:
            assert offset == 0
            assert max_concurrency == 1
            requested_lengths[self.name] = length
            payload, digest = assets[self.name]
            return SimpleNamespace(
                properties=SimpleNamespace(
                    content_settings=SimpleNamespace(content_type="application/json"),
                    metadata={"payload_sha256": digest},
                    version_id=f"version-{self.name}",
                ),
                readall=lambda: payload,
            )

    class _Container:
        @staticmethod
        def get_blob_client(name: str) -> _Blob:
            return _Blob(name)

    publisher = object.__new__(AzureBlobIncidentAssetPublisher)
    publisher._container = _Container()
    publisher._signing_key_id = INCIDENT_KEY_ID
    publisher._signing_key_fingerprint = INCIDENT_KEY_FINGERPRINT
    publisher._signature_verifier = lambda _payload, _signature: True

    snapshot = publisher.read_current_incident_state(incident_id=state.incident_id)

    assert snapshot is not None
    assert snapshot.state == state
    assert snapshot.pointer == publication.pointer
    assert snapshot.occurrence is not None
    assert requested_lengths == {
        publication.current_pointer_asset.blob_name: (MAX_INCIDENT_FEED_POINTER_BYTES + 1),
        publication.pointer_asset.blob_name: (MAX_INCIDENT_FEED_POINTER_BYTES + 1),
        publication.pointer_attestation_asset.blob_name: (MAX_PRESENTATION_ATTESTATION_BYTES + 1),
        publication.state.blob_name: MAX_INCIDENT_STATE_BYTES + 1,
        publication.attestation.blob_name: MAX_PRESENTATION_ATTESTATION_BYTES + 1,
    }

    stale_payload = publication.pointer.model_dump(
        mode="python",
        by_alias=True,
    )
    stale_payload["publishedAt"] = state.updated_at - timedelta(seconds=1)
    stale_pointer = IncidentFeedPointer(**stale_payload)
    stale_pointer_bytes = stale_pointer.canonical_bytes()
    stale_pointer_digest = sha256_hex(stale_pointer_bytes)
    stale_attestation = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=stale_pointer_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=INCIDENT_KEY_ID,
        detachedSignature="c3ludGhldGlj",
    )
    assets[publication.current_pointer_asset.blob_name] = (
        stale_pointer_bytes,
        stale_pointer_digest,
    )
    assets[publication.pointer_asset.blob_name] = (
        stale_pointer_bytes,
        stale_pointer_digest,
    )
    assets[publication.pointer_attestation_asset.blob_name] = (
        stale_attestation.canonical_bytes(),
        sha256_hex(stale_attestation.canonical_bytes()),
    )
    legacy_snapshot = publisher.read_current_incident_state(incident_id=state.incident_id)
    assert legacy_snapshot is not None
    assert legacy_snapshot.state == state
    assert legacy_snapshot.occurrence is None

    assets[publication.state.blob_name] = (
        publication.state.payload,
        "sha256:" + "0" * 64,
    )
    with pytest.raises(
        PresentationAssetUnavailableError,
        match="metadata",
    ):
        publisher.read_current_incident_state(incident_id=state.incident_id)


def test_notification_outbox_has_stable_transition_id_and_incident_session() -> None:
    class _Message:
        def __init__(self, body: bytes, **kwargs: object) -> None:
            self._body = body
            for key, value in kwargs.items():
                setattr(self, key, value)

        def __bytes__(self) -> bytes:
            return self._body

    class _BusSender:
        def __init__(self) -> None:
            self.messages: list[object] = []

        def send_messages(self, message: object) -> None:
            self.messages.append(message)

    sender = _BusSender()
    outbox = AzureServiceBusNotificationOutbox(sender, message_factory=_Message)
    transition_id = "wc016-" + "a" * 64
    outbox.enqueue(
        incident_id="inc-aabbccddeeff",
        lifecycle="active",
        transition_id=transition_id,
        message="Synthetic bounded message.",
    )
    message = sender.messages[0]
    notification = IncidentNotification.model_validate_json(bytes(message))

    assert message.session_id == "inc-aabbccddeeff"
    assert message.message_id == notification.notification_id
    assert notification.transition_id == transition_id
    _validate_notification_broker_metadata(message, notification)


def _notification_message(
    *,
    notification_id_suffix: str = "c",
    lifecycle: str = "active",
) -> tuple[IncidentNotification, SimpleNamespace]:
    notification = IncidentNotification(
        schemaVersion="athena.incidentNotification.v1",
        notificationId="notify-" + notification_id_suffix * 64,
        transitionId="wc016-" + "b" * 64,
        incidentId="inc-aabbccddeeff",
        lifecycle=lifecycle,
        message="Synthetic bounded message.",
    )
    return notification, SimpleNamespace(
        body=notification.canonical_bytes(),
        content_type="application/json",
        message_id=notification.notification_id,
        session_id=notification.incident_id,
        application_properties={
            "schemaVersion": "athena.incidentNotification.v1",
            "lifecycle": lifecycle,
            "transitionId": notification.transition_id,
        },
    )


class _NotificationStore:
    def __init__(self) -> None:
        self.state: str | None = None
        self.etag = 0
        self.fail_mark_dispatching_once = False
        self.fail_mark_delivered_once = False
        self.lose_dispatch_lease_once = False
        self.events: list[str] = []

    def acquire(
        self,
        *,
        notification_id: str,
        reserved_at: datetime,
    ) -> NotificationDeliveryClaim:
        assert notification_id.startswith("notify-")
        assert reserved_at.tzinfo is not None
        if self.state == "delivered":
            self.events.append("observed-delivered")
            return NotificationDeliveryClaim(disposition="delivered")
        if self.state == "dispatching":
            self.events.append("observed-dispatching")
            return NotificationDeliveryClaim(disposition="dispatching")
        self.state = "reserved"
        self.etag += 1
        self.events.append("reserved")
        return NotificationDeliveryClaim(disposition="acquired", etag=str(self.etag))

    def mark_dispatching(
        self,
        *,
        notification_id: str,
        etag: str,
        dispatching_at: datetime,
    ) -> str | None:
        assert notification_id.startswith("notify-")
        assert dispatching_at.tzinfo is not None
        assert self.state == "reserved"
        assert etag == str(self.etag)
        if self.fail_mark_dispatching_once:
            self.fail_mark_dispatching_once = False
            raise RuntimeError("synthetic crash before dispatch")
        if self.lose_dispatch_lease_once:
            self.lose_dispatch_lease_once = False
            self.events.append("dispatch-lease-lost")
            return None
        self.state = "dispatching"
        self.etag += 1
        self.events.append("dispatching")
        return str(self.etag)

    def mark_delivered(
        self,
        *,
        notification_id: str,
        etag: str,
        delivered_at: datetime,
    ) -> bool:
        assert notification_id.startswith("notify-")
        assert delivered_at.tzinfo is not None
        assert self.state == "dispatching"
        assert etag == str(self.etag)
        if self.fail_mark_delivered_once:
            self.fail_mark_delivered_once = False
            raise RuntimeError("synthetic crash after HTTP success")
        self.state = "delivered"
        self.etag += 1
        self.events.append("delivered")
        return True

    def reset_for_retry(
        self,
        *,
        notification_id: str,
        etag: str,
        reserved_at: datetime,
    ) -> bool:
        assert notification_id.startswith("notify-")
        assert reserved_at.tzinfo is not None
        assert self.state == "dispatching"
        assert etag == str(self.etag)
        self.state = "reserved"
        self.etag += 1
        self.events.append("reset-reserved")
        return True


class _NotificationReceiver:
    def __init__(self) -> None:
        self.completed = 0
        self.dead_letter_reasons: list[str] = []
        self.abandoned = 0
        self.fail_complete_once = False

    def complete_message(self, _message: object) -> None:
        if self.fail_complete_once:
            self.fail_complete_once = False
            raise RuntimeError("synthetic crash before Service Bus completion")
        self.completed += 1

    def dead_letter_message(self, _message: object, **kwargs: str) -> None:
        self.dead_letter_reasons.append(kwargs["reason"])

    def abandon_message(self, _message: object) -> None:
        self.abandoned += 1


class _NotificationResponse:
    status = 202

    def __enter__(self) -> _NotificationResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    @staticmethod
    def read(_maximum_bytes: int) -> bytes:
        return b"{}"


def _notification_arguments(
    *,
    message: object,
    receiver: _NotificationReceiver,
    store: _NotificationStore,
) -> dict[str, object]:
    return {
        "message": message,
        "receiver": receiver,
        "credential": SimpleNamespace(
            get_token=lambda _scope: SimpleNamespace(token="synthetic-token")
        ),
        "webhook_url": (
            "https://example.logic.azure.com/workflows/synthetic/triggers/manual/"
            "paths/invoke?api-version=2019-05-01"
        ),
        "delivery_store": store,
    }


def test_notification_table_state_transitions_use_etag_ownership() -> None:
    class _Exists(Exception):
        pass

    class _Modified(Exception):
        pass

    class _NotFound(Exception):
        pass

    class _HttpError(Exception):
        pass

    class _Entity(dict[str, object]):
        def __init__(self, values: dict[str, object], etag: str) -> None:
            super().__init__(values)
            self.metadata = {"etag": etag}

    class _Table:
        def __init__(self) -> None:
            self.entity: dict[str, object] | None = None
            self.etag = 0

        def create_entity(self, entity: dict[str, object]) -> dict[str, str]:
            if self.entity is not None:
                raise _Exists
            self.entity = dict(entity)
            self.etag += 1
            return {"etag": str(self.etag)}

        def get_entity(self, _partition_key: str, _row_key: str) -> _Entity:
            if self.entity is None:
                raise _NotFound
            return _Entity(self.entity, str(self.etag))

        def update_entity(
            self,
            entity: dict[str, object],
            *,
            mode: object = None,
            etag: str,
            match_condition: object,
        ) -> dict[str, str]:
            assert match_condition == "if-not-modified"
            if etag != str(self.etag):
                raise _Modified
            if mode == "replace":
                self.entity = dict(entity)
            else:
                assert self.entity is not None
                self.entity.update(entity)
            self.etag += 1
            return {"etag": str(self.etag)}

        @staticmethod
        def query_entities(**_kwargs: object) -> list[object]:
            return []

    table = _Table()
    store = AzureTableNotificationDeliveryStore.__new__(AzureTableNotificationDeliveryStore)
    store._table = table
    store._partition_key = "wc016-notification-delivery"
    store._exists = _Exists
    store._modified = _Modified
    store._not_found = _NotFound
    store._http_error = _HttpError
    store._if_not_modified = "if-not-modified"
    store._replace = "replace"
    notification_id = "notify-" + "7" * 64

    first = store.acquire(notification_id=notification_id, reserved_at=NOW)
    second = store.acquire(
        notification_id=notification_id,
        reserved_at=NOW + timedelta(seconds=1),
    )

    assert first.disposition == "acquired"
    assert second.disposition == "acquired"
    assert first.etag is not None
    assert second.etag is not None
    assert (
        store.mark_dispatching(
            notification_id=notification_id,
            etag=first.etag,
            dispatching_at=NOW + timedelta(seconds=2),
        )
        is None
    )

    dispatching_etag = store.mark_dispatching(
        notification_id=notification_id,
        etag=second.etag,
        dispatching_at=NOW + timedelta(seconds=2),
    )
    assert dispatching_etag is not None
    assert (
        store.acquire(
            notification_id=notification_id,
            reserved_at=NOW + timedelta(seconds=3),
        ).disposition
        == "dispatching"
    )
    assert store.mark_delivered(
        notification_id=notification_id,
        etag=dispatching_etag,
        delivered_at=NOW + timedelta(seconds=4),
    )
    assert (
        store.acquire(
            notification_id=notification_id,
            reserved_at=NOW + timedelta(seconds=5),
        ).disposition
        == "delivered"
    )


def test_notification_pruning_never_removes_dispatching_or_delivered_records() -> None:
    class _Modified(Exception):
        pass

    class _NotFound(Exception):
        pass

    class _HttpError(Exception):
        pass

    class _Entity(dict[str, object]):
        metadata = {"etag": "synthetic-etag"}

    class _Table:
        def __init__(self) -> None:
            self.filter = ""
            self.deleted: list[str] = []

        def query_entities(self, *, query_filter: str, **_kwargs: object) -> list[_Entity]:
            self.filter = query_filter
            return [
                _Entity(
                    {
                        "PartitionKey": "wc016-notification-delivery",
                        "RowKey": "notify-" + "8" * 64,
                        "state": "reserved",
                    }
                )
            ]

        def delete_entity(
            self,
            entity: _Entity,
            *,
            etag: str,
            match_condition: object,
        ) -> None:
            assert etag == "synthetic-etag"
            assert match_condition == "if-not-modified"
            self.deleted.append(str(entity["RowKey"]))

    table = _Table()
    store = AzureTableNotificationDeliveryStore.__new__(AzureTableNotificationDeliveryStore)
    store._table = table
    store._partition_key = "wc016-notification-delivery"
    store._modified = _Modified
    store._not_found = _NotFound
    store._http_error = _HttpError
    store._if_not_modified = "if-not-modified"

    store._prune_expired(NOW)

    assert "state eq 'reserved'" in table.filter
    assert table.deleted == ["notify-" + "8" * 64]


def test_notification_dispatch_uses_durable_id_and_suppresses_duplicate_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    notification, message = _notification_message()
    request_bodies: list[dict[str, str]] = []

    def open_request(request: object, *, timeout: int) -> _NotificationResponse:
        assert timeout == 30
        request_bodies.append(json.loads(request.data))
        return _NotificationResponse()

    monkeypatch.setattr(runtime_module, "urlopen", open_request)
    store = _NotificationStore()
    receiver = _NotificationReceiver()
    arguments = _notification_arguments(
        message=message,
        receiver=receiver,
        store=store,
    )

    assert _dispatch_notification_message(**arguments)
    assert _dispatch_notification_message(**arguments)

    assert request_bodies == [
        {
            "notificationId": notification.notification_id,
            "message": notification.message,
        }
    ]
    assert store.events == ["reserved", "dispatching", "delivered", "observed-delivered"]
    assert receiver.completed == 2
    assert receiver.dead_letter_reasons == []


def test_notification_reserved_after_pre_dispatch_crash_is_safely_reacquired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, message = _notification_message(notification_id_suffix="d")
    store = _NotificationStore()
    store.fail_mark_dispatching_once = True
    receiver = _NotificationReceiver()
    attempts = 0

    def open_request(_request: object, *, timeout: int) -> _NotificationResponse:
        nonlocal attempts
        assert timeout == 30
        attempts += 1
        return _NotificationResponse()

    monkeypatch.setattr(runtime_module, "urlopen", open_request)
    arguments = _notification_arguments(
        message=message,
        receiver=receiver,
        store=store,
    )

    with pytest.raises(RuntimeError, match="synthetic crash before dispatch"):
        _dispatch_notification_message(**arguments)
    assert store.state == "reserved"
    assert attempts == 0

    assert _dispatch_notification_message(**arguments)
    assert attempts == 1
    assert receiver.completed == 1
    assert store.state == "delivered"


def test_notification_dispatching_crash_is_dead_lettered_without_repost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _SyntheticCrash(BaseException):
        pass

    _, message = _notification_message(notification_id_suffix="e")
    store = _NotificationStore()
    receiver = _NotificationReceiver()
    attempts = 0

    def crash_request(_request: object, *, timeout: int) -> object:
        nonlocal attempts
        assert timeout == 30
        attempts += 1
        raise _SyntheticCrash()

    monkeypatch.setattr(runtime_module, "urlopen", crash_request)
    arguments = _notification_arguments(
        message=message,
        receiver=receiver,
        store=store,
    )

    with pytest.raises(_SyntheticCrash):
        _dispatch_notification_message(**arguments)
    assert store.state == "dispatching"

    assert _dispatch_notification_message(**arguments) is False
    assert attempts == 1
    assert receiver.dead_letter_reasons == ["AthenaNotificationDeliveryUncertain"]


def test_notification_success_then_delivery_state_crash_is_not_reposted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, message = _notification_message(notification_id_suffix="f")
    store = _NotificationStore()
    store.fail_mark_delivered_once = True
    receiver = _NotificationReceiver()
    attempts = 0

    def open_request(_request: object, *, timeout: int) -> _NotificationResponse:
        nonlocal attempts
        assert timeout == 30
        attempts += 1
        return _NotificationResponse()

    monkeypatch.setattr(runtime_module, "urlopen", open_request)
    arguments = _notification_arguments(
        message=message,
        receiver=receiver,
        store=store,
    )

    with pytest.raises(RuntimeError, match="synthetic crash after HTTP success"):
        _dispatch_notification_message(**arguments)
    assert store.state == "dispatching"

    assert _dispatch_notification_message(**arguments) is False
    assert attempts == 1
    assert receiver.dead_letter_reasons == ["AthenaNotificationDeliveryUncertain"]


def test_notification_delivered_before_service_bus_crash_completes_on_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, message = _notification_message(notification_id_suffix="1")
    store = _NotificationStore()
    receiver = _NotificationReceiver()
    receiver.fail_complete_once = True
    attempts = 0

    def open_request(_request: object, *, timeout: int) -> _NotificationResponse:
        nonlocal attempts
        assert timeout == 30
        attempts += 1
        return _NotificationResponse()

    monkeypatch.setattr(runtime_module, "urlopen", open_request)
    arguments = _notification_arguments(
        message=message,
        receiver=receiver,
        store=store,
    )

    with pytest.raises(RuntimeError, match="Service Bus completion"):
        _dispatch_notification_message(**arguments)
    assert store.state == "delivered"

    assert _dispatch_notification_message(**arguments)
    assert attempts == 1
    assert receiver.completed == 1


def test_notification_ambiguous_http_outcome_is_explicitly_uncertain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, message = _notification_message(notification_id_suffix="2", lifecycle="resolved")
    store = _NotificationStore()
    receiver = _NotificationReceiver()
    attempts = 0

    def timeout_request(_request: object, *, timeout: int) -> object:
        nonlocal attempts
        assert timeout == 30
        attempts += 1
        raise TimeoutError("synthetic ambiguous timeout")

    monkeypatch.setattr(runtime_module, "urlopen", timeout_request)
    arguments = _notification_arguments(
        message=message,
        receiver=receiver,
        store=store,
    )

    assert _dispatch_notification_message(**arguments) is False
    assert store.state == "dispatching"
    assert _dispatch_notification_message(**arguments) is False
    assert attempts == 1
    assert receiver.dead_letter_reasons == [
        "AthenaNotificationDeliveryUncertain",
        "AthenaNotificationDeliveryUncertain",
    ]


def test_notification_token_failure_does_not_create_delivery_reservation() -> None:
    notification, message = _notification_message(notification_id_suffix="3")

    class _Store:
        def acquire(
            self,
            *,
            notification_id: str,
            reserved_at: datetime,
        ) -> NotificationDeliveryClaim:
            raise AssertionError(
                f"token failure must not reserve {notification_id} at {reserved_at}"
            )

        def mark_dispatching(self, **_kwargs: object) -> str | None:
            raise AssertionError("token failure must not mark dispatching")

        def mark_delivered(self, **_kwargs: object) -> bool:
            raise AssertionError("token failure must not mark delivered")

        def reset_for_retry(self, **_kwargs: object) -> bool:
            raise AssertionError("token failure must not reset")

    class _Receiver:
        def complete_message(self, _message: object) -> None:
            raise AssertionError("token failure must not complete the message")

        def dead_letter_message(self, _message: object, **_kwargs: str) -> None:
            raise AssertionError("pre-dispatch token failure must remain retryable")

    def fail_token(_scope: str) -> object:
        raise RuntimeError("synthetic token failure")

    with pytest.raises(RuntimeError, match="token failure"):
        _dispatch_notification_message(
            message=message,
            receiver=_Receiver(),
            credential=SimpleNamespace(get_token=fail_token),
            webhook_url=(
                "https://example.logic.azure.com/workflows/synthetic/triggers/manual/"
                "paths/invoke?api-version=2019-05-01"
            ),
            delivery_store=_Store(),
        )


@pytest.mark.parametrize("status_code", [408, 429])
def test_notification_transient_http_status_resets_and_retries(
    status_code: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from urllib.error import HTTPError

    _, message = _notification_message(notification_id_suffix="4")
    store = _NotificationStore()
    receiver = _NotificationReceiver()
    responses = iter(
        [
            HTTPError(
                url="https://example.logic.azure.com",
                code=status_code,
                msg="synthetic transient response",
                hdrs=None,
                fp=None,
            ),
            _NotificationResponse(),
        ]
    )

    def open_request(_request: object, *, timeout: int) -> object:
        assert timeout == 30
        response = next(responses)
        if isinstance(response, HTTPError):
            raise response
        return response

    monkeypatch.setattr(runtime_module, "urlopen", open_request)
    arguments = _notification_arguments(
        message=message,
        receiver=receiver,
        store=store,
    )

    assert _dispatch_notification_message(**arguments) is False
    assert store.state == "reserved"
    assert receiver.abandoned == 1
    assert _dispatch_notification_message(**arguments)
    assert store.state == "delivered"
    assert receiver.completed == 1


def test_notification_permanent_http_rejection_is_dead_lettered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from urllib.error import HTTPError

    _, message = _notification_message(notification_id_suffix="5")
    store = _NotificationStore()
    receiver = _NotificationReceiver()

    def reject_request(_request: object, *, timeout: int) -> object:
        assert timeout == 30
        raise HTTPError(
            url="https://example.logic.azure.com",
            code=400,
            msg="synthetic rejection",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(runtime_module, "urlopen", reject_request)

    assert (
        _dispatch_notification_message(
            **_notification_arguments(
                message=message,
                receiver=receiver,
                store=store,
            )
        )
        is False
    )
    assert store.state == "dispatching"
    assert receiver.dead_letter_reasons == ["AthenaNotificationRejected"]


def test_notification_lost_reservation_lease_abandons_without_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, message = _notification_message(notification_id_suffix="6")
    store = _NotificationStore()
    store.lose_dispatch_lease_once = True
    receiver = _NotificationReceiver()

    def unexpected_request(_request: object, *, timeout: int) -> object:
        raise AssertionError(f"lost lease must prevent HTTP at timeout {timeout}")

    monkeypatch.setattr(runtime_module, "urlopen", unexpected_request)

    assert (
        _dispatch_notification_message(
            **_notification_arguments(
                message=message,
                receiver=receiver,
                store=store,
            )
        )
        is False
    )
    assert receiver.abandoned == 1


def test_reassessment_broker_metadata_is_exact() -> None:
    request = _request(WEB_ID, "powerOff")
    message = type(
        "_Message",
        (),
        {
            "content_type": "application/json",
            "message_id": request.idempotency_key,
            "session_id": request.incident_id,
            "application_properties": {
                b"schemaVersion": b"athena.incidentReassessmentRequest.v1",
                b"scenario": request.scenario.encode(),
                b"lifecycle": request.lifecycle.encode(),
            },
        },
    )()
    _validate_reassessment_broker_metadata(message, request)
    message.message_id = "tampered"
    with pytest.raises(ValueError, match="broker metadata"):
        _validate_reassessment_broker_metadata(message, request)


@pytest.mark.parametrize("status_code", [408, 429])
def test_notification_transient_http_statuses_are_retried(status_code: int) -> None:
    assert _notification_http_error_is_permanent(status_code) is False
    assert _notification_http_error_is_permanent(400) is True


class _Reassessment:
    def __init__(self, healthy: bool, observed_at: datetime = NOW) -> None:
        self.healthy = healthy
        self.observed_at = observed_at

    def reassess(self, request: object):
        from athena_context.contracts.eventing import VerifiedReassessmentResult

        return VerifiedReassessmentResult(
            schemaVersion="athena.incidentReassessmentResult.v1",
            requestId=request.request_id,
            snapshotId="synthetic-current-state",
            observedAt=self.observed_at,
            targetBinding="sha256:" + "1" * 64,
            verifiedHealthy=self.healthy,
            findings=(
                IncidentFinding(
                    clauseId="synthetic-current-state",
                    verdict="resolved" if self.healthy else "fail",
                    summary="Current state was independently verified.",
                    evidenceRefs=("synthetic-live-evidence",),
                ),
            ),
            reasoning=("Current state was independently verified.",),
        )


class _Publisher:
    def __init__(
        self,
        snapshot: ActiveIncidentIndexSnapshot | None = None,
        current: CurrentIncidentStateSnapshot | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.requests: list[object] = []
        self.index_requests: list[object] = []
        self.snapshot = snapshot
        self.current = current
        self.events = events

    def read_active_incident_index(self) -> ActiveIncidentIndexSnapshot | None:
        return self.snapshot

    def read_current_incident_state(
        self,
        *,
        incident_id: str,
    ) -> CurrentIncidentStateSnapshot | None:
        if self.current is not None:
            assert self.current.state.incident_id == incident_id
        return self.current

    def publish_incident(self, request: object) -> IncidentPublicationReceipt:
        if self.events is not None:
            self.events.append("publish")
        self.requests.append(request)
        state = IncidentState.model_validate_json(request.state.payload)
        state_attestation = IncidentStateAttestation.model_validate_json(
            request.attestation.payload
        )
        pointer_attestation = IncidentFeedAttestation.model_validate_json(
            request.pointer_attestation_asset.payload
        )
        occurrence = build_incident_occurrence_receipt(
            state,
            state_attestation,
            request.pointer,
            pointer_attestation,
            state_reference=VersionPinnedBlobReference(
                name=request.state.blob_name,
                version="synthetic-state-version",
                contentDigest=request.state.payload_sha256,
            ),
            state_attestation_reference=VersionPinnedBlobReference(
                name=request.attestation.blob_name,
                version="synthetic-state-attestation-version",
                contentDigest=request.attestation.payload_sha256,
            ),
            pointer_reference=VersionPinnedBlobReference(
                name=request.pointer_asset.blob_name,
                version="synthetic-pointer-version",
                contentDigest=request.pointer_asset.payload_sha256,
            ),
            pointer_attestation_reference=VersionPinnedBlobReference(
                name=request.pointer_attestation_asset.blob_name,
                version="synthetic-pointer-attestation-version",
                contentDigest=(request.pointer_attestation_asset.payload_sha256),
            ),
        )
        self.current = CurrentIncidentStateSnapshot(
            state=state,
            pointer=request.pointer,
            pointer_sha256=request.pointer_asset.payload_sha256,
            occurrence=occurrence,
        )
        self.snapshot = ActiveIncidentIndexSnapshot(
            index=request.active_index,
            payload_sha256=request.active_index_asset.payload_sha256,
        )
        return _issue_incident_publication_receipt(
            incident_id=request.pointer.incident_id,
            pointer_sha256=request.pointer_asset.payload_sha256,
            active_index_sha256=request.active_index_asset.payload_sha256,
            occurrence=occurrence,
        )

    def publish_active_incident_index(
        self,
        request: object,
    ) -> ActiveIncidentIndexSnapshot:
        self.index_requests.append(request)
        self.snapshot = ActiveIncidentIndexSnapshot(
            index=request.active_index,
            payload_sha256=request.active_index_asset.payload_sha256,
        )
        return self.snapshot


class _Notifications:
    def __init__(self, events: list[str] | None = None) -> None:
        self.transitions: list[str] = []
        self.events = events

    def enqueue(
        self,
        *,
        incident_id: str,
        lifecycle: str,
        transition_id: str,
        message: str,
    ) -> None:
        assert incident_id and lifecycle and message
        if self.events is not None:
            self.events.append("notify")
        self.transitions.append(transition_id)


def test_duplicate_or_resolution_without_active_incident_is_noop_without_signing() -> None:
    class _FailSigner:
        def sign_preimage(self, _canonical_preimage: bytes) -> str:
            raise AssertionError("no-op reconciliation must not sign")

    publisher = _Publisher()
    notifications = _Notifications()
    result = run_incident_reassessment(
        _request(DB_ID, "start"),
        detected_at=NOW,
        updated_at=NOW,
        published_at=NOW,
        presentation_url="https://athena.invalid",
        signing_key_id=INCIDENT_KEY_ID,
        signing_key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        reassessment=_Reassessment(True),
        signer=_FailSigner(),
        publisher=publisher,
        notifications=notifications,
    )

    assert result is None
    assert publisher.requests == []
    assert notifications.transitions == []


def test_active_index_heartbeat_requires_live_health_to_match_and_handles_cas_winner() -> None:
    _, state, attestation = _state_and_attestation(DB_ID, "deallocate", False)
    active = build_incident_publication(
        state,
        attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    snapshot = ActiveIncidentIndexSnapshot(
        index=active.active_index,
        payload_sha256=active.active_index_asset.payload_sha256,
    )

    with pytest.raises(ValueError, match="does not match independently verified"):
        run_active_incident_index_heartbeat(
            (_detector_request(DB_ID, healthy=True),),
            published_at=NOW + timedelta(minutes=5),
            signing_key_id=INCIDENT_KEY_ID,
            signing_key_fingerprint=INCIDENT_KEY_FINGERPRINT,
            signer=_Signer(),
            publisher=_Publisher(snapshot),
        )

    class _ConcurrentPublisher(_Publisher):
        first_attempt = True

        def publish_active_incident_index(
            self,
            request: object,
        ) -> ActiveIncidentIndexSnapshot:
            if self.first_attempt:
                self.first_attempt = False
                self.snapshot = ActiveIncidentIndexSnapshot(
                    index=request.active_index,
                    payload_sha256=request.active_index_asset.payload_sha256,
                )
                raise PresentationAssetAlreadyExistsError("synthetic CAS loss")
            return super().publish_active_incident_index(request)

    publisher = _ConcurrentPublisher(snapshot)
    refreshed = run_active_incident_index_heartbeat(
        (_detector_request(DB_ID, healthy=False),),
        published_at=NOW + timedelta(minutes=5),
        signing_key_id=INCIDENT_KEY_ID,
        signing_key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
        publisher=publisher,
    )

    assert refreshed.index.incidents == snapshot.index.incidents
    assert refreshed.index.published_at == NOW + timedelta(minutes=5)
    assert publisher.index_requests == []


def test_duplicate_active_hint_is_noop_against_signed_index() -> None:
    _, state, attestation = _state_and_attestation(DB_ID, "deallocate", False)
    current = build_incident_publication(
        state,
        attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    snapshot = ActiveIncidentIndexSnapshot(
        index=current.active_index,
        payload_sha256=current.active_index_asset.payload_sha256,
    )
    publisher = _Publisher(snapshot)
    notifications = _Notifications()

    result = run_incident_reassessment(
        _request(DB_ID, "deallocate"),
        detected_at=NOW,
        updated_at=NOW + timedelta(minutes=30),
        published_at=NOW + timedelta(minutes=30),
        presentation_url="https://athena.invalid",
        signing_key_id=INCIDENT_KEY_ID,
        signing_key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        reassessment=_Reassessment(False),
        signer=_Signer(),
        publisher=publisher,
        notifications=notifications,
    )

    assert result is None
    assert publisher.requests == []
    assert notifications.transitions == []


def test_retry_after_publication_reenqueues_the_same_notification() -> None:
    request = _request(DB_ID, "deallocate")
    publisher = _Publisher()

    class _FailOnceNotifications(_Notifications):
        def __init__(self) -> None:
            super().__init__()
            self.attempts = 0

        def enqueue(
            self,
            *,
            incident_id: str,
            lifecycle: str,
            transition_id: str,
            message: str,
        ) -> None:
            self.attempts += 1
            if self.attempts == 1:
                raise RuntimeError("synthetic enqueue failure")
            super().enqueue(
                incident_id=incident_id,
                lifecycle=lifecycle,
                transition_id=transition_id,
                message=message,
            )

    notifications = _FailOnceNotifications()
    arguments = {
        "detected_at": NOW,
        "updated_at": NOW,
        "published_at": NOW,
        "presentation_url": "https://athena.invalid",
        "signing_key_id": INCIDENT_KEY_ID,
        "signing_key_fingerprint": INCIDENT_KEY_FINGERPRINT,
        "reassessment": _Reassessment(False),
        "signer": _Signer(),
        "publisher": publisher,
        "notifications": notifications,
    }

    with pytest.raises(RuntimeError, match="enqueue failure"):
        run_incident_reassessment(request, **arguments)
    assert publisher.current is not None
    assert publisher.current.state.transition_id == request.idempotency_key

    recovered = run_incident_reassessment(request, **arguments)
    assert recovered is not None
    assert recovered[1].occurrence == publisher.current.occurrence
    assert len(publisher.requests) == 1
    assert notifications.transitions == [request.idempotency_key]


def test_retry_with_incoherent_active_index_does_not_return_receipt() -> None:
    request = _request(DB_ID, "deallocate")
    publisher = _Publisher()
    arguments = {
        "detected_at": NOW,
        "updated_at": NOW,
        "published_at": NOW,
        "presentation_url": "https://athena.invalid",
        "signing_key_id": INCIDENT_KEY_ID,
        "signing_key_fingerprint": INCIDENT_KEY_FINGERPRINT,
        "reassessment": _Reassessment(False),
        "signer": _Signer(),
        "publisher": publisher,
        "notifications": _Notifications(),
    }
    first = run_incident_reassessment(request, **arguments)
    assert first is not None
    assert publisher.snapshot is not None
    entry = publisher.snapshot.index.incidents[0]
    stale_entry = entry.model_copy(update={"pointer_sha256": "sha256:" + "0" * 64})
    stale_payload = publisher.snapshot.index.model_dump(
        mode="python",
        by_alias=True,
    )
    stale_payload["incidents"] = (stale_entry,)
    stale_index = ActiveIncidentIndex(**stale_payload)
    publisher.snapshot = ActiveIncidentIndexSnapshot(
        index=stale_index,
        payload_sha256=sha256_hex(stale_index.canonical_bytes()),
    )
    notifications = _Notifications()
    arguments["notifications"] = notifications

    with pytest.raises(RuntimeError, match="not coherent"):
        run_incident_reassessment(request, **arguments)

    assert notifications.transitions == []


def test_resolution_retry_reenqueues_from_published_current_state() -> None:
    _, active_state, active_attestation = _state_and_attestation(
        DB_ID,
        "deallocate",
        False,
    )
    active_publication = build_incident_publication(
        active_state,
        active_attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    publisher = _Publisher(
        ActiveIncidentIndexSnapshot(
            index=active_publication.active_index,
            payload_sha256=active_publication.active_index_asset.payload_sha256,
        ),
        CurrentIncidentStateSnapshot(
            state=active_state,
            pointer=active_publication.pointer,
            pointer_sha256=active_publication.pointer_asset.payload_sha256,
        ),
    )
    request = _request(DB_ID, "start")

    class _FailOnceNotifications(_Notifications):
        failed = False

        def enqueue(
            self,
            *,
            incident_id: str,
            lifecycle: str,
            transition_id: str,
            message: str,
        ) -> None:
            if not self.failed:
                self.failed = True
                raise RuntimeError("synthetic enqueue failure")
            super().enqueue(
                incident_id=incident_id,
                lifecycle=lifecycle,
                transition_id=transition_id,
                message=message,
            )

    notifications = _FailOnceNotifications()
    arguments = {
        "detected_at": NOW,
        "updated_at": NOW + timedelta(minutes=1),
        "published_at": NOW + timedelta(minutes=1),
        "presentation_url": "https://athena.invalid",
        "signing_key_id": INCIDENT_KEY_ID,
        "signing_key_fingerprint": INCIDENT_KEY_FINGERPRINT,
        "reassessment": _Reassessment(True, NOW + timedelta(minutes=1)),
        "signer": _Signer(),
        "publisher": publisher,
        "notifications": notifications,
    }

    with pytest.raises(RuntimeError, match="enqueue failure"):
        run_incident_reassessment(request, **arguments)
    assert publisher.current is not None
    assert publisher.current.state.lifecycle == "resolved"

    recovered = run_incident_reassessment(request, **arguments)
    assert recovered is not None
    assert recovered[1].occurrence == publisher.current.occurrence
    assert len(publisher.requests) == 1
    assert notifications.transitions == [request.idempotency_key]


def test_minted_noop_hint_cannot_reenqueue_a_prior_transition() -> None:
    original_request, state, attestation = _state_and_attestation(
        DB_ID,
        "deallocate",
        False,
    )
    current = build_incident_publication(
        state,
        attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    publisher = _Publisher(
        ActiveIncidentIndexSnapshot(
            index=current.active_index,
            payload_sha256=current.active_index_asset.payload_sha256,
        ),
        CurrentIncidentStateSnapshot(
            state=state,
            pointer=current.pointer,
            pointer_sha256=current.pointer_asset.payload_sha256,
        ),
    )
    minted_request = _request(DB_ID, "powerOff")
    assert minted_request.idempotency_key != original_request.idempotency_key
    notifications = _Notifications()

    result = run_incident_reassessment(
        minted_request,
        detected_at=NOW,
        updated_at=NOW + timedelta(minutes=1),
        published_at=NOW + timedelta(minutes=1),
        presentation_url="https://athena.invalid",
        signing_key_id=INCIDENT_KEY_ID,
        signing_key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        reassessment=_Reassessment(False),
        signer=_Signer(),
        publisher=publisher,
        notifications=notifications,
    )

    assert result is None
    assert notifications.transitions == []


def test_live_resolution_uses_prior_detected_time_and_current_observation() -> None:
    _, state, attestation = _state_and_attestation(DB_ID, "deallocate", False)
    current = build_incident_publication(
        state,
        attestation,
        published_at=NOW,
        key_id=INCIDENT_KEY_ID,
        key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        signer=_Signer(),
    )
    publisher = _Publisher(
        ActiveIncidentIndexSnapshot(
            index=current.active_index,
            payload_sha256=current.active_index_asset.payload_sha256,
        )
    )
    observed_at = NOW + timedelta(minutes=30)

    result = run_incident_reassessment(
        _detector_request(DB_ID, healthy=False),
        detected_at=NOW,
        updated_at=NOW,
        published_at=observed_at,
        presentation_url="https://athena.invalid",
        signing_key_id=INCIDENT_KEY_ID,
        signing_key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        reassessment=_Reassessment(True, observed_at),
        signer=_Signer(),
        publisher=publisher,
        notifications=_Notifications(),
    )

    assert result is not None
    resolved, _ = result
    assert resolved.lifecycle == "resolved"
    assert resolved.detected_at == state.detected_at
    assert resolved.updated_at == observed_at


def test_live_health_overrides_the_untrusted_hint_lifecycle() -> None:
    result = run_incident_reassessment(
        _detector_request(DB_ID, healthy=True),
        detected_at=NOW,
        updated_at=NOW,
        published_at=NOW,
        presentation_url="https://athena.invalid",
        signing_key_id=INCIDENT_KEY_ID,
        signing_key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        reassessment=_Reassessment(False),
        signer=_Signer(),
        publisher=_Publisher(),
        notifications=_Notifications(),
    )

    assert result is not None
    active, _ = result
    assert active.lifecycle == "active"


def test_publication_failure_cannot_enqueue_notification() -> None:
    class _FailingPublisher(_Publisher):
        def publish_incident(self, request: object) -> IncidentPublicationReceipt:
            self.requests.append(request)
            raise RuntimeError("synthetic CAS loss")

    notifications = _Notifications()
    with pytest.raises(RuntimeError, match="CAS loss"):
        run_incident_reassessment(
            _request(DB_ID, "deallocate"),
            detected_at=NOW,
            updated_at=NOW,
            published_at=NOW,
            presentation_url="https://athena.invalid",
            signing_key_id=INCIDENT_KEY_ID,
            signing_key_fingerprint=INCIDENT_KEY_FINGERPRINT,
            reassessment=_Reassessment(False),
            signer=_Signer(),
            publisher=_FailingPublisher(),
            notifications=notifications,
        )
    assert notifications.transitions == []


def test_signed_state_reports_outbox_enqueue_semantics() -> None:
    request = _request(DB_ID, "deallocate")
    events: list[str] = []
    publisher = _Publisher(events=events)
    notifications = _Notifications(events)

    state, _ = run_incident_reassessment(
        request,
        detected_at=NOW,
        updated_at=NOW,
        published_at=NOW,
        presentation_url="https://athena.invalid",
        signing_key_id=INCIDENT_KEY_ID,
        signing_key_fingerprint=INCIDENT_KEY_FINGERPRINT,
        reassessment=_Reassessment(False),
        signer=_Signer(),
        publisher=publisher,
        notifications=notifications,
    )

    assert state.notification_status == "pendingDispatch"
    assert state.transition_id == request.idempotency_key
    assert notifications.transitions == [request.idempotency_key]
    assert len(publisher.requests) == 1
    assert events == ["publish", "notify"]
    assert notification_message(
        state,
        presentation_url="https://athena.invalid",
    ).endswith("Sent by Kanga, my AI sidekick 🦘")


def test_cli_removed_raw_normalizer_and_requires_incident_trust_boundaries() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["wc016-event-processor"])

    gateway = parser.parse_args(
        [
            "presentation-asset-gateway",
            "--blob-endpoint",
            "https://athena.blob.core.windows.net",
            "--managed-identity-client-id",
            "11111111-1111-1111-1111-111111111111",
            "--incident-key-id",
            INCIDENT_KEY_ID,
            "--incident-key-fingerprint",
            INCIDENT_KEY_FINGERPRINT,
            "--incident-public-key",
            "wc016-incident-public-key.pem",
        ]
    )
    assert gateway.container == "presentation-assets"
    assert gateway.incident_container == "incident-assets"

    notification = parser.parse_args(
        [
            "wc016-notification-dispatcher",
            "--service-bus-namespace",
            "athena.servicebus.windows.net",
            "--managed-identity-client-id",
            "11111111-1111-1111-1111-111111111111",
            "--notification-state-table-endpoint",
            "https://athena.table.core.windows.net",
            "--notification-state-table-name",
            "Wc016NotificationState",
            "--notification-state-partition-key",
            "wc016-notification-delivery",
        ]
    )
    assert notification.notification_state_table_name == "Wc016NotificationState"

    heartbeat = parser.parse_args(
        [
            "wc016-incident-feed-heartbeat",
            "--managed-identity-client-id",
            "11111111-1111-1111-1111-111111111111",
            "--approved-resource-roles-json",
            json.dumps(ROLES),
            "--approved-alert-rules-json",
            json.dumps(DETECTOR_RULES),
            "--blob-endpoint",
            "https://athena.blob.core.windows.net",
            "--key-vault-key-id",
            "https://athena.vault.azure.net/keys/wc016-signing/version",
            "--signing-key-id",
            INCIDENT_KEY_ID,
            "--signing-key-fingerprint",
            INCIDENT_KEY_FINGERPRINT,
        ]
    )
    assert heartbeat.command == "wc016-incident-feed-heartbeat"


def test_incident_state_contract_rejects_false_enqueue_status() -> None:
    _, state, _ = _state_and_attestation(DB_ID, "deallocate", False)
    payload = state.model_dump(mode="json", by_alias=True)
    payload["notificationStatus"] = "outboxEnqueued"
    with pytest.raises(ValidationError):
        IncidentState.model_validate(payload)
