from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.request import Request

import pytest

import athena_context.eventing.change_ingestion as change_ingestion
from athena_context.artifacts import (
    ArtifactAlreadyExistsError,
    ArtifactCurrentReadRequest,
    ArtifactMetadataHashes,
    ArtifactNotFoundError,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactWriteError,
    ArtifactWriteReceipt,
    ArtifactWriteRequest,
)
from athena_context.cli import _load_approved_change_scope
from athena_context.contracts import sha256_hex
from athena_context.contracts.change_ingestion import (
    ApprovedChangeScope,
    ChangedProperty,
    ChangeEvidenceArtifact,
    ChangePolicyContext,
    DeploymentSource,
    NormalizedChangeEvidence,
)
from athena_context.eventing.change_ingestion import (
    AzureResourceGraphChangeHistoryAdapter,
    ChangeIngestionError,
    ManagedIdentityResourceGraphChangeHistoryClient,
    _process_event_grid_message,
    build_change_evidence_artifact,
    build_resource_graph_change_history_query,
    ingest_event_grid_delivery,
    ingest_resource_graph_changes,
    normalize_event_grid_change,
    normalize_resource_graph_change,
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
NSG_RULE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
    "/providers/Microsoft.Network/networkSecurityGroups/athena-nsg/securityRules/allow-web"
)
NOW = datetime(2026, 9, 6, 5, 30, tzinfo=UTC)
KEY_ID = "https://athena-demo.vault.azure.net/keys/wc025-change-signing/abcdef123456"
OTHER_KEY_ID = "https://athena-demo.vault.azure.net/keys/wc025-change-signing/fedcba654321"


def _scope() -> ApprovedChangeScope:
    return ApprovedChangeScope(
        schemaVersion="athena.approvedChangeScope.v1",
        subscriptionId=SUBSCRIPTION_ID,
        resourceGroupName=RESOURCE_GROUP,
        approvedResourceIds=tuple(sorted((DB_ID.lower(), WEB_ID.lower()))),
    )


def _child_resource_scope() -> ApprovedChangeScope:
    return ApprovedChangeScope(
        schemaVersion="athena.approvedChangeScope.v1",
        subscriptionId=SUBSCRIPTION_ID,
        resourceGroupName=RESOURCE_GROUP,
        approvedResourceIds=(NSG_RULE_ID.lower(),),
    )


def _event(
    *,
    resource_id: str = WEB_ID,
    observed_at: datetime = NOW,
) -> dict[str, object]:
    return {
        "id": "synthetic-event-grid-change-001",
        "eventType": "Microsoft.Resources.ResourceWriteSuccess",
        "subject": resource_id,
        "eventTime": observed_at.isoformat().replace("+00:00", "Z"),
        "data": {
            "resourceUri": resource_id,
            "operationName": "Microsoft.Compute/virtualMachines/write",
            "status": "Succeeded",
            "correlationId": "11111111-1111-1111-1111-111111111111",
            "claims": {"appid": "synthetic-workload-deployer"},
            "clientType": "Azure Resource Manager",
            "policyContext": {
                "assignmentId": "/providers/Microsoft.Authorization/policyAssignments/demo",
                "definitionId": "/providers/Microsoft.Authorization/policyDefinitions/demo",
                "enforcementMode": "Default",
            },
        },
    }


def _resource_graph_change(
    *,
    resource_id: str = WEB_ID,
    observed_at: datetime = NOW,
) -> dict[str, object]:
    return {
        "id": (f"{resource_id}/providers/Microsoft.Resources/changes/synthetic-change-history-001"),
        "properties": {
            "targetResourceId": resource_id,
            "targetResourceType": "microsoft.compute/virtualmachines",
            "changeType": "Update",
            "changeAttributes": {
                "previousResourceSnapshotId": "synthetic-before-snapshot",
                "newResourceSnapshotId": "synthetic-after-snapshot",
                "correlationId": "11111111-1111-1111-1111-111111111111",
                "changedByType": "User",
                "changesCount": 2,
                "changedBy": "synthetic.operator@example.invalid",
                "clientType": "Azure Portal",
                "operation": "Microsoft.Compute/virtualMachines/write",
                "timestamp": observed_at.isoformat().replace("+00:00", "Z"),
                "policyAssignmentId": "synthetic-policy-assignment",
                "policyDefinitionId": "synthetic-policy-definition",
                "policyEnforcementMode": "DoNotEnforce",
            },
            "changes": {
                "tags.environment": {
                    "previousValue": "Development",
                    "newValue": "Production",
                },
                "properties.hardwareProfile.vmSize": {
                    "previousValue": "Standard_B2s",
                    "newValue": "Standard_D2s_v5",
                    "isTruncated": "false",
                },
            },
        },
    }


class _Signer:
    def __init__(self) -> None:
        self.preimages: list[bytes] = []
        self.verified_preimages: list[bytes] = []

    def sign_preimage(self, canonical_preimage: bytes) -> str:
        self.preimages.append(canonical_preimage)
        signature = hmac.new(
            b"synthetic-change-evidence-signing-key",
            canonical_preimage,
            hashlib.sha256,
        ).digest()
        return base64.b64encode(signature).decode("ascii")

    def verify_preimage(
        self,
        canonical_preimage: bytes,
        signature: bytes,
    ) -> bool:
        self.verified_preimages.append(canonical_preimage)
        expected = hmac.new(
            b"synthetic-change-evidence-signing-key",
            canonical_preimage,
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(signature, expected)


class _Writer:
    def __init__(self) -> None:
        self.requests: dict[str, ArtifactWriteRequest] = {}
        self.receipts: dict[str, ArtifactWriteReceipt] = {}
        self.current_payload_overrides: dict[str, bytes] = {}
        self.fail_handoff_create_once = False
        self.current_reads: list[str] = []
        self.exact_reads: list[ArtifactReadRequest] = []

    def create(self, request: ArtifactWriteRequest) -> ArtifactWriteReceipt:
        if self.fail_handoff_create_once and request.blob_name.endswith(
            "/persistence-handoff.json"
        ):
            self.fail_handoff_create_once = False
            raise ArtifactWriteError("synthetic handoff index failure")
        if request.blob_name in self.requests:
            raise ArtifactAlreadyExistsError("synthetic duplicate")
        self.requests[request.blob_name] = request
        receipt = ArtifactWriteReceipt(
            container_name="change-evidence",
            blob_name=request.blob_name,
            version_id=f"synthetic-version-{len(self.requests):03}",
            etag="synthetic-etag-001",
            last_modified=NOW,
            size_bytes=len(request.payload),
            payload_sha256=request.hashes.payload_sha256,
        )
        self.receipts[request.blob_name] = receipt
        return receipt

    def read_current(self, request: ArtifactCurrentReadRequest) -> ArtifactReadResult:
        self.current_reads.append(request.blob_name)
        try:
            write_request = self.requests[request.blob_name]
            receipt = self.receipts[request.blob_name]
        except KeyError as exc:
            raise ArtifactNotFoundError("synthetic absent artifact") from exc
        payload = self.current_payload_overrides.get(request.blob_name, write_request.payload)
        return ArtifactReadResult(
            container_name=receipt.container_name,
            blob_name=receipt.blob_name,
            version_id=receipt.version_id,
            payload=payload,
            size_bytes=len(payload),
            content_type="application/json",
            payload_sha256=write_request.hashes.payload_sha256,
        )

    def read(self, request: ArtifactReadRequest) -> ArtifactReadResult:
        self.exact_reads.append(request)
        try:
            write_request = self.requests[request.blob_name]
            receipt = self.receipts[request.blob_name]
        except KeyError as exc:
            raise ArtifactNotFoundError("synthetic absent artifact") from exc
        if (
            request.version_id != receipt.version_id
            or request.expected_payload_sha256 != write_request.hashes.payload_sha256
        ):
            raise AssertionError("recovery did not use the exact evidence version and digest")
        return ArtifactReadResult(
            container_name=receipt.container_name,
            blob_name=receipt.blob_name,
            version_id=receipt.version_id,
            payload=write_request.payload,
            size_bytes=len(write_request.payload),
            content_type="application/json",
            payload_sha256=write_request.hashes.payload_sha256,
        )


def _preclaim_change_evidence(
    writer: _Writer,
    *,
    signer: _Signer,
    signature: str | None = None,
    signing_key_id: str = KEY_ID,
    create_handoff: bool = False,
    artifact_evidence: NormalizedChangeEvidence | None = None,
) -> None:
    evidence = normalize_event_grid_change(
        _event(),
        scope=_scope(),
        received_at=NOW,
    )
    artifact = build_change_evidence_artifact(
        artifact_evidence or evidence,
        signer=signer,
        signing_key_id=signing_key_id,
    )
    payload = artifact.canonical_bytes()
    if signature is not None:
        payload = payload.replace(
            artifact.attestation.signature.encode("ascii"),
            signature.encode("ascii"),
        )
    receipt = writer.create(
        ArtifactWriteRequest(
            blob_name=(
                "change-evidence/"
                f"{evidence.deduplication_key.removeprefix('sha256:')}/evidence.json"
            ),
            payload=payload,
            content_type="application/json",
            hashes=ArtifactMetadataHashes(payload_sha256=sha256_hex(payload)),
        )
    )
    if create_handoff:
        handoff = change_ingestion._persistence_handoff(
            evidence=evidence,
            artifact=change_ingestion._version_pinned_reference(
                blob_name=receipt.blob_name,
                version_id=receipt.version_id,
                payload_sha256=receipt.payload_sha256,
            ),
        )
        handoff_payload = handoff.canonical_bytes()
        writer.create(
            ArtifactWriteRequest(
                blob_name=(
                    "change-evidence/"
                    f"{evidence.deduplication_key.removeprefix('sha256:')}/"
                    "persistence-handoff.json"
                ),
                payload=handoff_payload,
                content_type="application/json",
                hashes=ArtifactMetadataHashes(payload_sha256=sha256_hex(handoff_payload)),
            )
        )


class _ResourceGraphAccessToken:
    token = "synthetic-access-token"


class _ResourceGraphCredential:
    def get_token(self, scope: str) -> _ResourceGraphAccessToken:
        assert scope == "https://management.azure.com/.default"
        return _ResourceGraphAccessToken()


class _ResourceGraphResponse:
    status = 200

    def __init__(self, payload: Mapping[str, object]) -> None:
        self._payload = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> _ResourceGraphResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, amount: int) -> bytes:
        assert amount > len(self._payload)
        return self._payload


class _Receiver:
    def __init__(self) -> None:
        self.completed: list[object] = []
        self.dead_letters: list[tuple[object, str, str]] = []

    def complete_message(self, message: object) -> None:
        self.completed.append(message)

    def dead_letter_message(
        self,
        message: object,
        *,
        reason: str,
        error_description: str,
    ) -> None:
        self.dead_letters.append((message, reason, error_description))


def _resource_graph_client() -> ManagedIdentityResourceGraphChangeHistoryClient:
    client = object.__new__(ManagedIdentityResourceGraphChangeHistoryClient)
    client._credential = _ResourceGraphCredential()
    return client


def test_event_grid_change_is_normalized_with_bounded_provenance() -> None:
    evidence = normalize_event_grid_change(
        _event(),
        scope=_scope(),
        received_at=NOW + timedelta(minutes=1),
    )

    assert evidence.source_system == "azureEventGrid"
    assert evidence.target_resource_id == WEB_ID.lower()
    assert evidence.operation == "createOrUpdate"
    assert evidence.result == "succeeded"
    assert evidence.changed_properties == ()
    assert evidence.actor.kind == "application"
    assert evidence.deployment_source.kind == "resourceManager"
    assert evidence.policy_context.enforcement_mode == "default"
    assert evidence.correlation_id == "11111111-1111-1111-1111-111111111111"
    assert evidence.occurred_at == NOW
    assert evidence.before_evidence_reference is None
    assert evidence.after_evidence_reference is None
    assert evidence.source_record_reference != "synthetic-event-grid-change-001"


@pytest.mark.parametrize(
    ("event_type", "status", "operation_name", "operation"),
    [
        (
            "Microsoft.Resources.ResourceWriteFailure",
            "Failed",
            "Microsoft.Compute/virtualMachines/write",
            "createOrUpdate",
        ),
        (
            "Microsoft.Resources.ResourceWriteCancel",
            "Canceled",
            "Microsoft.Compute/virtualMachines/write",
            "createOrUpdate",
        ),
        (
            "Microsoft.Resources.ResourceDeleteFailure",
            "Failed",
            "Microsoft.Compute/virtualMachines/delete",
            "delete",
        ),
        (
            "Microsoft.Resources.ResourceDeleteCancel",
            "Canceled",
            "Microsoft.Compute/virtualMachines/delete",
            "delete",
        ),
        (
            "Microsoft.Resources.ResourceActionSuccess",
            "Succeeded",
            "Microsoft.Compute/virtualMachines/restart/action",
            "action",
        ),
        (
            "Microsoft.Resources.ResourceActionFailure",
            "Failed",
            "Microsoft.Compute/virtualMachines/restart/action",
            "action",
        ),
        (
            "Microsoft.Resources.ResourceActionCancel",
            "Canceled",
            "Microsoft.Compute/virtualMachines/restart/action",
            "action",
        ),
    ],
)
def test_event_grid_failure_and_cancel_events_are_normalized_deterministically(
    event_type: str,
    status: str,
    operation_name: str,
    operation: str,
) -> None:
    event = _event()
    event["eventType"] = event_type
    data = event["data"]
    assert isinstance(data, dict)
    data["status"] = status
    data["operationName"] = operation_name

    evidence = normalize_event_grid_change(event, scope=_scope(), received_at=NOW)

    assert evidence.operation == operation
    assert evidence.result == ("succeeded" if event_type.endswith("Success") else "failed")


def test_event_grid_user_claim_takes_priority_over_client_application() -> None:
    event = _event()
    event_data = event["data"]
    assert isinstance(event_data, dict)
    event_data["claims"] = {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": (
            "synthetic.operator@example.invalid"
        ),
        "appid": "synthetic-workload-deployer",
    }

    evidence = normalize_event_grid_change(
        event,
        scope=_scope(),
        received_at=NOW,
    )

    assert evidence.actor.kind == "user"
    assert "synthetic.operator@example.invalid" not in evidence.canonical_bytes().decode()


@pytest.mark.parametrize(
    "resource_id",
    [
        DB_ID.replace(RESOURCE_GROUP, "other-rg"),
        (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
            "/providers/Microsoft.Compute/virtualMachines/not-approved"
        ),
    ],
)
def test_event_grid_scope_rejects_other_or_unapproved_resources(resource_id: str) -> None:
    with pytest.raises(ChangeIngestionError, match="exact approved"):
        normalize_event_grid_change(
            _event(resource_id=resource_id),
            scope=_scope(),
            received_at=NOW,
        )


def test_approved_scope_accepts_an_exact_nested_resource_id() -> None:
    scope = _child_resource_scope()

    assert scope.contains(NSG_RULE_ID.upper())
    assert not scope.contains(NSG_RULE_ID.rsplit("/securityRules/", maxsplit=1)[0])


def test_resource_graph_change_retains_only_hashed_property_and_identity_evidence() -> None:
    evidence = normalize_resource_graph_change(
        _resource_graph_change(),
        scope=_scope(),
        received_at=NOW + timedelta(minutes=2),
    )

    assert evidence.source_system == "azureResourceGraphChangeHistory"
    assert evidence.operation == "update"
    assert evidence.result == "succeeded"
    assert [item.path for item in evidence.changed_properties] == [
        "properties.hardwareProfile.vmSize",
        "tags.environment",
    ]
    assert all(
        item.before_evidence_reference and item.after_evidence_reference
        for item in evidence.changed_properties
    )
    assert evidence.before_evidence_reference
    assert evidence.after_evidence_reference
    assert evidence.actor.kind == "user"
    assert evidence.deployment_source.kind == "azurePortal"
    assert evidence.policy_context.enforcement_mode == "doNotEnforce"
    serialized = evidence.canonical_bytes().decode("utf-8")
    assert "synthetic.operator@example.invalid" not in serialized
    assert "Standard_D2s_v5" not in serialized
    assert "synthetic-policy-assignment" not in serialized


@pytest.mark.parametrize(
    ("is_truncated", "expected"),
    [
        ("true", True),
        ("false", False),
        (True, True),
        (False, False),
    ],
)
def test_resource_graph_change_accepts_only_documented_truncation_values(
    is_truncated: str | bool,
    expected: bool,
) -> None:
    change = _resource_graph_change()
    properties = change["properties"]
    assert isinstance(properties, dict)
    changes = properties["changes"]
    assert isinstance(changes, dict)
    detail = changes["properties.hardwareProfile.vmSize"]
    assert isinstance(detail, dict)
    detail["isTruncated"] = is_truncated

    evidence = normalize_resource_graph_change(
        change,
        scope=_scope(),
        received_at=NOW,
    )

    assert evidence.changed_properties[0].is_truncated is expected


@pytest.mark.parametrize("invalid_value", ["True", " false", 0, None])
def test_resource_graph_change_rejects_malformed_property_truncation_values(
    invalid_value: object,
) -> None:
    change = _resource_graph_change()
    properties = change["properties"]
    assert isinstance(properties, dict)
    changes = properties["changes"]
    assert isinstance(changes, dict)
    detail = changes["properties.hardwareProfile.vmSize"]
    assert isinstance(detail, dict)
    detail["isTruncated"] = invalid_value

    with pytest.raises(ChangeIngestionError, match="truncation marker is invalid"):
        normalize_resource_graph_change(change, scope=_scope(), received_at=NOW)


def test_incomplete_resource_graph_observation_cannot_claim_a_later_enriched_record() -> None:
    incomplete = _resource_graph_change()
    incomplete_properties = incomplete["properties"]
    assert isinstance(incomplete_properties, dict)
    incomplete_attributes = incomplete_properties["changeAttributes"]
    assert isinstance(incomplete_attributes, dict)
    incomplete_attributes["changesCount"] = 1
    incomplete_properties.pop("changes")
    writer = _Writer()

    with pytest.raises(ChangeIngestionError, match="details are incomplete"):
        normalize_resource_graph_change(incomplete, scope=_scope(), received_at=NOW)

    enriched = normalize_resource_graph_change(
        _resource_graph_change(),
        scope=_scope(),
        received_at=NOW,
    )
    handoff = ingest_resource_graph_changes(
        (enriched,),
        writer=writer,
        signer=_Signer(),
        signing_key_id=KEY_ID,
    )

    assert writer.requests.keys() == {
        f"change-evidence/{enriched.deduplication_key.removeprefix('sha256:')}/evidence.json",
        (
            f"change-evidence/{enriched.deduplication_key.removeprefix('sha256:')}/"
            "persistence-handoff.json"
        ),
    }
    assert handoff[0].artifact.version == "synthetic-version-001"


@pytest.mark.parametrize("changes_count", [None, -1, "2", 65])
def test_resource_graph_change_rejects_invalid_or_unbounded_changes_count(
    changes_count: object,
) -> None:
    change = _resource_graph_change()
    properties = change["properties"]
    assert isinstance(properties, dict)
    attributes = properties["changeAttributes"]
    assert isinstance(attributes, dict)
    attributes["changesCount"] = changes_count

    with pytest.raises(ChangeIngestionError, match="changesCount"):
        normalize_resource_graph_change(change, scope=_scope(), received_at=NOW)


def test_resource_graph_change_rejects_changed_property_count_mismatch() -> None:
    change = _resource_graph_change()
    properties = change["properties"]
    assert isinstance(properties, dict)
    attributes = properties["changeAttributes"]
    assert isinstance(attributes, dict)
    attributes["changesCount"] = 1

    with pytest.raises(ChangeIngestionError, match="details are incomplete"):
        normalize_resource_graph_change(change, scope=_scope(), received_at=NOW)


def test_resource_graph_adapter_uses_one_narrow_deterministic_query() -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []

    class _QueryPort:
        def query_resource_changes(
            self,
            *,
            query: str,
            subscriptions: tuple[str, ...],
        ) -> Sequence[Mapping[str, object]]:
            calls.append((query, subscriptions))
            return (_resource_graph_change(observed_at=NOW - timedelta(minutes=1)),)

    adapter = AzureResourceGraphChangeHistoryAdapter(
        query_port=_QueryPort(),
        scope=_scope(),
        clock=lambda: NOW,
    )

    evidence = adapter.collect(lookback=timedelta(minutes=10))

    assert len(evidence) == 1
    query, subscriptions = calls[0]
    assert subscriptions == (SUBSCRIPTION_ID,)
    assert f"resourceGroup =~ '{RESOURCE_GROUP}'" in query
    assert DB_ID.lower() in query
    assert WEB_ID.lower() in query
    assert "| take 101" in query
    assert "resourceactions" not in query.casefold()
    assert "activitylogs" not in query.casefold()


def test_resource_graph_adapter_fails_closed_when_the_probe_limit_is_reached() -> None:
    class _QueryPort:
        def query_resource_changes(
            self,
            *,
            query: str,
            subscriptions: tuple[str, ...],
        ) -> Sequence[Mapping[str, object]]:
            return tuple({} for _ in range(101))

    adapter = AzureResourceGraphChangeHistoryAdapter(
        query_port=_QueryPort(),
        scope=_scope(),
        clock=lambda: NOW,
    )

    with pytest.raises(ChangeIngestionError, match="too many"):
        adapter.collect(lookback=timedelta(minutes=10))


@pytest.mark.parametrize("result_truncated", ["false", False])
def test_resource_graph_transport_uses_the_managed_identity_bearer_token(
    monkeypatch: pytest.MonkeyPatch,
    result_truncated: str | bool,
) -> None:
    requests: list[Request] = []

    def fake_urlopen(request: Request, timeout: int) -> _ResourceGraphResponse:
        assert timeout == 30
        requests.append(request)
        return _ResourceGraphResponse({"data": [], "resultTruncated": result_truncated})

    monkeypatch.setattr(change_ingestion, "urlopen", fake_urlopen)

    rows = _resource_graph_client().query_resource_changes(
        query="resourcechanges\n| take 101",
        subscriptions=(SUBSCRIPTION_ID,),
    )

    assert rows == ()
    assert requests[0].get_header("Authorization") == "Bearer synthetic-access-token"
    assert json.loads(requests[0].data or b"{}") == {
        "subscriptions": [SUBSCRIPTION_ID],
        "query": "resourcechanges\n| take 101",
        "options": {"$top": 101, "resultFormat": "ObjectArray"},
    }


@pytest.mark.parametrize(
    "response_body",
    [
        {"data": [], "resultTruncated": "true"},
        {"data": [], "resultTruncated": True},
        {"data": [], "$skipToken": "synthetic-continuation"},
    ],
)
def test_resource_graph_transport_rejects_incomplete_responses(
    monkeypatch: pytest.MonkeyPatch,
    response_body: Mapping[str, object],
) -> None:
    def fake_urlopen(request: Request, timeout: int) -> _ResourceGraphResponse:
        assert timeout == 30
        return _ResourceGraphResponse(response_body)

    monkeypatch.setattr(change_ingestion, "urlopen", fake_urlopen)

    with pytest.raises(ChangeIngestionError, match="incomplete"):
        _resource_graph_client().query_resource_changes(
            query="resourcechanges\n| take 101",
            subscriptions=(SUBSCRIPTION_ID,),
        )


@pytest.mark.parametrize(
    "response_body",
    [
        {"data": []},
        {"data": [], "resultTruncated": "False"},
        {"data": [], "resultTruncated": " false"},
        {"data": [], "resultTruncated": 0},
        {"data": [], "resultTruncated": None},
    ],
)
def test_resource_graph_transport_rejects_unknown_truncation_markers(
    monkeypatch: pytest.MonkeyPatch,
    response_body: Mapping[str, object],
) -> None:
    def fake_urlopen(request: Request, timeout: int) -> _ResourceGraphResponse:
        assert timeout == 30
        return _ResourceGraphResponse(response_body)

    monkeypatch.setattr(change_ingestion, "urlopen", fake_urlopen)

    with pytest.raises(ChangeIngestionError, match="truncation marker is invalid"):
        _resource_graph_client().query_resource_changes(
            query="resourcechanges\n| take 101",
            subscriptions=(SUBSCRIPTION_ID,),
        )


def test_query_builder_rejects_unbounded_or_non_utc_windows() -> None:
    with pytest.raises(ChangeIngestionError, match="outside its bound"):
        build_resource_graph_change_history_query(
            scope=_scope(),
            since=NOW - timedelta(minutes=16),
            until=NOW,
        )
    with pytest.raises(ChangeIngestionError, match="UTC"):
        build_resource_graph_change_history_query(
            scope=_scope(),
            since=datetime(2026, 9, 6, 5, 29),
            until=NOW,
        )


def test_cli_scope_loader_canonicalizes_deployment_json_arrays(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ATHENA_WC025_APPROVED_CHANGE_SCOPE_JSON",
        (
            '{"schemaVersion":"athena.approvedChangeScope.v1",'
            f'"subscriptionId":"{SUBSCRIPTION_ID}",'
            f'"resourceGroupName":"{RESOURCE_GROUP}",'
            f'"approvedResourceIds":["{WEB_ID}","{DB_ID}"]}}'
        ),
    )

    scope = _load_approved_change_scope(None)

    assert scope.approved_resource_ids == tuple(sorted((DB_ID.lower(), WEB_ID.lower())))


@pytest.mark.parametrize(
    "value, received_at, message",
    [
        (
            _event(observed_at=NOW - timedelta(minutes=16)),
            NOW,
            "stale",
        ),
        (
            {
                **_event(),
                "data": {
                    **_event()["data"],  # type: ignore[arg-type]
                    "correlationId": "not-a-guid",
                },
            },
            NOW,
            "invalid",
        ),
        (
            {
                **_resource_graph_change(),
                "properties": {
                    **_resource_graph_change()["properties"],  # type: ignore[arg-type]
                    "changeAttributes": {
                        **_resource_graph_change()["properties"]["changeAttributes"],  # type: ignore[index]
                        "changesCount": 1,
                    },
                    "changes": {
                        "properties.invalid": {
                            "unapproved": "value",
                        }
                    },
                },
            },
            NOW,
            "unsupported",
        ),
    ],
)
def test_malformed_or_stale_evidence_fails_closed(
    value: object,
    received_at: datetime,
    message: str,
) -> None:
    normalizer = (
        normalize_resource_graph_change
        if isinstance(value, dict) and "properties" in value
        else normalize_event_grid_change
    )
    with pytest.raises(ChangeIngestionError, match=message):
        normalizer(value, scope=_scope(), received_at=received_at)


def test_signed_persistence_handoff_is_version_pinned_and_idempotent() -> None:
    signer = _Signer()
    writer = _Writer()
    event = _event()

    handoff = ingest_event_grid_delivery(
        event,
        scope=_scope(),
        received_at=NOW,
        writer=writer,
        signer=signer,
        signing_key_id=KEY_ID,
    )
    duplicate = ingest_event_grid_delivery(
        event,
        scope=_scope(),
        received_at=NOW + timedelta(minutes=1),
        writer=writer,
        signer=signer,
        signing_key_id=KEY_ID,
    )

    assert handoff is not None
    assert duplicate == handoff
    assert handoff.artifact.name.endswith("/evidence.json")
    assert handoff.artifact.version == "synthetic-version-001"
    assert len(writer.requests) == 2
    assert any(name.endswith("/persistence-handoff.json") for name in writer.requests)
    artifact = ChangeEvidenceArtifact.model_validate_json(
        writer.requests[handoff.artifact.name].payload
    )
    assert artifact.attestation.key_vault_key_id == KEY_ID
    assert artifact.attestation.signed_preimage_digest.startswith("sha256:")
    assert artifact.evidence.received_at == NOW
    assert len(signer.preimages) == 1
    assert writer.exact_reads[0].version_id == handoff.artifact.version


def test_upload_success_handoff_failure_retries_to_a_durable_version_pinned_handoff() -> None:
    signer = _Signer()
    writer = _Writer()
    writer.fail_handoff_create_once = True

    with pytest.raises(ArtifactWriteError, match="handoff index failure"):
        ingest_event_grid_delivery(
            _event(),
            scope=_scope(),
            received_at=NOW,
            writer=writer,
            signer=signer,
            signing_key_id=KEY_ID,
        )

    assert len(writer.requests) == 1
    assert next(iter(writer.requests)).endswith("/evidence.json")

    handoff = ingest_event_grid_delivery(
        _event(),
        scope=_scope(),
        received_at=NOW + timedelta(minutes=1),
        writer=writer,
        signer=signer,
        signing_key_id=KEY_ID,
    )

    assert handoff.artifact.version == "synthetic-version-001"
    assert len(writer.requests) == 2
    assert len(signer.preimages) == 1
    assert handoff.artifact.name in writer.current_reads


def test_duplicate_evidence_with_mismatched_content_is_rejected() -> None:
    writer = _Writer()
    writer.fail_handoff_create_once = True

    with pytest.raises(ArtifactWriteError):
        ingest_event_grid_delivery(
            _event(),
            scope=_scope(),
            received_at=NOW,
            writer=writer,
            signer=_Signer(),
            signing_key_id=KEY_ID,
        )

    evidence_name = next(iter(writer.requests))
    writer.current_payload_overrides[evidence_name] = b"{}"

    with pytest.raises(ChangeIngestionError, match="recovered change evidence artifact is invalid"):
        ingest_event_grid_delivery(
            _event(),
            scope=_scope(),
            received_at=NOW,
            writer=writer,
            signer=_Signer(),
            signing_key_id=KEY_ID,
        )


@pytest.mark.parametrize(
    "altered_evidence",
    [
        lambda evidence: evidence.model_copy(
            update={
                "actor": evidence.actor.model_copy(
                    update={
                        "kind": "managedIdentity",
                        "reference": "actor:sha256:" + "a" * 64,
                    }
                )
            }
        ),
        lambda evidence: evidence.model_copy(
            update={
                "changed_properties": (
                    ChangedProperty(
                        path="properties.synthetic",
                        beforeEvidenceReference="property-before:sha256:" + "b" * 64,
                        isTruncated=False,
                    ),
                )
            }
        ),
        lambda evidence: evidence.model_copy(
            update={
                "occurred_at": NOW - timedelta(minutes=1),
                "received_at": NOW - timedelta(minutes=1),
            }
        ),
        lambda evidence: evidence.model_copy(update={"operation": "update"}),
        lambda evidence: evidence.model_copy(
            update={
                "result": "failed",
                "change_key": sha256_hex(
                    "\0".join(
                        (
                            evidence.target_resource_id,
                            "write",
                            "failed",
                            evidence.correlation_id,
                        )
                    ).encode()
                ),
            }
        ),
        lambda evidence: evidence.model_copy(
            update={
                "deployment_source": DeploymentSource(
                    kind="automation",
                    reference="deployment:sha256:" + "c" * 64,
                )
            }
        ),
        lambda evidence: evidence.model_copy(
            update={
                "policy_context": ChangePolicyContext(
                    assignmentReference="policy-assignment:sha256:" + "d" * 64,
                    definitionReference="policy-definition:sha256:" + "e" * 64,
                    enforcementMode="doNotEnforce",
                )
            }
        ),
    ],
    ids=[
        "actor",
        "changed-properties",
        "timestamps",
        "operation",
        "result",
        "deployment-source",
        "policy-context",
    ],
)
def test_recovery_rejects_a_valid_signed_artifact_with_altered_evidence(
    altered_evidence: Callable[[NormalizedChangeEvidence], NormalizedChangeEvidence],
) -> None:
    writer = _Writer()
    signer = _Signer()
    expected = normalize_event_grid_change(_event(), scope=_scope(), received_at=NOW)
    recovered = altered_evidence(expected)
    _preclaim_change_evidence(
        writer,
        signer=signer,
        artifact_evidence=recovered,
    )

    with pytest.raises(
        ChangeIngestionError,
        match="does not match the bounded source record",
    ):
        ingest_event_grid_delivery(
            _event(),
            scope=_scope(),
            received_at=NOW,
            writer=writer,
            signer=signer,
            signing_key_id=KEY_ID,
        )

    assert signer.verified_preimages == []


def test_key_vault_signer_verifies_with_the_exact_rs256_key_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure.keyvault.keys import crypto

    calls: list[tuple[object, bytes, bytes]] = []

    class _Credential:
        pass

    class _CryptographyClient:
        def __init__(self, key_id: str, credential: object) -> None:
            assert key_id == KEY_ID
            assert isinstance(credential, _Credential)

        def verify(
            self,
            algorithm: object,
            digest: bytes,
            signature: bytes,
        ) -> object:
            calls.append((algorithm, digest, signature))
            return SimpleNamespace(is_valid=True)

    monkeypatch.setattr(
        change_ingestion,
        "production_managed_identity_credential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(crypto, "CryptographyClient", _CryptographyClient)
    signer = change_ingestion.KeyVaultChangeEvidenceSigner(
        key_vault_key_id=KEY_ID,
        managed_identity_client_id="11111111-1111-1111-1111-111111111111",
    )
    preimage = b'{"synthetic":"canonical"}'
    signature = b"synthetic-signature"

    assert signer.verify_preimage(preimage, signature) is True
    assert calls == [
        (
            crypto.SignatureAlgorithm.rs256,
            hashlib.sha256(preimage).digest(),
            signature,
        )
    ]


@pytest.mark.parametrize(
    ("signature", "expected_verifications", "match"),
    [
        (base64.b64encode(b"forged-signature").decode("ascii"), 1, "verification failed"),
        ("not valid base64!", 0, "signature is malformed"),
    ],
)
def test_storage_only_preclaim_cannot_claim_a_recovered_artifact(
    signature: str,
    expected_verifications: int,
    match: str,
) -> None:
    writer = _Writer()
    signer = _Signer()
    _preclaim_change_evidence(
        writer,
        signer=signer,
        signature=signature,
    )

    with pytest.raises(ChangeIngestionError, match=match):
        ingest_event_grid_delivery(
            _event(),
            scope=_scope(),
            received_at=NOW,
            writer=writer,
            signer=signer,
            signing_key_id=KEY_ID,
        )

    assert len(writer.requests) == 1
    assert len(signer.verified_preimages) == expected_verifications


def test_durable_handoff_recovery_verifies_the_recovered_artifact_signature() -> None:
    writer = _Writer()
    signer = _Signer()
    _preclaim_change_evidence(
        writer,
        signer=signer,
        signature=base64.b64encode(b"forged-signature").decode("ascii"),
        create_handoff=True,
    )

    with pytest.raises(ChangeIngestionError, match="signature verification failed"):
        ingest_event_grid_delivery(
            _event(),
            scope=_scope(),
            received_at=NOW,
            writer=writer,
            signer=signer,
            signing_key_id=KEY_ID,
        )

    assert len(writer.requests) == 2
    assert len(writer.exact_reads) == 1
    assert len(signer.verified_preimages) == 1


def test_recovery_rejects_an_artifact_attested_by_another_key_version() -> None:
    writer = _Writer()
    signer = _Signer()
    _preclaim_change_evidence(
        writer,
        signer=signer,
        signing_key_id=OTHER_KEY_ID,
    )

    with pytest.raises(ChangeIngestionError, match="does not match the bounded source record"):
        ingest_event_grid_delivery(
            _event(),
            scope=_scope(),
            received_at=NOW,
            writer=writer,
            signer=signer,
            signing_key_id=KEY_ID,
        )

    assert signer.verified_preimages == []


def test_event_grid_message_is_not_settled_until_the_durable_handoff_exists() -> None:
    message = SimpleNamespace(body=json.dumps(_event()).encode("utf-8"))
    receiver = _Receiver()
    writer = _Writer()
    writer.fail_handoff_create_once = True

    with pytest.raises(ArtifactWriteError, match="handoff index failure"):
        _process_event_grid_message(
            receiver=receiver,
            message=message,
            scope=_scope(),
            received_at=NOW,
            writer=writer,
            signer=_Signer(),
            signing_key_id=KEY_ID,
        )

    assert receiver.completed == []
    assert receiver.dead_letters == []
    assert len(writer.requests) == 1

    processed = _process_event_grid_message(
        receiver=receiver,
        message=message,
        scope=_scope(),
        received_at=NOW,
        writer=writer,
        signer=_Signer(),
        signing_key_id=KEY_ID,
    )

    assert processed == 1
    assert receiver.completed == [message]
    assert len(writer.requests) == 2


def test_malformed_later_event_grid_record_is_rejected_before_any_batch_write() -> None:
    malformed = _event()
    malformed_data = malformed["data"]
    assert isinstance(malformed_data, dict)
    malformed_data["correlationId"] = "not-a-guid"
    message = SimpleNamespace(body=json.dumps([_event(), malformed]).encode("utf-8"))
    receiver = _Receiver()
    signer = _Signer()
    writer = _Writer()

    processed = _process_event_grid_message(
        receiver=receiver,
        message=message,
        scope=_scope(),
        received_at=NOW,
        writer=writer,
        signer=signer,
        signing_key_id=KEY_ID,
    )

    assert processed == 0
    assert writer.requests == {}
    assert signer.preimages == []
    assert receiver.completed == []
    assert receiver.dead_letters[0][1] == "AthenaChangeEvidenceRejected"


def test_query_replay_deduplicates_per_source_without_discarding_event_provenance() -> None:
    signer = _Signer()
    writer = _Writer()
    query_evidence = normalize_resource_graph_change(
        _resource_graph_change(),
        scope=_scope(),
        received_at=NOW,
    )

    first = ingest_resource_graph_changes(
        (query_evidence,),
        writer=writer,
        signer=signer,
        signing_key_id=KEY_ID,
    )
    replay_evidence = normalize_resource_graph_change(
        _resource_graph_change(),
        scope=_scope(),
        received_at=NOW + timedelta(minutes=5),
    )
    replay = ingest_resource_graph_changes(
        (replay_evidence,),
        writer=writer,
        signer=signer,
        signing_key_id=KEY_ID,
    )
    event_handoff = ingest_event_grid_delivery(
        _event(),
        scope=_scope(),
        received_at=NOW,
        writer=writer,
        signer=signer,
        signing_key_id=KEY_ID,
    )

    assert len(first) == 1
    assert replay == first
    persisted = ChangeEvidenceArtifact.model_validate_json(
        writer.requests[first[0].artifact.name].payload
    )
    assert persisted.evidence.received_at == NOW
    assert event_handoff is not None
    assert first[0].change_key == event_handoff.change_key
    assert first[0].deduplication_key != event_handoff.deduplication_key
    assert len(writer.requests) == 4
