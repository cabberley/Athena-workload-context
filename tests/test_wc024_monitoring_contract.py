from __future__ import annotations

import base64
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ValidationError

from athena_context.contracts import (
    MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION,
    MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
    MonitoringCollectorContract,
    MonitoringEvidenceAttestation,
    MonitoringEvidenceHandoff,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    VersionPinnedBlobReference,
    canonicalize_json,
    compute_artifact_digest,
    monitoring_handoff_preimage,
    sha256_hex,
    verify_monitoring_evidence_handoff_attestation,
)

COLLECTOR_CONTRACT_MODULE = (
    Path(__file__).parents[1]
    / "infra"
    / "wc024-monitoring-foundation"
    / "modules"
    / "monitoring-collector-contract.bicep"
)
MONITORING_FOUNDATION_MAIN = (
    Path(__file__).parents[1]
    / "infra"
    / "wc024-monitoring-foundation"
    / "main.bicep"
)


REVIEWED_VM_NAMES = (
    "athena-hackathon-client-01",
    "athena-hackathon-ecp-01",
    "athena-hackathon-ecp-02",
    "athena-hackathon-ecp-03",
    "athena-hackathon-iris-01",
    "athena-hackathon-mid-01",
    "athena-hackathon-mid-02",
    "athena-hackathon-sqlvm-01",
    "athena-hackathon-web-01",
    "athena-hackathon-web-02",
    "athena-hackathon-web-03",
)
REVIEWED_WORKLOAD_VNET_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
    "rg-athena-demo-workload/providers/Microsoft.Network/virtualNetworks/"
    "athena-hackathon-vnet"
)
REVIEWED_SIGNING_KEY_URI = (
    "https://athenademomonkv.vault.azure.net/keys/monitoring-evidence-signing/"
    "0123456789abcdef0123456789abcdef"
)
SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
MONITORING_RESOURCE_GROUP_ROOT = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-monitoring"
)
WORKLOAD_RESOURCE_GROUP_ROOT = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-workload"
)
READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
)
SIGNAL_READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/2fda1d90-37da-55d9-8ac3-132fb7bdca5d"
)
LOG_ANALYTICS_DATA_READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/3b03c2da-16b3-4a49-8834-0f8130efdd3b"
)
REVIEWED_LOG_TABLES = (
    "Heartbeat",
    "Perf",
    "InsightsMetrics",
    "Syslog",
    "VMComputer",
    "VMConnection",
    "VMBoundPort",
    "VMProcess",
    "NTANetAnalytics",
    "NWConnectionMonitorDestinationListenerResult",
    "NWConnectionMonitorDNSResult",
    "NWConnectionMonitorPathResult",
    "NWConnectionMonitorTestResult",
)
LOG_ANALYTICS_ACCESS_CONDITION = (
    "((!(ActionMatches"
    "{'Microsoft.OperationalInsights/workspaces/tables/data/read'}"
    ")) OR ("
    + " OR ".join(
        "@Resource[Microsoft.OperationalInsights/workspaces/tables:name] "
        f"StringEquals '{table_name}'"
        for table_name in REVIEWED_LOG_TABLES
    )
    + "))"
)
SIGNAL_READ_SCOPE_IDS = tuple(
    f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Compute/"
    f"virtualMachines/{vm_name}"
    for vm_name in REVIEWED_VM_NAMES
)
RESOURCE_READ_SCOPE_IDS = (
    (
        f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.Insights/"
        "dataCollectionEndpoints/athena-hackathon-linux-dce"
    ),
    (
        f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.Insights/"
        "dataCollectionRules/athena-hackathon-linux-dcr"
    ),
    (
        f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.Insights/"
        "privateLinkScopes/athena-demo-monitoring-workload-ampls"
    ),
    (
        f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.Insights/"
        "privateLinkScopes/athena-demo-monitoring-collector-ampls"
    ),
    *(
        (
            f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Compute/"
            f"virtualMachines/{vm_name}/providers/Microsoft.Insights/"
            "dataCollectionRuleAssociations/athena-linux-dcr"
        )
        for vm_name in REVIEWED_VM_NAMES
    ),
    *(
        (
            f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Compute/"
            f"virtualMachines/{vm_name}/providers/Microsoft.Insights/"
            "dataCollectionRuleAssociations/configurationAccessEndpoint"
        )
        for vm_name in REVIEWED_VM_NAMES
    ),
    (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/"
        "providers/Microsoft.Network/networkWatchers/NetworkWatcher_australiaeast/"
        "flowLogs/athena-hackathon-vnet-rg-athena-demo-workload-flowlog"
    ),
)


def test_bicep_and_python_share_one_canonical_vm_allowlist() -> None:
    source = MONITORING_FOUNDATION_MAIN.read_text(encoding="utf-8")
    block = source.split(
        "var reviewedApprovedVmNames = [",
        maxsplit=1,
    )[1].split("]", maxsplit=1)[0]
    bicep_names = tuple(
        line.strip().strip("'")
        for line in block.splitlines()
        if line.strip()
    )

    assert bicep_names == REVIEWED_VM_NAMES
    assert "? reviewedApprovedVmNames" in source


def test_workload_vnet_id_is_canonicalized_before_digesting() -> None:
    canonical = _collector_contract()
    uppercase_payload = canonical.model_dump(
        mode="json",
        by_alias=True,
    )
    uppercase_payload["workloadVirtualNetworkResourceId"] = (
        canonical.workload_virtual_network_resource_id.upper()
    )

    normalized = MonitoringCollectorContract.model_validate_json(
        json.dumps(uppercase_payload)
    )

    assert normalized.workload_virtual_network_resource_id == (
        canonical.workload_virtual_network_resource_id
    )
    assert normalized.compute_artifact_digest_value() == (
        canonical.compute_artifact_digest_value()
    )


def _collector_contract() -> MonitoringCollectorContract:
    return MonitoringCollectorContract(
        schemaVersion=MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        collectorIdentityResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-monitoring/providers/Microsoft.ManagedIdentity/"
            "userAssignedIdentities/athena-demo-monitoring-monitoring-collector-id"
        ),
        collectorIdentityClientId="00000000-0000-0000-0000-000000000001",
        monitoringResourceGroupId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-athena-demo-monitoring"
        ),
        workloadResourceGroupId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-athena-demo-workload"
        ),
        workloadVirtualNetworkResourceId=REVIEWED_WORKLOAD_VNET_ID,
        approvedVmNames=REVIEWED_VM_NAMES,
        workspaceResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-monitoring/providers/Microsoft.OperationalInsights/"
            "workspaces/athena-hackathon-law"
        ),
        dataCollectionRuleResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-monitoring/providers/Microsoft.Insights/dataCollectionRules/"
            "athena-hackathon-linux-dcr"
        ),
        dataCollectionEndpointResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-monitoring/providers/Microsoft.Insights/"
            "dataCollectionEndpoints/athena-hackathon-linux-dce"
        ),
        authorizationMode="conditionedWorkspacePlusExactResourceContext",
        workspaceAccessControlMode="workspaceAndResourceContext",
        readerRoleDefinitionId=READER_ROLE_DEFINITION_ID,
        signalReaderRoleDefinitionId=SIGNAL_READER_ROLE_DEFINITION_ID,
        logAnalyticsDataReaderRoleDefinitionId=(
            LOG_ANALYTICS_DATA_READER_ROLE_DEFINITION_ID
        ),
        logAnalyticsAllowedTables=REVIEWED_LOG_TABLES,
        logAnalyticsAccessCondition=LOG_ANALYTICS_ACCESS_CONDITION,
        resourceReadScopeIds=RESOURCE_READ_SCOPE_IDS,
        signalReadScopeIds=SIGNAL_READ_SCOPE_IDS,
        signingKeyResourceId=REVIEWED_SIGNING_KEY_URI,
        evidenceStorageAccountResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-monitoring/providers/Microsoft.Storage/storageAccounts/"
            "athenademomonstore"
        ),
        evidenceContainerName="monitoring-evidence",
        signalKinds=(
            "heartbeat",
            "perf",
            "insightsMetrics",
            "syslog",
            "disk",
            "guest",
            "vnetFlow",
            "trafficAnalytics",
        ),
        allowedReadOperations=(
            "Microsoft.OperationalInsights/workspaces/read",
            "Microsoft.OperationalInsights/workspaces/query/read",
            "Microsoft.OperationalInsights/workspaces/tables/data/read",
            "Microsoft.Compute/virtualMachines/instanceView/read",
            "Microsoft.Insights/Metrics/Read",
            "Microsoft.Insights/dataCollectionRules/read",
            "Microsoft.Insights/dataCollectionEndpoints/read",
            "Microsoft.Insights/dataCollectionRuleAssociations/read",
            "Microsoft.Insights/privateLinkScopes/read",
            "Microsoft.Network/networkWatchers/flowLogs/read",
        ),
        collectionMode="isolatedSignedCollector",
        handoffSchemaVersion=MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
        maximumEvidenceAgeSeconds=600,
        connectionMonitorMode="capabilityOnly",
        connectionMonitorDeploymentMode="capability-only",
    )


def _handoff_payload() -> dict[str, object]:
    return {
        "schemaVersion": MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
        "collectorContractDigest": _collector_contract().compute_artifact_digest_value(),
        "collectionId": "wc024-0123456789ab",
        "observedAt": datetime(2026, 9, 6, 6, 0, tzinfo=UTC),
        "evidence": VersionPinnedBlobReference(
            name="wc024-monitoring/wc024-0123456789ab/evidence.json",
            version="2026-09-06T06:00:00.0000000Z",
            contentDigest="sha256:" + "a" * 64,
        ),
    }


def _signed_handoff() -> MonitoringEvidenceHandoff:
    payload = _handoff_payload()
    signature = base64.b64encode(b"synthetic-signature").decode("ascii")
    evidence = payload["evidence"]
    assert isinstance(evidence, VersionPinnedBlobReference)
    attestation = MonitoringEvidenceAttestation(
        signatureAlgorithm="RS256",
        trustAnchorRef=REVIEWED_SIGNING_KEY_URI,
        signedPreimageDigest=compute_artifact_digest(
            {
                "domain": MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
                "handoff": {
                    **payload,
                    "evidence": evidence.model_dump(mode="json", by_alias=True),
                },
            }
        ),
        signature=signature,
    )
    return MonitoringEvidenceHandoff(**payload, collectorAttestation=attestation)


def test_collector_contract_is_exact_generic_and_deterministic() -> None:
    contract = _collector_contract()

    assert contract.canonical_json() == _collector_contract().canonical_json()
    assert contract.collection_mode == "isolatedSignedCollector"
    assert contract.connection_monitor_mode == "capabilityOnly"


def test_collector_contract_bicep_output_matches_the_production_contract() -> None:
    source = COLLECTOR_CONTRACT_MODULE.read_text(encoding="utf-8")
    output_fields = set(
        re.findall(
            r"^  (?P<field>[a-zA-Z][a-zA-Z0-9]*):",
            source.split("output collectorContract object = {", maxsplit=1)[1].split(
                "\n}", maxsplit=1
            )[0],
            flags=re.MULTILINE,
        )
    )
    expected_fields = {
        field.alias
        for field in MonitoringCollectorContract.model_fields.values()
        if field.alias is not None
    }
    bicep_output = _collector_contract().model_dump(by_alias=True)

    assert output_fields == expected_fields == set(bicep_output)
    assert MonitoringCollectorContract(**bicep_output) == _collector_contract()
    for operation in _collector_contract().allowed_read_operations:
        assert f"'{operation}'" in source


@pytest.mark.parametrize(
    "change",
    [
        {"signalKinds": ("heartbeat",) * 8},
        {"allowedReadOperations": ("Microsoft.Insights/Metrics/Read",) * 10},
        {"authorizationMode": "customRole"},
        {"workspaceAccessControlMode": "unknown"},
        {"logAnalyticsAllowedTables": ("Heartbeat",) * 13},
        {"logAnalyticsAccessCondition": "allow everything"},
        {"resourceReadScopeIds": RESOURCE_READ_SCOPE_IDS[:-1]},
        {"signalReadScopeIds": SIGNAL_READ_SCOPE_IDS[:-1]},
        {"maximumEvidenceAgeSeconds": 901},
        {"connectionMonitorMode": "configured"},
        {"unpublishedEndpointPath": "synthetic"},
    ],
)
def test_collector_contract_fails_closed_for_non_generic_configuration(
    change: dict[str, object],
) -> None:
    payload = _collector_contract().model_dump(by_alias=True)
    payload.update(change)

    with pytest.raises(ValidationError):
        MonitoringCollectorContract(**payload)


def test_signed_handoff_binds_exact_version_pinned_evidence() -> None:
    handoff = _signed_handoff()

    assert handoff.evidence.name == "wc024-monitoring/wc024-0123456789ab/evidence.json"
    assert monitoring_handoff_preimage(handoff)["domain"] == (
        MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION
    )


def test_signed_handoff_rejects_changed_reference_or_attestation_binding() -> None:
    payload = _signed_handoff().model_dump(by_alias=True)
    payload["evidence"]["contentDigest"] = "sha256:" + "b" * 64  # type: ignore[index]

    with pytest.raises(ValidationError):
        MonitoringEvidenceHandoff(**payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "workloadResourceGroupId",
            "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/"
            "rg-athena-demo-workload",
        ),
        (
            "workspaceResourceId",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-workload/providers/Microsoft.OperationalInsights/workspaces/"
            "athena-demo-monitoring-law",
        ),
        (
            "workloadVirtualNetworkResourceId",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-workload/providers/Microsoft.Network/virtualNetworks/"
            "other-vnet",
        ),
        ("approvedVmNames", ("athena-hackathon-web-01",) * 11),
        ("signingKeyResourceId", "not-a-versioned-key-uri"),
        ("evidenceStorageAccountResourceId", "not-a-resource-id"),
    ],
)
def test_collector_contract_fails_closed_for_invalid_scope_or_resource_ids(
    field: str,
    value: str,
) -> None:
    payload = _collector_contract().model_dump(by_alias=True)
    payload[field] = value

    with pytest.raises(ValidationError):
        MonitoringCollectorContract(**payload)


def _trusted_signed_handoff() -> tuple[
    MonitoringEvidenceHandoff,
    MonitoringCollectorContract,
    TrustedKeyAnchor,
    TrustedKeyRecord,
]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    handoff = _signed_handoff()
    signature = base64.b64encode(
        private_key.sign(
            canonicalize_json(monitoring_handoff_preimage(handoff)).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    ).decode("ascii")
    attestation = handoff.collector_attestation.model_copy(update={"signature": signature})
    signed_handoff = handoff.model_copy(update={"collector_attestation": attestation})
    public_key = private_key.public_key()
    fingerprint = sha256_hex(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    anchor = TrustedKeyAnchor.from_key_vault_key_id(
        attestation.trust_anchor_ref,
        public_key_fingerprint=fingerprint,
    )
    record = TrustedKeyRecord(
        anchor=anchor,
        public_key=public_key,
        enabled=True,
        activated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    return signed_handoff, _collector_contract(), anchor, record


def test_signed_handoff_requires_the_exact_active_collector_key() -> None:
    signed_handoff, contract, anchor, record = _trusted_signed_handoff()

    verify_monitoring_evidence_handoff_attestation(
        signed_handoff,
        as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
        reviewed_collector_contract=contract,
        trusted_key_anchor=anchor,
        key_resolver=lambda _: record,
    )

    with pytest.raises(ValueError, match="expected collector contract"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest="sha256:" + "b" * 64,
            reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
            reviewed_signing_key_resource_id=contract.signing_key_resource_id,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="trusted key"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            reviewed_collector_contract=contract,
            trusted_key_anchor=TrustedKeyAnchor.from_key_vault_key_id(
                "https://athenademomonkv.vault.azure.net/keys/another-key/"
                "0123456789abcdef0123456789abcdef",
                public_key_fingerprint=anchor.public_key_fingerprint,
            ),
            key_resolver=lambda _: record,
        )

    wrong_record_anchor = TrustedKeyAnchor.from_key_vault_key_id(
        "https://athenademomonkv.vault.azure.net/keys/another-key/"
        "0123456789abcdef0123456789abcdef",
        public_key_fingerprint=anchor.public_key_fingerprint,
    )
    wrong_record = TrustedKeyRecord(
        anchor=wrong_record_anchor,
        public_key=record.public_key,
        enabled=True,
        activated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="key is not trusted"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            reviewed_collector_contract=contract,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: wrong_record,
        )

    payload = _signed_handoff().model_dump(by_alias=True)
    payload["evidence"]["name"] = "wc024-monitoring/other/evidence.json"  # type: ignore[index]

    with pytest.raises(ValidationError):
        MonitoringEvidenceHandoff(**payload)


def test_signed_handoff_binds_reviewed_signing_key_to_trusted_anchor() -> None:
    signed_handoff, contract, anchor, record = _trusted_signed_handoff()
    other_key_uri = (
        "https://athenademomonkv.vault.azure.net/keys/other-monitoring-key/"
        "0123456789abcdef0123456789abcdef"
    )

    with pytest.raises(ValueError, match="trusted key"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest=signed_handoff.collector_contract_digest,
            reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
            reviewed_signing_key_resource_id=other_key_uri,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="expected collector contract"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            reviewed_collector_contract=contract.model_copy(
                update={"signing_key_resource_id": other_key_uri}
            ),
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="reviewed signing key"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest=signed_handoff.collector_contract_digest,
            reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )


def test_signed_handoff_rejects_key_retired_or_expired_at_trusted_as_of() -> None:
    signed_handoff, contract, anchor, record = _trusted_signed_handoff()

    for stale_record in (
        TrustedKeyRecord(
            anchor=anchor,
            public_key=record.public_key,
            enabled=True,
            activated_at=datetime(2026, 1, 1, tzinfo=UTC),
            retired_at=datetime(2026, 9, 6, 6, 5, tzinfo=UTC),
        ),
        TrustedKeyRecord(
            anchor=anchor,
            public_key=record.public_key,
            enabled=True,
            activated_at=datetime(2026, 1, 1, tzinfo=UTC),
            expires_at=datetime(2026, 9, 6, 6, 5, tzinfo=UTC),
        ),
    ):
        with pytest.raises(ValueError, match="key is not trusted"):
            verify_monitoring_evidence_handoff_attestation(
                signed_handoff,
                as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
                reviewed_collector_contract=contract,
                trusted_key_anchor=anchor,
                key_resolver=lambda _, stale_record=stale_record: stale_record,
            )


def test_signed_handoff_requires_trusted_as_of_and_reviewed_freshness() -> None:
    signed_handoff, contract, anchor, record = _trusted_signed_handoff()

    verify_monitoring_evidence_handoff_attestation(
        signed_handoff,
        as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
        expected_collector_contract_digest=signed_handoff.collector_contract_digest,
        reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
        reviewed_signing_key_resource_id=contract.signing_key_resource_id,
        trusted_key_anchor=anchor,
        key_resolver=lambda _: record,
    )

    with pytest.raises(ValueError, match="future"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 5, 59, 59, tzinfo=UTC),
            reviewed_collector_contract=contract,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="reviewed maximum age"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, 1, tzinfo=UTC),
            reviewed_collector_contract=contract,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="trusted UTC"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10),
            reviewed_collector_contract=contract,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="reviewed maximum evidence age"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest=signed_handoff.collector_contract_digest,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )
