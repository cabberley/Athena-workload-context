from __future__ import annotations

import base64
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel, ValidationError

from athena_context.contracts import (
    MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
    MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
    MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION,
    MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
    MONITORING_IDENTITY_PROOF_AUDIENCE,
    MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS,
    MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
    MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
    MonitoringAcquisitionExchange,
    MonitoringAcquisitionReceipt,
    MonitoringAcquisitionWireAttempt,
    MonitoringCollectorContract,
    MonitoringEffectiveRbacInventory,
    MonitoringEvidenceAttestation,
    MonitoringEvidenceHandoff,
    MonitoringIdentityProof,
    MonitoringSelectedIncident,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    VersionPinnedBlobReference,
    canonicalize_json,
    compute_artifact_digest,
    monitoring_acquisition_receipt_preimage,
    monitoring_handoff_preimage,
    sha256_hex,
    verify_monitoring_acquisition_receipt_attestation,
    verify_monitoring_evidence_handoff_attestation,
)
from athena_context.monitoring_incident import (
    build_selected_incident,
)

COLLECTOR_CONTRACT_MODULE = (
    Path(__file__).parents[1]
    / "infra"
    / "wc024-monitoring-foundation"
    / "modules"
    / "monitoring-collector-contract.bicep"
)
EFFECTIVE_RBAC_INVENTORY_EXAMPLE = (
    Path(__file__).parents[1]
    / "infra"
    / "wc024-monitoring-foundation"
    / "effective-rbac-inventory.example.json"
)
MONITORING_FOUNDATION_MAIN = (
    Path(__file__).parents[1] / "infra" / "wc024-monitoring-foundation" / "main.bicep"
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
WORKSPACE_ID = (
    f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.OperationalInsights/"
    "workspaces/athena-hackathon-law"
)
RESOURCE_CONTEXT_TABLES = (
    "Heartbeat",
    "Perf",
    "InsightsMetrics",
    "Syslog",
    "VMConnection",
)
RESOURCE_CONTEXT_TABLE_PLANS = tuple(
    {
        "table": table,
        "plan": "Analytics",
        "tableResourceId": f"{WORKSPACE_ID}/tables/{table}",
    }
    for table in RESOURCE_CONTEXT_TABLES
)
READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
)
SIGNAL_READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/2fda1d90-37da-55d9-8ac3-132fb7bdca5d"
)
RESOURCE_LOG_READER_ROLE_DEFINITION_ID = (
    f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Authorization/"
    "roleDefinitions/f33a4363-5d9a-5d50-9871-c08582234978"
)
LOG_ANALYTICS_DATA_READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/3b03c2da-16b3-4a49-8834-0f8130efdd3b"
)
IP_FLOW_VERIFY_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/"
    "providers/Microsoft.Authorization/"
    "roleDefinitions/3728cdf6-4efd-5282-bdfc-63b7872fd801"
)
NETWORK_WATCHER_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/"
    "providers/Microsoft.Network/networkWatchers/NetworkWatcher_australiaeast"
)
IP_FLOW_VERIFY_OPERATIONS = (
    "Microsoft.Network/networkWatchers/ipFlowVerify/action",
    "Microsoft.Network/networkWatchers/ipFlowVerify/read",
)
RESOURCE_HEALTH_ROLE_DEFINITION_ID = (
    f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Authorization/"
    "roleDefinitions/0790d6f2-9553-5b63-84ac-56596b7e4072"
)
PREVIOUS_RESOURCE_HEALTH_OPERATIONS = ("Microsoft.ResourceHealth/AvailabilityStatuses/read",)
RESOURCE_HEALTH_OPERATIONS = ("Microsoft.ResourceHealth/AvailabilityStatuses/current/read",)
PREVIOUS_RESOURCE_LOG_OPERATIONS = (
    "Microsoft.Insights/logs/Heartbeat/read",
    "Microsoft.Insights/logs/NTANetAnalytics/read",
    "Microsoft.Insights/logs/NWConnectionMonitorTestResult/read",
    "Microsoft.Insights/logs/VMConnection/read",
)
RESOURCE_LOG_OPERATIONS = (
    "Microsoft.Insights/Logs/Heartbeat/Read",
    "Microsoft.Insights/Logs/Perf/Read",
    "Microsoft.Insights/Logs/InsightsMetrics/Read",
    "Microsoft.Insights/Logs/Syslog/Read",
    "Microsoft.Insights/Logs/VMConnection/Read",
)
MEASURED_RBAC_FIELDS = (
    "signalReaderRoleName",
    "resourceLogReaderRoleDefinitionId",
    "resourceLogReaderRoleName",
    "resourceLogAllowedOperations",
    "resourceLogReadScopeIds",
    "ipFlowVerifyRoleName",
    "resourceHealthRoleName",
    "signingKeyArmResourceId",
    "signingKeyCryptoUserRoleDefinitionId",
    "evidenceContainerResourceId",
    "evidenceWriterRoleDefinitionId",
    "effectiveRbacInventory",
    "workspaceResourceContextAccessEnabled",
    "workspaceSkuName",
    "resourceContextTablePlans",
    "resourceIdColumn",
    "logQueryPreferHeader",
    "flowTableAcquisitionMode",
    "rbacAttestorIdentityResourceId",
    "rbacAttestorIdentityClientId",
    "rbacAttestorPrincipalId",
    "rbacAttestorTenantId",
    "rbacAttestorRoleDefinitionId",
    "rbacAttestorRoleName",
    "rbacAttestorScopeId",
    "rbacAttestorAllowedOperations",
    "rbacAttestorIdentitySeparationEnforced",
)
V8_ONLY_CONTRACT_FIELDS = (
    "workspaceResourceContextAccessEnabled",
    "workspaceSkuName",
    "resourceContextTablePlans",
    "resourceIdColumn",
    "logQueryPreferHeader",
    "flowTableAcquisitionMode",
    "rbacAttestorIdentityResourceId",
    "rbacAttestorIdentityClientId",
    "rbacAttestorPrincipalId",
    "rbacAttestorTenantId",
    "rbacAttestorRoleDefinitionId",
    "rbacAttestorRoleName",
    "rbacAttestorScopeId",
    "rbacAttestorAllowedOperations",
    "rbacAttestorIdentitySeparationEnforced",
)
SIGNAL_READER_ROLE_NAME = "Athena WC016 Approved Signal Reader synthetic00000"
RESOURCE_LOG_READER_ROLE_NAME = "Athena WC-028 VM Resource Log Reader"
IP_FLOW_VERIFY_ROLE_NAME = "Athena WC-028 Network Watcher IP Flow Verify"
RESOURCE_HEALTH_ROLE_NAME = "Athena WC-028 VM Resource Health Reader"
EVIDENCE_CONTAINER_RESOURCE_ID = (
    f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.Storage/storageAccounts/"
    "athenademomonstore/blobServices/default/containers/monitoring-evidence"
)
EVIDENCE_WRITER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe"
)
SIGNING_KEY_ARM_RESOURCE_ID = (
    f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.KeyVault/vaults/"
    "athenademomonkv/keys/monitoring-evidence-signing"
)
SIGNING_KEY_CRYPTO_USER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/12338af0-0e69-4776-bea7-57ae8d297424"
)
COLLECTOR_TENANT_ID = "00000000-0000-0000-0000-000000000003"
RBAC_ATTESTOR_ID = (
    f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/athena-demo-monitoring-monitoring-rbac-attestor-id"
)
RBAC_ATTESTOR_CLIENT_ID = "44444444-4444-4444-4444-444444444444"
RBAC_ATTESTOR_PRINCIPAL_ID = "55555555-5555-5555-5555-555555555555"
RBAC_ATTESTOR_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/2a8d9aea-2688-5841-a7e4-82f23d0f1bac"
)
RBAC_ATTESTOR_ROLE_NAME = "Athena WC-028 Effective RBAC Attestor"
RBAC_ATTESTOR_OPERATIONS = (
    "Microsoft.Authorization/denyAssignments/read",
    "Microsoft.Authorization/roleAssignmentScheduleInstances/read",
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/roleDefinitions/read",
)


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items() if item is not None}
    return value


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
    f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Compute/virtualMachines/{vm_name}"
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
    bicep_names = tuple(line.strip().strip("'") for line in block.splitlines() if line.strip())

    assert bicep_names == REVIEWED_VM_NAMES


def test_acquisition_contract_resolves_and_separates_actual_context_uami() -> None:
    source = MONITORING_FOUNDATION_MAIN.read_text(encoding="utf-8")

    assert "param athenaContextIdentityResourceId string" in source
    assert (
        "resource athenaContextIdentity "
        "'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing"
    ) in source
    assert "collectorIdentityResourceId) != toLower(athenaContextIdentity.id)" in source
    assert (
        "collectorIdentityPrincipalId) != toLower(athenaContextIdentity.properties.principalId)"
    ) in source
    assert "physicalIdentitySeparationEnforced: acquisitionIdentitySeparation" in source
    assert "collectorTenantId: monitoringEvidenceSeams.outputs.collectorIdentityTenantId" in source
    assert "module monitoringRbacAttestor" in source
    assert (
        "rbacAttestorPrincipalId: monitoringEvidenceSeams.outputs.rbacAttestorIdentityPrincipalId"
    ) in source
    assert "flowTableAcquisitionMode: 'unsupportedUnavailable'" in (
        Path(__file__).parents[1]
        / "infra"
        / "wc024-monitoring-foundation"
        / "modules"
        / "monitoring-collector-contract.bicep"
    ).read_text(encoding="utf-8")
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

    normalized = MonitoringCollectorContract.model_validate_json(json.dumps(uppercase_payload))

    assert normalized.workload_virtual_network_resource_id == (
        canonical.workload_virtual_network_resource_id
    )
    assert normalized.compute_artifact_digest_value() == (canonical.compute_artifact_digest_value())


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
        workspaceResourceId=WORKSPACE_ID,
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
        logAnalyticsDataReaderRoleDefinitionId=(LOG_ANALYTICS_DATA_READER_ROLE_DEFINITION_ID),
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


def _effective_rbac_grant(
    *,
    principal_id: str,
    role_definition_id: str,
    role_definition_name: str,
    assignment_scope_ids: tuple[str, ...],
    condition: str | None = None,
    condition_version: str | None = None,
    assigned_principal_id: str | None = None,
    assigned_principal_type: str = "ServicePrincipal",
    inheritance: str = "direct",
    group_derived: bool = False,
) -> dict[str, object]:
    assigned_principal_id = principal_id if assigned_principal_id is None else assigned_principal_id
    payload: dict[str, object] = {
        "assignedPrincipalId": assigned_principal_id,
        "assignedPrincipalType": assigned_principal_type,
        "effectivePrincipalId": principal_id,
        "roleDefinitionId": role_definition_id.casefold(),
        "roleDefinitionName": role_definition_name,
        "assignmentScopeIds": tuple(sorted(item.casefold() for item in assignment_scope_ids)),
        "inheritance": inheritance,
        "groupDerived": group_derived,
    }
    if condition is not None:
        payload["condition"] = condition
        payload["conditionVersion"] = condition_version
    return {
        **payload,
        "grantDigest": compute_artifact_digest(_json_value(payload)),
    }


def _effective_rbac_role_definition(
    *,
    role_definition_id: str,
    role_definition_name: str,
    actions: tuple[str, ...] = (),
    not_actions: tuple[str, ...] = (),
    data_actions: tuple[str, ...] = (),
    not_data_actions: tuple[str, ...] = (),
) -> dict[str, object]:
    normalized_payload: dict[str, object] = {
        "roleDefinitionId": role_definition_id.casefold(),
        "roleDefinitionName": role_definition_name,
        "actions": tuple(sorted(item.casefold() for item in actions)),
        "notActions": tuple(sorted(item.casefold() for item in not_actions)),
        "dataActions": tuple(sorted(item.casefold() for item in data_actions)),
        "notDataActions": tuple(sorted(item.casefold() for item in not_data_actions)),
    }
    payload = {
        **normalized_payload,
        "rawDefinitionDigest": compute_artifact_digest(
            {"rawRoleDefinition": _json_value(normalized_payload)}
        ),
    }
    return {
        **payload,
        "definitionDigest": compute_artifact_digest(_json_value(payload)),
    }


def _effective_rbac_principal_evidence(
    *,
    principal_id: str,
    target_scope_ids: tuple[str, ...],
    transitive_group_ids: tuple[str, ...] = (),
) -> dict[str, object]:
    targets = tuple(sorted(item.casefold() for item in target_scope_ids))
    target_digests = tuple(
        compute_artifact_digest(
            {
                "principalId": principal_id.casefold(),
                "targetScopeId": target,
                "queryFilter": "atScope() and assignedTo(principalId)",
            }
        )
        for target in targets
    )
    payload: dict[str, object] = {
        "principalId": principal_id.casefold(),
        "queryFilter": "atScope() and assignedTo(principalId)",
        "targetScopeIds": targets,
        "firstReadTargetDigests": target_digests,
        "secondReadTargetDigests": target_digests,
        "roleAssignmentRawPageDigests": (
            compute_artifact_digest(
                {
                    "principalId": principal_id.casefold(),
                    "page": "roleAssignments",
                }
            ),
        ),
        "transitiveGroupIds": tuple(sorted(item.casefold() for item in transitive_group_ids)),
        "transitiveGroupRawPageDigests": (
            compute_artifact_digest(
                {
                    "principalId": principal_id.casefold(),
                    "page": "transitiveGroups",
                }
            ),
        ),
        "allPagesRetrieved": True,
    }
    return {
        **payload,
        "evidenceDigest": compute_artifact_digest(_json_value(payload)),
    }


def _effective_rbac_inventory(payload: dict[str, object]) -> dict[str, object]:
    principal_id = str(payload["monitoringReaderPrincipalId"])
    grants = (
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=str(payload["readerRoleDefinitionId"]),
            role_definition_name="Reader",
            assignment_scope_ids=tuple(payload["resourceReadScopeIds"]),
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=str(payload["signalReaderRoleDefinitionId"]),
            role_definition_name=SIGNAL_READER_ROLE_NAME,
            assignment_scope_ids=tuple(payload["signalReadScopeIds"]),
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=RESOURCE_LOG_READER_ROLE_DEFINITION_ID,
            role_definition_name=RESOURCE_LOG_READER_ROLE_NAME,
            assignment_scope_ids=SIGNAL_READ_SCOPE_IDS,
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=RESOURCE_HEALTH_ROLE_DEFINITION_ID,
            role_definition_name=RESOURCE_HEALTH_ROLE_NAME,
            assignment_scope_ids=SIGNAL_READ_SCOPE_IDS,
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=EVIDENCE_WRITER_ROLE_DEFINITION_ID,
            role_definition_name="Storage Blob Data Contributor",
            assignment_scope_ids=(EVIDENCE_CONTAINER_RESOURCE_ID,),
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=SIGNING_KEY_CRYPTO_USER_ROLE_DEFINITION_ID,
            role_definition_name="Key Vault Crypto User",
            assignment_scope_ids=(SIGNING_KEY_ARM_RESOURCE_ID,),
        ),
    )
    ordered_grants = tuple(sorted(grants, key=lambda item: str(item["grantDigest"])))
    role_definitions = tuple(
        sorted(
            (
                _effective_rbac_role_definition(
                    role_definition_id=str(payload["readerRoleDefinitionId"]),
                    role_definition_name="Reader",
                    actions=("*/read",),
                ),
                _effective_rbac_role_definition(
                    role_definition_id=str(payload["signalReaderRoleDefinitionId"]),
                    role_definition_name=SIGNAL_READER_ROLE_NAME,
                    actions=(
                        "Microsoft.Compute/virtualMachines/instanceView/read",
                        "Microsoft.Insights/metrics/read",
                    ),
                ),
                _effective_rbac_role_definition(
                    role_definition_id=RESOURCE_LOG_READER_ROLE_DEFINITION_ID,
                    role_definition_name=RESOURCE_LOG_READER_ROLE_NAME,
                    actions=RESOURCE_LOG_OPERATIONS,
                ),
                _effective_rbac_role_definition(
                    role_definition_id=RESOURCE_HEALTH_ROLE_DEFINITION_ID,
                    role_definition_name=RESOURCE_HEALTH_ROLE_NAME,
                    actions=RESOURCE_HEALTH_OPERATIONS,
                ),
                _effective_rbac_role_definition(
                    role_definition_id=EVIDENCE_WRITER_ROLE_DEFINITION_ID,
                    role_definition_name="Storage Blob Data Contributor",
                    data_actions=(
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*",
                    ),
                ),
                _effective_rbac_role_definition(
                    role_definition_id=SIGNING_KEY_CRYPTO_USER_ROLE_DEFINITION_ID,
                    role_definition_name="Key Vault Crypto User",
                    data_actions=(
                        "Microsoft.KeyVault/vaults/keys/read",
                        "Microsoft.KeyVault/vaults/keys/sign/action",
                    ),
                ),
                _effective_rbac_role_definition(
                    role_definition_id=RBAC_ATTESTOR_ROLE_DEFINITION_ID,
                    role_definition_name=RBAC_ATTESTOR_ROLE_NAME,
                    actions=RBAC_ATTESTOR_OPERATIONS,
                ),
            ),
            key=lambda item: str(item["roleDefinitionId"]),
        )
    )
    target_scope_ids = tuple(
        sorted(
            {
                f"/subscriptions/{SUBSCRIPTION_ID}",
                MONITORING_RESOURCE_GROUP_ROOT.casefold(),
                WORKLOAD_RESOURCE_GROUP_ROOT.casefold(),
                "/providers/microsoft.management/managementgroups/synthetic-root",
                *(
                    str(scope).casefold()
                    for grant in ordered_grants
                    for scope in tuple(grant["assignmentScopeIds"])
                ),
            }
        )
    )
    collector_principal_evidence = _effective_rbac_principal_evidence(
        principal_id=principal_id,
        target_scope_ids=target_scope_ids,
    )
    context_principal_evidence = _effective_rbac_principal_evidence(
        principal_id=str(payload["athenaContextPrincipalId"]),
        target_scope_ids=target_scope_ids,
    )
    role_definition_page_digest = compute_artifact_digest(
        {"page": "roleDefinitions", "roles": _json_value(role_definitions)}
    )
    deny_page_digest = compute_artifact_digest({"page": "denyAssignments", "items": []})
    pim_page_digest = compute_artifact_digest(
        {"page": "roleAssignmentScheduleInstances", "items": []}
    )
    raw_snapshot_digest = compute_artifact_digest(
        _json_value(
            {
                "collectorPrincipalEvidenceDigest": (
                    collector_principal_evidence["evidenceDigest"]
                ),
                "athenaContextPrincipalEvidenceDigest": (
                    context_principal_evidence["evidenceDigest"]
                ),
                "roleDefinitionRawPageDigests": (role_definition_page_digest,),
                "denyAssignmentRawPageDigests": (deny_page_digest,),
                "pimScheduleInstanceRawPageDigests": (pim_page_digest,),
                "roleDefinitionRawDigests": tuple(
                    item["rawDefinitionDigest"] for item in role_definitions
                ),
                "denyAssignmentRawDigests": (),
                "pimScheduleInstanceRawDigests": (),
            }
        )
    )
    inventory_payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringEffectiveRbacInventory.v2",
        "collectionRunId": "monitoring-rbac-" + "a" * 32,
        "tenantId": COLLECTOR_TENANT_ID,
        "subscriptionId": SUBSCRIPTION_ID,
        "collectorPrincipalId": principal_id,
        "athenaContextPrincipalId": str(payload["athenaContextPrincipalId"]),
        "attestorIdentityResourceId": RBAC_ATTESTOR_ID.casefold(),
        "attestorClientId": RBAC_ATTESTOR_CLIENT_ID,
        "attestorPrincipalId": RBAC_ATTESTOR_PRINCIPAL_ID,
        "attestorTenantId": COLLECTOR_TENANT_ID,
        "collectedAt": datetime(2026, 9, 10, 1, 55, tzinfo=UTC),
        "expiresAt": datetime(2026, 9, 10, 2, 10, tzinfo=UTC),
        "managementGroupAncestry": (
            "/providers/microsoft.management/managementgroups/synthetic-root",
        ),
        "ancestorScopeCollectionComplete": True,
        "subscriptionDescendantCollectionComplete": True,
        "groupMembershipCollectionComplete": True,
        "roleDefinitionCollectionComplete": True,
        "denyAssignmentCollectionComplete": True,
        "pimScheduleInstanceCollectionComplete": True,
        "signalReaderRoleActions": tuple(
            sorted(
                (
                    "microsoft.compute/virtualmachines/instanceview/read",
                    "microsoft.insights/metrics/read",
                )
            )
        ),
        "resourceLogReaderRoleActions": tuple(
            sorted(item.casefold() for item in RESOURCE_LOG_OPERATIONS)
        ),
        "resourceHealthRoleActions": tuple(item.casefold() for item in RESOURCE_HEALTH_OPERATIONS),
        "collectorSecurityGroupIds": (),
        "athenaContextSecurityGroupIds": (),
        "collectorGrants": ordered_grants,
        "athenaContextGrants": (),
        "collectorPrincipalEvidence": collector_principal_evidence,
        "athenaContextPrincipalEvidence": context_principal_evidence,
        "roleDefinitions": role_definitions,
        "denyAssignments": (),
        "activePimScheduleInstances": (),
        "roleDefinitionRawPageDigests": (role_definition_page_digest,),
        "denyAssignmentRawPageDigests": (deny_page_digest,),
        "pimScheduleInstanceRawPageDigests": (pim_page_digest,),
        "firstRawSnapshotDigest": raw_snapshot_digest,
        "secondRawSnapshotDigest": raw_snapshot_digest,
        "repeatedReadStable": True,
        "assignmentCount": sum(len(tuple(item["assignmentScopeIds"])) for item in ordered_grants),
        "sourceReference": VersionPinnedBlobReference(
            name=("monitoring-rbac/monitoring-rbac-" + "a" * 32 + "/effective-rbac-inventory.json"),
            version="2026-09-10T01:55:00.0000000Z",
            contentDigest="sha256:" + "e" * 64,
        ),
        "sourceManifestDigest": "sha256:" + "e" * 64,
    }
    return {
        **inventory_payload,
        "inventoryDigest": compute_artifact_digest(_json_value(inventory_payload)),
    }


def _recompute_effective_rbac_inventory(
    inventory: dict[str, object],
) -> None:
    grants = tuple(
        sorted(
            tuple(inventory["collectorGrants"]),
            key=lambda item: str(item["grantDigest"]),
        )
    )
    inventory["collectorGrants"] = grants
    inventory["assignmentCount"] = sum(len(tuple(item["assignmentScopeIds"])) for item in grants)
    if inventory.get("schemaVersion") == "athena.wc028MonitoringEffectiveRbacInventory.v2":
        collector_evidence = inventory["collectorPrincipalEvidence"]
        context_evidence = inventory["athenaContextPrincipalEvidence"]
        assert isinstance(collector_evidence, dict)
        assert isinstance(context_evidence, dict)
        raw_snapshot_digest = compute_artifact_digest(
            _json_value(
                {
                    "collectorPrincipalEvidenceDigest": (collector_evidence["evidenceDigest"]),
                    "athenaContextPrincipalEvidenceDigest": (context_evidence["evidenceDigest"]),
                    "roleDefinitionRawPageDigests": (inventory["roleDefinitionRawPageDigests"]),
                    "denyAssignmentRawPageDigests": (inventory["denyAssignmentRawPageDigests"]),
                    "pimScheduleInstanceRawPageDigests": (
                        inventory["pimScheduleInstanceRawPageDigests"]
                    ),
                    "roleDefinitionRawDigests": tuple(
                        item["rawDefinitionDigest"] for item in tuple(inventory["roleDefinitions"])
                    ),
                    "denyAssignmentRawDigests": tuple(
                        item["rawAssignmentDigest"] for item in tuple(inventory["denyAssignments"])
                    ),
                    "pimScheduleInstanceRawDigests": tuple(
                        item["rawInstanceDigest"]
                        for item in tuple(inventory["activePimScheduleInstances"])
                    ),
                }
            )
        )
        inventory["firstRawSnapshotDigest"] = raw_snapshot_digest
        inventory["secondRawSnapshotDigest"] = raw_snapshot_digest
    inventory.pop("inventoryDigest", None)
    inventory["inventoryDigest"] = compute_artifact_digest(_json_value(inventory))


def _recompute_principal_evidence(evidence: dict[str, object]) -> None:
    evidence.pop("evidenceDigest", None)
    evidence["evidenceDigest"] = compute_artifact_digest(_json_value(evidence))


def _deny_assignment(
    *,
    principal_id: str,
    actions: tuple[str, ...],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "denyAssignmentId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/denyAssignments/"
            "66666666-6666-6666-6666-666666666666"
        ).casefold(),
        "scopeId": f"/subscriptions/{SUBSCRIPTION_ID}",
        "principalIds": (principal_id,),
        "excludedPrincipalIds": (),
        "actions": tuple(sorted(item.casefold() for item in actions)),
        "notActions": (),
        "dataActions": (),
        "notDataActions": (),
        "doNotApplyToChildScopes": False,
        "rawAssignmentDigest": "sha256:" + "6" * 64,
    }
    return {
        **payload,
        "denyAssignmentDigest": compute_artifact_digest(_json_value(payload)),
    }


def _pim_schedule_instance(
    *,
    principal_id: str,
    role_definition_id: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "scheduleInstanceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleAssignmentScheduleInstances/"
            "77777777-7777-7777-7777-777777777777"
        ).casefold(),
        "principalId": principal_id,
        "roleDefinitionId": role_definition_id.casefold(),
        "scopeId": f"/subscriptions/{SUBSCRIPTION_ID}",
        "assignmentType": "Activated",
        "startAt": datetime(2026, 9, 10, 1, 50, tzinfo=UTC),
        "endAt": datetime(2026, 9, 10, 2, 5, tzinfo=UTC),
        "rawInstanceDigest": "sha256:" + "7" * 64,
    }
    return {
        **payload,
        "instanceDigest": compute_artifact_digest(_json_value(payload)),
    }


def _previous_effective_rbac_inventory(
    payload: dict[str, object],
) -> dict[str, object]:
    inventory = _effective_rbac_inventory(payload)
    ip_flow_grant = _effective_rbac_grant(
        principal_id=str(payload["monitoringReaderPrincipalId"]),
        role_definition_id=IP_FLOW_VERIFY_ROLE_DEFINITION_ID,
        role_definition_name=IP_FLOW_VERIFY_ROLE_NAME,
        assignment_scope_ids=(NETWORK_WATCHER_RESOURCE_ID,),
    )
    inventory["schemaVersion"] = "athena.wc028MonitoringEffectiveRbacInventory.v1"
    inventory["resourceLogReaderRoleActions"] = tuple(
        sorted(item.casefold() for item in PREVIOUS_RESOURCE_LOG_OPERATIONS)
    )
    inventory["ipFlowVerifyRoleActions"] = tuple(
        sorted(item.casefold() for item in IP_FLOW_VERIFY_OPERATIONS)
    )
    inventory["resourceHealthRoleActions"] = tuple(
        item.casefold() for item in PREVIOUS_RESOURCE_HEALTH_OPERATIONS
    )
    inventory["collectorGrants"] = tuple(
        sorted(
            (*tuple(inventory["collectorGrants"]), ip_flow_grant),
            key=lambda item: str(item["grantDigest"]),
        )
    )
    for field in (
        "attestorIdentityResourceId",
        "attestorClientId",
        "attestorPrincipalId",
        "attestorTenantId",
        "denyAssignmentCollectionComplete",
        "pimScheduleInstanceCollectionComplete",
        "collectorPrincipalEvidence",
        "athenaContextPrincipalEvidence",
        "roleDefinitions",
        "denyAssignments",
        "activePimScheduleInstances",
        "roleDefinitionRawPageDigests",
        "denyAssignmentRawPageDigests",
        "pimScheduleInstanceRawPageDigests",
        "firstRawSnapshotDigest",
        "secondRawSnapshotDigest",
        "repeatedReadStable",
    ):
        inventory.pop(field)
    _recompute_effective_rbac_inventory(inventory)
    return inventory


def _acquisition_collector_contract() -> MonitoringCollectorContract:
    payload = _collector_contract().model_dump(mode="python", by_alias=True)
    payload.update(
        {
            "schemaVersion": MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            "collectorTenantId": COLLECTOR_TENANT_ID,
            "monitoringReaderPrincipalId": "11111111-1111-1111-1111-111111111111",
            "athenaContextIdentityId": (
                f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/"
                "Microsoft.ManagedIdentity/userAssignedIdentities/synthetic-athena-context"
            ),
            "athenaContextPrincipalId": "22222222-2222-2222-2222-222222222222",
            "physicalIdentitySeparationEnforced": True,
            "signalReaderRoleName": SIGNAL_READER_ROLE_NAME,
            "resourceLogReaderRoleDefinitionId": (RESOURCE_LOG_READER_ROLE_DEFINITION_ID),
            "resourceLogReaderRoleName": RESOURCE_LOG_READER_ROLE_NAME,
            "resourceLogAllowedOperations": RESOURCE_LOG_OPERATIONS,
            "resourceLogReadScopeIds": SIGNAL_READ_SCOPE_IDS,
            "workspaceResourceContextAccessEnabled": True,
            "workspaceSkuName": "PerGB2018",
            "resourceContextTablePlans": RESOURCE_CONTEXT_TABLE_PLANS,
            "resourceIdColumn": "_ResourceId",
            "logQueryPreferHeader": "include-permissions=true",
            "flowTableAcquisitionMode": "unsupportedUnavailable",
            "rbacAttestorIdentityResourceId": RBAC_ATTESTOR_ID,
            "rbacAttestorIdentityClientId": RBAC_ATTESTOR_CLIENT_ID,
            "rbacAttestorPrincipalId": RBAC_ATTESTOR_PRINCIPAL_ID,
            "rbacAttestorTenantId": COLLECTOR_TENANT_ID,
            "rbacAttestorRoleDefinitionId": RBAC_ATTESTOR_ROLE_DEFINITION_ID,
            "rbacAttestorRoleName": RBAC_ATTESTOR_ROLE_NAME,
            "rbacAttestorScopeId": f"/subscriptions/{SUBSCRIPTION_ID}",
            "rbacAttestorAllowedOperations": RBAC_ATTESTOR_OPERATIONS,
            "rbacAttestorIdentitySeparationEnforced": True,
            "identityProofAudience": MONITORING_IDENTITY_PROOF_AUDIENCE,
            "identityProofTokenVersion": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
            "identityProofRequiredRole": MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
            "identityProofMaximumLifetimeSeconds": (
                MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
            ),
            "resourceHealthRoleDefinitionId": RESOURCE_HEALTH_ROLE_DEFINITION_ID,
            "resourceHealthRoleName": RESOURCE_HEALTH_ROLE_NAME,
            "resourceHealthScopeIds": SIGNAL_READ_SCOPE_IDS,
            "resourceHealthAllowedOperations": RESOURCE_HEALTH_OPERATIONS,
            "allowedReadOperations": (
                *(
                    operation
                    for operation in payload["allowedReadOperations"]
                    if not operation.startswith("Microsoft.OperationalInsights/workspaces")
                ),
                *RESOURCE_HEALTH_OPERATIONS,
                *RESOURCE_LOG_OPERATIONS,
            ),
            "signingKeyArmResourceId": SIGNING_KEY_ARM_RESOURCE_ID,
            "signingKeyCryptoUserRoleDefinitionId": (SIGNING_KEY_CRYPTO_USER_ROLE_DEFINITION_ID),
            "evidenceContainerResourceId": EVIDENCE_CONTAINER_RESOURCE_ID,
            "evidenceWriterRoleDefinitionId": EVIDENCE_WRITER_ROLE_DEFINITION_ID,
            "handoffSchemaVersion": "athena.wc028MonitoringEvidenceHandoff.v2",
            "acquisitionReceiptSchemaVersion": MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
        }
    )
    payload["effectiveRbacInventory"] = _effective_rbac_inventory(payload)
    return MonitoringCollectorContract(**payload)


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


def test_acquisition_collector_contract_authorizes_receipt_handoff() -> None:
    contract = _acquisition_collector_contract()

    assert contract.handoff_schema_version == "athena.wc028MonitoringEvidenceHandoff.v2"
    assert (
        contract.acquisition_receipt_schema_version == MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION
    )
    assert contract.ip_flow_verify_scope_id is None
    assert contract.ip_flow_verify_allowed_operations is None
    assert contract.flow_table_acquisition_mode == "unsupportedUnavailable"
    assert contract.identity_proof_audience == MONITORING_IDENTITY_PROOF_AUDIENCE
    assert "Microsoft.Network/networkWatchers/read" not in contract.allowed_read_operations
    assert contract.resource_health_scope_ids == SIGNAL_READ_SCOPE_IDS
    assert contract.resource_health_allowed_operations == RESOURCE_HEALTH_OPERATIONS
    assert contract.workspace_access_control_mode == "workspaceAndResourceContext"
    assert contract.workspace_resource_context_access_enabled is True
    assert contract.workspace_sku_name == "PerGB2018"
    assert tuple(item.table for item in contract.resource_context_table_plans or ()) == (
        RESOURCE_CONTEXT_TABLES
    )
    assert contract.resource_id_column == "_ResourceId"
    assert contract.log_query_prefer_header == "include-permissions=true"
    assert contract.resource_log_allowed_operations == RESOURCE_LOG_OPERATIONS
    assert contract.rbac_attestor_identity_resource_id == RBAC_ATTESTOR_ID.casefold()
    assert contract.rbac_attestor_principal_id == RBAC_ATTESTOR_PRINCIPAL_ID
    assert contract.rbac_attestor_allowed_operations == RBAC_ATTESTOR_OPERATIONS
    assert contract.effective_rbac_inventory is not None
    assert not any(
        operation.startswith("Microsoft.OperationalInsights/workspaces")
        for operation in contract.allowed_read_operations
    )
    assert all(
        item.role_definition_name != "Log Analytics Data Reader"
        for item in contract.effective_rbac_inventory.collector_grants
    )


def test_effective_rbac_inventory_example_matches_reviewed_contract() -> None:
    inventory = MonitoringEffectiveRbacInventory.model_validate_json(
        EFFECTIVE_RBAC_INVENTORY_EXAMPLE.read_text(encoding="utf-8")
    )

    assert inventory == _acquisition_collector_contract().effective_rbac_inventory


def test_legacy_v3_acquisition_collector_contract_remains_readable() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload["schemaVersion"] = "athena.wc028MonitoringCollectorContract.v3"
    payload["allowedReadOperations"] = _collector_contract().allowed_read_operations
    for field in (
        "collectorTenantId",
        "ipFlowVerifyRoleDefinitionId",
        "ipFlowVerifyScopeId",
        "ipFlowVerifyAllowedOperations",
        "identityProofAudience",
        "identityProofTokenVersion",
        "identityProofRequiredRole",
        "identityProofMaximumLifetimeSeconds",
        "resourceHealthRoleDefinitionId",
        "resourceHealthScopeIds",
        "resourceHealthAllowedOperations",
        "acquisitionReceiptSchemaVersion",
        *MEASURED_RBAC_FIELDS,
    ):
        payload.pop(field, None)

    legacy = MonitoringCollectorContract(**payload)

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v3"
    assert legacy.ip_flow_verify_role_definition_id is None


def test_legacy_v4_acquisition_collector_contract_remains_readable() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload["schemaVersion"] = "athena.wc028MonitoringCollectorContract.v4"
    payload["acquisitionReceiptSchemaVersion"] = "athena.wc028MonitoringAcquisitionReceipt.v3"
    payload["allowedReadOperations"] = (
        *_collector_contract().allowed_read_operations,
        *IP_FLOW_VERIFY_OPERATIONS,
    )
    payload.update(
        {
            "ipFlowVerifyRoleDefinitionId": IP_FLOW_VERIFY_ROLE_DEFINITION_ID,
            "ipFlowVerifyScopeId": NETWORK_WATCHER_RESOURCE_ID,
            "ipFlowVerifyAllowedOperations": IP_FLOW_VERIFY_OPERATIONS,
        }
    )
    for field in (
        "identityProofAudience",
        "identityProofTokenVersion",
        "identityProofRequiredRole",
        "identityProofMaximumLifetimeSeconds",
        "resourceHealthRoleDefinitionId",
        "resourceHealthScopeIds",
        "resourceHealthAllowedOperations",
        *MEASURED_RBAC_FIELDS,
    ):
        payload.pop(field, None)

    legacy = MonitoringCollectorContract(**payload)

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v4"
    assert legacy.identity_proof_audience is None


def test_legacy_v5_acquisition_collector_contract_remains_readable() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload["schemaVersion"] = "athena.wc028MonitoringCollectorContract.v5"
    payload["acquisitionReceiptSchemaVersion"] = "athena.wc028MonitoringAcquisitionReceipt.v4"
    payload["allowedReadOperations"] = (
        *_collector_contract().allowed_read_operations,
        *IP_FLOW_VERIFY_OPERATIONS,
    )
    payload.update(
        {
            "ipFlowVerifyRoleDefinitionId": IP_FLOW_VERIFY_ROLE_DEFINITION_ID,
            "ipFlowVerifyScopeId": NETWORK_WATCHER_RESOURCE_ID,
            "ipFlowVerifyAllowedOperations": IP_FLOW_VERIFY_OPERATIONS,
        }
    )
    for field in (
        "resourceHealthRoleDefinitionId",
        "resourceHealthScopeIds",
        "resourceHealthAllowedOperations",
        *MEASURED_RBAC_FIELDS,
    ):
        payload.pop(field, None)

    legacy = MonitoringCollectorContract(**payload)

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v5"
    assert legacy.resource_health_role_definition_id is None


def test_legacy_v6_acquisition_collector_contract_remains_readable() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload["schemaVersion"] = "athena.wc028MonitoringCollectorContract.v6"
    payload["acquisitionReceiptSchemaVersion"] = "athena.wc028MonitoringAcquisitionReceipt.v4"
    payload["allowedReadOperations"] = (
        *_collector_contract().allowed_read_operations,
        *IP_FLOW_VERIFY_OPERATIONS,
        *PREVIOUS_RESOURCE_HEALTH_OPERATIONS,
    )
    payload.update(
        {
            "ipFlowVerifyRoleDefinitionId": IP_FLOW_VERIFY_ROLE_DEFINITION_ID,
            "ipFlowVerifyScopeId": NETWORK_WATCHER_RESOURCE_ID,
            "ipFlowVerifyAllowedOperations": IP_FLOW_VERIFY_OPERATIONS,
            "resourceHealthAllowedOperations": PREVIOUS_RESOURCE_HEALTH_OPERATIONS,
        }
    )
    for field in MEASURED_RBAC_FIELDS:
        payload.pop(field, None)

    legacy = MonitoringCollectorContract(**payload)

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v6"
    assert legacy.resource_health_role_definition_id == (RESOURCE_HEALTH_ROLE_DEFINITION_ID)
    assert legacy.effective_rbac_inventory is None


def test_legacy_v7_measured_rbac_contract_remains_readable() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload.update(
        {
            "schemaVersion": "athena.wc028MonitoringCollectorContract.v7",
            "ipFlowVerifyRoleDefinitionId": IP_FLOW_VERIFY_ROLE_DEFINITION_ID,
            "ipFlowVerifyRoleName": IP_FLOW_VERIFY_ROLE_NAME,
            "ipFlowVerifyScopeId": NETWORK_WATCHER_RESOURCE_ID,
            "ipFlowVerifyAllowedOperations": IP_FLOW_VERIFY_OPERATIONS,
            "resourceLogAllowedOperations": PREVIOUS_RESOURCE_LOG_OPERATIONS,
            "resourceHealthAllowedOperations": PREVIOUS_RESOURCE_HEALTH_OPERATIONS,
            "allowedReadOperations": (
                *(
                    operation
                    for operation in _collector_contract().allowed_read_operations
                    if not operation.startswith("Microsoft.OperationalInsights/workspaces")
                ),
                *IP_FLOW_VERIFY_OPERATIONS,
                *PREVIOUS_RESOURCE_HEALTH_OPERATIONS,
                *PREVIOUS_RESOURCE_LOG_OPERATIONS,
            ),
        }
    )
    for field in V8_ONLY_CONTRACT_FIELDS:
        payload.pop(field, None)
    payload["effectiveRbacInventory"] = _previous_effective_rbac_inventory(payload)

    legacy = MonitoringCollectorContract(**payload)

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v7"
    assert legacy.ip_flow_verify_scope_id == NETWORK_WATCHER_RESOURCE_ID
    assert legacy.effective_rbac_inventory is not None
    assert (
        legacy.effective_rbac_inventory.schema_version
        == "athena.wc028MonitoringEffectiveRbacInventory.v1"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("ipFlowVerifyRoleDefinitionId", READER_ROLE_DEFINITION_ID),
        ("ipFlowVerifyScopeId", f"{NETWORK_WATCHER_RESOURCE_ID}/flowLogs/synthetic"),
        (
            "ipFlowVerifyAllowedOperations",
            ("Microsoft.Network/networkWatchers/ipFlowVerify/read",) * 2,
        ),
        (
            "allowedReadOperations",
            _collector_contract().allowed_read_operations,
        ),
        ("collectorTenantId", None),
        ("identityProofAudience", "api://unreviewed-proof"),
        ("identityProofRequiredRole", None),
        ("identityProofMaximumLifetimeSeconds", None),
        ("resourceHealthRoleDefinitionId", READER_ROLE_DEFINITION_ID),
        ("resourceHealthScopeIds", SIGNAL_READ_SCOPE_IDS[:-1]),
        ("resourceHealthAllowedOperations", ("Microsoft.ResourceHealth/events/read",)),
        ("workspaceAccessControlMode", "workspaceOnly"),
        ("workspaceResourceContextAccessEnabled", None),
        ("workspaceSkuName", None),
        (
            "resourceContextTablePlans",
            tuple(
                {
                    **item,
                    "plan": "Basic" if item["table"] == "Heartbeat" else "Analytics",
                }
                for item in RESOURCE_CONTEXT_TABLE_PLANS
            ),
        ),
        ("resourceIdColumn", None),
        ("logQueryPreferHeader", None),
        ("flowTableAcquisitionMode", None),
        (
            "resourceLogAllowedOperations",
            ("Microsoft.Insights/Logs/*/Read",) * 5,
        ),
        ("rbacAttestorIdentityResourceId", None),
        ("rbacAttestorRoleDefinitionId", READER_ROLE_DEFINITION_ID),
        ("rbacAttestorAllowedOperations", RBAC_ATTESTOR_OPERATIONS[:-1]),
        ("effectiveRbacInventory", None),
        ("acquisitionReceiptSchemaVersion", None),
    ),
)
def test_acquisition_contract_rejects_missing_or_incorrect_permission_policy(
    field: str,
    value: object,
) -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    payload[field] = value

    with pytest.raises(ValidationError):
        MonitoringCollectorContract(**payload)


def test_acquisition_contract_rejects_unexpected_effective_rbac_paths() -> None:
    base_contract = _acquisition_collector_contract()
    principal_id = str(base_contract.monitoring_reader_principal_id)
    group_id = "33333333-3333-3333-3333-333333333333"
    cases = (
        (
            _effective_rbac_grant(
                principal_id=principal_id,
                role_definition_id=(
                    f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                    "Microsoft.Authorization/roleDefinitions/"
                    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
                ),
                role_definition_name="Owner",
                assignment_scope_ids=(f"/subscriptions/{SUBSCRIPTION_ID}",),
                inheritance="inherited",
            ),
            (),
        ),
        (
            _effective_rbac_grant(
                principal_id=principal_id,
                assigned_principal_id=group_id,
                assigned_principal_type="Group",
                group_derived=True,
                role_definition_id=READER_ROLE_DEFINITION_ID,
                role_definition_name="Reader",
                assignment_scope_ids=(WORKLOAD_RESOURCE_GROUP_ROOT,),
            ),
            (group_id,),
        ),
        (
            _effective_rbac_grant(
                principal_id=principal_id,
                role_definition_id=READER_ROLE_DEFINITION_ID,
                role_definition_name="Reader",
                assignment_scope_ids=(WORKLOAD_RESOURCE_GROUP_ROOT,),
                condition="synthetic-unreviewed-condition",
                condition_version="2.0",
            ),
            (),
        ),
    )
    for extra_grant, security_group_ids in cases:
        payload = base_contract.model_dump(mode="python", by_alias=True)
        inventory = payload["effectiveRbacInventory"]
        assert isinstance(inventory, dict)
        inventory["collectorGrants"] = (
            *tuple(inventory["collectorGrants"]),
            extra_grant,
        )
        inventory["collectorSecurityGroupIds"] = security_group_ids
        _recompute_effective_rbac_inventory(inventory)

        with pytest.raises(
            ValidationError,
            match="effective RBAC",
        ):
            MonitoringCollectorContract(**payload)


def test_acquisition_contract_rejects_incomplete_effective_rbac_inventory() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["subscriptionDescendantCollectionComplete"] = False
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError):
        MonitoringCollectorContract(**payload)


def test_acquisition_contract_rejects_unbound_effective_rbac_source() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    source_reference = inventory["sourceReference"]
    assert isinstance(source_reference, dict)
    source_reference["contentDigest"] = "sha256:" + "f" * 64
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError, match="effective RBAC inventory"):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_requires_every_exact_target() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorPrincipalEvidence"]
    assert isinstance(evidence, dict)
    evidence["targetScopeIds"] = tuple(evidence["targetScopeIds"])[:-1]
    evidence["firstReadTargetDigests"] = tuple(evidence["firstReadTargetDigests"])[:-1]
    evidence["secondReadTargetDigests"] = tuple(evidence["secondReadTargetDigests"])[:-1]
    _recompute_principal_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError, match="omitted an exact target scope"):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_unstable_or_incomplete_pages() -> None:
    for field, value, expected in (
        ("secondRawSnapshotDigest", "sha256:" + "0" * 64, "stable"),
        ("denyAssignmentCollectionComplete", False, "literal_error"),
    ):
        payload = _acquisition_collector_contract().model_dump(
            mode="python",
            by_alias=True,
        )
        inventory = payload["effectiveRbacInventory"]
        assert isinstance(inventory, dict)
        inventory[field] = value
        if field == "secondRawSnapshotDigest":
            inventory.pop("inventoryDigest", None)
            inventory["inventoryDigest"] = compute_artifact_digest(_json_value(inventory))
        else:
            _recompute_effective_rbac_inventory(inventory)

        with pytest.raises(ValidationError, match=expected):
            MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_missing_roles_and_conditions() -> None:
    missing_role = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    missing_inventory = missing_role["effectiveRbacInventory"]
    assert isinstance(missing_inventory, dict)
    missing_inventory["roleDefinitions"] = tuple(missing_inventory["roleDefinitions"])[1:]
    _recompute_effective_rbac_inventory(missing_inventory)
    with pytest.raises(
        ValidationError,
        match="omitted a referenced full role definition",
    ):
        MonitoringCollectorContract(**missing_role)

    conditioned = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    conditioned_inventory = conditioned["effectiveRbacInventory"]
    assert isinstance(conditioned_inventory, dict)
    grant = dict(tuple(conditioned_inventory["collectorGrants"])[0])
    grant["condition"] = "synthetic unsupported condition"
    grant["conditionVersion"] = "2.0"
    grant.pop("grantDigest")
    grant["grantDigest"] = compute_artifact_digest(_json_value(grant))
    conditioned_inventory["collectorGrants"] = (
        grant,
        *tuple(conditioned_inventory["collectorGrants"])[1:],
    )
    _recompute_effective_rbac_inventory(conditioned_inventory)
    with pytest.raises(ValidationError, match="unsupported conditions"):
        MonitoringCollectorContract(**conditioned)


def test_current_rbac_attestation_evaluates_wildcard_denies_and_active_pim() -> None:
    denied = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    denied_inventory = denied["effectiveRbacInventory"]
    assert isinstance(denied_inventory, dict)
    denied_inventory["denyAssignments"] = (
        _deny_assignment(
            principal_id=str(denied["monitoringReaderPrincipalId"]),
            actions=("*/read",),
        ),
    )
    _recompute_effective_rbac_inventory(denied_inventory)
    with pytest.raises(ValidationError, match="deny assignment removes"):
        MonitoringCollectorContract(**denied)

    pim = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    pim_inventory = pim["effectiveRbacInventory"]
    assert isinstance(pim_inventory, dict)
    pim_inventory["activePimScheduleInstances"] = (
        _pim_schedule_instance(
            principal_id=str(pim["monitoringReaderPrincipalId"]),
            role_definition_id=READER_ROLE_DEFINITION_ID,
        ),
    )
    _recompute_effective_rbac_inventory(pim_inventory)
    with pytest.raises(ValidationError, match="must not depend on active PIM"):
        MonitoringCollectorContract(**pim)


def test_current_rbac_attestation_requires_transitive_group_evidence() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["collectorSecurityGroupIds"] = ("33333333-3333-3333-3333-333333333333",)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError, match="groups"):
        MonitoringCollectorContract(**payload)


def test_collector_contract_bicep_output_matches_the_production_contract() -> None:
    source = COLLECTOR_CONTRACT_MODULE.read_text(encoding="utf-8")
    output_fields = set(
        re.findall(
            r"^  (?P<field>[a-zA-Z][a-zA-Z0-9]*):",
            source.split("var collectorContract = {", maxsplit=1)[1].split("\n}", maxsplit=1)[0],
            flags=re.MULTILINE,
        )
    )
    bicep_output = _collector_contract().model_dump(by_alias=True, exclude_none=True)
    expected_fields = set(bicep_output)

    assert output_fields == expected_fields == set(bicep_output)
    assert MonitoringCollectorContract(**bicep_output) == _collector_contract()
    for operation in _collector_contract().allowed_read_operations:
        assert f"'{operation}'" in source
    assert "output collectorContract object = collectorContract" in source
    assert "athena.wc028MonitoringCollectorContract.v8" in source
    assert "athena.wc028MonitoringEvidenceHandoff.v2" in source


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


def test_reviewed_collector_contract_must_authorize_handoff_version() -> None:
    payload = _handoff_payload()
    payload["schemaVersion"] = "athena.wc028MonitoringEvidenceHandoff.v2"
    payload["acquisitionReceiptDigest"] = "sha256:" + "f" * 64
    evidence = payload["evidence"]
    assert isinstance(evidence, VersionPinnedBlobReference)
    handoff = MonitoringEvidenceHandoff(
        **payload,
        collectorAttestation=MonitoringEvidenceAttestation(
            signatureAlgorithm="RS256",
            trustAnchorRef=REVIEWED_SIGNING_KEY_URI,
            signedPreimageDigest=compute_artifact_digest(
                monitoring_handoff_preimage(
                    {
                        **payload,
                        "evidence": evidence.model_dump(
                            mode="json",
                            by_alias=True,
                        ),
                    }
                )
            ),
            signature=base64.b64encode(b"synthetic-signature").decode("ascii"),
        ),
    )
    _, contract, anchor, record = _trusted_signed_handoff()

    with pytest.raises(ValueError, match="schema is not authorized"):
        verify_monitoring_evidence_handoff_attestation(
            handoff,
            as_of=handoff.observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
        )
    with pytest.raises(ValueError, match="full reviewed collector contract"):
        verify_monitoring_evidence_handoff_attestation(
            handoff,
            as_of=handoff.observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            expected_collector_contract_digest=contract.compute_artifact_digest_value(),
            reviewed_maximum_evidence_age_seconds=(contract.maximum_evidence_age_seconds),
            reviewed_signing_key_resource_id=contract.signing_key_resource_id,
            expected_handoff_schema_version=("athena.wc028MonitoringEvidenceHandoff.v2"),
        )


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


def _selected_incident() -> MonitoringSelectedIncident:
    selected = build_selected_incident(
        incident_resource_id=SIGNAL_READ_SCOPE_IDS[0],
        previous_record_id="heartbeat-previous",
        current_record_ids=("heartbeat-current",),
        current_state="unhealthy",
    )
    return MonitoringSelectedIncident.model_validate(
        {
            "incidentResourceId": selected.incident_resource_id,
            "previousRecordId": selected.previous_record_id,
            "currentRecordIds": selected.current_record_ids,
            "currentState": selected.current_state,
            "transitionDigest": selected.transition_digest,
        }
    )


def test_signed_acquisition_receipt_reverifies_deployed_identity_policy() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    contract = _acquisition_collector_contract()
    reader_identity = contract.collector_identity_resource_id
    reader_principal = contract.monitoring_reader_principal_id
    reader_client = contract.collector_identity_client_id
    reader_tenant = contract.collector_tenant_id
    context_identity = contract.athena_context_identity_id
    context_principal = contract.athena_context_principal_id
    assert reader_principal is not None
    assert reader_tenant is not None
    assert context_identity is not None
    assert context_principal is not None
    effective_rbac_inventory = contract.effective_rbac_inventory
    assert effective_rbac_inventory is not None
    deployment_digest = compute_artifact_digest(
        {
            "monitoringReaderIdentityId": reader_identity.casefold(),
            "monitoringReaderPrincipalId": reader_principal,
            "monitoringReaderClientId": reader_client,
            "monitoringReaderTenantId": reader_tenant,
            "athenaContextIdentityId": context_identity.casefold(),
            "athenaContextPrincipalId": context_principal,
            "effectiveRbacInventoryDigest": effective_rbac_inventory.inventory_digest,
            "effectiveRbacSourceManifestDigest": (effective_rbac_inventory.source_manifest_digest),
        }
    )
    authority_digest = "sha256:" + "c" * 64
    collector_digest = contract.compute_artifact_digest_value()
    observed_at = datetime(2026, 9, 10, 2, 0, tzinfo=UTC)
    proof_payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringIdentityProof.v1",
        "tokenVersion": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        "tenantId": reader_tenant,
        "principalId": reader_principal,
        "clientId": reader_client,
        "subject": reader_principal,
        "issuer": f"https://sts.windows.net/{reader_tenant}/",
        "audience": MONITORING_IDENTITY_PROOF_AUDIENCE,
        "identityType": "app",
        "roles": [MONITORING_IDENTITY_PROOF_REQUIRED_ROLE],
        "tokenHash": "sha256:" + "6" * 64,
        "keyId": "synthetic-kid",
        "issuedAt": observed_at,
        "notBefore": observed_at,
        "expiresAt": observed_at.replace(hour=3),
        "verifiedAt": observed_at,
    }
    proof = MonitoringIdentityProof(
        **{
            **proof_payload,
            "roles": (MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,),
        },
        proofDigest=compute_artifact_digest(proof_payload),
    )
    exchange = MonitoringAcquisitionExchange(
        sequence=1,
        source="ipFlowVerify",
        requestDigest="sha256:" + "d" * 64,
        resultDigest="sha256:" + "e" * 64,
        requestedAt=observed_at,
        receivedAt=observed_at,
        checkedAt=observed_at,
        identityProofDigest=proof.proof_digest,
    )
    wire_attempt = MonitoringAcquisitionWireAttempt(
        sequence=1,
        exchangeSequence=1,
        attempt=1,
        source="ipFlowVerify",
        logicalRequestDigest=exchange.request_digest,
        wireRequestDigest="sha256:" + "7" * 64,
        wireResponseDigest="sha256:" + "8" * 64,
        requestedAt=observed_at,
        completedAt=observed_at,
        responseStatus=200,
        responseBytes=128,
    )
    selected_incident = _selected_incident()
    payload: dict[str, object] = {
        "schemaVersion": MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
        "authenticatedPrincipalId": reader_principal,
        "authenticatedClientId": reader_client,
        "authenticatedTenantId": reader_tenant,
        "monitoringReaderIdentityId": reader_identity,
        "athenaContextIdentityId": context_identity,
        "athenaContextPrincipalId": context_principal,
        "deploymentIdentityContractDigest": deployment_digest,
        "acquisitionAuthorityDigest": authority_digest,
        "collectorContractDigest": collector_digest,
        "intentId": "monitoring-intent-" + "1" * 32,
        "intentDigest": "sha256:" + "2" * 64,
        "contextBindingDigest": "sha256:" + "3" * 64,
        "collectionBatchDigest": "sha256:" + "4" * 64,
        "normalizedEvidenceDigest": "sha256:" + "5" * 64,
        "selectedIncident": selected_incident.model_dump(
            mode="json",
            by_alias=True,
        ),
        "executionStartedAt": observed_at,
        "executionCompletedAt": observed_at,
        "receiptIssuedAt": observed_at,
        "exchanges": [
            exchange.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        ],
        "wireAttempts": [
            wire_attempt.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        ],
        "identityProof": proof.model_dump(mode="json", by_alias=True),
    }
    receipt_digest = compute_artifact_digest(payload)
    signed_payload = {
        **payload,
        "receiptId": (
            f"monitoring-acquisition-receipt-{receipt_digest.removeprefix('sha256:')[:32]}"
        ),
        "receiptDigest": receipt_digest,
    }
    preimage = monitoring_acquisition_receipt_preimage(signed_payload)
    signature = base64.b64encode(
        private_key.sign(
            canonicalize_json(preimage).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    ).decode("ascii")
    receipt = MonitoringAcquisitionReceipt(
        **{
            **signed_payload,
            "exchanges": (exchange,),
            "wireAttempts": (wire_attempt,),
            "identityProof": proof,
            "selectedIncident": selected_incident,
        },
        collectorAttestation=MonitoringEvidenceAttestation(
            signatureAlgorithm="RS256",
            trustAnchorRef=REVIEWED_SIGNING_KEY_URI,
            signedPreimageDigest=compute_artifact_digest(preimage),
            signature=signature,
        ),
    )
    public_key = private_key.public_key()
    anchor = TrustedKeyAnchor.from_key_vault_key_id(
        REVIEWED_SIGNING_KEY_URI,
        public_key_fingerprint=sha256_hex(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ),
    )
    record = TrustedKeyRecord(
        anchor=anchor,
        public_key=public_key,
        enabled=True,
        activated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    verify_monitoring_acquisition_receipt_attestation(
        receipt,
        as_of=observed_at,
        trusted_key_anchor=anchor,
        key_resolver=lambda _anchor: record,
        reviewed_collector_contract=contract,
        expected_acquisition_authority_digest=authority_digest,
        maximum_receipt_age_seconds=600,
    )
    effective_inventory = contract.effective_rbac_inventory
    assert effective_inventory is not None
    for escaped_exchange in (
        exchange.model_copy(
            update={
                "requested_at": effective_inventory.expires_at,
                "received_at": effective_inventory.expires_at,
                "checked_at": effective_inventory.expires_at,
            }
        ),
        exchange.model_copy(update={"received_at": effective_inventory.expires_at}),
    ):
        with pytest.raises(
            ValueError,
            match="exchange times escape measured effective RBAC lifetime",
        ):
            verify_monitoring_acquisition_receipt_attestation(
                receipt.model_copy(update={"exchanges": (escaped_exchange,)}),
                as_of=observed_at,
                trusted_key_anchor=anchor,
                key_resolver=lambda _anchor: record,
                reviewed_collector_contract=contract,
                expected_acquisition_authority_digest=authority_digest,
                maximum_receipt_age_seconds=600,
            )
    escaped_wire_attempt = wire_attempt.model_copy(
        update={
            "requested_at": effective_inventory.expires_at,
            "completed_at": effective_inventory.expires_at,
        }
    )
    with pytest.raises(
        ValueError,
        match="wire-attempt times escape measured effective RBAC lifetime",
    ):
        verify_monitoring_acquisition_receipt_attestation(
            receipt.model_copy(update={"wire_attempts": (escaped_wire_attempt,)}),
            as_of=observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
        )
    with pytest.raises(
        ValueError,
        match="execution is outside measured effective RBAC lifetime",
    ):
        verify_monitoring_acquisition_receipt_attestation(
            receipt.model_copy(
                update={
                    "execution_completed_at": effective_inventory.expires_at,
                }
            ),
            as_of=observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
        )
    with pytest.raises(ValueError, match="does not match deployed acquisition authority"):
        verify_monitoring_acquisition_receipt_attestation(
            receipt.model_copy(update={"authenticated_principal_id": context_principal}),
            as_of=observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
        )
    other_anchor = TrustedKeyAnchor.from_key_vault_key_id(
        "https://athenademomonkv.vault.azure.net/keys/other/0123456789abcdef0123456789abcdef",
        public_key_fingerprint=anchor.public_key_fingerprint,
    )
    with pytest.raises(ValueError, match="signing key is not authority-approved"):
        verify_monitoring_acquisition_receipt_attestation(
            receipt,
            as_of=observed_at,
            trusted_key_anchor=other_anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
        )

    legacy_exchange = exchange.model_copy(update={"identity_proof_digest": None})
    legacy_payload = {
        key: value
        for key, value in payload.items()
        if key
        not in {
            "authenticatedClientId",
            "authenticatedTenantId",
            "monitoringReaderIdentityId",
            "athenaContextPrincipalId",
            "identityProof",
            "selectedIncident",
            "wireAttempts",
        }
    }
    legacy_payload.update(
        {
            "schemaVersion": "athena.wc028MonitoringAcquisitionReceipt.v1",
            "authenticatedPrincipalId": reader_identity,
            "exchanges": [
                legacy_exchange.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            ],
        }
    )
    legacy_digest = compute_artifact_digest(legacy_payload)
    legacy_signed_payload = {
        **legacy_payload,
        "receiptId": (
            f"monitoring-acquisition-receipt-{legacy_digest.removeprefix('sha256:')[:32]}"
        ),
        "receiptDigest": legacy_digest,
    }
    legacy_preimage = monitoring_acquisition_receipt_preimage(legacy_signed_payload)
    legacy_receipt = MonitoringAcquisitionReceipt(
        **{**legacy_signed_payload, "exchanges": (legacy_exchange,)},
        collectorAttestation=MonitoringEvidenceAttestation(
            signatureAlgorithm="RS256",
            trustAnchorRef=REVIEWED_SIGNING_KEY_URI,
            signedPreimageDigest=compute_artifact_digest(legacy_preimage),
            signature=base64.b64encode(
                private_key.sign(
                    canonicalize_json(legacy_preimage).encode("utf-8"),
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            ).decode("ascii"),
        ),
    )
    assert legacy_receipt.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v1"
    with pytest.raises(ValueError, match="requires incident-bound acquisition receipt v5"):
        verify_monitoring_acquisition_receipt_attestation(
            legacy_receipt,
            as_of=observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
        )


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
            expected_handoff_schema_version=MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
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
        "https://athenademomonkv.vault.azure.net/keys/another-key/0123456789abcdef0123456789abcdef",
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
            expected_handoff_schema_version=MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
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

    with pytest.raises(ValueError, match="reviewed handoff schema"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest=signed_handoff.collector_contract_digest,
            reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
            reviewed_signing_key_resource_id=contract.signing_key_resource_id,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="reviewed schema"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest=signed_handoff.collector_contract_digest,
            reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
            reviewed_signing_key_resource_id=contract.signing_key_resource_id,
            expected_handoff_schema_version=("athena.wc028MonitoringEvidenceHandoff.v2"),
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    verify_monitoring_evidence_handoff_attestation(
        signed_handoff,
        as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
        expected_collector_contract_digest=signed_handoff.collector_contract_digest,
        reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
        reviewed_signing_key_resource_id=contract.signing_key_resource_id,
        expected_handoff_schema_version=MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
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
