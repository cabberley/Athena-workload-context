from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WC024_ROOT = ROOT / "infra" / "wc024-monitoring-foundation"
WC024_CONNECTIVITY_ROOT = ROOT / "infra" / "wc024-monitoring-connectivity"
MAIN = (WC024_ROOT / "main.bicep").read_text(encoding="utf-8")
PARAMETERS = (WC024_ROOT / "main.example.bicepparam").read_text(encoding="utf-8")
AMPLS_BOOTSTRAP = (WC024_ROOT / "bootstrap-ampls.bicep").read_text(encoding="utf-8")
AMPLS_BOOTSTRAP_SCRIPT = (WC024_ROOT / "bootstrap-ampls.ps1").read_text(encoding="utf-8")
DATA_PLATFORM = (WC024_ROOT / "modules" / "monitoring-data-platform.bicep").read_text(
    encoding="utf-8"
)
STORAGE = (WC024_ROOT / "modules" / "monitoring-flow-log-storage.bicep").read_text(encoding="utf-8")
EVIDENCE_SEAMS = (WC024_ROOT / "modules" / "monitoring-evidence-seams.bicep").read_text(
    encoding="utf-8"
)
EVIDENCE_WRITER_ROLE = (WC024_ROOT / "modules" / "monitoring-evidence-writer-role.bicep").read_text(
    encoding="utf-8"
)
REVIEWER_KEY_READER_ROLE = (
    WC024_ROOT / "modules" / "monitoring-reviewer-key-reader-role.bicep"
).read_text(encoding="utf-8")
REVIEWER_KEY_READER_ASSIGNMENT = (
    WC024_ROOT / "modules" / "monitoring-reviewer-key-reader-assignment.bicep"
).read_text(encoding="utf-8")
PRIVATE_ENDPOINTS = (WC024_ROOT / "modules" / "monitoring-private-endpoints.bicep").read_text(
    encoding="utf-8"
)
READER_RBAC = (WC024_ROOT / "modules" / "monitoring-evidence-reader-rbac.bicep").read_text(
    encoding="utf-8"
)
WORKLOAD_READER_RBAC = (
    WC024_ROOT / "modules" / "workload-monitoring-evidence-reader-rbac.bicep"
).read_text(encoding="utf-8")
NETWORK_WATCHER_READER_RBAC = (
    WC024_ROOT / "modules" / "network-watcher-monitoring-evidence-reader-rbac.bicep"
).read_text(encoding="utf-8")
RBAC_ATTESTOR = (WC024_ROOT / "modules" / "monitoring-rbac-attestor.bicep").read_text(
    encoding="utf-8"
)
RBAC_BOOTSTRAP_HANDOFF = (
    WC024_ROOT / "modules" / "monitoring-rbac-bootstrap-handoff.bicep"
).read_text(encoding="utf-8")
RBAC_INVENTORY_ATTESTATION_VALIDATION = (
    WC024_ROOT / "modules" / "monitoring-rbac-inventory-attestation-validation.bicep"
).read_text(encoding="utf-8")
PUBLICATION_VALIDATION_GATE = (
    WC024_ROOT / "modules" / "monitoring-publication-validation-gate.bicep"
).read_text(encoding="utf-8")
RBAC_INVENTORY_ATTESTATION_VERIFIER = (
    WC024_ROOT / "scripts" / "verify-rbac-inventory-attestation.py"
).read_text(encoding="utf-8")
IDENTITY_PROOF_AUTHORITY = (
    WC024_ROOT / "modules" / "monitoring-identity-proof-authority.bicep"
).read_text(encoding="utf-8")
DCR_ASSOCIATIONS = (WC024_ROOT / "modules" / "dcr-associations.bicep").read_text(encoding="utf-8")
DCR_ASSOCIATION_VALIDATION = (
    WC024_ROOT / "modules" / "dcr-association-validation.bicep"
).read_text(encoding="utf-8")
PRIVATE_RUNTIME_TOPOLOGY_VALIDATION = (
    WC024_ROOT / "modules" / "private-runtime-topology-validation.bicep"
).read_text(encoding="utf-8")
FLOW_LOG = (WC024_ROOT / "modules" / "vnet-flow-log.bicep").read_text(encoding="utf-8")
FLOW_LOG_VALIDATION = (WC024_ROOT / "modules" / "canonical-flow-log-validation.bicep").read_text(
    encoding="utf-8"
)
PRIVATE_ACCESS_SCRIPT = (WC024_ROOT / "set-private-access.ps1").read_text(encoding="utf-8")
PRIVATE_DNS_VNET_LINKS = (WC024_ROOT / "modules" / "private-dns-vnet-links.bicep").read_text(
    encoding="utf-8"
)
PRIVATE_DNS_ZONES = (WC024_ROOT / "modules" / "private-dns-zones.bicep").read_text(encoding="utf-8")
COLLECTOR_KEY_VAULT_DNS = (
    WC024_ROOT / "modules" / "collector-key-vault-private-dns.bicep"
).read_text(encoding="utf-8")
LEGACY_FLOW_LOG_MIGRATION = (WC024_ROOT / "modules" / "legacy-flow-log-migration.bicep").read_text(
    encoding="utf-8"
)
CONNECTION_MONITOR = (WC024_ROOT / "modules" / "connection-monitor-capability.bicep").read_text(
    encoding="utf-8"
)
COLLECTOR_CONTRACT = (WC024_ROOT / "modules" / "monitoring-collector-contract.bicep").read_text(
    encoding="utf-8"
)
PUBLISH_CONTRACT = (WC024_ROOT / "publish-monitoring-contract.bicep").read_text(encoding="utf-8")
PHASE_ONE = f"{MAIN}\n{RBAC_BOOTSTRAP_HANDOFF}"
ADR = (ROOT / "docs" / "adr" / "0020-wc024-generic-monitoring-foundation.md").read_text(
    encoding="utf-8"
)
CONNECTIVITY_MAIN = (WC024_CONNECTIVITY_ROOT / "main.bicep").read_text(encoding="utf-8")
CONNECTIVITY_HUB = (
    WC024_CONNECTIVITY_ROOT / "modules" / "monitoring-collector-network.bicep"
).read_text(encoding="utf-8")


def test_wc024_adr_uses_unique_sequential_number_after_wc021_wc022_merges() -> None:
    assert (ROOT / "docs" / "adr" / "0020-wc024-generic-monitoring-foundation.md").is_file()
    assert not (ROOT / "docs" / "adr" / "0018-wc024-generic-monitoring-foundation.md").exists()
    assert ADR.startswith(
        "# ADR 0020: Isolate generic monitoring evidence from context and presentation runtimes"
    )


def test_wc024_adopts_existing_law_dce_dcr_and_associations_without_duplicates() -> None:
    assert (
        "resource monitoringResourceGroup "
        "'Microsoft.Resources/resourceGroups@2025-04-01' existing" in MAIN
    )
    assert "@allowed([\n  'rg-athena-demo-workload'\n])\nparam workloadResourceGroupName" in MAIN
    assert "var reviewedWorkloadVirtualNetworkResourceId" in MAIN
    assert "virtualNetworks/athena-hackathon-vnet" in MAIN
    assert "var reviewedApprovedVmNames = [" in MAIN
    assert "var unreviewedApprovedVmNames" in MAIN
    assert "var missingReviewedVmNames" in MAIN
    assert "validatedApprovedVmNames" in MAIN
    assert "validatedWorkloadVirtualNetworkResourceId" in MAIN
    for vm_name in (
        "athena-hackathon-client-01",
        "athena-hackathon-ecp-01",
        "athena-hackathon-ecp-03",
        "athena-hackathon-iris-01",
        "athena-hackathon-mid-01",
        "athena-hackathon-mid-02",
        "athena-hackathon-sqlvm-01",
        "athena-hackathon-web-03",
    ):
        assert vm_name in MAIN
    assert "param workspaceName string = 'athena-hackathon-law'" in MAIN
    assert "param dataCollectionEndpointName string = 'athena-hackathon-linux-dce'" in MAIN
    assert "param dataCollectionRuleName string = 'athena-hackathon-linux-dcr'" in MAIN
    assert "param dataCollectionRuleAssociationName string = 'athena-linux-dcr'" in MAIN
    assert (
        "param dataCollectionEndpointAssociationName string = 'configurationAccessEndpoint'" in MAIN
    )
    assert (
        "resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing"
        in DATA_PLATFORM
    )
    assert (
        "resource dataCollectionEndpoint "
        "'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' existing" in DATA_PLATFORM
    )
    assert (
        "resource dataCollectionRule "
        "'Microsoft.Insights/dataCollectionRules@2024-03-11' existing" in DATA_PLATFORM
    )
    assert "${namePrefix}-law" not in DATA_PLATFORM
    assert "${namePrefix}-dce" not in DATA_PLATFORM
    assert "${namePrefix}-guest-dcr" not in DATA_PLATFORM
    assert "Custom-AthenaJson" in DATA_PLATFORM
    assert "Custom-AthenaApp_CL" in DATA_PLATFORM
    assert "@minLength(11)\n@maxLength(11)\nparam approvedVmNames array" in MAIN
    assert "@minLength(11)\n@maxLength(11)\nparam approvedVmNames array" in (DCR_ASSOCIATIONS)
    dcr_declaration = DATA_PLATFORM.split("resource dataCollectionRule ", maxsplit=1)[1].split(
        "\n}", maxsplit=1
    )[0]
    assert "existing = {" in dcr_declaration
    assert "tags:" not in dcr_declaration
    assert "Microsoft.Compute/virtualMachines/extensions" not in DCR_ASSOCIATIONS
    assert "dataCollectionRuleAssociations" in DCR_ASSOCIATIONS
    assert "name: dataCollectionEndpointAssociationName" in DCR_ASSOCIATIONS
    assert "dataCollectionEndpointResourceId" in DCR_ASSOCIATIONS
    assert "param dataCollectionEndpointLocation string" in DCR_ASSOCIATIONS
    assert "dataCollectionEndpointId: !empty(validatedDcrAssociationIds[index])" in (
        DCR_ASSOCIATIONS
    )
    assert "approvedVms[index].location" in DCR_ASSOCIATIONS
    assert "toLower(dataCollectionEndpointLocation)" in DCR_ASSOCIATIONS
    assert "dataCollectionRuleId:" not in DCR_ASSOCIATIONS
    assert "dataCollectionRuleResourceId" not in DCR_ASSOCIATIONS
    assert "dataCollectionRuleAssociationName" not in DCR_ASSOCIATIONS
    assert "validatedDataCollectionRuleAssociationResourceIds" in DCR_ASSOCIATIONS
    assert (
        "dataCollectionRuleResourceId: "
        "monitoringDataPlatform.outputs.dataCollectionRuleResourceId" in MAIN
    )
    assert (
        "dataCollectionEndpointLocation: "
        "monitoringDataPlatform.outputs.dataCollectionEndpointLocation" in MAIN
    )
    assert (
        "resource configurationAccessEndpointAssociation "
        "'Microsoft.Insights/dataCollectionRuleAssociations@2024-03-11'" in DCR_ASSOCIATIONS
    )
    assert "output dataCollectionEndpointAssociationResourceIds array" in DCR_ASSOCIATIONS
    assert "validate-adopted-dcr-associations" in MAIN
    assert "create-dce-associations-after-dcr-validation" in MAIN
    assert (
        "output adoptedDataCollectionRuleAssociationResourceIds array = "
        "dcrAssociationValidation.outputs."
        "validatedAdoptedDataCollectionRuleAssociationResourceIds" in MAIN
    )
    assert (
        "output dataCollectionEndpointAssociationResourceIds array = "
        "dcrAssociations.outputs.dataCollectionEndpointAssociationResourceIds" in MAIN
    )
    assert "map(approvedVmNames, vmName => toLower(string(vmName)))" in DCR_ASSOCIATIONS
    assert "var uniqueApprovedVmNames = union(normalizedApprovedVmNames, [])" in (DCR_ASSOCIATIONS)
    assert "fail('WC-024 requires exactly 11 distinct approved VM names" in DCR_ASSOCIATIONS
    assert "for vmName in validatedApprovedVmNames" in DCR_ASSOCIATIONS
    assert "for (vmName, index) in validatedApprovedVmNames" in DCR_ASSOCIATIONS


def test_wc024_validates_preserved_dcr_associations_before_dce_association_puts() -> None:
    adopted_association_declaration = DCR_ASSOCIATION_VALIDATION.split(
        "resource adoptedDataCollectionRuleAssociation ", maxsplit=1
    )[1].split("\n]\n\n@description", maxsplit=1)[0]
    assert "existing = [" in adopted_association_declaration
    assert "properties:" not in adopted_association_declaration
    assert "@minLength(11)\n@maxLength(11)\nparam approvedVmNames array" in (
        DCR_ASSOCIATION_VALIDATION
    )
    assert "adoptedDataCollectionRuleAssociation[index].properties.dataCollectionRuleId" in (
        DCR_ASSOCIATION_VALIDATION
    )
    assert "toLower(dataCollectionRuleResourceId)" in DCR_ASSOCIATION_VALIDATION
    assert "missing or does not reference the adopted data collection rule" in (
        DCR_ASSOCIATION_VALIDATION
    )
    assert "resource adoptedDataCollectionRuleAssociation" not in DCR_ASSOCIATIONS
    assert "properties.dataCollectionRuleId" not in DCR_ASSOCIATIONS
    assert "dataCollectionRuleId:" not in DCR_ASSOCIATIONS
    assert "validatedDcrAssociationIds[index]" in DCR_ASSOCIATIONS
    assert "prerequisite adopted DCR association validation" in DCR_ASSOCIATIONS
    assert "module dcrAssociationValidation 'modules/dcr-association-validation.bicep'" in MAIN
    dcr_associations_declaration = MAIN.split("module dcrAssociations", maxsplit=1)[1].split(
        "module workloadPrivateDnsZones", maxsplit=1
    )[0]
    assert "dependsOn: [" in dcr_associations_declaration
    assert "dcrAssociationValidation" in dcr_associations_declaration
    assert (
        "validatedDataCollectionRuleAssociationResourceIds: "
        "dcrAssociationValidation.outputs."
        "validatedAdoptedDataCollectionRuleAssociationResourceIds" in dcr_associations_declaration
    )
    assert (
        "dataCollectionRuleResourceId: "
        "monitoringDataPlatform.outputs.dataCollectionRuleResourceId" in MAIN
    )


def test_wc024_private_networking_and_storage_lifecycle_are_enforced() -> None:
    assert PRIVATE_ENDPOINTS.count("Microsoft.Network/privateEndpoints@2024-10-01") == 4
    assert "azuremonitor" in PRIVATE_ENDPOINTS
    assert "privateDnsZoneConfigs" in PRIVATE_ENDPOINTS
    assert "name: 'azure-monitor-blob'" in PRIVATE_ENDPOINTS
    assert "workloadStorageBlobPrivateDnsZoneResourceId" in PRIVATE_ENDPOINTS
    assert "collectorStorageBlobPrivateDnsZoneResourceId" in PRIVATE_ENDPOINTS
    assert "collectorKeyVaultPrivateDnsZoneResourceId" in PRIVATE_ENDPOINTS
    assert "@minLength(4)" in PRIVATE_ENDPOINTS
    assert PRIVATE_DNS_ZONES.count("Microsoft.Network/privateDnsZones@2024-06-01") == 5
    assert (
        PRIVATE_DNS_VNET_LINKS.count(
            "Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01"
        )
        == 5
    )
    assert "privatelink.vaultcore.azure.net" not in PRIVATE_DNS_ZONES
    assert "privatelink.vaultcore.azure.net" in COLLECTOR_KEY_VAULT_DNS
    assert "accessBoundary: 'collector-only'" in COLLECTOR_KEY_VAULT_DNS
    for zone in (
        "privatelink.monitor.azure.com",
        "privatelink.oms.opinsights.azure.com",
        "privatelink.ods.opinsights.azure.com",
        "privatelink.agentsvc.azure-automation.net",
        "privatelink.blob.core.windows.net",
    ):
        assert zone in PRIVATE_DNS_ZONES
        assert zone in PRIVATE_DNS_VNET_LINKS
    assert "id: virtualNetworkResourceId" in PRIVATE_DNS_VNET_LINKS
    assert "collectorRuntimeRequiresSeparateLinks" not in PRIVATE_DNS_VNET_LINKS
    assert "registrationEnabled: false" in PRIVATE_DNS_VNET_LINKS
    assert "existing = {" in PRIVATE_DNS_VNET_LINKS
    assert "virtualNetworkLinks" not in PRIVATE_DNS_ZONES
    assert "workloadPrivateDnsZones.outputs.storageBlobPrivateDnsZoneResourceId" in MAIN
    assert "collectorPrivateDnsZones.outputs.storageBlobPrivateDnsZoneResourceId" in MAIN
    assert "collectorKeyVaultPrivateDns.outputs.keyVaultPrivateDnsZoneResourceId" in MAIN
    assert "allowBlobPublicAccess: false" in STORAGE
    assert "allowSharedKeyAccess: false" in STORAGE
    assert "defaultToOAuthAuthentication: true" in STORAGE
    assert "publicNetworkAccess: 'Enabled'" in STORAGE
    assert "publicNetworkAccess: 'Disabled'" not in STORAGE
    assert "defaultAction: 'Deny'" in STORAGE
    assert "bypass: 'AzureServices'" in STORAGE
    assert "ipRules: []" in STORAGE
    assert "virtualNetworkRules: []" in STORAGE
    assert "isVersioningEnabled: true" in STORAGE
    assert "output blobVersioningEnabled bool" in STORAGE
    assert "deleteRetentionPolicy" in STORAGE
    assert "immutabilityPeriodSinceCreationInDays: retentionDays" in STORAGE
    assert "allowProtectedAppendWrites: false" in STORAGE
    assert "allowProtectedAppendWritesAll: false" in STORAGE
    assert "output monitoringEvidenceContainerHasImmutabilityPolicy bool" in STORAGE
    assert "output monitoringEvidenceImmutabilityPolicyState string" in STORAGE
    assert "flow-log-evidence-retention" in STORAGE
    assert "'insights-logs-flowlogflowevent/'" in STORAGE
    assert "'monitoring-evidence/'" in STORAGE
    assert "tierToArchive" not in STORAGE
    assert "publicNetworkAccess: 'Disabled'" in EVIDENCE_SEAMS
    assert "enablePurgeProtection: true" in EVIDENCE_SEAMS
    assert "output monitoringEvidenceContainerResourceId string" in STORAGE
    assert "param monitoringEvidenceContainerResourceId string" in EVIDENCE_SEAMS
    assert "validatedMonitoringEvidenceContainerResourceId" in EVIDENCE_SEAMS
    assert "guid(validatedMonitoringEvidenceContainerResourceId" in EVIDENCE_SEAMS
    evidence_seams_declaration = MAIN.split("module monitoringEvidenceSeams", maxsplit=1)[1].split(
        "module monitoringPrivateEndpoints", maxsplit=1
    )[0]
    assert "dependsOn: [" in evidence_seams_declaration
    assert "monitoringStorage" in evidence_seams_declaration
    assert (
        "monitoringEvidenceContainerResourceId: "
        "monitoringStorage.outputs.monitoringEvidenceContainerResourceId"
        in evidence_seams_declaration
    )


def test_wc024_standardizes_vnet_flow_log_and_traffic_analytics() -> None:
    assert "Microsoft.Network/networkWatchers/flowLogs@2024-10-01" in FLOW_LOG
    assert "targetResourceId: workloadVirtualNetworkResourceId" in FLOW_LOG
    assert "storageId: storageAccountResourceId" in FLOW_LOG
    assert "retentionPolicy" in FLOW_LOG
    assert "flowAnalyticsConfiguration" in FLOW_LOG
    assert "trafficAnalyticsInterval: 10" in FLOW_LOG
    assert "workspaceResourceId: workspaceResourceId" in FLOW_LOG
    assert (
        "param flowLogName string = 'athena-hackathon-vnet-rg-athena-demo-workload-flowlog'" in MAIN
    )
    assert "name: flowLogName" in FLOW_LOG
    assert "athenahackathonflowwhtco" in MAIN
    assert "retainedLegacyFlowLogStorageAccountName" in MAIN
    assert "@allowed([\n  'athena-hackathon-vnet-rg-athena-demo-workload-flowlog'\n])" in MAIN
    assert "resource existingFlowLog" in FLOW_LOG_VALIDATION
    assert "existingFlowLog.properties.targetResourceId" in FLOW_LOG_VALIDATION
    assert "refuses to update the canonical flow log" in FLOW_LOG_VALIDATION
    assert "canonicalFlowLogValidation.outputs.validatedFlowLogName" in MAIN


def test_wc024_disables_redundant_legacy_flow_logs_only_after_canonical_cutover() -> None:
    assert "legacyFlowLogNames" in MAIN
    assert "legacyFlowLogTargetResourceIds" in MAIN
    assert "reviewedLegacyFlowLogMigrationAllowlist" not in MAIN
    assert "var reviewedLegacyFlowLogMigrationAllowlist = [" in LEGACY_FLOW_LOG_MIGRATION
    assert LEGACY_FLOW_LOG_MIGRATION.count("targetResourceId: '${workloadScopeId}") == 18
    assert "legacyFlowLogStorageAccountResourceId" in LEGACY_FLOW_LOG_MIGRATION
    assert "canonicalVnetFlowLogCutoverConfirmed" in MAIN
    assert "dependsOn: [\n    vnetFlowLog\n  ]" in MAIN
    assert "@maxLength(32)" in LEGACY_FLOW_LOG_MIGRATION
    assert "length(legacyFlowLogNames) == length(legacyFlowLogTargetResourceIds)" in (
        LEGACY_FLOW_LOG_MIGRATION
    )
    assert "reviewedLegacyFlowLogMigrationAllowlist" in LEGACY_FLOW_LOG_MIGRATION
    assert "unreviewedLegacyFlowLogMigrationPairs" in LEGACY_FLOW_LOG_MIGRATION
    assert "existingLegacyFlowLogs" in LEGACY_FLOW_LOG_MIGRATION
    assert "properties.targetResourceId" in LEGACY_FLOW_LOG_MIGRATION
    assert "existing target and storage account match the reviewed allowlist" in (
        LEGACY_FLOW_LOG_MIGRATION
    )
    assert "toLower(canonicalVnetFlowLogName)" in (LEGACY_FLOW_LOG_MIGRATION)
    assert "canonicalVnetFlowLogCutoverConfirmed" in LEGACY_FLOW_LOG_MIGRATION
    assert "a6add389-9978-47ac-ab1e-a09212e321d4" in LEGACY_FLOW_LOG_MIGRATION
    assert "validatedMigrationSubscriptionId" in LEGACY_FLOW_LOG_MIGRATION
    assert "legacyFlowLogMigrationRequested" in LEGACY_FLOW_LOG_MIGRATION
    assert "refuses destructive legacy flow-log migration outside subscription" in (
        LEGACY_FLOW_LOG_MIGRATION
    )
    assert "enabled: false" in LEGACY_FLOW_LOG_MIGRATION
    assert "storageId: replacementStorageAccountResourceId" in LEGACY_FLOW_LOG_MIGRATION
    assert "delete" not in LEGACY_FLOW_LOG_MIGRATION.lower()


def test_wc024_legacy_flow_log_cutover_rejects_unapproved_subscription() -> None:
    approved_subscription_id = "a6add389-9978-47ac-ab1e-a09212e321d4"

    def cutover_subscription_is_valid(
        subscription_id: str,
        flow_log_names: list[str],
        target_resource_ids: list[str],
    ) -> bool:
        migration_requested = bool(flow_log_names or target_resource_ids)
        return not migration_requested or subscription_id.casefold() == (
            approved_subscription_id.casefold()
        )

    assert cutover_subscription_is_valid(approved_subscription_id, ["legacy"], ["target"])
    assert cutover_subscription_is_valid("00000000-0000-0000-0000-000000000000", [], [])
    assert not cutover_subscription_is_valid(
        "00000000-0000-0000-0000-000000000000",
        ["legacy"],
        ["target"],
    )
    assert not cutover_subscription_is_valid(
        "00000000-0000-0000-0000-000000000000",
        [],
        ["target"],
    )


def test_wc024_disables_adopted_public_access_only_after_private_readiness() -> None:
    assert "privateLinkScopeDeploymentPhase" not in MAIN
    assert "privateLinkScopeDeploymentPhase" not in DATA_PLATFORM
    assert (
        "resource workloadPrivateLinkScope "
        "'Microsoft.Insights/privateLinkScopes@2021-09-01' existing" in DATA_PLATFORM
    )
    assert (
        "resource collectorPrivateLinkScope "
        "'Microsoft.Insights/privateLinkScopes@2021-09-01' existing" in DATA_PLATFORM
    )
    assert "resource privateLinkScope" in AMPLS_BOOTSTRAP
    assert "queryAccessMode: 'Open'" in AMPLS_BOOTSTRAP
    assert "ingestionAccessMode: 'Open'" in AMPLS_BOOTSTRAP
    assert "athena-demo-monitoring-workload-ampls" in AMPLS_BOOTSTRAP
    assert "athena-demo-monitoring-collector-ampls" in AMPLS_BOOTSTRAP
    assert "properties: {}" not in AMPLS_BOOTSTRAP
    assert "az resource show" in AMPLS_BOOTSTRAP_SCRIPT
    assert "already exists" in AMPLS_BOOTSTRAP_SCRIPT
    assert "$LASTEXITCODE -ne 3" in AMPLS_BOOTSTRAP_SCRIPT
    assert "az deployment group create" in AMPLS_BOOTSTRAP_SCRIPT
    assert "continue" in AMPLS_BOOTSTRAP_SCRIPT
    assert "--parameters privateLinkScopeName=$scopeName" in AMPLS_BOOTSTRAP_SCRIPT
    assert "monitoring-private-access.bicep" not in MAIN
    assert "privateMonitoringIngestionCutoverConfirmed" not in MAIN
    assert "--ingestion-access Disabled" in PRIVATE_ACCESS_SCRIPT
    assert "--query-access Disabled" in PRIVATE_ACCESS_SCRIPT
    assert "--public-network-access Disabled" in PRIVATE_ACCESS_SCRIPT
    assert "queryAccessMode = 'PrivateOnly'" in PRIVATE_ACCESS_SCRIPT
    assert "ingestionAccessMode = 'PrivateOnly'" in PRIVATE_ACCESS_SCRIPT
    for confirmation in (
        "ConnectivityValidated",
        "DnsValidated",
        "IngestionValidated",
    ):
        assert f"[switch] ${confirmation}" in PRIVATE_ACCESS_SCRIPT
    assert "monitoringPrivateEndpoints" in MAIN
    assert "workloadPrivateDnsZones" in MAIN
    assert "collectorPrivateDnsZones" in MAIN
    assert "workloadPrivateDnsVnetLinks" in MAIN
    assert "collectorPrivateDnsVnetLinks" in MAIN
    assert "dcrAssociations" in MAIN
    assert "az monitor log-analytics workspace update" in PRIVATE_ACCESS_SCRIPT
    assert "az monitor data-collection endpoint update" in PRIVATE_ACCESS_SCRIPT
    assert "az rest" in PRIVATE_ACCESS_SCRIPT
    assert "--method put" in PRIVATE_ACCESS_SCRIPT
    assert "If-Match" not in PRIVATE_ACCESS_SCRIPT
    assert "$exclusions = @()" in PRIVATE_ACCESS_SCRIPT
    assert "private cutover requires an empty exclusion set" in PRIVATE_ACCESS_SCRIPT
    assert PRIVATE_ACCESS_SCRIPT.index(
        "private cutover requires an empty exclusion set"
    ) < PRIVATE_ACCESS_SCRIPT.index("--method put")
    assert "exclusions = $exclusions" in PRIVATE_ACCESS_SCRIPT
    assert "$updatedTags -ne $expectedTags" in PRIVATE_ACCESS_SCRIPT
    assert "$updatedExclusions -ne $expectedExclusions" in PRIVATE_ACCESS_SCRIPT
    assert "scopedResources?api-version=2021-09-01" in PRIVATE_ACCESS_SCRIPT
    assert "privateEndpointConnections?api-version=2021-09-01" in (PRIVATE_ACCESS_SCRIPT)
    assert "does not contain the exact reviewed LAW and DCE" in PRIVATE_ACCESS_SCRIPT
    assert "does not contain the exact approved private endpoint" in (PRIVATE_ACCESS_SCRIPT)
    assert "[ValidateSet('a6add389-9978-47ac-ab1e-a09212e321d4')]" in PRIVATE_ACCESS_SCRIPT
    assert "athena-demo-monitoring-workload-ampls" in PRIVATE_ACCESS_SCRIPT
    assert "athena-demo-monitoring-collector-ampls" in PRIVATE_ACCESS_SCRIPT
    assert "Private access verification failed" in PRIVATE_ACCESS_SCRIPT


def test_wc024_serializes_ampls_links_to_shared_law_and_dce() -> None:
    assert (
        "resource workloadDcePrivateLinkScope "
        "'Microsoft.Insights/privateLinkScopes/scopedResources@2021-09-01' = {" in DATA_PLATFORM
    )
    assert "dependsOn: [\n    workloadWorkspacePrivateLinkScope\n  ]" in DATA_PLATFORM
    assert "dependsOn: [\n    workloadDcePrivateLinkScope\n  ]" in DATA_PLATFORM
    assert "dependsOn: [\n    collectorWorkspacePrivateLinkScope\n  ]" in DATA_PLATFORM


def test_wc024_uses_adopted_monitoring_locations_not_deployment_location() -> None:
    assert "@allowed([\n  'australiaeast'\n])\nparam location" in MAIN
    assert "var adoptedWorkspaceLocation = workspace.location" in DATA_PLATFORM
    assert (
        "var adoptedDataCollectionEndpointLocation = dataCollectionEndpoint.location"
        in DATA_PLATFORM
    )
    assert (
        "toLower(adoptedWorkspaceLocation) == "
        "toLower(adoptedDataCollectionEndpointLocation)" in DATA_PLATFORM
    )
    assert (
        "fail('WC-024 requires the adopted Log Analytics workspace and data collection "
        "endpoint to use the same Azure region." in DATA_PLATFORM
    )
    assert "output workspaceLocation string = validatedWorkspaceLocation" in DATA_PLATFORM
    assert "output workspaceDailyQuotaGb" not in DATA_PLATFORM
    assert (
        "output dataCollectionEndpointLocation string = "
        "validatedDataCollectionEndpointLocation" in DATA_PLATFORM
    )
    flow_log_declaration = MAIN.split("module vnetFlowLog", maxsplit=1)[1].split(
        "module legacyFlowLogMigration", maxsplit=1
    )[0]

    assert "workspaceLocation: location" not in flow_log_declaration
    assert (
        "workspaceLocation: monitoringDataPlatform.outputs.workspaceLocation"
        in flow_log_declaration
    )
    assert "location: location" in flow_log_declaration
    assert "location: location" in FLOW_LOG
    assert "output validatedFlowLogLocation string" in FLOW_LOG_VALIDATION


def test_wc024_populates_private_dns_before_workload_vnet_links() -> None:
    assert (
        MAIN.index("module dcrAssociationValidation")
        < MAIN.index("module dcrAssociations")
        < MAIN.index("module workloadPrivateDnsZones")
        < MAIN.index("module monitoringPrivateEndpoints")
        < MAIN.index("module workloadPrivateDnsVnetLinks")
        < MAIN.index("module collectorKeyVaultPrivateDnsLink")
    )
    private_endpoints_declaration = MAIN.split("module monitoringPrivateEndpoints", maxsplit=1)[
        1
    ].split("module workloadPrivateDnsVnetLinks", maxsplit=1)[0]
    private_dns_zones_declaration = MAIN.split("module workloadPrivateDnsZones", maxsplit=1)[
        1
    ].split("module monitoringStorage", maxsplit=1)[0]
    vnet_links_declaration = MAIN.split("module workloadPrivateDnsVnetLinks", maxsplit=1)[1].split(
        "module monitoringEvidenceReaderAssignments", maxsplit=1
    )[0]
    assert "dependsOn: [\n    dcrAssociations\n  ]" in private_endpoints_declaration
    assert "dependsOn: [\n    dcrAssociations\n  ]" in private_dns_zones_declaration
    assert "dependsOn: [\n    monitoringPrivateEndpoints\n  ]" in (vnet_links_declaration)
    key_vault_link_declaration = MAIN.split(
        "module collectorKeyVaultPrivateDnsLink",
        maxsplit=1,
    )[1].split("module monitoringEvidenceReaderAssignments", maxsplit=1)[0]
    assert "dependsOn: [\n    monitoringPrivateEndpoints\n  ]" in (key_vault_link_declaration)


def test_wc024_requires_private_collector_runtime_topology_and_dns_links() -> None:
    for parameter in (
        "workloadPrivateEndpointSubnetResourceId",
        "collectorRuntimeVirtualNetworkResourceId",
        "collectorRuntimeSubnetResourceId",
        "collectorPrivateEndpointSubnetResourceId",
    ):
        assert f"param {parameter} " in MAIN
        assert f"param {parameter} " in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION

    assert "deploymentSubscriptionPrefix" in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    assert "workloadPrivateEndpointSubnetBelongsToWorkloadVnet" in (
        PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    )
    assert "collectorRuntimeSubnetBelongsToCollectorVnet" in (PRIVATE_RUNTIME_TOPOLOGY_VALIDATION)
    assert "collectorPrivateEndpointSubnetBelongsToCollectorVnet" in (
        PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    )
    assert "collectorSubnetsAreDistinct" in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    assert "networksRemainIsolated" in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    assert "module privateRuntimeTopologyValidation" in MAIN
    assert (
        "workloadPrivateEndpointSubnetResourceId: "
        "privateRuntimeTopologyValidation.outputs.workloadPrivateEndpointSubnetResourceId" in MAIN
    )
    assert "collectorRuntimeVirtualNetworkResourceId:" in MAIN
    assert (
        "privateRuntimeTopologyValidation.outputs.collectorRuntimeVirtualNetworkResourceId" in MAIN
    )
    assert "module workloadPrivateDnsVnetLinks" in MAIN
    assert "module collectorPrivateDnsVnetLinks" in MAIN


def test_wc024_connectivity_is_a_separate_isolated_collector_deployment() -> None:
    for exact_name in (
        "rg-athena-demo-monitoring",
        "rg-athena-demo-workload",
        "athena-hackathon-vnet",
        "athena-demo-monitoring-collector-vnet",
    ):
        assert exact_name in CONNECTIVITY_MAIN
    assert "10.45.0.0/24" in CONNECTIVITY_HUB
    assert "10.45.0.0/25" in CONNECTIVITY_HUB
    assert "10.45.0.128/26" in CONNECTIVITY_HUB
    assert "destinationPortRange: '443'" in CONNECTIVITY_HUB
    assert "DenyUnreviewedPrivateEndpointInbound" in CONNECTIVITY_HUB
    assert "privateEndpointNetworkPolicies: 'Enabled'" in CONNECTIVITY_HUB
    assert "virtualNetworkPeerings@" not in CONNECTIVITY_MAIN
    assert "virtualNetworkPeerings@" not in CONNECTIVITY_HUB
    assert "workloadCollectorNetworkConnected" not in CONNECTIVITY_MAIN
    assert "collectorRuntimeSubnetResourceId" in CONNECTIVITY_MAIN
    assert "collectorPrivateEndpointSubnetResourceId" in CONNECTIVITY_MAIN


def test_wc024_rbac_is_collector_only_and_narrow() -> None:
    assert not (WC024_ROOT / "modules" / "monitoring-evidence-reader-role.bicep").exists()
    assert "3b03c2da-16b3-4a49-8834-0f8130efdd3b" in READER_RBAC
    assert "acdd72a7-3385-48ef-bd42-f606fba81ae7" in READER_RBAC
    assert "conditionVersion: '2.0'" not in READER_RBAC
    assert "Microsoft.OperationalInsights/workspaces/tables/data/read" in READER_RBAC
    for table in (
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
    ):
        assert f"  '{table}'" in READER_RBAC
    assert "StringEquals \\'${tableName}\\'" in READER_RBAC
    assert "AzureNetworkAnalytics_CL" not in READER_RBAC
    assert "Microsoft.OperationalInsights/workspaces/tables/data/read" in (COLLECTOR_CONTRACT)
    assert "Microsoft.Compute/virtualMachines/instanceView/read" in (COLLECTOR_CONTRACT)
    assert "Microsoft.Network/networkWatchers/connectionMonitors/read" not in (COLLECTOR_CONTRACT)
    assert "AzureNetworkAnalytics_CL" not in COLLECTOR_CONTRACT
    assert "scope: workspace" not in READER_RBAC
    assert "resource collectorWorkspaceDataReader" not in READER_RBAC
    assert "scope: dataCollectionEndpoint" in READER_RBAC
    assert "scope: dataCollectionRule" in READER_RBAC
    assert "scope: privateLinkScopes[index]" in READER_RBAC
    assert "2fda1d90-37da-55d9-8ac3-132fb7bdca5d" in WORKLOAD_READER_RBAC
    assert "scope: collectorVmSignalReaders" not in WORKLOAD_READER_RBAC
    assert "scope: approvedVms[index]" in WORKLOAD_READER_RBAC
    assert "scope: adoptedDcrAssociations[index]" in WORKLOAD_READER_RBAC
    assert "scope: dceAssociations[index]" in WORKLOAD_READER_RBAC
    assert "map(approvedVms, vm => vm.id)" not in WORKLOAD_READER_RBAC
    assert "dataCollectionRuleAssociations/${dataCollectionRuleAssociationName}" in (
        WORKLOAD_READER_RBAC
    )
    assert "dataCollectionRuleAssociations/${dataCollectionEndpointAssociationName}" in (
        WORKLOAD_READER_RBAC
    )
    vm_signal_assignment = WORKLOAD_READER_RBAC.split(
        "resource collectorVmSignalReaders",
        maxsplit=1,
    )[1].split("resource collectorDcrAssociationReaders", maxsplit=1)[0]
    assert "roleDefinitionId: validatedSignalReaderRoleDefinitionId" in (vm_signal_assignment)
    assert "roleDefinitionId: readerRoleDefinitionId" not in vm_signal_assignment
    resource_health_assignment = WORKLOAD_READER_RBAC.split(
        "resource collectorVmResourceHealthReaders",
        maxsplit=1,
    )[1].split("resource collectorDcrAssociationReaders", maxsplit=1)[0]
    assert "scope: approvedVms[index]" in resource_health_assignment
    assert "roleDefinitionId: resourceHealthRoleDefinition.id" in (resource_health_assignment)
    assert "roleDefinitionId: readerRoleDefinitionId" not in resource_health_assignment
    assert "0790d6f2-9553-5b63-84ac-56596b7e4072" in WORKLOAD_READER_RBAC
    assert "Microsoft.ResourceHealth/availabilityStatuses/read" in WORKLOAD_READER_RBAC
    resource_health_role = WORKLOAD_READER_RBAC.split(
        "resource resourceHealthRoleDefinition",
        maxsplit=1,
    )[1].split("var signalReaderPermission", maxsplit=1)[0]
    assert "Microsoft.ResourceGraph/resources/read" not in resource_health_role
    assert "Microsoft.Compute/virtualMachines/read" not in resource_health_role
    assert "Microsoft.ResourceHealth/availabilityStatuses/current/read" not in (
        WORKLOAD_READER_RBAC
    )
    assert "resourceHealthAllowedOperations" in WORKLOAD_READER_RBAC
    assert "5687977f-aa06-5699-8e18-1a54a074b532" in WORKLOAD_READER_RBAC
    assert "Microsoft.ResourceGraph/resources/read" in WORKLOAD_READER_RBAC
    query_role = WORKLOAD_READER_RBAC.split(
        "resource resourceGraphQueryRoleDefinition",
        maxsplit=1,
    )[1].split("resource resourceHealthRoleDefinition", maxsplit=1)[0]
    assert "resourceGroup().id" in query_role
    assert "subscription().id" not in query_role
    assert "Microsoft.ResourceHealth/availabilityStatuses/read" not in query_role
    assert "*/read" not in query_role
    assert "Microsoft.Compute/virtualMachines/read" not in query_role
    query_assignment = WORKLOAD_READER_RBAC.split(
        "resource collectorResourceGraphQueryReader",
        maxsplit=1,
    )[1].split("resource collectorVmSignalReaders", maxsplit=1)[0]
    assert "scope: resourceGroup()" in query_assignment
    assert "roleDefinitionId: resourceGraphQueryRoleDefinition.id" in query_assignment
    assert "scope: approvedVms[index]" not in query_assignment
    assert "resourceGraphQueryRoleDefinitionId" in WORKLOAD_READER_RBAC
    assert "resourceGraphQueryScopeId" in WORKLOAD_READER_RBAC
    assert "resourceHealthAllowedOperations" in WORKLOAD_READER_RBAC
    assert (
        "resourceHealthAllowedOperations = concat(\n"
        "  resourceGraphQueryAllowedOperations,\n"
        "  resourceHealthRoleAllowedOperations\n"
        ")" in WORKLOAD_READER_RBAC
    )
    assert "workloadEvidenceReaderAssignments.outputs.resourceGraphQueryRoleDefinitionId" in MAIN
    assert "dataActions: []" in WORKLOAD_READER_RBAC
    assert "expectedSignalReaderActions" in WORKLOAD_READER_RBAC
    assert "unexpectedSignalReaderActions" in WORKLOAD_READER_RBAC
    for operation in (
        "Microsoft.Insights/Logs/Heartbeat/Read",
        "Microsoft.Insights/Logs/Perf/Read",
        "Microsoft.Insights/Logs/InsightsMetrics/Read",
        "Microsoft.Insights/Logs/Syslog/Read",
        "Microsoft.Insights/Logs/VMConnection/Read",
    ):
        assert operation in WORKLOAD_READER_RBAC
    assert "Microsoft.Insights/logs/NTANetAnalytics/read" not in WORKLOAD_READER_RBAC
    assert "Microsoft.Insights/logs/NWConnectionMonitorTestResult/read" not in WORKLOAD_READER_RBAC
    assert "Microsoft.Insights/logs/*/read" not in WORKLOAD_READER_RBAC
    assert "f33a4363-5d9a-5d50-9871-c08582234978" in WORKLOAD_READER_RBAC
    resource_log_assignment = WORKLOAD_READER_RBAC.split(
        "resource collectorVmResourceLogReaders",
        maxsplit=1,
    )[1].split("resource collectorVmResourceHealthReaders", maxsplit=1)[0]
    assert "scope: approvedVms[index]" in resource_log_assignment
    assert "roleDefinitionId: resourceLogReaderRoleDefinition.id" in (resource_log_assignment)
    assert "scope: resourceGroup()" not in resource_log_assignment
    assert "signalReaderAssignableScopes" in WORKLOAD_READER_RBAC
    assert "length(signalReaderRoleDefinition.properties.permissions) == 1" in (
        WORKLOAD_READER_RBAC
    )
    flow_log_assignment = NETWORK_WATCHER_READER_RBAC.split(
        "resource collectorFlowLogReader",
        maxsplit=1,
    )[1].split("output readerRoleDefinitionId", maxsplit=1)[0]
    assert "scope: flowLog" in flow_log_assignment
    assert "roleDefinitionId: readerRoleDefinitionId" in flow_log_assignment
    assert "scope: networkWatcher" not in flow_log_assignment
    assert "collectorIpFlowVerifier" not in NETWORK_WATCHER_READER_RBAC
    assert "ipFlowVerify/action" not in NETWORK_WATCHER_READER_RBAC
    assert "ipFlowVerify/read" not in NETWORK_WATCHER_READER_RBAC
    assert "Microsoft.Network/networkWatchers/read" not in NETWORK_WATCHER_READER_RBAC
    for operation in (
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Authorization/roleDefinitions/read",
        "Microsoft.Authorization/denyAssignments/read",
        "Microsoft.Authorization/roleAssignmentScheduleInstances/read",
        "Microsoft.App/jobs/read",
        "Microsoft.KeyVault/vaults/read",
        "Microsoft.ManagedIdentity/userAssignedIdentities/listAssociatedResources/action",
        "Microsoft.ManagedIdentity/userAssignedIdentities/read",
        "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read",
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Storage/storageAccounts/blobServices/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/read",
    ):
        assert operation in RBAC_ATTESTOR
    assert "dataActions: []" in RBAC_ATTESTOR
    assert "notActions: []" in RBAC_ATTESTOR
    assert "scope: subscription()" in RBAC_ATTESTOR
    assert "extension microsoftGraphV1" in RBAC_ATTESTOR
    assert "Microsoft.Graph/appRoleAssignedTo@v1.0" in RBAC_ATTESTOR
    assert "00000003-0000-0000-c000-000000000000" in RBAC_ATTESTOR
    assert "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" in RBAC_ATTESTOR
    assert "Microsoft.Graph/applications@v1.0" in IDENTITY_PROOF_AUTHORITY
    assert "Microsoft.Graph/servicePrincipals@v1.0" in IDENTITY_PROOF_AUTHORITY
    assert "Microsoft.Graph/appRoleAssignedTo@v1.0" in IDENTITY_PROOF_AUTHORITY
    assert "requestedAccessTokenVersion: 1" in IDENTITY_PROOF_AUTHORITY
    assert "name: 'idtyp'" in IDENTITY_PROOF_AUTHORITY
    assert "essential: true" in IDENTITY_PROOF_AUTHORITY
    assert "api://${toLower(tenantId)}/athena-monitoring-identity-proof" in (
        IDENTITY_PROOF_AUTHORITY
    )
    assert "principalId: collectorPrincipalId" in IDENTITY_PROOF_AUTHORITY
    combined_rbac = READER_RBAC + WORKLOAD_READER_RBAC + NETWORK_WATCHER_READER_RBAC + RBAC_ATTESTOR
    assert "Owner" not in combined_rbac
    assert "Contributor" not in combined_rbac
    assert "collectorPrincipalId" in combined_rbac
    for forbidden_identity in (
        "athenacontext",
        "presentation",
        "correlation",
        "mcpidentity",
    ):
        assert forbidden_identity not in combined_rbac.lower()
    assert "collectorIdentity.properties.principalId" in EVIDENCE_SEAMS
    assert "collectorIdentity.properties.tenantId" in EVIDENCE_SEAMS
    assert "scope: monitoringEvidenceContainer" in EVIDENCE_SEAMS
    assert "scope: signingKey" in EVIDENCE_SEAMS
    assert "Athena WC028 Monitoring Evidence Create-Only Writer" in EVIDENCE_SEAMS
    assert "containers/blobs/read" in EVIDENCE_SEAMS
    assert "containers/blobs/add/action" in EVIDENCE_SEAMS
    assert "containers/blobs/write" not in EVIDENCE_SEAMS
    assert "Storage Blob Data Contributor" not in EVIDENCE_SEAMS
    assert "SubOperationMatches{\\'Blob.List\\'}" in EVIDENCE_SEAMS
    assert "conditionVersion: '2.0'" in EVIDENCE_SEAMS
    assert "targetScope = 'subscription'" in EVIDENCE_WRITER_ROLE
    assert "Athena WC028 Monitoring Evidence Create-Only Writer" in EVIDENCE_WRITER_ROLE
    assert "containers/blobs/read" in EVIDENCE_WRITER_ROLE
    assert "containers/blobs/add/action" in EVIDENCE_WRITER_ROLE
    assert "containers/blobs/write" not in EVIDENCE_WRITER_ROLE
    assert "module monitoringEvidenceWriterRole" in MAIN
    assert (
        "evidenceWriterRoleDefinitionId: monitoringEvidenceWriterRole.outputs.roleDefinitionId"
        in MAIN
    )
    assert "listKeys" not in EVIDENCE_SEAMS
    assert "Athena WC028 RBAC Reviewer Public Key Reader" in REVIEWER_KEY_READER_ROLE
    assert "Microsoft.KeyVault/vaults/keys/read" in REVIEWER_KEY_READER_ROLE
    assert "Microsoft.KeyVault/vaults/keys/sign/action" not in REVIEWER_KEY_READER_ROLE
    assert "scope: reviewerKey" in REVIEWER_KEY_READER_ASSIGNMENT
    assert "principalType: 'ServicePrincipal'" in REVIEWER_KEY_READER_ASSIGNMENT
    assert "module monitoringReviewerKeyReaderRole" in MAIN
    assert "module monitoringReviewerKeyReaderAssignment" in MAIN


def test_wc024_uses_exact_resource_scopes_and_separate_rbac_attestor() -> None:
    assert "workloadSubscriptionId" not in MAIN
    assert "networkWatcherSubscriptionId" not in MAIN
    assert "collectorRoleDefinitionGuid" not in MAIN
    assert "monitoring-evidence-reader-role.bicep" not in MAIN
    assert (
        "var workloadResourceGroupId = '${subscription().id}/resourceGroups/"
        "${workloadResourceGroupName}'"
    ) in MAIN
    assert "@allowed([\n  'NetworkWatcherRG'\n])" in MAIN
    assert "@allowed([\n  'NetworkWatcher_australiaeast'\n])" in MAIN
    assert "module monitoringEvidenceReaderAssignments" in MAIN
    assert "module workloadEvidenceReaderAssignments" in MAIN
    assert "module networkWatcherEvidenceReaderAssignment" in MAIN
    assert "module monitoringRbacAttestor" in MAIN
    assert "targetScope = 'resourceGroup'" in READER_RBAC
    assert "targetScope = 'resourceGroup'" in WORKLOAD_READER_RBAC
    assert "targetScope = 'resourceGroup'" in NETWORK_WATCHER_READER_RBAC
    assert "ipFlowVerifyRoleDefinitionGuid" not in NETWORK_WATCHER_READER_RBAC
    assert "2a8d9aea-2688-5841-a7e4-82f23d0f1bac" in RBAC_ATTESTOR
    assert "scope: resourceGroup(workloadResourceGroupName)" in MAIN
    assert "scope: resourceGroup(networkWatcherResourceGroupName)" in MAIN
    workload_assignment = MAIN.split(
        "module workloadEvidenceReaderAssignments",
        maxsplit=1,
    )[1].split("module canonicalFlowLogValidation", maxsplit=1)[0]
    assert "dependsOn: [\n    dcrAssociations\n  ]" in workload_assignment


def test_wc024_collector_contract_is_signed_handoff_ready_and_generic_only() -> None:
    assert "athena.wc024MonitoringCollectorContract.v2" in COLLECTOR_CONTRACT
    assert "athena.wc024MonitoringEvidenceHandoff.v1" in COLLECTOR_CONTRACT
    assert "isolatedSignedCollector" in COLLECTOR_CONTRACT
    assert "capabilityOnly" in COLLECTOR_CONTRACT
    assert "authorizationMode: authorizationMode" in COLLECTOR_CONTRACT
    assert "workspaceAccessControlMode: workspaceAccessControlMode" in (COLLECTOR_CONTRACT)
    assert "readerRoleDefinitionId: readerRoleDefinitionId" in COLLECTOR_CONTRACT
    assert "signalReaderRoleDefinitionId: signalReaderRoleDefinitionId" in (COLLECTOR_CONTRACT)
    assert (
        "logAnalyticsDataReaderRoleDefinitionId: logAnalyticsDataReaderRoleDefinitionId"
    ) in COLLECTOR_CONTRACT
    assert "logAnalyticsAllowedTables: logAnalyticsAllowedTables" in COLLECTOR_CONTRACT
    assert "logAnalyticsAccessCondition: logAnalyticsAccessCondition" in (COLLECTOR_CONTRACT)
    assert "resourceReadScopeIds: resourceReadScopeIds" in COLLECTOR_CONTRACT
    assert "signalReadScopeIds: signalReadScopeIds" in COLLECTOR_CONTRACT
    assert "athena.wc028MonitoringCollectorContract.v10" in COLLECTOR_CONTRACT
    assert "athena.wc028MonitoringAcquisitionReceipt.v6" in COLLECTOR_CONTRACT
    assert "validatedAcquisitionWorkspaceAccessControlMode" in COLLECTOR_CONTRACT
    assert "resource-context Log Analytics mode" in COLLECTOR_CONTRACT
    assert "effectiveRbacInventory: effectiveRbacInventory" in COLLECTOR_CONTRACT
    assert "runtimeSupportStorageReaderRoleDefinitionId" in COLLECTOR_CONTRACT
    assert "evidenceContainerPublicAccess" in COLLECTOR_CONTRACT
    assert "evidenceStorageReadbackBindingId" in COLLECTOR_CONTRACT
    assert "evidenceStorageReadinessDigest" in COLLECTOR_CONTRACT
    assert "param monitoringEffectiveRbacInventory" not in MAIN
    assert "athena.wc024MonitoringRbacBootstrapHandoff.v1" in PHASE_ONE
    assert "blockedPendingEffectiveRbacInventory" in PHASE_ONE
    assert "subscriptionAssignedToAllInheritedAndUnfilteredWithProtectedScopes" in PHASE_ONE
    assert "allPrincipalRoleAssignmentCollectionScopeId: subscription().id" in PHASE_ONE
    assert "allPrincipalRoleAssignmentQueryFilter: 'none'" in PHASE_ONE
    assert "roleAssignmentApiVersion: '2022-04-01'" in PHASE_ONE
    assert (
        "managementGroupAncestorDisposition: "
        "'explicitManagementGroupAndTenantRootEnumerationRequired'" in PHASE_ONE
    )
    assert "roleAssignmentIncludeInherited: true" in PHASE_ONE
    assert "roleAssignmentIncludeGroups: true" in PHASE_ONE
    assert "explicitManagementGroupAndTenantRootEnumerationRequired" in PHASE_ONE
    assert "allPrincipalRoleAssignmentIncludeInherited: true" in PHASE_ONE
    assert "denyAssignmentIncludeInherited: true" in PHASE_ONE
    assert "pimScheduleInstanceIncludeInherited: true" in PHASE_ONE
    assert "output monitoringRbacBootstrapHandoff object" in PHASE_ONE
    assert "sourceDeploymentName: deployment().name" in PHASE_ONE
    assert "sourceDeploymentId: sourceDeploymentId" in PHASE_ONE
    assert "collectorContractInputsBindingId: collectorContractInputsBindingId" in PHASE_ONE
    assert "collectorContractInputsBindingId = guid(string(collectorContractInputs))" in PHASE_ONE
    assert "directoryMembershipCollection:" in PHASE_ONE
    assert (
        "module monitoringIdentityProofAuthority "
        "'modules/monitoring-identity-proof-authority.bicep'" in MAIN
    )
    assert "identityProofAuthority:" in PHASE_ONE
    assert "managedIdentityAttachmentCollection:" in PHASE_ONE
    assert "listAssociatedResources?api-version=2021-09-30-preview" in MAIN
    assert "federatedIdentityCredentials?api-version=2023-01-31" in MAIN
    assert "exclusiveDataPlanePrincipalCollection:" in PHASE_ONE
    assert "evidenceStorageConfigurationRequestPath" in MAIN
    assert "evidenceBlobServiceConfigurationRequestPath" in MAIN
    assert "evidenceContainerConfigurationRequestPath" in MAIN
    assert "evidenceImmutabilityPolicyConfigurationRequestPath" in MAIN
    assert "signingKeyVaultConfigurationRequestPath" in MAIN
    assert "legacyCollectorRbacCleanupDigest" in MAIN
    assert "reviewAuthoritySeparationEnforced" in MAIN
    main_review_separation = MAIN[
        MAIN.index("var reviewAuthoritySeparation =") : MAIN.index(
            "var resourceReadScopeIds ="
        )
    ]
    publish_review_separation = PUBLISH_CONTRACT[
        PUBLISH_CONTRACT.index("var reviewAuthorityIsSeparated =") : PUBLISH_CONTRACT.index(
            "var expectedCollectorAssociatedResourcesRequestPath ="
        )
    ]
    assert "toLower(runtimeSupportIdentity.properties.principalId)" in main_review_separation
    assert (
        "toLower(contractInputs.runtimeSupportIdentityPrincipalId)"
        in publish_review_separation
    )
    assert (
        "toLower(collectorContractInputs.runtimeSupportIdentityPrincipalId)"
        in RBAC_BOOTSTRAP_HANDOFF
    )
    assert "validatedRbacInventoryReviewAuthority" in MAIN
    assert "reviewedRbacInventoryReviewerVaultHost" in MAIN
    assert "athenarbacevidencekv.${environment().suffixes.keyvaultDns}" in MAIN
    assert "monitoring-rbac-inventory-review" in MAIN
    assert "graphApplicationReadAllAssignmentId" in MAIN
    assert "ConsistencyLevel: 'eventual'" in MAIN
    assert "$count=true&$select=id" in MAIN
    assert "workspaceTableResourceIds" in MAIN
    assert "evidenceBlobServiceResourceId" in MAIN
    assert "evidenceImmutabilityPolicyResourceId" in MAIN
    assert "networkWatcherResourceGroupId" in MAIN
    assert "networkWatcherResourceId" in MAIN
    assert "signingKeyVaultResourceId" in MAIN
    assert "param monitoringEffectiveRbacInventory object" in PUBLISH_CONTRACT
    assert "param monitoringRbacBootstrapDeploymentName string" in PUBLISH_CONTRACT
    assert "param reviewedMonitoringEffectiveRbacInventoryDigest string" in PUBLISH_CONTRACT
    assert "param monitoringEffectiveRbacInventoryAttestation object" in PUBLISH_CONTRACT
    assert "param collectorRuntimeResourceId string" in PUBLISH_CONTRACT
    assert "param rbacAttestorRuntimeResourceId string" in PUBLISH_CONTRACT
    assert "param runtimeSupportIdentityResourceId string" in PUBLISH_CONTRACT
    assert "rbacInventoryVerifierIdentityResourceId" in PUBLISH_CONTRACT
    assert "reviewerKeyVerifierEvidence" in PUBLISH_CONTRACT
    assert "verifierEvidenceMatches" in PUBLISH_CONTRACT
    assert "verifierRoleDefinitionMatches" in PUBLISH_CONTRACT
    assert "verifierDenyAssignmentsAreSafe" in PUBLISH_CONTRACT
    assert "validatedReviewedInventoryDigest" in PUBLISH_CONTRACT
    assert "Microsoft.Resources/deployments@2025-04-01" in PUBLISH_CONTRACT
    assert "monitoringRbacBootstrapDeployment.properties.outputs" in PUBLISH_CONTRACT
    assert "athena.wc024MonitoringContractPublicationHandoff.v1" in PUBLISH_CONTRACT
    assert "athena.wc028MonitoringEffectiveRbacInventory.v6" in PUBLISH_CONTRACT
    assert "athena.wc028MonitoringEffectiveRbacInventoryAttestation.v2" in PUBLISH_CONTRACT
    assert "resourceGraphQueryRoleActions" in PUBLISH_CONTRACT
    assert "resourceHealthRoleActions" in PUBLISH_CONTRACT
    assert "resourceGraphQueryScopeIsExact" in PUBLISH_CONTRACT
    assert "resourceHealthOperationTupleIsExact" in PUBLISH_CONTRACT
    assert "resourceHealthReasonAuthorityIsExact" in PUBLISH_CONTRACT
    assert "resourceHealthReasonAuthorityMode: 'availabilityStatusUnknownOnly'" in MAIN
    assert "resourceHealthReasonEvidenceVersion: 2" in MAIN
    assert "resourceHealthReasonAuthorityMode: resourceHealthReasonAuthorityMode" in (
        COLLECTOR_CONTRACT
    )
    assert "resourceHealthReasonEvidenceVersion: resourceHealthReasonEvidenceVersion" in (
        COLLECTOR_CONTRACT
    )
    assert "contractInputs.resourceHealthAllowedOperations[0]" in PUBLISH_CONTRACT
    assert "contractInputs.resourceHealthAllowedOperations[1]" in PUBLISH_CONTRACT
    assert "length(normalizedResourceHealthScopeIds) + 5" in PUBLISH_CONTRACT
    assert "expectedHandoffId = guid(" in PUBLISH_CONTRACT
    assert "handoff.handoffId == expectedHandoffId" in PUBLISH_CONTRACT
    assert "handoffTargetsAreUnique" in PUBLISH_CONTRACT
    assert "collectorTargetsAreUnique" in PUBLISH_CONTRACT
    assert "contextTargetsAreUnique" in PUBLISH_CONTRACT
    assert "targetReadEvidence" in PUBLISH_CONTRACT
    assert "assignedToPrincipalIncludingInheritedGroupsAndDescendants" in PUBLISH_CONTRACT
    assert "collectorTargetBindingsAreValid" in PUBLISH_CONTRACT
    assert "contextTargetBindingsAreValid" in PUBLISH_CONTRACT
    assert "runtimeSupportTargetBindingsAreValid" in PUBLISH_CONTRACT
    assert "targetRead.bindingId != guid(" in PUBLISH_CONTRACT
    assert "contains(evidence, 'roleAssignmentRawPageDigests')" in PUBLISH_CONTRACT
    assert "contains(evidence, 'transitiveGroupRawPageDigests')" in PUBLISH_CONTRACT
    assert "module publicationClock 'modules/deployment-timestamp.bicep'" in PUBLISH_CONTRACT
    assert "publicationClock.outputs.deploymentTimestamp" in PUBLISH_CONTRACT
    assert "inventoryIsFresh" in PUBLISH_CONTRACT
    assert "independentReadTimesAreValid" in PUBLISH_CONTRACT
    assert "globalRepeatedReadPagesAreStable" in PUBLISH_CONTRACT
    assert "principalEvidenceIsComplete" in PUBLISH_CONTRACT
    assert "collectorAttachmentMatches" in PUBLISH_CONTRACT
    assert "attestorAttachmentMatches" in PUBLISH_CONTRACT
    assert "associatedResourceIdentityResourceIds" in PUBLISH_CONTRACT
    assert "associatedResourceConfigurationRequestPaths" in PUBLISH_CONTRACT
    assert "expectedCollectorRuntimeConfigurationRequestPath" in PUBLISH_CONTRACT
    assert "exclusivePrincipalEvidenceMatches" in PUBLISH_CONTRACT
    assert "evidenceStorageSharedKeyAccessEnabled == false" in PUBLISH_CONTRACT
    assert "evidenceBlobVersioningEnabled" in PUBLISH_CONTRACT
    assert "evidenceContainerHasImmutabilityPolicy" in PUBLISH_CONTRACT
    assert "evidenceContainerImmutabilityPolicyState" in PUBLISH_CONTRACT
    assert "evidenceContainerImmutabilityPeriodDays" in PUBLISH_CONTRACT
    assert "evidenceWriterRoleDefinitionMatches" in PUBLISH_CONTRACT
    assert "expectedEvidenceWriterCondition" in PUBLISH_CONTRACT
    assert "signingKeyVaultRbacAuthorizationEnabled == true" in PUBLISH_CONTRACT
    assert "allPrincipalRoleAssignmentQueryFilter == 'none'" in PUBLISH_CONTRACT
    assert "subscriptionAssignedToAllInheritedAndUnfilteredWithProtectedScopes" in PUBLISH_CONTRACT
    assert "collectorGrantsMatch" in PUBLISH_CONTRACT
    assert "missingOrDuplicateExpectedCollectorGrants" in PUBLISH_CONTRACT
    assert "roleDefinitionSetMatches" in PUBLISH_CONTRACT
    assert "collectorEffectivePrincipalIds" in PUBLISH_CONTRACT
    assert "effectiveDenyAssignments" in PUBLISH_CONTRACT
    assert "denyAssignmentsAreSafe" in PUBLISH_CONTRACT
    assert "empty(inventory.denyAssignments)" not in PUBLISH_CONTRACT
    assert "inventory.inventoryDigest == validatedReviewedInventoryDigest" in (PUBLISH_CONTRACT)
    assert "identityProofAuthorityMatches" in PUBLISH_CONTRACT
    assert "expectedIdentityProofAudience" in PUBLISH_CONTRACT
    assert "unproved parent-scope completeness is forbidden" in PUBLISH_CONTRACT
    assert "module inventoryAttestationValidation" in PUBLISH_CONTRACT
    assert "monitoring-rbac-inventory-attestation-validation.bicep" in PUBLISH_CONTRACT
    assert "inventoryAttestationValidation.outputs.validated == true" in PUBLISH_CONTRACT
    assert "inventoryAttestation.bootstrapHandoffId == handoff.handoffId" in PUBLISH_CONTRACT
    assert "inventoryAttestation.bootstrapTemplateHash == bootstrapTemplateHash" in (
        PUBLISH_CONTRACT
    )
    assert "sealedInventoryAttestation" in PUBLISH_CONTRACT
    assert "effectiveRbacInventoryAttestation: sealedInventoryAttestation" in PUBLISH_CONTRACT
    assert "module bootstrapCoreValidationGate" in PUBLISH_CONTRACT
    assert "module inventoryAttestationValidationGate" in PUBLISH_CONTRACT
    assert "module inventoryCoreValidationGate" in PUBLISH_CONTRACT
    assert "module inventoryPrivilegeValidationGate" in PUBLISH_CONTRACT
    assert "inventoryValidationGate" not in PUBLISH_CONTRACT
    assert "targetScope = 'subscription'" in PUBLICATION_VALIDATION_GATE
    assert "output validated bool = valid ? true : fail(failureMessage)" in (
        PUBLICATION_VALIDATION_GATE
    )
    assert "legacyCollectorRbacCleanupDigest" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "ATHENA_BOOTSTRAP_HANDOFF_ID" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "ATHENA_BOOTSTRAP_DEPLOYMENT_ID" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "ATHENA_BOOTSTRAP_TEMPLATE_HASH" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "ATHENA_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID" in (RBAC_INVENTORY_ATTESTATION_VALIDATION)
    assert "effectiveRbacCryptographicReviewVerified" in PUBLISH_CONTRACT
    assert "module collectorContract" in PUBLISH_CONTRACT
    assert "monitoringEffectiveRbacInventory" not in PARAMETERS
    assert "ipFlowVerifyRoleDefinitionId" not in COLLECTOR_CONTRACT
    assert "ipFlowVerifyScopeId" not in COLLECTOR_CONTRACT
    assert "ipFlowVerifyAllowedOperations" not in COLLECTOR_CONTRACT
    assert "flowTableAcquisitionMode: 'unsupportedUnavailable'" in COLLECTOR_CONTRACT
    assert "workspaceResourceContextAccessEnabled" in COLLECTOR_CONTRACT
    assert "workspaceSkuName: workspaceSkuName" in COLLECTOR_CONTRACT
    assert "resourceContextTablePlans: resourceContextTablePlans" in COLLECTOR_CONTRACT
    assert "resourceIdColumn: '_ResourceId'" in COLLECTOR_CONTRACT
    assert "logQueryPreferHeader: 'include-permissions=true'" in COLLECTOR_CONTRACT
    assert "rbacAttestorIdentityResourceId" in COLLECTOR_CONTRACT
    assert "rbacAttestorRoleDefinitionId" in COLLECTOR_CONTRACT
    assert "rbacAttestorAllowedOperations" in COLLECTOR_CONTRACT
    assert "collectorRuntimeResourceId: collectorRuntimeResourceId" in COLLECTOR_CONTRACT
    assert "rbacAttestorRuntimeResourceId: rbacAttestorRuntimeResourceId" in COLLECTOR_CONTRACT
    assert "runtimeSupportIdentityResourceId: runtimeSupportIdentityResourceId" in (
        COLLECTOR_CONTRACT
    )
    assert "effectiveRbacInventoryAttestation: effectiveRbacInventoryAttestation" in (
        COLLECTOR_CONTRACT
    )
    assert "evidenceWriterAllowedDataActions: evidenceWriterAllowedDataActions" in (
        COLLECTOR_CONTRACT
    )
    assert "evidenceWriterAssignmentCondition: evidenceWriterAssignmentCondition" in (
        COLLECTOR_CONTRACT
    )
    assert "legacyCollectorRbacCleanupDigest: legacyCollectorRbacCleanupDigest" in (
        COLLECTOR_CONTRACT
    )
    assert "collectorTenantId: collectorTenantId" in COLLECTOR_CONTRACT
    assert "identityProofAudience: identityProofAudience" in COLLECTOR_CONTRACT
    assert "identityProofApplicationId: identityProofApplicationId" in COLLECTOR_CONTRACT
    assert "identityProofApplicationObjectId: identityProofApplicationObjectId" in (
        COLLECTOR_CONTRACT
    )
    assert "identityProofServicePrincipalId: identityProofServicePrincipalId" in (
        COLLECTOR_CONTRACT
    )
    assert "identityProofAppRoleId: identityProofAppRoleId" in COLLECTOR_CONTRACT
    assert "identityProofAppRoleAssignmentId: identityProofAppRoleAssignmentId" in (
        COLLECTOR_CONTRACT
    )
    assert "identityProofAssignedPrincipalId: identityProofAssignedPrincipalId" in (
        COLLECTOR_CONTRACT
    )
    assert "identityProofTokenVersion: '1.0'" in COLLECTOR_CONTRACT
    assert "identityProofRequiredRole: identityProofAppRoleValue" in COLLECTOR_CONTRACT
    assert "identityProofMaximumLifetimeSeconds: 7200" in COLLECTOR_CONTRACT
    assert "resourceGraphQueryRoleDefinitionId: resourceGraphQueryRoleDefinitionId" in (
        COLLECTOR_CONTRACT
    )
    assert "resourceGraphQueryScopeId: resourceGraphQueryScopeId" in COLLECTOR_CONTRACT
    assert "resourceHealthRoleDefinitionId: resourceHealthRoleDefinitionId" in (COLLECTOR_CONTRACT)
    assert "resourceHealthScopeIds: resourceHealthScopeIds" in COLLECTOR_CONTRACT
    assert "resourceHealthAllowedOperations: validatedResourceHealthAllowedOperations" in (
        COLLECTOR_CONTRACT
    )
    assert "validatedResourceHealthAllowedOperations" in COLLECTOR_CONTRACT
    assert "workspaceResourceContextAccessEnabled" in DATA_PLATFORM
    assert "resourceContextTablePlans" in DATA_PLATFORM
    assert "plan: resourceContextTables[index].properties.plan == 'Analytics'" in (DATA_PLATFORM)
    assert "'workspaceAndResourceContext'" in MAIN
    assert "'workspaceOnly'" in MAIN
    assert "Microsoft.Network/networkWatchers/connectionMonitors/read" not in (COLLECTOR_CONTRACT)
    assert "workloadVirtualNetworkResourceId: workloadVirtualNetworkResourceId" in (
        COLLECTOR_CONTRACT
    )
    assert "approvedVmNames: approvedVmNames" in COLLECTOR_CONTRACT
    assert "signingKeyResourceId: signingKeyResourceId" in COLLECTOR_CONTRACT
    assert (
        "evidenceStorageAccountResourceId: evidenceStorageAccountResourceId" in COLLECTOR_CONTRACT
    )
    assert "evidenceContainerName: 'monitoring-evidence'" in COLLECTOR_CONTRACT
    assert "connectionMonitorDeploymentMode: validatedConnectionMonitorDeploymentMode" in (
        COLLECTOR_CONTRACT
    )
    for signal in (
        "heartbeat",
        "perf",
        "insightsMetrics",
        "syslog",
        "disk",
        "guest",
        "vnetFlow",
        "trafficAnalytics",
    ):
        assert f"'{signal}'" in COLLECTOR_CONTRACT
    assert "unpublished" not in COLLECTOR_CONTRACT.lower()
    assert "endpointpath" not in COLLECTOR_CONTRACT.lower()


def test_wc024_connection_monitor_is_capability_only() -> None:
    all_bicep = "\n".join(path.read_text(encoding="utf-8") for path in WC024_ROOT.rglob("*.bicep"))

    assert "connectionMonitorDeploymentEnabled" in CONNECTION_MONITOR
    assert "capability-only" in CONNECTION_MONITOR
    assert "fail('WC-024 provides Connection Monitor capability only" in CONNECTION_MONITOR
    assert "Microsoft.Network/networkWatchers/connectionMonitors@" not in all_bicep


def test_wc024_example_parameters_are_synthetic_and_keyless() -> None:
    assert "Synthetic, non-deployable values" in PARAMETERS
    assert "00000000-0000-0000-0000-000000000000" in PARAMETERS
    assert "athenahackathonflowwhtco" not in PARAMETERS
    assert "legacyFlowLogNames = []" in PARAMETERS
    assert "canonicalVnetFlowLogCutoverConfirmed = false" in PARAMETERS
    assert "privateLinkScopeDeploymentPhase" not in PARAMETERS
    assert "workloadPrivateEndpointSubnetResourceId" in PARAMETERS
    assert "collectorRuntimeVirtualNetworkResourceId" in PARAMETERS
    assert "collectorRuntimeSubnetResourceId" in PARAMETERS
    assert "collectorPrivateEndpointSubnetResourceId" in PARAMETERS
    assert "collectorRuntimeResourceId" in PARAMETERS
    assert "rbacAttestorRuntimeResourceId" in PARAMETERS
    assert "runtimeSupportIdentityResourceId" in PARAMETERS
    for vm_name in (
        "athena-hackathon-client-01",
        "athena-hackathon-ecp-01",
        "athena-hackathon-ecp-03",
        "athena-hackathon-iris-01",
        "athena-hackathon-mid-01",
        "athena-hackathon-mid-02",
        "athena-hackathon-sqlvm-01",
        "athena-hackathon-web-01",
        "athena-hackathon-web-03",
    ):
        assert f"'{vm_name}'" in PARAMETERS
    assert "virtualNetworks/athena-hackathon-vnet" in PARAMETERS
    assert "password" not in PARAMETERS.lower()
    assert "clientsecret" not in PARAMETERS.lower()
    assert "connectionstring" not in PARAMETERS.lower()


def test_wc024_records_and_preserves_the_live_telemetry_cutover_baseline() -> None:
    for signal in (
        "Heartbeat",
        "Perf",
        "InsightsMetrics",
        "Syslog",
        "AthenaApp_CL",
        "NTANetAnalytics",
    ):
        assert signal in ADR
        assert signal in COLLECTOR_CONTRACT or signal in DATA_PLATFORM or signal in READER_RBAC
    assert "All 11 workload VMs had successful" in ADR
    assert "configurationAccessEndpoint" in ADR
    assert "DCR association is read without being rewritten" in ADR
    assert "AzureMonitorLinuxAgent" in ADR
    assert "Shared Key disabled" in ADR
    assert "private-access cutover operation" in ADR
    assert "AMPLS resources" in ADR
    assert "remain open" in ADR
    assert "empty private zones" in ADR
    assert "storage account keeps public network access" in ADR
    assert "enabled solely to activate the storage firewall" in ADR
    assert "30-day retention" in ADR
    assert "`workspaceCapping.dailyQuotaGb` of `-1`" in ADR
    assert "`features.disableLocalAuth` set to `true`" in ADR


def test_wc024_phase_two_cryptographically_verifies_external_rbac_review() -> None:
    assert "Microsoft.Resources/deploymentScripts@2023-08-01" in (
        RBAC_INVENTORY_ATTESTATION_VALIDATION
    )
    assert "azCliVersion: '2.88.0'" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "cleanupPreference: 'Always'" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "retentionInterval: 'PT1H'" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "loadTextContent('../scripts/verify-rbac-inventory-attestation.py')" in (
        RBAC_INVENTORY_ATTESTATION_VALIDATION
    )
    assert "verifierSourceBase64 = base64(" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "base64 --decode" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "python3 /tmp/verify-rbac-inventory-attestation.py" in (
        RBAC_INVENTORY_ATTESTATION_VALIDATION
    )
    assert "param verifierIdentityResourceId string" in (RBAC_INVENTORY_ATTESTATION_VALIDATION)
    assert "type: 'UserAssigned'" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "'${verifierIdentityResourceId}': {}" in (RBAC_INVENTORY_ATTESTATION_VALIDATION)
    assert "az keyvault key show --id" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "ATHENA_REVIEWER_JWK_JSON" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "ATHENA_ATTESTATION_SCHEMA_VERSION" in (
        RBAC_INVENTORY_ATTESTATION_VALIDATION
    )
    assert "ATHENA_RUNTIME_SUPPORT_PRINCIPAL_ID" in (
        RBAC_INVENTORY_ATTESTATION_VALIDATION
    )
    assert "ATHENA_INVENTORY_JSON" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "@maxLength(62000)" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "length(callerEnvironmentPayload) <= 64000" in (RBAC_INVENTORY_ATTESTATION_VALIDATION)
    assert "validatedEffectiveRbacInventoryJson" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "output validated bool" in RBAC_INVENTORY_ATTESTATION_VALIDATION
    assert "output validationDigest string" in RBAC_INVENTORY_ATTESTATION_VALIDATION

    assert 'digest_payload.pop("inventoryDigest", None)' in RBAC_INVENTORY_ATTESTATION_VERIFIER
    assert "_jwk_decode_integer(" in RBAC_INVENTORY_ATTESTATION_VERIFIER
    assert "jwk_modulus != modulus or jwk_exponent != exponent" in (
        RBAC_INVENTORY_ATTESTATION_VERIFIER
    )
    assert 'reviewer_jwk.get("n") != public_key_modulus' not in (
        RBAC_INVENTORY_ATTESTATION_VERIFIER
    )
    assert "modulus.bit_length() < 2048 or exponent != 65537" in (
        RBAC_INVENTORY_ATTESTATION_VERIFIER
    )
    assert 'signature_integer = int.from_bytes(signature, "big")' in (
        RBAC_INVENTORY_ATTESTATION_VERIFIER
    )
    assert "signature_integer >= modulus" in RBAC_INVENTORY_ATTESTATION_VERIFIER
    assert "pow(signature_integer, exponent, modulus)" in (RBAC_INVENTORY_ATTESTATION_VERIFIER)
    assert "_SHA256_DIGEST_INFO_PREFIX" in RBAC_INVENTORY_ATTESTATION_VERIFIER
    assert "hmac.compare_digest(encoded_message, expected)" in (RBAC_INVENTORY_ATTESTATION_VERIFIER)
    assert "AZ_SCRIPTS_OUTPUT_PATH" in RBAC_INVENTORY_ATTESTATION_VERIFIER
    assert "az login" not in RBAC_INVENTORY_ATTESTATION_VERIFIER
    assert "athenarbacevidencekv.vault.azure.net" in PARAMETERS
    assert "rbacInventoryVerifierIdentityResourceId" in PARAMETERS
    assert "rbacInventoryReviewerKeyArmResourceId" in PARAMETERS
    assert "legacyCollectorRbacCleanupDigest" in PARAMETERS
    assert (
        "sha256:0000000000000000000000000000000000000000000000000000000000000000" not in PARAMETERS
    )
    assert "https://athenademomonkv.vault.azure.net/keys/monitoring-rbac-inventory-review" not in (
        PARAMETERS
    )


def _run_az_bicep(args: list[str], output_file: Path) -> None:
    az_cli = shutil.which("az")
    if az_cli is None:
        pytest.fail("az CLI is required to verify checked-in WC-024 Bicep artifacts")
    result = subprocess.run(
        [az_cli, "bicep", *args, "--outfile", str(output_file)],
        cwd=WC024_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            "az bicep artifact validation failed: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def _without_bicep_generator_metadata(value: object) -> object:
    if isinstance(value, list):
        return [_without_bicep_generator_metadata(item) for item in value]
    if not isinstance(value, dict):
        return value

    cleaned: dict[str, object] = {}
    for key, item in value.items():
        if key == "metadata" and isinstance(item, dict):
            cleaned[key] = {
                metadata_key: _without_bicep_generator_metadata(metadata_value)
                for metadata_key, metadata_value in item.items()
                if metadata_key != "_generator"
            }
        else:
            cleaned[key] = _without_bicep_generator_metadata(item)
    return cleaned


def _template_without_bicep_generator(path: Path) -> object:
    return _without_bicep_generator_metadata(json.loads(path.read_text(encoding="utf-8")))


def _arm_expressions(value: object, path: str = "") -> list[tuple[str, int]]:
    if isinstance(value, str):
        if value.startswith("[") and value.endswith("]"):
            return [(path, len(value))]
        return []
    if isinstance(value, list):
        return [
            expression
            for index, item in enumerate(value)
            for expression in _arm_expressions(item, f"{path}/{index}")
        ]
    if isinstance(value, dict):
        return [
            expression
            for key, item in value.items()
            for expression in _arm_expressions(item, f"{path}/{key}")
        ]
    return []


def test_wc024_compiled_templates_stay_below_arm_expression_limit(tmp_path: Path) -> None:
    compiled_templates = []
    for source_name in ("main.bicep", "publish-monitoring-contract.bicep"):
        compiled = tmp_path / source_name.replace(".bicep", ".json")
        _run_az_bicep(["build", "--file", str(WC024_ROOT / source_name)], compiled)
        compiled_templates.append((source_name, json.loads(compiled.read_text(encoding="utf-8"))))

    oversized = [
        (source_name, path, length)
        for source_name, template in compiled_templates
        for path, length in _arm_expressions(template)
        if length > 24_576
    ]
    assert not oversized, f"compiled ARM expressions exceed 24,576 characters: {oversized}"


def test_wc024_inventory_example_fits_deployment_script_transport_budget() -> None:
    inventory = json.loads(
        (WC024_ROOT / "effective-rbac-inventory.example.json").read_text(encoding="utf-8")
    )
    compact_inventory = json.dumps(inventory, separators=(",", ":"), ensure_ascii=True)

    assert len(compact_inventory.encode("utf-8")) <= 62_000
    assert "length(effectiveRbacInventoryJson) <= 62000" in PUBLISH_CONTRACT
    assert "length(callerEnvironmentPayload) <= 64000" in (RBAC_INVENTORY_ATTESTATION_VALIDATION)


def test_wc024_generator_metadata_normalization_is_recursive_and_only_metadata() -> None:
    payload = {
        "metadata": {"_generator": {"version": "0.46.1"}, "owner": "athena"},
        "resources": [
            {
                "properties": {
                    "template": {
                        "metadata": {"_generator": {"version": "0.47.16"}},
                        "semantic": "retained",
                    }
                }
            }
        ],
        "_generator": "not metadata and therefore semantic",
    }

    assert _without_bicep_generator_metadata(payload) == {
        "metadata": {"owner": "athena"},
        "resources": [{"properties": {"template": {"metadata": {}, "semantic": "retained"}}}],
        "_generator": "not metadata and therefore semantic",
    }


def test_wc024_checked_in_generated_artifacts_match_current_bicep(tmp_path: Path) -> None:
    generated_template = tmp_path / "main.json"
    generated_parameters = tmp_path / "main.example.json"

    _run_az_bicep(["build", "--file", str(WC024_ROOT / "main.bicep")], generated_template)
    _run_az_bicep(
        ["build-params", "--file", str(WC024_ROOT / "main.example.bicepparam")],
        generated_parameters,
    )
    _run_az_bicep(
        [
            "build",
            "--file",
            str(WC024_ROOT / "publish-monitoring-contract.bicep"),
        ],
        tmp_path / "publish-monitoring-contract.json",
    )

    assert _template_without_bicep_generator(WC024_ROOT / "main.json") == (
        _template_without_bicep_generator(generated_template)
    )
    assert json.loads((WC024_ROOT / "main.example.json").read_text(encoding="utf-8")) == (
        json.loads(generated_parameters.read_text(encoding="utf-8"))
    )


def test_wc024_connectivity_templates_build(tmp_path: Path) -> None:
    _run_az_bicep(
        ["build", "--file", str(WC024_CONNECTIVITY_ROOT / "main.bicep")],
        tmp_path / "connectivity.json",
    )
    _run_az_bicep(
        [
            "build-params",
            "--file",
            str(WC024_CONNECTIVITY_ROOT / "main.example.bicepparam"),
        ],
        tmp_path / "connectivity.example.json",
    )
    _run_az_bicep(
        ["build", "--file", str(WC024_ROOT / "bootstrap-ampls.bicep")],
        tmp_path / "bootstrap-ampls.json",
    )
