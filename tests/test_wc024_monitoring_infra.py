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
STORAGE = (WC024_ROOT / "modules" / "monitoring-flow-log-storage.bicep").read_text(
    encoding="utf-8"
)
EVIDENCE_SEAMS = (WC024_ROOT / "modules" / "monitoring-evidence-seams.bicep").read_text(
    encoding="utf-8"
)
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
DCR_ASSOCIATIONS = (WC024_ROOT / "modules" / "dcr-associations.bicep").read_text(
    encoding="utf-8"
)
DCR_ASSOCIATION_VALIDATION = (
    WC024_ROOT / "modules" / "dcr-association-validation.bicep"
).read_text(encoding="utf-8")
PRIVATE_RUNTIME_TOPOLOGY_VALIDATION = (
    WC024_ROOT / "modules" / "private-runtime-topology-validation.bicep"
).read_text(encoding="utf-8")
FLOW_LOG = (WC024_ROOT / "modules" / "vnet-flow-log.bicep").read_text(encoding="utf-8")
FLOW_LOG_VALIDATION = (
    WC024_ROOT / "modules" / "canonical-flow-log-validation.bicep"
).read_text(encoding="utf-8")
PRIVATE_ACCESS_SCRIPT = (WC024_ROOT / "set-private-access.ps1").read_text(
    encoding="utf-8"
)
PRIVATE_DNS_VNET_LINKS = (
    WC024_ROOT / "modules" / "private-dns-vnet-links.bicep"
).read_text(encoding="utf-8")
PRIVATE_DNS_ZONES = (WC024_ROOT / "modules" / "private-dns-zones.bicep").read_text(
    encoding="utf-8"
)
COLLECTOR_KEY_VAULT_DNS = (
    WC024_ROOT / "modules" / "collector-key-vault-private-dns.bicep"
).read_text(encoding="utf-8")
LEGACY_FLOW_LOG_MIGRATION = (
    WC024_ROOT / "modules" / "legacy-flow-log-migration.bicep"
).read_text(encoding="utf-8")
CONNECTION_MONITOR = (
    WC024_ROOT / "modules" / "connection-monitor-capability.bicep"
).read_text(encoding="utf-8")
COLLECTOR_CONTRACT = (
    WC024_ROOT / "modules" / "monitoring-collector-contract.bicep"
).read_text(encoding="utf-8")
ADR = (ROOT / "docs" / "adr" / "0020-wc024-generic-monitoring-foundation.md").read_text(
    encoding="utf-8"
)
CONNECTIVITY_MAIN = (WC024_CONNECTIVITY_ROOT / "main.bicep").read_text(
    encoding="utf-8"
)
CONNECTIVITY_HUB = (
    WC024_CONNECTIVITY_ROOT
    / "modules"
    / "monitoring-collector-network.bicep"
).read_text(encoding="utf-8")


def test_wc024_adr_uses_unique_sequential_number_after_wc021_wc022_merges() -> None:
    assert (ROOT / "docs" / "adr" / "0020-wc024-generic-monitoring-foundation.md").is_file()
    assert not (ROOT / "docs" / "adr" / "0018-wc024-generic-monitoring-foundation.md").exists()
    assert ADR.startswith(
        "# ADR 0020: Isolate generic monitoring evidence from context and "
        "presentation runtimes"
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
        "param dataCollectionEndpointAssociationName string = "
        "'configurationAccessEndpoint'" in MAIN
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
    assert "@minLength(11)\n@maxLength(11)\nparam approvedVmNames array" in (
        DCR_ASSOCIATIONS
    )
    dcr_declaration = DATA_PLATFORM.split(
        "resource dataCollectionRule ", maxsplit=1
    )[1].split("\n}", maxsplit=1)[0]
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
        "'Microsoft.Insights/dataCollectionRuleAssociations@2024-03-11'"
        in DCR_ASSOCIATIONS
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
        "dcrAssociations.outputs.dataCollectionEndpointAssociationResourceIds"
        in MAIN
    )
    assert "map(approvedVmNames, vmName => toLower(string(vmName)))" in DCR_ASSOCIATIONS
    assert "var uniqueApprovedVmNames = union(normalizedApprovedVmNames, [])" in (
        DCR_ASSOCIATIONS
    )
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
    dcr_associations_declaration = MAIN.split(
        "module dcrAssociations", maxsplit=1
    )[1].split("module workloadPrivateDnsZones", maxsplit=1)[0]
    assert "dependsOn: [" in dcr_associations_declaration
    assert "dcrAssociationValidation" in dcr_associations_declaration
    assert (
        "validatedDataCollectionRuleAssociationResourceIds: "
        "dcrAssociationValidation.outputs."
        "validatedAdoptedDataCollectionRuleAssociationResourceIds"
        in dcr_associations_declaration
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
    assert PRIVATE_DNS_VNET_LINKS.count(
        "Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01"
    ) == 5
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
    assert "deleteRetentionPolicy" in STORAGE
    assert "immutabilityPeriodSinceCreationInDays: retentionDays" in STORAGE
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
    evidence_seams_declaration = MAIN.split("module monitoringEvidenceSeams", maxsplit=1)[
        1
    ].split("module monitoringPrivateEndpoints", maxsplit=1)[0]
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
        "param flowLogName string = "
        "'athena-hackathon-vnet-rg-athena-demo-workload-flowlog'" in MAIN
    )
    assert "name: flowLogName" in FLOW_LOG
    assert "athenahackathonflowwhtco" in MAIN
    assert "retainedLegacyFlowLogStorageAccountName" in MAIN
    assert (
        "@allowed([\n  'athena-hackathon-vnet-rg-athena-demo-workload-flowlog'\n])"
        in MAIN
    )
    assert "resource existingFlowLog" in FLOW_LOG_VALIDATION
    assert "existingFlowLog.properties.targetResourceId" in FLOW_LOG_VALIDATION
    assert "refuses to update the canonical flow log" in FLOW_LOG_VALIDATION
    assert "canonicalFlowLogValidation.outputs.validatedFlowLogName" in MAIN


def test_wc024_disables_redundant_legacy_flow_logs_only_after_canonical_cutover() -> None:
    assert "legacyFlowLogNames" in MAIN
    assert "legacyFlowLogTargetResourceIds" in MAIN
    assert "reviewedLegacyFlowLogMigrationAllowlist" not in MAIN
    assert "var reviewedLegacyFlowLogMigrationAllowlist = []" in LEGACY_FLOW_LOG_MIGRATION
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
    assert "existing target matches the reviewed allowlist" in LEGACY_FLOW_LOG_MIGRATION
    assert "toLower(canonicalVnetFlowLogName)" in (
        LEGACY_FLOW_LOG_MIGRATION
    )
    assert "canonicalVnetFlowLogCutoverConfirmed" in LEGACY_FLOW_LOG_MIGRATION
    assert "enabled: false" in LEGACY_FLOW_LOG_MIGRATION
    assert "storageId: replacementStorageAccountResourceId" in LEGACY_FLOW_LOG_MIGRATION
    assert "delete" not in LEGACY_FLOW_LOG_MIGRATION.lower()


def test_wc024_disables_adopted_public_access_only_after_private_readiness() -> None:
    assert "privateLinkScopeDeploymentPhase" not in MAIN
    assert "privateLinkScopeDeploymentPhase" not in DATA_PLATFORM
    assert (
        "resource workloadPrivateLinkScope "
        "'Microsoft.Insights/privateLinkScopes@2021-09-01' existing"
        in DATA_PLATFORM
    )
    assert (
        "resource collectorPrivateLinkScope "
        "'Microsoft.Insights/privateLinkScopes@2021-09-01' existing"
        in DATA_PLATFORM
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
    assert "privateEndpointConnections?api-version=2021-09-01" in (
        PRIVATE_ACCESS_SCRIPT
    )
    assert "does not contain the exact reviewed LAW and DCE" in PRIVATE_ACCESS_SCRIPT
    assert "does not contain the exact approved private endpoint" in (
        PRIVATE_ACCESS_SCRIPT
    )
    assert (
        "[ValidateSet('a6add389-9978-47ac-ab1e-a09212e321d4')]"
        in PRIVATE_ACCESS_SCRIPT
    )
    assert "athena-demo-monitoring-workload-ampls" in PRIVATE_ACCESS_SCRIPT
    assert "athena-demo-monitoring-collector-ampls" in PRIVATE_ACCESS_SCRIPT
    assert "Private access verification failed" in PRIVATE_ACCESS_SCRIPT


def test_wc024_serializes_ampls_links_to_shared_law_and_dce() -> None:
    assert (
        "resource workloadDcePrivateLinkScope "
        "'Microsoft.Insights/privateLinkScopes/scopedResources@2021-09-01' = {"
        in DATA_PLATFORM
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


def test_wc024_populates_private_dns_before_workload_vnet_links() -> None:
    assert (
        MAIN.index("module dcrAssociationValidation")
        < MAIN.index("module dcrAssociations")
        < MAIN.index("module workloadPrivateDnsZones")
        < MAIN.index("module monitoringPrivateEndpoints")
        < MAIN.index("module workloadPrivateDnsVnetLinks")
        < MAIN.index("module collectorKeyVaultPrivateDnsLink")
    )
    private_endpoints_declaration = MAIN.split(
        "module monitoringPrivateEndpoints", maxsplit=1
    )[1].split("module workloadPrivateDnsVnetLinks", maxsplit=1)[0]
    private_dns_zones_declaration = MAIN.split(
        "module workloadPrivateDnsZones", maxsplit=1
    )[1].split("module monitoringStorage", maxsplit=1)[0]
    vnet_links_declaration = MAIN.split(
        "module workloadPrivateDnsVnetLinks", maxsplit=1
    )[1].split("module monitoringEvidenceReaderAssignments", maxsplit=1)[0]
    assert "dependsOn: [\n    dcrAssociations\n  ]" in private_endpoints_declaration
    assert "dependsOn: [\n    dcrAssociations\n  ]" in private_dns_zones_declaration
    assert "dependsOn: [\n    monitoringPrivateEndpoints\n  ]" in (
        vnet_links_declaration
    )
    key_vault_link_declaration = MAIN.split(
        "module collectorKeyVaultPrivateDnsLink",
        maxsplit=1,
    )[1].split("module monitoringEvidenceReaderAssignments", maxsplit=1)[0]
    assert "dependsOn: [\n    monitoringPrivateEndpoints\n  ]" in (
        key_vault_link_declaration
    )


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
    assert "collectorRuntimeSubnetBelongsToCollectorVnet" in (
        PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    )
    assert "collectorPrivateEndpointSubnetBelongsToCollectorVnet" in (
        PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    )
    assert "collectorSubnetsAreDistinct" in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    assert "networksRemainIsolated" in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    assert "module privateRuntimeTopologyValidation" in MAIN
    assert (
        "workloadPrivateEndpointSubnetResourceId: "
        "privateRuntimeTopologyValidation.outputs.workloadPrivateEndpointSubnetResourceId"
        in MAIN
    )
    assert "collectorRuntimeVirtualNetworkResourceId:" in MAIN
    assert (
        "privateRuntimeTopologyValidation.outputs.collectorRuntimeVirtualNetworkResourceId"
        in MAIN
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
    assert "conditionVersion: '2.0'" in READER_RBAC
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
    assert "Microsoft.OperationalInsights/workspaces/tables/data/read" in (
        COLLECTOR_CONTRACT
    )
    assert "Microsoft.Compute/virtualMachines/instanceView/read" in (
        COLLECTOR_CONTRACT
    )
    assert "Microsoft.Network/networkWatchers/connectionMonitors/read" not in (
        COLLECTOR_CONTRACT
    )
    assert "AzureNetworkAnalytics_CL" not in COLLECTOR_CONTRACT
    assert "scope: workspace" in READER_RBAC
    assert "scope: dataCollectionEndpoint" in READER_RBAC
    assert "scope: dataCollectionRule" in READER_RBAC
    assert "scope: privateLinkScopes[index]" in READER_RBAC
    assert "2fda1d90-37da-55d9-8ac3-132fb7bdca5d" in WORKLOAD_READER_RBAC
    assert "scope: collectorVmSignalReaders" not in WORKLOAD_READER_RBAC
    assert "scope: approvedVms[index]" in WORKLOAD_READER_RBAC
    assert "scope: adoptedDcrAssociations[index]" in WORKLOAD_READER_RBAC
    assert "scope: dceAssociations[index]" in WORKLOAD_READER_RBAC
    vm_signal_assignment = WORKLOAD_READER_RBAC.split(
        "resource collectorVmSignalReaders",
        maxsplit=1,
    )[1].split("resource collectorDcrAssociationReaders", maxsplit=1)[0]
    assert "roleDefinitionId: validatedSignalReaderRoleDefinitionId" in (
        vm_signal_assignment
    )
    assert "roleDefinitionId: readerRoleDefinitionId" not in vm_signal_assignment
    assert "expectedSignalReaderActions" in WORKLOAD_READER_RBAC
    assert "unexpectedSignalReaderActions" in WORKLOAD_READER_RBAC
    assert "signalReaderAssignableScopes" in WORKLOAD_READER_RBAC
    assert "length(signalReaderRoleDefinition.properties.permissions) == 1" in (
        WORKLOAD_READER_RBAC
    )
    assert "scope: flowLog" in NETWORK_WATCHER_READER_RBAC
    assert "scope: networkWatcher" not in NETWORK_WATCHER_READER_RBAC
    combined_rbac = READER_RBAC + WORKLOAD_READER_RBAC + NETWORK_WATCHER_READER_RBAC
    assert "Owner" not in combined_rbac
    assert "Contributor" not in combined_rbac
    assert "collectorPrincipalId" in combined_rbac
    for forbidden_identity in ("context", "presentation", "correlation", "mcp"):
        assert forbidden_identity not in combined_rbac.lower()
    assert "collectorIdentity.properties.principalId" in EVIDENCE_SEAMS
    assert "scope: monitoringEvidenceContainer" in EVIDENCE_SEAMS
    assert "scope: signingKey" in EVIDENCE_SEAMS
    assert "listKeys" not in EVIDENCE_SEAMS


def test_wc024_uses_exact_resource_scopes_without_creating_a_custom_role() -> None:
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
    assert "targetScope = 'resourceGroup'" in READER_RBAC
    assert "targetScope = 'resourceGroup'" in WORKLOAD_READER_RBAC
    assert "targetScope = 'resourceGroup'" in NETWORK_WATCHER_READER_RBAC
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
    assert "workspaceAccessControlMode: workspaceAccessControlMode" in (
        COLLECTOR_CONTRACT
    )
    assert "readerRoleDefinitionId: readerRoleDefinitionId" in COLLECTOR_CONTRACT
    assert "signalReaderRoleDefinitionId: signalReaderRoleDefinitionId" in (
        COLLECTOR_CONTRACT
    )
    assert (
        "logAnalyticsDataReaderRoleDefinitionId: "
        "logAnalyticsDataReaderRoleDefinitionId"
    ) in COLLECTOR_CONTRACT
    assert "logAnalyticsAllowedTables: logAnalyticsAllowedTables" in COLLECTOR_CONTRACT
    assert "logAnalyticsAccessCondition: logAnalyticsAccessCondition" in (
        COLLECTOR_CONTRACT
    )
    assert "resourceReadScopeIds: resourceReadScopeIds" in COLLECTOR_CONTRACT
    assert "signalReadScopeIds: signalReadScopeIds" in COLLECTOR_CONTRACT
    assert "workspaceResourceContextAccessEnabled" in DATA_PLATFORM
    assert "'workspaceAndResourceContext'" in MAIN
    assert "'workspaceOnly'" in MAIN
    assert "Microsoft.Network/networkWatchers/connectionMonitors/read" not in (
        COLLECTOR_CONTRACT
    )
    assert "workloadVirtualNetworkResourceId: workloadVirtualNetworkResourceId" in (
        COLLECTOR_CONTRACT
    )
    assert "approvedVmNames: approvedVmNames" in COLLECTOR_CONTRACT
    assert "signingKeyResourceId: signingKeyResourceId" in COLLECTOR_CONTRACT
    assert (
        "evidenceStorageAccountResourceId: evidenceStorageAccountResourceId"
        in COLLECTOR_CONTRACT
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
    all_bicep = "\n".join(
        path.read_text(encoding="utf-8") for path in WC024_ROOT.rglob("*.bicep")
    )

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
        assert (
            signal in COLLECTOR_CONTRACT
            or signal in DATA_PLATFORM
            or signal in READER_RBAC
        )
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


def _template_without_bicep_generator(path: Path) -> object:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        metadata = payload.get("metadata")
        if isinstance(metadata, dict):
            metadata.pop("_generator", None)
    return payload


def test_wc024_checked_in_generated_artifacts_match_current_bicep(tmp_path: Path) -> None:
    generated_template = tmp_path / "main.json"
    generated_parameters = tmp_path / "main.example.json"

    _run_az_bicep(["build", "--file", str(WC024_ROOT / "main.bicep")], generated_template)
    _run_az_bicep(
        ["build-params", "--file", str(WC024_ROOT / "main.example.bicepparam")],
        generated_parameters,
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
