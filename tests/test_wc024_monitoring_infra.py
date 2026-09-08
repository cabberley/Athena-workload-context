from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WC024_ROOT = ROOT / "infra" / "wc024-monitoring-foundation"
MAIN = (WC024_ROOT / "main.bicep").read_text(encoding="utf-8")
PARAMETERS = (WC024_ROOT / "main.example.bicepparam").read_text(encoding="utf-8")
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
READER_ROLE = (WC024_ROOT / "modules" / "monitoring-evidence-reader-role.bicep").read_text(
    encoding="utf-8"
)
READER_RBAC = (WC024_ROOT / "modules" / "monitoring-evidence-reader-rbac.bicep").read_text(
    encoding="utf-8"
)
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
PRIVATE_ACCESS = (
    WC024_ROOT / "modules" / "monitoring-private-access.bicep"
).read_text(encoding="utf-8")
PRIVATE_DNS_VNET_LINKS = (
    WC024_ROOT / "modules" / "private-dns-vnet-links.bicep"
).read_text(encoding="utf-8")
PRIVATE_DNS_ZONES = (WC024_ROOT / "modules" / "private-dns-zones.bicep").read_text(
    encoding="utf-8"
)
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
    )[1].split("module privateDnsZones", maxsplit=1)[0]
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
    assert PRIVATE_ENDPOINTS.count("Microsoft.Network/privateEndpoints@2024-10-01") == 3
    assert "azuremonitor" in PRIVATE_ENDPOINTS
    assert "privateDnsZoneConfigs" in PRIVATE_ENDPOINTS
    assert "name: 'azure-monitor-blob'" in PRIVATE_ENDPOINTS
    assert "privateDnsZoneId: storageBlobPrivateDnsZoneResourceId" in PRIVATE_ENDPOINTS
    assert "@minLength(4)" in PRIVATE_ENDPOINTS
    assert PRIVATE_DNS_ZONES.count("Microsoft.Network/privateDnsZones@2024-06-01") == 6
    assert PRIVATE_DNS_VNET_LINKS.count(
        "Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01"
    ) == 12
    for zone in (
        "privatelink.monitor.azure.com",
        "privatelink.oms.opinsights.azure.com",
        "privatelink.ods.opinsights.azure.com",
        "privatelink.agentsvc.azure-automation.net",
        "privatelink.blob.core.windows.net",
        "privatelink.vaultcore.azure.net",
    ):
        assert zone in PRIVATE_DNS_ZONES
        assert zone in PRIVATE_DNS_VNET_LINKS
    assert "id: workloadVirtualNetworkResourceId" in PRIVATE_DNS_VNET_LINKS
    assert "id: collectorRuntimeVirtualNetworkResourceId" in PRIVATE_DNS_VNET_LINKS
    assert "collectorRuntimeRequiresSeparateLinks" in PRIVATE_DNS_VNET_LINKS
    assert "registrationEnabled: false" in PRIVATE_DNS_VNET_LINKS
    assert "existing = {" in PRIVATE_DNS_VNET_LINKS
    assert "virtualNetworkLinks" not in PRIVATE_DNS_ZONES
    assert "privateDnsZones.outputs.storageBlobPrivateDnsZoneResourceId" in MAIN
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


def test_wc024_disables_redundant_legacy_flow_logs_only_after_canonical_cutover() -> None:
    assert "legacyFlowLogNames" in MAIN
    assert "legacyFlowLogTargetResourceIds" in MAIN
    assert "canonicalVnetFlowLogCutoverConfirmed" in MAIN
    assert "dependsOn: [\n    vnetFlowLog\n  ]" in MAIN
    assert "@maxLength(32)" in LEGACY_FLOW_LOG_MIGRATION
    assert "length(legacyFlowLogNames) == length(legacyFlowLogTargetResourceIds)" in (
        LEGACY_FLOW_LOG_MIGRATION
    )
    assert "toLower(canonicalVnetFlowLogName)" in (
        LEGACY_FLOW_LOG_MIGRATION
    )
    assert "canonicalVnetFlowLogCutoverConfirmed" in LEGACY_FLOW_LOG_MIGRATION
    assert "enabled: false" in LEGACY_FLOW_LOG_MIGRATION
    assert "storageId: replacementStorageAccountResourceId" in LEGACY_FLOW_LOG_MIGRATION
    assert "delete" not in LEGACY_FLOW_LOG_MIGRATION.lower()


def test_wc024_disables_adopted_public_access_only_after_private_readiness() -> None:
    assert "param createPrivateLinkScope bool = false" in MAIN
    assert "validatedCreatePrivateLinkScope" in MAIN
    assert "createPrivateLinkScope: validatedCreatePrivateLinkScope" in MAIN
    assert (
        "cannot create an Open Azure Monitor Private Link Scope during the "
        "private-only cutover"
    ) in MAIN
    assert "param createPrivateLinkScope bool = false" in DATA_PLATFORM
    assert (
        "resource createdPrivateLinkScope "
        "'Microsoft.Insights/privateLinkScopes@2021-09-01' = "
        "if (createPrivateLinkScope)" in DATA_PLATFORM
    )
    assert (
        "resource adoptedPrivateLinkScope "
        "'Microsoft.Insights/privateLinkScopes@2021-09-01' existing = "
        "if (!createPrivateLinkScope)" in DATA_PLATFORM
    )
    created_private_link_scope = DATA_PLATFORM.split(
        "resource createdPrivateLinkScope", maxsplit=1
    )[1].split("resource adoptedPrivateLinkScope", maxsplit=1)[0]
    assert "queryAccessMode: 'Open'" in created_private_link_scope
    assert "ingestionAccessMode: 'Open'" in created_private_link_scope
    assert (
        "output privateLinkScopeResourceId string = createPrivateLinkScope"
        in DATA_PLATFORM
    )
    assert "adoptedPrivateLinkScope!.id" in DATA_PLATFORM
    assert "adoptedPrivateLinkScope!.tags" in DATA_PLATFORM
    assert "publicNetworkAccessForIngestion: 'Disabled'" in PRIVATE_ACCESS
    assert "publicNetworkAccessForQuery: 'Disabled'" in PRIVATE_ACCESS
    assert "publicNetworkAccess: 'Disabled'" in PRIVATE_ACCESS
    assert "resource privateLinkScope" in PRIVATE_ACCESS
    assert "queryAccessMode: 'PrivateOnly'" in PRIVATE_ACCESS
    assert "ingestionAccessMode: 'PrivateOnly'" in PRIVATE_ACCESS
    assert "privateLinkScopeName: '${namePrefix}-ampls'" in MAIN
    assert "monitoringPrivateEndpoints" in MAIN
    assert "privateDnsZones" in MAIN
    assert "privateDnsVnetLinks" in MAIN
    assert "dcrAssociations" in MAIN
    assert "disable-adopted-monitoring-public-access" in MAIN
    assert "privateMonitoringIngestionCutoverConfirmed bool = false" in MAIN
    assert (
        "module monitoringPrivateAccess 'modules/monitoring-private-access.bicep' = "
        "if (privateMonitoringIngestionCutoverConfirmed)" in MAIN
    )
    for preserved_value in (
        "workspaceLocation",
        "workspaceTags",
        "dataCollectionEndpointLocation",
        "dataCollectionEndpointTags",
        "privateLinkScopeTags",
        "privateLinkScopeAccessModeExclusions",
        "workspaceSkuName",
        "workspaceRetentionDays",
        "workspaceDailyQuotaGb",
        "workspaceFeatures",
    ):
        assert f"param {preserved_value} " in PRIVATE_ACCESS
        assert f"{preserved_value}: monitoringDataPlatform.outputs.{preserved_value}" in MAIN
    for nullable_preserved_value in (
        "dataCollectionEndpointDescription",
        "dataCollectionEndpointKind",
    ):
        assert f"param {nullable_preserved_value} string?" in PRIVATE_ACCESS
        assert (
            f"{nullable_preserved_value}: "
            f"monitoringDataPlatform.outputs.?{nullable_preserved_value}"
            in MAIN
        )
    assert "location: location" not in PRIVATE_ACCESS
    assert "location: workspaceLocation" in PRIVATE_ACCESS
    assert "location: dataCollectionEndpointLocation" in PRIVATE_ACCESS
    assert "tags: workspaceTags" in PRIVATE_ACCESS
    assert "tags: dataCollectionEndpointTags" in PRIVATE_ACCESS
    assert "tags: privateLinkScopeTags" in PRIVATE_ACCESS
    assert "param dataCollectionEndpointDescription string?" in PRIVATE_ACCESS
    assert "param dataCollectionEndpointKind string?" in PRIVATE_ACCESS
    assert "dataCollectionEndpointDescription == null ? {}" in PRIVATE_ACCESS
    assert (
        "resource dataCollectionEndpointWithKind "
        "'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' = "
        "if (dataCollectionEndpointKind != null)" in PRIVATE_ACCESS
    )
    assert "kind: dataCollectionEndpointKind!" in PRIVATE_ACCESS
    assert (
        "resource dataCollectionEndpointWithoutKind "
        "'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' = "
        "if (dataCollectionEndpointKind == null)" in PRIVATE_ACCESS
    )
    without_kind_declaration = PRIVATE_ACCESS.split(
        "resource dataCollectionEndpointWithoutKind", maxsplit=1
    )[1].split("resource privateLinkScope", maxsplit=1)[0]
    assert "kind:" not in without_kind_declaration
    assert "var dataCollectionEndpointProperties = union(" in PRIVATE_ACCESS
    assert "dailyQuotaGb: workspaceDailyQuotaGb" in PRIVATE_ACCESS
    assert "features: workspaceFeatures" in PRIVATE_ACCESS
    assert "exclusions: privateLinkScopeAccessModeExclusions" in PRIVATE_ACCESS
    assert "resourceTags" not in PRIVATE_ACCESS
    assert "enableLogAccessUsingOnlyResourcePermissions: true" not in PRIVATE_ACCESS
    assert "disableLocalAuth: false" not in PRIVATE_ACCESS
    assert "param workspaceSkuName" not in MAIN
    for preserved_output in (
        "workspaceLocation",
        "workspaceTags",
        "workspaceSkuName",
        "workspaceRetentionDays",
        "workspaceDailyQuotaGb",
        "workspaceFeatures",
        "dataCollectionEndpointLocation",
        "dataCollectionEndpointTags",
        "dataCollectionEndpointDescription",
        "dataCollectionEndpointKind",
        "privateLinkScopeTags",
        "privateLinkScopeAccessModeExclusions",
    ):
        assert f"output {preserved_output} " in DATA_PLATFORM
    assert "output dataCollectionEndpointDescription string?" in DATA_PLATFORM
    assert "output dataCollectionEndpointKind string?" in DATA_PLATFORM
    assert (
        "output dataCollectionEndpointDescription string? = "
        "dataCollectionEndpoint.properties.?description" in DATA_PLATFORM
    )
    assert (
        "output dataCollectionEndpointKind string? = "
        "dataCollectionEndpoint.?kind" in DATA_PLATFORM
    )


def test_wc024_uses_adopted_monitoring_locations_not_deployment_location() -> None:
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
    private_access_declaration = MAIN.split(
        "module monitoringPrivateAccess", maxsplit=1
    )[1].split("module vnetFlowLog", maxsplit=1)[0]
    flow_log_declaration = MAIN.split("module vnetFlowLog", maxsplit=1)[1].split(
        "module legacyFlowLogMigration", maxsplit=1
    )[0]

    assert "location: location" not in private_access_declaration
    assert (
        "workspaceLocation: monitoringDataPlatform.outputs.workspaceLocation"
        in private_access_declaration
    )
    assert (
        "dataCollectionEndpointLocation: "
        "monitoringDataPlatform.outputs.dataCollectionEndpointLocation"
        in private_access_declaration
    )
    assert "workspaceLocation: location" not in flow_log_declaration
    assert (
        "workspaceLocation: monitoringDataPlatform.outputs.workspaceLocation"
        in flow_log_declaration
    )


def test_wc024_populates_private_dns_before_workload_vnet_links() -> None:
    assert (
        MAIN.index("module dcrAssociationValidation")
        < MAIN.index("module dcrAssociations")
        < MAIN.index("module privateDnsZones")
        < MAIN.index("module monitoringPrivateEndpoints")
        < MAIN.index("module privateDnsVnetLinks")
        < MAIN.index("module monitoringPrivateAccess")
    )
    private_endpoints_declaration = MAIN.split(
        "module monitoringPrivateEndpoints", maxsplit=1
    )[1].split("module privateDnsVnetLinks", maxsplit=1)[0]
    private_dns_zones_declaration = MAIN.split(
        "module privateDnsZones", maxsplit=1
    )[1].split("module monitoringStorage", maxsplit=1)[0]
    vnet_links_declaration = MAIN.split(
        "module privateDnsVnetLinks", maxsplit=1
    )[1].split("module monitoringEvidenceReaderRole", maxsplit=1)[0]
    private_access_declaration = MAIN.split(
        "module monitoringPrivateAccess", maxsplit=1
    )[1].split("module vnetFlowLog", maxsplit=1)[0]

    assert "dependsOn: [\n    dcrAssociations\n  ]" in private_endpoints_declaration
    assert "dependsOn: [\n    dcrAssociations\n  ]" in private_dns_zones_declaration
    assert "dependsOn: [\n    monitoringPrivateEndpoints\n  ]" in (
        vnet_links_declaration
    )
    assert "privateDnsVnetLinks" in private_access_declaration
    assert "dcrAssociations" in private_access_declaration


def test_wc024_requires_private_collector_runtime_topology_and_dns_links() -> None:
    for parameter in (
        "privateEndpointVirtualNetworkResourceId",
        "collectorRuntimeVirtualNetworkResourceId",
        "collectorRuntimeSubnetResourceId",
        "workloadPrivateEndpointConnectivityConfirmed",
        "collectorRuntimePrivateEndpointConnectivityConfirmed",
        "workloadPrivateDnsResolutionConfirmed",
        "collectorRuntimePrivateDnsResolutionConfirmed",
        "privateMonitoringIngestionCutoverConfirmed",
    ):
        assert f"param {parameter} " in MAIN
        assert f"param {parameter} " in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION

    assert "deploymentSubscriptionPrefix" in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    assert "privateEndpointSubnetBelongsToDeclaredVnet" in (
        PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    )
    assert "collectorRuntimeSubnetBelongsToDeclaredVnet" in (
        PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    )
    assert "workloadCanReachPrivateEndpoints" in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    assert "collectorCanReachPrivateEndpoints" in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    assert "privateCutoverDnsResolutionConfirmed" in PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    assert "!privateMonitoringIngestionCutoverConfirmed ||" in (
        PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    )
    assert "reviewed private DNS resolution for the phase-two private cutover" in (
        PRIVATE_RUNTIME_TOPOLOGY_VALIDATION
    )
    assert "module privateRuntimeTopologyValidation" in MAIN
    assert (
        "privateEndpointSubnetResourceId: "
        "privateRuntimeTopologyValidation.outputs.privateEndpointSubnetResourceId"
        in MAIN
    )
    assert (
        "collectorRuntimeVirtualNetworkResourceId: "
        "privateRuntimeTopologyValidation.outputs."
        "collectorRuntimeVirtualNetworkResourceId"
        in MAIN
    )
    assert "if (collectorRuntimeRequiresSeparateLinks)" in PRIVATE_DNS_VNET_LINKS
    assert "collectorRuntimeVirtualNetworkResourceId" in PRIVATE_DNS_VNET_LINKS
    assert "privateDnsVnetLinks" in MAIN
    assert (
        "privateMonitoringIngestionCutoverConfirmed: "
        "privateMonitoringIngestionCutoverConfirmed" in MAIN
    )


def test_wc024_rbac_is_collector_only_and_narrow() -> None:
    assert "Athena WC024 Isolated Monitoring Evidence Reader" in READER_ROLE
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
        assert f"Microsoft.OperationalInsights/workspaces/query/{table}/read" in READER_ROLE
    assert "AzureNetworkAnalytics_CL" not in READER_ROLE
    assert "'Microsoft.OperationalInsights/workspaces/query/read'" not in READER_ROLE
    assert "Microsoft.Insights/Metrics/Read" in READER_ROLE
    assert "Microsoft.Insights/dataCollectionRuleAssociations/read" in READER_ROLE
    assert "Microsoft.Network/networkWatchers/flowLogs/read" in READER_ROLE
    assert "Microsoft.Network/networkWatchers/connectionMonitors/read" in READER_ROLE
    for operation in (
        "Microsoft.OperationalInsights/workspaces/query/"
        "NWConnectionMonitorDestinationListenerResult/read",
        "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorDNSResult/read",
        "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorPathResult/read",
        "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorTestResult/read",
    ):
        assert operation in READER_ROLE
        assert operation in COLLECTOR_CONTRACT
    assert (
        "Microsoft.OperationalInsights/workspaces/query/NTANetAnalytics/read"
        in COLLECTOR_CONTRACT
    )
    assert "AzureNetworkAnalytics_CL" not in COLLECTOR_CONTRACT
    assert "*/read" not in READER_ROLE
    assert "Owner" not in READER_ROLE
    assert "Contributor" not in READER_ROLE
    assert "collectorPrincipalId" in READER_RBAC
    for forbidden_identity in ("context", "presentation", "correlation", "mcp"):
        assert forbidden_identity not in READER_RBAC.lower()
    assert "collectorIdentity.properties.principalId" in EVIDENCE_SEAMS
    assert "scope: monitoringEvidenceContainer" in EVIDENCE_SEAMS
    assert "scope: signingKey" in EVIDENCE_SEAMS
    assert "listKeys" not in EVIDENCE_SEAMS


def test_wc024_uses_deployment_subscription_for_all_custom_role_scopes() -> None:
    assert "workloadSubscriptionId" not in MAIN
    assert "networkWatcherSubscriptionId" not in MAIN
    assert (
        "var workloadResourceGroupId = '${subscription().id}/resourceGroups/"
        "${workloadResourceGroupName}'"
    ) in MAIN
    assert (
        "var networkWatcherResourceGroupId = '${subscription().id}/resourceGroups/"
        "${networkWatcherResourceGroupName}'"
    ) in MAIN
    assert "scope: resourceGroup(workloadResourceGroupName)" in MAIN
    assert "scope: resourceGroup(networkWatcherResourceGroupName)" in MAIN


def test_wc024_collector_contract_is_signed_handoff_ready_and_generic_only() -> None:
    assert "athena.wc024MonitoringCollectorContract.v1" in COLLECTOR_CONTRACT
    assert "athena.wc024MonitoringEvidenceHandoff.v1" in COLLECTOR_CONTRACT
    assert "isolatedSignedCollector" in COLLECTOR_CONTRACT
    assert "capabilityOnly" in COLLECTOR_CONTRACT
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
    assert "privateMonitoringIngestionCutoverConfirmed = false" in PARAMETERS
    assert "createPrivateLinkScope = true" in PARAMETERS
    assert "privateEndpointVirtualNetworkResourceId" in PARAMETERS
    assert "collectorRuntimeVirtualNetworkResourceId" in PARAMETERS
    assert "collectorRuntimeSubnetResourceId" in PARAMETERS
    assert "workloadPrivateEndpointConnectivityConfirmed = true" in PARAMETERS
    assert "collectorRuntimePrivateEndpointConnectivityConfirmed = true" in PARAMETERS
    assert "workloadPrivateDnsResolutionConfirmed = false" in PARAMETERS
    assert "collectorRuntimePrivateDnsResolutionConfirmed = false" in PARAMETERS
    for vm_number in range(1, 12):
        assert f"'synthetic-vm-{vm_number:02d}'" in PARAMETERS
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
        assert signal in MAIN
    assert "All 11 workload VMs had successful" in ADR
    assert "configurationAccessEndpoint" in ADR
    assert "DCR association is read without being rewritten" in ADR
    assert "AzureMonitorLinuxAgent" in ADR
    assert "Shared Key disabled" in ADR
    assert "private-ingestion cutover confirmation" in ADR
    assert "AMPLS remains open" in ADR
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
