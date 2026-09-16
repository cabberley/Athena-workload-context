from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).parents[1]
INFRA = ROOT / "infra" / "wc029-monitoring-prerequisites"
MAIN = (INFRA / "main.bicep").read_text(encoding="utf-8")
GUEST = (INFRA / "modules" / "guest-coverage-validation.bicep").read_text(encoding="utf-8")
DCR = (INFRA / "modules" / "data-collection-coverage-validation.bicep").read_text(encoding="utf-8")
NETWORK = (INFRA / "modules" / "network-evidence-validation.bicep").read_text(encoding="utf-8")
STORAGE = (INFRA / "modules" / "storage-validation.bicep").read_text(encoding="utf-8")
PARAMETERS = (INFRA / "main.preparation.bicepparam").read_text(encoding="utf-8")
READINESS = (INFRA / "Test-MonitoringReadiness.ps1").read_text(encoding="utf-8")
READINESS_TEST = (
    ROOT / "tests" / "Test-Wc029MonitoringReadiness.ps1"
).read_text(encoding="utf-8")
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
WC025_PARAMETERS = (
    ROOT / "infra" / "wc025-change-ingestion" / "main.example.bicepparam"
).read_text(encoding="utf-8")


def test_wc029_is_subscription_scoped_and_pinned_to_reviewed_environment() -> None:
    assert "targetScope = 'subscription'" in MAIN
    assert "a6add389-9978-47ac-ab1e-a09212e321d4" in MAIN
    assert "rg-athena-demo-workload" in MAIN
    assert "rg-athena-demo-monitoring" in MAIN
    assert "NetworkWatcherRG" in MAIN
    assert "australiaeast" in MAIN
    assert "validatedSubscriptionId" in MAIN
    assert "athena-hackathon-vnet" in MAIN
    assert MAIN.count("athena-hackathon-") >= 14


def test_wc029_readiness_adversarial_wrapper_runs_in_ci() -> None:
    assert "Test WC-029 monitoring readiness rules" in CI
    assert "./tests/Test-Wc029MonitoringReadiness.ps1" in CI
    assert "Parser]::ParseFile" in READINESS_TEST
    assert "Invoke-AzJson" not in READINESS_TEST
    assert "& az" not in READINESS_TEST


def test_wc029_validates_ama_dcr_dce_and_vm_insights_coverage() -> None:
    assert "AzureMonitorLinuxAgent" in GUEST
    assert "properties.provisioningState == 'Succeeded'" in GUEST
    assert "athena-linux-dcr" in GUEST
    assert "configurationAccessEndpoint" in GUEST
    assert "properties.dataCollectionRuleId" in GUEST
    assert "properties.dataCollectionEndpointId" in GUEST
    assert "VMInsights(athena-hackathon-law)" in DCR
    for stream in (
        "Microsoft-Perf",
        "Microsoft-InsightsMetrics",
        "Microsoft-Syslog",
        "Custom-AthenaJson",
    ):
        assert stream in DCR
    for counter in (
        "Processor(_Total)",
        "Memory\\\\% Used Memory",
        "Logical Disk(*)\\\\% Used Space",
        "Network(*)\\\\Total Bytes Received",
        "VmInsights\\\\DetailedMetrics",
    ):
        assert counter in DCR
    assert "approvedWorkspaceDestinationNames" in DCR
    assert "fail('Every required DCR stream must flow" in DCR


def _required_streams_reach_workspace(
    data_flows: list[dict[str, object]],
    destinations: list[dict[str, str]],
    workspace_resource_id: str,
) -> bool:
    approved_names = {
        destination["name"].casefold()
        for destination in destinations
        if destination["workspaceResourceId"].casefold() == workspace_resource_id.casefold()
    }
    for stream in (
        "Microsoft-Perf",
        "Microsoft-InsightsMetrics",
        "Microsoft-Syslog",
        "Custom-AthenaJson",
    ):
        stream_flows = [
            flow for flow in data_flows if stream in cast(list[str], flow["streams"])
        ]
        if not stream_flows:
            return False
        for flow in stream_flows:
            flow_destinations = [
                destination.casefold()
                for destination in cast(list[str], flow["destinations"])
            ]
            if len(flow_destinations) != 1 or flow_destinations[0] not in approved_names:
                return False
    return True


def test_wc029_requires_each_stream_to_reach_the_approved_workspace() -> None:
    approved_workspace = "/subscriptions/reviewed/workspaces/athena-hackathon-law"
    destinations = [
        {"name": "approved", "workspaceResourceId": approved_workspace},
        {"name": "approved-alias", "workspaceResourceId": approved_workspace},
        {"name": "decoy", "workspaceResourceId": "/subscriptions/other/workspaces/x"},
    ]
    positive_flows: list[dict[str, object]] = [
        {
            "streams": [
                "Microsoft-Perf",
                "Microsoft-InsightsMetrics",
                "Microsoft-Syslog",
                "Custom-AthenaJson",
            ],
            "destinations": ["approved"],
        }
    ]
    assert _required_streams_reach_workspace(positive_flows, destinations, approved_workspace)
    for adversarial_flows in (
        [
            {
                "streams": [
                    "Microsoft-Perf",
                    "Microsoft-InsightsMetrics",
                    "Microsoft-Syslog",
                ],
                "destinations": ["approved"],
            },
            {"streams": ["Custom-AthenaJson"], "destinations": ["decoy"]},
        ],
        [
            {
                "streams": [
                    "Microsoft-Perf",
                    "Microsoft-InsightsMetrics",
                    "Microsoft-Syslog",
                    "Custom-AthenaJson",
                ],
                "destinations": ["approved", "decoy"],
            }
        ],
        [
            {
                "streams": [
                    "Microsoft-Perf",
                    "Microsoft-InsightsMetrics",
                    "Microsoft-Syslog",
                    "Custom-AthenaJson",
                ],
                "destinations": ["approved", "approved-alias"],
            }
        ],
        [
            {
                "streams": [
                    "Microsoft-Perf",
                    "Microsoft-InsightsMetrics",
                    "Microsoft-Syslog",
                    "Custom-AthenaJson",
                ],
                "destinations": ["approved"],
            },
            {"streams": ["Microsoft-Perf"], "destinations": ["decoy"]},
        ],
    ):
        assert not _required_streams_reach_workspace(
            adversarial_flows, destinations, approved_workspace
        )
    assert "approvedWorkspaceDestinationNames" in DCR
    assert "streamsMissingExclusiveApprovedWorkspaceFlow" in DCR
    assert "length(flow.?destinations ?? []) != 1" in DCR
    assert "empty(filter(flow.?destinations ?? []" in DCR
    assert "empty(streamsMissingExclusiveApprovedWorkspaceFlow)" in DCR
    assert "Test-DcrStreamFlowsUseExclusiveDestinations" in READINESS
    assert "$flowDestinations.Count -ne 1" in READINESS
    assert "$flowDestinations[0] -notin $ApprovedDestinationNames" in READINESS


def test_wc029_dereferences_dce_and_vm_insights_health_and_binding() -> None:
    assert "resource dataCollectionEndpoint" in GUEST
    assert "toLower(dataCollectionEndpoint.id)" in GUEST
    assert "toLower(dataCollectionEndpoint.location) == location" in GUEST
    assert "dataCollectionEndpoint.properties.provisioningState == 'Succeeded'" in GUEST
    assert "validatedDataCollectionEndpointResourceId" in GUEST
    assert "dataCollectionEndpointResourceId: dataCollectionEndpointResourceId" in MAIN
    assert "dataCollectionRule.properties.?dataCollectionEndpointId" in DCR
    assert "dcrDataCollectionEndpointIsValid" in DCR
    assert "Test-DcrDataCollectionEndpoint" in READINESS
    assert "$ama[0].publisher -eq 'Microsoft.Azure.Monitor'" in READINESS
    assert "$ama[0].typePropertiesType -eq 'AzureMonitorLinuxAgent'" in READINESS
    assert "toLower(vmInsightsSolution.location) == location" in DCR
    assert "vmInsightsSolution.properties.provisioningState == 'Succeeded'" in DCR
    assert "vmInsightsSolution.properties.workspaceResourceId" in DCR
    assert "validatedVmInsightsSolutionResourceId" in DCR


def _monitoring_associations_are_valid(**overrides: object) -> bool:
    expected_dcr_id = "/subscriptions/reviewed/providers/Microsoft.Insights/dcr/approved"
    expected_dce_id = "/subscriptions/reviewed/providers/Microsoft.Insights/dce/approved"
    expected_workspace_id = (
        "/subscriptions/reviewed/providers/Microsoft.OperationalInsights/workspaces/approved"
    )
    posture: dict[str, object] = {
        "dce_id": expected_dce_id,
        "dce_location": "australiaeast",
        "dce_provisioning_state": "Succeeded",
        "dcr_data_collection_endpoint_id": expected_dce_id,
        "vm_location": "australiaeast",
        "ama_publisher": "Microsoft.Azure.Monitor",
        "ama_type": "AzureMonitorLinuxAgent",
        "ama_provisioning_state": "Succeeded",
        "dcr_association_id": expected_dcr_id,
        "dce_association_id": expected_dce_id,
        "vm_insights_location": "australiaeast",
        "vm_insights_provisioning_state": "Succeeded",
        "vm_insights_workspace_id": expected_workspace_id,
    }
    posture.update(overrides)
    return (
        str(posture["dce_id"]).casefold() == expected_dce_id.casefold()
        and posture["dce_location"] == "australiaeast"
        and posture["dce_provisioning_state"] == "Succeeded"
        and str(posture["dcr_data_collection_endpoint_id"]).casefold()
        == expected_dce_id.casefold()
        and posture["vm_location"] == "australiaeast"
        and posture["ama_publisher"] == "Microsoft.Azure.Monitor"
        and posture["ama_type"] == "AzureMonitorLinuxAgent"
        and posture["ama_provisioning_state"] == "Succeeded"
        and str(posture["dcr_association_id"]).casefold() == expected_dcr_id.casefold()
        and str(posture["dce_association_id"]).casefold() == expected_dce_id.casefold()
        and posture["vm_insights_location"] == "australiaeast"
        and posture["vm_insights_provisioning_state"] == "Succeeded"
        and str(posture["vm_insights_workspace_id"]).casefold()
        == expected_workspace_id.casefold()
    )


@pytest.mark.parametrize(
    "override",
    [
        {"dce_id": "/subscriptions/reviewed/providers/Microsoft.Insights/dce/decoy"},
        {"dce_provisioning_state": "Failed"},
        {
            "dcr_data_collection_endpoint_id": (
                "/subscriptions/reviewed/providers/Microsoft.Insights/dce/decoy"
            )
        },
        {"ama_provisioning_state": "Failed"},
        {"dcr_association_id": "/subscriptions/reviewed/providers/Microsoft.Insights/dcr/decoy"},
        {"dce_association_id": "/subscriptions/reviewed/providers/Microsoft.Insights/dce/decoy"},
        {
            "vm_insights_workspace_id": (
                "/subscriptions/other/providers/"
                "Microsoft.OperationalInsights/workspaces/decoy"
            )
        },
    ],
)
def test_wc029_rejects_decoy_or_unhealthy_monitoring_associations(
    override: dict[str, object],
) -> None:
    assert _monitoring_associations_are_valid()
    assert not _monitoring_associations_are_valid(**override)


def test_wc029_uses_pinned_avm_for_explicitly_gated_guest_prerequisites() -> None:
    assert MAIN.count("br/public:avm/res/compute/virtual-machine/extension:0.1.0") == 2
    assert "param deployVmInsightsDependencyAgent bool = false" in MAIN
    assert "param deployConnectionMonitorAgent bool = false" in MAIN
    assert "Microsoft.Azure.Monitoring.DependencyAgent" in MAIN
    assert "DependencyAgentLinux" in MAIN
    assert "enableAMA: 'true'" in MAIN
    assert "Microsoft.Azure.NetworkWatcher" in MAIN
    assert "NetworkWatcherAgentLinux" in MAIN
    assert "connectionMonitorSourceVmNames" in MAIN
    assert "enableTelemetry: false" in MAIN
    assert "Microsoft.Network/networkWatchers/connectionMonitors@" not in MAIN


def test_wc029_validates_flow_analytics_and_private_storage_without_shared_keys() -> None:
    assert "athena-hackathon-vnet-rg-athena-demo-workload-flowlog" in NETWORK
    assert "trafficAnalyticsInterval == 10" in NETWORK
    assert "properties.storageId" in NETWORK
    assert "athenahackathonflowwhtco" in NETWORK
    assert "athenademomonchab01" in PARAMETERS
    assert "allowSharedKeyAccess == false" in STORAGE
    assert "allowBlobPublicAccess == false" in STORAGE
    assert "defaultToOAuthAuthentication == true" in STORAGE
    assert "defaultAction == 'Deny'" in STORAGE
    assert "bypass == 'AzureServices'" in STORAGE
    assert "flow-log-evidence-retention" in STORAGE
    assert "privateLinkServiceConnections" in STORAGE
    assert "'blob'" in STORAGE
    assert "listKeys(" not in MAIN + STORAGE


def _reviewed_storage_posture_is_valid(**overrides: object) -> bool:
    expected_collector_vnet_id = "/subscriptions/reviewed/virtualNetworks/collector"
    expected_private_endpoint_subnet_id = f"{expected_collector_vnet_id}/subnets/private-endpoints"
    expected_blob_private_dns_zone_id = (
        "/subscriptions/reviewed/privateDnsZones/privatelink.blob.core.windows.net"
    )
    posture: dict[str, object] = {
        "rule_enabled": True,
        "rule_type": "Lifecycle",
        "tier_to_cool_days": 30,
        "base_delete_days": 30,
        "version_delete_days": 30,
        "blob_types": ["blockBlob"],
        "prefixes": [
            "insights-logs-flowlogflowevent/",
            "monitoring-evidence/",
        ],
        "blob_soft_delete_enabled": True,
        "blob_soft_delete_days": 30,
        "container_soft_delete_enabled": True,
        "container_soft_delete_days": 30,
        "connection_status": "Approved",
        "connection_provisioning_state": "Succeeded",
        "connection_group_ids": ["blob"],
        "overlapping_delete_days": [30],
        "private_endpoint_subnet_id": expected_private_endpoint_subnet_id,
        "dns_zone_group_provisioning_state": "Succeeded",
        "dns_zone_ids": [expected_blob_private_dns_zone_id],
        "dns_vnet_link_provisioning_state": "Succeeded",
        "dns_vnet_link_state": "Completed",
        "dns_vnet_registration_enabled": False,
        "dns_vnet_link_vnet_id": expected_collector_vnet_id,
    }
    posture.update(overrides)
    return (
        posture["rule_enabled"] is True
        and posture["rule_type"] == "Lifecycle"
        and posture["tier_to_cool_days"] == 30
        and int(posture["base_delete_days"]) >= 30
        and int(posture["version_delete_days"]) >= 30
        and posture["blob_types"] == ["blockBlob"]
        and set(posture["prefixes"]) == {"insights-logs-flowlogflowevent/", "monitoring-evidence/"}
        and posture["blob_soft_delete_enabled"] is True
        and int(posture["blob_soft_delete_days"]) >= 30
        and posture["container_soft_delete_enabled"] is True
        and int(posture["container_soft_delete_days"]) >= 30
        and posture["connection_status"] == "Approved"
        and posture["connection_provisioning_state"] == "Succeeded"
        and posture["connection_group_ids"] == ["blob"]
        and all(
            days >= 30 for days in cast(list[int], posture["overlapping_delete_days"])
        )
        and str(posture["private_endpoint_subnet_id"]).casefold()
        == expected_private_endpoint_subnet_id.casefold()
        and posture["dns_zone_group_provisioning_state"] == "Succeeded"
        and [
            str(zone_id).casefold()
            for zone_id in cast(list[str], posture["dns_zone_ids"])
        ]
        == [expected_blob_private_dns_zone_id.casefold()]
        and posture["dns_vnet_link_provisioning_state"] == "Succeeded"
        and posture["dns_vnet_link_state"] == "Completed"
        and posture["dns_vnet_registration_enabled"] is False
        and str(posture["dns_vnet_link_vnet_id"]).casefold()
        == expected_collector_vnet_id.casefold()
    )


def test_wc029_accepts_complete_reviewed_storage_posture() -> None:
    assert _reviewed_storage_posture_is_valid()
    for required_check in (
        "rule.enabled == true",
        "tierToCool.?daysAfterModificationGreaterThan",
        "baseBlob.?delete.?daysAfterModificationGreaterThan",
        "version.?delete.?daysAfterCreationGreaterThan",
        "deleteRetentionPolicy.days >= requiredRetentionDays",
        "containerDeleteRetentionPolicy.days >= requiredRetentionDays",
        "privateLinkServiceConnectionState.status == 'Approved'",
        "connection.properties.provisioningState == 'Succeeded'",
        "length(connection.properties.groupIds) == 1",
        "unsafeRetentionRules",
        "empty(unsafeRetentionRules)",
        "length(approvedBlobConnections) == 1",
        "storagePrivateEndpoint.properties.subnet.id",
        "storagePrivateDnsZoneGroup.properties.provisioningState == 'Succeeded'",
        "length(approvedBlobPrivateDnsZoneConfigs) == 1",
        "collectorBlobPrivateDnsVnetLink.properties.virtualNetworkLinkState == 'Completed'",
    ):
        assert required_check in STORAGE
    assert "$filters.PSObject.Properties['prefixMatch']" in READINESS


@pytest.mark.parametrize(
    "override",
    [
        {"rule_enabled": False},
        {"blob_soft_delete_enabled": False},
        {"container_soft_delete_enabled": False},
        {"base_delete_days": 29},
        {"version_delete_days": 29},
        {"blob_soft_delete_days": 29},
        {"container_soft_delete_days": 29},
        {"connection_status": "Rejected"},
        {"connection_provisioning_state": "Failed"},
        {"connection_group_ids": ["blob", "dfs"]},
        {"overlapping_delete_days": [30, 29]},
        {"private_endpoint_subnet_id": "/subscriptions/reviewed/subnets/decoy"},
        {"dns_zone_group_provisioning_state": "Failed"},
        {"dns_zone_ids": ["/subscriptions/reviewed/privateDnsZones/decoy"]},
        {"dns_vnet_link_state": "Disconnected"},
        {"dns_vnet_registration_enabled": True},
        {"dns_vnet_link_vnet_id": "/subscriptions/reviewed/virtualNetworks/decoy"},
    ],
)
def test_wc029_rejects_disabled_shortened_or_rejected_storage_posture(
    override: dict[str, object],
) -> None:
    assert not _reviewed_storage_posture_is_valid(**override)


def test_wc029_keeps_connection_monitor_and_subscription_export_disabled() -> None:
    assert "@allowed([\n  false\n])\nparam subscriptionActivityLogExportEnabled" in MAIN
    assert "@allowed([\n  false\n])\nparam connectionMonitorDefinitionsEnabled" in MAIN
    assert "subscriptionActivityLogExportEnabled = false" in PARAMETERS
    assert "connectionMonitorDefinitionsEnabled = false" in PARAMETERS
    assert "deployConnectionMonitorAgent = false" in PARAMETERS
    assert "connectionMonitorSourceVmNames = []" in PARAMETERS
    combined = "\n".join(path.read_text(encoding="utf-8") for path in INFRA.rglob("*.bicep"))
    assert "Microsoft.Insights/diagnosticSettings" not in combined
    assert "Microsoft.Network/networkWatchers/connectionMonitors@" not in combined


def test_wc029_readiness_check_is_read_only_and_covers_remaining_evidence() -> None:
    assert "Set-StrictMode -Version Latest" in READINESS
    assert "athenahackathonflowwhtco" in READINESS
    assert "athenademomonchab01" in READINESS
    assert "flow-log-evidence-retention" in READINESS
    assert "subscriptionActivityLogExportCount" in READINESS
    assert "Microsoft.Resources.ResourceGroups" in READINESS
    assert "RequireDependencyAgent" in READINESS
    assert "RequireConnectionMonitorAgent" in READINESS
    assert "RequireChangeEventRoute" in READINESS
    assert "noMutationPerformed = $true" in READINESS
    for mutation in (
        "az account set",
        "deployment create",
        "deployment sub create",
        "resource update",
        "vm extension set",
        "flow-log create",
    ):
        assert mutation not in READINESS.casefold()


def test_wc025_example_is_synthetic_and_subscription_export_stays_off() -> None:
    assert "Synthetic and intentionally non-deployable" in WC025_PARAMETERS
    assert "00000000-0000-0000-0000-000000000000" in WC025_PARAMETERS
    assert "subscriptionActivityLogExportEnabled = false" in WC025_PARAMETERS
    assert "rg-athena-demo-workload" in WC025_PARAMETERS
    assert "password" not in WC025_PARAMETERS.casefold()
    assert "connectionstring" not in WC025_PARAMETERS.casefold()


def _run_bicep(args: list[str], cwd: Path) -> None:
    az_cli = shutil.which("az")
    if az_cli is None:
        pytest.fail("az CLI is required for WC-029 Bicep validation")
    result = subprocess.run(
        [az_cli, "bicep", *args, "--stdout"],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            f"az bicep validation failed: stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def test_wc029_and_wc025_parameter_artifacts_build() -> None:
    _run_bicep(["build", "--file", str(INFRA / "main.bicep")], INFRA)
    _run_bicep(
        [
            "build-params",
            "--file",
            str(INFRA / "main.preparation.bicepparam"),
        ],
        ROOT,
    )
    _run_bicep(
        [
            "build-params",
            "--file",
            str(ROOT / "infra" / "wc025-change-ingestion" / "main.example.bicepparam"),
        ],
        ROOT,
    )
