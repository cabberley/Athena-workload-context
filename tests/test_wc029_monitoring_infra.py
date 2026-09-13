from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
INFRA = ROOT / "infra" / "wc029-monitoring-prerequisites"
MAIN = (INFRA / "main.bicep").read_text(encoding="utf-8")
GUEST = (INFRA / "modules" / "guest-coverage-validation.bicep").read_text(
    encoding="utf-8"
)
DCR = (INFRA / "modules" / "data-collection-coverage-validation.bicep").read_text(
    encoding="utf-8"
)
NETWORK = (INFRA / "modules" / "network-evidence-validation.bicep").read_text(
    encoding="utf-8"
)
STORAGE = (INFRA / "modules" / "storage-validation.bicep").read_text(
    encoding="utf-8"
)
PARAMETERS = (INFRA / "main.preparation.bicepparam").read_text(
    encoding="utf-8"
)
READINESS = (INFRA / "Test-MonitoringReadiness.ps1").read_text(encoding="utf-8")
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
    assert "destinationWorkspaceResourceIds" in DCR
    assert "fail('The adopted DCR must retain" in DCR


def test_wc029_uses_pinned_avm_for_explicitly_gated_guest_prerequisites() -> None:
    assert MAIN.count(
        "br/public:avm/res/compute/virtual-machine/extension:0.1.0"
    ) == 2
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
            "az bicep validation failed: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
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
