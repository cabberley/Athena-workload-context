from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "infra" / "azure-mcp"
MAIN = (MCP_ROOT / "main.bicep").read_text(encoding="utf-8")
CONTAINER_APP = (MCP_ROOT / "modules" / "container-app.bicep").read_text(
    encoding="utf-8"
)
WORKLOAD_RBAC = (MCP_ROOT / "modules" / "workload-read-rbac.bicep").read_text(
    encoding="utf-8"
)
WORKSPACE_RBAC = (MCP_ROOT / "modules" / "workspace-log-rbac.bicep").read_text(
    encoding="utf-8"
)
EXAMPLE_PARAMS = (
    ROOT / "infra" / "examples" / "azure-mcp-foundation" / "main.example.bicepparam"
).read_text(encoding="utf-8")

EXPECTED_TOOLS = (
    "azmcp_group_resource_list",
    "azmcp_monitor_activitylog_list",
    "azmcp_monitor_metrics_definitions",
    "azmcp_monitor_metrics_query",
    "azmcp_monitor_resource_log_query",
    "azmcp_monitor_workspace_log_query",
    "azmcp_resourcehealth_availability-status_get",
)
APPROVED_READ_ROLE_IDS = {
    "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "43d0d8ad-25c7-4714-9337-8ba259a9fe05",
    "96aae8d4-72a9-4bc2-ae31-3a10c2c4e526",
    "73c42c96-874c-492b-b04d-ab87d138a893",
}


def _quoted_values_in_variable(source: str, variable: str) -> tuple[str, ...]:
    match = re.search(rf"var {variable} = \[(?P<body>.*?)\n\]", source, re.DOTALL)
    assert match is not None
    return tuple(re.findall(r"'([^']+)'", match.group("body")))


def test_ingress_and_environment_are_private() -> None:
    assert "publicNetworkAccess: 'Disabled'" in MAIN
    assert "internal: true" in MAIN
    assert "external: false" in CONTAINER_APP
    assert "allowInsecure: false" in CONTAINER_APP
    assert "external: true" not in CONTAINER_APP


def test_image_is_reviewed_and_immutable() -> None:
    assert "param azureMcpVersion string = '2.0.5'" in MAIN
    assert (
        "sha256:2285f62dc1720ebf5da90498828b27e73d8fae6fd6fb89cab8cf67e3646fce3a"
        in MAIN
    )
    assert "@allowed([\n  '2.0.5'\n])" in MAIN
    assert "azureMcpVersion}@${azureMcpImageDigest}" in CONTAINER_APP
    assert ":latest" not in "\n".join(
        path.read_text(encoding="utf-8")
        for path in MCP_ROOT.rglob("*.bicep")
    ).lower()


def test_server_is_authenticated_host_identity_read_only() -> None:
    args = _quoted_values_in_variable(CONTAINER_APP, "baseServerArgs")
    assert args == (
        "--transport",
        "http",
        "--outgoing-auth-strategy",
        "UseHostingEnvironmentIdentity",
        "--mode",
        "all",
        "--read-only",
    )
    assert "AzureAd__TenantId" in CONTAINER_APP
    assert "AzureAd__ClientId" in CONTAINER_APP
    assert "AZURE_CLIENT_ID" in CONTAINER_APP
    assert "disable-http-incoming-auth" not in CONTAINER_APP.lower()


def test_tool_allowlist_is_exact_without_wildcards_or_mutations() -> None:
    tools = _quoted_values_in_variable(CONTAINER_APP, "approvedTools")
    assert tools == EXPECTED_TOOLS
    assert all("*" not in tool for tool in tools)
    assert "--namespace" not in CONTAINER_APP
    assert all(
        verb not in tool
        for tool in tools
        for verb in ("_create", "_update", "_delete", "_write", "_deploy")
    )
    assert CONTAINER_APP.count("'--tool'") == 1


def test_context_and_mcp_identities_are_separate() -> None:
    assert "resource mcpIdentity" in MAIN
    assert "resource contextIdentity" in MAIN
    assert "'UserAssigned'" in CONTAINER_APP
    assert "'${mcpIdentityResourceId}': {}" in CONTAINER_APP
    assert "mcpIdentity.properties.principalId" in MAIN
    assert "contextIdentity.properties.principalId" not in MAIN
    assert "contextIdentity" not in WORKLOAD_RBAC
    assert "contextIdentity" not in WORKSPACE_RBAC


def test_rbac_is_optional_narrow_and_read_only() -> None:
    assert "param workloadReadScopes array = []" in MAIN
    assert "param approvedLogWorkspaces array = []" in MAIN
    assert "scope: resourceGroup(" in MAIN
    assert "scope: approvedWorkspace" in WORKSPACE_RBAC
    assert "targetScope = 'subscription'" not in WORKLOAD_RBAC
    assert "targetScope = 'subscription'" not in WORKSPACE_RBAC

    role_sources = WORKLOAD_RBAC + WORKSPACE_RBAC
    observed_role_ids = set(
        re.findall(r"'([0-9a-f]{8}-[0-9a-f-]{27,})'", role_sources)
    )
    assert observed_role_ids == APPROVED_READ_ROLE_IDS
    assert all(
        broad_role not in role_sources.lower()
        for broad_role in ("owner", "contributor", "user access administrator")
    )


def test_example_denies_evidence_access_by_default_and_contains_no_secret() -> None:
    assert "param workloadReadScopes = []" in EXAMPLE_PARAMS
    assert "param approvedLogWorkspaces = []" in EXAMPLE_PARAMS
    assert "password" not in EXAMPLE_PARAMS.lower()
    assert "secret" not in EXAMPLE_PARAMS.lower()


def test_bicep_parameters_contain_no_credentials() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "infra").rglob("*.bicep")
    ).lower()
    assert "clientsecret" not in source
    assert "client_secret" not in source
    assert "password" not in source
    assert "connectionstring" not in source
