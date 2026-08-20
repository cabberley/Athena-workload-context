from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "infra" / "azure-mcp"
WC013_MAIN = (
    ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"
).read_text(encoding="utf-8")
MAIN = (MCP_ROOT / "main.bicep").read_text(encoding="utf-8")
CONTAINER_APP = (MCP_ROOT / "modules" / "container-app.bicep").read_text(
    encoding="utf-8"
)
PRIVATE_DNS = (
    MCP_ROOT / "modules" / "container-apps-private-dns.bicep"
).read_text(encoding="utf-8")
WORKLOAD_RBAC = (MCP_ROOT / "modules" / "workload-read-rbac.bicep").read_text(
    encoding="utf-8"
)
WORKSPACE_RBAC = (MCP_ROOT / "modules" / "workspace-log-rbac.bicep").read_text(
    encoding="utf-8"
)
README = (MCP_ROOT / "README.md").read_text(encoding="utf-8")
EXAMPLE_PARAMS = (
    ROOT / "infra" / "examples" / "azure-mcp-foundation" / "main.example.bicepparam"
).read_text(encoding="utf-8")


def _load_fixture(name: str) -> dict[str, Any]:
    fixture = MCP_ROOT / "validation" / name
    return json.loads(fixture.read_text(encoding="utf-8"))


TOOL_CATALOG = _load_fixture("azure-mcp-2.0.5-tool-catalog.json")
ROLE_CATALOG = _load_fixture("azure-built-in-role-catalog.json")


def _quoted_values_in_variable(source: str, variable: str) -> tuple[str, ...]:
    match = re.search(rf"var {variable} = \[(?P<body>.*?)\n\]", source, re.DOTALL)
    assert match is not None
    return tuple(re.findall(r"'([^']+)'", match.group("body")))


def test_ingress_is_vnet_scoped_without_public_environment_exposure() -> None:
    assert "publicNetworkAccess: 'Disabled'" in MAIN
    assert "internal: true" in MAIN
    assert "external: true" in CONTAINER_APP
    assert "allowInsecure: false" in CONTAINER_APP
    assert "external: false" not in CONTAINER_APP
    assert "modules/container-apps-private-dns.bicep" in MAIN
    assert (
        "environmentDefaultDomain: managedEnvironment.properties.defaultDomain"
        in MAIN
    )
    assert "environmentStaticIp: managedEnvironment.properties.staticIp" in MAIN
    assert "virtualNetworkResourceId: virtualNetwork.id" in MAIN
    assert (
        "containerAppsPrivateDnsVnetLinkName: 'wc013-containerapps-link'"
        in WC013_MAIN
    )


def test_private_dns_maps_container_apps_domain_to_environment_static_ip() -> None:
    assert (
        "resource containerAppsPrivateDnsZone "
        "'Microsoft.Network/privateDnsZones@2024-06-01'"
        in PRIVATE_DNS
    )
    assert "name: environmentDefaultDomain" in PRIVATE_DNS
    assert (
        "resource containerAppsPrivateDnsZoneLink "
        "'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01'"
        in PRIVATE_DNS
    )
    assert "registrationEnabled: false" in PRIVATE_DNS
    assert "name: virtualNetworkLinkName" in PRIVATE_DNS
    assert "id: virtualNetworkResourceId" in PRIVATE_DNS
    assert (
        "resource containerAppsWildcardRecord "
        "'Microsoft.Network/privateDnsZones/A@2024-06-01'"
        in PRIVATE_DNS
    )
    assert "name: '*'" in PRIVATE_DNS
    assert "ipv4Address: environmentStaticIp" in PRIVATE_DNS


def test_http_endpoint_uses_pinned_server_root_route() -> None:
    provenance = TOOL_CATALOG["provenance"]
    assert TOOL_CATALOG["httpRoute"] == "/"
    assert provenance["routeMapping"] == "app.MapMcp()"
    assert provenance["routeSource"].endswith("ServiceStartCommand.cs")
    assert (
        "output internalEndpoint string = "
        "'https://${azureMcp.properties.configuration.ingress.fqdn}'"
        in CONTAINER_APP
    )
    assert "/mcp" not in CONTAINER_APP
    assert "send `POST /`" in README


def test_image_is_reviewed_and_immutable() -> None:
    package = TOOL_CATALOG["package"]
    image = TOOL_CATALOG["image"]
    source = TOOL_CATALOG["source"]
    version = TOOL_CATALOG["serverVersion"]
    assert version == package["version"] == image["tag"] == source["releaseVersion"]
    assert package["name"] == "@azure/mcp"
    assert package["repository"] == f"{source['repository']}.git"
    assert re.fullmatch(r"[0-9a-f]{40}", package["distShasum"])
    assert source["revision"] == image["sourceRevisionLabel"]["value"]
    assert source["revision"] == "2712e19ddf1c55f8e73ead8fb671915ec92801cc"
    assert image["sourceRevisionLabel"]["name"] == (
        "com.azure.dev.image.build.sourceversion"
    )
    assert source["releaseVersionEvidence"].startswith(f"## {version} ")
    assert set(source["gitBlobs"]) == {
        source["releaseVersionSource"],
        TOOL_CATALOG["provenance"]["routeSource"],
        TOOL_CATALOG["provenance"]["toolNameSource"],
        TOOL_CATALOG["provenance"]["toolExposureSource"],
    }
    assert all(
        re.fullmatch(r"[0-9a-f]{40}", blob_id)
        for blob_id in source["gitBlobs"].values()
    )
    assert f"param azureMcpVersion string = '{version}'" in MAIN
    assert image["manifestDigest"] in MAIN
    assert f"@allowed([\n  '{version}'\n])" in MAIN
    assert "azureMcpVersion}@${azureMcpImageDigest}" in CONTAINER_APP
    assert ":latest" not in "\n".join(
        path.read_text(encoding="utf-8") for path in MCP_ROOT.rglob("*.bicep")
    ).lower()


def test_pinned_tool_catalog_has_runtime_provenance() -> None:
    provenance = TOOL_CATALOG["provenance"]
    tools = TOOL_CATALOG["tools"]
    package_label = f"{TOOL_CATALOG['package']['name']}@{TOOL_CATALOG['package']['version']}"
    assert provenance["package"] == package_label
    assert provenance["catalogCommand"] == f"npx -y {package_label} tools list"
    assert provenance["catalogRecordCount"] == 235
    assert provenance["catalogHashScope"] == "results"
    assert "keys sorted" in provenance["catalogCanonicalization"]
    assert (
        provenance["catalogCanonicalSha256"]
        == "032b52ae4214b9df410182292b2bf0a82f9a84eec7b64cc5c8c40f726c4d4a0c"
    )
    assert provenance["toolNameSeparator"] == "_"
    assert provenance["toolExposureAssignment"] == "Name = fullName"
    assert len(tools) == 7
    assert len({tool["id"] for tool in tools}) == len(tools)
    assert len({tool["name"] for tool in tools}) == len(tools)
    assert all(tool["name"] == tool["command"].replace(" ", "_") for tool in tools)
    assert all(not tool["name"].startswith("azmcp_") for tool in tools)


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


def test_tool_allowlist_matches_pinned_catalog_without_mutations() -> None:
    catalog_tools = TOOL_CATALOG["tools"]
    expected_tools = tuple(tool["name"] for tool in catalog_tools)
    configured_tools = _quoted_values_in_variable(CONTAINER_APP, "approvedTools")
    assert configured_tools == expected_tools
    assert all(tool["readOnly"] is True for tool in catalog_tools)
    assert all(tool["destructive"] is False for tool in catalog_tools)
    assert all(tool["secret"] is False for tool in catalog_tools)
    assert all(tool["openWorld"] is False for tool in catalog_tools)
    assert all("*" not in tool for tool in configured_tools)
    assert "--namespace" not in CONTAINER_APP
    assert all(
        verb not in tool
        for tool in configured_tools
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


def test_official_reader_covers_required_resource_health_read() -> None:
    roles = {role["name"]: role for role in ROLE_CATALOG["roles"]}
    reader = roles["Reader"]
    required = ROLE_CATALOG["requiredPermissions"]["resourceHealthAvailability"]
    assert reader["roleType"] == "BuiltInRole"
    assert reader["id"] == "acdd72a7-3385-48ef-bd42-f606fba81ae7"
    assert required == "Microsoft.ResourceHealth/availabilityStatuses/read"
    assert required.endswith("/read")
    assert "*/read" in reader["actions"]
    assert reader["dataActions"] == []
    assert WORKLOAD_RBAC.count("Microsoft.Authorization/roleAssignments") == 1
    assert "96aae8d4-72a9-4bc2-ae31-3a10c2c4e526" not in WORKLOAD_RBAC


def test_workspace_role_is_query_only_log_analytics_data_reader() -> None:
    roles = {role["name"]: role for role in ROLE_CATALOG["roles"]}
    data_reader = roles["Log Analytics Data Reader"]
    permissions = data_reader["actions"] + data_reader["dataActions"]
    assert data_reader["id"] == "3b03c2da-16b3-4a49-8834-0f8130efdd3b"
    assert data_reader["roleType"] == "BuiltInRole"
    assert all(permission.endswith("/read") for permission in permissions)
    assert all(
        forbidden not in permission.lower()
        for permission in permissions
        for forbidden in ("/action", "/write", "/delete", "export")
    )
    assert data_reader["notActions"] == []
    assert data_reader["notDataActions"] == []
    assert data_reader["id"] in WORKSPACE_RBAC
    assert "73c42c96-874c-492b-b04d-ab87d138a893" not in WORKSPACE_RBAC


def test_rbac_is_optional_narrow_nonduplicative_and_read_only() -> None:
    assert "param workloadReadScopes array = []" in MAIN
    assert "param approvedLogWorkspaces array = []" in MAIN
    assert "scope: resourceGroup(" in MAIN
    assert "scope: approvedWorkspace" in WORKSPACE_RBAC
    assert "targetScope = 'subscription'" not in WORKLOAD_RBAC
    assert "targetScope = 'subscription'" not in WORKSPACE_RBAC

    role_sources = WORKLOAD_RBAC + WORKSPACE_RBAC
    fixture_role_ids = {role["id"] for role in ROLE_CATALOG["roles"]}
    observed_role_ids = set(
        re.findall(r"'([0-9a-f]{8}-[0-9a-f-]{27,})'", role_sources)
    )
    assert observed_role_ids == fixture_role_ids
    assert "monitoringReaderRoleDefinitionId" not in role_sources
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
