from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_wc013_bicep_keeps_runtime_private_keyless_and_least_privileged() -> None:
    orchestration = _read("infra/wc013-live-acceptance/main.bicep")
    resources = _read("infra/wc013-live-acceptance/modules/acceptance-resources.bicep")
    foundation = _read("infra/azure-mcp/main.bicep")
    workload_rbac = _read("infra/azure-mcp/modules/workload-read-rbac.bicep")

    assert "workloadReadScopes: [" in orchestration
    assert "approvedLogWorkspaces: []" in orchestration
    assert "contains(acceptanceImage, '@sha256:')" in orchestration
    assert "acdd72a7-3385-48ef-bd42-f606fba81ae7" in workload_rbac
    expected_reader_scope = (
        "scope: resourceGroup(readScope.subscriptionId, readScope.resourceGroupName)"
    )
    assert expected_reader_scope in foundation
    assert "privateEndpointNetworkPolicies: 'Disabled'" in foundation
    assert "publicNetworkAccess: 'Disabled'" in resources
    assert "allowSharedKeyAccess: false" in resources
    assert "defaultToOAuthAuthentication: true" in resources
    assert "roleDefinitionIdOrName: 'Key Vault Crypto User'" in resources
    assert "scope: replayTable" in resources
    assert "storageTableDataContributorRoleDefinitionId" in resources
    assert "triggerType: 'Manual'" in resources
    assert "replicaRetryLimit: 0" in resources
    assert "acceptanceIdentityResourceId" in resources
    assert "evidenceIdentityResourceId" in resources
    assert "AZURE_CLIENT_ID" in resources
    for forbidden in ("passwordSecretRef", "connectionString", "listKeys(", "secrets:"):
        assert forbidden not in resources


def test_wc013_container_images_use_the_packaged_cli_and_only_reviewed_config_files() -> None:
    runner = _read("Dockerfile")
    delivery = _read("Dockerfile.wc013-delivery")
    dockerignore = _read(".dockerignore")

    assert "python -m pip install --no-cache-dir ." in runner
    assert 'ENTRYPOINT ["athena-context"]' in runner
    assert '"wc013-live-acceptance"' in runner
    assert "USER athena" in runner
    assert "wc013-live/ /opt/athena/wc013-live/" in delivery
    assert "wc013-signing-public-key.pem" in delivery
    assert "!src/**" in dockerignore
    assert "!pyproject.toml" in dockerignore
