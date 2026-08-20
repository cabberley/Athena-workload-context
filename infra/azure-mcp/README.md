# Private Azure MCP foundation

This issue-scoped Bicep module deploys Azure MCP as a customer-hosted Azure Container App. It does
not change shared root orchestration.

## Security posture

- The reviewed `mcr.microsoft.com/azure-sdk/azure-mcp:2.0.5` image is pinned to manifest digest
  `sha256:2285f62dc1720ebf5da90498828b27e73d8fae6fd6fb89cab8cf67e3646fce3a`.
- The Container Apps environment is internal with public network access disabled. App ingress is
  external to the app environment (`external: true`) so approved VNet callers can use the normal
  non-`.internal` FQDN, but the environment virtual IP remains private and is not internet
  reachable. Envoy remains HTTPS-only.
- A private DNS zone named for the environment `defaultDomain` is linked only to the dedicated VNet.
  Its wildcard A record maps every Container Apps FQDN in that domain to the environment
  `staticIp`.
- Azure MCP requires an Entra bearer token. Supply an existing Entra application client ID
  configured with the Azure MCP `Mcp.Tools.ReadWrite.All` application role and grant that role only
  to approved calling identities. No client secret is required by this deployment.
- Outbound Azure access uses `UseHostingEnvironmentIdentity` and a dedicated user-assigned managed
  identity. `--read-only` remains enabled.
- The separately created Athena context identity is never passed to an RBAC module. It has no
  workload Reader or workspace log role.
- Workload and workspace assignments default to empty. Workload roles can only be assigned at an
  explicitly named resource group; log access can only be assigned on an explicitly named existing
  Log Analytics workspace. There is no subscription-scope role-assignment path.
- Telemetry export is disabled. No secret, connection string, unrestricted log export, or Key Vault
  reference is needed.

The modules follow Azure Verified Module conventions where feasible: one concern per module,
described parameters and outputs, deterministic names, idempotent role-assignment GUIDs, tags, and
secure defaults. Native resources are used because the private environment, exact command line, and
cross-resource-group optional RBAC scopes must stay visible for review.

## Exact Azure MCP tool allowlist

The allowlist is a source constant, not a deployment parameter:

1. `group_resource_list`
2. `monitor_activitylog_list`
3. `monitor_metrics_definitions`
4. `monitor_metrics_query`
5. `monitor_resource_log_query`
6. `monitor_workspace_log_query`
7. `resourcehealth_availability-status_get`

Every tool is read-only in Azure MCP 2.0.5. Namespace filters and wildcards are not accepted.
The pinned catalog snapshot under `validation/` records each runtime name, command ID, safety
metadata, source commit, catalog hash, image digest, and retrieval command. Runtime tool names do
not include the CLI executable prefix.

Azure MCP 2.0.5 maps HTTP MCP with `app.MapMcp()` at `/`. The deployment output is therefore the
root internal FQDN, with no `/mcp` suffix. Clients send MCP requests using `POST /`.

## RBAC inputs

`workloadReadScopes` accepts reviewed resource-group targets:

```bicep
[
  {
    subscriptionId: '<target-subscription-guid>'
    resourceGroupName: 'synthetic-workload-rg'
  }
]
```

`approvedLogWorkspaces` accepts reviewed workspace targets:

```bicep
[
  {
    subscriptionId: '<target-subscription-guid>'
    resourceGroupName: 'synthetic-monitoring-rg'
    name: 'synthetic-logs'
  }
]
```

The only assignable built-in roles are:

- **Reader** at each approved workload resource group. Its official `*/read` permission covers
  inventory, metrics, activity logs, and
  `Microsoft.ResourceHealth/availabilityStatuses/read`. No duplicate Monitoring Reader or
  nonexistent Resource Health Reader assignment is added.
- **Log Analytics Data Reader** at each approved workspace. Its permissions are limited to
  workspace/query reads and table data reads; it has no export, action, write, or delete permission.

The official role snapshot under `validation/` records the reviewed role IDs and permissions. Do
not use a subscription as a convenience scope. The deployment principal is a separate operator or
CI identity and must not be either runtime identity.

## Deployment

Prerequisites:

1. Review the pinned release and digest.
2. Create or approve the Entra resource application and application role described above. Grant
   the role to only the calling Athena service identity; do not add Azure workload roles to that
   identity.
3. Ensure the calling Athena service runs inside the linked VNet boundary. The WC-013 job shares
   the Container Apps environment; other approved VNet callers must have both network connectivity
   and private DNS resolution for the environment domain.
4. Review every optional RBAC target and ensure the deployment identity can deploy at those exact
   scopes.

Build and review the example without deploying:

```powershell
az bicep build `
  --file infra/examples/azure-mcp-foundation/main.bicep `
  --stdout

az deployment sub what-if `
  --location australiaeast `
  --parameters infra/examples/azure-mcp-foundation/main.example.bicepparam `
  --parameters entraApplicationClientId='<reviewed-app-client-id>'
```

Review what-if for deletes, public exposure, identity replacement, role broadening, or unexpected
scopes. Deploy only after approval:

```powershell
az deployment sub create `
  --name wc008-private-azure-mcp `
  --location australiaeast `
  --parameters infra/examples/azure-mcp-foundation/main.example.bicepparam `
  --parameters entraApplicationClientId='<reviewed-app-client-id>'
```

## Optional live validation

These commands are optional and require an approved deployed environment. They are not part of the
default test suite.

```powershell
# The environment must report internal=true/public=Disabled.
az containerapp env show --name <environment> --resource-group <hosting-rg> `
  --query '{internal:properties.vnetConfiguration.internal,public:properties.publicNetworkAccess}'
# The app must report external=true/allowInsecure=false.
# Here external means VNet-reachable, not public.
az containerapp show --name <container-app> --resource-group <hosting-rg> `
  --query 'properties.configuration.ingress.{external:external,allowInsecure:allowInsecure}'

# Confirm the private DNS wildcard resolves the environment domain to its static private IP.
az network private-dns record-set a show --resource-group <hosting-rg> `
  --zone-name <environment-default-domain> --name '*' `
  --query 'aRecords[].ipv4Address'

# Confirm only one UAMI is attached and inspect the exact immutable image and startup arguments.
az containerapp show --name <container-app> --resource-group <hosting-rg> `
  --query '{identity:identity,image:properties.template.containers[0].image,args:properties.template.containers[0].args}'

# Confirm role assignments exist only for the MCP principal at reviewed scopes.
az role assignment list --assignee-object-id <mcp-principal-id> --all `
  --query '[].{scope:scope,role:roleDefinitionName}'
az role assignment list --assignee-object-id <context-principal-id> --all `
  --query "[?contains(scope, '/resourceGroups/<workload-rg>')]"
```

From an approved caller inside the linked VNet boundary, first resolve the non-`.internal` MCP FQDN
to the environment static private IP, then send `POST /` without a token and confirm HTTP 401. Use
its managed identity to request the configured resource-app token and issue an MCP `tools/list`
request. Compare the returned names exactly with the seven entries above. Exercise one denied write
tool and one out-of-scope resource and confirm both fail.

Treat every successful MCP response as untrusted. Before Athena uses it, the evidence boundary must
validate the requested and returned tool identity, exact resource scope, observation time and
freshness, maximum item count and byte size, expected schema, and request/source provenance. Reject
missing, malformed, stale, oversized, out-of-scope, or mismatched output; never publish it directly
or use it for remediation.

## Rollback

1. Revoke the MCP identity's workload/workspace role assignments and caller application-role grants.
2. Pin `azureMcpVersion` and `azureMcpImageDigest` to the last reviewed pair, run what-if, and
   redeploy to roll back only the server revision.
3. To remove the foundation, delete the issue-scoped subscription deployment and then the dedicated
   hosting resource group after confirming it contains no shared resources.
4. Verify both principals have no residual assignments at the removed scopes. Preserve the Athena
   context identity only if another approved component has adopted it.
