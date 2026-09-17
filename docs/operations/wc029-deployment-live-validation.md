# WC-029 deployment and live-validation runbook

This runbook is the release gate for governed intelligent monitoring in the existing Athena demo
environment. It is deliberately fail-closed: every mutating action requires an explicit apply
step, an approved recovery action, and evidence that the environment returned to its baseline.

## Fixed deployment scope

| Setting | Value |
| --- | --- |
| Subscription | `a6add389-9978-47ac-ab1e-a09212e321d4` |
| Region | `australiaeast` |
| Runtime resource group | `rg-athena-wc013-live` |
| Workload resource group | `rg-athena-demo-workload` |
| Monitoring resource group | `rg-athena-demo-monitoring` |
| ACR resource group | `rg-athena-platform-dev` |
| Network Watcher resource group | `NetworkWatcherRG` |
| ACR | `athenademoa6add389.azurecr.io` |

Do not deploy WC-029 resources into `rg-athena-demo-dev-*`. Do not create a new deployment path:
this repository currently uses Azure CLI with subscription-scope Bicep, not `azd`.

## Release prerequisites

Do not begin deployment until all items are true:

1. WC-027 report, guidance, enrichment, feed, presentation, and notification changes are merged.
2. WC-028 reconciliation is merged and the exact published manifest version is approved.
3. WC-025 change ingestion is deployed or NSG-change scenarios are explicitly disabled.
4. Final container images are digest-pinned in `.azure/wc013.parameters.json`.
5. Report, guidance, enrichment, and notification signing keys and identities are declared in IaC.
6. Repository CI, release review, security review, and the zero-delete what-if gate are green.
7. An operator has approved the bounded live scenarios and their recovery windows.

## Authoritative deployment roots

Deploy and review each root independently:

- `infra/wc013-live-acceptance/main.bicep`
- `infra/wc024-monitoring-connectivity/main.bicep`
- `infra/wc024-monitoring-foundation/main.bicep`
- `infra/wc025-change-ingestion/main.bicep`
- `infra/wc029-monitoring-prerequisites/main.bicep` (preparation/readiness and explicitly gated guest extensions)

`bootstrap-ampls.bicep` is not a repeatable deployment root. It sets AMPLS access modes to
`Open/Open` and is resource-group scoped. Verify an existing AMPLS read-only. A missing AMPLS may
be created once only through `infra/wc024-monitoring-foundation/bootstrap-ampls.ps1`, after its
bootstrap-state checks pass. Before invoking the wrapper, run and review a separate
`az deployment group what-if` against `bootstrap-ampls.bicep` for every missing approved AMPLS
name; the wrapper may create both scopes. The wrapper itself performs the creates and refuses an
incompatible existing AMPLS, but does not run what-if.

`infra/wc024-monitoring-foundation/set-private-access.ps1` remains a separate, deferred cutover.
Do not run it until private DNS, AMPLS, collector access, Storage, Key Vault, and negative access
tests all pass.

## Required publication boundary

The final deployment must provide separate, least-privilege signing roles for:

- WC-016 incident state;
- WC-025 change evidence;
- WC-026 correlation report publication;
- WC-027 guidance-authority binding;
- WC-027 guidance publication;
- WC-027 enrichment publication; and
- WC-027 notification publication.

Report, guidance, and enrichment assets remain under the existing `incident-assets` trust domain
unless the final merged contracts explicitly say otherwise. A deployment runbook must never choose
a different container after contract freeze.

The presentation identity may read compact signed presentation and incident assets only. It must
not gain Log Analytics, workload Reader, Key Vault, ARM write, or raw evidence access.

## Phase 1: read-only baseline

Record all output in a timestamped evidence directory outside the repository.

```powershell
$SubscriptionId = 'a6add389-9978-47ac-ab1e-a09212e321d4'
$Location = 'australiaeast'
$RuntimeRg = 'rg-athena-wc013-live'
$WorkloadRg = 'rg-athena-demo-workload'
$MonitoringRg = 'rg-athena-demo-monitoring'

az account set --subscription $SubscriptionId
az account show --output json
az group show --name $RuntimeRg --output json
az group show --name $WorkloadRg --output json
az group show --name $MonitoringRg --output json
```

Baseline acceptance:

- all expected demo VMs are running;
- incident reassessment and notification queues have zero active/dead-letter messages;
- the presentation health endpoint returns HTTP 200 from an approved network location;
- the signed v1 active incident feed is readable and contains only known incidents;
- no temporary WC-029 NSG rules, probe changes, or pressure files exist;
- monitoring and runtime Log Analytics workspaces remain separate; and
- the current published manifest, authority, signing-key versions, and container image digests are
  recorded.

Stop if the baseline is already degraded or if a prior scenario was not completely recovered.

## Phase 2: validation and zero-delete what-if

Use a unique immutable deployment name containing the timestamp and commit SHA.

```powershell
$DeploymentName = "wc029-preflight-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))"

az deployment sub validate `
  --subscription $SubscriptionId `
  --location $Location `
  --template-file infra/wc013-live-acceptance/main.bicep `
  --parameters .azure/wc013.parameters.json

az deployment sub what-if `
  --subscription $SubscriptionId `
  --name $DeploymentName `
  --location $Location `
  --template-file infra/wc013-live-acceptance/main.bicep `
  --parameters '@.azure/wc013.parameters.json' `
  --result-format FullResourcePayloads `
  --validation-level Provider `
  --no-prompt true `
  --no-pretty-print `
  --output json
```

Use scope-correct, reviewed parameters for every root:

| Root | Scope | Parameter requirement |
| --- | --- | --- |
| WC-013/WC-016 | Subscription | `.azure/wc013.parameters.json` with final image digests |
| WC-024 connectivity | Subscription | Reviewed copy of `main.example.bicepparam` |
| WC-024 foundation | Subscription | Reviewed environment parameter artifact; examples are not deployable approval |
| WC-025 change ingestion | Subscription | New reviewed parameter artifact containing the exact image, identities, resource allowlist, containers, and versioned signing key |
| WC-029 monitoring prerequisites | Subscription | `infra/wc029-monitoring-prerequisites/main.preparation.bicepparam` with both extension gates false; enabling either requires a separately reviewed immutable copy |

The release cannot proceed while any non-WC-013 root lacks its reviewed immutable parameter
artifact. Run `az deployment sub validate` and `az deployment sub what-if` separately for each
subscription-scope root. Save raw JSON before review. AMPLS bootstrap, when genuinely required,
uses `az deployment group` only through its guarded wrapper.

Evaluate each saved full-resource what-if artifact with the repository CLI. Repeat
`--allow-change` for every exact reviewed `Create` or `Modify` resource ID for that root; omit it
when the only acceptable result is `NoChange`.

Create one collection run ID and one immutable deployment execution ID for both what-if and RBAC
evidence. Prepare one fixed trusted ledger root and one persistent release-ledger directory beneath
it in the protected release workspace. No component in either path may be a POSIX symlink or a
Windows symlink, junction, or other reparse point, including redirected parent directories. Do not
delete, clone, replace, or redirect either path after a preflight consumes evidence.
Containment is checked before the candidate ledger is touched. On Windows, the verifier holds a
non-reparse ledger-directory handle and verifies each record handle before writing, so replacing a
validated directory with a junction cannot redirect a successful consumption.
POSIX ledger reads are nonblocking and no-follow, then require a regular file by `fstat`; FIFOs,
sockets, and devices fail deterministically. Ledger writes and reads share one 64-KiB record bound.
Each write is completed and fsynced in a random staging file inside the secured directory before an
atomic no-overwrite publication. Orphaned empty/partial staging files never reserve a final record;
concurrent writers produce one complete winner, binary descriptors preserve the physical 64-KiB
bound on Windows, and malformed final consumption records are corruption rather than proof of prior
use.
Windows publication is accepted only on a local fixed NTFS volume. It opens the staging record with
`CreateFileW` and `FILE_FLAG_WRITE_THROUGH`, renames the open handle through
`SetFileInformationByHandle(FileRenameInfo)` with `ReplaceIfExists = FALSE`, then securely reopens
the final name to verify the same file identity and exact bytes before flushing the final handle.
Windows directory fsync is unsupported and is not claimed. If any post-rename verification or
durability step fails, the matching final is rolled back and the preflight fails; do not treat it as
consumed.
Keep the persistent `.wc029-ledger.lock` file with the release evidence. Its secure cross-process
lock spans publication, synchronization, rollback, and existing-record comparison. Its fsynced
pending/idle state remains pending after a failed durability barrier even if rollback also fails, so
concurrent or later invocations cannot accept the uncertain final.
Rollback inspects the published name with nonblocking/no-follow semantics before removing only the
matching inode; substituted FIFOs, sockets, and links fail closed without hanging the ledger lock.

The versioned `athena.wc029PreflightManifest.v1` records UTC `collectedAt`/`expiresAt` with a
validity window no longer than 30 minutes, the deployment execution ID, and a reviewed
`deploymentTarget` containing the exact tenant, subscription, and non-empty resource-group boundary
set. It also contains SHA-256 bindings for the raw what-if, RBAC payload, reviewed policy,
deployment, template, parameters, normalized allowlist, and the exact `whatIfRequest` command and
arguments used to obtain the result. Store one byte-equivalent shared manifest in both artifacts and
have a reviewer approve its SHA-256 digest independently of the artifacts. Every what-if resource,
snapshot, potential-change, and allowlist ID must be inside the manifest boundary. The RBAC target
must match its tenant, subscription, and resource group exactly.

The attested request must prove exact `az deployment sub what-if` or
`az deployment group what-if` execution with `FullResourcePayloads`, full `Provider` validation,
the exact separate pair `--no-prompt true`, exact `--no-pretty-print` and `--output json`, and no
query, output transform, exclusion, short-circuit, or unknown option. Omission, `false`, interactive
values, aliases, equals form, and duplicate `--no-prompt` options fail for both subscription and
resource-group commands. JSON mode uses one local `--template-file` and one
`--parameters @file.json`. Reviewed `.bicepparam` mode passes the `.bicepparam` path directly and
omits `--template-file`; do not prefix Bicep parameter files with `@`. Reject every non-empty
diagnostic anywhere in the response; warnings and incomplete-analysis diagnostics require a new
collection rather than operator interpretation.
Option values may not begin with `-`. Deployment names and relative template/parameter paths must
use the exact bounded grammar documented by the verifier; absolute, drive-qualified, URI, dot,
parent, empty, padded, Unicode, or malformed values fail closed.

```powershell
$CollectionRunId = [guid]::NewGuid().ToString()
$DeploymentExecutionId = [guid]::NewGuid().ToString()
$TrustedReleaseLedgerRoot = (Resolve-Path .\evidence).Path
$ReleaseLedgerPath = (Resolve-Path .\evidence\release-ledger).Path
$PreflightJson = & athena-context wc029-preflight what-if `
  .\evidence\wc013.what-if.json `
  --collection-run-id $CollectionRunId `
  --deployment-execution-id $DeploymentExecutionId `
  --release-ledger $ReleaseLedgerPath `
  --trusted-release-ledger-root $TrustedReleaseLedgerRoot `
  --attestation-manifest-digest 'sha256:<reviewed-manifest-digest>' `
  --deployment-digest 'sha256:<reviewed-deployment-digest>' `
  --template-digest 'sha256:<reviewed-template-digest>' `
  --parameters-digest 'sha256:<reviewed-parameters-digest>' `
  --allow-change '/subscriptions/.../providers/Microsoft.App/containerApps/athena-presentation' `
  --format json
$PreflightExitCode = $LASTEXITCODE
$PreflightJson | Set-Content -Encoding utf8 .\evidence\wc013.preflight.json
if ($PreflightExitCode -ne 0) {
  throw "WC-029 what-if preflight blocked deployment with exit code $PreflightExitCode"
}
```

The command reads only the saved JSON file. It does not authenticate to Azure, submit a
deployment, or modify resources. Exit `2` means the policy blocked the saved plan; exit `3` means
the evidence could not be safely evaluated. Either result stops the runbook. Use the default text
format for an operator-readable summary and retain `--format json` output as release evidence.
Each input path is opened once as a bounded binary descriptor; POSIX uses no-follow and nonblocking
flags. The verifier reads at most the configured limit plus one from that descriptor, rejects
non-regular files, overflow, and concurrent metadata changes, and only then performs strict UTF-8
decoding. Do not replace, grow, truncate, symlink, or redirect an evidence path while it is being
consumed.
Every `NoChange` row must retain complete identical `before` and `after` resource objects and no
effective delta. Preserve matching `id`, `name`, `type`, and object-valued `properties`, and retain
only `NoEffect` entries that exactly reconcile with both snapshots; do not reduce unchanged rows to
resource IDs. Every `NoEffect`, including one inside a `Modify`, requires type-exact equal
`before`/`after` values and complete resource snapshots that reconcile at its exact path. Complete
Modify snapshots require matching `id`, `name`, `type`, and object-valued `properties`; partial or
resource-inconsistent snapshots fail closed.

Only exact root aliases `<resource>`, `<resource>.`, and `.` are accepted. Non-root paths use dotted
ASCII identifier components and canonical numeric indexes such as `containers[0]`. Slash,
backslash, tilde escapes, malformed or non-numeric brackets, leading-zero indexes, and any other root
suffix fail closed.

The checked-in WC-029 artifact is preparation-only: it validates the existing baseline and leaves
Dependency Agent and Network Watcher Agent deployment disabled. See
[WC-029 monitoring infrastructure preparation](wc029-monitoring-infrastructure-preparation.md)
for exact prepared scope and blockers. It is not deployment approval.

The gate fails on:

- any `Delete`;
- any `<resource>`, `<resource>.`, or `.` root `Delete`/`Remove` hidden under a non-delete change;
- any planned `Microsoft.Authorization/roleAssignments` or `roleDefinitions` create or modify,
  any PIM assignment/eligibility schedule request, any `Microsoft.ManagedServices` registration
  assignment/definition, any Key Vault `vaults/accessPolicies` resource or
  `properties.accessPolicies`/`properties.enableRbacAuthorization` mutation, any managed-identity
  federated credential, Microsoft Graph app-role/delegated-permission/credential grant, equivalent
  identity-granting resource, or any `Microsoft.Resources/deploymentScripts` mutation, even if its
  resource ID is allowlisted, until post-deployment effects are fully evaluated;
- any Key Vault change to `enabledForTemplateDeployment`, `enabledForDeployment`, or
  `enabledForDiskEncryption` unless the final value is proven as exact boolean `false`.
  Delete/Remove, omitted final values, descendant-only evidence, non-boolean values, and partial or
  conflicting snapshots or overlapping delta observations remain unsupported authorization
  changes. Every exact, ancestor, or descendant observation must independently resolve the
  protected property to `false`; a separate exact value cannot mask an omission;
- any Create, Modify, or Delete of `Microsoft.Resources/deploymentStacks` or
  `Microsoft.Storage/storageAccounts/localUsers`, including stack
  `denySettings`/`actionOnUnmanage` and local-user SSH key, password, shared-key, ACL, or
  `permissionScopes` changes, until their downstream deny/delete/credential/data-permission effects
  are evaluated;
- an unapproved `Create` or `Modify`;
- changes to VNet, subnet, NSG, load balancer, Key Vault, Storage network rules, AMPLS, private DNS,
  or role assignments that are absent from the reviewed change set;
- public Container Apps ingress or public data-plane access;
- Storage shared-key access being enabled;
- broad `Owner`, `Contributor`, or `User Access Administrator` assignment at subscription,
  resource-group, or management-group scope;
- `Reader` at subscription/resource-group/management-group scope except the exact approved evidence
  identity assignment; management-group roles still undergo descendant separation checks; or
- overlap between context, evidence, presentation, collector, publication, and notification
  identities.

Subscription-scope what-if may report a resource group itself with the exact ID
`/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}` and type
`Microsoft.Resources/resourceGroups`. The verifier accepts that provider-less ARM ID only in this
exact shape. Create and Modify still require the reviewed allowlist and meaningful full-resource
evidence; NoChange still requires identical complete snapshots. Every row remains bound to the
reviewed subscription and resource-group boundary.

Every canonical resource ID may appear only once across the combined `changes` and
`potentialChanges` collections. Duplicate exact IDs, case or trailing-slash aliases, and
contradictory rows such as Modify plus NoChange fail before property evaluation. Percent-encoded
resource aliases are invalid, and the complete row set remains bound to the reviewed
`whatIfDigest` and exact request digest.

ARM resource and role-definition IDs, scopes, reviewed allowlist values, and request URLs must
remain ASCII. Do not normalize or transliterate Unicode lookalikes; Kelvin sign `K`, long-s `ſ`, and
percent-encoded Unicode aliases fail the gate.

Property paths are individually limited to 4096 characters and share one aggregate generated-path
work budget. Complete snapshot pairs are indexed once by canonical lowercase path, and every
`NoEffect` lookup/token is charged to a deterministic aggregate budget. Nested delta hierarchies,
wide snapshots, or lookup work that exceeds a bound fail before candidate materialization.
`NoChange` uses one delta traversal and retains explicit root-object and inspectable-array checks.
Protected schemas require object-valued `properties` and protected parents, array-valued access
policy collections, and leaf booleans/strings without descendants. Paths such as
`properties[0]`, `allowSharedKeyAccess.value`, `publicNetworkAccess.value`, or
`ingress.external.value`, mixed exact/array paths, and delta/full-snapshot representation conflicts
are malformed rather than interpreted. The same rule applies to dynamically named protected
descendants that are represented as both objects and arrays, and to repeated or combined dotted
snapshot aliases. Create/Delete/Remove presence claims and parent/child values must agree across
every delta representation regardless of order. Complete snapshots are reconciled through their
canonical path index; wide partial observations and ancestor traversal consume the same bounded
lookup-work budget. Unchanged protected strings still require exact trimmed ASCII spelling and an
allowed enum value.
Partial snapshots recursively register every present protected dynamic path, scalar value, and
container kind without interpreting omitted fields as absent. Present partial values must reconcile
with delta evidence in either order.
Ancestor delta objects are checked against those stored kinds at every depth; `ipRules: {}` and
`ipRules: []` are contradictory even when one appears inside a broader ancestor value.
Unknown unprotected containers in partial snapshots fail closed rather than being discarded. The
permitted `tags` and `systemData` metadata containers must remain flat; nested objects or arrays
below either root are rejected recursively.
All status, change, method, principal/role type, and protected network/access values must be exact
trimmed ASCII tokens before normalization. Do not repair whitespace or Unicode lookalikes manually.

Do not continue by manually ignoring a failed preflight result. Update IaC or the reviewed
allowlist and rerun the gate.

## Phase 3: effective RBAC

Collect evidence for the exact target tenant, subscription, and resource group. All managed-identity
identifiers below are service-principal **object IDs**, never application/client IDs.

```powershell
$TargetResourceGroupId = (
  "/subscriptions/$SubscriptionId/resourceGroups/$WorkloadRg"
)
```

First save the target subscription's Resource Graph `managementGroupAncestorsChain`. Corroborate it
with successful ARM reads for the target subscription, target resource group, and every management
group in the chain, retaining each management group's ARM parent ID. Retain the raw responses
unchanged. In particular, Management Groups Get Subscription API `2020-05-01` reports the tenant in
one literal, case-sensitive `properties.tenant` key. Do not rename it to `Tenant` or `tenantId`, add
an alias, or retain conflicting tenant fields inside the raw response. The verifier derives the
leaf-to-root chain in memory, so no normalized duplicate is needed. Missing nodes, `403`/`404`, a
tenant or subscription mismatch, cycles, disconnected nodes, or Resource Graph/ARM disagreement
block the gate. The policy's
`approvedManagementGroupAncestry` is a separately reviewed copy of the expected path; a changed path
requires new review.

The Resource Graph response must contain no non-null `skipToken` or `$skipToken`, must explicitly
set `resultTruncated` to JSON `false` or the exact transport string `"false"`, and must satisfy
`count == totalRecords == data.Count == 1`.

For every expected managed identity, record Graph object identity and complete transitive
security-group membership:

```powershell
$ServicePrincipal = az rest `
  --method get `
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId?`$select=id,appId" `
  --output json
if ($LASTEXITCODE -ne 0) {
  throw "Failed to resolve service-principal object ID $PrincipalId"
}

$GroupMembership = az rest `
  --method post `
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/getMemberGroups" `
  --body '{"securityEnabledOnly":true}' `
  --headers Content-Type=application/json `
  --output json
if ($LASTEXITCODE -ne 0) {
  throw "Failed to collect security groups for $PrincipalId"
}
```

`getMemberGroups` must use `securityEnabledOnly: true`. A paged
`servicePrincipals/{principalId}/transitiveMemberOf` collection is also accepted when every next
link is exhausted and every group record includes `securityEnabled`. Preserve the request URL,
HTTP status, values, and next link for each Graph response.

The preferred role collection is the ARM role assignments API `2022-04-01` at
`$TargetResourceGroupId`, filtered by the service-principal object ID:

```powershell
$Filter = [uri]::EscapeDataString(
  "atScope() and assignedTo('$PrincipalId')"
)
$NextUrl = (
  "https://management.azure.com$TargetResourceGroupId/" +
  "providers/Microsoft.Authorization/roleAssignments" +
  "?api-version=2022-04-01&`$filter=$Filter"
)
$RoleAssignmentPages = @()
while ($null -ne $NextUrl) {
  $RequestUrl = $NextUrl
  $ResponseJson = az rest --method get --url $RequestUrl --output json
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to collect effective RBAC for $PrincipalId"
  }
  $Response = $ResponseJson | ConvertFrom-Json
  $RoleAssignmentPages += [ordered]@{
    requestUrl = $RequestUrl
    statusCode = 200
    value = @($Response.value)
    nextLink = $Response.nextLink
  }
  $NextUrl = $Response.nextLink
}
```

Do not drop, reorder, or manually splice pages. Each returned `nextLink` must be the following page's
request URL, and the last page wrapper must contain literal `nextLink` set to null. Preserve the
service-issued query key spelling: ARM authorization continuation URLs use exactly one non-empty
`$skipToken`. ARM page wrappers reject `@odata.nextLink`, case aliases, duplicate fields,
whitespace, and empty cursors.

The target-scope query does not cover role assignments on individual workload resources or sibling
resource groups. Collect a second, complete subscription-descendant inventory for the effective
service principal and every security group returned by Graph:

```powershell
$AssignedPrincipalIds = @($PrincipalId) + @($SecurityGroupIds)
$DescendantCollections = @()
foreach ($AssignedPrincipalId in $AssignedPrincipalIds) {
  $DescendantFilter = [uri]::EscapeDataString(
    "principalId eq '$AssignedPrincipalId'"
  )
  $NextUrl = (
    "https://management.azure.com/subscriptions/$SubscriptionId/" +
    "providers/Microsoft.Authorization/roleAssignments" +
    "?api-version=2022-04-01&`$filter=$DescendantFilter"
  )
  $Pages = @()
  while ($null -ne $NextUrl) {
    $RequestUrl = $NextUrl
    $ResponseJson = az rest --method get --url $RequestUrl --output json
    if ($LASTEXITCODE -ne 0) {
      throw "Failed descendant RBAC collection for $AssignedPrincipalId"
    }
    $Response = $ResponseJson | ConvertFrom-Json
    $Pages += [ordered]@{
      requestUrl = $RequestUrl
      statusCode = 200
      value = @($Response.value)
      nextLink = $Response.nextLink
    }
    $NextUrl = $Response.nextLink
  }
  $DescendantCollections += [ordered]@{
    assignedToPrincipalId = $AssignedPrincipalId
    apiVersion = '2022-04-01'
    scope = "/subscriptions/$SubscriptionId"
    filter = "principalId eq '$AssignedPrincipalId'"
    pages = @($Pages)
  }
}
```

The ARM descendant collection set must exactly cover the service-principal object ID and every
complete transitive security-group ID, including empty result sets. If the API repeats root,
management-group, subscription, or target assignments, retain them; the verifier accepts only
corroborated ancestors or subscription descendants and deduplicates the final union.

Also collect complete, unfiltered deny-assignment evidence. One collection uses exact
`$filter=atScope()` at the target resource group to capture every deny effective at the target or an
ancestor. A second collection lists the complete subscription inventory without a principal or
scope filter so All Principals, exclusions, and descendant-scope denies cannot be omitted.

```powershell
$DenyFilter = [uri]::EscapeDataString('atScope()')
$DenyCollectionSpecifications = @(
  [ordered]@{
    collectionType = 'target-and-ancestors'
    apiVersion = '2022-04-01'
    scope = $TargetResourceGroupId
    filter = 'atScope()'
    initialUrl = (
      "https://management.azure.com$TargetResourceGroupId/" +
      "providers/Microsoft.Authorization/denyAssignments" +
      "?api-version=2022-04-01&`$filter=$DenyFilter"
    )
  },
  [ordered]@{
    collectionType = 'subscription-inventory'
    apiVersion = '2022-04-01'
    scope = "/subscriptions/$SubscriptionId"
    filter = $null
    initialUrl = (
      "https://management.azure.com/subscriptions/$SubscriptionId/" +
      "providers/Microsoft.Authorization/denyAssignments" +
      '?api-version=2022-04-01'
    )
  }
)

$DenyCollections = @()
foreach ($Specification in $DenyCollectionSpecifications) {
  $NextUrl = $Specification.initialUrl
  $Pages = @()
  while ($null -ne $NextUrl) {
    $RequestUrl = $NextUrl
    $ResponseJson = az rest --method get --url $RequestUrl --output json
    if ($LASTEXITCODE -ne 0) {
      throw "Failed deny-assignment collection $($Specification.collectionType)"
    }
    $Response = $ResponseJson | ConvertFrom-Json
    $Pages += [ordered]@{
      requestUrl = $RequestUrl
      statusCode = 200
      value = @($Response.value)
      nextLink = $Response.nextLink
    }
    $NextUrl = $Response.nextLink
  }
  $Collection = [ordered]@{
    collectionType = $Specification.collectionType
    apiVersion = $Specification.apiVersion
    scope = $Specification.scope
    pages = @($Pages)
  }
  if ($null -ne $Specification.filter) {
    $Collection['filter'] = $Specification.filter
  }
  $DenyCollections += $Collection
}

$DenyAssignments = [ordered]@{
  method = 'arm'
  collections = @($DenyCollections)
}
```

Retain the same byte-equivalent `$DenyAssignments` object under every principal artifact. The
verifier evaluates the service-principal object ID, every transitive security group, All Principals,
`excludePrincipals`, scope inheritance, and `doNotApplyToChildScopes`. Any applicable deny with a
condition blocks conservatively because the offline gate does not execute Azure ABAC expressions.
Missing collections, incomplete pagination, collection disagreement, or a deny that might invalidate
approved access stops release.
Deny parsing and checks use precomputed ancestry and one canonical access-scope token trie per
principal under a document-wide deterministic work budget. Known list sizes are reserved before
traversal, and large deny/access sets that exceed the bound fail closed instead of performing
repeated deny-by-scope-by-ancestry scans. Each scope token is processed a constant number of times,
avoiding quadratic tuple-prefix copying for deep but otherwise valid ARM scopes. The complete
Graph/RBAC artifact also has document-wide expansion-work and request/page-count limits spanning
hierarchy, service-principal, membership, deny, ancestor, descendant, and guarded CLI evidence.

When the Azure CLI is used instead, retain the exact successful argument list and raw output. The
equivalent scoped command is:

```powershell
az role assignment list `
  --subscription $SubscriptionId `
  --scope $TargetResourceGroupId `
  --assignee-object-id $PrincipalId `
  --include-inherited `
  --include-groups `
  --fill-principal-name false `
  --fill-role-definition-name true `
  --output json
```

Do not use `--assignee`, omit either include flag, combine `--all` with `--scope`, add `--role`,
`--resource-group`, or `--query`, use equals-form duplicate options, or transform the JSON output.
Option names must be exact lowercase ASCII and fixed values such as `--output json` are
case-sensitive. Decoded request-URL query keys must use the exact spelling defined by their
endpoint and remain unique after percent decoding. ARM authorization continuations require exactly
one non-empty `$skipToken`; Graph continuations require exactly one non-empty `$skiptoken` and
reject `$skip`. ARM page wrappers use literal `nextLink`; Graph page wrappers use literal
`@odata.nextLink`. Cross-endpoint aliases, duplicates, whitespace, ambiguous cursor fields, and case
variants fail closed. Single-dash-prefixed values are rejected rather than treated as positional
data.
The verifier then canonicalizes each validated request from its scheme, host, decoded
case-normalized path, and decoded sorted endpoint query. A repeated canonical request or decoded
cursor fails even when percent encoding, path casing, or query ordering differs.

The CLI equivalent for the separate subscription-descendant inventory is:

```powershell
az role assignment list `
  --subscription $SubscriptionId `
  --assignee-object-id $PrincipalId `
  --include-groups `
  --all `
  --output json
```

This command must not include `--scope`; its output is unioned with the scoped ancestor/target
collection.

The verifier derives direct and group-derived effective assignments from the attested hierarchy,
Graph membership, and ARM/CLI evidence. Direct rows must assign the service-principal object ID.
Group rows must name a security group present in the complete Graph set. The separately reviewed
policy uses `approvedAssignments`; never populate it by copying the observed output. Preserve
`condition`, `conditionVersion`, canonical `roleDefinitionId`, `assignedPrincipalId`,
`assignedPrincipalType`, and `effectivePrincipalId`.
Build one tenant-wide type view from the complete artifact: every effective ID is a service
principal, every accepted membership ID is a group, and each assignment or deny
principal/exclusion retains its supplied type. Any GUID claimed with different types across policy,
identity, membership, role-assignment, deny, collection, or page evidence requires recollection.
Retain every typed `transitiveMemberOf` object: the verifier registers its type before excluding
non-group objects from the accepted security-group set.
The all-zero All Principals GUID is rejected directly from every workload-identity field and is also
pre-registered as `SystemDefined` before any reviewed or observed principal claim. It cannot be
used as an effective service principal, group, assignment principal, or client ID when deny
inventories are empty.
Retain every ARM and guarded Azure CLI role-assignment `id` and `type` unchanged. The verifier
permits the same group-derived ID under multiple effective principals only when the canonical
identity-bearing body is identical across methods and collections. Non-identity display metadata
may vary, but changing principal, role, scope, type, or condition under one ID invalidates the
evidence.

The RBAC envelope uses the same `$CollectionRunId`, bounded timestamps, and SHA-256 bindings for the
reviewed policy, target, hierarchy, membership, both role-assignment collections, and both complete
deny-assignment collections. Its embedded manifest must be byte-equivalent to the what-if manifest
and use the same `$DeploymentExecutionId`, reviewed `deploymentTarget`, and release ledger. The
independently reviewed manifest digest must not be regenerated after evidence changes. Each
separation rule must include the reviewed IDs in
`forbiddenRoleDefinitionIds` as well as their display names:

```powershell
$RbacPreflightJson = & athena-context wc029-preflight rbac `
  .\evidence\role-assignments.json `
  --policy .\evidence\reviewed-rbac-policy.json `
  --collection-run-id $CollectionRunId `
  --deployment-execution-id $DeploymentExecutionId `
  --release-ledger $ReleaseLedgerPath `
  --trusted-release-ledger-root $TrustedReleaseLedgerRoot `
  --attestation-manifest-digest 'sha256:<same-reviewed-manifest-digest>' `
  --format json
$RbacPreflightExitCode = $LASTEXITCODE
$RbacPreflightJson | Set-Content -Encoding utf8 .\evidence\rbac.preflight.json
if ($RbacPreflightExitCode -ne 0) {
  throw "WC-029 RBAC preflight blocked deployment with exit code $RbacPreflightExitCode"
}
```

Separation rules are indexed by effective principal and role before assignment evaluation. The
verifier records each identical assignment violation once, enforces the 256-unique-violation limit
while generating findings, and charges rule-token and scope-match work to a deterministic budget
instead of materializing assignment-by-rule duplicates. Scope-prefix minimization is a sorted
segment-aware linear pass rather than an all-pairs comparison.

Each artifact kind can be consumed once for the deployment execution. A repeated what-if or RBAC
evaluation, or an attempt to use a different manifest with the same execution ID, exits `3` even
when `expiresAt` has not elapsed. The ledger also binds each `collectionRunId` to exactly one
deployment execution and manifest, so a new execution ID cannot make the same collected evidence
reusable. Retain the collection binding, deployment binding, and both consumption records with the
release evidence.

Required separation:

- context identity: no workload Reader and no Log Analytics Reader;
- evidence identity: workload Reader only at the approved workload scope;
- monitoring collector: exact monitoring query/data roles and governed resource scopes;
- presentation identity: Blob Data Reader for presentation/incident assets and ACR pull only;
- incident/enrichment publishers: exact Blob contributor, queue, and Key Vault crypto roles only;
- notification dispatcher: exact v2 queue/table/Logic App rights only; and
- no generic Contributor assignment for a runtime identity.

## Phase 4: deploy

Deployment is an explicit operator action. The approved command, commit SHA, image digests,
deployment name, deployment execution ID, what-if digest, ledger binding, both consumption records,
and operator identity must be captured before execution. Do not deploy unless both one-time
preflight consumptions exist for the same shared manifest.

After deployment:

1. record deployment outputs and provisioning state;
2. repeat RBAC checks;
3. verify all Container Apps revisions use the reviewed image digests;
4. verify Storage shared-key and public access remain disabled where required;
5. verify monitoring/runtime workspace isolation;
6. verify exact key versions and trusted fingerprints; and
7. run signed feed/report/guidance/enrichment readback before any fault injection.

## Phase 5: bounded live scenarios

Every scenario follows the same mutation lifecycle:

1. **Plan**: capture target, baseline, expected signal, abort threshold, and recovery command.
2. **Apply**: perform one bounded mutation.
3. **Observe**: capture the evidence supported by that scenario. Incident-producing scenarios
   include guidance/feed/notification evidence; correlation-only scenarios stop at verified
   monitoring, change, correlation, and recovery evidence.
4. **Recover**: restore only the changed setting/resource.
5. **Verify**: prove healthy state and no residual mutation. Incident-producing scenarios also
   require a resolved occurrence and queue drain.

Never run two fault scenarios concurrently.

### Disk-capacity pressure

- Prefer an agreed non-critical demo VM.
- Record current free bytes and abort unless the recovery floor can be maintained.
- Create one capped temporary file beneath `/tmp/athena-wc029/`.
- Keep at least 4 GiB free and never fill the filesystem.
- Delete the exact file during recovery.

Expected evidence: AMA/VM Insights pressure, a bounded WC-026 `guestResourcePressure` report, and
explicit recovery observations. This is correlation-only until a signed incident producer for disk
pressure is deployed; do not claim WC-027 guidance or notifications from WC-016 alone.

### VM failure

- Stop/start one approved low-blast-radius VM.
- Do not delete or deallocate unrelated resources.
- Record the original power state and restore it exactly.

For a non-WC-016 target such as `athena-hackathon-client-01`, acceptance is monitoring and
correlation only. A full active/resolved incident and guidance test must use a resource/scenario
explicitly supported by the deployed WC-016 producer.

### Web-tier failure

- Stop only `athena-hackathon-web-01`.
- Keep the remaining web instances running.
- Restore the VM and verify the original backend health.

Expected evidence: degraded web-role impact, active and resolved signed assets, and active/resolved
notification behavior.

### Backend or load-balancer degradation

Preferred mutation: stop only `athena-hackathon-mid-01`, leaving `mid-02` healthy.

An invalid load-balancer probe path may be used only with separate operator approval. Capture the
complete original probe configuration and restore `/health` on port `8001`.

Expected evidence must distinguish partial backend degradation from complete VIP/path loss.
Partial backend degradation is correlation-only unless the deployed incident producer explicitly
supports that transition. A full signed incident test uses the supported load-balancer VIP failure
scenario.

### NSG connectivity loss

Requires deployed WC-025 change ingestion.

Create one temporary rule on `athena-hackathon-nsg-middle`:

| Field | Value |
| --- | --- |
| Name | `athena-wc029-temp-deny-web-to-middle` |
| Priority | `200` |
| Direction | `Inbound` |
| Source | `10.42.3.0/24` |
| Destination | `10.42.4.0/24` |
| Destination port | `8001` |
| Access | `Deny` |

Abort if priority `200` is already occupied or the captured NSG no longer matches the baseline.
Recovery removes only this exact temporary rule.

Expected evidence: exact change artifact, path-bound flow/Connection Monitor evidence,
`networkSecurityChange` correlation, and recovery after rule removal. Guidance and notifications
are required only after a signed NSG-connectivity incident producer is deployed; the current WC-016
scenario set does not provide that occurrence.

## Signed evidence acceptance

For incident-producing scenarios, verify and retain:

- exact IncidentState occurrence and attestation;
- exact manifest version and clause citations;
- verified WC-026 report and publication attestation;
- deterministic WC-027 guidance and attestation;
- enrichment manifest and attestation;
- v2 feed entry/pointer/index attestations;
- active and resolved notification provenance;
- `noAutoRemediation=true` at every layer;
- queue/dead-letter counts returning to zero; and
- baseline-versus-recovered resource configuration.

For correlation-only scenarios, retain the exact monitoring/change artifacts, verified WC-026
report, report publication attestation, bounded omission metadata, and recovery evidence. Absence
of a supported IncidentState occurrence is expected and must not be replaced with a synthetic or
caller-asserted occurrence.

The scenario fails if any asset requires a mutable/latest read, an untrusted key ID, a draft
manifest, missing recovery evidence, or a renderer-generated instruction.

## Final acceptance and cleanup

WC-029 is complete only when:

1. all reviewed deployments succeeded with no unintended delete or public exposure;
2. effective RBAC matches the separation policy;
3. every enabled scenario met its declared incident-producing or correlation-only acceptance
   criteria;
4. each incident-producing scenario rendered verified guidance from closed templates;
5. each incident-producing scenario used Notification v2 provenance and idempotency for Teams;
6. all temporary files, rules, probe changes, and VM state changes were recovered;
7. active/dead-letter queues are empty;
8. monitoring/runtime isolation remains intact; and
9. the evidence bundle records commit, deployment names, image digests, manifest version, key
   versions, report/guidance/enrichment digests, and operator approval.

If any recovery check fails, stop the release, preserve evidence, and notify the owner because
operator intervention is then required.
