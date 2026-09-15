# WC-029 offline preflight verifier

The production `athena-context wc029-preflight` command evaluates saved Azure deployment what-if
and role-assignment JSON without authenticating to Azure or changing resources. It delegates to
the existing bounded `athena_context.wc029_preflight` validators; the wrapper does not implement a
second policy path.

## ARM what-if

The default policy permits only `NoChange`. Every expected create/modify resource must be listed
explicitly; deletes and unsafe public/shared-key settings remain forbidden.

Generate input with `az deployment ... what-if --result-format FullResourcePayloads`. A
resource-ID-only or otherwise uninspectable change fails closed even when its resource ID is
allowlisted. New Storage accounts and Key Vaults must explicitly declare private network defaults;
Storage accounts must also disable Shared Key and public blob access. Omitting those parent-resource
properties is treated as unsafe; child resources such as containers and keys are evaluated by
their own payloads. Blob containers must explicitly use `publicAccess: None`.
Storage or Key Vault network ACL changes must include a complete after-state proving
`publicNetworkAccess: Disabled` and `networkAcls.defaultAction: Deny`; deleting the ACL parent or
changing any higher protected-property ancestor without every protected descendant's explicit safe
after-value, or providing only a partial child delta, fails closed.
Container Apps network values are type checked independently: ingress `external` must be boolean
`false`, managed-environment `vnetConfiguration.internal` must be boolean `true`, and
`publicNetworkAccess` must be `Disabled`. Unknown values and partial parent deltas fail closed.

The attested artifact also contains `whatIfRequest`, the exact Azure CLI command token array and
argument array used to obtain the result. The release gate accepts only `az deployment sub what-if`
or `az deployment group what-if` with one exact subscription, name,
the exact separate pair `--no-prompt true`, `--no-pretty-print`, exact JSON output,
`FullResourcePayloads`, and full `Provider` validation. Omission, `false`, interactive values,
aliases, equals form, and duplicate `--no-prompt` options fail for both subscription and
resource-group commands. JSON mode requires one local template file and one `@parameters.json`
file. A separately exact `.bicepparam` mode passes one direct `.bicepparam` path and omits
`--template-file`, because the Bicep parameter artifact declares its template with `using`.
Subscription requests require a canonical location; group requests require one resource group from
the reviewed deployment boundary. Unknown or duplicate options, equals-form options, case or
Unicode aliases, `--query`, output transforms, excluded change types, weaker validation, and
short-circuit/create commands fail closed. Values beginning with either `-` are never accepted as
option values. Deployment names use only the bounded Azure deployment-name character set. Template,
JSON parameter, and `.bicepparam` values are relative ASCII file paths with no URI, drive, absolute,
empty, dot, or parent segment. The shared manifest binds `whatIfRequestDigest`, so a valid-looking
request cannot be substituted after review.

ARM `Ignore` and `Deploy` results fail closed because they do not provide a predictable reviewed
final state. Any non-empty `potentialChanges` collection also blocks the gate because those
resources were not resolved into the reviewed `changes` collection.
Any non-empty `diagnostics` or `validationDiagnostics` value anywhere in the response makes the
analysis incomplete for release and fails closed. Planned creates or modifies under any
`Microsoft.Authorization` or `Microsoft.ManagedServices` resource family also block, including PIM
assignment/eligibility schedule requests and Lighthouse registration assignments/definitions.
`Microsoft.Resources/deploymentScripts` and descendants block as unsupported imperative execution.
These changes remain blocked even when allowlisted because the gate does not yet derive their full
post-deployment authorization or execution effects.
`NoChange` is accepted only with complete, object-valued, type-exact, structurally identical
`before` and `after` snapshots and no effective delta. Each snapshot must contain matching `id`,
`name`, `type`, and object-valued `properties`. Every `NoEffect` entry must contain both `before`
and `after`, those values must be type-exact and equal, and the path and values must reconcile with
complete resource-level `before` and `after` snapshots. Complete Modify snapshots require matching
`id`, `name`, `type`, and object-valued `properties`; a partial or type-inconsistent snapshot cannot
reclassify the resource or supply protected-state evidence. Missing, changed, or
snapshot-conflicting `NoEffect` evidence is malformed rather than ignored.
Every `NoEffect` path and value in a `NoChange` row is resolved against both root snapshots;
missing, duplicate, contradictory, nested type-changing, or out-of-snapshot entries fail. Nested or
root deletion/removal, conflicting snapshots, or any non-empty effective property change makes the
artifact malformed rather than silently safe.
Documents that mix root-level and `properties` result envelopes are rejected rather than choosing
one representation. Empty delta child arrays are not inspectable evidence, and dotted JSON property
names cannot impersonate structurally nested protected settings. Property paths use an allowlisted
grammar: the only root aliases are exact `<resource>`, `<resource>.`, and `.`; non-root paths use
dotted ASCII identifier components and canonical numeric indexes such as `containers[0]`. Forward
slashes, backslashes, tildes/JSON-pointer escapes, non-exact root suffixes, empty components,
non-numeric or malformed brackets, and leading-zero indexes are rejected. Unicode characters whose
case fold or lowercase form is ASCII-equivalent are rejected in JSON keys and textual property
paths. Each canonical path is limited to 4096 characters, and one evaluation has bounded aggregate
generated-path count and character work. Nested path accumulation and wide generated snapshots fail
deterministically before an unbounded candidate set is materialized. Complete snapshot pairs build
one canonical lowercase-key index per snapshot; all `NoEffect` paths use constant-time indexed
lookups, and index/token work is charged to the same deterministic evaluation budget. The
`NoChange` path is walked once; its previous second delta traversal is removed while retaining root
object and inspectable-array validation.
Status, change type, property-change type, role/principal type, collection method, resource type,
public network access, network default action, public access, and every other protected enum or
security decision are normalized only after the raw token is proven trimmed ASCII. Surrounding
whitespace, long-s, Kelvin sign, and other Unicode/lookalike forms are malformed rather than aliases.
Every `Modify` must contain a meaningful effective property delta. `NoEffect` entries, empty or
missing deltas backed only by an `after` payload, resource metadata such as `id`, `name`, or `type`,
and leaves whose `before` and `after` values are unchanged do not make a change inspectable. When
both complete resource `before` and `after` snapshots are present, the verifier derives the actual
changed leaves, ignores unchanged metadata, and applies the same protected-property checks to that
derived delta.
`<resource>`, `<resource>.`, and `.` are the same canonical resource root. A root `Delete` or
`Remove` under any non-`Delete` top-level change is still a deletion and always blocks, even when a
separate `after` snapshot appears safe. A root `after` value must be an object, and root deltas are
treated as ancestors of every protected property.

Production what-if evidence is an attested envelope containing `whatIf` and the versioned
`athena.wc029PreflightManifest.v1` manifest. The manifest contains `collectionRunId`, an immutable
`deploymentExecutionId`, `collectedAt`, `expiresAt`, a reviewed `deploymentTarget`, and SHA-256
bindings for the what-if result, RBAC evidence, policy, deployment, template, parameters, and
normalized `--allow-change` list, plus the exact `whatIfRequest`. `deploymentTarget` contains the
exact tenant, subscription, and non-empty set of resource-group boundaries. Every what-if resource
ID, snapshot ID, potential-change ID, and allowlist ID must belong to that subscription and one of
those resource groups. The RBAC target tenant, subscription, and resource group must match the same
manifest exactly.

The validity window must be positive and no longer than 30 minutes; a collection time more than five
minutes in the future fails deterministically. Time validity alone is not replay protection. Both
artifacts must embed the same byte-equivalent manifest and use the same independently reviewed
manifest digest, `collectionRunId`, and `deploymentExecutionId`.

The guarded CLI also requires a fixed, persistent `--trusted-release-ledger-root` controlled by the
release workflow and a `--release-ledger` directory beneath it. Every existing component from the
filesystem root through both paths must be a real directory: POSIX symlinks and Windows symlinks,
junctions, and all other reparse points are rejected, including redirected parents. On platforms
with directory-relative and no-follow support, the verifier securely opens each directory component
and performs create-only/read operations relative to the ledger handle. Windows retains a
non-reparse ledger-directory handle and validates every newly opened record handle against that
directory before writing or reading, so a junction swap after path validation fails closed. Lexical
trusted-root containment is checked before any candidate-ledger filesystem access. Existing records
must be regular, valid UTF-8 JSON; decoding or schema failure is reported deterministically with
exit `3`. POSIX reads use `O_NONBLOCK|O_NOFOLLOW`, then `fstat` the opened descriptor and reject
FIFO, socket, device, or any non-regular entry before reading. Writer and reader use the same
64-KiB serialized-record limit, checked before create, so a successful first record is always
readable by the paired artifact.

The ledger creates one immutable deployment binding and one create-only consumption record
for each artifact kind. It also creates an immutable collection-run binding so one
`collectionRunId` cannot be wrapped in a new manifest or rebound to a second deployment execution.
The first valid what-if and first valid RBAC evaluation may consume the shared manifest; any repeated
use of either kind, a different manifest or deployment target for the same execution, a reused
collection run under another execution, a missing ledger, or a symlink ledger fails with exit `3`.
Do not delete, clone, replace, or redirect the ledger to make evidence reusable.

Security-bound ARM resource and role-definition IDs, scopes, allowlist values, and request URLs must
be ASCII. Unicode aliases such as Kelvin sign `K` or long-s `ſ` are rejected before normalization,
including percent-encoded URL forms. The allowlist binding records both raw and canonical ASCII
identifiers, so reviewed manifest digests preserve spelling distinctions rather than hashing only
case-folded values.

```powershell
athena-context wc029-preflight what-if .\evidence\what-if.json `
  --collection-run-id '<collection-run-guid>' `
  --deployment-execution-id '<deployment-execution-guid>' `
  --release-ledger .\evidence\release-ledger `
  --trusted-release-ledger-root .\evidence `
  --attestation-manifest-digest 'sha256:<reviewed-manifest-digest>' `
  --deployment-digest 'sha256:<deployment-digest>' `
  --template-digest 'sha256:<template-digest>' `
  --parameters-digest 'sha256:<parameters-digest>' `
  --allow-change '/subscriptions/.../providers/Microsoft.App/containerApps/athena-presentation'
```

Exit codes:

- `0`: safe;
- `2`: policy violations; and
- `3`: malformed, empty, unreadable, or oversized input.

The default `text` format is intended for an operator terminal. Use `--format json` for a compact,
key-sorted machine-readable result. Violations are ordered by code, normalized subject, and detail
in both formats so repeated evaluation of the same saved inputs is byte-stable. Missing command-line
arguments are rejected by the parser with exit code `2` before any input is evaluated.

The legacy module entry point remains available for existing automation and continues to default to
JSON:

```powershell
python -m athena_context.wc029_preflight what-if .\evidence\what-if.json
```

## RBAC

```powershell
athena-context wc029-preflight rbac .\evidence\role-assignments.json `
  --policy .\evidence\reviewed-rbac-policy.json `
  --collection-run-id '<same-collection-run-guid>' `
  --deployment-execution-id '<same-deployment-execution-guid>' `
  --release-ledger .\evidence\release-ledger `
  --trusted-release-ledger-root .\evidence `
  --attestation-manifest-digest 'sha256:<same-reviewed-manifest-digest>'
```

The production wrapper requires `--policy`, a reviewed target tenant/subscription/resource group,
a non-empty `expectedPrincipalIds` array, separately reviewed `approvedAssignments`, and one
non-vacuous `separationRules` entry for every expected principal. `expectedAssignments` is rejected
in guarded mode: an observed inventory cannot prove its own completeness.

Guarded evidence contains three raw artifact families:

1. `target` identifies the tenant, subscription, and resource-group scope.
2. `hierarchy` contains the subscription's Resource Graph
   `managementGroupAncestorsChain` plus ARM subscription, resource-group, and management-group
   parent/path responses.
3. `principals` contains, for every managed-identity service-principal object ID:
   - the Graph service-principal response with both object `id` and client `appId`;
   - a complete security-group membership result from
     `servicePrincipals/{id}/getMemberGroups` with `securityEnabledOnly: true`, or every page of
     `transitiveMemberOf`; and
   - every page of the ARM role assignments API `2022-04-01` query at the target scope using
     `atScope() and assignedTo('<service-principal-object-id>')`; and
   - a separate complete subscription-descendant inventory for the effective principal and every
     transitive security group, including individual workload resources and sibling resource
     groups.

Complete subscription responses may repeat root, corroborated management-group, subscription, or
target assignments. Those rows are accepted only inside the reviewed boundary and deduplicated
against the target/ancestor collection.

Every page records its request URL, HTTP status, values, and returned next link. The next link must
match the following page exactly and the final page must have no next link. Missing pages, non-200
responses including `403`/`404`, repeated pages, mixed subscriptions or tenants, and malformed
request URLs fail closed.

Initial Graph requests must use the unfiltered service-principal membership endpoint; a cursor or
filter on the first page is rejected. Initial ARM role-assignment requests allow only
`api-version=2022-04-01` and the exact `atScope() and assignedTo(...)` filter. Continuations must stay
on the same host, endpoint, target scope, and principal and may add only the service-issued cursor.
Cross-tenant parameters and caller-added selection filters are rejected. Decoded query keys must use
the exact endpoint spelling and be unique after percent decoding. ARM Role Assignments API
`2022-04-01` continuations use `$skipToken`; Graph continuations use exact `$skiptoken` where
documented. Exact duplicates, percent-decoded duplicates, casefold collisions, aliases, and other
case variants fail before query comparison.

The Resource Graph response must explicitly report `resultTruncated` as JSON `false` or the exact
transport string `"false"`, no non-null `skipToken` or `$skipToken`, and
`count == totalRecords == len(data) == 1`. Other strings, numbers, null, and missing values fail.

The retained Management Groups Get Subscription API `2020-05-01` response must keep its documented
raw `properties.tenant` field. The verifier validates it directly against the reviewed target tenant
and derives hierarchy metadata in memory; a caller-renamed `properties.tenantId` is not accepted as
the raw response. Because the complete raw RBAC payload is manifest-bound, no unbound normalized
copy is used as provenance.

The verifier derives the management-group path from ARM parent links, rejects missing, disconnected,
or cyclic nodes, and requires the leaf-to-root ARM path to exactly match Resource Graph and the
policy's reviewed `approvedManagementGroupAncestry`. A hierarchy change therefore requires a new
human review rather than silently changing assignment inheritance.
Separation scope matching uses that validated chain in both directions. A forbidden management-group
prefix matches child management groups in the chain and every descendant subscription,
resource-group, and resource scope. An assignment at a parent management group likewise matches a
forbidden child-management-group or workload prefix only when both are connected by the reviewed
ancestry. Unreviewed management groups are never inferred as ancestors.

ARM supplies the assigned principal. The normalized policy and output preserve:

- `assignedPrincipalId`;
- `assignedPrincipalType`;
- `effectivePrincipalId`; and
- role ID, scope, condition, and condition version.

A direct assignment requires `assignedPrincipalType: ServicePrincipal` and equality between the
assigned and effective object IDs. A group-derived assignment requires
`assignedPrincipalType: Group`, a distinct group object ID, and that ID's presence in the complete
Graph transitive security-group set. The service-principal object ID must match Graph `id` and must
not be the Graph `appId` client ID. Graph/ARM disagreement fails closed.

The verifier derives and deduplicates the union of target/ancestor assignments and the complete
subscription-descendant inventory, then compares it with separately reviewed
`approvedAssignments`. The legacy module entry point keeps its historical optional-policy and
list-input behavior for compatibility and must not be used as the guarded deployment gate.

The RBAC envelope uses the same bounded timestamps, `collectionRunId`, `deploymentExecutionId`,
`deploymentTarget`, independently reviewed manifest digest, and trusted release ledger as the
what-if envelope. The manifest binds the reviewed policy and the complete RBAC payload, including
target, hierarchy, service-principal and membership inputs, and ancestor/descendant assignment
collections. Mutating evidence and regenerating only its embedded digests fails against the
externally supplied manifest digest. A second RBAC evaluation for the same execution fails even
while the manifest remains within its validity window.

CLI-equivalent evidence requires two exact collections. The target/ancestor command uses
`--scope`, `--include-inherited`, and `--include-groups` without `--all`. The subscription-descendant
command uses `--all`, `--assignee-object-id`, and `--include-groups` without `--scope`. Selection or
output transforms such as `--role`, `--resource-group`, or `--query`, equals-form overrides,
duplicate flags, and alternate assignee forms fail closed. Every option token is exact lowercase
ASCII, and fixed values such as `--output json`, principal IDs, and boolean fill values are
case-sensitive; Unicode/casefold aliases, surrounding whitespace, fuzzy option spelling, and
single-dash-prefixed values are invalid.

The policy is bounded JSON:

```json
{
  "target": {
    "tenantId": "00000000-0000-0000-0000-000000000100",
    "subscriptionId": "00000000-0000-0000-0000-000000000000",
    "resourceGroupId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload",
    "approvedManagementGroupAncestry": [
      "/providers/Microsoft.Management/managementGroups/workloads",
      "/providers/Microsoft.Management/managementGroups/tenant-root"
    ]
  },
  "expectedPrincipalIds": [
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002"
  ],
  "approvedAssignments": [
    {
      "assignedPrincipalId": "00000000-0000-0000-0000-000000000001",
      "assignedPrincipalType": "ServicePrincipal",
      "effectivePrincipalId": "00000000-0000-0000-0000-000000000001",
      "roleDefinitionName": "Reader",
      "roleDefinitionId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload"
    },
    {
      "assignedPrincipalId": "00000000-0000-0000-0000-000000000002",
      "assignedPrincipalType": "ServicePrincipal",
      "effectivePrincipalId": "00000000-0000-0000-0000-000000000002",
      "roleDefinitionName": "Storage Blob Data Reader",
      "roleDefinitionId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload",
      "condition": "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'evidence'",
      "conditionVersion": "2.0"
    }
  ],
  "allowedBroadAssignments": [
    {
      "assignedPrincipalId": "00000000-0000-0000-0000-000000000001",
      "assignedPrincipalType": "ServicePrincipal",
      "effectivePrincipalId": "00000000-0000-0000-0000-000000000001",
      "roleDefinitionName": "Reader",
      "roleDefinitionId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload"
    }
  ],
  "separationRules": [
    {
      "principalId": "00000000-0000-0000-0000-000000000001",
      "forbiddenRoleNames": ["Owner", "Contributor"],
      "forbiddenRoleDefinitionIds": [
        "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
      ],
      "forbiddenScopePrefixes": [
        "/subscriptions/00000000-0000-0000-0000-000000000000"
      ]
    },
    {
      "principalId": "00000000-0000-0000-0000-000000000002",
      "forbiddenRoleNames": ["Reader", "Log Analytics Reader"],
      "forbiddenRoleDefinitionIds": [
        "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
        "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/73c42c96-874c-492b-b04d-ab87d138a893"
      ],
      "forbiddenScopePrefixes": [
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload"
      ]
    }
  ]
}
```

Broad `Owner`, `Contributor`, `Reader`, and `User Access Administrator` assignments at subscription
resource-group, or management-group scope fail unless the exact principal, role, and scope tuple is
reviewed in `allowedBroadAssignments`. `Role Based Access Control Administrator` is also treated as
privileged. The verifier recognizes the official built-in role definition IDs as well as display
names. Separation rules remain enforced independently. Management-group assignments are considered
ancestors only when the assigned scope appears in the corroborated, reviewed hierarchy artifact.

JSON object keys must be unique and cannot collide under case folding. Scope values are normalized
without trailing slashes and structurally validated before allowance, broad-scope, and separation
evaluation, so alternate or noncanonical ARM scope spellings cannot bypass the gate. Role definition
IDs are likewise structurally checked before their built-in privilege is evaluated. Paginated
evidence is accepted only when every next link is exhausted without a gap. Allowances that supply
both a role name and role ID must agree and must be present in `approvedAssignments`.
Authorization-affecting `condition` and `conditionVersion` fields must be supplied together and are
included in exact approval and allowance matching. Approved assignments and broad-assignment
allowances require both `roleDefinitionName` and a canonical `roleDefinitionId`, plus
`assignedPrincipalId`, `assignedPrincipalType`, and `effectivePrincipalId`.
Recognized built-in role names must agree with their official IDs; name-only, ID-only, or spoofed-ID
entries fail closed. Every production separation rule also requires reviewed
`forbiddenRoleDefinitionIds`; matching either a forbidden name or ID blocks the assignment, so a
false display name cannot bypass separation. Oversized integer literals and other parser failures
are reported as malformed input with exit code `3`. JSON decimals are parsed into bounded exact
values and hashed from their lossless `Decimal.as_tuple()` representation without active-context
rounding. Integer and decimal representation classes remain distinct, so wide decimals and `1`
versus `1.0` cannot collapse before `NoEffect` or manifest-digest comparison. Every JSON key and
string must round-trip through strict UTF-8; escaped lone surrogates and any defensive encoding
failure produce a bounded `PreflightInputError`/exit `3`, never a traceback.

Equivalent separation rules are rejected before evaluation. Identical violations from distinct
non-equivalent rules are emitted once, no result may contain more than 256 unique violations, and
JSON or text output is bounded to 1 MiB.

The verifier is an offline review gate, not proof of Azure deployment success. It performs no Azure
network call, but the guarded wrapper writes create-only local release-ledger records. Preserve the
raw Resource Graph, ARM, and Graph responses or the explicitly attested CLI-equivalent collection,
exact repeated `--allow-change` values, reviewed policy, shared manifest, trusted ledger root,
ledger directory, and machine-readable verifier output beside the release evidence. Run both the
what-if and RBAC checks; a successful result from one does not waive the other.
