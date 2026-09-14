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

ARM `Ignore` and `Deploy` results fail closed because they do not provide a predictable reviewed
final state. Any non-empty `potentialChanges` collection also blocks the gate because those
resources were not resolved into the reviewed `changes` collection.
Documents that mix root-level and `properties` result envelopes are rejected rather than choosing
one representation. Empty delta child arrays are not inspectable evidence, and dotted JSON property
names cannot impersonate structurally nested protected settings. Unicode characters whose case fold
or lowercase form is ASCII-equivalent are rejected in JSON keys and textual property paths.

```powershell
athena-context wc029-preflight what-if .\evidence\what-if.json `
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
  --policy .\evidence\reviewed-rbac-policy.json
```

The production wrapper requires `--policy`, a non-empty `expectedPrincipalIds` array, an exact
reviewed `expectedAssignments` inventory, and one non-vacuous `separationRules` entry for every
expected principal. Every rule must name at least one forbidden role and one forbidden scope prefix.
The saved role-assignment evidence must be non-empty and must match the normalized expected
assignment inventory exactly; policy entries or assignments for an unexpected principal fail
closed. This prevents a partial export or an unrelated syntactically valid rule from producing a
safe result. The legacy module entry point keeps its historical optional-policy behavior for
compatibility and must not be used as the guarded deployment gate without a reviewed policy.

The policy is bounded JSON:

```json
{
  "expectedPrincipalIds": [
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002"
  ],
  "expectedAssignments": [
    {
      "principalId": "00000000-0000-0000-0000-000000000001",
      "roleDefinitionName": "Reader",
      "roleDefinitionId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload"
    },
    {
      "principalId": "00000000-0000-0000-0000-000000000002",
      "roleDefinitionName": "Storage Blob Data Reader",
      "roleDefinitionId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload/providers/Microsoft.Storage/storageAccounts/athena/blobServices/default/containers/evidence",
      "condition": "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'evidence'",
      "conditionVersion": "2.0"
    }
  ],
  "allowedBroadAssignments": [
    {
      "principalId": "00000000-0000-0000-0000-000000000001",
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
names. Separation rules remain enforced independently.

JSON object keys must be unique and cannot collide under case folding. Scope values are normalized
without trailing slashes and structurally validated before allowance, broad-scope, and separation
evaluation, so alternate or noncanonical ARM scope spellings cannot bypass the gate. Role definition
IDs are likewise structurally checked before their built-in privilege is evaluated. Paginated
object-form evidence containing a continuation link is rejected as incomplete. Allowances that
supply both a role name and role ID must agree and must be present in `expectedAssignments`.
Authorization-affecting `condition` and `conditionVersion` fields must be supplied together and are
included in exact inventory and allowance matching. Production evidence, expected assignments, and
broad-assignment allowances require both `roleDefinitionName` and a canonical `roleDefinitionId`.
Recognized built-in role names must agree with their official IDs; name-only, ID-only, or spoofed-ID
entries fail closed. Every production separation rule also requires reviewed
`forbiddenRoleDefinitionIds`; matching either a forbidden name or ID blocks the assignment, so a
false display name cannot bypass separation. Oversized integer literals and other parser failures
are reported as malformed input with exit code `3`.

The verifier is an offline review gate, not proof of Azure deployment success. Preserve the raw
Azure CLI output, exact repeated `--allow-change` values, reviewed policy, and machine-readable
verifier output beside the release evidence. Run both the what-if and RBAC checks; a successful
result from one does not waive the other.
