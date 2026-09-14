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

ARM `Ignore` and `Deploy` results fail closed because they do not provide a predictable reviewed
final state.

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

The production wrapper requires `--policy`, a non-empty `expectedPrincipalIds` array, and one
non-vacuous `separationRules` entry for every expected principal. Every rule must name at least one
forbidden role and one forbidden scope prefix. The saved role-assignment evidence must be non-empty
and must cover exactly the expected principals; policy entries or assignments for an unexpected
principal fail closed. This prevents an incomplete export or an unrelated syntactically valid rule
from producing a safe result. The legacy module entry point keeps its historical optional-policy
behavior for compatibility and must not be used as the guarded deployment gate without a reviewed
policy.

The policy is bounded JSON:

```json
{
  "expectedPrincipalIds": [
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002"
  ],
  "allowedBroadAssignments": [
    {
      "principalId": "00000000-0000-0000-0000-000000000001",
      "roleDefinitionName": "Reader",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload"
    }
  ],
  "separationRules": [
    {
      "principalId": "00000000-0000-0000-0000-000000000002",
      "forbiddenRoleNames": ["Reader", "Log Analytics Reader"],
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
without trailing slashes before allowance, broad-scope, and separation evaluation, so alternate
subscription or resource-group spellings cannot bypass the gate. Oversized integer literals and
other parser failures are reported as malformed input with exit code `3`.

The verifier is an offline review gate, not proof of Azure deployment success. Preserve the raw
Azure CLI output, exact repeated `--allow-change` values, reviewed policy, and machine-readable
verifier output beside the release evidence. Run both the what-if and RBAC checks; a successful
result from one does not waive the other.
