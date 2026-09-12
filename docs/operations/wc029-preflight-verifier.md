# WC-029 offline preflight verifier

`athena_context.wc029_preflight` evaluates saved Azure deployment what-if and role-assignment JSON
without authenticating to Azure or changing resources.

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
python -m athena_context.wc029_preflight what-if .\evidence\what-if.json `
  --allow-change '/subscriptions/.../providers/Microsoft.App/containerApps/athena-presentation'
```

Exit codes:

- `0`: safe;
- `2`: policy violations; and
- `3`: malformed, empty, unreadable, or oversized input.

## RBAC

```powershell
python -m athena_context.wc029_preflight rbac .\evidence\role-assignments.json `
  --policy .\evidence\reviewed-rbac-policy.json
```

The policy is bounded JSON:

```json
{
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

The verifier is an offline review gate, not proof of Azure deployment success. Preserve the raw
Azure CLI output and the reviewed allowlist/policy beside the release evidence.
