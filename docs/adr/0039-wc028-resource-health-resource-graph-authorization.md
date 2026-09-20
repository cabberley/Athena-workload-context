# ADR 0039: Split Resource Graph query authorization from Resource Health visibility

- **Status:** Proposed
- **Date:** 2026-09-18
- **Amended:** 2026-09-20

## Context

The WC-028 production Resource Health client submits a subscription-scoped Azure Resource Graph
request and queries `HealthResources` rows whose type is
`microsoft.resourcehealth/availabilitystatuses`. The deployed custom role granted only
`Microsoft.ResourceGraph/resources/read`, and granted it at each approved VM. That action permits
submitting a Resource Graph query within a specified subscription, management group, or tenant
scope; it does not grant the Resource Health provider read that makes availability-status rows
visible. A VM-scoped assignment is also narrower than the approved workload object group that the
query is authorized to inspect.

Microsoft documents two independent authorization semantics:

- Resource Graph requires authorization for the query operation at the query scope and returns
  only resources the principal can read.
- `Microsoft.ResourceHealth/availabilityStatuses/read` gets availability statuses for resources
  in the assignment scope.

Granting Reader or generic VM read at the subscription would make the request work but would
violate the collector identity boundary and expose unrelated workload resources.

## Decision

Use two exact custom roles and two non-overlapping assignment shapes:

1. `Athena WC-028 Resource Graph Query Submitter` contains only
   `Microsoft.ResourceGraph/resources/read`. It is assignable and assigned only at the reviewed
   workload resource group. The REST body retains the exact subscription allowlist, while the KQL
   retains the exact approved VM-ID allowlist; neither requires a generic subscription read
   assignment. This role grants no `*/read`, `Microsoft.Compute/virtualMachines/read`, Resource
   Health action, data action, or write action.
2. `Athena WC-028 VM Resource Health Reader` contains only the canonical
   `Microsoft.ResourceHealth/availabilityStatuses/read` action. It remains assigned directly at
   each of the 11 approved VM resource IDs and nowhere at resource-group, subscription,
   management-group, or tenant scope.

The collector contract advances to `athena.wc028MonitoringCollectorContract.v10`. It separately
binds each role definition, role name, action allowlist, and assignment scope. The effective RBAC
inventory advances to `athena.wc028MonitoringEffectiveRbacInventory.v5` and separately records
both action fingerprints, both grants, and both full role definitions. Contract v9 and inventory
v4 remain parseable only as historical evidence and cannot execute current production acquisition.

The signed inventory verifier and publication template reject a missing or altered query action, a
missing or altered availability action, a query assignment outside the exact workload resource
group, a
Resource Health assignment outside the exact approved VM set, an unreferenced role, an extra
grant, or a deny assignment that removes either required action. The bounded query still includes
only approved VM IDs, and the client rejects any returned peer or otherwise unapproved VM row.

Adding the extra exact grant and role definition increases the canonical inventory size. The
inventory remains bounded to 62,000 bytes and the complete deployment-script environment payload
to 64,000 characters, below Azure deployment scripts' documented 64-KB environment-variable
limit. Oversized evidence fails before the verifier runs.

## Consequences

- Production Resource Health acquisition has both permissions Azure evaluates and no longer
  fails solely because the provider read is absent.
- The Resource Graph operation is authorized at the workload resource group even though the REST
  request body names the containing subscription; no generic subscription read or VM read is
  granted.
- Availability-status visibility remains resource-scoped, so a peer VM that is not in the
  approved set is not authorized and cannot become trusted evidence.
- Existing identity separation, group and ancestor expansion, inherited deny evaluation, active
  PIM rejection, attachment evidence, conditioned persistence, and `noAutoRemediation` behavior
  are unchanged.
- Operators must recollect and independently sign a v5 effective RBAC inventory before publishing
  the v10 contract.

## Alternatives considered

- **Grant Reader at the subscription:** rejected because it exposes unrelated resources and
  violates least privilege.
- **Grant both actions in one subscription-scoped role:** rejected because the Resource Health
  action would expose availability status for every supported resource in the subscription.
- **Assign the query action only at each VM:** rejected because the approved query authorization
  boundary is the workload resource group, while VM visibility is separately controlled by the
  Resource Health assignments.
- **Assign the query action at the subscription:** rejected because the selected provider contract
  does not require that broader assignment and the workload resource group is sufficient.
- **Rely only on KQL filtering:** rejected because query text is defense in depth, not an
  authorization boundary.

## Validation

- Build `main.bicep` and `publish-monitoring-contract.bicep`, then compare the checked-in
  `main.json` with a fresh Bicep build.
- Verify the query role has exactly one workload-resource-group assignment and exactly one action.
- Verify the Resource Health role has exactly 11 direct VM assignments and exactly one action.
- Validate v10/v5 contracts and reject missing permissions, wrong role fingerprints, subscription-
  scoped Resource Health, subscription- or VM-scoped query authorization, extra grants, and an
  unapproved peer VM scope.
- Run the production client test that injects an unapproved peer row and requires a fail-closed
  result before evidence can be committed.
