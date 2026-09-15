# ADR 0039: Bind WC-029 preflight to one deployment and one-time ledger

- **Status:** Proposed
- **Date:** 2026-09-15

## Context

The WC-029 offline preflight already binds saved what-if and RBAC evidence to a reviewed manifest,
bounded timestamps, and one collection run ID. Exact-SHA review found five remaining fail-open
paths:

- ambiguous property-path separators, brackets, escapes, and resource-root suffixes could avoid
  deletion or protected-property matching;
- contradictory or incomplete `NoEffect` entries could be ignored;
- planned Microsoft.Authorization role-assignment and role-definition mutations were treated as
  ordinary resources rather than authorization changes;
- what-if and RBAC artifacts could use different tenant, subscription, or resource-group targets;
  and
- a still-valid collection run and manifest could be evaluated repeatedly.

Freshness does not prove single use, and the pure what-if evaluator does not yet derive the
post-deployment principal, role, condition, and inherited scope needed to apply the reviewed
separation policy to an authorization mutation.

## Decision

Use the following guarded preflight contract:

1. Property paths accept only exact root aliases `<resource>`, `<resource>.`, and `.`, or dotted
   ASCII identifier components with canonical numeric indexes. Slash, backslash, tilde escapes,
   empty components, non-exact root suffixes, malformed or non-numeric brackets, and leading-zero
   indexes are invalid.
2. Every `NoEffect` entry contains both `before` and `after`. The values are type-exact and equal,
   and they resolve to the same values in complete resource-level before and after snapshots.
   Complete Modify snapshots contain matching `id`, `name`, `type`, and object-valued `properties`.
   Any supplied identity field makes the entire snapshot identity mandatory, preventing a snapshot
   type from reclassifying a benign resource ID.
3. What-if creates or modifies for `Microsoft.Authorization/roleAssignments` and
   `Microsoft.Authorization/roleDefinitions` always block until a separation-aware
   post-deployment authorization evaluator is implemented.
4. Both artifacts embed one byte-equivalent `athena.wc029PreflightManifest.v1`. It binds one
   immutable `deploymentExecutionId` and one `deploymentTarget` containing the reviewed tenant,
   subscription, and non-empty resource-group boundary set. Every what-if resource, snapshot,
   potential-change, and allowlist ID stays inside that target. The RBAC evidence and policy target
   match it exactly.
5. The production CLI requires one trusted, persistent release-ledger directory. It atomically
   creates one immutable collection-run binding, one immutable binding for the deployment execution
   and manifest, then one create-only consumption record for each artifact kind. One
   `collectionRunId` can map to only one deployment execution and manifest. The first what-if and
   first RBAC evaluation may consume the shared manifest. Repeated use of either kind, a different
   manifest for the same execution, or the same collection run under another execution fails even
   before `expiresAt`.
6. JSON decimal values are parsed into a bounded exact representation and serialized canonically
   for hashing. Direct binary floating-point values are rejected, so distinct evidence values cannot
   collapse before equality or digest checks.

The pure evaluators remain free of storage I/O. One-time consumption belongs to the production CLI
boundary after parsing, policy evaluation, and bounded rendering succeed but before success or
blocked output is returned.

## Consequences

- Existing guarded artifacts must add `schemaVersion`, `deploymentExecutionId`, and
  `deploymentTarget`, and their attestations must carry the same deployment execution ID.
- Guarded CLI invocations must add `--deployment-execution-id` and `--release-ledger`.
- What-if and RBAC checks must use the same exact manifest and ledger. Separate manifests sharing
  only a collection run ID are invalid for one deployment execution.
- A policy-blocked but otherwise valid artifact is consumed. Any corrected deployment requires new
  evidence, a new manifest, and a new deployment execution ID.
- The same collection run cannot be rebound to another deployment execution, even if a caller
  regenerates an otherwise valid manifest.
- The release ledger is trusted workflow state. Operators must keep it persistent and protected and
  must not delete, clone, replace, or redirect it to reuse evidence.
- The legacy module entry point remains available for compatibility but is not the guarded
  deployment gate.
- Authorization mutations remain deliberately unavailable rather than being accepted without
  separation analysis.

## Alternatives considered

- **Rely only on the 30-minute validity window:** rejected because the same evidence remains
  replayable throughout the window.
- **Embed a static non-reuse receipt in the artifact:** rejected because the same receipt can be
  replayed without trusted external state.
- **Perform ledger writes in the pure evaluators:** rejected because policy logic must remain
  deterministic and independent of I/O.
- **Partially infer role assignments from what-if payloads:** rejected because incomplete
  principal, group, condition, or inheritance data could weaken separation enforcement.
- **Continue accepting broad property-path syntax and normalize it:** rejected because alternate
  separators and escapes create security-equivalent aliases.

## Validation

Deterministic tests cover every rejected path grammar family, valid numeric indexes, incomplete,
changed, type-conflicting, and snapshot-conflicting `NoEffect`, allowlisted authorization
mutations, cross-subscription and cross-resource-group what-if IDs, RBAC target mismatch, shared
manifest success across both artifact kinds, repeated consumption, and cross-artifact manifest
rebinding, collection-run rebinding, complete snapshot identity, snapshot type spoofing, and
high-precision decimal distinction. Existing Unicode, freshness, pagination, hierarchy,
group-derived assignment, complete inventory, meaningful-delta, duplicate-rule, violation-count,
and rendered-output bounds remain in the full test suite.
