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

Further exact-SHA review found that the saved what-if result did not prove the exact collection
request, diagnostics could be ignored, additional authorization/imperative resource families were
not blocked, decimal hashing was non-injective under active context, RBAC URL/CLI tokens admitted
aliases, and nested path generation had no aggregate work budget.

The latest exact-SHA review found three remaining provenance and compatibility gaps:

- what-if provenance could omit `--no-prompt true` and therefore did not prove a non-interactive
  collection;
- Management Groups Get Subscription API `2020-05-01` raw evidence was read from the undocumented
  `properties.tenantId` alias instead of documented `properties.tenant`; and
- one global lowercase query-key rule rejected the documented ARM `$skipToken` continuation while
  Graph requires the distinct `$skiptoken` spelling.

The next exact-SHA review reproduced five additional fail-open paths:

- authorization-affecting Key Vault, federated identity, Microsoft Graph, and equivalent credential
  grant mutations were not classified with the already blocked authorization families;
- generic page parsing accepted cross-endpoint next-link aliases and empty or inappropriate cursor
  forms;
- approved role grants were evaluated without complete deny-assignment evidence;
- the Management Groups subscription tenant field was still retrieved case-insensitively; and
- input size validation performed a pathname `stat` followed by a separate pathname read.

The following exact-SHA review found three remaining resource-classification gaps:

- deployment stacks and storage local users could change downstream deny/delete behavior,
  credentials, and scoped data permissions without the dedicated post-deployment evaluators;
- Key Vault VM, disk-encryption, and template-deployment secret-access flags were not classified as
  authorization-affecting enablement; and
- exact resource-group IDs have no `providers` segment and were rejected before otherwise complete
  FullResourcePayloads rows could be evaluated.

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
   for hashing from lossless `Decimal.as_tuple()` fields without active-context operations. Integer
   and decimal representation classes use different canonical type tags. Direct binary
   floating-point values are rejected.
7. The what-if envelope carries the exact Azure CLI command and arguments. The manifest binds their
   digest. Only direct subscription/group what-if commands with `FullResourcePayloads`, full
   `Provider` validation, the exact separate pair `--no-prompt true`, exact `--no-pretty-print` and
   JSON output, and no exclusions, transforms, or unknown options are valid. JSON mode requires one
   template file and one `@file.json`; `.bicepparam` mode passes one direct `.bicepparam` path and
   forbids `--template-file`. Any non-empty diagnostic blocks release.
8. Creates or modifies under any `Microsoft.Authorization`, `Microsoft.ManagedServices`, or
   Microsoft Graph family; Key Vault access-policy resources or
   `accessPolicies`/`enableRbacAuthorization` property mutations; managed-identity federated
   credentials; equivalent app-role, delegated-permission, or identity-credential grants; and
   `Microsoft.Resources/deploymentScripts` remain blocked until their post-deployment effects are
   fully evaluated. Every Create, Modify, or Delete of `Microsoft.Resources/deploymentStacks` and
   `Microsoft.Storage/storageAccounts/localUsers` also blocks until stack deny/delete behavior and
   local-user SSH/password/permission effects are evaluated. Key Vault changes that enable
   `enabledForTemplateDeployment`, `enabledForDeployment`, or `enabledForDiskEncryption` block;
   exact boolean `false` remains an accepted tightening.
9. Paged evidence uses endpoint-exact fields and cursors. ARM pages require literal `nextLink` and
   exactly one non-empty `$skipToken` on continuation URLs. Graph pages require literal
   `@odata.nextLink` and exactly one non-empty `$skiptoken`; `$skip` is not accepted. Cross-endpoint
   aliases, whitespace, duplicates, case variants, and ambiguous cursor fields fail.
10. Canonical paths have a 4096-character limit and one evaluation-wide generated-path item and
    character budget, checked before concatenation or candidate materialization.
11. The release ledger must be beneath a separately supplied fixed trusted root. Every existing path
    component is rejected if it is a POSIX symlink or Windows symlink, junction, or other reparse
    point. Where supported, directory components are opened with no-follow semantics and ledger
    files are created/read relative to the securely opened directory handle. Windows keeps a
    non-reparse ledger-directory handle and verifies the final path and attributes of every opened
    record handle before any content is written or read. Trusted-root containment is checked before
    accessing the candidate ledger path.
12. Complete snapshot pairs are indexed once by canonical lowercase path. `NoEffect`
    reconciliation uses constant-time indexed lookups, removes the second delta walk, and charges
    deterministic index/path-token work to an aggregate lookup budget. The single `NoChange` pass
    retains inspectable-array and resource-root after-object requirements.
13. Separation matching uses the corroborated leaf-to-root management-group ancestry in both
    directions. Reviewed management-group prefixes cover connected child management groups and
    subscription descendants; parent assignments cover connected child prefixes. No unreviewed
    management-group ancestry is inferred.
14. Security decision strings are normalized only after exact trimmed ASCII validation. Azure CLI
    values beginning with `-`, malformed deployment names, and non-canonical relative
    template/parameter paths are rejected.
15. JSON keys and strings must encode as strict UTF-8. Lone surrogates and defensive encode failures
    become bounded preflight input failures.
16. POSIX ledger reads add nonblocking/no-follow flags and require a regular file from `fstat`.
    Writer and reader share one 64-KiB record bound checked before file creation.
17. Management Groups Get Subscription API `2020-05-01` evidence is retained in its documented raw
    shape and requires one literal, case-sensitive `properties.tenant` key. `Tenant`, `tenantId`,
    duplicate/case aliases, and conflicts are invalid. The manifest binds the complete raw RBAC
    payload; the verifier derives hierarchy metadata in memory rather than inserting an unbound
    normalized tenant alias into the response.
18. Every effective principal carries the same complete ARM deny-assignment evidence: an exact
    target-resource-group `atScope()` collection and an unfiltered subscription inventory, both
    fully paged. The verifier checks the effective principal, transitive groups, All Principals,
    exclusions, scope inheritance, `doNotApplyToChildScopes`, and conditions. Any conditional or
    otherwise applicable deny that might invalidate approved access fails conservatively.
19. Every JSON input is opened once as a binary descriptor, using no-follow/nonblocking flags where
    available. The verifier requires a regular file by `fstat`, reads no more than the configured
    bound plus one byte from that descriptor, rejects overflow or concurrent descriptor metadata
    change, and performs strict UTF-8 decoding only after the bounded read.
20. The exact provider-less resource-group ID
    `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}` maps to
    `Microsoft.Resources/resourceGroups`. Its Create, Modify, and NoChange rows undergo the same
    manifest boundary, subscription, snapshot identity/type, allowlist, meaningful-delta, and
    deletion controls as provider resource IDs.

The pure evaluators remain free of storage I/O. One-time consumption belongs to the production CLI
boundary after parsing, policy evaluation, and bounded rendering succeed but before success or
blocked output is returned.

## Consequences

- Existing guarded artifacts must add `schemaVersion`, `deploymentExecutionId`, and
  `deploymentTarget`, and their attestations must carry the same deployment execution ID.
- Guarded CLI invocations must add `--deployment-execution-id`, `--release-ledger`, and
  `--trusted-release-ledger-root`.
- What-if and RBAC checks must use the same exact manifest and ledger. Separate manifests sharing
  only a collection run ID are invalid for one deployment execution.
- A policy-blocked but otherwise valid artifact is consumed. Any corrected deployment requires new
  evidence, a new manifest, and a new deployment execution ID.
- The same collection run cannot be rebound to another deployment execution, even if a caller
  regenerates an otherwise valid manifest.
- The release ledger is trusted workflow state. Operators must keep it persistent and protected and
  must not delete, clone, replace, or redirect it to reuse evidence.
- Windows reparse points and junctions are treated as redirections, not directories. POSIX and
  Windows path validation covers the trusted root, ledger, and every parent component.
- Corrupted or non-UTF-8 existing ledger records produce a bounded preflight failure rather than an
  uncaught decoder error.
- FIFO, socket, device, symlink, junction, and reparse entries cannot be consumed as ledger records.
- A ledger record accepted by the create-only writer is guaranteed to fit the paired reader's bound.
- Guarded what-if artifacts must add exact request provenance and regenerate the reviewed shared
  manifest because `whatIfRequestDigest` is mandatory. The reviewed request includes exact
  `--no-prompt true` for both subscription and resource-group what-if commands.
- Guarded RBAC artifacts must retain Management Groups Get Subscription `properties.tenant`
  unchanged and regenerate the raw-evidence binding when that response changes.
- Guarded principal artifacts must add byte-equivalent, complete deny-assignment evidence and
  regenerate the raw-evidence binding.
- ARM and Graph page fields and continuation query keys are validated against their own endpoint
  contracts rather than generic aliases.
- Evidence path replacement cannot redirect an already opened descriptor, while growth beyond the
  bound and POSIX symlink or special-file inputs fail deterministically.
- Deployment-stack and storage-local-user changes remain unavailable rather than bypassing deny,
  deletion, credential, or scoped data-permission analysis.
- Resource-group rows are evaluable without weakening their reviewed target boundary or allowlist
  requirements.
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
and rendered-output bounds remain in the full test suite. Additional adversarial cases cover request
transforms/exclusions, diagnostics, expanded authorization and imperative families, decoded query
key collisions, fuzzy/non-ASCII CLI tokens, wide decimals, integer-versus-decimal digest identity,
surrounding-whitespace aliases, JSON and `.bicepparam` request modes, required
`--no-pretty-print`, exact `--no-prompt true` for both deployment scopes, Windows junction/reparse
paths, POSIX symlink/no-follow behavior, and a 14,000-leaf deterministic linear-work snapshot
regression. RBAC compatibility tests use the official Management Groups subscription
`properties.tenant` shape and exact two-page ARM `$skipToken` continuations, while rejecting tenant
case/legacy aliases and conflicts, Graph/ARM cursor spelling swaps, wrong next-link fields, empty or
whitespace cursors, duplicates, and casefold collisions. Deny-assignment regressions cover missing
collections, pagination, direct and group principals, All Principals, exclusions, inheritance,
conditions, unrelated scopes, and cross-principal collection disagreement. Provider-family tests
cover Key Vault access policies/RBAC mode, managed-identity federated credentials, Microsoft Graph
permission grants, and existing authorization/imperative families. Input tests prove single binary
open, maximum-plus-one reads, deterministic growth rejection, POSIX replacement stability,
no-follow symlink rejection, and nonblocking FIFO rejection. Windows tests include a synchronized
junction swap between validation and file open; ledger tests also cover outside nonexistent paths,
invalid UTF-8 collection/binding records, POSIX FIFO/socket rejection, and symmetric record-size
bounds. Scope regressions cover parent/child management groups and management-group-to-resource
matching in both directions. Token tests cover whitespace and Unicode aliases, lone surrogates,
single-dash values, and exact deployment/file grammars.
Fully attested resource-family regressions additionally cover deployment-stack
`denySettings`/`actionOnUnmanage`, storage local-user SSH/password/permission scopes, all three Key
Vault privileged deployment-access flags across deltas and full snapshots, safe disablement, and
exact resource-group Create/Modify/NoChange, allowlist, delta, snapshot-type, and boundary behavior.
