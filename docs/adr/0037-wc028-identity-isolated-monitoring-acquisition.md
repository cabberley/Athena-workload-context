# ADR 0037: Acquire monitoring evidence through an identity-isolated coordinator

- **Status:** Proposed
- **Date:** 2026-09-13
- **Amended:** 2026-09-15

## Context

ADR 0036 defines strict normalized monitoring records and an atomic collection transaction, but it
does not define how Azure evidence is requested. Allowing callers to supply KQL, resource scope, or
source-specific filters would bypass published monitoring intent. Independently persisting source
results could also expose partial evidence as complete.

Azure Monitor sources have important uncertainty. Missing rows are not proof of zero events.
Resource-context authorization applies only to registered resource-side table actions, while
Traffic Analytics and custom flow tables generally require workspace-context data access. A table
role exposes every row in that table; KQL filtering is not an authorization boundary.

## Decision

Add an identity-isolated monitoring acquisition coordinator in
`athena_context.monitoring_acquisition`.

The coordinator:

- accepts only an activation-eligible `PublishedMonitoringIntent` bound to the exact active
  `PublishedRuntimeContextBinding`, and verifies its version-pinned asset reference, detached
  signature, and trusted signing key before issuing any Azure read;
- exposes no caller-supplied query, table, column, filter, resource-scope, or time-window input;
- derives exact Log Analytics queries, Activity Log filters, Resource Graph scopes, Resource
  Health filters, and bounded windows from the verified intent plus reviewed constants;
- emits Log Analytics request v3 with the collector execution timestamp, exact
  authority-selected `EvidenceCoverageScope`, required `_ResourceId`, and
  `Prefer: include-permissions=true`; current responses must retain exact resource/workspace
  permission evidence with no denied tables or silent exclusions;
- accepts only the production `AzureMonitoringAdapter`, which internally creates one direct
  `ManagedIdentityCredential(client_id=<reviewed client ID>)`; after identity proof succeeds, the
  adapter passes that exact credential object to each Azure client so the SDK can legitimately
  acquire its own service-audience token without exposing or parsing ARM or Log Analytics tokens;
- implements credential-bound clients over Azure Core authenticated transports with fixed public
  Azure endpoints and audiences: resource-centric Azure Monitor Logs, exact-resource Activity Log
  filters, generated bounded Resource Graph change queries, and the per-VM Resource Health current
  endpoint. The historical IP Flow client remains parseable but current contract v8 rejects it
  before transport;
- normalizes Azure service values, resource IDs, UTC timestamps, enums, dynamic resource-candidate
  arrays, row ordering, truncation markers, and response byte counts into the existing strict
  acquisition result contracts while retaining duplicate source rows for downstream ambiguity
  detection;
- obtains identity proof before the first source read by requesting only the Athena-owned
  single-tenant `api://athena-monitoring-identity-proof` audience, then validates RS256 signature
  through tenant-pinned JWKS, token version `1.0`, exact issuer and audience, tenant, `oid`,
  `appid`/`azp`, app-only `idtyp`, exact application role, and `iat`/`nbf`/`exp`;
- captures `verifiedAt` only after token acquisition, JWKS retrieval, cryptographic verification,
  and claim validation, then uses that same trusted time for lifetime checks, normalized proof,
  collection time, and receipt execution start;
- persists only one frozen normalized identity proof containing those reviewed fields, signing-key
  ID, token hash, timestamps, the reviewed two-hour maximum lifetime, and a deterministic proof
  digest; the bearer token is discarded, and every exchange plus the signed receipt binds the same
  proof digest;
- requires a digest-pinned acquisition authority that binds the reader identity, the Athena
  non-reader identity, the collector contract, exact read-only source allowlist, resource
  allowlist, payload limits, freshness limit, total acquisition-call budget, receipt signing key,
  managed-identity tenant/client/object IDs, and a digest of the deployment identity-separation
  contract;
- requires acquisition-authority v5 to bind the current `contextBindingDigest`, the exact sorted
  `requiredCoverageScopeDigests`, and a sorted one-to-one binding from every required coverage
  digest to one selected control ID, control digest, and scope digest; the same exact control IDs
  are separately pinned, and all bindings are verified before credential acquisition or entry into
  any source-call loop, so stale, added-control, or omitted-control authority produces zero Azure
  evidence calls;
- requires authority `allowedSources` and `allowedResourceIds` to equal the exact selected
  source-specific collector-contract scope before identity acquisition: resource-context log
  targets and VM evidence use exact approved VM scopes, Resource Health uses its exact VM
  assignments, workload network/change resources stay under the reviewed workload resource group,
  and monitoring evidence resources stay under the reviewed monitoring resource group;
- replaces self-asserted read-only RBAC booleans with a digest-bound, externally collected
  effective RBAC inventory covering management-group ancestry, subscription descendants, direct
  and inherited assignments, assignment conditions, transitive group-derived grants, and measured
  custom-role actions; the inventory cites one immutable version-pinned source artifact and external
  manifest digest, the contract derives its expected collector grants from reviewed role IDs,
  conditions, and exact scopes, and acquisition rejects stale, incomplete, missing, or unexpected
  inventory before identity proof or source I/O;
- emits an immutable signed acquisition receipt containing collector-owned execution, call, result
  receipt, and issuance times plus every exact request/result digest; IP Flow entries also bind the
  collector-owned `checkedAt`; receipt v5 additionally signs the collector-selected incident
  resource plus exact previous/current source-record and observation bindings with a deterministic
  transition digest, and binds the exact normalized collection-batch digest plus a deterministic
  digest of normalized observations and coverage so neither persisted evidence nor the incident
  anchor can be replaced; it also binds the Athena identity proof and its tenant, client, object,
  app-only role, token-version, issuer, and audience policy;
- persists that receipt plus an independently digest-bound batch/request/result manifest in the
  WC-028 evidence bundle, binds the receipt digest into the signed monitoring handoff, and requires
  production correlation verification to revalidate the receipt signature, manifest, signed
  intent, context binding, deployed identities, acquisition authority, collector contract, and
  freshness;
- binds every request to the exact signed intent, control digest, scope digest, query text and
  query digest, then binds every normalized log record and coverage statement to an exact
  query-execution digest;
- requires exact source, table, schema version, column set, request digest, collection timestamp,
  row count, byte size, and time-window conformance;
- performs separate adjacent current and prior log queries where a transition needs both states,
  with one coverage record per exact execution;
- accepts a zero aggregate as evidence only when the result includes positive raw-input and
  ingestion-completeness proof bound to the exact query and window; an unproved empty `summarize`
  default, truncated result, or future ingestion watermark is omitted and surfaced as unavailable;
- requires Resource Health transitions to be supported by distinct real prior and current source
  rows, never by synthesizing a prior observation from a row's `previousStatus` field;
- pairs Activity Log and Resource Graph changes one-to-one using resource, correlation ID,
  timestamp, operation, and result, rejecting duplicate pair keys;
- omits ambiguous VMConnection and Traffic Analytics IP-to-resource mappings rather than selecting
  a candidate or claiming causality;
- treats `NTANetAnalytics`, `AzureNetworkAnalytics_CL`, and Connection Monitor workspace tables as
  unsupported for current acquisition because the design has no dedicated or ABAC-isolated
  workspace/table boundary; each control emits deterministic unavailable coverage with zero Log
  Analytics and zero IP Flow calls;
- does not grant or publish any IP Flow Verify role, assignment, or current collector operation;
  KQL `_ResourceId` predicates are retained only as an exact query/output binding and are never
  treated as authorization for workspace-context flow tables;
- requires the adopted workspace to have
  `enableLogAccessUsingOnlyResourcePermissions=true`, the exact supported tables to use the
  `Analytics` plan, and every returned `_ResourceId` to equal the reviewed VM target;
- retains the normalized Logs `permissions` payload in signed coverage, binds it to each resulting
  observation, and fails closed if the response omits the target resource, workspace data source,
  or reports any denied table;
- captures every actual source call start inside the execution boundary and validates proof
  lifetime, execution freshness, and monotonicity before invoking transport;
- marks missing, truncated, ambiguous, or otherwise incomplete results as unavailable, truncated,
  or partial coverage with an explicit manual-investigation reason rather than producing a zero;
  and
- constructs exactly one deterministically ordered `MonitoringCollectionBatch` after every
  applicable source succeeds, then invokes `MonitoringCollectionTransaction.execute` once.
- preselects only authority-pinned required controls before authorization, source calls, and call
  budgeting, then requires those controls to satisfy exactly `requiredCoverageScopeDigests`; records,
  observations, coverage, and incident selection therefore remain one governed unit. Supporting
  Activity Log controls without their own required coverage are not executed.
- provisions a separate Resource Health custom role containing only
  `Microsoft.ResourceHealth/AvailabilityStatuses/current/read`, makes it assignable only in
  `rg-athena-demo-workload`, and assigns it independently at each exact approved VM; built-in
  Reader remains limited to the already reviewed DCR/DCE-association and flow-log child resources.
- provisions a separate WC-028 resource-log role with only
  `Microsoft.Insights/Logs/Heartbeat/Read`, `Perf/Read`, `InsightsMetrics/Read`, `Syslog/Read`, and
  `VMConnection/Read`, assigns it only at the 11 exact approved VMs, and includes no invented NTA
  or Connection Monitor table action.
- provisions a physically separate RBAC attestor UAMI with only
  `roleAssignments/read`, `roleDefinitions/read`, `denyAssignments/read`, and
  `roleAssignmentScheduleInstances/read` at the subscription. Effective RBAC inventory v2 binds
  exact-target `atScope() and assignedTo(principalId)` results for collector and context
  principals, complete role definitions, applicable denies, active PIM instances, transitive
  groups, raw page hashes, freshness, and repeated-read stability.

Source exceptions, stale results, schema mismatches, scope escapes, duplicate change pairings, or
ambiguous incident transitions fail before the persistence transaction is entered.

## Consequences

- The Context API, policy, presentation, and correlation identities do not receive workload or
  monitoring Reader access.
- Query authority remains human-owned through the immutable published intent.
- Acquisition contract publication is a guarded second phase after infrastructure and role
  assignments exist: an external hierarchy-complete RBAC collection supplies the short-lived
  inventory and source-manifest digest, and acquisition remains blocked until that measured
  inventory is refreshed and matches the deployed identities and exact expected grants.
- Reordered source rows produce identical batch bytes.
- Source `sourceIdentityId` values remain untrusted compatibility fields and cannot replace adapter
  proof; a fake source client cannot alter the identity stamped into exchanges or receipts.
- Different Azure services may acquire different audience tokens, but all clients receive the same
  structurally owned `ManagedIdentityCredential` object after proof succeeds.
- `DefaultAzureCredential` and other local credential chains cannot be injected into the production
  adapter or emit production receipts.
- Empty aggregate defaults cannot become healthy or complete evidence.
- Optional controls cannot select an incident outside the required runtime coverage unit.
- Traffic Analytics cardinality cannot trigger any current acquisition call.
- A source failure cannot commit a partial monitoring bundle.
- Coverage and returned acquisition outcomes preserve limitations for operator investigation.
- Only coverage scopes required by the exact published runtime binding enter the atomic batch;
  optional observations cannot silently broaden required completeness.
- Acquisition emits only `athena.wc028MonitoringCollectionBatch.v2` and preserves its strict
  execution, trusted-time freshness, control-provenance, and exact coverage invariants.
- Receipt-bearing acquisitions use `athena.wc028MonitoringEvidenceBundle.v3` and
  `athena.wc028MonitoringEvidenceHandoff.v2`; legacy collection paths remain on their existing
  versioned contracts and cannot silently add receipt fields.
- The deployment publishes `athena.wc028MonitoringCollectorContract.v8` while retaining parse
  support for WC-024 v2 and legacy WC-028 v3-v7 contracts. Production verification requires the
  full reviewed v8 contract, permission-attested resource-context logs, effective RBAC inventory
  v2, separate attestor identity, identity proof, and current Resource Health policy.
- Legacy acquisition-authority v1-v4 documents remain readable, but only v5 authorities can execute
  production acquisition. Production receipt verification requires receipt v5 and derives deployed
  tenant/client/object/resource identity and proof policy from the full reviewed
  collector contract rather than caller assertions.
- Production collection transactions require cryptographic receipt verification before persistence;
  receiptless compatibility is isolated in an explicitly named legacy/test transaction type.
- This slice removes the IP Flow role and Network Watcher assignment, adds one separate narrow
  Resource Health current-status role, one separate five-table resource-log role with exact per-VM
  assignments, and one separate read-only RBAC attestor role. It leaves the shared WC-016
  resource-group role unchanged and adds no Reader
  broadening, diagnostic setting, alert, query deployment, Connection Monitor mutation, or write
  permission.

## Alternatives considered

- **Allow caller-provided KQL or resource IDs:** rejected because it creates an unreviewed read
  surface and can escape governed scope.
- **Use the Athena context identity for Azure reads:** rejected because it violates identity
  separation and least privilege.
- **Trust a runtime principal string beside an independently injected source port:** rejected
  because it cannot prove that the credential named in the receipt is the credential that
  authorized the Azure calls.
- **Parse Microsoft-owned ARM or Log Analytics tokens as identity evidence:** rejected because
  Azure Identity exposes no supported principal metadata and clients must treat tokens for those
  resources as opaque. Only the Athena-owned proof audience is parsed and cryptographically
  validated.
- **Use `DefaultAzureCredential` in production:** rejected because a local or chained credential
  can select an identity other than the reviewed managed identity.
- **Assign Reader or IP Flow permissions at the Network Watcher:** rejected because current
  acquisition does not execute flow verification and the existing Reader remains scoped only to
  the canonical flow-log child.
- **Treat no rows as zero:** rejected because ingestion gaps, latency, retention, and truncation are
  indistinguishable from a genuine zero without additional proof.
- **Use Traffic Analytics or IP Flow Verify alone as historical causality:** rejected because one
  is aggregated and the other is point-in-time.
- **Commit each source independently:** rejected because downstream correlation could observe an
  incomplete batch.

## Validation

- Exact requests are derived from the verified intent and monitoring-reader identity.
- Invalid intent signatures, acquisition-authority digests, identity reuse, stale collection
  times, unauthorized sources, or unauthorized resource scopes fail before any read.
- Invalid proof signature, token version, issuer, audience, tenant, object ID, client ID, app-only
  identity type, role, or lifetime fails before client construction and the first source I/O.
- Clock-advance tests prove `verifiedAt` is captured after token and JWKS work and is reused as the
  exact collection and execution-start timestamp.
- Tests prove the exact same `ManagedIdentityCredential` object reaches all five Azure clients,
  fake source identity values cannot change receipt identity, and `DefaultAzureCredential` cannot
  enter the production receipt path.
- Mocked Azure SDK transport contracts prove all five production clients use their reviewed
  endpoint, token audience, resource scope, request shape, bounded response handling, and
  deterministic normalization.
- Synthetic source clients are bound by a closure to each exact adapter instance, with an
  adversarial two-adapter execution proving construction and requests cannot cross-route through
  shared mutable fixture state.
- An authority issued for another context binding, required-coverage set, or control selection
  fails before credential acquisition and produces zero source calls.
- Any current IP Flow role, unregistered resource-side table action, missing Analytics plan,
  disabled resource-only workspace access, or missing permissions response fails before trusted
  use.
- Source schema, freshness, time, row, and byte bounds fail closed.
- Missing and truncated data produce manual-investigation coverage.
- Ambiguous VMConnection mappings do not become endpoint evidence.
- Every Traffic Analytics or custom flow-table control produces deterministic unavailable
  coverage, zero Log Analytics calls, zero IP Flow calls, and no retained network-flow record.
- Log request v3 tests bind current and prior windows, collector execution time, `_ResourceId`,
  exact authority coverage, the permissions response, and the `Prefer` header without module
  globals.
- IaC and contract tests require the exact Resource Health role ID, one allowed operation, and all
  11 approved VM scopes while proving Reader was not broadened.
- Receipt signatures and deployed identity/authority bindings are reverified in the production
  correlation boundary.
- Replacing the incident anchor and recomputing unsigned correlation request and inventory digests
  fails because correlation reconstructs the canonical collector selection from signed persisted
  observations and requires the receipt's exact source-record, observation, resource, state, and
  interval bindings.
- Extra authority resources, stale effective RBAC evidence, inherited or group-derived unexpected
  roles, changed assignment conditions, incomplete hierarchy evidence, workspace-context query
  targets, and persisted out-of-contract resources all fail before trusted use.
- Identical unsupported flow input produces identical unavailable signed evidence regardless of
  hypothetical IP Flow results, with zero transport calls.
- Forged source identity claims, caller-backdated collection time, unproved aggregate zero,
  optional incident controls, excessive Traffic Analytics cardinality, and acquisition-call budget
  exhaustion all fail closed in adversarial tests.
- More than one persistable row from one exact query execution fails closed rather than weakening
  the batch's one-observation-per-execution coverage contract.
- Duplicate Activity Log or Resource Graph pair keys fail before commit.
- Source failure leaves the transaction commit count at zero.
- Source-row reordering yields identical batch bytes.
