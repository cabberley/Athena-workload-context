# ADR 0037: Acquire monitoring evidence through an identity-isolated coordinator

- **Status:** Proposed
- **Date:** 2026-09-13
- **Amended:** 2026-09-15

## Context

ADR 0036 defines strict normalized monitoring records and an atomic collection transaction, but it
does not define how Azure evidence is requested. Allowing callers to supply KQL, resource scope, or
source-specific filters would bypass published monitoring intent. Independently persisting source
results could also expose partial evidence as complete.

Azure Monitor and Network Watcher sources have important uncertainty. Missing rows are not proof
of zero events. Traffic Analytics is aggregated rather than packet-level evidence. IP Flow Verify
is a point-in-time test rather than historical proof. VMConnection addresses can map to more than
one resource.

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
- accepts only the production `AzureMonitoringAdapter`, which internally creates one direct
  `ManagedIdentityCredential(client_id=<reviewed client ID>)`; after identity proof succeeds, the
  adapter passes that exact credential object to each Azure client so the SDK can legitimately
  acquire its own service-audience token without exposing or parsing ARM or Log Analytics tokens;
- obtains identity proof before the first source read by requesting only the Athena-owned
  single-tenant `api://athena-monitoring-identity-proof` audience, then validates RS256 signature
  through tenant-pinned JWKS, token version `1.0`, exact issuer and audience, tenant, `oid`,
  `appid`/`azp`, app-only `idtyp`, exact application role, and `iat`/`nbf`/`exp`;
- persists only one frozen normalized identity proof containing those reviewed fields, signing-key
  ID, token hash, timestamps, the reviewed two-hour maximum lifetime, and a deterministic proof
  digest; the bearer token is discarded, and every exchange plus the signed receipt binds the same
  proof digest;
- requires a digest-pinned acquisition authority that binds the reader identity, the Athena
  non-reader identity, the collector contract, exact read-only source allowlist, resource
  allowlist, payload limits, freshness limit, total acquisition-call budget, receipt signing key,
  managed-identity tenant/client/object IDs, and a digest of the deployment identity-separation
  contract;
- requires acquisition-authority v4 to bind the current `contextBindingDigest`, the exact sorted
  `requiredCoverageScopeDigests`, and a sorted one-to-one binding from every required coverage
  digest to one selected control ID, control digest, and scope digest; the same exact control IDs
  are separately pinned, and all bindings are verified before credential acquisition or entry into
  any source-call loop, so stale, added-control, or omitted-control authority produces zero Azure
  evidence calls;
- emits an immutable signed acquisition receipt containing collector-owned execution, call, result
  receipt, and issuance times plus every exact request/result digest; IP Flow entries also bind the
  collector-owned `checkedAt`, and the receipt binds the exact normalized collection-batch digest
  plus a deterministic digest of the normalized observations and coverage so it cannot be replayed
  with altered persisted evidence; receipt v4 additionally binds the Athena identity proof and its
  tenant, client, object, app-only role, token-version, issuer, and audience policy;
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
- issues IP Flow Verify as its own identity-bound, request-digest-bound point-in-time read after
  an unambiguous Traffic Analytics mapping, and permits direct NSG attribution only when one
  successful, earlier, deny-introducing change matches its exact denied rule result;
- rejects Traffic Analytics responses with more than one row before issuing any IP Flow calls, and
  rejects all further reads once the authority's total acquisition-call budget is exhausted;
- when a selected Traffic Analytics query returns no usable flow row, emits unavailable network
  coverage and its actual Log Analytics exchange only; no IP Flow call or source-specific proof is
  created, while the acquisition-wide Athena identity proof remains bound to every emitted exchange;
- always marks Traffic Analytics coverage partial and records both its aggregation limitation and
  IP Flow Verify's point-in-time limitation;
- marks missing, truncated, ambiguous, or otherwise incomplete results as unavailable, truncated,
  or partial coverage with an explicit manual-investigation reason rather than producing a zero;
  and
- constructs exactly one deterministically ordered `MonitoringCollectionBatch` after every
  applicable source succeeds, then invokes `MonitoringCollectionTransaction.execute` once.
- preselects only authority-pinned required controls before authorization, source calls, and call
  budgeting, then requires those controls to satisfy exactly `requiredCoverageScopeDigests`; records,
  observations, coverage, and incident selection therefore remain one governed unit. Supporting
  Activity Log controls without their own required coverage are not executed.
- provisions one custom Network Watcher role with only
  `Microsoft.Network/networkWatchers/ipFlowVerify/action` and
  `Microsoft.Network/networkWatchers/ipFlowVerify/read`, makes it assignable only in
  `NetworkWatcherRG`, and assigns it only at the exact
  `NetworkWatcher_australiaeast` resource; the existing built-in Reader assignment remains scoped
  only to the canonical flow-log child;
- publishes the exact IP Flow role-definition ID, Network Watcher assignment scope, and two-action
  allowlist in production collector contract v5, alongside the collector tenant/client/object
  identity, Athena proof audience/version/role, and acquisition receipt v4 schema.

Source exceptions, stale results, schema mismatches, scope escapes, duplicate change pairings, or
ambiguous incident transitions fail before the persistence transaction is entered.

## Consequences

- The Context API, policy, presentation, and correlation identities do not receive workload or
  monitoring Reader access.
- Query authority remains human-owned through the immutable published intent.
- Reordered source rows produce identical batch bytes.
- Source `sourceIdentityId` values remain untrusted compatibility fields and cannot replace adapter
  proof; a fake source client cannot alter the identity stamped into exchanges or receipts.
- Different Azure services may acquire different audience tokens, but all clients receive the same
  structurally owned `ManagedIdentityCredential` object after proof succeeds.
- `DefaultAzureCredential` and other local credential chains cannot be injected into the production
  adapter or emit production receipts.
- Empty aggregate defaults cannot become healthy or complete evidence.
- Optional controls cannot select an incident outside the required runtime coverage unit.
- Traffic Analytics cardinality cannot amplify one query into unbounded IP Flow calls.
- A source failure cannot commit a partial monitoring bundle.
- Coverage and returned acquisition outcomes preserve limitations for operator investigation.
- Only coverage scopes required by the exact published runtime binding enter the atomic batch;
  optional observations cannot silently broaden required completeness.
- Acquisition emits only `athena.wc028MonitoringCollectionBatch.v2` and preserves its strict
  execution, trusted-time freshness, control-provenance, and exact coverage invariants.
- Receipt-bearing acquisitions use `athena.wc028MonitoringEvidenceBundle.v3` and
  `athena.wc028MonitoringEvidenceHandoff.v2`; legacy collection paths remain on their existing
  versioned contracts and cannot silently add receipt fields.
- The deployment publishes `athena.wc028MonitoringCollectorContract.v5` while retaining parse
  support for WC-024 v2 and legacy WC-028 v3/v4 contracts. Production verification requires the
  full reviewed v5 contract and its exact proof policy.
- Legacy acquisition-authority v1-v3 documents remain readable, but only v4 authorities can execute
  production acquisition. Production receipt verification requires receipt v4 and derives deployed
  tenant/client/object/resource identity, proof policy, and IP Flow policy from the full reviewed
  collector contract rather than caller assertions.
- Production collection transactions require cryptographic receipt verification before persistence;
  receiptless compatibility is isolated in an explicitly named legacy/test transaction type.
- This slice adds exactly one narrow custom role definition and one assignment at the existing
  regional Network Watcher. It adds no Reader broadening, diagnostic setting, alert, query
  deployment, Connection Monitor mutation, or write permission.

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
- **Assign Reader at the Network Watcher:** rejected because IP Flow Verify needs only two exact
  actions and broad Reader would enlarge the management-plane read surface.
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
- Tests prove the exact same `ManagedIdentityCredential` object reaches all five Azure clients,
  fake source identity values cannot change receipt identity, and `DefaultAzureCredential` cannot
  enter the production receipt path.
- An authority issued for another context binding, required-coverage set, or control selection
  fails before credential acquisition and produces zero source calls.
- Missing or incorrect IP Flow role ID, exact Network Watcher scope, two-action allowlist, or
  receipt schema fails collector-contract validation before external I/O.
- Source schema, freshness, time, row, and byte bounds fail closed.
- Missing and truncated data produce manual-investigation coverage.
- Ambiguous VMConnection mappings do not become endpoint evidence.
- IP Flow Verify has an independent exact request/result binding and cannot be smuggled inside
  Traffic Analytics rows.
- Empty or unusable Traffic Analytics results produce deterministic unavailable coverage, no IP
  Flow exchange, and a valid receipt v4 with no orphan source proof.
- Receipt signatures and deployed identity/authority bindings are reverified in the production
  correlation boundary.
- Forged source identity claims, caller-backdated collection/IP Flow time, unproved aggregate zero,
  optional incident controls, excessive Traffic Analytics cardinality, and acquisition-call budget
  exhaustion all fail closed in adversarial tests.
- More than one persistable row from one exact query execution fails closed rather than weakening
  the batch's one-observation-per-execution coverage contract.
- Duplicate Activity Log or Resource Graph pair keys fail before commit.
- Source failure leaves the transaction commit count at zero.
- Source-row reordering yields identical batch bytes.
