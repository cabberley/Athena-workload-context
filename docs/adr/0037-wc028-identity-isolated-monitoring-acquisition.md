# ADR 0037: Acquire monitoring evidence through an identity-isolated coordinator

- **Status:** Proposed
- **Date:** 2026-09-13

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
- sends every request through a read-only port bound to one configured monitoring-reader managed
  identity, requires that identity to differ from the Athena context identity, and rejects
  responses that cite another identity;
- requires a digest-pinned acquisition authority that binds the reader identity, the Athena
  non-reader identity, the collector contract, exact read-only source allowlist, resource
  allowlist, payload limits, freshness limit, total acquisition-call budget, receipt signing key,
  and a digest of the deployment identity-separation contract;
- obtains the authenticated principal and execution clock from the collector runtime rather than
  trusting source-port or request-caller identity/time claims, and rejects execution unless the
  platform-authenticated principal is the approved monitoring reader and is distinct from Athena's
  non-reader context identity;
- emits an immutable signed acquisition receipt containing collector-owned execution, call, result
  receipt, and issuance times plus every exact request/result digest; IP Flow entries also bind the
  collector-owned `checkedAt`, and the receipt binds the exact normalized collection-batch digest
  plus a deterministic digest of the normalized observations and coverage so it cannot be replayed
  with altered persisted evidence;
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
- always marks Traffic Analytics coverage partial and records both its aggregation limitation and
  IP Flow Verify's point-in-time limitation;
- marks missing, truncated, ambiguous, or otherwise incomplete results as unavailable, truncated,
  or partial coverage with an explicit manual-investigation reason rather than producing a zero;
  and
- constructs exactly one deterministically ordered `MonitoringCollectionBatch` after every
  applicable source succeeds, then invokes `MonitoringCollectionTransaction.execute` once.
- rejects executable optional controls whose coverage is absent from
  `requiredCoverageScopeDigests`, so records, observations, coverage, and incident selection remain
  one governed unit; supporting Activity Log controls without their own required coverage are not
  executed, so they cannot consume acquisition calls or confer direct attribution.

Source exceptions, stale results, schema mismatches, scope escapes, duplicate change pairings, or
ambiguous incident transitions fail before the persistence transaction is entered.

## Consequences

- The Context API, policy, presentation, and correlation identities do not receive workload or
  monitoring Reader access.
- Query authority remains human-owned through the immutable published intent.
- Reordered source rows produce identical batch bytes.
- Source-port identity/time claims cannot replace platform-authenticated receipt provenance.
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
- The deployment publishes a separate `athena.wc028MonitoringCollectorContract.v3` for the v2
  receipt-bearing handoff while retaining the WC-024 v2/v1 collector contract for legacy paths;
  production verification requires the full reviewed contract for receipt-bearing handoffs.
- Legacy acquisition-authority v1 documents remain readable, but only v2 authorities can execute
  receipt-bearing acquisition. Production handoff verification requires the reviewed collector
  contract to authorize the exact handoff schema version and the acquisition authority to pin the
  receipt signing key.
- This slice adds no Azure resource, RBAC assignment, diagnostic setting, alert, query deployment,
  or Connection Monitor mutation.

## Alternatives considered

- **Allow caller-provided KQL or resource IDs:** rejected because it creates an unreviewed read
  surface and can escape governed scope.
- **Use the Athena context identity for Azure reads:** rejected because it violates identity
  separation and least privilege.
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
- Source schema, freshness, time, row, and byte bounds fail closed.
- Missing and truncated data produce manual-investigation coverage.
- Ambiguous VMConnection mappings do not become endpoint evidence.
- IP Flow Verify has an independent exact request/result binding and cannot be smuggled inside
  Traffic Analytics rows.
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
