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
  allowlist, payload limits, and freshness limit;
- binds every request to the exact signed intent, control digest, scope digest, query text and
  query digest, then binds every normalized log record and coverage statement to an exact
  query-execution digest;
- requires exact source, table, schema version, column set, request digest, collection timestamp,
  row count, byte size, and time-window conformance;
- performs separate adjacent current and prior log queries where a transition needs both states,
  with one coverage record per exact execution;
- requires Resource Health transitions to be supported by distinct real prior and current source
  rows, never by synthesizing a prior observation from a row's `previousStatus` field;
- pairs Activity Log and Resource Graph changes one-to-one using resource, correlation ID,
  timestamp, operation, and result, rejecting duplicate pair keys;
- omits ambiguous VMConnection and Traffic Analytics IP-to-resource mappings rather than selecting
  a candidate or claiming causality;
- issues IP Flow Verify as its own identity-bound, request-digest-bound point-in-time read after
  an unambiguous Traffic Analytics mapping, and permits direct NSG attribution only when one
  successful, earlier, deny-introducing change matches its exact denied rule result;
- always marks Traffic Analytics coverage partial and records both its aggregation limitation and
  IP Flow Verify's point-in-time limitation;
- marks missing, truncated, ambiguous, or otherwise incomplete results as unavailable, truncated,
  or partial coverage with an explicit manual-investigation reason rather than producing a zero;
  and
- constructs exactly one deterministically ordered `MonitoringCollectionBatch` after every
  applicable source succeeds, then invokes `MonitoringCollectionTransaction.execute` once.

Source exceptions, stale results, schema mismatches, scope escapes, duplicate change pairings, or
ambiguous incident transitions fail before the persistence transaction is entered.

## Consequences

- The Context API, policy, presentation, and correlation identities do not receive workload or
  monitoring Reader access.
- Query authority remains human-owned through the immutable published intent.
- Reordered source rows produce identical batch bytes.
- A source failure cannot commit a partial monitoring bundle.
- Coverage and returned acquisition outcomes preserve limitations for operator investigation.
- Only coverage scopes required by the exact published runtime binding enter the atomic batch;
  optional observations cannot silently broaden required completeness.
- Acquisition emits only `athena.wc028MonitoringCollectionBatch.v2` and preserves its strict
  execution, trusted-time freshness, control-provenance, and exact coverage invariants.
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
- More than one persistable row from one exact query execution fails closed rather than weakening
  the batch's one-observation-per-execution coverage contract.
- Duplicate Activity Log or Resource Graph pair keys fail before commit.
- Source failure leaves the transaction commit count at zero.
- Source-row reordering yields identical batch bytes.
