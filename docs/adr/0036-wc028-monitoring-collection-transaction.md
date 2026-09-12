# ADR 0036: Normalize monitoring and change evidence before atomic persistence

- **Status:** Proposed
- **Date:** 2026-09-13

## Context

WC-028 has published monitoring intent and deterministic correlation contracts, but no production
boundary joins Azure Monitor Agent/VM Insights, Network Watcher, Activity Log/resource-change, and
Resource Health evidence. Letting each collector create correlation inputs independently would
permit partial batches, scope substitution, unreviewed queries, and inconsistent change
attribution.

The first required scenario is a VM connectivity loss after an NSG rule change. The existing
WC-026 engine already owns confidence, contradiction, and missing-evidence semantics, so WC-028
must feed that engine rather than introduce a second scoring shape.

## Decision

Add an all-or-nothing monitoring collection preparation boundary.

The boundary:

- validates one exact `PublishedMonitoringIntent` against one exact
  `PublishedRuntimeContextBinding`;
- accepts bounded, strict records for AMA heartbeat, VM Insights connection health, Network
  Watcher flow evidence, Connection Monitor, Resource Health, and paired Activity Log/Resource
  Graph changes;
- requires every record to cite an exact published control and, for Log Analytics-derived
  evidence, the exact published query digest, target, evaluation window, frequency, and expected
  source table for that collector record kind;
- rejects resources or dependency paths outside the control and published context;
- binds each declared coverage family to the control's reviewed Azure source table so one
  collector cannot claim another collector's completeness;
- normalizes into the existing WC-026 observation, coverage, change-artifact, incident-transition,
  evidence-inventory, and correlation-request contracts;
- attributes a denied flow to an NSG rule change only when one successful, causal, pre-incident
  change matches the exact rule and correlation ID and strict direct attribution evidence binds
  the method, deny decision, rule, tuple, change correlation ID, and an exact
  `properties.access` transition from Allow to Deny;
- leaves ambiguous flow evidence unattributed so the existing engine caps confidence and emits the
  required manual investigation evidence; and
- enters persistence only after the complete batch and correlation request window have validated.
  The persistence port exposes a transaction context: immutable handoffs are checked and the
  correlation request is constructed before successful context exit commits the write.

The transaction exposes the existing `CorrelationRequest`; `CorrelationService` remains the sole
owner of confidence and manual-investigation evidence.

Incident construction preserves the selected adverse health state (`degraded`, `unhealthy`, or
`unavailable`) and expands the anchor to the complete overlapping evidence interval required by
the WC-026 verifier. A Resource Health incident anchor must be an active event that explicitly
transitions from `Available`; a resolved event cannot open an incident.

## Consequences

- A complete synthetic NSG-change/connectivity-loss batch produces a Confirmed existing
  `networkSecurityChange` hypothesis.
- Omitting direct rule attribution produces High confidence plus
  `effectiveRuleAttribution` manual-investigation evidence.
- Invalid queries, filters, scope, paths, health transitions, coverage, or change pairing fail
  before the persistence port is called.
- No Azure resource, RBAC assignment, query deployment, alert rule, or connection monitor is
  created by this slice.
- A later slice must implement the identity-isolated Azure acquisition and atomic persistence port,
  including signed immutable collection-authority receipts.

## Alternatives considered

- **Add a WC-028 scoring model:** rejected because WC-026 is the deterministic authority.
- **Persist each source independently:** rejected because partial batches can misstate evidence
  completeness.
- **Infer controls from table names or resource types:** rejected because collection must be
  authorized by exact published monitoring intent.
- **Treat temporal proximity as direct NSG attribution:** rejected because recent change alone is
  not causal proof.

## Validation

- Confirmed NSG connectivity-loss correlation from normalized multi-source evidence.
- High-confidence cap and explicit IP Flow Verify investigation evidence without direct
  attribution.
- No persistence call when an unreviewed query digest is supplied.
- Stable bundle and change-artifact bytes under input reordering.
