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
  `PublishedRuntimeContextBinding`, but only after validating the intent's version-pinned asset
  references, detached signature, trusted signing key, and activation eligibility; a structurally
  valid or `dryRunOnly` intent is not executable;
- accepts bounded, strict records for AMA heartbeat, VM Insights connection health, Network
  Watcher flow evidence, Connection Monitor, Resource Health, and paired Activity Log/Resource
  Graph changes;
- requires every record to cite an exact published control and, for Log Analytics-derived
  evidence, the exact published query digest, target, evaluation window, frequency, and expected
  source table for that collector record kind;
- rejects resources or dependency paths outside the control and published context;
- binds each declared coverage family to the control's reviewed Azure source table so one
  collector cannot claim another collector's completeness;
- binds query-derived coverage to exact query-execution digests, reviewed query digest and target,
  evaluation window, and frequency. Complete coverage must be composed solely of bounded,
  contiguous, fresh executions with an exact matching resource/path/tuple scope. Every persisted
  query-derived observation carries its own execution digest, and that digest must occur exactly
  once in compatible persisted coverage for the same control and scope;
- rejects `treatAsHealthy` for activation-eligible intent. The value remains parseable for
  backward-compatible draft inspection, but production activation cannot convert missing
  telemetry into healthy evidence;
- validates every observation interval, coverage interval, and normalized Resource Graph change
  against `trustedAsOf`, reapplies each source's reviewed freshness limit at that time, and bounds
  the delay from collection to trusted evaluation to 20 minutes;
- persists the immutable intent and attestation Blob references with the monitoring bundle,
  includes them in the correlation evidence inventory, and records digest-bound `controlId`,
  `controlDigest`, and `sourceClausePath` provenance on every observation and coverage record;
- requires the production correlation verifier to re-read the version-pinned intent and
  attestation, verify the detached signature and active-context binding, and resolve every
  persisted control provenance tuple before evaluating any hypothesis. The verifier also uses
  the bundle's immutable `collectedAt` and the reverified control metadata to reapply each query
  evaluation-window-plus-frequency limit, Resource Health maximum event age, the 15-minute
  change-evidence limit, and the 20-minute collection delay against the request's
  `trustedAsOf`; recomputing the unkeyed request digest with a later trust time cannot refresh
  persisted evidence;
- requires confidence matchers to use the complete coverage record containing the scored
  observation's own query-execution digest; complete coverage for another execution cannot
  upgrade partial evidence;
- keeps monitoring-owned evidence resources, such as a Connection Monitor resource, in a signed
  `evidenceResourceIds` scope distinct from workload dependency-path coverage resources;
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
`unavailable`). One shared canonical selector chooses the primary healthy-to-adverse transition
and then expands it to every connected, overlapping, same-state corroborating health component
across controls. The complete expanded source-record set is signed in `selectedIncident`, used by
the collection transaction, and reconstructed by production correlation; a caller cannot narrow
the signed selection while leaving corroborating observations in the anchor. Disconnected
episodes within one control and overlapping healthy evidence fail closed. A Resource Health
incident anchor must be an active event that explicitly transitions from `Available`; a resolved
event cannot open an incident. Resource Health event intervals must also remain within the
control's reviewed `maximumEventAgeSeconds` at both collection time and the request's trusted
evaluation time.

The strengthened input contract is `athena.wc028MonitoringCollectionBatch.v2`, and monitoring
intent is `athena.wc028PublishedMonitoringIntent.v2` because Resource Health controls now carry a
required freshness bound. Version 1 assets are rejected rather than silently treating unbound
coverage or unbounded health events as activation eligible.

Production acquisition uses `athena.wc028MonitoringEvidenceBundle.v3`,
`athena.wc028MonitoringAcquisitionReceipt.v6`, and
`athena.wc028CorrelationRequest.v5`. Receipt v6 preserves the v5 minimal `selectedIncident`
containing the
canonical incident resource, exact previous/current normalized source-record IDs, selected adverse
state, and transition digest. It additionally signs the exact effective-RBAC inventory digest,
source-manifest digest, validity interval on every exchange, every ordered physical Azure request
attempt, and the runtime's complete
`athena.wc028MonitoringPersistenceReplay.v3`
execution/cleanup/storage-readiness/request-window binding. Acquisition-authority v6 supplies
separate physical-attempt and logical-exchange budgets; v5 remains byte-compatible and parse-only.
Correlation
request v5 carries the same selected incident and reconstructs both the selection and canonical
citation-bearing transition from persisted evidence.

Current production acquisition does not query Traffic Analytics, custom flow tables, Connection
Monitor workspace tables, or IP Flow Verify. Without a dedicated or ABAC-isolated workspace/table
boundary, those controls persist deterministic unavailable coverage with zero source calls and no
network-flow observation. Historical v3 requests may retain their prior versioned flow evidence,
but production request v5 accepts only permission-attested resource-context log evidence.

`athena.wc028MonitoringEvidenceBundle.v2` with
`athena.wc028CorrelationRequest.v4` with receipt v5, `athena.wc028CorrelationRequest.v3`, and the
legacy WC-026 v1/v2 pair remain parseable for historical and explicitly non-production
compatibility only. Production `CorrelationService` rejects those older request versions.

## Consequences

- A complete synthetic NSG-change/connectivity-loss batch produces a Confirmed existing
  `networkSecurityChange` hypothesis.
- Omitting direct rule attribution produces High confidence plus
  `effectiveRuleAttribution` manual-investigation evidence.
- Invalid queries, filters, scope, paths, health transitions, coverage, or change pairing fail
  before the persistence port is called.
- Unsigned, incorrectly signed, or dry-run-only monitoring intent fails before evidence
  normalization or persistence.
- Activation-eligible intent using `treatAsHealthy`, uncovered or multiply covered query
  observations, excessive collection-to-trust delay, and unresolved signed control provenance all
  fail closed.
- Query and change evidence that was fresh at collection but exceeds its source-specific age at
  `trustedAsOf` fails before persistence.
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
- Persisted query observations and coverage retain exact execution digests with one-to-one
  compatible coverage.
- Production verification re-reads the immutable signed monitoring intent and attestation and
  rejects unresolved control provenance.
- Production verification rejects a caller-reissued request whose `trustedAsOf` is moved forward
  and whose request digest is recomputed when the persisted source evidence is no longer fresh
  under the reverified signed control limits.
- Stable bundle and change-artifact bytes under input reordering.
