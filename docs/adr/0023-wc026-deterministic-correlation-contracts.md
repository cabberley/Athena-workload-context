# ADR 0023: Freeze deterministic correlation contracts before scoring

## Status

Proposed.

## Context

WC-026 correlates health transitions, guest telemetry, network evidence, platform health,
resource changes, and governed dependency context. Its output can influence incident statements
and operator investigation, so ambiguity in evidence shape or authority would turn a deterministic
algorithm into an unreviewed trust decision.

WC-022, WC-024, and WC-025 already provide governed context, a signed monitoring handoff, and
signed normalized change artifacts. They do not define one typed payload for the monitoring Blob
referenced by the WC-024 handoff. A frozen object or caller-provided `verified` flag is not proof
that signatures, immutable Blob versions, scope, freshness, or completeness were checked.

The initial scoring proposal also risked treating a high numeric score as causality. In particular,
an NSG change, denied flow, failing connection test, and unhealthy endpoint still do not prove the
changed rule was the effective rule for the affected five-tuple.

## Decision

WC-026 first introduces strict correlation contracts without an engine, API, queue consumer, or
browser integration.

### Monitoring evidence bundle

`athena.wc026MonitoringEvidenceBundle.v1` is the typed payload referenced by the verified WC-024
handoff. It contains bounded discriminated observations for:

- guest and service signals;
- network flow decisions and effective-rule attribution;
- Connection Monitor results;
- endpoint and backend health;
- platform and Resource Health;
- explicit evidence coverage, gaps, truncation, and unavailability.

Every observation binds a canonical Azure resource ID, UTC observation interval, bounded source
record reference, provenance-root digest, summary code, deterministic ID, and content digest. The
bundle has no self-referential content-digest field. Its canonical persisted bytes must hash to the
exact immutable Blob digest carried by the signed WC-024 handoff.

### Correlation request boundary

`athena.wc026CorrelationRequest.v1` contains:

- exact governed context and dependency paths;
- one incident health transition;
- the signed WC-024 handoff and its typed bundle;
- signed WC-025 change artifacts;
- a deterministic evidence inventory;
- trusted `asOf`, algorithm ID, rule-catalog digest, and request digest.

The wire contract is explicitly untrusted and has no `verified`, `trusted`, or equivalent Boolean.
A later verification adapter must
read exact Blob versions, validate content digests and signatures, enforce scope/freshness, create
the non-wire verified input in memory, and invoke the pure engine directly. The raw engine will not
be exposed over HTTP or queues.

Published runtime and draft preview are distinct binding modes. Runtime incident and notification
paths carry a digest-bound publication authority record matching the exact manifest, profile, and
dependency graph. Draft authority is represented by a distinct preview-only variant and can never
feed runtime incident state. The later verification adapter remains responsible for resolving the
authority record against durable publication state.

### Report and confidence surface

`athena.wc026CorrelationReport.v1` contains ranked root-cause hypotheses with:

- fixed integer score components and raw score;
- confidence `Confirmed`, `High`, `Medium`, `Low`, or `Unknown`;
- supporting evidence, contradictions, and missing evidence;
- explicit causal gates and confidence caps;
- affected path and candidate causal time;
- deterministic IDs and digests;
- `noAutoRemediation=true`.

Raw score and confidence are separate. A later pure engine must apply category gates and caps after
scoring. Recent change alone is capped at Low. Hard conflicts force Unknown. Confirmed requires
direct category-specific attribution; NSG confirmation requires verified effective-rule or IP Flow
Verify attribution for the exact direction and five-tuple.

Reports bind the exact correlation request and incident-transition digests. A contract helper
validates every cited supporting, gate, and contradiction evidence ID against the request's
deterministic evidence index.

Independent corroboration is counted once per evidence family and provenance-root digest.
Observation windows are intervals rather than point timestamps. Absence is contradictory only when
a complete evidence-coverage record spans the exact resource/path and interval.

## Determinism

Contracts use:

- strict frozen Pydantic models;
- canonical resource IDs and UTC millisecond timestamps;
- bounded tuples rather than mutable collections;
- deterministic ordinal ordering and duplicate rejection;
- digest-bound observation, bundle, transition, hypothesis, and report IDs;
- exact schema, algorithm, context, inventory, and report digests.

The engine PR must define one fixed category order and ranking order, reject identity/digest
collisions, and prove permutation and Python hash-seed invariance.

## Deferred work

This prerequisite PR does not complete issue #53 and does not add scoring logic or
operational-content rendering. A subsequent WC-026 PR adds the pure engine and golden scenarios.
Operator guidance and Context Studio/runtime presentation remain later workstreams. Before
correlation output can enter the existing operational receipt, Python and TypeScript must introduce
and parity-test a typed operational-content v2 projection.

## Consequences

- Correlation can be reviewed independently from Azure and storage I/O.
- WC-024 and WC-025 remain frozen and are consumed rather than duplicated.
- Monitoring payload completeness and provenance become explicit.
- Confidence labels cannot hide missing gates, contradictions, or evidence gaps.
- The contract is intentionally verbose because causal claims must remain auditable.
