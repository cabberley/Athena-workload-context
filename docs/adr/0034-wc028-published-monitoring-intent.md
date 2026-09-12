# ADR 0034: Require explicit published monitoring intent

- **Status:** Proposed
- **Date:** 2026-09-12

## Context

The current workload manifest describes business intent, topology, objectives, and reviewed
controls, but it does not contain enough information to deploy Azure Monitor rules. A reconciler
would otherwise have to invent metric names, KQL, thresholds, operators, windows, frequencies,
dimensions, missing-data behavior, ownership, and deployment scope.

WC-028 must not infer those values. Drafts and legacy manifests must never affect live monitoring.
Governance publication and runtime activation are also distinct: an immutable published artifact
proves historical bytes, while a later CAS-protected active pointer will decide which successfully
applied authority is current.

## Decision

Introduce `PublishedMonitoringIntent.v1` as a separate immutable contract bound to one exact
`PublishedRuntimeContextBinding`.

Every monitoring control explicitly declares:

- signal kind and exact metric/query/event fields;
- unit, aggregation, operator, and threshold;
- evaluation window and frequency;
- dimensions or event filters;
- severity and missing-data behavior;
- an explicit non-notifying action behavior for this first slice;
- exact governed resource, dependency-path, and role scope;
- owner and source manifest clause; and
- whether the control is dry-run-only.

There are no default threshold, timing, query, ownership, or scope values. A legacy manifest that
has no separately reviewed monitoring intent is unsupported/no-op; it is not translated using
guesses.

The intent binds the exact manifest ID/version/digest, resolved profile, dependency graph, context
binding, publication authority, version-pinned authority bytes, publication record, audit head,
environment, and controls. IDs and digests are deterministic. The canonical intent is limited to
64 KiB and retains `noAutoRemediation=true`.

The builder accepts only an exact `PublishedRuntimeContextBinding`, requires the caller to identify
the expected currently active context-authority digest, and rejects any control scope outside the
control's explicitly selected dependency paths/resources/roles. Metric controls are single-resource
until a later contract binds homogeneous target type and region. Log-query controls identify their
execution target and reject cross-workspace, cross-cluster, application, or external-data queries.
Activity Log and Resource Health controls use event condition fields rather than periodic metric
threshold semantics. The expected-active check is a boundary confirmation, not a replacement for
the later signed activation pointer.

Durable consumers must call `validate_published_monitoring_intent_context` with the exact published
runtime context before review or activation. Asset signature validation alone authenticates bytes;
it does not re-prove governed scope.

The contract also defines a detached attestation and immutable version-pinned asset reference.
`validate_monitoring_intent_activation_eligible` rejects any intent containing a dry-run-only
control. Applied authority, active-pointer state, approval, Azure readback, and ARM mutation remain
out of scope.

## Consequences

- WC-028 can compile and review monitoring configuration without inventing policy.
- Current manifests remain valid governance documents but do not become deployable monitoring
  intent automatically.
- Monitoring intent can be signed and persisted before any apply workflow exists.
- A later PR must add publication outbox, proposal/approval, fenced apply/readback, immutable
  applied authority, CAS activation history, and vNext event/incident provenance.
- No Azure resource is created, changed, adopted, or deleted by this slice.

## Alternatives considered

- **Derive defaults from objectives:** rejected because objectives lack deployable signal semantics.
- **Reuse MonitoringAlertControl:** rejected because it describes observed controls, not desired
  Azure configuration.
- **Activate directly from published intent:** rejected because publication does not prove Azure
  apply/readback success or current authority.
- **Embed intent into the manifest:** rejected to preserve manifest compatibility and human-owned
  publication boundaries.

## Validation

- Exact published-context, manifest, profile, graph, and authority binding.
- Draft and mismatched-active-authority rejection.
- Required-field/no-default validation for every signal.
- Deterministic ordering, IDs, digests, and 64-KiB bound.
- Scope substitution and extra-field rejection.
- Dry-run intent cannot become activation-eligible.
- Exact immutable asset and signature validation.
