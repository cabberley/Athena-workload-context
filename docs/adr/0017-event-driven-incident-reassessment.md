# ADR 0017: Event-driven incident reassessment

## Status

Accepted for implementation.

## Context

WC-013 proves a governed baseline, fault, and recovery lifecycle when an operator starts each
phase. It does not continuously watch the workload. WC-016 must react to database VM, web VM, and
Azure Load Balancer failures while preserving Athena's identity, evidence, and approval
boundaries.

## Decision

Azure remains the event source. Activity Log and Resource Health events identify VM lifecycle
changes. Azure Monitor common-alert-schema metric or Resource Health alerts identify Load Balancer
data-path, VIP, DIP, and health-probe failures. ARM write success alone is not Load Balancer health
evidence.

Events are reduced to a bounded allowlisted contract, assigned a deterministic duplicate key, and
placed on private Premium Service Bus. A separate orchestrator resolves the exact resource through
approved workload context and emits a scoped reassessment request. Unknown or ambiguous bindings
fail closed.

The reassessment uses the separated WC-013 evidence identity and existing context-only evaluation
boundary. Athena never remediates. Verified results produce an immutable signed incident state and
attestation, followed by a separately signed `incidents/current.json` pointer update protected by
an ETag compare-and-swap. This feed is independent of the existing signed
baseline/faulted/recovered lifecycle.

The presentation sidecar serves only the current pointer and its three pointer-referenced immutable
assets. The browser polls every eight seconds and renders incident data only after pointer
signature, digest, trust-anchor, canonical-result, and detached RS256 verification.

Active and resolved incidents write notification messages to a private outbox. A pre-authorized
Azure Logic App Teams connection consumes that outbox. The connection is deliberately outside the
Athena runtime identity; absence or failure remains visible as notification status and never changes
the incident verdict.

## Consequences

- Detection is near-real-time but assessment latency still includes evidence collection.
- Service Bus duplicate detection and deterministic IDs make replay idempotent.
- Teams authorization requires an operator-owned managed connection.
- No raw alert body, caller identity, IP address, webhook secret, or unrestricted Azure identifier
  is published to the browser.
- Failed or stale reassessment cannot claim an active or resolved incident.
