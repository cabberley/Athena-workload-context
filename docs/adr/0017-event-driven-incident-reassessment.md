# ADR 0017: Event-driven incident reassessment

## Status

Accepted for implementation.

## Context

WC-013 proves a governed baseline, fault, and recovery lifecycle. WC-016 adds continuous
reassessment without allowing an untrusted queue message, a compromised detector, or the incident
runtime to cross the lifecycle trust boundary.

## Decision

The scheduled detector has a dedicated user-assigned managed identity. It can pull its image, send
only to the reassessment queue, update only `Wc016DetectorState`, and read only VM instance view
and Azure Monitor metrics through a custom signal-reader role. Runtime allowlists narrow that role
to the exact database VM, web VMs, and Load Balancer. The evidence identity is not reused.

The detector reads current state once per minute. VM health requires exactly one running power
state. Load Balancer failure is determined only by `VipAvailability`; degraded
`DipAvailability` is reported as backend degradation and never relabelled as a Load Balancer
failure. Missing, duplicate, unknown, non-numeric, or failed reads fail closed.

Transition state contains committed and pending checkpoints. A transition ID and request body are
persisted before send and retained until the send and committed-state update both succeed.
Therefore a retry after an uncertain send or state-write failure uses the identical request and
Service Bus message ID.

The reassessment request is an untrusted wake-up hint. The orchestrator validates exact broker
metadata, source, rule, resource, role, scenario, incident ID, request ID, lifecycle, and
idempotency key from deployment-owned bindings, then independently queries current ARM state
through the same bounded approved signal adapter. The event's observed-to-received interval remains
bounded to ten minutes, while a valid queued hint may be processed for the queue's one-day lifetime
after an outage. The queued lifecycle is not evidence: independently verified live health and the
trusted signed active index alone determine whether the incident becomes active or resolved. A
hint/live mismatch therefore cannot mint a separate status, while an ambiguous live read prevents
publication and eventually ages out the signed feed heartbeat. No state change, including a
duplicate or minted hint, produces an incident publication or notification, and a resolution
without a prior active incident is a no-op.

Raw-event normalization is not exposed as a deployed worker. WC-016 creates only the
session-enabled reassessment queue and notification outbox.

Incident signing and publication are isolated from WC-013 lifecycle assets:

- a dedicated non-exportable Key Vault RSA key signs only WC-016 incident objects;
- `incident-assets` is a dedicated private, non-WORM Blob container;
- the orchestrator has Crypto User only on the incident key and Blob Data Contributor only on
  `incident-assets`;
- it has no lifecycle signing-key permission and no `presentation-assets` write permission; and
- the presentation identity has read-only access to `incident-assets`.

Each publication has an immutable signed
`incidents/<incident-id>/versions/<digest>/pointer.json` pointer. A deterministic,
incident-ID-sorted signed `incidents/active.json` index references the exact immutable pointer for
every active incident. Immutable assets are uploaded before the aggregate compare-and-swap. A
losing concurrent publisher therefore cannot invalidate the winning feed. Resolving one incident
removes only that incident from the aggregate.

A separate five-minute scheduled feed-heartbeat Job reuses the orchestrator identity but does not
consume queues or emit notifications. It independently reads every allowlisted workload signal and
refreshes only the signed aggregate index when the complete live health set matches the indexed
active incidents. It bootstraps a signed empty index when every approved resource is healthy. A
transition race or any live/index mismatch prevents the heartbeat from asserting freshness. The
browser accepts only an aggregate published within fifteen minutes, while incident state
timestamps remain event timestamps and may legitimately be older for a long-running outage.

The signed state includes the exact detector transition ID. A bounded
`incidents/<incident-id>/current.json` pointer references the latest immutable signed state for that
incident. This lets a retry after successful publication but failed enqueue reproduce the same
notification ID only when the current signed transition and actionable live lifecycle still match.
Hints carrying a newly minted transition ID remain no-ops.

The gateway and browser independently verify a separately pinned incident key ID, SHA-256
fingerprint, and public key. There is no fallback to the WC-013 lifecycle key or an unverified
payload.

The signed incident and aggregate index are published before notification enqueue. Notification
IDs are deterministic from transition ID and lifecycle. Messages use the incident ID as the Service
Bus session ID, preserving per-incident ordering. The Logic App body includes `notificationId`.
Before invoking it, the dispatcher obtains its Logic Apps managed-identity token, creates a
`reserved` notification record, and uses ETag compare-and-swap to transition it to `dispatching`
immediately before HTTP and `delivered` after a 2xx response. A redelivered `delivered` record
completes without reposting; a recoverable `reserved` record can be reacquired without concurrent
dispatch. A redelivered `dispatching` record is explicit uncertainty and is dead-lettered as
`AthenaNotificationDeliveryUncertain`, never silently completed or resent. HTTP 408 and 429 reset
to `reserved` before retry, while permanent 4xx and ambiguous network outcomes are dead-lettered.
Only expired `reserved` records are pruned; `dispatching` and `delivered` records remain durable.
This is at-most-once delivery with explicit uncertainty rather than an exactly-once claim. The
notification identity has no access to the detector state table. Signed incident state records
`pendingDispatch`, which describes notification intent without claiming that the later durable
enqueue or Teams delivery has completed.

## Trust-anchor rollout

`wc016RuntimeEnabled` defaults to `false`. The first deployment provisions the incident key,
container, detector state table, and hardened v2 detector, orchestrator, and notification identities
without creating WC-016 runtime role assignments, queues, or Jobs. Their Azure resource names end
in `-v2-id`; the four hardened Container Apps Jobs end in `-v2`. This prevents an incremental
deployment from updating the legacy Jobs in place or attaching their existing principals.

Incremental ARM deployment cannot prove removal of resources omitted from a newer template.
Therefore `scripts/audit-remove-wc016-legacy-runtime.ps1` is the mandatory migration boundary. It
defaults to read-only audit and has a fixed allowlist for the four legacy Jobs, three legacy queues,
six exact legacy metric alerts, three legacy identities, all role assignments belonging to those
deleted principals, and only the evidence identity's exact reassessment-queue sender assignment.
The evidence identity,
Service Bus namespace, Logic App, and unrelated resources are protected from deletion. Apply mode
performs exact-ID deletion followed by readback and emits a digest-bearing JSON report.

`wc016LegacyCleanupConfirmed` defaults to `false`. It may be set to `true` only after the cleanup
apply report records `zeroResidualReadback=true`. The operator then exports the deployed public key,
updates `wc016-incident-public-key.pem`, the browser JWK, and the pinned fingerprint, rebuilds the
delivery, presentation, detector, and orchestrator images, and verifies both public-key
representations match the deployed key. Only a reviewed second deployment may set both
`wc016LegacyCleanupConfirmed=true` and `wc016RuntimeEnabled=true`. Bicep fails activation if either
cleanup confirmation is absent or the checked-in fixture fingerprint remains. A mismatch stays
fail closed; it never falls back to lifecycle trust.

## Consequences

- Detection and orchestration use separate identities and separate live reads.
- Legacy runtime removal is explicit, exact-ID scoped, auditable, and required before activation.
- Queue replay reconciles current state for the queue's bounded lifetime.
- Multiple incidents remain independently visible.
- A separately scheduled, live-verified signed heartbeat makes stale or replayed aggregate feeds
  fail closed without expiring long-running incident states.
- Notification delivery follows signed incident truth and is durably idempotent.
- Athena remains private, keyless, least-privileged, and non-remediating.
