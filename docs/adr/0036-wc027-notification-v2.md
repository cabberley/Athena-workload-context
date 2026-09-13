# ADR 0036: Bind Teams notifications to verified WC-027 enrichment

- **Status:** Proposed
- **Date:** 2026-09-13

## Context

Incident notification v1 remains the deployed lifecycle notification contract. WC-027 adds signed
guidance through a derivative feed, but that feed cannot create, resolve, or hide incidents. A
Teams message must not claim verified guidance from an untrusted, stale, or mismatched enrichment.

## Decision

Add a signed `IncidentNotification.v2` envelope that is produced only after independently verifying:

- the fresh signed v1 active index and signed v2 active/recently-resolved index;
- exact version-pinned occurrence state, pointer, attestations, and occurrence digest;
- the signed feed pointer and its exact index entry;
- the signed enrichment manifest, correlation report, and guidance assets; and
- lifecycle consistency with the v1 authority.

The notification binds the exact feed-index digest, immutable feed references, enrichment and
guidance references, incident-specific presentation fragment, and a concise non-remediating Teams
message. Its ID is deterministic from the immutable lifecycle, occurrence, and guidance authority,
so a routine newly signed feed-index head does not create a duplicate notification identity.
Service Bus continues to use the incident ID as the session ID.

The dispatcher accepts v1 unchanged. V2 requires a pinned signing key and rejects unsigned or
tampered envelopes. Durable delivery reservations suppress replay after success. HTTP 408, 429, and
5xx responses reset the reservation and abandon the queue message for retry; ambiguous network
outcomes remain dead-lettered to avoid duplicate sends.

WC-016 does not deploy the WC-027 enrichment/feed-index producer. Notification v2 activation
depends on that separately governed producer committing the exact immutable enrichment pointer and
signed `incidents/feed-v2.json` head after the winning v1 active-index publication. Missing or
lagging feed-v2 authority is explicitly source-not-ready: the orchestrator and dispatcher retry in
place while `AutoLockRenewer` retains the Service Bus session lock, preserving per-incident order.
If that bounded window expires, they abandon for a later delivery rather than explicitly
dead-lettering the message as invalid. No retry synthesizes feed data or downgrades the notification.
A signed refresh of the feed head is tolerated only when the immutable lifecycle, occurrence, feed
pointer, enrichment, and guidance authority still match.

## Consequences

- V1 remains the lifecycle authority and remains byte-compatible.
- V2 is never silently downgraded to a successful v1 guidance notification.
- Active and recently resolved notifications remain discoverable only through the verified v2
  feed while retaining per-incident ordering.
- Deployment remains integration-blocked until the separately governed WC-027 feed-v2 producer is
  present and healthy; the deployment gate defaults notification v2 off until that is confirmed.
- Teams receives no remediation command or execution authorization.

## Validation

Adversarial tests cover immutable asset tampering, stale and untrusted feeds, lifecycle mismatch,
deep-link substitution, replay/idempotency, per-incident ordering, transient retry, and resolved
rendering.
