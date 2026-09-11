# ADR 0028: Publish immutable WC-027 guidance authority

- **Status:** Proposed
- **Date:** 2026-09-11

ADR 0029 advances the pre-runtime guidance authority wire contracts to v2 so runbook references
carry immutable versions and content digests.

## Context

WC-027 guidance may cite manual options and runbooks only when they are part of exact published
workload context and applicable to the affected role, cause, path, action, and confidence. The
existing `ManualFailoverRunbookControl` does not carry that complete applicability, review-expiry,
URI-policy, or execution-authorization boundary.

Adding fields to the existing WC-026 publication authority would break strict request v2 readers
and change completed context and correlation digests.

## Decision

WC-027 introduces an outer immutable `PublishedGuidanceAuthority.v1` and
`PublishedGuidanceAuthorityBinding.v1`.

The authority binds the exact published context identity and authority reference plus zero or more
deterministic runbook guidance options. Each option carries:

- exact manifest/profile/clause/owner provenance;
- cause, role, path, action, and minimum-confidence applicability;
- a safe HTTPS or approved opaque runbook reference;
- control health, review time, review expiry; and
- `executionAuthorizationRequired=true`.

A zero-option authority is valid only with signed deterministic no-runbook reasons. Until a future manifest-authoring prerequisite introduces a
fully applicable operator-guidance control, legacy `manualFailoverRunbook` controls are not
promoted and guidance must select a structured `noRunbook` outcome.

The binding wraps the merged WC-027 incident-bound request and exact WC-026 report without changing
either contract. It validates the report as published runtime output, binds an immutable authority
Blob named `guidance-authority/{authorityId}/authority.json`, checks context identity, and records
either:

- one exact effective, unexpired, applicable selected option; or
- one explicit no-runbook reason.

No-runbook selection is rejected when any effective, unexpired, applicable option exists, and its
reason must match the signed authority omissions or deterministic option failures. All freshness
checks use one binding evaluation time that cannot predate the correlation report and must remain
inside the request validity window.

Prescriptive manual or rollback actions require Confirmed confidence, no material Medium-or-higher
competing hypothesis, and no explicit competing-cause contradiction. Every
binding carries a domain-separated detached-signature preimage digest. This prerequisite defines
contracts only; later production code must read exact Blob versions and verify signatures,
publication state, audit continuity, owner authority, and freshness.

## Consequences

- WC-026 request/report and WC-027 incident-subject contracts remain unchanged.
- No runbook is safer and valid when authority is absent, stale, unhealthy, inapplicable, or too
  weakly supported.
- Renderers may open only validated HTTPS references. Opaque references remain display-only.
- Athena still does not execute runbooks or remediation.
- Manifest authoring must later add an applicable operator-guidance control before production
  authorities can contain selectable options.

## Alternatives considered

- **Extend `PublishedContextAuthority`:** rejected because it would break WC-026 request v2.
- **Use legacy failover controls directly:** rejected because they lack cause, role, path, action,
  expiry, and authorization applicability.
- **Allow generated fallback runbooks:** rejected because observed or generated text is not
  published human-owned intent.

## Validation

- Contract tests cover safe and unsafe references, applicability and confidence rules, option
  health and expiry, context/Blob/report cross-binding, selected-option legality, draft rejection,
  and valid zero-option/no-runbook authority.
- WC-027 subject, WC-026 contract, and WC-005 golden-proof tests remain green.
