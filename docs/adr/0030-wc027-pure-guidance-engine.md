# ADR 0030: Generate WC-027 guidance with a pure closed-template engine

- **Status:** Proposed
- **Date:** 2026-09-11

## Context

WC-027 must turn a verified correlation result and published guidance authority into useful
operator guidance without allowing model-generated prose, low-confidence prescription, or
automatic remediation. Guidance must remain deterministic and small enough to persist separately
from the incident state.

## Decision

`build_incident_guidance` is a pure domain function. It accepts one exact
`PublishedGuidanceAuthorityBinding` and emits one `IncidentGuidance.v1`. It performs no Azure,
storage, MCP, HTTP, clock, signing, publishing, or notification I/O.

The engine:

- reuses the contract-defined source, impact, hypothesis, and legality projections;
- constructs a bounded timeline from exact incident, supporting, and recovery evidence;
- selects only reviewed template codes and binding-resolved identifier parameters;
- maps root-cause categories to deterministic confirmation and investigation templates;
- emits recovery validation only when recovery gates cite evidence;
- emits runbook links only for High or Confirmed selected-runbook authority;
- emits manual or rollback steps only when the binding-derived legality authorizes the exact
  requested action;
- emits escalation for no-runbook, lower-confidence, missing-evidence, or competing-cause cases;
- preserves the exact union of report missing-evidence codes; and
- fails rather than truncating required hypotheses, evidence, or guidance beyond contract bounds.

Recovery guidance is derived only from a satisfied recovery gate on the top-ranked hypothesis.
Recovery evidence belonging only to a competing hypothesis is not attributed to the top cause.

Unknown, Low, and Medium guidance is read-only. High guidance remains confirmation-oriented.
Confirmed guidance may expose human-only options, but every option retains
`requiresAuthorization=true` and `noAutoRemediation=true`.

## Consequences

- Guidance behavior is deterministic and independently testable.
- Text rendering is deferred to reviewed templates in presentation and notification layers.
- The pure engine cannot verify signatures or publish assets; a later atomic service must verify
  the incident subject, correlation report, and guidance authority, construct guidance internally
  with this engine, and rederive and byte-compare the canonical guidance before signing and
  persistence. Contract binding validation alone does not establish canonical producer output.
- Category policy changes require code review and deterministic regression updates.

## Alternatives considered

- **Generate prose with an LLM:** rejected because wording could bypass confidence and authority
  controls.
- **Embed guidance in the correlation engine:** rejected to keep causal scoring independent from
  operator action policy.
- **Silently truncate oversized guidance:** rejected because omitted hypotheses or evidence would
  change the operator judgment surface.

## Validation

- Golden category and confidence scenarios cover network, guest, backend, deployment, unknown,
  recovery, no-runbook, selected-runbook, competing-cause, and authorized manual actions.
- Repeated and permuted inputs produce identical guidance digests.
- Contract binding and canonical byte limits are exercised before release.
