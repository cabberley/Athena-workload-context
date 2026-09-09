# ADR 0022: Bind Context Studio workflows to durable lifecycle authority

- **Status:** Proposed
- **Date:** 2026-09-08

## Context

Context Studio must support complete manifest review and editing without becoming an alternative
authority path. It also needs durable cohort decisions, exact version comparison, and rollback
without mutating published versions. Observed and inferred topology must remain visibly distinct
from declared intent.

## Decision

Context Studio uses the existing authenticated Context API lifecycle and cohort routes. The browser
holds no publication authority, Azure Reader role, or direct persistence credentials.

Production cohort routes are hosted through the explicit `apps/cohort-api` composition boundary.
The repository-owned production factory builds one shared durable lifecycle/proposal/decision
graph and loads only narrow deployment-owned trusted snapshot, verifier, and durable cache ports.
Studio requires an explicit `cohortApiBaseUrl`; no endpoint fallback or fake default service is
allowed. The cohort application removes lifecycle mutation, publication, comparison, and audit
routes from its router. Lifecycle, proposal, and decision services share one store, clock, and
authorization adapter identity.

- Full-manifest edits retain the canonical shape, immutable manifest identity, and candidate
  version. The browser recomputes digests, and the server performs final schema, concurrency, and
  authorization validation.
- Submission is followed by a separate persisted human Review decision. Review records the exact
  revision/digest, comments, rejected JSON-pointer fields, and required corrections. Approval is
  refused without the current approved Review decision; requested corrections return the draft to
  editing without deleting review history.
- Cohort approve, reject, split, and merge actions use durable decision endpoints. Approved
  selector changes and their decision record commit atomically; rejection remains authoritative for
  the exact proposal-set version.
- Published versions are immutable. Comparison names two exact versions. Rollback records an exact
  older `rollback_source_version`, clones its content and selector authority, and creates a new
  higher-version draft linked to the current active predecessor.
- Declared, observed, inferred, and exception relationships use distinct view contracts and styles.
  Observed or inferred records require evidence references and confidence; their absence is shown as
  an evidence gap.
- Review gaps and field provenance identify the exact draft revision or published version under
  review. Missing owner, criticality, confidence, validation, or runbook data is never defaulted to a
  healthy state.
- Observed/inferred relationships and findings enter through an explicit host-provided
  WC-026/WC-028 port. Studio validates workload, version, profile, snapshot, evidence, and confidence
  bindings before merging them into the lifecycle view; an absent port remains a visible evidence
  gap. The binding names the exact profile ID, draft ID and revision, manifest and resolved-profile
  digests, collection/expiry times, and an integrity-bound evidence inventory. Expiry immediately
  clears only operational data, preserves unsaved manifest edits, and blocks approval/publication
  until refresh.
- The trusted operational integration exchanges that validated snapshot for a compact immutable
  Context API receipt through a service-only route. The issuer has only exact-workload read and
  receipt-issuance authority. Context API recomputes the evidence inventory and binding digests,
  resolves the current profile itself, persists only digests/counts rather than raw evidence, and
  atomically revalidates the receipt during approval or publication. Approval and publication each
  require a receipt for their own exact draft revision. The operational port returns the complete
  server receipt metadata and digest beside the rendered snapshot; Studio verifies exact snapshot,
  binding, inventory, rendered-content, issuer, time, receipt-digest, and deterministic receipt-ID
  equality before enabling approval.
- Interrupted successor publication is reconstructed from persisted predecessor/successor lineage
  after browser reload so exact supersession recovery remains available.
- Large cohort decisions and selector baselines are stored as integrity-bound chunk entities under
  the Azure Table state anchor. Compact receipts point to the exact decision digest instead of
  duplicating the full authority record. A missing legacy selector baseline is committed and
  revalidated in a prerequisite transaction before the bounded decision transaction, so two
  independently maximal chunked records cannot exceed Azure Table's 100-operation batch limit.
- Existing pre-WC-023 drafts receive an immutable selector-baseline backfill from their validated
  canonical content before their next governed mutation; backfill is refused after cohort decisions
  or when the stored digest is invalid.
- Async proposal previews, decisions, workload loads, and operational refreshes carry monotonic
  request generations so late results, including A-to-B-to-A races, cannot appear under another
  review context.

## Consequences

- Draft editing, validation, approval, publication, supersession, and rollback remain human-governed
  and workload-scoped.
- Cohort proposals cannot bypass lifecycle approval or publish directly.
- Rollback preserves history and auditability by producing a new version.
- Runtime monitoring configuration is unaffected until a separately governed reconciliation
  workflow consumes an exact published version.

## Validation

Python tests cover durable decision persistence, overlap and rejection authority, atomic selector
application, authoritative Review decisions, service-only operational receipt issuance, atomic
approval/publication receipt validation, concrete production composition, route authorization,
and exact lifecycle concurrency. Web tests cover production
decision transport, complete manifest editing, relationship classes, evidence-gap rendering,
expiry without edit loss, A-to-B-to-A stale response rejection, version comparison,
rollback-by-new-version, keyboard interaction, responsive behavior, and automated accessibility.
