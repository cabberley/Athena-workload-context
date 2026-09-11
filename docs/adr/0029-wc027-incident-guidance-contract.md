# ADR 0029: Persist WC-027 guidance as a separate bounded asset

- **Status:** Proposed
- **Date:** 2026-09-11

## Context

WC-027 must present evidence-bound investigation and manual-resolution guidance without inflating
the signed incident-state asset or treating generated text as published authority. WC-026 reports
can contain up to 64 hypotheses and extensive evidence, while the incident-state publication path
has a 64-KiB bound and legacy consumers parse an exact v1 shape.

Confidence alone is insufficient to authorize a manual action. Guidance must also respect the exact
published guidance selection, competing causes, missing evidence, and the no-runbook outcome.

## Decision

`IncidentGuidance.v1` is a separate immutable, maximum-64-KiB projection. It binds the exact
incident subject, incident-bound request, WC-026 report, evidence inventory, rule catalog, published
guidance authority, authority binding, and selected/no-runbook outcome through
`IncidentGuidanceSourceBinding`.

The guidance asset contains bounded structured sections for:

- affected role and impact;
- evidence-backed timeline;
- exact ranked hypothesis summaries;
- confirmation and read-only investigation checks;
- safe human-only manual options;
- rollback considerations;
- recovery validation;
- escalation;
- runbook references; and
- missing evidence and action-legality reasons.

Every timeline entry, step, link, source binding, guidance object, and asset reference uses
deterministic ordering and digest-bound identifiers. Evidence references must resolve in the exact
WC-026 request. Runbook and option references must match the selected published guidance option.
Guidance steps use a closed catalog of reviewed template codes plus bounded display parameters;
free-form action instructions are not accepted by the contract. Template parameters are typed
resource, path, evidence, option, or role identifiers and must resolve inside the exact signed
binding. Impact statements and runbook labels are closed codes derived from signed incident state.
Runbook authority contracts advance to v2 before first runtime use so every reference carries an
immutable version and content digest; later readers must verify fetched bytes.

Action legality is enforced by contract:

- Unknown, Low, and Medium guidance is read-only and requires confirmation plus investigation.
- High guidance may expose a reference-only approved runbook but cannot include manual or rollback
  instructions.
- Manual and rollback instructions require Confirmed confidence and explicit authority from the
  selected option.
- A no-runbook selection contains no runbook links or manual/rollback actions and requires an
  escalation step.
- `noAutoRemediation=true` is invariant.

`IncidentGuidanceAttestation.v1` signs the guidance digest.
`IncidentGuidanceAssetReference.v1` binds exact immutable guidance and attestation paths beneath the
signed incident-state version. Full report, authority, and guidance remain separate assets.
Validation requires trusted-key signature verifiers for both the guidance-authority binding and the
guidance asset attestation before trust elevation.

## Consequences

- Existing IncidentState v1, notification v1, and active-feed readers remain unchanged.
- Later IncidentState v2 can reference compact guidance/report assets rather than embed them.
- Lower-confidence guidance cannot become prescriptive through a renderer or notification.
- The contract does not generate guidance, publish assets, render UI, send Teams messages, or
  execute remediation.

## Alternatives considered

- **Embed the full report and guidance in IncidentState:** rejected because it exceeds existing
  bounds and breaks v1 readers.
- **Use free-form generated text:** rejected because action legality and provenance would not be
  machine-verifiable.
- **Treat all selected runbooks as executable:** rejected because selection is reference authority,
  not execution authorization.

## Validation

- Tests cover no-runbook read-only guidance and Confirmed human-only options.
- Source/report/evidence/runbook substitutions fail.
- Canonical byte budget and asset paths are enforced.
- Existing WC-027 authority/subject, WC-026 contract, and WC-005 golden-proof tests remain green.
