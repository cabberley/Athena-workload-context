# ADR 0011: Orchestrate the operational demonstration through an external fail-closed operator

- **Status:** Proposed
- **Date:** 2026-08-20

## Context

ADR 0010 allows Athena to run one reviewed baseline, faulted, or recovered phase once the exact
receipt and prior completion data are supplied. What is still missing is the outer operator that
proves the workload was healthy before baseline, invokes the governed workload mutation path,
starts the reviewed phase Job, retrieves the exact completion index produced by that Job, and
verifies every run-scoped artifact before reporting success.

That outer loop must not collapse boundaries:

- Athena remains non-mutating.
- Workload mutation remains inside a workload-owned executable or script.
- Container Apps Job execution remains a separate governed runtime boundary.
- ARGUS remains presentation-only and cannot become the source of truth for Azure identity,
  resource, or receipt data.

The operator also needs an explicit human confirmation step. A generic "yes" would make it too
easy to replay the wrong reviewed run or a stale bundle.

## Decision

Add a new external CLI command:

```text
athena-context operational-demo-operator
```

The command reads a bounded `athena.operationalDemoOperator.v1` configuration file. The reviewed
configuration pins:

- the synthetic scenario and run ID;
- the reviewed phase-delivery bundle;
- the presentation verification public key;
- one workload controller executable for fixed `status`, `inject`, and `reset` actions;
- one phase-job controller executable for fixed `start`, `status`, and `handoff` verbs; and
- one exact-version Blob reader configuration.

`--validate-only` performs only local file parsing and contract validation. It prints a compact
synthetic-safe plan and one exact per-run confirmation phrase. No credential, network, Azure,
subprocess, or injected-port call is allowed in that mode.

Live execution requires the exact confirmation phrase. The operator then:

1. proves the workload is healthy and running through a bounded `status` receipt;
2. runs the baseline phase Job and verifies its completion index plus every indexed artifact by
   exact name, version, and SHA-256;
3. invokes the bounded `inject` action;
4. runs the faulted phase Job and verifies the exact artifact chain;
5. always attempts `reset` after `inject` was attempted, even when injection or the faulted phase
   failed ambiguously; and
6. runs the recovered phase only after a confirmed successful reset.

The phase-job controller returns an exact execution ID and later an
`athena.operationalPhaseReferenceHandoff.v1` document containing the exact completion-index Blob
reference. The operator never lists Blob versions or selects "latest". It reads only the version
and hash named by the handoff and completion index.

Artifact verification reuses existing contracts and APIs:

- `OperationalPhaseCompletionIndex` for run, phase, lineage, chronology, and digest-chain
  continuity;
- `verify_wc013_live_result` plus `verify_demo_evaluation_result` for the stored WC-013 result and
  snapshot binding; and
- `project_argus_presentation` plus `verify_presentation_attestation` for the stored synthetic
  ARGUS payload and detached signature.

The standalone `operational-phase-runner` command gains an optional `--handoff-output` file so the
phase Job can emit the governed reference handoff needed by the external operator.

## Consequences

- Athena still performs no workload mutation.
- The workload controller owns all status, inject, and reset side effects.
- A baseline failure before injection never triggers reset.
- A reset failure is surfaced separately and blocks recovery.
- A combined faulted/reset failure preserves both failures in the final operator result.
- Console output remains compact and synthetic-safe: run ID, phase, synthetic snapshot IDs,
  digests, verdicts, and reset status only.
- Azure IDs, resource-group names, VM names, command stdout/stderr, tokens, paths, and raw
  boundary exceptions stay out of user-facing output.

## Alternatives considered

### Let Athena perform injection and reset directly

Rejected. That would give Athena mutation authority and would bypass the workload-owned operational
controls.

### Let the operator read the latest completion index or artifact version

Rejected. The demonstration must remain replay-safe and exact-version governed. Listing or "latest"
selection would weaken provenance and make ambiguity hard to detect.

### Trust the ARGUS payload without re-verifying the result and snapshot

Rejected. ARGUS is synthetic-safe presentation only. The operator must verify the exact Athena
artifacts first and only then accept the projection.

## Compatibility and rollback

The operator CLI, its contracts, and the phase handoff file are additive. Existing golden proof,
WC-013 live acceptance, ARGUS export, and single-phase runner flows remain unchanged. Rollback
removes the additive operator and handoff features without changing previously written immutable
artifacts.

## Validation

Deterministic tests cover:

- validate-only with no side effects;
- exact confirmation enforcement;
- status -> baseline -> inject -> faulted -> reset -> recovered ordering;
- baseline failure with no reset;
- ambiguous inject with forced reset;
- faulted failure with reset;
- reset failure blocking recovery;
- combined primary/reset failure reporting;
- bounded phase status timeout, failed, and unknown terminal states;
- exact-version reads and no list/latest behavior;
- completion-index lineage and digest-chain mismatch rejection;
- presentation-attestation integrity verification; and
- output/error redaction.
