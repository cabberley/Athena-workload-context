# ADR 0008: Run reviewed operational phases through a non-mutating job boundary

- **Status:** Superseded by [ADR 0010](0010-progressive-operational-phase-completion-chain.md)
- **Date:** 2026-08-20

## Context

> This ADR records the original all-receipts-up-front design. ADR 0010 replaces that delivery
> model with progressive version-pinned inputs so baseline does not depend on future fault/reset
> receipts.

The `athena-web-node-fault.v1` demonstration needs three independently reviewable WC-013
evaluations: baseline, faulted, and recovered. Each evaluation consumes different observed Azure
state and must reserve a new attempt ID, snapshot ID, and idempotency key. A job that selects
configuration dynamically from arbitrary paths, reuses replay identities, trusts serialized
results without verification, or writes artifacts through an overwrite-capable adapter would
weaken the existing WC-013 and ARGUS boundaries.

Fault injection and reset are separate governed operator actions. Athena must consume their
confirmed `athena.demoFaultRun.v1` receipts, but this prerequisite must not stop, start, restart, or
otherwise mutate a workload resource.

## Decision

Add the closed `athena.operationalPhaseDeliveryBundle.v1` contract. It contains exactly one
baseline, faulted, and recovered configuration and a fixed `allowedPhases` value in that order.
Each phase pins:

- one portable relative WC-013 configuration file and its canonical SHA-256 digest;
- one portable relative fault receipt file and its canonical SHA-256 digest;
- the exact WC-013 attempt ID, snapshot ID, and idempotency key.

All three attempt IDs, snapshot IDs, idempotency keys, configuration paths, and receipt paths must
be unique. The bundle has its own canonical digest. The runtime selector accepts only `baseline`,
`faulted`, or `recovered`; it cannot select a path or add another lifecycle state.

The `operational-phase-runner` command performs these steps:

1. require injected trusted result and snapshot verifiers, a presentation signer, and a
   create-only artifact writer before reading the bundle;
2. validate the bundle digest and resolve all three phase files beneath the bundle directory;
3. validate every WC-013 plan and fault receipt digest, bind every plan's attempt, snapshot, and
   idempotency values to its bundle entry, and require the receipts to share one target/run lineage
   in baseline-faulted-recovered chronology;
4. execute the existing WC-013 one-shot path from the already parsed selected plan, without
   reopening its configuration file or enabling its direct snapshot-file output;
5. require the result snapshot and sole collector attempt to match the selected reviewed phase;
6. issue the existing `VerifiedDemoEvaluationResult` capability through full result and snapshot
   verification;
7. project the existing synthetic-safe ARGUS payload and sign its canonical preimage through the
   existing `PresentationSigner` interface, which is implemented by `KeyVaultRsaSigner`;
8. submit one five-artifact set to the injected create-only writer.

The five deterministic artifact names are:

```text
operational-demo/<phase>/demo-evaluation-result.json
operational-demo/<phase>/evidence-snapshot.json
operational-demo/<phase>/argus-presentation.json
operational-demo/<phase>/presentation-attestation.json
operational-demo/<phase>/phase-receipt.json
```

The compact `athena.operationalPhaseReceipt.v1` records bundle/configuration/receipt bindings,
replay identifiers, authoritative result and snapshot digests, presentation digest, and the exact
content digest of the first four output files. The runner result also reports the exact content
digest of the receipt file.

The writer is a port, not a storage implementation. Its `create_only` operation receives the
complete artifact set in one call and must reject any existing name. This change does not add or
modify a Blob, Files, Table, Bicep, or other infrastructure adapter.

## Security and operational consequences

- The runner performs no fault injection, reset, remediation, or other workload mutation.
- Path traversal, symlink escape, phase drift, digest drift, cross-phase target or chronology drift,
  replay-identity reuse, configuration replacement after validation, direct WC-013 file output,
  missing trust ports, and verifier/signer/writer failures fail closed.
- Full authoritative result and snapshot JSON remain inside the configured artifact boundary.
  Only the previously reviewed synthetic-safe projection is suitable for ARGUS.
- Console success output is limited to the allowlisted phase, snapshot identifier, and digests.
  Port exceptions and input payloads are not copied into logs.
- Production composition supplies the existing managed-identity-backed `KeyVaultRsaSigner`, trusted
  WC-013 result/snapshot verifiers, and a reviewed create-only artifact writer.

## Alternatives considered

### Let the runner invoke the external fault/reset workflow

Rejected. Combining mutation and evidence evaluation would collapse the operator approval,
receipt, and observation boundaries and would add remediation authority to Athena.

### Select an arbitrary configuration path at runtime

Rejected. A digest-pinned bundle and closed selector are required so a Job invocation can choose
only one previously reviewed phase.

### Write files directly from the CLI

Rejected. Production artifact durability and create-only semantics belong behind an injected port.
Adding a storage adapter here would broaden this prerequisite into infrastructure work.

### Reuse one WC-013 command with different receipts

Rejected. Durable replay protection intentionally requires a fresh attempt and request, and each
immutable snapshot must retain a unique identity.

## Compatibility and rollback

The contracts, runner module, and CLI subcommand are additive. Existing WC-013 execution and ARGUS
presentation export behavior are unchanged. Rollback removes the additive command and contracts;
it does not alter previously published evaluations or artifacts.

## Validation

Deterministic tests cover the closed selector and generated JSON Schema, phase/key binding, unique
attempt/snapshot/idempotency values, selected plan and receipt digest binding, all three phases,
five fixed artifact names and exact content digests, synthetic presentation safety, missing ports,
verifier and signer failures, writer failures, and payload-free failure messages.
