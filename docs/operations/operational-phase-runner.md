# Operational phase runner

The operational phase runner is the non-mutating Job prerequisite for the
`athena-web-node-fault.v1` baseline, faulted, and recovered evidence sequence. It runs exactly one
reviewed WC-013 configuration, consumes the separately produced fault/status/reset receipt, and
writes a complete immutable artifact set. It does **not** inject or reset the fault.

See [ADR 0007](../adr/0007-operational-phase-runner-boundary.md).

## Responsibility boundary

The external operator workflow is responsible for:

1. confirming the healthy baseline and producing a `status` receipt;
2. injecting the reviewed web-node power-state fault and producing an `inject` receipt; and
3. resetting the same node and producing a `reset` receipt.

The phase runner only reads one of those receipts after it has been placed in the reviewed delivery
bundle. It has no interface for start, stop, restart, deallocate, deployment, or reset operations.

## Reviewed delivery layout

Use a single read-only delivery root. Paths in the bundle are portable relative paths and may not
escape this root.

```text
delivery/
  operational-phase-bundle.json
  configs/
    baseline.json
    faulted.json
    recovered.json
  receipts/
    baseline.json
    faulted.json
    recovered.json
  ...the WC-007, WC-008, and public-key files referenced by each WC-013 plan...
```

`operational-phase-bundle.json` uses
`schemaVersion = athena.operationalPhaseDeliveryBundle.v1` and contains:

```json
{
  "schemaVersion": "athena.operationalPhaseDeliveryBundle.v1",
  "scenarioId": "athena-web-node-fault.v1",
  "allowedPhases": ["baseline", "faulted", "recovered"],
  "syntheticPresentationKeyId": "synthetic-key://athena-argus-demo/rs256-v1",
  "configurations": {
    "baseline": {
      "phase": "baseline",
      "wc013ConfigurationFile": "configs/baseline.json",
      "wc013ConfigurationDigest": "sha256:<canonical-plan-digest>",
      "faultReceiptFile": "receipts/baseline.json",
      "faultReceiptDigest": "sha256:<canonical-receipt-digest>",
      "attemptId": "attempt-<12-lowercase-hex>",
      "snapshotId": "snap-<12-lowercase-hex>",
      "idempotencyKey": "<unique-reviewed-value>"
    },
    "faulted": {
      "phase": "faulted",
      "wc013ConfigurationFile": "configs/faulted.json",
      "wc013ConfigurationDigest": "sha256:<canonical-plan-digest>",
      "faultReceiptFile": "receipts/faulted.json",
      "faultReceiptDigest": "sha256:<canonical-receipt-digest>",
      "attemptId": "attempt-<different-12-lowercase-hex>",
      "snapshotId": "snap-<different-12-lowercase-hex>",
      "idempotencyKey": "<different-reviewed-value>"
    },
    "recovered": {
      "phase": "recovered",
      "wc013ConfigurationFile": "configs/recovered.json",
      "wc013ConfigurationDigest": "sha256:<canonical-plan-digest>",
      "faultReceiptFile": "receipts/recovered.json",
      "faultReceiptDigest": "sha256:<canonical-receipt-digest>",
      "attemptId": "attempt-<different-12-lowercase-hex>",
      "snapshotId": "snap-<different-12-lowercase-hex>",
      "idempotencyKey": "<different-reviewed-value>"
    }
  },
  "bundleDigest": "sha256:<canonical-bundle-digest>"
}
```

Build and validate the bundle through `OperationalPhaseConfiguration`,
`OperationalPhaseConfigurations`, and `build_operational_phase_delivery_bundle`; do not calculate
digests with pretty-printed JSON bytes or hand-edit the final digest.

Each phase plan must retain all WC-013 prerequisites described in
[WC-013 live acceptance](wc013-live-acceptance.md). The bundle adds another review layer; it does
not replace WC-007 authority, WC-008 deployment approval, Key Vault trust, or replay-table
protection.

All three receipts must describe the same fault-run ID, resource group, prefix, target VM, exact VM
resource ID, and eligible web-node set. Their timestamps must be ordered baseline, faulted,
recovered. The recovered receipt's before-state must equal the faulted receipt's confirmed
after-state, so a recovery cannot be signed for a different node or unrelated fault.

## Job composition

The Job composition root must inject:

- a `TrustedDemoEvaluationVerifier` for the complete WC-013 result;
- a `TrustedSnapshotVerifier` for the exact `EvidenceSnapshot`;
- the existing `KeyVaultRsaSigner` through the `PresentationSigner` interface; and
- a `CreateOnlyArtifactWriterPort` whose `create_only` implementation preflights and creates the
  full five-artifact set without overwriting an existing name.

The standalone command intentionally fails closed when those ports are absent. No storage adapter
or Key Vault credential is accepted from command-line arguments.

Invoke one allowlisted phase:

```powershell
athena-context operational-phase-runner `
  --bundle $configurationRoot\operational-phase-bundle.json `
  --phase baseline
```

Repeat only after the external workflow has completed the next reviewed action and delivered its
receipt:

```powershell
athena-context operational-phase-runner `
  --bundle $configurationRoot\operational-phase-bundle.json `
  --phase faulted

athena-context operational-phase-runner `
  --bundle $configurationRoot\operational-phase-bundle.json `
  --phase recovered
```

Do not retry a post-reservation WC-013 failure with the same phase configuration. Render and review
a replacement configuration with new attempt, snapshot, and idempotency values, then rebuild the
bundle digest.

## Artifact set

For `<phase>` equal to `baseline`, `faulted`, or `recovered`, the writer receives:

```text
operational-demo/<phase>/demo-evaluation-result.json
operational-demo/<phase>/evidence-snapshot.json
operational-demo/<phase>/argus-presentation.json
operational-demo/<phase>/presentation-attestation.json
operational-demo/<phase>/phase-receipt.json
```

Every request includes the SHA-256 digest of the exact UTF-8 bytes. The compact phase receipt binds
the reviewed inputs to the authoritative result/snapshot digests, presentation digest, and first
four artifact content digests. The runner reports the receipt file's content digest after the
create-only call succeeds.

## Expected logging

Success output contains only:

- the allowlisted phase;
- the snapshot identifier;
- result digest;
- presentation digest; and
- receipt content digest.

No result JSON, evidence record, Azure resource ID, resource name, receipt payload, exception
payload, token claim, or signature is written to stdout or stderr.

## Fail-closed checks

The Job must fail without calling the writer when:

- the selector is not one of the three allowlisted phases;
- the bundle, WC-013 plan, or fault receipt digest changes;
- a selected file is missing or escapes the delivery root;
- any unselected phase file is missing, invalid, or no longer digest-bound;
- attempt, snapshot, or idempotency values do not match the selected plan;
- replay values are reused across phases;
- the receipt action does not match `status`, `inject`, or `reset` for the selected phase;
- the three receipts do not share one target/run lineage and ordered power-state sequence;
- the selected plan file changes after validation (execution uses the already parsed model);
- WC-013 writes a direct snapshot output instead of returning in memory;
- the full result or snapshot verifier rejects the exact object;
- presentation projection or Key Vault signing fails; or
- the create-only writer cannot persist the complete artifact set.
