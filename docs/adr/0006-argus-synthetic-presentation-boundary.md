# ADR 0006: Export a synthetic-safe ARGUS presentation boundary

- **Status:** Proposed
- **Date:** 2026-08-20

## Context

The frozen `athena-web-node-fault.v1` demonstration needs a presentation artifact that ARGUS can
render without receiving Athena's evidence snapshot, Azure identifiers, collector identity
evidence, token claims, or customer-classified metadata. Athena's authoritative evaluation result
and `athena.demoFaultRun.v1` receipt both contain values that are required for verification but are
not safe to copy across that boundary.

The ARGUS consumer has frozen `athena.argus.presentation.v1`. It verifies a SHA-256 digest and a
detached RS256 signature over recursively sorted canonical JSON with `athena.resultDigest` excluded
from its own preimage. The presentation export must preserve those bytes exactly while failing
closed if either source artifact is untrusted or inconsistent with the requested lifecycle phase.

## Decision

Athena adds a closed, strict `athena.argus.presentation.v1` model and a pure projector for the
`athena-web-node-fault.v1` scenario.

Projection requires a nominal `VerifiedDemoEvaluationResult` capability. That capability is issued
only after:

1. a caller-configured trusted result verifier returns the exact supplied `DemoEvaluationResult`;
2. the existing cohort snapshot verifier recomputes the exact snapshot components, invokes a
   caller-configured trusted snapshot verifier, and binds the capability to the evaluation time;
3. all finding metadata and citations are bound to the result publication and snapshot.

The projector accepts one strict `athena.demoFaultRun.v1` receipt for every phase. A baseline uses a
confirmed `status` receipt but omits `faultRun` from the frozen payload. Faulted and recovered
phases require confirmed `inject` and `reset` receipts respectively. Receipt resource group,
eligible VM set, target resource ID, completion time, observed VM state, web-tier counts, and the
single operational-state finding must agree.

Only these source-derived values cross the boundary:

- manifest version;
- web-tier integer counts;
- source snapshot artifact and semantic digests;
- domain-separated SHA-256 synthetic identifiers for manifest, profile, resource group, snapshot,
  clause, VM, fault run, receipt, and evidence references.

All display text, finding summaries, predicted issues, risk levels, and recommended human actions
are fixed synthetic-safe strings. No source display name, resource ID, resource group name, VM
name, tenant or subscription GUID, Key Vault URL, token claim, raw evidence record, or source
finding text is copied.

`athena.resultDigest` is SHA-256 over the canonical UTF-8 presentation bytes with that field
excluded. Signature bytes remain outside the frozen payload in
`athena.argus.presentationAttestation.v1`. The signer interface accepts those exact bytes and is
structurally compatible with `KeyVaultRsaSigner.sign_preimage`; standard base64 signer output is
normalized to unpadded base64url for ARGUS. Independent verification rechecks the digest,
attestation metadata, and detached signature.

The CLI adds `argus-presentation-export`. It writes a new canonical payload file and a separate
canonical attestation file and refuses existing outputs. The command requires trusted result,
snapshot-verification, and signing ports from its composition root. An unconfigured standalone
command fails closed rather than treating a serialized result as proof of verification. This is an
export operation only; it does not inject, reset, or otherwise orchestrate a fault.

## Alternatives considered

### Copy selected fields directly from the result and receipt

Rejected. Allowlists based only on field names can still disclose resource names, Azure IDs, or
customer labels. Domain-separated hashes and fixed text make the output boundary explicit and
testable.

### Treat a valid `DemoEvaluationResult` model as a verified source

Rejected. Model validation proves internal digest consistency but does not prove the configured
trust anchor, collector identity, source response, or authoritative evaluation path. A nominal
capability backed by exact trusted verifier callbacks preserves that distinction.

### Embed the signature in `athena.argus.presentation.v1`

Rejected. It would change the frozen consumer contract and create a circular digest preimage.
Signature metadata remains in the payload; signature bytes use a detached attestation.

### Emit the real Key Vault key ID

Rejected. A Key Vault URL is an infrastructure identifier. The payload contains only a pinned
synthetic key alias while the signer retains the real non-exportable key identity internally.

## Security and operational consequences

- Projection performs no Azure reads and no workload mutation.
- Unknown states, evidence gaps, missing or ambiguous operational findings, incomplete redundancy,
  stale or mismatched receipts, and phase inconsistencies fail closed.
- Real identifiers are used only for in-process validation and hashing and are never copied into
  presentation text.
- Private key material is never accepted by the presentation contract or CLI. Production signing
  can use the existing managed-identity-backed Key Vault signer.
- Payload and attestation files are immutable create-only outputs. A partial payload is removed if
  attestation creation fails.

## Compatibility and rollback

The new models and command are additive. Existing Athena manifests, evaluations, snapshots, and
CLI commands are unchanged. ARGUS receives the exact frozen payload keys and detached base64url
signature shape.

Rollback removes the exporter, presentation contracts, and CLI subcommand. It does not rewrite
published Athena artifacts or fault receipts.

## Validation

Tests cover baseline, stopped and deallocated faulted states, recovered state, all three manifest
profiles, deterministic canonical JSON and synthetic hashes, independent deterministic RS256
verification, malformed and stale source inputs, unverified capabilities, citation mismatches,
unknown state, insufficient healthy nodes, phase/receipt mismatch, unsafe signing identifiers,
signature tampering, and create-only CLI export behavior.
