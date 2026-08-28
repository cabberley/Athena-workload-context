# ADR 0015: Add a standalone verified Athena presentation web boundary

- **Status:** Proposed
- **Date:** 2026-08-28

## Context

The synthetic `athena-web-node-fault.v1` lifecycle has frozen
`athena.argus.presentation.v1` payloads and detached
`athena.argus.presentationAttestation.v1` signatures. A temporary ARGUS feature branch rendered
these artifacts, but Athena needs a standalone presentation surface so ARGUS `main` remains
Overlake-only.

A static browser cannot be allowed to discover Azure resources, select arbitrary artifacts, trust
an unsigned payload, or partially render a lifecycle before verification completes.

## Decision

Add `apps/presentation-web/`, an independent strict TypeScript, React, and Vite application.

The browser consumes only same-origin reviewed JSON assets. A new app-local
`athena.presentationWeb.runtime.v1` manifest contains exactly three ordered phase entries and one
reviewed public-key entry. Its paths are bounded relative JSON paths and its SHA-256 values bind
the exact hosted bytes. The app-local manifest does not modify or wrap the frozen presentation
payloads and attestations.

The public key asset contains an RS256 verification-only JWK, its synthetic key ID, and a SHA-256
fingerprint over DER SPKI bytes. The same key ID and fingerprint are pinned in application code.

Startup fetches and verifies the complete asset set before rendering lifecycle data. Verification
enforces:

- same-origin URLs, no redirects, timeouts, response byte bounds, JSON content type, and fatal
  UTF-8 decoding;
- exact object keys, contract value allowlists, synthetic identifiers, phase semantics, and frozen
  display text;
- RFC 8785-compatible canonical result digests;
- detached RS256 signatures with Web Crypto;
- payload, attestation, key ID, and SPKI fingerprint binding;
- phase-distinct snapshot identifiers and artifact, semantic, and result digests; and
- common workload, expected-node, clause, and fault/reset lineage across
  baseline-to-faulted-to-recovered.

Blast radius and impact are pure post-verification derivations over signed phase, service, node,
fault/reset, verdict, and risk fields. Unsupported or inconsistent combinations fail closed. The
application makes no Azure SDK, Blob, ARM, MCP, storage, or workload request and has no mutation
authority.

## Consequences

- ARGUS can remove or abandon its temporary Athena-specific feature without adding Athena
  contracts to ARGUS `main`.
- Static hosting must preserve reviewed JSON bytes and serve them from the application origin.
- Replacing an asset requires review of its exact file digest; replacing the key also requires an
  application change to the pinned SPKI fingerprint.
- Runtime-manifest compromise cannot substitute an attacker key because the trust anchor remains
  compiled into the application.
- The included fixtures remain clearly synthetic presentation artifacts, not authoritative Azure
  evidence.

## Alternatives considered

### Fetch phase artifacts directly from Blob Storage

Rejected. It would add direct cloud access, storage URLs, CORS, and artifact-selection ambiguity to
the browser boundary.

### Embed payloads and signatures in the JavaScript bundle

Rejected. Separate reviewed static artifacts preserve the export boundary and make hosting-byte
digests explicit without mutating frozen contracts.

### Trust only runtime-manifest file hashes

Rejected. A same-origin manifest and assets can be replaced together. Detached RS256 verification
against a separately pinned key fingerprint remains the authenticity anchor.

## Validation

Vitest and Testing Library cover canonicalization, valid and tampered signatures, wrong keys,
schema and byte bounds, same-origin enforcement, lifecycle consistency, blast-radius and impact
derivations, fail-closed rendering, keyboard focus, accessibility, and successful rendering of all
three phases. CI validates this app independently and retains the existing Context Studio gates.
