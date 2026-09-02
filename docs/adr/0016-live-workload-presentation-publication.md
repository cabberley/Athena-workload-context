# ADR 0016: Publish verified live lifecycle assets through a private sidecar

- **Status:** Proposed
- **Date:** 2026-09-02

## Context

The operational phase Jobs already create exact version-pinned
`argus-presentation.json` and `presentation-attestation.json` artifacts in the immutable
`operational-artifacts` container. The external operator independently verifies the completion
chain, source envelopes, snapshots, results, projected presentation payloads, and detached
signatures for baseline, faulted, and recovered.

The standalone presentation web previously consumed only reviewed static v1 fixtures. A live view
must not give the browser Azure credentials, Blob URLs, SAS tokens, container listing, arbitrary
artifact selection, or access to the immutable operational artifact plane.

## Decision

Extend the already verified operator boundary with an optional reviewed `presentationPublisher`
configuration. After recovered-phase verification succeeds, the operator publishes only the six
verified presentation payload/attestation byte sequences to a dedicated private
`presentation-assets` container. Run assets use create-only writes under
`live/runs/<runId>/<phase>/`. The operator then performs one overwrite of
`runtime-manifest.json`; a single Blob PUT is the atomic current-pointer replacement. Failed or
partial run publication never changes the previous current pointer.

The current pointer uses strict `athena.presentationWeb.runtime.v2` with classification
`live-workload-evaluation`, run ID, target resource group, UTC publication time, the reviewed
static public-key path/key ID/SPKI fingerprint/content digest, and exactly the ordered baseline,
faulted, and recovered payload/attestation paths and SHA-256 content digests. The operator requires
all verified phase receipts to target the same case-insensitive resource-group name and requires
the operator verification key to match the browser-pinned SPKI fingerprint.

Keep `operational-artifacts` unchanged and WORM-protected. Create `presentation-assets` as private
and non-WORM on the same version-enabled, private-endpoint Storage account. Operator principals
retain Blob Data Reader on `operational-artifacts` and receive Blob Data Contributor only on
`presentation-assets`. The presentation identity receives Blob Data Reader only on
`presentation-assets`; it receives no access to `operational-artifacts`.

Add `athena-context presentation-asset-gateway` to the digest-pinned WC-013 delivery image. The
stdlib HTTP sidecar listens on port 8081, authenticates with the presentation managed identity,
and performs no Blob listing or write. It serves only `/healthz`, the current
`/runtime-manifest.json`, and `/live/runs/...` paths present in the currently revalidated v2
manifest. Every Blob transfer is bounded, requires JSON media type and matching digest metadata,
and is rehashed before response. Errors are generic.

NGINX retains the application security headers and static `/trust/...` key. It proxies only the
exact current manifest and `/live/` prefix to localhost, so the browser remains same-origin.

The browser supports existing v1 static fixtures and v2 live manifests. For v2 it hashes
`athena-web-node-fault.v1\0rg\0<casefolded targetResourceGroup>` with SHA-256 and requires every
signed payload to contain `synthetic-rg-<hex>`. No live lifecycle is rendered until all content
digests, signatures, lifecycle relationships, key pins, and resource-group bindings verify.

## Consequences

- No public Blob access, CORS, SAS, account key, browser credential, or direct browser Azure call
  is introduced.
- A partially uploaded run is unreachable because the current pointer is written last. Those
  create-only blobs remain as immutable run evidence and the same run ID cannot silently replace
  them.
- If publication fails after reset and recovered verification, the operator exits unsuccessfully
  and explicitly reports that reset succeeded.
- If no current manifest exists, the gateway returns a generic unavailable response and the
  browser withholds the lifecycle. If an older pointer remains after a failed new publication, its
  visible publication time makes that staleness explicit rather than selecting partial assets.
- Blob account versioning also records pointer replacement history, while the logical pointer
  remains intentionally overwriteable.
- The presentation identity boundary expands from ACR pull only to ACR pull plus container-scoped
  Blob Data Reader, without access to operational artifacts or workload resources.
- Existing operator configurations without `presentationPublisher` and existing v1 fixture tests
  retain their previous behavior.

## Alternatives considered

### Let the browser read Blob Storage directly

Rejected because it requires public/CORS exposure, a token or SAS flow, and browser-side artifact
selection.

### Let the presentation identity read operational-artifacts

Rejected because that container contains broader control/evidence-plane artifacts and is an
immutable operator verification boundary, not a presentation delivery plane.

### Copy assets before verification or update the pointer first

Rejected because either approach can expose unverified or incomplete lifecycle data.

### Make presentation-assets WORM

Rejected because the small current manifest pointer must be atomically replaceable. Run-scoped
assets remain immutable through create-only names while Storage account versioning protects
pointer history.

## Validation

Python tests cover strict v2 contracts, exact run paths, create-only asset writes, pointer-last
overwrite, managed-identity Blob reads, generic gateway errors, method/path allowlists, digest
revalidation, optional operator compatibility, publication ordering, and post-reset failure
reporting. TypeScript tests cover v1 and v2 loading, resource-group hash binding, metadata
exposure, fail-closed mismatches, and live UI labels. Bicep/config tests prove private non-WORM
container creation, exact container-scoped roles, sidecar composition, digest-pinned delivery
image validation, and absence of presentation access to `operational-artifacts`.
