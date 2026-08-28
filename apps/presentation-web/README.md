# Athena standalone presentation web

This Vite application presents the already-proven synthetic
`athena-web-node-fault.v1` lifecycle without adding a browser-to-Azure path. It is intentionally
separate from ARGUS so ARGUS `main` can remain Overlake-only.

## Trust boundary

The browser reads only same-origin static JSON:

1. `runtime-manifest.json`, a closed `athena.presentationWeb.runtime.v1` file;
2. one frozen `athena.argus.presentation.v1` payload per lifecycle phase;
3. one detached `athena.argus.presentationAttestation.v1` per payload; and
4. one reviewed RSA verification-only JWK.

The runtime manifest may select only `baseline`, `faulted`, and `recovered`, in that order. Every
path is bounded and relative, every file has a reviewed SHA-256 content digest, and the key ID plus
SHA-256 SPKI fingerprint are pinned in both the manifest and application code. The manifest does
not alter either frozen Python contract.

Before any lifecycle data is rendered, the browser:

- enforces byte limits, timeouts, `application/json`, fatal UTF-8 decoding, and same-origin URLs;
- applies exact-key schemas, value allowlists, phase semantics, and synthetic-only identifiers;
- recomputes the RFC 8785-compatible presentation result digest with `athena.resultDigest`
  excluded;
- verifies the detached RS256 signature through Web Crypto;
- binds payload, attestation, reviewed key ID, and SPKI fingerprint;
- validates phase-distinct snapshot artifact, semantic, and result digests; and
- validates one baseline-to-faulted-to-recovered workload, clause, node-count, and fault/reset
  lineage.

Any failure withholds the complete lifecycle. The app has no Azure SDK, Blob, ARM, MCP, storage
credential, direct cloud call, mutation, or remediation capability.

## Synthetic fixtures

The files under `public/fixtures/` preserve the exact frozen payload and detached signature values
from the deterministic Athena presentation proof. They are clearly synthetic and contain no
customer identifiers. Do not hand-edit a payload, attestation, or public key.

To publish a newly reviewed export:

1. generate each payload and detached attestation through Athena's existing trusted presentation
   exporter;
2. place only the synthetic-safe outputs under `public/fixtures/`;
3. publish the corresponding verification-only RSA public key under `public/trust/`;
4. independently review the key ID and SHA-256 digest of its DER SPKI representation;
5. update the runtime manifest's exact file SHA-256 values; and
6. run every local validation command below.

The host must serve the built directory without JSON transformation, with
`Content-Type: application/json`, over the same HTTPS origin as `index.html`. It must not rewrite
asset requests to HTML. The included CSP limits scripts, styles, and connections to the same
origin. The hosting layer should additionally send `Content-Security-Policy:
frame-ancestors 'none'`, because browsers do not enforce that directive from an HTML meta tag.

## Local development

```text
cd apps/presentation-web
npm ci
npm run test
npm run typecheck
npm run lint
npm run build
npm audit --audit-level=high
```

Use `npm run dev` for local viewing. Static hosting can publish `dist/` at an origin root or
sub-path because the Vite build uses relative URLs.

## Display derivations

Blast radius and impact are derived only after verification:

- baseline plus zero faulted nodes: `none-active`;
- faulted plus exactly one stopped node and at least one running peer: `contained-web-tier`;
- recovered plus zero faulted nodes and a signed running reset state: `resolved`;
- healthy/recovered: availability `normal`;
- degraded redundancy: availability `warning`;
- zero/one faulted node: redundancy `full`/`reduced`; and
- operator attention: only the signed `riskLevel` (`normal`/`warning`).

The UI never infers database, worker, load-balancer, geographic, or customer impact.
