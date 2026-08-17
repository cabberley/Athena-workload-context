# Athena Context Studio

Context Studio is the accessible WC-011 browser client for the authoritative WC-007 manifest
lifecycle.

## Runtime authentication

Production has no fixture, default workload, global lifecycle cache, actor environment variable, or
Vite bearer token. The authenticated host must inject `window.athenaContextStudioRuntime` before the
application module runs:

```ts
window.athenaContextStudioRuntime = {
  apiBaseUrl: 'https://context-api.example.invalid',
  authPort: {
    acquireSession: async () => enterpriseSessionAdapter.currentSession(),
    acquireAccessToken: async (session) =>
      enterpriseSessionAdapter.acquirePerUserAccessToken(session),
  },
}
```

`acquireSession` must return verified actor metadata and explicit `authorizedWorkloadIds`.
`acquireAccessToken` obtains a per-user token just in time for each request. A missing session,
workload scope, or token fails closed before workload data is rendered.

Startup reads each authorized workload only through:

- `GET /v1/drafts?manifest_id={authorized_workload_id}`
- `GET /v1/manifests/{authorized_workload_id}/versions`

The client never uses unrestricted `GET /v1/drafts`.

## Contract and governance behavior

- WC-007 record and command members use exact `snake_case`.
- The nested WC-001 `CanonicalWorkloadManifest` retains its canonical `camelCase` aliases and every
  section.
- Structured edits are mapped onto a clone of the full manifest. Artifact and semantic digests use
  Python-compatible default materialization and sorting, RFC 8785 canonical JSON, Unicode NFC and
  case folding, Web Crypto SHA-256, and Python fixture reference digests.
- `manifestDigest` is never added to a canonical manifest. WC-007's required top-level
  `manifest_digest` and `replacement_digest` command members carry the computed artifact digest.
- Published list responses are unwrapped from `{ published, supersession }`. A successor requires
  one unsuperseded predecessor, no active draft, an unused higher version, an exact
  `previous_version`, and a newly computed digest.
- Publishing a successor immediately calls
  `POST /v1/manifests/{manifest_id}/versions/{predecessor_version}/supersede` with the predecessor
  revision/version/digest and successor version/digest. Reload must confirm one active version.
  If publication succeeds but supersession fails or cannot be verified, the UI enters a blocking
  recovery state and retries the same command with its original idempotency key.
- Canonical relationships are a discriminated `declared | exception` union. Exceptions render
  their target, risk acceptance, governance scope, rationale, owner, and expiry; they never receive
  fabricated endpoint or relationship-kind fields.
- Authority, provenance, observed relationships, and confidence are never invented. Missing
  WC-007 evidence or confidence is displayed as not provided.
- Agent sessions cannot approve or publish. Human users must explicitly confirm review of the exact
  candidate digest before approval and publication.
- Error rendering is bounded and never displays unrestricted non-JSON response or log bodies.

The mock adapter is under `src/test/` and is imported only by tests.

## Local validation

```bash
cd apps/web
npm ci
npm run test
npm run typecheck
npm run lint
npm run build
npm audit --audit-level=high
```
