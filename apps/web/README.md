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
  cohortApiBaseUrl: 'https://cohort-api.example.invalid',
  authPort: {
    acquireSession: async () => enterpriseSessionAdapter.currentSession(),
    acquireAccessToken: async (session) =>
      enterpriseSessionAdapter.acquirePerUserAccessToken(session),
  },
}
```

`cohortApiBaseUrl` may be omitted when the cohort routes are hosted with the Context API.
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

## Cohort review boundary

Context Studio has a typed, authenticated WC-010 proposal port and HTTP adapter. Production
composition never imports the synthetic proposal adapter. The production API dependency is tracked
by [issue #31](https://github.com/cabberley/Athena-workload-context/issues/31); until those routes
exist, opening **Cohorts** reports the API failure and does not invent proposal or approval state.

The narrow adapter uses:

- `GET /v1/cohort-proposals` with exact `manifest_id`, `manifest_version`, `profile_id`, `draft_id`,
  `expected_revision`, and `expected_digest` query bindings.
- `POST /v1/cohort-proposals/preview` for server-generated `split` and `merge` previews. The command
  carries the same draft binding, proposal-set and snapshot digests, proposal IDs, a bounded
  resolution rationale, source role references, and an idempotency key.

Proposal responses remain non-authoritative: `requiresHumanReview` must be `true`, while
`publicationAllowed` and `manifestMutated` must be `false`. The adapter checks workload scope,
draft binding, confidence invariants, snapshot binding, selector limits, and an 8 MiB response
boundary. It reduces evidence references to counts and never retains or renders raw evidence or log
bodies. The proposal service must consume a verified snapshot server-side; neither the browser
identity nor the Athena context identity receives workload Reader access.

The review view shows environment, manifest version, approval state, evidence snapshot, confidence
band, support, dissent, conflicts, rejected candidates, selector preview, and digests. Member details
are filterable and paginated 25 at a time; there is no per-resource editor. Medium, low,
conflicting, cross-environment, split, and merge actions require a bounded rationale and explicit
acknowledgement. Rejection is visibly session-only until a server decision endpoint exists.

A confirmed cohort approval is available only to a verified human `proposer`. It calls WC-007
`PUT /v1/drafts/{draft_id}` with the exact revision/version/digest and a stable idempotency key,
adding only profile-scoped bounded role selectors. The cohort flow never calls validate, lifecycle
approve, publish, or supersede.

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
