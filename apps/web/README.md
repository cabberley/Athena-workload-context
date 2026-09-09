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
  operationalContextPort: {
    loadOperationalContext: async ({ workloadId, manifestVersion, profileId }) =>
      trustedCorrelationAdapter.loadExactSnapshot({
        workloadId,
        manifestVersion,
        profileId,
      }),
  },
}
```

`cohortApiBaseUrl` is always required. A deployment may deliberately set it to the same origin as
`apiBaseUrl`, but Studio never infers that routing decision.
`acquireSession` must return verified actor metadata and explicit `authorizedWorkloadIds`.
`acquireAccessToken` obtains a per-user token just in time for each request. A missing session,
workload scope, or token fails closed before workload data is rendered.
The optional operational port is the production WC-026/WC-028 boundary for observed/inferred
relationships and findings. Its response is rejected unless every record matches the exact
workload, manifest version, profile, snapshot, evidence-reference, and confidence contract. When
the port is absent, Studio shows an explicit evidence gap and does not fabricate operational data;
approval and publication remain disabled. The trusted adapter must return a non-empty evidence
inventory plus the complete receipt metadata and digest issued by Context API's service-only
operational receipt route for that exact draft revision and canonical production profile. Studio
canonicalizes the rendered evidence source, confidence, relationships, and findings, then verifies
that content digest, the evidence inventory, full receipt digest, and deterministic receipt ID
before enabling lifecycle authority.

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
- The full canonical manifest can be edited through a bounded JSON section editor. Manifest
  identity and candidate version are immutable in the browser, and every save still passes through
  WC-007 canonical validation and optimistic concurrency.
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
- Exact version comparison uses `GET /v1/manifests/{manifest_id}/compare`; rollback clones a selected
  older immutable version into a new higher-version draft whose predecessor is the current active
  publication. The command records `rollback_source_version`; existing versions are never mutated
  or reactivated.
- Relationship rendering distinguishes `declared`, `observed`, `inferred`, and `exception` records.
  Exceptions render their governance fields; observed and inferred records require cited evidence
  and confidence. Missing runtime findings or confidence are displayed as evidence gaps, never pass.
- Controls expose explicit unknowns, missing declarations, and field provenance for the exact draft
  revision or published version being reviewed.
- Agent sessions cannot approve or publish. Human users must explicitly confirm review of the exact
  candidate digest, then record a durable human Review decision with comments and any rejected
  fields/corrections. Approval requires that exact current approved Review. Each approval and
  publication also sends the current operational receipt ID; both Review and approval increment
  the draft revision, so fresh operational receipts are required.
- Error rendering is bounded and never displays unrestricted non-JSON response or log bodies.

The mock adapter is under `src/test/` and is imported only by tests.

## Cohort review boundary

Context Studio has a typed, authenticated WC-010 proposal port and HTTP adapter. Production
composition never imports the synthetic proposal adapter. The merged WC-031 API supplies the
proposal and split/merge preview routes; a missing, stale, malformed, or out-of-scope response fails
closed without inventing proposal or approval state.

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
acknowledgement. Direct approval requires an existing bounded selector preview; low or conflicting
proposals without one may still request a server-generated split preview. A rejection is accepted
only as a visible durable decision; local session-only rejection is not treated as authority.

The production adapter uses the authenticated durable-decision routes:

- `GET /v1/cohort-proposals/decisions` with the exact draft, profile, proposal-set, proposal IDs,
  and evidence snapshot binding.
- `POST /v1/cohort-proposals/decisions` with the complete bounded rationale and exact candidate.

Decisions and selector-only draft mutation commit atomically in the Context API store. Rejections
are durable and block later actions for the same proposal authority. No browser path performs a
direct WC-007 replacement for cohort apply.

The decision flow sends the complete bounded 1–2,000 character rationale to the durable decision
record. Context Studio never concatenates that rationale or a proposal list into a WC-007
`ReplaceDraftCommand.reason`, and it never calls WC-007 directly for cohort apply. The merged
decision service must atomically add only profile-scoped bounded role selectors and keep the
WC-007 reason at 500 characters or fewer with its durable decision ID. The cohort flow never calls
validate, lifecycle approve, publish, or supersede.

Before submitting an apply decision, the browser verifies that selector-preview members form a
normalized, duplicate-free, disjoint union exactly equal to the source proposal members, with exact
per-role member counts and `maxMatches` bounds.

The browser also validates that every split/merge response from the merged route is the exact
normalized source-member union before it can reach the WC-007 draft boundary.
Persisted rejection immediately clears cached previews and disables approve, split, merge, and
apply; decision state is reloaded for the exact draft, proposal-set, and snapshot binding.

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
