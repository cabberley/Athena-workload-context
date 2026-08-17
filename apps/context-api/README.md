# Context API

This ASGI service is the sole authoritative writer for workload manifests. It exposes idempotent,
optimistically concurrent draft, validation, review, human approval, publication, supersession,
comparison, and audit operations.

The default composition root intentionally rejects every credential and has no grants. A
deployment must inject an authentication port that verifies Entra/JWT credentials before returning
typed actor claims, plus manifest-scoped role grants. `X-Athena-Actor` and other caller-supplied
identity assertions are never trusted. Agent actors are denied approval, publication, and
supersession even if they are accidentally granted a privileged role.

Published manifest values are immutable. Supersession is stored as a separate append-only relation.
Submission replaces untrusted draft audit values with a server-finalized publication candidate and
recomputes canonical digests. Human approval binds that exact candidate; publication does not
mutate it.

## WC-013 bounded demo evaluation

An explicitly composed Context API may expose `POST /v1/demo-evaluations` and
`GET /v1/demo-evaluations/{snapshot_id}`. The default composition does not expose these routes.
The mutation requires verified human publisher authority, an active trusted human approval
decision, an idempotency key, exact published canonical manifest/profile digests, and one explicit
authorized evidence scope.

The integration composes the merged components without introducing direct Azure access:

- A trusted WC-008 configuration port verifies a bounded deployment-output assertion against a
  separately pinned human operator decision. The assertion binds the exact endpoint, managed
  environment and Container App resource IDs, internal/private ingress flags, separate identity
  IDs, Azure MCP 2.0.5 image digest, seven-tool allowlist/catalog hash, and explicit read scopes.
  A hostname suffix or caller-supplied private flag is never treated as proof of private ingress.
- `PrivateMcpEvidenceTransport` owns that immutable verified configuration and derives the endpoint
  used by its injected invoker from it; no independent endpoint label can be supplied. It
  maps the WC-009 semantic inventory operation to WC-008's exact `group_resource_list` deployment
  tool. The service rejects composition unless the actual transport configuration exactly equals
  the separately loaded trusted WC-008 configuration.
- WC-009 validates tool identity, trust evidence, freshness, schema, count, size, and scope before
  the Context API sees evidence.
- The app-owned `ContextService` resolves WC-007 context, approvals, and evaluation grants before
  collection directly through its configured persistence transaction. `DemoEvaluationService`
  has no commit, resolver, approval, authorization, store, lock, or backend adapter injection
  point. The evaluation rejects missing, ambiguous, or superseded context and requires every
  applicable weakening override and resolved risk acceptance to be approved and active before MCP
  collection. The service never renews, edits, approves, or publishes a manifest on an agent's
  behalf.
- WC-007 profile IDs are bounded NFC+casefold-normalized strings rather than a closed environment
  enum. The selected ID must resolve in the published manifest; manifest-defined IDs such as
  `prod-east` use the same canonical inheritance and governance checks.
- `ContextService` exposes no public evaluation commit or caller-constructible commit candidate.
  During app-owned composition it pins the exact operator-trusted WC-008 configuration and
  collector trust into the same persistence backend that owns publication. For each request it
  issues a private, single-use orchestration handle whose immutable actor, command, idempotency
  input, collection authority, and pre-collection authority token remain in a service-private
  registry. Fabricated, reused, or foreign handles fail before a transaction is opened.
  The service-owned final operation opens the actual configured persistence transaction and
  creates a narrow transaction-scoped unit of work from that exact transaction. It reads the
  active unsuperseded WC-007 context revision/ETag,
  approval revision/status/expiry, publisher grant revision, and context-reader identity/grant
  revision, canonically resolves the complete profile inheritance chain, and compares typed
  authority tokens captured before collection. Both publisher and reader authorization are read
  from the transaction-owned grant state; no independently locked reader authorization can
  authorize an evaluation.
  Signing-key trust is also versioned state in that exact transaction, not a caller-advertised or
  independently mutable resolver. After every persistence delay, the conditional operation loads
  the exact configured key anchor and compares its revision and digest with the pre-collection
  authority token. Disabled, retired, expired, revoked, missing, or changed key trust aborts the
  transaction. After persistence delay and exact key-revision comparison, the transaction performs
  the delay-capable cryptographic verification and authoritative WC-004 evaluation. Only after
  that work returns does preparation return immutable data rather than executable behavior.
  Persistence then re-resolves and compares the complete context/profile, approval, publisher
  grant, reader grant, key trust, snapshot/envelope binding, inherited governance, risk authority,
  and all associated revisions and digests from the transaction's current local state. No
  Pydantic/model equality participates in those comparisons: every token is reconstructed as
  exact base primitive values, so polymorphic equality cannot hide a grant revision or digest
  change. Key identity, status, revision, digest, and temporal bounds are likewise sealed before
  the final clock sample; no caller-derived key-record property is read afterward. No
  overridable hook receives the active unit of work. A mutation staged through that same unit of
  work during preparation therefore aborts and rolls back with the artifact and receipt.
  Persistence independently reconstructs its WC-008 Reader authority from its own pinned
  configuration. It requires the signed snapshot ID, sole collector attempt ID, exact authorized
  scope, bounded transport request, request digest, freshness/timeout/size/count limits, source
  envelope, collector identity claims, evidence identity resource, and Reader assignment revision
  to match the service-issued command exactly. A valid signature from another snapshot, attempt,
  scope, identity, assignment revision, or collection bound has no publication authority.
  Persistence computes the idempotency request digest and complete candidate digest itself from
  transaction-resolved authority and normalized evidence; neither digest is accepted from a
  caller or prepared artifact. It then independently reverifies the exact RSA snapshot/envelope
  proof against the transaction-owned key and recomputes WC-004 findings rather than trusting a
  prepared artifact.
  Before obtaining its authoritative insertion timestamp it removes caller model subclasses,
  canonicalizes the snapshot/scope/envelope, constructs every digest, validates and round-trips
  the publication/result schemas, and packages base-model-only immutable storage material.
  It then obtains its authoritative insertion timestamp and runs its own sealed, bounded, no-I/O
  finalizer. No caller-supplied callback, model serialization, canonicalization, cryptography, or
  policy work runs after the timestamp. The finalizer revalidates the already loaded exact approval,
  complete profile governance and risk acceptances, bound key trust, snapshot expiry, and every
  policy evidence-freshness bound at that exact value. Prepared findings are accepted only when
  they exactly equal the persistence-recomputed findings and are proven temporally unchanged at
  insertion; the same value is used for `publishedAt` and `evaluatedAt`. No hook, authority read, trust lookup, cryptographic
  operation, policy evaluator, or independently supplied persistence call can run between
  timestamp acquisition and insertion. Timestamp-dependent JSON and digests are deterministic
  projections of the immutable committed columns and are rendered only after the transaction has
  committed, so output serialization cannot backdate the state change.
  The operation inserts the idempotency receipt, snapshot, source envelope, publication, and final
  recomputed result as one state change. No independently supplied commit capability can redirect
  publication to a foreign store. The store binds one opaque root capability to its owning
  `ContextService`; only the service can exchange it, after full validation, for a transaction-local
  single-use permit bound to that transaction entry's unique epoch. Every exit invalidates all
  permits, including aborted transactions, so inactive, cross-epoch, or re-entry reuse fails. The
  public transaction surface has no general evaluation-artifact write, and fabricated permits or
  prepared artifacts fail before callbacks or state mutation. The HTTP composition root accepts only non-authoritative
  evidence/configuration/signing dependencies and constructs the demo service with the exact
  app-owned `ContextService`; preconstructed demo services are rejected.

  Context, approval, evaluation-grant, signing-key trust, receipt, and artifact operations are
  methods on the same unit of work. The in-memory store owns its commit clock, lock, and key-trust
  revision, samples time only after its persistence-delay seam, and snapshots and commits all six
  state sets under that lock, including rollback on failure. Production implementations must
  obtain authoritative database time and provide the same key-revision comparison and conditional
  finalization on the transaction returned by the actual Context API persistence adapter or one
  equivalent database conditional batch. Object identity, advertised backend equality, and nested
  independently locked registries are not accepted as evidence of atomicity. Approval
  revoke/expiry, inherited override or risk-acceptance expiry,
  supersession, authorization removal, or revision change after evaluation leaves no artifact.
  Authority tokens bind whether the caller selected an exact version or the unique active version.
  A unique-active commit repeats that lookup with no version inside the transaction, so a
  concurrently published second active version aborts rather than silently pinning the first.
- Pure snapshot assembly computes canonical component digests. A trusted signing port supplies the
  RS256 attestation; production composition must back it with the configured versioned Key Vault
  key and managed identity rather than key material in configuration.
- A typed artifact store atomically appends the canonical snapshot, source envelope, human-bound
  publication record, exact findings, and idempotency receipt only after cryptographic verification
  and authoritative WC-004 evaluation of the resolved canonical profile succeeds.

Authorization failure, stale or malformed output, endpoint/tool unavailability, scope mismatch,
gaps, inactive governance, missing or ambiguous context, superseded context, signature failure, or
policy-evaluation failure produces no publication.
The context identity configuration forbids Azure workload roles. The MCP identity configuration
permits only reviewed read roles and forbids Context API permissions.

The deterministic tests use a clearly synthetic endpoint, operator-pinned configuration port, and
fake invoker. The WC-005 golden fixture is evaluated only at its historical June 2025 proof time.
A separate 2026 test creates a new synthetic manifest version with bounded governance dates and
publishes it through the complete WC-007 proposer, validation, review, human approval, and
human-authorized publication lifecycle.

The optional live authentication probe is marked `live` and skipped unless explicitly enabled. The
live path requires an exact published context identity in addition to bounded WC-008 assertion and
operator-approval JSON files. Full evaluation composition must resolve this selection through
WC-007 and rejects an expired, missing, ambiguous, or superseded selection:

```powershell
$env:ATHENA_WC013_LIVE = '1'
$env:ATHENA_WC013_WC008_DEPLOYMENT_ASSERTION_FILE = '<bounded WC-008 assertion JSON>'
$env:ATHENA_WC013_WC008_OPERATOR_APPROVAL_FILE = '<operator approval JSON>'
$env:ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST = 'sha256:<exact assertion digest>'
$env:ATHENA_WC013_MANIFEST_ID = '<active published manifest ID>'
$env:ATHENA_WC013_MANIFEST_VERSION = '<active published manifest version>'
$env:ATHENA_WC013_PROFILE_ID = '<active profile ID>'
$env:ATHENA_WC013_CONTEXT_API_ENDPOINT = 'https://<private-context-api-origin>'
$env:ATHENA_WC013_CONTEXT_API_AUDIENCE = 'api://<context-api-app-id>'
python -m pytest tests/test_wc013_live.py -m live
```

Before accessing MCP, the live path uses `DefaultAzureCredential` to resolve that exact selection
from the authoritative Context API and rejects missing, expired, malformed, or superseded context.
The Context API reader rejects every HTTP redirect, so its managed-identity bearer token is sent
only to the configured HTTPS origin and is never forwarded to another host or downgraded scheme.
The probe then sends only an unauthenticated synthetic `tools/list` request and requires HTTP 401
or 403. It does not deploy resources, collect workload evidence, or use customer data.

## Cohort proposal routes

- `GET /v1/cohort-proposals` resolves one exact active draft/profile binding, retrieves an
  immutable workload-scoped snapshot through a typed repository port, cryptographically verifies
  it through the trusted verifier port, and returns the bounded WC-010 batch with `sourceDraft`.
- `POST /v1/cohort-proposals/preview` accepts only exact split/merge bindings and returns
  deterministic selector-only candidates. It never mutates a manifest, validates a draft,
  approves, or publishes.

Both routes require a verified human identity and a concrete workload grant; wildcard grants do
not cross this boundary. Deployments must inject the snapshot repository, cryptographic verifier,
immutable proposal cache, and actor-scoped idempotency receipt ports. The default composition
contains no evidence and grants no access.

The literal `*` is reserved and is never a valid manifest or workload identifier at an HTTP or
command boundary. Cross-workload WC-007 access uses the typed `AllWorkloadsGrantScope`; cohort
routes require an exact `WorkloadGrantScope`.
