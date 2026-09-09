# Context API

This ASGI service is the sole authoritative writer for workload manifests. It exposes idempotent,
optimistically concurrent draft, validation, review, human approval, publication, supersession,
comparison, and audit operations.

The test/default composition intentionally rejects every credential and has no grants.
`apps/context-api/main.py` is the production composition root; it configures Entra/JWT
authentication and deployment-owned exact-workload role grants before exposing the API.
`X-Athena-Actor` and other caller-supplied identity assertions are never trusted. Service actors
are denied approval, publication, and supersession even if they are accidentally granted a
privileged role.

Published manifest values are immutable. Supersession is stored as a separate append-only relation.
Submission replaces untrusted draft audit values with a server-finalized publication candidate and
recomputes canonical digests. Human approval binds that exact candidate; publication does not
mutate it. Approval and publication also require a current server-verifiable operational-context
receipt for the exact draft revision and canonical production profile.

`POST /v1/drafts/{draft_id}/review` is a distinct human-only reviewer operation between submission
and approval. It stores the exact revision/digest, decision, comments, rejected JSON-pointer
fields, and required corrections. An approved review advances the in-review revision and is linked
from the later approval. A changes-requested review returns the candidate to draft state while
retaining the immutable review history. Browser confirmation is never review authority.

## Operational-context receipts

`POST /v1/operational-context-receipts` is the sole receipt-issuance route. It accepts only a
verified service actor with the exact-workload `operational_context_issuer` role. The trusted
WC-026/WC-028 integration submits the complete bounded evidence inventory plus its canonical
digest and the operational binding digest. Context API independently verifies:

- the current draft ID, revision, manifest version, and manifest digest;
- the server-resolved active profile ID and resolved-profile digest;
- collection/expiry time and current freshness;
- unique bounded evidence references and their inventory digest; and
- the canonical rendered-content digest covering evidence source, confidence,
  relationships, and findings; and
- the exact snapshot and binding digest used by Context Studio.

The durable receipt stores the exact authority binding, evidence count, inventory digest, and
rendered-content digest and expiry, but not raw operational evidence. Approve and publish commands
require its receipt ID and revalidate it inside the same persistence transaction as the lifecycle
mutation. Because approval increments the draft revision, publication requires a newly issued
receipt for the approved revision. Pre-existing published records without these optional
provenance fields remain readable; all new approval and publication mutations require receipts.

## Durable production persistence

`apps/context-api/main.py` is the production ASGI root. It refuses startup unless these
deployment-provided settings select the dedicated Azure Table context store:

- `ATHENA_CONTEXT_STORE_ENDPOINT`
- `ATHENA_CONTEXT_STORE_TABLE_NAME`
- `ATHENA_CONTEXT_STORE_PARTITION_KEY`
- `ATHENA_CONTEXT_IDENTITY_CLIENT_ID`
- `ATHENA_CONTEXT_STORE_WORKLOAD_ID`
- `ATHENA_CONTEXT_AUTH_TENANT_ID`
- `ATHENA_CONTEXT_AUTH_AUDIENCE`
- `ATHENA_CONTEXT_AUTH_DELEGATED_SCOPE`
- `ATHENA_CONTEXT_ROLE_GRANTS_JSON`

`ATHENA_CONTEXT_AUTH_TENANT_ID` must be the deployment's Entra tenant GUID.
`ATHENA_CONTEXT_AUTH_AUDIENCE` is the exact Context API resource audience. The API accepts only
bounded RS256 tokens resolved from that tenant's v2 JWKS endpoint, with the exact v2 issuer,
audience, `exp`, `nbf`, `iat`, `tid`, `sub`, and `oid` claims verified. A delegated token must
contain the exact deployment-owned `ATHENA_CONTEXT_AUTH_DELEGATED_SCOPE` value in its signed
space-delimited `scp` claim; the optional `idtyp=user` claim is accepted but not required.
Ordinary delegated identities map the lower-case Entra object ID (`oid`) to a human actor, while
signed Entra agent-identity facet claims map the same subject to an agent so it cannot satisfy
human-only approval, publication, or supersession checks. A signed `idtyp=app` token maps to a
service actor, requires one consistent signed application client ID, and cannot contain a
delegated scope. Any conflicting or unknown identity shape fails closed.

`ATHENA_CONTEXT_ROLE_GRANTS_JSON` is a UTF-8 JSON array of one to 64 `RoleGrant` objects and is
deployment configuration, never request input. Every grant must explicitly use
`{"scope_type":"workload","workload_id":"<ATHENA_CONTEXT_STORE_WORKLOAD_ID>"}`; omitted or
`all_workloads` scopes, duplicates, empty arrays, invalid JSON, and foreign workload grants fail
startup. The configured workload ID also bounds the durable adapter: it rejects any lifecycle
record or read for another workload. Workload identifiers use the same route-safe ASCII contract
as the HTTP API. The operational evidence service must receive only the
`operational_context_issuer` role for the configured workload; that role can read exact lifecycle
authority and issue receipts, but cannot approve, publish, supersede, or edit manifests.

An empty partition is never a normal store state. On the controlled first deployment only, an
operator runs `python apps/context-api/bootstrap.py` as a one-shot deployment step under the
Context API managed identity. That command invokes the explicit `initialize_empty_partition`
operation and exits after creating the generation-one state-row continuity root. Normal API
startup never has bootstrap authority and rejects the obsolete
`ATHENA_CONTEXT_STORE_BOOTSTRAP_ENABLED` setting. It validates the complete committed partition
and fails closed if the continuity root is absent, so a deleted complete partition cannot become a
new store merely because an API replica restarts. Run the bootstrap step before starting scaled
API replicas, then retain its deployment record with the initial state-anchor checkpoint.

The Table and its private networking and data-plane RBAC are provisioned separately. The API uses
only the supplied managed identity; it does not accept connection strings, create the table, or
give Context MCP, presentation, agent, or evidence identities direct store write access. The
partition is dedicated to one Context API deployment so a manifest mutation, idempotency receipt,
and linked audit event commit as one conditional Azure Table batch. A stale writer receives a
conflict without a partial commit. Each commit also replaces an ETag-protected state anchor over
the complete partition record set and audit tail, so deleted immutable rows or a truncated audit
history fail closed on the next load. Lifecycle row keys never expose logical identifiers: each
untrusted component is represented by a domain-separated canonical SHA-256 digest, while original
identifiers remain in the canonical `recordJson` and are verified against the same derivation on
load. `recordJson` uses the 60 KiB operational margin measured as UTF-16LE bytes (without a BOM),
which matches Azure Table `Edm.String` property encoding limits rather than UTF-8 byte length.

This adapter deliberately stores exactly one workload in one atomic Azure Table partition, so
drafts, receipts, publication provenance, supersessions, and audit events retain single-batch
semantics. It emits a capacity warning at 3,584 entities (87.5% of the 4,096 hard limit) on
startup/read and attempted commits. The operational alert contract is the warning event
`athena_context_store_capacity_warning`, with `workload_id`, `entity_count`, `capacity`, and a
required migration action; deployments must route that event to their normal operational alerting.
Before the hard limit, operators must approve a retention/cutover plan. It must freeze writers,
verify and retain the old partition's state-anchor checkpoint, and leave that partition
read-only—never delete or prune rows from the active audit chain. A successor per-workload shard
requires a separately reviewed adapter and explicit continuity record/resolver before it accepts
writes; this adapter does not silently replay history or invent cross-partition transactions.
Demo-evaluation approvals, findings, receipts, and artifacts are outside `ContextStorePort`, are
not migrated by this adapter, and the production root deliberately does not compose demo
evaluation routes on this store.

## WC-013 bounded demo evaluation

An explicitly composed Context API may expose `POST /v1/demo-evaluations` and
`GET /v1/demo-evaluations/{snapshot_id}`. The default composition does not expose these routes.
The mutation requires verified human publisher authority, an active trusted human approval
decision, an idempotency key, exact published canonical manifest/profile digests, and one explicit
authorized evidence scope.

Configured deployments also expose idempotent approval create/revoke operations and an
approval read route. Approval input contains intent only: the Context API derives `approvedBy`
from the verified human actor, obtains `approvedAt` from its injected authoritative clock, fixes
the initial revision, and derives private endpoint and evidence-identity binding from the pinned
WC-008 configuration. Caller-supplied provenance is rejected. Approval reads first load the
authoritative decision and then require current audit authority for that stored workload, so a
foreign-workload grant or a revoked grant cannot disclose approval metadata, even after
publication.

The integration composes the merged components without introducing direct Azure access:

- A trusted WC-008 configuration port verifies a bounded deployment-output assertion against a
  separately pinned human operator decision. The assertion binds the exact endpoint, managed
  environment and Container App resource IDs, internal/private ingress flags, separate identity
  IDs, Azure MCP 2.0.5 image digest, eight-tool allowlist/catalog hash, and explicit read scopes.
  A hostname suffix or caller-supplied private flag is never treated as proof of private ingress.
- `PrivateMcpEvidenceTransport` owns that immutable verified configuration and derives the endpoint
  used by its injected invoker from it; no independent endpoint label can be supplied. It
  maps the WC-009 semantic inventory operation to WC-008's exact `group_resource_list` deployment
  tool, then uses the separately allowlisted `compute_vm_get` tool in the same initialized MCP
  session to enrich only projected VM records with bounded instance-view power state. The WC-009
  adapter and its immutable client share one exact transport object. Collection
  checks the concrete transport and invoker type, object identity, and original method
  implementation, then calls the captured implementation directly with the sealed endpoint.
  Per-instance, class-level, or embedded-client method/transport replacement therefore fails
  closed before publication. The production HTTP invoker is
  `ManagedIdentityPrivateMcpInvoker`. It accepts only the trusted WC-008 configuration and managed
  identity audience, constructs its exact credential and zero-state HTTP stack internally, and
  has no injected clock, token provider, opener, or handler. Each request constructs a
  redirect-rejecting opener before attaching its keyless bearer token and rejects every 30x
  response without an authenticated follow-up. The zero-state HTTP identity and exact credential
  and HTTP implementations are sealed and revalidated before invocation; the credential itself is
  freshly constructed inside that sealed path. The service rejects composition unless the actual
  transport configuration exactly equals the separately loaded trusted WC-008 configuration.
- WC-009 validates tool identity, trust evidence, freshness, schema, count, size, and scope before
  the Context API sees evidence.
- The app-owned `ContextService` resolves WC-007 context, approvals, and evaluation grants before
  collection directly through its configured persistence transaction. `DemoEvaluationService`
  has no commit, resolver, approval, authorization, store, lock, or backend adapter injection
  point. The evaluation rejects missing, wrong-version, or superseded context and requires every
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
  Authority tokens bind an exact manifest ID and immutable version. Evaluation and runtime
  selection never use a unique-active fallback, so publishing another active version cannot
  silently alter an in-flight selection.
- Pure snapshot assembly computes canonical component digests. A trusted signing port supplies the
  RS256 attestation; production composition must back it with the configured versioned Key Vault
  key and managed identity rather than key material in configuration.
- A typed artifact store atomically appends the canonical snapshot, source envelope, human-bound
  publication record, exact findings, and idempotency receipt only after cryptographic verification
  and authoritative WC-004 evaluation of the resolved canonical profile succeeds.

Authorization failure, stale or malformed output, endpoint/tool unavailability, scope mismatch,
gaps, inactive governance, missing or exact context, superseded context, signature failure, or
policy-evaluation failure produces no publication.
The context identity configuration forbids Azure workload roles. The MCP identity configuration
permits only reviewed read roles and forbids Context API permissions.

The deterministic tests use a clearly synthetic endpoint, operator-pinned configuration port, and
fake invoker. The WC-005 golden fixture is evaluated only at its historical June 2025 proof time.
A separate 2026 test creates a new synthetic manifest version with bounded governance dates and
publishes it through the complete WC-007 proposer, validation, review, human approval, and
human-authorized publication lifecycle.

The initial opt-in live gate is a one-shot Container Apps Job and does not require this HTTP app to
be deployed. It imports a bounded, human-approved, digest-pinned WC-007 authority bundle into the
existing transactional `ContextService`, directly composes the WC-013 production adapters, requires
a successful real private Azure MCP attempt, and cryptographically verifies the immutable
`EvidenceSnapshot`. A future long-running API deployment must use equivalent durable Context API
persistence rather than this one-shot authority import. Exact configuration, Azure resources,
environment variables, and commands are documented in
[WC-013 live acceptance](../../docs/operations/wc013-live-acceptance.md).

## Cohort proposal routes

- `GET /v1/cohort-proposals` resolves one exact active draft/profile binding, retrieves an
  immutable workload-scoped snapshot through a typed repository port, cryptographically verifies
  it through the trusted verifier port, and returns the bounded WC-010 batch with `sourceDraft`.
- `POST /v1/cohort-proposals/preview` accepts only exact split/merge bindings and returns
  deterministic selector-only candidates. It never mutates a manifest, validates a draft,
  approves, or publishes.
- `POST /v1/cohort-proposals/decisions` durably records an idempotent human
  `approve`, `reject`, `split`, or `merge` decision. Apply decisions revalidate the exact batch,
  proposal union, snapshot, profile, source draft, and immutable candidate before invoking the
  WC-007 `ContextService` selector-only replacement inside the same storage transaction.
  The replacement materializes only a requested-profile local, complete role override. Generic
  resolution and ordinary draft replacement reject every disjoint selector identity, including
  guarded conjunctions copied from a preview. Ordinary replacement compares the current and
  replacement global roles and every profile-local override by normalized role ID, so moving a
  rejected candidate into a global role cannot establish a new inheritance baseline. Split/merge
  preview instead emits final guarded
  conjunctions whose inherited selector child proves narrowing and whose exact child binds the
  reviewed cohort. The decision transaction first persists an immutable apply authorization bound
  to the authenticated actor, candidate digest, workload/profile, proposal set, snapshot, exact
  source/current/resulting draft state, and complete replacement command. `ContextService` loads
  and verifies that persisted decision itself before mutation; no caller-constructed capability is
  accepted. The candidate is actor scoped and applied without post-approval transformation.
  It preserves role authority, never edits an ancestor or global role, and rejects candidates
  that cannot satisfy canonical weakening-governance rules. Every profile is
  resolved before and after; any non-target role or semantic-digest change fails closed.
  Every draft also has an immutable, transactionally stored selector baseline. Generic create,
  replace, validate, submit, approve, and publish paths compare selector identity, variant,
  semantic digest, normalized role identity, and global/profile location against that baseline
  plus exact persisted apply provenance. Removal/re-addition, role rename, profile/global
  movement, same-ID variant changes, and fresh-draft/version laundering therefore cannot turn a
  rejected or merely proposed candidate into a new baseline. Create and ordinary replacement
  resolve every profile before any baseline, draft, audit, or receipt write. A selector-preserving
  replacement after an approved decision recovers only persisted apply provenance, so unrelated
  non-selector edits remain legal without accepting caller-supplied authority. Replacement also
  compares the effective resolved selector provenance of every profile before and after the
  mutation. Inheritance-topology changes cannot make approved selectors effective in another
  profile; selector-neutral inheritance and non-selector edits remain legal. Fresh drafts compare
  every effective profile, including profile additions and removals, with the authoritative
  same-version draft, declared published predecessor, or single latest workload baseline before
  any baseline, audit, receipt, or draft write. Missing, invalid, or ambiguous predecessor lineage
  fails closed. An inferred unpublished predecessor is accepted only when it has no persisted
  selector authority and its stored manifest still exactly matches its immutable creation digest
  and selector-baseline entries. The successor baseline stores the exact neutral predecessor
  baseline reference and recursively verifies it during every lifecycle transition. A cohort
  decision therefore prevents that mutable draft from seeding any higher version: the
  decision-applied draft must first be published and the successor must declare that exact
  `previous_version`. The API rejects unsafe inferred creation before writing a draft that could
  fail later lifecycle validation.
  Selected proposal IDs are canonicalized once at the request boundary and are part of the
  decision version: disjoint selections in one batch may be decided independently, while any
  overlap conflicts and a rejection blocks only its covered authority members. Durable authority
  groups normalized immutable member fingerprints under a canonical workload, profile, role, and
  selector fingerprint rather than proposal boundaries. Transactional overlap checks therefore
  reject whole, subset, superset, split, merge, and partial-overlap repartitioning while
  preserving decisions on member-disjoint proposals, including disjoint members under the same
  role.
  Draft ID, revision, digest, manifest version, inheritance topology, resolved-profile digest,
  snapshot, proposal-set regeneration, proposal evaluation time, input digest, and proposal shape
  cannot bypass a durable rejection. Exact batch, snapshot, profile, and draft coordinates remain
  mandatory only for candidate and stale-application validation; no rejection is released without
  a separately audited reconsideration workflow.
  Overlap arbitration occurs before mutable draft freshness checks. A disjoint apply from the same
  immutable batch may atomically rebase only over the contiguous draft revisions produced by
  earlier decisions from that batch; unrelated draft changes remain stale. Preview candidate
  identities and repository lookups are actor scoped, so one reviewer can never submit another
  reviewer's candidate. Rebased replacement starts from the current draft and therefore preserves
  every prior disjoint selector change. Applied selectors are exactly the final selectors shown in
  the approved candidate; selector IDs needed for a safe local override are finalized before human
  review. The final decision transaction performs cryptographic and candidate verification first,
  then samples a fresh authoritative timestamp immediately before persistence. The atomic draft
  path samples again after resolver validation and immediately before mutation, so expiry crossing
  during either verifier or resolver work rolls the entire transaction back.
- `GET /v1/cohort-proposals/decisions` and
  `GET /v1/cohort-proposals/decisions/{decision_id}` return only decisions under an explicitly
  granted workload scope.

All cohort routes require a verified human identity and a concrete workload grant; wildcard grants
do not cross this boundary. Reject is durable and blocks later apply for the same proposal-set
version. Decision, decision audit, idempotency receipt, and draft replacement commit together or
roll back together. The bounded WC-007 replacement reason references the decision ID while the
decision record retains the full rationale. These routes never publish or change role authority
metadata.

Validation resolves every profile and enforces selector identity inheritance before changing
state. Submission repeats that check before and after server finalization, and publication checks
the approved candidate again. Exact selector identities introduced by a cohort decision remain
resolvable only from their persisted apply provenance. Proposal resolution recovers that immutable
provenance, and publication carries it through the published source draft into an exact
selector-preserving next-version baseline. Published recovery recursively validates the complete
`previous_version` lineage and deduplicates exact decision bindings, so that authority survives
multiple successor versions without granting generic selector-change authority. Any failure leaves
draft state, revision, audit, and idempotency receipts unchanged.

Deployments must inject the snapshot repository, cryptographic verifier, immutable proposal and
candidate cache, actor-scoped idempotency ports, and a decision transaction port spanning WC-007
draft storage. The default composition contains no evidence and grants no access.

The literal `*` is reserved and is never a valid manifest or workload identifier at an HTTP or
command boundary. Cross-workload WC-007 access uses the typed `AllWorkloadsGrantScope`; cohort
routes require an exact `WorkloadGrantScope`.
