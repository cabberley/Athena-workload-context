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
