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
  The replacement materializes only a requested-profile local, same-variant role override. It
  preserves role authority and unrelated selectors, never edits an ancestor or global role, and
  rejects candidates that cannot satisfy canonical weakening-governance rules. Every profile is
  resolved before and after; any non-target role or semantic-digest change fails closed.
- `GET /v1/cohort-proposals/decisions` and
  `GET /v1/cohort-proposals/decisions/{decision_id}` return only decisions under an explicitly
  granted workload scope.

All cohort routes require a verified human identity and a concrete workload grant; wildcard grants
do not cross this boundary. Reject is durable and blocks later apply for the same proposal-set
version. Decision, decision audit, idempotency receipt, and draft replacement commit together or
roll back together. The bounded WC-007 replacement reason references the decision ID while the
decision record retains the full rationale. These routes never publish or change role authority
metadata.

Deployments must inject the snapshot repository, cryptographic verifier, immutable proposal and
candidate cache, actor-scoped idempotency ports, and a decision transaction port spanning WC-007
draft storage. The default composition contains no evidence and grants no access.

The literal `*` is reserved and is never a valid manifest or workload identifier at an HTTP or
command boundary. Cross-workload WC-007 access uses the typed `AllWorkloadsGrantScope`; cohort
routes require an exact `WorkloadGrantScope`.
