# ADR 0002: Canonical context and evidence contracts

- **Status:** Proposed
- **Date:** 2026-08-15

## Context

WC-001 must freeze the public contracts before any Python implementation begins. Athena needs a
single canonical representation for workload intent, environment inheritance, resource roles,
relationship classes, evidence snapshots, controls, risks, objectives, ownership, and contextual
verdicts. These contracts must preserve ADR 0001: Athena is the context and judgment plane, while a
separately deployed private Azure MCP remains the read-only Azure evidence plane.

The prototype proof also requires one constrained topology to be evaluated through one policy path
under Production, Development, and Training profiles. That topology intentionally contains one
supported singleton database VM in one zone, worker VMs that must share that zone, and web-services
VMs that must span multiple zones. Athena must preserve the real residual risk and compensating
controls instead of replacing this workload-specific constraint with generic Azure HA advice.

## Decision

Athena will define the WC-001 contract set in the companion design specification
[Canonical workload context contract design](../contracts/canonical-workload-context-contracts.md).
The future Pydantic and JSON Schema implementation must follow that specification and no production
Python contract code is introduced by this ADR.

The canonical contracts are:

1. **Workload manifest.** A human-approved, versioned, immutable publication containing workload
   identity, profile definitions, role declarations, dynamic selectors, declared relationships,
   constraints, controls, risk acceptances, objectives, operational ownership, and compatibility
   metadata.
2. **Environment profile inheritance.** Profiles form an acyclic single-parent chain. Resolution is
   deterministic, explicit, provenance-preserving, and fail-closed for circular inheritance,
   unresolved references, ambiguous overrides, unknown enum values, or policy-weakening changes
   without an explicit profile-scoped rationale.
3. **Workload roles and dynamic selectors.** Roles define workload meaning. Selectors bind Azure MCP
   evidence to roles through a bounded, reviewed predicate grammar. Selector matches are proposals
   until approved by the Context API; ambiguous or over-broad selectors fail closed.
4. **Relationship classes.** Declared, observed, inferred, and exception relationships are separate
   collections with separate provenance. Observed and inferred relationships never overwrite
   declared intent. Exceptions waive or explain a scoped deviation; they do not mutate the original
   declaration.
5. **Immutable evidence snapshots.** Evidence snapshots are canonicalized, hashed, freshness-bound,
   scope-bound, and immutable. They cite the private Azure MCP tool, version, response envelope, and
   Azure MCP managed identity reference. They do not contain unrestricted log bodies, secrets, PHI,
   PII, or customer proprietary payloads.
6. **Provenance boundary.** Findings cite both a manifest clause and evidence snapshot reference.
   Context-plane provenance and private Azure MCP evidence-plane provenance remain distinct. The
   Athena context identity has no workload Reader role and never becomes the collector of Azure
   evidence.
7. **Closed contextual verdicts.** Verdicts are limited to `pass`, `violation`,
   `expectedConstraint`, `acceptedResidualRisk`, `observation`, `unknown`, and `conflicting`.
   Anything outside that vocabulary is invalid. `unknown` and `conflicting` are fail-closed states,
   not passes.
8. **Separate control/risk/constraint contracts.** Architecture constraints, compensating-control
   health, and risk acceptance are modeled independently. A healthy compensating control can reduce
   residual risk evidence; it cannot erase the underlying constraint. A risk acceptance can yield
   `acceptedResidualRisk`; it cannot yield `pass`.
9. **Canonical constrained-topology proof.** The contracts must directly support proof clauses for
   exactly one supported singleton database VM in one availability zone, worker resources sharing
   the database zone, and web-service resources spanning at least two zones for profiles that require
   multi-zone web. Missing zone evidence is `unknown`; mismatched worker zone is `violation`; active
   singleton risk acceptance is `acceptedResidualRisk` or `expectedConstraint`, never `pass`.
10. **Compatibility.** Contract schema versions use semantic versioning. Unknown major versions,
    unknown enum values, malformed extensions, stale evidence, ambiguous selectors, or unbounded
    collections are rejected or evaluated as fail-closed findings before publication or policy use.

## Declared-versus-inferred precedence

Declared manifest intent is authoritative for policy semantics after human publication. Observed
Azure MCP evidence is authoritative only for current Azure state. Inferred relationships are
Athena-generated interpretations with confidence and cannot weaken, replace, or silently amend a
declared relationship or constraint. Active exceptions and risk acceptances may change the contextual
verdict for a scoped finding, but they remain explicit overlays with owner, rationale, expiry, and
provenance.

Precedence during evaluation is:

1. validate manifest and profile resolution;
2. validate evidence scope, freshness, hash, and provenance;
3. evaluate declared constraints against observed evidence;
4. include inferred relationships only as non-authoritative context unless a policy explicitly
   references them;
5. apply active exceptions or risk acceptances as overlays; and
6. surface conflicts between sources as `conflicting` rather than reconciling them silently.

## Consequences

- Builders get a stable target for Pydantic models and generated JSON Schema in the next WC-001
  phase.
- The Context API remains the only publisher of authoritative manifests.
- Context MCP and Copilot tools may propose drafts but cannot publish, remediate, or rewrite intent.
- Azure MCP availability and snapshot freshness become explicit inputs to policy verdicts.
- Generic Azure HA recommendations are suppressed only when workload-specific approved constraints,
  residual risk, and compensating controls explain why the constrained design is expected.
- Contract evolution requires compatibility tests and an ADR for breaking semantics.

## Security impact

The decision preserves the ADR 0001 trust boundary. Athena context-plane services store and evaluate
context but do not receive direct workload Azure Reader permissions. The private Azure MCP evidence
plane uses a separate managed identity, read-only tool allowlist, bounded response validation, and
auditable evidence envelopes. Persisted evidence excludes secrets, unrestricted logs, PHI, PII, and
customer proprietary bodies.

## Operational impact

Operators must maintain profile owners, role owners, control owners, risk acceptance expiry, and
runbook references. Expired acceptances, stale snapshots, missing control evidence, unresolved role
references, and ambiguous selector output generate fail-closed findings that require human review.
This increases governance work but prevents unsafe silent assumptions.

## Compatibility and rollback

- Schema major versions are incompatible and rejected unless explicitly supported.
- Minor versions may add optional fields and enum members only after compatibility tests prove older
  readers fail closed instead of treating new semantics as pass.
- Patch versions clarify documentation or validation wording without changing serialized meaning.
- Published manifest versions remain immutable. Rollback means publishing a new superseding version
  that restores earlier intent with a new audit trail entry; it never edits history in place.

## Alternatives considered

### Let observed Azure topology become declared intent

Rejected. It would allow accidental drift to rewrite human-approved workload meaning and violates
ADR 0001's distinction between context and evidence.

### Store one generic relationship graph with a source label

Rejected. A single graph invites silent reconciliation and makes it too easy for observed or
inferred edges to mask declared requirements. Separate relationship collections make precedence and
conflicts auditable.

### Use open-ended verdict strings

Rejected. Open strings would make policy behavior, UI status, and reviewer gates inconsistent.
Closed verdicts are required so invalid or future values fail closed.

### Allow direct Azure reads from Athena services for convenience

Rejected. Direct reads would erode the context-plane versus evidence-plane identity boundary and
recreate generic Azure MCP capability. Narrow direct-read exceptions require a future ADR.

## Validation

The implementation phase must satisfy the measurable acceptance criteria in the design
specification, including generated JSON Schemas, closed enum tests, bounded collection tests,
profile-inheritance negative tests, distinct provenance tests, evidence freshness and scope tests,
canonical constrained-topology proof tests, and compatibility/fail-closed tests. Implementation must
not begin until the GPT-5.6 Sol Architecture Reviewer returns `approved-for-implementation` or this
ADR is corrected.
