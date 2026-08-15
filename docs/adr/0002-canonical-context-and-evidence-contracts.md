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

1. **Closed schemas.** Public contracts are closed by default: generated JSON Schema uses
   `additionalProperties: false` and Pydantic models use `extra="forbid"` except for a bounded,
   namespaced `extensions` object that has no policy semantics. Scope, proof requirement,
   relationship, control, evidence record, and provenance shapes are bounded discriminated unions,
   not opaque objects.
   Azure evidence scope and Athena governance scope are separate closed unions.
2. **Workload manifest.** A human-approved, versioned, immutable publication containing workload
   identity, profile definitions, role declarations, dynamic selectors, declared relationships,
   constraints, controls, risk acceptances, objectives, operational ownership, and compatibility
   metadata.
3. **Environment profile inheritance.** Profiles form an acyclic single-parent chain. Resolution is
   deterministic, explicit, provenance-preserving, and fail-closed for circular inheritance,
   unresolved references, ambiguous overrides, unknown enum values, or policy-weakening changes
   without an explicit profile-scoped rationale.
   `zoneLossContinuityRequired` is a strict boolean at
   `/resolvedProfiles/{profileId}/settings/continuity/zoneLossContinuityRequired`.
4. **Workload roles and dynamic selectors.** Roles define workload meaning. Selectors bind Azure MCP
   evidence to roles through a bounded, reviewed predicate grammar. Selector matches are proposals
   until approved by the Context API; ambiguous or over-broad selectors fail closed.
5. **Relationship classes.** Declared, observed, inferred, and exception relationships are separate
   discriminated collections with separate provenance. Observed and inferred relationships never
   overwrite declared intent. Exceptions identify scoped deviations only; they cannot directly
   produce `acceptedResidualRisk` and must reference an active `riskAcceptanceRef` before acceptance
   semantics apply.
6. **Immutable evidence snapshots.** Evidence snapshots are canonicalized, hashed, freshness-bound,
   scope-bound, and immutable. Each evidence item carries digest-covered provenance back to a
   specific digest-covered collector attempt. Collector attempts are closed variants for successful
   response, failed response, timeout/no-response, authorization failure, and tool-unavailable
   outcomes, so collector-unavailable snapshots can be valid without fabricated MCP responses. Every
   attempt cites a verifiable signed collector identity attestation for the private Azure MCP
   managed identity. Evidence records are profile-neutral and do not contain Athena judgments such
   as clause paths, verdicts, or profile-specific `not required` statements. They do not contain
   unrestricted log bodies, secrets, PHI, PII, or customer proprietary payloads.
7. **Provenance boundary.** Findings cite both a manifest clause and evidence reference. Context-plane
   provenance and private Azure MCP evidence-plane provenance remain distinct. The Athena context
   identity has no workload Reader role and never becomes the collector of Azure evidence. Findings
   without concrete evidence must cite a typed `evidenceGap` reference.
8. **Closed contextual verdicts.** Verdicts are limited to `pass`, `violation`,
   `expectedConstraint`, `acceptedResidualRisk`, `observation`, `unknown`, and `conflicting`.
   Anything outside that vocabulary is invalid. `unknown` and `conflicting` are fail-closed states,
   not passes.
9. **Closed finding kinds.** Findings separately identify `architectureConstraint`,
   `technologyConstraint`, `actualSpof`, `controlHealth`, `riskAcceptance`, `objective`,
   `relationshipConflict`, and `evidenceGap` so a supported technology limitation, an actual
   single point of failure, control state, and acceptance state cannot be collapsed into one pass.
10. **Separate control/risk/constraint contracts.** Architecture constraints, compensating-control
   health, and risk acceptance are modeled independently. A healthy compensating control can reduce
   residual risk evidence; it cannot erase the underlying constraint. A risk acceptance can yield
   `acceptedResidualRisk`; it cannot yield `pass`.
11. **Canonical constrained-topology oracle.** The contracts must directly support one canonical
   manifest and one immutable evidence snapshot with exact Production, Development, and Training
   overrides and expected verdicts for the singleton database, database-zone SPOF, worker same-zone,
   and web multi-zone clauses.
12. **Canonical constrained-topology proof.** The contracts must directly support proof clauses for
   exactly one supported singleton database VM in one availability zone, worker resources sharing
   the database zone, and web-service resources spanning at least two zones for profiles that require
   multi-zone web. Missing zone evidence is `unknown`; mismatched worker zone is `violation`; active
   singleton risk acceptance is `acceptedResidualRisk` or `expectedConstraint`, never `pass`.
13. **Compatibility.** Contract schema versions use semantic versioning and include separate
    artifact and semantic digests. Policy-affecting optional fields and enum additions require
    closed `requiresCapabilities` and `minimumReaderVersion` metadata plus deterministic negotiation,
    or a major version. Schema, digest, and compatibility metadata live only under `/compatibility`.
    Digests use pre-validation NFC normalization with collision rejection, then unmodified RFC 8785
    JCS, exclude only their own digest fields and closed transport metadata, and use SHA-256.
    Semantic digests use closed pointer allowlists. Unknown major versions, unknown required
    capabilities, unknown enum values, malformed extensions, stale evidence, ambiguous selectors, or
    unbounded collections are rejected or evaluated as fail-closed findings before publication or
    policy use.

## Declared-versus-inferred precedence

Declared manifest intent is authoritative for policy semantics after human publication. Observed
Azure MCP evidence is authoritative only for current Azure state. Inferred relationships are
Athena-generated interpretations with confidence and cannot weaken, replace, or silently amend a
declared relationship or constraint. WC-001 prohibits inferred relationships from satisfying
normative requirements. Exceptions document scoped deviations only. A finding can become
`acceptedResidualRisk` only when the applicable exception or SPOF condition references a currently
active risk acceptance with matching governance scope, owner, rationale, expiry, and provenance.

Precedence during evaluation is:

1. validate manifest and profile resolution;
2. validate evidence scope, freshness, hash, and provenance;
3. evaluate declared constraints against observed evidence;
4. treat inferred relationships as explanatory context only; WC-001 prohibits them from satisfying
   normative requirements, and any proof that needs inference returns fail-closed `unknown` until
   declared intent or observed evidence is available;
5. apply active exceptions as scoped explanatory overlays, then apply matching active risk
   acceptances as the only source of `acceptedResidualRisk`; and
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
- Artifact digests cover exact canonical bytes; semantic digests cover policy-affecting normalized
  fields. Both must be persisted and cited.
- Minor versions may add non-policy optional metadata only when artifact digest changes and semantic
  digest is unchanged. Policy-affecting optional fields or enum members require a declared
  capability, a `minimumReaderVersion`, and negotiation; otherwise they require a major version.
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
specification, including generated JSON Schemas with `additionalProperties: false`, discriminated
union tests, closed enum tests, bounded collection tests, deterministic merge/cross-reference tests,
distinct provenance tests, collector-attempt and signed-attestation tests, canonicalization/digest
fixture tests, evidence freshness and scope tests, the exact three-profile oracle, and
compatibility/fail-closed tests. Implementation must not begin until the GPT-5.6 Sol Architecture
Reviewer returns `approved-for-implementation` or this ADR is corrected.
