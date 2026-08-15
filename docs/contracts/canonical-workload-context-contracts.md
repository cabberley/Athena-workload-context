# Canonical workload context contract design

This specification is the WC-001 architecture target for future Pydantic contracts and generated
JSON Schemas. It is design documentation only; it intentionally contains no production Python
implementation.

Related decision: [ADR 0002](../adr/0002-canonical-context-and-evidence-contracts.md).

## Design goals

- Preserve the Athena context plane versus private Azure MCP evidence plane identity boundary.
- Make published workload intent human-owned, versioned, immutable, and auditable.
- Keep declared, observed, inferred, and exception relationships distinct.
- Use closed enums and bounded collections at every contract boundary.
- Fail closed for invalid, ambiguous, stale, missing, low-confidence, or conflicting inputs.
- Support one canonical policy path that can evaluate the same evidence snapshot under Production,
  Development, and Training profiles and produce different contextual outcomes.
- Represent singleton-database residual risk without converting it into a false high-availability
  pass.

## Contract package boundaries

Future implementation should group contracts by meaning, not by caller:

| Contract group | Purpose | Examples |
|---|---|---|
| Manifest | Human-approved workload intent | workload, profiles, roles, selectors, declared relationships |
| Evidence | Immutable Azure MCP evidence | resource records, observed relationships, metrics, health envelopes |
| Policy | Deterministic contextual evaluation | constraints, verdicts, findings, proof requirements |
| Governance | Human overlays | exceptions, compensating controls, risk acceptances, ownership |
| Compatibility | Versioning and evolution | schema version, extension policy, migration metadata |

No contract group may contain direct Azure SDK client configuration or credentials.

## Identity and evidence-plane boundary

Athena has two distinct provenance planes:

| Plane | Identity | Allowed responsibilities | Prohibited responsibilities |
|---|---|---|---|
| Context plane | Athena Context API / workers managed identity | Read and write Athena-owned manifests, drafts, findings, approvals, history, and context store data | Azure workload Reader role, direct workload inventory, direct Log Analytics or Resource Graph reads |
| Evidence plane | Private Azure MCP managed identity | Read-only Azure inventory, relationship, metrics, health, and change evidence through reviewed MCP tools | Publishing manifests, approving context, remediation, unrestricted log body export |

Every finding must cite both:

1. an Athena context reference: manifest id, manifest version, profile id, clause path; and
2. an Azure MCP evidence reference: snapshot id, snapshot digest, MCP tool name/version, collected
   time, evidence item path.

If either citation is missing, stale, out of scope, or malformed, the finding verdict is `unknown`
and the publication/evaluation path fails closed.

## Canonical workload manifest

A workload manifest is the only authoritative document for workload intent. It is human-published by
the Context API and immutable after publication.

Required top-level fields:

| Field | Type | Bound | Notes |
|---|---|---|---|
| `schemaVersion` | semantic version string | exactly one | Unknown major versions are rejected. |
| `manifestId` | stable id | 1 | Does not encode customer names or secrets. |
| `manifestVersion` | semantic version string | 1 | Immutable publication version. |
| `workload` | object | 1 | Workload metadata and classification. |
| `profiles` | map by profile id | 1-25 | Must include `production`, `development`, and `training` for the prototype. |
| `roles` | array | 1-200 | Role ids are unique and referenced by relationships and constraints. |
| `relationships` | object | 1 | Contains declared and exception relationships only. |
| `constraints` | array | 0-500 | Architecture constraints, separate from risk and controls. |
| `controls` | array | 0-500 | Compensating or governance controls. |
| `riskAcceptances` | array | 0-200 | Time-bound human risk decisions. |
| `objectives` | array | 0-200 | SLO, RTO, RPO, capacity, and service-hour objectives. |
| `ownership` | object | 1 | Operational and escalation ownership. |
| `compatibility` | object | 1 | Compatibility and extension declarations. |
| `audit` | object | 1 | Publication metadata and hash inputs. |

### JSON shape sketch

```json
{
  "schemaVersion": "1.0.0",
  "manifestId": "wl-synthetic-clinical-platform",
  "manifestVersion": "0.1.0",
  "workload": {
    "displayName": "Synthetic clinical platform",
    "businessCriticality": "missionCritical",
    "dataSensitivity": "syntheticOnly",
    "allowedEvidenceScopes": ["/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-fixture"]
  },
  "profiles": {
    "production": { "profileType": "production", "extends": null },
    "development": { "profileType": "development", "extends": "production" },
    "training": { "profileType": "training", "extends": "production" }
  },
  "roles": [],
  "relationships": { "declared": [], "exceptions": [] },
  "constraints": [],
  "controls": [],
  "riskAcceptances": [],
  "objectives": [],
  "ownership": {},
  "compatibility": { "extensionPolicy": "rejectUnknownDecisionFields" },
  "audit": { "publishedBy": "human-approved-context-api", "canonicalDigest": "sha256:..." }
}
```

## Environment profile inheritance

Profiles express environment-specific intent without duplicating entire manifests.

Rules:

1. Each profile has exactly one optional parent through `extends`.
2. The inheritance graph must be acyclic and fully resolvable.
3. Profile ids are unique and use a closed `profileType` enum: `production`, `development`,
   `training`, `test`, `disasterRecovery`, `sandbox`.
4. Resolution order is parent first, child second.
5. Scalars override only through an explicit `overrides` object.
6. Keyed collections merge by stable id. Deletes require an explicit `disabledRefs` entry with
   rationale and are not allowed for required prototype constraints.
7. Any override that weakens severity, lowers proof strength, disables a constraint, extends a risk
   acceptance, or marks a control optional must include profile-scoped rationale and owner.
8. Unknown parent, circular inheritance, unresolved role reference, duplicate id, ambiguous override,
   or unbounded collection fails closed before evaluation.

Resolved profile output is canonicalized and hashed. Findings cite the resolved profile digest, not
only the source manifest.

## Workload roles

Roles map Azure resources to workload meaning. A role may bind one resource, a cohort, or a logical
service tier.

Closed role kinds:

- `singletonDatabase`
- `databaseReplica`
- `worker`
- `webService`
- `loadBalancer`
- `integrationEndpoint`
- `storage`
- `network`
- `identity`
- `observability`
- `externalDependency`

Role fields:

| Field | Type | Bound | Notes |
|---|---|---|---|
| `roleId` | stable id | 1 | Referenced everywhere else. |
| `kind` | closed enum | 1 | Invalid values fail closed. |
| `displayName` | string | 1-120 chars | Human label only. |
| `cardinality` | object | 1 | `exactlyOne`, `oneOrMore`, `zeroOrMore`, or bounded min/max. |
| `selectors` | array | 1-20 | Dynamic or explicit resource selectors. |
| `profileApplicability` | array | 1-25 | Profiles where the role exists. |
| `ownerRef` | ownership reference | 1 | Must resolve to ownership entry. |
| `approvalState` | enum | 1 | `draft`, `approved`, `deprecated`; only approved participates in published evaluation. |

## Dynamic resource selectors

Selectors are reviewed rules that bind evidence records to roles. They do not query Azure directly;
they evaluate only against an immutable evidence snapshot collected by Azure MCP.

Closed selector types:

- `resourceIdList`: exact resource ids, bounded to 200 ids.
- `tagPredicate`: exact tag key/value matches, bounded to 20 predicates.
- `namePattern`: anchored prefix/suffix pattern, no unbounded regex.
- `resourceTypeScope`: exact Azure resource type plus optional location/resource group filters.
- `compositeAll`: all child selectors must match, bounded to 10 children.
- `compositeAny`: one child selector must match, bounded to 10 children.

Selector behavior:

- Every selector declares `maxMatches`; default maximum is 1,000 resources.
- A selector that exceeds `maxMatches`, references a scope outside `allowedEvidenceScopes`, matches
  resources from multiple incompatible roles, or has confidence below the role threshold is
  `ambiguous` and fails closed.
- Selector output is a proposal until the Context API records approval.
- Selector evaluation records positive matches, dissenting evidence, rejected candidates, confidence,
  and the evidence snapshot digest.

## Relationship classes

Relationships are intentionally modeled as separate collections.

| Class | Source of truth | Mutability | Policy use |
|---|---|---|---|
| Declared | Published manifest | Immutable per version | Normative workload intent |
| Observed | Azure MCP evidence snapshot | Immutable per snapshot | Current Azure state |
| Inferred | Athena deterministic analysis | Recomputed | Non-authoritative interpretation with confidence |
| Exception | Human-approved manifest overlay | Immutable per version, time-bound | Scoped waiver/explanation; does not mutate declarations |

Closed relationship kinds:

- `requires`
- `dependsOn`
- `calls`
- `storesDataIn`
- `replicatesTo`
- `failsOverTo`
- `sharesZoneWith`
- `isolatedFrom`
- `monitors`
- `protectedBy`
- `prohibited`

Relationship precedence:

1. Declared relationships define intended semantics.
2. Observed relationships prove or disprove current state.
3. Inferred relationships may explain patterns but cannot satisfy a declared requirement unless a
   policy explicitly says inference is acceptable and cites its confidence threshold.
4. Exception relationships can explain an approved deviation and may change a verdict to
   `acceptedResidualRisk`; they never alter the declared relationship.
5. Declared versus observed disagreement with no active exception yields `violation` when evidence is
   fresh and complete, or `unknown`/`conflicting` when evidence is incomplete or contradictory.

## Immutable evidence snapshots

Evidence snapshots are the only policy input from Azure MCP. They are immutable, canonicalized, and
hash-addressed.

Required fields:

| Field | Type | Bound | Notes |
|---|---|---|---|
| `snapshotId` | id | 1 | Stable immutable id. |
| `snapshotSchemaVersion` | semantic version | 1 | Unknown major versions fail closed. |
| `scope` | array | 1-100 | Azure subscriptions/resource groups/workspaces authorized for this snapshot. |
| `collectedAt` | datetime | 1 | UTC. |
| `expiresAt` | datetime | 1 | Must be after `collectedAt` and policy freshness threshold. |
| `collector` | Azure MCP provenance | 1 | Tool names, versions, allowlist hash, MCP identity reference. |
| `resources` | array | 0-10,000 | Bounded resource evidence records. |
| `observedRelationships` | array | 0-20,000 | Separate from manifest relationships. |
| `healthSignals` | array | 0-10,000 | Bounded summaries only, no raw log bodies. |
| `canonicalDigest` | sha256 string | 1 | Digest of canonical JSON excluding transport metadata. |

Evidence record constraints:

- Resource ids must be normalized and scope-checked.
- Zones may be `unknown`, but policy then emits `unknown` for zone-dependent proof.
- Tags are bounded and treated as untrusted evidence.
- Log and metric records persist only aggregate values, query metadata, and evidence references.
- Raw log bodies, secrets, PHI, PII, credentials, and proprietary payloads are invalid.

## Provenance references

Every policy finding carries structured provenance:

```json
{
  "contextRef": {
    "manifestId": "wl-synthetic-clinical-platform",
    "manifestVersion": "0.1.0",
    "profileId": "production",
    "resolvedProfileDigest": "sha256:...",
    "clausePath": "/constraints/db-singleton-supported"
  },
  "evidenceRef": {
    "snapshotId": "snap-20260815-0001",
    "snapshotDigest": "sha256:...",
    "mcpTool": "azure.resourceInventory.read",
    "mcpToolVersion": "1.0.0",
    "collectorIdentityRef": "mi-private-azure-mcp-readonly",
    "evidencePath": "/resources/0"
  }
}
```

`collectorIdentityRef` is an Azure MCP evidence-plane identity reference. It must not be replaced by
an Athena context-plane identity reference for Azure resource evidence.

## Closed verdict vocabulary

Verdict strings are closed and case-sensitive:

| Verdict | Meaning | Fail-closed? |
|---|---|---|
| `pass` | Fresh evidence proves the declared requirement is satisfied and no active conflict remains. | No |
| `violation` | Fresh evidence proves a declared requirement is breached and no active exception or acceptance changes the outcome. | Yes |
| `expectedConstraint` | The manifest declares a supported limitation or topology constraint that is intentionally present. Residual risk remains visible. | No, but not a pass |
| `acceptedResidualRisk` | A current, scoped, human-approved risk acceptance applies to the finding. | No, but not a pass |
| `observation` | Informational contextual statement with no pass/fail semantics. | No |
| `unknown` | Evidence, context, freshness, scope, confidence, or references are insufficient. | Yes |
| `conflicting` | Declared, observed, inferred, or exception data disagree in a way policy cannot safely reconcile. | Yes |

Only `pass`, `expectedConstraint`, `acceptedResidualRisk`, and `observation` may be non-blocking.
`expectedConstraint` and `acceptedResidualRisk` must remain visually distinct from `pass` and must
not suppress residual risk text or control status.

## Fail-closed behavior

The implementation must fail closed at both publication time and evaluation time.

Publication fails when:

- schema version major is unsupported;
- enum value is unknown;
- collection bound is exceeded;
- profile inheritance is circular or unresolved;
- role, relationship, constraint, objective, ownership, control, or risk references are unresolved;
- canonicalization or digest verification fails;
- an exception or risk acceptance lacks owner, rationale, scope, or expiry; or
- a selector grammar is unsupported or unbounded.

Evaluation returns `unknown` or `conflicting` and blocks automated pass when:

- evidence is missing, stale, out of scope, malformed, or oversized;
- Azure MCP provenance is missing or comes from an unapproved tool;
- the Athena context identity appears as the Azure evidence collector;
- dynamic selector output is ambiguous or over-broad;
- zone, dependency, health, or metric evidence needed for a proof is unavailable;
- declared and observed relationships conflict without enough evidence for a `violation`; or
- confidence is below the policy threshold.

Fail-closed behavior never triggers remediation. It surfaces a finding for human review.

## Architecture constraints

Architecture constraints are declarative requirements or allowed limitations. They are separate from
compensating controls and risk acceptances.

Closed constraint types:

- `cardinality`
- `zoneColocation`
- `zoneDistribution`
- `dependencyRequired`
- `dependencyProhibited`
- `supportedSingleton`
- `objectiveRequired`
- `evidenceFreshness`
- `controlRequired`

Constraint fields:

| Field | Type | Bound | Notes |
|---|---|---|---|
| `constraintId` | id | 1 | Stable within manifest. |
| `type` | enum | 1 | Closed constraint type. |
| `appliesToRoleRefs` | array | 1-50 | Role ids must resolve. |
| `profiles` | array | 1-25 | Profiles where constraint applies. |
| `severity` | enum | 1 | `critical`, `high`, `medium`, `low`, `informational`. |
| `proofRequirement` | object | 1 | Deterministic evidence required for pass or expected constraint. |
| `sourceClause` | string | 1 | Human-readable manifest clause. |
| `failureMode` | enum | 1 | `violation`, `unknown`, or `conflicting`. |

## Canonical constrained-topology proof requirements

The prototype's canonical topology must be represented by these constraints.

### Singleton database proof

- Role: `database-primary`, kind `singletonDatabase`.
- Cardinality: exactly one supported database VM resource in the resolved profile.
- Evidence required: one Azure MCP resource record with normalized resource id, resource type,
  availability zone, location, power/provisioning state, role selector provenance, and snapshot
  freshness within the profile threshold.
- Verdict rules:
  - exactly one resource with zone evidence and active singleton support clause yields
    `expectedConstraint`;
  - zero, more than one, missing zone, stale evidence, or ambiguous selector output yields
    `unknown` unless fresh evidence proves a declared cardinality breach, then `violation`;
  - active risk acceptance for database or zone loss yields `acceptedResidualRisk` as a separate
    finding, not `pass`.

### Worker same-zone proof

- Role: `worker`, kind `worker`.
- Relationship: every worker `sharesZoneWith` `database-primary`.
- Evidence required: database zone and every worker zone from the same immutable snapshot.
- Verdict rules:
  - all workers in the database zone yields `pass`;
  - any worker in another known zone yields `violation`;
  - missing zone evidence for database or any worker yields `unknown`;
  - an exception must identify the exact worker scope and expiry to change the worker finding to
    `acceptedResidualRisk`.

### Web multi-zone proof

- Role: `web`, kind `webService`.
- Constraint: profile-specific minimum distinct zones. Production requires at least two zones;
  Development and Training may explicitly override only with rationale and owner.
- Evidence required: all selected web resources, zone for each resource, distinct-zone count, and
  selector provenance from the same immutable snapshot.
- Verdict rules:
  - distinct zone count greater than or equal to the profile requirement yields `pass`;
  - fresh complete evidence below the profile requirement yields `violation`;
  - missing zone evidence or over-broad selector output yields `unknown`;
  - generic advice to add database HA is suppressed when the singleton DB constraint and risk
    acceptance are active, but the web-zone verdict remains independently evaluated.

## Compensating controls

Compensating controls describe mitigating activities or platform capabilities. They never rewrite
constraints or accept risk by themselves.

Closed control types:

- `backup`
- `restoreTest`
- `manualFailoverRunbook`
- `monitoringAlert`
- `capacityReview`
- `accessReview`
- `changeApproval`
- `vendorSupport`

Closed control health values:

- `effective`
- `degraded`
- `missing`
- `unknown`
- `expired`
- `notApplicable`

A control has owner, scope, evidence references, review cadence, last-tested time, expiry or next
review time, and profile applicability. Missing or stale control evidence yields a separate control
finding and does not turn the related architecture finding into `pass`.

## Risk acceptance

Risk acceptances are explicit human decisions about residual risk. They are not controls and not
constraints.

Required fields:

| Field | Type | Bound | Notes |
|---|---|---|---|
| `riskAcceptanceId` | id | 1 | Stable id. |
| `scope` | role/constraint/profile refs | 1 | Must be narrow and resolvable. |
| `residualRiskStatement` | string | 1-2,000 chars | States retained risk. |
| `acceptedBy` | human approval reference | 1 | No secrets; auditable principal reference. |
| `ownedBy` | ownership ref | 1 | Team accountable for review. |
| `acceptedAt` | datetime | 1 | UTC. |
| `expiresAt` | datetime | 1 | Required; no indefinite acceptance. |
| `linkedControlRefs` | array | 0-50 | Controls that mitigate but do not erase risk. |
| `profiles` | array | 1-25 | Environments where acceptance applies. |

Expired, ownerless, rationale-free, or scope-broad acceptances are invalid at publication. An active
acceptance changes applicable findings to `acceptedResidualRisk`; it does not produce `pass`.

## Objectives

Objectives express operational commitments and context used by forecasting or policy.

Closed objective types:

- `availabilitySlo`
- `latencySlo`
- `throughputSlo`
- `rto`
- `rpo`
- `serviceHours`
- `capacityHeadroom`
- `recoveryPriority`

Each objective includes profile applicability, target value, measurement window, evidence source
expectation, owner, and breach verdict mapping. Objective evaluation requires fresh evidence; missing
or stale metric evidence is `unknown`.

## Operational ownership

Ownership entries provide accountability without embedding secrets or sensitive personal data.

Closed owner roles:

- `businessOwner`
- `technicalOwner`
- `operationsOwner`
- `securityOwner`
- `vendorOwner`
- `approver`
- `onCallGroup`

Ownership entries may reference group aliases, service tree ids, runbook URIs, escalation policy ids,
and approval authority. They must not include passwords, tokens, private keys, unrestricted logs, or
PHI/PII payloads. A missing owner for a constraint, control, risk acceptance, role, or objective is a
publication failure.

## Compatibility and versioning

Compatibility rules:

1. `schemaVersion` follows `MAJOR.MINOR.PATCH`.
2. Unsupported major versions are rejected.
3. Minor versions may add optional fields only when older readers ignore them safely or fail closed.
4. New enum values require a minor version and compatibility tests proving older readers do not treat
   them as `pass`.
5. Patch versions cannot change serialized semantics.
6. Extension fields are allowed only under an explicit `extensions` object with namespaced keys,
   bounded size, and no decision-making semantics unless a future ADR promotes them.
7. Canonical hashes are computed after sorting keys, normalizing ids, removing transport metadata,
   and preserving semantically relevant nulls.
8. Published manifests and evidence snapshots are immutable. Supersession creates new versions; it
   never edits prior artifacts.

## Pydantic shape sketch

The following sketch illustrates intended contract shape only.

```python
from datetime import datetime
from typing import Literal

Verdict = Literal[
    "pass",
    "violation",
    "expectedConstraint",
    "acceptedResidualRisk",
    "observation",
    "unknown",
    "conflicting",
]

RelationshipClass = Literal["declared", "observed", "inferred", "exception"]
RoleKind = Literal[
    "singletonDatabase",
    "databaseReplica",
    "worker",
    "webService",
    "loadBalancer",
    "integrationEndpoint",
    "storage",
    "network",
    "identity",
    "observability",
    "externalDependency",
]

class WorkloadRoleSketch(BaseModel):
    role_id: str
    kind: RoleKind
    selectors: list[DynamicSelectorSketch]  # min 1, max 20
    cardinality: CardinalitySketch
    owner_ref: str

class EvidenceSnapshotSketch(BaseModel):
    snapshot_id: str
    snapshot_schema_version: str
    collected_at: datetime
    expires_at: datetime
    collector: AzureMcpCollectorProvenanceSketch
    resources: list[ResourceEvidenceSketch]  # max 10_000
    observed_relationships: list[ObservedRelationshipSketch]  # max 20_000
    canonical_digest: str

class ContextualFindingSketch(BaseModel):
    finding_id: str
    verdict: Verdict
    context_ref: ManifestClauseRefSketch
    evidence_refs: list[EvidenceRefSketch]  # min 1 unless verdict is pure observation
    relationship_class_refs: list[RelationshipClass]
    confidence: float  # 0.0 through 1.0
    residual_risk: str | None
    next_actions: list[str]  # max 10; advisory only
```

Implementation must use real Pydantic constraints such as `Field(min_length=...)`, bounded lists,
closed `Literal` or enum types, model validators for cross-reference checks, and canonicalization
helpers. The implementation must not copy this sketch blindly.

## Generated JSON Schema requirements

Generated JSON Schemas must exist for at least:

- workload manifest;
- resolved environment profile;
- workload role;
- dynamic selector;
- declared relationship;
- observed relationship;
- inferred relationship;
- exception relationship;
- immutable evidence snapshot;
- contextual finding and verdict;
- architecture constraint;
- compensating control;
- risk acceptance;
- objective;
- operational ownership reference; and
- compatibility metadata.

Schemas must include `$id`, schema version, required properties, enum values, min/max collection
bounds, additional-property behavior, string length limits, and cross-reference validation notes.

## Measurable implementation acceptance criteria

1. Contract tests prove all public enums are closed, including verdicts, relationship classes, role
   kinds, selector types, constraint types, control health values, objective types, and owner roles.
2. Generated JSON Schemas include required properties and bounded collection constraints for every
   contract listed above.
3. A manifest with Production, Development, and Training profiles resolves deterministically and
   emits a stable resolved-profile digest.
4. Circular profile inheritance, missing parent profile, unresolved role reference, duplicate role id,
   ambiguous override, and weakening override without rationale all fail publication.
5. Declared, observed, inferred, and exception relationships serialize as distinct collections and
   cannot be silently merged by validation or canonicalization.
6. Policy findings cite both a manifest clause and an Azure MCP evidence reference; missing either
   produces `unknown` and a blocking validation error.
7. Evidence snapshots are immutable, freshness-bound, scope-checked, canonicalized, and hash-stable
   across key ordering differences.
8. Evidence collected by the Athena context identity for Azure resources is rejected; only the
   private Azure MCP collector identity reference is valid for Azure evidence.
9. Selector tests cover exact ids, tag predicates, type scope, composites, over-broad matches,
   out-of-scope matches, and low-confidence ambiguous matches.
10. The canonical topology proof evaluates the same snapshot under Production, Development, and
    Training through one code path and distinguishes singleton DB expected constraint, worker
    same-zone pass/violation/unknown, and web multi-zone pass/violation/unknown.
11. Active database singleton risk acceptance produces `acceptedResidualRisk` as a separate finding
    and never converts the singleton constraint to `pass`.
12. Expired risk acceptance, stale control evidence, missing owner, and absent rationale fail closed.
13. Unknown schema major version, unknown enum value, oversized collection, unsupported extension,
    malformed digest, stale evidence, and unapproved Azure MCP tool all fail closed.
14. Context API publication tests prove agents and Context MCP proposal paths cannot publish
    authoritative manifests.
15. Compatibility tests prove minor/patch versions preserve canonical hashes where semantics are
    unchanged and reject incompatible major versions.
16. Security tests prove no raw log bodies, secrets, PHI, PII, credentials, or customer proprietary
    payload fields are accepted in manifests or evidence snapshots.
17. Repository validation, lint, type checks, and unit tests pass after implementation; this design
    change itself requires repository markdown/customization validation only.

## Architecture-review questions for GPT-5.6 Sol

- Does this contract set preserve the context-plane/evidence-plane identity boundary from ADR 0001?
- Are any fields likely to recreate generic Azure MCP discovery or monitoring inside Athena?
- Are closed verdicts sufficient for UI, policy, and review gates without creating hidden pass states?
- Are risk acceptance, compensating-control health, and architecture constraints separated clearly
  enough for implementation?
- Are selector and evidence bounds measurable and safe for the first 1,000-resource synthetic test?
- Is declared-versus-inferred precedence explicit enough to prevent silent drift acceptance?
- Are the singleton database, worker same-zone, and web multi-zone proof requirements implementable
  without production code ambiguity?
