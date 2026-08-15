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

## Closed schema and deterministic resolution rules

All public contract models are closed by default.

- Generated JSON Schema must set `additionalProperties: false` on every decision-making object.
- Pydantic models must use `extra="forbid"` on every decision-making model.
- The only extension point is `extensions`: a bounded map with reverse-DNS or URI-like namespace
  keys, JSON scalar/list/object values capped at 16 KiB per artifact, and no policy semantics.
- Scope, proof requirement, relationship, control, evidence record, evidence reference, and selector
  contracts are discriminated unions. Each union uses a single required discriminator field and has a
  closed list of allowed variants.
- Unknown discriminator values, unknown properties outside `extensions`, or union variants with
  missing required fields are publication failures or fail-closed evaluation results.

Deterministic profile resolution and cross-reference validation run in this order:

1. Parse all artifacts using closed schemas and supported schema/capability versions.
2. Resolve profile inheritance parent-first and reject cycles before applying any overrides.
3. Merge keyed collections by stable id in lexicographic id order.
4. Permit child overrides only against the same discriminator variant. Changing a variant, such as a
   `zoneDistributionProof` into a `cardinalityProof`, requires disabling the original id with
   rationale and adding a new id.
5. Reject duplicate ids after case-folded normalization.
6. Apply explicit `disabledRefs` only after verifying owner, rationale, profile scope, and that the
   referenced item is not one of the canonical prototype proof clauses.
7. Validate all references after merge: role refs, profile refs, owner refs, relationship refs,
   control refs, risk acceptance refs, objective refs, selector refs, evidence refs, and capability
   refs must resolve exactly once.
8. Canonicalize sorted resolved output and calculate both artifact and semantic digests.

Cross-reference validation is all-or-nothing. An unresolved, duplicate, ambiguous, or profile-hidden
reference blocks publication; it is never silently dropped.

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

## Scope discriminated union

Scopes are not opaque strings. Manifest allowed-evidence scopes, snapshot scopes, selector scopes,
and risk/control scopes use the same bounded discriminated union with `scopeType` as the
discriminator:

| `scopeType` | Required fields | Bounds and validation |
|---|---|---|
| `subscription` | `tenantId`, `subscriptionId` | GUID format; no wildcard subscription ids. |
| `resourceGroup` | `tenantId`, `subscriptionId`, `resourceGroupName` | Name length 1-90; exact case-preserving canonical form. |
| `resourceId` | `resourceId` | Normalized Azure resource id; must be within an allowed parent scope. |
| `logAnalyticsWorkspace` | `tenantId`, `subscriptionId`, `resourceGroupName`, `workspaceName` | Workspace name length 4-63; query evidence still stores summaries only. |
| `serviceHealthRegion` | `cloud`, `region` | Closed `cloud` enum and Azure region id; no broad global default. |

Collections containing scopes are capped at 100 entries per artifact. Overlapping scopes are
canonicalized from broad to narrow but do not grant broader evidence access. A child scope outside
the manifest `allowedEvidenceScopes` fails closed.

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
    "allowedEvidenceScopes": [
      {
        "scopeType": "resourceGroup",
        "tenantId": "00000000-0000-0000-0000-000000000000",
        "subscriptionId": "00000000-0000-0000-0000-000000000000",
        "resourceGroupName": "rg-athena-fixture"
      }
    ]
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
  "audit": {
    "publishedBy": "human-approved-context-api",
    "artifactDigest": "sha256:...",
    "semanticDigest": "sha256:..."
  }
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
9. Discriminated union variants are invariant through inheritance. A child profile may adjust
   bounded scalar fields of a `zoneDistributionProof`; it may not reinterpret that proof as a
   different proof kind.
10. Cross-profile references are resolved against the final merged profile. A relationship, control,
    risk acceptance, or objective hidden by profile applicability cannot satisfy a constraint in
    that profile.

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
| `cardinality` | discriminated union | 1 | `exactlyOne`, `oneOrMore`, `zeroOrMore`, or bounded min/max. |
| `selectors` | array | 1-20 | Dynamic or explicit resource selectors. |
| `profileApplicability` | array | 1-25 | Profiles where the role exists. |
| `ownerRef` | ownership reference | 1 | Must resolve to ownership entry. |
| `approvalState` | enum | 1 | `draft`, `approved`, `deprecated`; only approved participates in published evaluation. |

Cardinality uses `cardinalityKind` as a discriminator: `exactlyOne`, `oneOrMore`, `zeroOrMore`, or
`boundedRange` with integer `minimum` and `maximum`. `boundedRange.maximum` is capped at 10,000 and
must be greater than or equal to `minimum`.

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

## Relationship discriminated unions

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

Every relationship has `relationshipClass` as its discriminator and forbids unknown properties.
Variants are:

| Variant | Required fields | Bound and rule |
|---|---|---|
| `declared` | `relationshipId`, `kind`, `from`, `to`, `profiles`, `ownerRef`, `sourceClause` | Endpoints are role refs or declared external dependency refs only. |
| `observed` | `relationshipId`, `kind`, `from`, `to`, `evidenceItemRef`, `observedAt` | Endpoints are resource refs or external evidence refs from the same snapshot. |
| `inferred` | `relationshipId`, `kind`, `from`, `to`, `confidence`, `inputEvidenceRefs`, `algorithmId` | Confidence is 0.0-1.0 and input evidence refs are capped at 20. |
| `exception` | `exceptionId`, `appliesToRelationshipRef`, `riskAcceptanceRef`, `scope`, `ownerRef`, `rationale`, `expiresAt` | Requires a matching active risk acceptance; does not itself accept risk. |

Relationship endpoints are also discriminated unions:

- `roleRef`: a role id in the resolved profile.
- `resourceRef`: a normalized resource id present in the evidence snapshot.
- `externalRef`: a declared external dependency id or bounded evidence external id.

Endpoint collections are capped at one source and one target per relationship for WC-001. N-ary
relationships must be decomposed into deterministic pairwise edges with stable ids.

Relationship precedence:

1. Declared relationships define intended semantics.
2. Observed relationships prove or disprove current state.
3. Inferred relationships may explain patterns but cannot satisfy a declared requirement unless a
   policy explicitly says inference is acceptable and cites its confidence threshold.
4. Exception relationships can explain an approved deviation only when their `riskAcceptanceRef`
   resolves to an active acceptance with matching scope. The exception never directly changes a
   verdict to `acceptedResidualRisk` and never alters the declared relationship.
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
| `authorizedScopes` | `Scope` union array | 1-100 | Scope discriminated union; must be allowed by manifest. |
| `collectedAt` | datetime | 1 | UTC. |
| `expiresAt` | datetime | 1 | Must be after `collectedAt` and policy freshness threshold. |
| `collector` | Azure MCP provenance | 1 | Tool names, versions, allowlist hash, MCP identity attestation. |
| `mcpResponses` | array | 1-500 | Canonical response envelopes from approved MCP tools. |
| `evidenceRecords` | `EvidenceRecord` union array | 0-30,000 | Bounded evidence records with digest-covered provenance. |
| `artifactDigest` | sha256 string | 1 | Digest of exact canonical snapshot bytes. |
| `semanticDigest` | sha256 string | 1 | Digest of policy-affecting normalized fields. |

Evidence record constraints:

- Resource ids must be normalized and scope-checked.
- Zones may be `unknown`, but policy then emits `unknown` for zone-dependent proof.
- Tags are bounded and treated as untrusted evidence.
- Log and metric records persist only aggregate values, query metadata, and evidence references.
- Raw log bodies, secrets, PHI, PII, credentials, and proprietary payloads are invalid.

### Evidence record discriminated union

Evidence records use `recordType` as the discriminator and forbid unknown properties.

| `recordType` | Required fields | Bound and rule |
|---|---|---|
| `resource` | `resourceId`, `resourceType`, `location`, `availabilityZone`, `tags`, `state`, `provenance` | Tags capped at 50; state is a closed enum. |
| `observedRelationship` | `relationship`, `provenance` | Relationship is the `observed` relationship variant and cites one MCP response item. |
| `metricAggregate` | `resourceId`, `metricName`, `aggregation`, `windowStart`, `windowEnd`, `value`, `unit`, `provenance` | Aggregation and unit are closed enums; no raw samples. |
| `healthEvent` | `scope`, `healthKind`, `status`, `startedAt`, `endedAt`, `summary`, `provenance` | Summary capped at 1,000 chars; no raw incident body. |
| `activitySummary` | `scope`, `operationName`, `status`, `count`, `windowStart`, `windowEnd`, `provenance` | Count only; no caller PII or request body. |
| `advisorRecommendation` | `resourceId`, `category`, `impact`, `recommendationCode`, `provenance` | Recommendation text is capped and treated as advisory only. |
| `evidenceGap` | `gapId`, `scope`, `gapReason`, `neededForClauseRef`, `collectorAttemptRef` | Used when absence of evidence itself is the cited fact. |

Closed `gapReason` values are `missing`, `stale`, `unauthorized`, `filtered`, `malformed`,
`collectorUnavailable`, `scopeMismatch`, `responseOversized`, `unsupportedTool`, and
`notRequiredByProfile`.

### Cryptographic MCP provenance

Each `mcpResponses` entry records the approved tool name, tool version, request shape digest,
response envelope digest, collected time, and collector identity attestation. The response envelope
digest covers the canonical MCP response after redaction of prohibited raw bodies and before
projection into evidence records.

Each evidence record contains:

- `itemDigest`: SHA-256 over the canonical evidence record excluding transport metadata;
- `sourceResponseDigest`: SHA-256 of the canonical MCP response envelope that produced the item;
- `sourceResponsePointer`: JSON Pointer to the exact response item or aggregate input range;
- `projectionAlgorithm`: stable id and semantic version for the projection logic; and
- `collectorIdentityAttestationRef`: reference to the collector attestation in `collector`.

The snapshot `artifactDigest` covers all `mcpResponses`, evidence records, item digests, and
attestation references. The `semanticDigest` covers only policy-affecting normalized fields and item
digests. If an evidence item cannot be tied to a digest-covered MCP response item, it is invalid.

The collector identity attestation stores no token. It records the authenticated private Azure MCP
managed identity subject, tenant, issuer, audience, issued/expiry times, attestation digest, and the
MCP host allowlist digest. A snapshot whose collector identity is the Athena context-plane identity
or whose attestation cannot be verified is rejected.

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
    "refType": "evidenceItem",
    "snapshotId": "snap-wc001-canonical-001",
    "snapshotArtifactDigest": "sha256:...",
    "snapshotSemanticDigest": "sha256:...",
    "evidenceItemDigest": "sha256:...",
    "mcpTool": "azure.resourceInventory.read",
    "mcpToolVersion": "1.0.0",
    "collectorIdentityRef": "mi-private-azure-mcp-readonly",
    "sourceResponseDigest": "sha256:...",
    "sourceResponsePointer": "/value/0"
  }
}
```

`collectorIdentityRef` is an Azure MCP evidence-plane identity reference. It must not be replaced by
an Athena context-plane identity reference for Azure resource evidence.

Findings may not be evidence-free. When the finding is about missing evidence, it must cite an
`evidenceGap` reference:

```json
{
  "refType": "evidenceGap",
  "snapshotId": "snap-wc001-canonical-001",
  "gapId": "gap-worker-zone-missing",
  "gapReason": "missing",
  "neededForClauseRef": "/constraints/worker-db-zone-colocation",
  "collectorAttemptRef": "mcp-response-attempt-001"
}
```

The `observation` verdict therefore still has evidence: either a concrete evidence item or a typed
evidence-gap reference.

## Finding kinds

Finding `findingKind` is a closed enum separate from verdict:

| `findingKind` | Purpose |
|---|---|
| `architectureConstraint` | Ordinary declared architecture requirement such as worker colocation or web zone distribution. |
| `technologyConstraint` | Supported technology limitation, such as one approved singleton database. |
| `actualSpof` | Evidence-backed single point of failure or blast-radius fact that remains true. |
| `controlHealth` | State of a compensating or governance control. |
| `riskAcceptance` | State and applicability of a risk acceptance. |
| `objective` | SLO/RTO/RPO/capacity/service-hour objective result. |
| `relationshipConflict` | Declared, observed, inferred, or exception relationship conflict. |
| `evidenceGap` | Missing, stale, unauthorized, malformed, or unsupported evidence needed for judgment. |

Finding kind determines which contract is being judged. Verdict determines the outcome. For example,
the same singleton database can yield a `technologyConstraint` finding with `expectedConstraint`, an
`actualSpof` finding with `acceptedResidualRisk`, and a `controlHealth` finding with `pass` or
`unknown`.

## Closed verdict vocabulary

Verdict strings are closed and case-sensitive:

| Verdict | Meaning | Fail-closed? |
|---|---|---|
| `pass` | Fresh evidence proves the declared requirement is satisfied and no active conflict remains. | No |
| `violation` | Fresh evidence proves a declared requirement is breached and no active risk acceptance changes the outcome. | Yes |
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

- an object contains unknown properties outside the bounded `extensions` object;
- schema version major is unsupported;
- a required capability or `minimumReaderVersion` cannot be satisfied;
- enum value is unknown;
- discriminated union variant is unknown or malformed;
- collection bound is exceeded;
- profile inheritance is circular or unresolved;
- role, relationship, constraint, objective, ownership, control, or risk references are unresolved;
- canonicalization or digest verification fails;
- an exception or risk acceptance lacks owner, rationale, scope, or expiry; or
- a selector grammar is unsupported or unbounded.

Evaluation returns `unknown` or `conflicting` and blocks automated pass when:

- evidence is missing, stale, out of scope, malformed, or oversized;
- Azure MCP provenance is missing or comes from an unapproved tool;
- an evidence item lacks a digest-covered pointer to an MCP response item;
- collector identity attestation is absent, expired, unverifiable, or not the approved private Azure
  MCP identity;
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
| `proofRequirement` | `ProofRequirement` union | 1 | Deterministic evidence required for pass or expected constraint. |
| `sourceClause` | string | 1 | Human-readable manifest clause. |
| `failureMode` | enum | 1 | `violation`, `unknown`, or `conflicting`. |

### Proof requirement discriminated union

`proofRequirement` uses `proofKind` as the discriminator and forbids unknown properties.

| `proofKind` | Required fields | Bound and rule |
|---|---|---|
| `cardinalityProof` | `roleRef`, `expected`, `resourceEvidenceRefs` | `expected` is `exactlyOne`, `oneOrMore`, `zeroOrMore`, or bounded min/max. |
| `zoneColocationProof` | `subjectRoleRef`, `anchorRoleRef`, `zoneEvidenceRefs` | Requires same snapshot and known zone for all resources. |
| `zoneDistributionProof` | `roleRef`, `minimumDistinctZones`, `zoneEvidenceRefs` | Minimum is 1-3 for WC-001; evidence refs capped at 1,000. |
| `relationshipPresenceProof` | `declaredRelationshipRef`, `observedRelationshipEvidenceRefs` | Observed refs must be from the same snapshot. |
| `evidenceFreshnessProof` | `maximumAge`, `evidenceRefs` | Maximum age is profile-resolved and capped at 30 days. |
| `controlHealthProof` | `controlRef`, `requiredHealth`, `controlEvidenceRefs` | Required health is a closed enum set. |
| `objectiveThresholdProof` | `objectiveRef`, `metricEvidenceRefs`, `comparison` | Comparison operators are `lt`, `lte`, `gt`, `gte`, `eq`. |

Every proof requirement includes `requiredEvidenceRefKinds`, `onMissingEvidence`, and
`onConflictingEvidence`. These outcomes are closed to `unknown`, `conflicting`, or `violation`.
Proof requirements never embed free-form code, query text, or direct Azure client configuration.

## Three-profile oracle

WC-001 implementation must include exactly one canonical manifest and one immutable evidence
snapshot for the first policy oracle. The fixture is synthetic and contains no customer data.

### Canonical oracle manifest

Manifest id: `wl-athena-wc001-canonical`. Required profile ids and overrides:

| Profile | Extends | Required overrides |
|---|---|---|
| `production` | none | `web.minimumDistinctZones = 2`; `zoneLossContinuityRequired = true`; active `riskAcceptanceRef = ra-db-zone-loss-prod`. |
| `development` | `production` | `web.minimumDistinctZones = 1`; `zoneLossContinuityRequired = false`; no active database zone-loss risk acceptance is required because the profile does not claim zone-loss continuity. |
| `training` | `production` | `web.minimumDistinctZones = 3`; `zoneLossContinuityRequired = true`; active `riskAcceptanceRef = ra-db-zone-loss-training`. |

Required role ids:

- `database-primary`: kind `singletonDatabase`, cardinality exactly one.
- `worker`: kind `worker`, cardinality one or more.
- `web`: kind `webService`, cardinality one or more.

Required clause ids:

- `db-singleton-supported`: `technologyConstraint`, `cardinalityProof`, one database primary.
- `db-zone-loss-spof`: `actualSpof`, evidence-backed singleton database zone-loss SPOF.
- `worker-db-zone-colocation`: `architectureConstraint`, `zoneColocationProof`, workers share
  database zone.
- `web-zone-distribution`: `architectureConstraint`, `zoneDistributionProof`, profile-specific
  minimum distinct web zones.
- `db-zone-loss-acceptance`: `riskAcceptance`, applies only where the profile has an active
  matching risk acceptance.

### Canonical oracle snapshot

Snapshot id: `snap-wc001-canonical-001`. The immutable snapshot contains these resource evidence
records and no other resources:

| Role | Resource id suffix | Zone | Notes |
|---|---|---|---|
| `database-primary` | `Microsoft.Compute/virtualMachines/athena-db-01` | `1` | Supported singleton database VM. |
| `worker` | `Microsoft.Compute/virtualMachines/athena-worker-01` | `1` | Shares database zone. |
| `worker` | `Microsoft.Compute/virtualMachines/athena-worker-02` | `1` | Shares database zone. |
| `web` | `Microsoft.Compute/virtualMachines/athena-web-01` | `1` | First web zone. |
| `web` | `Microsoft.Compute/virtualMachines/athena-web-02` | `2` | Second web zone. |

All records are in synthetic resource group `rg-athena-fixture`, subscription
`00000000-0000-0000-0000-000000000000`, and tenant
`00000000-0000-0000-0000-000000000000`. Each evidence item must cite a digest-covered MCP response
item and the private Azure MCP collector attestation.

### Expected verdict matrix

The same snapshot must be evaluated through one policy path and produce exactly this matrix:

| Clause id | Finding kind | Production | Development | Training |
|---|---|---|---|---|
| `db-singleton-supported` | `technologyConstraint` | `expectedConstraint` | `expectedConstraint` | `expectedConstraint` |
| `db-zone-loss-spof` | `actualSpof` | `acceptedResidualRisk` via `ra-db-zone-loss-prod` | `observation` with evidence item refs | `acceptedResidualRisk` via `ra-db-zone-loss-training` |
| `db-zone-loss-acceptance` | `riskAcceptance` | `acceptedResidualRisk` | `observation` with typed evidence-gap ref `notRequiredByProfile` | `acceptedResidualRisk` |
| `worker-db-zone-colocation` | `architectureConstraint` | `pass` | `pass` | `pass` |
| `web-zone-distribution` | `architectureConstraint` | `pass` because 2 >= 2 | `pass` because 2 >= 1 | `violation` because 2 < 3 |

No exception record may alter this matrix unless it references an active risk acceptance whose scope
matches the exact clause, profile, and resource set. A missing acceptance for `db-zone-loss-spof` in
a profile that requires zone-loss continuity yields `violation`, not `acceptedResidualRisk`.

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
  - actual database zone-loss SPOF is a separate `actualSpof` finding; only a matching active
    risk acceptance can yield `acceptedResidualRisk`, and the technology constraint remains
    `expectedConstraint`, not `pass`.

### Worker same-zone proof

- Role: `worker`, kind `worker`.
- Relationship: every worker `sharesZoneWith` `database-primary`.
- Evidence required: database zone and every worker zone from the same immutable snapshot.
- Verdict rules:
  - all workers in the database zone yields `pass`;
  - any worker in another known zone yields `violation`;
  - missing zone evidence for database or any worker yields `unknown`;
  - an exception must identify the exact worker scope, expiry, and active `riskAcceptanceRef`;
    without that acceptance it is explanatory only and the worker finding remains `violation` or
    `unknown`.

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

Controls use `controlKind` as a discriminator and forbid unknown properties:

| `controlKind` | Required fields | Bound and rule |
|---|---|---|
| `backup` | `controlId`, `scope`, `backupPolicyRef`, `lastSuccessfulBackupAt`, `evidenceRefs` | Backup policy ref is bounded text, not a secret. |
| `restoreTest` | `controlId`, `scope`, `lastTestedAt`, `testOutcome`, `rtoObserved`, `evidenceRefs` | `testOutcome` is `passed`, `failed`, `partial`, or `unknown`. |
| `manualFailoverRunbook` | `controlId`, `scope`, `runbookRef`, `lastReviewedAt`, `ownerRef` | Runbook ref is URI/id only; no embedded procedure body required. |
| `monitoringAlert` | `controlId`, `scope`, `alertRuleRef`, `enabledState`, `lastFiredAt`, `evidenceRefs` | `enabledState` is closed enum. |
| `capacityReview` | `controlId`, `scope`, `cadence`, `lastReviewedAt`, `nextReviewDueAt` | Cadence is closed enum and max 180 days. |
| `accessReview` | `controlId`, `scope`, `cadence`, `lastCompletedAt`, `reviewSystemRef` | No user lists or PII payloads. |
| `changeApproval` | `controlId`, `scope`, `approvalSystemRef`, `requiredForChangeKinds` | Change kinds are closed enum values. |
| `vendorSupport` | `controlId`, `scope`, `supportPlanRef`, `coverageHours`, `expiry` | Support plan ref is bounded metadata only. |

Control health evaluation produces `findingKind = controlHealth`. It cannot produce
`acceptedResidualRisk`; only a risk acceptance finding can do that.

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

Risk acceptances are the only contract that can produce a `riskAcceptance` finding with
`acceptedResidualRisk`. Exception records, control health, and technology constraints may reference a
risk acceptance, but none of them directly produce acceptance. The evaluator must verify exact
profile, clause, role/resource, owner, expiry, and digest-covered provenance before applying a
`riskAcceptanceRef`.

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
3. Each artifact carries `artifactDigest` and `semanticDigest`.
4. `artifactDigest` covers exact canonical bytes after key sorting, id normalization, transport
   metadata removal, and preservation of semantically relevant nulls.
5. `semanticDigest` covers policy-affecting normalized fields, resolved references, discriminators,
   and evidence item digests. Non-policy documentation metadata may change artifact digest without
   changing semantic digest.
6. Minor versions may add non-policy optional metadata only when older readers can ignore it safely
   and semantic digest is unchanged.
7. Policy-affecting optional fields, new proof variants, new control variants, new evidence record
   variants, new finding kinds, and new enum values cannot be silently ignored. They require either:
   - a declared `requiresCapabilities` entry;
   - a `minimumReaderVersion` whose capability negotiation succeeds before publication/evaluation;
     or
   - a major schema version.
8. Unknown required capability, unknown discriminator, unknown enum, or reader version below
   `minimumReaderVersion` fails closed.
9. Patch versions cannot change serialized semantics.
10. Extension fields are allowed only under an explicit `extensions` object with namespaced keys,
    bounded size, and no decision-making semantics unless a future ADR promotes them.
11. Published manifests and evidence snapshots are immutable. Supersession creates new versions; it
    never edits prior artifacts.

## Pydantic shape sketch

The following sketch illustrates intended contract shape only.

```python
from datetime import datetime
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


class ClosedSketch(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
FindingKind = Literal[
    "architectureConstraint",
    "technologyConstraint",
    "actualSpof",
    "controlHealth",
    "riskAcceptance",
    "objective",
    "relationshipConflict",
    "evidenceGap",
]
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

class ResourceGroupScopeSketch(ClosedSketch):
    scope_type: Literal["resourceGroup"]
    tenant_id: str
    subscription_id: str
    resource_group_name: str

class ResourceIdScopeSketch(ClosedSketch):
    scope_type: Literal["resourceId"]
    resource_id: str

ScopeSketch = Annotated[
    Union[ResourceGroupScopeSketch, ResourceIdScopeSketch],
    Field(discriminator="scope_type"),
]

class CardinalityProofSketch(ClosedSketch):
    proof_kind: Literal["cardinalityProof"]
    role_ref: str
    expected: str

class ZoneDistributionProofSketch(ClosedSketch):
    proof_kind: Literal["zoneDistributionProof"]
    role_ref: str
    minimum_distinct_zones: int

ProofRequirementSketch = Annotated[
    Union[CardinalityProofSketch, ZoneDistributionProofSketch],
    Field(discriminator="proof_kind"),
]

class WorkloadRoleSketch(ClosedSketch):
    role_id: str
    kind: RoleKind
    selectors: list[DynamicSelectorSketch]  # min 1, max 20
    cardinality: CardinalitySketch
    owner_ref: str

class EvidenceItemRefSketch(ClosedSketch):
    ref_type: Literal["evidenceItem"]
    snapshot_id: str
    snapshot_artifact_digest: str
    snapshot_semantic_digest: str
    evidence_item_digest: str
    source_response_digest: str
    source_response_pointer: str

class EvidenceGapRefSketch(ClosedSketch):
    ref_type: Literal["evidenceGap"]
    snapshot_id: str
    gap_id: str
    gap_reason: str
    needed_for_clause_ref: str

EvidenceReferenceSketch = Annotated[
    Union[EvidenceItemRefSketch, EvidenceGapRefSketch],
    Field(discriminator="ref_type"),
]

class EvidenceSnapshotSketch(ClosedSketch):
    snapshot_id: str
    snapshot_schema_version: str
    collected_at: datetime
    expires_at: datetime
    collector: AzureMcpCollectorProvenanceSketch
    authorized_scopes: list[ScopeSketch]  # min 1, max 100
    evidence_records: list[EvidenceRecordSketch]  # discriminated union, max 30_000
    artifact_digest: str
    semantic_digest: str

class ContextualFindingSketch(ClosedSketch):
    finding_id: str
    finding_kind: FindingKind
    verdict: Verdict
    context_ref: ManifestClauseRefSketch
    evidence_refs: list[EvidenceReferenceSketch]  # min 1; gaps are explicit refs
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
- scope union and every scope variant;
- relationship union and every declared, observed, inferred, and exception variant;
- relationship endpoint union;
- immutable evidence snapshot;
- evidence record union and every record variant;
- evidence reference union, including evidence gap references;
- contextual finding, finding kind, and verdict;
- architecture constraint and proof requirement union;
- compensating control union and every control variant;
- risk acceptance;
- objective;
- operational ownership reference; and
- compatibility metadata.

Schemas must include `$id`, schema version, required properties, enum values, discriminators,
`oneOf`/`anyOf` structure where appropriate, min/max collection bounds, `additionalProperties:
false`, string length limits, capability metadata, and cross-reference validation notes.

## Measurable implementation acceptance criteria

1. Contract tests prove all public enums are closed, including verdicts, relationship classes, role
   kinds, finding kinds, selector types, constraint types, control health values, objective types,
   owner roles, and gap reasons.
2. Generated JSON Schemas include required properties, discriminators, `additionalProperties: false`,
   and bounded collection constraints for every contract listed above.
3. A manifest with Production, Development, and Training profiles resolves deterministically and
   emits a stable resolved-profile digest.
4. Circular profile inheritance, missing parent profile, unresolved role reference, duplicate role id,
   ambiguous override, and weakening override without rationale all fail publication.
5. Deterministic merge tests prove keyed collections merge by id, discriminator variants cannot be
   changed by override, `disabledRefs` require owner/rationale, and all cross-references resolve
   exactly once after profile resolution.
6. Declared, observed, inferred, and exception relationships serialize as distinct discriminated
   collections and cannot be silently merged by validation or canonicalization.
7. Exception records without a matching active `riskAcceptanceRef` never produce
   `acceptedResidualRisk`.
8. Policy findings cite both a manifest clause and an Azure MCP evidence item or typed evidence-gap
   reference; missing either produces `unknown` and a blocking validation error.
9. Evidence snapshots are immutable, freshness-bound, scope-checked, canonicalized, and hash-stable
   across key ordering differences, with both artifact and semantic digests verified.
10. Evidence records include digest-covered item-to-MCP-response provenance and authenticated
    collector identity attestation.
11. Evidence collected by the Athena context identity for Azure resources is rejected; only the
    private Azure MCP collector identity reference is valid for Azure evidence.
12. Selector tests cover exact ids, tag predicates, type scope, composites, over-broad matches,
    out-of-scope matches, and low-confidence ambiguous matches.
13. The exact three-profile oracle evaluates `snap-wc001-canonical-001` under Production,
    Development, and Training through one code path and matches every verdict in the expected
    matrix.
14. Active database singleton risk acceptance produces `acceptedResidualRisk` as a separate finding
    and never converts the singleton constraint to `pass`.
15. Distinct `technologyConstraint`, `actualSpof`, `controlHealth`, and `riskAcceptance` finding
    kinds are emitted for the singleton database risk model.
16. Expired risk acceptance, stale control evidence, missing owner, and absent rationale fail closed.
17. Unknown schema major version, unknown required capability, unknown enum value, unknown
    discriminator, oversized collection, unsupported extension, malformed digest, stale evidence,
    and unapproved Azure MCP tool all fail closed.
18. Policy-affecting optional fields or enum additions require capability/minimum-reader negotiation
    or a major version; older readers cannot silently ignore them.
19. Context API publication tests prove agents and Context MCP proposal paths cannot publish
    authoritative manifests.
20. Compatibility tests prove non-policy metadata changes alter only artifact digest, policy changes
    alter semantic digest, patch versions preserve semantics, and incompatible major versions reject.
21. Security tests prove no raw log bodies, secrets, PHI, PII, credentials, or customer proprietary
    payload fields are accepted in manifests or evidence snapshots.
22. Repository validation, lint, type checks, and unit tests pass after implementation; this design
    change itself requires repository markdown/customization validation only.

## Architecture-review questions for GPT-5.6 Sol

- Does this contract set preserve the context-plane/evidence-plane identity boundary from ADR 0001?
- Are any fields likely to recreate generic Azure MCP discovery or monitoring inside Athena?
- Are scope, proof requirement, relationship, control, evidence record, and evidence reference
  unions closed and bounded enough for implementation?
- Are closed verdicts sufficient for UI, policy, and review gates without creating hidden pass states?
- Are finding kinds separated enough to prevent technology constraints, actual SPOFs, control health,
  and risk acceptance from being conflated?
- Are risk acceptance, compensating-control health, and architecture constraints separated clearly
  enough for implementation?
- Does the exception model correctly require an active risk acceptance before any
  `acceptedResidualRisk` verdict?
- Does cryptographic item-to-MCP-response provenance and collector identity attestation preserve the
  evidence-plane boundary?
- Are selector and evidence bounds measurable and safe for the first 1,000-resource synthetic test?
- Is declared-versus-inferred precedence explicit enough to prevent silent drift acceptance?
- Is the three-profile oracle exact enough for a future implementation to produce deterministic
  Production, Development, and Training results?
- Are artifact/semantic digest and capability/minimum-reader rules strict enough to prevent older
  readers from silently ignoring policy-affecting changes?
