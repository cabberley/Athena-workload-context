# ADR 0005: Evaluate role operational state from resource evidence

- **Status:** Proposed
- **Date:** 2026-08-20

## Context

The frozen `athena-web-node-fault.v1` demonstration needs Athena to distinguish a healthy web tier,
a degraded-but-available tier, an unavailable tier, and an indeterminate tier from the immutable
resource evidence already collected by WC-013. `ResourceEvidenceRecord.state` is the authoritative
observed value, but the existing pure policy context carries only evidence completeness and
availability-zone facts.

Athena must not infer that an unrecognised or missing state is healthy. The same three-node topology
must also support different minimum healthy counts for Production, Development, and Training
without introducing Azure reads, orchestration behavior, or an ARGUS-specific response shape.

## Decision

Athena adds a closed `roleOperationalStateProof` manifest proof with:

- `roleRef`;
- bounded, non-empty, unique, disjoint `healthyStates` and `failureStates`;
- `minimumHealthy`.

The `unknown` resource state cannot be classified as healthy or failed. Any unknown or state omitted
from both configured sets therefore produces the fail-closed `unknown` verdict.

`ResourceProofFact` adds the serialized `operationalState` field. Resource evidence-context builders
copy it directly from `ResourceEvidenceRecord.state`, and snapshot verification requires the proof
fact value to equal the cited immutable resource record. Older serialized proof facts that omit the
new field remain readable and default to `unknown`; they cannot satisfy the new proof.

Policy evaluation uses the existing exact role binding and evidence gates:

1. incomplete, inferred, conflicting, or mismatched role evidence remains `unknown` or
   `conflicting`;
2. unknown or unclassified operational state is `unknown`;
3. fewer healthy resources than `minimumHealthy` uses the constraint `failureVerdict`;
4. the minimum is met but at least one configured failure state is present produces `observation`
   (degraded but available);
5. all resources are healthy and the minimum is met uses the constraint `successVerdict`.

The matching closed constraint and finding variants are `roleOperationalState` and
`operationalState`. Findings use the existing manifest clause provenance and canonical,
deduplicated evidence-reference ordering. In inherited profiles, the role and state
classifications are invariant for a constraint id. Lowering `minimumHealthy` requires a governed
`constraintRequirementRelaxation`; raising it is stricter and does not.

The canonical manifest role remains `web`; its approved synthetic evidence selector binds resources
tagged `workloadRole=web-service`.

## Alternatives considered

### Evaluate the Azure snapshot directly in the policy function

Rejected. It would couple pure policy logic to the evidence transport and bypass the verified,
serialized evidence-reference context.

### Treat any non-running state as failed

Rejected. Future or unsupported states would silently receive policy meaning. Explicit state sets
and fail-closed classification preserve contract control.

### Return pass while the minimum remains healthy

Rejected. A stopped or deallocated node is operationally relevant even when service capacity
remains above the declared minimum. `observation` preserves the degraded-but-available signal.

## Security and operational consequences

- No Azure RBAC, managed identity, MCP tool allowlist, ingress, or data-boundary change is made.
- No remediation or workload mutation is introduced.
- Every operational-state finding cites the exact resource evidence used for the decision.
- Unknown, omitted, tampered, or newly introduced states fail closed for human review.

## Compatibility and rollback

Existing manifests and proof facts remain readable. Existing constraints ignore
`operationalState`; a legacy proof fact without it resolves to `unknown` only when evaluated by the
new proof. Writers producing operational-state findings must emit the field from verified resource
evidence.

Rollback removes new operational-state constraints from subsequently published manifests and stops
emitting the optional proof-fact field. Published manifests and evidence remain immutable and are
not rewritten.

## Validation

Tests cover serialized proof validation and legacy defaulting, all-running baseline, stopped and
deallocated degradation, insufficient healthy resources, unknown and unclassified states,
deterministic evidence references, verified snapshot-state binding, and Production, Development,
and Training behavior over the same three-resource topology.
