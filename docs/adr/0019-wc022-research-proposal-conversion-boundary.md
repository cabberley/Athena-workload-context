# ADR 0019: Keep WC-022 research conversion outside the runtime manifest boundary

- **Status:** Proposed
- **Date:** 2026-09-06

## Context

The public-safe Epic-on-Azure research draft retains useful abstract concepts, but it is explicitly
`draft-pre-wc-001`, `runtimeUse: prohibited`, and `loadPolicy: never-load`. It deliberately omits
customer identity, Azure resource bindings, data classification, criticality, objectives, recovery
targets, ownership assignments, evidence scopes, and approval records. Treating it as a WC-001
manifest would turn hypotheses or omissions into runtime intent.

WC-022 needs a deterministic starting point for human review without changing persistence,
publication, live monitoring, Azure access, or the canonical manifest contract being worked in
parallel.

## Decision

Add an issue-contained `athena_context.wc022_epic_proposal` package with closed Pydantic contracts
for an `athena.wc022.governedProposal.v1` artifact. The artifact is permanently marked
`unpublished` and `runtimeUse: prohibited`; it is not imported by runtime evaluators, persistence,
or monitoring code.

The sole public conversion operation takes no input. It reads the canonical repository draft and
dossier from their exact repository paths, normalizes text line endings to LF, verifies their
reviewed SHA-256 digests, parses and validates the source shape, then converts the fresh in-memory
result before it can be exposed. Line-ending normalization makes the review seal independent of
Git checkout behavior without normalizing any semantic YAML or Markdown content.
There is no reviewed descriptor, seal token, Mapping-accepting converter, or caller-supplied
`--input` path that can mint canonical provenance. The private conversion helper also accepts no
authority input and re-verifies canonical bytes before applying canonical provenance. Internal
Mapping validation remains bounded by canonical serialized size, nesting depth, and item count.

The contract additionally binds the result to a separately reviewed canonical proposal digest.
Validation requires both that `proposalDigest` is the self-digest of its canonical preimage and
that it equals the pinned reviewed conversion output. A modified artifact therefore cannot become
valid merely by recomputing its checksum; source and conversion changes require an explicit
reviewed-attestation update. The reviewed WC-022 output digest is
`sha256:7ecfab336e3146886bbc28dd614f866e010784f392ced1500d19e2c107479a7a`.

The draft must have all four research-boundary markers:

- `schemaStatus: draft-pre-wc-001`;
- `runtimeUse: prohibited`;
- `loadPolicy: never-load`; and
- `classification: public-safe-synthetic-draft`.

It selects and sorts public-safe concepts only after the shape validation: workload identity,
environment profiles, abstract roles, dependency categories, relationship hypotheses, objectives,
monitoring categories, ownership roles, recovery concepts, candidate exception requirements, and
opaque source labels. Every emitted dependency and relationship carries a non-empty, declared
source reference; missing, invalid, or undeclared references fail conversion rather than falling
back to a generic label. The output is canonical JSON with a digest computed from the raw proposal
preimage before one ordinary final contract validation. There is no unsealed validation mode.

Proposal identifiers and source references use safe NFC-normalized identifier syntax and are
unique after normalized comparison. This includes roles, environments, objectives, dependencies,
relationship hypotheses, ownership roles, placement constraints, exception candidates, and every
provenance reference surface.

Every absent, customer-specific, unsupported, or hypothesis-only value remains an `unknown` or
`humanDecisionRequired` contract value. In particular, no resource selector, identity, evidence
scope, criticality, SLO/RTO/RPO target, owner assignment, relationship semantics, monitoring
threshold, exception approval, or published version is invented. The source draft produces only
`exceptionCandidates`, never approved exceptions or an equivalent approval field. A future
authorized Context API/Studio workflow maps human-approved decisions into canonical
`riskAcceptances` or exception relationships; it is outside WC-022.

`scripts/convert_wc022_research_draft.py` is a local proposal-generation entry point. It writes
only a caller-selected new local file (or stdout), never a context store, and refuses to overwrite a
file. Human Context API review and publication remain the sole route to a runtime manifest.

## Consequences

- The conversion is deterministic, reviewable, and safe to rerun without live Azure or persistence
  access.
- The new proposal shape is intentionally incompatible with `CanonicalWorkloadManifest`; the
  research YAML fails canonical-manifest validation before evaluation. Static and isolated runtime
  import checks also prohibit WC-022 proposal or research-draft imports from production evaluators,
  Context API, and eventing modules.
- Provenance remains limited to sanitized opaque labels and a canonical source-payload digest.
  Detailed source provenance remains in the approved private evidence system.
- The package is isolated from shared WC-001 contracts to avoid creating a parallel publication
  path or conflicting with serialized contract work.

## Alternatives considered

### Load the research YAML as a runtime manifest

Rejected. Its explicit non-runtime markers and missing governed decisions require fail-closed
rejection.

### Fill unknown values with default production assumptions

Rejected. Defaults for criticality, data class, placement, parity, objectives, recovery, ownership,
and monitoring would create unsupported customer claims.

### Store or publish the converted artifact automatically

Rejected. Persistence and publication are separate governed workstreams and require authorized
human approval.

## Validation

Unit tests validate the JSON Schema and closed serialization shape, prove output stability from
the atomic canonical conversion, assert explicit unknown/human-decision values and candidate-only
exceptions, reject approved-exception fields, altered provenance labels/digests, recomputed
self-digests for modified content, unreviewed source keys, missing or unknown source references,
oversized/deep Mapping inputs, unsafe or duplicate identifiers, and deprecated descriptors,
seals, Mapping converters, and caller-controlled CLI input. They prove the raw research YAML
cannot validate as a canonical runtime manifest and cannot cross static or runtime import
boundaries into the evaluator, API, or eventing packages. The WC-005 golden proof is rerun
unchanged.
