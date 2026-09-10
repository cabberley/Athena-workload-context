# ADR 0024: Bind WC-026 runtime context to immutable publication authority

- **Status:** Proposed
- **Date:** 2026-09-11

## Context

The WC-026 request contract binds manifest, profile, and dependency-graph digests, but its
publication authority did not commit the resolved dependency paths or required monitoring coverage
scopes. A caller could therefore construct a new self-consistent context binding around a genuine
publication record and present unapproved paths as published intent.

The authority also had no exact immutable storage reference for the verification boundary to read.
Comparing only caller-carried authority values cannot prove that they match durable published
state.

## Decision

`PublishedContextAuthority` commits a `contextBindingPayloadDigest` over the exact workload,
manifest, profile, dependency graph, dependency paths, and required coverage-scope digests.

`PublishedRuntimeContextBinding` carries a version-pinned immutable authority Blob reference. The
reference name is derived from the authority ID, and its content digest must match the authority's
canonical bytes. Runtime request inventory includes this reference alongside monitoring and change
evidence references.

Because these required fields are wire-incompatible with the prerequisite contract,
`CorrelationRequest` advances from v1 to `athena.wc026CorrelationRequest.v2`. The prototype has no
deployed request producer or runtime consumer yet, so no dual-read migration path is required.

The contract also exposes its confidence thresholds, mandatory caps, and collection limits as
named constants. The later engine catalog can assert exact compatibility instead of silently
duplicating contract constraints.

## Consequences

- Published runtime paths and required monitoring scopes cannot be substituted without a different
  publication authority.
- Verification can read one exact immutable authority record rather than trust a request-local
  copy.
- Existing WC-026 prototype request producers must add the authority payload digest and immutable
  reference.
- Draft-preview bindings remain separate and do not claim durable publication authority.

## Alternatives considered

- **Trust the binding's self-digest:** rejected because it proves consistency, not publication.
- **Bind only the dependency-graph digest:** rejected because the resolved paths and coverage
  requirements are the runtime authorization surface.
- **Resolve authority by caller-provided repository interface:** rejected because an untrusted
  implementation could echo the request.

## Validation

- Contract tests mutate coverage requirements while retaining the authority and must fail closed.
- Request inventory tests require the exact authority Blob reference.
- Existing report-binding, causality, digest, expiry, and deterministic-order tests remain green.
