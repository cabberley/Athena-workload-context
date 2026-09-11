# ADR 0031: Bound verified WC-026 correlation reports

- **Status:** Proposed
- **Date:** 2026-09-11

## Context

WC-027 must publish the exact verified WC-026 correlation report as an immutable artifact.
`CorrelationReport.v1` already bounds hypothesis and collection counts, but those count limits do
not bound serialized bytes. Evidence citations can contain long Azure resource identifiers and
can be repeated across ranked hypotheses. A valid engine-produced synthetic report exceeded
8 MiB even though it remained within all count and work budgets.

The artifact layer permits a maximum configured transfer of 8 MiB. Publishing an unbounded report
would therefore fail after correlation succeeded, potentially after signing or partial
publication. Raising transport limits would move rather than solve the unbounded-output problem.

## Decision

WC-026 defines `CORRELATION_MAX_CANONICAL_BYTES = 8 MiB` as an intrinsic report invariant. The same
value is part of the immutable correlation rule catalog and therefore its digest.

Before constructing or sealing a `VerifiedCorrelationReport`, the verification boundary:

1. keeps hypotheses in deterministic rank order;
2. retains the largest leading set that fits the byte budget;
3. replaces every omitted lower-ranked hypothesis with one deterministic `Unknown` omission
   record containing structural `omittedCandidateCount` and `omittedCandidateDigest` values plus a
   dedicated `omittedCandidates` missing-evidence code; and
4. fails closed if the top hypothesis plus the omission record cannot fit.

The fit calculation uses the exact canonical report document, including its digest-bound report
ID and report digest. The final `CorrelationReport` model and runtime validator independently
enforce the same byte limit. The omission hypothesis carries no supporting evidence because the
omitted set is already committed by digest and retaining current-state citations there can itself
defeat the byte bound. The WC-027 compact hypothesis projection preserves the omission count and
digest so machine consumers do not mistake a compacted report for a complete candidate set.

The report remains schema `athena.wc026CorrelationReport.v1`. This is a compatibility exception:
the report has not yet been persisted or exposed as a public runtime artifact, and WC-027
publication is the first durable consumer. Existing in-process consumers already receive reports
from the verified engine boundary and therefore gain the stronger invariant without a wire
migration.

WC-027 report publication must explicitly configure its writer, exact-version reader, and write
request to the 8-MiB limit. The general artifact default remains 1 MiB.

## Consequences

- Every successfully verified report can be persisted as one exact JSON artifact within the
  existing maximum transfer ceiling.
- Top-ranked causal conclusions are preserved; only lower-ranked candidates are summarized.
- Omission is explicit and digest-bound rather than silently truncated.
- Rule-catalog digests change, so requests created against the previous catalog fail closed and
  must be regenerated.
- Very large top hypotheses remain a deliberate hard failure rather than being partially emitted.

## Alternatives considered

- **Allow reports larger than 8 MiB:** rejected because the current transport cannot read or write
  them atomically.
- **Chunk reports:** rejected for this phase because chunk manifests, reassembly, retry recovery,
  and consumer validation add a second publication protocol.
- **Publish only a compact projection:** rejected because WC-027 requires the exact verified report
  for audit and evidence review.
- **Fail only during publication:** rejected because it would turn a successful correlation result
  into a late, partially executed publication failure.

## Validation

- An adversarial valid request first produces an unbounded report document larger than 8 MiB.
- The verified engine preserves the top hypothesis, emits one omission record, and returns an exact
  report at or below the limit.
- Repeated construction produces the same hypotheses, omission digest, report ID, and report
  digest.
- Exact-bound model validation accepts the report; limit-plus-one validation rejects it.
- Existing WC-026 correlation, WC-027 guidance, and WC-005 golden-proof behavior remains green.
