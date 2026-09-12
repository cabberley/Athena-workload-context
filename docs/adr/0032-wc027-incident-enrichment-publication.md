# ADR 0032: Publish WC-027 incident enrichment as immutable assets

- **Status:** Accepted
- **Date:** 2026-09-11

## Context

WC-027 must persist the verified WC-026 correlation report and deterministic operator guidance
without changing the existing IncidentState v1, active index, pointer, browser, or notification
contracts. Those consumers parse exact v1 shapes and must migrate before any state-version switch.

The correlation report can also be substantially larger than the 64-KiB state and guidance
budgets. A valid 64-hypothesis synthetic report with long bounded Azure resource identifiers is
more than 256 KiB. Embedding either report or guidance in an incident state would therefore break
the existing size and compatibility guarantees.

## Decision

Publish one compact `IncidentEnrichmentManifest.v1` beneath the immutable IncidentState v1
occurrence. It references, rather than embeds:

- one exact published correlation report and its attestation;
- one exact IncidentGuidance asset and its existing attestation; and
- the exact signed IncidentState v1 occurrence, incident subject, and incident-bound request.

`IncidentState.v2` is deferred until consumers can read both versions. The enrichment contract does
not change the v1 current pointer, active index, feed, notification queue, or presentation model.

### Asset layout

```text
incidents/<incident-id>/versions/<v1-result-digest-hex>/
  correlation-reports/<report-id>/report.json
  correlation-reports/<report-id>/attestation.json
  guidance/<guidance-id>/guidance.json
  guidance/<guidance-id>/attestation.json
  enrichments/<enrichment-id>/manifest.json
  enrichments/<enrichment-id>/attestation.json
```

Every reference is a `VersionPinnedBlobReference` containing the exact Blob version and SHA-256
content digest. The v1 result digest used in the path remains distinct from the content digest of
the persisted state bytes.

### Correlation report publication

`PublishedCorrelationReportAttestation.v1` signs a domain-separated
`PublishedCorrelationReportStatement.v1`, not bare report bytes. The statement binds:

- the report ID, semantic digest, and canonical-content digest;
- the exact incident ID, WC-016 transition ID, revision, and state result digest;
- exact version-pinned state and state-attestation references;
- the incident subject and incident-bound request IDs and digests;
- the correlation request and transition digests; and
- the authority proof digest returned by verified WC-026 execution.

The report remains `noAutoRemediation=true`. WC-026 first applies its intrinsic 8-MiB canonical
report budget, preserving the largest ranked prefix and one structural omission record with exact
count and digest. WC-027 uses that same 8-MiB bound and the artifact layer's maximum configurable
transfer size; all other artifact defaults remain unchanged.

### Enrichment manifest

The manifest is a maximum-64-KiB immutable join record. It repeats only compact identifiers needed
to reject cross-incident, cross-occurrence, cross-request, cross-report, or cross-guidance
substitution. It does not duplicate `IncidentGuidanceSourceBinding`; readers recover that binding
from the exact referenced guidance bytes and cross-check it against the report and occurrence. It
never duplicates v1 lifecycle, finding, reasoning, impact, or notification fields.

The manifest and report use separate attestations and signing roles. The existing
`IncidentGuidanceAttestation.v1` and `IncidentGuidanceAssetReference.v1` remain unchanged.

### Publication trust boundary

The publication service rejects all inputs before writing unless it has:

1. accepted the coherent `IncidentPublicationReceipt` returned only after the v1 current-pointer
   and active-index CAS operations complete;
2. exact-version read and verified all four occurrence assets: state, state attestation, immutable
   pointer, and pointer attestation;
3. verified the v1 state, pointer, incident-subject, and incident-bound-request signatures against
   pinned trusted keys;
4. accepted only a `VerifiedCorrelationReport` whose process receipt passes
   `CorrelationService.validate_result`;
5. verified the guidance-authority binding signature and exact immutable authority bytes;
6. generated guidance internally with `build_incident_guidance`;
7. re-parsed and byte-compared the canonical guidance; and
8. checked every report, guidance, and manifest cross-binding in this contract.

Attestation fields bind claimed preimages but do not establish that a key is trusted. Trusted key
roles remain service configuration, never data supplied by the artifact.

This is an explicit **trust-transcoding** boundary. The six published assets do not persist the full
incident subject, incident-bound request, or guidance-authority binding. Consumers trust the
separate report, guidance, and enrichment publication signatures as assertions that the publisher
verified those upstream signatures and immutable bytes. End-to-end replay of every upstream
attestation would require additional version-pinned artifacts and is outside this slice.

The process-local `VerifiedCorrelationReport` HMAC receipt is not transportable. Publication must
run synchronously with the same `CorrelationService` instance that created the receipt, or
recompute correlation inside that boundary. It must never persist or queue the current HMAC as
durable authority.

### Create-only order

The publication service writes or recovers exact existing bytes in this order:

1. correlation report;
2. correlation report attestation;
3. guidance;
4. guidance attestation;
5. enrichment manifest; and
6. enrichment attestation.

The operation is an idempotent staged saga, not an atomic storage transaction. The manifest is
published only after all referenced assets exist, and the final enrichment attestation is the
commit marker consumers require. Conflicting existing bytes fail closed. This slice creates no
mutable discovery pointer; consumer-first v1/v2 feed work will add discovery separately.

Production composition must also:

- enforce separate pinned report, guidance, and enrichment key versions and identities;
- normalize signer output to the unpadded Base64URL form required by the contracts and immediately
  self-verify every signature;
- use path/prefix-constrained create-only storage adapters with Blob versioning and reviewed
  retention controls; and
- reject selected-runbook publication until the exact immutable runbook bytes can be verified by a
  scheme-specific reader. A verified `noRunbook` outcome remains publishable.

The implementation is split between:

- `athena_context.enrichment.publication.IncidentEnrichmentPublicationService`, which owns the
  trust-transcoding and staged-saga ordering; and
- `athena_context.enrichment.azure.AzureBlobIncidentEnrichmentArtifactWriter`, which restricts
  writes to the six approved incident-enrichment paths and recovers exact current versions without
  listing.

## Consequences

- Existing IncidentState v1 consumers remain byte-for-byte compatible.
- Full reports and bounded guidance remain independently retrievable and verifiable.
- A persisted report proves both exact content and the verified occurrence/request context in which
  it was published.
- Enrichments are immutable but intentionally undiscoverable through the v1 feed until the next
  consumer migration slice.
- The later implementation needs dedicated report and enrichment signing identities without
  broadening workload read permissions.

## Alternatives considered

- **Create IncidentState v2 immediately:** rejected because existing pointers and readers are
  v1-only and duplicating v1 fields creates divergence and size risk.
- **Embed report or guidance in state:** rejected because report capacity exceeds 256 KiB and state
  remains bounded to 64 KiB.
- **Sign bare report bytes:** rejected because bytes alone do not bind the verified WC-027 incident
  occurrence, request, or authority proof.
- **Use one attestation for all assets:** rejected because report, guidance, and manifest have
  distinct trust purposes and independent retry/recovery lifecycles.

## Validation

- Strict contract round trips and unknown-field rejection.
- Deterministic digest-bound IDs and exact immutable path checks.
- Cross-incident, cross-occurrence, cross-request, cross-report, cross-guidance, content, and
  signature substitution failures.
- Maximum-hypothesis report proof above 256 KiB and below the WC-026 8-MiB publication bound.
- Existing WC-016, WC-026, WC-027, and WC-005 regression suites remain green.
