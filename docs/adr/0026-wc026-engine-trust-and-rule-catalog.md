# ADR 0026: Bind WC-026 execution to an engine-owned rule catalog

- **Status:** Proposed
- **Date:** 2026-09-11

## Context

WC-026 receives self-consistent but untrusted correlation requests. A caller-selected rule-catalog
digest, reusable verified-input object, or independently callable raw engine would allow the report
to claim stronger provenance than the executing rules and verification path provide.

Correlation also combines multiple observations on one governed dependency path. Evidence from
different directions, five-tuples, enforcement resources, or incident intervals must not be
spliced into one causal chain.

## Decision

The correlation package owns one immutable, canonical rule catalog. Its digest is derived inside
the package and binds confidence thresholds, category order, causal property paths, score weights,
confidence ceilings, and report capacity. Verification rejects any request carrying another
catalog digest.

The supported production entry point is `CorrelationService.correlate`. It composes three
container- and identity-scoped Azure Blob readers for monitoring, change, and publication
authority, plus exact Key Vault verifiers. It verifies signed monitoring/change evidence and an
immutable publication-authority Blob, then invokes the private pure engine in one operation.
Production execution accepts published runtime bindings only. The authority commits the exact
dependency paths and required coverage scopes through a context-payload digest.

Verification and correlation are one atomic operation. The verification layer never returns a
reusable request capability; it invokes the private pure engine only after every configured proof
succeeds. Pure computation returns hypotheses rather than a runtime report. `CorrelationService`
alone builds the report and returns a `VerifiedCorrelationReport` carrying an HMAC-SHA256 receipt
bound to the report, request, catalog, context, inventory, and immutable publication-authority
proof. The service reparses requests and reports through their strict models, obtains evaluation
time from its own UTC clock, and validates the receipt before downstream use. The engine rechecks
the engine-owned catalog before processing, and raw computation returns hypotheses rather than a
runtime report.

NSG hypotheses are built per exact governed path, direction, five-tuple, enforcement resource, and
rule. Only the selected flow can satisfy direct attribution. Other chains remain separate
hypotheses, while complete exact counterevidence remains a hard conflict for its own chain.
Observation-only hypotheses require strict incident overlap and an evidenced connection to the
incident resource. Recovery scoring requires the exact degraded signal or endpoint; full
corrective credit additionally requires the same property set with exact before/after reversal.
The incident interval is the complete connected interval for each cited current-state health
stream in the immutable monitoring bundle; callers cannot narrow it to omit overlapping evidence.

## Consequences

- Reports cannot advertise a caller-invented rule catalog.
- Production callers cannot obtain or reuse a public verified-input capability.
- Evidence writers cannot create authority records in the same container or identity trust domain.
- Correlation stays deterministic and free of Azure or storage I/O after verification.
- Separate network chains may create multiple hypotheses for one change; the existing bounded
  ranking and omission record constrain report size.
- Catalog-bound candidate and evaluation-work budgets fail closed before dense change/flow inputs
  can exhaust a worker.
- Unit tests use private verification seams, while production construction rejects non-Azure
  verifier implementations.

## Alternatives considered

- **Caller-supplied catalog digest:** rejected because equality between two caller claims does not
  bind execution behavior.
- **Public verify-then-correlate API:** rejected because the intermediate capability can be forged,
  reused, or detached from the production verifier composition.
- **One NSG hypothesis per change:** rejected because it can splice attribution and corroboration
  from different flows or erase chain-specific counterevidence.

## Validation

- Contract, engine, and golden-proof tests must pass.
- Tests must reject forged internal inputs, non-production public adapters, and a mismatched catalog
  digest.
- Tests must prove strict interval handling, exact chain separation, hard-counterevidence
  preservation, exact recovery matching, contradiction bounding, report bounding, input
  permutation stability, and Python hash-seed stability.
