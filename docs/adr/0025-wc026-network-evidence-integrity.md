# ADR 0025: Enforce exact WC-026 network and change-property identity

- **Status:** Proposed
- **Date:** 2026-09-11

## Context

WC-026 uses network flow observations and normalized resource changes to support causal
attribution. Two ambiguous identities remained possible:

- a flow could name a security rule from a different parent NSG than the enforcement resource; and
- changed-property paths differing only by case could survive normalization as distinct entries.

The report validator also compared flows without their explicit rule identity, so complete evidence
from a sibling rule could be treated as counterevidence for the selected rule.

## Decision

When `ruleResourceId` is present, its parent network security group must exactly equal
`enforcementResourceId`. Exact flow comparison includes `ruleResourceId`, preserving separate
causal and counterevidence chains for sibling rules.

Normalized change evidence rejects changed-property paths that collide after Unicode-preserving
case folding. Existing deterministic ordinal ordering remains required.

These are stricter validation rules for existing v1 evidence objects and do not add or remove wire
fields.

## Consequences

- A security rule cannot be attributed through another NSG's enforcement boundary.
- Allowed or denied observations from sibling rules do not cross-bind.
- Case variants cannot collapse inside later correlation maps or reversal checks.
- Producers emitting ambiguous evidence must fail closed and recollect normalized evidence.

## Alternatives considered

- **Resolve ambiguity only in the engine:** rejected because invalid evidence would remain usable by
  other consumers.
- **Treat all rules under one NSG as equivalent:** rejected because rule-level causality and
  counterevidence would be overstated.
- **Normalize paths to lowercase silently:** rejected because it could discard one of two
  conflicting source properties.

## Validation

- Contract tests reject a rule whose parent differs from the enforcement NSG.
- Contract tests prove sibling-rule flows are not exact matches.
- Change evidence tests reject case-insensitive changed-property collisions.
- Existing WC-025 and WC-026 contract suites, MyPy, Ruff, repository validation, and WC-005 golden
  proof remain green.
