---
applyTo:
  - "tests/**"
---

# Test rules

- Use clearly synthetic fixtures.
- Keep unit tests Azure-free and deterministic.
- Test Production, Development, and Training using the same topology fixture and code path.
- Test ambiguous and conflicting cohort bindings fail closed.
- Test contextual constraints separately from risk acceptance and compensating controls.
- Mark live Azure tests explicitly and keep them out of the default fast suite.
- Include negative security and authorization cases.
