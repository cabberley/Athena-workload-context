---
applyTo:
  - "src/athena_context/contracts/**"
  - "src/athena_context/manifest/**"
  - "content/**"
---

# Contract and manifest rules

- Treat published manifests as human-approved declarations, not inferred truth.
- Use explicit versioned Pydantic contracts and generated JSON Schema.
- Define declared, observed, inferred, and exception provenance separately.
- Preserve unknown fields only when the schema explicitly supports extensions.
- Reject ambiguous inheritance, circular profile inheritance, and unresolved role references.
- Canonicalize before hashing or signing.
- Contract changes require an ADR and compatibility tests.
