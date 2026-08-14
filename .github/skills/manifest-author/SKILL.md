---
name: manifest-author
description: Authors and validates versioned Athena workload manifests, environment profiles, roles, selectors, relationships, constraints, controls, and risk acceptances.
---

1. Start from the canonical schema and synthetic template.
2. Define stable workload and role identifiers.
3. Model environment inheritance explicitly.
4. Separate architecture constraints, residual risk, treatment, controls, and approval.
5. Use dynamic selectors rather than long resource ID lists.
6. Resolve every role and relationship reference.
7. Validate schema, semantic rules, inheritance, and canonical representation.
8. Add compatibility and negative tests.
9. Never infer business criticality or publish without human approval.
