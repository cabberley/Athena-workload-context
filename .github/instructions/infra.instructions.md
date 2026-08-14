---
applyTo:
  - "infra/**"
  - ".github/workflows/**"
---

# Infrastructure and workflow rules

- Use Bicep and managed identities; do not introduce secrets or connection strings.
- Keep Athena context and Azure MCP identities separate.
- Keep ingress private and authenticated by default.
- Azure MCP must run read-only with exact reviewed tool allowlisting.
- Scope RBAC to workload resource groups and approved workspaces unless an ADR approves broader
  discovery.
- Use separate runtime and deployment identities.
- What-if output must be reviewed for deletes, public exposure, and role broadening.
