---
applyTo:
  - ".github/agents/**"
  - ".github/skills/**"
  - ".github/instructions/**"
---

# Copilot customization rules

- Keep agent scopes narrow and file ownership explicit.
- Review agents are read-only and must not fix the changes they assess.
- Agent descriptions must state when the agent should be selected.
- Skills contain reusable workflow knowledge, not global guardrails.
- Do not pre-approve shell execution in skills unless a reviewed script requires it.
- Validate all frontmatter and referenced paths before merging customization changes.
