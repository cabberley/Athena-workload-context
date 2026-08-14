# Agent operating model

This repository is built by a senior human owner directing GitHub Copilot agents. Agents implement,
test, review, and document focused issues; humans own product direction, architecture approval,
security acceptance, and final merge decisions.

## Delivery loop

```text
Issue
  -> assigned specialist agent
  -> isolated branch or worktree
  -> implementation and targeted tests
  -> independent model review
  -> corrections
  -> pull request
  -> CI, security, and human review
  -> merge
```

Read `.github/copilot-instructions.md` and any matching files under `.github/instructions/` before
changing the repository.

## Coordination rules

1. One issue per branch and pull request.
2. Contract, root IaC orchestration, and central routing changes are serialized.
3. No agent reviews or approves its own implementation.
4. Use OpenAI-first model separation as defined in `docs/planning/model-allocation.md`.
5. Keep no more than six to eight builders active concurrently.
6. Agents must not broaden Azure RBAC, weaken private ingress, or bypass approval workflows.
7. Feature changes include tests; architecture changes include an ADR.
8. Synthetic fixtures must be clearly fake and contain no customer, PHI, PII, or proprietary data.

## Definition of done

- Acceptance criteria are demonstrably met.
- Targeted tests pass.
- Repository lint and type checks pass once those toolchains are introduced.
- Security invariants remain enforced.
- Documentation matches behavior.
- An independent reviewer has examined the change.
- The working tree contains no unrelated or sensitive artifacts.

See `.github/agents/team.md` for role ownership.
