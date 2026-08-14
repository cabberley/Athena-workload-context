# Copilot CLI launch playbook

## Before the remote exists

The repository can be developed locally. Do not add a placeholder remote.

```powershell
Set-Location C:\Users\chabberl\tempgit\athena-workload-context
git status
copilot
```

Inside Copilot CLI:

```text
/model gpt-5.6-sol --repo
/agent coordinator
```

Initial coordinator prompt:

```text
Read README.md, ARCHITECTURE.md, AGENTS.md, .github/copilot-instructions.md,
.github/agents/team.md, and docs/planning/initial-build-plan.md.

Prepare Wave 0 issues WC-001 and WC-002. Do not start dependent implementation until the public
contracts and ownership are frozen. Assign GPT-5.5 architecture design, then require GPT-5.6 Sol
fresh-context architecture challenge before MAI-Code-1.1-Flash implementation begins. Assign
MAI-Code-1.1-Flash test coverage and GPT-5.6 Sol independent code review and validation. Keep each
issue on a separate branch and preserve the context/evidence identity boundary.
```

## Day 1

Run WC-001 first. It owns contracts and ADRs. WC-002 starts only after the initial contract shapes
are available.

Recommended agents:

```text
/agent architect
/agent architecture-reviewer
/agent contract-manifest-engineer
/agent test-engineer
```

Run the architecture reviewer in a fresh Copilot session after the ADR and proposed contracts are
ready. MAI implementation must not begin until it records `approved-for-implementation`. Do not
enable broad fleet execution until WC-001 merges.

## After contract lock: complete the proof first

Run only the differentiation proof:

```text
WC-003 manifest inheritance
WC-004 contextual policy engine
WC-005 three-environment golden proof
WC-006 local reference-demo command
```

Do not start WC-007 or later until WC-005 and WC-006 are green. After that gate, use fleet or
parallel subagents for Context API, Azure MCP, cohort binding, and Context Studio. The coordinator
must ensure no two branches modify public contracts, root dependency manifests, root Bicep
orchestration, or the same application router.

## Review loop

For each implementation, launch the disabled reviewer agents manually in fresh Copilot sessions:

```text
builder implementation
  -> targeted tests
  -> /agent code-reviewer
  -> /agent security-reviewer when relevant
  -> builder corrections
  -> /agent integration-validator for an integrated milestone
  -> /agent release-reviewer for a release candidate
```

Reviewers receive requirements and the diff, not the builder's reasoning transcript.
MAI-Code-1.1-Flash applies corrections; GPT-5.6 Sol revalidates the corrected diff and test results.

Each reviewer prompt must include the issue or milestone acceptance criteria, relevant diff, and
recorded validation evidence. Reviewer profiles are intentionally not invoked automatically.

## When the GitHub repository is known

```powershell
git remote add origin https://github.com/<owner>/<repository>.git
git push -u origin main
```

Then create milestones and issues from `docs/planning/initial-build-plan.md`. Configure branch
protection after CI is visible:

- pull requests required;
- at least one human approval;
- repository validation and future CI checks required;
- conversations resolved;
- force pushes and branch deletion disabled;
- secret scanning and code scanning enabled where available.

Until the remote exists, use local issue IDs from the plan, one local branch per issue, and local
commits. Pull requests, branch protection, GitHub issues, and remote validation begin only after the
real remote is configured.
