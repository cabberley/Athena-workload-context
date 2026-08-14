---
name: issue-triage
description: Routes Athena work to the correct agent, ownership lane, reviewers, dependencies, and validation. Use when creating or refining issues and plans.
---

1. State the customer or prototype outcome.
2. Identify the primary owner from `.github/agents/routing.md`.
3. List exact owned paths and serialized shared paths.
4. Define prerequisites and dependent issues.
5. Write measurable acceptance criteria and negative cases.
6. Assign MAI-Code-1.1-Flash for implementation and GPT-5.6 Sol for independent fresh-context code
   review and validation.
7. Name targeted tests and live validation, if any.
8. Reject issues that combine architecture, implementation, deployment, and release without a
   justified dependency structure.
