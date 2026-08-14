# OpenAI-first model allocation

| Responsibility | Preferred model | Effort |
|---|---|---|
| Copilot CLI coordination and integration | GPT-5.6 Sol | high or xhigh |
| Architecture and contract design | GPT-5.5 | xhigh |
| All initial code, tests, UX, and infrastructure implementation | MAI-Code-1.1-Flash | high |
| Independent code review and validation | GPT-5.6 Sol | xhigh |
| Independent integration validation | GPT-5.6 Sol | xhigh |
| Security review | GPT-5.6 Sol | xhigh |
| Release review | GPT-5.6 Sol | xhigh |
| Exploration and command execution | GPT-5.4 mini | low or medium |

## Separation rules

1. MAI-Code-1.1-Flash writes the initial implementation and tests.
2. GPT-5.6 Sol reviews and validates every implementation in fresh context.
3. Reviewers receive requirements and the diff, not the builder's reasoning transcript.
4. Reviews remain read-only; the MAI builder applies accepted corrections.
5. Security review is separate from general code review, even though both use GPT-5.6 Sol.
6. Deterministic tests and static checks remain authoritative.
7. GPT-5.5 architecture decisions are challenged by GPT-5.6 Sol before implementation begins.
8. The coordinator runs tools and records evidence; a separate read-only GPT-5.6 Sol integration
   validator judges whether the evidence satisfies the milestone.
