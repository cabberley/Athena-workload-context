# OpenAI-first model allocation

| Responsibility | Preferred model | Effort |
|---|---|---|
| Copilot CLI coordination and integration | GPT-5.6 Sol | high or xhigh |
| Architecture and contract design | GPT-5.5 | xhigh |
| Complex backend, Azure, and eventing implementation | GPT-5.6 Sol | high |
| Focused implementation and tests | GPT-5.3 Codex | high |
| UX and documentation | GPT-5.4 | high |
| Independent architecture and code review | GPT-5.5 | xhigh |
| Release review | GPT-5.5 | xhigh |
| Exploration and command execution | GPT-5.4 mini | low or medium |

## Separation rules

1. A model does not approve its own implementation.
2. Reviewers receive requirements and the diff, not the builder's reasoning transcript.
3. Reviews run in fresh context and remain read-only.
4. Security review is separate from general code review.
5. Deterministic tests and static checks remain authoritative.
6. GPT-5.6 Terra or Luna may be calibrated later as an additional release challenge, but is not a
   required bootstrap dependency.
