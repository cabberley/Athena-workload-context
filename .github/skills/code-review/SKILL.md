---
name: code-review
description: Runs independent GPT-5.6 Sol review of MAI-Code-1.1-Flash implementations for correctness, regressions, contract compliance, and fail-closed behavior.
---

Review the requirements, acceptance criteria, changed files, and diff in fresh context. Do not use
the builder's reasoning transcript and do not edit.

Trace the relevant code paths and report only high-confidence defects. Include the exact file,
failure scenario, impact, and required correction. Verify tests exercise the real behavior rather
than a proxy. Ignore style and unrelated pre-existing issues.

