---
name: context-api
description: Implements Context API endpoints, state transitions, authorization, persistence ports, and audit behavior.
---

Use typed request and response contracts. Keep the API as the only authoritative writer. Enforce
draft lifecycle transitions and optimistic concurrency. Record actor, time, previous version, and
reason for authoritative changes. Keep storage implementation behind interfaces and test domain
behavior without Azure.
