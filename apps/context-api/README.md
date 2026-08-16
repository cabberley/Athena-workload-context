# Context API

This ASGI service is the sole authoritative writer for workload manifests. It exposes idempotent,
optimistically concurrent draft, validation, review, human approval, publication, supersession,
comparison, and audit operations.

The default composition root intentionally has no principals or grants. A deployment must inject
an authenticated actor directory and manifest-scoped role grants. Client-supplied roles and actor
types are never accepted, and agent actors are denied approval, publication, and supersession even
if they are accidentally granted a privileged role.

Published manifest values are immutable. Supersession is stored as a separate append-only relation.
