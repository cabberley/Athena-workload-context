# Context API

This ASGI service is the sole authoritative writer for workload manifests. It exposes idempotent,
optimistically concurrent draft, validation, review, human approval, publication, supersession,
comparison, and audit operations.

The default composition root intentionally rejects every credential and has no grants. A
deployment must inject an authentication port that verifies Entra/JWT credentials before returning
typed actor claims, plus manifest-scoped role grants. `X-Athena-Actor` and other caller-supplied
identity assertions are never trusted. Agent actors are denied approval, publication, and
supersession even if they are accidentally granted a privileged role.

Published manifest values are immutable. Supersession is stored as a separate append-only relation.
Submission replaces untrusted draft audit values with a server-finalized publication candidate and
recomputes canonical digests. Human approval binds that exact candidate; publication does not
mutate it.

## WC-013 bounded demo evaluation

An explicitly composed Context API may expose `POST /v1/demo-evaluations` and
`GET /v1/demo-evaluations/{snapshot_id}`. The default composition does not expose these routes.
The mutation requires verified human publisher authority, an active trusted human approval
decision, an idempotency key, the exact published WC-005 manifest/profile digests, and one explicit
authorized evidence scope.

The integration composes the merged components without introducing direct Azure access:

- WC-008 outputs provide the HTTPS internal Container Apps endpoint, exact Azure MCP 2.0.5 tool
  list, separate identity IDs, and read assignments at explicit scopes.
- `PrivateMcpEvidenceTransport` feeds that endpoint to an injected invoker, and
  maps the WC-009 semantic inventory operation to WC-008's exact `group_resource_list` deployment
  tool. `Wc009EvidenceClientAdapter` binds the resulting typed client to the same endpoint.
- WC-009 validates tool identity, trust evidence, freshness, schema, count, size, and scope before
  the Context API sees evidence.
- Pure snapshot assembly computes canonical component digests. A trusted signing port supplies the
  RS256 attestation; production composition must back it with the configured versioned Key Vault
  key and managed identity rather than key material in configuration.
- A typed artifact store atomically appends the canonical snapshot, source envelope, human-bound
  publication record, exact findings, and idempotency receipt only after cryptographic verification
  and WC-004/WC-005 evaluation succeed.

Authorization failure, stale or malformed output, endpoint/tool unavailability, scope mismatch,
gaps, superseded context, signature failure, or golden-oracle mismatch produces no publication.
The context identity configuration forbids Azure workload roles. The MCP identity configuration
permits only reviewed read roles and forbids Context API permissions.

The deterministic tests use a clearly synthetic `.internal` endpoint and fake invoker. The optional
live authentication probe is marked `live` and skipped unless both variables are explicitly set:

```powershell
$env:ATHENA_WC013_LIVE = '1'
$env:ATHENA_WC013_PRIVATE_MCP_ENDPOINT = '<WC-008 azureMcpInternalEndpoint>'
python -m pytest tests/test_wc013_live.py -m live
```

The probe sends only an unauthenticated synthetic `tools/list` request and requires HTTP 401 or
403. It does not deploy resources, acquire credentials, collect workload evidence, or use customer
data.
