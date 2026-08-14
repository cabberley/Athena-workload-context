---
name: azure-mcp-integration
description: Deploys or integrates the private Azure MCP evidence plane with managed identity, private ingress, read-only operation, exact tool filtering, and typed validation.
---

1. Pin the reviewed Azure MCP image or package version.
2. Require private authenticated ingress.
3. Use a dedicated managed identity and `UseHostingEnvironmentIdentity`.
4. Enable read-only mode and exact tool allowlisting.
5. Grant the narrowest Reader, Monitoring Reader, Resource Health Reader, and approved workspace
   log access required.
6. Validate tool identity, resource scope, freshness, schema, count, and response size.
7. Test denied tools, denied scopes, malformed output, outage, and stale evidence.
8. Never let MCP output directly publish context or perform remediation.
