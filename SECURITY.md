# Security

## Reporting

Do not open a public issue containing a suspected vulnerability, customer information, credentials,
resource identifiers, or log contents. Use the owning organisation's approved private security
reporting process after the GitHub repository is created.

## Security invariants

- No secrets, keys, connection strings, tokens, or customer data in source control.
- Use Managed Identity and `DefaultAzureCredential`.
- Keep Athena and Azure MCP on private authenticated endpoints.
- Keep Azure MCP read-only with an exact tool allowlist.
- Keep the Athena context identity free of workload Reader permissions.
- Store raw operational logs only in their approved Azure monitoring systems.
- Persist bounded evidence references and summaries, not unrestricted log bodies.
- Require human approval before publishing context changes or applying remediation.
