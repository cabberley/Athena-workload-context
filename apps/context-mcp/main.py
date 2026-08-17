"""Composition helper for the transport-neutral Athena Context MCP server."""

from athena_context.agent import (
    AuthoritativeFindingsPort,
    ConfirmationSignerPort,
    ConfirmationStorePort,
    ContextApiPort,
    ContextMcpServer,
    TrustedClockPort,
    build_context_mcp_server,
)


def create_server(
    *,
    context_api: ContextApiPort,
    findings: AuthoritativeFindingsPort,
    confirmation_signer: ConfirmationSignerPort,
    confirmation_store: ConfirmationStorePort,
    trusted_clock: TrustedClockPort,
) -> ContextMcpServer:
    """Compose the exact reviewed tools over deployment-supplied authoritative ports."""

    return build_context_mcp_server(
        context_api=context_api,
        findings=findings,
        confirmation_signer=confirmation_signer,
        confirmation_store=confirmation_store,
        trusted_clock=trusted_clock,
    )


__all__ = ["create_server"]
