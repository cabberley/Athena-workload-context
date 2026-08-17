"""Composition helper for the transport-neutral Athena Context MCP server."""

from athena_context.agent import (
    AuthoritativeFindingsPort,
    ContextApiPort,
    ContextMcpServer,
    build_context_mcp_server,
)


def create_server(
    *,
    context_api: ContextApiPort,
    findings: AuthoritativeFindingsPort,
) -> ContextMcpServer:
    """Compose the exact reviewed tools over deployment-supplied authoritative ports."""

    return build_context_mcp_server(context_api=context_api, findings=findings)


__all__ = ["create_server"]
