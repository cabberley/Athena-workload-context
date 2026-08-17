from __future__ import annotations


class ContextMcpError(Exception):
    """Bounded fail-closed error safe for an MCP transport to serialize."""

    code = "context_mcp_error"

    def __init__(self, message: str) -> None:
        bounded = message[:300]
        super().__init__(bounded)
        self.message = bounded


class ToolNotFoundError(ContextMcpError):
    code = "unknown_tool"


class ToolInputError(ContextMcpError):
    code = "invalid_tool_input"


class ToolAuthenticationError(ContextMcpError):
    code = "authentication_required"


class ToolAuthorizationError(ContextMcpError):
    code = "workload_scope_denied"


class ToolGroundingError(ContextMcpError):
    code = "grounding_failed"


class ToolResponseTooLargeError(ContextMcpError):
    code = "response_too_large"


class ToolPortError(ContextMcpError):
    code = "authoritative_port_rejected"


class ToolConfirmationError(ContextMcpError):
    code = "confirmation_rejected"


__all__ = [
    "ContextMcpError",
    "ToolAuthenticationError",
    "ToolAuthorizationError",
    "ToolConfirmationError",
    "ToolGroundingError",
    "ToolInputError",
    "ToolNotFoundError",
    "ToolPortError",
    "ToolResponseTooLargeError",
]
