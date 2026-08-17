from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from athena_context.api.domain import Actor, PublishedManifestView
from athena_context.api.evaluation_domain import DemoEvaluationApproval
from athena_context.api.service import ContextService
from athena_context.evidence import (
    AZURE_RESOURCE_INVENTORY_TOOL,
    CollectedEvidence,
    EvidenceCollectionCommand,
    SyncEvidenceClient,
)
from athena_context.evidence.models import EvidenceTransportRequest, McpTransportOutcome

AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL = "group_resource_list"


class PrivateMcpInvokerPort(Protocol):
    def invoke(
        self,
        private_mcp_endpoint: str,
        deployment_tool_name: str,
        request: EvidenceTransportRequest,
    ) -> McpTransportOutcome: ...


class PrivateMcpEvidenceTransport:
    """Feed the exact configured WC-008 endpoint into a narrow MCP transport adapter."""

    def __init__(
        self,
        *,
        private_mcp_endpoint: str,
        invoker: PrivateMcpInvokerPort,
    ) -> None:
        self._private_mcp_endpoint = private_mcp_endpoint
        self._invoker = invoker

    def invoke(self, request: EvidenceTransportRequest) -> McpTransportOutcome:
        if request.tool_name != AZURE_RESOURCE_INVENTORY_TOOL:
            raise ValueError("private MCP transport received an unsupported semantic tool")
        return self._invoker.invoke(
            self._private_mcp_endpoint,
            AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL,
            request,
        )


class Wc009EvidenceClientAdapter:
    """Bind the reviewed private WC-008 endpoint to the typed WC-009 client."""

    def __init__(
        self,
        *,
        private_mcp_endpoint: str,
        client: SyncEvidenceClient,
    ) -> None:
        self._private_mcp_endpoint = private_mcp_endpoint
        self._client = client

    @property
    def private_mcp_endpoint(self) -> str:
        return self._private_mcp_endpoint

    def collect(self, command: EvidenceCollectionCommand) -> CollectedEvidence:
        return self._client.collect(command)


class ContextServicePublishedContextResolver:
    """Resolve context only through the authorized WC-007 service, never its store."""

    def __init__(self, *, service: ContextService, reader_actor: Actor) -> None:
        self._service = service
        self._reader_actor = reader_actor

    def resolve(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifestView:
        return self._service.get_published(
            self._reader_actor,
            manifest_version,
            manifest_id=manifest_id,
        )


class StaticDemoEvaluationApprovalResolver:
    """Deterministic adapter for tests and explicitly injected local demo configuration."""

    def __init__(self, approvals: Iterable[DemoEvaluationApproval]) -> None:
        self._approvals = {approval.decision_id: approval for approval in approvals}

    def resolve(self, decision_id: str) -> DemoEvaluationApproval | None:
        return self._approvals.get(decision_id)


__all__ = [
    "AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL",
    "ContextServicePublishedContextResolver",
    "PrivateMcpEvidenceTransport",
    "PrivateMcpInvokerPort",
    "StaticDemoEvaluationApprovalResolver",
    "Wc009EvidenceClientAdapter",
]
