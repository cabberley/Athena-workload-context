from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from athena_context.api.domain import Actor
from athena_context.api.errors import (
    AmbiguousLookupError,
    DemoEvaluationConfigurationError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_domain import (
    DemoEvaluationApproval,
    OperatorDeploymentApproval,
    PublishedContextSelection,
    ResolvedPublishedContext,
    VerifiedWc008DeploymentConfiguration,
    Wc008DeploymentOutputAssertion,
)
from athena_context.api.service import ContextService
from athena_context.contracts import (
    TrustedKeyAnchor,
    TrustedKeyResolver,
    resolve_manifest_profile,
)
from athena_context.evidence import (
    AZURE_RESOURCE_INVENTORY_TOOL,
    Clock,
    CollectedEvidence,
    CollectorTrustConfiguration,
    EvidenceCollectionCommand,
    SyncAttemptReplayGuard,
    SyncEvidenceClient,
    SyncTrustedIngestionSigner,
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
    """Own the immutable verified WC-008 identity used for every MCP invocation."""

    def __init__(
        self,
        *,
        deployment_configuration: VerifiedWc008DeploymentConfiguration,
        invoker: PrivateMcpInvokerPort,
    ) -> None:
        self._deployment_configuration = deployment_configuration
        self._invoker = invoker

    @property
    def deployment_configuration(self) -> VerifiedWc008DeploymentConfiguration:
        return self._deployment_configuration

    def invoke(self, request: EvidenceTransportRequest) -> McpTransportOutcome:
        if request.tool_name != AZURE_RESOURCE_INVENTORY_TOOL:
            raise ValueError("private MCP transport received an unsupported semantic tool")
        return self._invoker.invoke(
            self._deployment_configuration.assertion.azure_mcp_internal_endpoint,
            AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL,
            request,
        )


class Wc009EvidenceClientAdapter:
    """Construct WC-009 around the endpoint-owning transport; no independent label exists."""

    def __init__(
        self,
        *,
        transport: PrivateMcpEvidenceTransport,
        signer: SyncTrustedIngestionSigner,
        replay_guard: SyncAttemptReplayGuard,
        clock: Clock,
        trust_configuration: CollectorTrustConfiguration,
        key_resolver: TrustedKeyResolver,
        trusted_key_anchor: TrustedKeyAnchor,
    ) -> None:
        self._transport = transport
        self._trust_configuration = trust_configuration
        self._key_resolver = key_resolver
        self._trusted_key_anchor = trusted_key_anchor
        self._client = SyncEvidenceClient(
            transport=transport,
            signer=signer,
            replay_guard=replay_guard,
            clock=clock,
            trust_configuration=trust_configuration,
            key_resolver=key_resolver,
            trusted_key_anchor=trusted_key_anchor,
        )

    @property
    def deployment_configuration(self) -> VerifiedWc008DeploymentConfiguration:
        return self._transport.deployment_configuration

    @property
    def trust_configuration(self) -> CollectorTrustConfiguration:
        return self._trust_configuration

    @property
    def key_resolver(self) -> TrustedKeyResolver:
        return self._key_resolver

    @property
    def trusted_key_anchor(self) -> TrustedKeyAnchor:
        return self._trusted_key_anchor

    def collect(self, command: EvidenceCollectionCommand) -> CollectedEvidence:
        return self._client.collect(command)


class OperatorTrustedWc008ConfigurationPort:
    """Verify a raw assertion against a separately pinned operator decision."""

    def __init__(
        self,
        *,
        assertion: Wc008DeploymentOutputAssertion,
        pinned_assertion_digest: str,
        operator_approval: OperatorDeploymentApproval,
    ) -> None:
        self._assertion = assertion
        self._pinned_assertion_digest = pinned_assertion_digest
        self._operator_approval = operator_approval

    def load_verified(self) -> VerifiedWc008DeploymentConfiguration:
        if (
            self._assertion.assertion_digest != self._pinned_assertion_digest
            or self._operator_approval.assertion_digest
            != self._pinned_assertion_digest
        ):
            raise DemoEvaluationConfigurationError(
                "WC-008 deployment outputs do not match the pinned assertion digest "
                "and operator trust decision"
            )
        return VerifiedWc008DeploymentConfiguration(
            assertion=self._assertion,
            operator_approval=self._operator_approval,
        )


class EnvironmentWc008DeploymentConfigurationPort:
    """Live adapter loading bounded operator-pinned WC-008 output files."""

    _MAX_CONFIG_BYTES = 131_072

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = dict(os.environ if environment is None else environment)

    def load_verified(self) -> VerifiedWc008DeploymentConfiguration:
        assertion_path = self._required_path(
            "ATHENA_WC013_WC008_DEPLOYMENT_ASSERTION_FILE"
        )
        approval_path = self._required_path(
            "ATHENA_WC013_WC008_OPERATOR_APPROVAL_FILE"
        )
        pinned_digest = self._environment.get(
            "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST"
        )
        if pinned_digest is None:
            raise DemoEvaluationConfigurationError(
                "live WC-008 pinned assertion digest is required"
            )
        try:
            assertion = Wc008DeploymentOutputAssertion.model_validate_json(
                self._read_bounded(assertion_path)
            )
            approval = OperatorDeploymentApproval.model_validate_json(
                self._read_bounded(approval_path)
            )
        except ValidationError as exc:
            raise DemoEvaluationConfigurationError(
                "live WC-008 configuration file is malformed or untrusted"
            ) from exc
        return OperatorTrustedWc008ConfigurationPort(
            assertion=assertion,
            pinned_assertion_digest=pinned_digest,
            operator_approval=approval,
        ).load_verified()

    def _required_path(self, variable: str) -> Path:
        value = self._environment.get(variable)
        if value is None:
            raise DemoEvaluationConfigurationError(
                f"live WC-008 configuration variable {variable} is required"
            )
        return Path(value)

    def _read_bounded(self, path: Path) -> str:
        try:
            with path.open("rb") as stream:
                content = stream.read(self._MAX_CONFIG_BYTES + 1)
        except OSError as exc:
            raise DemoEvaluationConfigurationError(
                "live WC-008 configuration file is unavailable"
            ) from exc
        if not content or len(content) > self._MAX_CONFIG_BYTES:
            raise DemoEvaluationConfigurationError(
                "live WC-008 configuration file exceeds its trusted bound"
            )
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DemoEvaluationConfigurationError(
                "live WC-008 configuration file is not valid UTF-8"
            ) from exc


class EnvironmentWc007PublishedContextSelectionPort:
    """Load an exact live WC-007 manifest version and profile selection."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = dict(os.environ if environment is None else environment)

    def load(self) -> PublishedContextSelection:
        return PublishedContextSelection(
            manifest_id=self._required("ATHENA_WC013_MANIFEST_ID"),
            manifest_version=self._required("ATHENA_WC013_MANIFEST_VERSION"),
            profile_id=self._required("ATHENA_WC013_PROFILE_ID"),
        )

    def _required(self, variable: str) -> str:
        value = self._environment.get(variable)
        if value is None or not value.strip():
            raise DemoEvaluationConfigurationError(
                f"live WC-007 context variable {variable} is required"
            )
        return value


class ContextServicePublishedContextResolver:
    """Resolve context only through the authorized WC-007 service, never its store."""

    def __init__(self, *, service: ContextService, reader_actor: Actor) -> None:
        self._service = service
        self._reader_actor = reader_actor

    def resolve(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> ResolvedPublishedContext:
        if selection.manifest_version is None:
            active = [
                view
                for view in self._service.list_published(
                    self._reader_actor,
                    selection.manifest_id,
                )
                if view.supersession is None
            ]
            if not active:
                raise ResourceNotFoundError(
                    "published manifest has no active version"
                )
            if len(active) != 1:
                raise AmbiguousLookupError(
                    "published manifest has multiple active versions"
                )
            view = active[0]
        else:
            view = self._service.get_published(
                self._reader_actor,
                selection.manifest_version,
                manifest_id=selection.manifest_id,
            )
        profile = resolve_manifest_profile(
            view.published.manifest,
            selection.profile_id,
            as_of=as_of,
        )
        return ResolvedPublishedContext(
            view=view,
            profile=profile,
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
    "EnvironmentWc007PublishedContextSelectionPort",
    "EnvironmentWc008DeploymentConfigurationPort",
    "OperatorTrustedWc008ConfigurationPort",
    "PrivateMcpEvidenceTransport",
    "PrivateMcpInvokerPort",
    "StaticDemoEvaluationApprovalResolver",
    "Wc009EvidenceClientAdapter",
]
