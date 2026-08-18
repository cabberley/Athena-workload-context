from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from inspect import getattr_static
from pathlib import Path
from types import FunctionType, MappingProxyType
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import BaseHandler, HTTPRedirectHandler, Request, build_opener

from azure.identity import DefaultAzureCredential
from pydantic import TypeAdapter, ValidationError

from athena_context.api.domain import Actor, PublishedManifestView
from athena_context.api.errors import (
    AmbiguousLookupError,
    DemoEvaluationConfigurationError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_domain import (
    OperatorDeploymentApproval,
    PublishedContextSelection,
    ResolvedPublishedContext,
    VerifiedWc008DeploymentConfiguration,
    Wc008DeploymentOutputAssertion,
    build_published_context_authority_token,
)
from athena_context.api.evaluation_ports import (
    SealedMcpTransportConfiguration,
    seal_mcp_transport_configuration,
    sealed_mcp_transport_configuration_primitives,
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
    EvidenceClientCompositionError,
    EvidenceCollectionCommand,
    McpAuthorizationFailure,
    McpFailedResponse,
    McpSuccessResponse,
    McpToolUnavailable,
    SyncAttemptReplayGuard,
    SyncEvidenceClient,
    SyncEvidenceTransport,
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


class PrivateMcpAccessTokenPort(Protocol):
    def get_token(self, private_mcp_endpoint: str) -> str: ...


class ContextApiAccessTokenPort(Protocol):
    def get_token(self, audience: str) -> str: ...


class PublishedContextReaderPort(Protocol):
    def get_published(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifestView: ...

    def list_published(self, manifest_id: str) -> tuple[PublishedManifestView, ...]: ...


class _RejectRedirectHandler(HTTPRedirectHandler):
    """Never forward an Athena managed-identity bearer token through a redirect."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class DefaultAzureCredentialContextApiToken:
    """Keyless Context API token provider for explicitly configured live runs."""

    def __init__(self) -> None:
        self._credential = DefaultAzureCredential()

    def get_token(self, audience: str) -> str:
        scope = f"{audience.rstrip('/')}/.default"
        return self._credential.get_token(scope).token


class DefaultAzureCredentialPrivateMcpToken:
    """Keyless token provider pinned to one private MCP endpoint and audience."""

    _audience: str
    _credential: DefaultAzureCredential
    _private_mcp_endpoint: str

    __slots__ = (
        "_audience",
        "_credential",
        "_private_mcp_endpoint",
    )

    def __init__(
        self,
        *,
        private_mcp_endpoint: str,
        audience: str,
    ) -> None:
        parsed = urlsplit(private_mcp_endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP token endpoint must be a trusted HTTPS origin"
            )
        if (
            type(audience) is not str
            or not audience.strip()
            or audience != audience.strip()
            or len(audience) > 512
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP managed identity audience is required"
            )
        object.__setattr__(self, "_private_mcp_endpoint", private_mcp_endpoint.rstrip("/"))
        object.__setattr__(self, "_audience", audience)
        object.__setattr__(self, "_credential", DefaultAzureCredential())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("private MCP token provider composition is immutable")

    def get_token(self, private_mcp_endpoint: str) -> str:
        if private_mcp_endpoint.rstrip("/") != self._private_mcp_endpoint:
            raise DemoEvaluationConfigurationError(
                "private MCP token request did not match its pinned endpoint"
            )
        scope = f"{self._audience.rstrip('/')}/.default"
        return self._credential.get_token(scope).token


class ManagedIdentityPrivateMcpInvoker:
    """Authenticated MCP HTTP boundary that installs a zero-redirect policy first."""

    _clock: Clock
    _http_handler: BaseHandler | None
    _token_provider: PrivateMcpAccessTokenPort

    __slots__ = (
        "_clock",
        "_http_handler",
        "_token_provider",
    )

    def __init__(
        self,
        *,
        clock: Clock,
        token_provider: PrivateMcpAccessTokenPort,
        http_handler: BaseHandler | None = None,
    ) -> None:
        object.__setattr__(self, "_clock", clock)
        object.__setattr__(self, "_http_handler", http_handler)
        object.__setattr__(
            self,
            "_token_provider",
            token_provider,
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("private MCP invoker composition is immutable")

    def invoke(
        self,
        private_mcp_endpoint: str,
        deployment_tool_name: str,
        request: EvidenceTransportRequest,
    ) -> McpTransportOutcome:
        # Install the rejection handler before obtaining or attaching a bearer token.
        handlers: tuple[BaseHandler, ...] = (
            ()
            if self._http_handler is None
            else (self._http_handler,)
        )
        opener = build_opener(_RejectRedirectHandler(), *handlers)
        credential = self._token_provider.get_token(private_mcp_endpoint)
        if (
            type(credential) is not str
            or not credential
            or credential != credential.strip()
            or any(character in credential for character in "\r\n")
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP managed identity returned an invalid credential"
            )
        endpoint = f"{private_mcp_endpoint.rstrip('/')}/"
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request.attempt_id,
                "method": "tools/call",
                "params": {
                    "name": deployment_tool_name,
                    "arguments": request.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    ),
                },
            },
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        outbound = Request(  # noqa: S310 - the endpoint is operator-sealed HTTPS
            endpoint,
            data=body,
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {credential}",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with opener.open(  # noqa: S310 - redirect handling is explicitly disabled
                outbound,
                timeout=request.bounds.timeout_milliseconds / 1_000,
            ) as response:
                response_url = response.geturl()
                status_code = response.getcode()
                content = response.read(request.bounds.max_response_bytes + 1)
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                raise DemoEvaluationConfigurationError(
                    "private MCP HTTP redirect was rejected"
                ) from exc
            observed_at = self._clock.now()
            if exc.code in {401, 403}:
                return McpAuthorizationFailure(
                    authorization_status="denied",
                    observed_at=observed_at,
                )
            content = exc.read(request.bounds.max_response_bytes + 1)
            if not content or len(content) > request.bounds.max_response_bytes:
                return McpToolUnavailable(
                    unavailable_reason="mcpUnavailable",
                    observed_at=observed_at,
                )
            return McpFailedResponse(
                body=content,
                response_received_at=observed_at,
            )
        except URLError:
            return McpToolUnavailable(
                unavailable_reason="networkUnavailable",
                observed_at=self._clock.now(),
            )
        if (
            response_url != endpoint
            or not 200 <= status_code < 300
            or not content
            or len(content) > request.bounds.max_response_bytes
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP returned an untrusted HTTP response"
            )
        return McpSuccessResponse(
            body=content,
            response_received_at=self._clock.now(),
        )


_MANAGED_IDENTITY_MCP_INVOKE_IMPLEMENTATION = (
    ManagedIdentityPrivateMcpInvoker.invoke
)


class EnvironmentContextApiPublishedContextReader:
    """Bounded HTTPS reader for the authoritative deployed Context API."""

    _MAX_RESPONSE_BYTES = 4_194_304

    def __init__(
        self,
        environment: Mapping[str, str] | None = None,
        *,
        token_provider: ContextApiAccessTokenPort | None = None,
    ) -> None:
        values = dict(os.environ if environment is None else environment)
        endpoint = values.get("ATHENA_WC013_CONTEXT_API_ENDPOINT", "").rstrip("/")
        audience = values.get("ATHENA_WC013_CONTEXT_API_AUDIENCE", "")
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise DemoEvaluationConfigurationError(
                "live Context API endpoint must be a trusted HTTPS origin"
            )
        if (
            not audience.strip()
            or audience != audience.strip()
            or len(audience) > 512
        ):
            raise DemoEvaluationConfigurationError(
                "live Context API managed identity audience is required"
            )
        self._endpoint = endpoint
        self._audience = audience
        self._token_provider = (
            token_provider or DefaultAzureCredentialContextApiToken()
        )
        self._opener = build_opener(_RejectRedirectHandler())

    def get_published(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifestView:
        path = (
            f"/v1/manifests/{quote(manifest_id, safe='')}/versions/"
            f"{quote(manifest_version, safe='')}"
        )
        return PublishedManifestView.model_validate_json(self._request(path))

    def list_published(
        self,
        manifest_id: str,
    ) -> tuple[PublishedManifestView, ...]:
        path = f"/v1/manifests/{quote(manifest_id, safe='')}/versions"
        return tuple(
            TypeAdapter(list[PublishedManifestView]).validate_json(
                self._request(path)
            )
        )

    def _request(self, path: str) -> bytes:
        credential = self._token_provider.get_token(self._audience)
        request = Request(  # noqa: S310 - endpoint was restricted to HTTPS above
            f"{self._endpoint}{path}",
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Authorization": f"Bearer {credential}",
            },
            method="GET",
        )
        try:
            with self._opener.open(  # noqa: S310
                request,
                timeout=10,
            ) as response:
                content = response.read(self._MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code == 404:
                raise ResourceNotFoundError(
                    "selected published Context API record was not found"
                ) from exc
            raise DemoEvaluationConfigurationError(
                "authoritative Context API rejected the live resolution"
            ) from exc
        except URLError as exc:
            raise DemoEvaluationConfigurationError(
                "authoritative Context API is unavailable"
            ) from exc
        if not content or len(content) > self._MAX_RESPONSE_BYTES:
            raise DemoEvaluationConfigurationError(
                "authoritative Context API response exceeded its bound"
            )
        return content


type _PrivateMcpInvokeImplementation = Callable[
    [object, str, str, EvidenceTransportRequest],
    McpTransportOutcome,
]


@dataclass(frozen=True, slots=True)
class _PrivateMcpInvokerBinding:
    invoker: PrivateMcpInvokerPort
    invoker_type: type[object]
    invoke_implementation: _PrivateMcpInvokeImplementation


def _static_instance_state(instance: object) -> Mapping[str, object] | None:
    try:
        state = object.__getattribute__(instance, "__dict__")
    except AttributeError:
        return None
    if type(state) is not dict:
        raise DemoEvaluationConfigurationError(
            "private MCP invoker has non-concrete instance state"
        )
    return MappingProxyType(cast(dict[str, object], state))


def _has_instance_invoke_override(instance: object) -> bool:
    state = _static_instance_state(instance)
    return state is not None and "invoke" in state


def _validate_invoker_instance_state(invoker: object) -> Mapping[str, object] | None:
    state = _static_instance_state(invoker)
    if state is None:
        return None
    for value in state.values():
        if callable(value):
            raise DemoEvaluationConfigurationError(
                "private MCP invoker instance state contains mutable dispatch"
            )
    return state


def _copy_invoker_with_sealed_state[Invoker: PrivateMcpInvokerPort](
    invoker: Invoker,
) -> Invoker:
    state = _validate_invoker_instance_state(invoker)
    if state is None:
        return invoker
    sealed = object.__new__(type(invoker))
    sealed_state = object.__getattribute__(sealed, "__dict__")
    if type(sealed_state) is not dict:
        raise DemoEvaluationConfigurationError(
            "private MCP invoker has non-concrete instance state"
        )
    for name, value in state.items():
        sealed_state[str.__str__(name)] = value
    return cast(Invoker, sealed)


def _seal_private_mcp_invoker(
    invoker: PrivateMcpInvokerPort,
) -> _PrivateMcpInvokerBinding:
    invoker_type = type(invoker)
    implementation = getattr_static(invoker_type, "invoke", None)
    if (
        type(implementation) is not FunctionType
        or (
            invoker_type is ManagedIdentityPrivateMcpInvoker
            and implementation is not _MANAGED_IDENTITY_MCP_INVOKE_IMPLEMENTATION
        )
        or _has_instance_invoke_override(invoker)
    ):
        raise DemoEvaluationConfigurationError(
            "private MCP invoker must expose one concrete unmodified implementation"
        )
    sealed_invoker = _copy_invoker_with_sealed_state(invoker)
    return _PrivateMcpInvokerBinding(
        invoker=sealed_invoker,
        invoker_type=invoker_type,
        invoke_implementation=cast(
            _PrivateMcpInvokeImplementation,
            implementation,
        ),
    )


def _require_exact_private_mcp_invoker(
    binding: _PrivateMcpInvokerBinding,
) -> None:
    try:
        invalid = (
            type(binding.invoker) is not binding.invoker_type
            or getattr_static(binding.invoker_type, "invoke", None)
            is not binding.invoke_implementation
            or _has_instance_invoke_override(binding.invoker)
        )
        _validate_invoker_instance_state(binding.invoker)
    except DemoEvaluationConfigurationError as exc:
        raise EvidenceClientCompositionError(
            "private MCP invoker composition changed after composition"
        ) from exc
    if invalid:
        raise EvidenceClientCompositionError(
            "private MCP invoker implementation changed after composition"
        )


class PrivateMcpEvidenceTransport:
    """Own the immutable verified WC-008 identity used for every MCP invocation."""

    _deployment_configuration: VerifiedWc008DeploymentConfiguration
    _invoker_binding: _PrivateMcpInvokerBinding
    _transport_configuration: SealedMcpTransportConfiguration

    __slots__ = (
        "_deployment_configuration",
        "_invoker_binding",
        "_transport_configuration",
    )

    def __init__(
        self,
        *,
        deployment_configuration: VerifiedWc008DeploymentConfiguration,
        invoker: PrivateMcpInvokerPort,
    ) -> None:
        try:
            normalized, sealed = seal_mcp_transport_configuration(
                deployment_configuration
            )
        except ValueError as exc:
            raise DemoEvaluationConfigurationError(
                "private MCP transport requires an exact operator-verified "
                "WC-008 configuration"
            ) from exc
        object.__setattr__(self, "_deployment_configuration", normalized)
        object.__setattr__(self, "_transport_configuration", sealed)
        object.__setattr__(
            self,
            "_invoker_binding",
            _seal_private_mcp_invoker(invoker),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("private MCP transport composition is immutable")

    @property
    def deployment_configuration(self) -> VerifiedWc008DeploymentConfiguration:
        return self._deployment_configuration

    @property
    def transport_configuration(self) -> SealedMcpTransportConfiguration:
        """Return the same sealed primitives consumed by invoke()."""

        return self._transport_configuration

    def invoke(self, request: EvidenceTransportRequest) -> McpTransportOutcome:
        return _invoke_exact_private_mcp_transport(self, request)


_PRIVATE_MCP_TRANSPORT_INVOKE_IMPLEMENTATION = PrivateMcpEvidenceTransport.invoke


def _require_exact_private_mcp_transport(
    transport: PrivateMcpEvidenceTransport,
) -> None:
    if (
        type(transport) is not PrivateMcpEvidenceTransport
        or getattr_static(PrivateMcpEvidenceTransport, "invoke", None)
        is not _PRIVATE_MCP_TRANSPORT_INVOKE_IMPLEMENTATION
        or _has_instance_invoke_override(transport)
    ):
        raise EvidenceClientCompositionError(
            "private MCP transport implementation changed after composition"
        )
    configuration = object.__getattribute__(
        transport,
        "_transport_configuration",
    )
    try:
        sealed_mcp_transport_configuration_primitives(configuration)
    except ValueError as exc:
        raise EvidenceClientCompositionError(
            "private MCP transport configuration is not sealed"
        ) from exc
    _require_exact_private_mcp_invoker(
        object.__getattribute__(transport, "_invoker_binding")
    )


def _invoke_exact_private_mcp_transport(
    transport: SyncEvidenceTransport,
    request: EvidenceTransportRequest,
) -> McpTransportOutcome:
    if type(transport) is not PrivateMcpEvidenceTransport:
        raise EvidenceClientCompositionError(
            "private MCP invocation did not receive the exact transport"
        )
    concrete_transport = cast(PrivateMcpEvidenceTransport, transport)
    _require_exact_private_mcp_transport(concrete_transport)
    if request.tool_name != AZURE_RESOURCE_INVENTORY_TOOL:
        raise ValueError("private MCP transport received an unsupported semantic tool")
    _, endpoint = sealed_mcp_transport_configuration_primitives(
        object.__getattribute__(
            concrete_transport,
            "_transport_configuration",
        )
    )
    binding = object.__getattribute__(
        concrete_transport,
        "_invoker_binding",
    )
    return binding.invoke_implementation(
        binding.invoker,
        endpoint,
        AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL,
        request,
    )


class Wc009EvidenceClientAdapter:
    """Construct WC-009 around the endpoint-owning transport; no independent label exists."""

    _client: SyncEvidenceClient
    _key_resolver: TrustedKeyResolver
    _transport: PrivateMcpEvidenceTransport
    _trust_configuration: CollectorTrustConfiguration
    _trusted_key_anchor: TrustedKeyAnchor

    __slots__ = (
        "_client",
        "_key_resolver",
        "_transport",
        "_trust_configuration",
        "_trusted_key_anchor",
    )

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
        if type(transport) is not PrivateMcpEvidenceTransport:
            raise DemoEvaluationConfigurationError(
                "WC-009 requires the exact endpoint-owning private MCP transport"
            )
        object.__setattr__(self, "_transport", transport)
        object.__setattr__(self, "_trust_configuration", trust_configuration)
        object.__setattr__(self, "_key_resolver", key_resolver)
        object.__setattr__(self, "_trusted_key_anchor", trusted_key_anchor)
        object.__setattr__(
            self,
            "_client",
            SyncEvidenceClient(
                transport=transport,
                signer=signer,
                replay_guard=replay_guard,
                clock=clock,
                trust_configuration=trust_configuration,
                key_resolver=key_resolver,
                trusted_key_anchor=trusted_key_anchor,
            ),
        )
        self._require_exact_runtime_transport()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("WC-009 evidence client composition is immutable")

    def _require_exact_runtime_transport(self) -> PrivateMcpEvidenceTransport:
        """Bind advertised configuration to the object WC-009 will invoke."""

        if (
            type(self) is not Wc009EvidenceClientAdapter
            or type(self._transport) is not PrivateMcpEvidenceTransport
            or type(self._client) is not SyncEvidenceClient
            or self._client._transport is not self._transport
        ):
            raise DemoEvaluationConfigurationError(
                "WC-009 runtime transport is not the exact sealed private "
                "MCP transport"
            )
        try:
            _require_exact_private_mcp_transport(self._transport)
        except EvidenceClientCompositionError as exc:
            raise DemoEvaluationConfigurationError(
                "WC-009 runtime transport or invoker composition changed"
            ) from exc
        return self._transport

    @property
    def deployment_configuration(self) -> VerifiedWc008DeploymentConfiguration:
        self._require_exact_runtime_transport()
        return object.__getattribute__(
            self._transport,
            "_deployment_configuration",
        )

    @property
    def transport_configuration(self) -> SealedMcpTransportConfiguration:
        self._require_exact_runtime_transport()
        return object.__getattribute__(
            self._transport,
            "_transport_configuration",
        )

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
        transport = self._require_exact_runtime_transport()
        try:
            collected = SyncEvidenceClient._collect_with_bound_transport(
                self._client,
                command,
                transport=transport,
                transport_invoke=_invoke_exact_private_mcp_transport,
            )
        except EvidenceClientCompositionError as exc:
            raise DemoEvaluationConfigurationError(
                "WC-009 runtime transport changed before MCP invocation"
            ) from exc
        self._require_exact_runtime_transport()
        return collected


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


class ContextApiPublishedContextResolver:
    """Production read adapter resolving only authoritative Context API responses."""

    def __init__(self, reader: PublishedContextReaderPort) -> None:
        self._reader = reader

    def resolve(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> ResolvedPublishedContext:
        if selection.manifest_version is None:
            active = [
                view
                for view in self._reader.list_published(selection.manifest_id)
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
            view = self._reader.get_published(
                selection.manifest_id,
                selection.manifest_version,
            )
        profile = resolve_manifest_profile(
            view.published.manifest,
            selection.profile_id,
            as_of=as_of,
        )
        return ResolvedPublishedContext(
            view=view,
            profile=profile,
            authority_token=build_published_context_authority_token(
                view,
                profile,
                requested_manifest_version=selection.manifest_version,
            ),
        )


class ContextServicePublishedContextReader:
    """Authorized in-process reader backed by real ContextService state."""

    def __init__(self, *, service: ContextService, reader_actor: Actor) -> None:
        self._service = service
        self._reader_actor = reader_actor

    def get_published(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifestView:
        return self._service.get_published(
            self._reader_actor,
            manifest_version,
            manifest_id=manifest_id,
        )

    def list_published(
        self,
        manifest_id: str,
    ) -> tuple[PublishedManifestView, ...]:
        return tuple(
            self._service.list_published(
                self._reader_actor,
                manifest_id,
            )
        )


class ContextServicePublishedContextResolver:
    """Resolve context only through the authorized WC-007 service, never its store."""

    def __init__(
        self,
        *,
        service: ContextService,
        reader_actor: Actor,
    ) -> None:
        self._resolver = ContextApiPublishedContextResolver(
            ContextServicePublishedContextReader(
                service=service,
                reader_actor=reader_actor,
            )
        )

    def resolve(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> ResolvedPublishedContext:
        return self._resolver.resolve(selection, as_of=as_of)


__all__ = [
    "AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL",
    "ContextApiPublishedContextResolver",
    "ContextServicePublishedContextReader",
    "ContextServicePublishedContextResolver",
    "DefaultAzureCredentialContextApiToken",
    "DefaultAzureCredentialPrivateMcpToken",
    "EnvironmentContextApiPublishedContextReader",
    "EnvironmentWc007PublishedContextSelectionPort",
    "EnvironmentWc008DeploymentConfigurationPort",
    "ManagedIdentityPrivateMcpInvoker",
    "OperatorTrustedWc008ConfigurationPort",
    "PrivateMcpAccessTokenPort",
    "PrivateMcpEvidenceTransport",
    "PrivateMcpInvokerPort",
    "Wc009EvidenceClientAdapter",
]
