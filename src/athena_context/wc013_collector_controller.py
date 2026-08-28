from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from azure.identity import DefaultAzureCredential
from pydantic import Field, JsonValue, ValidationError, field_validator, model_validator

from athena_context.contracts import AthenaBaseModel, compute_artifact_digest

_ARM_SCOPE = "https://management.azure.com/.default"
_ARM_API_VERSION = "2024-03-01"
_MAX_CONTRACT_BYTES = 128 * 1024
_MAX_ARM_RESPONSE_BYTES = 256 * 1024
_GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_JOB_RESOURCE_ID_PATTERN = (
    r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}/"
    r"providers/Microsoft\.App/jobs/[A-Za-z0-9-]{1,64}$"
)
_IDENTITY_RESOURCE_ID_PATTERN = (
    r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}/"
    r"providers/Microsoft\.ManagedIdentity/userAssignedIdentities/"
    r"[A-Za-z0-9-_]{1,128}$"
)


class Wc013CollectorControllerError(RuntimeError):
    """Raised when a collector start cannot preserve the reviewed template."""


class _CollectorRegistry(AthenaBaseModel):
    server: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,253}[a-z0-9]$")
    identity: str = Field(pattern=_IDENTITY_RESOURCE_ID_PATTERN)


class _CollectorManualTrigger(AthenaBaseModel):
    parallelism: Literal[1]
    replica_completion_count: Literal[1] = Field(alias="replicaCompletionCount")


class _CollectorJobConfiguration(AthenaBaseModel):
    trigger_type: Literal["Manual"] = Field(alias="triggerType")
    replica_retry_limit: Literal[0] = Field(alias="replicaRetryLimit")
    replica_timeout: int = Field(alias="replicaTimeout", ge=1, le=900)
    manual_trigger_config: _CollectorManualTrigger = Field(alias="manualTriggerConfig")
    registries: tuple[_CollectorRegistry, ...] = Field(min_length=1, max_length=1)
    secrets: tuple[JsonValue, ...] = ()

    @field_validator("registries", "secrets", mode="before")
    @classmethod
    def normalize_configuration_arrays(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="before")
    @classmethod
    def normalize_empty_configuration_fields(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        normalized = dict(value)
        for name in ("eventTriggerConfig", "scheduleTriggerConfig"):
            if normalized.get(name) is None:
                normalized.pop(name, None)
        if normalized.get("secrets") in (None, []):
            normalized.pop("secrets", None)
        return normalized

    @model_validator(mode="after")
    def reject_secrets(self) -> _CollectorJobConfiguration:
        if self.secrets:
            raise ValueError("collector job configuration must not contain secrets")
        return self


class _CollectorEnvironmentVariable(AthenaBaseModel):
    name: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,127}$")
    value: str = Field(max_length=4096)


class _CollectorContainerResources(AthenaBaseModel):
    cpu: str
    memory: Literal["1Gi"]

    @field_validator("cpu", mode="before")
    @classmethod
    def normalize_cpu(cls, value: object) -> str:
        if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
            raise ValueError("collector CPU must be an exact numeric value")
        try:
            normalized = Decimal(str(value)).normalize()
        except InvalidOperation as exc:
            raise ValueError("collector CPU must be an exact numeric value") from exc
        if normalized != Decimal("0.5"):
            raise ValueError("collector CPU must remain exactly 0.5")
        return "0.5"


class _CollectorContainer(AthenaBaseModel):
    name: str = Field(pattern=r"^wc013-[a-z0-9-]+-evidence-collector$")
    image: str = Field(
        pattern=r"^[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9._/-]+"
        r"@sha256:[a-f0-9]{64}$"
    )
    command: tuple[str, ...] = Field(min_length=1, max_length=1)
    args: tuple[str, ...] = Field(min_length=8, max_length=8)
    env: tuple[_CollectorEnvironmentVariable, ...] = Field(min_length=4, max_length=4)
    resources: _CollectorContainerResources
    probes: tuple[JsonValue, ...] = ()
    volume_mounts: tuple[JsonValue, ...] = Field(default=(), alias="volumeMounts")

    @field_validator(
        "command",
        "args",
        "env",
        "probes",
        "volume_mounts",
        mode="before",
    )
    @classmethod
    def normalize_container_arrays(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="before")
    @classmethod
    def normalize_default_container_fields(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        normalized = dict(value)
        if normalized.get("imageType") in (None, "ContainerImage"):
            normalized.pop("imageType", None)
        for name in ("probes", "volumeMounts"):
            if normalized.get(name) in (None, []):
                normalized.pop(name, None)
        return normalized

    @model_validator(mode="after")
    def validate_fixed_collector_command(self) -> _CollectorContainer:
        if self.command != ("athena-context",):
            raise ValueError("collector command must remain the packaged Athena CLI")
        if (
            self.args[0] != "wc013-evidence-collector-job"
            or self.args[1] != "--config"
            or not self.args[2].startswith("/opt/athena/wc013-live/")
            or not self.args[2].endswith(".json")
            or self.args[3] != "--artifact-blob-endpoint"
            or self.args[5] != "--artifact-container"
            or self.args[7] != "--emit-handoff-base64"
        ):
            raise ValueError("collector arguments do not match the fixed reviewed command")
        if self.args[8:] != ():
            raise ValueError("collector arguments contain an unreviewed suffix")
        if not self.args[4].startswith("https://") or not self.args[4].endswith(
            ".blob.core.windows.net"
        ):
            raise ValueError("collector artifact endpoint is not a private Blob origin")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?", self.args[6]):
            raise ValueError("collector artifact container name is invalid")
        if self.probes or self.volume_mounts:
            raise ValueError("collector container must not add probes or volume mounts")
        return self


class _CollectorJobTemplate(AthenaBaseModel):
    containers: tuple[_CollectorContainer, ...] = Field(min_length=1, max_length=1)
    init_containers: tuple[JsonValue, ...] = Field(default=(), alias="initContainers")
    volumes: tuple[JsonValue, ...] = ()

    @field_validator("containers", "init_containers", "volumes", mode="before")
    @classmethod
    def normalize_template_arrays(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="before")
    @classmethod
    def normalize_empty_template_fields(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        normalized = dict(value)
        for name in ("initContainers", "volumes"):
            if normalized.get(name) in (None, []):
                normalized.pop(name, None)
        return normalized

    @model_validator(mode="after")
    def reject_additional_execution_surfaces(self) -> _CollectorJobTemplate:
        if self.init_containers or self.volumes:
            raise ValueError("collector template must not add init containers or volumes")
        return self


class Wc013CollectorStartContract(AthenaBaseModel):
    """Reviewed exact Container Apps Job template accepted by the controller."""

    schema_version: Literal["athena.wc013CollectorStartContract.v1"] = Field(
        alias="schemaVersion"
    )
    job_resource_id: str = Field(alias="jobResourceId", pattern=_JOB_RESOURCE_ID_PATTERN)
    evidence_identity_resource_id: str = Field(
        alias="evidenceIdentityResourceId",
        pattern=_IDENTITY_RESOURCE_ID_PATTERN,
    )
    evidence_identity_client_id: str = Field(
        alias="evidenceIdentityClientId",
        pattern=(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        ),
    )
    wc007_pinned_authority_digest: str = Field(
        alias="wc007PinnedAuthorityDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    wc008_pinned_assertion_digest: str = Field(
        alias="wc008PinnedAssertionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    configuration: _CollectorJobConfiguration
    template: _CollectorJobTemplate

    @model_validator(mode="after")
    def validate_identity_and_environment_binding(self) -> Wc013CollectorStartContract:
        registry = self.configuration.registries[0]
        if registry.identity.casefold() != self.evidence_identity_resource_id.casefold():
            raise ValueError("collector registry identity must be the evidence identity")
        environment = self.template.containers[0].env
        values = {item.name: item.value for item in environment}
        expected = {
            "AZURE_CLIENT_ID": self.evidence_identity_client_id,
            "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID": (
                self.evidence_identity_client_id
            ),
            "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST": (
                self.wc007_pinned_authority_digest
            ),
            "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": (
                self.wc008_pinned_assertion_digest
            ),
        }
        if len(values) != len(environment) or values != expected:
            raise ValueError(
                "collector environment must exactly match the reviewed evidence-only pins"
            )
        return self

    @property
    def execution_template_digest(self) -> str:
        return compute_artifact_digest(
            {
                "configuration": self.configuration.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                ),
                "template": self.template.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                ),
                "evidenceIdentityResourceId": self.evidence_identity_resource_id,
            }
        )


@dataclass(frozen=True, slots=True)
class Wc013CollectorStartResult:
    job_resource_id: str
    execution_template_digest: str
    execution_name: str | None


class Wc013CollectorJobManagementPort(Protocol):
    def get_job(self, job_resource_id: str) -> Mapping[str, JsonValue]: ...

    def start_job_with_exact_template(
        self,
        job_resource_id: str,
        template: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]: ...


class _NoRedirectHandler(HTTPRedirectHandler):
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


class _ArmHttpStack:
    def request(
        self,
        *,
        method: Literal["GET", "POST"],
        url: str,
        token: str,
        body: bytes | None,
    ) -> tuple[int, str, bytes]:
        request = Request(  # noqa: S310 - URL is built from a validated ARM resource ID.
            url,
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                **(
                    {"Content-Type": "application/json"}
                    if body is not None
                    else {}
                ),
            },
            method=method,
        )
        opener = build_opener(_NoRedirectHandler())
        with opener.open(request, timeout=30) as response:
            status = int(response.status)
            response_url = str(response.geturl())
            payload = response.read(_MAX_ARM_RESPONSE_BYTES + 1)
        return status, response_url, payload


class AzureContainerAppsCollectorJobManagementClient:
    """ARM client exposing GET and exact-template start operations."""

    def __init__(self, *, controller_identity_client_id: str) -> None:
        if _GUID_PATTERN.fullmatch(controller_identity_client_id) is None:
            raise ValueError("controller identity client ID must be a GUID")
        self._credential = DefaultAzureCredential(
            managed_identity_client_id=controller_identity_client_id,
            exclude_environment_credential=True,
            exclude_shared_token_cache_credential=True,
            exclude_visual_studio_code_credential=True,
            exclude_cli_credential=True,
            exclude_powershell_credential=True,
            exclude_developer_cli_credential=True,
            exclude_workload_identity_credential=True,
            exclude_broker_credential=True,
        )
        self._http = _ArmHttpStack()

    def _request(
        self,
        *,
        method: Literal["GET", "POST"],
        job_resource_id: str,
        start: bool,
        body: bytes | None = None,
    ) -> Mapping[str, JsonValue]:
        suffix = "/start" if start else ""
        url = (
            f"https://management.azure.com{job_resource_id}{suffix}"
            f"?api-version={_ARM_API_VERSION}"
        )
        try:
            access_token = self._credential.get_token(_ARM_SCOPE).token
            status, response_url, payload = self._http.request(
                method=method,
                url=url,
                token=access_token,
                body=body,
            )
        except (HTTPError, URLError, OSError, ValueError) as exc:
            raise Wc013CollectorControllerError(
                f"collector job ARM {method} failed closed ({type(exc).__name__})"
            ) from exc
        if (
            response_url != url
            or status not in ({200} if method == "GET" else {200, 202})
            or len(payload) > _MAX_ARM_RESPONSE_BYTES
        ):
            raise Wc013CollectorControllerError(
                f"collector job ARM {method} returned an invalid bounded response"
            )
        if not payload:
            return {}
        try:
            parsed = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Wc013CollectorControllerError(
                f"collector job ARM {method} response was not JSON"
            ) from exc
        if not isinstance(parsed, dict):
            raise Wc013CollectorControllerError(
                f"collector job ARM {method} response was not an object"
            )
        return cast(Mapping[str, JsonValue], parsed)

    def get_job(self, job_resource_id: str) -> Mapping[str, JsonValue]:
        return self._request(
            method="GET",
            job_resource_id=job_resource_id,
            start=False,
        )

    def start_job_with_exact_template(
        self,
        job_resource_id: str,
        template: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]:
        body = json.dumps(
            template,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return self._request(
            method="POST",
            job_resource_id=job_resource_id,
            start=True,
            body=body,
        )


def load_wc013_collector_start_contract(
    path: Path,
) -> Wc013CollectorStartContract:
    try:
        with path.open("rb") as stream:
            payload = stream.read(_MAX_CONTRACT_BYTES + 1)
    except OSError as exc:
        raise Wc013CollectorControllerError(
            "collector start contract is unavailable"
        ) from exc
    if not payload or len(payload) > _MAX_CONTRACT_BYTES:
        raise Wc013CollectorControllerError(
            "collector start contract is empty or oversized"
        )
    try:
        return Wc013CollectorStartContract.model_validate_json(payload)
    except ValidationError as exc:
        raise Wc013CollectorControllerError(
            "collector start contract failed closed validation"
        ) from exc


def validate_deployed_wc013_collector_job(
    contract: Wc013CollectorStartContract,
    deployed: Mapping[str, JsonValue],
) -> str:
    try:
        resource_id = deployed["id"]
        identity = deployed["identity"]
        properties = deployed["properties"]
        if (
            type(resource_id) is not str
            or resource_id.casefold() != contract.job_resource_id.casefold()
            or not isinstance(identity, dict)
            or not isinstance(properties, dict)
        ):
            raise ValueError("collector job resource identity is invalid")
        if identity.get("type") != "UserAssigned":
            raise ValueError("collector job must use only one user-assigned identity")
        assigned = identity.get("userAssignedIdentities")
        if not isinstance(assigned, dict) or {
            str(resource_id).casefold() for resource_id in assigned
        } != {contract.evidence_identity_resource_id.casefold()}:
            raise ValueError("collector job identity is not the exact evidence identity")
        configuration = _CollectorJobConfiguration.model_validate(
            properties.get("configuration")
        )
        template = _CollectorJobTemplate.model_validate(properties.get("template"))
        if configuration != contract.configuration or template != contract.template:
            raise ValueError("collector job execution template changed after review")
        return contract.execution_template_digest
    except (KeyError, TypeError, ValidationError, ValueError) as exc:
        raise Wc013CollectorControllerError(
            "deployed collector job does not match its exact reviewed template"
        ) from exc


def run_governed_wc013_collector_start(
    contract_path: Path,
    *,
    controller_identity_client_id: str,
    management: Wc013CollectorJobManagementPort | None = None,
    validate_only: bool = False,
) -> Wc013CollectorStartResult:
    contract = load_wc013_collector_start_contract(contract_path)
    client = management or AzureContainerAppsCollectorJobManagementClient(
        controller_identity_client_id=controller_identity_client_id
    )
    deployed = client.get_job(contract.job_resource_id)
    template_digest = validate_deployed_wc013_collector_job(contract, deployed)
    execution_name: str | None = None
    if not validate_only:
        exact_template = cast(
            Mapping[str, JsonValue],
            contract.template.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
        )
        response = client.start_job_with_exact_template(
            contract.job_resource_id,
            exact_template,
        )
        candidate = response.get("name")
        if candidate is not None and (
            type(candidate) is not str or not 1 <= len(candidate) <= 128
        ):
            raise Wc013CollectorControllerError(
                "collector start response contained an invalid execution name"
            )
        execution_name = cast(str | None, candidate)
    return Wc013CollectorStartResult(
        job_resource_id=contract.job_resource_id,
        execution_template_digest=template_digest,
        execution_name=execution_name,
    )


__all__ = [
    "AzureContainerAppsCollectorJobManagementClient",
    "Wc013CollectorControllerError",
    "Wc013CollectorJobManagementPort",
    "Wc013CollectorStartContract",
    "Wc013CollectorStartResult",
    "load_wc013_collector_start_contract",
    "run_governed_wc013_collector_start",
    "validate_deployed_wc013_collector_job",
]
