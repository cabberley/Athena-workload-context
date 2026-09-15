from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import sleep
from typing import Any, Literal, NoReturn, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.artifacts import (
    ArtifactAlreadyExistsError,
    ArtifactCurrentReadRequest,
    ArtifactMetadataHashes,
    ArtifactReadError,
    ArtifactWriteError,
    ArtifactWriteRequest,
    CreateOnlyArtifactWriterPort,
    CurrentArtifactReaderPort,
)
from athena_context.azure_adapters import (
    AzureBlobChangeEvidenceReplayStore,
    KeyVaultRsaPublicKeyVerifier,
    KeyVaultRsaSigner,
    KeyVaultTrustedKeyResolver,
)
from athena_context.contracts import (
    MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
    MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
    ApprovedChangeScope,
    ChangeEvidencePersistenceHandoff,
    CorrelationRequest,
    MonitoringAcquisitionReceipt,
    MonitoringCollectorContract,
    MonitoringEvidenceAttestation,
    MonitoringEvidenceHandoff,
    PublishedMonitoringIntent,
    PublishedMonitoringIntentAssetReference,
    PublishedMonitoringIntentAttestation,
    PublishedRuntimeContextBinding,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    TrustedKeyResolver,
    VersionPinnedBlobReference,
    canonicalize_json,
    compute_artifact_digest,
    monitoring_handoff_preimage,
    sha256_hex,
    validate_monitoring_intent_activation_eligible,
    validate_published_monitoring_intent_assets,
    verify_monitoring_acquisition_receipt_attestation,
    verify_monitoring_evidence_handoff_attestation,
)
from athena_context.eventing.change_ingestion import KeyVaultChangeEvidenceSigner
from athena_context.monitoring_acquisition import (
    ActivityLogQueryRequest,
    ActivityLogQueryResult,
    CredentialBoundMonitoringAcquisitionAdapter,
    IpFlowVerifyRequest,
    IpFlowVerifyResult,
    LogAnalyticsQueryRequest,
    LogAnalyticsQueryResult,
    MonitoringAcquisitionAuthority,
    MonitoringAcquisitionCoordinator,
    MonitoringAcquisitionError,
    MonitoringAcquisitionOutcome,
    ResourceGraphChangeQueryRequest,
    ResourceGraphChangeQueryResult,
    ResourceHealthQueryRequest,
    ResourceHealthQueryResult,
)
from athena_context.monitoring_collection import (
    CommittedMonitoringCollection,
    MonitoringCollectionError,
    MonitoringCollectionTransaction,
    PreparedMonitoringCollection,
)

_RESOURCE_GRAPH_ENDPOINT = (
    "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"
    "?api-version=2022-10-01"
)
_IDENTITY_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/"
    r"providers/microsoft\.managedidentity/userassignedidentities/[a-z0-9-_]{1,128}$"
)
_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/providers/"
    r"[a-z0-9.]+/[a-z0-9._()-]+/[a-z0-9._()-]+"
    r"(?:/[a-z0-9._()-]+/[a-z0-9._()-]+)*$"
)
_STORAGE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/providers/"
    r"microsoft\.storage/storageaccounts/[a-z0-9]{3,24}$"
)
_GUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_MAX_CONFIGURATION_BYTES = 512 * 1024
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_ROWS = 500


class MonitoringAcquisitionJobError(RuntimeError):
    """Raised when the production WC-028 acquisition job cannot fail closed."""


class _StrictRuntimeModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        populate_by_name=True,
    )


class MonitoringRuntimeTrustedKey(_StrictRuntimeModel):
    key_vault_key_id: str = Field(alias="keyVaultKeyId", min_length=1, max_length=2048)
    public_key_fingerprint: str = Field(
        alias="publicKeyFingerprint",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    activated_at: datetime = Field(alias="activatedAt")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")

    @model_validator(mode="after")
    def validate_key(self) -> MonitoringRuntimeTrustedKey:
        anchor = self.anchor
        del anchor
        for value in (self.activated_at, self.expires_at):
            if value is not None and (
                value.utcoffset() != UTC.utcoffset(value) or value.microsecond % 1000
            ):
                raise ValueError("trusted key times must use millisecond UTC")
        if self.expires_at is not None and self.expires_at <= self.activated_at:
            raise ValueError("trusted key expiry must follow activation")
        return self

    @property
    def anchor(self) -> TrustedKeyAnchor:
        return TrustedKeyAnchor.from_key_vault_key_id(
            self.key_vault_key_id,
            public_key_fingerprint=self.public_key_fingerprint,
        )


class Wc028MonitoringAcquisitionJobConfiguration(_StrictRuntimeModel):
    schema_version: Literal["athena.wc028MonitoringAcquisitionJobConfiguration.v1"] = Field(
        alias="schemaVersion"
    )
    managed_identity_client_id: str = Field(
        alias="managedIdentityClientId",
        pattern=_GUID_PATTERN.pattern,
    )
    collector_identity_resource_id: str = Field(alias="collectorIdentityResourceId")
    athena_context_identity_resource_id: str = Field(alias="athenaContextIdentityResourceId")
    source_storage_account_resource_id: str = Field(alias="sourceStorageAccountResourceId")
    evidence_storage_account_resource_id: str = Field(alias="evidenceStorageAccountResourceId")
    evidence_blob_endpoint: str = Field(alias="evidenceBlobEndpoint")
    evidence_container_name: Literal["monitoring-evidence"] = Field(alias="evidenceContainerName")
    change_evidence_storage_account_resource_id: str = Field(
        alias="changeEvidenceStorageAccountResourceId"
    )
    change_evidence_blob_endpoint: str = Field(alias="changeEvidenceBlobEndpoint")
    change_evidence_container_name: Literal["change-evidence"] = Field(
        alias="changeEvidenceContainerName"
    )
    workspace_resource_id: str = Field(alias="workspaceResourceId")
    workspace_customer_id: str = Field(
        alias="workspaceCustomerId",
        pattern=_GUID_PATTERN.pattern,
    )
    network_watcher_resource_id: str = Field(alias="networkWatcherResourceId")
    monitoring_intent_trusted_key: MonitoringRuntimeTrustedKey = Field(
        alias="monitoringIntentTrustedKey"
    )
    collector_signing_key: MonitoringRuntimeTrustedKey = Field(alias="collectorSigningKey")
    monitoring_intent: dict[str, object] = Field(alias="monitoringIntent")
    monitoring_intent_reference: dict[str, object] = Field(alias="monitoringIntentReference")
    monitoring_intent_attestation: dict[str, object] = Field(alias="monitoringIntentAttestation")
    context_binding: dict[str, object] = Field(alias="contextBinding")
    acquisition_authority: dict[str, object] = Field(alias="acquisitionAuthority")
    monitoring_collector_contract: dict[str, object] = Field(alias="monitoringCollectorContract")
    approved_change_scope: dict[str, object] = Field(alias="approvedChangeScope")
    expected_active_context_authority_digest: str = Field(
        alias="expectedActiveContextAuthorityDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    expected_acquisition_authority_digest: str = Field(
        alias="expectedAcquisitionAuthorityDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    incident_revision: int = Field(alias="incidentRevision", ge=1)
    trust_delay_seconds: int = Field(alias="trustDelaySeconds", ge=1, le=600)
    request_lifetime_seconds: int = Field(
        alias="requestLifetimeSeconds",
        ge=2,
        le=900,
    )
    http_timeout_seconds: int = Field(
        default=30,
        alias="httpTimeoutSeconds",
        ge=1,
        le=60,
    )
    http_retry_limit: int = Field(
        default=2,
        alias="httpRetryLimit",
        ge=0,
        le=3,
    )

    @field_validator(
        "collector_identity_resource_id",
        "athena_context_identity_resource_id",
    )
    @classmethod
    def validate_identity_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        if _IDENTITY_PATTERN.fullmatch(normalized) is None:
            raise ValueError("runtime identity resource ID is invalid")
        return normalized

    @field_validator(
        "source_storage_account_resource_id",
        "evidence_storage_account_resource_id",
        "change_evidence_storage_account_resource_id",
    )
    @classmethod
    def validate_storage_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        if _STORAGE_ID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("runtime storage account resource ID is invalid")
        return normalized

    @field_validator("workspace_resource_id", "network_watcher_resource_id")
    @classmethod
    def validate_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        if _RESOURCE_ID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("runtime Azure resource ID is invalid")
        return normalized

    @field_validator("evidence_blob_endpoint", "change_evidence_blob_endpoint")
    @classmethod
    def validate_blob_endpoint(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.hostname is None
            or not parsed.hostname.endswith(".blob.core.windows.net")
        ):
            raise ValueError("evidence Blob endpoint must be an Azure public-cloud origin")
        return f"https://{parsed.hostname}"

    @model_validator(mode="after")
    def validate_boundary(self) -> Wc028MonitoringAcquisitionJobConfiguration:
        if self.collector_identity_resource_id == self.athena_context_identity_resource_id:
            raise ValueError("monitoring and Athena context identities must be separate")
        if self.source_storage_account_resource_id == self.evidence_storage_account_resource_id:
            raise ValueError("source authority and monitoring evidence storage must be separate")
        if self.trust_delay_seconds >= self.request_lifetime_seconds:
            raise ValueError("request lifetime must extend beyond trustedAsOf")
        expected_storage_account_name = self.evidence_storage_account_resource_id.rsplit(
            "/",
            maxsplit=1,
        )[-1]
        if (
            urlsplit(self.evidence_blob_endpoint).hostname
            != f"{expected_storage_account_name}.blob.core.windows.net"
        ):
            raise ValueError("evidence Blob endpoint does not match the reviewed storage account")
        expected_change_storage_account_name = (
            self.change_evidence_storage_account_resource_id.rsplit(
                "/",
                maxsplit=1,
            )[-1]
        )
        if (
            urlsplit(self.change_evidence_blob_endpoint).hostname
            != f"{expected_change_storage_account_name}.blob.core.windows.net"
        ):
            raise ValueError(
                "change evidence Blob endpoint does not match the reviewed storage account"
            )

        contract = self.monitoring_collector_contract
        authority = self.acquisition_authority
        collector_principal_id = str(contract.get("monitoringReaderPrincipalId", "")).casefold()
        collector_tenant_id = str(contract.get("collectorTenantId", "")).casefold()
        context_principal_id = str(contract.get("athenaContextPrincipalId", "")).casefold()
        exact_bindings = (
            (
                contract.get("schemaVersion"),
                MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
                "collector contract schema",
            ),
            (
                contract.get("handoffSchemaVersion"),
                "athena.wc028MonitoringEvidenceHandoff.v2",
                "collector contract handoff schema",
            ),
            (
                contract.get("acquisitionReceiptSchemaVersion"),
                MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
                "collector contract receipt schema",
            ),
            (
                str(contract.get("collectorIdentityClientId", "")).casefold(),
                self.managed_identity_client_id.casefold(),
                "collector contract client identity",
            ),
            (
                str(contract.get("collectorIdentityResourceId", "")).casefold(),
                self.collector_identity_resource_id,
                "collector contract resource identity",
            ),
            (
                str(contract.get("athenaContextIdentityId", "")).casefold(),
                self.athena_context_identity_resource_id,
                "collector contract context identity",
            ),
            (
                str(contract.get("workspaceResourceId", "")).casefold(),
                self.workspace_resource_id,
                "collector contract workspace",
            ),
            (
                str(contract.get("evidenceStorageAccountResourceId", "")).casefold(),
                self.evidence_storage_account_resource_id,
                "collector contract evidence storage",
            ),
            (
                contract.get("evidenceContainerName"),
                self.evidence_container_name,
                "collector contract evidence container",
            ),
            (
                contract.get("signingKeyResourceId"),
                self.collector_signing_key.key_vault_key_id,
                "collector contract signing key",
            ),
            (
                str(contract.get("ipFlowVerifyScopeId", "")).casefold(),
                self.network_watcher_resource_id,
                "collector contract IP Flow Verify scope",
            ),
            (
                contract.get("physicalIdentitySeparationEnforced"),
                True,
                "collector contract physical identity separation",
            ),
            (
                authority.get("schemaVersion"),
                "athena.wc028MonitoringAcquisitionAuthority.v3",
                "acquisition authority schema",
            ),
            (
                str(authority.get("monitoringReaderIdentityId", "")).casefold(),
                self.collector_identity_resource_id,
                "acquisition reader identity",
            ),
            (
                str(authority.get("monitoringReaderPrincipalId", "")).casefold(),
                collector_principal_id,
                "acquisition reader principal",
            ),
            (
                str(authority.get("monitoringReaderClientId", "")).casefold(),
                self.managed_identity_client_id.casefold(),
                "acquisition reader client",
            ),
            (
                str(authority.get("monitoringReaderTenantId", "")).casefold(),
                collector_tenant_id,
                "acquisition reader tenant",
            ),
            (
                str(authority.get("athenaContextIdentityId", "")).casefold(),
                self.athena_context_identity_resource_id,
                "acquisition context identity",
            ),
            (
                str(authority.get("athenaContextPrincipalId", "")).casefold(),
                context_principal_id,
                "acquisition context principal",
            ),
            (
                authority.get("receiptSigningKeyId"),
                self.collector_signing_key.key_vault_key_id,
                "acquisition receipt signing key",
            ),
            (
                authority.get("authorityDigest"),
                self.expected_acquisition_authority_digest,
                "acquisition authority digest",
            ),
            (
                authority.get("contextBindingDigest"),
                self.context_binding.get("bindingDigest"),
                "acquisition context binding digest",
            ),
            (
                authority.get("requiredCoverageScopeDigests"),
                self.context_binding.get("requiredCoverageScopeDigests"),
                "acquisition required coverage",
            ),
        )
        for actual, expected, label in exact_bindings:
            if actual != expected:
                raise ValueError(f"{label} does not match the production deployment")
        if (
            _GUID_PATTERN.fullmatch(collector_principal_id) is None
            or _GUID_PATTERN.fullmatch(collector_tenant_id) is None
            or _GUID_PATTERN.fullmatch(context_principal_id) is None
            or collector_principal_id == context_principal_id
        ):
            raise ValueError("collector contract principal identities must be valid and separate")
        environment_client_id = os.environ.get("AZURE_CLIENT_ID")
        if (
            environment_client_id is not None
            and environment_client_id.casefold() != self.managed_identity_client_id.casefold()
        ):
            raise ValueError("AZURE_CLIENT_ID does not match the configured collector identity")
        evidence_container_resource_id = (
            f"{self.evidence_storage_account_resource_id}/blobservices/default/"
            f"containers/{self.evidence_container_name}"
        )
        change_evidence_container_resource_id = (
            f"{self.change_evidence_storage_account_resource_id}/blobservices/default/"
            f"containers/{self.change_evidence_container_name}"
        )
        deployment_bindings = (
            (
                "ATHENA_WC028_DEPLOYED_COLLECTOR_IDENTITY_RESOURCE_ID",
                self.collector_identity_resource_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_COLLECTOR_IDENTITY_PRINCIPAL_ID",
                collector_principal_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_ATHENA_CONTEXT_IDENTITY_RESOURCE_ID",
                self.athena_context_identity_resource_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_SOURCE_STORAGE_ACCOUNT_RESOURCE_ID",
                self.source_storage_account_resource_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID",
                self.evidence_storage_account_resource_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_EVIDENCE_CONTAINER_RESOURCE_ID",
                evidence_container_resource_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_COLLECTOR_SIGNING_KEY_ID",
                self.collector_signing_key.key_vault_key_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_MONITORING_INTENT_SIGNING_KEY_ID",
                self.monitoring_intent_trusted_key.key_vault_key_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_WORKLOAD_RESOURCE_GROUP_ID",
                str(contract.get("workloadResourceGroupId", "")),
            ),
            (
                "ATHENA_WC028_DEPLOYED_NETWORK_WATCHER_RESOURCE_ID",
                self.network_watcher_resource_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_CHANGE_EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID",
                self.change_evidence_storage_account_resource_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_CHANGE_EVIDENCE_CONTAINER_RESOURCE_ID",
                change_evidence_container_resource_id,
            ),
        )
        for environment_name, expected in deployment_bindings:
            deployed = os.environ.get(environment_name)
            if deployed is not None and deployed.casefold().rstrip("/") != (
                expected.casefold().rstrip("/")
            ):
                raise ValueError(
                    f"{environment_name} does not match the reviewed runtime configuration"
                )
        return self


def load_wc028_monitoring_acquisition_job_configuration(
    *,
    path: Path | None,
    environment_json: str | None = None,
    expected_digest: str | None = None,
) -> Wc028MonitoringAcquisitionJobConfiguration:
    if path is not None and environment_json is not None:
        raise ValueError("provide either a config path or environment JSON")
    raw: bytes | str | None
    if path is not None:
        try:
            size_bytes = path.stat().st_size
            if not 1 <= size_bytes <= _MAX_CONFIGURATION_BYTES:
                raise ValueError(
                    "WC-028 monitoring acquisition configuration is outside its byte bound"
                )
            raw = path.read_bytes()
        except OSError as exc:
            raise ValueError(
                "WC-028 monitoring acquisition configuration could not be read"
            ) from exc
    else:
        raw = (
            environment_json
            if environment_json is not None
            else os.environ.get("ATHENA_WC028_MONITORING_ACQUISITION_CONFIG_JSON")
        )
    if raw is None:
        raise ValueError("WC-028 monitoring acquisition configuration is required")
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not 1 <= len(raw) <= _MAX_CONFIGURATION_BYTES:
        raise ValueError("WC-028 monitoring acquisition configuration is outside its byte bound")
    if (
        expected_digest is None
        or re.fullmatch(r"sha256:[a-f0-9]{64}", expected_digest) is None
        or sha256_hex(raw) != expected_digest
    ):
        raise ValueError(
            "WC-028 monitoring acquisition configuration does not match its pinned digest"
        )
    return Wc028MonitoringAcquisitionJobConfiguration.model_validate_json(raw)


def _utc_now_milliseconds() -> datetime:
    value = datetime.now(UTC)
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)


class _CredentialBoundAcquisitionClock:
    """Share the credential verification time with source result claims."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._clock = _utc_now_milliseconds if clock is None else clock
        self._collection_time: datetime | None = None

    def runtime_now(self) -> datetime:
        current = self._clock()
        if (
            not isinstance(current, datetime)
            or current.utcoffset() != UTC.utcoffset(current)
            or current.microsecond % 1000
        ):
            raise MonitoringAcquisitionJobError("acquisition runtime clock is not millisecond UTC")
        if self._collection_time is None:
            self._collection_time = current
        return current

    def source_collection_time(self) -> datetime:
        if self._collection_time is None:
            raise MonitoringAcquisitionJobError(
                "credential verification time is unavailable before source I/O"
            )
        return self._collection_time


def _validate_monitoring_intent_key_lifecycle(
    *,
    monitoring_intent: PublishedMonitoringIntent,
    key_record: TrustedKeyRecord,
    as_of: datetime,
) -> None:
    if (
        as_of.utcoffset() != UTC.utcoffset(as_of)
        or as_of.microsecond % 1000
        or not key_record.enabled
        or key_record.activated_at > monitoring_intent.published_at
        or key_record.activated_at > as_of
        or (key_record.retired_at is not None and key_record.retired_at <= as_of)
        or (
            key_record.expires_at is not None
            and (
                key_record.expires_at <= monitoring_intent.published_at
                or key_record.expires_at <= as_of
            )
        )
    ):
        raise MonitoringAcquisitionJobError(
            "monitoring intent signing key is not trusted for publication and acquisition"
        )


def _azure_utc_milliseconds(value: object, *, label: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise MonitoringAcquisitionJobError(f"{label} is not an Azure UTC timestamp") from exc
    else:
        raise MonitoringAcquisitionJobError(f"{label} is not an Azure UTC timestamp")
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise MonitoringAcquisitionJobError(f"{label} must use UTC")
    normalized = parsed.astimezone(UTC)
    return normalized.replace(microsecond=(normalized.microsecond // 1000) * 1000)


class _HandoffSigner(Protocol):
    def sign_preimage(self, canonical_preimage: bytes) -> str: ...


class MonitoringAcquisitionJobOutcome(Protocol):
    committed: CommittedMonitoringCollection
    correlation_request: CorrelationRequest


class _JsonTransport(Protocol):
    def request_json(
        self,
        *,
        method: Literal["GET", "POST"],
        url: str,
        access_token: str,
        body: Mapping[str, object] | None = None,
    ) -> tuple[object, int]: ...


class AzureManagedIdentityJsonTransport:
    """Bounded HTTPS JSON transport with fixed retries and no caller-selected host."""

    def __init__(
        self,
        *,
        timeout_seconds: int,
        retry_limit: int,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._retry_limit = retry_limit

    def request_json(
        self,
        *,
        method: Literal["GET", "POST"],
        url: str,
        access_token: str,
        body: Mapping[str, object] | None = None,
    ) -> tuple[object, int]:
        if (
            type(access_token) is not str
            or not access_token
            or access_token != access_token.strip()
            or len(access_token) > 32 * 1024
        ):
            raise MonitoringAcquisitionJobError("monitoring source access token is invalid")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in {
            "api.loganalytics.azure.com",
            "management.azure.com",
        }:
            raise MonitoringAcquisitionJobError("monitoring source host is not allowlisted")
        payload = (
            None
            if body is None
            else json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=payload, headers=headers, method=method)  # noqa: S310
        request.add_unredirected_header(
            "Authorization",
            "Bearer" + " " + access_token,
        )
        for attempt in range(self._retry_limit + 1):
            try:
                with urlopen(request, timeout=self._timeout_seconds) as response:  # noqa: S310
                    response_bytes = response.read(_MAX_RESPONSE_BYTES + 1)
                    if len(response_bytes) > _MAX_RESPONSE_BYTES:
                        raise MonitoringAcquisitionJobError(
                            "monitoring source response exceeded its byte bound"
                        )
                    if response.status < 200 or response.status >= 300:
                        raise MonitoringAcquisitionJobError(
                            "monitoring source returned a non-success response"
                        )
                    try:
                        return (
                            json.loads(response_bytes, parse_constant=_reject_json_constant),
                            len(response_bytes),
                        )
                    except (UnicodeDecodeError, ValueError) as exc:
                        raise MonitoringAcquisitionJobError(
                            "monitoring source response was not strict JSON"
                        ) from exc
            except HTTPError as exc:
                if attempt < self._retry_limit and (
                    exc.code in {408, 429} or 500 <= exc.code < 600
                ):
                    sleep(2**attempt)
                    continue
                raise MonitoringAcquisitionJobError(
                    "monitoring source HTTP request failed"
                ) from exc
            except (URLError, TimeoutError, OSError) as exc:
                if attempt < self._retry_limit:
                    sleep(2**attempt)
                    continue
                raise MonitoringAcquisitionJobError("monitoring source transport failed") from exc
        raise AssertionError("bounded retry loop did not terminate")


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"non-standard JSON constant is not allowed: {value}")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise MonitoringAcquisitionJobError(f"{label} must be a JSON object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise MonitoringAcquisitionJobError(f"{label} must be a JSON array")
    return value


def _field(mapping: Mapping[str, object], name: str, label: str) -> object:
    if name not in mapping:
        raise MonitoringAcquisitionJobError(f"{label} omitted {name}")
    return mapping[name]


def _model_payload(model: object) -> Mapping[str, object]:
    dump = getattr(model, "model_dump", None)
    if not callable(dump):
        raise TypeError("acquisition request must be a Pydantic contract")
    payload = dump(mode="json", by_alias=True, exclude_none=True)
    return _mapping(payload, "acquisition request")


def _result[ModelT: BaseModel](
    model: type[ModelT],
    payload: Mapping[str, object],
) -> ModelT:
    return model.model_validate_json(canonicalize_json(_json_compatible(payload)))


def _embedded_model(model: Any, payload: object) -> Any:
    return model.model_validate_json(canonicalize_json(payload))


def _json_compatible(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_compatible(item) for item in value]
    return value


def _response_base(
    request: Mapping[str, object],
    *,
    source_identity_id: str,
    collected_at: datetime,
    columns: tuple[str, ...],
    response_bytes: int,
    truncated: bool,
) -> dict[str, object]:
    return {
        "requestDigest": _field(request, "requestDigest", "acquisition request"),
        "sourceIdentityId": source_identity_id,
        "collectedAt": collected_at,
        "columns": columns,
        "truncated": truncated,
        "responseBytes": response_bytes,
    }


def _aggregate_completeness_proof(
    request: Mapping[str, object],
    *,
    table_name: str,
    proof_tables: Sequence[object],
) -> dict[str, object] | None:
    if not proof_tables:
        return None
    if table_name not in {"Heartbeat", "VMConnection"} or len(proof_tables) != 1:
        raise MonitoringAcquisitionJobError(
            "Log Analytics returned an unauthorized auxiliary result table"
        )
    table = _mapping(proof_tables[0], "Log Analytics aggregate proof table")
    columns = tuple(
        str(_field(_mapping(item, "aggregate proof column"), "name", "column"))
        for item in _sequence(_field(table, "columns", "aggregate proof table"), "columns")
    )
    if columns != ("rawInputRowCount", "ingestionCompleteThrough"):
        raise MonitoringAcquisitionJobError("Log Analytics aggregate proof columns are invalid")
    rows = _sequence(_field(table, "rows", "aggregate proof table"), "rows")
    if len(rows) != 1:
        raise MonitoringAcquisitionJobError(
            "Log Analytics aggregate proof must contain exactly one row"
        )
    values = _sequence(rows[0], "Log Analytics aggregate proof row")
    if len(values) != 2 or type(values[0]) is not int or values[0] < 1:
        raise MonitoringAcquisitionJobError("Log Analytics aggregate proof row is invalid")
    window_start = _azure_utc_milliseconds(
        _field(request, "windowStart", "log request"),
        label="Log Analytics proof windowStart",
    )
    window_end = _azure_utc_milliseconds(
        _field(request, "windowEnd", "log request"),
        label="Log Analytics proof windowEnd",
    )
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028LogAggregateCompletenessProof.v1",
        "rawInputRowCount": values[0],
        "ingestionCompleteThrough": _azure_utc_milliseconds(
            values[1],
            label="Log Analytics proof ingestionCompleteThrough",
        ),
        "windowStart": window_start,
        "windowEnd": window_end,
        "requestDigest": _field(request, "requestDigest", "log request"),
        "queryDigest": _field(request, "queryDigest", "log request"),
    }
    payload["proofDigest"] = compute_artifact_digest(payload)
    return payload


@dataclass(frozen=True, slots=True)
class AzureMonitoringAcquisitionPort:
    """Production read-only Azure Monitor/ARM adapter for coordinator-owned requests."""

    collector_identity_resource_id: str
    workspace_resource_id: str
    workspace_customer_id: str
    network_watcher_resource_id: str
    authorized_resource_ids: tuple[str, ...]
    transport: _JsonTransport
    clock: Any = _utc_now_milliseconds

    def _now(self) -> datetime:
        value = self.clock()
        if (
            not isinstance(value, datetime)
            or value.utcoffset() != UTC.utcoffset(value)
            or value.microsecond % 1000
        ):
            raise MonitoringAcquisitionJobError("acquisition adapter clock is not millisecond UTC")
        return value

    def _validate_identity(self, request: Mapping[str, object]) -> None:
        if (
            str(_field(request, "monitoringReaderIdentityId", "acquisition request")).casefold()
            != self.collector_identity_resource_id
        ):
            raise MonitoringAcquisitionJobError(
                "acquisition request selected another monitoring identity"
            )

    def _validate_authorized_resources(self, resource_ids: Sequence[str]) -> None:
        authorized = set(self.authorized_resource_ids)
        if any(item.casefold().rstrip("/") not in authorized for item in resource_ids):
            raise MonitoringAcquisitionJobError(
                "acquisition request escaped the reviewed resource allowlist"
            )

    def _resolve_ip_flow_rule(self, rule_name: object) -> str | None:
        if not isinstance(rule_name, str) or not rule_name.strip():
            return None
        stripped = rule_name.strip()
        normalized = stripped.casefold().strip("/")
        if stripped.startswith("/"):
            resource_id = f"/{normalized}"
            return resource_id if resource_id in self.authorized_resource_ids else None
        suffix = f"/{normalized}"
        leaf_suffix = f"/{normalized.rsplit('/', maxsplit=1)[-1]}"
        candidates = tuple(
            item
            for item in self.authorized_resource_ids
            if ("/securityrules/" in item or "/defaultsecurityrules/" in item)
            and (item.endswith(suffix) if "/" in normalized else item.endswith(leaf_suffix))
        )
        return candidates[0] if len(candidates) == 1 else None

    def query_log_analytics(
        self,
        request_model: LogAnalyticsQueryRequest,
        *,
        access_token: str,
    ) -> LogAnalyticsQueryResult:
        request = _model_payload(request_model)
        self._validate_identity(request)
        if str(_field(request, "queryTargetResourceId", "log request")).casefold() != (
            self.workspace_resource_id
        ):
            raise MonitoringAcquisitionJobError("log query target is not the reviewed workspace")
        self._validate_authorized_resources((self.workspace_resource_id,))
        expected_columns = tuple(
            cast(str, item)
            for item in _sequence(
                _field(request, "expectedColumns", "log request"),
                "log expectedColumns",
            )
        )
        url = (
            "https://api.loganalytics.azure.com/v1/workspaces/"
            f"{quote(self.workspace_customer_id, safe='')}/query"
        )
        payload, response_bytes = self.transport.request_json(
            method="POST",
            url=url,
            access_token=access_token,
            body={
                "query": _field(request, "query", "log request"),
                "timespan": (
                    f"{_field(request, 'windowStart', 'log request')}/"
                    f"{_field(request, 'windowEnd', 'log request')}"
                ),
            },
        )
        response = _mapping(payload, "Log Analytics response")
        tables = _sequence(_field(response, "tables", "Log Analytics response"), "tables")
        if not 1 <= len(tables) <= 2:
            raise MonitoringAcquisitionJobError(
                "Log Analytics response must contain one primary and at most one proof table"
            )
        table = _mapping(tables[0], "Log Analytics table")
        columns = tuple(
            str(_field(_mapping(item, "Log Analytics column"), "name", "column"))
            for item in _sequence(_field(table, "columns", "Log Analytics table"), "columns")
        )
        if columns != expected_columns:
            raise MonitoringAcquisitionJobError(
                "Log Analytics response columns do not match the reviewed query"
            )
        raw_rows = _sequence(_field(table, "rows", "Log Analytics table"), "rows")
        if len(raw_rows) > _MAX_ROWS:
            raise MonitoringAcquisitionJobError("Log Analytics returned too many rows")
        table_name = str(_field(request, "table", "log request"))
        row_kind = {
            "Heartbeat": "heartbeat",
            "VMConnection": "vmConnection",
            "NWConnectionMonitorTestResult": "connectionMonitor",
            "NTANetAnalytics": "trafficAnalytics",
        }.get(table_name)
        if row_kind is None:
            raise MonitoringAcquisitionJobError("log request selected an unsupported table")
        rows: list[dict[str, object]] = []
        for raw_row in raw_rows:
            values = _sequence(raw_row, "Log Analytics row")
            if len(values) != len(columns):
                raise MonitoringAcquisitionJobError("Log Analytics row width is invalid")
            row = {"rowKind": row_kind, **dict(zip(columns, values, strict=True))}
            row["observedStart"] = _azure_utc_milliseconds(
                _field(row, "observedStart", "Log Analytics row"),
                label="Log Analytics observedStart",
            )
            row["observedEnd"] = _azure_utc_milliseconds(
                _field(row, "observedEnd", "Log Analytics row"),
                label="Log Analytics observedEnd",
            )
            rows.append(row)
        result_payload = {
            "schemaVersion": "athena.wc028LogAnalyticsQueryResult.v1",
            "source": "logAnalytics",
            "table": table_name,
            **_response_base(
                request,
                source_identity_id=self.collector_identity_resource_id,
                collected_at=self._now(),
                columns=columns,
                response_bytes=response_bytes,
                truncated=len(rows) == _MAX_ROWS or "error" in response,
            ),
            "rows": rows,
        }
        aggregate_proof = _aggregate_completeness_proof(
            request,
            table_name=table_name,
            proof_tables=tables[1:],
        )
        if aggregate_proof is not None:
            result_payload["aggregateCompletenessProof"] = aggregate_proof
        descriptor = _coverage_descriptor(table_name, rows)
        if descriptor is not None:
            result_payload["coverageDescriptor"] = descriptor
        return _result(LogAnalyticsQueryResult, result_payload)

    def query_activity_log(
        self,
        request_model: ActivityLogQueryRequest,
        *,
        access_token: str,
    ) -> ActivityLogQueryResult:
        request = _model_payload(request_model)
        self._validate_identity(request)
        resource_ids = tuple(
            str(item).casefold()
            for item in _sequence(_field(request, "resourceIds", "activity request"), "resourceIds")
        )
        self._validate_authorized_resources(resource_ids)
        subscriptions = {_subscription_id(item) for item in resource_ids}
        if len(subscriptions) != 1:
            raise MonitoringAcquisitionJobError(
                "Activity Log request must remain in one subscription"
            )
        subscription_id = subscriptions.pop()
        allowed_resources = set(resource_ids)
        allowed_categories = set(
            cast(Sequence[str], _field(request, "categories", "activity request"))
        )
        allowed_operations = set(
            cast(Sequence[str], _field(request, "operationNames", "activity request"))
        )
        allowed_results = set(
            cast(Sequence[str], _field(request, "resultTypes", "activity request"))
        )
        allowed_levels = set(cast(Sequence[str], _field(request, "levels", "activity request")))
        rows: list[dict[str, object]] = []
        response_bytes = 0
        truncated = False
        source_row_count = 0
        for resource_id in resource_ids:
            escaped_resource_id = resource_id.replace("'", "''")
            escaped_resource_group = _resource_group_name(resource_id).replace("'", "''")
            query = urlencode(
                {
                    "api-version": "2015-04-01",
                    "$filter": (
                        "eventTimestamp ge "
                        f"{_field(request, 'windowStart', 'activity request')} "
                        "and eventTimestamp le "
                        f"{_field(request, 'windowEnd', 'activity request')} "
                        f"and resourceGroupName eq '{escaped_resource_group}' "
                        f"and resourceUri eq '{escaped_resource_id}'"
                    ),
                },
                quote_via=quote,
            )
            payload, single_response_bytes = self.transport.request_json(
                method="GET",
                url=(
                    f"https://management.azure.com/subscriptions/{subscription_id}/providers/"
                    f"microsoft.insights/eventtypes/management/values?{query}"
                ),
                access_token=access_token,
            )
            response_bytes += single_response_bytes
            if response_bytes > _MAX_RESPONSE_BYTES:
                raise MonitoringAcquisitionJobError(
                    "combined Activity Log response exceeded its byte bound"
                )
            response = _mapping(payload, "Activity Log response")
            values = _sequence(_field(response, "value", "Activity Log response"), "value")
            source_row_count += len(values)
            truncated = truncated or "nextLink" in response
            for value in values:
                event = _mapping(value, "Activity Log event")
                category = _localized_value(event.get("category"))
                operation = _localized_value(event.get("operationName"))
                result = _localized_value(event.get("status"))
                level = str(event.get("level", ""))
                target = str(event.get("resourceId", "")).casefold().rstrip("/")
                if target not in allowed_resources or target != resource_id:
                    raise MonitoringAcquisitionJobError(
                        "Activity Log returned evidence outside the requested resource scope"
                    )
                if (
                    category not in allowed_categories
                    or operation not in allowed_operations
                    or result not in allowed_results
                    or level not in allowed_levels
                ):
                    continue
                rows.append(
                    {
                        "category": category,
                        "operationName": operation,
                        "resultType": result,
                        "level": level,
                        "targetResourceId": target,
                        "correlationId": event.get("correlationId"),
                        "occurredAt": _azure_utc_milliseconds(
                            event.get("eventTimestamp"),
                            label="Activity Log eventTimestamp",
                        ),
                    }
                )
        columns = tuple(
            cast(str, item)
            for item in _sequence(
                _field(request, "expectedColumns", "activity request"),
                "expectedColumns",
            )
        )
        return _result(
            ActivityLogQueryResult,
            {
                "schemaVersion": "athena.wc028ActivityLogQueryResult.v1",
                "source": "activityLog",
                **_response_base(
                    request,
                    source_identity_id=self.collector_identity_resource_id,
                    collected_at=self._now(),
                    columns=columns,
                    response_bytes=response_bytes,
                    truncated=truncated or source_row_count >= _MAX_ROWS,
                ),
                "rows": rows,
            },
        )

    def query_resource_graph_changes(
        self,
        request_model: ResourceGraphChangeQueryRequest,
        *,
        access_token: str,
    ) -> ResourceGraphChangeQueryResult:
        request = _model_payload(request_model)
        self._validate_identity(request)
        resource_ids = tuple(
            str(item).casefold()
            for item in _sequence(
                _field(request, "resourceIds", "Resource Graph request"),
                "resourceIds",
            )
        )
        self._validate_authorized_resources(resource_ids)
        subscriptions = tuple(sorted({_subscription_id(item) for item in resource_ids}))
        escaped_ids = ", ".join("'" + item.replace("'", "''") + "'" for item in resource_ids)
        query = "\n".join(
            (
                "resourcechanges",
                (
                    "| extend targetResourceId=tolower(tostring(properties.targetResourceId)), "
                    "occurredAt=todatetime(properties.changeAttributes.timestamp)"
                ),
                f"| where targetResourceId in~ ({escaped_ids})",
                (
                    "| where occurredAt between "
                    f"(datetime({_field(request, 'windowStart', 'Resource Graph request')}) .. "
                    f"datetime({_field(request, 'windowEnd', 'Resource Graph request')}))"
                ),
                "| order by occurredAt asc",
                f"| take {_MAX_ROWS}",
                "| project id, properties",
            )
        )
        payload, response_bytes = self.transport.request_json(
            method="POST",
            url=_RESOURCE_GRAPH_ENDPOINT,
            access_token=access_token,
            body={
                "subscriptions": subscriptions,
                "query": query,
                "options": {"$top": _MAX_ROWS, "resultFormat": "ObjectArray"},
            },
        )
        response = _mapping(payload, "Resource Graph response")
        values = _sequence(_field(response, "data", "Resource Graph response"), "data")
        allowed_resource_ids = set(resource_ids)
        rows: list[dict[str, object]] = []
        for item in values:
            raw_row = dict(_mapping(item, "Resource Graph row"))
            properties = _mapping(
                _field(raw_row, "properties", "Resource Graph row"),
                "Resource Graph properties",
            )
            attributes = _mapping(
                _field(
                    properties,
                    "changeAttributes",
                    "Resource Graph properties",
                ),
                "Resource Graph change attributes",
            )
            target_resource_id = (
                str(
                    _field(
                        properties,
                        "targetResourceId",
                        "Resource Graph properties",
                    )
                )
                .casefold()
                .rstrip("/")
            )
            if target_resource_id not in allowed_resource_ids:
                raise MonitoringAcquisitionJobError(
                    "Resource Graph returned evidence outside the requested resource scope"
                )
            rows.append(
                {
                    "targetResourceId": target_resource_id,
                    "correlationId": _field(
                        attributes,
                        "correlationId",
                        "Resource Graph change attributes",
                    ),
                    "occurredAt": _azure_utc_milliseconds(
                        _field(
                            attributes,
                            "timestamp",
                            "Resource Graph change attributes",
                        ),
                        label="Resource Graph change timestamp",
                    ),
                    "operationName": attributes.get("operation", "unspecified"),
                    "resultType": "Succeeded",
                    "change": raw_row,
                }
            )
        columns = tuple(
            cast(str, item)
            for item in _sequence(
                _field(request, "expectedColumns", "Resource Graph request"),
                "expectedColumns",
            )
        )
        truncated_marker = response.get("resultTruncated")
        truncated = (
            truncated_marker is True or truncated_marker == "true" or "$skipToken" in response
        )
        return _result(
            ResourceGraphChangeQueryResult,
            {
                "schemaVersion": "athena.wc028ResourceGraphChangeQueryResult.v1",
                "source": "resourceGraph",
                **_response_base(
                    request,
                    source_identity_id=self.collector_identity_resource_id,
                    collected_at=self._now(),
                    columns=columns,
                    response_bytes=response_bytes,
                    truncated=truncated or len(values) == _MAX_ROWS,
                ),
                "rows": rows,
            },
        )

    def query_resource_health(
        self,
        request_model: ResourceHealthQueryRequest,
        *,
        access_token: str,
    ) -> ResourceHealthQueryResult:
        request = _model_payload(request_model)
        self._validate_identity(request)
        resource_ids = tuple(
            str(item).casefold()
            for item in _sequence(
                _field(request, "resourceIds", "Resource Health request"),
                "resourceIds",
            )
        )
        self._validate_authorized_resources(resource_ids)
        window_start = _azure_utc_milliseconds(
            _field(request, "windowStart", "Resource Health request"),
            label="Resource Health windowStart",
        )
        window_end = _azure_utc_milliseconds(
            _field(request, "windowEnd", "Resource Health request"),
            label="Resource Health windowEnd",
        )
        allowed_event_statuses = set(
            cast(
                Sequence[str],
                _field(request, "eventStatuses", "Resource Health request"),
            )
        )
        allowed_current_statuses = set(
            cast(
                Sequence[str],
                _field(request, "currentStatuses", "Resource Health request"),
            )
        )
        allowed_previous_statuses = set(
            cast(
                Sequence[str],
                _field(request, "previousStatuses", "Resource Health request"),
            )
        )
        allowed_reason_types = set(
            cast(
                Sequence[str],
                _field(request, "reasonTypes", "Resource Health request"),
            )
        )
        rows: list[dict[str, object]] = []
        total_bytes = 0
        truncated = False
        for resource_id in resource_ids:
            query = urlencode({"api-version": "2025-05-01"}, quote_via=quote)
            payload, response_bytes = self.transport.request_json(
                method="GET",
                url=(
                    f"https://management.azure.com{resource_id}/providers/"
                    f"Microsoft.ResourceHealth/availabilityStatuses?{query}"
                ),
                access_token=access_token,
            )
            total_bytes += response_bytes
            if total_bytes > _MAX_RESPONSE_BYTES:
                raise MonitoringAcquisitionJobError(
                    "combined Resource Health response exceeded its byte bound"
                )
            response = _mapping(payload, "Resource Health response")
            values = _sequence(_field(response, "value", "Resource Health response"), "value")
            truncated = truncated or "nextLink" in response
            candidates: list[dict[str, object]] = []
            for item in values:
                properties = _mapping(
                    _field(_mapping(item, "Resource Health item"), "properties", "item"),
                    "Resource Health properties",
                )
                current = properties.get("availabilityState")
                if current not in {
                    "Available",
                    "Degraded",
                    "Unavailable",
                    "Unknown",
                }:
                    continue
                cause = properties.get("healthEventCause")
                context = properties.get("context")
                if cause in {"PlatformInitiated", "UserInitiated"}:
                    reason_type = cause
                elif isinstance(context, str) and context.casefold() == "platform":
                    reason_type = "PlatformInitiated"
                elif isinstance(context, str) and context.casefold() in {
                    "customer",
                    "user",
                }:
                    reason_type = "UserInitiated"
                else:
                    reason_type = "Unknown"
                recently_resolved = properties.get("recentlyResolved")
                if recently_resolved is not None and not isinstance(
                    recently_resolved,
                    Mapping,
                ):
                    raise MonitoringAcquisitionJobError(
                        "Resource Health recentlyResolved is not an object"
                    )
                if current == "Available" and recently_resolved is not None:
                    resolved = cast(Mapping[str, object], recently_resolved)
                    observed_start = _azure_utc_milliseconds(
                        resolved.get(
                            "unavailableOccuredTime",
                            resolved.get("unavailableOccurredTime"),
                        ),
                        label="Resource Health unavailable time",
                    )
                    observed_end = _azure_utc_milliseconds(
                        resolved.get("resolvedTime"),
                        label="Resource Health resolved time",
                    )
                    candidate_previous: object = "Unavailable"
                    candidate_event_status: object = "Resolved"
                else:
                    observed_start = _azure_utc_milliseconds(
                        properties.get(
                            "occuredTime",
                            properties.get("occurredTime"),
                        ),
                        label="Resource Health occurred time",
                    )
                    observed_end = _azure_utc_milliseconds(
                        properties.get("reportedTime"),
                        label="Resource Health reported time",
                    )
                    source_previous = properties.get("previousAvailabilityState")
                    candidate_previous = (
                        source_previous
                        if source_previous in {"Available", "Degraded", "Unavailable", "Unknown"}
                        else "Unknown"
                    )
                    source_event_status = properties.get("eventStatus")
                    candidate_event_status = (
                        source_event_status
                        if source_event_status in {"Active", "In Progress", "Resolved", "Updated"}
                        else ""
                    )
                candidates.append(
                    {
                        "current": current,
                        "previous": candidate_previous,
                        "eventStatus": candidate_event_status,
                        "reasonType": reason_type,
                        "observedStart": observed_start,
                        "observedEnd": observed_end,
                    }
                )
            candidates.sort(
                key=lambda item: (
                    cast(datetime, item["observedStart"]),
                    cast(datetime, item["observedEnd"]),
                    cast(str, item["current"]),
                )
            )
            for index, candidate in enumerate(candidates):
                current = cast(str, candidate["current"])
                previous = cast(str, candidate["previous"])
                if previous == "Unknown" and index:
                    predecessor = candidates[index - 1]
                    if cast(datetime, predecessor["observedEnd"]) <= cast(
                        datetime,
                        candidate["observedStart"],
                    ):
                        previous = cast(str, predecessor["current"])
                event_status = cast(str, candidate["eventStatus"])
                if not event_status:
                    if current in {"Degraded", "Unavailable"}:
                        event_status = "Active" if index == len(candidates) - 1 else "Resolved"
                    elif previous in {"Degraded", "Unavailable"}:
                        event_status = "Resolved"
                    else:
                        event_status = "Updated"
                observed_start = cast(datetime, candidate["observedStart"])
                observed_end = cast(datetime, candidate["observedEnd"])
                reason_type = cast(str, candidate["reasonType"])
                if not (
                    window_start <= observed_start <= observed_end <= window_end
                    and event_status in allowed_event_statuses
                    and current in allowed_current_statuses
                    and previous in allowed_previous_statuses
                    and reason_type in allowed_reason_types
                ):
                    continue
                rows.append(
                    {
                        "resourceId": resource_id,
                        "eventStatus": event_status,
                        "currentStatus": current,
                        "previousStatus": previous,
                        "reasonType": reason_type,
                        "observedStart": observed_start,
                        "observedEnd": observed_end,
                    }
                )
        columns = tuple(
            cast(str, item)
            for item in _sequence(
                _field(request, "expectedColumns", "Resource Health request"),
                "expectedColumns",
            )
        )
        return _result(
            ResourceHealthQueryResult,
            {
                "schemaVersion": "athena.wc028ResourceHealthQueryResult.v1",
                "source": "resourceHealth",
                **_response_base(
                    request,
                    source_identity_id=self.collector_identity_resource_id,
                    collected_at=self._now(),
                    columns=columns,
                    response_bytes=total_bytes,
                    truncated=truncated or len(rows) >= _MAX_ROWS,
                ),
                "rows": rows[:_MAX_ROWS],
            },
        )

    def query_ip_flow_verify(
        self,
        request_model: IpFlowVerifyRequest,
        *,
        access_token: str,
    ) -> IpFlowVerifyResult:
        request = _model_payload(request_model)
        self._validate_identity(request)
        direction = str(_field(request, "direction", "IP Flow request"))
        protocol = _field(request, "protocol", "IP Flow request")
        if protocol not in {"Tcp", "Udp"}:
            raise MonitoringAcquisitionJobError(
                "Azure IP Flow Verify supports only reviewed TCP or UDP checks"
            )
        target_resource_id = (
            str(_field(request, "targetResourceId", "IP Flow request")).casefold().rstrip("/")
        )
        self._validate_authorized_resources((target_resource_id,))
        inbound = direction == "inbound"
        body = {
            "targetResourceId": target_resource_id,
            "direction": "Inbound" if inbound else "Outbound",
            "protocol": protocol.upper(),
            "localIPAddress": _field(
                request,
                "destinationAddress" if inbound else "sourceAddress",
                "IP Flow request",
            ),
            "remoteIPAddress": _field(
                request,
                "sourceAddress" if inbound else "destinationAddress",
                "IP Flow request",
            ),
            "localPort": str(
                _field(
                    request,
                    "destinationPort" if inbound else "sourcePort",
                    "IP Flow request",
                )
                or 0
            ),
            "remotePort": str(
                _field(
                    request,
                    "sourcePort" if inbound else "destinationPort",
                    "IP Flow request",
                )
                or 0
            ),
        }
        payload, response_bytes = self.transport.request_json(
            method="POST",
            url=(
                f"https://management.azure.com{self.network_watcher_resource_id}/"
                "ipFlowVerify?api-version=2024-10-01"
            ),
            access_token=access_token,
            body=body,
        )
        response = _mapping(payload, "IP Flow Verify response")
        rule_resource_id = self._resolve_ip_flow_rule(response.get("ruleName"))
        return _result(
            IpFlowVerifyResult,
            {
                "schemaVersion": "athena.wc028IpFlowVerifyResult.v1",
                "source": "ipFlowVerify",
                "requestDigest": _field(request, "requestDigest", "IP Flow request"),
                "sourceIdentityId": self.collector_identity_resource_id,
                "collectedAt": self._now(),
                "checkedAt": _field(request, "checkedAt", "IP Flow request"),
                "access": _field(response, "access", "IP Flow Verify response"),
                "ruleResourceId": rule_resource_id,
                "responseBytes": response_bytes,
                "limitation": "pointInTimeNotHistorical",
            },
        )


def _localized_value(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        candidate = value.get("value", value.get("localizedValue"))
        if isinstance(candidate, str):
            return candidate
    return ""


def _subscription_id(resource_id: str) -> str:
    parts = resource_id.split("/")
    if len(parts) < 3 or parts[1] != "subscriptions" or _GUID_PATTERN.fullmatch(parts[2]) is None:
        raise MonitoringAcquisitionJobError("resource ID omitted a valid subscription")
    return parts[2]


def _resource_group_name(resource_id: str) -> str:
    parts = resource_id.split("/")
    if len(parts) < 5 or parts[3] != "resourcegroups" or not parts[4]:
        raise MonitoringAcquisitionJobError("resource ID omitted a valid resource group")
    return parts[4]


def _coverage_descriptor(
    table: str,
    rows: Sequence[Mapping[str, object]],
) -> dict[str, object] | None:
    if table not in {"NWConnectionMonitorTestResult", "NTANetAnalytics"}:
        return None
    if not rows:
        raise MonitoringAcquisitionJobError(
            "network source cannot prove coverage without an exact descriptor row"
        )
    row = rows[0]
    if table == "NWConnectionMonitorTestResult":
        resource_ids = tuple(
            sorted(
                {
                    str(row[name]).casefold()
                    for name in (
                        "subjectResourceId",
                        "sourceResourceId",
                        "destinationResourceId",
                    )
                }
            )
        )
        tuple_payload = {
            "direction": row.get("direction"),
            "protocol": row.get("protocol"),
            "sourceResourceId": str(row.get("sourceResourceId", "")).casefold(),
            "destinationResourceId": str(row.get("destinationResourceId", "")).casefold(),
            "sourceAddress": row.get("sourceAddress"),
            "destinationAddress": row.get("destinationAddress"),
            "sourcePort": row.get("sourcePort"),
            "destinationPort": row.get("destinationPort"),
        }
        return {
            "resourceIds": resource_ids,
            "pathId": row.get("pathId"),
            "direction": row.get("direction"),
            "fiveTupleDigest": compute_artifact_digest(tuple_payload),
            "endpointTestReference": row.get("testConfigurationReference"),
            "endpointTestDigest": row.get("testConfigurationDigest"),
        }
    subject_candidates = tuple(
        sorted(
            str(item).casefold()
            for item in cast(
                Sequence[object],
                row.get("subjectResourceCandidates", ()),
            )
        )
    )
    source_candidates = tuple(
        sorted(
            str(item).casefold()
            for item in cast(
                Sequence[object],
                row.get("sourceResourceCandidates", ()),
            )
        )
    )
    destination_candidates = tuple(
        sorted(
            str(item).casefold()
            for item in cast(
                Sequence[object],
                row.get("destinationResourceCandidates", ()),
            )
        )
    )
    resource_ids = tuple(
        sorted(
            {
                *subject_candidates,
                *source_candidates,
                *destination_candidates,
            }
        )
    )
    return {
        "resourceIds": resource_ids,
        "pathId": row.get("pathId"),
        "direction": row.get("direction"),
        "fiveTupleDigest": compute_artifact_digest(
            {
                "direction": row.get("direction"),
                "protocol": row.get("protocol"),
                "sourceResourceId": (source_candidates[0] if len(source_candidates) == 1 else ""),
                "destinationResourceId": (
                    destination_candidates[0] if len(destination_candidates) == 1 else ""
                ),
                "sourceAddress": row.get("sourceAddress"),
                "destinationAddress": row.get("destinationAddress"),
                "sourcePort": row.get("sourcePort"),
                "destinationPort": row.get("destinationPort"),
            }
        ),
    }


def _validate_acquisition_authority_preflight(
    *,
    acquisition_authority: MonitoringAcquisitionAuthority,
    configuration: Wc028MonitoringAcquisitionJobConfiguration,
    collector_contract: MonitoringCollectorContract,
    context_binding: PublishedRuntimeContextBinding,
) -> None:
    if acquisition_authority.authority_digest != (
        configuration.expected_acquisition_authority_digest
    ):
        raise MonitoringAcquisitionJobError(
            "monitoring acquisition authority is not the configured authority"
        )
    if acquisition_authority.schema_version != ("athena.wc028MonitoringAcquisitionAuthority.v3"):
        raise MonitoringAcquisitionJobError(
            "production monitoring acquisition requires authority schema v3"
        )
    if (
        collector_contract.schema_version
        != MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION
        or collector_contract.handoff_schema_version != "athena.wc028MonitoringEvidenceHandoff.v2"
        or collector_contract.acquisition_receipt_schema_version
        != MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION
    ):
        raise MonitoringAcquisitionJobError(
            "production monitoring acquisition requires the receipt-bearing collector contract"
        )
    collector_contract_digest = collector_contract.compute_artifact_digest_value()
    if (
        acquisition_authority.monitoring_reader_identity_id
        != configuration.collector_identity_resource_id
        or acquisition_authority.athena_context_identity_id
        != configuration.athena_context_identity_resource_id
        or collector_contract.collector_identity_resource_id.casefold().rstrip("/")
        != configuration.collector_identity_resource_id
        or collector_contract.collector_identity_client_id.casefold()
        != configuration.managed_identity_client_id.casefold()
        or collector_contract.collector_identity_client_id
        != acquisition_authority.monitoring_reader_client_id
        or collector_contract.collector_tenant_id
        != acquisition_authority.monitoring_reader_tenant_id
        or collector_contract.monitoring_reader_principal_id
        != acquisition_authority.monitoring_reader_principal_id
        or collector_contract.athena_context_identity_id
        != acquisition_authority.athena_context_identity_id
        or collector_contract.athena_context_principal_id
        != acquisition_authority.athena_context_principal_id
        or collector_contract.physical_identity_separation_enforced is not True
        or acquisition_authority.context_binding_digest != context_binding.binding_digest
        or acquisition_authority.required_coverage_scope_digests
        != context_binding.required_coverage_scope_digests
    ):
        raise MonitoringAcquisitionJobError(
            "monitoring acquisition authority changed the deployed identity boundary"
        )
    if acquisition_authority.collector_contract_digest != collector_contract_digest:
        raise MonitoringAcquisitionJobError(
            "collector contract does not match the acquisition authority"
        )
    if (
        collector_contract.workspace_resource_id.casefold().rstrip("/")
        != configuration.workspace_resource_id
        or collector_contract.evidence_storage_account_resource_id.casefold().rstrip("/")
        != configuration.evidence_storage_account_resource_id
        or collector_contract.evidence_container_name != configuration.evidence_container_name
        or collector_contract.signing_key_resource_id
        != configuration.collector_signing_key.key_vault_key_id
        or acquisition_authority.receipt_signing_key_id
        != configuration.collector_signing_key.key_vault_key_id
        or collector_contract.ip_flow_verify_scope_id is None
        or collector_contract.ip_flow_verify_scope_id.casefold().rstrip("/")
        != configuration.network_watcher_resource_id
    ):
        raise MonitoringAcquisitionJobError(
            "collector contract changed the deployed evidence trust boundary"
        )
    if configuration.trust_delay_seconds > min(
        acquisition_authority.max_freshness_seconds,
        collector_contract.maximum_evidence_age_seconds,
    ):
        raise MonitoringAcquisitionJobError(
            "configured trust delay exceeds acquisition authority freshness"
        )


def _build_acquisition_receipt_verifier(
    *,
    acquisition_authority: MonitoringAcquisitionAuthority,
    collector_contract: MonitoringCollectorContract,
    trusted_key: MonitoringRuntimeTrustedKey,
    key_resolver: TrustedKeyResolver,
) -> Callable[[MonitoringAcquisitionReceipt, datetime], None]:
    def verify(receipt: MonitoringAcquisitionReceipt, as_of: datetime) -> None:
        verify_monitoring_acquisition_receipt_attestation(
            receipt,
            as_of=as_of,
            trusted_key_anchor=trusted_key.anchor,
            key_resolver=key_resolver,
            reviewed_collector_contract=collector_contract,
            expected_acquisition_authority_digest=(acquisition_authority.authority_digest),
            maximum_receipt_age_seconds=min(
                acquisition_authority.max_freshness_seconds,
                collector_contract.maximum_evidence_age_seconds,
            ),
        )

    return verify


class MonitoringEvidenceCommitPort:
    """Create-only persistence for one exact normalized monitoring transaction."""

    def __init__(
        self,
        *,
        monitoring_writer: CreateOnlyArtifactWriterPort,
        change_writer: CreateOnlyArtifactWriterPort,
        signer: _HandoffSigner,
        trusted_key: MonitoringRuntimeTrustedKey,
        reviewed_collector_contract: MonitoringCollectorContract,
        key_resolver: TrustedKeyResolver | None = None,
        key_record: TrustedKeyRecord | None = None,
        monitoring_current_reader: CurrentArtifactReaderPort | None = None,
        change_current_reader: CurrentArtifactReaderPort | None = None,
    ) -> None:
        if key_resolver is not None and key_record is not None:
            raise TypeError("provide either a monitoring key resolver or a trusted key record")
        self._monitoring_writer = monitoring_writer
        self._change_writer = change_writer
        self._signer = signer
        self._trusted_key = trusted_key
        self._reviewed_collector_contract = reviewed_collector_contract
        self._monitoring_current_reader = monitoring_current_reader
        self._change_current_reader = change_current_reader
        self._key_resolver: TrustedKeyResolver
        if key_resolver is None:
            record = key_record or TrustedKeyRecord(
                anchor=trusted_key.anchor,
                public_key=KeyVaultRsaPublicKeyVerifier(
                    trusted_key_anchor=trusted_key.anchor,
                    managed_identity_client_id=(
                        reviewed_collector_contract.collector_identity_client_id
                    ),
                ).public_key,
                enabled=True,
                activated_at=trusted_key.activated_at,
                expires_at=trusted_key.expires_at,
            )

            def resolve(anchor: TrustedKeyAnchor) -> TrustedKeyRecord | None:
                return record if anchor == trusted_key.anchor else None

            self._key_resolver = resolve
        else:
            self._key_resolver = key_resolver

    @contextmanager
    def transaction(
        self,
        prepared: PreparedMonitoringCollection,
    ) -> Iterator[CommittedMonitoringCollection]:
        bundle = prepared.monitoring_bundle
        observed_at = cast(datetime, bundle.collected_at)
        bundle_bytes = bundle.canonical_bytes()
        bundle_digest = sha256_hex(bundle_bytes)
        collection_id = f"wc024-{bundle_digest.removeprefix('sha256:')[:12]}"
        blob_name = f"wc024-monitoring/{collection_id}/evidence.json"
        evidence_reference = self._write(
            writer=self._monitoring_writer,
            current_reader=self._monitoring_current_reader,
            blob_name=blob_name,
            payload=bundle_bytes,
        )
        acquisition_receipt = getattr(bundle, "acquisition_receipt", None)
        payload: dict[str, object] = {
            "schemaVersion": (
                "athena.wc028MonitoringEvidenceHandoff.v2"
                if acquisition_receipt is not None
                else "athena.wc024MonitoringEvidenceHandoff.v1"
            ),
            "collectorContractDigest": (
                self._reviewed_collector_contract.compute_artifact_digest_value()
            ),
            "collectionId": collection_id,
            "observedAt": observed_at,
            "evidence": evidence_reference.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
        }
        if acquisition_receipt is not None:
            payload["acquisitionReceiptDigest"] = acquisition_receipt.receipt_digest
        try:
            preimage = monitoring_handoff_preimage(payload)
            handoff = MonitoringEvidenceHandoff.model_validate(
                {
                    **payload,
                    "collectorAttestation": MonitoringEvidenceAttestation(
                        signatureAlgorithm="RS256",
                        trustAnchorRef=self._trusted_key.key_vault_key_id,
                        signedPreimageDigest=compute_artifact_digest(preimage),
                        signature=self._signer.sign_preimage(
                            canonicalize_json(preimage).encode("utf-8")
                        ),
                    ),
                }
            )
            verify_monitoring_evidence_handoff_attestation(
                handoff,
                as_of=observed_at,
                trusted_key_anchor=self._trusted_key.anchor,
                key_resolver=self._key_resolver,
                reviewed_collector_contract=self._reviewed_collector_contract,
            )
        except (TypeError, ValueError) as exc:
            raise MonitoringAcquisitionJobError(
                "signed monitoring evidence handoff failed verification"
            ) from exc
        change_handoffs = tuple(
            self._write_change_artifact(artifact) for artifact in prepared.change_artifacts
        )
        committed = CommittedMonitoringCollection(
            monitoring_handoff=handoff,
            change_handoffs=change_handoffs,
        )
        yield committed

    def _write(
        self,
        *,
        writer: CreateOnlyArtifactWriterPort,
        current_reader: CurrentArtifactReaderPort | None,
        blob_name: str,
        payload: bytes,
    ) -> VersionPinnedBlobReference:
        try:
            receipt = writer.create(
                ArtifactWriteRequest(
                    blob_name=blob_name,
                    payload=payload,
                    content_type="application/json",
                    hashes=ArtifactMetadataHashes(payload_sha256=sha256_hex(payload)),
                    maximum_payload_bytes=1024 * 1024,
                )
            )
        except ArtifactAlreadyExistsError as exc:
            if current_reader is not None:
                recovered = current_reader.read_current(
                    ArtifactCurrentReadRequest(blob_name=blob_name)
                )
                if recovered.payload == payload and recovered.payload_sha256 == sha256_hex(payload):
                    return VersionPinnedBlobReference(
                        name=recovered.blob_name,
                        version=recovered.version_id,
                        contentDigest=recovered.payload_sha256,
                    )
            raise MonitoringAcquisitionJobError(
                f"immutable monitoring artifact already exists: {blob_name}"
            ) from exc
        return VersionPinnedBlobReference(
            name=receipt.blob_name,
            version=receipt.version_id,
            contentDigest=receipt.payload_sha256,
        )

    def _write_change_artifact(self, artifact: Any) -> ChangeEvidencePersistenceHandoff:
        evidence = artifact.evidence
        blob_name = (
            f"change-evidence/{evidence.deduplication_key.removeprefix('sha256:')}/evidence.json"
        )
        reference = self._write(
            writer=self._change_writer,
            current_reader=self._change_current_reader,
            blob_name=blob_name,
            payload=artifact.canonical_bytes(),
        )
        return ChangeEvidencePersistenceHandoff(
            schemaVersion="athena.changeEvidencePersistenceHandoff.v1",
            evidenceId=evidence.evidence_id,
            deduplicationKey=evidence.deduplication_key,
            changeKey=evidence.change_key,
            artifact=reference,
        )


def run_wc028_monitoring_acquisition_job(
    *,
    configuration: Wc028MonitoringAcquisitionJobConfiguration,
) -> MonitoringAcquisitionOutcome:
    try:
        monitoring_intent = _embedded_model(
            PublishedMonitoringIntent, configuration.monitoring_intent
        )
        intent_reference = _embedded_model(
            PublishedMonitoringIntentAssetReference, configuration.monitoring_intent_reference
        )
        intent_attestation = _embedded_model(
            PublishedMonitoringIntentAttestation, configuration.monitoring_intent_attestation
        )
        context_binding = _embedded_model(
            PublishedRuntimeContextBinding, configuration.context_binding
        )
        collector_contract = _embedded_model(
            MonitoringCollectorContract, configuration.monitoring_collector_contract
        )
        change_scope = _embedded_model(ApprovedChangeScope, configuration.approved_change_scope)
        acquisition_authority = _embedded_model(
            MonitoringAcquisitionAuthority, configuration.acquisition_authority
        )
    except ValueError as exc:
        raise MonitoringAcquisitionJobError(
            "WC-028 production authority configuration is invalid"
        ) from exc
    collector_contract_digest = collector_contract.compute_artifact_digest_value()
    if (
        collector_contract.collector_identity_resource_id.casefold()
        != configuration.collector_identity_resource_id
    ):
        raise MonitoringAcquisitionJobError(
            "collector contract changed the deployed identity boundary"
        )
    _validate_acquisition_authority_preflight(
        acquisition_authority=acquisition_authority,
        configuration=configuration,
        collector_contract=collector_contract,
        context_binding=context_binding,
    )

    intent_verifier = KeyVaultRsaPublicKeyVerifier(
        trusted_key_anchor=configuration.monitoring_intent_trusted_key.anchor,
        managed_identity_client_id=configuration.managed_identity_client_id,
    )
    expected_intent_key_record = TrustedKeyRecord(
        anchor=configuration.monitoring_intent_trusted_key.anchor,
        public_key=intent_verifier.public_key,
        enabled=True,
        activated_at=configuration.monitoring_intent_trusted_key.activated_at,
        expires_at=configuration.monitoring_intent_trusted_key.expires_at,
    )
    intent_key_resolver = KeyVaultTrustedKeyResolver(
        expected_record=expected_intent_key_record,
        managed_identity_client_id=configuration.managed_identity_client_id,
    )
    resolved_intent_key_record = intent_key_resolver(
        configuration.monitoring_intent_trusted_key.anchor
    )
    if resolved_intent_key_record is None:
        raise MonitoringAcquisitionJobError(
            "monitoring intent signing key is not the pinned enabled version"
        )
    _validate_monitoring_intent_key_lifecycle(
        monitoring_intent=monitoring_intent,
        key_record=resolved_intent_key_record,
        as_of=_utc_now_milliseconds(),
    )
    validate_published_monitoring_intent_assets(
        intent_reference,
        monitoring_intent,
        intent_attestation,
        trusted_key_id=(configuration.monitoring_intent_trusted_key.key_vault_key_id),
        signature_verifier=intent_verifier.verify_preimage,
    )
    validate_monitoring_intent_activation_eligible(
        monitoring_intent,
        context_binding,
        expected_active_context_authority_digest=(
            configuration.expected_active_context_authority_digest
        ),
    )
    collector_key_verifier = KeyVaultRsaPublicKeyVerifier(
        trusted_key_anchor=configuration.collector_signing_key.anchor,
        managed_identity_client_id=configuration.managed_identity_client_id,
    )
    collector_key_record = TrustedKeyRecord(
        anchor=configuration.collector_signing_key.anchor,
        public_key=collector_key_verifier.public_key,
        enabled=True,
        activated_at=configuration.collector_signing_key.activated_at,
        expires_at=configuration.collector_signing_key.expires_at,
    )
    collector_key_resolver = KeyVaultTrustedKeyResolver(
        expected_record=collector_key_record,
        managed_identity_client_id=configuration.managed_identity_client_id,
    )
    collector_signer = KeyVaultRsaSigner(
        trusted_key_anchor=configuration.collector_signing_key.anchor,
        managed_identity_client_id=configuration.managed_identity_client_id,
    )
    change_signer = KeyVaultChangeEvidenceSigner(
        key_vault_key_id=configuration.collector_signing_key.key_vault_key_id,
        managed_identity_client_id=configuration.managed_identity_client_id,
    )

    def load_intent_assets(
        supplied: PublishedMonitoringIntent,
    ) -> tuple[
        PublishedMonitoringIntentAssetReference,
        PublishedMonitoringIntentAttestation,
    ]:
        if supplied != monitoring_intent:
            raise MonitoringAcquisitionJobError(
                "coordinator requested assets for another monitoring intent"
            )
        return intent_reference, intent_attestation

    acquisition_receipt_verifier = _build_acquisition_receipt_verifier(
        acquisition_authority=acquisition_authority,
        collector_contract=collector_contract,
        trusted_key=configuration.collector_signing_key,
        key_resolver=collector_key_resolver,
    )
    collection_transaction = MonitoringCollectionTransaction(
        acquisition_receipt_verifier=acquisition_receipt_verifier,
        change_signer=change_signer,
        change_signing_key_id=configuration.collector_signing_key.key_vault_key_id,
        monitoring_intent_trusted_key_id=(
            configuration.monitoring_intent_trusted_key.key_vault_key_id
        ),
        monitoring_intent_signature_verifier=intent_verifier.verify_preimage,
        monitoring_intent_asset_loader=load_intent_assets,
    )
    acquisition_clock = _CredentialBoundAcquisitionClock()
    transport = AzureManagedIdentityJsonTransport(
        timeout_seconds=configuration.http_timeout_seconds,
        retry_limit=configuration.http_retry_limit,
    )
    port = AzureMonitoringAcquisitionPort(
        collector_identity_resource_id=configuration.collector_identity_resource_id,
        workspace_resource_id=configuration.workspace_resource_id,
        workspace_customer_id=configuration.workspace_customer_id,
        network_watcher_resource_id=configuration.network_watcher_resource_id,
        authorized_resource_ids=acquisition_authority.allowed_resource_ids,
        transport=transport,
        clock=acquisition_clock.source_collection_time,
    )
    acquisition_adapter = CredentialBoundMonitoringAcquisitionAdapter(
        reviewed_collector_contract=collector_contract,
        acquisition_port=port,
        utc_now=acquisition_clock.runtime_now,
    )
    monitoring_evidence_store = AzureBlobChangeEvidenceReplayStore(
        blob_endpoint=configuration.evidence_blob_endpoint,
        container_name=configuration.evidence_container_name,
        managed_identity_client_id=configuration.managed_identity_client_id,
    )
    change_evidence_store = AzureBlobChangeEvidenceReplayStore(
        blob_endpoint=configuration.change_evidence_blob_endpoint,
        container_name=configuration.change_evidence_container_name,
        managed_identity_client_id=configuration.managed_identity_client_id,
    )
    commit_port = MonitoringEvidenceCommitPort(
        monitoring_writer=monitoring_evidence_store,
        change_writer=change_evidence_store,
        signer=collector_signer,
        trusted_key=configuration.collector_signing_key,
        reviewed_collector_contract=collector_contract,
        key_resolver=collector_key_resolver,
        monitoring_current_reader=monitoring_evidence_store,
        change_current_reader=change_evidence_store,
    )
    coordinator = MonitoringAcquisitionCoordinator(
        acquisition_adapter=acquisition_adapter,
        acquisition_authority=acquisition_authority,
        expected_acquisition_authority_digest=(configuration.expected_acquisition_authority_digest),
        expected_collector_contract_digest=collector_contract_digest,
        monitoring_intent_trusted_key_id=(
            configuration.monitoring_intent_trusted_key.key_vault_key_id
        ),
        monitoring_intent_signature_verifier=intent_verifier.verify_preimage,
        monitoring_intent_asset_loader=load_intent_assets,
        collection_transaction=collection_transaction,
        receipt_signer=collector_signer,
    )
    issued_at = _utc_now_milliseconds()
    trusted_as_of = issued_at + timedelta(seconds=configuration.trust_delay_seconds)
    expires_at = issued_at + timedelta(seconds=configuration.request_lifetime_seconds)
    try:
        return coordinator.execute(
            monitoring_intent=monitoring_intent,
            context_binding=context_binding,
            expected_active_context_authority_digest=(
                configuration.expected_active_context_authority_digest
            ),
            collected_at=issued_at,
            change_scope=change_scope,
            commit_port=commit_port,
            incident_revision=configuration.incident_revision,
            issued_at=issued_at,
            trusted_as_of=trusted_as_of,
            expires_at=expires_at,
        )
    except (MonitoringAcquisitionError, MonitoringCollectionError) as exc:
        raise MonitoringAcquisitionJobError(str(exc)) from exc
    except (ArtifactReadError, ArtifactWriteError) as exc:
        raise MonitoringAcquisitionJobError("WC-028 immutable evidence persistence failed") from exc


__all__ = [
    "AzureManagedIdentityJsonTransport",
    "AzureMonitoringAcquisitionPort",
    "MonitoringAcquisitionJobError",
    "MonitoringAcquisitionJobOutcome",
    "MonitoringEvidenceCommitPort",
    "MonitoringRuntimeTrustedKey",
    "Wc028MonitoringAcquisitionJobConfiguration",
    "load_wc028_monitoring_acquisition_job_configuration",
    "run_wc028_monitoring_acquisition_job",
]
