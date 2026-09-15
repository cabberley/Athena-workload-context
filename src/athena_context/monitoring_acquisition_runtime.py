from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.artifacts import (
    ArtifactAlreadyExistsError,
    ArtifactCurrentReadRequest,
    ArtifactMetadataHashes,
    ArtifactNotFoundError,
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
    MONITORING_IDENTITY_PROOF_AUDIENCE,
    MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS,
    MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
    MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
    ApprovedChangeScope,
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
from athena_context.monitoring_acquisition import (
    AzureMonitoringAdapter,
    MonitoringAcquisitionAuthority,
    MonitoringAcquisitionCoordinator,
    MonitoringAcquisitionError,
    MonitoringAcquisitionOutcome,
    compute_monitoring_acquisition_authority_scope,
)
from athena_context.monitoring_collection import (
    CommittedMonitoringCollection,
    MonitoringCollectionError,
    MonitoringCollectionTransaction,
    PreparedMonitoringCollection,
)

_IDENTITY_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/"
    r"providers/microsoft\.managedidentity/userassignedidentities/[a-z0-9-_]{1,128}$"
)
_STORAGE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/providers/"
    r"microsoft\.storage/storageaccounts/[a-z0-9]{3,24}$"
)
_GUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_MAX_CONFIGURATION_BYTES = 512 * 1024
_RESOURCE_LOG_READER_ROLE_DEFINITION_GUID = "f33a4363-5d9a-5d50-9871-c08582234978"
_RESOURCE_HEALTH_ROLE_DEFINITION_GUID = "0790d6f2-9553-5b63-84ac-56596b7e4072"
_RESOURCE_LOG_ALLOWED_OPERATIONS = (
    "Microsoft.Insights/Logs/Heartbeat/Read",
    "Microsoft.Insights/Logs/Perf/Read",
    "Microsoft.Insights/Logs/InsightsMetrics/Read",
    "Microsoft.Insights/Logs/Syslog/Read",
    "Microsoft.Insights/Logs/VMConnection/Read",
)
_RESOURCE_HEALTH_ALLOWED_OPERATIONS = (
    "Microsoft.ResourceHealth/AvailabilityStatuses/current/read",
)


def _configuration_tuple(value: object) -> tuple[object, ...]:
    return tuple(value) if isinstance(value, list | tuple) else ()


def _configuration_resource_ids(value: object) -> tuple[str, ...]:
    return tuple(
        str(item).casefold().rstrip("/")
        for item in _configuration_tuple(value)
        if isinstance(item, str)
    )


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
    schema_version: Literal["athena.wc028MonitoringAcquisitionJobConfiguration.v2"] = Field(
        alias="schemaVersion"
    )
    managed_identity_client_id: str = Field(
        alias="managedIdentityClientId",
        pattern=_GUID_PATTERN.pattern,
    )
    collector_identity_resource_id: str = Field(alias="collectorIdentityResourceId")
    athena_context_identity_resource_id: str = Field(alias="athenaContextIdentityResourceId")
    runtime_support_identity_resource_id: str = Field(alias="runtimeSupportIdentityResourceId")
    runtime_support_identity_client_id: str = Field(
        alias="runtimeSupportIdentityClientId",
        pattern=_GUID_PATTERN.pattern,
    )
    runtime_support_identity_principal_id: str = Field(
        alias="runtimeSupportIdentityPrincipalId",
        pattern=_GUID_PATTERN.pattern,
    )
    source_storage_account_resource_id: str = Field(alias="sourceStorageAccountResourceId")
    evidence_storage_account_resource_id: str = Field(alias="evidenceStorageAccountResourceId")
    evidence_blob_endpoint: str = Field(alias="evidenceBlobEndpoint")
    evidence_container_name: Literal["monitoring-evidence"] = Field(alias="evidenceContainerName")
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
    execution_id: str = Field(
        alias="executionId",
        pattern=r"^wc028-execution-[a-f0-9]{32}$",
    )
    persistence_replay_key: str = Field(
        alias="persistenceReplayKey",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    legacy_collector_rbac_cleanup_digest: str = Field(
        alias="legacyCollectorRbacCleanupDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    trust_delay_seconds: int = Field(alias="trustDelaySeconds", ge=1, le=600)
    request_lifetime_seconds: int = Field(
        alias="requestLifetimeSeconds",
        ge=2,
        le=900,
    )

    @field_validator(
        "collector_identity_resource_id",
        "athena_context_identity_resource_id",
        "runtime_support_identity_resource_id",
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
    )
    @classmethod
    def validate_storage_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        if _STORAGE_ID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("runtime storage account resource ID is invalid")
        return normalized

    @field_validator("evidence_blob_endpoint")
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
        if (
            len(
                {
                    self.collector_identity_resource_id,
                    self.athena_context_identity_resource_id,
                    self.runtime_support_identity_resource_id,
                }
            )
            != 3
        ):
            raise ValueError("collector, support, and Athena context identities must be separate")
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
        contract = self.monitoring_collector_contract
        authority = self.acquisition_authority
        collector_principal_id = str(contract.get("monitoringReaderPrincipalId", "")).casefold()
        collector_tenant_id = str(contract.get("collectorTenantId", "")).casefold()
        context_principal_id = str(contract.get("athenaContextPrincipalId", "")).casefold()
        workload_resource_group_id = str(contract.get("workloadResourceGroupId", "")).casefold()
        expected_resource_log_role_definition_id = (
            f"{workload_resource_group_id}/providers/microsoft.authorization/"
            f"roledefinitions/{_RESOURCE_LOG_READER_ROLE_DEFINITION_GUID}"
        )
        expected_resource_health_role_definition_id = (
            f"{workload_resource_group_id}/providers/microsoft.authorization/"
            f"roledefinitions/{_RESOURCE_HEALTH_ROLE_DEFINITION_GUID}"
        )
        effective_rbac_inventory = contract.get("effectiveRbacInventory")
        if not isinstance(effective_rbac_inventory, dict):
            raise ValueError("collector contract omitted measured effective RBAC inventory")
        signal_read_scope_ids = _configuration_resource_ids(contract.get("signalReadScopeIds"))
        resource_log_read_scope_ids = _configuration_resource_ids(
            contract.get("resourceLogReadScopeIds")
        )
        resource_health_scope_ids = _configuration_resource_ids(
            contract.get("resourceHealthScopeIds")
        )
        exact_bindings: tuple[tuple[object, object, str], ...] = (
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
                contract.get("flowTableAcquisitionMode"),
                "unsupportedUnavailable",
                "collector contract flow acquisition mode",
            ),
            (
                contract.get("workspaceResourceContextAccessEnabled"),
                True,
                "collector contract resource-context log access",
            ),
            (
                contract.get("workspaceSkuName"),
                "PerGB2018",
                "collector contract workspace SKU",
            ),
            (
                contract.get("resourceIdColumn"),
                "_ResourceId",
                "collector contract resource ID column",
            ),
            (
                contract.get("logQueryPreferHeader"),
                "include-permissions=true",
                "collector contract log permission header",
            ),
            (
                str(contract.get("resourceLogReaderRoleDefinitionId", "")).casefold(),
                expected_resource_log_role_definition_id,
                "collector contract resource-log role",
            ),
            (
                _configuration_tuple(contract.get("resourceLogAllowedOperations")),
                _RESOURCE_LOG_ALLOWED_OPERATIONS,
                "collector contract resource-log operations",
            ),
            (
                resource_log_read_scope_ids,
                signal_read_scope_ids,
                "collector contract resource-log scopes",
            ),
            (
                str(contract.get("resourceHealthRoleDefinitionId", "")).casefold(),
                expected_resource_health_role_definition_id,
                "collector contract Resource Health role",
            ),
            (
                _configuration_tuple(contract.get("resourceHealthAllowedOperations")),
                _RESOURCE_HEALTH_ALLOWED_OPERATIONS,
                "collector contract Resource Health operations",
            ),
            (
                resource_health_scope_ids,
                signal_read_scope_ids,
                "collector contract Resource Health scopes",
            ),
            (
                contract.get("identityProofAudience"),
                MONITORING_IDENTITY_PROOF_AUDIENCE,
                "collector contract identity proof audience",
            ),
            (
                contract.get("identityProofTokenVersion"),
                MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
                "collector contract identity proof token version",
            ),
            (
                contract.get("identityProofRequiredRole"),
                MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
                "collector contract identity proof role",
            ),
            (
                contract.get("identityProofMaximumLifetimeSeconds"),
                MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS,
                "collector contract identity proof lifetime",
            ),
            (
                contract.get("physicalIdentitySeparationEnforced"),
                True,
                "collector contract physical identity separation",
            ),
            (
                authority.get("schemaVersion"),
                "athena.wc028MonitoringAcquisitionAuthority.v5",
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
                authority.get("identityProofAudience"),
                MONITORING_IDENTITY_PROOF_AUDIENCE,
                "acquisition identity proof audience",
            ),
            (
                authority.get("identityProofTokenVersion"),
                MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
                "acquisition identity proof token version",
            ),
            (
                authority.get("identityProofRequiredRole"),
                MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
                "acquisition identity proof role",
            ),
            (
                authority.get("identityProofMaximumLifetimeSeconds"),
                MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS,
                "acquisition identity proof lifetime",
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
            (
                authority.get("effectiveRbacInventoryDigest"),
                effective_rbac_inventory.get("inventoryDigest"),
                "acquisition effective RBAC inventory",
            ),
            (
                authority.get("effectiveRbacSourceManifestDigest"),
                effective_rbac_inventory.get("sourceManifestDigest"),
                "acquisition effective RBAC source manifest",
            ),
        )
        for actual, expected, label in exact_bindings:
            if actual != expected:
                raise ValueError(f"{label} does not match the production deployment")
        unsupported_ip_flow_fields = (
            "ipFlowVerifyRoleDefinitionId",
            "ipFlowVerifyRoleName",
            "ipFlowVerifyScopeId",
            "ipFlowVerifyAllowedOperations",
        )
        if (
            any(contract.get(name) is not None for name in unsupported_ip_flow_fields)
            or "ipFlowVerify" in _configuration_tuple(authority.get("allowedSources"))
            or any(
                "ipflowverify" in str(operation).casefold()
                for operation in _configuration_tuple(contract.get("allowedReadOperations"))
            )
        ):
            raise ValueError("current collector contract must not authorize IP Flow")
        monitoring_intent_digest = self.monitoring_intent.get("intentDigest")
        context_binding_digest = self.context_binding.get("bindingDigest")
        expected_replay_key = compute_artifact_digest(
            {
                "schemaVersion": "athena.wc028MonitoringPersistenceReplay.v1",
                "executionId": self.execution_id,
                "acquisitionAuthorityDigest": self.expected_acquisition_authority_digest,
                "monitoringIntentDigest": monitoring_intent_digest,
                "contextBindingDigest": context_binding_digest,
                "incidentRevision": self.incident_revision,
                "legacyCollectorRbacCleanupDigest": (self.legacy_collector_rbac_cleanup_digest),
            }
        )
        if (
            not isinstance(monitoring_intent_digest, str)
            or not isinstance(context_binding_digest, str)
            or self.persistence_replay_key != expected_replay_key
        ):
            raise ValueError("persistenceReplayKey does not bind the reviewed execution")
        if (
            _GUID_PATTERN.fullmatch(collector_principal_id) is None
            or _GUID_PATTERN.fullmatch(collector_tenant_id) is None
            or _GUID_PATTERN.fullmatch(context_principal_id) is None
            or collector_principal_id == context_principal_id
            or self.runtime_support_identity_client_id.casefold()
            == self.managed_identity_client_id.casefold()
            or self.runtime_support_identity_principal_id
            in {collector_principal_id, context_principal_id}
        ):
            raise ValueError(
                "collector, support, and context client and principal identities "
                "must be valid and separate"
            )
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
                "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_IDENTITY_RESOURCE_ID",
                self.runtime_support_identity_resource_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_IDENTITY_CLIENT_ID",
                self.runtime_support_identity_client_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_IDENTITY_PRINCIPAL_ID",
                self.runtime_support_identity_principal_id,
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
                "ATHENA_WC028_DEPLOYED_LEGACY_COLLECTOR_RBAC_CLEANUP_DIGEST",
                self.legacy_collector_rbac_cleanup_digest,
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
        support_client_id = os.environ.get("ATHENA_WC028_RUNTIME_SUPPORT_CLIENT_ID")
        if (
            support_client_id is not None
            and support_client_id.casefold() != self.runtime_support_identity_client_id.casefold()
        ):
            raise ValueError(
                "ATHENA_WC028_RUNTIME_SUPPORT_CLIENT_ID does not match the support identity"
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


def _embedded_model(model: Any, payload: object) -> Any:
    return model.model_validate_json(canonicalize_json(payload))


class _HandoffSigner(Protocol):
    def sign_preimage(self, canonical_preimage: bytes) -> str: ...


class _UnsupportedChangeEvidenceSigner:
    """Fail closed if the current collector unexpectedly produces change artifacts."""

    @staticmethod
    def sign_preimage(_canonical_preimage: bytes) -> str:
        raise MonitoringAcquisitionJobError(
            "current collector contract does not authorize runtime change evidence"
        )

    @staticmethod
    def verify_preimage(_canonical_preimage: bytes, _signature: bytes) -> bool:
        raise MonitoringAcquisitionJobError(
            "current collector contract does not authorize runtime change evidence"
        )


class MonitoringAcquisitionJobOutcome(Protocol):
    committed: CommittedMonitoringCollection
    correlation_request: CorrelationRequest


class MonitoringPersistenceCommitManifest(_StrictRuntimeModel):
    schema_version: Literal["athena.wc028MonitoringPersistenceCommit.v1"] = Field(
        alias="schemaVersion"
    )
    replay_key: str = Field(alias="replayKey", pattern=r"^sha256:[a-f0-9]{64}$")
    prepared_digest: str = Field(alias="preparedDigest", pattern=r"^sha256:[a-f0-9]{64}$")
    collection_id: str = Field(alias="collectionId", pattern=r"^wc024-[a-f0-9]{12}$")
    intent_id: str = Field(
        alias="intentId",
        pattern=r"^monitoring-intent-[a-f0-9]{32}$",
    )
    intent_digest: str = Field(alias="intentDigest", pattern=r"^sha256:[a-f0-9]{64}$")
    context_binding_digest: str = Field(
        alias="contextBindingDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    collector_contract_digest: str = Field(
        alias="collectorContractDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    monitoring_bundle_digest: str = Field(
        alias="monitoringBundleDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    acquisition_receipt_digest: str = Field(
        alias="acquisitionReceiptDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    monitoring_handoff: MonitoringEvidenceHandoff = Field(alias="monitoringHandoff")
    manifest_digest: str = Field(alias="manifestDigest", pattern=r"^sha256:[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_manifest(self) -> MonitoringPersistenceCommitManifest:
        if (
            self.monitoring_handoff.collection_id != self.collection_id
            or self.monitoring_handoff.collector_contract_digest != self.collector_contract_digest
            or self.monitoring_handoff.evidence.content_digest != self.monitoring_bundle_digest
            or self.monitoring_handoff.acquisition_receipt_digest != self.acquisition_receipt_digest
        ):
            raise ValueError("monitoring handoff does not bind the persistence commit")
        prepared_payload = {
            "intentId": self.intent_id,
            "intentDigest": self.intent_digest,
            "contextBindingDigest": self.context_binding_digest,
            "collectorContractDigest": self.collector_contract_digest,
            "monitoringBundleDigest": self.monitoring_bundle_digest,
            "acquisitionReceiptDigest": self.acquisition_receipt_digest,
        }
        if self.prepared_digest != compute_artifact_digest(prepared_payload):
            raise ValueError("preparedDigest does not bind the exact prepared transaction")
        expected_manifest_digest = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"manifest_digest"},
            )
        )
        if self.manifest_digest != expected_manifest_digest:
            raise ValueError("manifestDigest does not bind the persistence commit")
        return self

    def canonical_bytes(self) -> bytes:
        return (canonicalize_json(self.model_dump(mode="json", by_alias=True)) + "\n").encode(
            "utf-8"
        )


def _monitoring_persistence_replay_payload(
    prepared: PreparedMonitoringCollection,
) -> dict[str, object]:
    acquisition_receipt = prepared.monitoring_bundle.acquisition_receipt
    if acquisition_receipt is None:
        raise MonitoringAcquisitionJobError(
            "WC-028 persistence requires the verified acquisition receipt"
        )
    if prepared.change_artifacts:
        raise MonitoringAcquisitionJobError(
            "current collector contract does not authorize runtime change persistence"
        )
    return {
        "intentId": prepared.intent_id,
        "intentDigest": prepared.intent_digest,
        "contextBindingDigest": prepared.context_binding_digest,
        "collectorContractDigest": prepared.monitoring_bundle.monitoring_contract_digest,
        "monitoringBundleDigest": sha256_hex(prepared.monitoring_bundle.canonical_bytes()),
        "acquisitionReceiptDigest": acquisition_receipt.receipt_digest,
    }


def _monitoring_persistence_collection_id(replay_key: str) -> str:
    if re.fullmatch(r"sha256:[a-f0-9]{64}", replay_key) is None:
        raise ValueError("replay_key must be one exact SHA-256 digest")
    return f"wc024-{replay_key.removeprefix('sha256:')[:12]}"


def _validate_acquisition_authority_preflight(
    *,
    acquisition_authority: MonitoringAcquisitionAuthority,
    configuration: Wc028MonitoringAcquisitionJobConfiguration,
    collector_contract: MonitoringCollectorContract,
    context_binding: PublishedRuntimeContextBinding,
    monitoring_intent: PublishedMonitoringIntent,
) -> None:
    if acquisition_authority.authority_digest != (
        configuration.expected_acquisition_authority_digest
    ):
        raise MonitoringAcquisitionJobError(
            "monitoring acquisition authority is not the configured authority"
        )
    if acquisition_authority.schema_version != ("athena.wc028MonitoringAcquisitionAuthority.v5"):
        raise MonitoringAcquisitionJobError(
            "production monitoring acquisition requires authority schema v5"
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
    effective_rbac_inventory = collector_contract.effective_rbac_inventory
    if effective_rbac_inventory is None:
        raise MonitoringAcquisitionJobError(
            "collector contract omitted measured effective RBAC inventory"
        )
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
        or cast(str, collector_contract.athena_context_identity_id).casefold().rstrip("/")
        != acquisition_authority.athena_context_identity_id
        or collector_contract.athena_context_principal_id
        != acquisition_authority.athena_context_principal_id
        or collector_contract.physical_identity_separation_enforced is not True
        or collector_contract.identity_proof_audience
        != acquisition_authority.identity_proof_audience
        or collector_contract.identity_proof_token_version
        != acquisition_authority.identity_proof_token_version
        or collector_contract.identity_proof_required_role
        != acquisition_authority.identity_proof_required_role
        or collector_contract.identity_proof_maximum_lifetime_seconds
        != acquisition_authority.identity_proof_maximum_lifetime_seconds
        or acquisition_authority.effective_rbac_inventory_digest
        != effective_rbac_inventory.inventory_digest
        or acquisition_authority.effective_rbac_source_manifest_digest
        != effective_rbac_inventory.source_manifest_digest
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
    controls_by_id = {item.control_id: item for item in monitoring_intent.controls}
    required_control_ids = cast(tuple[str, ...], acquisition_authority.required_control_ids)
    if any(control_id not in controls_by_id for control_id in required_control_ids):
        raise MonitoringAcquisitionJobError(
            "monitoring acquisition authority references an unknown required control"
        )
    try:
        expected_sources, expected_resources = compute_monitoring_acquisition_authority_scope(
            tuple(controls_by_id[control_id] for control_id in required_control_ids),
            collector_contract,
        )
    except (TypeError, ValueError, MonitoringAcquisitionError) as exc:
        raise MonitoringAcquisitionJobError(
            "monitoring acquisition controls escape the reviewed collector contract"
        ) from exc
    unsupported_sources = set(expected_sources) - {"logAnalytics", "resourceHealth"}
    if unsupported_sources:
        raise MonitoringAcquisitionJobError(
            "current collector contract does not authorize runtime acquisition from "
            + ", ".join(sorted(unsupported_sources))
        )
    if (
        acquisition_authority.allowed_sources != expected_sources
        or acquisition_authority.allowed_resource_ids != expected_resources
    ):
        raise MonitoringAcquisitionJobError(
            "monitoring acquisition authority does not exactly bind contract scope"
        )
    evidence_container_resource_id = (
        f"{configuration.evidence_storage_account_resource_id}/blobservices/default/"
        f"containers/{configuration.evidence_container_name}"
    )
    if (
        collector_contract.evidence_storage_account_resource_id.casefold().rstrip("/")
        != configuration.evidence_storage_account_resource_id
        or collector_contract.evidence_container_resource_id is None
        or collector_contract.evidence_container_resource_id.casefold().rstrip("/")
        != evidence_container_resource_id
        or collector_contract.evidence_container_name != configuration.evidence_container_name
        or collector_contract.signing_key_resource_id
        != configuration.collector_signing_key.key_vault_key_id
        or acquisition_authority.receipt_signing_key_id
        != configuration.collector_signing_key.key_vault_key_id
        or collector_contract.flow_table_acquisition_mode != "unsupportedUnavailable"
        or collector_contract.ip_flow_verify_role_definition_id is not None
        or collector_contract.ip_flow_verify_role_name is not None
        or collector_contract.ip_flow_verify_scope_id is not None
        or collector_contract.ip_flow_verify_allowed_operations is not None
        or collector_contract.resource_log_allowed_operations != _RESOURCE_LOG_ALLOWED_OPERATIONS
        or collector_contract.resource_health_allowed_operations
        != _RESOURCE_HEALTH_ALLOWED_OPERATIONS
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
    """Manifest-last persistence for one replay-safe normalized monitoring transaction."""

    def __init__(
        self,
        *,
        monitoring_writer: CreateOnlyArtifactWriterPort,
        signer: _HandoffSigner,
        trusted_key: MonitoringRuntimeTrustedKey,
        reviewed_collector_contract: MonitoringCollectorContract,
        monitoring_current_reader: CurrentArtifactReaderPort,
        persistence_replay_key: str,
        key_resolver: TrustedKeyResolver | None = None,
        key_record: TrustedKeyRecord | None = None,
    ) -> None:
        if key_resolver is not None and key_record is not None:
            raise TypeError("provide either a monitoring key resolver or a trusted key record")
        if re.fullmatch(r"sha256:[a-f0-9]{64}", persistence_replay_key) is None:
            raise ValueError("persistence_replay_key must be one exact SHA-256 digest")
        self._monitoring_writer = monitoring_writer
        self._signer = signer
        self._trusted_key = trusted_key
        self._reviewed_collector_contract = reviewed_collector_contract
        self._monitoring_current_reader = monitoring_current_reader
        self._persistence_replay_key = persistence_replay_key
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
        if prepared.change_artifacts:
            raise MonitoringAcquisitionJobError(
                "current collector contract does not authorize runtime change persistence"
            )
        bundle = prepared.monitoring_bundle
        observed_at = cast(datetime, bundle.collected_at)
        bundle_bytes = bundle.canonical_bytes()
        replay_payload = _monitoring_persistence_replay_payload(prepared)
        prepared_digest = compute_artifact_digest(replay_payload)
        replay_key = self._persistence_replay_key
        collection_id = _monitoring_persistence_collection_id(replay_key)
        manifest_blob_name = (
            f"wc024-monitoring/commits/{replay_key.removeprefix('sha256:')}/manifest.json"
        )
        recovered = self._recover_commit_manifest(
            prepared=prepared,
            replay_key=replay_key,
            manifest_blob_name=manifest_blob_name,
        )
        if recovered is not None:
            yield recovered
            return

        blob_name = f"wc024-monitoring/{collection_id}/evidence.json"
        evidence_reference = self._write(
            writer=self._monitoring_writer,
            current_reader=self._monitoring_current_reader,
            blob_name=blob_name,
            payload=bundle_bytes,
        )
        acquisition_receipt = bundle.acquisition_receipt
        if acquisition_receipt is None:
            raise MonitoringAcquisitionJobError(
                "WC-028 monitoring bundle omitted its acquisition receipt"
            )
        payload: dict[str, object] = {
            "schemaVersion": "athena.wc028MonitoringEvidenceHandoff.v2",
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
            "acquisitionReceiptDigest": acquisition_receipt.receipt_digest,
        }
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
        committed = CommittedMonitoringCollection(
            monitoring_handoff=handoff,
            change_handoffs=(),
        )
        commit_manifest = self._build_commit_manifest(
            prepared=prepared,
            replay_key=replay_key,
            prepared_digest=prepared_digest,
            committed=committed,
        )
        yield committed
        self._write(
            writer=self._monitoring_writer,
            current_reader=self._monitoring_current_reader,
            blob_name=manifest_blob_name,
            payload=commit_manifest.canonical_bytes(),
        )
        durable = self._recover_commit_manifest(
            prepared=prepared,
            replay_key=replay_key,
            manifest_blob_name=manifest_blob_name,
        )
        if durable is None:
            raise MonitoringAcquisitionJobError(
                "monitoring persistence commit manifest disappeared after creation"
            )

    def _build_commit_manifest(
        self,
        *,
        prepared: PreparedMonitoringCollection,
        replay_key: str,
        prepared_digest: str,
        committed: CommittedMonitoringCollection,
    ) -> MonitoringPersistenceCommitManifest:
        acquisition_receipt = prepared.monitoring_bundle.acquisition_receipt
        if acquisition_receipt is None:
            raise MonitoringAcquisitionJobError(
                "WC-028 monitoring bundle omitted its acquisition receipt"
            )
        replay_payload = _monitoring_persistence_replay_payload(prepared)
        payload: dict[str, object] = {
            "schemaVersion": "athena.wc028MonitoringPersistenceCommit.v1",
            "replayKey": replay_key,
            "preparedDigest": prepared_digest,
            "collectionId": committed.monitoring_handoff.collection_id,
            **replay_payload,
            "monitoringHandoff": committed.monitoring_handoff.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
        }
        return MonitoringPersistenceCommitManifest.model_validate_json(
            canonicalize_json(
                {
                    **payload,
                    "manifestDigest": compute_artifact_digest(payload),
                }
            )
        )

    def _recover_commit_manifest(
        self,
        *,
        prepared: PreparedMonitoringCollection,
        replay_key: str,
        manifest_blob_name: str,
    ) -> CommittedMonitoringCollection | None:
        try:
            result = self._monitoring_current_reader.read_current(
                ArtifactCurrentReadRequest(blob_name=manifest_blob_name)
            )
        except ArtifactNotFoundError:
            return None
        try:
            manifest = MonitoringPersistenceCommitManifest.model_validate_json(result.payload)
        except (UnicodeDecodeError, ValueError) as exc:
            raise MonitoringAcquisitionJobError(
                "recovered monitoring persistence commit manifest is invalid"
            ) from exc
        if (
            result.blob_name != manifest_blob_name
            or result.payload_sha256 != sha256_hex(result.payload)
            or result.payload != manifest.canonical_bytes()
            or manifest.replay_key != replay_key
            or manifest.collection_id != _monitoring_persistence_collection_id(replay_key)
            or manifest.prepared_digest
            != compute_artifact_digest(_monitoring_persistence_replay_payload(prepared))
        ):
            raise MonitoringAcquisitionJobError(
                "recovered monitoring persistence commit does not match the prepared transaction"
            )
        self._verify_current_reference(
            reader=self._monitoring_current_reader,
            reference=manifest.monitoring_handoff.evidence,
            expected_payload=prepared.monitoring_bundle.canonical_bytes(),
            label="monitoring evidence",
        )
        try:
            verify_monitoring_evidence_handoff_attestation(
                manifest.monitoring_handoff,
                as_of=cast(datetime, prepared.monitoring_bundle.collected_at),
                trusted_key_anchor=self._trusted_key.anchor,
                key_resolver=self._key_resolver,
                reviewed_collector_contract=self._reviewed_collector_contract,
            )
        except (TypeError, ValueError) as exc:
            raise MonitoringAcquisitionJobError(
                "recovered monitoring persistence handoff failed verification"
            ) from exc
        return CommittedMonitoringCollection(
            monitoring_handoff=manifest.monitoring_handoff,
            change_handoffs=(),
        )

    @staticmethod
    def _verify_current_reference(
        *,
        reader: CurrentArtifactReaderPort,
        reference: VersionPinnedBlobReference,
        expected_payload: bytes,
        label: str,
    ) -> None:
        result = reader.read_current(ArtifactCurrentReadRequest(blob_name=reference.name))
        if (
            result.blob_name != reference.name
            or result.version_id != reference.version
            or result.payload_sha256 != reference.content_digest
            or result.payload_sha256 != sha256_hex(expected_payload)
            or result.payload != expected_payload
        ):
            raise MonitoringAcquisitionJobError(
                f"recovered {label} does not match its version-pinned commit reference"
            )

    def _write(
        self,
        *,
        writer: CreateOnlyArtifactWriterPort,
        current_reader: CurrentArtifactReaderPort,
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
            recovered = current_reader.read_current(ArtifactCurrentReadRequest(blob_name=blob_name))
            if recovered.payload == payload and recovered.payload_sha256 == sha256_hex(payload):
                return VersionPinnedBlobReference(
                    name=recovered.blob_name,
                    version=recovered.version_id,
                    contentDigest=recovered.payload_sha256,
                )
            raise MonitoringAcquisitionJobError(
                f"immutable persistence artifact already exists: {blob_name}"
            ) from exc
        if receipt.blob_name != blob_name or receipt.payload_sha256 != sha256_hex(payload):
            raise MonitoringAcquisitionJobError(
                "artifact writer returned a mismatched create-only receipt"
            )
        return VersionPinnedBlobReference(
            name=receipt.blob_name,
            version=receipt.version_id,
            contentDigest=receipt.payload_sha256,
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
        monitoring_intent=monitoring_intent,
    )

    intent_verifier = KeyVaultRsaPublicKeyVerifier(
        trusted_key_anchor=configuration.monitoring_intent_trusted_key.anchor,
        managed_identity_client_id=configuration.runtime_support_identity_client_id,
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
        managed_identity_client_id=configuration.runtime_support_identity_client_id,
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
        change_signer=_UnsupportedChangeEvidenceSigner(),
        change_signing_key_id=configuration.collector_signing_key.key_vault_key_id,
        monitoring_intent_trusted_key_id=(
            configuration.monitoring_intent_trusted_key.key_vault_key_id
        ),
        monitoring_intent_signature_verifier=intent_verifier.verify_preimage,
        monitoring_intent_asset_loader=load_intent_assets,
    )
    acquisition_adapter = AzureMonitoringAdapter(
        reviewed_collector_contract=collector_contract,
    )
    monitoring_evidence_store = AzureBlobChangeEvidenceReplayStore(
        blob_endpoint=configuration.evidence_blob_endpoint,
        container_name=configuration.evidence_container_name,
        managed_identity_client_id=configuration.managed_identity_client_id,
    )
    commit_port = MonitoringEvidenceCommitPort(
        monitoring_writer=monitoring_evidence_store,
        signer=collector_signer,
        trusted_key=configuration.collector_signing_key,
        reviewed_collector_contract=collector_contract,
        monitoring_current_reader=monitoring_evidence_store,
        persistence_replay_key=configuration.persistence_replay_key,
        key_resolver=collector_key_resolver,
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
    "MonitoringAcquisitionJobError",
    "MonitoringAcquisitionJobOutcome",
    "MonitoringEvidenceCommitPort",
    "MonitoringRuntimeTrustedKey",
    "Wc028MonitoringAcquisitionJobConfiguration",
    "load_wc028_monitoring_acquisition_job_configuration",
    "run_wc028_monitoring_acquisition_job",
]
