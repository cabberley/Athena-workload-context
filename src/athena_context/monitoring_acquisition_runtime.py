from __future__ import annotations

import base64
import os
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid5

from azure.core.exceptions import AzureError
from azure.servicebus.exceptions import ServiceBusError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.artifacts import (
    ArtifactAlreadyExistsError,
    ArtifactCurrentReadRequest,
    ArtifactMetadataHashes,
    ArtifactNotFoundError,
    ArtifactReadError,
    ArtifactReadResult,
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
    MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS,
    MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
    MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
    ApprovedChangeScope,
    CorrelationRequest,
    EndpointHealthObservation,
    GuestSignalObservation,
    MonitoringAcquisitionReceipt,
    MonitoringCollectorContract,
    MonitoringEffectiveRbacDenyAssignment,
    MonitoringEffectiveRbacGrant,
    MonitoringEffectiveRbacPimScheduleInstance,
    MonitoringEffectiveRbacPrincipalEvidence,
    MonitoringEffectiveRbacRoleDefinition,
    MonitoringEvidenceAttestation,
    MonitoringEvidenceBundle,
    MonitoringEvidenceHandoff,
    PlatformHealthObservation,
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
    compute_monitoring_acquisition_authority_scope,
)
from athena_context.monitoring_collection import (
    CommittedMonitoringCollection,
    MonitoringCollectionError,
    MonitoringCollectionTransaction,
    PreparedMonitoringCollection,
    build_collected_correlation_request,
)

_IDENTITY_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/"
    r"providers/microsoft\.managedidentity/userassignedidentities/[a-z0-9-_]{1,128}$"
)
_STORAGE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/providers/"
    r"microsoft\.storage/storageaccounts/[a-z0-9]{3,24}$"
)
_REGISTRY_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/providers/"
    r"microsoft\.containerregistry/registries/[a-z0-9]{5,50}$"
)
_KEY_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/providers/"
    r"microsoft\.keyvault/vaults/[a-z0-9-]{3,24}/keys/[a-z0-9-]{1,127}$"
)
_ROLE_DEFINITION_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/providers/microsoft\.authorization/"
    r"roledefinitions/[0-9a-f-]{36}$"
)
_GUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_MAX_CONFIGURATION_BYTES = 512 * 1024
_MAX_PERSISTENCE_RECONCILIATION_PASSES = 2
_RESOURCE_LOG_READER_ROLE_DEFINITION_GUID = "f33a4363-5d9a-5d50-9871-c08582234978"
_RESOURCE_HEALTH_ROLE_DEFINITION_GUID = "0790d6f2-9553-5b63-84ac-56596b7e4072"
_RESOURCE_LOG_ALLOWED_OPERATIONS = (
    "Microsoft.Insights/Logs/Heartbeat/Read",
    "Microsoft.Insights/Logs/Perf/Read",
    "Microsoft.Insights/Logs/InsightsMetrics/Read",
    "Microsoft.Insights/Logs/Syslog/Read",
    "Microsoft.Insights/Logs/VMConnection/Read",
)
_RESOURCE_HEALTH_ALLOWED_OPERATIONS = ("Microsoft.ResourceGraph/resources/read",)
_BLOCKED_PR99_CONTRACT_SCHEMA_VERSION = "athena.wc028MonitoringCollectorContract.v8"
_ACR_PULL_ROLE_DEFINITION_GUID = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
_ACR_PULL_ROLE_NAME = "AcrPull"
_ACR_PULL_ACTION = "Microsoft.ContainerRegistry/registries/pull/read"
_MONITORING_INTENT_KEY_READER_ROLE_NAME = "Athena WC028 Monitoring Intent Key Reader"
_MONITORING_INTENT_KEY_READ_DATA_ACTION = "Microsoft.KeyVault/vaults/keys/read"
_ZERO_DIGEST = f"sha256:{'0' * 64}"
_NIL_GUID = "00000000-0000-0000-0000-000000000000"
_ZERO_EXECUTION_ID = f"wc028-execution-{'0' * 32}"
_ARM_TEMPLATE_GUID_NAMESPACE = UUID("11fb06fb-712d-4ddd-98c7-e71bbd588830")
_EXTERNAL_AZURE_FAILURES = (AzureError, ServiceBusError, OSError, TimeoutError)


def _configuration_tuple(value: object) -> tuple[object, ...]:
    return tuple(value) if isinstance(value, list | tuple) else ()


def _configuration_resource_ids(value: object) -> tuple[str, ...]:
    return tuple(
        str(item).casefold().rstrip("/")
        for item in _configuration_tuple(value)
        if isinstance(item, str)
    )


def _canonical_resource_id(value: str) -> str:
    return value.casefold().rstrip("/")


def _require_nonzero_guid(value: str, *, label: str) -> str:
    normalized = value.casefold()
    if _GUID_PATTERN.fullmatch(normalized) is None or normalized == _NIL_GUID:
        raise ValueError(f"{label} must be one non-nil GUID")
    return normalized


def _require_nonzero_digest(value: str, *, label: str) -> str:
    if re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None or value == _ZERO_DIGEST:
        raise ValueError(f"{label} must be one non-zero SHA-256 digest")
    return value


def _contains_forbidden_startup_sentinel(value: object) -> bool:
    if isinstance(value, str):
        return value.casefold() in {_NIL_GUID, _ZERO_DIGEST, _ZERO_EXECUTION_ID}
    if isinstance(value, dict):
        return any(_contains_forbidden_startup_sentinel(item) for item in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_forbidden_startup_sentinel(item) for item in value)
    return False


def _subscription_id_from_resource_id(value: str) -> str:
    segments = _canonical_resource_id(value).strip("/").split("/")
    if (
        len(segments) < 2
        or segments[0] != "subscriptions"
        or _GUID_PATTERN.fullmatch(segments[1]) is None
        or segments[1] == _NIL_GUID
    ):
        raise ValueError("runtime resource ID must identify one Azure subscription")
    return segments[1]


def _resource_scope_ancestry(value: str) -> tuple[str, ...]:
    normalized = _canonical_resource_id(value)
    segments = normalized.strip("/").split("/")
    _subscription_id_from_resource_id(normalized)
    subscription_scope = f"/subscriptions/{segments[1]}"
    scopes = {subscription_scope}
    index = 2
    if index < len(segments) and segments[index] == "resourcegroups":
        if index + 1 >= len(segments) or not segments[index + 1]:
            raise ValueError("runtime resource ID has an invalid resource-group scope")
        index += 2
        scopes.add("/" + "/".join(segments[:index]))
    if index == len(segments):
        return tuple(sorted(scopes))
    while index < len(segments):
        if segments[index] != "providers" or index + 1 >= len(segments) or not segments[index + 1]:
            raise ValueError("runtime resource ID has an invalid provider scope")
        index += 2
        resource_count = 0
        while index < len(segments) and segments[index] != "providers":
            if index + 1 >= len(segments) or not segments[index] or not segments[index + 1]:
                raise ValueError("runtime resource ID has an incomplete nested resource scope")
            index += 2
            resource_count += 1
            scopes.add("/" + "/".join(segments[:index]))
        if resource_count == 0:
            raise ValueError("runtime resource ID provider has no resource scope")
    if normalized not in scopes:
        raise ValueError("runtime resource ID ancestry did not reach the exact target")
    return tuple(sorted(scopes))


def _rbac_scope_applies(
    assignment_scope: str,
    target_scope: str,
    *,
    management_group_ancestry: tuple[str, ...],
    do_not_apply_to_child_scopes: bool = False,
) -> bool:
    assignment = _canonical_resource_id(assignment_scope)
    target = _canonical_resource_id(target_scope)
    if assignment == target:
        return True
    if do_not_apply_to_child_scopes:
        return False
    if assignment in management_group_ancestry:
        return True
    return target.startswith(f"{assignment}/")


def _rbac_action_matches(
    action: str,
    *,
    actions: tuple[str, ...],
    not_actions: tuple[str, ...],
) -> bool:
    normalized = action.casefold()
    return any(fnmatchcase(normalized, pattern) for pattern in actions) and not any(
        fnmatchcase(normalized, pattern) for pattern in not_actions
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
        _require_nonzero_digest(
            self.public_key_fingerprint,
            label="trusted public-key fingerprint",
        )
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


def _monitoring_evidence_storage_readiness_preimage(
    *,
    storage_account_resource_id: str,
    blob_service_resource_id: str,
    container_resource_id: str,
    immutability_policy_resource_id: str,
    container_public_access: str,
    immutability_policy_state: str,
    immutability_retention_days: int,
) -> str:
    return "|".join(
        (
            "athena.wc028MonitoringEvidenceStorageReadiness.v1",
            _canonical_resource_id(storage_account_resource_id),
            _canonical_resource_id(blob_service_resource_id),
            _canonical_resource_id(container_resource_id),
            _canonical_resource_id(immutability_policy_resource_id),
            "true",
            container_public_access,
            immutability_policy_state,
            str(immutability_retention_days),
            "false",
            "false",
        )
    )


def _arm_template_guid(*values: str) -> str:
    if not values or any(not value for value in values):
        raise ValueError("ARM guid inputs must be non-empty")
    return str(uuid5(_ARM_TEMPLATE_GUID_NAMESPACE, "-".join(values)))


class MonitoringEvidenceStorageReadiness(_StrictRuntimeModel):
    """Reviewed WC-024 Blob versioning and container immutability readback."""

    schema_version: Literal["athena.wc028MonitoringEvidenceStorageReadiness.v1"] = Field(
        alias="schemaVersion"
    )
    storage_account_resource_id: str = Field(alias="storageAccountResourceId")
    blob_service_resource_id: str = Field(alias="blobServiceResourceId")
    container_resource_id: str = Field(alias="containerResourceId")
    immutability_policy_resource_id: str = Field(alias="immutabilityPolicyResourceId")
    versioning_enabled: Literal[True] = Field(alias="versioningEnabled")
    container_public_access: Literal["None"] = Field(alias="containerPublicAccess")
    immutability_policy_state: Literal["Locked", "Unlocked"] = Field(
        alias="immutabilityPolicyState"
    )
    immutability_retention_days: int = Field(
        alias="immutabilityRetentionDays",
        ge=1,
        le=365000,
    )
    allow_protected_append_writes: Literal[False] = Field(alias="allowProtectedAppendWrites")
    allow_protected_append_writes_all: Literal[False] = Field(alias="allowProtectedAppendWritesAll")
    readback_binding_id: str = Field(
        alias="readbackBindingId",
        pattern=_GUID_PATTERN.pattern,
    )
    readiness_digest: str = Field(
        alias="readinessDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @field_validator(
        "storage_account_resource_id",
        "blob_service_resource_id",
        "container_resource_id",
        "immutability_policy_resource_id",
    )
    @classmethod
    def normalize_storage_resource_id(cls, value: str) -> str:
        normalized = _canonical_resource_id(value)
        _subscription_id_from_resource_id(normalized)
        return normalized

    @field_validator("readiness_digest")
    @classmethod
    def validate_readiness_digest(cls, value: str) -> str:
        return _require_nonzero_digest(
            value,
            label="monitoring evidence storage readiness digest",
        )

    @field_validator("readback_binding_id")
    @classmethod
    def validate_readback_binding_id(cls, value: str) -> str:
        return _require_nonzero_guid(
            value,
            label="monitoring evidence storage readback binding",
        )

    @model_validator(mode="after")
    def validate_readiness(self) -> MonitoringEvidenceStorageReadiness:
        expected_blob_service_id = f"{self.storage_account_resource_id}/blobservices/default"
        expected_container_id = f"{expected_blob_service_id}/containers/monitoring-evidence"
        expected_policy_id = f"{expected_container_id}/immutabilitypolicies/default"
        if (
            _STORAGE_ID_PATTERN.fullmatch(self.storage_account_resource_id) is None
            or self.blob_service_resource_id != expected_blob_service_id
            or self.container_resource_id != expected_container_id
            or self.immutability_policy_resource_id != expected_policy_id
        ):
            raise ValueError("storage readiness does not bind the exact WC-024 evidence resources")
        readiness_preimage = _monitoring_evidence_storage_readiness_preimage(
            storage_account_resource_id=self.storage_account_resource_id,
            blob_service_resource_id=self.blob_service_resource_id,
            container_resource_id=self.container_resource_id,
            immutability_policy_resource_id=self.immutability_policy_resource_id,
            container_public_access=self.container_public_access,
            immutability_policy_state=self.immutability_policy_state,
            immutability_retention_days=self.immutability_retention_days,
        )
        if self.readback_binding_id != _arm_template_guid(readiness_preimage):
            raise ValueError("readbackBindingId does not bind live WC-024 storage protection")
        expected_digest = sha256_hex(readiness_preimage.encode("utf-8"))
        if self.readiness_digest != expected_digest:
            raise ValueError("readinessDigest does not bind WC-024 storage protection readback")
        return self


class MonitoringRuntimeSupportEffectiveRbacInventory(_StrictRuntimeModel):
    """Hierarchy-complete effective RBAC evidence for the runtime-support UAMI."""

    schema_version: Literal["athena.wc028RuntimeSupportEffectiveRbacInventory.v1"] = Field(
        alias="schemaVersion"
    )
    collection_run_id: str = Field(
        alias="collectionRunId",
        pattern=r"^runtime-support-rbac-[a-f0-9]{32}$",
    )
    tenant_id: str = Field(alias="tenantId", pattern=_GUID_PATTERN.pattern)
    subscription_id: str = Field(alias="subscriptionId", pattern=_GUID_PATTERN.pattern)
    support_identity_resource_id: str = Field(alias="supportIdentityResourceId")
    support_client_id: str = Field(alias="supportClientId", pattern=_GUID_PATTERN.pattern)
    support_principal_id: str = Field(alias="supportPrincipalId", pattern=_GUID_PATTERN.pattern)
    attestor_identity_resource_id: str = Field(alias="attestorIdentityResourceId")
    attestor_client_id: str = Field(alias="attestorClientId", pattern=_GUID_PATTERN.pattern)
    attestor_principal_id: str = Field(alias="attestorPrincipalId", pattern=_GUID_PATTERN.pattern)
    attestor_tenant_id: str = Field(alias="attestorTenantId", pattern=_GUID_PATTERN.pattern)
    collected_at: datetime = Field(alias="collectedAt")
    expires_at: datetime = Field(alias="expiresAt")
    management_group_ancestry: tuple[str, ...] = Field(
        alias="managementGroupAncestry",
        min_length=1,
        max_length=32,
    )
    ancestor_scope_collection_complete: Literal[True] = Field(
        alias="ancestorScopeCollectionComplete"
    )
    subscription_descendant_collection_complete: Literal[True] = Field(
        alias="subscriptionDescendantCollectionComplete"
    )
    group_membership_collection_complete: Literal[True] = Field(
        alias="groupMembershipCollectionComplete"
    )
    role_definition_collection_complete: Literal[True] = Field(
        alias="roleDefinitionCollectionComplete"
    )
    deny_assignment_collection_complete: Literal[True] = Field(
        alias="denyAssignmentCollectionComplete"
    )
    pim_schedule_instance_collection_complete: Literal[True] = Field(
        alias="pimScheduleInstanceCollectionComplete"
    )
    support_security_group_ids: tuple[str, ...] = Field(
        default=(),
        alias="supportSecurityGroupIds",
        max_length=256,
    )
    support_grants: tuple[MonitoringEffectiveRbacGrant, ...] = Field(
        alias="supportGrants",
        min_length=2,
        max_length=2,
    )
    support_principal_evidence: MonitoringEffectiveRbacPrincipalEvidence = Field(
        alias="supportPrincipalEvidence"
    )
    role_definitions: tuple[MonitoringEffectiveRbacRoleDefinition, ...] = Field(
        alias="roleDefinitions",
        min_length=2,
        max_length=2,
    )
    deny_assignments: tuple[MonitoringEffectiveRbacDenyAssignment, ...] = Field(
        alias="denyAssignments",
        max_length=256,
    )
    active_pim_schedule_instances: tuple[MonitoringEffectiveRbacPimScheduleInstance, ...] = Field(
        alias="activePimScheduleInstances",
        max_length=256,
    )
    role_definition_raw_page_digests: tuple[str, ...] = Field(
        alias="roleDefinitionRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    deny_assignment_raw_page_digests: tuple[str, ...] = Field(
        alias="denyAssignmentRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    pim_schedule_instance_raw_page_digests: tuple[str, ...] = Field(
        alias="pimScheduleInstanceRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    first_raw_snapshot_digest: str = Field(
        alias="firstRawSnapshotDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    second_raw_snapshot_digest: str = Field(
        alias="secondRawSnapshotDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    repeated_read_stable: Literal[True] = Field(alias="repeatedReadStable")
    assignment_count: int = Field(alias="assignmentCount", ge=0, le=1024)
    source_reference: VersionPinnedBlobReference = Field(alias="sourceReference")
    source_manifest_digest: str = Field(
        alias="sourceManifestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    inventory_digest: str = Field(
        alias="inventoryDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @field_validator(
        "tenant_id",
        "subscription_id",
        "support_client_id",
        "support_principal_id",
        "attestor_client_id",
        "attestor_principal_id",
        "attestor_tenant_id",
    )
    @classmethod
    def normalize_guid(cls, value: str) -> str:
        return _require_nonzero_guid(
            value,
            label="runtime-support RBAC identity field",
        )

    @field_validator("support_identity_resource_id", "attestor_identity_resource_id")
    @classmethod
    def normalize_identity_resource_id(cls, value: str) -> str:
        normalized = _canonical_resource_id(value)
        if _IDENTITY_PATTERN.fullmatch(normalized) is None:
            raise ValueError("runtime-support RBAC identity must be one user-assigned identity")
        return normalized

    @field_validator("collected_at", "expires_at")
    @classmethod
    def validate_evidence_time(cls, value: datetime) -> datetime:
        if value.utcoffset() != UTC.utcoffset(value) or value.microsecond % 1000:
            raise ValueError("runtime-support RBAC times must use millisecond UTC")
        return value

    @field_validator("management_group_ancestry")
    @classmethod
    def normalize_management_group_ancestry(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(_canonical_resource_id(item) for item in values)
        if (
            normalized != tuple(sorted(normalized))
            or len(normalized) != len(set(normalized))
            or any(
                not item.startswith("/providers/microsoft.management/managementgroups/")
                for item in normalized
            )
        ):
            raise ValueError(
                "runtime-support management-group ancestry must be sorted and complete"
            )
        return normalized

    @field_validator("support_security_group_ids")
    @classmethod
    def normalize_group_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(item.casefold() for item in values)
        if (
            normalized != tuple(sorted(normalized))
            or len(normalized) != len(set(normalized))
            or any(
                _GUID_PATTERN.fullmatch(item) is None or item == _NIL_GUID for item in normalized
            )
        ):
            raise ValueError("runtime-support security-group IDs must be sorted UUIDs")
        return normalized

    @field_validator("support_grants")
    @classmethod
    def validate_grant_order(
        cls,
        values: tuple[MonitoringEffectiveRbacGrant, ...],
    ) -> tuple[MonitoringEffectiveRbacGrant, ...]:
        digests = tuple(item.grant_digest for item in values)
        if digests != tuple(sorted(digests)) or len(digests) != len(set(digests)):
            raise ValueError("runtime-support grants must be sorted and unique")
        return values

    @field_validator("role_definitions")
    @classmethod
    def validate_role_definition_order(
        cls,
        values: tuple[MonitoringEffectiveRbacRoleDefinition, ...],
    ) -> tuple[MonitoringEffectiveRbacRoleDefinition, ...]:
        identifiers = tuple(item.role_definition_id for item in values)
        if identifiers != tuple(sorted(identifiers)) or len(identifiers) != len(set(identifiers)):
            raise ValueError("runtime-support role definitions must be sorted and unique")
        return values

    @field_validator("deny_assignments")
    @classmethod
    def validate_deny_assignment_order(
        cls,
        values: tuple[MonitoringEffectiveRbacDenyAssignment, ...],
    ) -> tuple[MonitoringEffectiveRbacDenyAssignment, ...]:
        identifiers = tuple(item.deny_assignment_id for item in values)
        if identifiers != tuple(sorted(identifiers)) or len(identifiers) != len(set(identifiers)):
            raise ValueError("runtime-support deny assignments must be sorted and unique")
        return values

    @field_validator("active_pim_schedule_instances")
    @classmethod
    def validate_pim_order(
        cls,
        values: tuple[MonitoringEffectiveRbacPimScheduleInstance, ...],
    ) -> tuple[MonitoringEffectiveRbacPimScheduleInstance, ...]:
        identifiers = tuple(item.schedule_instance_id for item in values)
        if identifiers != tuple(sorted(identifiers)) or len(identifiers) != len(set(identifiers)):
            raise ValueError("runtime-support PIM instances must be sorted and unique")
        return values

    @field_validator(
        "role_definition_raw_page_digests",
        "deny_assignment_raw_page_digests",
        "pim_schedule_instance_raw_page_digests",
    )
    @classmethod
    def validate_raw_page_digests(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        if (
            values != tuple(sorted(values))
            or len(values) != len(set(values))
            or any(
                re.fullmatch(r"sha256:[a-f0-9]{64}", item) is None or item == _ZERO_DIGEST
                for item in values
            )
        ):
            raise ValueError("runtime-support raw page digests must be sorted and unique")
        return values

    @model_validator(mode="after")
    def validate_inventory(self) -> MonitoringRuntimeSupportEffectiveRbacInventory:
        principal_evidence = self.support_principal_evidence
        if self.collection_run_id == f"runtime-support-rbac-{'0' * 32}":
            raise ValueError("runtime-support RBAC collection run ID must be non-zero")
        if (
            len(
                {
                    self.support_client_id,
                    self.support_principal_id,
                    self.attestor_client_id,
                    self.attestor_principal_id,
                }
            )
            != 4
        ):
            raise ValueError(
                "runtime-support and attestor client/principal identities must be distinct"
            )
        nested_guid_values = (
            *(
                value
                for item in self.support_grants
                for value in (
                    item.assigned_principal_id,
                    item.effective_principal_id,
                    item.role_definition_id.rsplit("/", maxsplit=1)[-1],
                )
            ),
            *(
                value
                for item in self.role_definitions
                for value in (item.role_definition_id.rsplit("/", maxsplit=1)[-1],)
            ),
            *(
                value
                for item in self.deny_assignments
                for value in (
                    item.deny_assignment_id.rsplit("/", maxsplit=1)[-1],
                    *item.principal_ids,
                    *item.excluded_principal_ids,
                )
            ),
            *(
                value
                for item in self.active_pim_schedule_instances
                for value in (
                    item.schedule_instance_id.rsplit("/", maxsplit=1)[-1],
                    item.principal_id,
                    item.role_definition_id.rsplit("/", maxsplit=1)[-1],
                )
            ),
        )
        if any(value.casefold() == _NIL_GUID for value in nested_guid_values):
            raise ValueError("runtime-support RBAC evidence contains a nil GUID")
        digest_values = (
            self.first_raw_snapshot_digest,
            self.second_raw_snapshot_digest,
            self.source_manifest_digest,
            self.inventory_digest,
            self.source_reference.content_digest,
            principal_evidence.evidence_digest,
            *principal_evidence.first_read_target_digests,
            *principal_evidence.second_read_target_digests,
            *(principal_evidence.role_assignment_raw_page_digests or ()),
            *(principal_evidence.transitive_group_raw_page_digests or ()),
            *(principal_evidence.first_role_assignment_raw_page_digests or ()),
            *(principal_evidence.second_role_assignment_raw_page_digests or ()),
            *(principal_evidence.first_transitive_group_raw_page_digests or ()),
            *(principal_evidence.second_transitive_group_raw_page_digests or ()),
            *self.role_definition_raw_page_digests,
            *self.deny_assignment_raw_page_digests,
            *self.pim_schedule_instance_raw_page_digests,
            *(item.grant_digest for item in self.support_grants),
            *(
                digest
                for item in self.role_definitions
                for digest in (item.raw_definition_digest, item.definition_digest)
            ),
            *(
                digest
                for item in self.deny_assignments
                for digest in (item.raw_assignment_digest, item.deny_assignment_digest)
            ),
            *(
                digest
                for item in self.active_pim_schedule_instances
                for digest in (item.raw_instance_digest, item.instance_digest)
            ),
        )
        if any(value == _ZERO_DIGEST for value in digest_values):
            raise ValueError("runtime-support RBAC evidence digests must be non-zero")
        raw_snapshot_payload = {
            "supportPrincipalEvidenceDigest": principal_evidence.evidence_digest,
            "roleDefinitionRawPageDigests": list(self.role_definition_raw_page_digests),
            "denyAssignmentRawPageDigests": list(self.deny_assignment_raw_page_digests),
            "pimScheduleInstanceRawPageDigests": list(self.pim_schedule_instance_raw_page_digests),
            "roleDefinitionRawDigests": [
                item.raw_definition_digest for item in self.role_definitions
            ],
            "denyAssignmentRawDigests": [
                item.raw_assignment_digest for item in self.deny_assignments
            ],
            "pimScheduleInstanceRawDigests": [
                item.raw_instance_digest for item in self.active_pim_schedule_instances
            ],
        }
        expected_raw_snapshot_digest = compute_artifact_digest(raw_snapshot_payload)
        if (
            self.tenant_id != self.attestor_tenant_id
            or self.support_identity_resource_id == self.attestor_identity_resource_id
            or self.support_client_id == self.attestor_client_id
            or self.support_principal_id == self.attestor_principal_id
            or _subscription_id_from_resource_id(self.support_identity_resource_id)
            != self.subscription_id
            or _subscription_id_from_resource_id(self.attestor_identity_resource_id)
            != self.subscription_id
            or not self.collected_at < self.expires_at
            or (self.expires_at - self.collected_at).total_seconds() > 900
            or self.assignment_count
            != sum(len(item.assignment_scope_ids) for item in self.support_grants)
            or principal_evidence.principal_id != self.support_principal_id
            or principal_evidence.transitive_group_ids != self.support_security_group_ids
            or self.first_raw_snapshot_digest != expected_raw_snapshot_digest
            or self.second_raw_snapshot_digest != expected_raw_snapshot_digest
            or self.source_reference.name
            != (
                f"wc028-runtime-support-rbac/{self.collection_run_id}/effective-rbac-inventory.json"
            )
            or self.source_reference.content_digest != self.source_manifest_digest
        ):
            raise ValueError(
                "runtime-support effective RBAC identity, freshness, or raw evidence is invalid"
            )
        expected_inventory_digest = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
                exclude={"inventory_digest"},
            )
        )
        if self.inventory_digest != expected_inventory_digest:
            raise ValueError(
                "inventoryDigest does not bind runtime-support effective RBAC evidence"
            )
        return self


class Wc028MonitoringAcquisitionJobConfiguration(_StrictRuntimeModel):
    schema_version: Literal["athena.wc028MonitoringAcquisitionJobConfiguration.v4"] = Field(
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
    registry_resource_id: str = Field(alias="registryResourceId")
    runtime_support_acr_pull_role_definition_id: str = Field(
        alias="runtimeSupportAcrPullRoleDefinitionId"
    )
    monitoring_intent_signing_key_resource_id: str = Field(
        alias="monitoringIntentSigningKeyResourceId"
    )
    runtime_support_monitoring_intent_key_reader_role_definition_id: str = Field(
        alias="runtimeSupportMonitoringIntentKeyReaderRoleDefinitionId"
    )
    runtime_support_effective_rbac_inventory: MonitoringRuntimeSupportEffectiveRbacInventory = (
        Field(alias="runtimeSupportEffectiveRbacInventory")
    )
    source_storage_account_resource_id: str = Field(alias="sourceStorageAccountResourceId")
    evidence_storage_account_resource_id: str = Field(alias="evidenceStorageAccountResourceId")
    evidence_blob_endpoint: str = Field(alias="evidenceBlobEndpoint")
    evidence_container_name: Literal["monitoring-evidence"] = Field(alias="evidenceContainerName")
    monitoring_evidence_storage_readiness: MonitoringEvidenceStorageReadiness = Field(
        alias="monitoringEvidenceStorageReadiness"
    )
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
        "managed_identity_client_id",
        "runtime_support_identity_client_id",
        "runtime_support_identity_principal_id",
    )
    @classmethod
    def validate_nonzero_identity_guid(cls, value: str) -> str:
        return _require_nonzero_guid(value, label="runtime identity")

    @field_validator(
        "expected_active_context_authority_digest",
        "expected_acquisition_authority_digest",
        "persistence_replay_key",
    )
    @classmethod
    def validate_nonzero_runtime_digest(cls, value: str) -> str:
        return _require_nonzero_digest(value, label="runtime authority or replay digest")

    @field_validator("execution_id")
    @classmethod
    def validate_execution_id(cls, value: str) -> str:
        if value == _ZERO_EXECUTION_ID:
            raise ValueError("executionId must be non-zero")
        return value

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

    @field_validator("registry_resource_id")
    @classmethod
    def validate_registry_resource_id(cls, value: str) -> str:
        normalized = _canonical_resource_id(value)
        if _REGISTRY_ID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("runtime registry resource ID is invalid")
        return normalized

    @field_validator("monitoring_intent_signing_key_resource_id")
    @classmethod
    def validate_key_resource_id(cls, value: str) -> str:
        normalized = _canonical_resource_id(value)
        if _KEY_RESOURCE_ID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("monitoring-intent key resource ID is invalid")
        return normalized

    @field_validator(
        "runtime_support_acr_pull_role_definition_id",
        "runtime_support_monitoring_intent_key_reader_role_definition_id",
    )
    @classmethod
    def validate_role_definition_id(cls, value: str) -> str:
        normalized = _canonical_resource_id(value)
        if _ROLE_DEFINITION_ID_PATTERN.fullmatch(normalized) is None or normalized.endswith(
            f"/{_NIL_GUID}"
        ):
            raise ValueError("runtime-support role definition ID is invalid")
        return normalized

    @field_validator("legacy_collector_rbac_cleanup_digest")
    @classmethod
    def reject_empty_cleanup_evidence(cls, value: str) -> str:
        return _require_nonzero_digest(
            value,
            label="legacyCollectorRbacCleanupDigest cleanup evidence",
        )

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
        if any(
            _contains_forbidden_startup_sentinel(payload)
            for payload in (
                self.monitoring_intent,
                self.monitoring_intent_reference,
                self.monitoring_intent_attestation,
                self.context_binding,
                self.acquisition_authority,
                self.monitoring_collector_contract,
                self.approved_change_scope,
            )
        ):
            raise ValueError(
                "WC-028 startup models contain a nil identity or zero evidence sentinel"
            )
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
        subscription_ids = {
            _subscription_id_from_resource_id(self.collector_identity_resource_id),
            _subscription_id_from_resource_id(self.athena_context_identity_resource_id),
            _subscription_id_from_resource_id(self.runtime_support_identity_resource_id),
            _subscription_id_from_resource_id(self.registry_resource_id),
            _subscription_id_from_resource_id(self.monitoring_intent_signing_key_resource_id),
            _subscription_id_from_resource_id(self.source_storage_account_resource_id),
            _subscription_id_from_resource_id(self.evidence_storage_account_resource_id),
        }
        if len(subscription_ids) != 1:
            raise ValueError("WC-028 runtime resources must remain in one reviewed subscription")
        subscription_id = next(iter(subscription_ids))
        expected_acr_pull_role_definition_id = (
            f"/subscriptions/{subscription_id}/providers/microsoft.authorization/"
            f"roledefinitions/{_ACR_PULL_ROLE_DEFINITION_GUID}"
        )
        if (
            self.runtime_support_acr_pull_role_definition_id != expected_acr_pull_role_definition_id
            or self.runtime_support_acr_pull_role_definition_id
            == self.runtime_support_monitoring_intent_key_reader_role_definition_id
        ):
            raise ValueError("runtime-support role IDs do not bind exact ACR and key-read roles")
        key_url = urlsplit(self.monitoring_intent_trusted_key.key_vault_key_id)
        key_path_segments = key_url.path.strip("/").split("/")
        key_vault_name = (
            key_url.hostname.removesuffix(".vault.azure.net")
            if key_url.hostname is not None
            else ""
        )
        expected_key_suffix = (
            "/providers/microsoft.keyvault/"
            f"vaults/{key_vault_name.casefold()}/keys/"
            f"{key_path_segments[1].casefold() if len(key_path_segments) > 1 else ''}"
        )
        if (
            len(key_path_segments) != 3
            or key_path_segments[0] != "keys"
            or not self.monitoring_intent_signing_key_resource_id.endswith(expected_key_suffix)
        ):
            raise ValueError("monitoring-intent key URI does not match its reviewed ARM resource")
        expected_storage_account_name = self.evidence_storage_account_resource_id.rsplit(
            "/",
            maxsplit=1,
        )[-1]
        if (
            urlsplit(self.evidence_blob_endpoint).hostname
            != f"{expected_storage_account_name}.blob.core.windows.net"
        ):
            raise ValueError("evidence Blob endpoint does not match the reviewed storage account")
        expected_evidence_container_id = (
            f"{self.evidence_storage_account_resource_id}/blobservices/default/"
            f"containers/{self.evidence_container_name}"
        )
        if (
            self.monitoring_evidence_storage_readiness.storage_account_resource_id
            != self.evidence_storage_account_resource_id
            or self.monitoring_evidence_storage_readiness.container_resource_id
            != expected_evidence_container_id
        ):
            raise ValueError(
                "storage readiness does not match the configured monitoring evidence boundary"
            )
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
        for value, label in (
            (self.monitoring_intent.get("intentDigest"), "monitoring intent digest"),
            (
                self.monitoring_intent_reference.get("referenceDigest"),
                "monitoring intent reference digest",
            ),
            (self.context_binding.get("bindingDigest"), "context binding digest"),
            (
                effective_rbac_inventory.get("inventoryDigest"),
                "collector effective RBAC inventory digest",
            ),
            (
                effective_rbac_inventory.get("sourceManifestDigest"),
                "collector effective RBAC source manifest digest",
            ),
        ):
            if not isinstance(value, str):
                raise ValueError(f"{label} is required")
            _require_nonzero_digest(value, label=label)
        collector_principal_id = _require_nonzero_guid(
            collector_principal_id,
            label="collector principal",
        )
        collector_tenant_id = _require_nonzero_guid(
            collector_tenant_id,
            label="collector tenant",
        )
        expected_identity_proof_audience = (
            f"api://{collector_tenant_id}/athena-monitoring-identity-proof"
        )
        context_principal_id = _require_nonzero_guid(
            context_principal_id,
            label="Athena context principal",
        )
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
                expected_identity_proof_audience,
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
                expected_identity_proof_audience,
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
        monitoring_intent_reference_digest = self.monitoring_intent_reference.get("referenceDigest")
        context_binding_digest = self.context_binding.get("bindingDigest")
        expected_replay_key = compute_artifact_digest(
            {
                "schemaVersion": "athena.wc028MonitoringPersistenceReplay.v3",
                "executionId": self.execution_id,
                "acquisitionAuthorityDigest": self.expected_acquisition_authority_digest,
                "monitoringIntentDigest": monitoring_intent_digest,
                "monitoringIntentReferenceDigest": (monitoring_intent_reference_digest),
                "contextBindingDigest": context_binding_digest,
                "incidentRevision": self.incident_revision,
                "legacyCollectorRbacCleanupDigest": (self.legacy_collector_rbac_cleanup_digest),
                "monitoringEvidenceStorageReadinessDigest": (
                    self.monitoring_evidence_storage_readiness.readiness_digest
                ),
                "trustDelaySeconds": self.trust_delay_seconds,
                "requestLifetimeSeconds": self.request_lifetime_seconds,
            }
        )
        if (
            not isinstance(monitoring_intent_digest, str)
            or not isinstance(monitoring_intent_reference_digest, str)
            or not isinstance(context_binding_digest, str)
            or self.persistence_replay_key != expected_replay_key
        ):
            raise ValueError("persistenceReplayKey does not bind the reviewed execution")
        identity_guids = {
            self.managed_identity_client_id.casefold(),
            collector_principal_id,
            context_principal_id,
            self.runtime_support_identity_client_id.casefold(),
            self.runtime_support_identity_principal_id,
            self.runtime_support_effective_rbac_inventory.attestor_client_id,
            self.runtime_support_effective_rbac_inventory.attestor_principal_id,
        }
        if len(identity_guids) != 7:
            raise ValueError(
                "collector, support, context, and attestor client/principal identities "
                "must be non-nil and pairwise separate"
            )
        _validate_runtime_support_effective_rbac(
            configuration=self,
            as_of=None,
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
                "ATHENA_WC028_DEPLOYED_REGISTRY_RESOURCE_ID",
                self.registry_resource_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_ACR_PULL_ROLE_DEFINITION_ID",
                self.runtime_support_acr_pull_role_definition_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_MONITORING_INTENT_SIGNING_KEY_RESOURCE_ID",
                self.monitoring_intent_signing_key_resource_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_INTENT_KEY_READER_ROLE_DEFINITION_ID",
                self.runtime_support_monitoring_intent_key_reader_role_definition_id,
            ),
            (
                "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_RBAC_INVENTORY_DIGEST",
                self.runtime_support_effective_rbac_inventory.inventory_digest,
            ),
            (
                "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_RBAC_SOURCE_MANIFEST_DIGEST",
                self.runtime_support_effective_rbac_inventory.source_manifest_digest,
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
                "ATHENA_WC028_DEPLOYED_MONITORING_EVIDENCE_STORAGE_READINESS_DIGEST",
                self.monitoring_evidence_storage_readiness.readiness_digest,
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
        supplied_deployment_bindings = tuple(
            environment_name
            for environment_name, _ in deployment_bindings
            if os.environ.get(environment_name) is not None
        )
        if supplied_deployment_bindings and len(supplied_deployment_bindings) != len(
            deployment_bindings
        ):
            raise ValueError(
                "WC-028 deployed runtime bindings must be supplied as one complete set"
            )
        support_client_id = os.environ.get("ATHENA_WC028_RUNTIME_SUPPORT_CLIENT_ID")
        if (
            support_client_id is not None
            and support_client_id.casefold() != self.runtime_support_identity_client_id.casefold()
        ):
            raise ValueError(
                "ATHENA_WC028_RUNTIME_SUPPORT_CLIENT_ID does not match the support identity"
            )
        if supplied_deployment_bindings and support_client_id is None:
            raise ValueError(
                "ATHENA_WC028_RUNTIME_SUPPORT_CLIENT_ID is required with deployed bindings"
            )
        return self


def _validate_runtime_support_effective_rbac(
    *,
    configuration: Wc028MonitoringAcquisitionJobConfiguration,
    as_of: datetime | None,
) -> None:
    inventory = configuration.runtime_support_effective_rbac_inventory
    expected_subscription_id = _subscription_id_from_resource_id(
        configuration.runtime_support_identity_resource_id
    )
    expected_target_scopes = {
        *inventory.management_group_ancestry,
        *_resource_scope_ancestry(configuration.registry_resource_id),
        *_resource_scope_ancestry(configuration.monitoring_intent_signing_key_resource_id),
    }
    collector_principal_id = str(
        configuration.monitoring_collector_contract.get("monitoringReaderPrincipalId", "")
    ).casefold()
    context_principal_id = str(
        configuration.monitoring_collector_contract.get("athenaContextPrincipalId", "")
    ).casefold()
    collector_tenant_id = str(
        configuration.monitoring_collector_contract.get("collectorTenantId", "")
    ).casefold()
    if (
        inventory.subscription_id != expected_subscription_id
        or inventory.tenant_id != collector_tenant_id
        or inventory.support_identity_resource_id
        != configuration.runtime_support_identity_resource_id
        or inventory.support_client_id.casefold()
        != configuration.runtime_support_identity_client_id.casefold()
        or inventory.support_principal_id != configuration.runtime_support_identity_principal_id
        or inventory.attestor_principal_id
        in {
            inventory.support_principal_id,
            collector_principal_id,
            context_principal_id,
            configuration.managed_identity_client_id.casefold(),
            configuration.runtime_support_identity_client_id.casefold(),
        }
        or inventory.attestor_client_id
        in {
            inventory.support_client_id,
            inventory.support_principal_id,
            collector_principal_id,
            context_principal_id,
            configuration.managed_identity_client_id.casefold(),
        }
        or inventory.attestor_identity_resource_id
        in {
            configuration.runtime_support_identity_resource_id,
            configuration.collector_identity_resource_id,
            configuration.athena_context_identity_resource_id,
        }
        or inventory.support_security_group_ids
        or inventory.support_principal_evidence.transitive_group_ids
        or set(inventory.support_principal_evidence.target_scope_ids) != expected_target_scopes
        or inventory.active_pim_schedule_instances
        or inventory.assignment_count != 2
        or inventory.source_manifest_digest == _ZERO_DIGEST
        or inventory.inventory_digest == _ZERO_DIGEST
    ):
        raise ValueError(
            "runtime-support identity lacks hierarchy-complete dedicated effective RBAC evidence"
        )
    if as_of is not None and (
        as_of.utcoffset() != UTC.utcoffset(as_of)
        or as_of.microsecond % 1000
        or inventory.collected_at > as_of
        or inventory.expires_at <= as_of
        or (as_of - inventory.collected_at).total_seconds() > 900
    ):
        raise MonitoringAcquisitionJobError(
            "runtime-support effective RBAC evidence is stale before job execution"
        )
    expected_grants = {
        configuration.runtime_support_acr_pull_role_definition_id: (
            _ACR_PULL_ROLE_NAME,
            configuration.registry_resource_id,
        ),
        configuration.runtime_support_monitoring_intent_key_reader_role_definition_id: (
            _MONITORING_INTENT_KEY_READER_ROLE_NAME,
            configuration.monitoring_intent_signing_key_resource_id,
        ),
    }
    grants_by_role = {item.role_definition_id: item for item in inventory.support_grants}
    if set(grants_by_role) != set(expected_grants):
        raise ValueError("runtime-support identity has arbitrary effective Azure privileges")
    for role_definition_id, (role_name, scope_id) in expected_grants.items():
        grant = grants_by_role[role_definition_id]
        if (
            grant.role_definition_name != role_name
            or grant.assigned_principal_id != inventory.support_principal_id
            or grant.assigned_principal_type != "ServicePrincipal"
            or grant.effective_principal_id != inventory.support_principal_id
            or grant.assignment_scope_ids != (scope_id,)
            or grant.inheritance != "direct"
            or grant.group_derived
            or grant.condition is not None
            or grant.condition_version is not None
        ):
            raise ValueError(
                "runtime-support identity grants are not exact direct governed assignments"
            )
    roles_by_id = {item.role_definition_id: item for item in inventory.role_definitions}
    if set(roles_by_id) != set(expected_grants):
        raise ValueError("runtime-support role-definition evidence is incomplete or arbitrary")
    acr_pull_role = roles_by_id[configuration.runtime_support_acr_pull_role_definition_id]
    if (
        acr_pull_role.role_definition_name != _ACR_PULL_ROLE_NAME
        or acr_pull_role.actions != (_ACR_PULL_ACTION.casefold(),)
        or acr_pull_role.not_actions
        or acr_pull_role.data_actions
        or acr_pull_role.not_data_actions
    ):
        raise ValueError("runtime-support AcrPull role definition is not exact")
    key_reader_role = roles_by_id[
        configuration.runtime_support_monitoring_intent_key_reader_role_definition_id
    ]
    if (
        key_reader_role.role_definition_name != _MONITORING_INTENT_KEY_READER_ROLE_NAME
        or key_reader_role.actions
        or key_reader_role.not_actions
        or key_reader_role.data_actions != (_MONITORING_INTENT_KEY_READ_DATA_ACTION.casefold(),)
        or key_reader_role.not_data_actions
    ):
        raise ValueError("runtime-support monitoring-intent key-read role is not exact")
    effective_principals = {inventory.support_principal_id}
    for deny in inventory.deny_assignments:
        if deny.condition is not None:
            raise ValueError("runtime-support deny conditions are not supported")
        candidate_principals = (
            effective_principals
            if not deny.principal_ids
            else effective_principals.intersection(deny.principal_ids)
        )
        applicable_principals = candidate_principals.difference(deny.excluded_principal_ids)
        if not applicable_principals:
            continue
        denies_acr_pull = _rbac_scope_applies(
            deny.scope_id,
            configuration.registry_resource_id,
            management_group_ancestry=inventory.management_group_ancestry,
            do_not_apply_to_child_scopes=deny.do_not_apply_to_child_scopes,
        ) and _rbac_action_matches(
            _ACR_PULL_ACTION,
            actions=deny.actions,
            not_actions=deny.not_actions,
        )
        denies_key_read = _rbac_scope_applies(
            deny.scope_id,
            configuration.monitoring_intent_signing_key_resource_id,
            management_group_ancestry=inventory.management_group_ancestry,
            do_not_apply_to_child_scopes=deny.do_not_apply_to_child_scopes,
        ) and _rbac_action_matches(
            _MONITORING_INTENT_KEY_READ_DATA_ACTION,
            actions=deny.data_actions,
            not_actions=deny.not_data_actions,
        )
        if denies_acr_pull or denies_key_read:
            raise ValueError("runtime-support deny assignment removes an exact required permission")


def _revalidate_monitoring_evidence_storage_readiness(
    *,
    configuration: Wc028MonitoringAcquisitionJobConfiguration,
    expected_signed_digest: str | None = None,
    verifier: (
        Callable[
            [MonitoringEvidenceStorageReadiness],
            MonitoringEvidenceStorageReadiness,
        ]
        | None
    ) = None,
) -> MonitoringEvidenceStorageReadiness:
    try:
        readiness = MonitoringEvidenceStorageReadiness.model_validate_json(
            configuration.monitoring_evidence_storage_readiness.model_dump_json(by_alias=True)
        )
    except ValueError as exc:
        raise MonitoringAcquisitionJobError(
            "monitoring evidence storage readiness failed runtime revalidation"
        ) from exc
    if (
        readiness.storage_account_resource_id != configuration.evidence_storage_account_resource_id
        or readiness.container_resource_id
        != (
            f"{configuration.evidence_storage_account_resource_id}/"
            f"blobservices/default/containers/{configuration.evidence_container_name}"
        )
        or (
            expected_signed_digest is not None
            and readiness.readiness_digest != expected_signed_digest
        )
    ):
        raise MonitoringAcquisitionJobError(
            "monitoring evidence storage readiness changed before writer access"
        )
    if verifier is None:
        return readiness
    try:
        current = verifier(readiness)
        current = MonitoringEvidenceStorageReadiness.model_validate_json(
            current.model_dump_json(by_alias=True)
        )
    except MonitoringAcquisitionJobError:
        raise
    except (AttributeError, TypeError, ValueError, *_EXTERNAL_AZURE_FAILURES) as exc:
        raise MonitoringAcquisitionJobError(
            "live monitoring evidence storage readiness verification failed closed"
        ) from exc
    if current != readiness:
        raise MonitoringAcquisitionJobError(
            "live monitoring evidence storage protection changed before writer access"
        )
    return current


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
    @property
    def committed(self) -> CommittedMonitoringCollection: ...

    @property
    def correlation_request(self) -> CorrelationRequest: ...


@dataclass(frozen=True, slots=True)
class RecoveredMonitoringAcquisitionJobOutcome:
    """The durable result returned when restart recovery skips reacquisition."""

    committed: CommittedMonitoringCollection
    correlation_request: CorrelationRequest


def _monitoring_recovery_state_preimage(
    recovery_state_payload: dict[str, object],
) -> dict[str, object]:
    return {
        "schemaVersion": "athena.wc028MonitoringPersistenceRecoveryBinding.v1",
        "recoveryState": recovery_state_payload,
    }


class MonitoringPersistenceRecoveryState(_StrictRuntimeModel):
    schema_version: Literal["athena.wc028MonitoringPersistenceRecoveryState.v2"] = Field(
        alias="schemaVersion"
    )
    replay_key: str = Field(alias="replayKey", pattern=r"^sha256:[a-f0-9]{64}$")
    replay_preimage_digest: str = Field(
        alias="replayPreimageDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    execution_id: str = Field(
        alias="executionId",
        pattern=r"^wc028-execution-[a-f0-9]{32}$",
    )
    acquisition_authority_digest: str = Field(
        alias="acquisitionAuthorityDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    legacy_collector_rbac_cleanup_digest: str = Field(
        alias="legacyCollectorRbacCleanupDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    prepared_digest: str = Field(alias="preparedDigest", pattern=r"^sha256:[a-f0-9]{64}$")
    collection_id: str = Field(alias="collectionId", pattern=r"^wc024-[a-f0-9]{12}$")
    incident_revision: int = Field(alias="incidentRevision", ge=1)
    issued_at: datetime = Field(alias="issuedAt")
    trusted_as_of: datetime = Field(alias="trustedAsOf")
    expires_at: datetime = Field(alias="expiresAt")
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
    monitoring_intent_reference: PublishedMonitoringIntentAssetReference = Field(
        alias="monitoringIntentReference"
    )
    monitoring_bundle: MonitoringEvidenceBundle = Field(alias="monitoringBundle")
    incident_resource_id: str = Field(alias="incidentResourceId", min_length=1, max_length=2048)
    previous_health_source_record_id: str = Field(
        alias="previousHealthSourceRecordId",
        min_length=1,
        max_length=2048,
    )
    current_health_source_record_ids: tuple[str, ...] = Field(
        alias="currentHealthSourceRecordIds",
        min_length=1,
        max_length=32,
    )
    previous_health_observation_id: str = Field(
        alias="previousHealthObservationId",
        min_length=1,
        max_length=2048,
    )
    current_health_observation_ids: tuple[str, ...] = Field(
        alias="currentHealthObservationIds",
        min_length=1,
        max_length=32,
    )
    current_health_state: Literal["degraded", "unhealthy", "unavailable"] = Field(
        alias="currentHealthState"
    )
    runtime_support_identity_resource_id: str = Field(alias="runtimeSupportIdentityResourceId")
    runtime_support_identity_client_id: str = Field(
        alias="runtimeSupportIdentityClientId",
        pattern=_GUID_PATTERN.pattern,
    )
    runtime_support_identity_principal_id: str = Field(
        alias="runtimeSupportIdentityPrincipalId",
        pattern=_GUID_PATTERN.pattern,
    )
    runtime_support_attestor_identity_resource_id: str = Field(
        alias="runtimeSupportAttestorIdentityResourceId"
    )
    runtime_support_attestor_client_id: str = Field(
        alias="runtimeSupportAttestorClientId",
        pattern=_GUID_PATTERN.pattern,
    )
    runtime_support_attestor_principal_id: str = Field(
        alias="runtimeSupportAttestorPrincipalId",
        pattern=_GUID_PATTERN.pattern,
    )
    runtime_support_attestor_tenant_id: str = Field(
        alias="runtimeSupportAttestorTenantId",
        pattern=_GUID_PATTERN.pattern,
    )
    runtime_support_effective_rbac_inventory_digest: str = Field(
        alias="runtimeSupportEffectiveRbacInventoryDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    runtime_support_effective_rbac_source_manifest_digest: str = Field(
        alias="runtimeSupportEffectiveRbacSourceManifestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    monitoring_evidence_storage_readiness_digest: str = Field(
        alias="monitoringEvidenceStorageReadinessDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    runtime_support_effective_rbac_collected_at: datetime = Field(
        alias="runtimeSupportEffectiveRbacCollectedAt"
    )
    runtime_support_effective_rbac_expires_at: datetime = Field(
        alias="runtimeSupportEffectiveRbacExpiresAt"
    )
    registry_resource_id: str = Field(alias="registryResourceId")
    runtime_support_acr_pull_role_definition_id: str = Field(
        alias="runtimeSupportAcrPullRoleDefinitionId"
    )
    monitoring_intent_signing_key_resource_id: str = Field(
        alias="monitoringIntentSigningKeyResourceId"
    )
    runtime_support_monitoring_intent_key_reader_role_definition_id: str = Field(
        alias="runtimeSupportMonitoringIntentKeyReaderRoleDefinitionId"
    )
    state_digest: str = Field(alias="stateDigest", pattern=r"^sha256:[a-f0-9]{64}$")
    collector_attestation: MonitoringEvidenceAttestation = Field(alias="collectorAttestation")

    @field_validator(
        "issued_at",
        "trusted_as_of",
        "expires_at",
        "runtime_support_effective_rbac_collected_at",
        "runtime_support_effective_rbac_expires_at",
    )
    @classmethod
    def validate_correlation_time(cls, value: datetime) -> datetime:
        if value.utcoffset() != UTC.utcoffset(value) or value.microsecond % 1000:
            raise ValueError("recovery correlation times must use millisecond UTC")
        return value

    @field_validator(
        "runtime_support_identity_resource_id",
        "runtime_support_attestor_identity_resource_id",
    )
    @classmethod
    def validate_recovery_identity_resource_id(cls, value: str) -> str:
        normalized = _canonical_resource_id(value)
        if _IDENTITY_PATTERN.fullmatch(normalized) is None:
            raise ValueError("recovery identity must be one user-assigned managed identity")
        _subscription_id_from_resource_id(normalized)
        return normalized

    @field_validator(
        "runtime_support_identity_client_id",
        "runtime_support_identity_principal_id",
        "runtime_support_attestor_client_id",
        "runtime_support_attestor_principal_id",
        "runtime_support_attestor_tenant_id",
    )
    @classmethod
    def validate_recovery_identity_guid(cls, value: str) -> str:
        return _require_nonzero_guid(value, label="recovery identity")

    @field_validator("registry_resource_id")
    @classmethod
    def validate_recovery_registry_resource_id(cls, value: str) -> str:
        normalized = _canonical_resource_id(value)
        if _REGISTRY_ID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("recovery registry resource ID is invalid")
        _subscription_id_from_resource_id(normalized)
        return normalized

    @field_validator("monitoring_intent_signing_key_resource_id")
    @classmethod
    def validate_recovery_key_resource_id(cls, value: str) -> str:
        normalized = _canonical_resource_id(value)
        if _KEY_RESOURCE_ID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("recovery monitoring-intent key resource ID is invalid")
        _subscription_id_from_resource_id(normalized)
        return normalized

    @field_validator(
        "runtime_support_acr_pull_role_definition_id",
        "runtime_support_monitoring_intent_key_reader_role_definition_id",
    )
    @classmethod
    def validate_recovery_role_definition_id(cls, value: str) -> str:
        normalized = _canonical_resource_id(value)
        if _ROLE_DEFINITION_ID_PATTERN.fullmatch(normalized) is None or normalized.endswith(
            f"/{_NIL_GUID}"
        ):
            raise ValueError("recovery runtime-support role definition ID is invalid")
        return normalized

    @field_validator(
        "replay_key",
        "replay_preimage_digest",
        "acquisition_authority_digest",
        "legacy_collector_rbac_cleanup_digest",
        "prepared_digest",
        "intent_digest",
        "context_binding_digest",
        "collector_contract_digest",
        "monitoring_bundle_digest",
        "acquisition_receipt_digest",
        "runtime_support_effective_rbac_inventory_digest",
        "runtime_support_effective_rbac_source_manifest_digest",
        "monitoring_evidence_storage_readiness_digest",
        "state_digest",
    )
    @classmethod
    def validate_recovery_digest(cls, value: str) -> str:
        return _require_nonzero_digest(value, label="recovery binding digest")

    @field_validator("execution_id")
    @classmethod
    def validate_recovery_execution_id(cls, value: str) -> str:
        if value == _ZERO_EXECUTION_ID:
            raise ValueError("recovery executionId must be non-zero")
        return value

    @field_validator(
        "current_health_source_record_ids",
        "current_health_observation_ids",
    )
    @classmethod
    def validate_sorted_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(values)) or len(values) != len(set(values)):
            raise ValueError("recovery incident IDs must be sorted and unique")
        return values

    @model_validator(mode="after")
    def validate_state(self) -> MonitoringPersistenceRecoveryState:
        receipt = self.monitoring_bundle.acquisition_receipt
        if receipt is None:
            raise ValueError("recovery state requires a signed acquisition receipt")
        resource_identities = {
            self.runtime_support_identity_resource_id,
            self.runtime_support_attestor_identity_resource_id,
        }
        principal_identities = {
            self.runtime_support_identity_client_id,
            self.runtime_support_identity_principal_id,
            self.runtime_support_attestor_client_id,
            self.runtime_support_attestor_principal_id,
        }
        subscription_ids = {
            _subscription_id_from_resource_id(item)
            for item in (
                *resource_identities,
                self.registry_resource_id,
                self.monitoring_intent_signing_key_resource_id,
            )
        }
        if (
            len(resource_identities) != 2
            or len(principal_identities) != 4
            or len(subscription_ids) != 1
        ):
            raise ValueError(
                "recovery support and attestor identity tuples overlap or cross subscriptions"
            )
        replay_payload = {
            "intentId": self.intent_id,
            "intentDigest": self.intent_digest,
            "contextBindingDigest": self.context_binding_digest,
            "collectorContractDigest": self.collector_contract_digest,
            "monitoringBundleDigest": self.monitoring_bundle_digest,
            "acquisitionReceiptDigest": self.acquisition_receipt_digest,
        }
        if (
            self.collection_id != _monitoring_persistence_collection_id(self.replay_key)
            or self.replay_preimage_digest != self.replay_key
            or self.monitoring_intent_reference.intent_id != self.intent_id
            or self.monitoring_intent_reference.intent_digest != self.intent_digest
            or self.monitoring_bundle.monitoring_contract_digest != self.collector_contract_digest
            or sha256_hex(self.monitoring_bundle.canonical_bytes()) != self.monitoring_bundle_digest
            or receipt.receipt_digest != self.acquisition_receipt_digest
            or receipt.intent_id != self.intent_id
            or receipt.intent_digest != self.intent_digest
            or receipt.context_binding_digest != self.context_binding_digest
            or receipt.collector_contract_digest != self.collector_contract_digest
            or receipt.acquisition_authority_digest != self.acquisition_authority_digest
            or receipt.execution_started_at != self.issued_at
            or not self.runtime_support_effective_rbac_collected_at
            <= receipt.execution_started_at
            <= receipt.execution_completed_at
            < self.runtime_support_effective_rbac_expires_at
            or self.runtime_support_identity_resource_id
            == self.runtime_support_attestor_identity_resource_id
            or len(
                {
                    self.runtime_support_identity_client_id,
                    self.runtime_support_identity_principal_id,
                    self.runtime_support_attestor_client_id,
                    self.runtime_support_attestor_principal_id,
                }
            )
            != 4
            or not self.issued_at <= self.trusted_as_of <= self.expires_at
            or (self.expires_at - self.issued_at).total_seconds() > 900
            or self.prepared_digest != compute_artifact_digest(replay_payload)
        ):
            raise ValueError("recovery state does not bind the exact prepared transaction")
        expected_state_digest = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
                exclude={"state_digest", "collector_attestation"},
            )
        )
        if self.state_digest != expected_state_digest:
            raise ValueError("stateDigest does not bind the persistence recovery state")
        signed_payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"collector_attestation"},
        )
        expected_signed_preimage_digest = compute_artifact_digest(
            _monitoring_recovery_state_preimage(signed_payload)
        )
        if self.collector_attestation.signed_preimage_digest != expected_signed_preimage_digest:
            raise ValueError("collector attestation does not bind the complete recovery state")
        return self

    def canonical_bytes(self) -> bytes:
        return (canonicalize_json(self.model_dump(mode="json", by_alias=True)) + "\n").encode(
            "utf-8"
        )

    def prepared_collection(self) -> PreparedMonitoringCollection:
        return PreparedMonitoringCollection(
            intent_id=self.intent_id,
            intent_digest=self.intent_digest,
            context_binding_digest=self.context_binding_digest,
            monitoring_intent_reference=self.monitoring_intent_reference,
            monitoring_bundle=self.monitoring_bundle,
            change_artifacts=(),
            incident_resource_id=self.incident_resource_id,
            previous_health_source_record_id=self.previous_health_source_record_id,
            current_health_source_record_ids=self.current_health_source_record_ids,
            previous_health_observation_id=self.previous_health_observation_id,
            current_health_observation_ids=self.current_health_observation_ids,
            current_health_state=self.current_health_state,
        )


class MonitoringPersistenceCommitManifest(_StrictRuntimeModel):
    schema_version: Literal["athena.wc028MonitoringPersistenceCommit.v3"] = Field(
        alias="schemaVersion"
    )
    replay_key: str = Field(alias="replayKey", pattern=r"^sha256:[a-f0-9]{64}$")
    execution_id: str = Field(
        alias="executionId",
        pattern=r"^wc028-execution-[a-f0-9]{32}$",
    )
    prepared_digest: str = Field(alias="preparedDigest", pattern=r"^sha256:[a-f0-9]{64}$")
    collection_id: str = Field(alias="collectionId", pattern=r"^wc024-[a-f0-9]{12}$")
    recovery_state: VersionPinnedBlobReference = Field(alias="recoveryState")
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
    correlation_request_id: str = Field(
        alias="correlationRequestId",
        pattern=r"^request-[a-f0-9]{32}$",
    )
    correlation_request_digest: str = Field(
        alias="correlationRequestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    manifest_digest: str = Field(alias="manifestDigest", pattern=r"^sha256:[a-f0-9]{64}$")

    @field_validator(
        "replay_key",
        "prepared_digest",
        "intent_digest",
        "context_binding_digest",
        "collector_contract_digest",
        "monitoring_bundle_digest",
        "acquisition_receipt_digest",
        "correlation_request_digest",
        "manifest_digest",
    )
    @classmethod
    def validate_manifest_digest(cls, value: str) -> str:
        return _require_nonzero_digest(value, label="persistence manifest digest")

    @field_validator("execution_id")
    @classmethod
    def validate_manifest_execution_id(cls, value: str) -> str:
        if value == _ZERO_EXECUTION_ID:
            raise ValueError("persistence manifest executionId must be non-zero")
        return value

    @model_validator(mode="after")
    def validate_manifest(self) -> MonitoringPersistenceCommitManifest:
        if (
            self.collection_id != _monitoring_persistence_collection_id(self.replay_key)
            or self.recovery_state.name
            != (f"wc024-monitoring/commits/{self.replay_key.removeprefix('sha256:')}/recovery.json")
            or self.monitoring_handoff.collection_id != self.collection_id
            or self.monitoring_handoff.collector_contract_digest != self.collector_contract_digest
            or self.monitoring_handoff.evidence.content_digest != self.monitoring_bundle_digest
            or self.monitoring_handoff.acquisition_receipt_digest != self.acquisition_receipt_digest
            or self.recovery_state.content_digest == _ZERO_DIGEST
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
                exclude_none=True,
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


def _monitoring_persistence_blob_names(replay_key: str) -> tuple[str, str, str]:
    collection_id = _monitoring_persistence_collection_id(replay_key)
    prefix = f"wc024-monitoring/commits/{replay_key.removeprefix('sha256:')}"
    return (
        f"{prefix}/manifest.json",
        f"{prefix}/recovery.json",
        f"wc024-monitoring/{collection_id}/evidence.json",
    )


@dataclass(frozen=True, slots=True)
class _MonitoringPersistenceProbe:
    manifest_result: ArtifactReadResult | None
    recovery_state_result: ArtifactReadResult | None
    evidence_result: ArtifactReadResult | None

    @property
    def has_durable_artifacts(self) -> bool:
        return any(
            item is not None
            for item in (
                self.manifest_result,
                self.recovery_state_result,
                self.evidence_result,
            )
        )


def _read_current_if_present(
    reader: CurrentArtifactReaderPort,
    *,
    blob_name: str,
) -> ArtifactReadResult | None:
    try:
        return reader.read_current(ArtifactCurrentReadRequest(blob_name=blob_name))
    except ArtifactNotFoundError:
        return None


def _parse_recovery_state_result(
    result: ArtifactReadResult,
    *,
    expected_blob_name: str,
) -> MonitoringPersistenceRecoveryState:
    try:
        state = MonitoringPersistenceRecoveryState.model_validate_json(result.payload)
    except (AttributeError, UnicodeDecodeError, ValueError) as exc:
        raise MonitoringAcquisitionJobError(
            "recovered monitoring persistence state is invalid"
        ) from exc
    if (
        result.blob_name != expected_blob_name
        or result.payload_sha256 != sha256_hex(result.payload)
        or result.payload != state.canonical_bytes()
    ):
        raise MonitoringAcquisitionJobError(
            "recovered monitoring persistence state failed byte verification"
        )
    return state


def _parse_commit_manifest_result(
    result: ArtifactReadResult,
    *,
    expected_blob_name: str,
) -> MonitoringPersistenceCommitManifest:
    try:
        manifest = MonitoringPersistenceCommitManifest.model_validate_json(result.payload)
    except (AttributeError, UnicodeDecodeError, ValueError) as exc:
        raise MonitoringAcquisitionJobError(
            "recovered monitoring persistence commit manifest is invalid"
        ) from exc
    if (
        result.blob_name != expected_blob_name
        or result.payload_sha256 != sha256_hex(result.payload)
        or result.payload != manifest.canonical_bytes()
    ):
        raise MonitoringAcquisitionJobError(
            "recovered monitoring persistence commit manifest failed byte verification"
        )
    return manifest


def _probe_monitoring_persistence(
    *,
    reader: CurrentArtifactReaderPort,
    replay_key: str,
) -> _MonitoringPersistenceProbe:
    manifest_blob_name, recovery_blob_name, evidence_blob_name = _monitoring_persistence_blob_names(
        replay_key
    )
    manifest_result = _read_current_if_present(
        reader,
        blob_name=manifest_blob_name,
    )
    if manifest_result is not None:
        _parse_commit_manifest_result(
            manifest_result,
            expected_blob_name=manifest_blob_name,
        )
    recovery_state_result = _read_current_if_present(
        reader,
        blob_name=recovery_blob_name,
    )
    if recovery_state_result is not None:
        _parse_recovery_state_result(
            recovery_state_result,
            expected_blob_name=recovery_blob_name,
        )
    evidence_result = _read_current_if_present(
        reader,
        blob_name=evidence_blob_name,
    )
    if evidence_result is not None and recovery_state_result is None:
        for _ in range(_MAX_PERSISTENCE_RECONCILIATION_PASSES):
            refreshed_manifest = _read_current_if_present(
                reader,
                blob_name=manifest_blob_name,
            )
            if refreshed_manifest is not None:
                _parse_commit_manifest_result(
                    refreshed_manifest,
                    expected_blob_name=manifest_blob_name,
                )
                manifest_result = refreshed_manifest
            refreshed_state = _read_current_if_present(
                reader,
                blob_name=recovery_blob_name,
            )
            if refreshed_state is not None:
                _parse_recovery_state_result(
                    refreshed_state,
                    expected_blob_name=recovery_blob_name,
                )
                recovery_state_result = refreshed_state
                break
    return _MonitoringPersistenceProbe(
        manifest_result=manifest_result,
        recovery_state_result=recovery_state_result,
        evidence_result=evidence_result,
    )


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


def _require_pr99_conditioned_blob_contract(
    collector_contract: MonitoringCollectorContract,
) -> None:
    if collector_contract.schema_version == _BLOCKED_PR99_CONTRACT_SCHEMA_VERSION:
        raise MonitoringAcquisitionJobError(
            "WC-028 deployment remains blocked until PR #99 publishes the conditioned "
            "known-name Blob read and add/action collector contract and bootstrap, "
            "reviewed storage-protection contract, signed persistence replay binding, "
            "and ancestor-complete collector RBAC evidence"
        )


def _blocked_pr99_storage_readiness_verifier(
    _expected: MonitoringEvidenceStorageReadiness,
) -> MonitoringEvidenceStorageReadiness:
    raise MonitoringAcquisitionJobError(
        "live monitoring evidence storage verification remains blocked until PR #99 "
        "publishes the reviewed storage contract and runtime read authorization"
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
    """Manifest-first recovery and manifest-last commit for one replay-safe transaction."""

    def __init__(
        self,
        *,
        monitoring_writer: CreateOnlyArtifactWriterPort,
        signer: _HandoffSigner,
        trusted_key: MonitoringRuntimeTrustedKey,
        reviewed_collector_contract: MonitoringCollectorContract,
        monitoring_current_reader: CurrentArtifactReaderPort,
        persistence_replay_key: str,
        configuration: Wc028MonitoringAcquisitionJobConfiguration,
        context_binding: PublishedRuntimeContextBinding,
        monitoring_intent_reference: PublishedMonitoringIntentAssetReference,
        acquisition_receipt_verifier: Callable[[MonitoringAcquisitionReceipt, datetime], None],
        storage_readiness_verifier: Callable[
            [MonitoringEvidenceStorageReadiness],
            MonitoringEvidenceStorageReadiness,
        ],
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
        self._configuration = configuration
        self._context_binding = context_binding
        self._monitoring_intent_reference = monitoring_intent_reference
        self._acquisition_receipt_verifier = acquisition_receipt_verifier
        self._storage_readiness_verifier = storage_readiness_verifier
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

    @staticmethod
    def _observation_health_state(observation: object) -> str | None:
        if isinstance(observation, GuestSignalObservation):
            return observation.state
        if isinstance(observation, EndpointHealthObservation | PlatformHealthObservation):
            return observation.status
        return None

    @staticmethod
    def _observations_for_source_record(
        bundle: MonitoringEvidenceBundle,
        source_record_id: str,
    ) -> tuple[Any, ...]:
        expected_digest = sha256_hex(source_record_id.encode("utf-8"))
        return tuple(
            item
            for item in bundle.observations
            if item.source_record_reference.endswith(expected_digest)
        )

    def _prepared_from_evidence_bundle(
        self,
        bundle: MonitoringEvidenceBundle,
    ) -> PreparedMonitoringCollection:
        receipt = bundle.acquisition_receipt
        if receipt is None or receipt.selected_incident is None:
            raise MonitoringAcquisitionJobError(
                "persisted monitoring evidence omitted its signed incident selection"
            )
        selected = receipt.selected_incident
        previous_candidates = self._observations_for_source_record(
            bundle,
            selected.previous_record_id,
        )
        if len(previous_candidates) != 1:
            raise MonitoringAcquisitionJobError(
                "persisted evidence does not identify one previous incident observation"
            )
        current_candidates: list[Any] = []
        for source_record_id in selected.current_record_ids:
            candidates = self._observations_for_source_record(bundle, source_record_id)
            if len(candidates) != 1:
                raise MonitoringAcquisitionJobError(
                    "persisted evidence does not identify each current incident observation"
                )
            current_candidates.append(candidates[0])
        previous = previous_candidates[0]
        incident_start = min(item.observed_start for item in current_candidates)
        incident_end = max(item.observed_end for item in current_candidates)
        expanded_current = set(current_candidates)
        changed = True
        while changed:
            changed = False
            for candidate in bundle.observations:
                if (
                    candidate in expanded_current
                    or candidate.subject_resource_id != selected.incident_resource_id
                    or self._observation_health_state(candidate) != selected.current_state
                    or candidate.observed_start > incident_end
                    or candidate.observed_end < incident_start
                ):
                    continue
                expanded_current.add(candidate)
                incident_start = min(incident_start, candidate.observed_start)
                incident_end = max(incident_end, candidate.observed_end)
                changed = True
        if (
            previous.subject_resource_id != selected.incident_resource_id
            or self._observation_health_state(previous) != "healthy"
            or any(
                item.subject_resource_id != selected.incident_resource_id
                or self._observation_health_state(item) != selected.current_state
                for item in expanded_current
            )
            or previous.observed_end > incident_start
        ):
            raise MonitoringAcquisitionJobError(
                "persisted evidence incident selection is not the signed health transition"
            )
        return PreparedMonitoringCollection(
            intent_id=receipt.intent_id,
            intent_digest=receipt.intent_digest,
            context_binding_digest=receipt.context_binding_digest,
            monitoring_intent_reference=self._monitoring_intent_reference,
            monitoring_bundle=bundle,
            change_artifacts=(),
            incident_resource_id=selected.incident_resource_id,
            previous_health_source_record_id=selected.previous_record_id,
            current_health_source_record_ids=selected.current_record_ids,
            previous_health_observation_id=previous.observation_id,
            current_health_observation_ids=tuple(
                sorted(item.observation_id for item in expanded_current)
            ),
            current_health_state=selected.current_state,
        )

    def _build_recovery_state(
        self,
        prepared: PreparedMonitoringCollection,
    ) -> MonitoringPersistenceRecoveryState:
        receipt = prepared.monitoring_bundle.acquisition_receipt
        if receipt is None:
            raise MonitoringAcquisitionJobError(
                "WC-028 persistence requires the verified acquisition receipt"
            )
        issued_at = receipt.execution_started_at
        trusted_as_of = issued_at + timedelta(seconds=self._configuration.trust_delay_seconds)
        expires_at = issued_at + timedelta(seconds=self._configuration.request_lifetime_seconds)
        replay_payload = _monitoring_persistence_replay_payload(prepared)
        support_inventory = self._configuration.runtime_support_effective_rbac_inventory
        payload: dict[str, object] = {
            "schemaVersion": "athena.wc028MonitoringPersistenceRecoveryState.v2",
            "replayKey": self._persistence_replay_key,
            "replayPreimageDigest": self._persistence_replay_key,
            "executionId": self._configuration.execution_id,
            "acquisitionAuthorityDigest": (
                self._configuration.expected_acquisition_authority_digest
            ),
            "legacyCollectorRbacCleanupDigest": (
                self._configuration.legacy_collector_rbac_cleanup_digest
            ),
            "preparedDigest": compute_artifact_digest(replay_payload),
            "collectionId": _monitoring_persistence_collection_id(self._persistence_replay_key),
            "incidentRevision": self._configuration.incident_revision,
            "issuedAt": issued_at,
            "trustedAsOf": trusted_as_of,
            "expiresAt": expires_at,
            **replay_payload,
            "monitoringIntentReference": prepared.monitoring_intent_reference.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            "monitoringBundle": prepared.monitoring_bundle.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            "incidentResourceId": prepared.incident_resource_id,
            "previousHealthSourceRecordId": prepared.previous_health_source_record_id,
            "currentHealthSourceRecordIds": list(prepared.current_health_source_record_ids),
            "previousHealthObservationId": prepared.previous_health_observation_id,
            "currentHealthObservationIds": list(prepared.current_health_observation_ids),
            "currentHealthState": prepared.current_health_state,
            "runtimeSupportIdentityResourceId": (
                self._configuration.runtime_support_identity_resource_id
            ),
            "runtimeSupportIdentityClientId": (
                self._configuration.runtime_support_identity_client_id
            ),
            "runtimeSupportIdentityPrincipalId": (
                self._configuration.runtime_support_identity_principal_id
            ),
            "runtimeSupportAttestorIdentityResourceId": (
                support_inventory.attestor_identity_resource_id
            ),
            "runtimeSupportAttestorClientId": support_inventory.attestor_client_id,
            "runtimeSupportAttestorPrincipalId": support_inventory.attestor_principal_id,
            "runtimeSupportAttestorTenantId": support_inventory.attestor_tenant_id,
            "runtimeSupportEffectiveRbacInventoryDigest": support_inventory.inventory_digest,
            "runtimeSupportEffectiveRbacSourceManifestDigest": (
                support_inventory.source_manifest_digest
            ),
            "monitoringEvidenceStorageReadinessDigest": (
                self._configuration.monitoring_evidence_storage_readiness.readiness_digest
            ),
            "runtimeSupportEffectiveRbacCollectedAt": support_inventory.collected_at,
            "runtimeSupportEffectiveRbacExpiresAt": support_inventory.expires_at,
            "registryResourceId": self._configuration.registry_resource_id,
            "runtimeSupportAcrPullRoleDefinitionId": (
                self._configuration.runtime_support_acr_pull_role_definition_id
            ),
            "monitoringIntentSigningKeyResourceId": (
                self._configuration.monitoring_intent_signing_key_resource_id
            ),
            "runtimeSupportMonitoringIntentKeyReaderRoleDefinitionId": (
                self._configuration.runtime_support_monitoring_intent_key_reader_role_definition_id
            ),
        }
        state_digest = compute_artifact_digest(payload)
        signed_payload = {
            **payload,
            "stateDigest": state_digest,
        }
        preimage = _monitoring_recovery_state_preimage(signed_payload)
        try:
            signature = self._signer.sign_preimage(canonicalize_json(preimage).encode("utf-8"))
        except (TypeError, ValueError, *_EXTERNAL_AZURE_FAILURES) as exc:
            raise MonitoringAcquisitionJobError(
                "collector recovery-state signing failed before persistence"
            ) from exc
        return MonitoringPersistenceRecoveryState.model_validate_json(
            canonicalize_json(
                {
                    **signed_payload,
                    "collectorAttestation": MonitoringEvidenceAttestation(
                        signatureAlgorithm="RS256",
                        trustAnchorRef=self._trusted_key.key_vault_key_id,
                        signedPreimageDigest=compute_artifact_digest(preimage),
                        signature=signature,
                    ).model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    ),
                }
            )
        )

    def _validate_recovery_state_binding(
        self,
        state: MonitoringPersistenceRecoveryState,
    ) -> PreparedMonitoringCollection:
        expected_collector_contract_digest = (
            self._reviewed_collector_contract.compute_artifact_digest_value()
        )
        receipt = state.monitoring_bundle.acquisition_receipt
        if receipt is None:
            raise MonitoringAcquisitionJobError(
                "recovered monitoring evidence omitted its signed acquisition receipt"
            )
        if (
            state.replay_key != self._persistence_replay_key
            or state.replay_preimage_digest != self._configuration.persistence_replay_key
            or state.execution_id != self._configuration.execution_id
            or state.acquisition_authority_digest
            != self._configuration.expected_acquisition_authority_digest
            or state.legacy_collector_rbac_cleanup_digest
            != self._configuration.legacy_collector_rbac_cleanup_digest
            or state.incident_revision != self._configuration.incident_revision
            or state.trusted_as_of
            != state.issued_at + timedelta(seconds=self._configuration.trust_delay_seconds)
            or state.expires_at
            != state.issued_at + timedelta(seconds=self._configuration.request_lifetime_seconds)
            or state.intent_id != self._monitoring_intent_reference.intent_id
            or state.intent_digest != self._monitoring_intent_reference.intent_digest
            or state.context_binding_digest != self._context_binding.binding_digest
            or state.collector_contract_digest != expected_collector_contract_digest
            or state.monitoring_intent_reference != self._monitoring_intent_reference
            or state.runtime_support_identity_resource_id
            != self._configuration.runtime_support_identity_resource_id
            or state.runtime_support_identity_client_id.casefold()
            != self._configuration.runtime_support_identity_client_id.casefold()
            or state.runtime_support_identity_principal_id
            != self._configuration.runtime_support_identity_principal_id
            or state.registry_resource_id != self._configuration.registry_resource_id
            or state.runtime_support_acr_pull_role_definition_id
            != self._configuration.runtime_support_acr_pull_role_definition_id
            or state.monitoring_intent_signing_key_resource_id
            != self._configuration.monitoring_intent_signing_key_resource_id
            or state.runtime_support_monitoring_intent_key_reader_role_definition_id
            != (self._configuration.runtime_support_monitoring_intent_key_reader_role_definition_id)
            or state.runtime_support_attestor_tenant_id
            != self._reviewed_collector_contract.collector_tenant_id
            or state.monitoring_evidence_storage_readiness_digest
            != self._configuration.monitoring_evidence_storage_readiness.readiness_digest
        ):
            raise MonitoringAcquisitionJobError(
                "recovered persistence state does not match the reviewed runtime configuration"
            )
        resource_identities = {
            self._configuration.collector_identity_resource_id,
            self._configuration.athena_context_identity_resource_id,
            state.runtime_support_identity_resource_id,
            state.runtime_support_attestor_identity_resource_id,
        }
        principal_identities = {
            self._configuration.managed_identity_client_id.casefold(),
            cast(str, self._reviewed_collector_contract.monitoring_reader_principal_id),
            cast(str, self._reviewed_collector_contract.athena_context_principal_id),
            state.runtime_support_identity_client_id,
            state.runtime_support_identity_principal_id,
            state.runtime_support_attestor_client_id,
            state.runtime_support_attestor_principal_id,
        }
        if len(resource_identities) != 4 or len(principal_identities) != 7:
            raise MonitoringAcquisitionJobError(
                "recovered collector, context, support, and attestor identities overlap"
            )
        persisted_prepared = state.prepared_collection()
        derived_prepared = self._prepared_from_evidence_bundle(state.monitoring_bundle)
        if persisted_prepared != derived_prepared:
            raise MonitoringAcquisitionJobError(
                "recovered persistence incident fields do not match signed evidence"
            )
        return derived_prepared

    def _verify_receipt(
        self,
        receipt: MonitoringAcquisitionReceipt,
        *,
        as_of: datetime,
    ) -> None:
        try:
            self._acquisition_receipt_verifier(receipt, as_of)
        except MonitoringAcquisitionJobError:
            raise
        except (TypeError, ValueError, *_EXTERNAL_AZURE_FAILURES) as exc:
            raise MonitoringAcquisitionJobError(
                "recovered acquisition receipt failed signed verification"
            ) from exc

    def _verify_acquisition_receipt(
        self,
        state: MonitoringPersistenceRecoveryState,
    ) -> None:
        receipt = state.monitoring_bundle.acquisition_receipt
        if receipt is None:
            raise MonitoringAcquisitionJobError(
                "recovered monitoring evidence omitted its signed acquisition receipt"
            )
        self._verify_receipt(receipt, as_of=state.trusted_as_of)

    def _verify_recovery_state_attestation(
        self,
        state: MonitoringPersistenceRecoveryState,
    ) -> None:
        attestation = state.collector_attestation
        signed_payload = state.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"collector_attestation"},
        )
        preimage = _monitoring_recovery_state_preimage(signed_payload)
        try:
            record = self._key_resolver(self._trusted_key.anchor)
            if (
                attestation.trust_anchor_ref != self._trusted_key.key_vault_key_id
                or attestation.signed_preimage_digest != compute_artifact_digest(preimage)
                or record is None
                or record.anchor != self._trusted_key.anchor
                or not record.enabled
                or record.activated_at > state.issued_at
                or (record.retired_at is not None and record.retired_at <= state.trusted_as_of)
                or (record.expires_at is not None and record.expires_at <= state.trusted_as_of)
                or not isinstance(record.public_key, rsa.RSAPublicKey)
            ):
                raise ValueError("collector recovery-state attestation key is not trusted")
            signature = base64.b64decode(attestation.signature, validate=True)
            record.public_key.verify(
                signature,
                canonicalize_json(preimage).encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except MonitoringAcquisitionJobError:
            raise
        except (
            InvalidSignature,
            TypeError,
            ValueError,
            *_EXTERNAL_AZURE_FAILURES,
        ) as exc:
            raise MonitoringAcquisitionJobError(
                "collector recovery-state attestation failed verification"
            ) from exc

    def _build_committed(
        self,
        *,
        state: MonitoringPersistenceRecoveryState,
        evidence_reference: VersionPinnedBlobReference,
    ) -> CommittedMonitoringCollection:
        payload: dict[str, object] = {
            "schemaVersion": "athena.wc028MonitoringEvidenceHandoff.v2",
            "collectorContractDigest": state.collector_contract_digest,
            "collectionId": state.collection_id,
            "observedAt": state.monitoring_bundle.collected_at,
            "evidence": evidence_reference.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            "acquisitionReceiptDigest": state.acquisition_receipt_digest,
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
                as_of=state.trusted_as_of,
                trusted_key_anchor=self._trusted_key.anchor,
                key_resolver=self._key_resolver,
                reviewed_collector_contract=self._reviewed_collector_contract,
            )
        except MonitoringAcquisitionJobError:
            raise
        except (TypeError, ValueError, *_EXTERNAL_AZURE_FAILURES) as exc:
            raise MonitoringAcquisitionJobError(
                "signed monitoring evidence handoff failed verification"
            ) from exc
        return CommittedMonitoringCollection(
            monitoring_handoff=handoff,
            change_handoffs=(),
        )

    def _build_correlation_request(
        self,
        *,
        state: MonitoringPersistenceRecoveryState,
        prepared: PreparedMonitoringCollection,
        committed: CommittedMonitoringCollection,
    ) -> CorrelationRequest:
        try:
            return build_collected_correlation_request(
                prepared,
                committed,
                context_binding=self._context_binding,
                incident_revision=state.incident_revision,
                issued_at=state.issued_at,
                trusted_as_of=state.trusted_as_of,
                expires_at=state.expires_at,
            )
        except (KeyError, TypeError, ValueError, MonitoringCollectionError) as exc:
            raise MonitoringAcquisitionJobError(
                "deterministic monitoring correlation recovery failed"
            ) from exc

    @staticmethod
    def _reference_from_result(result: ArtifactReadResult) -> VersionPinnedBlobReference:
        return VersionPinnedBlobReference(
            name=result.blob_name,
            version=result.version_id,
            contentDigest=result.payload_sha256,
        )

    @staticmethod
    def _validate_recovery_reference(
        *,
        result: ArtifactReadResult,
        reference: VersionPinnedBlobReference,
        expected_payload: bytes,
        label: str,
    ) -> VersionPinnedBlobReference:
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
        return reference

    def _validate_evidence_result(
        self,
        result: ArtifactReadResult,
        *,
        expected_blob_name: str,
        expected_bundle: MonitoringEvidenceBundle | None,
    ) -> tuple[MonitoringEvidenceBundle, VersionPinnedBlobReference]:
        try:
            bundle = MonitoringEvidenceBundle.model_validate_json(result.payload)
        except (UnicodeDecodeError, ValueError) as exc:
            raise MonitoringAcquisitionJobError(
                "recovered immutable monitoring evidence is invalid"
            ) from exc
        if (
            result.blob_name != expected_blob_name
            or result.payload_sha256 != sha256_hex(result.payload)
            or result.payload != bundle.canonical_bytes()
            or (
                expected_bundle is not None
                and bundle.canonical_bytes() != expected_bundle.canonical_bytes()
            )
        ):
            raise MonitoringAcquisitionJobError(
                "recovered immutable monitoring evidence failed byte verification"
            )
        return bundle, self._reference_from_result(result)

    def _build_commit_manifest(
        self,
        *,
        state: MonitoringPersistenceRecoveryState,
        state_reference: VersionPinnedBlobReference,
        committed: CommittedMonitoringCollection,
        correlation_request: CorrelationRequest,
    ) -> MonitoringPersistenceCommitManifest:
        replay_payload = {
            "intentId": state.intent_id,
            "intentDigest": state.intent_digest,
            "contextBindingDigest": state.context_binding_digest,
            "collectorContractDigest": state.collector_contract_digest,
            "monitoringBundleDigest": state.monitoring_bundle_digest,
            "acquisitionReceiptDigest": state.acquisition_receipt_digest,
        }
        payload: dict[str, object] = {
            "schemaVersion": "athena.wc028MonitoringPersistenceCommit.v3",
            "replayKey": state.replay_key,
            "executionId": state.execution_id,
            "preparedDigest": state.prepared_digest,
            "collectionId": state.collection_id,
            "recoveryState": state_reference.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            **replay_payload,
            "monitoringHandoff": committed.monitoring_handoff.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            "correlationRequestId": correlation_request.request_id,
            "correlationRequestDigest": correlation_request.request_digest,
        }
        return MonitoringPersistenceCommitManifest.model_validate_json(
            canonicalize_json(
                {
                    **payload,
                    "manifestDigest": compute_artifact_digest(payload),
                }
            )
        )

    def recover(
        self,
        probe: _MonitoringPersistenceProbe,
    ) -> RecoveredMonitoringAcquisitionJobOutcome | None:
        if not probe.has_durable_artifacts:
            return None
        manifest_blob_name, recovery_blob_name, evidence_blob_name = (
            _monitoring_persistence_blob_names(self._persistence_replay_key)
        )
        manifest = (
            None
            if probe.manifest_result is None
            else _parse_commit_manifest_result(
                probe.manifest_result,
                expected_blob_name=manifest_blob_name,
            )
        )
        state = (
            None
            if probe.recovery_state_result is None
            else _parse_recovery_state_result(
                probe.recovery_state_result,
                expected_blob_name=recovery_blob_name,
            )
        )
        evidence_bundle: MonitoringEvidenceBundle | None = None
        evidence_reference: VersionPinnedBlobReference | None = None
        if probe.evidence_result is not None:
            evidence_bundle, evidence_reference = self._validate_evidence_result(
                probe.evidence_result,
                expected_blob_name=evidence_blob_name,
                expected_bundle=None if state is None else state.monitoring_bundle,
            )
        if manifest is not None:
            if (
                state is None
                or probe.recovery_state_result is None
                or evidence_bundle is None
                or probe.evidence_result is None
            ):
                raise MonitoringAcquisitionJobError(
                    "commit manifest exists without its exact recovery state and evidence"
                )
            self._verify_recovery_state_attestation(state)
            self._verify_acquisition_receipt(state)
            prepared = self._validate_recovery_state_binding(state)
            self._validate_recovery_reference(
                result=probe.recovery_state_result,
                reference=manifest.recovery_state,
                expected_payload=state.canonical_bytes(),
                label="persistence recovery state",
            )
            self._validate_recovery_reference(
                result=probe.evidence_result,
                reference=manifest.monitoring_handoff.evidence,
                expected_payload=state.monitoring_bundle.canonical_bytes(),
                label="monitoring evidence",
            )
            if (
                manifest.replay_key != state.replay_key
                or manifest.execution_id != state.execution_id
                or manifest.prepared_digest != state.prepared_digest
                or manifest.collection_id != state.collection_id
            ):
                raise MonitoringAcquisitionJobError(
                    "commit manifest does not bind the exact recovery state"
                )
            committed = CommittedMonitoringCollection(
                monitoring_handoff=manifest.monitoring_handoff,
                change_handoffs=(),
            )
            try:
                verify_monitoring_evidence_handoff_attestation(
                    committed.monitoring_handoff,
                    as_of=state.trusted_as_of,
                    trusted_key_anchor=self._trusted_key.anchor,
                    key_resolver=self._key_resolver,
                    reviewed_collector_contract=self._reviewed_collector_contract,
                )
            except (TypeError, ValueError, *_EXTERNAL_AZURE_FAILURES) as exc:
                raise MonitoringAcquisitionJobError(
                    "recovered monitoring persistence handoff failed verification"
                ) from exc
            rebuilt_correlation = self._build_correlation_request(
                state=state,
                prepared=prepared,
                committed=committed,
            )
            if (
                rebuilt_correlation.request_id != manifest.correlation_request_id
                or rebuilt_correlation.request_digest != manifest.correlation_request_digest
            ):
                raise MonitoringAcquisitionJobError(
                    "commit manifest correlation request is not byte-identical"
                )
            return RecoveredMonitoringAcquisitionJobOutcome(
                committed=committed,
                correlation_request=rebuilt_correlation,
            )

        if state is None:
            raise MonitoringAcquisitionJobError(
                "immutable evidence exists without its collector-signed recovery binding"
            )
        self._verify_recovery_state_attestation(state)
        self._verify_acquisition_receipt(state)
        prepared = self._validate_recovery_state_binding(state)
        _revalidate_monitoring_evidence_storage_readiness(
            configuration=self._configuration,
            expected_signed_digest=(state.monitoring_evidence_storage_readiness_digest),
            verifier=self._storage_readiness_verifier,
        )
        if probe.recovery_state_result is None:
            state_reference = self._write(
                writer=self._monitoring_writer,
                current_reader=self._monitoring_current_reader,
                blob_name=recovery_blob_name,
                payload=state.canonical_bytes(),
            )
        else:
            state_reference = self._reference_from_result(probe.recovery_state_result)
        if evidence_bundle is None:
            evidence_reference = self._write(
                writer=self._monitoring_writer,
                current_reader=self._monitoring_current_reader,
                blob_name=evidence_blob_name,
                payload=state.monitoring_bundle.canonical_bytes(),
                allow_existing_exact_collision=probe.recovery_state_result is not None,
            )
        if evidence_reference is None:
            raise MonitoringAcquisitionJobError(
                "immutable monitoring evidence recovery did not produce a reference"
            )
        committed = self._build_committed(
            state=state,
            evidence_reference=evidence_reference,
        )
        correlation_request = self._build_correlation_request(
            state=state,
            prepared=prepared,
            committed=committed,
        )
        manifest = self._build_commit_manifest(
            state=state,
            state_reference=state_reference,
            committed=committed,
            correlation_request=correlation_request,
        )
        self._write(
            writer=self._monitoring_writer,
            current_reader=self._monitoring_current_reader,
            blob_name=manifest_blob_name,
            payload=manifest.canonical_bytes(),
        )
        durable_result = self._monitoring_current_reader.read_current(
            ArtifactCurrentReadRequest(blob_name=manifest_blob_name)
        )
        durable_manifest = _parse_commit_manifest_result(
            durable_result,
            expected_blob_name=manifest_blob_name,
        )
        if durable_manifest != manifest:
            raise MonitoringAcquisitionJobError(
                "monitoring persistence commit manifest changed after creation"
            )
        return RecoveredMonitoringAcquisitionJobOutcome(
            committed=committed,
            correlation_request=correlation_request,
        )

    @contextmanager
    def transaction(
        self,
        prepared: PreparedMonitoringCollection,
    ) -> Iterator[CommittedMonitoringCollection]:
        if prepared.change_artifacts:
            raise MonitoringAcquisitionJobError(
                "current collector contract does not authorize runtime change persistence"
            )
        manifest_blob_name, recovery_blob_name, evidence_blob_name = (
            _monitoring_persistence_blob_names(self._persistence_replay_key)
        )
        probe = _probe_monitoring_persistence(
            reader=self._monitoring_current_reader,
            replay_key=self._persistence_replay_key,
        )
        if probe.manifest_result is None:
            if probe.recovery_state_result is not None:
                persisted_state = _parse_recovery_state_result(
                    probe.recovery_state_result,
                    expected_blob_name=recovery_blob_name,
                )
                self._verify_recovery_state_attestation(persisted_state)
                self._verify_acquisition_receipt(persisted_state)
                if self._validate_recovery_state_binding(persisted_state) != prepared:
                    raise MonitoringAcquisitionJobError(
                        "partial persistence state does not match reacquired transaction"
                    )
            if (
                probe.evidence_result is not None
                and probe.evidence_result.payload != prepared.monitoring_bundle.canonical_bytes()
            ):
                raise MonitoringAcquisitionJobError(
                    "partial immutable evidence does not match reacquired transaction"
                )
        recovered = self.recover(probe)
        if recovered is not None:
            if (
                recovered.correlation_request.monitoring_bundle.canonical_bytes()
                != prepared.monitoring_bundle.canonical_bytes()
                or recovered.correlation_request.context_binding.binding_digest
                != prepared.context_binding_digest
            ):
                raise MonitoringAcquisitionJobError(
                    "durable commit does not match the supplied prepared transaction"
                )
            yield recovered.committed
            return
        state = self._build_recovery_state(prepared)
        self._verify_recovery_state_attestation(state)
        self._verify_acquisition_receipt(state)
        self._validate_recovery_state_binding(state)
        _revalidate_monitoring_evidence_storage_readiness(
            configuration=self._configuration,
            expected_signed_digest=(state.monitoring_evidence_storage_readiness_digest),
            verifier=self._storage_readiness_verifier,
        )
        state_reference = self._write(
            writer=self._monitoring_writer,
            current_reader=self._monitoring_current_reader,
            blob_name=recovery_blob_name,
            payload=state.canonical_bytes(),
        )
        evidence_reference = self._write(
            writer=self._monitoring_writer,
            current_reader=self._monitoring_current_reader,
            blob_name=evidence_blob_name,
            payload=state.monitoring_bundle.canonical_bytes(),
            allow_existing_exact_collision=False,
        )
        committed = self._build_committed(
            state=state,
            evidence_reference=evidence_reference,
        )
        yield committed
        correlation_request = self._build_correlation_request(
            state=state,
            prepared=prepared,
            committed=committed,
        )
        commit_manifest = self._build_commit_manifest(
            state=state,
            state_reference=state_reference,
            committed=committed,
            correlation_request=correlation_request,
        )
        self._write(
            writer=self._monitoring_writer,
            current_reader=self._monitoring_current_reader,
            blob_name=manifest_blob_name,
            payload=commit_manifest.canonical_bytes(),
        )
        durable_result = self._monitoring_current_reader.read_current(
            ArtifactCurrentReadRequest(blob_name=manifest_blob_name)
        )
        durable = _parse_commit_manifest_result(
            durable_result,
            expected_blob_name=manifest_blob_name,
        )
        if durable != commit_manifest:
            raise MonitoringAcquisitionJobError(
                "monitoring persistence commit manifest changed after creation"
            )

    def _write(
        self,
        *,
        writer: CreateOnlyArtifactWriterPort,
        current_reader: CurrentArtifactReaderPort,
        blob_name: str,
        payload: bytes,
        allow_existing_exact_collision: bool = True,
    ) -> VersionPinnedBlobReference:
        if type(allow_existing_exact_collision) is not bool:
            raise TypeError("allow_existing_exact_collision must be an exact bool")
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
            try:
                recovered = current_reader.read_current(
                    ArtifactCurrentReadRequest(blob_name=blob_name)
                )
            except (ArtifactReadError, *_EXTERNAL_AZURE_FAILURES) as read_exc:
                raise MonitoringAcquisitionJobError(
                    f"immutable persistence collision could not be recovered: {blob_name}"
                ) from read_exc
            if (
                recovered.blob_name == blob_name
                and recovered.payload == payload
                and recovered.payload_sha256 == sha256_hex(payload)
            ):
                if not allow_existing_exact_collision:
                    raise MonitoringAcquisitionJobError(
                        "immutable monitoring evidence pre-existed its signed recovery state"
                    ) from exc
                return VersionPinnedBlobReference(
                    name=recovered.blob_name,
                    version=recovered.version_id,
                    contentDigest=recovered.payload_sha256,
                )
            raise MonitoringAcquisitionJobError(
                f"immutable persistence artifact already exists: {blob_name}"
            ) from exc
        except _EXTERNAL_AZURE_FAILURES as exc:
            try:
                recovered = current_reader.read_current(
                    ArtifactCurrentReadRequest(blob_name=blob_name)
                )
            except ArtifactNotFoundError:
                raise MonitoringAcquisitionJobError(
                    f"ambiguous create failed without a durable known-name artifact: {blob_name}"
                ) from exc
            except (ArtifactReadError, *_EXTERNAL_AZURE_FAILURES) as read_exc:
                raise MonitoringAcquisitionJobError(
                    f"ambiguous create recovery failed for known-name artifact: {blob_name}"
                ) from read_exc
            if (
                recovered.blob_name == blob_name
                and recovered.payload == payload
                and recovered.payload_sha256 == sha256_hex(payload)
            ):
                return VersionPinnedBlobReference(
                    name=recovered.blob_name,
                    version=recovered.version_id,
                    contentDigest=recovered.payload_sha256,
                )
            raise MonitoringAcquisitionJobError(
                f"ambiguous create recovered conflicting immutable bytes: {blob_name}"
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
) -> MonitoringAcquisitionJobOutcome:
    try:
        try:
            monitoring_intent = _embedded_model(
                PublishedMonitoringIntent, configuration.monitoring_intent
            )
            intent_reference = _embedded_model(
                PublishedMonitoringIntentAssetReference,
                configuration.monitoring_intent_reference,
            )
            intent_attestation = _embedded_model(
                PublishedMonitoringIntentAttestation,
                configuration.monitoring_intent_attestation,
            )
            context_binding = _embedded_model(
                PublishedRuntimeContextBinding, configuration.context_binding
            )
            collector_contract = _embedded_model(
                MonitoringCollectorContract,
                configuration.monitoring_collector_contract,
            )
            change_scope = _embedded_model(
                ApprovedChangeScope,
                configuration.approved_change_scope,
            )
            acquisition_authority = _embedded_model(
                MonitoringAcquisitionAuthority,
                configuration.acquisition_authority,
            )
        except (TypeError, ValueError) as exc:
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
        _require_pr99_conditioned_blob_contract(collector_contract)
        _revalidate_monitoring_evidence_storage_readiness(
            configuration=configuration,
        )
        monitoring_evidence_store = AzureBlobChangeEvidenceReplayStore(
            blob_endpoint=configuration.evidence_blob_endpoint,
            container_name=configuration.evidence_container_name,
            managed_identity_client_id=configuration.managed_identity_client_id,
        )
        persistence_probe = _probe_monitoring_persistence(
            reader=monitoring_evidence_store,
            replay_key=configuration.persistence_replay_key,
        )

        def build_collector_commit_port() -> tuple[
            KeyVaultRsaSigner,
            Callable[[MonitoringAcquisitionReceipt, datetime], None],
            MonitoringEvidenceCommitPort,
        ]:
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
            acquisition_receipt_verifier = _build_acquisition_receipt_verifier(
                acquisition_authority=acquisition_authority,
                collector_contract=collector_contract,
                trusted_key=configuration.collector_signing_key,
                key_resolver=collector_key_resolver,
            )
            return (
                collector_signer,
                acquisition_receipt_verifier,
                MonitoringEvidenceCommitPort(
                    monitoring_writer=monitoring_evidence_store,
                    signer=collector_signer,
                    trusted_key=configuration.collector_signing_key,
                    reviewed_collector_contract=collector_contract,
                    monitoring_current_reader=monitoring_evidence_store,
                    persistence_replay_key=configuration.persistence_replay_key,
                    configuration=configuration,
                    context_binding=context_binding,
                    monitoring_intent_reference=intent_reference,
                    acquisition_receipt_verifier=acquisition_receipt_verifier,
                    storage_readiness_verifier=(_blocked_pr99_storage_readiness_verifier),
                    key_resolver=collector_key_resolver,
                ),
            )

        if persistence_probe.has_durable_artifacts:
            _, _, recovery_commit_port = build_collector_commit_port()
            recovered = recovery_commit_port.recover(persistence_probe)
            if recovered is None:
                raise MonitoringAcquisitionJobError(
                    "durable persistence recovery returned no committed result"
                )
            return recovered

        startup_as_of = _utc_now_milliseconds()
        _validate_runtime_support_effective_rbac(
            configuration=configuration,
            as_of=startup_as_of,
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
            as_of=startup_as_of,
        )
        try:
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
        except (TypeError, ValueError) as exc:
            raise MonitoringAcquisitionJobError(
                "monitoring intent is not eligible for production acquisition"
            ) from exc

        collector_signer, acquisition_receipt_verifier, commit_port = build_collector_commit_port()

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
        coordinator = MonitoringAcquisitionCoordinator(
            acquisition_adapter=acquisition_adapter,
            acquisition_authority=acquisition_authority,
            expected_acquisition_authority_digest=(
                configuration.expected_acquisition_authority_digest
            ),
            expected_collector_contract_digest=collector_contract_digest,
            monitoring_intent_trusted_key_id=(
                configuration.monitoring_intent_trusted_key.key_vault_key_id
            ),
            monitoring_intent_signature_verifier=intent_verifier.verify_preimage,
            monitoring_intent_asset_loader=load_intent_assets,
            collection_transaction=collection_transaction,
            receipt_signer=collector_signer,
        )
        issued_at = startup_as_of
        trusted_as_of = issued_at + timedelta(seconds=configuration.trust_delay_seconds)
        expires_at = issued_at + timedelta(seconds=configuration.request_lifetime_seconds)
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
            stabilize_correlation_window=True,
        )
    except MonitoringAcquisitionJobError:
        raise
    except (MonitoringAcquisitionError, MonitoringCollectionError) as exc:
        raise MonitoringAcquisitionJobError(str(exc)) from exc
    except (ArtifactReadError, ArtifactWriteError) as exc:
        raise MonitoringAcquisitionJobError("WC-028 immutable evidence persistence failed") from exc
    except _EXTERNAL_AZURE_FAILURES as exc:
        raise MonitoringAcquisitionJobError(
            "WC-028 Azure client or transport operation failed"
        ) from exc
    except ValueError as exc:
        raise MonitoringAcquisitionJobError(
            "WC-028 Azure key or persistence verification failed"
        ) from exc


__all__ = [
    "MonitoringAcquisitionJobError",
    "MonitoringAcquisitionJobOutcome",
    "MonitoringEvidenceStorageReadiness",
    "MonitoringEvidenceCommitPort",
    "MonitoringPersistenceCommitManifest",
    "MonitoringPersistenceRecoveryState",
    "MonitoringRuntimeSupportEffectiveRbacInventory",
    "MonitoringRuntimeTrustedKey",
    "RecoveredMonitoringAcquisitionJobOutcome",
    "Wc028MonitoringAcquisitionJobConfiguration",
    "load_wc028_monitoring_acquisition_job_configuration",
    "run_wc028_monitoring_acquisition_job",
]
