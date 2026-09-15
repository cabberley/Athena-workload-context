from __future__ import annotations

import base64
import re
from datetime import UTC, datetime
from typing import Literal, cast
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import canonicalize_json, compute_artifact_digest
from athena_context.contracts.models import (
    AthenaBaseModel,
    Sha256Digest,
    TrustedKeyAnchor,
    TrustedKeyResolver,
    UtcDateTime,
)
from athena_context.contracts.operational_phase import VersionPinnedBlobReference
from athena_context.monitoring_incident import (
    MonitoringHealthRecordKind,
    monitoring_health_source_record_reference,
)

MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION = "athena.wc024MonitoringCollectorContract.v2"
MONITORING_LEGACY_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION = (
    "athena.wc028MonitoringCollectorContract.v3"
)
MONITORING_PREVIOUS_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION = (
    "athena.wc028MonitoringCollectorContract.v4"
)
MONITORING_IDENTITY_PROOF_COLLECTOR_CONTRACT_SCHEMA_VERSION = (
    "athena.wc028MonitoringCollectorContract.v5"
)
MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION = (
    "athena.wc028MonitoringCollectorContract.v6"
)
MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION = (
    "athena.wc028MonitoringCollectorContract.v7"
)
MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION = "athena.wc024MonitoringEvidenceHandoff.v1"
MONITORING_PREVIOUS_ACQUISITION_RECEIPT_SCHEMA_VERSION = (
    "athena.wc028MonitoringAcquisitionReceipt.v4"
)
MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION = "athena.wc028MonitoringAcquisitionReceipt.v5"
MONITORING_ACQUISITION_HANDOFF_SCHEMA_VERSION = "athena.wc028MonitoringEvidenceHandoff.v2"
MONITORING_IDENTITY_PROOF_AUDIENCE = "api://athena-monitoring-identity-proof"
MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS = 7200
MONITORING_IDENTITY_PROOF_REQUIRED_ROLE = "Athena.MonitoringAcquisition.ProveIdentity"
MONITORING_IDENTITY_PROOF_TOKEN_VERSION = "1.0"  # noqa: S105

type MonitoringSignalKind = Literal[
    "heartbeat",
    "perf",
    "insightsMetrics",
    "syslog",
    "disk",
    "guest",
    "vnetFlow",
    "trafficAnalytics",
]
type MonitoringReadOperation = Literal[
    "Microsoft.OperationalInsights/workspaces/read",
    "Microsoft.OperationalInsights/workspaces/query/read",
    "Microsoft.OperationalInsights/workspaces/tables/data/read",
    "Microsoft.Compute/virtualMachines/instanceView/read",
    "Microsoft.Insights/Metrics/Read",
    "Microsoft.Insights/dataCollectionRules/read",
    "Microsoft.Insights/dataCollectionEndpoints/read",
    "Microsoft.Insights/dataCollectionRuleAssociations/read",
    "Microsoft.Insights/privateLinkScopes/read",
    "Microsoft.Network/networkWatchers/flowLogs/read",
    "Microsoft.Network/networkWatchers/ipFlowVerify/action",
    "Microsoft.Network/networkWatchers/ipFlowVerify/read",
    "Microsoft.ResourceHealth/AvailabilityStatuses/read",
    "Microsoft.Insights/logs/Heartbeat/read",
    "Microsoft.Insights/logs/VMConnection/read",
    "Microsoft.Insights/logs/NWConnectionMonitorTestResult/read",
    "Microsoft.Insights/logs/NTANetAnalytics/read",
]
type MonitoringIpFlowVerifyOperation = Literal[
    "Microsoft.Network/networkWatchers/ipFlowVerify/action",
    "Microsoft.Network/networkWatchers/ipFlowVerify/read",
]
type MonitoringResourceHealthOperation = Literal[
    "Microsoft.ResourceHealth/AvailabilityStatuses/read",
]
type MonitoringResourceLogOperation = Literal[
    "Microsoft.Insights/logs/Heartbeat/read",
    "Microsoft.Insights/logs/VMConnection/read",
    "Microsoft.Insights/logs/NWConnectionMonitorTestResult/read",
    "Microsoft.Insights/logs/NTANetAnalytics/read",
]
type MonitoringLogTable = Literal[
    "Heartbeat",
    "Perf",
    "InsightsMetrics",
    "Syslog",
    "VMComputer",
    "VMConnection",
    "VMBoundPort",
    "VMProcess",
    "NTANetAnalytics",
    "NWConnectionMonitorDestinationListenerResult",
    "NWConnectionMonitorDNSResult",
    "NWConnectionMonitorPathResult",
    "NWConnectionMonitorTestResult",
]

_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_COLLECTION_ID_PATTERN = r"^wc024-[a-f0-9]{12}$"
_SUBSCRIPTION_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_KEY_VAULT_KEY_ID_PATTERN = re.compile(
    r"^https://[A-Za-z0-9-]+\.vault\.azure\.net/keys/"
    r"[A-Za-z0-9-]{1,127}/[A-Fa-f0-9]{32}$"
)
_READER_ROLE_DEFINITION_GUID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
_SIGNAL_READER_ROLE_DEFINITION_GUID = "2fda1d90-37da-55d9-8ac3-132fb7bdca5d"
_RESOURCE_LOG_READER_ROLE_DEFINITION_GUID = "f33a4363-5d9a-5d50-9871-c08582234978"
_LOG_ANALYTICS_DATA_READER_ROLE_DEFINITION_GUID = "3b03c2da-16b3-4a49-8834-0f8130efdd3b"
_IP_FLOW_VERIFY_ROLE_DEFINITION_GUID = "3728cdf6-4efd-5282-bdfc-63b7872fd801"
_RESOURCE_HEALTH_ROLE_DEFINITION_GUID = "0790d6f2-9553-5b63-84ac-56596b7e4072"
_STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE_DEFINITION_GUID = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
_KEY_VAULT_CRYPTO_USER_ROLE_DEFINITION_GUID = "12338af0-0e69-4776-bea7-57ae8d297424"
_SIGNAL_READER_ROLE_NAME_PREFIX = "Athena WC016 Approved Signal Reader "
_RESOURCE_LOG_READER_ROLE_NAME = "Athena WC-028 VM Resource Log Reader"
_IP_FLOW_VERIFY_ROLE_NAME = "Athena WC-028 Network Watcher IP Flow Verify"
_RESOURCE_HEALTH_ROLE_NAME = "Athena WC-028 VM Resource Health Reader"
_STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE_NAME = "Storage Blob Data Contributor"
_KEY_VAULT_CRYPTO_USER_ROLE_NAME = "Key Vault Crypto User"
_REVIEWED_WORKLOAD_RESOURCE_GROUP = "rg-athena-demo-workload"
_REVIEWED_WORKLOAD_VNET_NAME = "athena-hackathon-vnet"
_REVIEWED_MONITORING_RESOURCE_GROUP = "rg-athena-demo-monitoring"
_REVIEWED_NETWORK_WATCHER_RESOURCE_GROUP = "NetworkWatcherRG"
_REVIEWED_NETWORK_WATCHER_NAME = "NetworkWatcher_australiaeast"
_REVIEWED_FLOW_LOG_NAME = "athena-hackathon-vnet-rg-athena-demo-workload-flowlog"
_REVIEWED_WORKSPACE_NAME = "athena-hackathon-law"
_REVIEWED_DCE_NAME = "athena-hackathon-linux-dce"
_REVIEWED_DCR_NAME = "athena-hackathon-linux-dcr"
_REVIEWED_AMPLS_NAMES = (
    "athena-demo-monitoring-workload-ampls",
    "athena-demo-monitoring-collector-ampls",
)
_EXPECTED_LOG_TABLES: tuple[MonitoringLogTable, ...] = (
    "Heartbeat",
    "Perf",
    "InsightsMetrics",
    "Syslog",
    "VMComputer",
    "VMConnection",
    "VMBoundPort",
    "VMProcess",
    "NTANetAnalytics",
    "NWConnectionMonitorDestinationListenerResult",
    "NWConnectionMonitorDNSResult",
    "NWConnectionMonitorPathResult",
    "NWConnectionMonitorTestResult",
)
_EXPECTED_LOG_ANALYTICS_ACCESS_CONDITION = (
    "((!(ActionMatches"
    "{'Microsoft.OperationalInsights/workspaces/tables/data/read'}"
    ")) OR ("
    + " OR ".join(
        "@Resource[Microsoft.OperationalInsights/workspaces/tables:name] "
        f"StringEquals '{table_name}'"
        for table_name in _EXPECTED_LOG_TABLES
    )
    + "))"
)
_EXPECTED_APPROVED_VM_NAMES: tuple[str, ...] = (
    "athena-hackathon-client-01",
    "athena-hackathon-ecp-01",
    "athena-hackathon-ecp-02",
    "athena-hackathon-ecp-03",
    "athena-hackathon-iris-01",
    "athena-hackathon-mid-01",
    "athena-hackathon-mid-02",
    "athena-hackathon-sqlvm-01",
    "athena-hackathon-web-01",
    "athena-hackathon-web-02",
    "athena-hackathon-web-03",
)
_EXPECTED_SIGNALS: tuple[MonitoringSignalKind, ...] = (
    "heartbeat",
    "perf",
    "insightsMetrics",
    "syslog",
    "disk",
    "guest",
    "vnetFlow",
    "trafficAnalytics",
)
_EXPECTED_READ_OPERATIONS: tuple[MonitoringReadOperation, ...] = (
    "Microsoft.OperationalInsights/workspaces/read",
    "Microsoft.OperationalInsights/workspaces/query/read",
    "Microsoft.OperationalInsights/workspaces/tables/data/read",
    "Microsoft.Compute/virtualMachines/instanceView/read",
    "Microsoft.Insights/Metrics/Read",
    "Microsoft.Insights/dataCollectionRules/read",
    "Microsoft.Insights/dataCollectionEndpoints/read",
    "Microsoft.Insights/dataCollectionRuleAssociations/read",
    "Microsoft.Insights/privateLinkScopes/read",
    "Microsoft.Network/networkWatchers/flowLogs/read",
)
_EXPECTED_IP_FLOW_VERIFY_OPERATIONS: tuple[MonitoringIpFlowVerifyOperation, ...] = (
    "Microsoft.Network/networkWatchers/ipFlowVerify/action",
    "Microsoft.Network/networkWatchers/ipFlowVerify/read",
)
_EXPECTED_PREVIOUS_ACQUISITION_READ_OPERATIONS: tuple[MonitoringReadOperation, ...] = (
    *_EXPECTED_READ_OPERATIONS,
    *_EXPECTED_IP_FLOW_VERIFY_OPERATIONS,
)
_EXPECTED_RESOURCE_HEALTH_OPERATIONS: tuple[MonitoringResourceHealthOperation, ...] = (
    "Microsoft.ResourceHealth/AvailabilityStatuses/read",
)
_EXPECTED_RESOURCE_LOG_OPERATIONS: tuple[MonitoringResourceLogOperation, ...] = (
    "Microsoft.Insights/logs/Heartbeat/read",
    "Microsoft.Insights/logs/NTANetAnalytics/read",
    "Microsoft.Insights/logs/NWConnectionMonitorTestResult/read",
    "Microsoft.Insights/logs/VMConnection/read",
)
_EXPECTED_PREVIOUS_PRODUCTION_ACQUISITION_READ_OPERATIONS: tuple[MonitoringReadOperation, ...] = (
    *_EXPECTED_PREVIOUS_ACQUISITION_READ_OPERATIONS,
    *_EXPECTED_RESOURCE_HEALTH_OPERATIONS,
)
_EXPECTED_ACQUISITION_READ_OPERATIONS: tuple[MonitoringReadOperation, ...] = (
    *_EXPECTED_READ_OPERATIONS[3:],
    *_EXPECTED_IP_FLOW_VERIFY_OPERATIONS,
    *_EXPECTED_RESOURCE_HEALTH_OPERATIONS,
    *_EXPECTED_RESOURCE_LOG_OPERATIONS,
)
_MAX_VERIFIED_TOKEN_LIFETIME_SECONDS = 28 * 60 * 60


class _StrictMonitoringContract(AthenaBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )


def _parse_arm_resource_id(
    resource_id: str,
) -> tuple[str, str, str | None, tuple[str, ...]]:
    """Parse a fully qualified ARM resource or resource-group ID."""

    segments = resource_id.split("/")
    if (
        not resource_id.startswith("/")
        or len(segments) < 5
        or segments[1].casefold() != "subscriptions"
        or not _SUBSCRIPTION_ID_PATTERN.fullmatch(segments[2])
        or segments[3].casefold() != "resourcegroups"
        or not segments[4]
    ):
        raise ValueError("must be a fully qualified ARM resource-group ID")

    if len(segments) == 5:
        return segments[2].casefold(), segments[4].casefold(), None, ()

    if (
        len(segments) < 9
        or segments[5].casefold() != "providers"
        or not segments[6]
        or len(segments[7:]) % 2 != 0
        or any(not segment for segment in segments[7:])
    ):
        raise ValueError("must be a fully qualified ARM resource ID")

    return (
        segments[2].casefold(),
        segments[4].casefold(),
        segments[6].casefold(),
        tuple(segment.casefold() for segment in segments[7::2]),
    )


def _canonical_rbac_scope(value: str) -> str:
    normalized = value.casefold().rstrip("/")
    if normalized == "":
        return "/"
    segments = normalized.strip("/").split("/")
    if (
        len(segments) == 4
        and segments[:3] == ["providers", "microsoft.management", "managementgroups"]
        and segments[3]
    ):
        return normalized
    if (
        len(segments) == 2
        and segments[0] == "subscriptions"
        and _SUBSCRIPTION_ID_PATTERN.fullmatch(segments[1]) is not None
    ):
        return normalized
    if (
        len(segments) >= 4
        and segments[0] == "subscriptions"
        and _SUBSCRIPTION_ID_PATTERN.fullmatch(segments[1]) is not None
        and segments[2] == "resourcegroups"
        and segments[3]
    ):
        if len(segments) == 4:
            return normalized
        _parse_arm_resource_id(normalized)
        return normalized
    raise ValueError("effective RBAC scope must be one canonical Azure hierarchy scope")


class MonitoringEffectiveRbacGrant(_StrictMonitoringContract):
    """Measured effective Azure RBAC grants grouped only by identical semantics."""

    assigned_principal_id: str = Field(
        alias="assignedPrincipalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    assigned_principal_type: Literal["ServicePrincipal", "Group"] = Field(
        alias="assignedPrincipalType"
    )
    effective_principal_id: str = Field(
        alias="effectivePrincipalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    role_definition_id: str = Field(
        alias="roleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    role_definition_name: str = Field(
        alias="roleDefinitionName",
        min_length=1,
        max_length=256,
    )
    assignment_scope_ids: tuple[str, ...] = Field(
        alias="assignmentScopeIds",
        min_length=1,
        max_length=256,
    )
    inheritance: Literal["direct", "inherited"]
    group_derived: bool = Field(alias="groupDerived")
    condition: str | None = Field(default=None, min_length=1, max_length=8192)
    condition_version: Literal["2.0"] | None = Field(
        default=None,
        alias="conditionVersion",
    )
    grant_digest: Sha256Digest = Field(alias="grantDigest")

    @field_validator("assigned_principal_id", "effective_principal_id")
    @classmethod
    def normalize_principal_id(cls, value: str) -> str:
        return value.casefold()

    @field_validator("role_definition_id")
    @classmethod
    def normalize_role_definition_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        segments = normalized.strip("/").split("/")
        provider_index = (
            2
            if len(segments) == 6
            else 4
            if len(segments) == 8 and segments[2] == "resourcegroups" and segments[3]
            else -1
        )
        if (
            provider_index < 0
            or segments[0] != "subscriptions"
            or _SUBSCRIPTION_ID_PATTERN.fullmatch(segments[1]) is None
            or segments[provider_index] != "providers"
            or segments[provider_index + 1] != "microsoft.authorization"
            or segments[provider_index + 2] != "roledefinitions"
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{4}-[0-9a-f]{12}",
                segments[provider_index + 3],
            )
            is None
        ):
            raise ValueError("effective RBAC roleDefinitionId must identify one Azure role")
        return normalized

    @field_validator("role_definition_name")
    @classmethod
    def validate_role_name(cls, value: str) -> str:
        if not value.isascii() or value != value.strip():
            raise ValueError("effective RBAC roleDefinitionName must use exact ASCII")
        return value

    @field_validator("assignment_scope_ids")
    @classmethod
    def normalize_scopes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_canonical_rbac_scope(item) for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("effective RBAC assignment scopes must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_grant(self) -> MonitoringEffectiveRbacGrant:
        if (self.condition is None) != (self.condition_version is None):
            raise ValueError(
                "effective RBAC condition and conditionVersion must be supplied together"
            )
        if self.group_derived != (
            self.assigned_principal_type == "Group"
            and self.assigned_principal_id != self.effective_principal_id
        ):
            raise ValueError(
                "effective RBAC groupDerived must match assigned and effective principals"
            )
        if not self.group_derived and self.assigned_principal_id != self.effective_principal_id:
            raise ValueError("direct effective RBAC grant must retain the assigned principal")
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
                exclude={"grant_digest"},
            )
        )
        if self.grant_digest != expected:
            raise ValueError("grantDigest does not bind the effective RBAC grant")
        return self


class MonitoringEffectiveRbacInventory(_StrictMonitoringContract):
    """Hierarchy-complete measured effective assignments for isolated identities."""

    schema_version: Literal["athena.wc028MonitoringEffectiveRbacInventory.v1"] = Field(
        alias="schemaVersion"
    )
    collection_run_id: str = Field(
        alias="collectionRunId",
        pattern=r"^monitoring-rbac-[a-f0-9]{32}$",
    )
    tenant_id: str = Field(
        alias="tenantId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    subscription_id: str = Field(
        alias="subscriptionId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    collector_principal_id: str = Field(
        alias="collectorPrincipalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    athena_context_principal_id: str = Field(
        alias="athenaContextPrincipalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    collected_at: UtcDateTime = Field(alias="collectedAt")
    expires_at: UtcDateTime = Field(alias="expiresAt")
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
    signal_reader_role_actions: tuple[str, ...] = Field(
        alias="signalReaderRoleActions",
        min_length=2,
        max_length=2,
    )
    resource_log_reader_role_actions: tuple[str, ...] = Field(
        alias="resourceLogReaderRoleActions",
        min_length=4,
        max_length=4,
    )
    ip_flow_verify_role_actions: tuple[str, ...] = Field(
        alias="ipFlowVerifyRoleActions",
        min_length=2,
        max_length=2,
    )
    resource_health_role_actions: tuple[str, ...] = Field(
        alias="resourceHealthRoleActions",
        min_length=1,
        max_length=1,
    )
    collector_security_group_ids: tuple[str, ...] = Field(
        default=(),
        alias="collectorSecurityGroupIds",
        max_length=256,
    )
    athena_context_security_group_ids: tuple[str, ...] = Field(
        default=(),
        alias="athenaContextSecurityGroupIds",
        max_length=256,
    )
    collector_grants: tuple[MonitoringEffectiveRbacGrant, ...] = Field(
        alias="collectorGrants",
        max_length=64,
    )
    athena_context_grants: tuple[MonitoringEffectiveRbacGrant, ...] = Field(
        alias="athenaContextGrants",
        max_length=64,
    )
    assignment_count: int = Field(alias="assignmentCount", ge=0, le=1024)
    source_reference: VersionPinnedBlobReference = Field(alias="sourceReference")
    source_manifest_digest: Sha256Digest = Field(alias="sourceManifestDigest")
    inventory_digest: Sha256Digest = Field(alias="inventoryDigest")

    @field_validator(
        "tenant_id",
        "subscription_id",
        "collector_principal_id",
        "athena_context_principal_id",
    )
    @classmethod
    def normalize_guid(cls, value: str) -> str:
        return value.casefold()

    @field_validator(
        "collector_security_group_ids",
        "athena_context_security_group_ids",
    )
    @classmethod
    def normalize_group_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(item.casefold() for item in values))
        if len(normalized) != len(set(normalized)) or any(
            re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{4}-[0-9a-f]{12}",
                item,
            )
            is None
            for item in normalized
        ):
            raise ValueError("effective RBAC security-group IDs must be sorted UUIDs")
        return normalized

    @field_validator(
        "signal_reader_role_actions",
        "resource_log_reader_role_actions",
        "ip_flow_verify_role_actions",
        "resource_health_role_actions",
    )
    @classmethod
    def normalize_role_actions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(item.casefold() for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("effective RBAC role actions must be sorted and unique")
        return normalized

    @field_validator("management_group_ancestry")
    @classmethod
    def normalize_management_group_ancestry(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(_canonical_rbac_scope(item) for item in values)
        if len(normalized) != len(set(normalized)) or any(
            not item.startswith("/providers/microsoft.management/managementgroups/")
            for item in normalized
        ):
            raise ValueError("effective RBAC management-group ancestry must be complete and unique")
        return normalized

    @field_validator("collector_grants", "athena_context_grants")
    @classmethod
    def validate_grant_order(
        cls,
        values: tuple[MonitoringEffectiveRbacGrant, ...],
    ) -> tuple[MonitoringEffectiveRbacGrant, ...]:
        digests = tuple(item.grant_digest for item in values)
        if digests != tuple(sorted(digests)) or len(digests) != len(set(digests)):
            raise ValueError("effective RBAC grants must be sorted and unique")
        return values

    @model_validator(mode="after")
    def validate_inventory(self) -> MonitoringEffectiveRbacInventory:
        if (
            self.collector_principal_id == self.athena_context_principal_id
            or not self.collected_at < self.expires_at
            or (self.expires_at - self.collected_at).total_seconds() > 900
            or self.assignment_count
            != sum(
                len(item.assignment_scope_ids)
                for item in (*self.collector_grants, *self.athena_context_grants)
            )
            or self.source_reference.name
            != (f"monitoring-rbac/{self.collection_run_id}/effective-rbac-inventory.json")
            or self.source_reference.content_digest != self.source_manifest_digest
        ):
            raise ValueError(
                "effective RBAC inventory identity, lifetime, or assignment count is invalid"
            )
        effective_principals = {
            self.collector_principal_id,
            *self.collector_security_group_ids,
        }
        if any(
            item.effective_principal_id != self.collector_principal_id
            or item.assigned_principal_id not in effective_principals
            for item in self.collector_grants
        ):
            raise ValueError(
                "collector effective RBAC grants do not resolve through complete membership"
            )
        context_principals = {
            self.athena_context_principal_id,
            *self.athena_context_security_group_ids,
        }
        if any(
            item.effective_principal_id != self.athena_context_principal_id
            or item.assigned_principal_id not in context_principals
            for item in self.athena_context_grants
        ):
            raise ValueError(
                "Athena context effective RBAC grants do not resolve through complete membership"
            )
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
                exclude={"inventory_digest"},
            )
        )
        if self.inventory_digest != expected:
            raise ValueError("inventoryDigest does not bind effective RBAC evidence")
        return self


class MonitoringCollectorContract(_StrictMonitoringContract):
    """Reviewed generic boundary for one identity-isolated monitoring collector."""

    schema_version: Literal[
        "athena.wc024MonitoringCollectorContract.v2",
        "athena.wc028MonitoringCollectorContract.v3",
        "athena.wc028MonitoringCollectorContract.v4",
        "athena.wc028MonitoringCollectorContract.v5",
        "athena.wc028MonitoringCollectorContract.v6",
        "athena.wc028MonitoringCollectorContract.v7",
    ] = Field(alias="schemaVersion")
    collector_identity_resource_id: str = Field(
        alias="collectorIdentityResourceId",
        min_length=1,
        max_length=2048,
    )
    collector_identity_client_id: str = Field(
        alias="collectorIdentityClientId",
        min_length=1,
        max_length=128,
    )
    collector_tenant_id: str | None = Field(
        default=None,
        alias="collectorTenantId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    monitoring_reader_principal_id: str | None = Field(
        default=None,
        alias="monitoringReaderPrincipalId",
    )
    athena_context_identity_id: str | None = Field(
        default=None,
        alias="athenaContextIdentityId",
        min_length=1,
        max_length=2048,
    )
    athena_context_principal_id: str | None = Field(
        default=None,
        alias="athenaContextPrincipalId",
    )
    physical_identity_separation_enforced: Literal[True] | None = Field(
        default=None,
        alias="physicalIdentitySeparationEnforced",
    )
    monitoring_resource_group_id: str = Field(
        alias="monitoringResourceGroupId",
        min_length=1,
        max_length=2048,
    )
    workload_resource_group_id: str = Field(
        alias="workloadResourceGroupId",
        min_length=1,
        max_length=2048,
    )
    workload_virtual_network_resource_id: str = Field(
        alias="workloadVirtualNetworkResourceId",
        min_length=1,
        max_length=2048,
    )
    approved_vm_names: tuple[str, ...] = Field(
        alias="approvedVmNames",
        min_length=len(_EXPECTED_APPROVED_VM_NAMES),
        max_length=len(_EXPECTED_APPROVED_VM_NAMES),
    )
    workspace_resource_id: str = Field(
        alias="workspaceResourceId",
        min_length=1,
        max_length=2048,
    )
    data_collection_rule_resource_id: str = Field(
        alias="dataCollectionRuleResourceId",
        min_length=1,
        max_length=2048,
    )
    data_collection_endpoint_resource_id: str = Field(
        alias="dataCollectionEndpointResourceId",
        min_length=1,
        max_length=2048,
    )
    authorization_mode: Literal["conditionedWorkspacePlusExactResourceContext"] = Field(
        alias="authorizationMode"
    )
    workspace_access_control_mode: Literal[
        "workspaceAndResourceContext",
        "workspaceOnly",
    ] = Field(alias="workspaceAccessControlMode")
    reader_role_definition_id: str = Field(
        alias="readerRoleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    signal_reader_role_definition_id: str = Field(
        alias="signalReaderRoleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    signal_reader_role_name: str | None = Field(
        default=None,
        alias="signalReaderRoleName",
        min_length=1,
        max_length=256,
    )
    resource_log_reader_role_definition_id: str | None = Field(
        default=None,
        alias="resourceLogReaderRoleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    resource_log_reader_role_name: str | None = Field(
        default=None,
        alias="resourceLogReaderRoleName",
        min_length=1,
        max_length=256,
    )
    resource_log_allowed_operations: tuple[MonitoringResourceLogOperation, ...] | None = Field(
        default=None,
        alias="resourceLogAllowedOperations",
        min_length=len(_EXPECTED_RESOURCE_LOG_OPERATIONS),
        max_length=len(_EXPECTED_RESOURCE_LOG_OPERATIONS),
    )
    resource_log_read_scope_ids: tuple[str, ...] | None = Field(
        default=None,
        alias="resourceLogReadScopeIds",
        min_length=len(_EXPECTED_APPROVED_VM_NAMES),
        max_length=len(_EXPECTED_APPROVED_VM_NAMES),
    )
    log_analytics_data_reader_role_definition_id: str = Field(
        alias="logAnalyticsDataReaderRoleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    ip_flow_verify_role_definition_id: str | None = Field(
        default=None,
        alias="ipFlowVerifyRoleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    ip_flow_verify_role_name: str | None = Field(
        default=None,
        alias="ipFlowVerifyRoleName",
        min_length=1,
        max_length=256,
    )
    ip_flow_verify_scope_id: str | None = Field(
        default=None,
        alias="ipFlowVerifyScopeId",
        min_length=1,
        max_length=2048,
    )
    ip_flow_verify_allowed_operations: tuple[MonitoringIpFlowVerifyOperation, ...] | None = Field(
        default=None,
        alias="ipFlowVerifyAllowedOperations",
        min_length=len(_EXPECTED_IP_FLOW_VERIFY_OPERATIONS),
        max_length=len(_EXPECTED_IP_FLOW_VERIFY_OPERATIONS),
    )
    identity_proof_audience: str | None = Field(
        default=None,
        alias="identityProofAudience",
        pattern=r"^api://[a-z0-9][a-z0-9.-]{2,127}$",
    )
    identity_proof_token_version: Literal["1.0"] | None = Field(
        default=None,
        alias="identityProofTokenVersion",
    )
    identity_proof_required_role: Literal["Athena.MonitoringAcquisition.ProveIdentity"] | None = (
        Field(
            default=None,
            alias="identityProofRequiredRole",
        )
    )
    identity_proof_maximum_lifetime_seconds: Literal[7200] | None = Field(
        default=None,
        alias="identityProofMaximumLifetimeSeconds",
    )
    resource_health_role_definition_id: str | None = Field(
        default=None,
        alias="resourceHealthRoleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    resource_health_role_name: str | None = Field(
        default=None,
        alias="resourceHealthRoleName",
        min_length=1,
        max_length=256,
    )
    resource_health_scope_ids: tuple[str, ...] | None = Field(
        default=None,
        alias="resourceHealthScopeIds",
        min_length=len(_EXPECTED_APPROVED_VM_NAMES),
        max_length=len(_EXPECTED_APPROVED_VM_NAMES),
    )
    resource_health_allowed_operations: tuple[MonitoringResourceHealthOperation, ...] | None = (
        Field(
            default=None,
            alias="resourceHealthAllowedOperations",
            min_length=len(_EXPECTED_RESOURCE_HEALTH_OPERATIONS),
            max_length=len(_EXPECTED_RESOURCE_HEALTH_OPERATIONS),
        )
    )
    log_analytics_allowed_tables: tuple[MonitoringLogTable, ...] = Field(
        alias="logAnalyticsAllowedTables",
        min_length=len(_EXPECTED_LOG_TABLES),
        max_length=len(_EXPECTED_LOG_TABLES),
    )
    log_analytics_access_condition: str = Field(
        alias="logAnalyticsAccessCondition",
        min_length=1,
        max_length=8192,
    )
    resource_read_scope_ids: tuple[str, ...] = Field(
        alias="resourceReadScopeIds",
        min_length=27,
        max_length=27,
    )
    signal_read_scope_ids: tuple[str, ...] = Field(
        alias="signalReadScopeIds",
        min_length=len(_EXPECTED_APPROVED_VM_NAMES),
        max_length=len(_EXPECTED_APPROVED_VM_NAMES),
    )
    signing_key_resource_id: str = Field(
        alias="signingKeyResourceId",
        min_length=1,
        max_length=2048,
    )
    signing_key_arm_resource_id: str | None = Field(
        default=None,
        alias="signingKeyArmResourceId",
        min_length=1,
        max_length=2048,
    )
    signing_key_crypto_user_role_definition_id: str | None = Field(
        default=None,
        alias="signingKeyCryptoUserRoleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    evidence_storage_account_resource_id: str = Field(
        alias="evidenceStorageAccountResourceId",
        min_length=1,
        max_length=2048,
    )
    evidence_container_resource_id: str | None = Field(
        default=None,
        alias="evidenceContainerResourceId",
        min_length=1,
        max_length=2048,
    )
    evidence_writer_role_definition_id: str | None = Field(
        default=None,
        alias="evidenceWriterRoleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    evidence_container_name: Literal["monitoring-evidence"] = Field(alias="evidenceContainerName")
    signal_kinds: tuple[MonitoringSignalKind, ...] = Field(
        alias="signalKinds",
        min_length=len(_EXPECTED_SIGNALS),
        max_length=len(_EXPECTED_SIGNALS),
    )
    allowed_read_operations: tuple[MonitoringReadOperation, ...] = Field(
        alias="allowedReadOperations",
        min_length=len(_EXPECTED_READ_OPERATIONS),
        max_length=len(_EXPECTED_ACQUISITION_READ_OPERATIONS),
    )
    collection_mode: Literal["isolatedSignedCollector"] = Field(alias="collectionMode")
    handoff_schema_version: Literal[
        "athena.wc024MonitoringEvidenceHandoff.v1",
        "athena.wc028MonitoringEvidenceHandoff.v2",
    ] = Field(alias="handoffSchemaVersion")
    acquisition_receipt_schema_version: (
        Literal[
            "athena.wc028MonitoringAcquisitionReceipt.v3",
            "athena.wc028MonitoringAcquisitionReceipt.v4",
            "athena.wc028MonitoringAcquisitionReceipt.v5",
        ]
        | None
    ) = Field(
        default=None,
        alias="acquisitionReceiptSchemaVersion",
    )
    maximum_evidence_age_seconds: int = Field(
        alias="maximumEvidenceAgeSeconds",
        ge=60,
        le=900,
    )
    connection_monitor_mode: Literal["capabilityOnly"] = Field(alias="connectionMonitorMode")
    connection_monitor_deployment_mode: Literal["capability-only"] = Field(
        alias="connectionMonitorDeploymentMode"
    )
    effective_rbac_inventory: MonitoringEffectiveRbacInventory | None = Field(
        default=None,
        alias="effectiveRbacInventory",
    )

    @field_validator(
        "collector_identity_client_id",
        "collector_tenant_id",
        "monitoring_reader_principal_id",
        "athena_context_principal_id",
        mode="before",
    )
    @classmethod
    def canonicalize_identity_guid(cls, value: object) -> object:
        return value.casefold() if type(value) is str else value

    @field_validator("workload_virtual_network_resource_id")
    @classmethod
    def canonicalize_workload_vnet_id(cls, value: str) -> str:
        subscription_id, resource_group, provider, resource_types = _parse_arm_resource_id(value)
        if (
            resource_group == _REVIEWED_WORKLOAD_RESOURCE_GROUP
            and provider == "microsoft.network"
            and resource_types == ("virtualnetworks",)
            and value.rsplit("/", 1)[-1].casefold() == _REVIEWED_WORKLOAD_VNET_NAME
        ):
            return (
                f"/subscriptions/{subscription_id}/resourceGroups/"
                f"{_REVIEWED_WORKLOAD_RESOURCE_GROUP}/providers/"
                "Microsoft.Network/virtualNetworks/"
                f"{_REVIEWED_WORKLOAD_VNET_NAME}"
            )
        return value

    @model_validator(mode="after")
    def require_complete_generic_monitoring_allowlist(self) -> MonitoringCollectorContract:
        if (
            self.schema_version == MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION
            and self.handoff_schema_version != MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION
        ) or (
            self.schema_version
            in {
                MONITORING_LEGACY_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
                MONITORING_PREVIOUS_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
                MONITORING_IDENTITY_PROOF_COLLECTOR_CONTRACT_SCHEMA_VERSION,
                MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
                MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            }
            and self.handoff_schema_version != MONITORING_ACQUISITION_HANDOFF_SCHEMA_VERSION
        ):
            raise ValueError("collector contract version does not authorize its handoff schema")
        if self.signal_kinds != _EXPECTED_SIGNALS:
            raise ValueError("monitoring signals must use the complete reviewed generic allowlist")
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION:
            expected_read_operations = _EXPECTED_ACQUISITION_READ_OPERATIONS
        elif (
            self.schema_version
            == MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION
        ):
            expected_read_operations = _EXPECTED_PREVIOUS_PRODUCTION_ACQUISITION_READ_OPERATIONS
        elif self.schema_version in {
            MONITORING_PREVIOUS_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_IDENTITY_PROOF_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        }:
            expected_read_operations = _EXPECTED_PREVIOUS_ACQUISITION_READ_OPERATIONS
        else:
            expected_read_operations = _EXPECTED_READ_OPERATIONS
        if self.allowed_read_operations != expected_read_operations:
            raise ValueError("monitoring read operations must use the complete reviewed allowlist")
        if self.log_analytics_allowed_tables != _EXPECTED_LOG_TABLES:
            raise ValueError("Log Analytics tables must use the complete reviewed allowlist")
        normalized_condition = "".join(self.log_analytics_access_condition.split())
        expected_condition = "".join(_EXPECTED_LOG_ANALYTICS_ACCESS_CONDITION.split())
        if normalized_condition != expected_condition:
            raise ValueError(
                "Log Analytics access condition must restrict data reads to the "
                "reviewed table allowlist"
            )
        acquisition_identity_fields = (
            self.monitoring_reader_principal_id,
            self.athena_context_identity_id,
            self.athena_context_principal_id,
            self.physical_identity_separation_enforced,
        )
        credential_and_ip_flow_fields = (
            self.collector_tenant_id,
            self.ip_flow_verify_role_definition_id,
            self.ip_flow_verify_scope_id,
            self.ip_flow_verify_allowed_operations,
        )
        identity_proof_fields = (
            self.identity_proof_audience,
            self.identity_proof_token_version,
            self.identity_proof_required_role,
            self.identity_proof_maximum_lifetime_seconds,
        )
        resource_health_fields = (
            self.resource_health_role_definition_id,
            self.resource_health_scope_ids,
            self.resource_health_allowed_operations,
        )
        measured_rbac_fields = (
            self.signal_reader_role_name,
            self.resource_log_reader_role_definition_id,
            self.resource_log_reader_role_name,
            self.resource_log_allowed_operations,
            self.resource_log_read_scope_ids,
            self.ip_flow_verify_role_name,
            self.resource_health_role_name,
            self.signing_key_arm_resource_id,
            self.signing_key_crypto_user_role_definition_id,
            self.evidence_container_resource_id,
            self.evidence_writer_role_definition_id,
            self.effective_rbac_inventory,
        )
        if self.schema_version == MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION:
            if any(
                item is not None
                for item in (
                    *acquisition_identity_fields,
                    *credential_and_ip_flow_fields,
                    *identity_proof_fields,
                    *resource_health_fields,
                    *measured_rbac_fields,
                    self.acquisition_receipt_schema_version,
                )
            ):
                raise ValueError("WC-024 collector contract cannot contain acquisition identities")
        elif any(item is None for item in acquisition_identity_fields):
            raise ValueError("WC-028 collector contract requires physical identity separation")
        else:
            try:
                reader_principal = UUID(cast(str, self.monitoring_reader_principal_id))
                context_principal = UUID(cast(str, self.athena_context_principal_id))
            except ValueError as exc:
                raise ValueError("collector principal IDs must be UUIDs") from exc
            if (
                reader_principal == context_principal
                or self.collector_identity_resource_id.casefold().rstrip("/")
                == cast(str, self.athena_context_identity_id).casefold().rstrip("/")
            ):
                raise ValueError("collector and Athena context identities must be separate")
        if (
            self.schema_version == MONITORING_LEGACY_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION
            and any(
                item is not None
                for item in (
                    *credential_and_ip_flow_fields,
                    *identity_proof_fields,
                    *resource_health_fields,
                    *measured_rbac_fields,
                    self.acquisition_receipt_schema_version,
                )
            )
        ):
            raise ValueError(
                "legacy WC-028 collector contract cannot contain credential or IP Flow policy"
            )
        if self.schema_version in {
            MONITORING_PREVIOUS_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_IDENTITY_PROOF_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        }:
            if any(item is None for item in credential_and_ip_flow_fields):
                raise ValueError(
                    "credential-bound WC-028 collector contract requires exact IP Flow policy"
                )
            if self.ip_flow_verify_allowed_operations != _EXPECTED_IP_FLOW_VERIFY_OPERATIONS:
                raise ValueError("IP Flow Verify operations must use the exact reviewed allowlist")
            try:
                UUID(cast(str, self.collector_tenant_id))
            except ValueError as exc:
                raise ValueError("collector tenant ID must be a UUID") from exc
        if (
            self.schema_version == MONITORING_PREVIOUS_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION
            and (
                any(item is not None for item in identity_proof_fields)
                or any(item is not None for item in resource_health_fields)
                or self.acquisition_receipt_schema_version
                != "athena.wc028MonitoringAcquisitionReceipt.v3"
            )
        ):
            raise ValueError(
                "legacy credential-bound collector contract must use receipt v3 "
                "without Athena identity proof policy"
            )
        if self.schema_version in {
            MONITORING_IDENTITY_PROOF_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        } and (
            any(item is None for item in identity_proof_fields)
            or self.identity_proof_audience != MONITORING_IDENTITY_PROOF_AUDIENCE
            or self.identity_proof_token_version != MONITORING_IDENTITY_PROOF_TOKEN_VERSION
            or self.identity_proof_required_role != MONITORING_IDENTITY_PROOF_REQUIRED_ROLE
            or self.identity_proof_maximum_lifetime_seconds
            != MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ):
            raise ValueError(
                "production collector contract requires the exact Athena identity proof policy"
            )
        if (
            self.schema_version
            in {
                MONITORING_IDENTITY_PROOF_COLLECTOR_CONTRACT_SCHEMA_VERSION,
                MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            }
            and self.acquisition_receipt_schema_version
            != MONITORING_PREVIOUS_ACQUISITION_RECEIPT_SCHEMA_VERSION
        ):
            raise ValueError(
                "legacy identity-proof collector contract must use acquisition receipt v4"
            )
        if (
            self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION
            and self.acquisition_receipt_schema_version
            != MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION
        ):
            raise ValueError("current collector contract must use acquisition receipt v5")
        if (
            self.schema_version == MONITORING_IDENTITY_PROOF_COLLECTOR_CONTRACT_SCHEMA_VERSION
            and any(item is not None for item in resource_health_fields)
        ):
            raise ValueError(
                "legacy identity-proof collector contract cannot contain Resource Health policy"
            )
        if self.schema_version in {
            MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        } and (
            any(item is None for item in resource_health_fields)
            or self.resource_health_allowed_operations != _EXPECTED_RESOURCE_HEALTH_OPERATIONS
        ):
            raise ValueError("production collector contract requires exact Resource Health policy")
        if self.schema_version != MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION and any(
            item is not None for item in measured_rbac_fields
        ):
            raise ValueError("legacy collector contracts cannot contain measured RBAC policy")
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION and (
            any(item is None for item in measured_rbac_fields)
            or self.resource_log_allowed_operations != _EXPECTED_RESOURCE_LOG_OPERATIONS
            or self.workspace_access_control_mode != "workspaceAndResourceContext"
        ):
            raise ValueError(
                "current collector contract requires resource-context logs and measured RBAC"
            )
        try:
            UUID(self.collector_identity_client_id)
        except ValueError as exc:
            raise ValueError("collector identity client ID must be a UUID") from exc

        (
            monitoring_subscription,
            monitoring_resource_group,
            monitoring_provider,
            monitoring_types,
        ) = _parse_arm_resource_id(self.monitoring_resource_group_id)
        if monitoring_provider is not None or monitoring_types:
            raise ValueError("monitoring scope must be a resource-group ID")
        workload_subscription, workload_resource_group, workload_provider, workload_types = (
            _parse_arm_resource_id(self.workload_resource_group_id)
        )
        if workload_provider is not None or workload_types:
            raise ValueError("workload scope must be a resource-group ID")
        if workload_subscription != monitoring_subscription:
            raise ValueError("workload scope must use the monitoring deployment subscription")
        if workload_resource_group != _REVIEWED_WORKLOAD_RESOURCE_GROUP:
            raise ValueError("workload scope must be the reviewed WC-024 workload resource group")
        if self.approved_vm_names != _EXPECTED_APPROVED_VM_NAMES:
            raise ValueError("approved VMs must match the exact reviewed WC-024 VM allowlist")
        (
            workload_vnet_subscription,
            workload_vnet_resource_group,
            workload_vnet_provider,
            workload_vnet_types,
        ) = _parse_arm_resource_id(self.workload_virtual_network_resource_id)
        if (
            workload_vnet_subscription != monitoring_subscription
            or workload_vnet_resource_group != _REVIEWED_WORKLOAD_RESOURCE_GROUP
            or workload_vnet_provider != "microsoft.network"
            or workload_vnet_types != ("virtualnetworks",)
            or self.workload_virtual_network_resource_id.rsplit("/", 1)[-1].casefold()
            != _REVIEWED_WORKLOAD_VNET_NAME
        ):
            raise ValueError("workload VNet must match the exact reviewed WC-024 boundary")
        if _KEY_VAULT_KEY_ID_PATTERN.fullmatch(self.signing_key_resource_id) is None:
            raise ValueError("signing key must be an exact versioned Key Vault key URI")
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION and (
            cast(str, self.signal_reader_role_name).startswith(_SIGNAL_READER_ROLE_NAME_PREFIX)
            is not True
            or self.resource_log_reader_role_name != _RESOURCE_LOG_READER_ROLE_NAME
            or self.ip_flow_verify_role_name != _IP_FLOW_VERIFY_ROLE_NAME
            or self.resource_health_role_name != _RESOURCE_HEALTH_ROLE_NAME
        ):
            raise ValueError("current collector contract role names do not match deployed roles")

        expected_role_definition_ids = (
            (
                self.reader_role_definition_id,
                _READER_ROLE_DEFINITION_GUID,
                "Reader",
            ),
            (
                self.signal_reader_role_definition_id,
                _SIGNAL_READER_ROLE_DEFINITION_GUID,
                "signal reader",
            ),
            (
                self.log_analytics_data_reader_role_definition_id,
                _LOG_ANALYTICS_DATA_READER_ROLE_DEFINITION_GUID,
                "Log Analytics Data Reader",
            ),
        )
        for role_definition_id, role_guid, role_name in expected_role_definition_ids:
            expected_role_definition_id = (
                f"/subscriptions/{monitoring_subscription}/providers/"
                f"Microsoft.Authorization/roleDefinitions/{role_guid}"
            )
            if role_definition_id.casefold() != expected_role_definition_id.casefold():
                raise ValueError(
                    f"{role_name} role definition must match the reviewed built-in "
                    "or existing narrow role"
                )

        expected_network_watcher_scope_id = (
            f"/subscriptions/{monitoring_subscription}/resourceGroups/"
            f"{_REVIEWED_NETWORK_WATCHER_RESOURCE_GROUP}/providers/"
            f"Microsoft.Network/networkWatchers/{_REVIEWED_NETWORK_WATCHER_NAME}"
        )
        if self.schema_version in {
            MONITORING_PREVIOUS_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_IDENTITY_PROOF_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        }:
            expected_ip_flow_role_definition_id = (
                f"/subscriptions/{monitoring_subscription}/resourceGroups/"
                f"{_REVIEWED_NETWORK_WATCHER_RESOURCE_GROUP}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{_IP_FLOW_VERIFY_ROLE_DEFINITION_GUID}"
            )
            if (
                cast(str, self.ip_flow_verify_role_definition_id).casefold()
                != expected_ip_flow_role_definition_id.casefold()
            ):
                raise ValueError(
                    "IP Flow Verify role definition must match the exact reviewed custom role"
                )
            if (
                cast(str, self.ip_flow_verify_scope_id).casefold().rstrip("/")
                != expected_network_watcher_scope_id.casefold()
            ):
                raise ValueError(
                    "IP Flow Verify role assignment must target the exact Network Watcher"
                )

        monitoring_resource_group_root = (
            f"/subscriptions/{monitoring_subscription}/resourceGroups/"
            f"{_REVIEWED_MONITORING_RESOURCE_GROUP}"
        )
        workload_resource_group_root = (
            f"/subscriptions/{monitoring_subscription}/resourceGroups/"
            f"{_REVIEWED_WORKLOAD_RESOURCE_GROUP}"
        )
        expected_signal_read_scope_ids = tuple(
            (
                f"{workload_resource_group_root}/providers/Microsoft.Compute/"
                f"virtualMachines/{vm_name}"
            )
            for vm_name in _EXPECTED_APPROVED_VM_NAMES
        )
        if tuple(scope.casefold() for scope in self.signal_read_scope_ids) != tuple(
            scope.casefold() for scope in expected_signal_read_scope_ids
        ):
            raise ValueError("signal-reader scopes must match the exact reviewed VMs")
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION:
            expected_resource_log_role_definition_id = (
                f"{workload_resource_group_root}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{_RESOURCE_LOG_READER_ROLE_DEFINITION_GUID}"
            )
            if cast(
                str,
                self.resource_log_reader_role_definition_id,
            ).casefold() != expected_resource_log_role_definition_id.casefold() or tuple(
                scope.casefold()
                for scope in cast(
                    tuple[str, ...],
                    self.resource_log_read_scope_ids,
                )
            ) != tuple(scope.casefold() for scope in expected_signal_read_scope_ids):
                raise ValueError(
                    "resource-log reader role and scopes must match exact approved VMs"
                )
        if self.schema_version in {
            MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        }:
            expected_resource_health_role_definition_id = (
                f"{workload_resource_group_root}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{_RESOURCE_HEALTH_ROLE_DEFINITION_GUID}"
            )
            if (
                cast(str, self.resource_health_role_definition_id).casefold()
                != expected_resource_health_role_definition_id.casefold()
            ):
                raise ValueError(
                    "Resource Health role definition must match the exact reviewed custom role"
                )
            if tuple(
                scope.casefold() for scope in cast(tuple[str, ...], self.resource_health_scope_ids)
            ) != tuple(scope.casefold() for scope in expected_signal_read_scope_ids):
                raise ValueError("Resource Health assignments must match the exact approved VMs")

        expected_resource_read_scope_ids = (
            (
                f"{monitoring_resource_group_root}/providers/Microsoft.Insights/"
                f"dataCollectionEndpoints/{_REVIEWED_DCE_NAME}"
            ),
            (
                f"{monitoring_resource_group_root}/providers/Microsoft.Insights/"
                f"dataCollectionRules/{_REVIEWED_DCR_NAME}"
            ),
            *(
                (
                    f"{monitoring_resource_group_root}/providers/Microsoft.Insights/"
                    f"privateLinkScopes/{scope_name}"
                )
                for scope_name in _REVIEWED_AMPLS_NAMES
            ),
            *(
                (
                    f"{workload_resource_group_root}/providers/Microsoft.Compute/"
                    f"virtualMachines/{vm_name}/providers/Microsoft.Insights/"
                    "dataCollectionRuleAssociations/athena-linux-dcr"
                )
                for vm_name in _EXPECTED_APPROVED_VM_NAMES
            ),
            *(
                (
                    f"{workload_resource_group_root}/providers/Microsoft.Compute/"
                    f"virtualMachines/{vm_name}/providers/Microsoft.Insights/"
                    "dataCollectionRuleAssociations/configurationAccessEndpoint"
                )
                for vm_name in _EXPECTED_APPROVED_VM_NAMES
            ),
            (
                f"/subscriptions/{monitoring_subscription}/resourceGroups/"
                f"{_REVIEWED_NETWORK_WATCHER_RESOURCE_GROUP}/providers/"
                f"Microsoft.Network/networkWatchers/{_REVIEWED_NETWORK_WATCHER_NAME}/"
                f"flowLogs/{_REVIEWED_FLOW_LOG_NAME}"
            ),
        )
        if tuple(scope.casefold() for scope in self.resource_read_scope_ids) != tuple(
            scope.casefold() for scope in expected_resource_read_scope_ids
        ):
            raise ValueError("Reader scopes must match the exact reviewed monitoring resources")

        resource_bindings = (
            (
                self.collector_identity_resource_id,
                "microsoft.managedidentity",
                ("userassignedidentities",),
                "collector identity",
            ),
            (
                self.workspace_resource_id,
                "microsoft.operationalinsights",
                ("workspaces",),
                "workspace",
            ),
            (
                self.data_collection_rule_resource_id,
                "microsoft.insights",
                ("datacollectionrules",),
                "data collection rule",
            ),
            (
                self.data_collection_endpoint_resource_id,
                "microsoft.insights",
                ("datacollectionendpoints",),
                "data collection endpoint",
            ),
            (
                self.evidence_storage_account_resource_id,
                "microsoft.storage",
                ("storageaccounts",),
                "evidence storage account",
            ),
        )
        for resource_id, provider, resource_types, resource_name in resource_bindings:
            resource_subscription, resource_group, actual_provider, actual_types = (
                _parse_arm_resource_id(resource_id)
            )
            if (
                resource_subscription != monitoring_subscription
                or resource_group != monitoring_resource_group
                or actual_provider != provider
                or actual_types != resource_types
            ):
                raise ValueError(
                    f"{resource_name} must be the expected monitoring-scoped ARM resource"
                )
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION:
            expected_evidence_writer_role_id = (
                f"/subscriptions/{monitoring_subscription}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{_STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE_DEFINITION_GUID}"
            )
            expected_signing_key_role_id = (
                f"/subscriptions/{monitoring_subscription}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{_KEY_VAULT_CRYPTO_USER_ROLE_DEFINITION_GUID}"
            )
            if (
                cast(str, self.evidence_writer_role_definition_id).casefold()
                != expected_evidence_writer_role_id.casefold()
                or cast(
                    str,
                    self.signing_key_crypto_user_role_definition_id,
                ).casefold()
                != expected_signing_key_role_id.casefold()
            ):
                raise ValueError(
                    "evidence persistence roles must match the exact reviewed built-ins"
                )
            signing_key_arm_id = cast(str, self.signing_key_arm_resource_id)
            (
                signing_key_subscription,
                signing_key_resource_group,
                signing_key_provider,
                signing_key_types,
            ) = _parse_arm_resource_id(signing_key_arm_id)
            evidence_container_id = cast(str, self.evidence_container_resource_id)
            (
                evidence_subscription,
                evidence_resource_group,
                evidence_provider,
                evidence_types,
            ) = _parse_arm_resource_id(evidence_container_id)
            signing_key_uri_segments = self.signing_key_resource_id.split("/")
            if (
                signing_key_subscription != monitoring_subscription
                or signing_key_resource_group != monitoring_resource_group
                or signing_key_provider != "microsoft.keyvault"
                or signing_key_types != ("vaults", "keys")
                or signing_key_arm_id.rsplit("/", 1)[-1].casefold()
                != signing_key_uri_segments[-2].casefold()
                or signing_key_arm_id.split("/")[-3].casefold()
                != signing_key_uri_segments[2].split(".", 1)[0].casefold()
            ):
                raise ValueError("signing-key ARM scope must match the exact versioned signing key")
            if (
                evidence_subscription != monitoring_subscription
                or evidence_resource_group != monitoring_resource_group
                or evidence_provider != "microsoft.storage"
                or evidence_types != ("storageaccounts", "blobservices", "containers")
                or not evidence_container_id.casefold().endswith(
                    "/blobservices/default/containers/monitoring-evidence"
                )
                or not evidence_container_id.casefold().startswith(
                    self.evidence_storage_account_resource_id.casefold().rstrip("/") + "/"
                )
            ):
                raise ValueError(
                    "evidence container must match the exact monitoring storage boundary"
                )
            inventory = cast(
                MonitoringEffectiveRbacInventory,
                self.effective_rbac_inventory,
            )
            if (
                inventory.tenant_id != cast(str, self.collector_tenant_id)
                or inventory.subscription_id != monitoring_subscription
                or inventory.collector_principal_id
                != cast(str, self.monitoring_reader_principal_id)
                or inventory.athena_context_principal_id
                != cast(str, self.athena_context_principal_id)
                or inventory.signal_reader_role_actions
                != tuple(
                    sorted(
                        (
                            "microsoft.compute/virtualmachines/instanceview/read",
                            "microsoft.insights/metrics/read",
                        )
                    )
                )
                or inventory.resource_log_reader_role_actions
                != tuple(sorted(item.casefold() for item in _EXPECTED_RESOURCE_LOG_OPERATIONS))
                or inventory.ip_flow_verify_role_actions
                != tuple(sorted(item.casefold() for item in _EXPECTED_IP_FLOW_VERIFY_OPERATIONS))
                or inventory.resource_health_role_actions
                != tuple(item.casefold() for item in _EXPECTED_RESOURCE_HEALTH_OPERATIONS)
                or inventory.collector_grants != _expected_monitoring_effective_rbac_grants(self)
                or any(
                    _effective_grant_affects_acquisition_scope(item, self)
                    for item in inventory.athena_context_grants
                )
            ):
                raise ValueError(
                    "effective RBAC inventory does not match exact deployed assignments"
                )
        return self


def _effective_rbac_grant(
    *,
    principal_id: str,
    role_definition_id: str,
    role_definition_name: str,
    assignment_scope_ids: tuple[str, ...],
    condition: str | None = None,
    condition_version: Literal["2.0"] | None = None,
) -> MonitoringEffectiveRbacGrant:
    normalized_scopes = tuple(sorted(_canonical_rbac_scope(item) for item in assignment_scope_ids))
    payload: dict[str, object] = {
        "assignedPrincipalId": principal_id.casefold(),
        "assignedPrincipalType": "ServicePrincipal",
        "effectivePrincipalId": principal_id.casefold(),
        "roleDefinitionId": role_definition_id.casefold().rstrip("/"),
        "roleDefinitionName": role_definition_name,
        "assignmentScopeIds": normalized_scopes,
        "inheritance": "direct",
        "groupDerived": False,
        "condition": condition,
        "conditionVersion": condition_version,
    }
    digest_payload = {
        **payload,
        "assignmentScopeIds": list(normalized_scopes),
    }
    if condition is None:
        digest_payload.pop("condition")
        digest_payload.pop("conditionVersion")
    return MonitoringEffectiveRbacGrant.model_validate(
        {
            **payload,
            "grantDigest": compute_artifact_digest(digest_payload),
        }
    )


def _expected_monitoring_effective_rbac_grants(
    contract: MonitoringCollectorContract,
) -> tuple[MonitoringEffectiveRbacGrant, ...]:
    principal_id = cast(str, contract.monitoring_reader_principal_id)
    grants = (
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=contract.reader_role_definition_id,
            role_definition_name="Reader",
            assignment_scope_ids=contract.resource_read_scope_ids,
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=contract.signal_reader_role_definition_id,
            role_definition_name=cast(str, contract.signal_reader_role_name),
            assignment_scope_ids=contract.signal_read_scope_ids,
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=cast(
                str,
                contract.resource_log_reader_role_definition_id,
            ),
            role_definition_name=cast(
                str,
                contract.resource_log_reader_role_name,
            ),
            assignment_scope_ids=cast(
                tuple[str, ...],
                contract.resource_log_read_scope_ids,
            ),
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=cast(
                str,
                contract.resource_health_role_definition_id,
            ),
            role_definition_name=cast(str, contract.resource_health_role_name),
            assignment_scope_ids=cast(
                tuple[str, ...],
                contract.resource_health_scope_ids,
            ),
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=cast(
                str,
                contract.ip_flow_verify_role_definition_id,
            ),
            role_definition_name=cast(str, contract.ip_flow_verify_role_name),
            assignment_scope_ids=(cast(str, contract.ip_flow_verify_scope_id),),
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=cast(
                str,
                contract.evidence_writer_role_definition_id,
            ),
            role_definition_name=_STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE_NAME,
            assignment_scope_ids=(cast(str, contract.evidence_container_resource_id),),
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=cast(
                str,
                contract.signing_key_crypto_user_role_definition_id,
            ),
            role_definition_name=_KEY_VAULT_CRYPTO_USER_ROLE_NAME,
            assignment_scope_ids=(cast(str, contract.signing_key_arm_resource_id),),
        ),
    )
    return tuple(sorted(grants, key=lambda item: item.grant_digest))


def _effective_grant_affects_acquisition_scope(
    grant: MonitoringEffectiveRbacGrant,
    contract: MonitoringCollectorContract,
) -> bool:
    watcher_segments = cast(str, contract.ip_flow_verify_scope_id).split("/")
    network_watcher_resource_group = "/".join(watcher_segments[:5])
    protected_roots = (
        contract.workload_resource_group_id.casefold().rstrip("/"),
        contract.monitoring_resource_group_id.casefold().rstrip("/"),
        network_watcher_resource_group.casefold().rstrip("/"),
    )
    subscription_scope = (
        f"/subscriptions/{_parse_arm_resource_id(contract.workload_resource_group_id)[0]}"
    )
    for scope in grant.assignment_scope_ids:
        if (
            scope == "/"
            or scope.startswith("/providers/microsoft.management/managementgroups/")
            or scope == subscription_scope
            or any(
                scope == root or scope.startswith(root + "/") or root.startswith(scope + "/")
                for root in protected_roots
            )
        ):
            return True
    return False


class MonitoringEvidenceAttestation(_StrictMonitoringContract):
    """Detached signature metadata that binds one immutable collector handoff."""

    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    trust_anchor_ref: str = Field(alias="trustAnchorRef", min_length=1, max_length=2048)
    signed_preimage_digest: str = Field(
        alias="signedPreimageDigest",
        pattern=_DIGEST_PATTERN,
    )
    signature: str = Field(min_length=1, max_length=8192)

    @field_validator("signature")
    @classmethod
    def validate_signature_encoding(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("monitoring handoff signature must be standard base64") from exc
        if not decoded:
            raise ValueError("monitoring handoff signature must not be empty")
        return value


class MonitoringCredentialProof(_StrictMonitoringContract):
    """Legacy proof derived from Azure service tokens; never trusted for production v4 receipts."""

    schema_version: Literal["athena.wc028MonitoringCredentialProof.v1"] = Field(
        alias="schemaVersion"
    )
    tenant_id: str = Field(
        alias="tenantId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    principal_id: str = Field(
        alias="principalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    client_id: str = Field(
        alias="clientId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    subject: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    issuer: str = Field(min_length=1, max_length=256)
    audience: Literal[
        "https://api.loganalytics.io",
        "https://api.loganalytics.io/",
        "https://management.azure.com/",
        "https://management.core.windows.net/",
    ]
    token_hash: Sha256Digest = Field(alias="tokenHash")
    key_id: str = Field(alias="keyId", pattern=r"^[A-Za-z0-9_-]{8,256}$")
    issued_at: UtcDateTime = Field(alias="issuedAt")
    not_before: UtcDateTime = Field(alias="notBefore")
    expires_at: UtcDateTime = Field(alias="expiresAt")
    verified_at: UtcDateTime = Field(alias="verifiedAt")
    proof_digest: Sha256Digest = Field(alias="proofDigest")

    @model_validator(mode="after")
    def validate_proof(self) -> MonitoringCredentialProof:
        allowed_issuers = {
            f"https://login.microsoftonline.com/{self.tenant_id}/v2.0",
            f"https://sts.windows.net/{self.tenant_id}/",
        }
        if self.issuer not in allowed_issuers:
            raise ValueError("credential proof issuer does not match the reviewed tenant")
        if self.subject not in {self.principal_id, self.client_id}:
            raise ValueError("credential proof subject does not match the reviewed identity")
        if not self.issued_at <= self.not_before <= self.verified_at < self.expires_at:
            raise ValueError("credential proof is outside its verified token lifetime")
        if (
            self.expires_at - self.issued_at
        ).total_seconds() > _MAX_VERIFIED_TOKEN_LIFETIME_SECONDS:
            raise ValueError("credential proof token lifetime exceeds the reviewed bound")
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"proof_digest"},
            )
        )
        if self.proof_digest != expected:
            raise ValueError("proofDigest does not bind the verified credential")
        return self


class MonitoringIdentityProof(_StrictMonitoringContract):
    """Normalized proof from the Athena-owned single-tenant identity-proof audience."""

    schema_version: Literal["athena.wc028MonitoringIdentityProof.v1"] = Field(alias="schemaVersion")
    token_version: Literal["1.0"] = Field(alias="tokenVersion")
    tenant_id: str = Field(
        alias="tenantId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    principal_id: str = Field(
        alias="principalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    client_id: str = Field(
        alias="clientId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    subject: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    issuer: str = Field(min_length=1, max_length=256)
    audience: str = Field(
        pattern=r"^api://[a-z0-9][a-z0-9.-]{2,127}$",
    )
    identity_type: Literal["app"] = Field(alias="identityType")
    roles: tuple[str, ...] = Field(min_length=1, max_length=8)
    token_hash: Sha256Digest = Field(alias="tokenHash")
    key_id: str = Field(alias="keyId", pattern=r"^[A-Za-z0-9_-]{8,256}$")
    issued_at: UtcDateTime = Field(alias="issuedAt")
    not_before: UtcDateTime = Field(alias="notBefore")
    expires_at: UtcDateTime = Field(alias="expiresAt")
    verified_at: UtcDateTime = Field(alias="verifiedAt")
    proof_digest: Sha256Digest = Field(alias="proofDigest")

    @model_validator(mode="after")
    def validate_proof(self) -> MonitoringIdentityProof:
        if self.issuer != f"https://sts.windows.net/{self.tenant_id}/":
            raise ValueError("identity proof issuer does not match pinned token version and tenant")
        if self.subject not in {self.principal_id, self.client_id}:
            raise ValueError("identity proof subject does not match the reviewed identity")
        if self.roles != tuple(sorted(self.roles)) or len(self.roles) != len(set(self.roles)):
            raise ValueError("identity proof roles must be sorted and unique")
        if not self.issued_at <= self.not_before <= self.verified_at < self.expires_at:
            raise ValueError("identity proof is outside its verified token lifetime")
        if (
            self.expires_at - self.issued_at
        ).total_seconds() > MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS:
            raise ValueError("identity proof token lifetime exceeds the reviewed bound")
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"proof_digest"},
            )
        )
        if self.proof_digest != expected:
            raise ValueError("proofDigest does not bind the normalized identity proof")
        return self


class MonitoringAcquisitionExchange(_StrictMonitoringContract):
    """Collector-timed receipt entry for one exact Azure acquisition call."""

    sequence: int = Field(ge=1, le=32)
    source: Literal[
        "activityLog",
        "ipFlowVerify",
        "logAnalytics",
        "resourceGraph",
        "resourceHealth",
    ]
    request_digest: str = Field(alias="requestDigest", pattern=_DIGEST_PATTERN)
    result_digest: str = Field(alias="resultDigest", pattern=_DIGEST_PATTERN)
    requested_at: UtcDateTime = Field(alias="requestedAt")
    received_at: UtcDateTime = Field(alias="receivedAt")
    checked_at: UtcDateTime | None = Field(default=None, alias="checkedAt")
    credential_proof_digest: Sha256Digest | None = Field(
        default=None,
        alias="credentialProofDigest",
    )
    identity_proof_digest: Sha256Digest | None = Field(
        default=None,
        alias="identityProofDigest",
    )

    @model_validator(mode="after")
    def validate_exchange(self) -> MonitoringAcquisitionExchange:
        if self.requested_at > self.received_at:
            raise ValueError("acquisition exchange receipt times are reversed")
        if self.source == "ipFlowVerify":
            if (
                self.checked_at is None
                or self.checked_at < self.requested_at
                or self.checked_at > self.received_at
            ):
                raise ValueError("IP Flow receipt requires a collector-bounded checkedAt")
        elif self.checked_at is not None:
            raise ValueError("only IP Flow receipt entries may contain checkedAt")
        return self


class MonitoringIncidentHealthSampleBinding(_StrictMonitoringContract):
    """Signed binding from one source health record to its persisted observation."""

    record_kind: MonitoringHealthRecordKind = Field(alias="recordKind")
    source_record_id: str = Field(
        alias="sourceRecordId",
        min_length=1,
        max_length=2048,
    )
    source_record_reference: str = Field(
        alias="sourceRecordReference",
        pattern=r"^[a-z-]+:sha256:[a-f0-9]{64}$",
    )
    observation_id: str = Field(
        alias="observationId",
        pattern=r"^obs-[a-f0-9]{32}$",
    )
    control_id: str = Field(
        alias="controlId",
        pattern=r"^monitoring-control-[a-f0-9]{32}$",
    )
    resource_id: str = Field(
        alias="resourceId",
        min_length=1,
        max_length=2048,
    )
    state: Literal["healthy", "degraded", "unhealthy", "unavailable"]
    observed_start: UtcDateTime = Field(alias="observedStart")
    observed_end: UtcDateTime = Field(alias="observedEnd")
    sample_digest: Sha256Digest = Field(alias="sampleDigest")

    @field_validator("resource_id")
    @classmethod
    def normalize_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        _parse_arm_resource_id(normalized)
        return normalized

    @model_validator(mode="after")
    def validate_sample(self) -> MonitoringIncidentHealthSampleBinding:
        if self.source_record_reference != monitoring_health_source_record_reference(
            self.record_kind,
            self.source_record_id,
        ):
            raise ValueError("incident sample sourceRecordReference does not bind sourceRecordId")
        if self.observed_start > self.observed_end:
            raise ValueError("incident sample interval is invalid")
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"sample_digest"},
            )
        )
        if self.sample_digest != expected:
            raise ValueError("sampleDigest does not bind the incident health sample")
        return self


class MonitoringIncidentSelection(_StrictMonitoringContract):
    """Collector-signed canonical incident seed selected from acquired health records."""

    incident_resource_id: str = Field(
        alias="incidentResourceId",
        min_length=1,
        max_length=2048,
    )
    previous_health: MonitoringIncidentHealthSampleBinding = Field(alias="previousHealth")
    current_health: tuple[MonitoringIncidentHealthSampleBinding, ...] = Field(
        alias="currentHealth",
        min_length=1,
        max_length=32,
    )
    transition_digest: Sha256Digest = Field(alias="transitionDigest")

    @field_validator("incident_resource_id")
    @classmethod
    def normalize_incident_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        _parse_arm_resource_id(normalized)
        return normalized

    @model_validator(mode="after")
    def validate_selection(self) -> MonitoringIncidentSelection:
        current_keys = tuple(
            (item.source_record_reference, item.observation_id) for item in self.current_health
        )
        current_states = {item.state for item in self.current_health}
        current_controls = {item.control_id for item in self.current_health}
        if (
            self.previous_health.state != "healthy"
            or not current_states
            or not current_states.issubset({"degraded", "unhealthy", "unavailable"})
            or len(current_states) != 1
            or len(current_controls) != 1
            or self.previous_health.control_id not in current_controls
            or self.previous_health.resource_id != self.incident_resource_id
            or any(item.resource_id != self.incident_resource_id for item in self.current_health)
            or self.previous_health.observed_end
            > min(item.observed_start for item in self.current_health)
            or current_keys != tuple(sorted(current_keys))
            or len(current_keys) != len(set(current_keys))
            or self.previous_health.observation_id
            in {item.observation_id for item in self.current_health}
        ):
            raise ValueError(
                "incident selection is not one deterministic healthy-to-adverse transition"
            )
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"transition_digest"},
            )
        )
        if self.transition_digest != expected:
            raise ValueError("transitionDigest does not bind the incident selection")
        return self


class MonitoringAcquisitionReceipt(_StrictMonitoringContract):
    """Immutable collector-signed provenance for one bounded acquisition execution."""

    schema_version: Literal[
        "athena.wc028MonitoringAcquisitionReceipt.v1",
        "athena.wc028MonitoringAcquisitionReceipt.v2",
        "athena.wc028MonitoringAcquisitionReceipt.v3",
        "athena.wc028MonitoringAcquisitionReceipt.v4",
        "athena.wc028MonitoringAcquisitionReceipt.v5",
    ] = Field(alias="schemaVersion")
    receipt_id: str = Field(
        alias="receiptId",
        pattern=r"^monitoring-acquisition-receipt-[a-f0-9]{32}$",
    )
    authenticated_principal_id: str = Field(
        alias="authenticatedPrincipalId",
        min_length=1,
        max_length=2048,
    )
    authenticated_client_id: str | None = Field(
        default=None,
        alias="authenticatedClientId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    authenticated_tenant_id: str | None = Field(
        default=None,
        alias="authenticatedTenantId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    monitoring_reader_identity_id: str | None = Field(
        default=None,
        alias="monitoringReaderIdentityId",
        min_length=1,
        max_length=2048,
    )
    athena_context_identity_id: str = Field(
        alias="athenaContextIdentityId",
        min_length=1,
        max_length=2048,
    )
    athena_context_principal_id: str | None = Field(
        default=None,
        alias="athenaContextPrincipalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    deployment_identity_contract_digest: str = Field(
        alias="deploymentIdentityContractDigest",
        pattern=_DIGEST_PATTERN,
    )
    acquisition_authority_digest: str = Field(
        alias="acquisitionAuthorityDigest",
        pattern=_DIGEST_PATTERN,
    )
    collector_contract_digest: str = Field(
        alias="collectorContractDigest",
        pattern=_DIGEST_PATTERN,
    )
    intent_id: str = Field(
        alias="intentId",
        pattern=r"^monitoring-intent-[a-f0-9]{32}$",
    )
    intent_digest: str = Field(alias="intentDigest", pattern=_DIGEST_PATTERN)
    context_binding_digest: str = Field(
        alias="contextBindingDigest",
        pattern=_DIGEST_PATTERN,
    )
    collection_batch_digest: str = Field(
        alias="collectionBatchDigest",
        pattern=_DIGEST_PATTERN,
    )
    normalized_evidence_digest: str = Field(
        alias="normalizedEvidenceDigest",
        pattern=_DIGEST_PATTERN,
    )
    incident_selection: MonitoringIncidentSelection | None = Field(
        default=None,
        alias="incidentSelection",
    )
    execution_started_at: UtcDateTime = Field(alias="executionStartedAt")
    execution_completed_at: UtcDateTime = Field(alias="executionCompletedAt")
    receipt_issued_at: UtcDateTime = Field(alias="receiptIssuedAt")
    exchanges: tuple[MonitoringAcquisitionExchange, ...] = Field(
        min_length=1,
        max_length=32,
    )
    receipt_digest: str = Field(alias="receiptDigest", pattern=_DIGEST_PATTERN)
    credential_proofs: tuple[MonitoringCredentialProof, ...] | None = Field(
        default=None,
        alias="credentialProofs",
        min_length=1,
        max_length=2,
    )
    identity_proof: MonitoringIdentityProof | None = Field(
        default=None,
        alias="identityProof",
    )
    collector_attestation: MonitoringEvidenceAttestation = Field(alias="collectorAttestation")

    @model_validator(mode="after")
    def validate_receipt(self) -> MonitoringAcquisitionReceipt:
        if self.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v1":
            if (
                self.monitoring_reader_identity_id is not None
                or self.athena_context_principal_id is not None
                or self.authenticated_client_id is not None
                or self.authenticated_tenant_id is not None
                or self.credential_proofs is not None
                or self.identity_proof is not None
                or self.incident_selection is not None
                or any(item.credential_proof_digest is not None for item in self.exchanges)
                or any(item.identity_proof_digest is not None for item in self.exchanges)
            ):
                raise ValueError("v1 acquisition receipt cannot contain newer identity bindings")
        elif self.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v2":
            if (
                self.monitoring_reader_identity_id is None
                or self.athena_context_principal_id is None
                or re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    self.authenticated_principal_id,
                )
                is None
                or self.authenticated_client_id is not None
                or self.authenticated_tenant_id is not None
                or self.credential_proofs is not None
                or self.identity_proof is not None
                or self.incident_selection is not None
                or any(item.credential_proof_digest is not None for item in self.exchanges)
                or any(item.identity_proof_digest is not None for item in self.exchanges)
            ):
                raise ValueError(
                    "v2 acquisition receipt requires only resource and principal identities"
                )
        elif self.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v3":
            if (
                self.monitoring_reader_identity_id is None
                or self.athena_context_principal_id is None
                or self.authenticated_client_id is None
                or self.authenticated_tenant_id is None
                or self.credential_proofs is None
                or self.identity_proof is not None
                or self.incident_selection is not None
                or re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    self.authenticated_principal_id,
                )
                is None
                or any(item.identity_proof_digest is not None for item in self.exchanges)
            ):
                raise ValueError("v3 acquisition receipt requires only legacy service-token proofs")
        else:
            identity_proof_invalid = (
                self.monitoring_reader_identity_id is None
                or self.athena_context_principal_id is None
                or self.authenticated_client_id is None
                or self.authenticated_tenant_id is None
                or self.identity_proof is None
                or self.credential_proofs is not None
                or re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    self.authenticated_principal_id,
                )
                is None
                or any(item.credential_proof_digest is not None for item in self.exchanges)
            )
            if self.schema_version == MONITORING_PREVIOUS_ACQUISITION_RECEIPT_SCHEMA_VERSION:
                if identity_proof_invalid or self.incident_selection is not None:
                    raise ValueError(
                        "v4 acquisition receipt requires only one Athena identity proof"
                    )
            elif identity_proof_invalid or self.incident_selection is None:
                raise ValueError(
                    "v5 acquisition receipt requires identity proof and incident selection"
                )
        if self.schema_version in {
            "athena.wc028MonitoringAcquisitionReceipt.v2",
            "athena.wc028MonitoringAcquisitionReceipt.v3",
            "athena.wc028MonitoringAcquisitionReceipt.v4",
        } and (
            cast(str, self.monitoring_reader_identity_id).casefold().rstrip("/")
            == self.athena_context_identity_id.casefold().rstrip("/")
            or self.authenticated_principal_id == self.athena_context_principal_id
        ):
            raise ValueError(
                "acquisition principal must be separate from the Athena context identity"
            )
        if self.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v3":
            proofs = cast(tuple[MonitoringCredentialProof, ...], self.credential_proofs)
            proof_digests = {item.proof_digest for item in proofs}
            if (
                proofs != tuple(sorted(proofs, key=lambda item: (item.audience, item.proof_digest)))
                or len({item.audience for item in proofs}) != len(proofs)
                or any(
                    proof.principal_id != self.authenticated_principal_id
                    or proof.client_id != self.authenticated_client_id
                    or proof.tenant_id != self.authenticated_tenant_id
                    or proof.verified_at != self.execution_started_at
                    for proof in proofs
                )
                or {item.credential_proof_digest for item in self.exchanges} != proof_digests
            ):
                raise ValueError(
                    "credential proof does not bind every acquisition exchange and identity"
                )
        if self.schema_version in {
            MONITORING_PREVIOUS_ACQUISITION_RECEIPT_SCHEMA_VERSION,
            MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
        }:
            proof = cast(MonitoringIdentityProof, self.identity_proof)
            if (
                proof.principal_id != self.authenticated_principal_id
                or proof.client_id != self.authenticated_client_id
                or proof.tenant_id != self.authenticated_tenant_id
                or proof.verified_at != self.execution_started_at
                or any(item.identity_proof_digest != proof.proof_digest for item in self.exchanges)
            ):
                raise ValueError(
                    "Athena identity proof does not bind every acquisition exchange and identity"
                )
        if not (self.execution_started_at <= self.execution_completed_at <= self.receipt_issued_at):
            raise ValueError("acquisition receipt times are reversed")
        if tuple(item.sequence for item in self.exchanges) != tuple(
            range(1, len(self.exchanges) + 1)
        ):
            raise ValueError("acquisition exchanges must use contiguous execution order")
        request_digests = tuple(item.request_digest for item in self.exchanges)
        if len(request_digests) != len(set(request_digests)):
            raise ValueError("acquisition receipt request digests must be unique")
        if any(
            item.requested_at < self.execution_started_at
            or item.received_at > self.execution_completed_at
            for item in self.exchanges
        ):
            raise ValueError("acquisition exchanges escape collector execution time")
        if any(
            item.source == "ipFlowVerify"
            and (
                item.checked_at is None
                or item.checked_at < self.execution_started_at
                or item.checked_at > item.received_at
            )
            for item in self.exchanges
        ):
            raise ValueError("IP Flow checkedAt must use collector-owned execution time")
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
                exclude={"receipt_id", "receipt_digest", "collector_attestation"},
            )
        )
        if self.receipt_digest != expected:
            raise ValueError("receiptDigest does not bind the acquisition receipt")
        if self.receipt_id != (
            f"monitoring-acquisition-receipt-{expected.removeprefix('sha256:')[:32]}"
        ):
            raise ValueError("receiptId is not digest-bound")
        if self.collector_attestation.signed_preimage_digest != compute_artifact_digest(
            monitoring_acquisition_receipt_preimage(self)
        ):
            raise ValueError("acquisition receipt attestation does not bind the exact receipt")
        return self


class MonitoringEvidenceHandoff(_StrictMonitoringContract):
    """Version-pinned evidence reference emitted only by the isolated collector."""

    schema_version: Literal[
        "athena.wc024MonitoringEvidenceHandoff.v1",
        "athena.wc028MonitoringEvidenceHandoff.v2",
    ] = Field(alias="schemaVersion")
    collector_contract_digest: str = Field(
        alias="collectorContractDigest",
        pattern=_DIGEST_PATTERN,
    )
    collection_id: str = Field(alias="collectionId", pattern=_COLLECTION_ID_PATTERN)
    observed_at: UtcDateTime = Field(alias="observedAt")
    acquisition_receipt_digest: str | None = Field(
        default=None,
        alias="acquisitionReceiptDigest",
        pattern=_DIGEST_PATTERN,
    )
    evidence: VersionPinnedBlobReference
    collector_attestation: MonitoringEvidenceAttestation = Field(alias="collectorAttestation")

    @model_validator(mode="after")
    def bind_exact_evidence_and_attestation(self) -> MonitoringEvidenceHandoff:
        expected_name = f"wc024-monitoring/{self.collection_id}/evidence.json"
        if self.evidence.name != expected_name:
            raise ValueError("monitoring evidence reference name is not deterministic")
        if (
            self.schema_version == MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION
            and self.acquisition_receipt_digest is not None
        ):
            raise ValueError("legacy monitoring handoff cannot contain acquisition provenance")
        if (
            self.schema_version == MONITORING_ACQUISITION_HANDOFF_SCHEMA_VERSION
            and self.acquisition_receipt_digest is None
        ):
            raise ValueError("WC028 monitoring handoff requires acquisition provenance")
        if self.collector_attestation.signed_preimage_digest != compute_artifact_digest(
            monitoring_handoff_preimage(self)
        ):
            raise ValueError(
                "monitoring handoff attestation does not bind the exact evidence reference"
            )
        return self


def monitoring_handoff_preimage(
    handoff: MonitoringEvidenceHandoff | dict[str, object],
) -> dict[str, object]:
    """Return the domain-separated content signed by the evidence collector."""

    if isinstance(handoff, MonitoringEvidenceHandoff):
        payload = handoff.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"collector_attestation"},
        )
    else:
        payload = handoff
    return {
        "domain": payload["schemaVersion"],
        "handoff": payload,
    }


def monitoring_acquisition_receipt_preimage(
    receipt: MonitoringAcquisitionReceipt | dict[str, object],
) -> dict[str, object]:
    """Return domain-separated acquisition provenance signed by the collector."""

    if isinstance(receipt, MonitoringAcquisitionReceipt):
        payload = receipt.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"collector_attestation"},
        )
    else:
        payload = receipt
    return {
        "domain": payload["schemaVersion"],
        "receipt": payload,
    }


def _resolve_reviewed_contract_binding(
    *,
    reviewed_collector_contract: MonitoringCollectorContract | None,
    expected_collector_contract_digest: str | None,
    reviewed_maximum_evidence_age_seconds: int | None,
    reviewed_signing_key_resource_id: str | None,
) -> tuple[str, int, str]:
    if reviewed_collector_contract is not None:
        reviewed_digest = reviewed_collector_contract.compute_artifact_digest_value()
        reviewed_max_age = reviewed_collector_contract.maximum_evidence_age_seconds
        if (
            expected_collector_contract_digest is not None
            and expected_collector_contract_digest != reviewed_digest
        ):
            raise ValueError("monitoring handoff does not bind the expected collector contract")
        if (
            reviewed_maximum_evidence_age_seconds is not None
            and reviewed_maximum_evidence_age_seconds != reviewed_max_age
        ):
            raise ValueError(
                "monitoring handoff freshness policy does not match the reviewed contract"
            )
        if (
            reviewed_signing_key_resource_id is not None
            and reviewed_signing_key_resource_id
            != reviewed_collector_contract.signing_key_resource_id
        ):
            raise ValueError("monitoring handoff signing key does not match the reviewed contract")
        return (
            reviewed_digest,
            reviewed_max_age,
            reviewed_collector_contract.signing_key_resource_id,
        )

    if expected_collector_contract_digest is None:
        raise ValueError(
            "monitoring handoff verification requires a reviewed collector contract digest"
        )
    if reviewed_maximum_evidence_age_seconds is None:
        raise ValueError(
            "monitoring handoff verification requires the reviewed maximum evidence age"
        )
    if reviewed_signing_key_resource_id is None:
        raise ValueError("monitoring handoff verification requires the reviewed signing key")
    if not isinstance(reviewed_maximum_evidence_age_seconds, int) or not (
        60 <= reviewed_maximum_evidence_age_seconds <= 900
    ):
        raise ValueError("monitoring handoff reviewed maximum evidence age is invalid")
    if _KEY_VAULT_KEY_ID_PATTERN.fullmatch(reviewed_signing_key_resource_id) is None:
        raise ValueError("monitoring handoff reviewed signing key is invalid")
    return (
        expected_collector_contract_digest,
        reviewed_maximum_evidence_age_seconds,
        reviewed_signing_key_resource_id,
    )


def _require_trusted_as_of(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("monitoring handoff verification as_of must be a trusted UTC timestamp")
    if value.microsecond % 1000:
        raise ValueError(
            "monitoring handoff verification as_of precision must be exactly representable "
            "in milliseconds"
        )


def verify_monitoring_evidence_handoff_attestation(
    handoff: MonitoringEvidenceHandoff,
    *,
    as_of: datetime,
    trusted_key_anchor: TrustedKeyAnchor,
    key_resolver: TrustedKeyResolver,
    reviewed_collector_contract: MonitoringCollectorContract | None = None,
    expected_collector_contract_digest: str | None = None,
    reviewed_maximum_evidence_age_seconds: int | None = None,
    reviewed_signing_key_resource_id: str | None = None,
    expected_handoff_schema_version: str | None = None,
) -> None:
    """Fail closed unless a reviewed contract, trusted time, and exact key bind the handoff.

    Callers must provide either the full reviewed collector contract, or its digest,
    handoff schema, maximum evidence age, and signing key. ``as_of`` is supplied by
    the trusted caller so verification never depends on local wall-clock time.
    """

    attestation = handoff.collector_attestation
    expected_digest, maximum_age_seconds, reviewed_signing_key = _resolve_reviewed_contract_binding(
        reviewed_collector_contract=reviewed_collector_contract,
        expected_collector_contract_digest=expected_collector_contract_digest,
        reviewed_maximum_evidence_age_seconds=reviewed_maximum_evidence_age_seconds,
        reviewed_signing_key_resource_id=reviewed_signing_key_resource_id,
    )
    _require_trusted_as_of(as_of)
    if (
        not re.fullmatch(_DIGEST_PATTERN, expected_digest)
        or handoff.collector_contract_digest != expected_digest
    ):
        raise ValueError("monitoring handoff does not bind the expected collector contract")
    if reviewed_collector_contract is None:
        if expected_handoff_schema_version is None:
            raise ValueError("digest-only verification requires the reviewed handoff schema")
        if handoff.schema_version != expected_handoff_schema_version:
            raise ValueError("monitoring handoff schema does not match the reviewed schema")
    if (
        reviewed_collector_contract is not None
        and handoff.schema_version != reviewed_collector_contract.handoff_schema_version
    ):
        raise ValueError(
            "monitoring handoff schema is not authorized by the reviewed collector contract"
        )
    if (
        handoff.schema_version == MONITORING_ACQUISITION_HANDOFF_SCHEMA_VERSION
        and reviewed_collector_contract is None
    ):
        raise ValueError(
            "receipt-bearing handoff verification requires the full reviewed collector contract"
        )
    if handoff.observed_at > as_of:
        raise ValueError("monitoring handoff observation time is in the future")
    if (as_of - handoff.observed_at).total_seconds() > maximum_age_seconds:
        raise ValueError("monitoring handoff evidence is older than the reviewed maximum age")
    if reviewed_signing_key != trusted_key_anchor.key_vault_key_id:
        raise ValueError("monitoring handoff signing key does not match the trusted key")
    if attestation.trust_anchor_ref != trusted_key_anchor.key_vault_key_id:
        raise ValueError("monitoring handoff attestation uses an untrusted key")
    record = key_resolver(trusted_key_anchor)
    if (
        record is None
        or record.anchor != trusted_key_anchor
        or not record.enabled
        or record.activated_at > handoff.observed_at
        or (record.retired_at is not None and record.retired_at <= as_of)
        or (record.expires_at is not None and record.expires_at <= as_of)
        or not isinstance(record.public_key, rsa.RSAPublicKey)
    ):
        raise ValueError("monitoring handoff attestation key is not trusted")
    try:
        signature = base64.b64decode(attestation.signature, validate=True)
        record.public_key.verify(
            signature,
            canonicalize_json(monitoring_handoff_preimage(handoff)).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("monitoring handoff attestation signature is invalid") from exc


def verify_monitoring_acquisition_receipt_attestation(
    receipt: MonitoringAcquisitionReceipt,
    *,
    as_of: datetime,
    trusted_key_anchor: TrustedKeyAnchor,
    key_resolver: TrustedKeyResolver,
    reviewed_collector_contract: MonitoringCollectorContract,
    expected_acquisition_authority_digest: str,
    maximum_receipt_age_seconds: int,
) -> None:
    """Reverify signed acquisition provenance against one full reviewed contract."""

    _require_trusted_as_of(as_of)
    if not isinstance(maximum_receipt_age_seconds, int) or not (
        60 <= maximum_receipt_age_seconds <= 3600
    ):
        raise ValueError("acquisition receipt maximum age is invalid")
    if (
        type(reviewed_collector_contract) is not MonitoringCollectorContract
        or reviewed_collector_contract.schema_version
        != MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION
        or reviewed_collector_contract.acquisition_receipt_schema_version
        != MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION
        or reviewed_collector_contract.monitoring_reader_principal_id is None
        or reviewed_collector_contract.athena_context_identity_id is None
        or reviewed_collector_contract.athena_context_principal_id is None
        or reviewed_collector_contract.collector_tenant_id is None
        or reviewed_collector_contract.identity_proof_audience is None
        or reviewed_collector_contract.identity_proof_token_version is None
        or reviewed_collector_contract.identity_proof_required_role is None
        or reviewed_collector_contract.identity_proof_maximum_lifetime_seconds is None
        or reviewed_collector_contract.resource_health_role_definition_id is None
        or reviewed_collector_contract.resource_health_scope_ids is None
        or reviewed_collector_contract.resource_health_allowed_operations is None
        or reviewed_collector_contract.resource_log_allowed_operations is None
        or reviewed_collector_contract.effective_rbac_inventory is None
    ):
        raise ValueError(
            "production acquisition verification requires the credential-bound collector contract"
        )
    expected_authenticated_principal_id = cast(
        str,
        reviewed_collector_contract.monitoring_reader_principal_id,
    )
    expected_monitoring_reader_identity_id = (
        reviewed_collector_contract.collector_identity_resource_id
    )
    expected_authenticated_client_id = reviewed_collector_contract.collector_identity_client_id
    expected_authenticated_tenant_id = cast(
        str,
        reviewed_collector_contract.collector_tenant_id,
    )
    expected_athena_context_identity_id = cast(
        str,
        reviewed_collector_contract.athena_context_identity_id,
    )
    expected_athena_context_principal_id = cast(
        str,
        reviewed_collector_contract.athena_context_principal_id,
    )
    expected_collector_contract_digest = reviewed_collector_contract.compute_artifact_digest_value()
    expected_receipt_signing_key_id = reviewed_collector_contract.signing_key_resource_id
    if (
        receipt.schema_version != MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION
        or receipt.monitoring_reader_identity_id is None
        or receipt.athena_context_principal_id is None
        or receipt.authenticated_client_id is None
        or receipt.authenticated_tenant_id is None
        or receipt.identity_proof is None
        or receipt.incident_selection is None
    ):
        raise ValueError("production verification requires incident-bound acquisition receipt v5")
    effective_rbac_inventory = cast(
        MonitoringEffectiveRbacInventory,
        reviewed_collector_contract.effective_rbac_inventory,
    )
    deployment_digest = compute_artifact_digest(
        {
            "monitoringReaderIdentityId": (
                expected_monitoring_reader_identity_id.casefold().rstrip("/")
            ),
            "monitoringReaderPrincipalId": expected_authenticated_principal_id.casefold(),
            "monitoringReaderClientId": expected_authenticated_client_id.casefold(),
            "monitoringReaderTenantId": expected_authenticated_tenant_id.casefold(),
            "athenaContextIdentityId": (expected_athena_context_identity_id.casefold().rstrip("/")),
            "athenaContextPrincipalId": expected_athena_context_principal_id.casefold(),
            "effectiveRbacInventoryDigest": effective_rbac_inventory.inventory_digest,
            "effectiveRbacSourceManifestDigest": (effective_rbac_inventory.source_manifest_digest),
        }
    )
    if (
        expected_monitoring_reader_identity_id.casefold().rstrip("/")
        == expected_athena_context_identity_id.casefold().rstrip("/")
        or expected_authenticated_principal_id.casefold()
        == expected_athena_context_principal_id.casefold()
    ):
        raise ValueError("deployed acquisition identity separation is invalid")
    if not (
        effective_rbac_inventory.collected_at
        <= receipt.execution_started_at
        < effective_rbac_inventory.expires_at
    ):
        raise ValueError(
            "acquisition receipt execution is outside measured effective RBAC lifetime"
        )
    if (
        receipt.acquisition_authority_digest != expected_acquisition_authority_digest
        or receipt.collector_contract_digest != expected_collector_contract_digest
        or receipt.deployment_identity_contract_digest != deployment_digest
        or receipt.authenticated_principal_id.casefold().rstrip("/")
        != expected_authenticated_principal_id.casefold().rstrip("/")
        or receipt.authenticated_client_id.casefold() != expected_authenticated_client_id.casefold()
        or receipt.authenticated_tenant_id.casefold() != expected_authenticated_tenant_id.casefold()
        or receipt.monitoring_reader_identity_id.casefold().rstrip("/")
        != expected_monitoring_reader_identity_id.casefold().rstrip("/")
        or receipt.athena_context_identity_id.casefold().rstrip("/")
        != expected_athena_context_identity_id.casefold().rstrip("/")
        or receipt.athena_context_principal_id.casefold()
        != expected_athena_context_principal_id.casefold()
        or receipt.identity_proof.principal_id.casefold()
        != expected_authenticated_principal_id.casefold()
        or receipt.identity_proof.client_id.casefold()
        != expected_authenticated_client_id.casefold()
        or receipt.identity_proof.tenant_id.casefold()
        != expected_authenticated_tenant_id.casefold()
        or receipt.identity_proof.audience != reviewed_collector_contract.identity_proof_audience
        or receipt.identity_proof.token_version
        != reviewed_collector_contract.identity_proof_token_version
        or receipt.identity_proof.identity_type != "app"
        or receipt.identity_proof.roles
        != (reviewed_collector_contract.identity_proof_required_role,)
    ):
        raise ValueError("acquisition receipt does not match deployed acquisition authority")
    if (
        expected_receipt_signing_key_id != trusted_key_anchor.key_vault_key_id
        or receipt.collector_attestation.trust_anchor_ref != expected_receipt_signing_key_id
    ):
        raise ValueError("acquisition receipt signing key is not authority-approved")
    if receipt.receipt_issued_at > as_of:
        raise ValueError("acquisition receipt was issued in the future")
    if (as_of - receipt.receipt_issued_at).total_seconds() > maximum_receipt_age_seconds:
        raise ValueError("acquisition receipt is older than the reviewed maximum age")
    record = key_resolver(trusted_key_anchor)
    if (
        record is None
        or record.anchor != trusted_key_anchor
        or not record.enabled
        or record.activated_at > receipt.execution_started_at
        or (record.retired_at is not None and record.retired_at <= as_of)
        or (record.expires_at is not None and record.expires_at <= as_of)
        or not isinstance(record.public_key, rsa.RSAPublicKey)
    ):
        raise ValueError("acquisition receipt attestation key is not trusted")
    try:
        signature = base64.b64decode(
            receipt.collector_attestation.signature,
            validate=True,
        )
        record.public_key.verify(
            signature,
            canonicalize_json(monitoring_acquisition_receipt_preimage(receipt)).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("acquisition receipt attestation signature is invalid") from exc


__all__ = [
    "MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION",
    "MONITORING_ACQUISITION_HANDOFF_SCHEMA_VERSION",
    "MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION",
    "MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION",
    "MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION",
    "MONITORING_IDENTITY_PROOF_AUDIENCE",
    "MONITORING_IDENTITY_PROOF_COLLECTOR_CONTRACT_SCHEMA_VERSION",
    "MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS",
    "MONITORING_IDENTITY_PROOF_REQUIRED_ROLE",
    "MONITORING_IDENTITY_PROOF_TOKEN_VERSION",
    "MONITORING_LEGACY_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION",
    "MONITORING_PREVIOUS_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION",
    "MONITORING_PREVIOUS_ACQUISITION_RECEIPT_SCHEMA_VERSION",
    "MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION",
    "MonitoringAcquisitionExchange",
    "MonitoringAcquisitionReceipt",
    "MonitoringCollectorContract",
    "MonitoringCredentialProof",
    "MonitoringEffectiveRbacGrant",
    "MonitoringEffectiveRbacInventory",
    "MonitoringEvidenceAttestation",
    "MonitoringEvidenceHandoff",
    "MonitoringIdentityProof",
    "MonitoringIncidentHealthSampleBinding",
    "MonitoringIncidentSelection",
    "MonitoringIpFlowVerifyOperation",
    "MonitoringReadOperation",
    "MonitoringResourceLogOperation",
    "MonitoringResourceHealthOperation",
    "MonitoringSignalKind",
    "monitoring_acquisition_receipt_preimage",
    "monitoring_handoff_preimage",
    "verify_monitoring_acquisition_receipt_attestation",
    "verify_monitoring_evidence_handoff_attestation",
]
