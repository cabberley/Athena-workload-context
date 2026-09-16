from __future__ import annotations

import base64
import re
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from ipaddress import ip_address
from typing import Literal, cast
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ConfigDict, Field, ValidationInfo, field_validator, model_validator

from athena_context.contracts.common import canonicalize_json, compute_artifact_digest
from athena_context.contracts.models import (
    AthenaBaseModel,
    Sha256Digest,
    TrustedKeyAnchor,
    TrustedKeyResolver,
    UtcDateTime,
)
from athena_context.contracts.operational_phase import VersionPinnedBlobReference
from athena_context.monitoring_incident import build_selected_incident

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
MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION = (
    "athena.wc028MonitoringCollectorContract.v7"
)
MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION = (
    "athena.wc028MonitoringCollectorContract.v8"
)
MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION = "athena.wc024MonitoringEvidenceHandoff.v1"
MONITORING_PREVIOUS_ACQUISITION_RECEIPT_SCHEMA_VERSION = (
    "athena.wc028MonitoringAcquisitionReceipt.v4"
)
MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION = "athena.wc028MonitoringAcquisitionReceipt.v5"
MONITORING_ACQUISITION_HANDOFF_SCHEMA_VERSION = "athena.wc028MonitoringEvidenceHandoff.v2"
_LEGACY_MONITORING_IDENTITY_PROOF_AUDIENCE = "api://athena-monitoring-identity-proof"
_MONITORING_IDENTITY_PROOF_AUDIENCE_SUFFIX = "/athena-monitoring-identity-proof"
MONITORING_IDENTITY_PROOF_AUDIENCE = (
    f"api://00000000-0000-0000-0000-000000000003{_MONITORING_IDENTITY_PROOF_AUDIENCE_SUFFIX}"
)
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
    "Microsoft.ResourceHealth/AvailabilityStatuses/current/read",
    "Microsoft.ResourceGraph/resources/read",
    "Microsoft.Insights/logs/Heartbeat/read",
    "Microsoft.Insights/logs/VMConnection/read",
    "Microsoft.Insights/logs/NWConnectionMonitorTestResult/read",
    "Microsoft.Insights/logs/NTANetAnalytics/read",
    "Microsoft.Insights/Logs/Heartbeat/Read",
    "Microsoft.Insights/Logs/Perf/Read",
    "Microsoft.Insights/Logs/InsightsMetrics/Read",
    "Microsoft.Insights/Logs/Syslog/Read",
    "Microsoft.Insights/Logs/VMConnection/Read",
]
type MonitoringIpFlowVerifyOperation = Literal[
    "Microsoft.Network/networkWatchers/ipFlowVerify/action",
    "Microsoft.Network/networkWatchers/ipFlowVerify/read",
]
type MonitoringResourceHealthOperation = Literal[
    "Microsoft.ResourceHealth/AvailabilityStatuses/read",
    "Microsoft.ResourceHealth/AvailabilityStatuses/current/read",
    "Microsoft.ResourceGraph/resources/read",
]
type MonitoringResourceLogOperation = Literal[
    "Microsoft.Insights/logs/Heartbeat/read",
    "Microsoft.Insights/logs/VMConnection/read",
    "Microsoft.Insights/logs/NWConnectionMonitorTestResult/read",
    "Microsoft.Insights/logs/NTANetAnalytics/read",
    "Microsoft.Insights/Logs/Heartbeat/Read",
    "Microsoft.Insights/Logs/Perf/Read",
    "Microsoft.Insights/Logs/InsightsMetrics/Read",
    "Microsoft.Insights/Logs/Syslog/Read",
    "Microsoft.Insights/Logs/VMConnection/Read",
]
type MonitoringResourceContextLogTable = Literal[
    "Heartbeat",
    "Perf",
    "InsightsMetrics",
    "Syslog",
    "VMConnection",
]
type MonitoringRbacAttestorOperation = Literal[
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/roleDefinitions/read",
    "Microsoft.Authorization/denyAssignments/read",
    "Microsoft.Authorization/roleAssignmentScheduleInstances/read",
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
_RBAC_ATTESTOR_ROLE_DEFINITION_GUID = "2a8d9aea-2688-5841-a7e4-82f23d0f1bac"
_STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE_DEFINITION_GUID = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
_KEY_VAULT_CRYPTO_USER_ROLE_DEFINITION_GUID = "12338af0-0e69-4776-bea7-57ae8d297424"
_SIGNAL_READER_ROLE_NAME_PREFIX = "Athena WC016 Approved Signal Reader "
_RESOURCE_LOG_READER_ROLE_NAME = "Athena WC-028 VM Resource Log Reader"
_IP_FLOW_VERIFY_ROLE_NAME = "Athena WC-028 Network Watcher IP Flow Verify"
_RESOURCE_HEALTH_ROLE_NAME = "Athena WC-028 VM Resource Health Reader"
_RBAC_ATTESTOR_ROLE_NAME = "Athena WC-028 Effective RBAC Attestor"
_STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE_NAME = "Storage Blob Data Contributor"
_KEY_VAULT_CRYPTO_USER_ROLE_NAME = "Key Vault Crypto User"
_ALL_PRINCIPALS_ID = "00000000-0000-0000-0000-000000000000"
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
    "Microsoft.ResourceGraph/resources/read",
)
_EXPECTED_RESOURCE_LOG_OPERATIONS: tuple[MonitoringResourceLogOperation, ...] = (
    "Microsoft.Insights/Logs/Heartbeat/Read",
    "Microsoft.Insights/Logs/Perf/Read",
    "Microsoft.Insights/Logs/InsightsMetrics/Read",
    "Microsoft.Insights/Logs/Syslog/Read",
    "Microsoft.Insights/Logs/VMConnection/Read",
)
_EXPECTED_PREVIOUS_RESOURCE_HEALTH_OPERATIONS: tuple[MonitoringResourceHealthOperation, ...] = (
    "Microsoft.ResourceHealth/AvailabilityStatuses/read",
)
_EXPECTED_PREVIOUS_RESOURCE_LOG_OPERATIONS: tuple[MonitoringResourceLogOperation, ...] = (
    "Microsoft.Insights/logs/Heartbeat/read",
    "Microsoft.Insights/logs/NTANetAnalytics/read",
    "Microsoft.Insights/logs/NWConnectionMonitorTestResult/read",
    "Microsoft.Insights/logs/VMConnection/read",
)
_EXPECTED_RESOURCE_CONTEXT_LOG_TABLES: tuple[MonitoringResourceContextLogTable, ...] = (
    "Heartbeat",
    "Perf",
    "InsightsMetrics",
    "Syslog",
    "VMConnection",
)
_EXPECTED_RBAC_ATTESTOR_OPERATIONS: tuple[MonitoringRbacAttestorOperation, ...] = (
    "Microsoft.Authorization/denyAssignments/read",
    "Microsoft.Authorization/roleAssignmentScheduleInstances/read",
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/roleDefinitions/read",
)
_EXPECTED_PREVIOUS_PRODUCTION_ACQUISITION_READ_OPERATIONS: tuple[MonitoringReadOperation, ...] = (
    *_EXPECTED_PREVIOUS_ACQUISITION_READ_OPERATIONS,
    *_EXPECTED_PREVIOUS_RESOURCE_HEALTH_OPERATIONS,
)
_EXPECTED_PREVIOUS_MEASURED_RBAC_READ_OPERATIONS: tuple[MonitoringReadOperation, ...] = (
    *_EXPECTED_READ_OPERATIONS[3:],
    *_EXPECTED_IP_FLOW_VERIFY_OPERATIONS,
    *_EXPECTED_PREVIOUS_RESOURCE_HEALTH_OPERATIONS,
    *_EXPECTED_PREVIOUS_RESOURCE_LOG_OPERATIONS,
)
_EXPECTED_ACQUISITION_READ_OPERATIONS: tuple[MonitoringReadOperation, ...] = (
    *_EXPECTED_READ_OPERATIONS[3:],
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


class MonitoringResourceContextTablePlan(_StrictMonitoringContract):
    """Observed Analytics-plan state for one resource-context log table."""

    table: MonitoringResourceContextLogTable
    plan: Literal["Analytics"]
    table_resource_id: str = Field(
        alias="tableResourceId",
        min_length=1,
        max_length=2048,
    )

    @field_validator("table_resource_id")
    @classmethod
    def normalize_table_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        _parse_arm_resource_id(normalized)
        return normalized


class MonitoringLogPermissionResource(_StrictMonitoringContract):
    """One resource entry from the Logs query permissions payload."""

    resource_id: str = Field(alias="resourceId", min_length=1, max_length=2048)
    data_source_ids: tuple[str, ...] = Field(
        alias="dataSourceIds",
        min_length=1,
        max_length=16,
    )
    deny_tables: tuple[str, ...] = Field(
        default=(),
        alias="denyTables",
        max_length=256,
    )

    @field_validator("resource_id")
    @classmethod
    def normalize_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        _parse_arm_resource_id(normalized)
        return normalized

    @field_validator("data_source_ids")
    @classmethod
    def normalize_data_sources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(item.casefold().rstrip("/") for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("permission data sources must be sorted and unique")
        for value in normalized:
            _, _, provider, types = _parse_arm_resource_id(value)
            if provider != "microsoft.operationalinsights" or types != ("workspaces",):
                raise ValueError("permission data sources must identify Log Analytics workspaces")
        return normalized

    @field_validator("deny_tables")
    @classmethod
    def normalize_deny_tables(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(values, key=str.casefold))
        if len({item.casefold() for item in normalized}) != len(normalized):
            raise ValueError("permission deny tables must be unique")
        return normalized


class MonitoringLogPermissionDataSource(_StrictMonitoringContract):
    """One workspace entry from the Logs query permissions payload."""

    resource_id: str = Field(alias="resourceId", min_length=1, max_length=2048)
    deny_tables: tuple[str, ...] = Field(
        default=(),
        alias="denyTables",
        max_length=256,
    )

    @field_validator("resource_id")
    @classmethod
    def normalize_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        _, _, provider, types = _parse_arm_resource_id(normalized)
        if provider != "microsoft.operationalinsights" or types != ("workspaces",):
            raise ValueError("permission data source must identify one Log Analytics workspace")
        return normalized

    @field_validator("deny_tables")
    @classmethod
    def normalize_deny_tables(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(values, key=str.casefold))
        if len({item.casefold() for item in normalized}) != len(normalized):
            raise ValueError("permission deny tables must be unique")
        return normalized


class MonitoringLogPermissionEvidence(_StrictMonitoringContract):
    """Persisted proof that a resource-context Logs query had complete access."""

    schema_version: Literal["athena.wc028MonitoringLogPermissionEvidence.v1"] = Field(
        alias="schemaVersion"
    )
    query_target_resource_id: str = Field(
        alias="queryTargetResourceId",
        min_length=1,
        max_length=2048,
    )
    workspace_resource_id: str = Field(
        alias="workspaceResourceId",
        min_length=1,
        max_length=2048,
    )
    table: MonitoringResourceContextLogTable
    resources: tuple[MonitoringLogPermissionResource, ...] = Field(
        min_length=1,
        max_length=1,
    )
    data_sources: tuple[MonitoringLogPermissionDataSource, ...] = Field(
        alias="dataSources",
        min_length=1,
        max_length=1,
    )
    raw_permissions_digest: Sha256Digest = Field(alias="rawPermissionsDigest")
    evidence_digest: Sha256Digest = Field(alias="evidenceDigest")

    @field_validator("query_target_resource_id", "workspace_resource_id")
    @classmethod
    def normalize_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        _parse_arm_resource_id(normalized)
        return normalized

    @model_validator(mode="after")
    def validate_permission_evidence(self) -> MonitoringLogPermissionEvidence:
        resource = self.resources[0]
        data_source = self.data_sources[0]
        if (
            resource.resource_id != self.query_target_resource_id
            or resource.data_source_ids != (self.workspace_resource_id,)
            or resource.deny_tables
            or data_source.resource_id != self.workspace_resource_id
            or data_source.deny_tables
        ):
            raise ValueError(
                "Logs permission evidence reports a silent resource, workspace, or table exclusion"
            )
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"evidence_digest"},
                exclude_none=True,
            )
        )
        if self.evidence_digest != expected:
            raise ValueError("evidenceDigest does not bind Logs permission evidence")
        return self


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


def _normalize_rbac_actions(
    values: tuple[str, ...],
    *,
    field_name: str,
) -> tuple[str, ...]:
    normalized = tuple(sorted(item.casefold() for item in values))
    if len(normalized) != len(set(normalized)) or any(
        not item or not item.isascii() for item in normalized
    ):
        raise ValueError(f"{field_name} must be sorted unique ASCII actions")
    return normalized


def _rbac_action_is_allowed(
    action: str,
    *,
    actions: tuple[str, ...],
    not_actions: tuple[str, ...],
) -> bool:
    normalized = action.casefold()
    return any(fnmatchcase(normalized, pattern) for pattern in actions) and not any(
        fnmatchcase(normalized, pattern) for pattern in not_actions
    )


class MonitoringEffectiveRbacRoleDefinition(_StrictMonitoringContract):
    """Full stable Azure role definition referenced by measured assignments."""

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
    actions: tuple[str, ...] = Field(default=(), max_length=512)
    not_actions: tuple[str, ...] = Field(
        default=(),
        alias="notActions",
        max_length=512,
    )
    data_actions: tuple[str, ...] = Field(
        default=(),
        alias="dataActions",
        max_length=512,
    )
    not_data_actions: tuple[str, ...] = Field(
        default=(),
        alias="notDataActions",
        max_length=512,
    )
    raw_definition_digest: Sha256Digest = Field(alias="rawDefinitionDigest")
    definition_digest: Sha256Digest = Field(alias="definitionDigest")

    @field_validator("role_definition_id")
    @classmethod
    def normalize_role_definition_id(cls, value: str) -> str:
        return MonitoringEffectiveRbacGrant.normalize_role_definition_id(value)

    @field_validator("role_definition_name")
    @classmethod
    def validate_role_name(cls, value: str) -> str:
        return MonitoringEffectiveRbacGrant.validate_role_name(value)

    @field_validator(
        "actions",
        "not_actions",
        "data_actions",
        "not_data_actions",
    )
    @classmethod
    def normalize_actions(
        cls,
        values: tuple[str, ...],
        info: ValidationInfo,
    ) -> tuple[str, ...]:
        return _normalize_rbac_actions(
            values,
            field_name=info.field_name or "actions",
        )

    @model_validator(mode="after")
    def validate_definition(self) -> MonitoringEffectiveRbacRoleDefinition:
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"definition_digest"},
                exclude_none=True,
            )
        )
        if self.definition_digest != expected:
            raise ValueError("definitionDigest does not bind the full Azure role definition")
        return self


class MonitoringEffectiveRbacPrincipalEvidence(_StrictMonitoringContract):
    """Stable repeated exact-target role-assignment and group collection."""

    principal_id: str = Field(
        alias="principalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    query_filter: Literal["atScope() and assignedTo(principalId)"] = Field(alias="queryFilter")
    target_scope_ids: tuple[str, ...] = Field(
        alias="targetScopeIds",
        min_length=1,
        max_length=256,
    )
    first_read_target_digests: tuple[Sha256Digest, ...] = Field(
        alias="firstReadTargetDigests",
        min_length=1,
        max_length=256,
    )
    second_read_target_digests: tuple[Sha256Digest, ...] = Field(
        alias="secondReadTargetDigests",
        min_length=1,
        max_length=256,
    )
    role_assignment_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="roleAssignmentRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    transitive_group_ids: tuple[str, ...] = Field(
        default=(),
        alias="transitiveGroupIds",
        max_length=256,
    )
    transitive_group_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="transitiveGroupRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    first_role_assignment_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="firstRoleAssignmentRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    second_role_assignment_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="secondRoleAssignmentRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    first_transitive_group_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="firstTransitiveGroupRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    second_transitive_group_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="secondTransitiveGroupRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    all_pages_retrieved: Literal[True] = Field(alias="allPagesRetrieved")
    evidence_digest: Sha256Digest = Field(alias="evidenceDigest")

    @field_validator("principal_id")
    @classmethod
    def normalize_principal_id(cls, value: str) -> str:
        return value.casefold()

    @field_validator("target_scope_ids")
    @classmethod
    def normalize_target_scopes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_canonical_rbac_scope(item) for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("RBAC target scopes must be sorted and unique")
        return normalized

    @field_validator("transitive_group_ids")
    @classmethod
    def normalize_group_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(item.casefold() for item in values))
        if len(normalized) != len(set(normalized)) or any(
            _SUBSCRIPTION_ID_PATTERN.fullmatch(item) is None for item in normalized
        ):
            raise ValueError("transitive group IDs must be sorted UUIDs")
        return normalized

    @field_validator(
        "role_assignment_raw_page_digests",
        "transitive_group_raw_page_digests",
        "first_role_assignment_raw_page_digests",
        "second_role_assignment_raw_page_digests",
        "first_transitive_group_raw_page_digests",
        "second_transitive_group_raw_page_digests",
    )
    @classmethod
    def validate_page_digests(
        cls,
        values: tuple[Sha256Digest, ...] | None,
    ) -> tuple[Sha256Digest, ...] | None:
        if values is None:
            return None
        if values != tuple(sorted(values)) or len(values) != len(set(values)):
            raise ValueError("raw page digests must be sorted and unique")
        return values

    @model_validator(mode="after")
    def validate_principal_evidence(self) -> MonitoringEffectiveRbacPrincipalEvidence:
        legacy_page_fields = (
            self.role_assignment_raw_page_digests,
            self.transitive_group_raw_page_digests,
        )
        independent_page_fields = (
            self.first_role_assignment_raw_page_digests,
            self.second_role_assignment_raw_page_digests,
            self.first_transitive_group_raw_page_digests,
            self.second_transitive_group_raw_page_digests,
        )
        if (
            len(self.first_read_target_digests) != len(self.target_scope_ids)
            or self.first_read_target_digests != self.second_read_target_digests
            or (
                any(item is None for item in legacy_page_fields)
                and any(item is None for item in independent_page_fields)
            )
            or (
                all(item is not None for item in legacy_page_fields)
                and any(item is not None for item in independent_page_fields)
            )
            or (
                all(item is not None for item in independent_page_fields)
                and any(item is not None for item in legacy_page_fields)
            )
            or (
                self.first_role_assignment_raw_page_digests is not None
                and self.first_role_assignment_raw_page_digests
                != self.second_role_assignment_raw_page_digests
            )
            or (
                self.first_transitive_group_raw_page_digests is not None
                and self.first_transitive_group_raw_page_digests
                != self.second_transitive_group_raw_page_digests
            )
        ):
            raise ValueError(
                "RBAC exact-target repeated reads must use one complete stable evidence shape"
            )
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"evidence_digest"},
                exclude_none=True,
            )
        )
        if self.evidence_digest != expected:
            raise ValueError("evidenceDigest does not bind exact-target RBAC evidence")
        return self


class MonitoringEffectiveRbacDenyAssignment(_StrictMonitoringContract):
    """Applicable Azure deny assignment retained for effective evaluation."""

    deny_assignment_id: str = Field(
        alias="denyAssignmentId",
        min_length=1,
        max_length=2048,
    )
    scope_id: str = Field(alias="scopeId", min_length=1, max_length=2048)
    principal_ids: tuple[str, ...] = Field(
        alias="principalIds",
        max_length=256,
    )
    excluded_principal_ids: tuple[str, ...] = Field(
        default=(),
        alias="excludedPrincipalIds",
        max_length=256,
    )
    actions: tuple[str, ...] = Field(default=(), max_length=512)
    not_actions: tuple[str, ...] = Field(
        default=(),
        alias="notActions",
        max_length=512,
    )
    data_actions: tuple[str, ...] = Field(
        default=(),
        alias="dataActions",
        max_length=512,
    )
    not_data_actions: tuple[str, ...] = Field(
        default=(),
        alias="notDataActions",
        max_length=512,
    )
    do_not_apply_to_child_scopes: bool = Field(alias="doNotApplyToChildScopes")
    condition: str | None = Field(default=None, min_length=1, max_length=8192)
    raw_assignment_digest: Sha256Digest = Field(alias="rawAssignmentDigest")
    deny_assignment_digest: Sha256Digest = Field(alias="denyAssignmentDigest")

    @field_validator("deny_assignment_id")
    @classmethod
    def normalize_deny_assignment_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        if "/providers/microsoft.authorization/denyassignments/" not in normalized:
            raise ValueError("denyAssignmentId must identify an Azure deny assignment")
        return normalized

    @field_validator("scope_id")
    @classmethod
    def normalize_scope_id(cls, value: str) -> str:
        return _canonical_rbac_scope(value)

    @field_validator("principal_ids", "excluded_principal_ids")
    @classmethod
    def normalize_principal_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(item.casefold() for item in values))
        if len(normalized) != len(set(normalized)) or any(
            _SUBSCRIPTION_ID_PATTERN.fullmatch(item) is None for item in normalized
        ):
            raise ValueError("deny assignment principals must be sorted UUIDs")
        return normalized

    @field_validator(
        "actions",
        "not_actions",
        "data_actions",
        "not_data_actions",
    )
    @classmethod
    def normalize_actions(
        cls,
        values: tuple[str, ...],
        info: ValidationInfo,
    ) -> tuple[str, ...]:
        return _normalize_rbac_actions(
            values,
            field_name=info.field_name or "actions",
        )

    @model_validator(mode="after")
    def validate_deny_assignment(self) -> MonitoringEffectiveRbacDenyAssignment:
        if _ALL_PRINCIPALS_ID in self.excluded_principal_ids:
            raise ValueError("All Principals cannot appear in excludedPrincipalIds")
        if _ALL_PRINCIPALS_ID in self.principal_ids and self.principal_ids != (_ALL_PRINCIPALS_ID,):
            raise ValueError("All Principals must be the sole deny-assignment principal")
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"deny_assignment_digest"},
                exclude_none=True,
            )
        )
        if self.deny_assignment_digest != expected:
            raise ValueError("denyAssignmentDigest does not bind the full deny assignment")
        return self


class MonitoringEffectiveRbacPimScheduleInstance(_StrictMonitoringContract):
    """Active PIM assignment schedule instance retained by the attestor."""

    schedule_instance_id: str = Field(
        alias="scheduleInstanceId",
        min_length=1,
        max_length=2048,
    )
    principal_id: str = Field(
        alias="principalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    role_definition_id: str = Field(
        alias="roleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    scope_id: str = Field(alias="scopeId", min_length=1, max_length=2048)
    assignment_type: Literal["Activated", "Assigned"] = Field(alias="assignmentType")
    start_at: UtcDateTime = Field(alias="startAt")
    end_at: UtcDateTime = Field(alias="endAt")
    condition: str | None = Field(default=None, min_length=1, max_length=8192)
    raw_instance_digest: Sha256Digest = Field(alias="rawInstanceDigest")
    instance_digest: Sha256Digest = Field(alias="instanceDigest")

    @field_validator("schedule_instance_id")
    @classmethod
    def normalize_schedule_instance_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        if "/roleassignmentscheduleinstances/" not in normalized:
            raise ValueError("scheduleInstanceId must identify a PIM schedule instance")
        return normalized

    @field_validator("principal_id")
    @classmethod
    def normalize_principal_id(cls, value: str) -> str:
        return value.casefold()

    @field_validator("role_definition_id")
    @classmethod
    def normalize_role_definition_id(cls, value: str) -> str:
        return MonitoringEffectiveRbacGrant.normalize_role_definition_id(value)

    @field_validator("scope_id")
    @classmethod
    def normalize_scope_id(cls, value: str) -> str:
        return _canonical_rbac_scope(value)

    @model_validator(mode="after")
    def validate_schedule_instance(
        self,
    ) -> MonitoringEffectiveRbacPimScheduleInstance:
        if self.start_at >= self.end_at:
            raise ValueError("PIM schedule instance interval is invalid")
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"instance_digest"},
                exclude_none=True,
            )
        )
        if self.instance_digest != expected:
            raise ValueError("instanceDigest does not bind the active PIM schedule instance")
        return self


class MonitoringEffectiveRbacInventory(_StrictMonitoringContract):
    """Measured effective assignments from the explicitly collectable RBAC scopes."""

    schema_version: Literal[
        "athena.wc028MonitoringEffectiveRbacInventory.v1",
        "athena.wc028MonitoringEffectiveRbacInventory.v2",
        "athena.wc028MonitoringEffectiveRbacInventory.v3",
    ] = Field(alias="schemaVersion")
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
    attestor_identity_resource_id: str | None = Field(
        default=None,
        alias="attestorIdentityResourceId",
        min_length=1,
        max_length=2048,
    )
    attestor_client_id: str | None = Field(
        default=None,
        alias="attestorClientId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    attestor_principal_id: str | None = Field(
        default=None,
        alias="attestorPrincipalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    attestor_tenant_id: str | None = Field(
        default=None,
        alias="attestorTenantId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    collected_at: UtcDateTime = Field(alias="collectedAt")
    expires_at: UtcDateTime = Field(alias="expiresAt")
    first_read_completed_at: UtcDateTime | None = Field(
        default=None,
        alias="firstReadCompletedAt",
    )
    second_read_completed_at: UtcDateTime | None = Field(
        default=None,
        alias="secondReadCompletedAt",
    )
    scope_collection_mode: Literal["subscriptionAndDescendantAtScope"] | None = Field(
        default=None,
        alias="scopeCollectionMode",
    )
    management_group_ancestry: tuple[str, ...] = Field(
        alias="managementGroupAncestry",
        max_length=32,
    )
    ancestor_scope_collection_complete: bool = Field(alias="ancestorScopeCollectionComplete")
    subscription_descendant_collection_complete: Literal[True] = Field(
        alias="subscriptionDescendantCollectionComplete"
    )
    group_membership_collection_complete: Literal[True] = Field(
        alias="groupMembershipCollectionComplete"
    )
    role_definition_collection_complete: Literal[True] = Field(
        alias="roleDefinitionCollectionComplete"
    )
    deny_assignment_collection_complete: Literal[True] | None = Field(
        default=None,
        alias="denyAssignmentCollectionComplete",
    )
    pim_schedule_instance_collection_complete: Literal[True] | None = Field(
        default=None,
        alias="pimScheduleInstanceCollectionComplete",
    )
    signal_reader_role_actions: tuple[str, ...] = Field(
        alias="signalReaderRoleActions",
        min_length=2,
        max_length=2,
    )
    resource_log_reader_role_actions: tuple[str, ...] = Field(
        alias="resourceLogReaderRoleActions",
        min_length=4,
        max_length=5,
    )
    ip_flow_verify_role_actions: tuple[str, ...] | None = Field(
        default=None,
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
    collector_principal_evidence: MonitoringEffectiveRbacPrincipalEvidence | None = Field(
        default=None,
        alias="collectorPrincipalEvidence",
    )
    athena_context_principal_evidence: MonitoringEffectiveRbacPrincipalEvidence | None = Field(
        default=None,
        alias="athenaContextPrincipalEvidence",
    )
    role_definitions: tuple[MonitoringEffectiveRbacRoleDefinition, ...] | None = Field(
        default=None,
        alias="roleDefinitions",
        min_length=1,
        max_length=64,
    )
    deny_assignments: tuple[MonitoringEffectiveRbacDenyAssignment, ...] | None = Field(
        default=None,
        alias="denyAssignments",
        max_length=256,
    )
    active_pim_schedule_instances: tuple[MonitoringEffectiveRbacPimScheduleInstance, ...] | None = (
        Field(
            default=None,
            alias="activePimScheduleInstances",
            max_length=256,
        )
    )
    role_definition_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="roleDefinitionRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    deny_assignment_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="denyAssignmentRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    pim_schedule_instance_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="pimScheduleInstanceRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    first_role_definition_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="firstRoleDefinitionRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    second_role_definition_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="secondRoleDefinitionRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    first_deny_assignment_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="firstDenyAssignmentRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    second_deny_assignment_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="secondDenyAssignmentRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    first_pim_schedule_instance_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="firstPimScheduleInstanceRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    second_pim_schedule_instance_raw_page_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="secondPimScheduleInstanceRawPageDigests",
        min_length=1,
        max_length=1024,
    )
    first_raw_snapshot_digest: Sha256Digest | None = Field(
        default=None,
        alias="firstRawSnapshotDigest",
    )
    second_raw_snapshot_digest: Sha256Digest | None = Field(
        default=None,
        alias="secondRawSnapshotDigest",
    )
    repeated_read_stable: Literal[True] | None = Field(
        default=None,
        alias="repeatedReadStable",
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
        "attestor_client_id",
        "attestor_principal_id",
        "attestor_tenant_id",
    )
    @classmethod
    def normalize_guid(cls, value: str | None) -> str | None:
        return None if value is None else value.casefold()

    @field_validator("attestor_identity_resource_id")
    @classmethod
    def normalize_attestor_identity_resource_id(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        normalized = value.casefold().rstrip("/")
        _, _, provider, types = _parse_arm_resource_id(normalized)
        if provider != "microsoft.managedidentity" or types != ("userassignedidentities",):
            raise ValueError("RBAC attestor identity must be one user-assigned managed identity")
        return normalized

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
        "resource_health_role_actions",
    )
    @classmethod
    def normalize_role_actions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(item.casefold() for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("effective RBAC role actions must be sorted and unique")
        return normalized

    @field_validator("ip_flow_verify_role_actions")
    @classmethod
    def normalize_optional_role_actions(
        cls,
        values: tuple[str, ...] | None,
    ) -> tuple[str, ...] | None:
        if values is None:
            return None
        return _normalize_rbac_actions(
            values,
            field_name="ipFlowVerifyRoleActions",
        )

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
            raise ValueError(
                "effective RBAC management-group ancestry must be canonical and unique"
            )
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

    @field_validator("role_definitions")
    @classmethod
    def validate_role_definition_order(
        cls,
        values: tuple[MonitoringEffectiveRbacRoleDefinition, ...] | None,
    ) -> tuple[MonitoringEffectiveRbacRoleDefinition, ...] | None:
        if values is None:
            return None
        ids = tuple(item.role_definition_id for item in values)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("effective RBAC role definitions must be sorted and unique")
        return values

    @field_validator("deny_assignments")
    @classmethod
    def validate_deny_assignment_order(
        cls,
        values: tuple[MonitoringEffectiveRbacDenyAssignment, ...] | None,
    ) -> tuple[MonitoringEffectiveRbacDenyAssignment, ...] | None:
        if values is None:
            return None
        ids = tuple(item.deny_assignment_id for item in values)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("deny assignments must be sorted and unique")
        return values

    @field_validator("active_pim_schedule_instances")
    @classmethod
    def validate_pim_instance_order(
        cls,
        values: tuple[MonitoringEffectiveRbacPimScheduleInstance, ...] | None,
    ) -> tuple[MonitoringEffectiveRbacPimScheduleInstance, ...] | None:
        if values is None:
            return None
        ids = tuple(item.schedule_instance_id for item in values)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("PIM schedule instances must be sorted and unique")
        return values

    @field_validator(
        "role_definition_raw_page_digests",
        "deny_assignment_raw_page_digests",
        "pim_schedule_instance_raw_page_digests",
        "first_role_definition_raw_page_digests",
        "second_role_definition_raw_page_digests",
        "first_deny_assignment_raw_page_digests",
        "second_deny_assignment_raw_page_digests",
        "first_pim_schedule_instance_raw_page_digests",
        "second_pim_schedule_instance_raw_page_digests",
    )
    @classmethod
    def validate_optional_raw_page_digests(
        cls,
        values: tuple[Sha256Digest, ...] | None,
    ) -> tuple[Sha256Digest, ...] | None:
        if values is None:
            return None
        if values != tuple(sorted(values)) or len(values) != len(set(values)):
            raise ValueError("effective RBAC raw page digests must be sorted and unique")
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
        common_attestor_fields = (
            self.attestor_identity_resource_id,
            self.attestor_client_id,
            self.attestor_principal_id,
            self.attestor_tenant_id,
            self.deny_assignment_collection_complete,
            self.pim_schedule_instance_collection_complete,
            self.collector_principal_evidence,
            self.athena_context_principal_evidence,
            self.role_definitions,
            self.deny_assignments,
            self.active_pim_schedule_instances,
            self.first_raw_snapshot_digest,
            self.second_raw_snapshot_digest,
            self.repeated_read_stable,
        )
        legacy_repeated_read_fields = (
            self.role_definition_raw_page_digests,
            self.deny_assignment_raw_page_digests,
            self.pim_schedule_instance_raw_page_digests,
        )
        repeated_read_v3_fields = (
            self.first_read_completed_at,
            self.second_read_completed_at,
            self.first_role_definition_raw_page_digests,
            self.second_role_definition_raw_page_digests,
            self.first_deny_assignment_raw_page_digests,
            self.second_deny_assignment_raw_page_digests,
            self.first_pim_schedule_instance_raw_page_digests,
            self.second_pim_schedule_instance_raw_page_digests,
        )
        if self.schema_version == "athena.wc028MonitoringEffectiveRbacInventory.v1":
            if (
                any(
                    item is not None
                    for item in (
                        *common_attestor_fields,
                        *legacy_repeated_read_fields,
                        *repeated_read_v3_fields,
                    )
                )
                or self.ip_flow_verify_role_actions is None
                or self.scope_collection_mode is not None
                or not self.management_group_ancestry
                or self.ancestor_scope_collection_complete is not True
            ):
                raise ValueError("effective RBAC inventory v1 cannot contain attestor evidence")
        else:
            if (
                any(item is None for item in common_attestor_fields)
                or self.ip_flow_verify_role_actions is not None
                or self.attestor_principal_id
                in {
                    self.collector_principal_id,
                    self.athena_context_principal_id,
                }
                or self.attestor_tenant_id != self.tenant_id
                or self.first_raw_snapshot_digest != self.second_raw_snapshot_digest
            ):
                raise ValueError(
                    "effective RBAC inventory requires stable separate-attestor evidence"
                )
            collector_evidence = cast(
                MonitoringEffectiveRbacPrincipalEvidence,
                self.collector_principal_evidence,
            )
            context_evidence = cast(
                MonitoringEffectiveRbacPrincipalEvidence,
                self.athena_context_principal_evidence,
            )
            role_definitions = cast(
                tuple[MonitoringEffectiveRbacRoleDefinition, ...],
                self.role_definitions,
            )
            deny_assignments = cast(
                tuple[MonitoringEffectiveRbacDenyAssignment, ...],
                self.deny_assignments,
            )
            pim_instances = cast(
                tuple[MonitoringEffectiveRbacPimScheduleInstance, ...],
                self.active_pim_schedule_instances,
            )
            if (
                collector_evidence.principal_id != self.collector_principal_id
                or context_evidence.principal_id != self.athena_context_principal_id
                or collector_evidence.transitive_group_ids != self.collector_security_group_ids
                or context_evidence.transitive_group_ids != self.athena_context_security_group_ids
                or any(
                    item.condition is not None
                    for item in (
                        *self.collector_grants,
                        *self.athena_context_grants,
                    )
                )
                or any(item.condition is not None for item in deny_assignments)
                or any(item.condition is not None for item in pim_instances)
                or any(
                    not item.start_at <= self.collected_at < item.end_at for item in pim_instances
                )
            ):
                raise ValueError(
                    "effective RBAC evidence has unsupported conditions, groups, or PIM state"
                )
            referenced_role_ids = {
                item.role_definition_id
                for item in (
                    *self.collector_grants,
                    *self.athena_context_grants,
                )
            }
            referenced_role_ids.update(item.role_definition_id for item in pim_instances)
            available_role_ids = {item.role_definition_id for item in role_definitions}
            if not referenced_role_ids.issubset(available_role_ids):
                raise ValueError(
                    "effective RBAC evidence omitted a referenced full role definition"
                )
            normalized_record_digests = {
                "roleDefinitionRawDigests": [
                    item.raw_definition_digest for item in role_definitions
                ],
                "denyAssignmentRawDigests": [
                    item.raw_assignment_digest for item in deny_assignments
                ],
                "pimScheduleInstanceRawDigests": [
                    item.raw_instance_digest for item in pim_instances
                ],
            }
            if self.schema_version == "athena.wc028MonitoringEffectiveRbacInventory.v2":
                if (
                    self.scope_collection_mode is not None
                    or not self.management_group_ancestry
                    or self.ancestor_scope_collection_complete is not True
                ):
                    raise ValueError(
                        "effective RBAC inventory v2 requires historical ancestor scope evidence"
                    )
                if (
                    any(item is None for item in legacy_repeated_read_fields)
                    or any(item is not None for item in repeated_read_v3_fields)
                    or collector_evidence.role_assignment_raw_page_digests is None
                    or collector_evidence.transitive_group_raw_page_digests is None
                    or context_evidence.role_assignment_raw_page_digests is None
                    or context_evidence.transitive_group_raw_page_digests is None
                ):
                    raise ValueError(
                        "effective RBAC inventory v2 cannot contain independent read receipts"
                    )
                raw_snapshot_payload = {
                    "collectorPrincipalEvidenceDigest": (collector_evidence.evidence_digest),
                    "athenaContextPrincipalEvidenceDigest": (context_evidence.evidence_digest),
                    "roleDefinitionRawPageDigests": (
                        list(
                            cast(
                                tuple[Sha256Digest, ...],
                                self.role_definition_raw_page_digests,
                            )
                        )
                    ),
                    "denyAssignmentRawPageDigests": (
                        list(
                            cast(
                                tuple[Sha256Digest, ...],
                                self.deny_assignment_raw_page_digests,
                            )
                        )
                    ),
                    "pimScheduleInstanceRawPageDigests": (
                        list(
                            cast(
                                tuple[Sha256Digest, ...],
                                self.pim_schedule_instance_raw_page_digests,
                            )
                        )
                    ),
                    **normalized_record_digests,
                }
                expected_raw_snapshot_digest = compute_artifact_digest(raw_snapshot_payload)
                if (
                    self.first_raw_snapshot_digest != expected_raw_snapshot_digest
                    or self.second_raw_snapshot_digest != expected_raw_snapshot_digest
                ):
                    raise ValueError(
                        "effective RBAC repeated-read snapshot does not bind raw hashes"
                    )
            else:
                if (
                    self.scope_collection_mode != "subscriptionAndDescendantAtScope"
                    or self.management_group_ancestry
                    or self.ancestor_scope_collection_complete is not False
                ):
                    raise ValueError(
                        "effective RBAC inventory v3 requires exact collectable scope evidence"
                    )
                if (
                    any(item is not None for item in legacy_repeated_read_fields)
                    or any(item is None for item in repeated_read_v3_fields)
                    or collector_evidence.role_assignment_raw_page_digests is not None
                    or collector_evidence.transitive_group_raw_page_digests is not None
                    or context_evidence.role_assignment_raw_page_digests is not None
                    or context_evidence.transitive_group_raw_page_digests is not None
                    or any(
                        item is None
                        for item in (
                            collector_evidence.first_role_assignment_raw_page_digests,
                            collector_evidence.second_role_assignment_raw_page_digests,
                            collector_evidence.first_transitive_group_raw_page_digests,
                            collector_evidence.second_transitive_group_raw_page_digests,
                            context_evidence.first_role_assignment_raw_page_digests,
                            context_evidence.second_role_assignment_raw_page_digests,
                            context_evidence.first_transitive_group_raw_page_digests,
                            context_evidence.second_transitive_group_raw_page_digests,
                        )
                    )
                ):
                    raise ValueError(
                        "effective RBAC inventory v3 requires independent read receipts"
                    )
                first_read_completed_at = cast(
                    UtcDateTime,
                    self.first_read_completed_at,
                )
                second_read_completed_at = cast(
                    UtcDateTime,
                    self.second_read_completed_at,
                )
                if not first_read_completed_at < second_read_completed_at <= self.collected_at:
                    raise ValueError("effective RBAC inventory v3 read receipts are not distinct")
                first_snapshot_payload = {
                    "collectorPrincipalId": collector_evidence.principal_id,
                    "collectorTargetReadDigests": list(
                        collector_evidence.first_read_target_digests
                    ),
                    "athenaContextPrincipalId": context_evidence.principal_id,
                    "athenaContextTargetReadDigests": list(
                        context_evidence.first_read_target_digests
                    ),
                    "collectorRoleAssignmentRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            collector_evidence.first_role_assignment_raw_page_digests,
                        )
                    ),
                    "collectorTransitiveGroupRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            collector_evidence.first_transitive_group_raw_page_digests,
                        )
                    ),
                    "athenaContextRoleAssignmentRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            context_evidence.first_role_assignment_raw_page_digests,
                        )
                    ),
                    "athenaContextTransitiveGroupRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            context_evidence.first_transitive_group_raw_page_digests,
                        )
                    ),
                    "roleDefinitionRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            self.first_role_definition_raw_page_digests,
                        )
                    ),
                    "denyAssignmentRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            self.first_deny_assignment_raw_page_digests,
                        )
                    ),
                    "pimScheduleInstanceRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            self.first_pim_schedule_instance_raw_page_digests,
                        )
                    ),
                    **normalized_record_digests,
                }
                second_snapshot_payload = {
                    "collectorPrincipalId": collector_evidence.principal_id,
                    "collectorTargetReadDigests": list(
                        collector_evidence.second_read_target_digests
                    ),
                    "athenaContextPrincipalId": context_evidence.principal_id,
                    "athenaContextTargetReadDigests": list(
                        context_evidence.second_read_target_digests
                    ),
                    "collectorRoleAssignmentRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            collector_evidence.second_role_assignment_raw_page_digests,
                        )
                    ),
                    "collectorTransitiveGroupRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            collector_evidence.second_transitive_group_raw_page_digests,
                        )
                    ),
                    "athenaContextRoleAssignmentRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            context_evidence.second_role_assignment_raw_page_digests,
                        )
                    ),
                    "athenaContextTransitiveGroupRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            context_evidence.second_transitive_group_raw_page_digests,
                        )
                    ),
                    "roleDefinitionRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            self.second_role_definition_raw_page_digests,
                        )
                    ),
                    "denyAssignmentRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            self.second_deny_assignment_raw_page_digests,
                        )
                    ),
                    "pimScheduleInstanceRawPageDigests": list(
                        cast(
                            tuple[Sha256Digest, ...],
                            self.second_pim_schedule_instance_raw_page_digests,
                        )
                    ),
                    **normalized_record_digests,
                }
                if (
                    self.first_raw_snapshot_digest
                    != compute_artifact_digest(first_snapshot_payload)
                    or self.second_raw_snapshot_digest
                    != compute_artifact_digest(second_snapshot_payload)
                    or self.first_raw_snapshot_digest != self.second_raw_snapshot_digest
                ):
                    raise ValueError(
                        "effective RBAC independent snapshots are incomplete or unstable"
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
        "athena.wc028MonitoringCollectorContract.v8",
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
    workspace_resource_context_access_enabled: Literal[True] | None = Field(
        default=None,
        alias="workspaceResourceContextAccessEnabled",
    )
    workspace_sku_name: Literal["PerGB2018"] | None = Field(
        default=None,
        alias="workspaceSkuName",
    )
    resource_context_table_plans: tuple[MonitoringResourceContextTablePlan, ...] | None = Field(
        default=None,
        alias="resourceContextTablePlans",
        min_length=len(_EXPECTED_RESOURCE_CONTEXT_LOG_TABLES),
        max_length=len(_EXPECTED_RESOURCE_CONTEXT_LOG_TABLES),
    )
    resource_id_column: Literal["_ResourceId"] | None = Field(
        default=None,
        alias="resourceIdColumn",
    )
    log_query_prefer_header: Literal["include-permissions=true"] | None = Field(
        default=None,
        alias="logQueryPreferHeader",
    )
    flow_table_acquisition_mode: Literal["unsupportedUnavailable"] | None = Field(
        default=None,
        alias="flowTableAcquisitionMode",
    )
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
        min_length=len(_EXPECTED_PREVIOUS_RESOURCE_LOG_OPERATIONS),
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
    rbac_attestor_identity_resource_id: str | None = Field(
        default=None,
        alias="rbacAttestorIdentityResourceId",
        min_length=1,
        max_length=2048,
    )
    rbac_attestor_identity_client_id: str | None = Field(
        default=None,
        alias="rbacAttestorIdentityClientId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    rbac_attestor_principal_id: str | None = Field(
        default=None,
        alias="rbacAttestorPrincipalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    rbac_attestor_tenant_id: str | None = Field(
        default=None,
        alias="rbacAttestorTenantId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    rbac_attestor_role_definition_id: str | None = Field(
        default=None,
        alias="rbacAttestorRoleDefinitionId",
        min_length=1,
        max_length=2048,
    )
    rbac_attestor_role_name: str | None = Field(
        default=None,
        alias="rbacAttestorRoleName",
        min_length=1,
        max_length=256,
    )
    rbac_attestor_scope_id: str | None = Field(
        default=None,
        alias="rbacAttestorScopeId",
        min_length=1,
        max_length=2048,
    )
    rbac_attestor_allowed_operations: tuple[MonitoringRbacAttestorOperation, ...] | None = Field(
        default=None,
        alias="rbacAttestorAllowedOperations",
        min_length=len(_EXPECTED_RBAC_ATTESTOR_OPERATIONS),
        max_length=len(_EXPECTED_RBAC_ATTESTOR_OPERATIONS),
    )
    rbac_attestor_identity_separation_enforced: Literal[True] | None = Field(
        default=None,
        alias="rbacAttestorIdentitySeparationEnforced",
    )
    identity_proof_audience: str | None = Field(
        default=None,
        alias="identityProofAudience",
        pattern=(
            r"^api://(?:athena-monitoring-identity-proof|"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{12}/athena-monitoring-identity-proof)$"
        ),
    )
    identity_proof_application_id: str | None = Field(
        default=None,
        alias="identityProofApplicationId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    identity_proof_application_object_id: str | None = Field(
        default=None,
        alias="identityProofApplicationObjectId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    identity_proof_service_principal_id: str | None = Field(
        default=None,
        alias="identityProofServicePrincipalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    identity_proof_app_role_id: str | None = Field(
        default=None,
        alias="identityProofAppRoleId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    identity_proof_app_role_assignment_id: str | None = Field(
        default=None,
        alias="identityProofAppRoleAssignmentId",
        min_length=1,
        max_length=2048,
    )
    identity_proof_assigned_principal_id: str | None = Field(
        default=None,
        alias="identityProofAssignedPrincipalId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
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
        max_length=max(
            len(_EXPECTED_ACQUISITION_READ_OPERATIONS),
            len(_EXPECTED_PREVIOUS_MEASURED_RBAC_READ_OPERATIONS),
        ),
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
        "rbac_attestor_identity_client_id",
        "rbac_attestor_principal_id",
        "rbac_attestor_tenant_id",
        "identity_proof_application_id",
        "identity_proof_application_object_id",
        "identity_proof_service_principal_id",
        "identity_proof_app_role_id",
        "identity_proof_assigned_principal_id",
        mode="before",
    )
    @classmethod
    def canonicalize_identity_guid(cls, value: object) -> object:
        return value.casefold() if type(value) is str else value

    @field_validator("identity_proof_app_role_assignment_id")
    @classmethod
    def validate_identity_proof_app_role_assignment_id(
        cls,
        value: str | None,
    ) -> str | None:
        if value is not None and (
            not value.isascii()
            or value != value.strip()
            or any(character.isspace() for character in value)
        ):
            raise ValueError("identity-proof app-role assignment ID must be exact ASCII")
        return value

    @field_validator("rbac_attestor_identity_resource_id")
    @classmethod
    def canonicalize_attestor_identity_id(
        cls,
        value: str | None,
    ) -> str | None:
        return None if value is None else value.casefold().rstrip("/")

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
                MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
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
            == MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION
        ):
            expected_read_operations = _EXPECTED_PREVIOUS_MEASURED_RBAC_READ_OPERATIONS
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
        credential_fields = (self.collector_tenant_id,)
        ip_flow_policy_fields = (
            self.ip_flow_verify_role_definition_id,
            self.ip_flow_verify_scope_id,
            self.ip_flow_verify_allowed_operations,
        )
        identity_proof_policy_fields = (
            self.identity_proof_audience,
            self.identity_proof_token_version,
            self.identity_proof_required_role,
            self.identity_proof_maximum_lifetime_seconds,
        )
        identity_proof_authority_fields = (
            self.identity_proof_application_id,
            self.identity_proof_application_object_id,
            self.identity_proof_service_principal_id,
            self.identity_proof_app_role_id,
            self.identity_proof_app_role_assignment_id,
            self.identity_proof_assigned_principal_id,
        )
        resource_health_fields = (
            self.resource_health_role_definition_id,
            self.resource_health_scope_ids,
            self.resource_health_allowed_operations,
        )
        measured_rbac_common_fields = (
            self.signal_reader_role_name,
            self.resource_log_reader_role_definition_id,
            self.resource_log_reader_role_name,
            self.resource_log_allowed_operations,
            self.resource_log_read_scope_ids,
            self.resource_health_role_name,
            self.signing_key_arm_resource_id,
            self.signing_key_crypto_user_role_definition_id,
            self.evidence_container_resource_id,
            self.evidence_writer_role_definition_id,
            self.effective_rbac_inventory,
        )
        current_resource_context_fields = (
            self.workspace_resource_context_access_enabled,
            self.workspace_sku_name,
            self.resource_context_table_plans,
            self.resource_id_column,
            self.log_query_prefer_header,
            self.flow_table_acquisition_mode,
        )
        attestor_fields = (
            self.rbac_attestor_identity_resource_id,
            self.rbac_attestor_identity_client_id,
            self.rbac_attestor_principal_id,
            self.rbac_attestor_tenant_id,
            self.rbac_attestor_role_definition_id,
            self.rbac_attestor_role_name,
            self.rbac_attestor_scope_id,
            self.rbac_attestor_allowed_operations,
            self.rbac_attestor_identity_separation_enforced,
        )
        if self.schema_version == MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION:
            if any(
                item is not None
                for item in (
                    *acquisition_identity_fields,
                    *credential_fields,
                    *ip_flow_policy_fields,
                    self.ip_flow_verify_role_name,
                    *identity_proof_policy_fields,
                    *identity_proof_authority_fields,
                    *resource_health_fields,
                    *measured_rbac_common_fields,
                    *current_resource_context_fields,
                    *attestor_fields,
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
                    *credential_fields,
                    *ip_flow_policy_fields,
                    self.ip_flow_verify_role_name,
                    *identity_proof_policy_fields,
                    *identity_proof_authority_fields,
                    *resource_health_fields,
                    *measured_rbac_common_fields,
                    *current_resource_context_fields,
                    *attestor_fields,
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
            MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        }:
            if any(item is None for item in (*credential_fields, *ip_flow_policy_fields)):
                raise ValueError(
                    "credential-bound WC-028 collector contract requires exact IP Flow policy"
                )
            if self.ip_flow_verify_allowed_operations != _EXPECTED_IP_FLOW_VERIFY_OPERATIONS:
                raise ValueError("IP Flow Verify operations must use the exact reviewed allowlist")
            try:
                UUID(cast(str, self.collector_tenant_id))
            except ValueError as exc:
                raise ValueError("collector tenant ID must be a UUID") from exc
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION:
            if any(item is None for item in credential_fields) or any(
                item is not None
                for item in (
                    *ip_flow_policy_fields,
                    self.ip_flow_verify_role_name,
                )
            ):
                raise ValueError(
                    "current collector contract requires credential-bound acquisition "
                    "without IP Flow authorization"
                )
            try:
                UUID(cast(str, self.collector_tenant_id))
            except ValueError as exc:
                raise ValueError("collector tenant ID must be a UUID") from exc
        if (
            self.schema_version == MONITORING_PREVIOUS_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION
            and (
                any(item is not None for item in identity_proof_policy_fields)
                or any(item is not None for item in identity_proof_authority_fields)
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
            MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        } and (
            any(item is None for item in identity_proof_policy_fields)
            or self.identity_proof_token_version != MONITORING_IDENTITY_PROOF_TOKEN_VERSION
            or self.identity_proof_required_role != MONITORING_IDENTITY_PROOF_REQUIRED_ROLE
            or self.identity_proof_maximum_lifetime_seconds
            != MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ):
            raise ValueError(
                "production collector contract requires the exact Athena identity proof policy"
            )
        if self.schema_version in {
            MONITORING_IDENTITY_PROOF_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        }:
            expected_legacy_audience = (
                f"api://{cast(str, self.collector_tenant_id)}"
                f"{_MONITORING_IDENTITY_PROOF_AUDIENCE_SUFFIX}"
            )
            if self.identity_proof_audience not in {
                _LEGACY_MONITORING_IDENTITY_PROOF_AUDIENCE,
                expected_legacy_audience,
            } or any(item is not None for item in identity_proof_authority_fields):
                raise ValueError(
                    "legacy identity-proof collector contract contains unsupported authority IDs"
                )
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION:
            expected_current_audience = (
                f"api://{cast(str, self.collector_tenant_id)}"
                f"{_MONITORING_IDENTITY_PROOF_AUDIENCE_SUFFIX}"
            )
            authority_ids = cast(
                tuple[str, ...],
                identity_proof_authority_fields,
            )
            if (
                any(item is None for item in identity_proof_authority_fields)
                or self.identity_proof_audience != expected_current_audience
                or self.identity_proof_assigned_principal_id != self.monitoring_reader_principal_id
                or len(set(authority_ids)) != len(authority_ids)
            ):
                raise ValueError(
                    "current collector contract does not bind the deployed identity-proof authority"
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
            self.schema_version
            in {
                MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
                MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            }
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
            MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        } and (
            any(item is None for item in resource_health_fields)
            or self.resource_health_allowed_operations
            != _EXPECTED_PREVIOUS_RESOURCE_HEALTH_OPERATIONS
        ):
            raise ValueError(
                "historical production collector contract requires its exact Resource Health policy"
            )
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION and (
            any(item is None for item in resource_health_fields)
            or self.resource_health_allowed_operations != _EXPECTED_RESOURCE_HEALTH_OPERATIONS
        ):
            raise ValueError(
                "current collector contract requires exact current Resource Health policy"
            )
        legacy_measured_fields = (
            *measured_rbac_common_fields,
            self.ip_flow_verify_role_name,
        )
        if self.schema_version not in {
            MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        } and any(
            item is not None
            for item in (
                *legacy_measured_fields,
                *current_resource_context_fields,
                *attestor_fields,
            )
        ):
            raise ValueError("legacy collector contracts cannot contain measured RBAC policy")
        if (
            self.schema_version
            == MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION
            and (
                any(item is None for item in legacy_measured_fields)
                or any(
                    item is not None
                    for item in (
                        *current_resource_context_fields,
                        *attestor_fields,
                    )
                )
                or self.resource_log_allowed_operations
                != _EXPECTED_PREVIOUS_RESOURCE_LOG_OPERATIONS
                or self.workspace_access_control_mode != "workspaceAndResourceContext"
            )
        ):
            raise ValueError("collector contract v7 requires its historical measured RBAC policy")
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION and (
            any(
                item is None
                for item in (
                    *measured_rbac_common_fields,
                    *current_resource_context_fields,
                    *attestor_fields,
                )
            )
            or self.resource_log_allowed_operations != _EXPECTED_RESOURCE_LOG_OPERATIONS
            or self.workspace_access_control_mode != "workspaceAndResourceContext"
        ):
            raise ValueError(
                "current collector contract requires permission-attested resource-context logs "
                "and separate measured RBAC attestation"
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
        if (
            self.schema_version
            == MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION
            and (
                cast(str, self.signal_reader_role_name).startswith(_SIGNAL_READER_ROLE_NAME_PREFIX)
                is not True
                or self.resource_log_reader_role_name != _RESOURCE_LOG_READER_ROLE_NAME
                or self.ip_flow_verify_role_name != _IP_FLOW_VERIFY_ROLE_NAME
                or self.resource_health_role_name != _RESOURCE_HEALTH_ROLE_NAME
            )
        ):
            raise ValueError("collector contract v7 role names do not match deployed roles")
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION and (
            cast(str, self.signal_reader_role_name).startswith(_SIGNAL_READER_ROLE_NAME_PREFIX)
            is not True
            or self.resource_log_reader_role_name != _RESOURCE_LOG_READER_ROLE_NAME
            or self.resource_health_role_name != _RESOURCE_HEALTH_ROLE_NAME
            or self.rbac_attestor_role_name != _RBAC_ATTESTOR_ROLE_NAME
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
            MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
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
        if self.schema_version in {
            MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        }:
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
            MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
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
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION:
            table_plans = cast(
                tuple[MonitoringResourceContextTablePlan, ...],
                self.resource_context_table_plans,
            )
            expected_table_ids = tuple(
                (f"{self.workspace_resource_id.casefold().rstrip('/')}/tables/{table.casefold()}")
                for table in _EXPECTED_RESOURCE_CONTEXT_LOG_TABLES
            )
            if (
                tuple(item.table for item in table_plans) != _EXPECTED_RESOURCE_CONTEXT_LOG_TABLES
                or tuple(item.table_resource_id for item in table_plans) != expected_table_ids
            ):
                raise ValueError(
                    "resource-context tables must use exact Analytics-plan workspace tables"
                )
            expected_attestor_role_id = (
                f"/subscriptions/{monitoring_subscription}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{_RBAC_ATTESTOR_ROLE_DEFINITION_GUID}"
            )
            expected_attestor_scope = f"/subscriptions/{monitoring_subscription}"
            attestor_identity_id = cast(
                str,
                self.rbac_attestor_identity_resource_id,
            )
            (
                attestor_subscription,
                attestor_resource_group,
                attestor_provider,
                attestor_types,
            ) = _parse_arm_resource_id(attestor_identity_id)
            attestor_principal = cast(str, self.rbac_attestor_principal_id)
            if (
                attestor_subscription != monitoring_subscription
                or attestor_resource_group != monitoring_resource_group
                or attestor_provider != "microsoft.managedidentity"
                or attestor_types != ("userassignedidentities",)
                or attestor_identity_id.casefold().rstrip("/")
                in {
                    self.collector_identity_resource_id.casefold().rstrip("/"),
                    cast(str, self.athena_context_identity_id).casefold().rstrip("/"),
                }
                or attestor_principal
                in {
                    cast(str, self.monitoring_reader_principal_id),
                    cast(str, self.athena_context_principal_id),
                }
                or self.rbac_attestor_tenant_id != self.collector_tenant_id
                or cast(
                    str,
                    self.rbac_attestor_role_definition_id,
                ).casefold()
                != expected_attestor_role_id.casefold()
                or cast(str, self.rbac_attestor_scope_id).casefold().rstrip("/")
                != expected_attestor_scope.casefold()
                or self.rbac_attestor_allowed_operations != _EXPECTED_RBAC_ATTESTOR_OPERATIONS
            ):
                raise ValueError("RBAC attestor identity and exact read-only role are invalid")

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
        if self.schema_version in {
            MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        }:
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
                or inventory.collector_grants != _expected_monitoring_effective_rbac_grants(self)
                or any(
                    _effective_grant_affects_acquisition_scope(item, self)
                    for item in inventory.athena_context_grants
                )
            ):
                raise ValueError(
                    "effective RBAC inventory does not match exact deployed assignments"
                )
            if (
                self.schema_version
                == MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION
            ):
                if (
                    inventory.schema_version != "athena.wc028MonitoringEffectiveRbacInventory.v1"
                    or inventory.resource_log_reader_role_actions
                    != tuple(
                        sorted(
                            item.casefold() for item in _EXPECTED_PREVIOUS_RESOURCE_LOG_OPERATIONS
                        )
                    )
                    or inventory.ip_flow_verify_role_actions
                    != tuple(
                        sorted(item.casefold() for item in _EXPECTED_IP_FLOW_VERIFY_OPERATIONS)
                    )
                    or inventory.resource_health_role_actions
                    != tuple(
                        item.casefold() for item in _EXPECTED_PREVIOUS_RESOURCE_HEALTH_OPERATIONS
                    )
                ):
                    raise ValueError(
                        "collector contract v7 requires its exact effective RBAC inventory"
                    )
            else:
                if (
                    inventory.resource_log_reader_role_actions
                    != tuple(sorted(item.casefold() for item in _EXPECTED_RESOURCE_LOG_OPERATIONS))
                    or inventory.ip_flow_verify_role_actions is not None
                    or inventory.resource_health_role_actions
                    != tuple(item.casefold() for item in _EXPECTED_RESOURCE_HEALTH_OPERATIONS)
                    or inventory.attestor_identity_resource_id
                    != cast(str, self.rbac_attestor_identity_resource_id).casefold().rstrip("/")
                    or inventory.attestor_client_id != self.rbac_attestor_identity_client_id
                    or inventory.attestor_principal_id != self.rbac_attestor_principal_id
                    or inventory.attestor_tenant_id != self.rbac_attestor_tenant_id
                ):
                    raise ValueError(
                        "current effective RBAC inventory does not bind the separate attestor"
                    )
                _validate_current_effective_rbac_evidence(self, inventory)
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
    grants = [
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
    ]
    if contract.ip_flow_verify_role_definition_id is not None:
        grants.append(
            _effective_rbac_grant(
                principal_id=principal_id,
                role_definition_id=contract.ip_flow_verify_role_definition_id,
                role_definition_name=cast(str, contract.ip_flow_verify_role_name),
                assignment_scope_ids=(cast(str, contract.ip_flow_verify_scope_id),),
            )
        )
    return tuple(sorted(grants, key=lambda item: item.grant_digest))


def _effective_grant_affects_acquisition_scope(
    grant: MonitoringEffectiveRbacGrant,
    contract: MonitoringCollectorContract,
) -> bool:
    protected_scopes = {
        contract.workload_resource_group_id.casefold().rstrip("/"),
        contract.monitoring_resource_group_id.casefold().rstrip("/"),
        *(item.casefold().rstrip("/") for item in contract.resource_read_scope_ids),
        *(item.casefold().rstrip("/") for item in contract.signal_read_scope_ids),
        *(item.casefold().rstrip("/") for item in contract.resource_log_read_scope_ids or ()),
        *(item.casefold().rstrip("/") for item in contract.resource_health_scope_ids or ()),
    }
    if contract.ip_flow_verify_scope_id is not None:
        protected_scopes.add(contract.ip_flow_verify_scope_id.casefold().rstrip("/"))
    subscription_scope = (
        f"/subscriptions/{_parse_arm_resource_id(contract.workload_resource_group_id)[0]}"
    )
    for scope in grant.assignment_scope_ids:
        if (
            scope == "/"
            or scope.startswith("/providers/microsoft.management/managementgroups/")
            or scope == subscription_scope
            or any(
                scope == protected
                or scope.startswith(protected + "/")
                or protected.startswith(scope + "/")
                for protected in protected_scopes
            )
        ):
            return True
    return False


def _deny_assignment_applies_to_principal(
    deny: MonitoringEffectiveRbacDenyAssignment,
    *,
    principal_id: str,
    security_group_ids: tuple[str, ...],
) -> bool:
    excluded = set(deny.excluded_principal_ids)
    effective_principal_ids = {
        principal_id,
        *security_group_ids,
    }
    if effective_principal_ids.intersection(excluded):
        return False
    if not deny.principal_ids or _ALL_PRINCIPALS_ID in deny.principal_ids:
        return True
    return bool(effective_principal_ids.intersection(deny.principal_ids).difference(excluded))


def _rbac_scope_applies(
    assignment_scope: str,
    target_scope: str,
    *,
    management_group_ancestry: tuple[str, ...],
    do_not_apply_to_child_scopes: bool,
) -> bool:
    assignment = assignment_scope.casefold().rstrip("/")
    target = target_scope.casefold().rstrip("/")
    if assignment == "/":
        return not do_not_apply_to_child_scopes or target == "/"
    if target == assignment:
        return True
    if assignment.startswith("/providers/microsoft.management/managementgroups/"):
        if management_group_ancestry and assignment not in management_group_ancestry:
            return False
        return not do_not_apply_to_child_scopes
    return not do_not_apply_to_child_scopes and target.startswith(assignment + "/")


def _rbac_action_is_denied(
    action: str,
    *,
    actions: tuple[str, ...],
    not_actions: tuple[str, ...],
) -> bool:
    normalized = action.casefold()
    return any(fnmatchcase(normalized, pattern) for pattern in actions) and not any(
        fnmatchcase(normalized, pattern) for pattern in not_actions
    )


def _expected_effective_rbac_target_scopes(
    contract: MonitoringCollectorContract,
    inventory: MonitoringEffectiveRbacInventory,
) -> tuple[str, ...]:
    subscription_scope = (
        f"/subscriptions/{_parse_arm_resource_id(contract.workload_resource_group_id)[0]}"
    )
    evidence_storage_account_scope = (
        contract.evidence_storage_account_resource_id.casefold().rstrip("/")
    )
    signing_key_scope = (
        cast(
            str,
            contract.signing_key_arm_resource_id,
        )
        .casefold()
        .rstrip("/")
    )
    signing_key_vault_scope = signing_key_scope.rsplit("/keys/", maxsplit=1)[0]
    network_watcher_parent_scopes: set[str] = set()
    for scope in contract.resource_read_scope_ids:
        normalized = scope.casefold().rstrip("/")
        if "/providers/microsoft.network/networkwatchers/" not in normalized:
            continue
        segments = normalized.strip("/").split("/")
        network_watcher_index = segments.index("networkwatchers")
        network_watcher_parent_scopes.add("/" + "/".join(segments[: network_watcher_index + 2]))
        network_watcher_parent_scopes.add("/" + "/".join(segments[:4]))
    return tuple(
        sorted(
            {
                subscription_scope.casefold(),
                contract.workload_resource_group_id.casefold().rstrip("/"),
                contract.monitoring_resource_group_id.casefold().rstrip("/"),
                contract.workload_virtual_network_resource_id.casefold().rstrip("/"),
                contract.workspace_resource_id.casefold().rstrip("/"),
                *(
                    f"{contract.workspace_resource_id.casefold().rstrip('/')}/tables/"
                    f"{table_name.casefold()}"
                    for table_name in contract.log_analytics_allowed_tables
                ),
                evidence_storage_account_scope,
                f"{evidence_storage_account_scope}/blobservices/default",
                cast(
                    str,
                    contract.evidence_container_resource_id,
                )
                .casefold()
                .rstrip("/"),
                signing_key_vault_scope,
                signing_key_scope,
                *network_watcher_parent_scopes,
                *inventory.management_group_ancestry,
                *(
                    scope
                    for grant in inventory.collector_grants
                    for scope in grant.assignment_scope_ids
                ),
            }
        )
    )


def _validate_current_effective_rbac_evidence(
    contract: MonitoringCollectorContract,
    inventory: MonitoringEffectiveRbacInventory,
) -> None:
    if inventory.schema_version != "athena.wc028MonitoringEffectiveRbacInventory.v3":
        raise ValueError("current collector contract requires effective RBAC inventory v3")
    expected_targets = _expected_effective_rbac_target_scopes(contract, inventory)
    collector_evidence = cast(
        MonitoringEffectiveRbacPrincipalEvidence,
        inventory.collector_principal_evidence,
    )
    context_evidence = cast(
        MonitoringEffectiveRbacPrincipalEvidence,
        inventory.athena_context_principal_evidence,
    )
    if (
        collector_evidence.target_scope_ids != expected_targets
        or context_evidence.target_scope_ids != expected_targets
    ):
        raise ValueError("effective RBAC attestation omitted an exact target scope")

    role_definitions = cast(
        tuple[MonitoringEffectiveRbacRoleDefinition, ...],
        inventory.role_definitions,
    )
    roles_by_id = {item.role_definition_id: item for item in role_definitions}
    attestor_role_id = cast(str, contract.rbac_attestor_role_definition_id).casefold()
    expected_role_ids = {
        *(item.role_definition_id for item in inventory.collector_grants),
        *(item.role_definition_id for item in inventory.athena_context_grants),
        attestor_role_id,
    }
    if set(roles_by_id) != expected_role_ids:
        raise ValueError(
            "effective RBAC role-definition evidence is missing or contains an unreferenced role"
        )

    exact_control_plane_roles = {
        cast(str, contract.signal_reader_role_definition_id).casefold(): tuple(
            sorted(
                (
                    "microsoft.compute/virtualmachines/instanceview/read",
                    "microsoft.insights/metrics/read",
                )
            )
        ),
        cast(str, contract.resource_log_reader_role_definition_id).casefold(): tuple(
            sorted(item.casefold() for item in _EXPECTED_RESOURCE_LOG_OPERATIONS)
        ),
        cast(str, contract.resource_health_role_definition_id).casefold(): tuple(
            sorted(item.casefold() for item in _EXPECTED_RESOURCE_HEALTH_OPERATIONS)
        ),
        attestor_role_id: tuple(
            sorted(item.casefold() for item in _EXPECTED_RBAC_ATTESTOR_OPERATIONS)
        ),
    }
    for role_id, expected_actions in exact_control_plane_roles.items():
        role = roles_by_id.get(role_id)
        if (
            role is None
            or role.actions != expected_actions
            or role.not_actions
            or role.data_actions
            or role.not_data_actions
        ):
            raise ValueError("effective RBAC custom role definition does not match exact actions")

    reader_role = roles_by_id.get(contract.reader_role_definition_id.casefold())
    if reader_role is None or any(
        not _rbac_action_is_allowed(
            action,
            actions=reader_role.actions,
            not_actions=reader_role.not_actions,
        )
        for action in _EXPECTED_READ_OPERATIONS[3:]
    ):
        raise ValueError("effective RBAC Reader definition does not permit required reviewed reads")

    writer_role = roles_by_id.get(cast(str, contract.evidence_writer_role_definition_id).casefold())
    signing_role = roles_by_id.get(
        cast(str, contract.signing_key_crypto_user_role_definition_id).casefold()
    )
    if (
        writer_role is None
        or not _rbac_action_is_allowed(
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
            actions=writer_role.data_actions,
            not_actions=writer_role.not_data_actions,
        )
        or signing_role is None
        or not _rbac_action_is_allowed(
            "Microsoft.KeyVault/vaults/keys/sign/action",
            actions=signing_role.data_actions,
            not_actions=signing_role.not_data_actions,
        )
    ):
        raise ValueError("effective RBAC persistence role definitions omit required data actions")

    if cast(
        tuple[MonitoringEffectiveRbacPimScheduleInstance, ...],
        inventory.active_pim_schedule_instances,
    ):
        raise ValueError("current collector identities must not depend on active PIM assignments")

    required_control_actions: list[tuple[str, str]] = []
    for scope in contract.signal_read_scope_ids:
        required_control_actions.extend(
            (scope, action)
            for action in (
                "Microsoft.Compute/virtualMachines/instanceView/read",
                "Microsoft.Insights/metrics/read",
                *_EXPECTED_RESOURCE_LOG_OPERATIONS,
                *_EXPECTED_RESOURCE_HEALTH_OPERATIONS,
            )
        )
    for scope in contract.resource_read_scope_ids:
        required_control_actions.extend((scope, action) for action in _EXPECTED_READ_OPERATIONS[3:])
    required_data_actions = (
        (
            cast(str, contract.evidence_container_resource_id),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        ),
        (
            cast(str, contract.signing_key_arm_resource_id),
            "Microsoft.KeyVault/vaults/keys/sign/action",
        ),
    )
    for deny in cast(
        tuple[MonitoringEffectiveRbacDenyAssignment, ...],
        inventory.deny_assignments,
    ):
        if not _deny_assignment_applies_to_principal(
            deny,
            principal_id=inventory.collector_principal_id,
            security_group_ids=inventory.collector_security_group_ids,
        ):
            continue
        if any(
            _rbac_scope_applies(
                deny.scope_id,
                scope,
                management_group_ancestry=inventory.management_group_ancestry,
                do_not_apply_to_child_scopes=deny.do_not_apply_to_child_scopes,
            )
            and _rbac_action_is_denied(
                action,
                actions=deny.actions,
                not_actions=deny.not_actions,
            )
            for scope, action in required_control_actions
        ) or any(
            _rbac_scope_applies(
                deny.scope_id,
                scope,
                management_group_ancestry=inventory.management_group_ancestry,
                do_not_apply_to_child_scopes=deny.do_not_apply_to_child_scopes,
            )
            and _rbac_action_is_denied(
                action,
                actions=deny.data_actions,
                not_actions=deny.not_data_actions,
            )
            for scope, action in required_data_actions
        ):
            raise ValueError(
                "applicable Azure deny assignment removes a required collector permission"
            )


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
        pattern=(
            r"^api://(?:athena-monitoring-identity-proof|"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{12}/athena-monitoring-identity-proof)$"
        ),
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


class MonitoringAcquisitionWireAttempt(_StrictMonitoringContract):
    """One exact HTTP request/response interval within a logical acquisition exchange."""

    sequence: int = Field(ge=1, le=256)
    exchange_sequence: int = Field(alias="exchangeSequence", ge=1, le=32)
    attempt: int = Field(ge=1, le=64)
    source: Literal[
        "activityLog",
        "ipFlowVerify",
        "logAnalytics",
        "resourceGraph",
        "resourceHealth",
    ]
    logical_request_digest: str = Field(
        alias="logicalRequestDigest",
        pattern=_DIGEST_PATTERN,
    )
    wire_request_digest: str = Field(
        alias="wireRequestDigest",
        pattern=_DIGEST_PATTERN,
    )
    wire_response_digest: str = Field(
        alias="wireResponseDigest",
        pattern=_DIGEST_PATTERN,
    )
    requested_at: UtcDateTime = Field(alias="requestedAt")
    completed_at: UtcDateTime = Field(alias="completedAt")
    response_status: int = Field(alias="responseStatus", ge=100, le=599)
    response_bytes: int = Field(alias="responseBytes", ge=0, le=16 * 1024 * 1024)

    @model_validator(mode="after")
    def validate_attempt(self) -> MonitoringAcquisitionWireAttempt:
        if self.requested_at > self.completed_at:
            raise ValueError("acquisition wire-attempt times are reversed")
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


class MonitoringIpFlowProvenance(_StrictMonitoringContract):
    """Signed normalized IP Flow evidence bound to one acquisition exchange."""

    schema_version: Literal["athena.wc028MonitoringIpFlowProvenance.v1"] = Field(
        alias="schemaVersion"
    )
    exchange_sequence: int = Field(alias="exchangeSequence", ge=1, le=32)
    ip_flow_request_digest: Sha256Digest = Field(alias="ipFlowRequestDigest")
    ip_flow_result_digest: Sha256Digest = Field(alias="ipFlowResultDigest")
    traffic_analytics_request_digest: Sha256Digest = Field(alias="trafficAnalyticsRequestDigest")
    correlation_request_id: str = Field(
        alias="correlationRequestId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    target_resource_id: str = Field(
        alias="targetResourceId",
        min_length=1,
        max_length=2048,
    )
    source_resource_id: str = Field(
        alias="sourceResourceId",
        min_length=1,
        max_length=2048,
    )
    destination_resource_id: str = Field(
        alias="destinationResourceId",
        min_length=1,
        max_length=2048,
    )
    direction: Literal["inbound", "outbound"]
    protocol: Literal["Tcp", "Udp"]
    source_address: str = Field(alias="sourceAddress", min_length=2, max_length=45)
    destination_address: str = Field(
        alias="destinationAddress",
        min_length=2,
        max_length=45,
    )
    source_port: int = Field(alias="sourcePort", ge=0, le=65535)
    destination_port: int = Field(alias="destinationPort", ge=0, le=65535)
    five_tuple_digest: Sha256Digest = Field(alias="fiveTupleDigest")
    historical_decision: Literal["allowed", "denied", "unknown"] = Field(alias="historicalDecision")
    historical_rule_resource_id: str = Field(
        alias="historicalRuleResourceId",
        min_length=1,
        max_length=2048,
    )
    access: Literal["Allow", "Deny"]
    result_rule_resource_id: str | None = Field(
        default=None,
        alias="resultRuleResourceId",
        min_length=1,
        max_length=2048,
    )
    causal_change_correlation_id: str | None = Field(
        default=None,
        alias="causalChangeCorrelationId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    requested_at: UtcDateTime = Field(alias="requestedAt")
    received_at: UtcDateTime = Field(alias="receivedAt")
    checked_at: UtcDateTime = Field(alias="checkedAt")
    provenance_digest: Sha256Digest = Field(alias="provenanceDigest")

    @field_validator(
        "target_resource_id",
        "source_resource_id",
        "destination_resource_id",
        "historical_rule_resource_id",
        "result_rule_resource_id",
    )
    @classmethod
    def normalize_resource_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.casefold().rstrip("/")
        _parse_arm_resource_id(normalized)
        return normalized

    @field_validator("source_address", "destination_address")
    @classmethod
    def normalize_address(cls, value: str) -> str:
        try:
            return ip_address(value).compressed
        except ValueError as exc:
            raise ValueError("IP Flow provenance address must be canonical") from exc

    @field_validator("correlation_request_id")
    @classmethod
    def normalize_correlation_request_id(cls, value: str) -> str:
        return value.casefold()

    @model_validator(mode="after")
    def validate_provenance(self) -> MonitoringIpFlowProvenance:
        expected_target = (
            self.destination_resource_id if self.direction == "inbound" else self.source_resource_id
        )
        tuple_payload = {
            "direction": self.direction,
            "protocol": self.protocol,
            "sourceResourceId": self.source_resource_id,
            "destinationResourceId": self.destination_resource_id,
            "sourceAddress": self.source_address,
            "destinationAddress": self.destination_address,
            "sourcePort": self.source_port,
            "destinationPort": self.destination_port,
        }
        if (
            self.requested_at != self.checked_at
            or self.checked_at > self.received_at
            or self.target_resource_id != expected_target
            or self.five_tuple_digest != compute_artifact_digest(tuple_payload)
        ):
            raise ValueError(
                "IP Flow provenance does not bind exact exchange time, target, and tuple"
            )
        if self.access == "Deny" and self.result_rule_resource_id is None:
            raise ValueError("denied IP Flow provenance requires the returned rule")
        if self.causal_change_correlation_id is not None and (
            self.historical_decision != "denied"
            or self.access != "Deny"
            or self.result_rule_resource_id != self.historical_rule_resource_id
        ):
            raise ValueError(
                "causal IP Flow provenance requires exact denied decision and rule binding"
            )
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
                exclude={"provenance_digest"},
            )
        )
        if self.provenance_digest != expected:
            raise ValueError("provenanceDigest does not bind normalized IP Flow evidence")
        return self


class MonitoringSelectedIncident(_StrictMonitoringContract):
    """Minimal collector-signed incident selection bound to normalized batch IDs."""

    incident_resource_id: str = Field(
        alias="incidentResourceId",
        min_length=1,
        max_length=2048,
    )
    previous_record_id: str = Field(
        alias="previousRecordId",
        min_length=1,
        max_length=2048,
    )
    current_record_ids: tuple[str, ...] = Field(
        alias="currentRecordIds",
        min_length=1,
        max_length=32,
    )
    current_state: Literal["degraded", "unhealthy", "unavailable"] = Field(alias="currentState")
    transition_digest: Sha256Digest = Field(alias="transitionDigest")

    @field_validator("incident_resource_id")
    @classmethod
    def normalize_incident_resource_id(cls, value: str) -> str:
        normalized = value.casefold().rstrip("/")
        _parse_arm_resource_id(normalized)
        return normalized

    @field_validator("current_record_ids")
    @classmethod
    def validate_current_record_ids(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        if values != tuple(sorted(values)) or len(values) != len(set(values)):
            raise ValueError("currentRecordIds must be sorted and unique")
        return values

    @model_validator(mode="after")
    def validate_selection(self) -> MonitoringSelectedIncident:
        expected = build_selected_incident(
            incident_resource_id=self.incident_resource_id,
            previous_record_id=self.previous_record_id,
            current_record_ids=self.current_record_ids,
            current_state=self.current_state,
        )
        if (
            self.previous_record_id in self.current_record_ids
            or self.transition_digest != expected.transition_digest
        ):
            raise ValueError("transitionDigest does not bind selectedIncident")
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
    selected_incident: MonitoringSelectedIncident | None = Field(
        default=None,
        alias="selectedIncident",
    )
    execution_started_at: UtcDateTime = Field(alias="executionStartedAt")
    execution_completed_at: UtcDateTime = Field(alias="executionCompletedAt")
    receipt_issued_at: UtcDateTime = Field(alias="receiptIssuedAt")
    exchanges: tuple[MonitoringAcquisitionExchange, ...] = Field(
        min_length=0,
        max_length=32,
    )
    wire_attempts: tuple[MonitoringAcquisitionWireAttempt, ...] | None = Field(
        default=None,
        alias="wireAttempts",
        max_length=256,
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
                not self.exchanges
                or self.monitoring_reader_identity_id is not None
                or self.athena_context_principal_id is not None
                or self.authenticated_client_id is not None
                or self.authenticated_tenant_id is not None
                or self.credential_proofs is not None
                or self.identity_proof is not None
                or self.selected_incident is not None
                or any(item.credential_proof_digest is not None for item in self.exchanges)
                or any(item.identity_proof_digest is not None for item in self.exchanges)
            ):
                raise ValueError("v1 acquisition receipt cannot contain newer identity bindings")
        elif self.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v2":
            if (
                not self.exchanges
                or self.monitoring_reader_identity_id is None
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
                or self.selected_incident is not None
                or any(item.credential_proof_digest is not None for item in self.exchanges)
                or any(item.identity_proof_digest is not None for item in self.exchanges)
            ):
                raise ValueError(
                    "v2 acquisition receipt requires only resource and principal identities"
                )
        elif self.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v3":
            if (
                not self.exchanges
                or self.monitoring_reader_identity_id is None
                or self.athena_context_principal_id is None
                or self.authenticated_client_id is None
                or self.authenticated_tenant_id is None
                or self.credential_proofs is None
                or self.identity_proof is not None
                or self.selected_incident is not None
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
                if (
                    identity_proof_invalid
                    or not self.exchanges
                    or self.selected_incident is not None
                ):
                    raise ValueError(
                        "v4 acquisition receipt requires only one Athena identity proof"
                    )
            elif identity_proof_invalid or self.selected_incident is None:
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
        if (
            self.schema_version != MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION
            and self.wire_attempts
        ):
            raise ValueError("historical acquisition receipts cannot contain wire attempts")
        if self.wire_attempts:
            if tuple(item.sequence for item in self.wire_attempts) != tuple(
                range(1, len(self.wire_attempts) + 1)
            ):
                raise ValueError("acquisition wire attempts must use contiguous execution order")
            wire_request_digests = tuple(item.wire_request_digest for item in self.wire_attempts)
            if len(wire_request_digests) != len(set(wire_request_digests)):
                raise ValueError("acquisition wire request digests must be unique")
            attempts_by_exchange = {
                exchange.sequence: tuple(
                    item
                    for item in self.wire_attempts
                    if item.exchange_sequence == exchange.sequence
                )
                for exchange in self.exchanges
            }
            if any(
                item.exchange_sequence not in attempts_by_exchange for item in self.wire_attempts
            ):
                raise ValueError("wire attempt references an unknown acquisition exchange")
            for exchange in self.exchanges:
                attempts = attempts_by_exchange[exchange.sequence]
                if (
                    not attempts
                    or tuple(item.attempt for item in attempts)
                    != tuple(range(1, len(attempts) + 1))
                    or any(
                        item.source != exchange.source
                        or item.logical_request_digest != exchange.request_digest
                        or not exchange.requested_at
                        <= item.requested_at
                        <= item.completed_at
                        <= exchange.received_at
                        for item in attempts
                    )
                ):
                    raise ValueError(
                        "wire attempts do not exactly bind their logical acquisition exchange"
                    )
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
        or reviewed_collector_contract.identity_proof_application_id is None
        or reviewed_collector_contract.identity_proof_application_object_id is None
        or reviewed_collector_contract.identity_proof_service_principal_id is None
        or reviewed_collector_contract.identity_proof_app_role_id is None
        or reviewed_collector_contract.identity_proof_app_role_assignment_id is None
        or reviewed_collector_contract.identity_proof_assigned_principal_id is None
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
        or receipt.selected_incident is None
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
    if (
        not effective_rbac_inventory.collected_at
        <= receipt.execution_started_at
        <= receipt.execution_completed_at
        <= receipt.receipt_issued_at
        < effective_rbac_inventory.expires_at
        or (receipt.receipt_issued_at - effective_rbac_inventory.collected_at).total_seconds()
        > maximum_receipt_age_seconds
    ):
        raise ValueError(
            "acquisition receipt execution is outside measured effective RBAC lifetime"
        )
    if any(
        not effective_rbac_inventory.collected_at
        <= exchange.requested_at
        <= exchange.received_at
        < effective_rbac_inventory.expires_at
        or (exchange.received_at - effective_rbac_inventory.collected_at).total_seconds()
        > maximum_receipt_age_seconds
        for exchange in receipt.exchanges
    ):
        raise ValueError(
            "acquisition receipt exchange times escape measured effective RBAC lifetime"
        )
    wire_attempts = receipt.wire_attempts or ()
    if receipt.exchanges and not wire_attempts:
        raise ValueError("production acquisition receipt omitted wire-attempt timing")
    if any(
        not effective_rbac_inventory.collected_at
        <= attempt.requested_at
        <= attempt.completed_at
        < effective_rbac_inventory.expires_at
        or (attempt.completed_at - effective_rbac_inventory.collected_at).total_seconds()
        > maximum_receipt_age_seconds
        for attempt in wire_attempts
    ):
        raise ValueError("acquisition wire-attempt times escape measured effective RBAC lifetime")
    attempts_by_exchange = {
        exchange.sequence: tuple(
            attempt for attempt in wire_attempts if attempt.exchange_sequence == exchange.sequence
        )
        for exchange in receipt.exchanges
    }
    if any(
        not attempts_by_exchange[exchange.sequence]
        or any(
            attempt.source != exchange.source
            or attempt.logical_request_digest != exchange.request_digest
            or not exchange.requested_at
            <= attempt.requested_at
            <= attempt.completed_at
            <= exchange.received_at
            for attempt in attempts_by_exchange[exchange.sequence]
        )
        for exchange in receipt.exchanges
    ):
        raise ValueError("acquisition wire attempts do not bind every signed exchange")
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
    "MONITORING_PREVIOUS_MEASURED_RBAC_COLLECTOR_CONTRACT_SCHEMA_VERSION",
    "MONITORING_PREVIOUS_PRODUCTION_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION",
    "MonitoringAcquisitionExchange",
    "MonitoringAcquisitionReceipt",
    "MonitoringAcquisitionWireAttempt",
    "MonitoringCollectorContract",
    "MonitoringCredentialProof",
    "MonitoringEffectiveRbacGrant",
    "MonitoringEffectiveRbacDenyAssignment",
    "MonitoringEffectiveRbacInventory",
    "MonitoringEffectiveRbacPimScheduleInstance",
    "MonitoringEffectiveRbacPrincipalEvidence",
    "MonitoringEffectiveRbacRoleDefinition",
    "MonitoringEvidenceAttestation",
    "MonitoringEvidenceHandoff",
    "MonitoringIdentityProof",
    "MonitoringIpFlowProvenance",
    "MonitoringLogPermissionDataSource",
    "MonitoringLogPermissionEvidence",
    "MonitoringLogPermissionResource",
    "MonitoringResourceContextTablePlan",
    "MonitoringSelectedIncident",
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
