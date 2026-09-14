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

MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION = "athena.wc024MonitoringCollectorContract.v2"
MONITORING_LEGACY_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION = (
    "athena.wc028MonitoringCollectorContract.v3"
)
MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION = (
    "athena.wc028MonitoringCollectorContract.v4"
)
MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION = "athena.wc024MonitoringEvidenceHandoff.v1"
MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION = "athena.wc028MonitoringAcquisitionReceipt.v3"
MONITORING_ACQUISITION_HANDOFF_SCHEMA_VERSION = "athena.wc028MonitoringEvidenceHandoff.v2"

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
]
type MonitoringIpFlowVerifyOperation = Literal[
    "Microsoft.Network/networkWatchers/ipFlowVerify/action",
    "Microsoft.Network/networkWatchers/ipFlowVerify/read",
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
_LOG_ANALYTICS_DATA_READER_ROLE_DEFINITION_GUID = "3b03c2da-16b3-4a49-8834-0f8130efdd3b"
_IP_FLOW_VERIFY_ROLE_DEFINITION_GUID = "3728cdf6-4efd-5282-bdfc-63b7872fd801"
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
_EXPECTED_ACQUISITION_READ_OPERATIONS: tuple[MonitoringReadOperation, ...] = (
    *_EXPECTED_READ_OPERATIONS,
    *_EXPECTED_IP_FLOW_VERIFY_OPERATIONS,
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


class MonitoringCollectorContract(_StrictMonitoringContract):
    """Reviewed generic boundary for one identity-isolated monitoring collector."""

    schema_version: Literal[
        "athena.wc024MonitoringCollectorContract.v2",
        "athena.wc028MonitoringCollectorContract.v3",
        "athena.wc028MonitoringCollectorContract.v4",
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
    evidence_storage_account_resource_id: str = Field(
        alias="evidenceStorageAccountResourceId",
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
        Literal["athena.wc028MonitoringAcquisitionReceipt.v3"] | None
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
                MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            }
            and self.handoff_schema_version != MONITORING_ACQUISITION_HANDOFF_SCHEMA_VERSION
        ):
            raise ValueError("collector contract version does not authorize its handoff schema")
        if self.signal_kinds != _EXPECTED_SIGNALS:
            raise ValueError("monitoring signals must use the complete reviewed generic allowlist")
        expected_read_operations = (
            _EXPECTED_ACQUISITION_READ_OPERATIONS
            if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION
            else _EXPECTED_READ_OPERATIONS
        )
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
            self.acquisition_receipt_schema_version,
        )
        if self.schema_version == MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION:
            if any(
                item is not None
                for item in (*acquisition_identity_fields, *credential_and_ip_flow_fields)
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
            and any(item is not None for item in credential_and_ip_flow_fields)
        ):
            raise ValueError(
                "legacy WC-028 collector contract cannot contain credential or IP Flow policy"
            )
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION:
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
        if self.schema_version == MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION:
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
        return self


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
    """Verified Entra proof for the exact credential whose token authorized Azure calls."""

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


class MonitoringAcquisitionReceipt(_StrictMonitoringContract):
    """Immutable collector-signed provenance for one bounded acquisition execution."""

    schema_version: Literal[
        "athena.wc028MonitoringAcquisitionReceipt.v1",
        "athena.wc028MonitoringAcquisitionReceipt.v2",
        "athena.wc028MonitoringAcquisitionReceipt.v3",
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
                or any(item.credential_proof_digest is not None for item in self.exchanges)
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
                or any(item.credential_proof_digest is not None for item in self.exchanges)
            ):
                raise ValueError(
                    "v2 acquisition receipt requires only resource and principal identities"
                )
        elif (
            self.monitoring_reader_identity_id is None
            or self.athena_context_principal_id is None
            or self.authenticated_client_id is None
            or self.authenticated_tenant_id is None
            or self.credential_proofs is None
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                self.authenticated_principal_id,
            )
            is None
        ):
            raise ValueError("v3 acquisition receipt requires credential-bound identities")
        if self.schema_version in {
            "athena.wc028MonitoringAcquisitionReceipt.v2",
            "athena.wc028MonitoringAcquisitionReceipt.v3",
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
        or receipt.credential_proofs is None
    ):
        raise ValueError("production verification requires credential-bound acquisition receipt v3")
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
            "monitoringReaderHasReadOnlyWorkloadAccess": True,
            "athenaContextHasWorkloadReader": False,
            "readOnly": True,
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
        or any(
            proof.principal_id.casefold() != expected_authenticated_principal_id.casefold()
            or proof.client_id.casefold() != expected_authenticated_client_id.casefold()
            or proof.tenant_id.casefold() != expected_authenticated_tenant_id.casefold()
            for proof in receipt.credential_proofs
        )
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
    "MONITORING_LEGACY_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION",
    "MonitoringAcquisitionExchange",
    "MonitoringAcquisitionReceipt",
    "MonitoringCollectorContract",
    "MonitoringCredentialProof",
    "MonitoringEvidenceAttestation",
    "MonitoringEvidenceHandoff",
    "MonitoringIpFlowVerifyOperation",
    "MonitoringReadOperation",
    "MonitoringSignalKind",
    "monitoring_acquisition_receipt_preimage",
    "monitoring_handoff_preimage",
    "verify_monitoring_acquisition_receipt_attestation",
    "verify_monitoring_evidence_handoff_attestation",
]
