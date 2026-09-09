from __future__ import annotations

import base64
import re
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import canonicalize_json, compute_artifact_digest
from athena_context.contracts.models import (
    AthenaBaseModel,
    TrustedKeyAnchor,
    TrustedKeyResolver,
    UtcDateTime,
)
from athena_context.contracts.operational_phase import VersionPinnedBlobReference

MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION = (
    "athena.wc024MonitoringCollectorContract.v1"
)
MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION = (
    "athena.wc024MonitoringEvidenceHandoff.v1"
)

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
    "Microsoft.OperationalInsights/workspaces/query/Heartbeat/read",
    "Microsoft.OperationalInsights/workspaces/query/Perf/read",
    "Microsoft.OperationalInsights/workspaces/query/InsightsMetrics/read",
    "Microsoft.OperationalInsights/workspaces/query/Syslog/read",
    "Microsoft.OperationalInsights/workspaces/query/VMComputer/read",
    "Microsoft.OperationalInsights/workspaces/query/VMConnection/read",
    "Microsoft.OperationalInsights/workspaces/query/VMBoundPort/read",
    "Microsoft.OperationalInsights/workspaces/query/VMProcess/read",
    "Microsoft.OperationalInsights/workspaces/query/NTANetAnalytics/read",
    "Microsoft.Insights/Metrics/Read",
    "Microsoft.Insights/dataCollectionRules/read",
    "Microsoft.Insights/dataCollectionEndpoints/read",
    "Microsoft.Insights/dataCollectionRuleAssociations/read",
    "Microsoft.Insights/privateLinkScopes/read",
    "Microsoft.Network/networkWatchers/flowLogs/read",
    "Microsoft.Network/networkWatchers/connectionMonitors/read",
    "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorDestinationListenerResult/read",
    "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorDNSResult/read",
    "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorPathResult/read",
    "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorTestResult/read",
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
_REVIEWED_WORKLOAD_RESOURCE_GROUP = "rg-athena-demo-workload"
_REVIEWED_WORKLOAD_VNET_NAME = "athena-hackathon-vnet"
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
    "Microsoft.OperationalInsights/workspaces/query/Heartbeat/read",
    "Microsoft.OperationalInsights/workspaces/query/Perf/read",
    "Microsoft.OperationalInsights/workspaces/query/InsightsMetrics/read",
    "Microsoft.OperationalInsights/workspaces/query/Syslog/read",
    "Microsoft.OperationalInsights/workspaces/query/VMComputer/read",
    "Microsoft.OperationalInsights/workspaces/query/VMConnection/read",
    "Microsoft.OperationalInsights/workspaces/query/VMBoundPort/read",
    "Microsoft.OperationalInsights/workspaces/query/VMProcess/read",
    "Microsoft.OperationalInsights/workspaces/query/NTANetAnalytics/read",
    "Microsoft.Insights/Metrics/Read",
    "Microsoft.Insights/dataCollectionRules/read",
    "Microsoft.Insights/dataCollectionEndpoints/read",
    "Microsoft.Insights/dataCollectionRuleAssociations/read",
    "Microsoft.Insights/privateLinkScopes/read",
    "Microsoft.Network/networkWatchers/flowLogs/read",
    "Microsoft.Network/networkWatchers/connectionMonitors/read",
    "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorDestinationListenerResult/read",
    "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorDNSResult/read",
    "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorPathResult/read",
    "Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorTestResult/read",
)


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

    schema_version: Literal["athena.wc024MonitoringCollectorContract.v1"] = Field(
        alias="schemaVersion"
    )
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
    evidence_container_name: Literal["monitoring-evidence"] = Field(
        alias="evidenceContainerName"
    )
    signal_kinds: tuple[MonitoringSignalKind, ...] = Field(
        alias="signalKinds",
        min_length=len(_EXPECTED_SIGNALS),
        max_length=len(_EXPECTED_SIGNALS),
    )
    allowed_read_operations: tuple[MonitoringReadOperation, ...] = Field(
        alias="allowedReadOperations",
        min_length=len(_EXPECTED_READ_OPERATIONS),
        max_length=len(_EXPECTED_READ_OPERATIONS),
    )
    collection_mode: Literal["isolatedSignedCollector"] = Field(alias="collectionMode")
    handoff_schema_version: Literal["athena.wc024MonitoringEvidenceHandoff.v1"] = Field(
        alias="handoffSchemaVersion"
    )
    maximum_evidence_age_seconds: int = Field(
        alias="maximumEvidenceAgeSeconds",
        ge=60,
        le=900,
    )
    connection_monitor_mode: Literal["capabilityOnly"] = Field(
        alias="connectionMonitorMode"
    )
    connection_monitor_deployment_mode: Literal["capability-only"] = Field(
        alias="connectionMonitorDeploymentMode"
    )

    @field_validator("workload_virtual_network_resource_id")
    @classmethod
    def canonicalize_workload_vnet_id(cls, value: str) -> str:
        subscription_id, resource_group, provider, resource_types = (
            _parse_arm_resource_id(value)
        )
        if (
            resource_group == _REVIEWED_WORKLOAD_RESOURCE_GROUP
            and provider == "microsoft.network"
            and resource_types == ("virtualnetworks",)
            and value.rsplit("/", 1)[-1].casefold()
            == _REVIEWED_WORKLOAD_VNET_NAME
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
        if self.signal_kinds != _EXPECTED_SIGNALS:
            raise ValueError("monitoring signals must use the complete reviewed generic allowlist")
        if self.allowed_read_operations != _EXPECTED_READ_OPERATIONS:
            raise ValueError(
                "monitoring read operations must use the complete reviewed allowlist"
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


class MonitoringEvidenceHandoff(_StrictMonitoringContract):
    """Version-pinned evidence reference emitted only by the isolated collector."""

    schema_version: Literal["athena.wc024MonitoringEvidenceHandoff.v1"] = Field(
        alias="schemaVersion"
    )
    collector_contract_digest: str = Field(
        alias="collectorContractDigest",
        pattern=_DIGEST_PATTERN,
    )
    collection_id: str = Field(alias="collectionId", pattern=_COLLECTION_ID_PATTERN)
    observed_at: UtcDateTime = Field(alias="observedAt")
    evidence: VersionPinnedBlobReference
    collector_attestation: MonitoringEvidenceAttestation = Field(
        alias="collectorAttestation"
    )

    @model_validator(mode="after")
    def bind_exact_evidence_and_attestation(self) -> MonitoringEvidenceHandoff:
        expected_name = f"wc024-monitoring/{self.collection_id}/evidence.json"
        if self.evidence.name != expected_name:
            raise ValueError("monitoring evidence reference name is not deterministic")
        if (
            self.collector_attestation.signed_preimage_digest
            != compute_artifact_digest(monitoring_handoff_preimage(self))
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
        "domain": MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
        "handoff": payload,
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
) -> None:
    """Fail closed unless a reviewed contract, trusted time, and exact key bind the handoff.

    Callers must provide either the full reviewed collector contract, or the reviewed
    collector-contract digest, maximum evidence age, and signing key. ``as_of`` is supplied by the
    trusted caller so verification never depends on local wall-clock time.
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


__all__ = [
    "MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION",
    "MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION",
    "MonitoringCollectorContract",
    "MonitoringEvidenceAttestation",
    "MonitoringEvidenceHandoff",
    "MonitoringReadOperation",
    "MonitoringSignalKind",
    "monitoring_handoff_preimage",
    "verify_monitoring_evidence_handoff_attestation",
]
