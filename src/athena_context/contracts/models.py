from __future__ import annotations

import base64
import re
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    compute_artifact_digest,
    compute_semantic_digest,
    normalize_nfc_text,
)


class AthenaBaseModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        validate_assignment=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_json(self) -> str:
        return canonicalize_json(self.model_dump(mode="json", exclude_none=True, by_alias=True))

    def compute_artifact_digest_value(self) -> str:
        payload = self.model_dump(mode="json", exclude_none=True, by_alias=True)
        return compute_artifact_digest(payload)

    def compute_semantic_digest_value(self) -> str:
        payload = self._semantic_projection()
        return compute_semantic_digest(payload)

    def _semantic_projection(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for field_name, field_info in self.__class__.model_fields.items():
            value = getattr(self, field_name)
            if not self._is_semantic_field(field_info):
                continue
            if value is None:
                result[field_name] = None
                continue
            if isinstance(value, AthenaBaseModel):
                result[field_name] = value._semantic_projection()
                continue
            if isinstance(value, list):
                result[field_name] = [
                    item._semantic_projection() if isinstance(item, AthenaBaseModel) else item
                    for item in value
                ]
                continue
            if isinstance(value, dict):
                result[field_name] = {
                    key: item._semantic_projection() if isinstance(item, AthenaBaseModel) else item
                    for key, item in value.items()
                }
                continue
            result[field_name] = value
        return result

    @staticmethod
    def _is_semantic_field(field_info: Any) -> bool:
        extra = field_info.json_schema_extra or {}
        if not isinstance(extra, dict):
            return False
        semantic_value = extra.get("x-athena-semanticClass") or extra.get("x-athena-semantic-class")
        return semantic_value == "semantic"

    @classmethod
    def on_model_validate(cls) -> None:
        return None

    @model_validator(mode="after")
    def validate_timezone_aware_datetimes(self) -> AthenaBaseModel:
        for field_name in self.__class__.model_fields:
            value = getattr(self, field_name)
            if isinstance(value, datetime) and value.tzinfo is None:
                alias = self.__class__.model_fields[field_name].alias or field_name
                raise AthenaValidationError(f"{alias} must be timezone-aware")
        return self


type Verdict = Literal[
    "pass",
    "violation",
    "expectedConstraint",
    "acceptedResidualRisk",
    "observation",
    "unknown",
    "conflicting",
]

type FindingKind = Literal[
    "architectureConstraint",
    "technologyConstraint",
    "actualSpof",
    "controlHealth",
    "riskAcceptance",
    "objective",
    "relationshipConflict",
    "evidenceGap",
]

type RoleKind = Literal[
    "singletonDatabase",
    "databaseReplica",
    "worker",
    "webService",
    "loadBalancer",
    "integrationEndpoint",
    "storage",
    "network",
    "identity",
    "observability",
    "externalDependency",
]

type ProfileType = Literal[
    "production", "development", "training", "test", "disasterRecovery", "sandbox"
]

type CapConstraint = Literal["critical", "high", "medium", "low", "informational"]

type CapabilityRequiredFor = Literal["read", "publish", "evaluate", "render"]

type ConstraintType = Literal[
    "cardinality",
    "zoneColocation",
    "zoneDistribution",
    "dependencyRequired",
    "dependencyProhibited",
    "supportedSingleton",
    "objectiveRequired",
    "evidenceFreshness",
    "controlRequired",
]

type ProofKind = Literal[
    "cardinalityProof",
    "zoneColocationProof",
    "zoneDistributionProof",
    "relationshipPresenceProof",
    "evidenceFreshnessProof",
    "controlHealthProof",
    "objectiveThresholdProof",
]

type RelationshipClass = Literal["declared", "observed", "inferred", "exception"]
type RelationshipKind = Literal[
    "requires",
    "dependsOn",
    "calls",
    "storesDataIn",
    "replicatesTo",
    "failsOverTo",
    "sharesZoneWith",
    "isolatedFrom",
    "monitors",
    "protectedBy",
    "prohibited",
]

type SelectorType = Literal[
    "resourceIdList",
    "tagPredicate",
    "namePattern",
    "resourceTypeScope",
    "compositeAll",
    "compositeAny",
]

type EvidenceRecordType = Literal[
    "resource",
    "observedRelationship",
    "metricAggregate",
    "healthEvent",
    "activitySummary",
    "advisorRecommendation",
    "evidenceGap",
]
type ExpectedEvidenceRecordType = Literal[
    "resource",
    "observedRelationship",
    "metricAggregate",
    "healthEvent",
    "activitySummary",
    "advisorRecommendation",
]

type AttemptType = Literal[
    "successResponse",
    "failedResponse",
    "timeoutNoResponse",
    "authorizationFailure",
    "toolUnavailable",
]

type OwnerRole = Literal[
    "businessOwner",
    "technicalOwner",
    "operationsOwner",
    "securityOwner",
    "vendorOwner",
    "approver",
    "onCallGroup",
]

type ScopeType = Literal[
    "subscription", "resourceGroup", "resourceId", "logAnalyticsWorkspace", "serviceHealthRegion"
]
type AzureCloud = Literal[
    "azureCloud",
    "azureChinaCloud",
    "azureUSGovernment",
    "azureGermanCloud",
]
type GovernanceScopeType = Literal[
    "manifest",
    "profile",
    "clause",
    "role",
    "resourceBinding",
    "relationship",
    "control",
    "objective",
]

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_KID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_SHA256_RE = re.compile(r"^sha256:[a-fA-F0-9]{64}$")
_AZURE_REGION_RE = re.compile(r"^(?!.*[*?])(?:[a-z0-9]+(?:-[a-z0-9]+)*)$")
_KEY_VAULT_KEY_ID_RE = re.compile(
    r"^https://[A-Za-z0-9-]+\.vault\.azure\.net/keys/[A-Za-z0-9-]{1,127}/[A-Za-z0-9-]{1,127}$"
)
_TRANSPORT_ONLY_ENVELOPE_FIELDS = frozenset(
    {
        "requestId",
        "correlationId",
        "retryCount",
        "transportLatencyMs",
        "receivedAt",
        "rawTransportHeaders",
        "bearerToken",
        "rawBearerToken",
    }
)

type EvidenceEnvelopeResolver = Callable[[str, Literal["response", "failure"], str], Any]


def _is_valid_guid(value: str) -> bool:
    return bool(_GUID_RE.fullmatch(value)) and "*" not in value and "?" not in value


def _is_sha256_digest(value: str | None) -> bool:
    return value is not None and bool(_SHA256_RE.fullmatch(value))


def _is_valid_json_pointer(value: str | None) -> bool:
    if value is None:
        return False
    if value == "":
        return True
    if not value.startswith("/"):
        return False
    for token in value.split("/")[1:]:
        if not token:
            continue
        index = 0
        while index < len(token):
            if token[index] == "~":
                if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
                    return False
                index += 2
            else:
                index += 1
    return True


def _json_digest_payload(value: Any) -> Any:
    if isinstance(value, AthenaBaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, dict):
        return {
            key: _json_digest_payload(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [_json_digest_payload(item) for item in value]
    return value


def _without_root_fields(value: Any, excluded_fields: frozenset[str]) -> dict[str, Any]:
    payload = _json_digest_payload(value)
    if not isinstance(payload, dict):
        raise AthenaValidationError("digest preimage must be a JSON object")
    return {key: item for key, item in payload.items() if key not in excluded_fields}


def _without_root_fields_preserving_nulls(
    value: Any, excluded_fields: frozenset[str]
) -> dict[str, Any]:
    if isinstance(value, AthenaBaseModel):
        payload = value.model_dump(mode="json", by_alias=True)
    else:
        payload = value
    if not isinstance(payload, dict):
        raise AthenaValidationError("digest preimage must be a JSON object")
    return {key: item for key, item in payload.items() if key not in excluded_fields}


def compute_evidence_record_digest(value: Any) -> str:
    return compute_artifact_digest(_without_root_fields(value, frozenset({"itemDigest"})))


def compute_token_verification_digest(value: Any) -> str:
    return compute_artifact_digest(
        _without_root_fields_preserving_nulls(
            value,
            frozenset({"tokenVerificationDigest"}),
        )
    )


def compute_response_envelope_digest(value: Any) -> str:
    return compute_artifact_digest(_response_envelope_digest_preimage(value))


def _response_envelope_digest_preimage(value: Any) -> dict[str, Any]:
    return _without_root_fields_preserving_nulls(
        value,
        _TRANSPORT_ONLY_ENVELOPE_FIELDS | frozenset({"responseDigest"}),
    )


def compute_failure_envelope_digest(value: Any) -> str:
    return compute_artifact_digest(_failure_envelope_digest_preimage(value))


def _failure_envelope_digest_preimage(value: Any) -> dict[str, Any]:
    return _without_root_fields_preserving_nulls(
        value,
        _TRANSPORT_ONLY_ENVELOPE_FIELDS | frozenset({"failureDigest"}),
    )


def compute_evidence_snapshot_artifact_digest(value: Any) -> str:
    return compute_artifact_digest(_snapshot_digest_preimage(value))


def compute_evidence_snapshot_semantic_digest(value: Any) -> str:
    return compute_semantic_digest(
        _snapshot_digest_preimage(value)
    )


def _snapshot_digest_preimage(value: Any) -> dict[str, Any]:
    payload = _without_root_fields(value, frozenset())
    compatibility = payload.get("compatibility")
    if not isinstance(compatibility, dict):
        raise AthenaValidationError("snapshot digest preimage requires compatibility metadata")
    compatibility = dict(compatibility)
    compatibility.pop("artifactDigest", None)
    compatibility.pop("semanticDigest", None)
    payload["compatibility"] = compatibility
    evidence_refs = payload.get("evidenceRefs", [])
    if not isinstance(evidence_refs, list):
        raise AthenaValidationError("snapshot digest preimage requires an evidenceRefs array")
    sanitized_refs: list[Any] = []
    for evidence_ref in evidence_refs:
        if not isinstance(evidence_ref, dict):
            raise AthenaValidationError("snapshot evidenceRefs must contain JSON objects")
        sanitized_ref = dict(evidence_ref)
        sanitized_ref.pop("snapshotArtifactDigest", None)
        sanitized_ref.pop("snapshotSemanticDigest", None)
        sanitized_refs.append(sanitized_ref)
    payload["evidenceRefs"] = sanitized_refs
    return payload


def _parse_azure_resource_id(value: str) -> tuple[str, ...]:
    if value != value.strip() or "\\" in value or any(token in value for token in ("*", "?")):
        raise AthenaValidationError("Azure resource ID contains invalid characters")
    raw_parts = value.split("/")
    if len(raw_parts) < 3 or raw_parts[0] != "" or any(part == "" for part in raw_parts[1:]):
        raise AthenaValidationError("Azure resource ID must be an absolute component path")
    parts = tuple(part.casefold() for part in raw_parts[1:])
    if parts[0] != "subscriptions" or not _is_valid_guid(parts[1]):
        raise AthenaValidationError("Azure resource ID must begin with /subscriptions/{guid}")

    index = 2
    if index < len(parts) and parts[index] == "resourcegroups":
        if index + 1 >= len(parts):
            raise AthenaValidationError("Azure resource ID resourceGroups segment is incomplete")
        index += 2
    if index == len(parts):
        return parts
    while index < len(parts):
        if parts[index] != "providers" or index + 3 >= len(parts):
            raise AthenaValidationError("Azure resource ID provider path is malformed")
        index += 2
        resource_component_count = 0
        while index < len(parts) and parts[index] != "providers":
            if index + 1 >= len(parts):
                raise AthenaValidationError("Azure resource ID type/name path is incomplete")
            resource_component_count += 2
            index += 2
        if resource_component_count == 0:
            raise AthenaValidationError("Azure resource ID provider has no resource type/name")
    return parts


def _resource_id_parts_from_scope(scope: Any) -> tuple[str, ...] | None:
    if isinstance(scope, ResourceIdScope):
        return _parse_azure_resource_id(scope.resource_id)
    if isinstance(scope, SubscriptionScope):
        return ("subscriptions", scope.subscription_id.casefold())
    if isinstance(scope, ResourceGroupScope):
        return (
            "subscriptions",
            scope.subscription_id.casefold(),
            "resourcegroups",
            scope.resource_group_name.casefold(),
        )
    if isinstance(scope, LogAnalyticsWorkspaceScope):
        return (
            "subscriptions",
            scope.subscription_id.casefold(),
            "resourcegroups",
            scope.resource_group_name.casefold(),
            "providers",
            "microsoft.operationalinsights",
            "workspaces",
            scope.workspace_name.casefold(),
        )
    return None


def _components_contain(container: tuple[str, ...], candidate: tuple[str, ...]) -> bool:
    return len(container) <= len(candidate) and candidate[: len(container)] == container


def _scope_contains(container: Any, candidate: Any) -> bool:
    if container.__class__ is candidate.__class__:
        container_payload = container.model_dump(mode="json", by_alias=True)
        candidate_payload = candidate.model_dump(mode="json", by_alias=True)
        return canonicalize_json(container_payload) == canonicalize_json(candidate_payload)
    if isinstance(container, SubscriptionScope):
        if isinstance(candidate, ResourceGroupScope):
            return (
                candidate.tenant_id == container.tenant_id
                and candidate.subscription_id == container.subscription_id
            )
        if isinstance(candidate, ResourceIdScope):
            return _components_contain(
                _resource_id_parts_from_scope(container) or (),
                _parse_azure_resource_id(candidate.resource_id),
            )
        if isinstance(candidate, LogAnalyticsWorkspaceScope):
            return (
                candidate.tenant_id == container.tenant_id
                and candidate.subscription_id == container.subscription_id
            )
        return False
    if isinstance(container, ResourceGroupScope):
        if isinstance(candidate, ResourceIdScope):
            return _components_contain(
                _resource_id_parts_from_scope(container) or (),
                _parse_azure_resource_id(candidate.resource_id),
            )
        return False
    if isinstance(container, LogAnalyticsWorkspaceScope):
        if isinstance(candidate, ResourceIdScope):
            return _components_contain(
                _resource_id_parts_from_scope(container) or (),
                _parse_azure_resource_id(candidate.resource_id),
            )
        return False
    if isinstance(container, ServiceHealthRegionScope):
        if isinstance(candidate, ServiceHealthRegionScope):
            return (
                candidate.cloud == container.cloud and candidate.region == container.region
            )
        return False
    return False


def _resolve_json_pointer(envelope: Any, pointer: str) -> Any:
    if not _is_valid_json_pointer(pointer):
        raise AthenaValidationError("envelope pointer is not valid RFC 6901 syntax")
    current = envelope
    if pointer == "":
        return current
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise AthenaValidationError("envelope pointer does not resolve")
            current = current[token]
            continue
        if isinstance(current, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token):
                raise AthenaValidationError("envelope array pointer token is invalid")
            index = int(token)
            if index >= len(current):
                raise AthenaValidationError("envelope pointer does not resolve")
            current = current[index]
            continue
        raise AthenaValidationError("envelope pointer traverses a scalar value")
    return current


def _validate_evidence_record_digest(record: AthenaBaseModel) -> None:
    item_digest = getattr(record, "item_digest", None)
    if not _is_sha256_digest(item_digest):
        raise AthenaValidationError("evidence record itemDigest must be a sha256 digest")
    expected = compute_evidence_record_digest(record)
    if item_digest != expected:
        raise AthenaValidationError(
            "evidence record itemDigest mismatched the canonical record "
            "without its own digest"
        )


def _attempt_observation_time(attempt: Any) -> datetime:
    if attempt.attempt_type in {"successResponse", "failedResponse"}:
        return attempt.response_received_at
    if attempt.attempt_type == "timeoutNoResponse":
        return attempt.timed_out_at
    return attempt.observed_at


def _attempt_binding_payload(attempt: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attemptId": attempt.attempt_id,
        "attemptType": attempt.attempt_type,
        "attemptDigest": attempt.attempt_digest,
        "toolName": attempt.tool_name,
        "toolVersion": attempt.tool_version,
        "requestDigest": attempt.request_digest,
        "attemptStartedAt": attempt.attempt_started_at,
    }
    if attempt.attempt_type == "successResponse":
        payload["responseDigest"] = attempt.response_digest
        payload["responseReceivedAt"] = attempt.response_received_at
    elif attempt.attempt_type == "failedResponse":
        payload["failureDigest"] = attempt.failure_digest
        payload["responseReceivedAt"] = attempt.response_received_at
    elif attempt.attempt_type == "timeoutNoResponse":
        payload["deadlineAt"] = attempt.deadline_at
        payload["timedOutAt"] = attempt.timed_out_at
    else:
        payload["observedAt"] = attempt.observed_at
    return payload


def _evidence_source_projection(record: AthenaBaseModel) -> dict[str, Any]:
    return _without_root_fields(
        record,
        frozenset(
            {
                "provenance",
                "itemDigest",
                "collectorAttemptDigest",
                "collectorIdentityEvidenceRef",
            }
        ),
    )


def _is_valid_key_vault_key_id(value: str) -> bool:
    return value is not None and bool(_KEY_VAULT_KEY_ID_RE.fullmatch(value)) and "\\" not in value


def _is_valid_azure_region(value: str | None) -> bool:
    return (
        value is not None
        and bool(_AZURE_REGION_RE.fullmatch(value))
        and "*" not in value
        and "?" not in value
        and "\\" not in value
    )


def verify_key_vault_signature(
    *,
    raw_signature: str,
    preimage: str | bytes,
    public_key: Any,
    algorithm: Literal["RS256"] = "RS256",
) -> bool:
    if algorithm != "RS256":
        return False
    if raw_signature in {"", "none", "alg:none"}:
        return False
    try:
        signature_bytes = base64.b64decode(raw_signature, validate=True)
    except (TypeError, ValueError):
        return False
    if not signature_bytes:
        return False
    if isinstance(public_key, (bytes, bytearray)):
        try:
            public_key = serialization.load_pem_public_key(bytes(public_key))
        except (ValueError, TypeError):
            return False
    payload = preimage.encode("utf-8") if isinstance(preimage, str) else preimage
    try:
        public_key.verify(
            signature_bytes,
            payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except (AttributeError, TypeError, ValueError, InvalidSignature):
        return False


def verify_trusted_ingestion_signature(
    identity_evidence: CollectorIdentityEvidence,
    *,
    key_resolver: Callable[[str], Any],
    trust_anchor_ref: str | None = None,
    attempt: CollectorAttempt | None = None,
) -> bool:
    if key_resolver is None:
        return False
    if trust_anchor_ref is not None and identity_evidence.trust_anchor_ref != trust_anchor_ref:
        return False
    if identity_evidence.trust_anchor_ref != identity_evidence.ingestion_signature.trust_anchor_ref:
        return False
    if identity_evidence.ingestion_signature.signature_algorithm != "RS256":
        return False
    if identity_evidence.ingestion_signature.key_status_at_signing not in {"active", "verifyOnly"}:
        return False
    if identity_evidence.token_verification.status != "valid":
        return False
    if identity_evidence.ingestion_signature.signature_verification.status != "valid":
        return False
    if (
        identity_evidence.identity_evidence_id
        != identity_evidence.ingestion_derivation.identity_evidence_id
    ):
        return False
    if (
        identity_evidence.verified_claims.tenant_id
        != identity_evidence.ingestion_derivation.mcp_host_tenant_id
    ):
        return False
    if (
        identity_evidence.verified_claims.managed_identity_object_id
        != identity_evidence.ingestion_derivation.mcp_host_managed_identity_object_id
    ):
        return False
    if (
        identity_evidence.verified_claims.managed_identity_client_id
        != identity_evidence.ingestion_derivation.mcp_host_managed_identity_client_id
    ):
        return False
    if identity_evidence.verified_claims.subject not in {
        identity_evidence.verified_claims.managed_identity_object_id,
        identity_evidence.verified_claims.managed_identity_client_id,
    }:
        return False
    if (
        identity_evidence.ingestion_derivation.derived_collector_identity_ref
        != identity_evidence.identity_evidence_id
    ):
        return False
    if attempt is not None:
        binding = identity_evidence.ingestion_derivation.attempt_binding
        binding_payload = binding.model_dump(mode="python", by_alias=True, exclude_none=True)
        if canonicalize_json(binding_payload) != canonicalize_json(
            _attempt_binding_payload(attempt)
        ):
            return False
    payload = identity_evidence.ingestion_derivation.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    payload.pop("derivationDigest", None)
    canonical = canonicalize_json(payload)
    expected_digest = compute_artifact_digest(payload)
    if identity_evidence.ingestion_signature.signed_preimage_digest != expected_digest:
        return False
    if identity_evidence.ingestion_derivation.derivation_digest != expected_digest:
        return False
    key_id = identity_evidence.ingestion_signature.key_vault_key_id
    try:
        public_key = key_resolver(key_id)
    except Exception:
        return False
    if public_key is None:
        return False
    return verify_key_vault_signature(
        raw_signature=identity_evidence.ingestion_signature.signature,
        preimage=canonical,
        public_key=public_key,
        algorithm=identity_evidence.ingestion_signature.signature_algorithm,
    )


class CapabilityRequirement(AthenaBaseModel):
    capability_id: str = Field(
        ...,
        alias="capabilityId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    minimum_version: str = Field(
        ...,
        alias="minimumVersion",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_for: CapabilityRequiredFor = Field(
        ..., alias="requiredFor", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ProducerInfo(AthenaBaseModel):
    producer_id: str = Field(
        ..., alias="producerId", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    version: str = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})


class CompatibilityMetadata(AthenaBaseModel):
    artifact_kind: Literal[
        "workloadManifest",
        "resolvedProfile",
        "evidenceSnapshot",
        "contextualFinding",
        "generatedJsonSchema",
    ] = Field(
        ...,
        alias="artifactKind",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    schema_version: str = Field(
        ..., alias="schemaVersion", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    semantic_contract_version: str = Field(
        ...,
        alias="semanticContractVersion",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    policy_contract_version: str = Field(
        ..., alias="policyContractVersion", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    minimum_reader_version: str = Field(
        ..., alias="minimumReaderVersion", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    requires_capabilities: list[CapabilityRequirement] = Field(
        default_factory=list,
        alias="requiresCapabilities",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    produced_by: ProducerInfo = Field(
        ..., alias="producedBy", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    extension_policy: Literal["rejectUnknownDecisionFields"] = Field(
        ..., alias="extensionPolicy", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    artifact_digest: str = Field(
        ..., alias="artifactDigest", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    semantic_digest: str = Field(
        ..., alias="semanticDigest", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )



class SubscriptionScope(AthenaBaseModel):
    scope_type: Literal["subscription"] = Field(
        ..., alias="scopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tenant_id: str = Field(
        ...,
        alias="tenantId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    subscription_id: str = Field(
        ...,
        alias="subscriptionId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @field_validator("tenant_id", "subscription_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        if not _is_valid_guid(value):
            raise AthenaValidationError(f"invalid Azure GUID scope value: {value!r}")
        return value


class ResourceGroupScope(AthenaBaseModel):
    scope_type: Literal["resourceGroup"] = Field(
        ..., alias="scopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tenant_id: str = Field(
        ...,
        alias="tenantId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    subscription_id: str = Field(
        ...,
        alias="subscriptionId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    resource_group_name: str = Field(
        ...,
        alias="resourceGroupName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @field_validator("tenant_id", "subscription_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        if not _is_valid_guid(value):
            raise AthenaValidationError(f"invalid Azure GUID scope value: {value!r}")
        return value

    @field_validator("resource_group_name")
    @classmethod
    def validate_resource_group_name(cls, value: str) -> str:
        if any(token in value for token in ("*", "?")):
            raise AthenaValidationError("resource group names may not contain wildcards")
        return value


class ResourceIdScope(AthenaBaseModel):
    scope_type: Literal["resourceId"] = Field(
        ..., alias="scopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @field_validator("resource_id")
    @classmethod
    def validate_resource_id(cls, value: str) -> str:
        _parse_azure_resource_id(value)
        return value


class LogAnalyticsWorkspaceScope(AthenaBaseModel):
    scope_type: Literal["logAnalyticsWorkspace"] = Field(
        ..., alias="scopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tenant_id: str = Field(
        ...,
        alias="tenantId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    subscription_id: str = Field(
        ...,
        alias="subscriptionId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    resource_group_name: str = Field(
        ...,
        alias="resourceGroupName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    workspace_name: str = Field(
        ...,
        alias="workspaceName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @field_validator("tenant_id", "subscription_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        if not _is_valid_guid(value):
            raise AthenaValidationError(f"invalid Azure GUID scope value: {value!r}")
        return value

    @field_validator("resource_group_name", "workspace_name")
    @classmethod
    def validate_names(cls, value: str) -> str:
        if any(token in value for token in ("*", "?")):
            raise AthenaValidationError("scope names may not contain wildcards")
        return value


class ServiceHealthRegionScope(AthenaBaseModel):
    scope_type: Literal["serviceHealthRegion"] = Field(
        ..., alias="scopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    cloud: AzureCloud = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    region: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})

    @field_validator("region")
    @classmethod
    def validate_region(cls, value: str) -> str:
        if not _is_valid_azure_region(value):
            raise AthenaValidationError(
                "serviceHealthRegion.region must be a concrete Azure region identifier"
            )
        return value


type EvidenceScope = Annotated[
    SubscriptionScope
    | ResourceGroupScope
    | ResourceIdScope
    | LogAnalyticsWorkspaceScope
    | ServiceHealthRegionScope,
    Field(discriminator="scope_type"),
]


class GovernanceManifestScope(AthenaBaseModel):
    governance_scope_type: Literal["manifest"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceProfileScope(AthenaBaseModel):
    governance_scope_type: Literal["profile"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_id: str = Field(
        ...,
        alias="profileId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceClauseScope(AthenaBaseModel):
    governance_scope_type: Literal["clause"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    clause_path: str = Field(
        ...,
        alias="clausePath",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceRoleScope(AthenaBaseModel):
    governance_scope_type: Literal["role"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    role_ref: str = Field(
        ..., alias="roleRef", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class GovernanceResourceBindingScope(AthenaBaseModel):
    governance_scope_type: Literal["resourceBinding"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    role_ref: str = Field(
        ..., alias="roleRef", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceRelationshipScope(AthenaBaseModel):
    governance_scope_type: Literal["relationship"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    relationship_ref: str = Field(
        ...,
        alias="relationshipRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceControlScope(AthenaBaseModel):
    governance_scope_type: Literal["control"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    control_ref: str = Field(
        ...,
        alias="controlRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceObjectiveScope(AthenaBaseModel):
    governance_scope_type: Literal["objective"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    objective_ref: str = Field(
        ...,
        alias="objectiveRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


type GovernanceScope = Annotated[
    GovernanceManifestScope
    | GovernanceProfileScope
    | GovernanceClauseScope
    | GovernanceRoleScope
    | GovernanceResourceBindingScope
    | GovernanceRelationshipScope
    | GovernanceControlScope
    | GovernanceObjectiveScope,
    Field(discriminator="governance_scope_type"),
]


class ProfileContinuitySettings(AthenaBaseModel):
    zone_loss_continuity_required: bool = Field(
        ...,
        alias="zoneLossContinuityRequired",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ProfileSettings(AthenaBaseModel):
    continuity: ProfileContinuitySettings = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class WorkloadIdentity(AthenaBaseModel):
    display_name: str = Field(
        ...,
        alias="displayName",
        min_length=1,
        max_length=200,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    environment: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    business_criticality: str | None = Field(
        default=None,
        alias="businessCriticality",
        min_length=1,
        max_length=64,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    data_sensitivity: str | None = Field(
        default=None,
        alias="dataSensitivity",
        min_length=1,
        max_length=64,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    allowed_evidence_scopes: list[EvidenceScope] = Field(
        default_factory=list,
        alias="allowedEvidenceScopes",
        max_length=50,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class OperationalOwnership(AthenaBaseModel):
    business_owner: str | None = Field(
        default=None,
        alias="businessOwner",
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    technical_owner: str | None = Field(
        default=None,
        alias="technicalOwner",
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    operations_owner: str | None = Field(
        default=None,
        alias="operationsOwner",
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    security_owner: str | None = Field(
        default=None,
        alias="securityOwner",
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    approver: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ManifestAudit(AthenaBaseModel):
    published_by: str = Field(
        ...,
        alias="publishedBy",
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    reviewed_by: str | None = Field(
        default=None,
        alias="reviewedBy",
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    published_at: datetime | None = Field(
        default=None,
        alias="publishedAt",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    change_reason: str | None = Field(
        default=None,
        alias="changeReason",
        min_length=1,
        max_length=512,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ProfileOverride(AthenaBaseModel):
    profile_id: str = Field(
        ...,
        alias="profileId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    extends: str | None = Field(
        default=None, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    settings: ProfileSettings = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    disabled_refs: list[str] = Field(
        default_factory=list,
        alias="disabledRefs",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    rationale: str | None = Field(
        default=None, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str | None = Field(
        default=None, alias="ownerRef", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )

    @model_validator(mode="after")
    def validate_disabled_refs(self) -> ProfileOverride:
        if self.disabled_refs and (not self.owner_ref or not self.rationale):
            raise AthenaValidationError("disabledRefs requires both ownerRef and rationale")
        return self


class ManifestRelationshipSet(AthenaBaseModel):
    declared: list[DeclaredRelationship] = Field(
        default_factory=list,
        min_length=0,
        max_length=500,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    exceptions: list[ExceptionRelationship] = Field(
        default_factory=list,
        min_length=0,
        max_length=500,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ProfileDefinition(AthenaBaseModel):
    profile_id: str = Field(
        ...,
        alias="profileId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_type: ProfileType = Field(
        ..., alias="profileType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    extends: str | None = Field(
        default=None, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    settings: ProfileSettings = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    overrides: list[ProfileOverride] = Field(
        default_factory=list, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )

    def resolve(self, registry: dict[str, ProfileDefinition]) -> ProfileDefinition:
        visited: set[str] = set()
        resolved_settings = ProfileSettings.model_validate(
            {"continuity": {"zoneLossContinuityRequired": False}}
        )
        inherited_chain: list[ProfileDefinition] = []
        current_id: str | None = self.profile_id

        while current_id is not None:
            if current_id in visited:
                raise AthenaValidationError(f"profile inheritance cycle detected: {current_id!r}")
            visited.add(current_id)
            current = registry.get(current_id)
            if current is None:
                raise AthenaValidationError(f"profile reference not found: {current_id!r}")
            inherited_chain.append(current)
            current_id = current.extends

        for profile in reversed(inherited_chain):
            resolved_settings = _merge_profile_settings(resolved_settings, profile.settings)

        resolved_override_settings: dict[str, Any] = {
            "continuity": {
                "zoneLossContinuityRequired": (
                    resolved_settings.continuity.zone_loss_continuity_required
                )
            }
        }
        return ProfileDefinition(
            profileId=self.profile_id,
            profileType=self.profile_type,
            extends=self.extends,
            settings=ProfileSettings.model_validate(resolved_override_settings),
            overrides=self.overrides,
        )

    @classmethod
    def validate_profile_hierarchy(cls, profiles: dict[str, ProfileDefinition]) -> None:
        seen: set[str] = set()
        stack: set[str] = set()

        def walk(profile_id: str) -> None:
            if profile_id in stack:
                raise AthenaValidationError(f"profile inheritance cycle detected: {profile_id!r}")
            if profile_id in seen:
                return
            seen.add(profile_id)
            stack.add(profile_id)
            profile = profiles.get(profile_id)
            if profile is None:
                raise AthenaValidationError(f"profile reference not found: {profile_id!r}")
            if profile.extends is not None:
                walk(profile.extends)
            stack.remove(profile_id)

        for profile_id in profiles:
            walk(profile_id)


def _deep_merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _merge_profile_settings(base: ProfileSettings, override: ProfileSettings) -> ProfileSettings:
    merged = _deep_merge_dict(
        base.model_dump(mode="json", by_alias=True),
        override.model_dump(mode="json", by_alias=True),
    )
    return ProfileSettings.model_validate(merged)


class RoleCardinalityExactlyOne(AthenaBaseModel):
    cardinality_kind: Literal["exactlyOne"] = Field(
        ..., alias="cardinalityKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RoleCardinalityOneOrMore(AthenaBaseModel):
    cardinality_kind: Literal["oneOrMore"] = Field(
        ..., alias="cardinalityKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RoleCardinalityZeroOrMore(AthenaBaseModel):
    cardinality_kind: Literal["zeroOrMore"] = Field(
        ..., alias="cardinalityKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RoleCardinalityBoundedRange(AthenaBaseModel):
    cardinality_kind: Literal["boundedRange"] = Field(
        ..., alias="cardinalityKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    minimum: int = Field(
        ..., ge=0, le=10000, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    maximum: int = Field(
        ..., ge=0, le=10000, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )

    @model_validator(mode="after")
    def validate_bounds(self) -> RoleCardinalityBoundedRange:
        if self.maximum < self.minimum:
            raise AthenaValidationError("bounded range maximum must be >= minimum")
        return self


type RoleCardinality = Annotated[
    RoleCardinalityExactlyOne
    | RoleCardinalityOneOrMore
    | RoleCardinalityZeroOrMore
    | RoleCardinalityBoundedRange,
    Field(discriminator="cardinality_kind"),
]


class ResourceIdListSelector(AthenaBaseModel):
    selector_type: Literal["resourceIdList"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_ids: list[str] = Field(
        ...,
        alias="resourceIds",
        min_length=1,
        max_length=200,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class TagPredicateSelector(AthenaBaseModel):
    selector_type: Literal["tagPredicate"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    key: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    value: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    predicates: list[str] | None = Field(
        default=None,
        min_length=1,
        max_length=20,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_predicate_shape(self) -> TagPredicateSelector:
        has_key_value = self.key is not None or self.value is not None
        if self.predicates is None and not has_key_value:
            raise AthenaValidationError("tagPredicate requires either key/value or predicates")
        if self.predicates is not None and has_key_value:
            raise AthenaValidationError("tagPredicate cannot mix key/value and predicates")
        if self.predicates is not None and not self.predicates:
            raise AthenaValidationError("predicates cannot be empty")
        return self


class NamePatternSelector(AthenaBaseModel):
    selector_type: Literal["namePattern"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    pattern: str | None = Field(
        default=None,
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    prefix: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    suffix: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_name_pattern(self) -> NamePatternSelector:
        if self.pattern is None and self.prefix is None and self.suffix is None:
            raise AthenaValidationError("namePattern requires pattern, prefix, or suffix")
        return self


class ResourceTypeScopeSelector(AthenaBaseModel):
    selector_type: Literal["resourceTypeScope"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_type: str = Field(
        ...,
        alias="resourceType",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    location: str | None = Field(
        default=None, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_group_name: str | None = Field(
        default=None,
        alias="resourceGroupName",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class CompositeAllSelector(AthenaBaseModel):
    selector_type: Literal["compositeAll"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    children: list[Selector] = Field(
        ..., min_length=1, max_length=10, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class CompositeAnySelector(AthenaBaseModel):
    selector_type: Literal["compositeAny"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    children: list[Selector] = Field(
        ..., min_length=1, max_length=10, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


type Selector = Annotated[
    ResourceIdListSelector
    | TagPredicateSelector
    | NamePatternSelector
    | ResourceTypeScopeSelector
    | CompositeAllSelector
    | CompositeAnySelector,
    Field(discriminator="selector_type"),
]


class OwnershipReference(AthenaBaseModel):
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    owner_role: OwnerRole = Field(
        ..., alias="ownerRole", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class WorkloadRole(AthenaBaseModel):
    role_id: str = Field(
        ..., alias="roleId", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    kind: RoleKind = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    display_name: str = Field(
        ...,
        alias="displayName",
        min_length=1,
        max_length=120,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    cardinality: RoleCardinality = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    selectors: list[Selector] = Field(
        default_factory=list,
        min_length=1,
        max_length=20,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_applicability: list[str] = Field(
        default_factory=list,
        alias="profileApplicability",
        min_length=1,
        max_length=25,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    approval_state: Literal["draft", "approved", "deprecated"] = Field(
        ..., alias="approvalState", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RoleRef(AthenaBaseModel):
    ref_kind: Literal["roleRef"] = Field(
        ..., alias="refKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    role_id: str = Field(
        ..., alias="roleId", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ResourceRef(AthenaBaseModel):
    ref_kind: Literal["resourceRef"] = Field(
        ..., alias="refKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ExternalRef(AthenaBaseModel):
    ref_kind: Literal["externalRef"] = Field(
        ..., alias="refKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    external_id: str = Field(
        ...,
        alias="externalId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


type RelationshipEndpoint = Annotated[
    RoleRef | ResourceRef | ExternalRef, Field(discriminator="ref_kind")
]


class DeclaredRelationship(AthenaBaseModel):
    relationship_class: Literal["declared"] = Field(
        ..., alias="relationshipClass", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    relationship_id: str = Field(
        ...,
        alias="relationshipId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    kind: RelationshipKind = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    source: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    target: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    profiles: list[str] = Field(
        ..., min_length=1, max_length=25, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    source_clause: str = Field(
        ...,
        alias="sourceClause",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ObservedRelationship(AthenaBaseModel):
    relationship_class: Literal["observed"] = Field(
        ..., alias="relationshipClass", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    relationship_id: str = Field(
        ...,
        alias="relationshipId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    kind: RelationshipKind = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    source: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    target: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    evidence_item_ref: str = Field(
        ...,
        alias="evidenceItemRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    observed_at: datetime = Field(
        ..., alias="observedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class InferredRelationship(AthenaBaseModel):
    relationship_class: Literal["inferred"] = Field(
        ..., alias="relationshipClass", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    relationship_id: str = Field(
        ...,
        alias="relationshipId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    kind: RelationshipKind = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    source: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    target: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    input_evidence_refs: list[str] = Field(
        ...,
        alias="inputEvidenceRefs",
        min_length=1,
        max_length=20,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    algorithm_id: str = Field(
        ...,
        alias="algorithmId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ExceptionRelationship(AthenaBaseModel):
    relationship_class: Literal["exception"] = Field(
        ..., alias="relationshipClass", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    exception_id: str = Field(
        ...,
        alias="exceptionId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    applies_to_relationship_ref: str = Field(
        ...,
        alias="appliesToRelationshipRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    risk_acceptance_ref: str = Field(
        ...,
        alias="riskAcceptanceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    governance_scope: GovernanceScope = Field(
        ..., alias="governanceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    rationale: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expires_at: datetime = Field(
        ..., alias="expiresAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


type Relationship = Annotated[
    DeclaredRelationship | ObservedRelationship | InferredRelationship | ExceptionRelationship,
    Field(discriminator="relationship_class"),
]


class CardProof(AthenaBaseModel):
    proof_kind: Literal["cardinalityProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    role_ref: str = Field(
        ..., alias="roleRef", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expected: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_evidence_refs: list[str] = Field(
        ...,
        alias="resourceEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ZoneColocationProof(AthenaBaseModel):
    proof_kind: Literal["zoneColocationProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    subject_role_ref: str = Field(
        ...,
        alias="subjectRoleRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    anchor_role_ref: str = Field(
        ...,
        alias="anchorRoleRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    zone_evidence_refs: list[str] = Field(
        ...,
        alias="zoneEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ZoneDistributionProof(AthenaBaseModel):
    proof_kind: Literal["zoneDistributionProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    role_ref: str = Field(
        ..., alias="roleRef", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    minimum_distinct_zones: int = Field(
        ...,
        alias="minimumDistinctZones",
        ge=1,
        le=3,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    zone_evidence_refs: list[str] = Field(
        ...,
        alias="zoneEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RelationshipPresenceProof(AthenaBaseModel):
    proof_kind: Literal["relationshipPresenceProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    declared_relationship_ref: str = Field(
        ...,
        alias="declaredRelationshipRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    observed_relationship_evidence_refs: list[str] = Field(
        ...,
        alias="observedRelationshipEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class EvidenceFreshnessProof(AthenaBaseModel):
    proof_kind: Literal["evidenceFreshnessProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    maximum_age: int = Field(
        ...,
        alias="maximumAge",
        ge=1,
        le=30 * 24 * 60 * 60,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    evidence_refs: list[str] = Field(
        ...,
        alias="evidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ControlHealthProof(AthenaBaseModel):
    proof_kind: Literal["controlHealthProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    control_ref: str = Field(
        ...,
        alias="controlRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_health: str = Field(
        ...,
        alias="requiredHealth",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    control_evidence_refs: list[str] = Field(
        ...,
        alias="controlEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ObjectiveThresholdProof(AthenaBaseModel):
    proof_kind: Literal["objectiveThresholdProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    objective_ref: str = Field(
        ...,
        alias="objectiveRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    metric_evidence_refs: list[str] = Field(
        ...,
        alias="metricEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    comparison: Literal["lt", "lte", "gt", "gte", "eq"] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


type ProofRequirement = Annotated[
    CardProof
    | ZoneColocationProof
    | ZoneDistributionProof
    | RelationshipPresenceProof
    | EvidenceFreshnessProof
    | ControlHealthProof
    | ObjectiveThresholdProof,
    Field(discriminator="proof_kind"),
]


class Constraint(AthenaBaseModel):
    constraint_id: str = Field(
        ...,
        alias="constraintId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    type: ConstraintType = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    governance_scope: GovernanceScope = Field(
        ..., alias="governanceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    applies_to_role_refs: list[str] = Field(
        ...,
        alias="appliesToRoleRefs",
        min_length=1,
        max_length=50,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profiles: list[str] = Field(
        ..., min_length=1, max_length=25, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    severity: Literal["critical", "high", "medium", "low", "informational"] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    proof_requirement: ProofRequirement = Field(
        ..., alias="proofRequirement", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    source_clause: str = Field(
        ...,
        alias="sourceClause",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_mode: Literal["violation", "unknown", "conflicting"] = Field(
        ..., alias="failureMode", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RiskAcceptance(AthenaBaseModel):
    risk_acceptance_id: str = Field(
        ...,
        alias="riskAcceptanceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    governance_scope: GovernanceScope = Field(
        ..., alias="governanceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    rationale: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    accepted_at: datetime = Field(
        ..., alias="acceptedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expires_at: datetime = Field(
        ..., alias="expiresAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    active: bool = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    applies_to_clause_path: str | None = Field(
        default=None,
        alias="appliesToClausePath",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_risk_acceptance(self) -> RiskAcceptance:
        if self.accepted_at > self.expires_at:
            raise AthenaValidationError("acceptedAt must be earlier than or equal to expiresAt")
        if self.active and self.expires_at <= datetime.now(tz=UTC):
            raise AthenaValidationError("active risk acceptance cannot already be expired")
        return self


class Control(AthenaBaseModel):
    control_id: str = Field(
        ...,
        alias="controlId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    name: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    governance_scope: GovernanceScope = Field(
        ..., alias="governanceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    status: Literal["healthy", "degraded", "failed", "unknown"] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    risk_acceptance_ref: str | None = Field(
        default=None,
        alias="riskAcceptanceRef",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class Objective(AthenaBaseModel):
    objective_id: str = Field(
        ...,
        alias="objectiveId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    objective_type: Literal[
        "availabilitySlo",
        "latencySlo",
        "throughputSlo",
        "rto",
        "rpo",
        "serviceHours",
        "capacityHeadroom",
        "recoveryPriority",
    ] = Field(..., alias="objectiveType", json_schema_extra={"x-athena-semanticClass": "semantic"})
    target_value: float = Field(
        ..., alias="targetValue", ge=0, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_applicability: list[str] = Field(
        ...,
        alias="profileApplicability",
        min_length=1,
        max_length=25,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class WorkloadManifest(AthenaBaseModel):
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    manifest_version: str = Field(
        ...,
        alias="manifestVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    workload: WorkloadIdentity = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    profiles: dict[str, ProfileDefinition] = Field(
        ..., min_length=1, max_length=25, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    roles: list[WorkloadRole] = Field(
        ..., min_length=1, max_length=200, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    relationships: ManifestRelationshipSet = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    constraints: list[Constraint] = Field(
        default_factory=list,
        max_length=500,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    controls: list[Control] = Field(
        default_factory=list,
        max_length=500,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    risk_acceptances: list[RiskAcceptance] = Field(
        default_factory=list,
        alias="riskAcceptances",
        max_length=200,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    objectives: list[Objective] = Field(
        default_factory=list,
        max_length=200,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    ownership: OperationalOwnership = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    compatibility: CompatibilityMetadata = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    audit: ManifestAudit = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})

    @field_validator("profiles")
    @classmethod
    def validate_profile_ids(
        cls, profiles: dict[str, ProfileDefinition]
    ) -> dict[str, ProfileDefinition]:
        if not profiles:
            raise AthenaValidationError("manifest requires at least one profile")
        normalized: set[str] = set()
        for profile_key, profile_def in profiles.items():
            key_normalized = normalize_nfc_text(profile_key)
            if key_normalized in normalized:
                raise AthenaValidationError(f"duplicate profile id: {profile_key!r}")
            normalized.add(key_normalized)
            if profile_def.profile_id != profile_key:
                raise AthenaValidationError("profiles must use stable id keys matching profileId")
        return profiles

    @model_validator(mode="after")
    def validate_manifest(self) -> WorkloadManifest:
        for role in self.roles:
            if not role.selectors and role.approval_state == "approved":
                raise AthenaValidationError("approved role must declare selectors")
        if (
            "production" not in self.profiles
            or "development" not in self.profiles
            or "training" not in self.profiles
        ):
            raise AthenaValidationError(
                "prototype manifest requires production, development, and training profiles"
            )
        ProfileDefinition.validate_profile_hierarchy(self.profiles)
        return self

    def resolved_profiles(self) -> dict[str, ProfileDefinition]:
        resolved: dict[str, ProfileDefinition] = {}
        for profile_id, profile in self.profiles.items():
            resolved[profile_id] = profile.resolve(self.profiles)
        return resolved


class EvidenceItemRef(AthenaBaseModel):
    ref_type: Literal["evidenceItem"] = Field(
        ..., alias="refType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    snapshot_id: str = Field(
        ...,
        alias="snapshotId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    snapshot_artifact_digest: str = Field(
        ...,
        alias="snapshotArtifactDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    snapshot_semantic_digest: str = Field(
        ...,
        alias="snapshotSemanticDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_id: str = Field(
        ...,
        alias="collectorAttemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_tool_name: str = Field(
        ...,
        alias="collectorToolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_tool_version: str = Field(
        ...,
        alias="collectorToolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_at: datetime = Field(
        ..., alias="collectorAttemptAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    source_response_digest: str = Field(
        ...,
        alias="sourceResponseDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    source_response_pointer: str = Field(
        ...,
        alias="sourceResponsePointer",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_evidence_item_ref(self) -> EvidenceItemRef:
        if not _is_sha256_digest(self.item_digest):
            raise AthenaValidationError("EvidenceItemRef.itemDigest must be a sha256 digest")
        if not _is_sha256_digest(self.snapshot_artifact_digest):
            raise AthenaValidationError(
                "EvidenceItemRef.snapshotArtifactDigest must be a sha256 digest"
            )
        if not _is_sha256_digest(self.snapshot_semantic_digest):
            raise AthenaValidationError(
                "EvidenceItemRef.snapshotSemanticDigest must be a sha256 digest"
            )
        if not _is_sha256_digest(self.source_response_digest):
            raise AthenaValidationError(
                "EvidenceItemRef.sourceResponseDigest must be a sha256 digest"
            )
        if not _is_valid_json_pointer(self.source_response_pointer):
            raise AthenaValidationError(
                "EvidenceItemRef.sourceResponsePointer is not a valid JSON Pointer"
            )
        return self


class EvidenceGapRef(AthenaBaseModel):
    ref_type: Literal["evidenceGap"] = Field(
        ..., alias="refType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    snapshot_id: str = Field(
        ...,
        alias="snapshotId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    snapshot_artifact_digest: str = Field(
        ...,
        alias="snapshotArtifactDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    snapshot_semantic_digest: str = Field(
        ...,
        alias="snapshotSemanticDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    gap_id: str = Field(
        ..., alias="gapId", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    gap_record_digest: str = Field(
        ...,
        alias="gapRecordDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    evidence_scope: EvidenceScope = Field(
        ..., alias="evidenceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expected_record_type: ExpectedEvidenceRecordType = Field(
        ..., alias="expectedRecordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_attempt_id: str = Field(
        ...,
        alias="collectorAttemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_tool_name: str = Field(
        ...,
        alias="collectorToolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_tool_version: str = Field(
        ...,
        alias="collectorToolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_at: datetime = Field(
        ..., alias="collectorAttemptAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    gap_reason: Literal[
        "missing",
        "stale",
        "unauthorized",
        "filtered",
        "malformed",
        "collectorUnavailable",
        "scopeMismatch",
        "responseOversized",
        "unsupportedTool",
    ] = Field(
        ...,
        alias="gapReason",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_payload_digest: str | None = Field(
        default=None,
        alias="failurePayloadDigest",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_payload_pointer: str | None = Field(
        default=None,
        alias="failurePayloadPointer",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_evidence_gap_ref(self) -> EvidenceGapRef:
        if not _is_sha256_digest(self.snapshot_artifact_digest):
            raise AthenaValidationError(
                "EvidenceGapRef.snapshotArtifactDigest must be a sha256 digest"
            )
        if not _is_sha256_digest(self.snapshot_semantic_digest):
            raise AthenaValidationError(
                "EvidenceGapRef.snapshotSemanticDigest must be a sha256 digest"
            )
        if not _is_sha256_digest(self.gap_record_digest):
            raise AthenaValidationError("EvidenceGapRef.gapRecordDigest must be a sha256 digest")
        if self.failure_payload_digest is not None and not _is_sha256_digest(
            self.failure_payload_digest
        ):
            raise AthenaValidationError(
                "EvidenceGapRef.failurePayloadDigest must be a sha256 digest when present"
            )
        if self.failure_payload_pointer is not None and not _is_valid_json_pointer(
            self.failure_payload_pointer
        ):
            raise AthenaValidationError(
                "EvidenceGapRef.failurePayloadPointer is not a valid JSON Pointer"
            )
        if (self.failure_payload_digest is None) != (self.failure_payload_pointer is None):
            raise AthenaValidationError(
                "EvidenceGapRef failure payload digest and pointer must appear together"
            )
        return self


type EvidenceReference = Annotated[
    EvidenceItemRef | EvidenceGapRef, Field(discriminator="ref_type")
]


class ContextRef(AthenaBaseModel):
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    manifest_version: str = Field(
        ...,
        alias="manifestVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_id: str = Field(
        ...,
        alias="profileId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    resolved_profile_digest: str = Field(
        ...,
        alias="resolvedProfileDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    clause_path: str = Field(
        ...,
        alias="clausePath",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class JwtHeader(AthenaBaseModel):
    alg: Literal["RS256"] = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    kid: str = Field(
        ...,
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]{8,128}$",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    typ: Literal["JWT"] = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})


class VerifiedEntraClaims(AthenaBaseModel):
    issuer: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    audience: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tenant_id: str = Field(
        ...,
        alias="tenantId",
        min_length=1,
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    managed_identity_object_id: str = Field(
        ...,
        alias="managedIdentityObjectId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    managed_identity_client_id: str = Field(
        ...,
        alias="managedIdentityClientId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    subject: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    jti: str = Field(
        ..., min_length=1, max_length=128, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    issued_at: datetime = Field(
        ..., alias="issuedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expires_at: datetime = Field(
        ..., alias="expiresAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )

    @model_validator(mode="after")
    def validate_claims(self) -> VerifiedEntraClaims:
        if (
            self.tenant_id not in self.issuer
            and self.tenant_id not in self.audience
            and not self.issuer.startswith(
                ("https://login.microsoftonline.com/", "https://sts.windows.net/")
            )
        ):
            raise AthenaValidationError("issuer must be an Entra issuer URL")
        if (
            self.issuer.startswith("https://login.microsoftonline.com/")
            and self.tenant_id not in self.issuer
        ):
            raise AthenaValidationError("issuer must contain the tenantId for the MCP host token")
        if self.expires_at <= self.issued_at:
            raise AthenaValidationError("Entra token expiry must be later than issuedAt")
        if self.subject not in {self.managed_identity_object_id, self.managed_identity_client_id}:
            raise AthenaValidationError(
                "subject must match the managed identity object or client id"
            )
        return self


class TokenVerification(AthenaBaseModel):
    status: Literal[
        "valid",
        "expired",
        "notYetValid",
        "badSignature",
        "unknownKey",
        "untrustedIssuer",
        "audienceMismatch",
        "claimMismatch",
        "trustAnchorUnavailable",
    ] = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    verified_at: datetime = Field(
        ..., alias="verifiedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    key_id: str = Field(
        ...,
        alias="keyId",
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]{8,128}$",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    token_verification_digest: str = Field(
        ...,
        alias="tokenVerificationDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_digest(self) -> TokenVerification:
        if not _is_sha256_digest(self.token_verification_digest):
            raise AthenaValidationError(
                "TokenVerification.tokenVerificationDigest must be a sha256 digest"
            )
        if self.token_verification_digest != compute_token_verification_digest(self):
            raise AthenaValidationError(
                "TokenVerification.tokenVerificationDigest mismatched its canonical preimage"
            )
        return self


class AttemptBinding(AthenaBaseModel):
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_type: AttemptType = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    response_digest: str | None = Field(
        default=None,
        alias="responseDigest",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_digest: str | None = Field(
        default=None,
        alias="failureDigest",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    response_received_at: datetime | None = Field(
        default=None,
        alias="responseReceivedAt",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    deadline_at: datetime | None = Field(
        default=None, alias="deadlineAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    timed_out_at: datetime | None = Field(
        default=None, alias="timedOutAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    observed_at: datetime | None = Field(
        default=None, alias="observedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )

    @model_validator(mode="after")
    def validate_attempt_binding(self) -> AttemptBinding:
        if not _is_sha256_digest(self.attempt_digest):
            raise AthenaValidationError("attemptBinding.attemptDigest must be a sha256 digest")
        if not _is_sha256_digest(self.request_digest):
            raise AthenaValidationError("attemptBinding.requestDigest must be a sha256 digest")
        if self.response_digest is not None and not _is_sha256_digest(self.response_digest):
            raise AthenaValidationError("responseDigest must be a sha256 digest")
        if self.failure_digest is not None and not _is_sha256_digest(self.failure_digest):
            raise AthenaValidationError("failureDigest must be a sha256 digest")
        if self.attempt_type == "successResponse":
            if self.response_digest is None or self.failure_digest is not None:
                raise AthenaValidationError(
                    "successResponse attempts require responseDigest and no failureDigest"
                )
            if self.response_received_at is None:
                raise AthenaValidationError("successResponse attempts require responseReceivedAt")
            if self.response_received_at < self.attempt_started_at:
                raise AthenaValidationError("responseReceivedAt must not precede attemptStartedAt")
            if any(
                value is not None
                for value in (self.deadline_at, self.timed_out_at, self.observed_at)
            ):
                raise AthenaValidationError(
                    "successResponse attempt binding contains fields from another variant"
                )
        elif self.attempt_type == "failedResponse":
            if self.failure_digest is None or self.response_received_at is None:
                raise AthenaValidationError(
                    "failedResponse attempts require failureDigest and responseReceivedAt"
                )
            if self.response_digest is not None:
                raise AthenaValidationError(
                    "failedResponse attempts must not include responseDigest"
                )
            if self.response_received_at < self.attempt_started_at:
                raise AthenaValidationError("responseReceivedAt must not precede attemptStartedAt")
            if any(
                value is not None
                for value in (self.deadline_at, self.timed_out_at, self.observed_at)
            ):
                raise AthenaValidationError(
                    "failedResponse attempt binding contains fields from another variant"
                )
        elif self.attempt_type == "timeoutNoResponse":
            if self.deadline_at is None or self.timed_out_at is None:
                raise AthenaValidationError(
                    "timeoutNoResponse attempts require deadlineAt and timedOutAt"
                )
            if self.response_digest is not None or self.failure_digest is not None:
                raise AthenaValidationError(
                    "timeoutNoResponse attempts must omit responseDigest and failureDigest"
                )
            if self.deadline_at < self.attempt_started_at:
                raise AthenaValidationError("deadlineAt must not precede attemptStartedAt")
            if self.timed_out_at <= self.deadline_at:
                raise AthenaValidationError("timedOutAt must be after deadlineAt")
            if self.response_received_at is not None or self.observed_at is not None:
                raise AthenaValidationError(
                    "timeoutNoResponse attempt binding contains fields from another variant"
                )
        elif self.attempt_type in {"authorizationFailure", "toolUnavailable"}:
            if self.observed_at is None:
                raise AthenaValidationError(f"{self.attempt_type} attempts require observedAt")
            if self.response_digest is not None or self.failure_digest is not None:
                raise AthenaValidationError(
                    f"{self.attempt_type} attempts must omit responseDigest and failureDigest"
                )
            if self.observed_at < self.attempt_started_at:
                raise AthenaValidationError("observedAt must not precede attemptStartedAt")
            if any(
                value is not None
                for value in (
                    self.response_received_at,
                    self.deadline_at,
                    self.timed_out_at,
                )
            ):
                raise AthenaValidationError(
                    f"{self.attempt_type} attempt binding contains fields from another variant"
                )
        return self


class IngestionDerivation(AthenaBaseModel):
    derivation_preimage_type: Literal["athena.mcpCollectorAttemptDerivation"] = Field(
        ...,
        alias="derivationPreimageType",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    derivation_preimage_version: str = Field(
        ...,
        alias="derivationPreimageVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    schema_version: str = Field(
        ...,
        alias="schemaVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    semantic_contract_version: str = Field(
        ...,
        alias="semanticContractVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    policy_contract_version: str = Field(
        ...,
        alias="policyContractVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    identity_evidence_id: str = Field(
        ...,
        alias="identityEvidenceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    token_hash: str = Field(
        ...,
        alias="tokenHash",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    token_verification_status: Literal[
        "valid",
        "expired",
        "notYetValid",
        "badSignature",
        "unknownKey",
        "untrustedIssuer",
        "audienceMismatch",
        "claimMismatch",
        "trustAnchorUnavailable",
    ] = Field(
        ...,
        alias="tokenVerificationStatus",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    token_verification_digest: str = Field(
        ...,
        alias="tokenVerificationDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    mcp_host_id: str = Field(
        ...,
        alias="mcpHostId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    mcp_host_tenant_id: str = Field(
        ...,
        alias="mcpHostTenantId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    mcp_host_managed_identity_object_id: str = Field(
        ...,
        alias="mcpHostManagedIdentityObjectId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    mcp_host_managed_identity_client_id: str = Field(
        ...,
        alias="mcpHostManagedIdentityClientId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    ingestion_service_id: str = Field(
        ...,
        alias="ingestionServiceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    ingestion_audience: str = Field(
        ...,
        alias="ingestionAudience",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_allowlist_digest: str = Field(
        ...,
        alias="toolAllowlistDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    derived_collector_identity_ref: str = Field(
        ...,
        alias="derivedCollectorIdentityRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_binding: AttemptBinding = Field(
        ..., alias="attemptBinding", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    derived_at: datetime = Field(
        ..., alias="derivedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    derivation_digest: str = Field(
        ...,
        alias="derivationDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_derivation(self) -> IngestionDerivation:
        if not _is_sha256_digest(self.token_hash):
            raise AthenaValidationError("IngestionDerivation.tokenHash must be a sha256 digest")
        if not _is_sha256_digest(self.token_verification_digest):
            raise AthenaValidationError(
                "IngestionDerivation.tokenVerificationDigest must be a sha256 digest"
            )
        if not _is_sha256_digest(self.tool_allowlist_digest):
            raise AthenaValidationError(
                "IngestionDerivation.toolAllowlistDigest must be a sha256 digest"
            )
        if not _is_sha256_digest(self.derivation_digest):
            raise AthenaValidationError(
                "IngestionDerivation.derivationDigest must be a sha256 digest"
            )
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("derivationDigest", None)
        expected = compute_artifact_digest(payload)
        if self.derivation_digest != expected:
            raise AthenaValidationError(
                "IngestionDerivation.derivationDigest mismatched the canonical preimage"
            )
        return self


class IngestionSignatureVerification(AthenaBaseModel):
    status: Literal[
        "valid",
        "badSignature",
        "unknownKey",
        "retiredKey",
        "trustAnchorUnavailable",
        "preimageMismatch",
        "expiredVerification",
    ] = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    verified_at: datetime = Field(
        ..., alias="verifiedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    key_version: str = Field(
        ...,
        alias="keyVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class IngestionSignature(AthenaBaseModel):
    signature_algorithm: Literal["RS256"] = Field(
        ..., alias="signatureAlgorithm", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    key_vault_key_id: str = Field(
        ...,
        alias="keyVaultKeyId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    key_version: str = Field(
        ...,
        alias="keyVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    signed_preimage_digest: str = Field(
        ...,
        alias="signedPreimageDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    signature: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    signed_at: datetime = Field(
        ..., alias="signedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    trust_anchor_ref: str = Field(
        ...,
        alias="trustAnchorRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    key_status_at_signing: Literal["active", "verifyOnly", "retired"] = Field(
        ..., alias="keyStatusAtSigning", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    signature_verification: IngestionSignatureVerification = Field(
        ..., alias="signatureVerification", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )

    @model_validator(mode="after")
    def validate_signature(self) -> IngestionSignature:
        if not _is_valid_key_vault_key_id(self.key_vault_key_id):
            raise AthenaValidationError(
                "keyVaultKeyId does not match the Azure Key Vault key pattern"
            )
        if not _is_sha256_digest(self.signed_preimage_digest):
            raise AthenaValidationError(
                "IngestionSignature.signedPreimageDigest must be a sha256 digest"
            )
        if self.signature in {"none", "", "alg:none"}:
            raise AthenaValidationError("Key Vault signature must not be empty or use alg none")
        return self


class CollectorIdentityEvidence(AthenaBaseModel):
    identity_evidence_id: str = Field(
        ...,
        alias="identityEvidenceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    identity_evidence_type: Literal["entraJwtTokenEvidence"] = Field(
        ..., alias="identityEvidenceType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    token_hash: str = Field(
        ...,
        alias="tokenHash",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    jwt_header: JwtHeader = Field(
        ..., alias="jwtHeader", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    trust_anchor_ref: str = Field(
        ...,
        alias="trustAnchorRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    verified_claims: VerifiedEntraClaims = Field(
        ..., alias="verifiedClaims", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    token_verification: TokenVerification = Field(
        ..., alias="tokenVerification", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    ingestion_derivation: IngestionDerivation = Field(
        ..., alias="ingestionDerivation", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    ingestion_signature: IngestionSignature = Field(
        ..., alias="ingestionSignature", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    identity_evidence_digest: str = Field(
        ...,
        alias="identityEvidenceDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_identity_evidence(self) -> CollectorIdentityEvidence:
        if self.jwt_header.alg != "RS256":
            raise AthenaValidationError("JWT alg must be RS256")
        if self.jwt_header.kid != self.token_verification.key_id:
            raise AthenaValidationError("jwtHeader.kid must match tokenVerification.keyId")
        if self.trust_anchor_ref != self.ingestion_signature.trust_anchor_ref:
            raise AthenaValidationError(
                "trustAnchorRef must match ingestionSignature.trustAnchorRef"
            )
        if self.token_hash != self.ingestion_derivation.token_hash:
            raise AthenaValidationError("tokenHash must match ingestionDerivation.tokenHash")
        if self.token_verification.status != self.ingestion_derivation.token_verification_status:
            raise AthenaValidationError(
                "tokenVerification.status must equal ingestionDerivation.tokenVerificationStatus"
            )
        if (
            self.token_verification.token_verification_digest
            != self.ingestion_derivation.token_verification_digest
        ):
            raise AthenaValidationError(
                "tokenVerificationDigest must equal ingestionDerivation.tokenVerificationDigest"
            )
        if self.verified_claims.audience != self.ingestion_derivation.ingestion_audience:
            raise AthenaValidationError(
                "verifiedClaims.audience must equal ingestionDerivation.ingestionAudience"
            )
        if not (
            self.verified_claims.issued_at
            <= self.token_verification.verified_at
            < self.verified_claims.expires_at
        ):
            raise AthenaValidationError(
                "tokenVerification.verifiedAt must fall inside the verified token lifetime"
            )
        if self.token_verification.status != "valid":
            raise AthenaValidationError(
                "tokenVerification.status must be valid for persisted collector identity evidence"
            )
        if self.ingestion_signature.signature_verification.status != "valid":
            raise AthenaValidationError(
                "ingestionSignature.signatureVerification.status must be valid"
            )
        if (
            self.ingestion_signature.signed_preimage_digest
            != self.ingestion_derivation.derivation_digest
        ):
            raise AthenaValidationError(
                "signedPreimageDigest must equal ingestionDerivation.derivationDigest"
            )
        expected_identity_digest = compute_artifact_digest(
            _without_root_fields(self, frozenset({"identityEvidenceDigest"}))
        )
        if self.identity_evidence_digest != expected_identity_digest:
            raise AthenaValidationError(
                "identityEvidenceDigest mismatched the canonical record without its own digest"
            )
        if self.verified_claims.tenant_id != self.ingestion_derivation.mcp_host_tenant_id:
            raise AthenaValidationError(
                "verifiedClaims.tenantId must equal ingestionDerivation.mcpHostTenantId"
            )
        if (
            self.verified_claims.managed_identity_object_id
            != self.ingestion_derivation.mcp_host_managed_identity_object_id
        ):
            raise AthenaValidationError(
                "verifiedClaims.managedIdentityObjectId must equal "
                "ingestionDerivation.mcpHostManagedIdentityObjectId"
            )
        if (
            self.verified_claims.managed_identity_client_id
            != self.ingestion_derivation.mcp_host_managed_identity_client_id
        ):
            raise AthenaValidationError(
                "verifiedClaims.managedIdentityClientId must equal "
                "ingestionDerivation.mcpHostManagedIdentityClientId"
            )
        if self.identity_evidence_id != self.ingestion_derivation.identity_evidence_id:
            raise AthenaValidationError(
                "identityEvidenceId must equal ingestionDerivation.identityEvidenceId"
            )
        return self

    def verify_signature(
        self,
        *,
        key_resolver: Callable[[str], Any],
        trust_anchor_ref: str | None = None,
        attempt: CollectorAttempt | None = None,
    ) -> bool:
        return verify_trusted_ingestion_signature(
            self,
            key_resolver=key_resolver,
            trust_anchor_ref=trust_anchor_ref,
            attempt=attempt,
        )


class _CollectorAttemptDigestBound(AthenaBaseModel):
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_attempt_digest(self) -> _CollectorAttemptDigestBound:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("attemptDigest", None)
        expected = compute_artifact_digest(payload)
        if self.attempt_digest != expected:
            raise AthenaValidationError(
                "attemptDigest mismatched the canonical attempt payload without its own digest"
            )
        return self


class SuccessResponseCollectorAttempt(_CollectorAttemptDigestBound):
    attempt_type: Literal["successResponse"] = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    response_digest: str = Field(
        ...,
        alias="responseDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    response_received_at: datetime = Field(
        ..., alias="responseReceivedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_success_attempt(self) -> SuccessResponseCollectorAttempt:
        if not _is_sha256_digest(self.request_digest):
            raise AthenaValidationError(
                "SuccessResponseCollectorAttempt.requestDigest must be a sha256 digest"
            )
        if not _is_sha256_digest(self.response_digest):
            raise AthenaValidationError(
                "SuccessResponseCollectorAttempt.responseDigest must be a sha256 digest"
            )
        if self.response_received_at < self.attempt_started_at:
            raise AthenaValidationError("responseReceivedAt must not precede attemptStartedAt")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("attemptDigest", None)
        expected = compute_artifact_digest(payload)
        if self.attempt_digest != expected:
            raise AthenaValidationError(
                "attemptDigest mismatch: successResponse collector attempt must be "
                "canonicalized without its own digest"
            )
        return self


class FailedResponseCollectorAttempt(AthenaBaseModel):
    attempt_type: Literal["failedResponse"] = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_code: str = Field(
        ...,
        alias="failureCode",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_status: str = Field(
        ...,
        alias="failureStatus",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_digest: str = Field(
        ...,
        alias="failureDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    response_received_at: datetime = Field(
        ..., alias="responseReceivedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_failed_attempt(self) -> FailedResponseCollectorAttempt:
        if not _is_sha256_digest(self.request_digest):
            raise AthenaValidationError(
                "FailedResponseCollectorAttempt.requestDigest must be a sha256 digest"
            )
        if not _is_sha256_digest(self.failure_digest):
            raise AthenaValidationError(
                "FailedResponseCollectorAttempt.failureDigest must be a sha256 digest"
            )
        if self.response_received_at < self.attempt_started_at:
            raise AthenaValidationError("responseReceivedAt must not precede attemptStartedAt")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("attemptDigest", None)
        expected = compute_artifact_digest(payload)
        if self.attempt_digest != expected:
            raise AthenaValidationError(
                "attemptDigest mismatch: failedResponse collector attempt must be "
                "canonicalized without its own digest"
            )
        return self


class TimeoutNoResponseCollectorAttempt(AthenaBaseModel):
    attempt_type: Literal["timeoutNoResponse"] = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    deadline_at: datetime = Field(
        ..., alias="deadlineAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    timed_out_at: datetime = Field(
        ..., alias="timedOutAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_timeout_attempt(self) -> TimeoutNoResponseCollectorAttempt:
        if not _is_sha256_digest(self.request_digest):
            raise AthenaValidationError(
                "TimeoutNoResponseCollectorAttempt.requestDigest must be a sha256 digest"
            )
        if self.deadline_at < self.attempt_started_at:
            raise AthenaValidationError("deadlineAt must not precede attemptStartedAt")
        if self.timed_out_at <= self.deadline_at:
            raise AthenaValidationError("timedOutAt must be after deadlineAt")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("attemptDigest", None)
        expected = compute_artifact_digest(payload)
        if self.attempt_digest != expected:
            raise AthenaValidationError(
                "attemptDigest mismatch: timeoutNoResponse collector attempt must be "
                "canonicalized without its own digest"
            )
        return self


class AuthorizationFailureCollectorAttempt(AthenaBaseModel):
    attempt_type: Literal["authorizationFailure"] = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    authorization_status: Literal[
        "denied",
        "expiredCredential",
        "scopeNotAllowed",
        "identityMismatch",
    ] = Field(
        ...,
        alias="authorizationStatus",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    observed_at: datetime = Field(
        ..., alias="observedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_authorization_error(self) -> AuthorizationFailureCollectorAttempt:
        if not _is_sha256_digest(self.request_digest):
            raise AthenaValidationError(
                "AuthorizationFailureCollectorAttempt.requestDigest must be a sha256 digest"
            )
        if self.observed_at < self.attempt_started_at:
            raise AthenaValidationError("observedAt must not precede attemptStartedAt")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("attemptDigest", None)
        expected = compute_artifact_digest(payload)
        if self.attempt_digest != expected:
            raise AthenaValidationError(
                "attemptDigest mismatch: authorizationFailure collector attempt must be "
                "canonicalized without its own digest"
            )
        return self


class ToolUnavailableCollectorAttempt(AthenaBaseModel):
    attempt_type: Literal["toolUnavailable"] = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    unavailable_reason: Literal[
        "notAllowlisted",
        "notHosted",
        "versionUnavailable",
        "networkUnavailable",
        "mcpUnavailable",
    ] = Field(
        ...,
        alias="unavailableReason",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    observed_at: datetime = Field(
        ..., alias="observedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_tool_unavailable(self) -> ToolUnavailableCollectorAttempt:
        if not _is_sha256_digest(self.request_digest):
            raise AthenaValidationError(
                "ToolUnavailableCollectorAttempt.requestDigest must be a sha256 digest"
            )
        if self.observed_at < self.attempt_started_at:
            raise AthenaValidationError("observedAt must not precede attemptStartedAt")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("attemptDigest", None)
        expected = compute_artifact_digest(payload)
        if self.attempt_digest != expected:
            raise AthenaValidationError(
                "attemptDigest mismatch: toolUnavailable collector attempt must be "
                "canonicalized without its own digest"
            )
        return self


type CollectorAttempt = Annotated[
    SuccessResponseCollectorAttempt
    | FailedResponseCollectorAttempt
    | TimeoutNoResponseCollectorAttempt
    | AuthorizationFailureCollectorAttempt
    | ToolUnavailableCollectorAttempt,
    Field(discriminator="attempt_type"),
]


class EvidenceRecordProvenance(AthenaBaseModel):
    collector_attempt_id: str = Field(
        ...,
        alias="collectorAttemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    source_response_digest: str | None = Field(
        default=None,
        alias="sourceResponseDigest",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    source_response_pointer: str | None = Field(
        default=None,
        alias="sourceResponsePointer",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_payload_digest: str | None = Field(
        default=None,
        alias="failurePayloadDigest",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_payload_pointer: str | None = Field(
        default=None,
        alias="failurePayloadPointer",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_provenance(self) -> EvidenceRecordProvenance:
        if self.source_response_digest is not None and not _is_sha256_digest(
            self.source_response_digest
        ):
            raise AthenaValidationError("sourceResponseDigest must be a sha256 digest")
        if self.failure_payload_digest is not None and not _is_sha256_digest(
            self.failure_payload_digest
        ):
            raise AthenaValidationError("failurePayloadDigest must be a sha256 digest")
        if self.source_response_pointer is not None and not _is_valid_json_pointer(
            self.source_response_pointer
        ):
            raise AthenaValidationError("sourceResponsePointer must be a valid JSON Pointer")
        if self.failure_payload_pointer is not None and not _is_valid_json_pointer(
            self.failure_payload_pointer
        ):
            raise AthenaValidationError("failurePayloadPointer must be a valid JSON Pointer")
        if (self.source_response_digest is None) != (self.source_response_pointer is None):
            raise AthenaValidationError(
                "source response digest and pointer must appear together"
            )
        if (self.failure_payload_digest is None) != (self.failure_payload_pointer is None):
            raise AthenaValidationError(
                "failure payload digest and pointer must appear together"
            )
        if self.source_response_digest is not None and self.failure_payload_digest is not None:
            raise AthenaValidationError(
                "record provenance cannot contain both response and failure payload fields"
            )
        return self


class SnapshotCollector(AthenaBaseModel):
    collector_type: Literal["azureMcpHost"] = Field(
        ..., alias="collectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    mcp_host_id: str = Field(
        ...,
        alias="mcpHostId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tenant_id: str = Field(
        ...,
        alias="tenantId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    trust_anchor_ref: str = Field(
        ...,
        alias="trustAnchorRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    ingestion_service_id: str = Field(
        ...,
        alias="ingestionServiceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    ingestion_audience: str = Field(
        ...,
        alias="ingestionAudience",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_allowlist_digest: str = Field(
        ...,
        alias="toolAllowlistDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_collector(self) -> SnapshotCollector:
        if not _is_valid_guid(self.tenant_id):
            raise AthenaValidationError("SnapshotCollector.tenantId must be an Azure GUID")
        if not _is_valid_key_vault_key_id(self.trust_anchor_ref):
            raise AthenaValidationError(
                "SnapshotCollector.trustAnchorRef must be a Key Vault key ID"
            )
        if not _is_sha256_digest(self.tool_allowlist_digest):
            raise AthenaValidationError(
                "SnapshotCollector.toolAllowlistDigest must be a sha256 digest"
            )
        return self


class ResourceEvidenceRecord(AthenaBaseModel):
    record_type: Literal["resource"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    resource_type: str = Field(
        ...,
        alias="resourceType",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    location: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    availability_zone: str | None = Field(
        default=None,
        alias="availabilityZone",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tags: dict[str, str] = Field(
        default_factory=dict, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    state: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    provenance: EvidenceRecordProvenance = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @field_validator("resource_id")
    @classmethod
    def validate_resource_id(cls, value: str) -> str:
        _parse_azure_resource_id(value)
        return value

    @model_validator(mode="after")
    def validate_item_digest(self) -> ResourceEvidenceRecord:
        _validate_evidence_record_digest(self)
        return self


class ObservedRelationshipEvidenceRecord(AthenaBaseModel):
    record_type: Literal["observedRelationship"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    relationship: Relationship = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    provenance: EvidenceRecordProvenance = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_item_digest(self) -> ObservedRelationshipEvidenceRecord:
        _validate_evidence_record_digest(self)
        return self


class MetricAggregateEvidenceRecord(AthenaBaseModel):
    record_type: Literal["metricAggregate"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    metric_name: str = Field(
        ...,
        alias="metricName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    aggregation: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    window_start: datetime = Field(
        ..., alias="windowStart", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    window_end: datetime = Field(
        ..., alias="windowEnd", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    value: float = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    unit: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    provenance: EvidenceRecordProvenance = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @field_validator("resource_id")
    @classmethod
    def validate_resource_id(cls, value: str) -> str:
        _parse_azure_resource_id(value)
        return value

    @model_validator(mode="after")
    def validate_metric_record(self) -> MetricAggregateEvidenceRecord:
        if self.window_start > self.window_end:
            raise AthenaValidationError("metric windowStart must not be after windowEnd")
        _validate_evidence_record_digest(self)
        return self


class HealthEventEvidenceRecord(AthenaBaseModel):
    record_type: Literal["healthEvent"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    evidence_scope: EvidenceScope = Field(
        ..., alias="evidenceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    health_kind: str = Field(
        ...,
        alias="healthKind",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    status: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    started_at: datetime = Field(
        ..., alias="startedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    ended_at: datetime = Field(
        ..., alias="endedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    summary: str = Field(
        ..., min_length=1, max_length=1000, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    provenance: EvidenceRecordProvenance = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_health_record(self) -> HealthEventEvidenceRecord:
        if self.started_at > self.ended_at:
            raise AthenaValidationError("health event startedAt must not be after endedAt")
        _validate_evidence_record_digest(self)
        return self


class ActivitySummaryEvidenceRecord(AthenaBaseModel):
    record_type: Literal["activitySummary"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    evidence_scope: EvidenceScope = Field(
        ..., alias="evidenceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    operation_name: str = Field(
        ...,
        alias="operationName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    status: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    count: int = Field(..., ge=0, json_schema_extra={"x-athena-semanticClass": "semantic"})
    window_start: datetime = Field(
        ..., alias="windowStart", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    window_end: datetime = Field(
        ..., alias="windowEnd", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    provenance: EvidenceRecordProvenance = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_activity_record(self) -> ActivitySummaryEvidenceRecord:
        if self.window_start > self.window_end:
            raise AthenaValidationError("activity windowStart must not be after windowEnd")
        _validate_evidence_record_digest(self)
        return self


class AdvisorRecommendationEvidenceRecord(AthenaBaseModel):
    record_type: Literal["advisorRecommendation"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    category: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    impact: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    recommendation_code: str = Field(
        ...,
        alias="recommendationCode",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    provenance: EvidenceRecordProvenance = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @field_validator("resource_id")
    @classmethod
    def validate_resource_id(cls, value: str) -> str:
        _parse_azure_resource_id(value)
        return value

    @model_validator(mode="after")
    def validate_item_digest(self) -> AdvisorRecommendationEvidenceRecord:
        _validate_evidence_record_digest(self)
        return self


class EvidenceGapRecord(AthenaBaseModel):
    record_type: Literal["evidenceGap"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    gap_id: str = Field(
        ..., alias="gapId", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    evidence_scope: EvidenceScope = Field(
        ..., alias="evidenceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    gap_reason: Literal[
        "missing",
        "stale",
        "unauthorized",
        "filtered",
        "malformed",
        "collectorUnavailable",
        "scopeMismatch",
        "responseOversized",
        "unsupportedTool",
    ] = Field(
        ...,
        alias="gapReason",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    expected_record_type: ExpectedEvidenceRecordType = Field(
        ..., alias="expectedRecordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_attempt_id: str = Field(
        ...,
        alias="collectorAttemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    observed_at: datetime = Field(
        ..., alias="observedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_payload_digest: str | None = Field(
        default=None,
        alias="failurePayloadDigest",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_payload_pointer: str | None = Field(
        default=None,
        alias="failurePayloadPointer",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_gap_record(self) -> EvidenceGapRecord:
        if self.failure_payload_digest is not None and not _is_sha256_digest(
            self.failure_payload_digest
        ):
            raise AthenaValidationError("evidence gap failurePayloadDigest must be a sha256 digest")
        if (self.failure_payload_digest is None) != (self.failure_payload_pointer is None):
            raise AthenaValidationError(
                "evidence gap failure payload digest and pointer must appear together"
            )
        if self.failure_payload_pointer is not None and not _is_valid_json_pointer(
            self.failure_payload_pointer
        ):
            raise AthenaValidationError(
                "evidence gap failurePayloadPointer must be a valid JSON Pointer"
            )
        _validate_evidence_record_digest(self)
        return self


type EvidenceRecord = Annotated[
    ResourceEvidenceRecord
    | ObservedRelationshipEvidenceRecord
    | MetricAggregateEvidenceRecord
    | HealthEventEvidenceRecord
    | ActivitySummaryEvidenceRecord
    | AdvisorRecommendationEvidenceRecord
    | EvidenceGapRecord,
    Field(discriminator="record_type"),
]


class EvidenceSnapshot(AthenaBaseModel):
    snapshot_id: str = Field(
        ...,
        alias="snapshotId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    compatibility: CompatibilityMetadata = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    authorized_scopes: list[EvidenceScope] = Field(
        ...,
        alias="authorizedScopes",
        min_length=1,
        max_length=100,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collected_at: datetime = Field(
        ..., alias="collectedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expires_at: datetime = Field(
        ..., alias="expiresAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector: SnapshotCollector = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_attempts: list[CollectorAttempt] = Field(
        ...,
        alias="collectorAttempts",
        min_length=1,
        max_length=500,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    evidence_records: list[EvidenceRecord] = Field(
        ...,
        alias="evidenceRecords",
        max_length=30000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    evidence_refs: list[EvidenceReference] = Field(
        default_factory=list,
        alias="evidenceRefs",
        max_length=30000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    identity_evidence: list[CollectorIdentityEvidence] = Field(
        default_factory=list,
        alias="identityEvidence",
        max_length=500,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )

    @model_validator(mode="after")
    def validate_snapshot(self) -> EvidenceSnapshot:
        if self.compatibility.artifact_kind != "evidenceSnapshot":
            raise AthenaValidationError(
                "EvidenceSnapshot compatibility.artifactKind must be evidenceSnapshot"
            )
        if not _is_sha256_digest(self.compatibility.artifact_digest):
            raise AthenaValidationError(
                "EvidenceSnapshot compatibility.artifactDigest must be a sha256 digest"
            )
        if not _is_sha256_digest(self.compatibility.semantic_digest):
            raise AthenaValidationError(
                "EvidenceSnapshot compatibility.semanticDigest must be a sha256 digest"
            )
        if self.collected_at >= self.expires_at:
            raise AthenaValidationError("EvidenceSnapshot.collectedAt must be before expiresAt")
        if len(self.authorized_scopes) != len(
            {
                canonicalize_json(scope.model_dump(mode="json", by_alias=True))
                for scope in self.authorized_scopes
            }
        ):
            raise AthenaValidationError("authorizedScopes must not contain duplicates")
        for scope in self.authorized_scopes:
            scope_tenant_id = getattr(scope, "tenant_id", None)
            if scope_tenant_id is not None and scope_tenant_id != self.collector.tenant_id:
                raise AthenaValidationError(
                    "authorized scope tenantId must match the snapshot collector tenantId"
                )
            if isinstance(scope, ResourceIdScope):
                _parse_azure_resource_id(scope.resource_id)
                if not any(
                    isinstance(parent, (SubscriptionScope, ResourceGroupScope))
                    and parent.tenant_id == self.collector.tenant_id
                    and _components_contain(
                        _resource_id_parts_from_scope(parent) or (),
                        _parse_azure_resource_id(scope.resource_id),
                    )
                    for parent in self.authorized_scopes
                ):
                    raise AthenaValidationError(
                        "resourceId authorized scopes require a matching tenant-bound parent scope"
                    )

        if self.identity_evidence:
            identity_lookup_by_id: dict[str, CollectorIdentityEvidence] = {}
            for identity in self.identity_evidence:
                if identity.identity_evidence_id in identity_lookup_by_id:
                    raise AthenaValidationError(
                        "identityEvidence must contain unique identityEvidenceId values"
                    )
                identity_lookup_by_id[identity.identity_evidence_id] = identity
            for attempt in self.collector_attempts:
                ref = attempt.collector_identity_evidence_ref
                if ref not in identity_lookup_by_id:
                    raise AthenaValidationError(
                        "collectorAttempts must resolve to a trusted identityEvidence record"
                    )
            for record in self.evidence_records:
                if record.collector_identity_evidence_ref not in identity_lookup_by_id:
                    raise AthenaValidationError(
                        "evidence records must resolve to a trusted identityEvidence record"
                    )

        attempt_lookup_by_id: dict[str, CollectorAttempt] = {}
        attempt_lookup_by_digest: dict[str, CollectorAttempt] = {}
        for attempt in self.collector_attempts:
            if (
                attempt.collector_identity_evidence_ref
                != self.collector.collector_identity_evidence_ref
            ):
                raise AthenaValidationError(
                    "collectorAttempts must reference the snapshot "
                    "collectorIdentityEvidenceRef"
                )
            if attempt.attempt_id in attempt_lookup_by_id:
                raise AthenaValidationError("collectorAttempts must have unique attemptId values")
            if attempt.attempt_digest in attempt_lookup_by_digest:
                raise AthenaValidationError(
                    "collectorAttempts must have unique attemptDigest values"
                )
            attempt_lookup_by_id[attempt.attempt_id] = attempt
            attempt_lookup_by_digest[attempt.attempt_digest] = attempt

        def resource_id_is_authorized(resource_id: str) -> bool:
            candidate_parts = _parse_azure_resource_id(resource_id)
            return any(
                container_parts is not None
                and _components_contain(container_parts, candidate_parts)
                for container_parts in (
                    _resource_id_parts_from_scope(scope) for scope in self.authorized_scopes
                )
            )

        seen_record_ids: set[str] = set()
        for record in self.evidence_records:
            if (
                record.collector_identity_evidence_ref
                != self.collector.collector_identity_evidence_ref
            ):
                raise AthenaValidationError(
                    "evidence records must reference the snapshot collectorIdentityEvidenceRef"
                )
            current_attempt = attempt_lookup_by_digest.get(record.collector_attempt_digest)
            if current_attempt is None:
                raise AthenaValidationError(
                    "evidence record references an unknown collector attempt"
                )
            if (
                hasattr(record, "collector_attempt_id")
                and current_attempt.attempt_id != record.collector_attempt_id
            ):
                raise AthenaValidationError(
                    "evidence record attemptId does not match its collector attempt"
                )
            if hasattr(record, "provenance"):
                if record.provenance.collector_attempt_id != current_attempt.attempt_id:
                    raise AthenaValidationError(
                        "record provenance attemptId must match the selected collector attempt"
                    )
                if record.provenance.tool_name != current_attempt.tool_name:
                    raise AthenaValidationError(
                        "record provenance toolName must match the selected collector attempt"
                    )
                if record.provenance.tool_version != current_attempt.tool_version:
                    raise AthenaValidationError(
                        "record provenance toolVersion must match the selected collector attempt"
                    )
                if (
                    record.provenance.collector_identity_evidence_ref
                    != self.collector.collector_identity_evidence_ref
                ):
                    raise AthenaValidationError(
                        "record provenance identityEvidenceRef must match the "
                        "snapshot collector evidence ref"
                    )
                if current_attempt.attempt_type == "successResponse":
                    if record.provenance.source_response_digest != current_attempt.response_digest:
                        raise AthenaValidationError(
                            "record provenance sourceResponseDigest must match the "
                            "selected successful attempt"
                        )
                    if record.provenance.source_response_pointer is None:
                        raise AthenaValidationError(
                            "successResponse provenance requires a sourceResponsePointer"
                        )
                    if record.provenance.failure_payload_digest is not None:
                        raise AthenaValidationError(
                            "successful concrete evidence must not carry failure payload fields"
                        )
            if record.record_type == "evidenceGap":
                gap_record = cast(EvidenceGapRecord, record)
                record_key = gap_record.gap_id
                if gap_record.observed_at != _attempt_observation_time(current_attempt):
                    raise AthenaValidationError(
                        "evidenceGap observedAt must equal the selected attempt observation time"
                    )
                if gap_record.evidence_scope not in self.authorized_scopes and not any(
                    _scope_contains(auth_scope, gap_record.evidence_scope)
                    for auth_scope in self.authorized_scopes
                ):
                    raise AthenaValidationError(
                        "evidenceGap record scope must be contained by the snapshot "
                        "authorized scopes"
                    )
                if current_attempt.attempt_type == "failedResponse":
                    if (
                        gap_record.failure_payload_digest != current_attempt.failure_digest
                        or gap_record.failure_payload_pointer is None
                    ):
                        raise AthenaValidationError(
                            "failedResponse gaps require the exact failure digest and pointer"
                        )
                elif current_attempt.attempt_type == "successResponse":
                    if gap_record.gap_reason not in {
                        "filtered",
                        "malformed",
                        "stale",
                        "scopeMismatch",
                        "responseOversized",
                    }:
                        raise AthenaValidationError(
                            "successResponse gap reason is not allowed by the closed variant"
                        )
                    if (
                        gap_record.failure_payload_digest != current_attempt.response_digest
                        or gap_record.failure_payload_pointer is None
                    ):
                        raise AthenaValidationError(
                            "successResponse gaps require the exact response digest and "
                            "offending-item pointer"
                        )
                elif (
                    gap_record.failure_payload_digest is not None
                    or gap_record.failure_payload_pointer is not None
                ):
                    raise AthenaValidationError(
                        "no-response gaps must not fabricate failure payload fields"
                    )
            else:
                concrete_record = cast(
                    ResourceEvidenceRecord
                    | ObservedRelationshipEvidenceRecord
                    | MetricAggregateEvidenceRecord
                    | HealthEventEvidenceRecord
                    | ActivitySummaryEvidenceRecord
                    | AdvisorRecommendationEvidenceRecord,
                    record,
                )
                record_key = concrete_record.item_digest
                if current_attempt.attempt_type != "successResponse":
                    raise AthenaValidationError(
                        "concrete evidence records must reference a "
                        "successResponse collector attempt only"
                    )
                if hasattr(concrete_record, "evidence_scope") and not any(
                    _scope_contains(auth_scope, concrete_record.evidence_scope)
                    for auth_scope in self.authorized_scopes
                ):
                    raise AthenaValidationError(
                        "concrete evidence record scope must be contained by the snapshot "
                        "authorized scopes"
                    )
                direct_resource_id = getattr(concrete_record, "resource_id", None)
                if direct_resource_id is not None and not resource_id_is_authorized(
                    direct_resource_id
                ):
                    raise AthenaValidationError(
                        "evidence record resourceId is outside the snapshot authorized scopes"
                    )
                if isinstance(concrete_record, ObservedRelationshipEvidenceRecord):
                    if concrete_record.relationship.relationship_class != "observed":
                        raise AthenaValidationError(
                            "observedRelationship evidence must contain an observed relationship"
                        )
                    for endpoint in (
                        concrete_record.relationship.source,
                        concrete_record.relationship.target,
                    ):
                        if isinstance(endpoint, ResourceRef) and not resource_id_is_authorized(
                            endpoint.resource_id
                        ):
                            raise AthenaValidationError(
                                "relationship resource endpoint is outside the snapshot "
                                "authorized scopes"
                            )
            if record_key in seen_record_ids:
                raise AthenaValidationError(
                    "evidence records must have unique itemDigest/gapId values"
                )
            seen_record_ids.add(record_key)

        seen_refs: set[tuple[str, str, str]] = set()
        referenced_records: set[str] = set()
        for evidence_ref in self.evidence_refs:
            if evidence_ref.ref_type == "evidenceItem":
                if evidence_ref.snapshot_id != self.snapshot_id:
                    raise AthenaValidationError(
                        "EvidenceItemRef.snapshotId must match the current snapshot"
                    )
                if evidence_ref.snapshot_artifact_digest != self.compatibility.artifact_digest:
                    raise AthenaValidationError(
                        "EvidenceItemRef.snapshotArtifactDigest must match the current "
                        "snapshot artifact digest"
                    )
                if evidence_ref.snapshot_semantic_digest != self.compatibility.semantic_digest:
                    raise AthenaValidationError(
                        "EvidenceItemRef.snapshotSemanticDigest must match the current "
                        "snapshot semantic digest"
                    )
                matched_records = [
                        record
                        for record in self.evidence_records
                        if record.record_type != "evidenceGap"
                        and record.item_digest == evidence_ref.item_digest
                        and record.collector_attempt_digest
                        == evidence_ref.collector_attempt_digest
                        and record.collector_identity_evidence_ref
                        == evidence_ref.collector_identity_evidence_ref
                        and record.provenance.collector_attempt_id
                        == evidence_ref.collector_attempt_id
                        and record.provenance.source_response_digest
                        == evidence_ref.source_response_digest
                        and record.provenance.source_response_pointer
                        == evidence_ref.source_response_pointer
                ]
                if len(matched_records) != 1:
                    raise AthenaValidationError(
                        "EvidenceItemRef must resolve exactly once to an item in "
                        "the current snapshot"
                    )
                matching_attempt = attempt_lookup_by_id.get(evidence_ref.collector_attempt_id)
                if matching_attempt is None:
                    raise AthenaValidationError(
                        "EvidenceItemRef must resolve to a current snapshot collector attempt"
                    )
                if evidence_ref.collector_tool_name != matching_attempt.tool_name:
                    raise AthenaValidationError(
                        "EvidenceItemRef.collectorToolName must match the selected attempt"
                    )
                if evidence_ref.collector_tool_version != matching_attempt.tool_version:
                    raise AthenaValidationError(
                        "EvidenceItemRef.collectorToolVersion must match the selected attempt"
                    )
                if evidence_ref.collector_attempt_at != _attempt_observation_time(
                    matching_attempt
                ):
                    raise AthenaValidationError(
                        "EvidenceItemRef.collectorAttemptAt must equal the selected "
                        "attempt response time"
                    )
                key: tuple[str, str, str] = (
                    evidence_ref.ref_type,
                    evidence_ref.snapshot_id,
                    evidence_ref.item_digest,
                )
                referenced_records.add(evidence_ref.item_digest)
            else:
                if evidence_ref.snapshot_id != self.snapshot_id:
                    raise AthenaValidationError(
                        "EvidenceGapRef.snapshotId must match the current snapshot"
                    )
                if evidence_ref.snapshot_artifact_digest != self.compatibility.artifact_digest:
                    raise AthenaValidationError(
                        "EvidenceGapRef.snapshotArtifactDigest must match the current "
                        "snapshot artifact digest"
                    )
                if evidence_ref.snapshot_semantic_digest != self.compatibility.semantic_digest:
                    raise AthenaValidationError(
                        "EvidenceGapRef.snapshotSemanticDigest must match the current "
                        "snapshot semantic digest"
                    )
                matched_gaps = [
                        record
                        for record in self.evidence_records
                        if record.record_type == "evidenceGap"
                        and record.gap_id == evidence_ref.gap_id
                        and record.item_digest == evidence_ref.gap_record_digest
                        and record.collector_attempt_id == evidence_ref.collector_attempt_id
                        and record.collector_attempt_digest
                        == evidence_ref.collector_attempt_digest
                ]
                if len(matched_gaps) != 1:
                    raise AthenaValidationError(
                        "EvidenceGapRef must resolve exactly once to a gap in the current "
                        "snapshot"
                    )
                matched_gap = cast(EvidenceGapRecord, matched_gaps[0])
                matching_attempt = attempt_lookup_by_id.get(evidence_ref.collector_attempt_id)
                if matching_attempt is None:
                    raise AthenaValidationError(
                        "EvidenceGapRef must resolve to a current snapshot collector attempt"
                    )
                if evidence_ref.collector_tool_name != matching_attempt.tool_name:
                    raise AthenaValidationError(
                        "EvidenceGapRef.collectorToolName must match the selected attempt"
                    )
                if evidence_ref.collector_tool_version != matching_attempt.tool_version:
                    raise AthenaValidationError(
                        "EvidenceGapRef.collectorToolVersion must match the selected attempt"
                    )
                if evidence_ref.collector_attempt_at != _attempt_observation_time(
                    matching_attempt
                ):
                    raise AthenaValidationError(
                        "EvidenceGapRef.collectorAttemptAt must equal the selected "
                        "attempt observation time"
                    )
                if matched_gap.evidence_scope != evidence_ref.evidence_scope:
                    raise AthenaValidationError(
                        "EvidenceGapRef.evidenceScope must match the resolved gap scope"
                    )
                if matched_gap.expected_record_type != evidence_ref.expected_record_type:
                    raise AthenaValidationError(
                        "EvidenceGapRef.expectedRecordType must match the resolved gap"
                    )
                if matched_gap.gap_reason != evidence_ref.gap_reason:
                    raise AthenaValidationError(
                        "EvidenceGapRef.gapReason must match the resolved gap"
                    )
                if (
                    matched_gap.collector_identity_evidence_ref
                    != evidence_ref.collector_identity_evidence_ref
                ):
                    raise AthenaValidationError(
                        "EvidenceGapRef.collectorIdentityEvidenceRef must match the resolved gap"
                    )
                if (
                    matched_gap.failure_payload_digest
                    != evidence_ref.failure_payload_digest
                    or matched_gap.failure_payload_pointer
                    != evidence_ref.failure_payload_pointer
                ):
                    raise AthenaValidationError(
                        "EvidenceGapRef failure payload fields must match the resolved gap"
                    )
                key = (evidence_ref.ref_type, evidence_ref.snapshot_id, evidence_ref.gap_id)
                referenced_records.add(evidence_ref.gap_id)
            if key in seen_refs:
                raise AthenaValidationError(
                    "EvidenceSnapshot.evidenceRefs must contain each reference exactly once"
                )
            seen_refs.add(key)
        if referenced_records != seen_record_ids:
            raise AthenaValidationError(
                "every evidence record must have exactly one matching evidence reference"
            )
        expected_artifact_digest = compute_evidence_snapshot_artifact_digest(self)
        if self.compatibility.artifact_digest != expected_artifact_digest:
            raise AthenaValidationError(
                "EvidenceSnapshot compatibility.artifactDigest mismatched the canonical snapshot "
                "preimage"
            )
        expected_semantic_digest = compute_evidence_snapshot_semantic_digest(self)
        if self.compatibility.semantic_digest != expected_semantic_digest:
            raise AthenaValidationError(
                "EvidenceSnapshot compatibility.semanticDigest mismatched the canonical snapshot "
                "semantic preimage"
            )
        return self

    def validate_for_evaluation(
        self,
        *,
        as_of: datetime,
        identity_evidence: Iterable[CollectorIdentityEvidence] | None = None,
        identity_resolver: Callable[[str], CollectorIdentityEvidence] | None = None,
        key_resolver: Callable[[str], Any] | None = None,
        envelope_resolver: EvidenceEnvelopeResolver | None = None,
    ) -> EvidenceSnapshot:
        if as_of.tzinfo is None:
            raise AthenaValidationError("as_of must be timezone-aware")
        if (
            self.compatibility.artifact_digest
            != compute_evidence_snapshot_artifact_digest(self)
        ):
            raise AthenaValidationError(
                "snapshot artifact digest must be valid at evaluation time"
            )
        if (
            self.compatibility.semantic_digest
            != compute_evidence_snapshot_semantic_digest(self)
        ):
            raise AthenaValidationError(
                "snapshot semantic digest must be valid at evaluation time"
            )
        if as_of < self.collected_at or as_of >= self.expires_at:
            raise AthenaValidationError(
                "snapshot must be fresh and not expired at the evaluation as_of"
            )
        if not self.identity_evidence and not identity_resolver and not identity_evidence:
            raise AthenaValidationError(
                "snapshot evaluation requires either embedded identityEvidence or an "
                "explicit trusted identity resolver"
            )
        resolution_source = list(identity_evidence or self.identity_evidence)
        resolved_identity_lookup: dict[str, CollectorIdentityEvidence] = {}
        for identity in resolution_source:
            if identity.identity_evidence_id in resolved_identity_lookup:
                raise AthenaValidationError(
                    "identityEvidence must contain unique identityEvidenceId values"
                )
            resolved_identity_lookup[identity.identity_evidence_id] = identity
        if identity_resolver is not None:
            for identity_ref in {
                attempt.collector_identity_evidence_ref for attempt in self.collector_attempts
            } | {
                record.collector_identity_evidence_ref for record in self.evidence_records
            }:
                if identity_ref in resolved_identity_lookup:
                    continue
                resolved = identity_resolver(identity_ref)
                if resolved is None:
                    raise AthenaValidationError(
                        "snapshot identityEvidenceRef is missing from the trusted resolver"
                    )
                if resolved.identity_evidence_id != identity_ref:
                    raise AthenaValidationError(
                        "trusted identity resolver must return the exact identityEvidenceId "
                        "mapping"
                    )
                resolved_identity_lookup[identity_ref] = resolved
        if key_resolver is None:
            raise AthenaValidationError(
                "snapshot evaluation requires an explicit key_resolver for cryptographic "
                "verification"
            )
        attempt_lookup_by_id: dict[str, CollectorAttempt] = {}
        attempt_lookup_by_digest: dict[str, CollectorAttempt] = {}
        for attempt in self.collector_attempts:
            attempt_lookup_by_id[attempt.attempt_id] = attempt
            attempt_lookup_by_digest[attempt.attempt_digest] = attempt
            attempt_identity = resolved_identity_lookup.get(attempt.collector_identity_evidence_ref)
            if attempt_identity is None:
                raise AthenaValidationError("collector attempt identity evidence was not resolved")
            if not attempt_identity.verify_signature(key_resolver=key_resolver, attempt=attempt):
                raise AthenaValidationError(
                    "collector attempt identity evidence verification failed"
                )
            derivation = attempt_identity.ingestion_derivation
            if (
                derivation.mcp_host_id != self.collector.mcp_host_id
                or derivation.mcp_host_tenant_id != self.collector.tenant_id
                or derivation.ingestion_service_id != self.collector.ingestion_service_id
                or derivation.ingestion_audience != self.collector.ingestion_audience
                or derivation.tool_allowlist_digest != self.collector.tool_allowlist_digest
                or attempt_identity.trust_anchor_ref != self.collector.trust_anchor_ref
                or derivation.schema_version != self.compatibility.schema_version
                or derivation.semantic_contract_version
                != self.compatibility.semantic_contract_version
                or derivation.policy_contract_version
                != self.compatibility.policy_contract_version
            ):
                raise AthenaValidationError(
                    "signed ingestion derivation must exactly match snapshot collector "
                    "and compatibility metadata"
                )
            if not (
                attempt_identity.verified_claims.issued_at
                <= self.collected_at
                < attempt_identity.verified_claims.expires_at
            ):
                raise AthenaValidationError(
                    "collector token must be valid at snapshot collectedAt"
                )
            if attempt.attempt_started_at < self.collected_at or attempt.attempt_started_at > as_of:
                raise AthenaValidationError(
                    "collector attempt timestamps must fall inside the snapshot collection window"
                )
            response_received_at = getattr(attempt, "response_received_at", None)
            if (
                response_received_at is not None
                and (
                    response_received_at < self.collected_at
                    or response_received_at > as_of
                )
            ):
                raise AthenaValidationError(
                    "attempt response timestamps must be inside the collection "
                    "window and before as_of"
                )
            timed_out_at = getattr(attempt, "timed_out_at", None)
            if timed_out_at is not None and (
                timed_out_at < self.collected_at or timed_out_at > as_of
            ):
                raise AthenaValidationError(
                    "timeout timestamps must be inside the collection window and before as_of"
                )
            deadline_at = getattr(attempt, "deadline_at", None)
            if deadline_at is not None and (
                deadline_at < self.collected_at or deadline_at > as_of
            ):
                raise AthenaValidationError(
                    "deadlineAt must fall inside the collection window and before as_of"
                )
            observed_at = getattr(attempt, "observed_at", None)
            if observed_at is not None and (
                observed_at < self.collected_at or observed_at > as_of
            ):
                raise AthenaValidationError(
                    "observedAt must fall inside the collection window and before as_of"
                )
        envelope_cache: dict[tuple[str, str, str], Any] = {}
        pointer_cache: dict[tuple[str, str, str, str], Any] = {}

        def resolve_envelope_pointer_once(
            attempt: CollectorAttempt,
            envelope_kind: Literal["response", "failure"],
            digest: str,
            pointer: str,
        ) -> Any:
            if envelope_resolver is None:
                raise AthenaValidationError(
                    "snapshot evaluation requires an explicit trusted envelope_resolver"
                )
            claim = (attempt.attempt_id, envelope_kind, digest, pointer)
            if claim in pointer_cache:
                return pointer_cache[claim]
            cache_key = (attempt.attempt_id, envelope_kind, digest)
            if cache_key not in envelope_cache:
                envelope = envelope_resolver(attempt.attempt_id, envelope_kind, digest)
                if envelope is None:
                    raise AthenaValidationError(
                        "trusted envelope resolver returned no digest-covered envelope"
                    )
                computed_digest = (
                    compute_response_envelope_digest(envelope)
                    if envelope_kind == "response"
                    else compute_failure_envelope_digest(envelope)
                )
                if computed_digest != digest:
                    raise AthenaValidationError(
                        "trusted envelope resolver returned an envelope with a mismatched digest"
                    )
                envelope_cache[cache_key] = (
                    _response_envelope_digest_preimage(envelope)
                    if envelope_kind == "response"
                    else _failure_envelope_digest_preimage(envelope)
                )
            resolved = _resolve_json_pointer(envelope_cache[cache_key], pointer)
            pointer_cache[claim] = resolved
            return resolved

        for record in self.evidence_records:
            if hasattr(record, "observed_at") and (
                record.observed_at < self.collected_at or record.observed_at > as_of
            ):
                raise AthenaValidationError(
                    "evidence record observedAt must fall inside the snapshot collection window"
                )
            if hasattr(record, "window_start") and (
                record.window_start < self.collected_at or record.window_start > as_of
            ):
                raise AthenaValidationError(
                    "evidence record windowStart must fall inside the snapshot collection window"
                )
            if hasattr(record, "window_end") and (
                record.window_end < self.collected_at or record.window_end > as_of
            ):
                raise AthenaValidationError(
                    "evidence record windowEnd must fall inside the snapshot collection window"
                )
            if hasattr(record, "started_at") and (
                record.started_at < self.collected_at or record.started_at > as_of
            ):
                raise AthenaValidationError(
                    "health event startedAt must fall inside the snapshot collection window"
                )
            if hasattr(record, "ended_at") and (
                record.ended_at < self.collected_at or record.ended_at > as_of
            ):
                raise AthenaValidationError(
                    "health event endedAt must fall inside the snapshot collection window"
                )
            if isinstance(record, ObservedRelationshipEvidenceRecord):
                relationship = cast(ObservedRelationship, record.relationship)
                relationship_observed_at = relationship.observed_at
                if (
                    relationship_observed_at < self.collected_at
                    or relationship_observed_at > as_of
                ):
                    raise AthenaValidationError(
                        "observed relationship observedAt must fall inside the snapshot "
                        "collection window"
                    )
            if record.record_type != "evidenceGap":
                concrete_record = cast(
                    ResourceEvidenceRecord
                    | ObservedRelationshipEvidenceRecord
                    | MetricAggregateEvidenceRecord
                    | HealthEventEvidenceRecord
                    | ActivitySummaryEvidenceRecord
                    | AdvisorRecommendationEvidenceRecord,
                    record,
                )
                if (
                    concrete_record.provenance.source_response_digest is not None
                    and concrete_record.provenance.source_response_pointer is None
                ):
                    raise AthenaValidationError(
                        "sourceResponsePointer is required when sourceResponseDigest is present"
                    )
                if (
                    concrete_record.provenance.failure_payload_pointer is not None
                    and not _is_valid_json_pointer(
                        concrete_record.provenance.failure_payload_pointer
                    )
                ):
                    raise AthenaValidationError(
                        "failurePayloadPointer must be a valid RFC 6901 JSON Pointer"
                    )
                if (
                    concrete_record.provenance.source_response_pointer is not None
                    and not _is_valid_json_pointer(
                        concrete_record.provenance.source_response_pointer
                    )
                ):
                    raise AthenaValidationError(
                        "sourceResponsePointer must be a valid RFC 6901 JSON Pointer"
                    )
            proof_identity = resolved_identity_lookup.get(record.collector_identity_evidence_ref)
            if proof_identity is None:
                raise AthenaValidationError(
                    "evidence record must resolve to a trusted identityEvidence record"
                )
            record_attempt_id = getattr(record, "collector_attempt_id", None)
            record_attempt_digest = getattr(record, "collector_attempt_digest", None)
            attempt_for_record = (
                attempt_lookup_by_digest.get(record_attempt_digest)
                if record_attempt_digest is not None
                else None
            )
            if record_attempt_id is not None:
                attempt_by_id = attempt_lookup_by_id.get(record_attempt_id)
                if attempt_by_id is not attempt_for_record:
                    raise AthenaValidationError(
                        "evidence record attemptId and collectorAttemptDigest must resolve "
                        "to the same attempt"
                    )
            if attempt_for_record is None:
                raise AthenaValidationError(
                    "evidence record must resolve to an attempt in the current snapshot"
                )
            if not proof_identity.verify_signature(
                key_resolver=key_resolver,
                attempt=attempt_for_record,
            ):
                raise AthenaValidationError(
                    "evidence record identity evidence verification failed"
                )
            if record.record_type == "evidenceGap":
                gap_record = cast(EvidenceGapRecord, record)
                if (
                    gap_record.failure_payload_digest is not None
                    and gap_record.failure_payload_pointer is not None
                ):
                    envelope_kind: Literal["response", "failure"] = (
                        "response"
                        if attempt_for_record.attempt_type == "successResponse"
                        else "failure"
                    )
                    resolve_envelope_pointer_once(
                        attempt_for_record,
                        envelope_kind,
                        gap_record.failure_payload_digest,
                        gap_record.failure_payload_pointer,
                    )
            else:
                concrete_record = cast(
                    ResourceEvidenceRecord
                    | ObservedRelationshipEvidenceRecord
                    | MetricAggregateEvidenceRecord
                    | HealthEventEvidenceRecord
                    | ActivitySummaryEvidenceRecord
                    | AdvisorRecommendationEvidenceRecord,
                    record,
                )
                if (
                    concrete_record.provenance.source_response_digest is None
                    or concrete_record.provenance.source_response_pointer is None
                ):
                    raise AthenaValidationError(
                        "concrete evidence requires response digest and pointer provenance"
                    )
                resolved_source = resolve_envelope_pointer_once(
                    attempt_for_record,
                    "response",
                    concrete_record.provenance.source_response_digest,
                    concrete_record.provenance.source_response_pointer,
                )
                if canonicalize_json(resolved_source) != canonicalize_json(
                    _evidence_source_projection(concrete_record)
                ):
                    raise AthenaValidationError(
                        "resolved response item does not match the evidence record projection"
                    )
        return self


class Finding(AthenaBaseModel):
    finding_kind: FindingKind = Field(
        ..., alias="findingKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    verdict: Verdict = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    governance_scope: GovernanceScope = Field(
        ..., alias="governanceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    context_ref: ContextRef = Field(
        ..., alias="contextRef", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    evidence_ref: EvidenceReference = Field(
        ..., alias="evidenceRef", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    summary: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


__all__ = [
    "AthenaBaseModel",
    "AthenaValidationError",
    "CapabilityRequirement",
    "CompatibilityMetadata",
    "verify_key_vault_signature",
    "verify_trusted_ingestion_signature",
    "compute_evidence_record_digest",
    "compute_token_verification_digest",
    "compute_response_envelope_digest",
    "compute_failure_envelope_digest",
    "compute_evidence_snapshot_artifact_digest",
    "compute_evidence_snapshot_semantic_digest",
    "EvidenceEnvelopeResolver",
    "ProducerInfo",
    "AzureCloud",
    "WorkloadIdentity",
    "OperationalOwnership",
    "ManifestAudit",
    "ManifestRelationshipSet",
    "SubscriptionScope",
    "ResourceGroupScope",
    "ResourceIdScope",
    "LogAnalyticsWorkspaceScope",
    "ServiceHealthRegionScope",
    "EvidenceScope",
    "GovernanceManifestScope",
    "GovernanceProfileScope",
    "GovernanceClauseScope",
    "GovernanceRoleScope",
    "GovernanceResourceBindingScope",
    "GovernanceRelationshipScope",
    "GovernanceControlScope",
    "GovernanceObjectiveScope",
    "GovernanceScope",
    "ProfileDefinition",
    "ProfileOverride",
    "ProfileContinuitySettings",
    "ProfileSettings",
    "RoleCardinalityExactlyOne",
    "RoleCardinalityOneOrMore",
    "RoleCardinalityZeroOrMore",
    "RoleCardinalityBoundedRange",
    "RoleCardinality",
    "ResourceIdListSelector",
    "TagPredicateSelector",
    "NamePatternSelector",
    "ResourceTypeScopeSelector",
    "CompositeAllSelector",
    "CompositeAnySelector",
    "Selector",
    "OwnershipReference",
    "WorkloadRole",
    "RoleRef",
    "ResourceRef",
    "ExternalRef",
    "Relationship",
    "DeclaredRelationship",
    "ObservedRelationship",
    "InferredRelationship",
    "ExceptionRelationship",
    "Constraint",
    "ProofRequirement",
    "CardProof",
    "ZoneColocationProof",
    "ZoneDistributionProof",
    "RelationshipPresenceProof",
    "EvidenceFreshnessProof",
    "ControlHealthProof",
    "ObjectiveThresholdProof",
    "Control",
    "RiskAcceptance",
    "Objective",
    "WorkloadManifest",
    "EvidenceItemRef",
    "EvidenceGapRef",
    "EvidenceReference",
    "ContextRef",
    "JwtHeader",
    "VerifiedEntraClaims",
    "TokenVerification",
    "AttemptBinding",
    "IngestionDerivation",
    "IngestionSignatureVerification",
    "IngestionSignature",
    "CollectorIdentityEvidence",
    "EvidenceRecordProvenance",
    "SnapshotCollector",
    "SuccessResponseCollectorAttempt",
    "FailedResponseCollectorAttempt",
    "TimeoutNoResponseCollectorAttempt",
    "AuthorizationFailureCollectorAttempt",
    "ToolUnavailableCollectorAttempt",
    "CollectorAttempt",
    "ResourceEvidenceRecord",
    "ObservedRelationshipEvidenceRecord",
    "MetricAggregateEvidenceRecord",
    "HealthEventEvidenceRecord",
    "ActivitySummaryEvidenceRecord",
    "AdvisorRecommendationEvidenceRecord",
    "EvidenceGapRecord",
    "EvidenceRecord",
    "EvidenceSnapshot",
    "Finding",
    "Verdict",
    "FindingKind",
    "RoleKind",
    "SelectorType",
    "RelationshipKind",
    "ConstraintType",
    "ProofKind",
    "ProfileType",
]
