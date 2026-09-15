from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from athena_context.wc029_preflight import (  # noqa: E402
    PreflightInputError,
    evaluate_role_assignments,
    evaluate_what_if,
)

SOURCE_COMMIT = subprocess.run(  # noqa: S603
    ["git", "-C", str(ROOT), "rev-parse", "HEAD"],  # noqa: S607
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()

STAGES = ("foundation", "producer", "publisher", "live-acceptance")
EXPECTED_PREDECESSOR_STAGES = {
    "foundation": (),
    "producer": ("foundation",),
    "publisher": ("foundation", "producer"),
    "live-acceptance": ("foundation", "producer", "publisher"),
}
TEMPLATES = {
    "foundation": ROOT / "infra" / "wc013-live-acceptance" / "main.bicep",
    "producer": ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep",
    "publisher": ROOT / "infra" / "wc027-guidance-authority-publisher" / "main.bicep",
    "live-acceptance": ROOT / "infra" / "wc013-live-acceptance" / "main.bicep",
}
SUBSCRIPTION_STAGES = frozenset({"foundation", "live-acceptance"})
SHA256_PREFIX = "sha256:"
PREFLIGHT_PATH = ROOT / "src" / "athena_context" / "wc029_preflight.py"
PLAN_SCHEMA_VERSION = "athena.wc029DeploymentPlan.v2"
HANDOFF_SCHEMA_VERSION = "athena.wc029DeploymentHandoff.v2"
RECEIPT_SCHEMA_VERSION = "athena.wc029DeploymentReceipt.v1"
HANDOFF_FIELDS = frozenset(
    {
        "schemaVersion",
        "stage",
        "sourceCommit",
        "subscriptionId",
        "resourceGroup",
        "deploymentName",
        "outputs",
        "outputsSha256",
        "parameterBindings",
        "parameterBindingsSha256",
        "planManifestSha256",
        "predecessorReceiptSha256s",
    }
)
PLAN_FIELDS = frozenset(
    {
        "schemaVersion",
        "stage",
        "sourceCommit",
        "subscriptionId",
        "location",
        "resourceGroup",
        "deploymentName",
        "templatePath",
        "templateSha256",
        "orchestratorSha256",
        "preflightSha256",
        "baseParameterPath",
        "baseParameterSha256",
        "effectiveParameterPath",
        "effectiveParameterSha256",
        "whatIfPath",
        "whatIfSha256",
        "allowedChangeResourceIds",
        "foundationHandoffPath",
        "foundationHandoffSha256",
        "producerHandoffPath",
        "producerHandoffSha256",
        "publisherHandoffPath",
        "publisherHandoffSha256",
        "predecessorReceipts",
    }
)
PREDECESSOR_RECEIPT_REFERENCE_FIELDS = frozenset(
    {
        "path",
        "sha256",
        "reviewedSha256",
    }
)
RECEIPT_FIELDS = frozenset(
    {
        "schemaVersion",
        "stage",
        "sourceCommit",
        "subscriptionId",
        "resourceGroup",
        "deploymentName",
        "planManifestPath",
        "planManifestSha256",
        "reviewedPlanSha256",
        "handoffPath",
        "handoffSha256",
        "predecessorReceiptSha256s",
    }
)
FOUNDATION_OUTPUT_FIELDS = frozenset(
    {
        "managedEnvironmentResourceId",
        "replayStorageAccountResourceId",
        "keyVaultResourceId",
        "incidentAssetContainerResourceId",
        "presentationIdentityResourceId",
        "presentationHttpsUrl",
        "wc016ServiceBusNamespace",
        "incidentSigningKeyUriWithVersion",
        "wc016ApprovedConfiguration",
    }
)
FOUNDATION_ORCHESTRATION_FIELDS = frozenset(
    {
        "notificationQueueName",
        "feedSigningKeyUriWithVersion",
        "reportSigningKeyUriWithVersion",
        "guidanceSigningKeyUriWithVersion",
        "enrichmentSigningKeyUriWithVersion",
        "notificationSigningKeyUriWithVersion",
    }
)
FOUNDATION_BINDING_FIELDS = frozenset({"foundationParametersSha256"})
LIVE_ACCEPTANCE_OUTPUT_FIELDS = frozenset(
    {
        "wc027DeploymentReadiness",
        "publisherInvocationBoundary",
    }
)
PUBLISHER_INVOCATION_BOUNDARY = {
    "schemaVersion": "athena.wc029PublisherInvocationBoundary.v1",
    "automaticRequestProducerPresent": False,
    "runtimeInvocationValidated": False,
    "requiredRequestSchemaVersion": ("athena.wc027GuidanceAuthorityPublicationRequest.v1"),
}
SERVICE_BUS_NON_AUTO_DELETE_DURATION = "P10675199DT2H48M5.4775807S"
PRODUCER_TRIGGER_QUEUE_PROFILE = {
    "status": "Active",
    "autoDeleteOnIdle": SERVICE_BUS_NON_AUTO_DELETE_DURATION,
    "requiresSession": True,
    "requiresDuplicateDetection": True,
    "duplicateDetectionHistoryTimeWindow": "P7D",
    "deadLetteringOnMessageExpiration": True,
    "defaultMessageTimeToLive": "P1D",
    "lockDuration": "PT5M",
    "maxDeliveryCount": 10,
    "maxMessageSizeInKilobytes": 12288,
    "maxSizeInMegabytes": 1024,
    "enableBatchedOperations": True,
    "enableExpress": False,
    "enablePartitioning": False,
}
PUBLISHER_REQUEST_QUEUE_PROFILE = {
    "status": "Active",
    "autoDeleteOnIdle": SERVICE_BUS_NON_AUTO_DELETE_DURATION,
    "requiresSession": True,
    "requiresDuplicateDetection": True,
    "duplicateDetectionHistoryTimeWindow": "PT15M",
    "deadLetteringOnMessageExpiration": True,
    "defaultMessageTimeToLive": "PT5M",
    "lockDuration": "PT5M",
    "maxDeliveryCount": 5,
    "maxMessageSizeInKilobytes": 12288,
    "maxSizeInMegabytes": 1024,
    "enableBatchedOperations": True,
    "enableExpress": False,
    "enablePartitioning": False,
}
NOTIFICATION_QUEUE_PROFILE = {
    "status": "Active",
    "autoDeleteOnIdle": SERVICE_BUS_NON_AUTO_DELETE_DURATION,
    "requiresSession": True,
    "requiresDuplicateDetection": True,
    "duplicateDetectionHistoryTimeWindow": "P7D",
    "deadLetteringOnMessageExpiration": True,
    "defaultMessageTimeToLive": "P7D",
    "lockDuration": "PT1M",
    "maxDeliveryCount": 10,
    "maxMessageSizeInKilobytes": 1024,
    "maxSizeInMegabytes": 1024,
    "enableBatchedOperations": True,
    "enableExpress": False,
    "enablePartitioning": False,
}
PRODUCER_OUTPUT_FIELDS = frozenset(
    {
        "producerJobResourceId",
        "producerImage",
        "deployedRuntimeConfigurationDigest",
        "deployedRuntimeConfigurationJson",
        "attachedIdentityResourceIds",
        "bindingEvidenceDigest",
        "feedV2WriterRoleDefinitionId",
        "feedV2ContainerName",
        "feedV2ContainerResourceId",
        "feedRegistryTableResourceId",
        "guidanceActivationTableResourceId",
        "guidanceAuthoritySourceContainerResourceId",
        "triggerQueueName",
        "triggerQueueResourceId",
        "notificationQueueName",
        "notificationQueueResourceId",
        "namespaceHostName",
    }
)
PUBLISHER_OUTPUT_FIELDS = frozenset(
    {
        "publisherJobResourceId",
        "publisherImage",
        "deployedPublisherConfigurationJson",
        "deployedPublisherConfigurationDigest",
        "attachedIdentityResourceIds",
        "bindingEvidenceDigest",
        "requestQueueName",
        "requestQueueResourceId",
        "triggerQueueResourceId",
        "authorityContainerName",
        "authorityContainerResourceId",
        "activationTableName",
        "activationTableResourceId",
        "bindingLogicalKeyId",
        "bindingKeyResourceId",
        "bindingKeyVaultKeyId",
    }
)
PRODUCER_BINDING_FIELDS = frozenset(
    {
        "correlationSourceStorageAccountResourceId",
        "correlationBindingKeyResourceId",
        "changeKeyResourceId",
        "feedV2ReaderIdentityResourceId",
        "guidanceBindingKeyResourceId",
        "managedEnvironmentResourceId",
        "monitoringCollectorKeyResourceId",
        "monitoringIntentKeyResourceId",
        "registryResourceId",
        "serviceBusNamespaceName",
        "triggerSubmitterIdentityResourceIds",
    }
)
PUBLISHER_BINDING_FIELDS = frozenset(
    {
        "authorityStorageAccountResourceId",
        "activationStorageAccountResourceId",
        "bindingTrustReaderIdentityResourceId",
        "bindingKeyResourceId",
        "managedEnvironmentResourceId",
        "registryResourceId",
        "requestSubmitterIdentityResourceIds",
        "requestKeyResourceId",
        "serviceBusNamespaceName",
    }
)
WC027_ACCEPTANCE_PARAMETER_NAMES = frozenset(
    {
        "wc027FeedV2ProducerReady",
        "wc027EnrichmentFeedProducerJobResourceId",
        "wc027EnrichmentFeedProducerConfigurationDigest",
        "wc027EnrichmentFeedProducerConfigurationJson",
        "wc027EnrichmentFeedProducerImage",
        "wc027PublisherReady",
        "wc027PublisherJobResourceId",
        "wc027PublisherConfigurationDigest",
        "wc027PublisherConfigurationJson",
        "wc027PublisherImage",
    }
)


class OrchestrationError(ValueError):
    """Raised when deployment evidence or a cross-root handoff fails closed."""


@dataclass(frozen=True, slots=True)
class _ExpectedRoleAssignment:
    label: str
    principal_id: str
    scope: str
    role_definition_id: str
    condition_version: str | None = None
    condition: str | None = None


def _sha256_bytes(value: bytes) -> str:
    return f"{SHA256_PREFIX}{hashlib.sha256(value).hexdigest()}"


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OrchestrationError(f"cannot read valid JSON from {path}: {exc}") from exc


def _ensure_clean_worktree() -> None:
    completed = subprocess.run(  # noqa: S603
        ["git", "-C", str(ROOT), "status", "--porcelain=v1"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    if completed.stdout.strip():
        raise OrchestrationError(
            "deployment planning and apply require a clean committed working tree"
        )


def _mapping(value: object, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise OrchestrationError(f"{field} must be a JSON object")
    return value


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    field: str,
) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        raise OrchestrationError(
            f"{field} fields do not match the exact schema; "
            f"missing={missing}; unexpected={unexpected}"
        )


def _string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise OrchestrationError(f"{field} must be a non-empty string")
    return value


def _string_list(value: object, *, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise OrchestrationError(f"{field} must be a non-empty string array")
    if len({item.casefold() for item in value}) != len(value):
        raise OrchestrationError(f"{field} must contain distinct values")
    return value


def _canonical_subscription_id(value: object, *, field: str) -> str:
    subscription_id = _string(value, field=field)
    try:
        canonical = str(UUID(subscription_id))
    except ValueError as exc:
        raise OrchestrationError(f"{field} must be one canonical UUID") from exc
    if subscription_id != canonical:
        raise OrchestrationError(f"{field} must use canonical lowercase UUID form")
    return subscription_id


def _validate_resource_id_segment(segment: str, *, field: str) -> None:
    if (
        not segment
        or segment in {".", ".."}
        or segment != segment.strip()
        or any(character in segment for character in ("\\", "?", "#"))
    ):
        raise OrchestrationError(f"{field} contains a noncanonical path segment")


def _canonical_subscription_resource_id(
    value: object,
    *,
    subscription_id: str,
    field: str,
) -> str:
    resource_id = _string(value, field=field)
    if resource_id != resource_id.strip() or resource_id.endswith("/"):
        raise OrchestrationError(f"{field} must be a canonical Azure resource ID")
    segments = resource_id.split("/")
    if len(segments) < 3 or segments[0] != "" or segments[1] != "subscriptions":
        raise OrchestrationError(f"{field} must begin with the canonical /subscriptions/ scope")
    resource_subscription = _canonical_subscription_id(
        segments[2],
        field=f"{field} subscription",
    )
    if resource_subscription != subscription_id:
        raise OrchestrationError(f"{field} is outside the governed deployment subscription")
    if len(segments) == 3:
        return resource_id
    index = 3
    if segments[index] == "resourceGroups":
        if len(segments) < 5:
            raise OrchestrationError(f"{field} has an incomplete resource-group scope")
        _validate_resource_id_segment(
            segments[4],
            field=f"{field} resource group",
        )
        index = 5
        if index == len(segments):
            return resource_id
    if index >= len(segments) or segments[index] != "providers":
        raise OrchestrationError(f"{field} has a noncanonical provider boundary")
    while index < len(segments):
        if segments[index] != "providers" or index + 3 >= len(segments):
            raise OrchestrationError(f"{field} has an incomplete provider resource path")
        _validate_resource_id_segment(
            segments[index + 1],
            field=f"{field} provider namespace",
        )
        index += 2
        resource_pairs = 0
        while index < len(segments) and segments[index] != "providers":
            if index + 1 >= len(segments):
                raise OrchestrationError(f"{field} has an unmatched resource type/name segment")
            _validate_resource_id_segment(
                segments[index],
                field=f"{field} resource type",
            )
            _validate_resource_id_segment(
                segments[index + 1],
                field=f"{field} resource name",
            )
            resource_pairs += 1
            index += 2
        if resource_pairs == 0:
            raise OrchestrationError(f"{field} has no resource type/name pair")
    return resource_id


def _validate_subscription_boundary(
    value: object,
    *,
    subscription_id: str,
    field: str,
) -> None:
    if isinstance(value, dict):
        identity_map = field.rsplit(".", 1)[-1].casefold() == ("userassignedidentities")
        for key, child in value.items():
            child_field = f"{field}.{key}"
            normalized_key = key.casefold()
            if identity_map or "/subscriptions/" in normalized_key:
                _canonical_subscription_resource_id(
                    key,
                    subscription_id=subscription_id,
                    field=f"{field} resource ID key",
                )
            id_like_value = (
                isinstance(child, str)
                and "/subscriptions/" in child.casefold()
                and (normalized_key in {"id", "scope"} or normalized_key.endswith("id"))
            )
            declared_resource_id = normalized_key.endswith("resourceid") and child not in (None, "")
            if id_like_value or declared_resource_id:
                _canonical_subscription_resource_id(
                    child,
                    subscription_id=subscription_id,
                    field=child_field,
                )
            elif normalized_key.endswith("resourceids"):
                if not isinstance(child, list) or any(not isinstance(item, str) for item in child):
                    raise OrchestrationError(
                        f"{child_field} must be an array of canonical resource IDs"
                    )
                for index, resource_id in enumerate(child):
                    _canonical_subscription_resource_id(
                        resource_id,
                        subscription_id=subscription_id,
                        field=f"{child_field}[{index}]",
                    )
            if (
                key.casefold().endswith("subscriptionid")
                and isinstance(child, str)
                and _canonical_subscription_id(child, field=child_field) != subscription_id
            ):
                raise OrchestrationError(f"{child_field} does not match the governed subscription")
            _validate_subscription_boundary(
                child,
                subscription_id=subscription_id,
                field=child_field,
            )
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_subscription_boundary(
                child,
                subscription_id=subscription_id,
                field=f"{field}[{index}]",
            )
        return
    if not isinstance(value, str):
        return
    if value.lstrip().casefold().startswith("/subscriptions/"):
        _canonical_subscription_resource_id(
            value,
            subscription_id=subscription_id,
            field=field,
        )
        return
    stripped = value.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            nested = json.loads(value)
        except json.JSONDecodeError as exc:
            raise OrchestrationError(f"{field} contains malformed embedded JSON") from exc
        _validate_subscription_boundary(
            nested,
            subscription_id=subscription_id,
            field=f"{field} embedded JSON",
        )


def _validate_effective_parameter_subscription_boundary(
    parameters: Mapping[str, Mapping[str, object]],
    *,
    subscription_id: str,
) -> None:
    for name, entry in parameters.items():
        value = entry["value"]
        if (
            name.casefold().endswith("subscriptionid")
            and isinstance(value, str)
            and _canonical_subscription_id(
                value,
                field=f"parameters.{name}",
            )
            != subscription_id
        ):
            raise OrchestrationError(f"parameters.{name} does not match the governed subscription")
        _validate_subscription_boundary(
            value,
            subscription_id=subscription_id,
            field=f"parameters.{name}",
        )


def _sha256_digest(value: object, *, field: str) -> str:
    digest = _string(value, field=field)
    suffix = digest.removeprefix(SHA256_PREFIX)
    if (
        not digest.startswith(SHA256_PREFIX)
        or len(suffix) != 64
        or suffix != suffix.lower()
        or any(character not in "0123456789abcdef" for character in suffix)
    ):
        raise OrchestrationError(f"{field} must be a lowercase SHA-256 digest")
    return digest


def _digest_pinned_image(value: object, *, field: str) -> str:
    image = _string(value, field=field)
    if image != image.lower() or image.count("@sha256:") != 1:
        raise OrchestrationError(f"{field} must be one lowercase digest-pinned image")
    repository, digest = image.rsplit("@sha256:", 1)
    if (
        "/" not in repository
        or len(digest) != 64
        or digest == "0" * 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise OrchestrationError(f"{field} must contain a real lowercase SHA-256 digest")
    return image


def _azure_resource_id(value: object, *, field: str) -> str:
    resource_id = _string(value, field=field)
    segments = [segment for segment in resource_id.split("/") if segment]
    if (
        len(segments) < 8
        or segments[0].casefold() != "subscriptions"
        or segments[2].casefold() != "resourcegroups"
        or segments[4].casefold() != "providers"
    ):
        raise OrchestrationError(f"{field} must be a complete Azure resource ID")
    return resource_id


def _job_resource_id(value: object, *, field: str) -> str:
    resource_id = _azure_resource_id(value, field=field)
    segments = [segment for segment in resource_id.split("/") if segment]
    if (
        len(segments) != 8
        or segments[5].casefold() != "microsoft.app"
        or segments[6].casefold() != "jobs"
    ):
        raise OrchestrationError(f"{field} must identify one Microsoft.App/jobs resource")
    return resource_id


def _resource_subscription_and_group(resource_id: str) -> tuple[str, str]:
    segments = [segment for segment in resource_id.split("/") if segment]
    return segments[1], segments[3]


def _require_resource_id_equal(
    actual: object,
    expected: object,
    *,
    field: str,
) -> None:
    actual_id = _azure_resource_id(actual, field=f"{field} actual")
    expected_id = _azure_resource_id(expected, field=f"{field} expected")
    if actual_id.casefold() != expected_id.casefold():
        raise OrchestrationError(f"{field} does not match its authoritative handoff")


def _require_subscription_resource_id_equal(
    actual: object,
    expected: object,
    *,
    subscription_id: str,
    field: str,
) -> None:
    actual_id = _canonical_subscription_resource_id(
        actual,
        subscription_id=subscription_id,
        field=f"{field} actual",
    )
    expected_id = _canonical_subscription_resource_id(
        expected,
        subscription_id=subscription_id,
        field=f"{field} expected",
    )
    if actual_id.casefold() != expected_id.casefold():
        raise OrchestrationError(f"{field} does not match its exact intended value")


def _write_new_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical_json_bytes(value).decode("utf-8"))
            handle.write("\n")
    except FileExistsError as exc:
        raise OrchestrationError(f"refusing to overwrite immutable evidence {path}") from exc


def _load_parameters(path: Path) -> dict[str, dict[str, object]]:
    document = _mapping(_read_json(path), field="parameter document")
    parameters = _mapping(document.get("parameters"), field="parameters")
    normalized: dict[str, dict[str, object]] = {}
    for name, raw_entry in parameters.items():
        entry = _mapping(raw_entry, field=f"parameters.{name}")
        if set(entry) != {"value"}:
            raise OrchestrationError(f"parameters.{name} must contain exactly one value property")
        normalized[name] = {"value": entry["value"]}
    return normalized


def _parameter_value(
    parameters: Mapping[str, Mapping[str, object]],
    name: str,
) -> object:
    try:
        return parameters[name]["value"]
    except KeyError as exc:
        raise OrchestrationError(f"required deployment parameter is absent: {name}") from exc


def _set_parameter(
    parameters: dict[str, dict[str, object]],
    name: str,
    value: object,
) -> None:
    parameters[name] = {"value": value}


def _foundation_parameter_digest(
    parameters: Mapping[str, Mapping[str, object]],
) -> str:
    values = {
        name: entry["value"]
        for name, entry in sorted(parameters.items())
        if name not in WC027_ACCEPTANCE_PARAMETER_NAMES
    }
    return _sha256_bytes(_canonical_json_bytes(values))


def _require_equal(actual: object, expected: object, *, field: str) -> None:
    if actual != expected:
        raise OrchestrationError(f"{field} does not match its authoritative foundation handoff")


def _require_absent_or_empty(value: object, *, field: str) -> None:
    if value not in (None, "", [], {}):
        raise OrchestrationError(f"{field} must be absent or empty")


def _resource_name(resource_id: str) -> str:
    parts = resource_id.rstrip("/").split("/")
    if len(parts) < 2:
        raise OrchestrationError(f"invalid Azure resource ID: {resource_id}")
    return parts[-1]


def _key_name(versioned_key_uri: str) -> str:
    segments = [segment for segment in urlparse(versioned_key_uri).path.split("/") if segment]
    if len(segments) != 3 or segments[0].casefold() != "keys" or not segments[2]:
        raise OrchestrationError(
            f"expected an exact versioned Key Vault key URI: {versioned_key_uri}"
        )
    return segments[1]


def _digest_json_string(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _load_handoff(path: Path, *, expected_stage: str) -> dict[str, Any]:
    handoff = _mapping(_read_json(path), field="handoff")
    _require_exact_fields(handoff, HANDOFF_FIELDS, field="deployment handoff")
    if handoff.get("schemaVersion") != HANDOFF_SCHEMA_VERSION:
        raise OrchestrationError("unsupported WC-029 deployment handoff schema")
    if handoff.get("stage") != expected_stage:
        raise OrchestrationError(
            f"expected {expected_stage} handoff, found {handoff.get('stage')!r}"
        )
    if handoff.get("sourceCommit") != SOURCE_COMMIT:
        raise OrchestrationError(
            "deployment handoffs must be produced from the current exact source commit"
        )
    handoff_subscription = _canonical_subscription_id(
        handoff.get("subscriptionId"),
        field="handoff.subscriptionId",
    )
    resource_group = handoff.get("resourceGroup")
    if expected_stage in {"producer", "publisher"}:
        _string(resource_group, field="handoff.resourceGroup")
    elif resource_group is not None:
        raise OrchestrationError(f"{expected_stage} handoff must use subscription deployment scope")
    _string(handoff.get("deploymentName"), field="handoff.deploymentName")
    _sha256_digest(
        handoff.get("planManifestSha256"),
        field="handoff.planManifestSha256",
    )
    predecessor_receipt_hashes = _mapping(
        handoff.get("predecessorReceiptSha256s"),
        field="handoff.predecessorReceiptSha256s",
    )
    expected_predecessors = frozenset(EXPECTED_PREDECESSOR_STAGES[expected_stage])
    _require_exact_fields(
        predecessor_receipt_hashes,
        expected_predecessors,
        field="handoff predecessor receipt hashes",
    )
    for predecessor_stage, digest in predecessor_receipt_hashes.items():
        _sha256_digest(
            digest,
            field=f"handoff predecessor receipt {predecessor_stage}",
        )
    outputs = _mapping(handoff.get("outputs"), field="handoff.outputs")
    _validate_subscription_boundary(
        outputs,
        subscription_id=handoff_subscription,
        field="handoff.outputs",
    )
    expected_digest = _sha256_digest(
        handoff.get("outputsSha256"),
        field="handoff.outputsSha256",
    )
    if _sha256_bytes(_canonical_json_bytes(outputs)) != expected_digest:
        raise OrchestrationError("handoff outputs digest does not match")
    parameter_bindings = _mapping(
        handoff.get("parameterBindings", {}),
        field="handoff.parameterBindings",
    )
    _validate_subscription_boundary(
        parameter_bindings,
        subscription_id=handoff_subscription,
        field="handoff.parameterBindings",
    )
    expected_binding_fields = {
        "foundation": FOUNDATION_BINDING_FIELDS,
        "producer": PRODUCER_BINDING_FIELDS,
        "publisher": PUBLISHER_BINDING_FIELDS,
        "live-acceptance": frozenset(),
    }.get(expected_stage)
    if expected_binding_fields is not None:
        _require_exact_fields(
            parameter_bindings,
            expected_binding_fields,
            field=f"{expected_stage} handoff parameter bindings",
        )
    bindings_digest = _sha256_digest(
        handoff.get("parameterBindingsSha256"),
        field="handoff.parameterBindingsSha256",
    )
    if _sha256_bytes(_canonical_json_bytes(parameter_bindings)) != bindings_digest:
        raise OrchestrationError("handoff parameter bindings digest does not match")
    if expected_stage == "foundation":
        _foundation_outputs(handoff, require_exact=True)
    elif expected_stage == "producer":
        _producer_outputs(handoff)
    elif expected_stage == "publisher":
        _publisher_outputs(handoff)
    elif expected_stage == "live-acceptance":
        _validate_live_acceptance_handoff_outputs(outputs)
    return handoff


def _handoff_bindings(handoff: Mapping[str, object]) -> dict[str, Any]:
    return _mapping(
        handoff.get("parameterBindings", {}),
        field="handoff.parameterBindings",
    )


def _verify_handoff_scope(
    handoff: Mapping[str, object],
    *,
    subscription_id: str,
    resource_group: str | None = None,
) -> None:
    governed_subscription = _canonical_subscription_id(
        subscription_id,
        field="governed subscription",
    )
    handoff_subscription = _canonical_subscription_id(
        handoff.get("subscriptionId"),
        field="handoff.subscriptionId",
    )
    if handoff_subscription != governed_subscription:
        raise OrchestrationError("deployment handoff subscription does not match the current stage")
    if resource_group is not None:
        handoff_resource_group = _string(
            handoff.get("resourceGroup"),
            field="handoff.resourceGroup",
        )
        if handoff_resource_group.casefold() != resource_group.casefold():
            raise OrchestrationError(
                "deployment handoff resource group does not match the current stage"
            )


def _validate_stage_inputs(
    *,
    stage: str,
    resource_group: str | None,
    foundation_handoff_path: Path | None,
    producer_handoff_path: Path | None,
    publisher_handoff_path: Path | None,
) -> None:
    expected_handoffs = {
        "foundation": (False, False, False),
        "producer": (True, False, False),
        "publisher": (True, True, False),
        "live-acceptance": (True, True, True),
    }
    try:
        expected = expected_handoffs[stage]
    except KeyError as exc:
        raise OrchestrationError(f"unsupported deployment stage: {stage}") from exc
    actual = (
        foundation_handoff_path is not None,
        producer_handoff_path is not None,
        publisher_handoff_path is not None,
    )
    if actual != expected:
        raise OrchestrationError(f"{stage} requires exactly the governed predecessor handoffs")
    if stage in SUBSCRIPTION_STAGES:
        if resource_group is not None:
            raise OrchestrationError(f"{stage} is subscription-scoped and rejects --resource-group")
    elif not resource_group:
        raise OrchestrationError(f"{stage} requires --resource-group")


def _validate_predecessor_receipt_inputs(
    *,
    stage: str,
    receipt_paths: Mapping[str, Path | None],
    reviewed_receipt_sha256s: Mapping[str, str | None],
) -> None:
    expected = frozenset(EXPECTED_PREDECESSOR_STAGES[stage])
    provided_paths = frozenset(
        predecessor for predecessor, path in receipt_paths.items() if path is not None
    )
    provided_digests = frozenset(
        predecessor
        for predecessor, digest in reviewed_receipt_sha256s.items()
        if digest is not None
    )
    if provided_paths != expected or provided_digests != expected:
        raise OrchestrationError(
            f"{stage} requires the exact predecessor receipt paths and "
            "independently reviewed receipt digests"
        )
    for predecessor in expected:
        _sha256_digest(
            reviewed_receipt_sha256s[predecessor],
            field=f"{predecessor} reviewed receipt SHA-256",
        )


def _ensure_evidence_directory_outside_repository(path: Path) -> None:
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return
    raise OrchestrationError("deployment evidence directory must be outside the repository")


def _load_plan_manifest(
    path: Path,
    *,
    expected_stage: str | None = None,
) -> dict[str, Any]:
    _ensure_evidence_directory_outside_repository(path.parent)
    manifest = _mapping(_read_json(path), field="plan manifest")
    _require_exact_fields(manifest, PLAN_FIELDS, field="plan manifest")
    if manifest.get("schemaVersion") != PLAN_SCHEMA_VERSION:
        raise OrchestrationError("unsupported WC-029 deployment plan schema")
    stage = _string(manifest.get("stage"), field="plan stage")
    if stage not in STAGES or (expected_stage is not None and stage != expected_stage):
        raise OrchestrationError("plan stage does not match the required predecessor stage")
    if manifest.get("sourceCommit") != SOURCE_COMMIT:
        raise OrchestrationError("plan source commit is not the current exact commit")
    subscription_id = _canonical_subscription_id(
        manifest.get("subscriptionId"),
        field="plan subscription",
    )
    resource_group_value = manifest.get("resourceGroup")
    resource_group = (
        None
        if resource_group_value is None
        else _string(resource_group_value, field="plan resource group")
    )
    handoff_paths = {
        predecessor: (
            None
            if manifest.get(f"{predecessor}HandoffPath") is None
            else Path(
                _string(
                    manifest.get(f"{predecessor}HandoffPath"),
                    field=f"plan {predecessor} handoff path",
                )
            )
        )
        for predecessor in ("foundation", "producer", "publisher")
    }
    _validate_stage_inputs(
        stage=stage,
        resource_group=resource_group,
        foundation_handoff_path=handoff_paths["foundation"],
        producer_handoff_path=handoff_paths["producer"],
        publisher_handoff_path=handoff_paths["publisher"],
    )
    expected_template_path = str(TEMPLATES[stage].relative_to(ROOT)).replace(
        "\\",
        "/",
    )
    if manifest.get("templatePath") != expected_template_path:
        raise OrchestrationError("plan template path does not match its exact stage")
    if _sha256_file(TEMPLATES[stage]) != _sha256_digest(
        manifest.get("templateSha256"),
        field="plan template SHA-256",
    ):
        raise OrchestrationError("planned Bicep template changed after review")
    if _sha256_file(Path(__file__).resolve()) != _sha256_digest(
        manifest.get("orchestratorSha256"),
        field="plan orchestrator SHA-256",
    ):
        raise OrchestrationError("orchestrator implementation changed after review")
    if _sha256_file(PREFLIGHT_PATH) != _sha256_digest(
        manifest.get("preflightSha256"),
        field="plan preflight SHA-256",
    ):
        raise OrchestrationError("preflight implementation changed after review")
    base_parameter_path = Path(
        _string(manifest.get("baseParameterPath"), field="plan base parameters")
    )
    effective_parameter_path = Path(
        _string(
            manifest.get("effectiveParameterPath"),
            field="plan effective parameters",
        )
    )
    what_if_path = Path(_string(manifest.get("whatIfPath"), field="plan what-if path"))
    _ensure_evidence_directory_outside_repository(effective_parameter_path.parent)
    _ensure_evidence_directory_outside_repository(what_if_path.parent)
    for artifact_path, digest_field, field in (
        (base_parameter_path, "baseParameterSha256", "base parameter artifact"),
        (
            effective_parameter_path,
            "effectiveParameterSha256",
            "effective parameter artifact",
        ),
        (what_if_path, "whatIfSha256", "what-if artifact"),
    ):
        expected_digest = _sha256_digest(
            manifest.get(digest_field),
            field=f"plan {field} SHA-256",
        )
        if _sha256_file(artifact_path) != expected_digest:
            raise OrchestrationError(f"plan {field} changed after review")
    effective_parameters = _load_parameters(effective_parameter_path)
    _validate_effective_parameter_subscription_boundary(
        effective_parameters,
        subscription_id=subscription_id,
    )
    what_if = _read_json(what_if_path)
    _validate_subscription_boundary(
        what_if,
        subscription_id=subscription_id,
        field="plan what-if",
    )
    raw_allowed_changes = manifest.get("allowedChangeResourceIds")
    if not isinstance(raw_allowed_changes, list) or any(
        not isinstance(item, str) for item in raw_allowed_changes
    ):
        raise OrchestrationError("plan allowed changes must be a string array")
    allowed_changes = [
        _canonical_subscription_resource_id(
            resource_id,
            subscription_id=subscription_id,
            field=f"plan allowed changes[{index}]",
        )
        for index, resource_id in enumerate(raw_allowed_changes)
    ]
    if allowed_changes != sorted(allowed_changes) or len(
        {item.casefold() for item in allowed_changes}
    ) != len(allowed_changes):
        raise OrchestrationError("plan allowed change resource IDs must be sorted and distinct")
    violations = evaluate_what_if(
        what_if,
        allowed_change_ids=frozenset(allowed_changes),
    )
    if violations:
        raise OrchestrationError("predecessor plan what-if no longer passes")
    predecessor_receipts = _mapping(
        manifest.get("predecessorReceipts"),
        field="plan predecessor receipts",
    )
    expected_predecessors = frozenset(EXPECTED_PREDECESSOR_STAGES[stage])
    _require_exact_fields(
        predecessor_receipts,
        expected_predecessors,
        field="plan predecessor receipts",
    )
    for predecessor, raw_reference in predecessor_receipts.items():
        reference = _mapping(
            raw_reference,
            field=f"plan predecessor receipt {predecessor}",
        )
        _require_exact_fields(
            reference,
            PREDECESSOR_RECEIPT_REFERENCE_FIELDS,
            field=f"plan predecessor receipt {predecessor}",
        )
        _string(reference.get("path"), field=f"{predecessor} receipt path")
        actual_digest = _sha256_digest(
            reference.get("sha256"),
            field=f"{predecessor} receipt SHA-256",
        )
        reviewed_digest = _sha256_digest(
            reference.get("reviewedSha256"),
            field=f"{predecessor} reviewed receipt SHA-256",
        )
        if actual_digest != reviewed_digest:
            raise OrchestrationError(f"{predecessor} receipt digest was not independently approved")
    for predecessor in ("foundation", "producer", "publisher"):
        handoff_path = handoff_paths[predecessor]
        handoff_digest_value = manifest.get(f"{predecessor}HandoffSha256")
        if handoff_path is None:
            if handoff_digest_value is not None:
                raise OrchestrationError(f"plan {predecessor} handoff digest has no path")
            continue
        handoff_digest = _sha256_digest(
            handoff_digest_value,
            field=f"plan {predecessor} handoff SHA-256",
        )
        if _sha256_file(handoff_path) != handoff_digest:
            raise OrchestrationError(f"plan {predecessor} handoff changed after review")
    _string(manifest.get("location"), field="plan location")
    _string(manifest.get("deploymentName"), field="plan deployment name")
    return manifest


def _load_verified_predecessor(
    *,
    expected_stage: str,
    handoff_path: Path,
    receipt_path: Path,
    reviewed_receipt_sha256: str,
) -> dict[str, Any]:
    for artifact in (handoff_path, receipt_path):
        _ensure_evidence_directory_outside_repository(artifact.parent)
    reviewed_digest = _sha256_digest(
        reviewed_receipt_sha256,
        field=f"{expected_stage} reviewed receipt SHA-256",
    )
    actual_receipt_digest = _sha256_file(receipt_path)
    if actual_receipt_digest != reviewed_digest:
        raise OrchestrationError(
            f"{expected_stage} receipt does not match its trusted approval digest"
        )
    receipt = _mapping(_read_json(receipt_path), field=f"{expected_stage} receipt")
    _require_exact_fields(receipt, RECEIPT_FIELDS, field=f"{expected_stage} receipt")
    if receipt.get("schemaVersion") != RECEIPT_SCHEMA_VERSION:
        raise OrchestrationError("unsupported WC-029 deployment receipt schema")
    if receipt.get("stage") != expected_stage:
        raise OrchestrationError(
            f"expected {expected_stage} receipt, found {receipt.get('stage')!r}"
        )
    if receipt.get("sourceCommit") != SOURCE_COMMIT:
        raise OrchestrationError(
            "deployment receipt must be produced from the current exact source commit"
        )
    plan_path = Path(
        _string(
            receipt.get("planManifestPath"),
            field=f"{expected_stage} receipt plan path",
        )
    )
    _ensure_evidence_directory_outside_repository(plan_path.parent)
    receipt_handoff_path = Path(
        _string(
            receipt.get("handoffPath"),
            field=f"{expected_stage} receipt handoff path",
        )
    )
    if plan_path.resolve() == receipt_path.resolve():
        raise OrchestrationError("deployment receipt cannot be its own plan artifact")
    if receipt_handoff_path.resolve() != handoff_path.resolve():
        raise OrchestrationError(
            f"{expected_stage} handoff path does not match its approved receipt"
        )
    plan_digest = _sha256_digest(
        receipt.get("planManifestSha256"),
        field=f"{expected_stage} receipt plan SHA-256",
    )
    reviewed_plan_digest = _sha256_digest(
        receipt.get("reviewedPlanSha256"),
        field=f"{expected_stage} reviewed plan SHA-256",
    )
    if plan_digest != reviewed_plan_digest or _sha256_file(plan_path) != plan_digest:
        raise OrchestrationError(
            f"{expected_stage} receipt does not prove an independently reviewed plan"
        )
    handoff_digest = _sha256_digest(
        receipt.get("handoffSha256"),
        field=f"{expected_stage} receipt handoff SHA-256",
    )
    if _sha256_file(handoff_path) != handoff_digest:
        raise OrchestrationError(f"{expected_stage} handoff does not match its deployment receipt")
    plan = _load_plan_manifest(plan_path, expected_stage=expected_stage)
    handoff = _load_handoff(handoff_path, expected_stage=expected_stage)
    receipt_subscription = _canonical_subscription_id(
        receipt.get("subscriptionId"),
        field=f"{expected_stage} receipt subscription",
    )
    for document_name, document in (("plan", plan), ("handoff", handoff)):
        if (
            document.get("stage") != expected_stage
            or document.get("sourceCommit") != SOURCE_COMMIT
            or document.get("subscriptionId") != receipt_subscription
            or document.get("resourceGroup") != receipt.get("resourceGroup")
            or document.get("deploymentName") != receipt.get("deploymentName")
        ):
            raise OrchestrationError(
                f"{expected_stage} {document_name} does not match its receipt scope"
            )
    if handoff.get("planManifestSha256") != plan_digest:
        raise OrchestrationError(f"{expected_stage} handoff is not bound to its reviewed plan")
    receipt_predecessors = _mapping(
        receipt.get("predecessorReceiptSha256s"),
        field=f"{expected_stage} receipt predecessor hashes",
    )
    expected_predecessors = frozenset(EXPECTED_PREDECESSOR_STAGES[expected_stage])
    _require_exact_fields(
        receipt_predecessors,
        expected_predecessors,
        field=f"{expected_stage} receipt predecessor hashes",
    )
    for predecessor, digest in receipt_predecessors.items():
        _sha256_digest(
            digest,
            field=f"{expected_stage} predecessor receipt {predecessor}",
        )
    if handoff.get("predecessorReceiptSha256s") != receipt_predecessors:
        raise OrchestrationError(
            f"{expected_stage} handoff predecessor receipt chain does not match"
        )
    plan_predecessors = _mapping(
        plan.get("predecessorReceipts"),
        field=f"{expected_stage} plan predecessor receipts",
    )
    plan_predecessor_hashes = {
        predecessor: _mapping(
            reference,
            field=f"{expected_stage} plan predecessor {predecessor}",
        ).get("sha256")
        for predecessor, reference in plan_predecessors.items()
    }
    if plan_predecessor_hashes != receipt_predecessors:
        raise OrchestrationError(f"{expected_stage} plan predecessor receipt chain does not match")
    return {
        "handoff": handoff,
        "handoffPath": handoff_path.resolve(),
        "handoffSha256": handoff_digest,
        "plan": plan,
        "planPath": plan_path.resolve(),
        "receipt": receipt,
        "receiptPath": receipt_path.resolve(),
        "receiptSha256": actual_receipt_digest,
        "reviewedReceiptSha256": reviewed_digest,
    }


def _load_verified_predecessors(
    *,
    stage: str,
    handoff_paths: Mapping[str, Path | None],
    receipt_paths: Mapping[str, Path | None],
    reviewed_receipt_sha256s: Mapping[str, str | None],
) -> dict[str, dict[str, Any]]:
    _validate_predecessor_receipt_inputs(
        stage=stage,
        receipt_paths=receipt_paths,
        reviewed_receipt_sha256s=reviewed_receipt_sha256s,
    )
    verified: dict[str, dict[str, Any]] = {}
    expected = EXPECTED_PREDECESSOR_STAGES[stage]
    for predecessor in expected:
        handoff_path = handoff_paths[predecessor]
        receipt_path = receipt_paths[predecessor]
        reviewed_digest = reviewed_receipt_sha256s[predecessor]
        if handoff_path is None or receipt_path is None or reviewed_digest is None:
            raise OrchestrationError(f"{stage} predecessor receipt inputs are incomplete")
        record = _load_verified_predecessor(
            expected_stage=predecessor,
            handoff_path=handoff_path,
            receipt_path=receipt_path,
            reviewed_receipt_sha256=reviewed_digest,
        )
        expected_prior_hashes = {
            prior: verified[prior]["receiptSha256"]
            for prior in EXPECTED_PREDECESSOR_STAGES[predecessor]
        }
        receipt = _mapping(
            record["receipt"],
            field=f"{predecessor} receipt",
        )
        if receipt.get("predecessorReceiptSha256s") != expected_prior_hashes:
            raise OrchestrationError(
                f"{predecessor} receipt does not preserve the exact approval chain"
            )
        plan = _mapping(record["plan"], field=f"{predecessor} plan")
        plan_references = _mapping(
            plan.get("predecessorReceipts"),
            field=f"{predecessor} plan predecessor receipts",
        )
        for prior, prior_record in verified.items():
            reference = _mapping(
                plan_references.get(prior),
                field=f"{predecessor} plan predecessor {prior}",
            )
            if (
                Path(_string(reference.get("path"), field="receipt path")).resolve()
                != prior_record["receiptPath"]
                or reference.get("sha256") != prior_record["receiptSha256"]
                or reference.get("reviewedSha256") != prior_record["reviewedReceiptSha256"]
                or Path(
                    _string(
                        plan.get(f"{prior}HandoffPath"),
                        field=f"{prior} handoff path",
                    )
                ).resolve()
                != prior_record["handoffPath"]
                or plan.get(f"{prior}HandoffSha256") != prior_record["handoffSha256"]
            ):
                raise OrchestrationError(
                    f"{predecessor} plan does not preserve the exact {prior} chain"
                )
        verified[predecessor] = record
    return verified


def _predecessor_receipt_references(
    verified: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    return {
        stage: {
            "path": str(record["receiptPath"]),
            "sha256": record["receiptSha256"],
            "reviewedSha256": record["reviewedReceiptSha256"],
        }
        for stage, record in verified.items()
    }


def _predecessor_receipt_hashes(
    verified: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    return {stage: record["receiptSha256"] for stage, record in verified.items()}


def _foundation_outputs(
    handoff: Mapping[str, object],
    *,
    require_exact: bool = False,
) -> dict[str, Any]:
    outputs = _mapping(handoff.get("outputs"), field="foundation outputs")
    if require_exact:
        _require_exact_fields(
            outputs,
            FOUNDATION_OUTPUT_FIELDS,
            field="foundation deployment outputs",
        )
    approved_configuration = _mapping(
        outputs.get("wc016ApprovedConfiguration"),
        field="foundation outputs.wc016ApprovedConfiguration",
    )
    if require_exact:
        _require_exact_fields(
            approved_configuration,
            frozenset({"wc027OrchestrationFoundation"}),
            field="foundation approved configuration",
        )
    wc027_foundation = _mapping(
        approved_configuration.get("wc027OrchestrationFoundation"),
        field="foundation WC-027 orchestration outputs",
    )
    _require_exact_fields(
        wc027_foundation,
        FOUNDATION_ORCHESTRATION_FIELDS,
        field="foundation WC-027 orchestration outputs",
    )
    normalized_outputs = dict(outputs)
    normalized_outputs.update(
        {
            "wc016NotificationQueueName": wc027_foundation.get("notificationQueueName"),
            "incidentFeedV2SigningKeyUriWithVersion": wc027_foundation.get(
                "feedSigningKeyUriWithVersion"
            ),
            "incidentReportSigningKeyUriWithVersion": wc027_foundation.get(
                "reportSigningKeyUriWithVersion"
            ),
            "incidentGuidanceSigningKeyUriWithVersion": wc027_foundation.get(
                "guidanceSigningKeyUriWithVersion"
            ),
            "incidentEnrichmentSigningKeyUriWithVersion": wc027_foundation.get(
                "enrichmentSigningKeyUriWithVersion"
            ),
            "incidentNotificationSigningKeyUriWithVersion": wc027_foundation.get(
                "notificationSigningKeyUriWithVersion"
            ),
        }
    )
    required = (
        "managedEnvironmentResourceId",
        "replayStorageAccountResourceId",
        "keyVaultResourceId",
        "incidentAssetContainerResourceId",
        "presentationIdentityResourceId",
        "presentationHttpsUrl",
        "wc016ServiceBusNamespace",
        "wc016NotificationQueueName",
        "incidentSigningKeyUriWithVersion",
        "incidentFeedV2SigningKeyUriWithVersion",
        "incidentReportSigningKeyUriWithVersion",
        "incidentGuidanceSigningKeyUriWithVersion",
        "incidentEnrichmentSigningKeyUriWithVersion",
        "incidentNotificationSigningKeyUriWithVersion",
    )
    for name in required:
        _string(normalized_outputs.get(name), field=f"foundation outputs.{name}")
    resource_output_names = (
        "managedEnvironmentResourceId",
        "replayStorageAccountResourceId",
        "keyVaultResourceId",
        "incidentAssetContainerResourceId",
        "presentationIdentityResourceId",
    )
    for name in resource_output_names:
        resource_id = _azure_resource_id(
            normalized_outputs[name],
            field=f"foundation outputs.{name}",
        )
        if handoff.get("subscriptionId") is not None:
            subscription_id, _ = _resource_subscription_and_group(resource_id)
            if (
                subscription_id.casefold()
                != _string(
                    handoff.get("subscriptionId"),
                    field="foundation handoff subscription",
                ).casefold()
            ):
                raise OrchestrationError(
                    f"foundation output {name} is outside the handoff subscription"
                )
    for name in required[-6:]:
        _key_name(_string(normalized_outputs[name], field=name))
    return normalized_outputs


def _configured_identity_resource_ids(value: object) -> set[str]:
    resource_ids: set[str] = set()

    def visit(item: object) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if key.casefold().endswith("identityresourceid"):
                    resource_ids.add(
                        _azure_resource_id(
                            child,
                            field="configured identity resource ID",
                        ).casefold()
                    )
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return resource_ids


def _producer_outputs(handoff: Mapping[str, object]) -> dict[str, Any]:
    outputs = _mapping(handoff.get("outputs"), field="producer outputs")
    _require_exact_fields(
        outputs,
        PRODUCER_OUTPUT_FIELDS,
        field="producer deployment outputs",
    )
    job_resource_id = _job_resource_id(
        outputs.get("producerJobResourceId"),
        field="producer job",
    )
    if handoff.get("subscriptionId") is not None:
        subscription_id, resource_group = _resource_subscription_and_group(job_resource_id)
        if (
            subscription_id.casefold()
            != _string(
                handoff.get("subscriptionId"),
                field="producer handoff subscription",
            ).casefold()
        ):
            raise OrchestrationError(
                "producer Job subscription does not match its deployment handoff"
            )
        if (
            resource_group.casefold()
            != _string(
                handoff.get("resourceGroup"),
                field="producer handoff resource group",
            ).casefold()
        ):
            raise OrchestrationError(
                "producer Job resource group does not match its deployment handoff"
            )
    _digest_pinned_image(outputs.get("producerImage"), field="producer image")
    configuration_json = _string(
        outputs.get("deployedRuntimeConfigurationJson"),
        field="producer configuration JSON",
    )
    configuration_digest = _sha256_digest(
        outputs.get("deployedRuntimeConfigurationDigest"),
        field="producer configuration digest",
    )
    if _digest_json_string(configuration_json) != configuration_digest:
        raise OrchestrationError(
            "producer configuration digest does not hash the exact deployed JSON"
        )
    try:
        configuration = _mapping(
            json.loads(configuration_json),
            field="producer configuration",
        )
    except json.JSONDecodeError as exc:
        raise OrchestrationError("producer configuration JSON is invalid") from exc
    binding = _mapping(
        configuration.get("deploymentBinding"),
        field="producer deployment binding",
    )
    identities = _string_list(
        binding.get("attachedIdentityResourceIds"),
        field="producer attached identities",
    )
    _require_equal(
        identities,
        _string_list(
            outputs.get("attachedIdentityResourceIds"),
            field="producer output identities",
        ),
        field="producer attached identities",
    )
    configured_identities = _configured_identity_resource_ids(configuration)
    if configured_identities != {identity.casefold() for identity in identities}:
        raise OrchestrationError(
            "producer configuration identities do not match its deployment binding"
        )
    _require_equal(
        _string(binding.get("bindingEvidenceId"), field="producer binding evidence"),
        _string(outputs.get("bindingEvidenceDigest"), field="producer output evidence"),
        field="producer binding evidence",
    )
    service_bus = _mapping(
        configuration.get("serviceBus"),
        field="producer service bus",
    )
    enrichment_assets = _mapping(
        configuration.get("enrichmentFeedAssets"),
        field="producer enrichment/feed assets",
    )
    feed_registry = _mapping(
        configuration.get("feedRegistry"),
        field="producer feed registry",
    )
    guidance_activation = _mapping(
        configuration.get("guidanceActivation"),
        field="producer guidance activation",
    )
    guidance_authority = _mapping(
        configuration.get("guidanceAuthoritySource"),
        field="producer guidance authority",
    )
    _require_equal(
        outputs.get("namespaceHostName"),
        service_bus.get("namespace"),
        field="producer namespace output",
    )
    _require_equal(
        outputs.get("triggerQueueName"),
        service_bus.get("triggerQueueName"),
        field="producer trigger queue output",
    )
    _require_equal(
        outputs.get("notificationQueueName"),
        service_bus.get("notificationQueueName"),
        field="producer notification queue output",
    )
    _require_equal(
        outputs.get("feedV2ContainerName"),
        enrichment_assets.get("containerName"),
        field="producer feed-v2 container output",
    )
    resource_outputs = (
        "triggerQueueResourceId",
        "notificationQueueResourceId",
        "feedV2ContainerResourceId",
        "feedRegistryTableResourceId",
        "guidanceActivationTableResourceId",
        "guidanceAuthoritySourceContainerResourceId",
    )
    for name in resource_outputs:
        _azure_resource_id(outputs.get(name), field=f"producer output {name}")
    namespace_name = _string(
        service_bus.get("namespace"),
        field="producer namespace",
    ).removesuffix(".servicebus.windows.net")
    expected_suffixes = {
        "triggerQueueResourceId": (
            f"/namespaces/{namespace_name}/queues/"
            f"{_string(service_bus.get('triggerQueueName'), field='trigger queue')}"
        ),
        "notificationQueueResourceId": (
            f"/namespaces/{namespace_name}/queues/"
            f"{_string(service_bus.get('notificationQueueName'), field='notification queue')}"
        ),
        "feedV2ContainerResourceId": (
            f"/containers/{_string(enrichment_assets.get('containerName'), field='feed container')}"
        ),
        "feedRegistryTableResourceId": (
            f"/tables/{_string(feed_registry.get('tableName'), field='feed registry table')}"
        ),
        "guidanceActivationTableResourceId": (
            f"/tables/{_string(guidance_activation.get('tableName'), field='activation table')}"
        ),
        "guidanceAuthoritySourceContainerResourceId": (
            "/containers/"
            f"{_string(guidance_authority.get('containerName'), field='authority container')}"
        ),
    }
    for name, suffix in expected_suffixes.items():
        resource_id = _string(outputs[name], field=f"producer output {name}")
        if not resource_id.casefold().endswith(suffix.casefold()):
            raise OrchestrationError(
                f"producer output {name} does not match the deployed configuration"
            )
    return outputs


def _publisher_outputs(handoff: Mapping[str, object]) -> dict[str, Any]:
    outputs = _mapping(handoff.get("outputs"), field="publisher outputs")
    _require_exact_fields(
        outputs,
        PUBLISHER_OUTPUT_FIELDS,
        field="publisher deployment outputs",
    )
    job_resource_id = _job_resource_id(
        outputs.get("publisherJobResourceId"),
        field="publisher job",
    )
    if handoff.get("subscriptionId") is not None:
        subscription_id, resource_group = _resource_subscription_and_group(job_resource_id)
        if (
            subscription_id.casefold()
            != _string(
                handoff.get("subscriptionId"),
                field="publisher handoff subscription",
            ).casefold()
        ):
            raise OrchestrationError(
                "publisher Job subscription does not match its deployment handoff"
            )
        if (
            resource_group.casefold()
            != _string(
                handoff.get("resourceGroup"),
                field="publisher handoff resource group",
            ).casefold()
        ):
            raise OrchestrationError(
                "publisher Job resource group does not match its deployment handoff"
            )
    _digest_pinned_image(outputs.get("publisherImage"), field="publisher image")
    configuration_json = _string(
        outputs.get("deployedPublisherConfigurationJson"),
        field="publisher configuration JSON",
    )
    configuration_digest = _sha256_digest(
        outputs.get("deployedPublisherConfigurationDigest"),
        field="publisher configuration digest",
    )
    if _digest_json_string(configuration_json) != configuration_digest:
        raise OrchestrationError(
            "publisher configuration digest does not hash the exact deployed JSON"
        )
    try:
        configuration = _mapping(
            json.loads(configuration_json),
            field="publisher configuration",
        )
    except json.JSONDecodeError as exc:
        raise OrchestrationError("publisher configuration JSON is invalid") from exc
    binding = _mapping(
        configuration.get("deploymentBinding"),
        field="publisher deployment binding",
    )
    identities = _string_list(
        binding.get("attachedIdentityResourceIds"),
        field="publisher attached identities",
    )
    _require_equal(
        identities,
        _string_list(
            outputs.get("attachedIdentityResourceIds"),
            field="publisher output identities",
        ),
        field="publisher attached identities",
    )
    _require_equal(
        _string(binding.get("bindingEvidenceId"), field="publisher binding evidence"),
        _string(outputs.get("bindingEvidenceDigest"), field="publisher output evidence"),
        field="publisher binding evidence",
    )
    service_bus = _mapping(
        configuration.get("serviceBus"),
        field="publisher service bus",
    )
    authority_assets = _mapping(
        configuration.get("authorityAssets"),
        field="publisher authority assets",
    )
    guidance_activation = _mapping(
        configuration.get("guidanceActivation"),
        field="publisher guidance activation",
    )
    binding_key = _mapping(
        configuration.get("bindingSigningKey"),
        field="publisher binding key",
    )
    _require_equal(
        outputs.get("requestQueueName"),
        service_bus.get("requestQueueName"),
        field="publisher request queue output",
    )
    _require_equal(
        outputs.get("authorityContainerName"),
        authority_assets.get("containerName"),
        field="publisher authority container output",
    )
    _require_equal(
        outputs.get("activationTableName"),
        guidance_activation.get("tableName"),
        field="publisher activation table output",
    )
    _require_equal(
        outputs.get("bindingLogicalKeyId"),
        binding_key.get("keyId"),
        field="publisher binding logical key output",
    )
    _require_equal(
        outputs.get("bindingKeyVaultKeyId"),
        binding_key.get("keyVaultKeyId"),
        field="publisher binding key version output",
    )
    for name in (
        "requestQueueResourceId",
        "triggerQueueResourceId",
        "authorityContainerResourceId",
        "activationTableResourceId",
        "bindingKeyResourceId",
    ):
        _azure_resource_id(outputs.get(name), field=f"publisher output {name}")
    namespace_name = _string(
        service_bus.get("namespace"),
        field="publisher namespace",
    ).removesuffix(".servicebus.windows.net")
    expected_suffixes = {
        "requestQueueResourceId": (
            f"/namespaces/{namespace_name}/queues/"
            f"{_string(service_bus.get('requestQueueName'), field='request queue')}"
        ),
        "triggerQueueResourceId": (
            f"/namespaces/{namespace_name}/queues/"
            f"{_string(service_bus.get('triggerQueueName'), field='trigger queue')}"
        ),
        "authorityContainerResourceId": (
            "/containers/"
            f"{_string(authority_assets.get('containerName'), field='authority container')}"
        ),
        "activationTableResourceId": (
            f"/tables/{_string(guidance_activation.get('tableName'), field='activation table')}"
        ),
    }
    for name, suffix in expected_suffixes.items():
        resource_id = _string(outputs[name], field=f"publisher output {name}")
        if not resource_id.casefold().endswith(suffix.casefold()):
            raise OrchestrationError(
                f"publisher output {name} does not match the deployed configuration"
            )
    return outputs


def _foundation_parameters(
    parameters: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    if _parameter_value(parameters, "wc016RuntimeEnabled") is not True:
        raise OrchestrationError(
            "foundation deployment must enable WC-016 so the private broker exists"
        )
    if _parameter_value(parameters, "wc016LegacyCleanupConfirmed") is not True:
        raise OrchestrationError(
            "foundation deployment requires confirmed zero-residual WC-016 cleanup"
        )
    for name, value in (
        ("wc027FeedV2ProducerReady", False),
        ("wc027EnrichmentFeedProducerJobResourceId", ""),
        ("wc027EnrichmentFeedProducerConfigurationDigest", ""),
        ("wc027EnrichmentFeedProducerConfigurationJson", ""),
        ("wc027EnrichmentFeedProducerImage", ""),
        ("wc027PublisherReady", False),
        ("wc027PublisherJobResourceId", ""),
        ("wc027PublisherConfigurationDigest", ""),
        ("wc027PublisherConfigurationJson", ""),
        ("wc027PublisherImage", ""),
    ):
        _set_parameter(parameters, name, value)
    return parameters


def _producer_parameters(
    parameters: dict[str, dict[str, object]],
    foundation: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    outputs = _foundation_outputs(foundation)
    service_bus_host = _string(outputs["wc016ServiceBusNamespace"], field="broker")
    expected = {
        "managedEnvironmentResourceId": outputs["managedEnvironmentResourceId"],
        "replayStorageAccountName": _resource_name(
            _string(outputs["replayStorageAccountResourceId"], field="replay storage")
        ),
        "serviceBusNamespaceName": service_bus_host.removesuffix(".servicebus.windows.net"),
        "notificationQueueName": outputs["wc016NotificationQueueName"],
        "incidentAssetContainerName": _resource_name(
            _string(
                outputs["incidentAssetContainerResourceId"],
                field="incident container",
            )
        ),
        "feedV2ReaderIdentityResourceId": outputs["presentationIdentityResourceId"],
        "presentationUrl": outputs["presentationHttpsUrl"],
        "keyVaultName": _resource_name(_string(outputs["keyVaultResourceId"], field="key vault")),
        "incidentSigningKeyName": _key_name(
            _string(outputs["incidentSigningKeyUriWithVersion"], field="incident key")
        ),
        "feedSigningKeyName": _key_name(
            _string(outputs["incidentFeedV2SigningKeyUriWithVersion"], field="feed key")
        ),
        "reportSigningKeyName": _key_name(
            _string(outputs["incidentReportSigningKeyUriWithVersion"], field="report key")
        ),
        "guidanceSigningKeyName": _key_name(
            _string(
                outputs["incidentGuidanceSigningKeyUriWithVersion"],
                field="guidance key",
            )
        ),
        "enrichmentSigningKeyName": _key_name(
            _string(
                outputs["incidentEnrichmentSigningKeyUriWithVersion"],
                field="enrichment key",
            )
        ),
        "notificationSigningKeyName": _key_name(
            _string(
                outputs["incidentNotificationSigningKeyUriWithVersion"],
                field="notification key",
            )
        ),
    }
    for name, value in expected.items():
        _require_equal(_parameter_value(parameters, name), value, field=name)
    return parameters


def _publisher_parameters(
    parameters: dict[str, dict[str, object]],
    foundation: Mapping[str, object],
    producer: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    foundation_values = _foundation_outputs(foundation)
    outputs = _producer_outputs(producer)
    producer_bindings = _handoff_bindings(producer)
    producer_configuration = _mapping(
        json.loads(
            _string(
                outputs["deployedRuntimeConfigurationJson"],
                field="producer configuration",
            )
        ),
        field="producer configuration",
    )
    service_bus = _mapping(
        producer_configuration.get("serviceBus"),
        field="producer service bus",
    )
    namespace_host = _string(
        service_bus.get("namespace"),
        field="producer service bus namespace",
    )
    incident_assets = _mapping(
        producer_configuration.get("incidentLifecycleAssets"),
        field="producer incident assets",
    )
    correlation_sources = _mapping(
        producer_configuration.get("correlationSources"),
        field="producer correlation sources",
    )
    keys = _mapping(producer_configuration.get("keys"), field="producer keys")
    monitoring_collector_key = _mapping(
        producer_configuration.get("monitoringCollectorKey"),
        field="producer monitoring collector key",
    )
    guidance_binding_key = _mapping(
        keys.get("guidanceBinding"),
        field="producer guidance binding key",
    )
    broker_identity_resource_id = _azure_resource_id(
        service_bus.get("brokerIdentityResourceId"),
        field="producer broker identity",
    )
    binding_trust_identity_resource_id = _string(
        guidance_binding_key.get("identityResourceId"),
        field="producer guidance binding trust identity",
    )
    binding_logical_key_id = _string(
        guidance_binding_key.get("keyId"),
        field="producer guidance binding logical key ID",
    )
    binding_key_fingerprint = _sha256_digest(
        guidance_binding_key.get("keyFingerprint"),
        field="producer guidance binding key fingerprint",
    )
    source_candidates = [
        incident_assets.get("identityResourceId"),
        *(
            _mapping(correlation_sources.get(name), field=f"producer {name} source").get(
                "identityResourceId"
            )
            for name in ("monitoring", "change", "contextAuthority", "monitoringIntent")
        ),
        monitoring_collector_key.get("identityResourceId"),
        *(
            _mapping(keys.get(name), field=f"producer key {name}").get("identityResourceId")
            for name in (
                "incident",
                "correlationBinding",
                "guidanceBinding",
                "change",
                "monitoringIntent",
            )
        ),
    ]
    source_identity_resource_ids: list[str] = []
    seen_source_identities: set[str] = set()
    for index, candidate in enumerate(source_candidates):
        identity_resource_id = _string(
            candidate,
            field=f"producer source identity {index}",
        )
        normalized = identity_resource_id.casefold()
        if (
            normalized != binding_trust_identity_resource_id.casefold()
            and normalized not in seen_source_identities
        ):
            seen_source_identities.add(normalized)
            source_identity_resource_ids.append(identity_resource_id)
    _set_parameter(
        parameters,
        "managedEnvironmentResourceId",
        foundation_values["managedEnvironmentResourceId"],
    )
    _set_parameter(
        parameters,
        "activationStorageAccountResourceId",
        foundation_values["replayStorageAccountResourceId"],
    )
    _set_parameter(
        parameters,
        "authorityStorageAccountResourceId",
        _azure_resource_id(
            producer_bindings.get("correlationSourceStorageAccountResourceId"),
            field="producer correlation storage binding",
        ),
    )
    _set_parameter(
        parameters,
        "serviceBusNamespaceName",
        namespace_host.removesuffix(".servicebus.windows.net"),
    )
    _set_parameter(
        parameters,
        "brokerIdentityResourceId",
        broker_identity_resource_id,
    )
    _set_parameter(
        parameters,
        "sourceIdentityResourceIds",
        source_identity_resource_ids,
    )
    _set_parameter(
        parameters,
        "bindingTrustReaderIdentityResourceId",
        binding_trust_identity_resource_id,
    )
    _set_parameter(
        parameters,
        "bindingKeyResourceId",
        _azure_resource_id(
            producer_bindings.get("guidanceBindingKeyResourceId"),
            field="producer guidance-binding key resource",
        ),
    )
    _set_parameter(
        parameters,
        "bindingLogicalKeyId",
        binding_logical_key_id,
    )
    _set_parameter(
        parameters,
        "bindingKeyFingerprint",
        binding_key_fingerprint,
    )
    _set_parameter(
        parameters,
        "enrichmentRuntimeConfigurationJson",
        outputs["deployedRuntimeConfigurationJson"],
    )
    _set_parameter(
        parameters,
        "enrichmentRuntimeConfigurationDigest",
        outputs["deployedRuntimeConfigurationDigest"],
    )
    return parameters


def _acceptance_parameters(
    parameters: dict[str, dict[str, object]],
    foundation: Mapping[str, object],
    producer: Mapping[str, object],
    publisher: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    foundation_bindings = _handoff_bindings(foundation)
    if not foundation_bindings:
        raise OrchestrationError(
            "foundation handoff is missing its exact effective parameter binding"
        )
    _require_exact_fields(
        foundation_bindings,
        FOUNDATION_BINDING_FIELDS,
        field="foundation handoff parameter bindings",
    )
    _require_equal(
        _foundation_parameter_digest(parameters),
        _sha256_digest(
            foundation_bindings.get("foundationParametersSha256"),
            field="foundation parameter binding digest",
        ),
        field="live-acceptance foundation parameters",
    )
    producer_outputs = _producer_outputs(producer)
    publisher_outputs = _publisher_outputs(publisher)
    publisher_configuration = _mapping(
        json.loads(
            _string(
                publisher_outputs["deployedPublisherConfigurationJson"],
                field="publisher configuration",
            )
        ),
        field="publisher configuration",
    )
    producer_configuration = json.loads(
        _string(
            producer_outputs["deployedRuntimeConfigurationJson"],
            field="producer configuration",
        )
    )
    _require_equal(
        publisher_configuration.get("enrichmentRuntimeConfiguration"),
        producer_configuration,
        field="publisher embedded producer configuration",
    )
    for name, value in (
        ("wc027FeedV2ProducerReady", True),
        (
            "wc027EnrichmentFeedProducerJobResourceId",
            producer_outputs["producerJobResourceId"],
        ),
        (
            "wc027EnrichmentFeedProducerConfigurationDigest",
            producer_outputs["deployedRuntimeConfigurationDigest"],
        ),
        (
            "wc027EnrichmentFeedProducerConfigurationJson",
            producer_outputs["deployedRuntimeConfigurationJson"],
        ),
        ("wc027EnrichmentFeedProducerImage", producer_outputs["producerImage"]),
        ("wc027PublisherReady", True),
        ("wc027PublisherJobResourceId", publisher_outputs["publisherJobResourceId"]),
        (
            "wc027PublisherConfigurationDigest",
            publisher_outputs["deployedPublisherConfigurationDigest"],
        ),
        (
            "wc027PublisherConfigurationJson",
            publisher_outputs["deployedPublisherConfigurationJson"],
        ),
        ("wc027PublisherImage", publisher_outputs["publisherImage"]),
    ):
        _set_parameter(parameters, name, value)
    return parameters


def build_effective_parameters(
    *,
    stage: str,
    parameter_path: Path,
    foundation_handoff_path: Path | None = None,
    producer_handoff_path: Path | None = None,
    publisher_handoff_path: Path | None = None,
) -> dict[str, dict[str, object]]:
    parameters = _load_parameters(parameter_path)
    if stage == "foundation":
        return _foundation_parameters(parameters)
    if stage == "producer":
        if foundation_handoff_path is None:
            raise OrchestrationError("producer stage requires a foundation handoff")
        return _producer_parameters(
            parameters,
            _load_handoff(foundation_handoff_path, expected_stage="foundation"),
        )
    if stage == "publisher":
        if foundation_handoff_path is None or producer_handoff_path is None:
            raise OrchestrationError("publisher stage requires foundation and producer handoffs")
        return _publisher_parameters(
            parameters,
            _load_handoff(foundation_handoff_path, expected_stage="foundation"),
            _load_handoff(producer_handoff_path, expected_stage="producer"),
        )
    if stage == "live-acceptance":
        if (
            foundation_handoff_path is None
            or producer_handoff_path is None
            or publisher_handoff_path is None
        ):
            raise OrchestrationError(
                "live-acceptance requires foundation, producer, and publisher handoffs"
            )
        return _acceptance_parameters(
            parameters,
            _load_handoff(foundation_handoff_path, expected_stage="foundation"),
            _load_handoff(producer_handoff_path, expected_stage="producer"),
            _load_handoff(publisher_handoff_path, expected_stage="publisher"),
        )
    raise OrchestrationError(f"unsupported deployment stage: {stage}")


def _parameter_document(parameters: Mapping[str, object]) -> dict[str, object]:
    return {
        "$schema": (
            "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
        ),
        "contentVersion": "1.0.0.0",
        "parameters": parameters,
    }


def _az_command(
    *,
    operation: str,
    stage: str,
    deployment_name: str,
    subscription_id: str,
    location: str,
    resource_group: str | None,
    parameter_path: Path,
) -> list[str]:
    scope = "sub" if stage in SUBSCRIPTION_STAGES else "group"
    command = ["az", "deployment", scope, operation, "--subscription", subscription_id]
    if scope == "sub":
        command.extend(["--location", location])
    else:
        if not resource_group:
            raise OrchestrationError(f"{stage} requires --resource-group")
        command.extend(["--resource-group", resource_group])
    command.extend(
        [
            "--name",
            deployment_name,
            "--template-file",
            str(TEMPLATES[stage]),
            "--parameters",
            str(parameter_path),
            "--only-show-errors",
            "--output",
            "json",
        ]
    )
    if operation == "what-if":
        command.extend(["--result-format", "FullResourcePayloads", "--no-pretty-print"])
    return command


def _run(command: Sequence[str]) -> str:
    completed = subprocess.run(  # noqa: S603
        list(command),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise OrchestrationError(f"command failed with exit code {completed.returncode}: {detail}")
    return completed.stdout


def _run_json(command: Sequence[str], *, field: str) -> object:
    output = _run(command)
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise OrchestrationError(f"{field} did not return valid JSON") from exc


def _get_resource(resource_id: str, *, subscription_id: str) -> dict[str, Any]:
    governed_subscription_id = _canonical_subscription_id(
        subscription_id,
        field="governed subscription",
    )
    normalized_resource_id = _canonical_subscription_resource_id(
        resource_id,
        subscription_id=governed_subscription_id,
        field="Azure resource ID",
    )
    return _mapping(
        _run_json(
            [
                "az",
                "resource",
                "show",
                "--subscription",
                governed_subscription_id,
                "--ids",
                normalized_resource_id,
                "--only-show-errors",
                "--output",
                "json",
            ],
            field=f"Azure resource {normalized_resource_id}",
        ),
        field=f"Azure resource {normalized_resource_id}",
    )


def _verify_resource(resource_id: str, *, subscription_id: str) -> None:
    resource = _get_resource(resource_id, subscription_id=subscription_id)
    _require_resource_id_equal(
        resource.get("id"),
        resource_id,
        field="Azure resource readback",
    )


def _verify_private_storage_account(
    resource_id: str,
    *,
    subscription_id: str,
) -> None:
    resource = _get_resource(resource_id, subscription_id=subscription_id)
    _require_resource_id_equal(
        resource.get("id"),
        resource_id,
        field="Storage account readback",
    )
    properties = _mapping(
        resource.get("properties"),
        field="Storage account properties",
    )
    if properties.get("allowSharedKeyAccess") is not False:
        raise OrchestrationError("Storage account shared-key access must be disabled")
    if properties.get("allowBlobPublicAccess") is not False:
        raise OrchestrationError("Storage account public Blob access must be disabled")
    if str(properties.get("publicNetworkAccess", "")).casefold() != "disabled":
        raise OrchestrationError("Storage account public network access must be disabled")
    network_acls = _mapping(
        properties.get("networkAcls"),
        field="Storage account network ACLs",
    )
    if str(network_acls.get("defaultAction", "")).casefold() != "deny":
        raise OrchestrationError("Storage account network default action must be Deny")


def _verify_private_blob_container(
    resource_id: str,
    *,
    subscription_id: str,
) -> None:
    resource = _get_resource(resource_id, subscription_id=subscription_id)
    _require_resource_id_equal(
        resource.get("id"),
        resource_id,
        field="Blob container readback",
    )
    properties = _mapping(
        resource.get("properties"),
        field="Blob container properties",
    )
    if str(properties.get("publicAccess", "")).casefold() != "none":
        raise OrchestrationError("Blob container public access must be None")


def _verify_private_key_vault(
    resource_id: str,
    *,
    subscription_id: str,
) -> None:
    resource = _get_resource(resource_id, subscription_id=subscription_id)
    _require_resource_id_equal(
        resource.get("id"),
        resource_id,
        field="Key Vault readback",
    )
    properties = _mapping(resource.get("properties"), field="Key Vault properties")
    if properties.get("enableRbacAuthorization") is not True:
        raise OrchestrationError("Key Vault must use Azure RBAC authorization")
    if str(properties.get("publicNetworkAccess", "")).casefold() != "disabled":
        raise OrchestrationError("Key Vault public network access must be disabled")
    network_acls = _mapping(
        properties.get("networkAcls"),
        field="Key Vault network ACLs",
    )
    if str(network_acls.get("defaultAction", "")).casefold() != "deny":
        raise OrchestrationError("Key Vault network default action must be Deny")


def _verify_private_service_bus_namespace(
    *,
    job_resource_id: str,
    namespace_name: str,
    subscription_id: str,
) -> None:
    namespace_id = (
        f"{_resource_group_scope(job_resource_id)}/providers/"
        f"Microsoft.ServiceBus/namespaces/{namespace_name}"
    )
    namespace = _get_resource(namespace_id, subscription_id=subscription_id)
    _require_resource_id_equal(
        namespace.get("id"),
        namespace_id,
        field="Service Bus namespace readback",
    )
    properties = _mapping(
        namespace.get("properties"),
        field="Service Bus namespace properties",
    )
    if properties.get("disableLocalAuth") is not True:
        raise OrchestrationError("Service Bus local authentication must be disabled")
    if str(properties.get("publicNetworkAccess", "")).casefold() != "disabled":
        raise OrchestrationError("Service Bus public network access must be disabled")
    if str(properties.get("minimumTlsVersion", "")) != "1.2":
        raise OrchestrationError("Service Bus minimum TLS version must be 1.2")
    network_rules_id = f"{namespace_id}/networkRuleSets/default"
    network_rules = _get_resource(
        network_rules_id,
        subscription_id=subscription_id,
    )
    _require_resource_id_equal(
        network_rules.get("id"),
        network_rules_id,
        field="Service Bus network rules readback",
    )
    network_properties = _mapping(
        network_rules.get("properties"),
        field="Service Bus network rule properties",
    )
    if str(network_properties.get("defaultAction", "")).casefold() != "deny":
        raise OrchestrationError("Service Bus network default action must be Deny")
    if str(network_properties.get("publicNetworkAccess", "")).casefold() != "disabled":
        raise OrchestrationError("Service Bus network rules must keep public access disabled")
    if network_properties.get("trustedServiceAccessEnabled") is not False:
        raise OrchestrationError("Service Bus trusted-service network bypass must be disabled")


def _resource_group_scope(resource_id: str) -> str:
    marker = "/providers/"
    if marker.casefold() not in resource_id.casefold():
        raise OrchestrationError(f"resource ID has no provider boundary: {resource_id}")
    index = resource_id.casefold().index(marker.casefold())
    return resource_id[:index]


ACR_PULL_ROLE_ID = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
SERVICE_BUS_DATA_RECEIVER_ROLE_ID = "4f6c0938-94ea-4d52-8e5a-2e02b7ef8e7d"
SERVICE_BUS_DATA_SENDER_ROLE_ID = "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
BLOB_DATA_READER_ROLE_ID = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
TABLE_DATA_CONTRIBUTOR_ROLE_ID = "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"
TABLE_DATA_READER_ROLE_ID = "76199698-9eea-4c19-bc75-cec21354c6b6"
KEY_VAULT_CRYPTO_USER_ROLE_ID = "12338af0-0e69-4776-bea7-57ae8d297424"
BLOB_READ_DATA_ACTION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
BUILT_IN_DATA_ROLE_IDS = frozenset(
    {
        ACR_PULL_ROLE_ID,
        SERVICE_BUS_DATA_RECEIVER_ROLE_ID,
        SERVICE_BUS_DATA_SENDER_ROLE_ID,
        BLOB_DATA_READER_ROLE_ID,
        TABLE_DATA_CONTRIBUTOR_ROLE_ID,
        TABLE_DATA_READER_ROLE_ID,
        KEY_VAULT_CRYPTO_USER_ROLE_ID,
    }
)
BLOB_LIST_DENY_CONDITION = (
    "(!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/"
    "containers/blobs/read'} AND SubOperationMatches{'Blob.List'}))"
)
ALLOWED_CUSTOM_DATA_ACTIONS = frozenset(
    {
        frozenset(
            {
                BLOB_READ_DATA_ACTION,
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
            }
        ),
        frozenset({"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"}),
        frozenset(
            {
                "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read",
                "Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action",
                "Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action",
            }
        ),
        frozenset(
            {
                "Microsoft.KeyVault/vaults/keys/read",
                "Microsoft.KeyVault/vaults/keys/verify/action",
            }
        ),
        frozenset({"Microsoft.KeyVault/vaults/keys/sign/action"}),
    }
)
ALLOWED_BUILT_IN_ROLES_BY_SCOPE_TYPE = {
    "microsoft.containerregistry/registries": frozenset({ACR_PULL_ROLE_ID}),
    "microsoft.servicebus/namespaces/queues": frozenset(
        {
            SERVICE_BUS_DATA_RECEIVER_ROLE_ID,
            SERVICE_BUS_DATA_SENDER_ROLE_ID,
        }
    ),
    "microsoft.storage/storageaccounts/blobservices/containers": frozenset(
        {BLOB_DATA_READER_ROLE_ID}
    ),
    "microsoft.storage/storageaccounts/tableservices/tables": frozenset(
        {
            TABLE_DATA_CONTRIBUTOR_ROLE_ID,
            TABLE_DATA_READER_ROLE_ID,
        }
    ),
    "microsoft.keyvault/vaults/keys": frozenset({KEY_VAULT_CRYPTO_USER_ROLE_ID}),
}
ALLOWED_CUSTOM_ACTIONS_BY_SCOPE_TYPE = {
    "microsoft.storage/storageaccounts/blobservices/containers": frozenset(
        {
            frozenset(
                {
                    BLOB_READ_DATA_ACTION,
                    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
                }
            ),
            frozenset(
                {"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"}
            ),
        }
    ),
    "microsoft.storage/storageaccounts/tableservices/tables": frozenset(
        {
            frozenset(
                {
                    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read",
                    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action",
                    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action",
                }
            )
        }
    ),
    "microsoft.keyvault/vaults/keys": frozenset(
        {
            frozenset(
                {
                    "Microsoft.KeyVault/vaults/keys/read",
                    "Microsoft.KeyVault/vaults/keys/verify/action",
                }
            ),
            frozenset({"Microsoft.KeyVault/vaults/keys/sign/action"}),
        }
    ),
}


def _identity_bindings(value: object) -> dict[str, str]:
    bindings: dict[str, str] = {}

    def visit(item: object) -> None:
        if isinstance(item, dict):
            for key, resource_id in item.items():
                if not key.casefold().endswith("identityresourceid"):
                    continue
                client_key = f"{key.removesuffix('ResourceId')}ClientId"
                normalized_resource_id = _azure_resource_id(
                    resource_id,
                    field="configured identity resource ID",
                ).casefold()
                configured_client_id = _string(
                    item.get(client_key),
                    field="configured identity client ID",
                )
                existing = bindings.get(normalized_resource_id)
                if existing is not None and existing.casefold() != configured_client_id.casefold():
                    raise OrchestrationError(
                        "one identity resource ID has conflicting configured client IDs"
                    )
                bindings[normalized_resource_id] = configured_client_id
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return bindings


def _verify_identities(
    configuration: Mapping[str, object],
    *,
    additional_identity_resource_ids: Sequence[str],
    rbac_identity_resource_ids: Sequence[str],
    subscription_id: str,
) -> dict[str, str]:
    bindings = _identity_bindings(configuration)
    identity_resource_ids = {
        *bindings,
        *(item.casefold() for item in additional_identity_resource_ids),
    }
    rbac_identity_ids = {item.casefold() for item in rbac_identity_resource_ids}
    principal_ids: dict[str, str] = {}
    for normalized_resource_id in identity_resource_ids:
        identity = _get_resource(
            normalized_resource_id,
            subscription_id=subscription_id,
        )
        _require_resource_id_equal(
            identity.get("id"),
            normalized_resource_id,
            field="managed identity readback",
        )
        properties = _mapping(identity.get("properties"), field="identity properties")
        configured_client_id = bindings.get(normalized_resource_id)
        if configured_client_id is not None:
            _require_equal(
                str(properties.get("clientId", "")).casefold(),
                configured_client_id.casefold(),
                field="managed identity client ID",
            )
        principal_id = _string(
            properties.get("principalId"),
            field="managed identity principal ID",
        ).casefold()
        if normalized_resource_id in rbac_identity_ids:
            principal_ids[normalized_resource_id] = principal_id
    return principal_ids


def _built_in_role_definition_id(subscription_id: str, role_id: str) -> str:
    return (
        f"/subscriptions/{subscription_id}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{role_id}"
    )


def _binding_rbac_resource_ids(binding: Mapping[str, object]) -> list[str]:
    return _string_list(
        binding.get("rbacResourceIds"),
        field="deployment binding RBAC resource IDs",
    )


def _binding_role_definition_ids(binding: Mapping[str, object]) -> list[str]:
    return [
        resource_id
        for resource_id in _binding_rbac_resource_ids(binding)
        if "/providers/microsoft.authorization/roledefinitions/" in resource_id.casefold()
    ]


def _bind_expected_assignment_ids(
    binding: Mapping[str, object],
    expected_assignments: Sequence[_ExpectedRoleAssignment],
    *,
    root_name: str,
) -> dict[str, _ExpectedRoleAssignment]:
    assignment_ids = [
        resource_id
        for resource_id in _binding_rbac_resource_ids(binding)
        if "/providers/microsoft.authorization/roleassignments/" in resource_id.casefold()
    ]
    if len(assignment_ids) != len(expected_assignments):
        raise OrchestrationError(
            f"{root_name} deployment binding does not contain its exact expected "
            "role-assignment mapping"
        )
    return {
        assignment_id.casefold(): expected
        for assignment_id, expected in zip(
            assignment_ids,
            expected_assignments,
            strict=True,
        )
    }


def _configured_identity_resource_id(value: object, *, field: str) -> str:
    return _azure_resource_id(
        _mapping(value, field=field).get("identityResourceId"),
        field=f"{field} identity resource ID",
    )


def _principal_for_identity(
    principal_ids_by_identity: Mapping[str, str],
    identity_resource_id: str,
    *,
    field: str,
) -> str:
    normalized_identity_id = _azure_resource_id(
        identity_resource_id,
        field=field,
    ).casefold()
    principal_id = principal_ids_by_identity.get(normalized_identity_id)
    if principal_id is None:
        raise OrchestrationError(
            f"{field} is missing from the exact resolved identity-to-principal mapping"
        )
    return principal_id


def _expected_role_assignment(
    label: str,
    *,
    identity_resource_id: str,
    principal_ids_by_identity: Mapping[str, str],
    scope: str,
    role_definition_id: str,
    condition_version: str | None = None,
    condition: str | None = None,
) -> _ExpectedRoleAssignment:
    return _ExpectedRoleAssignment(
        label=label,
        principal_id=_principal_for_identity(
            principal_ids_by_identity,
            identity_resource_id,
            field=f"{label} identity",
        ),
        scope=_azure_resource_id(scope, field=f"{label} scope"),
        role_definition_id=role_definition_id,
        condition_version=condition_version,
        condition=condition,
    )


def _producer_expected_rbac_assignments(
    binding: Mapping[str, object],
    *,
    configuration: Mapping[str, object],
    outputs: Mapping[str, object],
    foundation_values: Mapping[str, object],
    effective_parameters: Mapping[str, Mapping[str, object]],
    principal_ids_by_identity: Mapping[str, str],
    subscription_id: str,
) -> dict[str, _ExpectedRoleAssignment]:
    role_definition_ids = _binding_role_definition_ids(binding)
    if len(role_definition_ids) != 7:
        raise OrchestrationError(
            "producer deployment binding does not contain its exact custom role definitions"
        )
    _require_subscription_resource_id_equal(
        role_definition_ids[0],
        outputs.get("feedV2WriterRoleDefinitionId"),
        subscription_id=subscription_id,
        field="producer feed-v2 writer role definition",
    )

    service_bus = _mapping(
        configuration.get("serviceBus"),
        field="producer service bus",
    )
    incident_assets = _mapping(
        configuration.get("incidentLifecycleAssets"),
        field="producer incident lifecycle assets",
    )
    enrichment_assets = _mapping(
        configuration.get("enrichmentFeedAssets"),
        field="producer enrichment/feed assets",
    )
    feed_registry = _mapping(
        configuration.get("feedRegistry"),
        field="producer feed registry",
    )
    guidance_activation = _mapping(
        configuration.get("guidanceActivation"),
        field="producer guidance activation",
    )
    correlation_sources = _mapping(
        configuration.get("correlationSources"),
        field="producer correlation sources",
    )
    guidance_authority = _mapping(
        configuration.get("guidanceAuthoritySource"),
        field="producer guidance authority source",
    )
    monitoring_collector_key = _mapping(
        configuration.get("monitoringCollectorKey"),
        field="producer monitoring collector key",
    )
    keys = _mapping(configuration.get("keys"), field="producer keys")

    broker_identity_id = _azure_resource_id(
        service_bus.get("brokerIdentityResourceId"),
        field="producer broker identity",
    )
    incident_reader_identity_id = _configured_identity_resource_id(
        incident_assets,
        field="producer incident lifecycle assets",
    )
    feed_reader_identity_id = _azure_resource_id(
        enrichment_assets.get("readerIdentityResourceId"),
        field="producer enrichment/feed reader identity",
    )
    feed_writer_identity_id = _azure_resource_id(
        enrichment_assets.get("writerIdentityResourceId"),
        field="producer enrichment/feed writer identity",
    )
    registry_writer_identity_id = _configured_identity_resource_id(
        feed_registry,
        field="producer feed registry",
    )
    activation_reader_identity_id = _configured_identity_resource_id(
        guidance_activation,
        field="producer guidance activation",
    )
    monitoring_identity_id = _configured_identity_resource_id(
        correlation_sources.get("monitoring"),
        field="producer monitoring source",
    )
    change_identity_id = _configured_identity_resource_id(
        correlation_sources.get("change"),
        field="producer change source",
    )
    context_identity_id = _configured_identity_resource_id(
        correlation_sources.get("contextAuthority"),
        field="producer context-authority source",
    )
    monitoring_intent_identity_id = _configured_identity_resource_id(
        correlation_sources.get("monitoringIntent"),
        field="producer monitoring-intent source",
    )
    authority_identity_id = _configured_identity_resource_id(
        guidance_authority,
        field="producer guidance-authority source",
    )
    trust_identity_id = _configured_identity_resource_id(
        monitoring_collector_key,
        field="producer monitoring collector key",
    )

    trigger_queue_id = _azure_resource_id(
        outputs.get("triggerQueueResourceId"),
        field="producer trigger queue resource ID",
    )
    notification_queue_id = _azure_resource_id(
        outputs.get("notificationQueueResourceId"),
        field="producer notification queue resource ID",
    )
    registry_id = _azure_resource_id(
        _parameter_value(effective_parameters, "registryResourceId"),
        field="producer registry resource ID",
    )
    feed_container_id = _azure_resource_id(
        outputs.get("feedV2ContainerResourceId"),
        field="producer feed-v2 container resource ID",
    )
    incident_container_id = _azure_resource_id(
        foundation_values.get("incidentAssetContainerResourceId"),
        field="producer incident container resource ID",
    )
    correlation_storage_id = _azure_resource_id(
        _parameter_value(
            effective_parameters,
            "correlationSourceStorageAccountResourceId",
        ),
        field="producer correlation storage resource ID",
    )

    def correlation_container_id(name: str, *, field: str) -> str:
        source = _mapping(correlation_sources.get(name), field=field)
        container_name = _string(
            source.get("containerName"),
            field=f"{field} container name",
        )
        return f"{correlation_storage_id}/blobServices/default/containers/{container_name}"

    monitoring_container_id = correlation_container_id(
        "monitoring",
        field="producer monitoring source",
    )
    change_container_id = correlation_container_id(
        "change",
        field="producer change source",
    )
    context_container_id = correlation_container_id(
        "contextAuthority",
        field="producer context-authority source",
    )
    monitoring_intent_container_id = correlation_container_id(
        "monitoringIntent",
        field="producer monitoring-intent source",
    )
    authority_container_id = _azure_resource_id(
        outputs.get("guidanceAuthoritySourceContainerResourceId"),
        field="producer guidance-authority container resource ID",
    )
    registry_table_id = _azure_resource_id(
        outputs.get("feedRegistryTableResourceId"),
        field="producer feed registry table resource ID",
    )
    activation_table_id = _azure_resource_id(
        outputs.get("guidanceActivationTableResourceId"),
        field="producer guidance activation table resource ID",
    )
    key_vault_id = _azure_resource_id(
        foundation_values.get("keyVaultResourceId"),
        field="producer foundation Key Vault resource ID",
    )

    def foundation_key_scope(name: str) -> str:
        key = _mapping(keys.get(name), field=f"producer key {name}")
        key_name = _key_name(
            _string(
                key.get("keyVaultKeyId"),
                field=f"producer key {name} URI",
            )
        )
        return f"{key_vault_id}/keys/{key_name}"

    incident_key_id = foundation_key_scope("incident")
    report_key_id = foundation_key_scope("report")
    guidance_key_id = foundation_key_scope("guidance")
    enrichment_key_id = foundation_key_scope("enrichment")
    feed_key_id = foundation_key_scope("feed")
    notification_key_id = foundation_key_scope("notification")
    correlation_binding_key_id = _azure_resource_id(
        _parameter_value(effective_parameters, "correlationBindingKeyResourceId"),
        field="producer correlation-binding key resource ID",
    )
    guidance_binding_key_id = _azure_resource_id(
        _parameter_value(effective_parameters, "guidanceBindingKeyResourceId"),
        field="producer guidance-binding key resource ID",
    )
    change_key_id = _azure_resource_id(
        _parameter_value(effective_parameters, "changeKeyResourceId"),
        field="producer change key resource ID",
    )
    monitoring_intent_key_id = _azure_resource_id(
        _parameter_value(effective_parameters, "monitoringIntentKeyResourceId"),
        field="producer monitoring-intent key resource ID",
    )
    monitoring_collector_key_id = _azure_resource_id(
        _parameter_value(effective_parameters, "monitoringCollectorKeyResourceId"),
        field="producer monitoring-collector key resource ID",
    )

    blob_condition = {
        "condition_version": "2.0",
        "condition": BLOB_LIST_DENY_CONDITION,
    }
    built_in_roles = {
        "acr_pull": _built_in_role_definition_id(
            subscription_id,
            ACR_PULL_ROLE_ID,
        ),
        "service_bus_receiver": _built_in_role_definition_id(
            subscription_id,
            SERVICE_BUS_DATA_RECEIVER_ROLE_ID,
        ),
        "service_bus_sender": _built_in_role_definition_id(
            subscription_id,
            SERVICE_BUS_DATA_SENDER_ROLE_ID,
        ),
        "blob_reader": _built_in_role_definition_id(
            subscription_id,
            BLOB_DATA_READER_ROLE_ID,
        ),
        "table_contributor": _built_in_role_definition_id(
            subscription_id,
            TABLE_DATA_CONTRIBUTOR_ROLE_ID,
        ),
        "table_reader": _built_in_role_definition_id(
            subscription_id,
            TABLE_DATA_READER_ROLE_ID,
        ),
        "key_crypto_user": _built_in_role_definition_id(
            subscription_id,
            KEY_VAULT_CRYPTO_USER_ROLE_ID,
        ),
    }

    expected = [
        _expected_role_assignment(
            "producer trigger receiver",
            identity_resource_id=broker_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=trigger_queue_id,
            role_definition_id=built_in_roles["service_bus_receiver"],
        ),
        _expected_role_assignment(
            "producer notification sender",
            identity_resource_id=broker_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=notification_queue_id,
            role_definition_id=built_in_roles["service_bus_sender"],
        ),
        _expected_role_assignment(
            "producer registry pull",
            identity_resource_id=broker_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=registry_id,
            role_definition_id=built_in_roles["acr_pull"],
        ),
        _expected_role_assignment(
            "producer feed-v2 writer",
            identity_resource_id=feed_writer_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=feed_container_id,
            role_definition_id=role_definition_ids[0],
            **blob_condition,
        ),
        _expected_role_assignment(
            "producer feed-v2 readback reader",
            identity_resource_id=feed_reader_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=feed_container_id,
            role_definition_id=built_in_roles["blob_reader"],
            **blob_condition,
        ),
        _expected_role_assignment(
            "producer presentation feed-v2 reader",
            identity_resource_id=_string(
                _parameter_value(
                    effective_parameters,
                    "feedV2ReaderIdentityResourceId",
                ),
                field="producer presentation reader identity",
            ),
            principal_ids_by_identity=principal_ids_by_identity,
            scope=feed_container_id,
            role_definition_id=built_in_roles["blob_reader"],
            **blob_condition,
        ),
        _expected_role_assignment(
            "producer incident reader",
            identity_resource_id=incident_reader_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=incident_container_id,
            role_definition_id=built_in_roles["blob_reader"],
            **blob_condition,
        ),
        _expected_role_assignment(
            "producer monitoring source reader",
            identity_resource_id=monitoring_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=monitoring_container_id,
            role_definition_id=built_in_roles["blob_reader"],
            **blob_condition,
        ),
        _expected_role_assignment(
            "producer change source reader",
            identity_resource_id=change_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=change_container_id,
            role_definition_id=built_in_roles["blob_reader"],
            **blob_condition,
        ),
        _expected_role_assignment(
            "producer context-authority source reader",
            identity_resource_id=context_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=context_container_id,
            role_definition_id=built_in_roles["blob_reader"],
            **blob_condition,
        ),
        _expected_role_assignment(
            "producer monitoring-intent source reader",
            identity_resource_id=monitoring_intent_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=monitoring_intent_container_id,
            role_definition_id=built_in_roles["blob_reader"],
            **blob_condition,
        ),
        _expected_role_assignment(
            "producer guidance-authority source reader",
            identity_resource_id=authority_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=authority_container_id,
            role_definition_id=built_in_roles["blob_reader"],
            **blob_condition,
        ),
        _expected_role_assignment(
            "producer feed registry writer",
            identity_resource_id=registry_writer_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=registry_table_id,
            role_definition_id=built_in_roles["table_contributor"],
        ),
        _expected_role_assignment(
            "producer guidance activation reader",
            identity_resource_id=activation_reader_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=activation_table_id,
            role_definition_id=built_in_roles["table_reader"],
        ),
        _expected_role_assignment(
            "producer incident key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=incident_key_id,
            role_definition_id=role_definition_ids[1],
        ),
        _expected_role_assignment(
            "producer correlation-binding key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=correlation_binding_key_id,
            role_definition_id=role_definition_ids[2],
        ),
        _expected_role_assignment(
            "producer guidance-binding key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=guidance_binding_key_id,
            role_definition_id=role_definition_ids[3],
        ),
        _expected_role_assignment(
            "producer change key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=change_key_id,
            role_definition_id=role_definition_ids[4],
        ),
        _expected_role_assignment(
            "producer monitoring-intent key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=monitoring_intent_key_id,
            role_definition_id=role_definition_ids[5],
        ),
        _expected_role_assignment(
            "producer monitoring-collector key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=monitoring_collector_key_id,
            role_definition_id=role_definition_ids[6],
        ),
    ]
    for name, scope in (
        ("report", report_key_id),
        ("guidance", guidance_key_id),
        ("enrichment", enrichment_key_id),
        ("feed", feed_key_id),
        ("notification", notification_key_id),
    ):
        expected.append(
            _expected_role_assignment(
                f"producer {name} signer",
                identity_resource_id=_configured_identity_resource_id(
                    keys.get(name),
                    field=f"producer key {name}",
                ),
                principal_ids_by_identity=principal_ids_by_identity,
                scope=scope,
                role_definition_id=built_in_roles["key_crypto_user"],
            )
        )
    for index, identity_resource_id in enumerate(
        _string_list(
            _parameter_value(
                effective_parameters,
                "triggerSubmitterIdentityResourceIds",
            ),
            field="producer trigger submitter identities",
        )
    ):
        expected.append(
            _expected_role_assignment(
                f"producer trigger submitter {index}",
                identity_resource_id=identity_resource_id,
                principal_ids_by_identity=principal_ids_by_identity,
                scope=trigger_queue_id,
                role_definition_id=built_in_roles["service_bus_sender"],
            )
        )
    return _bind_expected_assignment_ids(
        binding,
        expected,
        root_name="producer",
    )


def _publisher_expected_rbac_assignments(
    binding: Mapping[str, object],
    *,
    configuration: Mapping[str, object],
    outputs: Mapping[str, object],
    effective_parameters: Mapping[str, Mapping[str, object]],
    principal_ids_by_identity: Mapping[str, str],
    subscription_id: str,
) -> dict[str, _ExpectedRoleAssignment]:
    role_definition_ids = _binding_role_definition_ids(binding)
    if len(role_definition_ids) != 5:
        raise OrchestrationError(
            "publisher deployment binding does not contain its exact custom role definitions"
        )

    service_bus = _mapping(
        configuration.get("serviceBus"),
        field="publisher service bus",
    )
    authority_assets = _mapping(
        configuration.get("authorityAssets"),
        field="publisher authority assets",
    )
    guidance_activation = _mapping(
        configuration.get("guidanceActivation"),
        field="publisher guidance activation",
    )
    request_key = _mapping(
        configuration.get("requestKey"),
        field="publisher request key",
    )
    binding_key = _mapping(
        configuration.get("bindingSigningKey"),
        field="publisher binding signing key",
    )

    broker_identity_id = _azure_resource_id(
        service_bus.get("brokerIdentityResourceId"),
        field="publisher broker identity",
    )
    authority_reader_identity_id = _azure_resource_id(
        authority_assets.get("readerIdentityResourceId"),
        field="publisher authority reader identity",
    )
    authority_writer_identity_id = _azure_resource_id(
        authority_assets.get("writerIdentityResourceId"),
        field="publisher authority writer identity",
    )
    activation_writer_identity_id = _configured_identity_resource_id(
        guidance_activation,
        field="publisher guidance activation",
    )
    request_trust_identity_id = _configured_identity_resource_id(
        request_key,
        field="publisher request key",
    )
    binding_signer_identity_id = _configured_identity_resource_id(
        binding_key,
        field="publisher binding signing key",
    )
    binding_trust_identity_id = _azure_resource_id(
        _parameter_value(
            effective_parameters,
            "bindingTrustReaderIdentityResourceId",
        ),
        field="publisher binding trust reader identity",
    )

    request_queue_id = _azure_resource_id(
        outputs.get("requestQueueResourceId"),
        field="publisher request queue resource ID",
    )
    trigger_queue_id = _azure_resource_id(
        outputs.get("triggerQueueResourceId"),
        field="publisher trigger queue resource ID",
    )
    authority_container_id = _azure_resource_id(
        outputs.get("authorityContainerResourceId"),
        field="publisher authority container resource ID",
    )
    activation_table_id = _azure_resource_id(
        outputs.get("activationTableResourceId"),
        field="publisher activation table resource ID",
    )
    request_key_id = _azure_resource_id(
        _parameter_value(effective_parameters, "requestKeyResourceId"),
        field="publisher request key resource ID",
    )
    binding_key_id = _azure_resource_id(
        _parameter_value(effective_parameters, "bindingKeyResourceId"),
        field="publisher binding key resource ID",
    )
    registry_id = _azure_resource_id(
        _parameter_value(effective_parameters, "registryResourceId"),
        field="publisher registry resource ID",
    )

    blob_condition = {
        "condition_version": "2.0",
        "condition": BLOB_LIST_DENY_CONDITION,
    }
    built_in_roles = {
        "acr_pull": _built_in_role_definition_id(
            subscription_id,
            ACR_PULL_ROLE_ID,
        ),
        "service_bus_receiver": _built_in_role_definition_id(
            subscription_id,
            SERVICE_BUS_DATA_RECEIVER_ROLE_ID,
        ),
        "service_bus_sender": _built_in_role_definition_id(
            subscription_id,
            SERVICE_BUS_DATA_SENDER_ROLE_ID,
        ),
        "blob_reader": _built_in_role_definition_id(
            subscription_id,
            BLOB_DATA_READER_ROLE_ID,
        ),
    }
    expected = [
        _expected_role_assignment(
            "publisher request receiver",
            identity_resource_id=broker_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=request_queue_id,
            role_definition_id=built_in_roles["service_bus_receiver"],
        ),
        _expected_role_assignment(
            "publisher producer-trigger sender",
            identity_resource_id=broker_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=trigger_queue_id,
            role_definition_id=built_in_roles["service_bus_sender"],
        ),
        _expected_role_assignment(
            "publisher authority writer",
            identity_resource_id=authority_writer_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=authority_container_id,
            role_definition_id=role_definition_ids[0],
        ),
        _expected_role_assignment(
            "publisher authority reader",
            identity_resource_id=authority_reader_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=authority_container_id,
            role_definition_id=built_in_roles["blob_reader"],
            **blob_condition,
        ),
        _expected_role_assignment(
            "publisher activation writer",
            identity_resource_id=activation_writer_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=activation_table_id,
            role_definition_id=role_definition_ids[1],
        ),
        _expected_role_assignment(
            "publisher request key verifier",
            identity_resource_id=request_trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=request_key_id,
            role_definition_id=role_definition_ids[2],
        ),
        _expected_role_assignment(
            "publisher binding key verifier",
            identity_resource_id=binding_trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=binding_key_id,
            role_definition_id=role_definition_ids[3],
        ),
        _expected_role_assignment(
            "publisher binding signer",
            identity_resource_id=binding_signer_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=binding_key_id,
            role_definition_id=role_definition_ids[4],
        ),
        _expected_role_assignment(
            "publisher registry pull",
            identity_resource_id=broker_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=registry_id,
            role_definition_id=built_in_roles["acr_pull"],
        ),
    ]
    for index, identity_resource_id in enumerate(
        _string_list(
            _parameter_value(
                effective_parameters,
                "requestSubmitterIdentityResourceIds",
            ),
            field="publisher request submitter identities",
        )
    ):
        expected.append(
            _expected_role_assignment(
                f"publisher request submitter {index}",
                identity_resource_id=identity_resource_id,
                principal_ids_by_identity=principal_ids_by_identity,
                scope=request_queue_id,
                role_definition_id=built_in_roles["service_bus_sender"],
            )
        )
    return _bind_expected_assignment_ids(
        binding,
        expected,
        root_name="publisher",
    )


def _resource_type(resource_id: str) -> str:
    segments = [segment.casefold() for segment in resource_id.split("/") if segment]
    if len(segments) < 8 or segments[4] != "providers":
        raise OrchestrationError(f"resource ID has an unsupported shape: {resource_id}")
    type_segments = segments[6::2]
    name_segments = segments[7::2]
    if not type_segments or len(type_segments) != len(name_segments):
        raise OrchestrationError(f"resource ID has an invalid type path: {resource_id}")
    return "/".join((segments[5], *type_segments))


def _role_assignment_scope(resource_id: str) -> str:
    marker = "/providers/microsoft.authorization/roleassignments/"
    normalized = resource_id.casefold()
    if marker not in normalized:
        raise OrchestrationError(
            f"role assignment resource ID has no assignment boundary: {resource_id}"
        )
    return resource_id[: normalized.rindex(marker)]


def _verify_custom_role(resource: Mapping[str, object]) -> frozenset[str]:
    properties = _mapping(resource.get("properties"), field="custom role properties")
    permissions = properties.get("permissions")
    if not isinstance(permissions, list) or len(permissions) != 1:
        raise OrchestrationError("custom role must contain exactly one permission block")
    permission = _mapping(permissions[0], field="custom role permission")
    for field in ("actions", "notActions", "notDataActions"):
        if permission.get(field) not in (None, []):
            raise OrchestrationError(f"custom data role has unexpected {field}")
    data_actions = permission.get("dataActions")
    if not isinstance(data_actions, list) or any(
        not isinstance(item, str) for item in data_actions
    ):
        raise OrchestrationError("custom data role has invalid data actions")
    if frozenset(data_actions) not in ALLOWED_CUSTOM_DATA_ACTIONS:
        raise OrchestrationError("custom data role permissions do not match an approved profile")
    return frozenset(data_actions)


def _verify_rbac_resources(
    binding: Mapping[str, object],
    *,
    expected_assignments: Mapping[str, _ExpectedRoleAssignment],
    subscription_id: str,
) -> dict[str, set[str]]:
    resource_ids = _binding_rbac_resource_ids(binding)
    assignment_ids = {
        resource_id.casefold()
        for resource_id in resource_ids
        if "/providers/microsoft.authorization/roleassignments/" in resource_id.casefold()
    }
    if assignment_ids != set(expected_assignments):
        raise OrchestrationError(
            "deployment binding role assignments do not match the exact expected mapping"
        )
    for resource_id in resource_ids:
        normalized_id = resource_id.casefold()
        if (
            "/providers/microsoft.authorization/roledefinitions/" not in normalized_id
            and "/providers/microsoft.authorization/roleassignments/" not in normalized_id
        ):
            raise OrchestrationError(
                f"deployment binding contains unsupported RBAC resource: {resource_id}"
            )
    resources: dict[str, dict[str, Any]] = {}
    for resource_id in resource_ids:
        resource = _get_resource(resource_id, subscription_id=subscription_id)
        _require_resource_id_equal(
            resource.get("id"),
            resource_id,
            field="RBAC resource readback",
        )
        resources[resource_id.casefold()] = resource
    custom_roles: dict[str, frozenset[str]] = {}
    for resource_id in resource_ids:
        normalized_id = resource_id.casefold()
        if "/providers/microsoft.authorization/roledefinitions/" in normalized_id:
            custom_roles[normalized_id] = _verify_custom_role(resources[normalized_id])
            continue
    used_custom_roles: set[str] = set()
    assignment_ids_by_principal: dict[str, set[str]] = {}
    for resource_id in resource_ids:
        normalized_id = resource_id.casefold()
        if "/providers/microsoft.authorization/roledefinitions/" in normalized_id:
            continue
        expected = expected_assignments[normalized_id]
        resource = resources[normalized_id]
        properties = _mapping(
            resource.get("properties"),
            field=f"{expected.label} role assignment properties",
        )
        principal_id = _string(
            properties.get("principalId"),
            field=f"{expected.label} role assignment principal ID",
        ).casefold()
        if principal_id != expected.principal_id.casefold():
            raise OrchestrationError(
                f"{expected.label} role assignment does not match its exact intended principal"
            )
        assignment_ids_by_principal.setdefault(principal_id, set()).add(normalized_id)
        role_definition_id = _canonical_subscription_resource_id(
            properties.get("roleDefinitionId"),
            subscription_id=subscription_id,
            field=f"{expected.label} role assignment role definition",
        )
        _require_subscription_resource_id_equal(
            role_definition_id,
            expected.role_definition_id,
            subscription_id=subscription_id,
            field=f"{expected.label} role assignment role definition",
        )
        role_id = role_definition_id.casefold().rsplit("/", 1)[-1]
        scope = _role_assignment_scope(resource_id)
        _require_resource_id_equal(
            scope,
            expected.scope,
            field=f"{expected.label} role assignment scope",
        )
        if properties.get("scope") is not None:
            _require_resource_id_equal(
                properties.get("scope"),
                expected.scope,
                field=f"{expected.label} role assignment scope property",
            )
        if properties.get("principalType") != "ServicePrincipal":
            raise OrchestrationError(
                f"{expected.label} role assignment principal type must be ServicePrincipal"
            )

        custom_actions = custom_roles.get(role_definition_id.casefold())
        grants_blob_read = role_id == BLOB_DATA_READER_ROLE_ID or (
            custom_actions is not None and BLOB_READ_DATA_ACTION in custom_actions
        )
        if grants_blob_read and (
            properties.get("conditionVersion") != "2.0"
            or properties.get("condition") != BLOB_LIST_DENY_CONDITION
        ):
            raise OrchestrationError(
                f"{expected.label} role assignment whose resolved role includes "
                "Blob read must use the exact no-Blob.List ABAC condition"
            )
        if (
            properties.get("conditionVersion") != expected.condition_version
            or properties.get("condition") != expected.condition
        ):
            raise OrchestrationError(
                f"{expected.label} role assignment does not match its exact intended condition"
            )

        scope_type = _resource_type(scope)
        if role_id in BUILT_IN_DATA_ROLE_IDS:
            allowed_role_ids = ALLOWED_BUILT_IN_ROLES_BY_SCOPE_TYPE.get(
                scope_type,
                frozenset(),
            )
            if role_id not in allowed_role_ids:
                raise OrchestrationError(
                    "role assignment role does not match its exact resource scope"
                )
            continue
        if custom_actions is None:
            raise OrchestrationError(
                "role assignment references a custom role outside the deployment binding"
            )
        allowed_custom_actions = ALLOWED_CUSTOM_ACTIONS_BY_SCOPE_TYPE.get(
            scope_type,
            frozenset(),
        )
        if custom_actions not in allowed_custom_actions:
            raise OrchestrationError(
                "custom role permissions do not match the assignment resource scope"
            )
        used_custom_roles.add(role_definition_id.casefold())
    if used_custom_roles != set(custom_roles):
        raise OrchestrationError("deployment binding contains an unused or unassigned custom role")
    return assignment_ids_by_principal


def _effective_role_assignments(
    principal_id: str,
    *,
    subscription_id: str,
    field: str,
) -> list[dict[str, Any]]:
    subscription_scope = f"/subscriptions/{subscription_id}"
    query_documents = (
        _run_json(
            [
                "az",
                "role",
                "assignment",
                "list",
                "--subscription",
                subscription_id,
                "--assignee-object-id",
                principal_id,
                "--all",
                "--only-show-errors",
                "--output",
                "json",
            ],
            field=f"{field} at or below the subscription",
        ),
        _run_json(
            [
                "az",
                "role",
                "assignment",
                "list",
                "--subscription",
                subscription_id,
                "--assignee-object-id",
                principal_id,
                "--scope",
                subscription_scope,
                "--include-inherited",
                "--only-show-errors",
                "--output",
                "json",
            ],
            field=f"{field} inherited from subscription ancestors",
        ),
    )
    merged: dict[str, dict[str, Any]] = {}
    for document in query_documents:
        if not isinstance(document, list):
            raise OrchestrationError(f"{field} must be an array")
        for index, raw_assignment in enumerate(document):
            assignment = _mapping(
                raw_assignment,
                field=f"{field} item {index}",
            )
            assignment_id = _string(
                assignment.get("id"),
                field=f"{field} assignment ID",
            ).casefold()
            existing = merged.get(assignment_id)
            if existing is None:
                merged[assignment_id] = assignment
                continue
            for property_name in (
                "principalId",
                "roleDefinitionId",
                "roleDefinitionName",
                "scope",
            ):
                existing_value = existing.get(property_name)
                incoming_value = assignment.get(property_name)
                if (
                    existing_value not in (None, "")
                    and incoming_value not in (None, "")
                    and str(existing_value).casefold() != str(incoming_value).casefold()
                ):
                    raise OrchestrationError(
                        f"{field} returned conflicting duplicate assignment {assignment_id}"
                    )
                if existing_value in (None, "") and incoming_value not in (None, ""):
                    existing[property_name] = incoming_value
    return list(merged.values())


def _verify_no_broad_effective_assignments(
    principal_ids: set[str],
    *,
    subscription_id: str,
) -> dict[str, list[dict[str, Any]]]:
    assignments_by_principal: dict[str, list[dict[str, Any]]] = {}
    for principal_id in sorted(principal_ids):
        assignments = _effective_role_assignments(
            principal_id,
            subscription_id=subscription_id,
            field=f"effective role assignments for {principal_id}",
        )
        assignments_by_principal[principal_id.casefold()] = assignments
        violations = evaluate_role_assignments(assignments)
        if violations:
            details = "; ".join(f"{item.code}: {item.detail}" for item in violations)
            raise OrchestrationError(f"governed identity has prohibited broad RBAC: {details}")
    return assignments_by_principal


def _role_assignment_ids(binding: Mapping[str, object]) -> set[str]:
    return {
        resource_id.casefold()
        for resource_id in _string_list(
            binding.get("rbacResourceIds"),
            field="deployment binding RBAC resource IDs",
        )
        if "/providers/microsoft.authorization/roleassignments/" in resource_id.casefold()
    }


def _governed_rbac_scopes(assignment_ids: set[str]) -> set[str]:
    return {_role_assignment_scope(resource_id).casefold() for resource_id in assignment_ids}


def _scopes_overlap(first: str, second: str) -> bool:
    normalized_first = first.rstrip("/").casefold()
    normalized_second = second.rstrip("/").casefold()
    management_group_prefix = "/providers/microsoft.management/managementgroups/"
    if normalized_first in {"", "/"} or normalized_second in {"", "/"}:
        return True
    if normalized_first.startswith(management_group_prefix) or normalized_second.startswith(
        management_group_prefix
    ):
        # No independently reviewed management-group hierarchy is accepted by this
        # orchestration path. Conservatively treat every management-group assignment
        # returned as inherited by every governed resource in the subscription.
        return True
    return (
        normalized_first == normalized_second
        or normalized_first.startswith(normalized_second + "/")
        or normalized_second.startswith(normalized_first + "/")
    )


def _verify_exact_effective_assignments(
    expected_assignments_by_principal: Mapping[str, set[str]],
    *,
    additional_allowed_assignment_ids: set[str],
    subscription_id: str,
    effective_assignments_by_principal: Mapping[str, list[dict[str, Any]]] | None = None,
) -> None:
    additional_assignment_ids_by_principal: dict[str, set[str]] = {}
    for assignment_id in sorted(additional_allowed_assignment_ids):
        assignment = _get_resource(
            assignment_id,
            subscription_id=subscription_id,
        )
        _require_resource_id_equal(
            assignment.get("id"),
            assignment_id,
            field="additional reviewed RBAC assignment readback",
        )
        properties = _mapping(
            assignment.get("properties"),
            field="additional reviewed RBAC assignment properties",
        )
        principal_id = _string(
            properties.get("principalId"),
            field="additional reviewed RBAC assignment principal ID",
        ).casefold()
        if properties.get("principalType") != "ServicePrincipal":
            raise OrchestrationError(
                "additional reviewed RBAC assignment principal type must be ServicePrincipal"
            )
        additional_assignment_ids_by_principal.setdefault(principal_id, set()).add(
            assignment_id.casefold()
        )
    for principal_id, expected_assignment_ids in sorted(expected_assignments_by_principal.items()):
        allowed_assignment_ids = {
            assignment_id.casefold() for assignment_id in expected_assignment_ids
        }
        allowed_assignment_ids.update(
            additional_assignment_ids_by_principal.get(principal_id.casefold(), set())
        )
        governed_scopes = _governed_rbac_scopes(expected_assignment_ids)
        assignments = (
            _effective_role_assignments(
                principal_id,
                subscription_id=subscription_id,
                field=f"exact role assignments for {principal_id}",
            )
            if effective_assignments_by_principal is None
            else effective_assignments_by_principal.get(principal_id.casefold())
        )
        if assignments is None:
            raise OrchestrationError(
                "effective role assignment evidence is missing a governed principal"
            )
        for index, raw_assignment in enumerate(assignments):
            assignment = _mapping(
                raw_assignment,
                field=f"effective role assignment {index}",
            )
            assignment_id = _string(
                assignment.get("id"),
                field="effective role assignment ID",
            ).casefold()
            assignment_scope = _string(
                assignment.get("scope"),
                field="effective role assignment scope",
            )
            if assignment_scope != assignment_scope.strip() or not assignment_scope.startswith("/"):
                raise OrchestrationError(
                    "effective role assignment scope must be a canonical absolute scope"
                )
            if (
                any(
                    _scopes_overlap(assignment_scope, governed_scope)
                    for governed_scope in governed_scopes
                )
                and assignment_id not in allowed_assignment_ids
            ):
                raise OrchestrationError(
                    "governed runtime identity has an unreviewed effective role assignment"
                )


def _verify_job_deployment_binding(
    *,
    job: Mapping[str, object],
    expected_resource_id: str,
    expected_environment_resource_id: str,
    expected_identity_resource_ids: Sequence[str],
    expected_configuration_digest: str,
    expected_binding_evidence: str,
    expected_embedded_configuration_digest: str | None = None,
) -> None:
    _require_resource_id_equal(
        job.get("id"),
        expected_resource_id,
        field="deployed Job resource ID",
    )
    properties = _mapping(job.get("properties"), field="job properties")
    _require_equal(
        properties.get("provisioningState"),
        "Succeeded",
        field="job provisioning state",
    )
    _require_resource_id_equal(
        properties.get("environmentId"),
        expected_environment_resource_id,
        field="job managed environment",
    )
    identity = _mapping(job.get("identity"), field="job identity")
    _require_equal(identity.get("type"), "UserAssigned", field="job identity type")
    user_assigned = _mapping(
        identity.get("userAssignedIdentities"),
        field="job user-assigned identities",
    )
    actual_identity_ids = {resource_id.casefold() for resource_id in user_assigned}
    expected_identity_ids = {
        _azure_resource_id(resource_id, field="expected job identity").casefold()
        for resource_id in expected_identity_resource_ids
    }
    if actual_identity_ids != expected_identity_ids:
        raise OrchestrationError(
            "deployed Job identities do not exactly match its deployment binding"
        )
    tags = _mapping(job.get("tags"), field="job tags")
    _require_equal(
        tags.get("runtimeConfigurationDigest"),
        expected_configuration_digest,
        field="job runtime configuration digest tag",
    )
    _require_equal(
        tags.get("bindingEvidenceDigest"),
        expected_binding_evidence,
        field="job binding evidence tag",
    )
    if expected_embedded_configuration_digest is not None:
        _require_equal(
            tags.get("enrichmentRuntimeConfigurationDigest"),
            expected_embedded_configuration_digest,
            field="job embedded producer configuration digest tag",
        )


def _verify_job_behavior(
    *,
    job: Mapping[str, object],
    expected_image: str,
    expected_container_name: str,
    expected_command: str,
    expected_argument: str,
    expected_rule_name: str,
    expected_environment_name: str,
    expected_configuration_json: str,
    broker_identity_resource_id: str,
    namespace_host: str,
    queue_name: str,
) -> None:
    properties = _mapping(job.get("properties"), field="job properties")
    template = _mapping(properties.get("template"), field="job template")
    _require_absent_or_empty(
        template.get("initContainers"),
        field="job init containers",
    )
    _require_absent_or_empty(template.get("volumes"), field="job volumes")
    containers = template.get("containers")
    if not isinstance(containers, list) or len(containers) != 1:
        raise OrchestrationError("deployed Job must contain exactly one container")
    container = _mapping(containers[0], field="job container")
    _require_equal(
        container.get("name"),
        expected_container_name,
        field="job container name",
    )
    _require_absent_or_empty(
        container.get("volumeMounts"),
        field="job container volume mounts",
    )
    _require_absent_or_empty(container.get("probes"), field="job container probes")
    _require_equal(container.get("image"), expected_image, field="job image")
    _require_equal(container.get("command"), [expected_command], field="job command")
    _require_equal(container.get("args"), [expected_argument], field="job arguments")
    environment = container.get("env")
    if not isinstance(environment, list) or len(environment) != 2:
        raise OrchestrationError("deployed Job must contain exactly two environment entries")
    for item in environment:
        entry = _mapping(item, field="job environment entry")
        _require_absent_or_empty(
            entry.get("secretRef"),
            field="job environment secret reference",
        )
    try:
        expected_configuration = _mapping(
            json.loads(expected_configuration_json),
            field="job runtime configuration",
        )
    except json.JSONDecodeError as exc:
        raise OrchestrationError("job runtime configuration JSON is invalid") from exc
    expected_service_bus = _mapping(
        expected_configuration.get("serviceBus"),
        field="job runtime service bus",
    )
    expected_environment = {
        "AZURE_CLIENT_ID": _string(
            expected_service_bus.get("brokerIdentityClientId"),
            field="job broker identity client ID",
        ),
        expected_environment_name: expected_configuration_json,
    }
    actual_environment = {
        _string(
            _mapping(item, field="job environment entry").get("name"),
            field="job environment name",
        ): _mapping(item, field="job environment entry").get("value")
        for item in environment
    }
    _require_equal(actual_environment, expected_environment, field="job environment")
    resources = _mapping(container.get("resources"), field="job container resources")
    _require_equal(resources.get("cpu"), 1, field="job container CPU")
    _require_equal(resources.get("memory"), "2Gi", field="job container memory")
    configuration = _mapping(
        properties.get("configuration"),
        field="job trigger configuration",
    )
    for field_name in (
        "identitySettings",
        "manualTriggerConfig",
        "scheduleTriggerConfig",
        "secrets",
    ):
        _require_absent_or_empty(
            configuration.get(field_name),
            field=f"job {field_name}",
        )
    _require_equal(configuration.get("replicaTimeout"), 900, field="job replica timeout")
    _require_equal(configuration.get("replicaRetryLimit"), 0, field="job retry limit")
    _require_equal(configuration.get("triggerType"), "Event", field="job trigger type")
    event_trigger = _mapping(
        configuration.get("eventTriggerConfig"),
        field="job event trigger",
    )
    _require_equal(event_trigger.get("parallelism"), 1, field="job parallelism")
    _require_equal(
        event_trigger.get("replicaCompletionCount"),
        1,
        field="job replica completion count",
    )
    scale = _mapping(event_trigger.get("scale"), field="job scale")
    _require_equal(scale.get("minExecutions"), 0, field="job minimum executions")
    _require_equal(scale.get("maxExecutions"), 1, field="job maximum executions")
    _require_equal(scale.get("pollingInterval"), 30, field="job polling interval")
    rules = scale.get("rules")
    if not isinstance(rules, list) or len(rules) != 1:
        raise OrchestrationError("deployed Job must contain exactly one scaler rule")
    rule = _mapping(rules[0], field="job scaler rule")
    _require_absent_or_empty(rule.get("auth"), field="job scaler secret authentication")
    _require_equal(rule.get("name"), expected_rule_name, field="job scaler name")
    _require_equal(rule.get("type"), "azure-servicebus", field="job scaler type")
    _require_equal(
        rule.get("identity"),
        broker_identity_resource_id,
        field="job scaler identity",
    )
    metadata = _mapping(rule.get("metadata"), field="job scaler metadata")
    _require_equal(
        metadata.get("namespace"),
        namespace_host.removesuffix(".servicebus.windows.net"),
        field="job scaler namespace",
    )
    _require_equal(metadata.get("queueName"), queue_name, field="job scaler queue")
    _require_equal(metadata.get("messageCount"), "1", field="job scaler message count")
    _require_equal(metadata.get("cloud"), "AzurePublicCloud", field="job scaler cloud")
    _require_equal(
        metadata.get("isSessionsEnabled"),
        "true",
        field="job scaler session setting",
    )
    registries = configuration.get("registries")
    if not isinstance(registries, list) or len(registries) != 1:
        raise OrchestrationError("deployed Job must contain exactly one registry")
    registry = _mapping(registries[0], field="job registry")
    _require_absent_or_empty(
        registry.get("username"),
        field="job registry username",
    )
    _require_absent_or_empty(
        registry.get("passwordSecretRef"),
        field="job registry password secret reference",
    )
    _require_equal(
        registry.get("server"),
        expected_image.split("/", 1)[0],
        field="job registry server",
    )
    _require_equal(
        registry.get("identity"),
        broker_identity_resource_id,
        field="job registry identity",
    )


def _verify_service_bus_queue(
    *,
    job_resource_id: str,
    namespace_name: str,
    queue_name: str,
    profile_name: str,
    expected_profile: Mapping[str, object],
    subscription_id: str,
) -> None:
    queue_id = (
        f"{_resource_group_scope(job_resource_id)}/providers/"
        f"Microsoft.ServiceBus/namespaces/{namespace_name}/queues/{queue_name}"
    )
    queue = _get_resource(
        queue_id,
        subscription_id=subscription_id,
    )
    _require_resource_id_equal(
        queue.get("id"),
        queue_id,
        field="Service Bus queue readback",
    )
    properties = _mapping(
        queue.get("properties"),
        field="Service Bus queue properties",
    )
    for property_name, expected_value in expected_profile.items():
        _require_equal(
            properties.get(property_name),
            expected_value,
            field=f"{profile_name} Service Bus queue {property_name}",
        )
    for forwarding_property in ("forwardTo", "forwardDeadLetteredMessagesTo"):
        _require_absent_or_empty(
            properties.get(forwarding_property),
            field=f"{profile_name} Service Bus queue {forwarding_property}",
        )


def _parse_key_time(value: object, *, field: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise OrchestrationError(f"{field} is not a valid timestamp") from exc
    raise OrchestrationError(f"{field} is not a valid timestamp")


def _verify_key(
    versioned_key_uri: str,
    *,
    subscription_id: str,
    required_operations: frozenset[str],
) -> None:
    document = _mapping(
        _run_json(
            [
                "az",
                "keyvault",
                "key",
                "show",
                "--subscription",
                subscription_id,
                "--id",
                versioned_key_uri,
                "--only-show-errors",
                "--output",
                "json",
            ],
            field=f"Key Vault key {versioned_key_uri}",
        ),
        field=f"Key Vault key {versioned_key_uri}",
    )
    attributes = _mapping(document.get("attributes"), field="key attributes")
    if attributes.get("enabled") is not True:
        raise OrchestrationError(f"Key Vault key is disabled: {versioned_key_uri}")
    now = datetime.now(UTC)
    not_before = _parse_key_time(
        attributes.get("notBefore"),
        field="key notBefore",
    )
    expires = _parse_key_time(attributes.get("expires"), field="key expires")
    if not_before is not None and not_before > now:
        raise OrchestrationError(f"Key Vault key is not active yet: {versioned_key_uri}")
    if expires is not None and expires <= now:
        raise OrchestrationError(f"Key Vault key is expired: {versioned_key_uri}")
    key = _mapping(document.get("key"), field="key material")
    key_operations = key.get("keyOps")
    if not isinstance(key_operations, list) or any(
        not isinstance(item, str) for item in key_operations
    ):
        raise OrchestrationError("Key Vault key operations are absent")
    if not required_operations.issubset({item.casefold() for item in key_operations}):
        raise OrchestrationError(
            f"Key Vault key lacks required operations {sorted(required_operations)}: "
            f"{versioned_key_uri}"
        )


def _latest_key_uri(
    *,
    vault_name: str,
    key_name: str,
    subscription_id: str,
) -> str:
    return _run(
        [
            "az",
            "keyvault",
            "key",
            "show",
            "--subscription",
            subscription_id,
            "--vault-name",
            vault_name,
            "--name",
            key_name,
            "--query",
            "key.kid",
            "--only-show-errors",
            "--output",
            "tsv",
        ]
    ).strip()


def _verify_latest_key_uri(
    versioned_key_uri: str,
    *,
    subscription_id: str,
) -> None:
    parsed = urlparse(versioned_key_uri)
    vault_name = parsed.netloc.split(".", 1)[0]
    key_name = _key_name(versioned_key_uri)
    if (
        _latest_key_uri(
            vault_name=vault_name,
            key_name=key_name,
            subscription_id=subscription_id,
        ).casefold()
        != versioned_key_uri.casefold()
    ):
        raise OrchestrationError(
            f"current Key Vault key version drifted from the foundation handoff: {key_name}"
        )


def _verify_foundation_key_heads(
    foundation: Mapping[str, object],
    *,
    subscription_id: str,
) -> None:
    outputs = _foundation_outputs(foundation)
    for name in (
        "incidentSigningKeyUriWithVersion",
        "incidentFeedV2SigningKeyUriWithVersion",
        "incidentReportSigningKeyUriWithVersion",
        "incidentGuidanceSigningKeyUriWithVersion",
        "incidentEnrichmentSigningKeyUriWithVersion",
        "incidentNotificationSigningKeyUriWithVersion",
    ):
        key_uri = _string(outputs[name], field=name)
        _verify_latest_key_uri(
            key_uri,
            subscription_id=subscription_id,
        )
        _verify_key(
            key_uri,
            subscription_id=subscription_id,
            required_operations=frozenset({"sign", "verify"}),
        )


def _verify_foundation_resources(
    foundation: Mapping[str, object],
    *,
    subscription_id: str,
) -> None:
    outputs = _foundation_outputs(foundation)
    for name in (
        "managedEnvironmentResourceId",
        "presentationIdentityResourceId",
    ):
        _verify_resource(
            _string(outputs[name], field=name),
            subscription_id=subscription_id,
        )
    _verify_private_storage_account(
        _string(
            outputs["replayStorageAccountResourceId"],
            field="replay storage account",
        ),
        subscription_id=subscription_id,
    )
    _verify_private_key_vault(
        _string(outputs["keyVaultResourceId"], field="Key Vault"),
        subscription_id=subscription_id,
    )
    _verify_private_blob_container(
        _string(
            outputs["incidentAssetContainerResourceId"],
            field="incident asset container",
        ),
        subscription_id=subscription_id,
    )
    _verify_foundation_key_heads(
        foundation,
        subscription_id=subscription_id,
    )


def _key_resource_parts(resource_id: str) -> tuple[str, str]:
    segments = [segment for segment in resource_id.split("/") if segment]
    lowered = [segment.casefold() for segment in segments]
    try:
        vault_index = lowered.index("vaults")
        key_index = lowered.index("keys", vault_index + 2)
        vault_name = segments[vault_index + 1]
        key_name = segments[key_index + 1]
    except (ValueError, IndexError) as exc:
        raise OrchestrationError(f"invalid Key Vault key resource ID: {resource_id}") from exc
    return vault_name, key_name


def _key_vault_resource_id(key_resource_id: str) -> str:
    resource_id = _azure_resource_id(
        key_resource_id,
        field="Key Vault key resource ID",
    )
    segments = [segment for segment in resource_id.split("/") if segment]
    lowered = [segment.casefold() for segment in segments]
    try:
        key_index = lowered.index("keys")
    except ValueError as exc:
        raise OrchestrationError(f"invalid Key Vault key resource ID: {key_resource_id}") from exc
    if key_index < 2 or lowered[key_index - 2] != "vaults":
        raise OrchestrationError(f"invalid Key Vault key resource ID: {key_resource_id}")
    return "/" + "/".join(segments[:key_index])


def _verify_key_resource_binding(
    key_resource_id: str,
    versioned_key_uri: str,
    *,
    subscription_id: str,
) -> None:
    vault_name, key_name = _key_resource_parts(key_resource_id)
    parsed = urlparse(versioned_key_uri)
    configured_vault_name = parsed.netloc.split(".", 1)[0]
    configured_key_name = _key_name(versioned_key_uri)
    if (
        configured_vault_name.casefold() != vault_name.casefold()
        or configured_key_name.casefold() != key_name.casefold()
    ):
        raise OrchestrationError(
            "versioned Key Vault URI does not match its governed ARM key resource"
        )
    _verify_private_key_vault(
        _key_vault_resource_id(key_resource_id),
        subscription_id=subscription_id,
    )


def _verify_publisher_binding_key_head(
    effective_parameters: Mapping[str, Mapping[str, object]],
    producer: Mapping[str, object],
    *,
    subscription_id: str,
) -> None:
    producer_outputs = _producer_outputs(producer)
    producer_configuration = _mapping(
        json.loads(
            _string(
                producer_outputs["deployedRuntimeConfigurationJson"],
                field="producer configuration",
            )
        ),
        field="producer configuration",
    )
    keys = _mapping(producer_configuration.get("keys"), field="producer keys")
    guidance_binding = _mapping(
        keys.get("guidanceBinding"),
        field="producer guidance binding key",
    )
    expected_uri = _string(
        guidance_binding.get("keyVaultKeyId"),
        field="producer guidance binding key URI",
    )
    resource_id = _string(
        _parameter_value(effective_parameters, "bindingKeyResourceId"),
        field="publisher binding key resource ID",
    )
    vault_name, key_name = _key_resource_parts(resource_id)
    current_uri = _latest_key_uri(
        vault_name=vault_name,
        key_name=key_name,
        subscription_id=subscription_id,
    )
    if current_uri.casefold() != expected_uri.casefold():
        raise OrchestrationError(
            "publisher binding key version does not match the producer trust binding"
        )


def _verify_producer_resources(
    outputs: Mapping[str, object],
    *,
    foundation: Mapping[str, object],
    effective_parameters: Mapping[str, Mapping[str, object]],
    subscription_id: str,
    additional_rbac_bindings: Sequence[Mapping[str, object]] = (),
) -> None:
    foundation_values = _foundation_outputs(foundation)
    validated_outputs = _producer_outputs({"outputs": dict(outputs)})
    configuration = _mapping(
        json.loads(
            _string(
                validated_outputs["deployedRuntimeConfigurationJson"],
                field="producer configuration",
            )
        ),
        field="producer configuration",
    )
    producer_job_id = _job_resource_id(
        validated_outputs["producerJobResourceId"],
        field="producer job",
    )
    producer_image = _digest_pinned_image(
        validated_outputs["producerImage"],
        field="producer image",
    )
    producer_job = _get_resource(
        producer_job_id,
        subscription_id=subscription_id,
    )
    service_bus = _mapping(configuration["serviceBus"], field="producer service bus")
    namespace_host = _string(
        service_bus["namespace"],
        field="producer namespace",
    )
    broker_identity_resource_id = _string(
        service_bus["brokerIdentityResourceId"],
        field="producer broker identity",
    )
    trigger_queue_name = _string(
        service_bus["triggerQueueName"],
        field="producer trigger queue",
    )
    notification_queue_name = _string(
        service_bus["notificationQueueName"],
        field="producer notification queue",
    )
    binding = _mapping(configuration["deploymentBinding"], field="producer binding")
    attached_identity_ids = _string_list(
        binding["attachedIdentityResourceIds"],
        field="producer identities",
    )
    _verify_job_deployment_binding(
        job=producer_job,
        expected_resource_id=producer_job_id,
        expected_environment_resource_id=_string(
            foundation_values["managedEnvironmentResourceId"],
            field="foundation managed environment",
        ),
        expected_identity_resource_ids=attached_identity_ids,
        expected_configuration_digest=_sha256_digest(
            validated_outputs["deployedRuntimeConfigurationDigest"],
            field="producer configuration digest",
        ),
        expected_binding_evidence=_string(
            validated_outputs["bindingEvidenceDigest"],
            field="producer binding evidence",
        ),
    )
    _verify_job_behavior(
        job=producer_job,
        expected_image=producer_image,
        expected_container_name="wc027-enrichment-feed-producer",
        expected_command="athena-context",
        expected_argument="wc027-enrichment-feed-producer",
        expected_rule_name="wc027-signed-binding",
        expected_environment_name="ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON",
        expected_configuration_json=_string(
            validated_outputs["deployedRuntimeConfigurationJson"],
            field="producer configuration JSON",
        ),
        broker_identity_resource_id=broker_identity_resource_id,
        namespace_host=namespace_host,
        queue_name=trigger_queue_name,
    )
    additional_identity_ids = [
        _string(
            _parameter_value(effective_parameters, "feedV2ReaderIdentityResourceId"),
            field="producer presentation reader identity",
        ),
        *_string_list(
            _parameter_value(
                effective_parameters,
                "triggerSubmitterIdentityResourceIds",
            ),
            field="producer trigger submitter identities",
        ),
    ]
    identity_principal_ids = _verify_identities(
        configuration,
        additional_identity_resource_ids=[
            *attached_identity_ids,
            *additional_identity_ids,
        ],
        rbac_identity_resource_ids=[
            *attached_identity_ids,
            *additional_identity_ids,
        ],
        subscription_id=subscription_id,
    )
    allowed_principal_ids = set(identity_principal_ids.values())
    expected_assignments = _producer_expected_rbac_assignments(
        binding,
        configuration=configuration,
        outputs=validated_outputs,
        foundation_values=foundation_values,
        effective_parameters=effective_parameters,
        principal_ids_by_identity=identity_principal_ids,
        subscription_id=subscription_id,
    )
    assignment_ids_by_principal = _verify_rbac_resources(
        binding,
        expected_assignments=expected_assignments,
        subscription_id=subscription_id,
    )
    effective_assignments_by_principal = _verify_no_broad_effective_assignments(
        allowed_principal_ids,
        subscription_id=subscription_id,
    )
    additional_allowed_assignment_ids: set[str] = set()
    for additional_binding in additional_rbac_bindings:
        additional_allowed_assignment_ids.update(_role_assignment_ids(additional_binding))
    _verify_exact_effective_assignments(
        assignment_ids_by_principal,
        additional_allowed_assignment_ids=additional_allowed_assignment_ids,
        subscription_id=subscription_id,
        effective_assignments_by_principal=effective_assignments_by_principal,
    )
    namespace_name = _string(
        _parameter_value(effective_parameters, "serviceBusNamespaceName"),
        field="producer Service Bus namespace",
    )
    _require_equal(
        namespace_name,
        namespace_host.removesuffix(".servicebus.windows.net"),
        field="producer Service Bus namespace",
    )
    _verify_private_service_bus_namespace(
        job_resource_id=producer_job_id,
        namespace_name=namespace_name,
        subscription_id=subscription_id,
    )
    _verify_service_bus_queue(
        job_resource_id=producer_job_id,
        namespace_name=namespace_name,
        queue_name=trigger_queue_name,
        profile_name="producer trigger",
        expected_profile=PRODUCER_TRIGGER_QUEUE_PROFILE,
        subscription_id=subscription_id,
    )
    _verify_service_bus_queue(
        job_resource_id=producer_job_id,
        namespace_name=namespace_name,
        queue_name=notification_queue_name,
        profile_name="notification outbox",
        expected_profile=NOTIFICATION_QUEUE_PROFILE,
        subscription_id=subscription_id,
    )
    _require_resource_id_equal(
        validated_outputs["triggerQueueResourceId"],
        (
            f"{_resource_group_scope(producer_job_id)}/providers/"
            f"Microsoft.ServiceBus/namespaces/{namespace_name}/queues/"
            f"{trigger_queue_name}"
        ),
        field="producer trigger queue output",
    )
    _require_resource_id_equal(
        validated_outputs["notificationQueueResourceId"],
        (
            f"{_resource_group_scope(producer_job_id)}/providers/"
            f"Microsoft.ServiceBus/namespaces/{namespace_name}/queues/"
            f"{notification_queue_name}"
        ),
        field="producer notification queue output",
    )
    replay_id = _string(
        foundation_values["replayStorageAccountResourceId"],
        field="replay storage",
    )
    correlation_id = _string(
        _parameter_value(effective_parameters, "correlationSourceStorageAccountResourceId"),
        field="correlation storage",
    )
    _verify_private_storage_account(
        replay_id,
        subscription_id=subscription_id,
    )
    _verify_private_storage_account(
        correlation_id,
        subscription_id=subscription_id,
    )
    artifacts = (
        foundation_values["incidentAssetContainerResourceId"],
        f"{replay_id}/blobServices/default/containers/"
        f"{_mapping(configuration['enrichmentFeedAssets'], field='assets')['containerName']}",
        f"{replay_id}/tableServices/default/tables/"
        f"{_mapping(configuration['feedRegistry'], field='registry')['tableName']}",
        f"{replay_id}/tableServices/default/tables/"
        f"{_mapping(configuration['guidanceActivation'], field='activation')['tableName']}",
        f"{correlation_id}/blobServices/default/containers/"
        f"{_mapping(configuration['guidanceAuthoritySource'], field='authority')['containerName']}",
    )
    for resource_id in artifacts:
        _verify_resource(
            _string(resource_id, field="storage artifact"),
            subscription_id=subscription_id,
        )
    for resource_id in (artifacts[1], artifacts[4]):
        _verify_private_blob_container(
            _string(resource_id, field="private Blob container"),
            subscription_id=subscription_id,
        )
    for output_name, expected_resource_id in zip(
        (
            "feedV2ContainerResourceId",
            "feedRegistryTableResourceId",
            "guidanceActivationTableResourceId",
            "guidanceAuthoritySourceContainerResourceId",
        ),
        artifacts[1:],
        strict=True,
    ):
        _require_resource_id_equal(
            validated_outputs[output_name],
            expected_resource_id,
            field=f"producer {output_name}",
        )
    collector_key = _mapping(
        configuration["monitoringCollectorKey"],
        field="collector key",
    )
    _verify_key(
        _string(collector_key["keyVaultKeyId"], field="collector key URI"),
        subscription_id=subscription_id,
        required_operations=frozenset({"verify"}),
    )
    configured_keys = _mapping(configuration["keys"], field="producer keys")
    for parameter_name, configured_key in (
        ("monitoringCollectorKeyResourceId", collector_key),
        (
            "correlationBindingKeyResourceId",
            _mapping(
                configured_keys["correlationBinding"],
                field="producer correlation-binding key",
            ),
        ),
        (
            "guidanceBindingKeyResourceId",
            _mapping(
                configured_keys["guidanceBinding"],
                field="producer guidance-binding key",
            ),
        ),
        (
            "changeKeyResourceId",
            _mapping(configured_keys["change"], field="producer change key"),
        ),
        (
            "monitoringIntentKeyResourceId",
            _mapping(
                configured_keys["monitoringIntent"],
                field="producer monitoring-intent key",
            ),
        ),
    ):
        _verify_key_resource_binding(
            _azure_resource_id(
                _parameter_value(effective_parameters, parameter_name),
                field=f"producer {parameter_name}",
            ),
            _string(
                configured_key["keyVaultKeyId"],
                field=f"producer {parameter_name} URI",
            ),
            subscription_id=subscription_id,
        )
    for name, value in configured_keys.items():
        configured_key = _mapping(value, field=f"producer key {name}")
        _verify_key(
            _string(
                configured_key["keyVaultKeyId"],
                field=f"producer key {name} URI",
            ),
            subscription_id=subscription_id,
            required_operations=(
                frozenset({"sign"})
                if name in {"report", "guidance", "enrichment", "feed", "notification"}
                else frozenset({"verify"})
            ),
        )
    expected_foundation_keys = {
        "incident": foundation_values["incidentSigningKeyUriWithVersion"],
        "feed": foundation_values["incidentFeedV2SigningKeyUriWithVersion"],
        "report": foundation_values["incidentReportSigningKeyUriWithVersion"],
        "guidance": foundation_values["incidentGuidanceSigningKeyUriWithVersion"],
        "enrichment": foundation_values["incidentEnrichmentSigningKeyUriWithVersion"],
        "notification": foundation_values["incidentNotificationSigningKeyUriWithVersion"],
    }
    for name, expected_uri in expected_foundation_keys.items():
        configured_key = _mapping(
            configured_keys[name],
            field=f"producer key {name}",
        )
        _require_equal(
            configured_key.get("keyVaultKeyId"),
            expected_uri,
            field=f"producer exact {name} key version",
        )


def _verify_publisher_resources(
    outputs: Mapping[str, object],
    *,
    producer: Mapping[str, object],
    effective_parameters: Mapping[str, Mapping[str, object]],
    subscription_id: str,
) -> None:
    validated_outputs = _publisher_outputs({"outputs": dict(outputs)})
    configuration = _mapping(
        json.loads(
            _string(
                validated_outputs["deployedPublisherConfigurationJson"],
                field="publisher configuration",
            )
        ),
        field="publisher configuration",
    )
    publisher_job_id = _job_resource_id(
        validated_outputs["publisherJobResourceId"],
        field="publisher job",
    )
    publisher_job = _get_resource(
        publisher_job_id,
        subscription_id=subscription_id,
    )
    service_bus = _mapping(configuration["serviceBus"], field="publisher service bus")
    namespace_host = _string(
        service_bus["namespace"],
        field="publisher namespace",
    )
    namespace_name = namespace_host.removesuffix(".servicebus.windows.net")
    _verify_private_service_bus_namespace(
        job_resource_id=publisher_job_id,
        namespace_name=namespace_name,
        subscription_id=subscription_id,
    )
    broker_identity_resource_id = _string(
        service_bus["brokerIdentityResourceId"],
        field="publisher broker identity",
    )
    request_queue_name = _string(
        service_bus["requestQueueName"],
        field="publisher request queue",
    )
    trigger_queue_name = _string(
        service_bus["triggerQueueName"],
        field="publisher trigger queue",
    )
    binding = _mapping(configuration["deploymentBinding"], field="publisher binding")
    attached_identity_ids = _string_list(
        binding["attachedIdentityResourceIds"],
        field="publisher identities",
    )
    producer_outputs = _producer_outputs(producer)
    _verify_job_deployment_binding(
        job=publisher_job,
        expected_resource_id=publisher_job_id,
        expected_environment_resource_id=_string(
            _parameter_value(effective_parameters, "managedEnvironmentResourceId"),
            field="publisher managed environment",
        ),
        expected_identity_resource_ids=attached_identity_ids,
        expected_configuration_digest=_sha256_digest(
            validated_outputs["deployedPublisherConfigurationDigest"],
            field="publisher configuration digest",
        ),
        expected_binding_evidence=_string(
            validated_outputs["bindingEvidenceDigest"],
            field="publisher binding evidence",
        ),
        expected_embedded_configuration_digest=_sha256_digest(
            producer_outputs["deployedRuntimeConfigurationDigest"],
            field="producer configuration digest",
        ),
    )
    _verify_job_behavior(
        job=publisher_job,
        expected_image=_digest_pinned_image(
            validated_outputs["publisherImage"],
            field="publisher image",
        ),
        expected_container_name="wc027-guidance-authority-publisher",
        expected_command="athena-context",
        expected_argument="wc027-guidance-authority-publisher",
        expected_rule_name="wc027-guidance-authority-request",
        expected_environment_name=("ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON"),
        expected_configuration_json=_string(
            validated_outputs["deployedPublisherConfigurationJson"],
            field="publisher configuration JSON",
        ),
        broker_identity_resource_id=broker_identity_resource_id,
        namespace_host=namespace_host,
        queue_name=request_queue_name,
    )
    additional_identity_ids = _parameter_value(
        effective_parameters,
        "requestSubmitterIdentityResourceIds",
    )
    if not isinstance(additional_identity_ids, list) or any(
        not isinstance(item, str) for item in additional_identity_ids
    ):
        raise OrchestrationError("publisher submitter identity binding is invalid")
    identity_principal_ids = _verify_identities(
        configuration,
        additional_identity_resource_ids=[
            *attached_identity_ids,
            *additional_identity_ids,
        ],
        rbac_identity_resource_ids=[
            *attached_identity_ids,
            *additional_identity_ids,
        ],
        subscription_id=subscription_id,
    )
    allowed_principal_ids = set(identity_principal_ids.values())
    expected_assignments = _publisher_expected_rbac_assignments(
        binding,
        configuration=configuration,
        outputs=validated_outputs,
        effective_parameters=effective_parameters,
        principal_ids_by_identity=identity_principal_ids,
        subscription_id=subscription_id,
    )
    assignment_ids_by_principal = _verify_rbac_resources(
        binding,
        expected_assignments=expected_assignments,
        subscription_id=subscription_id,
    )
    effective_assignments_by_principal = _verify_no_broad_effective_assignments(
        allowed_principal_ids,
        subscription_id=subscription_id,
    )
    producer_configuration_for_rbac = _mapping(
        json.loads(
            _string(
                producer_outputs["deployedRuntimeConfigurationJson"],
                field="producer configuration",
            )
        ),
        field="producer configuration",
    )
    producer_binding_for_rbac = _mapping(
        producer_configuration_for_rbac.get("deploymentBinding"),
        field="producer deployment binding",
    )
    additional_allowed_assignment_ids = _role_assignment_ids(producer_binding_for_rbac)
    _verify_exact_effective_assignments(
        assignment_ids_by_principal,
        additional_allowed_assignment_ids=additional_allowed_assignment_ids,
        subscription_id=subscription_id,
        effective_assignments_by_principal=effective_assignments_by_principal,
    )
    _verify_service_bus_queue(
        job_resource_id=publisher_job_id,
        namespace_name=namespace_name,
        queue_name=request_queue_name,
        profile_name="publisher request",
        expected_profile=PUBLISHER_REQUEST_QUEUE_PROFILE,
        subscription_id=subscription_id,
    )
    _verify_service_bus_queue(
        job_resource_id=publisher_job_id,
        namespace_name=namespace_name,
        queue_name=trigger_queue_name,
        profile_name="producer trigger",
        expected_profile=PRODUCER_TRIGGER_QUEUE_PROFILE,
        subscription_id=subscription_id,
    )
    for output_name, queue_name in (
        ("requestQueueResourceId", request_queue_name),
        ("triggerQueueResourceId", trigger_queue_name),
    ):
        _require_resource_id_equal(
            validated_outputs[output_name],
            (
                f"{_resource_group_scope(publisher_job_id)}/providers/"
                f"Microsoft.ServiceBus/namespaces/{namespace_name}/queues/{queue_name}"
            ),
            field=f"publisher {output_name}",
        )
    _require_resource_id_equal(
        validated_outputs["triggerQueueResourceId"],
        producer_outputs["triggerQueueResourceId"],
        field="publisher-to-producer trigger queue handoff",
    )
    authority_storage_id = _azure_resource_id(
        _parameter_value(effective_parameters, "authorityStorageAccountResourceId"),
        field="publisher authority storage",
    )
    activation_storage_id = _azure_resource_id(
        _parameter_value(effective_parameters, "activationStorageAccountResourceId"),
        field="publisher activation storage",
    )
    _verify_private_storage_account(
        authority_storage_id,
        subscription_id=subscription_id,
    )
    if activation_storage_id.casefold() != authority_storage_id.casefold():
        _verify_private_storage_account(
            activation_storage_id,
            subscription_id=subscription_id,
        )
    authority_assets = _mapping(
        configuration["authorityAssets"],
        field="publisher authority assets",
    )
    guidance_activation = _mapping(
        configuration["guidanceActivation"],
        field="publisher guidance activation",
    )
    authority_container_id = (
        f"{authority_storage_id}/blobServices/default/containers/"
        f"{_string(authority_assets['containerName'], field='authority container')}"
    )
    activation_table_id = (
        f"{activation_storage_id}/tableServices/default/tables/"
        f"{_string(guidance_activation['tableName'], field='activation table')}"
    )
    for resource_id in (authority_container_id, activation_table_id):
        _verify_resource(resource_id, subscription_id=subscription_id)
    _verify_private_blob_container(
        authority_container_id,
        subscription_id=subscription_id,
    )
    _require_resource_id_equal(
        validated_outputs["authorityContainerResourceId"],
        authority_container_id,
        field="publisher authority container output",
    )
    _require_resource_id_equal(
        validated_outputs["activationTableResourceId"],
        activation_table_id,
        field="publisher activation table output",
    )
    for key_name, parameter_name, required_operations in (
        ("requestKey", "requestKeyResourceId", frozenset({"verify"})),
        ("bindingSigningKey", "bindingKeyResourceId", frozenset({"sign"})),
    ):
        key = _mapping(configuration[key_name], field=key_name)
        key_uri = _string(
            key["keyVaultKeyId"],
            field=f"{key_name}.keyVaultKeyId",
        )
        _verify_key_resource_binding(
            _azure_resource_id(
                _parameter_value(effective_parameters, parameter_name),
                field=f"publisher {parameter_name}",
            ),
            key_uri,
            subscription_id=subscription_id,
        )
        _verify_key(
            key_uri,
            subscription_id=subscription_id,
            required_operations=required_operations,
        )
    binding_key_resource_id = _azure_resource_id(
        _parameter_value(effective_parameters, "bindingKeyResourceId"),
        field="publisher binding key resource",
    )
    _require_resource_id_equal(
        validated_outputs["bindingKeyResourceId"],
        binding_key_resource_id,
        field="publisher binding key output",
    )
    producer_job = _get_resource(
        _job_resource_id(producer_outputs["producerJobResourceId"], field="producer job"),
        subscription_id=subscription_id,
    )
    _require_resource_id_equal(
        _mapping(publisher_job["properties"], field="publisher job properties").get(
            "environmentId"
        ),
        _mapping(producer_job["properties"], field="producer job properties").get("environmentId"),
        field="publisher managed environment",
    )
    producer_configuration = _mapping(
        json.loads(
            _string(
                producer_outputs["deployedRuntimeConfigurationJson"],
                field="producer configuration",
            )
        ),
        field="producer configuration",
    )
    producer_keys = _mapping(producer_configuration["keys"], field="producer keys")
    guidance_binding = _mapping(
        producer_keys["guidanceBinding"],
        field="producer guidance binding key",
    )
    publisher_binding = _mapping(
        configuration["bindingSigningKey"],
        field="publisher binding key",
    )
    _require_equal(
        publisher_binding.get("keyVaultKeyId"),
        guidance_binding.get("keyVaultKeyId"),
        field="publisher exact guidance-binding key version",
    )
    _require_equal(
        publisher_binding.get("keyId"),
        guidance_binding.get("keyId"),
        field="publisher guidance-binding logical key ID",
    )
    _require_equal(
        publisher_binding.get("keyFingerprint"),
        guidance_binding.get("keyFingerprint"),
        field="publisher guidance-binding key fingerprint",
    )
    _verify_latest_key_uri(
        _string(
            publisher_binding.get("keyVaultKeyId"),
            field="publisher guidance-binding key URI",
        ),
        subscription_id=subscription_id,
    )


def _parameter_bindings(
    stage: str,
    effective_parameters: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    if stage == "foundation":
        return {"foundationParametersSha256": _foundation_parameter_digest(effective_parameters)}
    names = {
        "producer": (
            "correlationSourceStorageAccountResourceId",
            "correlationBindingKeyResourceId",
            "changeKeyResourceId",
            "feedV2ReaderIdentityResourceId",
            "guidanceBindingKeyResourceId",
            "managedEnvironmentResourceId",
            "monitoringCollectorKeyResourceId",
            "monitoringIntentKeyResourceId",
            "registryResourceId",
            "serviceBusNamespaceName",
            "triggerSubmitterIdentityResourceIds",
        ),
        "publisher": (
            "authorityStorageAccountResourceId",
            "activationStorageAccountResourceId",
            "bindingTrustReaderIdentityResourceId",
            "bindingKeyResourceId",
            "managedEnvironmentResourceId",
            "registryResourceId",
            "requestSubmitterIdentityResourceIds",
            "requestKeyResourceId",
            "serviceBusNamespaceName",
        ),
    }.get(stage, ())
    return {name: _parameter_value(effective_parameters, name) for name in names}


def _handoff_outputs(
    stage: str,
    deployment_outputs: Mapping[str, object],
) -> dict[str, object]:
    if stage == "foundation":
        approved_configuration = _mapping(
            deployment_outputs.get("wc016ApprovedConfiguration"),
            field="foundation approved configuration",
        )
        wc027_foundation = _mapping(
            approved_configuration.get("wc027OrchestrationFoundation"),
            field="foundation WC-027 orchestration outputs",
        )
        projected = {
            name: deployment_outputs[name]
            for name in FOUNDATION_OUTPUT_FIELDS
            if name != "wc016ApprovedConfiguration"
        }
        projected["wc016ApprovedConfiguration"] = {
            "wc027OrchestrationFoundation": dict(wc027_foundation)
        }
        _foundation_outputs({"outputs": projected}, require_exact=True)
        return projected
    if stage == "producer":
        projected = dict(deployment_outputs)
        _producer_outputs({"outputs": projected})
        return projected
    if stage == "publisher":
        projected = dict(deployment_outputs)
        _publisher_outputs({"outputs": projected})
        return projected
    if stage == "live-acceptance":
        approved_configuration = _mapping(
            deployment_outputs.get("wc016ApprovedConfiguration"),
            field="live-acceptance approved configuration",
        )
        projected = {
            "wc027DeploymentReadiness": _mapping(
                approved_configuration.get("wc027DeploymentReadiness"),
                field="live-acceptance WC-027 readiness",
            ),
            "publisherInvocationBoundary": dict(PUBLISHER_INVOCATION_BOUNDARY),
        }
        _validate_live_acceptance_handoff_outputs(projected)
        return projected
    raise OrchestrationError(f"unsupported deployment stage: {stage}")


def _bindings_as_parameters(
    bindings: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    return {name: {"value": value} for name, value in bindings.items()}


def _verify_live_dependencies(
    *,
    foundation: Mapping[str, object],
    producer: Mapping[str, object],
    publisher: Mapping[str, object],
    subscription_id: str,
) -> None:
    _verify_foundation_resources(foundation, subscription_id=subscription_id)
    publisher_outputs = _publisher_outputs(publisher)
    publisher_configuration = _mapping(
        json.loads(
            _string(
                publisher_outputs["deployedPublisherConfigurationJson"],
                field="publisher configuration",
            )
        ),
        field="publisher configuration",
    )
    publisher_binding = _mapping(
        publisher_configuration.get("deploymentBinding"),
        field="publisher deployment binding",
    )
    _verify_producer_resources(
        _mapping(producer["outputs"], field="producer outputs"),
        foundation=foundation,
        effective_parameters=_bindings_as_parameters(_handoff_bindings(producer)),
        subscription_id=subscription_id,
        additional_rbac_bindings=(publisher_binding,),
    )
    _verify_publisher_resources(
        _mapping(publisher["outputs"], field="publisher outputs"),
        producer=producer,
        effective_parameters=_bindings_as_parameters(_handoff_bindings(publisher)),
        subscription_id=subscription_id,
    )


def _deployment_outputs(document: object) -> dict[str, Any]:
    root = _mapping(document, field="deployment result")
    properties = _mapping(root.get("properties"), field="deployment properties")
    _require_equal(
        properties.get("provisioningState"),
        "Succeeded",
        field="deployment provisioning state",
    )
    raw_outputs = _mapping(properties.get("outputs"), field="deployment outputs")
    outputs: dict[str, Any] = {}
    for name, raw_output in raw_outputs.items():
        output = _mapping(raw_output, field=f"deployment output {name}")
        if "value" not in output:
            raise OrchestrationError(f"deployment output {name} has no value")
        outputs[name] = output["value"]
    return outputs


def _readiness_sections(
    outputs: Mapping[str, object],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if "wc027DeploymentReadiness" in outputs:
        readiness = _mapping(
            outputs.get("wc027DeploymentReadiness"),
            field="live-acceptance WC-027 readiness output",
        )
    else:
        approved_configuration = _mapping(
            outputs.get("wc016ApprovedConfiguration"),
            field="live-acceptance approved configuration output",
        )
        readiness = _mapping(
            approved_configuration.get("wc027DeploymentReadiness"),
            field="live-acceptance WC-027 readiness output",
        )
    if set(readiness) != {"producer", "publisher"}:
        raise OrchestrationError("live-acceptance WC-027 readiness output has unexpected fields")
    producer_readback = _mapping(
        readiness.get("producer"),
        field="live-acceptance producer readback",
    )
    publisher_readback = _mapping(
        readiness.get("publisher"),
        field="live-acceptance publisher readback",
    )
    if set(producer_readback) != {
        "ready",
        "jobResourceId",
        "image",
        "configurationDigest",
        "bindingEvidenceDigest",
    }:
        raise OrchestrationError("live-acceptance producer readback has unexpected fields")
    if set(publisher_readback) != {
        "ready",
        "jobResourceId",
        "image",
        "configurationDigest",
        "embeddedProducerConfigurationDigest",
        "bindingEvidenceDigest",
    }:
        raise OrchestrationError("live-acceptance publisher readback has unexpected fields")
    if producer_readback.get("ready") is not True:
        raise OrchestrationError("live-acceptance did not confirm producer readiness")
    if publisher_readback.get("ready") is not True:
        raise OrchestrationError("live-acceptance did not confirm publisher readiness")
    return producer_readback, publisher_readback


def _validate_live_acceptance_handoff_outputs(
    outputs: Mapping[str, object],
) -> None:
    _require_exact_fields(
        outputs,
        LIVE_ACCEPTANCE_OUTPUT_FIELDS,
        field="live-acceptance deployment outputs",
    )
    invocation_boundary = _mapping(
        outputs.get("publisherInvocationBoundary"),
        field="publisher invocation boundary",
    )
    _require_exact_fields(
        invocation_boundary,
        frozenset(PUBLISHER_INVOCATION_BOUNDARY),
        field="publisher invocation boundary",
    )
    _require_equal(
        invocation_boundary,
        PUBLISHER_INVOCATION_BOUNDARY,
        field="publisher invocation boundary",
    )
    _readiness_sections(outputs)


def _acceptance_outputs(
    outputs: Mapping[str, object],
    *,
    producer: Mapping[str, object],
    publisher: Mapping[str, object],
) -> None:
    producer_readback, publisher_readback = _readiness_sections(outputs)
    producer_outputs = _producer_outputs(producer)
    publisher_outputs = _publisher_outputs(publisher)
    _require_resource_id_equal(
        producer_readback.get("jobResourceId"),
        producer_outputs["producerJobResourceId"],
        field="live-acceptance producer Job",
    )
    _require_equal(
        producer_readback.get("image"),
        producer_outputs["producerImage"],
        field="live-acceptance producer image",
    )
    _require_equal(
        producer_readback.get("configurationDigest"),
        producer_outputs["deployedRuntimeConfigurationDigest"],
        field="live-acceptance producer configuration digest",
    )
    _require_equal(
        producer_readback.get("bindingEvidenceDigest"),
        producer_outputs["bindingEvidenceDigest"],
        field="live-acceptance producer binding evidence",
    )
    _require_resource_id_equal(
        publisher_readback.get("jobResourceId"),
        publisher_outputs["publisherJobResourceId"],
        field="live-acceptance publisher Job",
    )
    _require_equal(
        publisher_readback.get("image"),
        publisher_outputs["publisherImage"],
        field="live-acceptance publisher image",
    )
    _require_equal(
        publisher_readback.get("configurationDigest"),
        publisher_outputs["deployedPublisherConfigurationDigest"],
        field="live-acceptance publisher configuration digest",
    )
    _require_equal(
        publisher_readback.get("embeddedProducerConfigurationDigest"),
        producer_outputs["deployedRuntimeConfigurationDigest"],
        field="live-acceptance embedded producer configuration digest",
    )
    _require_equal(
        publisher_readback.get("bindingEvidenceDigest"),
        publisher_outputs["bindingEvidenceDigest"],
        field="live-acceptance publisher binding evidence",
    )


def _validate_stage_outputs(
    stage: str,
    outputs: dict[str, Any],
    *,
    producer: Mapping[str, object] | None = None,
    publisher: Mapping[str, object] | None = None,
) -> None:
    wrapper = {"outputs": outputs}
    if stage == "foundation":
        _foundation_outputs(wrapper)
    elif stage == "producer":
        _producer_outputs(wrapper)
    elif stage == "publisher":
        _publisher_outputs(wrapper)
    elif stage == "live-acceptance":
        if producer is None or publisher is None:
            raise OrchestrationError(
                "live-acceptance output validation requires both WC-027 handoffs"
            )
        _acceptance_outputs(outputs, producer=producer, publisher=publisher)
    else:
        raise OrchestrationError(f"unsupported deployment stage: {stage}")


def plan(args: argparse.Namespace) -> Path:
    subscription_id = _canonical_subscription_id(
        args.subscription,
        field="subscription",
    )
    handoff_paths = {
        "foundation": args.foundation_handoff,
        "producer": args.producer_handoff,
        "publisher": args.publisher_handoff,
    }
    receipt_paths = {
        "foundation": args.foundation_receipt,
        "producer": args.producer_receipt,
        "publisher": args.publisher_receipt,
    }
    reviewed_receipt_sha256s = {
        "foundation": args.foundation_reviewed_receipt_sha256,
        "producer": args.producer_reviewed_receipt_sha256,
        "publisher": args.publisher_reviewed_receipt_sha256,
    }
    _validate_stage_inputs(
        stage=args.stage,
        resource_group=args.resource_group,
        foundation_handoff_path=args.foundation_handoff,
        producer_handoff_path=args.producer_handoff,
        publisher_handoff_path=args.publisher_handoff,
    )
    verified_predecessors = _load_verified_predecessors(
        stage=args.stage,
        handoff_paths=handoff_paths,
        receipt_paths=receipt_paths,
        reviewed_receipt_sha256s=reviewed_receipt_sha256s,
    )
    _ensure_evidence_directory_outside_repository(args.evidence_directory)
    allowed_changes = [
        _canonical_subscription_resource_id(
            value,
            subscription_id=subscription_id,
            field="allowed change resource ID",
        )
        for value in args.allow_change
    ]
    if len({value.casefold() for value in allowed_changes}) != len(allowed_changes):
        raise OrchestrationError("allowed change resource IDs must be distinct")
    _ensure_clean_worktree()
    effective = build_effective_parameters(
        stage=args.stage,
        parameter_path=args.parameters,
        foundation_handoff_path=args.foundation_handoff,
        producer_handoff_path=args.producer_handoff,
        publisher_handoff_path=args.publisher_handoff,
    )
    _validate_effective_parameter_subscription_boundary(
        effective,
        subscription_id=subscription_id,
    )
    if args.stage == "producer":
        foundation = _mapping(
            verified_predecessors["foundation"]["handoff"],
            field="verified foundation handoff",
        )
        _verify_handoff_scope(
            foundation,
            subscription_id=subscription_id,
        )
        _verify_foundation_resources(
            foundation,
            subscription_id=subscription_id,
        )
    elif args.stage == "publisher":
        foundation = _mapping(
            verified_predecessors["foundation"]["handoff"],
            field="verified foundation handoff",
        )
        producer = _mapping(
            verified_predecessors["producer"]["handoff"],
            field="verified producer handoff",
        )
        _verify_handoff_scope(
            foundation,
            subscription_id=subscription_id,
        )
        _verify_handoff_scope(
            producer,
            subscription_id=subscription_id,
            resource_group=args.resource_group,
        )
        _verify_foundation_resources(
            foundation,
            subscription_id=subscription_id,
        )
        _verify_producer_resources(
            _mapping(producer["outputs"], field="producer outputs"),
            foundation=foundation,
            effective_parameters=_bindings_as_parameters(_handoff_bindings(producer)),
            subscription_id=subscription_id,
        )
        _verify_publisher_binding_key_head(
            effective,
            producer,
            subscription_id=subscription_id,
        )
    elif args.stage == "live-acceptance":
        foundation = _mapping(
            verified_predecessors["foundation"]["handoff"],
            field="verified foundation handoff",
        )
        producer = _mapping(
            verified_predecessors["producer"]["handoff"],
            field="verified producer handoff",
        )
        publisher = _mapping(
            verified_predecessors["publisher"]["handoff"],
            field="verified publisher handoff",
        )
        _verify_handoff_scope(
            foundation,
            subscription_id=subscription_id,
        )
        producer_resource_group = _string(
            producer.get("resourceGroup"),
            field="producer handoff resource group",
        )
        _verify_handoff_scope(
            producer,
            subscription_id=subscription_id,
            resource_group=producer_resource_group,
        )
        _verify_handoff_scope(
            publisher,
            subscription_id=subscription_id,
            resource_group=producer_resource_group,
        )
        _verify_live_dependencies(
            foundation=foundation,
            producer=producer,
            publisher=publisher,
            subscription_id=subscription_id,
        )
    stem = f"{args.stage}-{args.deployment_name}"
    effective_path = args.evidence_directory / f"{stem}.parameters.json"
    what_if_path = args.evidence_directory / f"{stem}.what-if.json"
    manifest_path = args.evidence_directory / f"{stem}.plan.json"
    _write_new_json(effective_path, _parameter_document(effective))
    _run(
        _az_command(
            operation="validate",
            stage=args.stage,
            deployment_name=args.deployment_name,
            subscription_id=subscription_id,
            location=args.location,
            resource_group=args.resource_group,
            parameter_path=effective_path,
        )
    )
    what_if = _run_json(
        _az_command(
            operation="what-if",
            stage=args.stage,
            deployment_name=args.deployment_name,
            subscription_id=subscription_id,
            location=args.location,
            resource_group=args.resource_group,
            parameter_path=effective_path,
        ),
        field="what-if",
    )
    _validate_subscription_boundary(
        what_if,
        subscription_id=subscription_id,
        field="what-if",
    )
    _write_new_json(what_if_path, what_if)
    violations = evaluate_what_if(
        what_if,
        allowed_change_ids=frozenset(allowed_changes),
    )
    if violations:
        details = "; ".join(f"{item.code}: {item.subject}: {item.detail}" for item in violations)
        raise OrchestrationError(f"WC-029 what-if gate failed: {details}")
    manifest = {
        "schemaVersion": PLAN_SCHEMA_VERSION,
        "stage": args.stage,
        "sourceCommit": SOURCE_COMMIT,
        "subscriptionId": subscription_id,
        "location": args.location,
        "resourceGroup": args.resource_group,
        "deploymentName": args.deployment_name,
        "templatePath": str(TEMPLATES[args.stage].relative_to(ROOT)).replace("\\", "/"),
        "templateSha256": _sha256_file(TEMPLATES[args.stage]),
        "orchestratorSha256": _sha256_file(Path(__file__).resolve()),
        "preflightSha256": _sha256_file(PREFLIGHT_PATH),
        "baseParameterPath": str(args.parameters.resolve()),
        "baseParameterSha256": _sha256_file(args.parameters),
        "effectiveParameterPath": str(effective_path.resolve()),
        "effectiveParameterSha256": _sha256_file(effective_path),
        "whatIfPath": str(what_if_path.resolve()),
        "whatIfSha256": _sha256_file(what_if_path),
        "allowedChangeResourceIds": sorted(allowed_changes),
        "foundationHandoffPath": (
            None if args.foundation_handoff is None else str(args.foundation_handoff.resolve())
        ),
        "foundationHandoffSha256": (
            None if args.foundation_handoff is None else _sha256_file(args.foundation_handoff)
        ),
        "producerHandoffPath": (
            None if args.producer_handoff is None else str(args.producer_handoff.resolve())
        ),
        "producerHandoffSha256": (
            None if args.producer_handoff is None else _sha256_file(args.producer_handoff)
        ),
        "publisherHandoffPath": (
            None if args.publisher_handoff is None else str(args.publisher_handoff.resolve())
        ),
        "publisherHandoffSha256": (
            None if args.publisher_handoff is None else _sha256_file(args.publisher_handoff)
        ),
        "predecessorReceipts": _predecessor_receipt_references(verified_predecessors),
    }
    _write_new_json(manifest_path, manifest)
    return manifest_path


def apply(args: argparse.Namespace) -> Path:
    reviewed_digest = _sha256_digest(
        args.reviewed_plan_sha256,
        field="reviewed plan SHA-256",
    )
    if _sha256_file(args.plan_manifest) != reviewed_digest:
        raise OrchestrationError("plan manifest does not match the independently reviewed SHA-256")
    _ensure_evidence_directory_outside_repository(args.plan_manifest.parent)
    _ensure_clean_worktree()
    manifest = _load_plan_manifest(args.plan_manifest)
    if manifest.get("schemaVersion") != PLAN_SCHEMA_VERSION:
        raise OrchestrationError("unsupported WC-029 deployment plan schema")
    stage = _string(manifest.get("stage"), field="plan stage")
    if stage not in STAGES:
        raise OrchestrationError("plan has an unsupported deployment stage")
    if manifest.get("sourceCommit") != SOURCE_COMMIT:
        raise OrchestrationError("plan source commit is not the current exact commit")
    template = TEMPLATES[stage]
    if _sha256_file(template) != manifest.get("templateSha256"):
        raise OrchestrationError("planned Bicep template changed after review")
    if _sha256_file(Path(__file__).resolve()) != manifest.get("orchestratorSha256"):
        raise OrchestrationError("orchestrator implementation changed after review")
    if _sha256_file(PREFLIGHT_PATH) != manifest.get("preflightSha256"):
        raise OrchestrationError("preflight implementation changed after review")
    effective_path = Path(
        _string(manifest.get("effectiveParameterPath"), field="effective parameters")
    )
    what_if_path = Path(_string(manifest.get("whatIfPath"), field="what-if path"))
    base_parameter_path = Path(_string(manifest.get("baseParameterPath"), field="base parameters"))
    if _sha256_file(base_parameter_path) != manifest.get("baseParameterSha256"):
        raise OrchestrationError("base parameter artifact changed after review")
    if _sha256_file(effective_path) != manifest.get("effectiveParameterSha256"):
        raise OrchestrationError("effective parameter artifact changed after review")
    if _sha256_file(what_if_path) != manifest.get("whatIfSha256"):
        raise OrchestrationError("what-if artifact changed after review")
    for prefix in ("foundation", "producer", "publisher"):
        handoff_path_value = manifest.get(f"{prefix}HandoffPath")
        handoff_digest = manifest.get(f"{prefix}HandoffSha256")
        if handoff_path_value is None:
            if handoff_digest is not None:
                raise OrchestrationError(f"{prefix} handoff digest has no path")
            continue
        handoff_path = Path(_string(handoff_path_value, field=f"{prefix} handoff"))
        if _sha256_file(handoff_path) != handoff_digest:
            raise OrchestrationError(f"{prefix} handoff changed after review")
    subscription_id = _canonical_subscription_id(
        manifest.get("subscriptionId"),
        field="subscription",
    )
    what_if = _read_json(what_if_path)
    _validate_subscription_boundary(
        what_if,
        subscription_id=subscription_id,
        field="reviewed what-if",
    )
    allowed_change_ids = (
        _string_list(
            manifest.get("allowedChangeResourceIds"),
            field="allowed changes",
        )
        if manifest.get("allowedChangeResourceIds")
        else []
    )
    for index, resource_id in enumerate(allowed_change_ids):
        _canonical_subscription_resource_id(
            resource_id,
            subscription_id=subscription_id,
            field=f"allowed changes[{index}]",
        )
    violations = evaluate_what_if(
        what_if,
        allowed_change_ids=frozenset(allowed_change_ids),
    )
    if violations:
        raise OrchestrationError("reviewed what-if no longer passes the zero-delete gate")
    location = _string(manifest.get("location"), field="location")
    resource_group_value = manifest.get("resourceGroup")
    resource_group = (
        None
        if resource_group_value is None
        else _string(resource_group_value, field="resource group")
    )
    deployment_name = _string(manifest.get("deploymentName"), field="deployment name")
    foundation_path = manifest.get("foundationHandoffPath")
    producer_path = manifest.get("producerHandoffPath")
    publisher_path = manifest.get("publisherHandoffPath")
    predecessor_receipt_references = _mapping(
        manifest.get("predecessorReceipts"),
        field="plan predecessor receipts",
    )
    receipt_paths = {
        predecessor: (
            None
            if predecessor not in predecessor_receipt_references
            else Path(
                _string(
                    _mapping(
                        predecessor_receipt_references[predecessor],
                        field=f"plan predecessor receipt {predecessor}",
                    ).get("path"),
                    field=f"{predecessor} receipt path",
                )
            )
        )
        for predecessor in ("foundation", "producer", "publisher")
    }
    reviewed_receipt_sha256s = {
        predecessor: (
            None
            if predecessor not in predecessor_receipt_references
            else _string(
                _mapping(
                    predecessor_receipt_references[predecessor],
                    field=f"plan predecessor receipt {predecessor}",
                ).get("reviewedSha256"),
                field=f"{predecessor} reviewed receipt SHA-256",
            )
        )
        for predecessor in ("foundation", "producer", "publisher")
    }
    handoff_paths = {
        "foundation": (None if foundation_path is None else Path(str(foundation_path))),
        "producer": None if producer_path is None else Path(str(producer_path)),
        "publisher": (None if publisher_path is None else Path(str(publisher_path))),
    }
    _validate_stage_inputs(
        stage=stage,
        resource_group=resource_group,
        foundation_handoff_path=handoff_paths["foundation"],
        producer_handoff_path=handoff_paths["producer"],
        publisher_handoff_path=handoff_paths["publisher"],
    )
    verified_predecessors = _load_verified_predecessors(
        stage=stage,
        handoff_paths=handoff_paths,
        receipt_paths=receipt_paths,
        reviewed_receipt_sha256s=reviewed_receipt_sha256s,
    )
    effective_parameters = _load_parameters(effective_path)
    _validate_effective_parameter_subscription_boundary(
        effective_parameters,
        subscription_id=subscription_id,
    )
    foundation = (
        None
        if "foundation" not in verified_predecessors
        else _mapping(
            verified_predecessors["foundation"]["handoff"],
            field="verified foundation handoff",
        )
    )
    producer = (
        None
        if "producer" not in verified_predecessors
        else _mapping(
            verified_predecessors["producer"]["handoff"],
            field="verified producer handoff",
        )
    )
    publisher = (
        None
        if "publisher" not in verified_predecessors
        else _mapping(
            verified_predecessors["publisher"]["handoff"],
            field="verified publisher handoff",
        )
    )
    if stage == "producer":
        if foundation is None:
            raise OrchestrationError("producer plan lost its foundation handoff")
        _verify_handoff_scope(
            foundation,
            subscription_id=subscription_id,
        )
        _verify_foundation_resources(
            foundation,
            subscription_id=subscription_id,
        )
    elif stage == "publisher":
        if foundation is None or producer is None:
            raise OrchestrationError("publisher plan lost required handoffs")
        _verify_handoff_scope(
            foundation,
            subscription_id=subscription_id,
        )
        _verify_handoff_scope(
            producer,
            subscription_id=subscription_id,
            resource_group=resource_group,
        )
        _verify_foundation_resources(
            foundation,
            subscription_id=subscription_id,
        )
        _verify_producer_resources(
            _mapping(producer["outputs"], field="producer outputs"),
            foundation=foundation,
            effective_parameters=_bindings_as_parameters(_handoff_bindings(producer)),
            subscription_id=subscription_id,
        )
        _verify_publisher_binding_key_head(
            effective_parameters,
            producer,
            subscription_id=subscription_id,
        )
    elif stage == "live-acceptance":
        if foundation is None or producer is None or publisher is None:
            raise OrchestrationError("live-acceptance plan lost required handoffs")
        _verify_handoff_scope(
            foundation,
            subscription_id=subscription_id,
        )
        producer_resource_group = _string(
            producer.get("resourceGroup"),
            field="producer handoff resource group",
        )
        _verify_handoff_scope(
            producer,
            subscription_id=subscription_id,
            resource_group=producer_resource_group,
        )
        _verify_handoff_scope(
            publisher,
            subscription_id=subscription_id,
            resource_group=producer_resource_group,
        )
        _verify_live_dependencies(
            foundation=foundation,
            producer=producer,
            publisher=publisher,
            subscription_id=subscription_id,
        )
    current_what_if = _run_json(
        _az_command(
            operation="what-if",
            stage=stage,
            deployment_name=deployment_name,
            subscription_id=subscription_id,
            location=location,
            resource_group=resource_group,
            parameter_path=effective_path,
        ),
        field="current what-if",
    )
    _validate_subscription_boundary(
        current_what_if,
        subscription_id=subscription_id,
        field="current what-if",
    )
    if _canonical_json_bytes(current_what_if) != _canonical_json_bytes(what_if):
        raise OrchestrationError(
            "Azure state changed after review; current what-if differs from the plan"
        )
    result = _run_json(
        _az_command(
            operation="create",
            stage=stage,
            deployment_name=deployment_name,
            subscription_id=subscription_id,
            location=location,
            resource_group=resource_group,
            parameter_path=effective_path,
        ),
        field="deployment create",
    )
    outputs = _deployment_outputs(result)
    _validate_subscription_boundary(
        outputs,
        subscription_id=subscription_id,
        field="deployment outputs",
    )
    _validate_stage_outputs(
        stage,
        outputs,
        producer=producer,
        publisher=publisher,
    )
    if stage == "foundation":
        _verify_foundation_resources(
            {"outputs": outputs},
            subscription_id=subscription_id,
        )
    elif stage == "producer":
        if foundation is None:
            raise OrchestrationError("producer plan lost its foundation handoff")
        _verify_producer_resources(
            outputs,
            foundation=foundation,
            effective_parameters=effective_parameters,
            subscription_id=subscription_id,
        )
    elif stage == "live-acceptance":
        if foundation is None or producer is None or publisher is None:
            raise OrchestrationError("live-acceptance plan lost required handoffs")
        _verify_live_dependencies(
            foundation=foundation,
            producer=producer,
            publisher=publisher,
            subscription_id=subscription_id,
        )
    elif stage == "publisher":
        if foundation is None or producer is None:
            raise OrchestrationError("publisher plan lost required handoffs")
        deployed_publisher_configuration = _mapping(
            json.loads(
                _string(
                    outputs["deployedPublisherConfigurationJson"],
                    field="publisher configuration",
                )
            ),
            field="publisher configuration",
        )
        deployed_publisher_binding = _mapping(
            deployed_publisher_configuration.get("deploymentBinding"),
            field="publisher deployment binding",
        )
        _verify_producer_resources(
            _mapping(producer["outputs"], field="producer outputs"),
            foundation=foundation,
            effective_parameters=_bindings_as_parameters(_handoff_bindings(producer)),
            subscription_id=subscription_id,
            additional_rbac_bindings=(deployed_publisher_binding,),
        )
        _verify_publisher_resources(
            outputs,
            producer=producer,
            effective_parameters=effective_parameters,
            subscription_id=subscription_id,
        )
    bindings = _parameter_bindings(stage, effective_parameters)
    handoff_outputs = _handoff_outputs(stage, outputs)
    predecessor_receipt_hashes = _predecessor_receipt_hashes(verified_predecessors)
    handoff = {
        "schemaVersion": HANDOFF_SCHEMA_VERSION,
        "stage": stage,
        "sourceCommit": SOURCE_COMMIT,
        "subscriptionId": subscription_id,
        "resourceGroup": resource_group,
        "deploymentName": deployment_name,
        "outputs": handoff_outputs,
        "outputsSha256": _sha256_bytes(_canonical_json_bytes(handoff_outputs)),
        "parameterBindings": bindings,
        "parameterBindingsSha256": _sha256_bytes(_canonical_json_bytes(bindings)),
        "planManifestSha256": _sha256_file(args.plan_manifest),
        "predecessorReceiptSha256s": predecessor_receipt_hashes,
    }
    handoff_path = args.plan_manifest.with_name(f"{stage}-{deployment_name}.handoff.json")
    _write_new_json(handoff_path, handoff)
    receipt = {
        "schemaVersion": RECEIPT_SCHEMA_VERSION,
        "stage": stage,
        "sourceCommit": SOURCE_COMMIT,
        "subscriptionId": subscription_id,
        "resourceGroup": resource_group,
        "deploymentName": deployment_name,
        "planManifestPath": str(args.plan_manifest.resolve()),
        "planManifestSha256": _sha256_file(args.plan_manifest),
        "reviewedPlanSha256": reviewed_digest,
        "handoffPath": str(handoff_path.resolve()),
        "handoffSha256": _sha256_file(handoff_path),
        "predecessorReceiptSha256s": predecessor_receipt_hashes,
    }
    receipt_path = args.plan_manifest.with_name(f"{stage}-{deployment_name}.receipt.json")
    _write_new_json(receipt_path, receipt)
    return receipt_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Plan and apply the governed WC-029 foundation -> WC-027 producer -> "
            "WC-027 publisher -> WC-013 live-acceptance deployment sequence."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--stage", choices=STAGES, required=True)
    plan_parser.add_argument("--subscription", required=True)
    plan_parser.add_argument("--location", required=True)
    plan_parser.add_argument("--resource-group")
    plan_parser.add_argument("--deployment-name", required=True)
    plan_parser.add_argument("--parameters", type=Path, required=True)
    plan_parser.add_argument("--evidence-directory", type=Path, required=True)
    plan_parser.add_argument("--foundation-handoff", type=Path)
    plan_parser.add_argument("--foundation-receipt", type=Path)
    plan_parser.add_argument("--foundation-reviewed-receipt-sha256")
    plan_parser.add_argument("--producer-handoff", type=Path)
    plan_parser.add_argument("--producer-receipt", type=Path)
    plan_parser.add_argument("--producer-reviewed-receipt-sha256")
    plan_parser.add_argument("--publisher-handoff", type=Path)
    plan_parser.add_argument("--publisher-receipt", type=Path)
    plan_parser.add_argument("--publisher-reviewed-receipt-sha256")
    plan_parser.add_argument("--allow-change", action="append", default=[])
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--plan-manifest", type=Path, required=True)
    apply_parser.add_argument("--reviewed-plan-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        output = plan(args) if args.command == "plan" else apply(args)
    except (OrchestrationError, PreflightInputError, json.JSONDecodeError) as exc:
        print(f"WC-029 orchestration failed closed: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
