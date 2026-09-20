from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Never
from urllib.parse import parse_qs, urlencode, urlparse
from uuid import UUID, uuid4, uuid5

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from athena_context.contracts import (  # noqa: E402
    MAX_GUIDANCE_AUTHORITY_BINDING_BYTES,
    PublishedGuidanceAuthority,
    PublishedGuidanceAuthorityBinding,
)
from athena_context.enrichment.production import (  # noqa: E402
    Wc027EnrichmentFeedProductionConfiguration,
)
from athena_context.guidance.production import (  # noqa: E402
    Wc027GuidanceAuthorityPublisherConfiguration,
)
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
    timeout=30,
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
ARM_GUID_NAMESPACE = UUID("11fb06fb-712d-4ddd-98c7-e71bbd588830")
GRAPH_HOST = "graph.microsoft.com"
ARM_HOST = "management.azure.com"
MAX_TRANSITIVE_GROUPS = 10_000
MAX_GRAPH_MEMBERSHIP_PAGES = 128
MAX_AUTHORIZATION_SCAN_PAGES = 512
MAX_AUTHORIZATION_SCAN_ITEMS = 10_000
MAX_DENY_ASSIGNMENT_PAGES = 128
MAX_DENY_ASSIGNMENTS = 10_000
MAX_APPROVED_TRIGGER_QUEUE_TRANSITION_ASSIGNMENTS = 4
MAX_APPROVED_ROTATION_TRANSITION_ASSIGNMENTS = 32
MAX_LEGACY_CRYPTO_USER_MIGRATION_ASSIGNMENTS = 5
MAX_LEGACY_ACR_PULL_MIGRATION_ASSIGNMENTS = 16
MAX_AUTHORITY_CHECKPOINT_VERSIONS = 4096
MAX_AUTHORITY_CHECKPOINT_CONTENT_BYTES = 64 * 1024 * 1024
MAX_REVIEWED_ARTIFACT_BYTES = 64 * 1024 * 1024
GIT_COMMAND_TIMEOUT_SECONDS = 30
AZURE_READ_TIMEOUT_SECONDS = 180
AZURE_LIST_TIMEOUT_SECONDS = 300
BICEP_BUILD_TIMEOUT_SECONDS = 300
DEPLOYMENT_VALIDATE_TIMEOUT_SECONDS = 900
DEPLOYMENT_WHAT_IF_TIMEOUT_SECONDS = 1_800
DEPLOYMENT_CREATE_TIMEOUT_SECONDS = 3_600
CONTAINER_APP_JOB_START_TIMEOUT_SECONDS = 300
DEPLOYMENT_TIMESTAMP_FUTURE_SKEW = timedelta(minutes=5)
DEPLOYMENT_NONTERMINAL_STATES = frozenset(
    {
        "NotSpecified",
        "Accepted",
        "Running",
        "Ready",
        "Creating",
        "Created",
        "Updating",
        "Deleting",
    }
)
DEPLOYMENT_TERMINAL_FAILURE_STATES = frozenset(
    {
        "Failed",
        "Canceled",
        "Cancelled",
        "Deleted",
    }
)
READBACK_MAX_ATTEMPTS = 8
READBACK_RETRY_SECONDS = 5.0
IMAGE_PULL_EXECUTION_POLL_ATTEMPTS = 24
MINIMUM_RSA_KEY_SIZE_BITS = 2048
REVIEWED_RSA_KEY_SIZE_BITS = 3072
REVIEWED_RSA_KEY_OPERATIONS = frozenset({"sign", "verify"})
PREFLIGHT_PATH = ROOT / "src" / "athena_context" / "wc029_preflight.py"
PLAN_SCHEMA_VERSION = "athena.wc029DeploymentPlan.v7"
HANDOFF_SCHEMA_VERSION = "athena.wc029DeploymentHandoff.v7"
RECEIPT_SCHEMA_VERSION = "athena.wc029DeploymentReceipt.v4"
REVOCATION_PLAN_SCHEMA_VERSION = "athena.wc029RevocationPlan.v1"
AUTHORITY_BLOB_INVENTORY_SCHEMA_VERSION = "athena.wc029AuthorityBlobInventory.v2"
IMAGE_PULL_EVIDENCE_SCHEMA_VERSION = "athena.wc029ImagePullEvidence.v3"
EVIDENCE_COMMIT_SCHEMA_VERSION = "athena.wc029EvidenceCommit.v1"
EVIDENCE_COMMIT_FIELDS = frozenset(
    {
        "schemaVersion",
        "generationId",
        "generationDirectory",
        "generationManifestPath",
        "handoffPath",
        "handoffSha256",
        "receiptPath",
        "receiptSha256",
    }
)
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
        "effectiveParameterSha256",
        "applicationMode",
        "deploymentRecordSha256",
        "deployedTemplateSha256",
        "authorityBlobInventory",
        "authorityBlobInventorySha256",
        "imagePullEvidence",
        "imagePullEvidenceSha256",
        "revocationAssignments",
        "revocationAssignmentsSha256",
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
        "compiledTemplatePath",
        "compiledTemplateSha256",
        "orchestratorSha256",
        "preflightSha256",
        "baseParameterPath",
        "baseParameterSha256",
        "effectiveParameterPath",
        "effectiveParameterSha256",
        "whatIfPath",
        "whatIfSha256",
        "allowedChangeResourceIds",
        "rotationTransitionAssignments",
        "legacyCryptoUserMigrationAssignmentIds",
        "legacyAcrPullMigrationAssignments",
        "authorityBlobInventory",
        "authorityBlobInventorySha256",
        "requiredAuthorityCheckpointSha256s",
        "revocationPlanPath",
        "revocationPlanSha256",
        "reviewedRevocationPlanSha256",
        "revocationAssignments",
        "priorStageHandoffPath",
        "priorStageHandoffSha256",
        "priorStageReceipt",
        "foundationHandoffPath",
        "foundationHandoffSha256",
        "producerHandoffPath",
        "producerHandoffSha256",
        "publisherHandoffPath",
        "publisherHandoffSha256",
        "predecessorReceipts",
    }
)
REVOCATION_PLAN_FIELDS = frozenset(
    {
        "schemaVersion",
        "stage",
        "sourceCommit",
        "subscriptionId",
        "resourceGroup",
        "deploymentName",
        "baseParameterPath",
        "baseParameterSha256",
        "effectiveParameterPath",
        "effectiveParameterSha256",
        "foundationHandoffPath",
        "foundationHandoffSha256",
        "producerHandoffPath",
        "producerHandoffSha256",
        "publisherHandoffPath",
        "publisherHandoffSha256",
        "predecessorReceipts",
        "rotationTransitionAssignments",
        "legacyCryptoUserMigrationAssignmentIds",
        "legacyAcrPullMigrationAssignments",
        "revocationAssignments",
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
        "effectiveParameterSha256",
        "applicationMode",
        "deploymentRecordSha256",
        "deployedTemplateSha256",
        "authorityBlobInventorySha256",
        "imagePullEvidenceSha256",
        "revocationAssignmentsSha256",
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
        "incidentSigningKeyFingerprint",
        "feedSigningKeyUriWithVersion",
        "feedSigningKeyFingerprint",
        "reportSigningKeyUriWithVersion",
        "reportSigningKeyFingerprint",
        "guidanceSigningKeyUriWithVersion",
        "guidanceSigningKeyFingerprint",
        "enrichmentSigningKeyUriWithVersion",
        "enrichmentSigningKeyFingerprint",
        "notificationSigningKeyUriWithVersion",
        "notificationSigningKeyFingerprint",
    }
)
FOUNDATION_BINDING_FIELDS = frozenset({"foundationParametersSha256"})
LIVE_ACCEPTANCE_OUTPUT_FIELDS = frozenset(
    {
        "wc027DeploymentReadiness",
        "publisherInvocationBoundary",
        "wc013AcrPullAssignments",
    }
)
WC013_ACR_ASSIGNMENT_LABELS = (
    "acceptance",
    "evidence",
    "controller",
    "presentation",
    "wc016-detector",
    "wc016-orchestrator",
    "wc016-notification",
)
WC013_ACR_ABAC_ASSIGNMENT_LABELS = (
    "acceptance",
    "evidence",
    "controller",
    "presentation",
    "presentation-delivery",
    "wc016-detector",
    "wc016-orchestrator",
    "wc016-notification",
)
PUBLISHER_INVOCATION_BOUNDARY = {
    "schemaVersion": "athena.wc029PublisherInvocationBoundary.v1",
    "automaticRequestProducerPresent": False,
    "runtimeInvocationValidated": False,
    "requiredRequestSchemaVersion": ("athena.wc027GuidanceAuthorityPublicationRequest.v1"),
}
SERVICE_BUS_NON_AUTO_DELETE_DURATION = "P10675199DT2H48M5.4775807S"
PRODUCER_TRIGGER_QUEUE_NAME = "wc027-enrichment-feed-requests"
SCALER_METADATA_FIELDS = frozenset(
    {
        "namespace",
        "queueName",
        "messageCount",
        "cloud",
        "isSessionsEnabled",
    }
)
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
        "registryResourceId",
        "registryRoleAssignmentMode",
        "registryAnonymousPullEnabled",
        "registryRepositoryName",
        "registryPullRoleDefinitionId",
        "registryPullRoleAssignmentResourceId",
        "registryPullConditionVersion",
        "registryPullCondition",
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
        "registryResourceId",
        "registryRoleAssignmentMode",
        "registryAnonymousPullEnabled",
        "registryRepositoryName",
        "registryPullRoleDefinitionId",
        "registryPullRoleAssignmentResourceId",
        "registryPullConditionVersion",
        "registryPullCondition",
    }
)
PRODUCER_BINDING_FIELDS = frozenset(
    {
        "correlationSourceStorageAccountResourceId",
        "correlationBindingKeyResourceId",
        "changeKeyResourceId",
        "brokerIdentityPrincipalId",
        "feedV2ReaderIdentityResourceId",
        "guidanceBindingKeyResourceId",
        "managedEnvironmentResourceId",
        "monitoringCollectorKeyResourceId",
        "monitoringIntentKeyResourceId",
        "registryResourceId",
        "registryRoleAssignmentMode",
        "serviceBusNamespaceName",
        "triggerSubmitterIdentityResourceIds",
    }
)
PUBLISHER_BINDING_FIELDS = frozenset(
    {
        "authorityStorageAccountResourceId",
        "activationStorageAccountResourceId",
        "brokerIdentityPrincipalId",
        "bindingTrustReaderIdentityResourceId",
        "bindingKeyResourceId",
        "managedEnvironmentResourceId",
        "registryResourceId",
        "registryRoleAssignmentMode",
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


class TerminalEvidenceError(OrchestrationError):
    """Raised when successful execution is followed by non-retryable evidence drift."""


class _UnknownDeploymentOutcome(OrchestrationError):
    """Raised when deployment mutation may have happened but the response is not authoritative."""


class _TerminalDeploymentFailure(OrchestrationError):
    """Raised when ARM has authoritatively reported a failed or canceled deployment."""


class _CommandFailure(OrchestrationError):
    def __init__(self, returncode: int, detail: str) -> None:
        self.returncode = returncode
        self.detail = detail
        super().__init__(f"command failed with exit code {returncode}: {detail}")


class _CommandTimeout(OrchestrationError):
    def __init__(
        self,
        *,
        operation: str,
        timeout_seconds: int,
        outcome_unknown: bool,
    ) -> None:
        self.operation = operation
        self.timeout_seconds = timeout_seconds
        self.outcome_unknown = outcome_unknown
        outcome = "; mutation outcome is unknown" if outcome_unknown else ""
        super().__init__(
            f"{operation} exceeded its bounded {timeout_seconds}-second timeout{outcome}"
        )


@dataclass(frozen=True, slots=True)
class _RolePermissionProfile:
    actions: frozenset[str] = frozenset()
    not_actions: frozenset[str] = frozenset()
    data_actions: frozenset[str] = frozenset()
    not_data_actions: frozenset[str] = frozenset()


@dataclass(slots=True)
class _AuthorizationScanBudget:
    remaining_pages: int
    remaining_items: int

    @classmethod
    def bounded(cls) -> _AuthorizationScanBudget:
        return cls(
            remaining_pages=MAX_AUTHORIZATION_SCAN_PAGES,
            remaining_items=MAX_AUTHORIZATION_SCAN_ITEMS,
        )

    def consume_page(self) -> None:
        if self.remaining_pages < 1:
            raise OrchestrationError(
                "authorization assignment pagination exceeded its bounded page budget"
            )
        self.remaining_pages -= 1

    def consume_item(self) -> None:
        if self.remaining_items < 1:
            raise OrchestrationError(
                "authorization assignment evidence exceeded its bounded item budget"
            )
        self.remaining_items -= 1


@dataclass(frozen=True, slots=True)
class _EvidenceBundlePaths:
    generation_id: str
    generation_directory: Path
    generation_manifest_path: Path
    commit_manifest_path: Path
    handoff_path: Path
    receipt_path: Path


@dataclass(frozen=True, slots=True)
class _ExpectedRoleAssignment:
    label: str
    principal_id: str
    scope: str
    role_definition_id: str
    condition_version: str | None = None
    condition: str | None = None
    custom_role_permissions: _RolePermissionProfile | None = None
    repository_name: str | None = None


@dataclass(frozen=True, slots=True)
class _RequiredRuntimeAction:
    label: str
    principal_id: str
    scope: str
    action: str
    is_data_action: bool
    repository_name: str | None = None
    suboperation: str | None = None


@dataclass(frozen=True, slots=True)
class _RotationTransitionEvidence:
    assignment_resource_id: str
    retired_principal_id: str

    def document(self) -> dict[str, str]:
        return {
            "assignmentResourceId": self.assignment_resource_id,
            "retiredPrincipalId": self.retired_principal_id,
        }


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


@dataclass(frozen=True, slots=True)
class _CapturedJsonArtifact:
    path: Path
    raw_bytes: bytes
    document: object
    sha256: str
    identity: _FileIdentity


@dataclass(frozen=True, slots=True)
class _PinnedArtifact:
    path: Path
    raw_bytes: bytes
    sha256: str
    identity: _FileIdentity

    def verify(self) -> None:
        raw_bytes, identity = _read_regular_file_once(
            self.path,
            field="pinned deployment parameter artifact",
        )
        if (
            identity != self.identity
            or raw_bytes != self.raw_bytes
            or _sha256_bytes(raw_bytes) != self.sha256
        ):
            raise OrchestrationError(
                "pinned deployment parameter artifact changed during Azure execution"
            )


class _ArtifactReader:
    def __init__(self) -> None:
        self._by_path: dict[Path, _CapturedJsonArtifact] = {}
        self._paths_by_identity: dict[tuple[int, int], Path] = {}

    def capture_json(
        self,
        path: Path,
        *,
        field: str,
    ) -> _CapturedJsonArtifact:
        absolute_path = Path(os.path.abspath(path))
        existing = self._by_path.get(absolute_path)
        if existing is not None:
            return existing
        raw_bytes, identity = _read_regular_file_once(
            absolute_path,
            field=field,
        )
        try:
            document = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise OrchestrationError(f"{field} is not valid UTF-8 JSON: {exc}") from exc
        identity_key = (identity.device, identity.inode)
        aliased_path = self._paths_by_identity.get(identity_key)
        if aliased_path is not None and aliased_path != absolute_path:
            raise OrchestrationError(
                f"{field} aliases the already captured reviewed artifact {aliased_path}"
            )
        captured = _CapturedJsonArtifact(
            path=absolute_path,
            raw_bytes=raw_bytes,
            document=document,
            sha256=_sha256_bytes(raw_bytes),
            identity=identity,
        )
        self._by_path[absolute_path] = captured
        self._paths_by_identity[identity_key] = absolute_path
        return captured


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


def _identity_from_stat(value: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        modified_ns=value.st_mtime_ns,
    )


def _read_regular_file_once(
    path: Path,
    *,
    field: str,
) -> tuple[bytes, _FileIdentity]:
    try:
        path_stat = path.lstat()
        reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if not stat.S_ISREG(path_stat.st_mode) or bool(
            getattr(path_stat, "st_file_attributes", 0) & reparse_attribute
        ):
            raise OrchestrationError(f"{field} must be one non-reparse regular file")
        path_identity = _identity_from_stat(path_stat)
        if path_identity.size > MAX_REVIEWED_ARTIFACT_BYTES:
            raise OrchestrationError(f"{field} exceeds the bounded reviewed artifact size")
        with path.open("rb") as handle:
            opened_identity = _identity_from_stat(os.fstat(handle.fileno()))
            if opened_identity != path_identity:
                raise OrchestrationError(f"{field} changed before it could be read")
            raw_bytes = handle.read()
            completed_identity = _identity_from_stat(os.fstat(handle.fileno()))
        final_identity = _identity_from_stat(path.lstat())
        if (
            completed_identity != opened_identity
            or final_identity != path_identity
            or len(raw_bytes) != opened_identity.size
        ):
            raise OrchestrationError(f"{field} changed while it was being read")
    except OrchestrationError:
        raise
    except OSError as exc:
        raise OrchestrationError(f"cannot read {field} from {path}: {exc}") from exc
    return raw_bytes, path_identity


def _read_json_artifact(
    path: Path,
    *,
    field: str,
) -> tuple[object, str]:
    captured = _ArtifactReader().capture_json(path, field=field)
    return captured.document, captured.sha256


def _canonical_json_file_bytes(value: object) -> bytes:
    return _canonical_json_bytes(value) + b"\n"


@contextmanager
def _materialized_private_artifact(
    raw_bytes: bytes,
    *,
    file_name: str = "parameters.json",
) -> Iterator[_PinnedArtifact]:
    with tempfile.TemporaryDirectory(prefix="athena-wc029-parameters-") as directory_value:
        directory = Path(directory_value)
        os.chmod(directory, 0o700)
        path = directory / file_name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            offset = 0
            while offset < len(raw_bytes):
                written = os.write(descriptor, raw_bytes[offset:])
                if written <= 0:
                    raise OrchestrationError(
                        "materialized deployment parameter write made no progress"
                    )
                offset += written
            os.fsync(descriptor)
            identity = _identity_from_stat(os.fstat(descriptor))
        finally:
            os.close(descriptor)
        captured_bytes, captured_identity = _read_regular_file_once(
            path,
            field="materialized deployment parameter artifact",
        )
        if captured_bytes != raw_bytes or captured_identity != identity:
            raise OrchestrationError(
                "materialized deployment parameter artifact does not match captured bytes"
            )
        pinned = _PinnedArtifact(
            path=path,
            raw_bytes=raw_bytes,
            sha256=_sha256_bytes(raw_bytes),
            identity=identity,
        )
        pinned.verify()
        try:
            yield pinned
        finally:
            pinned.verify()


def _ensure_clean_worktree() -> None:
    try:
        completed = subprocess.run(  # noqa: S603
            ["git", "-C", str(ROOT), "status", "--porcelain=v1"],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise OrchestrationError("git worktree status exceeded its bounded timeout") from None
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
        or any(character in segment for character in ("/", "\\", "?", "#"))
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
            versioned_collector_key_uri = (
                child_field.casefold().endswith("monitoringcollectorcontract.signingkeyresourceid")
                and isinstance(child, str)
                and child.startswith("https://")
            )
            declared_resource_id = (
                normalized_key.endswith("resourceid")
                and child not in (None, "")
                and not versioned_collector_key_uri
            )
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


def _git_commit_sha(value: object, *, field: str) -> str:
    commit_sha = _string(value, field=field)
    if (
        len(commit_sha) != 40
        or commit_sha != commit_sha.lower()
        or any(character not in "0123456789abcdef" for character in commit_sha)
    ):
        raise OrchestrationError(f"{field} must be one lowercase full Git commit SHA")
    return commit_sha


def _application_mode(value: object, *, field: str) -> str:
    mode = _string(value, field=field)
    if mode not in {"create", "resume-succeeded-deployment"}:
        raise OrchestrationError(f"{field} is not a supported governed apply mode")
    return mode


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


def _acr_repository_name(
    image: object,
    registry_resource_id: object,
    *,
    field: str,
) -> str:
    digest_pinned_image = _digest_pinned_image(image, field=field)
    registry_id = _azure_resource_id(
        registry_resource_id,
        field=f"{field} registry resource ID",
    )
    if _resource_type(registry_id) != "microsoft.containerregistry/registries":
        raise OrchestrationError(f"{field} registry resource ID must identify one registry")
    registry_name = registry_id.rstrip("/").rsplit("/", 1)[-1].casefold()
    registry_prefix = f"{registry_name}.azurecr.io/"
    repository_reference = digest_pinned_image.rsplit("@sha256:", 1)[0]
    if not repository_reference.startswith(registry_prefix):
        raise OrchestrationError(
            f"{field} registry server does not match its reviewed registry resource ID"
        )
    repository_name = repository_reference.removeprefix(registry_prefix)
    if (
        len(repository_name) > 256
        or re.fullmatch(
            r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*",
            repository_name,
        )
        is None
    ):
        raise OrchestrationError(f"{field} contains an invalid ACR repository name")
    return repository_name


def _acr_repository_condition(repository_name: str) -> str:
    if (
        len(repository_name) > 256
        or re.fullmatch(
            r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*",
            repository_name,
        )
        is None
    ):
        raise OrchestrationError("ACR repository condition requires one canonical repository name")
    return f"{ACR_REPOSITORY_CONDITION_PREFIX}{repository_name}{ACR_REPOSITORY_CONDITION_SUFFIX}"


def _acr_repository_name_from_condition(value: object, *, field: str) -> str:
    condition = _string(value, field=field)
    if not (
        condition.startswith(ACR_REPOSITORY_CONDITION_PREFIX)
        and condition.endswith(ACR_REPOSITORY_CONDITION_SUFFIX)
    ):
        raise OrchestrationError(f"{field} is not the canonical exact-repository condition")
    repository_name = condition[
        len(ACR_REPOSITORY_CONDITION_PREFIX) : -len(ACR_REPOSITORY_CONDITION_SUFFIX)
    ]
    if _acr_repository_condition(repository_name) != condition:
        raise OrchestrationError(f"{field} is not the canonical exact-repository condition")
    return repository_name


def _acr_pull_assignment_condition(
    *,
    role_assignment_mode: str,
    repository_name: str,
) -> tuple[str | None, str | None]:
    if role_assignment_mode == ACR_LEGACY_ROLE_ASSIGNMENT_MODE:
        return None, None
    if role_assignment_mode != ACR_ABAC_ROLE_ASSIGNMENT_MODE:
        raise OrchestrationError("ACR role-assignment mode is unsupported")
    return "2.0", _acr_repository_condition(repository_name)


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


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".athena-directory-sync.",
            suffix=".tmp",
            dir=path,
        )
        temporary_path = Path(temporary_name)
        marker_path = path / ".athena-directory-sync"
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(b"athena-directory-sync\n")
                handle.flush()
                os.fsync(handle.fileno())
            move_file = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
            move_file.argtypes = [
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.DWORD,
            ]
            move_file.restype = wintypes.BOOL
            move_file_replace_existing = 0x1
            move_file_write_through = 0x8
            if not move_file(
                str(temporary_path),
                str(marker_path),
                move_file_replace_existing | move_file_write_through,
            ):
                error_code = ctypes.get_last_error()
                raise OSError(
                    error_code,
                    "MoveFileExW failed to flush the directory namespace",
                    str(path),
                )
            temporary_path = None
        except OSError as exc:
            raise OrchestrationError(
                f"cannot durably flush evidence directory {path}: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path is not None:
                with suppress(FileNotFoundError):
                    temporary_path.unlink()
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        os.fsync(descriptor)
    except OSError as exc:
        raise OrchestrationError(f"cannot fsync evidence directory {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_new_bytes(path: Path, raw_bytes: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            offset = 0
            while offset < len(raw_bytes):
                written = handle.write(raw_bytes[offset:])
                if written is None or written <= 0:
                    raise OrchestrationError(
                        f"immutable evidence write made no progress for {path}"
                    )
                offset += written
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, path)
        _fsync_directory(path.parent)
    except FileExistsError as exc:
        raise OrchestrationError(f"refusing to overwrite immutable evidence {path}") from exc
    except OrchestrationError:
        raise
    except OSError as exc:
        raise OrchestrationError(
            f"cannot atomically publish immutable evidence {path}: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            with suppress(FileNotFoundError):
                temporary_path.unlink()


def _write_new_json(path: Path, value: object) -> None:
    _write_new_bytes(path, _canonical_json_file_bytes(value))


def _new_evidence_bundle_paths(
    evidence_directory: Path,
    *,
    stem: str,
) -> _EvidenceBundlePaths:
    _validate_resource_id_segment(
        stem,
        field="evidence bundle stem",
    )
    generation_id = str(uuid4())
    generations_directory = evidence_directory / f".{stem}.evidence-generations"
    generation_directory = generations_directory / generation_id
    return _EvidenceBundlePaths(
        generation_id=generation_id,
        generation_directory=generation_directory,
        generation_manifest_path=generation_directory / "generation-manifest.json",
        commit_manifest_path=evidence_directory / f"{stem}.evidence-commit.json",
        handoff_path=generation_directory / f"{stem}.handoff.json",
        receipt_path=generation_directory / f"{stem}.receipt.json",
    )


def _evidence_bundle_paths_from_artifacts(
    *,
    handoff_path: Path,
    receipt_path: Path,
) -> _EvidenceBundlePaths:
    absolute_handoff = handoff_path.resolve()
    absolute_receipt = receipt_path.resolve()
    if absolute_handoff.parent != absolute_receipt.parent:
        raise OrchestrationError(
            "deployment handoff and receipt must share one immutable generation"
        )
    generation_directory = absolute_handoff.parent
    generations_directory = generation_directory.parent
    prefix = "."
    suffix = ".evidence-generations"
    if not generations_directory.name.startswith(prefix) or not generations_directory.name.endswith(
        suffix
    ):
        raise OrchestrationError(
            "deployment handoff and receipt are outside an immutable evidence generation"
        )
    stem = generations_directory.name[len(prefix) : -len(suffix)]
    _validate_resource_id_segment(
        stem,
        field="evidence bundle stem",
    )
    generation_id = generation_directory.name
    try:
        canonical_generation_id = str(UUID(generation_id))
    except ValueError as exc:
        raise OrchestrationError("evidence generation ID must be one UUID") from exc
    if canonical_generation_id != generation_id:
        raise OrchestrationError("evidence generation ID must use canonical lowercase UUID form")
    expected_handoff = generation_directory / f"{stem}.handoff.json"
    expected_receipt = generation_directory / f"{stem}.receipt.json"
    if absolute_handoff != expected_handoff or absolute_receipt != expected_receipt:
        raise OrchestrationError(
            "deployment handoff and receipt names do not match their evidence generation"
        )
    return _EvidenceBundlePaths(
        generation_id=generation_id,
        generation_directory=generation_directory,
        generation_manifest_path=generation_directory / "generation-manifest.json",
        commit_manifest_path=generations_directory.parent / f"{stem}.evidence-commit.json",
        handoff_path=absolute_handoff,
        receipt_path=absolute_receipt,
    )


def _evidence_commit_document(
    paths: _EvidenceBundlePaths,
    *,
    handoff_sha256: str,
    receipt_sha256: str,
) -> dict[str, str]:
    return {
        "schemaVersion": EVIDENCE_COMMIT_SCHEMA_VERSION,
        "generationId": paths.generation_id,
        "generationDirectory": str(paths.generation_directory.resolve()),
        "generationManifestPath": str(paths.generation_manifest_path.resolve()),
        "handoffPath": str(paths.handoff_path.resolve()),
        "handoffSha256": handoff_sha256,
        "receiptPath": str(paths.receipt_path.resolve()),
        "receiptSha256": receipt_sha256,
    }


def _commit_evidence_generation(paths: _EvidenceBundlePaths) -> None:
    handoff_bytes, _ = _read_regular_file_once(
        paths.handoff_path,
        field="generated deployment handoff",
    )
    receipt_bytes, _ = _read_regular_file_once(
        paths.receipt_path,
        field="generated deployment receipt",
    )
    commit = _evidence_commit_document(
        paths,
        handoff_sha256=_sha256_bytes(handoff_bytes),
        receipt_sha256=_sha256_bytes(receipt_bytes),
    )
    commit_bytes = _canonical_json_file_bytes(commit)
    _write_new_bytes(paths.generation_manifest_path, commit_bytes)
    _fsync_directory(paths.generation_directory)
    _write_new_bytes(paths.commit_manifest_path, commit_bytes)
    _fsync_directory(paths.commit_manifest_path.parent)


def _publish_evidence_bundle(
    *,
    paths: _EvidenceBundlePaths,
    handoff_raw_bytes: bytes,
    receipt_raw_bytes: bytes,
) -> None:
    if paths.commit_manifest_path.exists():
        raise OrchestrationError(
            f"refusing to overwrite committed evidence {paths.commit_manifest_path}"
        )
    if paths.generation_directory.exists():
        raise OrchestrationError(
            f"refusing to reuse evidence generation {paths.generation_directory}"
        )
    generations_directory = paths.generation_directory.parent
    if not generations_directory.exists():
        generations_directory.mkdir(parents=True, exist_ok=False)
        os.chmod(generations_directory, 0o700)
        _fsync_directory(generations_directory.parent)
    paths.generation_directory.mkdir(exist_ok=False)
    os.chmod(paths.generation_directory, 0o700)
    _fsync_directory(generations_directory)
    _write_new_bytes(paths.handoff_path, handoff_raw_bytes)
    _write_new_bytes(paths.receipt_path, receipt_raw_bytes)
    _commit_evidence_generation(paths)


def _capture_committed_evidence_pair(
    *,
    handoff_path: Path,
    receipt_path: Path,
    artifact_reader: _ArtifactReader,
    field: str,
) -> tuple[_CapturedJsonArtifact, _CapturedJsonArtifact]:
    paths = _evidence_bundle_paths_from_artifacts(
        handoff_path=handoff_path,
        receipt_path=receipt_path,
    )
    commit_capture = artifact_reader.capture_json(
        paths.commit_manifest_path,
        field=f"{field} committed manifest",
    )
    commit = _mapping(
        commit_capture.document,
        field=f"{field} committed manifest",
    )
    _require_exact_fields(
        commit,
        EVIDENCE_COMMIT_FIELDS,
        field=f"{field} committed manifest",
    )
    if commit.get("schemaVersion") != EVIDENCE_COMMIT_SCHEMA_VERSION:
        raise OrchestrationError("unsupported WC-029 evidence commit schema")
    expected_commit = _evidence_commit_document(
        paths,
        handoff_sha256=_sha256_digest(
            commit.get("handoffSha256"),
            field=f"{field} committed handoff SHA-256",
        ),
        receipt_sha256=_sha256_digest(
            commit.get("receiptSha256"),
            field=f"{field} committed receipt SHA-256",
        ),
    )
    if commit != expected_commit:
        raise OrchestrationError(
            f"{field} committed manifest does not match its immutable generation"
        )
    generation_manifest = artifact_reader.capture_json(
        paths.generation_manifest_path,
        field=f"{field} generation manifest",
    )
    if generation_manifest.raw_bytes != commit_capture.raw_bytes:
        raise OrchestrationError(
            f"{field} committed pointer does not match its generation manifest"
        )
    handoff_capture = artifact_reader.capture_json(
        paths.handoff_path,
        field=f"{field} handoff",
    )
    receipt_capture = artifact_reader.capture_json(
        paths.receipt_path,
        field=f"{field} receipt",
    )
    if (
        handoff_capture.sha256 != expected_commit["handoffSha256"]
        or receipt_capture.sha256 != expected_commit["receiptSha256"]
    ):
        raise OrchestrationError(f"{field} committed evidence pair changed after publication")
    return handoff_capture, receipt_capture


def _write_and_capture_exact_json(
    path: Path,
    *,
    raw_bytes: bytes,
    document: object,
    artifact_reader: _ArtifactReader,
    field: str,
) -> _CapturedJsonArtifact:
    _write_new_bytes(path, raw_bytes)
    artifact = artifact_reader.capture_json(path, field=field)
    if (
        artifact.raw_bytes != raw_bytes
        or artifact.sha256 != _sha256_bytes(raw_bytes)
        or artifact.document != document
    ):
        raise OrchestrationError(f"{field} does not match the exact generated bytes")
    return artifact


def _load_parameters(path: Path) -> dict[str, dict[str, object]]:
    document = (
        _ArtifactReader()
        .capture_json(
            path,
            field="parameter document",
        )
        .document
    )
    return _load_parameter_document(document)


def _load_parameter_document(document: object) -> dict[str, dict[str, object]]:
    document = _mapping(document, field="parameter document")
    parameters = _mapping(document.get("parameters"), field="parameters")
    normalized: dict[str, dict[str, object]] = {}
    for name, raw_entry in parameters.items():
        entry = _mapping(raw_entry, field=f"parameters.{name}")
        if set(entry) != {"value"}:
            raise OrchestrationError(f"parameters.{name} must contain exactly one value property")
        normalized[name] = {"value": entry["value"]}
    return normalized


def _compiled_template(stage: str) -> tuple[dict[str, Any], bytes, str]:
    template = _mapping(
        _run_json(
            [
                "az",
                "bicep",
                "build",
                "--file",
                str(TEMPLATES[stage]),
                "--stdout",
            ],
            field=f"compiled {stage} Bicep template",
        ),
        field=f"compiled {stage} Bicep template",
    )
    raw_bytes = _canonical_json_file_bytes(template)
    return template, raw_bytes, _sha256_bytes(raw_bytes)


def _required_parameter_names_from_template(
    template: Mapping[str, object],
    *,
    stage: str,
) -> set[str]:
    parameters = _mapping(
        template.get("parameters"),
        field=f"compiled {stage} template parameters",
    )
    required: set[str] = set()
    for name, raw_definition in parameters.items():
        definition = _mapping(
            raw_definition,
            field=f"compiled {stage} template parameter {name}",
        )
        if "defaultValue" not in definition:
            required.add(name)
    return required


def _required_template_parameter_names(stage: str) -> set[str]:
    template, _, _ = _compiled_template(stage)
    return _required_parameter_names_from_template(template, stage=stage)


def _verify_effective_parameter_completeness(
    stage: str,
    parameters: Mapping[str, Mapping[str, object]],
    *,
    required_parameter_names: set[str] | None = None,
) -> None:
    required = (
        _required_template_parameter_names(stage)
        if required_parameter_names is None
        else required_parameter_names
    )
    missing = required - set(parameters)
    if missing:
        raise OrchestrationError(
            "effective parameter document omits required template parameters: "
            + ", ".join(sorted(missing))
        )


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


def _load_handoff(
    path: Path,
    *,
    expected_stage: str,
    expected_source_commit: str = SOURCE_COMMIT,
    document: object | None = None,
    artifact_reader: _ArtifactReader | None = None,
) -> dict[str, Any]:
    reader = artifact_reader or _ArtifactReader()
    handoff = _mapping(
        reader.capture_json(
            path,
            field=f"{expected_stage} handoff",
        ).document
        if document is None
        else document,
        field="handoff",
    )
    _require_exact_fields(handoff, HANDOFF_FIELDS, field="deployment handoff")
    if handoff.get("schemaVersion") != HANDOFF_SCHEMA_VERSION:
        raise OrchestrationError("unsupported WC-029 deployment handoff schema")
    if handoff.get("stage") != expected_stage:
        raise OrchestrationError(
            f"expected {expected_stage} handoff, found {handoff.get('stage')!r}"
        )
    if handoff.get("sourceCommit") != expected_source_commit:
        raise OrchestrationError(
            "deployment handoff source commit does not match its trusted receipt"
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
    _sha256_digest(
        handoff.get("effectiveParameterSha256"),
        field="handoff.effectiveParameterSha256",
    )
    _application_mode(
        handoff.get("applicationMode"),
        field="handoff.applicationMode",
    )
    _sha256_digest(
        handoff.get("deploymentRecordSha256"),
        field="handoff.deploymentRecordSha256",
    )
    _sha256_digest(
        handoff.get("deployedTemplateSha256"),
        field="handoff.deployedTemplateSha256",
    )
    authority_inventory = _validated_authority_blob_inventory(
        handoff.get("authorityBlobInventory"),
        subscription_id=handoff_subscription,
    )
    authority_inventory_digest = handoff.get("authorityBlobInventorySha256")
    if expected_stage == "foundation":
        if authority_inventory is not None or authority_inventory_digest is not None:
            raise OrchestrationError("foundation handoff cannot carry authority Blob inventory")
    elif authority_inventory is None or _sha256_digest(
        authority_inventory_digest,
        field="handoff.authorityBlobInventorySha256",
    ) != _authority_checkpoint_sha256(authority_inventory):
        raise OrchestrationError("handoff authority Blob checkpoint digest does not match")
    image_pull_evidence = _validated_image_pull_evidence(
        handoff.get("imagePullEvidence"),
        stage=expected_stage,
        subscription_id=handoff_subscription,
    )
    image_pull_evidence_digest = handoff.get("imagePullEvidenceSha256")
    if expected_stage == "foundation":
        if image_pull_evidence_digest is not None:
            raise OrchestrationError("foundation handoff cannot carry image-pull evidence")
    elif image_pull_evidence is None or _sha256_digest(
        image_pull_evidence_digest,
        field="handoff.imagePullEvidenceSha256",
    ) != _image_pull_evidence_sha256(image_pull_evidence):
        raise OrchestrationError("handoff image-pull evidence digest does not match")
    if expected_stage in {"producer", "publisher"}:
        if image_pull_evidence is None:
            raise OrchestrationError(f"{expected_stage} handoff is missing image-pull evidence")
        _verify_image_pull_evidence_matches_outputs(
            image_pull_evidence,
            kind=expected_stage,
            outputs=outputs,
            principal_id=_string(
                parameter_bindings.get("brokerIdentityPrincipalId"),
                field=f"{expected_stage} handoff broker principal ID",
            ),
        )
    revocation_assignments = _validated_revocation_assignment_evidence(
        handoff.get("revocationAssignments"),
        subscription_id=handoff_subscription,
    )
    if _sha256_digest(
        handoff.get("revocationAssignmentsSha256"),
        field="handoff.revocationAssignmentsSha256",
    ) != _revocation_assignment_evidence_sha256(revocation_assignments):
        raise OrchestrationError("handoff revocation assignment evidence digest does not match")
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
    document: object | None = None,
    artifact_reader: _ArtifactReader | None = None,
) -> dict[str, Any]:
    reader = artifact_reader or _ArtifactReader()
    _ensure_evidence_directory_outside_repository(path.parent)
    manifest = _mapping(
        reader.capture_json(
            path,
            field="plan manifest",
        ).document
        if document is None
        else document,
        field="plan manifest",
    )
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
    _sha256_digest(
        manifest.get("templateSha256"),
        field="plan template SHA-256",
    )
    compiled_template_path = Path(
        _string(
            manifest.get("compiledTemplatePath"),
            field="plan compiled template path",
        )
    )
    _ensure_evidence_directory_outside_repository(compiled_template_path.parent)
    compiled_template_artifact = reader.capture_json(
        compiled_template_path,
        field="plan compiled template artifact",
    )
    if compiled_template_artifact.sha256 != _sha256_digest(
        manifest.get("compiledTemplateSha256"),
        field="plan compiled template SHA-256",
    ):
        raise OrchestrationError("compiled Bicep template changed after review")
    compiled_template = _mapping(
        compiled_template_artifact.document,
        field="plan compiled template",
    )
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
    captured_artifacts: dict[str, _CapturedJsonArtifact] = {}
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
        captured = reader.capture_json(
            artifact_path,
            field=f"plan {field}",
        )
        captured_artifacts[digest_field] = captured
        if captured.sha256 != expected_digest:
            raise OrchestrationError(f"plan {field} changed after review")
    effective_parameters = _load_parameter_document(
        captured_artifacts["effectiveParameterSha256"].document
    )
    _validate_effective_parameter_subscription_boundary(
        effective_parameters,
        subscription_id=subscription_id,
    )
    _verify_effective_parameter_completeness(
        stage,
        effective_parameters,
        required_parameter_names=_required_parameter_names_from_template(
            compiled_template,
            stage=stage,
        ),
    )
    what_if = captured_artifacts["whatIfSha256"].document
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
    rotation_transition_assignments = _canonical_rotation_transition_assignments(
        manifest.get("rotationTransitionAssignments"),
        subscription_id=subscription_id,
        field="plan rotation transition assignments",
    )
    if manifest.get("rotationTransitionAssignments") != rotation_transition_assignments:
        raise OrchestrationError("plan rotation transition assignments must be sorted")
    legacy_crypto_user_migration_assignments = _canonical_legacy_crypto_user_migration_assignments(
        manifest.get("legacyCryptoUserMigrationAssignmentIds"),
        subscription_id=subscription_id,
        field="plan legacy Crypto User migration assignments",
    )
    if manifest.get("legacyCryptoUserMigrationAssignmentIds") != (
        legacy_crypto_user_migration_assignments
    ):
        raise OrchestrationError("plan legacy Crypto User migration assignment IDs must be sorted")
    legacy_acr_pull_migrations = _canonical_legacy_acr_pull_migration_assignments(
        manifest.get("legacyAcrPullMigrationAssignments"),
        subscription_id=subscription_id,
        field="plan legacy ACR pull migration assignments",
    )
    if manifest.get("legacyAcrPullMigrationAssignments") != legacy_acr_pull_migrations:
        raise OrchestrationError("plan legacy ACR pull migration assignments must be sorted")
    revocation_plan_path_value = manifest.get("revocationPlanPath")
    revocation_plan_sha256_value = manifest.get("revocationPlanSha256")
    reviewed_revocation_plan_sha256_value = manifest.get("reviewedRevocationPlanSha256")
    revocation_values = (
        revocation_plan_path_value,
        revocation_plan_sha256_value,
        reviewed_revocation_plan_sha256_value,
    )
    if any(value is not None for value in revocation_values) and not all(
        value is not None for value in revocation_values
    ):
        raise OrchestrationError("plan revocation evidence is incomplete")
    revocation_assignments = _validated_revocation_assignment_evidence(
        manifest.get("revocationAssignments"),
        subscription_id=subscription_id,
    )
    if all(value is not None for value in revocation_values):
        revocation_path = Path(
            _string(
                revocation_plan_path_value,
                field="plan revocation path",
            )
        )
        revocation_artifact = reader.capture_json(
            revocation_path,
            field="plan revocation artifact",
        )
        revocation_digest = _sha256_digest(
            revocation_plan_sha256_value,
            field="plan revocation SHA-256",
        )
        if (
            revocation_artifact.sha256 != revocation_digest
            or _sha256_digest(
                reviewed_revocation_plan_sha256_value,
                field="plan reviewed revocation SHA-256",
            )
            != revocation_digest
        ):
            raise OrchestrationError("plan revocation evidence does not match independent review")
    elif revocation_assignments:
        raise OrchestrationError("plan revocation assignments have no reviewed phase-A plan")
    authority_blob_inventory = _validated_authority_blob_inventory(
        manifest.get("authorityBlobInventory"),
        subscription_id=subscription_id,
    )
    authority_blob_inventory_digest = manifest.get("authorityBlobInventorySha256")
    if stage == "foundation":
        if authority_blob_inventory is not None or authority_blob_inventory_digest is not None:
            raise OrchestrationError("foundation plan cannot contain authority Blob inventory")
    elif authority_blob_inventory is None or _sha256_digest(
        authority_blob_inventory_digest,
        field="plan authority Blob inventory SHA-256",
    ) != _authority_checkpoint_sha256(authority_blob_inventory):
        raise OrchestrationError("WC-027 plan authority Blob checkpoint digest does not match")
    prior_handoff_path = manifest.get("priorStageHandoffPath")
    prior_handoff_sha256 = manifest.get("priorStageHandoffSha256")
    prior_receipt_value = manifest.get("priorStageReceipt")
    prior_values = (
        prior_handoff_path,
        prior_handoff_sha256,
        prior_receipt_value,
    )
    if any(value is not None for value in prior_values) and not all(
        value is not None for value in prior_values
    ):
        raise OrchestrationError("plan prior same-stage evidence is incomplete")
    if any(value is not None for value in prior_values):
        if stage not in {"producer", "publisher"}:
            raise OrchestrationError("plan prior same-stage evidence is invalid for this stage")
        _string(prior_handoff_path, field="plan prior stage handoff path")
        _sha256_digest(
            prior_handoff_sha256,
            field="plan prior stage handoff SHA-256",
        )
        prior_receipt = _mapping(
            prior_receipt_value,
            field="plan prior stage receipt",
        )
        _require_exact_fields(
            prior_receipt,
            PREDECESSOR_RECEIPT_REFERENCE_FIELDS,
            field="plan prior stage receipt",
        )
        _string(
            prior_receipt.get("path"),
            field="plan prior stage receipt path",
        )
        receipt_digest = _sha256_digest(
            prior_receipt.get("sha256"),
            field="plan prior stage receipt SHA-256",
        )
        if (
            _sha256_digest(
                prior_receipt.get("reviewedSha256"),
                field="plan prior reviewed receipt SHA-256",
            )
            != receipt_digest
        ):
            raise OrchestrationError("plan prior stage receipt was not independently reviewed")
    required_checkpoint_sha256s = _mapping(
        manifest.get("requiredAuthorityCheckpointSha256s"),
        field="plan required authority checkpoint SHA-256s",
    )
    expected_checkpoint_keys: set[str] = set()
    if stage == "publisher":
        expected_checkpoint_keys.add("producer")
    elif stage == "live-acceptance":
        expected_checkpoint_keys.add("publisher")
    if any(value is not None for value in prior_values):
        expected_checkpoint_keys.add("priorStage")
    _require_exact_fields(
        required_checkpoint_sha256s,
        frozenset(expected_checkpoint_keys),
        field="plan required authority checkpoint SHA-256s",
    )
    for name, digest in required_checkpoint_sha256s.items():
        _sha256_digest(
            digest,
            field=f"plan required authority checkpoint {name}",
        )
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
        handoff_capture = reader.capture_json(
            handoff_path,
            field=f"plan {predecessor} handoff",
        )
        if handoff_capture.sha256 != handoff_digest:
            raise OrchestrationError(f"plan {predecessor} handoff changed after review")
    _azure_location(manifest.get("location"), field="plan location")
    _string(manifest.get("deploymentName"), field="plan deployment name")
    return manifest


def _load_revocation_plan(
    path: Path,
    *,
    reviewed_sha256: str,
    artifact_reader: _ArtifactReader,
) -> dict[str, Any]:
    _ensure_evidence_directory_outside_repository(path.parent)
    artifact = artifact_reader.capture_json(
        path,
        field="reviewed revocation plan",
    )
    reviewed_digest = _sha256_digest(
        reviewed_sha256,
        field="reviewed revocation plan SHA-256",
    )
    if artifact.sha256 != reviewed_digest:
        raise OrchestrationError(
            "revocation plan does not match its independently reviewed SHA-256"
        )
    plan = _mapping(artifact.document, field="revocation plan")
    _require_exact_fields(plan, REVOCATION_PLAN_FIELDS, field="revocation plan")
    if plan.get("schemaVersion") != REVOCATION_PLAN_SCHEMA_VERSION:
        raise OrchestrationError("unsupported WC-029 revocation plan schema")
    stage = _string(plan.get("stage"), field="revocation plan stage")
    if stage not in STAGES:
        raise OrchestrationError("revocation plan stage is unsupported")
    if plan.get("sourceCommit") != SOURCE_COMMIT:
        raise OrchestrationError("revocation plan source commit is not the current exact commit")
    subscription_id = _canonical_subscription_id(
        plan.get("subscriptionId"),
        field="revocation plan subscription",
    )
    resource_group = plan.get("resourceGroup")
    if stage in {"producer", "publisher"}:
        _string(resource_group, field="revocation plan resource group")
    elif resource_group is not None:
        raise OrchestrationError(f"{stage} revocation plan must use subscription deployment scope")
    _string(plan.get("deploymentName"), field="revocation plan deployment name")
    base_path = Path(
        _string(
            plan.get("baseParameterPath"),
            field="revocation plan base parameter path",
        )
    )
    effective_path = Path(
        _string(
            plan.get("effectiveParameterPath"),
            field="revocation plan effective parameter path",
        )
    )
    base_artifact = artifact_reader.capture_json(
        base_path,
        field="revocation plan base parameters",
    )
    effective_artifact = artifact_reader.capture_json(
        effective_path,
        field="revocation plan effective parameters",
    )
    if base_artifact.sha256 != _sha256_digest(
        plan.get("baseParameterSha256"),
        field="revocation plan base parameter SHA-256",
    ):
        raise OrchestrationError("revocation plan base parameters changed after review")
    if effective_artifact.sha256 != _sha256_digest(
        plan.get("effectiveParameterSha256"),
        field="revocation plan effective parameter SHA-256",
    ):
        raise OrchestrationError("revocation plan effective parameters changed after review")
    handoff_paths: dict[str, Path | None] = {}
    for predecessor in ("foundation", "producer", "publisher"):
        path_value = plan.get(f"{predecessor}HandoffPath")
        digest_value = plan.get(f"{predecessor}HandoffSha256")
        if path_value is None:
            if digest_value is not None:
                raise OrchestrationError(
                    f"revocation plan {predecessor} handoff digest has no path"
                )
            handoff_paths[predecessor] = None
            continue
        handoff_path = Path(
            _string(
                path_value,
                field=f"revocation plan {predecessor} handoff path",
            )
        )
        handoff_paths[predecessor] = handoff_path
        if artifact_reader.capture_json(
            handoff_path,
            field=f"revocation plan {predecessor} handoff",
        ).sha256 != _sha256_digest(
            digest_value,
            field=f"revocation plan {predecessor} handoff SHA-256",
        ):
            raise OrchestrationError(f"revocation plan {predecessor} handoff changed after review")
    _validate_stage_inputs(
        stage=stage,
        resource_group=(None if resource_group is None else str(resource_group)),
        foundation_handoff_path=handoff_paths["foundation"],
        producer_handoff_path=handoff_paths["producer"],
        publisher_handoff_path=handoff_paths["publisher"],
    )
    predecessor_receipts = _mapping(
        plan.get("predecessorReceipts"),
        field="revocation plan predecessor receipts",
    )
    _require_exact_fields(
        predecessor_receipts,
        frozenset(EXPECTED_PREDECESSOR_STAGES[stage]),
        field="revocation plan predecessor receipts",
    )
    for predecessor, raw_reference in predecessor_receipts.items():
        reference = _mapping(
            raw_reference,
            field=f"revocation plan {predecessor} receipt",
        )
        _require_exact_fields(
            reference,
            PREDECESSOR_RECEIPT_REFERENCE_FIELDS,
            field=f"revocation plan {predecessor} receipt",
        )
        _string(
            reference.get("path"),
            field=f"revocation plan {predecessor} receipt path",
        )
        actual_digest = _sha256_digest(
            reference.get("sha256"),
            field=f"revocation plan {predecessor} receipt SHA-256",
        )
        if (
            _sha256_digest(
                reference.get("reviewedSha256"),
                field=f"revocation plan {predecessor} reviewed receipt SHA-256",
            )
            != actual_digest
        ):
            raise OrchestrationError(
                f"revocation plan {predecessor} receipt is not independently reviewed"
            )
    rotations = _canonical_rotation_transition_assignments(
        plan.get("rotationTransitionAssignments"),
        subscription_id=subscription_id,
        field="revocation plan rotation transitions",
    )
    legacy_crypto = _canonical_legacy_crypto_user_migration_assignments(
        plan.get("legacyCryptoUserMigrationAssignmentIds"),
        subscription_id=subscription_id,
        field="revocation plan legacy Crypto User migrations",
    )
    legacy_acr = _canonical_legacy_acr_pull_migration_assignments(
        plan.get("legacyAcrPullMigrationAssignments"),
        subscription_id=subscription_id,
        field="revocation plan legacy ACR pull migrations",
    )
    if (
        plan.get("rotationTransitionAssignments") != rotations
        or plan.get("legacyCryptoUserMigrationAssignmentIds") != legacy_crypto
        or plan.get("legacyAcrPullMigrationAssignments") != legacy_acr
    ):
        raise OrchestrationError("revocation plan assignment sets must be canonical and sorted")
    evidence = _validated_revocation_assignment_evidence(
        plan.get("revocationAssignments"),
        subscription_id=subscription_id,
    )
    expected_ids = {
        *(item["assignmentResourceId"].casefold() for item in rotations),
        *(item.casefold() for item in legacy_crypto),
        *(item["assignmentResourceId"].casefold() for item in legacy_acr),
    }
    if {str(item["assignmentResourceId"]).casefold() for item in evidence} != expected_ids:
        raise OrchestrationError(
            "revocation plan evidence does not match its exact assignment sets"
        )
    _verify_revocation_assignment_evidence_bindings(
        evidence,
        rotations=rotations,
        legacy_acr_migrations=legacy_acr,
        legacy_crypto_expected=None,
        subscription_id=subscription_id,
    )
    return {
        "plan": plan,
        "artifact": artifact,
        "baseArtifact": base_artifact,
        "effectiveArtifact": effective_artifact,
        "rotationTransitionAssignments": rotations,
        "legacyCryptoUserMigrationAssignmentIds": legacy_crypto,
        "legacyAcrPullMigrationAssignments": legacy_acr,
        "revocationAssignments": evidence,
    }


def _verify_revocation_plan_binding(
    record: Mapping[str, object],
    *,
    stage: str,
    subscription_id: str,
    resource_group: str | None,
    deployment_name: str,
    base_parameter_artifact: _CapturedJsonArtifact,
    effective_parameters: Mapping[str, Mapping[str, object]],
    verified_predecessors: Mapping[str, Mapping[str, object]],
) -> None:
    plan = _mapping(record.get("plan"), field="revocation plan")
    if (
        plan.get("stage") != stage
        or plan.get("subscriptionId") != subscription_id
        or plan.get("resourceGroup") != resource_group
        or plan.get("deploymentName") != deployment_name
        or plan.get("baseParameterPath") != str(base_parameter_artifact.path)
        or plan.get("baseParameterSha256") != base_parameter_artifact.sha256
    ):
        raise OrchestrationError(
            "revocation plan does not match the final deployment scope and base parameters"
        )
    effective_artifact = record.get("effectiveArtifact")
    if not isinstance(effective_artifact, _CapturedJsonArtifact):
        raise OrchestrationError("revocation plan lost its captured effective parameters")
    if effective_artifact.raw_bytes != _canonical_json_file_bytes(
        _parameter_document(effective_parameters)
    ):
        raise OrchestrationError(
            "revocation plan effective parameters differ from final planning inputs"
        )
    if plan.get("predecessorReceipts") != _predecessor_receipt_references(verified_predecessors):
        raise OrchestrationError(
            "revocation plan predecessor receipts differ from final planning inputs"
        )
    for predecessor in ("foundation", "producer", "publisher"):
        record_value = verified_predecessors.get(predecessor)
        expected_path = None if record_value is None else str(record_value["handoffPath"])
        expected_digest = None if record_value is None else record_value["handoffSha256"]
        if (
            plan.get(f"{predecessor}HandoffPath") != expected_path
            or plan.get(f"{predecessor}HandoffSha256") != expected_digest
        ):
            raise OrchestrationError(
                f"revocation plan {predecessor} handoff differs from final planning inputs"
            )
    legacy_crypto_ids = record.get("legacyCryptoUserMigrationAssignmentIds")
    if not isinstance(legacy_crypto_ids, list):
        raise OrchestrationError("revocation plan lost legacy Crypto User migration IDs")
    legacy_crypto_expected: Mapping[str, _ExpectedRoleAssignment] | None = None
    if legacy_crypto_ids:
        if stage != "producer":
            raise OrchestrationError(
                "legacy Crypto User revocation evidence is producer-stage only"
            )
        all_expected = _planned_legacy_crypto_user_assignments(
            effective_parameters=effective_parameters,
            resource_group=_string(
                resource_group,
                field="producer resource group",
            ),
            subscription_id=subscription_id,
        )
        missing_legacy_ids = {
            assignment_id.casefold() for assignment_id in legacy_crypto_ids
        } - set(all_expected)
        if missing_legacy_ids:
            raise OrchestrationError(
                "revocation plan legacy Crypto User IDs are outside the exact expected set"
            )
        legacy_crypto_expected = {
            assignment_id.casefold(): all_expected[assignment_id.casefold()]
            for assignment_id in legacy_crypto_ids
        }
    _verify_revocation_assignment_evidence_bindings(
        record["revocationAssignments"],
        rotations=record["rotationTransitionAssignments"],
        legacy_acr_migrations=record["legacyAcrPullMigrationAssignments"],
        legacy_crypto_expected=legacy_crypto_expected,
        subscription_id=subscription_id,
    )


def _load_verified_predecessor(
    *,
    expected_stage: str,
    handoff_path: Path,
    receipt_path: Path,
    reviewed_receipt_sha256: str,
    artifact_reader: _ArtifactReader | None = None,
) -> dict[str, Any]:
    reader = artifact_reader or _ArtifactReader()
    for artifact in (handoff_path, receipt_path):
        _ensure_evidence_directory_outside_repository(artifact.parent)
    reviewed_digest = _sha256_digest(
        reviewed_receipt_sha256,
        field=f"{expected_stage} reviewed receipt SHA-256",
    )
    handoff_capture, receipt_capture = _capture_committed_evidence_pair(
        handoff_path=handoff_path,
        receipt_path=receipt_path,
        artifact_reader=reader,
        field=f"{expected_stage} deployment evidence",
    )
    receipt_document = receipt_capture.document
    actual_receipt_digest = receipt_capture.sha256
    if actual_receipt_digest != reviewed_digest:
        raise OrchestrationError(
            f"{expected_stage} receipt does not match its trusted approval digest"
        )
    receipt = _mapping(receipt_document, field=f"{expected_stage} receipt")
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
    receipt_effective_parameter_sha256 = _sha256_digest(
        receipt.get("effectiveParameterSha256"),
        field=f"{expected_stage} receipt effective parameter SHA-256",
    )
    receipt_application_mode = _application_mode(
        receipt.get("applicationMode"),
        field=f"{expected_stage} receipt application mode",
    )
    receipt_deployment_record_sha256 = _sha256_digest(
        receipt.get("deploymentRecordSha256"),
        field=f"{expected_stage} receipt deployment record SHA-256",
    )
    receipt_deployed_template_sha256 = _sha256_digest(
        receipt.get("deployedTemplateSha256"),
        field=f"{expected_stage} receipt deployed template SHA-256",
    )
    receipt_authority_inventory_sha256 = receipt.get("authorityBlobInventorySha256")
    receipt_image_pull_evidence_sha256 = receipt.get("imagePullEvidenceSha256")
    receipt_revocation_assignments_sha256 = _sha256_digest(
        receipt.get("revocationAssignmentsSha256"),
        field=f"{expected_stage} receipt revocation assignments SHA-256",
    )
    if expected_stage == "foundation":
        if (
            receipt_authority_inventory_sha256 is not None
            or receipt_image_pull_evidence_sha256 is not None
        ):
            raise OrchestrationError("foundation receipt cannot carry WC-027 readiness evidence")
    else:
        receipt_authority_inventory_sha256 = _sha256_digest(
            receipt_authority_inventory_sha256,
            field=f"{expected_stage} receipt authority inventory SHA-256",
        )
        receipt_image_pull_evidence_sha256 = _sha256_digest(
            receipt_image_pull_evidence_sha256,
            field=f"{expected_stage} receipt image-pull evidence SHA-256",
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
    plan_capture = reader.capture_json(
        plan_path,
        field=f"{expected_stage} plan",
    )
    plan_document = plan_capture.document
    actual_plan_digest = plan_capture.sha256
    if plan_digest != reviewed_plan_digest or actual_plan_digest != plan_digest:
        raise OrchestrationError(
            f"{expected_stage} receipt does not prove an independently reviewed plan"
        )
    handoff_digest = _sha256_digest(
        receipt.get("handoffSha256"),
        field=f"{expected_stage} receipt handoff SHA-256",
    )
    handoff_document = handoff_capture.document
    actual_handoff_digest = handoff_capture.sha256
    if actual_handoff_digest != handoff_digest:
        raise OrchestrationError(f"{expected_stage} handoff does not match its deployment receipt")
    plan = _load_plan_manifest(
        plan_path,
        expected_stage=expected_stage,
        document=plan_document,
        artifact_reader=reader,
    )
    handoff = _load_handoff(
        handoff_path,
        expected_stage=expected_stage,
        document=handoff_document,
        artifact_reader=reader,
    )
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
    if (
        plan.get("effectiveParameterSha256") != receipt_effective_parameter_sha256
        or handoff.get("effectiveParameterSha256") != receipt_effective_parameter_sha256
        or handoff.get("applicationMode") != receipt_application_mode
        or handoff.get("deploymentRecordSha256") != receipt_deployment_record_sha256
        or handoff.get("deployedTemplateSha256") != receipt_deployed_template_sha256
        or plan.get("compiledTemplateSha256") != receipt_deployed_template_sha256
        or handoff.get("authorityBlobInventorySha256") != receipt_authority_inventory_sha256
        or handoff.get("imagePullEvidenceSha256") != receipt_image_pull_evidence_sha256
        or handoff.get("revocationAssignmentsSha256") != receipt_revocation_assignments_sha256
    ):
        raise OrchestrationError(
            f"{expected_stage} receipt deployment attestation chain does not match"
        )
    if expected_stage != "foundation":
        planned_inventory = _validated_authority_blob_inventory(
            plan.get("authorityBlobInventory"),
            subscription_id=receipt_subscription,
        )
        final_inventory = _validated_authority_blob_inventory(
            handoff.get("authorityBlobInventory"),
            subscription_id=receipt_subscription,
        )
        if planned_inventory is None or final_inventory is None:
            raise OrchestrationError(f"{expected_stage} receipt authority checkpoint is incomplete")
        _verify_authority_checkpoint_successor(
            previous_inventory=planned_inventory,
            current_inventory=final_inventory,
            allow_container_creation=(
                expected_stage == "producer" and planned_inventory.get("containerExists") is False
            ),
        )
    if expected_stage == "live-acceptance":
        image_pull_evidence = _validated_image_pull_evidence(
            handoff.get("imagePullEvidence"),
            stage=expected_stage,
            subscription_id=receipt_subscription,
        )
        if image_pull_evidence is None:
            raise OrchestrationError("live-acceptance receipt is missing image-pull evidence")
        for predecessor in ("producer", "publisher"):
            predecessor_handoff = _load_handoff(
                Path(
                    _string(
                        plan.get(f"{predecessor}HandoffPath"),
                        field=f"live-acceptance {predecessor} handoff path",
                    )
                ),
                expected_stage=predecessor,
                artifact_reader=reader,
            )
            _verify_image_pull_evidence_matches_outputs(
                image_pull_evidence,
                kind=predecessor,
                outputs=_mapping(
                    predecessor_handoff.get("outputs"),
                    field=f"live-acceptance {predecessor} outputs",
                ),
                principal_id=_string(
                    _handoff_bindings(predecessor_handoff).get("brokerIdentityPrincipalId"),
                    field=f"live-acceptance {predecessor} principal ID",
                ),
            )
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
        "handoffArtifact": handoff_capture,
        "handoffPath": handoff_path.resolve(),
        "handoffSha256": handoff_digest,
        "plan": plan,
        "planArtifact": plan_capture,
        "planPath": plan_path.resolve(),
        "receipt": receipt,
        "receiptArtifact": receipt_capture,
        "receiptPath": receipt_path.resolve(),
        "receiptSha256": actual_receipt_digest,
        "reviewedReceiptSha256": reviewed_digest,
    }


def _load_verified_prior_stage_inventory(
    *,
    expected_stage: str,
    handoff_path: Path,
    receipt_path: Path,
    reviewed_receipt_sha256: str,
    subscription_id: str,
    resource_group: str,
    artifact_reader: _ArtifactReader | None = None,
) -> dict[str, object]:
    reader = artifact_reader or _ArtifactReader()
    if expected_stage not in {"producer", "publisher"}:
        raise OrchestrationError("prior same-stage inventory is supported only for WC-027 stages")
    for artifact in (handoff_path, receipt_path):
        _ensure_evidence_directory_outside_repository(artifact.parent)
    reviewed_digest = _sha256_digest(
        reviewed_receipt_sha256,
        field="prior stage reviewed receipt SHA-256",
    )
    handoff_capture, receipt_capture = _capture_committed_evidence_pair(
        handoff_path=handoff_path,
        receipt_path=receipt_path,
        artifact_reader=reader,
        field="prior stage deployment evidence",
    )
    receipt_document = receipt_capture.document
    actual_receipt_digest = receipt_capture.sha256
    if actual_receipt_digest != reviewed_digest:
        raise OrchestrationError("prior stage receipt does not match its reviewed SHA-256")
    receipt = _mapping(receipt_document, field="prior stage receipt")
    _require_exact_fields(
        receipt,
        RECEIPT_FIELDS,
        field="prior stage receipt",
    )
    source_commit = _git_commit_sha(
        receipt.get("sourceCommit"),
        field="prior stage source commit",
    )
    receipt_subscription = _canonical_subscription_id(
        receipt.get("subscriptionId"),
        field="prior stage receipt subscription",
    )
    receipt_resource_group = _string(
        receipt.get("resourceGroup"),
        field="prior stage receipt resource group",
    )
    deployment_name = _string(
        receipt.get("deploymentName"),
        field="prior stage receipt deployment name",
    )
    if (
        receipt.get("schemaVersion") != RECEIPT_SCHEMA_VERSION
        or receipt.get("stage") != expected_stage
        or receipt_subscription != subscription_id
        or receipt_resource_group != resource_group
    ):
        raise OrchestrationError("prior stage receipt does not match the requested stage scope")
    receipt_effective_parameter_sha256 = _sha256_digest(
        receipt.get("effectiveParameterSha256"),
        field="prior stage receipt effective parameter SHA-256",
    )
    receipt_application_mode = _application_mode(
        receipt.get("applicationMode"),
        field="prior stage receipt application mode",
    )
    receipt_deployment_record_sha256 = _sha256_digest(
        receipt.get("deploymentRecordSha256"),
        field="prior stage receipt deployment record SHA-256",
    )
    receipt_deployed_template_sha256 = _sha256_digest(
        receipt.get("deployedTemplateSha256"),
        field="prior stage receipt deployed template SHA-256",
    )
    receipt_authority_inventory_sha256 = _sha256_digest(
        receipt.get("authorityBlobInventorySha256"),
        field="prior stage receipt authority inventory SHA-256",
    )
    receipt_image_pull_evidence_sha256 = _sha256_digest(
        receipt.get("imagePullEvidenceSha256"),
        field="prior stage receipt image-pull evidence SHA-256",
    )
    receipt_revocation_assignments_sha256 = _sha256_digest(
        receipt.get("revocationAssignmentsSha256"),
        field="prior stage receipt revocation assignments SHA-256",
    )
    receipt_predecessors = _mapping(
        receipt.get("predecessorReceiptSha256s"),
        field="prior stage receipt predecessor hashes",
    )
    expected_predecessors = frozenset(EXPECTED_PREDECESSOR_STAGES[expected_stage])
    _require_exact_fields(
        receipt_predecessors,
        expected_predecessors,
        field="prior stage receipt predecessor hashes",
    )
    for predecessor, digest in receipt_predecessors.items():
        _sha256_digest(
            digest,
            field=f"prior stage receipt predecessor {predecessor}",
        )
    plan_path = Path(
        _string(
            receipt.get("planManifestPath"),
            field="prior stage plan path",
        )
    )
    _ensure_evidence_directory_outside_repository(plan_path.parent)
    if plan_path.resolve() == receipt_path.resolve():
        raise OrchestrationError("prior stage receipt cannot be its own plan artifact")
    receipt_handoff_path = Path(
        _string(
            receipt.get("handoffPath"),
            field="prior stage receipt handoff path",
        )
    )
    if receipt_handoff_path.resolve() != handoff_path.resolve():
        raise OrchestrationError("prior stage handoff path does not match its receipt")
    plan_digest = _sha256_digest(
        receipt.get("planManifestSha256"),
        field="prior stage plan SHA-256",
    )
    plan_capture = reader.capture_json(
        plan_path,
        field="prior stage plan",
    )
    plan_document = plan_capture.document
    actual_plan_digest = plan_capture.sha256
    if (
        plan_digest
        != _sha256_digest(
            receipt.get("reviewedPlanSha256"),
            field="prior stage reviewed plan SHA-256",
        )
        or actual_plan_digest != plan_digest
    ):
        raise OrchestrationError(
            "prior stage receipt does not prove an independently reviewed plan"
        )
    handoff_digest = _sha256_digest(
        receipt.get("handoffSha256"),
        field="prior stage handoff SHA-256",
    )
    handoff_document = handoff_capture.document
    actual_handoff_digest = handoff_capture.sha256
    if actual_handoff_digest != handoff_digest:
        raise OrchestrationError("prior stage handoff does not match its receipt")
    plan = _mapping(plan_document, field="prior stage plan")
    _require_exact_fields(
        plan,
        PLAN_FIELDS,
        field="prior stage plan",
    )
    if plan.get("schemaVersion") != PLAN_SCHEMA_VERSION:
        raise OrchestrationError("prior stage plan predates authority Blob inventory evidence")
    plan_subscription = _canonical_subscription_id(
        plan.get("subscriptionId"),
        field="prior stage plan subscription",
    )
    plan_resource_group = _string(
        plan.get("resourceGroup"),
        field="prior stage plan resource group",
    )
    if (
        plan.get("stage") != expected_stage
        or plan.get("sourceCommit") != source_commit
        or plan_subscription != receipt_subscription
        or plan_resource_group != receipt_resource_group
        or plan.get("deploymentName") != deployment_name
    ):
        raise OrchestrationError("prior stage plan does not match its receipt scope")
    expected_template_path = str(TEMPLATES[expected_stage].relative_to(ROOT)).replace(
        "\\",
        "/",
    )
    if plan.get("templatePath") != expected_template_path:
        raise OrchestrationError("prior stage plan template does not match its exact stage")
    _azure_location(plan.get("location"), field="prior stage plan location")
    for digest_name in (
        "templateSha256",
        "compiledTemplateSha256",
        "orchestratorSha256",
        "preflightSha256",
        "baseParameterSha256",
        "effectiveParameterSha256",
        "whatIfSha256",
    ):
        _sha256_digest(
            plan.get(digest_name),
            field=f"prior stage plan {digest_name}",
        )
    for path_name, digest_name in (
        ("compiledTemplatePath", "compiledTemplateSha256"),
        ("baseParameterPath", "baseParameterSha256"),
        ("effectiveParameterPath", "effectiveParameterSha256"),
        ("whatIfPath", "whatIfSha256"),
    ):
        artifact_path = Path(
            _string(
                plan.get(path_name),
                field=f"prior stage plan {path_name}",
            )
        )
        captured_artifact = reader.capture_json(
            artifact_path,
            field=f"prior stage plan {path_name}",
        )
        if captured_artifact.sha256 != _sha256_digest(
            plan.get(digest_name),
            field=f"prior stage plan {digest_name}",
        ):
            raise OrchestrationError(f"prior stage plan {path_name} changed after review")
    raw_allowed_changes = plan.get("allowedChangeResourceIds")
    if not isinstance(raw_allowed_changes, list) or any(
        not isinstance(item, str) for item in raw_allowed_changes
    ):
        raise OrchestrationError("prior stage plan allowed changes must be a string array")
    allowed_changes = [
        _canonical_subscription_resource_id(
            resource_id,
            subscription_id=subscription_id,
            field=f"prior stage plan allowed changes[{index}]",
        )
        for index, resource_id in enumerate(raw_allowed_changes)
    ]
    if allowed_changes != sorted(allowed_changes) or len(
        {item.casefold() for item in allowed_changes}
    ) != len(allowed_changes):
        raise OrchestrationError(
            "prior stage plan allowed change resource IDs must be sorted and distinct"
        )
    rotation_transition_assignments = _canonical_rotation_transition_assignments(
        plan.get("rotationTransitionAssignments"),
        subscription_id=subscription_id,
        field="prior stage plan rotation transition assignments",
    )
    if plan.get("rotationTransitionAssignments") != rotation_transition_assignments:
        raise OrchestrationError("prior stage plan rotation transition assignments must be sorted")
    legacy_crypto_user_migration_assignments = _canonical_legacy_crypto_user_migration_assignments(
        plan.get("legacyCryptoUserMigrationAssignmentIds"),
        subscription_id=subscription_id,
        field="prior stage plan legacy Crypto User migration assignments",
    )
    if (
        plan.get("legacyCryptoUserMigrationAssignmentIds")
        != legacy_crypto_user_migration_assignments
    ):
        raise OrchestrationError(
            "prior stage plan legacy Crypto User migration assignment IDs must be sorted"
        )
    legacy_acr_pull_migrations = _canonical_legacy_acr_pull_migration_assignments(
        plan.get("legacyAcrPullMigrationAssignments"),
        subscription_id=subscription_id,
        field="prior stage plan legacy ACR pull migration assignments",
    )
    if plan.get("legacyAcrPullMigrationAssignments") != legacy_acr_pull_migrations:
        raise OrchestrationError(
            "prior stage plan legacy ACR pull migration assignments must be sorted"
        )
    revocation_plan_path_value = plan.get("revocationPlanPath")
    revocation_plan_sha256_value = plan.get("revocationPlanSha256")
    reviewed_revocation_plan_sha256_value = plan.get("reviewedRevocationPlanSha256")
    revocation_values = (
        revocation_plan_path_value,
        revocation_plan_sha256_value,
        reviewed_revocation_plan_sha256_value,
    )
    if any(value is not None for value in revocation_values) and not all(
        value is not None for value in revocation_values
    ):
        raise OrchestrationError("prior stage plan revocation evidence is incomplete")
    _validated_revocation_assignment_evidence(
        plan.get("revocationAssignments"),
        subscription_id=subscription_id,
    )
    if all(value is not None for value in revocation_values):
        revocation_artifact = reader.capture_json(
            Path(
                _string(
                    revocation_plan_path_value,
                    field="prior stage revocation plan path",
                )
            ),
            field="prior stage revocation plan",
        )
        revocation_digest = _sha256_digest(
            revocation_plan_sha256_value,
            field="prior stage revocation plan SHA-256",
        )
        if (
            revocation_artifact.sha256 != revocation_digest
            or _sha256_digest(
                reviewed_revocation_plan_sha256_value,
                field="prior stage reviewed revocation plan SHA-256",
            )
            != revocation_digest
        ):
            raise OrchestrationError(
                "prior stage revocation plan does not match independent review"
            )
    planned_handoff_paths = {
        predecessor: (
            None
            if plan.get(f"{predecessor}HandoffPath") is None
            else Path(
                _string(
                    plan.get(f"{predecessor}HandoffPath"),
                    field=f"prior stage plan {predecessor} handoff path",
                )
            )
        )
        for predecessor in ("foundation", "producer", "publisher")
    }
    _validate_stage_inputs(
        stage=expected_stage,
        resource_group=plan_resource_group,
        foundation_handoff_path=planned_handoff_paths["foundation"],
        producer_handoff_path=planned_handoff_paths["producer"],
        publisher_handoff_path=planned_handoff_paths["publisher"],
    )
    for predecessor, predecessor_handoff_path in planned_handoff_paths.items():
        predecessor_handoff_digest = plan.get(f"{predecessor}HandoffSha256")
        if predecessor_handoff_path is None:
            if predecessor_handoff_digest is not None:
                raise OrchestrationError(
                    f"prior stage plan {predecessor} handoff digest has no path"
                )
            continue
        _sha256_digest(
            predecessor_handoff_digest,
            field=f"prior stage plan {predecessor} handoff SHA-256",
        )
        if (
            reader.capture_json(
                predecessor_handoff_path,
                field=f"prior stage plan {predecessor} handoff",
            ).sha256
            != predecessor_handoff_digest
        ):
            raise OrchestrationError(f"prior stage plan {predecessor} handoff changed after review")
    prior_handoff_path = plan.get("priorStageHandoffPath")
    prior_handoff_sha256 = plan.get("priorStageHandoffSha256")
    prior_receipt_value = plan.get("priorStageReceipt")
    prior_values = (
        prior_handoff_path,
        prior_handoff_sha256,
        prior_receipt_value,
    )
    if any(value is not None for value in prior_values) and not all(
        value is not None for value in prior_values
    ):
        raise OrchestrationError("prior stage plan has incomplete earlier same-stage evidence")
    if all(value is not None for value in prior_values):
        _string(
            prior_handoff_path,
            field="prior stage plan earlier handoff path",
        )
        _sha256_digest(
            prior_handoff_sha256,
            field="prior stage plan earlier handoff SHA-256",
        )
        prior_receipt = _mapping(
            prior_receipt_value,
            field="prior stage plan earlier receipt",
        )
        _require_exact_fields(
            prior_receipt,
            PREDECESSOR_RECEIPT_REFERENCE_FIELDS,
            field="prior stage plan earlier receipt",
        )
        _string(
            prior_receipt.get("path"),
            field="prior stage plan earlier receipt path",
        )
        prior_receipt_digest = _sha256_digest(
            prior_receipt.get("sha256"),
            field="prior stage plan earlier receipt SHA-256",
        )
        if (
            _sha256_digest(
                prior_receipt.get("reviewedSha256"),
                field="prior stage plan earlier reviewed receipt SHA-256",
            )
            != prior_receipt_digest
        ):
            raise OrchestrationError(
                "prior stage plan earlier receipt was not independently reviewed"
            )
    required_checkpoint_sha256s = _mapping(
        plan.get("requiredAuthorityCheckpointSha256s"),
        field="prior stage plan required authority checkpoint SHA-256s",
    )
    expected_checkpoint_keys = {"producer" if expected_stage == "publisher" else ""}
    expected_checkpoint_keys.discard("")
    if all(value is not None for value in prior_values):
        expected_checkpoint_keys.add("priorStage")
    _require_exact_fields(
        required_checkpoint_sha256s,
        frozenset(expected_checkpoint_keys),
        field="prior stage plan required authority checkpoint SHA-256s",
    )
    for name, digest in required_checkpoint_sha256s.items():
        _sha256_digest(
            digest,
            field=f"prior stage plan required authority checkpoint {name}",
        )
    plan_predecessors = _mapping(
        plan.get("predecessorReceipts"),
        field="prior stage plan predecessor receipts",
    )
    _require_exact_fields(
        plan_predecessors,
        expected_predecessors,
        field="prior stage plan predecessor receipts",
    )
    for predecessor, raw_reference in plan_predecessors.items():
        reference = _mapping(
            raw_reference,
            field=f"prior stage plan predecessor receipt {predecessor}",
        )
        _require_exact_fields(
            reference,
            PREDECESSOR_RECEIPT_REFERENCE_FIELDS,
            field=f"prior stage plan predecessor receipt {predecessor}",
        )
        _string(
            reference.get("path"),
            field=f"prior stage plan predecessor receipt {predecessor} path",
        )
        predecessor_digest = _sha256_digest(
            reference.get("sha256"),
            field=f"prior stage plan predecessor receipt {predecessor} SHA-256",
        )
        if (
            predecessor_digest
            != _sha256_digest(
                reference.get("reviewedSha256"),
                field=(f"prior stage plan predecessor receipt {predecessor} reviewed SHA-256"),
            )
            or predecessor_digest != receipt_predecessors[predecessor]
        ):
            raise OrchestrationError("prior stage plan predecessor receipt chain does not match")
    handoff = _load_handoff(
        handoff_path,
        expected_stage=expected_stage,
        expected_source_commit=source_commit,
        document=handoff_document,
        artifact_reader=reader,
    )
    if (
        handoff.get("subscriptionId") != receipt_subscription
        or handoff.get("resourceGroup") != receipt_resource_group
        or handoff.get("deploymentName") != deployment_name
        or handoff.get("planManifestSha256") != plan_digest
        or handoff.get("predecessorReceiptSha256s") != receipt_predecessors
    ):
        raise OrchestrationError("prior stage handoff does not match its receipt and plan")
    if (
        plan.get("effectiveParameterSha256") != receipt_effective_parameter_sha256
        or handoff.get("effectiveParameterSha256") != receipt_effective_parameter_sha256
        or handoff.get("applicationMode") != receipt_application_mode
        or handoff.get("deploymentRecordSha256") != receipt_deployment_record_sha256
        or handoff.get("deployedTemplateSha256") != receipt_deployed_template_sha256
        or plan.get("compiledTemplateSha256") != receipt_deployed_template_sha256
        or handoff.get("authorityBlobInventorySha256") != receipt_authority_inventory_sha256
        or handoff.get("imagePullEvidenceSha256") != receipt_image_pull_evidence_sha256
        or handoff.get("revocationAssignmentsSha256") != receipt_revocation_assignments_sha256
    ):
        raise OrchestrationError("prior stage deployment attestation chain does not match")
    planned_inventory = _validated_authority_blob_inventory(
        plan.get("authorityBlobInventory"),
        subscription_id=subscription_id,
    )
    if planned_inventory is None:
        raise OrchestrationError("prior stage plan is missing authority Blob inventory")
    if plan.get("authorityBlobInventorySha256") != _authority_checkpoint_sha256(planned_inventory):
        raise OrchestrationError("prior stage plan authority checkpoint digest does not match")
    inventory = _validated_authority_blob_inventory(
        handoff.get("authorityBlobInventory"),
        subscription_id=subscription_id,
    )
    if inventory is None:
        raise OrchestrationError("prior stage handoff is missing authority Blob inventory")
    if handoff.get("authorityBlobInventorySha256") != _authority_checkpoint_sha256(
        inventory
    ) or receipt.get("authorityBlobInventorySha256") != _authority_checkpoint_sha256(inventory):
        raise OrchestrationError("prior stage authority checkpoint digest chain does not match")
    _verify_authority_checkpoint_successor(
        previous_inventory=planned_inventory,
        current_inventory=inventory,
        allow_container_creation=(
            expected_stage == "producer" and planned_inventory.get("containerExists") is False
        ),
    )
    handoff_outputs = (
        _producer_outputs(handoff) if expected_stage == "producer" else _publisher_outputs(handoff)
    )
    expected_container_id = _canonical_subscription_resource_id(
        handoff_outputs[
            "guidanceAuthoritySourceContainerResourceId"
            if expected_stage == "producer"
            else "authorityContainerResourceId"
        ],
        subscription_id=subscription_id,
        field="prior stage handoff authority Blob container",
    )
    if inventory["containerResourceId"] != expected_container_id:
        raise OrchestrationError(
            "prior stage authority Blob inventory does not match its exact handoff output"
        )
    return {
        "handoffPath": handoff_path.resolve(),
        "handoff": handoff,
        "handoffArtifact": handoff_capture,
        "handoffSha256": handoff_digest,
        "receiptPath": receipt_path.resolve(),
        "receiptArtifact": receipt_capture,
        "receiptSha256": actual_receipt_digest,
        "reviewedReceiptSha256": reviewed_digest,
        "inventory": inventory,
    }


def _load_verified_predecessors(
    *,
    stage: str,
    handoff_paths: Mapping[str, Path | None],
    receipt_paths: Mapping[str, Path | None],
    reviewed_receipt_sha256s: Mapping[str, str | None],
    artifact_reader: _ArtifactReader | None = None,
) -> dict[str, dict[str, Any]]:
    reader = artifact_reader or _ArtifactReader()
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
            artifact_reader=reader,
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


def _predecessor_rotation_transition_assignments(
    verified: Mapping[str, Mapping[str, object]],
    *,
    subscription_id: str,
) -> list[dict[str, str]]:
    transitions: dict[str, dict[str, str]] = {}
    for predecessor, record in verified.items():
        plan = _mapping(
            record.get("plan"),
            field=f"verified {predecessor} plan",
        )
        for transition in _canonical_rotation_transition_assignments(
            plan.get("rotationTransitionAssignments"),
            subscription_id=subscription_id,
            field=f"{predecessor} rotation transition assignments",
        ):
            normalized_id = transition["assignmentResourceId"].casefold()
            existing = transitions.get(normalized_id)
            if existing is not None and existing != transition:
                raise OrchestrationError(
                    "predecessor rotation transition evidence binds one assignment "
                    "to conflicting retired principals"
                )
            transitions[normalized_id] = transition
    return sorted(
        transitions.values(),
        key=lambda item: (
            item["assignmentResourceId"].casefold(),
            item["retiredPrincipalId"],
        ),
    )


def _predecessor_legacy_acr_pull_migration_assignments(
    verified: Mapping[str, Mapping[str, object]],
    *,
    subscription_id: str,
) -> list[dict[str, str]]:
    migrations: dict[str, dict[str, str]] = {}
    for predecessor, record in verified.items():
        plan = _mapping(
            record.get("plan"),
            field=f"verified {predecessor} plan",
        )
        for migration in _canonical_legacy_acr_pull_migration_assignments(
            plan.get("legacyAcrPullMigrationAssignments"),
            subscription_id=subscription_id,
            field=f"{predecessor} legacy ACR pull migrations",
        ):
            normalized_id = migration["assignmentResourceId"].casefold()
            existing = migrations.get(normalized_id)
            if existing is not None and existing != migration:
                raise OrchestrationError(
                    "predecessor legacy ACR migration binds one assignment "
                    "to conflicting principals"
                )
            migrations[normalized_id] = migration
    return sorted(
        migrations.values(),
        key=lambda item: (
            item["assignmentResourceId"].casefold(),
            item["principalId"],
        ),
    )


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


def _validated_wc013_acr_pull_assignments(
    value: object,
    *,
    subscription_id: str,
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise OrchestrationError("WC-013 ACR pull assignments must be an array")
    assignments: list[dict[str, object]] = []
    for index, raw_assignment in enumerate(value):
        assignment = _mapping(
            raw_assignment,
            field=f"WC-013 ACR pull assignment {index}",
        )
        _require_exact_fields(
            assignment,
            frozenset(
                {
                    "label",
                    "assignmentResourceId",
                    "principalId",
                    "principalType",
                    "roleDefinitionId",
                    "roleAssignmentMode",
                    "anonymousPullEnabled",
                    "scope",
                    "image",
                    "repositoryName",
                    "conditionVersion",
                    "condition",
                }
            ),
            field=f"WC-013 ACR pull assignment {index}",
        )
        _string(
            assignment.get("label"),
            field=f"WC-013 ACR pull assignment {index} label",
        )
        assignment_resource_id = _canonical_subscription_resource_id(
            assignment.get("assignmentResourceId"),
            subscription_id=subscription_id,
            field=f"WC-013 ACR pull assignment {index} ID",
        )
        principal_id = _canonical_directory_object_id(
            assignment.get("principalId"),
            field=f"WC-013 ACR pull assignment {index} principal",
        )
        if assignment.get("principalType") != "ServicePrincipal":
            raise OrchestrationError(
                "WC-013 ACR pull assignment principal type must be ServicePrincipal"
            )
        role_assignment_mode = _acr_role_assignment_mode(
            assignment.get("roleAssignmentMode"),
            field=f"WC-013 ACR pull assignment {index} mode",
        )
        if assignment.get("anonymousPullEnabled") is not False:
            raise OrchestrationError(
                "WC-013 ACR pull assignment must prove anonymousPullEnabled is false"
            )
        expected_role_definition_id = _acr_pull_role_definition_id(
            role_assignment_mode=role_assignment_mode,
            subscription_id=subscription_id,
        )
        _require_subscription_resource_id_equal(
            assignment.get("roleDefinitionId"),
            expected_role_definition_id,
            subscription_id=subscription_id,
            field=f"WC-013 ACR pull assignment {index} role",
        )
        scope = _canonical_subscription_resource_id(
            assignment.get("scope"),
            subscription_id=subscription_id,
            field=f"WC-013 ACR pull assignment {index} scope",
        )
        if _resource_type(scope) != "microsoft.containerregistry/registries":
            raise OrchestrationError("WC-013 ACR pull assignment scope must identify one registry")
        image = _digest_pinned_image(
            assignment.get("image"),
            field=f"WC-013 ACR pull assignment {index} image",
        )
        repository_name = _acr_repository_name(
            image,
            scope,
            field=f"WC-013 ACR pull assignment {index} image",
        )
        _require_equal(
            assignment.get("repositoryName"),
            repository_name,
            field=f"WC-013 ACR pull assignment {index} repository name",
        )
        _require_subscription_resource_id_equal(
            assignment_resource_id,
            _acr_pull_role_assignment_id(
                scope=scope,
                principal_id=principal_id,
                role_definition_id=expected_role_definition_id,
                role_assignment_mode=role_assignment_mode,
                repository_name=repository_name,
            ),
            subscription_id=subscription_id,
            field=f"WC-013 ACR pull assignment {index} deterministic ID",
        )
        expected_condition_version, expected_condition = _acr_pull_assignment_condition(
            role_assignment_mode=role_assignment_mode,
            repository_name=repository_name,
        )
        if (
            assignment.get("conditionVersion") != expected_condition_version
            or assignment.get("condition") != expected_condition
        ):
            raise OrchestrationError(
                "WC-013 ACR pull assignment condition does not restrict its exact repository"
            )
        assignments.append(dict(assignment))
    labels = tuple(item["label"] for item in assignments)
    presentation = next(
        (item for item in assignments if item["label"] == "presentation"),
        None,
    )
    if presentation is None:
        raise OrchestrationError(
            "WC-013 ACR pull assignment labels/order do not match the exact inventory"
        )
    expected_labels = (
        WC013_ACR_ABAC_ASSIGNMENT_LABELS
        if presentation["roleAssignmentMode"] == ACR_ABAC_ROLE_ASSIGNMENT_MODE
        else WC013_ACR_ASSIGNMENT_LABELS
    )
    if labels != expected_labels:
        raise OrchestrationError(
            "WC-013 ACR pull assignment labels/order do not match the exact inventory"
        )
    assignment_ids = {str(item["assignmentResourceId"]).casefold() for item in assignments}
    if len(assignment_ids) != len(assignments):
        raise OrchestrationError("WC-013 ACR pull assignment IDs must be distinct")
    labels_by_principal: dict[str, set[str]] = {}
    for item in assignments:
        labels_by_principal.setdefault(
            str(item["principalId"]).casefold(),
            set(),
        ).add(str(item["label"]))
    duplicate_label_sets = {
        frozenset(item_labels)
        for item_labels in labels_by_principal.values()
        if len(item_labels) > 1
    }
    allowed_duplicate_label_sets = (
        {frozenset({"presentation", "presentation-delivery"})}
        if labels == WC013_ACR_ABAC_ASSIGNMENT_LABELS
        else set()
    )
    if duplicate_label_sets - allowed_duplicate_label_sets:
        raise OrchestrationError(
            "WC-013 ACR pull assignment principals must be distinct except for "
            "the exact ABAC presentation image pair"
        )
    if labels == WC013_ACR_ABAC_ASSIGNMENT_LABELS:
        presentation_delivery = next(
            item for item in assignments if item["label"] == "presentation-delivery"
        )
        if (
            presentation_delivery["principalId"] != presentation["principalId"]
            or str(presentation_delivery["scope"]).casefold()
            != str(presentation["scope"]).casefold()
            or presentation_delivery["roleAssignmentMode"] != ACR_ABAC_ROLE_ASSIGNMENT_MODE
            or presentation_delivery["repositoryName"] == presentation["repositoryName"]
        ):
            raise OrchestrationError(
                "WC-013 ABAC presentation assignments must bind one principal to "
                "two distinct exact image repositories"
            )
    return assignments


def _verify_wc013_acr_pull_assignments(
    value: object,
    *,
    subscription_id: str,
) -> list[dict[str, object]]:
    assignments = _validated_wc013_acr_pull_assignments(
        value,
        subscription_id=subscription_id,
    )
    expected_by_principal: dict[str, list[dict[str, object]]] = {}
    for item in assignments:
        expected_by_principal.setdefault(
            str(item["principalId"]).casefold(),
            [],
        ).append(item)
    registry_modes: dict[str, str] = {}
    for assignment in assignments:
        scope = str(assignment["scope"])
        normalized_scope = scope.casefold()
        if normalized_scope not in registry_modes:
            registry = _get_resource(
                scope,
                subscription_id=subscription_id,
            )
            _require_resource_id_equal(
                registry.get("id"),
                scope,
                field="WC-013 ACR runtime readback",
            )
            registry_modes[normalized_scope] = _acr_role_assignment_mode(
                _mapping(
                    registry.get("properties"),
                    field="WC-013 ACR properties",
                ).get("roleAssignmentMode"),
                field="WC-013 ACR live role-assignment mode",
            )
            _require_anonymous_pull_disabled(
                _mapping(
                    registry.get("properties"),
                    field="WC-013 ACR properties",
                ),
                field="WC-013 ACR",
            )
        _require_equal(
            assignment["roleAssignmentMode"],
            registry_modes[normalized_scope],
            field="WC-013 ACR role-assignment mode",
        )
        assignment_resource = _get_resource(
            str(assignment["assignmentResourceId"]),
            subscription_id=subscription_id,
        )
        _require_resource_id_equal(
            assignment_resource.get("id"),
            assignment["assignmentResourceId"],
            field="WC-013 ACR assignment readback",
        )
        properties = _mapping(
            assignment_resource.get("properties"),
            field="WC-013 ACR assignment properties",
        )
        if (
            _canonical_directory_object_id(
                properties.get("principalId"),
                field="WC-013 ACR assignment principal",
            )
            != assignment["principalId"]
            or properties.get("principalType") != "ServicePrincipal"
        ):
            raise OrchestrationError("WC-013 ACR assignment principal does not match inventory")
        _require_subscription_resource_id_equal(
            properties.get("roleDefinitionId"),
            assignment["roleDefinitionId"],
            subscription_id=subscription_id,
            field="WC-013 ACR assignment role",
        )
        if properties.get("scope") is not None:
            _require_resource_id_equal(
                properties.get("scope"),
                scope,
                field="WC-013 ACR assignment scope",
            )
        if (
            properties.get("conditionVersion") != assignment["conditionVersion"]
            or properties.get("condition") != assignment["condition"]
        ):
            raise OrchestrationError(
                "WC-013 ACR assignment does not preserve its exact repository condition"
            )
    _verify_exact_pull_capable_assignments(
        set(expected_by_principal),
        expected_acr_assignments_by_principal={
            principal_id: {
                str(expected["assignmentResourceId"]).casefold()
                for expected in expected_assignments
            }
            for principal_id, expected_assignments in expected_by_principal.items()
        },
        subscription_id=subscription_id,
        field="effective WC-013 ACR assignments",
    )
    _verify_no_applicable_deny_assignments(
        [
            _ExpectedRoleAssignment(
                label=f"WC-013 {assignment['label']} image pull",
                principal_id=str(assignment["principalId"]),
                scope=str(assignment["scope"]),
                role_definition_id=str(assignment["roleDefinitionId"]),
                condition_version=(
                    None
                    if assignment["conditionVersion"] is None
                    else str(assignment["conditionVersion"])
                ),
                condition=(
                    None if assignment["condition"] is None else str(assignment["condition"])
                ),
                repository_name=str(assignment["repositoryName"]),
            )
            for assignment in assignments
        ],
        subscription_id=subscription_id,
    )
    return assignments


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
            frozenset(
                {
                    "wc027OrchestrationFoundation",
                    "wc013AcrPullAssignments",
                }
            ),
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
    handoff_subscription = (
        _canonical_subscription_id(
            handoff.get("subscriptionId"),
            field="foundation handoff subscription",
        )
        if handoff.get("subscriptionId") is not None
        else _resource_subscription_and_group(
            _string(
                outputs.get("managedEnvironmentResourceId"),
                field="foundation managed environment",
            )
        )[0]
    )
    wc013_acr_assignments = _validated_wc013_acr_pull_assignments(
        approved_configuration.get("wc013AcrPullAssignments"),
        subscription_id=handoff_subscription,
    )
    normalized_outputs.update(
        {
            "wc016NotificationQueueName": wc027_foundation.get("notificationQueueName"),
            "incidentSigningKeyFingerprint": wc027_foundation.get("incidentSigningKeyFingerprint"),
            "incidentFeedV2SigningKeyUriWithVersion": wc027_foundation.get(
                "feedSigningKeyUriWithVersion"
            ),
            "feedSigningKeyFingerprint": wc027_foundation.get("feedSigningKeyFingerprint"),
            "incidentReportSigningKeyUriWithVersion": wc027_foundation.get(
                "reportSigningKeyUriWithVersion"
            ),
            "reportSigningKeyFingerprint": wc027_foundation.get("reportSigningKeyFingerprint"),
            "incidentGuidanceSigningKeyUriWithVersion": wc027_foundation.get(
                "guidanceSigningKeyUriWithVersion"
            ),
            "guidanceSigningKeyFingerprint": wc027_foundation.get("guidanceSigningKeyFingerprint"),
            "incidentEnrichmentSigningKeyUriWithVersion": wc027_foundation.get(
                "enrichmentSigningKeyUriWithVersion"
            ),
            "enrichmentSigningKeyFingerprint": wc027_foundation.get(
                "enrichmentSigningKeyFingerprint"
            ),
            "incidentNotificationSigningKeyUriWithVersion": wc027_foundation.get(
                "notificationSigningKeyUriWithVersion"
            ),
            "notificationSigningKeyFingerprint": wc027_foundation.get(
                "notificationSigningKeyFingerprint"
            ),
            "wc013AcrPullAssignments": wc013_acr_assignments,
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
        "incidentSigningKeyFingerprint",
        "incidentFeedV2SigningKeyUriWithVersion",
        "feedSigningKeyFingerprint",
        "incidentReportSigningKeyUriWithVersion",
        "reportSigningKeyFingerprint",
        "incidentGuidanceSigningKeyUriWithVersion",
        "guidanceSigningKeyFingerprint",
        "incidentEnrichmentSigningKeyUriWithVersion",
        "enrichmentSigningKeyFingerprint",
        "incidentNotificationSigningKeyUriWithVersion",
        "notificationSigningKeyFingerprint",
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
    for name in (
        "incidentSigningKeyUriWithVersion",
        "incidentFeedV2SigningKeyUriWithVersion",
        "incidentReportSigningKeyUriWithVersion",
        "incidentGuidanceSigningKeyUriWithVersion",
        "incidentEnrichmentSigningKeyUriWithVersion",
        "incidentNotificationSigningKeyUriWithVersion",
    ):
        _key_name(_string(normalized_outputs[name], field=name))
    for name in (
        "incidentSigningKeyFingerprint",
        "feedSigningKeyFingerprint",
        "reportSigningKeyFingerprint",
        "guidanceSigningKeyFingerprint",
        "enrichmentSigningKeyFingerprint",
        "notificationSigningKeyFingerprint",
    ):
        _sha256_digest(normalized_outputs[name], field=name)
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
        Wc027EnrichmentFeedProductionConfiguration.model_validate_json(configuration_json)
    except (TypeError, ValueError) as exc:
        raise OrchestrationError(
            "producer configuration fails the authoritative production model"
        ) from exc
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
        "registryResourceId",
        "registryPullRoleAssignmentResourceId",
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
    registry_mode = _acr_role_assignment_mode(
        outputs.get("registryRoleAssignmentMode"),
        field="producer registry role-assignment mode",
    )
    if outputs.get("registryAnonymousPullEnabled") is not False:
        raise OrchestrationError("producer registry anonymousPullEnabled must be explicitly false")
    repository_name = _acr_repository_name(
        outputs["producerImage"],
        outputs["registryResourceId"],
        field="producer image",
    )
    _require_equal(
        outputs.get("registryRepositoryName"),
        repository_name,
        field="producer registry repository name",
    )
    condition_version, condition = _acr_pull_assignment_condition(
        role_assignment_mode=registry_mode,
        repository_name=repository_name,
    )
    _require_equal(
        outputs.get("registryPullConditionVersion"),
        condition_version,
        field="producer registry pull condition version",
    )
    _require_equal(
        outputs.get("registryPullCondition"),
        condition,
        field="producer registry pull condition",
    )
    _string(
        outputs.get("registryPullRoleDefinitionId"),
        field="producer registry pull role definition",
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
        Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(configuration_json)
    except (TypeError, ValueError) as exc:
        raise OrchestrationError(
            "publisher configuration fails the authoritative production model"
        ) from exc
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
        "registryResourceId",
        "registryPullRoleAssignmentResourceId",
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
    registry_mode = _acr_role_assignment_mode(
        outputs.get("registryRoleAssignmentMode"),
        field="publisher registry role-assignment mode",
    )
    if outputs.get("registryAnonymousPullEnabled") is not False:
        raise OrchestrationError("publisher registry anonymousPullEnabled must be explicitly false")
    repository_name = _acr_repository_name(
        outputs["publisherImage"],
        outputs["registryResourceId"],
        field="publisher image",
    )
    _require_equal(
        outputs.get("registryRepositoryName"),
        repository_name,
        field="publisher registry repository name",
    )
    condition_version, condition = _acr_pull_assignment_condition(
        role_assignment_mode=registry_mode,
        repository_name=repository_name,
    )
    _require_equal(
        outputs.get("registryPullConditionVersion"),
        condition_version,
        field="publisher registry pull condition version",
    )
    _require_equal(
        outputs.get("registryPullCondition"),
        condition,
        field="publisher registry pull condition",
    )
    _string(
        outputs.get("registryPullRoleDefinitionId"),
        field="publisher registry pull role definition",
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
    _set_parameter(
        parameters,
        "registryRoleAssignmentMode",
        outputs["registryRoleAssignmentMode"],
    )
    _set_parameter(
        parameters,
        "registryResourceId",
        _azure_resource_id(
            producer_bindings.get("registryResourceId"),
            field="producer registry resource binding",
        ),
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
    reader = _ArtifactReader()
    parameter_document = reader.capture_json(
        parameter_path,
        field="base parameter document",
    ).document
    handoffs: dict[str, Mapping[str, object]] = {}
    for handoff_stage, handoff_path in (
        ("foundation", foundation_handoff_path),
        ("producer", producer_handoff_path),
        ("publisher", publisher_handoff_path),
    ):
        if handoff_path is not None:
            handoffs[handoff_stage] = _load_handoff(
                handoff_path,
                expected_stage=handoff_stage,
                artifact_reader=reader,
            )
    return _build_effective_parameters_from_documents(
        stage=stage,
        parameter_document=parameter_document,
        handoffs=handoffs,
    )


def _build_effective_parameters_from_documents(
    *,
    stage: str,
    parameter_document: object,
    handoffs: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    parameters = _load_parameter_document(parameter_document)
    if stage == "foundation":
        return _foundation_parameters(parameters)
    if stage == "producer":
        foundation = handoffs.get("foundation")
        if foundation is None:
            raise OrchestrationError("producer stage requires a foundation handoff")
        return _producer_parameters(
            parameters,
            foundation,
        )
    if stage == "publisher":
        foundation = handoffs.get("foundation")
        producer = handoffs.get("producer")
        if foundation is None or producer is None:
            raise OrchestrationError("publisher stage requires foundation and producer handoffs")
        return _publisher_parameters(
            parameters,
            foundation,
            producer,
        )
    if stage == "live-acceptance":
        foundation = handoffs.get("foundation")
        producer = handoffs.get("producer")
        publisher = handoffs.get("publisher")
        if foundation is None or producer is None or publisher is None:
            raise OrchestrationError(
                "live-acceptance requires foundation, producer, and publisher handoffs"
            )
        return _acceptance_parameters(
            parameters,
            foundation,
            producer,
            publisher,
        )
    raise OrchestrationError(f"unsupported deployment stage: {stage}")


def _bind_broker_identity_principal(
    *,
    stage: str,
    effective_parameters: dict[str, dict[str, object]],
    subscription_id: str,
) -> None:
    if stage not in {"producer", "publisher"}:
        return
    identity_resource_id = _canonical_subscription_resource_id(
        _parameter_value(
            effective_parameters,
            "brokerIdentityResourceId",
        ),
        subscription_id=subscription_id,
        field=f"{stage} broker identity resource ID",
    )
    identity = _get_resource(
        identity_resource_id,
        subscription_id=subscription_id,
    )
    _require_resource_id_equal(
        identity.get("id"),
        identity_resource_id,
        field=f"{stage} broker identity runtime readback",
    )
    properties = _mapping(
        identity.get("properties"),
        field=f"{stage} broker identity properties",
    )
    _set_parameter(
        effective_parameters,
        "brokerIdentityPrincipalId",
        _canonical_directory_object_id(
            properties.get("principalId"),
            field=f"{stage} broker identity principal ID",
        ),
    )


def _parameter_document(parameters: Mapping[str, object]) -> dict[str, object]:
    return {
        "$schema": (
            "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
        ),
        "contentVersion": "1.0.0.0",
        "parameters": parameters,
    }


def _azure_location(value: object, *, field: str) -> str:
    location = _string(value, field=field)
    if (
        location != location.strip()
        or location != location.casefold()
        or re.fullmatch(r"[a-z0-9-]{1,64}", location) is None
    ):
        raise OrchestrationError(f"{field} must be one canonical Azure location")
    return location


def _resource_group_location(
    *,
    subscription_id: str,
    resource_group: str,
) -> str:
    canonical_resource_group = _string(
        resource_group,
        field="deployment resource group",
    )
    _validate_resource_id_segment(
        canonical_resource_group,
        field="deployment resource group",
    )
    expected_id = f"/subscriptions/{subscription_id}/resourceGroups/{canonical_resource_group}"
    document = _mapping(
        _run_json(
            [
                "az",
                "group",
                "show",
                "--subscription",
                subscription_id,
                "--name",
                canonical_resource_group,
                "--only-show-errors",
                "--output",
                "json",
            ],
            field="deployment resource group",
        ),
        field="deployment resource group",
    )
    actual_id = _canonical_subscription_resource_id(
        document.get("id"),
        subscription_id=subscription_id,
        field="deployment resource-group ID",
    )
    if actual_id.casefold() != expected_id.casefold():
        raise OrchestrationError(
            "deployment resource-group readback does not match its exact scope"
        )
    if (
        _string(document.get("name"), field="deployment resource-group name").casefold()
        != canonical_resource_group.casefold()
    ):
        raise OrchestrationError("deployment resource-group readback does not match its exact name")
    properties = _mapping(
        document.get("properties"),
        field="deployment resource-group properties",
    )
    _require_equal(
        properties.get("provisioningState"),
        "Succeeded",
        field="deployment resource-group provisioning state",
    )
    return _azure_location(
        document.get("location"),
        field="deployment resource-group location",
    )


def _effective_deployment_location(
    *,
    stage: str,
    reviewed_location: object,
    subscription_id: str,
    resource_group: str | None,
) -> str:
    location = _azure_location(
        reviewed_location,
        field="reviewed deployment location",
    )
    if stage in SUBSCRIPTION_STAGES:
        if resource_group is not None:
            raise OrchestrationError(
                f"{stage} deployment location cannot be bound to a resource group"
            )
        return location
    live_location = _resource_group_location(
        subscription_id=subscription_id,
        resource_group=_string(
            resource_group,
            field=f"{stage} deployment resource group",
        ),
    )
    if live_location != location:
        raise OrchestrationError(
            f"{stage} reviewed location does not match the live resource-group location"
        )
    return live_location


def _az_command(
    *,
    operation: str,
    stage: str,
    deployment_name: str,
    subscription_id: str,
    location: str,
    resource_group: str | None,
    template_path: Path,
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
            str(template_path),
            "--parameters",
            str(parameter_path),
            "--no-prompt",
            "true",
            "--only-show-errors",
            "--output",
            "json",
        ]
    )
    if operation == "what-if":
        command.extend(["--result-format", "FullResourcePayloads", "--no-pretty-print"])
    return command


def _command_timeout(command: Sequence[str]) -> tuple[str, int, bool]:
    arguments = list(command)
    if not arguments or arguments[0] != "az":
        raise OrchestrationError("subprocess operation has no reviewed timeout classification")
    if len(arguments) >= 4 and arguments[1] == "deployment":
        scope = arguments[2]
        operation = arguments[3]
        if scope not in {"sub", "group"}:
            raise OrchestrationError("deployment command has an unsupported scope")
        timeout_by_operation = {
            "validate": DEPLOYMENT_VALIDATE_TIMEOUT_SECONDS,
            "what-if": DEPLOYMENT_WHAT_IF_TIMEOUT_SECONDS,
            "create": DEPLOYMENT_CREATE_TIMEOUT_SECONDS,
            "show": AZURE_READ_TIMEOUT_SECONDS,
            "export": AZURE_LIST_TIMEOUT_SECONDS,
        }
        timeout_seconds = timeout_by_operation.get(operation)
        if timeout_seconds is None:
            raise OrchestrationError("deployment command has no reviewed timeout")
        return (
            f"Azure {scope} deployment {operation}",
            timeout_seconds,
            operation == "create",
        )
    reviewed_operations: tuple[tuple[tuple[str, ...], str, int, bool], ...] = (
        (("az", "bicep", "build"), "Bicep build", BICEP_BUILD_TIMEOUT_SECONDS, False),
        (("az", "rest"), "Azure REST read", AZURE_READ_TIMEOUT_SECONDS, False),
        (("az", "resource", "show"), "Azure resource read", AZURE_READ_TIMEOUT_SECONDS, False),
        (("az", "group", "show"), "Azure resource-group read", AZURE_READ_TIMEOUT_SECONDS, False),
        (
            ("az", "role", "assignment", "list"),
            "Azure role-assignment list",
            AZURE_LIST_TIMEOUT_SECONDS,
            False,
        ),
        (
            ("az", "storage", "container", "exists"),
            "Azure Blob container existence read",
            AZURE_READ_TIMEOUT_SECONDS,
            False,
        ),
        (
            ("az", "storage", "blob", "list"),
            "Azure Blob list",
            AZURE_LIST_TIMEOUT_SECONDS,
            False,
        ),
        (
            ("az", "storage", "blob", "download"),
            "Azure Blob download",
            AZURE_LIST_TIMEOUT_SECONDS,
            False,
        ),
        (
            ("az", "storage", "account", "blob-service-properties", "show"),
            "Azure Blob service properties read",
            AZURE_READ_TIMEOUT_SECONDS,
            False,
        ),
        (
            ("az", "keyvault", "key", "show"),
            "Azure Key Vault key read",
            AZURE_READ_TIMEOUT_SECONDS,
            False,
        ),
        (
            ("az", "containerapp", "job", "start"),
            "Azure Container Apps Job start",
            CONTAINER_APP_JOB_START_TIMEOUT_SECONDS,
            True,
        ),
        (
            ("az", "containerapp", "job", "execution", "show"),
            "Azure Container Apps Job execution read",
            AZURE_READ_TIMEOUT_SECONDS,
            False,
        ),
    )
    for prefix, operation, timeout_seconds, outcome_unknown in reviewed_operations:
        if tuple(arguments[: len(prefix)]) == prefix:
            return operation, timeout_seconds, outcome_unknown
    raise OrchestrationError("Azure CLI operation has no reviewed bounded timeout")


def _run(command: Sequence[str]) -> str:
    operation, timeout_seconds, outcome_unknown = _command_timeout(command)
    resolved_command = list(command)
    if resolved_command and resolved_command[0] == "az":
        az_executable = shutil.which("az") or shutil.which("az.cmd")
        if az_executable is None:
            raise OrchestrationError("Azure CLI executable is unavailable")
        resolved_command[0] = az_executable
    try:
        completed = subprocess.run(  # noqa: S603
            resolved_command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        raise _CommandTimeout(
            operation=operation,
            timeout_seconds=timeout_seconds,
            outcome_unknown=outcome_unknown,
        ) from None
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise _CommandFailure(completed.returncode, detail)
    return completed.stdout


def _run_bytes(command: Sequence[str]) -> bytes:
    operation, timeout_seconds, outcome_unknown = _command_timeout(command)
    resolved_command = list(command)
    if resolved_command and resolved_command[0] == "az":
        az_executable = shutil.which("az") or shutil.which("az.cmd")
        if az_executable is None:
            raise OrchestrationError("Azure CLI executable is unavailable")
        resolved_command[0] = az_executable
    try:
        completed = subprocess.run(  # noqa: S603
            resolved_command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        raise _CommandTimeout(
            operation=operation,
            timeout_seconds=timeout_seconds,
            outcome_unknown=outcome_unknown,
        ) from None
    if completed.returncode != 0:
        detail_bytes = completed.stderr.strip() or completed.stdout.strip()
        detail = detail_bytes.decode("utf-8", errors="replace")
        raise _CommandFailure(completed.returncode, detail)
    return completed.stdout


def _run_json(command: Sequence[str], *, field: str) -> object:
    output = _run(command)
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise OrchestrationError(f"{field} did not return valid JSON") from exc


def _azure_error_code(detail: str) -> str | None:
    try:
        document = json.loads(detail)
    except json.JSONDecodeError:
        document = None
    if isinstance(document, dict):
        error = document.get("error")
        candidates = [document, error] if isinstance(error, dict) else [document]
        for candidate in candidates:
            code = candidate.get("code")
            if isinstance(code, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", code):
                return code
    for pattern in (
        r"(?m)^(?:ERROR:\s*)?\(([A-Za-z][A-Za-z0-9_.-]{0,127})\)",
        r"(?m)^\s*Code:\s*([A-Za-z][A-Za-z0-9_.-]{0,127})\s*$",
    ):
        match = re.search(pattern, detail)
        if match is not None:
            return match.group(1)
    return None


def _run_json_allowing_absence(
    command: Sequence[str],
    *,
    field: str,
    absent_error_codes: frozenset[str],
) -> object | None:
    try:
        return _run_json(command, field=field)
    except _CommandFailure as exc:
        error_code = _azure_error_code(exc.detail)
        if error_code is not None and error_code.casefold() in {
            code.casefold() for code in absent_error_codes
        }:
            return None
        raise


def _retry_eventually_consistent[T](
    operation: Callable[[], T],
    *,
    field: str,
) -> T:
    last_error: OrchestrationError | None = None
    for attempt in range(1, READBACK_MAX_ATTEMPTS + 1):
        try:
            return operation()
        except TerminalEvidenceError, _TerminalDeploymentFailure, _UnknownDeploymentOutcome:
            raise
        except _CommandTimeout as exc:
            if exc.outcome_unknown:
                raise
            last_error = exc
            if attempt < READBACK_MAX_ATTEMPTS:
                time.sleep(READBACK_RETRY_SECONDS)
        except OrchestrationError as exc:
            last_error = exc
            if attempt == READBACK_MAX_ATTEMPTS:
                break
            time.sleep(READBACK_RETRY_SECONDS)
    if last_error is None:
        raise OrchestrationError(f"{field} failed without a captured error")
    raise OrchestrationError(
        f"{field} did not converge after {READBACK_MAX_ATTEMPTS} bounded read-only attempts: "
        f"{last_error}"
    ) from last_error


def _retry_post_deployment_readiness(
    operation: Callable[
        [],
        tuple[dict[str, object] | None, dict[str, object] | None],
    ],
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    return _retry_eventually_consistent(
        operation,
        field="post-deployment readiness and authority checkpoint",
    )


def _deployment_read_command(
    *,
    operation: str,
    stage: str,
    deployment_name: str,
    subscription_id: str,
    resource_group: str | None,
) -> list[str]:
    if operation not in {"show", "export"}:
        raise OrchestrationError("deployment read operation is unsupported")
    scope = "sub" if stage in SUBSCRIPTION_STAGES else "group"
    command = [
        "az",
        "deployment",
        scope,
        operation,
        "--subscription",
        subscription_id,
        "--name",
        deployment_name,
    ]
    if scope == "group":
        if not resource_group:
            raise OrchestrationError(f"{stage} requires a resource group")
        command.extend(["--resource-group", resource_group])
    command.extend(["--only-show-errors", "--output", "json"])
    return command


def _optional_resource(
    resource_id: str,
    *,
    subscription_id: str,
    field: str,
) -> dict[str, Any] | None:
    canonical_resource_id = _canonical_subscription_resource_id(
        resource_id,
        subscription_id=subscription_id,
        field=field,
    )
    document = _run_json_allowing_absence(
        [
            "az",
            "resource",
            "show",
            "--subscription",
            subscription_id,
            "--ids",
            canonical_resource_id,
            "--only-show-errors",
            "--output",
            "json",
        ],
        field=field,
        absent_error_codes=frozenset({"ResourceNotFound"}),
    )
    if document is None:
        return None
    resource = _mapping(document, field=field)
    _require_resource_id_equal(
        resource.get("id"),
        canonical_resource_id,
        field=field,
    )
    return resource


def _publisher_job_resource_id(
    effective_parameters: Mapping[str, Mapping[str, object]],
    *,
    subscription_id: str,
    resource_group: str,
) -> str:
    name_prefix = _string(
        _parameter_value(effective_parameters, "namePrefix"),
        field="publisher name prefix",
    )
    resource_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/"
        f"providers/Microsoft.App/jobs/{name_prefix[:18]}-w27-guide-auth"
    )
    return _canonical_subscription_resource_id(
        resource_id,
        subscription_id=subscription_id,
        field="publisher Job resource ID",
    )


def _verify_initial_publisher_absence(
    *,
    effective_parameters: Mapping[str, Mapping[str, object]],
    deployment_name: str,
    subscription_id: str,
    resource_group: str,
) -> None:
    publisher_job_id = _publisher_job_resource_id(
        effective_parameters,
        subscription_id=subscription_id,
        resource_group=resource_group,
    )
    if (
        _optional_resource(
            publisher_job_id,
            subscription_id=subscription_id,
            field="initial publisher Job",
        )
        is not None
    ):
        raise OrchestrationError(
            "publisher Job already exists; a prior publisher receipt and checkpoint are required"
        )
    deployment = _run_json_allowing_absence(
        _deployment_read_command(
            operation="show",
            stage="publisher",
            deployment_name=deployment_name,
            subscription_id=subscription_id,
            resource_group=resource_group,
        ),
        field="initial publisher deployment",
        absent_error_codes=frozenset({"DeploymentNotFound"}),
    )
    if deployment is not None:
        record = _mapping(
            deployment,
            field="initial publisher deployment",
        )
        if record.get("name") != deployment_name:
            raise OrchestrationError(
                "initial publisher deployment readback does not match the requested name"
            )
        raise OrchestrationError(
            "publisher deployment already exists; a prior publisher receipt "
            "and checkpoint are required"
        )


def _deployment_resource_id(
    *,
    stage: str,
    deployment_name: str,
    subscription_id: str,
    resource_group: str | None,
) -> str:
    _validate_resource_id_segment(
        deployment_name,
        field="deployment name",
    )
    if stage in SUBSCRIPTION_STAGES:
        if resource_group is not None:
            raise OrchestrationError(f"{stage} deployment cannot include a resource-group scope")
        resource_id = (
            f"/subscriptions/{subscription_id}/providers/"
            f"Microsoft.Resources/deployments/{deployment_name}"
        )
    else:
        canonical_resource_group = _string(
            resource_group,
            field=f"{stage} deployment resource group",
        )
        _validate_resource_id_segment(
            canonical_resource_group,
            field=f"{stage} deployment resource group",
        )
        resource_id = (
            f"/subscriptions/{subscription_id}/resourceGroups/{canonical_resource_group}/"
            f"providers/Microsoft.Resources/deployments/{deployment_name}"
        )
    return _canonical_subscription_resource_id(
        resource_id,
        subscription_id=subscription_id,
        field="deployment resource ID",
    )


def _deployment_timestamp(value: object, *, field: str) -> datetime:
    timestamp = _string(value, field=field)
    if timestamp != timestamp.strip() or len(timestamp) > 128:
        raise OrchestrationError(f"{field} must be one bounded UTC timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OrchestrationError(f"{field} must be one ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise OrchestrationError(f"{field} must include a UTC offset")
    return parsed.astimezone(UTC)


def _required_deployment_field(
    value: Mapping[str, object],
    name: str,
    *,
    field: str,
    incomplete_is_unknown: bool,
) -> object:
    if name not in value:
        if incomplete_is_unknown:
            raise _UnknownDeploymentOutcome(
                f"{field} omitted required field {name}; deployment outcome is unknown"
            )
        raise OrchestrationError(f"{field} omitted required field {name}")
    return value[name]


def _validate_succeeded_deployment_record(
    document: object,
    *,
    stage: str,
    deployment_name: str,
    subscription_id: str,
    location: str,
    resource_group: str | None,
    effective_parameters: Mapping[str, Mapping[str, object]],
    compiled_template: Mapping[str, object],
    minimum_timestamp: datetime | None,
    incomplete_is_unknown: bool,
    field: str,
) -> dict[str, Any]:
    root = _mapping(document, field=field)
    properties = _mapping(
        _required_deployment_field(
            root,
            "properties",
            field=field,
            incomplete_is_unknown=incomplete_is_unknown,
        ),
        field=f"{field} properties",
    )
    state = _string(
        _required_deployment_field(
            properties,
            "provisioningState",
            field=f"{field} properties",
            incomplete_is_unknown=incomplete_is_unknown,
        ),
        field=f"{field} provisioning state",
    )
    if state in DEPLOYMENT_TERMINAL_FAILURE_STATES:
        raise _TerminalDeploymentFailure(f"{field} provisioning state is {state}")
    if state != "Succeeded":
        if incomplete_is_unknown and state in DEPLOYMENT_NONTERMINAL_STATES:
            raise _UnknownDeploymentOutcome(
                f"{field} is still {state}; deployment outcome is unknown"
            )
        raise OrchestrationError(f"{field} provisioning state is unsupported: {state}")
    expected_id = _deployment_resource_id(
        stage=stage,
        deployment_name=deployment_name,
        subscription_id=subscription_id,
        resource_group=resource_group,
    )
    actual_id = _canonical_subscription_resource_id(
        _required_deployment_field(
            root,
            "id",
            field=field,
            incomplete_is_unknown=incomplete_is_unknown,
        ),
        subscription_id=subscription_id,
        field=f"{field} ID",
    )
    if actual_id.casefold() != expected_id.casefold():
        raise OrchestrationError(f"{field} ID does not match the exact deployment scope")
    _require_equal(
        _required_deployment_field(
            root,
            "name",
            field=field,
            incomplete_is_unknown=incomplete_is_unknown,
        ),
        deployment_name,
        field=f"{field} name",
    )
    resource_type = _string(
        _required_deployment_field(
            root,
            "type",
            field=field,
            incomplete_is_unknown=incomplete_is_unknown,
        ),
        field=f"{field} type",
    )
    if resource_type.casefold() != "microsoft.resources/deployments":
        raise OrchestrationError(f"{field} type is not Microsoft.Resources/deployments")
    if stage in SUBSCRIPTION_STAGES:
        _require_equal(
            _azure_location(
                _required_deployment_field(
                    root,
                    "location",
                    field=field,
                    incomplete_is_unknown=incomplete_is_unknown,
                ),
                field=f"{field} location",
            ),
            location,
            field=f"{field} location",
        )
    elif root.get("location") is not None:
        _require_equal(
            _azure_location(root.get("location"), field=f"{field} location"),
            location,
            field=f"{field} location",
        )
    _require_equal(
        _required_deployment_field(
            properties,
            "mode",
            field=f"{field} properties",
            incomplete_is_unknown=incomplete_is_unknown,
        ),
        "Incremental",
        field=f"{field} mode",
    )
    timestamp = _deployment_timestamp(
        _required_deployment_field(
            properties,
            "timestamp",
            field=f"{field} properties",
            incomplete_is_unknown=incomplete_is_unknown,
        ),
        field=f"{field} timestamp",
    )
    now = datetime.now(UTC)
    if timestamp > now + DEPLOYMENT_TIMESTAMP_FUTURE_SKEW:
        raise OrchestrationError(f"{field} timestamp is implausibly in the future")
    if minimum_timestamp is not None and timestamp < minimum_timestamp.astimezone(UTC):
        raise OrchestrationError(f"{field} is stale relative to this deployment attempt")
    try:
        UUID(
            _string(
                _required_deployment_field(
                    properties,
                    "correlationId",
                    field=f"{field} properties",
                    incomplete_is_unknown=incomplete_is_unknown,
                ),
                field=f"{field} correlation ID",
            )
        )
    except ValueError as exc:
        raise OrchestrationError(f"{field} correlation ID must be one UUID") from exc
    duration = _string(
        _required_deployment_field(
            properties,
            "duration",
            field=f"{field} properties",
            incomplete_is_unknown=incomplete_is_unknown,
        ),
        field=f"{field} duration",
    )
    if len(duration) > 128 or not duration.startswith("P"):
        raise OrchestrationError(f"{field} duration is invalid")
    for list_field in ("providers", "dependencies"):
        values = _required_deployment_field(
            properties,
            list_field,
            field=f"{field} properties",
            incomplete_is_unknown=incomplete_is_unknown,
        )
        if not isinstance(values, list):
            raise OrchestrationError(f"{field} {list_field} must be an array")
    recorded_parameters = _required_deployment_field(
        properties,
        "parameters",
        field=f"{field} properties",
        incomplete_is_unknown=incomplete_is_unknown,
    )
    _required_deployment_field(
        properties,
        "outputs",
        field=f"{field} properties",
        incomplete_is_unknown=incomplete_is_unknown,
    )
    _verify_recorded_deployment_parameters(
        recorded_parameters,
        effective_parameters=effective_parameters,
        compiled_template=compiled_template,
    )
    return _deployment_outputs(root)


def _verify_deployment_absent_before_create(
    *,
    stage: str,
    deployment_name: str,
    subscription_id: str,
    resource_group: str | None,
) -> None:
    document = _run_json_allowing_absence(
        _deployment_read_command(
            operation="show",
            stage=stage,
            deployment_name=deployment_name,
            subscription_id=subscription_id,
            resource_group=resource_group,
        ),
        field="pre-create deployment readback",
        absent_error_codes=frozenset({"DeploymentNotFound"}),
    )
    if document is None:
        return
    record = _mapping(document, field="pre-create deployment readback")
    expected_id = _deployment_resource_id(
        stage=stage,
        deployment_name=deployment_name,
        subscription_id=subscription_id,
        resource_group=resource_group,
    )
    actual_id = _canonical_subscription_resource_id(
        record.get("id"),
        subscription_id=subscription_id,
        field="pre-create deployment ID",
    )
    if actual_id.casefold() != expected_id.casefold() or record.get("name") != deployment_name:
        raise OrchestrationError(
            "pre-create deployment readback returned a mismatched same-name record"
        )
    raise OrchestrationError(
        "deployment name already exists before create; refusing stale same-name reconciliation"
    )


def _verify_recorded_deployment_parameters(
    recorded: object,
    *,
    effective_parameters: Mapping[str, Mapping[str, object]],
    compiled_template: Mapping[str, object],
) -> None:
    recorded_parameters = _mapping(
        recorded,
        field="succeeded deployment parameters",
    )
    template_parameters = _mapping(
        compiled_template.get("parameters"),
        field="compiled template parameters",
    )
    missing = set(effective_parameters) - set(recorded_parameters)
    if missing:
        raise OrchestrationError(
            "succeeded deployment record omits reviewed parameters: " + ", ".join(sorted(missing))
        )
    for name, expected in effective_parameters.items():
        recorded_entry = _mapping(
            recorded_parameters[name],
            field=f"succeeded deployment parameter {name}",
        )
        if recorded_entry.get("value") != expected["value"]:
            raise OrchestrationError(
                f"succeeded deployment parameter {name} differs from reviewed bytes"
            )
    for name in set(recorded_parameters) - set(effective_parameters):
        definition = _mapping(
            template_parameters.get(name),
            field=f"compiled template parameter {name}",
        )
        recorded_entry = _mapping(
            recorded_parameters[name],
            field=f"succeeded deployment default parameter {name}",
        )
        if (
            "defaultValue" not in definition
            or recorded_entry.get("value") != definition["defaultValue"]
        ):
            raise OrchestrationError(f"succeeded deployment contains unreviewed parameter {name}")


def _attest_succeeded_deployment(
    *,
    stage: str,
    deployment_name: str,
    subscription_id: str,
    location: str,
    resource_group: str | None,
    effective_parameters: Mapping[str, Mapping[str, object]],
    compiled_template: Mapping[str, object],
    compiled_template_sha256: str,
    minimum_timestamp: datetime | None = None,
) -> tuple[dict[str, Any], str, str]:
    record = _mapping(
        _run_json(
            _deployment_read_command(
                operation="show",
                stage=stage,
                deployment_name=deployment_name,
                subscription_id=subscription_id,
                resource_group=resource_group,
            ),
            field="succeeded deployment record",
        ),
        field="succeeded deployment record",
    )
    outputs = _validate_succeeded_deployment_record(
        record,
        stage=stage,
        deployment_name=deployment_name,
        subscription_id=subscription_id,
        location=location,
        resource_group=resource_group,
        effective_parameters=effective_parameters,
        compiled_template=compiled_template,
        minimum_timestamp=minimum_timestamp,
        incomplete_is_unknown=False,
        field="succeeded deployment record",
    )
    exported_template = _mapping(
        _run_json(
            _deployment_read_command(
                operation="export",
                stage=stage,
                deployment_name=deployment_name,
                subscription_id=subscription_id,
                resource_group=resource_group,
            ),
            field="succeeded deployment exported template",
        ),
        field="succeeded deployment exported template",
    )
    deployed_template_sha256 = _sha256_bytes(_canonical_json_file_bytes(exported_template))
    if deployed_template_sha256 != compiled_template_sha256:
        raise OrchestrationError(
            "succeeded deployment template differs from the reviewed compiled template"
        )
    return (
        outputs,
        _sha256_bytes(_canonical_json_bytes(record)),
        deployed_template_sha256,
    )


def _execute_reviewed_deployment(
    *,
    resume_succeeded_deployment: bool,
    stage: str,
    deployment_name: str,
    subscription_id: str,
    location: str,
    resource_group: str | None,
    effective_parameter_artifact: _CapturedJsonArtifact,
    effective_parameters: Mapping[str, Mapping[str, object]],
    reviewed_what_if: object,
    compiled_template_artifact: _CapturedJsonArtifact,
    compiled_template: Mapping[str, object],
    compiled_template_sha256: str,
) -> tuple[dict[str, Any], str, str]:
    created_outputs: dict[str, Any] | None = None
    minimum_deployment_timestamp: datetime | None = None
    unknown_outcome_reason: OrchestrationError | None = None
    if not resume_succeeded_deployment:
        with (
            _materialized_private_artifact(
                compiled_template_artifact.raw_bytes,
                file_name="template.json",
            ) as pinned_template,
            _materialized_private_artifact(
                effective_parameter_artifact.raw_bytes
            ) as pinned_parameters,
        ):
            pinned_template.verify()
            pinned_parameters.verify()
            current_what_if = _run_json(
                _az_command(
                    operation="what-if",
                    stage=stage,
                    deployment_name=deployment_name,
                    subscription_id=subscription_id,
                    location=location,
                    resource_group=resource_group,
                    template_path=pinned_template.path,
                    parameter_path=pinned_parameters.path,
                ),
                field="current what-if",
            )
            pinned_template.verify()
            pinned_parameters.verify()
            _validate_subscription_boundary(
                current_what_if,
                subscription_id=subscription_id,
                field="current what-if",
            )
            if _canonical_json_bytes(current_what_if) != _canonical_json_bytes(reviewed_what_if):
                raise OrchestrationError(
                    "Azure state changed after review; current what-if differs from the plan"
                )
            _verify_deployment_absent_before_create(
                stage=stage,
                deployment_name=deployment_name,
                subscription_id=subscription_id,
                resource_group=resource_group,
            )
            minimum_deployment_timestamp = datetime.now(UTC)
            try:
                result = _run_json(
                    _az_command(
                        operation="create",
                        stage=stage,
                        deployment_name=deployment_name,
                        subscription_id=subscription_id,
                        location=location,
                        resource_group=resource_group,
                        template_path=pinned_template.path,
                        parameter_path=pinned_parameters.path,
                    ),
                    field="deployment create",
                )
            except _CommandTimeout as exc:
                if not exc.outcome_unknown:
                    raise
                unknown_outcome_reason = exc
            except _CommandFailure:
                raise
            except OrchestrationError as exc:
                unknown_outcome_reason = _UnknownDeploymentOutcome(
                    f"deployment create response was unreadable; outcome is unknown: {exc}"
                )
            else:
                try:
                    created_outputs = _validate_succeeded_deployment_record(
                        result,
                        stage=stage,
                        deployment_name=deployment_name,
                        subscription_id=subscription_id,
                        location=location,
                        resource_group=resource_group,
                        effective_parameters=effective_parameters,
                        compiled_template=compiled_template,
                        minimum_timestamp=minimum_deployment_timestamp,
                        incomplete_is_unknown=True,
                        field="deployment create response",
                    )
                except _UnknownDeploymentOutcome as exc:
                    unknown_outcome_reason = exc
            pinned_template.verify()
            pinned_parameters.verify()
    (
        outputs,
        deployment_record_sha256,
        deployed_template_sha256,
    ) = _retry_eventually_consistent(
        lambda: _attest_succeeded_deployment(
            stage=stage,
            deployment_name=deployment_name,
            subscription_id=subscription_id,
            location=location,
            resource_group=resource_group,
            effective_parameters=effective_parameters,
            compiled_template=compiled_template,
            compiled_template_sha256=compiled_template_sha256,
            minimum_timestamp=minimum_deployment_timestamp,
        ),
        field=(
            "unknown-outcome deployment read-only reconciliation"
            if unknown_outcome_reason is not None
            else "succeeded deployment attestation"
        ),
    )
    if created_outputs is not None and _canonical_json_bytes(
        created_outputs
    ) != _canonical_json_bytes(outputs):
        raise OrchestrationError(
            "succeeded deployment record outputs differ from the create response"
        )
    return (
        outputs,
        deployment_record_sha256,
        deployed_template_sha256,
    )


def _get_resource(resource_id: str, *, subscription_id: str) -> dict[str, Any]:
    governed_subscription_id = _canonical_subscription_id(
        subscription_id,
        field="governed subscription",
    )
    canonical_resource_id = _canonical_subscription_resource_id(
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
                canonical_resource_id,
                "--only-show-errors",
                "--output",
                "json",
            ],
            field=f"Azure resource {canonical_resource_id}",
        ),
        field=f"Azure resource {canonical_resource_id}",
    )


def _verify_resource(resource_id: str, *, subscription_id: str) -> None:
    resource = _get_resource(resource_id, subscription_id=subscription_id)
    _require_resource_id_equal(
        resource.get("id"),
        resource_id,
        field="Azure resource readback",
    )


def _verify_live_acr_authentication_required(
    registry_resource_id: str,
    *,
    expected_role_assignment_mode: object,
    subscription_id: str,
    field: str,
) -> str:
    registry = _get_resource(
        registry_resource_id,
        subscription_id=subscription_id,
    )
    _require_resource_id_equal(
        registry.get("id"),
        registry_resource_id,
        field=f"{field} registry runtime readback",
    )
    properties = _mapping(
        registry.get("properties"),
        field=f"{field} registry properties",
    )
    _require_anonymous_pull_disabled(
        properties,
        field=f"{field} registry",
    )
    role_assignment_mode = _acr_role_assignment_mode(
        properties.get("roleAssignmentMode"),
        field=f"{field} live registry role-assignment mode",
    )
    _require_equal(
        expected_role_assignment_mode,
        role_assignment_mode,
        field=f"{field} registry role-assignment mode",
    )
    return role_assignment_mode


def _verify_acr_pull_binding(
    outputs: Mapping[str, object],
    *,
    effective_parameters: Mapping[str, Mapping[str, object]],
    principal_id: str,
    subscription_id: str,
    field: str,
) -> str:
    image = _digest_pinned_image(
        outputs.get(f"{field}Image"),
        field=f"{field} image",
    )
    registry_resource_id = _canonical_subscription_resource_id(
        outputs.get("registryResourceId"),
        subscription_id=subscription_id,
        field=f"{field} registry resource ID",
    )
    _require_subscription_resource_id_equal(
        registry_resource_id,
        _parameter_value(effective_parameters, "registryResourceId"),
        subscription_id=subscription_id,
        field=f"{field} registry resource ID",
    )
    role_assignment_mode = _verify_live_acr_authentication_required(
        registry_resource_id,
        expected_role_assignment_mode=outputs.get("registryRoleAssignmentMode"),
        subscription_id=subscription_id,
        field=field,
    )
    _require_equal(
        outputs.get("registryAnonymousPullEnabled"),
        False,
        field=f"{field} registry anonymous-pull output",
    )
    _require_equal(
        _parameter_value(
            effective_parameters,
            "registryRoleAssignmentMode",
        ),
        role_assignment_mode,
        field=f"{field} reviewed registry role-assignment mode",
    )
    expected_role_definition_id = _acr_pull_role_definition_id(
        role_assignment_mode=role_assignment_mode,
        subscription_id=subscription_id,
    )
    _require_subscription_resource_id_equal(
        outputs.get("registryPullRoleDefinitionId"),
        expected_role_definition_id,
        subscription_id=subscription_id,
        field=f"{field} registry pull role definition",
    )
    repository_name = _acr_repository_name(
        image,
        registry_resource_id,
        field=f"{field} image",
    )
    _require_equal(
        outputs.get("registryRepositoryName"),
        repository_name,
        field=f"{field} registry repository name",
    )
    condition_version, condition = _acr_pull_assignment_condition(
        role_assignment_mode=role_assignment_mode,
        repository_name=repository_name,
    )
    _require_equal(
        outputs.get("registryPullConditionVersion"),
        condition_version,
        field=f"{field} registry pull condition version",
    )
    _require_equal(
        outputs.get("registryPullCondition"),
        condition,
        field=f"{field} registry pull condition",
    )
    expected_assignment_id = _acr_pull_role_assignment_id(
        scope=registry_resource_id,
        principal_id=principal_id,
        role_definition_id=expected_role_definition_id,
        role_assignment_mode=role_assignment_mode,
        repository_name=repository_name,
    )
    _require_subscription_resource_id_equal(
        outputs.get("registryPullRoleAssignmentResourceId"),
        expected_assignment_id,
        subscription_id=subscription_id,
        field=f"{field} registry pull assignment",
    )
    return expected_role_definition_id


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


def _blob_container_parts(
    resource_id: str,
) -> tuple[str, str, str, str]:
    container_id = _azure_resource_id(
        resource_id,
        field="Blob container resource ID",
    )
    if _resource_type(container_id) != "microsoft.storage/storageaccounts/blobservices/containers":
        raise OrchestrationError("authority Blob inventory requires an exact container resource ID")
    segments = [segment for segment in container_id.split("/") if segment]
    storage_account_name = segments[7]
    container_name = segments[11]
    storage_account_id = "/" + "/".join(segments[:8])
    blob_service_id = f"{storage_account_id}/blobServices/default"
    return (
        storage_account_name,
        container_name,
        storage_account_id,
        blob_service_id,
    )


def _verify_blob_service_versioning(
    container_resource_id: str,
    *,
    subscription_id: str,
) -> None:
    _, _, _, blob_service_id = _blob_container_parts(container_resource_id)
    blob_service = _get_resource(
        blob_service_id,
        subscription_id=subscription_id,
    )
    _require_resource_id_equal(
        blob_service.get("id"),
        blob_service_id,
        field="Blob service readback",
    )
    properties = _mapping(
        blob_service.get("properties"),
        field="Blob service properties",
    )
    if properties.get("isVersioningEnabled") is not True:
        raise OrchestrationError("authority Blob service versioning must be enabled")


def _blob_live_version_entry(value: object) -> dict[str, object]:
    item = _mapping(value, field="authority Blob inventory item")
    properties = _mapping(
        item.get("properties"),
        field="authority Blob inventory properties",
    )
    entry: dict[str, object] = {
        "name": _string(item.get("name"), field="authority Blob name"),
        "versionId": _string(
            item.get("versionId"),
            field="authority Blob version ID",
        ),
        "etag": _string(
            properties.get("etag"),
            field="authority Blob ETag",
        ),
        "contentLength": properties.get("contentLength"),
        "isCurrentVersion": item.get("isCurrentVersion"),
    }
    if (
        not isinstance(entry["contentLength"], int)
        or isinstance(entry["contentLength"], bool)
        or entry["contentLength"] < 0
    ):
        raise OrchestrationError("authority Blob content length must be a non-negative integer")
    if entry["isCurrentVersion"] not in (True, False):
        raise OrchestrationError("authority Blob version must declare isCurrentVersion")
    return entry


def _download_authority_blob_version(
    container_resource_id: str,
    *,
    blob_name: str,
    version_id: str,
    subscription_id: str,
) -> bytes:
    account_name, container_name, _, _ = _blob_container_parts(container_resource_id)
    return _run_bytes(
        [
            "az",
            "storage",
            "blob",
            "download",
            "--subscription",
            subscription_id,
            "--account-name",
            account_name,
            "--container-name",
            container_name,
            "--name",
            blob_name,
            "--version-id",
            version_id,
            "--auth-mode",
            "login",
            "--no-progress",
            "--only-show-errors",
            "--output",
            "none",
        ]
    )


def _authority_contract_metadata(
    *,
    blob_name: str,
    payload: bytes,
) -> dict[str, object]:
    try:
        if blob_name.startswith("guidance-authority/"):
            authority = PublishedGuidanceAuthority.model_validate_json(payload)
            if payload != authority.canonical_bytes() or blob_name != (
                f"guidance-authority/{authority.authority_id}/authority.json"
            ):
                raise OrchestrationError("authority Blob payload is not canonical or path-bound")
            return {
                "kind": "authority",
                "artifactId": authority.authority_id,
            }
        if blob_name.startswith("guidance-bindings/"):
            binding = PublishedGuidanceAuthorityBinding.model_validate_json(payload)
            if (
                payload != binding.canonical_bytes()
                or blob_name != f"guidance-bindings/{binding.binding_id}/binding.json"
            ):
                raise OrchestrationError(
                    "guidance binding Blob payload is not canonical or path-bound"
                )
            reference = binding.guidance_authority_reference
            return {
                "kind": "binding",
                "artifactId": binding.binding_id,
                "authorityReference": {
                    "name": reference.name,
                    "versionId": reference.version,
                    "contentSha256": reference.content_digest,
                },
            }
    except ValueError as exc:
        raise OrchestrationError(
            f"authority Blob payload does not conform to its published contract: {blob_name}"
        ) from exc
    raise OrchestrationError(
        f"authority Blob path is outside the reviewed authority/binding contract: {blob_name}"
    )


def _authority_checkpoint_sha256(value: Mapping[str, object] | None) -> str | None:
    if value is None:
        return None
    return _sha256_bytes(_canonical_json_bytes(value))


def _verify_authority_inventory_content_equal(
    *,
    expected_inventory: Mapping[str, object],
    current_inventory: Mapping[str, object],
    field: str,
) -> None:
    for field_name in (
        "containerResourceId",
        "containerExists",
        "currentBlobs",
        "versions",
    ):
        if _canonical_json_bytes(current_inventory.get(field_name)) != _canonical_json_bytes(
            expected_inventory.get(field_name)
        ):
            raise OrchestrationError(
                f"{field} live authority content does not exactly match the producer "
                "checkpoint; a prior publisher receipt and checkpoint are required"
            )


def _authority_blob_inventory(
    container_resource_id: str,
    *,
    subscription_id: str,
    previous_inventory: Mapping[str, object] | None = None,
) -> dict[str, object]:
    container_id = _azure_resource_id(
        container_resource_id,
        field="authority Blob container resource ID",
    )
    trusted_previous = _validated_authority_blob_inventory(
        previous_inventory,
        subscription_id=subscription_id,
    )
    previous_digest = _authority_checkpoint_sha256(trusted_previous)
    account_name, container_name, _, _ = _blob_container_parts(container_id)
    _verify_blob_service_versioning(
        container_id,
        subscription_id=subscription_id,
    )
    existence = _mapping(
        _run_json(
            [
                "az",
                "storage",
                "container",
                "exists",
                "--subscription",
                subscription_id,
                "--account-name",
                account_name,
                "--name",
                container_name,
                "--auth-mode",
                "login",
                "--only-show-errors",
                "--output",
                "json",
            ],
            field="authority Blob container existence",
        ),
        field="authority Blob container existence",
    )
    exists = existence.get("exists")
    if exists not in (True, False):
        raise OrchestrationError("authority Blob container existence response is invalid")
    if not exists:
        if trusted_previous is not None and trusted_previous.get("containerExists") is True:
            raise OrchestrationError(
                "authority Blob container disappeared after the reviewed checkpoint"
            )
        return {
            "schemaVersion": AUTHORITY_BLOB_INVENTORY_SCHEMA_VERSION,
            "containerResourceId": container_id,
            "containerExists": False,
            "previousCheckpointSha256": previous_digest,
            "currentBlobs": [],
            "versions": [],
        }

    common_command = [
        "az",
        "storage",
        "blob",
        "list",
        "--subscription",
        subscription_id,
        "--account-name",
        account_name,
        "--container-name",
        container_name,
        "--auth-mode",
        "login",
        "--num-results",
        "*",
        "--only-show-errors",
        "--output",
        "json",
    ]
    version_document = _run_json(
        [*common_command, "--include", "v"],
        field="versioned authority Blob inventory",
    )
    if not isinstance(version_document, list):
        raise OrchestrationError("authority Blob inventory command must return one complete array")
    live_versions = [_blob_live_version_entry(item) for item in version_document]
    live_versions.sort(
        key=lambda item: (
            str(item["name"]),
            str(item["versionId"]),
        )
    )
    if len(live_versions) > MAX_AUTHORITY_CHECKPOINT_VERSIONS:
        raise OrchestrationError("authority Blob inventory exceeds the bounded version count")
    if any(item["isCurrentVersion"] is not True for item in live_versions):
        raise OrchestrationError(
            "authority Blob inventory is not append-only; every content-addressed "
            "asset must retain one current immutable version"
        )
    live_version_keys = {(str(item["name"]), str(item["versionId"])) for item in live_versions}
    if len(live_version_keys) != len(live_versions):
        raise OrchestrationError("authority Blob version inventory contains duplicates")
    if len({str(item["name"]) for item in live_versions}) != len(live_versions):
        raise OrchestrationError(
            "authority Blob content-addressed names cannot have multiple versions"
        )
    listed_content_bytes = 0
    for live in live_versions:
        content_length = int(live["contentLength"])
        if content_length > MAX_GUIDANCE_AUTHORITY_BINDING_BYTES:
            raise OrchestrationError(
                "authority Blob content exceeds the published contract byte bound"
            )
        listed_content_bytes += content_length
        if listed_content_bytes > MAX_AUTHORITY_CHECKPOINT_CONTENT_BYTES:
            raise OrchestrationError(
                "authority Blob listed content exceeds the bounded total before download"
            )

    previous_versions = (
        {}
        if trusted_previous is None
        else {
            (str(item["name"]), str(item["versionId"])): item
            for item in trusted_previous["versions"]
        }
    )
    missing_previous = set(previous_versions) - live_version_keys
    if missing_previous:
        raise OrchestrationError(
            "authority Blob inventory removed a version from the reviewed checkpoint"
        )
    for live in live_versions:
        key = (str(live["name"]), str(live["versionId"]))
        previous = previous_versions.get(key)
        if previous is None:
            continue
        for field_name in ("name", "versionId", "etag", "contentLength"):
            if live[field_name] != previous[field_name]:
                raise OrchestrationError(
                    "authority Blob version metadata changed after checkpoint review"
                )
    checkpoint_versions: list[dict[str, object]] = []
    total_content_bytes = 0
    for live in live_versions:
        key = (str(live["name"]), str(live["versionId"]))
        previous = previous_versions.get(key)
        if previous is not None:
            checkpoint_versions.append(dict(previous))
            total_content_bytes += int(previous["contentLength"])
            continue
        content_length = int(live["contentLength"])
        payload = _download_authority_blob_version(
            container_id,
            blob_name=str(live["name"]),
            version_id=str(live["versionId"]),
            subscription_id=subscription_id,
        )
        if len(payload) != content_length:
            raise OrchestrationError(
                "authority Blob downloaded bytes do not match listed content length"
            )
        checkpoint_versions.append(
            {
                "name": live["name"],
                "versionId": live["versionId"],
                "etag": live["etag"],
                "contentLength": content_length,
                "contentSha256": _sha256_bytes(payload),
                "contract": _authority_contract_metadata(
                    blob_name=str(live["name"]),
                    payload=payload,
                ),
            }
        )
        total_content_bytes += content_length
    if total_content_bytes > MAX_AUTHORITY_CHECKPOINT_CONTENT_BYTES:
        raise OrchestrationError("authority Blob checkpoint exceeds the bounded total content size")
    checkpoint_versions.sort(
        key=lambda item: (
            str(item["name"]),
            str(item["versionId"]),
        )
    )
    checkpoint = {
        "schemaVersion": AUTHORITY_BLOB_INVENTORY_SCHEMA_VERSION,
        "containerResourceId": container_id,
        "containerExists": True,
        "previousCheckpointSha256": previous_digest,
        "currentBlobs": [
            {
                "name": item["name"],
                "versionId": item["versionId"],
                "etag": item["etag"],
                "contentLength": item["contentLength"],
                "contentSha256": item["contentSha256"],
            }
            for item in checkpoint_versions
        ],
        "versions": checkpoint_versions,
    }
    validated = _validated_authority_blob_inventory(
        checkpoint,
        subscription_id=subscription_id,
    )
    if validated is None:
        raise OrchestrationError("authority Blob checkpoint unexpectedly vanished")
    return validated


def _validated_authority_blob_inventory(
    value: object,
    *,
    subscription_id: str,
) -> dict[str, object] | None:
    if value is None:
        return None
    inventory = _mapping(value, field="authority Blob inventory")
    _require_exact_fields(
        inventory,
        frozenset(
            {
                "schemaVersion",
                "containerResourceId",
                "containerExists",
                "previousCheckpointSha256",
                "currentBlobs",
                "versions",
            }
        ),
        field="authority Blob inventory",
    )
    if inventory.get("schemaVersion") != (AUTHORITY_BLOB_INVENTORY_SCHEMA_VERSION):
        raise OrchestrationError("authority Blob inventory schema is unsupported")
    _canonical_subscription_resource_id(
        inventory.get("containerResourceId"),
        subscription_id=subscription_id,
        field="authority Blob inventory container",
    )
    if inventory.get("containerExists") not in (True, False):
        raise OrchestrationError("authority Blob inventory existence flag is invalid")
    previous_checkpoint = inventory.get("previousCheckpointSha256")
    if previous_checkpoint is not None:
        _sha256_digest(
            previous_checkpoint,
            field="authority Blob previous checkpoint SHA-256",
        )
    current_blobs = inventory.get("currentBlobs")
    versions = inventory.get("versions")
    if not isinstance(current_blobs, list) or not isinstance(versions, list):
        raise OrchestrationError(
            "authority Blob checkpoint currentBlobs and versions must be arrays"
        )
    if len(versions) > MAX_AUTHORITY_CHECKPOINT_VERSIONS:
        raise OrchestrationError("authority Blob checkpoint exceeds the bounded version count")
    for index, raw_item in enumerate(current_blobs):
        item = _mapping(
            raw_item,
            field=f"authority Blob currentBlobs[{index}]",
        )
        _require_exact_fields(
            item,
            frozenset(
                {
                    "name",
                    "versionId",
                    "etag",
                    "contentLength",
                    "contentSha256",
                }
            ),
            field=f"authority Blob currentBlobs[{index}]",
        )
        _string(item.get("name"), field="authority Blob current name")
        _string(item.get("versionId"), field="authority Blob current version")
        _string(item.get("etag"), field="authority Blob current ETag")
        _sha256_digest(
            item.get("contentSha256"),
            field="authority Blob current content SHA-256",
        )
        content_length = item.get("contentLength")
        if (
            not isinstance(content_length, int)
            or isinstance(content_length, bool)
            or content_length < 0
        ):
            raise OrchestrationError("authority Blob current content length is invalid")
    total_content_bytes = 0
    for index, raw_item in enumerate(versions):
        item = _mapping(
            raw_item,
            field=f"authority Blob versions[{index}]",
        )
        _require_exact_fields(
            item,
            frozenset(
                {
                    "name",
                    "versionId",
                    "etag",
                    "contentLength",
                    "contentSha256",
                    "contract",
                }
            ),
            field=f"authority Blob versions[{index}]",
        )
        name = _string(item.get("name"), field="authority Blob version name")
        _string(item.get("versionId"), field="authority Blob version ID")
        _string(item.get("etag"), field="authority Blob version ETag")
        _sha256_digest(
            item.get("contentSha256"),
            field="authority Blob version content SHA-256",
        )
        content_length = item.get("contentLength")
        if (
            not isinstance(content_length, int)
            or isinstance(content_length, bool)
            or content_length < 0
            or content_length > MAX_GUIDANCE_AUTHORITY_BINDING_BYTES
        ):
            raise OrchestrationError("authority Blob version content length is invalid")
        total_content_bytes += content_length
        contract = _mapping(
            item.get("contract"),
            field="authority Blob version contract",
        )
        kind = contract.get("kind")
        if kind == "authority":
            _require_exact_fields(
                contract,
                frozenset({"kind", "artifactId"}),
                field="authority Blob authority contract",
            )
            artifact_id = _string(
                contract.get("artifactId"),
                field="authority Blob authority ID",
            )
            if name != f"guidance-authority/{artifact_id}/authority.json":
                raise OrchestrationError("authority Blob authority contract is not path-bound")
        elif kind == "binding":
            _require_exact_fields(
                contract,
                frozenset({"kind", "artifactId", "authorityReference"}),
                field="authority Blob binding contract",
            )
            artifact_id = _string(
                contract.get("artifactId"),
                field="authority Blob binding ID",
            )
            if name != f"guidance-bindings/{artifact_id}/binding.json":
                raise OrchestrationError("authority Blob binding contract is not path-bound")
            reference = _mapping(
                contract.get("authorityReference"),
                field="authority Blob binding authority reference",
            )
            _require_exact_fields(
                reference,
                frozenset({"name", "versionId", "contentSha256"}),
                field="authority Blob binding authority reference",
            )
            _string(
                reference.get("name"),
                field="authority Blob binding authority name",
            )
            _string(
                reference.get("versionId"),
                field="authority Blob binding authority version",
            )
            _sha256_digest(
                reference.get("contentSha256"),
                field="authority Blob binding authority content SHA-256",
            )
        else:
            raise OrchestrationError(
                "authority Blob checkpoint contains an unsupported contract kind"
            )
    if total_content_bytes > MAX_AUTHORITY_CHECKPOINT_CONTENT_BYTES:
        raise OrchestrationError("authority Blob checkpoint exceeds the bounded total content size")
    if inventory["containerExists"] is False and (
        inventory["currentBlobs"] or inventory["versions"]
    ):
        raise OrchestrationError("absent authority Blob container cannot contain inventory")
    if current_blobs != sorted(
        current_blobs,
        key=lambda item: (
            str(item["name"]),
            str(item["versionId"]),
        ),
    ) or versions != sorted(
        versions,
        key=lambda item: (
            str(item["name"]),
            str(item["versionId"]),
        ),
    ):
        raise OrchestrationError("authority Blob inventory entries must be sorted")
    if len({str(item["name"]) for item in current_blobs}) != len(current_blobs):
        raise OrchestrationError("authority Blob current inventory contains duplicate names")
    if len(
        {
            (
                str(item["name"]),
                str(item["versionId"]),
            )
            for item in versions
        }
    ) != len(versions):
        raise OrchestrationError("authority Blob version inventory contains duplicates")
    if len({str(item["name"]) for item in versions}) != len(versions):
        raise OrchestrationError(
            "authority Blob content-addressed names cannot have multiple versions"
        )
    projected_current_blobs = [
        {
            "name": item["name"],
            "versionId": item["versionId"],
            "etag": item["etag"],
            "contentLength": item["contentLength"],
            "contentSha256": item["contentSha256"],
        }
        for item in versions
    ]
    projected_current_blobs.sort(
        key=lambda item: (
            str(item["name"]),
            str(item["versionId"]),
        )
    )
    if inventory["containerExists"] is True and current_blobs != projected_current_blobs:
        raise OrchestrationError("authority Blob current and version inventories conflict")
    version_by_reference = {(str(item["name"]), str(item["versionId"])): item for item in versions}
    referenced_authorities: set[tuple[str, str]] = set()
    authority_keys = {
        (str(item["name"]), str(item["versionId"]))
        for item in versions
        if _mapping(item["contract"], field="authority contract").get("kind") == "authority"
    }
    for item in versions:
        contract = _mapping(item["contract"], field="authority contract")
        if contract.get("kind") != "binding":
            continue
        reference = _mapping(
            contract["authorityReference"],
            field="binding authority reference",
        )
        reference_key = (
            str(reference["name"]),
            str(reference["versionId"]),
        )
        authority = version_by_reference.get(reference_key)
        if (
            authority is None
            or _mapping(
                authority["contract"],
                field="referenced authority contract",
            ).get("kind")
            != "authority"
            or authority["contentSha256"] != reference["contentSha256"]
        ):
            raise OrchestrationError(
                "authority Blob binding does not reference an exact checkpointed authority"
            )
        referenced_authorities.add(reference_key)
    if authority_keys != referenced_authorities:
        raise OrchestrationError(
            "authority Blob checkpoint contains an unpaired authority or binding"
        )
    return inventory


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
ACR_PUSH_ROLE_ID = "8311e382-0749-4cb8-b61a-304f252e45ec"
ACR_REPOSITORY_READER_ROLE_ID = "b93aa761-3e63-49ed-ac28-beffa264f7ac"
ACR_REPOSITORY_WRITER_ROLE_ID = "2a1e307c-b015-4ebd-883e-5b7698a07328"
ACR_REPOSITORY_CONTRIBUTOR_ROLE_ID = "2efddaa5-3f1f-4df3-97df-af3f13818f4c"
ACR_LEGACY_ROLE_ASSIGNMENT_MODE = "LegacyRegistryPermissions"
ACR_ABAC_ROLE_ASSIGNMENT_MODE = "AbacRepositoryPermissions"
SERVICE_BUS_DATA_RECEIVER_ROLE_ID = "4f6c0938-94ea-4d52-8e5a-2e02b7ef8e7d"
SERVICE_BUS_DATA_SENDER_ROLE_ID = "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
BLOB_DATA_READER_ROLE_ID = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
TABLE_DATA_CONTRIBUTOR_ROLE_ID = "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"
TABLE_DATA_READER_ROLE_ID = "76199698-9eea-4c19-bc75-cec21354c6b6"
KEY_VAULT_CRYPTO_USER_ROLE_ID = "12338af0-0e69-4776-bea7-57ae8d297424"
ACR_LEGACY_PULL_ACTION = "Microsoft.ContainerRegistry/registries/pull/read"
ACR_QUARANTINE_READ_ACTION = "Microsoft.ContainerRegistry/registries/quarantine/read"
ACR_REPOSITORY_CONTENT_READ_DATA_ACTION = (
    "Microsoft.ContainerRegistry/registries/repositories/content/read"
)
ACR_REPOSITORY_METADATA_READ_DATA_ACTION = (
    "Microsoft.ContainerRegistry/registries/repositories/metadata/read"
)
ACR_QUARANTINED_ARTIFACTS_READ_DATA_ACTION = (
    "Microsoft.ContainerRegistry/registries/quarantinedArtifacts/read"
)
ACR_REGISTRY_ESCALATION_ACTIONS = frozenset(
    {
        "Microsoft.ContainerRegistry/registries/write",
        "Microsoft.ContainerRegistry/registries/listCredentials/action",
        "Microsoft.ContainerRegistry/registries/generateCredentials/action",
        "Microsoft.ContainerRegistry/registries/regenerateCredential/action",
        "Microsoft.ContainerRegistry/registries/quarantine/write",
        "Microsoft.ContainerRegistry/registries/scheduleRun/action",
        "Microsoft.ContainerRegistry/registries/scopeMaps/write",
        "Microsoft.ContainerRegistry/registries/tasks/listDetails/action",
        "Microsoft.ContainerRegistry/registries/tasks/write",
        "Microsoft.ContainerRegistry/registries/taskruns/listDetails/action",
        "Microsoft.ContainerRegistry/registries/taskruns/write",
        "Microsoft.ContainerRegistry/registries/tokens/write",
        "Microsoft.ContainerRegistry/registries/updatePolicies/write",
    }
)
ACR_REGISTRY_ESCALATION_DATA_ACTIONS = frozenset(
    {
        "Microsoft.ContainerRegistry/registries/quarantinedArtifacts/write",
    }
)
AUTHORIZATION_ESCALATION_ACTIONS = frozenset(
    {
        "Microsoft.Authorization/elevateAccess/action",
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Authorization/roleAssignmentScheduleRequests/write",
        "Microsoft.Authorization/roleDefinitions/write",
        "Microsoft.Authorization/roleEligibilityScheduleRequests/write",
        "Microsoft.Authorization/roleEligibilityScheduleRequests/whenApprovalRequired/write",
        "Microsoft.Authorization/roleManagementPolicies/write",
        "Microsoft.Authorization/roleManagementPolicies/approvalRule/action",
    }
)
ACR_REPOSITORY_CONDITION_PREFIX = (
    "((!(ActionMatches{"
    f"'{ACR_REPOSITORY_CONTENT_READ_DATA_ACTION}'"
    "}) AND !(ActionMatches{"
    f"'{ACR_REPOSITORY_METADATA_READ_DATA_ACTION}'"
    "})) OR (@Request[Microsoft.ContainerRegistry/registries/repositories:name] "
    "StringEqualsIgnoreCase '"
)
ACR_REPOSITORY_CONDITION_SUFFIX = "'))"
SERVICE_BUS_RECEIVE_DATA_ACTION = "Microsoft.ServiceBus/namespaces/messages/receive/action"
SERVICE_BUS_SEND_DATA_ACTION = "Microsoft.ServiceBus/namespaces/messages/send/action"
SERVICE_BUS_ESCALATION_ACTIONS = frozenset(
    {
        "Microsoft.ServiceBus/namespaces/write",
        "Microsoft.ServiceBus/namespaces/authorizationRules/action",
        "Microsoft.ServiceBus/namespaces/authorizationRules/write",
        "Microsoft.ServiceBus/namespaces/authorizationRules/listkeys/action",
        "Microsoft.ServiceBus/namespaces/authorizationRules/regenerateKeys/action",
        "Microsoft.ServiceBus/namespaces/queues/authorizationRules/action",
        "Microsoft.ServiceBus/namespaces/queues/authorizationRules/write",
        "Microsoft.ServiceBus/namespaces/queues/authorizationRules/listkeys/action",
        "Microsoft.ServiceBus/namespaces/queues/authorizationRules/regenerateKeys/action",
    }
)
BLOB_READ_DATA_ACTION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
BLOB_WRITE_DATA_ACTION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
BLOB_ADD_DATA_ACTION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"
TABLE_ENTITY_READ_DATA_ACTION = (
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"
)
TABLE_ENTITY_ADD_DATA_ACTION = (
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action"
)
TABLE_ENTITY_UPDATE_DATA_ACTION = (
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action"
)
KEY_READ_DATA_ACTION = "Microsoft.KeyVault/vaults/keys/read"
KEY_VERIFY_DATA_ACTION = "Microsoft.KeyVault/vaults/keys/verify/action"
KEY_SIGN_DATA_ACTION = "Microsoft.KeyVault/vaults/keys/sign/action"
ALL_PRINCIPALS_ID = "00000000-0000-0000-0000-000000000000"
ROLE_ASSIGNMENTS_API_VERSION = "2022-04-01"
PIM_SCHEDULE_INSTANCES_API_VERSION = "2020-10-01"
AUTHORIZATION_RESOURCE_API_VERSIONS = {
    "roleAssignments": ROLE_ASSIGNMENTS_API_VERSION,
    "roleAssignmentScheduleInstances": PIM_SCHEDULE_INSTANCES_API_VERSION,
    "roleEligibilityScheduleInstances": PIM_SCHEDULE_INSTANCES_API_VERSION,
}
AUTHORIZATION_SCHEDULE_STATUSES = frozenset(
    {
        "accepted",
        "pendingevaluation",
        "granted",
        "denied",
        "pendingprovisioning",
        "provisioned",
        "pendingrevocation",
        "revoked",
        "canceled",
        "failed",
        "pendingapprovalprovisioning",
        "pendingapproval",
        "failedasresourceislocked",
        "pendingadmindecision",
        "adminapproved",
        "admindenied",
        "timedout",
        "provisioningstarted",
        "invalid",
        "pendingschedulecreation",
        "schedulecreated",
        "pendingexternalprovisioning",
    }
)
INACTIVE_AUTHORIZATION_SCHEDULE_STATUSES = frozenset(
    {
        "denied",
        "revoked",
        "canceled",
        "failed",
        "failedasresourceislocked",
        "admindenied",
        "timedout",
        "invalid",
    }
)
DENY_ASSIGNMENTS_API_VERSION = "2022-04-01"
BUILT_IN_DATA_ROLE_IDS = frozenset(
    {
        ACR_PULL_ROLE_ID,
        ACR_REPOSITORY_READER_ROLE_ID,
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
FEED_BLOB_WRITER_PERMISSION_PROFILE = _RolePermissionProfile(
    data_actions=frozenset({BLOB_READ_DATA_ACTION, BLOB_WRITE_DATA_ACTION})
)
IMMUTABLE_BLOB_CREATOR_PERMISSION_PROFILE = _RolePermissionProfile(
    data_actions=frozenset({BLOB_ADD_DATA_ACTION})
)
TABLE_CAS_PERMISSION_PROFILE = _RolePermissionProfile(
    data_actions=frozenset(
        {
            TABLE_ENTITY_READ_DATA_ACTION,
            TABLE_ENTITY_ADD_DATA_ACTION,
            TABLE_ENTITY_UPDATE_DATA_ACTION,
        }
    )
)
KEY_VERIFY_PERMISSION_PROFILE = _RolePermissionProfile(
    data_actions=frozenset({KEY_READ_DATA_ACTION, KEY_VERIFY_DATA_ACTION})
)
KEY_SIGN_PERMISSION_PROFILE = _RolePermissionProfile(data_actions=frozenset({KEY_SIGN_DATA_ACTION}))
KEY_SIGN_VERIFY_PERMISSION_PROFILE = _RolePermissionProfile(
    data_actions=frozenset({KEY_SIGN_DATA_ACTION, KEY_VERIFY_DATA_ACTION})
)
BUILT_IN_REQUIRED_PERMISSION_PROFILES = {
    ACR_PULL_ROLE_ID: _RolePermissionProfile(actions=frozenset({ACR_LEGACY_PULL_ACTION})),
    ACR_REPOSITORY_READER_ROLE_ID: _RolePermissionProfile(
        data_actions=frozenset(
            {
                ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
                ACR_REPOSITORY_METADATA_READ_DATA_ACTION,
            }
        )
    ),
    SERVICE_BUS_DATA_RECEIVER_ROLE_ID: _RolePermissionProfile(
        data_actions=frozenset({SERVICE_BUS_RECEIVE_DATA_ACTION})
    ),
    SERVICE_BUS_DATA_SENDER_ROLE_ID: _RolePermissionProfile(
        data_actions=frozenset({SERVICE_BUS_SEND_DATA_ACTION})
    ),
    BLOB_DATA_READER_ROLE_ID: _RolePermissionProfile(
        data_actions=frozenset({BLOB_READ_DATA_ACTION})
    ),
    TABLE_DATA_CONTRIBUTOR_ROLE_ID: TABLE_CAS_PERMISSION_PROFILE,
    TABLE_DATA_READER_ROLE_ID: _RolePermissionProfile(
        data_actions=frozenset({TABLE_ENTITY_READ_DATA_ACTION})
    ),
    KEY_VAULT_CRYPTO_USER_ROLE_ID: KEY_SIGN_VERIFY_PERMISSION_PROFILE,
}
APPROVED_CUSTOM_ROLE_PERMISSION_PROFILES = frozenset(
    {
        FEED_BLOB_WRITER_PERMISSION_PROFILE,
        IMMUTABLE_BLOB_CREATOR_PERMISSION_PROFILE,
        TABLE_CAS_PERMISSION_PROFILE,
        KEY_VERIFY_PERMISSION_PROFILE,
        KEY_SIGN_PERMISSION_PROFILE,
        KEY_SIGN_VERIFY_PERMISSION_PROFILE,
    }
)
ALLOWED_BUILT_IN_ROLES_BY_SCOPE_TYPE = {
    "microsoft.containerregistry/registries": frozenset(
        {
            ACR_PULL_ROLE_ID,
            ACR_REPOSITORY_READER_ROLE_ID,
        }
    ),
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
ALLOWED_CUSTOM_PERMISSION_PROFILES_BY_SCOPE_TYPE = {
    "microsoft.storage/storageaccounts/blobservices/containers": frozenset(
        {
            FEED_BLOB_WRITER_PERMISSION_PROFILE,
            IMMUTABLE_BLOB_CREATOR_PERMISSION_PROFILE,
        }
    ),
    "microsoft.storage/storageaccounts/tableservices/tables": frozenset(
        {TABLE_CAS_PERMISSION_PROFILE}
    ),
    "microsoft.keyvault/vaults/keys": frozenset(
        {
            KEY_VERIFY_PERMISSION_PROFILE,
            KEY_SIGN_PERMISSION_PROFILE,
            KEY_SIGN_VERIFY_PERMISSION_PROFILE,
        }
    ),
}


def _identity_bindings(value: object) -> dict[str, tuple[str, str]]:
    bindings: dict[str, tuple[str, str]] = {}

    def visit(item: object) -> None:
        if isinstance(item, dict):
            for key, resource_id in item.items():
                if not key.casefold().endswith("identityresourceid"):
                    continue
                client_key = f"{key.removesuffix('ResourceId')}ClientId"
                original_resource_id = _azure_resource_id(
                    resource_id,
                    field="configured identity resource ID",
                )
                normalized_resource_id = original_resource_id.casefold()
                configured_client_id = _string(
                    item.get(client_key),
                    field="configured identity client ID",
                )
                existing = bindings.get(normalized_resource_id)
                if (
                    existing is not None
                    and existing[1].casefold() != configured_client_id.casefold()
                ):
                    raise OrchestrationError(
                        "one identity resource ID has conflicting configured client IDs"
                    )
                bindings[normalized_resource_id] = (
                    original_resource_id,
                    configured_client_id,
                )
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
        normalized_resource_id: original_and_client_id[0]
        for normalized_resource_id, original_and_client_id in bindings.items()
    }
    for resource_id in additional_identity_resource_ids:
        original_resource_id = _azure_resource_id(
            resource_id,
            field="additional identity resource ID",
        )
        identity_resource_ids.setdefault(
            original_resource_id.casefold(),
            original_resource_id,
        )
    rbac_identity_ids = {
        _azure_resource_id(
            item,
            field="RBAC identity resource ID",
        ).casefold()
        for item in rbac_identity_resource_ids
    }
    principal_ids: dict[str, str] = {}
    for normalized_resource_id, original_resource_id in identity_resource_ids.items():
        identity = _get_resource(
            original_resource_id,
            subscription_id=subscription_id,
        )
        _require_resource_id_equal(
            identity.get("id"),
            original_resource_id,
            field="managed identity readback",
        )
        properties = _mapping(identity.get("properties"), field="identity properties")
        configured_binding = bindings.get(normalized_resource_id)
        if configured_binding is not None:
            _require_equal(
                str(properties.get("clientId", "")).casefold(),
                configured_binding[1].casefold(),
                field="managed identity client ID",
            )
        principal_id = _string(
            properties.get("principalId"),
            field="managed identity principal ID",
        ).casefold()
        if normalized_resource_id in rbac_identity_ids:
            principal_ids[normalized_resource_id] = principal_id
    return principal_ids


def _arm_guid(*values: str) -> str:
    if not values or any(not value for value in values):
        raise OrchestrationError("ARM guid inputs must be non-empty strings")
    return str(uuid5(ARM_GUID_NAMESPACE, "-".join(values)))


def _deterministic_role_assignment_id(
    scope: str,
    identity_resource_id: str,
    role_id: str,
) -> str:
    assignment_name = _arm_guid(
        scope,
        identity_resource_id,
        role_id,
    )
    return f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_name}"


def _deterministic_principal_role_assignment_id(
    scope: str,
    principal_id: str,
    role_definition_id: str,
) -> str:
    assignment_name = _arm_guid(
        scope,
        _canonical_directory_object_id(
            principal_id,
            field="role assignment principal ID",
        ),
        role_definition_id,
    )
    return f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_name}"


def _acr_pull_role_assignment_id(
    *,
    scope: str,
    principal_id: str,
    role_definition_id: str,
    role_assignment_mode: str,
    repository_name: str,
) -> str:
    canonical_principal_id = _canonical_directory_object_id(
        principal_id,
        field="ACR role assignment principal ID",
    )
    assignment_name = _arm_guid(
        scope,
        canonical_principal_id,
        role_definition_id,
        *((repository_name,) if role_assignment_mode == ACR_ABAC_ROLE_ASSIGNMENT_MODE else ()),
    )
    return f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_name}"


def _acr_role_assignment_mode(value: object, *, field: str) -> str:
    mode = _string(value, field=field)
    if mode not in {
        ACR_LEGACY_ROLE_ASSIGNMENT_MODE,
        ACR_ABAC_ROLE_ASSIGNMENT_MODE,
    }:
        raise OrchestrationError(
            f"{field} must be {ACR_LEGACY_ROLE_ASSIGNMENT_MODE} or {ACR_ABAC_ROLE_ASSIGNMENT_MODE}"
        )
    return mode


def _require_anonymous_pull_disabled(
    properties: Mapping[str, object],
    *,
    field: str,
) -> None:
    if properties.get("anonymousPullEnabled") is not False:
        raise OrchestrationError(f"{field} anonymousPullEnabled must be explicitly false")


def _acr_pull_role_definition_id(
    *,
    role_assignment_mode: str,
    subscription_id: str,
) -> str:
    role_id = (
        ACR_PULL_ROLE_ID
        if role_assignment_mode == ACR_LEGACY_ROLE_ASSIGNMENT_MODE
        else ACR_REPOSITORY_READER_ROLE_ID
    )
    return _built_in_role_definition_id(subscription_id, role_id)


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
    custom_role_permissions: _RolePermissionProfile | None = None,
    repository_name: str | None = None,
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
        custom_role_permissions=custom_role_permissions,
        repository_name=repository_name,
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
    if len(role_definition_ids) != 12:
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
        outputs.get("registryResourceId"),
        field="producer registry resource ID output",
    )
    _require_resource_id_equal(
        registry_id,
        _parameter_value(effective_parameters, "registryResourceId"),
        field="producer registry resource ID",
    )
    registry_role_assignment_mode = _acr_role_assignment_mode(
        outputs.get("registryRoleAssignmentMode"),
        field="producer registry role-assignment mode",
    )
    registry_pull_role_definition_id = _acr_pull_role_definition_id(
        role_assignment_mode=registry_role_assignment_mode,
        subscription_id=subscription_id,
    )
    _require_subscription_resource_id_equal(
        outputs.get("registryPullRoleDefinitionId"),
        registry_pull_role_definition_id,
        subscription_id=subscription_id,
        field="producer registry pull role definition",
    )
    registry_repository_name = _acr_repository_name(
        outputs.get("producerImage"),
        registry_id,
        field="producer image",
    )
    registry_condition_version, registry_condition = _acr_pull_assignment_condition(
        role_assignment_mode=registry_role_assignment_mode,
        repository_name=registry_repository_name,
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
        "acr_pull": registry_pull_role_definition_id,
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
            condition_version=registry_condition_version,
            condition=registry_condition,
            repository_name=registry_repository_name,
        ),
        _expected_role_assignment(
            "producer feed-v2 writer",
            identity_resource_id=feed_writer_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=feed_container_id,
            role_definition_id=role_definition_ids[0],
            custom_role_permissions=FEED_BLOB_WRITER_PERMISSION_PROFILE,
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
            custom_role_permissions=KEY_VERIFY_PERMISSION_PROFILE,
        ),
        _expected_role_assignment(
            "producer correlation-binding key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=correlation_binding_key_id,
            role_definition_id=role_definition_ids[2],
            custom_role_permissions=KEY_VERIFY_PERMISSION_PROFILE,
        ),
        _expected_role_assignment(
            "producer guidance-binding key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=guidance_binding_key_id,
            role_definition_id=role_definition_ids[3],
            custom_role_permissions=KEY_VERIFY_PERMISSION_PROFILE,
        ),
        _expected_role_assignment(
            "producer change key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=change_key_id,
            role_definition_id=role_definition_ids[4],
            custom_role_permissions=KEY_VERIFY_PERMISSION_PROFILE,
        ),
        _expected_role_assignment(
            "producer monitoring-intent key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=monitoring_intent_key_id,
            role_definition_id=role_definition_ids[5],
            custom_role_permissions=KEY_VERIFY_PERMISSION_PROFILE,
        ),
        _expected_role_assignment(
            "producer monitoring-collector key verifier",
            identity_resource_id=trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=monitoring_collector_key_id,
            role_definition_id=role_definition_ids[6],
            custom_role_permissions=KEY_VERIFY_PERMISSION_PROFILE,
        ),
    ]
    for role_index, (name, scope) in enumerate(
        (
            ("report", report_key_id),
            ("guidance", guidance_key_id),
            ("enrichment", enrichment_key_id),
            ("feed", feed_key_id),
            ("notification", notification_key_id),
        ),
        start=7,
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
                role_definition_id=role_definition_ids[role_index],
                custom_role_permissions=KEY_SIGN_VERIFY_PERMISSION_PROFILE,
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


def _prospective_publisher_sender_assignment(
    *,
    configuration: Mapping[str, object],
    outputs: Mapping[str, object],
    principal_ids_by_identity: Mapping[str, str],
    subscription_id: str,
) -> dict[str, _ExpectedRoleAssignment]:
    service_bus = _mapping(
        configuration.get("serviceBus"),
        field="producer service bus",
    )
    broker_identity_id = _azure_resource_id(
        service_bus.get("brokerIdentityResourceId"),
        field="producer broker identity",
    )
    trigger_queue_id = _azure_resource_id(
        outputs.get("triggerQueueResourceId"),
        field="producer trigger queue resource ID",
    )
    assignment_id = _deterministic_role_assignment_id(
        trigger_queue_id,
        broker_identity_id,
        SERVICE_BUS_DATA_SENDER_ROLE_ID,
    )
    return {
        assignment_id.casefold(): _expected_role_assignment(
            "prospective publisher producer-trigger sender",
            identity_resource_id=broker_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=trigger_queue_id,
            role_definition_id=_built_in_role_definition_id(
                subscription_id,
                SERVICE_BUS_DATA_SENDER_ROLE_ID,
            ),
        )
    }


def _producer_legacy_crypto_user_assignments(
    *,
    configuration: Mapping[str, object],
    foundation_values: Mapping[str, object],
    principal_ids_by_identity: Mapping[str, str],
    subscription_id: str,
) -> dict[str, _ExpectedRoleAssignment]:
    keys = _mapping(configuration.get("keys"), field="producer keys")
    key_vault_id = _azure_resource_id(
        foundation_values.get("keyVaultResourceId"),
        field="producer foundation Key Vault resource ID",
    )
    role_definition_id = _built_in_role_definition_id(
        subscription_id,
        KEY_VAULT_CRYPTO_USER_ROLE_ID,
    )
    expected: dict[str, _ExpectedRoleAssignment] = {}
    for name in (
        "report",
        "guidance",
        "enrichment",
        "feed",
        "notification",
    ):
        key = _mapping(keys.get(name), field=f"producer key {name}")
        identity_resource_id = _configured_identity_resource_id(
            key,
            field=f"producer key {name}",
        )
        scope = (
            f"{key_vault_id}/keys/"
            f"{_key_name(_string(key.get('keyVaultKeyId'), field=f'producer key {name} URI'))}"
        )
        assignment_id = _deterministic_role_assignment_id(
            scope,
            identity_resource_id,
            KEY_VAULT_CRYPTO_USER_ROLE_ID,
        )
        expected[assignment_id.casefold()] = _expected_role_assignment(
            f"legacy producer {name} Crypto User migration",
            identity_resource_id=identity_resource_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=scope,
            role_definition_id=role_definition_id,
        )
    return expected


def _planned_trigger_queue_assignments(
    *,
    effective_parameters: Mapping[str, Mapping[str, object]],
    resource_group: str,
    subscription_id: str,
) -> dict[str, _ExpectedRoleAssignment]:
    namespace_name = _string(
        _parameter_value(effective_parameters, "serviceBusNamespaceName"),
        field="planned producer Service Bus namespace",
    )
    trigger_queue_scope = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/"
        "providers/Microsoft.ServiceBus/namespaces/"
        f"{namespace_name}/queues/{PRODUCER_TRIGGER_QUEUE_NAME}"
    )
    broker_identity_id = _azure_resource_id(
        _parameter_value(effective_parameters, "brokerIdentityResourceId"),
        field="planned producer broker identity",
    )
    submitter_identity_ids = _string_list(
        _parameter_value(
            effective_parameters,
            "triggerSubmitterIdentityResourceIds",
        ),
        field="planned producer trigger submitter identities",
    )
    identity_ids = list(
        {
            broker_identity_id.casefold(): broker_identity_id,
            **{
                identity_resource_id.casefold(): identity_resource_id
                for identity_resource_id in submitter_identity_ids
            },
        }.values()
    )
    principal_ids_by_identity = _verify_identities(
        {},
        additional_identity_resource_ids=identity_ids,
        rbac_identity_resource_ids=identity_ids,
        subscription_id=subscription_id,
    )
    receiver_role_definition_id = _built_in_role_definition_id(
        subscription_id,
        SERVICE_BUS_DATA_RECEIVER_ROLE_ID,
    )
    sender_role_definition_id = _built_in_role_definition_id(
        subscription_id,
        SERVICE_BUS_DATA_SENDER_ROLE_ID,
    )
    expected: dict[str, _ExpectedRoleAssignment] = {}

    def add_assignment(
        label: str,
        *,
        identity_resource_id: str,
        role_id: str,
        role_definition_id: str,
    ) -> None:
        assignment_id = _deterministic_role_assignment_id(
            trigger_queue_scope,
            identity_resource_id,
            role_id,
        )
        expected[assignment_id.casefold()] = _expected_role_assignment(
            label,
            identity_resource_id=identity_resource_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=trigger_queue_scope,
            role_definition_id=role_definition_id,
        )

    add_assignment(
        "planned producer trigger receiver",
        identity_resource_id=broker_identity_id,
        role_id=SERVICE_BUS_DATA_RECEIVER_ROLE_ID,
        role_definition_id=receiver_role_definition_id,
    )
    add_assignment(
        "planned prospective publisher trigger sender",
        identity_resource_id=broker_identity_id,
        role_id=SERVICE_BUS_DATA_SENDER_ROLE_ID,
        role_definition_id=sender_role_definition_id,
    )
    for index, identity_resource_id in enumerate(submitter_identity_ids):
        add_assignment(
            f"planned producer trigger submitter {index}",
            identity_resource_id=identity_resource_id,
            role_id=SERVICE_BUS_DATA_SENDER_ROLE_ID,
            role_definition_id=sender_role_definition_id,
        )
    return expected


def _planned_legacy_crypto_user_assignments(
    *,
    effective_parameters: Mapping[str, Mapping[str, object]],
    resource_group: str,
    subscription_id: str,
) -> dict[str, _ExpectedRoleAssignment]:
    key_vault_name = _string(
        _parameter_value(effective_parameters, "keyVaultName"),
        field="planned producer Key Vault name",
    )
    signer_bindings = (
        ("report", "reportSigningKeyName", "reportSignerIdentityResourceId"),
        (
            "guidance",
            "guidanceSigningKeyName",
            "guidanceSignerIdentityResourceId",
        ),
        (
            "enrichment",
            "enrichmentSigningKeyName",
            "enrichmentSignerIdentityResourceId",
        ),
        ("feed", "feedSigningKeyName", "feedSignerIdentityResourceId"),
        (
            "notification",
            "notificationSigningKeyName",
            "notificationSignerIdentityResourceId",
        ),
    )
    identity_resource_ids = [
        _azure_resource_id(
            _parameter_value(effective_parameters, identity_parameter),
            field=f"planned producer {name} signer identity",
        )
        for name, _key_parameter, identity_parameter in signer_bindings
    ]
    principal_ids_by_identity = _verify_identities(
        {},
        additional_identity_resource_ids=identity_resource_ids,
        rbac_identity_resource_ids=identity_resource_ids,
        subscription_id=subscription_id,
    )
    role_definition_id = _built_in_role_definition_id(
        subscription_id,
        KEY_VAULT_CRYPTO_USER_ROLE_ID,
    )
    expected: dict[str, _ExpectedRoleAssignment] = {}
    for (
        name,
        key_parameter,
        identity_parameter,
    ), identity_resource_id in zip(
        signer_bindings,
        identity_resource_ids,
        strict=True,
    ):
        key_name = _string(
            _parameter_value(effective_parameters, key_parameter),
            field=f"planned producer {name} signing key",
        )
        scope = (
            f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/"
            f"providers/Microsoft.KeyVault/vaults/{key_vault_name}/keys/{key_name}"
        )
        assignment_id = _deterministic_role_assignment_id(
            scope,
            identity_resource_id,
            KEY_VAULT_CRYPTO_USER_ROLE_ID,
        )
        expected[assignment_id.casefold()] = _expected_role_assignment(
            f"legacy producer {name} Crypto User migration",
            identity_resource_id=_azure_resource_id(
                _parameter_value(effective_parameters, identity_parameter),
                field=f"planned producer {name} signer identity",
            ),
            principal_ids_by_identity=principal_ids_by_identity,
            scope=scope,
            role_definition_id=role_definition_id,
        )
    return expected


def _verify_planned_trigger_queue_transition_state(
    *,
    effective_parameters: Mapping[str, Mapping[str, object]],
    resource_group: str,
    approved_transitions: object,
    transition_state: str,
    subscription_id: str,
) -> None:
    _verify_complete_trigger_queue_assignment_set(
        current_expected_assignments=_planned_trigger_queue_assignments(
            effective_parameters=effective_parameters,
            resource_group=resource_group,
            subscription_id=subscription_id,
        ),
        required_current_assignment_ids=set(),
        approved_transitions=approved_transitions,
        transition_state=transition_state,
        subscription_id=subscription_id,
    )


def _current_principal_ids_from_effective_parameters(
    parameters: Mapping[str, Mapping[str, object]],
    *,
    subscription_id: str,
) -> set[str]:
    identity_resource_ids: dict[str, str] = {}
    for name, entry in parameters.items():
        normalized_name = name.casefold()
        value = entry.get("value")
        if normalized_name.endswith("identityresourceid") and isinstance(value, str):
            resource_id = _azure_resource_id(
                value,
                field=f"parameters.{name}",
            )
            identity_resource_ids[resource_id.casefold()] = resource_id
        elif normalized_name.endswith("identityresourceids"):
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise OrchestrationError(f"parameters.{name} must be an identity resource ID array")
            for index, item in enumerate(value):
                resource_id = _azure_resource_id(
                    item,
                    field=f"parameters.{name}[{index}]",
                )
                identity_resource_ids[resource_id.casefold()] = resource_id
    if not identity_resource_ids:
        raise OrchestrationError("rotation verification found no current identity resource IDs")
    principals_by_identity = _verify_identities(
        {},
        additional_identity_resource_ids=list(identity_resource_ids.values()),
        rbac_identity_resource_ids=list(identity_resource_ids.values()),
        subscription_id=subscription_id,
    )
    return set(principals_by_identity.values())


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
        outputs.get("registryResourceId"),
        field="publisher registry resource ID output",
    )
    _require_resource_id_equal(
        registry_id,
        _parameter_value(effective_parameters, "registryResourceId"),
        field="publisher registry resource ID",
    )
    registry_role_assignment_mode = _acr_role_assignment_mode(
        outputs.get("registryRoleAssignmentMode"),
        field="publisher registry role-assignment mode",
    )
    registry_pull_role_definition_id = _acr_pull_role_definition_id(
        role_assignment_mode=registry_role_assignment_mode,
        subscription_id=subscription_id,
    )
    _require_subscription_resource_id_equal(
        outputs.get("registryPullRoleDefinitionId"),
        registry_pull_role_definition_id,
        subscription_id=subscription_id,
        field="publisher registry pull role definition",
    )
    registry_repository_name = _acr_repository_name(
        outputs.get("publisherImage"),
        registry_id,
        field="publisher image",
    )
    registry_condition_version, registry_condition = _acr_pull_assignment_condition(
        role_assignment_mode=registry_role_assignment_mode,
        repository_name=registry_repository_name,
    )

    blob_condition = {
        "condition_version": "2.0",
        "condition": BLOB_LIST_DENY_CONDITION,
    }
    built_in_roles = {
        "acr_pull": registry_pull_role_definition_id,
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
            custom_role_permissions=IMMUTABLE_BLOB_CREATOR_PERMISSION_PROFILE,
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
            custom_role_permissions=TABLE_CAS_PERMISSION_PROFILE,
        ),
        _expected_role_assignment(
            "publisher request key verifier",
            identity_resource_id=request_trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=request_key_id,
            role_definition_id=role_definition_ids[2],
            custom_role_permissions=KEY_VERIFY_PERMISSION_PROFILE,
        ),
        _expected_role_assignment(
            "publisher binding key verifier",
            identity_resource_id=binding_trust_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=binding_key_id,
            role_definition_id=role_definition_ids[3],
            custom_role_permissions=KEY_VERIFY_PERMISSION_PROFILE,
        ),
        _expected_role_assignment(
            "publisher binding signer",
            identity_resource_id=binding_signer_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=binding_key_id,
            role_definition_id=role_definition_ids[4],
            custom_role_permissions=KEY_SIGN_PERMISSION_PROFILE,
        ),
        _expected_role_assignment(
            "publisher registry pull",
            identity_resource_id=broker_identity_id,
            principal_ids_by_identity=principal_ids_by_identity,
            scope=registry_id,
            role_definition_id=built_in_roles["acr_pull"],
            condition_version=registry_condition_version,
            condition=registry_condition,
            repository_name=registry_repository_name,
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


def _role_permission_profiles(
    resource: Mapping[str, object],
    *,
    field: str,
) -> tuple[_RolePermissionProfile, ...]:
    properties = _mapping(resource.get("properties"), field=f"{field} properties")
    permissions = properties.get("permissions")
    if not isinstance(permissions, list) or not 1 <= len(permissions) <= 64:
        raise OrchestrationError(f"{field} must contain a bounded non-empty permissions array")

    profiles: list[_RolePermissionProfile] = []
    for index, raw_permission in enumerate(permissions):
        permission = _mapping(
            raw_permission,
            field=f"{field} permission {index}",
        )

        def permission_set(
            json_field: str,
            *,
            current_permission: Mapping[str, object] = permission,
            permission_index: int = index,
        ) -> frozenset[str]:
            values = current_permission.get(json_field)
            if not isinstance(values, list) or any(
                not isinstance(item, str) or not item or item != item.strip() or len(item) > 512
                for item in values
            ):
                raise OrchestrationError(
                    f"{field} permission {permission_index} {json_field} "
                    "must be a bounded string array"
                )
            normalized = [item.casefold() for item in values]
            if len(set(normalized)) != len(normalized):
                raise OrchestrationError(
                    f"{field} permission {permission_index} {json_field} "
                    "must contain distinct values"
                )
            return frozenset(values)

        profiles.append(
            _RolePermissionProfile(
                actions=permission_set("actions"),
                not_actions=permission_set("notActions"),
                data_actions=permission_set("dataActions"),
                not_data_actions=permission_set("notDataActions"),
            )
        )
    return tuple(profiles)


def _verify_custom_role(resource: Mapping[str, object]) -> _RolePermissionProfile:
    profiles = _role_permission_profiles(
        resource,
        field="custom role",
    )
    if len(profiles) != 1 or profiles[0] not in APPROVED_CUSTOM_ROLE_PERMISSION_PROFILES:
        raise OrchestrationError("custom data role permissions do not match an approved profile")
    return profiles[0]


def _azure_permission_pattern_matches(pattern: str, action: str) -> bool:
    normalized_pattern = pattern.casefold()
    normalized_action = action.casefold()
    expression = re.escape(normalized_pattern).replace(r"\*", ".*")
    return re.fullmatch(expression, normalized_action) is not None


def _permission_profile_grants_action(
    profile: _RolePermissionProfile,
    action: str,
    *,
    is_data_action: bool,
) -> bool:
    granted = profile.data_actions if is_data_action else profile.actions
    excluded = profile.not_data_actions if is_data_action else profile.not_actions
    return any(
        _azure_permission_pattern_matches(pattern, action) for pattern in granted
    ) and not any(_azure_permission_pattern_matches(pattern, action) for pattern in excluded)


def _permission_profiles_grant_any_action(
    profiles: Sequence[_RolePermissionProfile],
    actions: frozenset[str],
    *,
    is_data_action: bool,
) -> bool:
    return any(
        _permission_profile_grants_action(
            profile,
            action,
            is_data_action=is_data_action,
        )
        for profile in profiles
        for action in actions
    )


def _role_definition_grants_authorization_escalation(
    profiles: Sequence[_RolePermissionProfile],
) -> bool:
    return _permission_profiles_grant_any_action(
        profiles,
        AUTHORIZATION_ESCALATION_ACTIONS,
        is_data_action=False,
    )


def _scope_can_govern_acr(scope: str) -> bool:
    normalized = scope.rstrip("/").casefold() or "/"
    if normalized == "/" or normalized.startswith(
        "/providers/microsoft.management/managementgroups/"
    ):
        return True
    segments = [segment for segment in normalized.split("/") if segment]
    if (
        len(segments) == 2
        and segments[0] == "subscriptions"
        or len(segments) == 4
        and segments[0] == "subscriptions"
        and segments[2] == "resourcegroups"
    ):
        return True
    try:
        resource_type = _resource_type(scope)
    except OrchestrationError:
        return False
    return resource_type == "microsoft.containerregistry/registries" or resource_type.startswith(
        "microsoft.containerregistry/registries/"
    )


def _role_definition_grants_trigger_queue_access(
    resource: Mapping[str, object],
) -> bool:
    profiles = _role_permission_profiles(
        resource,
        field="effective trigger-queue role definition",
    )
    return (
        _permission_profiles_grant_any_action(
            profiles,
            frozenset(
                {
                    SERVICE_BUS_RECEIVE_DATA_ACTION,
                    SERVICE_BUS_SEND_DATA_ACTION,
                }
            ),
            is_data_action=True,
        )
        or _permission_profiles_grant_any_action(
            profiles,
            SERVICE_BUS_ESCALATION_ACTIONS,
            is_data_action=False,
        )
        or _role_definition_grants_authorization_escalation(profiles)
    )


def _get_role_definition(
    role_definition_id: str,
    *,
    subscription_id: str,
) -> dict[str, Any]:
    normalized = role_definition_id.casefold()
    marker = "/providers/microsoft.authorization/roledefinitions/"
    if (
        marker not in normalized
        or role_definition_id != role_definition_id.strip()
        or role_definition_id.endswith("/")
        or urlparse(role_definition_id).query
        or urlparse(role_definition_id).fragment
    ):
        raise OrchestrationError("effective authorization role definition ID is not canonical")
    try:
        role_definition_guid = str(UUID(role_definition_id.rsplit("/", 1)[-1]))
    except ValueError as exc:
        raise OrchestrationError(
            "effective authorization role definition ID must end in one canonical UUID"
        ) from exc
    if role_definition_id.rsplit("/", 1)[-1] != role_definition_guid:
        raise OrchestrationError(
            "effective authorization role definition ID must use canonical lowercase UUID form"
        )
    if normalized.startswith("/subscriptions/"):
        canonical_id = _canonical_subscription_resource_id(
            role_definition_id,
            subscription_id=subscription_id,
            field="effective authorization role definition ID",
        )
    elif normalized.startswith("/providers/microsoft.management/managementgroups/"):
        segments = role_definition_id.split("/")
        if (
            len(segments) != 9
            or segments[0] != ""
            or segments[1] != "providers"
            or segments[2].casefold() != "microsoft.management"
            or segments[3].casefold() != "managementgroups"
            or segments[5] != "providers"
            or segments[6].casefold() != "microsoft.authorization"
            or segments[7].casefold() != "roledefinitions"
        ):
            raise OrchestrationError(
                "effective authorization management-group role definition ID is not canonical"
            )
        _validate_resource_id_segment(
            segments[4],
            field="effective authorization role definition management group",
        )
        canonical_id = role_definition_id
    elif normalized.startswith("/providers/microsoft.authorization/roledefinitions/"):
        segments = role_definition_id.split("/")
        if (
            len(segments) != 5
            or segments[0] != ""
            or segments[1] != "providers"
            or segments[2].casefold() != "microsoft.authorization"
            or segments[3].casefold() != "roledefinitions"
        ):
            raise OrchestrationError(
                "effective authorization tenant role definition ID is not canonical"
            )
        canonical_id = role_definition_id
    else:
        raise OrchestrationError(
            "effective authorization role definition is outside the governed subscription hierarchy"
        )
    role = _mapping(
        _run_json(
            [
                "az",
                "rest",
                "--method",
                "get",
                "--url",
                (f"https://{ARM_HOST}{canonical_id}?api-version={DENY_ASSIGNMENTS_API_VERSION}"),
                "--only-show-errors",
                "--output",
                "json",
            ],
            field="effective authorization role definition",
        ),
        field="effective authorization role definition",
    )
    if str(role.get("id", "")).casefold() != normalized:
        raise OrchestrationError(
            "effective authorization role definition readback does not match its assignment"
        )
    return role


def _role_definition_grants_acr_pull(
    resource: Mapping[str, object],
    *,
    assignment_scope: str,
) -> bool:
    if not _scope_can_govern_acr(assignment_scope):
        return False
    profiles = _role_permission_profiles(
        resource,
        field="effective ACR role definition",
    )
    return (
        _permission_profiles_grant_any_action(
            profiles,
            frozenset(
                {
                    ACR_LEGACY_PULL_ACTION,
                    ACR_QUARANTINE_READ_ACTION,
                }
            ),
            is_data_action=False,
        )
        or _permission_profiles_grant_any_action(
            profiles,
            frozenset(
                {
                    ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
                    ACR_QUARANTINED_ARTIFACTS_READ_DATA_ACTION,
                }
            ),
            is_data_action=True,
        )
        or _permission_profiles_grant_any_action(
            profiles,
            ACR_REGISTRY_ESCALATION_ACTIONS,
            is_data_action=False,
        )
        or _permission_profiles_grant_any_action(
            profiles,
            ACR_REGISTRY_ESCALATION_DATA_ACTIONS,
            is_data_action=True,
        )
        or _role_definition_grants_authorization_escalation(profiles)
    )


def _acr_assignment_ids_by_principal(
    assignment_ids_by_principal: Mapping[str, set[str]],
) -> dict[str, set[str]]:
    return {
        principal_id.casefold(): {
            assignment_id.casefold()
            for assignment_id in assignment_ids
            if _resource_type(_role_assignment_scope(assignment_id))
            == "microsoft.containerregistry/registries"
        }
        for principal_id, assignment_ids in assignment_ids_by_principal.items()
    }


def _verify_exact_pull_capable_assignments(
    principal_ids: set[str],
    *,
    expected_acr_assignments_by_principal: Mapping[str, set[str]],
    subscription_id: str,
    field: str,
    effective_assignments_by_principal: Mapping[str, list[dict[str, Any]]] | None = None,
) -> None:
    normalized_principal_ids = {
        _canonical_directory_object_id(
            principal_id,
            field=f"{field} principal ID",
        )
        for principal_id in principal_ids
    }
    expected_by_principal = {
        principal_id.casefold(): {assignment_id.casefold() for assignment_id in assignment_ids}
        for principal_id, assignment_ids in expected_acr_assignments_by_principal.items()
    }
    if set(expected_by_principal) - normalized_principal_ids:
        raise OrchestrationError(
            f"{field} expected ACR assignments contain an ungoverned principal"
        )
    role_definitions: dict[str, dict[str, Any]] = {}
    budget = (
        _AuthorizationScanBudget.bounded() if effective_assignments_by_principal is None else None
    )
    as_of = datetime.now(UTC)
    for principal_id in sorted(normalized_principal_ids):
        expected_assignment_ids = expected_by_principal.get(principal_id, set())
        assignments = (
            _resolved_effective_role_assignments(
                principal_id,
                subscription_id=subscription_id,
                field=f"{field} for {principal_id}",
                budget=budget,
                as_of=as_of,
            )
            if effective_assignments_by_principal is None
            else effective_assignments_by_principal.get(principal_id)
        )
        if assignments is None:
            raise OrchestrationError(
                f"{field} evidence is missing governed principal {principal_id}"
            )
        observed_expected_ids: set[str] = set()
        for index, raw_assignment in enumerate(assignments):
            assignment = _mapping(
                raw_assignment,
                field=f"{field} assignment {index}",
            )
            assignment_scope = _canonical_authorization_assignment_scope(
                assignment.get("scope"),
                subscription_id=subscription_id,
                field=f"{field} assignment {index} scope",
            )
            if not _scope_can_govern_acr(assignment_scope):
                continue
            role_definition_id = _string(
                assignment.get("roleDefinitionId"),
                field=f"{field} assignment {index} role definition ID",
            )
            normalized_role_definition_id = role_definition_id.casefold()
            role_definition = role_definitions.get(normalized_role_definition_id)
            if role_definition is None:
                role_definition = _get_role_definition(
                    role_definition_id,
                    subscription_id=subscription_id,
                )
                role_definitions[normalized_role_definition_id] = role_definition
            if not _role_definition_grants_acr_pull(
                role_definition,
                assignment_scope=assignment_scope,
            ):
                continue
            assignment_id = _string(
                assignment.get("id"),
                field=f"{field} assignment {index} ID",
            ).casefold()
            assignment_principal_id = _canonical_directory_object_id(
                assignment.get("principalId"),
                field=f"{field} assignment {index} principal ID",
            )
            if (
                assignment_id not in expected_assignment_ids
                or assignment_principal_id != principal_id
            ):
                raise OrchestrationError(
                    f"{field} contains an unreviewed direct, inherited, group-derived, "
                    "or sibling-registry pull-capable assignment or pull-escalating assignment"
                )
            observed_expected_ids.add(assignment_id)
        if observed_expected_ids != expected_assignment_ids:
            raise OrchestrationError(
                f"{field} evidence is missing an exact reviewed ACR assignment"
            )


def _verify_role_profile_condition(
    *,
    scope: str,
    role_definition_id: str,
    custom_permissions: _RolePermissionProfile | None,
    condition_version: object,
    condition: object,
    field: str,
) -> str | None:
    role_id = role_definition_id.casefold().rsplit("/", 1)[-1]
    scope_type = _resource_type(scope)
    grants_blob_read = role_id == BLOB_DATA_READER_ROLE_ID or (
        custom_permissions is not None and BLOB_READ_DATA_ACTION in custom_permissions.data_actions
    )
    expected_condition_version: str | None = None
    expected_condition: str | None = None
    repository_name: str | None = None
    if grants_blob_read:
        expected_condition_version = "2.0"
        expected_condition = BLOB_LIST_DENY_CONDITION
    elif (
        scope_type == "microsoft.containerregistry/registries"
        and role_id == ACR_REPOSITORY_READER_ROLE_ID
    ):
        if condition_version != "2.0":
            raise OrchestrationError(
                f"{field} Repository Reader condition version must be exactly 2.0"
            )
        repository_name = _acr_repository_name_from_condition(
            condition,
            field=f"{field} Repository Reader condition",
        )
        expected_condition_version = "2.0"
        expected_condition = _acr_repository_condition(repository_name)
    if condition_version != expected_condition_version or condition != expected_condition:
        raise OrchestrationError(f"{field} condition does not match its exact role profile")
    return repository_name


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
    custom_roles: dict[str, _RolePermissionProfile] = {}
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

        custom_permissions = custom_roles.get(role_definition_id.casefold())
        if expected.custom_role_permissions is None and custom_permissions is not None:
            raise OrchestrationError(
                f"{expected.label} unexpectedly references a custom role definition"
            )
        if expected.custom_role_permissions is not None:
            if custom_permissions is None:
                raise OrchestrationError(
                    f"{expected.label} does not reference its exact custom role definition"
                )
            if custom_permissions != expected.custom_role_permissions:
                raise OrchestrationError(
                    f"{expected.label} custom role does not match its exact "
                    "per-assignment permission profile"
                )
        grants_blob_read = role_id == BLOB_DATA_READER_ROLE_ID or (
            custom_permissions is not None
            and BLOB_READ_DATA_ACTION in custom_permissions.data_actions
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
        if custom_permissions is None:
            raise OrchestrationError(
                "role assignment references a custom role outside the deployment binding"
            )
        allowed_custom_profiles = ALLOWED_CUSTOM_PERMISSION_PROFILES_BY_SCOPE_TYPE.get(
            scope_type,
            frozenset(),
        )
        if custom_permissions not in allowed_custom_profiles:
            raise OrchestrationError(
                "custom role permissions do not match the assignment resource scope"
            )
        used_custom_roles.add(role_definition_id.casefold())
    if used_custom_roles != set(custom_roles):
        raise OrchestrationError("deployment binding contains an unused or unassigned custom role")
    return assignment_ids_by_principal


def _verify_legacy_crypto_user_migration(
    expected_assignments: Mapping[str, _ExpectedRoleAssignment],
    reviewed_assignment_ids: set[str] | frozenset[str],
    *,
    migration_state: str,
    subscription_id: str,
) -> None:
    if migration_state not in {"present", "absent"}:
        raise OrchestrationError("legacy Crypto User migration state is invalid")
    reviewed_ids = {resource_id.casefold() for resource_id in reviewed_assignment_ids}
    if not reviewed_ids.issubset(expected_assignments):
        raise OrchestrationError(
            "legacy Crypto User migration approval is outside the exact "
            "deterministic assignment set"
        )
    assignments_by_scope: dict[str, set[str]] = {}
    for assignment_id, expected in expected_assignments.items():
        assignments_by_scope.setdefault(expected.scope.casefold(), set()).add(assignment_id)
    observed_resource_ids: dict[str, str] = {}
    for normalized_scope, expected_ids in assignments_by_scope.items():
        scope = next(
            expected.scope
            for expected in expected_assignments.values()
            if expected.scope.casefold() == normalized_scope
        )
        assignments = _merge_effective_role_assignment_documents(
            [
                _run_json(
                    [
                        "az",
                        "role",
                        "assignment",
                        "list",
                        "--subscription",
                        subscription_id,
                        "--scope",
                        scope,
                        "--only-show-errors",
                        "--output",
                        "json",
                    ],
                    field=f"legacy Crypto User assignments at {scope}",
                )
            ],
            field=f"legacy Crypto User assignments at {scope}",
        )
        scope_resource_ids = {
            resource_id.casefold(): resource_id
            for resource_id in (
                _string(
                    assignment.get("id"),
                    field="legacy Crypto User assignment ID",
                )
                for assignment in assignments
            )
        }
        for assignment_id in expected_ids & set(scope_resource_ids):
            observed_resource_ids[assignment_id] = scope_resource_ids[assignment_id]
    observed_ids = set(observed_resource_ids)
    if migration_state == "present":
        if observed_ids != reviewed_ids:
            raise OrchestrationError(
                "legacy Crypto User migration evidence does not exactly match "
                "the reviewed assignment IDs"
            )
        if observed_ids:
            _verify_rbac_resources(
                {
                    "rbacResourceIds": [
                        observed_resource_ids[assignment_id]
                        for assignment_id in sorted(observed_ids)
                    ]
                },
                expected_assignments={
                    assignment_id: expected_assignments[assignment_id]
                    for assignment_id in observed_ids
                },
                subscription_id=subscription_id,
            )
    elif observed_ids:
        raise OrchestrationError(
            "legacy Crypto User assignments require controlled revocation "
            "before deployment or readiness"
        )


def _reviewed_acr_registry_scopes(
    *,
    stage: str,
    effective_parameters: Mapping[str, Mapping[str, object]],
    subscription_id: str,
) -> set[str]:
    parameter_names = (
        (
            "acceptanceImageRegistryResourceId",
            "presentationImageRegistryResourceId",
        )
        if stage in {"foundation", "live-acceptance"}
        else ("registryResourceId",)
    )
    return {
        _canonical_subscription_resource_id(
            _parameter_value(effective_parameters, name),
            subscription_id=subscription_id,
            field=f"{stage} reviewed ACR scope {name}",
        )
        for name in parameter_names
    }


def _verify_legacy_acr_pull_migration(
    reviewed_assignments: object,
    *,
    migration_state: str,
    stage: str,
    effective_parameters: Mapping[str, Mapping[str, object]],
    subscription_id: str,
    allow_reviewed_assignment_scopes: bool = False,
) -> None:
    if migration_state not in {"present", "absent"}:
        raise OrchestrationError("legacy ACR pull migration state is invalid")
    assignments = _canonical_legacy_acr_pull_migration_assignments(
        reviewed_assignments,
        subscription_id=subscription_id,
        field="legacy ACR pull migration assignments",
    )
    if not assignments:
        return
    reviewed_scopes = (
        {
            _role_assignment_scope(
                assignment["assignmentResourceId"]
            ).casefold(): _role_assignment_scope(assignment["assignmentResourceId"])
            for assignment in assignments
        }
        if allow_reviewed_assignment_scopes
        else {
            scope.casefold(): scope
            for scope in _reviewed_acr_registry_scopes(
                stage=stage,
                effective_parameters=effective_parameters,
                subscription_id=subscription_id,
            )
        }
    )
    if any(
        _resource_type(scope) != "microsoft.containerregistry/registries"
        for scope in reviewed_scopes.values()
    ):
        raise OrchestrationError(
            "legacy ACR pull migration scope must identify a container registry"
        )
    assignments_by_scope: dict[str, list[dict[str, str]]] = {}
    for assignment in assignments:
        scope = _role_assignment_scope(assignment["assignmentResourceId"])
        if scope.casefold() not in reviewed_scopes:
            raise OrchestrationError(
                "legacy ACR pull migration assignment is outside the reviewed registry scopes"
            )
        assignments_by_scope.setdefault(scope.casefold(), []).append(assignment)

    observed_resource_ids: dict[str, str] = {}
    for normalized_scope, scoped_assignments in assignments_by_scope.items():
        scope = reviewed_scopes[normalized_scope]
        observed = _merge_effective_role_assignment_documents(
            [
                _run_json(
                    [
                        "az",
                        "role",
                        "assignment",
                        "list",
                        "--subscription",
                        subscription_id,
                        "--scope",
                        scope,
                        "--only-show-errors",
                        "--output",
                        "json",
                    ],
                    field=f"legacy ACR pull assignments at {scope}",
                )
            ],
            field=f"legacy ACR pull assignments at {scope}",
        )
        observed_at_scope = {
            _string(
                item.get("id"),
                field="legacy ACR pull assignment ID",
            ).casefold(): _string(
                item.get("id"),
                field="legacy ACR pull assignment ID",
            )
            for item in observed
        }
        for assignment in scoped_assignments:
            normalized_id = assignment["assignmentResourceId"].casefold()
            if normalized_id in observed_at_scope:
                observed_resource_ids[normalized_id] = observed_at_scope[normalized_id]

    reviewed_by_id = {item["assignmentResourceId"].casefold(): item for item in assignments}
    observed_ids = set(observed_resource_ids)
    if migration_state == "absent":
        if observed_ids:
            raise OrchestrationError(
                "legacy ACR pull assignments require controlled revocation "
                "before deployment or readiness"
            )
        return
    if observed_ids != set(reviewed_by_id):
        raise OrchestrationError(
            "legacy ACR pull migration evidence does not exactly match the reviewed assignment IDs"
        )
    for assignment_id in sorted(observed_ids):
        reviewed = reviewed_by_id[assignment_id]
        original_assignment_id = observed_resource_ids[assignment_id]
        scope = _role_assignment_scope(original_assignment_id)
        resource = _get_resource(
            original_assignment_id,
            subscription_id=subscription_id,
        )
        _require_resource_id_equal(
            resource.get("id"),
            original_assignment_id,
            field="legacy ACR pull assignment readback",
        )
        properties = _mapping(
            resource.get("properties"),
            field="legacy ACR pull assignment properties",
        )
        if (
            _canonical_directory_object_id(
                properties.get("principalId"),
                field="legacy ACR pull principal ID",
            )
            != reviewed["principalId"]
            or properties.get("principalType") != "ServicePrincipal"
        ):
            raise OrchestrationError("legacy ACR pull assignment principal does not match review")
        role_definition_id = _canonical_subscription_resource_id(
            properties.get("roleDefinitionId"),
            subscription_id=subscription_id,
            field="legacy ACR pull role definition",
        )
        role_id = role_definition_id.casefold().rsplit("/", 1)[-1]
        _require_resource_id_equal(
            scope,
            _role_assignment_scope(reviewed["assignmentResourceId"]),
            field="legacy ACR pull scope",
        )
        if properties.get("scope") is not None:
            _require_resource_id_equal(
                properties.get("scope"),
                _role_assignment_scope(reviewed["assignmentResourceId"]),
                field="legacy ACR pull scope property",
            )
        registry = _get_resource(
            scope,
            subscription_id=subscription_id,
        )
        _require_resource_id_equal(
            registry.get("id"),
            scope,
            field="legacy ACR registry readback",
        )
        registry_mode = _acr_role_assignment_mode(
            _mapping(
                registry.get("properties"),
                field="legacy ACR registry properties",
            ).get("roleAssignmentMode"),
            field="legacy ACR registry role-assignment mode",
        )
        if role_id == ACR_PULL_ROLE_ID:
            if (
                properties.get("conditionVersion") is not None
                or properties.get("condition") is not None
            ):
                raise OrchestrationError(
                    "legacy AcrPull migration assignment must not contain a condition"
                )
            if (
                registry_mode == ACR_LEGACY_ROLE_ASSIGNMENT_MODE
                and assignment_id
                == _acr_pull_role_assignment_id(
                    scope=scope,
                    principal_id=reviewed["principalId"],
                    role_definition_id=role_definition_id,
                    role_assignment_mode=ACR_LEGACY_ROLE_ASSIGNMENT_MODE,
                    repository_name="",
                ).casefold()
            ):
                raise OrchestrationError(
                    "current principal-seeded AcrPull assignment cannot be classified as legacy"
                )
            continue
        if role_id == ACR_REPOSITORY_READER_ROLE_ID:
            if registry_mode != ACR_ABAC_ROLE_ASSIGNMENT_MODE:
                raise OrchestrationError(
                    "obsolete Repository Reader migration requires an ABAC-enabled registry"
                )
            if (
                properties.get("conditionVersion") is not None
                or properties.get("condition") is not None
            ):
                raise OrchestrationError(
                    "obsolete Repository Reader migration is limited to the "
                    "unconditioned pre-remediation assignment"
                )
            continue
        raise OrchestrationError(
            "legacy ACR migration must identify AcrPull or the obsolete "
            "unconditioned Repository Reader role"
        )


def _capture_revocation_assignment_evidence(
    assignment_resource_ids: Sequence[str],
    *,
    subscription_id: str,
) -> list[dict[str, object]]:
    evidence: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw_assignment_id in enumerate(assignment_resource_ids):
        assignment_id = _canonical_subscription_resource_id(
            raw_assignment_id,
            subscription_id=subscription_id,
            field=f"revocation assignment {index}",
        )
        normalized_id = assignment_id.casefold()
        if normalized_id in seen:
            raise OrchestrationError("revocation assignment evidence must contain distinct IDs")
        seen.add(normalized_id)
        resource = _get_resource(
            assignment_id,
            subscription_id=subscription_id,
        )
        _require_resource_id_equal(
            resource.get("id"),
            assignment_id,
            field="revocation assignment readback",
        )
        properties = _mapping(
            resource.get("properties"),
            field="revocation assignment properties",
        )
        scope = _role_assignment_scope(assignment_id)
        if properties.get("scope") is not None:
            _require_resource_id_equal(
                properties.get("scope"),
                scope,
                field="revocation assignment scope",
            )
        registry_mode: str | None = None
        if _resource_type(scope) == "microsoft.containerregistry/registries":
            registry = _get_resource(
                scope,
                subscription_id=subscription_id,
            )
            _require_resource_id_equal(
                registry.get("id"),
                scope,
                field="revocation ACR runtime readback",
            )
            registry_mode = _acr_role_assignment_mode(
                _mapping(
                    registry.get("properties"),
                    field="revocation ACR properties",
                ).get("roleAssignmentMode"),
                field="revocation ACR role-assignment mode",
            )
        evidence.append(
            {
                "assignmentResourceId": assignment_id,
                "principalId": _canonical_directory_object_id(
                    properties.get("principalId"),
                    field="revocation assignment principal ID",
                ),
                "principalType": _string(
                    properties.get("principalType"),
                    field="revocation assignment principal type",
                ),
                "roleDefinitionId": _canonical_subscription_resource_id(
                    properties.get("roleDefinitionId"),
                    subscription_id=subscription_id,
                    field="revocation assignment role definition",
                ),
                "scope": scope,
                "conditionVersion": properties.get("conditionVersion"),
                "condition": properties.get("condition"),
                "registryRoleAssignmentMode": registry_mode,
            }
        )
    evidence.sort(key=lambda item: str(item["assignmentResourceId"]).casefold())
    return evidence


def _validated_revocation_assignment_evidence(
    value: object,
    *,
    subscription_id: str,
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise OrchestrationError("revocation assignments must be an array")
    validated: list[dict[str, object]] = []
    for index, raw_assignment in enumerate(value):
        assignment = _mapping(
            raw_assignment,
            field=f"revocation assignment evidence {index}",
        )
        _require_exact_fields(
            assignment,
            frozenset(
                {
                    "assignmentResourceId",
                    "principalId",
                    "principalType",
                    "roleDefinitionId",
                    "scope",
                    "conditionVersion",
                    "condition",
                    "registryRoleAssignmentMode",
                }
            ),
            field=f"revocation assignment evidence {index}",
        )
        assignment_id = _canonical_subscription_resource_id(
            assignment.get("assignmentResourceId"),
            subscription_id=subscription_id,
            field=f"revocation assignment evidence {index} ID",
        )
        scope = _azure_resource_id(
            assignment.get("scope"),
            field=f"revocation assignment evidence {index} scope",
        )
        _require_resource_id_equal(
            _role_assignment_scope(assignment_id),
            scope,
            field=f"revocation assignment evidence {index} scope",
        )
        _canonical_directory_object_id(
            assignment.get("principalId"),
            field=f"revocation assignment evidence {index} principal",
        )
        if assignment.get("principalType") != "ServicePrincipal":
            raise OrchestrationError(
                "revocation assignment principal type must be ServicePrincipal"
            )
        _canonical_subscription_resource_id(
            assignment.get("roleDefinitionId"),
            subscription_id=subscription_id,
            field=f"revocation assignment evidence {index} role",
        )
        for condition_field in ("conditionVersion", "condition"):
            condition_value = assignment.get(condition_field)
            if condition_value is not None and not isinstance(
                condition_value,
                str,
            ):
                raise OrchestrationError(f"revocation assignment {condition_field} is invalid")
        registry_mode = assignment.get("registryRoleAssignmentMode")
        if _resource_type(scope) == "microsoft.containerregistry/registries":
            _acr_role_assignment_mode(
                registry_mode,
                field="revocation assignment registry mode",
            )
        elif registry_mode is not None:
            raise OrchestrationError("non-ACR revocation assignment cannot carry a registry mode")
        validated.append(dict(assignment))
    if validated != sorted(
        validated,
        key=lambda item: str(item["assignmentResourceId"]).casefold(),
    ) or len({str(item["assignmentResourceId"]).casefold() for item in validated}) != len(
        validated
    ):
        raise OrchestrationError("revocation assignment evidence must be sorted and distinct")
    return validated


def _revocation_assignment_evidence_sha256(
    value: Sequence[Mapping[str, object]],
) -> str:
    return _sha256_bytes(_canonical_json_bytes(list(value)))


def _verify_revocation_assignment_evidence_bindings(
    evidence: Sequence[Mapping[str, object]],
    *,
    rotations: Sequence[Mapping[str, str]],
    legacy_acr_migrations: Sequence[Mapping[str, str]],
    legacy_crypto_expected: Mapping[str, _ExpectedRoleAssignment] | None,
    subscription_id: str,
) -> None:
    by_id = {str(item["assignmentResourceId"]).casefold(): item for item in evidence}
    rotation_ids = {item["assignmentResourceId"].casefold() for item in rotations}
    legacy_acr_ids = {item["assignmentResourceId"].casefold() for item in legacy_acr_migrations}
    legacy_crypto_ids = set() if legacy_crypto_expected is None else set(legacy_crypto_expected)
    if len(rotation_ids | legacy_acr_ids | legacy_crypto_ids) != len(rotation_ids) + len(
        legacy_acr_ids
    ) + len(legacy_crypto_ids):
        raise OrchestrationError(
            "one revocation assignment cannot belong to multiple migration categories"
        )
    for rotation in rotations:
        assignment_id = rotation["assignmentResourceId"].casefold()
        item = by_id[assignment_id]
        if item["principalId"] != rotation["retiredPrincipalId"]:
            raise OrchestrationError(
                "revocation evidence principal differs from the reviewed retired principal"
            )
        scope = str(item["scope"])
        role_definition_id = str(item["roleDefinitionId"])
        role_id = role_definition_id.casefold().rsplit("/", 1)[-1]
        scope_type = _resource_type(scope)
        custom_permissions: _RolePermissionProfile | None = None
        if role_id in BUILT_IN_DATA_ROLE_IDS:
            if role_id not in ALLOWED_BUILT_IN_ROLES_BY_SCOPE_TYPE.get(
                scope_type,
                frozenset(),
            ):
                raise OrchestrationError(
                    "revocation evidence role does not match its reviewed scope"
                )
        else:
            role = _get_resource(
                role_definition_id,
                subscription_id=subscription_id,
            )
            _require_subscription_resource_id_equal(
                role.get("id"),
                role_definition_id,
                subscription_id=subscription_id,
                field="revocation evidence custom role readback",
            )
            custom_permissions = _verify_custom_role(role)
            if custom_permissions not in (
                ALLOWED_CUSTOM_PERMISSION_PROFILES_BY_SCOPE_TYPE.get(
                    scope_type,
                    frozenset(),
                )
            ):
                raise OrchestrationError("revocation evidence custom role does not match its scope")
        _verify_role_profile_condition(
            scope=scope,
            role_definition_id=role_definition_id,
            custom_permissions=custom_permissions,
            condition_version=item["conditionVersion"],
            condition=item["condition"],
            field="revocation evidence",
        )
        if scope_type == "microsoft.containerregistry/registries":
            mode = _acr_role_assignment_mode(
                item["registryRoleAssignmentMode"],
                field="revocation evidence ACR mode",
            )
            _require_subscription_resource_id_equal(
                role_definition_id,
                _acr_pull_role_definition_id(
                    role_assignment_mode=mode,
                    subscription_id=subscription_id,
                ),
                subscription_id=subscription_id,
                field="revocation evidence ACR role",
            )
    for migration in legacy_acr_migrations:
        item = by_id[migration["assignmentResourceId"].casefold()]
        if item["principalId"] != migration["principalId"]:
            raise OrchestrationError("legacy ACR revocation evidence principal differs from review")
        if _resource_type(str(item["scope"])) != "microsoft.containerregistry/registries":
            raise OrchestrationError("legacy ACR revocation evidence scope is invalid")
        mode = _acr_role_assignment_mode(
            item["registryRoleAssignmentMode"],
            field="legacy ACR revocation evidence mode",
        )
        role_definition_id = _canonical_subscription_resource_id(
            item["roleDefinitionId"],
            subscription_id=subscription_id,
            field="legacy ACR revocation evidence role",
        )
        role_id = role_definition_id.casefold().rsplit("/", 1)[-1]
        if item["conditionVersion"] is not None or item["condition"] is not None:
            raise OrchestrationError(
                "legacy ACR revocation evidence must identify an unconditioned assignment"
            )
        if role_id == ACR_PULL_ROLE_ID:
            continue
        if role_id == ACR_REPOSITORY_READER_ROLE_ID and mode == ACR_ABAC_ROLE_ASSIGNMENT_MODE:
            continue
        raise OrchestrationError(
            "legacy ACR revocation evidence must identify AcrPull or the obsolete "
            "ABAC Repository Reader role"
        )
    if legacy_crypto_expected is not None:
        for assignment_id, expected in legacy_crypto_expected.items():
            item = by_id[assignment_id]
            if (
                item["principalId"] != expected.principal_id
                or str(item["scope"]).casefold() != expected.scope.casefold()
                or str(item["roleDefinitionId"]).casefold()
                != expected.role_definition_id.casefold()
                or item["conditionVersion"] != expected.condition_version
                or item["condition"] != expected.condition
            ):
                raise OrchestrationError(
                    "legacy Crypto User revocation evidence differs from exact review"
                )


def _verify_complete_trigger_queue_assignment_set(
    *,
    current_expected_assignments: Mapping[str, _ExpectedRoleAssignment],
    required_current_assignment_ids: set[str],
    approved_transitions: object,
    transition_state: str,
    subscription_id: str,
) -> dict[str, set[str]]:
    if transition_state not in {"present", "absent"}:
        raise OrchestrationError("trigger-queue transition state is invalid")
    if not current_expected_assignments:
        raise OrchestrationError("trigger-queue verification requires current expected assignments")
    trigger_queue_scopes = {
        expected.scope.casefold() for expected in current_expected_assignments.values()
    }
    if len(trigger_queue_scopes) != 1:
        raise OrchestrationError("trigger-queue expectations do not share one exact queue scope")
    trigger_queue_scope = next(iter(current_expected_assignments.values())).scope
    normalized_required_ids = {
        assignment_id.casefold() for assignment_id in required_current_assignment_ids
    }
    if not normalized_required_ids.issubset(current_expected_assignments):
        raise OrchestrationError(
            "required trigger-queue assignments are outside the current expected set"
        )
    current_principal_ids = {
        expected.principal_id.casefold() for expected in current_expected_assignments.values()
    }
    transitions = {
        assignment_id: evidence
        for assignment_id, evidence in _rotation_transition_assignments_by_id(
            approved_transitions,
            subscription_id=subscription_id,
        ).items()
        if (
            "/providers/microsoft.authorization/roleassignments/"
            in evidence.assignment_resource_id.casefold()
            and _role_assignment_scope(evidence.assignment_resource_id).casefold()
            == trigger_queue_scope.casefold()
        )
    }
    transition_assignment_ids = set(transitions)
    if len(transition_assignment_ids) > MAX_APPROVED_TRIGGER_QUEUE_TRANSITION_ASSIGNMENTS:
        raise OrchestrationError(
            "approved trigger-queue transition assignments exceed the bounded maximum"
        )

    all_scoped_assignments = _authorization_assignments_at_or_above_scope(
        trigger_queue_scope,
        subscription_id=subscription_id,
        field="complete trigger-queue authorization assignments",
        include_eligibility=True,
    )
    role_definitions: dict[str, dict[str, Any]] = {}
    scoped_assignments: list[dict[str, Any]] = []
    for index, assignment in enumerate(all_scoped_assignments):
        assignment_scope = _canonical_authorization_assignment_scope(
            assignment.get("scope"),
            subscription_id=subscription_id,
            field=f"trigger-queue authorization assignment {index} scope",
        )
        if not _scope_contains_resource(assignment_scope, trigger_queue_scope):
            raise OrchestrationError(
                "trigger-queue atScope evidence contains an unrelated assignment scope"
            )
        if assignment_scope.casefold() == trigger_queue_scope.casefold():
            scoped_assignments.append(assignment)
            continue
        role_definition_id = _string(
            assignment.get("roleDefinitionId"),
            field=f"trigger-queue authorization assignment {index} role definition ID",
        )
        normalized_role_definition_id = role_definition_id.casefold()
        role_definition = role_definitions.get(normalized_role_definition_id)
        if role_definition is None:
            role_definition = _get_role_definition(
                role_definition_id,
                subscription_id=subscription_id,
            )
            role_definitions[normalized_role_definition_id] = role_definition
        if _role_definition_grants_trigger_queue_access(role_definition):
            scoped_assignments.append(assignment)
    observed_resource_ids = {
        resource_id.casefold(): resource_id
        for resource_id in (
            _string(
                assignment.get("id"),
                field="trigger-queue role assignment ID",
            )
            for assignment in scoped_assignments
        )
    }
    observed_assignment_ids = set(observed_resource_ids)
    allowed_assignment_ids = {
        *current_expected_assignments,
        *transition_assignment_ids,
    }
    if observed_assignment_ids - allowed_assignment_ids:
        raise OrchestrationError(
            "trigger queue contains an unreviewed or obsolete role assignment or schedule"
        )
    if normalized_required_ids - observed_assignment_ids:
        raise OrchestrationError(
            "trigger-queue assignment evidence is incomplete for the current binding"
        )

    observed_current_expectations = {
        assignment_id: current_expected_assignments[assignment_id]
        for assignment_id in observed_assignment_ids & set(current_expected_assignments)
        if assignment_id not in transition_assignment_ids
    }
    verified_current_assignments = (
        {}
        if not observed_current_expectations
        else _verify_rbac_resources(
            {
                "rbacResourceIds": [
                    observed_resource_ids[assignment_id]
                    for assignment_id in sorted(observed_current_expectations)
                ]
            },
            expected_assignments=observed_current_expectations,
            subscription_id=subscription_id,
        )
    )

    observed_transition_ids = transition_assignment_ids & observed_assignment_ids
    allowed_transition_role_definition_ids = {
        _built_in_role_definition_id(
            subscription_id,
            SERVICE_BUS_DATA_RECEIVER_ROLE_ID,
        ).casefold(),
        _built_in_role_definition_id(
            subscription_id,
            SERVICE_BUS_DATA_SENDER_ROLE_ID,
        ).casefold(),
    }
    reused_current_assignments: dict[str, set[str]] = {}
    for assignment_id in sorted(observed_transition_ids):
        evidence = transitions[assignment_id]
        original_assignment_id = evidence.assignment_resource_id
        resource = _get_resource(
            original_assignment_id,
            subscription_id=subscription_id,
        )
        _require_resource_id_equal(
            resource.get("id"),
            original_assignment_id,
            field="approved trigger-queue transition assignment readback",
        )
        properties = _mapping(
            resource.get("properties"),
            field="approved trigger-queue transition assignment properties",
        )
        principal_id = _canonical_directory_object_id(
            properties.get("principalId"),
            field="trigger-queue transition principal ID",
        )
        if transition_state == "absent":
            if principal_id == evidence.retired_principal_id:
                raise OrchestrationError(
                    "retired trigger-queue assignment still targets the reviewed retired principal"
                )
            expected = current_expected_assignments.get(assignment_id)
            if expected is None:
                raise OrchestrationError(
                    "trigger-queue transition assignment ID was reused outside "
                    "the exact current assignment set"
                )
            _verify_current_transition_reuse(
                original_assignment_id,
                resource,
                expected,
                subscription_id=subscription_id,
            )
            reused_current_assignments.setdefault(
                expected.principal_id.casefold(),
                set(),
            ).add(assignment_id)
            continue
        if principal_id != evidence.retired_principal_id:
            raise OrchestrationError(
                "trigger-queue transition assignment principal does not match "
                "the independently reviewed retired principal"
            )
        if principal_id in current_principal_ids:
            raise OrchestrationError(
                "approved trigger-queue transition assignment is not bound to a retired principal"
            )
        if properties.get("principalType") != "ServicePrincipal":
            raise OrchestrationError(
                "approved trigger-queue transition principal type must be ServicePrincipal"
            )
        transition_role_definition_id = _canonical_subscription_resource_id(
            properties.get("roleDefinitionId"),
            subscription_id=subscription_id,
            field="approved trigger-queue transition role definition",
        )
        if transition_role_definition_id.casefold() not in allowed_transition_role_definition_ids:
            raise OrchestrationError(
                "approved trigger-queue transition role must be Service Bus "
                "Data Receiver or Data Sender"
            )
        _require_resource_id_equal(
            _role_assignment_scope(original_assignment_id),
            trigger_queue_scope,
            field="approved trigger-queue transition scope",
        )
        if properties.get("scope") is not None:
            _require_resource_id_equal(
                properties.get("scope"),
                trigger_queue_scope,
                field="approved trigger-queue transition scope property",
            )
        if (
            properties.get("conditionVersion") is not None
            or properties.get("condition") is not None
        ):
            raise OrchestrationError(
                "approved trigger-queue transition assignment must have no condition"
            )
    if transition_state == "present" and (transition_assignment_ids - observed_assignment_ids):
        raise OrchestrationError("approved trigger-queue transition evidence is incomplete")
    for principal_id, assignment_ids in reused_current_assignments.items():
        verified_current_assignments.setdefault(principal_id, set()).update(assignment_ids)
    return verified_current_assignments


def _verify_trigger_queue_assignment_set(
    *,
    producer_expected_assignments: Mapping[str, _ExpectedRoleAssignment],
    prospective_publisher_assignments: Mapping[str, _ExpectedRoleAssignment],
    approved_transitions: object,
    require_transition_revoked: bool,
    subscription_id: str,
) -> dict[str, set[str]]:
    if len(prospective_publisher_assignments) != 1:
        raise OrchestrationError(
            "producer verification requires one exact prospective publisher assignment"
        )
    prospective_id, prospective_expected = next(iter(prospective_publisher_assignments.items()))
    trigger_queue_scope = prospective_expected.scope
    producer_queue_expectations = {
        assignment_id: expected
        for assignment_id, expected in producer_expected_assignments.items()
        if expected.scope.casefold() == trigger_queue_scope.casefold()
    }
    if not producer_queue_expectations:
        raise OrchestrationError("producer binding contains no exact trigger-queue assignments")
    current_expectations = {
        **producer_queue_expectations,
        **prospective_publisher_assignments,
    }
    verified_current_assignments = _verify_complete_trigger_queue_assignment_set(
        current_expected_assignments=current_expectations,
        required_current_assignment_ids=set(producer_queue_expectations),
        approved_transitions=approved_transitions,
        transition_state=("absent" if require_transition_revoked else "present"),
        subscription_id=subscription_id,
    )
    prospective_assignment_ids = verified_current_assignments.get(
        prospective_expected.principal_id.casefold(),
        set(),
    )
    if prospective_id not in prospective_assignment_ids:
        return {}
    return {prospective_expected.principal_id.casefold(): {prospective_id.casefold()}}


def _canonical_rotation_transition_assignments(
    values: object,
    *,
    subscription_id: str,
    field: str,
) -> list[dict[str, str]]:
    if not isinstance(values, list):
        raise OrchestrationError(f"{field} must be an array")
    canonical: list[_RotationTransitionEvidence] = []
    for index, raw_value in enumerate(values):
        value = _mapping(
            raw_value,
            field=f"{field}[{index}]",
        )
        _require_exact_fields(
            value,
            frozenset({"assignmentResourceId", "retiredPrincipalId"}),
            field=f"{field}[{index}]",
        )
        assignment_resource_id = _canonical_subscription_resource_id(
            value.get("assignmentResourceId"),
            subscription_id=subscription_id,
            field=f"{field}[{index}].assignmentResourceId",
        )
        if (
            "/providers/microsoft.authorization/roleassignments/"
            not in assignment_resource_id.casefold()
        ):
            raise OrchestrationError(f"{field}[{index}] must identify one role assignment")
        canonical.append(
            _RotationTransitionEvidence(
                assignment_resource_id=assignment_resource_id,
                retired_principal_id=_canonical_directory_object_id(
                    value.get("retiredPrincipalId"),
                    field=f"{field}[{index}].retiredPrincipalId",
                ),
            )
        )
    normalized_ids = {item.assignment_resource_id.casefold() for item in canonical}
    if len(normalized_ids) != len(canonical):
        raise OrchestrationError(f"{field} must contain distinct assignment IDs")
    if len(canonical) > MAX_APPROVED_ROTATION_TRANSITION_ASSIGNMENTS:
        raise OrchestrationError(f"{field} exceeds the bounded maximum")
    canonical.sort(
        key=lambda item: (
            item.assignment_resource_id.casefold(),
            item.retired_principal_id,
        )
    )
    return [item.document() for item in canonical]


def _canonical_legacy_crypto_user_migration_assignments(
    values: object,
    *,
    subscription_id: str,
    field: str,
) -> list[str]:
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise OrchestrationError(f"{field} must be a string array")
    assignments = [
        _canonical_subscription_resource_id(
            resource_id,
            subscription_id=subscription_id,
            field=f"{field}[{index}]",
        )
        for index, resource_id in enumerate(values)
    ]
    if any(
        "/providers/microsoft.authorization/roleassignments/" not in resource_id.casefold()
        for resource_id in assignments
    ):
        raise OrchestrationError(f"{field} must contain only role assignment resource IDs")
    if len({resource_id.casefold() for resource_id in assignments}) != len(assignments):
        raise OrchestrationError(f"{field} must contain distinct values")
    if len(assignments) > MAX_LEGACY_CRYPTO_USER_MIGRATION_ASSIGNMENTS:
        raise OrchestrationError(f"{field} exceeds the bounded maximum")
    return sorted(assignments)


def _canonical_legacy_acr_pull_migration_assignments(
    values: object,
    *,
    subscription_id: str,
    field: str,
) -> list[dict[str, str]]:
    if not isinstance(values, list):
        raise OrchestrationError(f"{field} must be an array")
    canonical: list[dict[str, str]] = []
    for index, raw_value in enumerate(values):
        value = _mapping(raw_value, field=f"{field}[{index}]")
        _require_exact_fields(
            value,
            frozenset({"assignmentResourceId", "principalId"}),
            field=f"{field}[{index}]",
        )
        assignment_resource_id = _canonical_subscription_resource_id(
            value.get("assignmentResourceId"),
            subscription_id=subscription_id,
            field=f"{field}[{index}].assignmentResourceId",
        )
        if (
            "/providers/microsoft.authorization/roleassignments/"
            not in assignment_resource_id.casefold()
        ):
            raise OrchestrationError(f"{field}[{index}] must identify one ACR role assignment")
        canonical.append(
            {
                "assignmentResourceId": assignment_resource_id,
                "principalId": _canonical_directory_object_id(
                    value.get("principalId"),
                    field=f"{field}[{index}].principalId",
                ),
            }
        )
    if len({item["assignmentResourceId"].casefold() for item in canonical}) != len(canonical):
        raise OrchestrationError(f"{field} must contain distinct assignment resource IDs")
    if len(canonical) > MAX_LEGACY_ACR_PULL_MIGRATION_ASSIGNMENTS:
        raise OrchestrationError(f"{field} exceeds the bounded maximum")
    return sorted(
        canonical,
        key=lambda item: (
            item["assignmentResourceId"].casefold(),
            item["principalId"],
        ),
    )


def _merge_legacy_acr_pull_migration_assignments(
    *sources: object,
    subscription_id: str,
) -> list[dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for source_index, source in enumerate(sources):
        for migration in _canonical_legacy_acr_pull_migration_assignments(
            source,
            subscription_id=subscription_id,
            field=f"legacy ACR pull migration source {source_index}",
        ):
            normalized_id = migration["assignmentResourceId"].casefold()
            existing = merged.get(normalized_id)
            if existing is not None and existing != migration:
                raise OrchestrationError(
                    "one legacy ACR assignment is bound to conflicting principals"
                )
            merged[normalized_id] = migration
    return sorted(
        merged.values(),
        key=lambda item: (
            item["assignmentResourceId"].casefold(),
            item["principalId"],
        ),
    )


def _rotation_transition_assignments_by_id(
    approved_transitions: object,
    *,
    subscription_id: str,
) -> dict[str, _RotationTransitionEvidence]:
    canonical = _canonical_rotation_transition_assignments(
        approved_transitions,
        subscription_id=subscription_id,
        field="approved rotation transitions",
    )
    return {
        item["assignmentResourceId"].casefold(): _RotationTransitionEvidence(
            assignment_resource_id=item["assignmentResourceId"],
            retired_principal_id=item["retiredPrincipalId"],
        )
        for item in canonical
    }


def _merge_rotation_transition_assignments(
    *sources: object,
    subscription_id: str,
) -> list[dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for source_index, source in enumerate(sources):
        for transition in _canonical_rotation_transition_assignments(
            source,
            subscription_id=subscription_id,
            field=f"rotation transition source {source_index}",
        ):
            normalized_id = transition["assignmentResourceId"].casefold()
            existing = merged.get(normalized_id)
            if existing is not None and existing != transition:
                raise OrchestrationError(
                    "one rotation assignment is bound to conflicting retired principals"
                )
            merged[normalized_id] = transition
    return sorted(
        merged.values(),
        key=lambda item: (
            item["assignmentResourceId"].casefold(),
            item["retiredPrincipalId"],
        ),
    )


def _rotation_transitions_for_expected_assignments(
    approved_transitions: object,
    *,
    expected_assignments: Mapping[str, _ExpectedRoleAssignment],
    subscription_id: str,
) -> list[dict[str, str]]:
    expected_scopes = {expected.scope.casefold() for expected in expected_assignments.values()}
    return [
        evidence.document()
        for evidence in _rotation_transition_assignments_by_id(
            approved_transitions,
            subscription_id=subscription_id,
        ).values()
        if _role_assignment_scope(evidence.assignment_resource_id).casefold() in expected_scopes
    ]


def _record_handled_rotation_transitions(
    handled_transition_ids: set[str] | None,
    transitions: Sequence[Mapping[str, object]],
) -> None:
    if handled_transition_ids is None:
        return
    handled_transition_ids.update(
        _string(
            transition.get("assignmentResourceId"),
            field="handled rotation transition assignment ID",
        ).casefold()
        for transition in transitions
    )


def _verify_unmatched_rotation_transitions_absent(
    approved_transitions: object,
    *,
    handled_transition_ids: set[str],
    subscription_id: str,
) -> None:
    remaining = [
        evidence.document()
        for assignment_id, evidence in _rotation_transition_assignments_by_id(
            approved_transitions,
            subscription_id=subscription_id,
        ).items()
        if assignment_id not in handled_transition_ids
    ]
    _verify_reviewed_rotation_transitions(
        remaining,
        current_principal_ids=set(),
        transition_state="absent",
        subscription_id=subscription_id,
    )


def _verify_current_transition_reuse(
    resource_id: str,
    resource: Mapping[str, object],
    expected: _ExpectedRoleAssignment,
    *,
    subscription_id: str,
) -> None:
    properties = _mapping(
        resource.get("properties"),
        field=f"{expected.label} recreated assignment properties",
    )
    if (
        _canonical_directory_object_id(
            properties.get("principalId"),
            field=f"{expected.label} recreated assignment principal",
        )
        != _canonical_directory_object_id(
            expected.principal_id,
            field=f"{expected.label} expected principal",
        )
        or properties.get("principalType") != "ServicePrincipal"
    ):
        raise OrchestrationError(
            f"{expected.label} deterministic assignment ID was not recreated "
            "for the exact current service principal"
        )
    role_definition_id = _canonical_subscription_resource_id(
        properties.get("roleDefinitionId"),
        subscription_id=subscription_id,
        field=f"{expected.label} recreated assignment role definition",
    )
    _require_subscription_resource_id_equal(
        role_definition_id,
        expected.role_definition_id,
        subscription_id=subscription_id,
        field=f"{expected.label} recreated assignment role definition",
    )
    scope = _role_assignment_scope(resource_id)
    _require_resource_id_equal(
        scope,
        expected.scope,
        field=f"{expected.label} recreated assignment scope",
    )
    if properties.get("scope") is not None:
        _require_resource_id_equal(
            properties.get("scope"),
            expected.scope,
            field=f"{expected.label} recreated assignment scope property",
        )
    if (
        properties.get("conditionVersion") != expected.condition_version
        or properties.get("condition") != expected.condition
    ):
        raise OrchestrationError(f"{expected.label} recreated assignment condition does not match")
    if expected.custom_role_permissions is not None:
        role = _get_resource(
            role_definition_id,
            subscription_id=subscription_id,
        )
        _require_subscription_resource_id_equal(
            role.get("id"),
            role_definition_id,
            subscription_id=subscription_id,
            field=f"{expected.label} recreated custom role readback",
        )
        if _verify_custom_role(role) != expected.custom_role_permissions:
            raise OrchestrationError(
                f"{expected.label} recreated custom role permissions do not match"
            )


def _verify_reviewed_rotation_transitions(
    approved_transitions: object,
    *,
    current_principal_ids: set[str],
    transition_state: str,
    subscription_id: str,
    current_expected_assignments: Mapping[
        str,
        _ExpectedRoleAssignment,
    ]
    | None = None,
) -> None:
    if transition_state not in {"present", "absent"}:
        raise OrchestrationError("rotation transition state is invalid")
    transitions = _rotation_transition_assignments_by_id(
        approved_transitions,
        subscription_id=subscription_id,
    )
    transition_ids = set(transitions)
    if not transition_ids:
        return
    transition_ids_by_scope: dict[str, set[str]] = {}
    scope_resource_ids: dict[str, str] = {}
    for assignment_id, evidence in transitions.items():
        scope = _role_assignment_scope(evidence.assignment_resource_id)
        scope_resource_ids.setdefault(scope.casefold(), scope)
        transition_ids_by_scope.setdefault(scope.casefold(), set()).add(assignment_id)
    observed_transition_ids: set[str] = set()
    for normalized_scope, scoped_transition_ids in transition_ids_by_scope.items():
        scope = scope_resource_ids[normalized_scope]
        assignments = _merge_effective_role_assignment_documents(
            [
                _run_json(
                    [
                        "az",
                        "role",
                        "assignment",
                        "list",
                        "--subscription",
                        subscription_id,
                        "--scope",
                        scope,
                        "--only-show-errors",
                        "--output",
                        "json",
                    ],
                    field=f"complete role assignments at rotation scope {scope}",
                )
            ],
            field=f"rotation role assignments at {normalized_scope}",
        )
        observed_ids = {
            _string(
                assignment.get("id"),
                field="rotation scope role assignment ID",
            ).casefold()
            for assignment in assignments
        }
        observed_transition_ids.update(scoped_transition_ids & observed_ids)
    normalized_current_principals = {
        principal_id.casefold() for principal_id in current_principal_ids
    }
    expected_assignments = (
        {} if current_expected_assignments is None else current_expected_assignments
    )
    for assignment_id in sorted(observed_transition_ids):
        evidence = transitions[assignment_id]
        original_assignment_id = evidence.assignment_resource_id
        resource = _get_resource(
            original_assignment_id,
            subscription_id=subscription_id,
        )
        _require_resource_id_equal(
            resource.get("id"),
            original_assignment_id,
            field="approved rotation transition assignment readback",
        )
        properties = _mapping(
            resource.get("properties"),
            field="approved rotation transition assignment properties",
        )
        principal_id = _canonical_directory_object_id(
            properties.get("principalId"),
            field="rotation transition principal ID",
        )
        if transition_state == "absent":
            if principal_id == evidence.retired_principal_id:
                raise OrchestrationError(
                    "retired deterministic assignment still targets the reviewed retired principal"
                )
            current_expected = expected_assignments.get(assignment_id)
            if current_expected is None:
                raise OrchestrationError(
                    "rotation assignment ID was reused outside the exact current assignment set"
                )
            _verify_current_transition_reuse(
                original_assignment_id,
                resource,
                current_expected,
                subscription_id=subscription_id,
            )
            continue
        if principal_id != evidence.retired_principal_id:
            raise OrchestrationError(
                "rotation transition assignment principal does not match the "
                "independently reviewed retired principal"
            )
        if principal_id in normalized_current_principals:
            raise OrchestrationError(
                "approved rotation transition assignment is not bound to a retired principal"
            )
        if properties.get("principalType") != "ServicePrincipal":
            raise OrchestrationError(
                "approved rotation transition principal type must be ServicePrincipal"
            )
        scope = _role_assignment_scope(original_assignment_id)
        if properties.get("scope") is not None:
            _require_resource_id_equal(
                properties.get("scope"),
                scope,
                field="approved rotation transition scope",
            )
        role_definition_id = _canonical_subscription_resource_id(
            properties.get("roleDefinitionId"),
            subscription_id=subscription_id,
            field="approved rotation transition role definition",
        )
        role_id = role_definition_id.casefold().rsplit("/", 1)[-1]
        scope_type = _resource_type(scope)
        custom_permissions: _RolePermissionProfile | None = None
        if role_id in BUILT_IN_DATA_ROLE_IDS:
            if role_id not in ALLOWED_BUILT_IN_ROLES_BY_SCOPE_TYPE.get(
                scope_type,
                frozenset(),
            ):
                raise OrchestrationError(
                    "approved rotation transition role does not match its scope"
                )
        else:
            role = _get_resource(
                role_definition_id,
                subscription_id=subscription_id,
            )
            _require_subscription_resource_id_equal(
                role.get("id"),
                role_definition_id,
                subscription_id=subscription_id,
                field="approved rotation custom role readback",
            )
            custom_permissions = _verify_custom_role(role)
            if custom_permissions not in (
                ALLOWED_CUSTOM_PERMISSION_PROFILES_BY_SCOPE_TYPE.get(
                    scope_type,
                    frozenset(),
                )
            ):
                raise OrchestrationError("approved rotation custom role does not match its scope")
        _verify_role_profile_condition(
            scope=scope,
            role_definition_id=role_definition_id,
            custom_permissions=custom_permissions,
            condition_version=properties.get("conditionVersion"),
            condition=properties.get("condition"),
            field="approved rotation transition",
        )
    if transition_state == "present":
        missing = transition_ids - observed_transition_ids
        if missing:
            raise OrchestrationError(
                "approved rotation transition assignment evidence is incomplete"
            )


def _canonical_directory_object_id(value: object, *, field: str) -> str:
    object_id = _string(value, field=field)
    try:
        return str(UUID(object_id))
    except ValueError as exc:
        raise OrchestrationError(f"{field} must be one directory object UUID") from exc


def _validate_graph_membership_url(url: str, *, principal_id: str) -> None:
    parsed = urlparse(url)
    expected_path = (
        f"/v1.0/servicePrincipals/{principal_id}/transitiveMemberOf/microsoft.graph.group"
    )
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != GRAPH_HOST
        or parsed.path.casefold() != expected_path.casefold()
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise OrchestrationError(
            "Microsoft Graph group-membership pagination returned an untrusted continuation URL"
        )


def _transitive_group_ids(principal_id: str) -> set[str]:
    canonical_principal_id = _canonical_directory_object_id(
        principal_id,
        field="managed identity principal ID",
    )
    next_url: str | None = (
        f"https://{GRAPH_HOST}/v1.0/servicePrincipals/{canonical_principal_id}/"
        "transitiveMemberOf/microsoft.graph.group"
        "?$select=id&$count=true&$top=999"
    )
    expected_count: int | None = None
    group_ids: set[str] = set()
    seen_urls: set[str] = set()
    page_number = 0
    while next_url is not None:
        page_number += 1
        if page_number > MAX_GRAPH_MEMBERSHIP_PAGES:
            raise OrchestrationError(
                "Microsoft Graph group-membership pagination exceeded its page bound"
            )
        _validate_graph_membership_url(
            next_url,
            principal_id=canonical_principal_id,
        )
        if next_url in seen_urls:
            raise OrchestrationError("Microsoft Graph group-membership pagination contains a cycle")
        seen_urls.add(next_url)
        page = _mapping(
            _run_json(
                [
                    "az",
                    "rest",
                    "--method",
                    "get",
                    "--url",
                    next_url,
                    "--headers",
                    "ConsistencyLevel=eventual",
                    "--only-show-errors",
                    "--output",
                    "json",
                ],
                field=(
                    "transitive Microsoft Entra group memberships for "
                    f"{canonical_principal_id} page {page_number}"
                ),
            ),
            field="Microsoft Graph group-membership page",
        )
        page_count = page.get("@odata.count")
        if page_number == 1:
            if (
                not isinstance(page_count, int)
                or isinstance(page_count, bool)
                or page_count < 0
                or page_count > MAX_TRANSITIVE_GROUPS
            ):
                raise OrchestrationError(
                    "Microsoft Graph group-membership response is missing a "
                    "bounded authoritative count"
                )
            expected_count = page_count
        elif page_count is not None and page_count != expected_count:
            raise OrchestrationError("Microsoft Graph group-membership count changed across pages")
        values = page.get("value")
        if not isinstance(values, list):
            raise OrchestrationError(
                "Microsoft Graph group-membership page must contain a value array"
            )
        for index, raw_group in enumerate(values):
            group = _mapping(
                raw_group,
                field=f"Microsoft Graph group-membership item {index}",
            )
            object_type = group.get("@odata.type")
            if object_type not in (None, "#microsoft.graph.group"):
                raise OrchestrationError(
                    "Microsoft Graph transitive membership returned a non-group object"
                )
            group_id = _canonical_directory_object_id(
                group.get("id"),
                field="Microsoft Graph group ID",
            )
            if group_id in group_ids:
                raise OrchestrationError(
                    "Microsoft Graph group-membership pages contain a duplicate group"
                )
            group_ids.add(group_id)
            if len(group_ids) > MAX_TRANSITIVE_GROUPS:
                raise OrchestrationError(
                    "Microsoft Graph group membership exceeds its bounded maximum"
                )
        continuation = page.get("@odata.nextLink")
        if continuation is None:
            next_url = None
        elif not isinstance(continuation, str) or not continuation:
            raise OrchestrationError("Microsoft Graph group-membership continuation is invalid")
        else:
            next_url = continuation
    if expected_count is None or len(group_ids) != expected_count:
        raise OrchestrationError("Microsoft Graph group-membership pagination is incomplete")
    return group_ids


def _canonical_authorization_assignment_scope(
    value: object,
    *,
    subscription_id: str,
    field: str,
) -> str:
    scope = _string(value, field=field)
    if scope == "/":
        return scope
    if scope != scope.strip() or scope.endswith("/"):
        raise OrchestrationError(f"{field} must be one canonical Azure scope")
    if scope.casefold().startswith("/subscriptions/"):
        return _canonical_subscription_resource_id(
            scope,
            subscription_id=subscription_id,
            field=field,
        )
    segments = scope.split("/")
    if (
        len(segments) != 5
        or segments[0] != ""
        or segments[1].casefold() != "providers"
        or segments[2].casefold() != "microsoft.management"
        or segments[3].casefold() != "managementgroups"
    ):
        raise OrchestrationError(f"{field} is outside the governed subscription hierarchy")
    _validate_resource_id_segment(
        segments[4],
        field=f"{field} management group",
    )
    return scope


def _parse_authorization_schedule_time(
    value: object,
    *,
    field: str,
    required: bool,
) -> datetime | None:
    if value is None and not required:
        return None
    timestamp = _string(value, field=field)
    if timestamp != timestamp.strip() or len(timestamp) > 128:
        raise OrchestrationError(f"{field} must be one bounded UTC timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OrchestrationError(f"{field} must be one ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise OrchestrationError(f"{field} must include a UTC offset")
    return parsed.astimezone(UTC)


def _active_or_upcoming_authorization_schedule(
    properties: Mapping[str, object],
    *,
    field: str,
    as_of: datetime,
) -> bool:
    if as_of.tzinfo is None:
        raise OrchestrationError(f"{field} evaluation time must include a UTC offset")
    as_of = as_of.astimezone(UTC)
    status = _string(
        properties.get("status"),
        field=f"{field} status",
    )
    if status != status.strip() or status.casefold() not in AUTHORIZATION_SCHEDULE_STATUSES:
        raise OrchestrationError(f"{field} status is unknown")
    start = _parse_authorization_schedule_time(
        properties.get("startDateTime"),
        field=f"{field} startDateTime",
        required=True,
    )
    end = _parse_authorization_schedule_time(
        properties.get("endDateTime"),
        field=f"{field} endDateTime",
        required=False,
    )
    if start is None:
        raise OrchestrationError(f"{field} startDateTime is missing")
    if end is not None and end <= start:
        raise OrchestrationError(f"{field} schedule interval is invalid")
    if status.casefold() in INACTIVE_AUTHORIZATION_SCHEDULE_STATUSES:
        return False
    return end is None or end > as_of


def _authorization_assignment_from_resource(
    resource: Mapping[str, object],
    *,
    resource_type: str,
    subscription_id: str,
    field: str,
    as_of: datetime,
) -> dict[str, Any] | None:
    expected_type = f"Microsoft.Authorization/{resource_type}"
    actual_type = resource.get("type")
    if actual_type is not None and (
        not isinstance(actual_type, str) or actual_type.casefold() != expected_type.casefold()
    ):
        raise OrchestrationError(f"{field} has an unexpected authorization resource type")
    resource_id = _string(
        resource.get("id"),
        field=f"{field} ID",
    )
    marker = f"/providers/microsoft.authorization/{resource_type.casefold()}/"
    normalized_resource_id = resource_id.casefold()
    if (
        resource_id != resource_id.strip()
        or resource_id.endswith("/")
        or any(character in resource_id for character in ("\\", "?", "#"))
        or marker not in normalized_resource_id
    ):
        raise OrchestrationError(f"{field} ID is not canonical")
    try:
        canonical_resource_name = str(UUID(resource_id.rsplit("/", 1)[-1]))
    except ValueError as exc:
        raise OrchestrationError(f"{field} ID must end in one canonical UUID") from exc
    if resource_id.rsplit("/", 1)[-1] != canonical_resource_name:
        raise OrchestrationError(f"{field} ID must use canonical lowercase UUID form")
    properties = _mapping(
        resource.get("properties"),
        field=f"{field} properties",
    )
    principal_id = _canonical_directory_object_id(
        properties.get("principalId"),
        field=f"{field} principal ID",
    )
    scope = _canonical_authorization_assignment_scope(
        properties.get("scope"),
        subscription_id=subscription_id,
        field=f"{field} scope",
    )
    resource_scope = resource_id[: normalized_resource_id.rindex(marker)] or "/"
    if resource_scope.casefold() != scope.casefold():
        raise OrchestrationError(f"{field} ID does not match its assignment scope")
    role_definition_id = _string(
        properties.get("roleDefinitionId"),
        field=f"{field} role definition ID",
    )
    if (
        role_definition_id != role_definition_id.strip()
        or not role_definition_id.startswith("/")
        or any(character in role_definition_id for character in ("\\", "?", "#"))
    ):
        raise OrchestrationError(f"{field} role definition ID is not canonical")
    if resource_type != "roleAssignments":
        member_type = _string(
            properties.get("memberType"),
            field=f"{field} memberType",
        )
        if member_type not in {"Direct", "Group", "Inherited"}:
            raise OrchestrationError(f"{field} memberType is unknown")
        if resource_type == "roleAssignmentScheduleInstances":
            assignment_type = _string(
                properties.get("assignmentType"),
                field=f"{field} assignmentType",
            )
            if assignment_type not in {"Activated", "Assigned"}:
                raise OrchestrationError(f"{field} assignmentType is unknown")
        if not _active_or_upcoming_authorization_schedule(
            properties,
            field=field,
            as_of=as_of,
        ):
            return None
    principal_type = properties.get("principalType")
    if principal_type is not None and (
        not isinstance(principal_type, str)
        or principal_type
        not in {
            "User",
            "Group",
            "ServicePrincipal",
            "ForeignGroup",
            "Device",
            "AgentUser",
            "AgentServicePrincipal",
        }
    ):
        raise OrchestrationError(f"{field} principalType is unknown")
    normalized: dict[str, Any] = {
        "id": resource_id,
        "principalId": principal_id,
        "roleDefinitionId": role_definition_id,
        "scope": scope,
        "authorizationEvidenceKinds": [resource_type],
    }
    for property_name in (
        "principalType",
        "conditionVersion",
        "condition",
        "status",
        "startDateTime",
        "endDateTime",
        "memberType",
        "assignmentType",
    ):
        if property_name in properties:
            normalized[property_name] = properties[property_name]
    expanded = properties.get("expandedProperties")
    if expanded is not None:
        expanded_properties = _mapping(
            expanded,
            field=f"{field} expanded properties",
        )
        expanded_role = expanded_properties.get("roleDefinition")
        if expanded_role is not None:
            role = _mapping(
                expanded_role,
                field=f"{field} expanded role definition",
            )
            display_name = role.get("displayName")
            if display_name is not None:
                normalized["roleDefinitionName"] = _string(
                    display_name,
                    field=f"{field} role definition display name",
                )
    return normalized


def _validate_authorization_assignment_url(
    url: str,
    *,
    scope: str,
    resource_type: str,
    filter_value: str,
    is_continuation: bool,
) -> None:
    if len(url) > 16_384:
        raise OrchestrationError(
            "authorization assignment pagination returned an oversized continuation URL"
        )
    parsed = urlparse(url)
    expected_path = f"{scope.rstrip('/')}/providers/Microsoft.Authorization/{resource_type}"
    raw_query = parse_qs(parsed.query, keep_blank_values=True)
    query: dict[str, list[str]] = {}
    for key, values in raw_query.items():
        normalized_key = key.casefold()
        if normalized_key in query:
            raise OrchestrationError(
                "authorization assignment pagination returned duplicate query fields"
            )
        query[normalized_key] = values
    api_version = AUTHORIZATION_RESOURCE_API_VERSIONS[resource_type]
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != ARM_HOST
        or parsed.path.casefold() != expected_path.casefold()
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or query.get("api-version") != [api_version]
        or any(key not in {"api-version", "$filter", "$skiptoken"} for key in query)
        or any(len(values) != 1 for values in query.values())
        or ("$filter" in query and query["$filter"] != [filter_value])
        or ("$skiptoken" in query and not query["$skiptoken"][0])
        or is_continuation != ("$skiptoken" in query)
    ):
        raise OrchestrationError(
            "authorization assignment pagination returned an untrusted continuation URL"
        )


def _authorization_assignment_pages(
    *,
    scope: str,
    resource_type: str,
    filter_value: str,
    subscription_id: str,
    field: str,
    budget: _AuthorizationScanBudget,
    as_of: datetime,
) -> list[dict[str, Any]]:
    api_version = AUTHORIZATION_RESOURCE_API_VERSIONS[resource_type]
    next_url: str | None = (
        f"https://{ARM_HOST}{scope.rstrip('/')}/providers/"
        f"Microsoft.Authorization/{resource_type}?"
        + urlencode(
            {
                "api-version": api_version,
                "$filter": filter_value,
            }
        )
    )
    assignments: dict[str, dict[str, Any]] = {}
    seen_urls: set[str] = set()
    page_number = 0
    is_continuation = False
    while next_url is not None:
        budget.consume_page()
        page_number += 1
        _validate_authorization_assignment_url(
            next_url,
            scope=scope,
            resource_type=resource_type,
            filter_value=filter_value,
            is_continuation=is_continuation,
        )
        if next_url in seen_urls:
            raise OrchestrationError("authorization assignment pagination contains a cycle")
        seen_urls.add(next_url)
        page = _mapping(
            _run_json(
                [
                    "az",
                    "rest",
                    "--method",
                    "get",
                    "--url",
                    next_url,
                    "--only-show-errors",
                    "--output",
                    "json",
                ],
                field=f"{field} {resource_type} page {page_number}",
            ),
            field=f"{field} {resource_type} page {page_number}",
        )
        values = page.get("value")
        if not isinstance(values, list):
            raise OrchestrationError("authorization assignment page must contain a value array")
        for index, raw_assignment in enumerate(values):
            budget.consume_item()
            assignment = _authorization_assignment_from_resource(
                _mapping(
                    raw_assignment,
                    field=f"{field} {resource_type} page {page_number} item {index}",
                ),
                resource_type=resource_type,
                subscription_id=subscription_id,
                field=f"{field} {resource_type} page {page_number} item {index}",
                as_of=as_of,
            )
            if assignment is None:
                continue
            assignment_id = str(assignment["id"]).casefold()
            existing = assignments.get(assignment_id)
            if existing is not None and _canonical_json_bytes(existing) != _canonical_json_bytes(
                assignment
            ):
                raise OrchestrationError(
                    "authorization assignment pagination returned conflicting duplicate evidence"
                )
            assignments[assignment_id] = assignment
        continuation = page.get("nextLink")
        if continuation is None:
            next_url = None
        elif not isinstance(continuation, str) or not continuation:
            raise OrchestrationError("authorization assignment continuation is invalid")
        else:
            next_url = continuation
            is_continuation = True
    return [assignments[key] for key in sorted(assignments)]


def _authorization_assignments(
    *,
    scope: str,
    filter_value: str,
    subscription_id: str,
    field: str,
    include_eligibility: bool,
    budget: _AuthorizationScanBudget,
    as_of: datetime,
) -> list[dict[str, Any]]:
    resource_types = [
        "roleAssignments",
        "roleAssignmentScheduleInstances",
    ]
    if include_eligibility:
        resource_types.append("roleEligibilityScheduleInstances")
    return _merge_effective_role_assignment_documents(
        [
            _authorization_assignment_pages(
                scope=scope,
                resource_type=resource_type,
                filter_value=filter_value,
                subscription_id=subscription_id,
                field=field,
                budget=budget,
                as_of=as_of,
            )
            for resource_type in resource_types
        ],
        field=field,
    )


def _merge_effective_role_assignment_documents(
    documents: Sequence[object],
    *,
    field: str,
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for document_index, document in enumerate(documents):
        if not isinstance(document, list):
            raise OrchestrationError(f"{field} document {document_index} must be an array")
        for assignment_index, raw_assignment in enumerate(document):
            assignment = _mapping(
                raw_assignment,
                field=f"{field} document {document_index} item {assignment_index}",
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
                "conditionVersion",
                "condition",
                "principalType",
                "status",
                "startDateTime",
                "endDateTime",
                "memberType",
                "assignmentType",
            ):
                existing_value = existing.get(property_name)
                incoming_value = assignment.get(property_name)
                if (
                    existing_value not in (None, "")
                    and incoming_value not in (None, "")
                    and (
                        (
                            property_name
                            in {
                                "principalId",
                                "roleDefinitionId",
                                "roleDefinitionName",
                                "scope",
                            }
                            and str(existing_value).casefold() != str(incoming_value).casefold()
                        )
                        or (
                            property_name
                            not in {
                                "principalId",
                                "roleDefinitionId",
                                "roleDefinitionName",
                                "scope",
                            }
                            and existing_value != incoming_value
                        )
                    )
                ):
                    raise OrchestrationError(
                        f"{field} returned conflicting duplicate assignment {assignment_id}"
                    )
                if existing_value in (None, "") and incoming_value not in (None, ""):
                    existing[property_name] = incoming_value
            evidence_kinds: set[str] = set()
            for candidate in (
                existing.get("authorizationEvidenceKinds"),
                assignment.get("authorizationEvidenceKinds"),
            ):
                if candidate is None:
                    continue
                if not isinstance(candidate, list) or any(
                    not isinstance(item, str) or not item for item in candidate
                ):
                    raise OrchestrationError(
                        f"{field} contains invalid authorization evidence kinds"
                    )
                evidence_kinds.update(candidate)
            if evidence_kinds:
                existing["authorizationEvidenceKinds"] = sorted(evidence_kinds)
    return [merged[key] for key in sorted(merged)]


def _effective_role_assignments(
    principal_id: str,
    *,
    subscription_id: str,
    field: str,
    include_eligibility: bool = True,
    budget: _AuthorizationScanBudget | None = None,
    as_of: datetime | None = None,
) -> list[dict[str, Any]]:
    canonical_principal_id = _canonical_directory_object_id(
        principal_id,
        field=f"{field} principal ID",
    )
    subscription_scope = f"/subscriptions/{subscription_id}"
    scan_budget = _AuthorizationScanBudget.bounded() if budget is None else budget
    observed_at = datetime.now(UTC) if as_of is None else as_of.astimezone(UTC)
    assignments = _authorization_assignments(
        scope=subscription_scope,
        filter_value=f"principalId eq '{canonical_principal_id}'",
        subscription_id=subscription_id,
        field=field,
        include_eligibility=include_eligibility,
        budget=scan_budget,
        as_of=observed_at,
    )
    for assignment in assignments:
        if (
            _canonical_directory_object_id(
                assignment.get("principalId"),
                field=f"{field} returned principal ID",
            )
            != canonical_principal_id
        ):
            raise OrchestrationError(f"{field} returned an assignment for another principal")
    return assignments


def _authorization_assignments_at_or_above_scope(
    scope: str,
    *,
    subscription_id: str,
    field: str,
    include_eligibility: bool = True,
) -> list[dict[str, Any]]:
    canonical_scope = _canonical_subscription_resource_id(
        scope,
        subscription_id=subscription_id,
        field=f"{field} scope",
    )
    return _authorization_assignments(
        scope=canonical_scope,
        filter_value="atScope()",
        subscription_id=subscription_id,
        field=field,
        include_eligibility=include_eligibility,
        budget=_AuthorizationScanBudget.bounded(),
        as_of=datetime.now(UTC),
    )


def _resolved_effective_role_assignments(
    principal_id: str,
    *,
    subscription_id: str,
    field: str,
    budget: _AuthorizationScanBudget | None = None,
    as_of: datetime | None = None,
) -> list[dict[str, Any]]:
    scan_budget = _AuthorizationScanBudget.bounded() if budget is None else budget
    observed_at = datetime.now(UTC) if as_of is None else as_of.astimezone(UTC)
    documents: list[object] = [
        _effective_role_assignments(
            principal_id,
            subscription_id=subscription_id,
            field=f"{field} for service principal {principal_id}",
            budget=scan_budget,
            as_of=observed_at,
        )
    ]
    for group_id in sorted(_transitive_group_ids(principal_id)):
        documents.append(
            _effective_role_assignments(
                group_id,
                subscription_id=subscription_id,
                field=f"{field} for transitive group {group_id}",
                budget=scan_budget,
                as_of=observed_at,
            )
        )
    return _merge_effective_role_assignment_documents(
        documents,
        field=field,
    )


def _verify_no_broad_effective_assignments(
    principal_ids: set[str],
    *,
    subscription_id: str,
) -> dict[str, list[dict[str, Any]]]:
    assignments_by_principal: dict[str, list[dict[str, Any]]] = {}
    budget = _AuthorizationScanBudget.bounded()
    as_of = datetime.now(UTC)
    for principal_id in sorted(principal_ids):
        assignments = _resolved_effective_role_assignments(
            principal_id,
            subscription_id=subscription_id,
            field=f"effective role assignments for {principal_id}",
            budget=budget,
            as_of=as_of,
        )
        assignments_by_principal[principal_id.casefold()] = assignments
        violations = evaluate_role_assignments(assignments)
        if violations:
            details = "; ".join(f"{item.code}: {item.detail}" for item in violations)
            raise OrchestrationError(f"governed identity has prohibited broad RBAC: {details}")
    return assignments_by_principal


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


def _scope_contains_resource(ancestor: str, resource_scope: str) -> bool:
    normalized_ancestor = ancestor.rstrip("/").casefold() or "/"
    normalized_resource = resource_scope.rstrip("/").casefold() or "/"
    if normalized_ancestor == "/":
        return True
    if normalized_ancestor.startswith("/providers/microsoft.management/managementgroups/"):
        # The atScope() response is authoritative for management-group ancestry.
        return True
    return normalized_resource == normalized_ancestor or normalized_resource.startswith(
        normalized_ancestor + "/"
    )


def _validate_deny_assignment_url(url: str, *, scope: str) -> None:
    if len(url) > 16_384:
        raise OrchestrationError(
            "deny-assignment pagination returned an oversized continuation URL"
        )
    parsed = urlparse(url)
    expected_path = f"{scope.rstrip('/')}/providers/Microsoft.Authorization/denyAssignments"
    query = parse_qs(parsed.query, keep_blank_values=True)
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != ARM_HOST
        or parsed.path.casefold() != expected_path.casefold()
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or query.get("api-version") != [DENY_ASSIGNMENTS_API_VERSION]
        or any(key not in {"api-version", "$filter", "$skiptoken"} for key in query)
        or any(len(values) != 1 for values in query.values())
        or ("$filter" in query and query["$filter"] != ["atScope()"])
    ):
        raise OrchestrationError(
            "deny-assignment pagination returned an untrusted continuation URL"
        )


def _deny_assignments_at_or_above_scope(
    scope: str,
    *,
    subscription_id: str,
) -> list[dict[str, Any]]:
    canonical_scope = _canonical_subscription_resource_id(
        scope,
        subscription_id=subscription_id,
        field="deny-assignment governed scope",
    )
    next_url: str | None = (
        f"https://{ARM_HOST}{canonical_scope}/providers/"
        "Microsoft.Authorization/denyAssignments"
        f"?api-version={DENY_ASSIGNMENTS_API_VERSION}&%24filter=atScope%28%29"
    )
    assignments: dict[str, dict[str, Any]] = {}
    seen_urls: set[str] = set()
    page_number = 0
    while next_url is not None:
        page_number += 1
        if page_number > MAX_DENY_ASSIGNMENT_PAGES:
            raise OrchestrationError("deny-assignment pagination exceeded its page bound")
        _validate_deny_assignment_url(next_url, scope=canonical_scope)
        if next_url in seen_urls:
            raise OrchestrationError("deny-assignment pagination contains a cycle")
        seen_urls.add(next_url)
        page = _mapping(
            _run_json(
                [
                    "az",
                    "rest",
                    "--method",
                    "get",
                    "--url",
                    next_url,
                    "--only-show-errors",
                    "--output",
                    "json",
                ],
                field=f"deny assignments for {canonical_scope} page {page_number}",
            ),
            field=f"deny assignments for {canonical_scope} page {page_number}",
        )
        values = page.get("value")
        if not isinstance(values, list):
            raise OrchestrationError("deny-assignment page must contain a value array")
        for index, raw_assignment in enumerate(values):
            assignment = _mapping(
                raw_assignment,
                field=f"deny-assignment page {page_number} item {index}",
            )
            assignment_id = _string(
                assignment.get("id"),
                field="deny-assignment ID",
            )
            normalized_id = assignment_id.casefold()
            existing = assignments.get(normalized_id)
            if existing is not None and _canonical_json_bytes(existing) != _canonical_json_bytes(
                assignment
            ):
                raise OrchestrationError(
                    "deny-assignment pagination returned conflicting duplicate evidence"
                )
            assignments[normalized_id] = assignment
            if len(assignments) > MAX_DENY_ASSIGNMENTS:
                raise OrchestrationError("deny-assignment evidence exceeds its bounded maximum")
        continuation = page.get("nextLink")
        if continuation is None:
            next_url = None
        elif not isinstance(continuation, str) or not continuation:
            raise OrchestrationError("deny-assignment continuation is invalid")
        else:
            next_url = continuation
    return list(assignments.values())


def _deny_assignment_scope(
    assignment: Mapping[str, object],
) -> str:
    assignment_id = _string(
        assignment.get("id"),
        field="deny-assignment ID",
    )
    marker = "/providers/microsoft.authorization/denyassignments/"
    normalized_id = assignment_id.casefold()
    if marker not in normalized_id:
        raise OrchestrationError("deny-assignment ID has no deny-assignment boundary")
    scope_from_id = assignment_id[: normalized_id.rindex(marker)] or "/"
    properties = _mapping(
        assignment.get("properties"),
        field="deny-assignment properties",
    )
    scope_value = properties.get("scope")
    if scope_value is None:
        return scope_from_id
    scope = _string(scope_value, field="deny-assignment scope")
    if scope.rstrip("/").casefold() != scope_from_id.rstrip("/").casefold():
        raise OrchestrationError("deny-assignment scope does not match its resource identifier")
    return scope


def _deny_principal_ids(
    value: object,
    *,
    field: str,
    allow_all_principals: bool,
) -> set[str]:
    if not isinstance(value, list) or len(value) > MAX_TRANSITIVE_GROUPS + 1:
        raise OrchestrationError(f"{field} must be a bounded array")
    principal_ids: set[str] = set()
    for index, raw_principal in enumerate(value):
        principal = _mapping(
            raw_principal,
            field=f"{field}[{index}]",
        )
        principal_id = _canonical_directory_object_id(
            principal.get("id"),
            field=f"{field}[{index}].id",
        )
        principal_type = _string(
            principal.get("type"),
            field=f"{field}[{index}].type",
        )
        if principal_id == ALL_PRINCIPALS_ID:
            if not allow_all_principals or principal_type.casefold() != "systemdefined":
                raise OrchestrationError(f"{field} contains an invalid All Principals entry")
        elif principal_type.casefold() == "systemdefined":
            raise OrchestrationError(f"{field} contains an invalid system-defined principal")
        if principal_id in principal_ids:
            raise OrchestrationError(f"{field} contains a duplicate principal")
        principal_ids.add(principal_id)
    return principal_ids


def _resource_condition_attributes(scope: str) -> dict[tuple[str, str], str]:
    segments = [segment for segment in scope.split("/") if segment]
    lowered = [segment.casefold() for segment in segments]
    try:
        provider_index = lowered.index("providers")
        namespace = segments[provider_index + 1]
    except (ValueError, IndexError) as exc:
        raise OrchestrationError(
            "deny-condition governed resource scope has no provider boundary"
        ) from exc
    attributes: dict[tuple[str, str], str] = {}
    type_segments: list[str] = []
    index = provider_index + 2
    while index + 1 < len(segments):
        if lowered[index] == "providers":
            if index + 3 >= len(segments):
                raise OrchestrationError(
                    "deny-condition governed resource scope has an incomplete extension path"
                )
            namespace = segments[index + 1]
            type_segments = []
            index += 2
        resource_type = segments[index]
        resource_name = segments[index + 1]
        type_segments.append(resource_type)
        type_path = "/".join((namespace, *type_segments)).casefold()
        attributes[(type_path, "name")] = resource_name
        alias = {
            "registries": "registryname",
            "storageaccounts": "storageaccountname",
            "namespaces": "namespacename",
            "blobservices": "blobservicename",
            "queues": "queuename",
            "containers": "containername",
            "tableservices": "tableservicename",
            "tables": "tablename",
            "vaults": "vaultname",
            "keys": "keyname",
        }.get(resource_type.casefold())
        if alias is not None:
            attributes[(type_path, alias)] = resource_name
        index += 2
    if index != len(segments):
        raise OrchestrationError(
            "deny-condition governed resource scope has an unmatched resource path"
        )
    return attributes


class _DenyConditionParser:
    def __init__(
        self,
        condition: str,
        *,
        action: str,
        scope: str,
        repository_name: str | None,
        suboperation: str | None,
    ) -> None:
        self._condition = condition
        self._position = 0
        self._action = action
        self._suboperation = suboperation
        self._attributes = {
            ("resource", type_path, attribute): value
            for (type_path, attribute), value in _resource_condition_attributes(scope).items()
        }
        if repository_name is not None:
            self._attributes[
                (
                    "request",
                    "microsoft.containerregistry/registries/repositories",
                    "name",
                )
            ] = repository_name

    def parse(self) -> bool:
        result = self._parse_or()
        self._skip_whitespace()
        if self._position != len(self._condition):
            self._fail()
        return result

    def _skip_whitespace(self) -> None:
        while self._position < len(self._condition) and self._condition[self._position].isspace():
            self._position += 1

    def _consume_character(self, character: str) -> bool:
        self._skip_whitespace()
        if self._condition.startswith(character, self._position):
            self._position += len(character)
            return True
        return False

    def _consume_keyword(self, keyword: str) -> bool:
        self._skip_whitespace()
        end = self._position + len(keyword)
        if self._condition[self._position : end].casefold() != keyword.casefold():
            return False
        if end < len(self._condition) and (
            self._condition[end].isalnum() or self._condition[end] == "_"
        ):
            return False
        self._position = end
        return True

    def _parse_or(self) -> bool:
        result = self._parse_and()
        while self._consume_keyword("OR"):
            right = self._parse_and()
            result = result or right
        return result

    def _parse_and(self) -> bool:
        result = self._parse_unary()
        while self._consume_keyword("AND"):
            right = self._parse_unary()
            result = result and right
        return result

    def _parse_unary(self) -> bool:
        if self._consume_character("!"):
            return not self._parse_unary()
        if self._consume_keyword("NOT"):
            return not self._parse_unary()
        if self._consume_character("("):
            result = self._parse_or()
            if not self._consume_character(")"):
                self._fail()
            return result
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        self._skip_whitespace()
        remaining = self._condition[self._position :]
        action_match = re.match(
            r"ActionMatches\s*\{\s*'([^']+)'\s*\}",
            remaining,
            flags=re.IGNORECASE,
        )
        if action_match is not None:
            if "\\" in action_match.group(1):
                self._fail()
            self._position += action_match.end()
            return _azure_permission_pattern_matches(
                action_match.group(1),
                self._action,
            )
        suboperation_match = re.match(
            r"SubOperationMatches\s*\{\s*'([^']+)'\s*\}",
            remaining,
            flags=re.IGNORECASE,
        )
        if suboperation_match is not None:
            if "\\" in suboperation_match.group(1):
                self._fail()
            self._position += suboperation_match.end()
            return (
                self._suboperation is not None
                and self._suboperation.casefold() == suboperation_match.group(1).casefold()
            )
        attribute_match = re.match(
            (
                r"@(Resource|Request)\[([^\]]+)\]\s+"
                r"(StringEqualsIgnoreCase|StringNotEqualsIgnoreCase|"
                r"StringStartsWithIgnoreCase|StringNotStartsWithIgnoreCase)\s+"
                r"'([^']*)'"
            ),
            remaining,
            flags=re.IGNORECASE,
        )
        if attribute_match is None:
            self._fail()
        self._position += attribute_match.end()
        attribute_reference = attribute_match.group(2)
        if ":" not in attribute_reference:
            self._fail()
        resource_type, attribute_name = attribute_reference.rsplit(":", 1)
        actual = self._attributes.get(
            (
                attribute_match.group(1).casefold(),
                resource_type.casefold(),
                attribute_name.casefold(),
            )
        )
        if actual is None:
            raise OrchestrationError(
                "deny-assignment condition evidence is incomplete for a referenced attribute"
            )
        expected = attribute_match.group(4)
        if "\\" in expected:
            self._fail()
        operator = attribute_match.group(3).casefold()
        if operator == "stringequalsignorecase":
            return actual.casefold() == expected.casefold()
        if operator == "stringnotequalsignorecase":
            return actual.casefold() != expected.casefold()
        if operator == "stringstartswithignorecase":
            return actual.casefold().startswith(expected.casefold())
        if operator == "stringnotstartswithignorecase":
            return not actual.casefold().startswith(expected.casefold())
        self._fail()

    def _fail(self) -> Never:
        raise OrchestrationError(
            "deny-assignment condition evidence is incomplete or uses unsupported syntax"
        )


def _deny_condition_applies(
    condition: str,
    *,
    action: str,
    scope: str,
    repository_name: str | None,
    suboperation: str | None,
) -> bool:
    if not condition or len(condition) > 16_384:
        raise OrchestrationError("deny-assignment condition must be a bounded expression")
    return _DenyConditionParser(
        condition,
        action=action,
        scope=scope,
        repository_name=repository_name,
        suboperation=suboperation,
    ).parse()


def _deny_permission_blocks_action(
    permission: Mapping[str, object],
    *,
    action: str,
    is_data_action: bool,
    scope: str,
    repository_name: str | None,
    suboperation: str | None,
    field: str,
) -> bool:
    allowed_fields = {
        "actions",
        "notActions",
        "dataActions",
        "notDataActions",
        "condition",
        "conditionVersion",
    }
    unexpected_fields = set(permission) - allowed_fields
    if unexpected_fields:
        raise OrchestrationError(
            f"{field} contains unsupported fields: {sorted(unexpected_fields)}"
        )

    def permission_set(json_field: str) -> tuple[str, ...]:
        values = permission.get(json_field)
        if not isinstance(values, list) or any(
            not isinstance(item, str) or not item or item != item.strip() or len(item) > 512
            for item in values
        ):
            raise OrchestrationError(f"{field}.{json_field} must be a bounded string array")
        normalized = [item.casefold() for item in values]
        if len(set(normalized)) != len(normalized):
            raise OrchestrationError(f"{field}.{json_field} contains duplicates")
        return tuple(values)

    actions = permission_set("actions")
    not_actions = permission_set("notActions")
    data_actions = permission_set("dataActions")
    not_data_actions = permission_set("notDataActions")
    granted = data_actions if is_data_action else actions
    excluded = not_data_actions if is_data_action else not_actions
    action_is_denied = any(
        _azure_permission_pattern_matches(pattern, action) for pattern in granted
    ) and not any(_azure_permission_pattern_matches(pattern, action) for pattern in excluded)
    if not action_is_denied:
        return False
    condition = permission.get("condition")
    condition_version = permission.get("conditionVersion")
    if condition is None and condition_version is None:
        return True
    if not (isinstance(condition, str) and condition and condition_version == "2.0"):
        raise OrchestrationError(f"{field} condition evidence is incomplete or unsupported")
    return _deny_condition_applies(
        condition,
        action=action,
        scope=scope,
        repository_name=repository_name,
        suboperation=suboperation,
    )


def _deny_assignment_blocks_runtime_action(
    assignment: Mapping[str, object],
    *,
    runtime_action: _RequiredRuntimeAction,
    principal_memberships: set[str],
) -> bool:
    properties = _mapping(
        assignment.get("properties"),
        field="deny-assignment properties",
    )
    assignment_scope = _deny_assignment_scope(assignment)
    if not _scope_contains_resource(assignment_scope, runtime_action.scope):
        raise OrchestrationError(
            "deny-assignment atScope evidence contains an unrelated assignment scope"
        )
    do_not_apply_to_children = properties.get("doNotApplyToChildScopes", False)
    if not isinstance(do_not_apply_to_children, bool):
        raise OrchestrationError("deny-assignment doNotApplyToChildScopes must be boolean")
    if (
        do_not_apply_to_children
        and assignment_scope.rstrip("/").casefold() != runtime_action.scope.rstrip("/").casefold()
    ):
        return False
    principals = _deny_principal_ids(
        properties.get("principals"),
        field="deny-assignment principals",
        allow_all_principals=True,
    )
    exclusions = _deny_principal_ids(
        properties.get("excludePrincipals", []),
        field="deny-assignment exclusions",
        allow_all_principals=False,
    )
    if not principals:
        raise OrchestrationError("deny-assignment principals must not be empty")
    applies_to_principal = ALL_PRINCIPALS_ID in principals or bool(
        principals & principal_memberships
    )
    if not applies_to_principal or bool(exclusions & principal_memberships):
        return False
    effect = properties.get("denyAssignmentEffect", "Enforced")
    if not isinstance(effect, str) or effect.casefold() not in {"enforced", "audit"}:
        raise OrchestrationError("deny-assignment effect is invalid")
    if effect.casefold() == "audit":
        return False
    permissions = properties.get("permissions")
    if not isinstance(permissions, list) or not 1 <= len(permissions) <= 64:
        raise OrchestrationError("deny-assignment permissions must be a bounded non-empty array")
    action_is_denied = any(
        _deny_permission_blocks_action(
            _mapping(
                raw_permission,
                field=f"deny-assignment permission {index}",
            ),
            action=runtime_action.action,
            is_data_action=runtime_action.is_data_action,
            scope=runtime_action.scope,
            repository_name=runtime_action.repository_name,
            suboperation=runtime_action.suboperation,
            field=f"deny-assignment permission {index}",
        )
        for index, raw_permission in enumerate(permissions)
    )
    if not action_is_denied:
        return False
    condition = properties.get("condition")
    condition_version = properties.get("conditionVersion")
    if condition is None and condition_version is None:
        condition_applies = True
    elif isinstance(condition, str) and condition and condition_version == "2.0":
        condition_applies = _deny_condition_applies(
            condition,
            action=runtime_action.action,
            scope=runtime_action.scope,
            repository_name=runtime_action.repository_name,
            suboperation=runtime_action.suboperation,
        )
    else:
        raise OrchestrationError("deny-assignment condition evidence is incomplete or unsupported")
    return condition_applies


def _required_runtime_actions(
    expected_assignments: Sequence[_ExpectedRoleAssignment],
) -> list[_RequiredRuntimeAction]:
    required: list[_RequiredRuntimeAction] = []
    seen: set[tuple[str, str, str, bool, str | None]] = set()
    for expected in expected_assignments:
        role_id = expected.role_definition_id.casefold().rsplit("/", 1)[-1]
        profile = (
            expected.custom_role_permissions
            if expected.custom_role_permissions is not None
            else BUILT_IN_REQUIRED_PERMISSION_PROFILES.get(role_id)
        )
        if profile is None:
            raise OrchestrationError(
                f"{expected.label} has no complete required runtime-action profile"
            )
        for is_data_action, actions in (
            (False, profile.actions),
            (True, profile.data_actions),
        ):
            for action in sorted(actions):
                key = (
                    expected.principal_id.casefold(),
                    expected.scope.casefold(),
                    action.casefold(),
                    is_data_action,
                    expected.repository_name,
                )
                if key in seen:
                    continue
                seen.add(key)
                required.append(
                    _RequiredRuntimeAction(
                        label=expected.label,
                        principal_id=expected.principal_id,
                        scope=expected.scope,
                        action=action,
                        is_data_action=is_data_action,
                        repository_name=expected.repository_name,
                    )
                )
    return required


def _verify_no_applicable_deny_assignments(
    expected_assignments: Sequence[_ExpectedRoleAssignment],
    *,
    subscription_id: str,
) -> None:
    runtime_actions = _required_runtime_actions(expected_assignments)
    memberships_by_principal: dict[str, set[str]] = {}
    deny_assignments_by_scope: dict[str, list[dict[str, Any]]] = {}
    for runtime_action in runtime_actions:
        principal_id = _canonical_directory_object_id(
            runtime_action.principal_id,
            field=f"{runtime_action.label} principal ID",
        )
        principal_memberships = memberships_by_principal.get(principal_id)
        if principal_memberships is None:
            principal_memberships = {
                principal_id,
                *(group_id.casefold() for group_id in _transitive_group_ids(principal_id)),
            }
            memberships_by_principal[principal_id] = principal_memberships
        canonical_scope = _canonical_subscription_resource_id(
            runtime_action.scope,
            subscription_id=subscription_id,
            field=f"{runtime_action.label} governed scope",
        )
        normalized_scope = canonical_scope.casefold()
        deny_assignments = deny_assignments_by_scope.get(normalized_scope)
        if deny_assignments is None:
            deny_assignments = _deny_assignments_at_or_above_scope(
                canonical_scope,
                subscription_id=subscription_id,
            )
            deny_assignments_by_scope[normalized_scope] = deny_assignments
        for assignment in deny_assignments:
            if _deny_assignment_blocks_runtime_action(
                assignment,
                runtime_action=runtime_action,
                principal_memberships=principal_memberships,
            ):
                assignment_id = _string(
                    assignment.get("id"),
                    field="deny-assignment ID",
                )
                raise OrchestrationError(
                    f"{runtime_action.label} required action {runtime_action.action} "
                    f"is denied by {assignment_id}"
                )


def _verify_exact_effective_assignments(
    expected_assignments_by_principal: Mapping[str, set[str]],
    *,
    additional_allowed_assignments_by_principal: Mapping[str, set[str]],
    subscription_id: str,
    effective_assignments_by_principal: Mapping[str, list[dict[str, Any]]] | None = None,
) -> None:
    reviewed_assignments_by_principal: dict[str, set[str]] = {}
    assignment_principals: dict[str, str] = {}
    for source in (
        expected_assignments_by_principal,
        additional_allowed_assignments_by_principal,
    ):
        for principal_id, assignment_ids in source.items():
            normalized_principal_id = principal_id.casefold()
            normalized_assignment_ids = {
                assignment_id.casefold() for assignment_id in assignment_ids
            }
            for assignment_id in normalized_assignment_ids:
                existing_principal = assignment_principals.get(assignment_id)
                if existing_principal is not None and existing_principal != normalized_principal_id:
                    raise OrchestrationError(
                        "one reviewed role assignment is bound to multiple principals"
                    )
                assignment_principals[assignment_id] = normalized_principal_id
            reviewed_assignments_by_principal.setdefault(
                normalized_principal_id,
                set(),
            ).update(normalized_assignment_ids)
    governed_scopes = _governed_rbac_scopes(set(assignment_principals))
    principal_ids = set(reviewed_assignments_by_principal)
    budget = (
        _AuthorizationScanBudget.bounded() if effective_assignments_by_principal is None else None
    )
    as_of = datetime.now(UTC)
    for principal_id in sorted(principal_ids):
        allowed_assignment_ids = reviewed_assignments_by_principal[principal_id]
        assignments = (
            _resolved_effective_role_assignments(
                principal_id,
                subscription_id=subscription_id,
                field=f"exact role assignments for {principal_id}",
                budget=budget,
                as_of=as_of,
            )
            if effective_assignments_by_principal is None
            else effective_assignments_by_principal.get(principal_id.casefold())
        )
        if assignments is None:
            raise OrchestrationError(
                "effective role assignment evidence is missing a governed principal"
            )
        observed_assignment_ids: set[str] = set()
        for index, raw_assignment in enumerate(assignments):
            assignment = _mapping(
                raw_assignment,
                field=f"effective role assignment {index}",
            )
            assignment_id = _string(
                assignment.get("id"),
                field="effective role assignment ID",
            ).casefold()
            observed_assignment_ids.add(assignment_id)
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
        missing_assignment_ids = allowed_assignment_ids - observed_assignment_ids
        if missing_assignment_ids:
            raise OrchestrationError(
                "effective role assignment evidence is incomplete for a governed principal"
            )


def _verify_publisher_effective_assignments(
    *,
    publisher_principal_ids: set[str],
    publisher_assignment_ids_by_principal: Mapping[str, set[str]],
    producer_assignment_ids_by_principal: Mapping[str, set[str]],
    subscription_id: str,
) -> None:
    required_principal_ids = {
        *(principal_id.casefold() for principal_id in publisher_principal_ids),
        *(principal_id.casefold() for principal_id in producer_assignment_ids_by_principal),
    }
    effective_assignments_by_principal = _verify_no_broad_effective_assignments(
        required_principal_ids,
        subscription_id=subscription_id,
    )
    _verify_exact_effective_assignments(
        publisher_assignment_ids_by_principal,
        additional_allowed_assignments_by_principal=(producer_assignment_ids_by_principal),
        subscription_id=subscription_id,
        effective_assignments_by_principal=effective_assignments_by_principal,
    )
    reviewed_assignments_by_principal: dict[str, set[str]] = {}
    for assignments_by_principal in (
        producer_assignment_ids_by_principal,
        publisher_assignment_ids_by_principal,
    ):
        for principal_id, assignment_ids in assignments_by_principal.items():
            reviewed_assignments_by_principal.setdefault(
                principal_id.casefold(),
                set(),
            ).update(assignment_id.casefold() for assignment_id in assignment_ids)
    _verify_exact_pull_capable_assignments(
        required_principal_ids,
        expected_acr_assignments_by_principal=(
            _acr_assignment_ids_by_principal(reviewed_assignments_by_principal)
        ),
        subscription_id=subscription_id,
        field="effective producer/publisher ACR assignments",
        effective_assignments_by_principal=effective_assignments_by_principal,
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
    _require_exact_fields(
        metadata,
        SCALER_METADATA_FIELDS,
        field="job scaler metadata",
    )
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


def _image_pull_evidence_sha256(
    value: Mapping[str, object] | None,
) -> str | None:
    if value is None:
        return None
    return _sha256_bytes(_canonical_json_bytes(value))


def _validated_image_pull_evidence(
    value: object,
    *,
    stage: str,
    subscription_id: str,
) -> dict[str, object] | None:
    if value is None:
        if stage != "foundation":
            raise OrchestrationError(
                f"{stage} handoff is missing digest-pinned image-pull evidence"
            )
        return None
    evidence = _mapping(value, field="image-pull evidence")
    _require_exact_fields(
        evidence,
        frozenset({"schemaVersion", "executions"}),
        field="image-pull evidence",
    )
    if evidence.get("schemaVersion") != IMAGE_PULL_EVIDENCE_SCHEMA_VERSION:
        raise OrchestrationError("image-pull evidence schema is unsupported")
    executions = evidence.get("executions")
    if not isinstance(executions, list):
        raise OrchestrationError("image-pull evidence executions must be an array")
    expected_count = 2 if stage == "live-acceptance" else 1
    if stage == "foundation" or len(executions) != expected_count:
        raise OrchestrationError(f"{stage} image-pull evidence has an unexpected execution count")
    for index, raw_execution in enumerate(executions):
        execution = _mapping(
            raw_execution,
            field=f"image-pull execution {index}",
        )
        _require_exact_fields(
            execution,
            frozenset(
                {
                    "kind",
                    "jobResourceId",
                    "executionName",
                    "image",
                    "containerName",
                    "registryResourceId",
                    "principalId",
                    "registryRoleAssignmentMode",
                    "registryAnonymousPullEnabled",
                    "registryRepositoryName",
                    "registryPullRoleDefinitionId",
                    "registryPullRoleAssignmentResourceId",
                    "registryPullConditionVersion",
                    "registryPullCondition",
                    "status",
                }
            ),
            field=f"image-pull execution {index}",
        )
        kind = _string(
            execution.get("kind"),
            field=f"image-pull execution {index} kind",
        )
        if kind not in {"producer", "publisher"}:
            raise OrchestrationError(f"image-pull execution {index} kind is unsupported")
        _canonical_subscription_resource_id(
            execution.get("jobResourceId"),
            subscription_id=subscription_id,
            field=f"image-pull execution {index} job",
        )
        _string(
            execution.get("executionName"),
            field=f"image-pull execution {index} name",
        )
        image = _digest_pinned_image(
            execution.get("image"),
            field=f"image-pull execution {index} image",
        )
        _string(
            execution.get("containerName"),
            field=f"image-pull execution {index} container",
        )
        registry_resource_id = _canonical_subscription_resource_id(
            execution.get("registryResourceId"),
            subscription_id=subscription_id,
            field=f"image-pull execution {index} registry",
        )
        principal_id = _canonical_directory_object_id(
            execution.get("principalId"),
            field=f"image-pull execution {index} principal ID",
        )
        role_assignment_mode = _acr_role_assignment_mode(
            execution.get("registryRoleAssignmentMode"),
            field=f"image-pull execution {index} registry mode",
        )
        if execution.get("registryAnonymousPullEnabled") is not False:
            raise OrchestrationError(
                f"image-pull execution {index} must prove anonymous pull is disabled"
            )
        expected_role_definition_id = _acr_pull_role_definition_id(
            role_assignment_mode=role_assignment_mode,
            subscription_id=subscription_id,
        )
        _require_subscription_resource_id_equal(
            execution.get("registryPullRoleDefinitionId"),
            expected_role_definition_id,
            subscription_id=subscription_id,
            field=f"image-pull execution {index} role definition",
        )
        _canonical_subscription_resource_id(
            execution.get("registryPullRoleAssignmentResourceId"),
            subscription_id=subscription_id,
            field=f"image-pull execution {index} role assignment",
        )
        _require_subscription_resource_id_equal(
            execution.get("registryPullRoleAssignmentResourceId"),
            _acr_pull_role_assignment_id(
                scope=registry_resource_id,
                principal_id=principal_id,
                role_definition_id=expected_role_definition_id,
                role_assignment_mode=role_assignment_mode,
                repository_name=_acr_repository_name(
                    image,
                    registry_resource_id,
                    field=f"image-pull execution {index} image",
                ),
            ),
            subscription_id=subscription_id,
            field=f"image-pull execution {index} deterministic role assignment",
        )
        repository_name = _acr_repository_name(
            image,
            registry_resource_id,
            field=f"image-pull execution {index} image",
        )
        _require_equal(
            execution.get("registryRepositoryName"),
            repository_name,
            field=f"image-pull execution {index} repository",
        )
        condition_version, condition = _acr_pull_assignment_condition(
            role_assignment_mode=role_assignment_mode,
            repository_name=repository_name,
        )
        _require_equal(
            execution.get("registryPullConditionVersion"),
            condition_version,
            field=f"image-pull execution {index} condition version",
        )
        _require_equal(
            execution.get("registryPullCondition"),
            condition,
            field=f"image-pull execution {index} condition",
        )
        _require_equal(
            execution.get("status"),
            "Succeeded",
            field=f"image-pull execution {index} status",
        )
    if executions != sorted(
        executions,
        key=lambda item: str(item["jobResourceId"]).casefold(),
    ):
        raise OrchestrationError("image-pull evidence executions must be sorted")
    expected_kinds = (
        {
            "producer",
            "publisher",
        }
        if stage == "live-acceptance"
        else {stage}
    )
    if {str(item["kind"]) for item in executions} != expected_kinds:
        raise OrchestrationError(
            f"{stage} image-pull evidence does not contain its exact job kinds"
        )
    return evidence


def _verify_digest_pinned_job_image_pull(
    *,
    job_resource_id: str,
    image: str,
    container_name: str,
    registry_resource_id: str,
    principal_id: str,
    registry_role_assignment_mode: str,
    registry_anonymous_pull_enabled: object,
    registry_pull_role_definition_id: str,
    registry_pull_role_assignment_resource_id: str,
    subscription_id: str,
) -> dict[str, object]:
    job_id = _job_resource_id(job_resource_id, field="image-pull probe job")
    _, resource_group = _resource_subscription_and_group(job_id)
    job_name = _resource_name(job_id)
    expected_image = _digest_pinned_image(image, field="image-pull probe image")
    repository_name = _acr_repository_name(
        expected_image,
        registry_resource_id,
        field="image-pull probe image",
    )
    condition_version, condition = _acr_pull_assignment_condition(
        role_assignment_mode=registry_role_assignment_mode,
        repository_name=repository_name,
    )
    if registry_anonymous_pull_enabled is not False:
        raise OrchestrationError(
            "digest-pinned image-pull probe requires anonymous pull to be disabled"
        )
    last_error: OrchestrationError | None = None
    for attempt in range(1, READBACK_MAX_ATTEMPTS + 1):
        successful_execution_seen = False
        try:
            _verify_live_acr_authentication_required(
                registry_resource_id,
                expected_role_assignment_mode=registry_role_assignment_mode,
                subscription_id=subscription_id,
                field="image-pull probe",
            )
            start = _mapping(
                _run_json(
                    [
                        "az",
                        "containerapp",
                        "job",
                        "start",
                        "--subscription",
                        subscription_id,
                        "--resource-group",
                        resource_group,
                        "--name",
                        job_name,
                        "--container-name",
                        container_name,
                        "--image",
                        expected_image,
                        "--cpu",
                        "1",
                        "--memory",
                        "2Gi",
                        "--command",
                        "/bin/sh",
                        "--args",
                        "-c",
                        "exit 0",
                        "--only-show-errors",
                        "--output",
                        "json",
                    ],
                    field="digest-pinned image-pull probe start",
                ),
                field="digest-pinned image-pull probe start",
            )
            execution_name = _string(
                start.get("name"),
                field="digest-pinned image-pull execution name",
            )
            for poll in range(1, IMAGE_PULL_EXECUTION_POLL_ATTEMPTS + 1):
                execution = _mapping(
                    _run_json(
                        [
                            "az",
                            "containerapp",
                            "job",
                            "execution",
                            "show",
                            "--subscription",
                            subscription_id,
                            "--resource-group",
                            resource_group,
                            "--name",
                            job_name,
                            "--job-execution-name",
                            execution_name,
                            "--only-show-errors",
                            "--output",
                            "json",
                        ],
                        field="digest-pinned image-pull execution",
                    ),
                    field="digest-pinned image-pull execution",
                )
                properties = _mapping(
                    execution.get("properties"),
                    field="digest-pinned image-pull execution properties",
                )
                status = _string(
                    properties.get("status"),
                    field="digest-pinned image-pull execution status",
                )
                if status == "Succeeded":
                    successful_execution_seen = True
                    template = _mapping(
                        properties.get("template"),
                        field="digest-pinned image-pull execution template",
                    )
                    containers = template.get("containers")
                    if not isinstance(containers, list) or len(containers) != 1:
                        raise OrchestrationError(
                            "image-pull execution must contain one exact container"
                        )
                    container = _mapping(
                        containers[0],
                        field="digest-pinned image-pull execution container",
                    )
                    _require_equal(
                        container.get("name"),
                        container_name,
                        field="image-pull execution container name",
                    )
                    _require_equal(
                        container.get("image"),
                        expected_image,
                        field="image-pull execution image",
                    )
                    _require_equal(
                        container.get("command"),
                        ["/bin/sh"],
                        field="image-pull execution command",
                    )
                    _require_equal(
                        container.get("args"),
                        ["-c", "exit 0"],
                        field="image-pull execution arguments",
                    )
                    _verify_live_acr_authentication_required(
                        registry_resource_id,
                        expected_role_assignment_mode=registry_role_assignment_mode,
                        subscription_id=subscription_id,
                        field="successful image-pull probe",
                    )
                    return {
                        "jobResourceId": job_id,
                        "executionName": execution_name,
                        "image": expected_image,
                        "containerName": container_name,
                        "registryResourceId": registry_resource_id,
                        "principalId": principal_id,
                        "registryRoleAssignmentMode": registry_role_assignment_mode,
                        "registryAnonymousPullEnabled": False,
                        "registryRepositoryName": repository_name,
                        "registryPullRoleDefinitionId": registry_pull_role_definition_id,
                        "registryPullRoleAssignmentResourceId": (
                            registry_pull_role_assignment_resource_id
                        ),
                        "registryPullConditionVersion": condition_version,
                        "registryPullCondition": condition,
                        "status": "Succeeded",
                    }
                if status == "Failed":
                    raise OrchestrationError("digest-pinned image-pull execution failed")
                if poll < IMAGE_PULL_EXECUTION_POLL_ATTEMPTS:
                    time.sleep(READBACK_RETRY_SECONDS)
            raise OrchestrationError(
                "digest-pinned image-pull execution did not reach a terminal state"
            )
        except TerminalEvidenceError:
            raise
        except _CommandTimeout as exc:
            if successful_execution_seen or exc.outcome_unknown:
                raise TerminalEvidenceError(
                    "digest-pinned image-pull evidence timed out after a successful "
                    "or outcome-unknown mutation"
                ) from exc
            last_error = exc
            if attempt < READBACK_MAX_ATTEMPTS:
                time.sleep(READBACK_RETRY_SECONDS)
        except OrchestrationError as exc:
            if successful_execution_seen:
                raise TerminalEvidenceError(
                    "successful digest-pinned image-pull execution failed terminal "
                    f"evidence validation: {exc}"
                ) from exc
            last_error = exc
            if attempt < READBACK_MAX_ATTEMPTS:
                time.sleep(READBACK_RETRY_SECONDS)
    if last_error is None:
        raise OrchestrationError("digest-pinned image-pull probe failed without an error")
    raise OrchestrationError(
        f"digest-pinned image pull did not succeed after bounded RBAC propagation: {last_error}"
    ) from last_error


def _image_pull_probe_from_outputs(
    outputs: Mapping[str, object],
    *,
    kind: str,
    principal_id: str,
    subscription_id: str,
) -> dict[str, object]:
    if kind == "producer":
        return {
            "kind": kind,
            **_verify_digest_pinned_job_image_pull(
                job_resource_id=_string(
                    outputs.get("producerJobResourceId"),
                    field="producer image-pull job",
                ),
                image=_string(outputs.get("producerImage"), field="producer image"),
                container_name="wc027-enrichment-feed-producer",
                registry_resource_id=_string(
                    outputs.get("registryResourceId"),
                    field="producer registry resource ID",
                ),
                principal_id=principal_id,
                registry_role_assignment_mode=_string(
                    outputs.get("registryRoleAssignmentMode"),
                    field="producer registry role-assignment mode",
                ),
                registry_anonymous_pull_enabled=outputs.get("registryAnonymousPullEnabled"),
                registry_pull_role_definition_id=_string(
                    outputs.get("registryPullRoleDefinitionId"),
                    field="producer registry pull role definition",
                ),
                registry_pull_role_assignment_resource_id=_string(
                    outputs.get("registryPullRoleAssignmentResourceId"),
                    field="producer registry pull role assignment",
                ),
                subscription_id=subscription_id,
            ),
        }
    if kind == "publisher":
        return {
            "kind": kind,
            **_verify_digest_pinned_job_image_pull(
                job_resource_id=_string(
                    outputs.get("publisherJobResourceId"),
                    field="publisher image-pull job",
                ),
                image=_string(outputs.get("publisherImage"), field="publisher image"),
                container_name="wc027-guidance-authority-publisher",
                registry_resource_id=_string(
                    outputs.get("registryResourceId"),
                    field="publisher registry resource ID",
                ),
                principal_id=principal_id,
                registry_role_assignment_mode=_string(
                    outputs.get("registryRoleAssignmentMode"),
                    field="publisher registry role-assignment mode",
                ),
                registry_anonymous_pull_enabled=outputs.get("registryAnonymousPullEnabled"),
                registry_pull_role_definition_id=_string(
                    outputs.get("registryPullRoleDefinitionId"),
                    field="publisher registry pull role definition",
                ),
                registry_pull_role_assignment_resource_id=_string(
                    outputs.get("registryPullRoleAssignmentResourceId"),
                    field="publisher registry pull role assignment",
                ),
                subscription_id=subscription_id,
            ),
        }
    raise OrchestrationError(f"unsupported image-pull probe kind: {kind}")


def _expected_image_pull_binding(
    outputs: Mapping[str, object],
    *,
    kind: str,
    principal_id: str,
) -> dict[str, object]:
    prefix = "producer" if kind == "producer" else "publisher"
    return {
        "kind": kind,
        "jobResourceId": outputs[f"{prefix}JobResourceId"],
        "image": outputs[f"{prefix}Image"],
        "containerName": (
            "wc027-enrichment-feed-producer"
            if kind == "producer"
            else "wc027-guidance-authority-publisher"
        ),
        "registryResourceId": outputs["registryResourceId"],
        "principalId": principal_id,
        "registryRoleAssignmentMode": outputs["registryRoleAssignmentMode"],
        "registryAnonymousPullEnabled": outputs["registryAnonymousPullEnabled"],
        "registryRepositoryName": outputs["registryRepositoryName"],
        "registryPullRoleDefinitionId": outputs["registryPullRoleDefinitionId"],
        "registryPullRoleAssignmentResourceId": outputs["registryPullRoleAssignmentResourceId"],
        "registryPullConditionVersion": outputs["registryPullConditionVersion"],
        "registryPullCondition": outputs["registryPullCondition"],
        "status": "Succeeded",
    }


def _verify_image_pull_evidence_matches_outputs(
    evidence: Mapping[str, object],
    *,
    kind: str,
    outputs: Mapping[str, object],
    principal_id: str,
) -> None:
    executions = evidence.get("executions")
    if not isinstance(executions, list):
        raise OrchestrationError("image-pull evidence executions must be an array")
    matches = [
        _mapping(item, field=f"{kind} image-pull evidence")
        for item in executions
        if isinstance(item, dict) and item.get("kind") == kind
    ]
    if len(matches) != 1:
        raise OrchestrationError(f"image-pull evidence must contain one exact {kind} execution")
    actual = dict(matches[0])
    actual.pop("executionName", None)
    if actual != _expected_image_pull_binding(
        outputs,
        kind=kind,
        principal_id=principal_id,
    ):
        raise OrchestrationError(f"{kind} image-pull evidence does not match reviewed outputs")


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


def _base64url_uint(value: object, *, field: str) -> int:
    encoded = _string(value, field=field)
    if "=" in encoded or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in encoded
    ):
        raise OrchestrationError(f"{field} must be canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, binascii.Error) as exc:
        raise OrchestrationError(f"{field} is invalid base64url") from exc
    if (
        not decoded
        or decoded[0] == 0
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != encoded
    ):
        raise OrchestrationError(f"{field} must be a canonical unsigned integer")
    return int.from_bytes(decoded, "big")


def _verify_key(
    versioned_key_uri: str,
    *,
    subscription_id: str,
    required_operations: frozenset[str],
    expected_fingerprint: str,
    expected_key_size_bits: int = REVIEWED_RSA_KEY_SIZE_BITS,
) -> None:
    parsed = urlparse(versioned_key_uri)
    vault_name = parsed.netloc.split(".", 1)[0]
    key_name = _key_name(versioned_key_uri)
    if (
        parsed.scheme != "https"
        or not vault_name
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise OrchestrationError(
            f"expected an exact versioned Key Vault key URI: {versioned_key_uri}"
        )
    document = _mapping(
        _run_json(
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
    _require_equal(
        key.get("kid"),
        versioned_key_uri,
        field="Key Vault key version",
    )
    _require_equal(key.get("kty"), "RSA", field="Key Vault key type")
    modulus = _base64url_uint(key.get("n"), field="Key Vault RSA modulus")
    exponent = _base64url_uint(key.get("e"), field="Key Vault RSA exponent")
    try:
        public_key = rsa.RSAPublicNumbers(
            exponent,
            modulus,
        ).public_key()
    except ValueError as exc:
        raise OrchestrationError("Key Vault RSA public material is invalid") from exc
    if public_key.key_size < MINIMUM_RSA_KEY_SIZE_BITS:
        raise OrchestrationError("Key Vault RSA key is below the minimum size")
    if public_key.key_size != expected_key_size_bits:
        raise OrchestrationError("Key Vault RSA key size does not match the reviewed size")
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual_fingerprint = f"{SHA256_PREFIX}{hashlib.sha256(spki).hexdigest()}"
    _require_equal(
        actual_fingerprint,
        _sha256_digest(
            expected_fingerprint,
            field="configured key fingerprint",
        ),
        field="Key Vault public key fingerprint",
    )
    key_operations = key.get("keyOps")
    if not isinstance(key_operations, list) or any(
        not isinstance(item, str) or not item for item in key_operations
    ):
        raise OrchestrationError("Key Vault key operations are absent")
    normalized_operations = [item.casefold() for item in key_operations]
    if len(set(normalized_operations)) != len(normalized_operations):
        raise OrchestrationError("Key Vault key operations must be distinct")
    actual_operations = frozenset(normalized_operations)
    if actual_operations != REVIEWED_RSA_KEY_OPERATIONS or not required_operations.issubset(
        actual_operations
    ):
        raise OrchestrationError(
            f"Key Vault key operations do not match reviewed operations "
            f"{sorted(REVIEWED_RSA_KEY_OPERATIONS)}: "
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
        )
        != versioned_key_uri
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
    for uri_name, fingerprint_name in (
        (
            "incidentSigningKeyUriWithVersion",
            "incidentSigningKeyFingerprint",
        ),
        (
            "incidentFeedV2SigningKeyUriWithVersion",
            "feedSigningKeyFingerprint",
        ),
        (
            "incidentReportSigningKeyUriWithVersion",
            "reportSigningKeyFingerprint",
        ),
        (
            "incidentGuidanceSigningKeyUriWithVersion",
            "guidanceSigningKeyFingerprint",
        ),
        (
            "incidentEnrichmentSigningKeyUriWithVersion",
            "enrichmentSigningKeyFingerprint",
        ),
        (
            "incidentNotificationSigningKeyUriWithVersion",
            "notificationSigningKeyFingerprint",
        ),
    ):
        key_uri = _string(outputs[uri_name], field=uri_name)
        _verify_latest_key_uri(
            key_uri,
            subscription_id=subscription_id,
        )
        _verify_key(
            key_uri,
            subscription_id=subscription_id,
            required_operations=frozenset({"sign", "verify"}),
            expected_fingerprint=_sha256_digest(
                outputs[fingerprint_name],
                field=fingerprint_name,
            ),
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
    _verify_wc013_acr_pull_assignments(
        outputs["wc013AcrPullAssignments"],
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
    if current_uri != expected_uri:
        raise OrchestrationError(
            "publisher binding key version does not match the producer trust binding"
        )


def _verify_producer_resources(
    outputs: Mapping[str, object],
    *,
    foundation: Mapping[str, object],
    effective_parameters: Mapping[str, Mapping[str, object]],
    subscription_id: str,
    approved_transitions: object | None = None,
    require_transition_revoked: bool = True,
    handled_transition_ids: set[str] | None = None,
) -> dict[str, set[str]]:
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
    _verify_acr_pull_binding(
        validated_outputs,
        effective_parameters=effective_parameters,
        principal_id=_principal_for_identity(
            identity_principal_ids,
            broker_identity_resource_id,
            field="producer broker identity",
        ),
        subscription_id=subscription_id,
        field="producer",
    )
    _verify_legacy_crypto_user_migration(
        _producer_legacy_crypto_user_assignments(
            configuration=configuration,
            foundation_values=foundation_values,
            principal_ids_by_identity=identity_principal_ids,
            subscription_id=subscription_id,
        ),
        set(),
        migration_state="absent",
        subscription_id=subscription_id,
    )
    expected_assignments = _producer_expected_rbac_assignments(
        binding,
        configuration=configuration,
        outputs=validated_outputs,
        foundation_values=foundation_values,
        effective_parameters=effective_parameters,
        principal_ids_by_identity=identity_principal_ids,
        subscription_id=subscription_id,
    )
    prospective_publisher_sender = _prospective_publisher_sender_assignment(
        configuration=configuration,
        outputs=validated_outputs,
        principal_ids_by_identity=identity_principal_ids,
        subscription_id=subscription_id,
    )
    prospective_expected = next(iter(prospective_publisher_sender.values()))
    trigger_queue_scope = prospective_expected.scope.casefold()
    trigger_expectations = {
        **{
            assignment_id: expected
            for assignment_id, expected in expected_assignments.items()
            if expected.scope.casefold() == trigger_queue_scope
        },
        **prospective_publisher_sender,
    }
    non_trigger_expectations = {
        assignment_id: expected
        for assignment_id, expected in expected_assignments.items()
        if expected.scope.casefold() != trigger_queue_scope
    }
    reviewed_transitions = [] if approved_transitions is None else approved_transitions
    non_trigger_transitions = _rotation_transitions_for_expected_assignments(
        reviewed_transitions,
        expected_assignments=non_trigger_expectations,
        subscription_id=subscription_id,
    )
    trigger_transitions = _rotation_transitions_for_expected_assignments(
        reviewed_transitions,
        expected_assignments=trigger_expectations,
        subscription_id=subscription_id,
    )
    _record_handled_rotation_transitions(
        handled_transition_ids,
        non_trigger_transitions,
    )
    _record_handled_rotation_transitions(
        handled_transition_ids,
        trigger_transitions,
    )
    _verify_reviewed_rotation_transitions(
        non_trigger_transitions,
        current_principal_ids=allowed_principal_ids,
        transition_state=("absent" if require_transition_revoked else "present"),
        subscription_id=subscription_id,
        current_expected_assignments=non_trigger_expectations,
    )
    assignment_ids_by_principal = _verify_rbac_resources(
        binding,
        expected_assignments=expected_assignments,
        subscription_id=subscription_id,
    )
    prospective_assignment_ids_by_principal = _verify_trigger_queue_assignment_set(
        producer_expected_assignments=expected_assignments,
        prospective_publisher_assignments=prospective_publisher_sender,
        approved_transitions=trigger_transitions,
        require_transition_revoked=require_transition_revoked,
        subscription_id=subscription_id,
    )
    effective_assignments_by_principal = _verify_no_broad_effective_assignments(
        allowed_principal_ids,
        subscription_id=subscription_id,
    )
    _verify_exact_effective_assignments(
        assignment_ids_by_principal,
        additional_allowed_assignments_by_principal=(prospective_assignment_ids_by_principal),
        subscription_id=subscription_id,
        effective_assignments_by_principal=effective_assignments_by_principal,
    )
    _verify_exact_pull_capable_assignments(
        allowed_principal_ids,
        expected_acr_assignments_by_principal=(
            _acr_assignment_ids_by_principal(assignment_ids_by_principal)
        ),
        subscription_id=subscription_id,
        field="effective producer ACR assignments",
        effective_assignments_by_principal=effective_assignments_by_principal,
    )
    _verify_no_applicable_deny_assignments(
        [
            *expected_assignments.values(),
            *prospective_publisher_sender.values(),
        ],
        subscription_id=subscription_id,
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
        expected_fingerprint=_sha256_digest(
            collector_key.get("keyFingerprint"),
            field="collector key fingerprint",
        ),
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
            expected_fingerprint=_sha256_digest(
                configured_key.get("keyFingerprint"),
                field=f"producer key {name} fingerprint",
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
    return assignment_ids_by_principal


def _verify_publisher_resources(
    outputs: Mapping[str, object],
    *,
    producer: Mapping[str, object],
    effective_parameters: Mapping[str, Mapping[str, object]],
    producer_assignment_ids_by_principal: Mapping[str, set[str]],
    subscription_id: str,
    approved_transitions: object | None = None,
    require_transition_revoked: bool = True,
    handled_transition_ids: set[str] | None = None,
) -> dict[str, set[str]]:
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
    _verify_acr_pull_binding(
        validated_outputs,
        effective_parameters=effective_parameters,
        principal_id=_principal_for_identity(
            identity_principal_ids,
            broker_identity_resource_id,
            field="publisher broker identity",
        ),
        subscription_id=subscription_id,
        field="publisher",
    )
    expected_assignments = _publisher_expected_rbac_assignments(
        binding,
        configuration=configuration,
        outputs=validated_outputs,
        effective_parameters=effective_parameters,
        principal_ids_by_identity=identity_principal_ids,
        subscription_id=subscription_id,
    )
    reviewed_transitions = [] if approved_transitions is None else approved_transitions
    scoped_transitions = _rotation_transitions_for_expected_assignments(
        reviewed_transitions,
        expected_assignments=expected_assignments,
        subscription_id=subscription_id,
    )
    _record_handled_rotation_transitions(
        handled_transition_ids,
        scoped_transitions,
    )
    _verify_reviewed_rotation_transitions(
        scoped_transitions,
        current_principal_ids={
            *allowed_principal_ids,
            *(principal_id.casefold() for principal_id in producer_assignment_ids_by_principal),
        },
        transition_state=("absent" if require_transition_revoked else "present"),
        subscription_id=subscription_id,
        current_expected_assignments=expected_assignments,
    )
    assignment_ids_by_principal = _verify_rbac_resources(
        binding,
        expected_assignments=expected_assignments,
        subscription_id=subscription_id,
    )
    _verify_publisher_effective_assignments(
        publisher_principal_ids=allowed_principal_ids,
        publisher_assignment_ids_by_principal=assignment_ids_by_principal,
        producer_assignment_ids_by_principal=producer_assignment_ids_by_principal,
        subscription_id=subscription_id,
    )
    _verify_no_applicable_deny_assignments(
        list(expected_assignments.values()),
        subscription_id=subscription_id,
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
            expected_fingerprint=_sha256_digest(
                key.get("keyFingerprint"),
                field=f"{key_name}.keyFingerprint",
            ),
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
    return assignment_ids_by_principal


def _parameter_bindings(
    stage: str,
    effective_parameters: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    if stage == "foundation":
        return {"foundationParametersSha256": _foundation_parameter_digest(effective_parameters)}
    names = {
        "producer": (
            "brokerIdentityPrincipalId",
            "correlationSourceStorageAccountResourceId",
            "correlationBindingKeyResourceId",
            "changeKeyResourceId",
            "feedV2ReaderIdentityResourceId",
            "guidanceBindingKeyResourceId",
            "managedEnvironmentResourceId",
            "monitoringCollectorKeyResourceId",
            "monitoringIntentKeyResourceId",
            "registryResourceId",
            "registryRoleAssignmentMode",
            "serviceBusNamespaceName",
            "triggerSubmitterIdentityResourceIds",
        ),
        "publisher": (
            "authorityStorageAccountResourceId",
            "activationStorageAccountResourceId",
            "brokerIdentityPrincipalId",
            "bindingTrustReaderIdentityResourceId",
            "bindingKeyResourceId",
            "managedEnvironmentResourceId",
            "registryResourceId",
            "registryRoleAssignmentMode",
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
            "wc027OrchestrationFoundation": dict(wc027_foundation),
            "wc013AcrPullAssignments": approved_configuration.get("wc013AcrPullAssignments"),
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
            "wc013AcrPullAssignments": approved_configuration.get("wc013AcrPullAssignments"),
        }
        _validate_live_acceptance_handoff_outputs(projected)
        return projected
    raise OrchestrationError(f"unsupported deployment stage: {stage}")


def _bindings_as_parameters(
    bindings: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    return {name: {"value": value} for name, value in bindings.items()}


def _authority_container_resource_id_for_stage(
    *,
    stage: str,
    effective_parameters: Mapping[str, Mapping[str, object]],
    verified_predecessors: Mapping[str, Mapping[str, object]],
) -> str | None:
    if stage == "foundation":
        return None
    if stage == "producer":
        storage_account_id = _azure_resource_id(
            _parameter_value(
                effective_parameters,
                "correlationSourceStorageAccountResourceId",
            ),
            field="producer authority storage account",
        )
        container_name = _string(
            _parameter_value(
                effective_parameters,
                "guidanceAuthoritySourceContainerName",
            ),
            field="producer authority container name",
        )
        return f"{storage_account_id}/blobServices/default/containers/{container_name}"
    predecessor_name = "producer" if stage == "publisher" else "publisher"
    predecessor = _mapping(
        verified_predecessors[predecessor_name].get("handoff"),
        field=f"verified {predecessor_name} handoff",
    )
    outputs = (
        _producer_outputs(predecessor) if stage == "publisher" else _publisher_outputs(predecessor)
    )
    output_name = (
        "guidanceAuthoritySourceContainerResourceId"
        if stage == "publisher"
        else "authorityContainerResourceId"
    )
    return _azure_resource_id(
        outputs[output_name],
        field=f"{stage} authority container",
    )


def _verify_planned_authority_blob_inventory(
    *,
    stage: str,
    current_inventory: Mapping[str, object] | None,
    trusted_inventory: Mapping[str, object] | None,
) -> None:
    if stage == "foundation":
        if current_inventory is not None or trusted_inventory is not None:
            raise OrchestrationError("foundation stage cannot contain authority Blob inventory")
        return
    if current_inventory is None:
        raise OrchestrationError("authority Blob inventory is required for WC-027 planning")
    if trusted_inventory is not None:
        _verify_authority_checkpoint_successor(
            previous_inventory=trusted_inventory,
            current_inventory=current_inventory,
            allow_container_creation=False,
        )
        return
    if stage != "producer":
        raise OrchestrationError(
            "authority Blob inventory requires independently reviewed predecessor evidence"
        )
    if (
        current_inventory.get("containerExists") is not False
        or current_inventory.get("previousCheckpointSha256") is not None
        or current_inventory.get("currentBlobs") != []
        or current_inventory.get("versions") != []
    ):
        raise OrchestrationError(
            "fresh producer planning requires the authority container to be absent; "
            "every pre-existing container requires a reviewed prior producer receipt and handoff"
        )


def _validate_resume_succeeded_deployment(
    *,
    requested: bool,
    stage: str,
    reviewed_authority_inventory: Mapping[str, object] | None,
    trusted_prior_inventory: Mapping[str, object] | None,
) -> None:
    if not requested:
        return
    if not (
        stage == "producer"
        and reviewed_authority_inventory is not None
        and reviewed_authority_inventory.get("containerExists") is False
        and reviewed_authority_inventory.get("previousCheckpointSha256") is None
        and trusted_prior_inventory is None
    ):
        raise OrchestrationError(
            "succeeded-deployment resume is limited to a reviewed fresh producer bootstrap plan"
        )


def _verify_authority_checkpoint_successor(
    *,
    previous_inventory: Mapping[str, object],
    current_inventory: Mapping[str, object],
    allow_container_creation: bool,
) -> None:
    previous_digest = _authority_checkpoint_sha256(previous_inventory)
    if current_inventory.get("previousCheckpointSha256") != previous_digest:
        raise OrchestrationError(
            "authority Blob checkpoint does not reference its exact reviewed predecessor"
        )
    if current_inventory.get("containerResourceId") != previous_inventory.get(
        "containerResourceId"
    ):
        raise OrchestrationError("authority Blob checkpoint changed its governed container")
    if (
        previous_inventory.get("containerExists") is True
        and current_inventory.get("containerExists") is not True
    ):
        raise OrchestrationError("authority Blob checkpoint removed the governed container")
    if (
        previous_inventory.get("containerExists") is False
        and current_inventory.get("containerExists") is True
        and not allow_container_creation
    ):
        raise OrchestrationError(
            "authority Blob checkpoint created a container outside the reviewed bootstrap"
        )

    _verify_authority_checkpoint_contains(
        required_inventory=previous_inventory,
        current_inventory=current_inventory,
    )


def _verify_authority_checkpoint_contains(
    *,
    required_inventory: Mapping[str, object],
    current_inventory: Mapping[str, object],
) -> None:
    if current_inventory.get("containerResourceId") != required_inventory.get(
        "containerResourceId"
    ):
        raise OrchestrationError("authority Blob checkpoint changed its governed container")
    if (
        required_inventory.get("containerExists") is True
        and current_inventory.get("containerExists") is not True
    ):
        raise OrchestrationError("authority Blob checkpoint removed a required container")
    required_versions = {
        (str(item["name"]), str(item["versionId"])): item for item in required_inventory["versions"]
    }
    current_versions = {
        (str(item["name"]), str(item["versionId"])): item for item in current_inventory["versions"]
    }
    if not set(required_versions).issubset(current_versions):
        raise OrchestrationError("authority Blob checkpoint removed a reviewed immutable version")
    for key, required in required_versions.items():
        if current_versions[key] != required:
            raise OrchestrationError(
                "authority Blob checkpoint changed reviewed version bytes or metadata"
            )


def _verify_post_deployment_authority_inventory(
    *,
    stage: str,
    reviewed_inventory: Mapping[str, object] | None,
    current_inventory: Mapping[str, object] | None,
) -> None:
    if stage == "foundation":
        if reviewed_inventory is not None or current_inventory is not None:
            raise OrchestrationError("foundation stage cannot contain authority Blob inventory")
        return
    if reviewed_inventory is None or current_inventory is None:
        raise OrchestrationError("authority Blob inventory is required for WC-027 readiness")
    fresh_producer = stage == "producer" and reviewed_inventory.get("containerExists") is False
    _verify_authority_checkpoint_successor(
        previous_inventory=reviewed_inventory,
        current_inventory=current_inventory,
        allow_container_creation=fresh_producer,
    )
    if fresh_producer and (
        current_inventory.get("containerExists") is not True
        or current_inventory.get("currentBlobs") != []
        or current_inventory.get("versions") != []
    ):
        raise OrchestrationError(
            "fresh authority container must contain zero current and versioned blobs"
        )


def _predecessor_authority_blob_inventory(
    *,
    stage: str,
    verified_predecessors: Mapping[str, Mapping[str, object]],
    subscription_id: str,
) -> dict[str, object] | None:
    if stage not in {"publisher", "live-acceptance"}:
        return None
    predecessor_name = "producer" if stage == "publisher" else "publisher"
    handoff = _mapping(
        verified_predecessors[predecessor_name].get("handoff"),
        field=f"verified {predecessor_name} handoff",
    )
    inventory = _validated_authority_blob_inventory(
        handoff.get("authorityBlobInventory"),
        subscription_id=subscription_id,
    )
    if inventory is None:
        raise OrchestrationError(f"{predecessor_name} handoff is missing authority Blob inventory")
    if handoff.get("authorityBlobInventorySha256") != _authority_checkpoint_sha256(inventory):
        raise OrchestrationError(
            f"{predecessor_name} handoff authority checkpoint digest does not match"
        )
    return inventory


def _required_authority_checkpoint_sha256s(
    *,
    stage: str,
    predecessor_inventory: Mapping[str, object] | None,
    prior_stage_inventory: Mapping[str, object] | None,
) -> dict[str, str]:
    required: dict[str, str] = {}
    if predecessor_inventory is not None:
        predecessor_name = "producer" if stage == "publisher" else "publisher"
        digest = _authority_checkpoint_sha256(predecessor_inventory)
        if digest is None:
            raise OrchestrationError(
                "predecessor authority checkpoint digest unexpectedly vanished"
            )
        required[predecessor_name] = digest
    if prior_stage_inventory is not None:
        digest = _authority_checkpoint_sha256(prior_stage_inventory)
        if digest is None:
            raise OrchestrationError(
                "prior-stage authority checkpoint digest unexpectedly vanished"
            )
        required["priorStage"] = digest
    return {name: required[name] for name in sorted(required)}


def _verify_live_dependencies(
    *,
    foundation: Mapping[str, object],
    producer: Mapping[str, object],
    publisher: Mapping[str, object],
    subscription_id: str,
    rotation_transitions: object | None = None,
) -> None:
    reviewed_transitions = [] if rotation_transitions is None else rotation_transitions
    handled_transition_ids: set[str] = set()
    _verify_foundation_resources(foundation, subscription_id=subscription_id)
    producer_assignment_ids_by_principal = _verify_producer_resources(
        _mapping(producer["outputs"], field="producer outputs"),
        foundation=foundation,
        effective_parameters=_bindings_as_parameters(_handoff_bindings(producer)),
        subscription_id=subscription_id,
        approved_transitions=reviewed_transitions,
        require_transition_revoked=True,
        handled_transition_ids=handled_transition_ids,
    )
    _verify_publisher_resources(
        _mapping(publisher["outputs"], field="publisher outputs"),
        producer=producer,
        effective_parameters=_bindings_as_parameters(_handoff_bindings(publisher)),
        producer_assignment_ids_by_principal=producer_assignment_ids_by_principal,
        subscription_id=subscription_id,
        approved_transitions=reviewed_transitions,
        require_transition_revoked=True,
        handled_transition_ids=handled_transition_ids,
    )
    _verify_unmatched_rotation_transitions_absent(
        reviewed_transitions,
        handled_transition_ids=handled_transition_ids,
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
    producer_readback, _ = _readiness_sections(outputs)
    subscription_id, _ = _resource_subscription_and_group(
        _job_resource_id(
            producer_readback.get("jobResourceId"),
            field="live-acceptance producer job",
        )
    )
    _validated_wc013_acr_pull_assignments(
        outputs.get("wc013AcrPullAssignments"),
        subscription_id=subscription_id,
    )


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


def _verify_deployed_stage_state(
    *,
    stage: str,
    outputs: dict[str, Any],
    foundation: Mapping[str, object] | None,
    producer: Mapping[str, object] | None,
    publisher: Mapping[str, object] | None,
    effective_parameters: Mapping[str, Mapping[str, object]],
    reviewed_transitions: object,
    legacy_acr_pull_migrations: object,
    authority_container_id: str | None,
    reviewed_authority_inventory: Mapping[str, object] | None,
    subscription_id: str,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    handled_transition_ids: set[str] = set()
    image_pull_executions: list[dict[str, object]] = []
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
    _verify_legacy_acr_pull_migration(
        legacy_acr_pull_migrations,
        migration_state="absent",
        stage=stage,
        effective_parameters=effective_parameters,
        subscription_id=subscription_id,
        allow_reviewed_assignment_scopes=True,
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
            approved_transitions=reviewed_transitions,
            require_transition_revoked=True,
            handled_transition_ids=handled_transition_ids,
        )
        image_pull_executions.append(
            _image_pull_probe_from_outputs(
                outputs,
                kind="producer",
                principal_id=_string(
                    _parameter_value(
                        effective_parameters,
                        "brokerIdentityPrincipalId",
                    ),
                    field="producer broker principal ID",
                ),
                subscription_id=subscription_id,
            )
        )
    elif stage == "live-acceptance":
        if foundation is None or producer is None or publisher is None:
            raise OrchestrationError("live-acceptance plan lost required handoffs")
        _verify_live_dependencies(
            foundation=foundation,
            producer=producer,
            publisher=publisher,
            subscription_id=subscription_id,
            rotation_transitions=reviewed_transitions,
        )
        _verify_wc013_acr_pull_assignments(
            outputs["wc013AcrPullAssignments"],
            subscription_id=subscription_id,
        )
        image_pull_executions.extend(
            [
                _image_pull_probe_from_outputs(
                    _mapping(producer["outputs"], field="producer outputs"),
                    kind="producer",
                    principal_id=_string(
                        _handoff_bindings(producer).get("brokerIdentityPrincipalId"),
                        field="producer broker principal ID",
                    ),
                    subscription_id=subscription_id,
                ),
                _image_pull_probe_from_outputs(
                    _mapping(publisher["outputs"], field="publisher outputs"),
                    kind="publisher",
                    principal_id=_string(
                        _handoff_bindings(publisher).get("brokerIdentityPrincipalId"),
                        field="publisher broker principal ID",
                    ),
                    subscription_id=subscription_id,
                ),
            ]
        )
    elif stage == "publisher":
        if foundation is None or producer is None:
            raise OrchestrationError("publisher plan lost required handoffs")
        producer_assignment_ids_by_principal = _verify_producer_resources(
            _mapping(producer["outputs"], field="producer outputs"),
            foundation=foundation,
            effective_parameters=_bindings_as_parameters(_handoff_bindings(producer)),
            subscription_id=subscription_id,
            approved_transitions=reviewed_transitions,
            require_transition_revoked=True,
            handled_transition_ids=handled_transition_ids,
        )
        _verify_publisher_resources(
            outputs,
            producer=producer,
            effective_parameters=effective_parameters,
            producer_assignment_ids_by_principal=producer_assignment_ids_by_principal,
            subscription_id=subscription_id,
            approved_transitions=reviewed_transitions,
            require_transition_revoked=True,
            handled_transition_ids=handled_transition_ids,
        )
        image_pull_executions.append(
            _image_pull_probe_from_outputs(
                outputs,
                kind="publisher",
                principal_id=_string(
                    _parameter_value(
                        effective_parameters,
                        "brokerIdentityPrincipalId",
                    ),
                    field="publisher broker principal ID",
                ),
                subscription_id=subscription_id,
            )
        )
    if stage in {"producer", "publisher"}:
        _verify_unmatched_rotation_transitions_absent(
            reviewed_transitions,
            handled_transition_ids=handled_transition_ids,
            subscription_id=subscription_id,
        )
    if authority_container_id is None:
        if reviewed_authority_inventory is not None:
            raise OrchestrationError("foundation deployment cannot carry authority Blob inventory")
        return None, None
    if reviewed_authority_inventory is None:
        raise OrchestrationError("WC-027 deployment is missing its reviewed authority checkpoint")
    current_inventory = _authority_blob_inventory(
        authority_container_id,
        subscription_id=subscription_id,
        previous_inventory=reviewed_authority_inventory,
    )
    _verify_post_deployment_authority_inventory(
        stage=stage,
        reviewed_inventory=reviewed_authority_inventory,
        current_inventory=current_inventory,
    )
    image_pull_executions.sort(key=lambda item: str(item["jobResourceId"]).casefold())
    image_pull_evidence = {
        "schemaVersion": IMAGE_PULL_EVIDENCE_SCHEMA_VERSION,
        "executions": image_pull_executions,
    }
    validated_image_pull_evidence = _validated_image_pull_evidence(
        image_pull_evidence,
        stage=stage,
        subscription_id=subscription_id,
    )
    if validated_image_pull_evidence is None:
        raise OrchestrationError("image-pull evidence unexpectedly vanished")
    return current_inventory, validated_image_pull_evidence


def prepare_revocation(args: argparse.Namespace) -> Path:
    artifact_reader = _ArtifactReader()
    subscription_id = _canonical_subscription_id(
        args.subscription,
        field="subscription",
    )
    base_parameter_artifact = artifact_reader.capture_json(
        args.parameters,
        field="reviewed base parameter artifact",
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
        artifact_reader=artifact_reader,
    )
    _ensure_evidence_directory_outside_repository(args.evidence_directory)
    _ensure_clean_worktree()
    effective = _build_effective_parameters_from_documents(
        stage=args.stage,
        parameter_document=base_parameter_artifact.document,
        handoffs={
            predecessor: _mapping(
                record["handoff"],
                field=f"verified {predecessor} handoff",
            )
            for predecessor, record in verified_predecessors.items()
        },
    )
    _bind_broker_identity_principal(
        stage=args.stage,
        effective_parameters=effective,
        subscription_id=subscription_id,
    )
    _validate_effective_parameter_subscription_boundary(
        effective,
        subscription_id=subscription_id,
    )
    raw_rotations = list(getattr(args, "rotation_transition_assignment", []))
    rotations = _canonical_rotation_transition_assignments(
        [
            {
                "assignmentResourceId": pair[0],
                "retiredPrincipalId": pair[1],
            }
            for pair in raw_rotations
            if isinstance(pair, list | tuple) and len(pair) == 2
        ],
        subscription_id=subscription_id,
        field="revocation rotation transitions",
    )
    if len(rotations) != len(raw_rotations):
        raise OrchestrationError(
            "each rotation transition requires an assignment ID and retired principal ID"
        )
    legacy_crypto = _canonical_legacy_crypto_user_migration_assignments(
        list(
            getattr(
                args,
                "legacy_crypto_user_migration_assignment",
                [],
            )
        ),
        subscription_id=subscription_id,
        field="revocation legacy Crypto User migrations",
    )
    raw_legacy_acr = list(getattr(args, "legacy_acr_pull_migration_assignment", []))
    legacy_acr = _canonical_legacy_acr_pull_migration_assignments(
        [
            {
                "assignmentResourceId": pair[0],
                "principalId": pair[1],
            }
            for pair in raw_legacy_acr
            if isinstance(pair, list | tuple) and len(pair) == 2
        ],
        subscription_id=subscription_id,
        field="revocation legacy ACR pull migrations",
    )
    if len(legacy_acr) != len(raw_legacy_acr):
        raise OrchestrationError(
            "each legacy ACR pull migration requires an assignment ID and principal ID"
        )
    if not rotations and not legacy_crypto and not legacy_acr:
        raise OrchestrationError(
            "revocation planning requires at least one exact reviewed assignment"
        )
    if args.stage != "producer" and legacy_crypto:
        raise OrchestrationError("legacy Crypto User migration assignments are producer-stage only")
    current_principal_ids = (
        set()
        if args.stage in {"foundation", "live-acceptance"}
        else _current_principal_ids_from_effective_parameters(
            effective,
            subscription_id=subscription_id,
        )
    )
    if rotations:
        _verify_reviewed_rotation_transitions(
            rotations,
            current_principal_ids=current_principal_ids,
            transition_state="present",
            subscription_id=subscription_id,
        )
    legacy_crypto_expected: Mapping[str, _ExpectedRoleAssignment] | None = None
    if args.stage == "producer":
        _verify_planned_trigger_queue_transition_state(
            effective_parameters=effective,
            resource_group=_string(
                args.resource_group,
                field="producer resource group",
            ),
            approved_transitions=rotations,
            transition_state="present",
            subscription_id=subscription_id,
        )
        all_legacy_crypto_expected = _planned_legacy_crypto_user_assignments(
            effective_parameters=effective,
            resource_group=_string(
                args.resource_group,
                field="producer resource group",
            ),
            subscription_id=subscription_id,
        )
        _verify_legacy_crypto_user_migration(
            all_legacy_crypto_expected,
            set(legacy_crypto),
            migration_state="present",
            subscription_id=subscription_id,
        )
        legacy_crypto_expected = {
            assignment_id.casefold(): all_legacy_crypto_expected[assignment_id.casefold()]
            for assignment_id in legacy_crypto
        }
    if legacy_acr:
        _verify_legacy_acr_pull_migration(
            legacy_acr,
            migration_state="present",
            stage=args.stage,
            effective_parameters=effective,
            subscription_id=subscription_id,
        )
    assignment_ids = [
        *(item["assignmentResourceId"] for item in rotations),
        *legacy_crypto,
        *(item["assignmentResourceId"] for item in legacy_acr),
    ]
    revocation_assignments = _capture_revocation_assignment_evidence(
        assignment_ids,
        subscription_id=subscription_id,
    )
    _verify_revocation_assignment_evidence_bindings(
        revocation_assignments,
        rotations=rotations,
        legacy_acr_migrations=legacy_acr,
        legacy_crypto_expected=legacy_crypto_expected,
        subscription_id=subscription_id,
    )
    stem = f"{args.stage}-{args.deployment_name}"
    effective_path = args.evidence_directory / f"{stem}.revocation.parameters.json"
    plan_path = args.evidence_directory / f"{stem}.revocation.plan.json"
    for evidence_path in (effective_path, plan_path):
        if evidence_path.exists():
            raise OrchestrationError(f"refusing to overwrite immutable evidence {evidence_path}")
    effective_raw_bytes = _canonical_json_file_bytes(_parameter_document(effective))
    _write_new_bytes(effective_path, effective_raw_bytes)
    plan = {
        "schemaVersion": REVOCATION_PLAN_SCHEMA_VERSION,
        "stage": args.stage,
        "sourceCommit": SOURCE_COMMIT,
        "subscriptionId": subscription_id,
        "resourceGroup": args.resource_group,
        "deploymentName": args.deployment_name,
        "baseParameterPath": str(base_parameter_artifact.path),
        "baseParameterSha256": base_parameter_artifact.sha256,
        "effectiveParameterPath": str(effective_path.resolve()),
        "effectiveParameterSha256": _sha256_bytes(effective_raw_bytes),
        "foundationHandoffPath": (
            None
            if "foundation" not in verified_predecessors
            else str(verified_predecessors["foundation"]["handoffPath"])
        ),
        "foundationHandoffSha256": (
            None
            if "foundation" not in verified_predecessors
            else verified_predecessors["foundation"]["handoffSha256"]
        ),
        "producerHandoffPath": (
            None
            if "producer" not in verified_predecessors
            else str(verified_predecessors["producer"]["handoffPath"])
        ),
        "producerHandoffSha256": (
            None
            if "producer" not in verified_predecessors
            else verified_predecessors["producer"]["handoffSha256"]
        ),
        "publisherHandoffPath": (
            None
            if "publisher" not in verified_predecessors
            else str(verified_predecessors["publisher"]["handoffPath"])
        ),
        "publisherHandoffSha256": (
            None
            if "publisher" not in verified_predecessors
            else verified_predecessors["publisher"]["handoffSha256"]
        ),
        "predecessorReceipts": _predecessor_receipt_references(verified_predecessors),
        "rotationTransitionAssignments": rotations,
        "legacyCryptoUserMigrationAssignmentIds": legacy_crypto,
        "legacyAcrPullMigrationAssignments": legacy_acr,
        "revocationAssignments": revocation_assignments,
    }
    _write_new_json(plan_path, plan)
    return plan_path


def plan(args: argparse.Namespace) -> Path:
    artifact_reader = _ArtifactReader()
    subscription_id = _canonical_subscription_id(
        args.subscription,
        field="subscription",
    )
    base_parameter_artifact = artifact_reader.capture_json(
        args.parameters,
        field="reviewed base parameter artifact",
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
    effective_location = _effective_deployment_location(
        stage=args.stage,
        reviewed_location=args.location,
        subscription_id=subscription_id,
        resource_group=args.resource_group,
    )
    verified_predecessors = _load_verified_predecessors(
        stage=args.stage,
        handoff_paths=handoff_paths,
        receipt_paths=receipt_paths,
        reviewed_receipt_sha256s=reviewed_receipt_sha256s,
        artifact_reader=artifact_reader,
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
    rotation_transition_assignments: list[dict[str, str]] = []
    legacy_crypto_user_migration_assignments: list[str] = []
    legacy_acr_pull_migrations: list[dict[str, str]] = []
    revocation_assignments: list[dict[str, object]] = []
    revocation_plan_record: dict[str, Any] | None = None
    predecessor_rotation_transitions = _predecessor_rotation_transition_assignments(
        verified_predecessors,
        subscription_id=subscription_id,
    )
    predecessor_legacy_acr_migrations = _predecessor_legacy_acr_pull_migration_assignments(
        verified_predecessors,
        subscription_id=subscription_id,
    )
    prior_stage_handoff = getattr(args, "prior_stage_handoff", None)
    prior_stage_receipt = getattr(args, "prior_stage_receipt", None)
    prior_stage_reviewed_receipt_sha256 = getattr(
        args,
        "prior_stage_reviewed_receipt_sha256",
        None,
    )
    prior_stage_values = (
        prior_stage_handoff,
        prior_stage_receipt,
        prior_stage_reviewed_receipt_sha256,
    )
    if any(value is not None for value in prior_stage_values) and not all(
        value is not None for value in prior_stage_values
    ):
        raise OrchestrationError(
            "prior same-stage evidence requires handoff, receipt, and "
            "independently reviewed receipt SHA-256"
        )
    if any(value is not None for value in prior_stage_values) and args.stage not in {
        "producer",
        "publisher",
    }:
        raise OrchestrationError("prior same-stage evidence is supported only for WC-027 stages")
    prior_stage_record = (
        None
        if prior_stage_handoff is None
        or prior_stage_receipt is None
        or prior_stage_reviewed_receipt_sha256 is None
        else _load_verified_prior_stage_inventory(
            expected_stage=args.stage,
            handoff_path=prior_stage_handoff,
            receipt_path=prior_stage_receipt,
            reviewed_receipt_sha256=prior_stage_reviewed_receipt_sha256,
            subscription_id=subscription_id,
            resource_group=_string(
                args.resource_group,
                field="prior stage resource group",
            ),
            artifact_reader=artifact_reader,
        )
    )
    _ensure_clean_worktree()
    effective = _build_effective_parameters_from_documents(
        stage=args.stage,
        parameter_document=base_parameter_artifact.document,
        handoffs={
            predecessor: _mapping(
                record["handoff"],
                field=f"verified {predecessor} handoff",
            )
            for predecessor, record in verified_predecessors.items()
        },
    )
    _bind_broker_identity_principal(
        stage=args.stage,
        effective_parameters=effective,
        subscription_id=subscription_id,
    )
    _validate_effective_parameter_subscription_boundary(
        effective,
        subscription_id=subscription_id,
    )
    revocation_plan_path = getattr(args, "revocation_plan", None)
    reviewed_revocation_plan_sha256 = getattr(
        args,
        "reviewed_revocation_plan_sha256",
        None,
    )
    if (revocation_plan_path is None) != (reviewed_revocation_plan_sha256 is None):
        raise OrchestrationError(
            "final planning requires both revocation plan path and reviewed SHA-256"
        )
    phase_a_rotation_assignments: list[dict[str, str]] = []
    if revocation_plan_path is not None:
        revocation_plan_record = _load_revocation_plan(
            revocation_plan_path,
            reviewed_sha256=_string(
                reviewed_revocation_plan_sha256,
                field="reviewed revocation plan SHA-256",
            ),
            artifact_reader=artifact_reader,
        )
        _verify_revocation_plan_binding(
            revocation_plan_record,
            stage=args.stage,
            subscription_id=subscription_id,
            resource_group=args.resource_group,
            deployment_name=args.deployment_name,
            base_parameter_artifact=base_parameter_artifact,
            effective_parameters=effective,
            verified_predecessors=verified_predecessors,
        )
        phase_a_rotation_assignments = list(revocation_plan_record["rotationTransitionAssignments"])
        legacy_crypto_user_migration_assignments = list(
            revocation_plan_record["legacyCryptoUserMigrationAssignmentIds"]
        )
        legacy_acr_pull_migrations = list(
            revocation_plan_record["legacyAcrPullMigrationAssignments"]
        )
        revocation_assignments = list(revocation_plan_record["revocationAssignments"])
    rotation_transition_assignments = _merge_rotation_transition_assignments(
        phase_a_rotation_assignments,
        predecessor_rotation_transitions,
        subscription_id=subscription_id,
    )
    legacy_acr_pull_migrations = _merge_legacy_acr_pull_migration_assignments(
        legacy_acr_pull_migrations,
        predecessor_legacy_acr_migrations,
        subscription_id=subscription_id,
    )
    if phase_a_rotation_assignments:
        _verify_reviewed_rotation_transitions(
            phase_a_rotation_assignments,
            current_principal_ids=set(),
            transition_state="absent",
            subscription_id=subscription_id,
        )
    if legacy_acr_pull_migrations:
        _verify_legacy_acr_pull_migration(
            legacy_acr_pull_migrations,
            migration_state="absent",
            stage=args.stage,
            effective_parameters=effective,
            subscription_id=subscription_id,
            allow_reviewed_assignment_scopes=True,
        )
    if legacy_crypto_user_migration_assignments:
        if args.stage != "producer":
            raise OrchestrationError(
                "legacy Crypto User migration assignments are producer-stage only"
            )
        _verify_legacy_crypto_user_migration(
            _planned_legacy_crypto_user_assignments(
                effective_parameters=effective,
                resource_group=_string(
                    args.resource_group,
                    field="producer resource group",
                ),
                subscription_id=subscription_id,
            ),
            set(legacy_crypto_user_migration_assignments),
            migration_state="absent",
            subscription_id=subscription_id,
        )
    (
        compiled_template,
        compiled_template_raw_bytes,
        compiled_template_sha256,
    ) = _compiled_template(args.stage)
    _verify_effective_parameter_completeness(
        args.stage,
        effective,
        required_parameter_names=_required_parameter_names_from_template(
            compiled_template,
            stage=args.stage,
        ),
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
        _verify_planned_trigger_queue_transition_state(
            effective_parameters=effective,
            resource_group=_string(
                args.resource_group,
                field="producer resource group",
            ),
            approved_transitions=rotation_transition_assignments,
            transition_state="absent",
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
            approved_transitions=rotation_transition_assignments,
            require_transition_revoked=True,
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
            rotation_transitions=predecessor_rotation_transitions,
        )
    initial_publisher = args.stage == "publisher" and prior_stage_record is None
    if initial_publisher:
        _verify_initial_publisher_absence(
            effective_parameters=effective,
            deployment_name=_string(
                args.deployment_name,
                field="publisher deployment name",
            ),
            subscription_id=subscription_id,
            resource_group=_string(
                args.resource_group,
                field="publisher resource group",
            ),
        )
    predecessor_authority_inventory = _predecessor_authority_blob_inventory(
        stage=args.stage,
        verified_predecessors=verified_predecessors,
        subscription_id=subscription_id,
    )
    trusted_prior_inventory = (
        prior_stage_record["inventory"]
        if prior_stage_record is not None
        else predecessor_authority_inventory
    )
    additional_required_inventories = (
        [predecessor_authority_inventory]
        if (prior_stage_record is not None and predecessor_authority_inventory is not None)
        else []
    )
    required_authority_checkpoint_sha256s = _required_authority_checkpoint_sha256s(
        stage=args.stage,
        predecessor_inventory=predecessor_authority_inventory,
        prior_stage_inventory=(
            None if prior_stage_record is None else prior_stage_record["inventory"]
        ),
    )
    authority_container_id = _authority_container_resource_id_for_stage(
        stage=args.stage,
        effective_parameters=effective,
        verified_predecessors=verified_predecessors,
    )
    authority_blob_inventory = (
        None
        if authority_container_id is None
        else _authority_blob_inventory(
            authority_container_id,
            subscription_id=subscription_id,
            previous_inventory=trusted_prior_inventory,
        )
    )
    _verify_planned_authority_blob_inventory(
        stage=args.stage,
        current_inventory=authority_blob_inventory,
        trusted_inventory=trusted_prior_inventory,
    )
    if initial_publisher:
        if predecessor_authority_inventory is None or authority_blob_inventory is None:
            raise OrchestrationError(
                "initial publisher planning is missing the producer authority checkpoint"
            )
        _verify_authority_inventory_content_equal(
            expected_inventory=predecessor_authority_inventory,
            current_inventory=authority_blob_inventory,
            field="initial publisher planning",
        )
    if authority_blob_inventory is not None:
        for required_inventory in additional_required_inventories:
            _verify_authority_checkpoint_contains(
                required_inventory=required_inventory,
                current_inventory=authority_blob_inventory,
            )
    stem = f"{args.stage}-{args.deployment_name}"
    compiled_template_path = args.evidence_directory / f"{stem}.template.json"
    effective_path = args.evidence_directory / f"{stem}.parameters.json"
    what_if_path = args.evidence_directory / f"{stem}.what-if.json"
    manifest_path = args.evidence_directory / f"{stem}.plan.json"
    for evidence_path in (
        compiled_template_path,
        effective_path,
        what_if_path,
        manifest_path,
    ):
        if evidence_path.exists():
            raise OrchestrationError(f"refusing to overwrite immutable evidence {evidence_path}")
    compiled_template_artifact = _write_and_capture_exact_json(
        compiled_template_path,
        raw_bytes=compiled_template_raw_bytes,
        document=compiled_template,
        artifact_reader=artifact_reader,
        field="compiled deployment template artifact",
    )
    if compiled_template_artifact.sha256 != compiled_template_sha256:
        raise OrchestrationError("persisted ARM template digest differs from compiler output")
    effective_document = _parameter_document(effective)
    effective_raw_bytes = _canonical_json_file_bytes(effective_document)
    with (
        _materialized_private_artifact(
            compiled_template_artifact.raw_bytes,
            file_name="template.json",
        ) as pinned_template,
        _materialized_private_artifact(effective_raw_bytes) as pinned_parameters,
    ):
        pinned_template.verify()
        pinned_parameters.verify()
        _run(
            _az_command(
                operation="validate",
                stage=args.stage,
                deployment_name=args.deployment_name,
                subscription_id=subscription_id,
                location=effective_location,
                resource_group=args.resource_group,
                template_path=pinned_template.path,
                parameter_path=pinned_parameters.path,
            )
        )
        pinned_template.verify()
        pinned_parameters.verify()
        what_if = _run_json(
            _az_command(
                operation="what-if",
                stage=args.stage,
                deployment_name=args.deployment_name,
                subscription_id=subscription_id,
                location=effective_location,
                resource_group=args.resource_group,
                template_path=pinned_template.path,
                parameter_path=pinned_parameters.path,
            ),
            field="what-if",
        )
        pinned_template.verify()
        pinned_parameters.verify()
    _validate_subscription_boundary(
        what_if,
        subscription_id=subscription_id,
        field="what-if",
    )
    what_if_raw_bytes = _canonical_json_file_bytes(what_if)
    violations = evaluate_what_if(
        what_if,
        allowed_change_ids=frozenset(allowed_changes),
    )
    if violations:
        details = "; ".join(f"{item.code}: {item.subject}: {item.detail}" for item in violations)
        raise OrchestrationError(f"WC-029 what-if gate failed: {details}")
    _write_new_bytes(effective_path, effective_raw_bytes)
    _write_new_bytes(what_if_path, what_if_raw_bytes)
    manifest = {
        "schemaVersion": PLAN_SCHEMA_VERSION,
        "stage": args.stage,
        "sourceCommit": SOURCE_COMMIT,
        "subscriptionId": subscription_id,
        "location": effective_location,
        "resourceGroup": args.resource_group,
        "deploymentName": args.deployment_name,
        "templatePath": str(TEMPLATES[args.stage].relative_to(ROOT)).replace("\\", "/"),
        "templateSha256": _sha256_file(TEMPLATES[args.stage]),
        "compiledTemplatePath": str(compiled_template_artifact.path),
        "compiledTemplateSha256": compiled_template_artifact.sha256,
        "orchestratorSha256": _sha256_file(Path(__file__).resolve()),
        "preflightSha256": _sha256_file(PREFLIGHT_PATH),
        "baseParameterPath": str(base_parameter_artifact.path),
        "baseParameterSha256": base_parameter_artifact.sha256,
        "effectiveParameterPath": str(effective_path.resolve()),
        "effectiveParameterSha256": _sha256_bytes(effective_raw_bytes),
        "whatIfPath": str(what_if_path.resolve()),
        "whatIfSha256": _sha256_bytes(what_if_raw_bytes),
        "allowedChangeResourceIds": sorted(allowed_changes),
        "rotationTransitionAssignments": rotation_transition_assignments,
        "legacyCryptoUserMigrationAssignmentIds": (legacy_crypto_user_migration_assignments),
        "legacyAcrPullMigrationAssignments": legacy_acr_pull_migrations,
        "revocationPlanPath": (
            None if revocation_plan_record is None else str(revocation_plan_record["artifact"].path)
        ),
        "revocationPlanSha256": (
            None if revocation_plan_record is None else revocation_plan_record["artifact"].sha256
        ),
        "reviewedRevocationPlanSha256": (
            None if revocation_plan_record is None else revocation_plan_record["artifact"].sha256
        ),
        "revocationAssignments": revocation_assignments,
        "authorityBlobInventory": authority_blob_inventory,
        "authorityBlobInventorySha256": _authority_checkpoint_sha256(authority_blob_inventory),
        "requiredAuthorityCheckpointSha256s": (required_authority_checkpoint_sha256s),
        "priorStageHandoffPath": (
            None if prior_stage_record is None else str(prior_stage_record["handoffPath"])
        ),
        "priorStageHandoffSha256": (
            None if prior_stage_record is None else prior_stage_record["handoffSha256"]
        ),
        "priorStageReceipt": (
            None
            if prior_stage_record is None
            else {
                "path": str(prior_stage_record["receiptPath"]),
                "sha256": prior_stage_record["receiptSha256"],
                "reviewedSha256": prior_stage_record["reviewedReceiptSha256"],
            }
        ),
        "foundationHandoffPath": (
            None
            if "foundation" not in verified_predecessors
            else str(verified_predecessors["foundation"]["handoffPath"])
        ),
        "foundationHandoffSha256": (
            None
            if "foundation" not in verified_predecessors
            else verified_predecessors["foundation"]["handoffSha256"]
        ),
        "producerHandoffPath": (
            None
            if "producer" not in verified_predecessors
            else str(verified_predecessors["producer"]["handoffPath"])
        ),
        "producerHandoffSha256": (
            None
            if "producer" not in verified_predecessors
            else verified_predecessors["producer"]["handoffSha256"]
        ),
        "publisherHandoffPath": (
            None
            if "publisher" not in verified_predecessors
            else str(verified_predecessors["publisher"]["handoffPath"])
        ),
        "publisherHandoffSha256": (
            None
            if "publisher" not in verified_predecessors
            else verified_predecessors["publisher"]["handoffSha256"]
        ),
        "predecessorReceipts": _predecessor_receipt_references(verified_predecessors),
    }
    _write_new_json(manifest_path, manifest)
    return manifest_path


def apply(args: argparse.Namespace) -> Path:
    artifact_reader = _ArtifactReader()
    reviewed_digest = _sha256_digest(
        args.reviewed_plan_sha256,
        field="reviewed plan SHA-256",
    )
    plan_artifact = artifact_reader.capture_json(
        args.plan_manifest,
        field="reviewed plan manifest",
    )
    if plan_artifact.sha256 != reviewed_digest:
        raise OrchestrationError("plan manifest does not match the independently reviewed SHA-256")
    _ensure_evidence_directory_outside_repository(args.plan_manifest.parent)
    _ensure_clean_worktree()
    manifest = _load_plan_manifest(
        args.plan_manifest,
        document=plan_artifact.document,
        artifact_reader=artifact_reader,
    )
    if manifest.get("schemaVersion") != PLAN_SCHEMA_VERSION:
        raise OrchestrationError("unsupported WC-029 deployment plan schema")
    stage = _string(manifest.get("stage"), field="plan stage")
    if stage not in STAGES:
        raise OrchestrationError("plan has an unsupported deployment stage")
    if manifest.get("sourceCommit") != SOURCE_COMMIT:
        raise OrchestrationError("plan source commit is not the current exact commit")
    if _sha256_file(Path(__file__).resolve()) != manifest.get("orchestratorSha256"):
        raise OrchestrationError("orchestrator implementation changed after review")
    if _sha256_file(PREFLIGHT_PATH) != manifest.get("preflightSha256"):
        raise OrchestrationError("preflight implementation changed after review")
    compiled_template_path = Path(
        _string(
            manifest.get("compiledTemplatePath"),
            field="compiled deployment template",
        )
    )
    compiled_template_artifact = artifact_reader.capture_json(
        compiled_template_path,
        field="reviewed compiled deployment template",
    )
    if compiled_template_artifact.sha256 != manifest.get("compiledTemplateSha256"):
        raise OrchestrationError("compiled Bicep template changed after review")
    compiled_template = _mapping(
        compiled_template_artifact.document,
        field="reviewed compiled deployment template",
    )
    compiled_template_sha256 = compiled_template_artifact.sha256
    effective_path = Path(
        _string(manifest.get("effectiveParameterPath"), field="effective parameters")
    )
    what_if_path = Path(_string(manifest.get("whatIfPath"), field="what-if path"))
    base_parameter_path = Path(_string(manifest.get("baseParameterPath"), field="base parameters"))
    base_parameter_artifact = artifact_reader.capture_json(
        base_parameter_path,
        field="reviewed base parameter artifact",
    )
    effective_parameter_artifact = artifact_reader.capture_json(
        effective_path,
        field="reviewed effective parameter artifact",
    )
    what_if_artifact = artifact_reader.capture_json(
        what_if_path,
        field="reviewed what-if artifact",
    )
    if base_parameter_artifact.sha256 != manifest.get("baseParameterSha256"):
        raise OrchestrationError("base parameter artifact changed after review")
    if effective_parameter_artifact.sha256 != manifest.get("effectiveParameterSha256"):
        raise OrchestrationError("effective parameter artifact changed after review")
    if what_if_artifact.sha256 != manifest.get("whatIfSha256"):
        raise OrchestrationError("what-if artifact changed after review")
    for prefix in ("foundation", "producer", "publisher"):
        handoff_path_value = manifest.get(f"{prefix}HandoffPath")
        handoff_digest = manifest.get(f"{prefix}HandoffSha256")
        if handoff_path_value is None:
            if handoff_digest is not None:
                raise OrchestrationError(f"{prefix} handoff digest has no path")
            continue
        handoff_path = Path(_string(handoff_path_value, field=f"{prefix} handoff"))
        if (
            artifact_reader.capture_json(
                handoff_path,
                field=f"reviewed {prefix} handoff",
            ).sha256
            != handoff_digest
        ):
            raise OrchestrationError(f"{prefix} handoff changed after review")
    subscription_id = _canonical_subscription_id(
        manifest.get("subscriptionId"),
        field="subscription",
    )
    what_if = what_if_artifact.document
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
    rotation_transition_assignments = _canonical_rotation_transition_assignments(
        manifest.get("rotationTransitionAssignments"),
        subscription_id=subscription_id,
        field="rotation transition assignments",
    )
    legacy_crypto_user_migration_assignment_ids = (
        _canonical_legacy_crypto_user_migration_assignments(
            manifest.get("legacyCryptoUserMigrationAssignmentIds"),
            subscription_id=subscription_id,
            field="legacy Crypto User migration assignments",
        )
    )
    legacy_acr_pull_migrations = _canonical_legacy_acr_pull_migration_assignments(
        manifest.get("legacyAcrPullMigrationAssignments"),
        subscription_id=subscription_id,
        field="legacy ACR pull migration assignments",
    )
    revocation_assignments = _validated_revocation_assignment_evidence(
        manifest.get("revocationAssignments"),
        subscription_id=subscription_id,
    )
    reviewed_authority_blob_inventory = _validated_authority_blob_inventory(
        manifest.get("authorityBlobInventory"),
        subscription_id=subscription_id,
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
    location = _effective_deployment_location(
        stage=stage,
        reviewed_location=location,
        subscription_id=subscription_id,
        resource_group=resource_group,
    )
    prior_stage_handoff_value = manifest.get("priorStageHandoffPath")
    prior_stage_receipt_value = manifest.get("priorStageReceipt")
    prior_stage_record = None
    if prior_stage_handoff_value is not None:
        prior_stage_receipt = _mapping(
            prior_stage_receipt_value,
            field="prior stage receipt reference",
        )
        prior_stage_record = _load_verified_prior_stage_inventory(
            expected_stage=stage,
            handoff_path=Path(
                _string(
                    prior_stage_handoff_value,
                    field="prior stage handoff path",
                )
            ),
            receipt_path=Path(
                _string(
                    prior_stage_receipt.get("path"),
                    field="prior stage receipt path",
                )
            ),
            reviewed_receipt_sha256=_string(
                prior_stage_receipt.get("reviewedSha256"),
                field="prior stage reviewed receipt SHA-256",
            ),
            subscription_id=subscription_id,
            resource_group=_string(
                resource_group,
                field="prior stage resource group",
            ),
            artifact_reader=artifact_reader,
        )
        _require_equal(
            prior_stage_record["handoffSha256"],
            _sha256_digest(
                manifest.get("priorStageHandoffSha256"),
                field="prior stage handoff SHA-256",
            ),
            field="prior stage handoff SHA-256",
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
        artifact_reader=artifact_reader,
    )
    predecessor_rotation_transitions = _predecessor_rotation_transition_assignments(
        verified_predecessors,
        subscription_id=subscription_id,
    )
    predecessor_legacy_acr_migrations = _predecessor_legacy_acr_pull_migration_assignments(
        verified_predecessors,
        subscription_id=subscription_id,
    )
    if stage != "producer" and legacy_crypto_user_migration_assignment_ids:
        raise OrchestrationError("legacy Crypto User migration assignments are producer-stage only")
    effective_parameters = _load_parameter_document(effective_parameter_artifact.document)
    _validate_effective_parameter_subscription_boundary(
        effective_parameters,
        subscription_id=subscription_id,
    )
    _verify_effective_parameter_completeness(
        stage,
        effective_parameters,
        required_parameter_names=_required_parameter_names_from_template(
            compiled_template,
            stage=stage,
        ),
    )
    recomputed_effective_parameters = _build_effective_parameters_from_documents(
        stage=stage,
        parameter_document=base_parameter_artifact.document,
        handoffs={
            predecessor: _mapping(
                record["handoff"],
                field=f"verified {predecessor} handoff",
            )
            for predecessor, record in verified_predecessors.items()
        },
    )
    _bind_broker_identity_principal(
        stage=stage,
        effective_parameters=recomputed_effective_parameters,
        subscription_id=subscription_id,
    )
    if (
        effective_parameters != recomputed_effective_parameters
        or effective_parameter_artifact.raw_bytes
        != _canonical_json_file_bytes(_parameter_document(recomputed_effective_parameters))
    ):
        raise OrchestrationError(
            "reviewed effective parameters do not match the captured base and handoffs"
        )
    phase_a_rotations: list[dict[str, str]] = []
    phase_a_legacy_crypto: list[str] = []
    phase_a_legacy_acr: list[dict[str, str]] = []
    phase_a_revocation_assignments: list[dict[str, object]] = []
    revocation_plan_path_value = manifest.get("revocationPlanPath")
    if revocation_plan_path_value is not None:
        revocation_plan_record = _load_revocation_plan(
            Path(
                _string(
                    revocation_plan_path_value,
                    field="plan revocation path",
                )
            ),
            reviewed_sha256=_string(
                manifest.get("reviewedRevocationPlanSha256"),
                field="reviewed revocation plan SHA-256",
            ),
            artifact_reader=artifact_reader,
        )
        _verify_revocation_plan_binding(
            revocation_plan_record,
            stage=stage,
            subscription_id=subscription_id,
            resource_group=resource_group,
            deployment_name=deployment_name,
            base_parameter_artifact=base_parameter_artifact,
            effective_parameters=effective_parameters,
            verified_predecessors=verified_predecessors,
        )
        if manifest.get("revocationAssignments") != revocation_plan_record.get(
            "revocationAssignments"
        ):
            raise OrchestrationError("final plan revocation assignments differ from phase-A review")
        phase_a_rotations = list(revocation_plan_record["rotationTransitionAssignments"])
        phase_a_legacy_crypto = list(
            revocation_plan_record["legacyCryptoUserMigrationAssignmentIds"]
        )
        phase_a_legacy_acr = list(revocation_plan_record["legacyAcrPullMigrationAssignments"])
        phase_a_revocation_assignments = list(revocation_plan_record["revocationAssignments"])
    elif revocation_assignments:
        raise OrchestrationError(
            "final plan contains revocation assignments without phase-A review"
        )
    expected_rotation_transitions = _merge_rotation_transition_assignments(
        phase_a_rotations,
        predecessor_rotation_transitions,
        subscription_id=subscription_id,
    )
    expected_legacy_acr_migrations = _merge_legacy_acr_pull_migration_assignments(
        phase_a_legacy_acr,
        predecessor_legacy_acr_migrations,
        subscription_id=subscription_id,
    )
    if (
        rotation_transition_assignments != expected_rotation_transitions
        or legacy_acr_pull_migrations != expected_legacy_acr_migrations
        or legacy_crypto_user_migration_assignment_ids != phase_a_legacy_crypto
        or revocation_assignments != phase_a_revocation_assignments
    ):
        raise OrchestrationError(
            "final plan assignment sets are not the exact phase-A plus predecessor sets"
        )
    reviewed_rotation_transitions = expected_rotation_transitions
    reviewed_legacy_acr_migrations = expected_legacy_acr_migrations
    if phase_a_rotations:
        _verify_reviewed_rotation_transitions(
            phase_a_rotations,
            current_principal_ids=set(),
            transition_state="absent",
            subscription_id=subscription_id,
        )
    if what_if_artifact.raw_bytes != _canonical_json_file_bytes(what_if):
        raise OrchestrationError("reviewed what-if artifact is not canonical")
    _verify_legacy_acr_pull_migration(
        reviewed_legacy_acr_migrations,
        migration_state="absent",
        stage=stage,
        effective_parameters=effective_parameters,
        subscription_id=subscription_id,
        allow_reviewed_assignment_scopes=True,
    )
    authority_container_id = _authority_container_resource_id_for_stage(
        stage=stage,
        effective_parameters=effective_parameters,
        verified_predecessors=verified_predecessors,
    )
    predecessor_authority_inventory = _predecessor_authority_blob_inventory(
        stage=stage,
        verified_predecessors=verified_predecessors,
        subscription_id=subscription_id,
    )
    initial_publisher = stage == "publisher" and prior_stage_record is None
    if initial_publisher:
        _verify_initial_publisher_absence(
            effective_parameters=effective_parameters,
            deployment_name=deployment_name,
            subscription_id=subscription_id,
            resource_group=_string(
                resource_group,
                field="publisher resource group",
            ),
        )
    trusted_prior_inventory = (
        prior_stage_record["inventory"]
        if prior_stage_record is not None
        else predecessor_authority_inventory
    )
    additional_required_inventories = (
        [predecessor_authority_inventory]
        if (prior_stage_record is not None and predecessor_authority_inventory is not None)
        else []
    )
    expected_required_checkpoint_sha256s = _required_authority_checkpoint_sha256s(
        stage=stage,
        predecessor_inventory=predecessor_authority_inventory,
        prior_stage_inventory=(
            None if prior_stage_record is None else prior_stage_record["inventory"]
        ),
    )
    planned_required_checkpoint_sha256s = _mapping(
        manifest.get("requiredAuthorityCheckpointSha256s"),
        field="plan required authority checkpoint SHA-256s",
    )
    for name, digest in planned_required_checkpoint_sha256s.items():
        _sha256_digest(
            digest,
            field=f"plan required authority checkpoint {name}",
        )
    if planned_required_checkpoint_sha256s != expected_required_checkpoint_sha256s:
        raise OrchestrationError(
            "plan required authority checkpoint digests do not match its receipts"
        )
    _verify_planned_authority_blob_inventory(
        stage=stage,
        current_inventory=reviewed_authority_blob_inventory,
        trusted_inventory=trusted_prior_inventory,
    )
    if reviewed_authority_blob_inventory is not None:
        for required_inventory in additional_required_inventories:
            _verify_authority_checkpoint_contains(
                required_inventory=required_inventory,
                current_inventory=reviewed_authority_blob_inventory,
            )
    resume_succeeded_deployment = bool(getattr(args, "resume_succeeded_deployment", False))
    _validate_resume_succeeded_deployment(
        requested=resume_succeeded_deployment,
        stage=stage,
        reviewed_authority_inventory=reviewed_authority_blob_inventory,
        trusted_prior_inventory=trusted_prior_inventory,
    )
    if authority_container_id is None:
        if reviewed_authority_blob_inventory is not None:
            raise OrchestrationError("foundation plan cannot contain authority Blob inventory")
    else:
        if reviewed_authority_blob_inventory is None:
            raise OrchestrationError("reviewed plan is missing authority Blob inventory")
        _require_resource_id_equal(
            reviewed_authority_blob_inventory["containerResourceId"],
            authority_container_id,
            field="reviewed authority Blob inventory container",
        )
        if not resume_succeeded_deployment:
            current_authority_blob_inventory = _authority_blob_inventory(
                authority_container_id,
                subscription_id=subscription_id,
                previous_inventory=trusted_prior_inventory,
            )
            if initial_publisher:
                if predecessor_authority_inventory is None:
                    raise OrchestrationError(
                        "initial publisher apply is missing the producer authority checkpoint"
                    )
                _verify_authority_inventory_content_equal(
                    expected_inventory=predecessor_authority_inventory,
                    current_inventory=current_authority_blob_inventory,
                    field="initial publisher apply",
                )
            if _canonical_json_bytes(current_authority_blob_inventory) != (
                _canonical_json_bytes(reviewed_authority_blob_inventory)
            ):
                raise OrchestrationError("authority Blob checkpoint changed after plan review")
        if prior_stage_record is not None and reviewed_authority_blob_inventory.get(
            "previousCheckpointSha256"
        ) != _authority_checkpoint_sha256(prior_stage_record["inventory"]):
            raise OrchestrationError(
                "reviewed authority checkpoint is not chained to the prior same-stage receipt"
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
        if not resume_succeeded_deployment:
            _verify_planned_trigger_queue_transition_state(
                effective_parameters=effective_parameters,
                resource_group=_string(
                    resource_group,
                    field="producer resource group",
                ),
                approved_transitions=reviewed_rotation_transitions,
                transition_state="absent",
                subscription_id=subscription_id,
            )
            _verify_legacy_crypto_user_migration(
                _planned_legacy_crypto_user_assignments(
                    effective_parameters=effective_parameters,
                    resource_group=_string(
                        resource_group,
                        field="producer resource group",
                    ),
                    subscription_id=subscription_id,
                ),
                set(legacy_crypto_user_migration_assignment_ids),
                migration_state="absent",
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
            approved_transitions=reviewed_rotation_transitions,
            require_transition_revoked=True,
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
            rotation_transitions=reviewed_rotation_transitions,
        )
    evidence_paths = _new_evidence_bundle_paths(
        args.plan_manifest.parent,
        stem=f"{stage}-{deployment_name}",
    )
    if evidence_paths.commit_manifest_path.exists():
        raise OrchestrationError(
            "deployment evidence is already committed for this stage and deployment name"
        )
    application_mode = "resume-succeeded-deployment" if resume_succeeded_deployment else "create"
    (
        outputs,
        deployment_record_sha256,
        deployed_template_sha256,
    ) = _execute_reviewed_deployment(
        resume_succeeded_deployment=resume_succeeded_deployment,
        stage=stage,
        deployment_name=deployment_name,
        subscription_id=subscription_id,
        location=location,
        resource_group=resource_group,
        effective_parameter_artifact=effective_parameter_artifact,
        effective_parameters=effective_parameters,
        reviewed_what_if=what_if,
        compiled_template_artifact=compiled_template_artifact,
        compiled_template=compiled_template,
        compiled_template_sha256=compiled_template_sha256,
    )
    (
        post_deployment_authority_inventory,
        image_pull_evidence,
    ) = _retry_post_deployment_readiness(
        lambda: _verify_deployed_stage_state(
            stage=stage,
            outputs=outputs,
            foundation=foundation,
            producer=producer,
            publisher=publisher,
            effective_parameters=effective_parameters,
            reviewed_transitions=reviewed_rotation_transitions,
            legacy_acr_pull_migrations=reviewed_legacy_acr_migrations,
            authority_container_id=authority_container_id,
            reviewed_authority_inventory=reviewed_authority_blob_inventory,
            subscription_id=subscription_id,
        )
    )
    bindings = _parameter_bindings(stage, effective_parameters)
    handoff_outputs = _handoff_outputs(stage, outputs)
    predecessor_receipt_hashes = _predecessor_receipt_hashes(verified_predecessors)
    published_image_pull_evidence = image_pull_evidence
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
        "planManifestSha256": plan_artifact.sha256,
        "predecessorReceiptSha256s": predecessor_receipt_hashes,
        "effectiveParameterSha256": effective_parameter_artifact.sha256,
        "applicationMode": application_mode,
        "deploymentRecordSha256": deployment_record_sha256,
        "deployedTemplateSha256": deployed_template_sha256,
        "authorityBlobInventory": post_deployment_authority_inventory,
        "authorityBlobInventorySha256": _authority_checkpoint_sha256(
            post_deployment_authority_inventory
        ),
        "imagePullEvidence": published_image_pull_evidence,
        "imagePullEvidenceSha256": _image_pull_evidence_sha256(published_image_pull_evidence),
        "revocationAssignments": revocation_assignments,
        "revocationAssignmentsSha256": (
            _revocation_assignment_evidence_sha256(revocation_assignments)
        ),
    }
    handoff_raw_bytes = _canonical_json_file_bytes(handoff)
    handoff_sha256 = _sha256_bytes(handoff_raw_bytes)
    receipt = {
        "schemaVersion": RECEIPT_SCHEMA_VERSION,
        "stage": stage,
        "sourceCommit": SOURCE_COMMIT,
        "subscriptionId": subscription_id,
        "resourceGroup": resource_group,
        "deploymentName": deployment_name,
        "planManifestPath": str(plan_artifact.path),
        "planManifestSha256": plan_artifact.sha256,
        "reviewedPlanSha256": reviewed_digest,
        "handoffPath": str(evidence_paths.handoff_path.resolve()),
        "handoffSha256": handoff_sha256,
        "predecessorReceiptSha256s": predecessor_receipt_hashes,
        "effectiveParameterSha256": effective_parameter_artifact.sha256,
        "applicationMode": application_mode,
        "deploymentRecordSha256": deployment_record_sha256,
        "deployedTemplateSha256": deployed_template_sha256,
        "authorityBlobInventorySha256": _authority_checkpoint_sha256(
            post_deployment_authority_inventory
        ),
        "imagePullEvidenceSha256": _image_pull_evidence_sha256(published_image_pull_evidence),
        "revocationAssignmentsSha256": (
            _revocation_assignment_evidence_sha256(revocation_assignments)
        ),
    }
    _publish_evidence_bundle(
        paths=evidence_paths,
        handoff_raw_bytes=handoff_raw_bytes,
        receipt_raw_bytes=_canonical_json_file_bytes(receipt),
    )
    return evidence_paths.receipt_path


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
    plan_parser.add_argument(
        "--location",
        required=True,
        help=(
            "Subscription deployment location; for producer/publisher this must "
            "exactly match the live resource-group location."
        ),
    )
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
    plan_parser.add_argument("--revocation-plan", type=Path)
    plan_parser.add_argument("--reviewed-revocation-plan-sha256")
    plan_parser.add_argument("--prior-stage-handoff", type=Path)
    plan_parser.add_argument("--prior-stage-receipt", type=Path)
    plan_parser.add_argument("--prior-stage-reviewed-receipt-sha256")

    revocation_parser = subparsers.add_parser("prepare-revocation")
    revocation_parser.add_argument("--stage", choices=STAGES, required=True)
    revocation_parser.add_argument("--subscription", required=True)
    revocation_parser.add_argument("--resource-group")
    revocation_parser.add_argument("--deployment-name", required=True)
    revocation_parser.add_argument("--parameters", type=Path, required=True)
    revocation_parser.add_argument("--evidence-directory", type=Path, required=True)
    revocation_parser.add_argument("--foundation-handoff", type=Path)
    revocation_parser.add_argument("--foundation-receipt", type=Path)
    revocation_parser.add_argument("--foundation-reviewed-receipt-sha256")
    revocation_parser.add_argument("--producer-handoff", type=Path)
    revocation_parser.add_argument("--producer-receipt", type=Path)
    revocation_parser.add_argument("--producer-reviewed-receipt-sha256")
    revocation_parser.add_argument("--publisher-handoff", type=Path)
    revocation_parser.add_argument("--publisher-receipt", type=Path)
    revocation_parser.add_argument("--publisher-reviewed-receipt-sha256")
    revocation_parser.add_argument(
        "--rotation-transition-assignment",
        action="append",
        nargs=2,
        metavar=("ASSIGNMENT_RESOURCE_ID", "RETIRED_PRINCIPAL_ID"),
        default=[],
    )
    revocation_parser.add_argument(
        "--legacy-crypto-user-migration-assignment",
        action="append",
        default=[],
    )
    revocation_parser.add_argument(
        "--legacy-acr-pull-migration-assignment",
        action="append",
        nargs=2,
        metavar=("ASSIGNMENT_RESOURCE_ID", "PRINCIPAL_ID"),
        default=[],
    )
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--plan-manifest", type=Path, required=True)
    apply_parser.add_argument("--reviewed-plan-sha256", required=True)
    apply_parser.add_argument(
        "--resume-succeeded-deployment",
        action="store_true",
        help=(
            "Issue a receipt for a previously succeeded fresh producer deployment "
            "after exact deployment re-attestation and bounded read-only readiness retries."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare-revocation":
            output = prepare_revocation(args)
        elif args.command == "plan":
            output = plan(args)
        else:
            output = apply(args)
    except (OrchestrationError, PreflightInputError, json.JSONDecodeError) as exc:
        print(f"WC-029 orchestration failed closed: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
