from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import json
import os
import re
import secrets
import stat
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal, NoReturn, cast
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from athena_context.artifacts import MAX_ARTIFACT_TRANSFER_BYTES
from athena_context.contracts import (
    ChangeEvidenceArtifact,
    CorrelationReport,
    IncidentEnrichmentAttestation,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentEnrichmentManifest,
    IncidentFeedIndexAttestationV2,
    IncidentFeedIndexV2,
    IncidentGuidance,
    IncidentGuidanceAttestation,
    IncidentNotificationEnvelopeV2,
    IncidentState,
    IncidentStateAttestation,
    MonitoringEvidenceHandoff,
    PublishedContextAuthority,
    PublishedCorrelationReportAttestation,
    UtcDateTime,
    canonicalize_json,
    compute_artifact_digest,
    incident_state_signature_preimage,
    sha256_hex,
)
from athena_context.contracts.change_ingestion import change_evidence_attestation_preimage
from athena_context.contracts.monitoring import monitoring_handoff_preimage
from athena_context.wc029_preflight import (
    PreflightInputError,
    evaluate_role_assignments,
    evaluate_what_if,
)

ACCEPTANCE_INDEX_SCHEMA_VERSION = "athena.wc029AcceptanceEvidenceIndex.v1"
ACCEPTANCE_RECORD_SCHEMA_VERSION = "athena.wc029AcceptanceEvidenceRecord.v1"
VERSION_INVENTORY_SCHEMA_VERSION = "athena.wc029VersionInventory.v1"
SIGNING_PUBLIC_KEY_SCHEMA_VERSION = "athena.wc029SigningPublicKey.v1"
PUBLISHED_MANIFEST_SCHEMA_VERSION = "athena.wc029PublishedManifest.v1"
PUBLICATION_AUTHORITY_SCHEMA_VERSION = "athena.wc029PublicationAuthority.v1"
PUBLICATION_AUTHORITY_ATTESTATION_SCHEMA_VERSION = "athena.wc029PublicationAuthorityAttestation.v1"
DEPLOYMENT_READBACK_SCHEMA_VERSION = "athena.wc029DeploymentReadback.v1"
JOB_EXECUTION_SCHEMA_VERSION = "athena.wc029JobExecution.v1"
JOB_READBACK_SCHEMA_VERSION = "athena.wc029JobReadback.v1"
PREFLIGHT_RESULT_SCHEMA_VERSION = "athena.wc029PreflightResult.v1"
SCENARIO_PLAN_SCHEMA_VERSION = "athena.wc029ScenarioPlan.v1"
SCENARIO_EXECUTION_MANIFEST_SCHEMA_VERSION = "athena.wc029ScenarioExecutionManifest.v1"
SCENARIO_EXECUTION_ATTESTATION_SCHEMA_VERSION = "athena.wc029ScenarioExecutionAttestation.v1"
MUTATION_RECEIPT_SCHEMA_VERSION = "athena.wc029MutationReceipt.v1"
RECOVERY_ACTION_SCHEMA_VERSION = "athena.wc029RecoveryAction.v1"
RESOURCE_STATE_SCHEMA_VERSION = "athena.wc029ResourceState.v1"
MANIFEST_CITATION_SCHEMA_VERSION = "athena.wc029ManifestCitation.v1"
INCIDENT_OMISSION_SCHEMA_VERSION = "athena.wc029IncidentOmission.v1"
RECOVERY_PROOF_SCHEMA_VERSION = "athena.wc029RecoveryProof.v1"
QUEUE_STATE_SCHEMA_VERSION = "athena.wc029QueueState.v1"
URL_PROBE_SCHEMA_VERSION = "athena.wc029UrlProbe.v1"

MAX_INDEX_BYTES = 512 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_FILES = 256
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
MAX_RECORD_BYTES = 2 * 1024 * 1024

type ScenarioClass = Literal[
    "disk-capacity-pressure",
    "vm-failure",
    "web-tier-failure",
    "load-balancer-vip-failure",
    "backend-degradation",
    "nsg-connectivity-loss",
]
type ScenarioMode = Literal["correlation-only", "incident-producing"]
type ScenarioPhase = Literal["plan", "apply", "observe", "recover", "verify"]
type PreflightKind = Literal["what-if", "rbac"]
type QueueScope = Literal["baseline", "scenario-verify", "final"]
type DeploymentStage = Literal["foundation", "producer", "publisher", "live-acceptance"]
type JobScope = Literal["global", "scenario"]
type EvidenceClass = Literal[
    "version-inventory",
    "signing-public-key",
    "published-manifest",
    "publication-authority",
    "publication-authority-attestation",
    "deployment-plan",
    "deployment-what-if",
    "deployment-output",
    "deployment-readback",
    "job-execution",
    "job-readback",
    "url-probe",
    "effective-rbac",
    "rbac-policy",
    "preflight-result",
    "queue-state",
    "scenario-plan",
    "baseline-state",
    "mutation-receipt",
    "monitoring-evidence",
    "change-evidence",
    "correlation-report",
    "correlation-report-attestation",
    "incident-omission",
    "incident-state-active",
    "incident-state-active-attestation",
    "incident-state-resolved",
    "incident-state-resolved-attestation",
    "manifest-citation",
    "guidance",
    "guidance-attestation",
    "enrichment-manifest",
    "enrichment-attestation",
    "feed-active",
    "feed-active-attestation",
    "feed-index-active",
    "feed-index-active-attestation",
    "feed-resolved",
    "feed-resolved-attestation",
    "feed-index-resolved",
    "feed-index-resolved-attestation",
    "notification-active",
    "notification-resolved",
    "recovery-action",
    "recovered-state",
    "scenario-execution-manifest",
    "scenario-execution-attestation",
    "recovery-proof",
]

REQUIRED_SCENARIO_CLASSES: tuple[ScenarioClass, ...] = (
    "backend-degradation",
    "disk-capacity-pressure",
    "load-balancer-vip-failure",
    "nsg-connectivity-loss",
    "vm-failure",
    "web-tier-failure",
)

_DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}$")
_PORTABLE_RELATIVE_FILE_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,510}[A-Za-z0-9])?$")
_IMAGE_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?"
    r"/[a-z0-9](?:[a-z0-9._/-]*[a-z0-9])?@sha256:(?P<digest>[a-f0-9]{64})$"
)
_SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9_+/=-]{1,8192}$")
_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]{1,90}/providers/"
    r"[A-Za-z0-9.]+/[A-Za-z0-9._()/-]+$",
    re.IGNORECASE,
)
_JOB_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]{1,90}/providers/"
    r"Microsoft\.App/jobs/[A-Za-z0-9-]{1,64}$",
    re.IGNORECASE,
)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_ZERO_DIGEST = "sha256:" + ("0" * 64)
_PREFLIGHT_IMPLEMENTATION = Path(__file__).with_name("wc029_preflight.py")

_GLOBAL_REQUIRED_CLASSES: frozenset[EvidenceClass] = frozenset(
    {
        "version-inventory",
        "signing-public-key",
        "published-manifest",
        "publication-authority",
        "publication-authority-attestation",
        "deployment-plan",
        "deployment-what-if",
        "deployment-output",
        "deployment-readback",
        "job-execution",
        "job-readback",
        "url-probe",
        "effective-rbac",
        "rbac-policy",
        "preflight-result",
        "queue-state",
    }
)
_INCIDENT_ONLY_CLASSES: frozenset[EvidenceClass] = frozenset(
    {
        "incident-state-active",
        "incident-state-active-attestation",
        "incident-state-resolved",
        "incident-state-resolved-attestation",
        "manifest-citation",
        "guidance",
        "guidance-attestation",
        "enrichment-manifest",
        "enrichment-attestation",
        "feed-active",
        "feed-active-attestation",
        "feed-index-active",
        "feed-index-active-attestation",
        "feed-resolved",
        "feed-resolved-attestation",
        "feed-index-resolved",
        "feed-index-resolved-attestation",
        "notification-active",
        "notification-resolved",
    }
)
_ATTESTATION_SUBJECT_CLASSES: dict[EvidenceClass, EvidenceClass] = {
    "correlation-report-attestation": "correlation-report",
    "incident-state-active-attestation": "incident-state-active",
    "incident-state-resolved-attestation": "incident-state-resolved",
    "guidance-attestation": "guidance",
    "enrichment-attestation": "enrichment-manifest",
    "feed-active-attestation": "feed-active",
    "feed-resolved-attestation": "feed-resolved",
    "feed-index-active-attestation": "feed-index-active",
    "feed-index-resolved-attestation": "feed-index-resolved",
    "publication-authority-attestation": "publication-authority",
    "scenario-execution-attestation": "scenario-execution-manifest",
}
_SIGNED_KEY_PURPOSE_BY_CLASS: dict[EvidenceClass, str] = {
    "monitoring-evidence": "monitoring",
    "change-evidence": "change",
    "correlation-report-attestation": "report",
    "incident-state-active-attestation": "incident",
    "incident-state-resolved-attestation": "incident",
    "guidance-attestation": "guidance",
    "enrichment-attestation": "enrichment",
    "feed-active-attestation": "feed",
    "feed-resolved-attestation": "feed",
    "feed-index-active-attestation": "feed",
    "feed-index-resolved-attestation": "feed",
    "publication-authority-attestation": "context-authority",
    "scenario-execution-attestation": "scenario-authority",
    "notification-active": "notification",
    "notification-resolved": "notification",
}
_EXPECTED_SCHEMA_BY_CLASS: dict[EvidenceClass, str | None] = {
    "version-inventory": VERSION_INVENTORY_SCHEMA_VERSION,
    "signing-public-key": SIGNING_PUBLIC_KEY_SCHEMA_VERSION,
    "published-manifest": PUBLISHED_MANIFEST_SCHEMA_VERSION,
    "publication-authority": PUBLICATION_AUTHORITY_SCHEMA_VERSION,
    "publication-authority-attestation": (PUBLICATION_AUTHORITY_ATTESTATION_SCHEMA_VERSION),
    "deployment-plan": "athena.wc029DeploymentPlan.v1",
    "deployment-what-if": None,
    "deployment-output": "athena.wc029DeploymentHandoff.v1",
    "deployment-readback": DEPLOYMENT_READBACK_SCHEMA_VERSION,
    "job-execution": JOB_EXECUTION_SCHEMA_VERSION,
    "job-readback": JOB_READBACK_SCHEMA_VERSION,
    "url-probe": URL_PROBE_SCHEMA_VERSION,
    "effective-rbac": None,
    "rbac-policy": None,
    "preflight-result": PREFLIGHT_RESULT_SCHEMA_VERSION,
    "queue-state": QUEUE_STATE_SCHEMA_VERSION,
    "scenario-plan": SCENARIO_PLAN_SCHEMA_VERSION,
    "baseline-state": RESOURCE_STATE_SCHEMA_VERSION,
    "mutation-receipt": MUTATION_RECEIPT_SCHEMA_VERSION,
    "monitoring-evidence": "athena.wc024MonitoringEvidenceHandoff.v1",
    "change-evidence": "athena.changeEvidenceArtifact.v1",
    "correlation-report": "athena.wc026CorrelationReport.v1",
    "correlation-report-attestation": ("athena.wc027PublishedCorrelationReportAttestation.v1"),
    "incident-omission": INCIDENT_OMISSION_SCHEMA_VERSION,
    "incident-state-active": "athena.incidentState.v1",
    "incident-state-active-attestation": "athena.incidentStateAttestation.v1",
    "incident-state-resolved": "athena.incidentState.v1",
    "incident-state-resolved-attestation": "athena.incidentStateAttestation.v1",
    "manifest-citation": MANIFEST_CITATION_SCHEMA_VERSION,
    "guidance": "athena.wc027IncidentGuidance.v1",
    "guidance-attestation": "athena.wc027IncidentGuidanceAttestation.v1",
    "enrichment-manifest": "athena.wc027IncidentEnrichmentManifest.v1",
    "enrichment-attestation": "athena.wc027IncidentEnrichmentAttestation.v1",
    "feed-active": "athena.wc027IncidentEnrichmentFeedPointer.v2",
    "feed-active-attestation": ("athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"),
    "feed-index-active": "athena.wc027IncidentFeedIndex.v2",
    "feed-index-active-attestation": ("athena.wc027IncidentFeedIndexAttestation.v2"),
    "feed-resolved": "athena.wc027IncidentEnrichmentFeedPointer.v2",
    "feed-resolved-attestation": ("athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"),
    "feed-index-resolved": "athena.wc027IncidentFeedIndex.v2",
    "feed-index-resolved-attestation": ("athena.wc027IncidentFeedIndexAttestation.v2"),
    "notification-active": "athena.wc027IncidentNotificationEnvelope.v2",
    "notification-resolved": "athena.wc027IncidentNotificationEnvelope.v2",
    "recovery-action": RECOVERY_ACTION_SCHEMA_VERSION,
    "recovered-state": RESOURCE_STATE_SCHEMA_VERSION,
    "scenario-execution-manifest": SCENARIO_EXECUTION_MANIFEST_SCHEMA_VERSION,
    "scenario-execution-attestation": (SCENARIO_EXECUTION_ATTESTATION_SCHEMA_VERSION),
    "recovery-proof": RECOVERY_PROOF_SCHEMA_VERSION,
}


class Wc029AcceptanceEvidenceError(RuntimeError):
    """Raised when an offline acceptance bundle cannot be aggregated safely."""


class _StrictAcceptanceModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_json(self) -> str:
        return canonicalize_json(self.model_dump(mode="json", by_alias=True, exclude_none=True))

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


def _validate_fixed_text(
    value: str,
    *,
    label: str,
    maximum_length: int,
) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum_length
        or value != value.strip()
        or any(character in value for character in ("\0", "\r", "\n"))
    ):
        raise ValueError(f"{label} must be one bounded exact string")
    return value


def _validate_digest(value: str, *, label: str, allow_zero: bool = False) -> str:
    if (
        type(value) is not str
        or _DIGEST_PATTERN.fullmatch(value) is None
        or (not allow_zero and value == _ZERO_DIGEST)
    ):
        raise ValueError(f"{label} must be a real lowercase sha256 digest")
    return value


def _validate_relative_file(value: str) -> str:
    if (
        value != value.strip()
        or "\\" in value
        or ":" in value
        or _PORTABLE_RELATIVE_FILE_PATTERN.fullmatch(value) is None
        or not value.endswith(".json")
    ):
        raise ValueError("evidence path must be one bounded portable relative JSON file")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("evidence path must not contain empty or traversing segments")
    return value


def _validate_portable_relative_path(value: str) -> str:
    if (
        value != value.strip()
        or "\\" in value
        or ":" in value
        or _PORTABLE_RELATIVE_FILE_PATTERN.fullmatch(value) is None
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("path must be one bounded portable relative path")
    return value


def _validate_versioned_key_id(value: str) -> str:
    parsed = urlsplit(value)
    parts = [part for part in parsed.path.split("/") if part]
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or not parsed.hostname.casefold().endswith(".vault.azure.net")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or len(parts) != 3
        or parts[0].casefold() != "keys"
        or re.fullmatch(r"[A-Za-z0-9-]{1,127}", parts[1]) is None
        or re.fullmatch(r"[A-Fa-f0-9]{32}", parts[2]) is None
    ):
        raise ValueError("keyVaultKeyId must be one exact versioned Key Vault key ID")
    return value


class Wc029TrustedUpstreamHandoff(_StrictAcceptanceModel):
    stage: Literal["foundation", "producer", "publisher"]
    deployment_id: str = Field(
        alias="deploymentId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$",
    )
    output_artifact_id: str = Field(
        alias="outputArtifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    handoff_path: str = Field(
        alias="handoffPath",
        min_length=1,
        max_length=2048,
    )
    content_sha256: str = Field(
        alias="contentSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @field_validator("content_sha256")
    @classmethod
    def validate_content_digest(cls, value: str) -> str:
        return _validate_digest(value, label="upstream contentSha256")


class Wc029DeploymentVersion(_StrictAcceptanceModel):
    deployment_id: str = Field(
        alias="deploymentId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$",
    )
    deployment_name: str = Field(
        alias="deploymentName",
        min_length=1,
        max_length=128,
    )
    stage: DeploymentStage
    subscription_id: str = Field(
        alias="subscriptionId",
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    )
    resource_group: str | None = Field(
        default=None,
        alias="resourceGroup",
        min_length=1,
        max_length=90,
    )
    location: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
    )
    template_path: str = Field(
        alias="templatePath",
        min_length=1,
        max_length=512,
    )
    template_sha256: str = Field(
        alias="templateSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    base_parameter_sha256: str = Field(
        alias="baseParameterSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    effective_parameter_sha256: str = Field(
        alias="effectiveParameterSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    parameter_bindings_sha256: str = Field(
        alias="parameterBindingsSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    upstream_handoffs: tuple[Wc029TrustedUpstreamHandoff, ...] = Field(
        default=(),
        alias="upstreamHandoffs",
        max_length=3,
    )

    @field_validator("deployment_name")
    @classmethod
    def validate_deployment_name(cls, value: str) -> str:
        return _validate_fixed_text(
            value,
            label="deploymentName",
            maximum_length=128,
        )

    @field_validator("template_sha256")
    @classmethod
    def validate_template_digest(cls, value: str) -> str:
        return _validate_digest(value, label="templateSha256")

    @model_validator(mode="after")
    def validate_scope_and_dependencies(self) -> Wc029DeploymentVersion:
        if (self.stage in {"foundation", "live-acceptance"}) != (self.resource_group is None):
            raise ValueError("trusted deployment scope does not match its stage")
        keys = tuple((item.stage, item.deployment_id) for item in self.upstream_handoffs)
        stage_rank = {"foundation": 0, "producer": 1, "publisher": 2}
        if keys != tuple(sorted(keys, key=lambda item: (stage_rank[item[0]], item[1]))) or len(
            keys
        ) != len(set(keys)):
            raise ValueError("upstreamHandoffs must be unique and stage ordered")
        _validate_portable_relative_path(self.template_path)
        return self


class Wc029ImageVersion(_StrictAcceptanceModel):
    component: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    image: str = Field(min_length=1, max_length=512)

    @field_validator("image")
    @classmethod
    def validate_image(cls, value: str) -> str:
        match = _IMAGE_PATTERN.fullmatch(value)
        if match is None or match.group("digest") == "0" * 64:
            raise ValueError("image must be one real lowercase digest-pinned reference")
        return value


class Wc029EndpointVersion(_StrictAcceptanceModel):
    endpoint_id: str = Field(
        alias="endpointId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$",
    )
    origin: str = Field(min_length=1, max_length=2048)
    allowed_paths: tuple[str, ...] = Field(
        alias="allowedPaths",
        min_length=1,
        max_length=32,
    )

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("endpoint origin must be credential-free HTTPS")
        return value.rstrip("/")

    @field_validator("allowed_paths")
    @classmethod
    def validate_allowed_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if (
            any(
                not value.startswith("/")
                or "//" in value
                or "?" in value
                or "#" in value
                or "\\" in value
                or len(value) > 512
                for value in values
            )
            or values != tuple(sorted(values))
            or len(values) != len(set(values))
        ):
            raise ValueError("endpoint paths must be unique sorted absolute URL paths")
        return values


class Wc029RbacBoundary(_StrictAcceptanceModel):
    boundary_id: str = Field(
        alias="boundaryId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$",
    )
    principal_id: str = Field(
        alias="principalId",
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    )
    forbidden_role_names: tuple[str, ...] = Field(
        alias="forbiddenRoleNames",
        min_length=1,
        max_length=64,
    )
    forbidden_scope_prefixes: tuple[str, ...] = Field(
        alias="forbiddenScopePrefixes",
        min_length=1,
        max_length=64,
    )
    boundary_digest: str = Field(
        alias="boundaryDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("boundaryDigest")
        return payload

    @model_validator(mode="after")
    def validate_boundary(self) -> Wc029RbacBoundary:
        roles = tuple(item.casefold() for item in self.forbidden_role_names)
        scopes = tuple(item.casefold().rstrip("/") for item in self.forbidden_scope_prefixes)
        if (
            roles != tuple(sorted(roles))
            or len(roles) != len(set(roles))
            or scopes != tuple(sorted(scopes))
            or len(scopes) != len(set(scopes))
        ):
            raise ValueError("RBAC boundary roles and scopes must be unique and sorted")
        if self.boundary_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("boundaryDigest does not bind the RBAC boundary")
        return self


class Wc029ScenarioCapability(_StrictAcceptanceModel):
    scenario_class: ScenarioClass = Field(alias="scenarioClass")
    target_resource_id: str = Field(
        alias="targetResourceId",
        min_length=1,
        max_length=2048,
    )
    mutation_action_digest: str = Field(
        alias="mutationActionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    recovery_action_digest: str = Field(
        alias="recoveryActionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    incident_producer_schema_version: Literal["athena.incidentState.v1"] | None = Field(
        default=None,
        alias="incidentProducerSchemaVersion",
    )
    capability_digest: str = Field(
        alias="capabilityDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("capabilityDigest")
        return payload

    @property
    def evidence_mode(self) -> ScenarioMode:
        return (
            "incident-producing"
            if self.incident_producer_schema_version is not None
            else "correlation-only"
        )

    @model_validator(mode="after")
    def validate_capability(self) -> Wc029ScenarioCapability:
        if _RESOURCE_ID_PATTERN.fullmatch(self.target_resource_id) is None:
            raise ValueError("scenario capability target must be a complete resource ID")
        if self.capability_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("capabilityDigest does not bind scenario capability")
        return self


class Wc029PublishedClause(_StrictAcceptanceModel):
    clause_id: str = Field(
        alias="clauseId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    json_pointer: str = Field(
        alias="jsonPointer",
        min_length=1,
        max_length=512,
        pattern=r"^/(?:[^/~]|~0|~1)+(?:/(?:[^/~]|~0|~1)+)*$",
    )
    clause_digest: str = Field(
        alias="clauseDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )


def _resolve_json_pointer(document: object, pointer: str) -> object:
    current = document
    for raw_segment in pointer.removeprefix("/").split("/"):
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if segment not in current:
                raise ValueError("manifest clause JSON pointer is unresolved")
            current = current[segment]
        elif isinstance(current, list):
            if not segment.isdigit():
                raise ValueError("manifest clause array pointer is invalid")
            index = int(segment)
            if index >= len(current):
                raise ValueError("manifest clause array pointer is unresolved")
            current = current[index]
        else:
            raise ValueError("manifest clause JSON pointer crosses a scalar")
    return current


class Wc029PublishedManifestEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029PublishedManifest.v1"] = Field(alias="schemaVersion")
    workload_id: str = Field(
        alias="workloadId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    manifest_id: str = Field(alias="manifestId", min_length=1, max_length=128)
    manifest_version: str = Field(
        alias="manifestVersion",
        min_length=1,
        max_length=256,
    )
    profile_id: str = Field(alias="profileId", min_length=1, max_length=128)
    manifest_document: dict[str, Any] = Field(alias="manifestDocument")
    cited_clauses: tuple[Wc029PublishedClause, ...] = Field(
        alias="citedClauses",
        min_length=1,
        max_length=128,
    )
    publication_record_digest: str = Field(
        alias="publicationRecordDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    audit_head_digest: str = Field(
        alias="auditHeadDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    published_at: UtcDateTime = Field(alias="publishedAt")
    manifest_digest: str = Field(
        alias="manifestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @model_validator(mode="after")
    def validate_manifest(self) -> Wc029PublishedManifestEvidence:
        if not self.manifest_document:
            raise ValueError("published manifest document must not be empty")
        if (
            self.manifest_document.get("manifestId") != self.manifest_id
            or self.manifest_document.get("manifestVersion") != self.manifest_version
        ):
            raise ValueError("published manifest coordinates do not match its document")
        if self.manifest_digest != compute_artifact_digest(self.manifest_document):
            raise ValueError("manifestDigest does not bind manifestDocument")
        clause_ids = tuple(item.clause_id for item in self.cited_clauses)
        pointers = tuple(item.json_pointer for item in self.cited_clauses)
        if (
            clause_ids != tuple(sorted(clause_ids))
            or len(clause_ids) != len(set(clause_ids))
            or len(pointers) != len(set(pointers))
        ):
            raise ValueError("cited manifest clauses must be unique and sorted")
        for clause in self.cited_clauses:
            resolved_clause = _resolve_json_pointer(
                self.manifest_document,
                clause.json_pointer,
            )
            if (
                not isinstance(resolved_clause, dict)
                or resolved_clause.get("clauseId") != clause.clause_id
                or clause.clause_digest != compute_artifact_digest(resolved_clause)
            ):
                raise ValueError("cited clause digest does not bind manifest content")
        return self


class Wc029PublicationAuthorityEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029PublicationAuthority.v1"] = Field(alias="schemaVersion")
    authority: PublishedContextAuthority


class Wc029PublicationAuthorityAttestation(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029PublicationAuthorityAttestation.v1"] = Field(
        alias="schemaVersion"
    )
    authority_id: str = Field(
        alias="authorityId",
        pattern=r"^publication-authority-[a-f0-9]{32}$",
    )
    authority_digest: str = Field(
        alias="authorityDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        min_length=1,
        max_length=512,
    )
    signed_preimage_digest: str = Field(
        alias="signedPreimageDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    detached_signature: str = Field(
        alias="detachedSignature",
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=1,
        max_length=8192,
    )


class Wc029ManifestVersion(_StrictAcceptanceModel):
    manifest_id: str = Field(alias="manifestId", min_length=1, max_length=128)
    manifest_version: str = Field(
        alias="manifestVersion",
        min_length=1,
        max_length=256,
    )
    profile_id: str = Field(alias="profileId", min_length=1, max_length=128)
    manifest_digest: str = Field(
        alias="manifestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    publication_status: Literal["published"] = Field(alias="publicationStatus")
    manifest_artifact_id: str = Field(
        alias="manifestArtifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    manifest_artifact_sha256: str = Field(
        alias="manifestArtifactSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    cited_clause_map_digest: str = Field(
        alias="citedClauseMapDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    authority_artifact_id: str = Field(
        alias="authorityArtifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    authority_attestation_artifact_id: str = Field(
        alias="authorityAttestationArtifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    authority_digest: str = Field(
        alias="authorityDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @field_validator("manifest_id", "profile_id")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _validate_fixed_text(value, label="manifest identifier", maximum_length=128)

    @field_validator("manifest_version")
    @classmethod
    def validate_manifest_version(cls, value: str) -> str:
        if _VERSION_PATTERN.fullmatch(value) is None:
            raise ValueError("manifestVersion is not a bounded exact version")
        return value

    @field_validator("manifest_digest")
    @classmethod
    def validate_manifest_digest(cls, value: str) -> str:
        return _validate_digest(value, label="manifestDigest")

    @model_validator(mode="after")
    def validate_publication_coordinates(self) -> Wc029ManifestVersion:
        _validate_digest(self.authority_digest, label="authorityDigest")
        _validate_digest(
            self.manifest_artifact_sha256,
            label="manifestArtifactSha256",
        )
        _validate_digest(
            self.cited_clause_map_digest,
            label="citedClauseMapDigest",
        )
        if (
            len(
                {
                    self.manifest_artifact_id,
                    self.authority_artifact_id,
                    self.authority_attestation_artifact_id,
                }
            )
            != 3
        ):
            raise ValueError("manifest publication artifact IDs must be distinct")
        return self


class Wc029KeyVersion(_StrictAcceptanceModel):
    purpose: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        min_length=1,
        max_length=512,
    )
    public_key_fingerprint: str = Field(
        alias="publicKeyFingerprint",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    public_key_artifact_id: str = Field(
        alias="publicKeyArtifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )

    @model_validator(mode="after")
    def validate_versioned_key(self) -> Wc029KeyVersion:
        _validate_digest(
            self.public_key_fingerprint,
            label="publicKeyFingerprint",
        )
        _validate_versioned_key_id(self.key_vault_key_id)
        return self


class Wc029VersionInventory(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029VersionInventory.v1"] = Field(alias="schemaVersion")
    source_commit: str = Field(alias="sourceCommit", pattern=r"^[a-f0-9]{40}$")
    deployments: tuple[Wc029DeploymentVersion, ...] = Field(
        min_length=1,
        max_length=32,
    )
    images: tuple[Wc029ImageVersion, ...] = Field(min_length=1, max_length=64)
    endpoints: tuple[Wc029EndpointVersion, ...] = Field(min_length=1, max_length=32)
    rbac_boundaries: tuple[Wc029RbacBoundary, ...] = Field(
        alias="rbacBoundaries",
        min_length=1,
        max_length=128,
    )
    capability_deployment_id: str = Field(
        alias="capabilityDeploymentId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$",
    )
    scenario_capabilities: tuple[Wc029ScenarioCapability, ...] = Field(
        alias="scenarioCapabilities",
        min_length=len(REQUIRED_SCENARIO_CLASSES),
        max_length=len(REQUIRED_SCENARIO_CLASSES),
    )
    manifest: Wc029ManifestVersion
    keys: tuple[Wc029KeyVersion, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_inventory(self) -> Wc029VersionInventory:
        if self.source_commit == "0" * 40:
            raise ValueError("sourceCommit must not be the all-zero commit")
        collections: tuple[tuple[str, tuple[str, ...]], ...] = (
            (
                "deployment IDs",
                tuple(item.deployment_id for item in self.deployments),
            ),
            (
                "deployment names",
                tuple(item.deployment_name.casefold() for item in self.deployments),
            ),
            (
                "image components",
                tuple(item.component for item in self.images),
            ),
            (
                "image references",
                tuple(item.image for item in self.images),
            ),
            (
                "endpoint IDs",
                tuple(item.endpoint_id for item in self.endpoints),
            ),
            (
                "endpoint origins",
                tuple(item.origin.casefold() for item in self.endpoints),
            ),
            (
                "RBAC boundary IDs",
                tuple(item.boundary_id for item in self.rbac_boundaries),
            ),
            (
                "RBAC boundary digests",
                tuple(item.boundary_digest for item in self.rbac_boundaries),
            ),
            (
                "scenario capability digests",
                tuple(item.capability_digest for item in self.scenario_capabilities),
            ),
            (
                "key purposes",
                tuple(item.purpose for item in self.keys),
            ),
            (
                "Key Vault key IDs",
                tuple(item.key_vault_key_id.casefold() for item in self.keys),
            ),
            (
                "key fingerprints",
                tuple(item.public_key_fingerprint for item in self.keys),
            ),
            (
                "public key artifact IDs",
                tuple(item.public_key_artifact_id for item in self.keys),
            ),
        )
        for label, values in collections:
            if len(values) != len(set(values)):
                raise ValueError(f"version inventory {label} must be unique")
        if tuple(item.deployment_id for item in self.deployments) != tuple(
            sorted(item.deployment_id for item in self.deployments)
        ):
            raise ValueError("deployments must be sorted by deploymentId")
        if tuple(item.component for item in self.images) != tuple(
            sorted(item.component for item in self.images)
        ):
            raise ValueError("images must be sorted by component")
        if tuple(item.endpoint_id for item in self.endpoints) != tuple(
            sorted(item.endpoint_id for item in self.endpoints)
        ):
            raise ValueError("endpoints must be sorted by endpointId")
        if tuple(item.boundary_id for item in self.rbac_boundaries) != tuple(
            sorted(item.boundary_id for item in self.rbac_boundaries)
        ):
            raise ValueError("rbacBoundaries must be sorted by boundaryId")
        capability_classes = tuple(item.scenario_class for item in self.scenario_capabilities)
        if capability_classes != tuple(sorted(REQUIRED_SCENARIO_CLASSES)) or set(
            capability_classes
        ) != set(REQUIRED_SCENARIO_CLASSES):
            raise ValueError("scenarioCapabilities must cover every required scenario class")
        if {item.evidence_mode for item in self.scenario_capabilities} != {
            "correlation-only",
            "incident-producing",
        }:
            raise ValueError("trusted scenario capabilities must exercise both evidence modes")
        deployment_ids = {item.deployment_id for item in self.deployments}
        stage_rank = {
            "foundation": 0,
            "producer": 1,
            "publisher": 2,
            "live-acceptance": 3,
        }
        deployment_by_id = {item.deployment_id: item for item in self.deployments}
        for deployment in self.deployments:
            if any(
                upstream.deployment_id not in deployment_ids
                or upstream.deployment_id == deployment.deployment_id
                or deployment_by_id[upstream.deployment_id].stage != upstream.stage
                or stage_rank[upstream.stage] >= stage_rank[deployment.stage]
                for upstream in deployment.upstream_handoffs
            ):
                raise ValueError("trusted deployment upstream roots are missing or out of order")
        if self.capability_deployment_id not in deployment_ids:
            raise ValueError("capabilityDeploymentId must identify one trusted deployment root")
        if tuple(item.purpose for item in self.keys) != tuple(
            sorted(item.purpose for item in self.keys)
        ):
            raise ValueError("keys must be sorted by purpose")
        required_key_purposes = {
            "change",
            "context-authority",
            "enrichment",
            "feed",
            "guidance",
            "incident",
            "monitoring",
            "notification",
            "report",
            "scenario-authority",
        }
        if {item.purpose for item in self.keys} != required_key_purposes:
            raise ValueError("trusted inventory must contain every independent signing purpose")
        manifest_artifact_ids = {
            self.manifest.manifest_artifact_id,
            self.manifest.authority_artifact_id,
            self.manifest.authority_attestation_artifact_id,
        }
        if len(manifest_artifact_ids) != 3:
            raise ValueError("manifest publication artifact IDs must be distinct")
        return self


class Wc029SigningPublicKeyEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029SigningPublicKey.v1"] = Field(alias="schemaVersion")
    purpose: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        min_length=1,
        max_length=512,
    )
    public_key_fingerprint: str = Field(
        alias="publicKeyFingerprint",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    public_key_pem: str = Field(
        alias="publicKeyPem",
        min_length=1,
        max_length=16 * 1024,
    )

    @model_validator(mode="after")
    def validate_public_key(self) -> Wc029SigningPublicKeyEvidence:
        _validate_versioned_key_id(self.key_vault_key_id)
        _validate_digest(
            self.public_key_fingerprint,
            label="publicKeyFingerprint",
        )
        public_key = self.rsa_public_key()
        fingerprint = sha256_hex(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        if fingerprint != self.public_key_fingerprint:
            raise ValueError("publicKeyFingerprint does not match publicKeyPem")
        return self

    def rsa_public_key(self) -> rsa.RSAPublicKey:
        try:
            public_key = serialization.load_pem_public_key(self.public_key_pem.encode("ascii"))
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise ValueError("publicKeyPem is not valid ASCII PEM") from exc
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
            raise ValueError("publicKeyPem must contain an RSA key of at least 2048 bits")
        return public_key


class Wc029DeploymentPlanEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029DeploymentPlan.v1"] = Field(alias="schemaVersion")
    stage: DeploymentStage
    source_commit: str = Field(alias="sourceCommit", pattern=r"^[a-f0-9]{40}$")
    subscription_id: str = Field(alias="subscriptionId", min_length=1, max_length=64)
    location: str = Field(min_length=1, max_length=64)
    resource_group: str | None = Field(
        default=None,
        alias="resourceGroup",
        min_length=1,
        max_length=90,
    )
    deployment_name: str = Field(
        alias="deploymentName",
        min_length=1,
        max_length=128,
    )
    template_path: str = Field(alias="templatePath", min_length=1, max_length=512)
    template_sha256: str = Field(
        alias="templateSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    orchestrator_sha256: str = Field(
        alias="orchestratorSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    preflight_sha256: str = Field(
        alias="preflightSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    base_parameter_path: str = Field(
        alias="baseParameterPath",
        min_length=1,
        max_length=2048,
    )
    base_parameter_sha256: str = Field(
        alias="baseParameterSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    effective_parameter_path: str = Field(
        alias="effectiveParameterPath",
        min_length=1,
        max_length=2048,
    )
    effective_parameter_sha256: str = Field(
        alias="effectiveParameterSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    what_if_path: str = Field(alias="whatIfPath", min_length=1, max_length=2048)
    what_if_sha256: str = Field(
        alias="whatIfSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    allowed_change_resource_ids: tuple[str, ...] = Field(
        alias="allowedChangeResourceIds",
        max_length=512,
    )
    foundation_handoff_path: str | None = Field(
        default=None,
        alias="foundationHandoffPath",
        min_length=1,
        max_length=2048,
    )
    foundation_handoff_sha256: str | None = Field(
        default=None,
        alias="foundationHandoffSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    producer_handoff_path: str | None = Field(
        default=None,
        alias="producerHandoffPath",
        min_length=1,
        max_length=2048,
    )
    producer_handoff_sha256: str | None = Field(
        default=None,
        alias="producerHandoffSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    publisher_handoff_path: str | None = Field(
        default=None,
        alias="publisherHandoffPath",
        min_length=1,
        max_length=2048,
    )
    publisher_handoff_sha256: str | None = Field(
        default=None,
        alias="publisherHandoffSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @model_validator(mode="after")
    def validate_plan(self) -> Wc029DeploymentPlanEvidence:
        if self.source_commit == "0" * 40:
            raise ValueError("deployment plan sourceCommit must not be all zero")
        if (self.stage in {"foundation", "live-acceptance"}) != (self.resource_group is None):
            raise ValueError("deployment plan scope does not match its stage")
        if tuple(item.casefold() for item in self.allowed_change_resource_ids) != tuple(
            sorted(item.casefold() for item in self.allowed_change_resource_ids)
        ) or len({item.casefold() for item in self.allowed_change_resource_ids}) != len(
            self.allowed_change_resource_ids
        ):
            raise ValueError("allowedChangeResourceIds must be unique and sorted")
        for label, path_value, digest_value in (
            (
                "foundation handoff",
                self.foundation_handoff_path,
                self.foundation_handoff_sha256,
            ),
            (
                "producer handoff",
                self.producer_handoff_path,
                self.producer_handoff_sha256,
            ),
            (
                "publisher handoff",
                self.publisher_handoff_path,
                self.publisher_handoff_sha256,
            ),
        ):
            if (path_value is None) != (digest_value is None):
                raise ValueError(f"{label} path and digest must be supplied together")
        return self


class Wc029DeploymentHandoffEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029DeploymentHandoff.v1"] = Field(alias="schemaVersion")
    stage: DeploymentStage
    source_commit: str = Field(alias="sourceCommit", pattern=r"^[a-f0-9]{40}$")
    subscription_id: str = Field(alias="subscriptionId", min_length=1, max_length=64)
    resource_group: str | None = Field(
        default=None,
        alias="resourceGroup",
        min_length=1,
        max_length=90,
    )
    deployment_name: str = Field(
        alias="deploymentName",
        min_length=1,
        max_length=128,
    )
    outputs: dict[str, Any]
    outputs_sha256: str = Field(
        alias="outputsSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    parameter_bindings: dict[str, Any] = Field(alias="parameterBindings")
    parameter_bindings_sha256: str = Field(
        alias="parameterBindingsSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    plan_manifest_sha256: str = Field(
        alias="planManifestSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @model_validator(mode="after")
    def validate_handoff(self) -> Wc029DeploymentHandoffEvidence:
        if not self.outputs:
            raise ValueError("deployment output handoff must contain outputs")
        if self.outputs_sha256 != sha256_hex(canonicalize_json(self.outputs)):
            raise ValueError("outputsSha256 does not bind deployment outputs")
        if self.parameter_bindings_sha256 != sha256_hex(canonicalize_json(self.parameter_bindings)):
            raise ValueError("parameterBindingsSha256 does not bind deployment parameters")
        if (self.stage in {"foundation", "live-acceptance"}) != (self.resource_group is None):
            raise ValueError("deployment handoff scope does not match its stage")
        return self


class Wc029DeploymentReadbackEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029DeploymentReadback.v1"] = Field(alias="schemaVersion")
    stage: DeploymentStage
    source_commit: str = Field(alias="sourceCommit", pattern=r"^[a-f0-9]{40}$")
    subscription_id: str = Field(alias="subscriptionId", min_length=1, max_length=64)
    resource_group: str | None = Field(
        default=None,
        alias="resourceGroup",
        min_length=1,
        max_length=90,
    )
    location: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
    )
    deployment_name: str = Field(
        alias="deploymentName",
        min_length=1,
        max_length=128,
    )
    template_path: str = Field(
        alias="templatePath",
        min_length=1,
        max_length=512,
    )
    template_sha256: str = Field(
        alias="templateSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    base_parameter_sha256: str = Field(
        alias="baseParameterSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    effective_parameter_sha256: str = Field(
        alias="effectiveParameterSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    parameter_bindings_sha256: str = Field(
        alias="parameterBindingsSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    upstream_handoffs: tuple[Wc029TrustedUpstreamHandoff, ...] = Field(
        alias="upstreamHandoffs",
        max_length=3,
    )
    observed_at: UtcDateTime = Field(alias="observedAt")
    provisioning_state: Literal["Succeeded"] = Field(alias="provisioningState")
    output_handoff_sha256: str = Field(
        alias="outputHandoffSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    outputs: dict[str, Any]
    outputs_sha256: str = Field(
        alias="outputsSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @model_validator(mode="after")
    def validate_readback(self) -> Wc029DeploymentReadbackEvidence:
        if not self.outputs:
            raise ValueError("deployment read-back must contain outputs")
        if self.outputs_sha256 != sha256_hex(canonicalize_json(self.outputs)):
            raise ValueError("deployment read-back outputs digest is invalid")
        _validate_portable_relative_path(self.template_path)
        keys = tuple((item.stage, item.deployment_id) for item in self.upstream_handoffs)
        stage_rank = {"foundation": 0, "producer": 1, "publisher": 2}
        if keys != tuple(sorted(keys, key=lambda item: (stage_rank[item[0]], item[1]))) or len(
            keys
        ) != len(set(keys)):
            raise ValueError("upstreamHandoffs must be unique and stage ordered")
        return self


class Wc029ArtifactDigestReference(_StrictAcceptanceModel):
    artifact_id: str = Field(
        alias="artifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    content_sha256: str = Field(
        alias="contentSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @field_validator("content_sha256")
    @classmethod
    def validate_content_digest(cls, value: str) -> str:
        return _validate_digest(value, label="contentSha256")


class Wc029JobExecutionEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029JobExecution.v1"] = Field(alias="schemaVersion")
    scope: JobScope
    scenario_id: str | None = Field(
        default=None,
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_execution_id: str | None = Field(
        default=None,
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    scenario_plan_digest: str | None = Field(
        default=None,
        alias="scenarioPlanDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    input_digest: str = Field(
        alias="inputDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    phase: ScenarioPhase | None = None
    execution_id: str = Field(
        alias="executionId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )
    job_resource_id: str = Field(
        alias="jobResourceId",
        min_length=1,
        max_length=2048,
    )
    source_commit: str = Field(alias="sourceCommit", pattern=r"^[a-f0-9]{40}$")
    component: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    image: str = Field(min_length=1, max_length=512)
    started_at: UtcDateTime = Field(alias="startedAt")
    completed_at: UtcDateTime = Field(alias="completedAt")
    status: Literal["Succeeded"]
    exit_code: Literal[0] = Field(alias="exitCode")
    execution_digest: str = Field(
        alias="executionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("executionDigest")
        return payload

    @model_validator(mode="after")
    def validate_execution(self) -> Wc029JobExecutionEvidence:
        scenario_values = (
            self.scenario_id,
            self.scenario_execution_id,
            self.scenario_plan_digest,
            self.phase,
        )
        if (self.scope == "scenario") != all(item is not None for item in scenario_values):
            raise ValueError("scenario job execution requires scenario, execution, plan, and phase")
        if self.scope == "global" and any(item is not None for item in scenario_values):
            raise ValueError("global job execution cannot claim a scenario phase")
        if self.completed_at < self.started_at:
            raise ValueError("job completion precedes start")
        if _JOB_RESOURCE_ID_PATTERN.fullmatch(self.job_resource_id) is None:
            raise ValueError("jobResourceId must identify one Microsoft.App Job")
        Wc029ImageVersion(component=self.component, image=self.image)
        if self.execution_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("executionDigest does not bind the Job execution")
        return self


class Wc029JobReadbackEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029JobReadback.v1"] = Field(alias="schemaVersion")
    scope: JobScope
    scenario_id: str | None = Field(
        default=None,
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_execution_id: str | None = Field(
        default=None,
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    scenario_plan_digest: str | None = Field(
        default=None,
        alias="scenarioPlanDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    phase: ScenarioPhase | None = None
    execution_id: str = Field(
        alias="executionId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )
    execution_digest: str = Field(
        alias="executionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    job_resource_id: str = Field(
        alias="jobResourceId",
        min_length=1,
        max_length=2048,
    )
    source_commit: str = Field(alias="sourceCommit", pattern=r"^[a-f0-9]{40}$")
    component: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    image: str = Field(min_length=1, max_length=512)
    observed_at: UtcDateTime = Field(alias="observedAt")
    provisioning_state: Literal["Succeeded"] = Field(alias="provisioningState")
    status: Literal["Succeeded"]
    result_artifacts: tuple[Wc029ArtifactDigestReference, ...] = Field(
        alias="resultArtifacts",
        min_length=1,
        max_length=64,
    )
    readback_digest: str = Field(
        alias="readbackDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("readbackDigest")
        return payload

    @model_validator(mode="after")
    def validate_readback(self) -> Wc029JobReadbackEvidence:
        scenario_values = (
            self.scenario_id,
            self.scenario_execution_id,
            self.scenario_plan_digest,
            self.phase,
        )
        if (self.scope == "scenario") != all(item is not None for item in scenario_values):
            raise ValueError("scenario Job read-back requires scenario, execution, plan, and phase")
        if self.scope == "global" and any(item is not None for item in scenario_values):
            raise ValueError("global Job read-back cannot claim a scenario phase")
        Wc029ImageVersion(component=self.component, image=self.image)
        ids = tuple(item.artifact_id for item in self.result_artifacts)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("resultArtifacts must be unique and sorted")
        if self.readback_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("readbackDigest does not bind the Job read-back")
        return self


class Wc029PreflightResultEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029PreflightResult.v1"] = Field(alias="schemaVersion")
    kind: PreflightKind
    deployment_id: str | None = Field(
        default=None,
        alias="deploymentId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$",
    )
    input_artifact_id: str = Field(
        alias="inputArtifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    input_sha256: str = Field(
        alias="inputSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    policy_artifact_id: str | None = Field(
        default=None,
        alias="policyArtifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    policy_sha256: str | None = Field(
        default=None,
        alias="policySha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    validator_sha256: str = Field(
        alias="validatorSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    safe: Literal[True]
    violations: tuple[()] = ()

    @model_validator(mode="after")
    def validate_preflight(self) -> Wc029PreflightResultEvidence:
        if self.kind == "what-if":
            if (
                self.deployment_id is None
                or self.policy_artifact_id is not None
                or self.policy_sha256 is not None
            ):
                raise ValueError("what-if preflight requires only deploymentId and input")
        elif (
            self.deployment_id is not None
            or self.policy_artifact_id is None
            or self.policy_sha256 is None
        ):
            raise ValueError("RBAC preflight requires input and policy artifacts")
        return self


class Wc029ScenarioPlanEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029ScenarioPlan.v1"] = Field(alias="schemaVersion")
    scenario_id: str = Field(
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_execution_id: str = Field(
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    scenario_class: ScenarioClass = Field(alias="scenarioClass")
    evidence_mode: ScenarioMode = Field(alias="evidenceMode")
    capability_digest: str = Field(
        alias="capabilityDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    source_commit: str = Field(alias="sourceCommit", pattern=r"^[a-f0-9]{40}$")
    target_resource_id: str = Field(
        alias="targetResourceId",
        min_length=1,
        max_length=2048,
    )
    baseline_state_digest: str = Field(
        alias="baselineStateDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    mutation_action_digest: str = Field(
        alias="mutationActionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    recovery_action_digest: str = Field(
        alias="recoveryActionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    monitoring_request_digest: str = Field(
        alias="monitoringRequestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    correlation_request_digest: str = Field(
        alias="correlationRequestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    change_request_digest: str | None = Field(
        default=None,
        alias="changeRequestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    verification_input_digest: str = Field(
        alias="verificationInputDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    baseline_state_artifact_id: str = Field(
        alias="baselineStateArtifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    planned_at: UtcDateTime = Field(alias="plannedAt")
    expected_signal_codes: tuple[str, ...] = Field(
        alias="expectedSignalCodes",
        min_length=1,
        max_length=32,
    )
    abort_thresholds: tuple[str, ...] = Field(
        alias="abortThresholds",
        min_length=1,
        max_length=32,
    )
    operator_approval_digest: str = Field(
        alias="operatorApprovalDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    plan_digest: str = Field(
        alias="planDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("planDigest")
        return payload

    @model_validator(mode="after")
    def validate_plan(self) -> Wc029ScenarioPlanEvidence:
        if _RESOURCE_ID_PATTERN.fullmatch(self.target_resource_id) is None:
            raise ValueError("scenario target must be a complete Azure resource ID")
        if (self.scenario_class == "nsg-connectivity-loss") != (
            self.change_request_digest is not None
        ):
            raise ValueError("changeRequestDigest is required only for NSG connectivity loss")
        for label, values in (
            ("expectedSignalCodes", self.expected_signal_codes),
            ("abortThresholds", self.abort_thresholds),
        ):
            if values != tuple(sorted(values)) or len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique and sorted")
        if self.plan_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("planDigest does not bind the scenario plan")
        return self


class Wc029MutationReceipt(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029MutationReceipt.v1"] = Field(alias="schemaVersion")
    scenario_id: str = Field(
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_execution_id: str = Field(
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    scenario_class: ScenarioClass = Field(alias="scenarioClass")
    plan_digest: str | None = Field(
        default=None,
        alias="planDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    target_resource_id: str = Field(
        alias="targetResourceId",
        min_length=1,
        max_length=2048,
    )
    mutation_action_digest: str = Field(
        alias="mutationActionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    applied_at: UtcDateTime = Field(alias="appliedAt")
    completed: Literal[True]
    result_digest: str = Field(
        alias="resultDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("resultDigest")
        return payload

    @model_validator(mode="after")
    def validate_receipt(self) -> Wc029MutationReceipt:
        if self.result_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("resultDigest does not bind the mutation receipt")
        return self


class Wc029RecoveryActionEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029RecoveryAction.v1"] = Field(alias="schemaVersion")
    scenario_id: str = Field(
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_execution_id: str = Field(
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    scenario_class: ScenarioClass = Field(alias="scenarioClass")
    plan_digest: str = Field(
        alias="planDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    mutation_receipt_digest: str = Field(
        alias="mutationReceiptDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    target_resource_id: str = Field(
        alias="targetResourceId",
        min_length=1,
        max_length=2048,
    )
    recovery_action_digest: str = Field(
        alias="recoveryActionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    recovered_at: UtcDateTime = Field(alias="recoveredAt")
    completed: Literal[True]
    result_digest: str = Field(
        alias="resultDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("resultDigest")
        return payload

    @model_validator(mode="after")
    def validate_action(self) -> Wc029RecoveryActionEvidence:
        if self.result_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("resultDigest does not bind the recovery action")
        return self


class Wc029ManifestCitationEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029ManifestCitation.v1"] = Field(alias="schemaVersion")
    scenario_id: str = Field(
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_execution_id: str = Field(
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    manifest_id: str = Field(alias="manifestId", min_length=1, max_length=128)
    manifest_version: str = Field(
        alias="manifestVersion",
        min_length=1,
        max_length=256,
    )
    profile_id: str = Field(alias="profileId", min_length=1, max_length=128)
    manifest_digest: str = Field(
        alias="manifestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    correlation_report_id: str = Field(
        alias="correlationReportId",
        pattern=r"^report-[a-f0-9]{32}$",
    )
    correlation_report_digest: str = Field(
        alias="correlationReportDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    incident_state_result_digest: str = Field(
        alias="incidentStateResultDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    clause_ids: tuple[str, ...] = Field(alias="clauseIds", min_length=1, max_length=64)
    citation_digest: str = Field(
        alias="citationDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("citationDigest")
        return payload

    @model_validator(mode="after")
    def validate_citation(self) -> Wc029ManifestCitationEvidence:
        if self.clause_ids != tuple(sorted(self.clause_ids)) or len(self.clause_ids) != len(
            set(self.clause_ids)
        ):
            raise ValueError("clauseIds must be unique and sorted")
        if self.citation_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("citationDigest does not bind the manifest citation")
        return self


class Wc029QueueState(_StrictAcceptanceModel):
    namespace: str = Field(min_length=1, max_length=256)
    queue_name: str = Field(alias="queueName", min_length=1, max_length=128)
    active_message_count: Literal[0] = Field(alias="activeMessageCount")
    dead_letter_message_count: Literal[0] = Field(alias="deadLetterMessageCount")
    transfer_dead_letter_message_count: Literal[0] = Field(alias="transferDeadLetterMessageCount")

    @field_validator("namespace", "queue_name")
    @classmethod
    def validate_queue_text(cls, value: str) -> str:
        return _validate_fixed_text(value, label="queue coordinate", maximum_length=256)


class Wc029QueueStateEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029QueueState.v1"] = Field(alias="schemaVersion")
    capture_scope: QueueScope = Field(alias="captureScope")
    scenario_id: str | None = Field(
        default=None,
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_execution_id: str | None = Field(
        default=None,
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    captured_at: UtcDateTime = Field(alias="capturedAt")
    queues: tuple[Wc029QueueState, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_scope(self) -> Wc029QueueStateEvidence:
        if (self.capture_scope == "scenario-verify") != (
            self.scenario_id is not None and self.scenario_execution_id is not None
        ):
            raise ValueError(
                "scenarioId and scenarioExecutionId are required only for scenario-verify"
            )
        if self.capture_scope != "scenario-verify" and (
            self.scenario_id is not None or self.scenario_execution_id is not None
        ):
            raise ValueError("global queue evidence cannot claim a scenario execution")
        keys = tuple(
            (item.namespace.casefold(), item.queue_name.casefold()) for item in self.queues
        )
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("queue evidence must contain unique sorted queue coordinates")
        return self


class Wc029UrlProbeEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029UrlProbe.v1"] = Field(alias="schemaVersion")
    probe_id: str = Field(
        alias="probeId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    endpoint_id: str = Field(
        alias="endpointId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$",
    )
    url: str = Field(min_length=1, max_length=2048)
    observed_at: UtcDateTime = Field(alias="observedAt")
    status_code: Literal[200] = Field(alias="statusCode")
    content_type: str = Field(alias="contentType", min_length=1, max_length=256)
    response_body_sha256: str = Field(
        alias="responseBodySha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    tls_verified: Literal[True] = Field(alias="tlsVerified")
    approved_network_location: Literal[True] = Field(alias="approvedNetworkLocation")

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("probe URL must be credential-free HTTPS")
        return value

    @field_validator("content_type")
    @classmethod
    def validate_content_type(cls, value: str) -> str:
        return _validate_fixed_text(
            value,
            label="contentType",
            maximum_length=256,
        )

    @field_validator("response_body_sha256")
    @classmethod
    def validate_body_digest(cls, value: str) -> str:
        return _validate_digest(value, label="responseBodySha256")


class Wc029IncidentOmission(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029IncidentOmission.v1"] = Field(alias="schemaVersion")
    scenario_id: str = Field(
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_execution_id: str = Field(
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    reason_code: Literal["unsupported-incident-producer"] = Field(alias="reasonCode")
    incident_evidence_expected: Literal[False] = Field(alias="incidentEvidenceExpected")
    incident_evidence_observed: Literal[False] = Field(alias="incidentEvidenceObserved")
    synthetic_incident_evidence_created: Literal[False] = Field(
        alias="syntheticIncidentEvidenceCreated"
    )
    observed_at: UtcDateTime = Field(alias="observedAt")
    detail: str = Field(min_length=1, max_length=512)

    @field_validator("detail")
    @classmethod
    def validate_detail(cls, value: str) -> str:
        return _validate_fixed_text(value, label="omission detail", maximum_length=512)


class Wc029ResourceStateEvidence(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029ResourceState.v1"] = Field(alias="schemaVersion")
    capture_kind: Literal["baseline", "recovered"] = Field(alias="captureKind")
    scenario_id: str = Field(
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_execution_id: str = Field(
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    scenario_class: ScenarioClass = Field(alias="scenarioClass")
    plan_digest: str | None = Field(
        default=None,
        alias="planDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    mutation_receipt_digest: str | None = Field(
        default=None,
        alias="mutationReceiptDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    target_resource_id: str = Field(
        alias="targetResourceId",
        min_length=1,
        max_length=2048,
    )
    captured_at: UtcDateTime = Field(alias="capturedAt")
    state_document: dict[str, Any] = Field(alias="stateDocument")
    state_digest: str = Field(
        alias="stateDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @model_validator(mode="after")
    def validate_state(self) -> Wc029ResourceStateEvidence:
        if not self.state_document:
            raise ValueError("resource state document must not be empty")
        if (self.capture_kind == "recovered") != (
            self.mutation_receipt_digest is not None and self.plan_digest is not None
        ):
            raise ValueError(
                "planDigest and mutationReceiptDigest are required only for recovered state"
            )
        if self.capture_kind == "baseline" and (
            self.plan_digest is not None or self.mutation_receipt_digest is not None
        ):
            raise ValueError("baseline state cannot depend on future plan or mutation")
        expected = compute_artifact_digest(
            {
                "targetResourceId": self.target_resource_id.casefold().rstrip("/"),
                "stateDocument": self.state_document,
            }
        )
        if self.state_digest != expected:
            raise ValueError("stateDigest does not bind target and stateDocument")
        return self


class Wc029ScenarioPhaseWindow(_StrictAcceptanceModel):
    phase: ScenarioPhase
    started_at: UtcDateTime = Field(alias="startedAt")
    completed_at: UtcDateTime = Field(alias="completedAt")

    @model_validator(mode="after")
    def validate_window(self) -> Wc029ScenarioPhaseWindow:
        if self.completed_at < self.started_at:
            raise ValueError("scenario phase window completes before it starts")
        return self


class Wc029ScenarioArtifactBinding(_StrictAcceptanceModel):
    artifact_id: str = Field(
        alias="artifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    phase: ScenarioPhase
    content_sha256: str = Field(
        alias="contentSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    input_digest: str = Field(
        alias="inputDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )


class Wc029ScenarioExecutionManifest(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029ScenarioExecutionManifest.v1"] = Field(
        alias="schemaVersion"
    )
    scenario_execution_id: str = Field(
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    scenario_id: str = Field(
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_class: ScenarioClass = Field(alias="scenarioClass")
    evidence_mode: ScenarioMode = Field(alias="evidenceMode")
    capability_digest: str = Field(
        alias="capabilityDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    source_commit: str = Field(alias="sourceCommit", pattern=r"^[a-f0-9]{40}$")
    target_resource_id: str = Field(
        alias="targetResourceId",
        min_length=1,
        max_length=2048,
    )
    mutation_action_digest: str = Field(
        alias="mutationActionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    recovery_action_digest: str = Field(
        alias="recoveryActionDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    monitoring_request_digest: str = Field(
        alias="monitoringRequestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    correlation_request_digest: str = Field(
        alias="correlationRequestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    change_request_digest: str | None = Field(
        default=None,
        alias="changeRequestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    verification_input_digest: str = Field(
        alias="verificationInputDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    plan_digest: str = Field(
        alias="planDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    mutation_receipt_digest: str = Field(
        alias="mutationReceiptDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    recovery_action_result_digest: str = Field(
        alias="recoveryActionResultDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    phase_windows: tuple[Wc029ScenarioPhaseWindow, ...] = Field(
        alias="phaseWindows",
        min_length=5,
        max_length=5,
    )
    artifacts: tuple[Wc029ScenarioArtifactBinding, ...] = Field(
        min_length=1,
        max_length=128,
    )
    manifest_digest: str = Field(
        alias="manifestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("manifestDigest")
        return payload

    @model_validator(mode="after")
    def validate_manifest(self) -> Wc029ScenarioExecutionManifest:
        phases = tuple(item.phase for item in self.phase_windows)
        expected_phases: tuple[ScenarioPhase, ...] = (
            "plan",
            "apply",
            "observe",
            "recover",
            "verify",
        )
        if phases != expected_phases:
            raise ValueError("phaseWindows must use the exact lifecycle order")
        if any(
            current.completed_at > following.started_at
            for current, following in zip(
                self.phase_windows,
                self.phase_windows[1:],
                strict=False,
            )
        ):
            raise ValueError("scenario phase windows must not overlap")
        if self.phase_windows[-1].completed_at - self.phase_windows[0].started_at > timedelta(
            hours=24
        ):
            raise ValueError("scenario execution window must not exceed 24 hours")
        phase_rank = {
            "plan": 0,
            "apply": 1,
            "observe": 2,
            "recover": 3,
            "verify": 4,
        }
        keys = tuple((item.phase, item.artifact_id) for item in self.artifacts)
        if keys != tuple(sorted(keys, key=lambda item: (phase_rank[item[0]], item[1]))) or len(
            keys
        ) != len(set(keys)):
            raise ValueError("scenario artifact bindings must be unique and sorted")
        if self.manifest_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("manifestDigest does not bind scenario execution")
        return self


class Wc029ScenarioExecutionAttestation(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029ScenarioExecutionAttestation.v1"] = Field(
        alias="schemaVersion"
    )
    scenario_execution_id: str = Field(
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    manifest_digest: str = Field(
        alias="manifestDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        min_length=1,
        max_length=512,
    )
    signed_preimage_digest: str = Field(
        alias="signedPreimageDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    detached_signature: str = Field(
        alias="detachedSignature",
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=1,
        max_length=8192,
    )


class Wc029RecoveryProof(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029RecoveryProof.v1"] = Field(alias="schemaVersion")
    scenario_id: str = Field(
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_execution_id: str = Field(
        alias="scenarioExecutionId",
        pattern=r"^wc029-execution-[a-f0-9]{32}$",
    )
    scenario_class: ScenarioClass = Field(alias="scenarioClass")
    plan_digest: str = Field(
        alias="planDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    mutation_receipt_digest: str = Field(
        alias="mutationReceiptDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    recovery_action_result_digest: str = Field(
        alias="recoveryActionResultDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    target_resource_id: str = Field(
        alias="targetResourceId",
        min_length=1,
        max_length=2048,
    )
    verified_at: UtcDateTime = Field(alias="verifiedAt")
    healthy: Literal[True]
    residual_mutation_count: Literal[0] = Field(alias="residualMutationCount")
    baseline_state: Wc029ArtifactDigestReference = Field(alias="baselineState")
    recovered_state: Wc029ArtifactDigestReference = Field(alias="recoveredState")
    baseline_state_digest: str = Field(
        alias="baselineStateDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    recovered_state_digest: str = Field(
        alias="recoveredStateDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    post_recovery_job_readback: Wc029ArtifactDigestReference = Field(
        alias="postRecoveryJobReadback"
    )
    evidence_artifact_ids: tuple[str, ...] = Field(
        alias="evidenceArtifactIds",
        min_length=1,
        max_length=32,
    )

    @field_validator("baseline_state_digest", "recovered_state_digest")
    @classmethod
    def validate_state_digest(cls, value: str) -> str:
        return _validate_digest(value, label="recovery state digest")

    @model_validator(mode="after")
    def validate_recovery(self) -> Wc029RecoveryProof:
        if _RESOURCE_ID_PATTERN.fullmatch(self.target_resource_id) is None:
            raise ValueError("recovery proof target must be a complete Azure resource ID")
        if tuple(self.evidence_artifact_ids) != tuple(sorted(self.evidence_artifact_ids)) or len(
            self.evidence_artifact_ids
        ) != len(set(self.evidence_artifact_ids)):
            raise ValueError("recovery evidence artifact IDs must be unique and sorted")
        return self


class Wc029EvidenceFileDeclaration(_StrictAcceptanceModel):
    artifact_id: str = Field(
        alias="artifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    evidence_class: EvidenceClass = Field(alias="evidenceClass")
    path: str = Field(min_length=1, max_length=512)
    expected_sha256: str | None = Field(
        default=None,
        alias="expectedSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    expected_schema_version: str | None = Field(
        default=None,
        alias="expectedSchemaVersion",
        min_length=1,
        max_length=256,
    )
    deployment_id: str | None = Field(
        default=None,
        alias="deploymentId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$",
    )
    preflight_kind: PreflightKind | None = Field(
        default=None,
        alias="preflightKind",
    )
    queue_scope: QueueScope | None = Field(default=None, alias="queueScope")
    signing_key_purpose: str | None = Field(
        default=None,
        alias="signingKeyPurpose",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$",
    )
    binds_artifact_id: str | None = Field(
        default=None,
        alias="bindsArtifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _validate_relative_file(value)

    @field_validator("expected_sha256")
    @classmethod
    def validate_expected_digest(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_digest(value, label="expectedSha256")
        return value

    @field_validator("expected_schema_version")
    @classmethod
    def validate_expected_schema(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_fixed_text(
                value,
                label="expectedSchemaVersion",
                maximum_length=256,
            )
        return value

    @model_validator(mode="after")
    def validate_class_metadata(self) -> Wc029EvidenceFileDeclaration:
        expected_schema = _EXPECTED_SCHEMA_BY_CLASS[self.evidence_class]
        if self.expected_schema_version != expected_schema:
            raise ValueError(
                f"{self.evidence_class} requires expectedSchemaVersion {expected_schema!r}"
            )
        is_deployment = self.evidence_class in {
            "deployment-plan",
            "deployment-what-if",
            "deployment-output",
            "deployment-readback",
        }
        if is_deployment != (self.deployment_id is not None):
            raise ValueError("deploymentId is required only for deployment evidence")
        binding_classes = {
            "deployment-output",
            "deployment-readback",
            "job-readback",
            *_ATTESTATION_SUBJECT_CLASSES,
        }
        if (self.evidence_class in binding_classes) != (self.binds_artifact_id is not None):
            raise ValueError("bindsArtifactId is required only for exact paired evidence")
        if (self.evidence_class == "preflight-result") != (self.preflight_kind is not None):
            raise ValueError("preflightKind is required only for preflight-result evidence")
        if (self.evidence_class == "queue-state") != (self.queue_scope is not None):
            raise ValueError("queueScope is required only for queue-state evidence")
        expected_purpose = (
            self.signing_key_purpose
            if self.evidence_class == "signing-public-key"
            else _SIGNED_KEY_PURPOSE_BY_CLASS.get(self.evidence_class)
        )
        if self.evidence_class == "signing-public-key":
            if self.signing_key_purpose is None:
                raise ValueError("signing-public-key requires signingKeyPurpose")
        elif self.signing_key_purpose != expected_purpose:
            raise ValueError(
                f"{self.evidence_class} requires signingKeyPurpose {expected_purpose!r}"
            )
        return self


class Wc029ScenarioPhases(_StrictAcceptanceModel):
    plan: tuple[str, ...] = Field(min_length=1, max_length=32)
    apply: tuple[str, ...] = Field(min_length=1, max_length=32)
    observe: tuple[str, ...] = Field(min_length=1, max_length=64)
    recover: tuple[str, ...] = Field(min_length=1, max_length=32)
    verify: tuple[str, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_phase_references(self) -> Wc029ScenarioPhases:
        references = (*self.plan, *self.apply, *self.observe, *self.recover, *self.verify)
        if len(references) != len(set(references)):
            raise ValueError("scenario artifact IDs must not repeat across phases")
        return self

    def items(self) -> tuple[tuple[ScenarioPhase, tuple[str, ...]], ...]:
        return (
            ("plan", self.plan),
            ("apply", self.apply),
            ("observe", self.observe),
            ("recover", self.recover),
            ("verify", self.verify),
        )


class Wc029ScenarioEvidence(_StrictAcceptanceModel):
    scenario_id: str = Field(
        alias="scenarioId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    scenario_class: ScenarioClass = Field(alias="scenarioClass")
    evidence_mode: ScenarioMode = Field(alias="evidenceMode")
    phases: Wc029ScenarioPhases


class Wc029AcceptanceEvidenceIndex(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029AcceptanceEvidenceIndex.v1"] = Field(alias="schemaVersion")
    acceptance_id: str = Field(
        alias="acceptanceId",
        pattern=r"^wc029-acceptance-[a-z0-9][a-z0-9._-]{0,95}$",
    )
    version_inventory_artifact_id: str = Field(
        alias="versionInventoryArtifactId",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    artifacts: tuple[Wc029EvidenceFileDeclaration, ...] = Field(
        min_length=1,
        max_length=MAX_EVIDENCE_FILES,
    )
    global_artifact_ids: tuple[str, ...] = Field(
        alias="globalArtifactIds",
        min_length=1,
        max_length=MAX_EVIDENCE_FILES,
    )
    scenarios: tuple[Wc029ScenarioEvidence, ...] = Field(
        min_length=len(REQUIRED_SCENARIO_CLASSES),
        max_length=len(REQUIRED_SCENARIO_CLASSES),
    )

    @model_validator(mode="after")
    def validate_index(self) -> Wc029AcceptanceEvidenceIndex:
        artifact_ids = tuple(item.artifact_id for item in self.artifacts)
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("artifact IDs must be unique")
        normalized_paths = tuple(item.path.casefold() for item in self.artifacts)
        if len(normalized_paths) != len(set(normalized_paths)):
            raise ValueError("artifact paths must be unique case-insensitively")
        artifact_by_id = {item.artifact_id: item for item in self.artifacts}

        scenario_ids = tuple(item.scenario_id for item in self.scenarios)
        scenario_classes = tuple(item.scenario_class for item in self.scenarios)
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ValueError("scenario IDs must be unique")
        if set(scenario_classes) != set(REQUIRED_SCENARIO_CLASSES):
            raise ValueError("acceptance index must contain every required WC-029 scenario class")
        references = list(self.global_artifact_ids)
        for scenario in self.scenarios:
            for _phase, phase_ids in scenario.phases.items():
                references.extend(phase_ids)
        unknown = set(references) - set(artifact_ids)
        if unknown:
            raise ValueError(f"index references unknown artifact IDs: {sorted(unknown)}")
        counts = Counter(references)
        if any(count != 1 for count in counts.values()):
            raise ValueError("each artifact must be owned by exactly one global or scenario slot")
        if set(references) != set(artifact_ids):
            raise ValueError("every declared artifact must be included exactly once")

        if self.version_inventory_artifact_id not in self.global_artifact_ids:
            raise ValueError("version inventory must be global evidence")
        inventory_declaration = artifact_by_id[self.version_inventory_artifact_id]
        if inventory_declaration.evidence_class != "version-inventory":
            raise ValueError("versionInventoryArtifactId must name version-inventory evidence")

        global_declarations = tuple(
            artifact_by_id[artifact_id] for artifact_id in self.global_artifact_ids
        )
        global_class_counts = Counter(item.evidence_class for item in global_declarations)
        global_classes = set(global_class_counts)
        missing_global = _GLOBAL_REQUIRED_CLASSES - global_classes
        if missing_global:
            raise ValueError(
                f"global evidence is missing required classes: {sorted(missing_global)}"
            )
        singleton_classes: tuple[EvidenceClass, ...] = (
            "version-inventory",
            "published-manifest",
            "publication-authority",
            "publication-authority-attestation",
            "effective-rbac",
            "rbac-policy",
        )
        for singleton in singleton_classes:
            if global_class_counts[singleton] != 1:
                raise ValueError(f"global evidence requires exactly one {singleton}")
        preflight_kind_counts = Counter(
            item.preflight_kind
            for item in global_declarations
            if item.evidence_class == "preflight-result"
        )
        if preflight_kind_counts["rbac"] != 1 or preflight_kind_counts["what-if"] < 1:
            raise ValueError(
                "global evidence requires one RBAC and at least one what-if preflight result"
            )
        global_queue_scope_counts = Counter(
            item.queue_scope for item in global_declarations if item.evidence_class == "queue-state"
        )
        if global_queue_scope_counts != Counter({"baseline": 1, "final": 1}):
            raise ValueError(
                "global evidence requires exactly one baseline and final queue-state capture"
            )

        plan_ids: dict[str, str] = {}
        what_if_ids: dict[str, str] = {}
        output_ids: dict[str, str] = {}
        readback_ids: dict[str, str] = {}
        for item in global_declarations:
            if item.evidence_class == "deployment-plan":
                deployment_id = cast(str, item.deployment_id)
                if deployment_id in plan_ids:
                    raise ValueError("each deployment must have one reviewed plan")
                plan_ids[deployment_id] = item.artifact_id
            elif item.evidence_class == "deployment-what-if":
                deployment_id = cast(str, item.deployment_id)
                if deployment_id in what_if_ids:
                    raise ValueError("each deployment must have one saved what-if")
                what_if_ids[deployment_id] = item.artifact_id
            elif item.evidence_class == "deployment-output":
                deployment_id = cast(str, item.deployment_id)
                if deployment_id in output_ids:
                    raise ValueError("each deployment must have one output handoff")
                output_ids[deployment_id] = item.artifact_id
            elif item.evidence_class == "deployment-readback":
                deployment_id = cast(str, item.deployment_id)
                if deployment_id in readback_ids:
                    raise ValueError("each deployment must have one successful read-back")
                readback_ids[deployment_id] = item.artifact_id
        if (
            not plan_ids
            or plan_ids.keys() != what_if_ids.keys()
            or plan_ids.keys() != output_ids.keys()
            or plan_ids.keys() != readback_ids.keys()
            or preflight_kind_counts["what-if"] != len(plan_ids)
        ):
            raise ValueError(
                "plan, what-if, preflight, output, and read-back must cover identical deployments"
            )
        for deployment_id, output_id in output_ids.items():
            if artifact_by_id[output_id].binds_artifact_id != plan_ids[deployment_id]:
                raise ValueError("deployment output must bind the plan for the same deployment")
            if artifact_by_id[readback_ids[deployment_id]].binds_artifact_id != output_id:
                raise ValueError(
                    "deployment read-back must bind the output for the same deployment"
                )

        owner: dict[str, tuple[str, ScenarioPhase] | None] = {
            artifact_id: None for artifact_id in self.global_artifact_ids
        }
        for scenario in self.scenarios:
            for phase, phase_ids in scenario.phases.items():
                for artifact_id in phase_ids:
                    owner[artifact_id] = (scenario.scenario_id, phase)
            self._validate_scenario_requirements(scenario, artifact_by_id)
        for item in self.artifacts:
            expected_subject_class = _ATTESTATION_SUBJECT_CLASSES.get(item.evidence_class)
            if expected_subject_class is None:
                continue
            subject_id = cast(str, item.binds_artifact_id)
            subject = artifact_by_id[subject_id]
            if subject.evidence_class != expected_subject_class:
                raise ValueError(
                    f"{item.artifact_id} binds {subject.evidence_class}, "
                    f"expected {expected_subject_class}"
                )
            if owner.get(item.artifact_id) != owner.get(subject_id):
                raise ValueError("attestation and subject must belong to the same scenario phase")
        for item in self.artifacts:
            if item.evidence_class != "job-readback":
                continue
            execution = artifact_by_id[cast(str, item.binds_artifact_id)]
            if execution.evidence_class != "job-execution":
                raise ValueError("Job read-back must bind a Job execution")
            if owner[item.artifact_id] != owner[execution.artifact_id]:
                raise ValueError("Job execution and read-back must share one evidence scope")
        return self

    @staticmethod
    def _validate_scenario_requirements(
        scenario: Wc029ScenarioEvidence,
        artifact_by_id: Mapping[str, Wc029EvidenceFileDeclaration],
    ) -> None:
        phase_counts = {
            phase: Counter(
                artifact_by_id[artifact_id].evidence_class for artifact_id in artifact_ids
            )
            for phase, artifact_ids in scenario.phases.items()
        }
        required_common: dict[ScenarioPhase, tuple[EvidenceClass, ...]] = {
            "plan": ("scenario-plan", "baseline-state"),
            "apply": ("mutation-receipt",),
            "observe": (
                "monitoring-evidence",
                "correlation-report",
                "correlation-report-attestation",
            ),
            "recover": ("recovery-action",),
            "verify": (
                "recovered-state",
                "scenario-execution-manifest",
                "scenario-execution-attestation",
                "recovery-proof",
                "job-execution",
                "job-readback",
            ),
        }
        for phase, required in required_common.items():
            invalid = [
                evidence_class
                for evidence_class in required
                if phase_counts[phase][evidence_class] != 1
            ]
            if invalid:
                raise ValueError(
                    f"{scenario.scenario_id} {phase} evidence requires exactly one "
                    f"{sorted(invalid)}"
                )
        all_counts = sum(phase_counts.values(), Counter())
        if scenario.scenario_class == "nsg-connectivity-loss" and (
            phase_counts["observe"]["change-evidence"] != 1
        ):
            raise ValueError("NSG connectivity evidence requires an exact change artifact")
        if scenario.scenario_class != "nsg-connectivity-loss" and all_counts["change-evidence"] > 1:
            raise ValueError("a scenario cannot contain duplicate change evidence")
        omission_count = phase_counts["observe"]["incident-omission"]
        if omission_count > 1:
            raise ValueError("a scenario cannot contain duplicate incident omission evidence")
        if omission_count == 1:
            forbidden = {
                evidence_class
                for evidence_class in _INCIDENT_ONLY_CLASSES
                if all_counts[evidence_class]
            }
            if forbidden:
                raise ValueError(
                    "correlation-only scenarios must not contain incident-producing evidence"
                )
            return
        required_incident_observe: set[EvidenceClass] = {
            "incident-state-active",
            "incident-state-active-attestation",
            "manifest-citation",
            "guidance",
            "guidance-attestation",
            "enrichment-manifest",
            "enrichment-attestation",
            "feed-active",
            "feed-active-attestation",
            "feed-index-active",
            "feed-index-active-attestation",
            "notification-active",
        }
        required_incident_verify: set[EvidenceClass] = {
            "incident-state-resolved",
            "incident-state-resolved-attestation",
            "feed-resolved",
            "feed-resolved-attestation",
            "feed-index-resolved",
            "feed-index-resolved-attestation",
            "notification-resolved",
            "queue-state",
        }
        missing_observe = {
            evidence_class
            for evidence_class in required_incident_observe
            if phase_counts["observe"][evidence_class] != 1
        }
        missing_verify = {
            evidence_class
            for evidence_class in required_incident_verify
            if phase_counts["verify"][evidence_class] != 1
        }
        if missing_observe or missing_verify:
            raise ValueError(
                "incident-producing scenario is missing signed active/resolved evidence: "
                f"observe={sorted(missing_observe)}, verify={sorted(missing_verify)}"
            )


class Wc029SourceIndexRecord(_StrictAcceptanceModel):
    path: str
    size_bytes: int = Field(alias="sizeBytes", ge=1, le=MAX_INDEX_BYTES)
    content_sha256: str = Field(
        alias="contentSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    canonical_json_sha256: str = Field(
        alias="canonicalJsonSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )


class Wc029EvidenceArtifactRecord(_StrictAcceptanceModel):
    artifact_id: str = Field(alias="artifactId")
    evidence_class: EvidenceClass = Field(alias="evidenceClass")
    path: str
    size_bytes: int = Field(
        alias="sizeBytes",
        ge=1,
        le=MAX_ARTIFACT_TRANSFER_BYTES,
    )
    content_sha256: str = Field(
        alias="contentSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    canonical_json_sha256: str = Field(
        alias="canonicalJsonSha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    schema_version: str | None = Field(default=None, alias="schemaVersion")
    deployment_id: str | None = Field(default=None, alias="deploymentId")
    preflight_kind: PreflightKind | None = Field(default=None, alias="preflightKind")
    queue_scope: QueueScope | None = Field(default=None, alias="queueScope")
    signing_key_purpose: str | None = Field(
        default=None,
        alias="signingKeyPurpose",
    )
    binds_artifact_id: str | None = Field(
        default=None,
        alias="bindsArtifactId",
    )


class Wc029AcceptanceEvidenceRecord(_StrictAcceptanceModel):
    schema_version: Literal["athena.wc029AcceptanceEvidenceRecord.v1"] = Field(
        alias="schemaVersion"
    )
    acceptance_id: str = Field(alias="acceptanceId")
    validation_mode: Literal["offline-contract-digest-and-signature"] = Field(
        alias="validationMode"
    )
    azure_mutation_performed: Literal[False] = Field(alias="azureMutationPerformed")
    incident_evidence_synthesized: Literal[False] = Field(alias="incidentEvidenceSynthesized")
    evidence_status: Literal["complete"] = Field(alias="evidenceStatus")
    source_index: Wc029SourceIndexRecord = Field(alias="sourceIndex")
    approved_inventory_sha256: str = Field(
        alias="approvedInventorySha256",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    version_inventory: Wc029VersionInventory = Field(alias="versionInventory")
    global_artifact_ids: tuple[str, ...] = Field(alias="globalArtifactIds")
    scenarios: tuple[Wc029ScenarioEvidence, ...]
    artifacts: tuple[Wc029EvidenceArtifactRecord, ...]
    artifact_count: int = Field(alias="artifactCount", ge=1, le=MAX_EVIDENCE_FILES)
    total_evidence_bytes: int = Field(
        alias="totalEvidenceBytes",
        ge=1,
        le=MAX_TOTAL_EVIDENCE_BYTES + MAX_INDEX_BYTES,
    )
    aggregate_digest: str = Field(
        alias="aggregateDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("aggregateDigest")
        return payload

    @model_validator(mode="after")
    def validate_record(self) -> Wc029AcceptanceEvidenceRecord:
        artifact_ids = tuple(item.artifact_id for item in self.artifacts)
        if artifact_ids != tuple(sorted(artifact_ids)):
            raise ValueError("aggregate artifact records must be sorted by artifactId")
        scenario_classes = tuple(item.scenario_class for item in self.scenarios)
        if scenario_classes != tuple(sorted(scenario_classes)):
            raise ValueError("aggregate scenarios must be sorted by scenarioClass")
        if self.global_artifact_ids != tuple(sorted(self.global_artifact_ids)):
            raise ValueError("global artifact IDs must be sorted")
        if self.artifact_count != len(self.artifacts):
            raise ValueError("artifactCount does not match aggregate artifacts")
        if self.aggregate_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("aggregateDigest does not bind the canonical acceptance record")
        if len(self.canonical_bytes()) > MAX_RECORD_BYTES:
            raise ValueError("acceptance record exceeds its byte budget")
        return self


@dataclass(frozen=True, slots=True)
class _LoadedArtifact:
    declaration: Wc029EvidenceFileDeclaration
    raw: bytes
    parsed: object
    canonical_json: bytes
    record: Wc029EvidenceArtifactRecord
    model: BaseModel | None


_KNOWN_MODELS: dict[str, type[BaseModel]] = {
    VERSION_INVENTORY_SCHEMA_VERSION: Wc029VersionInventory,
    SIGNING_PUBLIC_KEY_SCHEMA_VERSION: Wc029SigningPublicKeyEvidence,
    PUBLISHED_MANIFEST_SCHEMA_VERSION: Wc029PublishedManifestEvidence,
    PUBLICATION_AUTHORITY_SCHEMA_VERSION: Wc029PublicationAuthorityEvidence,
    PUBLICATION_AUTHORITY_ATTESTATION_SCHEMA_VERSION: (Wc029PublicationAuthorityAttestation),
    "athena.wc029DeploymentPlan.v1": Wc029DeploymentPlanEvidence,
    "athena.wc029DeploymentHandoff.v1": Wc029DeploymentHandoffEvidence,
    DEPLOYMENT_READBACK_SCHEMA_VERSION: Wc029DeploymentReadbackEvidence,
    JOB_EXECUTION_SCHEMA_VERSION: Wc029JobExecutionEvidence,
    JOB_READBACK_SCHEMA_VERSION: Wc029JobReadbackEvidence,
    PREFLIGHT_RESULT_SCHEMA_VERSION: Wc029PreflightResultEvidence,
    SCENARIO_PLAN_SCHEMA_VERSION: Wc029ScenarioPlanEvidence,
    RESOURCE_STATE_SCHEMA_VERSION: Wc029ResourceStateEvidence,
    SCENARIO_EXECUTION_MANIFEST_SCHEMA_VERSION: (Wc029ScenarioExecutionManifest),
    SCENARIO_EXECUTION_ATTESTATION_SCHEMA_VERSION: (Wc029ScenarioExecutionAttestation),
    MUTATION_RECEIPT_SCHEMA_VERSION: Wc029MutationReceipt,
    RECOVERY_ACTION_SCHEMA_VERSION: Wc029RecoveryActionEvidence,
    MANIFEST_CITATION_SCHEMA_VERSION: Wc029ManifestCitationEvidence,
    INCIDENT_OMISSION_SCHEMA_VERSION: Wc029IncidentOmission,
    RECOVERY_PROOF_SCHEMA_VERSION: Wc029RecoveryProof,
    QUEUE_STATE_SCHEMA_VERSION: Wc029QueueStateEvidence,
    URL_PROBE_SCHEMA_VERSION: Wc029UrlProbeEvidence,
    "athena.wc024MonitoringEvidenceHandoff.v1": MonitoringEvidenceHandoff,
    "athena.changeEvidenceArtifact.v1": ChangeEvidenceArtifact,
    "athena.wc026CorrelationReport.v1": CorrelationReport,
    "athena.incidentState.v1": IncidentState,
    "athena.incidentStateAttestation.v1": IncidentStateAttestation,
    "athena.wc027PublishedCorrelationReportAttestation.v1": (PublishedCorrelationReportAttestation),
    "athena.wc027IncidentGuidance.v1": IncidentGuidance,
    "athena.wc027IncidentGuidanceAttestation.v1": IncidentGuidanceAttestation,
    "athena.wc027IncidentEnrichmentManifest.v1": IncidentEnrichmentManifest,
    "athena.wc027IncidentEnrichmentAttestation.v1": IncidentEnrichmentAttestation,
    "athena.wc027IncidentEnrichmentFeedPointer.v2": IncidentEnrichmentFeedPointer,
    "athena.wc027IncidentEnrichmentFeedPointerAttestation.v2": (
        IncidentEnrichmentFeedPointerAttestation
    ),
    "athena.wc027IncidentFeedIndex.v2": IncidentFeedIndexV2,
    "athena.wc027IncidentFeedIndexAttestation.v2": IncidentFeedIndexAttestationV2,
    "athena.wc027IncidentNotificationEnvelope.v2": IncidentNotificationEnvelopeV2,
}


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    normalized_keys: set[str] = set()
    for key, item in pairs:
        normalized_key = key.casefold()
        if normalized_key in normalized_keys:
            raise Wc029AcceptanceEvidenceError(
                "JSON input contains a case-insensitive duplicate object key"
            )
        normalized_keys.add(normalized_key)
        value[key] = item
    return value


def _reject_json_constant(value: str) -> NoReturn:
    raise Wc029AcceptanceEvidenceError(f"JSON input contains invalid constant {value}")


def _validate_json_shape(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise Wc029AcceptanceEvidenceError("JSON input exceeds depth or node bounds")
        if isinstance(item, dict):
            if any(type(key) is not str or len(key) > 4096 for key in item):
                raise Wc029AcceptanceEvidenceError("JSON object key is invalid")
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > MAX_ARTIFACT_TRANSFER_BYTES:
                raise Wc029AcceptanceEvidenceError("JSON string exceeds its byte bound")
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise Wc029AcceptanceEvidenceError("JSON input contains an unsupported value")


def _validate_json_nesting(raw: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in {0x7B, 0x5B}:
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise Wc029AcceptanceEvidenceError("JSON input exceeds its parse-time depth bound")
        elif byte in {0x7D, 0x5D}:
            depth -= 1
            if depth < 0:
                raise Wc029AcceptanceEvidenceError("JSON input has unbalanced containers")


def _parse_strict_json(raw: bytes, *, label: str) -> tuple[object, bytes]:
    try:
        _validate_json_nesting(raw)
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        _validate_json_shape(parsed)
        canonical = canonicalize_json(parsed).encode("utf-8")
    except Wc029AcceptanceEvidenceError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise Wc029AcceptanceEvidenceError(
            f"{label} is not strict canonicalizable UTF-8 JSON"
        ) from exc
    return parsed, canonical


def _is_reparse_point(path_stat: os.stat_result) -> bool:
    return bool(getattr(path_stat, "st_file_attributes", 0) & _REPARSE_POINT)


@dataclass(frozen=True, slots=True)
class _PathIdentity:
    device: int
    inode: int
    mode: int
    link_count: int
    size: int
    modified_ns: int
    file_attributes: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _PathIdentity:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            link_count=value.st_nlink,
            size=value.st_size,
            modified_ns=value.st_mtime_ns,
            file_attributes=getattr(value, "st_file_attributes", 0),
        )


@dataclass(slots=True)
class _PinnedDirectoryHandle:
    path: Path
    identity: _PathIdentity
    descriptor: int | None = None
    windows_handle: int | None = None

    def close(self) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        if self.windows_handle is not None:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle(ctypes.c_void_p(self.windows_handle))
            self.windows_handle = None


class _WindowsByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_ulong),
        ("ftCreationTimeLow", ctypes.c_ulong),
        ("ftCreationTimeHigh", ctypes.c_ulong),
        ("ftLastAccessTimeLow", ctypes.c_ulong),
        ("ftLastAccessTimeHigh", ctypes.c_ulong),
        ("ftLastWriteTimeLow", ctypes.c_ulong),
        ("ftLastWriteTimeHigh", ctypes.c_ulong),
        ("dwVolumeSerialNumber", ctypes.c_ulong),
        ("nFileSizeHigh", ctypes.c_ulong),
        ("nFileSizeLow", ctypes.c_ulong),
        ("nNumberOfLinks", ctypes.c_ulong),
        ("nFileIndexHigh", ctypes.c_ulong),
        ("nFileIndexLow", ctypes.c_ulong),
    ]


def _windows_directory_identity(handle: int) -> tuple[int, int, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsByHandleFileInformation),
    ]
    get_information.restype = ctypes.c_int
    information = _WindowsByHandleFileInformation()
    if (
        get_information(
            ctypes.c_void_p(handle),
            ctypes.byref(information),
        )
        == 0
    ):
        raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle failed")
    file_index = (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)
    return (
        file_index,
        int(information.nNumberOfLinks),
        int(information.dwFileAttributes),
    )


def _open_pinned_directory(
    path: Path,
    expected: _PathIdentity,
    *,
    parent: _PinnedDirectoryHandle | None = None,
    name: str | None = None,
) -> _PinnedDirectoryHandle:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(
            str(path),
            0x0001 | 0x0080,
            0x0001 | 0x0002,
            None,
            3,
            0x02000000 | 0x00200000,
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if handle in {None, invalid_handle}:
            raise OSError(ctypes.get_last_error(), "CreateFileW failed")
        raw_handle = int(handle)
        try:
            inode, link_count, attributes = _windows_directory_identity(raw_handle)
            if (
                inode != expected.inode
                or link_count != expected.link_count
                or attributes != expected.file_attributes
                or attributes & _REPARSE_POINT
                or not attributes & 0x10
            ):
                raise Wc029AcceptanceEvidenceError(
                    "directory handle identity does not match its validated path"
                )
        except OSError, Wc029AcceptanceEvidenceError:
            kernel32.CloseHandle(ctypes.c_void_p(raw_handle))
            raise
        return _PinnedDirectoryHandle(
            path=path,
            identity=expected,
            windows_handle=raw_handle,
        )

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(
        name if parent is not None and name is not None else path,
        flags,
        dir_fd=None if parent is None else parent.descriptor,
    )
    opened = _PathIdentity.from_stat(os.fstat(descriptor))
    if (
        opened != expected
        or not stat.S_ISDIR(opened.mode)
        or stat.S_ISLNK(opened.mode)
        or _is_reparse_point(os.fstat(descriptor))
    ):
        os.close(descriptor)
        raise Wc029AcceptanceEvidenceError(
            "directory handle identity does not match its validated path"
        )
    return _PinnedDirectoryHandle(
        path=path,
        identity=expected,
        descriptor=descriptor,
    )


def _stable_directory_path(
    path: Path,
    *,
    label: str,
) -> tuple[Path, _PathIdentity]:
    absolute = Path(os.path.abspath(path))
    try:
        expected = _PathIdentity.from_stat(absolute.lstat())
    except OSError as exc:
        raise Wc029AcceptanceEvidenceError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISDIR(expected.mode)
        or stat.S_ISLNK(expected.mode)
        or expected.file_attributes & _REPARSE_POINT
    ):
        raise Wc029AcceptanceEvidenceError(
            f"{label} must be one real directory without reparse points"
        )
    pin = _open_pinned_directory(absolute, expected)
    try:
        resolved = absolute.resolve(strict=True)
        if (
            os.path.normcase(str(resolved)) != os.path.normcase(str(absolute))
            or _PathIdentity.from_stat(resolved.lstat()) != expected
        ):
            raise Wc029AcceptanceEvidenceError(f"{label} contains a linked or unstable parent path")
    finally:
        pin.close()
    return absolute, expected


@dataclass(frozen=True, slots=True)
class _BundleSnapshot:
    files: dict[str, bytes]


def _scan_bundle_tree(
    root: Path,
) -> tuple[dict[str, _PathIdentity], dict[str, _PathIdentity]]:
    directories: dict[str, _PathIdentity] = {".": _PathIdentity.from_stat(root.lstat())}
    files: dict[str, _PathIdentity] = {}
    for current_text, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        current = Path(current_text)
        for name in directory_names:
            directory = current / name
            try:
                directory_stat = directory.lstat()
            except OSError as exc:
                raise Wc029AcceptanceEvidenceError(
                    "evidence directory contains an unreadable entry"
                ) from exc
            if (
                not stat.S_ISDIR(directory_stat.st_mode)
                or stat.S_ISLNK(directory_stat.st_mode)
                or _is_reparse_point(directory_stat)
            ):
                raise Wc029AcceptanceEvidenceError(
                    "evidence directory contains a linked or non-directory entry"
                )
            directories[directory.relative_to(root).as_posix()] = _PathIdentity.from_stat(
                directory_stat
            )
        for name in file_names:
            path = current / name
            relative = path.relative_to(root).as_posix()
            if not relative.endswith(".json"):
                raise Wc029AcceptanceEvidenceError(
                    f"evidence directory contains non-JSON file {relative}"
                )
            try:
                file_stat = path.lstat()
            except OSError as exc:
                raise Wc029AcceptanceEvidenceError(
                    f"evidence file {relative} cannot be inspected"
                ) from exc
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or stat.S_ISLNK(file_stat.st_mode)
                or _is_reparse_point(file_stat)
                or file_stat.st_nlink != 1
            ):
                raise Wc029AcceptanceEvidenceError(
                    f"evidence file {relative} must be one singly linked regular file"
                )
            files[relative] = _PathIdentity.from_stat(file_stat)
            if len(files) > MAX_EVIDENCE_FILES + 1:
                raise Wc029AcceptanceEvidenceError(
                    "evidence directory exceeds its file-count bound"
                )
    return directories, files


def _read_snapshot_file(
    path: Path,
    expected: _PathIdentity,
    *,
    parent: _PinnedDirectoryHandle,
    maximum_bytes: int,
    label: str,
) -> bytes:
    if expected.size < 1 or expected.size > maximum_bytes:
        raise Wc029AcceptanceEvidenceError(
            f"{label} must contain between 1 and {maximum_bytes} bytes"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(
            path if os.name == "nt" else path.name,
            flags,
            dir_fd=(None if os.name == "nt" else parent.descriptor),
        )
        opened = os.fstat(descriptor)
        opened_identity = _PathIdentity.from_stat(opened)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened_identity != expected:
            raise Wc029AcceptanceEvidenceError(
                f"{label} changed before its stable handle was opened"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            content = stream.read(maximum_bytes + 1)
            after = _PathIdentity.from_stat(os.fstat(stream.fileno()))
        if after != opened_identity:
            raise Wc029AcceptanceEvidenceError(f"{label} changed while its stable handle was read")
    except Wc029AcceptanceEvidenceError:
        raise
    except OSError as exc:
        raise Wc029AcceptanceEvidenceError(
            f"{label} could not be captured into the private snapshot"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not content or len(content) > maximum_bytes:
        raise Wc029AcceptanceEvidenceError(f"{label} is empty or oversized")
    return content


def _capture_bundle_snapshot(
    root: Path,
    *,
    index_relative: str,
) -> _BundleSnapshot:
    stable_root, root_identity = _stable_directory_path(
        root,
        label="evidence root",
    )
    pins: dict[str, _PinnedDirectoryHandle] = {}
    try:
        pins["."] = _open_pinned_directory(
            stable_root,
            root_identity,
        )
        before_directories, before_files = _scan_bundle_tree(stable_root)
        if before_directories.get(".") != root_identity:
            raise Wc029AcceptanceEvidenceError(
                "evidence root changed after its stable handle was opened"
            )
        for relative in sorted(
            (item for item in before_directories if item != "."),
            key=lambda item: (len(Path(item).parts), item),
        ):
            relative_path = Path(relative)
            parent_relative = (
                relative_path.parent.as_posix() if relative_path.parent != Path(".") else "."
            )
            pins[relative] = _open_pinned_directory(
                stable_root / relative_path,
                before_directories[relative],
                parent=pins[parent_relative],
                name=relative_path.name,
            )
        if index_relative not in before_files:
            raise Wc029AcceptanceEvidenceError("acceptance index is missing")
        artifact_bytes = sum(
            identity.size
            for relative, identity in before_files.items()
            if relative != index_relative
        )
        if artifact_bytes > MAX_TOTAL_EVIDENCE_BYTES:
            raise Wc029AcceptanceEvidenceError("aggregate evidence exceeds its total byte bound")
        captured: dict[str, bytes] = {}
        for relative, identity in sorted(before_files.items()):
            relative_path = Path(relative)
            parent_relative = (
                relative_path.parent.as_posix() if relative_path.parent != Path(".") else "."
            )
            captured[relative] = _read_snapshot_file(
                stable_root / relative_path,
                identity,
                parent=pins[parent_relative],
                maximum_bytes=(
                    MAX_INDEX_BYTES if relative == index_relative else MAX_ARTIFACT_TRANSFER_BYTES
                ),
                label=(
                    "acceptance index"
                    if relative == index_relative
                    else f"evidence file {relative}"
                ),
            )
        after_directories, after_files = _scan_bundle_tree(stable_root)
        if before_directories != after_directories or before_files != after_files:
            raise Wc029AcceptanceEvidenceError(
                "evidence directory changed while the private snapshot was captured"
            )
        return _BundleSnapshot(files=captured)
    finally:
        for pin in reversed(tuple(pins.values())):
            pin.close()


def _raise_walk_error(error: OSError) -> NoReturn:
    raise Wc029AcceptanceEvidenceError(
        "evidence directory contains an unreadable subtree"
    ) from error


def _model_canonical_bytes(model: BaseModel) -> bytes:
    return (
        canonicalize_json(model.model_dump(mode="json", by_alias=True, exclude_none=True)) + "\n"
    ).encode("utf-8")


def _load_artifact(
    raw: bytes,
    declaration: Wc029EvidenceFileDeclaration,
) -> _LoadedArtifact:
    parsed, canonical = _parse_strict_json(
        raw,
        label=f"artifact {declaration.artifact_id}",
    )
    content_digest = sha256_hex(raw)
    if declaration.expected_sha256 is not None and declaration.expected_sha256 != content_digest:
        raise Wc029AcceptanceEvidenceError(
            f"artifact {declaration.artifact_id} does not match expectedSha256"
        )
    schema_version = (
        parsed.get("schemaVersion")
        if isinstance(parsed, dict) and isinstance(parsed.get("schemaVersion"), str)
        else None
    )
    if (
        declaration.expected_schema_version is not None
        and schema_version != declaration.expected_schema_version
    ):
        raise Wc029AcceptanceEvidenceError(
            f"artifact {declaration.artifact_id} has the wrong schemaVersion"
        )
    model: BaseModel | None = None
    if schema_version in _KNOWN_MODELS:
        model_type = _KNOWN_MODELS[cast(str, schema_version)]
        try:
            model = model_type.model_validate_json(raw)
        except (RecursionError, ValidationError, TypeError, ValueError) as exc:
            raise Wc029AcceptanceEvidenceError(
                f"artifact {declaration.artifact_id} violates {schema_version}"
            ) from exc
        if raw != _model_canonical_bytes(model):
            raise Wc029AcceptanceEvidenceError(
                f"artifact {declaration.artifact_id} is not exact canonical contract bytes"
            )
    elif declaration.expected_schema_version is not None:
        raise Wc029AcceptanceEvidenceError(
            f"artifact {declaration.artifact_id} uses an unsupported contract schema"
        )
    record = Wc029EvidenceArtifactRecord(
        artifactId=declaration.artifact_id,
        evidenceClass=declaration.evidence_class,
        path=declaration.path,
        sizeBytes=len(raw),
        contentSha256=content_digest,
        canonicalJsonSha256=sha256_hex(canonical),
        schemaVersion=schema_version,
        deploymentId=declaration.deployment_id,
        preflightKind=declaration.preflight_kind,
        queueScope=declaration.queue_scope,
        signingKeyPurpose=declaration.signing_key_purpose,
        bindsArtifactId=declaration.binds_artifact_id,
    )
    return _LoadedArtifact(
        declaration=declaration,
        raw=raw,
        parsed=parsed,
        canonical_json=canonical,
        record=record,
        model=model,
    )


def _require_mapping(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise Wc029AcceptanceEvidenceError(f"{label} must be one JSON object")
    return value


def _require_model[Model: BaseModel](
    artifact: _LoadedArtifact,
    model: type[Model],
) -> Model:
    if not isinstance(artifact.model, model):
        raise Wc029AcceptanceEvidenceError(
            f"artifact {artifact.declaration.artifact_id} is not {model.__name__}"
        )
    return artifact.model


def _preflight_implementation_sha256() -> str:
    try:
        payload = _PREFLIGHT_IMPLEMENTATION.read_bytes()
    except OSError as exc:
        raise Wc029AcceptanceEvidenceError(
            "WC-029 preflight implementation is unavailable"
        ) from exc
    return sha256_hex(payload)


def _normalize_casefold_json(value: object) -> object:
    if isinstance(value, dict):
        return {str(key).casefold(): _normalize_casefold_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_casefold_json(item) for item in value]
    return value


def _validate_rbac_document(
    document: object,
    *,
    label: str,
) -> tuple[object, frozenset[str]]:
    normalized = _normalize_casefold_json(document)
    assignments = (
        normalized
        if isinstance(normalized, list)
        else _require_mapping(normalized, label=label).get("value")
    )
    if not isinstance(assignments, list) or not assignments:
        raise Wc029AcceptanceEvidenceError(f"{label} must contain at least one role assignment")
    principal_ids: set[str] = set()
    for raw_assignment in assignments:
        assignment = _require_mapping(raw_assignment, label="role assignment")
        principal_id = assignment.get("principalid")
        if type(principal_id) is not str or not principal_id:
            raise Wc029AcceptanceEvidenceError("effective RBAC assignment is missing principalId")
        principal_ids.add(principal_id.casefold())
    return normalized, frozenset(principal_ids)


def _validate_rbac_policy(
    document: object,
    *,
    inventory: Wc029VersionInventory,
) -> object:
    normalized = _normalize_casefold_json(document)
    policy = _require_mapping(normalized, label="RBAC policy")
    if set(policy) != {"allowedbroadassignments", "separationrules"}:
        raise Wc029AcceptanceEvidenceError(
            "RBAC policy must contain exact allowance and separation collections"
        )
    if not isinstance(policy["allowedbroadassignments"], list) or not isinstance(
        policy["separationrules"],
        list,
    ):
        raise Wc029AcceptanceEvidenceError("RBAC policy collections must be arrays")
    rules = policy["separationrules"]
    if not rules:
        raise Wc029AcceptanceEvidenceError(
            "RBAC policy requires at least one identity-separation rule"
        )
    normalized_rules: set[tuple[str, tuple[str, ...], tuple[str, ...]]] = set()
    for raw_rule in rules:
        rule = _require_mapping(raw_rule, label="RBAC separation rule")
        if set(rule) != {
            "principalid",
            "forbiddenrolenames",
            "forbiddenscopeprefixes",
        }:
            raise Wc029AcceptanceEvidenceError("RBAC separation rule has unexpected fields")
        principal = rule.get("principalid")
        roles = rule.get("forbiddenrolenames")
        scopes = rule.get("forbiddenscopeprefixes")
        if (
            type(principal) is not str
            or not principal
            or not isinstance(roles, list)
            or not roles
            or any(type(item) is not str or not item for item in roles)
            or not isinstance(scopes, list)
            or not scopes
            or any(type(item) is not str or not item for item in scopes)
        ):
            raise Wc029AcceptanceEvidenceError("RBAC separation rule must be non-vacuous")
        key = (
            principal.casefold(),
            tuple(sorted(item.casefold() for item in roles)),
            tuple(sorted(item.casefold().rstrip("/") for item in scopes)),
        )
        if key in normalized_rules:
            raise Wc029AcceptanceEvidenceError("RBAC separation rules must be unique")
        normalized_rules.add(key)

    expected = {
        (
            boundary.principal_id.casefold(),
            tuple(sorted(item.casefold() for item in boundary.forbidden_role_names)),
            tuple(
                sorted(item.casefold().rstrip("/") for item in boundary.forbidden_scope_prefixes)
            ),
        )
        for boundary in inventory.rbac_boundaries
    }
    if normalized_rules != expected:
        raise Wc029AcceptanceEvidenceError(
            "RBAC policy does not exactly cover every approved principal boundary"
        )
    return normalized


def _validate_preflight_evidence(
    inventory: Wc029VersionInventory,
    artifacts: Mapping[str, _LoadedArtifact],
) -> None:
    validator_digest = _preflight_implementation_sha256()
    results = tuple(
        _require_model(item, Wc029PreflightResultEvidence)
        for item in artifacts.values()
        if item.declaration.evidence_class == "preflight-result"
    )
    rbac_results = tuple(item for item in results if item.kind == "rbac")
    if len(rbac_results) != 1:
        raise Wc029AcceptanceEvidenceError(
            "acceptance evidence requires exactly one RBAC preflight result"
        )
    rbac = rbac_results[0]
    rbac_input = artifacts.get(rbac.input_artifact_id)
    policy = artifacts.get(cast(str, rbac.policy_artifact_id))
    if (
        rbac_input is None
        or rbac_input.declaration.evidence_class != "effective-rbac"
        or policy is None
        or policy.declaration.evidence_class != "rbac-policy"
        or rbac.input_sha256 != rbac_input.record.content_sha256
        or rbac.policy_sha256 != policy.record.content_sha256
        or rbac.validator_sha256 != validator_digest
    ):
        raise Wc029AcceptanceEvidenceError(
            "RBAC preflight result does not bind its exact input, policy, and validator"
        )
    normalized_rbac, principal_ids = _validate_rbac_document(
        rbac_input.parsed,
        label="effective RBAC",
    )
    expected_principals = frozenset(
        item.principal_id.casefold() for item in inventory.rbac_boundaries
    )
    if principal_ids != expected_principals:
        raise Wc029AcceptanceEvidenceError(
            "effective RBAC does not cover the exact inventoried principals"
        )
    normalized_policy = _validate_rbac_policy(
        policy.parsed,
        inventory=inventory,
    )
    try:
        violations = evaluate_role_assignments(
            normalized_rbac,
            policy_document=normalized_policy,
        )
    except PreflightInputError as exc:
        raise Wc029AcceptanceEvidenceError(
            "effective RBAC or its policy failed preflight validation"
        ) from exc
    if violations:
        raise Wc029AcceptanceEvidenceError(
            "effective RBAC does not satisfy the reviewed separation policy"
        )

    deployment_ids = {item.deployment_id for item in inventory.deployments}
    what_if_results = tuple(item for item in results if item.kind == "what-if")
    if {cast(str, item.deployment_id) for item in what_if_results} != deployment_ids:
        raise Wc029AcceptanceEvidenceError(
            "what-if preflight results do not cover every inventoried deployment"
        )
    plans = {
        cast(str, item.declaration.deployment_id): item
        for item in artifacts.values()
        if item.declaration.evidence_class == "deployment-plan"
    }
    what_if_inputs = {
        cast(str, item.declaration.deployment_id): item
        for item in artifacts.values()
        if item.declaration.evidence_class == "deployment-what-if"
    }
    for result in what_if_results:
        deployment_id = cast(str, result.deployment_id)
        input_artifact = what_if_inputs[deployment_id]
        plan = _require_model(plans[deployment_id], Wc029DeploymentPlanEvidence)
        if (
            result.input_artifact_id != input_artifact.declaration.artifact_id
            or result.input_sha256 != input_artifact.record.content_sha256
            or result.validator_sha256 != validator_digest
        ):
            raise Wc029AcceptanceEvidenceError(
                f"what-if preflight {deployment_id} does not bind exact evidence"
            )
        try:
            violations = evaluate_what_if(
                input_artifact.parsed,
                allowed_change_ids=frozenset(plan.allowed_change_resource_ids),
            )
        except PreflightInputError as exc:
            raise Wc029AcceptanceEvidenceError(
                f"what-if evidence {deployment_id} failed preflight validation"
            ) from exc
        if violations:
            raise Wc029AcceptanceEvidenceError(
                f"what-if evidence {deployment_id} violates the reviewed plan"
            )


def _validate_deployment_evidence(
    inventory: Wc029VersionInventory,
    artifacts: Mapping[str, _LoadedArtifact],
) -> None:
    plans = {
        cast(str, item.declaration.deployment_id): item
        for item in artifacts.values()
        if item.declaration.evidence_class == "deployment-plan"
    }
    what_ifs = {
        cast(str, item.declaration.deployment_id): item
        for item in artifacts.values()
        if item.declaration.evidence_class == "deployment-what-if"
    }
    outputs = {
        cast(str, item.declaration.deployment_id): item
        for item in artifacts.values()
        if item.declaration.evidence_class == "deployment-output"
    }
    readbacks = {
        cast(str, item.declaration.deployment_id): item
        for item in artifacts.values()
        if item.declaration.evidence_class == "deployment-readback"
    }
    inventory_deployments = {item.deployment_id: item for item in inventory.deployments}
    if not (
        plans.keys()
        == what_ifs.keys()
        == outputs.keys()
        == readbacks.keys()
        == inventory_deployments.keys()
    ):
        raise Wc029AcceptanceEvidenceError(
            "version inventory and deployment evidence do not cover identical deployments"
        )
    for deployment_id, coordinate in inventory_deployments.items():
        plan_artifact = plans[deployment_id]
        output_artifact = outputs[deployment_id]
        readback_artifact = readbacks[deployment_id]
        plan = _require_model(plan_artifact, Wc029DeploymentPlanEvidence)
        output = _require_model(
            output_artifact,
            Wc029DeploymentHandoffEvidence,
        )
        readback = _require_model(
            readback_artifact,
            Wc029DeploymentReadbackEvidence,
        )
        plan_upstream = {
            "foundation": (
                plan.foundation_handoff_path,
                plan.foundation_handoff_sha256,
            ),
            "producer": (
                plan.producer_handoff_path,
                plan.producer_handoff_sha256,
            ),
            "publisher": (
                plan.publisher_handoff_path,
                plan.publisher_handoff_sha256,
            ),
        }
        for upstream in coordinate.upstream_handoffs:
            upstream_artifact = artifacts.get(upstream.output_artifact_id)
            if (
                upstream_artifact is None
                or upstream_artifact.declaration.evidence_class != "deployment-output"
                or upstream_artifact.declaration.deployment_id != upstream.deployment_id
                or upstream_artifact.record.content_sha256 != upstream.content_sha256
                or plan_upstream[upstream.stage] != (upstream.handoff_path, upstream.content_sha256)
            ):
                raise Wc029AcceptanceEvidenceError(
                    f"deployment {deployment_id} upstream {upstream.stage} "
                    "handoff identity is invalid"
                )
        unused_plan_handoffs = {
            stage
            for stage, values in plan_upstream.items()
            if values != (None, None)
            and stage not in {item.stage for item in coordinate.upstream_handoffs}
        }
        if unused_plan_handoffs:
            raise Wc029AcceptanceEvidenceError(
                f"deployment {deployment_id} contains unapproved named handoffs"
            )
        if (
            plan.source_commit != inventory.source_commit
            or plan.stage != coordinate.stage
            or plan.subscription_id.casefold() != coordinate.subscription_id.casefold()
            or (plan.resource_group or "").casefold()
            != (coordinate.resource_group or "").casefold()
            or plan.location != coordinate.location
            or plan.deployment_name != coordinate.deployment_name
            or plan.template_path != coordinate.template_path
            or plan.template_sha256 != coordinate.template_sha256
            or plan.base_parameter_sha256 != coordinate.base_parameter_sha256
            or plan.effective_parameter_sha256 != coordinate.effective_parameter_sha256
            or plan.what_if_sha256 != what_ifs[deployment_id].record.content_sha256
            or plan.preflight_sha256 != _preflight_implementation_sha256()
        ):
            raise Wc029AcceptanceEvidenceError(
                f"deployment plan {deployment_id} does not match inventory and what-if"
            )
        if (
            output.source_commit != inventory.source_commit
            or output.stage != coordinate.stage
            or output.subscription_id.casefold() != coordinate.subscription_id.casefold()
            or (output.resource_group or "").casefold()
            != (coordinate.resource_group or "").casefold()
            or output.deployment_name != coordinate.deployment_name
            or output.parameter_bindings_sha256 != coordinate.parameter_bindings_sha256
            or output.plan_manifest_sha256 != plan_artifact.record.content_sha256
            or output_artifact.declaration.binds_artifact_id
            != plan_artifact.declaration.artifact_id
        ):
            raise Wc029AcceptanceEvidenceError(
                f"deployment output {deployment_id} does not bind its reviewed plan"
            )
        if (
            readback.source_commit != inventory.source_commit
            or readback.stage != coordinate.stage
            or readback.subscription_id.casefold() != coordinate.subscription_id.casefold()
            or (readback.resource_group or "").casefold()
            != (coordinate.resource_group or "").casefold()
            or readback.location != coordinate.location
            or readback.deployment_name != coordinate.deployment_name
            or readback.template_path != coordinate.template_path
            or readback.template_sha256 != coordinate.template_sha256
            or readback.base_parameter_sha256 != coordinate.base_parameter_sha256
            or readback.effective_parameter_sha256 != coordinate.effective_parameter_sha256
            or readback.parameter_bindings_sha256 != coordinate.parameter_bindings_sha256
            or readback.upstream_handoffs != coordinate.upstream_handoffs
            or readback.output_handoff_sha256 != output_artifact.record.content_sha256
            or readback.outputs != output.outputs
            or readback.outputs_sha256 != output.outputs_sha256
            or readback_artifact.declaration.binds_artifact_id
            != output_artifact.declaration.artifact_id
        ):
            raise Wc029AcceptanceEvidenceError(
                f"deployment read-back {deployment_id} does not prove successful output state"
            )
        if deployment_id == inventory.capability_deployment_id:
            capabilities = [
                item.model_dump(mode="json", by_alias=True, exclude_none=True)
                for item in inventory.scenario_capabilities
            ]
            capability_digest = compute_artifact_digest(capabilities)
            if (
                readback.outputs.get("wc029ScenarioCapabilities") != capabilities
                or readback.outputs.get("wc029ScenarioCapabilitiesDigest") != capability_digest
            ):
                raise Wc029AcceptanceEvidenceError(
                    "trusted scenario capabilities are absent from deployment read-back"
                )


def _decode_signature(value: str, *, standard_base64: bool) -> bytes:
    if _SIGNATURE_PATTERN.fullmatch(value) is None:
        raise Wc029AcceptanceEvidenceError("signature encoding is invalid")
    try:
        if standard_base64:
            signature = base64.b64decode(value, validate=True)
            if base64.b64encode(signature).decode("ascii") != value:
                raise ValueError
        else:
            padding_length = (-len(value)) % 4
            signature = base64.urlsafe_b64decode(value + ("=" * padding_length))
            if base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=") != value.rstrip("="):
                raise ValueError
    except (ValueError, binascii.Error) as exc:
        raise Wc029AcceptanceEvidenceError("signature encoding is invalid") from exc
    if not signature:
        raise Wc029AcceptanceEvidenceError("signature must not be empty")
    return signature


def _verify_signature(
    public_key: rsa.RSAPublicKey,
    *,
    preimage: bytes,
    signature: str,
    standard_base64: bool,
    artifact_id: str,
) -> None:
    try:
        public_key.verify(
            _decode_signature(signature, standard_base64=standard_base64),
            preimage,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise Wc029AcceptanceEvidenceError(
            f"signed artifact {artifact_id} has an invalid RSA signature"
        ) from exc


def _load_public_keys(
    inventory: Wc029VersionInventory,
    artifacts: Mapping[str, _LoadedArtifact],
) -> dict[str, rsa.RSAPublicKey]:
    key_artifacts = {
        item.declaration.artifact_id: item
        for item in artifacts.values()
        if item.declaration.evidence_class == "signing-public-key"
    }
    if set(key_artifacts) != {item.public_key_artifact_id for item in inventory.keys}:
        raise Wc029AcceptanceEvidenceError(
            "public-key evidence does not exactly cover the version inventory"
        )
    public_keys: dict[str, rsa.RSAPublicKey] = {}
    for key in inventory.keys:
        artifact = key_artifacts[key.public_key_artifact_id]
        public_key_evidence = _require_model(
            artifact,
            Wc029SigningPublicKeyEvidence,
        )
        if (
            artifact.declaration.signing_key_purpose != key.purpose
            or public_key_evidence.purpose != key.purpose
            or public_key_evidence.key_vault_key_id.casefold() != key.key_vault_key_id.casefold()
            or public_key_evidence.public_key_fingerprint != key.public_key_fingerprint
        ):
            raise Wc029AcceptanceEvidenceError(
                f"public-key evidence for {key.purpose} does not match inventory"
            )
        public_keys[key.purpose] = public_key_evidence.rsa_public_key()
    return public_keys


def _validate_signed_artifacts(
    inventory: Wc029VersionInventory,
    artifacts: Mapping[str, _LoadedArtifact],
) -> None:
    keys = {item.purpose: item for item in inventory.keys}
    public_keys = _load_public_keys(inventory, artifacts)
    used_purposes: set[str] = set()
    for artifact in artifacts.values():
        purpose = _SIGNED_KEY_PURPOSE_BY_CLASS.get(artifact.declaration.evidence_class)
        if purpose is None:
            continue
        key = keys.get(purpose)
        public_key = public_keys.get(purpose)
        if key is None or public_key is None:
            raise Wc029AcceptanceEvidenceError(
                f"signed artifact {artifact.declaration.artifact_id} "
                f"requires absent key purpose {purpose}"
            )
        used_purposes.add(purpose)
        evidence_class = artifact.declaration.evidence_class
        subject = (
            None
            if artifact.declaration.binds_artifact_id is None
            else artifacts[artifact.declaration.binds_artifact_id]
        )
        if evidence_class == "monitoring-evidence":
            handoff = _require_model(artifact, MonitoringEvidenceHandoff)
            monitoring_attestation = handoff.collector_attestation
            preimage = canonicalize_json(monitoring_handoff_preimage(handoff)).encode("utf-8")
            if (
                monitoring_attestation.trust_anchor_ref.casefold()
                != key.key_vault_key_id.casefold()
                or monitoring_attestation.signed_preimage_digest
                != compute_artifact_digest(monitoring_handoff_preimage(handoff))
            ):
                raise Wc029AcceptanceEvidenceError(
                    "monitoring evidence does not bind its inventoried signing key"
                )
            _verify_signature(
                public_key,
                preimage=preimage,
                signature=monitoring_attestation.signature,
                standard_base64=True,
                artifact_id=artifact.declaration.artifact_id,
            )
        elif evidence_class == "change-evidence":
            change = _require_model(artifact, ChangeEvidenceArtifact)
            preimage = canonicalize_json(
                change_evidence_attestation_preimage(change.evidence)
            ).encode("utf-8")
            if (
                change.attestation.key_vault_key_id.casefold() != key.key_vault_key_id.casefold()
                or change.attestation.signed_preimage_digest != sha256_hex(preimage)
            ):
                raise Wc029AcceptanceEvidenceError(
                    "change evidence does not bind its exact signed preimage"
                )
            _verify_signature(
                public_key,
                preimage=preimage,
                signature=change.attestation.signature,
                standard_base64=True,
                artifact_id=artifact.declaration.artifact_id,
            )
        elif evidence_class == "correlation-report-attestation":
            report_attestation = _require_model(
                artifact,
                PublishedCorrelationReportAttestation,
            )
            report = _require_model(cast(_LoadedArtifact, subject), CorrelationReport)
            statement = report_attestation.statement
            if (
                statement.report_id != report.report_id
                or statement.report_digest != report.report_digest
                or statement.report_content_digest != sha256_hex(report.canonical_bytes())
                or report_attestation.key_vault_key_id.casefold() != key.key_vault_key_id.casefold()
                or report_attestation.signed_preimage_digest
                != sha256_hex(statement.canonical_bytes())
            ):
                raise Wc029AcceptanceEvidenceError(
                    "report attestation does not bind the exact correlation report"
                )
            _verify_signature(
                public_key,
                preimage=statement.canonical_bytes(),
                signature=report_attestation.detached_signature,
                standard_base64=False,
                artifact_id=artifact.declaration.artifact_id,
            )
        elif evidence_class == "publication-authority-attestation":
            authority_attestation = _require_model(
                artifact,
                Wc029PublicationAuthorityAttestation,
            )
            authority_evidence = _require_model(
                cast(_LoadedArtifact, subject),
                Wc029PublicationAuthorityEvidence,
            )
            authority = authority_evidence.authority
            if (
                authority_attestation.authority_id != authority.authority_id
                or authority_attestation.authority_digest != authority.authority_digest
                or authority_attestation.signed_preimage_digest
                != sha256_hex(authority.canonical_bytes())
                or authority_attestation.key_vault_key_id.casefold()
                != key.key_vault_key_id.casefold()
            ):
                raise Wc029AcceptanceEvidenceError(
                    "publication authority attestation does not bind exact authority"
                )
            _verify_signature(
                public_key,
                preimage=authority.canonical_bytes(),
                signature=authority_attestation.detached_signature,
                standard_base64=False,
                artifact_id=artifact.declaration.artifact_id,
            )
        elif evidence_class in {
            "incident-state-active-attestation",
            "incident-state-resolved-attestation",
        }:
            state_attestation = _require_model(
                artifact,
                IncidentStateAttestation,
            )
            state = _require_model(cast(_LoadedArtifact, subject), IncidentState)
            preimage = incident_state_signature_preimage(state)
            if (
                state_attestation.result_digest != state.result_digest
                or state_attestation.key_vault_key_id.casefold() != key.key_vault_key_id.casefold()
            ):
                raise Wc029AcceptanceEvidenceError(
                    "incident attestation does not bind the exact IncidentState"
                )
            _verify_signature(
                public_key,
                preimage=preimage,
                signature=state_attestation.detached_signature,
                standard_base64=False,
                artifact_id=artifact.declaration.artifact_id,
            )
        elif evidence_class == "guidance-attestation":
            guidance_attestation = _require_model(
                artifact,
                IncidentGuidanceAttestation,
            )
            guidance = _require_model(cast(_LoadedArtifact, subject), IncidentGuidance)
            if (
                guidance_attestation.guidance_id != guidance.guidance_id
                or guidance_attestation.guidance_digest != guidance.guidance_digest
                or guidance_attestation.signed_preimage_digest
                != sha256_hex(guidance.canonical_bytes())
                or guidance_attestation.key_vault_key_id.casefold()
                != key.key_vault_key_id.casefold()
            ):
                raise Wc029AcceptanceEvidenceError(
                    "guidance attestation does not bind exact guidance"
                )
            _verify_signature(
                public_key,
                preimage=guidance.canonical_bytes(),
                signature=guidance_attestation.detached_signature,
                standard_base64=False,
                artifact_id=artifact.declaration.artifact_id,
            )
        elif evidence_class == "enrichment-attestation":
            enrichment_attestation = _require_model(
                artifact,
                IncidentEnrichmentAttestation,
            )
            manifest = _require_model(
                cast(_LoadedArtifact, subject),
                IncidentEnrichmentManifest,
            )
            if (
                enrichment_attestation.enrichment_id != manifest.enrichment_id
                or enrichment_attestation.manifest_digest != manifest.manifest_digest
                or enrichment_attestation.signed_preimage_digest
                != sha256_hex(manifest.canonical_bytes())
                or enrichment_attestation.key_vault_key_id.casefold()
                != key.key_vault_key_id.casefold()
            ):
                raise Wc029AcceptanceEvidenceError(
                    "enrichment attestation does not bind exact manifest"
                )
            _verify_signature(
                public_key,
                preimage=manifest.canonical_bytes(),
                signature=enrichment_attestation.detached_signature,
                standard_base64=False,
                artifact_id=artifact.declaration.artifact_id,
            )
        elif evidence_class in {
            "feed-active-attestation",
            "feed-resolved-attestation",
        }:
            feed_attestation = _require_model(
                artifact,
                IncidentEnrichmentFeedPointerAttestation,
            )
            pointer = _require_model(
                cast(_LoadedArtifact, subject),
                IncidentEnrichmentFeedPointer,
            )
            if (
                feed_attestation.pointer_id != pointer.pointer_id
                or feed_attestation.pointer_digest != pointer.pointer_digest
                or feed_attestation.signed_preimage_digest != sha256_hex(pointer.canonical_bytes())
                or feed_attestation.key_vault_key_id.casefold() != key.key_vault_key_id.casefold()
            ):
                raise Wc029AcceptanceEvidenceError("feed attestation does not bind exact pointer")
            _verify_signature(
                public_key,
                preimage=pointer.canonical_bytes(),
                signature=feed_attestation.detached_signature,
                standard_base64=False,
                artifact_id=artifact.declaration.artifact_id,
            )
        elif evidence_class in {
            "feed-index-active-attestation",
            "feed-index-resolved-attestation",
        }:
            index_attestation = _require_model(
                artifact,
                IncidentFeedIndexAttestationV2,
            )
            feed_index = _require_model(
                cast(_LoadedArtifact, subject),
                IncidentFeedIndexV2,
            )
            if (
                index_attestation.index_digest != sha256_hex(feed_index.canonical_bytes())
                or index_attestation.key_vault_key_id.casefold() != key.key_vault_key_id.casefold()
                or feed_index.key_id.casefold() != key.key_vault_key_id.casefold()
                or feed_index.key_fingerprint != key.public_key_fingerprint
            ):
                raise Wc029AcceptanceEvidenceError(
                    "feed index attestation does not bind exact index and key"
                )
            _verify_signature(
                public_key,
                preimage=feed_index.canonical_bytes(),
                signature=index_attestation.detached_signature,
                standard_base64=False,
                artifact_id=artifact.declaration.artifact_id,
            )
        elif evidence_class == "scenario-execution-attestation":
            execution_attestation = _require_model(
                artifact,
                Wc029ScenarioExecutionAttestation,
            )
            execution_manifest = _require_model(
                cast(_LoadedArtifact, subject),
                Wc029ScenarioExecutionManifest,
            )
            if (
                execution_attestation.scenario_execution_id
                != execution_manifest.scenario_execution_id
                or execution_attestation.manifest_digest != execution_manifest.manifest_digest
                or execution_attestation.signed_preimage_digest
                != sha256_hex(execution_manifest.canonical_bytes())
                or execution_attestation.key_vault_key_id.casefold()
                != key.key_vault_key_id.casefold()
            ):
                raise Wc029AcceptanceEvidenceError(
                    "scenario execution attestation does not bind exact manifest"
                )
            _verify_signature(
                public_key,
                preimage=execution_manifest.canonical_bytes(),
                signature=execution_attestation.detached_signature,
                standard_base64=False,
                artifact_id=artifact.declaration.artifact_id,
            )
        elif evidence_class in {
            "notification-active",
            "notification-resolved",
        }:
            envelope = _require_model(artifact, IncidentNotificationEnvelopeV2)
            if envelope.attestation.key_vault_key_id.casefold() != key.key_vault_key_id.casefold():
                raise Wc029AcceptanceEvidenceError(
                    "notification does not use the inventoried signing key"
                )
            _verify_signature(
                public_key,
                preimage=envelope.notification.canonical_bytes(),
                signature=envelope.attestation.detached_signature,
                standard_base64=False,
                artifact_id=artifact.declaration.artifact_id,
            )
    if used_purposes != set(keys):
        raise Wc029AcceptanceEvidenceError(
            "every inventoried signing key must be exercised by captured signed evidence"
        )


def _artifact_owners(
    index: Wc029AcceptanceEvidenceIndex,
) -> dict[str, tuple[str, ScenarioPhase] | None]:
    owners: dict[str, tuple[str, ScenarioPhase] | None] = {
        artifact_id: None for artifact_id in index.global_artifact_ids
    }
    for scenario in index.scenarios:
        for phase, artifact_ids in scenario.phases.items():
            for artifact_id in artifact_ids:
                owners[artifact_id] = (scenario.scenario_id, phase)
    return owners


def _validate_job_evidence(
    index: Wc029AcceptanceEvidenceIndex,
    inventory: Wc029VersionInventory,
    artifacts: Mapping[str, _LoadedArtifact],
) -> None:
    owners = _artifact_owners(index)
    executions = {
        item.declaration.artifact_id: (
            item,
            _require_model(item, Wc029JobExecutionEvidence),
        )
        for item in artifacts.values()
        if item.declaration.evidence_class == "job-execution"
    }
    readbacks = tuple(
        (
            item,
            _require_model(item, Wc029JobReadbackEvidence),
        )
        for item in artifacts.values()
        if item.declaration.evidence_class == "job-readback"
    )
    bound_execution_ids = {cast(str, item.declaration.binds_artifact_id) for item, _ in readbacks}
    if bound_execution_ids != set(executions):
        raise Wc029AcceptanceEvidenceError("every Job execution must have exactly one read-back")
    if len(bound_execution_ids) != len(readbacks):
        raise Wc029AcceptanceEvidenceError("multiple Job read-backs cannot bind one execution")
    inventory_images = {item.component: item.image for item in inventory.images}
    used_components: set[str] = set()
    execution_ids: set[str] = set()
    for artifact, execution in executions.values():
        if execution.execution_id in execution_ids:
            raise Wc029AcceptanceEvidenceError("Job execution IDs must be unique")
        execution_ids.add(execution.execution_id)
        if (
            execution.source_commit != inventory.source_commit
            or inventory_images.get(execution.component) != execution.image
        ):
            raise Wc029AcceptanceEvidenceError(
                f"Job execution {artifact.declaration.artifact_id} "
                "does not match inventoried source and image"
            )
        owner = owners[artifact.declaration.artifact_id]
        if owner is None:
            if execution.scope != "global":
                raise Wc029AcceptanceEvidenceError("global Job execution has scenario scope")
        elif (
            execution.scope != "scenario"
            or execution.scenario_id != owner[0]
            or execution.phase != owner[1]
        ):
            raise Wc029AcceptanceEvidenceError(
                "scenario Job execution does not bind its index phase"
            )
        used_components.add(execution.component)

    for artifact, readback in readbacks:
        execution_artifact, execution = executions[
            cast(str, artifact.declaration.binds_artifact_id)
        ]
        if (
            readback.execution_id != execution.execution_id
            or readback.execution_digest != execution.execution_digest
            or readback.job_resource_id.casefold() != execution.job_resource_id.casefold()
            or readback.source_commit != execution.source_commit
            or readback.component != execution.component
            or readback.image != execution.image
            or readback.scope != execution.scope
            or readback.scenario_id != execution.scenario_id
            or readback.scenario_execution_id != execution.scenario_execution_id
            or readback.scenario_plan_digest != execution.scenario_plan_digest
            or readback.phase != execution.phase
            or readback.observed_at < execution.completed_at
        ):
            raise Wc029AcceptanceEvidenceError(
                f"Job read-back {artifact.declaration.artifact_id} "
                "does not bind its exact successful execution"
            )
        owner = owners[artifact.declaration.artifact_id]
        for result in readback.result_artifacts:
            result_artifact = artifacts.get(result.artifact_id)
            if (
                result_artifact is None
                or result_artifact.record.content_sha256 != result.content_sha256
                or result.artifact_id
                in {
                    artifact.declaration.artifact_id,
                    execution_artifact.declaration.artifact_id,
                }
            ):
                raise Wc029AcceptanceEvidenceError(
                    "Job read-back result artifact reference is invalid"
                )
            result_owner = owners[result.artifact_id]
            if owner is None:
                if result_owner is not None:
                    raise Wc029AcceptanceEvidenceError(
                        "global Job read-back cannot claim scenario evidence"
                    )
            elif result_owner is None or result_owner[0] != owner[0]:
                raise Wc029AcceptanceEvidenceError(
                    "scenario Job read-back references another evidence scope"
                )
    if used_components != set(inventory_images):
        raise Wc029AcceptanceEvidenceError(
            "Job evidence does not exercise every inventoried image component"
        )


def _validate_url_probes(
    inventory: Wc029VersionInventory,
    artifacts: Mapping[str, _LoadedArtifact],
) -> None:
    endpoints = {item.endpoint_id: item for item in inventory.endpoints}
    probes = tuple(
        _require_model(item, Wc029UrlProbeEvidence)
        for item in artifacts.values()
        if item.declaration.evidence_class == "url-probe"
    )
    expected_coordinates = {
        (endpoint.endpoint_id, endpoint.origin + path)
        for endpoint in inventory.endpoints
        for path in endpoint.allowed_paths
    }
    actual_coordinates: set[tuple[str, str]] = set()
    probe_ids: set[str] = set()
    for probe in probes:
        endpoint = endpoints.get(probe.endpoint_id)
        parsed = urlsplit(probe.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if (
            endpoint is None
            or origin.casefold() != endpoint.origin.casefold()
            or parsed.path not in endpoint.allowed_paths
            or parsed.query
            or parsed.fragment
        ):
            raise Wc029AcceptanceEvidenceError(
                f"URL probe {probe.probe_id} is outside inventoried endpoint paths"
            )
        coordinate = (probe.endpoint_id, endpoint.origin + parsed.path)
        if probe.probe_id in probe_ids or coordinate in actual_coordinates:
            raise Wc029AcceptanceEvidenceError("URL probes must be unique")
        probe_ids.add(probe.probe_id)
        actual_coordinates.add(coordinate)
    if actual_coordinates != expected_coordinates:
        raise Wc029AcceptanceEvidenceError(
            "URL probes do not cover every inventoried endpoint path"
        )


def _validate_publication_authority(
    inventory: Wc029VersionInventory,
    artifacts: Mapping[str, _LoadedArtifact],
) -> None:
    manifest_inventory = inventory.manifest
    manifest_artifact = artifacts.get(manifest_inventory.manifest_artifact_id)
    authority_artifact = artifacts.get(manifest_inventory.authority_artifact_id)
    attestation_artifact = artifacts.get(manifest_inventory.authority_attestation_artifact_id)
    if (
        manifest_artifact is None
        or manifest_artifact.declaration.evidence_class != "published-manifest"
        or authority_artifact is None
        or authority_artifact.declaration.evidence_class != "publication-authority"
        or attestation_artifact is None
        or attestation_artifact.declaration.evidence_class != "publication-authority-attestation"
        or attestation_artifact.declaration.binds_artifact_id
        != authority_artifact.declaration.artifact_id
    ):
        raise Wc029AcceptanceEvidenceError(
            "trusted manifest publication artifacts are missing or misbound"
        )
    manifest = _require_model(
        manifest_artifact,
        Wc029PublishedManifestEvidence,
    )
    authority = _require_model(
        authority_artifact,
        Wc029PublicationAuthorityEvidence,
    ).authority
    if (
        manifest.manifest_id != manifest_inventory.manifest_id
        or manifest.manifest_version != manifest_inventory.manifest_version
        or manifest.profile_id != manifest_inventory.profile_id
        or manifest.manifest_digest != manifest_inventory.manifest_digest
        or manifest_artifact.record.content_sha256 != manifest_inventory.manifest_artifact_sha256
        or compute_artifact_digest(
            [
                item.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
                for item in manifest.cited_clauses
            ]
        )
        != manifest_inventory.cited_clause_map_digest
        or authority.workload_id != manifest.workload_id
        or authority.manifest_id != manifest.manifest_id
        or authority.manifest_version != manifest.manifest_version
        or authority.manifest_digest != manifest.manifest_digest
        or authority.profile_id != manifest.profile_id
        or authority.publication_record_digest != manifest.publication_record_digest
        or authority.audit_head_digest != manifest.audit_head_digest
        or authority.published_at != manifest.published_at
        or authority.authority_digest != manifest_inventory.authority_digest
    ):
        raise Wc029AcceptanceEvidenceError(
            "published manifest and authority do not match approved inventory"
        )


def _scenario_artifacts_by_class(
    scenario: Wc029ScenarioEvidence,
    artifacts: Mapping[str, _LoadedArtifact],
) -> dict[EvidenceClass, _LoadedArtifact]:
    selected: dict[EvidenceClass, _LoadedArtifact] = {}
    for _phase, artifact_ids in scenario.phases.items():
        for artifact_id in artifact_ids:
            artifact = artifacts[artifact_id]
            if artifact.declaration.evidence_class in selected:
                raise Wc029AcceptanceEvidenceError(
                    f"scenario {scenario.scenario_id} has duplicate "
                    f"{artifact.declaration.evidence_class}"
                )
            selected[artifact.declaration.evidence_class] = artifact
    return selected


def _phase_window(
    manifest: Wc029ScenarioExecutionManifest,
    phase: ScenarioPhase,
) -> Wc029ScenarioPhaseWindow:
    return next(item for item in manifest.phase_windows if item.phase == phase)


def _require_in_phase(
    manifest: Wc029ScenarioExecutionManifest,
    phase: ScenarioPhase,
    value: UtcDateTime,
    *,
    label: str,
) -> None:
    window = _phase_window(manifest, phase)
    if value < window.started_at or value > window.completed_at:
        raise Wc029AcceptanceEvidenceError(f"{label} falls outside the signed {phase} phase window")


def _scenario_artifact_input_digest(
    artifact: _LoadedArtifact,
    *,
    plan: Wc029ScenarioPlanEvidence,
) -> str:
    evidence_class = artifact.declaration.evidence_class
    model = artifact.model
    if isinstance(model, Wc029ScenarioPlanEvidence):
        return model.plan_digest
    if isinstance(model, Wc029ResourceStateEvidence):
        return model.state_digest
    if isinstance(model, Wc029MutationReceipt):
        return model.result_digest
    if isinstance(model, MonitoringEvidenceHandoff):
        return plan.monitoring_request_digest
    if isinstance(model, ChangeEvidenceArtifact):
        return model.evidence.source_digest
    if isinstance(model, CorrelationReport):
        return model.request_digest
    if isinstance(model, PublishedCorrelationReportAttestation):
        return model.statement.correlation_request_digest
    if isinstance(model, Wc029IncidentOmission):
        return artifact.record.canonical_json_sha256
    if isinstance(model, IncidentState):
        return model.result_digest
    if isinstance(model, IncidentStateAttestation):
        return model.result_digest
    if isinstance(model, Wc029ManifestCitationEvidence):
        return model.citation_digest
    if isinstance(model, IncidentGuidance):
        return model.guidance_digest
    if isinstance(model, IncidentGuidanceAttestation):
        return model.guidance_digest
    if isinstance(model, IncidentEnrichmentManifest):
        return model.manifest_digest
    if isinstance(model, IncidentEnrichmentAttestation):
        return model.manifest_digest
    if isinstance(model, IncidentEnrichmentFeedPointer):
        return model.pointer_digest
    if isinstance(model, IncidentEnrichmentFeedPointerAttestation):
        return model.pointer_digest
    if isinstance(model, IncidentFeedIndexV2):
        return sha256_hex(model.canonical_bytes())
    if isinstance(model, IncidentFeedIndexAttestationV2):
        return model.index_digest
    if isinstance(model, IncidentNotificationEnvelopeV2):
        return model.notification.notification_digest
    if isinstance(model, Wc029RecoveryActionEvidence):
        return model.result_digest
    if isinstance(model, Wc029JobExecutionEvidence):
        return model.input_digest
    if isinstance(model, Wc029JobReadbackEvidence):
        return model.execution_digest
    if isinstance(model, Wc029QueueStateEvidence):
        return artifact.record.canonical_json_sha256
    if isinstance(model, Wc029RecoveryProof):
        return compute_artifact_digest(
            model.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
    raise Wc029AcceptanceEvidenceError(
        f"scenario artifact {artifact.declaration.artifact_id} "
        f"has no trusted input-digest rule for {evidence_class}"
    )


def _monitoring_request_digest(handoff: MonitoringEvidenceHandoff) -> str:
    return compute_artifact_digest(
        {
            "collectorContractDigest": handoff.collector_contract_digest,
            "collectionId": handoff.collection_id,
            "evidence": handoff.evidence.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
        }
    )


def _require_incident_state_digest(state: IncidentState) -> None:
    if state.result_digest != sha256_hex(incident_state_signature_preimage(state)):
        raise Wc029AcceptanceEvidenceError(
            "IncidentState resultDigest does not bind its signature preimage"
        )


def _validate_signed_scenario_execution(
    scenario: Wc029ScenarioEvidence,
    capability: Wc029ScenarioCapability,
    selected: Mapping[EvidenceClass, _LoadedArtifact],
    artifacts: Mapping[str, _LoadedArtifact],
) -> Wc029ScenarioExecutionManifest:
    plan = _require_model(
        selected["scenario-plan"],
        Wc029ScenarioPlanEvidence,
    )
    execution_manifest = _require_model(
        selected["scenario-execution-manifest"],
        Wc029ScenarioExecutionManifest,
    )
    execution_attestation = _require_model(
        selected["scenario-execution-attestation"],
        Wc029ScenarioExecutionAttestation,
    )
    if (
        execution_attestation.scenario_execution_id != execution_manifest.scenario_execution_id
        or execution_attestation.manifest_digest != execution_manifest.manifest_digest
        or selected["scenario-execution-attestation"].declaration.binds_artifact_id
        != selected["scenario-execution-manifest"].declaration.artifact_id
        or execution_manifest.scenario_id != scenario.scenario_id
        or execution_manifest.scenario_class != scenario.scenario_class
        or execution_manifest.evidence_mode != capability.evidence_mode
        or execution_manifest.capability_digest != capability.capability_digest
        or execution_manifest.source_commit != plan.source_commit
        or execution_manifest.target_resource_id.casefold()
        != capability.target_resource_id.casefold()
        or execution_manifest.mutation_action_digest != capability.mutation_action_digest
        or execution_manifest.recovery_action_digest != capability.recovery_action_digest
        or execution_manifest.monitoring_request_digest != plan.monitoring_request_digest
        or execution_manifest.correlation_request_digest != plan.correlation_request_digest
        or execution_manifest.change_request_digest != plan.change_request_digest
        or execution_manifest.verification_input_digest != plan.verification_input_digest
        or execution_manifest.plan_digest != plan.plan_digest
        or execution_manifest.scenario_execution_id != plan.scenario_execution_id
    ):
        raise Wc029AcceptanceEvidenceError(
            f"scenario {scenario.scenario_id} signed execution manifest "
            "does not match trusted capability and plan"
        )

    excluded_ids = {
        selected["scenario-execution-manifest"].declaration.artifact_id,
        selected["scenario-execution-attestation"].declaration.artifact_id,
    }
    expected_ids = {
        artifact_id
        for _phase, artifact_ids in scenario.phases.items()
        for artifact_id in artifact_ids
        if artifact_id not in excluded_ids
    }
    bindings = {item.artifact_id: item for item in execution_manifest.artifacts}
    if set(bindings) != expected_ids:
        raise Wc029AcceptanceEvidenceError(
            "signed scenario execution manifest does not cover every phase artifact"
        )
    phase_by_id = {
        artifact_id: phase
        for phase, artifact_ids in scenario.phases.items()
        for artifact_id in artifact_ids
    }
    for artifact_id, binding in bindings.items():
        bound = artifacts[artifact_id]
        if (
            binding.phase != phase_by_id[artifact_id]
            or binding.content_sha256 != bound.record.content_sha256
            or binding.input_digest != _scenario_artifact_input_digest(bound, plan=plan)
        ):
            raise Wc029AcceptanceEvidenceError(
                f"signed scenario binding for {artifact_id} is invalid"
            )
    return execution_manifest


def _validate_scenario_lifecycle(
    scenario: Wc029ScenarioEvidence,
    inventory: Wc029VersionInventory,
    selected: Mapping[EvidenceClass, _LoadedArtifact],
    artifacts: Mapping[str, _LoadedArtifact],
) -> None:
    active_state = _require_model(
        selected["incident-state-active"],
        IncidentState,
    )
    resolved_state = _require_model(
        selected["incident-state-resolved"],
        IncidentState,
    )
    expected_incident_scenario = {
        "web-tier-failure": "webServerFailure",
        "load-balancer-vip-failure": "loadBalancerFailure",
    }.get(scenario.scenario_class)
    if (
        expected_incident_scenario is None
        or active_state.scenario != expected_incident_scenario
        or resolved_state.scenario != expected_incident_scenario
        or active_state.lifecycle != "active"
        or resolved_state.lifecycle != "resolved"
        or active_state.incident_id != resolved_state.incident_id
    ):
        raise Wc029AcceptanceEvidenceError(
            f"scenario {scenario.scenario_id} incident lifecycle is inconsistent"
        )
    _require_incident_state_digest(active_state)
    _require_incident_state_digest(resolved_state)

    report = _require_model(selected["correlation-report"], CorrelationReport)
    report_attestation = _require_model(
        selected["correlation-report-attestation"],
        PublishedCorrelationReportAttestation,
    )
    authority = _require_model(
        artifacts[inventory.manifest.authority_artifact_id],
        Wc029PublicationAuthorityEvidence,
    ).authority
    if (
        report_attestation.statement.incident_id != active_state.incident_id
        or report_attestation.statement.incident_state_result_digest != active_state.result_digest
        or report_attestation.statement.authority_proof_digest
        != sha256_hex(authority.canonical_bytes())
    ):
        raise Wc029AcceptanceEvidenceError(
            "incident-producing report does not bind the active occurrence"
        )

    citation = _require_model(
        selected["manifest-citation"],
        Wc029ManifestCitationEvidence,
    )
    manifest = inventory.manifest
    published_manifest = _require_model(
        artifacts[manifest.manifest_artifact_id],
        Wc029PublishedManifestEvidence,
    )
    published_clauses = {item.clause_id for item in published_manifest.cited_clauses}
    if (
        citation.scenario_id != scenario.scenario_id
        or citation.scenario_execution_id
        != _require_model(
            selected["scenario-plan"],
            Wc029ScenarioPlanEvidence,
        ).scenario_execution_id
        or citation.manifest_id != manifest.manifest_id
        or citation.manifest_version != manifest.manifest_version
        or citation.profile_id != manifest.profile_id
        or citation.manifest_digest != manifest.manifest_digest
        or citation.correlation_report_id != report.report_id
        or citation.correlation_report_digest != report.report_digest
        or citation.incident_state_result_digest != active_state.result_digest
        or not set(citation.clause_ids).issubset(published_clauses)
    ):
        raise Wc029AcceptanceEvidenceError(
            "manifest citation does not match the exact published inventory"
        )

    guidance = _require_model(selected["guidance"], IncidentGuidance)
    enrichment = _require_model(
        selected["enrichment-manifest"],
        IncidentEnrichmentManifest,
    )
    active_feed = _require_model(
        selected["feed-active"],
        IncidentEnrichmentFeedPointer,
    )
    resolved_feed = _require_model(
        selected["feed-resolved"],
        IncidentEnrichmentFeedPointer,
    )
    active_feed_index = _require_model(
        selected["feed-index-active"],
        IncidentFeedIndexV2,
    )
    resolved_feed_index = _require_model(
        selected["feed-index-resolved"],
        IncidentFeedIndexV2,
    )
    active_notification = _require_model(
        selected["notification-active"],
        IncidentNotificationEnvelopeV2,
    ).notification
    resolved_notification = _require_model(
        selected["notification-resolved"],
        IncidentNotificationEnvelopeV2,
    ).notification
    active_entries = tuple(
        item for item in active_feed_index.active if item.incident_id == active_state.incident_id
    )
    resolved_entries = tuple(
        item
        for item in resolved_feed_index.recently_resolved
        if item.incident_id == resolved_state.incident_id
    )
    if len(active_entries) != 1 or len(resolved_entries) != 1:
        raise Wc029AcceptanceEvidenceError(
            "active and resolved feed indexes must each contain one scenario occurrence"
        )
    active_entry = active_entries[0]
    resolved_entry = resolved_entries[0]
    if (
        guidance.source_binding.incident_id != active_state.incident_id
        or guidance.source_binding.incident_state_digest != active_state.result_digest
        or guidance.source_binding.correlation_report_id != report.report_id
        or guidance.source_binding.correlation_report_digest != report.report_digest
        or enrichment.incident_id != active_state.incident_id
        or enrichment.incident_state_result_digest != active_state.result_digest
        or enrichment.correlation_report_asset.report_digest != report.report_digest
        or enrichment.guidance_asset.guidance_digest != guidance.guidance_digest
        or active_feed.lifecycle != "active"
        or active_feed.incident_id != active_state.incident_id
        or active_feed.state_result_digest != active_state.result_digest
        or active_feed.enrichment_asset.manifest_digest != enrichment.manifest_digest
        or active_entry.lifecycle != "active"
        or active_entry.state_result_digest != active_state.result_digest
        or active_entry.feed_pointer_reference.content_digest
        != sha256_hex(active_feed.canonical_bytes())
        or active_entry.feed_pointer_attestation_reference.content_digest
        != sha256_hex(
            _require_model(
                selected["feed-active-attestation"],
                IncidentEnrichmentFeedPointerAttestation,
            ).canonical_bytes()
        )
        or resolved_feed.lifecycle != "resolved"
        or any(item.incident_id == active_state.incident_id for item in resolved_feed_index.active)
        or resolved_feed_index.published_at < active_feed_index.published_at
        or resolved_feed.incident_id != resolved_state.incident_id
        or resolved_feed.state_result_digest != resolved_state.result_digest
        or resolved_entry.lifecycle != "resolved"
        or resolved_entry.state_result_digest != resolved_state.result_digest
        or resolved_entry.feed_pointer_reference.content_digest
        != sha256_hex(resolved_feed.canonical_bytes())
        or resolved_entry.feed_pointer_attestation_reference.content_digest
        != sha256_hex(
            _require_model(
                selected["feed-resolved-attestation"],
                IncidentEnrichmentFeedPointerAttestation,
            ).canonical_bytes()
        )
        or active_notification.lifecycle != "active"
        or active_notification.incident_id != active_state.incident_id
        or active_notification.transition_id != active_state.transition_id
        or active_notification.state_result_digest != active_state.result_digest
        or active_notification.occurrence_digest != active_feed.occurrence_digest
        or active_notification.enrichment_asset != active_feed.enrichment_asset
        or active_notification.feed_pointer_reference.content_digest
        != sha256_hex(active_feed.canonical_bytes())
        or active_notification.feed_pointer_reference != active_entry.feed_pointer_reference
        or active_notification.feed_pointer_attestation_reference
        != active_entry.feed_pointer_attestation_reference
        or active_notification.feed_index_digest != sha256_hex(active_feed_index.canonical_bytes())
        or active_notification.feed_published_at != active_feed_index.published_at
        or active_notification.guidance_asset != enrichment.guidance_asset
        or resolved_notification.lifecycle != "resolved"
        or resolved_notification.incident_id != resolved_state.incident_id
        or resolved_notification.transition_id != resolved_state.transition_id
        or resolved_notification.state_result_digest != resolved_state.result_digest
        or resolved_notification.occurrence_digest != resolved_feed.occurrence_digest
        or resolved_notification.enrichment_asset != resolved_feed.enrichment_asset
        or resolved_notification.feed_pointer_reference.content_digest
        != sha256_hex(resolved_feed.canonical_bytes())
        or resolved_notification.feed_pointer_reference != resolved_entry.feed_pointer_reference
        or resolved_notification.feed_pointer_attestation_reference
        != resolved_entry.feed_pointer_attestation_reference
        or resolved_notification.feed_index_digest
        != sha256_hex(resolved_feed_index.canonical_bytes())
        or resolved_notification.feed_published_at != resolved_feed_index.published_at
    ):
        raise Wc029AcceptanceEvidenceError(
            f"scenario {scenario.scenario_id} signed incident assets do not form one chain"
        )


def _validate_scenario_evidence(
    index: Wc029AcceptanceEvidenceIndex,
    inventory: Wc029VersionInventory,
    artifacts: Mapping[str, _LoadedArtifact],
) -> None:
    capabilities = {item.scenario_class: item for item in inventory.scenario_capabilities}
    for scenario in index.scenarios:
        capability = capabilities[scenario.scenario_class]
        if scenario.evidence_mode != capability.evidence_mode:
            raise Wc029AcceptanceEvidenceError(
                f"scenario {scenario.scenario_id} evidence mode does not match "
                "trusted deployed capability"
            )
        selected = _scenario_artifacts_by_class(scenario, artifacts)
        plan = _require_model(
            selected["scenario-plan"],
            Wc029ScenarioPlanEvidence,
        )
        mutation = _require_model(
            selected["mutation-receipt"],
            Wc029MutationReceipt,
        )
        recovery = _require_model(
            selected["recovery-action"],
            Wc029RecoveryActionEvidence,
        )
        baseline_state = _require_model(
            selected["baseline-state"],
            Wc029ResourceStateEvidence,
        )
        recovered_state = _require_model(
            selected["recovered-state"],
            Wc029ResourceStateEvidence,
        )
        job_execution = _require_model(
            selected["job-execution"],
            Wc029JobExecutionEvidence,
        )
        job_readback = _require_model(
            selected["job-readback"],
            Wc029JobReadbackEvidence,
        )
        proof = _require_model(
            selected["recovery-proof"],
            Wc029RecoveryProof,
        )
        execution_manifest = _validate_signed_scenario_execution(
            scenario,
            capability,
            selected,
            artifacts,
        )
        if (
            plan.scenario_id != scenario.scenario_id
            or plan.scenario_class != scenario.scenario_class
            or plan.evidence_mode != capability.evidence_mode
            or plan.capability_digest != capability.capability_digest
            or plan.source_commit != inventory.source_commit
            or plan.target_resource_id.casefold() != capability.target_resource_id.casefold()
            or plan.mutation_action_digest != capability.mutation_action_digest
            or plan.recovery_action_digest != capability.recovery_action_digest
            or plan.baseline_state_artifact_id != selected["baseline-state"].declaration.artifact_id
            or plan.baseline_state_digest != baseline_state.state_digest
            or baseline_state.capture_kind != "baseline"
            or baseline_state.scenario_id != scenario.scenario_id
            or baseline_state.scenario_execution_id != plan.scenario_execution_id
            or baseline_state.scenario_class != scenario.scenario_class
            or baseline_state.plan_digest is not None
            or baseline_state.mutation_receipt_digest is not None
            or baseline_state.target_resource_id.casefold() != plan.target_resource_id.casefold()
            or mutation.scenario_id != scenario.scenario_id
            or mutation.scenario_execution_id != plan.scenario_execution_id
            or mutation.scenario_class != scenario.scenario_class
            or mutation.plan_digest != plan.plan_digest
            or mutation.target_resource_id.casefold() != plan.target_resource_id.casefold()
            or mutation.mutation_action_digest != plan.mutation_action_digest
            or recovery.scenario_id != scenario.scenario_id
            or recovery.scenario_execution_id != plan.scenario_execution_id
            or recovery.scenario_class != scenario.scenario_class
            or recovery.plan_digest != plan.plan_digest
            or recovery.mutation_receipt_digest != mutation.result_digest
            or recovery.target_resource_id.casefold() != plan.target_resource_id.casefold()
            or recovery.recovery_action_digest != plan.recovery_action_digest
            or recovery.recovered_at < mutation.applied_at
            or recovered_state.capture_kind != "recovered"
            or recovered_state.scenario_id != scenario.scenario_id
            or recovered_state.scenario_execution_id != plan.scenario_execution_id
            or recovered_state.scenario_class != scenario.scenario_class
            or recovered_state.plan_digest != plan.plan_digest
            or recovered_state.mutation_receipt_digest != mutation.result_digest
            or recovered_state.target_resource_id.casefold() != plan.target_resource_id.casefold()
            or recovered_state.captured_at < recovery.recovered_at
            or recovered_state.state_digest != baseline_state.state_digest
            or proof.scenario_id != scenario.scenario_id
            or proof.scenario_execution_id != plan.scenario_execution_id
            or proof.scenario_class != scenario.scenario_class
            or proof.plan_digest != plan.plan_digest
            or proof.mutation_receipt_digest != mutation.result_digest
            or proof.recovery_action_result_digest != recovery.result_digest
            or proof.target_resource_id.casefold() != plan.target_resource_id.casefold()
            or proof.baseline_state_digest != baseline_state.state_digest
            or proof.recovered_state_digest != recovered_state.state_digest
            or proof.baseline_state.artifact_id
            != selected["baseline-state"].declaration.artifact_id
            or proof.baseline_state.content_sha256
            != selected["baseline-state"].record.content_sha256
            or proof.recovered_state.artifact_id
            != selected["recovered-state"].declaration.artifact_id
            or proof.recovered_state.content_sha256
            != selected["recovered-state"].record.content_sha256
            or proof.post_recovery_job_readback.artifact_id
            != selected["job-readback"].declaration.artifact_id
            or proof.post_recovery_job_readback.content_sha256
            != selected["job-readback"].record.content_sha256
            or proof.verified_at < recovery.recovered_at
            or execution_manifest.mutation_receipt_digest != mutation.result_digest
            or execution_manifest.recovery_action_result_digest != recovery.result_digest
        ):
            raise Wc029AcceptanceEvidenceError(
                f"scenario {scenario.scenario_id} phase receipts are not one exact chain"
            )

        verify_ids = set(scenario.phases.verify) - {
            selected["recovery-proof"].declaration.artifact_id
        }
        if not set(proof.evidence_artifact_ids).issubset(verify_ids):
            raise Wc029AcceptanceEvidenceError(
                "recovery proof references evidence outside its verify phase"
            )
        job_readback_id = selected["job-readback"].declaration.artifact_id
        if job_readback_id not in proof.evidence_artifact_ids:
            raise Wc029AcceptanceEvidenceError(
                "recovery proof must cite the scenario Job read-back"
            )
        job_results = {
            item.artifact_id: item.content_sha256 for item in job_readback.result_artifacts
        }
        if (
            job_execution.scenario_execution_id != plan.scenario_execution_id
            or job_execution.scenario_plan_digest != plan.plan_digest
            or job_execution.input_digest != plan.verification_input_digest
            or job_execution.started_at < recovery.recovered_at
            or job_execution.started_at < recovered_state.captured_at
            or job_readback.scenario_execution_id != plan.scenario_execution_id
            or job_readback.scenario_plan_digest != plan.plan_digest
            or job_readback.observed_at < job_execution.completed_at
            or job_readback.observed_at < recovered_state.captured_at
            or proof.verified_at < job_readback.observed_at
            or job_results.get(selected["recovered-state"].declaration.artifact_id)
            != selected["recovered-state"].record.content_sha256
            or job_results.get(selected["recovery-action"].declaration.artifact_id)
            != selected["recovery-action"].record.content_sha256
        ):
            raise Wc029AcceptanceEvidenceError(
                "post-recovery Job evidence does not bind recovered state and action"
            )

        report = _require_model(selected["correlation-report"], CorrelationReport)
        monitoring = _require_model(
            selected["monitoring-evidence"],
            MonitoringEvidenceHandoff,
        )
        if (
            report.binding_mode != "publishedRuntime"
            or report.preview_only
            or report.no_auto_remediation is not True
            or report.request_digest != plan.correlation_request_digest
            or plan.monitoring_request_digest != _monitoring_request_digest(monitoring)
        ):
            raise Wc029AcceptanceEvidenceError(
                "scenario correlation report is not a published read-only result"
            )
        if scenario.scenario_class == "nsg-connectivity-loss":
            change = _require_model(
                selected["change-evidence"],
                ChangeEvidenceArtifact,
            )
            if (
                change.evidence.source_digest != plan.change_request_digest
                or change.evidence.target_resource_id.casefold()
                != plan.target_resource_id.casefold()
            ):
                raise Wc029AcceptanceEvidenceError(
                    "change evidence does not bind the trusted scenario request and target"
                )
            _require_in_phase(
                execution_manifest,
                "observe",
                change.evidence.occurred_at,
                label="change occurrence",
            )
            _require_in_phase(
                execution_manifest,
                "observe",
                change.evidence.received_at,
                label="change receipt",
            )

        _require_in_phase(
            execution_manifest,
            "plan",
            plan.planned_at,
            label="scenario plan",
        )
        _require_in_phase(
            execution_manifest,
            "plan",
            baseline_state.captured_at,
            label="baseline state",
        )
        _require_in_phase(
            execution_manifest,
            "apply",
            mutation.applied_at,
            label="mutation receipt",
        )
        _require_in_phase(
            execution_manifest,
            "observe",
            monitoring.observed_at,
            label="monitoring evidence",
        )
        _require_in_phase(
            execution_manifest,
            "observe",
            report.as_of,
            label="correlation report",
        )
        _require_in_phase(
            execution_manifest,
            "recover",
            recovery.recovered_at,
            label="recovery action",
        )
        for label, timestamp in (
            ("recovered state", recovered_state.captured_at),
            ("verification Job start", job_execution.started_at),
            ("verification Job completion", job_execution.completed_at),
            ("verification Job read-back", job_readback.observed_at),
            ("recovery proof", proof.verified_at),
        ):
            _require_in_phase(
                execution_manifest,
                "verify",
                timestamp,
                label=label,
            )

        if capability.evidence_mode == "correlation-only":
            omission = _require_model(
                selected["incident-omission"],
                Wc029IncidentOmission,
            )
            if (
                omission.scenario_id != scenario.scenario_id
                or omission.scenario_execution_id != plan.scenario_execution_id
            ):
                raise Wc029AcceptanceEvidenceError(
                    "incident omission does not bind its correlation-only scenario"
                )
            _require_in_phase(
                execution_manifest,
                "observe",
                omission.observed_at,
                label="incident omission",
            )
            continue
        queue = _require_model(
            selected["queue-state"],
            Wc029QueueStateEvidence,
        )
        if (
            queue.capture_scope != "scenario-verify"
            or queue.scenario_id != scenario.scenario_id
            or queue.scenario_execution_id != plan.scenario_execution_id
            or selected["queue-state"].declaration.artifact_id not in proof.evidence_artifact_ids
            or proof.verified_at < queue.captured_at
        ):
            raise Wc029AcceptanceEvidenceError(
                "incident-producing recovery proof requires its drained queue evidence"
            )
        active_state = _require_model(
            selected["incident-state-active"],
            IncidentState,
        )
        resolved_state = _require_model(
            selected["incident-state-resolved"],
            IncidentState,
        )
        guidance = _require_model(selected["guidance"], IncidentGuidance)
        active_feed = _require_model(
            selected["feed-active"],
            IncidentEnrichmentFeedPointer,
        )
        active_feed_index = _require_model(
            selected["feed-index-active"],
            IncidentFeedIndexV2,
        )
        active_notification = _require_model(
            selected["notification-active"],
            IncidentNotificationEnvelopeV2,
        ).notification
        resolved_feed = _require_model(
            selected["feed-resolved"],
            IncidentEnrichmentFeedPointer,
        )
        resolved_feed_index = _require_model(
            selected["feed-index-resolved"],
            IncidentFeedIndexV2,
        )
        resolved_notification = _require_model(
            selected["notification-resolved"],
            IncidentNotificationEnvelopeV2,
        ).notification
        for label, timestamp in (
            ("active IncidentState", active_state.updated_at),
            ("incident guidance", guidance.generated_at),
            ("active feed pointer", active_feed.published_at),
            ("active feed index", active_feed_index.published_at),
            ("active notification", active_notification.feed_published_at),
        ):
            _require_in_phase(
                execution_manifest,
                "observe",
                timestamp,
                label=label,
            )
        for label, timestamp in (
            ("resolved IncidentState", resolved_state.updated_at),
            ("resolved feed pointer", resolved_feed.published_at),
            ("resolved feed index", resolved_feed_index.published_at),
            ("resolved notification", resolved_notification.feed_published_at),
            ("scenario queue drain", queue.captured_at),
        ):
            _require_in_phase(
                execution_manifest,
                "verify",
                timestamp,
                label=label,
            )
            if proof.verified_at < timestamp:
                raise Wc029AcceptanceEvidenceError(f"recovery proof precedes {label}")
        _validate_scenario_lifecycle(
            scenario,
            inventory,
            selected,
            artifacts,
        )


def _validate_global_chronology(
    index: Wc029AcceptanceEvidenceIndex,
    inventory: Wc029VersionInventory,
    artifacts: Mapping[str, _LoadedArtifact],
) -> None:
    baseline_queue = next(
        _require_model(item, Wc029QueueStateEvidence)
        for item in artifacts.values()
        if item.declaration.evidence_class == "queue-state"
        and item.declaration.queue_scope == "baseline"
    )
    final_queue = next(
        _require_model(item, Wc029QueueStateEvidence)
        for item in artifacts.values()
        if item.declaration.evidence_class == "queue-state"
        and item.declaration.queue_scope == "final"
    )
    capability_readback = next(
        _require_model(item, Wc029DeploymentReadbackEvidence)
        for item in artifacts.values()
        if item.declaration.evidence_class == "deployment-readback"
        and item.declaration.deployment_id == inventory.capability_deployment_id
    )
    scenario_starts: list[UtcDateTime] = []
    scenario_completions: list[UtcDateTime] = []
    for scenario in index.scenarios:
        selected = _scenario_artifacts_by_class(scenario, artifacts)
        plan = _require_model(
            selected["scenario-plan"],
            Wc029ScenarioPlanEvidence,
        )
        baseline_state = _require_model(
            selected["baseline-state"],
            Wc029ResourceStateEvidence,
        )
        proof = _require_model(
            selected["recovery-proof"],
            Wc029RecoveryProof,
        )
        scenario_starts.append(min(plan.planned_at, baseline_state.captured_at))
        scenario_completions.append(proof.verified_at)
    if (
        capability_readback.observed_at > baseline_queue.captured_at
        or baseline_queue.captured_at > min(scenario_starts)
        or final_queue.captured_at < max(scenario_completions)
    ):
        raise Wc029AcceptanceEvidenceError(
            "global deployment, baseline, scenario, and final chronology is invalid"
        )


def _validate_specialized_evidence(
    index: Wc029AcceptanceEvidenceIndex,
    inventory: Wc029VersionInventory,
    artifacts: Mapping[str, _LoadedArtifact],
) -> None:
    owners = _artifact_owners(index)
    scenario_by_id = {item.scenario_id: item for item in index.scenarios}
    capability_modes = {
        item.scenario_class: item.evidence_mode for item in inventory.scenario_capabilities
    }
    for artifact in artifacts.values():
        declaration = artifact.declaration
        if declaration.evidence_class == "queue-state":
            if not isinstance(artifact.model, Wc029QueueStateEvidence):
                raise Wc029AcceptanceEvidenceError("queue-state evidence is invalid")
            if artifact.model.capture_scope != declaration.queue_scope:
                raise Wc029AcceptanceEvidenceError(
                    f"queue-state {declaration.artifact_id} scope does not match its index"
                )
            owner = owners[declaration.artifact_id]
            if declaration.queue_scope == "scenario-verify":
                if (
                    owner is None
                    or owner[1] != "verify"
                    or artifact.model.scenario_id != owner[0]
                    or capability_modes[scenario_by_id[owner[0]].scenario_class]
                    != "incident-producing"
                ):
                    raise Wc029AcceptanceEvidenceError(
                        "scenario queue-state must verify one incident-producing scenario"
                    )
            elif owner is not None:
                raise Wc029AcceptanceEvidenceError(
                    "baseline and final queue-state evidence must be global"
                )
        elif declaration.evidence_class == "incident-omission":
            if not isinstance(artifact.model, Wc029IncidentOmission):
                raise Wc029AcceptanceEvidenceError("incident omission evidence is invalid")
            owner = owners[declaration.artifact_id]
            if (
                owner is None
                or owner[1] != "observe"
                or artifact.model.scenario_id != owner[0]
                or capability_modes[scenario_by_id[owner[0]].scenario_class] != "correlation-only"
            ):
                raise Wc029AcceptanceEvidenceError(
                    "incident omission does not bind its correlation-only scenario"
                )
    _validate_preflight_evidence(inventory, artifacts)
    _validate_job_evidence(index, inventory, artifacts)
    _validate_url_probes(inventory, artifacts)
    _validate_publication_authority(inventory, artifacts)
    _validate_scenario_evidence(index, inventory, artifacts)
    _validate_global_chronology(index, inventory, artifacts)


def _sorted_scenario(scenario: Wc029ScenarioEvidence) -> Wc029ScenarioEvidence:
    return Wc029ScenarioEvidence(
        scenarioId=scenario.scenario_id,
        scenarioClass=scenario.scenario_class,
        evidenceMode=scenario.evidence_mode,
        phases=Wc029ScenarioPhases(
            plan=tuple(sorted(scenario.phases.plan)),
            apply=tuple(sorted(scenario.phases.apply)),
            observe=tuple(sorted(scenario.phases.observe)),
            recover=tuple(sorted(scenario.phases.recover)),
            verify=tuple(sorted(scenario.phases.verify)),
        ),
    )


def aggregate_acceptance_evidence(
    evidence_root: Path,
    *,
    approved_inventory_sha256: str,
    index_file: str = "acceptance-index.json",
) -> Wc029AcceptanceEvidenceRecord:
    """Build one canonical WC-029 record without network or Azure operations."""

    root = Path(evidence_root)
    index_relative = _validate_relative_file(index_file)
    snapshot = _capture_bundle_snapshot(
        root,
        index_relative=index_relative,
    )
    index_raw = snapshot.files[index_relative]
    index_parsed, index_canonical = _parse_strict_json(
        index_raw,
        label="acceptance index",
    )
    try:
        index = Wc029AcceptanceEvidenceIndex.model_validate_json(index_raw)
    except (ValidationError, TypeError, ValueError) as exc:
        raise Wc029AcceptanceEvidenceError("acceptance index failed closed validation") from exc

    if any(item.path.casefold() == index_relative.casefold() for item in index.artifacts):
        raise Wc029AcceptanceEvidenceError(
            "acceptance index path must not also be declared as evidence"
        )
    expected_files = {index_relative, *(item.path for item in index.artifacts)}
    discovered_files = set(snapshot.files)
    if discovered_files != expected_files:
        missing = sorted(expected_files - discovered_files)
        unlisted = sorted(discovered_files - expected_files)
        raise Wc029AcceptanceEvidenceError(
            f"evidence directory membership mismatch; missing={missing}, unlisted={unlisted}"
        )
    artifact_total_bytes = sum(len(snapshot.files[item.path]) for item in index.artifacts)
    total_bytes = len(index_raw) + artifact_total_bytes
    if artifact_total_bytes > MAX_TOTAL_EVIDENCE_BYTES:
        raise Wc029AcceptanceEvidenceError("aggregate evidence exceeds its total byte bound")
    loaded: dict[str, _LoadedArtifact] = {}
    remaining_bytes = MAX_TOTAL_EVIDENCE_BYTES
    for declaration in index.artifacts:
        declared_size = len(snapshot.files[declaration.path])
        if declared_size > remaining_bytes:
            raise Wc029AcceptanceEvidenceError(
                "aggregate evidence exceeds its remaining byte budget"
            )
        loaded_artifact = _load_artifact(
            snapshot.files[declaration.path],
            declaration,
        )
        loaded[declaration.artifact_id] = loaded_artifact
        remaining_bytes -= len(loaded_artifact.raw)

    inventory_loaded = loaded[index.version_inventory_artifact_id]
    if not isinstance(inventory_loaded.model, Wc029VersionInventory):
        raise Wc029AcceptanceEvidenceError("version inventory artifact is invalid")
    try:
        approved_inventory_sha256 = _validate_digest(
            approved_inventory_sha256,
            label="approvedInventorySha256",
        )
    except ValueError as exc:
        raise Wc029AcceptanceEvidenceError("approved inventory digest is invalid") from exc
    if inventory_loaded.record.content_sha256 != approved_inventory_sha256:
        raise Wc029AcceptanceEvidenceError(
            "version inventory does not match the out-of-band approved digest"
        )
    inventory = inventory_loaded.model

    _validate_deployment_evidence(inventory, loaded)
    _validate_specialized_evidence(index, inventory, loaded)
    _validate_signed_artifacts(inventory, loaded)

    source_index = Wc029SourceIndexRecord(
        path=index_relative,
        sizeBytes=len(index_raw),
        contentSha256=sha256_hex(index_raw),
        canonicalJsonSha256=sha256_hex(index_canonical),
    )
    artifacts = tuple(loaded[artifact_id].record for artifact_id in sorted(loaded))
    scenarios = tuple(
        _sorted_scenario(scenario)
        for scenario in sorted(index.scenarios, key=lambda item: item.scenario_class)
    )
    draft = Wc029AcceptanceEvidenceRecord.model_construct(
        schema_version=ACCEPTANCE_RECORD_SCHEMA_VERSION,
        acceptance_id=index.acceptance_id,
        validation_mode="offline-contract-digest-and-signature",
        azure_mutation_performed=False,
        incident_evidence_synthesized=False,
        evidence_status="complete",
        source_index=source_index,
        approved_inventory_sha256=approved_inventory_sha256,
        version_inventory=inventory,
        global_artifact_ids=tuple(sorted(index.global_artifact_ids)),
        scenarios=scenarios,
        artifacts=artifacts,
        artifact_count=len(artifacts),
        total_evidence_bytes=total_bytes,
        aggregate_digest=_ZERO_DIGEST,
    )
    record_payload = {
        **draft.model_dump(mode="json", by_alias=True, exclude_none=True),
        "aggregateDigest": compute_artifact_digest(draft._digest_payload()),
    }
    return Wc029AcceptanceEvidenceRecord.model_validate_json(canonicalize_json(record_payload))


def write_acceptance_record(
    record: Wc029AcceptanceEvidenceRecord,
    *,
    output_directory: Path,
    evidence_root: Path,
) -> Path:
    """Create a content-addressed record exclusively outside the captured input root."""

    root, root_identity = _stable_directory_path(
        evidence_root,
        label="evidence root",
    )
    output_root, output_identity = _stable_directory_path(
        output_directory,
        label="output directory",
    )
    root_pin = _open_pinned_directory(root, root_identity)
    output_pin = _open_pinned_directory(output_root, output_identity)
    try:
        if output_root == root or output_root.is_relative_to(root):
            raise Wc029AcceptanceEvidenceError(
                "output directory must be outside the read-only evidence root"
            )
        filename = "wc029-acceptance-" + record.aggregate_digest.removeprefix("sha256:") + ".json"
        staging_name = f".{filename}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        output_path = output_root / filename
        staging_path = output_root / staging_name
        payload = record.canonical_bytes()

        descriptor = -1
        try:
            if os.name == "nt":
                with staging_path.open("xb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            else:
                descriptor = os.open(
                    staging_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=output_pin.descriptor,
                )
                with os.fdopen(descriptor, "wb", closefd=True) as stream:
                    descriptor = -1
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
        except FileExistsError as exc:
            raise Wc029AcceptanceEvidenceError(
                "acceptance staging path unexpectedly already exists"
            ) from exc
        except OSError as exc:
            raise Wc029AcceptanceEvidenceError(
                "acceptance record staging bytes could not be persisted"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

        try:
            if os.name == "nt":
                os.link(staging_path, output_path)
            else:
                os.link(
                    staging_name,
                    filename,
                    src_dir_fd=output_pin.descriptor,
                    dst_dir_fd=output_pin.descriptor,
                    follow_symlinks=False,
                )
        except FileExistsError as exc:
            if os.name == "nt":
                staging_path.unlink(missing_ok=True)
            else:
                with suppress(OSError):
                    os.unlink(staging_name, dir_fd=output_pin.descriptor)
            raise Wc029AcceptanceEvidenceError(
                "refusing to overwrite an existing immutable acceptance record"
            ) from exc
        except OSError as exc:
            if os.name == "nt":
                staging_path.unlink(missing_ok=True)
            else:
                with suppress(OSError):
                    os.unlink(staging_name, dir_fd=output_pin.descriptor)
            raise Wc029AcceptanceEvidenceError(
                "acceptance record could not be created exclusively"
            ) from exc

        if os.name == "nt":
            with suppress(OSError):
                staging_path.unlink()
        else:
            with suppress(OSError):
                os.unlink(staging_name, dir_fd=output_pin.descriptor)
        return output_path
    finally:
        output_pin.close()
        root_pin.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate captured WC-029 evidence into one canonical, "
            "content-addressed offline record."
        )
    )
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument(
        "--index",
        default="acceptance-index.json",
        help="portable path below evidence_root",
    )
    parser.add_argument("--approved-inventory-sha256", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        record = aggregate_acceptance_evidence(
            args.evidence_root,
            approved_inventory_sha256=args.approved_inventory_sha256,
            index_file=args.index,
        )
        output = write_acceptance_record(
            record,
            output_directory=args.output_directory,
            evidence_root=args.evidence_root,
        )
    except Wc029AcceptanceEvidenceError as exc:
        print(
            json.dumps(
                {"complete": False, "error": str(exc)},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "aggregateDigest": record.aggregate_digest,
                "complete": True,
                "output": str(output),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACCEPTANCE_INDEX_SCHEMA_VERSION",
    "ACCEPTANCE_RECORD_SCHEMA_VERSION",
    "DEPLOYMENT_READBACK_SCHEMA_VERSION",
    "INCIDENT_OMISSION_SCHEMA_VERSION",
    "JOB_EXECUTION_SCHEMA_VERSION",
    "JOB_READBACK_SCHEMA_VERSION",
    "MANIFEST_CITATION_SCHEMA_VERSION",
    "MUTATION_RECEIPT_SCHEMA_VERSION",
    "PREFLIGHT_RESULT_SCHEMA_VERSION",
    "PUBLISHED_MANIFEST_SCHEMA_VERSION",
    "PUBLICATION_AUTHORITY_ATTESTATION_SCHEMA_VERSION",
    "PUBLICATION_AUTHORITY_SCHEMA_VERSION",
    "QUEUE_STATE_SCHEMA_VERSION",
    "RECOVERY_ACTION_SCHEMA_VERSION",
    "RECOVERY_PROOF_SCHEMA_VERSION",
    "REQUIRED_SCENARIO_CLASSES",
    "RESOURCE_STATE_SCHEMA_VERSION",
    "SCENARIO_EXECUTION_ATTESTATION_SCHEMA_VERSION",
    "SCENARIO_EXECUTION_MANIFEST_SCHEMA_VERSION",
    "SCENARIO_PLAN_SCHEMA_VERSION",
    "SIGNING_PUBLIC_KEY_SCHEMA_VERSION",
    "URL_PROBE_SCHEMA_VERSION",
    "VERSION_INVENTORY_SCHEMA_VERSION",
    "Wc029AcceptanceEvidenceError",
    "Wc029AcceptanceEvidenceIndex",
    "Wc029AcceptanceEvidenceRecord",
    "Wc029DeploymentHandoffEvidence",
    "Wc029DeploymentPlanEvidence",
    "Wc029DeploymentReadbackEvidence",
    "Wc029DeploymentVersion",
    "Wc029EndpointVersion",
    "Wc029EvidenceFileDeclaration",
    "Wc029ImageVersion",
    "Wc029IncidentOmission",
    "Wc029JobExecutionEvidence",
    "Wc029JobReadbackEvidence",
    "Wc029KeyVersion",
    "Wc029ManifestCitationEvidence",
    "Wc029ManifestVersion",
    "Wc029MutationReceipt",
    "Wc029PreflightResultEvidence",
    "Wc029PublishedClause",
    "Wc029PublishedManifestEvidence",
    "Wc029PublicationAuthorityAttestation",
    "Wc029PublicationAuthorityEvidence",
    "Wc029QueueState",
    "Wc029QueueStateEvidence",
    "Wc029RecoveryActionEvidence",
    "Wc029RecoveryProof",
    "Wc029ResourceStateEvidence",
    "Wc029RbacBoundary",
    "Wc029ScenarioArtifactBinding",
    "Wc029ScenarioCapability",
    "Wc029ScenarioEvidence",
    "Wc029ScenarioExecutionAttestation",
    "Wc029ScenarioExecutionManifest",
    "Wc029ScenarioPhaseWindow",
    "Wc029ScenarioPlanEvidence",
    "Wc029ScenarioPhases",
    "Wc029SigningPublicKeyEvidence",
    "Wc029UrlProbeEvidence",
    "Wc029VersionInventory",
    "aggregate_acceptance_evidence",
    "main",
    "write_acceptance_record",
]
