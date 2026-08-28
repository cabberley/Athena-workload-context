from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    sha256_hex,
)
from athena_context.contracts.models import UtcDateTime

ARGUS_PRESENTATION_SCHEMA_VERSION = "athena.argus.presentation.v1"
ARGUS_PRESENTATION_ATTESTATION_SCHEMA_VERSION = (
    "athena.argus.presentationAttestation.v1"
)
ATHENA_WEB_NODE_FAULT_SCENARIO_ID = "athena-web-node-fault.v1"
SYNTHETIC_WORKLOAD_NAME = "Synthetic Athena web workload"

type ArgusPresentationPhase = Literal["baseline", "faulted", "recovered"]
type ArgusPresentationVerdict = Literal["pass", "fail", "resolved"]
type ArgusServiceState = Literal["healthy", "degraded-redundancy", "recovered"]
type ArgusRiskLevel = Literal["normal", "warning"]

_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_SYNTHETIC_ID_PATTERN = r"^synthetic-[a-z0-9][a-z0-9-]{0,126}$"
_SYNTHETIC_KEY_PATTERN = r"^synthetic-key://[a-z0-9][a-z0-9._/-]{0,199}$"
_FAULT_RUN_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_RESOURCE_GROUP_PATTERN = r"^[A-Za-z0-9_().-]{1,90}$"
_VM_NAME_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?$"
_PREFIX_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
_SEMVER_PATTERN = (
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_SUMMARY_BY_PHASE: dict[ArgusPresentationPhase, str] = {
    "baseline": "Both synthetic web nodes are represented as running.",
    "faulted": (
        "One redundant synthetic web node is stopped while its peer remains running."
    ),
    "recovered": (
        "The affected synthetic web node is represented as running after recovery."
    ),
}
_PREDICTED_ISSUE_BY_PHASE: dict[ArgusPresentationPhase, str] = {
    "baseline": "No synthetic web-node fault detected",
    "faulted": "Reduced synthetic web-tier redundancy",
    "recovered": "Synthetic web-tier redundancy restored",
}
_RECOMMENDED_ACTION_BY_PHASE: dict[ArgusPresentationPhase, str] = {
    "baseline": (
        "Observe the synthetic baseline and confirm both redundant nodes are represented "
        "as healthy."
    ),
    "faulted": (
        "Review the synthetic finding and authorize recovery only through the separate "
        "demo operator workflow."
    ),
    "recovered": (
        "Confirm the synthetic node and redundancy indicators are healthy, then close "
        "the demo finding."
    ),
}


class _StrictPresentationModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
    )

    def canonical_json(self) -> str:
        return canonicalize_json(
            self.model_dump(mode="json", by_alias=True, exclude_none=True)
        )


def _azure_vm_resource_id_components(value: str) -> tuple[str, str, str]:
    parts = value.strip("/").split("/")
    if (
        len(parts) != 8
        or parts[0].casefold() != "subscriptions"
        or not _GUID_RE.fullmatch(parts[1])
        or parts[2].casefold() != "resourcegroups"
        or parts[4].casefold() != "providers"
        or parts[5].casefold() != "microsoft.compute"
        or parts[6].casefold() != "virtualmachines"
    ):
        raise AthenaValidationError(
            "targetVmResourceId must be one exact Azure virtual-machine resource ID"
        )
    return parts[1], parts[3], parts[7]


class DemoFaultRunReceipt(_StrictPresentationModel):
    schema_version: Literal["athena.demoFaultRun.v1"] = Field(alias="schemaVersion")
    fault_run_id: str = Field(alias="faultRunId", pattern=_FAULT_RUN_ID_PATTERN)
    fault_kind: Literal["web-node-power-state"] = Field(alias="faultKind")
    action: Literal["inject", "status", "reset"]
    resource_group: str = Field(alias="resourceGroup", pattern=_RESOURCE_GROUP_PATTERN)
    prefix: str = Field(pattern=_PREFIX_PATTERN)
    target_vm_name: str = Field(alias="targetVmName", pattern=_VM_NAME_PATTERN)
    target_vm_resource_id: str = Field(
        alias="targetVmResourceId",
        min_length=1,
        max_length=1024,
    )
    eligible_web_vm_names: tuple[
        str,
        ...,
    ] = Field(alias="eligibleWebVmNames", min_length=2, max_length=100)
    before_power_state: Literal[
        "PowerState/running",
        "PowerState/stopped",
        "PowerState/deallocated",
    ] = Field(alias="beforePowerState")
    after_power_state: Literal[
        "PowerState/running",
        "PowerState/stopped",
        "PowerState/deallocated",
    ] = Field(alias="afterPowerState")
    started_at: UtcDateTime = Field(alias="startedAt")
    completed_at: UtcDateTime = Field(alias="completedAt")
    outcome: Literal["confirmed"]

    @model_validator(mode="after")
    def validate_receipt_binding(self) -> DemoFaultRunReceipt:
        if self.resource_group.endswith("."):
            raise AthenaValidationError("resourceGroup must not end with a period")
        if tuple(sorted(self.eligible_web_vm_names)) != self.eligible_web_vm_names:
            raise AthenaValidationError(
                "eligibleWebVmNames must use deterministic ordinal ordering"
            )
        normalized_names = [name.casefold() for name in self.eligible_web_vm_names]
        if len(normalized_names) != len(set(normalized_names)):
            raise AthenaValidationError("eligibleWebVmNames must be unique")
        if any(not re.fullmatch(_VM_NAME_PATTERN, name) for name in self.eligible_web_vm_names):
            raise AthenaValidationError(
                "eligibleWebVmNames contains an invalid Azure VM name"
            )
        if self.target_vm_name.casefold() not in normalized_names:
            raise AthenaValidationError(
                "targetVmName must be present in eligibleWebVmNames"
            )
        if not self.target_vm_name.casefold().startswith(
            self.prefix.casefold() + "-"
        ):
            raise AthenaValidationError(
                "targetVmName must be within the receipt prefix"
            )
        _, resource_group, vm_name = _azure_vm_resource_id_components(
            self.target_vm_resource_id
        )
        if (
            resource_group.casefold() != self.resource_group.casefold()
            or vm_name.casefold() != self.target_vm_name.casefold()
        ):
            raise AthenaValidationError(
                "targetVmResourceId must match resourceGroup and targetVmName"
            )
        if self.completed_at < self.started_at:
            raise AthenaValidationError("completedAt must not precede startedAt")
        if self.action == "status" and (
            self.before_power_state != self.after_power_state
        ):
            raise AthenaValidationError(
                "status receipts must not represent a power-state transition"
            )
        if self.action == "inject" and (
            self.before_power_state != "PowerState/running"
            or self.after_power_state
            not in {"PowerState/stopped", "PowerState/deallocated"}
        ):
            raise AthenaValidationError(
                "inject receipts must confirm running-to-faulted state"
            )
        if self.action == "reset" and (
            self.before_power_state
            not in {"PowerState/stopped", "PowerState/deallocated"}
            or self.after_power_state != "PowerState/running"
        ):
            raise AthenaValidationError(
                "reset receipts must confirm faulted-to-running state"
            )
        return self


class ArgusWorkload(_StrictPresentationModel):
    name: Literal["Synthetic Athena web workload"]
    manifest_id: str = Field(alias="manifestId", pattern=_SYNTHETIC_ID_PATTERN)
    manifest_version: str = Field(alias="manifestVersion", pattern=_SEMVER_PATTERN)
    profile_id: str = Field(alias="profileId", pattern=_SYNTHETIC_ID_PATTERN)
    resource_group: str = Field(alias="resourceGroup", pattern=_SYNTHETIC_ID_PATTERN)


class ArgusFaultRun(_StrictPresentationModel):
    fault_run_id: str = Field(alias="faultRunId", pattern=_SYNTHETIC_ID_PATTERN)
    target_vm_name: str = Field(alias="targetVmName", pattern=_SYNTHETIC_ID_PATTERN)
    after_power_state: Literal["stopped", "running"] = Field(
        alias="afterPowerState"
    )


class ArgusAthenaMetadata(_StrictPresentationModel):
    snapshot_id: str = Field(alias="snapshotId", pattern=_SYNTHETIC_ID_PATTERN)
    artifact_digest: str = Field(alias="artifactDigest", pattern=_DIGEST_PATTERN)
    semantic_digest: str = Field(alias="semanticDigest", pattern=_DIGEST_PATTERN)
    result_digest: str = Field(alias="resultDigest", pattern=_DIGEST_PATTERN)
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        pattern=_SYNTHETIC_KEY_PATTERN,
    )


class ArgusWebTierState(_StrictPresentationModel):
    expected_nodes: int = Field(alias="expectedNodes", ge=2, le=100)
    running_nodes: int = Field(alias="runningNodes", ge=0, le=100)
    faulted_nodes: int = Field(alias="faultedNodes", ge=0, le=100)
    service_state: ArgusServiceState = Field(alias="serviceState")

    @model_validator(mode="after")
    def validate_counts(self) -> ArgusWebTierState:
        if self.expected_nodes != self.running_nodes + self.faulted_nodes:
            raise AthenaValidationError(
                "web-tier expectedNodes must equal runningNodes plus faultedNodes"
            )
        return self


class ArgusRuntimeState(_StrictPresentationModel):
    web_tier: ArgusWebTierState = Field(alias="webTier")


class ArgusFinding(_StrictPresentationModel):
    clause_id: str = Field(alias="clauseId", pattern=_SYNTHETIC_ID_PATTERN)
    verdict: ArgusPresentationVerdict
    summary: str = Field(min_length=1, max_length=240)
    evidence_refs: tuple[str, ...] = Field(
        alias="evidenceRefs",
        min_length=1,
        max_length=100,
    )

    @model_validator(mode="after")
    def validate_evidence_refs(self) -> ArgusFinding:
        if any(not re.fullmatch(_SYNTHETIC_ID_PATTERN, ref) for ref in self.evidence_refs):
            raise AthenaValidationError(
                "presentation evidenceRefs must contain only synthetic identifiers"
            )
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs:
            raise AthenaValidationError(
                "presentation evidenceRefs must be unique and ordinally sorted"
            )
        return self


class ArgusRecommendation(_StrictPresentationModel):
    risk_level: ArgusRiskLevel = Field(alias="riskLevel")
    predicted_issue: str = Field(alias="predictedIssue", min_length=1, max_length=160)
    recommended_action: str = Field(
        alias="recommendedAction",
        min_length=1,
        max_length=300,
    )


class ArgusPresentationPayload(_StrictPresentationModel):
    schema_version: Literal["athena.argus.presentation.v1"] = Field(
        alias="schemaVersion"
    )
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    phase: ArgusPresentationPhase
    workload: ArgusWorkload
    fault_run: ArgusFaultRun | None = Field(default=None, alias="faultRun")
    athena: ArgusAthenaMetadata
    runtime_state: ArgusRuntimeState = Field(alias="runtimeState")
    findings: tuple[ArgusFinding, ...] = Field(min_length=1, max_length=100)
    argus: ArgusRecommendation

    def canonical_preimage(self) -> bytes:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        athena = payload.get("athena")
        if not isinstance(athena, dict):
            raise AthenaValidationError("presentation athena metadata is required")
        athena.pop("resultDigest", None)
        return canonicalize_json(payload).encode("utf-8")

    @model_validator(mode="after")
    def validate_phase_contract(self) -> ArgusPresentationPayload:
        expected_verdict: ArgusPresentationVerdict
        expected_service_state: ArgusServiceState
        expected_risk: ArgusRiskLevel
        if self.phase == "baseline":
            expected_verdict = "pass"
            expected_service_state = "healthy"
            expected_risk = "normal"
            if self.fault_run is not None:
                raise AthenaValidationError("baseline presentations must omit faultRun")
            if (
                self.runtime_state.web_tier.faulted_nodes != 0
                or self.runtime_state.web_tier.running_nodes
                != self.runtime_state.web_tier.expected_nodes
            ):
                raise AthenaValidationError(
                    "baseline presentations require every web node to be running"
                )
        elif self.phase == "faulted":
            expected_verdict = "fail"
            expected_service_state = "degraded-redundancy"
            expected_risk = "warning"
            if (
                self.fault_run is None
                or self.fault_run.after_power_state != "stopped"
            ):
                raise AthenaValidationError(
                    "faulted presentations require a stopped synthetic faultRun"
                )
            if (
                self.runtime_state.web_tier.faulted_nodes != 1
                or self.runtime_state.web_tier.running_nodes < 1
            ):
                raise AthenaValidationError(
                    "faulted presentations require one failed node and a running peer"
                )
        else:
            expected_verdict = "resolved"
            expected_service_state = "recovered"
            expected_risk = "normal"
            if (
                self.fault_run is None
                or self.fault_run.after_power_state != "running"
            ):
                raise AthenaValidationError(
                    "recovered presentations require a running synthetic faultRun"
                )
            if (
                self.runtime_state.web_tier.faulted_nodes != 0
                or self.runtime_state.web_tier.running_nodes
                != self.runtime_state.web_tier.expected_nodes
            ):
                raise AthenaValidationError(
                    "recovered presentations require every web node to be running"
                )

        if self.runtime_state.web_tier.service_state != expected_service_state:
            raise AthenaValidationError(
                "web-tier serviceState does not match presentation phase"
            )
        if self.argus.risk_level != expected_risk:
            raise AthenaValidationError("ARGUS riskLevel does not match presentation phase")
        if (
            self.argus.predicted_issue != _PREDICTED_ISSUE_BY_PHASE[self.phase]
            or self.argus.recommended_action
            != _RECOMMENDED_ACTION_BY_PHASE[self.phase]
        ):
            raise AthenaValidationError(
                "ARGUS guidance must use the frozen synthetic-safe phase text"
            )
        if any(
            finding.verdict != expected_verdict
            or finding.summary != _SUMMARY_BY_PHASE[self.phase]
            for finding in self.findings
        ):
            raise AthenaValidationError(
                "presentation findings do not match the frozen phase semantics"
            )
        clause_ids = [finding.clause_id for finding in self.findings]
        if len(clause_ids) != len(set(clause_ids)):
            raise AthenaValidationError("presentation clauseIds must be unique")
        if self.athena.result_digest != sha256_hex(self.canonical_preimage()):
            raise AthenaValidationError(
                "presentation resultDigest does not match canonical presentation bytes"
            )
        return self


class PresentationAttestation(_StrictPresentationModel):
    schema_version: Literal[
        "athena.argus.presentationAttestation.v1"
    ] = Field(alias="schemaVersion")
    result_digest: str = Field(alias="resultDigest", pattern=_DIGEST_PATTERN)
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        pattern=_SYNTHETIC_KEY_PATTERN,
    )
    detached_signature: str = Field(
        alias="detachedSignature",
        min_length=1,
        max_length=16384,
        pattern=r"^[A-Za-z0-9_-]+$",
    )


def presentation_phase_summary(phase: ArgusPresentationPhase) -> str:
    return _SUMMARY_BY_PHASE[phase]


def presentation_phase_predicted_issue(phase: ArgusPresentationPhase) -> str:
    return _PREDICTED_ISSUE_BY_PHASE[phase]


def presentation_phase_recommended_action(phase: ArgusPresentationPhase) -> str:
    return _RECOMMENDED_ACTION_BY_PHASE[phase]


__all__ = [
    "ARGUS_PRESENTATION_ATTESTATION_SCHEMA_VERSION",
    "ARGUS_PRESENTATION_SCHEMA_VERSION",
    "ATHENA_WEB_NODE_FAULT_SCENARIO_ID",
    "SYNTHETIC_WORKLOAD_NAME",
    "ArgusAthenaMetadata",
    "ArgusFaultRun",
    "ArgusFinding",
    "ArgusPresentationPayload",
    "ArgusPresentationPhase",
    "ArgusPresentationVerdict",
    "ArgusRecommendation",
    "ArgusRiskLevel",
    "ArgusRuntimeState",
    "ArgusServiceState",
    "ArgusWebTierState",
    "ArgusWorkload",
    "DemoFaultRunReceipt",
    "PresentationAttestation",
    "presentation_phase_predicted_issue",
    "presentation_phase_recommended_action",
    "presentation_phase_summary",
]
