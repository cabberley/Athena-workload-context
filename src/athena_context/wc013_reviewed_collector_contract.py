from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import ValidationError

from athena_context.wc013_collector_controller import Wc013CollectorStartContract

_MAX_ARTIFACT_BYTES = 512 * 1024
_MAX_INDEX_BYTES = 128 * 1024
_MAX_REVIEWED_DEPLOYMENTS = 16
_PHASES = ("baseline", "faulted", "recovered")
_PHASE_BINDINGS = {
    "baseline": (
        "-op-baseline-collector",
        "wc013-baseline-evidence-collector",
        "/opt/athena/wc013-live/delivery/configs/baseline.json",
    ),
    "faulted": (
        "-op-faulted-collector",
        "wc013-faulted-evidence-collector",
        "/opt/athena/wc013-live/delivery/configs/faulted.json",
    ),
    "recovered": (
        "-op-recovered-collector",
        "wc013-recovered-evidence-collector",
        "/opt/athena/wc013-live/delivery/configs/recovered.json",
    ),
}
_SHA256_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
_GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_DEPLOYMENT_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[0-9a-fA-F-]{36})/providers/"
    r"Microsoft\.Resources/deployments/"
    r"wc013-ready-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$"
)
_TEMPLATE_HASH_PATTERN = re.compile(r"^[0-9]{1,32}$")
_CONTROLLER_IMAGE_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{3,48}[a-z0-9])\.azurecr\.io/"
    r"[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$"
)
_DEPLOYMENT_NAME_PATTERN = re.compile(
    r"^wc013-ready-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$"
)
_OUTER_KEYS = frozenset(
    {
        "schemaVersion",
        "deploymentResourceId",
        "deploymentCorrelationId",
        "deploymentTemplateHash",
        "sourceCommit",
        "controllerImage",
        "collectorContractsDigest",
        "collectorContractDigests",
        "contracts",
    }
)


class ReviewedCollectorContractError(RuntimeError):
    """Raised when a reviewed deployment contract artifact is not exact."""


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReviewedCollectorContractError(
                "reviewed deployment contract contains duplicate JSON keys"
            )
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ReviewedCollectorContractError(
        f"reviewed deployment contract contains invalid JSON constant {value}"
    )


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_digest(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReviewedCollectorContractError(
            "reviewed deployment contracts are not canonical JSON values"
        ) from exc
    return _digest(payload)


def _validate_expected_digest(value: str) -> None:
    if _SHA256_PATTERN.fullmatch(value) is None or value == "sha256:" + "0" * 64:
        raise ReviewedCollectorContractError(
            "expected reviewed artifact digest must be a non-placeholder sha256 digest"
        )


def select_reviewed_collector_contract(
    artifact_path: Path,
    *,
    expected_artifact_digest: str,
    expected_deployment_resource_id: str,
    expected_deployment_correlation_id: str,
    expected_deployment_template_hash: str,
    expected_source_commit: str,
    phase: Literal["baseline", "faulted", "recovered"],
) -> Wc013CollectorStartContract:
    """Select one phase from an exact deployment-bound, byte-pinned artifact."""

    _validate_expected_digest(expected_artifact_digest)
    if phase not in _PHASES:
        raise ReviewedCollectorContractError("collector phase is not allowlisted")
    expected_deployment_match = _DEPLOYMENT_RESOURCE_ID_PATTERN.fullmatch(
        expected_deployment_resource_id
    )
    if expected_deployment_match is None:
        raise ReviewedCollectorContractError(
            "expected deployment resource ID is not an immutable WC-013 ready identifier"
        )
    if _GUID_PATTERN.fullmatch(expected_deployment_correlation_id) is None:
        raise ReviewedCollectorContractError(
            "expected deployment correlation ID is not a GUID"
        )
    if _TEMPLATE_HASH_PATTERN.fullmatch(expected_deployment_template_hash) is None:
        raise ReviewedCollectorContractError("expected deployment template hash is invalid")
    if _COMMIT_PATTERN.fullmatch(expected_source_commit) is None:
        raise ReviewedCollectorContractError("expected deployment source commit is invalid")

    try:
        payload = artifact_path.read_bytes()
    except OSError as exc:
        raise ReviewedCollectorContractError(
            "reviewed deployment contract artifact is unavailable"
        ) from exc
    if not payload or len(payload) > _MAX_ARTIFACT_BYTES:
        raise ReviewedCollectorContractError(
            "reviewed deployment contract artifact is empty or oversized"
        )
    if _digest(payload) != expected_artifact_digest:
        raise ReviewedCollectorContractError(
            "reviewed deployment contract artifact digest does not match"
        )

    try:
        parsed = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewedCollectorContractError(
            "reviewed deployment contract artifact is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(parsed, dict) or set(parsed) != _OUTER_KEYS:
        raise ReviewedCollectorContractError(
            "reviewed deployment contract artifact has unexpected fields"
        )
    if parsed["schemaVersion"] != "athena.wc013CollectorDeploymentContract.v2":
        raise ReviewedCollectorContractError(
            "reviewed deployment contract artifact schema is unsupported"
        )
    exact_metadata = {
        "deploymentResourceId": expected_deployment_resource_id,
        "deploymentCorrelationId": expected_deployment_correlation_id,
        "deploymentTemplateHash": expected_deployment_template_hash,
        "sourceCommit": expected_source_commit,
    }
    if any(parsed[name] != value for name, value in exact_metadata.items()):
        raise ReviewedCollectorContractError(
            "reviewed deployment contract metadata does not match the approved execution"
        )

    controller_image = parsed["controllerImage"]
    if (
        not isinstance(controller_image, str)
        or _CONTROLLER_IMAGE_PATTERN.fullmatch(controller_image) is None
        or controller_image.endswith("@sha256:" + "0" * 64)
    ):
        raise ReviewedCollectorContractError(
            "reviewed deployment contract controller image is not an exact ACR digest"
        )

    contracts = parsed["contracts"]
    if not isinstance(contracts, dict) or set(contracts) != set(_PHASES):
        raise ReviewedCollectorContractError(
            "reviewed deployment contract must contain exactly the three phases"
        )
    contract_digests = parsed["collectorContractDigests"]
    if not isinstance(contract_digests, dict) or set(contract_digests) != set(_PHASES):
        raise ReviewedCollectorContractError(
            "reviewed deployment contract must pin each selected contract"
        )
    for contract_phase in _PHASES:
        contract_digest = contract_digests[contract_phase]
        if (
            not isinstance(contract_digest, str)
            or _SHA256_PATTERN.fullmatch(contract_digest) is None
            or contract_digest == "sha256:" + "0" * 64
            or _canonical_digest(contracts[contract_phase]) != contract_digest
        ):
            raise ReviewedCollectorContractError(
                f"reviewed {contract_phase} collector contract digest does not match"
            )
    contracts_digest = parsed["collectorContractsDigest"]
    if (
        not isinstance(contracts_digest, str)
        or _SHA256_PATTERN.fullmatch(contracts_digest) is None
        or contracts_digest == "sha256:" + "0" * 64
        or _canonical_digest(contracts) != contracts_digest
    ):
        raise ReviewedCollectorContractError(
            "reviewed deployment collector contracts digest does not match"
        )

    deployment_subscription = expected_deployment_match.group("subscription").casefold()
    reviewed: dict[str, Wc013CollectorStartContract] = {}
    common_binding: tuple[str, str, str, str, str, str] | None = None
    job_ids: set[str] = set()
    for contract_phase in _PHASES:
        try:
            contract = Wc013CollectorStartContract.model_validate(
                contracts[contract_phase]
            )
        except ValidationError as exc:
            raise ReviewedCollectorContractError(
                f"reviewed {contract_phase} collector contract failed validation"
            ) from exc
        expected_suffix, expected_container_name, expected_config_path = (
            _PHASE_BINDINGS[contract_phase]
        )
        if not contract.job_resource_id.casefold().endswith(expected_suffix):
            raise ReviewedCollectorContractError(
                f"reviewed {contract_phase} collector contract targets the wrong job"
            )
        collector_container = contract.template.containers[0]
        if (
            collector_container.name != expected_container_name
            or collector_container.args[2] != expected_config_path
        ):
            raise ReviewedCollectorContractError(
                f"reviewed {contract_phase} collector contract has the wrong fixed "
                "phase semantics"
            )
        job_subscription = contract.job_resource_id.split("/", 3)[2].casefold()
        if job_subscription != deployment_subscription:
            raise ReviewedCollectorContractError(
                "reviewed collector contract is outside the deployment subscription"
            )
        normalized_job_id = contract.job_resource_id.casefold()
        if normalized_job_id in job_ids:
            raise ReviewedCollectorContractError(
                "reviewed deployment contract repeats a collector job"
            )
        job_ids.add(normalized_job_id)
        binding = (
            contract.evidence_identity_resource_id.casefold(),
            contract.evidence_identity_client_id.casefold(),
            contract.wc007_pinned_authority_digest,
            contract.wc008_pinned_assertion_digest,
            contract.configuration.registries[0].server,
            contract.template.containers[0].image,
        )
        if common_binding is None:
            common_binding = binding
        elif binding != common_binding:
            raise ReviewedCollectorContractError(
                "reviewed phase collector contracts do not share one deployment binding"
            )
        reviewed[contract_phase] = contract
    if common_binding is None or controller_image.split("/", 1)[0] != common_binding[4]:
        raise ReviewedCollectorContractError(
            "reviewed controller and collector images must use the same exact ACR"
        )
    return reviewed[phase]


def _load_strict_json(path: Path, *, maximum_bytes: int, label: str) -> object:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ReviewedCollectorContractError(f"{label} is unavailable") from exc
    if not payload or len(payload) > maximum_bytes:
        raise ReviewedCollectorContractError(f"{label} is empty or oversized")
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewedCollectorContractError(
            f"{label} is not strict UTF-8 JSON"
        ) from exc


def select_indexed_reviewed_collector_contract(
    index_path: Path,
    *,
    deployment: str,
    phase: Literal["baseline", "faulted", "recovered"],
) -> Wc013CollectorStartContract:
    """Resolve an allowlisted deployment without accepting a caller-supplied path."""

    if _DEPLOYMENT_NAME_PATTERN.fullmatch(deployment) is None:
        raise ReviewedCollectorContractError(
            "collector deployment selection is not an immutable reviewed identifier"
        )
    parsed = _load_strict_json(
        index_path,
        maximum_bytes=_MAX_INDEX_BYTES,
        label="reviewed deployment contract index",
    )
    if not isinstance(parsed, dict) or set(parsed) != {"schemaVersion", "deployments"}:
        raise ReviewedCollectorContractError(
            "reviewed deployment contract index has unexpected fields"
        )
    if parsed["schemaVersion"] != "athena.wc013CollectorDeploymentContractIndex.v1":
        raise ReviewedCollectorContractError(
            "reviewed deployment contract index schema is unsupported"
        )
    deployments = parsed["deployments"]
    if (
        not isinstance(deployments, dict)
        or len(deployments) > _MAX_REVIEWED_DEPLOYMENTS
        or any(
            not isinstance(name, str)
            or _DEPLOYMENT_NAME_PATTERN.fullmatch(name) is None
            for name in deployments
        )
    ):
        raise ReviewedCollectorContractError(
            "reviewed deployment contract index contains invalid deployment keys"
        )
    entry = deployments.get(deployment)
    expected_entry_keys = {
        "artifactFile",
        "artifactDigest",
        "deploymentResourceId",
        "deploymentCorrelationId",
        "deploymentTemplateHash",
        "sourceCommit",
    }
    if not isinstance(entry, dict) or set(entry) != expected_entry_keys:
        raise ReviewedCollectorContractError(
            "collector deployment selection is not present in the reviewed index"
        )
    if any(not isinstance(value, str) for value in entry.values()):
        raise ReviewedCollectorContractError(
            "reviewed deployment index metadata must contain only exact strings"
        )
    artifact_file = entry["artifactFile"]
    if artifact_file != f"{deployment}.json":
        raise ReviewedCollectorContractError(
            "reviewed deployment artifact filename is not exact"
        )
    deployment_resource_id = entry["deploymentResourceId"]
    if not deployment_resource_id.endswith(f"/deployments/{deployment}"):
        raise ReviewedCollectorContractError(
            "reviewed deployment resource ID does not match its index key"
        )
    return select_reviewed_collector_contract(
        index_path.parent / artifact_file,
        expected_artifact_digest=entry["artifactDigest"],
        expected_deployment_resource_id=deployment_resource_id,
        expected_deployment_correlation_id=entry["deploymentCorrelationId"],
        expected_deployment_template_hash=entry["deploymentTemplateHash"],
        expected_source_commit=entry["sourceCommit"],
        phase=phase,
    )


def write_reviewed_collector_contract(
    contract: Wc013CollectorStartContract,
    output_path: Path,
) -> None:
    payload = contract.model_dump_json(
        by_alias=True,
        exclude_none=True,
    ).encode("utf-8")
    try:
        with output_path.open("xb") as stream:
            stream.write(payload)
    except OSError as exc:
        raise ReviewedCollectorContractError(
            "selected collector contract output could not be created exclusively"
        ) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Select an exact collector contract from a reviewed deployment artifact."
    )
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--phase", required=True, choices=_PHASES)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        contract = select_indexed_reviewed_collector_contract(
            args.index,
            deployment=args.deployment,
            phase=cast(Literal["baseline", "faulted", "recovered"], args.phase),
        )
        write_reviewed_collector_contract(contract, args.output)
    except ReviewedCollectorContractError as exc:
        print(f"WC-013 reviewed collector contract selection failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
