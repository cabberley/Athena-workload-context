from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_MAX_INDEX_BYTES = 128 * 1024
_MAX_ARTIFACT_BYTES = 512 * 1024
_MAX_CONTRACT_BYTES = 128 * 1024
_MAX_REVIEWED_DEPLOYMENTS = 16
_PHASE_BINDINGS = {
    "baseline": (
        "-base-col",
        "wc013-baseline-evidence-collector",
        "/opt/athena/wc013-live/delivery/configs/baseline.json",
    ),
    "faulted": (
        "-fault-col",
        "wc013-faulted-evidence-collector",
        "/opt/athena/wc013-live/delivery/configs/faulted.json",
    ),
    "recovered": (
        "-recover-col",
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
_DEPLOYMENT_NAME_PATTERN = re.compile(
    r"^wc013-ready-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$"
)
_DEPLOYMENT_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[0-9a-fA-F-]{36})/providers/"
    r"Microsoft\.Resources/deployments/"
    r"(?P<deployment>wc013-ready-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12})$"
)
_TEMPLATE_HASH_PATTERN = re.compile(r"^[0-9]{1,32}$")
_ACR_SERVER_PATTERN = re.compile(r"^[a-z0-9]{5,50}\.azurecr\.io$")
_IDENTITY_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}/"
    r"providers/Microsoft\.ManagedIdentity/userAssignedIdentities/"
    r"[A-Za-z0-9-_]{1,128}$"
)
_JOB_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[0-9a-fA-F-]{36})/resourceGroups/"
    r"[A-Za-z0-9._()-]{1,90}/providers/Microsoft\.App/jobs/"
    r"(?P<name>[A-Za-z0-9-]{1,64})$"
)
_CONTROLLER_IMAGE_PATTERN = re.compile(
    r"^(?P<server>[a-z0-9]{5,50}\.azurecr\.io)/athena/wc013-controller"
    r"@sha256:(?P<digest>[a-f0-9]{64})$"
)
_INDEX_KEYS = frozenset({"schemaVersion", "deployments"})
_INDEX_ENTRY_KEYS = frozenset(
    {
        "artifactFile",
        "artifactDigest",
        "deploymentResourceId",
        "deploymentCorrelationId",
        "deploymentTemplateHash",
        "sourceCommit",
    }
)
_ARTIFACT_KEYS = frozenset(
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
_SELECTION_KEYS = frozenset(
    {
        "schemaVersion",
        "deployment",
        "phase",
        "controllerImage",
        "contractDigest",
        "contract",
    }
)


class StrictWc013SelectionError(RuntimeError):
    """Raised before mutable JSON values can reach workflow execution plumbing."""


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StrictWc013SelectionError(
                "strict WC-013 JSON contains a duplicate object key"
            )
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise StrictWc013SelectionError(
        "strict WC-013 JSON contains a non-standard numeric constant"
    )


def _load_strict_json(path: Path, *, maximum_bytes: int, label: str) -> tuple[bytes, object]:
    try:
        payload = path.read_bytes()
    except OSError:
        raise StrictWc013SelectionError(f"{label} is unavailable") from None
    if not payload or len(payload) > maximum_bytes:
        raise StrictWc013SelectionError(f"{label} is empty or oversized")
    try:
        parsed = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise StrictWc013SelectionError(
            f"{label} is not strict UTF-8 JSON"
        ) from None
    return payload, parsed


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise StrictWc013SelectionError(
            "strict WC-013 selection contains a non-canonical JSON value"
        ) from None


def _canonical_digest(value: object) -> str:
    return _digest(_canonical_bytes(value))


def _require_exact_object(value: object, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise StrictWc013SelectionError(f"{label} has unexpected fields")
    return value


def _require_non_placeholder_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or _SHA256_PATTERN.fullmatch(value) is None
        or value == "sha256:" + "0" * 64
    ):
        raise StrictWc013SelectionError(f"{label} is not a real sha256 digest")
    return value


def _phase_contract_binding(
    contract: object,
    phase: str,
    deployment_subscription: str,
) -> tuple[str, ...]:
    contract = _require_exact_object(
        contract,
        frozenset(
            {
                "schemaVersion",
                "jobResourceId",
                "evidenceIdentityResourceId",
                "evidenceIdentityClientId",
                "wc007PinnedAuthorityDigest",
                "wc008PinnedAssertionDigest",
                "configuration",
                "template",
            }
        ),
        f"reviewed {phase} contract",
    )
    if contract["schemaVersion"] != "athena.wc013CollectorStartContract.v1":
        raise StrictWc013SelectionError(
            f"reviewed {phase} contract schema is unsupported"
        )
    expected_suffix, expected_name, expected_config = _PHASE_BINDINGS[phase]
    job_resource_id = contract["jobResourceId"]
    evidence_resource_id = contract["evidenceIdentityResourceId"]
    evidence_client_id = contract["evidenceIdentityClientId"]
    wc007_digest = contract["wc007PinnedAuthorityDigest"]
    wc008_digest = contract["wc008PinnedAssertionDigest"]
    job_match = (
        _JOB_RESOURCE_ID_PATTERN.fullmatch(job_resource_id)
        if isinstance(job_resource_id, str)
        else None
    )
    if (
        job_match is None
        or not job_resource_id.casefold().endswith(expected_suffix)
        or job_match.group("subscription").casefold()
        != deployment_subscription.casefold()
    ):
        raise StrictWc013SelectionError(
            f"reviewed {phase} contract targets the wrong deployment job"
        )
    if (
        not isinstance(evidence_resource_id, str)
        or _IDENTITY_RESOURCE_ID_PATTERN.fullmatch(evidence_resource_id) is None
        or not isinstance(evidence_client_id, str)
        or _GUID_PATTERN.fullmatch(evidence_client_id) is None
    ):
        raise StrictWc013SelectionError(
            f"reviewed {phase} contract has invalid evidence identity bindings"
        )
    _require_non_placeholder_digest(wc007_digest, f"reviewed {phase} WC-007 digest")
    _require_non_placeholder_digest(wc008_digest, f"reviewed {phase} WC-008 digest")

    configuration = _require_exact_object(
        contract["configuration"],
        frozenset(
            {
                "triggerType",
                "replicaRetryLimit",
                "replicaTimeout",
                "manualTriggerConfig",
                "registries",
            }
        ),
        f"reviewed {phase} configuration",
    )
    manual_trigger = _require_exact_object(
        configuration["manualTriggerConfig"],
        frozenset({"parallelism", "replicaCompletionCount"}),
        f"reviewed {phase} manual trigger",
    )
    registries = configuration["registries"]
    if (
        configuration["triggerType"] != "Manual"
        or configuration["replicaRetryLimit"] != 0
        or configuration["replicaTimeout"] != 900
        or manual_trigger != {"parallelism": 1, "replicaCompletionCount": 1}
        or not isinstance(registries, list)
        or len(registries) != 1
    ):
        raise StrictWc013SelectionError(
            f"reviewed {phase} configuration is not the fixed manual job"
        )
    registry = _require_exact_object(
        registries[0],
        frozenset({"server", "identity"}),
        f"reviewed {phase} registry",
    )
    registry_server = registry["server"]
    if (
        not isinstance(registry_server, str)
        or _ACR_SERVER_PATTERN.fullmatch(registry_server) is None
        or not isinstance(registry["identity"], str)
        or registry["identity"].casefold() != evidence_resource_id.casefold()
    ):
        raise StrictWc013SelectionError(
            f"reviewed {phase} registry is not bound to the evidence identity"
        )

    template = _require_exact_object(
        contract["template"],
        frozenset({"containers"}),
        f"reviewed {phase} template",
    )
    containers = template["containers"]
    if not isinstance(containers, list) or len(containers) != 1:
        raise StrictWc013SelectionError(
            f"reviewed {phase} template must have one container"
        )
    container = _require_exact_object(
        containers[0],
        frozenset({"name", "image", "command", "args", "env", "resources"}),
        f"reviewed {phase} container",
    )
    image = container["image"]
    args = container["args"]
    if (
        container["name"] != expected_name
        or not isinstance(image, str)
        or container["command"] != ["athena-context"]
        or not isinstance(args, list)
        or len(args) != 8
        or args[0] != "wc013-evidence-collector-job"
        or args[1] != "--config"
        or args[2] != expected_config
        or args[3] != "--artifact-blob-endpoint"
        or not isinstance(args[4], str)
        or not args[4].startswith("https://")
        or not args[4].endswith(".blob.core.windows.net")
        or args[5] != "--artifact-container"
        or not isinstance(args[6], str)
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?", args[6]) is None
        or args[7] != "--emit-handoff-base64"
    ):
        raise StrictWc013SelectionError(
            f"reviewed {phase} container has the wrong fixed arguments"
        )
    image_prefix = f"{registry_server}/athena/wc013-live@sha256:"
    image_digest = image.removeprefix(image_prefix)
    if (
        image != image_prefix + image_digest
        or re.fullmatch(r"[a-f0-9]{64}", image_digest) is None
        or image_digest == "0" * 64
    ):
        raise StrictWc013SelectionError(
            f"reviewed {phase} contract has an invalid acceptance image"
        )

    environment = container["env"]
    if not isinstance(environment, list) or len(environment) != 4:
        raise StrictWc013SelectionError(
            f"reviewed {phase} environment is not exact"
        )
    environment_values: dict[str, str] = {}
    for item in environment:
        variable = _require_exact_object(
            item,
            frozenset({"name", "value"}),
            f"reviewed {phase} environment variable",
        )
        name = variable["name"]
        value = variable["value"]
        if not isinstance(name, str) or not isinstance(value, str) or name in environment_values:
            raise StrictWc013SelectionError(
                f"reviewed {phase} environment is ambiguous"
            )
        environment_values[name] = value
    if environment_values != {
        "AZURE_CLIENT_ID": evidence_client_id,
        "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID": evidence_client_id,
        "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST": wc007_digest,
        "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": wc008_digest,
    }:
        raise StrictWc013SelectionError(
            f"reviewed {phase} environment is not evidence-only"
        )
    resources = _require_exact_object(
        container["resources"],
        frozenset({"cpu", "memory"}),
        f"reviewed {phase} resources",
    )
    if (
        resources["cpu"] != "0.5"
        or resources["memory"] != "1Gi"
    ):
        raise StrictWc013SelectionError(
            f"reviewed {phase} resources are not exact"
        )
    return (
        evidence_resource_id.casefold(),
        evidence_client_id.casefold(),
        str(wc007_digest),
        str(wc008_digest),
        registry_server,
        image,
    )


def select_strict_wc013_contract(
    index_path: Path,
    *,
    deployment: str,
    phase: str,
) -> bytes:
    """Return one canonical bounded selection after strict recursive JSON verification."""

    if _DEPLOYMENT_NAME_PATTERN.fullmatch(deployment) is None:
        raise StrictWc013SelectionError(
            "deployment is not an immutable WC-013 reviewed identifier"
        )
    if phase not in _PHASE_BINDINGS:
        raise StrictWc013SelectionError("phase is not allowlisted")

    _, raw_index = _load_strict_json(
        index_path,
        maximum_bytes=_MAX_INDEX_BYTES,
        label="reviewed deployment index",
    )
    index = _require_exact_object(raw_index, _INDEX_KEYS, "reviewed deployment index")
    if index["schemaVersion"] != "athena.wc013CollectorDeploymentContractIndex.v1":
        raise StrictWc013SelectionError("reviewed deployment index schema is unsupported")
    deployments = index["deployments"]
    if (
        not isinstance(deployments, dict)
        or len(deployments) > _MAX_REVIEWED_DEPLOYMENTS
        or any(
            not isinstance(name, str)
            or _DEPLOYMENT_NAME_PATTERN.fullmatch(name) is None
            for name in deployments
        )
    ):
        raise StrictWc013SelectionError("reviewed deployment index keys are invalid")
    entry = _require_exact_object(
        deployments.get(deployment),
        _INDEX_ENTRY_KEYS,
        "reviewed deployment index entry",
    )
    if any(not isinstance(value, str) for value in entry.values()):
        raise StrictWc013SelectionError(
            "reviewed deployment index metadata must be exact strings"
        )
    artifact_file = entry["artifactFile"]
    if artifact_file != f"{deployment}.json":
        raise StrictWc013SelectionError("reviewed artifact filename is not exact")
    expected_artifact_digest = _require_non_placeholder_digest(
        entry["artifactDigest"], "reviewed artifact digest"
    )
    deployment_resource_id = entry["deploymentResourceId"]
    deployment_match = _DEPLOYMENT_RESOURCE_ID_PATTERN.fullmatch(deployment_resource_id)
    if deployment_match is None or deployment_match.group("deployment") != deployment:
        raise StrictWc013SelectionError("reviewed deployment resource ID is not exact")
    if _GUID_PATTERN.fullmatch(entry["deploymentCorrelationId"]) is None:
        raise StrictWc013SelectionError("reviewed deployment correlation ID is invalid")
    if _TEMPLATE_HASH_PATTERN.fullmatch(entry["deploymentTemplateHash"]) is None:
        raise StrictWc013SelectionError("reviewed deployment template hash is invalid")
    if _COMMIT_PATTERN.fullmatch(entry["sourceCommit"]) is None:
        raise StrictWc013SelectionError("reviewed deployment source commit is invalid")

    artifact_payload, raw_artifact = _load_strict_json(
        index_path.parent / artifact_file,
        maximum_bytes=_MAX_ARTIFACT_BYTES,
        label="reviewed deployment artifact",
    )
    if _digest(artifact_payload) != expected_artifact_digest:
        raise StrictWc013SelectionError("reviewed deployment artifact digest does not match")
    artifact = _require_exact_object(
        raw_artifact, _ARTIFACT_KEYS, "reviewed deployment artifact"
    )
    if artifact["schemaVersion"] != "athena.wc013CollectorDeploymentContract.v2":
        raise StrictWc013SelectionError("reviewed deployment artifact schema is unsupported")
    for key in (
        "deploymentResourceId",
        "deploymentCorrelationId",
        "deploymentTemplateHash",
        "sourceCommit",
    ):
        if artifact[key] != entry[key]:
            raise StrictWc013SelectionError(
                "reviewed deployment artifact metadata does not match its index"
            )

    controller_image = artifact["controllerImage"]
    controller_match = (
        _CONTROLLER_IMAGE_PATTERN.fullmatch(controller_image)
        if isinstance(controller_image, str)
        else None
    )
    if controller_match is None or controller_match.group("digest") == "0" * 64:
        raise StrictWc013SelectionError("reviewed controller image is not an exact ACR digest")

    contracts = artifact["contracts"]
    contract_digests = artifact["collectorContractDigests"]
    phase_keys = set(_PHASE_BINDINGS)
    if not isinstance(contracts, dict) or set(contracts) != phase_keys:
        raise StrictWc013SelectionError("reviewed artifact phase contracts are not exact")
    if not isinstance(contract_digests, dict) or set(contract_digests) != phase_keys:
        raise StrictWc013SelectionError("reviewed artifact phase digests are not exact")

    common_binding: tuple[str, ...] | None = None
    for contract_phase in _PHASE_BINDINGS:
        expected_contract_digest = _require_non_placeholder_digest(
            contract_digests[contract_phase],
            f"reviewed {contract_phase} contract digest",
        )
        if _canonical_digest(contracts[contract_phase]) != expected_contract_digest:
            raise StrictWc013SelectionError(
                f"reviewed {contract_phase} contract digest does not match"
            )
        binding = _phase_contract_binding(
            contracts[contract_phase],
            contract_phase,
            deployment_match.group("subscription"),
        )
        if common_binding is None:
            common_binding = binding
        elif binding != common_binding:
            raise StrictWc013SelectionError(
                "reviewed phase contracts do not share one deployment binding"
            )
    expected_contracts_digest = _require_non_placeholder_digest(
        artifact["collectorContractsDigest"], "reviewed contracts digest"
    )
    if _canonical_digest(contracts) != expected_contracts_digest:
        raise StrictWc013SelectionError("reviewed contracts digest does not match")
    if common_binding is None or controller_match.group("server") != common_binding[4]:
        raise StrictWc013SelectionError(
            "reviewed controller and collector images do not share one exact ACR"
        )

    selected_contract = contracts[phase]
    selected_contract_digest = contract_digests[phase]
    if len(_canonical_bytes(selected_contract)) > _MAX_CONTRACT_BYTES:
        raise StrictWc013SelectionError("selected collector contract is oversized")
    selection = {
        "schemaVersion": "athena.wc013StrictCollectorSelection.v1",
        "deployment": deployment,
        "phase": phase,
        "controllerImage": controller_image,
        "contractDigest": selected_contract_digest,
        "contract": selected_contract,
    }
    if set(selection) != _SELECTION_KEYS:
        raise StrictWc013SelectionError("strict selection output is invalid")
    return _canonical_bytes(selection)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Strictly select a duplicate-free WC-013 collector contract."
    )
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--phase", required=True, choices=tuple(_PHASE_BINDINGS))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        payload = select_strict_wc013_contract(
            args.index,
            deployment=args.deployment,
            phase=args.phase,
        )
    except StrictWc013SelectionError as exc:
        print(f"Strict WC-013 selection failed: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
