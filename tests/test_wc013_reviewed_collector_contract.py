from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from scripts.strict_select_wc013_contract import (
    StrictWc013SelectionError,
    select_strict_wc013_contract,
)

from athena_context.wc013_collector_controller import (
    load_wc013_collector_start_contract,
)
from athena_context.wc013_reviewed_collector_contract import (
    ReviewedCollectorContractError,
    select_indexed_reviewed_collector_contract,
    select_reviewed_collector_contract,
    write_reviewed_collector_contract,
)

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
DEPLOYMENT_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Resources/deployments/"
    "wc013-ready-20260831T030000Z-aaaaaaaaaaaa"
)
DEPLOYMENT_CORRELATION_ID = "22222222-2222-2222-2222-222222222222"
DEPLOYMENT_TEMPLATE_HASH = "1234567890123456789"
SOURCE_COMMIT = "a" * 40
CONTROLLER_IMAGE = (
    "athenafixture.azurecr.io/athena/wc013-controller@sha256:" + "5" * 64
)
EVIDENCE_IDENTITY_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-fixture/providers/"
    "Microsoft.ManagedIdentity/userAssignedIdentities/athena-mcp-evidence"
)
EVIDENCE_CLIENT_ID = "33333333-3333-3333-3333-333333333333"


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_digest(value: object) -> str:
    return _digest(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _contract(phase: str) -> dict[str, object]:
    return {
        "schemaVersion": "athena.wc013CollectorStartContract.v1",
        "jobResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-fixture/"
            f"providers/Microsoft.App/jobs/athena-wc013-live-op-{phase}-collector"
        ),
        "evidenceIdentityResourceId": EVIDENCE_IDENTITY_RESOURCE_ID,
        "evidenceIdentityClientId": EVIDENCE_CLIENT_ID,
        "wc007PinnedAuthorityDigest": "sha256:" + "7" * 64,
        "wc008PinnedAssertionDigest": "sha256:" + "8" * 64,
        "configuration": {
            "triggerType": "Manual",
            "replicaRetryLimit": 0,
            "replicaTimeout": 900,
            "manualTriggerConfig": {
                "parallelism": 1,
                "replicaCompletionCount": 1,
            },
            "registries": [
                {
                    "server": "athenafixture.azurecr.io",
                    "identity": EVIDENCE_IDENTITY_RESOURCE_ID,
                }
            ],
        },
        "template": {
            "containers": [
                {
                    "name": f"wc013-{phase}-evidence-collector",
                    "image": (
                        "athenafixture.azurecr.io/athena/wc013-live@sha256:"
                        + "9" * 64
                    ),
                    "command": ["athena-context"],
                    "args": [
                        "wc013-evidence-collector-job",
                        "--config",
                        f"/opt/athena/wc013-live/delivery/configs/{phase}.json",
                        "--artifact-blob-endpoint",
                        "https://athenafixture.blob.core.windows.net",
                        "--artifact-container",
                        "collected-evidence",
                        "--emit-handoff-base64",
                    ],
                    "env": [
                        {"name": "AZURE_CLIENT_ID", "value": EVIDENCE_CLIENT_ID},
                        {
                            "name": "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID",
                            "value": EVIDENCE_CLIENT_ID,
                        },
                        {
                            "name": "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST",
                            "value": "sha256:" + "7" * 64,
                        },
                        {
                            "name": "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST",
                            "value": "sha256:" + "8" * 64,
                        },
                    ],
                    "resources": {"cpu": 0.5, "memory": "1Gi"},
                }
            ]
        },
    }


def _write_artifact(
    path: Path,
    *,
    contracts: dict[str, object] | None = None,
) -> tuple[dict[str, object], str]:
    exact_contracts = contracts or {
        phase: _contract(phase) for phase in ("baseline", "faulted", "recovered")
    }
    artifact: dict[str, object] = {
        "schemaVersion": "athena.wc013CollectorDeploymentContract.v2",
        "deploymentResourceId": DEPLOYMENT_RESOURCE_ID,
        "deploymentCorrelationId": DEPLOYMENT_CORRELATION_ID,
        "deploymentTemplateHash": DEPLOYMENT_TEMPLATE_HASH,
        "sourceCommit": SOURCE_COMMIT,
        "controllerImage": CONTROLLER_IMAGE,
        "collectorContractsDigest": _canonical_digest(exact_contracts),
        "collectorContractDigests": {
            phase: _canonical_digest(contract)
            for phase, contract in exact_contracts.items()
        },
        "contracts": exact_contracts,
    }
    payload = json.dumps(
        artifact,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    path.write_bytes(payload)
    return artifact, _digest(payload)


def _select(path: Path, digest: str, phase: str = "faulted"):
    return select_reviewed_collector_contract(
        path,
        expected_artifact_digest=digest,
        expected_deployment_resource_id=DEPLOYMENT_RESOURCE_ID,
        expected_deployment_correlation_id=DEPLOYMENT_CORRELATION_ID,
        expected_deployment_template_hash=DEPLOYMENT_TEMPLATE_HASH,
        expected_source_commit=SOURCE_COMMIT,
        phase=phase,  # type: ignore[arg-type]
    )


def _write_index(path: Path, artifact_digest: str) -> None:
    deployment = DEPLOYMENT_RESOURCE_ID.rsplit("/", 1)[-1]
    index = {
        "schemaVersion": "athena.wc013CollectorDeploymentContractIndex.v1",
        "deployments": {
            deployment: {
                "artifactFile": f"{deployment}.json",
                "artifactDigest": artifact_digest,
                "deploymentResourceId": DEPLOYMENT_RESOURCE_ID,
                "deploymentCorrelationId": DEPLOYMENT_CORRELATION_ID,
                "deploymentTemplateHash": DEPLOYMENT_TEMPLATE_HASH,
                "sourceCommit": SOURCE_COMMIT,
            }
        },
    }
    path.write_text(
        json.dumps(index, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )


def _strict_fixture_paths(tmp_path: Path) -> tuple[Path, Path]:
    deployment = DEPLOYMENT_RESOURCE_ID.rsplit("/", 1)[-1]
    artifact_path = tmp_path / f"{deployment}.json"
    _, artifact_digest = _write_artifact(artifact_path)
    index_path = tmp_path / "index.json"
    _write_index(index_path, artifact_digest)
    return index_path, artifact_path


def _replace_once(payload: bytes, needle: bytes, replacement: bytes) -> bytes:
    assert needle in payload
    return payload.replace(needle, replacement, 1)


def _run_strict_gate_with_execution_markers(
    index_path: Path,
    events: list[str],
) -> bytes:
    selection = select_strict_wc013_contract(
        index_path,
        deployment=DEPLOYMENT_RESOURCE_ID.rsplit("/", 1)[-1],
        phase="baseline",
    )
    events.extend(("azure-login", "controller-image-pull", "controller-docker-run"))
    return selection


def test_strict_selector_emits_one_canonical_bounded_selection(tmp_path: Path) -> None:
    index_path, _ = _strict_fixture_paths(tmp_path)

    payload = select_strict_wc013_contract(
        index_path,
        deployment=DEPLOYMENT_RESOURCE_ID.rsplit("/", 1)[-1],
        phase="faulted",
    )
    selection = json.loads(payload)

    assert payload == json.dumps(
        selection,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert selection["schemaVersion"] == "athena.wc013StrictCollectorSelection.v1"
    assert selection["phase"] == "faulted"
    assert selection["controllerImage"] == CONTROLLER_IMAGE
    assert selection["contractDigest"] == _canonical_digest(selection["contract"])


@pytest.mark.parametrize(
    ("label", "needle", "replacement"),
    [
        (
            "controller image",
            f'"controllerImage":"{CONTROLLER_IMAGE}"'.encode(),
            (
                '"controllerImage":"duplicate",'
                f'"controllerImage":"{CONTROLLER_IMAGE}"'
            ).encode(),
        ),
        (
            "digest map",
            b'"collectorContractDigests":{"baseline":',
            (
                b'"collectorContractDigests":{"baseline":"sha256:'
                + b"0" * 64
                + b'","baseline":'
            ),
        ),
        (
            "contract slot",
            b'"contracts":{"baseline":',
            b'"contracts":{"baseline":{},"baseline":',
        ),
        (
            "nested job",
            b'"jobResourceId":',
            b'"jobResourceId":"duplicate","jobResourceId":',
        ),
        (
            "nested template",
            b'"template":{"containers":',
            b'"template":{"containers":[],"containers":',
        ),
        (
            "nested environment",
            b'"env":[{"name":"AZURE_CLIENT_ID"',
            br'"env":[{"name":"duplicate","n\u0061me":"AZURE_CLIENT_ID"',
        ),
    ],
)
def test_duplicate_artifact_or_nested_contract_key_stops_before_execution(
    tmp_path: Path,
    label: str,
    needle: bytes,
    replacement: bytes,
) -> None:
    index_path, artifact_path = _strict_fixture_paths(tmp_path)
    duplicate_payload = _replace_once(artifact_path.read_bytes(), needle, replacement)
    artifact_path.write_bytes(duplicate_payload)
    _write_index(index_path, _digest(duplicate_payload))
    events: list[str] = []

    with pytest.raises(StrictWc013SelectionError, match="duplicate object key"):
        _run_strict_gate_with_execution_markers(index_path, events)

    assert events == [], f"{label} duplicate crossed the pre-login execution gate"


def test_duplicate_index_key_stops_before_execution(tmp_path: Path) -> None:
    index_path, _ = _strict_fixture_paths(tmp_path)
    duplicate_index = _replace_once(
        index_path.read_bytes(),
        b'"artifactDigest":',
        b'"artifactDigest":"sha256:' + b"0" * 64 + b'","artifactDigest":',
    )
    index_path.write_bytes(duplicate_index)
    events: list[str] = []

    with pytest.raises(StrictWc013SelectionError, match="duplicate object key"):
        _run_strict_gate_with_execution_markers(index_path, events)

    assert events == []


def test_selects_one_phase_from_exact_deployment_bound_artifact(
    tmp_path: Path,
) -> None:
    artifact_path = tmp_path / "reviewed.json"
    _, digest = _write_artifact(artifact_path)

    selected = _select(artifact_path, digest)
    output_path = tmp_path / "selected.json"
    write_reviewed_collector_contract(selected, output_path)
    loaded = load_wc013_collector_start_contract(output_path)

    assert loaded == selected
    assert loaded.job_resource_id.endswith("-op-faulted-collector")


def test_index_resolves_only_exact_deployment_key_and_filename(
    tmp_path: Path,
) -> None:
    deployment = DEPLOYMENT_RESOURCE_ID.rsplit("/", 1)[-1]
    artifact_path = tmp_path / f"{deployment}.json"
    _, digest = _write_artifact(artifact_path)
    index_path = tmp_path / "index.json"
    _write_index(index_path, digest)

    selected = select_indexed_reviewed_collector_contract(
        index_path,
        deployment=deployment,
        phase="recovered",
    )
    assert selected.job_resource_id.endswith("-op-recovered-collector")

    with pytest.raises(ReviewedCollectorContractError, match="immutable reviewed"):
        select_indexed_reviewed_collector_contract(
            index_path,
            deployment="pending-review-no-deployment",
            phase="recovered",
        )

    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["deployments"][deployment]["artifactFile"] = "../reviewed.json"
    index_path.write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ReviewedCollectorContractError, match="filename is not exact"):
        select_indexed_reviewed_collector_contract(
            index_path,
            deployment=deployment,
            phase="recovered",
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"expected_artifact_digest": "sha256:" + "0" * 64},
            "non-placeholder",
        ),
        (
            {
                "expected_deployment_resource_id": DEPLOYMENT_RESOURCE_ID.replace(
                    "wc013-ready-", "wc013-ready"
                )
            },
            "immutable WC-013 ready identifier",
        ),
        (
            {"expected_deployment_correlation_id": "4" * 36},
            "correlation ID",
        ),
        ({"expected_source_commit": "main"}, "source commit"),
    ],
)
def test_rejects_unpinned_or_invalid_expected_deployment_metadata(
    tmp_path: Path,
    overrides: dict[str, str],
    message: str,
) -> None:
    artifact_path = tmp_path / "reviewed.json"
    _, digest = _write_artifact(artifact_path)
    arguments = {
        "expected_artifact_digest": digest,
        "expected_deployment_resource_id": DEPLOYMENT_RESOURCE_ID,
        "expected_deployment_correlation_id": DEPLOYMENT_CORRELATION_ID,
        "expected_deployment_template_hash": DEPLOYMENT_TEMPLATE_HASH,
        "expected_source_commit": SOURCE_COMMIT,
    }
    arguments.update(overrides)

    with pytest.raises(ReviewedCollectorContractError, match=message):
        select_reviewed_collector_contract(
            artifact_path,
            phase="baseline",
            **arguments,
        )


def test_rejects_artifact_byte_drift_and_unselected_contract_drift(
    tmp_path: Path,
) -> None:
    artifact_path = tmp_path / "reviewed.json"
    _, digest = _write_artifact(artifact_path)
    artifact_path.write_bytes(artifact_path.read_bytes() + b"\n")
    with pytest.raises(ReviewedCollectorContractError, match="artifact digest"):
        _select(artifact_path, digest)

    contracts = {
        phase: _contract(phase) for phase in ("baseline", "faulted", "recovered")
    }
    changed = deepcopy(contracts["recovered"])
    changed["template"]["containers"][0]["image"] = (  # type: ignore[index]
        "athenafixture.azurecr.io/athena/wc013-live@sha256:" + "6" * 64
    )
    contracts["recovered"] = changed
    _, changed_digest = _write_artifact(artifact_path, contracts=contracts)
    with pytest.raises(ReviewedCollectorContractError, match="one deployment binding"):
        _select(artifact_path, changed_digest, phase="baseline")


@pytest.mark.parametrize(
    ("requested_phase", "swapped_phase"),
    [
        ("baseline", "faulted"),
        ("faulted", "recovered"),
        ("recovered", "baseline"),
    ],
)
def test_rejects_contract_swapped_into_another_phase_slot(
    tmp_path: Path,
    requested_phase: str,
    swapped_phase: str,
) -> None:
    artifact_path = tmp_path / "reviewed.json"
    contracts = {
        phase: _contract(phase) for phase in ("baseline", "faulted", "recovered")
    }
    contracts[requested_phase] = deepcopy(contracts[swapped_phase])
    _, digest = _write_artifact(artifact_path, contracts=contracts)

    with pytest.raises(ReviewedCollectorContractError, match="targets the wrong job"):
        _select(artifact_path, digest, phase=requested_phase)


def test_rejects_relabelled_swapped_contract_phase_semantics(
    tmp_path: Path,
) -> None:
    artifact_path = tmp_path / "reviewed.json"
    contracts = {
        phase: _contract(phase) for phase in ("baseline", "faulted", "recovered")
    }
    swapped = deepcopy(contracts["faulted"])
    swapped["jobResourceId"] = contracts["baseline"]["jobResourceId"]  # type: ignore[index]
    contracts["baseline"] = swapped
    _, digest = _write_artifact(artifact_path, contracts=contracts)

    with pytest.raises(
        ReviewedCollectorContractError,
        match="wrong fixed phase semantics",
    ):
        _select(artifact_path, digest, phase="baseline")


def test_rejects_placeholder_or_cross_registry_controller_image(
    tmp_path: Path,
) -> None:
    artifact_path = tmp_path / "reviewed.json"
    artifact, _ = _write_artifact(artifact_path)
    artifact["controllerImage"] = (
        "athenafixture.azurecr.io/athena/wc013-controller@sha256:" + "0" * 64
    )
    payload = json.dumps(
        artifact,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    artifact_path.write_bytes(payload)
    with pytest.raises(ReviewedCollectorContractError, match="exact ACR digest"):
        _select(artifact_path, _digest(payload))

    artifact["controllerImage"] = (
        "otherfixture.azurecr.io/athena/wc013-controller@sha256:" + "5" * 64
    )
    payload = json.dumps(
        artifact,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    artifact_path.write_bytes(payload)
    with pytest.raises(ReviewedCollectorContractError, match="same exact ACR"):
        _select(artifact_path, _digest(payload))


def test_rejects_existing_selected_contract_output(tmp_path: Path) -> None:
    artifact_path = tmp_path / "reviewed.json"
    _, digest = _write_artifact(artifact_path)
    selected = _select(artifact_path, digest)
    output_path = tmp_path / "selected.json"
    output_path.write_text("do-not-overwrite", encoding="utf-8")

    with pytest.raises(ReviewedCollectorContractError, match="exclusively"):
        write_reviewed_collector_contract(selected, output_path)

    assert output_path.read_text(encoding="utf-8") == "do-not-overwrite"
