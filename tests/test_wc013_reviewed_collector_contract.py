from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

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
        "schemaVersion": "athena.wc013CollectorDeploymentContract.v1",
        "deploymentResourceId": DEPLOYMENT_RESOURCE_ID,
        "deploymentCorrelationId": DEPLOYMENT_CORRELATION_ID,
        "deploymentTemplateHash": DEPLOYMENT_TEMPLATE_HASH,
        "sourceCommit": SOURCE_COMMIT,
        "collectorContractsDigest": _canonical_digest(exact_contracts),
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


def test_rejects_existing_selected_contract_output(tmp_path: Path) -> None:
    artifact_path = tmp_path / "reviewed.json"
    _, digest = _write_artifact(artifact_path)
    selected = _select(artifact_path, digest)
    output_path = tmp_path / "selected.json"
    output_path.write_text("do-not-overwrite", encoding="utf-8")

    with pytest.raises(ReviewedCollectorContractError, match="exclusively"):
        write_reviewed_collector_contract(selected, output_path)

    assert output_path.read_text(encoding="utf-8") == "do-not-overwrite"
