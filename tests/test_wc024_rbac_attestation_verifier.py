from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from athena_context.contracts import (
    canonicalize_json,
    compute_artifact_digest,
    monitoring_effective_rbac_inventory_attestation_preimage,
)

ROOT = Path(__file__).parents[1]
VERIFIER = (
    ROOT
    / "infra"
    / "wc024-monitoring-foundation"
    / "scripts"
    / "verify-rbac-inventory-attestation.py"
)


def _base64url_integer(value: int) -> str:
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _reviewed_payload(
    *,
    key_size: int = 2048,
    inventory: dict[str, object] | None = None,
) -> tuple[dict[str, str], dict[str, object]]:
    if inventory is None:
        source_manifest_digest = "sha256:" + "e" * 64
        inventory_payload: dict[str, object] = {
            "schemaVersion": "athena.wc028MonitoringEffectiveRbacInventory.v5",
            "collectionRunId": "monitoring-rbac-" + "a" * 32,
            "sourceManifestDigest": source_manifest_digest,
            "assignmentCount": 0,
            "resourceGraphQueryRoleActions": [
                "microsoft.resourcegraph/resources/read",
            ],
            "resourceHealthRoleActions": [
                "microsoft.resourcehealth/availabilitystatuses/read",
            ],
        }
        inventory_digest = compute_artifact_digest(inventory_payload)
        inventory = {
            **inventory_payload,
            "inventoryDigest": inventory_digest,
        }
    else:
        inventory_digest = str(inventory["inventoryDigest"])
        source_manifest_digest = str(inventory["sourceManifestDigest"])

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    fingerprint = (
        "sha256:"
        + hashlib.sha256(
            public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
    )
    reviewer_principal_id = "77777777-7777-7777-7777-777777777777"
    bootstrap_handoff_id = "88888888-8888-8888-8888-888888888888"
    bootstrap_deployment_id = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/providers/"
        "microsoft.resources/deployments/wc024-monitoring-foundation-synthetic"
    )
    bootstrap_template_hash = "synthetic-template-hash-123456789"
    bootstrap_contract_inputs_binding_id = "99999999-9999-9999-9999-999999999999"
    cleanup_digest = "sha256:" + ("9" * 64)
    reviewer_key_id = (
        "https://athenarbacevidencekv.vault.azure.net/keys/"
        "monitoring-rbac-inventory-review/0123456789abcdef0123456789abcdef"
    )
    preimage = monitoring_effective_rbac_inventory_attestation_preimage(
        bootstrap_handoff_id=bootstrap_handoff_id,
        bootstrap_deployment_id=bootstrap_deployment_id,
        bootstrap_template_hash=bootstrap_template_hash,
        bootstrap_contract_inputs_binding_id=bootstrap_contract_inputs_binding_id,
        reviewer_principal_id=reviewer_principal_id,
        reviewer_key_id=reviewer_key_id,
        public_key_fingerprint=fingerprint,
        inventory_digest=inventory_digest,
        source_manifest_digest=source_manifest_digest,
        legacy_collector_rbac_cleanup_schema_version=("athena.wc028LegacyCollectorRbacCleanup.v3"),
        legacy_collector_rbac_cleanup_digest=cleanup_digest,
    )
    signature = private_key.sign(
        canonicalize_json(preimage).encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    environment = {
        "ATHENA_SIGNATURE_ALGORITHM": "RS256",
        "ATHENA_BOOTSTRAP_HANDOFF_ID": bootstrap_handoff_id,
        "ATHENA_BOOTSTRAP_DEPLOYMENT_ID": bootstrap_deployment_id,
        "ATHENA_BOOTSTRAP_TEMPLATE_HASH": bootstrap_template_hash,
        "ATHENA_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID": (bootstrap_contract_inputs_binding_id),
        "ATHENA_REVIEWER_PRINCIPAL_ID": reviewer_principal_id,
        "ATHENA_REVIEWER_KEY_ID": reviewer_key_id,
        "ATHENA_PUBLIC_KEY_MODULUS": _base64url_integer(numbers.n),
        "ATHENA_PUBLIC_KEY_EXPONENT": _base64url_integer(numbers.e),
        "ATHENA_PUBLIC_KEY_FINGERPRINT": fingerprint,
        "ATHENA_REVIEWER_JWK_JSON": json.dumps(
            {
                "kid": reviewer_key_id,
                "kty": "RSA",
                "key_ops": ["sign", "verify"],
                "n": _base64url_integer(numbers.n),
                "e": _base64url_integer(numbers.e),
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        "ATHENA_INVENTORY_DIGEST": inventory_digest,
        "ATHENA_SOURCE_MANIFEST_DIGEST": source_manifest_digest,
        "ATHENA_LEGACY_RBAC_CLEANUP_SCHEMA_VERSION": ("athena.wc028LegacyCollectorRbacCleanup.v3"),
        "ATHENA_LEGACY_RBAC_CLEANUP_DIGEST": cleanup_digest,
        "ATHENA_SIGNED_PREIMAGE_DIGEST": compute_artifact_digest(preimage),
        "ATHENA_SIGNATURE": base64.b64encode(signature).decode("ascii"),
        "ATHENA_INVENTORY_JSON": json.dumps(
            inventory,
            separators=(",", ":"),
            sort_keys=True,
        ),
    }
    return environment, inventory


def _run_verifier(
    tmp_path: Path,
    environment: dict[str, str],
) -> tuple[subprocess.CompletedProcess[str], Path]:
    output_path = tmp_path / "scriptoutputs.json"
    process_environment = os.environ.copy()
    process_environment.update(environment)
    process_environment["AZ_SCRIPTS_OUTPUT_PATH"] = str(output_path)
    result = subprocess.run(
        [sys.executable, str(VERIFIER)],
        cwd=ROOT,
        env=process_environment,
        capture_output=True,
        check=False,
        text=True,
    )
    return result, output_path


def test_deployment_verifier_accepts_exact_canonical_inventory_signature(
    tmp_path: Path,
) -> None:
    environment, _ = _reviewed_payload()

    result, output_path = _run_verifier(tmp_path, environment)

    assert result.returncode == 0, result.stderr
    outputs = json.loads(output_path.read_text(encoding="utf-8"))
    assert outputs["validated"] is True
    assert outputs["inventoryDigest"] == environment["ATHENA_INVENTORY_DIGEST"]
    assert outputs["signedPreimageDigest"] == environment["ATHENA_SIGNED_PREIMAGE_DIGEST"]
    assert outputs["validationDigest"].startswith("sha256:")


def test_azure_cli_deployment_script_launcher_executes_python_verifier(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("AzureCLI deployment-script launcher is validated on POSIX CI")
    bash = shutil.which("bash")
    python3 = shutil.which("python3")
    base64_command = shutil.which("base64")
    if bash is None or python3 is None or base64_command is None:
        pytest.skip("bash, python3, and base64 are required for AzureCLI launcher validation")
    environment, _ = _reviewed_payload()
    output_path = tmp_path / "scriptoutputs.json"
    environment = {**os.environ, **environment, "AZ_SCRIPTS_OUTPUT_PATH": str(output_path)}
    encoded_source = base64.b64encode(VERIFIER.read_bytes()).decode("ascii")
    verifier_path = tmp_path / "verify-rbac-inventory-attestation.py"
    launcher = (
        "set -euo pipefail\n"
        f"printf '%s' '{encoded_source}' | base64 --decode > '{verifier_path}'\n"
        f"python3 '{verifier_path}'"
    )

    result = subprocess.run(
        [bash, "-c", launcher],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(output_path.read_text(encoding="utf-8"))["validated"] is True


def test_deployment_verifier_matches_full_checked_in_inventory_canonicalization(
    tmp_path: Path,
) -> None:
    inventory = json.loads(
        (
            ROOT / "infra" / "wc024-monitoring-foundation" / "effective-rbac-inventory.example.json"
        ).read_text(encoding="utf-8")
    )
    environment, _ = _reviewed_payload(inventory=inventory)

    result, output_path = _run_verifier(tmp_path, environment)

    assert result.returncode == 0, result.stderr
    assert (
        json.loads(output_path.read_text(encoding="utf-8"))["inventoryDigest"]
        == inventory["inventoryDigest"]
    )


def test_full_inventory_and_verifier_environment_fit_azure_deployment_script_limit() -> None:
    inventory = json.loads(
        (
            ROOT / "infra" / "wc024-monitoring-foundation" / "effective-rbac-inventory.example.json"
        ).read_text(encoding="utf-8")
    )
    environment, _ = _reviewed_payload(inventory=inventory)
    caller_environment_payload = "|".join(
        f"{name}={value}" for name, value in environment.items()
    )

    assert len(json.dumps(inventory, separators=(",", ":")).encode("utf-8")) <= 62_000
    assert len(caller_environment_payload.encode("utf-8")) <= 64_000


def test_deployment_verifier_rejects_inventory_changed_after_review(
    tmp_path: Path,
) -> None:
    environment, inventory = _reviewed_payload()
    inventory["unreviewedMutation"] = True
    environment["ATHENA_INVENTORY_JSON"] = json.dumps(
        inventory,
        separators=(",", ":"),
        sort_keys=True,
    )

    result, output_path = _run_verifier(tmp_path, environment)

    assert result.returncode == 1
    assert "inventory digest is invalid" in result.stderr
    assert not output_path.exists()


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        (
            "resourceGraphQueryRoleActions",
            [],
            "Resource Graph query permission",
        ),
        (
            "resourceHealthRoleActions",
            ["microsoft.resourcegraph/resources/read"],
            "Resource Health availability permission",
        ),
        (
            "resourceHealthRoleActions",
            ["microsoft.resourcehealth/availabilitystatuses/current/read"],
            "Resource Health availability permission",
        ),
    ),
)
def test_deployment_verifier_rejects_missing_resource_health_permissions(
    tmp_path: Path,
    field_name: str,
    value: object,
    message: str,
) -> None:
    _, inventory = _reviewed_payload()
    inventory[field_name] = value
    inventory_payload = dict(inventory)
    inventory_payload.pop("inventoryDigest")
    inventory["inventoryDigest"] = compute_artifact_digest(inventory_payload)
    environment, _ = _reviewed_payload(inventory=inventory)

    result, output_path = _run_verifier(tmp_path, environment)

    assert result.returncode == 1
    assert message in result.stderr
    assert not output_path.exists()


def test_deployment_verifier_rejects_weak_or_forged_reviewer_proof(
    tmp_path: Path,
) -> None:
    weak_environment, _ = _reviewed_payload(key_size=1024)
    weak_result, _ = _run_verifier(tmp_path, weak_environment)
    assert weak_result.returncode == 1
    assert "RSA-2048 or stronger" in weak_result.stderr

    forged_environment, _ = _reviewed_payload()
    forged_environment["ATHENA_SIGNATURE"] = base64.b64encode(b"forged-reviewer-signature").decode(
        "ascii"
    )
    forged_result, _ = _run_verifier(tmp_path, forged_environment)
    assert forged_result.returncode == 1
    assert "signature length does not match" in forged_result.stderr


def test_deployment_verifier_rejects_caller_key_labeled_as_trusted_key_vault_version(
    tmp_path: Path,
) -> None:
    environment, _ = _reviewed_payload()
    trusted_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    trusted_numbers = trusted_key.public_key().public_numbers()
    environment["ATHENA_REVIEWER_JWK_JSON"] = json.dumps(
        {
            "kid": environment["ATHENA_REVIEWER_KEY_ID"],
            "kty": "RSA",
            "key_ops": ["sign", "verify"],
            "n": _base64url_integer(trusted_numbers.n),
            "e": _base64url_integer(trusted_numbers.e),
        },
        separators=(",", ":"),
        sort_keys=True,
    )

    result, output_path = _run_verifier(tmp_path, environment)

    assert result.returncode == 1
    assert "does not match the exact versioned Key Vault key" in result.stderr
    assert not output_path.exists()


def test_deployment_verifier_rejects_signature_representative_outside_modulus(
    tmp_path: Path,
) -> None:
    for _ in range(32):
        environment, _ = _reviewed_payload()
        modulus = int.from_bytes(
            base64.urlsafe_b64decode(
                environment["ATHENA_PUBLIC_KEY_MODULUS"]
                + "=" * (-len(environment["ATHENA_PUBLIC_KEY_MODULUS"]) % 4)
            ),
            "big",
        )
        signature = int.from_bytes(
            base64.b64decode(environment["ATHENA_SIGNATURE"]),
            "big",
        )
        modulus_size = (modulus.bit_length() + 7) // 8
        noncanonical_signature = signature + modulus
        if noncanonical_signature < 1 << (modulus_size * 8):
            environment["ATHENA_SIGNATURE"] = base64.b64encode(
                noncanonical_signature.to_bytes(modulus_size, "big")
            ).decode("ascii")
            break
    else:
        pytest.fail("could not construct an equal-length noncanonical RSA signature")

    result, output_path = _run_verifier(tmp_path, environment)

    assert result.returncode == 1
    assert "outside the RSA modulus" in result.stderr
    assert not output_path.exists()


def test_deployment_verifier_rejects_changed_bootstrap_or_cleanup_binding(
    tmp_path: Path,
) -> None:
    for field, value in (
        ("ATHENA_BOOTSTRAP_HANDOFF_ID", "99999999-9999-9999-9999-999999999999"),
        (
            "ATHENA_BOOTSTRAP_DEPLOYMENT_ID",
            (
                "/subscriptions/00000000-0000-0000-0000-000000000000/providers/"
                "microsoft.resources/deployments/changed-bootstrap"
            ),
        ),
        ("ATHENA_BOOTSTRAP_TEMPLATE_HASH", "changed-template-hash"),
        (
            "ATHENA_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        ),
        ("ATHENA_LEGACY_RBAC_CLEANUP_DIGEST", "sha256:" + ("8" * 64)),
    ):
        environment, _ = _reviewed_payload()
        environment[field] = value

        result, output_path = _run_verifier(tmp_path, environment)

        assert result.returncode == 1
        assert "signed-preimage digest is invalid" in result.stderr
        assert not output_path.exists()
