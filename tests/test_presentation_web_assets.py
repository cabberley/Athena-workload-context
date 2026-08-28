from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from scripts.generate_presentation_web_assets import (
    PUBLIC_ROOT,
    ROOT,
    SYNTHETIC_KEY_ID,
    build_presentation_web_assets,
    presentation_public_key_fingerprint,
)

from athena_context.contracts.presentation import (
    ARGUS_PRESENTATION_ATTESTATION_SCHEMA_VERSION,
    ARGUS_PRESENTATION_SCHEMA_VERSION,
    ArgusPresentationPayload,
    PresentationAttestation,
)
from athena_context.fixtures import CANONICAL_PRIVATE_KEY

EXPECTED_FINGERPRINT = (
    "sha256:9323d86eb7d1fffccc409a89795e04ef71db7c9b011dad9c2f3e3fcf6e81784a"
)


def test_generated_assets_match_exact_lf_bytes_and_git_clean_normalization() -> None:
    assets = build_presentation_web_assets()

    for relative_path, expected_bytes in assets.items():
        repository_path = (PUBLIC_ROOT / relative_path).relative_to(ROOT)
        observed_bytes = (ROOT / repository_path).read_bytes()
        assert observed_bytes == expected_bytes
        assert b"\r" not in expected_bytes

        attributes = _git(
            "check-attr",
            "text",
            "eol",
            "--",
            repository_path.as_posix(),
        ).decode("utf-8")
        assert f"{repository_path.as_posix()}: text: set" in attributes
        assert f"{repository_path.as_posix()}: eol: lf" in attributes

        clean_filtered_oid = _git(
            "hash-object",
            f"--path={repository_path.as_posix()}",
            "--stdin",
            input_bytes=observed_bytes,
        )
        generated_lf_oid = _git("hash-object", "--stdin", input_bytes=expected_bytes)
        assert clean_filtered_oid == generated_lf_oid


def test_runtime_hashes_cover_exact_generated_lf_bytes() -> None:
    assets = build_presentation_web_assets()
    manifest = json.loads(assets[Path("runtime-manifest.json")])

    key_path = Path(manifest["key"]["path"].removeprefix("./"))
    assert manifest["key"]["assetSha256"] == _sha256(assets[key_path])
    for phase in manifest["phases"]:
        payload_path = Path(phase["payloadPath"].removeprefix("./"))
        attestation_path = Path(phase["attestationPath"].removeprefix("./"))
        assert phase["payloadSha256"] == _sha256(assets[payload_path])
        assert phase["attestationSha256"] == _sha256(assets[attestation_path])


def test_browser_key_and_attestations_derive_from_canonical_proof_key() -> None:
    assets = build_presentation_web_assets()
    public_key = CANONICAL_PRIVATE_KEY.public_key()
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert presentation_public_key_fingerprint() == EXPECTED_FINGERPRINT
    assert _sha256(spki) == EXPECTED_FINGERPRINT

    key_asset = json.loads(assets[Path("trust/presentation-public-key.jwk.json")])
    public_numbers = public_key.public_numbers()
    assert key_asset["keyId"] == SYNTHETIC_KEY_ID
    assert key_asset["fingerprint"] == EXPECTED_FINGERPRINT
    assert key_asset["jwk"]["n"] == _base64url_uint(public_numbers.n)
    assert key_asset["jwk"]["e"] == _base64url_uint(public_numbers.e)

    for phase in ("baseline", "faulted", "recovered"):
        payload = ArgusPresentationPayload.model_validate_json(
            assets[Path("fixtures") / f"{phase}.presentation.json"]
        )
        attestation = PresentationAttestation.model_validate_json(
            assets[Path("fixtures") / f"{phase}.attestation.json"]
        )
        signature = base64.urlsafe_b64decode(
            attestation.detached_signature
            + "=" * (-len(attestation.detached_signature) % 4)
        )
        public_key.verify(
            signature,
            payload.canonical_preimage(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    combined_public_output = b"".join(assets.values())
    assert b"BEGIN RSA PRIVATE KEY" not in combined_public_output


def test_frozen_presentation_contract_versions_are_unchanged() -> None:
    assert ARGUS_PRESENTATION_SCHEMA_VERSION == "athena.argus.presentation.v1"
    assert (
        ARGUS_PRESENTATION_ATTESTATION_SCHEMA_VERSION
        == "athena.argus.presentationAttestation.v1"
    )


def _git(*arguments: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        input=input_bytes,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _base64url_uint(value: int) -> str:
    encoded = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")
