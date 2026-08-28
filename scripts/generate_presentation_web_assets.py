from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from athena_context.contracts.presentation import (
    ArgusPresentationPayload,
    ArgusPresentationPhase,
)
from athena_context.fixtures import CANONICAL_PRIVATE_KEY
from athena_context.presentation import attest_argus_presentation

ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "apps" / "presentation-web"
SOURCE_ROOT = APP_ROOT / "fixture-source"
PUBLIC_ROOT = APP_ROOT / "public"
SYNTHETIC_KEY_ID = "synthetic-key://athena-argus-demo/rs256-v1"
PHASES: tuple[ArgusPresentationPhase, ...] = (
    "baseline",
    "faulted",
    "recovered",
)


class DeterministicPresentationSigner:
    """Use the repository proof key with the production presentation signer port."""

    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key

    def sign_preimage(self, canonical_preimage: bytes) -> str:
        signature = self._private_key.sign(
            canonical_preimage,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("ascii")


def build_presentation_web_assets() -> dict[Path, bytes]:
    """Build every reviewed public JSON file as deterministic LF-terminated bytes."""

    signer = DeterministicPresentationSigner(CANONICAL_PRIVATE_KEY)
    assets: dict[Path, bytes] = {}
    for phase in PHASES:
        payload = _load_source_payload(phase)
        payload_path = Path("fixtures") / f"{phase}.presentation.json"
        attestation_path = Path("fixtures") / f"{phase}.attestation.json"
        assets[payload_path] = _json_bytes(
            payload.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
        attestation = attest_argus_presentation(payload, signer=signer)
        assets[attestation_path] = _json_bytes(
            attestation.model_dump(mode="json", by_alias=True)
        )

    public_key, fingerprint = _public_key_asset()
    key_path = Path("trust") / "presentation-public-key.jwk.json"
    assets[key_path] = _json_bytes(public_key)
    assets[Path("runtime-manifest.json")] = _json_bytes(
        _runtime_manifest(assets, key_path=key_path, fingerprint=fingerprint)
    )
    return assets


def write_presentation_web_assets(assets: dict[Path, bytes]) -> None:
    for relative_path, content in assets.items():
        output_path = PUBLIC_ROOT / relative_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(content)


def check_presentation_web_assets(assets: dict[Path, bytes]) -> list[str]:
    drift: list[str] = []
    for relative_path, expected in assets.items():
        output_path = PUBLIC_ROOT / relative_path
        try:
            observed = output_path.read_bytes()
        except OSError:
            drift.append(f"missing generated asset: {output_path.relative_to(ROOT)}")
            continue
        if observed != expected:
            drift.append(f"generated asset drift: {output_path.relative_to(ROOT)}")
    return drift


def presentation_public_key_fingerprint() -> str:
    _, fingerprint = _public_key_asset()
    return fingerprint


def _load_source_payload(phase: ArgusPresentationPhase) -> ArgusPresentationPayload:
    source_path = SOURCE_ROOT / f"{phase}.presentation.json"
    source_bytes = source_path.read_bytes()
    if not 0 < len(source_bytes) <= 128 * 1024:
        raise ValueError(f"{source_path.relative_to(ROOT)} is outside the source byte bound")
    payload = ArgusPresentationPayload.model_validate_json(source_bytes)
    if payload.phase != phase:
        raise ValueError(f"{source_path.relative_to(ROOT)} has the wrong lifecycle phase")
    if payload.athena.key_vault_key_id != SYNTHETIC_KEY_ID:
        raise ValueError(f"{source_path.relative_to(ROOT)} has the wrong synthetic key ID")
    return payload


def _public_key_asset() -> tuple[dict[str, Any], str]:
    public_key = CANONICAL_PRIVATE_KEY.public_key()
    numbers = public_key.public_numbers()
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = _sha256(spki)
    return (
        {
            "schemaVersion": "athena.presentationWeb.publicKey.v1",
            "keyId": SYNTHETIC_KEY_ID,
            "fingerprint": fingerprint,
            "jwk": {
                "kty": "RSA",
                "n": _base64url_uint(numbers.n),
                "e": _base64url_uint(numbers.e),
                "alg": "RS256",
                "key_ops": ["verify"],
                "ext": True,
            },
        },
        fingerprint,
    )


def _runtime_manifest(
    assets: dict[Path, bytes],
    *,
    key_path: Path,
    fingerprint: str,
) -> dict[str, Any]:
    phases: list[dict[str, str]] = []
    for phase in PHASES:
        payload_path = Path("fixtures") / f"{phase}.presentation.json"
        attestation_path = Path("fixtures") / f"{phase}.attestation.json"
        phases.append(
            {
                "phase": phase,
                "payloadPath": f"./{payload_path.as_posix()}",
                "payloadSha256": _sha256(assets[payload_path]),
                "attestationPath": f"./{attestation_path.as_posix()}",
                "attestationSha256": _sha256(assets[attestation_path]),
            }
        )
    return {
        "schemaVersion": "athena.presentationWeb.runtime.v1",
        "classification": "synthetic-demo-only",
        "key": {
            "path": f"./{key_path.as_posix()}",
            "assetSha256": _sha256(assets[key_path]),
            "keyId": SYNTHETIC_KEY_ID,
            "fingerprint": fingerprint,
        },
        "phases": phases,
    }


def _base64url_uint(value: int) -> str:
    encoded = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_bytes(value: Any) -> bytes:
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
    )
    return (rendered + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic standalone Athena presentation assets."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if checked-in public assets differ from deterministic output.",
    )
    args = parser.parse_args(argv)
    assets = build_presentation_web_assets()
    if args.check:
        drift = check_presentation_web_assets(assets)
        if drift:
            print("Presentation web asset generation check failed:")
            for error in drift:
                print(f"- {error}")
            return 1
        print(
            "Presentation web assets are deterministic and current; "
            f"SPKI fingerprint {presentation_public_key_fingerprint()}."
        )
        return 0

    write_presentation_web_assets(assets)
    print(
        "Generated deterministic presentation web assets with "
        f"SPKI fingerprint {presentation_public_key_fingerprint()}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
