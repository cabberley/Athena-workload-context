#!/usr/bin/env python3
"""Verify one reviewer-signed WC-028 effective-RBAC inventory."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sys
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn
from uuid import UUID, uuid5

_ATTESTATION_DOMAIN = "athena.wc028-effective-rbac-inventory-attestation-v2"
_VALIDATION_DOMAIN = "athena.wc028-effective-rbac-inventory-validation-v1"
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_STANDARD_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_SHA256_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_REVIEWER_PRINCIPAL_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_BOOTSTRAP_HANDOFF_PATTERN = _REVIEWER_PRINCIPAL_PATTERN
_BOOTSTRAP_DEPLOYMENT_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/providers/microsoft\.resources/"
    r"deployments/[a-z0-9._()-]{1,64}$"
)
_REVIEWER_KEY_ID_PATTERN = re.compile(
    r"^https://[A-Za-z0-9-]+\.vault\.azure\.net/keys/"
    r"[A-Za-z0-9-]{1,127}/[A-Fa-f0-9]{32}$"
)
_ISO_DATETIME_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.([0-9]+))?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
_ISO_DATETIME_PREFIX_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_INVENTORY_JSON_BYTES = 62_000
_ARM_TEMPLATE_GUID_NAMESPACE = UUID("11fb06fb-712d-4ddd-98c7-e71bbd588830")
_TARGET_QUERY_MODE = "assignedToPrincipalIncludingInheritedGroupsAndDescendants"


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value or value != value.strip():
        _fail(f"{name} is missing or malformed")
    return value


def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if any(0xD800 <= ord(character) <= 0xDFFF for character in normalized):
        _fail("canonical JSON cannot contain an unpaired surrogate")
    return normalized


def _normalize_datetime_text(value: str) -> str:
    lexical_match = _ISO_DATETIME_PATTERN.fullmatch(value)
    if lexical_match is None:
        if _ISO_DATETIME_PREFIX_PATTERN.match(value):
            _fail("timestamp text must use RFC 3339 with Z or an offset")
        return value
    fractional_seconds = lexical_match.group(1)
    if fractional_seconds is not None and len(fractional_seconds) > 3:
        if len(fractional_seconds) > 6:
            return value
        if any(digit != "0" for digit in fractional_seconds[3:]):
            return value
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return value
    utc_value = parsed.astimezone(UTC)
    if utc_value.microsecond % 1000:
        _fail("timestamp precision must be exactly representable in milliseconds")
    if utc_value.microsecond:
        return utc_value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return utc_value.strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"


def _normalize_json_value(value: object) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = _normalize_text(value)
        return _normalize_datetime_text(normalized) if "T" in normalized else normalized
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            _fail("canonical JSON integer exceeds the IEEE-754 safe range")
        return value
    if isinstance(value, float):
        _fail("effective-RBAC inventory cannot contain floating-point values")
    if isinstance(value, list):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, dict):
        normalized_items: dict[str, object] = {}
        for key, item in value.items():
            normalized_key = _normalize_text(str(key))
            if normalized_key in normalized_items:
                _fail("canonical JSON contains duplicate normalized object keys")
            normalized_items[normalized_key] = _normalize_json_value(item)
        return normalized_items
    _fail(f"canonical JSON contains unsupported type {type(value).__name__}")


def _utf16_sort_key(value: str) -> tuple[int, ...]:
    return tuple(value.encode("utf-16-le"))


def _render_canonical_json(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(_render_canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                f"{json.dumps(key, ensure_ascii=False, separators=(',', ':'))}:"
                f"{_render_canonical_json(value[key])}"
                for key in sorted(value, key=_utf16_sort_key)
            )
            + "}"
        )
    _fail(f"canonical JSON contains unsupported type {type(value).__name__}")


def _canonical_json(value: object) -> bytes:
    return _render_canonical_json(_normalize_json_value(value)).encode("utf-8")


def _artifact_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _arm_template_guid(*values: str) -> str:
    if not values or any(not value for value in values):
        _fail("ARM guid inputs must be non-empty strings")
    return str(uuid5(_ARM_TEMPLATE_GUID_NAMESPACE, "-".join(values)))


def _base64url_decode_integer(value: str, *, field_name: str) -> int:
    if _BASE64URL_PATTERN.fullmatch(value) is None:
        _fail(f"{field_name} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field_name} is not valid base64url") from exc
    if not decoded:
        _fail(f"{field_name} is empty")
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        _fail(f"{field_name} is not canonical base64url")
    return int.from_bytes(decoded, "big")


def _jwk_decode_integer(value: object, *, field_name: str) -> int:
    if not isinstance(value, str) or not value:
        _fail(f"{field_name} is missing or malformed")
    try:
        if _BASE64URL_PATTERN.fullmatch(value) is not None:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
                _fail(f"{field_name} is not canonical base64url")
        elif _STANDARD_BASE64_PATTERN.fullmatch(value) is not None:
            unpadded = value.rstrip("=")
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
            if base64.b64encode(decoded).decode("ascii").rstrip("=") != unpadded:
                _fail(f"{field_name} is not canonical base64")
        else:
            _fail(f"{field_name} is not valid base64 or base64url")
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field_name} is not valid base64 or base64url") from exc
    if not decoded:
        _fail(f"{field_name} is empty")
    return int.from_bytes(decoded, "big")


def _der_length(length: int) -> bytes:
    if length < 128:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _der_integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + _der_length(len(encoded)) + encoded


def _der_sequence(value: bytes) -> bytes:
    return b"\x30" + _der_length(len(value)) + value


def _subject_public_key_info(*, modulus: int, exponent: int) -> bytes:
    rsa_public_key = _der_sequence(_der_integer(modulus) + _der_integer(exponent))
    rsa_encryption_algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    subject_public_key = b"\x03" + _der_length(len(rsa_public_key) + 1) + b"\x00" + rsa_public_key
    return _der_sequence(rsa_encryption_algorithm + subject_public_key)


def _verify_rs256(
    *,
    modulus: int,
    exponent: int,
    signature: bytes,
    message: bytes,
) -> None:
    modulus_size = (modulus.bit_length() + 7) // 8
    if len(signature) != modulus_size:
        _fail("reviewer signature length does not match the RSA key")
    signature_integer = int.from_bytes(signature, "big")
    if signature_integer >= modulus:
        _fail("reviewer signature representative is outside the RSA modulus")
    encoded_message = pow(signature_integer, exponent, modulus).to_bytes(
        modulus_size,
        "big",
    )
    digest_info = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding_length = modulus_size - len(digest_info) - 3
    if padding_length < 8:
        _fail("reviewer RSA key is too small for RS256")
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    if not hmac.compare_digest(encoded_message, expected):
        _fail("reviewer signature is invalid")


def _load_and_validate_inventory(
    inventory_json: str,
    *,
    claimed_inventory_digest: str,
    source_manifest_digest: str,
) -> dict[str, object]:
    if len(inventory_json.encode("utf-8")) > _MAX_INVENTORY_JSON_BYTES:
        _fail("effective-RBAC inventory exceeds the deployment verification bound")
    try:
        inventory = json.loads(inventory_json)
    except json.JSONDecodeError as exc:
        raise ValueError("effective-RBAC inventory is not valid JSON") from exc
    if not isinstance(inventory, dict):
        _fail("effective-RBAC inventory must be a JSON object")
    if inventory.get("inventoryDigest") != claimed_inventory_digest:
        _fail("effective-RBAC inventory digest claim does not match the attestation")
    if inventory.get("sourceManifestDigest") != source_manifest_digest:
        _fail("effective-RBAC source manifest does not match the attestation")
    digest_payload = dict(inventory)
    digest_payload.pop("inventoryDigest", None)
    if _artifact_digest(digest_payload) != claimed_inventory_digest:
        _fail("effective-RBAC inventory digest is invalid")
    if inventory.get("schemaVersion") != "athena.wc028MonitoringEffectiveRbacInventory.v6":
        _fail("effective-RBAC inventory must use schema v6")
    if inventory.get("resourceGraphQueryRoleActions") != [
        "microsoft.resourcegraph/resources/read"
    ]:
        _fail("effective-RBAC inventory omits the exact Resource Graph query permission")
    if inventory.get("resourceHealthRoleActions") != [
        "microsoft.resourcehealth/availabilitystatuses/read"
    ]:
        _fail("effective-RBAC inventory omits the exact Resource Health availability permission")
    subscription_id = inventory.get("subscriptionId")
    ancestry = inventory.get("managementGroupAncestry")
    if (
        not isinstance(subscription_id, str)
        or _REVIEWER_PRINCIPAL_PATTERN.fullmatch(subscription_id) is None
        or not isinstance(ancestry, list)
        or not ancestry
        or any(not isinstance(item, str) for item in ancestry)
    ):
        _fail("effective-RBAC inventory target hierarchy is malformed")
    expected_principal_targets = sorted(
        [f"/subscriptions/{subscription_id.casefold()}", *(item.casefold() for item in ancestry)]
    )
    for field_name in (
        "collectorPrincipalEvidence",
        "athenaContextPrincipalEvidence",
        "runtimeSupportPrincipalEvidence",
    ):
        _validate_target_read_evidence(
            inventory.get(field_name),
            expected_target_scope_ids=expected_principal_targets,
            field_name=field_name,
        )
    verifier_evidence = inventory.get("reviewerKeyVerifierEvidence")
    if not isinstance(verifier_evidence, dict):
        _fail("reviewer-key verifier evidence is missing")
    _validate_target_read_evidence(
        verifier_evidence.get("principalEvidence"),
        expected_target_scope_ids=[f"/subscriptions/{subscription_id.casefold()}"],
        field_name="reviewerKeyVerifierEvidence.principalEvidence",
    )
    return inventory


def _validate_target_read_evidence(
    value: object,
    *,
    expected_target_scope_ids: list[str],
    field_name: str,
) -> None:
    if not isinstance(value, dict):
        _fail(f"{field_name} is missing")
    forbidden_legacy_fields = {
        "queryFilter",
        "includeInherited",
        "includeGroups",
        "includeAllDescendantScopes",
        "targetScopeIds",
        "firstReadTargetDigests",
        "secondReadTargetDigests",
        "roleAssignmentRawPageDigests",
        "transitiveGroupRawPageDigests",
        "firstRoleAssignmentRawPageDigests",
        "secondRoleAssignmentRawPageDigests",
    }
    if forbidden_legacy_fields.intersection(value):
        _fail(f"{field_name} contains legacy unbound target evidence")
    principal_id = value.get("principalId")
    target_reads = value.get("targetReadEvidence")
    first_group_pages = value.get("firstTransitiveGroupRawPageDigests")
    second_group_pages = value.get("secondTransitiveGroupRawPageDigests")
    if (
        not isinstance(principal_id, str)
        or _REVIEWER_PRINCIPAL_PATTERN.fullmatch(principal_id) is None
        or not isinstance(target_reads, list)
        or not target_reads
        or value.get("allPagesRetrieved") is not True
        or not isinstance(first_group_pages, list)
        or not first_group_pages
        or first_group_pages != second_group_pages
    ):
        _fail(f"{field_name} target-read evidence is incomplete")
    targets: list[str] = []
    target_digests: list[str] = []
    page_digests: list[str] = []
    binding_ids: list[str] = []
    required_keys = {
        "targetScopeId",
        "queryMode",
        "targetDigest",
        "rawPageDigests",
        "readCount",
        "allPagesRetrieved",
        "bindingId",
    }
    for target_read in target_reads:
        if not isinstance(target_read, dict) or set(target_read) != required_keys:
            _fail(f"{field_name} target read has an invalid shape")
        target_scope_id = target_read.get("targetScopeId")
        query_mode = target_read.get("queryMode")
        target_digest = target_read.get("targetDigest")
        raw_page_digests = target_read.get("rawPageDigests")
        binding_id = target_read.get("bindingId")
        if (
            not isinstance(target_scope_id, str)
            or target_scope_id != target_scope_id.casefold().rstrip("/")
            or query_mode != _TARGET_QUERY_MODE
            or not isinstance(target_digest, str)
            or _SHA256_PATTERN.fullmatch(target_digest) is None
            or not isinstance(raw_page_digests, list)
            or not raw_page_digests
            or raw_page_digests != sorted(raw_page_digests)
            or len(raw_page_digests) != len(set(raw_page_digests))
            or any(
                not isinstance(item, str) or _SHA256_PATTERN.fullmatch(item) is None
                for item in raw_page_digests
            )
            or target_read.get("readCount") != 2
            or target_read.get("allPagesRetrieved") is not True
            or not isinstance(binding_id, str)
            or _REVIEWER_PRINCIPAL_PATTERN.fullmatch(binding_id) is None
        ):
            _fail(f"{field_name} target read is malformed")
        expected_binding_id = _arm_template_guid(
            principal_id.casefold(),
            target_scope_id,
            _TARGET_QUERY_MODE,
            target_digest,
            ",".join(raw_page_digests),
            "2",
            "true",
        )
        if binding_id != expected_binding_id:
            _fail(f"{field_name} target read binding is invalid")
        targets.append(target_scope_id)
        target_digests.append(target_digest)
        page_digests.extend(raw_page_digests)
        binding_ids.append(binding_id)
    if (
        targets != sorted(expected_target_scope_ids)
        or len(targets) != len(set(targets))
        or len(target_digests) != len(set(target_digests))
        or len(page_digests) != len(set(page_digests))
        or len(binding_ids) != len(set(binding_ids))
    ):
        _fail(f"{field_name} target reads are duplicated or incomplete")
    evidence_digest = value.get("evidenceDigest")
    if not isinstance(evidence_digest, str) or _SHA256_PATTERN.fullmatch(evidence_digest) is None:
        _fail(f"{field_name} evidence digest is malformed")
    digest_payload = dict(value)
    digest_payload.pop("evidenceDigest", None)
    if _artifact_digest(digest_payload) != evidence_digest:
        _fail(f"{field_name} evidence digest is invalid")


def _validate() -> dict[str, object]:
    if (
        _required_environment("ATHENA_ATTESTATION_SCHEMA_VERSION")
        != "athena.wc028MonitoringEffectiveRbacInventoryAttestation.v2"
    ):
        _fail("effective-RBAC inventory attestation must use schema v2")
    if _required_environment("ATHENA_SIGNATURE_ALGORITHM") != "RS256":
        _fail("effective-RBAC inventory attestation must use RS256")
    bootstrap_handoff_id = _required_environment("ATHENA_BOOTSTRAP_HANDOFF_ID")
    bootstrap_deployment_id = (
        _required_environment("ATHENA_BOOTSTRAP_DEPLOYMENT_ID").casefold().rstrip("/")
    )
    bootstrap_template_hash = _required_environment("ATHENA_BOOTSTRAP_TEMPLATE_HASH")
    bootstrap_contract_inputs_binding_id = _required_environment(
        "ATHENA_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID"
    )
    reviewer_principal_id = _required_environment("ATHENA_REVIEWER_PRINCIPAL_ID")
    runtime_support_principal_id = _required_environment(
        "ATHENA_RUNTIME_SUPPORT_PRINCIPAL_ID"
    )
    reviewer_key_id = _required_environment("ATHENA_REVIEWER_KEY_ID")
    public_key_modulus = _required_environment("ATHENA_PUBLIC_KEY_MODULUS")
    public_key_exponent = _required_environment("ATHENA_PUBLIC_KEY_EXPONENT")
    public_key_fingerprint = _required_environment("ATHENA_PUBLIC_KEY_FINGERPRINT")
    reviewer_jwk_json = _required_environment("ATHENA_REVIEWER_JWK_JSON")
    inventory_digest = _required_environment("ATHENA_INVENTORY_DIGEST")
    source_manifest_digest = _required_environment("ATHENA_SOURCE_MANIFEST_DIGEST")
    cleanup_schema_version = _required_environment("ATHENA_LEGACY_RBAC_CLEANUP_SCHEMA_VERSION")
    cleanup_digest = _required_environment("ATHENA_LEGACY_RBAC_CLEANUP_DIGEST")
    signed_preimage_digest = _required_environment("ATHENA_SIGNED_PREIMAGE_DIGEST")
    signature_value = _required_environment("ATHENA_SIGNATURE")
    inventory_json = _required_environment("ATHENA_INVENTORY_JSON")

    if (
        _BOOTSTRAP_HANDOFF_PATTERN.fullmatch(bootstrap_handoff_id) is None
        or bootstrap_handoff_id == "00000000-0000-0000-0000-000000000000"
    ):
        _fail("bootstrap handoff ID is not a nonzero canonical UUID")
    if _BOOTSTRAP_DEPLOYMENT_PATTERN.fullmatch(bootstrap_deployment_id) is None:
        _fail("bootstrap deployment ID is not canonical")
    if (
        not bootstrap_template_hash
        or _BOOTSTRAP_HANDOFF_PATTERN.fullmatch(bootstrap_contract_inputs_binding_id) is None
    ):
        _fail("bootstrap template hash or contract-input binding ID is invalid")
    if (
        _REVIEWER_PRINCIPAL_PATTERN.fullmatch(reviewer_principal_id) is None
        or reviewer_principal_id == "00000000-0000-0000-0000-000000000000"
    ):
        _fail("reviewer principal is not a nonzero canonical UUID")
    if (
        _REVIEWER_PRINCIPAL_PATTERN.fullmatch(runtime_support_principal_id) is None
        or runtime_support_principal_id == "00000000-0000-0000-0000-000000000000"
        or reviewer_principal_id == runtime_support_principal_id
    ):
        _fail("reviewer principal must be separate from the runtime-support principal")
    if _REVIEWER_KEY_ID_PATTERN.fullmatch(
        reviewer_key_id
    ) is None or not reviewer_key_id.startswith(
        "https://athenarbacevidencekv.vault.azure.net/keys/monitoring-rbac-inventory-review/"
    ):
        _fail("reviewer key ID is not an exact versioned Azure Key Vault key")
    try:
        reviewer_jwk = json.loads(reviewer_jwk_json)
    except json.JSONDecodeError as exc:
        raise ValueError("reviewer Key Vault JWK is not valid JSON") from exc
    if not isinstance(reviewer_jwk, dict):
        _fail("reviewer public key does not match the exact versioned Key Vault key")
    key_operations = reviewer_jwk.get("key_ops")
    if (
        reviewer_jwk.get("kid") != reviewer_key_id
        or reviewer_jwk.get("kty") not in {"RSA", "RSA-HSM"}
        or not isinstance(key_operations, list)
        or not {"sign", "verify"}.issubset(set(key_operations))
    ):
        _fail("reviewer public key does not match the exact versioned Key Vault key")
    for name, value in (
        ("ATHENA_PUBLIC_KEY_FINGERPRINT", public_key_fingerprint),
        ("ATHENA_INVENTORY_DIGEST", inventory_digest),
        ("ATHENA_SOURCE_MANIFEST_DIGEST", source_manifest_digest),
        ("ATHENA_LEGACY_RBAC_CLEANUP_DIGEST", cleanup_digest),
        ("ATHENA_SIGNED_PREIMAGE_DIGEST", signed_preimage_digest),
    ):
        if _SHA256_PATTERN.fullmatch(value) is None:
            _fail(f"{name} is not a canonical SHA-256 digest")
    if (
        cleanup_schema_version != "athena.wc028LegacyCollectorRbacCleanup.v3"
        or cleanup_digest == "sha256:" + ("0" * 64)
    ):
        _fail("legacy collector RBAC cleanup binding is invalid")

    modulus = _base64url_decode_integer(
        public_key_modulus,
        field_name="ATHENA_PUBLIC_KEY_MODULUS",
    )
    exponent = _base64url_decode_integer(
        public_key_exponent,
        field_name="ATHENA_PUBLIC_KEY_EXPONENT",
    )
    jwk_modulus = _jwk_decode_integer(
        reviewer_jwk.get("n"),
        field_name="reviewer JWK modulus",
    )
    jwk_exponent = _jwk_decode_integer(
        reviewer_jwk.get("e"),
        field_name="reviewer JWK exponent",
    )
    if jwk_modulus != modulus or jwk_exponent != exponent:
        _fail("reviewer public key does not match the exact versioned Key Vault key")
    if modulus.bit_length() < 2048 or exponent != 65537:
        _fail("reviewer key must be RSA-2048 or stronger with exponent 65537")

    subject_public_key_info = _subject_public_key_info(
        modulus=modulus,
        exponent=exponent,
    )
    computed_fingerprint = "sha256:" + hashlib.sha256(subject_public_key_info).hexdigest()
    if not hmac.compare_digest(computed_fingerprint, public_key_fingerprint):
        _fail("reviewer public-key fingerprint is invalid")

    _load_and_validate_inventory(
        inventory_json,
        claimed_inventory_digest=inventory_digest,
        source_manifest_digest=source_manifest_digest,
    )
    preimage = {
        "domain": _ATTESTATION_DOMAIN,
        "bootstrapContractInputsBindingId": bootstrap_contract_inputs_binding_id,
        "bootstrapDeploymentId": bootstrap_deployment_id,
        "bootstrapHandoffId": bootstrap_handoff_id,
        "bootstrapTemplateHash": bootstrap_template_hash,
        "inventoryDigest": inventory_digest,
        "legacyCollectorRbacCleanupDigest": cleanup_digest,
        "legacyCollectorRbacCleanupSchemaVersion": cleanup_schema_version,
        "publicKeyFingerprint": public_key_fingerprint,
        "reviewerKeyId": reviewer_key_id,
        "reviewerPrincipalId": reviewer_principal_id,
        "sourceManifestDigest": source_manifest_digest,
    }
    encoded_preimage = _canonical_json(preimage)
    computed_preimage_digest = "sha256:" + hashlib.sha256(encoded_preimage).hexdigest()
    if not hmac.compare_digest(computed_preimage_digest, signed_preimage_digest):
        _fail("reviewer signed-preimage digest is invalid")
    try:
        signature = base64.b64decode(signature_value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("reviewer signature is not canonical base64") from exc
    _verify_rs256(
        modulus=modulus,
        exponent=exponent,
        signature=signature,
        message=encoded_preimage,
    )

    validation = {
        "domain": _VALIDATION_DOMAIN,
        "bootstrapHandoffId": bootstrap_handoff_id,
        "inventoryDigest": inventory_digest,
        "legacyCollectorRbacCleanupDigest": cleanup_digest,
        "publicKeyFingerprint": public_key_fingerprint,
        "signedPreimageDigest": signed_preimage_digest,
    }
    return {
        "validated": True,
        "inventoryDigest": inventory_digest,
        "signedPreimageDigest": signed_preimage_digest,
        "validationDigest": _artifact_digest(validation),
    }


def main() -> int:
    try:
        outputs = _validate()
        output_path = Path(_required_environment("AZ_SCRIPTS_OUTPUT_PATH"))
        output_path.write_text(
            json.dumps(outputs, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )
    except (OSError, ValueError) as exc:
        print(f"effective-RBAC inventory verification failed: {exc}", file=sys.stderr)
        return 1
    print("effective-RBAC inventory signature and canonical digest verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
