from __future__ import annotations

import json
import math
import re
import unicodedata
from datetime import UTC, datetime
from typing import Any

import rfc8785

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

_MAX_SAFE_INT = 9007199254740991
_ISO_DATETIME_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.([0-9]+))?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
_ISO_DATETIME_PREFIX_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
)


class AthenaValidationError(ValueError):
    """Raised when an Athena contract value fails a validation invariant."""


class NormalizationCollisionError(AthenaValidationError):
    """Raised when two NFC-normalized keys would collide."""


def normalize_nfc_text(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if _contains_unpaired_surrogate(normalized):
        raise AthenaValidationError("unpaired surrogate in normalized text")
    return normalized


def _contains_unpaired_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)


def _normalize_datetime_string(value: str) -> str:
    lexical_match = _ISO_DATETIME_RE.fullmatch(value)
    if lexical_match is None:
        if _ISO_DATETIME_PREFIX_RE.match(value):
            raise AthenaValidationError(
                "timestamp text must use RFC 3339 with Z or an ±HH:MM offset"
            )
        return value
    fractional_seconds = lexical_match.group(1)
    if (
        fractional_seconds is not None
        and len(fractional_seconds) > 3
        and any(digit != "0" for digit in fractional_seconds[3:])
    ):
        raise AthenaValidationError(
            "timestamp precision must be exactly representable in milliseconds"
        )
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return value
    utc_value = parsed.astimezone(UTC) if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    if utc_value.microsecond % 1000:
        raise AthenaValidationError(
            "timestamp precision must be exactly representable in milliseconds"
        )
    if utc_value.microsecond:
        return utc_value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return utc_value.strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"


def _utf16_sort_key(value: str) -> tuple[int, ...]:
    return tuple(value.encode("utf-16-le"))


def _normalize_json_value(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized_text = normalize_nfc_text(value)
        if "T" in normalized_text:
            return _normalize_datetime_string(normalized_text)
        return normalized_text
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise AthenaValidationError("numeric value exceeds IEEE-754 safe integer range")
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise AthenaValidationError("non-finite JSON numbers are invalid")
        if value == 0.0 and math.copysign(1.0, value) < 0:
            raise AthenaValidationError("negative zero is invalid in canonical JSON")
        if abs(value) > float("1.7976931348623157e308"):
            raise AthenaValidationError("float exceeds IEEE-754 range")
        return value
    if isinstance(value, datetime):
        utc_value = value.astimezone(UTC)
        if utc_value.microsecond % 1000:
            raise AthenaValidationError(
                "timestamp precision must be exactly representable in milliseconds"
            )
        if utc_value.microsecond:
            iso = utc_value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        else:
            iso = utc_value.strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"
        return iso
    if isinstance(value, list):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, dict):
        normalized_map: dict[str, Any] = {}
        for key, item in value.items():
            key_text = normalize_nfc_text(str(key))
            if key_text in normalized_map:
                raise NormalizationCollisionError(f"duplicate normalized object key: {key_text!r}")
            normalized_map[key_text] = _normalize_json_value(item)
        return normalized_map
    raise TypeError(f"unsupported JSON value type: {type(value)!r}")


def _render_json_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _render_canonical(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _render_json_string(value)
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise AthenaValidationError("numeric value exceeds IEEE-754 safe integer range")
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise AthenaValidationError("non-finite JSON numbers are invalid")
        if value == 0.0 and math.copysign(1.0, value) < 0:
            raise AthenaValidationError("negative zero is invalid in canonical JSON")
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_render_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        items = list(value.items())
        items.sort(key=lambda item: _utf16_sort_key(str(item[0])))
        rendered = ",".join(
            f"{_render_json_string(str(key))}:{_render_canonical(item)}" for key, item in items
        )
        return "{" + rendered + "}"
    raise TypeError(f"unsupported JSON value type: {type(value)!r}")


def canonicalize_json(value: Any) -> str:
    """Return RFC 8785-compatible canonical JSON as a UTF-8 string."""
    normalized = _normalize_json_value(value)
    encoded = rfc8785.dumps(normalized)
    return encoded.decode("utf-8")


def sha256_hex(value: str | bytes) -> str:
    import hashlib

    value_bytes = value.encode("utf-8") if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(value_bytes).hexdigest()


def canonicalize_for_digest(value: Any) -> str:
    return canonicalize_json(_normalize_json_value(value))


def compute_artifact_digest(value: Any) -> str:
    canonical = canonicalize_for_digest(value)
    return sha256_hex(canonical)


def compute_semantic_digest(value: Any) -> str:
    canonical = canonicalize_json(value)
    return sha256_hex(canonical)
