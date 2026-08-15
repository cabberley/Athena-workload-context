from __future__ import annotations

import json
import math
import unicodedata
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

import rfc8785

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

_MAX_SAFE_INT = 9007199254740991


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


def _utf16_sort_key(value: str) -> tuple[int, ...]:
    return tuple(value.encode("utf-16-le"))


def _normalize_json_value(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return normalize_nfc_text(value)
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
        if utc_value.microsecond:
            iso = utc_value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        else:
            iso = utc_value.strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"
        return iso
    if isinstance(value, list):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = normalize_nfc_text(str(key))
            if key_text in normalized:
                raise NormalizationCollisionError(f"duplicate normalized object key: {key_text!r}")
            normalized[key_text] = _normalize_json_value(item)
        return normalized
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


def canonicalize_for_digest(
    value: Any, *, exclude_pointer_paths: Iterable[str] | None = None
) -> str:
    data = _normalize_json_value(value)
    if exclude_pointer_paths is not None:
        data = strip_excluded_paths(data, exclude_pointer_paths)
    return canonicalize_json(data)


def json_pointer_to_parts(pointer: str) -> tuple[str, ...]:
    if pointer == "":
        return ()
    pointer = pointer.strip()
    if pointer.startswith("#/"):
        pointer = pointer[2:]
    elif pointer.startswith("/"):
        pointer = pointer[1:]
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/") if part)


def remove_json_pointer(value: Any, pointer: str) -> Any:
    parts = json_pointer_to_parts(pointer)
    if not parts:
        return value

    def _walk(current: Any, index: int) -> Any:
        if index == len(parts):
            return None
        part = parts[index]
        if isinstance(current, dict):
            if part not in current:
                return current
            if index == len(parts) - 1:
                copied_dict: dict[str, Any] = dict(current)
                del copied_dict[part]
                return copied_dict
            next_value = _walk(current[part], index + 1)
            if next_value is None:
                copied_dict = dict(current)
                del copied_dict[part]
                return copied_dict
            copied_dict = dict(current)
            copied_dict[part] = next_value
            return copied_dict
        if isinstance(current, list):
            try:
                idx = int(part)
            except ValueError:
                return current
            if idx < 0 or idx >= len(current):
                return current
            if index == len(parts) - 1:
                copied_list: list[Any] = list(current)
                copied_list.pop(idx)
                return copied_list
            next_value = _walk(current[idx], index + 1)
            if next_value is None:
                copied_list = list(current)
                copied_list.pop(idx)
                return copied_list
            copied_list = list(current)
            copied_list[idx] = next_value
            return copied_list
        return current

    return _walk(value, 0)


def strip_excluded_paths(value: Any, exclude_paths: Iterable[str]) -> Any:
    cleaned = value
    for path in exclude_paths:
        cleaned = remove_json_pointer(cleaned, path)
    return cleaned


def compute_artifact_digest(value: Any, *, exclude_paths: Iterable[str] | None = None) -> str:
    canonical = canonicalize_for_digest(value, exclude_pointer_paths=exclude_paths)
    return sha256_hex(canonical)


def compute_semantic_digest(value: Any) -> str:
    canonical = canonicalize_json(value)
    return sha256_hex(canonical)
