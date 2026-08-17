from __future__ import annotations

import re

from athena_context.contracts.common import AthenaValidationError, normalize_nfc_text

_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._()-]+$")


def normalize_resource_id(value: str) -> str:
    """Validate an absolute Azure resource ID and return its stable comparison form."""

    normalized = normalize_nfc_text(value)
    if (
        normalized != normalized.strip()
        or "\\" in normalized
        or any(token in normalized for token in ("*", "?"))
    ):
        raise AthenaValidationError("Azure resource ID contains invalid characters")
    raw_parts = normalized.split("/")
    if len(raw_parts) < 5 or raw_parts[0] != "" or any(not part for part in raw_parts[1:]):
        raise AthenaValidationError("Azure resource ID must be an absolute component path")
    parts = raw_parts[1:]
    if parts[0].casefold() != "subscriptions" or not _GUID_RE.fullmatch(parts[1]):
        raise AthenaValidationError("Azure resource ID must begin with /subscriptions/{guid}")

    index = 2
    if index < len(parts) and parts[index].casefold() == "resourcegroups":
        if index + 1 >= len(parts) or not _COMPONENT_RE.fullmatch(parts[index + 1]):
            raise AthenaValidationError("Azure resource ID resourceGroups segment is invalid")
        index += 2
    if index >= len(parts) or parts[index].casefold() != "providers":
        raise AthenaValidationError("Azure resource ID must contain a provider path")
    while index < len(parts):
        if parts[index].casefold() != "providers" or index + 3 >= len(parts):
            raise AthenaValidationError("Azure resource ID provider path is malformed")
        if not _COMPONENT_RE.fullmatch(parts[index + 1]):
            raise AthenaValidationError("Azure resource ID provider namespace is invalid")
        index += 2
        component_count = 0
        while index < len(parts) and parts[index].casefold() != "providers":
            if (
                index + 1 >= len(parts)
                or not _COMPONENT_RE.fullmatch(parts[index])
                or not _COMPONENT_RE.fullmatch(parts[index + 1])
            ):
                raise AthenaValidationError("Azure resource ID type/name path is incomplete")
            component_count += 2
            index += 2
        if component_count == 0:
            raise AthenaValidationError("Azure resource ID provider has no resource type/name")
    return normalized.casefold()


__all__ = ["normalize_resource_id"]
