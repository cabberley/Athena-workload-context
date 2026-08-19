from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from athena_context.live_acceptance import (
    prepare_wc013_live_acceptance,
    run_wc013_live_acceptance,
)


def _live_configuration_path() -> Path:
    if os.getenv("ATHENA_WC013_LIVE") != "1":
        pytest.skip("set ATHENA_WC013_LIVE=1 for explicit live acceptance")
    value = os.getenv("ATHENA_WC013_LIVE_CONFIG")
    if value is None or not value.strip():
        pytest.fail("ATHENA_WC013_LIVE_CONFIG is required for live acceptance")
    return Path(value)


@pytest.mark.live
def test_private_mcp_response_produces_cryptographically_verified_snapshot(
    tmp_path: Path,
) -> None:
    accepted = run_wc013_live_acceptance(
        _live_configuration_path(),
        snapshot_output=tmp_path / "wc013-live-evidence-snapshot.json",
    )

    assert accepted.result.snapshot.collector_attempts[0].attempt_type == (
        "successResponse"
    )
    assert accepted.result.snapshot.evidence_records
    assert accepted.result.snapshot.snapshot_attestation.signature
    assert accepted.snapshot_path is not None
    assert accepted.snapshot_path.is_file()


@pytest.mark.live
def test_optional_private_mcp_rejects_unauthenticated_tools_request() -> None:
    prepared = prepare_wc013_live_acceptance(_live_configuration_path())
    endpoint = prepared.assertion.azure_mcp_internal_endpoint

    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "wc013-unauthenticated-probe",
            "method": "tools/list",
            "params": {},
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5):  # noqa: S310
            pytest.fail("private MCP accepted an unauthenticated tools request")
    except HTTPError as exc:
        assert exc.code in {401, 403}
