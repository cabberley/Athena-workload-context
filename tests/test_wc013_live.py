from __future__ import annotations

import json
import os
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


@pytest.mark.live
def test_optional_private_mcp_rejects_unauthenticated_tools_request() -> None:
    if os.getenv("ATHENA_WC013_LIVE") != "1":
        pytest.skip("set ATHENA_WC013_LIVE=1 for explicit private endpoint validation")
    endpoint = os.environ.get("ATHENA_WC013_PRIVATE_MCP_ENDPOINT")
    if endpoint is None:
        pytest.fail("ATHENA_WC013_PRIVATE_MCP_ENDPOINT is required in live mode")
    if not endpoint.startswith("https://"):
        pytest.fail("live MCP endpoint must use HTTPS")

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
