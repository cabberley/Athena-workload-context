from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from athena_context.api import (
    ContextApiPublishedContextResolver,
    EnvironmentContextApiPublishedContextReader,
    EnvironmentWc007PublishedContextSelectionPort,
    EnvironmentWc008DeploymentConfigurationPort,
)


@pytest.mark.live
def test_optional_private_mcp_rejects_unauthenticated_tools_request() -> None:
    if os.getenv("ATHENA_WC013_LIVE") != "1":
        pytest.skip("set ATHENA_WC013_LIVE=1 for explicit private endpoint validation")
    selection = EnvironmentWc007PublishedContextSelectionPort().load()
    resolved = ContextApiPublishedContextResolver(
        EnvironmentContextApiPublishedContextReader()
    ).resolve(
        selection,
        as_of=datetime.now(UTC),
    )
    assert resolved.view.supersession is None
    assert resolved.authority_token.manifest_version == selection.manifest_version
    deployment = EnvironmentWc008DeploymentConfigurationPort().load_verified()
    endpoint = deployment.assertion.azure_mcp_internal_endpoint

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
