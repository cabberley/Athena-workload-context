from __future__ import annotations

import os

from pydantic import ValidationError

from athena_context.api.domain import WorkloadGrantScope
from athena_context.api.durable import AzureTableContextStore


def required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip() or value != value.strip():
        raise RuntimeError(f"{name} must be configured for the Context API")
    return value


def configured_workload_id() -> str:
    value = required_environment("ATHENA_CONTEXT_STORE_WORKLOAD_ID")
    try:
        return WorkloadGrantScope(workload_id=value).workload_id
    except ValidationError as exc:
        raise RuntimeError(
            "ATHENA_CONTEXT_STORE_WORKLOAD_ID must be a concrete route-safe "
            "workload identifier"
        ) from exc


def create_configured_context_store(
    *,
    workload_id: str,
    allow_empty_partition_bootstrap: bool = False,
) -> AzureTableContextStore:
    return AzureTableContextStore(
        endpoint=required_environment("ATHENA_CONTEXT_STORE_ENDPOINT"),
        table_name=required_environment("ATHENA_CONTEXT_STORE_TABLE_NAME"),
        partition_key=required_environment("ATHENA_CONTEXT_STORE_PARTITION_KEY"),
        managed_identity_client_id=required_environment(
            "ATHENA_CONTEXT_IDENTITY_CLIENT_ID"
        ),
        workload_id=workload_id,
        allow_empty_partition_bootstrap=allow_empty_partition_bootstrap,
    )
