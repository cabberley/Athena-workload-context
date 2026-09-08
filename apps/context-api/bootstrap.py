"""One-shot deployment entry point for the durable Context API continuity root."""

from athena_context.api.production import (
    configured_workload_id,
    create_configured_context_store,
)


def initialize_context_store() -> None:
    workload_id = configured_workload_id()
    store = create_configured_context_store(
        workload_id=workload_id,
        allow_empty_partition_bootstrap=True,
    )
    store.initialize_empty_partition()


if __name__ == "__main__":
    initialize_context_store()
