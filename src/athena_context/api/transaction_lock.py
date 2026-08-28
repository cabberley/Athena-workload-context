from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from threading import RLock


class InMemoryTransactionLock:
    """Small internally owned transaction lock for standalone adapters."""

    def __init__(self) -> None:
        self._lock = RLock()

    @property
    def lock(self) -> RLock:
        return self._lock

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            yield
