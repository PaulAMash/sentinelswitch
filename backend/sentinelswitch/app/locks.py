"""Process-wide serialization of state-changing requests.

Reads stay concurrent (each thread has its own SQLite connection), but a reset, a demo replay, an
assessment run, a remediation or an analyst decision must not interleave with another writer: each of
them loads the twin, changes it and saves it back. The lock is re-entrant so a handler may call another
serialized helper.
"""

from __future__ import annotations

import functools
import threading
from collections.abc import Callable
from typing import Any

MUTATION_LOCK = threading.RLock()


def serialized(fn: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with MUTATION_LOCK:
            return fn(*args, **kwargs)

    return wrapper
