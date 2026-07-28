from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    attempts: int = 4
    base_delay_seconds: float = 0.35
    max_delay_seconds: float = 5.0
    jitter_ratio: float = 0.20

    def normalized(self) -> "RetryPolicy":
        return RetryPolicy(
            attempts=max(1, int(self.attempts)),
            base_delay_seconds=max(0.0, float(self.base_delay_seconds)),
            max_delay_seconds=max(0.0, float(self.max_delay_seconds)),
            jitter_ratio=max(0.0, float(self.jitter_ratio)),
        )

    def delay_for_attempt(self, failed_attempt: int, *, random_value: float | None = None) -> float:
        policy = self.normalized()
        base = min(policy.max_delay_seconds, policy.base_delay_seconds * (2 ** max(0, failed_attempt - 1)))
        if base <= 0 or policy.jitter_ratio <= 0:
            return base
        value = random.random() if random_value is None else min(1.0, max(0.0, random_value))
        jitter = base * policy.jitter_ratio
        return max(0.0, base - jitter + (2 * jitter * value))


async def retry_async(
    operation: Callable[[], Awaitable[T]],
    *,
    policy: RetryPolicy,
    is_retryable: Callable[[BaseException], bool] | None = None,
    on_retry: Callable[[int, float, BaseException], Any] | None = None,
    sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
) -> T:
    """Run an async operation with bounded exponential backoff.

    Cancellation and process-exit exceptions are never swallowed. The final
    exception is raised unchanged so callers retain their normal error handling.
    """
    normalized = policy.normalized()
    predicate = is_retryable or (lambda exc: True)

    for attempt in range(1, normalized.attempts + 1):
        try:
            return await operation()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if attempt >= normalized.attempts or not predicate(exc):
                raise
            delay = normalized.delay_for_attempt(attempt)
            if on_retry is not None:
                result = on_retry(attempt, delay, exc)
                if asyncio.iscoroutine(result):
                    await result
            if delay > 0:
                await sleep(delay)

    raise RuntimeError("retry loop ended unexpectedly")
