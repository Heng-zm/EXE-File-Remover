import asyncio

from exe_remover_bot_app.retry import RetryPolicy, retry_async


def test_retry_eventually_succeeds():
    attempts = 0
    sleeps = []

    async def operation():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise OSError("temporary")
        return "ok"

    async def fake_sleep(delay):
        sleeps.append(delay)

    result = asyncio.run(retry_async(
        operation,
        policy=RetryPolicy(attempts=4, base_delay_seconds=0.1, max_delay_seconds=1, jitter_ratio=0),
        sleep=fake_sleep,
    ))
    assert result == "ok"
    assert attempts == 3
    assert sleeps == [0.1, 0.2]


def test_retry_stops_for_non_retryable_error():
    attempts = 0

    async def operation():
        nonlocal attempts
        attempts += 1
        raise ValueError("permanent")

    try:
        asyncio.run(retry_async(
            operation,
            policy=RetryPolicy(attempts=5, base_delay_seconds=0),
            is_retryable=lambda exc: isinstance(exc, OSError),
        ))
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError should be raised")
    assert attempts == 1
