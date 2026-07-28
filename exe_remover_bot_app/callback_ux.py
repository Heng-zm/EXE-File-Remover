from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

_RECENT_LOCK = asyncio.Lock()
_RECENT_ACTIONS: dict[str, float] = {}


def callback_fingerprint(query: Any) -> str:
    """Hash callback identity without retaining callback tokens or user data."""
    user = getattr(query, "from_user", None)
    message = getattr(query, "message", None)
    chat = getattr(message, "chat", None)
    material = "|".join(
        (
            str(getattr(user, "id", "")),
            str(getattr(chat, "id", "")),
            str(getattr(query, "data", "")),
        )
    )
    return hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()


async def claim_callback_action(
    query: Any,
    *,
    cooldown_seconds: float,
    max_items: int,
) -> bool:
    """Prevent rapid duplicate taps from applying a mutation twice."""
    cooldown = max(0.0, float(cooldown_seconds))
    if cooldown <= 0:
        return True

    fingerprint = callback_fingerprint(query)
    now = time.monotonic()
    async with _RECENT_LOCK:
        previous = _RECENT_ACTIONS.get(fingerprint, 0.0)
        if previous and now - previous < cooldown:
            return False
        _RECENT_ACTIONS[fingerprint] = now

        bounded_max = max(100, int(max_items))
        if len(_RECENT_ACTIONS) > bounded_max:
            cutoff = now - max(cooldown * 4, 30.0)
            for key, seen_at in list(_RECENT_ACTIONS.items()):
                if seen_at < cutoff:
                    _RECENT_ACTIONS.pop(key, None)
            overflow = len(_RECENT_ACTIONS) - bounded_max
            if overflow > 0:
                for key in list(_RECENT_ACTIONS)[:overflow]:
                    _RECENT_ACTIONS.pop(key, None)
    return True


__all__ = ["callback_fingerprint", "claim_callback_action"]
