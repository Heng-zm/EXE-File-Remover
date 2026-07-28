from __future__ import annotations

import asyncio
import logging
import os
import platform
import re
import sys
import threading
import time
import traceback
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable

from .config import (
    BOT_TOKEN,
    REDIS_STATE_SIGNING_SECRET,
    SERVER_LOG_API_KEY,
    SERVER_LOG_CAPTURE_DEBUG,
    SERVER_LOG_CAPTURE_INFO,
    SERVER_LOG_CAPTURE_PYTHON_LOGS,
    SERVER_LOG_ENABLED,
    SERVER_LOG_MAX_ITEMS,
    SERVER_LOG_TRACEBACK_MAX_CHARS,
    SERVER_LOG_VALUE_MAX_CHARS,
    SUPABASE_SERVICE_ROLE_KEY,
    WEBHOOK_SECRET_TOKEN,
)

SERVER_STARTED_MONOTONIC = time.monotonic()
SERVER_STARTED_AT_UTC = datetime.now(timezone.utc).isoformat()
_SERVER_LOGS: deque[dict[str, Any]] = deque(maxlen=SERVER_LOG_MAX_ITEMS)
_SERVER_LOG_LOCK = threading.RLock()
_SERVER_LOG_SEQUENCE = 0
_SERVER_LOG_REQUEST_TOTAL = 0
_SERVER_LOG_ERROR_TOTAL = 0
_SERVER_LOG_LAST_ERROR_UTC = ""
_RUNTIME_PROVIDER: Callable[[], dict[str, Any]] | None = None


def configure_runtime_provider(provider: Callable[[], dict[str, Any]]) -> None:
    global _RUNTIME_PROVIDER
    _RUNTIME_PROVIDER = provider


def increment_request_total() -> None:
    global _SERVER_LOG_REQUEST_TOTAL
    with _SERVER_LOG_LOCK:
        _SERVER_LOG_REQUEST_TOTAL += 1


def _server_log_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _server_log_safe_text(value: Any, *, max_chars: int | None = None) -> str:
    limit = max(20, int(max_chars or SERVER_LOG_VALUE_MAX_CHARS))
    try:
        text = str(value)
    except Exception:
        text = repr(value)

    secret_patterns = (
        r"(?i)(initData|init_data|tgWebAppData|telegram_init_data|webAppData)=([^&\s]+)",
        r"(?i)(hash)=([a-f0-9]{32,128})",
        r"(?i)(token|secret|authorization|api[_-]?key|service[_-]?role[_-]?key)=([^&\s]+)",
    )
    for pattern in secret_patterns:
        text = re.sub(pattern, r"\1=<redacted>", text)

    for secret_value in (BOT_TOKEN, WEBHOOK_SECRET_TOKEN, SERVER_LOG_API_KEY, SUPABASE_SERVICE_ROLE_KEY, REDIS_STATE_SIGNING_SECRET):
        if secret_value:
            text = text.replace(str(secret_value), "<redacted>")

    text = text.replace(chr(0), "").strip()
    return text[: max(0, limit - 1)] + "…" if len(text) > limit else text


def _server_log_safe_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 2:
        return _server_log_safe_text(value, max_chars=160)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _server_log_safe_text(value)
    if isinstance(value, (list, tuple, set)):
        return [_server_log_safe_value(item, depth=depth + 1) for item in list(value)[:20]]
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, item in list(value.items())[:50]:
            key_text = _server_log_safe_text(key, max_chars=80)
            if key_text.casefold() in {"authorization", "cookie", "set-cookie", "x-telegram-init-data", "x-telegram-web-app-data"}:
                safe[key_text] = "<redacted>"
            else:
                safe[key_text] = _server_log_safe_value(item, depth=depth + 1)
        return safe
    return _server_log_safe_text(value)


def server_log_event(category: str, level: str, message: str, **fields: Any) -> None:
    global _SERVER_LOG_SEQUENCE, _SERVER_LOG_ERROR_TOTAL, _SERVER_LOG_LAST_ERROR_UTC
    if not SERVER_LOG_ENABLED:
        return

    level_clean = str(level or "info").strip().casefold() or "info"
    if level_clean == "warn":
        level_clean = "warning"
    category_clean = _server_log_safe_text(category or "process", max_chars=80) or "process"
    now_iso = _server_log_utc_iso()
    record: dict[str, Any] = {
        "id": 0,
        "ts": now_iso,
        "ts_ms": int(time.time() * 1000),
        "category": category_clean,
        "level": level_clean,
        "message": _server_log_safe_text(message, max_chars=SERVER_LOG_VALUE_MAX_CHARS),
    }
    for key, value in fields.items():
        if value is not None:
            record[_server_log_safe_text(key, max_chars=80)] = _server_log_safe_value(value)

    with _SERVER_LOG_LOCK:
        _SERVER_LOG_SEQUENCE += 1
        record["id"] = _SERVER_LOG_SEQUENCE
        _SERVER_LOGS.appendleft(record)
        if level_clean in {"error", "critical"} or category_clean.endswith("error"):
            _SERVER_LOG_ERROR_TOTAL += 1
            _SERVER_LOG_LAST_ERROR_UTC = now_iso


def server_log_snapshot(*, limit: int = 200, level: str = "all", category: str = "all", since_id: int = 0) -> list[dict[str, Any]]:
    level_filter = str(level or "all").strip().casefold()
    category_filter = str(category or "all").strip().casefold()
    try:
        since_id_int = max(0, int(since_id or 0))
    except (TypeError, ValueError):
        since_id_int = 0
    try:
        requested_limit = int(limit or 200)
    except (TypeError, ValueError):
        requested_limit = 200
    max_rows = max(1, min(requested_limit, min(SERVER_LOG_MAX_ITEMS, 1000)))

    filtered: list[dict[str, Any]] = []
    with _SERVER_LOG_LOCK:
        for row in _SERVER_LOGS:
            if since_id_int and int(row.get("id") or 0) <= since_id_int:
                continue
            if level_filter not in {"", "all", "*"} and str(row.get("level") or "").casefold() != level_filter:
                continue
            if category_filter not in {"", "all", "*"} and str(row.get("category") or "").casefold() != category_filter:
                continue
            filtered.append(dict(row))
            if len(filtered) >= max_rows:
                break
    return filtered


def clear_server_logs() -> None:
    with _SERVER_LOG_LOCK:
        _SERVER_LOGS.clear()


def server_log_counters() -> dict[str, Any]:
    with _SERVER_LOG_LOCK:
        latest_id = _SERVER_LOG_SEQUENCE
        buffered = len(_SERVER_LOGS)
        request_total = _SERVER_LOG_REQUEST_TOTAL
        error_total = _SERVER_LOG_ERROR_TOTAL
        last_error_at = _SERVER_LOG_LAST_ERROR_UTC
    return {
        "enabled": SERVER_LOG_ENABLED,
        "buffered": buffered,
        "max_items": SERVER_LOG_MAX_ITEMS,
        "latest_id": latest_id,
        "request_total": request_total,
        "error_total": error_total,
        "last_error_at": last_error_at,
    }


def process_status_snapshot() -> dict[str, Any]:
    uptime_seconds = max(0.0, time.monotonic() - SERVER_STARTED_MONOTONIC)
    memory_kb: int | None = None
    try:
        import resource
        memory_kb = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except Exception:
        memory_kb = None

    task_count: int | None = None
    try:
        task_count = len(asyncio.all_tasks())
    except RuntimeError:
        task_count = None

    snapshot: dict[str, Any] = {
        "pid": os.getpid(),
        "started_at": SERVER_STARTED_AT_UTC,
        "uptime_seconds": round(uptime_seconds, 3),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "memory_kb": memory_kb,
        "active_asyncio_tasks": task_count,
    }
    if _RUNTIME_PROVIDER is not None:
        try:
            snapshot.update(_RUNTIME_PROVIDER())
        except Exception as exc:
            snapshot["runtime_provider_error"] = _server_log_safe_text(exc, max_chars=200)
    return snapshot


class InMemoryServerLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            if not SERVER_LOG_CAPTURE_PYTHON_LOGS:
                return
            level_name = record.levelname.casefold()
            if level_name == "debug" and not SERVER_LOG_CAPTURE_DEBUG:
                return
            if level_name == "info" and not SERVER_LOG_CAPTURE_INFO:
                return
            if record.name == __name__ and "server log" in record.getMessage().casefold():
                return
            fields: dict[str, Any] = {"logger": record.name, "module": record.module, "line": record.lineno}
            if record.exc_info:
                tb_text = "".join(traceback.format_exception(*record.exc_info))
                fields["traceback"] = _server_log_safe_text(tb_text, max_chars=SERVER_LOG_TRACEBACK_MAX_CHARS)
            server_log_event("python_log", level_name, record.getMessage(), **fields)
        except Exception:
            return


def install_server_log_handler() -> None:
    if not SERVER_LOG_ENABLED or not SERVER_LOG_CAPTURE_PYTHON_LOGS:
        return
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if isinstance(handler, InMemoryServerLogHandler):
            return
    handler = InMemoryServerLogHandler()
    handler.setLevel(logging.DEBUG if SERVER_LOG_CAPTURE_DEBUG else logging.INFO)
    root_logger.addHandler(handler)
    server_log_event(
        "process", "info", "server log capture initialized",
        max_items=SERVER_LOG_MAX_ITEMS,
        capture_info=SERVER_LOG_CAPTURE_INFO,
        capture_debug=SERVER_LOG_CAPTURE_DEBUG,
    )


__all__ = [
    "configure_runtime_provider", "increment_request_total", "install_server_log_handler", "_server_log_safe_text",
    "_server_log_safe_value", "server_log_event", "server_log_snapshot",
    "clear_server_logs", "server_log_counters", "process_status_snapshot",
]
