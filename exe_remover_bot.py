

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import hmac
import inspect
import io
import json
import logging
import os
import pickle
import platform
import re
import secrets
import sys
import threading
import time
import traceback
import unicodedata
import zipfile
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from typing import Any, Generic, Iterable, TypeVar
from urllib.parse import parse_qsl

import httpx
from dotenv import load_dotenv

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
except ImportError:  # Mini App API is optional; webhook/polling bot still works without it.
    FastAPI = None  # type: ignore[assignment]
    HTTPException = None  # type: ignore[assignment]
    Request = Any  # type: ignore[assignment,misc]
    CORSMiddleware = None  # type: ignore[assignment]
    uvicorn = None  # type: ignore[assignment]

try:
    import redis.asyncio as redis_async
except ImportError:  # Redis is optional; the bot falls back to local pickle persistence.
    redis_async = None  # type: ignore[assignment]
from telegram import ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatMemberStatus, ChatType, ParseMode
from telegram.error import BadRequest, Forbidden, RetryAfter, TelegramError, TimedOut
from telegram.ext import (
    Application,
    ApplicationBuilder,
    ApplicationHandlerStop,
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    PicklePersistence,
    TypeHandler,
    filters,
)

# ─────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────

load_dotenv()


def _env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_int(name: str, default: int, *, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = _env_str(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        value = default
    if min_value is not None:
        value = max(min_value, value)
    if max_value is not None:
        value = min(max_value, value)
    return value


def _env_float(name: str, default: float, *, min_value: float | None = None) -> float:
    raw = _env_str(name, str(default))
    try:
        value = float(raw)
    except ValueError:
        value = default
    if min_value is not None:
        value = max(min_value, value)
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = _env_str(name, "")
    if not raw:
        return default
    return raw.casefold() in {"1", "true", "yes", "y", "on"}


def _env_csv(name: str, default: Iterable[str]) -> tuple[str, ...]:
    raw = _env_str(name, "")
    items = [x.strip() for x in raw.split(",") if x.strip()] if raw else list(default)
    return tuple(dict.fromkeys(items))


def _normalize_extension(ext: str) -> str:
    cleaned = ext.strip().casefold()
    return cleaned if cleaned.startswith(".") else f".{cleaned}"


def _env_extensions(name: str, default: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(_normalize_extension(ext) for ext in _env_csv(name, default) if ext.strip()))


BOT_TOKEN = _env_str("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("CRITICAL: BOT_TOKEN is missing. Set BOT_TOKEN in the environment.")

BOT_MODE = _env_str("BOT_MODE", "AUTO").upper()
if BOT_MODE not in {"AUTO", "WEBHOOK", "POLLING"}:
    raise RuntimeError("BOT_MODE must be AUTO, WEBHOOK, or POLLING.")

PORT = _env_int("PORT", 8080, min_value=1, max_value=65535)
RENDER_EXTERNAL_URL = _env_str("RENDER_EXTERNAL_URL").rstrip("/")
WEBHOOK_BASE_URL = (_env_str("WEBHOOK_URL") or RENDER_EXTERNAL_URL).rstrip("/")
WEBHOOK_SECRET_TOKEN = _env_str("WEBHOOK_SECRET_TOKEN") or secrets.token_urlsafe(24)
WEBHOOK_URL_PATH = _env_str("WEBHOOK_URL_PATH") or f"tg-webhook/{WEBHOOK_SECRET_TOKEN}"
PERSISTENCE_FILE = _env_str("PERSISTENCE_FILE", "exe_bot_data.pickle")
LOCAL_PERSISTENCE_ENABLED = _env_bool("LOCAL_PERSISTENCE_ENABLED", True)

REDIS_URL = _env_str("REDIS_URL")
REDIS_ENABLED = _env_bool("REDIS_ENABLED", bool(REDIS_URL))
REDIS_PREFIX = _env_str("REDIS_PREFIX", "exe_remover_bot")
REDIS_STATE_KEY = _env_str("REDIS_STATE_KEY", f"{REDIS_PREFIX}:state")
REDIS_CONNECT_TIMEOUT_SECONDS = _env_float("REDIS_CONNECT_TIMEOUT_SECONDS", 5.0, min_value=1.0)
REDIS_SOCKET_TIMEOUT_SECONDS = _env_float("REDIS_SOCKET_TIMEOUT_SECONDS", 5.0, min_value=1.0)
REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS = _env_float("REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS", 2.0, min_value=0.0)
# Redis state is JSON + HMAC signed by default.  This removes the unsafe
# pickle.loads(raw) RCE vector from Redis while keeping local PTB
# PicklePersistence available for filesystem-only fallback.
REDIS_STATE_SIGNING_SECRET = _env_str("REDIS_STATE_SIGNING_SECRET")
REDIS_LEGACY_PICKLE_LOAD_ENABLED = _env_bool("REDIS_LEGACY_PICKLE_LOAD_ENABLED", False)

# Optional Supabase persistence. This stores the same durable bot_data snapshot
# as Redis, but in a Supabase/Postgres JSONB row. Redis/local pickle remain
# safe fallbacks when Supabase is disabled or temporarily unavailable.
SUPABASE_URL = _env_str("SUPABASE_URL").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = (
    _env_str("SUPABASE_SERVICE_ROLE_KEY")
    or _env_str("SUPABASE_SECRET_KEY")
    or _env_str("SUPABASE_KEY")
)
SUPABASE_ENABLED = _env_bool("SUPABASE_ENABLED", bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY))
SUPABASE_TABLE = _env_str("SUPABASE_TABLE", "bot_state")
SUPABASE_STATE_KEY = _env_str("SUPABASE_STATE_KEY", f"{REDIS_PREFIX}:state")
SUPABASE_TIMEOUT_SECONDS = _env_float("SUPABASE_TIMEOUT_SECONDS", 10.0, min_value=1.0)
SUPABASE_AUTOSAVE_MIN_INTERVAL_SECONDS = _env_float(
    "SUPABASE_AUTOSAVE_MIN_INTERVAL_SECONDS",
    REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS,
    min_value=0.0,
)
# Coalesce rapid settings/callback saves into one durable write. This keeps
# inline buttons responsive on Render when Redis/Supabase has cold-start or
# network latency, while force=True still skips backend save intervals.
MEMORY_SAVE_DEBOUNCE_SECONDS = _env_float("MEMORY_SAVE_DEBOUNCE_SECONDS", 1.25, min_value=0.0)


MAX_CONCURRENT_UPDATES = _env_int("MAX_CONCURRENT_UPDATES", 8, min_value=1, max_value=64)
TELEGRAM_CONNECTION_POOL_SIZE = _env_int("TELEGRAM_CONNECTION_POOL_SIZE", 32, min_value=8, max_value=256)
TELEGRAM_POOL_TIMEOUT = _env_float("TELEGRAM_POOL_TIMEOUT", 10.0, min_value=1.0)
TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES = 20_971_520
SILENT_MODE_NOTICE_DELETE_SECONDS = _env_int("SILENT_MODE_NOTICE_DELETE_SECONDS", 12, min_value=5, max_value=60)
# Professional security default: admins/owners should NOT bypass scanner.
# Previous builds allowed admin bypass when STRICT_ENFORCEMENT_ON_ADMINS=false,
# which let files such as 1.exe pass through if sent by an admin.
# ADMIN_BYPASS_ENABLED is now an explicit opt-in escape hatch, and even when
# enabled the bypass never applies to obvious dangerous filenames/MIME types.
STRICT_ENFORCEMENT_ON_ADMINS_DEFAULT = _env_bool("STRICT_ENFORCEMENT_ON_ADMINS", True)
ADMIN_BYPASS_ENABLED = _env_bool("ADMIN_BYPASS_ENABLED", False)
ADMIN_CACHE_TTL_SECONDS = _env_int("ADMIN_CACHE_TTL_SECONDS", 180, min_value=5)
BOT_MEMBER_CACHE_TTL_SECONDS = _env_int("BOT_MEMBER_CACHE_TTL_SECONDS", 60, min_value=5)
# When Telegram says the bot was kicked/removed from a group, suppress repeated
# live API checks for that chat. This prevents Render log spam and Telegram
# rate-limit pressure while still self-healing when my_chat_member reports the
# bot was added back.
INACCESSIBLE_CHAT_API_SUPPRESS_SECONDS = _env_int(
    "INACCESSIBLE_CHAT_API_SUPPRESS_SECONDS",
    3600,
    min_value=60,
    max_value=86400,
)
INCIDENT_TTL_SECONDS = _env_int("INCIDENT_TTL_SECONDS", 86400, min_value=60)
KEEP_AWAKE_INTERVAL_SECONDS = _env_int("KEEP_AWAKE_INTERVAL_SECONDS", 600, min_value=60)
DROP_PENDING_UPDATES = _env_bool("DROP_PENDING_UPDATES", False)
QUIET_HTTPX_LOGS = _env_bool("QUIET_HTTPX_LOGS", True)
QUIET_APSCHEDULER_LOGS = _env_bool("QUIET_APSCHEDULER_LOGS", True)

# Keep the original hard block behavior by default: .exe is always blocked.
# The suspicious scanner can catch renamed/double-extension executables and related risky formats.
BLOCKED_EXTENSIONS = _env_extensions("BLOCKED_EXTENSIONS", [".exe"])

DEFAULT_DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".msi",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".psd1", ".jar", ".apk", ".reg", ".lnk",
)
DANGEROUS_EXTENSIONS = tuple(dict.fromkeys(BLOCKED_EXTENSIONS + _env_extensions("DANGEROUS_EXTENSIONS", DEFAULT_DANGEROUS_EXTENSIONS)))
ARCHIVE_EXTENSIONS = _env_extensions("ARCHIVE_EXTENSIONS", [".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".iso"])
BLOCKED_MIME_TYPES = tuple(
    mt.casefold()
    for mt in _env_csv(
        "BLOCKED_MIME_TYPES",
        [
            "application/x-msdownload",
            "application/vnd.microsoft.portable-executable",
            "application/x-dosexec",
            "application/x-ms-installer",
            "application/java-archive",
            "application/vnd.android.package-archive",
        ],
    )
)
SUSPICIOUS_SCANNER_ENABLED = _env_bool("SUSPICIOUS_SCANNER_ENABLED", True)
SUSPICIOUS_MAGIC_SCAN_ENABLED = _env_bool("SUSPICIOUS_MAGIC_SCAN_ENABLED", True)
SUSPICIOUS_ARCHIVE_SCAN_ENABLED = _env_bool("SUSPICIOUS_ARCHIVE_SCAN_ENABLED", True)
SCANNER_MAX_DOWNLOAD_BYTES = _env_int("SCANNER_MAX_DOWNLOAD_BYTES", 2_000_000, min_value=0, max_value=20_000_000)
TRUSTED_FILE_HASH_WHITELIST_ENABLED = _env_bool("TRUSTED_FILE_HASH_WHITELIST_ENABLED", True)
TRUSTED_HASH_MAX_DOWNLOAD_BYTES = _env_int(
    "TRUSTED_HASH_MAX_DOWNLOAD_BYTES",
    max(SCANNER_MAX_DOWNLOAD_BYTES, 20_000_000),
    min_value=1,
    max_value=100_000_000,
)
MAX_TRUSTED_FILE_HASHES = _env_int("MAX_TRUSTED_FILE_HASHES", 128, min_value=1, max_value=1000)
MAX_ARCHIVE_MEMBERS_TO_SCAN = _env_int("MAX_ARCHIVE_MEMBERS_TO_SCAN", 500, min_value=1, max_value=5000)
MAX_CUSTOM_BLOCKED_EXTENSIONS = _env_int("MAX_CUSTOM_BLOCKED_EXTENSIONS", 64, min_value=1, max_value=256)
SCANNER_DOWNLOAD_CONCURRENCY = _env_int("SCANNER_DOWNLOAD_CONCURRENCY", 4, min_value=1, max_value=32)
ADMIN_ALERT_CONCURRENCY = _env_int("ADMIN_ALERT_CONCURRENCY", 20, min_value=1, max_value=64)
TELEGRAM_RETRY_AFTER_MAX_SECONDS = _env_float("TELEGRAM_RETRY_AFTER_MAX_SECONDS", 30.0, min_value=0.0)
RUNTIME_LOCK_PRUNE_LIMIT = _env_int("RUNTIME_LOCK_PRUNE_LIMIT", 10_000, min_value=100, max_value=250_000)
BOT_OWNER_IDS = tuple(
    int(x) for x in _env_csv("BOT_OWNER_IDS", [])
    if str(x).strip().lstrip("+-").isdigit()
)


# ─────────────────────────────────────────────────────────────
# TELEGRAM MINI APP / REST API CONFIG
# ─────────────────────────────────────────────────────────────
# The Mini App API lets a future Telegram Web App manage the same features that
# currently exist behind inline buttons: profile, linked groups/channels,
# scanner settings, incidents, trusted hashes, risk lists, and developer views.
# Authentication uses Telegram WebApp initData, so the API can auto-login the
# current Telegram user without a password.
MINI_APP_API_ENABLED = _env_bool("MINI_APP_API_ENABLED", True)
_MINI_APP_API_PREFIX_RAW = _env_str("MINI_APP_API_PREFIX", "/api").strip()
MINI_APP_API_PREFIX = "/" + _MINI_APP_API_PREFIX_RAW.strip("/")
if MINI_APP_API_PREFIX == "/":
    MINI_APP_API_PREFIX = "/api"
MINI_APP_AUTH_MAX_AGE_SECONDS = _env_int(
    "MINI_APP_AUTH_MAX_AGE_SECONDS",
    24 * 60 * 60,
    min_value=60,
    max_value=30 * 24 * 60 * 60,
)
MINI_APP_CORS_ORIGINS = _env_csv("MINI_APP_CORS_ORIGINS", ["*"])
MINI_APP_REQUEST_BODY_LIMIT_BYTES = _env_int(
    "MINI_APP_REQUEST_BODY_LIMIT_BYTES",
    128_000,
    min_value=1024,
    max_value=2_000_000,
)
MINI_APP_LIVE_REFRESH_ALLOWED = _env_bool("MINI_APP_LIVE_REFRESH_ALLOWED", True)
MINI_APP_UVICORN_ACCESS_LOG = _env_bool("MINI_APP_UVICORN_ACCESS_LOG", False)
MINI_APP_WEBHOOK_SECRET_HEADER_ENABLED = _env_bool("MINI_APP_WEBHOOK_SECRET_HEADER_ENABLED", True)

# In-memory API/server diagnostics for the Telegram Mini App frontend.
# These logs are process-local, bounded, and intentionally do not persist to
# Redis/Supabase because they can contain operational metadata. Only bot owners
# can read them through /api/server/log.
SERVER_LOG_ENABLED = _env_bool("SERVER_LOG_ENABLED", True)
SERVER_LOG_MAX_ITEMS = _env_int("SERVER_LOG_MAX_ITEMS", 1000, min_value=100, max_value=20_000)
SERVER_LOG_CAPTURE_PYTHON_LOGS = _env_bool("SERVER_LOG_CAPTURE_PYTHON_LOGS", True)
SERVER_LOG_CAPTURE_INFO = _env_bool("SERVER_LOG_CAPTURE_INFO", True)
SERVER_LOG_CAPTURE_DEBUG = _env_bool("SERVER_LOG_CAPTURE_DEBUG", False)
SERVER_LOG_VALUE_MAX_CHARS = _env_int("SERVER_LOG_VALUE_MAX_CHARS", 800, min_value=80, max_value=5000)
SERVER_LOG_TRACEBACK_MAX_CHARS = _env_int("SERVER_LOG_TRACEBACK_MAX_CHARS", 2500, min_value=300, max_value=20_000)
SERVER_LOG_SLOW_API_MS = _env_int("SERVER_LOG_SLOW_API_MS", 1500, min_value=100, max_value=120_000)
# Optional standalone auth for /api/server/log. This lets a browser, Vercel
# dashboard, Postman, or curl read logs without Telegram Mini App initData.
# Keep this secret. Do not put it in public frontend code unless the page is
# private/protected by your own backend. Telegram owner initData auth still works
# when SERVER_LOG_ALLOW_TELEGRAM_OWNER_AUTH=true.
SERVER_LOG_API_KEY = _env_str("SERVER_LOG_API_KEY") or _env_str("SERVER_LOG_TOKEN")
SERVER_LOG_ALLOW_TELEGRAM_OWNER_AUTH = _env_bool("SERVER_LOG_ALLOW_TELEGRAM_OWNER_AUTH", True)
SERVER_LOG_AUTH_QUERY_ENABLED = _env_bool("SERVER_LOG_AUTH_QUERY_ENABLED", True)
SERVER_LOG_PUBLIC_ACCESS = _env_bool("SERVER_LOG_PUBLIC_ACCESS", False)

# ─────────────────────────────────────────────────────────────
# DEFAULT BOT MIDDLEWARE CONFIG
# ─────────────────────────────────────────────────────────────
# These values are built into the bot, so the middleware works immediately
# without adding anything to Render/.env. Environment variables with the same
# names can still override them when you want production-specific tuning.
#
# Recommended defaults:
# - enabled: keep middleware active by default
# - rate window: 10 seconds
# - max updates: 18 per user/window
# - slow update warning: 2.5 seconds
DEFAULT_MIDDLEWARE_CONFIG: dict[str, int | float | bool] = {
    "MIDDLEWARE_ENABLED": True,
    "MIDDLEWARE_LOG_UPDATES": True,
    "MIDDLEWARE_RATE_LIMIT_ENABLED": True,
    "MIDDLEWARE_RATE_LIMIT_WINDOW_SECONDS": 10.0,
    "MIDDLEWARE_RATE_LIMIT_MAX_UPDATES": 18,
    "MIDDLEWARE_MAX_TRACKED_USERS": 50_000,
    "MIDDLEWARE_SLOW_UPDATE_SECONDS": 2.5,
}

# ─────────────────────────────────────────────────────────────
# DEFAULT PROFESSIONAL UI CONFIG - v3
# ─────────────────────────────────────────────────────────────
# Built-in defaults make the bot look polished immediately after deployment.
# Environment variables can still override the release label/brand without
# requiring code edits.
PROFESSIONAL_UI_ENABLED = _env_bool("PROFESSIONAL_UI_ENABLED", True)
PROFESSIONAL_UI_VERSION = _env_str("PROFESSIONAL_UI_VERSION", "v3.2") or "v3.2"
PROFESSIONAL_BRAND_NAME = _env_str("PROFESSIONAL_BRAND_NAME", "EXE Remover Security Bot") or "EXE Remover Security Bot"

# Lightweight bot middleware controls. PTB has no Express-style middleware,
# so we register TypeHandler(Update, ...) in early/late handler groups below.
MIDDLEWARE_ENABLED = _env_bool(
    "MIDDLEWARE_ENABLED",
    bool(DEFAULT_MIDDLEWARE_CONFIG["MIDDLEWARE_ENABLED"]),
)
MIDDLEWARE_LOG_UPDATES = _env_bool(
    "MIDDLEWARE_LOG_UPDATES",
    bool(DEFAULT_MIDDLEWARE_CONFIG["MIDDLEWARE_LOG_UPDATES"]),
)
MIDDLEWARE_RATE_LIMIT_ENABLED = _env_bool(
    "MIDDLEWARE_RATE_LIMIT_ENABLED",
    bool(DEFAULT_MIDDLEWARE_CONFIG["MIDDLEWARE_RATE_LIMIT_ENABLED"]),
)
MIDDLEWARE_RATE_LIMIT_WINDOW_SECONDS = _env_float(
    "MIDDLEWARE_RATE_LIMIT_WINDOW_SECONDS",
    float(DEFAULT_MIDDLEWARE_CONFIG["MIDDLEWARE_RATE_LIMIT_WINDOW_SECONDS"]),
    min_value=1.0,
)
MIDDLEWARE_RATE_LIMIT_MAX_UPDATES = _env_int(
    "MIDDLEWARE_RATE_LIMIT_MAX_UPDATES",
    int(DEFAULT_MIDDLEWARE_CONFIG["MIDDLEWARE_RATE_LIMIT_MAX_UPDATES"]),
    min_value=1,
    max_value=500,
)
MIDDLEWARE_MAX_TRACKED_USERS = _env_int(
    "MIDDLEWARE_MAX_TRACKED_USERS",
    int(DEFAULT_MIDDLEWARE_CONFIG["MIDDLEWARE_MAX_TRACKED_USERS"]),
    min_value=100,
    max_value=500_000,
)
MIDDLEWARE_SLOW_UPDATE_SECONDS = _env_float(
    "MIDDLEWARE_SLOW_UPDATE_SECONDS",
    float(DEFAULT_MIDDLEWARE_CONFIG["MIDDLEWARE_SLOW_UPDATE_SECONDS"]),
    min_value=0.1,
)
MIDDLEWARE_RATE_LIMIT_NOTICE_COOLDOWN_SECONDS = _env_float(
    "MIDDLEWARE_RATE_LIMIT_NOTICE_COOLDOWN_SECONDS",
    20.0,
    min_value=0.0,
)

ALLOWED_UPDATES = ["message", "callback_query", "my_chat_member"]
CHAT_TYPES_GROUP = {ChatType.GROUP, ChatType.SUPERGROUP, "group", "supergroup"}

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
)

# Keep production logs focused. Render keep-awake requests can generate noisy
# httpx/apscheduler INFO lines even when everything is healthy.
if QUIET_HTTPX_LOGS:
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
if QUIET_APSCHEDULER_LOGS:
    logging.getLogger("apscheduler.scheduler").setLevel(logging.WARNING)
    logging.getLogger("apscheduler.executors.default").setLevel(logging.WARNING)

logger = logging.getLogger("exe_remover_bot")

# ─────────────────────────────────────────────────────────────
# PROCESS-LOCAL STATE
# Keep asyncio locks/caches out of bot_data because PicklePersistence deep-copies
# bot_data and only copyable/pickleable objects should live there.
# ─────────────────────────────────────────────────────────────

T = TypeVar("T")

BOT_DATA_LOCK = asyncio.Lock()
REDIS_SAVE_LOCK = asyncio.Lock()
ADMIN_CACHE_LOCK = asyncio.Lock()
BOT_MEMBER_CACHE_LOCK = asyncio.Lock()
INCIDENT_LOCKS_LOCK = asyncio.Lock()

BOT_ID: int | None = None
BOT_USERNAME: str | None = None

# chat_id -> cache item
ADMIN_IDS_CACHE: dict[int, "CacheItem[list[int]]"] = {}
BOT_MEMBER_CACHE: dict[int, "CacheItem[BotPerms]"] = {}
INCIDENT_LOCKS: dict[str, asyncio.Lock] = {}
SCAN_DOWNLOAD_SEMAPHORE = asyncio.Semaphore(SCANNER_DOWNLOAD_CONCURRENCY)
KEEP_AWAKE_CLIENT: httpx.AsyncClient | None = None
REDIS_CLIENT: Any | None = None
REDIS_AVAILABLE = False
REDIS_LAST_SAVE_MONOTONIC = 0.0
REDIS_LAST_SAVE_UTC = "never"
SUPABASE_CLIENT: httpx.AsyncClient | None = None
SUPABASE_AVAILABLE = False
SUPABASE_LAST_SAVE_MONOTONIC = 0.0
SUPABASE_LAST_SAVE_UTC = "never"
PENDING_MEMORY_SAVE_TASKS: set[asyncio.Task[Any]] = set()
PENDING_MEMORY_SAVE_LOCK = asyncio.Lock()
PENDING_MEMORY_SAVE_PAYLOAD: dict[str, Any] | None = None
PENDING_MEMORY_SAVE_REASON = "manual"
PENDING_MEMORY_SAVE_FORCE = False
PENDING_MEMORY_SAVE_DEBOUNCE_TASK: asyncio.Task[Any] | None = None
GROUPS_PANEL_PAGE_SIZE = _env_int("GROUPS_PANEL_PAGE_SIZE", 8, min_value=5, max_value=10)
DESTRUCTIVE_CONFIRM_ACTIONS = {"clear", "clear_incidents", "clear_admin_logs"}

# Process-local server/API diagnostics ring buffer. It powers /api/server/log.
SERVER_STARTED_MONOTONIC = time.monotonic()
SERVER_STARTED_AT_UTC = datetime.now(timezone.utc).isoformat()
SERVER_LOGS: deque[dict[str, Any]] = deque(maxlen=SERVER_LOG_MAX_ITEMS)
SERVER_LOG_LOCK = threading.RLock()
SERVER_LOG_SEQUENCE = 0
SERVER_LOG_REQUEST_TOTAL = 0
SERVER_LOG_ERROR_TOTAL = 0
SERVER_LOG_LAST_ERROR_UTC = ""

# Process-local middleware metrics. Do not put these in bot_data, because
# bot_data is persisted/deep-copied and high-churn counters cause needless I/O.
MIDDLEWARE_RATE_BUCKETS: dict[int, list[float]] = {}
MIDDLEWARE_RATE_LIMIT_NOTICES: dict[int, float] = {}
MIDDLEWARE_UPDATE_STARTS: dict[int, float] = {}
MIDDLEWARE_HANDLED_UPDATES = 0
MIDDLEWARE_DROPPED_UPDATES = 0
MIDDLEWARE_LAST_PRUNE_MONOTONIC = 0.0


@dataclass(slots=True)
class CacheItem(Generic[T]):
    value: T
    expires_at: float


@dataclass(frozen=True, slots=True)
class BotPerms:
    status: str
    can_delete_messages: bool
    can_restrict_members: bool


@dataclass(frozen=True, slots=True)
class FileScanResult:
    blocked: bool
    reason_code: str
    reason_display: str
    details: tuple[str, ...]
    file_name: str
    mime_type: str
    matched_extension: str = ""
    file_sha256: str = ""


@dataclass(frozen=True, slots=True)
class SendMessageResult:
    ok: bool
    message_id: int | None = None
    error: str = ""
    error_type: str = ""
    permission_error: bool = False
    retryable: bool = False


# ─────────────────────────────────────────────────────────────
# PROCESS-LOCAL SERVER LOGS FOR /api/server/log
# ─────────────────────────────────────────────────────────────

def _server_log_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _server_log_safe_text(value: Any, *, max_chars: int | None = None) -> str:
    """Return compact, safe log text without auth secrets or huge payloads."""
    limit = max(20, int(max_chars or SERVER_LOG_VALUE_MAX_CHARS))
    try:
        text = str(value)
    except Exception:
        text = repr(value)

    # Never expose Telegram initData/hash-like secrets in the API log panel.
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
    if len(text) > limit:
        return text[: max(0, limit - 1)] + "…"
    return text


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
    """Append a bounded structured event used by /api/server/log."""
    global SERVER_LOG_SEQUENCE, SERVER_LOG_ERROR_TOTAL, SERVER_LOG_LAST_ERROR_UTC
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
        if value is None:
            continue
        record[_server_log_safe_text(key, max_chars=80)] = _server_log_safe_value(value)

    with SERVER_LOG_LOCK:
        SERVER_LOG_SEQUENCE += 1
        record["id"] = SERVER_LOG_SEQUENCE
        SERVER_LOGS.appendleft(record)
        if level_clean in {"error", "critical"} or category_clean.endswith("error"):
            SERVER_LOG_ERROR_TOTAL += 1
            SERVER_LOG_LAST_ERROR_UTC = now_iso


def server_log_snapshot(*, limit: int = 200, level: str = "all", category: str = "all", since_id: int = 0) -> list[dict[str, Any]]:
    level_filter = str(level or "all").strip().casefold()
    category_filter = str(category or "all").strip().casefold()
    max_rows = max(1, min(int(limit or 200), min(SERVER_LOG_MAX_ITEMS, 1000)))
    with SERVER_LOG_LOCK:
        rows = [dict(item) for item in SERVER_LOGS]
    filtered: list[dict[str, Any]] = []
    for row in rows:
        if since_id and int(row.get("id") or 0) <= since_id:
            continue
        if level_filter not in {"", "all", "*"} and str(row.get("level") or "").casefold() != level_filter:
            continue
        if category_filter not in {"", "all", "*"} and str(row.get("category") or "").casefold() != category_filter:
            continue
        filtered.append(row)
        if len(filtered) >= max_rows:
            break
    return filtered


def clear_server_logs() -> None:
    with SERVER_LOG_LOCK:
        SERVER_LOGS.clear()


def server_log_counters() -> dict[str, Any]:
    with SERVER_LOG_LOCK:
        latest_id = SERVER_LOG_SEQUENCE
        buffered = len(SERVER_LOGS)
    return {
        "enabled": SERVER_LOG_ENABLED,
        "buffered": buffered,
        "max_items": SERVER_LOG_MAX_ITEMS,
        "latest_id": latest_id,
        "request_total": SERVER_LOG_REQUEST_TOTAL,
        "error_total": SERVER_LOG_ERROR_TOTAL,
        "last_error_at": SERVER_LOG_LAST_ERROR_UTC,
    }


def process_status_snapshot() -> dict[str, Any]:
    uptime_seconds = max(0.0, time.monotonic() - SERVER_STARTED_MONOTONIC)
    memory_kb: int | None = None
    try:
        import resource  # Unix/Render friendly; optional on non-Unix runtimes.

        memory_kb = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except Exception:
        memory_kb = None

    task_count: int | None = None
    try:
        task_count = len(asyncio.all_tasks())
    except RuntimeError:
        task_count = None

    return {
        "pid": os.getpid(),
        "started_at": SERVER_STARTED_AT_UTC,
        "uptime_seconds": round(uptime_seconds, 3),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "memory_kb": memory_kb,
        "active_asyncio_tasks": task_count,
        "storage_backend": storage_backend_label() if "storage_backend_label" in globals() else "unknown",
        "redis": "connected" if REDIS_AVAILABLE else ("configured_offline" if REDIS_ENABLED else "disabled"),
        "supabase": "connected" if SUPABASE_AVAILABLE else ("configured_offline" if SUPABASE_ENABLED else "disabled"),
    }


class InMemoryServerLogHandler(logging.Handler):
    """Capture Python logger output into the in-memory server log panel."""

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

            fields: dict[str, Any] = {
                "logger": record.name,
                "module": record.module,
                "line": record.lineno,
            }
            if record.exc_info:
                tb_text = "".join(traceback.format_exception(*record.exc_info))
                fields["traceback"] = _server_log_safe_text(tb_text, max_chars=SERVER_LOG_TRACEBACK_MAX_CHARS)
            server_log_event("python_log", level_name, record.getMessage(), **fields)
        except Exception:
            # Logging handlers must never crash the bot/API process.
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
        "process",
        "info",
        "server log capture initialized",
        max_items=SERVER_LOG_MAX_ITEMS,
        capture_info=SERVER_LOG_CAPTURE_INFO,
        capture_debug=SERVER_LOG_CAPTURE_DEBUG,
    )


install_server_log_handler()


# ─────────────────────────────────────────────────────────────
# TRANSLATIONS - HTML parse mode, not Markdown
# ─────────────────────────────────────────────────────────────

TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "select_lang": "🌐 Please choose your preferred language / សូមជ្រើសរើសភាសារបស់អ្នក៖",
        "lang_set": "✅ Got it! I’ll communicate with you in <b>English</b> from now on.",
        "welcome": (
            "👋 <b>Hey there! I’m the EXE Remover Bot.</b>\n\n"
            "🛡️ I keep your groups safe by instantly deleting dangerous <code>.exe</code> files.\n"
            "📢 If someone sends a blocked file, I’ll alert the admins with quick options to <b>Ban</b>, <b>Warn</b>, or <b>Ignore</b>.\n\n"
            "➡️ Add me to your group and grant me <b>Delete Messages</b> permission to get started."
        ),
        "add_btn": "➕ Add Me to a Group",
        "check_btn": "🔄 Check My Permissions",
        "private_start": "Please open a private chat with me to choose your language and manage settings.",
        "no_group": "⚠️ I haven't detected your group yet. Add me to a group first, then click <b>Check My Permissions</b>.",
        "not_admin": (
            "❌ <b>I’m not an admin in your group yet.</b>\n\n"
            "Tap <b>➕ Add Bot as Admin</b> below, or go to Group Settings → Administrators → Add Member → select me, and enable <b>Delete Messages</b>."
        ),
        "no_delete_perm": (
            "⚠️ <b>I’m an admin, but I don't have permission to delete messages.</b>\n\n"
            "Tap <b>➕ Add Bot as Admin</b> below again, or enable <b>Delete Messages</b> permission for me manually."
        ),
        "setup_ok": (
            "🎉 <b>Awesome! I’m ready.</b>\n\n"
            "I’m now guarding <b>{group}</b>. If a blocked file appears, I’ll delete it and alert the admins. 🛡️"
        ),
        "exe_removed_group": (
            "🚫 <b>Blocked file removed.</b> {user}\n"
            "🧪 <b>Reason:</b> {reason}\n"
            "For everyone's safety, executable files are not allowed here."
        ),
        "admin_alert": (
            "🚨 <b>Security Alert: File Caught &amp; Deleted</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "👤 <b>Sender:</b> {sender_name} <code>{sender_id}</code>\n"
            "📄 <b>File Name:</b> <code>{file_name}</code>\n"
            "🧪 <b>Reason:</b> {scan_result}\n"
            "💬 <b>Group:</b> {group_name} <code>{group_id}</code>\n"
            "📅 <b>Time:</b> {time} UTC\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "What action would you like to take?"
        ),
        "btn_ban": "🔨 Ban User",
        "btn_warn": "⚠️ Warn User",
        "btn_ignore": "✅ Ignore",
        "action_ban_ok": "🔨 <b>Action taken:</b> {name} has been banned and removed from the group.",
        "action_ban_fail": "❌ I couldn’t ban the user. Please make sure I have the <b>Ban Users</b> permission.",
        "action_warn_ok": "⚠️ <b>Action taken:</b> I sent a formal warning to {name} in the group.",
        "action_warn_fail": "❌ I couldn’t send the warning message in the group.",
        "action_ignore_ok": "✅ <b>Action taken:</b> This incident has been ignored.",
        "action_done": "<i>Another admin has already handled this incident.</i>",
        "action_expired": "<i>This incident has expired or no longer exists.</i>",
        "action_not_admin": "❌ You are no longer an admin in that group, so this action was rejected.",
        "handled_by": "👮 <b>Handled by:</b> {admin}",
        "delete_failed": "❌ I detected a blocked file, but I couldn't delete it. Please ensure I have <b>Delete Messages</b> permission.",
        "warn_in_group": (
            "⚠️ <b>Official Warning</b> — {user}\n"
            "Sending executable files is strictly prohibited in this group. Please do not send them again."
        ),
        "help": (
            "💡 <b>EXE Remover Bot — Quick Guide</b>\n\n"
            "/start — Choose language and settings\n"
            "/help — Show this help message\n"
            "/status — Check bot permissions inside a group\n"
            "/admins — See group admins and alert readiness\n"
            "/scanner — Show scanner settings\n"
            "/scanname &lt;filename&gt; — Test if a filename is safe\n"
            "/memory — Show system memory status"
        ),
        "status_ok": "✅ Everything is running smoothly. I can delete blocked files and alert admins.",
        "status_no": "❌ I’m inactive here. Make sure I am an admin and have <b>Delete Messages</b> permission.",
        "status_error": "❌ Permission check failed: <code>{error}</code>",
        "admins_header": "👮 <b>Group Admin Alert Status</b>\n",
        "admins_enabled": "✅ Alerts enabled",
        "admins_need_start": "⚠️ Needs /start in private chat",
        "admins_note": "\n<i>Only admins who have privately started the bot can receive direct message alerts.</i>",
        "group_only": "Please send this command inside a group.",
        "scanner_status": (
            "🧪 <b>Suspicious File Scanner</b>\n"
            "Enabled: <code>{enabled}</code>\n"
            "Magic/header scan: <code>{magic}</code>\n"
            "Archive-name scan: <code>{archive}</code>\n"
            "Max download scan: <code>{max_bytes}</code> bytes\n"
            "Blocked extensions: <code>{blocked}</code>\n"
            "Dangerous extensions: <code>{dangerous}</code>\n"
            "Archive extensions: <code>{archives}</code>\n"
            "Trusted hash whitelist: <code>{hash_whitelist}</code>"
        ),
        "scanname_usage": "Usage: <code>/scanname invoice.pdf.exe</code>",
        "scanname_blocked": "🚫 <b>Blocked:</b> <code>{file}</code>\n🧪 <b>Reason:</b> {reason}",
        "scanname_clean": "✅ <b>No filename danger found:</b> <code>{file}</code>",
        "memory_status": (
            "🧠 <b>Bot Memory Status</b>\n"
            "Backend: <code>{backend}</code>\n"
            "Supabase: <code>{supabase}</code>\n"
            "Redis: <code>{redis}</code>\n"
            "Known users: <code>{users}</code>\n"
            "Saved groups: <code>{groups}</code>\n"
            "Open incidents: <code>{incidents}</code>\n"
            "Last Supabase save: <code>{supabase_last_save}</code>\n"
            "Last Redis save: <code>{redis_last_save}</code>"
        ),
        "unknown_error": "Something went wrong. Please try again.",
        "silent_notice_auto_delete": "\n<i>This notice will auto-delete shortly.</i>",
    },
    "km": {
        "select_lang": "🌐 Please choose your preferred language / សូមជ្រើសរើសភាសារបស់អ្នក៖",
        "lang_set": "✅ យល់ព្រម! ខ្ញុំនឹងទាក់ទងជាមួយអ្នកជា <b>ភាសាខ្មែរ</b> ចាប់ពីពេលនេះតទៅ។",
        "welcome": (
            "👋 <b>សួស្ដី! ខ្ញុំគឺ EXE Remover Bot។</b>\n\n"
            "🛡️ ខ្ញុំជួយការពារក្រុមរបស់អ្នក ដោយលុបចោលឯកសារ <code>.exe</code> ដែលមានហានិភ័យភ្លាមៗ។\n"
            "📢 ពេលមានអ្នកផ្ញើឯកសារប្រភេទនេះ ខ្ញុំនឹងជូនដំណឹងទៅកាន់ Admin ជាមួយជម្រើសរហ័ស៖ <b>Ban (បិទគណនី)</b>, <b>Warn (ព្រមាន)</b>, ឬ <b>Ignore (រំលង)</b>។\n\n"
            "➡️ សូមបន្ថែមខ្ញុំចូលទៅក្នុងក្រុមរបស់អ្នក ហើយផ្តល់សិទ្ធិ <b>Delete Messages (លុបសារ)</b> ដើម្បីចាប់ផ្ដើម។"
        ),
        "add_btn": "➕ បន្ថែមខ្ញុំទៅក្នុងក្រុម",
        "check_btn": "🔄 ពិនិត្យមើលសិទ្ធិរបស់ខ្ញុំ",
        "private_start": "សូមបើកសារឯកជន (Private Chat) ជាមួយខ្ញុំ ដើម្បីជ្រើសរើសភាសា និងរៀបចំការកំណត់ផ្សេងៗ។",
        "no_group": "⚠️ ខ្ញុំមិនទាន់រកឃើញក្រុមរបស់អ្នកទេ។ សូមបន្ថែមខ្ញុំចូលក្រុមជាមុនសិន រួចចុច <b>ពិនិត្យមើលសិទ្ធិរបស់ខ្ញុំ</b>។",
        "not_admin": (
            "❌ <b>ខ្ញុំមិនទាន់មានសិទ្ធិជា Admin នៅក្នុងក្រុមរបស់អ្នកនៅឡើយទេ។</b>\n\n"
            "ចុចប៊ូតុង <b>➕ ដាក់ Bot ជា Admin</b> ខាងក្រោម ឬចូលទៅកាន់ Group Settings → Administrators → Add Member → ជ្រើសរើសឈ្មោះខ្ញុំ រួចបើកសិទ្ធិ <b>Delete Messages</b>។"
        ),
        "no_delete_perm": (
            "⚠️ <b>ខ្ញុំជា Admin ប៉ុន្តែមិនទាន់មានសិទ្ធិលុបសារនៅឡើយទេ។</b>\n\n"
            "ចុចប៊ូតុង <b>➕ ដាក់ Bot ជា Admin</b> ខាងក្រោមម្តងទៀត ឬបើកសិទ្ធិ <b>Delete Messages</b> ឱ្យខ្ញុំដោយដៃ។"
        ),
        "setup_ok": (
            "🎉 <b>អស្ចារ្យណាស់! ខ្ញុំរួចរាល់ហើយ។</b>\n\n"
            "ឥឡូវនេះខ្ញុំកំពុងការពារក្រុម <b>{group}</b>។ ប្រសិនបើមានអ្នកផ្ញើឯកសារហាមឃាត់ ខ្ញុំនឹងលុបវាចោល ហើយរាយការណ៍ជូន Admin ភ្លាមៗ។ 🛡️"
        ),
        "exe_removed_group": (
            "🚫 <b>ឯកសារហាមឃាត់ត្រូវបានលុបចេញ។</b> {user}\n"
            "🧪 <b>មូលហេតុ៖</b> {reason}\n"
            "ដើម្បីសុវត្ថិភាពទាំងអស់គ្នា ឯកសារដែលអាចដំណើរការបាន (Executable Files) មិនត្រូវបានអនុញ្ញាតក្នុងក្រុមនេះទេ។"
        ),
        "admin_alert": (
            "🚨 <b>ការជូនដំណឹងសុវត្ថិភាព៖ រកឃើញ និងលុបឯកសារហាមឃាត់</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "👤 <b>អ្នកផ្ញើ៖</b> {sender_name} <code>{sender_id}</code>\n"
            "📄 <b>ឈ្មោះឯកសារ៖</b> <code>{file_name}</code>\n"
            "🧪 <b>មូលហេតុ៖</b> {scan_result}\n"
            "💬 <b>ក្រុម៖</b> {group_name} <code>{group_id}</code>\n"
            "📅 <b>ម៉ោង៖</b> {time} UTC\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "តើ Admin ចង់ចាត់វិធានការយ៉ាងណាដែរ?"
        ),
        "btn_ban": "🔨 Ban អ្នកប្រើប្រាស់",
        "btn_warn": "⚠️ ព្រមានអ្នកប្រើប្រាស់",
        "btn_ignore": "✅ រំលង",
        "action_ban_ok": "🔨 <b>ចំណាត់ការ៖</b> បាន Ban និងបណ្ដេញ {name} ចេញពីក្រុមរួចរាល់។",
        "action_ban_fail": "❌ ខ្ញុំមិនអាច Ban គាត់បានទេ។ សូមពិនិត្យមើលថាតើខ្ញុំមានសិទ្ធិ <b>Ban Users</b> ដែរឬទេ។",
        "action_warn_ok": "⚠️ <b>ចំណាត់ការ៖</b> ខ្ញុំបានផ្ញើសារព្រមានទៅកាន់ {name} នៅក្នុងក្រុមរួចរាល់។",
        "action_warn_fail": "❌ ខ្ញុំមិនអាចផ្ញើសារព្រមានចូលទៅក្នុងក្រុមបានទេ។",
        "action_ignore_ok": "✅ <b>ចំណាត់ការ៖</b> ករណីនេះត្រូវបានរំលង។",
        "action_done": "<i>Admin ផ្សេងទៀតបានចាត់ការករណីនេះរួចរាល់ហើយ។</i>",
        "action_expired": "<i>ករណីនេះផុតកំណត់ ឬលែងមានសុពលភាពហើយ។</i>",
        "action_not_admin": "❌ អ្នកលែងជា Admin នៅក្នុងក្រុមនោះទៀតហើយ ដូច្នេះចំណាត់ការនេះត្រូវបានបដិសេធ។",
        "handled_by": "👮 <b>ចាត់ការដោយ៖</b> {admin}",
        "delete_failed": "❌ ខ្ញុំបានរកឃើញឯកសារហាមឃាត់ ប៉ុន្តែមិនអាចលុបវាបានទេ។ សូមជួយផ្តល់សិទ្ធិ <b>Delete Messages</b> ឱ្យខ្ញុំ។",
        "warn_in_group": (
            "⚠️ <b>ការព្រមានជាផ្លូវការ</b> — {user}\n"
            "ការផ្ញើឯកសារដែលអាចដំណើរការបាន (Executable Files) ត្រូវបានហាមឃាត់យ៉ាងតឹងរ៉ឹងក្នុងក្រុមនេះ។ សូមកុំផ្ញើវាម្តងទៀត។"
        ),
        "help": (
            "💡 <b>EXE Remover Bot — មគ្គុទ្ទេសក៍ណែនាំរហ័ស</b>\n\n"
            "/start — ជ្រើសរើសភាសា និងការកំណត់នានា\n"
            "/help — បង្ហាញសារជំនួយនេះ\n"
            "/status — ពិនិត្យសិទ្ធិរបស់ Bot នៅក្នុងក្រុម\n"
            "/admins — មើលបញ្ជី Admin និងស្ថានភាពទទួលសារជូនដំណឹង\n"
            "/scanner — មើលការកំណត់ប្រព័ន្ធស្កេន (Scanner)\n"
            "/scanname &lt;filename&gt; — តេស្តឈ្មោះឯកសារថាតើមានសុវត្ថិភាពឬទេ\n"
            "/memory — មើលស្ថានភាពផ្ទុកទិន្នន័យរបស់ប្រព័ន្ធ"
        ),
        "status_ok": "✅ ដំណើរការបានយ៉ាងល្អ។ ខ្ញុំអាចលុបឯកសារហាមឃាត់ និងរាយការណ៍ទៅ Admin បាន។",
        "status_no": "❌ ខ្ញុំមិនអាចដំណើរការនៅទីនេះបានទេ។ សូមប្រាកដថាខ្ញុំជា Admin និងមានសិទ្ធិ <b>Delete Messages</b>។",
        "status_error": "❌ ការពិនិត្យសិទ្ធិទទួលបានបរាជ័យ៖ <code>{error}</code>",
        "admins_header": "👮 <b>ស្ថានភាពទទួលការជូនដំណឹងរបស់ Admin</b>\n",
        "admins_enabled": "✅ បើកការជូនដំណឹង",
        "admins_need_start": "⚠️ ត្រូវចុច /start ក្នុង Private Chat សិន",
        "admins_note": "\n<i>មានតែ Admin ដែលបានចុច /start ជាមួយ Bot ក្នុងសារឯកជនប៉ុណ្ណោះ ទើបអាចទទួលបានសាររាយការណ៍។</i>",
        "group_only": "សូមប្រើប្រាស់ Command នេះនៅខាងក្នុងក្រុម។",
        "scanner_status": (
            "🧪 <b>ប្រព័ន្ធស្កេនឯកសារសង្ស័យ</b>\n"
            "បើកដំណើរការ៖ <code>{enabled}</code>\n"
            "ស្កេន Header (Magic)៖ <code>{magic}</code>\n"
            "ស្កេនឈ្មោះឯកសារក្នុង Archive៖ <code>{archive}</code>\n"
            "ទំហំ Download អតិបរមា៖ <code>{max_bytes}</code> bytes\n"
            "Extension ដែលហាមឃាត់៖ <code>{blocked}</code>\n"
            "Extension គ្រោះថ្នាក់៖ <code>{dangerous}</code>\n"
            "Extension ប្រភេទ Archive៖ <code>{archives}</code>\n"
            "បញ្ជី Hash ដែលទុកចិត្ត៖ <code>{hash_whitelist}</code>"
        ),
        "scanname_usage": "របៀបប្រើ៖ <code>/scanname invoice.pdf.exe</code>",
        "scanname_blocked": "🚫 <b>បានហាមឃាត់៖</b> <code>{file}</code>\n🧪 <b>មូលហេតុ៖</b> {reason}",
        "scanname_clean": "✅ <b>មិនមានហានិភ័យដោយសារឈ្មោះឯកសារទេ៖</b> <code>{file}</code>",
        "memory_status": (
            "🧠 <b>ស្ថានភាពទិន្នន័យ (Memory)</b>\n"
            "Backend: <code>{backend}</code>\n"
            "Supabase: <code>{supabase}</code>\n"
            "Redis: <code>{redis}</code>\n"
            "អ្នកប្រើប្រាស់ដែលបានស្គាល់: <code>{users}</code>\n"
            "ក្រុមដែលបានរក្សាទុក: <code>{groups}</code>\n"
            "ករណីដែលកំពុងបើក: <code>{incidents}</code>\n"
            "Supabase save ចុងក្រោយ: <code>{supabase_last_save}</code>\n"
            "Redis save ចុងក្រោយ: <code>{redis_last_save}</code>"
        ),
        "unknown_error": "មានបញ្ហាបច្ចេកទេស។ សូមព្យាយាមម្តងទៀត។",
        "silent_notice_auto_delete": "\n<i>សារជូនដំណឹងនេះនឹងលុបដោយស្វ័យប្រវត្តិក្នុងពេលបន្តិចទៀត។</i>",
    },
}

EXTRA_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "home_title": (
            "🛡️ <b>EXE Remover Bot</b>\n\n"
            "Status: <b>Online</b>\n"
            "Use the buttons below to navigate. You can always come back to Home if you get stuck."
        ),
        "btn_home": "🏠 Home",
        "btn_groups": "👥 My Groups",
        "btn_add_group": "➕ Add to Group",
        "btn_help": "💡 Help",
        "btn_refresh": "🔄 Refresh",
        "btn_settings": "⚙️ Settings",
        "btn_back": "⬅️ Back",
        "groups_title": "👥 <b>Your Linked Groups</b>\n\nChoose a group to check its permissions or change protection settings.",
        "groups_empty": (
            "⚠️ <b>No linked groups yet.</b>\n\n"
            "Add me to a group, or type <code>/settings</code> inside a group to securely link it to this dashboard."
        ),
        "group_card": (
            "💬 <b>{group}</b>\n"
            "Permission: {permission}\n"
            "Protection: {protection}\n"
            "Strictness: <code>{strictness}</code>\n"
            "Silent mode: <code>{silent}</code>"
        ),
        "settings_title": (
            "⚙️ <b>Group Settings</b>\n"
            "💬 <b>{group}</b> <code>{chat_id}</code>\n\n"
            "Protection: {protection}\n"
            "Strictness: <code>{strictness}</code>\n"
            "Silent mode: <code>{silent}</code>\n"
            "Allowed extensions: <code>{allowed}</code>\n"
            "Custom delete formats: <code>{custom_blocked}</code>\n\n"
            "Standard mode blocks <code>.exe</code> and renamed executables. High mode blocks all dangerous extensions."
        ),
        "settings_saved": "✅ Settings updated successfully.",
        "group_linked": "✅ Group successfully linked to your private dashboard.",
        "group_admin_only": "❌ Only group admins can access this dashboard.",
        "group_no_access": "⚠️ <b>I cannot access this group right now.</b> I might have been removed or lost my permissions. Please add me back as an admin, enable <b>Delete Messages</b>, and tap Refresh.",
        "group_relinked": "✅ Group access restored. Permissions have been refreshed.",
        "access_denied": "❌ <b>Access denied.</b> This command is available only to bot owners or verified group admins.",
        "settings_group_open_private": "🔒 Configuration can only be done in private. Open our private chat to manage this group:",
        "config_private_only": "🔒 Configuration updates are restricted to private chats. I will not display or edit settings inside a public group.",
        "protection_on": "ON",
        "protection_off": "OFF",
        "silent_on": "True",
        "silent_off": "False",
        "strict_standard": "Standard",
        "strict_high": "High",
        "perm_ok": "✅ Delete OK",
        "perm_no": "❌ Needs Delete Messages",
        "perm_unknown": "⚠️ Unknown",
        "btn_manage_formats": "🧩 Manage Delete Formats",
        "btn_add_format": "➕ Add Format",
        "btn_remove_format": "🗑 Delete Format",
        "btn_edit_formats": "✏️ Edit List",
        "btn_clear_formats": "🧹 Clear All",
        "formats_title": (
            "🧩 <b>Custom Delete Formats</b>\n"
            "💬 <b>{group}</b> <code>{chat_id}</code>\n\n"
            "Current custom formats: <code>{custom_blocked}</code>\n\n"
            "Files ending with these extensions will be deleted in this group. Example: <code>.apk</code>, <code>.zip</code>, <code>.pdf</code>."
        ),
        "formats_empty": "No custom delete formats are set yet.",
        "formats_prompt_add": (
            "➕ <b>Add Delete Formats</b>\n\n"
            "Send extension names separated by spaces or commas.\n"
            "Example: <code>.apk .zip .pdf</code>\n\n"
            "Tap <b>Back</b> or <b>Home</b> to cancel."
        ),
        "formats_prompt_edit": (
            "✏️ <b>Edit Delete Format List</b>\n\n"
            "Send the complete new list. The old custom formats will be replaced.\n"
            "Example: <code>.apk .zip .pdf</code>\n\n"
            "Tap <b>Back</b> or <b>Home</b> to cancel."
        ),
        "formats_saved": "✅ Delete format list updated.",
        "formats_removed": "✅ Removed <code>{ext}</code> from delete formats.",
        "formats_cleared": "✅ Custom delete formats cleared.",
        "formats_invalid": "❌ I couldn't find a valid extension. Please send it like this: <code>.apk .zip .pdf</code>",
        "formats_cancelled": "✅ Action cancelled.",
        "scanner_group_status": (
            "\n\n⚙️ <b>This Group</b>\n"
            "Protection: <code>{protection}</code>\n"
            "Strictness: <code>{strictness}</code>\n"
            "Silent mode: <code>{silent}</code>\n"
            "Allowed extensions: <code>{allowed}</code>\n"
            "Custom delete formats: <code>{custom_blocked}</code>"
        ),
        "scanner_private_manage_hint": "Use the button below to safely manage delete formats in our private chat.",
        "scanner_group_private_only": "🔒 Scanner configuration is restricted to private chats. Open our private chat to view or update this group's delete formats and protection settings.",
    },
    "km": {
        "home_title": (
            "🛡️ <b>EXE Remover Bot</b>\n\n"
            "ស្ថានភាព៖ <b>Online</b>\n"
            "សូមប្រើប្រាស់ប៊ូតុងខាងក្រោម។ អ្នកអាចត្រឡប់មក Home វិញបានជានិច្ចប្រសិនបើមានបញ្ហា។"
        ),
        "btn_home": "🏠 Home (ទំព័រដើម)",
        "btn_groups": "👥 ក្រុមរបស់ខ្ញុំ",
        "btn_add_group": "➕ បន្ថែមទៅក្នុងក្រុម",
        "btn_help": "💡 ជំនួយ",
        "btn_refresh": "🔄 Refresh",
        "btn_settings": "⚙️ ការកំណត់",
        "btn_back": "⬅️ ត្រឡប់ក្រោយ",
        "groups_title": "👥 <b>ក្រុមដែលបានភ្ជាប់</b>\n\nសូមជ្រើសរើសក្រុមណាមួយ ដើម្បីពិនិត្យមើលសិទ្ធិ ឬកែប្រែការកំណត់សុវត្ថិភាព។",
        "groups_empty": (
            "⚠️ <b>មិនទាន់មានក្រុមដែលបានភ្ជាប់នៅឡើយទេ។</b>\n\n"
            "សូមបន្ថែមខ្ញុំទៅក្នុងក្រុម ឬវាយពាក្យ <code>/settings</code> នៅក្នុងក្រុមរបស់អ្នក ដើម្បីភ្ជាប់មកកាន់ផ្ទាំងគ្រប់គ្រង (Dashboard) នេះ។"
        ),
        "group_card": (
            "💬 <b>{group}</b>\n"
            "សិទ្ធិ៖ {permission}\n"
            "ការការពារ៖ {protection}\n"
            "កម្រិតតឹងរ៉ឹង៖ <code>{strictness}</code>\n"
            "មុខងារស្ងាត់ (Silent)៖ <code>{silent}</code>"
        ),
        "settings_title": (
            "⚙️ <b>ការកំណត់ក្រុម (Group Settings)</b>\n"
            "💬 <b>{group}</b> <code>{chat_id}</code>\n\n"
            "ការការពារ៖ {protection}\n"
            "កម្រិតតឹងរ៉ឹង៖ <code>{strictness}</code>\n"
            "មុខងារស្ងាត់ (Silent)៖ <code>{silent}</code>\n"
            "Extension ដែលអនុញ្ញាត៖ <code>{allowed}</code>\n"
            "Format ដែលត្រូវលុបបន្ថែម៖ <code>{custom_blocked}</code>\n\n"
            "Standard Mode លុបត្រឹម <code>.exe</code> និងឈ្មោះឯកសារដែលបន្លំ។ High Mode លុបរាល់ Extension ដែលមានហានិភ័យទាំងអស់។"
        ),
        "settings_saved": "✅ ការកំណត់ត្រូវបានកែប្រែដោយជោគជ័យ។",
        "group_linked": "✅ ក្រុមត្រូវបានភ្ជាប់មកកាន់ Dashboard ឯកជនរបស់អ្នករួចរាល់។",
        "group_admin_only": "❌ មានតែ Admin ក្រុមប៉ុណ្ណោះ ទើបអាចចូលមើល Dashboard នេះបាន។",
        "group_no_access": "⚠️ <b>ខ្ញុំមិនអាចដំណើរការក្នុងក្រុមនេះបានទេ។</b> ខ្ញុំប្រហែលជាត្រូវបានគេដកចេញ ឬដកសិទ្ធិ។ សូមបន្ថែមខ្ញុំជា Admin ឡើងវិញ ហើយបើកសិទ្ធិ <b>Delete Messages</b> បន្ទាប់មកចុច Refresh។",
        "group_relinked": "✅ ការភ្ជាប់ទៅកាន់ក្រុមត្រូវបានស្តារឡើងវិញ។ Permission ត្រូវបាន Refresh រួចរាល់។",
        "access_denied": "❌ <b>មិនមានសិទ្ធិ។</b> Command នេះអនុញ្ញាតសម្រាប់តែម្ចាស់ Bot ឬ Admin ក្រុមដែលបានបញ្ជាក់ត្រឹមត្រូវប៉ុណ្ណោះ។",
        "settings_group_open_private": "🔒 ការកំណត់អាចធ្វើបានតែក្នុង Private Chat ប៉ុណ្ណោះ។ សូមបើក Private Chat ដើម្បីគ្រប់គ្រងក្រុមនេះ៖",
        "config_private_only": "🔒 ការកែប្រែការកំណត់ត្រូវបានអនុញ្ញាតតែក្នុង Private Chat ប៉ុណ្ណោះ។ ខ្ញុំនឹងមិនបង្ហាញ ឬកែប្រែការកំណត់នៅខាងក្នុងក្រុមសាធារណៈឡើយ។",
        "protection_on": "បើក (ON)",
        "protection_off": "បិទ (OFF)",
        "silent_on": "ពិត (True)",
        "silent_off": "ទេ (False)",
        "strict_standard": "ធម្មតា (Standard)",
        "strict_high": "តឹងរ៉ឹង (High)",
        "perm_ok": "✅ អាចលុបបាន",
        "perm_no": "❌ ត្រូវការសិទ្ធិ Delete Messages",
        "perm_unknown": "⚠️ មិនច្បាស់លាស់",
        "btn_manage_formats": "🧩 គ្រប់គ្រង Format ត្រូវលុប",
        "btn_add_format": "➕ បន្ថែម Format",
        "btn_remove_format": "🗑 លុប Format",
        "btn_edit_formats": "✏️ កែប្រែបញ្ជី",
        "btn_clear_formats": "🧹 លុបចេញទាំងអស់",
        "formats_title": (
            "🧩 <b>គ្រប់គ្រងការលុបតាម Format (Custom Delete)</b>\n"
            "💬 <b>{group}</b> <code>{chat_id}</code>\n\n"
            "Format ដែលបានកំណត់បច្ចុប្បន្ន៖ <code>{custom_blocked}</code>\n\n"
            "រាល់ឯកសារដែលបញ្ចប់ដោយ Extension ទាំងនេះ នឹងត្រូវបានលុបចោលនៅក្នុងក្រុមនេះ។ ឧទាហរណ៍៖ <code>.apk</code>, <code>.zip</code>, <code>.pdf</code>។"
        ),
        "formats_empty": "មិនទាន់មាន Custom Delete Format នៅឡើយទេ។",
        "formats_prompt_add": (
            "➕ <b>បន្ថែម Delete Formats</b>\n\n"
            "សូមបញ្ចូល Extension ដោយដកឃ្លា ឬប្រើសញ្ញាក្បៀស (Comma)។\n"
            "ឧទាហរណ៍៖ <code>.apk .zip .pdf</code>\n\n"
            "ចុចប៊ូតុង <b>ត្រឡប់ក្រោយ</b> ឬ <b>Home</b> ដើម្បីបោះបង់។"
        ),
        "formats_prompt_edit": (
            "✏️ <b>កែប្រែបញ្ជី Delete Formats</b>\n\n"
            "សូមបញ្ជូនបញ្ជីថ្មីទាំងស្រុង។ បញ្ជីចាស់នឹងត្រូវបានជំនួស។\n"
            "ឧទាហរណ៍៖ <code>.apk .zip .pdf</code>\n\n"
            "ចុចប៊ូតុង <b>ត្រឡប់ក្រោយ</b> ឬ <b>Home</b> ដើម្បីបោះបង់។"
        ),
        "formats_saved": "✅ បញ្ជី Delete Formats ត្រូវបានធ្វើបច្ចុប្បន្នភាព។",
        "formats_removed": "✅ បានដក <code>{ext}</code> ចេញពីបញ្ជីដែលត្រូវលុប។",
        "formats_cleared": "✅ Custom Delete Formats ត្រូវបានលុបសម្អាត។",
        "formats_invalid": "❌ ខ្ញុំរកមិនឃើញ Extension ត្រឹមត្រូវទេ។ សូមសាកល្បងបញ្ចូលតាមគំរូនេះ៖ <code>.apk .zip .pdf</code>",
        "formats_cancelled": "✅ សកម្មភាពត្រូវបានបោះបង់។",
        "scanner_group_status": (
            "\n\n⚙️ <b>ក្រុមនេះ</b>\n"
            "ការការពារ៖ <code>{protection}</code>\n"
            "កម្រិតតឹងរ៉ឹង៖ <code>{strictness}</code>\n"
            "មុខងារស្ងាត់ (Silent)៖ <code>{silent}</code>\n"
            "Extension ដែលអនុញ្ញាត៖ <code>{allowed}</code>\n"
            "Format ត្រូវលុបបន្ថែម៖ <code>{custom_blocked}</code>"
        ),
        "scanner_private_manage_hint": "ប្រើប្រាស់ប៊ូតុងខាងក្រោម ដើម្បីគ្រប់គ្រង Delete Formats នៅក្នុង Private Chat ដោយសុវត្ថិភាព។",
        "scanner_group_private_only": "🔒 ការកំណត់ប្រព័ន្ធ Scanner អាចមើល និងកែប្រែបានតែក្នុង Private Chat ប៉ុណ្ណោះ។ សូមបើក Private Chat ដើម្បីកែប្រែ Delete Formats និងការកំណត់សុវត្ថិភាពរបស់ក្រុមនេះ។",
    },
}
for _lang, _items in EXTRA_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_items)

BUTTON_ONLY_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "home_title": (
            "🛡️ <b>EXE Remover Bot</b>\n\n"
            "Status: <b>Online</b>\n"
            "Use the buttons below to manage everything. No commands are needed."
        ),
        "help": (
            "💡 <b>How to use this bot</b>\n\n"
            "Use the buttons on the dashboard to add groups, check permissions, change protection settings, "
            "manage delete formats, and refresh status.\n\n"
            "Group admins can open settings from the private dashboard. Developers can open the developer dashboard "
            "to review users, groups, storage, and bot health."
        ),
        "btn_developer": "🧑‍💻 Developer Dashboard",
        "btn_dev_users": "👤 Bot Users",
        "btn_dev_groups": "💬 Bot Groups",
        "btn_dev_memory": "🧠 Memory / Storage",
        "btn_dev_hash_config": "🔐 Trusted Hash Config",
        "btn_hash_size": "📦 Max Hash File Size",
        "btn_hash_limit": "🔢 Max Hashes Per Group",
        "btn_hash_enable": "🟢 Enable Whitelist",
        "btn_hash_disable": "🔴 Disable Whitelist",
        "dev_hash_config_saved": "✅ Trusted hash config updated.",
        "dev_hash_config_title": (
            "🔐 <b>Trusted Hash Runtime Config</b>\n\n"
            "Enabled: <code>{enabled}</code>\n"
            "Max file hash download: <code>{max_bytes}</code> bytes (<code>{max_mb}</code>)\n"
            "Max trusted hashes per group: <code>{max_hashes}</code>\n\n"
            "Env defaults are still used on first boot, but these dashboard values override them and persist in Redis/Supabase."
        ),
        "dev_hash_size_title": "📦 <b>Choose max file size for trusted-hash uploads</b>\n\nCurrent: <code>{max_bytes}</code> bytes (<code>{max_mb}</code>)",
        "dev_hash_limit_title": "🔢 <b>Choose max trusted hashes per group</b>\n\nCurrent: <code>{max_hashes}</code>",
        "btn_next": "Next ➡️",
        "btn_prev": "⬅️ Prev",
        "dev_only": "❌ <b>Developer Dashboard locked.</b> Only bot developers listed in <code>BOT_OWNER_IDS</code> can open this panel. Group admins and normal users cannot access it.",
        "dev_only_alert": "Developer only. Group admins and normal users cannot access this dashboard.",
        "dev_title": (
            "🧑‍💻 <b>Developer Dashboard</b>\n\n"
            "Users: <code>{users}</code>\n"
            "Groups: <code>{groups}</code>\n"
            "Open incidents: <code>{incidents}</code>\n"
            "Feedback: <code>{feedback}</code>\n"
            "Admin cache: <code>{admin_cache}</code>\n"
            "Bot permission cache: <code>{bot_perm_cache}</code>\n"
            "Chat metadata cache: <code>{chat_meta}</code>\n"
            "Supabase: <code>{supabase}</code>\n"
            "Redis: <code>{redis}</code>\n"
            "Backend: <code>{backend}</code>"
        ),
        "dev_users_title": "👤 <b>Bot Users</b>\nPage <code>{page}</code>/<code>{pages}</code> · Total <code>{total}</code>\n\nTap a user to view details.",
        "dev_users_empty": "👤 <b>Bot Users</b>\n\nNo users are saved yet.",
        "dev_user_detail": (
            "👤 <b>User Detail</b>\n\n"
            "Name: <b>{name}</b>\n"
            "Username: <code>{username}</code>\n"
            "User ID: <code>{user_id}</code>\n"
            "Language: <code>{lang}</code>\n"
            "Groups linked: <code>{groups_count}</code>\n"
            "First seen: <code>{first_seen}</code>\n"
            "Last seen: <code>{last_seen}</code>"
        ),
        "dev_groups_title": "💬 <b>Bot Groups</b>\nTotal <code>{total}</code>\n\nTap a group to open settings.",
        "dev_groups_empty": "💬 <b>Bot Groups</b>\n\nNo groups are saved yet.",
        "dev_memory_title": (
            "🧠 <b>Memory / Storage</b>\n\n"
            "Backend: <code>{backend}</code>\n"
            "Supabase: <code>{supabase}</code>\n"
            "Redis: <code>{redis}</code>\n"
            "Known users: <code>{users}</code>\n"
            "Saved groups: <code>{groups}</code>\n"
            "Open incidents: <code>{incidents}</code>\n"
            "Last Supabase save: <code>{supabase_last_save}</code>\n"
            "Last Redis save: <code>{redis_last_save}</code>"
        ),
    },
    "km": {
        "home_title": (
            "🛡️ <b>EXE Remover Bot</b>\n\n"
            "ស្ថានភាព: <b>Online</b>\n"
            "សូមប្រើប៊ូតុងខាងក្រោមដើម្បីគ្រប់គ្រងមុខងារទាំងអស់ ដោយមិនចាំបាច់វាយ Command ឡើយ។"
        ),
        "help": (
            "💡 <b>របៀបប្រើប្រាស់ Bot នេះ</b>\n\n"
            "ប្រើប្រាស់ប៊ូតុងនៅលើ Dashboard ដើម្បីបន្ថែមក្រុម, ពិនិត្យសិទ្ធិ, កែប្រែការការពារ, "
            "គ្រប់គ្រង Delete Formats, និង Refresh ស្ថានភាព។\n\n"
            "Admin ក្រុមអាចបើក Settings ពី Private Dashboard។ ចំណែក Developer អាចបើក Developer Dashboard "
            "ដើម្បីត្រួតពិនិត្យអ្នកប្រើប្រាស់, ក្រុម, ទិន្នន័យ (Storage), និងស្ថានភាព Bot ទាំងមូល។"
        ),
        "btn_developer": "🧑‍💻 Developer Dashboard",
        "btn_dev_users": "👤 អ្នកប្រើប្រាស់ Bot",
        "btn_dev_groups": "💬 ក្រុមរបស់ Bot",
        "btn_dev_memory": "🧠 ស្ថានភាព Memory / Storage",
        "btn_dev_hash_config": "🔐 កំណត់ Trusted Hash",
        "btn_hash_size": "📦 ទំហំ File Hash អតិបរមា",
        "btn_hash_limit": "🔢 ចំនួន Hash អតិបរមាក្នុងមួយក្រុម",
        "btn_hash_enable": "🟢 បើក Whitelist",
        "btn_hash_disable": "🔴 បិទ Whitelist",
        "dev_hash_config_saved": "✅ បានកែប្រែ Trusted Hash Config រួចរាល់។",
        "dev_hash_config_title": (
            "🔐 <b>Trusted Hash Runtime Config</b>\n\n"
            "បើកដំណើរការ: <code>{enabled}</code>\n"
            "ទំហំ Download អតិបរមា: <code>{max_bytes}</code> bytes (<code>{max_mb}</code>)\n"
            "ចំនួន Trusted hashes អតិបរមា/ក្រុម: <code>{max_hashes}</code>\n\n"
            "Env defaults ប្រើពេល Boot ដំបូង ប៉ុន្តែតម្លៃក្នុង Dashboard នេះមានអាទិភាពជាង ហើយរក្សាទុកក្នុង Redis/Supabase។"
        ),
        "dev_hash_size_title": "📦 <b>ជ្រើសរើសទំហំ File អតិបរមា សម្រាប់ Trusted-hash upload</b>\n\nបច្ចុប្បន្ន: <code>{max_bytes}</code> bytes (<code>{max_mb}</code>)",
        "dev_hash_limit_title": "🔢 <b>ជ្រើសរើសចំនួន Trusted hashes អតិបរមា ក្នុងមួយក្រុម</b>\n\nបច្ចុប្បន្ន: <code>{max_hashes}</code>",
        "btn_next": "បន្ទាប់ ➡️",
        "btn_prev": "⬅️ ថយក្រោយ",
        "dev_only": "❌ <b>Developer Dashboard ត្រូវបាន Lock។</b> មានតែ Bot Developer ដែលបានកំណត់ក្នុង <code>BOT_OWNER_IDS</code> ប៉ុណ្ណោះអាចបើក Panel នេះបាន។ Admin ក្រុម និង User ធម្មតា មិនអាចចូលបានទេ។",
        "dev_only_alert": "សម្រាប់តែ Developer ប៉ុណ្ណោះ។ Admin ក្រុម និង User ធម្មតា មិនអាចចូល Dashboard នេះបានទេ។",
        "dev_title": (
            "🧑‍💻 <b>Developer Dashboard</b>\n\n"
            "អ្នកប្រើប្រាស់ (Users): <code>{users}</code>\n"
            "ក្រុម (Groups): <code>{groups}</code>\n"
            "ករណីកំពុងបើក (Incidents): <code>{incidents}</code>\n"
            "មតិកែលម្អ (Feedback): <code>{feedback}</code>\n"
            "Admin cache: <code>{admin_cache}</code>\n"
            "Bot permission cache: <code>{bot_perm_cache}</code>\n"
            "Chat metadata cache: <code>{chat_meta}</code>\n"
            "Supabase: <code>{supabase}</code>\n"
            "Redis: <code>{redis}</code>\n"
            "Backend: <code>{backend}</code>"
        ),
        "dev_users_title": "👤 <b>អ្នកប្រើប្រាស់ Bot</b>\nទំព័រ <code>{page}</code>/<code>{pages}</code> · សរុប <code>{total}</code>\n\nចុចលើឈ្មោះអ្នកប្រើប្រាស់ ដើម្បីមើលព័ត៌មានលម្អិត។",
        "dev_users_empty": "👤 <b>អ្នកប្រើប្រាស់ Bot</b>\n\nមិនទាន់មានអ្នកប្រើប្រាស់ដែលបានរក្សាទុកទេ។",
        "dev_user_detail": (
            "👤 <b>ព័ត៌មានលម្អិតអ្នកប្រើប្រាស់</b>\n\n"
            "ឈ្មោះ: <b>{name}</b>\n"
            "Username: <code>{username}</code>\n"
            "User ID: <code>{user_id}</code>\n"
            "ភាសា: <code>{lang}</code>\n"
            "ក្រុមដែលបានភ្ជាប់: <code>{groups_count}</code>\n"
            "First seen: <code>{first_seen}</code>\n"
            "Last seen: <code>{last_seen}</code>"
        ),
        "dev_groups_title": "💬 <b>ក្រុមរបស់ Bot</b>\nសរុប <code>{total}</code>\n\nចុចលើក្រុមណាមួយ ដើម្បីបើក Settings។",
        "dev_groups_empty": "💬 <b>ក្រុមរបស់ Bot</b>\n\nមិនទាន់មានក្រុមដែលបានរក្សាទុកទេ។",
        "dev_memory_title": (
            "🧠 <b>Memory / Storage</b>\n\n"
            "Backend: <code>{backend}</code>\n"
            "Supabase: <code>{supabase}</code>\n"
            "Redis: <code>{redis}</code>\n"
            "អ្នកប្រើប្រាស់ដែលបានស្គាល់: <code>{users}</code>\n"
            "ក្រុមដែលបានរក្សាទុក: <code>{groups}</code>\n"
            "ករណីដែលកំពុងបើក: <code>{incidents}</code>\n"
            "Supabase save ចុងក្រោយ: <code>{supabase_last_save}</code>\n"
            "Redis save ចុងក្រោយ: <code>{redis_last_save}</code>"
        ),
    },
}
for _lang, _items in BUTTON_ONLY_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_items)

GROUP_ADMIN_DASHBOARD_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "group_admin_title": "⚙️ <b>Group Admin Panel</b>\n💬 <b>{group}</b> <code>{chat_id}</code>\n\n🛡 Protection: <code>{protection}</code>\n🔥 Strictness: <code>{strictness}</code>\n🔇 Silent mode: <code>{silent}</code>\n🧩 Blocked formats: <code>{custom_blocked}</code>\n✅ Allowed formats: <code>{allowed}</code>\n🔐 Trusted hashes: <code>{trusted_hashes}</code>\n⚙️ Auto action: <code>{auto_action}</code>",
        "btn_protection_status": "🛡 Protection Status",
        "btn_scanner_settings": "🧪 Scanner Settings",
        "btn_incident_logs": "🚨 Incident Logs",
        "btn_member_risk": "👥 Member Risk List",
        "btn_admin_alert_status": "👮 Admin Alert Status",
        "btn_blocked_formats": "🧩 Blocked Formats",
        "btn_allowed_formats": "✅ Allowed Formats",
        "btn_silent_mode": "🔇 Silent Mode",
        "btn_strictness_level": "🔥 Strictness Level",
        "btn_group_health": "🩺 Group Health Check",
        "btn_auto_actions": "🤖 Auto Action Rules",
        "btn_trusted_hashes": "🔐 Trusted File Hashes",
        "btn_turn_on": "🟢 Turn ON",
        "btn_turn_off": "🔴 Turn OFF",
        "btn_clear_handled": "🧹 Clear Handled Logs",
        "protection_status_title": "🛡 <b>Protection Status</b>\n💬 <b>{group}</b>\n\nProtection: <code>{protection}</code>\nStrictness: <code>{strictness}</code>\nSilent mode: <code>{silent}</code>\nBot permission: <code>{bot_permission}</code>\nAuto action: <code>{auto_action}</code>",
        "scanner_panel_title": "🧪 <b>Scanner Settings</b>\n💬 <b>{group}</b>\n{scanner}",
        "incidents_title": "🚨 <b>Incident Logs</b>\n💬 <b>{group}</b>\nTotal: <code>{total}</code>\n\n{items}",
        "incidents_empty": "No incidents for this group yet.",
        "incidents_cleared": "✅ Handled incident logs cleared.",
        "member_risk_title": "👥 <b>Member Risk List</b>\n💬 <b>{group}</b>\n\n{items}",
        "member_risk_empty": "No risky members found yet.",
        "admin_alert_title": "👮 <b>Admin Alert Status</b>\n💬 <b>{group}</b>\nReady: <code>{ready}</code>/<code>{total}</code>\n\n{items}\n\n<i>Admins must open the bot privately once to receive alerts.</i>",
        "health_title": "🩺 <b>Group Health Check</b>\n💬 <b>{group}</b>\n\nBot is admin: {bot_admin}\nCan delete messages: {can_delete}\nCan restrict members: {can_restrict}\nProtection enabled: {protection}\nScanner enabled: {scanner}\nAdmin alerts ready: <code>{ready}</code>/<code>{total}</code>",
        "allowed_title": "✅ <b>Allowed Formats</b>\n💬 <b>{group}</b> <code>{chat_id}</code>\n\nCurrent allowed formats: <code>{allowed}</code>\n\nAllowed formats bypass custom blocked formats. Keep <code>.exe</code> blocked unless you fully trust the group.",
        "btn_add_allowed": "➕ Allow Format",
        "btn_edit_allowed": "✏️ Edit Allowed List",
        "btn_remove_allowed": "🗑 Remove Allowed Format",
        "btn_clear_allowed": "🧹 Clear Allowed List",
        "allowed_prompt_add": "✅ <b>Allow formats</b>\n\nSend extension names separated by spaces or commas.\nExample: <code>.zip .pdf</code>\n\nUse Home or Back to cancel.",
        "allowed_prompt_edit": "✏️ <b>Edit allowed list</b>\n\nSend the complete new allowed list.\nExample: <code>.zip .pdf</code>\n\nUse Home or Back to cancel.",
        "allowed_saved": "✅ Allowed format list updated.",
        "allowed_invalid": "❌ Hard-blocked executable formats cannot be added to Allowed Formats. Use Trusted File Hashes to approve one exact safe file instead.",
        "allowed_removed": "✅ Removed <code>{ext}</code> from allowed formats.",
        "allowed_cleared": "✅ Allowed formats cleared.",
        "auto_title": "🤖 <b>Auto Action Rules</b>\n💬 <b>{group}</b>\n\nMode: <code>{mode}</code>\nWarn threshold: <code>{warn_threshold}</code>\nMute threshold: <code>{mute_threshold}</code>\nBan threshold: <code>{ban_threshold}</code>\nMute length: <code>{mute_minutes} minutes</code>\n\nRecommended: <b>Smart</b> = warn first, mute repeat offenders, and ban persistent offenders.",
        "btn_auto_off": "⛔ Auto Action OFF",
        "btn_auto_warn": "⚠️ Warn Only",
        "btn_auto_smart": "🤖 Smart Warn → Mute → Ban",
        "btn_auto_ban": "🔨 Aggressive Auto Ban",
        "auto_saved": "✅ Auto action rule updated.",
        "trusted_hash_title": "🔐 <b>Trusted File Hash Whitelist</b>\n💬 <b>{group}</b> <code>{chat_id}</code>\n\nTrusted hashes: <code>{count}</code>/<code>{limit}</code>\n\n{items}\n\nSend a safe file or paste a SHA256 hash to approve that exact file. If the same file is sent later, the bot will allow it even when the filename ends in <code>.exe</code>.",
        "trusted_hash_empty": "No trusted hashes yet.",
        "btn_add_hash": "➕ Add Trusted File/Hash",
        "btn_remove_hash": "🗑 Remove Trusted Hash",
        "btn_clear_hashes": "🧹 Clear Trusted Hashes",
        "trusted_hash_prompt_add": "🔐 <b>Add Trusted File Hash</b>\n\nSend the safe file here in private chat, or paste a SHA256 hash.\n\n⚠️ Only approve files you personally trust. Use Home or Back to cancel.",
        "trusted_hash_saved": "✅ Trusted hash added.",
        "trusted_hash_removed": "✅ Trusted hash removed.",
        "trusted_hash_cleared": "✅ Trusted hash whitelist cleared.",
        "trusted_hash_invalid": "❌ Send a valid SHA256 hash, or upload a file smaller than the whitelist download limit.",
        "trusted_hash_limit": "❌ Trusted hash whitelist is full. Remove an old hash first.",
        "trusted_hash_file_too_large": "❌ File is too large to hash safely. Developer can increase the trusted-hash max file size from the Developer Dashboard.",
    },
    "km": {
        "group_admin_title": "⚙️ <b>Group Admin Panel</b>\n💬 <b>{group}</b> <code>{chat_id}</code>\n\n🛡 ការការពារ: <code>{protection}</code>\n🔥 កម្រិតតឹងរ៉ឹង: <code>{strictness}</code>\n🔇 មុខងារស្ងាត់: <code>{silent}</code>\n🧩 Format ដែលបាន Block: <code>{custom_blocked}</code>\n✅ Format ដែលអនុញ្ញាត: <code>{allowed}</code>\n🔐 Hash ដែលទុកចិត្ត: <code>{trusted_hashes}</code>\n⚙️ សកម្មភាពស្វ័យប្រវត្តិ: <code>{auto_action}</code>",
        "btn_protection_status": "🛡 ស្ថានភាពការពារ",
        "btn_scanner_settings": "🧪 ការកំណត់ Scanner",
        "btn_incident_logs": "🚨 ប្រវត្តិល្មើស (Incident)",
        "btn_member_risk": "👥 បញ្ជីសមាជិកមានហានិភ័យ",
        "btn_admin_alert_status": "👮 ស្ថានភាពសារជូនដំណឹង Admin",
        "btn_blocked_formats": "🧩 Blocked Formats",
        "btn_allowed_formats": "✅ Allowed Formats",
        "btn_silent_mode": "🔇 Silent Mode (ស្ងាត់)",
        "btn_strictness_level": "🔥 កម្រិតតឹងរ៉ឹង",
        "btn_group_health": "🩺 ពិនិត្យសុខភាពក្រុម",
        "btn_auto_actions": "🤖 Auto Action Rules",
        "btn_trusted_hashes": "🔐 Trusted File Hashes",
        "btn_turn_on": "🟢 បើក (ON)",
        "btn_turn_off": "🔴 បិទ (OFF)",
        "btn_clear_handled": "🧹 សម្អាត Logs ដែលបានចាត់ការហើយ",
        "protection_status_title": "🛡 <b>ស្ថានភាពការពារ</b>\n💬 <b>{group}</b>\n\nការការពារ: <code>{protection}</code>\nកម្រិតតឹងរ៉ឹង: <code>{strictness}</code>\nមុខងារស្ងាត់: <code>{silent}</code>\nសិទ្ធិរបស់ Bot: <code>{bot_permission}</code>\nសកម្មភាពស្វ័យប្រវត្តិ: <code>{auto_action}</code>",
        "scanner_panel_title": "🧪 <b>ការកំណត់ Scanner</b>\n💬 <b>{group}</b>\n{scanner}",
        "incidents_title": "🚨 <b>ប្រវត្តិល្មើស (Incident Logs)</b>\n💬 <b>{group}</b>\nសរុប: <code>{total}</code>\n\n{items}",
        "incidents_empty": "មិនទាន់មានប្រវត្តិល្មើសសម្រាប់ក្រុមនេះទេ។",
        "incidents_cleared": "✅ បានសម្អាត Incident Logs ដែលបានចាត់ការរួច។",
        "member_risk_title": "👥 <b>បញ្ជីសមាជិកមានហានិភ័យ</b>\n💬 <b>{group}</b>\n\n{items}",
        "member_risk_empty": "មិនទាន់មានសមាជិកដែលមានហានិភ័យទេ។",
        "admin_alert_title": "👮 <b>ស្ថានភាពសារជូនដំណឹង Admin</b>\n💬 <b>{group}</b>\nរួចរាល់: <code>{ready}</code>/<code>{total}</code>\n\n{items}\n\n<i>Admin ត្រូវចុច Start Bot ក្នុង Private Chat យ៉ាងហោចណាស់ម្ដង ដើម្បីទទួលបានសារជូនដំណឹង។</i>",
        "health_title": "🩺 <b>ពិនិត្យសុខភាពក្រុម</b>\n💬 <b>{group}</b>\n\nBot ជា Admin: {bot_admin}\nអាចលុបសារបាន: {can_delete}\nអាចកំណត់សិទ្ធិសមាជិកបាន (Restrict): {can_restrict}\nការការពារបានបើក: {protection}\nScanner បានបើក: {scanner}\nAdmin ត្រៀមទទួលសារជូនដំណឹង: <code>{ready}</code>/<code>{total}</code>",
        "allowed_title": "✅ <b>Format ដែលអនុញ្ញាត (Allowed Formats)</b>\n💬 <b>{group}</b> <code>{chat_id}</code>\n\nFormat ដែលអនុញ្ញាតបច្ចុប្បន្ន: <code>{allowed}</code>\n\nAllowed Formats អាចរំលង Blocked Formats របស់អ្នកបាន។ សូមកុំអនុញ្ញាត (Allow) <code>.exe</code> លើកលែងតែអ្នកទុកចិត្តក្រុមទាំងស្រុង។",
        "btn_add_allowed": "➕ បន្ថែម Allowed Format",
        "btn_edit_allowed": "✏️ កែប្រែបញ្ជី Allowed",
        "btn_remove_allowed": "🗑 លុប Allowed Format",
        "btn_clear_allowed": "🧹 សម្អាតបញ្ជី Allowed",
        "allowed_prompt_add": "✅ <b>បន្ថែម Allowed Formats</b>\n\nសូមបញ្ចូលឈ្មោះ Extension ដោយដកឃ្លា ឬប្រើសញ្ញាក្បៀស (Comma)។\nឧទាហរណ៍: <code>.zip .pdf</code>\n\nចុចប៊ូតុង Home ឬ Back ដើម្បីបោះបង់។",
        "allowed_prompt_edit": "✏️ <b>កែប្រែបញ្ជី Allowed Formats</b>\n\nសូមបញ្ចូលបញ្ជីថ្មីទាំងមូល។\nឧទាហរណ៍: <code>.zip .pdf</code>\n\nចុចប៊ូតុង Home ឬ Back ដើម្បីបោះបង់។",
        "allowed_saved": "✅ បញ្ជី Allowed Format ត្រូវបានកែប្រែដោយជោគជ័យ។",
        "allowed_invalid": "❌ មិនអាចបញ្ចូល Executable formats ដែលមានហានិភ័យខ្ពស់ ទៅក្នុង Allowed Formats បានទេ។ សូមប្រើប្រាស់ <b>Trusted File Hashes</b> ដើម្បីអនុញ្ញាត File សុវត្ថិភាពជាក់លាក់មួយវិញ។",
        "allowed_removed": "✅ បានដក <code>{ext}</code> ចេញពី Allowed formats រួចរាល់។",
        "allowed_cleared": "✅ បញ្ជី Allowed formats ត្រូវបានសម្អាត។",
        "auto_title": "🤖 <b>ច្បាប់ចំណាត់ការស្វ័យប្រវត្តិ (Auto Action Rules)</b>\n💬 <b>{group}</b>\n\nម៉ូដ (Mode): <code>{mode}</code>\nកម្រិតព្រមាន (Warn): <code>{warn_threshold}</code>\nកម្រិតបិទមតិ (Mute): <code>{mute_threshold}</code>\nកម្រិតបណ្ដេញចេញ (Ban): <code>{ban_threshold}</code>\nរយៈពេល Mute: <code>{mute_minutes} នាទី</code>\n\nណែនាំ៖ <b>Smart</b> = ព្រមានជាមុន, Mute អ្នកដែលនៅតែបន្តល្មើស, និង Ban អ្នកល្មើសធ្ងន់ធ្ងរ។",
        "btn_auto_off": "⛔ បិទ Auto Action",
        "btn_auto_warn": "⚠️ ត្រឹមតែព្រមាន (Warn Only)",
        "btn_auto_smart": "🤖 ឆ្លាតវៃ (Smart Warn → Mute → Ban)",
        "btn_auto_ban": "🔨 Ban ដោយស្វ័យប្រវត្តិ",
        "auto_saved": "✅ ច្បាប់ចំណាត់ការស្វ័យប្រវត្តិត្រូវបានកែប្រែ។",
        "trusted_hash_title": "🔐 <b>បញ្ជី File Hash ដែលទុកចិត្ត (Whitelist)</b>\n💬 <b>{group}</b> <code>{chat_id}</code>\n\nTrusted hashes: <code>{count}</code>/<code>{limit}</code>\n\n{items}\n\nផ្ញើ File ដែលមានសុវត្ថិភាពនៅក្នុង Private chat ឬ Paste លេខកូដ SHA256 hash ដើម្បីអនុញ្ញាត File នោះជាក់លាក់។ ប្រសិនបើ File នោះត្រូវបានគេផ្ញើម្ដងទៀត Bot នឹងអនុញ្ញាត ទោះបីជាឈ្មោះបញ្ចប់ដោយ <code>.exe</code> ក៏ដោយ។",
        "trusted_hash_empty": "មិនទាន់មាន Trusted hash នៅឡើយទេ។",
        "btn_add_hash": "➕ បន្ថែម Trusted File/Hash",
        "btn_remove_hash": "🗑 លុប Trusted Hash",
        "btn_clear_hashes": "🧹 សម្អាត Trusted Hashes",
        "trusted_hash_prompt_add": "🔐 <b>បន្ថែម Trusted File Hash</b>\n\nសូមផ្ញើ File ដែលមានសុវត្ថិភាពនៅទីនេះក្នុង Private chat ឬ Paste លេខកូដ SHA256 hash។\n\n⚠️ អនុញ្ញាតតែ File ណាដែលអ្នកជឿជាក់ពិតប្រាកដប៉ុណ្ណោះ។ ចុចប៊ូតុង Home ឬ Back ដើម្បីបោះបង់។",
        "trusted_hash_saved": "✅ បានបន្ថែម Trusted hash រួចរាល់។",
        "trusted_hash_removed": "✅ បានលុប Trusted hash ចេញវិញ។",
        "trusted_hash_cleared": "✅ បានសម្អាតបញ្ជី Trusted hash whitelist ទាំងស្រុង។",
        "trusted_hash_invalid": "❌ សូមបញ្ចូលកូដ SHA256 hash ឱ្យបានត្រឹមត្រូវ ឬ Upload File ដែលមានទំហំតូចជាងដែនកំណត់របស់ Whitelist។",
        "trusted_hash_limit": "❌ បញ្ជី Trusted hash whitelist ពេញហើយ។ សូមលុប Hash ចាស់ៗមួយចំនួនសិន។",
        "trusted_hash_file_too_large": "❌ File មានទំហំធំពេក មិនអាច Hash ដោយសុវត្ថិភាពបានទេ។ Developer អាចបង្កើនទំហំ File អតិបរមានៅក្នុង Developer Dashboard។",
    },
}
for _lang, _items in GROUP_ADMIN_DASHBOARD_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_items)

INTERFACE_UPGRADE_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "home_title": (
            "🛡️ <b>EXE Remover Bot Dashboard</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Status: 🟢 <b>Online</b>\n"
            "Mode: <b>Button-first Control Panel</b>\n\n"
            "Manage group protection, scanner rules, trusted hashes, admin alerts, and incidents from one clean dashboard."
        ),
        "groups_title": (
            "👥 <b>My Protected Groups</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Tap a group to open its Control Center.\n"
            "🟢 Ready · 🟡 Needs attention · 🔴 No access"
        ),
        "groups_empty": (
            "👥 <b>No Protected Groups Yet</b>\n\n"
            "Add me to a group, make me an admin, and enable <b>Delete Messages</b>.\n"
            "Then open this dashboard again to manage protection settings."
        ),
        "group_card": (
            "━━━━━━━━━━━━━━━━━━━━\n"
            "💬 <b>{group}</b>\n"
            "{permission}\n"
            "🛡 Protection: <b>{protection}</b> · 🔥 <code>{strictness}</code>\n"
            "🔇 Silent: <code>{silent}</code>"
        ),
        "group_admin_title": (
            "⚙️ <b>Group Control Center</b>\n"
            "💬 <b>{group}</b>\n"
            "<code>{chat_id}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🛡 Protection: <b>{protection}</b>\n"
            "🔥 Strictness: <code>{strictness}</code>\n"
            "🔇 Silent mode: <code>{silent}</code>\n"
            "🤖 Auto action: <code>{auto_action}</code>\n"
            "🔐 Trusted hashes: <code>{trusted_hashes}</code>\n"
            "🧩 Blocked formats: <code>{custom_blocked}</code>\n"
            "✅ Allowed formats: <code>{allowed}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Choose a tool below to update this group."
        ),
        "protection_status_title": (
            "🛡 <b>Protection Overview</b>\n"
            "💬 <b>{group}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Protection: <b>{protection}</b>\n"
            "Bot permission: <code>{bot_permission}</code>\n"
            "Strictness: <code>{strictness}</code>\n"
            "Silent mode: <code>{silent}</code>\n"
            "Auto action: <code>{auto_action}</code>\n\n"
            "Tip: Use <b>Standard</b> for safer daily use, and <b>High</b> for stricter groups."
        ),
        "scanner_panel_title": "🧪 <b>Scanner Center</b>\n💬 <b>{group}</b>\n━━━━━━━━━━━━━━━━━━━━\n{scanner}",
        "health_title": (
            "🩺 <b>Group Health Check</b>\n"
            "💬 <b>{group}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Bot is admin: {bot_admin}\n"
            "Can delete messages: {can_delete}\n"
            "Can restrict members: {can_restrict}\n"
            "Protection enabled: {protection}\n"
            "Scanner enabled: {scanner}\n"
            "Admin alerts ready: <code>{ready}</code>/<code>{total}</code>\n\n"
            "Best setup: Admin + Delete Messages + Restrict Members."
        ),
        "incidents_title": "🚨 <b>Incident Center</b>\n💬 <b>{group}</b>\nTotal: <code>{total}</code>\n━━━━━━━━━━━━━━━━━━━━\n{items}",
        "member_risk_title": "👥 <b>Member Risk Center</b>\n💬 <b>{group}</b>\n━━━━━━━━━━━━━━━━━━━━\n{items}",
        "admin_alert_title": "👮 <b>Admin Alert Readiness</b>\n💬 <b>{group}</b>\nReady: <code>{ready}</code>/<code>{total}</code>\n━━━━━━━━━━━━━━━━━━━━\n{items}\n\n<i>Admins must start the bot privately at least once to receive alerts.</i>",
        "auto_title": (
            "🤖 <b>Auto Action Rules</b>\n"
            "💬 <b>{group}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Current mode: <code>{mode}</code>\n"
            "Warn threshold: <code>{warn_threshold}</code>\n"
            "Mute threshold: <code>{mute_threshold}</code>\n"
            "Ban threshold: <code>{ban_threshold}</code>\n"
            "Mute length: <code>{mute_minutes} minutes</code>\n\n"
            "Recommended: <b>Smart</b> (Warn first, mute repeat offenders, and ban persistent offenders)."
        ),
        "trusted_hash_title": (
            "🔐 <b>Trusted File Hash Whitelist</b>\n"
            "💬 <b>{group}</b> <code>{chat_id}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Trusted hashes: <code>{count}</code>/<code>{limit}</code>\n\n"
            "{items}\n\n"
            "Approve only exact safe files. A renamed file with different content will still be blocked."
        ),
    },
    "km": {
        "home_title": (
            "🛡️ <b>ផ្ទាំងគ្រប់គ្រង EXE Remover Bot</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "ស្ថានភាព៖ 🟢 <b>Online</b>\n"
            "ម៉ូដ (Mode)៖ <b>Button-first Control Panel</b>\n\n"
            "អ្នកអាចគ្រប់គ្រងការការពារក្រុម, ច្បាប់ Scanner, Trusted Hashes, សារជូនដំណឹង Admin និងប្រវត្តិល្មើសចេញពីផ្ទាំងតែមួយ។"
        ),
        "groups_title": (
            "👥 <b>ក្រុមដែលកំពុងការពារ</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "ចុចលើក្រុមណាមួយ ដើម្បីបើកផ្ទាំងគ្រប់គ្រងរបស់ក្រុមនោះ។\n"
            "🟢 រួចរាល់ · 🟡 ត្រូវពិនិត្យមើល · 🔴 មិនអាចចូលបាន"
        ),
        "groups_empty": (
            "👥 <b>មិនទាន់មានក្រុមដែលកំពុងការពារទេ</b>\n\n"
            "សូមបន្ថែមខ្ញុំទៅក្នុងក្រុម ផ្តល់សិទ្ធិជា Admin និងបើកសិទ្ធិ <b>Delete Messages</b>។\n"
            "បន្ទាប់មក សូមបើកផ្ទាំងគ្រប់គ្រង (Dashboard) នេះឡើងវិញ ដើម្បីកែប្រែការការពារ។"
        ),
        "group_card": (
            "━━━━━━━━━━━━━━━━━━━━\n"
            "💬 <b>{group}</b>\n"
            "{permission}\n"
            "🛡 ការការពារ៖ <b>{protection}</b> · 🔥 <code>{strictness}</code>\n"
            "🔇 មុខងារស្ងាត់៖ <code>{silent}</code>"
        ),
        "group_admin_title": (
            "⚙️ <b>ផ្ទាំងគ្រប់គ្រងក្រុម (Control Center)</b>\n"
            "💬 <b>{group}</b>\n"
            "<code>{chat_id}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🛡 ការការពារ៖ <b>{protection}</b>\n"
            "🔥 កម្រិតតឹងរ៉ឹង៖ <code>{strictness}</code>\n"
            "🔇 មុខងារស្ងាត់៖ <code>{silent}</code>\n"
            "🤖 សកម្មភាពស្វ័យប្រវត្តិ៖ <code>{auto_action}</code>\n"
            "🔐 Hash ដែលទុកចិត្ត៖ <code>{trusted_hashes}</code>\n"
            "🧩 Format ដែលហាមឃាត់៖ <code>{custom_blocked}</code>\n"
            "✅ Format ដែលអនុញ្ញាត៖ <code>{allowed}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "សូមជ្រើសរើសជម្រើសខាងក្រោម ដើម្បីកែប្រែការកំណត់ក្រុមនេះ។"
        ),
        "protection_status_title": (
            "🛡 <b>ទិដ្ឋភាពទូទៅនៃការការពារ</b>\n"
            "💬 <b>{group}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "ការការពារ៖ <b>{protection}</b>\n"
            "សិទ្ធិរបស់ Bot៖ <code>{bot_permission}</code>\n"
            "កម្រិតតឹងរ៉ឹង៖ <code>{strictness}</code>\n"
            "មុខងារស្ងាត់៖ <code>{silent}</code>\n"
            "សកម្មភាពស្វ័យប្រវត្តិ៖ <code>{auto_action}</code>\n\n"
            "គន្លឹះ៖ គួរប្រើ <b>Standard</b> សម្រាប់ការប្រើប្រាស់ទូទៅ និង <b>High</b> សម្រាប់ក្រុមដែលទាមទារភាពតឹងរ៉ឹង។"
        ),
        "scanner_panel_title": "🧪 <b>មជ្ឈមណ្ឌល Scanner</b>\n💬 <b>{group}</b>\n━━━━━━━━━━━━━━━━━━━━\n{scanner}",
        "health_title": (
            "🩺 <b>ពិនិត្យសុខភាពក្រុម</b>\n"
            "💬 <b>{group}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Bot ជា Admin៖ {bot_admin}\n"
            "អាចលុបសារបាន៖ {can_delete}\n"
            "អាចកម្រិតសិទ្ធិសមាជិកបាន៖ {can_restrict}\n"
            "ការការពារបានបើក៖ {protection}\n"
            "Scanner បានបើក៖ {scanner}\n"
            "Admin ត្រៀមទទួលសារជូនដំណឹង៖ <code>{ready}</code>/<code>{total}</code>\n\n"
            "ការកំណត់ល្អបំផុត៖ Admin + Delete Messages + Restrict Members។"
        ),
        "incidents_title": "🚨 <b>ប្រវត្តិល្មើស (Incident Center)</b>\n💬 <b>{group}</b>\nសរុប៖ <code>{total}</code>\n━━━━━━━━━━━━━━━━━━━━\n{items}",
        "member_risk_title": "👥 <b>សមាជិកដែលមានហានិភ័យ</b>\n💬 <b>{group}</b>\n━━━━━━━━━━━━━━━━━━━━\n{items}",
        "admin_alert_title": "👮 <b>ស្ថានភាពទទួលសារជូនដំណឹង Admin</b>\n💬 <b>{group}</b>\nរួចរាល់៖ <code>{ready}</code>/<code>{total}</code>\n━━━━━━━━━━━━━━━━━━━━\n{items}\n\n<i>Admin ត្រូវចុច Start Bot ក្នុង Private Chat យ៉ាងហោចណាស់ម្តង ទើបអាចទទួលបានសារជូនដំណឹង។</i>",
        "auto_title": (
            "🤖 <b>ច្បាប់សកម្មភាពស្វ័យប្រវត្តិ</b>\n"
            "💬 <b>{group}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "ម៉ូដបច្ចុប្បន្ន៖ <code>{mode}</code>\n"
            "ចំនួនព្រមាន (Warn)៖ <code>{warn_threshold}</code>\n"
            "ចំនួនបិទមតិ (Mute)៖ <code>{mute_threshold}</code>\n"
            "ចំនួនបណ្ដេញចេញ (Ban)៖ <code>{ban_threshold}</code>\n"
            "រយៈពេល Mute៖ <code>{mute_minutes} នាទី</code>\n\n"
            "ណែនាំ៖ <b>Smart</b> (ព្រមានជាមុន, Mute អ្នកល្មើសដដែលៗ, ហើយ Ban អ្នកល្មើសធ្ងន់ធ្ងរ)។"
        ),
        "trusted_hash_title": (
            "🔐 <b>បញ្ជី File Hash ដែលទុកចិត្ត (Whitelist)</b>\n"
            "💬 <b>{group}</b> <code>{chat_id}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Hash ដែលទុកចិត្ត៖ <code>{count}</code>/<code>{limit}</code>\n\n"
            "{items}\n\n"
            "អនុញ្ញាតតែ File ដែលមានសុវត្ថិភាពពិតប្រាកដប៉ុណ្ណោះ។ File ដែលមានខ្លឹមសារខុសពីនេះ ទោះប្តូរឈ្មោះក៏នឹងត្រូវហាមឃាត់ដដែល។"
        ),
    },
}
for _lang, _items in INTERFACE_UPGRADE_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_items)

INTERFACE_BUTTON_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "btn_open_groups": "👥 Open My Groups",
        "btn_refresh_dashboard": "🔄 Refresh Dashboard",
        "btn_refresh_groups": "🔄 Refresh Groups",
        "btn_confirm_yes": "✅ Yes, clear all",
        "btn_confirm_no": "❌ No, cancel",
        "confirm_cancelled": "✅ Action cancelled.",
        "confirm_clear_title": (
            "⚠️ <b>Confirm destructive action</b>\n\n"
            "{summary}\n\n"
            "This action cannot be undone."
        ),
        "confirm_clear_formats": "Clear all custom delete formats for <b>{group}</b>?",
        "confirm_clear_allowed": "Clear the allowed-format list for <b>{group}</b>?",
        "confirm_clear_hashes": "Clear all trusted file hashes for <b>{group}</b>?",
        "confirm_clear_incidents": "Clear all handled incident logs for <b>{group}</b>?",
        "confirm_clear_admin_logs": "Clear all admin action logs for <b>{group}</b>?",
        "btn_refresh_incidents": "🔄 Refresh Incidents",
        "btn_refresh_developer": "🔄 Refresh Developer Dashboard",
        "btn_feedback": "💬 Send Feedback",
        "btn_dev_feedback": "💬 User Feedback",
        "btn_refresh_feedback": "🔄 Refresh Feedback",
        "feedback_prompt": (
            "💬 <b>Send Feedback</b>\n\n"
            "Please let me know if anything feels confusing, slow, or missing. You can write in Khmer or English.\n\n"
            "Example: <code>The group settings page is hard to understand.</code>\n\n"
            "Send <code>/cancel</code> to cancel."
        ),
        "feedback_thanks": "✅ Thanks! Your feedback was saved and sent to the developer dashboard.",
        "feedback_empty": "No feedback has been submitted yet.",
        "feedback_cancelled": "✅ Feedback cancelled.",
        "feedback_too_short": "❌ Please provide a little more detail so the developer can understand the issue.",
        "dev_feedback_title": "💬 <b>User Feedback</b>\nTotal: <code>{total}</code>\n━━━━━━━━━━━━━━━━━━━━\n{items}",
        "btn_scanner_center": "🧪 Scanner Center",
        "btn_health_check_short": "🩺 Health Check",
        "btn_incidents_short": "🚨 Incidents",
        "btn_risk_users": "👥 Risk Users",
        "btn_admin_alerts_short": "👮 Admin Alerts",
        "btn_blocked_formats_short": "🧩 Blocked Formats",
        "btn_allowed_formats_short": "✅ Allowed Formats",
        "btn_trusted_hashes_short": "🔐 Trusted Hashes",
        "btn_group_notice_on": "🔔 Group Notice: ON",
        "btn_silent_mode_on": "🔇 Silent Mode: ON",
        "label_protection_on": "🟢 Protection: ON",
        "label_protection_off": "🔴 Protection: OFF",
        "label_access_ok": "🟢 Access OK",
        "label_no_access": "🔴 No Access",
        "label_auto": "🤖 Auto",
    },
    "km": {
        "btn_open_groups": "👥 បើកក្រុមរបស់ខ្ញុំ",
        "btn_refresh_dashboard": "🔄 Refresh Dashboard",
        "btn_refresh_groups": "🔄 Refresh ក្រុម",
        "btn_confirm_yes": "✅ បាទ/ចាស លុបទាំងអស់",
        "btn_confirm_no": "❌ ទេ បោះបង់",
        "confirm_cancelled": "✅ បានបោះបង់សកម្មភាព។",
        "confirm_clear_title": (
            "⚠️ <b>បញ្ជាក់សកម្មភាពលុប</b>\n\n"
            "{summary}\n\n"
            "សកម្មភាពនេះមិនអាចត្រឡប់ក្រោយបានទេ។"
        ),
        "confirm_clear_formats": "លុប Custom Delete Formats ទាំងអស់សម្រាប់ <b>{group}</b>?",
        "confirm_clear_allowed": "លុប Allowed Formats ទាំងអស់សម្រាប់ <b>{group}</b>?",
        "confirm_clear_hashes": "លុប Trusted File Hashes ទាំងអស់សម្រាប់ <b>{group}</b>?",
        "confirm_clear_incidents": "លុប Incident Logs ដែលបានចាត់ការរួចសម្រាប់ <b>{group}</b>?",
        "confirm_clear_admin_logs": "លុប Admin Action Logs ទាំងអស់សម្រាប់ <b>{group}</b>?",
        "btn_refresh_incidents": "🔄 Refresh Incidents",
        "btn_refresh_developer": "🔄 Refresh Developer Dashboard",
        "btn_feedback": "💬 ផ្ញើ Feedback",
        "btn_dev_feedback": "💬 User Feedback",
        "btn_refresh_feedback": "🔄 Refresh Feedback",
        "feedback_prompt": (
            "💬 <b>ផ្ញើ Feedback</b>\n\n"
            "សូមប្រាប់ពួកយើងប្រសិនបើផ្នែកណាមួយពិបាកប្រើ, យឺត, ខ្វះមុខងារ ឬមានភាពច្របូកច្របល់។ អ្នកអាចសរសេរជាភាសាខ្មែរ ឬ English ក៏បាន។\n\n"
            "ឧទាហរណ៍: <code>ទំព័រ Group Settings មើលទៅរាងច្របូកច្របល់បន្តិច។</code>\n\n"
            "ផ្ញើ <code>/cancel</code> ដើម្បីបោះបង់សកម្មភាពនេះ។"
        ),
        "feedback_thanks": "✅ អរគុណ! Feedback របស់អ្នកត្រូវបានរក្សាទុកក្នុង Developer Dashboard រួចរាល់។",
        "feedback_empty": "មិនទាន់មាន Feedback នៅឡើយទេ។",
        "feedback_cancelled": "✅ បានបោះបង់ការផ្ញើ Feedback។",
        "feedback_too_short": "❌ សូមសរសេរលម្អិតបន្តិច ដើម្បីឱ្យ Developer ងាយស្រួលយល់ពីបញ្ហា។",
        "dev_feedback_title": "💬 <b>User Feedback</b>\nសរុប: <code>{total}</code>\n━━━━━━━━━━━━━━━━━━━━\n{items}",
        "btn_scanner_center": "🧪 Scanner Center",
        "btn_health_check_short": "🩺 ពិនិត្យសុខភាព",
        "btn_incidents_short": "🚨 Incidents",
        "btn_risk_users": "👥 Risk Users",
        "btn_admin_alerts_short": "👮 Admin Alerts",
        "btn_blocked_formats_short": "🧩 Blocked Formats",
        "btn_allowed_formats_short": "✅ Allowed Formats",
        "btn_trusted_hashes_short": "🔐 Trusted Hashes",
        "btn_group_notice_on": "🔔 Group Notice: ON",
        "btn_silent_mode_on": "🔇 Silent Mode: ON",
        "label_protection_on": "🟢 Protection: ON",
        "label_protection_off": "🔴 Protection: OFF",
        "label_access_ok": "🟢 Access OK",
        "label_no_access": "🔴 No Access",
        "label_auto": "🤖 Auto",
    },
}
for _lang, _items in INTERFACE_BUTTON_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_items)

ADMIN_PANEL_V4_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "group_admin_title": (
            "🛡️ <b>Admin Control Center v4</b>\n"
            "💬 <b>{group}</b>\n"
            "<code>{chat_id}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "{health_status}\n"
            "🛡 Protection: <b>{protection}</b>\n"
            "🔥 Strictness: <code>{strictness}</code>\n"
            "🔇 Silent mode: <code>{silent}</code>\n"
            "🤖 Auto action: <code>{auto_action}</code>\n"
            "👮 Admin alerts: <code>{admin_ready}</code>/<code>{admin_total}</code> ready\n"
            "🚨 Open incidents: <code>{open_incidents}</code>\n"
            "📝 Admin logs: <code>{admin_logs}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🧪 Security: <code>{custom_blocked}</code> blocked · <code>{allowed}</code> allowed\n"
            "🔐 Trusted hashes: <code>{trusted_hashes}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Choose a module below. Main safety settings are shown first."
        ),
        "btn_admin_logs": "📝 Admin Logs",
        "btn_refresh_admin_logs": "🔄 Refresh Admin Logs",
        "btn_clear_admin_logs": "🧹 Clear Admin Logs",
        "admin_logs_title": "📝 <b>Admin Action Logs</b>\n💬 <b>{group}</b>\nTotal: <code>{total}</code>\n━━━━━━━━━━━━━━━━━━━━\n{items}",
        "admin_logs_empty": "No admin actions have been recorded for this group yet.",
        "admin_logs_cleared": "✅ Admin action logs cleared for this group.",
        "admin_panel_tip": "💡 Tip: Keep <b>Smart Auto Action</b> ON for active groups and check <b>Health</b> after changing bot permissions.",
        "status_ready": "🟢 <b>Ready</b>: bot can protect this group.",
        "status_attention": "🟡 <b>Needs attention</b>: check bot permissions.",
        "status_no_access": "🔴 <b>No access</b>: bot was removed or cannot read this chat.",
        "btn_quick_auto": "🤖 Auto Rules",
        "btn_quick_health": "🩺 Health",
    },
    "km": {
        "group_admin_title": (
            "🛡️ <b>Admin Control Center v4</b>\n"
            "💬 <b>{group}</b>\n"
            "<code>{chat_id}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "{health_status}\n"
            "🛡 ការការពារ: <b>{protection}</b>\n"
            "🔥 កម្រិតតឹងរ៉ឹង: <code>{strictness}</code>\n"
            "🔇 មុខងារស្ងាត់: <code>{silent}</code>\n"
            "🤖 សកម្មភាពស្វ័យប្រវត្តិ: <code>{auto_action}</code>\n"
            "👮 Admin alerts: រួចរាល់ <code>{admin_ready}</code>/<code>{admin_total}</code>\n"
            "🚨 ករណីកំពុងបើក: <code>{open_incidents}</code>\n"
            "📝 Admin logs: <code>{admin_logs}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🧪 សុវត្ថិភាព: Block <code>{custom_blocked}</code> · Allow <code>{allowed}</code>\n"
            "🔐 Hash ដែលទុកចិត្ត: <code>{trusted_hashes}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "ជ្រើសរើសជម្រើសខាងក្រោម។ ការកំណត់សំខាន់ៗត្រូវបានបង្ហាញនៅខាងលើ។"
        ),
        "btn_admin_logs": "📝 Admin Logs",
        "btn_refresh_admin_logs": "🔄 Refresh Admin Logs",
        "btn_clear_admin_logs": "🧹 Clear Admin Logs",
        "admin_logs_title": "📝 <b>Admin Action Logs</b>\n💬 <b>{group}</b>\nសរុប: <code>{total}</code>\n━━━━━━━━━━━━━━━━━━━━\n{items}",
        "admin_logs_empty": "មិនទាន់មាន Admin Action Log សម្រាប់ក្រុមនេះទេ។",
        "admin_logs_cleared": "✅ បានសម្អាត Admin action logs សម្រាប់ក្រុមនេះ។",
        "admin_panel_tip": "💡 ណែនាំ: គួរប្រើប្រាស់ <b>Smart Auto Action</b> សម្រាប់ក្រុម Active និងកុំភ្លេចពិនិត្យ <b>Health</b> បន្ទាប់ពីកែប្រែ Permission។",
        "status_ready": "🟢 <b>Ready</b>: Bot អាចការពារក្រុមនេះបាន។",
        "status_attention": "🟡 <b>ត្រូវពិនិត្យ</b>: សូមពិនិត្យមើល Bot Permissions ឡើងវិញ។",
        "status_no_access": "🔴 <b>No access</b>: Bot ត្រូវបានដកចេញ ឬមិនអាចចូលក្នុងក្រុមនេះបានទេ។",
        "btn_quick_auto": "🤖 Auto Rules",
        "btn_quick_health": "🩺 Health",
    },
}
for _lang, _items in ADMIN_PANEL_V4_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_items)

PROFESSIONAL_UI_V3_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "home_title": (
            "🛡️ <b>{brand}</b> <code>{version}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Status: 🟢 <b>Online</b>\n"
            "Security mode: <b>Professional Group Protection</b>\n\n"
            "Protect Telegram groups from <code>.exe</code>, renamed malware-style files, risky archives, and repeat offenders.\n\n"
            "✅ Auto-delete dangerous uploads\n"
            "✅ Instant admin alerts with action buttons\n"
            "✅ Group-specific scanner settings\n"
            "✅ Trusted hash whitelist for exact safe files\n\n"
            "Choose an option below."
        ),
        "welcome": (
            "👋 <b>Welcome to {brand}</b> <code>{version}</code>\n\n"
            "I help protect Telegram groups by removing dangerous executable files, scanning suspicious uploads, and notifying admins instantly.\n\n"
            "Add me to your group, make me an admin, and enable <b>Delete Messages</b> to start protection."
        ),
        "help": (
            "💡 <b>How {brand} Works</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "1. Add the bot to your group.\n"
            "2. Grant <b>Delete Messages</b> permission.\n"
            "3. Open <b>My Protected Groups</b> from this dashboard.\n"
            "4. Configure scanner rules, blocked formats, trusted hashes, and auto actions.\n\n"
            "When a risky file is detected, I delete it, notify admins, and provide quick actions: Ban, Warn, Ignore, or View Risk Profile."
        ),
        "groups_title": (
            "👥 <b>My Protected Groups</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Select a group to open its v3 Security Control Center.\n"
            "🟢 Ready · 🟡 Needs attention · 🔴 No access"
        ),
        "groups_empty": (
            "👥 <b>No Protected Groups Yet</b>\n\n"
            "Add me to a group, make me an admin, and enable <b>Delete Messages</b>.\n"
            "After that, return here to manage professional security settings."
        ),
        "group_admin_title": (
            "🛡️ <b>Security Control Center {version}</b>\n"
            "💬 <b>{group}</b>\n"
            "<code>{chat_id}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "{health_status}\n"
            "🛡 Protection: <b>{protection}</b>\n"
            "🔥 Strictness: <code>{strictness}</code>\n"
            "🔇 Silent mode: <code>{silent}</code>\n"
            "🤖 Auto action: <code>{auto_action}</code>\n"
            "👮 Admin alerts: <code>{admin_ready}</code>/<code>{admin_total}</code> ready\n"
            "🚨 Open incidents: <code>{open_incidents}</code>\n"
            "📝 Admin logs: <code>{admin_logs}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🧪 Blocked: <code>{custom_blocked}</code> · Allowed: <code>{allowed}</code>\n"
            "🔐 Trusted hashes: <code>{trusted_hashes}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Choose a module below."
        ),
        "admin_alert": (
            "🚨 <b>Security Alert</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "A dangerous file was detected and removed.\n\n"
            "👤 <b>Sender:</b> {sender_name}\n"
            "🆔 <b>User ID:</b> <code>{sender_id}</code>\n"
            "📄 <b>File:</b> <code>{file_name}</code>\n"
            "🧪 <b>Reason:</b> {scan_result}\n"
            "💬 <b>Group:</b> {group_name} <code>{group_id}</code>\n"
            "🕒 <b>Time:</b> <code>{time}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Choose an admin action:"
        ),
        "btn_language": "🌐 Language",
        "btn_view_risk_profile": "📋 View Risk Profile",
        "language_title": "🌐 <b>Choose Dashboard Language</b>\n\nSelect the language used for private dashboards and alerts.",
        "risk_profile_title": (
            "📋 <b>User Risk Profile</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "👤 User: {user}\n"
            "🆔 User ID: <code>{target_user_id}</code>\n"
            "💬 Group: <b>{group}</b>\n"
            "📊 Risk level: <code>{risk}</code>\n"
            "🚨 Total incidents: <code>{incidents}</code>\n"
            "⚠️ Warnings: <code>{warns}</code>\n"
            "🔇 Mutes: <code>{mutes}</code>\n"
            "🔨 Bans: <code>{bans}</code>\n"
            "📄 Last file: <code>{last_file}</code>\n"
            "🕒 Last incident: <code>{last_seen}</code>\n\n"
            "Recommended action: <b>{recommended}</b>"
        ),
        "risk_recommend_warn": "Warn and monitor",
        "risk_recommend_mute": "Mute if behavior continues",
        "risk_recommend_ban": "Ban persistent offender",
    },
    "km": {
        "home_title": (
            "🛡️ <b>{brand}</b> <code>{version}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "ស្ថានភាព៖ 🟢 <b>Online</b>\n"
            "ម៉ូដសុវត្ថិភាព៖ <b>Professional Group Protection</b>\n\n"
            "ការពារក្រុម Telegram ពី <code>.exe</code>, file បន្លំឈ្មោះ, archive មានហានិភ័យ និងអ្នកល្មើសដដែលៗ។\n\n"
            "✅ លុប file គ្រោះថ្នាក់ដោយស្វ័យប្រវត្តិ\n"
            "✅ ជូនដំណឹង Admin ជាមួយប៊ូតុងចាត់ការ\n"
            "✅ កំណត់ Scanner ផ្សេងគ្នាតាមក្រុម\n"
            "✅ Trusted hash whitelist សម្រាប់ file សុវត្ថិភាពជាក់លាក់\n\n"
            "សូមជ្រើសរើសជម្រើសខាងក្រោម។"
        ),
        "welcome": (
            "👋 <b>សូមស្វាគមន៍មកកាន់ {brand}</b> <code>{version}</code>\n\n"
            "ខ្ញុំជួយការពារក្រុម Telegram ដោយលុប file executable គ្រោះថ្នាក់ ស្កេន upload សង្ស័យ និងជូនដំណឹង Admin ភ្លាមៗ។\n\n"
            "សូមបន្ថែមខ្ញុំទៅក្នុងក្រុម ដាក់ជាអ្នកគ្រប់គ្រង ហើយបើកសិទ្ធិ <b>Delete Messages</b> ដើម្បីចាប់ផ្តើមការពារ។"
        ),
        "help": (
            "💡 <b>របៀបដំណើរការ {brand}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "1. បន្ថែម Bot ទៅក្នុងក្រុម។\n"
            "2. ផ្តល់សិទ្ធិ <b>Delete Messages</b>។\n"
            "3. បើក <b>My Protected Groups</b> ពី Dashboard នេះ។\n"
            "4. កំណត់ Scanner rules, blocked formats, trusted hashes និង auto actions។\n\n"
            "ពេលរកឃើញ file មានហានិភ័យ ខ្ញុំនឹងលុបវា ជូនដំណឹង Admin ហើយផ្តល់ប៊ូតុង Ban, Warn, Ignore ឬ View Risk Profile។"
        ),
        "groups_title": (
            "👥 <b>ក្រុមដែលកំពុងការពារ</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "ជ្រើសរើសក្រុម ដើម្បីបើក v3 Security Control Center។\n"
            "🟢 រួចរាល់ · 🟡 ត្រូវពិនិត្យ · 🔴 មិនអាចចូលបាន"
        ),
        "groups_empty": (
            "👥 <b>មិនទាន់មានក្រុមដែលកំពុងការពារ</b>\n\n"
            "សូមបន្ថែមខ្ញុំទៅក្នុងក្រុម ដាក់ជាអ្នកគ្រប់គ្រង ហើយបើកសិទ្ធិ <b>Delete Messages</b>។\n"
            "បន្ទាប់មកត្រឡប់មកទីនេះ ដើម្បីគ្រប់គ្រងការកំណត់សុវត្ថិភាព។"
        ),
        "group_admin_title": (
            "🛡️ <b>Security Control Center {version}</b>\n"
            "💬 <b>{group}</b>\n"
            "<code>{chat_id}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "{health_status}\n"
            "🛡 ការការពារ: <b>{protection}</b>\n"
            "🔥 កម្រិតតឹងរ៉ឹង: <code>{strictness}</code>\n"
            "🔇 Silent mode: <code>{silent}</code>\n"
            "🤖 Auto action: <code>{auto_action}</code>\n"
            "👮 Admin alerts: <code>{admin_ready}</code>/<code>{admin_total}</code> ready\n"
            "🚨 ករណីកំពុងបើក: <code>{open_incidents}</code>\n"
            "📝 Admin logs: <code>{admin_logs}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🧪 Blocked: <code>{custom_blocked}</code> · Allowed: <code>{allowed}</code>\n"
            "🔐 Trusted hashes: <code>{trusted_hashes}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "សូមជ្រើសរើស module ខាងក្រោម។"
        ),
        "admin_alert": (
            "🚨 <b>Security Alert</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "រកឃើញ និងលុប file មានហានិភ័យរួចហើយ។\n\n"
            "👤 <b>អ្នកផ្ញើ:</b> {sender_name}\n"
            "🆔 <b>User ID:</b> <code>{sender_id}</code>\n"
            "📄 <b>File:</b> <code>{file_name}</code>\n"
            "🧪 <b>មូលហេតុ:</b> {scan_result}\n"
            "💬 <b>ក្រុម:</b> {group_name} <code>{group_id}</code>\n"
            "🕒 <b>ម៉ោង:</b> <code>{time}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "សូមជ្រើសរើសចំណាត់ការ Admin:"
        ),
        "btn_language": "🌐 ភាសា",
        "btn_view_risk_profile": "📋 មើល Risk Profile",
        "language_title": "🌐 <b>ជ្រើសរើសភាសា Dashboard</b>\n\nសូមជ្រើសរើសភាសាសម្រាប់ Private dashboard និងសារជូនដំណឹង។",
        "risk_profile_title": (
            "📋 <b>User Risk Profile</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "👤 User: {user}\n"
            "🆔 User ID: <code>{target_user_id}</code>\n"
            "💬 Group: <b>{group}</b>\n"
            "📊 Risk level: <code>{risk}</code>\n"
            "🚨 Incident សរុប: <code>{incidents}</code>\n"
            "⚠️ Warnings: <code>{warns}</code>\n"
            "🔇 Mutes: <code>{mutes}</code>\n"
            "🔨 Bans: <code>{bans}</code>\n"
            "📄 File ចុងក្រោយ: <code>{last_file}</code>\n"
            "🕒 Incident ចុងក្រោយ: <code>{last_seen}</code>\n\n"
            "ចំណាត់ការណែនាំ: <b>{recommended}</b>"
        ),
        "risk_recommend_warn": "ព្រមាន ហើយតាមដាន",
        "risk_recommend_mute": "Mute ប្រសិនបើនៅតែបន្ត",
        "risk_recommend_ban": "Ban អ្នកល្មើសដដែលៗ",
    },
}
if PROFESSIONAL_UI_ENABLED:
    for _lang, _items in PROFESSIONAL_UI_V3_TEXTS.items():
        TEXTS.setdefault(_lang, {}).update(_items)

BOT_ADMIN_REQUIRED_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "bot_admin_required_title": (
            "🔒 <b>Bot Settings Locked</b>\n"
            "💬 <b>{group}</b> <code>{chat_id}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Bot status: <code>{status}</code>\n"
            "Delete Messages: {can_delete}\n"
            "Restrict/Ban Users: {can_restrict}\n\n"
            "To unlock the Settings button, a group admin must add this bot as an <b>Administrator</b> and enable <b>Delete Messages</b>.\n\n"
            "Tap <b>Add Bot as Admin</b>, then return here and tap <b>Check Again</b>."
        ),
        "btn_check_again": "🔄 Check Again",
        "btn_add_bot_admin": "➕ Add Bot as Admin",
        "bot_admin_required_group": (
            "🔒 <b>Settings are locked.</b>\n\n"
            "Please add me as a group <b>Administrator</b> and enable <b>Delete Messages</b>. "
            "I will show the Settings button only after the permission is confirmed."
        ),
    },
    "km": {
        "bot_admin_required_title": (
            "🔒 <b>Bot Settings ត្រូវបាន Lock</b>\n"
            "💬 <b>{group}</b> <code>{chat_id}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Bot status: <code>{status}</code>\n"
            "សិទ្ធិ Delete Messages: {can_delete}\n"
            "សិទ្ធិ Restrict/Ban Users: {can_restrict}\n\n"
            "ដើម្បីបើកប៊ូតុង Settings ម្ចាស់/Admin ក្រុមត្រូវដាក់ Bot ជា <b>Administrator</b> ហើយបើកសិទ្ធិ <b>Delete Messages</b>។\n\n"
            "ចុច <b>ដាក់ Bot ជា Admin</b> រួចត្រឡប់មកចុច <b>ពិនិត្យម្តងទៀត</b>។"
        ),
        "btn_check_again": "🔄 ពិនិត្យម្តងទៀត",
        "btn_add_bot_admin": "➕ ដាក់ Bot ជា Admin",
        "bot_admin_required_group": (
            "🔒 <b>Settings ត្រូវបាន Lock។</b>\n\n"
            "សូមដាក់ខ្ញុំជា <b>Administrator</b> ក្នុងក្រុម ហើយបើកសិទ្ធិ <b>Delete Messages</b>។ "
            "ខ្ញុំនឹងបង្ហាញប៊ូតុង Settings តែបន្ទាប់ពី Permission ត្រូវបានបញ្ជាក់។"
        ),
    },
}
for _lang, _items in BOT_ADMIN_REQUIRED_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_items)

FIRST_TIME_DASHBOARD_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "first_time_home_title": (
            "🛡️ <b>{brand}</b> <code>{version}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Welcome! No protected groups are linked yet.\n\n"
            "To start protection, add this bot to your Telegram group, make it an <b>Administrator</b>, and enable <b>Delete Messages</b>.\n\n"
            "Only the setup buttons are shown until your first group is connected."
        ),
        "btn_add_group": "➕ Add Bot To Group",
        "btn_about": "ℹ️ About",
        "about_title": (
            "ℹ️ <b>About {brand}</b> <code>{version}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "This bot protects Telegram groups from dangerous executable uploads such as <code>.exe</code>, renamed malware-style files, risky archives, and repeat offenders.\n\n"
            "Main features:\n"
            "✅ Auto-delete dangerous files\n"
            "✅ Alert admins instantly\n"
            "✅ Ban / Warn / Ignore action buttons\n"
            "✅ Group-specific scanner settings\n"
            "✅ Trusted hash whitelist for exact safe files"
        ),
    },
    "km": {
        "first_time_home_title": (
            "🛡️ <b>{brand}</b> <code>{version}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "សូមស្វាគមន៍! មិនទាន់មានក្រុមណាមួយភ្ជាប់នៅឡើយទេ។\n\n"
            "ដើម្បីចាប់ផ្តើមការពារ សូមបន្ថែម Bot ទៅក្នុងក្រុម Telegram របស់អ្នក ដាក់ជា <b>Administrator</b> ហើយបើកសិទ្ធិ <b>Delete Messages</b>។\n\n"
            "រហូតដល់មានក្រុមដំបូង ត្រូវបង្ហាញតែប៊ូតុង Setup ប៉ុណ្ណោះ។"
        ),
        "btn_add_group": "➕ បន្ថែម Bot ទៅក្រុម",
        "btn_about": "ℹ️ អំពី Bot",
        "about_title": (
            "ℹ️ <b>អំពី {brand}</b> <code>{version}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Bot នេះជួយការពារក្រុម Telegram ពី file executable គ្រោះថ្នាក់ ដូចជា <code>.exe</code>, file បន្លំឈ្មោះ, archive មានហានិភ័យ និងអ្នកល្មើសដដែលៗ។\n\n"
            "មុខងារសំខាន់ៗ៖\n"
            "✅ លុប file គ្រោះថ្នាក់ដោយស្វ័យប្រវត្តិ\n"
            "✅ ជូនដំណឹង Admin ភ្លាមៗ\n"
            "✅ ប៊ូតុង Ban / Warn / Ignore\n"
            "✅ កំណត់ Scanner ផ្សេងគ្នាតាមក្រុម\n"
            "✅ Trusted hash whitelist សម្រាប់ file សុវត្ថិភាពជាក់លាក់"
        ),
    },
}
for _lang, _items in FIRST_TIME_DASHBOARD_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_items)

DEFAULT_GROUP_SETTINGS: dict[str, Any] = {
    "protection_enabled": True,
    "strictness": "standard",  # standard=.exe/PE only, high=all dangerous extensions, strict=high + archive-risk focus
    "silent_mode": False,
    "strict_enforcement_on_admins": STRICT_ENFORCEMENT_ON_ADMINS_DEFAULT,
    "allowed_extensions": [],
    "custom_blocked_extensions": [],
    "trusted_file_hashes": [],
    "auto_action_mode": "off",  # off | warn | smart | ban
    "auto_warn_threshold": 1,
    "auto_mute_threshold": 2,
    "auto_ban_threshold": 3,
    "auto_mute_minutes": 60,
}


# ─────────────────────────────────────────────────────────────
# DEVELOPER RUNTIME CONFIG
# Env vars are still the boot defaults, but the Developer Dashboard can override
# these values at runtime. Overrides are stored in bot_data["settings"] and are
# persisted by the existing Redis/Supabase memory flow.
# ─────────────────────────────────────────────────────────────

RUNTIME_CONFIG_KEY = "runtime_config"
TRUSTED_HASH_SIZE_OPTIONS = (2_000_000, 5_000_000, 10_000_000, 20_000_000, 50_000_000, 100_000_000)
TRUSTED_HASH_LIMIT_OPTIONS = (32, 64, 128, 256, 512, 1000)


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().casefold()
        if lowered in {"1", "true", "yes", "y", "on", "enabled"}:
            return True
        if lowered in {"0", "false", "no", "n", "off", "disabled"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return bool(default)


def _coerce_int_range(value: Any, default: int, *, min_value: int, max_value: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    return max(min_value, min(max_value, parsed))


def _runtime_config_bucket(bot_data: dict[str, Any], *, create: bool = False) -> dict[str, Any]:
    settings = bot_data.get("settings")
    if not isinstance(settings, dict):
        if not create:
            return {}
        settings = {}
        bot_data["settings"] = settings
    bucket = settings.get(RUNTIME_CONFIG_KEY)
    if not isinstance(bucket, dict):
        if not create:
            return {}
        bucket = {}
        settings[RUNTIME_CONFIG_KEY] = bucket
    return bucket


def ensure_runtime_config(bot_data: dict[str, Any]) -> dict[str, Any]:
    bucket = _runtime_config_bucket(bot_data, create=True)
    bucket["trusted_file_hash_whitelist_enabled"] = _coerce_bool(
        bucket.get("trusted_file_hash_whitelist_enabled"),
        TRUSTED_FILE_HASH_WHITELIST_ENABLED,
    )
    bucket["trusted_hash_max_download_bytes"] = _coerce_int_range(
        bucket.get("trusted_hash_max_download_bytes"),
        TRUSTED_HASH_MAX_DOWNLOAD_BYTES,
        min_value=1,
        max_value=100_000_000,
    )
    bucket["max_trusted_file_hashes"] = _coerce_int_range(
        bucket.get("max_trusted_file_hashes"),
        MAX_TRUSTED_FILE_HASHES,
        min_value=1,
        max_value=1000,
    )
    return bucket


def trusted_hash_whitelist_enabled(bot_data: dict[str, Any]) -> bool:
    bucket = _runtime_config_bucket(bot_data)
    return _coerce_bool(bucket.get("trusted_file_hash_whitelist_enabled"), TRUSTED_FILE_HASH_WHITELIST_ENABLED)


def trusted_hash_max_download_bytes(bot_data: dict[str, Any]) -> int:
    bucket = _runtime_config_bucket(bot_data)
    return _coerce_int_range(
        bucket.get("trusted_hash_max_download_bytes"),
        TRUSTED_HASH_MAX_DOWNLOAD_BYTES,
        min_value=1,
        max_value=100_000_000,
    )


def max_trusted_file_hashes(bot_data: dict[str, Any]) -> int:
    bucket = _runtime_config_bucket(bot_data)
    return _coerce_int_range(
        bucket.get("max_trusted_file_hashes"),
        MAX_TRUSTED_FILE_HASHES,
        min_value=1,
        max_value=1000,
    )


def format_bytes_mb(value: int) -> str:
    mb = int(value) / 1_000_000
    return f"{mb:.0f} MB" if mb.is_integer() else f"{mb:.1f} MB"

# ─────────────────────────────────────────────────────────────
# REDIS MEMORY / PERSISTENCE HELPERS
# ─────────────────────────────────────────────────────────────

PERSISTED_BOT_DATA_KEYS = (
    "user_state",
    "group_state",
    "known_users",
    "incidents",
    "incident_tokens",
    "warning_counts",
    "settings",
    "whitelisted_hashes",
    # Persist lightweight caches so private dashboards can render without live API calls after restart.
    "chat_meta_cache",
    "admin_ids_cache",
    "bot_member_cache",
    "inaccessible_chats",
)


def redis_configured() -> bool:
    return bool(REDIS_ENABLED and REDIS_URL and redis_async is not None)


def storage_backend_label() -> str:
    backends: list[str] = []
    if SUPABASE_AVAILABLE:
        backends.append("supabase")
    elif SUPABASE_ENABLED:
        if not SUPABASE_URL:
            backends.append("supabase-offline:url-missing")
        elif not SUPABASE_SERVICE_ROLE_KEY:
            backends.append("supabase-offline:key-missing")
        else:
            backends.append("supabase-offline")

    if REDIS_AVAILABLE:
        backends.append("redis")
    elif REDIS_ENABLED:
        if not REDIS_URL:
            backends.append("redis-offline:url-missing")
        elif redis_async is None:
            backends.append("redis-offline:package-missing")
        else:
            backends.append("redis-offline")

    if LOCAL_PERSISTENCE_ENABLED:
        backends.append("local")
    return "+".join(backends) if backends else "memory-only"


def prepare_local_persistence_file(path: str) -> None:
    """Create the parent folder for PicklePersistence before PTB opens it.

    Render deploys often use relative paths, but custom PERSISTENCE_FILE values
    such as /data/exe_bot_data.pickle or state/exe_bot_data.pickle fail if the
    parent folder does not exist. Creating it here prevents a boot-time crash.
    """
    if not path:
        return
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
    except OSError:
        logger.exception("Could not prepare persistence directory for %r", path, exc_info=True)
        raise


class ThreadedPicklePersistence(PicklePersistence):
    """PicklePersistence wrapper that moves blocking pickle/file IO off the PTB event loop.

    PTB persistence methods are async in modern releases, but the default
    PicklePersistence still performs synchronous pickle load/dump work inside
    those coroutines.  For large local state files this can freeze update
    handling.  This adapter serializes persistence calls and runs the base
    implementation in a worker thread, preserving the local-pickle fallback
    without blocking the bot loop.
    """

    __slots__ = ("_file_io_lock",)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._file_io_lock = asyncio.Lock()

    async def _call_base_in_thread(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        async with self._file_io_lock:
            def runner() -> Any:
                method = getattr(super(ThreadedPicklePersistence, self), method_name)
                result = method(*args, **kwargs)
                if inspect.isawaitable(result):
                    return asyncio.run(result)
                return result
            return await asyncio.to_thread(runner)

    async def get_user_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("get_user_data", *args, **kwargs)

    async def get_chat_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("get_chat_data", *args, **kwargs)

    async def get_bot_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("get_bot_data", *args, **kwargs)

    async def get_callback_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("get_callback_data", *args, **kwargs)

    async def get_conversations(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("get_conversations", *args, **kwargs)

    async def update_user_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("update_user_data", *args, **kwargs)

    async def update_chat_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("update_chat_data", *args, **kwargs)

    async def update_bot_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("update_bot_data", *args, **kwargs)

    async def update_callback_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("update_callback_data", *args, **kwargs)

    async def update_conversation(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("update_conversation", *args, **kwargs)

    async def drop_chat_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("drop_chat_data", *args, **kwargs)

    async def drop_user_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("drop_user_data", *args, **kwargs)

    async def refresh_user_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("refresh_user_data", *args, **kwargs)

    async def refresh_chat_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("refresh_chat_data", *args, **kwargs)

    async def refresh_bot_data(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("refresh_bot_data", *args, **kwargs)

    async def flush(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call_base_in_thread("flush", *args, **kwargs)


def export_bot_data_for_storage(bot_data: dict[str, Any]) -> dict[str, Any]:
    """Store only durable bot data. Runtime locks/caches stay outside bot_data."""
    exported: dict[str, Any] = {}
    for key in PERSISTED_BOT_DATA_KEYS:
        value = bot_data.get(key)
        if value is not None:
            exported[key] = value
    exported["_meta"] = {
        "saved_at_ms": now_ms(),
        "schema": 3,
        "bot": "exe_remover_bot",
    }
    return exported


def merge_loaded_bot_data(bot_data: dict[str, Any], loaded: dict[str, Any]) -> None:
    for key in PERSISTED_BOT_DATA_KEYS:
        value = loaded.get(key)
        if isinstance(value, dict):
            bot_data[key] = value


REDIS_JSON_CODEC = "exe-remover-json-hmac-sha256-v1"


def _redis_signing_secret_bytes() -> bytes:
    """Return stable signing key bytes for Redis payload integrity.

    Prefer REDIS_STATE_SIGNING_SECRET.  BOT_TOKEN is used as a secure fallback
    so existing Render deployments can enable the safer serializer without one
    more required environment variable.
    """
    secret = REDIS_STATE_SIGNING_SECRET or BOT_TOKEN
    return secret.encode("utf-8")


def _json_safe(value: Any) -> Any:
    """Convert persisted bot_data into JSON-safe primitives.

    This intentionally refuses to preserve arbitrary Python objects in Redis.
    Unsupported values are stringified rather than pickled, which removes the
    remote-code-execution class caused by untrusted pickle.loads(raw).
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return str(value)


def encode_redis_state(payload: dict[str, Any]) -> bytes:
    """Encode durable state as signed JSON bytes for Redis."""
    body_obj = {
        "codec": REDIS_JSON_CODEC,
        "payload": _json_safe(payload),
    }
    body = json.dumps(body_obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_redis_signing_secret_bytes(), body, hashlib.sha256).hexdigest()
    envelope = {
        "codec": REDIS_JSON_CODEC,
        "sig": sig,
        "body_b64": base64.urlsafe_b64encode(body).decode("ascii"),
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_redis_state(raw: bytes | str) -> dict[str, Any] | None:
    """Decode signed JSON Redis state.

    Legacy pickle Redis state is intentionally rejected by default.  One-time
    migration can be enabled with REDIS_LEGACY_PICKLE_LOAD_ENABLED=true, but it
    should only be used when Redis ACLs/network access are already trusted.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8")
    else:
        raw_bytes = bytes(raw)

    try:
        envelope = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(envelope, dict) or envelope.get("codec") != REDIS_JSON_CODEC:
            raise ValueError("unknown Redis JSON envelope")
        sig = str(envelope.get("sig") or "")
        body_b64 = str(envelope.get("body_b64") or "")
        body = base64.urlsafe_b64decode(body_b64.encode("ascii"))
        expected = hmac.new(_redis_signing_secret_bytes(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("Redis state signature mismatch")
        body_obj = json.loads(body.decode("utf-8"))
        if not isinstance(body_obj, dict) or body_obj.get("codec") != REDIS_JSON_CODEC:
            raise ValueError("invalid Redis state body")
        payload = body_obj.get("payload")
        return payload if isinstance(payload, dict) else None
    except Exception:
        if not REDIS_LEGACY_PICKLE_LOAD_ENABLED:
            logger.warning(
                "Redis state was not valid signed JSON and legacy pickle loading is disabled; "
                "skipping Redis hydration for safety."
            )
            return None
        try:
            loaded = pickle.loads(raw_bytes)
            if isinstance(loaded, dict):
                logger.warning(
                    "Loaded legacy pickled Redis state because REDIS_LEGACY_PICKLE_LOAD_ENABLED=true. "
                    "Disable this after one successful migration."
                )
                return loaded
        except Exception:
            logger.exception("Legacy Redis pickle migration failed", exc_info=True)
        return None


def sanitize_bot_data_in_place(bot_data: dict[str, Any]) -> None:
    """Normalize older/corrupt persisted state without network calls.

    Call this only while BOT_DATA_LOCK is held. It keeps dashboards fast after
    restarts and prevents random crashes from malformed persisted values.
    """
    for key in PERSISTED_BOT_DATA_KEYS:
        if key not in bot_data or not isinstance(bot_data.get(key), dict):
            bot_data[key] = {}

    users = bot_data.get("user_state", {})
    if isinstance(users, dict):
        for raw_uid in list(users.keys()):
            try:
                uid = int(raw_uid)
            except (TypeError, ValueError):
                users.pop(raw_uid, None)
                continue
            state = users.get(raw_uid)
            if not isinstance(state, dict):
                users.pop(raw_uid, None)
                continue
            if raw_uid != uid:
                merged = users.get(uid) if isinstance(users.get(uid), dict) else {}
                merged.update(state)
                users[uid] = merged
                users.pop(raw_uid, None)
            get_user_state(bot_data, uid)
            users[uid]["groups"] = get_groups(bot_data, uid)

    groups = bot_data.get("group_state", {})
    if isinstance(groups, dict):
        for raw_cid in list(groups.keys()):
            try:
                cid = int(raw_cid)
            except (TypeError, ValueError):
                groups.pop(raw_cid, None)
                continue
            state = groups.get(raw_cid)
            if not isinstance(state, dict):
                groups.pop(raw_cid, None)
                continue
            key = str(cid)
            if raw_cid != key:
                merged = groups.get(key) if isinstance(groups.get(key), dict) else {}
                merged.update(state)
                groups[key] = merged
                groups.pop(raw_cid, None)
            settings = get_group_settings(bot_data, cid)
            settings["allowed_extensions"] = _dedupe_valid_extensions(settings.get("allowed_extensions", []), limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
            settings["custom_blocked_extensions"] = _dedupe_valid_extensions(settings.get("custom_blocked_extensions", []), limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)

    for cache_name in ("admin_ids_cache", "bot_member_cache", "chat_meta_cache"):
        bucket = bot_data.get(cache_name, {})
        if isinstance(bucket, dict):
            for raw_key in list(bucket.keys()):
                try:
                    normalized_key = str(int(raw_key))
                except (TypeError, ValueError):
                    bucket.pop(raw_key, None)
                    continue
                if raw_key != normalized_key:
                    bucket[normalized_key] = bucket.pop(raw_key)

    inaccessible = bot_data.get("inaccessible_chats", {})
    if not isinstance(inaccessible, dict):
        bot_data["inaccessible_chats"] = {}
    else:
        for raw_key in list(inaccessible.keys()):
            try:
                normalized_key = str(int(raw_key))
            except (TypeError, ValueError):
                inaccessible.pop(raw_key, None)
                continue
            record = inaccessible.get(raw_key)
            if not isinstance(record, dict):
                inaccessible.pop(raw_key, None)
                continue
            try:
                suppress_until_ms = int(record.get("suppress_until_ms", 0) or 0)
            except (TypeError, ValueError):
                suppress_until_ms = 0
            if suppress_until_ms <= now_ms():
                inaccessible.pop(raw_key, None)
                continue
            if raw_key != normalized_key:
                inaccessible[normalized_key] = inaccessible.pop(raw_key)

    ensure_runtime_config(bot_data)


async def init_redis_memory(application: Application) -> None:
    """Connect to Redis and hydrate bot_data. Safe fallback when Redis is unavailable."""
    global REDIS_CLIENT, REDIS_AVAILABLE

    if not REDIS_ENABLED:
        logger.info("Redis memory disabled by REDIS_ENABLED=false. Using local persistence only.")
        return
    if not REDIS_URL:
        logger.info("REDIS_URL is not set. Using local persistence only.")
        return
    if redis_async is None:
        logger.warning("redis package is not installed. Add redis==5.0.8 to requirements.txt to enable Redis memory.")
        return

    try:
        REDIS_CLIENT = redis_async.from_url(
            REDIS_URL,
            encoding=None,
            decode_responses=False,
            socket_connect_timeout=REDIS_CONNECT_TIMEOUT_SECONDS,
            socket_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
            health_check_interval=30,
        )
        await REDIS_CLIENT.ping()
        REDIS_AVAILABLE = True
        logger.info("Redis memory connected. key=%s", REDIS_STATE_KEY)
    except Exception as exc:
        REDIS_AVAILABLE = False
        REDIS_CLIENT = None
        logger.exception("Redis memory unavailable; local persistence fallback is active", exc_info=True)
        return

    try:
        raw = await REDIS_CLIENT.get(REDIS_STATE_KEY)
        if raw:
            loaded = decode_redis_state(raw)
            if isinstance(loaded, dict):
                async with BOT_DATA_LOCK:
                    merge_loaded_bot_data(application.bot_data, loaded)
                    sanitize_bot_data_in_place(application.bot_data)
                logger.info(
                    "Loaded Redis memory: users=%s groups=%s incidents=%s",
                    len(application.bot_data.get("known_users", {})),
                    len(application.bot_data.get("group_state", {})),
                    len(application.bot_data.get("incidents", {})),
                )
            else:
                logger.warning("Redis memory exists but could not be decoded safely; continuing with current state.")
    except Exception as exc:
        logger.exception("Could not load Redis memory. Continuing with current local state", exc_info=True)


async def save_payload_to_redis(
    payload: dict[str, Any],
    *,
    reason: str = "manual",
    force: bool = False,
) -> bool:
    """Persist an already-snapshotted durable payload to Redis.

    This helper performs network I/O without touching BOT_DATA_LOCK.  It is used
    by UI handlers that already mutated bot_data under the lock, so slow Redis
    writes cannot freeze button callbacks or group moderation.
    """
    global REDIS_LAST_SAVE_MONOTONIC, REDIS_LAST_SAVE_UTC

    if not (REDIS_AVAILABLE and REDIS_CLIENT is not None):
        return False

    now = time.monotonic()
    if not force and REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS > 0:
        if now - REDIS_LAST_SAVE_MONOTONIC < REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS:
            return False

    try:
        encoded = encode_redis_state(payload)
    except Exception:
        logger.exception("Redis memory payload encode failed reason=%s", reason, exc_info=True)
        return False

    async with REDIS_SAVE_LOCK:
        try:
            await REDIS_CLIENT.set(REDIS_STATE_KEY, encoded)
            REDIS_LAST_SAVE_MONOTONIC = time.monotonic()
            REDIS_LAST_SAVE_UTC = now_utc_str()
            logger.debug("Saved Redis memory reason=%s bytes=%s", reason, len(encoded))
            return True
        except Exception:
            logger.exception("Redis memory save failed reason=%s", reason, exc_info=True)
            return False


async def save_bot_data_to_redis(
    bot_data: dict[str, Any],
    *,
    reason: str = "manual",
    force: bool = False,
    caller_holds_lock: bool = False,
) -> bool:
    """Snapshot durable memory, then persist it to Redis without crashing handlers."""
    try:
        if caller_holds_lock:
            payload = export_bot_data_for_storage(bot_data)
        else:
            async with BOT_DATA_LOCK:
                payload = export_bot_data_for_storage(bot_data)
    except Exception:
        logger.exception("Redis memory snapshot failed reason=%s", reason, exc_info=True)
        return False
    return await save_payload_to_redis(payload, reason=reason, force=force)


async def _persist_payload_to_backends(payload: dict[str, Any], *, reason: str, force: bool) -> None:
    """Write a snapshot payload to all enabled durable backends."""
    await save_payload_to_supabase(payload, reason=reason, force=force)
    await save_payload_to_redis(payload, reason=reason, force=force)


def _track_memory_save_task(task: asyncio.Task[Any]) -> None:
    """Track background persistence tasks and log unexpected task failures."""
    PENDING_MEMORY_SAVE_TASKS.add(task)

    def _done(done_task: asyncio.Task[Any]) -> None:
        PENDING_MEMORY_SAVE_TASKS.discard(done_task)
        try:
            exc = done_task.exception()
        except asyncio.CancelledError:
            return
        except Exception:
            logger.exception("Could not inspect memory save task", exc_info=True)
            return
        if exc is not None:
            logger.error("Background memory save task failed", exc_info=(type(exc), exc, exc.__traceback__))

    task.add_done_callback(_done)


def _create_app_task(context: Any, coro: Any, *, name: str | None = None) -> asyncio.Task[Any]:
    """Create a task through PTB when possible, with an asyncio fallback."""
    try:
        app = getattr(context, "application", context)
        task = app.create_task(coro, name=name) if name else app.create_task(coro)
        if task is not None:
            return task
    except TypeError:
        # Older PTB versions do not accept the name keyword.
        try:
            app = getattr(context, "application", context)
            task = app.create_task(coro)
            if task is not None:
                return task
        except Exception:
            pass
    except Exception:
        pass
    return asyncio.create_task(coro, name=name)


async def _debounced_memory_save_worker(context: Any) -> None:
    """Persist the most recent pending payload after a short debounce window."""
    global PENDING_MEMORY_SAVE_PAYLOAD, PENDING_MEMORY_SAVE_REASON, PENDING_MEMORY_SAVE_FORCE, PENDING_MEMORY_SAVE_DEBOUNCE_TASK

    try:
        if MEMORY_SAVE_DEBOUNCE_SECONDS > 0:
            await asyncio.sleep(MEMORY_SAVE_DEBOUNCE_SECONDS)
        async with PENDING_MEMORY_SAVE_LOCK:
            payload = PENDING_MEMORY_SAVE_PAYLOAD
            reason = PENDING_MEMORY_SAVE_REASON
            force = PENDING_MEMORY_SAVE_FORCE
            PENDING_MEMORY_SAVE_PAYLOAD = None
            PENDING_MEMORY_SAVE_REASON = "manual"
            PENDING_MEMORY_SAVE_FORCE = False
            PENDING_MEMORY_SAVE_DEBOUNCE_TASK = None
        if payload is not None:
            await _persist_payload_to_backends(payload, reason=reason, force=force)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Debounced memory save failed", exc_info=True)
        async with PENDING_MEMORY_SAVE_LOCK:
            PENDING_MEMORY_SAVE_DEBOUNCE_TASK = None


async def _queue_memory_payload_save(context: Any, payload: dict[str, Any], *, reason: str, force: bool) -> None:
    """Queue the latest snapshot and coalesce rapid saves into one backend write."""
    global PENDING_MEMORY_SAVE_PAYLOAD, PENDING_MEMORY_SAVE_REASON, PENDING_MEMORY_SAVE_FORCE, PENDING_MEMORY_SAVE_DEBOUNCE_TASK

    async with PENDING_MEMORY_SAVE_LOCK:
        PENDING_MEMORY_SAVE_PAYLOAD = payload
        PENDING_MEMORY_SAVE_REASON = reason
        PENDING_MEMORY_SAVE_FORCE = bool(PENDING_MEMORY_SAVE_FORCE or force)
        if PENDING_MEMORY_SAVE_DEBOUNCE_TASK is None or PENDING_MEMORY_SAVE_DEBOUNCE_TASK.done():
            task = _create_app_task(context, _debounced_memory_save_worker(context), name="debounced_memory_save")
            PENDING_MEMORY_SAVE_DEBOUNCE_TASK = task
            _track_memory_save_task(task)


def _schedule_memory_payload_save(context: Any, payload: dict[str, Any], *, reason: str, force: bool) -> None:
    """Schedule persistence without keeping BOT_DATA_LOCK blocked on network I/O."""
    task = _create_app_task(context, _queue_memory_payload_save(context, payload, reason=reason, force=force), name="queue_memory_save")
    _track_memory_save_task(task)


async def drain_pending_memory_saves(timeout: float = 5.0) -> None:
    """Flush best-effort background memory saves before shutdown closes clients."""
    global PENDING_MEMORY_SAVE_PAYLOAD, PENDING_MEMORY_SAVE_REASON, PENDING_MEMORY_SAVE_FORCE, PENDING_MEMORY_SAVE_DEBOUNCE_TASK

    deadline = time.monotonic() + max(0.1, float(timeout))
    while True:
        async with PENDING_MEMORY_SAVE_LOCK:
            payload = PENDING_MEMORY_SAVE_PAYLOAD
            reason = PENDING_MEMORY_SAVE_REASON
            force = PENDING_MEMORY_SAVE_FORCE
            PENDING_MEMORY_SAVE_PAYLOAD = None
            PENDING_MEMORY_SAVE_REASON = "manual"
            PENDING_MEMORY_SAVE_FORCE = False
            debounce_task = PENDING_MEMORY_SAVE_DEBOUNCE_TASK
            PENDING_MEMORY_SAVE_DEBOUNCE_TASK = None
        if debounce_task is not None and not debounce_task.done():
            debounce_task.cancel()
        if payload is not None:
            await _persist_payload_to_backends(payload, reason=reason, force=force)

        pending = [task for task in list(PENDING_MEMORY_SAVE_TASKS) if not task.done()]
        if not pending:
            async with PENDING_MEMORY_SAVE_LOCK:
                if PENDING_MEMORY_SAVE_PAYLOAD is None and (PENDING_MEMORY_SAVE_DEBOUNCE_TASK is None or PENDING_MEMORY_SAVE_DEBOUNCE_TASK.done()):
                    return
            continue

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.warning("Timed out while waiting for %s pending memory save task(s)", len(pending))
            return
        try:
            await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=remaining)
        except asyncio.TimeoutError:
            logger.warning("Timed out while waiting for %s pending memory save task(s)", len(pending))
            return


async def persist_context_memory(
    context: Any,
    *,
    reason: str,
    force: bool = False,
    caller_holds_lock: bool = False,
) -> None:
    """Persist durable bot_data to Supabase/Redis.

    Snapshot once, then write outside BOT_DATA_LOCK. Handler-triggered saves are
    queued/debounced so repeated button taps do not create a Redis/Supabase storm
    or make Telegram callbacks feel frozen. Shutdown and periodic jobs can call
    drain_pending_memory_saves() to flush the latest snapshot.
    """
    try:
        if caller_holds_lock:
            payload = export_bot_data_for_storage(context.bot_data)
        else:
            async with BOT_DATA_LOCK:
                payload = export_bot_data_for_storage(context.bot_data)
    except Exception:
        logger.exception("Durable memory snapshot failed reason=%s", reason, exc_info=True)
        return

    _schedule_memory_payload_save(context, payload, reason=reason, force=force)

async def close_redis_memory() -> None:
    global REDIS_CLIENT, REDIS_AVAILABLE
    if REDIS_CLIENT is not None:
        try:
            await REDIS_CLIENT.aclose()
        except Exception:
            logger.exception("Redis close failed", exc_info=True)
    REDIS_CLIENT = None
    REDIS_AVAILABLE = False


# ─────────────────────────────────────────────────────────────
# SUPABASE MEMORY / PERSISTENCE HELPERS
# ─────────────────────────────────────────────────────────────


def supabase_configured() -> bool:
    return bool(SUPABASE_ENABLED and SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)


def _valid_supabase_table_name(table_name: str) -> str:
    table = (table_name or "bot_state").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table):
        raise RuntimeError("SUPABASE_TABLE must contain only letters, numbers, and underscores, and cannot start with a number.")
    return table


def _supabase_rest_url(path: str = "") -> str:
    base = SUPABASE_URL.rstrip("/")
    if not base:
        raise RuntimeError("SUPABASE_URL is missing.")
    if not base.endswith("/rest/v1"):
        base = f"{base}/rest/v1"
    return f"{base}/{path.lstrip('/')}" if path else base


def _supabase_headers(*, prefer: str | None = None) -> dict[str, str]:
    key = SUPABASE_SERVICE_ROLE_KEY
    if not key:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY is missing.")
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    return headers


async def init_supabase_memory(application: Application) -> None:
    """Connect to Supabase REST and hydrate bot_data from one JSONB state row.

    Supabase stores the same JSON-safe payload as Redis. Use a service-role key
    on the server side, or configure RLS policies that allow this bot to read
    and upsert the configured state row.
    """
    global SUPABASE_CLIENT, SUPABASE_AVAILABLE

    if not SUPABASE_ENABLED:
        logger.info("Supabase memory disabled by SUPABASE_ENABLED=false.")
        return
    if not SUPABASE_URL:
        logger.warning("SUPABASE_URL is not set. Supabase memory disabled.")
        return
    if not SUPABASE_SERVICE_ROLE_KEY:
        logger.warning("SUPABASE_SERVICE_ROLE_KEY is not set. Supabase memory disabled.")
        return

    try:
        table = _valid_supabase_table_name(SUPABASE_TABLE)
        SUPABASE_CLIENT = httpx.AsyncClient(timeout=SUPABASE_TIMEOUT_SECONDS)
        response = await SUPABASE_CLIENT.get(
            _supabase_rest_url(table),
            headers=_supabase_headers(),
            params={
                "select": "payload",
                "state_key": f"eq.{SUPABASE_STATE_KEY}",
                "limit": "1",
            },
        )
        response.raise_for_status()
        SUPABASE_AVAILABLE = True
        logger.info("Supabase memory connected. table=%s key=%s", table, SUPABASE_STATE_KEY)

        rows = response.json()
        if isinstance(rows, list) and rows:
            payload = rows[0].get("payload") if isinstance(rows[0], dict) else None
            if isinstance(payload, dict):
                async with BOT_DATA_LOCK:
                    merge_loaded_bot_data(application.bot_data, payload)
                    sanitize_bot_data_in_place(application.bot_data)
                logger.info(
                    "Loaded Supabase memory: users=%s groups=%s incidents=%s",
                    len(application.bot_data.get("known_users", {})),
                    len(application.bot_data.get("group_state", {})),
                    len(application.bot_data.get("incidents", {})),
                )
        else:
            logger.info("No Supabase state row found yet; it will be created on the next save.")
    except httpx.HTTPStatusError as exc:
        SUPABASE_AVAILABLE = False
        logger.exception(
            "Supabase memory unavailable HTTP %s. Check table, key, and RLS policy.",
            exc.response.status_code if exc.response else "unknown",
            exc_info=True,
        )
        await close_supabase_memory()
    except Exception:
        SUPABASE_AVAILABLE = False
        logger.exception("Supabase memory unavailable; other persistence fallbacks remain active", exc_info=True)
        await close_supabase_memory()


async def save_payload_to_supabase(
    payload: dict[str, Any],
    *,
    reason: str = "manual",
    force: bool = False,
) -> bool:
    """Persist an already-snapshotted durable payload to Supabase."""
    global SUPABASE_LAST_SAVE_MONOTONIC, SUPABASE_LAST_SAVE_UTC

    if not (SUPABASE_AVAILABLE and SUPABASE_CLIENT is not None):
        return False

    now = time.monotonic()
    if not force and SUPABASE_AUTOSAVE_MIN_INTERVAL_SECONDS > 0:
        if now - SUPABASE_LAST_SAVE_MONOTONIC < SUPABASE_AUTOSAVE_MIN_INTERVAL_SECONDS:
            return False

    try:
        row = {
            "state_key": SUPABASE_STATE_KEY,
            "payload": _json_safe(payload),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception:
        logger.exception("Supabase memory payload build failed reason=%s", reason, exc_info=True)
        return False

    try:
        table = _valid_supabase_table_name(SUPABASE_TABLE)
        response = await SUPABASE_CLIENT.post(
            _supabase_rest_url(table),
            headers=_supabase_headers(prefer="resolution=merge-duplicates,return=minimal"),
            params={"on_conflict": "state_key"},
            json=row,
        )
        response.raise_for_status()
        SUPABASE_LAST_SAVE_MONOTONIC = time.monotonic()
        SUPABASE_LAST_SAVE_UTC = now_utc_str()
        logger.debug("Saved Supabase memory reason=%s", reason)
        return True
    except httpx.HTTPStatusError as exc:
        logger.exception(
            "Supabase memory save failed HTTP %s reason=%s",
            exc.response.status_code if exc.response else "unknown",
            reason,
            exc_info=True,
        )
        return False
    except Exception:
        logger.exception("Supabase memory save failed reason=%s", reason, exc_info=True)
        return False


async def save_bot_data_to_supabase(
    bot_data: dict[str, Any],
    *,
    reason: str = "manual",
    force: bool = False,
    caller_holds_lock: bool = False,
) -> bool:
    """Snapshot durable memory, then upsert it into Supabase."""
    try:
        if caller_holds_lock:
            payload = export_bot_data_for_storage(bot_data)
        else:
            async with BOT_DATA_LOCK:
                payload = export_bot_data_for_storage(bot_data)
    except Exception:
        logger.exception("Supabase memory snapshot failed reason=%s", reason, exc_info=True)
        return False
    return await save_payload_to_supabase(payload, reason=reason, force=force)

async def close_supabase_memory() -> None:
    global SUPABASE_CLIENT, SUPABASE_AVAILABLE
    if SUPABASE_CLIENT is not None:
        try:
            await SUPABASE_CLIENT.aclose()
        except Exception:
            logger.exception("Supabase close failed", exc_info=True)
    SUPABASE_CLIENT = None
    SUPABASE_AVAILABLE = False


# ─────────────────────────────────────────────────────────────
# HTML / STATE HELPERS
# ─────────────────────────────────────────────────────────────


def h(value: Any) -> str:
    """Escape text for Telegram HTML parse mode."""
    return html_escape(str(value), quote=False)


def user_link(user_id: int, name: str) -> str:
    return f'<a href="tg://user?id={int(user_id)}">{h(name)}</a>'


def get_user_state(bot_data: dict[str, Any], user_id: int) -> dict[str, Any]:
    """Return a stable user_state entry and migrate old string keys to int keys.

    Call this only while BOT_DATA_LOCK is held because it may mutate bot_data.
    """
    uid = int(user_id)
    user_state = bot_data.setdefault("user_state", {})
    if not isinstance(user_state, dict):
        user_state = {}
        bot_data["user_state"] = user_state

    existing = user_state.get(uid)
    legacy_key = str(uid)
    if not isinstance(existing, dict) and isinstance(user_state.get(legacy_key), dict):
        existing = user_state.pop(legacy_key)
        user_state[uid] = existing
    elif legacy_key in user_state and uid in user_state:
        user_state.pop(legacy_key, None)

    if not isinstance(existing, dict):
        existing = {"lang": "en", "groups": []}
        user_state[uid] = existing
    existing.setdefault("lang", "en")
    existing.setdefault("groups", [])
    if not isinstance(existing.get("groups"), list):
        existing["groups"] = []
    return existing


def _read_user_state(bot_data: dict[str, Any], user_id: int | None) -> dict[str, Any]:
    if not user_id:
        return {}
    users = bot_data.get("user_state", {})
    if not isinstance(users, dict):
        return {}
    state = users.get(int(user_id)) or users.get(str(int(user_id)))
    return state if isinstance(state, dict) else {}


def get_lang(bot_data: dict[str, Any], user_id: int | None) -> str:
    lang = _read_user_state(bot_data, user_id).get("lang", "en")
    return lang if lang in TEXTS else "en"


def tr(bot_data: dict[str, Any], user_id: int | None, key: str, **kwargs: Any) -> str:
    lang = get_lang(bot_data, user_id)
    text = TEXTS.get(lang, TEXTS["en"]).get(key, TEXTS["en"].get(key, key))
    fmt = {"brand": PROFESSIONAL_BRAND_NAME, "version": PROFESSIONAL_UI_VERSION}
    fmt.update(kwargs)
    try:
        return text.format(**fmt)
    except KeyError:
        # Defensive fallback for legacy translation strings with incomplete kwargs.
        return text.format(**kwargs) if kwargs else text


def get_groups(bot_data: dict[str, Any], user_id: int) -> list[int]:
    groups = _read_user_state(bot_data, user_id).get("groups", [])
    parsed: list[int] = []
    seen: set[int] = set()
    if not isinstance(groups, list):
        return []
    for group_id in groups:
        try:
            parsed_id = int(group_id)
        except (TypeError, ValueError):
            continue
        if parsed_id not in seen:
            parsed.append(parsed_id)
            seen.add(parsed_id)
    return parsed


async def get_groups_snapshot(bot_data: dict[str, Any], user_id: int) -> list[int]:
    async with BOT_DATA_LOCK:
        return get_groups(bot_data, user_id)


async def add_group(bot_data: dict[str, Any], user_id: int, chat_id: int) -> None:
    async with BOT_DATA_LOCK:
        state = get_user_state(bot_data, user_id)
        groups = state.setdefault("groups", [])
        if chat_id not in groups:
            groups.append(chat_id)


async def remember_user(bot_data: dict[str, Any], user_id: int, lang: str | None = None) -> None:
    async with BOT_DATA_LOCK:
        state = get_user_state(bot_data, user_id)
        state["last_seen_ms"] = now_ms()
        if "first_seen_ms" not in state:
            state["first_seen_ms"] = state["last_seen_ms"]
        if lang in TEXTS:
            state["lang"] = lang


async def remember_user_profile(bot_data: dict[str, Any], user: Any | None, lang: str | None = None) -> None:
    if not user:
        return
    async with BOT_DATA_LOCK:
        state = get_user_state(bot_data, int(user.id))
        state["last_seen_ms"] = now_ms()
        state.setdefault("first_seen_ms", state["last_seen_ms"])
        if lang in TEXTS:
            state["lang"] = lang

        known_users = bot_data.setdefault("known_users", {})
        profile = known_users.setdefault(str(user.id), {})
        profile.setdefault("first_seen_ms", state.get("first_seen_ms", now_ms()))
        profile.update(
            {
                "id": int(user.id),
                "is_bot": bool(getattr(user, "is_bot", False)),
                "username": getattr(user, "username", None) or "",
                "full_name": getattr(user, "full_name", None) or "Unknown",
                "language_code": getattr(user, "language_code", None) or "",
                "lang": state.get("lang", "en"),
                "last_seen_ms": now_ms(),
            }
        )


def get_group_state(bot_data: dict[str, Any], chat_id: int) -> dict[str, Any]:
    """Return durable group state and migrate old int keys to string keys.

    Call this only while BOT_DATA_LOCK is held because it may mutate bot_data.
    """
    cid = int(chat_id)
    key = str(cid)
    group_state = bot_data.setdefault("group_state", {})
    if not isinstance(group_state, dict):
        group_state = {}
        bot_data["group_state"] = group_state
    existing = group_state.get(key)
    if not isinstance(existing, dict) and isinstance(group_state.get(cid), dict):
        existing = group_state.pop(cid)
        group_state[key] = existing
    elif cid in group_state and key in group_state:
        group_state.pop(cid, None)
    if not isinstance(existing, dict):
        existing = {"lang": "en"}
        group_state[key] = existing
    existing.setdefault("lang", "en")
    return existing


def get_group_lang(bot_data: dict[str, Any], chat_id: int | None) -> str:
    if chat_id is None:
        return "en"
    groups = bot_data.get("group_state", {})
    state = groups.get(str(int(chat_id))) or groups.get(int(chat_id)) if isinstance(groups, dict) else {}
    lang = state.get("lang", "en") if isinstance(state, dict) else "en"
    return lang if lang in TEXTS else "en"


def tr_group(bot_data: dict[str, Any], chat_id: int | None, key: str, **kwargs: Any) -> str:
    lang = get_group_lang(bot_data, chat_id)
    text = TEXTS.get(lang, TEXTS["en"]).get(key, TEXTS["en"].get(key, key))
    fmt = {"brand": PROFESSIONAL_BRAND_NAME, "version": PROFESSIONAL_UI_VERSION}
    fmt.update(kwargs)
    try:
        return text.format(**fmt)
    except KeyError:
        return text.format(**kwargs) if kwargs else text


async def remember_group(
    bot_data: dict[str, Any],
    chat_id: int,
    *,
    added_by: int | None = None,
    lang: str | None = None,
    title: str | None = None,
    chat_type: str | None = None,
) -> None:
    """Persist minimal group metadata used by the private dashboard.

    This avoids live context.bot.get_chat() calls when rendering the dashboard.
    All bot_data mutations stay under BOT_DATA_LOCK.
    """
    async with BOT_DATA_LOCK:
        state = get_group_state(bot_data, chat_id)
        if added_by is not None:
            state["added_by"] = int(added_by)
        if lang in TEXTS:
            state["lang"] = lang
        if title:
            state["title"] = str(title)
            state["chat_title"] = str(title)
            bucket = _bot_data_cache_bucket(bot_data, "chat_meta_cache")
            bucket[str(int(chat_id))] = {
                "id": int(chat_id),
                "title": str(title),
                "type": str(chat_type or ""),
                "updated_at_ms": _cache_now_ms(),
            }
        state["last_seen_ms"] = now_ms()


async def remove_group_from_user(bot_data: dict[str, Any], user_id: int, chat_id: int) -> None:
    async with BOT_DATA_LOCK:
        state = get_user_state(bot_data, user_id)
        groups = state.setdefault("groups", [])
        kept: list[int] = []
        for group_id in groups:
            try:
                parsed = int(group_id)
            except (TypeError, ValueError):
                continue
            if parsed != int(chat_id):
                kept.append(parsed)
        state["groups"] = kept


def is_group_chat(chat_type: str | None) -> bool:
    return chat_type in CHAT_TYPES_GROUP


def normalize_filename(name: str | None) -> str:
    if not name:
        return "Unknown"
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", "", name).strip()
    return cleaned or "Unknown"


SUSPICIOUS_UNICODE_CONTROLS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069", "\ufeff",
}


def visible_controls_removed(name: str) -> str:
    cleaned_chars: list[str] = []
    for char in name:
        # Remove invisible formatting controls that can reverse or hide extensions.
        if char in SUSPICIOUS_UNICODE_CONTROLS or unicodedata.category(char) == "Cf":
            continue
        cleaned_chars.append(char)
    return "".join(cleaned_chars)


def compact_scan_name(name: str | None) -> str:
    normalized = normalize_filename(name)
    normalized = visible_controls_removed(normalized)
    normalized = normalized.replace("\\", "/").split("/")[-1]
    normalized = re.sub(r"\s+", " ", normalized).strip().rstrip(" .")
    return normalized or "Unknown"


_SUFFIX_TOKEN_RE = re.compile(r"^[a-z0-9_+-]{1,16}$")


def filename_suffixes(file_name: str) -> list[str]:
    """Return safe suffix candidates while preserving compound extensions.

    Examples:
    - archive.tar.gz -> [".tar.gz", ".gz"] instead of [".tar", ".gz"]
    - invoice.pdf.exe.zip -> includes ".exe" and keeps the true final suffix ".zip" last

    The last item is always the true final suffix when one exists. Compound
    candidates come first so custom blocklists such as .tar.gz can match.
    """
    clean_name = compact_scan_name(file_name).casefold()
    if "." not in clean_name:
        return []

    raw_parts = clean_name.split(".")
    ext_parts = raw_parts[1:]
    if not ext_parts or any(part == "" for part in ext_parts):
        candidates = [f".{part}" for part in ext_parts if _SUFFIX_TOKEN_RE.fullmatch(part)]
        return list(dict.fromkeys(_normalize_extension(ext) for ext in candidates))

    ext_parts = [part for part in ext_parts if _SUFFIX_TOKEN_RE.fullmatch(part)]
    if not ext_parts:
        return []

    final_ext = f".{ext_parts[-1]}"
    candidates: list[str] = []

    # Compound endings, excluding the final single suffix which is appended last.
    for start in range(0, max(len(ext_parts) - 1, 0)):
        compound = "." + ".".join(ext_parts[start:])
        if 2 <= len(compound) <= 64:
            candidates.append(compound)

    # Include individual non-final suffixes so invoice.exe.zip and
    # invoice.pdf.exe.zip both catch the hidden .exe before the archive suffix.
    # Harmless compound archives such as .tar.gz remain safe because .tar is not
    # in DANGEROUS_EXTENSIONS by default.
    if len(ext_parts) >= 2:
        for part in ext_parts[:-1]:
            candidates.append(f".{part}")

    candidates.append(final_ext)
    return list(dict.fromkeys(_normalize_extension(ext) for ext in candidates))


def describe_scan_reason(reason_code: str, details: Iterable[str]) -> str:
    detail_text = "; ".join(str(d) for d in details if str(d).strip())
    return h(detail_text or reason_code.replace("_", " "))


def scan_filename_only(file_name: str | None, mime_type: str | None = None) -> FileScanResult:
    original_name = normalize_filename(file_name)
    clean_name = compact_scan_name(original_name)
    lower_name = clean_name.casefold()
    mime = (mime_type or "").casefold().strip()
    suffixes = filename_suffixes(clean_name)
    details: list[str] = []

    had_unicode_trick = clean_name != normalize_filename(original_name)
    if had_unicode_trick:
        details.append("filename contains invisible Unicode control characters")

    # 1) Direct hard block extensions, including setup.exe and setup.exe.
    for ext in BLOCKED_EXTENSIONS:
        if lower_name.endswith(ext):
            return FileScanResult(True, "blocked_extension", f"blocked extension {ext}", tuple(details + [f"matched {ext}"]), clean_name, mime, ext)

    # 2) Suspicious scanner checks: dangerous extensions and misleading names.
    if SUSPICIOUS_SCANNER_ENABLED:
        dangerous_in_name = [ext for ext in suffixes if ext in DANGEROUS_EXTENSIONS]
        last_ext = suffixes[-1] if suffixes else ""

        if dangerous_in_name:
            matched = dangerous_in_name[-1]
            if last_ext == matched:
                return FileScanResult(True, "dangerous_extension", f"dangerous extension {matched}", tuple(details + [f"matched {matched}"]), clean_name, mime, matched)
            if last_ext in ARCHIVE_EXTENSIONS:
                return FileScanResult(True, "dangerous_inside_archive_name", f"dangerous extension {matched} hidden before archive suffix {last_ext}", tuple(details + [f"suffix chain: {' '.join(suffixes)}"]), clean_name, mime, matched)
            return FileScanResult(True, "misleading_double_extension", f"dangerous extension {matched} hidden inside filename", tuple(details + [f"suffix chain: {' '.join(suffixes)}"]), clean_name, mime, matched)

        # Names like "invoice.pdf________________________.exe" are already caught above;
        # this catches misleading long extension chains without a dangerous suffix.
        if len(suffixes) >= 3 and last_ext in ARCHIVE_EXTENSIONS:
            details.append(f"long archive suffix chain: {' '.join(suffixes)}")

        if had_unicode_trick:
            return FileScanResult(True, "unicode_extension_trick", "filename contains invisible Unicode extension-trick characters", tuple(details), clean_name, mime)

    # 3) MIME block list from Telegram metadata.
    if mime and mime in BLOCKED_MIME_TYPES:
        return FileScanResult(True, "blocked_mime", f"blocked MIME type {mime}", tuple(details + [f"mime {mime}"]), clean_name, mime)

    return FileScanResult(False, "clean", "no suspicious filename or MIME match", tuple(details), clean_name, mime)


def scan_file_bytes(file_name: str, mime_type: str, data: bytes) -> FileScanResult | None:
    if not data:
        return None

    details: list[str] = []
    lower_name = compact_scan_name(file_name).casefold()

    try:
        if data.startswith(b"MZ"):
            return FileScanResult(True, "pe_magic_header", "file content starts with Windows executable MZ header", ("matched MZ header",), file_name, mime_type, ".exe")
        if data.startswith(b"\x7fELF"):
            return FileScanResult(True, "elf_magic_header", "file content starts with ELF executable header", ("matched ELF header",), file_name, mime_type)
        if data[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}:
            return FileScanResult(True, "macho_magic_header", "file content starts with Mach-O executable header", ("matched Mach-O header",), file_name, mime_type)
        if data.startswith(b"#!") and any(token in data[:256].lower() for token in (b"/sh", b"bash", b"python", b"node", b"powershell", b"cmd")):
            return FileScanResult(True, "script_shebang", "file content starts with executable script shebang", ("matched script shebang",), file_name, mime_type)
    except Exception:
        logger.exception("Magic-byte scan failed for %r", file_name, exc_info=True)
        return None

    if not SUSPICIOUS_ARCHIVE_SCAN_ENABLED:
        return None

    suffixes = filename_suffixes(lower_name)
    may_be_zip = data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08") or (suffixes and suffixes[-1] == ".zip")
    if may_be_zip:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()[:MAX_ARCHIVE_MEMBERS_TO_SCAN]
        except (zipfile.BadZipFile, RuntimeError, OSError):
            logger.info("Archive scan skipped for non-readable ZIP file %r", file_name)
            return None

        for member in names:
            try:
                result = scan_filename_only(member, "")
            except Exception:
                logger.exception("Archive member scan failed for %r in %r", member, file_name, exc_info=True)
                continue
            if result.blocked:
                details.append(f"archive contains suspicious member: {member}")
                return FileScanResult(
                    True,
                    "archive_contains_dangerous_file",
                    f"archive contains dangerous file name: {member}",
                    tuple(details),
                    file_name,
                    mime_type,
                    result.matched_extension,
                )

    return None


async def _download_document_bytes_for_scanner(
    context: ContextTypes.DEFAULT_TYPE,
    document: Any,
    *,
    file_name: str,
    file_size: int,
    max_bytes: int | None = None,
) -> bytes | None:
    """Download a Telegram document only when it stays inside the active scanner limit."""
    limit = min(int(max_bytes or max(file_size, 1)), TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES)
    if file_size <= 0:
        logger.warning("Scanner download skipped; missing Telegram file_size file_name=%r", file_name)
        return None
    if file_size > TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES:
        logger.warning(
            "Scanner download skipped; Telegram Bot API file-size limit exceeded file_name=%r size=%s limit=%s",
            file_name,
            file_size,
            TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES,
        )
        return None
    if file_size > limit:
        logger.info("Scanner download skipped; metadata size exceeds active limit file_name=%r size=%s limit=%s", file_name, file_size, limit)
        return None

    for attempt in (1, 2):
        try:
            async with SCAN_DOWNLOAD_SEMAPHORE:
                tg_file = await context.bot.get_file(document.file_id)
                actual_size = int(getattr(tg_file, "file_size", 0) or file_size or 0)
                if actual_size > TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES:
                    logger.warning(
                        "Scanner download skipped; get_file reported size above Bot API limit file_name=%r size=%s limit=%s",
                        file_name,
                        actual_size,
                        TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES,
                    )
                    return None
                if actual_size > 0 and actual_size > limit:
                    logger.info("Scanner download skipped; Telegram file size exceeds active limit file_name=%r size=%s limit=%s", file_name, actual_size, limit)
                    return None
                data = bytes(await tg_file.download_as_bytearray())
                if len(data) > limit:
                    logger.warning("Scanner download discarded; downloaded bytes exceed limit file_name=%r bytes=%s limit=%s", file_name, len(data), limit)
                    return None
                return data
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="scanner_download"):
                continue
            logger.exception("Scanner download hit RetryAfter file_name=%r size=%s", file_name, file_size, exc_info=True)
            return None
        except (TimedOut, BadRequest, Forbidden, TelegramError):
            logger.exception("Could not download file for scanner file_name=%r size=%s", file_name, file_size, exc_info=True)
            return None
        except Exception:
            logger.exception("Unexpected scanner download failure file_name=%r size=%s", file_name, file_size, exc_info=True)
            return None
    return None


async def scan_document(context: ContextTypes.DEFAULT_TYPE, document: Any, *, chat_id: int | None = None) -> FileScanResult:
    """Suspicious file scanner that supports group trusted SHA256 whitelist."""
    file_name = normalize_filename(getattr(document, "file_name", None))
    mime_type = (getattr(document, "mime_type", "") or "").casefold().strip()

    try:
        result = scan_filename_only(file_name, mime_type)
    except Exception:
        logger.exception("Filename scanner crashed file_name=%r", file_name, exc_info=True)
        return FileScanResult(False, "scanner_error", "scanner skipped after filename parser error", (), file_name, mime_type)

    file_size = int(getattr(document, "file_size", 0) or 0)
    if file_size > TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES:
        if result.blocked:
            logger.warning(
                "Large document blocked by filename/MIME policy without byte download file_name=%r size=%s limit=%s reason=%s",
                file_name,
                file_size,
                TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES,
                result.reason_code,
            )
        else:
            logger.warning(
                "Scanner byte/hash analysis disabled; document exceeds Telegram Bot API download limit file_name=%r size=%s limit=%s",
                file_name,
                file_size,
                TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES,
            )
    can_download_for_hash = bool(
        trusted_hash_whitelist_enabled(context.bot_data)
        and chat_id is not None
        and file_size > 0
        and file_size <= trusted_hash_max_download_bytes(context.bot_data)
        and file_size <= TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES
    )
    can_download_for_magic = bool(
        SUSPICIOUS_SCANNER_ENABLED
        and SUSPICIOUS_MAGIC_SCAN_ENABLED
        and SCANNER_MAX_DOWNLOAD_BYTES > 0
        and file_size > 0
        and file_size <= SCANNER_MAX_DOWNLOAD_BYTES
        and file_size <= TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES
    )

    if result.blocked and not can_download_for_hash:
        return result
    if not (can_download_for_hash or can_download_for_magic):
        return result

    download_limit = max(
        trusted_hash_max_download_bytes(context.bot_data) if can_download_for_hash else 0,
        SCANNER_MAX_DOWNLOAD_BYTES if can_download_for_magic else 0,
    )
    data = await _download_document_bytes_for_scanner(context, document, file_name=file_name, file_size=file_size, max_bytes=download_limit)
    if data is None:
        return result

    file_sha256 = await calculate_file_hash_async(data)
    result = replace(result, file_sha256=file_sha256, details=tuple([*result.details, f"sha256:{file_sha256}"]))

    if chat_id is not None:
        try:
            async with BOT_DATA_LOCK:
                if is_trusted_file_hash(context.bot_data, chat_id, file_sha256):
                    return FileScanResult(
                        False,
                        "trusted_hash_whitelist",
                        "allowed by trusted SHA256 file hash whitelist",
                        (f"sha256:{file_sha256}",),
                        result.file_name,
                        result.mime_type,
                        result.matched_extension,
                        file_sha256,
                    )
        except Exception:
            logger.exception("Trusted hash whitelist check failed chat_id=%s file_name=%r", chat_id, file_name, exc_info=True)

    if result.blocked and not can_download_for_magic:
        return result

    if can_download_for_magic:
        try:
            magic_result = await scan_file_bytes_async(result.file_name, result.mime_type, data)
            if magic_result is not None:
                return replace(magic_result, file_sha256=file_sha256, details=tuple([*magic_result.details, f"sha256:{file_sha256}"]))
            return result
        except Exception:
            logger.exception("Byte scanner crashed file_name=%r", file_name, exc_info=True)
            return result

    return result

def now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def incident_key(chat_id: int, sender_id: int, message_id: int) -> str:
    # Include randomness to avoid millisecond collision under high concurrency.
    return f"{chat_id}:{sender_id}:{message_id}:{now_ms()}:{secrets.token_urlsafe(8)}"


def incident_timestamp_ms(ikey: str) -> int | None:
    try:
        parts = str(ikey).rsplit(":", 2)
        # New keys end with :timestamp:random. Legacy keys end with :timestamp.
        candidate = parts[-2] if len(parts) >= 2 and not parts[-1].isdigit() else parts[-1]
        return int(candidate)
    except (TypeError, ValueError, IndexError):
        return None


async def get_incident_lock(ikey: str) -> asyncio.Lock:
    async with INCIDENT_LOCKS_LOCK:
        lock = INCIDENT_LOCKS.get(ikey)
        if lock is None:
            lock = asyncio.Lock()
            INCIDENT_LOCKS[ikey] = lock
        return lock


async def _sleep_for_retry_after(exc: RetryAfter, *, operation: str) -> bool:
    delay = float(getattr(exc, "retry_after", 0) or 0)
    if TELEGRAM_RETRY_AFTER_MAX_SECONDS <= 0 or delay > TELEGRAM_RETRY_AFTER_MAX_SECONDS:
        logger.warning("Telegram RetryAfter for %s was %.2fs; not retrying", operation, delay, exc_info=True)
        return False
    logger.warning("Telegram RetryAfter for %s: sleeping %.2fs before one retry", operation, delay, exc_info=True)
    await asyncio.sleep(delay + 0.25)
    return True


async def safe_answer_callback(query: Any, text: str | None = None, *, show_alert: bool = False) -> None:
    """Answer callback queries immediately without blocking heavy callback flows.

    Callback acknowledgements clear Telegram's mobile loading spinner.  This
    helper must not sleep/retry on RetryAfter because callbacks call it before
    permission checks, cache refreshes, and persistence scheduling.
    """
    if query is None:
        return
    try:
        await query.answer(text=text, show_alert=show_alert)
    except RetryAfter as exc:
        delay = float(getattr(exc, "retry_after", 0) or 0)
        logger.warning(
            "Callback answer rate-limited retry_after=%.2fs; skipping retry to keep callback responsive",
            delay,
            exc_info=True,
        )
    except BadRequest as exc:
        # Stale callbacks are common when an old inline keyboard is tapped.
        lowered = str(exc).casefold()
        if "query is too old" not in lowered and "query_id_invalid" not in lowered:
            logger.debug("callback answer skipped: %s", exc)
    except TelegramError:
        logger.debug("callback answer failed", exc_info=True)
    except Exception:
        logger.exception("Unexpected callback answer failure", exc_info=True)


async def safe_send_message_result(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
    disable_web_page_preview: bool = True,
    operation: str = "send_message",
) -> SendMessageResult:
    for attempt in (1, 2):
        try:
            sent = await context.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode=ParseMode.HTML,
                reply_markup=reply_markup,
                disable_web_page_preview=disable_web_page_preview,
            )
            return SendMessageResult(ok=True, message_id=int(sent.message_id))
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation=operation):
                continue
            return SendMessageResult(
                ok=False,
                error=f"Telegram rate limit exceeded for {operation}",
                error_type="retry_after",
                retryable=True,
            )
        except Forbidden as exc:
            logger.warning("%s forbidden chat_id=%s: %s", operation, chat_id, exc)
            return SendMessageResult(
                ok=False,
                error=str(exc),
                error_type="forbidden",
                permission_error=True,
            )
        except BadRequest as exc:
            logger.exception("%s BadRequest chat_id=%s", operation, chat_id, exc_info=True)
            return SendMessageResult(ok=False, error=str(exc), error_type="bad_request")
        except TimedOut as exc:
            logger.exception("%s timed out chat_id=%s", operation, chat_id, exc_info=True)
            return SendMessageResult(ok=False, error=str(exc), error_type="timed_out", retryable=True)
        except TelegramError as exc:
            logger.exception("%s failed chat_id=%s", operation, chat_id, exc_info=True)
            return SendMessageResult(ok=False, error=str(exc), error_type="telegram_error")
        except Exception as exc:
            logger.exception("Unexpected %s failure chat_id=%s", operation, chat_id, exc_info=True)
            return SendMessageResult(ok=False, error=str(exc), error_type="unexpected")
    return SendMessageResult(ok=False, error="unknown send failure", error_type="unknown")


async def safe_send_message(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
    disable_web_page_preview: bool = True,
) -> int | None:
    result = await safe_send_message_result(
        context,
        chat_id,
        text,
        reply_markup=reply_markup,
        disable_web_page_preview=disable_web_page_preview,
    )
    return result.message_id if result.ok else None


async def auto_delete_message_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    data = context.job.data if context.job else {}
    if not isinstance(data, dict):
        return
    try:
        chat_id = int(data.get("chat_id"))
        message_id = int(data.get("message_id"))
    except (TypeError, ValueError):
        return
    try:
        await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
    except BadRequest as exc:
        text = str(exc).casefold()
        if "message to delete not found" not in text and "message can't be deleted" not in text:
            logger.info("Auto-delete notice failed chat_id=%s message_id=%s: %s", chat_id, message_id, exc)
    except (Forbidden, TimedOut, TelegramError) as exc:
        logger.info("Auto-delete notice skipped chat_id=%s message_id=%s: %s", chat_id, message_id, exc)
    except Exception:
        logger.exception("Unexpected auto-delete notice failure chat_id=%s message_id=%s", chat_id, message_id, exc_info=True)


def schedule_auto_delete_message(
    context: ContextTypes.DEFAULT_TYPE,
    *,
    chat_id: int,
    message_id: int | None,
    delay_seconds: int = SILENT_MODE_NOTICE_DELETE_SECONDS,
) -> None:
    if not message_id:
        return
    if not context.application.job_queue:
        logger.warning("JobQueue unavailable; cannot auto-delete silent-mode notice chat_id=%s message_id=%s", chat_id, message_id)
        return
    context.application.job_queue.run_once(
        auto_delete_message_job,
        when=max(1, int(delay_seconds)),
        data={"chat_id": int(chat_id), "message_id": int(message_id)},
        name=f"auto_delete_notice:{int(chat_id)}:{int(message_id)}",
    )


async def safe_reply(update: Update, text: str, *, reply_markup: InlineKeyboardMarkup | None = None) -> None:
    message = update.effective_message
    if not message:
        return
    for attempt in (1, 2):
        try:
            await message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=reply_markup, disable_web_page_preview=True)
            return
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="reply_text"):
                continue
            return
        except TelegramError:
            logger.exception("reply failed", exc_info=True)
            return
        except Exception:
            logger.exception("Unexpected reply failure", exc_info=True)
            return


async def safe_edit_query(query: Any, text: str, *, reply_markup: InlineKeyboardMarkup | None = None) -> None:
    for attempt in (1, 2):
        try:
            await query.edit_message_text(
                text=text,
                parse_mode=ParseMode.HTML,
                reply_markup=reply_markup,
                disable_web_page_preview=True,
            )
            return
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="edit_message_text"):
                continue
            return
        except BadRequest as exc:
            if "message is not modified" not in str(exc).casefold():
                logger.exception("edit_message_text failed", exc_info=True)
            return
        except TelegramError:
            logger.exception("edit_message_text failed", exc_info=True)
            return
        except Exception:
            logger.exception("Unexpected edit_message_text failure", exc_info=True)
            return


async def safe_edit_message(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    message_id: int,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> None:
    for attempt in (1, 2):
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=text,
                parse_mode=ParseMode.HTML,
                reply_markup=reply_markup,
                disable_web_page_preview=True,
            )
            return
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="edit_message_text"):
                continue
            return
        except BadRequest as exc:
            if "message is not modified" not in str(exc).casefold():
                logger.exception("edit_message_text failed chat_id=%s message_id=%s", chat_id, message_id, exc_info=True)
            return
        except TelegramError:
            logger.exception("edit_message_text failed chat_id=%s message_id=%s", chat_id, message_id, exc_info=True)
            return
        except Exception:
            logger.exception("Unexpected edit_message_text failure chat_id=%s message_id=%s", chat_id, message_id, exc_info=True)
            return


# ─────────────────────────────────────────────────────────────
# TELEGRAM API CACHE HELPERS
# ─────────────────────────────────────────────────────────────


async def get_bot_identity(bot: Any) -> tuple[int, str]:
    global BOT_ID, BOT_USERNAME
    if BOT_ID is not None and BOT_USERNAME is not None:
        return BOT_ID, BOT_USERNAME
    me = await bot.get_me()
    BOT_ID = int(me.id)
    BOT_USERNAME = me.username or ""
    return BOT_ID, BOT_USERNAME


def build_add_group_url(username: str | None = None, *, request_admin: bool = True) -> str:
    """Build a Telegram add-to-group URL.

    When request_admin=True, Telegram opens the add flow with the key
    permissions the security bot needs. Some Telegram clients may ignore the
    admin parameter, so the locked panel still tells admins to enable Delete
    Messages manually.
    """
    uname = (username or BOT_USERNAME or "").strip().lstrip("@")
    if not uname:
        return "https://t.me/"
    base = f"https://t.me/{uname}?startgroup=add"
    if request_admin:
        return base + "&admin=delete_messages+restrict_members"
    return base


def build_add_group_url_from_state(*, request_admin: bool = True) -> str:
    return build_add_group_url(BOT_USERNAME, request_admin=request_admin)


def _cache_now_ms() -> int:
    # Wall-clock milliseconds survive restarts better than time.monotonic() when
    # cache metadata is kept in bot_data / persistence.
    return now_ms()


def _bot_data_cache_bucket(bot_data: dict[str, Any], name: str) -> dict[str, Any]:
    bucket = bot_data.setdefault(name, {})
    if not isinstance(bucket, dict):
        bucket = {}
        bot_data[name] = bucket
    return bucket


async def remember_chat_meta(bot_data: dict[str, Any], chat: Any) -> None:
    if not chat:
        return
    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(bot_data, "chat_meta_cache")
        bucket[str(int(chat.id))] = {
            "id": int(chat.id),
            "title": getattr(chat, "title", None) or getattr(chat, "full_name", None) or str(chat.id),
            "type": str(getattr(chat, "type", "")),
            "updated_at_ms": _cache_now_ms(),
        }


def get_chat_title_from_state(bot_data: dict[str, Any], chat_id: int) -> str:
    cid = int(chat_id)
    meta = bot_data.get("chat_meta_cache", {})
    if isinstance(meta, dict):
        item = meta.get(str(cid)) or meta.get(cid)
        if isinstance(item, dict) and item.get("title"):
            return str(item["title"])
    group = bot_data.get("group_state", {})
    if isinstance(group, dict):
        state = group.get(str(cid)) or group.get(cid)
        if isinstance(state, dict):
            for key in ("title", "group_name", "chat_title"):
                if state.get(key):
                    return str(state[key])
    return str(cid)


async def get_chat_title_cached(context: ContextTypes.DEFAULT_TYPE, chat_id: int, *, force: bool = False) -> str:
    """Cached chat title lookup for dashboard rendering.

    Dashboard code should call this instead of context.bot.get_chat().  It only
    hits Telegram when force=True or no cached title exists yet, then stores the
    simple metadata in bot_data so persistence can survive restarts.
    """
    title = get_chat_title_from_state(context.bot_data, chat_id)
    if title != str(chat_id) and not force:
        return title

    for attempt in (1, 2):
        try:
            chat = await context.bot.get_chat(chat_id)
            await remember_chat_meta(context.bot_data, chat)
            return str(chat.title or chat_id)
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="get_chat"):
                continue
            return title
        except TelegramError:
            logger.exception("Could not refresh chat metadata chat_id=%s", chat_id, exc_info=True)
            return title
        except Exception:
            logger.exception("Unexpected chat metadata refresh failure chat_id=%s", chat_id, exc_info=True)
            return title
    return title


async def get_chat_admin_ids_from_state(bot_data: dict[str, Any], chat_id: int) -> list[int]:
    """Read persisted admin IDs only; never calls Telegram.

    Used by offline dashboard rendering and returned as a copy to avoid cache
    mutability leaks.
    """
    ids, _, _ = await get_chat_admin_ids_state_snapshot(bot_data, chat_id)
    return ids.copy()



def _parse_admin_ids(raw_ids: Any) -> list[int]:
    parsed: list[int] = []
    if not isinstance(raw_ids, list):
        return parsed
    for item in raw_ids:
        try:
            parsed.append(int(item))
        except (TypeError, ValueError):
            continue
    return parsed.copy()


async def get_chat_admin_ids_state_snapshot(bot_data: dict[str, Any], chat_id: int) -> tuple[list[int], bool, bool]:
    """Return (ids_copy, cache_exists, is_fresh) from durable bot_data only.

    This never calls Telegram and never returns mutable cache references.
    """
    now_wall = _cache_now_ms()
    async with BOT_DATA_LOCK:
        bucket = bot_data.get("admin_ids_cache")
        if not isinstance(bucket, dict):
            return [], False, False
        cached_state = bucket.get(str(int(chat_id))) or bucket.get(int(chat_id))
        if not isinstance(cached_state, dict):
            return [], False, False
        ids = _parse_admin_ids(cached_state.get("ids", []))
        try:
            fresh = int(cached_state.get("expires_at_ms", 0)) > now_wall
        except (TypeError, ValueError):
            fresh = False
        return ids.copy(), True, fresh


async def update_admin_member_cache(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    user_id: int,
    *,
    is_admin: bool,
    persist: bool = True,
) -> list[int]:
    """Update one user's admin membership in process + durable caches.

    Returns a copy of the updated IDs and never exposes mutable cache internals.
    """
    chat_id = int(chat_id)
    user_id = int(user_id)
    ids, _, _ = await get_chat_admin_ids_state_snapshot(context.bot_data, chat_id)
    id_set = {int(x) for x in ids}
    if is_admin:
        id_set.add(user_id)
    else:
        id_set.discard(user_id)
    updated_ids = sorted(id_set)
    expires_at_ms = _cache_now_ms() + ADMIN_CACHE_TTL_SECONDS * 1000

    async with ADMIN_CACHE_LOCK:
        ADMIN_IDS_CACHE[chat_id] = CacheItem(updated_ids.copy(), time.monotonic() + ADMIN_CACHE_TTL_SECONDS)

    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(context.bot_data, "admin_ids_cache")
        bucket[str(chat_id)] = {"ids": updated_ids.copy(), "expires_at_ms": expires_at_ms}
        if persist:
            await persist_context_memory(context, reason="admin_member_cache_update", force=False, caller_holds_lock=True)

    return updated_ids.copy()




def _telegram_error_text(exc: BaseException) -> str:
    return str(exc or "").casefold()


def _is_lost_chat_access_error(exc: BaseException) -> bool:
    """Return True for Telegram errors that mean this bot cannot access chat anymore."""
    text = _telegram_error_text(exc)
    return isinstance(exc, Forbidden) and any(
        needle in text
        for needle in (
            "bot was kicked",
            "bot is not a member",
            "forbidden: bot was kicked",
            "forbidden: bot is not a member",
            "chat not found",
        )
    )


def _inaccessible_chats_bucket(bot_data: dict[str, Any]) -> dict[str, Any]:
    return _bot_data_cache_bucket(bot_data, "inaccessible_chats")


def get_chat_inaccessible_record(bot_data: dict[str, Any], chat_id: int) -> dict[str, Any] | None:
    bucket = bot_data.get("inaccessible_chats")
    if not isinstance(bucket, dict):
        return None
    record = bucket.get(str(int(chat_id))) or bucket.get(int(chat_id))
    return record if isinstance(record, dict) else None


def is_chat_api_suppressed(bot_data: dict[str, Any], chat_id: int) -> bool:
    record = get_chat_inaccessible_record(bot_data, chat_id)
    if not record:
        return False
    try:
        until_ms = int(record.get("suppress_until_ms", 0) or 0)
    except (TypeError, ValueError):
        return False
    return until_ms > now_ms()


async def mark_chat_inaccessible(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    *,
    reason: str,
    purge: bool = True,
) -> None:
    """Remember a removed/inaccessible chat and optionally wipe linked group state.

    This stops repeated get_chat_member/get_chat_administrators calls after the
    bot is kicked.  my_chat_member_update clears this marker as soon as Telegram
    reports that the bot was added back.
    """
    chat_id = int(chat_id)
    chat_key = str(chat_id)
    async with BOT_DATA_LOCK:
        bucket = _inaccessible_chats_bucket(context.bot_data)
        bucket[chat_key] = {
            "reason": str(reason or "lost_access"),
            "marked_at_ms": now_ms(),
            "suppress_until_ms": now_ms() + INACCESSIBLE_CHAT_API_SUPPRESS_SECONDS * 1000,
        }
        await persist_context_memory(context, reason="chat_inaccessible_marked", force=True, caller_holds_lock=True)
    if purge:
        await purge_group_state(context, chat_id, reason=reason)


async def clear_chat_inaccessible(context: ContextTypes.DEFAULT_TYPE, chat_id: int, *, persist: bool = True) -> None:
    chat_id = int(chat_id)
    async with BOT_DATA_LOCK:
        bucket = context.bot_data.get("inaccessible_chats")
        if isinstance(bucket, dict):
            bucket.pop(str(chat_id), None)
            bucket.pop(chat_id, None)
        if persist:
            await persist_context_memory(context, reason="chat_inaccessible_cleared", force=True, caller_holds_lock=True)

async def get_chat_admin_ids_cached(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    *,
    force: bool = False,
    allow_api: bool = True,
) -> list[int]:
    chat_id = int(chat_id)
    now_wall = _cache_now_ms()

    async with ADMIN_CACHE_LOCK:
        cached = ADMIN_IDS_CACHE.get(chat_id)
        if cached and not force and cached.expires_at > time.monotonic():
            return list(cached.value)

    ids_from_state: list[int] | None = None
    corrupt_state = False
    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(context.bot_data, "admin_ids_cache")
        cached_state = bucket.get(str(chat_id))
        if isinstance(cached_state, dict) and not force:
            try:
                if int(cached_state.get("expires_at_ms", 0)) > now_wall:
                    ids_from_state = _parse_admin_ids(cached_state.get("ids", []))
            except (TypeError, ValueError):
                bucket.pop(str(chat_id), None)
                corrupt_state = True
                await persist_context_memory(context, reason="admin_cache_corrupt_pruned", force=True, caller_holds_lock=True)

    if ids_from_state is not None:
        async with ADMIN_CACHE_LOCK:
            ADMIN_IDS_CACHE[chat_id] = CacheItem(ids_from_state.copy(), time.monotonic() + ADMIN_CACHE_TTL_SECONDS)
        return ids_from_state.copy()

    if not allow_api:
        return await get_chat_admin_ids_from_state(context.bot_data, chat_id)

    if is_chat_api_suppressed(context.bot_data, chat_id):
        return await get_chat_admin_ids_from_state(context.bot_data, chat_id)

    ids: list[int] | None = None
    for attempt in (1, 2):
        try:
            admins = await context.bot.get_chat_administrators(chat_id)
            ids = [int(a.user.id) for a in admins if not a.user.is_bot]
            break
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="get_chat_administrators"):
                continue
            logger.exception("Admin fetch hit RetryAfter chat_id=%s", chat_id, exc_info=True)
            return await get_chat_admin_ids_from_state(context.bot_data, chat_id)
        except (TimedOut, BadRequest, Forbidden, TelegramError) as exc:
            if _is_lost_chat_access_error(exc):
                logger.info("Admin fetch skipped; bot lost access to chat_id=%s: %s", chat_id, exc)
                await mark_chat_inaccessible(context, chat_id, reason="admin_fetch_lost_access", purge=True)
            else:
                logger.exception("Could not fetch admins for chat_id=%s", chat_id, exc_info=True)
            return await get_chat_admin_ids_from_state(context.bot_data, chat_id)
        except Exception:
            logger.exception("Unexpected admin fetch failure chat_id=%s", chat_id, exc_info=True)
            return await get_chat_admin_ids_from_state(context.bot_data, chat_id)
    if ids is None:
        return await get_chat_admin_ids_from_state(context.bot_data, chat_id)

    async with ADMIN_CACHE_LOCK:
        ADMIN_IDS_CACHE[chat_id] = CacheItem(ids.copy(), time.monotonic() + ADMIN_CACHE_TTL_SECONDS)
    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(context.bot_data, "admin_ids_cache")
        bucket[str(chat_id)] = {"ids": ids.copy(), "expires_at_ms": now_wall + ADMIN_CACHE_TTL_SECONDS * 1000}
        await persist_context_memory(context, reason="admin_cache_refresh", force=False, caller_holds_lock=True)
    return ids.copy()


def get_bot_member_from_state(bot_data: dict[str, Any], chat_id: int) -> BotPerms | None:
    """Read cached bot permissions only; never calls Telegram."""
    bucket = bot_data.get("bot_member_cache")
    if not isinstance(bucket, dict):
        return None
    cached_state = bucket.get(str(int(chat_id))) or bucket.get(int(chat_id))
    if not isinstance(cached_state, dict):
        return None
    return BotPerms(
        status=str(cached_state.get("status", "")),
        can_delete_messages=bool(cached_state.get("can_delete_messages", False)),
        can_restrict_members=bool(cached_state.get("can_restrict_members", False)),
    )


async def get_bot_member_cached(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    *,
    force: bool = False,
    allow_api: bool = True,
) -> BotPerms:
    chat_id = int(chat_id)
    now_wall = _cache_now_ms()

    async with BOT_MEMBER_CACHE_LOCK:
        cached = BOT_MEMBER_CACHE.get(chat_id)
        if cached and not force and cached.expires_at > time.monotonic():
            return cached.value

    perms_from_state: BotPerms | None = None
    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(context.bot_data, "bot_member_cache")
        cached_state = bucket.get(str(chat_id))
        if isinstance(cached_state, dict) and not force:
            try:
                if int(cached_state.get("expires_at_ms", 0)) > now_wall:
                    perms_from_state = BotPerms(
                        status=str(cached_state.get("status", "")),
                        can_delete_messages=bool(cached_state.get("can_delete_messages", False)),
                        can_restrict_members=bool(cached_state.get("can_restrict_members", False)),
                    )
            except (TypeError, ValueError):
                bucket.pop(str(chat_id), None)
                await persist_context_memory(context, reason="bot_member_cache_corrupt_pruned", force=True, caller_holds_lock=True)

    if perms_from_state is not None:
        async with BOT_MEMBER_CACHE_LOCK:
            BOT_MEMBER_CACHE[chat_id] = CacheItem(perms_from_state, time.monotonic() + BOT_MEMBER_CACHE_TTL_SECONDS)
        return perms_from_state

    if not allow_api:
        cached_perms = get_bot_member_from_state(context.bot_data, chat_id)
        return cached_perms or BotPerms(status="unknown", can_delete_messages=False, can_restrict_members=False)

    if is_chat_api_suppressed(context.bot_data, chat_id):
        cached_perms = get_bot_member_from_state(context.bot_data, chat_id)
        return cached_perms or BotPerms(status="left", can_delete_messages=False, can_restrict_members=False)

    perms: BotPerms | None = None
    for attempt in (1, 2):
        try:
            bot_id, _ = await get_bot_identity(context.bot)
            member = await context.bot.get_chat_member(chat_id, bot_id)
            perms = BotPerms(
                status=str(member.status),
                can_delete_messages=bool(getattr(member, "can_delete_messages", False)),
                can_restrict_members=bool(getattr(member, "can_restrict_members", False)),
            )
            break
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="get_chat_member:bot"):
                continue
            logger.exception("Bot member refresh hit RetryAfter chat_id=%s", chat_id, exc_info=True)
            cached_perms = get_bot_member_from_state(context.bot_data, chat_id)
            return cached_perms or BotPerms(status="unknown", can_delete_messages=False, can_restrict_members=False)
        except (TimedOut, BadRequest, Forbidden, TelegramError) as exc:
            if _is_lost_chat_access_error(exc):
                logger.info("Bot member refresh skipped; bot lost access to chat_id=%s: %s", chat_id, exc)
                await mark_chat_inaccessible(context, chat_id, reason="bot_member_lost_access", purge=True)
                return BotPerms(status="left", can_delete_messages=False, can_restrict_members=False)
            logger.exception("Could not refresh bot member status chat_id=%s", chat_id, exc_info=True)
            cached_perms = get_bot_member_from_state(context.bot_data, chat_id)
            return cached_perms or BotPerms(status="unknown", can_delete_messages=False, can_restrict_members=False)
        except Exception:
            logger.exception("Unexpected bot member status refresh failure chat_id=%s", chat_id, exc_info=True)
            cached_perms = get_bot_member_from_state(context.bot_data, chat_id)
            return cached_perms or BotPerms(status="unknown", can_delete_messages=False, can_restrict_members=False)
    if perms is None:
        cached_perms = get_bot_member_from_state(context.bot_data, chat_id)
        return cached_perms or BotPerms(status="unknown", can_delete_messages=False, can_restrict_members=False)

    async with BOT_MEMBER_CACHE_LOCK:
        BOT_MEMBER_CACHE[chat_id] = CacheItem(perms, time.monotonic() + BOT_MEMBER_CACHE_TTL_SECONDS)
    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(context.bot_data, "bot_member_cache")
        bucket[str(chat_id)] = {
            "status": perms.status,
            "can_delete_messages": perms.can_delete_messages,
            "can_restrict_members": perms.can_restrict_members,
            "expires_at_ms": now_wall + BOT_MEMBER_CACHE_TTL_SECONDS * 1000,
        }
        await persist_context_memory(context, reason="bot_member_cache_refresh", force=False, caller_holds_lock=True)
    return perms




async def refresh_bot_member_status_silent(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    """Self-heal cached bot permissions without blocking UI rendering."""
    try:
        await get_bot_member_cached(context, int(chat_id), allow_api=True)
    except (TimedOut, BadRequest, Forbidden, TelegramError) as exc:
        if _is_lost_chat_access_error(exc):
            logger.info("Silent bot permission refresh skipped; chat inaccessible chat_id=%s: %s", chat_id, exc)
            return
        logger.exception("Silent bot permission refresh failed chat_id=%s", chat_id, exc_info=True)
    except Exception:
        logger.exception("Unexpected silent bot permission refresh failure chat_id=%s", chat_id, exc_info=True)


def schedule_bot_member_refresh(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    """Schedule a low-priority permission cache refresh."""
    try:
        context.application.create_task(refresh_bot_member_status_silent(context, int(chat_id)))
    except Exception:
        asyncio.create_task(refresh_bot_member_status_silent(context, int(chat_id)))


async def invalidate_chat_caches(chat_id: int, bot_data: dict[str, Any] | None = None) -> None:
    async with ADMIN_CACHE_LOCK:
        ADMIN_IDS_CACHE.pop(chat_id, None)
    async with BOT_MEMBER_CACHE_LOCK:
        BOT_MEMBER_CACHE.pop(chat_id, None)
    if bot_data is not None:
        async with BOT_DATA_LOCK:
            for bucket_name in ("admin_ids_cache", "bot_member_cache", "chat_meta_cache"):
                bucket = bot_data.get(bucket_name)
                if isinstance(bucket, dict):
                    bucket.pop(str(chat_id), None)
                    bucket.pop(chat_id, None)


async def purge_group_state(context: ContextTypes.DEFAULT_TYPE, chat_id: int, *, reason: str = "group_removed") -> None:
    """Hard-wipe every durable and runtime reference to a removed group."""
    chat_id = int(chat_id)
    chat_key = str(chat_id)

    async with BOT_DATA_LOCK:
        group_state = context.bot_data.get("group_state")
        if isinstance(group_state, dict):
            group_state.pop(chat_key, None)
            group_state.pop(chat_id, None)

        user_state = context.bot_data.get("user_state")
        if isinstance(user_state, dict):
            for state in list(user_state.values()):
                if not isinstance(state, dict):
                    continue
                groups = state.get("groups")
                if isinstance(groups, list):
                    state["groups"] = [g for g in groups if str(g) != chat_key]
                pending = state.get("pending_format_edit")
                if isinstance(pending, dict) and str(pending.get("chat_id")) == chat_key:
                    state.pop("pending_format_edit", None)

        incidents = context.bot_data.get("incidents")
        if isinstance(incidents, dict):
            for ikey, incident in list(incidents.items()):
                if str(ikey).startswith(f"{chat_key}:") or (isinstance(incident, dict) and str(incident.get("chat_id")) == chat_key):
                    incidents.pop(ikey, None)

        warning_counts = context.bot_data.get("warning_counts")
        if isinstance(warning_counts, dict):
            warning_counts.pop(chat_key, None)
            warning_counts.pop(chat_id, None)
            for key in list(warning_counts.keys()):
                if str(key).startswith(f"{chat_key}:"):
                    warning_counts.pop(key, None)

        for bucket_name in ("admin_ids_cache", "bot_member_cache", "chat_meta_cache"):
            bucket = context.bot_data.get(bucket_name)
            if isinstance(bucket, dict):
                bucket.pop(chat_key, None)
                bucket.pop(chat_id, None)

    async with ADMIN_CACHE_LOCK:
        ADMIN_IDS_CACHE.pop(chat_id, None)
    async with BOT_MEMBER_CACHE_LOCK:
        BOT_MEMBER_CACHE.pop(chat_id, None)
    async with INCIDENT_LOCKS_LOCK:
        for ikey in list(INCIDENT_LOCKS.keys()):
            if str(ikey).startswith(f"{chat_key}:"):
                INCIDENT_LOCKS.pop(ikey, None)

    # Persistence intentionally happens at the very end, under BOT_DATA_LOCK,
    # so the exact wiped state is what Redis/Pickle receives.
    async with BOT_DATA_LOCK:
        await persist_context_memory(context, reason="group_purged", force=True, caller_holds_lock=True)
    logger.info("Purged group state chat_id=%s reason=%s", chat_id, reason)


def has_delete_permission(perms: BotPerms) -> bool:
    return perms.status in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"} and perms.can_delete_messages


def has_ban_permission(perms: BotPerms) -> bool:
    return perms.status in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"} and perms.can_restrict_members


def bot_settings_unlocked_from_state(bot_data: dict[str, Any], chat_id: int) -> bool:
    """Settings are visible only after the bot is confirmed admin with Delete Messages."""
    if is_chat_api_suppressed(bot_data, int(chat_id)):
        return False
    perms = get_bot_member_from_state(bot_data, int(chat_id))
    return bool(perms and has_delete_permission(perms))


async def ensure_bot_settings_unlocked(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    *,
    force: bool = True,
) -> bool:
    """Refresh bot permissions and allow settings only when Delete Messages is available."""
    perms = await get_bot_member_cached(context, int(chat_id), force=force, allow_api=True)
    return has_delete_permission(perms)


def bot_admin_required_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    """Locked settings buttons for private chat before bot has admin/delete rights."""
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_add_bot_admin"), url=build_add_group_url_from_state(request_admin=True))],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_check_again"), callback_data=f"check_perm:{int(chat_id)}")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_quick_health"), callback_data=f"gap:{int(chat_id)}:health")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")],
        ]
    )


def bot_admin_required_group_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    """Locked settings buttons safe for public group messages.

    Group messages should not show private-only navigation callbacks such as
    Home/Settings. The only callback here refreshes the permission check for
    this exact group.
    """
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_add_bot_admin"), url=build_add_group_url_from_state(request_admin=True))],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_check_again"), callback_data=f"check_perm:{int(chat_id)}")],
        ]
    )


def bot_admin_required_text(bot_data: dict[str, Any], user_id: int, chat_id: int) -> str:
    title = get_chat_title_from_state(bot_data, int(chat_id))
    perms = get_bot_member_from_state(bot_data, int(chat_id)) or BotPerms("unknown", False, False)
    return tr(
        bot_data,
        user_id,
        "bot_admin_required_title",
        group=h(title),
        chat_id=int(chat_id),
        status=h(perms.status or "unknown"),
        can_delete=_yes_no(bool(perms.can_delete_messages)),
        can_restrict=_yes_no(bool(perms.can_restrict_members)),
    )


async def render_bot_admin_required_panel(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    chat_id: int,
    *,
    force_refresh: bool = False,
) -> None:
    if force_refresh:
        try:
            await get_bot_member_cached(context, int(chat_id), force=True, allow_api=True)
        except Exception:
            logger.exception("Bot permission refresh failed for locked settings panel chat_id=%s", chat_id, exc_info=True)
    async with BOT_DATA_LOCK:
        text = bot_admin_required_text(context.bot_data, user_id, int(chat_id))
        keyboard = bot_admin_required_keyboard(context.bot_data, user_id, int(chat_id))
    await send_or_edit_panel(update, text, keyboard)


# ─────────────────────────────────────────────────────────────
# KEYBOARDS
# ─────────────────────────────────────────────────────────────


def language_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("🇬🇧 English", callback_data="lang_en"), InlineKeyboardButton("🇰🇭 ភាសាខ្មែរ", callback_data="lang_km")]]
    )


async def setup_keyboard(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> InlineKeyboardMarkup:
    _, username = await get_bot_identity(context.bot)
    add_url = build_add_group_url(username, request_admin=True)
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr(context.bot_data, user_id, "add_btn"), url=add_url)],
            [InlineKeyboardButton(tr(context.bot_data, user_id, "check_btn"), callback_data="check_perm")],
        ]
    )


def ensure_incident_action_token(bot_data: dict[str, Any], ikey: str) -> str:
    """Return a compact callback token for an incident.

    Telegram callback_data is limited to 64 bytes. Full incident keys include
    chat_id, user_id, message_id, timestamp, and randomness, so using the full
    key inside ``act:ban:<ikey>`` can exceed that limit and Telegram rejects the
    inline keyboard. Store a short token instead and resolve it back to ikey in
    action_callback.
    """
    key = str(ikey or "")
    if not key:
        key = secrets.token_urlsafe(12)

    incidents = bot_data.setdefault("incidents", {})
    incident = incidents.get(key) if isinstance(incidents, dict) else None
    if isinstance(incident, dict):
        existing = str(incident.get("action_token") or "")
        if re.fullmatch(r"[A-Za-z0-9_-]{8,24}", existing):
            return existing

    tokens = bot_data.setdefault("incident_tokens", {})
    if not isinstance(tokens, dict):
        tokens = {}
        bot_data["incident_tokens"] = tokens

    for token, stored_key in list(tokens.items()):
        if str(stored_key) == key and re.fullmatch(r"[A-Za-z0-9_-]{8,24}", str(token)):
            if isinstance(incident, dict):
                incident["action_token"] = str(token)
            return str(token)

    while True:
        token = secrets.token_urlsafe(9).rstrip("=")[:12]
        if token and token not in tokens:
            break
    tokens[token] = key
    if isinstance(incident, dict):
        incident["action_token"] = token
    return token


def resolve_incident_action_key(bot_data: dict[str, Any], token_or_key: str) -> str:
    value = str(token_or_key or "")
    tokens = bot_data.get("incident_tokens", {})
    if isinstance(tokens, dict) and value in tokens:
        return str(tokens.get(value) or value)
    incidents = bot_data.get("incidents", {})
    if isinstance(incidents, dict):
        for ikey, incident in incidents.items():
            if isinstance(incident, dict) and str(incident.get("action_token") or "") == value:
                return str(ikey)
    # Backward compatibility for old admin alert buttons that used the full ikey.
    return value


def action_keyboard(bot_data: dict[str, Any], admin_id: int, ikey: str) -> InlineKeyboardMarkup:
    lang = get_lang(bot_data, admin_id)
    token = ensure_incident_action_token(bot_data, ikey)
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(TEXTS[lang]["btn_ban"], callback_data=f"act:ban:{token}"),
                InlineKeyboardButton(TEXTS[lang]["btn_warn"], callback_data=f"act:warn:{token}"),
                InlineKeyboardButton(TEXTS[lang]["btn_ignore"], callback_data=f"act:ignore:{token}"),
            ],
            [InlineKeyboardButton(tr(bot_data, admin_id, "btn_view_risk_profile"), callback_data=f"act:risk:{token}")],
        ]
    )


# ─────────────────────────────────────────────────────────────
# DYNAMIC PRIVATE DASHBOARD / GROUP SETTINGS FLOW
# ─────────────────────────────────────────────────────────────


def _user_state_exists(bot_data: dict[str, Any], user_id: int) -> bool:
    users = bot_data.get("user_state", {})
    return user_id in users or str(user_id) in users


# The literal pattern r"^\.[a-z0-9][a-z0-9_+-.]*{0,15}$" is invalid in Python
# because it stacks quantifiers ("*{0,15}"). This is the safe equivalent:
# - starts with a dot
# - supports compound extensions such as .tar.gz
# - blocks double dots and trailing dots
# - limits the body to 1..16 chars for compact callback payloads
VALID_EXTENSION_RE = re.compile(r"^\.(?!.*\.\.)(?!.*\.$)[a-z0-9][a-z0-9_+-.]{0,15}$")


def _dedupe_valid_extensions(values: Iterable[Any], *, limit: int | None = None) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in values:
        ext = _normalize_extension(str(raw).strip().strip("`'\"").lstrip("*"))
        if not VALID_EXTENSION_RE.fullmatch(ext):
            continue
        if ext not in seen:
            cleaned.append(ext)
            seen.add(ext)
        if limit is not None and len(cleaned) >= limit:
            break
    return cleaned


def _dedupe_allowed_extensions(values: Iterable[Any], *, limit: int | None = None) -> list[str]:
    """Allowed formats may bypass only custom blocks, never hard executable blocks."""
    hard_blocked = set(BLOCKED_EXTENSIONS)
    return [ext for ext in _dedupe_valid_extensions(values, limit=limit) if ext not in hard_blocked]


def parse_extensions_from_text(text: str) -> list[str]:
    tokens = re.split(r"[\s,;|]+", text.strip().casefold())
    return _dedupe_valid_extensions(tokens, limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)


def format_extension_list(values: Iterable[Any]) -> str:
    items = _dedupe_valid_extensions(values)
    return ", ".join(items) if items else "none"


VALID_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def normalize_sha256_hash(value: Any) -> str:
    cleaned = str(value or "").strip().casefold()
    cleaned = cleaned.removeprefix("sha256:").strip()
    return cleaned if VALID_SHA256_RE.fullmatch(cleaned) else ""


def _dedupe_valid_hashes(values: Iterable[Any], *, limit: int | None = None) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in values:
        digest = normalize_sha256_hash(raw)
        if digest and digest not in seen:
            cleaned.append(digest)
            seen.add(digest)
        if limit is not None and len(cleaned) >= limit:
            break
    return cleaned


def calculate_file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def calculate_file_hash_async(data: bytes) -> str:
    """Run SHA256 hashing outside the event loop for high-traffic downloads."""
    return await asyncio.to_thread(calculate_file_hash, data)


async def scan_file_bytes_async(file_name: str, mime_type: str, data: bytes) -> FileScanResult | None:
    """Run magic-byte and ZIP member analysis outside the event loop."""
    return await asyncio.to_thread(scan_file_bytes, file_name, mime_type, data)


def short_hash(value: str, *, length: int = 12) -> str:
    digest = normalize_sha256_hash(value)
    return digest[:length] if digest else ""


def format_hash_list(values: Iterable[Any], *, limit: int = 8) -> str:
    hashes = _dedupe_valid_hashes(values)
    if not hashes:
        return "none"
    shown = [f"<code>{h(item[:12])}…</code>" for item in hashes[:limit]]
    if len(hashes) > limit:
        shown.append(f"+{len(hashes) - limit} more")
    return "\n".join(shown)


def is_trusted_file_hash(bot_data: dict[str, Any], chat_id: int, file_sha256: str) -> bool:
    digest = normalize_sha256_hash(file_sha256)
    if not digest:
        return False
    settings = get_group_settings(bot_data, chat_id)
    return digest in set(settings.get("trusted_file_hashes", []))


def add_trusted_file_hash(bot_data: dict[str, Any], chat_id: int, file_sha256: str, *, added_by: int | None = None, file_name: str = "") -> bool:
    digest = normalize_sha256_hash(file_sha256)
    if not digest:
        return False
    settings = get_group_settings(bot_data, chat_id)
    current = _dedupe_valid_hashes(settings.get("trusted_file_hashes", []), limit=max_trusted_file_hashes(bot_data))
    if digest not in current:
        if len(current) >= max_trusted_file_hashes(bot_data):
            return False
        current.append(digest)
    settings["trusted_file_hashes"] = current
    bucket = bot_data.setdefault("whitelisted_hashes", {})
    if not isinstance(bucket, dict):
        bucket = {}
        bot_data["whitelisted_hashes"] = bucket
    group_bucket = bucket.setdefault(str(int(chat_id)), {})
    if isinstance(group_bucket, dict):
        group_bucket[digest] = {
            "sha256": digest,
            "file_name": str(file_name or ""),
            "added_by": int(added_by or 0),
            "added_at_ms": now_ms(),
        }
    return True


def remove_trusted_file_hash(bot_data: dict[str, Any], chat_id: int, file_hash_or_prefix: str) -> bool:
    key = str(file_hash_or_prefix or "").strip().casefold()
    if not key:
        return False
    settings = get_group_settings(bot_data, chat_id)
    current = _dedupe_valid_hashes(settings.get("trusted_file_hashes", []), limit=max_trusted_file_hashes(bot_data))
    removed = [item for item in current if item == key or item.startswith(key)]
    if not removed:
        return False
    settings["trusted_file_hashes"] = [item for item in current if item not in removed]
    bucket = bot_data.get("whitelisted_hashes")
    if isinstance(bucket, dict):
        group_bucket = bucket.get(str(int(chat_id)))
        if isinstance(group_bucket, dict):
            for digest in removed:
                group_bucket.pop(digest, None)
    return True


def clear_trusted_file_hashes(bot_data: dict[str, Any], chat_id: int) -> None:
    settings = get_group_settings(bot_data, chat_id)
    settings["trusted_file_hashes"] = []
    bucket = bot_data.get("whitelisted_hashes")
    if isinstance(bucket, dict):
        bucket.pop(str(int(chat_id)), None)


def get_group_settings(bot_data: dict[str, Any], chat_id: int) -> dict[str, Any]:
    state = get_group_state(bot_data, chat_id)
    settings = state.setdefault("settings", {})
    if not isinstance(settings, dict):
        settings = {}
        state["settings"] = settings
    for key, value in DEFAULT_GROUP_SETTINGS.items():
        if key not in settings:
            settings[key] = list(value) if isinstance(value, list) else value
    if settings.get("strictness") not in {"standard", "high", "strict"}:
        settings["strictness"] = "standard"
    if settings.get("auto_action_mode") not in {"off", "warn", "smart", "ban"}:
        settings["auto_action_mode"] = "off"
    for int_key, default_value in (
        ("auto_warn_threshold", 1),
        ("auto_mute_threshold", 2),
        ("auto_ban_threshold", 3),
        ("auto_mute_minutes", 60),
    ):
        try:
            settings[int_key] = max(1, int(settings.get(int_key, default_value)))
        except (TypeError, ValueError):
            settings[int_key] = default_value
    for list_key in ("allowed_extensions", "custom_blocked_extensions"):
        if not isinstance(settings.get(list_key), list):
            settings[list_key] = []
        if list_key == "allowed_extensions":
            settings[list_key] = _dedupe_allowed_extensions(settings.get(list_key, []), limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
        else:
            settings[list_key] = _dedupe_valid_extensions(settings.get(list_key, []), limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
    if not isinstance(settings.get("trusted_file_hashes"), list):
        settings["trusted_file_hashes"] = []
    settings["trusted_file_hashes"] = _dedupe_valid_hashes(settings.get("trusted_file_hashes", []), limit=max_trusted_file_hashes(bot_data))
    settings["protection_enabled"] = bool(settings.get("protection_enabled", True))
    settings["silent_mode"] = bool(settings.get("silent_mode", False))
    settings["strict_enforcement_on_admins"] = bool(settings.get("strict_enforcement_on_admins", STRICT_ENFORCEMENT_ON_ADMINS_DEFAULT))
    return settings

def _on_off(bot_data: dict[str, Any], user_id: int | None, enabled: bool, *, key_on: str = "protection_on", key_off: str = "protection_off") -> str:
    return tr(bot_data, user_id, key_on if enabled else key_off)


def _strictness_label(bot_data: dict[str, Any], user_id: int | None, strictness: str) -> str:
    if strictness == "strict":
        return "strict"
    return tr(bot_data, user_id, "strict_high" if strictness == "high" else "strict_standard")


def _auto_action_label(mode: Any) -> str:
    value = str(mode or "off")
    return value if value in {"off", "warn", "smart", "ban"} else "off"


def _yes_no(value: bool) -> str:
    return "✅" if value else "❌"


def _ui_state_badge(enabled: bool, *, on: str = "ON", off: str = "OFF") -> str:
    return f"🟢 {on}" if enabled else f"🔴 {off}"


def _permission_badge(perms: BotPerms | None) -> str:
    if perms is None or perms.status == "unknown":
        return "🟡 Permission: unknown"
    if has_delete_permission(perms):
        return "🟢 Permission: Delete OK"
    return "🔴 Permission: Need Delete Messages"


def _group_button_status(bot_data: dict[str, Any], chat_id: int) -> str:
    if is_chat_api_suppressed(bot_data, chat_id):
        return "🔴"
    perms = get_bot_member_from_state(bot_data, chat_id)
    if perms is None or perms.status == "unknown":
        return "🟡"
    return "🟢" if has_delete_permission(perms) else "🟡"


def _risk_badge(blocked: int) -> str:
    if blocked >= 3:
        return "🔴 High"
    if blocked >= 2:
        return "🟡 Medium"
    return "🟢 Low"


def _compact_extensions(values: Iterable[Any], *, fallback: str = "none") -> str:
    text = format_extension_list(values)
    return fallback if text == "none" else text


def _safe_button_title(title: str, *, limit: int = 34) -> str:
    cleaned = " ".join(str(title or "Unknown group").split())
    return cleaned if len(cleaned) <= limit else cleaned[: max(0, limit - 1)] + "…"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_chat_id_from_payload(payload: str) -> int | None:
    """Extract a Telegram chat_id from callback/deep-link payloads.

    Supported payloads:
    - settings_-1001234567890
    - group_-1001234567890
    - grp:-1001234567890
    - raw -1001234567890

    The previous implementation only split by underscore, so button payloads
    like ``grp:-100...`` failed and showed the generic Khmer/English error.
    """
    try:
        raw = str(payload or "").strip()
        if not raw:
            return None
        if ":" in raw:
            raw = raw.rsplit(":", 1)[-1]
        elif "_" in raw:
            raw = raw.rsplit("_", 1)[-1]
        return int(raw)
    except (TypeError, ValueError):
        return None


async def is_user_admin_in_group(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    user_id: int,
    *,
    force: bool = False,
    allow_api: bool = True,
) -> bool:
    """Single source of truth for hybrid group-admin authorization.

    Order:
    1. BOT_OWNER_IDS override.
    2. Fresh process cache.
    3. Fresh persisted bot_data cache.
    4. If cache is stale/missing and allow_api=True, live get_chat_member.
    5. Update caches and persist immediately after live refresh.
    """
    chat_id = int(chat_id)
    user_id = int(user_id)
    if user_id in BOT_OWNER_IDS:
        return True

    if not force:
        async with ADMIN_CACHE_LOCK:
            cached = ADMIN_IDS_CACHE.get(chat_id)
            if cached and cached.expires_at > time.monotonic():
                return user_id in set(list(cached.value))

    ids, cache_exists, cache_fresh = await get_chat_admin_ids_state_snapshot(context.bot_data, chat_id)
    if not force and cache_exists and cache_fresh:
        async with ADMIN_CACHE_LOCK:
            ADMIN_IDS_CACHE[chat_id] = CacheItem(ids.copy(), time.monotonic() + ADMIN_CACHE_TTL_SECONDS)
        return user_id in set(ids)

    if not allow_api:
        return user_id in set(ids)

    if is_chat_api_suppressed(context.bot_data, chat_id):
        return user_id in set(ids)

    member = None
    for attempt in (1, 2):
        try:
            member = await context.bot.get_chat_member(chat_id, user_id)
            break
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="get_chat_member:user"):
                continue
            logger.exception("Admin live membership check hit RetryAfter chat_id=%s user_id=%s", chat_id, user_id, exc_info=True)
            return user_id in set(ids)
        except (TimedOut, BadRequest, Forbidden, TelegramError) as exc:
            if _is_lost_chat_access_error(exc):
                logger.info("Admin live membership check skipped; bot lost access to chat_id=%s user_id=%s: %s", chat_id, user_id, exc)
                await mark_chat_inaccessible(context, chat_id, reason="admin_membership_lost_access", purge=True)
            else:
                logger.exception("Admin live membership check failed chat_id=%s user_id=%s", chat_id, user_id, exc_info=True)
            return user_id in set(ids)
        except Exception:
            logger.exception("Unexpected admin live membership check failure chat_id=%s user_id=%s", chat_id, user_id, exc_info=True)
            return user_id in set(ids)
    if member is None:
        return user_id in set(ids)

    status = str(getattr(member, "status", ""))
    is_admin = status in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"}
    await update_admin_member_cache(context, chat_id, user_id, is_admin=is_admin, persist=True)
    return is_admin


async def is_verified_admin_anywhere(
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    *,
    allow_api: bool = True,
) -> bool:
    if int(user_id) in BOT_OWNER_IDS:
        return True

    groups = await get_groups_snapshot(context.bot_data, user_id)
    if not groups:
        return False

    sem = asyncio.Semaphore(5)

    async def check_one(chat_id: int) -> bool:
        async with sem:
            return await is_user_admin_in_group(context, chat_id, user_id, allow_api=allow_api)

    results = await asyncio.gather(*(check_one(chat_id) for chat_id in groups), return_exceptions=True)
    return any(result is True for result in results)


async def is_admin_or_owner(
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    *,
    chat_id: int | None = None,
    allow_api: bool = True,
) -> bool:
    """Owner or verified group-admin check.

    allow_api=True gives commands/settings a self-healing live get_chat_member
    path when the admin cache is stale.  Dashboard callers should pass
    allow_api=False to stay completely offline and rate-limit safe.
    """
    if int(user_id) in BOT_OWNER_IDS:
        return True
    if chat_id is not None:
        return await is_user_admin_in_group(context, int(chat_id), int(user_id), allow_api=allow_api)
    return await is_verified_admin_anywhere(context, int(user_id), allow_api=allow_api)


async def require_admin_or_owner(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    *,
    silent: bool = False,
    allow_api: bool = True,
) -> bool:
    """Strict guard for diagnostic/config commands."""
    user = update.effective_user
    chat = update.effective_chat
    if not user:
        return False
    chat_id = chat.id if chat and is_group_chat(chat.type) else None
    ok = await is_admin_or_owner(context, user.id, chat_id=chat_id, allow_api=allow_api)
    if not ok and not silent:
        await safe_reply(update, tr(context.bot_data, user.id, "access_denied"))
    return ok


# Backward-compatible name used by older handlers in this file.
require_verified_admin = require_admin_or_owner


async def link_user_to_group(
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    chat_id: int,
    *,
    title: str | None = None,
    chat_type: str | None = None,
) -> None:
    """Atomically link a user to a group and persist immediately."""
    async with BOT_DATA_LOCK:
        state = get_user_state(context.bot_data, int(user_id))
        groups = state.setdefault("groups", [])
        if int(chat_id) not in [int(g) for g in groups if str(g).lstrip("-").isdigit()]:
            groups.append(int(chat_id))

        group_state = get_group_state(context.bot_data, int(chat_id))
        group_state["added_by"] = int(user_id)
        group_state["lang"] = get_lang(context.bot_data, int(user_id))
        if title:
            group_state["title"] = str(title)
            group_state["chat_title"] = str(title)
            bucket = _bot_data_cache_bucket(context.bot_data, "chat_meta_cache")
            bucket[str(int(chat_id))] = {
                "id": int(chat_id),
                "title": str(title),
                "type": str(chat_type or ""),
                "updated_at_ms": _cache_now_ms(),
            }
        group_state["last_seen_ms"] = now_ms()
        await persist_context_memory(context, reason="link_user_group", force=True, caller_holds_lock=True)


async def group_private_settings_url(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> str:
    _, username = await get_bot_identity(context.bot)
    return f"https://t.me/{username}?start=settings_{chat_id}" if username else "https://t.me/"


async def dashboard_first_time_keyboard(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> InlineKeyboardMarkup:
    """Minimal onboarding keyboard for users with no linked groups yet.

    Normal users and group admins with no linked group see only:
    Add Bot To Group, About, Help. Bot developers are the only exception;
    they also get the Developer Dashboard button because that panel is
    owner-only and independent from group-admin permissions.
    """
    _, username = await get_bot_identity(context.bot)
    add_url = build_add_group_url(username, request_admin=True)
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_add_group"), url=add_url)],
        [
            InlineKeyboardButton(tr(context.bot_data, user_id, "btn_about"), callback_data="nav:about"),
            InlineKeyboardButton(tr(context.bot_data, user_id, "btn_help"), callback_data="nav:help"),
        ],
    ]
    if _dev_is_owner(user_id):
        rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_developer"), callback_data="dev:home")])
    return InlineKeyboardMarkup(rows)


async def dashboard_home_keyboard(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> InlineKeyboardMarkup:
    # First-time users should not see Settings/My Groups/Feedback/Language/Refresh
    # until at least one group has been linked to their account.
    if not get_groups(context.bot_data, int(user_id)):
        return await dashboard_first_time_keyboard(context, user_id)

    _, username = await get_bot_identity(context.bot)
    add_url = build_add_group_url(username, request_admin=True)
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_open_groups"), callback_data="nav:groups")],
        [
            InlineKeyboardButton(tr(context.bot_data, user_id, "btn_add_group"), url=add_url),
            InlineKeyboardButton(tr(context.bot_data, user_id, "btn_help"), callback_data="nav:help"),
        ],
        [
            InlineKeyboardButton(tr(context.bot_data, user_id, "btn_feedback"), callback_data="nav:feedback"),
            InlineKeyboardButton(tr(context.bot_data, user_id, "btn_language"), callback_data="nav:language"),
        ],
    ]
    if _dev_is_owner(user_id):
        rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_developer"), callback_data="dev:home")])
    rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_refresh_dashboard"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)

def dashboard_back_home_keyboard(bot_data: dict[str, Any], user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data="nav:groups")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")],
        ]
    )


async def send_or_edit_panel(update: Update, text: str, reply_markup: InlineKeyboardMarkup | None = None) -> None:
    query = update.callback_query
    if query:
        await safe_edit_query(query, text, reply_markup=reply_markup)
    else:
        await safe_reply(update, text, reply_markup=reply_markup)


def callback_is_private(query: Any) -> bool:
    msg = getattr(query, "message", None)
    chat = getattr(msg, "chat", None)
    return bool(chat and chat.type == ChatType.PRIVATE)


async def reject_group_config_callback(query: Any, bot_data: dict[str, Any], user_id: int) -> None:
    try:
        await safe_answer_callback(query, text=tr(bot_data, user_id, "config_private_only"), show_alert=True)
    except TelegramError as exc:
        logger.exception("Could not answer private-only callback warning", exc_info=True)


async def render_home(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    title_key = "home_title" if get_groups(context.bot_data, int(user_id)) else "first_time_home_title"
    await send_or_edit_panel(update, tr(context.bot_data, user_id, title_key), await dashboard_home_keyboard(context, user_id))


async def render_about_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    keyboard = await dashboard_first_time_keyboard(context, user_id) if not get_groups(context.bot_data, int(user_id)) else dashboard_back_home_keyboard(context.bot_data, user_id)
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "about_title"), keyboard)


async def render_help_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    keyboard = await dashboard_first_time_keyboard(context, user_id) if not get_groups(context.bot_data, int(user_id)) else InlineKeyboardMarkup([[InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")]])
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "help"), keyboard)


async def render_language_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🇬🇧 English", callback_data="lang_en"), InlineKeyboardButton("🇰🇭 ភាសាខ្មែរ", callback_data="lang_km")],
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")],
    ])
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "language_title"), keyboard)


async def render_feedback_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    async with BOT_DATA_LOCK:
        state = get_user_state(context.bot_data, int(user_id))
        state["pending_user_feedback"] = {"created_at_ms": now_ms()}
        await persist_context_memory(context, reason="pending_user_feedback", force=True, caller_holds_lock=True)
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")],
    ])
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "feedback_prompt"), keyboard)


async def clear_pending_user_feedback(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    async with BOT_DATA_LOCK:
        state = get_user_state(context.bot_data, int(user_id))
        state.pop("pending_user_feedback", None)
        await persist_context_memory(context, reason="clear_pending_user_feedback", force=True, caller_holds_lock=True)


async def save_user_feedback(context: ContextTypes.DEFAULT_TYPE, user: Any, text: str) -> None:
    clean_text = re.sub(r"\s+", " ", str(text or "")).strip()
    async with BOT_DATA_LOCK:
        state = get_user_state(context.bot_data, int(user.id))
        state.pop("pending_user_feedback", None)
        feedback = context.bot_data.setdefault("user_feedback", [])
        if not isinstance(feedback, list):
            feedback = []
            context.bot_data["user_feedback"] = feedback
        feedback.insert(0, {
            "id": f"fb:{now_ms()}:{int(user.id)}",
            "user_id": int(user.id),
            "username": getattr(user, "username", None) or "",
            "full_name": getattr(user, "full_name", None) or "Unknown",
            "text": clean_text[:2000],
            "created_at_ms": now_ms(),
        })
        del feedback[MAX_USER_FEEDBACK_ITEMS:]
        await persist_context_memory(context, reason="user_feedback_saved", force=True, caller_holds_lock=True)


async def render_groups_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, page: int = 0) -> None:
    # Keep this function free of re-entrant BOT_DATA_LOCK deadlocks.  The
    # dashboard is rendered from synchronous snapshots; only state mutation and
    # default hydration are protected, and no await happens inside lock scopes.
    groups = get_groups(context.bot_data, user_id)

    if int(user_id) not in BOT_OWNER_IDS and groups:
        checks = await asyncio.gather(
            *(is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=False) for chat_id in groups),
            return_exceptions=True,
        )
        authorized_groups: list[int] = []
        for chat_id, check_result in zip(groups, checks):
            if check_result is True:
                authorized_groups.append(chat_id)
            elif isinstance(check_result, Exception):
                logger.warning(
                    "Suppressed dashboard admin check failed user_id=%s chat_id=%s error=%r",
                    user_id,
                    chat_id,
                    check_result,
                    exc_info=(type(check_result), check_result, check_result.__traceback__),
                )

        if len(authorized_groups) != len(groups):
            async with BOT_DATA_LOCK:
                state = get_user_state(context.bot_data, user_id)
                state["groups"] = authorized_groups
            await persist_context_memory(context, reason="dashboard_admin_prune", force=True)
        groups = authorized_groups

    if not groups:
        await send_or_edit_panel(update, tr(context.bot_data, user_id, "groups_empty"), await dashboard_first_time_keyboard(context, user_id))
        return

    total = len(groups)
    pages = max(1, (total + GROUPS_PANEL_PAGE_SIZE - 1) // GROUPS_PANEL_PAGE_SIZE)
    page = min(max(0, int(page or 0)), pages - 1)
    page_groups = groups[page * GROUPS_PANEL_PAGE_SIZE:(page + 1) * GROUPS_PANEL_PAGE_SIZE]

    group_cards: list[dict[str, Any]] = []
    async with BOT_DATA_LOCK:
        for chat_id in page_groups:
            title = get_chat_title_from_state(context.bot_data, chat_id)
            perms = get_bot_member_from_state(context.bot_data, chat_id)
            permission = _permission_badge(perms)
            settings = dict(get_group_settings(context.bot_data, chat_id))
            protection = _ui_state_badge(bool(settings.get("protection_enabled", True)))
            if is_chat_api_suppressed(context.bot_data, chat_id):
                permission = "🔴 Permission: bot cannot access this group"
            group_cards.append(
                {
                    "chat_id": int(chat_id),
                    "title": str(title),
                    "permission": str(permission),
                    "protection": str(protection),
                    "strictness": str(settings.get("strictness", "standard")),
                    "silent": bool(settings.get("silent_mode", False)),
                    "button_prefix": _group_button_status(context.bot_data, chat_id),
                }
            )

    lines = [tr(context.bot_data, user_id, "groups_title")]
    if pages > 1:
        lines.append(f"Page <code>{page + 1}</code>/<code>{pages}</code> · Total <code>{total}</code>")

    rows: list[list[InlineKeyboardButton]] = []
    for item in group_cards:
        title = item["title"]
        card = tr(
            context.bot_data,
            user_id,
            "group_card",
            group=h(title),
            permission=h(item["permission"]),
            protection=h(item["protection"]),
            strictness=h(_strictness_label(context.bot_data, user_id, item["strictness"])),
            silent=h(_on_off(context.bot_data, user_id, item["silent"], key_on="silent_on", key_off="silent_off")),
        )
        lines.append(card)
        rows.append([InlineKeyboardButton(f"{item['button_prefix']} {_safe_button_title(title)}", callback_data=f"grp:{item['chat_id']}")])

    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(tr(context.bot_data, user_id, "btn_prev"), callback_data=f"nav:groups:{page - 1}"))
    if page < pages - 1:
        nav.append(InlineKeyboardButton(tr(context.bot_data, user_id, "btn_next"), callback_data=f"nav:groups:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_refresh_groups"), callback_data=f"nav:groups:{page}")])
    rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")])

    await send_or_edit_panel(update, "\n\n".join(lines), InlineKeyboardMarkup(rows))


def group_settings_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    # Hide Settings modules until the bot is confirmed as admin with Delete Messages.
    if not bot_settings_unlocked_from_state(bot_data, int(chat_id)):
        return bot_admin_required_keyboard(bot_data, user_id, int(chat_id))

    settings = get_group_settings(bot_data, chat_id)
    protection_label = tr(bot_data, user_id, "label_protection_on" if settings.get("protection_enabled", True) else "label_protection_off")
    access_badge = tr(bot_data, user_id, "label_no_access" if is_chat_api_suppressed(bot_data, chat_id) else "label_access_ok")
    silent_label = tr(bot_data, user_id, "btn_silent_mode_on" if settings.get("silent_mode", False) else "btn_group_notice_on")
    strictness = _strictness_label(bot_data, user_id, str(settings.get("strictness", "standard"))).upper()
    auto_mode = _auto_action_label(settings.get("auto_action_mode")).upper()

    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(f"{protection_label} · {access_badge}", callback_data=f"gap:{chat_id}:protection")],
            [
                InlineKeyboardButton(tr(bot_data, user_id, "btn_quick_auto"), callback_data=f"gap:{chat_id}:auto"),
                InlineKeyboardButton(tr(bot_data, user_id, "btn_quick_health"), callback_data=f"gap:{chat_id}:health"),
            ],
            [
                InlineKeyboardButton(tr(bot_data, user_id, "btn_scanner_center"), callback_data=f"gap:{chat_id}:scanner"),
                InlineKeyboardButton(tr(bot_data, user_id, "btn_admin_alerts_short"), callback_data=f"gap:{chat_id}:admins"),
            ],
            [
                InlineKeyboardButton(tr(bot_data, user_id, "btn_incidents_short"), callback_data=f"gap:{chat_id}:incidents"),
                InlineKeyboardButton(tr(bot_data, user_id, "btn_risk_users"), callback_data=f"gap:{chat_id}:risk"),
            ],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_admin_logs"), callback_data=f"gap:{chat_id}:admin_logs")],
            [
                InlineKeyboardButton(tr(bot_data, user_id, "btn_blocked_formats_short"), callback_data=f"gfmt:{chat_id}:menu"),
                InlineKeyboardButton(tr(bot_data, user_id, "btn_allowed_formats_short"), callback_data=f"gallow:{chat_id}:menu"),
            ],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_trusted_hashes_short"), callback_data=f"ghash:{chat_id}:menu")],
            [
                InlineKeyboardButton(silent_label, callback_data=f"gset:{chat_id}:silent"),
                InlineKeyboardButton(f"🔥 {strictness}", callback_data=f"gset:{chat_id}:strictness"),
            ],
            [
                InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data="nav:groups"),
                InlineKeyboardButton(tr(bot_data, user_id, "btn_refresh"), callback_data=f"gap:{chat_id}:refresh"),
            ],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")],
        ]
    )


def format_manager_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    settings = get_group_settings(bot_data, chat_id)
    rows: list[list[InlineKeyboardButton]] = [
        [
            InlineKeyboardButton(tr(bot_data, user_id, "btn_add_format"), callback_data=f"gfmt:{chat_id}:add"),
            InlineKeyboardButton(tr(bot_data, user_id, "btn_edit_formats"), callback_data=f"gfmt:{chat_id}:edit"),
        ]
    ]
    if settings.get("custom_blocked_extensions"):
        rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_remove_format"), callback_data=f"gfmt:{chat_id}:remove")])
        rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_clear_formats"), callback_data=f"gfmt:{chat_id}:clear")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


def remove_format_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    settings = get_group_settings(bot_data, chat_id)
    rows: list[list[InlineKeyboardButton]] = []
    for ext in settings.get("custom_blocked_extensions", []):
        payload_ext = ext.removeprefix(".")
        rows.append([InlineKeyboardButton(f"🗑 {ext}", callback_data=f"gfmtdel:{chat_id}:{payload_ext}")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"gfmt:{chat_id}:menu")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


def _admin_action_logs(bot_data: dict[str, Any]) -> list[dict[str, Any]]:
    raw = bot_data.get("admin_action_logs", [])
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    bot_data["admin_action_logs"] = []
    return []


def _record_admin_action_log_locked(
    bot_data: dict[str, Any],
    *,
    chat_id: int,
    admin_id: int,
    admin_name: str,
    action: str,
    target_id: int | None = None,
    target_name: str = "",
    result: str = "",
) -> None:
    logs = _admin_action_logs(bot_data)
    logs.insert(0, {
        "chat_id": int(chat_id),
        "admin_id": int(admin_id),
        "admin_name": str(admin_name or admin_id),
        "target_id": int(target_id) if target_id is not None else None,
        "target_name": str(target_name or ""),
        "action": str(action or "unknown"),
        "result": str(result or ""),
        "created_at_ms": now_ms(),
    })
    del logs[MAX_ADMIN_ACTION_LOG_ITEMS:]
    bot_data["admin_action_logs"] = logs


def _admin_log_count_for_chat(bot_data: dict[str, Any], chat_id: int) -> int:
    return sum(1 for item in _admin_action_logs(bot_data) if str(item.get("chat_id")) == str(int(chat_id)))


def _open_incident_count_for_chat(bot_data: dict[str, Any], chat_id: int) -> int:
    incidents = bot_data.get("incidents", {})
    if not isinstance(incidents, dict):
        return 0
    return sum(1 for item in incidents.values() if isinstance(item, dict) and str(item.get("chat_id")) == str(int(chat_id)) and not item.get("done"))


def _admin_alert_ready_counts_from_state(bot_data: dict[str, Any], chat_id: int) -> tuple[int, int]:
    cache = bot_data.get("admin_ids_cache", {}) if isinstance(bot_data.get("admin_ids_cache", {}), dict) else {}
    record = cache.get(str(int(chat_id))) or cache.get(int(chat_id)) or {}
    admin_ids: list[int] = []
    if isinstance(record, dict):
        value = record.get("value") or record.get("admin_ids") or []
        if isinstance(value, list):
            for item in value:
                try:
                    admin_ids.append(int(item))
                except (TypeError, ValueError):
                    pass
    ready_user_ids: set[int] = set()
    user_state = bot_data.get("user_state", {})
    if isinstance(user_state, dict):
        for uid in user_state.keys():
            try:
                ready_user_ids.add(int(uid))
            except (TypeError, ValueError):
                pass
    ready = sum(1 for admin_id in admin_ids if admin_id in ready_user_ids)
    return ready, len(admin_ids)


def _group_health_status(bot_data: dict[str, Any], user_id: int, chat_id: int) -> str:
    if is_chat_api_suppressed(bot_data, chat_id):
        return tr(bot_data, user_id, "status_no_access")
    perms = get_bot_member_from_state(bot_data, chat_id)
    if perms is not None and has_delete_permission(perms):
        return tr(bot_data, user_id, "status_ready")
    return tr(bot_data, user_id, "status_attention")


async def render_group_settings_panel(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    chat_id: int,
    *,
    notice: str = "",
) -> None:
    async with BOT_DATA_LOCK:
        bot_ready = bot_settings_unlocked_from_state(context.bot_data, int(chat_id))
        if not bot_ready:
            text = bot_admin_required_text(context.bot_data, user_id, int(chat_id))
            keyboard = bot_admin_required_keyboard(context.bot_data, user_id, int(chat_id))
        else:
            title = get_chat_title_from_state(context.bot_data, chat_id)
            no_access = is_chat_api_suppressed(context.bot_data, chat_id)
            settings = dict(get_group_settings(context.bot_data, chat_id))
            allowed = format_extension_list(settings.get("allowed_extensions", []))
            custom_blocked = format_extension_list(settings.get("custom_blocked_extensions", []))
            admin_ready, admin_total = _admin_alert_ready_counts_from_state(context.bot_data, chat_id)
            text = tr(
                context.bot_data,
                user_id,
                "group_admin_title",
                group=h(title),
                chat_id=chat_id,
                health_status=_group_health_status(context.bot_data, user_id, chat_id),
                protection=_on_off(context.bot_data, user_id, bool(settings.get("protection_enabled"))),
                strictness=_strictness_label(context.bot_data, user_id, str(settings.get("strictness", "standard"))),
                silent=_on_off(context.bot_data, user_id, bool(settings.get("silent_mode")), key_on="silent_on", key_off="silent_off"),
                allowed=h(allowed),
                custom_blocked=h(custom_blocked),
                trusted_hashes=len(settings.get("trusted_file_hashes", [])) if isinstance(settings.get("trusted_file_hashes"), list) else 0,
                auto_action=h(_auto_action_label(settings.get("auto_action_mode"))),
                admin_ready=admin_ready,
                admin_total=admin_total,
                open_incidents=_open_incident_count_for_chat(context.bot_data, chat_id),
                admin_logs=_admin_log_count_for_chat(context.bot_data, chat_id),
            )
            text = f"{text}\n\n{tr(context.bot_data, user_id, 'admin_panel_tip')}"
            keyboard = group_settings_keyboard(context.bot_data, user_id, chat_id)
            if no_access and not notice:
                notice = tr(context.bot_data, user_id, "group_no_access")
    if notice:
        text = f"{notice}\n\n{text}"
    await send_or_edit_panel(update, text, keyboard)


async def render_format_manager_panel(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    chat_id: int,
    *,
    notice: str = "",
    remove_mode: bool = False,
) -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        settings = dict(get_group_settings(context.bot_data, chat_id))
        custom_blocked = format_extension_list(settings.get("custom_blocked_extensions", []))
        text = tr(
            context.bot_data,
            user_id,
            "formats_title",
            group=h(title),
            chat_id=chat_id,
            custom_blocked=h(custom_blocked),
        )
        keyboard = remove_format_keyboard(context.bot_data, user_id, chat_id) if remove_mode else format_manager_keyboard(context.bot_data, user_id, chat_id)
    if notice:
        text = f"{notice}\n\n{text}"
    await send_or_edit_panel(update, text, keyboard)




def allowed_manager_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    settings = get_group_settings(bot_data, chat_id)
    rows: list[list[InlineKeyboardButton]] = [[InlineKeyboardButton(tr(bot_data, user_id, "btn_add_allowed"), callback_data=f"gallow:{chat_id}:add"), InlineKeyboardButton(tr(bot_data, user_id, "btn_edit_allowed"), callback_data=f"gallow:{chat_id}:edit")]]
    if settings.get("allowed_extensions"):
        rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_remove_allowed"), callback_data=f"gallow:{chat_id}:remove")])
        rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_clear_allowed"), callback_data=f"gallow:{chat_id}:clear")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


def remove_allowed_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    settings = get_group_settings(bot_data, chat_id)
    rows: list[list[InlineKeyboardButton]] = [[InlineKeyboardButton(f"🗑 {ext}", callback_data=f"gallowdel:{chat_id}:{ext.removeprefix('.')}")] for ext in settings.get("allowed_extensions", [])]
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"gallow:{chat_id}:menu")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


async def render_allowed_manager_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, *, notice: str = "", remove_mode: bool = False) -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        settings = dict(get_group_settings(context.bot_data, chat_id))
        allowed = format_extension_list(settings.get("allowed_extensions", []))
        text = tr(context.bot_data, user_id, "allowed_title", group=h(title), chat_id=chat_id, allowed=h(allowed))
        keyboard = remove_allowed_keyboard(context.bot_data, user_id, chat_id) if remove_mode else allowed_manager_keyboard(context.bot_data, user_id, chat_id)
    if notice:
        text = f"{notice}\n\n{text}"
    await send_or_edit_panel(update, text, keyboard)


def trusted_hash_manager_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    settings = get_group_settings(bot_data, chat_id)
    rows: list[list[InlineKeyboardButton]] = [[InlineKeyboardButton(tr(bot_data, user_id, "btn_add_hash"), callback_data=f"ghash:{chat_id}:add")]]
    if settings.get("trusted_file_hashes"):
        rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_remove_hash"), callback_data=f"ghash:{chat_id}:remove")])
        rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_clear_hashes"), callback_data=f"ghash:{chat_id}:clear")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


def remove_trusted_hash_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    settings = get_group_settings(bot_data, chat_id)
    rows: list[list[InlineKeyboardButton]] = []
    for digest in settings.get("trusted_file_hashes", []):
        short = short_hash(digest)
        if short:
            rows.append([InlineKeyboardButton(f"🗑 {short}…", callback_data=f"ghashdel:{chat_id}:{short}")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"ghash:{chat_id}:menu")])
    rows.append([InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


async def render_trusted_hash_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, *, notice: str = "", remove_mode: bool = False) -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        settings = dict(get_group_settings(context.bot_data, chat_id))
        hashes = settings.get("trusted_file_hashes", []) if isinstance(settings.get("trusted_file_hashes"), list) else []
        items = format_hash_list(hashes)
        if items == "none":
            items = tr(context.bot_data, user_id, "trusted_hash_empty")
        text = tr(
            context.bot_data,
            user_id,
            "trusted_hash_title",
            group=h(title),
            chat_id=chat_id,
            count=len(hashes),
            limit=max_trusted_file_hashes(context.bot_data),
            items=items,
        )
        keyboard = remove_trusted_hash_keyboard(context.bot_data, user_id, chat_id) if remove_mode else trusted_hash_manager_keyboard(context.bot_data, user_id, chat_id)
    if notice:
        text = f"{notice}\n\n{text}"
    await send_or_edit_panel(update, text, keyboard)


def destructive_confirm_keyboard(bot_data: dict[str, Any], user_id: int, yes_callback: str, no_callback: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_confirm_yes"), callback_data=yes_callback)],
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_confirm_no"), callback_data=no_callback)],
    ])


async def render_destructive_confirmation(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    chat_id: int,
    *,
    summary_key: str,
    yes_callback: str,
    no_callback: str,
) -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        summary = tr(context.bot_data, user_id, summary_key, group=h(title))
        text = tr(context.bot_data, user_id, "confirm_clear_title", summary=summary)
        keyboard = destructive_confirm_keyboard(context.bot_data, user_id, yes_callback, no_callback)
    await send_or_edit_panel(update, text, keyboard)


def _group_back_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")], [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")]])


def _protection_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    settings = get_group_settings(bot_data, chat_id)
    protection_on = bool(settings.get("protection_enabled", True))
    protection_key = "btn_turn_off" if protection_on else "btn_turn_on"
    silent_on = bool(settings.get("silent_mode", False))
    silent_label = tr(bot_data, user_id, "btn_silent_mode_on" if silent_on else "btn_group_notice_on")
    strict_label = f"🔥 Strictness: {_strictness_label(bot_data, user_id, str(settings.get('strictness', 'standard'))).upper()}"
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(f"🛡 {tr(bot_data, user_id, protection_key)}", callback_data=f"gset:{chat_id}:protection")],
        [InlineKeyboardButton(strict_label, callback_data=f"gset:{chat_id}:strictness")],
        [InlineKeyboardButton(silent_label, callback_data=f"gset:{chat_id}:silent")],
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_auto_actions"), callback_data=f"gap:{chat_id}:auto")],
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")],
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")],
    ])

async def render_group_protection_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, *, notice: str = "") -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        settings = dict(get_group_settings(context.bot_data, chat_id))
        perms = get_bot_member_from_state(context.bot_data, chat_id)
        bot_permission = _permission_badge(perms).replace("Permission: ", "")
        text = tr(context.bot_data, user_id, "protection_status_title", group=h(title), protection=_on_off(context.bot_data, user_id, bool(settings.get("protection_enabled"))), strictness=_strictness_label(context.bot_data, user_id, str(settings.get("strictness", "standard"))), silent=_on_off(context.bot_data, user_id, bool(settings.get("silent_mode")), key_on="silent_on", key_off="silent_off"), bot_permission=h(bot_permission), auto_action=h(_auto_action_label(settings.get("auto_action_mode"))))
        keyboard = _protection_keyboard(context.bot_data, user_id, chat_id)
    if notice:
        text = f"{notice}\n\n{text}"
    await send_or_edit_panel(update, text, keyboard)


def _incident_created_ms(ikey: str, incident: dict[str, Any]) -> int:
    ts = incident_timestamp_ms(str(ikey))
    if ts is not None:
        return int(ts)
    try:
        return int(incident.get("created_at_ms", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _group_incident_items(bot_data: dict[str, Any], chat_id: int) -> list[tuple[str, dict[str, Any]]]:
    incidents = bot_data.get("incidents", {}) if isinstance(bot_data.get("incidents", {}), dict) else {}
    items = [(str(k), v.copy()) for k, v in incidents.items() if isinstance(v, dict) and str(v.get("chat_id")) == str(int(chat_id))]
    items.sort(key=lambda item: _incident_created_ms(item[0], item[1]), reverse=True)
    return items


async def render_group_incidents_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, *, notice: str = "") -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        items = _group_incident_items(context.bot_data, chat_id)
    lines = []
    for idx, (ikey, incident) in enumerate(items[:10], 1):
        created = _format_saved_ms(_incident_created_ms(ikey, incident))
        handled = "✅ Handled" if incident.get("done") else "⏳ Pending"
        action = str(incident.get("action") or incident.get("auto_action") or "pending")
        file_name = h(incident.get("file_name", "unknown"))
        sender = h(incident.get("sender_name", incident.get("sender_id", "unknown")))
        sender_id = h(incident.get("sender_id", ""))
        reason = h(incident.get("scan_reason") or incident.get("reason") or "blocked")
        lines.append(
            f"<b>{idx}. {handled}</b> · <code>{h(action)}</code>\n"
            f"📄 <code>{file_name}</code>\n"
            f"👤 {sender} <code>{sender_id}</code>\n"
            f"🧪 {reason}\n"
            f"🕒 <code>{h(created)}</code>"
        )
    if not lines:
        lines.append(tr(context.bot_data, user_id, "incidents_empty"))
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_refresh_incidents"), callback_data=f"gap:{chat_id}:incidents")],
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_clear_handled"), callback_data=f"gap:{chat_id}:clear_incidents")],
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")],
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")],
    ])
    text = tr(context.bot_data, user_id, "incidents_title", group=h(title), total=len(items), items="\n\n".join(lines))
    if notice:
        text = f"{notice}\n\n{text}"
    await send_or_edit_panel(update, text, keyboard)

async def render_group_risk_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int) -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        items = _group_incident_items(context.bot_data, chat_id)
        known_users = context.bot_data.get("known_users", {}) if isinstance(context.bot_data.get("known_users", {}), dict) else {}
    stats: dict[int, dict[str, Any]] = {}
    for _, incident in items:
        try:
            sender_id = int(incident.get("sender_id"))
        except (TypeError, ValueError):
            continue
        entry = stats.setdefault(sender_id, {"blocked": 0, "warned": 0, "muted": 0, "banned": 0, "name": str(incident.get("sender_name") or sender_id)})
        entry["blocked"] += 1
        action = str(incident.get("action") or incident.get("auto_action") or "")
        if action == "warn":
            entry["warned"] += 1
        elif action == "mute":
            entry["muted"] += 1
        elif action == "ban":
            entry["banned"] += 1
    ranked = sorted(stats.items(), key=lambda item: (item[1]["blocked"], item[1]["banned"], item[1]["muted"], item[1]["warned"]), reverse=True)[:10]
    lines = []
    for idx, (target_id, data) in enumerate(ranked, 1):
        profile = known_users.get(str(target_id), {}) if isinstance(known_users.get(str(target_id), {}), dict) else {}
        name = str(profile.get("full_name") or data.get("name") or target_id)
        blocked = _safe_int(data.get("blocked"), 0)
        risk = _risk_badge(blocked)
        lines.append(
            f"<b>{idx}. {user_link(target_id, name)}</b>\n"
            f"Risk: <code>{risk}</code> · Blocked: <code>{blocked}</code> · Warns: <code>{_safe_int(data.get('warned'), 0)}</code> · Mutes: <code>{_safe_int(data.get('muted'), 0)}</code> · Bans: <code>{_safe_int(data.get('banned'), 0)}</code>"
        )
    if not lines:
        lines.append(tr(context.bot_data, user_id, "member_risk_empty"))
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "member_risk_title", group=h(title), items="\n\n".join(lines)), _group_back_keyboard(context.bot_data, user_id, chat_id))

async def render_group_admin_alert_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int) -> None:
    admin_ids = await get_chat_admin_ids_cached(context, chat_id, allow_api=True)
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        ready_user_ids = {int(uid) for uid in context.bot_data.get("user_state", {}).keys() if str(uid).lstrip("-").isdigit()} if isinstance(context.bot_data.get("user_state", {}), dict) else set()
        known_users = context.bot_data.get("known_users", {}) if isinstance(context.bot_data.get("known_users", {}), dict) else {}
        lang = get_lang(context.bot_data, user_id)
    lines = []
    ready_count = 0
    for i, admin_id in enumerate(admin_ids, 1):
        profile = known_users.get(str(admin_id), {}) if isinstance(known_users.get(str(admin_id), {}), dict) else {}
        name = str(profile.get("full_name") or admin_id)
        ready = admin_id in ready_user_ids
        ready_count += 1 if ready else 0
        status = TEXTS[lang]["admins_enabled"] if ready else TEXTS[lang]["admins_need_start"]
        lines.append(f"{i}. {user_link(admin_id, name)} — {status}")
    if not lines:
        lines.append("No cached admins yet. Tap Refresh after adding the bot as admin.")
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "admin_alert_title", group=h(title), ready=ready_count, total=len(admin_ids), items="\n".join(lines)), _group_back_keyboard(context.bot_data, user_id, chat_id))


async def render_group_health_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int) -> None:
    perms = await get_bot_member_cached(context, chat_id, force=True, allow_api=True)
    admin_ids = await get_chat_admin_ids_cached(context, chat_id, allow_api=True)
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        settings = dict(get_group_settings(context.bot_data, chat_id))
        ready_user_ids = {int(uid) for uid in context.bot_data.get("user_state", {}).keys() if str(uid).lstrip("-").isdigit()} if isinstance(context.bot_data.get("user_state", {}), dict) else set()
    ready_count = sum(1 for admin_id in admin_ids if admin_id in ready_user_ids)
    text = tr(context.bot_data, user_id, "health_title", group=h(title), bot_admin=_yes_no(perms.status in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"}), can_delete=_yes_no(has_delete_permission(perms)), can_restrict=_yes_no(has_ban_permission(perms)), protection=_yes_no(bool(settings.get("protection_enabled"))), scanner=_yes_no(bool(SUSPICIOUS_SCANNER_ENABLED)), ready=ready_count, total=len(admin_ids))
    await send_or_edit_panel(update, text, _group_back_keyboard(context.bot_data, user_id, chat_id))


def _auto_actions_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    current = _auto_action_label(get_group_settings(bot_data, chat_id).get("auto_action_mode"))

    def row(mode: str, key: str) -> list[InlineKeyboardButton]:
        prefix = "✅ " if current == mode else "⚪ "
        return [InlineKeyboardButton(prefix + tr(bot_data, user_id, key), callback_data=f"gauto:{chat_id}:{mode}")]

    return InlineKeyboardMarkup([
        row("off", "btn_auto_off"),
        row("warn", "btn_auto_warn"),
        row("smart", "btn_auto_smart"),
        row("ban", "btn_auto_ban"),
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")],
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")],
    ])

async def render_auto_actions_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, *, notice: str = "") -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        settings = dict(get_group_settings(context.bot_data, chat_id))
        text = tr(context.bot_data, user_id, "auto_title", group=h(title), mode=h(_auto_action_label(settings.get("auto_action_mode"))), warn_threshold=int(settings.get("auto_warn_threshold", 1)), mute_threshold=int(settings.get("auto_mute_threshold", 2)), ban_threshold=int(settings.get("auto_ban_threshold", 3)), mute_minutes=int(settings.get("auto_mute_minutes", 60)))
        keyboard = _auto_actions_keyboard(context.bot_data, user_id, chat_id)
    if notice:
        text = f"{notice}\n\n{text}"
    await send_or_edit_panel(update, text, keyboard)


async def render_group_admin_logs_panel(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    chat_id: int,
    *,
    notice: str = "",
) -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        logs = [item for item in _admin_action_logs(context.bot_data) if str(item.get("chat_id")) == str(int(chat_id))]
        lines: list[str] = []
        for idx, item in enumerate(logs[:15], 1):
            admin_id = _safe_int(item.get("admin_id"), 0)
            admin_name = str(item.get("admin_name") or admin_id or "Admin")
            target_id_raw = item.get("target_id")
            target_name = str(item.get("target_name") or "")
            target_text = ""
            if target_id_raw not in (None, "", 0):
                target_id = _safe_int(target_id_raw, 0)
                if target_id:
                    target_text = f" → {user_link(target_id, target_name or str(target_id))}"
            created = _format_saved_ms(item.get("created_at_ms"))
            result = str(item.get("result") or "")
            result_line = f"\nResult: <code>{h(result)[:80]}</code>" if result else ""
            lines.append(
                f"<b>{idx}. {h(str(item.get('action') or 'action'))}</b>{target_text}\n"
                f"By: {user_link(admin_id, admin_name) if admin_id else h(admin_name)} · <code>{h(created)}</code>{result_line}"
            )
        if not lines:
            lines.append(tr(context.bot_data, user_id, "admin_logs_empty"))
        text = tr(context.bot_data, user_id, "admin_logs_title", group=h(title), total=len(logs), items="\n\n".join(lines))
        if notice:
            text = f"{notice}\n\n{text}"
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_refresh_admin_logs"), callback_data=f"gap:{chat_id}:admin_logs")],
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_clear_admin_logs"), callback_data=f"gap:{chat_id}:clear_admin_logs")],
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")],
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")],
        ])
    await send_or_edit_panel(update, text, keyboard)


# ─────────────────────────────────────────────────────────────
# DEVELOPER DASHBOARD - BUTTON ONLY
# ─────────────────────────────────────────────────────────────

DEV_USERS_PAGE_SIZE = 8
DEV_GROUPS_PAGE_SIZE = 10
MAX_USER_FEEDBACK_ITEMS = _env_int("MAX_USER_FEEDBACK_ITEMS", 200, min_value=20, max_value=2000)
MAX_ADMIN_ACTION_LOG_ITEMS = _env_int("MAX_ADMIN_ACTION_LOG_ITEMS", 500, min_value=50, max_value=5000)



def _developer_keyboard(bot_data: dict[str, Any], user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(tr(bot_data, user_id, "btn_dev_users"), callback_data="dev:users:0"),
                InlineKeyboardButton(tr(bot_data, user_id, "btn_dev_groups"), callback_data="dev:groups:0"),
            ],
            [
                InlineKeyboardButton(tr(bot_data, user_id, "btn_dev_memory"), callback_data="dev:memory"),
                InlineKeyboardButton(tr(bot_data, user_id, "btn_dev_hash_config"), callback_data="dev:hash"),
            ],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_dev_feedback"), callback_data="dev:feedback")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_refresh_developer"), callback_data="dev:refresh")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")],
        ]
    )

def _developer_back_keyboard(bot_data: dict[str, Any], user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data="dev:home")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")],
        ]
    )


def _dev_is_owner(user_id: int) -> bool:
    """Return True only for bot developers configured in BOT_OWNER_IDS.

    This deliberately does NOT check Telegram group-admin status.
    Group admins can manage only their own group panels; they can never
    open the bot-level Developer Dashboard unless their Telegram ID is
    explicitly present in BOT_OWNER_IDS.
    """
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return False
    return bool(BOT_OWNER_IDS) and uid in {int(owner_id) for owner_id in BOT_OWNER_IDS}


def _developer_denied_keyboard(bot_data: dict[str, Any], user_id: int) -> InlineKeyboardMarkup:
    """No group/settings shortcuts on developer-denied screens."""
    return InlineKeyboardMarkup([[InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")]])


def _format_saved_ms(value: Any) -> str:
    try:
        ms = int(value or 0)
    except (TypeError, ValueError):
        ms = 0
    if ms <= 0:
        return "never"
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "invalid"


def _safe_page(raw: str | None, *, default: int = 0) -> int:
    try:
        return max(0, int(raw if raw is not None else default))
    except (TypeError, ValueError):
        return default


def _dev_user_items(bot_data: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    known_users = bot_data.get("known_users", {})
    user_state = bot_data.get("user_state", {})
    users: dict[int, dict[str, Any]] = {}

    if isinstance(known_users, dict):
        for raw_uid, raw_profile in known_users.items():
            try:
                uid = int(raw_uid)
            except (TypeError, ValueError):
                continue
            profile = dict(raw_profile) if isinstance(raw_profile, dict) else {}
            profile.setdefault("id", uid)
            users[uid] = profile

    if isinstance(user_state, dict):
        for raw_uid, raw_state in user_state.items():
            try:
                uid = int(raw_uid)
            except (TypeError, ValueError):
                continue
            state = raw_state if isinstance(raw_state, dict) else {}
            profile = users.setdefault(uid, {"id": uid})
            if state:
                profile.setdefault("lang", state.get("lang", "en"))
                profile.setdefault("first_seen_ms", state.get("first_seen_ms", 0))
                profile.setdefault("last_seen_ms", state.get("last_seen_ms", 0))

    def sort_key(item: tuple[int, dict[str, Any]]) -> int:
        profile = item[1]
        try:
            return int(profile.get("last_seen_ms") or profile.get("first_seen_ms") or 0)
        except (TypeError, ValueError):
            return 0

    return sorted(users.items(), key=sort_key, reverse=True)


def _dev_group_items(bot_data: dict[str, Any]) -> list[tuple[int, str]]:
    group_state = bot_data.get("group_state", {})
    chat_ids: set[int] = set()
    if isinstance(group_state, dict):
        for raw_chat_id in group_state.keys():
            try:
                chat_ids.add(int(raw_chat_id))
            except (TypeError, ValueError):
                continue
    chat_meta = bot_data.get("chat_meta_cache", {})
    if isinstance(chat_meta, dict):
        for raw_chat_id in chat_meta.keys():
            try:
                chat_ids.add(int(raw_chat_id))
            except (TypeError, ValueError):
                continue
    return sorted((chat_id, get_chat_title_from_state(bot_data, chat_id)) for chat_id in chat_ids)


def _feedback_items(bot_data: dict[str, Any]) -> list[dict[str, Any]]:
    raw_items = bot_data.get("user_feedback", [])
    if not isinstance(raw_items, list):
        return []
    items = [dict(item) for item in raw_items if isinstance(item, dict)]
    items.sort(key=lambda item: _safe_int(item.get("created_at_ms"), 0), reverse=True)
    return items


async def render_developer_feedback_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    async with BOT_DATA_LOCK:
        items = _feedback_items(context.bot_data)
        lines: list[str] = []
        known_users = context.bot_data.get("known_users", {}) if isinstance(context.bot_data.get("known_users", {}), dict) else {}
        for idx, item in enumerate(items[:15], 1):
            try:
                uid = int(item.get("user_id"))
            except (TypeError, ValueError):
                uid = 0
            profile = known_users.get(str(uid), {}) if uid and isinstance(known_users.get(str(uid), {}), dict) else {}
            name = str(item.get("full_name") or profile.get("full_name") or uid or "Unknown")
            username = str(item.get("username") or profile.get("username") or "")
            when = _format_saved_ms(item.get("created_at_ms"))
            body = h(str(item.get("text") or "")[:600])
            who = user_link(uid, name) if uid else h(name)
            handle = f" @{h(username)}" if username else ""
            lines.append(
                f"<b>{idx}. {who}</b>{handle}\n"
                f"🕒 <code>{h(when)}</code>\n"
                f"💬 {body}"
            )
        if not lines:
            lines.append(tr(context.bot_data, user_id, "feedback_empty"))
        text = tr(context.bot_data, user_id, "dev_feedback_title", total=len(items), items="\n\n".join(lines))
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_refresh_feedback"), callback_data="dev:feedback")],
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_back"), callback_data="dev:home")],
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")],
        ])
    await send_or_edit_panel(update, text, keyboard)


async def render_developer_dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    if not _dev_is_owner(user_id):
        await send_or_edit_panel(
            update,
            tr(context.bot_data, user_id, "dev_only"),
            _developer_denied_keyboard(context.bot_data, user_id),
        )
        return
    async with BOT_DATA_LOCK:
        users = len(_dev_user_items(context.bot_data))
        groups = len(_dev_group_items(context.bot_data))
        incidents = len(context.bot_data.get("incidents", {})) if isinstance(context.bot_data.get("incidents", {}), dict) else 0
        admin_cache = len(context.bot_data.get("admin_ids_cache", {})) if isinstance(context.bot_data.get("admin_ids_cache", {}), dict) else 0
        bot_perm_cache = len(context.bot_data.get("bot_member_cache", {})) if isinstance(context.bot_data.get("bot_member_cache", {}), dict) else 0
        chat_meta = len(context.bot_data.get("chat_meta_cache", {})) if isinstance(context.bot_data.get("chat_meta_cache", {}), dict) else 0
        text = tr(
            context.bot_data,
            user_id,
            "dev_title",
            users=users,
            groups=groups,
            incidents=incidents,
            feedback=len(_feedback_items(context.bot_data)),
            admin_cache=admin_cache,
            bot_perm_cache=bot_perm_cache,
            chat_meta=chat_meta,
            supabase="connected" if SUPABASE_AVAILABLE else "offline/disabled",
            redis="connected" if REDIS_AVAILABLE else "offline/disabled",
            backend=h(storage_backend_label()),
        )
        keyboard = _developer_keyboard(context.bot_data, user_id)
    await send_or_edit_panel(update, text, keyboard)


async def render_developer_users_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, page: int = 0) -> None:
    async with BOT_DATA_LOCK:
        items = _dev_user_items(context.bot_data)
        total = len(items)
        if total == 0:
            text = tr(context.bot_data, user_id, "dev_users_empty")
            keyboard = _developer_back_keyboard(context.bot_data, user_id)
        else:
            pages = max(1, (total + DEV_USERS_PAGE_SIZE - 1) // DEV_USERS_PAGE_SIZE)
            page = min(max(0, page), pages - 1)
            start = page * DEV_USERS_PAGE_SIZE
            page_items = items[start:start + DEV_USERS_PAGE_SIZE]
            rows: list[list[InlineKeyboardButton]] = []
            for uid, profile in page_items:
                name = str(profile.get("full_name") or profile.get("username") or uid)
                username = str(profile.get("username") or "")
                label = f"👤 {name[:24]}" + (f" (@{username[:16]})" if username else "")
                rows.append([InlineKeyboardButton(label[:60], callback_data=f"dev:user:{uid}")])
            nav: list[InlineKeyboardButton] = []
            if page > 0:
                nav.append(InlineKeyboardButton(tr(context.bot_data, user_id, "btn_prev"), callback_data=f"dev:users:{page - 1}"))
            if page < pages - 1:
                nav.append(InlineKeyboardButton(tr(context.bot_data, user_id, "btn_next"), callback_data=f"dev:users:{page + 1}"))
            if nav:
                rows.append(nav)
            rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_back"), callback_data="dev:home")])
            rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")])
            text = tr(context.bot_data, user_id, "dev_users_title", page=page + 1, pages=pages, total=total)
            keyboard = InlineKeyboardMarkup(rows)
    await send_or_edit_panel(update, text, keyboard)


async def render_developer_user_detail(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, target_user_id: int) -> None:
    async with BOT_DATA_LOCK:
        items = dict(_dev_user_items(context.bot_data))
        profile = dict(items.get(int(target_user_id), {"id": int(target_user_id)}))
        user_state = context.bot_data.get("user_state", {})
        state = {}
        if isinstance(user_state, dict):
            raw_state = user_state.get(int(target_user_id)) or user_state.get(str(int(target_user_id)))
            state = raw_state if isinstance(raw_state, dict) else {}
        groups = get_groups(context.bot_data, int(target_user_id))
        name = h(profile.get("full_name") or profile.get("username") or target_user_id)
        username = profile.get("username") or "-"
        lang = profile.get("lang") or state.get("lang") or "en"
        first_seen = _format_saved_ms(profile.get("first_seen_ms") or state.get("first_seen_ms"))
        last_seen = _format_saved_ms(profile.get("last_seen_ms") or state.get("last_seen_ms"))
        text = tr(
            context.bot_data,
            user_id,
            "dev_user_detail",
            name=name,
            username=h(username),
            user_id=int(target_user_id),
            lang=h(lang),
            groups_count=len(groups),
            first_seen=h(first_seen),
            last_seen=h(last_seen),
        )
        rows: list[list[InlineKeyboardButton]] = []
        for chat_id in groups[:8]:
            title = get_chat_title_from_state(context.bot_data, chat_id)
            rows.append([InlineKeyboardButton(f"💬 {title[:40]}", callback_data=f"grp:{chat_id}")])
        rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_back"), callback_data="dev:users:0")])
        rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")])
        keyboard = InlineKeyboardMarkup(rows)
    await send_or_edit_panel(update, text, keyboard)


async def render_developer_groups_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, page: int = 0) -> None:
    async with BOT_DATA_LOCK:
        items = _dev_group_items(context.bot_data)
        total = len(items)
        if total == 0:
            text = tr(context.bot_data, user_id, "dev_groups_empty")
            keyboard = _developer_back_keyboard(context.bot_data, user_id)
        else:
            pages = max(1, (total + DEV_GROUPS_PAGE_SIZE - 1) // DEV_GROUPS_PAGE_SIZE)
            page = min(max(0, page), pages - 1)
            start = page * DEV_GROUPS_PAGE_SIZE
            page_items = items[start:start + DEV_GROUPS_PAGE_SIZE]
            rows: list[list[InlineKeyboardButton]] = [
                [InlineKeyboardButton(f"💬 {title[:42]}", callback_data=f"grp:{chat_id}")]
                for chat_id, title in page_items
            ]
            nav: list[InlineKeyboardButton] = []
            if page > 0:
                nav.append(InlineKeyboardButton(tr(context.bot_data, user_id, "btn_prev"), callback_data=f"dev:groups:{page - 1}"))
            if page < pages - 1:
                nav.append(InlineKeyboardButton(tr(context.bot_data, user_id, "btn_next"), callback_data=f"dev:groups:{page + 1}"))
            if nav:
                rows.append(nav)
            rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_back"), callback_data="dev:home")])
            rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")])
            text = tr(context.bot_data, user_id, "dev_groups_title", total=total)
            keyboard = InlineKeyboardMarkup(rows)
    await send_or_edit_panel(update, text, keyboard)


async def render_developer_memory_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    async with BOT_DATA_LOCK:
        users = len(_dev_user_items(context.bot_data))
        groups = len(_dev_group_items(context.bot_data))
        incidents = len(context.bot_data.get("incidents", {})) if isinstance(context.bot_data.get("incidents", {}), dict) else 0
        text = tr(
            context.bot_data,
            user_id,
            "dev_memory_title",
            backend=h(storage_backend_label()),
            supabase="connected" if SUPABASE_AVAILABLE else "offline/disabled",
            redis="connected" if REDIS_AVAILABLE else "offline/disabled",
            users=users,
            groups=groups,
            incidents=incidents,
            supabase_last_save=h(SUPABASE_LAST_SAVE_UTC),
            redis_last_save=h(REDIS_LAST_SAVE_UTC),
        )
        keyboard = _developer_back_keyboard(context.bot_data, user_id)
    await send_or_edit_panel(update, text, keyboard)




def _developer_hash_config_keyboard(bot_data: dict[str, Any], user_id: int) -> InlineKeyboardMarkup:
    enabled = trusted_hash_whitelist_enabled(bot_data)
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_hash_disable" if enabled else "btn_hash_enable"), callback_data="dev:hash:toggle")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_hash_size"), callback_data="dev:hash:size")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_hash_limit"), callback_data="dev:hash:limit")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data="dev:home")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")],
        ]
    )


async def render_developer_hash_config_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, *, notice: str = "") -> None:
    async with BOT_DATA_LOCK:
        ensure_runtime_config(context.bot_data)
        enabled = trusted_hash_whitelist_enabled(context.bot_data)
        max_bytes = trusted_hash_max_download_bytes(context.bot_data)
        max_hashes = max_trusted_file_hashes(context.bot_data)
        text = tr(
            context.bot_data,
            user_id,
            "dev_hash_config_title",
            enabled=str(enabled).lower(),
            max_bytes=max_bytes,
            max_mb=h(format_bytes_mb(max_bytes)),
            max_hashes=max_hashes,
        )
        if notice:
            text = f"{notice}\n\n{text}"
        keyboard = _developer_hash_config_keyboard(context.bot_data, user_id)
    await send_or_edit_panel(update, text, keyboard)


async def render_developer_hash_size_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    async with BOT_DATA_LOCK:
        max_bytes = trusted_hash_max_download_bytes(context.bot_data)
        rows = [[InlineKeyboardButton(f"📦 {format_bytes_mb(value)}", callback_data=f"dev:hash:size:{value}")] for value in TRUSTED_HASH_SIZE_OPTIONS]
        rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_back"), callback_data="dev:hash")])
        rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")])
        text = tr(context.bot_data, user_id, "dev_hash_size_title", max_bytes=max_bytes, max_mb=h(format_bytes_mb(max_bytes)))
        keyboard = InlineKeyboardMarkup(rows)
    await send_or_edit_panel(update, text, keyboard)


async def render_developer_hash_limit_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    async with BOT_DATA_LOCK:
        max_hashes = max_trusted_file_hashes(context.bot_data)
        rows = [[InlineKeyboardButton(f"🔢 {value}", callback_data=f"dev:hash:limit:{value}")] for value in TRUSTED_HASH_LIMIT_OPTIONS]
        rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_back"), callback_data="dev:hash")])
        rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")])
        text = tr(context.bot_data, user_id, "dev_hash_limit_title", max_hashes=max_hashes)
        keyboard = InlineKeyboardMarkup(rows)
    await send_or_edit_panel(update, text, keyboard)


async def update_developer_hash_config(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    *,
    toggle_enabled: bool = False,
    max_bytes: int | None = None,
    max_hashes: int | None = None,
) -> None:
    async with BOT_DATA_LOCK:
        config = ensure_runtime_config(context.bot_data)
        if toggle_enabled:
            config["trusted_file_hash_whitelist_enabled"] = not trusted_hash_whitelist_enabled(context.bot_data)
        if max_bytes is not None:
            config["trusted_hash_max_download_bytes"] = _coerce_int_range(max_bytes, TRUSTED_HASH_MAX_DOWNLOAD_BYTES, min_value=1, max_value=100_000_000)
        if max_hashes is not None:
            config["max_trusted_file_hashes"] = _coerce_int_range(max_hashes, MAX_TRUSTED_FILE_HASHES, min_value=1, max_value=1000)
        ensure_runtime_config(context.bot_data)
        await persist_context_memory(context, reason="developer_hash_runtime_config", force=True, caller_holds_lock=True)
    await render_developer_hash_config_panel(update, context, user_id, notice=tr(context.bot_data, user_id, "dev_hash_config_saved"))


async def set_pending_format_edit(context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, mode: str) -> None:
    async with BOT_DATA_LOCK:
        state = get_user_state(context.bot_data, int(user_id))
        state["pending_format_edit"] = {"chat_id": int(chat_id), "mode": str(mode), "created_at_ms": now_ms()}
        await persist_context_memory(context, reason="pending_format_edit", force=True, caller_holds_lock=True)


async def clear_pending_format_edit(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    async with BOT_DATA_LOCK:
        state = get_user_state(context.bot_data, int(user_id))
        state.pop("pending_format_edit", None)
        await persist_context_memory(context, reason="clear_pending_format_edit", force=True, caller_holds_lock=True)


async def navigation_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    user_id = query.from_user.id
    if not callback_is_private(query):
        await reject_group_config_callback(query, context.bot_data, user_id)
        return
    await safe_answer_callback(query)
    data = query.data or ""
    if data == "nav:home":
        await clear_pending_format_edit(context, user_id)
        await clear_pending_user_feedback(context, user_id)
        await render_home(update, context, user_id)
        return
    if data == "nav:help":
        await clear_pending_format_edit(context, user_id)
        await clear_pending_user_feedback(context, user_id)
        await render_help_panel(update, context, user_id)
        return
    if data == "nav:about":
        await clear_pending_format_edit(context, user_id)
        await clear_pending_user_feedback(context, user_id)
        await render_about_panel(update, context, user_id)
        return
    if data == "nav:language":
        await clear_pending_format_edit(context, user_id)
        await clear_pending_user_feedback(context, user_id)
        await render_language_panel(update, context, user_id)
        return
    if data == "nav:feedback":
        await clear_pending_format_edit(context, user_id)
        await render_feedback_prompt(update, context, user_id)
        return
    if data.startswith("nav:groups"):
        await clear_pending_format_edit(context, user_id)
        await clear_pending_user_feedback(context, user_id)
        page = 0
        parts = data.split(":")
        if len(parts) >= 3:
            try:
                page = int(parts[2])
            except ValueError:
                page = 0
        await render_groups_panel(update, context, user_id, page=page)
        return
    if not await is_admin_or_owner(context, user_id, allow_api=False):
        await safe_edit_query(query, tr(context.bot_data, user_id, "access_denied"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return
    await clear_pending_format_edit(context, user_id)
    await clear_pending_user_feedback(context, user_id)
    await render_home(update, context, user_id)


async def developer_dashboard_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    user_id = int(query.from_user.id)
    if not callback_is_private(query):
        await reject_group_config_callback(query, context.bot_data, user_id)
        return
    if not _dev_is_owner(user_id):
        await safe_answer_callback(query, text=tr(context.bot_data, user_id, "dev_only_alert"), show_alert=True)
        await safe_edit_query(query, tr(context.bot_data, user_id, "dev_only"), reply_markup=_developer_denied_keyboard(context.bot_data, user_id))
        logger.warning("Developer dashboard denied user_id=%s callback=%r", user_id, query.data)
        return
    await safe_answer_callback(query)

    data = query.data or "dev:home"
    parts = data.split(":")
    action = parts[1] if len(parts) > 1 else "home"

    if action in {"home", "refresh"}:
        await render_developer_dashboard(update, context, user_id)
        return
    if action == "memory":
        await render_developer_memory_panel(update, context, user_id)
        return
    if action == "feedback":
        await render_developer_feedback_panel(update, context, user_id)
        return
    if action == "hash":
        sub = parts[2] if len(parts) > 2 else "menu"
        if sub == "toggle":
            await update_developer_hash_config(update, context, user_id, toggle_enabled=True)
            return
        if sub == "size":
            if len(parts) > 3:
                try:
                    await update_developer_hash_config(update, context, user_id, max_bytes=int(parts[3]))
                except ValueError:
                    await render_developer_hash_size_panel(update, context, user_id)
                return
            await render_developer_hash_size_panel(update, context, user_id)
            return
        if sub == "limit":
            if len(parts) > 3:
                try:
                    await update_developer_hash_config(update, context, user_id, max_hashes=int(parts[3]))
                except ValueError:
                    await render_developer_hash_limit_panel(update, context, user_id)
                return
            await render_developer_hash_limit_panel(update, context, user_id)
            return
        await render_developer_hash_config_panel(update, context, user_id)
        return
    if action == "users":
        page = _safe_page(parts[2] if len(parts) > 2 else "0")
        await render_developer_users_panel(update, context, user_id, page)
        return
    if action == "user" and len(parts) > 2:
        try:
            target_user_id = int(parts[2])
        except ValueError:
            await render_developer_users_panel(update, context, user_id, 0)
            return
        await render_developer_user_detail(update, context, user_id, target_user_id)
        return
    if action == "groups":
        page = _safe_page(parts[2] if len(parts) > 2 else "0")
        await render_developer_groups_panel(update, context, user_id, page)
        return

    await render_developer_dashboard(update, context, user_id)


async def group_dashboard_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    user_id = query.from_user.id
    if not callback_is_private(query):
        await reject_group_config_callback(query, context.bot_data, user_id)
        return
    await safe_answer_callback(query)
    data = query.data or ""
    chat_id = _safe_chat_id_from_payload(data)
    if chat_id is None:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await link_user_to_group(context, user_id, chat_id)
        await render_bot_admin_required_panel(update, context, user_id, chat_id)
        return
    await link_user_to_group(context, user_id, chat_id)
    await render_group_settings_panel(update, context, user_id, chat_id)


async def group_settings_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    user_id = query.from_user.id
    if not callback_is_private(query):
        await reject_group_config_callback(query, context.bot_data, user_id)
        return
    await safe_answer_callback(query)
    data = query.data or ""
    parts = data.split(":", 2)
    if len(parts) != 3:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    _, chat_id_raw, field = parts
    try:
        chat_id = int(chat_id_raw)
    except ValueError:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await render_bot_admin_required_panel(update, context, user_id, chat_id)
        return

    async with BOT_DATA_LOCK:
        settings = get_group_settings(context.bot_data, chat_id)
        if field == "protection":
            settings["protection_enabled"] = not bool(settings.get("protection_enabled", True))
            action_label = f"toggle protection -> {settings['protection_enabled']}"
        elif field == "strictness":
            current_strictness = str(settings.get("strictness") or "standard")
            settings["strictness"] = {"standard": "high", "high": "strict", "strict": "standard"}.get(current_strictness, "standard")
            action_label = f"set strictness -> {settings['strictness']}"
        elif field == "silent":
            settings["silent_mode"] = not bool(settings.get("silent_mode", False))
            action_label = f"toggle silent mode -> {settings['silent_mode']}"
        else:
            await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
            return
        _record_admin_action_log_locked(context.bot_data, chat_id=chat_id, admin_id=user_id, admin_name=query.from_user.full_name, action=action_label, result="settings updated")
        state = get_user_state(context.bot_data, int(user_id))
        groups = state.setdefault("groups", [])
        if int(chat_id) not in [int(g) for g in groups if str(g).lstrip("-").isdigit()]:
            groups.append(int(chat_id))
        await persist_context_memory(context, reason="group_settings_update", force=True, caller_holds_lock=True)

    if field in {"protection", "silent", "strictness"}:
        await render_group_protection_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "settings_saved"))
    else:
        await render_group_settings_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "settings_saved"))


async def format_manager_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    user_id = query.from_user.id
    if not callback_is_private(query):
        await reject_group_config_callback(query, context.bot_data, user_id)
        return
    await safe_answer_callback(query)
    data = query.data or ""
    parts = data.split(":", 2)
    if len(parts) != 3:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    _, chat_id_raw, action = parts
    try:
        chat_id = int(chat_id_raw)
    except ValueError:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await render_bot_admin_required_panel(update, context, user_id, chat_id)
        return
    schedule_bot_member_refresh(context, chat_id)
    await link_user_to_group(context, user_id, chat_id)

    if action == "menu":
        await render_format_manager_panel(update, context, user_id, chat_id)
        return
    if action in {"add", "edit"}:
        await set_pending_format_edit(context, user_id, chat_id, action)
        prompt_key = "formats_prompt_add" if action == "add" else "formats_prompt_edit"
        await safe_edit_query(query, tr(context.bot_data, user_id, prompt_key), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return
    if action == "remove":
        async with BOT_DATA_LOCK:
            settings = dict(get_group_settings(context.bot_data, chat_id))
        if not settings.get("custom_blocked_extensions"):
            await render_format_manager_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "formats_empty"))
            return
        await render_format_manager_panel(update, context, user_id, chat_id, remove_mode=True)
        return
    if action == "clear":
        await render_destructive_confirmation(
            update,
            context,
            user_id,
            chat_id,
            summary_key="confirm_clear_formats",
            yes_callback=f"gfmt:{chat_id}:clear_yes",
            no_callback=f"gfmt:{chat_id}:menu",
        )
        return
    if action == "clear_yes":
        async with BOT_DATA_LOCK:
            settings = get_group_settings(context.bot_data, chat_id)
            settings["custom_blocked_extensions"] = []
            await persist_context_memory(context, reason="custom_formats_clear", force=True, caller_holds_lock=True)
        await render_format_manager_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "formats_cleared"))
        return

    await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))


async def delete_format_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    user_id = query.from_user.id
    if not callback_is_private(query):
        await reject_group_config_callback(query, context.bot_data, user_id)
        return
    await safe_answer_callback(query)
    data = query.data or ""
    parts = data.split(":", 2)
    if len(parts) != 3:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    _, chat_id_raw, ext_raw = parts
    try:
        chat_id = int(chat_id_raw)
    except ValueError:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    ext = _normalize_extension(ext_raw)
    if not VALID_EXTENSION_RE.fullmatch(ext):
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await render_bot_admin_required_panel(update, context, user_id, chat_id)
        return
    schedule_bot_member_refresh(context, chat_id)

    async with BOT_DATA_LOCK:
        settings = get_group_settings(context.bot_data, chat_id)
        settings["custom_blocked_extensions"] = [item for item in settings.get("custom_blocked_extensions", []) if item != ext]
        await persist_context_memory(context, reason="custom_format_delete", force=True, caller_holds_lock=True)
    await render_format_manager_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "formats_removed", ext=h(ext)))



async def allowed_formats_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user: return
    user_id = query.from_user.id
    if not callback_is_private(query):
        await reject_group_config_callback(query, context.bot_data, user_id); return
    await safe_answer_callback(query)
    parts = (query.data or "").split(":", 2)
    if len(parts) != 3:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    _, chat_id_raw, action = parts
    try: chat_id = int(chat_id_raw)
    except ValueError:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id)); return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await render_bot_admin_required_panel(update, context, user_id, chat_id)
        return
    schedule_bot_member_refresh(context, chat_id)
    await link_user_to_group(context, user_id, chat_id)
    if action == "menu": await render_allowed_manager_panel(update, context, user_id, chat_id); return
    if action in {"add", "edit"}:
        await set_pending_format_edit(context, user_id, chat_id, "allow_add" if action == "add" else "allow_edit")
        await safe_edit_query(query, tr(context.bot_data, user_id, "allowed_prompt_add" if action == "add" else "allowed_prompt_edit"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id)); return
    if action == "remove":
        async with BOT_DATA_LOCK: settings = dict(get_group_settings(context.bot_data, chat_id))
        if not settings.get("allowed_extensions"):
            await render_allowed_manager_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "formats_empty")); return
        await render_allowed_manager_panel(update, context, user_id, chat_id, remove_mode=True); return
    if action == "clear":
        await render_destructive_confirmation(update, context, user_id, chat_id, summary_key="confirm_clear_allowed", yes_callback=f"gallow:{chat_id}:clear_yes", no_callback=f"gallow:{chat_id}:menu"); return
    if action == "clear_yes":
        async with BOT_DATA_LOCK:
            settings = get_group_settings(context.bot_data, chat_id); settings["allowed_extensions"] = []
            await persist_context_memory(context, reason="allowed_formats_clear", force=True, caller_holds_lock=True)
        await render_allowed_manager_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "allowed_cleared")); return
    await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))


async def delete_allowed_format_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user: return
    user_id = query.from_user.id
    if not callback_is_private(query): await reject_group_config_callback(query, context.bot_data, user_id); return
    await safe_answer_callback(query)
    parts = (query.data or "").split(":", 2)
    if len(parts) != 3: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    _, chat_id_raw, ext_raw = parts
    try: chat_id = int(chat_id_raw)
    except ValueError: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    ext = _normalize_extension(ext_raw)
    if not VALID_EXTENSION_RE.fullmatch(ext): await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id)); return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await render_bot_admin_required_panel(update, context, user_id, chat_id)
        return
    async with BOT_DATA_LOCK:
        settings = get_group_settings(context.bot_data, chat_id)
        settings["allowed_extensions"] = [item for item in settings.get("allowed_extensions", []) if item != ext]
        await persist_context_memory(context, reason="allowed_format_delete", force=True, caller_holds_lock=True)
    await render_allowed_manager_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "allowed_removed", ext=h(ext)))


async def group_admin_panel_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user: return
    user_id = query.from_user.id
    if not callback_is_private(query): await reject_group_config_callback(query, context.bot_data, user_id); return
    await safe_answer_callback(query)
    parts = (query.data or "").split(":", 2)
    if len(parts) != 3: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    _, chat_id_raw, action = parts
    try: chat_id = int(chat_id_raw)
    except ValueError: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id)); return
    await link_user_to_group(context, user_id, chat_id)
    if action == "health":
        await render_group_health_panel(update, context, user_id, chat_id)
        return
    if action == "refresh":
        if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
            await render_bot_admin_required_panel(update, context, user_id, chat_id)
            return
        await render_group_settings_panel(update, context, user_id, chat_id)
        return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await render_bot_admin_required_panel(update, context, user_id, chat_id)
        return
    if action == "protection": await render_group_protection_panel(update, context, user_id, chat_id)
    elif action == "scanner":
        async with BOT_DATA_LOCK: title = get_chat_title_from_state(context.bot_data, chat_id)
        await send_or_edit_panel(update, tr(context.bot_data, user_id, "scanner_panel_title", group=h(title), scanner=scanner_group_config_text(context.bot_data, user_id, chat_id)), _group_back_keyboard(context.bot_data, user_id, chat_id))
    elif action == "incidents": await render_group_incidents_panel(update, context, user_id, chat_id)
    elif action == "clear_incidents":
        await render_destructive_confirmation(update, context, user_id, chat_id, summary_key="confirm_clear_incidents", yes_callback=f"gap:{chat_id}:clear_incidents_yes", no_callback=f"gap:{chat_id}:incidents")
    elif action == "clear_incidents_yes":
        async with BOT_DATA_LOCK:
            incidents = context.bot_data.get("incidents", {}) if isinstance(context.bot_data.get("incidents", {}), dict) else {}
            for ikey, incident in list(incidents.items()):
                if isinstance(incident, dict) and str(incident.get("chat_id")) == str(int(chat_id)) and incident.get("done"):
                    incidents.pop(ikey, None)
            await persist_context_memory(context, reason="group_clear_handled_incidents", force=True, caller_holds_lock=True)
        await render_group_incidents_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "incidents_cleared"))
    elif action == "risk": await render_group_risk_panel(update, context, user_id, chat_id)
    elif action == "admins": await render_group_admin_alert_panel(update, context, user_id, chat_id)
    elif action == "admin_logs": await render_group_admin_logs_panel(update, context, user_id, chat_id)
    elif action == "clear_admin_logs":
        await render_destructive_confirmation(update, context, user_id, chat_id, summary_key="confirm_clear_admin_logs", yes_callback=f"gap:{chat_id}:clear_admin_logs_yes", no_callback=f"gap:{chat_id}:admin_logs")
    elif action == "clear_admin_logs_yes":
        async with BOT_DATA_LOCK:
            logs = [item for item in _admin_action_logs(context.bot_data) if str(item.get("chat_id")) != str(int(chat_id))]
            context.bot_data["admin_action_logs"] = logs
            await persist_context_memory(context, reason="clear_admin_action_logs", force=True, caller_holds_lock=True)
        await render_group_admin_logs_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "admin_logs_cleared"))
    elif action == "allowed": await render_allowed_manager_panel(update, context, user_id, chat_id)
    elif action == "health": await render_group_health_panel(update, context, user_id, chat_id)
    elif action == "auto": await render_auto_actions_panel(update, context, user_id, chat_id)
    else: await render_group_settings_panel(update, context, user_id, chat_id)


async def trusted_hash_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    user_id = query.from_user.id
    if not callback_is_private(query):
        await reject_group_config_callback(query, context.bot_data, user_id)
        return
    await safe_answer_callback(query)
    parts = (query.data or "").split(":", 2)
    if len(parts) != 3:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    _, chat_id_raw, action = parts
    try:
        chat_id = int(chat_id_raw)
    except ValueError:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await render_bot_admin_required_panel(update, context, user_id, chat_id)
        return
    if action == "menu":
        await render_trusted_hash_panel(update, context, user_id, chat_id)
    elif action == "add":
        async with BOT_DATA_LOCK:
            state = get_user_state(context.bot_data, user_id)
            state["pending_format_edit"] = {"chat_id": int(chat_id), "mode": "hash_add"}
            await persist_context_memory(context, reason="trusted_hash_prompt", force=False, caller_holds_lock=True)
        await safe_edit_query(query, tr(context.bot_data, user_id, "trusted_hash_prompt_add"), reply_markup=_group_back_keyboard(context.bot_data, user_id, chat_id))
    elif action == "remove":
        await render_trusted_hash_panel(update, context, user_id, chat_id, remove_mode=True)
    elif action == "clear":
        await render_destructive_confirmation(
            update,
            context,
            user_id,
            chat_id,
            summary_key="confirm_clear_hashes",
            yes_callback=f"ghash:{chat_id}:clear_yes",
            no_callback=f"ghash:{chat_id}:menu",
        )
    elif action == "clear_yes":
        async with BOT_DATA_LOCK:
            clear_trusted_file_hashes(context.bot_data, chat_id)
            await persist_context_memory(context, reason="trusted_hash_clear", force=True, caller_holds_lock=True)
        await render_trusted_hash_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "trusted_hash_cleared"))
    else:
        await render_trusted_hash_panel(update, context, user_id, chat_id)


async def delete_trusted_hash_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    user_id = query.from_user.id
    if not callback_is_private(query):
        await reject_group_config_callback(query, context.bot_data, user_id)
        return
    await safe_answer_callback(query)
    parts = (query.data or "").split(":", 2)
    if len(parts) != 3:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    _, chat_id_raw, digest_prefix = parts
    try:
        chat_id = int(chat_id_raw)
    except ValueError:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await render_bot_admin_required_panel(update, context, user_id, chat_id)
        return
    async with BOT_DATA_LOCK:
        remove_trusted_file_hash(context.bot_data, chat_id, digest_prefix)
        await persist_context_memory(context, reason="trusted_hash_remove", force=True, caller_holds_lock=True)
    await render_trusted_hash_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "trusted_hash_removed"))


async def auto_actions_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user: return
    user_id = query.from_user.id
    if not callback_is_private(query): await reject_group_config_callback(query, context.bot_data, user_id); return
    await safe_answer_callback(query)
    parts = (query.data or "").split(":", 2)
    if len(parts) != 3: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    _, chat_id_raw, mode = parts
    try: chat_id = int(chat_id_raw)
    except ValueError: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    if mode not in {"off", "warn", "smart", "ban"}: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id)); return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await render_bot_admin_required_panel(update, context, user_id, chat_id)
        return
    async with BOT_DATA_LOCK:
        settings = get_group_settings(context.bot_data, chat_id)
        old_mode = str(settings.get("auto_action_mode") or "off")
        settings["auto_action_mode"] = mode
        _record_admin_action_log_locked(context.bot_data, chat_id=chat_id, admin_id=user_id, admin_name=query.from_user.full_name, action=f"auto action {old_mode} -> {mode}", result="auto rule updated")
        await persist_context_memory(context, reason="auto_action_update", force=True, caller_holds_lock=True)
    await render_auto_actions_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "auto_saved"))


async def private_text_flow_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    chat = update.effective_chat
    if not user or not message or not chat or chat.type != ChatType.PRIVATE:
        return

    text = (message.text or "").strip()
    async with BOT_DATA_LOCK:
        user_state = context.bot_data.get("user_state", {})
        state = (user_state.get(user.id) or user_state.get(str(user.id)) or {}) if isinstance(user_state, dict) else {}
        pending_feedback = isinstance(state, dict) and isinstance(state.get("pending_user_feedback"), dict)
        pending = dict(state.get("pending_format_edit")) if isinstance(state, dict) and isinstance(state.get("pending_format_edit"), dict) else None

    if pending_feedback:
        if text.casefold() in {"/cancel", "cancel", "បោះបង់"}:
            await clear_pending_user_feedback(context, user.id)
            await safe_reply(update, tr(context.bot_data, user.id, "feedback_cancelled"), reply_markup=await dashboard_home_keyboard(context, user.id))
            return
        if len(text) < 8:
            await safe_reply(update, tr(context.bot_data, user.id, "feedback_too_short"))
            return
        await save_user_feedback(context, user, text)
        await safe_reply(update, tr(context.bot_data, user.id, "feedback_thanks"), reply_markup=await dashboard_home_keyboard(context, user.id))
        return

    if not isinstance(pending, dict):
        return

    if text.casefold() in {"/cancel", "cancel", "បោះបង់"}:
        await clear_pending_format_edit(context, user.id)
        await safe_reply(update, tr(context.bot_data, user.id, "formats_cancelled"), reply_markup=await dashboard_home_keyboard(context, user.id))
        return

    try:
        chat_id = int(pending.get("chat_id"))
    except (TypeError, ValueError):
        await clear_pending_format_edit(context, user.id)
        await safe_reply(update, tr(context.bot_data, user.id, "unknown_error"), reply_markup=await dashboard_home_keyboard(context, user.id))
        return

    if not await is_user_admin_in_group(context, chat_id, user.id, allow_api=True):
        await clear_pending_format_edit(context, user.id)
        await safe_reply(update, tr(context.bot_data, user.id, "group_admin_only"), reply_markup=await dashboard_home_keyboard(context, user.id))
        return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await clear_pending_format_edit(context, user.id)
        await render_bot_admin_required_panel(update, context, user.id, chat_id)
        return

    mode = str(pending.get("mode") or "add")

    if mode == "hash_add":
        digest = normalize_sha256_hash(text)
        if not digest:
            await safe_reply(update, tr(context.bot_data, user.id, "trusted_hash_invalid"))
            return

        limit_reached = False
        async with BOT_DATA_LOCK:
            settings = get_group_settings(context.bot_data, chat_id)
            hashes = settings.get("trusted_file_hashes", [])
            if digest not in hashes and len(hashes) >= max_trusted_file_hashes(context.bot_data):
                limit_reached = True
            else:
                add_trusted_file_hash(context.bot_data, chat_id, digest, added_by=user.id, file_name="manual hash")
                state = get_user_state(context.bot_data, user.id)
                state.pop("pending_format_edit", None)
                await persist_context_memory(context, reason="trusted_hash_add_manual", force=True, caller_holds_lock=True)

        if limit_reached:
            await safe_reply(update, tr(context.bot_data, user.id, "trusted_hash_limit"))
            return
        await render_trusted_hash_panel(update, context, user.id, chat_id, notice=tr(context.bot_data, user.id, "trusted_hash_saved"))
        return

    parsed = parse_extensions_from_text(text)
    if not parsed:
        await safe_reply(update, tr(context.bot_data, user.id, "formats_invalid"))
        return

    if mode in {"allow_add", "allow_edit"}:
        parsed = _dedupe_allowed_extensions(parsed, limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
        if not parsed:
            await safe_reply(update, tr(context.bot_data, user.id, "allowed_invalid"))
            return
    else:
        parsed = _dedupe_valid_extensions(parsed, limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
        if not parsed:
            await safe_reply(update, tr(context.bot_data, user.id, "formats_invalid"))
            return

    async with BOT_DATA_LOCK:
        settings = get_group_settings(context.bot_data, chat_id)
        if mode in {"allow_add", "allow_edit"}:
            current = settings.get("allowed_extensions", [])
            if mode == "allow_edit":
                settings["allowed_extensions"] = parsed[:MAX_CUSTOM_BLOCKED_EXTENSIONS]
            else:
                settings["allowed_extensions"] = _dedupe_allowed_extensions([*current, *parsed], limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
            save_reason = "allowed_formats_save"
        else:
            current = settings.get("custom_blocked_extensions", [])
            if mode == "edit":
                settings["custom_blocked_extensions"] = parsed[:MAX_CUSTOM_BLOCKED_EXTENSIONS]
            else:
                settings["custom_blocked_extensions"] = _dedupe_valid_extensions([*current, *parsed], limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
            save_reason = "custom_formats_save"

        state = get_user_state(context.bot_data, user.id)
        state.pop("pending_format_edit", None)
        groups = state.setdefault("groups", [])
        if int(chat_id) not in [int(g) for g in groups if str(g).lstrip("-").isdigit()]:
            groups.append(int(chat_id))
        await persist_context_memory(context, reason=save_reason, force=True, caller_holds_lock=True)

    if mode in {"allow_add", "allow_edit"}:
        await render_allowed_manager_panel(update, context, user.id, chat_id, notice=tr(context.bot_data, user.id, "allowed_saved"))
    else:
        await render_format_manager_panel(update, context, user.id, chat_id, notice=tr(context.bot_data, user.id, "formats_saved"))


async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    chat = update.effective_chat
    if not user:
        return
    try:
        await remember_user_profile(context.bot_data, user)
        if chat and is_group_chat(chat.type):
            if not await is_admin_or_owner(context, user.id, chat_id=chat.id, allow_api=True):
                await safe_reply(update, tr(context.bot_data, user.id, "group_admin_only"))
                return
            await remember_chat_meta(context.bot_data, chat)
            await link_user_to_group(context, user.id, chat.id, title=chat.title or str(chat.id), chat_type=str(chat.type))
            if not await ensure_bot_settings_unlocked(context, chat.id, force=True):
                await safe_reply(
                    update,
                    tr(context.bot_data, user.id, "bot_admin_required_group"),
                    reply_markup=bot_admin_required_group_keyboard(context.bot_data, user.id, chat.id),
                )
                return
            url = await group_private_settings_url(context, chat.id)
            kb = InlineKeyboardMarkup([[InlineKeyboardButton(tr(context.bot_data, user.id, "btn_settings"), url=url)]])
            await safe_reply(update, tr(context.bot_data, user.id, "settings_group_open_private") + "\n\n" + tr(context.bot_data, user.id, "config_private_only"), reply_markup=kb)
            return
        await render_groups_panel(update, context, user.id)
    except Exception:
        logger.exception("/settings failed user_id=%s", user.id, exc_info=True)
        await safe_reply(update, tr(context.bot_data, user.id, "unknown_error"))



def apply_group_scan_policy(bot_data: dict[str, Any], chat_id: int, scan: FileScanResult) -> FileScanResult:
    settings = get_group_settings(bot_data, chat_id)
    if not settings.get("protection_enabled", True):
        return replace(scan, blocked=False, reason_code="protection_disabled", reason_display="group protection is disabled")

    if trusted_hash_whitelist_enabled(bot_data) and scan.file_sha256 and is_trusted_file_hash(bot_data, chat_id, scan.file_sha256):
        return replace(scan, blocked=False, reason_code="trusted_hash_whitelist", reason_display="allowed by trusted SHA256 file hash whitelist")

    matched_ext = _normalize_extension(scan.matched_extension) if scan.matched_extension else ""
    suffixes = filename_suffixes(scan.file_name)
    last_ext = suffixes[-1] if suffixes else matched_ext
    allowed_exts = set(settings.get("allowed_extensions", []))
    allowed_match = last_ext if last_ext in allowed_exts else ""

    custom_blocked = set(settings.get("custom_blocked_extensions", []))
    custom_match = last_ext if last_ext in custom_blocked else next((ext for ext in suffixes if ext in custom_blocked), "")
    if custom_match:
        # Allowed formats are meant to bypass only custom delete formats.
        # They must not override the core scanner, e.g. .exe, PE magic bytes,
        # or invoice.exe.zip. Exact executable exceptions belong in the
        # trusted SHA256 whitelist above.
        if allowed_match == custom_match and not scan.blocked:
            return replace(
                scan,
                blocked=False,
                reason_code="allowed_extension",
                reason_display=f"allowed by group settings: {allowed_match}",
                matched_extension=allowed_match,
            )
        return replace(
            scan,
            blocked=True,
            reason_code="custom_group_extension",
            reason_display=f"blocked by group custom delete format {custom_match}",
            matched_extension=custom_match,
        )

    strictness = str(settings.get("strictness", "standard"))
    if strictness == "standard" and scan.blocked:
        # Standard mode is intentionally calm: block .exe, renamed PE files, and archives containing .exe only.
        if matched_ext in BLOCKED_EXTENSIONS or scan.reason_code == "pe_magic_header":
            return scan
        return replace(scan, blocked=False, reason_code="standard_mode_allowed", reason_display="allowed by Standard strictness")

    return scan


# ─────────────────────────────────────────────────────────────
# ADMIN ALERTS
# ─────────────────────────────────────────────────────────────


def format_admin_alert(
    bot_data: dict[str, Any],
    admin_id: int,
    *,
    sender_name: str,
    sender_id: int,
    file_name: str,
    group_name: str,
    group_id: int,
    time_str: str,
    scan_result: str = "blocked file",
) -> str:
    lang = get_lang(bot_data, admin_id)
    return TEXTS[lang]["admin_alert"].format(
        sender_name=h(sender_name),
        sender_id=int(sender_id),
        file_name=h(file_name),
        scan_result=h(scan_result),
        group_name=h(group_name),
        group_id=int(group_id),
        time=h(time_str),
    )


def action_result_text(bot_data: dict[str, Any], admin_id: int, incident: dict[str, Any]) -> str:
    action = str(incident.get("action") or "")
    sender_name = h(incident.get("sender_name") or "Unknown")
    if action == "ban":
        return tr(bot_data, admin_id, "action_ban_ok", name=sender_name)
    if action == "warn":
        return tr(bot_data, admin_id, "action_warn_ok", name=sender_name)
    if action == "ignore":
        return tr(bot_data, admin_id, "action_ignore_ok")
    return ""


def handled_footer(bot_data: dict[str, Any], admin_id: int, incident: dict[str, Any]) -> str:
    if not incident.get("done"):
        return ""
    result = action_result_text(bot_data, admin_id, incident)
    handled_by = incident.get("handled_by")
    handled_by_name = str(incident.get("handled_by_name") or handled_by or "Admin")
    admin_display = user_link(int(handled_by), handled_by_name) if handled_by else h(handled_by_name)
    return f"\n\n{result}\n{tr(bot_data, admin_id, 'handled_by', admin=admin_display)}"


def format_incident_alert_for_admin(bot_data: dict[str, Any], admin_id: int, incident: dict[str, Any]) -> str:
    base = format_admin_alert(
        bot_data,
        admin_id,
        sender_name=str(incident.get("sender_name") or "Unknown"),
        sender_id=int(incident.get("sender_id") or 0),
        file_name=str(incident.get("file_name") or "Unknown"),
        group_name=str(incident.get("group_name") or incident.get("chat_id") or "Unknown"),
        group_id=int(incident.get("chat_id") or 0),
        time_str=now_utc_str(),
        scan_result=str(incident.get("scan_reason") or incident.get("reason") or "blocked file"),
    )
    return base + handled_footer(bot_data, admin_id, incident)


def _format_user_risk_profile(bot_data: dict[str, Any], admin_id: int, incident: dict[str, Any]) -> str:
    chat_id = int(incident.get("chat_id") or 0)
    sender_id = int(incident.get("sender_id") or 0)
    sender_name = str(incident.get("sender_name") or "Unknown")
    incidents = bot_data.get("incidents", {}) if isinstance(bot_data.get("incidents", {}), dict) else {}
    user_items = [
        item for item in incidents.values()
        if isinstance(item, dict)
        and str(item.get("chat_id")) == str(chat_id)
        and str(item.get("sender_id")) == str(sender_id)
    ]
    total_incidents = len(user_items) or 1
    warns = sum(1 for item in user_items if str(item.get("action") or "") == "warn")
    bans = sum(1 for item in user_items if str(item.get("action") or "") == "ban")
    mutes = sum(1 for item in user_items if str(item.get("auto_action") or "") == "mute")
    # Include admin action logs as an additional signal when incidents were already cleaned up.
    for log in _admin_action_logs(bot_data):
        if str(log.get("chat_id")) != str(chat_id) or str(log.get("target_id")) != str(sender_id):
            continue
        action_text = str(log.get("action") or "").casefold()
        if "warn" in action_text:
            warns += 1
        elif "ban" in action_text:
            bans += 1
        elif "mute" in action_text:
            mutes += 1
    risk = _risk_badge(max(total_incidents, warns + mutes + bans))
    if bans or total_incidents >= 3:
        recommended = tr(bot_data, admin_id, "risk_recommend_ban")
    elif mutes or total_incidents >= 2:
        recommended = tr(bot_data, admin_id, "risk_recommend_mute")
    else:
        recommended = tr(bot_data, admin_id, "risk_recommend_warn")
    latest = max(user_items, key=lambda item: _safe_int(item.get("created_at_ms"), 0), default=incident)
    return tr(
        bot_data,
        admin_id,
        "risk_profile_title",
        user=user_link(sender_id, sender_name) if sender_id else h(sender_name),
        target_user_id=sender_id,
        group=h(latest.get("group_name") or get_chat_title_from_state(bot_data, chat_id) or chat_id),
        risk=h(risk),
        incidents=total_incidents,
        warns=warns,
        mutes=mutes,
        bans=bans,
        last_file=h(latest.get("file_name") or incident.get("file_name") or "Unknown"),
        last_seen=h(_format_saved_ms(latest.get("created_at_ms") or incident.get("created_at_ms"))),
        recommended=h(recommended),
    )


async def send_single_alert(context: ContextTypes.DEFAULT_TYPE, admin_id: int, msg: str, ikey: str, sem: asyncio.Semaphore) -> tuple[int, int] | None:
    async with sem:
        message_id = await safe_send_message(context, admin_id, msg, reply_markup=action_keyboard(context.bot_data, admin_id, ikey))
        if message_id is None:
            logger.info("Admin alert skipped/failed for admin_id=%s. They may need to /start the bot.", admin_id)
            return None
        return admin_id, message_id


async def notify_admins(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    group_name: str,
    sender: Any,
    file_name: str,
    ikey: str,
    scan_result: str,
) -> None:
    try:
        admin_ids = await get_chat_admin_ids_cached(context, chat_id, allow_api=True)
    except Exception:
        logger.exception("Admin lookup failed while notifying chat_id=%s", chat_id, exc_info=True)
        admin_ids = []
    if not admin_ids:
        return

    sender_id = sender.id if sender else 0
    sender_name = sender.full_name if sender else "Unknown"
    time_str = now_utc_str()

    sem = asyncio.Semaphore(ADMIN_ALERT_CONCURRENCY)
    tasks = []
    for admin_id in admin_ids:
        msg = format_admin_alert(
            context.bot_data,
            admin_id,
            sender_name=sender_name,
            sender_id=sender_id,
            file_name=file_name,
            group_name=group_name,
            group_id=chat_id,
            time_str=time_str,
            scan_result=h(scan_result),
        )
        tasks.append(send_single_alert(context, admin_id, msg, ikey, sem))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    delivered: dict[str, int] = {}
    for result in results:
        if isinstance(result, Exception):
            logger.error("Admin alert task failed: %r", result, exc_info=(type(result), result, result.__traceback__))
        elif result:
            admin_id, message_id = result
            delivered[str(admin_id)] = int(message_id)

    if delivered:
        async with BOT_DATA_LOCK:
            incident = context.bot_data.setdefault("incidents", {}).get(ikey)
            if isinstance(incident, dict):
                incident.setdefault("alert_messages", {}).update(delivered)
                incident["alerted_admins"] = list(admin_ids)
                incident["alert_delivered_count"] = len(delivered)
                await persist_context_memory(context, reason="admin_alert_messages", force=True, caller_holds_lock=True)



async def maybe_apply_auto_action(context: ContextTypes.DEFAULT_TYPE, *, chat_id: int, sender_id: int, sender_name: str, ikey: str) -> None:
    """Apply group auto-action rules after a file was deleted."""
    try:
        async with BOT_DATA_LOCK:
            settings = dict(get_group_settings(context.bot_data, chat_id))
            mode = _auto_action_label(settings.get("auto_action_mode"))
            incidents = context.bot_data.get("incidents", {}) if isinstance(context.bot_data.get("incidents", {}), dict) else {}
            user_incident_count = sum(1 for item in incidents.values() if isinstance(item, dict) and str(item.get("chat_id")) == str(int(chat_id)) and str(item.get("sender_id")) == str(int(sender_id)))
            mute_threshold = int(settings.get("auto_mute_threshold", 2)); ban_threshold = int(settings.get("auto_ban_threshold", 3)); mute_minutes = int(settings.get("auto_mute_minutes", 60))
        if mode == "off": return
        action = "warn"
        if mode == "ban" or (mode == "smart" and user_incident_count >= ban_threshold): action = "ban"
        elif mode == "smart" and user_incident_count >= mute_threshold: action = "mute"
        result = "not-run"
        if action == "warn":
            mention = user_link(sender_id, sender_name); lang = get_group_lang(context.bot_data, chat_id)
            send_result = await safe_send_message_result(context, chat_id, TEXTS[lang]["warn_in_group"].format(user=mention), operation="auto_warn")
            result = "warned" if send_result.ok else f"warn-failed:{send_result.error_type or 'send_failed'}"
        elif action == "mute":
            perms = await get_bot_member_cached(context, chat_id, force=True, allow_api=True)
            if not has_ban_permission(perms): result = "mute-failed:no-restrict-permission"
            else:
                await context.bot.restrict_chat_member(chat_id, sender_id, permissions=ChatPermissions(can_send_messages=False), until_date=datetime.now(timezone.utc) + timedelta(minutes=mute_minutes))
                result = f"muted:{mute_minutes}m"
        elif action == "ban":
            perms = await get_bot_member_cached(context, chat_id, force=True, allow_api=True)
            if not has_ban_permission(perms): result = "ban-failed:no-ban-permission"
            else:
                await context.bot.ban_chat_member(chat_id, sender_id); result = "banned"
        async with BOT_DATA_LOCK:
            incident = context.bot_data.setdefault("incidents", {}).get(ikey)
            if isinstance(incident, dict):
                incident["auto_action"] = action; incident["auto_action_result"] = result; incident["auto_action_count"] = user_incident_count; incident["auto_action_at_ms"] = now_ms()
                await persist_context_memory(context, reason="auto_action_applied", force=True, caller_holds_lock=True)
    except Exception:
        logger.exception("Auto action failed chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)


async def sync_handled_alert_messages(
    context: ContextTypes.DEFAULT_TYPE,
    incident: dict[str, Any],
    *,
    exclude_admin_id: int | None = None,
    exclude_message_id: int | None = None,
) -> None:
    messages = incident.get("alert_messages") or {}
    if not isinstance(messages, dict):
        return

    sem = asyncio.Semaphore(10)

    async def edit_one(admin_id_raw: str, message_id_raw: Any) -> None:
        try:
            admin_id = int(admin_id_raw)
            message_id = int(message_id_raw)
        except (TypeError, ValueError):
            return
        if exclude_admin_id == admin_id and exclude_message_id == message_id:
            return
        text = format_incident_alert_for_admin(context.bot_data, admin_id, incident)
        async with sem:
            await safe_edit_message(context, admin_id, message_id, text)

    await asyncio.gather(*(edit_one(admin_id, message_id) for admin_id, message_id in messages.items()), return_exceptions=True)


# ─────────────────────────────────────────────────────────────
# JOBS
# ─────────────────────────────────────────────────────────────


async def clean_old_incidents(context: ContextTypes.DEFAULT_TYPE) -> None:
    cutoff = now_ms() - INCIDENT_TTL_SECONDS * 1000
    stale_keys: list[str] = []

    async with BOT_DATA_LOCK:
        incidents = context.bot_data.setdefault("incidents", {})
        if not isinstance(incidents, dict) or not incidents:
            return
        for ikey, incident in list(incidents.items()):
            ts = incident_timestamp_ms(str(ikey))
            created_at = ts if ts is not None else int(incident.get("created_at_ms", 0) or 0) if isinstance(incident, dict) else 0
            if created_at and created_at < cutoff:
                stale_keys.append(str(ikey))
        for ikey in stale_keys:
            incidents.pop(ikey, None)
        tokens = context.bot_data.get("incident_tokens", {})
        if isinstance(tokens, dict) and stale_keys:
            stale_set = set(stale_keys)
            for token, stored_key in list(tokens.items()):
                if str(stored_key) in stale_set:
                    tokens.pop(token, None)
        if stale_keys:
            await persist_context_memory(context, reason="cleanup_incidents", force=True, caller_holds_lock=True)

    if stale_keys:
        async with INCIDENT_LOCKS_LOCK:
            for ikey in stale_keys:
                INCIDENT_LOCKS.pop(ikey, None)
        logger.info("Cleaned %d stale incident(s).", len(stale_keys))


async def cleanup_runtime_caches(context: ContextTypes.DEFAULT_TYPE) -> None:
    now = time.monotonic()
    now_wall = _cache_now_ms()
    async with ADMIN_CACHE_LOCK:
        for chat_id, item in list(ADMIN_IDS_CACHE.items()):
            if item.expires_at <= now:
                ADMIN_IDS_CACHE.pop(chat_id, None)
    async with BOT_MEMBER_CACHE_LOCK:
        for chat_id, item in list(BOT_MEMBER_CACHE.items()):
            if item.expires_at <= now:
                BOT_MEMBER_CACHE.pop(chat_id, None)

    pruned = False
    async with BOT_DATA_LOCK:
        for bucket_name in ("admin_ids_cache", "bot_member_cache"):
            bucket = context.bot_data.get(bucket_name)
            if not isinstance(bucket, dict):
                continue
            for key, value in list(bucket.items()):
                if not isinstance(value, dict):
                    bucket.pop(key, None)
                    pruned = True
                    continue
                try:
                    expires_at_ms = int(value.get("expires_at_ms", 0))
                except (TypeError, ValueError):
                    expires_at_ms = 0
                # Keep stale authorization data for offline fallback, but remove very old corrupt/stale entries.
                if expires_at_ms and expires_at_ms < now_wall - 7 * 86400 * 1000:
                    bucket.pop(key, None)
                    pruned = True
        if pruned:
            await persist_context_memory(context, reason="cleanup_runtime_caches", force=True, caller_holds_lock=True)

    active_incident_keys: set[str] = set()
    async with BOT_DATA_LOCK:
        incidents = context.bot_data.get("incidents")
        if isinstance(incidents, dict):
            active_incident_keys = {str(k) for k in incidents.keys()}
        tokens = context.bot_data.get("incident_tokens", {})
        if isinstance(tokens, dict):
            before = len(tokens)
            for token, stored_key in list(tokens.items()):
                if str(stored_key) not in active_incident_keys:
                    tokens.pop(token, None)
            if len(tokens) != before:
                pruned = True
        if pruned:
            await persist_context_memory(context, reason="cleanup_runtime_caches", force=True, caller_holds_lock=True)
    async with INCIDENT_LOCKS_LOCK:
        if len(INCIDENT_LOCKS) > RUNTIME_LOCK_PRUNE_LIMIT:
            logger.warning("INCIDENT_LOCKS size=%s exceeded limit=%s; pruning aggressively", len(INCIDENT_LOCKS), RUNTIME_LOCK_PRUNE_LIMIT)
        for ikey in list(INCIDENT_LOCKS.keys()):
            if str(ikey) not in active_incident_keys or len(INCIDENT_LOCKS) > RUNTIME_LOCK_PRUNE_LIMIT:
                INCIDENT_LOCKS.pop(ikey, None)


async def periodic_memory_save(context: ContextTypes.DEFAULT_TYPE) -> None:
    await persist_context_memory(context, reason="periodic", force=True)


async def keep_awake(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Ping the public Render URL to keep the free instance warm.

    A 404/405 from the root URL is normal for python-telegram-bot's built-in
    webhook server because it only exposes the Telegram webhook path, not a
    website homepage. For keep-awake purposes, any completed HTTP response means
    the Render service woke up and answered, so normal statuses are logged only
    at DEBUG level to avoid scary but harmless production logs.
    """
    global KEEP_AWAKE_CLIENT
    if not WEBHOOK_BASE_URL:
        return
    try:
        if KEEP_AWAKE_CLIENT is None:
            KEEP_AWAKE_CLIENT = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        response = await KEEP_AWAKE_CLIENT.get(WEBHOOK_BASE_URL)
        status = response.status_code
        if status in {200, 204, 301, 302, 307, 308, 404, 405}:
            logger.debug("Keep-awake reached service; status=%s", status)
        else:
            logger.info("Keep-awake reached service with unexpected status=%s", status)
    except Exception as exc:
        logger.exception("Keep-awake ping failed", exc_info=True)


# ─────────────────────────────────────────────────────────────
# COMMAND / CALLBACK HANDLERS
# ─────────────────────────────────────────────────────────────


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    chat = update.effective_chat
    if not user:
        return

    async with BOT_DATA_LOCK:
        was_known = _user_state_exists(context.bot_data, user.id)

        state = get_user_state(context.bot_data, int(user.id))
        state["last_seen_ms"] = now_ms()
        state.setdefault("first_seen_ms", state["last_seen_ms"])
        known_users = context.bot_data.setdefault("known_users", {})
        profile = known_users.setdefault(str(user.id), {})
        profile.setdefault("first_seen_ms", state.get("first_seen_ms", now_ms()))
        profile.update(
            {
                "id": int(user.id),
                "is_bot": bool(getattr(user, "is_bot", False)),
                "username": getattr(user, "username", None) or "",
                "full_name": getattr(user, "full_name", None) or "Unknown",
                "language_code": getattr(user, "language_code", None) or "",
                "lang": state.get("lang", "en"),
                "last_seen_ms": now_ms(),
            }
        )
        await persist_context_memory(context, reason="start", force=True, caller_holds_lock=True)

    payload = (context.args[0] if context.args else "").strip()
    if payload.startswith(("settings_", "group_")):
        linked_chat_id = _safe_chat_id_from_payload(payload)
        if linked_chat_id is not None and await is_user_admin_in_group(context, linked_chat_id, user.id, allow_api=True):
            await link_user_to_group(context, user.id, linked_chat_id)
            await render_group_settings_panel(update, context, user.id, linked_chat_id, notice=tr(context.bot_data, user.id, "group_linked"))
            return
        await safe_reply(update, tr(context.bot_data, user.id, "group_admin_only"), reply_markup=await dashboard_home_keyboard(context, user.id))
        return

    if chat and is_group_chat(chat.type):
        _, username = await get_bot_identity(context.bot)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Open private chat", url=f"https://t.me/{username}" if username else "https://t.me/")]])
        await safe_reply(update, tr(context.bot_data, user.id, "private_start"), reply_markup=kb)
        return

    if not was_known:
        await safe_reply(update, tr(context.bot_data, user.id, "select_lang"), reply_markup=language_keyboard())
    else:
        await render_home(update, context, user.id)


async def lang_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    await safe_answer_callback(query)

    user_id = query.from_user.id
    data = query.data or ""
    lang = data.removeprefix("lang_")
    if lang not in TEXTS:
        await safe_edit_query(query, TEXTS["en"]["unknown_error"])
        return

    user = query.from_user
    async with BOT_DATA_LOCK:
        state = get_user_state(context.bot_data, int(user.id))
        state["last_seen_ms"] = now_ms()
        state.setdefault("first_seen_ms", state["last_seen_ms"])
        state["lang"] = lang
        known_users = context.bot_data.setdefault("known_users", {})
        profile = known_users.setdefault(str(user.id), {})
        profile.setdefault("first_seen_ms", state.get("first_seen_ms", now_ms()))
        profile.update(
            {
                "id": int(user.id),
                "is_bot": bool(getattr(user, "is_bot", False)),
                "username": getattr(user, "username", None) or "",
                "full_name": getattr(user, "full_name", None) or "Unknown",
                "language_code": getattr(user, "language_code", None) or "",
                "lang": lang,
                "last_seen_ms": now_ms(),
            }
        )
        await persist_context_memory(context, reason="language", force=True, caller_holds_lock=True)
    await safe_edit_query(
        query,
        tr(context.bot_data, user_id, "lang_set") + "\n\n" + tr(context.bot_data, user_id, "welcome"),
        reply_markup=await dashboard_home_keyboard(context, user_id),
    )


async def check_perm_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    user_id = int(query.from_user.id)
    data = query.data or "check_perm"
    target_chat_id = _safe_chat_id_from_payload(data) if data.startswith("check_perm:") else None
    _, username = await get_bot_identity(context.bot)

    # When the button is pressed from a group, only group admins may run the
    # permission check, and the check is scoped to that exact group. This avoids
    # leaking a user's private dashboard/group list into a public chat.
    if query.message and query.message.chat and is_group_chat(query.message.chat.type):
        group_chat_id = int(query.message.chat.id)
        target_chat_id = target_chat_id or group_chat_id
        if int(target_chat_id) != group_chat_id:
            await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
            return
        if not await is_user_admin_in_group(context, group_chat_id, user_id, allow_api=True):
            await safe_answer_callback(query, text=tr(context.bot_data, user_id, "group_admin_only"), show_alert=True)
            return
        await remember_chat_meta(context.bot_data, query.message.chat)
        await link_user_to_group(
            context,
            user_id,
            group_chat_id,
            title=getattr(query.message.chat, "title", None) or str(group_chat_id),
            chat_type=str(getattr(query.message.chat, "type", "group")),
        )

    await safe_answer_callback(query)

    retry_kb_private = InlineKeyboardMarkup([
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_add_bot_admin"), url=build_add_group_url(username, request_admin=True))],
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_check_again"), callback_data="check_perm")],
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")],
    ])

    groups = [int(target_chat_id)] if target_chat_id is not None else await get_groups_snapshot(context.bot_data, user_id)
    if not groups:
        await safe_edit_query(query, tr(context.bot_data, user_id, "no_group"), reply_markup=retry_kb_private)
        return

    async def check_one(chat_id: int) -> tuple[str | None, bool]:
        try:
            title = get_chat_title_from_state(context.bot_data, chat_id)
            # Force a live permission refresh because this button is commonly
            # tapped immediately after a group admin changes the bot's rights.
            perms = await get_bot_member_cached(context, chat_id, force=True, allow_api=True)
            safe_title = h(title)
            if perms.status not in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"}:
                return f"❌ <b>{safe_title}</b>\n{tr(context.bot_data, user_id, 'not_admin')}", False
            if not perms.can_delete_messages:
                return f"⚠️ <b>{safe_title}</b>\n{tr(context.bot_data, user_id, 'no_delete_perm')}", False
            return f"✅ <b>{safe_title}</b>\n{tr(context.bot_data, user_id, 'setup_ok', group=safe_title)}", True
        except (Forbidden, BadRequest) as exc:
            logger.exception("Permission check failed chat_id=%s and group was purged from saved list", chat_id, exc_info=True)
            await purge_group_state(context, chat_id, reason="remove_stale_group")
            return None, False
        except TelegramError as exc:
            logger.exception("Permission check failed chat_id=%s", chat_id, exc_info=True)
            return None, False

    sem = asyncio.Semaphore(5)

    async def guarded(chat_id: int) -> tuple[str | None, bool]:
        async with sem:
            return await check_one(chat_id)

    results = await asyncio.gather(*(guarded(chat_id) for chat_id in groups), return_exceptions=True)
    lines: list[str] = []
    ready_count = 0
    for item in results:
        if isinstance(item, tuple):
            line, ready = item
            if line:
                lines.append(line)
            if ready:
                ready_count += 1
        elif isinstance(item, Exception):
            logger.exception("Permission check task failed", exc_info=(type(item), item, item.__traceback__))

    text = "\n\n".join(lines) if lines else tr(context.bot_data, user_id, "no_group")

    # Public group check: keep buttons public-safe and scoped to the current group.
    if query.message and query.message.chat and is_group_chat(query.message.chat.type) and target_chat_id is not None:
        if ready_count:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton(tr(context.bot_data, user_id, "btn_settings"), url=await group_private_settings_url(context, int(target_chat_id))) ]])
        else:
            kb = bot_admin_required_group_keyboard(context.bot_data, user_id, int(target_chat_id))
        await safe_edit_query(query, text, reply_markup=kb)
        return

    if target_chat_id is not None:
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_check_again"), callback_data=f"check_perm:{int(target_chat_id)}")],
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")],
        ])
        if ready_count:
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_settings"), callback_data=f"grp:{int(target_chat_id)}")],
                [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")],
            ])
        await safe_edit_query(query, text, reply_markup=kb)
        return

    await safe_edit_query(query, text, reply_markup=await dashboard_home_keyboard(context, user_id) if ready_count else retry_kb_private)


async def action_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    await safe_answer_callback(query)

    admin_id = query.from_user.id
    data = query.data or ""
    parts = data.split(":", 2)
    if len(parts) != 3:
        await safe_edit_query(query, tr(context.bot_data, admin_id, "unknown_error"))
        return
    _, action, token_or_ikey = parts
    if action not in {"ban", "warn", "ignore", "risk"}:
        await safe_edit_query(query, tr(context.bot_data, admin_id, "unknown_error"))
        return

    ikey = resolve_incident_action_key(context.bot_data, token_or_ikey)
    lock = await get_incident_lock(ikey)
    async with lock:
        async with BOT_DATA_LOCK:
            incidents = context.bot_data.setdefault("incidents", {})
            incident = incidents.get(ikey)
            if not incident:
                await safe_edit_query(query, tr(context.bot_data, admin_id, "action_expired"))
                return
            if incident.get("done") and action != "risk":
                await safe_edit_query(query, tr(context.bot_data, admin_id, "action_done"))
                return
            chat_id = int(incident["chat_id"])
            sender_id = int(incident.get("sender_id", 0))
            sender_name_raw = str(incident.get("sender_name") or "Unknown")

        if not await is_user_admin_in_group(context, chat_id, admin_id, allow_api=True):
            await safe_edit_query(query, tr(context.bot_data, admin_id, "action_not_admin"))
            return

        if action == "risk":
            async with BOT_DATA_LOCK:
                incident = context.bot_data.setdefault("incidents", {}).get(ikey)
                if not isinstance(incident, dict):
                    await safe_edit_query(query, tr(context.bot_data, admin_id, "action_expired"))
                    return
                try:
                    profile_text = _format_user_risk_profile(context.bot_data, admin_id, incident)
                except Exception:
                    logger.exception("Risk profile render failed ikey=%s admin_id=%s", ikey, admin_id, exc_info=True)
                    profile_text = tr(context.bot_data, admin_id, "unknown_error")
                keyboard = action_keyboard(context.bot_data, admin_id, ikey) if not incident.get("done") else None
            await safe_edit_query(query, profile_text, reply_markup=keyboard)
            return

        result_msg = ""
        sender_name = h(sender_name_raw)
        if action == "ban":
            try:
                bot_perms = await get_bot_member_cached(context, chat_id, force=True, allow_api=True)
                if not has_ban_permission(bot_perms):
                    raise TelegramError("Bot does not have Ban Users permission")
                for ban_attempt in (1, 2):
                    try:
                        await context.bot.ban_chat_member(chat_id, sender_id)
                        break
                    except RetryAfter as exc:
                        if ban_attempt == 1 and await _sleep_for_retry_after(exc, operation="ban_chat_member"):
                            continue
                        raise
                result_msg = tr(context.bot_data, admin_id, "action_ban_ok", name=sender_name)
            except (TimedOut, BadRequest, Forbidden, TelegramError):
                logger.exception("Ban failed chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
                result_msg = tr(context.bot_data, admin_id, "action_ban_fail")
            except Exception:
                logger.exception("Unexpected ban failure chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
                result_msg = tr(context.bot_data, admin_id, "action_ban_fail")
        elif action == "warn":
            mention = user_link(sender_id, sender_name_raw)
            warn_text = TEXTS[get_lang(context.bot_data, admin_id)]["warn_in_group"].format(user=mention)
            try:
                send_result = await safe_send_message_result(context, chat_id, warn_text, operation="incident_warn")
                if not send_result.ok:
                    raise TelegramError(send_result.error or "warning message could not be delivered")
                result_msg = tr(context.bot_data, admin_id, "action_warn_ok", name=sender_name)
            except (TimedOut, BadRequest, Forbidden, TelegramError):
                logger.exception("Warn failed chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
                result_msg = tr(context.bot_data, admin_id, "action_warn_fail")
            except Exception:
                logger.exception("Unexpected warn failure chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
                result_msg = tr(context.bot_data, admin_id, "action_warn_fail")
        else:
            result_msg = tr(context.bot_data, admin_id, "action_ignore_ok")

        action_success = action == "ignore" or result_msg in {
            tr(context.bot_data, admin_id, "action_ban_ok", name=sender_name),
            tr(context.bot_data, admin_id, "action_warn_ok", name=sender_name),
        }

        async with BOT_DATA_LOCK:
            incident = context.bot_data.setdefault("incidents", {}).get(ikey)
            if not isinstance(incident, dict):
                await safe_edit_query(query, tr(context.bot_data, admin_id, "action_expired"))
                return
            if query.message:
                incident.setdefault("alert_messages", {})[str(admin_id)] = int(query.message.message_id)
            if action_success:
                incident["done"] = True
                incident["handled_by"] = admin_id
                incident["handled_by_name"] = query.from_user.full_name
                incident["handled_at_ms"] = now_ms()
                incident["action"] = action
            _record_admin_action_log_locked(context.bot_data, chat_id=chat_id, admin_id=admin_id, admin_name=query.from_user.full_name, action=f"incident {action}", target_id=sender_id, target_name=sender_name_raw, result="success" if action_success else "failed")
            await persist_context_memory(context, reason="incident_action", force=True, caller_holds_lock=True)
            final_text = format_incident_alert_for_admin(context.bot_data, admin_id, incident)

        if not action_success and result_msg:
            final_text += f"\n\n{result_msg}"
        await safe_edit_query(query, final_text)

        if action_success:
            clicked_message_id = int(query.message.message_id) if query.message else None
            await sync_handled_alert_messages(context, incident, exclude_admin_id=admin_id, exclude_message_id=clicked_message_id)


def _replace_group_id_in_sequence(values: Any, old_id: int, new_id: int) -> list[Any]:
    if not isinstance(values, list):
        return []
    replaced: list[Any] = []
    seen: set[int] = set()
    for item in values:
        try:
            parsed = int(item)
        except (TypeError, ValueError):
            replaced.append(item)
            continue
        if parsed == int(old_id):
            parsed = int(new_id)
        if parsed not in seen:
            replaced.append(parsed)
            seen.add(parsed)
    return replaced


async def migrate_group_state(context: ContextTypes.DEFAULT_TYPE, old_chat_id: int, new_chat_id: int, *, new_title: str = "", chat_type: str = "supergroup") -> None:
    """Copy every durable group reference from an upgraded group to its new supergroup ID."""
    old_chat_id = int(old_chat_id)
    new_chat_id = int(new_chat_id)
    old_key = str(old_chat_id)
    new_key = str(new_chat_id)
    if old_chat_id == new_chat_id:
        return

    async with BOT_DATA_LOCK:
        group_state = context.bot_data.setdefault("group_state", {})
        if not isinstance(group_state, dict):
            group_state = {}
            context.bot_data["group_state"] = group_state

        old_state = group_state.get(old_key) or group_state.get(old_chat_id)
        new_state = group_state.get(new_key) or group_state.get(new_chat_id)
        merged: dict[str, Any] = {}
        if isinstance(old_state, dict):
            merged.update(copy.deepcopy(old_state))
        if isinstance(new_state, dict):
            # Keep any fields already learned for the supergroup, but preserve
            # old settings/whitelists unless the new state explicitly has them.
            for key, value in copy.deepcopy(new_state).items():
                if key == "settings" and isinstance(merged.get("settings"), dict) and isinstance(value, dict):
                    settings = merged.setdefault("settings", {})
                    for setting_key, setting_value in value.items():
                        settings[setting_key] = setting_value
                else:
                    merged[key] = value
        merged.setdefault("lang", "en")
        merged["migrated_from_chat_id"] = old_chat_id
        merged["chat_id"] = new_chat_id
        merged["last_seen_ms"] = now_ms()
        if new_title:
            merged["title"] = str(new_title)
            merged["chat_title"] = str(new_title)
        group_state[new_key] = merged
        group_state.pop(old_key, None)
        group_state.pop(old_chat_id, None)
        group_state.pop(new_chat_id, None)

        # Ensure settings schema is normalized after merging.
        get_group_settings(context.bot_data, new_chat_id)

        user_state = context.bot_data.get("user_state")
        if isinstance(user_state, dict):
            for state in user_state.values():
                if not isinstance(state, dict):
                    continue
                if isinstance(state.get("groups"), list):
                    state["groups"] = _replace_group_id_in_sequence(state.get("groups"), old_chat_id, new_chat_id)
                pending = state.get("pending_format_edit")
                if isinstance(pending, dict) and str(pending.get("chat_id")) == old_key:
                    pending["chat_id"] = new_chat_id

        for bucket_name in ("admin_ids_cache", "bot_member_cache", "chat_meta_cache", "inaccessible_chats"):
            bucket = context.bot_data.get(bucket_name)
            if not isinstance(bucket, dict):
                continue
            record = bucket.pop(old_key, None)
            bucket.pop(old_chat_id, None)
            existing_new = bucket.get(new_key) or bucket.get(new_chat_id)
            if isinstance(record, dict):
                moved = copy.deepcopy(record)
                if bucket_name == "chat_meta_cache":
                    moved["id"] = new_chat_id
                    if new_title:
                        moved["title"] = str(new_title)
                    moved["type"] = str(chat_type or "supergroup")
                    moved["updated_at_ms"] = _cache_now_ms()
                if isinstance(existing_new, dict):
                    merged_cache = moved
                    merged_cache.update(copy.deepcopy(existing_new))
                    bucket[new_key] = merged_cache
                else:
                    bucket[new_key] = moved
                bucket.pop(new_chat_id, None)

        warning_counts = context.bot_data.get("warning_counts")
        if isinstance(warning_counts, dict):
            moved = warning_counts.pop(old_key, None)
            warning_counts.pop(old_chat_id, None)
            if moved is not None and new_key not in warning_counts:
                warning_counts[new_key] = moved
            for key in list(warning_counts.keys()):
                key_text = str(key)
                if key_text.startswith(f"{old_key}:"):
                    warning_counts[f"{new_key}:{key_text.split(':', 1)[1]}"] = warning_counts.pop(key)

        moved_incident_keys: dict[str, str] = {}
        incidents = context.bot_data.get("incidents")
        if isinstance(incidents, dict):
            for ikey, incident in list(incidents.items()):
                key_text = str(ikey)
                should_move_key = key_text.startswith(f"{old_key}:")
                should_update_chat = isinstance(incident, dict) and str(incident.get("chat_id")) == old_key
                if isinstance(incident, dict) and (should_move_key or should_update_chat):
                    incident["chat_id"] = new_chat_id
                    if new_title:
                        incident["group_name"] = str(new_title)
                if should_move_key:
                    suffix = key_text.split(":", 1)[1]
                    new_ikey = f"{new_key}:{suffix}"
                    if new_ikey not in incidents:
                        incidents[new_ikey] = incidents.pop(ikey)
                    else:
                        incidents.pop(ikey, None)
                    moved_incident_keys[key_text] = new_ikey

        tokens = context.bot_data.get("incident_tokens")
        if isinstance(tokens, dict) and moved_incident_keys:
            for token, stored_key in list(tokens.items()):
                replacement = moved_incident_keys.get(str(stored_key))
                if replacement:
                    tokens[token] = replacement

        await persist_context_memory(context, reason="chat_migration", force=True, caller_holds_lock=True)

    async with ADMIN_CACHE_LOCK:
        old_admin_cache = ADMIN_IDS_CACHE.pop(old_chat_id, None)
        if old_admin_cache is not None:
            ADMIN_IDS_CACHE[new_chat_id] = old_admin_cache
    async with BOT_MEMBER_CACHE_LOCK:
        old_bot_cache = BOT_MEMBER_CACHE.pop(old_chat_id, None)
        if old_bot_cache is not None:
            BOT_MEMBER_CACHE[new_chat_id] = old_bot_cache
    async with INCIDENT_LOCKS_LOCK:
        for ikey, lock in list(INCIDENT_LOCKS.items()):
            if str(ikey).startswith(f"{old_key}:"):
                suffix = str(ikey).split(":", 1)[1]
                INCIDENT_LOCKS[f"{new_key}:{suffix}"] = lock
                INCIDENT_LOCKS.pop(ikey, None)

    logger.info("Migrated group state old_chat_id=%s new_chat_id=%s title=%r", old_chat_id, new_chat_id, new_title)


async def handle_chat_migration(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    chat = update.effective_chat
    if not message:
        return
    migrate_to = getattr(message, "migrate_to_chat_id", None)
    migrate_from = getattr(message, "migrate_from_chat_id", None)
    if migrate_to is not None:
        old_chat_id = int(chat.id if chat else getattr(message, "chat_id", 0) or 0)
        new_chat_id = int(migrate_to)
    elif migrate_from is not None:
        old_chat_id = int(migrate_from)
        new_chat_id = int(chat.id if chat else getattr(message, "chat_id", 0) or 0)
    else:
        return
    if not old_chat_id or not new_chat_id:
        logger.warning("Chat migration update missing IDs migrate_from=%r migrate_to=%r chat=%r", migrate_from, migrate_to, getattr(chat, "id", None))
        return
    try:
        await migrate_group_state(
            context,
            old_chat_id,
            new_chat_id,
            new_title=getattr(chat, "title", None) or "",
            chat_type=str(getattr(chat, "type", "supergroup")),
        )
    except Exception:
        logger.exception("Failed to migrate group state old_chat_id=%s new_chat_id=%s", old_chat_id, new_chat_id, exc_info=True)


async def my_chat_member_update(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    result = update.my_chat_member
    if not result:
        return

    chat = result.chat
    new_member = result.new_chat_member
    old_member = result.old_chat_member
    new_status = str(new_member.status)

    if not is_group_chat(chat.type):
        return

    removed_statuses = {
        str(getattr(ChatMemberStatus, "LEFT", "left")),
        str(getattr(ChatMemberStatus, "BANNED", "kicked")),
        str(getattr(ChatMemberStatus, "KICKED", "kicked")),
        str(getattr(ChatMemberStatus, "DEACTIVATED", "deactivated")),
        "left",
        "banned",
        "kicked",
        "deactivated",
    }
    if new_status.casefold() in {status.casefold() for status in removed_statuses}:
        logger.info("Bot lost access to chat_id=%s title=%r; hard-wiping state", chat.id, getattr(chat, "title", None))
        await mark_chat_inaccessible(context, chat.id, reason="bot_lost_group_access", purge=True)
        return

    await clear_chat_inaccessible(context, chat.id, persist=False)

    adder = result.from_user
    if not adder or adder.is_bot:
        return

    try:
        await remember_user_profile(context.bot_data, adder)
        await remember_chat_meta(context.bot_data, chat)
        await link_user_to_group(context, adder.id, chat.id, title=chat.title or str(chat.id), chat_type=str(chat.type))
    except Exception:
        logger.exception("Failed to store chat member lifecycle metadata chat_id=%s", chat.id, exc_info=True)

    try:
        await get_chat_admin_ids_cached(context, chat.id, force=True, allow_api=True)
    except (TimedOut, BadRequest, Forbidden, TelegramError):
        logger.exception("Admin cache refresh failed in my_chat_member_update chat_id=%s", chat.id, exc_info=True)
    except Exception:
        logger.exception("Unexpected admin cache refresh failure in my_chat_member_update chat_id=%s", chat.id, exc_info=True)

    safe_title = h(chat.title or "Group")
    can_delete = bool(getattr(new_member, "can_delete_messages", False))
    can_restrict = bool(getattr(new_member, "can_restrict_members", False))
    is_admin = new_status in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"}
    perms = BotPerms(new_status, can_delete, can_restrict)

    async with BOT_MEMBER_CACHE_LOCK:
        BOT_MEMBER_CACHE[int(chat.id)] = CacheItem(perms, time.monotonic() + BOT_MEMBER_CACHE_TTL_SECONDS)
    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(context.bot_data, "bot_member_cache")
        bucket[str(int(chat.id))] = {
            "status": new_status,
            "can_delete_messages": can_delete,
            "can_restrict_members": can_restrict,
            "expires_at_ms": _cache_now_ms() + BOT_MEMBER_CACHE_TTL_SECONDS * 1000,
        }
        await persist_context_memory(context, reason="chat_member_update", force=True, caller_holds_lock=True)

    if is_admin and can_delete:
        msg = tr(context.bot_data, adder.id, "setup_ok", group=safe_title)
    elif is_admin:
        msg = tr(context.bot_data, adder.id, "no_delete_perm")
    else:
        msg = tr(context.bot_data, adder.id, "not_admin")

    try:
        rows: list[list[InlineKeyboardButton]] = []
        if is_admin and can_delete:
            rows.append([InlineKeyboardButton(tr(context.bot_data, adder.id, "btn_settings"), callback_data=f"grp:{chat.id}")])
        else:
            rows.append([InlineKeyboardButton(tr(context.bot_data, adder.id, "btn_add_bot_admin"), url=build_add_group_url_from_state(request_admin=True))])
        rows.append([InlineKeyboardButton(tr(context.bot_data, adder.id, "check_btn"), callback_data="check_perm")])
        rows.append([InlineKeyboardButton(tr(context.bot_data, adder.id, "btn_home"), callback_data="nav:home")])
        kb = InlineKeyboardMarkup(rows)
        await safe_send_message(context, adder.id, msg, reply_markup=kb)
    except Exception:
        logger.exception("Unexpected setup DM failure user_id=%s", adder.id, exc_info=True)

    logger.info("my_chat_member: chat_id=%s old=%s new=%s can_delete=%s", chat.id, getattr(old_member, "status", None), new_status, can_delete)


async def private_document_flow_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    chat = update.effective_chat
    if not user or not message or not message.document or not chat or chat.type != ChatType.PRIVATE:
        return

    async with BOT_DATA_LOCK:
        user_state = context.bot_data.get("user_state", {})
        state = (user_state.get(user.id) or user_state.get(str(user.id)) or {}) if isinstance(user_state, dict) else {}
        pending = dict(state.get("pending_format_edit")) if isinstance(state, dict) and isinstance(state.get("pending_format_edit"), dict) else None

    if not isinstance(pending, dict) or str(pending.get("mode") or "") != "hash_add":
        return

    try:
        chat_id = int(pending.get("chat_id"))
    except (TypeError, ValueError):
        await clear_pending_format_edit(context, user.id)
        await safe_reply(update, tr(context.bot_data, user.id, "unknown_error"), reply_markup=await dashboard_home_keyboard(context, user.id))
        return

    if not await is_user_admin_in_group(context, chat_id, user.id, allow_api=True):
        await clear_pending_format_edit(context, user.id)
        await safe_reply(update, tr(context.bot_data, user.id, "group_admin_only"), reply_markup=await dashboard_home_keyboard(context, user.id))
        return
    if not await ensure_bot_settings_unlocked(context, chat_id, force=True):
        await clear_pending_format_edit(context, user.id)
        await render_bot_admin_required_panel(update, context, user.id, chat_id)
        return

    document = message.document
    file_name = normalize_filename(getattr(document, "file_name", None))
    file_size = int(getattr(document, "file_size", 0) or 0)
    if file_size <= 0 or file_size > trusted_hash_max_download_bytes(context.bot_data) or file_size > TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES:
        if file_size > TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES:
            logger.warning(
                "Trusted-hash upload skipped; Telegram Bot API file-size limit exceeded user_id=%s chat_id=%s file_name=%r size=%s limit=%s",
                user.id,
                chat_id,
                file_name,
                file_size,
                TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES,
            )
        await safe_reply(update, tr(context.bot_data, user.id, "trusted_hash_file_too_large"))
        return

    data = await _download_document_bytes_for_scanner(
        context,
        document,
        file_name=file_name,
        file_size=file_size,
        max_bytes=trusted_hash_max_download_bytes(context.bot_data),
    )
    if data is None:
        await safe_reply(update, tr(context.bot_data, user.id, "trusted_hash_invalid"))
        return
    digest = await calculate_file_hash_async(data)

    async with BOT_DATA_LOCK:
        settings = get_group_settings(context.bot_data, chat_id)
        if digest not in settings.get("trusted_file_hashes", []) and len(settings.get("trusted_file_hashes", [])) >= max_trusted_file_hashes(context.bot_data):
            await safe_reply(update, tr(context.bot_data, user.id, "trusted_hash_limit"))
            return
        add_trusted_file_hash(context.bot_data, chat_id, digest, added_by=user.id, file_name=file_name)
        state = get_user_state(context.bot_data, user.id)
        state.pop("pending_format_edit", None)
        await persist_context_memory(context, reason="trusted_hash_add_file", force=True, caller_holds_lock=True)

    await render_trusted_hash_panel(update, context, user.id, chat_id, notice=tr(context.bot_data, user.id, "trusted_hash_saved"))


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    chat = update.effective_chat
    sender = message.from_user if message else None
    sender_id = int(sender.id) if sender else 0
    user_id = update.effective_user.id if update.effective_user else None
    if not message or not chat or not message.document or not is_group_chat(chat.type):
        return

    document = message.document
    file_name_meta = normalize_filename(getattr(document, "file_name", None))
    file_size = int(getattr(document, "file_size", 0) or 0)

    async with BOT_DATA_LOCK:
        settings_snapshot = dict(get_group_settings(context.bot_data, chat.id))

    if not settings_snapshot.get("protection_enabled", True):
        return

    # v3 security fix: do not let admins/owners bypass blocked executable files.
    # Safe default is to scan everyone.  If ADMIN_BYPASS_ENABLED=true is set
    # intentionally, only allow bypass for admins/owners when the cheap
    # filename/MIME pre-scan is clean. This prevents logs like:
    # "Document scan bypassed ... file_name='1.exe' strict_admins=False".
    strict_admins = bool(settings_snapshot.get("strict_enforcement_on_admins", STRICT_ENFORCEMENT_ON_ADMINS_DEFAULT))
    pre_scan = scan_filename_only(file_name_meta, getattr(document, "mime_type", "") or "")
    allow_admin_bypass = bool(ADMIN_BYPASS_ENABLED and sender_id and not strict_admins and not pre_scan.blocked)
    if allow_admin_bypass:
        try:
            admin_ids = await get_chat_admin_ids_cached(context, chat.id, allow_api=True)
            if sender_id in admin_ids or sender_id in BOT_OWNER_IDS:
                logger.info(
                    "Document scan bypassed for verified admin/owner clean file chat_id=%s user_id=%s file_name=%r admin_bypass_enabled=%s strict_admins=%s",
                    chat.id,
                    sender_id,
                    file_name_meta,
                    ADMIN_BYPASS_ENABLED,
                    strict_admins,
                )
                return
        except Exception:
            logger.exception("Admin bypass check failed; continuing with scanner chat_id=%s user_id=%s", chat.id, sender_id, exc_info=True)
    elif sender_id and pre_scan.blocked and (not strict_admins or sender_id in BOT_OWNER_IDS):
        logger.info(
            "Admin/owner upload will be scanned because filename/MIME is blocked chat_id=%s user_id=%s file_name=%r reason=%s",
            chat.id,
            sender_id,
            file_name_meta,
            pre_scan.reason_code,
        )

    if file_size > TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES:
        logger.warning(
            "Incoming document exceeds Telegram Bot API download limit; filename/MIME policy only chat_id=%s user_id=%s file_name=%r size=%s limit=%s",
            chat.id,
            sender_id,
            file_name_meta,
            file_size,
            TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES,
        )

    try:
        scan = await scan_document(context, document, chat_id=chat.id)
        async with BOT_DATA_LOCK:
            scan = apply_group_scan_policy(context.bot_data, chat.id, scan)
    except Exception:
        logger.exception("Document scanner failed chat_id=%s message_id=%s", getattr(chat, "id", None), getattr(message, "message_id", None), exc_info=True)
        await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "unknown_error"))
        return

    if not scan.blocked:
        return

    if file_size > TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES:
        logger.info(
            "Large document blocked by filename/MIME policy without byte download chat_id=%s user_id=%s file_name=%r reason=%s",
            chat.id,
            sender_id,
            file_name_meta,
            scan.reason_code,
        )

    sender_name_raw = sender.full_name if sender else "Unknown"
    file_name = scan.file_name

    deleted = False
    for attempt in (1, 2):
        try:
            await message.delete()
            deleted = True
            break
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="delete_message"):
                continue
            break
        except (TimedOut, BadRequest, Forbidden, TelegramError):
            logger.exception("Could not delete blocked file chat_id=%s message_id=%s", chat.id, message.message_id, exc_info=True)
            await invalidate_chat_caches(chat.id, context.bot_data)
            await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "delete_failed"))
            return
        except Exception:
            logger.exception("Unexpected delete failure chat_id=%s message_id=%s", chat.id, message.message_id, exc_info=True)
            return
    if not deleted:
        await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "delete_failed"))
        return

    try:
        await remember_user_profile(context.bot_data, sender)
        await remember_group(context.bot_data, chat.id, lang=get_group_lang(context.bot_data, chat.id), title=chat.title or str(chat.id), chat_type=str(chat.type))
        user_mention = user_link(sender_id, sender_name_raw)
        scan_reason = describe_scan_reason(scan.reason_code, (scan.reason_display, *scan.details))
        async with BOT_DATA_LOCK:
            settings = dict(get_group_settings(context.bot_data, chat.id))

        group_notice = tr_group(context.bot_data, chat.id, "exe_removed_group", user=user_mention, reason=h(scan_reason))
        if settings.get("silent_mode", False):
            group_notice += tr_group(context.bot_data, chat.id, "silent_notice_auto_delete")
            notice_id = await safe_send_message(context, chat.id, group_notice)
            schedule_auto_delete_message(context, chat_id=chat.id, message_id=notice_id)
        else:
            await safe_send_message(context, chat.id, group_notice)

        ikey = incident_key(chat.id, sender_id, message.message_id)
        async with BOT_DATA_LOCK:
            incident_record = {
                "done": False,
                "created_at_ms": now_ms(),
                "chat_id": chat.id,
                "group_name": chat.title or str(chat.id),
                "sender_id": sender_id,
                "sender_name": sender_name_raw,
                "file_name": file_name,
                "reason": scan.reason_code,
                "scan_reason": scan_reason,
                "scan_details": list(scan.details),
                "mime_type": scan.mime_type,
                "matched_extension": scan.matched_extension,
                "file_sha256": scan.file_sha256,
                "message_id": message.message_id,
                "alert_messages": {},
            }
            context.bot_data.setdefault("incidents", {})[ikey] = incident_record
            ensure_incident_action_token(context.bot_data, ikey)
            await persist_context_memory(context, reason="incident_created", force=True, caller_holds_lock=True)
        await maybe_apply_auto_action(context, chat_id=chat.id, sender_id=sender_id, sender_name=sender_name_raw, ikey=ikey)
        await notify_admins(context, chat.id, chat.title or str(chat.id), sender, file_name, ikey, scan_reason)
    except Exception:
        logger.exception("Post-delete incident workflow failed chat_id=%s user_id=%s", chat.id, user_id, exc_info=True)
        await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "unknown_error"))



def scanner_selftest_results() -> list[tuple[str, bool, str]]:
    """Run lightweight scanner checks that do not call Telegram APIs."""
    results: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        results.append((name, bool(ok), detail))

    r = scan_filename_only("invoice.pdf.exe")
    add("block direct .exe", r.blocked and r.reason_code == "blocked_extension", r.reason_code)

    r = scan_filename_only("invoice.exe.zip")
    add("block hidden .exe before archive", r.blocked and r.matched_extension == ".exe", r.reason_code)

    r = scan_filename_only("safe-report.pdf")
    add("allow normal PDF name", not r.blocked, r.reason_code)

    r = scan_file_bytes("renamed.bin", "application/octet-stream", b"MZ" + b"0" * 32)
    add("block PE magic header", bool(r and r.blocked and r.reason_code == "pe_magic_header"), r.reason_code if r else "no-result")

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("safe/readme.txt", b"ok")
        zf.writestr("payload.exe", b"fake")
    r = scan_file_bytes("bundle.zip", "application/zip", archive.getvalue())
    add("block dangerous ZIP member", bool(r and r.blocked and r.reason_code == "archive_contains_dangerous_file"), r.reason_code if r else "no-result")

    return results


async def selftest_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not _dev_is_owner(user.id):
        await safe_reply(update, tr(context.bot_data, user.id if user else None, "access_denied"))
        return

    results = scanner_selftest_results()
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    lines = ["🧪 <b>Scanner Self-Test</b>", f"Result: <code>{passed}/{total}</code> passed", ""]
    for name, ok, detail in results:
        lines.append(f"{'✅' if ok else '❌'} {h(name)} — <code>{h(detail)}</code>")
    lines.extend([
        "",
        f"Trusted hash whitelist: <code>{str(trusted_hash_whitelist_enabled(context.bot_data)).lower()}</code>",
        f"Hash max file size: <code>{trusted_hash_max_download_bytes(context.bot_data)}</code> bytes (<code>{format_bytes_mb(trusted_hash_max_download_bytes(context.bot_data))}</code>)",
        f"Max trusted hashes/group: <code>{max_trusted_file_hashes(context.bot_data)}</code>",
    ])
    await safe_reply(update, "\n".join(lines))


def scanner_config_text(bot_data: dict[str, Any], user_id: int | None) -> str:
    return tr(
        bot_data,
        user_id,
        "scanner_status",
        enabled=str(SUSPICIOUS_SCANNER_ENABLED).lower(),
        magic=str(SUSPICIOUS_MAGIC_SCAN_ENABLED).lower(),
        archive=str(SUSPICIOUS_ARCHIVE_SCAN_ENABLED).lower(),
        max_bytes=SCANNER_MAX_DOWNLOAD_BYTES,
        blocked=h(", ".join(BLOCKED_EXTENSIONS)),
        dangerous=h(", ".join(DANGEROUS_EXTENSIONS)),
        archives=h(", ".join(ARCHIVE_EXTENSIONS)),
        hash_whitelist=str(trusted_hash_whitelist_enabled(bot_data)).lower(),
    )


def scanner_group_config_text(bot_data: dict[str, Any], user_id: int | None, chat_id: int) -> str:
    settings = get_group_settings(bot_data, chat_id)
    return scanner_config_text(bot_data, user_id) + tr(
        bot_data,
        user_id,
        "scanner_group_status",
        protection=_on_off(bot_data, user_id, bool(settings.get("protection_enabled"))),
        strictness=_strictness_label(bot_data, user_id, str(settings.get("strictness", "standard"))),
        silent=_on_off(bot_data, user_id, bool(settings.get("silent_mode")), key_on="silent_on", key_off="silent_off"),
        allowed=h(format_extension_list(settings.get("allowed_extensions", []))),
        custom_blocked=h(format_extension_list(settings.get("custom_blocked_extensions", []))),
    )


async def scanner_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    chat = update.effective_chat
    user_id = user.id if user else None
    if not await require_admin_or_owner(update, context, allow_api=True):
        return

    try:
        if chat and is_group_chat(chat.type):
            if not user or not await is_admin_or_owner(context, user.id, chat_id=chat.id, allow_api=True):
                await safe_reply(update, tr(context.bot_data, user_id, "group_admin_only"))
                return
            await remember_chat_meta(context.bot_data, chat)
            await link_user_to_group(context, user.id, chat.id, title=chat.title or str(chat.id), chat_type=str(chat.type))
            if not await ensure_bot_settings_unlocked(context, chat.id, force=True):
                await safe_reply(
                    update,
                    tr(context.bot_data, user.id, "bot_admin_required_group"),
                    reply_markup=bot_admin_required_group_keyboard(context.bot_data, user.id, chat.id),
                )
                return
            url = await group_private_settings_url(context, chat.id)
            kb = InlineKeyboardMarkup([[InlineKeyboardButton(tr(context.bot_data, user.id, "btn_settings"), url=url)]])
            await safe_reply(update, tr(context.bot_data, user.id, "scanner_group_private_only"), reply_markup=kb)
            return
        await safe_reply(update, scanner_config_text(context.bot_data, user_id))
    except Exception:
        logger.exception("/scanner failed user_id=%s", user_id, exc_info=True)
        await safe_reply(update, tr(context.bot_data, user_id, "unknown_error"))



async def scanname_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
    if not await require_admin_or_owner(update, context):
        return
    file_name = " ".join(context.args or []).strip()
    if not file_name:
        await safe_reply(update, tr(context.bot_data, user_id, "scanname_usage"))
        return
    result = scan_filename_only(file_name, "")
    if result.blocked:
        await safe_reply(
            update,
            tr(context.bot_data, user_id, "scanname_blocked", file=h(result.file_name), reason=h(describe_scan_reason(result.reason_code, (result.reason_display, *result.details)))),
        )
    else:
        await safe_reply(update, tr(context.bot_data, user_id, "scanname_clean", file=h(result.file_name)))


def memory_status_text(bot_data: dict[str, Any], user_id: int | None) -> str:
    known_users = bot_data.get("known_users", {}) if isinstance(bot_data.get("known_users", {}), dict) else {}
    group_state = bot_data.get("group_state", {}) if isinstance(bot_data.get("group_state", {}), dict) else {}
    incidents = bot_data.get("incidents", {}) if isinstance(bot_data.get("incidents", {}), dict) else {}
    return tr(
        bot_data,
        user_id,
        "memory_status",
        backend=h(storage_backend_label()),
        supabase="connected" if SUPABASE_AVAILABLE else ("configured but offline" if SUPABASE_ENABLED else "disabled"),
        redis="connected" if REDIS_AVAILABLE else ("configured but offline" if REDIS_ENABLED else "disabled"),
        users=len(known_users),
        groups=len(group_state),
        incidents=len(incidents),
        supabase_last_save=h(SUPABASE_LAST_SAVE_UTC),
        redis_last_save=h(REDIS_LAST_SAVE_UTC),
    )


async def memory_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
    if not await require_admin_or_owner(update, context):
        return
    await safe_reply(update, memory_status_text(context.bot_data, user_id))


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
    await safe_reply(update, tr(context.bot_data, user_id, "help"))


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    user_id = update.effective_user.id if update.effective_user else None
    if not chat or not is_group_chat(chat.type):
        await safe_reply(update, tr(context.bot_data, user_id, "group_only"))
        return

    try:
        perms = await get_bot_member_cached(context, chat.id, force=True, allow_api=True)
        msg = tr(context.bot_data, user_id, "status_ok" if has_delete_permission(perms) else "status_no")
    except (TimedOut, BadRequest, Forbidden, TelegramError) as exc:
        logger.exception("/status permission check failed chat_id=%s", chat.id, exc_info=True)
        msg = tr(context.bot_data, user_id, "status_error", error=h(str(exc)))
    except Exception as exc:
        logger.exception("Unexpected /status failure chat_id=%s", chat.id, exc_info=True)
        msg = tr(context.bot_data, user_id, "status_error", error=h(str(exc)))
    await safe_reply(update, msg)


async def admins_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    user_id = update.effective_user.id if update.effective_user else None
    if not chat or not is_group_chat(chat.type):
        await safe_reply(update, tr(context.bot_data, user_id, "group_only"))
        return
    if not update.effective_user or not await is_user_admin_in_group(context, chat.id, update.effective_user.id, allow_api=True):
        await safe_reply(update, tr(context.bot_data, user_id, "group_admin_only"))
        return

    try:
        admin_ids = await get_chat_admin_ids_cached(context, chat.id, allow_api=True)
        async with BOT_DATA_LOCK:
            ready_user_ids = {int(uid) for uid in context.bot_data.get("user_state", {}).keys() if str(uid).lstrip("-").isdigit()}
            known_users = context.bot_data.get("known_users", {}) if isinstance(context.bot_data.get("known_users", {}), dict) else {}
            lang = get_lang(context.bot_data, user_id)
            lines = []
            for i, admin_id in enumerate(admin_ids, 1):
                profile = known_users.get(str(admin_id), {}) if isinstance(known_users.get(str(admin_id), {}), dict) else {}
                name = str(profile.get("full_name") or admin_id)
                status = TEXTS[lang]["admins_enabled"] if admin_id in ready_user_ids else TEXTS[lang]["admins_need_start"]
                lines.append(f"{i}. {user_link(admin_id, name)} — {status}")
            msg = tr(context.bot_data, user_id, "admins_header") + ("\n".join(lines) if lines else "No cached admins yet.") + tr(context.bot_data, user_id, "admins_note")
        await safe_reply(update, msg)
    except Exception:
        logger.exception("/admins failed chat_id=%s user_id=%s", chat.id, user_id, exc_info=True)
        await safe_reply(update, tr(context.bot_data, user_id, "unknown_error"))



# ─────────────────────────────────────────────────────────────
# TELEGRAM MINI APP API HELPERS
# ─────────────────────────────────────────────────────────────

@dataclass(slots=True)
class MiniAppPrincipal:
    """Authenticated Telegram Mini App user resolved from WebApp initData."""

    user_id: int
    user: dict[str, Any]
    auth_date: int
    query_id: str = ""
    init_data: str = ""


def _api_raise(status_code: int, detail: str) -> None:
    if HTTPException is None:
        raise RuntimeError(detail)
    raise HTTPException(status_code=status_code, detail=detail)


def _valid_webhook_secret_token(value: str) -> bool:
    """Telegram secret_token allows 1..256 chars from A-Z, a-z, 0-9, _, -."""
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,256}", str(value or "")))


def _telegram_secret_token_for_webhook() -> str | None:
    if not MINI_APP_WEBHOOK_SECRET_HEADER_ENABLED:
        return None
    return WEBHOOK_SECRET_TOKEN if _valid_webhook_secret_token(WEBHOOK_SECRET_TOKEN) else None


MINI_APP_INIT_DATA_KEYS = ("initData", "init_data", "tgWebAppData", "telegram_init_data", "webAppData")
MINI_APP_INIT_DATA_HEADERS = (
    "X-Telegram-Init-Data",
    "X-Telegram-Web-App-Data",
    "X-TMA-Init-Data",
    "Telegram-Init-Data",
)


def _extract_init_data_from_mapping(mapping: Any) -> str:
    """Read initData from a dict/query/form-like object without trusting initDataUnsafe."""
    if not mapping:
        return ""
    getter = getattr(mapping, "get", None)
    if not callable(getter):
        return ""
    for key in MINI_APP_INIT_DATA_KEYS:
        try:
            value = str(getter(key) or "").strip()
        except Exception:
            value = ""
        if value:
            return value
    return ""


def _extract_init_data_from_headers_and_query(request: Any) -> str:
    """Read Telegram WebApp initData from headers, Authorization, or query string."""
    headers = getattr(request, "headers", {}) or {}
    for header_name in MINI_APP_INIT_DATA_HEADERS:
        value = str(headers.get(header_name) or "").strip()
        if value:
            return value

    auth = str(headers.get("Authorization") or "").strip()
    for prefix in ("tma ", "telegram ", "bearer "):
        if auth.casefold().startswith(prefix):
            return auth[len(prefix):].strip()

    return _extract_init_data_from_mapping(getattr(request, "query_params", {}) or {})


async def _api_request_body_bytes(request: Any) -> bytes:
    """Read request body once and reuse it across auth + payload parsing."""
    state = getattr(request, "state", None)
    if state is not None:
        cached = getattr(state, "_mini_app_cached_body", None)
        if isinstance(cached, (bytes, bytearray)):
            return bytes(cached)
    try:
        body = await request.body()
    except Exception:
        _api_raise(400, "could not read request body")
    if len(body) > MINI_APP_REQUEST_BODY_LIMIT_BYTES:
        _api_raise(413, "request body too large")
    if state is not None:
        try:
            setattr(state, "_mini_app_cached_body", bytes(body))
        except Exception:
            pass
    return bytes(body)


async def _extract_init_data_from_request(request: Any) -> str:
    """Read Telegram WebApp initData from all frontend-friendly request locations.

    Preferred frontend usage is the `X-Telegram-Init-Data` header or
    `Authorization: tma <initData>`.  For easier React/Vite integration, JSON
    bodies like `{"initData": window.Telegram.WebApp.initData}` and raw
    x-www-form-urlencoded bodies are also accepted.
    """
    direct = _extract_init_data_from_headers_and_query(request)
    if direct:
        return direct

    method = str(getattr(request, "method", "") or "").upper()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return ""

    body = await _api_request_body_bytes(request)
    if not body:
        return ""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    stripped = text.strip()
    if not stripped:
        return ""

    headers = getattr(request, "headers", {}) or {}
    content_type = str(headers.get("content-type") or headers.get("Content-Type") or "").casefold()
    if "application/json" in content_type or stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            value = _extract_init_data_from_mapping(payload)
            if value:
                return value

    if "application/x-www-form-urlencoded" in content_type or ("auth_date=" in stripped and "hash=" in stripped):
        parsed = dict(parse_qsl(stripped, keep_blank_values=True, strict_parsing=False))
        value = _extract_init_data_from_mapping(parsed)
        if value:
            return value
        if "auth_date=" in stripped and "hash=" in stripped:
            return stripped

    return ""


def validate_telegram_webapp_init_data(init_data: str) -> MiniAppPrincipal:
    """Validate Telegram Mini App initData using the bot token HMAC scheme."""
    raw = str(init_data or "").strip()
    if not raw:
        _api_raise(401, "missing Telegram Mini App initData")

    parsed_pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=False)
    parsed: dict[str, str] = {str(key): str(value) for key, value in parsed_pairs}
    received_hash = parsed.pop("hash", "")
    if not received_hash:
        _api_raise(401, "missing Telegram initData hash")

    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(parsed.items()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode("utf-8"), hashlib.sha256).digest()
    calculated_hash = hmac.new(secret_key, data_check_string.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated_hash, received_hash):
        _api_raise(401, "invalid Telegram initData signature")

    try:
        auth_date = int(parsed.get("auth_date", "0") or 0)
    except (TypeError, ValueError):
        auth_date = 0
    if auth_date <= 0:
        _api_raise(401, "invalid Telegram initData auth_date")
    if MINI_APP_AUTH_MAX_AGE_SECONDS > 0 and int(time.time()) - auth_date > MINI_APP_AUTH_MAX_AGE_SECONDS:
        _api_raise(401, "expired Telegram initData")

    try:
        user_payload = json.loads(parsed.get("user", "{}") or "{}")
    except json.JSONDecodeError:
        user_payload = {}
    if not isinstance(user_payload, dict):
        user_payload = {}
    try:
        user_id = int(user_payload.get("id") or 0)
    except (TypeError, ValueError):
        user_id = 0
    if user_id <= 0:
        _api_raise(401, "Telegram initData does not contain a valid user")

    return MiniAppPrincipal(
        user_id=user_id,
        user=user_payload,
        auth_date=auth_date,
        query_id=str(parsed.get("query_id") or ""),
        init_data=raw,
    )


async def _api_principal_from_request(request: Any) -> MiniAppPrincipal:
    return validate_telegram_webapp_init_data(await _extract_init_data_from_request(request))


def _api_full_name(user: dict[str, Any]) -> str:
    first = str(user.get("first_name") or "").strip()
    last = str(user.get("last_name") or "").strip()
    full = " ".join(part for part in (first, last) if part).strip()
    return full or str(user.get("username") or user.get("id") or "Unknown")


def _api_public_profile_from_principal(principal: MiniAppPrincipal) -> dict[str, Any]:
    user = principal.user
    return {
        "id": principal.user_id,
        "is_bot": bool(user.get("is_bot", False)),
        "first_name": str(user.get("first_name") or ""),
        "last_name": str(user.get("last_name") or ""),
        "full_name": _api_full_name(user),
        "username": str(user.get("username") or ""),
        "language_code": str(user.get("language_code") or ""),
        "is_premium": bool(user.get("is_premium", False)),
        "allows_write_to_pm": bool(user.get("allows_write_to_pm", False)),
        "photo_url": str(user.get("photo_url") or ""),
    }


async def _api_remember_principal(application: Application, principal: MiniAppPrincipal, *, persist: bool) -> None:
    """Store/update the Mini App user profile in the same durable user cache."""
    profile = _api_public_profile_from_principal(principal)
    async with BOT_DATA_LOCK:
        state = get_user_state(application.bot_data, principal.user_id)
        state["last_seen_ms"] = now_ms()
        state.setdefault("first_seen_ms", state["last_seen_ms"])
        if not state.get("lang"):
            state["lang"] = "km" if str(profile.get("language_code", "")).startswith("km") else "en"

        known_users = application.bot_data.setdefault("known_users", {})
        if not isinstance(known_users, dict):
            known_users = {}
            application.bot_data["known_users"] = known_users
        saved = known_users.setdefault(str(principal.user_id), {})
        saved.setdefault("first_seen_ms", state.get("first_seen_ms", now_ms()))
        saved.update(
            {
                "id": principal.user_id,
                "is_bot": bool(profile["is_bot"]),
                "username": str(profile["username"]),
                "full_name": str(profile["full_name"]),
                "language_code": str(profile["language_code"]),
                "lang": state.get("lang", "en"),
                "is_premium": bool(profile["is_premium"]),
                "allows_write_to_pm": bool(profile["allows_write_to_pm"]),
                "photo_url": str(profile["photo_url"]),
                "last_seen_ms": now_ms(),
                "source": "mini_app",
            }
        )
        if persist:
            await persist_context_memory(application, reason="mini_app_user_session", force=False, caller_holds_lock=True)


def _api_json_safe(value: Any, *, depth: int = 0) -> Any:
    """Convert bot state values to JSON-safe structures without leaking objects."""
    if depth > 8:
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _api_json_safe(v, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_api_json_safe(item, depth=depth + 1) for item in value]
    return str(value)


def _api_ms_to_iso(value: Any) -> str:
    try:
        ms = int(value or 0)
    except (TypeError, ValueError):
        ms = 0
    if ms <= 0:
        return ""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


def _api_bool(value: Any, default: bool) -> bool:
    return _coerce_bool(value, default)


def _api_int(value: Any, default: int, *, min_value: int = 0, max_value: int = 10_000) -> int:
    return _coerce_int_range(value, default, min_value=min_value, max_value=max_value)


async def _api_request_json(request: Any) -> dict[str, Any]:
    body = await _api_request_body_bytes(request)
    if not body:
        return {}
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _api_raise(400, "invalid JSON body")
    if not isinstance(payload, dict):
        _api_raise(400, "JSON body must be an object")
    return payload


def _api_scan_result(result: FileScanResult) -> dict[str, Any]:
    return {
        "blocked": bool(result.blocked),
        "reason_code": result.reason_code,
        "reason_display": result.reason_display,
        "details": list(result.details),
        "file_name": result.file_name,
        "mime_type": result.mime_type,
        "matched_extension": result.matched_extension,
        "file_sha256": result.file_sha256,
    }


def _api_extension_values(value: Any, *, allowed: bool = False) -> list[str]:
    if isinstance(value, str):
        raw_values = re.split(r"[\s,;|]+", value.strip())
    elif isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, dict)):
        raw_values = list(value)
    else:
        raw_values = []
    if allowed:
        return _dedupe_allowed_extensions(raw_values, limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
    return _dedupe_valid_extensions(raw_values, limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)


def _api_public_settings_locked(bot_data: dict[str, Any], chat_id: int) -> dict[str, Any]:
    settings = get_group_settings(bot_data, chat_id)
    return {
        "protection_enabled": bool(settings.get("protection_enabled", True)),
        "strictness": str(settings.get("strictness", "standard")),
        "silent_mode": bool(settings.get("silent_mode", False)),
        "strict_enforcement_on_admins": bool(settings.get("strict_enforcement_on_admins", STRICT_ENFORCEMENT_ON_ADMINS_DEFAULT)),
        "allowed_extensions": list(settings.get("allowed_extensions", [])),
        "custom_blocked_extensions": list(settings.get("custom_blocked_extensions", [])),
        "trusted_file_hashes": list(settings.get("trusted_file_hashes", [])),
        "auto_action_mode": _auto_action_label(settings.get("auto_action_mode")),
        "auto_warn_threshold": _api_int(settings.get("auto_warn_threshold"), 1, min_value=1, max_value=100),
        "auto_mute_threshold": _api_int(settings.get("auto_mute_threshold"), 2, min_value=1, max_value=100),
        "auto_ban_threshold": _api_int(settings.get("auto_ban_threshold"), 3, min_value=1, max_value=100),
        "auto_mute_minutes": _api_int(settings.get("auto_mute_minutes"), 60, min_value=1, max_value=10080),
    }


def _api_admin_ready_counts_locked(bot_data: dict[str, Any], chat_id: int) -> tuple[int, int]:
    cache = bot_data.get("admin_ids_cache", {}) if isinstance(bot_data.get("admin_ids_cache", {}), dict) else {}
    record = cache.get(str(int(chat_id))) or cache.get(int(chat_id)) or {}
    admin_ids: list[int] = []
    if isinstance(record, dict):
        value = record.get("ids") or record.get("admin_ids") or record.get("value") or []
        if isinstance(value, list):
            for item in value:
                try:
                    admin_ids.append(int(item))
                except (TypeError, ValueError):
                    continue
    ready_user_ids: set[int] = set()
    user_state = bot_data.get("user_state", {})
    if isinstance(user_state, dict):
        for uid in user_state.keys():
            try:
                ready_user_ids.add(int(uid))
            except (TypeError, ValueError):
                continue
    return sum(1 for admin_id in admin_ids if admin_id in ready_user_ids), len(admin_ids)


def _api_group_state_locked(bot_data: dict[str, Any], chat_id: int) -> dict[str, Any]:
    groups = bot_data.get("group_state", {})
    if isinstance(groups, dict):
        state = groups.get(str(int(chat_id))) or groups.get(int(chat_id))
        if isinstance(state, dict):
            return state
    return {}


def _api_group_snapshot_locked(bot_data: dict[str, Any], user_id: int, chat_id: int) -> dict[str, Any]:
    state = _api_group_state_locked(bot_data, chat_id)
    meta_cache = bot_data.get("chat_meta_cache", {}) if isinstance(bot_data.get("chat_meta_cache", {}), dict) else {}
    meta = meta_cache.get(str(int(chat_id))) or meta_cache.get(int(chat_id)) or {}
    if not isinstance(meta, dict):
        meta = {}
    perms = get_bot_member_from_state(bot_data, chat_id)
    settings = _api_public_settings_locked(bot_data, chat_id)
    admin_ready, admin_total = _api_admin_ready_counts_locked(bot_data, chat_id)
    return {
        "id": int(chat_id),
        "title": get_chat_title_from_state(bot_data, chat_id),
        "type": str(meta.get("type") or state.get("chat_type") or state.get("type") or "group"),
        "lang": get_group_lang(bot_data, chat_id),
        "added_by": _safe_int(state.get("added_by"), 0) or None,
        "last_seen_ms": _safe_int(state.get("last_seen_ms"), 0),
        "last_seen_at": _api_ms_to_iso(state.get("last_seen_ms")),
        "settings": settings,
        "protection_enabled": bool(settings.get("protection_enabled")),
        "bot_permission": {
            "status": perms.status if perms else "unknown",
            "can_delete_messages": bool(perms.can_delete_messages) if perms else False,
            "can_restrict_members": bool(perms.can_restrict_members) if perms else False,
            "settings_unlocked": bot_settings_unlocked_from_state(bot_data, chat_id),
        },
        "counts": {
            "open_incidents": _open_incident_count_for_chat(bot_data, chat_id),
            "admin_logs": _admin_log_count_for_chat(bot_data, chat_id),
            "trusted_hashes": len(settings.get("trusted_file_hashes", [])),
            "admin_alert_ready": admin_ready,
            "admin_alert_total": admin_total,
        },
        "access": {
            "api_suppressed": is_chat_api_suppressed(bot_data, chat_id),
            "viewer_is_owner": int(user_id) in BOT_OWNER_IDS,
        },
    }


async def _api_group_snapshot(application: Application, user_id: int, chat_id: int) -> dict[str, Any]:
    async with BOT_DATA_LOCK:
        return _api_group_snapshot_locked(application.bot_data, user_id, chat_id)


async def _api_require_owner(principal: MiniAppPrincipal) -> None:
    if principal.user_id not in BOT_OWNER_IDS:
        _api_raise(403, "developer access required")


def _api_extract_server_log_api_key(request: Any) -> str:
    """Extract standalone /api/server/log key from header/query.

    Supported forms:
    - X-Server-Log-Key: <key>
    - X-API-Key: <key>
    - Authorization: Bearer <key>
    - ?server_log_key=<key> or ?key=<key> when SERVER_LOG_AUTH_QUERY_ENABLED=true
    """
    headers = getattr(request, "headers", {}) or {}
    for header_name in ("x-server-log-key", "X-Server-Log-Key", "x-api-key", "X-API-Key"):
        value = str(headers.get(header_name) or "").strip()
        if value:
            return value

    authorization = str(headers.get("authorization") or headers.get("Authorization") or "").strip()
    if authorization:
        lower = authorization.casefold()
        if lower.startswith("bearer "):
            return authorization[7:].strip()
        if lower.startswith("serverlog "):
            return authorization[10:].strip()

    if SERVER_LOG_AUTH_QUERY_ENABLED:
        query_params = getattr(request, "query_params", {}) or {}
        for key_name in ("server_log_key", "log_key", "api_key", "key"):
            value = str(query_params.get(key_name) or "").strip()
            if value:
                return value
    return ""


def _server_log_api_key_valid(value: str) -> bool:
    configured = str(SERVER_LOG_API_KEY or "").strip()
    provided = str(value or "").strip()
    if not configured or not provided:
        return False
    return hmac.compare_digest(provided, configured)


async def _api_require_server_log_access(request: Any) -> dict[str, Any]:
    """Authorize /api/server/log without requiring Telegram Mini App initData.

    Best production mode is SERVER_LOG_API_KEY. Telegram owner auth remains
    accepted for Mini App developer pages, but plain external API clients can
    use X-Server-Log-Key or Authorization: Bearer.
    """
    if SERVER_LOG_PUBLIC_ACCESS:
        return {"mode": "public", "user_id": None, "name": "public"}

    provided_key = _api_extract_server_log_api_key(request)
    if _server_log_api_key_valid(provided_key):
        return {"mode": "api_key", "user_id": None, "name": "server_log_api_key"}

    # Preserve old behavior for the Telegram Mini App developer dashboard.
    # We only attempt Telegram validation when initData is actually present,
    # so curl/Postman requests without initData receive a clear API-key error.
    if SERVER_LOG_ALLOW_TELEGRAM_OWNER_AUTH:
        init_data = await _extract_init_data_from_request(request)
        if init_data:
            principal = validate_telegram_webapp_init_data(init_data)
            await _api_require_owner(principal)
            return {"mode": "telegram_owner", "user_id": principal.user_id, "name": _api_full_name(principal.user)}

    if SERVER_LOG_API_KEY:
        _api_raise(401, "missing or invalid server log API key")
    _api_raise(503, "SERVER_LOG_API_KEY is not configured; set it in Render env to use /api/server/log without Telegram initData")


async def _api_require_group_admin(
    application: Application,
    principal: MiniAppPrincipal,
    chat_id: int,
    *,
    live: bool = True,
) -> None:
    if principal.user_id in BOT_OWNER_IDS:
        return
    if not await is_user_admin_in_group(application, int(chat_id), principal.user_id, allow_api=bool(live)):
        _api_raise(403, "group admin access required")


def _api_linked_group_ids_locked(bot_data: dict[str, Any], user_id: int) -> list[int]:
    ids = get_groups(bot_data, user_id)
    if user_id in BOT_OWNER_IDS:
        groups = bot_data.get("group_state", {})
        if isinstance(groups, dict):
            for key in groups.keys():
                try:
                    cid = int(key)
                except (TypeError, ValueError):
                    continue
                if cid not in ids:
                    ids.append(cid)
    return list(dict.fromkeys(int(item) for item in ids))


def _api_incident_locked(bot_data: dict[str, Any], ikey: str, incident: dict[str, Any]) -> dict[str, Any]:
    token = str(incident.get("action_token") or "")
    return {
        "key": str(ikey),
        "action_token": token,
        "chat_id": _safe_int(incident.get("chat_id"), 0),
        "group_name": str(incident.get("group_name") or incident.get("chat_id") or ""),
        "sender_id": _safe_int(incident.get("sender_id"), 0),
        "sender_name": str(incident.get("sender_name") or "Unknown"),
        "file_name": str(incident.get("file_name") or "Unknown"),
        "reason": str(incident.get("scan_reason") or incident.get("reason") or "blocked file"),
        "done": bool(incident.get("done", False)),
        "action": str(incident.get("action") or ""),
        "auto_action": str(incident.get("auto_action") or ""),
        "handled_by": _safe_int(incident.get("handled_by"), 0) or None,
        "handled_by_name": str(incident.get("handled_by_name") or ""),
        "created_at_ms": _safe_int(incident.get("created_at_ms"), incident_timestamp_ms(str(ikey)) or 0),
        "created_at": _api_ms_to_iso(incident.get("created_at_ms") or incident_timestamp_ms(str(ikey))),
        "handled_at_ms": _safe_int(incident.get("handled_at_ms"), 0),
        "handled_at": _api_ms_to_iso(incident.get("handled_at_ms")),
    }


def _api_incidents_for_chat_locked(bot_data: dict[str, Any], chat_id: int, *, status: str, limit: int) -> list[dict[str, Any]]:
    incidents = bot_data.get("incidents", {}) if isinstance(bot_data.get("incidents", {}), dict) else {}
    rows: list[dict[str, Any]] = []
    for ikey, incident in incidents.items():
        if not isinstance(incident, dict) or str(incident.get("chat_id")) != str(int(chat_id)):
            continue
        done = bool(incident.get("done", False))
        if status == "open" and done:
            continue
        if status == "handled" and not done:
            continue
        rows.append(_api_incident_locked(bot_data, str(ikey), incident))
    rows.sort(key=lambda item: int(item.get("created_at_ms") or 0), reverse=True)
    return rows[: max(1, min(int(limit), 200))]


def _api_risk_list_locked(bot_data: dict[str, Any], chat_id: int, *, limit: int = 20) -> list[dict[str, Any]]:
    incidents = bot_data.get("incidents", {}) if isinstance(bot_data.get("incidents", {}), dict) else {}
    known_users = bot_data.get("known_users", {}) if isinstance(bot_data.get("known_users", {}), dict) else {}
    stats: dict[int, dict[str, Any]] = {}
    for incident in incidents.values():
        if not isinstance(incident, dict) or str(incident.get("chat_id")) != str(int(chat_id)):
            continue
        sender_id = _safe_int(incident.get("sender_id"), 0)
        if not sender_id:
            continue
        entry = stats.setdefault(
            sender_id,
            {"user_id": sender_id, "name": str(incident.get("sender_name") or sender_id), "blocked": 0, "warned": 0, "muted": 0, "banned": 0, "last_file": "", "last_seen_ms": 0},
        )
        entry["blocked"] += 1
        entry["last_file"] = str(incident.get("file_name") or entry.get("last_file") or "")
        entry["last_seen_ms"] = max(_safe_int(entry.get("last_seen_ms"), 0), _safe_int(incident.get("created_at_ms"), incident_timestamp_ms("") or 0))
        action = str(incident.get("action") or incident.get("auto_action") or "").casefold()
        if action == "warn":
            entry["warned"] += 1
        elif action == "mute":
            entry["muted"] += 1
        elif action == "ban":
            entry["banned"] += 1
    rows = sorted(stats.values(), key=lambda item: (item["blocked"], item["banned"], item["muted"], item["warned"]), reverse=True)
    for row in rows:
        profile = known_users.get(str(row["user_id"]), {}) if isinstance(known_users.get(str(row["user_id"]), {}), dict) else {}
        row["username"] = str(profile.get("username") or "")
        row["display_name"] = str(profile.get("full_name") or row.get("name") or row["user_id"])
        row["risk"] = _risk_badge(_safe_int(row.get("blocked"), 0))
        row["last_seen_at"] = _api_ms_to_iso(row.get("last_seen_ms"))
    return rows[: max(1, min(int(limit), 100))]


def _api_admin_logs_for_chat_locked(bot_data: dict[str, Any], chat_id: int, *, limit: int = 100) -> list[dict[str, Any]]:
    rows = [dict(item) for item in _admin_action_logs(bot_data) if str(item.get("chat_id")) == str(int(chat_id))]
    rows.sort(key=lambda item: _safe_int(item.get("created_at_ms"), 0), reverse=True)
    for row in rows:
        row["created_at"] = _api_ms_to_iso(row.get("created_at_ms"))
    return _api_json_safe(rows[: max(1, min(int(limit), 200))])


def _api_memory_overview_locked(bot_data: dict[str, Any]) -> dict[str, Any]:
    known_users = bot_data.get("known_users", {}) if isinstance(bot_data.get("known_users", {}), dict) else {}
    group_state = bot_data.get("group_state", {}) if isinstance(bot_data.get("group_state", {}), dict) else {}
    incidents = bot_data.get("incidents", {}) if isinstance(bot_data.get("incidents", {}), dict) else {}
    feedback = bot_data.get("user_feedback", []) if isinstance(bot_data.get("user_feedback", []), list) else []
    return {
        "backend": storage_backend_label(),
        "supabase": "connected" if SUPABASE_AVAILABLE else ("configured_offline" if SUPABASE_ENABLED else "disabled"),
        "redis": "connected" if REDIS_AVAILABLE else ("configured_offline" if REDIS_ENABLED else "disabled"),
        "known_users": len(known_users),
        "groups": len(group_state),
        "open_incidents": sum(1 for item in incidents.values() if isinstance(item, dict) and not item.get("done")),
        "total_incidents": len(incidents),
        "feedback": len(feedback),
        "admin_cache": len(ADMIN_IDS_CACHE),
        "bot_permission_cache": len(BOT_MEMBER_CACHE),
        "last_supabase_save": SUPABASE_LAST_SAVE_UTC,
        "last_redis_save": REDIS_LAST_SAVE_UTC,
    }


def _api_route_catalog() -> dict[str, Any]:
    """Small public route catalog so a frontend can auto-wire API calls."""
    prefix = MINI_APP_API_PREFIX
    auth = "Send Telegram WebApp initData via X-Telegram-Init-Data or Authorization: tma <initData>."
    return {
        "auth": auth,
        "prefix": prefix,
        "public": {
            "root": "/",
            "health": f"{prefix}/health",
            "routes": f"{prefix}/routes",
        },
        "session": {
            "auth_session": f"{prefix}/auth/session",
            "session_alias": f"{prefix}/session",
            "bootstrap": f"{prefix}/bootstrap",
            "dashboard": f"{prefix}/dashboard",
            "me": f"{prefix}/me",
            "my_groups": f"{prefix}/me/groups",
            "groups_alias": f"{prefix}/groups",
        },
        "groups": {
            "detail": f"{prefix}/groups/{{chat_id}}",
            "settings": f"{prefix}/groups/{{chat_id}}/settings",
            "formats": f"{prefix}/groups/{{chat_id}}/formats/{{allowed|blocked}}",
            "trusted_hashes": f"{prefix}/groups/{{chat_id}}/trusted-hashes",
            "incidents": f"{prefix}/groups/{{chat_id}}/incidents",
            "risk": f"{prefix}/groups/{{chat_id}}/risk",
            "admins": f"{prefix}/groups/{{chat_id}}/admins",
            "admin_logs": f"{prefix}/groups/{{chat_id}}/admin-logs",
            "health": f"{prefix}/groups/{{chat_id}}/health",
        },
        "tools": {
            "scan_name": f"{prefix}/scan/name",
            "feedback": f"{prefix}/feedback",
            "incident_action": f"{prefix}/incidents/{{token_or_key}}/action",
        },
        "developer": {
            "overview": f"{prefix}/developer/overview",
            "users": f"{prefix}/developer/users",
            "groups": f"{prefix}/developer/groups",
            "feedback": f"{prefix}/developer/feedback",
            "runtime_config": f"{prefix}/developer/runtime-config",
            "server_log": f"{prefix}/server/log",
            "server_logs_alias": f"{prefix}/server/logs",
        },
    }


def _api_session_payload_locked(bot_data: dict[str, Any], principal: MiniAppPrincipal, *, include_groups: bool = False) -> dict[str, Any]:
    saved = bot_data.get("known_users", {}).get(str(principal.user_id), {}) if isinstance(bot_data.get("known_users", {}), dict) else {}
    state = _read_user_state(bot_data, principal.user_id)
    group_ids = _api_linked_group_ids_locked(bot_data, principal.user_id)
    payload: dict[str, Any] = {
        "ok": True,
        "user": _api_public_profile_from_principal(principal),
        "saved_profile": _api_json_safe(saved),
        "state": _api_json_safe(state),
        "is_developer": principal.user_id in BOT_OWNER_IDS,
        "linked_group_count": len(group_ids),
        "features": {
            "groups": True,
            "group_settings": True,
            "incidents": True,
            "trusted_hashes": trusted_hash_whitelist_enabled(bot_data),
            "developer_dashboard": principal.user_id in BOT_OWNER_IDS,
        },
        "routes": _api_route_catalog(),
    }
    if include_groups:
        payload["groups"] = [_api_group_snapshot_locked(bot_data, principal.user_id, chat_id) for chat_id in group_ids]
        payload["total_groups"] = len(payload["groups"])
    if principal.user_id in BOT_OWNER_IDS:
        payload["developer"] = {
            "overview": _api_memory_overview_locked(bot_data),
            "runtime_config": _api_json_safe(dict(ensure_runtime_config(bot_data))),
        }
    return payload


async def _api_perform_incident_action(
    application: Application,
    principal: MiniAppPrincipal,
    token_or_key: str,
    action: str,
) -> dict[str, Any]:
    action = str(action or "").strip().casefold()
    if action not in {"ban", "warn", "ignore", "risk"}:
        _api_raise(400, "action must be one of: ban, warn, ignore, risk")

    ikey = resolve_incident_action_key(application.bot_data, token_or_key)
    lock = await get_incident_lock(ikey)
    async with lock:
        async with BOT_DATA_LOCK:
            incidents = application.bot_data.setdefault("incidents", {})
            incident = incidents.get(ikey) if isinstance(incidents, dict) else None
            if not isinstance(incident, dict):
                _api_raise(404, "incident not found or expired")
            if incident.get("done") and action != "risk":
                _api_raise(409, "incident already handled")
            chat_id = int(incident.get("chat_id") or 0)
            sender_id = int(incident.get("sender_id") or 0)
            sender_name_raw = str(incident.get("sender_name") or "Unknown")

        await _api_require_group_admin(application, principal, chat_id, live=True)

        if action == "risk":
            async with BOT_DATA_LOCK:
                incident = application.bot_data.setdefault("incidents", {}).get(ikey)
                if not isinstance(incident, dict):
                    _api_raise(404, "incident not found or expired")
                return {
                    "ok": True,
                    "action": "risk",
                    "risk_html": _format_user_risk_profile(application.bot_data, principal.user_id, incident),
                    "incident": _api_incident_locked(application.bot_data, ikey, incident),
                }

        action_success = False
        result_message = ""
        sender_name = h(sender_name_raw)

        if action == "ban":
            try:
                bot_perms = await get_bot_member_cached(application, chat_id, force=True, allow_api=True)
                if not has_ban_permission(bot_perms):
                    raise TelegramError("Bot does not have Ban Users permission")
                for ban_attempt in (1, 2):
                    try:
                        await application.bot.ban_chat_member(chat_id, sender_id)
                        break
                    except RetryAfter as exc:
                        if ban_attempt == 1 and await _sleep_for_retry_after(exc, operation="api_ban_chat_member"):
                            continue
                        raise
                action_success = True
                result_message = tr(application.bot_data, principal.user_id, "action_ban_ok", name=sender_name)
            except (TimedOut, BadRequest, Forbidden, TelegramError):
                logger.exception("API ban failed chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
                result_message = tr(application.bot_data, principal.user_id, "action_ban_fail")
        elif action == "warn":
            mention = user_link(sender_id, sender_name_raw)
            warn_text = TEXTS[get_lang(application.bot_data, principal.user_id)]["warn_in_group"].format(user=mention)
            try:
                send_result = await safe_send_message_result(application, chat_id, warn_text, operation="api_incident_warn")
                if not send_result.ok:
                    raise TelegramError(send_result.error or "warning message could not be delivered")
                action_success = True
                result_message = tr(application.bot_data, principal.user_id, "action_warn_ok", name=sender_name)
            except (TimedOut, BadRequest, Forbidden, TelegramError):
                logger.exception("API warn failed chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
                result_message = tr(application.bot_data, principal.user_id, "action_warn_fail")
        else:
            action_success = True
            result_message = tr(application.bot_data, principal.user_id, "action_ignore_ok")

        async with BOT_DATA_LOCK:
            incident = application.bot_data.setdefault("incidents", {}).get(ikey)
            if not isinstance(incident, dict):
                _api_raise(404, "incident not found or expired")
            if action_success:
                incident["done"] = True
                incident["handled_by"] = principal.user_id
                incident["handled_by_name"] = _api_full_name(principal.user)
                incident["handled_at_ms"] = now_ms()
                incident["action"] = action
            _record_admin_action_log_locked(
                application.bot_data,
                chat_id=chat_id,
                admin_id=principal.user_id,
                admin_name=_api_full_name(principal.user),
                action=f"api incident {action}",
                target_id=sender_id,
                target_name=sender_name_raw,
                result="success" if action_success else "failed",
            )
            await persist_context_memory(application, reason="api_incident_action", force=True, caller_holds_lock=True)
            incident_response = _api_incident_locked(application.bot_data, ikey, incident)

        if action_success:
            await sync_handled_alert_messages(application, incident)

        return {"ok": bool(action_success), "action": action, "message": result_message, "incident": incident_response}


def create_mini_app_fastapi(application: Application, webhook_url: str) -> Any:
    """Create a FastAPI app that serves both Telegram webhook and Mini App API."""
    if FastAPI is None or CORSMiddleware is None or uvicorn is None:
        raise RuntimeError("MINI_APP_API_ENABLED=true requires dependencies: fastapi and uvicorn")

    api = FastAPI(title=f"{PROFESSIONAL_BRAND_NAME} Mini App API", version=PROFESSIONAL_UI_VERSION)
    cors_origins = [origin for origin in MINI_APP_CORS_ORIGINS if origin]
    cors_all = "*" in cors_origins or not cors_origins
    api.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if cors_all else cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        # Let Vite/Telegram/frontends send auth/initData headers without CORS preflight surprises.
        allow_headers=["*"],
        expose_headers=["Content-Type", "X-Request-ID"],
        max_age=86400,
    )

    webhook_route = "/" + WEBHOOK_URL_PATH.strip("/")
    secret_header = _telegram_secret_token_for_webhook()

    @api.middleware("http")
    async def api_server_log_middleware(request: Request, call_next: Any) -> Any:
        """Record every API/webhook connection, error, and slow process event."""
        global SERVER_LOG_REQUEST_TOTAL

        started = time.perf_counter()
        request_id = secrets.token_hex(6)
        path = str(getattr(request.url, "path", "") or "")
        method = str(getattr(request, "method", "") or "").upper()
        client = getattr(request, "client", None)
        client_host = str(getattr(client, "host", "") or "")
        user_agent = _server_log_safe_text(str(request.headers.get("user-agent") or ""), max_chars=180)
        log_this_request = path == "/" or path == webhook_route or path.startswith(MINI_APP_API_PREFIX.rstrip("/") + "/") or path == MINI_APP_API_PREFIX

        try:
            response = await call_next(request)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            try:
                response.headers["X-Request-ID"] = request_id
            except Exception:
                pass

            if log_this_request:
                SERVER_LOG_REQUEST_TOTAL += 1
                status_code = int(getattr(response, "status_code", 0) or 0)
                level = "error" if status_code >= 500 else "warning" if status_code >= 400 or elapsed_ms >= SERVER_LOG_SLOW_API_MS else "info"
                category = "api_error" if status_code >= 400 else "api_request"
                server_log_event(
                    category,
                    level,
                    "api request completed",
                    request_id=request_id,
                    method=method,
                    path=path,
                    status_code=status_code,
                    elapsed_ms=elapsed_ms,
                    client_host=client_host,
                    user_agent=user_agent,
                    slow=elapsed_ms >= SERVER_LOG_SLOW_API_MS,
                )
            return response
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            if log_this_request:
                SERVER_LOG_REQUEST_TOTAL += 1
                server_log_event(
                    "api_error",
                    "error",
                    "api request failed",
                    request_id=request_id,
                    method=method,
                    path=path,
                    elapsed_ms=elapsed_ms,
                    client_host=client_host,
                    user_agent=user_agent,
                    error_type=exc.__class__.__name__,
                    error=_server_log_safe_text(str(exc), max_chars=500),
                    traceback=_server_log_safe_text(traceback.format_exc(), max_chars=SERVER_LOG_TRACEBACK_MAX_CHARS),
                )
            raise

    @api.on_event("startup")
    async def _api_startup() -> None:
        await application.initialize()
        await post_init(application)
        await application.start()
        webhook_kwargs: dict[str, Any] = {
            "url": webhook_url,
            "allowed_updates": ALLOWED_UPDATES,
            "drop_pending_updates": DROP_PENDING_UPDATES,
        }
        if secret_header:
            webhook_kwargs["secret_token"] = secret_header
        await application.bot.set_webhook(**webhook_kwargs)
        logger.info("Mini App API enabled prefix=%s webhook_route=%s", MINI_APP_API_PREFIX, webhook_route)
        server_log_event("process", "info", "mini app api startup", prefix=MINI_APP_API_PREFIX, webhook_route=webhook_route, bot_username=BOT_USERNAME)

    @api.on_event("shutdown")
    async def _api_shutdown() -> None:
        server_log_event("process", "info", "mini app api shutdown")
        await application.stop()
        await post_shutdown(application)
        await application.shutdown()

    @api.get("/")
    async def api_root() -> dict[str, Any]:
        return {
            "ok": True,
            "name": PROFESSIONAL_BRAND_NAME,
            "version": PROFESSIONAL_UI_VERSION,
            "api_prefix": MINI_APP_API_PREFIX,
            "docs": "/docs",
            "routes": f"{MINI_APP_API_PREFIX}/routes",
            "bootstrap": f"{MINI_APP_API_PREFIX}/bootstrap",
            "server_log": f"{MINI_APP_API_PREFIX}/server/log",
        }

    @api.get(MINI_APP_API_PREFIX)
    @api.get(f"{MINI_APP_API_PREFIX}/")
    async def api_index() -> dict[str, Any]:
        return {"ok": True, "name": PROFESSIONAL_BRAND_NAME, "version": PROFESSIONAL_UI_VERSION, "routes": _api_route_catalog()}

    @api.get(f"{MINI_APP_API_PREFIX}/routes")
    async def api_routes() -> dict[str, Any]:
        return {"ok": True, "routes": _api_route_catalog()}

    @api.get(f"{MINI_APP_API_PREFIX}/health")
    async def api_health() -> dict[str, Any]:
        async with BOT_DATA_LOCK:
            memory = _api_memory_overview_locked(application.bot_data)
        return {
            "ok": True,
            "bot_id": BOT_ID,
            "bot_username": BOT_USERNAME,
            "mode": "WEBHOOK+API",
            "webhook_path": webhook_route,
            "memory": memory,
        }

    @api.api_route(webhook_route, methods=["POST"])
    async def telegram_webhook(request: Request) -> dict[str, bool]:
        if secret_header:
            got = str(request.headers.get("X-Telegram-Bot-Api-Secret-Token") or "")
            if not hmac.compare_digest(got, secret_header):
                _api_raise(403, "invalid Telegram webhook secret")
        payload = await _api_request_json(request)
        try:
            update = Update.de_json(payload, application.bot)
            await application.process_update(update)
        except Exception:
            logger.exception("Webhook update processing failed", exc_info=True)
            # Return ok=True to avoid Telegram retry storms for malformed or already-bad updates.
        return {"ok": True}

    @api.get(f"{MINI_APP_API_PREFIX}/auth/session")
    @api.post(f"{MINI_APP_API_PREFIX}/auth/session")
    @api.get(f"{MINI_APP_API_PREFIX}/session")
    @api.post(f"{MINI_APP_API_PREFIX}/session")
    async def api_auth_session(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_remember_principal(application, principal, persist=True)
        async with BOT_DATA_LOCK:
            return _api_session_payload_locked(application.bot_data, principal, include_groups=False)

    @api.get(f"{MINI_APP_API_PREFIX}/bootstrap")
    @api.post(f"{MINI_APP_API_PREFIX}/bootstrap")
    @api.get(f"{MINI_APP_API_PREFIX}/dashboard")
    @api.post(f"{MINI_APP_API_PREFIX}/dashboard")
    async def api_bootstrap(request: Request, refresh: bool = False) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_remember_principal(application, principal, persist=True)
        async with BOT_DATA_LOCK:
            group_ids = _api_linked_group_ids_locked(application.bot_data, principal.user_id)
        if refresh and MINI_APP_LIVE_REFRESH_ALLOWED:
            await asyncio.gather(
                *(get_bot_member_cached(application, chat_id, force=True, allow_api=True) for chat_id in group_ids[:25]),
                return_exceptions=True,
            )
        async with BOT_DATA_LOCK:
            return _api_session_payload_locked(application.bot_data, principal, include_groups=True)

    @api.get(f"{MINI_APP_API_PREFIX}/me")
    async def api_me(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        async with BOT_DATA_LOCK:
            saved = application.bot_data.get("known_users", {}).get(str(principal.user_id), {}) if isinstance(application.bot_data.get("known_users", {}), dict) else {}
            state = _read_user_state(application.bot_data, principal.user_id)
            groups = _api_linked_group_ids_locked(application.bot_data, principal.user_id)
        return {
            "ok": True,
            "user": _api_public_profile_from_principal(principal),
            "saved_profile": _api_json_safe(saved),
            "state": _api_json_safe(state),
            "is_developer": principal.user_id in BOT_OWNER_IDS,
            "linked_group_count": len(groups),
        }

    @api.get(f"{MINI_APP_API_PREFIX}/me/groups")
    @api.get(f"{MINI_APP_API_PREFIX}/groups")
    async def api_my_groups(request: Request, refresh: bool = False) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_remember_principal(application, principal, persist=False)
        async with BOT_DATA_LOCK:
            group_ids = _api_linked_group_ids_locked(application.bot_data, principal.user_id)
        if refresh and MINI_APP_LIVE_REFRESH_ALLOWED:
            await asyncio.gather(
                *(get_bot_member_cached(application, chat_id, force=True, allow_api=True) for chat_id in group_ids[:25]),
                return_exceptions=True,
            )
        async with BOT_DATA_LOCK:
            groups = [_api_group_snapshot_locked(application.bot_data, principal.user_id, chat_id) for chat_id in group_ids]
        return {"ok": True, "groups": groups, "total": len(groups)}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}")
    async def api_group_detail(chat_id: int, request: Request, refresh: bool = False) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=refresh and MINI_APP_LIVE_REFRESH_ALLOWED)
        if refresh and MINI_APP_LIVE_REFRESH_ALLOWED:
            await asyncio.gather(
                get_bot_member_cached(application, chat_id, force=True, allow_api=True),
                get_chat_admin_ids_cached(application, chat_id, force=True, allow_api=True),
                return_exceptions=True,
            )
        return {"ok": True, "group": await _api_group_snapshot(application, principal.user_id, chat_id)}

    @api.patch(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/settings")
    async def api_update_group_settings(chat_id: int, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        payload = await _api_request_json(request)
        changed: list[str] = []
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            if "protection_enabled" in payload:
                settings["protection_enabled"] = _api_bool(payload.get("protection_enabled"), bool(settings.get("protection_enabled", True)))
                changed.append("protection_enabled")
            if "silent_mode" in payload:
                settings["silent_mode"] = _api_bool(payload.get("silent_mode"), bool(settings.get("silent_mode", False)))
                changed.append("silent_mode")
            if "strictness" in payload:
                strictness = str(payload.get("strictness") or "standard").strip().casefold()
                if strictness not in {"standard", "high", "strict"}:
                    _api_raise(400, "strictness must be standard, high, or strict")
                settings["strictness"] = strictness
                changed.append("strictness")
            if "allowed_extensions" in payload:
                settings["allowed_extensions"] = _api_extension_values(payload.get("allowed_extensions"), allowed=True)
                changed.append("allowed_extensions")
            if "custom_blocked_extensions" in payload:
                settings["custom_blocked_extensions"] = _api_extension_values(payload.get("custom_blocked_extensions"), allowed=False)
                changed.append("custom_blocked_extensions")
            if "auto_action_mode" in payload:
                mode = str(payload.get("auto_action_mode") or "off").strip().casefold()
                if mode not in {"off", "warn", "smart", "ban"}:
                    _api_raise(400, "auto_action_mode must be off, warn, smart, or ban")
                settings["auto_action_mode"] = mode
                changed.append("auto_action_mode")
            for key, default, max_value in (
                ("auto_warn_threshold", 1, 100),
                ("auto_mute_threshold", 2, 100),
                ("auto_ban_threshold", 3, 100),
                ("auto_mute_minutes", 60, 10080),
            ):
                if key in payload:
                    settings[key] = _api_int(payload.get(key), default, min_value=1, max_value=max_value)
                    changed.append(key)
            if changed:
                _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action="api update settings", result=", ".join(changed))
                await persist_context_memory(application, reason="api_group_settings_update", force=True, caller_holds_lock=True)
            group = _api_group_snapshot_locked(application.bot_data, principal.user_id, chat_id)
        return {"ok": True, "changed": changed, "group": group}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/formats/{{kind}}")
    async def api_get_formats(chat_id: int, kind: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        kind = kind.strip().casefold()
        if kind not in {"allowed", "blocked"}:
            _api_raise(400, "kind must be allowed or blocked")
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            key = "allowed_extensions" if kind == "allowed" else "custom_blocked_extensions"
            return {"ok": True, "kind": kind, "extensions": list(settings.get(key, []))}

    @api.post(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/formats/{{kind}}")
    async def api_update_formats(chat_id: int, kind: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        kind = kind.strip().casefold()
        if kind not in {"allowed", "blocked"}:
            _api_raise(400, "kind must be allowed or blocked")
        payload = await _api_request_json(request)
        mode = str(payload.get("mode") or "append").strip().casefold()
        if mode not in {"append", "replace"}:
            _api_raise(400, "mode must be append or replace")
        new_exts = _api_extension_values(payload.get("extensions") or payload.get("extension") or "", allowed=(kind == "allowed"))
        if not new_exts and mode != "replace":
            _api_raise(400, "no valid extensions supplied")
        key = "allowed_extensions" if kind == "allowed" else "custom_blocked_extensions"
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            old = list(settings.get(key, []))
            combined = new_exts if mode == "replace" else old + new_exts
            settings[key] = _api_extension_values(combined, allowed=(kind == "allowed"))
            _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action=f"api {mode} {kind} formats", result=", ".join(settings[key]) or "empty")
            await persist_context_memory(application, reason="api_formats_update", force=True, caller_holds_lock=True)
            return {"ok": True, "kind": kind, "extensions": list(settings.get(key, [])), "group": _api_group_snapshot_locked(application.bot_data, principal.user_id, chat_id)}

    @api.delete(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/formats/{{kind}}/{{ext}}")
    async def api_delete_format(chat_id: int, kind: str, ext: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        kind = kind.strip().casefold()
        if kind not in {"allowed", "blocked"}:
            _api_raise(400, "kind must be allowed or blocked")
        normalized = _normalize_extension(ext)
        key = "allowed_extensions" if kind == "allowed" else "custom_blocked_extensions"
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            settings[key] = [item for item in settings.get(key, []) if item != normalized]
            _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action=f"api delete {kind} format", result=normalized)
            await persist_context_memory(application, reason="api_format_delete", force=True, caller_holds_lock=True)
            return {"ok": True, "kind": kind, "extensions": list(settings.get(key, []))}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/trusted-hashes")
    async def api_get_hashes(chat_id: int, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            bucket = application.bot_data.get("whitelisted_hashes", {}) if isinstance(application.bot_data.get("whitelisted_hashes", {}), dict) else {}
            meta = bucket.get(str(int(chat_id)), {}) if isinstance(bucket.get(str(int(chat_id)), {}), dict) else {}
            return {"ok": True, "enabled": trusted_hash_whitelist_enabled(application.bot_data), "hashes": list(settings.get("trusted_file_hashes", [])), "metadata": _api_json_safe(meta)}

    @api.post(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/trusted-hashes")
    async def api_add_hash(chat_id: int, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        payload = await _api_request_json(request)
        digest = normalize_sha256_hash(payload.get("sha256") or payload.get("hash") or payload.get("file_sha256"))
        if not digest:
            _api_raise(400, "valid sha256 hash is required")
        async with BOT_DATA_LOCK:
            ok = add_trusted_file_hash(application.bot_data, chat_id, digest, added_by=principal.user_id, file_name=str(payload.get("file_name") or ""))
            if not ok:
                _api_raise(400, "could not add trusted hash; check max hash limit")
            _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action="api add trusted hash", result=short_hash(digest))
            await persist_context_memory(application, reason="api_hash_add", force=True, caller_holds_lock=True)
            settings = get_group_settings(application.bot_data, chat_id)
            return {"ok": True, "hashes": list(settings.get("trusted_file_hashes", []))}

    @api.delete(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/trusted-hashes/{{digest}}")
    async def api_delete_hash(chat_id: int, digest: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        async with BOT_DATA_LOCK:
            ok = remove_trusted_file_hash(application.bot_data, chat_id, digest)
            if not ok:
                _api_raise(404, "trusted hash not found")
            _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action="api delete trusted hash", result=str(digest)[:12])
            await persist_context_memory(application, reason="api_hash_delete", force=True, caller_holds_lock=True)
            settings = get_group_settings(application.bot_data, chat_id)
            return {"ok": True, "hashes": list(settings.get("trusted_file_hashes", []))}

    @api.delete(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/trusted-hashes")
    async def api_clear_hashes(chat_id: int, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        async with BOT_DATA_LOCK:
            clear_trusted_file_hashes(application.bot_data, chat_id)
            _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action="api clear trusted hashes", result="cleared")
            await persist_context_memory(application, reason="api_hash_clear", force=True, caller_holds_lock=True)
        return {"ok": True, "hashes": []}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/incidents")
    async def api_group_incidents(chat_id: int, request: Request, status: str = "all", limit: int = 50) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        status = status.strip().casefold()
        if status not in {"all", "open", "handled"}:
            _api_raise(400, "status must be all, open, or handled")
        async with BOT_DATA_LOCK:
            rows = _api_incidents_for_chat_locked(application.bot_data, chat_id, status=status, limit=limit)
        return {"ok": True, "incidents": rows, "total": len(rows)}

    @api.post(f"{MINI_APP_API_PREFIX}/incidents/{{token_or_key}}/action")
    async def api_incident_action(token_or_key: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        payload = await _api_request_json(request)
        action = str(payload.get("action") or "").strip().casefold()
        return await _api_perform_incident_action(application, principal, token_or_key, action)

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/risk")
    async def api_group_risk(chat_id: int, request: Request, limit: int = 20) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        async with BOT_DATA_LOCK:
            rows = _api_risk_list_locked(application.bot_data, chat_id, limit=limit)
        return {"ok": True, "risk": rows, "total": len(rows)}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/admins")
    async def api_group_admins(chat_id: int, request: Request, refresh: bool = False) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=refresh and MINI_APP_LIVE_REFRESH_ALLOWED)
        if refresh and MINI_APP_LIVE_REFRESH_ALLOWED:
            ids = await get_chat_admin_ids_cached(application, chat_id, force=True, allow_api=True)
        else:
            ids = await get_chat_admin_ids_from_state(application.bot_data, chat_id)
        async with BOT_DATA_LOCK:
            known_users = application.bot_data.get("known_users", {}) if isinstance(application.bot_data.get("known_users", {}), dict) else {}
            user_state = application.bot_data.get("user_state", {}) if isinstance(application.bot_data.get("user_state", {}), dict) else {}
            admins = []
            for admin_id in ids:
                profile = known_users.get(str(admin_id), {}) if isinstance(known_users.get(str(admin_id), {}), dict) else {}
                admins.append({
                    "id": int(admin_id),
                    "full_name": str(profile.get("full_name") or admin_id),
                    "username": str(profile.get("username") or ""),
                    "alert_ready": str(admin_id) in {str(k) for k in user_state.keys()},
                })
        return {"ok": True, "admins": admins, "total": len(admins)}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/admin-logs")
    async def api_group_admin_logs(chat_id: int, request: Request, limit: int = 100) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        async with BOT_DATA_LOCK:
            rows = _api_admin_logs_for_chat_locked(application.bot_data, chat_id, limit=limit)
        return {"ok": True, "logs": rows, "total": len(rows)}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/health")
    async def api_group_health(chat_id: int, request: Request, refresh: bool = False) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=refresh and MINI_APP_LIVE_REFRESH_ALLOWED)
        if refresh and MINI_APP_LIVE_REFRESH_ALLOWED:
            await asyncio.gather(
                get_bot_member_cached(application, chat_id, force=True, allow_api=True),
                get_chat_admin_ids_cached(application, chat_id, force=True, allow_api=True),
                return_exceptions=True,
            )
        group = await _api_group_snapshot(application, principal.user_id, chat_id)
        return {"ok": True, "health": group["bot_permission"], "counts": group["counts"], "group": group}

    @api.post(f"{MINI_APP_API_PREFIX}/scan/name")
    async def api_scan_name(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        payload = await _api_request_json(request)
        file_name = str(payload.get("file_name") or payload.get("filename") or "").strip()
        if not file_name:
            _api_raise(400, "file_name is required")
        result = scan_filename_only(file_name, str(payload.get("mime_type") or ""))
        return {"ok": True, "user_id": principal.user_id, "scan": _api_scan_result(result)}

    @api.post(f"{MINI_APP_API_PREFIX}/feedback")
    async def api_feedback(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        payload = await _api_request_json(request)
        text = str(payload.get("text") or payload.get("message") or "").strip()
        if len(text) < 5:
            _api_raise(400, "feedback is too short")
        async with BOT_DATA_LOCK:
            feedback = application.bot_data.setdefault("user_feedback", [])
            if not isinstance(feedback, list):
                feedback = []
                application.bot_data["user_feedback"] = feedback
            feedback.insert(0, {
                "user_id": principal.user_id,
                "name": _api_full_name(principal.user),
                "username": str(principal.user.get("username") or ""),
                "text": text[:2000],
                "created_at_ms": now_ms(),
                "source": "mini_app_api",
            })
            del feedback[MAX_USER_FEEDBACK_ITEMS:]
            await persist_context_memory(application, reason="api_feedback", force=True, caller_holds_lock=True)
        return {"ok": True}

    @api.get(f"{MINI_APP_API_PREFIX}/server/log")
    @api.get(f"{MINI_APP_API_PREFIX}/server/logs")
    async def api_server_log(request: Request, limit: int = 200, level: str = "all", category: str = "all", since_id: int = 0) -> dict[str, Any]:
        auth_info = await _api_require_server_log_access(request)
        rows = server_log_snapshot(limit=limit, level=level, category=category, since_id=since_id)
        return {
            "ok": True,
            "auth": {"mode": auth_info.get("mode")},
            "logs": _api_json_safe(rows),
            "total": len(rows),
            "filters": {"limit": limit, "level": level, "category": category, "since_id": since_id},
            "counters": server_log_counters(),
            "process": process_status_snapshot(),
            "routes": {
                "self": f"{MINI_APP_API_PREFIX}/server/log",
                "clear": f"{MINI_APP_API_PREFIX}/server/log",
            },
        }

    @api.delete(f"{MINI_APP_API_PREFIX}/server/log")
    @api.delete(f"{MINI_APP_API_PREFIX}/server/logs")
    async def api_clear_server_log(request: Request) -> dict[str, Any]:
        auth_info = await _api_require_server_log_access(request)
        clear_server_logs()
        server_log_event(
            "process",
            "warning",
            "server logs cleared",
            auth_mode=auth_info.get("mode"),
            user_id=auth_info.get("user_id"),
            name=auth_info.get("name"),
        )
        return {"ok": True, "message": "server logs cleared", "auth": {"mode": auth_info.get("mode")}, "counters": server_log_counters()}

    @api.get(f"{MINI_APP_API_PREFIX}/developer/overview")
    async def api_developer_overview(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        async with BOT_DATA_LOCK:
            return {"ok": True, "overview": _api_memory_overview_locked(application.bot_data)}

    @api.get(f"{MINI_APP_API_PREFIX}/developer/users")
    async def api_developer_users(request: Request, limit: int = 100) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        async with BOT_DATA_LOCK:
            known = application.bot_data.get("known_users", {}) if isinstance(application.bot_data.get("known_users", {}), dict) else {}
            users = [_api_json_safe(value) for value in known.values() if isinstance(value, dict)]
            users.sort(key=lambda item: _safe_int(item.get("last_seen_ms"), 0), reverse=True)
        return {"ok": True, "users": users[: max(1, min(limit, 500))], "total": len(users)}

    @api.get(f"{MINI_APP_API_PREFIX}/developer/groups")
    async def api_developer_groups(request: Request, limit: int = 200) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        async with BOT_DATA_LOCK:
            ids = _api_linked_group_ids_locked(application.bot_data, principal.user_id)
            groups = [_api_group_snapshot_locked(application.bot_data, principal.user_id, cid) for cid in ids]
        return {"ok": True, "groups": groups[: max(1, min(limit, 1000))], "total": len(groups)}

    @api.get(f"{MINI_APP_API_PREFIX}/developer/feedback")
    async def api_developer_feedback(request: Request, limit: int = 100) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        async with BOT_DATA_LOCK:
            feedback = application.bot_data.get("user_feedback", []) if isinstance(application.bot_data.get("user_feedback", []), list) else []
            rows = [_api_json_safe(item) for item in feedback if isinstance(item, dict)]
        return {"ok": True, "feedback": rows[: max(1, min(limit, 500))], "total": len(rows)}

    @api.get(f"{MINI_APP_API_PREFIX}/developer/runtime-config")
    async def api_get_runtime_config(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        async with BOT_DATA_LOCK:
            config = dict(ensure_runtime_config(application.bot_data))
        return {"ok": True, "runtime_config": _api_json_safe(config)}

    @api.patch(f"{MINI_APP_API_PREFIX}/developer/runtime-config")
    async def api_update_runtime_config(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        payload = await _api_request_json(request)
        async with BOT_DATA_LOCK:
            config = ensure_runtime_config(application.bot_data)
            if "trusted_file_hash_whitelist_enabled" in payload:
                config["trusted_file_hash_whitelist_enabled"] = _api_bool(payload.get("trusted_file_hash_whitelist_enabled"), trusted_hash_whitelist_enabled(application.bot_data))
            if "trusted_hash_max_download_bytes" in payload:
                config["trusted_hash_max_download_bytes"] = _api_int(payload.get("trusted_hash_max_download_bytes"), TRUSTED_HASH_MAX_DOWNLOAD_BYTES, min_value=1, max_value=100_000_000)
            if "max_trusted_file_hashes" in payload:
                config["max_trusted_file_hashes"] = _api_int(payload.get("max_trusted_file_hashes"), MAX_TRUSTED_FILE_HASHES, min_value=1, max_value=1000)
            await persist_context_memory(application, reason="api_runtime_config_update", force=True, caller_holds_lock=True)
            return {"ok": True, "runtime_config": _api_json_safe(config)}

    return api


def run_webhook_with_mini_app_api(application: Application, webhook_url: str) -> None:
    """Run webhook + REST API on the same Render web service port."""
    api = create_mini_app_fastapi(application, webhook_url)
    uvicorn.run(
        api,
        host="0.0.0.0",
        port=PORT,
        log_level=_env_str("UVICORN_LOG_LEVEL", "info").lower(),
        access_log=MINI_APP_UVICORN_ACCESS_LOG,
    )

# ─────────────────────────────────────────────────────────────
# APP LIFECYCLE / ERROR HANDLING
# ─────────────────────────────────────────────────────────────


async def post_init(application: Application) -> None:
    global BOT_ID, BOT_USERNAME
    me = await application.bot.get_me()
    BOT_ID = int(me.id)
    BOT_USERNAME = me.username or ""
    logger.info("Bot initialized as @%s id=%s", BOT_USERNAME, BOT_ID)
    # Load Redis first, then Supabase. This lets an existing Redis deployment
    # migrate into Supabase automatically when Supabase has no row yet, while
    # Supabase can still override stale Redis if both already contain data.
    await init_redis_memory(application)
    await init_supabase_memory(application)
    async with BOT_DATA_LOCK:
        sanitize_bot_data_in_place(application.bot_data)
        await persist_context_memory(application, reason="state_sanitized_startup", force=True, caller_holds_lock=True)

    try:
        # Hide the Telegram slash-command menu so users manage the bot from buttons.
        # Handlers remain registered for /start deep links and safe developer fallback.
        try:
            await application.bot.delete_my_commands()
        except AttributeError:
            await application.bot.set_my_commands([])
    except TelegramError:
        logger.exception("Could not clear bot command menu", exc_info=True)


async def post_shutdown(application: Application) -> None:
    global KEEP_AWAKE_CLIENT
    await drain_pending_memory_saves(timeout=5.0)
    await persist_context_memory(application, reason="shutdown", force=True)
    await drain_pending_memory_saves(timeout=5.0)
    await close_supabase_memory()
    await close_redis_memory()
    if KEEP_AWAKE_CLIENT is not None:
        await KEEP_AWAKE_CLIENT.aclose()
        KEEP_AWAKE_CLIENT = None


async def debug_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Guarded diagnostic command. Shows only non-sensitive counters."""
    user_id = update.effective_user.id if update.effective_user else None
    if not await require_admin_or_owner(update, context):
        return
    async with BOT_DATA_LOCK:
        user_count = len(context.bot_data.get("known_users", {})) if isinstance(context.bot_data.get("known_users", {}), dict) else 0
        group_count = len(context.bot_data.get("group_state", {})) if isinstance(context.bot_data.get("group_state", {}), dict) else 0
        admin_cache_count = len(context.bot_data.get("admin_ids_cache", {})) if isinstance(context.bot_data.get("admin_ids_cache", {}), dict) else 0
        bot_perm_cache_count = len(context.bot_data.get("bot_member_cache", {})) if isinstance(context.bot_data.get("bot_member_cache", {}), dict) else 0
        chat_meta_count = len(context.bot_data.get("chat_meta_cache", {})) if isinstance(context.bot_data.get("chat_meta_cache", {}), dict) else 0
    text = (
        "🛠️ <b>Debug</b>\n"
        f"Users: <code>{user_count}</code>\n"
        f"Groups: <code>{group_count}</code>\n"
        f"Admin cache: <code>{admin_cache_count}</code>\n"
        f"Bot perm cache: <code>{bot_perm_cache_count}</code>\n"
        f"Chat meta cache: <code>{chat_meta_count}</code>\n"
        f"Middleware enabled: <code>{MIDDLEWARE_ENABLED}</code>\n"
        f"Middleware handled: <code>{MIDDLEWARE_HANDLED_UPDATES}</code>\n"
        f"Middleware dropped: <code>{MIDDLEWARE_DROPPED_UPDATES}</code>\n"
        f"Middleware buckets: <code>{len(MIDDLEWARE_RATE_BUCKETS)}</code>\n"
        f"Supabase: <code>{'connected' if SUPABASE_AVAILABLE else 'offline/disabled'}</code>\n"
        f"Redis: <code>{'connected' if REDIS_AVAILABLE else 'offline/disabled'}</code>"
    )
    await safe_reply(update, text)


def middleware_update_kind(update: Update) -> str:
    """Return a compact update type for logs/metrics without parsing payload deeply."""
    if update.callback_query:
        return "callback_query"
    if update.message:
        message = update.message
        if message.document:
            return "document"
        if message.text:
            return "command" if message.text.startswith("/") else "text"
        if message.new_chat_members or message.left_chat_member:
            return "chat_member_message"
        return "message"
    if update.my_chat_member:
        return "my_chat_member"
    if update.chat_member:
        return "chat_member"
    return "update"


def prune_middleware_rate_buckets(now: float) -> None:
    """Bound middleware memory under high traffic."""
    global MIDDLEWARE_LAST_PRUNE_MONOTONIC
    if now - MIDDLEWARE_LAST_PRUNE_MONOTONIC < 60.0:
        return
    MIDDLEWARE_LAST_PRUNE_MONOTONIC = now
    cutoff = now - MIDDLEWARE_RATE_LIMIT_WINDOW_SECONDS
    stale_user_ids: list[int] = []
    for user_id, bucket in list(MIDDLEWARE_RATE_BUCKETS.items()):
        bucket[:] = [ts for ts in bucket if ts >= cutoff]
        if not bucket:
            stale_user_ids.append(user_id)
    for user_id in stale_user_ids:
        MIDDLEWARE_RATE_BUCKETS.pop(user_id, None)

    notice_cutoff = now - max(MIDDLEWARE_RATE_LIMIT_NOTICE_COOLDOWN_SECONDS, 1.0)
    for user_id, ts in list(MIDDLEWARE_RATE_LIMIT_NOTICES.items()):
        if ts < notice_cutoff:
            MIDDLEWARE_RATE_LIMIT_NOTICES.pop(user_id, None)

    # ApplicationHandlerStop prevents the post-middleware from running, so prune
    # stale start markers here too. This avoids a tiny memory leak during spam.
    update_cutoff = now - max(MIDDLEWARE_SLOW_UPDATE_SECONDS * 4, MIDDLEWARE_RATE_LIMIT_WINDOW_SECONDS * 2, 60.0)
    for update_id, started_at in list(MIDDLEWARE_UPDATE_STARTS.items()):
        if started_at < update_cutoff:
            MIDDLEWARE_UPDATE_STARTS.pop(update_id, None)

    if len(MIDDLEWARE_RATE_BUCKETS) > MIDDLEWARE_MAX_TRACKED_USERS:
        overflow = len(MIDDLEWARE_RATE_BUCKETS) - MIDDLEWARE_MAX_TRACKED_USERS
        for user_id in list(MIDDLEWARE_RATE_BUCKETS.keys())[:overflow]:
            MIDDLEWARE_RATE_BUCKETS.pop(user_id, None)
            MIDDLEWARE_RATE_LIMIT_NOTICES.pop(user_id, None)


async def notify_rate_limited(update: Update) -> None:
    """Acknowledge callback spam without flooding users with duplicate alerts."""
    query = update.callback_query
    if not query:
        return
    user_id = int(query.from_user.id) if query.from_user else 0
    now = time.monotonic()
    last_notice = MIDDLEWARE_RATE_LIMIT_NOTICES.get(user_id, 0.0)
    show_text = (now - last_notice) >= MIDDLEWARE_RATE_LIMIT_NOTICE_COOLDOWN_SECONDS
    if show_text:
        MIDDLEWARE_RATE_LIMIT_NOTICES[user_id] = now
    try:
        await query.answer("Too many requests. Please slow down." if show_text else None, show_alert=False)
    except TelegramError:
        logger.debug("Could not send middleware rate-limit notice", exc_info=True)


async def bot_middleware_pre(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Runs before all business handlers.

    Responsibilities:
    - bounded per-user rate limit
    - structured request logging
    - start-time tracking for slow update diagnostics

    Raise ApplicationHandlerStop to drop abusive updates before expensive file
    scanning, admin lookups, Redis/Supabase writes, or Telegram API calls.
    """
    global MIDDLEWARE_DROPPED_UPDATES

    if not MIDDLEWARE_ENABLED:
        return

    now = time.monotonic()
    update_id = update.update_id
    if update_id is not None:
        MIDDLEWARE_UPDATE_STARTS[update_id] = now

    effective_user = update.effective_user
    effective_chat = update.effective_chat
    user_id = int(effective_user.id) if effective_user else None
    chat_id = int(effective_chat.id) if effective_chat else None
    kind = middleware_update_kind(update)

    if MIDDLEWARE_LOG_UPDATES:
        logger.debug(
            "middleware inbound kind=%s update_id=%s chat_id=%s user_id=%s",
            kind,
            update_id,
            chat_id,
            user_id,
        )

    if (
        MIDDLEWARE_RATE_LIMIT_ENABLED
        and user_id is not None
        and user_id not in BOT_OWNER_IDS
    ):
        prune_middleware_rate_buckets(now)
        cutoff = now - MIDDLEWARE_RATE_LIMIT_WINDOW_SECONDS
        bucket = MIDDLEWARE_RATE_BUCKETS.setdefault(user_id, [])
        bucket[:] = [ts for ts in bucket if ts >= cutoff]
        bucket.append(now)
        if len(bucket) > MIDDLEWARE_RATE_LIMIT_MAX_UPDATES:
            MIDDLEWARE_DROPPED_UPDATES += 1
            logger.warning(
                "middleware rate-limited update kind=%s update_id=%s chat_id=%s user_id=%s count=%s window=%ss",
                kind,
                update_id,
                chat_id,
                user_id,
                len(bucket),
                MIDDLEWARE_RATE_LIMIT_WINDOW_SECONDS,
            )
            await notify_rate_limited(update)
            raise ApplicationHandlerStop


async def bot_middleware_post(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Runs after normal handlers to record slow-update diagnostics."""
    global MIDDLEWARE_HANDLED_UPDATES

    if not MIDDLEWARE_ENABLED:
        return

    MIDDLEWARE_HANDLED_UPDATES += 1
    update_id = update.update_id
    started_at = MIDDLEWARE_UPDATE_STARTS.pop(update_id, None) if update_id is not None else None
    if started_at is None:
        return

    elapsed = time.monotonic() - started_at
    if elapsed >= MIDDLEWARE_SLOW_UPDATE_SECONDS:
        effective_user = update.effective_user
        effective_chat = update.effective_chat
        logger.warning(
            "slow update kind=%s update_id=%s chat_id=%s user_id=%s elapsed=%.3fs",
            middleware_update_kind(update),
            update_id,
            effective_chat.id if effective_chat else None,
            effective_user.id if effective_user else None,
            elapsed,
        )
    elif MIDDLEWARE_LOG_UPDATES:
        logger.debug(
            "middleware complete kind=%s update_id=%s elapsed=%.3fs",
            middleware_update_kind(update),
            update_id,
            elapsed,
        )


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled exception while processing update", exc_info=context.error)


def build_application() -> Application:
    if LOCAL_PERSISTENCE_ENABLED:
        prepare_local_persistence_file(PERSISTENCE_FILE)
    persistence = ThreadedPicklePersistence(filepath=PERSISTENCE_FILE) if LOCAL_PERSISTENCE_ENABLED else None

    builder: ApplicationBuilder = (
        Application.builder()
        .token(BOT_TOKEN)
        .concurrent_updates(MAX_CONCURRENT_UPDATES)
        .connection_pool_size(TELEGRAM_CONNECTION_POOL_SIZE)
        .pool_timeout(TELEGRAM_POOL_TIMEOUT)
        .connect_timeout(10.0)
        .read_timeout(20.0)
        .write_timeout(20.0)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
    )

    if persistence is not None:
        builder = builder.persistence(persistence)

    app = builder.build()

    # Middleware group -100 runs before all command/callback/message handlers.
    # Middleware group 1000 runs after normal handlers for slow-update metrics.
    app.add_handler(TypeHandler(Update, bot_middleware_pre), group=-100)
    app.add_handler(TypeHandler(Update, bot_middleware_post), group=1000)

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("settings", settings_command))
    app.add_handler(CommandHandler("admins", admins_command))
    app.add_handler(CommandHandler("scanner", scanner_command))
    app.add_handler(CommandHandler("scanname", scanname_command))
    app.add_handler(CommandHandler("memory", memory_command))
    app.add_handler(CommandHandler("debug", debug_command))
    app.add_handler(CommandHandler("selftest", selftest_command))
    app.add_handler(CallbackQueryHandler(lang_callback, pattern=r"^lang_(en|km)$"))
    app.add_handler(CallbackQueryHandler(navigation_callback, pattern=r"^nav:(home|groups(?::\d+)?|help|about|feedback|language)$"))
    app.add_handler(CallbackQueryHandler(developer_dashboard_callback, pattern=r"^dev:(home|refresh|memory|feedback|hash(?::(?:toggle|size(?::\d+)?|limit(?::\d+)?))?|users(?::\d+)?|user:-?\d+|groups(?::\d+)?)$"))
    app.add_handler(CallbackQueryHandler(group_dashboard_callback, pattern=r"^grp:-?\d+$"))
    app.add_handler(CallbackQueryHandler(group_admin_panel_callback, pattern=r"^gap:-?\d+:(protection|scanner|incidents|risk|admins|admin_logs|clear_admin_logs|clear_admin_logs_yes|allowed|health|auto|clear_incidents|clear_incidents_yes|refresh)$"))
    app.add_handler(CallbackQueryHandler(group_settings_callback, pattern=r"^gset:-?\d+:(protection|strictness|silent)$"))
    app.add_handler(CallbackQueryHandler(format_manager_callback, pattern=r"^gfmt:-?\d+:(menu|add|edit|remove|clear|clear_yes)$"))
    app.add_handler(CallbackQueryHandler(delete_format_callback, pattern=r"^gfmtdel:-?\d+:[A-Za-z0-9_.+-]{1,16}$"))
    app.add_handler(CallbackQueryHandler(allowed_formats_callback, pattern=r"^gallow:-?\d+:(menu|add|edit|remove|clear|clear_yes)$"))
    app.add_handler(CallbackQueryHandler(delete_allowed_format_callback, pattern=r"^gallowdel:-?\d+:[A-Za-z0-9_.+-]{1,16}$"))
    app.add_handler(CallbackQueryHandler(trusted_hash_callback, pattern=r"^ghash:-?\d+:(menu|add|remove|clear|clear_yes)$"))
    app.add_handler(CallbackQueryHandler(delete_trusted_hash_callback, pattern=r"^ghashdel:-?\d+:[a-fA-F0-9]{12}$"))
    app.add_handler(CallbackQueryHandler(auto_actions_callback, pattern=r"^gauto:-?\d+:(off|warn|smart|ban)$"))
    app.add_handler(CallbackQueryHandler(check_perm_callback, pattern=r"^check_perm(?::-?\d+)?$"))
    app.add_handler(CallbackQueryHandler(action_callback, pattern=r"^act:(ban|warn|ignore|risk):.+$"))
    app.add_handler(ChatMemberHandler(my_chat_member_update, ChatMemberHandler.MY_CHAT_MEMBER))
    app.add_handler(MessageHandler(filters.StatusUpdate.MIGRATE, handle_chat_migration))
    app.add_handler(MessageHandler(filters.Document.ALL & filters.ChatType.PRIVATE, private_document_flow_handler))
    app.add_handler(MessageHandler(filters.Document.ALL & (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP), handle_document))
    app.add_handler(MessageHandler(filters.TEXT & filters.ChatType.PRIVATE, private_text_flow_handler))
    app.add_error_handler(error_handler)

    if app.job_queue:
        app.job_queue.run_repeating(clean_old_incidents, interval=3600, first=30, name="clean_old_incidents")
        app.job_queue.run_repeating(cleanup_runtime_caches, interval=600, first=600, name="cleanup_runtime_caches")
        if REDIS_ENABLED or SUPABASE_ENABLED:
            app.job_queue.run_repeating(periodic_memory_save, interval=60, first=60, name="periodic_memory_save")

        default_keep_awake = bool(WEBHOOK_BASE_URL and (RENDER_EXTERNAL_URL or BOT_MODE == "WEBHOOK"))
        if _env_bool("KEEP_AWAKE_ENABLED", default_keep_awake):
            app.job_queue.run_repeating(keep_awake, interval=KEEP_AWAKE_INTERVAL_SECONDS, first=30, name="keep_awake")
    else:
        logger.warning(
            "JobQueue is unavailable. Install python-telegram-bot with [job-queue] extras to enable cleanup/keep-awake jobs."
        )

    return app


def resolve_run_mode() -> str:
    if BOT_MODE == "WEBHOOK":
        return "WEBHOOK"
    if BOT_MODE == "POLLING":
        return "POLLING"
    return "WEBHOOK" if WEBHOOK_BASE_URL else "POLLING"



def ensure_main_event_loop() -> None:
    """Create a default asyncio event loop for PTB on Python 3.14+.

    python-telegram-bot's run_webhook/run_polling still calls
    asyncio.get_event_loop() internally. On Python 3.14, the default policy
    raises RuntimeError when no loop has been set, so Render deployments can
    crash before the webhook starts. We set one explicitly and let PTB own the
    loop lifecycle after that.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
        return

    if loop.is_closed():
        asyncio.set_event_loop(asyncio.new_event_loop())


def main() -> None:
    ensure_main_event_loop()

    app = build_application()
    mode = resolve_run_mode()

    if mode == "WEBHOOK":
        if not WEBHOOK_BASE_URL:
            raise RuntimeError("WEBHOOK mode requires WEBHOOK_URL or RENDER_EXTERNAL_URL.")
        webhook_url = f"{WEBHOOK_BASE_URL}/{WEBHOOK_URL_PATH}"
        logger.info(
            "Starting webhook mode on 0.0.0.0:%s path=/%s drop_pending_updates=%s",
            PORT,
            WEBHOOK_URL_PATH,
            DROP_PENDING_UPDATES,
        )
        if MINI_APP_API_ENABLED:
            run_webhook_with_mini_app_api(app, webhook_url)
        else:
            app.run_webhook(
                listen="0.0.0.0",
                port=PORT,
                url_path=WEBHOOK_URL_PATH,
                webhook_url=webhook_url,
                allowed_updates=ALLOWED_UPDATES,
                drop_pending_updates=DROP_PENDING_UPDATES,
            )
    else:
        logger.info("Starting polling mode drop_pending_updates=%s", DROP_PENDING_UPDATES)
        app.run_polling(allowed_updates=ALLOWED_UPDATES, drop_pending_updates=DROP_PENDING_UPDATES)


if __name__ == "__main__":
    main()
