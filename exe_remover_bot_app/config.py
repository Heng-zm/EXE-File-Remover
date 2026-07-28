from __future__ import annotations

import os
import re
import secrets
from typing import Iterable

from dotenv import load_dotenv


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


def _looks_like_placeholder(value: str) -> bool:
    lowered = str(value or "").strip().casefold()
    return not lowered or any(marker in lowered for marker in ("replace_with", "your_", "example", "change_me", "changeme"))


# Parsing is intentionally side-effect free. Strict validation runs from
# startup.py immediately before the Telegram application is constructed.
BOT_TOKEN = _env_str("BOT_TOKEN")
BOT_MODE = _env_str("BOT_MODE", "AUTO").upper()

PORT = _env_int("PORT", 8080, min_value=1, max_value=65535)
RENDER_EXTERNAL_URL = _env_str("RENDER_EXTERNAL_URL").rstrip("/")
WEBHOOK_BASE_URL = (_env_str("WEBHOOK_URL") or RENDER_EXTERNAL_URL).rstrip("/")
# Keep the webhook URL path secret separate from Telegram's secret-token header.
# Reusing one value leaks the header secret anywhere the route is exposed.
WEBHOOK_SECRET_TOKEN = _env_str("WEBHOOK_SECRET_TOKEN") or secrets.token_urlsafe(32)
WEBHOOK_PATH_SECRET = _env_str("WEBHOOK_PATH_SECRET") or secrets.token_urlsafe(24)
WEBHOOK_URL_PATH = _env_str("WEBHOOK_URL_PATH") or f"tg-webhook/{WEBHOOK_PATH_SECRET}"
PERSISTENCE_FILE = _env_str("PERSISTENCE_FILE", "exe_bot_data.pickle")
# Pickle can execute code during deserialization. Keep it opt-in and prefer
# signed Redis JSON or Supabase JSONB for production persistence.
LOCAL_PERSISTENCE_ENABLED = _env_bool("LOCAL_PERSISTENCE_ENABLED", False)

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

# Callback UX and duplicate-tap protection. Telegram clients can submit the same
# destructive/toggle action more than once when users tap quickly on slow networks.
CALLBACK_DEDUP_WINDOW_SECONDS = _env_float("CALLBACK_DEDUP_WINDOW_SECONDS", 1.5, min_value=0.0)
CALLBACK_RECENT_MAX_ITEMS = _env_int("CALLBACK_RECENT_MAX_ITEMS", 10_000, min_value=100, max_value=100_000)

# v3.5 persistence retry policy. Retries use exponential backoff with jitter.
PERSISTENCE_RETRY_ATTEMPTS = _env_int("PERSISTENCE_RETRY_ATTEMPTS", 4, min_value=1, max_value=10)
PERSISTENCE_RETRY_BASE_DELAY_SECONDS = _env_float("PERSISTENCE_RETRY_BASE_DELAY_SECONDS", 0.35, min_value=0.0)
PERSISTENCE_RETRY_MAX_DELAY_SECONDS = _env_float("PERSISTENCE_RETRY_MAX_DELAY_SECONDS", 5.0, min_value=0.1)
PERSISTENCE_RETRY_JITTER_RATIO = _env_float("PERSISTENCE_RETRY_JITTER_RATIO", 0.20, min_value=0.0)

# Coordinated workflow retention and recovery. These stores are bounded to keep
# persistence snapshots and Mini App responses predictable under heavy traffic.
WORKFLOW_HISTORY_MAX_ITEMS = _env_int("WORKFLOW_HISTORY_MAX_ITEMS", 500, min_value=50, max_value=5000)
WORKFLOW_EVENT_MAX_ITEMS = _env_int("WORKFLOW_EVENT_MAX_ITEMS", 24, min_value=4, max_value=100)
WORKFLOW_STALE_SECONDS = _env_int("WORKFLOW_STALE_SECONDS", 900, min_value=60, max_value=86400)
STARTUP_VALIDATION_STRICT = _env_bool("STARTUP_VALIDATION_STRICT", True)



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
# Unknown/generic files that are too large to inspect are blocked by default.
# This closes the renamed-executable gap without blocking files with a trusted hash.
BLOCK_UNSCANNABLE_GENERIC_FILES = _env_bool("BLOCK_UNSCANNABLE_GENERIC_FILES", True)
GENERIC_BINARY_MIME_TYPES = frozenset({"", "application/octet-stream", "binary/octet-stream", "application/binary"})
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
# Prevent blank screens when a frontend is opened outside Telegram or before
# Telegram injects WebApp.initData. Authenticated routes still protect private
# data, but /api/bootstrap and /api/session can return a safe public shell
# payload so React can render an "Open in Telegram" / retry state instead
# of crashing on a 401 response.
MINI_APP_PUBLIC_BOOTSTRAP_ON_MISSING_INITDATA = _env_bool("MINI_APP_PUBLIC_BOOTSTRAP_ON_MISSING_INITDATA", True)
MINI_APP_FRONTEND_DEBUG_ENABLED = _env_bool("MINI_APP_FRONTEND_DEBUG_ENABLED", False)
# Production privacy defaults. Public OpenAPI docs and the full route catalog
# reveal internal administration surfaces even when the routes are protected.
MINI_APP_PUBLIC_DOCS_ENABLED = _env_bool("MINI_APP_PUBLIC_DOCS_ENABLED", False)
MINI_APP_PUBLIC_ROUTE_CATALOG_ENABLED = _env_bool("MINI_APP_PUBLIC_ROUTE_CATALOG_ENABLED", False)
MINI_APP_EXPOSE_BOT_ID_PUBLICLY = _env_bool("MINI_APP_EXPOSE_BOT_ID_PUBLICLY", False)
MINI_APP_SECURITY_HEADERS_ENABLED = _env_bool("MINI_APP_SECURITY_HEADERS_ENABLED", True)

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
SERVER_LOG_AUTH_QUERY_ENABLED = _env_bool("SERVER_LOG_AUTH_QUERY_ENABLED", False)
SERVER_LOG_PUBLIC_ACCESS = _env_bool("SERVER_LOG_PUBLIC_ACCESS", False)
# Successful reads of /api/server/log can spam the in-memory log when the
# frontend polls every few seconds. Keep error/DELETE/slow log events, but skip
# normal successful reads by default for cleaner logs and lower overhead.
SERVER_LOG_CAPTURE_LOG_ENDPOINT = _env_bool("SERVER_LOG_CAPTURE_LOG_ENDPOINT", False)
# Health-check HEAD requests should be accepted and not counted as API errors.
SERVER_LOG_CAPTURE_HEALTHCHECKS = _env_bool("SERVER_LOG_CAPTURE_HEALTHCHECKS", False)
# Never store raw visitor IP addresses by default. A short keyed fingerprint is
# enough to correlate abuse without retaining directly identifying network data.
SERVER_LOG_STORE_CLIENT_IP = _env_bool("SERVER_LOG_STORE_CLIENT_IP", False)
SERVER_LOG_CLIENT_FINGERPRINT_SECRET = (
    _env_str("SERVER_LOG_CLIENT_FINGERPRINT_SECRET")
    or REDIS_STATE_SIGNING_SECRET
    or WEBHOOK_PATH_SECRET
)
SERVER_LOG_REDACT_USER_AGENT = _env_bool("SERVER_LOG_REDACT_USER_AGENT", True)

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
PROFESSIONAL_UI_VERSION = _env_str("PROFESSIONAL_UI_VERSION", "v3.5.2") or "v3.5.2"
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


# Export helpers as well as configuration constants for the runtime module.
__all__ = [
    name for name in globals()
    if (name.isupper() or name in {
        "_env_str", "_env_int", "_env_float", "_env_bool", "_env_csv",
        "_normalize_extension", "_env_extensions", "_looks_like_placeholder",
    })
]
