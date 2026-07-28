

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
from html import escape as html_escape, unescape as html_unescape
from typing import Any, Generic, Iterable, TypeVar
from urllib.parse import parse_qsl

import httpx
from dotenv import load_dotenv

try:
    from fastapi import FastAPI, HTTPException, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
except ImportError:  # Mini App API is optional; webhook/polling bot still works without it.
    FastAPI = None  # type: ignore[assignment]
    HTTPException = None  # type: ignore[assignment]
    Request = Any  # type: ignore[assignment,misc]
    Response = Any  # type: ignore[assignment,misc]
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

from .config import *
from .callback_ux import claim_callback_action as claim_callback_action_once
from .diagnostics import (
    _server_log_safe_text,
    _server_log_safe_value,
    clear_server_logs,
    configure_runtime_provider,
    increment_request_total,
    install_server_log_handler,
    privacy_safe_client_id,
    process_status_snapshot,
    server_log_counters,
    server_log_event,
    server_log_snapshot,
)
from .policies import (
    ARCHIVE_POLICIES,
    NOTIFICATION_POLICIES,
    POLICY_DEFAULTS,
    SCANNER_PRESET_IDS,
    UNSCANNABLE_POLICIES,
    apply_scanner_preset,
    detect_scanner_preset,
    is_archive_name,
    normalize_policy_settings,
    scanner_presets_catalog,
)
from .retry import RetryPolicy, retry_async
from .scanner import (
    FileScanResult,
    compact_scan_name,
    describe_scan_reason,
    filename_suffixes,
    normalize_filename,
    scan_file_bytes,
    scan_filename_only,
    scanner_selftest_results,
    visible_controls_removed,
)
from .schema import (
    CURRENT_SCHEMA_VERSION,
    LOCAL_STATE_META_KEY,
    PERSISTED_BOT_DATA_KEYS,
    PERSISTED_BOT_DATA_TYPES,
    SchemaMigrationError,
    build_snapshot_meta,
    is_newer_snapshot,
    migrate_state_payload,
    payload_revision,
    payload_saved_at_ms,
)
from .startup import validate_startup_config
from .translations import TEXTS

from .workflow import (
    advance_workflow,
    begin_workflow,
    complete_workflow,
    fail_workflow,
    moderation_notification_targets,
    recover_interrupted_workflows,
    reconcile_group_state,
    select_auto_action,
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
install_server_log_handler()

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


# Process-local middleware metrics. Do not put these in bot_data, because
# bot_data is persisted/deep-copied and high-churn counters cause needless I/O.
MIDDLEWARE_RATE_BUCKETS: dict[int, list[float]] = {}
MIDDLEWARE_RATE_LIMIT_NOTICES: dict[int, float] = {}
MIDDLEWARE_UPDATE_STARTS: dict[int, float] = {}
MIDDLEWARE_HANDLED_UPDATES = 0
MIDDLEWARE_DROPPED_UPDATES = 0
MIDDLEWARE_LAST_PRUNE_MONOTONIC = 0.0


configure_runtime_provider(
    lambda: {
        "storage_backend": storage_backend_label() if "storage_backend_label" in globals() else "initializing",
        "redis": "connected" if REDIS_AVAILABLE else ("configured_offline" if REDIS_ENABLED else "disabled"),
        "supabase": "connected" if SUPABASE_AVAILABLE else ("configured_offline" if SUPABASE_ENABLED else "disabled"),
    }
)


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
class SendMessageResult:
    ok: bool
    message_id: int | None = None
    error: str = ""
    error_type: str = ""
    permission_error: bool = False
    retryable: bool = False


# Server diagnostics moved to diagnostics.py


# Translation catalogs moved to translations.py
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
    **POLICY_DEFAULTS,
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

LOADED_STATE_SAVED_AT_MS = 0
LOADED_STATE_REVISION = 0
STATE_EXPORT_REVISION = 0



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
    """Store durable bot data with a versioned, monotonic snapshot envelope."""
    global STATE_EXPORT_REVISION
    exported: dict[str, Any] = {}
    for key in PERSISTED_BOT_DATA_KEYS:
        value = bot_data.get(key)
        if value is not None:
            exported[key] = copy.deepcopy(value)
    saved_at_ms = now_ms()
    local_meta = bot_data.get(LOCAL_STATE_META_KEY)
    local_revision = payload_revision({"_meta": local_meta}) if isinstance(local_meta, dict) else 0
    exported["_meta"] = build_snapshot_meta(
        saved_at_ms=saved_at_ms,
        previous_revision=max(STATE_EXPORT_REVISION, LOADED_STATE_REVISION, local_revision),
        bot="exe_remover_bot",
    )
    bot_data[LOCAL_STATE_META_KEY] = copy.deepcopy(exported["_meta"])
    STATE_EXPORT_REVISION = int(exported["_meta"]["revision"])
    return exported


def merge_loaded_bot_data(bot_data: dict[str, Any], loaded: dict[str, Any]) -> bool:
    """Migrate and merge only a newer durable snapshot."""
    global LOADED_STATE_SAVED_AT_MS, LOADED_STATE_REVISION, STATE_EXPORT_REVISION
    try:
        migration = migrate_state_payload(loaded)
    except SchemaMigrationError:
        logger.exception("Persistence snapshot schema migration failed", exc_info=True)
        return False

    migrated = migration.payload
    incoming_saved_at = payload_saved_at_ms(migrated)
    incoming_revision = payload_revision(migrated)
    if not is_newer_snapshot(
        incoming_revision=incoming_revision,
        incoming_saved_at_ms=incoming_saved_at,
        current_revision=LOADED_STATE_REVISION,
        current_saved_at_ms=LOADED_STATE_SAVED_AT_MS,
    ):
        logger.info(
            "Skipped stale persistence snapshot revision=%s saved_at_ms=%s current_revision=%s current_saved_at_ms=%s",
            incoming_revision, incoming_saved_at, LOADED_STATE_REVISION, LOADED_STATE_SAVED_AT_MS,
        )
        return False

    changed = False
    for key in PERSISTED_BOT_DATA_KEYS:
        value = migrated.get(key)
        expected_type = PERSISTED_BOT_DATA_TYPES.get(key, dict)
        if isinstance(value, expected_type):
            bot_data[key] = copy.deepcopy(value)
            changed = True

    if changed:
        bot_data[LOCAL_STATE_META_KEY] = copy.deepcopy(migrated.get("_meta", {}))
        LOADED_STATE_SAVED_AT_MS = incoming_saved_at
        LOADED_STATE_REVISION = incoming_revision
        STATE_EXPORT_REVISION = max(STATE_EXPORT_REVISION, incoming_revision)
        if migration.applied:
            logger.info("Applied persistence migrations: %s", "; ".join(migration.applied))
    return changed


def migrate_local_bot_data_in_place(bot_data: dict[str, Any]) -> bool:
    """Apply schema migrations to PTB local bot_data before remote hydration."""
    snapshot: dict[str, Any] = {}
    for key in PERSISTED_BOT_DATA_KEYS:
        if key in bot_data:
            snapshot[key] = copy.deepcopy(bot_data.get(key))
    local_meta = bot_data.get(LOCAL_STATE_META_KEY)
    if isinstance(local_meta, dict):
        snapshot["_meta"] = copy.deepcopy(local_meta)
    return merge_loaded_bot_data(bot_data, snapshot)




def persistence_retry_policy() -> RetryPolicy:
    return RetryPolicy(
        attempts=PERSISTENCE_RETRY_ATTEMPTS,
        base_delay_seconds=PERSISTENCE_RETRY_BASE_DELAY_SECONDS,
        max_delay_seconds=PERSISTENCE_RETRY_MAX_DELAY_SECONDS,
        jitter_ratio=PERSISTENCE_RETRY_JITTER_RATIO,
    )


def _persistence_retry_log(operation: str):
    def callback(attempt: int, delay: float, exc: BaseException) -> None:
        logger.warning(
            "%s failed on attempt %s; retrying in %.2fs: %s",
            operation, attempt, delay, exc.__class__.__name__,
        )
    return callback


def _supabase_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        status = int(exc.response.status_code) if exc.response is not None else 0
        return status in {408, 409, 425, 429} or status >= 500
    return isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, OSError))


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
        expected_type = PERSISTED_BOT_DATA_TYPES.get(key, dict)
        if key not in bot_data or not isinstance(bot_data.get(key), expected_type):
            bot_data[key] = [] if expected_type is list else {}

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
        await retry_async(
            lambda: REDIS_CLIENT.ping(),
            policy=persistence_retry_policy(),
            on_retry=_persistence_retry_log("Redis ping"),
        )
        REDIS_AVAILABLE = True
        logger.info("Redis memory connected. key=%s", REDIS_STATE_KEY)
    except Exception as exc:
        REDIS_AVAILABLE = False
        REDIS_CLIENT = None
        logger.exception("Redis memory unavailable; local persistence fallback is active", exc_info=True)
        return

    try:
        raw = await retry_async(
            lambda: REDIS_CLIENT.get(REDIS_STATE_KEY),
            policy=persistence_retry_policy(),
            on_retry=_persistence_retry_log("Redis state load"),
        )
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
            await retry_async(
                lambda: REDIS_CLIENT.set(REDIS_STATE_KEY, encoded),
                policy=persistence_retry_policy(),
                on_retry=_persistence_retry_log("Redis state save"),
            )
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
        async def load_state_row() -> httpx.Response:
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
            return response

        response = await retry_async(
            load_state_row,
            policy=persistence_retry_policy(),
            is_retryable=_supabase_retryable,
            on_retry=_persistence_retry_log("Supabase state load"),
        )
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
        async def upsert_state_row() -> httpx.Response:
            response = await SUPABASE_CLIENT.post(
                _supabase_rest_url(table),
                headers=_supabase_headers(prefer="resolution=merge-duplicates,return=minimal"),
                params={"on_conflict": "state_key"},
                json=row,
            )
            response.raise_for_status()
            return response

        await retry_async(
            upsert_state_row,
            policy=persistence_retry_policy(),
            is_retryable=_supabase_retryable,
            on_retry=_persistence_retry_log("Supabase state save"),
        )
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


# Pure scanner engine moved to scanner.py
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
        if (
            BLOCK_UNSCANNABLE_GENERIC_FILES
            and not result.blocked
            and file_size > 0
            and mime_type in GENERIC_BINARY_MIME_TYPES
            and (
                file_size > TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES
                or SCANNER_MAX_DOWNLOAD_BYTES <= 0
                or file_size > SCANNER_MAX_DOWNLOAD_BYTES
            )
        ):
            return FileScanResult(
                True,
                "unscannable_generic_file",
                "generic binary file is too large for safe content inspection",
                (f"size:{file_size}", f"scan_limit:{SCANNER_MAX_DOWNLOAD_BYTES}"),
                result.file_name,
                result.mime_type,
                result.matched_extension,
            )
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


async def safe_answer_callback(query: Any, text: str | None = None, *, show_alert: bool = False) -> bool:
    """Acknowledge a callback immediately and never block the main action."""
    if query is None:
        return False
    callback_text = html_unescape(re.sub(r"<[^>]+>", "", str(text or ""))).strip()
    callback_text = callback_text[:200] or None
    try:
        await query.answer(text=callback_text, show_alert=show_alert)
        return True
    except RetryAfter as exc:
        delay = float(getattr(exc, "retry_after", 0) or 0)
        logger.warning("Callback acknowledgement rate-limited retry_after=%.2fs", delay)
    except BadRequest as exc:
        lowered = str(exc).casefold()
        if "query is too old" not in lowered and "query_id_invalid" not in lowered:
            logger.debug("callback acknowledgement skipped: %s", _server_log_safe_text(exc, max_chars=180))
    except TelegramError:
        logger.debug("callback acknowledgement failed", exc_info=True)
    except Exception:
        logger.exception("Unexpected callback acknowledgement failure", exc_info=True)
    return False


async def callback_ack(
    context: ContextTypes.DEFAULT_TYPE,
    query: Any,
    user_id: int,
    key: str = "callback_processing",
    *,
    show_alert: bool = False,
) -> bool:
    return await safe_answer_callback(query, text=tr(context.bot_data, int(user_id), key), show_alert=show_alert)


async def callback_mutation_guard(
    context: ContextTypes.DEFAULT_TYPE,
    query: Any,
    user_id: int,
    *,
    ack_key: str = "callback_saving",
) -> bool:
    if not await claim_callback_action_once(
        query,
        cooldown_seconds=CALLBACK_DEDUP_WINDOW_SECONDS,
        max_items=CALLBACK_RECENT_MAX_ITEMS,
    ):
        await callback_ack(context, query, user_id, "callback_already_processing", show_alert=False)
        return False
    await callback_ack(context, query, user_id, ack_key)
    return True


async def callback_invalid(
    context: ContextTypes.DEFAULT_TYPE,
    query: Any,
    user_id: int,
    *,
    edit_message: bool = False,
    answer_query: bool = True,
) -> None:
    if answer_query:
        await callback_ack(context, query, user_id, "callback_invalid", show_alert=True)
    if edit_message:
        await safe_edit_query(
            query,
            f"⚠️ {tr(context.bot_data, int(user_id), 'callback_invalid')}\n\n"
            f"{tr(context.bot_data, int(user_id), 'callback_retry_hint')}",
            reply_markup=dashboard_back_home_keyboard(context.bot_data, int(user_id)),
        )


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


async def safe_edit_query(query: Any, text: str, *, reply_markup: InlineKeyboardMarkup | None = None) -> bool:
    for attempt in (1, 2):
        try:
            await query.edit_message_text(
                text=text,
                parse_mode=ParseMode.HTML,
                reply_markup=reply_markup,
                disable_web_page_preview=True,
            )
            return True
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="edit_message_text"):
                continue
            return False
        except BadRequest as exc:
            lowered = str(exc).casefold()
            if "message is not modified" in lowered:
                return True
            if "message to edit not found" in lowered or "message can't be edited" in lowered:
                logger.info("callback panel is stale and cannot be edited")
            else:
                logger.exception("edit_message_text failed", exc_info=True)
            return False
        except TelegramError:
            logger.exception("edit_message_text failed", exc_info=True)
            return False
        except Exception:
            logger.exception("Unexpected edit_message_text failure", exc_info=True)
            return False
    return False


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
    normalize_policy_settings(settings)
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
        # Cached authorization is accepted only while explicitly fresh above.
        return False

    if is_chat_api_suppressed(context.bot_data, chat_id):
        return False

    member = None
    for attempt in (1, 2):
        try:
            member = await context.bot.get_chat_member(chat_id, user_id)
            break
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="get_chat_member:user"):
                continue
            logger.exception("Admin live membership check hit RetryAfter chat_id=%s user_id=%s", chat_id, user_id, exc_info=True)
            return False
        except (TimedOut, BadRequest, Forbidden, TelegramError) as exc:
            if _is_lost_chat_access_error(exc):
                logger.info("Admin live membership check skipped; bot lost access to chat_id=%s user_id=%s: %s", chat_id, user_id, exc)
                await mark_chat_inaccessible(context, chat_id, reason="admin_membership_lost_access", purge=True)
            else:
                logger.exception("Admin live membership check failed chat_id=%s user_id=%s", chat_id, user_id, exc_info=True)
            return False
        except Exception:
            logger.exception("Unexpected admin live membership check failure chat_id=%s user_id=%s", chat_id, user_id, exc_info=True)
            return False
    if member is None:
        return False

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
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_add_group"), url=add_url)],
        [
            InlineKeyboardButton(tr(context.bot_data, user_id, "btn_help"), callback_data="nav:help"),
            InlineKeyboardButton(tr(context.bot_data, user_id, "btn_about"), callback_data="nav:about"),
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
        await safe_answer_callback(query, text=tr(bot_data, user_id, "callback_security_blocked"), show_alert=True)
    except TelegramError as exc:
        logger.exception("Could not answer private-only callback warning", exc_info=True)


async def render_home(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    groups = get_groups(context.bot_data, int(user_id))
    title_key = "home_title" if groups else "first_time_home_title"
    text = tr(context.bot_data, user_id, title_key)
    if groups:
        protected = 0
        open_incidents = 0
        async with BOT_DATA_LOCK:
            group_state = context.bot_data.get("group_state", {})
            for chat_id in groups:
                state = group_state.get(str(int(chat_id)), {}) if isinstance(group_state, dict) else {}
                settings = state.get("settings", {}) if isinstance(state, dict) else {}
                if not isinstance(settings, dict) or settings.get("protection_enabled", True):
                    protected += 1
            incidents = context.bot_data.get("incidents", {})
            if isinstance(incidents, dict):
                linked_ids = {int(chat_id) for chat_id in groups}
                open_incidents = sum(
                    1
                    for item in incidents.values()
                    if isinstance(item, dict)
                    and not item.get("done")
                    and str(item.get("chat_id", "")).lstrip("-").isdigit()
                    and int(item.get("chat_id")) in linked_ids
                )
        text += tr(
            context.bot_data,
            user_id,
            "dashboard_summary",
            groups=len(groups),
            protected=protected,
            incidents=open_incidents,
            storage=h(storage_backend_label()),
        )
    await send_or_edit_panel(update, text, await dashboard_home_keyboard(context, user_id))


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
    await callback_ack(context, query, user_id, "callback_opening")
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
        logger.warning("Developer dashboard denied user_id=%s", user_id)
        return
    data = query.data or "dev:home"
    parts = data.split(":")
    action = parts[1] if len(parts) > 1 else "home"
    sub_action = parts[2] if len(parts) > 2 else ""
    if action == "hash" and sub_action in {"toggle", "size", "limit"}:
        if not await callback_mutation_guard(context, query, user_id):
            return
    else:
        await callback_ack(context, query, user_id, "callback_loading")

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
    await callback_ack(context, query, user_id, "callback_loading")
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
    if not await callback_mutation_guard(context, query, user_id):
        return
    data = query.data or ""
    parts = data.split(":", 2)
    if len(parts) != 3:
        await callback_invalid(context, query, user_id, edit_message=True, answer_query=False)
        return
    _, chat_id_raw, field = parts
    try:
        chat_id = int(chat_id_raw)
    except ValueError:
        await callback_invalid(context, query, user_id, edit_message=True, answer_query=False)
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
    if not await callback_mutation_guard(context, query, user_id):
        return
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
    if not await callback_mutation_guard(context, query, user_id):
        return
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
    if not await callback_mutation_guard(context, query, user_id):
        return
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
    if not await callback_mutation_guard(context, query, user_id):
        return
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
    if not await callback_mutation_guard(context, query, user_id, ack_key="callback_loading"):
        return
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
    if not await callback_mutation_guard(context, query, user_id):
        return
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
    if not await callback_mutation_guard(context, query, user_id):
        return
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
    if not await callback_mutation_guard(context, query, user_id):
        return
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



def apply_group_scan_policy(
    bot_data: dict[str, Any],
    chat_id: int,
    scan: FileScanResult,
    *,
    file_size: int = 0,
) -> FileScanResult:
    """Apply group-specific v3.5 policy after the shared scanner result.

    Core executable detections always win. Presets and custom policies can make
    a group stricter, but they cannot whitelist a dangerous executable except
    through the existing exact SHA256 trusted-file workflow.
    """
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

    max_file_size = int(settings.get("max_file_size_bytes") or 0)
    if file_size > 0 and max_file_size > 0 and file_size > max_file_size:
        return replace(
            scan,
            blocked=True,
            reason_code="group_max_file_size",
            reason_display=f"file exceeds group limit of {max_file_size} bytes",
            details=tuple([*scan.details, f"size:{file_size}", f"group_limit:{max_file_size}"]),
        )

    archive_policy = str(settings.get("archive_policy") or "scan")
    archive_name = is_archive_name(scan.file_name, ARCHIVE_EXTENSIONS)
    if archive_name and archive_policy == "block":
        return replace(
            scan,
            blocked=True,
            reason_code="group_archive_blocked",
            reason_display="archives are blocked by this group policy",
            matched_extension=last_ext or matched_ext,
        )

    if scan.reason_code in {"unscannable_generic_file", "scanner_error"} and settings.get("unscannable_policy") == "allow":
        scan = replace(scan, blocked=False, reason_code="group_unscannable_allowed", reason_display="unscannable file allowed by group policy")

    custom_blocked = set(settings.get("custom_blocked_extensions", []))
    custom_match = last_ext if last_ext in custom_blocked else next((ext for ext in suffixes if ext in custom_blocked), "")
    if custom_match:
        # Allowed formats bypass custom delete formats only. They never override
        # the core executable scanner or a dangerous archive member.
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

    if settings.get("allowed_only", False) and not allowed_match and not scan.blocked:
        return replace(
            scan,
            blocked=True,
            reason_code="group_allowlist_only",
            reason_display="this group allows only approved file formats",
            matched_extension=last_ext or matched_ext,
        )

    strictness = str(settings.get("strictness", "standard"))
    if strictness == "standard" and scan.blocked:
        # Standard mode remains calm: block .exe, renamed PE files, and archives
        # containing .exe, while allowing lower-risk script/archive detections.
        if matched_ext in BLOCKED_EXTENSIONS or scan.reason_code in {"pe_magic_header", "archive_dangerous_member"}:
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
) -> dict[str, Any]:
    """Notify eligible administrators and return one shared delivery report."""
    try:
        admin_ids = await get_chat_admin_ids_cached(context, chat_id, allow_api=True)
    except Exception:
        logger.exception("Admin lookup failed while notifying chat_id=%s", chat_id, exc_info=True)
        admin_ids = []
    if not admin_ids:
        return {"requested": 0, "delivered": 0, "failed": 0, "admin_ids": []}

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
    failures = 0
    for result in results:
        if isinstance(result, Exception):
            failures += 1
            logger.error("Admin alert task failed: %r", result, exc_info=(type(result), result, result.__traceback__))
        elif result:
            admin_id, message_id = result
            delivered[str(admin_id)] = int(message_id)
        else:
            failures += 1

    async with BOT_DATA_LOCK:
        incident = context.bot_data.setdefault("incidents", {}).get(ikey)
        if isinstance(incident, dict):
            incident.setdefault("alert_messages", {}).update(delivered)
            incident["alerted_admins"] = list(admin_ids)
            incident["alert_delivered_count"] = len(delivered)
            incident["alert_failed_count"] = failures
            await persist_context_memory(context, reason="admin_alert_messages", force=True, caller_holds_lock=True)

    return {
        "requested": len(admin_ids),
        "delivered": len(delivered),
        "failed": failures,
        "admin_ids": list(admin_ids),
    }



async def maybe_apply_auto_action(
    context: ContextTypes.DEFAULT_TYPE,
    *,
    chat_id: int,
    sender_id: int,
    sender_name: str,
    ikey: str,
) -> dict[str, Any]:
    """Apply the shared escalation plan and return its normalized result."""
    action = "none"
    result = "not-run"
    try:
        async with BOT_DATA_LOCK:
            settings = dict(get_group_settings(context.bot_data, chat_id))
            incidents = context.bot_data.get("incidents", {}) if isinstance(context.bot_data.get("incidents", {}), dict) else {}
            user_incident_count = sum(
                1
                for item in incidents.values()
                if isinstance(item, dict)
                and str(item.get("chat_id")) == str(int(chat_id))
                and str(item.get("sender_id")) == str(int(sender_id))
            )
            mute_minutes = int(settings.get("auto_mute_minutes", 60))
            action = select_auto_action(settings, incident_count=user_incident_count)

        if action == "none":
            result = "disabled"
        elif action == "warn":
            mention = user_link(sender_id, sender_name)
            lang = get_group_lang(context.bot_data, chat_id)
            send_result = await safe_send_message_result(
                context,
                chat_id,
                TEXTS[lang]["warn_in_group"].format(user=mention),
                operation="auto_warn",
            )
            result = "warned" if send_result.ok else f"warn-failed:{send_result.error_type or 'send_failed'}"
        elif action == "mute":
            perms = await get_bot_member_cached(context, chat_id, force=True, allow_api=True)
            if not has_ban_permission(perms):
                result = "mute-failed:no-restrict-permission"
            else:
                await context.bot.restrict_chat_member(
                    chat_id,
                    sender_id,
                    permissions=ChatPermissions(can_send_messages=False),
                    until_date=datetime.now(timezone.utc) + timedelta(minutes=mute_minutes),
                )
                result = f"muted:{mute_minutes}m"
        elif action == "ban":
            perms = await get_bot_member_cached(context, chat_id, force=True, allow_api=True)
            if not has_ban_permission(perms):
                result = "ban-failed:no-ban-permission"
            else:
                await context.bot.ban_chat_member(chat_id, sender_id)
                result = "banned"

        async with BOT_DATA_LOCK:
            incident = context.bot_data.setdefault("incidents", {}).get(ikey)
            if isinstance(incident, dict):
                incident["auto_action"] = action
                incident["auto_action_result"] = result
                incident["auto_action_count"] = user_incident_count
                incident["auto_action_at_ms"] = now_ms()
                await persist_context_memory(context, reason="auto_action_applied", force=True, caller_holds_lock=True)
        return {"action": action, "result": result, "incident_count": user_incident_count}
    except Exception as exc:
        logger.exception("Auto action failed chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
        return {"action": action, "result": f"failed:{exc.__class__.__name__}", "incident_count": 0}



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
    """Remove incidents using each group's v3.5 retention policy."""
    current_ms = now_ms()
    stale_keys: list[str] = []

    async with BOT_DATA_LOCK:
        incidents = context.bot_data.setdefault("incidents", {})
        if not isinstance(incidents, dict) or not incidents:
            return
        for ikey, incident in list(incidents.items()):
            if not isinstance(incident, dict):
                stale_keys.append(str(ikey))
                continue
            chat_id = int(incident.get("chat_id") or 0)
            retention_days = int(get_group_settings(context.bot_data, chat_id).get("incident_retention_days", 30)) if chat_id else 30
            cutoff = current_ms - max(1, retention_days) * 86_400_000
            ts = incident_timestamp_ms(str(ikey))
            created_at = ts if ts is not None else int(incident.get("created_at_ms", 0) or 0)
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
        logger.info("Cleaned %d stale incident(s) using group retention policies.", len(stale_keys))


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
    user_id = int(query.from_user.id)
    if not await callback_mutation_guard(context, query, user_id):
        return

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

    if not await callback_mutation_guard(context, query, user_id, ack_key="callback_refreshing"):
        return

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

    admin_id = int(query.from_user.id)
    data = str(query.data or "")
    parts = data.split(":", 2)
    if len(parts) != 3:
        await callback_invalid(context, query, admin_id, edit_message=True)
        return
    _, action, token_or_ikey = parts
    if action not in {"ban", "warn", "ignore", "risk"} or not token_or_ikey:
        await callback_invalid(context, query, admin_id, edit_message=True)
        return

    ack_key = "callback_loading" if action == "risk" else "callback_action_processing"
    if not await callback_mutation_guard(context, query, admin_id, ack_key=ack_key):
        return

    ikey = resolve_incident_action_key(context.bot_data, token_or_ikey)
    lock = await get_incident_lock(ikey)
    async with lock:
        async with BOT_DATA_LOCK:
            incidents = context.bot_data.setdefault("incidents", {})
            incident = incidents.get(ikey)
            if not isinstance(incident, dict):
                await safe_edit_query(
                    query,
                    f"⚠️ {tr(context.bot_data, admin_id, 'action_expired')}\n\n"
                    f"{tr(context.bot_data, admin_id, 'callback_retry_hint')}",
                    reply_markup=dashboard_back_home_keyboard(context.bot_data, admin_id),
                )
                return
            if incident.get("done") and action != "risk":
                final_text = format_incident_alert_for_admin(context.bot_data, admin_id, incident)
                final_text += f"\n\n{tr(context.bot_data, admin_id, 'action_done')}"
                await safe_edit_query(query, final_text)
                return
            chat_id = int(incident["chat_id"])
            sender_id = int(incident.get("sender_id", 0))
            sender_name_raw = str(incident.get("sender_name") or "Unknown")

        if not await is_user_admin_in_group(context, chat_id, admin_id, allow_api=True):
            await safe_edit_query(
                query,
                f"{tr(context.bot_data, admin_id, 'action_not_admin')}\n\n"
                f"{tr(context.bot_data, admin_id, 'callback_retry_hint')}",
                reply_markup=dashboard_back_home_keyboard(context.bot_data, admin_id),
            )
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
                    reference = secrets.token_hex(4)
                    logger.exception("Risk profile render failed reference=%s admin_id=%s", reference, admin_id, exc_info=True)
                    profile_text = (
                        f"❌ {tr(context.bot_data, admin_id, 'callback_failed_alert')}\n"
                        f"{tr(context.bot_data, admin_id, 'error_reference', reference=reference)}"
                    )
                keyboard = action_keyboard(context.bot_data, admin_id, ikey) if not incident.get("done") else None
            await safe_edit_query(query, profile_text, reply_markup=keyboard)
            return

        result_msg = ""
        action_success = False
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
                action_success = True
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
                action_success = True
                result_msg = tr(context.bot_data, admin_id, "action_warn_ok", name=sender_name)
            except (TimedOut, BadRequest, Forbidden, TelegramError):
                logger.exception("Warn failed chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
                result_msg = tr(context.bot_data, admin_id, "action_warn_fail")
            except Exception:
                logger.exception("Unexpected warn failure chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
                result_msg = tr(context.bot_data, admin_id, "action_warn_fail")
        else:
            action_success = True
            result_msg = tr(context.bot_data, admin_id, "action_ignore_ok")

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
            _record_admin_action_log_locked(
                context.bot_data,
                chat_id=chat_id,
                admin_id=admin_id,
                admin_name=query.from_user.full_name,
                action=f"incident {action}",
                target_id=sender_id,
                target_name=sender_name_raw,
                result="success" if action_success else "failed",
            )
            await persist_context_memory(context, reason="incident_action", force=True, caller_holds_lock=True)
            final_text = format_incident_alert_for_admin(context.bot_data, admin_id, incident)

        if result_msg:
            final_text += f"\n\n{result_msg}"
        retry_keyboard = None if action_success else action_keyboard(context.bot_data, admin_id, ikey)
        await safe_edit_query(query, final_text, reply_markup=retry_keyboard)

        if action_success:
            clicked_message_id = int(query.message.message_id) if query.message else None
            await sync_handled_alert_messages(
                context,
                incident,
                exclude_admin_id=admin_id,
                exclude_message_id=clicked_message_id,
            )

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
    """Run one coordinated moderation workflow for every group document."""
    message = update.effective_message
    chat = update.effective_chat
    sender = message.from_user if message else None
    sender_id = int(sender.id) if sender else 0
    user_id = update.effective_user.id if update.effective_user else None
    if not message or not chat or not message.document or not is_group_chat(chat.type):
        return

    document = message.document
    file_name_meta = normalize_filename(getattr(document, "file_name", None))
    mime_type_meta = str(getattr(document, "mime_type", "") or "")
    file_size = int(getattr(document, "file_size", 0) or 0)
    workflow_id = ""

    async def workflow_advance(stage: str, detail: str = "", data: dict[str, Any] | None = None) -> None:
        if not workflow_id:
            return
        async with BOT_DATA_LOCK:
            advance_workflow(context.bot_data, workflow_id, stage=stage, at_ms=now_ms(), detail=detail, data=data)

    async def workflow_complete(outcome: str, detail: str = "", data: dict[str, Any] | None = None, *, persist: bool = False) -> None:
        if not workflow_id:
            return
        async with BOT_DATA_LOCK:
            complete_workflow(context.bot_data, workflow_id, at_ms=now_ms(), outcome=outcome, detail=detail, data=data)
            if persist:
                await persist_context_memory(context, reason="workflow_completed", force=True, caller_holds_lock=True)

    async def workflow_fail(stage: str, error: str, data: dict[str, Any] | None = None) -> None:
        if not workflow_id:
            return
        async with BOT_DATA_LOCK:
            fail_workflow(context.bot_data, workflow_id, at_ms=now_ms(), stage=stage, error=error, data=data)
            await persist_context_memory(context, reason="workflow_failed", force=True, caller_holds_lock=True)

    async with BOT_DATA_LOCK:
        workflow = begin_workflow(
            context.bot_data,
            kind="file_moderation",
            chat_id=chat.id,
            actor_id=sender_id,
            source="telegram_group",
            subject_id=message.message_id,
            metadata={
                "file_name": file_name_meta,
                "mime_type": mime_type_meta,
                "file_size": file_size,
                "sender_name": sender.full_name if sender else "Unknown",
                "message_id": message.message_id,
            },
            at_ms=now_ms(),
        )
        workflow_id = str(workflow["id"])

    try:
        pre_scan = scan_filename_only(file_name_meta, mime_type_meta)
        async with BOT_DATA_LOCK:
            settings_snapshot = dict(get_group_settings(context.bot_data, chat.id))
            pre_policy_scan = apply_group_scan_policy(context.bot_data, chat.id, pre_scan, file_size=file_size)
        await workflow_advance(
            "policy_evaluated",
            pre_policy_scan.reason_code,
            {"blocked": pre_policy_scan.blocked, "reason": pre_policy_scan.reason_code},
        )

        if not settings_snapshot.get("protection_enabled", True):
            await workflow_complete("protection_disabled", "group protection is disabled")
            return

        # Admin bypass applies only to files that both core and group policy consider clean.
        strict_admins = bool(settings_snapshot.get("strict_enforcement_on_admins", STRICT_ENFORCEMENT_ON_ADMINS_DEFAULT))
        allow_admin_bypass = bool(ADMIN_BYPASS_ENABLED and sender_id and not strict_admins and not pre_policy_scan.blocked)
        if allow_admin_bypass:
            try:
                admin_ids = await get_chat_admin_ids_cached(context, chat.id, allow_api=True)
                if sender_id in admin_ids or sender_id in BOT_OWNER_IDS:
                    logger.info(
                        "Document workflow bypassed for verified admin workflow_id=%s chat_id=%s user_id=%s file_name=%r",
                        workflow_id,
                        chat.id,
                        sender_id,
                        file_name_meta,
                    )
                    await workflow_complete("admin_bypass", "verified administrator clean-file bypass")
                    return
            except Exception:
                logger.exception(
                    "Admin bypass check failed; scanner continues workflow_id=%s chat_id=%s user_id=%s",
                    workflow_id,
                    chat.id,
                    sender_id,
                    exc_info=True,
                )
        elif sender_id and pre_scan.blocked and (not strict_admins or sender_id in BOT_OWNER_IDS):
            logger.info(
                "Admin upload remains blocked workflow_id=%s chat_id=%s user_id=%s reason=%s",
                workflow_id,
                chat.id,
                sender_id,
                pre_scan.reason_code,
            )

        if file_size > TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES:
            logger.warning(
                "Incoming document exceeds Telegram download limit workflow_id=%s chat_id=%s user_id=%s file_name=%r size=%s",
                workflow_id,
                chat.id,
                sender_id,
                file_name_meta,
                file_size,
            )

        can_hash_for_trusted_policy = bool(
            trusted_hash_whitelist_enabled(context.bot_data)
            and file_size > 0
            and file_size <= trusted_hash_max_download_bytes(context.bot_data)
            and file_size <= TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES
        )
        if pre_policy_scan.blocked and not can_hash_for_trusted_policy:
            scan = pre_policy_scan
        else:
            scan = await scan_document(context, document, chat_id=chat.id)
            async with BOT_DATA_LOCK:
                scan = apply_group_scan_policy(context.bot_data, chat.id, scan, file_size=file_size)
        await workflow_advance(
            "scanned",
            scan.reason_code,
            {"blocked": scan.blocked, "reason": scan.reason_code, "sha256": scan.file_sha256},
        )

        if not scan.blocked:
            await workflow_complete("allowed", scan.reason_code, {"reason": scan.reason_code})
            return

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
            except (TimedOut, BadRequest, Forbidden, TelegramError) as exc:
                logger.exception(
                    "Could not delete blocked file workflow_id=%s chat_id=%s message_id=%s",
                    workflow_id,
                    chat.id,
                    message.message_id,
                    exc_info=True,
                )
                await invalidate_chat_caches(chat.id, context.bot_data)
                await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "delete_failed"))
                await workflow_fail("delete_failed", str(exc), {"reason": scan.reason_code})
                return
            except Exception as exc:
                logger.exception(
                    "Unexpected delete failure workflow_id=%s chat_id=%s message_id=%s",
                    workflow_id,
                    chat.id,
                    message.message_id,
                    exc_info=True,
                )
                await workflow_fail("delete_failed", str(exc), {"reason": scan.reason_code})
                return
        if not deleted:
            await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "delete_failed"))
            await workflow_fail("delete_failed", "Telegram did not confirm message deletion", {"reason": scan.reason_code})
            return
        await workflow_advance("deleted", "blocked file deleted", {"message_id": message.message_id})

        await remember_user_profile(context.bot_data, sender)
        await remember_group(
            context.bot_data,
            chat.id,
            lang=get_group_lang(context.bot_data, chat.id),
            title=chat.title or str(chat.id),
            chat_type=str(chat.type),
        )
        user_mention = user_link(sender_id, sender_name_raw)
        scan_reason = describe_scan_reason(scan.reason_code, (scan.reason_display, *scan.details))
        async with BOT_DATA_LOCK:
            settings = dict(get_group_settings(context.bot_data, chat.id))
        send_group_notice, send_admin_notice = moderation_notification_targets(settings)

        if send_group_notice:
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
                "workflow_id": workflow_id,
                "alert_messages": {},
            }
            context.bot_data.setdefault("incidents", {})[ikey] = incident_record
            ensure_incident_action_token(context.bot_data, ikey)
            advance_workflow(
                context.bot_data,
                workflow_id,
                stage="incident_recorded",
                at_ms=now_ms(),
                detail=ikey,
                data={"incident_key": ikey},
            )
            await persist_context_memory(context, reason="incident_created", force=True, caller_holds_lock=True)

        auto_report = await maybe_apply_auto_action(
            context,
            chat_id=chat.id,
            sender_id=sender_id,
            sender_name=sender_name_raw,
            ikey=ikey,
        )
        await workflow_advance("auto_action", auto_report.get("result", ""), auto_report)

        alert_report = {"requested": 0, "delivered": 0, "failed": 0, "admin_ids": []}
        if send_admin_notice:
            alert_report = await notify_admins(
                context,
                chat.id,
                chat.title or str(chat.id),
                sender,
                file_name,
                ikey,
                scan_reason,
            )
        await workflow_advance("notifications", "notification workflow completed", alert_report)
        await workflow_complete(
            "blocked_and_removed",
            scan_reason,
            {
                "incident_key": ikey,
                "auto_action": auto_report,
                "notifications": alert_report,
            },
            persist=True,
        )
    except Exception as exc:
        logger.exception(
            "Document moderation workflow failed workflow_id=%s chat_id=%s user_id=%s",
            workflow_id,
            getattr(chat, "id", None),
            user_id,
            exc_info=True,
        )
        await workflow_fail("workflow_exception", str(exc))
        await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "unknown_error"))



# Scanner self-tests moved to scanner.py
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
        async with BOT_DATA_LOCK:
            sync_report = reconcile_group_state(context.bot_data, chat.id, at_ms=now_ms())
            await persist_context_memory(context, reason="status_group_sync", force=True, caller_holds_lock=True)
        logger.info("Group state synchronized from /status chat_id=%s report=%s", chat.id, sync_report)
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



# Telegram Mini App API moved to miniapp_api.py

# ─────────────────────────────────────────────────────────────
# APP LIFECYCLE / ERROR HANDLING
# ─────────────────────────────────────────────────────────────


async def post_init(application: Application) -> None:
    global BOT_ID, BOT_USERNAME
    me = await application.bot.get_me()
    BOT_ID = int(me.id)
    BOT_USERNAME = me.username or ""
    logger.info("Bot initialized as @%s id=%s", BOT_USERNAME, BOT_ID)
    async with BOT_DATA_LOCK:
        migrate_local_bot_data_in_place(application.bot_data)
        sanitize_bot_data_in_place(application.bot_data)

    # Load Redis first, then Supabase. This lets an existing Redis deployment
    # migrate into Supabase automatically when Supabase has no row yet, while
    # Supabase can still override stale Redis if both already contain data.
    await init_redis_memory(application)
    await init_supabase_memory(application)
    async with BOT_DATA_LOCK:
        sanitize_bot_data_in_place(application.bot_data)
        recovered_workflows = recover_interrupted_workflows(application.bot_data, at_ms=now_ms())
        await persist_context_memory(application, reason="state_sanitized_startup", force=True, caller_holds_lock=True)
    if recovered_workflows:
        logger.warning("Recovered %s interrupted workflow(s) during startup", recovered_workflows)

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
    reference = secrets.token_hex(4)
    error = getattr(context, "error", None)
    exc_info = (type(error), error, error.__traceback__) if isinstance(error, BaseException) else True
    logger.error("Unhandled update exception reference=%s", reference, exc_info=exc_info)

    if not isinstance(update, Update):
        return
    user = update.effective_user
    user_id = int(user.id) if user else 0
    message = (
        f"❌ {tr(context.bot_data, user_id, 'callback_failed_alert')}\n"
        f"{tr(context.bot_data, user_id, 'error_reference', reference=reference)}"
    )
    query = update.callback_query
    if query:
        await safe_answer_callback(query, text=tr(context.bot_data, user_id, "callback_failed_alert"), show_alert=True)
        edited = await safe_edit_query(
            query,
            f"{message}\n\n{tr(context.bot_data, user_id, 'callback_retry_hint')}",
            reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id) if user_id else None,
        )
        if edited:
            return
    if update.effective_message:
        await safe_reply(update, message)


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




def startup_validation_snapshot() -> dict[str, Any]:
    return {
        "BOT_TOKEN": BOT_TOKEN,
        "BOT_MODE": BOT_MODE,
        "WEBHOOK_BASE_URL": WEBHOOK_BASE_URL,
        "WEBHOOK_SECRET_TOKEN": WEBHOOK_SECRET_TOKEN,
        "WEBHOOK_PATH_SECRET": WEBHOOK_PATH_SECRET,
        "WEBHOOK_URL_PATH": WEBHOOK_URL_PATH,
        "REDIS_ENABLED": REDIS_ENABLED,
        "REDIS_URL": REDIS_URL,
        "SUPABASE_ENABLED": SUPABASE_ENABLED,
        "SUPABASE_URL": SUPABASE_URL,
        "SUPABASE_SERVICE_ROLE_KEY": SUPABASE_SERVICE_ROLE_KEY,
        "LOCAL_PERSISTENCE_ENABLED": LOCAL_PERSISTENCE_ENABLED,
        "MINI_APP_API_ENABLED": MINI_APP_API_ENABLED,
        "MINI_APP_CORS_ORIGINS": MINI_APP_CORS_ORIGINS,
        "SERVER_LOG_PUBLIC_ACCESS": SERVER_LOG_PUBLIC_ACCESS,
        "SERVER_LOG_AUTH_QUERY_ENABLED": SERVER_LOG_AUTH_QUERY_ENABLED,
        "SERVER_LOG_API_KEY": SERVER_LOG_API_KEY,
        "SERVER_LOG_STORE_CLIENT_IP": SERVER_LOG_STORE_CLIENT_IP,
        "MINI_APP_PUBLIC_DOCS_ENABLED": MINI_APP_PUBLIC_DOCS_ENABLED,
        "MINI_APP_PUBLIC_ROUTE_CATALOG_ENABLED": MINI_APP_PUBLIC_ROUTE_CATALOG_ENABLED,
        "MINI_APP_FRONTEND_DEBUG_ENABLED": MINI_APP_FRONTEND_DEBUG_ENABLED,
    }


def run_startup_validation() -> None:
    dependencies: list[str] = []
    if FastAPI is not None and CORSMiddleware is not None:
        dependencies.append("fastapi")
    if uvicorn is not None:
        dependencies.append("uvicorn")
    report = validate_startup_config(startup_validation_snapshot(), available_dependencies=dependencies)
    report.log(logger)
    if STARTUP_VALIDATION_STRICT:
        report.raise_for_errors()
    elif report.errors:
        logger.warning("STARTUP_VALIDATION_STRICT=false; continuing despite %s validation error(s)", len(report.errors))


def main() -> None:
    run_startup_validation()
    ensure_main_event_loop()

    app = build_application()
    mode = resolve_run_mode()

    if mode == "WEBHOOK":
        if not WEBHOOK_BASE_URL:
            raise RuntimeError("WEBHOOK mode requires WEBHOOK_URL or RENDER_EXTERNAL_URL.")
        webhook_url = f"{WEBHOOK_BASE_URL}/{WEBHOOK_URL_PATH}"
        logger.info(
            "Starting webhook mode on 0.0.0.0:%s with secret path configured; drop_pending_updates=%s",
            PORT,
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


from .miniapp_api import run_webhook_with_mini_app_api

if __name__ == "__main__":
    main()
