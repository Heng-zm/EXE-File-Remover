

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import os
import pickle
import re
import secrets
import time
import unicodedata
import zipfile
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from typing import Any, Generic, Iterable, TypeVar

import httpx
from dotenv import load_dotenv

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
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    PicklePersistence,
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


MAX_CONCURRENT_UPDATES = _env_int("MAX_CONCURRENT_UPDATES", 8, min_value=1, max_value=64)
TELEGRAM_CONNECTION_POOL_SIZE = _env_int("TELEGRAM_CONNECTION_POOL_SIZE", 32, min_value=8, max_value=256)
TELEGRAM_POOL_TIMEOUT = _env_float("TELEGRAM_POOL_TIMEOUT", 10.0, min_value=1.0)
ADMIN_CACHE_TTL_SECONDS = _env_int("ADMIN_CACHE_TTL_SECONDS", 180, min_value=5)
BOT_MEMBER_CACHE_TTL_SECONDS = _env_int("BOT_MEMBER_CACHE_TTL_SECONDS", 60, min_value=5)
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


# ─────────────────────────────────────────────────────────────
# TRANSLATIONS - HTML parse mode, not Markdown
# ─────────────────────────────────────────────────────────────

TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "select_lang": "🌐 Please choose your preferred language / សូមជ្រើសរើសភាសារបស់អ្នក៖",
        "lang_set": "✅ Got it! I’ll speak to you in <b>English</b> from now on.",
        "welcome": (
            "👋 <b>Hey there! I’m your EXE Remover Bot.</b>\n\n"
            "🛡️ I keep your groups safe by instantly removing dangerous <code>.exe</code> files.\n"
            "📢 When someone sends one, I’ll DM the admin team with quick options to <b>Ban</b>, <b>Warn</b>, or <b>Ignore</b>.\n\n"
            "➡️ Add me to your group and give me <b>Delete Messages</b> permission."
        ),
        "add_btn": "➕ Add Me to a Group",
        "check_btn": "🔄 Check My Permissions",
        "private_start": "Open a private chat with me to choose language and manage settings.",
        "no_group": "⚠️ I haven’t detected your group yet. Add me to a group first, then click <b>Check My Permissions</b>.",
        "not_admin": (
            "❌ <b>I’m not an admin in your group yet.</b>\n\n"
            "Go to Group Settings → Administrators → Add Member → select me, then enable <b>Delete Messages</b>."
        ),
        "no_delete_perm": (
            "⚠️ <b>I’m an admin, but I can’t delete messages yet.</b>\n\n"
            "Please enable <b>Delete Messages</b> for me."
        ),
        "setup_ok": (
            "🎉 <b>Awesome! I’m ready.</b>\n\n"
            "I’m now guarding <b>{group}</b>. If a blocked file appears, I’ll delete it and alert the admin team. 🛡️"
        ),
        "exe_removed_group": (
            "🚫 <b>Blocked file removed.</b> {user}\n"
            "🧪 <b>Reason:</b> {reason}\n"
            "Executable files are not allowed here for everyone’s safety."
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
        "action_ban_ok": "🔨 <b>Action taken:</b> {name} has been banned and kicked from the group.",
        "action_ban_fail": "❌ I couldn’t ban them. Make sure I have <b>Ban Users</b> permission.",
        "action_warn_ok": "⚠️ <b>Action taken:</b> I sent a formal warning for {name} in the group.",
        "action_warn_fail": "❌ I couldn’t send the warning in the group.",
        "action_ignore_ok": "✅ <b>Action taken:</b> This incident has been ignored.",
        "action_done": "<i>Another admin has already handled this incident.</i>",
        "action_expired": "<i>This incident is expired or no longer exists.</i>",
        "action_not_admin": "❌ You are no longer an admin in that group, so this action was rejected.",
        "handled_by": "👮 <b>Handled by:</b> {admin}",
        "delete_failed": "❌ I detected a blocked file, but I could not delete it. Please give me <b>Delete Messages</b> permission.",
        "warn_in_group": (
            "⚠️ <b>Official Warning</b> — {user}\n"
            "Sending executable files is strictly prohibited here. Please do not send them again."
        ),
        "help": (
            "💡 <b>EXE Remover Bot — Quick Guide</b>\n\n"
            "/start — Choose language and settings\n"
            "/help — Show this help\n"
            "/status — Check bot permissions inside a group\n"
            "/admins — See group admins and alert readiness\n"
            "/scanner — Show scanner settings\n"
            "/scanname &lt;filename&gt; — Test a filename\n"
            "/memory — Show Supabase/Redis/user memory status"
        ),
        "status_ok": "✅ Everything is running correctly. I can delete blocked files and alert admins.",
        "status_no": "❌ I’m inactive here because I’m not admin or I don’t have <b>Delete Messages</b> permission.",
        "status_error": "❌ Permission check failed: <code>{error}</code>",
        "admins_header": "👮 <b>Group admin alert status</b>\n",
        "admins_enabled": "✅ alerts enabled",
        "admins_need_start": "⚠️ needs /start in private chat",
        "admins_note": "\n<i>Only admins who have privately started the bot can receive DM alerts.</i>",
        "group_only": "Send this command inside a group.",
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
        "scanname_clean": "✅ <b>No filename-only danger found:</b> <code>{file}</code>",
        "memory_status": (
            "🧠 <b>Bot Memory</b>\n"
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
    },
    "km": {
        "select_lang": "🌐 Please choose your preferred language / សូមជ្រើសរើសភាសារបស់អ្នក៖",
        "lang_set": "✅ បានកំណត់យក <b>ភាសាខ្មែរ</b> រួចរាល់ហើយបាទ។",
        "welcome": (
            "👋 <b>សួស្ដីបាទ! ខ្ញុំជា EXE Remover Bot។</b>\n\n"
            "🛡️ ខ្ញុំជួយការពារក្រុម ដោយលុបឯកសារ <code>.exe</code> ចោលភ្លាមៗ។\n"
            "📢 ពេលមានអ្នកផ្ញើឯកសារប្រភេទនេះ ខ្ញុំនឹងផ្ញើ DM ទៅ Admin ជាមួយជម្រើស <b>Ban</b>, <b>Warn</b>, ឬ <b>Ignore</b>។\n\n"
            "➡️ សូមបន្ថែមខ្ញុំទៅក្រុម ហើយផ្តល់សិទ្ធិ <b>Delete Messages</b>។"
        ),
        "add_btn": "➕ បន្ថែមខ្ញុំទៅក្នុងក្រុម",
        "check_btn": "🔄 ពិនិត្យសិទ្ធិ",
        "private_start": "សូមបើកឆាតឯកជនជាមួយខ្ញុំ ដើម្បីជ្រើសរើសភាសា និងកំណត់ការប្រើប្រាស់។",
        "no_group": "⚠️ ខ្ញុំមិនទាន់ឃើញក្រុមណាមួយទេ។ សូមបន្ថែមខ្ញុំទៅក្រុមជាមុនសិន រួចចុច <b>ពិនិត្យសិទ្ធិ</b>។",
        "not_admin": (
            "❌ <b>ខ្ញុំមិនទាន់ជា Admin ក្នុងក្រុមរបស់អ្នកទេ។</b>\n\n"
            "សូមចូល Group Settings → Administrators → Add Member → ជ្រើសខ្ញុំ ហើយបើកសិទ្ធិ <b>Delete Messages</b>។"
        ),
        "no_delete_perm": (
            "⚠️ <b>ខ្ញុំជា Admin ប៉ុន្តែមិនទាន់មានសិទ្ធិលុបសារ។</b>\n\n"
            "សូមបើកសិទ្ធិ <b>Delete Messages</b> ឱ្យខ្ញុំផងបាទ។"
        ),
        "setup_ok": (
            "🎉 <b>រួចរាល់ហើយបាទ!</b>\n\n"
            "ឥឡូវនេះខ្ញុំកំពុងការពារក្រុម <b>{group}</b>។ បើមានឯកសារហាមឃាត់ ខ្ញុំនឹងលុបវា និងរាយការណ៍ជូន Admin។ 🛡️"
        ),
        "exe_removed_group": (
            "🚫 <b>បានលុបឯកសារហាមឃាត់។</b> {user}\n"
            "🧪 <b>មូលហេតុ:</b> {reason}\n"
            "ឯកសារដែលអាចដំណើរការបាន មិនត្រូវបានអនុញ្ញាតក្នុងក្រុមនេះទេ។"
        ),
        "admin_alert": (
            "🚨 <b>ការជូនដំណឹងសន្តិសុខ៖ រកឃើញ និងលុបឯកសារ</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "👤 <b>អ្នកផ្ញើ:</b> {sender_name} <code>{sender_id}</code>\n"
            "📄 <b>ឈ្មោះឯកសារ:</b> <code>{file_name}</code>\n"
            "🧪 <b>មូលហេតុ:</b> {scan_result}\n"
            "💬 <b>ក្រុម:</b> {group_name} <code>{group_id}</code>\n"
            "📅 <b>ម៉ោង:</b> {time} UTC\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "តើ Admin ចង់ចាត់ការបែបណា?"
        ),
        "btn_ban": "🔨 Ban User",
        "btn_warn": "⚠️ Warn User",
        "btn_ignore": "✅ Ignore",
        "action_ban_ok": "🔨 <b>បានចាត់ការ:</b> បាន Ban និងបណ្តេញ {name} ចេញពីក្រុម។",
        "action_ban_fail": "❌ ខ្ញុំមិនអាច Ban បានទេ។ សូមពិនិត្យសិទ្ធិ <b>Ban Users</b>។",
        "action_warn_ok": "⚠️ <b>បានចាត់ការ:</b> ខ្ញុំបានផ្ញើសារព្រមានទៅក្រុមសម្រាប់ {name}។",
        "action_warn_fail": "❌ ខ្ញុំមិនអាចផ្ញើសារព្រមានទៅក្រុមបានទេ។",
        "action_ignore_ok": "✅ <b>បានចាត់ការ:</b> បានមិនអើពើករណីនេះ។",
        "action_done": "<i>Admin ផ្សេងបានចាត់ការករណីនេះរួចរាល់ហើយ។</i>",
        "action_expired": "<i>ករណីនេះផុតកំណត់ ឬមិនមានទៀតទេ។</i>",
        "action_not_admin": "❌ អ្នកមិនមែនជា Admin ក្នុងក្រុមនោះទៀតទេ ដូច្នេះមិនអាចចាត់ការបាន។",
        "handled_by": "👮 <b>ចាត់ការដោយ:</b> {admin}",
        "delete_failed": "❌ ខ្ញុំបានរកឃើញឯកសារហាមឃាត់ ប៉ុន្តែមិនអាចលុបវាបានទេ។ សូមផ្តល់សិទ្ធិ <b>Delete Messages</b> ឱ្យខ្ញុំ។",
        "warn_in_group": (
            "⚠️ <b>ការព្រមានជាផ្លូវការ</b> — {user}\n"
            "ការផ្ញើឯកសារដែលអាចដំណើរការបាន ត្រូវបានហាមឃាត់ក្នុងក្រុមនេះ។ សូមកុំផ្ញើវាម្តងទៀត។"
        ),
        "help": (
            "💡 <b>EXE Remover Bot — ជំនួយ</b>\n\n"
            "/start — ជ្រើសរើសភាសា និងកំណត់\n"
            "/help — បង្ហាញជំនួយ\n"
            "/status — ពិនិត្យសិទ្ធិ Bot ក្នុងក្រុម\n"
            "/admins — មើលស្ថានភាព Admin ទទួល Alert\n"
            "/scanner — មើលការកំណត់ Scanner\n"
            "/scanname &lt;filename&gt; — សាកល្បងឈ្មោះឯកសារ\n"
            "/memory — មើលស្ថានភាព Supabase/Redis/User memory"
        ),
        "status_ok": "✅ ដំណើរការត្រឹមត្រូវ។ ខ្ញុំអាចលុបឯកសារហាមឃាត់ និងរាយការណ៍ Admin បាន។",
        "status_no": "❌ ខ្ញុំមិនដំណើរការនៅទីនេះទេ ព្រោះមិនមែនជា Admin ឬមិនមានសិទ្ធិ <b>Delete Messages</b>។",
        "status_error": "❌ ពិនិត្យសិទ្ធិបរាជ័យ: <code>{error}</code>",
        "admins_header": "👮 <b>ស្ថានភាព Admin ទទួល Alert</b>\n",
        "admins_enabled": "✅ បើកទទួល Alert",
        "admins_need_start": "⚠️ ត្រូវ /start ក្នុងឆាតឯកជន",
        "admins_note": "\n<i>មានតែ Admin ដែលបាន /start ជាមួយ Bot ក្នុងឆាតឯកជនប៉ុណ្ណោះ ទើបទទួលបាន DM Alert។</i>",
        "group_only": "សូមផ្ញើ command នេះនៅក្នុងក្រុម។",
        "scanner_status": (
            "🧪 <b>Suspicious File Scanner</b>\n"
            "បើក: <code>{enabled}</code>\n"
            "ពិនិត្យ header: <code>{magic}</code>\n"
            "ពិនិត្យឈ្មោះក្នុង archive: <code>{archive}</code>\n"
            "ទំហំ download ស្កេនអតិបរមា: <code>{max_bytes}</code> bytes\n"
            "Extension ដែល block: <code>{blocked}</code>\n"
            "Extension គ្រោះថ្នាក់: <code>{dangerous}</code>\n"
            "Extension archive: <code>{archives}</code>\n"
            "Trusted hash whitelist: <code>{hash_whitelist}</code>"
        ),
        "scanname_usage": "ប្រើ: <code>/scanname invoice.pdf.exe</code>",
        "scanname_blocked": "🚫 <b>Blocked:</b> <code>{file}</code>\n🧪 <b>មូលហេតុ:</b> {reason}",
        "scanname_clean": "✅ <b>រកមិនឃើញគ្រោះថ្នាក់តាមឈ្មោះ:</b> <code>{file}</code>",
        "memory_status": (
            "🧠 <b>Bot Memory</b>\n"
            "Backend: <code>{backend}</code>\n"
            "Supabase: <code>{supabase}</code>\n"
            "Redis: <code>{redis}</code>\n"
            "អ្នកប្រើប្រាស់ដែលបានចងចាំ: <code>{users}</code>\n"
            "ក្រុមដែលបានរក្សាទុក: <code>{groups}</code>\n"
            "ករណីកំពុងបើក: <code>{incidents}</code>\n"
            "Supabase save ចុងក្រោយ: <code>{supabase_last_save}</code>\n"
            "Redis save ចុងក្រោយ: <code>{redis_last_save}</code>"
        ),
        "unknown_error": "មានបញ្ហាមួយកើតឡើង។ សូមព្យាយាមម្តងទៀត។",
    },
}


# ─────────────────────────────────────────────────────────────
# DYNAMIC USER FLOW / GROUP SETTINGS TEXT
# ─────────────────────────────────────────────────────────────

EXTRA_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "home_title": (
            "🛡️ <b>EXE Remover Bot</b>\n\n"
            "Status: <b>Online</b>\n"
            "Use the buttons below. You can always come back here, so the setup flow never gets stuck."
        ),
        "btn_home": "🏠 Home",
        "btn_groups": "👥 My Groups",
        "btn_add_group": "➕ Add to Group",
        "btn_help": "💡 Help",
        "btn_refresh": "🔄 Refresh",
        "btn_settings": "⚙️ Settings",
        "btn_back": "⬅️ Back",
        "groups_title": "👥 <b>Your linked groups</b>\n\nChoose a group to check permissions or change protection settings.",
        "groups_empty": (
            "⚠️ <b>No linked groups yet.</b>\n\n"
            "Add me to a group, or run <code>/settings</code> inside the group so I can safely link that group to your private dashboard."
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
            "Extra delete formats: <code>{custom_blocked}</code>\n\n"
            "Standard blocks <code>.exe</code> and renamed Windows executables. High blocks all dangerous extensions."
        ),
        "settings_saved": "✅ Settings updated.",
        "group_linked": "✅ Group linked to your private dashboard.",
        "group_admin_only": "❌ Only group admins can open this dashboard.",
        "access_denied": "❌ <b>Access denied.</b> This command is available only to bot owners or verified group admins.",
        "settings_group_open_private": "🔒 Configuration is private-chat only. Open private chat to manage this group:",
        "config_private_only": "🔒 Configuration updates are only available in private chat. I will not show or edit settings inside the group.",
        "protection_on": "ON",
        "protection_off": "OFF",
        "silent_on": "true",
        "silent_off": "false",
        "strict_standard": "standard",
        "strict_high": "high",
        "perm_ok": "✅ Delete OK",
        "perm_no": "❌ Need Delete Messages",
        "perm_unknown": "⚠️ Unknown",
        "btn_manage_formats": "🧩 Manage delete formats",
        "btn_add_format": "➕ Add format",
        "btn_remove_format": "🗑 Delete format",
        "btn_edit_formats": "✏️ Edit list",
        "btn_clear_formats": "🧹 Clear all",
        "formats_title": (
            "🧩 <b>Custom delete formats</b>\n"
            "💬 <b>{group}</b> <code>{chat_id}</code>\n\n"
            "Current custom formats: <code>{custom_blocked}</code>\n\n"
            "Files ending with these extensions will be deleted in this group. Example: <code>.apk</code>, <code>.zip</code>, <code>.pdf</code>."
        ),
        "formats_empty": "No custom delete formats yet.",
        "formats_prompt_add": (
            "➕ <b>Add delete formats</b>\n\n"
            "Send extension names separated by spaces or commas.\n"
            "Example: <code>.apk .zip .pdf</code>\n\n"
            "Tap <b>Back</b> or <b>Home</b> to cancel."
        ),
        "formats_prompt_edit": (
            "✏️ <b>Edit delete format list</b>\n\n"
            "Send the complete new list. Old custom formats will be replaced.\n"
            "Example: <code>.apk .zip .pdf</code>\n\n"
            "Tap <b>Back</b> or <b>Home</b> to cancel."
        ),
        "formats_saved": "✅ Delete format list updated.",
        "formats_removed": "✅ Removed <code>{ext}</code> from delete formats.",
        "formats_cleared": "✅ Custom delete formats cleared.",
        "formats_invalid": "❌ I could not find a valid extension. Send like: <code>.apk .zip .pdf</code>",
        "formats_cancelled": "✅ Cancelled.",
        "scanner_group_status": (
            "\n\n⚙️ <b>This group</b>\n"
            "Protection: <code>{protection}</code>\n"
            "Strictness: <code>{strictness}</code>\n"
            "Silent mode: <code>{silent}</code>\n"
            "Allowed extensions: <code>{allowed}</code>\n"
            "Extra delete formats: <code>{custom_blocked}</code>"
        ),
        "scanner_private_manage_hint": "Use the button below to manage delete formats safely in private chat.",
        "scanner_group_private_only": "🔒 Scanner configuration is private-chat only. Open private chat to view or update this group's delete formats and protection settings.",
    },
    "km": {
        "home_title": (
            "🛡️ <b>EXE Remover Bot</b>\n\n"
            "ស្ថានភាព: <b>Online</b>\n"
            "ប្រើប៊ូតុងខាងក្រោម។ អ្នកអាចត្រឡប់មក Home បានជានិច្ច ដូច្នេះ flow មិនជាប់គាំងទេ។"
        ),
        "btn_home": "🏠 Home",
        "btn_groups": "👥 ក្រុមរបស់ខ្ញុំ",
        "btn_add_group": "➕ បន្ថែមទៅក្រុម",
        "btn_help": "💡 ជំនួយ",
        "btn_refresh": "🔄 Refresh",
        "btn_settings": "⚙️ កំណត់",
        "btn_back": "⬅️ ត្រឡប់ក្រោយ",
        "groups_title": "👥 <b>ក្រុមដែលបានភ្ជាប់</b>\n\nជ្រើសក្រុម ដើម្បីពិនិត្យសិទ្ធិ ឬកែ settings។",
        "groups_empty": (
            "⚠️ <b>មិនទាន់មានក្រុមដែលបានភ្ជាប់ទេ។</b>\n\n"
            "បន្ថែម Bot ទៅក្រុម ឬវាយ <code>/settings</code> ក្នុងក្រុម ដើម្បីភ្ជាប់ទៅ private dashboard។"
        ),
        "group_card": (
            "💬 <b>{group}</b>\n"
            "សិទ្ធិ: {permission}\n"
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
            "Extra delete formats: <code>{custom_blocked}</code>\n\n"
            "Standard block <code>.exe</code> និង renamed Windows executables។ High block dangerous extensions ទាំងអស់។"
        ),
        "settings_saved": "✅ បានកែ settings រួចរាល់។",
        "group_linked": "✅ បានភ្ជាប់ក្រុមទៅ private dashboard រួច។",
        "group_admin_only": "❌ មានតែ Admin ក្នុងក្រុមប៉ុណ្ណោះអាចបើក dashboard នេះបាន។",
        "access_denied": "❌ <b>មិនមានសិទ្ធិ។</b> Command នេះអនុញ្ញាតតែ Bot owner ឬ Admin ក្រុមដែលបាន verify ប៉ុណ្ណោះ។",
        "settings_group_open_private": "🔒 ការកំណត់អាចកែបានតែក្នុង private chat ប៉ុណ្ណោះ។ សូមបើក private chat ដើម្បីគ្រប់គ្រងក្រុមនេះ:",
        "config_private_only": "🔒 ការកែ configuration អនុញ្ញាតតែក្នុង private chat ប៉ុណ្ណោះ។ ខ្ញុំនឹងមិនបង្ហាញ ឬកែ settings នៅក្នុង group ទេ។",
        "protection_on": "ON",
        "protection_off": "OFF",
        "silent_on": "true",
        "silent_off": "false",
        "strict_standard": "standard",
        "strict_high": "high",
        "perm_ok": "✅ Delete OK",
        "perm_no": "❌ ត្រូវការ Delete Messages",
        "perm_unknown": "⚠️ មិនដឹង",
        "btn_manage_formats": "🧩 គ្រប់គ្រង format លុប",
        "btn_add_format": "➕ បន្ថែម format",
        "btn_remove_format": "🗑 លុប format",
        "btn_edit_formats": "✏️ កែបញ្ជី",
        "btn_clear_formats": "🧹 លុបទាំងអស់",
        "formats_title": (
            "🧩 <b>Custom delete formats</b>\n"
            "💬 <b>{group}</b> <code>{chat_id}</code>\n\n"
            "Formats បច្ចុប្បន្ន: <code>{custom_blocked}</code>\n\n"
            "ឯកសារដែលបញ្ចប់ដោយ extension ទាំងនេះ នឹងត្រូវលុបក្នុងក្រុមនេះ។ ឧទាហរណ៍: <code>.apk</code>, <code>.zip</code>, <code>.pdf</code>."
        ),
        "formats_empty": "មិនទាន់មាន custom delete formats ទេ។",
        "formats_prompt_add": (
            "➕ <b>បន្ថែម delete formats</b>\n\n"
            "ផ្ញើ extension ដោយបំបែកជាចន្លោះ ឬ comma។\n"
            "ឧទាហរណ៍: <code>.apk .zip .pdf</code>\n\n"
            "ចុច <b>ត្រឡប់ក្រោយ</b> ឬ <b>Home</b> ដើម្បីបោះបង់។"
        ),
        "formats_prompt_edit": (
            "✏️ <b>កែបញ្ជី delete formats</b>\n\n"
            "ផ្ញើបញ្ជីថ្មីទាំងមូល។ បញ្ជីចាស់នឹងត្រូវជំនួស។\n"
            "ឧទាហរណ៍: <code>.apk .zip .pdf</code>\n\n"
            "ចុច <b>ត្រឡប់ក្រោយ</b> ឬ <b>Home</b> ដើម្បីបោះបង់។"
        ),
        "formats_saved": "✅ បានកែបញ្ជី delete formats រួចរាល់។",
        "formats_removed": "✅ បានដក <code>{ext}</code> ចេញពី delete formats។",
        "formats_cleared": "✅ បានសម្អាត custom delete formats រួច។",
        "formats_invalid": "❌ ខ្ញុំរកមិនឃើញ extension ត្រឹមត្រូវទេ។ សូមផ្ញើដូចជា: <code>.apk .zip .pdf</code>",
        "formats_cancelled": "✅ បានបោះបង់។",
        "scanner_group_status": (
            "\n\n⚙️ <b>ក្រុមនេះ</b>\n"
            "Protection: <code>{protection}</code>\n"
            "Strictness: <code>{strictness}</code>\n"
            "Silent mode: <code>{silent}</code>\n"
            "Allowed extensions: <code>{allowed}</code>\n"
            "Extra delete formats: <code>{custom_blocked}</code>"
        ),
        "scanner_private_manage_hint": "ប្រើប៊ូតុងខាងក្រោម ដើម្បីគ្រប់គ្រង delete formats ក្នុង private chat ដោយសុវត្ថិភាព។",
        "scanner_group_private_only": "🔒 Scanner configuration អាចមើល និងកែបានតែក្នុង private chat ប៉ុណ្ណោះ។ សូមបើក private chat ដើម្បីកែ delete formats និង protection settings របស់ក្រុមនេះ។",
    },
}
for _lang, _items in EXTRA_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_items)


# ─────────────────────────────────────────────────────────────
# BUTTON-ONLY UX + DEVELOPER DASHBOARD TEXT
# Commands still exist internally for Telegram deep-link/fallback handling, but
# the public interface is button-first and the Telegram command menu is hidden
# during post_init().
# ─────────────────────────────────────────────────────────────

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
        "dev_only": "❌ <b>Developer only.</b> Add your Telegram ID to <code>BOT_OWNER_IDS</code> to open this dashboard.",
        "dev_title": (
            "🧑‍💻 <b>Developer Dashboard</b>\n\n"
            "Users: <code>{users}</code>\n"
            "Groups: <code>{groups}</code>\n"
            "Open incidents: <code>{incidents}</code>\n"
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
            "ប្រើប៊ូតុងខាងក្រោមដើម្បីគ្រប់គ្រងទាំងអស់។ មិនចាំបាច់ប្រើ command ទេ។"
        ),
        "help": (
            "💡 <b>របៀបប្រើ Bot</b>\n\n"
            "ប្រើប៊ូតុងលើ dashboard ដើម្បីបន្ថែមក្រុម ពិនិត្យសិទ្ធិ កែការការពារ "
            "គ្រប់គ្រង delete formats និង refresh status។\n\n"
            "Admin ក្រុមអាចបើក settings ពី private dashboard។ Developer អាចបើក developer dashboard "
            "ដើម្បីមើល users, groups, storage និងស្ថានភាព bot។"
        ),
        "btn_developer": "🧑‍💻 Developer Dashboard",
        "btn_dev_users": "👤 អ្នកប្រើ Bot",
        "btn_dev_groups": "💬 ក្រុម Bot",
        "btn_dev_memory": "🧠 Memory / Storage",
        "btn_dev_hash_config": "🔐 Trusted Hash Config",
        "btn_hash_size": "📦 ទំហំ File Hash",
        "btn_hash_limit": "🔢 ចំនួន Hash ក្នុងមួយក្រុម",
        "btn_hash_enable": "🟢 បើក Whitelist",
        "btn_hash_disable": "🔴 បិទ Whitelist",
        "dev_hash_config_saved": "✅ បានកែ Trusted hash config រួចរាល់។",
        "dev_hash_config_title": (
            "🔐 <b>Trusted Hash Runtime Config</b>\n\n"
            "បើក: <code>{enabled}</code>\n"
            "ទំហំ download អតិបរមា: <code>{max_bytes}</code> bytes (<code>{max_mb}</code>)\n"
            "Trusted hashes អតិបរមា/ក្រុម: <code>{max_hashes}</code>\n\n"
            "Env defaults ប្រើពេល boot ដំបូង ប៉ុន្តែតម្លៃក្នុង Dashboard នេះ override ហើយរក្សាទុកក្នុង Redis/Supabase។"
        ),
        "dev_hash_size_title": "📦 <b>ជ្រើសទំហំ file អតិបរមា សម្រាប់ trusted-hash upload</b>\n\nបច្ចុប្បន្ន: <code>{max_bytes}</code> bytes (<code>{max_mb}</code>)",
        "dev_hash_limit_title": "🔢 <b>ជ្រើសចំនួន trusted hashes អតិបរមា ក្នុងមួយក្រុម</b>\n\nបច្ចុប្បន្ន: <code>{max_hashes}</code>",
        "btn_next": "បន្ទាប់ ➡️",
        "btn_prev": "⬅️ ថយក្រោយ",
        "dev_only": "❌ <b>សម្រាប់ Developer ប៉ុណ្ណោះ។</b> សូមបន្ថែម Telegram ID របស់អ្នកក្នុង <code>BOT_OWNER_IDS</code>។",
        "dev_title": (
            "🧑‍💻 <b>Developer Dashboard</b>\n\n"
            "Users: <code>{users}</code>\n"
            "Groups: <code>{groups}</code>\n"
            "Open incidents: <code>{incidents}</code>\n"
            "Admin cache: <code>{admin_cache}</code>\n"
            "Bot permission cache: <code>{bot_perm_cache}</code>\n"
            "Chat metadata cache: <code>{chat_meta}</code>\n"
            "Supabase: <code>{supabase}</code>\n"
            "Redis: <code>{redis}</code>\n"
            "Backend: <code>{backend}</code>"
        ),
        "dev_users_title": "👤 <b>អ្នកប្រើ Bot</b>\nPage <code>{page}</code>/<code>{pages}</code> · Total <code>{total}</code>\n\nចុចលើ user ដើម្បីមើលព័ត៌មានលម្អិត។",
        "dev_users_empty": "👤 <b>អ្នកប្រើ Bot</b>\n\nមិនទាន់មាន user បានរក្សាទុកទេ។",
        "dev_user_detail": (
            "👤 <b>User Detail</b>\n\n"
            "ឈ្មោះ: <b>{name}</b>\n"
            "Username: <code>{username}</code>\n"
            "User ID: <code>{user_id}</code>\n"
            "ភាសា: <code>{lang}</code>\n"
            "Groups linked: <code>{groups_count}</code>\n"
            "First seen: <code>{first_seen}</code>\n"
            "Last seen: <code>{last_seen}</code>"
        ),
        "dev_groups_title": "💬 <b>ក្រុម Bot</b>\nTotal <code>{total}</code>\n\nចុចលើក្រុមដើម្បីបើក settings។",
        "dev_groups_empty": "💬 <b>ក្រុម Bot</b>\n\nមិនទាន់មានក្រុមបានរក្សាទុកទេ។",
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
        "allowed_removed": "✅ Removed <code>{ext}</code> from allowed formats.",
        "allowed_cleared": "✅ Allowed formats cleared.",
        "auto_title": "🤖 <b>Auto Action Rules</b>\n💬 <b>{group}</b>\n\nMode: <code>{mode}</code>\nWarn threshold: <code>{warn_threshold}</code>\nMute threshold: <code>{mute_threshold}</code>\nBan threshold: <code>{ban_threshold}</code>\nMute length: <code>{mute_minutes} minutes</code>\n\nRecommended: <b>Smart</b> = warn first, mute repeated offenders, ban heavy repeat offenders.",
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
        "group_admin_title": "⚙️ <b>Group Admin Panel</b>\n💬 <b>{group}</b> <code>{chat_id}</code>\n\n🛡 Protection: <code>{protection}</code>\n🔥 Strictness: <code>{strictness}</code>\n🔇 Silent mode: <code>{silent}</code>\n🧩 Blocked formats: <code>{custom_blocked}</code>\n✅ Allowed formats: <code>{allowed}</code>\n🔐 Trusted hashes: <code>{trusted_hashes}</code>\n⚙️ Auto action: <code>{auto_action}</code>",
        "btn_protection_status": "🛡 ស្ថានភាពការពារ",
        "btn_scanner_settings": "🧪 កំណត់ Scanner",
        "btn_incident_logs": "🚨 ប្រវត្តិ Incident",
        "btn_member_risk": "👥 User Risk List",
        "btn_admin_alert_status": "👮 ស្ថានភាព Admin Alert",
        "btn_blocked_formats": "🧩 Blocked Formats",
        "btn_allowed_formats": "✅ Allowed Formats",
        "btn_silent_mode": "🔇 Silent Mode",
        "btn_strictness_level": "🔥 Strictness Level",
        "btn_group_health": "🩺 ពិនិត្យសុខភាពក្រុម",
        "btn_auto_actions": "🤖 Auto Action Rules",
        "btn_trusted_hashes": "🔐 Trusted File Hashes",
        "btn_turn_on": "🟢 បើក",
        "btn_turn_off": "🔴 បិទ",
        "btn_clear_handled": "🧹 សម្អាត Logs ដែលបានចាត់ការ",
        "protection_status_title": "🛡 <b>Protection Status</b>\n💬 <b>{group}</b>\n\nProtection: <code>{protection}</code>\nStrictness: <code>{strictness}</code>\nSilent mode: <code>{silent}</code>\nBot permission: <code>{bot_permission}</code>\nAuto action: <code>{auto_action}</code>",
        "scanner_panel_title": "🧪 <b>Scanner Settings</b>\n💬 <b>{group}</b>\n{scanner}",
        "incidents_title": "🚨 <b>Incident Logs</b>\n💬 <b>{group}</b>\nTotal: <code>{total}</code>\n\n{items}",
        "incidents_empty": "មិនទាន់មាន incident សម្រាប់ក្រុមនេះទេ។",
        "incidents_cleared": "✅ បានសម្អាត handled incident logs។",
        "member_risk_title": "👥 <b>Member Risk List</b>\n💬 <b>{group}</b>\n\n{items}",
        "member_risk_empty": "មិនទាន់មាន risky member ទេ។",
        "admin_alert_title": "👮 <b>Admin Alert Status</b>\n💬 <b>{group}</b>\nReady: <code>{ready}</code>/<code>{total}</code>\n\n{items}\n\n<i>Admin ត្រូវបើក bot ក្នុង private ម្តង ដើម្បីទទួល alert។</i>",
        "health_title": "🩺 <b>Group Health Check</b>\n💬 <b>{group}</b>\n\nBot is admin: {bot_admin}\nCan delete messages: {can_delete}\nCan restrict members: {can_restrict}\nProtection enabled: {protection}\nScanner enabled: {scanner}\nAdmin alerts ready: <code>{ready}</code>/<code>{total}</code>",
        "allowed_title": "✅ <b>Allowed Formats</b>\n💬 <b>{group}</b> <code>{chat_id}</code>\n\nAllowed formats បច្ចុប្បន្ន: <code>{allowed}</code>\n\nAllowed formats អាច bypass custom blocked formats។ កុំ allow <code>.exe</code> បើមិនទុកចិត្តក្រុម។",
        "btn_add_allowed": "➕ Allow Format",
        "btn_edit_allowed": "✏️ កែ Allowed List",
        "btn_remove_allowed": "🗑 លុប Allowed Format",
        "btn_clear_allowed": "🧹 សម្អាត Allowed List",
        "allowed_prompt_add": "✅ <b>Allow formats</b>\n\nផ្ញើ extension ដោយបំបែកជាចន្លោះ ឬ comma។\nឧទាហរណ៍: <code>.zip .pdf</code>\n\nចុច Home ឬ Back ដើម្បីបោះបង់។",
        "allowed_prompt_edit": "✏️ <b>Edit allowed list</b>\n\nផ្ញើ allowed list ថ្មីទាំងមូល។\nឧទាហរណ៍: <code>.zip .pdf</code>\n\nចុច Home ឬ Back ដើម្បីបោះបង់។",
        "allowed_saved": "✅ បានកែ allowed format list។",
        "allowed_removed": "✅ បានដក <code>{ext}</code> ចេញពី allowed formats។",
        "allowed_cleared": "✅ បានសម្អាត allowed formats។",
        "auto_title": "🤖 <b>Auto Action Rules</b>\n💬 <b>{group}</b>\n\nMode: <code>{mode}</code>\nWarn threshold: <code>{warn_threshold}</code>\nMute threshold: <code>{mute_threshold}</code>\nBan threshold: <code>{ban_threshold}</code>\nMute length: <code>{mute_minutes} minutes</code>\n\nណែនាំ: <b>Smart</b> = warn, mute អ្នកធ្វើម្ដងហើយម្ដងទៀត, ban អ្នកធ្ងន់។",
        "btn_auto_off": "⛔ Auto Action OFF",
        "btn_auto_warn": "⚠️ Warn Only",
        "btn_auto_smart": "🤖 Smart Warn → Mute → Ban",
        "btn_auto_ban": "🔨 Aggressive Auto Ban",
        "auto_saved": "✅ បានកែ auto action rule។",
        "trusted_hash_title": "🔐 <b>Trusted File Hash Whitelist</b>\n💬 <b>{group}</b> <code>{chat_id}</code>\n\nTrusted hashes: <code>{count}</code>/<code>{limit}</code>\n\n{items}\n\nផ្ញើ file ដែលមានសុវត្ថិភាពក្នុង private chat ឬ paste SHA256 hash ដើម្បីអនុញ្ញាត file នោះជាក់លាក់។ បើ file ដូចគ្នាត្រូវបានផ្ញើម្ដងទៀត Bot នឹងអនុញ្ញាត ទោះបីជា <code>.exe</code> ក៏ដោយ។",
        "trusted_hash_empty": "មិនទាន់មាន trusted hash ទេ។",
        "btn_add_hash": "➕ Add Trusted File/Hash",
        "btn_remove_hash": "🗑 Remove Trusted Hash",
        "btn_clear_hashes": "🧹 Clear Trusted Hashes",
        "trusted_hash_prompt_add": "🔐 <b>Add Trusted File Hash</b>\n\nផ្ញើ safe file នៅទីនេះក្នុង private chat ឬ paste SHA256 hash។\n\n⚠️ អនុញ្ញាតតែ file ដែលអ្នកទុកចិត្តពិតប្រាកដ។ ចុច Home ឬ Back ដើម្បីបោះបង់។",
        "trusted_hash_saved": "✅ បានបន្ថែម trusted hash។",
        "trusted_hash_removed": "✅ បានលុប trusted hash។",
        "trusted_hash_cleared": "✅ បានសម្អាត trusted hash whitelist។",
        "trusted_hash_invalid": "❌ ផ្ញើ SHA256 hash ត្រឹមត្រូវ ឬ upload file តូចជាង whitelist download limit។",
        "trusted_hash_limit": "❌ Trusted hash whitelist ពេញហើយ។ សូមលុប hash ចាស់មួយសិន។",
        "trusted_hash_file_too_large": "❌ File ធំពេក មិនអាច hash ដោយសុវត្ថិភាពបានទេ។ Developer អាចបង្កើន trusted-hash max file size ក្នុង Developer Dashboard។",
    },
}
for _lang, _items in GROUP_ADMIN_DASHBOARD_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_items)

DEFAULT_GROUP_SETTINGS: dict[str, Any] = {
    "protection_enabled": True,
    "strictness": "standard",  # standard=.exe/PE only, high=all dangerous extensions, strict=high + archive-risk focus
    "silent_mode": False,
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
    "warning_counts",
    "settings",
    "whitelisted_hashes",
    # Persist lightweight caches so private dashboards can render without live API calls after restart.
    "chat_meta_cache",
    "admin_ids_cache",
    "bot_member_cache",
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


async def save_bot_data_to_redis(
    bot_data: dict[str, Any],
    *,
    reason: str = "manual",
    force: bool = False,
    caller_holds_lock: bool = False,
) -> bool:
    """Persist durable memory to Redis without crashing handlers.

    Lock order is always safe:
    - If caller_holds_lock=True, the caller already owns BOT_DATA_LOCK, so we
      serialize from that stable state and only take REDIS_SAVE_LOCK for I/O.
    - Otherwise, we take a short BOT_DATA_LOCK snapshot first, release it, then
      write to Redis. This prevents Redis/network latency from blocking normal
      state readers.
    """
    global REDIS_LAST_SAVE_MONOTONIC, REDIS_LAST_SAVE_UTC

    if not (REDIS_AVAILABLE and REDIS_CLIENT is not None):
        return False

    now = time.monotonic()
    if not force and REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS > 0:
        if now - REDIS_LAST_SAVE_MONOTONIC < REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS:
            return False

    try:
        if caller_holds_lock:
            payload = export_bot_data_for_storage(bot_data)
        else:
            async with BOT_DATA_LOCK:
                payload = export_bot_data_for_storage(bot_data)
        encoded = encode_redis_state(payload)
    except Exception:
        logger.exception("Redis memory snapshot failed reason=%s", reason, exc_info=True)
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


async def persist_context_memory(
    context: Any,
    *,
    reason: str,
    force: bool = False,
    caller_holds_lock: bool = False,
) -> None:
    # Fan out durable state saves. Every existing handler can keep calling this
    # one function; Redis, Supabase, and local PicklePersistence stay decoupled.
    await save_bot_data_to_supabase(context.bot_data, reason=reason, force=force, caller_holds_lock=caller_holds_lock)
    await save_bot_data_to_redis(context.bot_data, reason=reason, force=force, caller_holds_lock=caller_holds_lock)


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


async def save_bot_data_to_supabase(
    bot_data: dict[str, Any],
    *,
    reason: str = "manual",
    force: bool = False,
    caller_holds_lock: bool = False,
) -> bool:
    """Upsert durable bot memory into Supabase without blocking handlers."""
    global SUPABASE_LAST_SAVE_MONOTONIC, SUPABASE_LAST_SAVE_UTC

    if not (SUPABASE_AVAILABLE and SUPABASE_CLIENT is not None):
        return False

    now = time.monotonic()
    if not force and SUPABASE_AUTOSAVE_MIN_INTERVAL_SECONDS > 0:
        if now - SUPABASE_LAST_SAVE_MONOTONIC < SUPABASE_AUTOSAVE_MIN_INTERVAL_SECONDS:
            return False

    try:
        if caller_holds_lock:
            payload = export_bot_data_for_storage(bot_data)
        else:
            async with BOT_DATA_LOCK:
                payload = export_bot_data_for_storage(bot_data)
        row = {
            "state_key": SUPABASE_STATE_KEY,
            "payload": _json_safe(payload),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception:
        logger.exception("Supabase memory snapshot failed reason=%s", reason, exc_info=True)
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

    # For long chains, include individual middle suffixes so invoice.pdf.exe.zip
    # still catches .exe without treating .tar.gz as [".tar", ".gz"].
    if len(ext_parts) >= 3:
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
        except (zipfile.BadZipFile, RuntimeError, OSError, Exception):
            logger.exception("Archive scan skipped for %r", file_name, exc_info=True)
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


async def _download_document_bytes_for_scanner(context: ContextTypes.DEFAULT_TYPE, document: Any, *, file_name: str, file_size: int) -> bytes | None:
    for attempt in (1, 2):
        try:
            async with SCAN_DOWNLOAD_SEMAPHORE:
                tg_file = await context.bot.get_file(document.file_id)
                return bytes(await tg_file.download_as_bytearray())
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
    can_download_for_hash = bool(
        trusted_hash_whitelist_enabled(context.bot_data)
        and chat_id is not None
        and file_size > 0
        and file_size <= trusted_hash_max_download_bytes(context.bot_data)
    )
    can_download_for_magic = bool(
        SUSPICIOUS_SCANNER_ENABLED
        and SUSPICIOUS_MAGIC_SCAN_ENABLED
        and SCANNER_MAX_DOWNLOAD_BYTES > 0
        and file_size > 0
        and file_size <= SCANNER_MAX_DOWNLOAD_BYTES
    )

    if result.blocked and not can_download_for_hash:
        return result
    if not (can_download_for_hash or can_download_for_magic):
        return result

    data = await _download_document_bytes_for_scanner(context, document, file_name=file_name, file_size=file_size)
    if data is None:
        return result

    file_sha256 = calculate_file_hash(data)
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
            magic_result = scan_file_bytes(result.file_name, result.mime_type, data)
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


async def safe_send_message(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
    disable_web_page_preview: bool = True,
) -> int | None:
    for attempt in (1, 2):
        try:
            sent = await context.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode=ParseMode.HTML,
                reply_markup=reply_markup,
                disable_web_page_preview=disable_web_page_preview,
            )
            return int(sent.message_id)
        except RetryAfter as exc:
            if attempt == 1 and await _sleep_for_retry_after(exc, operation="send_message"):
                continue
            return None
        except Forbidden:
            return None
        except BadRequest:
            logger.exception("send_message BadRequest chat_id=%s", chat_id, exc_info=True)
            return None
        except TimedOut:
            logger.exception("send_message timed out chat_id=%s", chat_id, exc_info=True)
            return None
        except TelegramError:
            logger.exception("send_message failed chat_id=%s", chat_id, exc_info=True)
            return None
        except Exception:
            logger.exception("Unexpected send_message failure chat_id=%s", chat_id, exc_info=True)
            return None
    return None


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
        except (TimedOut, BadRequest, Forbidden, TelegramError):
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
        except (TimedOut, BadRequest, Forbidden, TelegramError):
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
    except (TimedOut, BadRequest, Forbidden, TelegramError):
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


# ─────────────────────────────────────────────────────────────
# KEYBOARDS
# ─────────────────────────────────────────────────────────────


def language_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("🇬🇧 English", callback_data="lang_en"), InlineKeyboardButton("🇰🇭 ភាសាខ្មែរ", callback_data="lang_km")]]
    )


async def setup_keyboard(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> InlineKeyboardMarkup:
    _, username = await get_bot_identity(context.bot)
    add_url = f"https://t.me/{username}?startgroup=add" if username else "https://t.me/"
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr(context.bot_data, user_id, "add_btn"), url=add_url)],
            [InlineKeyboardButton(tr(context.bot_data, user_id, "check_btn"), callback_data="check_perm")],
        ]
    )


def action_keyboard(bot_data: dict[str, Any], admin_id: int, ikey: str) -> InlineKeyboardMarkup:
    lang = get_lang(bot_data, admin_id)
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(TEXTS[lang]["btn_ban"], callback_data=f"act:ban:{ikey}"),
                InlineKeyboardButton(TEXTS[lang]["btn_warn"], callback_data=f"act:warn:{ikey}"),
                InlineKeyboardButton(TEXTS[lang]["btn_ignore"], callback_data=f"act:ignore:{ikey}"),
            ]
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
        settings[list_key] = _dedupe_valid_extensions(settings.get(list_key, []), limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
    if not isinstance(settings.get("trusted_file_hashes"), list):
        settings["trusted_file_hashes"] = []
    settings["trusted_file_hashes"] = _dedupe_valid_hashes(settings.get("trusted_file_hashes", []), limit=max_trusted_file_hashes(bot_data))
    settings["protection_enabled"] = bool(settings.get("protection_enabled", True))
    settings["silent_mode"] = bool(settings.get("silent_mode", False))
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

def _safe_chat_id_from_payload(payload: str) -> int | None:
    try:
        return int(payload.rsplit("_", 1)[-1])
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
        except (TimedOut, BadRequest, Forbidden, TelegramError):
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


async def dashboard_home_keyboard(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> InlineKeyboardMarkup:
    _, username = await get_bot_identity(context.bot)
    add_url = f"https://t.me/{username}?startgroup=add" if username else "https://t.me/"
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_groups"), callback_data="nav:groups")],
        [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_add_group"), url=add_url)],
    ]
    if int(user_id) in BOT_OWNER_IDS:
        rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_developer"), callback_data="dev:home")])
    rows.append(
        [
            InlineKeyboardButton(tr(context.bot_data, user_id, "btn_help"), callback_data="nav:help"),
            InlineKeyboardButton(tr(context.bot_data, user_id, "btn_refresh"), callback_data="nav:home"),
        ]
    )
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
        await query.answer(tr(bot_data, user_id, "config_private_only"), show_alert=True)
    except TelegramError as exc:
        logger.exception("Could not answer private-only callback warning", exc_info=True)


async def render_home(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "home_title"), await dashboard_home_keyboard(context, user_id))


async def render_help_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "help"), dashboard_back_home_keyboard(context.bot_data, user_id))


async def render_groups_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    async with BOT_DATA_LOCK:
        groups = get_groups(context.bot_data, user_id)

    if int(user_id) not in BOT_OWNER_IDS and groups:
        checks = await asyncio.gather(
            *(is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=False) for chat_id in groups),
            return_exceptions=True,
        )
        authorized_groups = [chat_id for chat_id, ok in zip(groups, checks) if ok is True]
        if len(authorized_groups) != len(groups):
            async with BOT_DATA_LOCK:
                state = get_user_state(context.bot_data, user_id)
                state["groups"] = authorized_groups
                await persist_context_memory(context, reason="dashboard_admin_prune", force=True, caller_holds_lock=True)
        groups = authorized_groups

    if not groups:
        kb = InlineKeyboardMarkup(
            [
                [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_add_group"), url=(await dashboard_home_keyboard(context, user_id)).inline_keyboard[1][0].url)],
                [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")],
            ]
        )
        await send_or_edit_panel(update, tr(context.bot_data, user_id, "groups_empty"), kb)
        return

    rows: list[list[InlineKeyboardButton]] = []
    lines = [tr(context.bot_data, user_id, "groups_title")]
    sem = asyncio.Semaphore(5)

    async def describe_group(chat_id: int) -> tuple[int, str, str]:
        async with sem:
            async with BOT_DATA_LOCK:
                title = get_chat_title_from_state(context.bot_data, chat_id)
                perms = get_bot_member_from_state(context.bot_data, chat_id)
                if perms is None or perms.status == "unknown":
                    permission = tr(context.bot_data, user_id, "perm_unknown")
                else:
                    permission = tr(context.bot_data, user_id, "perm_ok" if has_delete_permission(perms) else "perm_no")
                settings = dict(get_group_settings(context.bot_data, chat_id))
                card = tr(
                    context.bot_data,
                    user_id,
                    "group_card",
                    group=h(title),
                    permission=permission,
                    protection=_on_off(context.bot_data, user_id, bool(settings.get("protection_enabled"))),
                    strictness=_strictness_label(context.bot_data, user_id, str(settings.get("strictness", "standard"))),
                    silent=_on_off(context.bot_data, user_id, bool(settings.get("silent_mode")), key_on="silent_on", key_off="silent_off"),
                )
            return chat_id, title, card

    described = await asyncio.gather(*(describe_group(chat_id) for chat_id in groups), return_exceptions=True)
    for item in described:
        if isinstance(item, Exception):
            logger.exception("Group dashboard render failed", exc_info=(type(item), item, item.__traceback__))
            continue
        chat_id, title, card = item
        lines.append(card)
        rows.append([InlineKeyboardButton(f"⚙️ {title[:32]}", callback_data=f"grp:{chat_id}")])

    rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_refresh"), callback_data="nav:groups")])
    rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")])
    await send_or_edit_panel(update, "\n\n".join(lines), InlineKeyboardMarkup(rows))


def group_settings_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_protection_status"), callback_data=f"gap:{chat_id}:protection"), InlineKeyboardButton(tr(bot_data, user_id, "btn_scanner_settings"), callback_data=f"gap:{chat_id}:scanner")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_incident_logs"), callback_data=f"gap:{chat_id}:incidents"), InlineKeyboardButton(tr(bot_data, user_id, "btn_member_risk"), callback_data=f"gap:{chat_id}:risk")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_admin_alert_status"), callback_data=f"gap:{chat_id}:admins"), InlineKeyboardButton(tr(bot_data, user_id, "btn_group_health"), callback_data=f"gap:{chat_id}:health")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_blocked_formats"), callback_data=f"gfmt:{chat_id}:menu"), InlineKeyboardButton(tr(bot_data, user_id, "btn_allowed_formats"), callback_data=f"gallow:{chat_id}:menu")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_silent_mode"), callback_data=f"gset:{chat_id}:silent"), InlineKeyboardButton(tr(bot_data, user_id, "btn_strictness_level"), callback_data=f"gset:{chat_id}:strictness")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_auto_actions"), callback_data=f"gap:{chat_id}:auto")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_trusted_hashes"), callback_data=f"ghash:{chat_id}:menu")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_refresh"), callback_data=f"gap:{chat_id}:refresh")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data="nav:groups")],
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


async def render_group_settings_panel(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    chat_id: int,
    *,
    notice: str = "",
) -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        settings = dict(get_group_settings(context.bot_data, chat_id))
        allowed = format_extension_list(settings.get("allowed_extensions", []))
        custom_blocked = format_extension_list(settings.get("custom_blocked_extensions", []))
        text = tr(
            context.bot_data,
            user_id,
            "group_admin_title",
            group=h(title),
            chat_id=chat_id,
            protection=_on_off(context.bot_data, user_id, bool(settings.get("protection_enabled"))),
            strictness=_strictness_label(context.bot_data, user_id, str(settings.get("strictness", "standard"))),
            silent=_on_off(context.bot_data, user_id, bool(settings.get("silent_mode")), key_on="silent_on", key_off="silent_off"),
            allowed=h(allowed),
            custom_blocked=h(custom_blocked),
            trusted_hashes=len(settings.get("trusted_file_hashes", [])) if isinstance(settings.get("trusted_file_hashes"), list) else 0,
            auto_action=h(_auto_action_label(settings.get("auto_action_mode"))),
        )
        keyboard = group_settings_keyboard(context.bot_data, user_id, chat_id)
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


def _group_back_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")], [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")]])


def _protection_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    settings = get_group_settings(bot_data, chat_id)
    protection_key = "btn_turn_off" if settings.get("protection_enabled", True) else "btn_turn_on"
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(tr(bot_data, user_id, protection_key), callback_data=f"gset:{chat_id}:protection")],
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_strictness_level"), callback_data=f"gset:{chat_id}:strictness"), InlineKeyboardButton(tr(bot_data, user_id, "btn_silent_mode"), callback_data=f"gset:{chat_id}:silent")],
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_auto_actions"), callback_data=f"gap:{chat_id}:auto")],
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")],
        [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")],
    ])


async def render_group_protection_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, *, notice: str = "") -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        settings = dict(get_group_settings(context.bot_data, chat_id))
        perms = get_bot_member_from_state(context.bot_data, chat_id)
        bot_permission = "unknown" if perms is None else ("delete-ok" if has_delete_permission(perms) else "need-delete-permission")
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
        handled = "✅" if incident.get("done") else "⏳"
        action = str(incident.get("action") or incident.get("auto_action") or "pending")
        lines.append(f"{idx}. {handled} <code>{h(incident.get('file_name', 'unknown'))}</code>\n   👤 {h(incident.get('sender_name', incident.get('sender_id', 'unknown')))} <code>{h(incident.get('sender_id', ''))}</code>\n   🧪 {h(incident.get('scan_reason') or incident.get('reason') or 'blocked')}\n   ⚙️ action: <code>{h(action)}</code> · <code>{h(created)}</code>")
    if not lines:
        lines.append(tr(context.bot_data, user_id, "incidents_empty"))
    keyboard = InlineKeyboardMarkup([[InlineKeyboardButton(tr(context.bot_data, user_id, "btn_refresh"), callback_data=f"gap:{chat_id}:incidents")], [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_clear_handled"), callback_data=f"gap:{chat_id}:clear_incidents")], [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")], [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")]])
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
        if action == "warn": entry["warned"] += 1
        elif action == "mute": entry["muted"] += 1
        elif action == "ban": entry["banned"] += 1
    ranked = sorted(stats.items(), key=lambda item: (item[1]["blocked"], item[1]["warned"], item[1]["muted"], item[1]["banned"]), reverse=True)[:10]
    lines = []
    for idx, (target_id, data) in enumerate(ranked, 1):
        profile = known_users.get(str(target_id), {}) if isinstance(known_users.get(str(target_id), {}), dict) else {}
        name = str(profile.get("full_name") or data.get("name") or target_id)
        blocked = int(data.get("blocked", 0))
        risk = "High" if blocked >= 3 else ("Medium" if blocked >= 2 else "Low")
        lines.append(f"{idx}. {user_link(target_id, name)} — Risk: <code>{risk}</code> · blocked: <code>{blocked}</code> · warns: <code>{data.get('warned', 0)}</code>")
    if not lines:
        lines.append(tr(context.bot_data, user_id, "member_risk_empty"))
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "member_risk_title", group=h(title), items="\n".join(lines)), _group_back_keyboard(context.bot_data, user_id, chat_id))


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
    return InlineKeyboardMarkup([[InlineKeyboardButton(tr(bot_data, user_id, "btn_auto_off"), callback_data=f"gauto:{chat_id}:off")], [InlineKeyboardButton(tr(bot_data, user_id, "btn_auto_warn"), callback_data=f"gauto:{chat_id}:warn")], [InlineKeyboardButton(tr(bot_data, user_id, "btn_auto_smart"), callback_data=f"gauto:{chat_id}:smart")], [InlineKeyboardButton(tr(bot_data, user_id, "btn_auto_ban"), callback_data=f"gauto:{chat_id}:ban")], [InlineKeyboardButton(tr(bot_data, user_id, "btn_back"), callback_data=f"grp:{chat_id}")], [InlineKeyboardButton(tr(bot_data, user_id, "btn_home"), callback_data="nav:home")]])


async def render_auto_actions_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, *, notice: str = "") -> None:
    async with BOT_DATA_LOCK:
        title = get_chat_title_from_state(context.bot_data, chat_id)
        settings = dict(get_group_settings(context.bot_data, chat_id))
        text = tr(context.bot_data, user_id, "auto_title", group=h(title), mode=h(_auto_action_label(settings.get("auto_action_mode"))), warn_threshold=int(settings.get("auto_warn_threshold", 1)), mute_threshold=int(settings.get("auto_mute_threshold", 2)), ban_threshold=int(settings.get("auto_ban_threshold", 3)), mute_minutes=int(settings.get("auto_mute_minutes", 60)))
        keyboard = _auto_actions_keyboard(context.bot_data, user_id, chat_id)
    if notice:
        text = f"{notice}\n\n{text}"
    await send_or_edit_panel(update, text, keyboard)


# ─────────────────────────────────────────────────────────────
# DEVELOPER DASHBOARD - BUTTON ONLY
# ─────────────────────────────────────────────────────────────

DEV_USERS_PAGE_SIZE = 8
DEV_GROUPS_PAGE_SIZE = 10


def _developer_keyboard(bot_data: dict[str, Any], user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_dev_users"), callback_data="dev:users:0")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_dev_groups"), callback_data="dev:groups:0")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_dev_memory"), callback_data="dev:memory")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_dev_hash_config"), callback_data="dev:hash")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_refresh"), callback_data="dev:refresh")],
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
    return int(user_id) in BOT_OWNER_IDS


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


async def render_developer_dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
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
    await query.answer()
    if not await is_admin_or_owner(context, user_id, allow_api=False):
        await safe_edit_query(query, tr(context.bot_data, user_id, "access_denied"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return
    data = query.data or ""
    if data == "nav:home":
        await clear_pending_format_edit(context, user_id)
        await render_home(update, context, user_id)
    elif data == "nav:groups":
        await clear_pending_format_edit(context, user_id)
        await render_groups_panel(update, context, user_id)
    elif data == "nav:help":
        await clear_pending_format_edit(context, user_id)
        await render_help_panel(update, context, user_id)
    else:
        await clear_pending_format_edit(context, user_id)
        await render_home(update, context, user_id)


async def developer_dashboard_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    user_id = int(query.from_user.id)
    if not callback_is_private(query):
        await reject_group_config_callback(query, context.bot_data, user_id)
        return
    await query.answer()
    if not _dev_is_owner(user_id):
        await safe_edit_query(query, tr(context.bot_data, user_id, "dev_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return

    data = query.data or "dev:home"
    parts = data.split(":")
    action = parts[1] if len(parts) > 1 else "home"

    if action in {"home", "refresh"}:
        await render_developer_dashboard(update, context, user_id)
        return
    if action == "memory":
        await render_developer_memory_panel(update, context, user_id)
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
    await query.answer()
    data = query.data or ""
    chat_id = _safe_chat_id_from_payload(data)
    if chat_id is None:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
        return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id))
        return
    schedule_bot_member_refresh(context, chat_id)
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
    await query.answer()
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
    schedule_bot_member_refresh(context, chat_id)

    async with BOT_DATA_LOCK:
        settings = get_group_settings(context.bot_data, chat_id)
        if field == "protection":
            settings["protection_enabled"] = not bool(settings.get("protection_enabled", True))
        elif field == "strictness":
            current_strictness = str(settings.get("strictness") or "standard")
            settings["strictness"] = {"standard": "high", "high": "strict", "strict": "standard"}.get(current_strictness, "standard")
        elif field == "silent":
            settings["silent_mode"] = not bool(settings.get("silent_mode", False))
        else:
            await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
            return
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
    await query.answer()
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
    await query.answer()
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
    await query.answer()
    parts = (query.data or "").split(":", 2)
    if len(parts) != 3:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    _, chat_id_raw, action = parts
    try: chat_id = int(chat_id_raw)
    except ValueError:
        await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id)); return
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
    await query.answer()
    parts = (query.data or "").split(":", 2)
    if len(parts) != 3: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    _, chat_id_raw, ext_raw = parts
    try: chat_id = int(chat_id_raw)
    except ValueError: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    ext = _normalize_extension(ext_raw)
    if not VALID_EXTENSION_RE.fullmatch(ext): await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id)); return
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
    await query.answer()
    parts = (query.data or "").split(":", 2)
    if len(parts) != 3: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    _, chat_id_raw, action = parts
    try: chat_id = int(chat_id_raw)
    except ValueError: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id)); return
    schedule_bot_member_refresh(context, chat_id)
    await link_user_to_group(context, user_id, chat_id)
    if action == "refresh": await render_group_settings_panel(update, context, user_id, chat_id)
    elif action == "protection": await render_group_protection_panel(update, context, user_id, chat_id)
    elif action == "scanner":
        async with BOT_DATA_LOCK: title = get_chat_title_from_state(context.bot_data, chat_id)
        await send_or_edit_panel(update, tr(context.bot_data, user_id, "scanner_panel_title", group=h(title), scanner=scanner_group_config_text(context.bot_data, user_id, chat_id)), _group_back_keyboard(context.bot_data, user_id, chat_id))
    elif action == "incidents": await render_group_incidents_panel(update, context, user_id, chat_id)
    elif action == "clear_incidents":
        async with BOT_DATA_LOCK:
            incidents = context.bot_data.get("incidents", {}) if isinstance(context.bot_data.get("incidents", {}), dict) else {}
            for ikey, incident in list(incidents.items()):
                if isinstance(incident, dict) and str(incident.get("chat_id")) == str(int(chat_id)) and incident.get("done"):
                    incidents.pop(ikey, None)
            await persist_context_memory(context, reason="group_clear_handled_incidents", force=True, caller_holds_lock=True)
        await render_group_incidents_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "incidents_cleared"))
    elif action == "risk": await render_group_risk_panel(update, context, user_id, chat_id)
    elif action == "admins": await render_group_admin_alert_panel(update, context, user_id, chat_id)
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
    await query.answer()
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
    await query.answer()
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
    async with BOT_DATA_LOCK:
        remove_trusted_file_hash(context.bot_data, chat_id, digest_prefix)
        await persist_context_memory(context, reason="trusted_hash_remove", force=True, caller_holds_lock=True)
    await render_trusted_hash_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "trusted_hash_removed"))


async def auto_actions_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user: return
    user_id = query.from_user.id
    if not callback_is_private(query): await reject_group_config_callback(query, context.bot_data, user_id); return
    await query.answer()
    parts = (query.data or "").split(":", 2)
    if len(parts) != 3: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    _, chat_id_raw, mode = parts
    try: chat_id = int(chat_id_raw)
    except ValueError: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    if mode not in {"off", "warn", "smart", "ban"}: await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error")); return
    if not await is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=True):
        await safe_edit_query(query, tr(context.bot_data, user_id, "group_admin_only"), reply_markup=dashboard_back_home_keyboard(context.bot_data, user_id)); return
    async with BOT_DATA_LOCK:
        settings = get_group_settings(context.bot_data, chat_id); settings["auto_action_mode"] = mode
        await persist_context_memory(context, reason="auto_action_update", force=True, caller_holds_lock=True)
    await render_auto_actions_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "auto_saved"))


async def private_text_flow_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    chat = update.effective_chat
    if not user or not message or not chat or chat.type != ChatType.PRIVATE:
        return

    async with BOT_DATA_LOCK:
        user_state = context.bot_data.get("user_state", {})
        state = (user_state.get(user.id) or user_state.get(str(user.id)) or {}) if isinstance(user_state, dict) else {}
        pending = dict(state.get("pending_format_edit")) if isinstance(state, dict) and isinstance(state.get("pending_format_edit"), dict) else None
    text = (message.text or "").strip()
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
    mode = str(pending.get("mode") or "add")

    if not await is_user_admin_in_group(context, chat_id, user.id, allow_api=True):
        await clear_pending_format_edit(context, user.id)
        await safe_reply(update, tr(context.bot_data, user.id, "group_admin_only"), reply_markup=await dashboard_home_keyboard(context, user.id))
        return

    if mode == "hash_add":
        digest = normalize_sha256_hash(text)
        if not digest:
            await safe_reply(update, tr(context.bot_data, user.id, "trusted_hash_invalid"))
            return
        async with BOT_DATA_LOCK:
            settings = get_group_settings(context.bot_data, chat_id)
            if digest not in settings.get("trusted_file_hashes", []) and len(settings.get("trusted_file_hashes", [])) >= max_trusted_file_hashes(context.bot_data):
                await safe_reply(update, tr(context.bot_data, user.id, "trusted_hash_limit"))
                return
            add_trusted_file_hash(context.bot_data, chat_id, digest, added_by=user.id, file_name="manual hash")
            state = get_user_state(context.bot_data, user.id)
            state.pop("pending_format_edit", None)
            await persist_context_memory(context, reason="trusted_hash_add_manual", force=True, caller_holds_lock=True)
        await render_trusted_hash_panel(update, context, user.id, chat_id, notice=tr(context.bot_data, user.id, "trusted_hash_saved"))
        return

    parsed = parse_extensions_from_text(text)
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
                settings["allowed_extensions"] = _dedupe_valid_extensions([*current, *parsed], limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
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
    allowed = matched_ext if matched_ext in allowed_exts else next((ext for ext in suffixes if ext in allowed_exts), "")
    if allowed:
        return replace(scan, blocked=False, reason_code="allowed_extension", reason_display=f"allowed by group settings: {allowed}")

    custom_blocked = set(settings.get("custom_blocked_extensions", []))
    custom_match = last_ext if last_ext in custom_blocked else next((ext for ext in suffixes if ext in custom_blocked), "")
    if custom_match:
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
        scan_result=scan_result,
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
            sent_id = await safe_send_message(context, chat_id, TEXTS[lang]["warn_in_group"].format(user=mention))
            result = "warned" if sent_id is not None else "warn-failed"
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
    await query.answer()

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
    await query.answer()

    user_id = query.from_user.id
    retry_kb = InlineKeyboardMarkup([[InlineKeyboardButton(tr(context.bot_data, user_id, "check_btn"), callback_data="check_perm")]])
    groups = await get_groups_snapshot(context.bot_data, user_id)
    if not groups:
        await safe_edit_query(query, tr(context.bot_data, user_id, "no_group"), reply_markup=retry_kb)
        return

    async def check_one(chat_id: int) -> str | None:
        try:
            title = get_chat_title_from_state(context.bot_data, chat_id)
            perms = await get_bot_member_cached(context, chat_id)
            safe_title = h(title)
            if perms.status not in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"}:
                return f"❌ <b>{safe_title}</b>\n{tr(context.bot_data, user_id, 'not_admin')}"
            if not perms.can_delete_messages:
                return f"⚠️ <b>{safe_title}</b>\n{tr(context.bot_data, user_id, 'no_delete_perm')}"
            return f"✅ <b>{safe_title}</b>\n{tr(context.bot_data, user_id, 'setup_ok', group=safe_title)}"
        except (Forbidden, BadRequest) as exc:
            logger.exception("Permission check failed chat_id=%s and group was purged from saved list", chat_id, exc_info=True)
            await purge_group_state(context, chat_id, reason="remove_stale_group")
            return None
        except TelegramError as exc:
            logger.exception("Permission check failed chat_id=%s", chat_id, exc_info=True)
            return None

    sem = asyncio.Semaphore(5)

    async def guarded(chat_id: int) -> str | None:
        async with sem:
            return await check_one(chat_id)

    results = await asyncio.gather(*(guarded(chat_id) for chat_id in groups), return_exceptions=True)
    lines: list[str] = []
    for item in results:
        if isinstance(item, str) and item:
            lines.append(item)
        elif isinstance(item, Exception):
            logger.exception("Permission check task failed", exc_info=(type(item), item, item.__traceback__))

    await safe_edit_query(query, "\n\n".join(lines) if lines else tr(context.bot_data, user_id, "no_group"), reply_markup=retry_kb)


async def action_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.from_user:
        return
    await query.answer()

    admin_id = query.from_user.id
    data = query.data or ""
    parts = data.split(":", 2)
    if len(parts) != 3:
        await safe_edit_query(query, tr(context.bot_data, admin_id, "unknown_error"))
        return
    _, action, ikey = parts
    if action not in {"ban", "warn", "ignore"}:
        await safe_edit_query(query, tr(context.bot_data, admin_id, "unknown_error"))
        return

    lock = await get_incident_lock(ikey)
    async with lock:
        async with BOT_DATA_LOCK:
            incidents = context.bot_data.setdefault("incidents", {})
            incident = incidents.get(ikey)
            if not incident:
                await safe_edit_query(query, tr(context.bot_data, admin_id, "action_expired"))
                return
            if incident.get("done"):
                await safe_edit_query(query, tr(context.bot_data, admin_id, "action_done"))
                return
            chat_id = int(incident["chat_id"])
            sender_id = int(incident.get("sender_id", 0))
            sender_name_raw = str(incident.get("sender_name") or "Unknown")

        if not await is_user_admin_in_group(context, chat_id, admin_id, allow_api=True):
            await safe_edit_query(query, tr(context.bot_data, admin_id, "action_not_admin"))
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
                sent_id = await safe_send_message(context, chat_id, warn_text)
                if sent_id is None:
                    raise TelegramError("warning message could not be delivered")
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
            await persist_context_memory(context, reason="incident_action", force=True, caller_holds_lock=True)
            final_text = format_incident_alert_for_admin(context.bot_data, admin_id, incident)

        if not action_success and result_msg:
            final_text += f"\n\n{result_msg}"
        await safe_edit_query(query, final_text)

        if action_success:
            clicked_message_id = int(query.message.message_id) if query.message else None
            await sync_handled_alert_messages(context, incident, exclude_admin_id=admin_id, exclude_message_id=clicked_message_id)


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
        await purge_group_state(context, chat.id, reason="bot_lost_group_access")
        return

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
        kb = InlineKeyboardMarkup(
            [
                [InlineKeyboardButton(tr(context.bot_data, adder.id, "btn_settings"), callback_data=f"grp:{chat.id}")],
                [InlineKeyboardButton(tr(context.bot_data, adder.id, "check_btn"), callback_data="check_perm")],
                [InlineKeyboardButton(tr(context.bot_data, adder.id, "btn_home"), callback_data="nav:home")],
            ]
        )
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

    document = message.document
    file_name = normalize_filename(getattr(document, "file_name", None))
    file_size = int(getattr(document, "file_size", 0) or 0)
    if file_size <= 0 or file_size > trusted_hash_max_download_bytes(context.bot_data):
        await safe_reply(update, tr(context.bot_data, user.id, "trusted_hash_file_too_large"))
        return

    data = await _download_document_bytes_for_scanner(context, document, file_name=file_name, file_size=file_size)
    if data is None:
        await safe_reply(update, tr(context.bot_data, user.id, "trusted_hash_invalid"))
        return
    digest = calculate_file_hash(data)

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
    user_id = update.effective_user.id if update.effective_user else None
    if not message or not chat or not message.document or not is_group_chat(chat.type):
        return

    try:
        scan = await scan_document(context, message.document, chat_id=chat.id)
        async with BOT_DATA_LOCK:
            scan = apply_group_scan_policy(context.bot_data, chat.id, scan)
    except Exception:
        logger.exception("Document scanner failed chat_id=%s message_id=%s", getattr(chat, "id", None), getattr(message, "message_id", None), exc_info=True)
        await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "unknown_error"))
        return

    if not scan.blocked:
        return

    sender = message.from_user
    sender_id = sender.id if sender else 0
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
        if not settings.get("silent_mode", False):
            group_notice = tr_group(context.bot_data, chat.id, "exe_removed_group", user=user_mention, reason=scan_reason)
            await safe_send_message(context, chat.id, group_notice)

        ikey = incident_key(chat.id, sender_id, message.message_id)
        async with BOT_DATA_LOCK:
            context.bot_data.setdefault("incidents", {})[ikey] = {
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
            await persist_context_memory(context, reason="incident_created", force=True, caller_holds_lock=True)
        await maybe_apply_auto_action(context, chat_id=chat.id, sender_id=sender_id, sender_name=sender_name_raw, ikey=ikey)
        await notify_admins(context, chat.id, chat.title or str(chat.id), sender, file_name, ikey, scan_reason)
    except Exception:
        logger.exception("Post-delete incident workflow failed chat_id=%s user_id=%s", chat.id, user_id, exc_info=True)
        await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "unknown_error"))


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
            tr(context.bot_data, user_id, "scanname_blocked", file=h(result.file_name), reason=describe_scan_reason(result.reason_code, (result.reason_display, *result.details))),
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
    await persist_context_memory(application, reason="shutdown", force=True)
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
        f"Supabase: <code>{'connected' if SUPABASE_AVAILABLE else 'offline/disabled'}</code>\n"
        f"Redis: <code>{'connected' if REDIS_AVAILABLE else 'offline/disabled'}</code>"
    )
    await safe_reply(update, text)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled exception while processing update", exc_info=context.error)


def build_application() -> Application:
    persistence = PicklePersistence(filepath=PERSISTENCE_FILE) if LOCAL_PERSISTENCE_ENABLED else None

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

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("settings", settings_command))
    app.add_handler(CommandHandler("admins", admins_command))
    app.add_handler(CommandHandler("scanner", scanner_command))
    app.add_handler(CommandHandler("scanname", scanname_command))
    app.add_handler(CommandHandler("memory", memory_command))
    app.add_handler(CommandHandler("debug", debug_command))
    app.add_handler(CallbackQueryHandler(lang_callback, pattern=r"^lang_(en|km)$"))
    app.add_handler(CallbackQueryHandler(navigation_callback, pattern=r"^nav:(home|groups|help)$"))
    app.add_handler(CallbackQueryHandler(developer_dashboard_callback, pattern=r"^dev:(home|refresh|memory|hash(?::(?:toggle|size(?::\d+)?|limit(?::\d+)?))?|users(?::\d+)?|user:-?\d+|groups(?::\d+)?)$"))
    app.add_handler(CallbackQueryHandler(group_dashboard_callback, pattern=r"^grp:-?\d+$"))
    app.add_handler(CallbackQueryHandler(group_admin_panel_callback, pattern=r"^gap:-?\d+:(protection|scanner|incidents|risk|admins|allowed|health|auto|clear_incidents|refresh)$"))
    app.add_handler(CallbackQueryHandler(group_settings_callback, pattern=r"^gset:-?\d+:(protection|strictness|silent)$"))
    app.add_handler(CallbackQueryHandler(format_manager_callback, pattern=r"^gfmt:-?\d+:(menu|add|edit|remove|clear)$"))
    app.add_handler(CallbackQueryHandler(delete_format_callback, pattern=r"^gfmtdel:-?\d+:[A-Za-z0-9_.+-]{1,16}$"))
    app.add_handler(CallbackQueryHandler(allowed_formats_callback, pattern=r"^gallow:-?\d+:(menu|add|edit|remove|clear)$"))
    app.add_handler(CallbackQueryHandler(delete_allowed_format_callback, pattern=r"^gallowdel:-?\d+:[A-Za-z0-9_.+-]{1,16}$"))
    app.add_handler(CallbackQueryHandler(trusted_hash_callback, pattern=r"^ghash:-?\d+:(menu|add|remove|clear)$"))
    app.add_handler(CallbackQueryHandler(delete_trusted_hash_callback, pattern=r"^ghashdel:-?\d+:[a-fA-F0-9]{12}$"))
    app.add_handler(CallbackQueryHandler(auto_actions_callback, pattern=r"^gauto:-?\d+:(off|warn|smart|ban)$"))
    app.add_handler(CallbackQueryHandler(check_perm_callback, pattern=r"^check_perm$"))
    app.add_handler(CallbackQueryHandler(action_callback, pattern=r"^act:(ban|warn|ignore):.+$"))
    app.add_handler(ChatMemberHandler(my_chat_member_update, ChatMemberHandler.MY_CHAT_MEMBER))
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
    """
    Python 3.14 no longer creates a default event loop for MainThread.
    python-telegram-bot's run_webhook/run_polling still asks asyncio for the
    current loop internally, so create and set one explicitly before calling it.
    """
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        logger.info("Created and set a MainThread asyncio event loop for Python 3.14 compatibility.")

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
