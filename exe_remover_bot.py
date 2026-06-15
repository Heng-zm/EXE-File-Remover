

from __future__ import annotations

import asyncio
import io
import logging
import os
import pickle
import re
import secrets
import time
import unicodedata
import zipfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from html import escape as html_escape
from typing import Any, Generic, Iterable, TypeVar

import httpx
from dotenv import load_dotenv

try:
    import redis.asyncio as redis_async
except ImportError:  # Redis is optional; the bot falls back to local pickle persistence.
    redis_async = None  # type: ignore[assignment]
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatMemberStatus, ChatType, ParseMode
from telegram.error import BadRequest, Forbidden, TelegramError, TimedOut
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
MAX_ARCHIVE_MEMBERS_TO_SCAN = _env_int("MAX_ARCHIVE_MEMBERS_TO_SCAN", 500, min_value=1, max_value=5000)
MAX_CUSTOM_BLOCKED_EXTENSIONS = _env_int("MAX_CUSTOM_BLOCKED_EXTENSIONS", 64, min_value=1, max_value=256)
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
KEEP_AWAKE_CLIENT: httpx.AsyncClient | None = None
REDIS_CLIENT: Any | None = None
REDIS_AVAILABLE = False
REDIS_LAST_SAVE_MONOTONIC = 0.0
REDIS_LAST_SAVE_UTC = "never"


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
            "/memory — Show Redis/user memory status"
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
            "Archive extensions: <code>{archives}</code>"
        ),
        "scanname_usage": "Usage: <code>/scanname invoice.pdf.exe</code>",
        "scanname_blocked": "🚫 <b>Blocked:</b> <code>{file}</code>\n🧪 <b>Reason:</b> {reason}",
        "scanname_clean": "✅ <b>No filename-only danger found:</b> <code>{file}</code>",
        "memory_status": (
            "🧠 <b>Bot Memory</b>\n"
            "Backend: <code>{backend}</code>\n"
            "Redis: <code>{redis}</code>\n"
            "Known users: <code>{users}</code>\n"
            "Saved groups: <code>{groups}</code>\n"
            "Open incidents: <code>{incidents}</code>\n"
            "Last Redis save: <code>{last_save}</code>"
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
            "/memory — មើលស្ថានភាព Redis/User memory"
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
            "Extension archive: <code>{archives}</code>"
        ),
        "scanname_usage": "ប្រើ: <code>/scanname invoice.pdf.exe</code>",
        "scanname_blocked": "🚫 <b>Blocked:</b> <code>{file}</code>\n🧪 <b>មូលហេតុ:</b> {reason}",
        "scanname_clean": "✅ <b>រកមិនឃើញគ្រោះថ្នាក់តាមឈ្មោះ:</b> <code>{file}</code>",
        "memory_status": (
            "🧠 <b>Bot Memory</b>\n"
            "Backend: <code>{backend}</code>\n"
            "Redis: <code>{redis}</code>\n"
            "អ្នកប្រើប្រាស់ដែលបានចងចាំ: <code>{users}</code>\n"
            "ក្រុមដែលបានរក្សាទុក: <code>{groups}</code>\n"
            "ករណីកំពុងបើក: <code>{incidents}</code>\n"
            "Redis save ចុងក្រោយ: <code>{last_save}</code>"
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
            "Send <code>/cancel</code> to stop."
        ),
        "formats_prompt_edit": (
            "✏️ <b>Edit delete format list</b>\n\n"
            "Send the complete new list. Old custom formats will be replaced.\n"
            "Example: <code>.apk .zip .pdf</code>\n\n"
            "Send <code>/cancel</code> to stop."
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
            "ផ្ញើ <code>/cancel</code> ដើម្បីបោះបង់។"
        ),
        "formats_prompt_edit": (
            "✏️ <b>កែបញ្ជី delete formats</b>\n\n"
            "ផ្ញើបញ្ជីថ្មីទាំងមូល។ បញ្ជីចាស់នឹងត្រូវជំនួស។\n"
            "ឧទាហរណ៍: <code>.apk .zip .pdf</code>\n\n"
            "ផ្ញើ <code>/cancel</code> ដើម្បីបោះបង់។"
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

DEFAULT_GROUP_SETTINGS: dict[str, Any] = {
    "protection_enabled": True,
    "strictness": "standard",  # standard=.exe/PE only, high=all dangerous extensions
    "silent_mode": False,
    "allowed_extensions": [],
    "custom_blocked_extensions": [],
}

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
    # Persist lightweight caches so private dashboards can render without live API calls after restart.
    "chat_meta_cache",
    "admin_ids_cache",
    "bot_member_cache",
)


def redis_configured() -> bool:
    return bool(REDIS_ENABLED and REDIS_URL and redis_async is not None)


def storage_backend_label() -> str:
    if REDIS_AVAILABLE:
        return "redis+local" if LOCAL_PERSISTENCE_ENABLED else "redis"
    if REDIS_ENABLED and not REDIS_URL:
        return "local (REDIS_URL missing)"
    if REDIS_ENABLED and redis_async is None:
        return "local (redis package missing)"
    return "local"


def export_bot_data_for_storage(bot_data: dict[str, Any]) -> dict[str, Any]:
    """Store only durable bot data. Runtime locks/caches stay outside bot_data."""
    exported: dict[str, Any] = {}
    for key in PERSISTED_BOT_DATA_KEYS:
        value = bot_data.get(key)
        if value is not None:
            exported[key] = value
    exported["_meta"] = {
        "saved_at_ms": now_ms(),
        "schema": 2,
        "bot": "exe_remover_bot",
    }
    return exported


def merge_loaded_bot_data(bot_data: dict[str, Any], loaded: dict[str, Any]) -> None:
    for key in PERSISTED_BOT_DATA_KEYS:
        value = loaded.get(key)
        if isinstance(value, dict):
            bot_data[key] = value


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
        logger.warning("Redis memory unavailable; local persistence fallback is active: %s", exc)
        return

    try:
        raw = await REDIS_CLIENT.get(REDIS_STATE_KEY)
        if raw:
            loaded = pickle.loads(raw)
            if isinstance(loaded, dict):
                async with BOT_DATA_LOCK:
                    merge_loaded_bot_data(application.bot_data, loaded)
                logger.info(
                    "Loaded Redis memory: users=%s groups=%s incidents=%s",
                    len(application.bot_data.get("known_users", {})),
                    len(application.bot_data.get("group_state", {})),
                    len(application.bot_data.get("incidents", {})),
                )
    except Exception as exc:
        logger.warning("Could not load Redis memory. Continuing with current local state: %s", exc)


async def save_bot_data_to_redis(bot_data: dict[str, Any], *, reason: str = "manual", force: bool = False) -> bool:
    """Persist durable memory to Redis. Never raises into handlers."""
    global REDIS_LAST_SAVE_MONOTONIC, REDIS_LAST_SAVE_UTC

    if not (REDIS_AVAILABLE and REDIS_CLIENT is not None):
        return False

    now = time.monotonic()
    if not force and REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS > 0:
        if now - REDIS_LAST_SAVE_MONOTONIC < REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS:
            return False

    async with REDIS_SAVE_LOCK:
        try:
            async with BOT_DATA_LOCK:
                payload = export_bot_data_for_storage(bot_data)
            encoded = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
            await REDIS_CLIENT.set(REDIS_STATE_KEY, encoded)
            REDIS_LAST_SAVE_MONOTONIC = time.monotonic()
            REDIS_LAST_SAVE_UTC = now_utc_str()
            logger.debug("Saved Redis memory reason=%s bytes=%s", reason, len(encoded))
            return True
        except Exception as exc:
            logger.warning("Redis memory save failed reason=%s: %s", reason, exc)
            return False


async def persist_context_memory(context: ContextTypes.DEFAULT_TYPE, *, reason: str, force: bool = False) -> None:
    await save_bot_data_to_redis(context.bot_data, reason=reason, force=force)


async def close_redis_memory() -> None:
    global REDIS_CLIENT, REDIS_AVAILABLE
    if REDIS_CLIENT is not None:
        try:
            await REDIS_CLIENT.aclose()
        except Exception as exc:
            logger.debug("Redis close failed: %s", exc)
    REDIS_CLIENT = None
    REDIS_AVAILABLE = False


# ─────────────────────────────────────────────────────────────
# HTML / STATE HELPERS
# ─────────────────────────────────────────────────────────────


def h(value: Any) -> str:
    """Escape text for Telegram HTML parse mode."""
    return html_escape(str(value), quote=False)


def user_link(user_id: int, name: str) -> str:
    return f'<a href="tg://user?id={int(user_id)}">{h(name)}</a>'


def get_user_state(bot_data: dict[str, Any], user_id: int) -> dict[str, Any]:
    user_state = bot_data.setdefault("user_state", {})
    return user_state.setdefault(user_id, {"lang": "en", "groups": []})


def get_lang(bot_data: dict[str, Any], user_id: int | None) -> str:
    if not user_id:
        return "en"
    lang = bot_data.get("user_state", {}).get(user_id, {}).get("lang", "en")
    return lang if lang in TEXTS else "en"


def tr(bot_data: dict[str, Any], user_id: int | None, key: str, **kwargs: Any) -> str:
    lang = get_lang(bot_data, user_id)
    text = TEXTS.get(lang, TEXTS["en"]).get(key, TEXTS["en"].get(key, key))
    return text.format(**kwargs) if kwargs else text


def get_groups(bot_data: dict[str, Any], user_id: int) -> list[int]:
    groups = bot_data.get("user_state", {}).get(user_id, {}).get("groups", [])
    return [int(g) for g in groups if isinstance(g, int) or str(g).lstrip("-").isdigit()]


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
    group_state = bot_data.setdefault("group_state", {})
    return group_state.setdefault(str(chat_id), {"lang": "en"})


def get_group_lang(bot_data: dict[str, Any], chat_id: int | None) -> str:
    if chat_id is None:
        return "en"
    lang = bot_data.get("group_state", {}).get(str(chat_id), {}).get("lang", "en")
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

    # Windows PE executables start with MZ. This catches renamed .exe files.
    if data.startswith(b"MZ"):
        return FileScanResult(True, "pe_magic_header", "file content starts with Windows executable MZ header", ("matched MZ header",), file_name, mime_type, ".exe")

    # Common non-Windows executable/script formats. These are still risky in groups.
    if data.startswith(b"\x7fELF"):
        return FileScanResult(True, "elf_magic_header", "file content starts with ELF executable header", ("matched ELF header",), file_name, mime_type)
    if data[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}:
        return FileScanResult(True, "macho_magic_header", "file content starts with Mach-O executable header", ("matched Mach-O header",), file_name, mime_type)
    if data.startswith(b"#!") and any(token in data[:256].lower() for token in (b"/sh", b"bash", b"python", b"node", b"powershell", b"cmd")):
        return FileScanResult(True, "script_shebang", "file content starts with executable script shebang", ("matched script shebang",), file_name, mime_type)

    if not SUSPICIOUS_ARCHIVE_SCAN_ENABLED:
        return None

    suffixes = filename_suffixes(lower_name)
    may_be_zip = data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08") or (suffixes and suffixes[-1] == ".zip")
    if may_be_zip:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()[:MAX_ARCHIVE_MEMBERS_TO_SCAN]
        except (zipfile.BadZipFile, RuntimeError, OSError, Exception) as exc:
            logger.debug("Archive scan skipped for %r: %s", file_name, exc)
            return None

        for member in names:
            result = scan_filename_only(member, "")
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


async def scan_document(context: ContextTypes.DEFAULT_TYPE, document: Any) -> FileScanResult:
    """Suspicious file scanner that avoids large downloads by default."""
    file_name = normalize_filename(getattr(document, "file_name", None))
    mime_type = (getattr(document, "mime_type", "") or "").casefold().strip()

    result = scan_filename_only(file_name, mime_type)
    if result.blocked:
        return result

    if not (SUSPICIOUS_SCANNER_ENABLED and SUSPICIOUS_MAGIC_SCAN_ENABLED and SCANNER_MAX_DOWNLOAD_BYTES > 0):
        return result

    file_size = int(getattr(document, "file_size", 0) or 0)
    if file_size <= 0 or file_size > SCANNER_MAX_DOWNLOAD_BYTES:
        return result

    try:
        tg_file = await context.bot.get_file(document.file_id)
        data = bytes(await tg_file.download_as_bytearray())
    except TelegramError as exc:
        logger.warning("Could not download file for scanner file_name=%r size=%s: %s", file_name, file_size, exc)
        return result
    except Exception as exc:
        logger.warning("Unexpected scanner download failure file_name=%r size=%s: %s", file_name, file_size, exc)
        return result

    magic_result = scan_file_bytes(result.file_name, result.mime_type, data)
    return magic_result or result


def now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def incident_key(chat_id: int, sender_id: int, message_id: int) -> str:
    return f"{chat_id}:{sender_id}:{message_id}:{now_ms()}"


def incident_timestamp_ms(ikey: str) -> int | None:
    try:
        return int(ikey.rsplit(":", 1)[-1])
    except (TypeError, ValueError):
        return None


async def get_incident_lock(ikey: str) -> asyncio.Lock:
    async with INCIDENT_LOCKS_LOCK:
        lock = INCIDENT_LOCKS.get(ikey)
        if lock is None:
            lock = asyncio.Lock()
            INCIDENT_LOCKS[ikey] = lock
        return lock


async def safe_send_message(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
    disable_web_page_preview: bool = True,
) -> int | None:
    try:
        sent = await context.bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode=ParseMode.HTML,
            reply_markup=reply_markup,
            disable_web_page_preview=disable_web_page_preview,
        )
        return int(sent.message_id)
    except Forbidden:
        return None
    except BadRequest as exc:
        logger.warning("send_message BadRequest chat_id=%s: %s", chat_id, exc)
        return None
    except TimedOut as exc:
        logger.warning("send_message timed out chat_id=%s: %s", chat_id, exc)
        return None
    except TelegramError as exc:
        logger.warning("send_message failed chat_id=%s: %s", chat_id, exc)
        return None


async def safe_reply(update: Update, text: str, *, reply_markup: InlineKeyboardMarkup | None = None) -> None:
    message = update.effective_message
    if not message:
        return
    try:
        await message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=reply_markup, disable_web_page_preview=True)
    except TelegramError as exc:
        logger.warning("reply failed: %s", exc)


async def safe_edit_query(query: Any, text: str, *, reply_markup: InlineKeyboardMarkup | None = None) -> None:
    try:
        await query.edit_message_text(
            text=text,
            parse_mode=ParseMode.HTML,
            reply_markup=reply_markup,
            disable_web_page_preview=True,
        )
    except BadRequest as exc:
        if "message is not modified" not in str(exc).casefold():
            logger.warning("edit_message_text failed: %s", exc)
    except TelegramError as exc:
        logger.warning("edit_message_text failed: %s", exc)


async def safe_edit_message(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    message_id: int,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> None:
    try:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=text,
            parse_mode=ParseMode.HTML,
            reply_markup=reply_markup,
            disable_web_page_preview=True,
        )
    except BadRequest as exc:
        if "message is not modified" not in str(exc).casefold():
            logger.warning("edit_message_text failed chat_id=%s message_id=%s: %s", chat_id, message_id, exc)
    except TelegramError as exc:
        logger.warning("edit_message_text failed chat_id=%s message_id=%s: %s", chat_id, message_id, exc)


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
    meta = bot_data.get("chat_meta_cache", {})
    if isinstance(meta, dict):
        item = meta.get(str(chat_id)) or meta.get(chat_id)
        if isinstance(item, dict) and item.get("title"):
            return str(item["title"])
    group = bot_data.get("group_state", {})
    if isinstance(group, dict):
        state = group.get(str(chat_id)) or group.get(chat_id)
        if isinstance(state, dict):
            for key in ("title", "group_name", "chat_title"):
                if state.get(key):
                    return str(state[key])
    return str(chat_id)


async def get_chat_title_cached(context: ContextTypes.DEFAULT_TYPE, chat_id: int, *, force: bool = False) -> str:
    """Cached chat title lookup for dashboard rendering.

    Dashboard code should call this instead of context.bot.get_chat().  It only
    hits Telegram when force=True or no cached title exists yet, then stores the
    simple metadata in bot_data so persistence can survive restarts.
    """
    title = get_chat_title_from_state(context.bot_data, chat_id)
    if title != str(chat_id) and not force:
        return title

    try:
        chat = await context.bot.get_chat(chat_id)
        await remember_chat_meta(context.bot_data, chat)
        return str(chat.title or chat_id)
    except TelegramError as exc:
        logger.info("Could not refresh chat metadata chat_id=%s: %s", chat_id, exc)
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
) -> list[int]:
    """Update one user's admin membership in both process and durable caches.

    Used by hybrid get_chat_member authorization so the full admin list does not
    need to be refetched during normal settings interactions.
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

    return updated_ids.copy()


async def get_chat_admin_ids_cached(context: ContextTypes.DEFAULT_TYPE, chat_id: int, *, force: bool = False, allow_api: bool = True) -> list[int]:
    now_wall = _cache_now_ms()

    # 1) Fast process-local cache.
    async with ADMIN_CACHE_LOCK:
        cached = ADMIN_IDS_CACHE.get(chat_id)
        if cached and not force and cached.expires_at > time.monotonic():
            return list(cached.value)

    # 2) bot_data cache survives PTB persistence / Redis hydrate.
    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(context.bot_data, "admin_ids_cache")
        cached_state = bucket.get(str(chat_id))
        if isinstance(cached_state, dict) and not force:
            try:
                if int(cached_state.get("expires_at_ms", 0)) > now_wall:
                    ids = [int(x) for x in cached_state.get("ids", [])]
                    async with ADMIN_CACHE_LOCK:
                        ADMIN_IDS_CACHE[chat_id] = CacheItem(ids, time.monotonic() + ADMIN_CACHE_TTL_SECONDS)
                    return list(ids)
            except (TypeError, ValueError):
                bucket.pop(str(chat_id), None)

    if not allow_api:
        return await get_chat_admin_ids_from_state(context.bot_data, chat_id)

    try:
        admins = await context.bot.get_chat_administrators(chat_id)
        ids = [int(a.user.id) for a in admins if not a.user.is_bot]
    except TelegramError as exc:
        logger.warning("Could not fetch admins for chat_id=%s: %s", chat_id, exc)
        return []

    async with ADMIN_CACHE_LOCK:
        ADMIN_IDS_CACHE[chat_id] = CacheItem(ids, time.monotonic() + ADMIN_CACHE_TTL_SECONDS)
    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(context.bot_data, "admin_ids_cache")
        bucket[str(chat_id)] = {"ids": ids, "expires_at_ms": now_wall + ADMIN_CACHE_TTL_SECONDS * 1000}
    return list(ids)


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


async def get_bot_member_cached(context: ContextTypes.DEFAULT_TYPE, chat_id: int, *, force: bool = False, allow_api: bool = True) -> BotPerms:
    now_wall = _cache_now_ms()

    async with BOT_MEMBER_CACHE_LOCK:
        cached = BOT_MEMBER_CACHE.get(chat_id)
        if cached and not force and cached.expires_at > time.monotonic():
            return cached.value

    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(context.bot_data, "bot_member_cache")
        cached_state = bucket.get(str(chat_id))
        if isinstance(cached_state, dict) and not force:
            try:
                if int(cached_state.get("expires_at_ms", 0)) > now_wall:
                    perms = BotPerms(
                        status=str(cached_state.get("status", "")),
                        can_delete_messages=bool(cached_state.get("can_delete_messages", False)),
                        can_restrict_members=bool(cached_state.get("can_restrict_members", False)),
                    )
                    async with BOT_MEMBER_CACHE_LOCK:
                        BOT_MEMBER_CACHE[chat_id] = CacheItem(perms, time.monotonic() + BOT_MEMBER_CACHE_TTL_SECONDS)
                    return perms
            except (TypeError, ValueError):
                bucket.pop(str(chat_id), None)

    if not allow_api:
        cached_perms = get_bot_member_from_state(context.bot_data, chat_id)
        return cached_perms or BotPerms(status="unknown", can_delete_messages=False, can_restrict_members=False)

    bot_id, _ = await get_bot_identity(context.bot)
    member = await context.bot.get_chat_member(chat_id, bot_id)
    perms = BotPerms(
        status=str(member.status),
        can_delete_messages=bool(getattr(member, "can_delete_messages", False)),
        can_restrict_members=bool(getattr(member, "can_restrict_members", False)),
    )

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
    return perms




async def refresh_bot_member_status_silent(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    """Self-heal cached bot permissions without blocking the dashboard UI.

    get_bot_member_cached(..., allow_api=True) only calls Telegram if both
    process and durable caches are missing/expired. Errors are swallowed so old
    dashboard messages never fail because of a refresh.
    """
    try:
        await get_bot_member_cached(context, int(chat_id), allow_api=True)
        await save_bot_data_to_redis(context.bot_data, reason="bot_member_cache_refresh", force=False)
    except TelegramError as exc:
        logger.info("Silent bot permission refresh failed chat_id=%s: %s", chat_id, exc)
    except Exception as exc:
        logger.debug("Silent bot permission refresh skipped chat_id=%s: %s", chat_id, exc)


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
    """Remove all durable state for a group after the bot leaves/is banned.

    Prevents zombie groups in the private dashboard and removes incidents/settings
    from Redis/Pickle-backed bot_data.
    """
    chat_key = str(int(chat_id))
    async with BOT_DATA_LOCK:
        group_state = context.bot_data.get("group_state")
        if isinstance(group_state, dict):
            group_state.pop(chat_key, None)
            group_state.pop(int(chat_id), None)

        user_state = context.bot_data.get("user_state")
        if isinstance(user_state, dict):
            for state in user_state.values():
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
            warning_counts.pop(int(chat_id), None)
            for key in list(warning_counts.keys()):
                if str(key).startswith(f"{chat_key}:"):
                    warning_counts.pop(key, None)

        for bucket_name in ("admin_ids_cache", "bot_member_cache", "chat_meta_cache"):
            bucket = context.bot_data.get(bucket_name)
            if isinstance(bucket, dict):
                bucket.pop(chat_key, None)
                bucket.pop(int(chat_id), None)

    async with INCIDENT_LOCKS_LOCK:
        for ikey in list(INCIDENT_LOCKS.keys()):
            if str(ikey).startswith(f"{chat_key}:"):
                INCIDENT_LOCKS.pop(ikey, None)

    await invalidate_chat_caches(chat_id)
    logger.info("Purged group state chat_id=%s reason=%s", chat_id, reason)
    await persist_context_memory(context, reason="group_purged", force=True)


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


def get_group_settings(bot_data: dict[str, Any], chat_id: int) -> dict[str, Any]:
    state = get_group_state(bot_data, chat_id)
    settings = state.setdefault("settings", {})
    if not isinstance(settings, dict):
        settings = {}
        state["settings"] = settings
    for key, value in DEFAULT_GROUP_SETTINGS.items():
        if key not in settings:
            settings[key] = list(value) if isinstance(value, list) else value
    if settings.get("strictness") not in {"standard", "high"}:
        settings["strictness"] = "standard"
    for list_key in ("allowed_extensions", "custom_blocked_extensions"):
        if not isinstance(settings.get(list_key), list):
            settings[list_key] = []
        settings[list_key] = _dedupe_valid_extensions(settings.get(list_key, []), limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
    settings["protection_enabled"] = bool(settings.get("protection_enabled", True))
    settings["silent_mode"] = bool(settings.get("silent_mode", False))
    return settings


def _on_off(bot_data: dict[str, Any], user_id: int | None, enabled: bool, *, key_on: str = "protection_on", key_off: str = "protection_off") -> str:
    return tr(bot_data, user_id, key_on if enabled else key_off)


def _strictness_label(bot_data: dict[str, Any], user_id: int | None, strictness: str) -> str:
    return tr(bot_data, user_id, "strict_high" if strictness == "high" else "strict_standard")


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
    """Hybrid group-admin authorization.

    - Owners always pass without Telegram API.
    - Fresh process/bot_data admin caches are used first.
    - If allow_api=True and the cache is missing/expired, performs one live
      get_chat_member(chat_id, user_id) lookup, then updates the durable cache.
    - If allow_api=False, falls back to offline bot_data only for dashboard/UI
      rendering so high-frequency screens never create 429/FloodWait pressure.
    """
    chat_id = int(chat_id)
    user_id = int(user_id)
    if user_id in BOT_OWNER_IDS:
        return True

    # 1) Process-local cache, only if fresh.
    if not force:
        async with ADMIN_CACHE_LOCK:
            cached = ADMIN_IDS_CACHE.get(chat_id)
            if cached and cached.expires_at > time.monotonic():
                return user_id in set(list(cached.value))

    # 2) Durable bot_data cache, only if fresh unless API is disallowed.
    ids, cache_exists, cache_fresh = await get_chat_admin_ids_state_snapshot(context.bot_data, chat_id)
    if not force and cache_exists and cache_fresh:
        async with ADMIN_CACHE_LOCK:
            ADMIN_IDS_CACHE[chat_id] = CacheItem(ids.copy(), time.monotonic() + ADMIN_CACHE_TTL_SECONDS)
        return user_id in set(ids)

    # 3) Offline UI path: use stale cache if it exists, but never call Telegram.
    if not allow_api:
        return user_id in set(ids)

    # 4) Hybrid self-healing path: one live member lookup for this user only.
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
    except TelegramError as exc:
        logger.warning(
            "Admin live membership check failed chat_id=%s user_id=%s: %s",
            chat_id,
            user_id,
            exc,
        )
        # Conservative fallback: stale cache is allowed only if it already knows this user.
        return user_id in set(ids)

    status = str(getattr(member, "status", ""))
    is_admin = status in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"}
    await update_admin_member_cache(context, chat_id, user_id, is_admin=is_admin)
    # Redis save is throttled by REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS to avoid write storms.
    await save_bot_data_to_redis(context.bot_data, reason="admin_member_live_refresh", force=False)
    return is_admin


async def is_verified_admin_anywhere(
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    *,
    allow_api: bool = True,
) -> bool:
    if int(user_id) in BOT_OWNER_IDS:
        return True

    groups = get_groups(context.bot_data, user_id)
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


async def link_user_to_group(context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, *, title: str | None = None, chat_type: str | None = None) -> None:
    await add_group(context.bot_data, user_id, chat_id)
    await remember_group(context.bot_data, chat_id, added_by=user_id, lang=get_lang(context.bot_data, user_id), title=title, chat_type=chat_type)
    await persist_context_memory(context, reason="link_user_group", force=True)


async def group_private_settings_url(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> str:
    _, username = await get_bot_identity(context.bot)
    return f"https://t.me/{username}?start=settings_{chat_id}" if username else "https://t.me/"


async def dashboard_home_keyboard(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> InlineKeyboardMarkup:
    _, username = await get_bot_identity(context.bot)
    add_url = f"https://t.me/{username}?startgroup=add" if username else "https://t.me/"
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_groups"), callback_data="nav:groups")],
            [InlineKeyboardButton(tr(context.bot_data, user_id, "btn_add_group"), url=add_url)],
            [
                InlineKeyboardButton(tr(context.bot_data, user_id, "btn_help"), callback_data="nav:help"),
                InlineKeyboardButton(tr(context.bot_data, user_id, "btn_refresh"), callback_data="nav:home"),
            ],
        ]
    )


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
        logger.debug("Could not answer private-only callback warning: %s", exc)


async def render_home(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "home_title"), await dashboard_home_keyboard(context, user_id))


async def render_help_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    await send_or_edit_panel(update, tr(context.bot_data, user_id, "help"), dashboard_back_home_keyboard(context.bot_data, user_id))


async def render_groups_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    groups = get_groups(context.bot_data, user_id)
    if int(user_id) not in BOT_OWNER_IDS and groups:
        checks = await asyncio.gather(
            *(is_admin_or_owner(context, user_id, chat_id=chat_id, allow_api=False) for chat_id in groups),
            return_exceptions=True,
        )
        authorized_groups = [
            chat_id
            for chat_id, ok in zip(groups, checks)
            if ok is True
        ]
        if len(authorized_groups) != len(groups):
            async with BOT_DATA_LOCK:
                state = get_user_state(context.bot_data, user_id)
                state["groups"] = authorized_groups
            await persist_context_memory(context, reason="dashboard_admin_prune", force=True)
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
            title = get_chat_title_from_state(context.bot_data, chat_id)
            perms = get_bot_member_from_state(context.bot_data, chat_id)
            if perms is None or perms.status == "unknown":
                permission = tr(context.bot_data, user_id, "perm_unknown")
            else:
                permission = tr(context.bot_data, user_id, "perm_ok" if has_delete_permission(perms) else "perm_no")
            async with BOT_DATA_LOCK:
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
            logger.warning("Group dashboard render failed: %s", item)
            continue
        chat_id, title, card = item
        lines.append(card)
        rows.append([InlineKeyboardButton(f"⚙️ {title[:32]}", callback_data=f"grp:{chat_id}")])

    rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_refresh"), callback_data="nav:groups")])
    rows.append([InlineKeyboardButton(tr(context.bot_data, user_id, "btn_home"), callback_data="nav:home")])
    await send_or_edit_panel(update, "\n\n".join(lines), InlineKeyboardMarkup(rows))


def group_settings_keyboard(bot_data: dict[str, Any], user_id: int, chat_id: int) -> InlineKeyboardMarkup:
    settings = get_group_settings(bot_data, chat_id)
    protection = "✅" if settings.get("protection_enabled") else "❌"
    strictness = "High" if settings.get("strictness") == "high" else "Standard"
    silent = "✅" if settings.get("silent_mode") else "❌"
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(f"{protection} Protection", callback_data=f"gset:{chat_id}:protection")],
            [InlineKeyboardButton(f"🧪 Strictness: {strictness}", callback_data=f"gset:{chat_id}:strictness")],
            [InlineKeyboardButton(f"🤫 Silent Mode: {silent}", callback_data=f"gset:{chat_id}:silent")],
            [InlineKeyboardButton(tr(bot_data, user_id, "btn_manage_formats"), callback_data=f"gfmt:{chat_id}:menu")],
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
    title = get_chat_title_from_state(context.bot_data, chat_id)

    settings = get_group_settings(context.bot_data, chat_id)
    allowed = format_extension_list(settings.get("allowed_extensions", []))
    custom_blocked = format_extension_list(settings.get("custom_blocked_extensions", []))
    text = tr(
        context.bot_data,
        user_id,
        "settings_title",
        group=h(title),
        chat_id=chat_id,
        protection=_on_off(context.bot_data, user_id, bool(settings.get("protection_enabled"))),
        strictness=_strictness_label(context.bot_data, user_id, str(settings.get("strictness", "standard"))),
        silent=_on_off(context.bot_data, user_id, bool(settings.get("silent_mode")), key_on="silent_on", key_off="silent_off"),
        allowed=h(allowed),
        custom_blocked=h(custom_blocked),
    )
    if notice:
        text = f"{notice}\n\n{text}"
    await send_or_edit_panel(update, text, group_settings_keyboard(context.bot_data, user_id, chat_id))


async def render_format_manager_panel(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    chat_id: int,
    *,
    notice: str = "",
    remove_mode: bool = False,
) -> None:
    title = get_chat_title_from_state(context.bot_data, chat_id)

    settings = get_group_settings(context.bot_data, chat_id)
    custom_blocked = format_extension_list(settings.get("custom_blocked_extensions", []))
    text = tr(
        context.bot_data,
        user_id,
        "formats_title",
        group=h(title),
        chat_id=chat_id,
        custom_blocked=h(custom_blocked),
    )
    if notice:
        text = f"{notice}\n\n{text}"
    keyboard = remove_format_keyboard(context.bot_data, user_id, chat_id) if remove_mode else format_manager_keyboard(context.bot_data, user_id, chat_id)
    await send_or_edit_panel(update, text, keyboard)


async def set_pending_format_edit(context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, mode: str) -> None:
    async with BOT_DATA_LOCK:
        state = get_user_state(context.bot_data, user_id)
        state["pending_format_edit"] = {"chat_id": int(chat_id), "mode": mode, "created_at_ms": now_ms()}
    await persist_context_memory(context, reason="pending_format_edit", force=True)


async def clear_pending_format_edit(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    async with BOT_DATA_LOCK:
        state = get_user_state(context.bot_data, user_id)
        state.pop("pending_format_edit", None)
    await persist_context_memory(context, reason="clear_pending_format_edit", force=True)


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
        await render_home(update, context, user_id)
    elif data == "nav:groups":
        await render_groups_panel(update, context, user_id)
    elif data == "nav:help":
        await render_help_panel(update, context, user_id)
    else:
        await render_home(update, context, user_id)


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
            settings["strictness"] = "high" if settings.get("strictness") == "standard" else "standard"
        elif field == "silent":
            settings["silent_mode"] = not bool(settings.get("silent_mode", False))
        else:
            await safe_edit_query(query, tr(context.bot_data, user_id, "unknown_error"))
            return

    await link_user_to_group(context, user_id, chat_id)
    await persist_context_memory(context, reason="group_settings_update", force=True)
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
        settings = get_group_settings(context.bot_data, chat_id)
        if not settings.get("custom_blocked_extensions"):
            await render_format_manager_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "formats_empty"))
            return
        await render_format_manager_panel(update, context, user_id, chat_id, remove_mode=True)
        return
    if action == "clear":
        async with BOT_DATA_LOCK:
            settings = get_group_settings(context.bot_data, chat_id)
            settings["custom_blocked_extensions"] = []
        await persist_context_memory(context, reason="custom_formats_clear", force=True)
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
    await persist_context_memory(context, reason="custom_format_delete", force=True)
    await render_format_manager_panel(update, context, user_id, chat_id, notice=tr(context.bot_data, user_id, "formats_removed", ext=h(ext)))


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
        # Do not auto-open the home menu for random private text.
        # CommandHandler handles /start, /settings, /help, etc. before this handler.
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

    if not await is_user_admin_in_group(context, chat_id, user.id):
        await clear_pending_format_edit(context, user.id)
        await safe_reply(update, tr(context.bot_data, user.id, "group_admin_only"), reply_markup=await dashboard_home_keyboard(context, user.id))
        return

    parsed = parse_extensions_from_text(text)
    if not parsed:
        await safe_reply(update, tr(context.bot_data, user.id, "formats_invalid"))
        return

    async with BOT_DATA_LOCK:
        settings = get_group_settings(context.bot_data, chat_id)
        current = settings.get("custom_blocked_extensions", [])
        if mode == "edit":
            settings["custom_blocked_extensions"] = parsed[:MAX_CUSTOM_BLOCKED_EXTENSIONS]
        else:
            settings["custom_blocked_extensions"] = _dedupe_valid_extensions([*current, *parsed], limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
        get_user_state(context.bot_data, user.id).pop("pending_format_edit", None)

    await link_user_to_group(context, user.id, chat_id)
    await persist_context_memory(context, reason="custom_formats_save", force=True)
    await render_format_manager_panel(update, context, user.id, chat_id, notice=tr(context.bot_data, user.id, "formats_saved"))


async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    chat = update.effective_chat
    if not user:
        return
    await remember_user_profile(context.bot_data, user)

    if chat and is_group_chat(chat.type):
        if not await is_admin_or_owner(context, user.id, chat_id=chat.id):
            await safe_reply(update, tr(context.bot_data, user.id, "group_admin_only"))
            return
        await remember_chat_meta(context.bot_data, chat)
        async with BOT_DATA_LOCK:
            get_group_state(context.bot_data, chat.id)["title"] = chat.title or str(chat.id)
        await link_user_to_group(context, user.id, chat.id, title=chat.title or str(chat.id), chat_type=str(chat.type))
        url = await group_private_settings_url(context, chat.id)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton(tr(context.bot_data, user.id, "btn_settings"), url=url)]])
        await safe_reply(
            update,
            tr(context.bot_data, user.id, "settings_group_open_private") + "\n\n" + tr(context.bot_data, user.id, "config_private_only"),
            reply_markup=kb,
        )
        return

    # Private /settings opens the user's dynamic group dashboard.
    await render_groups_panel(update, context, user.id)



def apply_group_scan_policy(bot_data: dict[str, Any], chat_id: int, scan: FileScanResult) -> FileScanResult:
    settings = get_group_settings(bot_data, chat_id)
    if not settings.get("protection_enabled", True):
        return replace(scan, blocked=False, reason_code="protection_disabled", reason_display="group protection is disabled")

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
    admin_ids = await get_chat_admin_ids_cached(context, chat_id)
    if not admin_ids:
        return

    sender_id = sender.id if sender else 0
    sender_name = sender.full_name if sender else "Unknown"
    time_str = now_utc_str()

    sem = asyncio.Semaphore(20)
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
            logger.warning("Admin alert task failed: %s", result)
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
        await persist_context_memory(context, reason="admin_alert_messages", force=True)


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
    incidents = context.bot_data.setdefault("incidents", {})
    if not isinstance(incidents, dict) or not incidents:
        return

    cutoff = now_ms() - INCIDENT_TTL_SECONDS * 1000
    stale_keys: list[str] = []
    for ikey, incident in list(incidents.items()):
        ts = incident_timestamp_ms(str(ikey))
        created_at = ts if ts is not None else int(incident.get("created_at_ms", 0) or 0)
        if created_at and created_at < cutoff:
            stale_keys.append(str(ikey))

    if stale_keys:
        async with BOT_DATA_LOCK:
            for ikey in stale_keys:
                incidents.pop(ikey, None)
        async with INCIDENT_LOCKS_LOCK:
            for ikey in stale_keys:
                INCIDENT_LOCKS.pop(ikey, None)
        logger.info("Cleaned %d stale incident(s).", len(stale_keys))
        await persist_context_memory(context, reason="cleanup_incidents", force=True)


async def cleanup_runtime_caches(context: ContextTypes.DEFAULT_TYPE) -> None:
    now = time.monotonic()
    async with ADMIN_CACHE_LOCK:
        for chat_id, item in list(ADMIN_IDS_CACHE.items()):
            if item.expires_at <= now:
                ADMIN_IDS_CACHE.pop(chat_id, None)
    async with BOT_MEMBER_CACHE_LOCK:
        for chat_id, item in list(BOT_MEMBER_CACHE.items()):
            if item.expires_at <= now:
                BOT_MEMBER_CACHE.pop(chat_id, None)


async def periodic_redis_save(context: ContextTypes.DEFAULT_TYPE) -> None:
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
        logger.warning("Keep-awake ping failed: %s", exc)


# ─────────────────────────────────────────────────────────────
# COMMAND / CALLBACK HANDLERS
# ─────────────────────────────────────────────────────────────


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    chat = update.effective_chat
    if not user:
        return

    was_known = _user_state_exists(context.bot_data, user.id)
    await remember_user_profile(context.bot_data, user)
    await persist_context_memory(context, reason="start", force=True)

    # Deep-link flow from /settings inside a group: /start settings_<chat_id>
    payload = (context.args[0] if context.args else "").strip()
    if payload.startswith(("settings_", "group_")):
        linked_chat_id = _safe_chat_id_from_payload(payload)
        if linked_chat_id is not None and await is_user_admin_in_group(context, linked_chat_id, user.id):
            await link_user_to_group(context, user.id, linked_chat_id)
            await render_group_settings_panel(
                update,
                context,
                user.id,
                linked_chat_id,
                notice=tr(context.bot_data, user.id, "group_linked"),
            )
            return
        await safe_reply(update, tr(context.bot_data, user.id, "group_admin_only"), reply_markup=await dashboard_home_keyboard(context, user.id))
        return

    if chat and is_group_chat(chat.type):
        _, username = await get_bot_identity(context.bot)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Open private chat", url=f"https://t.me/{username}" if username else "https://t.me/")]])
        await safe_reply(update, tr(context.bot_data, user.id, "private_start"), reply_markup=kb)
        return

    # New users choose a language first. Returning users go straight to Home.
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

    await remember_user_profile(context.bot_data, query.from_user, lang)
    await persist_context_memory(context, reason="language", force=True)
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
    groups = get_groups(context.bot_data, user_id)
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
            logger.warning("Permission check failed chat_id=%s and group was purged from saved list: %s", chat_id, exc)
            await purge_group_state(context, chat_id, reason="remove_stale_group")
            return None
        except TelegramError as exc:
            logger.warning("Permission check failed chat_id=%s: %s", chat_id, exc)
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
            logger.warning("Permission check task failed: %s", item)

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
        incidents = context.bot_data.setdefault("incidents", {})
        incident = incidents.get(ikey)
        if not incident:
            await safe_edit_query(query, tr(context.bot_data, admin_id, "action_expired"))
            return
        if incident.get("done"):
            await safe_edit_query(query, tr(context.bot_data, admin_id, "action_done"))
            return

        chat_id = int(incident["chat_id"])
        admin_ids = await get_chat_admin_ids_cached(context, chat_id, force=True)
        if admin_id not in admin_ids:
            await safe_edit_query(query, tr(context.bot_data, admin_id, "action_not_admin"))
            return

        if query.message:
            incident.setdefault("alert_messages", {})[str(admin_id)] = int(query.message.message_id)

        incident["done"] = True
        incident["handled_by"] = admin_id
        incident["handled_by_name"] = query.from_user.full_name
        incident["handled_at_ms"] = now_ms()
        incident["action"] = action

        sender_id = int(incident.get("sender_id", 0))
        sender_name_raw = str(incident.get("sender_name") or "Unknown")
        sender_name = h(sender_name_raw)
        file_name = h(incident.get("file_name") or "Unknown")
        group_name = h(incident.get("group_name") or str(chat_id))

        if action == "ban":
            try:
                bot_perms = await get_bot_member_cached(context, chat_id, force=True)
                if not has_ban_permission(bot_perms):
                    raise TelegramError("Bot does not have Ban Users permission")
                await context.bot.ban_chat_member(chat_id, sender_id)
                result_msg = tr(context.bot_data, admin_id, "action_ban_ok", name=sender_name)
            except TelegramError as exc:
                incident["done"] = False
                incident.pop("handled_by", None)
                incident.pop("handled_by_name", None)
                incident.pop("handled_at_ms", None)
                incident.pop("action", None)
                logger.warning("Ban failed chat_id=%s sender_id=%s: %s", chat_id, sender_id, exc)
                result_msg = tr(context.bot_data, admin_id, "action_ban_fail")

        elif action == "warn":
            mention = user_link(sender_id, sender_name_raw)
            warn_text = TEXTS[get_lang(context.bot_data, admin_id)]["warn_in_group"].format(user=mention)
            try:
                await context.bot.send_message(chat_id, warn_text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
                result_msg = tr(context.bot_data, admin_id, "action_warn_ok", name=sender_name)
            except TelegramError as exc:
                incident["done"] = False
                incident.pop("handled_by", None)
                incident.pop("handled_by_name", None)
                incident.pop("handled_at_ms", None)
                incident.pop("action", None)
                logger.warning("Warn failed chat_id=%s sender_id=%s: %s", chat_id, sender_id, exc)
                result_msg = tr(context.bot_data, admin_id, "action_warn_fail")
        else:
            result_msg = tr(context.bot_data, admin_id, "action_ignore_ok")

        final_text = format_incident_alert_for_admin(context.bot_data, admin_id, incident)
        if not incident.get("done") and result_msg:
            final_text += f"\n\n{result_msg}"
        await safe_edit_query(query, final_text)

        if incident.get("done"):
            clicked_message_id = int(query.message.message_id) if query.message else None
            await sync_handled_alert_messages(
                context,
                incident,
                exclude_admin_id=admin_id,
                exclude_message_id=clicked_message_id,
            )
        await persist_context_memory(context, reason="incident_action", force=True)


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

    await invalidate_chat_caches(chat.id, context.bot_data)

    # Bot removed/left/kicked: purge durable state so private dashboards do not show zombie groups.
    removed_statuses = {
        str(getattr(ChatMemberStatus, "LEFT", "left")),
        str(getattr(ChatMemberStatus, "BANNED", "kicked")),
        str(getattr(ChatMemberStatus, "KICKED", "kicked")),
        "left",
        "banned",
        "kicked",
    }
    if new_status.casefold() in {status.casefold() for status in removed_statuses}:
        logger.info("Bot removed from chat_id=%s title=%r; purging stored group state", chat.id, chat.title)
        await purge_group_state(context, chat.id, reason="bot_removed_from_group")
        return

    adder = result.from_user
    if not adder or adder.is_bot:
        return

    await remember_user_profile(context.bot_data, adder)
    await remember_chat_meta(context.bot_data, chat)
    await add_group(context.bot_data, adder.id, chat.id)
    await remember_group(context.bot_data, chat.id, added_by=adder.id, lang=get_lang(context.bot_data, adder.id), title=chat.title or str(chat.id), chat_type=str(chat.type))
    try:
        # Lifecycle refresh only. Standard UI authorization reads this cache exclusively.
        await get_chat_admin_ids_cached(context, chat.id, force=True, allow_api=True)
    except TelegramError as exc:
        logger.warning("Admin cache refresh failed in my_chat_member_update chat_id=%s: %s", chat.id, exc)

    safe_title = h(chat.title or "Group")
    can_delete = bool(getattr(new_member, "can_delete_messages", False))
    is_admin = new_status in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"}
    async with BOT_DATA_LOCK:
        bucket = _bot_data_cache_bucket(context.bot_data, "bot_member_cache")
        bucket[str(int(chat.id))] = {
            "status": new_status,
            "can_delete_messages": can_delete,
            "can_restrict_members": bool(getattr(new_member, "can_restrict_members", False)),
            "expires_at_ms": _cache_now_ms() + BOT_MEMBER_CACHE_TTL_SECONDS * 1000,
        }
    async with BOT_MEMBER_CACHE_LOCK:
        BOT_MEMBER_CACHE[int(chat.id)] = CacheItem(
            BotPerms(new_status, can_delete, bool(getattr(new_member, "can_restrict_members", False))),
            time.monotonic() + BOT_MEMBER_CACHE_TTL_SECONDS,
        )
    await persist_context_memory(context, reason="chat_member_update", force=True)

    if is_admin and can_delete:
        msg = tr(context.bot_data, adder.id, "setup_ok", group=safe_title)
    elif is_admin:
        msg = tr(context.bot_data, adder.id, "no_delete_perm")
    else:
        msg = tr(context.bot_data, adder.id, "not_admin")

    # Notify the user who added/promoted the bot. This may fail if they have not started the bot.
    try:
        kb = InlineKeyboardMarkup([[InlineKeyboardButton(tr(context.bot_data, adder.id, "check_btn"), callback_data="check_perm")]])
        await context.bot.send_message(adder.id, msg, parse_mode=ParseMode.HTML, reply_markup=kb, disable_web_page_preview=True)
    except TelegramError:
        pass

    logger.info(
        "my_chat_member: chat_id=%s old=%s new=%s can_delete=%s",
        chat.id,
        getattr(old_member, "status", None),
        new_status,
        can_delete,
    )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    chat = update.effective_chat
    if not message or not chat or not message.document or not is_group_chat(chat.type):
        return

    scan = await scan_document(context, message.document)
    scan = apply_group_scan_policy(context.bot_data, chat.id, scan)
    if not scan.blocked:
        return

    sender = message.from_user
    sender_id = sender.id if sender else 0
    sender_name_raw = sender.full_name if sender else "Unknown"
    file_name = scan.file_name

    try:
        await message.delete()
    except TelegramError as exc:
        logger.error("Could not delete blocked file chat_id=%s message_id=%s: %s", chat.id, message.message_id, exc)
        await invalidate_chat_caches(chat.id, context.bot_data)
        await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "delete_failed"))
        return

    await remember_user_profile(context.bot_data, sender)
    await remember_group(context.bot_data, chat.id, lang=get_group_lang(context.bot_data, chat.id), title=chat.title or str(chat.id), chat_type=str(chat.type))
    user_mention = user_link(sender_id, sender_name_raw)
    scan_reason = describe_scan_reason(scan.reason_code, (scan.reason_display, *scan.details))
    settings = get_group_settings(context.bot_data, chat.id)
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
            "message_id": message.message_id,
            "alert_messages": {},
        }

    await persist_context_memory(context, reason="incident_created", force=True)
    await notify_admins(context, chat.id, chat.title or str(chat.id), sender, file_name, ikey, scan_reason)
    await persist_context_memory(context, reason="incident_alerted", force=True)


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
    if not await require_admin_or_owner(update, context):
        return

    if chat and is_group_chat(chat.type):
        if not user or not await is_admin_or_owner(context, user.id, chat_id=chat.id):
            await safe_reply(update, tr(context.bot_data, user_id, "group_admin_only"))
            return
        await remember_chat_meta(context.bot_data, chat)
        async with BOT_DATA_LOCK:
            get_group_state(context.bot_data, chat.id)["title"] = chat.title or str(chat.id)
        await link_user_to_group(context, user.id, chat.id, title=chat.title or str(chat.id), chat_type=str(chat.type))
        url = await group_private_settings_url(context, chat.id)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton(tr(context.bot_data, user.id, "btn_settings"), url=url)]])
        await safe_reply(update, tr(context.bot_data, user.id, "scanner_group_private_only"), reply_markup=kb)
        return

    await safe_reply(update, scanner_config_text(context.bot_data, user_id))



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
        redis="connected" if REDIS_AVAILABLE else ("configured but offline" if REDIS_ENABLED else "disabled"),
        users=len(known_users),
        groups=len(group_state),
        incidents=len(incidents),
        last_save=h(REDIS_LAST_SAVE_UTC),
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
        perms = await get_bot_member_cached(context, chat.id, force=True)
        msg = tr(context.bot_data, user_id, "status_ok" if has_delete_permission(perms) else "status_no")
    except TelegramError as exc:
        msg = tr(context.bot_data, user_id, "status_error", error=h(str(exc)))
    await safe_reply(update, msg)


async def admins_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    user_id = update.effective_user.id if update.effective_user else None
    if not chat or not is_group_chat(chat.type):
        await safe_reply(update, tr(context.bot_data, user_id, "group_only"))
        return
    if not update.effective_user or not await is_user_admin_in_group(context, chat.id, update.effective_user.id):
        await safe_reply(update, tr(context.bot_data, user_id, "group_admin_only"))
        return

    admin_ids = await get_chat_admin_ids_cached(context, chat.id, allow_api=False)
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


# ─────────────────────────────────────────────────────────────
# APP LIFECYCLE / ERROR HANDLING
# ─────────────────────────────────────────────────────────────


async def post_init(application: Application) -> None:
    global BOT_ID, BOT_USERNAME
    me = await application.bot.get_me()
    BOT_ID = int(me.id)
    BOT_USERNAME = me.username or ""
    logger.info("Bot initialized as @%s id=%s", BOT_USERNAME, BOT_ID)
    await init_redis_memory(application)

    try:
        await application.bot.set_my_commands(
            [
                ("start", "Choose language and setup"),
                ("help", "Show help"),
                ("status", "Check bot status in a group"),
                ("settings", "Open dynamic group settings"),
                ("admins", "Show admin alert status in a group"),
                ("scanner", "Show scanner settings"),
                ("scanname", "Test a suspicious filename"),
                ("memory", "Show Redis/user memory status"),
                ("debug", "Show guarded diagnostic counters"),
            ]
        )
    except TelegramError as exc:
        logger.warning("Could not set bot commands: %s", exc)


async def post_shutdown(application: Application) -> None:
    global KEEP_AWAKE_CLIENT
    await save_bot_data_to_redis(application.bot_data, reason="shutdown", force=True)
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
    app.add_handler(CallbackQueryHandler(group_dashboard_callback, pattern=r"^grp:-?\d+$"))
    app.add_handler(CallbackQueryHandler(group_settings_callback, pattern=r"^gset:-?\d+:(protection|strictness|silent)$"))
    app.add_handler(CallbackQueryHandler(format_manager_callback, pattern=r"^gfmt:-?\d+:(menu|add|edit|remove|clear)$"))
    app.add_handler(CallbackQueryHandler(delete_format_callback, pattern=r"^gfmtdel:-?\d+:[A-Za-z0-9_.+-]{1,16}$"))
    app.add_handler(CallbackQueryHandler(check_perm_callback, pattern=r"^check_perm$"))
    app.add_handler(CallbackQueryHandler(action_callback, pattern=r"^act:(ban|warn|ignore):.+$"))
    app.add_handler(ChatMemberHandler(my_chat_member_update, ChatMemberHandler.MY_CHAT_MEMBER))
    app.add_handler(MessageHandler(filters.Document.ALL & (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP), handle_document))
    app.add_handler(MessageHandler(filters.TEXT & filters.ChatType.PRIVATE, private_text_flow_handler))
    app.add_error_handler(error_handler)

    if app.job_queue:
        app.job_queue.run_repeating(clean_old_incidents, interval=3600, first=30, name="clean_old_incidents")
        app.job_queue.run_repeating(cleanup_runtime_caches, interval=600, first=600, name="cleanup_runtime_caches")
        if REDIS_ENABLED:
            app.job_queue.run_repeating(periodic_redis_save, interval=60, first=60, name="periodic_redis_save")

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
