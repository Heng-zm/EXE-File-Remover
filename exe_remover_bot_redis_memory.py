#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram Bot - EXE File Remover (Render Production Ready)

What it does
------------
• Deletes blocked executable files from groups/supergroups.
• Alerts every human admin by DM with inline actions: Ban | Warn | Ignore.
• Updates all admin alert messages once one admin handles an incident.
• Supports English and Khmer.
• Supports Render webhooks and local polling.
• Persists user language/group state and incident state across restarts.

Recommended install
-------------------
pip install "python-telegram-bot[webhooks,job-queue]" python-dotenv httpx redis

Important environment variables
-------------------------------
BOT_TOKEN                         Required. Telegram bot token.
BOT_MODE                          Optional: AUTO, WEBHOOK, or POLLING. Default: AUTO.
PORT                              Optional. Default: 8080.
RENDER_EXTERNAL_URL               Optional. Render provides this automatically.
WEBHOOK_URL                       Optional. Override public base URL for webhook mode.
WEBHOOK_SECRET_TOKEN              Optional. Safe webhook path token. Auto-generated if missing.
PERSISTENCE_FILE                  Optional. Default: exe_bot_data.pickle.
LOCAL_PERSISTENCE_ENABLED         Optional: true/false. Default: true.
REDIS_URL                         Optional. Enables Redis memory when set.
REDIS_ENABLED                     Optional: true/false. Default: true when REDIS_URL is set.
REDIS_PREFIX                      Optional. Default: exe_remover_bot.
REDIS_STATE_KEY                   Optional. Default: {REDIS_PREFIX}:state.
REDIS_AUTOSAVE_MIN_INTERVAL_SECONDS Optional. Default: 2.
BLOCKED_EXTENSIONS                Optional. Comma list. Default: .exe
DANGEROUS_EXTENSIONS              Optional. Comma list used by suspicious scanner.
ARCHIVE_EXTENSIONS                Optional. Archive suffixes checked for hidden dangerous names.
BLOCKED_MIME_TYPES                Optional. Comma list of MIME types.
SUSPICIOUS_SCANNER_ENABLED        Optional: true/false. Default: true.
SUSPICIOUS_MAGIC_SCAN_ENABLED     Optional: true/false. Default: true.
SUSPICIOUS_ARCHIVE_SCAN_ENABLED   Optional: true/false. Default: true.
SCANNER_MAX_DOWNLOAD_BYTES        Optional. Default: 2000000. Small-file header/archive scan limit.
MAX_ARCHIVE_MEMBERS_TO_SCAN       Optional. Default: 500.
MAX_CONCURRENT_UPDATES            Optional. Default: 8.
TELEGRAM_CONNECTION_POOL_SIZE     Optional. Default: 32.
TELEGRAM_POOL_TIMEOUT             Optional. Default: 10.0.
ADMIN_CACHE_TTL_SECONDS           Optional. Default: 180.
BOT_MEMBER_CACHE_TTL_SECONDS      Optional. Default: 60.
INCIDENT_TTL_SECONDS              Optional. Default: 86400.
KEEP_AWAKE_ENABLED                Optional: true/false. Default: true on Render webhook mode.
KEEP_AWAKE_INTERVAL_SECONDS       Optional. Default: 600.
DROP_PENDING_UPDATES              Optional: true/false. Default: false.
"""

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
from dataclasses import dataclass
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

ALLOWED_UPDATES = ["message", "callback_query", "my_chat_member"]
CHAT_TYPES_GROUP = {ChatType.GROUP, ChatType.SUPERGROUP, "group", "supergroup"}

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
)
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
# REDIS MEMORY / PERSISTENCE HELPERS
# ─────────────────────────────────────────────────────────────

PERSISTED_BOT_DATA_KEYS = (
    "user_state",
    "group_state",
    "known_users",
    "incidents",
    "warning_counts",
    "settings",
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


async def remember_group(bot_data: dict[str, Any], chat_id: int, *, added_by: int | None = None, lang: str | None = None) -> None:
    async with BOT_DATA_LOCK:
        state = get_group_state(bot_data, chat_id)
        if added_by is not None:
            state["added_by"] = int(added_by)
        if lang in TEXTS:
            state["lang"] = lang
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


def filename_suffixes(file_name: str) -> list[str]:
    # A robust suffix parser that catches repeated suffixes like invoice.pdf.exe.zip.
    suffixes = re.findall(r"(?<!^)\.[A-Za-z0-9_+-]{1,16}", file_name.casefold())
    return [_normalize_extension(ext) for ext in suffixes]


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
        except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
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


async def get_chat_admin_ids_cached(context: ContextTypes.DEFAULT_TYPE, chat_id: int, *, force: bool = False) -> list[int]:
    now = time.monotonic()
    async with ADMIN_CACHE_LOCK:
        cached = ADMIN_IDS_CACHE.get(chat_id)
        if cached and not force and cached.expires_at > now:
            return list(cached.value)

    try:
        admins = await context.bot.get_chat_administrators(chat_id)
        ids = [a.user.id for a in admins if not a.user.is_bot]
    except TelegramError as exc:
        logger.warning("Could not fetch admins for chat_id=%s: %s", chat_id, exc)
        return []

    async with ADMIN_CACHE_LOCK:
        ADMIN_IDS_CACHE[chat_id] = CacheItem(ids, time.monotonic() + ADMIN_CACHE_TTL_SECONDS)
    return list(ids)


async def get_bot_member_cached(context: ContextTypes.DEFAULT_TYPE, chat_id: int, *, force: bool = False) -> BotPerms:
    now = time.monotonic()
    async with BOT_MEMBER_CACHE_LOCK:
        cached = BOT_MEMBER_CACHE.get(chat_id)
        if cached and not force and cached.expires_at > now:
            return cached.value

    bot_id, _ = await get_bot_identity(context.bot)
    member = await context.bot.get_chat_member(chat_id, bot_id)
    perms = BotPerms(
        status=str(member.status),
        can_delete_messages=bool(getattr(member, "can_delete_messages", False)),
        can_restrict_members=bool(getattr(member, "can_restrict_members", False)),
    )

    async with BOT_MEMBER_CACHE_LOCK:
        BOT_MEMBER_CACHE[chat_id] = CacheItem(perms, time.monotonic() + BOT_MEMBER_CACHE_TTL_SECONDS)
    return perms


async def invalidate_chat_caches(chat_id: int) -> None:
    async with ADMIN_CACHE_LOCK:
        ADMIN_IDS_CACHE.pop(chat_id, None)
    async with BOT_MEMBER_CACHE_LOCK:
        BOT_MEMBER_CACHE.pop(chat_id, None)


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
    global KEEP_AWAKE_CLIENT
    if not WEBHOOK_BASE_URL:
        return
    try:
        if KEEP_AWAKE_CLIENT is None:
            KEEP_AWAKE_CLIENT = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        response = await KEEP_AWAKE_CLIENT.get(WEBHOOK_BASE_URL)
        logger.info("Keep-awake ping status=%s", response.status_code)
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
    await remember_user_profile(context.bot_data, user)
    await persist_context_memory(context, reason="start", force=True)

    if chat and is_group_chat(chat.type):
        _, username = await get_bot_identity(context.bot)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Open private chat", url=f"https://t.me/{username}" if username else "https://t.me/")]])
        await safe_reply(update, tr(context.bot_data, user.id, "private_start"), reply_markup=kb)
        return

    await safe_reply(update, tr(context.bot_data, user.id, "select_lang"), reply_markup=language_keyboard())


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
    kb = await setup_keyboard(context, user_id)
    await safe_edit_query(query, tr(context.bot_data, user_id, "lang_set") + "\n\n" + tr(context.bot_data, user_id, "welcome"), reply_markup=kb)


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
            chat = await context.bot.get_chat(chat_id)
            perms = await get_bot_member_cached(context, chat_id, force=True)
            safe_title = h(chat.title or str(chat_id))
            if perms.status not in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"}:
                return f"❌ <b>{safe_title}</b>\n{tr(context.bot_data, user_id, 'not_admin')}"
            if not perms.can_delete_messages:
                return f"⚠️ <b>{safe_title}</b>\n{tr(context.bot_data, user_id, 'no_delete_perm')}"
            return f"✅ <b>{safe_title}</b>\n{tr(context.bot_data, user_id, 'setup_ok', group=safe_title)}"
        except (Forbidden, BadRequest) as exc:
            logger.warning("Permission check failed chat_id=%s and group was removed from saved list: %s", chat_id, exc)
            await remove_group_from_user(context.bot_data, user_id, chat_id)
            await invalidate_chat_caches(chat_id)
            await persist_context_memory(context, reason="remove_stale_group", force=True)
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

    await invalidate_chat_caches(chat.id)

    # Bot removed/left: no need to keep checking stale permissions in cache.
    banned_status = getattr(ChatMemberStatus, "BANNED", "kicked")
    if new_status in {str(ChatMemberStatus.LEFT), str(banned_status), "left", "kicked"}:
        logger.info("Bot removed from chat_id=%s title=%r", chat.id, chat.title)
        return

    adder = result.from_user
    if not adder or adder.is_bot:
        return

    await remember_user_profile(context.bot_data, adder)
    await add_group(context.bot_data, adder.id, chat.id)
    await remember_group(context.bot_data, chat.id, added_by=adder.id, lang=get_lang(context.bot_data, adder.id))
    await persist_context_memory(context, reason="chat_member_update", force=True)

    safe_title = h(chat.title or "Group")
    can_delete = bool(getattr(new_member, "can_delete_messages", False))
    is_admin = new_status in {str(ChatMemberStatus.ADMINISTRATOR), str(ChatMemberStatus.OWNER), "administrator", "creator"}

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
        await invalidate_chat_caches(chat.id)
        await safe_send_message(context, chat.id, tr_group(context.bot_data, chat.id, "delete_failed"))
        return

    await remember_user_profile(context.bot_data, sender)
    await remember_group(context.bot_data, chat.id, lang=get_group_lang(context.bot_data, chat.id))
    user_mention = user_link(sender_id, sender_name_raw)
    scan_reason = describe_scan_reason(scan.reason_code, (scan.reason_display, *scan.details))
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


async def scanner_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
    await safe_reply(update, scanner_config_text(context.bot_data, user_id))


async def scanname_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
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

    try:
        admins = await context.bot.get_chat_administrators(chat.id)
        human_admins = [a for a in admins if not a.user.is_bot]
        ready_user_ids = {int(uid) for uid in context.bot_data.get("user_state", {}).keys() if str(uid).lstrip("-").isdigit()}
        lang = get_lang(context.bot_data, user_id)
        lines = []
        for i, admin in enumerate(human_admins, 1):
            status = TEXTS[lang]["admins_enabled"] if admin.user.id in ready_user_ids else TEXTS[lang]["admins_need_start"]
            title = f" — <i>{h(admin.custom_title)}</i>" if getattr(admin, "custom_title", None) else ""
            lines.append(f"{i}. {user_link(admin.user.id, admin.user.full_name)}{title} — {status}")
        msg = tr(context.bot_data, user_id, "admins_header") + "\n".join(lines) + tr(context.bot_data, user_id, "admins_note")
    except TelegramError as exc:
        msg = tr(context.bot_data, user_id, "status_error", error=h(str(exc)))
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
                ("admins", "Show admin alert status in a group"),
                ("scanner", "Show scanner settings"),
                ("scanname", "Test a suspicious filename"),
                ("memory", "Show Redis/user memory status"),
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
    app.add_handler(CommandHandler("admins", admins_command))
    app.add_handler(CommandHandler("scanner", scanner_command))
    app.add_handler(CommandHandler("scanname", scanname_command))
    app.add_handler(CommandHandler("memory", memory_command))
    app.add_handler(CallbackQueryHandler(lang_callback, pattern=r"^lang_(en|km)$"))
    app.add_handler(CallbackQueryHandler(check_perm_callback, pattern=r"^check_perm$"))
    app.add_handler(CallbackQueryHandler(action_callback, pattern=r"^act:(ban|warn|ignore):.+$"))
    app.add_handler(ChatMemberHandler(my_chat_member_update, ChatMemberHandler.MY_CHAT_MEMBER))
    app.add_handler(MessageHandler(filters.Document.ALL & (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP), handle_document))
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
