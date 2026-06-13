"""
Telegram Bot - EXE File Remover (Render Production Ready)
• Deletes .exe files from groups
• Notifies every admin via DM with action buttons: Ban | Warn | Ignore
• Supports English 🇬🇧 and Khmer 🇰🇭
• Features: Webhook support for Render, Auto Self-Ping Keep-Awake, Persistent state
"""

import os
import logging
import asyncio
from datetime import datetime, timezone

from dotenv import load_dotenv
import httpx
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ChatMemberHandler,
    filters,
    ContextTypes,
    PicklePersistence,
)
from telegram.constants import ChatMemberStatus, ParseMode
from telegram.error import BadRequest, Forbidden

# ─────────────────────────────────────────────
# CONFIG & INITIALIZATION
# ─────────────────────────────────────────────
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    raise ValueError("CRITICAL: BOT_TOKEN is missing. Please set it in your environment variables.")

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Render Environment Variables (Injected automatically by Render)
PORT = int(os.getenv("PORT", "8080"))
RENDER_URL = os.getenv("RENDER_EXTERNAL_URL") 

# ─────────────────────────────────────────────
# HUMANIZED TRANSLATIONS
# ─────────────────────────────────────────────
TEXTS = {
    "en": {
        "welcome": (
            "👋 *Hey there! I'm your EXE Remover Bot.*\n\n"
            "🛡️ I keep your groups safe by instantly wiping out dangerous `.exe` files.\n"
            "📢 Whenever someone drops one, I'll slide into your DMs with quick options to *Ban*, *Warn*, or *Ignore* them.\n\n"
            "➡️ Ready to secure your chat? Just add me to your group and make sure I have the *Delete Messages* permission!"
        ),
        "select_lang":   "🌐 Please choose your preferred language / សូមជ្រើសរើសភាសារបស់អ្នក៖",
        "lang_set":      "✅ Got it! I'll speak to you in *English* from now on.",
        "add_btn":       "➕ Add Me to a Group",
        "check_btn":     "🔄 Check My Permissions",
        "no_group":      "⚠️ I haven't detected your group yet. Please add me to a group first, then click *Check My Permissions*.",
        "not_admin":     (
            "❌ *I don't look like an admin in your group yet.*\n\n"
            "Go to Group Settings → Administrators → Add Member → Select me, and turn on the *Delete Messages* option.\n\n"
            "Once that's done, click *Check My Permissions* again!"
        ),
        "no_delete_perm": (
            "⚠️ *I'm an admin, but I don't have the right permissions.*\n\n"
            "Please check my settings and make sure *Delete Messages* is allowed so I can do my job."
        ),
        "setup_ok": (
            "🎉 *Awesome! I'm all set up and ready to go.*\n\n"
            "I am now actively guarding *{group}*.\n"
            "If any `.exe` files pop up, I'll delete them immediately and alert the admin team. 🛡️"
        ),
        "exe_removed_group": (
            "🚫 *Heads up!* {user} just tried to send a `.exe` file, so I went ahead and removed it.\n"
            "We don't allow executable files here to keep everyone safe."
        ),
        "admin_alert": (
            "🚨 *Security Alert: EXE File Caught & Deleted!*\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "👤 *Sender:* {sender_name} (`{sender_id}`)\n"
            "📄 *File Name:* `{file_name}`\n"
            "💬 *Group:* {group_name} (`{group_id}`)\n"
            "📅 *Time:* {time} UTC\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "What action would you like to take against this user?"
        ),
        "btn_ban":    "🔨 Ban User",
        "btn_warn":   "⚠️ Warn User",
        "btn_ignore": "✅ Ignore",
        "action_ban_ok":    "🔨 *Action Taken:* {name} has been banned and kicked from the group.",
        "action_ban_fail":  "❌ *Oops!* I couldn't ban them. Make sure I have 'Ban Users' permission turned on.",
        "action_warn_ok":   "⚠️ *Action Taken:* I've dropped a formal warning for {name} directly in the chat.",
        "action_ignore_ok": "✅ *Action Taken:* This incident has been ignored. No further changes made.",
        "action_done":      "_(Another admin has already handled this incident)_",
        "warn_in_group": (
            "⚠️ *Official Warning* — {user}\n"
            "Sending `.exe` files is strictly prohibited here. "
            "Please refrain from doing it again, or you may find yourself permanently banned from the community."
        ),
        "help": (
            "💡 *EXE Remover Bot — Quick Guide*\n\n"
            "/start  — Choose language and change settings\n"
            "/help   — Bring up this help guide\n"
            "/status — Check if I'm running smoothly (Send inside a group)\n"
            "/admins — See which admins are receiving alerts (Send inside a group)"
        ),
        "status_ok":     "✅ Everything is running perfectly! I am actively watching for `.exe` files and alerting admins.",
        "status_no":     "❌ I am currently inactive because I'm not an admin. Please grant me *Delete Messages* permissions.",
        "admins_header": "👮 *Here are the admins signed up for alerts in this chat:*\n",
        "admins_note":   "\n_Note: Only admins who have private messaged /started the bot will get DM alerts._",
    },
    "km": {
        "welcome": (
            "👋 *សួស្ដីបាទ! ខ្ញុំជា EXE Remover Bot។*\n\n"
            "🛡️ ខ្ញុំមានតួនាទីជួយការពារក្រុមពិភាក្សារបស់អ្នក ដោយលុបឯកសារប្រភេទ `.exe` ចោលភ្លាមៗដោយស្វ័យប្រវត្តិ។\n"
            "📢 នៅពេលមានសមាជិកផ្ញើវាចូល ខ្ញុំនឹងផ្ញើសារមកកាន់ DM របស់ Admin ភ្លាមៗជាមួយជម្រើស *ហាមឃាត់*, *ព្រមាន* ឬ *មិនអើពើ*។\n\n"
            "➡️ ដើម្បីចាប់ផ្ដើម សូមទាញខ្ញុំចូលក្នុងក្រុមរបស់អ្នក រួចផ្ដល់សិទ្ធិជា *Admin* ដោយបើកសិទ្ធិ *លុបសារ (Delete Messages)* ផងបាទ!"
        ),
        "select_lang":   "🌐 Please choose your preferred language / សូមជ្រើសរើសភាសារបស់អ្នក៖",
        "lang_set":      "✅ បានកំណត់យក *ភាសាខ្មែរ* ជាផ្លូវការរួចរាល់ហើយបាទ។",
        "add_btn":       "➕ បន្ថែមខ្ញុំទៅក្នុងក្រុម",
        "check_btn":     "🔄 ពិនិត្យមើលការអនុញ្ញាតសិទ្ធិ",
        "no_group":      "⚠️ ខ្ញុំមិនទាន់ឃើញមានក្រុមណាមួយនៅឡើយទេ។ សូមបន្ថែមខ្ញុំទៅក្នុងក្រុមជាមុនសិន រួចចុចប៊ូតុង *ពិនិត្យមើលការអនុញ្ញាតសិទ្ធិ* ម្តងទៀត។",
        "not_admin":     (
            "❌ *ខ្ញុំហាក់ដូចជាមិនទាន់ក្លាយជា Admin នៅក្នុងក្រុមរបស់អ្នកនៅឡើយទេ។*\n\n"
            "សូមចូលទៅកាន់ ការកំណត់ក្រុម → អ្នកគ្រប់គ្រង (Administrators) → បន្ថែមសមាជិក → ជ្រើសរើសរូបខ្ញុំ រួចបើកសិទ្ធិ *លុបសារ (Delete Messages)*។\n\n"
            "បន្ទាប់ពីកំណត់រួចរាល់ហើយ សូមចុចប៊ូតុង *ពិនិត្យមើលការអនុញ្ញាតសិទ្ធិ* ឡើងវិញបាទ។"
        ),
        "no_delete_perm": (
            "⚠️ *ខ្ញុំជា Admin មែន ប៉ុន្តែមិនទាន់មានសិទ្ធិគ្រប់គ្រាន់ឡើយ។*\n\n"
            "សូមពិនិត្យមើលការកំណត់ Admin របស់ខ្ញុំឡើងវិញ រួចប្រាកដថាបានបើកសិទ្ធិ *លុបសារ (Delete Messages)* ដើម្បីឱ្យខ្ញុំអាចបំពេញភារកិច្ចបាន។"
        ),
        "setup_ok": (
            "🎉 *រួចរាល់ហើយបាទ! ខ្ញុំបានរៀបចំខ្លួនរួចជាស្រេចហើយ។*\n\n"
            "ឥឡូវនេះខ្ញុំកំពុងយាមកាមការពារក្រុម *{group}* យ៉ាងយកចិត្តទុកដាក់។\n"
            "រាល់ពេលមានឯកសារ `.exe` ផ្ញើចូល ខ្ញុំនឹងលុបវាចោលភ្លាម រួចរាយការណ៍ជូនក្រុម Admin ភ្លាមៗបាទ។ 🛡️"
        ),
        "exe_removed_group": (
            "🚫 *សូមប្រុងប្រយ័ត្ន!* {user} ទើបតែបានផ្ញើឯកសារប្រភេទ `.exe` ចូលក្នុងក្រុម ដូច្នេះខ្ញុំបានលុបវាចេញហើយបាទ។\n"
            "ក្រុមពិភាក្សារបស់យើងមិនអនុញ្ញាតឱ្យផ្ញើឯកសារដែលអាចដំឡើងបាន (Executable files) បែបនេះឡើយ ដើម្បីសុវត្ថិភាពសមាជិកទាំងអស់។"
        ),
        "admin_alert": (
            "🚨 *ការជូនដំណឹងសន្តិសុខ៖ រកឃើញ និងលុបឯកសារ EXE ចោលរួចរាល់!*\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "👤 *អ្នកផ្ញើ:* {sender_name} (`{sender_id}`)\n"
            "📄 *ឈ្មោះឯកសារ:* `{file_name}`\n"
            "💬 *ក្រុម:* {group_name} (`{group_id}`)\n"
            "📅 *ម៉ោង:* {time} UTC\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "តើលោក Admin ចង់ចាត់ការលើសមាជិករូបនេះបែបណាដែរ?"
        ),
        "btn_ban":    "🔨 ហាមឃាត់ (Ban)",
        "btn_warn":   "⚠️ ព្រមាន (Warn)",
        "btn_ignore": "✅ មិនអើពើ (Ignore)",
        "action_ban_ok":    "🔨 *សកម្មភាព៖* បានហាមឃាត់ និងបណ្ដេញ {name} ចេញពីក្រុមរួចរាល់។",
        "action_ban_fail":  "❌ *មានបញ្ហា៖* ខ្ញុំមិនអាច Ban គាត់បានឡើយ។ សូមពិនិត្យមើលថាខ្ញុំមានសិទ្ធិ 'Ban Users' ឬអត់។",
        "action_warn_ok":   "⚠️ *សកម្មភាព៖* ខ្ញុំបានផ្ញើសារព្រមានទៅកាន់ {name} នៅក្នុងក្រុមរួចរាល់ហើយ។",
        "action_ignore_ok": "✅ *សកម្មភាព៖* ជ្រើសរើសមិនអើពើ។ មិនមានការប្រែប្រួលអ្វីឡើយ។",
        "action_done":      "_(Admin ផ្សេងបានចាត់ការលើករណីនេះរួចរាល់ហើយ)_",
        "warn_in_group": (
            "⚠️ *ការព្រមានជាផ្លូវការ* — {user}\n"
            "ការផ្ញើឯកសារប្រភេទ `.exe` ត្រូវបានហាមឃាត់ដាច់ខាតនៅក្នុងក្រុមនេះ។ "
            "សូមមេត្តាកុំផ្ញើវាទៀតអី បើមិនដូច្នោះទេអ្នកអាចនឹងត្រូវបណ្ដេញចេញពីសហគមន៍យើងជាអចិន្ត្រៃយ៍។"
        ),
        "help": (
            "💡 *EXE Remover Bot — ណែនាំសង្ខេប*\n\n"
            "/start  — ជ្រើសរើសភាសា និងផ្លាស់ប្ដូរការកំណត់\n"
            "/help   — បង្ហាញសៀវភៅណែនាំជំនួយនេះ\n"
            "/status — ពិនិត្យមើលស្ថានភាពដំណើរការរបស់ Bot (ផ្ញើក្នុងក្រុម)\n"
            "/admins — មើលឈ្មោះ Admin ដែលទទួលបានការរាយការណ៍ (ផ្ញើក្នុងក្រុម)"
        ),
        "status_ok":     "✅ ដំណើរការជាធម្មតា និងប្រកបដោយសុវត្ថិភាព! ខ្ញុំកំពុងតាមដានឯកសារ `.exe` និងត្រៀមរាយការណ៍ជូន Admin ជានិច្ច។",
        "status_no":     "❌ ខ្ញុំមិនដំណើរការឡើយ ដោយសារមិនទាន់ជា Admin។ សូមមេត្តាជួយផ្ដល់សិទ្ធិ *លុបសារ (Delete Messages)* ដល់ខ្ញុំផងបាទ។",
        "admins_header": "👮 *នេះជាបញ្ជីឈ្មោះ Admin ដែលនឹងទទួលបានការរាយការណ៍ក្នុង DM ៖*\n",
        "admins_note":   "\n_សម្គាល់៖ មានតែ Admin ណាដែលធ្លាប់ចុច /start ជាមួយ Bot ក្នុងឆាតឯកជនប៉ុណ្ណោះ ទើបទទួលបានសាររាយការណ៍។_",
    },
}

# ─────────────────────────────────────────────
# HELPERS & ROUTINES
# ─────────────────────────────────────────────
def escape_md(text: str) -> str:
    return str(text).replace("_", "\\_").replace("*", "\\*").replace("`", "\\`").replace("[", "\\[")

def get_lang(bot_data: dict, user_id: int) -> str:
    return bot_data.get("user_state", {}).get(user_id, {}).get("lang", "en")

def t(bot_data: dict, user_id: int, key: str, **kwargs) -> str:
    lang = get_lang(bot_data, user_id)
    text = TEXTS[lang].get(key, TEXTS["en"].get(key, key))
    return text.format(**kwargs) if kwargs else text

def get_groups(bot_data: dict, user_id: int) -> list[int]:
    return bot_data.get("user_state", {}).get(user_id, {}).get("groups", [])

def add_group(bot_data: dict, user_id: int, chat_id: int):
    user_state = bot_data.setdefault("user_state", {})
    user_info = user_state.setdefault(user_id, {"lang": "en", "groups": []})
    if chat_id not in user_info["groups"]:
        user_info["groups"].append(chat_id)

async def get_admin_ids(bot, chat_id: int) -> list[int]:
    try:
        admins = await bot.get_chat_administrators(chat_id)
        return [a.user.id for a in admins if not a.user.is_bot]
    except Exception as e:
        logger.warning("Could not fetch admins for %s: %s", chat_id, e)
        return []

def action_keyboard(bot_data: dict, admin_id: int, ikey: str) -> InlineKeyboardMarkup:
    lang = get_lang(bot_data, admin_id)
    return InlineKeyboardMarkup([[
        InlineKeyboardButton(TEXTS[lang]["btn_ban"],    callback_data=f"act:ban:{ikey}"),
        InlineKeyboardButton(TEXTS[lang]["btn_warn"],   callback_data=f"act:warn:{ikey}"),
        InlineKeyboardButton(TEXTS[lang]["btn_ignore"], callback_data=f"act:ignore:{ikey}"),
    ]])

async def send_single_alert(context: ContextTypes.DEFAULT_TYPE, admin_id: int, msg: str, ikey: str):
    try:
        await context.bot.send_message(
            admin_id, msg,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=action_keyboard(context.bot_data, admin_id, ikey),
        )
    except (Forbidden, BadRequest):
        pass

async def notify_admins(context: ContextTypes.DEFAULT_TYPE, chat_id: int, group_name: str, sender, file_name: str, ikey: str):
    admin_ids = await get_admin_ids(context.bot, chat_id)
    now_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    sender_name = escape_md(sender.full_name) if sender else "Unknown"
    sender_id   = sender.id if sender else 0
    safe_group  = escape_md(group_name)

    tasks = []
    for admin_id in admin_ids:
        lang = get_lang(context.bot_data, admin_id)
        msg  = TEXTS[lang]["admin_alert"].format(
            sender_name=sender_name,
            sender_id=sender_id,
            file_name=escape_md(file_name),
            group_name=safe_group,
            group_id=chat_id,
            time=now_str,
        )
        tasks.append(send_single_alert(context, admin_id, msg, ikey))
    
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

# ─────────────────────────────────────────────
# JOBS (CLEANUP & KEEP-AWAKE PING)
# ─────────────────────────────────────────────
async def clean_old_incidents(context: ContextTypes.DEFAULT_TYPE):
    incidents = context.bot_data.get("incidents", {})
    if not incidents:
        return
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    to_delete = [ikey for ikey, d in incidents.items() if len(ikey.split(":")) == 3 and now_ms - int(ikey.split(":")[2]) > 86400000]
    for ikey in to_delete:
        del incidents[ikey]
    if to_delete:
        logger.info("Cleaned up %d stale incident(s) from memory.", len(to_delete))

async def keep_awake(context: ContextTypes.DEFAULT_TYPE):
    """Hits the external web port root routing mesh to force Render to stay active."""
    if RENDER_URL:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(RENDER_URL, timeout=10.0)
                logger.info("Self-ping keeping instances awake. Status: %s", response.status_code)
        except Exception as e:
            logger.warning("Keep-awake cycle execution missed: %s", e)

# ─────────────────────────────────────────────
# TELEGRAM HANDLERS
# ─────────────────────────────────────────────
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    kb = [[
        InlineKeyboardButton("🇬🇧 English",     callback_data="lang_en"),
        InlineKeyboardButton("🇰🇭 ភាសាខ្មែរ", callback_data="lang_km"),
    ]]
    await update.message.reply_text(t(context.bot_data, user_id, "select_lang"), reply_markup=InlineKeyboardMarkup(kb))

async def lang_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query   = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    lang    = query.data.split("_")[1]

    user_state = context.bot_data.setdefault("user_state", {})
    user_state.setdefault(user_id, {"lang": lang, "groups": []})
    user_state[user_id]["lang"] = lang

    kb = [
        [InlineKeyboardButton(t(context.bot_data, user_id, "add_btn"), url=f"https://t.me/{context.bot.username}?startgroup=add")],
        [InlineKeyboardButton(t(context.bot_data, user_id, "check_btn"), callback_data="check_perm")],
    ]
    await query.edit_message_text(
        t(context.bot_data, user_id, "lang_set") + "\n\n" + t(context.bot_data, user_id, "welcome"),
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=InlineKeyboardMarkup(kb),
    )

async def check_perm_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query   = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    groups  = get_groups(context.bot_data, user_id)
    retry_kb = InlineKeyboardMarkup([[InlineKeyboardButton(t(context.bot_data, user_id, "check_btn"), callback_data="check_perm")]])

    if not groups:
        await query.edit_message_text(t(context.bot_data, user_id, "no_group"), parse_mode=ParseMode.MARKDOWN, reply_markup=retry_kb)
        return

    results = []
    for chat_id in groups:
        try:
            chat   = await context.bot.get_chat(chat_id)
            member = await context.bot.get_chat_member(chat_id, context.bot.id)
            is_admin   = member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)
            can_delete = getattr(member, "can_delete_messages", False)
            safe_title = escape_md(chat.title or "Group")

            if not is_admin:
                results.append(("❌", safe_title, t(context.bot_data, user_id, "not_admin")))
            elif not can_delete:
                results.append(("⚠️", safe_title, t(context.bot_data, user_id, "no_delete_perm")))
            else:
                results.append(("✅", safe_title, t(context.bot_data, user_id, "setup_ok", group=safe_title)))
        except Exception as e:
            logger.warning("Perm check error for %s: %s", chat_id, e)

    msg = "\n\n".join(f"{i} *{ttl}*\n{d}" for i, ttl, d in results) if results else t(context.bot_data, user_id, "no_group")
    await query.edit_message_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=retry_kb)

async def action_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query    = update.callback_query
    await query.answer()

    admin_id  = query.from_user.id
    parts     = query.data.split(":", 2)
    action    = parts[1]
    ikey      = parts[2]

    incidents = context.bot_data.setdefault("incidents", {})
    incident  = incidents.get(ikey)
    
    if not incident or incident.get("done"):
        await query.edit_message_text(t(context.bot_data, admin_id, "action_done"), parse_mode=ParseMode.MARKDOWN)
        return

    incident["done"] = True   
    chat_id     = incident["chat_id"]
    sender_id   = incident["sender_id"]
    sender_name = escape_md(incident["sender_name"])
    file_name   = escape_md(incident["file_name"])
    group_name  = escape_md(incident.get("group_name", str(chat_id)))

    if action == "ban":
        try:
            await context.bot.ban_chat_member(chat_id, sender_id)
            result_msg = t(context.bot_data, admin_id, "action_ban_ok", name=sender_name)
        except Exception as e:
            incident["done"] = False
            result_msg = t(context.bot_data, admin_id, "action_ban_fail")
            logger.error("Ban failed: %s", e)

    elif action == "warn":
        user_mention = f"[{sender_name}](tg://user?id={sender_id})"
        warn_text = TEXTS[get_lang(context.bot_data, admin_id)]["warn_in_group"].format(user=user_mention)
        try:
            await context.bot.send_message(chat_id, warn_text, parse_mode=ParseMode.MARKDOWN)
            result_msg = t(context.bot_data, admin_id, "action_warn_ok", name=sender_name)
        except Exception as e:
            incident["done"] = False
            result_msg = f"❌ Could not send warning: {e}"
    else:
        result_msg = t(context.bot_data, admin_id, "action_ignore_ok")

    lang    = get_lang(context.bot_data, admin_id)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    new_text = TEXTS[lang]["admin_alert"].format(
        sender_name=sender_name, sender_id=sender_id, file_name=file_name,
        group_name=group_name, group_id=chat_id, time=now_str
    ) + f"\n\n{result_msg}"
    
    try:
        await query.edit_message_text(new_text, parse_mode=ParseMode.MARKDOWN)
    except Exception:
        pass

async def my_chat_member_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
    result     = update.my_chat_member
    new_status = result.new_chat_member.status
    chat       = result.chat

    if chat.type not in ("group", "supergroup") or new_status not in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.MEMBER):
        return

    adder_id   = result.from_user.id
    add_group(context.bot_data, adder_id, chat.id)
    can_delete = getattr(result.new_chat_member, "can_delete_messages", False)
    safe_title = escape_md(chat.title or "Group")

    msg = t(context.bot_data, adder_id, "setup_ok" if (new_status == ChatMemberStatus.ADMINISTRATOR and can_delete) else ("no_delete_perm" if new_status == ChatMemberStatus.ADMINISTRATOR else "not_admin"), group=safe_title)
    try:
        kb = [[InlineKeyboardButton(t(context.bot_data, adder_id, "check_btn"), callback_data="check_perm")]]
        await context.bot.send_message(adder_id, msg, parse_mode=ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
    except Exception:
        pass

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    if not message or not message.document:
        return

    file_name = (message.document.file_name or "").strip().lower()
    if not file_name.endswith(".exe") or message.chat.type not in ("group", "supergroup"):
        return

    sender       = message.from_user
    sender_name  = sender.full_name if sender else "Unknown"
    sender_id    = sender.id        if sender else 0
    user_mention = f"[{escape_md(sender_name)}](tg://user?id={sender_id})"

    try:
        await message.delete()
    except Exception as e:
        logger.error("Delete failed: %s", e)
        return

    try:
        await context.bot.send_message(message.chat.id, TEXTS["en"]["exe_removed_group"].format(user=user_mention), parse_mode=ParseMode.MARKDOWN)
    except Exception:
        pass

    ts = int(datetime.now(timezone.utc).timestamp() * 1000)
    ikey = f"{message.chat.id}:{sender_id}:{ts}"
    context.bot_data.setdefault("incidents", {})[ikey] = {
        "done": False, "chat_id": message.chat.id, "group_name": message.chat.title or str(message.chat.id),
        "sender_id": sender_id, "sender_name": sender_name, "file_name": message.document.file_name or "Unknown.exe"
    }
    await notify_admins(context, message.chat.id, message.chat.title or str(message.chat.id), sender, message.document.file_name or "Unknown.exe", ikey)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(t(context.bot_data, update.effective_user.id, "help"), parse_mode=ParseMode.MARKDOWN)

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if chat.type not in ("group", "supergroup"):
        await update.message.reply_text("Send /status inside a group.")
        return
    try:
        member = await context.bot.get_chat_member(chat.id, context.bot.id)
        msg = t(context.bot_data, update.effective_user.id, "status_ok" if (member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER) and getattr(member, "can_delete_messages", False)) else "status_no")
    except Exception as e:
        msg = f"Error: {e}"
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)

async def admins_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if chat.type not in ("group", "supergroup"):
        await update.message.reply_text("Send /admins inside a group.")
        return
    try:
        admins = await context.bot.get_chat_administrators(chat.id)
        lines = [f"{i}. [{escape_md(a.user.full_name)}](tg://user?id={a.user.id})" + (f" _{escape_md(a.custom_title)}_" if getattr(a, "custom_title", None) else "") for i, a in enumerate([a for a in admins if not a.user.is_bot], 1)]
        msg = t(context.bot_data, update.effective_user.id, "admins_header") + "\n".join(lines) + t(context.bot_data, update.effective_user.id, "admins_note")
    except Exception as e:
        msg = f"Error: {e}"
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)

# ─────────────────────────────────────────────
# MAIN EXECUTION
# ─────────────────────────────────────────────
def main():
    persistence = PicklePersistence(filepath="exe_bot_data.pickle")
    app = Application.builder().token(BOT_TOKEN).persistence(persistence).build()

    # Register handlers
    app.add_handler(CommandHandler("start",  start))
    app.add_handler(CommandHandler("help",   help_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("admins", admins_command))
    app.add_handler(CallbackQueryHandler(lang_callback,       pattern=r"^lang_(en|km)$"))
    app.add_handler(CallbackQueryHandler(check_perm_callback, pattern=r"^check_perm$"))
    app.add_handler(CallbackQueryHandler(action_callback,     pattern=r"^act:(ban|warn|ignore):.+$"))
    app.add_handler(ChatMemberHandler(my_chat_member_update,  ChatMemberHandler.MY_CHAT_MEMBER))
    app.add_handler(MessageHandler(filters.Document.ALL & (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP), handle_document))

    if app.job_queue:
        app.job_queue.run_repeating(clean_old_incidents, interval=3600, first=10)
        if RENDER_URL:
            # Wake loop runs every 10 minutes (600 seconds)
            app.job_queue.run_repeating(keep_awake, interval=600, first=30)

    # Production Webhook Engine vs Local Testing Polling Switch
    if RENDER_URL:
        logger.info("Production Mode: Starting Webhook engine on port %s", PORT)
        app.run_webhook(
            listen="0.0.0.0",
            port=PORT,
            url_path=BOT_TOKEN,
            webhook_url=f"{RENDER_URL}/{BOT_TOKEN}",
            allowed_updates=Update.ALL_TYPES
        )
    else:
        logger.info("Development Mode: Starting standard Polling system...")
        app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()