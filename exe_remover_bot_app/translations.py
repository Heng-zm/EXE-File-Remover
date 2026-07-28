from __future__ import annotations

from .config import PROFESSIONAL_UI_ENABLED

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
            "Status: 🟢 <b>Online and protecting groups</b>\n\n"
            "Use this dashboard to review group health, update scanner rules, manage trusted files, and handle incidents."
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
            "ស្ថានភាព៖ 🟢 <b>Online និងកំពុងការពារក្រុម</b>\n\n"
            "ប្រើ Dashboard នេះដើម្បីពិនិត្យសុខភាពក្រុម កែប្រែច្បាប់ Scanner គ្រប់គ្រង Trusted Files និងដោះស្រាយ Incident។"
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
        "btn_refresh_dashboard": "🔄 Refresh Status",
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
        "btn_refresh_dashboard": "🔄 ធ្វើបច្ចុប្បន្នភាពស្ថានភាព",
        "btn_refresh_groups": "🔄 ធ្វើបច្ចុប្បន្នភាពក្រុម",
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

UX_REFINEMENT_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "dashboard_summary": (
            "\n\n📊 <b>Current overview</b>\n"
            "Groups: <code>{groups}</code> · Protection on: <code>{protected}</code>\n"
            "Open incidents: <code>{incidents}</code> · Storage: <code>{storage}</code>\n\n"
            "Select a button below."
        ),
        "btn_about": "ℹ️ About & Security",
        "silent_on": "Enabled",
        "silent_off": "Disabled",
    },
    "km": {
        "dashboard_summary": (
            "\n\n📊 <b>ស្ថានភាពបច្ចុប្បន្ន</b>\n"
            "ក្រុម៖ <code>{groups}</code> · បានបើកការពារ៖ <code>{protected}</code>\n"
            "Incident កំពុងបើក៖ <code>{incidents}</code> · Storage៖ <code>{storage}</code>\n\n"
            "សូមជ្រើសរើសប៊ូតុងខាងក្រោម។"
        ),
        "btn_about": "ℹ️ អំពី Bot និងសុវត្ថិភាព",
        "silent_on": "បានបើក",
        "silent_off": "បានបិទ",
    },
}
for _lang, _items in UX_REFINEMENT_TEXTS.items():
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


V35_KHMER_UI_TEXTS: dict[str, str] = {
    "group_admin_title": (
        "⚙️ <b>ផ្ទាំងគ្រប់គ្រងក្រុម</b>\n💬 <b>{group}</b> <code>{chat_id}</code>\n\n"
        "🛡 ការការពារ៖ <code>{protection}</code>\n"
        "🔥 កម្រិតតឹងរ៉ឹង៖ <code>{strictness}</code>\n"
        "🔇 សារជូនដំណឹងបណ្ដោះអាសន្ន៖ <code>{silent}</code>\n"
        "🧩 ប្រភេទឯកសារដែលទប់ស្កាត់៖ <code>{custom_blocked}</code>\n"
        "✅ ប្រភេទឯកសារដែលអនុញ្ញាត៖ <code>{allowed}</code>\n"
        "🔐 លេខសម្គាល់ឯកសារដែលទុកចិត្ត៖ <code>{trusted_hashes}</code>\n"
        "⚙️ វិធានការស្វ័យប្រវត្តិ៖ <code>{auto_action}</code>"
    ),
    "btn_incident_logs": "🚨 ប្រវត្តិករណីល្មើស",
    "btn_blocked_formats": "🧩 ប្រភេទឯកសារដែលទប់ស្កាត់",
    "btn_allowed_formats": "✅ ប្រភេទឯកសារដែលអនុញ្ញាត",
    "btn_strictness_level": "🔥 កម្រិតតឹងរ៉ឹង",
    "btn_refresh_incidents": "🔄 ធ្វើបច្ចុប្បន្នភាពករណី",
    "btn_incidents_short": "🚨 ករណីល្មើស",
    "btn_blocked_formats_short": "🧩 ឯកសារទប់ស្កាត់",
    "btn_allowed_formats_short": "✅ ឯកសារអនុញ្ញាត",
    "language_title": "🌐 <b>ជ្រើសរើសភាសាផ្ទាំងគ្រប់គ្រង</b>\n\nសូមជ្រើសភាសាសម្រាប់ផ្ទាំងគ្រប់គ្រងឯកជន និងសារជូនដំណឹង។",
    "bot_admin_required_title": (
        "🔒 <b>ការកំណត់ Bot ត្រូវបានចាក់សោ</b>\n"
        "💬 <b>{group}</b> <code>{chat_id}</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "ស្ថានភាព Bot៖ <code>{status}</code>\n"
        "សិទ្ធិលុបសារ៖ {can_delete}\n"
        "សិទ្ធិដាក់កម្រិត ឬហាមឃាត់សមាជិក៖ {can_restrict}\n\n"
        "ដើម្បីបើកការកំណត់ អ្នកគ្រប់គ្រងក្រុមត្រូវដាក់ Bot ជា <b>អ្នកគ្រប់គ្រង</b> "
        "ហើយបើកសិទ្ធិ <b>លុបសារ</b>។\n\n"
        "ចុច <b>ដាក់ Bot ជាអ្នកគ្រប់គ្រង</b> រួចត្រឡប់មកចុច <b>ពិនិត្យម្តងទៀត</b>។"
    ),
    "bot_admin_required_group": (
        "🔒 <b>ការកំណត់ត្រូវបានចាក់សោ។</b>\n\n"
        "សូមដាក់ខ្ញុំជា <b>អ្នកគ្រប់គ្រង</b> ក្នុងក្រុម ហើយបើកសិទ្ធិ <b>លុបសារ</b>។ "
        "ប៊ូតុងការកំណត់នឹងបង្ហាញក្រោយពេលសិទ្ធិត្រូវបានផ្ទៀងផ្ទាត់។"
    ),
    "btn_add_bot_admin": "➕ ដាក់ Bot ជាអ្នកគ្រប់គ្រង",
    "first_time_home_title": (
        "🛡️ <b>{brand}</b> <code>{version}</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "សូមស្វាគមន៍! មិនទាន់មានក្រុមដែលបានភ្ជាប់ការពារទេ។\n\n"
        "ដើម្បីចាប់ផ្ដើម សូមបន្ថែម Bot ទៅក្នុងក្រុម Telegram ដាក់ជា <b>អ្នកគ្រប់គ្រង</b> "
        "ហើយបើកសិទ្ធិ <b>លុបសារ</b>។\n\n"
        "ប៊ូតុងរៀបចំដំបូងនឹងបង្ហាញរហូតដល់ក្រុមទីមួយត្រូវបានភ្ជាប់។"
    ),
    "about_title": (
        "ℹ️ <b>អំពី {brand}</b> <code>{version}</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Bot នេះការពារក្រុម Telegram ពីឯកសារដំណើរការដែលមានគ្រោះថ្នាក់ ដូចជា <code>.exe</code> "
        "ឯកសារបន្លំឈ្មោះ ឯកសារបង្រួមមានហានិភ័យ និងអ្នកល្មើសដដែលៗ។\n\n"
        "មុខងារសំខាន់ៗ៖\n"
        "✅ លុបឯកសារគ្រោះថ្នាក់ដោយស្វ័យប្រវត្តិ\n"
        "✅ ជូនដំណឹងអ្នកគ្រប់គ្រងភ្លាមៗ\n"
        "✅ ប៊ូតុងហាមឃាត់ ព្រមាន ឬរំលង\n"
        "✅ គោលការណ៍ស្កេនជាក់លាក់សម្រាប់ក្រុមនីមួយៗ\n"
        "✅ លេខសម្គាល់ SHA-256 សម្រាប់ឯកសារដែលទុកចិត្ត"
    ),
    "risk_profile_title": (
        "📋 <b>ប្រវត្តិហានិភ័យរបស់អ្នកប្រើ</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "👤 អ្នកប្រើ៖ {user}\n"
        "🆔 លេខសម្គាល់៖ <code>{target_user_id}</code>\n"
        "💬 ក្រុម៖ <b>{group}</b>\n"
        "📊 កម្រិតហានិភ័យ៖ <code>{risk}</code>\n"
        "🚨 ករណីសរុប៖ <code>{incidents}</code>\n"
        "⚠️ ការព្រមាន៖ <code>{warns}</code>\n"
        "🔇 ការផ្អាកសារ៖ <code>{mutes}</code>\n"
        "🔨 ការហាមឃាត់៖ <code>{bans}</code>\n"
        "📄 ឯកសារចុងក្រោយ៖ <code>{last_file}</code>\n"
        "🕒 ករណីចុងក្រោយ៖ <code>{last_seen}</code>\n\n"
        "វិធានការណែនាំ៖ <b>{recommended}</b>"
    ),
    "risk_recommend_mute": "ផ្អាកការផ្ញើសារ ប្រសិនបើនៅតែបន្ត",
    "risk_recommend_ban": "ហាមឃាត់អ្នកដែលល្មើសដដែលៗ",
}
TEXTS.setdefault("km", {}).update(V35_KHMER_UI_TEXTS)


CALLBACK_UX_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "callback_opening": "Opening…",
        "callback_loading": "Loading…",
        "callback_processing": "Processing…",
        "callback_saving": "Saving changes…",
        "callback_refreshing": "Refreshing…",
        "callback_action_processing": "Applying action…",
        "callback_already_processing": "This action is already being processed. Please wait a moment.",
        "callback_invalid": "This button is invalid or outdated. Please reopen the latest panel.",
        "callback_expired_alert": "This incident has expired or was already removed.",
        "callback_done_alert": "Another admin already handled this incident.",
        "callback_not_admin_alert": "You no longer have admin permission for this group.",
        "callback_failed_alert": "I could not complete that action. Please try again.",
        "callback_saved_alert": "Saved successfully.",
        "callback_cancelled_alert": "Cancelled. No changes were made.",
        "callback_security_blocked": "For security, this setting can only be changed in private chat.",
        "callback_retry_hint": "Please reopen the latest panel and try again.",
        "error_reference": "Reference: <code>{reference}</code>",
    },
    "km": {
        "callback_opening": "កំពុងបើក…",
        "callback_loading": "កំពុងផ្ទុក…",
        "callback_processing": "កំពុងដំណើរការ…",
        "callback_saving": "កំពុងរក្សាទុក…",
        "callback_refreshing": "កំពុងធ្វើបច្ចុប្បន្នភាព…",
        "callback_action_processing": "កំពុងអនុវត្តចំណាត់ការ…",
        "callback_already_processing": "ចំណាត់ការនេះកំពុងដំណើរការរួចហើយ។ សូមរង់ចាំបន្តិច។",
        "callback_invalid": "ប៊ូតុងនេះផុតកំណត់ ឬមិនត្រឹមត្រូវ។ សូមបើកផ្ទាំងថ្មីបំផុតម្តងទៀត។",
        "callback_expired_alert": "ករណីនេះផុតកំណត់ ឬត្រូវបានលុបរួចហើយ។",
        "callback_done_alert": "Admin ផ្សេងទៀតបានចាត់ការករណីនេះរួចហើយ។",
        "callback_not_admin_alert": "អ្នកលែងមានសិទ្ធិ Admin សម្រាប់ក្រុមនេះទៀតហើយ។",
        "callback_failed_alert": "ខ្ញុំមិនអាចបញ្ចប់ចំណាត់ការនេះបានទេ។ សូមព្យាយាមម្តងទៀត។",
        "callback_saved_alert": "បានរក្សាទុកដោយជោគជ័យ។",
        "callback_cancelled_alert": "បានបោះបង់។ មិនមានការកែប្រែទេ។",
        "callback_security_blocked": "ដើម្បីសុវត្ថិភាព ការកំណត់នេះអាចកែបានតែក្នុង Private Chat ប៉ុណ្ណោះ។",
        "callback_retry_hint": "សូមបើកផ្ទាំងថ្មីបំផុត ហើយព្យាយាមម្តងទៀត។",
        "error_reference": "លេខយោង៖ <code>{reference}</code>",
    },
}
for _lang, _values in CALLBACK_UX_TEXTS.items():
    TEXTS.setdefault(_lang, {}).update(_values)


__all__ = ["TEXTS", "FIRST_TIME_DASHBOARD_TEXTS", "V35_KHMER_UI_TEXTS", "CALLBACK_UX_TEXTS"]
