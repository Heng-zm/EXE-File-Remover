from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import sys
import time
import types
from pathlib import Path
from urllib.parse import urlencode


def _install_telegram_stubs() -> None:
    telegram = types.ModuleType("telegram")

    class Dummy:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    telegram.ChatPermissions = type("ChatPermissions", (Dummy,), {})
    telegram.InlineKeyboardButton = type("InlineKeyboardButton", (Dummy,), {})
    telegram.InlineKeyboardMarkup = type("InlineKeyboardMarkup", (Dummy,), {})
    telegram.Update = type("Update", (Dummy,), {})

    constants = types.ModuleType("telegram.constants")
    constants.ChatMemberStatus = type(
        "ChatMemberStatus",
        (),
        {
            "ADMINISTRATOR": "administrator",
            "OWNER": "creator",
            "CREATOR": "creator",
            "MEMBER": "member",
            "LEFT": "left",
            "BANNED": "kicked",
            "RESTRICTED": "restricted",
        },
    )
    constants.ChatType = type(
        "ChatType",
        (),
        {"GROUP": "group", "SUPERGROUP": "supergroup", "PRIVATE": "private", "CHANNEL": "channel"},
    )
    constants.ParseMode = type("ParseMode", (), {"HTML": "HTML"})

    errors = types.ModuleType("telegram.error")

    class TelegramError(Exception):
        pass

    errors.TelegramError = TelegramError
    errors.BadRequest = type("BadRequest", (TelegramError,), {})
    errors.Forbidden = type("Forbidden", (TelegramError,), {})
    errors.TimedOut = type("TimedOut", (TelegramError,), {})
    errors.RetryAfter = type("RetryAfter", (TelegramError,), {"retry_after": 1})

    ext = types.ModuleType("telegram.ext")

    class Filter:
        def __and__(self, other):
            return self

        def __or__(self, other):
            return self

        def __invert__(self):
            return self

    class FilterNamespace:
        def __init__(self):
            self.ALL = Filter()
            self.PRIVATE = Filter()
            self.GROUP = Filter()
            self.SUPERGROUP = Filter()
            self.MIGRATE = Filter()

        def __and__(self, other):
            return Filter()

        def __or__(self, other):
            return Filter()

        def __invert__(self):
            return Filter()

        def __getattr__(self, name):
            return FilterNamespace()

    class StubBot:
        id = 999
        username = "stubbot"

        async def get_me(self):
            return types.SimpleNamespace(id=self.id, username=self.username)

        async def delete_my_commands(self):
            return None

        async def set_webhook(self, **kwargs):
            self.webhook_kwargs = kwargs

        async def get_chat_administrators(self, chat_id):
            return [types.SimpleNamespace(user=types.SimpleNamespace(id=42, full_name="Tester", username="tester"), status="administrator")]

        async def get_chat_member(self, chat_id, user_id):
            if int(user_id) == int(self.id):
                return types.SimpleNamespace(status="administrator", can_delete_messages=True, can_restrict_members=True)
            return types.SimpleNamespace(status="administrator", can_delete_messages=True, can_restrict_members=True)

        async def ban_chat_member(self, chat_id, user_id):
            return True

        async def restrict_chat_member(self, chat_id, user_id, **kwargs):
            return True

        async def send_message(self, chat_id, text, **kwargs):
            return types.SimpleNamespace(message_id=123)

        async def edit_message_text(self, **kwargs):
            return True

    class StubApplication:
        def __init__(self):
            self.bot_data = {}
            self.bot = StubBot()
            self.job_queue = None

        def add_handler(self, *args, **kwargs):
            return None

        def add_error_handler(self, *args, **kwargs):
            return None

        async def process_update(self, update):
            return None

        async def initialize(self):
            return None

        async def start(self):
            return None

        async def stop(self):
            return None

        async def shutdown(self):
            return None

        def create_task(self, coroutine, **kwargs):
            import asyncio
            return asyncio.create_task(coroutine)

    class ApplicationBuilder:
        def __getattr__(self, name):
            if name == "build":
                return lambda: StubApplication()

            def chain(*args, **kwargs):
                return self

            return chain

    class Application:
        @classmethod
        def builder(cls):
            return ApplicationBuilder()

    ext.Application = Application
    ext.ApplicationBuilder = ApplicationBuilder
    ext.ApplicationHandlerStop = type("ApplicationHandlerStop", (Exception,), {})
    ext.CallbackQueryHandler = type("CallbackQueryHandler", (Dummy,), {})
    ext.ChatMemberHandler = type("ChatMemberHandler", (Dummy,), {"MY_CHAT_MEMBER": 1})
    ext.CommandHandler = type("CommandHandler", (Dummy,), {})
    ext.ContextTypes = type("ContextTypes", (), {"DEFAULT_TYPE": object})
    ext.MessageHandler = type("MessageHandler", (Dummy,), {})
    ext.PicklePersistence = type("PicklePersistence", (Dummy,), {})
    ext.TypeHandler = type("TypeHandler", (Dummy,), {})
    ext.filters = FilterNamespace()

    sys.modules["telegram"] = telegram
    sys.modules["telegram.constants"] = constants
    sys.modules["telegram.error"] = errors
    sys.modules["telegram.ext"] = ext


def _load_runtime():
    _install_telegram_stubs()
    sys.modules.pop("exe_remover_bot_app.miniapp_api", None)
    sys.modules.pop("exe_remover_bot_app.bot", None)
    return importlib.import_module("exe_remover_bot_app.bot")



def _signed_init_data(bot_token: str, user_id: int = 42) -> str:
    values = {
        "auth_date": str(int(time.time())),
        "query_id": "test-query",
        "user": json.dumps({"id": user_id, "first_name": "Tester", "language_code": "km"}, separators=(",", ":")),
    }
    data_check = "\n".join(f"{key}={value}" for key, value in sorted(values.items()))
    secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    values["hash"] = hmac.new(secret_key, data_check.encode("utf-8"), hashlib.sha256).hexdigest()
    return urlencode(values)

def test_runtime_builds_and_public_api_routes_respond():
    from fastapi.testclient import TestClient

    bot = _load_runtime()
    application = bot.build_application()
    miniapp = importlib.import_module("exe_remover_bot_app.miniapp_api")
    api = miniapp.create_mini_app_fastapi(application, "https://example.com/tg-webhook/test")
    assert len(api.routes) >= 50
    with TestClient(api) as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/health").json()["ok"] is True
        assert client.get("/api/routes").json()["ok"] is True
        assert client.get("/app").status_code == 200
        assert "EXE Remover Security" in client.get("/app").text
        assert client.get("/app/assets/app.js").status_code == 200
        dashboard_config = client.get("/app/config.js")
        assert dashboard_config.status_code == 200
        assert '"apiPrefix":"/api"' in dashboard_config.text
        presets = client.get("/api/scanner/presets?lang=km").json()
        assert presets["ok"] is True
        assert len(presets["presets"]) == 5
        bootstrap = client.post("/api/bootstrap", json={}).json()
        assert bootstrap["ok"] is True
        assert bootstrap["authenticated"] is False
    assert application.bot.webhook_kwargs["url"] == "https://example.com/tg-webhook/test"


def test_runtime_migrates_local_state_and_tracks_schema_meta():
    bot = _load_runtime()
    state = {
        "user_state": {"42": {"groups": ["-1001"]}},
        "group_state": {-1001: {"title": "Legacy"}},
    }

    assert bot.migrate_local_bot_data_in_place(state) is True
    assert state[bot.LOCAL_STATE_META_KEY]["schema"] == 7
    assert 42 in state["user_state"]
    assert "-1001" in state["group_state"]

    payload = bot.export_bot_data_for_storage(state)
    assert payload["_meta"]["schema"] == 7
    assert payload["_meta"]["revision"] >= state[bot.LOCAL_STATE_META_KEY]["revision"]


def test_authenticated_v35_policy_and_incident_routes():
    from fastapi.testclient import TestClient

    bot = _load_runtime()
    application = bot.build_application()
    miniapp = importlib.import_module("exe_remover_bot_app.miniapp_api")
    bot.BOT_OWNER_IDS = (42,)
    miniapp.BOT_OWNER_IDS = (42,)
    application.bot_data.update(
        {
            "group_state": {"-1001": {"title": "Security Group", "settings": {}}},
            "incidents": {
                "one": {
                    "chat_id": -1001,
                    "sender_id": 7,
                    "sender_name": "Sender",
                    "file_name": "payload.exe",
                    "reason": "pe_magic_header",
                    "matched_extension": ".exe",
                    "created_at_ms": 1_800_000_000_000,
                    "done": False,
                },
                "two": {
                    "chat_id": -1001,
                    "sender_id": 8,
                    "sender_name": "Other",
                    "file_name": "archive.zip",
                    "reason": "custom_group_extension",
                    "created_at_ms": 1_700_000_000_000,
                    "done": True,
                    "action": "ignore",
                },
            },
        }
    )
    api_app = miniapp.create_mini_app_fastapi(application, "https://example.com/tg-webhook/test")
    headers = {"X-Telegram-Init-Data": _signed_init_data(bot.BOT_TOKEN)}

    with TestClient(api_app) as client:
        bootstrap = client.post("/api/bootstrap", headers=headers, json={})
        assert bootstrap.status_code == 200
        assert bootstrap.json()["features"]["group_policies"] is True
        assert bootstrap.json()["features"]["workflow_center"] is True

        policies = client.get("/api/groups/-1001/policies?lang=km", headers=headers)
        assert policies.status_code == 200
        assert policies.json()["policy"]["scanner_preset"] == "standard"

        applied = client.post("/api/groups/-1001/presets/documents", headers=headers, json={})
        assert applied.status_code == 200
        assert applied.json()["group"]["settings"]["allowed_only"] is True

        updated = client.patch(
            "/api/groups/-1001/policies",
            headers=headers,
            json={"notification_policy": "admins_only", "incident_retention_days": 90},
        )
        assert updated.status_code == 200
        assert updated.json()["policy"]["notification_policy"] == "admins_only"
        assert updated.json()["policy"]["scanner_preset"] == "custom"

        incidents = client.get(
            "/api/groups/-1001/incidents?severity=critical&page=1&page_size=1",
            headers=headers,
        )
        assert incidents.status_code == 200
        payload = incidents.json()
        assert payload["total"] == 1
        assert payload["incidents"][0]["severity"] == "critical"
        assert payload["pagination"]["page_size"] == 1


        synchronized = client.post("/api/groups/-1001/sync", headers=headers, json={})
        assert synchronized.status_code == 200
        sync_payload = synchronized.json()
        assert sync_payload["ok"] is True
        assert sync_payload["workflow"]["status"] == "completed"
        assert sync_payload["report"]["chat_id"] == -1001

        workflows = client.get("/api/groups/-1001/workflows?limit=20&include_events=true", headers=headers)
        assert workflows.status_code == 200
        workflow_payload = workflows.json()
        assert workflow_payload["total"] >= 1
        assert any(item["kind"] == "group_sync" for item in workflow_payload["workflows"])


def test_group_document_runs_one_coordinated_workflow(monkeypatch):
    import asyncio

    bot = _load_runtime()
    application = bot.build_application()
    application.bot_data.update(
        {
            "group_state": {
                "-1001": {
                    "title": "Security Group",
                    "lang": "en",
                    "settings": {
                        "protection_enabled": True,
                        "strictness": "standard",
                        "auto_action_mode": "off",
                        "notification_policy": "group_only",
                    },
                }
            }
        }
    )

    async def no_persist(*args, **kwargs):
        return True

    monkeypatch.setattr(bot, "persist_context_memory", no_persist)
    monkeypatch.setattr(bot, "trusted_hash_whitelist_enabled", lambda bot_data: False)

    sender = types.SimpleNamespace(
        id=7,
        first_name="Sender",
        last_name="",
        full_name="Sender",
        username="sender",
        language_code="en",
        is_bot=False,
    )
    document = types.SimpleNamespace(
        file_id="file-1",
        file_name="payload.exe",
        mime_type="application/octet-stream",
        file_size=1024,
    )

    class Message:
        message_id = 55
        from_user = sender

        def __init__(self):
            self.document = document
            self.deleted = False

        async def delete(self):
            self.deleted = True

    message = Message()
    chat = types.SimpleNamespace(id=-1001, title="Security Group", type="supergroup")
    update = types.SimpleNamespace(
        effective_message=message,
        effective_chat=chat,
        effective_user=sender,
    )
    context = types.SimpleNamespace(
        bot=application.bot,
        bot_data=application.bot_data,
        job_queue=None,
        application=application,
    )

    asyncio.run(bot.handle_document(update, context))

    assert message.deleted is True
    incidents = application.bot_data["incidents"]
    assert len(incidents) == 1
    incident = next(iter(incidents.values()))
    assert incident["workflow_id"]
    workflows = application.bot_data["workflow_history"]
    moderation = next(item for item in workflows if item["id"] == incident["workflow_id"])
    assert moderation["kind"] == "file_moderation"
    assert moderation["status"] == "completed"
    assert moderation["outcome"] == "blocked_and_removed"
    stages = [event["stage"] for event in moderation["events"]]
    assert "policy_evaluated" in stages
    assert "scanned" in stages
    assert "deleted" in stages
    assert "incident_recorded" in stages
    assert "notifications" in stages
