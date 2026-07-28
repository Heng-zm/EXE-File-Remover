from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path


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
    assert state[bot.LOCAL_STATE_META_KEY]["schema"] == 5
    assert 42 in state["user_state"]
    assert "-1001" in state["group_state"]

    payload = bot.export_bot_data_for_storage(state)
    assert payload["_meta"]["schema"] == 5
    assert payload["_meta"]["revision"] >= state[bot.LOCAL_STATE_META_KEY]["revision"]
