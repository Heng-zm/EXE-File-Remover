from __future__ import annotations

import asyncio
import uuid

from exe_remover_bot_app.callback_ux import claim_callback_action
from exe_remover_bot_app.diagnostics import (
    _server_log_safe_text,
    _server_log_safe_value,
    privacy_safe_client_id,
)
from exe_remover_bot_app.startup import validate_startup_config


class _DummyQuery:
    def __init__(self, data: str):
        self.data = data
        self.from_user = type("User", (), {"id": 123})()
        chat = type("Chat", (), {"id": -100456})()
        self.message = type("Message", (), {"chat": chat})()


def test_log_redaction_covers_urls_json_headers_and_bot_tokens():
    bot_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef123456"
    raw = (
        'Authorization: Bearer super-secret-token '
        'redis_url=rediss://admin:p%40ss@redis.example.com:6380/0?token=redis-secret '
        'payload={"service_role_key":"service-secret","initData":"signed-user-data"} '
        f'bot={bot_token}'
    )
    safe = _server_log_safe_text(raw, max_chars=2000)

    for leaked in (
        "super-secret-token",
        "p%40ss",
        "redis-secret",
        "service-secret",
        "signed-user-data",
        bot_token,
    ):
        assert leaked not in safe
    assert "<redacted>" in safe


def test_nested_sensitive_log_fields_are_redacted():
    safe = _server_log_safe_value(
        {
            "user_id": 42,
            "authorization": "Bearer top-secret",
            "nested": {"api_key": "abc", "normal": "ok"},
        }
    )
    assert safe["user_id"] == 42
    assert safe["authorization"] == "<redacted>"
    assert safe["nested"]["api_key"] == "<redacted>"
    assert safe["nested"]["normal"] == "ok"


def test_client_address_is_fingerprinted_by_default():
    first = privacy_safe_client_id("203.0.113.10")
    second = privacy_safe_client_id("203.0.113.10")
    other = privacy_safe_client_id("203.0.113.11")

    assert first.startswith("client:")
    assert "203.0.113.10" not in first
    assert first == second
    assert first != other


def test_duplicate_callback_mutations_are_rejected_within_window():
    query = _DummyQuery(f"gset:-100456:protection:{uuid.uuid4().hex}")

    async def scenario() -> tuple[bool, bool]:
        first = await claim_callback_action(query, cooldown_seconds=5.0, max_items=1000)
        second = await claim_callback_action(query, cooldown_seconds=5.0, max_items=1000)
        return first, second

    first, second = asyncio.run(scenario())
    assert first is True
    assert second is False


def test_startup_rejects_public_logs_query_keys_and_weak_log_key():
    report = validate_startup_config(
        {
            "BOT_TOKEN": "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef123456",
            "BOT_MODE": "POLLING",
            "LOCAL_PERSISTENCE_ENABLED": False,
            "REDIS_ENABLED": False,
            "SUPABASE_ENABLED": False,
            "MINI_APP_API_ENABLED": False,
            "SERVER_LOG_PUBLIC_ACCESS": True,
            "SERVER_LOG_AUTH_QUERY_ENABLED": True,
            "SERVER_LOG_API_KEY": "weak",
        }
    )
    codes = {issue.code for issue in report.errors}
    assert {"public_server_logs", "query_log_key", "server_log_api_key"} <= codes


def test_callback_feedback_is_bilingual_plain_and_telegram_safe():
    from exe_remover_bot_app.translations import TEXTS

    keys = {
        "callback_opening",
        "callback_loading",
        "callback_processing",
        "callback_saving",
        "callback_refreshing",
        "callback_action_processing",
        "callback_already_processing",
        "callback_invalid",
        "callback_failed_alert",
        "callback_security_blocked",
    }
    for lang in ("en", "km"):
        for key in keys:
            text = TEXTS[lang][key]
            assert text.strip()
            assert len(text) <= 200
            assert "<" not in text and ">" not in text
