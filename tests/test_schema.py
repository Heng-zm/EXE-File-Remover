from exe_remover_bot_app.schema import (
    CURRENT_SCHEMA_VERSION,
    SchemaMigrationError,
    is_newer_snapshot,
    migrate_state_payload,
    payload_revision,
)


def test_migrates_legacy_payload_to_current_schema():
    legacy = {
        "user_state": {"123": {"groups": [-1001]}},
        "group_state": {-1001: {"title": "Demo"}},
        "_meta": {"schema": 1, "saved_at_ms": 12345},
    }
    result = migrate_state_payload(legacy)
    assert result.to_version == CURRENT_SCHEMA_VERSION
    assert result.payload["_meta"]["schema"] == CURRENT_SCHEMA_VERSION
    assert payload_revision(result.payload) >= 12345
    assert 123 in result.payload["user_state"]
    assert "-1001" in result.payload["group_state"]
    assert isinstance(result.payload["user_feedback"], list)
    assert isinstance(result.payload["admin_action_logs"], list)


def test_future_schema_is_rejected():
    try:
        migrate_state_payload({"_meta": {"schema": CURRENT_SCHEMA_VERSION + 1}})
    except SchemaMigrationError:
        pass
    else:
        raise AssertionError("future schema must be rejected")


def test_newer_snapshot_prefers_revision_then_timestamp():
    assert is_newer_snapshot(
        incoming_revision=11, incoming_saved_at_ms=100,
        current_revision=10, current_saved_at_ms=999,
    )
    assert not is_newer_snapshot(
        incoming_revision=9, incoming_saved_at_ms=9999,
        current_revision=10, current_saved_at_ms=100,
    )
