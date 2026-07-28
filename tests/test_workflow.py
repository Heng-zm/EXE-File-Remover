from exe_remover_bot_app.workflow import (
    advance_workflow,
    begin_workflow,
    complete_workflow,
    list_workflows,
    reconcile_group_state,
    recover_interrupted_workflows,
    select_auto_action,
)


def test_workflow_lifecycle_and_group_filtering():
    state = {}
    record = begin_workflow(
        state,
        kind="file_moderation",
        chat_id=-1001,
        actor_id=7,
        source="telegram_group",
        subject_id=55,
        metadata={"file_name": "payload.exe"},
        at_ms=1_000,
    )
    advance_workflow(state, record["id"], stage="scanned", at_ms=2_000, detail="pe_magic_header")
    completed = complete_workflow(
        state,
        record["id"],
        at_ms=3_000,
        outcome="blocked_and_removed",
        detail="dangerous file deleted",
    )
    assert completed is not None
    assert completed["status"] == "completed"
    assert completed["progress"] == 100
    page = list_workflows(state, chat_id=-1001, include_events=True)
    assert page.total == 1
    assert page.items[0]["metadata"]["file_name"] == "payload.exe"
    assert len(page.items[0]["events"]) >= 3


def test_shared_auto_action_selection_is_deterministic():
    settings = {"auto_action_mode": "smart", "auto_mute_threshold": 2, "auto_ban_threshold": 3}
    assert select_auto_action(settings, incident_count=1) == "warn"
    assert select_auto_action(settings, incident_count=2) == "mute"
    assert select_auto_action(settings, incident_count=3) == "ban"
    assert select_auto_action({"auto_action_mode": "off"}, incident_count=99) == "none"


def test_group_reconciliation_repairs_state_and_prunes_expired_records():
    now = 2_000_000_000_000
    state = {
        "group_state": {"-1001": {"settings": {"incident_retention_days": 30}}},
        "incidents": {
            "old": {"chat_id": -1001, "created_at_ms": now - 31 * 86_400_000},
            "new": {"chat_id": -1001, "created_at_ms": now - 1_000},
        },
        "incident_tokens": {"old-token": "old", "new-token": "new", "orphan": "missing"},
    }
    report = reconcile_group_state(state, -1001, at_ms=now)
    assert report["incidents_removed"] == 1
    assert "old" not in state["incidents"]
    assert "new" in state["incidents"]
    assert state["incident_tokens"] == {"new-token": "new"}
    assert state["group_state"]["-1001"]["last_sync_ms"] == now


def test_stale_running_workflow_is_recovered_after_restart():
    state = {}
    begin_workflow(
        state,
        kind="group_sync",
        chat_id=-1001,
        actor_id=42,
        source="miniapp",
        subject_id=-1001,
        at_ms=1_000,
    )
    recovered = recover_interrupted_workflows(state, at_ms=2_000_000, max_running_age_ms=60_000)
    assert recovered == 1
    page = list_workflows(state, chat_id=-1001)
    assert page.items[0]["status"] == "interrupted"
