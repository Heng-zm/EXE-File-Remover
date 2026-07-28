from __future__ import annotations

from exe_remover_bot_app.incidents import incident_severity, paginate_incidents, prune_group_incidents


def _incident(index: int, *, done: bool = False, reason: str = "custom_group_extension", action: str = ""):
    return {
        "chat_id": -1001,
        "sender_id": 100 + (index % 3),
        "sender_name": f"User {index % 3}",
        "file_name": f"file-{index}.zip",
        "reason": reason,
        "done": done,
        "action": action,
        "created_at_ms": 1_700_000_000_000 + index * 1000,
    }


def test_incident_filters_and_pagination():
    incidents = {f"incident:{index}": _incident(index, done=index % 2 == 0) for index in range(45)}
    page = paginate_incidents(incidents, -1001, status="open", page=2, page_size=10)
    assert page.total == 22
    assert page.page == 2
    assert page.pages == 3
    assert len(page.items) == 10
    assert page.has_previous is True
    assert page.has_next is True
    assert page.counts["all"] == 45
    assert page.counts["open"] == 22
    assert page.counts["handled"] == 23


def test_incident_search_severity_action_and_sender_filters():
    incidents = {
        "a": _incident(1, reason="pe_magic_header", action="ban"),
        "b": _incident(2, reason="custom_group_extension", action="warn"),
        "c": _incident(3, reason="clean", action="ignore"),
    }
    assert incident_severity(incidents["a"]) == "critical"
    result = paginate_incidents(incidents, -1001, severity="critical", action="ban", query="file-1", sender_id=101)
    assert result.total == 1
    assert result.items[0][0] == "a"


def test_prune_group_incidents_respects_handled_only():
    now_ms = 2_000_000_000_000
    incidents = {
        "old-handled": {**_incident(1, done=True), "created_at_ms": now_ms - 40 * 86_400_000},
        "old-open": {**_incident(2, done=False), "created_at_ms": now_ms - 40 * 86_400_000},
        "recent": {**_incident(3, done=True), "created_at_ms": now_ms - 2 * 86_400_000},
    }
    removed = prune_group_incidents(incidents, -1001, retention_days=30, now_ms=now_ms, handled_only=True)
    assert removed == 1
    assert "old-handled" not in incidents
    assert "old-open" in incidents
    assert "recent" in incidents
