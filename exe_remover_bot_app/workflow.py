from __future__ import annotations

import copy
import secrets
from dataclasses import dataclass
from typing import Any

from .config import WORKFLOW_EVENT_MAX_ITEMS, WORKFLOW_HISTORY_MAX_ITEMS, WORKFLOW_STALE_SECONDS
from .policies import detect_scanner_preset, normalize_policy_settings

WORKFLOW_STORE_KEY = "workflow_history"
WORKFLOW_VERSION = 1
WORKFLOW_HISTORY_LIMIT = WORKFLOW_HISTORY_MAX_ITEMS
WORKFLOW_EVENT_LIMIT = WORKFLOW_EVENT_MAX_ITEMS
WORKFLOW_STATUSES = ("running", "completed", "failed", "interrupted")
WORKFLOW_KINDS = ("file_moderation", "incident_action", "policy_update", "group_sync")

WORKFLOW_STAGES: dict[str, tuple[str, ...]] = {
    "file_moderation": (
        "received",
        "policy_evaluated",
        "scanned",
        "deleted",
        "incident_recorded",
        "auto_action",
        "notifications",
        "completed",
    ),
    "incident_action": (
        "received",
        "authorized",
        "executed",
        "alerts_synchronized",
        "completed",
    ),
    "policy_update": (
        "received",
        "validated",
        "applied",
        "persisted",
        "completed",
    ),
    "group_sync": (
        "received",
        "permissions_refreshed",
        "state_reconciled",
        "persisted",
        "completed",
    ),
}


@dataclass(frozen=True, slots=True)
class WorkflowPage:
    items: tuple[dict[str, Any], ...]
    total: int
    counts: dict[str, int]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _json_safe(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return str(value)[:240]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(key)[:80]: _json_safe(item, depth=depth + 1) for key, item in list(value.items())[:50]}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item, depth=depth + 1) for item in list(value)[:50]]
    return str(value)[:240]


def _history(bot_data: dict[str, Any]) -> list[dict[str, Any]]:
    value = bot_data.get(WORKFLOW_STORE_KEY)
    if not isinstance(value, list):
        value = []
        bot_data[WORKFLOW_STORE_KEY] = value
    return value


def _find_workflow(bot_data: dict[str, Any], workflow_id: str) -> dict[str, Any] | None:
    target = str(workflow_id or "")
    for item in reversed(_history(bot_data)):
        if isinstance(item, dict) and str(item.get("id") or "") == target:
            return item
    return None


def _progress(kind: str, stage: str, status: str) -> int:
    if status == "completed":
        return 100
    stages = WORKFLOW_STAGES.get(kind, ("received", "completed"))
    try:
        index = stages.index(stage)
    except ValueError:
        index = 0
    denominator = max(1, len(stages) - 1)
    return max(0, min(99, round(index * 100 / denominator)))


def _event(stage: str, *, status: str, at_ms: int, detail: str = "", data: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "stage": str(stage or "received"),
        "status": str(status or "running"),
        "at_ms": max(0, int(at_ms)),
        "detail": str(detail or "")[:500],
        "data": _json_safe(data or {}),
    }


def begin_workflow(
    bot_data: dict[str, Any],
    *,
    kind: str,
    chat_id: int = 0,
    actor_id: int = 0,
    source: str = "telegram",
    subject_id: str | int = "",
    metadata: dict[str, Any] | None = None,
    at_ms: int,
) -> dict[str, Any]:
    normalized_kind = str(kind or "").strip().casefold()
    if normalized_kind not in WORKFLOW_KINDS:
        normalized_kind = "file_moderation"
    workflow_id = f"wf_{int(at_ms):x}_{secrets.token_hex(5)}"
    record: dict[str, Any] = {
        "version": WORKFLOW_VERSION,
        "id": workflow_id,
        "kind": normalized_kind,
        "source": str(source or "telegram")[:40],
        "status": "running",
        "stage": "received",
        "progress": 0,
        "chat_id": int(chat_id or 0),
        "actor_id": int(actor_id or 0),
        "subject_id": str(subject_id or "")[:120],
        "started_at_ms": max(0, int(at_ms)),
        "updated_at_ms": max(0, int(at_ms)),
        "completed_at_ms": 0,
        "outcome": "",
        "detail": "",
        "metadata": _json_safe(metadata or {}),
        "events": [_event("received", status="running", at_ms=at_ms, detail="workflow started")],
    }
    history = _history(bot_data)
    history.append(record)
    if len(history) > WORKFLOW_HISTORY_LIMIT:
        del history[: len(history) - WORKFLOW_HISTORY_LIMIT]
    return record


def advance_workflow(
    bot_data: dict[str, Any],
    workflow_id: str,
    *,
    stage: str,
    at_ms: int,
    detail: str = "",
    data: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    record = _find_workflow(bot_data, workflow_id)
    if record is None or str(record.get("status")) != "running":
        return record
    stage_clean = str(stage or "received")
    record["stage"] = stage_clean
    record["updated_at_ms"] = max(0, int(at_ms))
    record["progress"] = _progress(str(record.get("kind") or ""), stage_clean, "running")
    if detail:
        record["detail"] = str(detail)[:500]
    events = record.setdefault("events", [])
    if not isinstance(events, list):
        events = []
        record["events"] = events
    events.append(_event(stage_clean, status="running", at_ms=at_ms, detail=detail, data=data))
    if len(events) > WORKFLOW_EVENT_LIMIT:
        del events[: len(events) - WORKFLOW_EVENT_LIMIT]
    return record


def complete_workflow(
    bot_data: dict[str, Any],
    workflow_id: str,
    *,
    at_ms: int,
    outcome: str,
    detail: str = "",
    data: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    record = _find_workflow(bot_data, workflow_id)
    if record is None:
        return None
    record["status"] = "completed"
    record["stage"] = "completed"
    record["progress"] = 100
    record["updated_at_ms"] = max(0, int(at_ms))
    record["completed_at_ms"] = max(0, int(at_ms))
    record["outcome"] = str(outcome or "completed")[:120]
    record["detail"] = str(detail or "")[:500]
    events = record.setdefault("events", [])
    if not isinstance(events, list):
        events = []
        record["events"] = events
    events.append(_event("completed", status="completed", at_ms=at_ms, detail=detail, data={"outcome": outcome, **(data or {})}))
    if len(events) > WORKFLOW_EVENT_LIMIT:
        del events[: len(events) - WORKFLOW_EVENT_LIMIT]
    return record


def fail_workflow(
    bot_data: dict[str, Any],
    workflow_id: str,
    *,
    at_ms: int,
    error: str,
    stage: str = "failed",
    data: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    record = _find_workflow(bot_data, workflow_id)
    if record is None:
        return None
    record["status"] = "failed"
    record["stage"] = str(stage or "failed")
    record["updated_at_ms"] = max(0, int(at_ms))
    record["completed_at_ms"] = max(0, int(at_ms))
    record["outcome"] = "failed"
    record["detail"] = str(error or "workflow failed")[:500]
    events = record.setdefault("events", [])
    if not isinstance(events, list):
        events = []
        record["events"] = events
    events.append(_event(record["stage"], status="failed", at_ms=at_ms, detail=error, data=data))
    if len(events) > WORKFLOW_EVENT_LIMIT:
        del events[: len(events) - WORKFLOW_EVENT_LIMIT]
    return record


def workflow_public_view(record: dict[str, Any], *, include_events: bool = False) -> dict[str, Any]:
    result = {
        "id": str(record.get("id") or ""),
        "kind": str(record.get("kind") or ""),
        "source": str(record.get("source") or ""),
        "status": str(record.get("status") or "running"),
        "stage": str(record.get("stage") or "received"),
        "progress": max(0, min(100, _safe_int(record.get("progress"), 0))),
        "chat_id": _safe_int(record.get("chat_id"), 0),
        "actor_id": _safe_int(record.get("actor_id"), 0),
        "subject_id": str(record.get("subject_id") or ""),
        "started_at_ms": _safe_int(record.get("started_at_ms"), 0),
        "updated_at_ms": _safe_int(record.get("updated_at_ms"), 0),
        "completed_at_ms": _safe_int(record.get("completed_at_ms"), 0),
        "outcome": str(record.get("outcome") or ""),
        "detail": str(record.get("detail") or ""),
        "metadata": copy.deepcopy(record.get("metadata") if isinstance(record.get("metadata"), dict) else {}),
    }
    if include_events:
        result["events"] = copy.deepcopy(record.get("events") if isinstance(record.get("events"), list) else [])
    return result


def list_workflows(
    bot_data: dict[str, Any],
    *,
    chat_id: int | None = None,
    kind: str = "all",
    status: str = "all",
    limit: int = 50,
    include_events: bool = False,
) -> WorkflowPage:
    kind_filter = str(kind or "all").strip().casefold()
    status_filter = str(status or "all").strip().casefold()
    items: list[dict[str, Any]] = []
    counts = {"running": 0, "completed": 0, "failed": 0, "interrupted": 0}
    for record in reversed(_history(bot_data)):
        if not isinstance(record, dict):
            continue
        if chat_id is not None and _safe_int(record.get("chat_id"), 0) != int(chat_id):
            continue
        record_status = str(record.get("status") or "running").casefold()
        record_kind = str(record.get("kind") or "").casefold()
        if record_status in counts:
            counts[record_status] += 1
        if kind_filter not in {"", "all", "*"} and record_kind != kind_filter:
            continue
        if status_filter not in {"", "all", "*"} and record_status != status_filter:
            continue
        items.append(workflow_public_view(record, include_events=include_events))
    total = len(items)
    return WorkflowPage(tuple(items[: max(1, min(int(limit), 200))]), total, counts)


def recover_interrupted_workflows(bot_data: dict[str, Any], *, at_ms: int, max_running_age_ms: int = WORKFLOW_STALE_SECONDS * 1000) -> int:
    recovered = 0
    cutoff = max(0, int(at_ms) - max(60_000, int(max_running_age_ms)))
    for record in _history(bot_data):
        if not isinstance(record, dict) or str(record.get("status")) != "running":
            continue
        updated = _safe_int(record.get("updated_at_ms"), _safe_int(record.get("started_at_ms"), 0))
        if updated and updated > cutoff:
            continue
        record["status"] = "interrupted"
        record["stage"] = "interrupted"
        record["outcome"] = "process_restarted"
        record["detail"] = "workflow was interrupted before completion"
        record["updated_at_ms"] = int(at_ms)
        record["completed_at_ms"] = int(at_ms)
        events = record.setdefault("events", [])
        if isinstance(events, list):
            events.append(_event("interrupted", status="interrupted", at_ms=at_ms, detail="recovered during startup"))
            if len(events) > WORKFLOW_EVENT_LIMIT:
                del events[: len(events) - WORKFLOW_EVENT_LIMIT]
        recovered += 1
    return recovered


def moderation_notification_targets(settings: dict[str, Any]) -> tuple[bool, bool]:
    policy = str(settings.get("notification_policy") or "group_and_admins").casefold()
    return policy in {"group_and_admins", "group_only"}, policy in {"group_and_admins", "admins_only"}


def select_auto_action(settings: dict[str, Any], *, incident_count: int) -> str:
    mode = str(settings.get("auto_action_mode") or "off").strip().casefold()
    if mode == "off":
        return "none"
    if mode == "ban":
        return "ban"
    if mode == "warn":
        return "warn"
    mute_threshold = max(1, _safe_int(settings.get("auto_mute_threshold"), 2))
    ban_threshold = max(mute_threshold, _safe_int(settings.get("auto_ban_threshold"), 3))
    if incident_count >= ban_threshold:
        return "ban"
    if incident_count >= mute_threshold:
        return "mute"
    return "warn"


def reconcile_group_state(bot_data: dict[str, Any], chat_id: int, *, at_ms: int) -> dict[str, Any]:
    """Normalize group state, prune expired incidents, and repair orphan tokens.

    Caller must hold the application's bot-data lock.
    """
    group_state = bot_data.setdefault("group_state", {})
    if not isinstance(group_state, dict):
        group_state = {}
        bot_data["group_state"] = group_state
    state = group_state.setdefault(str(int(chat_id)), {})
    if not isinstance(state, dict):
        state = {}
        group_state[str(int(chat_id))] = state
    settings = state.setdefault("settings", {})
    if not isinstance(settings, dict):
        settings = {}
        state["settings"] = settings
    normalize_policy_settings(settings)
    settings["scanner_preset"] = detect_scanner_preset(settings)

    incidents = bot_data.setdefault("incidents", {})
    if not isinstance(incidents, dict):
        incidents = {}
        bot_data["incidents"] = incidents
    retention_days = max(1, _safe_int(settings.get("incident_retention_days"), 30))
    cutoff = int(at_ms) - retention_days * 86_400_000
    removed_incidents: list[str] = []
    repaired_incidents = 0
    for key, incident in list(incidents.items()):
        if not isinstance(incident, dict):
            incidents.pop(key, None)
            removed_incidents.append(str(key))
            continue
        if _safe_int(incident.get("chat_id"), 0) != int(chat_id):
            continue
        incident.setdefault("done", False)
        incident.setdefault("alert_messages", {})
        created = _safe_int(incident.get("created_at_ms"), 0)
        if created and created < cutoff:
            incidents.pop(key, None)
            removed_incidents.append(str(key))
        else:
            repaired_incidents += 1

    tokens = bot_data.setdefault("incident_tokens", {})
    removed_tokens = 0
    if isinstance(tokens, dict):
        valid_keys = set(incidents.keys())
        for token, incident_key in list(tokens.items()):
            if str(incident_key) not in valid_keys:
                tokens.pop(token, None)
                removed_tokens += 1

    workflows = list_workflows(bot_data, chat_id=int(chat_id), limit=WORKFLOW_HISTORY_LIMIT)
    report = {
        "chat_id": int(chat_id),
        "settings_normalized": True,
        "detected_preset": str(settings.get("scanner_preset") or "custom"),
        "retention_days": retention_days,
        "incidents_active": repaired_incidents,
        "incidents_removed": len(removed_incidents),
        "tokens_removed": removed_tokens,
        "workflow_counts": dict(workflows.counts),
        "synced_at_ms": int(at_ms),
    }
    state["last_sync_ms"] = int(at_ms)
    state["last_sync_report"] = copy.deepcopy(report)
    return report
