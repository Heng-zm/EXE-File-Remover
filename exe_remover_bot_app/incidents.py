from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from typing import Any, Iterable

INCIDENT_STATUSES = ("all", "open", "handled")
INCIDENT_SEVERITIES = ("all", "low", "medium", "high", "critical")
INCIDENT_SORTS = ("newest", "oldest")


@dataclass(frozen=True, slots=True)
class IncidentPage:
    items: tuple[tuple[str, dict[str, Any]], ...]
    total: int
    page: int
    page_size: int
    pages: int
    has_next: bool
    has_previous: bool
    counts: dict[str, int]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def incident_created_at_ms(key: str, incident: dict[str, Any]) -> int:
    created = _safe_int(incident.get("created_at_ms"), 0)
    if created > 0:
        return created
    try:
        suffix = str(key).rsplit(":", 1)[-1]
        return max(0, int(suffix))
    except (TypeError, ValueError):
        return 0


def incident_status(incident: dict[str, Any]) -> str:
    return "handled" if bool(incident.get("done", False)) else "open"


def incident_action(incident: dict[str, Any]) -> str:
    return str(incident.get("action") or incident.get("auto_action") or "none").strip().casefold() or "none"


def incident_severity(incident: dict[str, Any]) -> str:
    explicit = str(incident.get("severity") or "").strip().casefold()
    if explicit in INCIDENT_SEVERITIES[1:]:
        return explicit

    action = incident_action(incident)
    reason = str(incident.get("reason") or incident.get("reason_code") or "").strip().casefold()
    matched = str(incident.get("matched_extension") or "").strip().casefold()

    if action == "ban" or matched in {".exe", ".scr", ".com", ".pif", ".msi"}:
        return "critical"
    if action == "mute" or reason in {
        "pe_magic_header", "archive_dangerous_member", "archive_scan_limit_exceeded",
        "unscannable_generic_file", "blocked_mime_type",
    }:
        return "high"
    if reason in {
        "custom_group_extension", "group_allowlist_only", "group_max_file_size",
        "group_archive_blocked", "dangerous_extension", "double_extension",
    }:
        return "medium"
    return "low"


def _normalized_choice(value: str, allowed: Iterable[str], default: str) -> str:
    normalized = str(value or default).strip().casefold()
    return normalized if normalized in set(allowed) else default


def paginate_incidents(
    incidents: dict[str, Any],
    chat_id: int,
    *,
    status: str = "all",
    severity: str = "all",
    action: str = "all",
    query: str = "",
    sender_id: int | None = None,
    date_from_ms: int = 0,
    date_to_ms: int = 0,
    page: int = 1,
    page_size: int = 25,
    sort: str = "newest",
) -> IncidentPage:
    status = _normalized_choice(status, INCIDENT_STATUSES, "all")
    severity = _normalized_choice(severity, INCIDENT_SEVERITIES, "all")
    sort = _normalized_choice(sort, INCIDENT_SORTS, "newest")
    action = str(action or "all").strip().casefold() or "all"
    search = str(query or "").strip().casefold()
    sender_filter = int(sender_id) if sender_id is not None else None
    start_ms = max(0, _safe_int(date_from_ms, 0))
    end_ms = max(0, _safe_int(date_to_ms, 0))
    requested_page = max(1, _safe_int(page, 1))
    requested_size = max(1, min(100, _safe_int(page_size, 25)))

    rows: list[tuple[str, dict[str, Any]]] = []
    counts = {"all": 0, "open": 0, "handled": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

    for key, raw in incidents.items():
        if not isinstance(raw, dict) or _safe_int(raw.get("chat_id"), 0) != int(chat_id):
            continue
        row_status = incident_status(raw)
        row_severity = incident_severity(raw)
        counts["all"] += 1
        counts[row_status] += 1
        counts[row_severity] += 1

        if status != "all" and row_status != status:
            continue
        if severity != "all" and row_severity != severity:
            continue
        row_action = incident_action(raw)
        if action != "all" and row_action != action:
            continue
        if sender_filter is not None and _safe_int(raw.get("sender_id"), 0) != sender_filter:
            continue
        created_ms = incident_created_at_ms(str(key), raw)
        if start_ms and created_ms < start_ms:
            continue
        if end_ms and created_ms > end_ms:
            continue
        if search:
            haystack = " ".join(
                str(raw.get(field) or "")
                for field in ("sender_name", "sender_id", "file_name", "reason", "scan_reason", "matched_extension", "action", "auto_action")
            ).casefold()
            if search not in haystack:
                continue
        rows.append((str(key), raw))

    reverse = sort == "newest"
    rows.sort(key=lambda item: incident_created_at_ms(item[0], item[1]), reverse=reverse)
    total = len(rows)
    pages = max(1, ceil(total / requested_size)) if total else 1
    actual_page = min(requested_page, pages)
    start = (actual_page - 1) * requested_size
    selected = tuple(rows[start:start + requested_size])
    return IncidentPage(
        items=selected,
        total=total,
        page=actual_page,
        page_size=requested_size,
        pages=pages,
        has_next=actual_page < pages,
        has_previous=actual_page > 1,
        counts=counts,
    )


def prune_group_incidents(
    incidents: dict[str, Any],
    chat_id: int,
    *,
    retention_days: int,
    now_ms: int,
    handled_only: bool = True,
) -> int:
    cutoff = max(0, int(now_ms) - max(1, int(retention_days)) * 86_400_000)
    to_remove: list[str] = []
    for key, raw in incidents.items():
        if not isinstance(raw, dict) or _safe_int(raw.get("chat_id"), 0) != int(chat_id):
            continue
        if handled_only and not bool(raw.get("done", False)):
            continue
        if incident_created_at_ms(str(key), raw) < cutoff:
            to_remove.append(str(key))
    for key in to_remove:
        incidents.pop(key, None)
    return len(to_remove)
