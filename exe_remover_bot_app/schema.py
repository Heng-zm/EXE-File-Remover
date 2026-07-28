from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable

from .config import WORKFLOW_HISTORY_MAX_ITEMS
from .policies import detect_scanner_preset, normalize_policy_settings

CURRENT_SCHEMA_VERSION = 7
LOCAL_STATE_META_KEY = "_persistence_meta"

PERSISTED_BOT_DATA_KEYS = (
    "user_state",
    "group_state",
    "known_users",
    "incidents",
    "incident_tokens",
    "warning_counts",
    "settings",
    "whitelisted_hashes",
    "user_feedback",
    "admin_action_logs",
    "workflow_history",
    "chat_meta_cache",
    "admin_ids_cache",
    "bot_member_cache",
    "inaccessible_chats",
)

PERSISTED_BOT_DATA_TYPES: dict[str, type] = {
    "user_feedback": list,
    "admin_action_logs": list,
    "workflow_history": list,
}


class SchemaMigrationError(ValueError):
    """Raised when a persistence snapshot cannot be migrated safely."""


@dataclass(frozen=True, slots=True)
class MigrationResult:
    payload: dict[str, Any]
    from_version: int
    to_version: int
    applied: tuple[str, ...]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def payload_schema_version(payload: dict[str, Any]) -> int:
    meta = payload.get("_meta")
    return max(0, _safe_int(meta.get("schema"), 0)) if isinstance(meta, dict) else 0


def payload_saved_at_ms(payload: dict[str, Any]) -> int:
    meta = payload.get("_meta")
    return max(0, _safe_int(meta.get("saved_at_ms"), 0)) if isinstance(meta, dict) else 0


def payload_revision(payload: dict[str, Any]) -> int:
    meta = payload.get("_meta")
    if not isinstance(meta, dict):
        return 0
    revision = max(0, _safe_int(meta.get("revision"), 0))
    return revision or payload_saved_at_ms(payload)


def next_revision(previous: int, saved_at_ms: int) -> int:
    """Return a revision that remains monotonic across restarts and processes."""
    return max(1, int(previous) + 1, int(saved_at_ms))


def build_snapshot_meta(*, saved_at_ms: int, previous_revision: int, bot: str) -> dict[str, Any]:
    return {
        "saved_at_ms": max(0, int(saved_at_ms)),
        "revision": next_revision(previous_revision, saved_at_ms),
        "schema": CURRENT_SCHEMA_VERSION,
        "bot": str(bot),
    }


def _ensure_durable_types(payload: dict[str, Any]) -> None:
    for key in PERSISTED_BOT_DATA_KEYS:
        expected = PERSISTED_BOT_DATA_TYPES.get(key, dict)
        value = payload.get(key)
        if not isinstance(value, expected):
            payload[key] = [] if expected is list else {}


def _migration_0_to_1(payload: dict[str, Any]) -> None:
    _ensure_durable_types(payload)


def _migration_1_to_2(payload: dict[str, Any]) -> None:
    # Older snapshots sometimes stored numeric group/user keys inconsistently.
    for bucket_name in ("user_state", "known_users"):
        bucket = payload.get(bucket_name)
        if isinstance(bucket, dict):
            normalized: dict[Any, Any] = {}
            for key, value in bucket.items():
                try:
                    normalized[int(key)] = value
                except (TypeError, ValueError):
                    continue
            payload[bucket_name] = normalized

    group_state = payload.get("group_state")
    if isinstance(group_state, dict):
        normalized_groups: dict[str, Any] = {}
        for key, value in group_state.items():
            try:
                normalized_groups[str(int(key))] = value
            except (TypeError, ValueError):
                continue
        payload["group_state"] = normalized_groups


def _migration_2_to_3(payload: dict[str, Any]) -> None:
    if not isinstance(payload.get("user_feedback"), list):
        payload["user_feedback"] = []
    if not isinstance(payload.get("admin_action_logs"), list):
        payload["admin_action_logs"] = []


def _migration_3_to_4(payload: dict[str, Any]) -> None:
    for key in ("chat_meta_cache", "admin_ids_cache", "bot_member_cache", "inaccessible_chats"):
        if not isinstance(payload.get(key), dict):
            payload[key] = {}


def _migration_4_to_5(payload: dict[str, Any]) -> None:
    _ensure_durable_types(payload)
    meta = payload.setdefault("_meta", {})
    if not isinstance(meta, dict):
        meta = {}
        payload["_meta"] = meta
    saved_at = max(0, _safe_int(meta.get("saved_at_ms"), 0))
    meta["revision"] = max(1, _safe_int(meta.get("revision"), 0), saved_at)


def _migration_5_to_6(payload: dict[str, Any]) -> None:
    group_state = payload.get("group_state")
    if not isinstance(group_state, dict):
        return
    for state in group_state.values():
        if not isinstance(state, dict):
            continue
        settings = state.get("settings")
        if not isinstance(settings, dict):
            settings = {}
            state["settings"] = settings
        normalize_policy_settings(settings)
        settings["scanner_preset"] = detect_scanner_preset(settings)


def _migration_6_to_7(payload: dict[str, Any]) -> None:
    if not isinstance(payload.get("workflow_history"), list):
        payload["workflow_history"] = []
    # Keep workflow history bounded and serializable. Older development builds
    # may have stored malformed rows while the workflow feature was prototyped.
    cleaned: list[dict[str, Any]] = []
    for item in payload["workflow_history"][-WORKFLOW_HISTORY_MAX_ITEMS:]:
        if isinstance(item, dict) and item.get("id"):
            cleaned.append(item)
    payload["workflow_history"] = cleaned


_MIGRATIONS: dict[int, tuple[str, Callable[[dict[str, Any]], None]]] = {
    0: ("initialize durable stores", _migration_0_to_1),
    1: ("normalize user and group identifiers", _migration_1_to_2),
    2: ("add feedback and admin-log stores", _migration_2_to_3),
    3: ("add persisted dashboard caches", _migration_3_to_4),
    4: ("add monotonic snapshot revisions", _migration_4_to_5),
    5: ("add group scanner presets and policy controls", _migration_5_to_6),
    6: ("add coordinated workflow history", _migration_6_to_7),
}


def migrate_state_payload(payload: dict[str, Any]) -> MigrationResult:
    if not isinstance(payload, dict):
        raise SchemaMigrationError("persistence payload must be a dictionary")

    migrated = copy.deepcopy(payload)
    from_version = payload_schema_version(migrated)
    if from_version > CURRENT_SCHEMA_VERSION:
        raise SchemaMigrationError(
            f"snapshot schema {from_version} is newer than supported schema {CURRENT_SCHEMA_VERSION}"
        )

    version = from_version
    applied: list[str] = []
    while version < CURRENT_SCHEMA_VERSION:
        migration = _MIGRATIONS.get(version)
        if migration is None:
            raise SchemaMigrationError(f"missing migration from schema {version}")
        label, handler = migration
        handler(migrated)
        version += 1
        meta = migrated.setdefault("_meta", {})
        if not isinstance(meta, dict):
            meta = {}
            migrated["_meta"] = meta
        meta["schema"] = version
        applied.append(f"v{version - 1}->v{version}: {label}")

    _ensure_durable_types(migrated)
    meta = migrated.setdefault("_meta", {})
    if not isinstance(meta, dict):
        meta = {}
        migrated["_meta"] = meta
    meta["schema"] = CURRENT_SCHEMA_VERSION
    saved_at = max(0, _safe_int(meta.get("saved_at_ms"), 0))
    meta["saved_at_ms"] = saved_at
    meta["revision"] = max(1, _safe_int(meta.get("revision"), 0), saved_at)
    meta.setdefault("bot", "exe_remover_bot")

    return MigrationResult(migrated, from_version, CURRENT_SCHEMA_VERSION, tuple(applied))


def is_newer_snapshot(
    *, incoming_revision: int, incoming_saved_at_ms: int,
    current_revision: int, current_saved_at_ms: int,
) -> bool:
    if current_revision <= 0 and current_saved_at_ms <= 0:
        return True
    incoming_key = (max(0, incoming_revision), max(0, incoming_saved_at_ms))
    current_key = (max(0, current_revision), max(0, current_saved_at_ms))
    return incoming_key > current_key
