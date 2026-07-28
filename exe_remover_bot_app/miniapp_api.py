from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

try:
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles
except ImportError:  # FastAPI remains optional for polling-only deployments.
    FileResponse = None  # type: ignore[assignment]
    StaticFiles = None  # type: ignore[assignment]

from .incidents import incident_action, incident_severity, incident_status, paginate_incidents
from .workflow import (
    advance_workflow,
    begin_workflow,
    complete_workflow,
    fail_workflow,
    list_workflows,
    reconcile_group_state,
    workflow_public_view,
)

# v3.5 compatibility bridge: the API layer is physically isolated while it
# uses the mature Telegram runtime services through one explicit module handle.
# Mutable scalar status values are referenced as runtime.<name> below.
from . import bot as runtime

globals().update({
    name: value for name, value in vars(runtime).items()
    if not name.startswith("__")
})

@dataclass(slots=True)
class MiniAppPrincipal:
    """Authenticated Telegram Mini App user resolved from WebApp initData."""

    user_id: int
    user: dict[str, Any]
    auth_date: int
    query_id: str = ""
    init_data: str = ""


def _api_raise(status_code: int, detail: str) -> None:
    if HTTPException is None:
        raise RuntimeError(detail)
    raise HTTPException(status_code=status_code, detail=detail)


def _valid_webhook_secret_token(value: str) -> bool:
    """Telegram secret_token allows 1..256 chars from A-Z, a-z, 0-9, _, -."""
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,256}", str(value or "")))


def _telegram_secret_token_for_webhook() -> str | None:
    if not MINI_APP_WEBHOOK_SECRET_HEADER_ENABLED:
        return None
    return WEBHOOK_SECRET_TOKEN if _valid_webhook_secret_token(WEBHOOK_SECRET_TOKEN) else None


MINI_APP_INIT_DATA_KEYS = ("initData", "init_data", "tgWebAppData", "telegram_init_data", "webAppData")
MINI_APP_INIT_DATA_HEADERS = (
    "X-Telegram-Init-Data",
    "X-Telegram-Web-App-Data",
    "X-TMA-Init-Data",
    "Telegram-Init-Data",
)


def _extract_init_data_from_mapping(mapping: Any) -> str:
    """Read initData from a dict/query/form-like object without trusting initDataUnsafe."""
    if not mapping:
        return ""
    getter = getattr(mapping, "get", None)
    if not callable(getter):
        return ""
    for key in MINI_APP_INIT_DATA_KEYS:
        try:
            value = str(getter(key) or "").strip()
        except Exception:
            value = ""
        if value:
            return value
    return ""


def _extract_init_data_from_headers_and_query(request: Any) -> str:
    """Read Telegram WebApp initData from headers, Authorization, or query string."""
    headers = getattr(request, "headers", {}) or {}
    for header_name in MINI_APP_INIT_DATA_HEADERS:
        value = str(headers.get(header_name) or "").strip()
        if value:
            return value

    auth = str(headers.get("Authorization") or "").strip()
    for prefix in ("tma ", "telegram ", "bearer "):
        if auth.casefold().startswith(prefix):
            return auth[len(prefix):].strip()

    return _extract_init_data_from_mapping(getattr(request, "query_params", {}) or {})


async def _api_request_body_bytes(request: Any) -> bytes:
    """Read request body once and reuse it across auth + payload parsing."""
    state = getattr(request, "state", None)
    if state is not None:
        cached = getattr(state, "_mini_app_cached_body", None)
        if isinstance(cached, (bytes, bytearray)):
            return bytes(cached)
    try:
        body = await request.body()
    except Exception:
        _api_raise(400, "could not read request body")
    if len(body) > MINI_APP_REQUEST_BODY_LIMIT_BYTES:
        _api_raise(413, "request body too large")
    if state is not None:
        try:
            setattr(state, "_mini_app_cached_body", bytes(body))
        except Exception:
            pass
    return bytes(body)


async def _extract_init_data_from_request(request: Any) -> str:
    """Read Telegram WebApp initData from all frontend-friendly request locations.

    Preferred frontend usage is the `X-Telegram-Init-Data` header or
    `Authorization: tma <initData>`.  For easier React/Vite integration, JSON
    bodies like `{"initData": window.Telegram.WebApp.initData}` and raw
    x-www-form-urlencoded bodies are also accepted.
    """
    direct = _extract_init_data_from_headers_and_query(request)
    if direct:
        return direct

    method = str(getattr(request, "method", "") or "").upper()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return ""

    body = await _api_request_body_bytes(request)
    if not body:
        return ""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    stripped = text.strip()
    if not stripped:
        return ""

    headers = getattr(request, "headers", {}) or {}
    content_type = str(headers.get("content-type") or headers.get("Content-Type") or "").casefold()
    if "application/json" in content_type or stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            value = _extract_init_data_from_mapping(payload)
            if value:
                return value

    if "application/x-www-form-urlencoded" in content_type or ("auth_date=" in stripped and "hash=" in stripped):
        parsed = dict(parse_qsl(stripped, keep_blank_values=True, strict_parsing=False))
        value = _extract_init_data_from_mapping(parsed)
        if value:
            return value
        if "auth_date=" in stripped and "hash=" in stripped:
            return stripped

    return ""


def validate_telegram_webapp_init_data(init_data: str) -> MiniAppPrincipal:
    """Validate Telegram Mini App initData using the bot token HMAC scheme."""
    raw = str(init_data or "").strip()
    if not raw:
        _api_raise(401, "missing Telegram Mini App initData")

    parsed_pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=False)
    parsed: dict[str, str] = {str(key): str(value) for key, value in parsed_pairs}
    received_hash = parsed.pop("hash", "")
    if not received_hash:
        _api_raise(401, "missing Telegram initData hash")

    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(parsed.items()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode("utf-8"), hashlib.sha256).digest()
    calculated_hash = hmac.new(secret_key, data_check_string.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated_hash, received_hash):
        _api_raise(401, "invalid Telegram initData signature")

    try:
        auth_date = int(parsed.get("auth_date", "0") or 0)
    except (TypeError, ValueError):
        auth_date = 0
    if auth_date <= 0:
        _api_raise(401, "invalid Telegram initData auth_date")
    if MINI_APP_AUTH_MAX_AGE_SECONDS > 0 and int(time.time()) - auth_date > MINI_APP_AUTH_MAX_AGE_SECONDS:
        _api_raise(401, "expired Telegram initData")

    try:
        user_payload = json.loads(parsed.get("user", "{}") or "{}")
    except json.JSONDecodeError:
        user_payload = {}
    if not isinstance(user_payload, dict):
        user_payload = {}
    try:
        user_id = int(user_payload.get("id") or 0)
    except (TypeError, ValueError):
        user_id = 0
    if user_id <= 0:
        _api_raise(401, "Telegram initData does not contain a valid user")

    return MiniAppPrincipal(
        user_id=user_id,
        user=user_payload,
        auth_date=auth_date,
        query_id=str(parsed.get("query_id") or ""),
        init_data=raw,
    )


async def _api_principal_from_request(request: Any) -> MiniAppPrincipal:
    return validate_telegram_webapp_init_data(await _extract_init_data_from_request(request))


def _api_full_name(user: dict[str, Any]) -> str:
    first = str(user.get("first_name") or "").strip()
    last = str(user.get("last_name") or "").strip()
    full = " ".join(part for part in (first, last) if part).strip()
    return full or str(user.get("username") or user.get("id") or "Unknown")


def _api_public_profile_from_principal(principal: MiniAppPrincipal) -> dict[str, Any]:
    user = principal.user
    return {
        "id": principal.user_id,
        "is_bot": bool(user.get("is_bot", False)),
        "first_name": str(user.get("first_name") or ""),
        "last_name": str(user.get("last_name") or ""),
        "full_name": _api_full_name(user),
        "username": str(user.get("username") or ""),
        "language_code": str(user.get("language_code") or ""),
        "is_premium": bool(user.get("is_premium", False)),
        "allows_write_to_pm": bool(user.get("allows_write_to_pm", False)),
        "photo_url": str(user.get("photo_url") or ""),
    }


async def _api_remember_principal(application: Application, principal: MiniAppPrincipal, *, persist: bool) -> None:
    """Store/update the Mini App user profile in the same durable user cache."""
    profile = _api_public_profile_from_principal(principal)
    async with BOT_DATA_LOCK:
        state = get_user_state(application.bot_data, principal.user_id)
        state["last_seen_ms"] = now_ms()
        state.setdefault("first_seen_ms", state["last_seen_ms"])
        if not state.get("lang"):
            state["lang"] = "km" if str(profile.get("language_code", "")).startswith("km") else "en"

        known_users = application.bot_data.setdefault("known_users", {})
        if not isinstance(known_users, dict):
            known_users = {}
            application.bot_data["known_users"] = known_users
        saved = known_users.setdefault(str(principal.user_id), {})
        saved.setdefault("first_seen_ms", state.get("first_seen_ms", now_ms()))
        saved.update(
            {
                "id": principal.user_id,
                "is_bot": bool(profile["is_bot"]),
                "username": str(profile["username"]),
                "full_name": str(profile["full_name"]),
                "language_code": str(profile["language_code"]),
                "lang": state.get("lang", "en"),
                "is_premium": bool(profile["is_premium"]),
                "allows_write_to_pm": bool(profile["allows_write_to_pm"]),
                "photo_url": str(profile["photo_url"]),
                "last_seen_ms": now_ms(),
                "source": "mini_app",
            }
        )
        if persist:
            await persist_context_memory(application, reason="mini_app_user_session", force=False, caller_holds_lock=True)


def _api_json_safe(value: Any, *, depth: int = 0) -> Any:
    """Convert bot state values to JSON-safe structures without leaking objects."""
    if depth > 8:
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _api_json_safe(v, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_api_json_safe(item, depth=depth + 1) for item in value]
    return str(value)


def _api_ms_to_iso(value: Any) -> str:
    try:
        ms = int(value or 0)
    except (TypeError, ValueError):
        ms = 0
    if ms <= 0:
        return ""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


def _api_bool(value: Any, default: bool) -> bool:
    return _coerce_bool(value, default)


def _api_int(value: Any, default: int, *, min_value: int = 0, max_value: int = 10_000) -> int:
    return _coerce_int_range(value, default, min_value=min_value, max_value=max_value)


async def _api_request_json(request: Any) -> dict[str, Any]:
    body = await _api_request_body_bytes(request)
    if not body:
        return {}
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _api_raise(400, "invalid JSON body")
    if not isinstance(payload, dict):
        _api_raise(400, "JSON body must be an object")
    return payload


def _api_scan_result(result: FileScanResult) -> dict[str, Any]:
    return {
        "blocked": bool(result.blocked),
        "reason_code": result.reason_code,
        "reason_display": result.reason_display,
        "details": list(result.details),
        "file_name": result.file_name,
        "mime_type": result.mime_type,
        "matched_extension": result.matched_extension,
        "file_sha256": result.file_sha256,
    }


def _api_extension_values(value: Any, *, allowed: bool = False) -> list[str]:
    if isinstance(value, str):
        raw_values = re.split(r"[\s,;|]+", value.strip())
    elif isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, dict)):
        raw_values = list(value)
    else:
        raw_values = []
    if allowed:
        return _dedupe_allowed_extensions(raw_values, limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)
    return _dedupe_valid_extensions(raw_values, limit=MAX_CUSTOM_BLOCKED_EXTENSIONS)


def _api_public_settings_locked(bot_data: dict[str, Any], chat_id: int) -> dict[str, Any]:
    settings = get_group_settings(bot_data, chat_id)
    return {
        "protection_enabled": bool(settings.get("protection_enabled", True)),
        "strictness": str(settings.get("strictness", "standard")),
        "silent_mode": bool(settings.get("silent_mode", False)),
        "strict_enforcement_on_admins": bool(settings.get("strict_enforcement_on_admins", STRICT_ENFORCEMENT_ON_ADMINS_DEFAULT)),
        "allowed_extensions": list(settings.get("allowed_extensions", [])),
        "custom_blocked_extensions": list(settings.get("custom_blocked_extensions", [])),
        "trusted_file_hashes": list(settings.get("trusted_file_hashes", [])),
        "auto_action_mode": _auto_action_label(settings.get("auto_action_mode")),
        "auto_warn_threshold": _api_int(settings.get("auto_warn_threshold"), 1, min_value=1, max_value=100),
        "auto_mute_threshold": _api_int(settings.get("auto_mute_threshold"), 2, min_value=1, max_value=100),
        "auto_ban_threshold": _api_int(settings.get("auto_ban_threshold"), 3, min_value=1, max_value=100),
        "auto_mute_minutes": _api_int(settings.get("auto_mute_minutes"), 60, min_value=1, max_value=10080),
        "scanner_preset": str(settings.get("scanner_preset") or "custom"),
        "detected_preset": detect_scanner_preset(settings),
        "allowed_only": bool(settings.get("allowed_only", False)),
        "max_file_size_bytes": _api_int(settings.get("max_file_size_bytes"), TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES, min_value=65536, max_value=2_147_483_648),
        "archive_policy": str(settings.get("archive_policy") or "scan"),
        "unscannable_policy": str(settings.get("unscannable_policy") or "block"),
        "notification_policy": str(settings.get("notification_policy") or "group_and_admins"),
        "incident_retention_days": _api_int(settings.get("incident_retention_days"), 30, min_value=1, max_value=3650),
        "policy_notes": str(settings.get("policy_notes") or ""),
        "policy_updated_at_ms": _safe_int(settings.get("policy_updated_at_ms"), 0),
        "policy_updated_at": _api_ms_to_iso(settings.get("policy_updated_at_ms")),
        "policy_updated_by": _safe_int(settings.get("policy_updated_by"), 0) or None,
    }


def _api_mark_policy_updated(settings: dict[str, Any], user_id: int, *, detect_preset: bool = True) -> None:
    normalize_policy_settings(settings)
    if detect_preset:
        settings["scanner_preset"] = detect_scanner_preset(settings)
    settings["policy_updated_at_ms"] = now_ms()
    settings["policy_updated_by"] = int(user_id)


def _api_record_policy_workflow_locked(
    bot_data: dict[str, Any],
    *,
    chat_id: int,
    actor_id: int,
    operation: str,
    changed: Iterable[Any],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record one completed administration mutation in the shared workflow stream."""
    changed_items = [str(item) for item in changed]
    workflow = begin_workflow(
        bot_data,
        kind="policy_update",
        chat_id=chat_id,
        actor_id=actor_id,
        source="miniapp",
        subject_id=operation,
        metadata={"operation": operation, "changed": changed_items, **(metadata or {})},
        at_ms=now_ms(),
    )
    workflow_id = str(workflow["id"])
    advance_workflow(bot_data, workflow_id, stage="validated", at_ms=now_ms(), detail="administration request validated")
    advance_workflow(
        bot_data,
        workflow_id,
        stage="applied",
        at_ms=now_ms(),
        detail=operation,
        data={"changed": changed_items},
    )
    advance_workflow(bot_data, workflow_id, stage="persisted", at_ms=now_ms(), detail="included in durable state save")
    completed = complete_workflow(
        bot_data,
        workflow_id,
        at_ms=now_ms(),
        outcome="policy_updated",
        detail=operation,
        data={"changed": changed_items},
    )
    return workflow_public_view(completed or {}, include_events=False)


def _api_admin_ready_counts_locked(bot_data: dict[str, Any], chat_id: int) -> tuple[int, int]:
    cache = bot_data.get("admin_ids_cache", {}) if isinstance(bot_data.get("admin_ids_cache", {}), dict) else {}
    record = cache.get(str(int(chat_id))) or cache.get(int(chat_id)) or {}
    admin_ids: list[int] = []
    if isinstance(record, dict):
        value = record.get("ids") or record.get("admin_ids") or record.get("value") or []
        if isinstance(value, list):
            for item in value:
                try:
                    admin_ids.append(int(item))
                except (TypeError, ValueError):
                    continue
    ready_user_ids: set[int] = set()
    user_state = bot_data.get("user_state", {})
    if isinstance(user_state, dict):
        for uid in user_state.keys():
            try:
                ready_user_ids.add(int(uid))
            except (TypeError, ValueError):
                continue
    return sum(1 for admin_id in admin_ids if admin_id in ready_user_ids), len(admin_ids)


def _api_group_state_locked(bot_data: dict[str, Any], chat_id: int) -> dict[str, Any]:
    groups = bot_data.get("group_state", {})
    if isinstance(groups, dict):
        state = groups.get(str(int(chat_id))) or groups.get(int(chat_id))
        if isinstance(state, dict):
            return state
    return {}


def _api_group_snapshot_locked(bot_data: dict[str, Any], user_id: int, chat_id: int) -> dict[str, Any]:
    state = _api_group_state_locked(bot_data, chat_id)
    meta_cache = bot_data.get("chat_meta_cache", {}) if isinstance(bot_data.get("chat_meta_cache", {}), dict) else {}
    meta = meta_cache.get(str(int(chat_id))) or meta_cache.get(int(chat_id)) or {}
    if not isinstance(meta, dict):
        meta = {}
    perms = get_bot_member_from_state(bot_data, chat_id)
    settings = _api_public_settings_locked(bot_data, chat_id)
    admin_ready, admin_total = _api_admin_ready_counts_locked(bot_data, chat_id)
    workflow_page = list_workflows(bot_data, chat_id=int(chat_id), limit=1)
    return {
        "id": int(chat_id),
        "title": get_chat_title_from_state(bot_data, chat_id),
        "type": str(meta.get("type") or state.get("chat_type") or state.get("type") or "group"),
        "lang": get_group_lang(bot_data, chat_id),
        "added_by": _safe_int(state.get("added_by"), 0) or None,
        "last_seen_ms": _safe_int(state.get("last_seen_ms"), 0),
        "last_seen_at": _api_ms_to_iso(state.get("last_seen_ms")),
        "settings": settings,
        "protection_enabled": bool(settings.get("protection_enabled")),
        "bot_permission": {
            "status": perms.status if perms else "unknown",
            "can_delete_messages": bool(perms.can_delete_messages) if perms else False,
            "can_restrict_members": bool(perms.can_restrict_members) if perms else False,
            "settings_unlocked": bot_settings_unlocked_from_state(bot_data, chat_id),
        },
        "counts": {
            "open_incidents": _open_incident_count_for_chat(bot_data, chat_id),
            "admin_logs": _admin_log_count_for_chat(bot_data, chat_id),
            "trusted_hashes": len(settings.get("trusted_file_hashes", [])),
            "admin_alert_ready": admin_ready,
            "admin_alert_total": admin_total,
            "workflow_running": int(workflow_page.counts.get("running", 0)),
            "workflow_failed": int(workflow_page.counts.get("failed", 0)) + int(workflow_page.counts.get("interrupted", 0)),
        },
        "sync": {
            "last_sync_ms": _safe_int(state.get("last_sync_ms"), 0),
            "last_sync_at": _api_ms_to_iso(state.get("last_sync_ms")),
            "last_report": _api_json_safe(state.get("last_sync_report") if isinstance(state.get("last_sync_report"), dict) else {}),
        },
        "access": {
            "api_suppressed": is_chat_api_suppressed(bot_data, chat_id),
            "viewer_is_owner": int(user_id) in BOT_OWNER_IDS,
        },
    }


async def _api_group_snapshot(application: Application, user_id: int, chat_id: int) -> dict[str, Any]:
    async with BOT_DATA_LOCK:
        return _api_group_snapshot_locked(application.bot_data, user_id, chat_id)


async def _api_require_owner(principal: MiniAppPrincipal) -> None:
    if principal.user_id not in BOT_OWNER_IDS:
        _api_raise(403, "developer access required")


def _api_extract_server_log_api_key(request: Any) -> str:
    """Extract standalone /api/server/log key from header/query.

    Supported forms:
    - X-Server-Log-Key: <key>
    - X-API-Key: <key>
    - Authorization: Bearer <key>
    - ?server_log_key=<key> or ?key=<key> when SERVER_LOG_AUTH_QUERY_ENABLED=true
    """
    headers = getattr(request, "headers", {}) or {}
    for header_name in ("x-server-log-key", "X-Server-Log-Key", "x-api-key", "X-API-Key"):
        value = str(headers.get(header_name) or "").strip()
        if value:
            return value

    authorization = str(headers.get("authorization") or headers.get("Authorization") or "").strip()
    if authorization:
        lower = authorization.casefold()
        if lower.startswith("bearer "):
            return authorization[7:].strip()
        if lower.startswith("serverlog "):
            return authorization[10:].strip()

    if SERVER_LOG_AUTH_QUERY_ENABLED:
        query_params = getattr(request, "query_params", {}) or {}
        for key_name in ("server_log_key", "log_key", "api_key", "key"):
            value = str(query_params.get(key_name) or "").strip()
            if value:
                return value
    return ""


def _server_log_api_key_valid(value: str) -> bool:
    configured = str(SERVER_LOG_API_KEY or "").strip()
    provided = str(value or "").strip()
    if not configured or not provided:
        return False
    return hmac.compare_digest(provided, configured)


async def _api_require_server_log_access(request: Any) -> dict[str, Any]:
    """Authorize /api/server/log without requiring Telegram Mini App initData.

    Best production mode is SERVER_LOG_API_KEY. Telegram owner auth remains
    accepted for Mini App developer pages, but plain external API clients can
    use X-Server-Log-Key or Authorization: Bearer.
    """
    if SERVER_LOG_PUBLIC_ACCESS:
        return {"mode": "public", "user_id": None, "name": "public"}

    provided_key = _api_extract_server_log_api_key(request)
    if _server_log_api_key_valid(provided_key):
        return {"mode": "api_key", "user_id": None, "name": "server_log_api_key"}

    # Preserve old behavior for the Telegram Mini App developer dashboard.
    # We only attempt Telegram validation when initData is actually present,
    # so curl/Postman requests without initData receive a clear API-key error.
    if SERVER_LOG_ALLOW_TELEGRAM_OWNER_AUTH:
        init_data = await _extract_init_data_from_request(request)
        if init_data:
            principal = validate_telegram_webapp_init_data(init_data)
            await _api_require_owner(principal)
            return {"mode": "telegram_owner", "user_id": principal.user_id, "name": _api_full_name(principal.user)}

    if SERVER_LOG_API_KEY:
        _api_raise(401, "missing or invalid server log API key")
    _api_raise(503, "SERVER_LOG_API_KEY is not configured; set it in Render env to use /api/server/log without Telegram initData")


async def _api_require_group_admin(
    application: Application,
    principal: MiniAppPrincipal,
    chat_id: int,
    *,
    live: bool = True,
) -> None:
    if principal.user_id in BOT_OWNER_IDS:
        return
    if not await is_user_admin_in_group(application, int(chat_id), principal.user_id, allow_api=bool(live)):
        _api_raise(403, "group admin access required")


def _api_linked_group_ids_locked(bot_data: dict[str, Any], user_id: int) -> list[int]:
    ids = get_groups(bot_data, user_id)
    if user_id in BOT_OWNER_IDS:
        groups = bot_data.get("group_state", {})
        if isinstance(groups, dict):
            for key in groups.keys():
                try:
                    cid = int(key)
                except (TypeError, ValueError):
                    continue
                if cid not in ids:
                    ids.append(cid)
    return list(dict.fromkeys(int(item) for item in ids))


def _api_incident_locked(bot_data: dict[str, Any], ikey: str, incident: dict[str, Any]) -> dict[str, Any]:
    token = str(incident.get("action_token") or "")
    return {
        "key": str(ikey),
        "action_token": token,
        "chat_id": _safe_int(incident.get("chat_id"), 0),
        "group_name": str(incident.get("group_name") or incident.get("chat_id") or ""),
        "sender_id": _safe_int(incident.get("sender_id"), 0),
        "sender_name": str(incident.get("sender_name") or "Unknown"),
        "file_name": str(incident.get("file_name") or "Unknown"),
        "reason": str(incident.get("scan_reason") or incident.get("reason") or "blocked file"),
        "reason_code": str(incident.get("reason") or ""),
        "severity": incident_severity(incident),
        "status": incident_status(incident),
        "done": bool(incident.get("done", False)),
        "action": str(incident.get("action") or ""),
        "effective_action": incident_action(incident),
        "auto_action": str(incident.get("auto_action") or ""),
        "handled_by": _safe_int(incident.get("handled_by"), 0) or None,
        "handled_by_name": str(incident.get("handled_by_name") or ""),
        "created_at_ms": _safe_int(incident.get("created_at_ms"), incident_timestamp_ms(str(ikey)) or 0),
        "created_at": _api_ms_to_iso(incident.get("created_at_ms") or incident_timestamp_ms(str(ikey))),
        "handled_at_ms": _safe_int(incident.get("handled_at_ms"), 0),
        "handled_at": _api_ms_to_iso(incident.get("handled_at_ms")),
        "workflow_id": str(incident.get("workflow_id") or ""),
        "last_action_workflow_id": str(incident.get("last_action_workflow_id") or ""),
    }


def _api_incidents_for_chat_locked(
    bot_data: dict[str, Any],
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
) -> dict[str, Any]:
    incidents = bot_data.get("incidents", {}) if isinstance(bot_data.get("incidents", {}), dict) else {}
    result = paginate_incidents(
        incidents,
        chat_id,
        status=status,
        severity=severity,
        action=action,
        query=query,
        sender_id=sender_id,
        date_from_ms=date_from_ms,
        date_to_ms=date_to_ms,
        page=page,
        page_size=page_size,
        sort=sort,
    )
    return {
        "incidents": [_api_incident_locked(bot_data, key, incident) for key, incident in result.items],
        "total": result.total,
        "pagination": {
            "page": result.page,
            "page_size": result.page_size,
            "pages": result.pages,
            "has_next": result.has_next,
            "has_previous": result.has_previous,
        },
        "counts": dict(result.counts),
    }


def _api_workflows_for_chat_locked(
    bot_data: dict[str, Any],
    chat_id: int,
    *,
    kind: str = "all",
    status: str = "all",
    limit: int = 50,
    include_events: bool = False,
) -> dict[str, Any]:
    page = list_workflows(
        bot_data,
        chat_id=int(chat_id),
        kind=kind,
        status=status,
        limit=limit,
        include_events=include_events,
    )
    items = []
    for item in page.items:
        row = dict(item)
        row["started_at"] = _api_ms_to_iso(row.get("started_at_ms"))
        row["updated_at"] = _api_ms_to_iso(row.get("updated_at_ms"))
        row["completed_at"] = _api_ms_to_iso(row.get("completed_at_ms"))
        items.append(row)
    return {"workflows": items, "total": page.total, "counts": dict(page.counts)}


def _api_risk_list_locked(bot_data: dict[str, Any], chat_id: int, *, limit: int = 20) -> list[dict[str, Any]]:
    incidents = bot_data.get("incidents", {}) if isinstance(bot_data.get("incidents", {}), dict) else {}
    known_users = bot_data.get("known_users", {}) if isinstance(bot_data.get("known_users", {}), dict) else {}
    stats: dict[int, dict[str, Any]] = {}
    for incident in incidents.values():
        if not isinstance(incident, dict) or str(incident.get("chat_id")) != str(int(chat_id)):
            continue
        sender_id = _safe_int(incident.get("sender_id"), 0)
        if not sender_id:
            continue
        entry = stats.setdefault(
            sender_id,
            {"user_id": sender_id, "name": str(incident.get("sender_name") or sender_id), "blocked": 0, "warned": 0, "muted": 0, "banned": 0, "last_file": "", "last_seen_ms": 0},
        )
        entry["blocked"] += 1
        entry["last_file"] = str(incident.get("file_name") or entry.get("last_file") or "")
        entry["last_seen_ms"] = max(_safe_int(entry.get("last_seen_ms"), 0), _safe_int(incident.get("created_at_ms"), incident_timestamp_ms("") or 0))
        action = str(incident.get("action") or incident.get("auto_action") or "").casefold()
        if action == "warn":
            entry["warned"] += 1
        elif action == "mute":
            entry["muted"] += 1
        elif action == "ban":
            entry["banned"] += 1
    rows = sorted(stats.values(), key=lambda item: (item["blocked"], item["banned"], item["muted"], item["warned"]), reverse=True)
    for row in rows:
        profile = known_users.get(str(row["user_id"]), {}) if isinstance(known_users.get(str(row["user_id"]), {}), dict) else {}
        row["username"] = str(profile.get("username") or "")
        row["display_name"] = str(profile.get("full_name") or row.get("name") or row["user_id"])
        row["risk"] = _risk_badge(_safe_int(row.get("blocked"), 0))
        row["last_seen_at"] = _api_ms_to_iso(row.get("last_seen_ms"))
    return rows[: max(1, min(int(limit), 100))]


def _api_admin_logs_for_chat_locked(bot_data: dict[str, Any], chat_id: int, *, limit: int = 100) -> list[dict[str, Any]]:
    rows = [dict(item) for item in _admin_action_logs(bot_data) if str(item.get("chat_id")) == str(int(chat_id))]
    rows.sort(key=lambda item: _safe_int(item.get("created_at_ms"), 0), reverse=True)
    for row in rows:
        row["created_at"] = _api_ms_to_iso(row.get("created_at_ms"))
    return _api_json_safe(rows[: max(1, min(int(limit), 200))])


def _api_memory_overview_locked(bot_data: dict[str, Any]) -> dict[str, Any]:
    known_users = bot_data.get("known_users", {}) if isinstance(bot_data.get("known_users", {}), dict) else {}
    group_state = bot_data.get("group_state", {}) if isinstance(bot_data.get("group_state", {}), dict) else {}
    incidents = bot_data.get("incidents", {}) if isinstance(bot_data.get("incidents", {}), dict) else {}
    feedback = bot_data.get("user_feedback", []) if isinstance(bot_data.get("user_feedback", []), list) else []
    return {
        "backend": storage_backend_label(),
        "supabase": "connected" if runtime.SUPABASE_AVAILABLE else ("configured_offline" if SUPABASE_ENABLED else "disabled"),
        "redis": "connected" if runtime.REDIS_AVAILABLE else ("configured_offline" if REDIS_ENABLED else "disabled"),
        "known_users": len(known_users),
        "groups": len(group_state),
        "open_incidents": sum(1 for item in incidents.values() if isinstance(item, dict) and not item.get("done")),
        "total_incidents": len(incidents),
        "feedback": len(feedback),
        "admin_cache": len(ADMIN_IDS_CACHE),
        "bot_permission_cache": len(BOT_MEMBER_CACHE),
        "last_supabase_save": runtime.SUPABASE_LAST_SAVE_UTC,
        "last_redis_save": runtime.REDIS_LAST_SAVE_UTC,
    }


def _api_route_catalog(*, include_private: bool = True, include_developer: bool = False) -> dict[str, Any]:
    """Return only the routes appropriate for the current authentication level."""
    prefix = MINI_APP_API_PREFIX
    catalog: dict[str, Any] = {
        "auth": "Send signed Telegram WebApp initData via X-Telegram-Init-Data.",
        "prefix": prefix,
        "public": {
            "root": "/",
            "health": f"{prefix}/health",
            "bootstrap": f"{prefix}/bootstrap",
            "scanner_presets": f"{prefix}/scanner/presets",
        },
    }
    if not include_private:
        if MINI_APP_PUBLIC_ROUTE_CATALOG_ENABLED:
            catalog["public"]["routes"] = f"{prefix}/routes"
        return catalog

    catalog.update({
        "session": {
            "auth_session": f"{prefix}/auth/session",
            "session_alias": f"{prefix}/session",
            "bootstrap": f"{prefix}/bootstrap",
            "dashboard": f"{prefix}/dashboard",
            "me": f"{prefix}/me",
            "preferences": f"{prefix}/me/preferences",
            "my_groups": f"{prefix}/me/groups",
            "groups_alias": f"{prefix}/groups",
        },
        "groups": {
            "detail": f"{prefix}/groups/{{chat_id}}",
            "settings": f"{prefix}/groups/{{chat_id}}/settings",
            "policies": f"{prefix}/groups/{{chat_id}}/policies",
            "apply_preset": f"{prefix}/groups/{{chat_id}}/presets/{{preset_id}}",
            "formats": f"{prefix}/groups/{{chat_id}}/formats/{{allowed|blocked}}",
            "trusted_hashes": f"{prefix}/groups/{{chat_id}}/trusted-hashes",
            "incidents": f"{prefix}/groups/{{chat_id}}/incidents",
            "risk": f"{prefix}/groups/{{chat_id}}/risk",
            "admins": f"{prefix}/groups/{{chat_id}}/admins",
            "admin_logs": f"{prefix}/groups/{{chat_id}}/admin-logs",
            "health": f"{prefix}/groups/{{chat_id}}/health",
            "workflows": f"{prefix}/groups/{{chat_id}}/workflows",
            "sync": f"{prefix}/groups/{{chat_id}}/sync",
        },
        "tools": {
            "scanner_presets": f"{prefix}/scanner/presets",
            "scan_name": f"{prefix}/scan/name",
            "feedback": f"{prefix}/feedback",
            "incident_action": f"{prefix}/incidents/{{token_or_key}}/action",
        },
    })
    if include_developer:
        catalog["developer"] = {
            "overview": f"{prefix}/developer/overview",
            "users": f"{prefix}/developer/users",
            "groups": f"{prefix}/developer/groups",
            "feedback": f"{prefix}/developer/feedback",
            "runtime_config": f"{prefix}/developer/runtime-config",
            "server_log": f"{prefix}/server/log",
            "server_logs_alias": f"{prefix}/server/logs",
        }
    return catalog

def _api_public_bootstrap_payload(*, reason: str = "missing_init_data") -> dict[str, Any]:
    """Safe unauthenticated payload for frontend boot.

    This intentionally contains no private user/group data. It lets a React
    Mini App render a friendly connection/auth state instead of a blank screen
    when window.Telegram.WebApp.initData is empty, the app is opened in a normal
    browser, or a frontend request is made before Telegram initialization.
    """
    return {
        "ok": True,
        "authenticated": False,
        "auth_required": True,
        "reason": str(reason or "missing_init_data"),
        "message": "Telegram Mini App initData is required for private user/group data. Open this page inside Telegram or send X-Telegram-Init-Data.",
        "user": None,
        "saved_profile": {},
        "state": {},
        "linked_group_count": 0,
        "groups": [],
        "total_groups": 0,
        "is_developer": False,
        "features": {
            "groups": False,
            "group_settings": False,
            "incidents": False,
            "incident_filters": False,
            "scanner_presets": True,
            "group_policies": False,
            "workflow_center": False,
            "trusted_hashes": False,
            "developer_dashboard": False,
        },
        "api": {
            "name": PROFESSIONAL_BRAND_NAME,
            "version": PROFESSIONAL_UI_VERSION,
            "prefix": MINI_APP_API_PREFIX,
            "bot_id": runtime.BOT_ID if MINI_APP_EXPOSE_BOT_ID_PUBLICLY else None,
            "bot_username": runtime.BOT_USERNAME,
        },
        "routes": _api_route_catalog(include_private=False),
    }


def _api_frontend_config_payload() -> dict[str, Any]:
    """Public frontend configuration and connectivity probe payload."""
    return {
        "ok": True,
        "name": PROFESSIONAL_BRAND_NAME,
        "version": PROFESSIONAL_UI_VERSION,
        "api_prefix": MINI_APP_API_PREFIX,
        "dashboard_url": "/app",
        "bot_id": runtime.BOT_ID if MINI_APP_EXPOSE_BOT_ID_PUBLICLY else None,
        "bot_username": runtime.BOT_USERNAME,
        "telegram_auth_required": True,
        "auth_header": "X-Telegram-Init-Data",
        "public_bootstrap_on_missing_initdata": MINI_APP_PUBLIC_BOOTSTRAP_ON_MISSING_INITDATA,
        "frontend_debug_enabled": MINI_APP_FRONTEND_DEBUG_ENABLED,
        "cors": {
            "wildcard": "*" in set(MINI_APP_CORS_ORIGINS),
            "origin_count": len(tuple(MINI_APP_CORS_ORIGINS)),
            "allow_methods": ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        },
        "routes": _api_route_catalog(include_private=False),
    }


def _api_session_payload_locked(bot_data: dict[str, Any], principal: MiniAppPrincipal, *, include_groups: bool = False) -> dict[str, Any]:
    saved = bot_data.get("known_users", {}).get(str(principal.user_id), {}) if isinstance(bot_data.get("known_users", {}), dict) else {}
    state = _read_user_state(bot_data, principal.user_id)
    group_ids = _api_linked_group_ids_locked(bot_data, principal.user_id)
    payload: dict[str, Any] = {
        "ok": True,
        "user": _api_public_profile_from_principal(principal),
        "saved_profile": _api_json_safe(saved),
        "state": _api_json_safe(state),
        "is_developer": principal.user_id in BOT_OWNER_IDS,
        "linked_group_count": len(group_ids),
        "features": {
            "groups": True,
            "group_settings": True,
            "incidents": True,
            "incident_filters": True,
            "scanner_presets": True,
            "group_policies": True,
            "workflow_center": True,
            "trusted_hashes": trusted_hash_whitelist_enabled(bot_data),
            "developer_dashboard": principal.user_id in BOT_OWNER_IDS,
        },
        "routes": _api_route_catalog(include_private=True, include_developer=principal.user_id in BOT_OWNER_IDS),
    }
    if include_groups:
        payload["groups"] = [_api_group_snapshot_locked(bot_data, principal.user_id, chat_id) for chat_id in group_ids]
        payload["total_groups"] = len(payload["groups"])
    if principal.user_id in BOT_OWNER_IDS:
        payload["developer"] = {
            "overview": _api_memory_overview_locked(bot_data),
            "runtime_config": _api_json_safe(dict(ensure_runtime_config(bot_data))),
        }
    return payload




def _find_workflow_record(bot_data: dict[str, Any], workflow_id: str) -> dict[str, Any] | None:
    history = bot_data.get("workflow_history", [])
    if not isinstance(history, list):
        return None
    for item in reversed(history):
        if isinstance(item, dict) and str(item.get("id") or "") == str(workflow_id):
            return item
    return None

async def _api_perform_incident_action(
    application: Application,
    principal: MiniAppPrincipal,
    token_or_key: str,
    action: str,
) -> dict[str, Any]:
    action = str(action or "").strip().casefold()
    if action not in {"ban", "warn", "ignore", "risk"}:
        _api_raise(400, "action must be one of: ban, warn, ignore, risk")

    ikey = resolve_incident_action_key(application.bot_data, token_or_key)
    lock = await get_incident_lock(ikey)
    async with lock:
        workflow_id = ""
        async with BOT_DATA_LOCK:
            incidents = application.bot_data.setdefault("incidents", {})
            incident = incidents.get(ikey) if isinstance(incidents, dict) else None
            if not isinstance(incident, dict):
                _api_raise(404, "incident not found or expired")
            if incident.get("done") and action != "risk":
                _api_raise(409, "incident already handled")
            chat_id = int(incident.get("chat_id") or 0)
            sender_id = int(incident.get("sender_id") or 0)
            sender_name_raw = str(incident.get("sender_name") or "Unknown")
            workflow = begin_workflow(
                application.bot_data,
                kind="incident_action",
                chat_id=chat_id,
                actor_id=principal.user_id,
                source="miniapp",
                subject_id=ikey,
                metadata={"action": action, "sender_id": sender_id, "sender_name": sender_name_raw},
                at_ms=now_ms(),
            )
            workflow_id = str(workflow["id"])

        try:
            await _api_require_group_admin(application, principal, chat_id, live=True)
        except Exception as exc:
            async with BOT_DATA_LOCK:
                fail_workflow(
                    application.bot_data,
                    workflow_id,
                    at_ms=now_ms(),
                    stage="authorization_failed",
                    error=str(exc),
                )
                await persist_context_memory(application, reason="api_incident_workflow_failed", force=True, caller_holds_lock=True)
            raise

        async with BOT_DATA_LOCK:
            advance_workflow(
                application.bot_data,
                workflow_id,
                stage="authorized",
                at_ms=now_ms(),
                detail="group administrator verified",
            )

        if action == "risk":
            async with BOT_DATA_LOCK:
                incident = application.bot_data.setdefault("incidents", {}).get(ikey)
                if not isinstance(incident, dict):
                    _api_raise(404, "incident not found or expired")
                complete_workflow(
                    application.bot_data,
                    workflow_id,
                    at_ms=now_ms(),
                    outcome="risk_profile_viewed",
                    detail="risk profile generated",
                )
                return {
                    "ok": True,
                    "action": "risk",
                    "risk_html": _format_user_risk_profile(application.bot_data, principal.user_id, incident),
                    "incident": _api_incident_locked(application.bot_data, ikey, incident),
                    "workflow": workflow_public_view(_find_workflow_record(application.bot_data, workflow_id), include_events=True),
                }

        action_success = False
        result_message = ""
        sender_name = h(sender_name_raw)
        error_detail = ""

        if action == "ban":
            try:
                bot_perms = await get_bot_member_cached(application, chat_id, force=True, allow_api=True)
                if not has_ban_permission(bot_perms):
                    raise TelegramError("Bot does not have Ban Users permission")
                for ban_attempt in (1, 2):
                    try:
                        await application.bot.ban_chat_member(chat_id, sender_id)
                        break
                    except RetryAfter as exc:
                        if ban_attempt == 1 and await _sleep_for_retry_after(exc, operation="api_ban_chat_member"):
                            continue
                        raise
                action_success = True
                result_message = tr(application.bot_data, principal.user_id, "action_ban_ok", name=sender_name)
            except (TimedOut, BadRequest, Forbidden, TelegramError) as exc:
                error_detail = str(exc)
                logger.exception("API ban failed chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
                result_message = tr(application.bot_data, principal.user_id, "action_ban_fail")
        elif action == "warn":
            mention = user_link(sender_id, sender_name_raw)
            warn_text = TEXTS[get_lang(application.bot_data, principal.user_id)]["warn_in_group"].format(user=mention)
            try:
                send_result = await safe_send_message_result(application, chat_id, warn_text, operation="api_incident_warn")
                if not send_result.ok:
                    raise TelegramError(send_result.error or "warning message could not be delivered")
                action_success = True
                result_message = tr(application.bot_data, principal.user_id, "action_warn_ok", name=sender_name)
            except (TimedOut, BadRequest, Forbidden, TelegramError) as exc:
                error_detail = str(exc)
                logger.exception("API warn failed chat_id=%s sender_id=%s", chat_id, sender_id, exc_info=True)
                result_message = tr(application.bot_data, principal.user_id, "action_warn_fail")
        else:
            action_success = True
            result_message = tr(application.bot_data, principal.user_id, "action_ignore_ok")

        async with BOT_DATA_LOCK:
            incident = application.bot_data.setdefault("incidents", {}).get(ikey)
            if not isinstance(incident, dict):
                _api_raise(404, "incident not found or expired")
            incident["last_action_workflow_id"] = workflow_id
            if action_success:
                incident["done"] = True
                incident["handled_by"] = principal.user_id
                incident["handled_by_name"] = _api_full_name(principal.user)
                incident["handled_at_ms"] = now_ms()
                incident["action"] = action
                advance_workflow(
                    application.bot_data,
                    workflow_id,
                    stage="executed",
                    at_ms=now_ms(),
                    detail=f"incident action {action} succeeded",
                    data={"action": action},
                )
            else:
                fail_workflow(
                    application.bot_data,
                    workflow_id,
                    at_ms=now_ms(),
                    stage="execution_failed",
                    error=error_detail or f"incident action {action} failed",
                    data={"action": action},
                )
            _record_admin_action_log_locked(
                application.bot_data,
                chat_id=chat_id,
                admin_id=principal.user_id,
                admin_name=_api_full_name(principal.user),
                action=f"api incident {action}",
                target_id=sender_id,
                target_name=sender_name_raw,
                result="success" if action_success else "failed",
            )
            await persist_context_memory(application, reason="api_incident_action", force=True, caller_holds_lock=True)
            incident_response = _api_incident_locked(application.bot_data, ikey, incident)

        if action_success:
            await sync_handled_alert_messages(application, incident)
            async with BOT_DATA_LOCK:
                advance_workflow(
                    application.bot_data,
                    workflow_id,
                    stage="alerts_synchronized",
                    at_ms=now_ms(),
                    detail="administrator alert messages synchronized",
                )
                completed = complete_workflow(
                    application.bot_data,
                    workflow_id,
                    at_ms=now_ms(),
                    outcome=f"incident_{action}",
                    detail=result_message,
                )
                await persist_context_memory(application, reason="api_incident_workflow_complete", force=True, caller_holds_lock=True)
                workflow_response = workflow_public_view(completed or {}, include_events=True)
        else:
            async with BOT_DATA_LOCK:
                failed = _find_workflow_record(application.bot_data, workflow_id)
                workflow_response = workflow_public_view(failed or {}, include_events=True)

        return {
            "ok": bool(action_success),
            "action": action,
            "message": result_message,
            "incident": incident_response,
            "workflow": workflow_response,
        }



def create_mini_app_fastapi(application: Application, webhook_url: str) -> Any:
    """Create a FastAPI app that serves both Telegram webhook and Mini App API."""
    if FastAPI is None or CORSMiddleware is None or uvicorn is None:
        raise RuntimeError("MINI_APP_API_ENABLED=true requires dependencies: fastapi and uvicorn")

    webhook_route = "/" + WEBHOOK_URL_PATH.strip("/")
    secret_header = _telegram_secret_token_for_webhook()

    @asynccontextmanager
    async def lifespan(_: Any):
        await application.initialize()
        await post_init(application)
        await application.start()
        webhook_kwargs: dict[str, Any] = {
            "url": webhook_url,
            "allowed_updates": ALLOWED_UPDATES,
            "drop_pending_updates": DROP_PENDING_UPDATES,
        }
        if secret_header:
            webhook_kwargs["secret_token"] = secret_header
        await application.bot.set_webhook(**webhook_kwargs)
        logger.info("Mini App API enabled prefix=%s webhook route configured", MINI_APP_API_PREFIX)
        server_log_event(
            "process", "info", "mini app api startup",
            prefix=MINI_APP_API_PREFIX, webhook_configured=True, bot_username=runtime.BOT_USERNAME,
        )
        try:
            yield
        finally:
            server_log_event("process", "info", "mini app api shutdown")
            await application.stop()
            await post_shutdown(application)
            await application.shutdown()

    api = FastAPI(
        title=f"{PROFESSIONAL_BRAND_NAME} Mini App API",
        version=PROFESSIONAL_UI_VERSION,
        lifespan=lifespan,
        docs_url="/docs" if MINI_APP_PUBLIC_DOCS_ENABLED else None,
        redoc_url="/redoc" if MINI_APP_PUBLIC_DOCS_ENABLED else None,
        openapi_url="/openapi.json" if MINI_APP_PUBLIC_DOCS_ENABLED else None,
    )
    cors_origins = [origin for origin in MINI_APP_CORS_ORIGINS if origin]
    cors_all = "*" in cors_origins or not cors_origins
    api.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if cors_all else cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Content-Type", "Authorization", "X-Telegram-Init-Data",
            "X-Telegram-Web-App-Data", "X-TMA-Init-Data", "Telegram-Init-Data",
            "X-Request-ID",
        ],
        expose_headers=["Content-Type", "X-Request-ID"],
        max_age=86400,
    )

    if not MINI_APP_PUBLIC_DOCS_ENABLED:
        @api.api_route("/docs", methods=["GET", "HEAD"], include_in_schema=False)
        @api.api_route("/redoc", methods=["GET", "HEAD"], include_in_schema=False)
        @api.api_route("/openapi.json", methods=["GET", "HEAD"], include_in_schema=False)
        async def disabled_api_documentation() -> Response:
            return Response(status_code=404)

    static_dir = Path(__file__).with_name("static")
    dashboard_index = static_dir / "index.html"
    if StaticFiles is not None and static_dir.is_dir():
        api.mount("/app/assets", StaticFiles(directory=str(static_dir)), name="miniapp-assets")

    @api.get("/app/config.js")
    async def miniapp_dashboard_config() -> Response:
        payload = json.dumps({"apiPrefix": MINI_APP_API_PREFIX}, separators=(",", ":"))
        return Response(
            content=f"window.__EXE_REMOVER_CONFIG__={payload};",
            media_type="application/javascript",
            headers={"Cache-Control": "no-cache"},
        )

    @api.head("/app")
    @api.head("/app/")
    async def miniapp_dashboard_head() -> Response:
        return Response(status_code=200, headers={"X-Service-Status": "ok"})

    @api.get("/app")
    @api.get("/app/")
    async def miniapp_dashboard() -> Any:
        if FileResponse is None or not dashboard_index.is_file():
            _api_raise(404, "Mini App dashboard assets are not installed")
        return FileResponse(str(dashboard_index), media_type="text/html", headers={"Cache-Control": "no-cache"})

    @api.middleware("http")
    async def api_server_log_middleware(request: Request, call_next: Any) -> Any:
        """Record every API/webhook connection, error, and slow process event."""
        started = time.perf_counter()
        request_id = secrets.token_hex(6)
        path = str(getattr(request.url, "path", "") or "")
        method = str(getattr(request, "method", "") or "").upper()
        client = getattr(request, "client", None)
        client_host = privacy_safe_client_id(getattr(client, "host", ""))
        user_agent = (
            "<redacted>" if SERVER_LOG_REDACT_USER_AGENT
            else _server_log_safe_text(str(request.headers.get("user-agent") or ""), max_chars=180)
        )
        api_prefix_clean = MINI_APP_API_PREFIX.rstrip("/")
        server_log_paths = {f"{api_prefix_clean}/server/log", f"{api_prefix_clean}/server/logs"}
        healthcheck_paths = {"/", MINI_APP_API_PREFIX, f"{api_prefix_clean}/", f"{api_prefix_clean}/health"}
        is_server_log_read = path in server_log_paths and method in {"GET", "HEAD"}
        is_healthcheck = method == "HEAD" and path in healthcheck_paths
        log_this_request = path == "/" or path == webhook_route or path.startswith(api_prefix_clean + "/") or path == MINI_APP_API_PREFIX
        if is_server_log_read and not SERVER_LOG_CAPTURE_LOG_ENDPOINT:
            log_this_request = False
        if is_healthcheck and not SERVER_LOG_CAPTURE_HEALTHCHECKS:
            log_this_request = False

        try:
            response = await call_next(request)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            try:
                response.headers["X-Request-ID"] = request_id
                if MINI_APP_SECURITY_HEADERS_ENABLED:
                    response.headers["X-Content-Type-Options"] = "nosniff"
                    response.headers["Referrer-Policy"] = "no-referrer"
                    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
                    response.headers["X-Frame-Options"] = "SAMEORIGIN"
                    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
                    if path.startswith(api_prefix_clean + "/"):
                        response.headers["Cache-Control"] = "no-store"
            except Exception:
                pass

            if log_this_request:
                increment_request_total()
                status_code = int(getattr(response, "status_code", 0) or 0)
                level = "error" if status_code >= 500 else "warning" if status_code >= 400 or elapsed_ms >= SERVER_LOG_SLOW_API_MS else "info"
                category = "api_error" if status_code >= 400 else "api_request"
                server_log_event(
                    category,
                    level,
                    "api request completed",
                    request_id=request_id,
                    method=method,
                    path=path,
                    status_code=status_code,
                    elapsed_ms=elapsed_ms,
                    client_host=client_host,
                    user_agent=user_agent,
                    slow=elapsed_ms >= SERVER_LOG_SLOW_API_MS,
                )
            return response
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            if log_this_request:
                increment_request_total()
                server_log_event(
                    "api_error",
                    "error",
                    "api request failed",
                    request_id=request_id,
                    method=method,
                    path=path,
                    elapsed_ms=elapsed_ms,
                    client_host=client_host,
                    user_agent=user_agent,
                    error_type=exc.__class__.__name__,
                    error=_server_log_safe_text(str(exc), max_chars=500),
                    traceback=_server_log_safe_text(traceback.format_exc(), max_chars=SERVER_LOG_TRACEBACK_MAX_CHARS),
                )
            raise

    @api.head("/")
    async def api_root_head() -> Response:
        # UptimeRobot and Render health checks often use HEAD. Returning 200
        # prevents harmless monitor probes from becoming noisy 405 errors.
        return Response(status_code=200, headers={"X-Service-Status": "ok", "X-API-Prefix": MINI_APP_API_PREFIX})

    @api.head(MINI_APP_API_PREFIX)
    @api.head(f"{MINI_APP_API_PREFIX}/")
    @api.head(f"{MINI_APP_API_PREFIX}/health")
    async def api_health_head() -> Response:
        return Response(status_code=200, headers={"X-Service-Status": "ok", "X-API-Prefix": MINI_APP_API_PREFIX})

    @api.get("/")
    async def api_root() -> dict[str, Any]:
        return {
            "ok": True,
            "name": PROFESSIONAL_BRAND_NAME,
            "version": PROFESSIONAL_UI_VERSION,
            "api_prefix": MINI_APP_API_PREFIX,
            "docs": "/docs" if MINI_APP_PUBLIC_DOCS_ENABLED else None,
            "dashboard": "/app",
            "bootstrap": f"{MINI_APP_API_PREFIX}/bootstrap",
        }

    @api.get(MINI_APP_API_PREFIX)
    @api.get(f"{MINI_APP_API_PREFIX}/")
    async def api_index() -> dict[str, Any]:
        return {"ok": True, "name": PROFESSIONAL_BRAND_NAME, "version": PROFESSIONAL_UI_VERSION, "routes": _api_route_catalog(include_private=False)}

    @api.get(f"{MINI_APP_API_PREFIX}/routes")
    async def api_routes() -> dict[str, Any]:
        return {"ok": True, "routes": _api_route_catalog(include_private=False)}

    @api.get(f"{MINI_APP_API_PREFIX}/health")
    async def api_health() -> dict[str, Any]:
        return {
            "ok": True,
            "service": PROFESSIONAL_BRAND_NAME,
            "version": PROFESSIONAL_UI_VERSION,
            "bot_id": runtime.BOT_ID if MINI_APP_EXPOSE_BOT_ID_PUBLICLY else None,
            "bot_username": runtime.BOT_USERNAME,
            "mode": "WEBHOOK+API",
            "uptime_seconds": process_status_snapshot().get("uptime_seconds", 0.0),
        }

    @api.get(f"{MINI_APP_API_PREFIX}/frontend/config")
    @api.get(f"{MINI_APP_API_PREFIX}/connect")
    @api.get(f"{MINI_APP_API_PREFIX}/connect-test")
    async def api_frontend_config() -> dict[str, Any]:
        # Public: contains only routing/config data. No private user/group data.
        return _api_frontend_config_payload()

    @api.get(f"{MINI_APP_API_PREFIX}/scanner/presets")
    async def api_scanner_presets(lang: str = "en") -> dict[str, Any]:
        return {
            "ok": True,
            "presets": scanner_presets_catalog(lang),
            "allowed_values": {
                "scanner_preset": list(SCANNER_PRESET_IDS),
                "archive_policy": list(ARCHIVE_POLICIES),
                "unscannable_policy": list(UNSCANNABLE_POLICIES),
                "notification_policy": list(NOTIFICATION_POLICIES),
            },
        }

    @api.options("/{full_path:path}")
    async def api_options_preflight(full_path: str) -> Response:
        # CORSMiddleware handles real browser preflights. This fallback keeps
        # manual OPTIONS checks from showing as failed connections.
        return Response(status_code=204)

    @api.api_route(webhook_route, methods=["POST"])
    async def telegram_webhook(request: Request) -> dict[str, bool]:
        if secret_header:
            got = str(request.headers.get("X-Telegram-Bot-Api-Secret-Token") or "")
            if not hmac.compare_digest(got, secret_header):
                _api_raise(403, "invalid Telegram webhook secret")
        payload = await _api_request_json(request)
        try:
            update = Update.de_json(payload, application.bot)
            await application.process_update(update)
        except Exception:
            logger.exception("Webhook update processing failed", exc_info=True)
            # Return ok=True to avoid Telegram retry storms for malformed or already-bad updates.
        return {"ok": True}

    @api.get(f"{MINI_APP_API_PREFIX}/auth/session")
    @api.post(f"{MINI_APP_API_PREFIX}/auth/session")
    @api.get(f"{MINI_APP_API_PREFIX}/session")
    @api.post(f"{MINI_APP_API_PREFIX}/session")
    async def api_auth_session(request: Request) -> dict[str, Any]:
        try:
            principal = await _api_principal_from_request(request)
        except HTTPException as exc:
            detail = str(getattr(exc, "detail", "") or "")
            if (
                MINI_APP_PUBLIC_BOOTSTRAP_ON_MISSING_INITDATA
                and int(getattr(exc, "status_code", 0) or 0) == 401
                and detail == "missing Telegram Mini App initData"
            ):
                return _api_public_bootstrap_payload(reason="missing_init_data")
            raise
        await _api_remember_principal(application, principal, persist=True)
        async with BOT_DATA_LOCK:
            return _api_session_payload_locked(application.bot_data, principal, include_groups=False)

    @api.get(f"{MINI_APP_API_PREFIX}/bootstrap")
    @api.post(f"{MINI_APP_API_PREFIX}/bootstrap")
    @api.get(f"{MINI_APP_API_PREFIX}/dashboard")
    @api.post(f"{MINI_APP_API_PREFIX}/dashboard")
    async def api_bootstrap(request: Request, refresh: bool = False) -> dict[str, Any]:
        try:
            principal = await _api_principal_from_request(request)
        except HTTPException as exc:
            detail = str(getattr(exc, "detail", "") or "")
            if (
                MINI_APP_PUBLIC_BOOTSTRAP_ON_MISSING_INITDATA
                and int(getattr(exc, "status_code", 0) or 0) == 401
                and detail == "missing Telegram Mini App initData"
            ):
                return _api_public_bootstrap_payload(reason="missing_init_data")
            raise
        await _api_remember_principal(application, principal, persist=True)
        async with BOT_DATA_LOCK:
            group_ids = _api_linked_group_ids_locked(application.bot_data, principal.user_id)
        if refresh and MINI_APP_LIVE_REFRESH_ALLOWED:
            await asyncio.gather(
                *(get_bot_member_cached(application, chat_id, force=True, allow_api=True) for chat_id in group_ids[:25]),
                return_exceptions=True,
            )
        async with BOT_DATA_LOCK:
            return _api_session_payload_locked(application.bot_data, principal, include_groups=True)

    @api.get(f"{MINI_APP_API_PREFIX}/me")
    async def api_me(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        async with BOT_DATA_LOCK:
            saved = application.bot_data.get("known_users", {}).get(str(principal.user_id), {}) if isinstance(application.bot_data.get("known_users", {}), dict) else {}
            state = _read_user_state(application.bot_data, principal.user_id)
            groups = _api_linked_group_ids_locked(application.bot_data, principal.user_id)
        return {
            "ok": True,
            "user": _api_public_profile_from_principal(principal),
            "saved_profile": _api_json_safe(saved),
            "state": _api_json_safe(state),
            "is_developer": principal.user_id in BOT_OWNER_IDS,
            "linked_group_count": len(groups),
        }

    @api.patch(f"{MINI_APP_API_PREFIX}/me/preferences")
    async def api_update_preferences(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        payload = await _api_request_json(request)
        lang = str(payload.get("lang") or "").strip().casefold()
        if lang not in {"en", "km"}:
            _api_raise(400, "lang must be en or km")
        async with BOT_DATA_LOCK:
            state = get_user_state(application.bot_data, principal.user_id)
            state["lang"] = lang
            state["last_seen_ms"] = now_ms()
            known_users = application.bot_data.setdefault("known_users", {})
            profile = known_users.setdefault(str(principal.user_id), {}) if isinstance(known_users, dict) else {}
            if isinstance(profile, dict):
                profile["lang"] = lang
            await persist_context_memory(application, reason="api_user_preferences", force=True, caller_holds_lock=True)
        return {"ok": True, "preferences": {"lang": lang}}

    @api.get(f"{MINI_APP_API_PREFIX}/me/groups")
    @api.get(f"{MINI_APP_API_PREFIX}/groups")
    async def api_my_groups(request: Request, refresh: bool = False) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_remember_principal(application, principal, persist=False)
        async with BOT_DATA_LOCK:
            group_ids = _api_linked_group_ids_locked(application.bot_data, principal.user_id)
        if refresh and MINI_APP_LIVE_REFRESH_ALLOWED:
            await asyncio.gather(
                *(get_bot_member_cached(application, chat_id, force=True, allow_api=True) for chat_id in group_ids[:25]),
                return_exceptions=True,
            )
        async with BOT_DATA_LOCK:
            groups = [_api_group_snapshot_locked(application.bot_data, principal.user_id, chat_id) for chat_id in group_ids]
        return {"ok": True, "groups": groups, "total": len(groups)}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}")
    async def api_group_detail(chat_id: int, request: Request, refresh: bool = False) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=refresh and MINI_APP_LIVE_REFRESH_ALLOWED)
        if refresh and MINI_APP_LIVE_REFRESH_ALLOWED:
            await asyncio.gather(
                get_bot_member_cached(application, chat_id, force=True, allow_api=True),
                get_chat_admin_ids_cached(application, chat_id, force=True, allow_api=True),
                return_exceptions=True,
            )
        return {"ok": True, "group": await _api_group_snapshot(application, principal.user_id, chat_id)}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/policies")
    async def api_group_policies(chat_id: int, request: Request, lang: str = "") -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        async with BOT_DATA_LOCK:
            user_lang = str(_read_user_state(application.bot_data, principal.user_id).get("lang") or "en")
            settings = _api_public_settings_locked(application.bot_data, chat_id)
        return {
            "ok": True,
            "policy": settings,
            "presets": scanner_presets_catalog(lang or user_lang),
            "allowed_values": {
                "archive_policy": list(ARCHIVE_POLICIES),
                "unscannable_policy": list(UNSCANNABLE_POLICIES),
                "notification_policy": list(NOTIFICATION_POLICIES),
            },
        }

    @api.patch(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/policies")
    async def api_update_group_policies(chat_id: int, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        payload = await _api_request_json(request)
        changed: list[str] = []
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            if "allowed_only" in payload:
                settings["allowed_only"] = _api_bool(payload.get("allowed_only"), bool(settings.get("allowed_only", False)))
                changed.append("allowed_only")
            if "max_file_size_mb" in payload:
                try:
                    size_bytes = int(float(payload.get("max_file_size_mb")) * 1024 * 1024)
                except (TypeError, ValueError):
                    _api_raise(400, "max_file_size_mb must be a number")
                settings["max_file_size_bytes"] = max(65_536, min(2_147_483_648, size_bytes))
                changed.append("max_file_size_bytes")
            elif "max_file_size_bytes" in payload:
                settings["max_file_size_bytes"] = _api_int(payload.get("max_file_size_bytes"), TELEGRAM_BOT_API_DOWNLOAD_LIMIT_BYTES, min_value=65_536, max_value=2_147_483_648)
                changed.append("max_file_size_bytes")
            for key, allowed, default in (
                ("archive_policy", ARCHIVE_POLICIES, "scan"),
                ("unscannable_policy", UNSCANNABLE_POLICIES, "block"),
                ("notification_policy", NOTIFICATION_POLICIES, "group_and_admins"),
            ):
                if key in payload:
                    value = str(payload.get(key) or default).strip().casefold()
                    if value not in allowed:
                        _api_raise(400, f"{key} must be one of: {', '.join(allowed)}")
                    settings[key] = value
                    changed.append(key)
            if "incident_retention_days" in payload:
                settings["incident_retention_days"] = _api_int(payload.get("incident_retention_days"), 30, min_value=1, max_value=3650)
                changed.append("incident_retention_days")
            if "policy_notes" in payload:
                settings["policy_notes"] = str(payload.get("policy_notes") or "").strip()[:500]
                changed.append("policy_notes")
            if "strict_enforcement_on_admins" in payload:
                settings["strict_enforcement_on_admins"] = _api_bool(payload.get("strict_enforcement_on_admins"), True)
                changed.append("strict_enforcement_on_admins")
            if changed:
                _api_mark_policy_updated(settings, principal.user_id, detect_preset=True)
                _record_admin_action_log_locked(
                    application.bot_data,
                    chat_id=chat_id,
                    admin_id=principal.user_id,
                    admin_name=_api_full_name(principal.user),
                    action="api update group policy",
                    result=", ".join(changed),
                )
                _api_record_policy_workflow_locked(application.bot_data, chat_id=chat_id, actor_id=principal.user_id, operation="update group policies", changed=changed)
                await persist_context_memory(application, reason="api_group_policy_update", force=True, caller_holds_lock=True)
            group = _api_group_snapshot_locked(application.bot_data, principal.user_id, chat_id)
        return {"ok": True, "changed": changed, "policy": group["settings"], "group": group}

    @api.post(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/presets/{{preset_id}}")
    async def api_apply_group_preset(chat_id: int, preset_id: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        normalized = str(preset_id or "").strip().casefold()
        if normalized not in SCANNER_PRESET_IDS or normalized == "custom":
            _api_raise(400, "preset_id must be standard, strict, documents, or media")
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            try:
                changed = apply_scanner_preset(settings, normalized)
            except ValueError as exc:
                _api_raise(400, str(exc))
            _api_mark_policy_updated(settings, principal.user_id, detect_preset=False)
            settings["scanner_preset"] = normalized
            _record_admin_action_log_locked(
                application.bot_data,
                chat_id=chat_id,
                admin_id=principal.user_id,
                admin_name=_api_full_name(principal.user),
                action="api apply scanner preset",
                result=normalized,
            )
            _api_record_policy_workflow_locked(application.bot_data, chat_id=chat_id, actor_id=principal.user_id, operation="apply scanner preset", changed=changed, metadata={"preset": normalized})
            await persist_context_memory(application, reason="api_scanner_preset_apply", force=True, caller_holds_lock=True)
            group = _api_group_snapshot_locked(application.bot_data, principal.user_id, chat_id)
        return {"ok": True, "preset": normalized, "changed": changed, "group": group}

    @api.patch(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/settings")
    async def api_update_group_settings(chat_id: int, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        payload = await _api_request_json(request)
        changed: list[str] = []
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            if "protection_enabled" in payload:
                settings["protection_enabled"] = _api_bool(payload.get("protection_enabled"), bool(settings.get("protection_enabled", True)))
                changed.append("protection_enabled")
            if "silent_mode" in payload:
                settings["silent_mode"] = _api_bool(payload.get("silent_mode"), bool(settings.get("silent_mode", False)))
                changed.append("silent_mode")
            if "strict_enforcement_on_admins" in payload:
                settings["strict_enforcement_on_admins"] = _api_bool(payload.get("strict_enforcement_on_admins"), bool(settings.get("strict_enforcement_on_admins", True)))
                changed.append("strict_enforcement_on_admins")
            if "strictness" in payload:
                strictness = str(payload.get("strictness") or "standard").strip().casefold()
                if strictness not in {"standard", "high", "strict"}:
                    _api_raise(400, "strictness must be standard, high, or strict")
                settings["strictness"] = strictness
                changed.append("strictness")
            if "allowed_extensions" in payload:
                settings["allowed_extensions"] = _api_extension_values(payload.get("allowed_extensions"), allowed=True)
                changed.append("allowed_extensions")
            if "custom_blocked_extensions" in payload:
                settings["custom_blocked_extensions"] = _api_extension_values(payload.get("custom_blocked_extensions"), allowed=False)
                changed.append("custom_blocked_extensions")
            if "auto_action_mode" in payload:
                mode = str(payload.get("auto_action_mode") or "off").strip().casefold()
                if mode not in {"off", "warn", "smart", "ban"}:
                    _api_raise(400, "auto_action_mode must be off, warn, smart, or ban")
                settings["auto_action_mode"] = mode
                changed.append("auto_action_mode")
            for key, default, max_value in (
                ("auto_warn_threshold", 1, 100),
                ("auto_mute_threshold", 2, 100),
                ("auto_ban_threshold", 3, 100),
                ("auto_mute_minutes", 60, 10080),
            ):
                if key in payload:
                    settings[key] = _api_int(payload.get(key), default, min_value=1, max_value=max_value)
                    changed.append(key)
            if changed:
                _api_mark_policy_updated(settings, principal.user_id, detect_preset=True)
                _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action="api update settings", result=", ".join(changed))
                _api_record_policy_workflow_locked(application.bot_data, chat_id=chat_id, actor_id=principal.user_id, operation="update group settings", changed=changed)
                await persist_context_memory(application, reason="api_group_settings_update", force=True, caller_holds_lock=True)
            group = _api_group_snapshot_locked(application.bot_data, principal.user_id, chat_id)
        return {"ok": True, "changed": changed, "group": group}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/formats/{{kind}}")
    async def api_get_formats(chat_id: int, kind: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        kind = kind.strip().casefold()
        if kind not in {"allowed", "blocked"}:
            _api_raise(400, "kind must be allowed or blocked")
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            key = "allowed_extensions" if kind == "allowed" else "custom_blocked_extensions"
            return {"ok": True, "kind": kind, "extensions": list(settings.get(key, []))}

    @api.post(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/formats/{{kind}}")
    async def api_update_formats(chat_id: int, kind: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        kind = kind.strip().casefold()
        if kind not in {"allowed", "blocked"}:
            _api_raise(400, "kind must be allowed or blocked")
        payload = await _api_request_json(request)
        mode = str(payload.get("mode") or "append").strip().casefold()
        if mode not in {"append", "replace"}:
            _api_raise(400, "mode must be append or replace")
        new_exts = _api_extension_values(payload.get("extensions") or payload.get("extension") or "", allowed=(kind == "allowed"))
        if not new_exts and mode != "replace":
            _api_raise(400, "no valid extensions supplied")
        key = "allowed_extensions" if kind == "allowed" else "custom_blocked_extensions"
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            old = list(settings.get(key, []))
            combined = new_exts if mode == "replace" else old + new_exts
            settings[key] = _api_extension_values(combined, allowed=(kind == "allowed"))
            _api_mark_policy_updated(settings, principal.user_id, detect_preset=True)
            _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action=f"api {mode} {kind} formats", result=", ".join(settings[key]) or "empty")
            _api_record_policy_workflow_locked(application.bot_data, chat_id=chat_id, actor_id=principal.user_id, operation=f"{mode} {kind} formats", changed=[key], metadata={"extensions": list(settings.get(key, []))})
            await persist_context_memory(application, reason="api_formats_update", force=True, caller_holds_lock=True)
            return {"ok": True, "kind": kind, "extensions": list(settings.get(key, [])), "group": _api_group_snapshot_locked(application.bot_data, principal.user_id, chat_id)}

    @api.delete(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/formats/{{kind}}/{{ext}}")
    async def api_delete_format(chat_id: int, kind: str, ext: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        kind = kind.strip().casefold()
        if kind not in {"allowed", "blocked"}:
            _api_raise(400, "kind must be allowed or blocked")
        normalized = _normalize_extension(ext)
        key = "allowed_extensions" if kind == "allowed" else "custom_blocked_extensions"
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            settings[key] = [item for item in settings.get(key, []) if item != normalized]
            _api_mark_policy_updated(settings, principal.user_id, detect_preset=True)
            _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action=f"api delete {kind} format", result=normalized)
            _api_record_policy_workflow_locked(application.bot_data, chat_id=chat_id, actor_id=principal.user_id, operation=f"delete {kind} format", changed=[key], metadata={"extension": normalized})
            await persist_context_memory(application, reason="api_format_delete", force=True, caller_holds_lock=True)
            return {"ok": True, "kind": kind, "extensions": list(settings.get(key, []))}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/trusted-hashes")
    async def api_get_hashes(chat_id: int, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        async with BOT_DATA_LOCK:
            settings = get_group_settings(application.bot_data, chat_id)
            bucket = application.bot_data.get("whitelisted_hashes", {}) if isinstance(application.bot_data.get("whitelisted_hashes", {}), dict) else {}
            meta = bucket.get(str(int(chat_id)), {}) if isinstance(bucket.get(str(int(chat_id)), {}), dict) else {}
            return {"ok": True, "enabled": trusted_hash_whitelist_enabled(application.bot_data), "hashes": list(settings.get("trusted_file_hashes", [])), "metadata": _api_json_safe(meta)}

    @api.post(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/trusted-hashes")
    async def api_add_hash(chat_id: int, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        payload = await _api_request_json(request)
        digest = normalize_sha256_hash(payload.get("sha256") or payload.get("hash") or payload.get("file_sha256"))
        if not digest:
            _api_raise(400, "valid sha256 hash is required")
        async with BOT_DATA_LOCK:
            ok = add_trusted_file_hash(application.bot_data, chat_id, digest, added_by=principal.user_id, file_name=str(payload.get("file_name") or ""))
            if not ok:
                _api_raise(400, "could not add trusted hash; check max hash limit")
            _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action="api add trusted hash", result=short_hash(digest))
            _api_record_policy_workflow_locked(application.bot_data, chat_id=chat_id, actor_id=principal.user_id, operation="add trusted hash", changed=["trusted_file_hashes"], metadata={"digest": short_hash(digest)})
            await persist_context_memory(application, reason="api_hash_add", force=True, caller_holds_lock=True)
            settings = get_group_settings(application.bot_data, chat_id)
            return {"ok": True, "hashes": list(settings.get("trusted_file_hashes", []))}

    @api.delete(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/trusted-hashes/{{digest}}")
    async def api_delete_hash(chat_id: int, digest: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        async with BOT_DATA_LOCK:
            ok = remove_trusted_file_hash(application.bot_data, chat_id, digest)
            if not ok:
                _api_raise(404, "trusted hash not found")
            _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action="api delete trusted hash", result=str(digest)[:12])
            _api_record_policy_workflow_locked(application.bot_data, chat_id=chat_id, actor_id=principal.user_id, operation="delete trusted hash", changed=["trusted_file_hashes"], metadata={"digest": str(digest)[:12]})
            await persist_context_memory(application, reason="api_hash_delete", force=True, caller_holds_lock=True)
            settings = get_group_settings(application.bot_data, chat_id)
            return {"ok": True, "hashes": list(settings.get("trusted_file_hashes", []))}

    @api.delete(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/trusted-hashes")
    async def api_clear_hashes(chat_id: int, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        async with BOT_DATA_LOCK:
            clear_trusted_file_hashes(application.bot_data, chat_id)
            _record_admin_action_log_locked(application.bot_data, chat_id=chat_id, admin_id=principal.user_id, admin_name=_api_full_name(principal.user), action="api clear trusted hashes", result="cleared")
            _api_record_policy_workflow_locked(application.bot_data, chat_id=chat_id, actor_id=principal.user_id, operation="clear trusted hashes", changed=["trusted_file_hashes"])
            await persist_context_memory(application, reason="api_hash_clear", force=True, caller_holds_lock=True)
        return {"ok": True, "hashes": []}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/incidents")
    async def api_group_incidents(
        chat_id: int,
        request: Request,
        status: str = "all",
        severity: str = "all",
        action: str = "all",
        query: str = "",
        sender_id: int | None = None,
        date_from_ms: int = 0,
        date_to_ms: int = 0,
        page: int = 1,
        page_size: int = 25,
        limit: int | None = None,
        sort: str = "newest",
    ) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        status = status.strip().casefold()
        severity = severity.strip().casefold()
        action = action.strip().casefold()
        sort = sort.strip().casefold()
        if status not in {"all", "open", "handled"}:
            _api_raise(400, "status must be all, open, or handled")
        if severity not in {"all", "low", "medium", "high", "critical"}:
            _api_raise(400, "severity must be all, low, medium, high, or critical")
        if action not in {"all", "none", "warn", "mute", "ban", "ignore", "risk"}:
            _api_raise(400, "action must be all, none, warn, mute, ban, ignore, or risk")
        if sort not in {"newest", "oldest"}:
            _api_raise(400, "sort must be newest or oldest")
        effective_page_size = limit if limit is not None else page_size
        async with BOT_DATA_LOCK:
            result = _api_incidents_for_chat_locked(
                application.bot_data,
                chat_id,
                status=status,
                severity=severity,
                action=action,
                query=query,
                sender_id=sender_id,
                date_from_ms=date_from_ms,
                date_to_ms=date_to_ms,
                page=page,
                page_size=effective_page_size,
                sort=sort,
            )
        return {"ok": True, **result}

    @api.post(f"{MINI_APP_API_PREFIX}/incidents/{{token_or_key}}/action")
    async def api_incident_action(token_or_key: str, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        payload = await _api_request_json(request)
        action = str(payload.get("action") or "").strip().casefold()
        return await _api_perform_incident_action(application, principal, token_or_key, action)

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/workflows")
    async def api_group_workflows(
        chat_id: int,
        request: Request,
        kind: str = "all",
        status: str = "all",
        limit: int = 50,
        include_events: bool = False,
    ) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        kind_clean = str(kind or "all").strip().casefold()
        status_clean = str(status or "all").strip().casefold()
        if kind_clean not in {"all", "file_moderation", "incident_action", "policy_update", "group_sync"}:
            _api_raise(400, "invalid workflow kind")
        if status_clean not in {"all", "running", "completed", "failed", "interrupted"}:
            _api_raise(400, "invalid workflow status")
        async with BOT_DATA_LOCK:
            result = _api_workflows_for_chat_locked(
                application.bot_data,
                chat_id,
                kind=kind_clean,
                status=status_clean,
                limit=limit,
                include_events=include_events,
            )
        return {"ok": True, **result}

    @api.post(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/sync")
    async def api_sync_group_workflow(chat_id: int, request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=True)
        async with BOT_DATA_LOCK:
            workflow = begin_workflow(
                application.bot_data,
                kind="group_sync",
                chat_id=chat_id,
                actor_id=principal.user_id,
                source="miniapp",
                subject_id=chat_id,
                metadata={"requested_by": _api_full_name(principal.user)},
                at_ms=now_ms(),
            )
            workflow_id = str(workflow["id"])

        try:
            admin_ids = await get_chat_admin_ids_cached(application, chat_id, force=True, allow_api=True)
            perms = await get_bot_member_cached(application, chat_id, force=True, allow_api=True)
            async with BOT_DATA_LOCK:
                advance_workflow(
                    application.bot_data,
                    workflow_id,
                    stage="permissions_refreshed",
                    at_ms=now_ms(),
                    detail="live Telegram permissions refreshed",
                    data={
                        "admin_count": len(admin_ids),
                        "bot_status": perms.status,
                        "can_delete_messages": perms.can_delete_messages,
                        "can_restrict_members": perms.can_restrict_members,
                    },
                )
                report = reconcile_group_state(application.bot_data, chat_id, at_ms=now_ms())
                advance_workflow(
                    application.bot_data,
                    workflow_id,
                    stage="state_reconciled",
                    at_ms=now_ms(),
                    detail="group settings, incidents, tokens, and workflow counters reconciled",
                    data=report,
                )
                _record_admin_action_log_locked(
                    application.bot_data,
                    chat_id=chat_id,
                    admin_id=principal.user_id,
                    admin_name=_api_full_name(principal.user),
                    action="api synchronize group workflow",
                    result=f"admins={len(admin_ids)} removed_incidents={report.get('incidents_removed', 0)}",
                )
                advance_workflow(
                    application.bot_data,
                    workflow_id,
                    stage="persisted",
                    at_ms=now_ms(),
                    detail="synchronized state queued for durable storage",
                )
                completed = complete_workflow(
                    application.bot_data,
                    workflow_id,
                    at_ms=now_ms(),
                    outcome="group_synchronized",
                    detail="Telegram and dashboard state are synchronized",
                    data=report,
                )
                await persist_context_memory(application, reason="api_group_sync", force=True, caller_holds_lock=True)
                group = _api_group_snapshot_locked(application.bot_data, principal.user_id, chat_id)
            return {
                "ok": True,
                "report": report,
                "workflow": workflow_public_view(completed or {}, include_events=True),
                "group": group,
            }
        except Exception as exc:
            async with BOT_DATA_LOCK:
                failed = fail_workflow(
                    application.bot_data,
                    workflow_id,
                    at_ms=now_ms(),
                    stage="sync_failed",
                    error=str(exc),
                )
                await persist_context_memory(application, reason="api_group_sync_failed", force=True, caller_holds_lock=True)
            logger.exception("Group workflow synchronization failed chat_id=%s", chat_id, exc_info=True)
            _api_raise(503, f"group synchronization failed: {exc.__class__.__name__}")

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/risk")
    async def api_group_risk(chat_id: int, request: Request, limit: int = 20) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        async with BOT_DATA_LOCK:
            rows = _api_risk_list_locked(application.bot_data, chat_id, limit=limit)
        return {"ok": True, "risk": rows, "total": len(rows)}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/admins")
    async def api_group_admins(chat_id: int, request: Request, refresh: bool = False) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=refresh and MINI_APP_LIVE_REFRESH_ALLOWED)
        if refresh and MINI_APP_LIVE_REFRESH_ALLOWED:
            ids = await get_chat_admin_ids_cached(application, chat_id, force=True, allow_api=True)
        else:
            ids = await get_chat_admin_ids_from_state(application.bot_data, chat_id)
        async with BOT_DATA_LOCK:
            known_users = application.bot_data.get("known_users", {}) if isinstance(application.bot_data.get("known_users", {}), dict) else {}
            user_state = application.bot_data.get("user_state", {}) if isinstance(application.bot_data.get("user_state", {}), dict) else {}
            admins = []
            for admin_id in ids:
                profile = known_users.get(str(admin_id), {}) if isinstance(known_users.get(str(admin_id), {}), dict) else {}
                admins.append({
                    "id": int(admin_id),
                    "full_name": str(profile.get("full_name") or admin_id),
                    "username": str(profile.get("username") or ""),
                    "alert_ready": str(admin_id) in {str(k) for k in user_state.keys()},
                })
        return {"ok": True, "admins": admins, "total": len(admins)}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/admin-logs")
    async def api_group_admin_logs(chat_id: int, request: Request, limit: int = 100) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=False)
        async with BOT_DATA_LOCK:
            rows = _api_admin_logs_for_chat_locked(application.bot_data, chat_id, limit=limit)
        return {"ok": True, "logs": rows, "total": len(rows)}

    @api.get(f"{MINI_APP_API_PREFIX}/groups/{{chat_id}}/health")
    async def api_group_health(chat_id: int, request: Request, refresh: bool = False) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_group_admin(application, principal, chat_id, live=refresh and MINI_APP_LIVE_REFRESH_ALLOWED)
        if refresh and MINI_APP_LIVE_REFRESH_ALLOWED:
            await asyncio.gather(
                get_bot_member_cached(application, chat_id, force=True, allow_api=True),
                get_chat_admin_ids_cached(application, chat_id, force=True, allow_api=True),
                return_exceptions=True,
            )
        group = await _api_group_snapshot(application, principal.user_id, chat_id)
        return {"ok": True, "health": group["bot_permission"], "counts": group["counts"], "group": group}

    @api.post(f"{MINI_APP_API_PREFIX}/scan/name")
    async def api_scan_name(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        payload = await _api_request_json(request)
        file_name = str(payload.get("file_name") or payload.get("filename") or "").strip()
        if not file_name:
            _api_raise(400, "file_name is required")
        result = scan_filename_only(file_name, str(payload.get("mime_type") or ""))
        return {"ok": True, "user_id": principal.user_id, "scan": _api_scan_result(result)}

    @api.post(f"{MINI_APP_API_PREFIX}/feedback")
    async def api_feedback(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        payload = await _api_request_json(request)
        text = str(payload.get("text") or payload.get("message") or "").strip()
        if len(text) < 5:
            _api_raise(400, "feedback is too short")
        async with BOT_DATA_LOCK:
            feedback = application.bot_data.setdefault("user_feedback", [])
            if not isinstance(feedback, list):
                feedback = []
                application.bot_data["user_feedback"] = feedback
            feedback.insert(0, {
                "user_id": principal.user_id,
                "name": _api_full_name(principal.user),
                "username": str(principal.user.get("username") or ""),
                "text": text[:2000],
                "created_at_ms": now_ms(),
                "source": "mini_app_api",
            })
            del feedback[MAX_USER_FEEDBACK_ITEMS:]
            await persist_context_memory(application, reason="api_feedback", force=True, caller_holds_lock=True)
        return {"ok": True}

    @api.get(f"{MINI_APP_API_PREFIX}/server/log")
    @api.get(f"{MINI_APP_API_PREFIX}/server/logs")
    async def api_server_log(request: Request, limit: int = 200, level: str = "all", category: str = "all", since_id: int = 0) -> dict[str, Any]:
        auth_info = await _api_require_server_log_access(request)
        rows = server_log_snapshot(limit=limit, level=level, category=category, since_id=since_id)
        return {
            "ok": True,
            "auth": {"mode": auth_info.get("mode")},
            "logs": _api_json_safe(rows),
            "total": len(rows),
            "filters": {"limit": limit, "level": level, "category": category, "since_id": since_id},
            "counters": server_log_counters(),
            "process": process_status_snapshot(),
            "config": {
                "public_access": SERVER_LOG_PUBLIC_ACCESS,
                "capture_log_endpoint": SERVER_LOG_CAPTURE_LOG_ENDPOINT,
                "capture_healthchecks": SERVER_LOG_CAPTURE_HEALTHCHECKS,
                "api_key_configured": bool(SERVER_LOG_API_KEY),
                "telegram_owner_auth": SERVER_LOG_ALLOW_TELEGRAM_OWNER_AUTH,
            },
            "routes": {
                "self": f"{MINI_APP_API_PREFIX}/server/log",
                "clear": f"{MINI_APP_API_PREFIX}/server/log",
            },
        }

    @api.delete(f"{MINI_APP_API_PREFIX}/server/log")
    @api.delete(f"{MINI_APP_API_PREFIX}/server/logs")
    async def api_clear_server_log(request: Request) -> dict[str, Any]:
        auth_info = await _api_require_server_log_access(request)
        clear_server_logs()
        server_log_event(
            "process",
            "warning",
            "server logs cleared",
            auth_mode=auth_info.get("mode"),
            user_id=auth_info.get("user_id"),
            name=auth_info.get("name"),
        )
        return {"ok": True, "message": "server logs cleared", "auth": {"mode": auth_info.get("mode")}, "counters": server_log_counters()}

    @api.get(f"{MINI_APP_API_PREFIX}/developer/overview")
    async def api_developer_overview(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        async with BOT_DATA_LOCK:
            return {"ok": True, "overview": _api_memory_overview_locked(application.bot_data)}

    @api.get(f"{MINI_APP_API_PREFIX}/developer/users")
    async def api_developer_users(request: Request, limit: int = 100) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        async with BOT_DATA_LOCK:
            known = application.bot_data.get("known_users", {}) if isinstance(application.bot_data.get("known_users", {}), dict) else {}
            users = [_api_json_safe(value) for value in known.values() if isinstance(value, dict)]
            users.sort(key=lambda item: _safe_int(item.get("last_seen_ms"), 0), reverse=True)
        return {"ok": True, "users": users[: max(1, min(limit, 500))], "total": len(users)}

    @api.get(f"{MINI_APP_API_PREFIX}/developer/groups")
    async def api_developer_groups(request: Request, limit: int = 200) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        async with BOT_DATA_LOCK:
            ids = _api_linked_group_ids_locked(application.bot_data, principal.user_id)
            groups = [_api_group_snapshot_locked(application.bot_data, principal.user_id, cid) for cid in ids]
        return {"ok": True, "groups": groups[: max(1, min(limit, 1000))], "total": len(groups)}

    @api.get(f"{MINI_APP_API_PREFIX}/developer/feedback")
    async def api_developer_feedback(request: Request, limit: int = 100) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        async with BOT_DATA_LOCK:
            feedback = application.bot_data.get("user_feedback", []) if isinstance(application.bot_data.get("user_feedback", []), list) else []
            rows = [_api_json_safe(item) for item in feedback if isinstance(item, dict)]
        return {"ok": True, "feedback": rows[: max(1, min(limit, 500))], "total": len(rows)}

    @api.get(f"{MINI_APP_API_PREFIX}/developer/runtime-config")
    async def api_get_runtime_config(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        async with BOT_DATA_LOCK:
            config = dict(ensure_runtime_config(application.bot_data))
        return {"ok": True, "runtime_config": _api_json_safe(config)}

    @api.patch(f"{MINI_APP_API_PREFIX}/developer/runtime-config")
    async def api_update_runtime_config(request: Request) -> dict[str, Any]:
        principal = await _api_principal_from_request(request)
        await _api_require_owner(principal)
        payload = await _api_request_json(request)
        async with BOT_DATA_LOCK:
            config = ensure_runtime_config(application.bot_data)
            if "trusted_file_hash_whitelist_enabled" in payload:
                config["trusted_file_hash_whitelist_enabled"] = _api_bool(payload.get("trusted_file_hash_whitelist_enabled"), trusted_hash_whitelist_enabled(application.bot_data))
            if "trusted_hash_max_download_bytes" in payload:
                config["trusted_hash_max_download_bytes"] = _api_int(payload.get("trusted_hash_max_download_bytes"), TRUSTED_HASH_MAX_DOWNLOAD_BYTES, min_value=1, max_value=100_000_000)
            if "max_trusted_file_hashes" in payload:
                config["max_trusted_file_hashes"] = _api_int(payload.get("max_trusted_file_hashes"), MAX_TRUSTED_FILE_HASHES, min_value=1, max_value=1000)
            await persist_context_memory(application, reason="api_runtime_config_update", force=True, caller_holds_lock=True)
            return {"ok": True, "runtime_config": _api_json_safe(config)}

    return api


def run_webhook_with_mini_app_api(application: Application, webhook_url: str) -> None:
    """Run webhook + REST API on the same Render web service port."""
    api = create_mini_app_fastapi(application, webhook_url)
    uvicorn.run(
        api,
        host="0.0.0.0",
        port=PORT,
        log_level=_env_str("UVICORN_LOG_LEVEL", "info").lower(),
        access_log=MINI_APP_UVICORN_ACCESS_LOG,
    )


__all__ = ["create_mini_app_fastapi", "run_webhook_with_mini_app_api", "validate_telegram_webapp_init_data"]
