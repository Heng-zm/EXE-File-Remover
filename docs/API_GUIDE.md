# EXE Remover Security Bot v3.5 — Mini App API

## Base paths

```text
Dashboard: https://your-service.onrender.com/app
API:       https://your-service.onrender.com/api
Docs:      https://your-service.onrender.com/docs
Health:    https://your-service.onrender.com/api/health
```

## Authentication

Protected routes validate Telegram Mini App signed `initData`. Send it unchanged:

```http
X-Telegram-Init-Data: <window.Telegram.WebApp.initData>
```

Do not authenticate with `initDataUnsafe`. Group routes also verify that the current user is a group administrator or configured bot owner.

Minimal browser client:

```js
const initData = window.Telegram?.WebApp?.initData || "";
const response = await fetch("/api/bootstrap", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-Telegram-Init-Data": initData,
  },
  body: "{}",
});
const data = await response.json();
```

## Public routes

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Service metadata and dashboard URL. |
| GET | `/app` | Built-in Mini App dashboard. |
| GET | `/api/health` | Public health summary without webhook secrets. |
| GET | `/api/routes` | Route catalog. |
| GET | `/api/frontend/config` | Safe frontend routing configuration. |
| GET | `/api/scanner/presets?lang=km` | Localized preset catalog and allowed values. |

## Session and preferences

| Method | Endpoint | Description |
|---|---|---|
| GET/POST | `/api/bootstrap` | User, linked groups, feature flags, routes, and overview data. |
| GET/POST | `/api/session` | Validate session. |
| GET | `/api/me` | Saved/current user profile. |
| PATCH | `/api/me/preferences` | Save `{"lang":"en"}` or `{"lang":"km"}`. |
| GET | `/api/groups` | Linked groups. |

## Group policy routes

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/groups/{chat_id}/policies` | Current policy, localized presets, and allowed values. |
| PATCH | `/api/groups/{chat_id}/policies` | Update group-specific policy values. |
| POST | `/api/groups/{chat_id}/presets/{preset_id}` | Apply `standard`, `strict`, `documents`, `media`, or `custom`. |
| PATCH | `/api/groups/{chat_id}/settings` | Update existing protection/escalation settings. |

Example policy update:

```json
{
  "allowed_only": true,
  "max_file_size_mb": 20,
  "archive_policy": "block",
  "unscannable_policy": "block",
  "notification_policy": "admins_only",
  "incident_retention_days": 90,
  "policy_notes": "Only verified work documents are allowed."
}
```

Allowed policy values:

```text
archive_policy:      scan | block | allow
unscannable_policy:  block | allow
notification_policy: group_and_admins | admins_only | group_only | silent
```

Applying a preset:

```http
POST /api/groups/-1001234567890/presets/documents
X-Telegram-Init-Data: ...
Content-Type: application/json

{}
```

## Incident filtering and pagination

```http
GET /api/groups/{chat_id}/incidents
```

Query parameters:

| Parameter | Values/default |
|---|---|
| `status` | `all`, `open`, `handled`; default `all`. |
| `severity` | `all`, `low`, `medium`, `high`, `critical`; default `all`. |
| `action` | `all` or an action such as `warn`, `mute`, `ban`, `ignore`. |
| `query` | Searches sender, user ID, filename, reason, extension, and action. |
| `sender_id` | Exact Telegram sender ID. |
| `date_from_ms` | Inclusive Unix timestamp in milliseconds. |
| `date_to_ms` | Inclusive Unix timestamp in milliseconds. |
| `sort` | `newest` or `oldest`. |
| `page` | 1-based page number. |
| `page_size` | 1–100; default 25. |
| `limit` | Backward-compatible alias for `page_size`. |

Example:

```text
/api/groups/-1001234567890/incidents?status=open&severity=high&query=invoice&page=2&page_size=20&sort=newest
```

Response shape:

```json
{
  "ok": true,
  "incidents": [],
  "total": 42,
  "pagination": {
    "page": 2,
    "page_size": 20,
    "pages": 3,
    "has_next": true,
    "has_previous": true
  },
  "counts": {
    "all": 80,
    "open": 42,
    "handled": 38,
    "low": 5,
    "medium": 20,
    "high": 40,
    "critical": 15
  }
}
```

Handle an incident:

```http
POST /api/incidents/{token_or_key}/action
Content-Type: application/json
X-Telegram-Init-Data: ...

{"action":"warn"}
```

Supported actions are `warn`, `ban`, and `ignore` where Telegram permissions permit them.

## Formats and trusted files

| Method | Endpoint | Description |
|---|---|---|
| GET/POST | `/api/groups/{chat_id}/formats/allowed` | Read or append/replace allowed extensions. |
| GET/POST | `/api/groups/{chat_id}/formats/blocked` | Read or append/replace blocked extensions. |
| GET/POST | `/api/groups/{chat_id}/trusted-hashes` | List or add trusted SHA-256 hashes. |
| DELETE | `/api/groups/{chat_id}/trusted-hashes/{digest}` | Remove one trusted hash. |
| DELETE | `/api/groups/{chat_id}/trusted-hashes` | Clear all trusted hashes. |

Changing preset-controlled format or policy values marks the active preset as `custom`.

## Administration

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/groups/{chat_id}/health` | Bot permission and protection health. |
| GET | `/api/groups/{chat_id}/admins` | Administrators and private-alert readiness. |
| GET | `/api/groups/{chat_id}/admin-logs` | Administrator action history. |
| GET | `/api/groups/{chat_id}/risk` | Repeat-risk members and escalation totals. |

Developer-only endpoints remain available under `/api/developer/*` and `/api/server/log` for users listed in `BOT_OWNER_IDS`.

## Production security

- Keep `WEBHOOK_SECRET_TOKEN` different from `WEBHOOK_PATH_SECRET`.
- Keep `SERVER_LOG_AUTH_QUERY_ENABLED=false`.
- Use exact production CORS origins where a separate frontend is used. The built-in `/app` dashboard is same-origin.
- Keep local pickle persistence disabled unless the file is fully trusted.
- Never expose the Supabase service-role key, Redis signing key, bot token, or Telegram `initData` in frontend source or logs.
