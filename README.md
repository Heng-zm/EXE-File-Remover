# EXE Remover Security Bot — Mini App API Guide

This README explains how to use the FastAPI REST API built into the EXE Remover Security Bot for a Telegram Mini App frontend.

The API lets your frontend auto-login with Telegram WebApp `initData`, fetch the current user profile, list linked groups, manage group scanner settings, view incidents, view risk/admin logs, send feedback, and access developer-only server logs.

---

## 1. Base URL

Use your Render service URL as the API base URL.

```txt
https://exe-file-remover.onrender.com
```

Default API prefix:

```txt
/api
```

Full API example:

```txt
https://exe-file-remover.onrender.com/api/bootstrap
```

You can change the prefix with:

```env
MINI_APP_API_PREFIX=/api
```

---

## 2. Required Environment Variables

At minimum, set these on Render:

```env
BOT_TOKEN=123456:ABC_your_telegram_bot_token
BOT_MODE=WEBHOOK
RENDER_EXTERNAL_URL=https://exe-file-remover.onrender.com
WEBHOOK_SECRET_TOKEN=use_a_long_random_secret
MINI_APP_API_ENABLED=true
BOT_OWNER_IDS=1272791365
```

Recommended optional values:

```env
MINI_APP_CORS_ORIGINS=*
MINI_APP_AUTH_MAX_AGE_SECONDS=86400
MINI_APP_REQUEST_BODY_LIMIT_BYTES=128000
MINI_APP_LIVE_REFRESH_ALLOWED=true
MINI_APP_UVICORN_ACCESS_LOG=false
SERVER_LOG_ENABLED=true
SERVER_LOG_MAX_ITEMS=1000
SERVER_LOG_CAPTURE_PYTHON_LOGS=true
SERVER_LOG_CAPTURE_HTTP_REQUESTS=true
```

Storage options:

```env
REDIS_URL=redis://...
REDIS_ENABLED=true

SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
SUPABASE_ENABLED=true
SUPABASE_TABLE=bot_state
```

Important: add your Telegram numeric ID to `BOT_OWNER_IDS`. Developer-only routes such as `/api/server/log` will return `403` if your Telegram ID is not listed there.

---

## 3. Authentication

All protected API routes use Telegram Mini App `initData`. Do **not** use `initDataUnsafe` for backend auth. The backend validates the real signed `initData` with the bot token.

Preferred frontend header:

```http
X-Telegram-Init-Data: <window.Telegram.WebApp.initData>
```

Also supported:

```http
Authorization: tma <initData>
Authorization: telegram <initData>
Authorization: bearer <initData>
```

Also accepted for convenience:

```json
{
  "initData": "<window.Telegram.WebApp.initData>"
}
```

or URL query:

```txt
/api/bootstrap?initData=<encoded-init-data>
```

Header auth is recommended because it keeps request bodies clean.

---

## 4. Telegram Mini App Frontend Fetch Helper

Use this helper in React/Vite/TypeScript.

```ts
const API_BASE = import.meta.env.VITE_API_BASE_URL || "https://exe-file-remover.onrender.com";

function getTelegramInitData(): string {
  return window.Telegram?.WebApp?.initData || "";
}

export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const initData = getTelegramInitData();

  if (!initData) {
    throw new Error("Telegram initData is missing. Open this page inside Telegram Mini App.");
  }

  const headers = new Headers(options.headers || {});
  headers.set("Content-Type", "application/json");
  headers.set("X-Telegram-Init-Data", initData);

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok || data.ok === false) {
    throw new Error(data.detail || data.message || `API request failed: ${res.status}`);
  }

  return data as T;
}
```

Use it like this:

```ts
const dashboard = await apiFetch("/api/bootstrap", { method: "POST", body: JSON.stringify({}) });
console.log(dashboard);
```

Initialize Telegram WebApp:

```ts
window.Telegram?.WebApp?.ready();
window.Telegram?.WebApp?.expand();
```

---

## 5. Public Routes

These routes do not require Telegram Mini App auth.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | API root info |
| `GET` | `/api` | API index |
| `GET` | `/api/` | API index alias |
| `GET` | `/api/routes` | Route catalog for frontend auto-wiring |
| `GET` | `/api/health` | Bot/API health and memory overview |
| `GET` | `/docs` | FastAPI Swagger docs |

Example:

```ts
const res = await fetch(`${API_BASE}/api/routes`);
const data = await res.json();
console.log(data.routes);
```

---

## 6. Session and Dashboard Routes

These routes require Telegram Mini App auth.

| Method | Endpoint | Description |
|---|---|---|
| `GET/POST` | `/api/auth/session` | Validate Telegram user and return profile/session |
| `GET/POST` | `/api/session` | Alias of auth session |
| `GET/POST` | `/api/bootstrap` | Best first call. Returns user, feature flags, routes, groups, developer info when owner |
| `GET/POST` | `/api/dashboard` | Alias of bootstrap |
| `GET` | `/api/me` | Current Telegram user and saved bot profile |
| `GET` | `/api/me/groups` | Current user’s linked groups |
| `GET` | `/api/groups` | Alias of linked groups |

Recommended first frontend call:

```ts
const data = await apiFetch("/api/bootstrap", {
  method: "POST",
  body: JSON.stringify({}),
});
```

Refresh live permission cache:

```ts
const data = await apiFetch("/api/bootstrap?refresh=true", {
  method: "POST",
  body: JSON.stringify({}),
});
```

Example response shape:

```json
{
  "ok": true,
  "user": {
    "id": 123456789,
    "first_name": "Kimheng",
    "last_name": "",
    "full_name": "Kimheng",
    "username": "hengk7401",
    "language_code": "km",
    "is_premium": false,
    "allows_write_to_pm": true,
    "photo_url": ""
  },
  "is_developer": true,
  "linked_group_count": 1,
  "groups": [],
  "features": {
    "groups": true,
    "group_settings": true,
    "incidents": true,
    "trusted_hashes": true,
    "developer_dashboard": true
  },
  "routes": {}
}
```

---

## 7. Group Routes

These routes require the Telegram user to be a verified admin of the target group, or a bot owner for developer-only workflows.

Replace `{chat_id}` with the Telegram group/supergroup ID, for example:

```txt
-1001234567890
```

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/groups/{chat_id}` | Full group details/settings snapshot |
| `PATCH` | `/api/groups/{chat_id}/settings` | Update protection/scanner settings |
| `GET` | `/api/groups/{chat_id}/health` | Group permission health check |
| `GET` | `/api/groups/{chat_id}/admins` | Group admins and alert readiness |
| `GET` | `/api/groups/{chat_id}/admin-logs` | Admin action logs |
| `GET` | `/api/groups/{chat_id}/incidents` | Incident logs |
| `GET` | `/api/groups/{chat_id}/risk` | Member risk list |

Get group detail:

```ts
const group = await apiFetch(`/api/groups/${chatId}`);
```

Refresh group detail with live Telegram checks:

```ts
const group = await apiFetch(`/api/groups/${chatId}?refresh=true`);
```

Update settings:

```ts
const updated = await apiFetch(`/api/groups/${chatId}/settings`, {
  method: "PATCH",
  body: JSON.stringify({
    protection_enabled: true,
    silent_mode: false,
    strictness: "high",
    auto_action_mode: "warn",
    auto_warn_threshold: 1,
    auto_mute_threshold: 2,
    auto_ban_threshold: 3,
    auto_mute_minutes: 60
  }),
});
```

Allowed `strictness` values:

```txt
standard
high
strict
```

Allowed `auto_action_mode` values:

```txt
off
warn
smart
ban
```

---

## 8. Formats API

Formats let a group admin configure allowed extensions or custom blocked extensions.

`kind` must be either:

```txt
allowed
blocked
```

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/groups/{chat_id}/formats/{kind}` | Get allowed or blocked extensions |
| `POST` | `/api/groups/{chat_id}/formats/{kind}` | Append or replace extensions |

Get blocked formats:

```ts
const formats = await apiFetch(`/api/groups/${chatId}/formats/blocked`);
```

Append blocked formats:

```ts
await apiFetch(`/api/groups/${chatId}/formats/blocked`, {
  method: "POST",
  body: JSON.stringify({
    mode: "append",
    extensions: [".apk", ".zip", ".jar"]
  }),
});
```

Replace allowed formats:

```ts
await apiFetch(`/api/groups/${chatId}/formats/allowed`, {
  method: "POST",
  body: JSON.stringify({
    mode: "replace",
    extensions: [".pdf", ".docx"]
  }),
});
```

Allowed `mode` values:

```txt
append
replace
```

---

## 9. Trusted Hashes API

Trusted hashes allow safe known files to bypass blocking rules when trusted hash whitelist is enabled.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/groups/{chat_id}/trusted-hashes` | List trusted hashes |
| `POST` | `/api/groups/{chat_id}/trusted-hashes` | Add a trusted hash |
| `DELETE` | `/api/groups/{chat_id}/trusted-hashes/{digest}` | Delete one trusted hash |
| `DELETE` | `/api/groups/{chat_id}/trusted-hashes` | Clear all trusted hashes |

Add trusted hash:

```ts
await apiFetch(`/api/groups/${chatId}/trusted-hashes`, {
  method: "POST",
  body: JSON.stringify({
    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }),
});
```

Delete trusted hash:

```ts
await apiFetch(`/api/groups/${chatId}/trusted-hashes/${digest}`, {
  method: "DELETE",
});
```

Clear all trusted hashes:

```ts
await apiFetch(`/api/groups/${chatId}/trusted-hashes`, {
  method: "DELETE",
});
```

---

## 10. Incidents API

View and act on blocked-file incidents.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/groups/{chat_id}/incidents?status=all&limit=50` | List group incidents |
| `POST` | `/api/incidents/{token_or_key}/action` | Ban, warn, or ignore incident |

Allowed incident `status` values:

```txt
all
open
handled
```

Get open incidents:

```ts
const incidents = await apiFetch(`/api/groups/${chatId}/incidents?status=open&limit=50`);
```

Handle an incident:

```ts
await apiFetch(`/api/incidents/${incidentToken}/action`, {
  method: "POST",
  body: JSON.stringify({
    action: "warn"
  }),
});
```

Typical actions:

```txt
ban
warn
ignore
```

---

## 11. Scanner Tool API

Use this to test whether a filename would be blocked.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan/name` | Scan a filename and MIME type |

Example:

```ts
const scan = await apiFetch("/api/scan/name", {
  method: "POST",
  body: JSON.stringify({
    file_name: "invoice.pdf.exe",
    mime_type: "application/octet-stream"
  }),
});
```

Example response:

```json
{
  "ok": true,
  "user_id": 123456789,
  "scan": {
    "blocked": true,
    "reason_code": "blocked_extension",
    "reason_display": "Blocked extension .exe",
    "details": [],
    "file_name": "invoice.pdf.exe",
    "mime_type": "application/octet-stream",
    "matched_extension": ".exe",
    "file_sha256": ""
  }
}
```

---

## 12. Feedback API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/feedback` | Save user feedback for developer dashboard |

Example:

```ts
await apiFetch("/api/feedback", {
  method: "POST",
  body: JSON.stringify({
    text: "Dashboard looks good, but group loading is slow."
  }),
});
```

Feedback text must be at least 5 characters.

---

## 13. Server Logs API

Server logs are developer-only. The Telegram user must be in `BOT_OWNER_IDS`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/server/log` | Read server/API logs |
| `GET` | `/api/server/logs` | Alias |
| `DELETE` | `/api/server/log` | Clear server logs |
| `DELETE` | `/api/server/logs` | Clear alias |

Read logs:

```ts
const logs = await apiFetch("/api/server/log?limit=200&level=all&category=all&since_id=0");
console.log(logs.logs);
```

Filter by level:

```ts
const errors = await apiFetch("/api/server/log?level=error&limit=100");
```

Filter by category:

```ts
const apiErrors = await apiFetch("/api/server/log?category=http_error&limit=100");
```

Incremental polling:

```ts
let lastId = 0;

async function pollLogs() {
  const data = await apiFetch(`/api/server/log?since_id=${lastId}&limit=100`);
  for (const row of data.logs) {
    lastId = Math.max(lastId, row.id);
  }
  return data.logs;
}
```

Clear logs:

```ts
await apiFetch("/api/server/log", {
  method: "DELETE",
});
```

Server log response shape:

```json
{
  "ok": true,
  "logs": [
    {
      "id": 1,
      "ts": "2026-06-19T07:00:00+00:00",
      "ts_ms": 1780000000000,
      "category": "http",
      "level": "info",
      "message": "api request completed",
      "method": "GET",
      "path": "/api/bootstrap",
      "status": 200,
      "duration_ms": 20.5,
      "request_id": "abc123"
    }
  ],
  "total": 1,
  "filters": {
    "limit": 200,
    "level": "all",
    "category": "all",
    "since_id": 0
  },
  "counters": {},
  "process": {},
  "routes": {
    "self": "/api/server/log",
    "clear": "/api/server/log"
  }
}
```

Security notes:

- Logs redact `initData`, authorization headers, tokens, secrets, service-role keys, and Telegram hashes.
- Only `BOT_OWNER_IDS` can read or clear server logs.
- Do not expose server logs to normal group admins or public users.

---

## 14. Developer Routes

Developer routes require `BOT_OWNER_IDS`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/developer/overview` | Bot memory/storage overview |
| `GET` | `/api/developer/users?limit=100` | Recent known users |
| `GET` | `/api/developer/groups?limit=200` | Developer group overview |
| `GET` | `/api/developer/feedback?limit=100` | User feedback |
| `GET` | `/api/developer/runtime-config` | Runtime scanner/hash config |
| `PATCH` | `/api/developer/runtime-config` | Update runtime scanner/hash config |
| `GET` | `/api/server/log` | Server/API logs |

Get runtime config:

```ts
const config = await apiFetch("/api/developer/runtime-config");
```

Update runtime config:

```ts
await apiFetch("/api/developer/runtime-config", {
  method: "PATCH",
  body: JSON.stringify({
    trusted_file_hash_whitelist_enabled: true,
    trusted_hash_max_download_bytes: 20000000,
    max_trusted_file_hashes: 128
  }),
});
```

---

## 15. Error Responses

FastAPI usually returns errors like this:

```json
{
  "detail": "missing Telegram Mini App initData"
}
```

Common status codes:

| Status | Meaning | Fix |
|---|---|---|
| `400` | Bad request body or invalid parameter | Check JSON payload |
| `401` | Missing/invalid/expired Telegram `initData` | Open inside Telegram Mini App and send `X-Telegram-Init-Data` |
| `403` | Not allowed | User must be group admin or in `BOT_OWNER_IDS` |
| `404` | Resource not found | Check route, group ID, incident token, or hash digest |
| `413` | Body too large | Reduce request body size |
| `500` | Server error | Check Render logs or `/api/server/log` as owner |

Recommended frontend error handler:

```ts
try {
  const data = await apiFetch("/api/bootstrap", { method: "POST", body: JSON.stringify({}) });
  console.log(data);
} catch (err) {
  console.error(err);
  alert(err instanceof Error ? err.message : "API error");
}
```

---

## 16. CORS for Frontend

For local Vite development and deployment, set:

```env
MINI_APP_CORS_ORIGINS=*
```

For stricter production security, set exact origins separated by commas:

```env
MINI_APP_CORS_ORIGINS=https://your-mini-app.vercel.app,https://your-domain.com
```

The API supports these frontend headers:

```txt
Content-Type
Authorization
X-Telegram-Init-Data
X-Telegram-Web-App-Data
X-TMA-Init-Data
Telegram-Init-Data
```

---

## 17. Render Deployment

Use a single Render Web Service that runs the bot webhook and API together.

Recommended start command:

```bash
python exe_remover_bot_miniapp_api_server_log.py
```

Make sure these environment variables are set:

```env
PORT=10000
BOT_TOKEN=your_bot_token
BOT_MODE=WEBHOOK
RENDER_EXTERNAL_URL=https://your-render-service.onrender.com
WEBHOOK_SECRET_TOKEN=long_random_secret
MINI_APP_API_ENABLED=true
BOT_OWNER_IDS=your_telegram_user_id
```

After deployment, test:

```txt
https://your-render-service.onrender.com/
https://your-render-service.onrender.com/api/health
https://your-render-service.onrender.com/api/routes
```

---

## 18. Telegram Mini App Setup

In BotFather:

1. Open `@BotFather`.
2. Select your bot.
3. Use `/newapp` or Mini App settings.
4. Set the Mini App URL to your frontend URL, for example:

```txt
https://your-mini-app.vercel.app
```

The frontend should call your Render API URL:

```env
VITE_API_BASE_URL=https://exe-file-remover.onrender.com
```

---

## 19. Quick Frontend Test Component

```tsx
import { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "https://exe-file-remover.onrender.com";

async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const initData = window.Telegram?.WebApp?.initData || "";
  const headers = new Headers(options.headers || {});
  headers.set("Content-Type", "application/json");
  headers.set("X-Telegram-Init-Data", initData);

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) {
    throw new Error(data.detail || data.message || `HTTP ${res.status}`);
  }
  return data as T;
}

export function ApiTest() {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    window.Telegram?.WebApp?.ready();
    window.Telegram?.WebApp?.expand();

    apiFetch("/api/bootstrap", {
      method: "POST",
      body: JSON.stringify({}),
    })
      .then(setData)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, []);

  if (error) return <pre>{error}</pre>;
  if (!data) return <p>Loading...</p>;

  return <pre>{JSON.stringify(data, null, 2)}</pre>;
}
```

---

## 20. Troubleshooting

### `401 missing Telegram Mini App initData`

Cause: frontend is opened outside Telegram, or the request did not include `X-Telegram-Init-Data`.

Fix:

```ts
headers.set("X-Telegram-Init-Data", window.Telegram.WebApp.initData);
```

### `401 invalid Telegram initData signature`

Cause: wrong `BOT_TOKEN`, modified `initData`, or sending `initDataUnsafe` instead of signed `initData`.

Fix:

- Use the same bot token that owns the Mini App.
- Send `window.Telegram.WebApp.initData` exactly as received.
- Do not JSON-stringify or decode/rebuild the initData manually.

### `401 expired Telegram initData`

Cause: `auth_date` is older than `MINI_APP_AUTH_MAX_AGE_SECONDS`.

Fix:

- Reopen the Mini App from Telegram.
- Increase `MINI_APP_AUTH_MAX_AGE_SECONDS` if needed.

### `403 Forbidden` on group routes

Cause: user is not a group admin or the group is not linked.

Fix:

- Add the bot to the group as admin.
- Open the bot in private chat.
- Use `/settings` or dashboard linking flow.
- Make sure the current Telegram user is an admin of that group.

### `403 Forbidden` on `/api/server/log`

Cause: your Telegram ID is not in `BOT_OWNER_IDS`.

Fix:

```env
BOT_OWNER_IDS=1272791365
```

Restart Render after changing environment variables.

### Frontend CORS error

Fix for development:

```env
MINI_APP_CORS_ORIGINS=*
```

Fix for production:

```env
MINI_APP_CORS_ORIGINS=https://your-frontend-domain.com
```

### `404 Not Found`

Check the API prefix. Default is `/api`.

Correct:

```txt
/api/bootstrap
```

Wrong:

```txt
/bootstrap
```

---

## 21. Recommended Frontend Flow

1. Call `/api/bootstrap` when the Mini App opens.
2. Show user profile from `data.user`.
3. Show linked groups from `data.groups`.
4. For each group, call `/api/groups/{chat_id}` when opened.
5. Use `/api/groups/{chat_id}/settings` to save toggles.
6. Use `/api/groups/{chat_id}/incidents` for incident history.
7. If `data.is_developer === true`, show developer pages and `/api/server/log`.

---

## 22. API Checklist

Before using the frontend, confirm:

- Bot is deployed on Render.
- `BOT_TOKEN` is correct.
- `BOT_MODE=WEBHOOK`.
- `RENDER_EXTERNAL_URL` is correct.
- `MINI_APP_API_ENABLED=true`.
- Frontend is opened inside Telegram Mini App.
- Frontend sends `X-Telegram-Init-Data`.
- Group routes are used only by group admins.
- Developer routes are used only by users listed in `BOT_OWNER_IDS`.

---

## 23. Useful URLs

Replace the domain with your Render URL.

```txt
Root:          https://exe-file-remover.onrender.com/
Health:        https://exe-file-remover.onrender.com/api/health
Routes:        https://exe-file-remover.onrender.com/api/routes
Bootstrap:     https://exe-file-remover.onrender.com/api/bootstrap
Server logs:   https://exe-file-remover.onrender.com/api/server/log
Swagger docs:  https://exe-file-remover.onrender.com/docs
```
