# EXE Remover Security Bot v3.5.2 — Security and Friendly Callbacks

Version 3.5.2 hardens the Telegram bot and Mini App against credential and metadata leaks while making inline-button actions clearer, safer, and easier to retry. It includes every v3.5.1 workflow, administration, scanner, and dashboard feature.

## What is new

### Security hardening

- Redacts secrets from URLs, JSON, forms, authorization headers, Telegram `initData`, Redis connections, service-role keys, webhook paths, and diagnostic tracebacks.
- Stores privacy-safe client fingerprints instead of raw IP addresses by default.
- Redacts user-agent metadata by default.
- Disables public Swagger/ReDoc/OpenAPI pages and the full public route catalog by default.
- Hides the bot numeric ID and developer/server-log routes from unauthenticated responses.
- Adds secure response headers and disables API response caching.
- Rejects public server logs, query-string log keys, and weak server-log API keys during strict startup validation.

### Callback and reply UX

- Shows immediate English/Khmer feedback such as “Loading…”, “Saving changes…”, and “Applying action…”.
- Prevents rapid duplicate taps from toggling settings twice.
- Gives clear guidance for outdated buttons and private-only settings.
- Keeps incident action buttons available when Ban or Warn fails, allowing an admin to fix permissions and retry.
- Keeps incident details visible when another administrator has already handled the event.
- Shows a short error reference to the user while keeping technical details inside protected diagnostics.

### Existing v3.5 workflow and administration

- Coordinated moderation workflow and Workflow Center.
- Full responsive Mini App at `/app`.
- English and Khmer interface.
- Incident filters, search, pagination, and actions.
- Scanner presets and group-specific policies.
- Redis/Supabase persistence, schema migrations, retries, and startup validation.

## Project layout

```text
exe_remover_bot.py                 # deployment entrypoint
exe_remover_bot_app/
  bot.py                           # Telegram handlers and moderation runtime
  callback_ux.py                   # duplicate-tap protection without retaining callback tokens
  config.py                        # environment configuration
  diagnostics.py                   # redacted in-memory diagnostics
  incidents.py                     # incident filtering and pagination
  miniapp_api.py                   # FastAPI API, dashboard, and webhook lifecycle
  policies.py                      # presets and group policy normalization
  retry.py                         # persistence retry/backoff
  scanner.py                       # filename/header/archive scanner
  schema.py                        # schema-v7 migrations and snapshot metadata
  startup.py                       # startup validation
  workflow.py                      # shared workflow state, escalation, reconciliation
  translations.py                  # Telegram English/Khmer messages
  static/
    index.html                     # Mini App shell
    app.js                         # dashboard screens and interactions
    api.js                         # Telegram-authenticated API client
    i18n.js                        # complete dashboard English/Khmer catalog
    styles.css                     # responsive Telegram-aware UI

tests/                             # automated unit and integration tests
```

## Deploy

The command is unchanged:

```bash
python exe_remover_bot.py
```

Set the Mini App URL in BotFather to:

```text
https://your-service.onrender.com/app
```

The backend serves both the Telegram webhook/API and the dashboard, so a separate Vercel or frontend build is not required.

Copy `.env.example` into your deployment environment and replace every placeholder. Never commit a real `.env`, bot token, service-role key, webhook secret, or persistence file.

## Security deployment checklist

Keep these production values:

```env
MINI_APP_FRONTEND_DEBUG_ENABLED=false
MINI_APP_PUBLIC_DOCS_ENABLED=false
MINI_APP_PUBLIC_ROUTE_CATALOG_ENABLED=false
MINI_APP_EXPOSE_BOT_ID_PUBLICLY=false
SERVER_LOG_AUTH_QUERY_ENABLED=false
SERVER_LOG_PUBLIC_ACCESS=false
SERVER_LOG_STORE_CLIENT_IP=false
SERVER_LOG_REDACT_USER_AGENT=true
LOCAL_PERSISTENCE_ENABLED=false
REDIS_LEGACY_PICKLE_LOAD_ENABLED=false
```

Use exact production origins in `MINI_APP_CORS_ORIGINS`. Generate independent random values for `WEBHOOK_SECRET_TOKEN`, `WEBHOOK_PATH_SECRET`, `REDIS_STATE_SIGNING_SECRET`, and any `SERVER_LOG_API_KEY`. Never place a server-log key in frontend JavaScript or a URL query parameter.

After upgrading from a build that may have exposed a secret in public health output or logs, rotate the affected webhook secret, API key, bot token, Redis credentials, or Supabase service-role key before redeploying.

## Dashboard

Open the deployed dashboard at:

```text
https://your-service.onrender.com/app
```

Private group data is shown only when the page is launched as a Telegram Mini App with valid signed `initData`. Opening `/app` in a normal browser shows a safe “Open in Telegram” state.

Dashboard sections:

1. **Overview** — protection health, permissions, active preset, incidents, and storage status.
2. **Policies** — apply presets and customize rules per group.
3. **Incidents** — filter, search, paginate, warn, ban, or ignore.
4. **Formats** — manage allowed and blocked extensions.
5. **Trusted files** — add or remove verified SHA-256 hashes.
6. **Workflow Center** — coordinated processing stages, status, progress, failures, and group synchronization.
7. **Administration** — administrator readiness, action logs, and repeat-risk users.

## Scanner presets

| Preset | Intended use |
|---|---|
| Standard | Balanced protection for general groups. |
| Strict | Blocks archives and unscannable files with stronger enforcement. |
| Documents Only | Allows approved document formats and blocks archives. |
| Media Only | Allows approved media formats and blocks archives. |
| Custom | Uses administrator-defined policy and format rules. |

Applying a preset updates the relevant group settings. Editing an individual preset-controlled value automatically marks the group policy as `custom`.

## Group-specific policies

Each group can independently configure:

- `allowed_only`
- `max_file_size_bytes` / dashboard `max_file_size_mb`
- `archive_policy`: `scan`, `block`, or `allow`
- `unscannable_policy`: `block` or `allow`
- `notification_policy`: `group_and_admins`, `admins_only`, `group_only`, or `silent`
- `incident_retention_days`
- `policy_notes`
- existing strictness, automatic action, administrator enforcement, format lists, and trusted hashes

Core executable detections remain protected and cannot be neutralized by an allow-list entry.

## Test

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

Additional syntax checks:

```bash
python -m compileall -q exe_remover_bot.py exe_remover_bot_app tests
node --check exe_remover_bot_app/static/api.js
node --check exe_remover_bot_app/static/i18n.js
node --check exe_remover_bot_app/static/app.js
```

## Persistence schema

Snapshots continue to use schema 7:

```json
{
  "_meta": {
    "schema": 7,
    "revision": 1780000000000,
    "saved_at_ms": 1780000000000,
    "bot": "exe_remover_bot"
  }
}
```

Schema v6 snapshots are migrated by adding a bounded `workflow_history` store. Running workflows that were left stale by a process restart are marked as interrupted during startup. Future unsupported schemas are rejected rather than guessed.

## Upgrade guide

See [`UPGRADE.md`](UPGRADE.md) before replacing a v3.5.1 or older deployment. Review [`SECURITY.md`](SECURITY.md) before configuring production credentials or diagnostic access.

## API documentation

See [`docs/API_GUIDE.md`](docs/API_GUIDE.md) for authentication, presets, policies, incident filters, workflow history, synchronization, and administration endpoints. See [`docs/WORKFLOW_GUIDE.md`](docs/WORKFLOW_GUIDE.md) for the coordinated moderation lifecycle and troubleshooting steps.
