# EXE Remover Security Bot v3.5 — UI and Administration

Version 3.5 builds on the v3.4 stability architecture with a complete Telegram Mini App dashboard, bilingual administration, scanner presets, group-specific policies, and scalable incident browsing.

## What is new

- Full responsive Mini App dashboard served by the backend at `/app`.
- English and Khmer interface with a saved per-user language preference.
- Group overview, live permission status, scanner policies, incidents, formats, trusted hashes, administrators, action logs, and risk users.
- Incident search, status/severity/action filters, newest/oldest sorting, and server-side pagination.
- Scanner presets: Standard, Strict, Documents Only, Media Only, and Custom.
- Group-specific maximum file size, archive handling, unscannable-file handling, notification routing, allow-list mode, policy notes, and incident retention.
- Persistence schema version 6 with automatic migration from older snapshots.
- Optimized moderation path that avoids downloading a file when group policy has already blocked it and a trusted-hash lookup is not required.

## Project layout

```text
exe_remover_bot.py                 # deployment entrypoint
exe_remover_bot_app/
  bot.py                           # Telegram moderation and orchestration
  config.py                        # environment configuration
  diagnostics.py                   # redacted in-memory diagnostics
  incidents.py                     # incident filtering and pagination
  miniapp_api.py                   # FastAPI API, dashboard, and webhook lifecycle
  policies.py                      # presets and group policy normalization
  retry.py                         # persistence retry/backoff
  scanner.py                       # filename/header/archive scanner
  schema.py                        # schema-v6 migrations and snapshot metadata
  startup.py                       # startup validation
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
6. **Administration** — administrator readiness, action logs, and repeat-risk users.

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

Snapshots now use schema 6:

```json
{
  "_meta": {
    "schema": 6,
    "revision": 1780000000000,
    "saved_at_ms": 1780000000000,
    "bot": "exe_remover_bot"
  }
}
```

Schema v5 snapshots are migrated by adding normalized scanner-policy fields to every stored group. Future unsupported schemas are rejected rather than guessed.

## Upgrade guide

See [`UPGRADE.md`](UPGRADE.md) before replacing a v3.4 deployment.

## API documentation

See [`docs/API_GUIDE.md`](docs/API_GUIDE.md) for authentication, presets, group policies, incident filters, pagination, and administration endpoints.
