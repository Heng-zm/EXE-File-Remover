# EXE Remover Security Bot v3.4 — Stability

Version 3.4 keeps the existing Telegram bot and Mini App features while splitting the previous 10,000+ line entry file into focused modules.

## Architecture

```text
exe_remover_bot.py                 # thin deployment entrypoint
exe_remover_bot_app/
  bot.py                           # Telegram handlers and orchestration
  config.py                        # environment parsing and constants
  diagnostics.py                   # bounded/redacted server logs
  miniapp_api.py                    # FastAPI routes and Telegram webhook lifecycle
  retry.py                         # exponential-backoff retry policy
  scanner.py                       # pure filename/header/archive scanner
  schema.py                        # persistence schema and migrations
  startup.py                       # preflight validation
  translations.py                  # English and Khmer UI catalogs
tests/                             # automated stability/security tests
```

## v3.4 changes

- Thin entrypoint and modular package layout.
- Persistence schema version 5 with sequential migrations from unversioned/older snapshots.
- Monotonic snapshot revisions prevent stale Redis/Supabase data from replacing newer state.
- Redis and Supabase reads/writes retry with bounded exponential backoff and jitter.
- Startup validation checks tokens, webhook URL/secrets, dependencies, persistence configuration, CORS, and unsafe log options.
- Pure scanner module can be tested without Telegram network access.
- FastAPI startup/shutdown now uses lifespan handlers instead of deprecated event hooks.
- Automated tests cover schema migration, retries, scanner regressions, startup validation, and project structure.

## Deploy

```bash
python exe_remover_bot.py
```

Copy `.env.example` into your deployment environment and replace every placeholder. Do not upload `.env` or trusted persistence files to a public repository.

## Test

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

Syntax-only validation without installing Telegram dependencies:

```bash
python -m compileall -q exe_remover_bot.py exe_remover_bot_app tests
```

## Persistence migrations

Snapshots now use:

```json
{
  "_meta": {
    "schema": 5,
    "revision": 1780000000000,
    "saved_at_ms": 1780000000000,
    "bot": "exe_remover_bot"
  }
}
```

Older snapshots are copied, migrated in memory, sanitized, and then written back in the current format. Snapshots from a future unsupported schema are rejected rather than guessed.

## Retry settings

```env
PERSISTENCE_RETRY_ATTEMPTS=4
PERSISTENCE_RETRY_BASE_DELAY_SECONDS=0.35
PERSISTENCE_RETRY_MAX_DELAY_SECONDS=5
PERSISTENCE_RETRY_JITTER_RATIO=0.20
```

Retries apply to Redis connection/load/save and Supabase load/save. Permanent Supabase 4xx errors are not repeatedly retried, except transient statuses such as 408, 409, 425, and 429.

## Startup validation

`STARTUP_VALIDATION_STRICT=true` stops startup when a critical configuration error is found. Warnings remain visible for risky but intentional configurations such as wildcard CORS or local pickle persistence.

## Detailed API documentation

See [`docs/API_GUIDE.md`](docs/API_GUIDE.md) for all Mini App routes, authentication headers, group settings, incidents, trusted hashes, logs, and frontend examples.
