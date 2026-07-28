# Changelog

## 3.4.0

- Modularized configuration, diagnostics, translations, scanner, Mini App API, schema, retry, and startup validation.
- Added schema v5 and migrations.
- Added persistence retry/backoff.
- Added startup preflight checks.
- Added 17 automated regression and integration tests.
- Replaced deprecated FastAPI startup/shutdown event hooks with lifespan handling.
- Kept `python exe_remover_bot.py` as the deployment command.
