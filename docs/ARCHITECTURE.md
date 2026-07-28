# v3.4 Architecture

The previous single deployment file has been replaced by a five-line entrypoint and a package of focused modules.

- `bot.py`: Telegram moderation, dashboards, handlers, persistence orchestration, and application construction.
- `miniapp_api.py`: Telegram Web App authentication, FastAPI routes, middleware, webhook lifecycle, and developer API.
- `scanner.py`: pure filename, magic-header, and ZIP-member scanner.
- `schema.py`: durable state contract and sequential migrations.
- `retry.py`: bounded async exponential backoff with jitter.
- `startup.py`: side-effect-free startup preflight validation.
- `config.py`: environment parsing only; it no longer crashes during import.
- `diagnostics.py`: redacted in-memory operational logs and process status.
- `translations.py`: English and Khmer UI catalogs.

The Mini App module currently uses a compatibility bridge to mature runtime services in `bot.py`. Mutable status scalars are read dynamically from the runtime module, preventing stale values after startup.
