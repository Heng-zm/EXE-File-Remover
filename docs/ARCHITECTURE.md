# v3.5 Architecture

The application uses a thin deployment entrypoint and focused Python modules.

- `bot.py`: Telegram moderation, handler registration, group state, incident actions, and persistence orchestration.
- `miniapp_api.py`: Telegram Web App authentication, REST routes, static dashboard mounting, middleware, webhook lifecycle, and developer APIs.
- `policies.py`: scanner presets, allowed policy values, normalization, and preset detection/application.
- `incidents.py`: side-effect-free severity calculation, filtering, sorting, pagination, counts, and retention pruning.
- `scanner.py`: pure filename, MIME, magic-header, and ZIP-member inspection.
- `schema.py`: durable state contract, schema-v6 migrations, revisions, and snapshot sanitation.
- `retry.py`: bounded asynchronous exponential backoff with jitter.
- `startup.py`: side-effect-free startup preflight validation.
- `config.py`: environment parsing and typed constants.
- `diagnostics.py`: redacted bounded process/API logs.
- `translations.py`: Telegram English and Khmer UI catalogs.
- `static/`: self-contained dashboard HTML, CSS, JavaScript API client, and bilingual catalog.

## Request flow

```text
Telegram group message
  -> Telegram handler
  -> shared scanner
  -> group-specific policy engine
  -> delete/notify/escalate
  -> incident + risk state
  -> debounced durable persistence

Telegram Mini App
  -> /app static dashboard
  -> signed initData header
  -> FastAPI authentication
  -> admin authorization
  -> policy/incident/admin APIs
  -> durable state update
```

## Policy precedence

1. Core dangerous filename, MIME, magic-header, and archive detections.
2. Trusted SHA-256 exception where enabled and safe to evaluate.
3. Group maximum file size.
4. Group archive and unscannable-file rules.
5. Custom blocked formats.
6. Allow-list-only formats.
7. Strictness and automatic escalation.

Core executable detections are deliberately evaluated before configurable allow-list behavior.

## Frontend model

The dashboard uses browser-native ES modules and is served directly by FastAPI. It has no Node build step, no external state store, and no client-side secrets. Every protected request sends Telegram’s signed `initData`; authorization is enforced again on the server.
