# Security Policy

## Supported release

Security fixes are maintained in the newest release. Version 3.5.2 is the current hardened release in this package.

## Production security baseline

Use these settings in production:

```env
STARTUP_VALIDATION_STRICT=true
LOCAL_PERSISTENCE_ENABLED=false
REDIS_LEGACY_PICKLE_LOAD_ENABLED=false
MINI_APP_FRONTEND_DEBUG_ENABLED=false
MINI_APP_PUBLIC_DOCS_ENABLED=false
MINI_APP_PUBLIC_ROUTE_CATALOG_ENABLED=false
MINI_APP_EXPOSE_BOT_ID_PUBLICLY=false
MINI_APP_SECURITY_HEADERS_ENABLED=true
SERVER_LOG_AUTH_QUERY_ENABLED=false
SERVER_LOG_PUBLIC_ACCESS=false
SERVER_LOG_STORE_CLIENT_IP=false
SERVER_LOG_REDACT_USER_AGENT=true
```

Set an exact trusted origin in `MINI_APP_CORS_ORIGINS`. Do not use `*` in production unless the deployment genuinely requires public cross-origin access.

Generate separate high-entropy values for:

- `BOT_TOKEN`
- `WEBHOOK_SECRET_TOKEN`
- `WEBHOOK_PATH_SECRET`
- `REDIS_STATE_SIGNING_SECRET`
- `SERVER_LOG_API_KEY`, when standalone log access is enabled
- `SUPABASE_SERVICE_ROLE_KEY`

The webhook header secret and webhook URL-path secret must never be the same.

## Secret handling

Never put credentials in:

- Git commits or source ZIP files
- Mini App JavaScript
- Query-string parameters
- Screenshots or support messages
- Public health, route-catalog, or documentation responses
- Unprotected logs

Version 3.5.2 redacts known credential forms and disables high-risk public metadata by default. Redaction is a defense-in-depth control, not a substitute for keeping secrets out of logs.

## Credential rotation

Rotate a secret immediately when it may have appeared in a public endpoint, browser URL, proxy log, exception, screenshot, or shared archive.

Recommended rotation order:

1. `WEBHOOK_SECRET_TOKEN` and `WEBHOOK_PATH_SECRET`
2. `SERVER_LOG_API_KEY`
3. `BOT_TOKEN`
4. Redis credentials and `REDIS_STATE_SIGNING_SECRET`
5. `SUPABASE_SERVICE_ROLE_KEY`

After rotating Telegram webhook secrets, redeploy the bot so it registers the new webhook URL and secret header.

## State-file safety

Python pickle files can execute code while loading. Local pickle persistence is disabled by default. Never deploy a pickle state file received from an untrusted source.

Prefer Redis signed JSON or Supabase JSON storage. Keep `REDIS_LEGACY_PICKLE_LOAD_ENABLED=false`.

## Log access

Server logs must remain owner-only. Query-string authentication and public log access are rejected by strict startup validation.

When standalone log-key access is needed:

- Use a random key of at least 32 characters.
- Send it only in the supported request header.
- Do not embed it in frontend code.
- Rotate it after staff or infrastructure changes.

## Callback safety

Mutation callbacks use bounded duplicate-tap protection. The cache stores a SHA-256 fingerprint rather than the callback token itself. Failed moderation actions keep retry controls visible without exposing internal exceptions.

## Reporting a vulnerability

Do not publish active credentials, exploit payloads, private user information, Telegram `initData`, or production log output in a public issue. Share only a minimal reproduction with all secrets and personal identifiers removed. Rotate any credential included accidentally before sending the report.
