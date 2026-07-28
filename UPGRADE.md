# Upgrade to v3.5.2

## 1. Back up state

Back up the current Redis/Supabase state before replacing the application. Schema version 7 is unchanged, so no destructive migration is required.

## 2. Replace the source

Keep the existing deployment command:

```bash
python exe_remover_bot.py
```

## 3. Add secure defaults

Add or verify:

```env
PROFESSIONAL_UI_VERSION=v3.5.2
MINI_APP_FRONTEND_DEBUG_ENABLED=false
MINI_APP_PUBLIC_DOCS_ENABLED=false
MINI_APP_PUBLIC_ROUTE_CATALOG_ENABLED=false
MINI_APP_EXPOSE_BOT_ID_PUBLICLY=false
MINI_APP_SECURITY_HEADERS_ENABLED=true
SERVER_LOG_AUTH_QUERY_ENABLED=false
SERVER_LOG_PUBLIC_ACCESS=false
SERVER_LOG_STORE_CLIENT_IP=false
SERVER_LOG_REDACT_USER_AGENT=true
CALLBACK_DEDUP_WINDOW_SECONDS=1.5
```

Use an exact Mini App origin rather than `*` where possible.

## 4. Rotate potentially exposed credentials

Rotate a credential when an earlier deployment printed or returned it in a public endpoint, exception, proxy log, screenshot, or browser URL. Prioritize:

1. `WEBHOOK_SECRET_TOKEN` and `WEBHOOK_PATH_SECRET`
2. `SERVER_LOG_API_KEY`
3. `BOT_TOKEN`
4. Redis credentials and `REDIS_STATE_SIGNING_SECRET`
5. `SUPABASE_SERVICE_ROLE_KEY`

Keep the webhook header secret and URL path secret different.

## 5. Verify callback behavior

From a private chat:

- Rapidly tap a protection toggle; it should change once.
- Trigger Refresh; Telegram should immediately show a loading acknowledgement.
- Test Ban/Warn without the required permission; the incident panel should remain visible with retry buttons.
- Tap an old button; the bot should explain that the panel is outdated.

## 6. Verify public privacy

Confirm:

```text
GET /docs          → 404
GET /openapi.json  → 404
GET /api/routes    → public routes only
GET /api/health    → no webhook path, secrets, or public bot ID by default
```

Authenticated owners still receive developer routes through the signed Mini App bootstrap payload.
