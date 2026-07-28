# Changelog

## 3.5.2 — Security and callback UX

### Leak prevention

- Expanded secret redaction to cover Telegram `initData`, authorization schemes, JSON/form credentials, bot-token patterns, Redis credentials, URL query strings, webhook path secrets, API keys, passwords, and service-role keys.
- Replaced raw client IP logging with a stable keyed fingerprint by default.
- Redacted user-agent values by default to reduce browser/device fingerprinting.
- Disabled public Swagger, ReDoc, and OpenAPI endpoints by default.
- Reduced the unauthenticated route catalog to public bootstrap and scanner metadata only.
- Removed public developer/server-log route disclosure and public bot ID exposure by default.
- Added API security headers and `Cache-Control: no-store` for API responses.
- Changed public server logs and query-string log keys from startup warnings to strict validation errors.
- Added minimum strength validation for standalone server-log API keys.

### Friendly and reliable callbacks

- Added immediate bilingual callback feedback for opening, loading, refreshing, saving, and incident actions.
- Added duplicate-tap protection so rapid button presses cannot toggle a setting twice.
- Fingerprinted callback actions instead of retaining callback tokens in the deduplication cache.
- Improved stale/invalid button guidance and private-chat security messages.
- Preserved incident details when another admin already handled an action.
- Kept Ban/Warn/Ignore buttons available after a failed action so an admin can fix permissions and retry.
- Replaced translation-string comparisons with explicit action-success state.
- Added user-facing error references while keeping internal exception details only in protected logs.

### Validation

- Added security regression tests for nested redaction, URL credentials, authorization headers, client privacy, public route minimization, security headers, startup guards, callback deduplication, and bilingual callback text.
- Validation suite increased to 40 passing tests.

## 3.5.1 — Coordinated workflow

- Added a shared workflow engine for moderation, incidents, policy changes, and synchronization.
- Added a bilingual Workflow Center and group synchronization APIs.
- Upgraded persistence schema to version 7 with bounded workflow history and interrupted-work recovery.
- Centralized notification routing and smart escalation selection.

## 3.5.0 — UI and administration

- Added the responsive Mini App dashboard, bilingual administration, incident filters and pagination, scanner presets, and group-specific policies.
- Upgraded persistence schema to version 6.

## 3.4.0 — Stability

- Modularized configuration, diagnostics, translations, scanner, Mini App API, schema, retry, and startup validation.
- Added schema migrations, persistence retry/backoff, and startup preflight checks.
