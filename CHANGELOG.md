# Changelog

## 3.5.1

### Coordinated workflow

- Added a shared workflow engine for file moderation, incident actions, policy changes, and group synchronization.
- Added bounded stage/event history with progress, outcome, actor, source, subject, and metadata.
- Added startup recovery that marks stale running workflows as interrupted.
- Added workflow IDs to incident records and incident-action records for traceability.
- Centralized notification routing and smart escalation selection.

### Mini App and administration

- Added a bilingual Workflow Center tab with recent runs, progress bars, status counts, failure visibility, and last synchronization time.
- Added `GET /api/groups/{chat_id}/workflows`.
- Added `POST /api/groups/{chat_id}/sync` to refresh live Telegram permissions/admins and reconcile durable state.
- Added policy, preset, format, and trusted-hash changes to the same workflow activity stream.

### Reliability

- Upgraded persistence schema from v6 to v7.
- Added workflow-state reconciliation, expired-incident pruning, orphan-token cleanup, and bounded workflow retention.
- Fixed duplicate FastAPI `application.start()` execution.
- Expanded automated workflow, migration, dashboard, and authenticated API tests.

## 3.5.0

### Mini App dashboard

- Added a complete responsive dashboard at `/app` with no separate frontend build step.
- Added Telegram theme integration, mobile bottom navigation, desktop sidebar, group switching, skeleton states, toasts, and confirmation dialogs.
- Added overview, policies, incidents, formats, trusted hashes, and administration screens.
- Added safe browser fallback when Telegram `initData` is absent.

### Administration and localization

- Added persistent English/Khmer language selection through `/api/me/preferences`.
- Reworked Khmer dashboard and Telegram bot wording for clearer, more natural administration terminology.
- Added administrator readiness, action log, and repeat-risk user views.

### Policies and presets

- Added Standard, Strict, Documents Only, Media Only, and Custom scanner presets.
- Added per-group file-size limits, archive policy, unscannable-file policy, notification routing, allow-list-only mode, policy notes, and incident retention.
- Added public preset catalog and authenticated group policy APIs.
- Optimized file handling to skip unnecessary downloads when a policy decision is already final.

### Incidents

- Added server-side filtering by status, severity, action, search text, sender, and date range.
- Added newest/oldest sorting, bounded page size, pagination metadata, and summary counts.
- Added deterministic severity classification and retention helpers.

### Persistence and tests

- Upgraded persistence schema from v5 to v6 with automatic group-policy migration.
- Added policy, incident, dashboard-asset, and authenticated API integration tests.
- Validation suite increased to 28 passing tests.

## 3.4.0

- Modularized configuration, diagnostics, translations, scanner, Mini App API, schema, retry, and startup validation.
- Added schema v5 and migrations.
- Added persistence retry/backoff and startup preflight checks.
- Replaced deprecated FastAPI startup/shutdown event hooks with lifespan handling.
- Kept `python exe_remover_bot.py` as the deployment command.
