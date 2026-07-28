# v3.5 Validation Report

- Python compilation: passed for the entrypoint, package modules, and tests.
- Automated tests: **28 passed**.
- JavaScript syntax: passed for `api.js`, `i18n.js`, and `app.js` using Node syntax checks.
- Runtime construction: Telegram application builder completed using interface-compatible Telegram stubs.
- Mini App construction: FastAPI application constructed 67 routes and mounted the static dashboard successfully.
- Public routes: root, health, route catalog, dashboard HTML/assets, and scanner preset catalog tested.
- Authentication: signed Telegram Mini App `initData` accepted; protected routes exercised with an authenticated owner principal.
- Group policies: preset retrieval/application, custom policy updates, normalization, and preset detection tested.
- Incidents: status/severity/action/search filters, sorting, pagination, counts, and retention tested.
- Scanner: executable names, hidden extensions, PE headers, normal ZIP folders, dangerous ZIP members, member limits, Unicode tricks, group policies, and unscannable files tested.
- Persistence: schema v0-v6 migrations, future-schema rejection, revisions, local metadata, retry behavior, and stale-snapshot ordering tested.
- Lifecycle: FastAPI lifespan, webhook registration, public route responses, and shutdown paths executed in integration tests.
- Packaging: wheel build passed; the thin entrypoint and all five static dashboard assets are included as package data.

The sandbox package index did not provide `python-telegram-bot==21.5`. Integration tests therefore use interface-compatible Telegram stubs while exercising the real FastAPI application, signed authentication logic, route handlers, policy engine, scanner, and persistence code. Production installation remains pinned in `requirements.txt`.
