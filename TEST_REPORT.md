# v3.4 Validation Report

- Python compilation: passed for entrypoint, package modules, and tests.
- Automated tests: 17 passed.
- Runtime integration: application builder completed using Telegram-compatible stubs.
- Mini App integration: 56 FastAPI routes constructed; public root, health, route catalog, and unauthenticated bootstrap returned expected responses.
- Lifespan integration: startup, webhook registration, and shutdown paths executed in tests.
- Persistence: schema v0-v5 migrations, future-schema rejection, monotonic revisions, local metadata, retry success/failure, and stale snapshot ordering tested.
- Scanner: direct executable, hidden archive suffix, PE header, safe ZIP folders, dangerous ZIP members, archive member limits, and Unicode tricks tested.
- Startup validation: valid configuration, reused secrets, and memory-only warnings tested.

The sandbox package index did not provide `python-telegram-bot==21.5`, so the full Telegram library could not be installed here. The runtime integration tests use interface-compatible stubs; deploy-time installation remains defined in `requirements.txt`.
