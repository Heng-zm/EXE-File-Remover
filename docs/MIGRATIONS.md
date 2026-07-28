# Persistence migrations

## Current schema: 7

The application migrates snapshots sequentially and rejects snapshots from a future unsupported schema.

### v6 → v7

- Adds `workflow_history` as a persisted list.
- Removes malformed workflow rows during migration.
- Bounds imported workflow history to the newest 500 rows.
- Preserves all existing group policies, incidents, tokens, users, hashes, feedback, caches, and admin logs.

At startup, stale `running` workflows older than the recovery window are changed to `interrupted` with outcome `process_restarted`.

## Safety

- Snapshot revision and timestamp ordering remains unchanged.
- Unsupported future schemas raise `SchemaMigrationError`.
- Migration operates on a deep copy before state replacement.
- Workflow metadata is JSON-safe and bounded.
