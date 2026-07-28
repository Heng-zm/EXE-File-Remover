# Persistence Schema Migrations

Current schema: **6**

| Migration | Purpose |
|---|---|
| v0 → v1 | Initialize durable dictionary and list stores. |
| v1 → v2 | Normalize user IDs to integers and group IDs to strings. |
| v2 → v3 | Add durable feedback and administrator action logs. |
| v3 → v4 | Add dashboard, administrator, member, and cache stores. |
| v4 → v5 | Add monotonic snapshot revisions for stale-write protection. |
| v5 → v6 | Add normalized scanner presets and group-specific policy fields. |

The v5 → v6 migration processes every stored group settings object and adds safe defaults for:

- scanner preset
- allow-list-only mode
- maximum file size
- archive handling
- unscannable-file handling
- notification routing
- incident retention
- policy notes and update metadata

Migrations operate on a deep copy. A snapshot from a future schema is rejected instead of being interpreted with guessed rules. Redis, Supabase, and opt-in local PTB state receive the current `_meta` envelope after a successful save.
