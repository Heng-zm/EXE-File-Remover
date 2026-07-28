# Persistence Schema Migrations

Current schema: **5**

| Migration | Purpose |
|---|---|
| v0 → v1 | Initialize all durable dictionaries and list stores. |
| v1 → v2 | Normalize user IDs to integers and group IDs to strings. |
| v2 → v3 | Add durable user feedback and administrator action logs. |
| v3 → v4 | Add dashboard/admin/member/cache stores. |
| v4 → v5 | Add monotonic snapshot revisions for stale-write protection. |

Migrations operate on a deep copy. A future schema is rejected instead of being interpreted with guessed rules. Redis, Supabase, and opt-in local PTB state all receive the current `_meta` envelope after a successful save.
