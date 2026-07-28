# Upgrade from v3.5 to v3.5.1

1. Back up the current Redis/Supabase snapshot before deployment.
2. Deploy the complete v3.5.1 project, including `workflow.py` and updated dashboard assets.
3. Keep the start command unchanged: `python exe_remover_bot.py`.
4. Keep existing environment values. Set `PROFESSIONAL_UI_VERSION=v3.5.1` when overriding the built-in label.
5. Open `/api/health`, then launch `/app` from Telegram.
6. Open **Workflow Center** and run **Synchronize now** once for each important group.

## Persistence migration

Schema v6 is migrated automatically to schema v7. The migration adds a bounded `workflow_history` list. Existing users, groups, policies, incidents, hashes, logs, and tokens remain intact.

Do not downgrade after a schema-v7 snapshot has been saved unless you restore a schema-v6 backup. Older code correctly rejects newer unknown schemas instead of guessing.

## Verification

- The dashboard shows the Workflow Center tab.
- `POST /api/groups/{chat_id}/sync` returns `group_synchronized`.
- `GET /api/groups/{chat_id}/workflows` returns recent activity.
- Group permissions and administrator readiness match Telegram.
- New blocked-file incidents include a `workflow_id`.
