# Upgrade from v3.4 to v3.5

1. Back up the current Redis/Supabase state.
2. Deploy the complete v3.5 project; do not copy only `bot.py`.
3. Keep the existing start command: `python exe_remover_bot.py`.
4. Keep all existing v3.4 environment values. Optionally set `PROFESSIONAL_UI_VERSION=v3.5`.
5. Set the BotFather Mini App URL to `https://your-service.onrender.com/app`.
6. Restart the service and open `/api/health`.
7. Launch the Mini App from Telegram and verify each linked group.
8. Review the automatically migrated Standard policy before applying stricter presets.

The first successful state load automatically migrates schema v5 snapshots to schema v6. The migration adds missing policy fields without deleting existing group settings, incidents, trusted hashes, formats, users, or administrator logs.

Recommended post-upgrade checks:

- Bot can delete messages in every protected group.
- Administrators who need direct alerts have started the bot privately.
- Incident filters and pagination return expected records.
- Group notification policy matches your moderation workflow.
- Documents Only or Media Only presets have the intended allow-list extensions.
- Redis/Supabase shows a successful schema-v6 save.
