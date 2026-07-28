# Coordinated Workflow Guide

Version 3.5.1 uses one shared workflow model for Telegram moderation, Mini App administration, policy changes, and state synchronization. This removes duplicated decisions between the bot and dashboard and gives administrators one traceable history.

## File moderation lifecycle

A blocked-file workflow moves through these stages:

1. `received` — Telegram update accepted.
2. `policy_evaluated` — protection, bypass, group preset, size, archive, and allow-list rules resolved.
3. `scanned` — filename, MIME type, magic bytes, archive names, and trusted hash checks completed when required.
4. `deleted` — the prohibited Telegram message removed.
5. `incident_recorded` — one durable incident linked to the workflow ID.
6. `auto_action` — shared escalation policy selects none, warn, mute, or ban.
7. `notifications` — the shared notification policy routes the result to the group, administrators, both, or neither.
8. `completed` — the final outcome and delivery report recorded.

A failure is recorded at the exact stage where it occurred. Stale running workflows are marked `interrupted` during the next startup instead of remaining permanently active.

## Other workflow kinds

- `incident_action` records a manual warn, ban, or ignore action from the Mini App or Telegram callback.
- `policy_update` records preset, policy, format, and trusted-hash changes.
- `group_sync` refreshes Telegram permissions and administrators, normalizes group policies, prunes expired incidents, removes orphan incident tokens, and refreshes dashboard counters.

## Workflow Center

Open **Workflow Center** in the Mini App to see:

- running, completed, failed, and interrupted counts;
- the current stage and progress percentage;
- event-level details for recent workflows;
- the last synchronization report;
- a manual **Synchronize now** action.

The API endpoints are:

```text
GET  /api/groups/{chat_id}/workflows
POST /api/groups/{chat_id}/sync
```

Useful workflow filters:

```text
?kind=file_moderation&status=failed&limit=50&include_events=true
```

## Telegram synchronization

Running `/status` inside a group now performs a live permission refresh and state reconciliation before showing the result. The Mini App synchronization action uses the same reconciliation function, so both surfaces report the same policy preset, incident counts, permissions, and workflow status.

## Persistence

Workflow history is stored in schema version 7 under `workflow_history`. History and per-workflow event counts are bounded by:

```env
WORKFLOW_HISTORY_MAX_ITEMS=500
WORKFLOW_EVENT_MAX_ITEMS=24
WORKFLOW_STALE_SECONDS=900
```

These values prevent unbounded memory and snapshot growth while retaining recent operational evidence.

## Troubleshooting

- **Workflow remains running:** restart recovery marks workflows older than `WORKFLOW_STALE_SECONDS` as interrupted.
- **Dashboard and Telegram disagree:** use **Synchronize now** or `/status` in the group.
- **Notifications are missing:** inspect the workflow `notifications` event and the group `notification_policy`.
- **Automatic action differs from expected:** inspect the incident count and the shared auto-action thresholds in the workflow event data.
- **Old incidents remain visible:** synchronize the group to apply its `incident_retention_days` policy immediately.
