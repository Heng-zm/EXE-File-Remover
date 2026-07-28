# v3.5.1 Architecture

The application uses a thin deployment entrypoint and focused Python modules.

- `bot.py`: Telegram handlers, moderation runtime, message delivery, persistence orchestration, and lifecycle.
- `miniapp_api.py`: Telegram Web App authentication, REST routes, static dashboard, middleware, webhook lifecycle, and developer APIs.
- `workflow.py`: shared workflow stages, bounded history, escalation selection, notification routing, interrupted-run recovery, and group-state reconciliation.
- `policies.py`: scanner presets, allowed policy values, normalization, and preset detection/application.
- `incidents.py`: severity calculation, filtering, sorting, pagination, counts, and retention helpers.
- `scanner.py`: pure filename, MIME, magic-header, and ZIP-member inspection.
- `schema.py`: durable state contract, schema-v7 migrations, revisions, and snapshot sanitation.
- `retry.py`: bounded asynchronous exponential backoff with jitter.
- `startup.py`: side-effect-free startup preflight validation.
- `config.py`: environment parsing and typed constants.
- `diagnostics.py`: redacted bounded process/API logs.
- `translations.py`: Telegram English and Khmer UI catalogs.
- `static/`: self-contained dashboard HTML, CSS, JavaScript API client, and bilingual catalog.

## Coordinated moderation flow

```text
Telegram group document
  -> begin file_moderation workflow
  -> filename/MIME pre-scan
  -> group policy evaluation
  -> optional byte/hash scan
  -> delete blocked message
  -> create incident with workflow_id
  -> shared automatic-action selection
  -> shared notification routing
  -> record delivery report
  -> complete and persist workflow
```

Every stage is recorded in one bounded workflow record. Failures retain the last successful stage and a normalized error outcome. A process restart marks stale running workflows as `interrupted` instead of leaving them indefinitely active.

## Administration flow

```text
Telegram Mini App request
  -> signed initData authentication
  -> group-admin authorization
  -> shared mutation or incident action
  -> admin audit record
  -> policy_update / incident_action workflow
  -> durable persistence
  -> synchronized group snapshot response
```

Policy, preset, format, and trusted-hash changes appear in the same workflow stream as moderation activity.

## Group synchronization

`POST /api/groups/{chat_id}/sync` performs one coordinated reconciliation:

1. Verify the requesting administrator.
2. Refresh Telegram administrator and bot-permission caches.
3. Normalize group settings and preset detection.
4. Apply incident retention and remove malformed/expired incidents.
5. Remove orphan incident-action tokens.
6. Refresh workflow counters and group sync metadata.
7. Persist the reconciled snapshot.

The Mini App Workflow Center presents the same report returned by the API.

## Policy precedence

1. Core dangerous filename, MIME, magic-header, and archive detections.
2. Trusted SHA-256 exception where enabled and safe to evaluate.
3. Group maximum file size.
4. Group archive and unscannable-file rules.
5. Custom blocked formats.
6. Allow-list-only formats.
7. Strictness and automatic escalation.

Core executable detections are deliberately evaluated before configurable allow-list behavior.

## Persistence

Schema v7 adds `workflow_history` as a bounded list. Workflow history stores JSON-safe metadata only and is included in Redis, Supabase, and supported local snapshots. The maximum retained history is 500 records with up to 24 events per record.
