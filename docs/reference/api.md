# API

Drive Nik from a script or another system: the REST API under `/api` is the same one the web app uses.

## The interactive documentation

Open `/api/docs` on a running server (for example `https://localhost:8443/api/docs`) for the Swagger UI. It is always in step with the server and lists every route with its request and response shapes.

1. Press **Authorize** and paste an API key.
2. Every route gains **Try it out**.

The OpenAPI document is at `/api/openapi.json`. Generate a typed client from it, for example:

```sh
openapi-generator generate -i https://HOST/api/openapi.json -g python
```

## Authentication

A request carries either a browser session (cookie) or an API key in the `X-API-Key` header:

```sh
curl -H "X-API-Key: nik_XXXXXXXX…" https://localhost:8443/api/incidents
```

### API keys

An admin creates and revokes keys in **Platform settings › Access › API keys** (or `POST /api/keys` with `{ label, roles, expiresInDays }`). The key is shown once. It carries:

- **roles**, as an account does (a read-only key has the role `viewer`);
- an optional **expiry**; an expired key is refused.

Every change is in the audit log: a key appears as `api:<label>`, a session as its username. A key is never asked for a second factor, but a key with the Admin role is held to the administrators' networks.

### Roles and permissions

A route asks for a permission, never for a role. A caller may do what its roles grant together; without the permission it gets 403. `GET /api/auth/me` answers with `roles` and `permissions`. A role given or taken away applies at the next request.

| Role | Grants |
| --- | --- |
| `viewer` | `read`: incidents, artifacts, indicators, analyses |
| `analyst` | `read`, `write` (change, upload, analyse), `automation.run` (run a playbook, answer an approval) |
| `playbooks` | `automation.run`, `automation.edit` (playbooks and scripts), `automation.debug`, `lists.manage` |
| `connectors` | `connectors.manage`: connectors, instances and their credentials |
| `rules` | `rules.manage`: YARA, capa, FLIRT rules and script signatures |
| `audit` | `audit.read`: the audit log |
| `dashboards` | `dashboards.share` |
| `admin` | Every permission, among them `admin` (accounts, keys, webhooks, storage, backup, the settings that decide what leaves the server), `automation.open`, `incidents.configure`, `content.manage` |

### Sessions

| Route | Does |
| --- | --- |
| `POST /api/auth/login` | `{ username, password }`; 10 attempts a minute per address |
| `POST /api/auth/login/code` | `{ code }` or `{ recoveryCode }`, after a password that answered `secondFactor` |
| `POST /api/auth/logout` | Ends the session |
| `GET /api/auth/me` | The signed-in caller, its roles and permissions |
| `GET /api/auth/bootstrap` | Whether any account exists. While none does, the first `POST /api/users` needs no authentication and creates an admin |

For an account with a second factor, the right password opens no session: the answer is `{ "secondFactor": { "kinds": ["totp"], "recoveryCodes": true, "seconds": 300 } }` and a cookie good only for `/api/auth/login/code`. After five failures in a row (per account and per address) attempts are answered 429 with `Retry-After`.

| Refusal (403) | `code` | Meaning |
| --- | --- | --- |
| Administrator without a second factor | `second_factor_required` | Administrators must have one; only `/api/auth/me`, `/api/auth/session` and the set-up routes answer |
| Outside the administrators' networks | `admin_network` | The caller holds Admin and is not on a listed network (keys too) |
| Sent by another site | `cross_site` | A change the browser marks as cross-site (`Sec-Fetch-Site`) |

## Conventions

| Topic | Rule |
| --- | --- |
| Ids | `{id}` of an incident is its uuid. Its `number` (`#00042`) is given by the server; `GET /api/incidents/by-number/{number}` finds it |
| Pagination | `limit` / `offset`; the total in `X-Total-Count` (incidents) or in the body |
| Lists at scale | `GET /api/incidents?view=summary` gives light rows; fetch one incident for its full document |
| Concurrency | `GET` returns an `ETag` (the incident's revision). Send it back as `If-Match` on `PATCH`: a stale write gets 412; read again, apply, retry |
| Conditional GET | `If-None-Match` answers 304 while nothing changed |
| Partial updates | `application/merge-patch+json` (RFC 7396): `{"flags": {"<key>": null}}` removes one flag. `application/json` replaces the given top-level fields |
| Idempotency | An `Idempotency-Key` header on `POST` notes and uploads makes retries safe |
| Background jobs | `?async=true` on an upload answers `202 { jobId }`; poll `GET /api/jobs/{jobId}` |
| Work in progress | The state of a disassembly, capa, a capture, a scan or a mailbox carries `work`: `{state, attempts, interruptedAt, resumedAt, progress, note}` |
| Rate limit | 600 requests a minute per client address ([`RATE_LIMIT_DEFAULT`](configuration.md#RATE_LIMIT_DEFAULT)), 10 for sign-in; 429 beyond |
| Tracing | Every answer carries `X-Request-ID` |
| Background requests | A client holding a session can send `X-Nik-Background` on requests it makes by itself: they do not count as use of the session |
| Versioning | The current API is v1 under `/api`; a breaking change would ship under a new prefix |

## Main routes

Swagger at `/api/docs` has every route and parameter. These are the ones most scripts use.

### Incidents

| Route | Does |
| --- | --- |
| `GET /api/incidents` | List. `q` (the [query language](query-language.md): `status:open severity:>=high`), `limit`, `offset`, `view=summary`, `fields=a,b` |
| `GET /api/incidents/{id}` | One incident, with its `ETag` |
| `POST /api/incidents` | Create (or upsert with an id) |
| `PATCH /api/incidents/{id}` | Change; honours `If-Match` |
| `DELETE /api/incidents/{id}` | Delete |
| `GET`, `PATCH /api/incidents/{id}/fields` | Read and set its fields by their registry names |
| `GET /api/incidents/{id}/context` | Its context |
| `POST /api/incidents/{id}/notes` | Add a note (`PATCH` / `DELETE …/{noteId}`) |
| `GET`, `POST /api/incidents/{id}/war-room` | Read the War Room; write a note |
| `POST /api/incidents/{id}/war-room/command` | What is typed in the War Room: `{ line, confirm? }` ([War Room commands](../guide/commands.md)) |
| `POST /api/incidents/{id}/report` | The report as PDF or HTML |
| `GET /api/incidents/{id}/iocs` | Its indicators |
| `GET /api/incidents/{id}/iocs/export` | `?format=` `csv`, `stix` or `misp` |
| `POST /api/incidents/{id}/iocs/found/scan` | Find indicators now |
| `PATCH /api/incidents/{id}/mirror` | Its mirroring |

### Evidence and artifacts

| Route | Does |
| --- | --- |
| `POST /api/incidents/{id}/upload` | A raw evidence file, parsed by the server ([Uploads](#uploads)) |
| `POST /api/incidents/{id}/samples` | A malware sample |
| `GET /api/samples/{sha256}` | Its analysis; `…/download` in an AES-256 zip (`infected`), audited |
| `POST /api/incidents/{id}/mails` | An e-mail (`.eml`, `.msg`); `GET /api/mails/{sha256}` its analysis |
| `POST /api/incidents/{id}/captures` | A packet capture |
| `POST /api/artifacts/mailboxes` | A mailbox or PST |
| `GET /api/artifacts` | The registry of everything analysed; `POST /api/artifacts/files`, `/urls` analyse on their own |
| `POST /api/artifacts/{id}/links` | Link an artifact to an incident |
| `PUT /api/artifacts/{id}/tags`, `…/expiry` | Tags; a date to be deleted |
| `POST /api/artifacts/export` | Several artifacts in one protected archive |
| `GET /api/search?q=` | Global search |
| `POST /api/query` | Any entity by the [query language](query-language.md); `GET /api/query/schema`, `POST /api/query/aggregate` |

### Indicators

| Route | Does |
| --- | --- |
| `GET /api/iocs` | The Indicators page: `q`, `type`, `verdict`, `origin`, `list`, `expired`, `sort`, `offset`, `limit` |
| `POST /api/iocs/parse`, `POST /api/iocs` | Read text (free text, CSV, STIX 2.1, MISP, Nik JSON); add indicators |
| `GET /api/iocs/lookup?type=&value=` | Every incident it appears in |
| `POST /api/iocs/check` | A reputation check of a scope (`dryRun` for the plan) |
| `POST /api/iocs/export` | Download a scope |
| `GET`, `POST /api/iocs/lists` | Lists of indicators; `GET …/{id}/feed` serves one to machines (key or HTTP Basic) |
| `GET /api/enrichment?type=&value=` | What the sources said |

### Automation

| Route | Does |
| --- | --- |
| `GET`, `POST /api/automation/playbooks` | Playbooks |
| `PUT /api/automation/playbooks/{id}/enabled` | Turn on or off |
| `POST /api/automation/playbooks/{id}/run` | Run on an incident |
| `POST /api/automation/hooks/{token}` | Start a playbook **From outside**: no account, the token is the secret |
| `GET /api/automation/runs`, `…/{id}` | Runs; `POST …/{id}/steps/{step}/resolve` answers an interrupted step |
| `GET /api/automation/approvals` | Approvals waiting |
| `GET /api/automation/connectors`, `GET`, `POST /api/automation/instances` | Connectors and their instances; `POST …/instances/{id}/test` |
| `GET /api/automation/catalog` | The commands, with their arguments |
| `GET`, `PUT /api/automation/state` | The general switch (**Stop all**) |
| `GET /api/packs`, `POST /api/packs/import` | Content packs; `GET /api/packs/catalogue` |
| `GET /api/tasks`, `GET /api/lists`, `GET /api/dashboards`, `GET /api/fetch` | Tasks, lists, dashboards, fetch status |

### Accounts and settings

| Route | Does |
| --- | --- |
| `GET`, `POST /api/users` | Accounts (admin): `{ username, password, roles }`, the password 8 characters at least |
| `PATCH /api/users/{id}` | `{ username, roles, password, disabled }`; a new password, roles or disabling end its sessions |
| `DELETE /api/users/{id}` | Never the caller's own nor the last admin |
| `PUT /api/users/me/password` | Change one's own password |
| `POST /api/users/{id}/second-factor/reset` | Take another account's second factor away (signed-in admin only) |
| `GET`, `PUT /api/auth/policy` | The sign-in policy |
| `GET`, `POST`, `DELETE /api/keys` | API keys |
| `GET`, `POST`, `DELETE /api/webhooks` | Webhooks ([below](#webhooks)) |
| `GET`, `PUT /api/settings` | Detection rules, business hours, allowlist, report header, mail and threat-intelligence options |

### Backups, recovery and health

| Route | Does |
| --- | --- |
| `GET /api/backups` | Settings and state of the backups, and the list (admin) |
| `POST /api/backups/run`, `POST /api/backups/{id}/verify` | A backup now; test one again (an admin's key may) |
| `PUT /api/backups/settings`, `PUT /api/backups/passphrase`, `GET /api/backups/{id}/download`, `DELETE /api/backups/{id}?confirm={id}` | Signed-in admin only |
| `GET /api/backup/export`, `POST /api/backup/import` | [Export as one file](../admin/backups.md#export-as-one-file) |
| `GET /api/recovery`, `POST /api/recovery/base`, `POST /api/recovery/test` | Recovery to a moment: state, a base backup now, a test now; `PUT …/settings` signed-in admin only |
| `GET /api/health` | `{"status":"ok"}` to anybody (or `standby`, `promoting`, `checking`, `superseded`) |
| `GET /api/health/details` | The Health page (admin) |
| `GET /api/metrics` | Prometheus, for the bearer of the scrape token only |
| `GET /api/workers`, `GET /api/storage`, `GET /api/system/keys` | Workers, storage, keys |
| `GET /api/audit` | The audit log (`audit.read`), with `total`; `DELETE /api/audit?olderThanDays=N` signed-in admin |
| `GET /api/audit/chain`, `POST …/chain/verify` | The chain |
| `GET`, `PUT /api/audit/forwarding`, `POST …/test` | Forwarding to syslog |

No route restores a backup, recovers the database, promotes a standby or returns a key: those are commands on the host.

## Bulk jobs

The incidents, artifacts and indicators have the same two routes: `POST /api/incidents/bulk`, `/api/artifacts/bulk`, `/api/iocs/bulk`, and `…/bulk/plan` beside each.

```json
{
  "action": "set",
  "params": { "changes": { "status": "closed", "close_reason": "Duplicate" } },
  "query": { "q": "status:open tag:campaign-q4" },
  "confirm": { "count": 1284, "typed": "close 1284" }
}
```

1. **Select** by `ids` (incident ids, artifact ids, indicators as `type:value`) or by `query` (the filter of the list), never both.
2. **Plan**: `POST …/bulk/plan` with the same body changes nothing and answers `{count, applies, notes, typed, limit, over, inline, label, refs}`.
3. **Run**: send `confirm.count` (the plan's count; 409 if the selection changed) and, for `delete` and closing more than the typed threshold, `confirm.typed` (the plan's `typed`, e.g. `delete 12`).
4. **Follow**: up to 50 items are done before the answer (200); a larger job answers 202 and is polled at `GET /api/bulk/{id}`. It survives a restart.

| List | Actions (`params`) |
| --- | --- |
| incidents | `set` (`changes`: fields as `PATCH …/fields` takes them; closing is `status: closed` with `close_reason`) · `tags` (`add`, `remove`) · `delete` · `playbook` (`playbook`; `automation.run`) · `mirror` (`direction`: `in`, `out`, `both`, `none`; `out`/`both` need `automation.run`) · `find_indicators` |
| artifacts | `tags` · `reanalyse` · `link`, `unlink` (`incident`) · `expiry` (`expiresAt` or null) · `delete` |
| iocs | `check` (`force`) · `tags` · `tlp` · `list_add`, `list_remove` (`list`) · `allowlist` · `incident_remove` (`incident`) · `delete` |

Each item ends `done`, `skipped`, `refused` (with the sentence a single change would have answered) or `failed`. Nothing is rolled back. `GET /api/bulk/{id}/items` and `…/result.csv` give the items; `POST /api/bulk/{id}/cancel` stops after the current item; `POST /api/bulk/{id}/retry` makes a job of the items that failed. Refusals of the whole request: 403 (permission), 404 (a named playbook, list or incident), 409 (confirmation, or another job of the caller on that list), 422 (unreadable, or more than 5,000 items). See [Act on many at once](../guide/bulk.md).

## Uploads

`POST /api/incidents/{id}/upload` takes a multipart file plus query parameters that route it to the right parser; the server parses it and merges the result into the incident. A file over [`ARTIFACT_MAX_MB`](configuration.md#ARTIFACT_MAX_MB) (500) is refused with 413.

```sh
# Browser history (Chromium History SQLite)
curl -H "X-API-Key: $KEY" -F file=@History \
  "https://localhost:8443/api/incidents/$ID/upload?tab=browser&browser=chrome&source=history"

# Shell history
curl -H "X-API-Key: $KEY" -F file=@.bash_history \
  "https://localhost:8443/api/incidents/$ID/upload?tab=commands&shell=bash"

# Endpoint artifact (a cron file)
curl -H "X-API-Key: $KEY" -F file=@crontab \
  "https://localhost:8443/api/incidents/$ID/upload?tab=endpoint&category=persistence&source=cron"

# Windows event log, parsed in the background
curl -H "X-API-Key: $KEY" -F file=@Security.evtx \
  "https://localhost:8443/api/incidents/$ID/upload?tab=eventlogs&async=true"
```

| `tab` | Needs |
| --- | --- |
| `browser` | `browser` (`chrome`, `firefox`, `edge`, `brave`, `opera`, `safari`) and `source` (`history`, `bookmarks`, `shortcuts`, `places`; Safari: `history`, `downloads`, `bookmarks`); optional `profile` (default `Default`) |
| `commands` | `shell` (`bash`, `zsh`, `fish`, `powershell`) |
| `endpoint` | `category` (`execution`, `persistence`, `fileaccess`, `usb`) and `source` |
| `eventlogs` | Nothing: the channel comes from the `.evtx` file |

A job cut by a restart ends in error with a sentence asking to upload the file again.

## Webhooks

An admin subscribes an address with `POST /api/webhooks`. Each delivery is signed with HMAC-SHA256 in `X-Nik-Signature`. Events: `incident.created`, `incident.updated`, `incident.deleted`, `note.added`, `upload.completed`, `ioc.watch_hit`, `mail.analysed`, `file.analysed`, `code.analysed`, `capabilities.analysed`, `capture.analysed`, `url.analysed`, `ioc.verdict_changed`, `storage.low`, `sla.breached`, `artifact.expiring`, `artifact.expired`. See [Events](events.md).

!!! warning
    A webhook sends what the event holds (senders, subjects, file names) to the address an admin gave, without the checks a playbook's nodes go through. Subscribe only addresses you trust with that.

## Related

- [Query language](query-language.md) — the `q` of every list
- [Events](events.md) — what webhooks and triggers carry
- [Security](security.md#accounts-sessions-and-the-audit-log) — how accounts and keys are protected
- [Accounts, roles and sign-in](../guide/accounts.md) — making keys in the app
- [Act on many at once](../guide/bulk.md)
