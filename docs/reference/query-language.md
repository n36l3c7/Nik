# Query language

Every operator, field and limit of the language that filters Nik's lists, saved filters, dashboard widgets and the API.

For a short introduction with screenshots, see [Search, filters and saved views](../guide/search.md#write-a-query).

## Where it is used

| Place | Asks |
|---|---|
| The query box of the list of incidents, and its [saved filters](../guide/search.md#saved-filters) | incidents |
| **Filter artifacts** in the artifacts panel | artifacts |
| **Filter indicators** on the Indicators page | indicators |
| The **Which ones** of a [dashboard widget](../guide/dashboards.md#the-widget-editor), and the filter of a dashboard | incidents, artifacts, indicators, tasks, runs, approvals, audit log |
| The **Chart of a dashboard** widget of an incident page | the widget's query, plus one field of the incident |
| A [bulk action](../guide/bulk.md) on everything a filter keeps | the list's query |
| The API: the `q` parameter of `GET /api/incidents`, `/api/artifacts`, `/api/iocs`; `POST /api/query`; `POST /api/query/aggregate` | any entity |

## Examples

```text
status:open severity:>=high owner:""                 open, high or critical, nobody has it
host:wks-* -status:closed created:>=now-7d          this week's incidents on workstations
tag:finance -tag:test status:open                   open, tagged finance, tests left out
type:Phishing closeReason:"False positive" closed:>=now-30d
severity IN (high, critical) slaBreached:true       serious ones that ran over their SLA
number:61                                           incident #00061
kind:mail verdict:phishing tag:campaign             phishing e-mails of a campaign
verdict:>=suspicious (type:ip or type:domain)       flagged addresses and domains
list:"Watched C2" expired:false                     indicators of a watch list, still current
action:user.* at:[2026-11-01 TO today]              account changes this month (audit log)
customer:acme amount:>=10000 !region:EMEA           fields made in Settings
```

## Syntax

| Write | Means |
|---|---|
| `word` · `"two words"` | The text, in any of the entity's text fields ([below](#entities-and-their-fields)). A value with a colon in it (`http://…`, `C:\…`, an IPv6 address) is text too. |
| `field:value` | A text field **contains** the value; a keyword field (status, kind, verdict) **is** the value. Case does not matter. |
| `field:"two words"` | Quote a value with spaces. Inside quotes, `\"` and `\\` escape. |
| `!field:value` | Not that value. A field that is empty counts as not that value. |
| `-cond` · `not cond` | Negates a condition or a group: `-test`, `not (kind:file or kind:mail)` |
| `field IN (a, b)` | One of the values: same as `field:a or field:b`. Values separated by commas or spaces. |
| `field NOT IN (a, b)` | None of them: same as `!field:a !field:b` |
| `field:>v` `:>=` `:<` `:<=` | Comparisons, for numbers, dates and ordered fields |
| `field:[a TO b]` | A range, both ends included. `*` leaves an end open: `score:[40 TO *]` |
| `*` · `?` | In an unquoted value: any run of characters, one character. With a wildcard the value is matched **whole**: `host:srv-*`. `\*` is a literal star. |
| `field:""` | The field is empty. `owner:""` is unassigned. |
| `field:*` | The field holds something. `tags:*` is tagged. |
| `a b` · `a and b` | Both must hold. |
| `a or b` | Either. `or` binds less tightly than `and`. |
| `( … )` | Groups. |

**Ordered fields** compare by rank: severity `low < medium < high < critical`; verdict of indicators `unknown < harmless < suspicious < malicious`.

!!! warning "The old way to write \"is not\" is refused"
    `status:!closed` is refused with a hint: write `!status:closed`.

### Dates

| Write | Means |
|---|---|
| `2026-11-10` | That day, whole |
| `2026-11` | That month |
| `2026-11-10T14:30` | That minute (seconds, `Z` or an offset are read too) |
| `today` · `yesterday` | Those days |
| `now` | This instant |
| `now-7d` · `now-12h` | That long ago. Units `m`, `h`, `d`, `w`. |
| `"7 days ago"` | The same in words: minutes, hours, days, weeks, months (30 days), years (365 days) |

Times are **UTC**. A date is a span: `created:2026-11-10` is the whole day, `created:>=2026-11-10` from its start, `created:>2026-11-10` after its end.

## Entities and their fields

A field also answers to the other names in brackets.

### Incidents

Plain words search `name`, `host`, `username`, `ticket`.

| Field | Kind | Means |
|---|---|---|
| `number` (`no`) | number | The number it is called by: `number:42` |
| `id` (`uuid`) | keyword | Its id |
| `name` | text | The name shown in the list |
| `ticket` (`ticketId`) | text | The ticket of your tracker |
| `host` | text | The host |
| `username` (`user`) | text | The account |
| `os` | keyword | The operating system |
| `severity` | ordered | `low`, `medium`, `high`, `critical` |
| `status` | keyword | `open`, `in_progress`, `closed` |
| `owner` (`assignee`) | keyword | Who has it; `owner:""` is nobody |
| `type` | keyword | The name of its type |
| `hasMail` (`mail`) | yes/no | It holds analysed e-mails |
| `created` (`createdAt`) · `modified` (`updated`, `updatedAt`) · `occurred` · `closed` (`closedAt`) | date | When it was created, last changed, happened, was closed |
| `closeReason` (`close_reason`) | keyword | Why it was closed |
| `close_notes` | text | What was written when it was closed |
| `source` | keyword | The name of the connection that fetched it |
| `source_instance` · `source_id` | keyword · text | The id of that connection · its id over there |
| `slaBreached` (`breached`, `sla_breached`) | yes/no | One of its SLA timers ran past its time |
| `timeToAssign` · `timeToContain` · `timeToClose` (`time_to_…`) | number | Seconds the timer counted |
| `labels` (`tag`, `tags`) | tags | Its tags, matched whole |
| `tlp` | choice | `clear`, `green`, `amber`, `amber+strict`, `red` |
| `phase` · `category` · `details` | text | |
| `due` | date | |
| `playbook` | text | The playbook set for it |
| `affected_hosts` · `affected_users` · `related_incidents` | tags | |
| `source_connector` · `source_url` · `mirror_direction` · `mirror_id` | text | |
| `mirror_last_sync` | date | When it was last mirrored |

Plus **every field made in Settings** ([below](#fields-made-in-settings)).

### Artifacts

Plain words search `name`, `hash`, `detail`, `tags`.

| Field | Kind | Means |
|---|---|---|
| `kind` (`type`) | keyword | `file`, `mail`, `pcap`, `url`, `mailbox` |
| `name` | text | Its name |
| `hash` (`sha256`, `ref`) | text | Its SHA-256, or the id of a capture or a scan |
| `verdict` | keyword | What the analysis concluded |
| `score` | number | The score of the analysis |
| `detail` | text | The line under the name |
| `size` | number | Bytes |
| `tags` (`tag`) | tags | |
| `created` (`createdAt`) | date | When it was added |
| `createdBy` (`by`) | keyword | Who added it |
| `linked` | yes/no | An incident references it |
| `incident` | keyword | The id of an incident that references it; `incident:*` any |
| `id` | keyword | |

### Indicators

Plain words search `value`, `note`, `tags`, `listNames`.

| Field | Kind | Means |
|---|---|---|
| `type` (`kind`) | keyword | `ip`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256` |
| `value` | text | The indicator itself |
| `verdict` | ordered | `unknown`, `harmless`, `suspicious`, `malicious`; `verdict:""` is not checked yet |
| `score` | number | The reputation score |
| `origin` | keyword | `incident`, `manual`, `import`, `artifact` |
| `incidents` | number | In how many incidents it was seen |
| `tags` (`tag`) | tags | |
| `note` | text | The note an analyst wrote |
| `tlp` | keyword | `clear`, `green`, `amber`, `red` |
| `list` (`lists`) | keyword | A watch list that keeps it, by name or id |
| `listNames` | tags | The names of its lists |
| `expired` | yes/no | Its date has passed |
| `expires` | date | After which it is no longer current |
| `firstSeen` (`first_seen`, `seen`) | date | When Nik first met it |
| `checked` (`checkedAt`) | date | When its reputation was last asked |
| `allowlisted` | yes/no | It is in the allowlist |
| `analysed` (`analyzed`) | yes/no | Nik analysed it itself (a URL it visited) |
| `addedBy` | keyword | Who added it by hand |

### Audit log, runs, approvals, tasks

These are asked by dashboard widgets and the API.

| Entity | You need | Fields |
|---|---|---|
| Audit log | Audit role | `at` (`date`, `when`), `actor` (`user`, `by`), `action` (`user.update`, `incident.*`), `target`, `details`, `incident`, `incidentId`, `origin` (`import`) |
| Runs | run playbooks | `id`, `playbook`, `status` (`queued`, `running`, `waiting`, `done`, `failed`, `stopped`), `dryRun` (`dry`), `on`, `incident`, `startedBy` (`by`), `started`, `finished`, `error` |
| Approvals | run playbooks | `id`, `status` (`waiting`, `approved`, `rejected`, `expired`), `question`, `playbook`, `asked`, `answered`, `answeredBy` (`by`) |
| Tasks | read | `id`, `kind` (`task`, `ask`), `status` (`open`, `overdue`, `done`, `skipped`), `title`, `assignee` (`user`), `role`, `incident`, `created`, `completed`, `completedBy` |

## Fields made in Settings

Every field of **Platform settings › Incidents › All fields** is a field of the language, by its name there. What a condition means follows its type:

| Type of the field | In a query |
|---|---|
| `text`, `long_text`, `url` | Text: contains the value; with a wildcard, matched whole |
| `user`, `role`, `choice` | Keyword: is the value. A choice takes its choices only; another value is refused with the list. |
| `number`, `timer` | Number, with comparisons and ranges. A timer is the seconds it counted. |
| `date` | Date, as `created` |
| `bool` | `true` or `false`; never set is not true |
| `tags`, `multi_choice` | Holds the value, matched whole |
| `indicator` | Text: the value of the indicator |
| `list`, `json` | Searched as text: found anywhere in it, or empty / filled. No comparison. |

```text
customer:acme !region:"North America" amount:[1000 TO *]
labels:vip due:<today sender_domain:""
```

- **A name the language already uses wins.** `number` is the incident's number, `user` its account, `source` the connection that fetched it. A field of yours with such a name is written `field.<name>`, which works for every field you made: `field.number:7`.
- **A field deleted since** makes a query, a saved filter or a widget that names it fail with the name of the field.
- **Speed.** Fields made in Settings are kept in one JSON column, which no index serves. On a large table, add a condition on `status` or `created` too.

## Counting and measuring

Dashboard widgets ask `POST /api/query/aggregate`, which answers numbers instead of rows. The query is compiled as above, so the answer never counts what the caller may not read.

```json
{ "entity": "incidents", "query": "status:open",
  "groupBy": ["created@day", "severity"], "measure": "count",
  "timeField": "created", "timeRange": "30d", "compare": "previous", "limit": 50 }
```

| Key | Takes |
|---|---|
| `groupBy` | Up to two fields. A date as `field@hour`, `@day`, `@week` (named by its Monday), `@month`, `@year`. A tags field counts a row under each tag. |
| `measure` | `count` (default), or `sum`, `avg`, `min`, `max`, `median`, `p90` of a number (`avg:score`) or of the seconds between two dates (`median:duration(created,closed)`; `duration(asked,now)` is an age) |
| `timeRange` | On `timeField`: `24h`, `7d`, `12w`, `6m`, `1y`, or `{from, to}` |
| `compare` | `"previous"` adds the total of the period of the same length before |
| `limit` | Groups returned: 50 by default, 500 at most; `more` says how many were left out |

A plain count is done by the database. Anything else is worked out from at most 100,000 matching rows; past that `truncated` is true.

## Limits and errors

| Limit | Value |
|---|---|
| Length of a query | 2,000 characters |
| Levels of parentheses | 20 |
| Conditions | 200 |
| Wildcards in one value | 8 |
| Rows per page of `POST /api/query` | 500 |
| Time the database may take | 10 seconds |

A query that cannot be read is answered `422`, with a sentence and, under `query`, the `position` of the problem, a `code` and, for a misspelt field or value, a `suggestion`:

```json
{ "detail": "\"stauts\" is not a field of incidents: did you mean \"status\"?",
  "query": { "code": "unknown_field", "position": 16, "suggestion": "status", "message": "…" } }
```

The query box shows the same sentence under the box, and the list stays as it was.

??? info "Details: the schema and checking a query"
    - `GET /api/query/schema` lists, for each entity you may query, its fields with their kind, their other names and the values a keyword can take. A field made in Settings carries its `label` and `custom: true`.
    - `POST /api/query/check` reads a query without running it: `{ok: true, tree}`, or `422` as above.
    - A query is compiled to bound parameters, never to SQL text. Who may query an entity is checked when it is compiled: `audit` needs the Audit role, `runs` and `approvals` the right to run playbooks, the others the right to read.

## Related

- [Search, filters and saved views](../guide/search.md)
- [Dashboards and My tasks](../guide/dashboards.md)
- [Act on many at once](../guide/bulk.md)
- [API](api.md)
- [Types, fields and pages](../guide/types.md)
