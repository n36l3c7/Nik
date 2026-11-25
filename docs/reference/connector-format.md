# Connector and pack format

Every key of a connector file and of a content pack, for people who write their own.

To learn by doing, follow [An integration (connector)](../guide/build/connector.md) and [A content pack](../guide/build/pack.md). To install and use them, see [Connectors and mirroring](../guide/connectors.md) and [Content packs](../guide/packs.md).

## The connector file

A connector is YAML, at most 1 MB and 400 commands. A key the format does not know is an error, with its line: a typo is told, not ignored. Texts between `{{ }}` are [expressions](playbook-nodes.md#expressions). There is no code in a connector.

### What templates can read

| Name | Holds | Read where |
| --- | --- | --- |
| `config` | The plain values of the instance (`config.url`) | Everywhere |
| `args` | The arguments of the command; one not given is `null` (or its `default`) | In a command |
| `steps` | Earlier steps of the same command: `steps.<name>.response`, `.status`, `.headers` | In a command made of steps |
| `secret` | The secrets of the instance (`secret.password`) | Only in what is sent; never in `outputs`, `error` or a condition |
| `now` | The moment the command runs: `now.iso`, `now.epoch`, `now.epoch_ms` | Everywhere |
| `idempotency.key` | The key of this step ([below](#a-command)) | Only in what is sent |
| `response`, `status`, `headers` | The answer (parsed JSON, or `{text}`), its status, its headers (lower case) | `outputs`, `success`, `error`, `pagination`, `poll` |

### Top-level keys

| Key | What it is |
| --- | --- |
| `name` (required) | What people read. 80 characters at most |
| `id` (required) | What playbooks refer to: a lower-case letter, then lower-case letters, digits or `-` (2 to 41). A command is the node `<id>.<command>`. Do not change it once used |
| `version` (required) | A whole number, raised at each change: an installed connector is replaced only by a higher one |
| `description`, `api_version` | What it is for; the vendor's API it was written against |
| `verified` | `true` once run against a real system. Default `false` (*not verified*) |
| `configuration` | What an instance asks for: 30 entries at most, one set of credentials at most |
| `base_url` (required) | Where every request starts: `"{{ config.url }}/api/v2"`. Its host is the instance's host |
| `headers` | Sent with every request; may read `config` |
| `test` | What **Test** sends: `request` and optionally `expect` (as `success`). Use something that needs good credentials and changes nothing |
| `commands` (required) | 1 to 400 commands |
| `fetch` | How an instance brings alerts in ([below](#fetch)) |
| `mirror` · `no_mirror` | How an incident is kept in step ([below](#mirror)) · why a connector that fetches does not mirror |
| `schema` | `incoming` and `outgoing`: lists of `{name, type, description}` (`text`, `number`, `bool`, `date`, `list`, `object`) the mapper editor offers |
| `more_hosts` | Other hosts commands may reach (40 at most; names, no port, no template). Credentials are not sent there |
| `download_hosts_from` | The name of a `hosts` configuration entry: storage hosts a file download may come from |
| `lookups` | For a reputation source: `{ weight: 1–3, informational: true }` |
| `ext_fields` | What it adds under `context.ext.<id>`: `{name, type, description}` |
| `native` | `mail`: the one kind Nik speaks itself (no `base_url`, `headers`, `test`, `request`) |

### Configuration entries

| Key | What it is |
| --- | --- |
| `name` (required) | How templates read it: `config.<name>`. A lower-case letter, then lower-case letters, digits or `_` (40 at most) |
| `label`, `help` | Shown beside and under the field |
| `type` | `url`, `text` (default), `number`, `bool`, `choice` (with `choices`), `hosts`, `secret` (stored encrypted, read as `secret.<name>`), or a kind of credentials (below) |
| `required`, `default`, `choices` | A value left empty takes the default |

Credentials, by `type`:

| `type` | Secrets | Sent as | More keys |
| --- | --- | --- | --- |
| `basic` | `username`, `password` | `Authorization: Basic …` | |
| `bearer` | `token` | `Authorization: Bearer …` | |
| `header` | `value` | The header you name | `header` (required), `prefix` (`"ApiToken "`) |
| `query` | `value` | A parameter added to every request | `param` (required) |
| `oauth2_client` | `client_id`, `client_secret` | A client-credentials token, then `Bearer` | `token_url` (required), `scope`, `auth_style` (`form` or `basic`) |
| `session` | `username`, `password`, `api_key` | A session opened before the command and closed after | `login` (`request`, `token`, `header`, `prefix`, `success`), `logout` (`request`) |
| `zscaler` | `username`, `password`, `api_key` | Zscaler's classic sign-in | |

A key left empty in the instance is not sent. For a host of `more_hosts` the file may write the value itself: `secret.token` (bearer), `secret.value` (header, query).

### A command

| Key | What it is |
| --- | --- |
| `name` (required) | Lower-case letters, digits and `-` (2 to 49): `create-ticket` |
| `description` | Shown under the name in the library |
| `arguments` | 40 at most. Each `name`, `type` (`text`, `number`, `bool`, `list`, `object`, `any`, `choice` with `choices`, `file`), `required`, `default` or `default_from` (a configuration entry), `description` |
| `request` or `steps` | One request, or up to 12 that feed each other |
| `success` | `status` (a code or a list; any 2xx by default) and `when` (conditions on the answer) |
| `error` | `message`: where the other side's explanation is. 429 and 5xx are retried |
| `pagination` · `poll` | Read a list to its end · send again until done ([below](#pages-steps-and-polls)) |
| `outputs` | Name → template over the answer. None: the node gives `response` |
| `context` | Up to 20 `{path, value}` written to the incident's [context](playbook-nodes.md#the-context-of-an-incident) |
| `sample` | What a dry run gives instead of the outputs |
| `timeout` | Seconds: 60 by default, 300 at most |
| `changes_outside` | `true` when it changes the other side: asks for approval, never sent in a dry run |
| `idempotent` | `false` when twice does it twice (a ticket, a comment): not retried after an unknown outcome, and interrupted after a restart. Default `true` |
| `idempotency_key` | `true` for a product that acts once per key: send `{{ idempotency.key }}` (same for every try of a step, 32 hex characters). Retried after a restart whatever `idempotent` says |
| `premium` | `true` for a paid-plan command (shown, not enforced) |
| `reputation` | `ip`, `domain`, `url`, `file` or `email`: makes the connector a threat-intelligence source. First argument takes the value; outputs `verdict` (`malicious`, `suspicious`, `harmless`, `unknown`), `summary`, `link` |
| `reputation_of` | `registered_domain`: a look-up of `www.example.co.uk` sends `example.co.uk` |

### A request

| Key | What it is |
| --- | --- |
| `method` | `GET` (default), `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `path` (required) | Added to `base_url`. A full address must be on the instance's host (or `more_hosts`) |
| `query`, `headers` | Names and templates. An empty query value is not sent |
| `json`, `form`, `multipart`, `body` | The body, one of the four. An empty key is left out |
| `files`, `body_file` | A file Nik holds, sent in a multipart form (10 at most) or as the body. The command must say `changes_outside: true` |
| `answer` | `auto` (default), `text`, or `file` (kept as an artifact; with `save_as {name, type}` and `unpack {format: zip, password}`) |

??? info "Files"
    With `answer: file` the bytes go to Nik's store as an artifact, never opened. `response` (and the default outputs) is `name`, `type`, `size`, `sha256`, `artifact`, `linked`; with `unpack`, also `files`, `count`, `skipped`. A file is as large as an upload at most (`SAMPLE_MAX_MB`); an archive holds 200 files at most. A redirect to a storage host is followed only to `more_hosts` or the hosts of `download_hosts_from`, with nothing of the connector sent along. A request whose answer is a file is not polled nor paged.

### Pages, steps and polls

`pagination` gives `response.items` (5 000 at most), `response.pages`, `response.truncated`:

| Key | |
| --- | --- |
| `type` | `offset`, `page` (from 1), `cursor` (with `next`), `link` (the `Link: rel="next"` header) |
| `items` | Where the items of a page are: `"{{ response.result }}"` |
| `param` · `next` | The parameter sent · for a cursor, where the next one is |
| `limit_param` · `limit` | Page size parameter · size (100 by default, 1 000 at most) |
| `max_pages` | 10 by default, 100 at most |
| `keep` | Values of the first page, read as `response.kept.<name>` |

`steps`: up to 12, each `name`, `request`, its own `success`, `error`, `poll`, and `when` (skip unless it holds). Later ones read `steps.<name>.response`.

`poll`: `until`, `fail_when` (conditions), `every` (5 s; 2 to 600), `timeout` (300 s; an hour at most). `Retry-After` is honoured up to ten minutes. The run waits without holding a worker.

Conditions: `{ all: [{ left: "{{ response.state }}", op: eq, right: finished }] }`, with `all` or `any` and `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `contains`, `in`, `exists`, `empty`.

### fetch

| Key | |
| --- | --- |
| `interval_seconds` | 120 by default; 30 to 86 400 |
| `first_fetch` | `30 minutes`, `12 hours`, `3 days` (a month at most) |
| `lookback_minutes` | 0 by default; 1 440 at most |
| `request`, `success`, `error` | As a command. Templates read `config`, `secret`, `since`, `state`, `first`, `now` |
| `since` | The moment to ask from: `since.iso`, `since.epoch`, `since.epoch_ms`. Compare with `>=`, ask oldest first |
| `item_time` | The time the request filters on, when it is not `occurred` |
| `pagination` or `items` | Where the alerts are |
| `item_id` (required) | What tells alerts apart: `"{{ item.id }}"` |
| `occurred` | When it happened |
| `first_state`, `next_state` | For a cursor instead of a time: the `state` before the first cycle (reads `first`) and after each (reads the answer and `items`) |

The first three are what an instance starts with; each is changed in the instance.

### mirror

| Key | |
| --- | --- |
| `get` | `{command, args}`: read the object |
| `item` | Where the object is in what `get` gave (`"{{ result.ticket }}"`); empty, or an answer of 404/410, means it is gone |
| `update` | `{command, args}`: change it (its command says `changes_outside: true`) |
| `comments` | `list` and `add` (`{command, args}`), `items`, and what a comment is: `id`, `text`, `author`, `at` (over `item`). `close_notes: true` makes the last comment a person wrote the close notes of a closed incident; `automations` (a template over `config`: a list, or names separated by commas) names the authors that are not people |
| `interval_seconds` | How often the other side is read (120) |
| `id` | Where the id of the object is in a fetched item; default the fetch's `item_id` |
| `kinds` | Several kinds of object, each with its own `get`, `item`, `update`, `comments`. An incident's mirror id is then `<kind>:<id>`; calls read `mirror.kind` |
| `thread` | A mirror fed by the fetch: `ids` (the earlier items an item goes on from), `text`, `author`, `at`. With no `get`, it goes in only |

`args` are templates over `mirror.id`, `mirror.kind`, `fields` (what the outgoing mapper gave), `comment.text`, `since`, `incident`, `context`. With no `args`, the id goes to the command's first argument.

`no_mirror` (beside `fetch`, instead of `mirror`) is a sentence saying why it does not mirror. A file with `fetch` and neither gets a warning on its `fetch` line, and its instances are offered **None** only.

## Mappers

Mappers are data in Nik, edited in the instance ([Classifiers and mappers](../guide/connectors.md#classifiers-and-mappers)); in a pack they are a file `mappers/<connector id>.json`:

```json
{
  "connector": "acme-desk",
  "incoming": [
    { "to": "name", "from": "{{ item.title }}" },
    { "to": "severity", "from": "{{ item.priority | severity('inverse') }}" },
    { "to": "Ticket(val.ID == obj.ID)", "from": { "ID": "{{ item.id }}", "System": "Acme Desk" } }
  ],
  "outgoing": [
    { "to": "title", "from": "{{ incident.name }}" }
  ],
  "types": { "Phishing": { "incoming": [], "outgoing": [] } },
  "classifier": { "rules": [], "defaultType": null }
}
```

- An incoming rule's `to` is a field of the registry or a context path; `from` is a template over `item` (or an object of templates for an entity); `"authoritative": true` is **Wins over edits**. An outgoing rule's `to` is a name of the product; `from` reads `incident`, `context` and `mirror`.
- `types` holds mappers for one type by its name, replacing the general one for it.
- `classifier` is what a new instance starts with: `rules`, each `{ "when": {conditions}, "type": "<type id>" }`, and `defaultType`.

## The pack format

A pack is a zip named `.nikpack`; in a repository, the same thing unzipped: `packs/<id>/`.

```text
pack.yml
logo.png                            the logo of the card (or logo.svg)
connectors/acme-desk/connector.yml  a connector (or connectors/acme-desk.yml), with logo.png and README.md beside it
scripts/ExtractDomains.yml          name, description, code, arguments, outputs, test
playbooks/phishing-triage.json      the graph of its current version, and its limits
fields/customer.json                a custom field
incident_types/customer-case.json   a type
mappers/acme-desk.json              mappers and the classifier
lists/vip_users.json                a list (items only when the pack carries them)
dashboards/customer-cases.json      a dashboard
preprocess_rules/drop-tests.json    a pre-processing rule
sigma/windows/odd-logon.yml         a Sigma rule for host evidence: one rule document in each .yml, at any depth
```

### pack.yml

```yaml
id: acme-desk            # a lower-case letter, then lower-case letters, digits or - (2 to 49)
name: Acme Desk
vendor: Acme             # cards are grouped by it
category: Ticketing
tags: [ticketing, itsm]  # lower-case words, 8 at most
version: 1.2.0           # three numbers
description: Tickets of Acme Desk as incidents, kept in step both ways.
author: Acme
requires:                # packs that must be installed first
  - { pack: acme-base, version: 1.0.0 }
nik: ">=6.10"            # the oldest Nik it is for
notice: |                # optional: the licence or the notice of what the pack carries (20,000 characters at most)
  Rules by their authors, under the Detection Rule License 1.1.
```

- `nik` is `>=` and a version (`">=6.0"`, `">=6.10"`); a pack for a later Nik is not offered.
- An item is found again by its **name** (a connector by its id), never by a database id. Each file is what exporting that item alone gives.
- Limits: 20 MB, 2 000 files, 100 MB unpacked, 5 MB an item; no path leaving the pack, no links, only these folders; YAML read without building objects.
- Kinds are applied in this order: fields, lists, scripts, connectors, playbooks, incident types, mappers, pre-processing rules, dashboards, Sigma rules.
- **Sigma rules** (7.0): the folder `sigma/`, in any depth, one rule document in each `.yml`; the `id` of the rule names it. They are given to the forensics worker 200 at a time. A rule arrives switched on when the worker can run it, its `status` is `stable` or `test` and its `level` is `medium` or more, and off otherwise. A rule a person changed keeps their text when the pack is updated, and **Reset** gives the pack's back. The `notice` is shown with the pack, and the report names the author of each rule that matched, as the licence of SigmaHQ asks.

A pack never carries an instance, a credential, an allowed host or an opened class of data.

## Related

- [An integration (connector)](../guide/build/connector.md)
- [A content pack](../guide/build/pack.md)
- [Connectors and mirroring](../guide/connectors.md)
- [Content packs](../guide/packs.md)
- [Playbook nodes and expressions](playbook-nodes.md)
