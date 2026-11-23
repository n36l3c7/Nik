# Events

Every event a playbook can be triggered by, and every field it carries under `{{ trigger.… }}`.

How to choose and filter one is in [Triggers and events](../guide/triggers.md). In the inspector an event reads *its label · its id*: **An incident is created · incident.created**.

## Common to every event

| Field | When | Holds |
| --- | --- | --- |
| `bulk` | The change was made by a bulk action | The id of the job; empty for a change made alone |
| `incident.…` | The event is about an incident, or what it is about is in one | The fields below |

The `incident` object:

| Field | Holds |
| --- | --- |
| `incident.id` · `incident.url` | Its id · its address in Nik (`/incident/<id>`) |
| `incident.name` · `incident.ticket` | Its name · the ticket id |
| `incident.status` | `open`, `in_progress` or `closed` |
| `incident.severity` | `low`, `medium`, `high` or `critical` |
| `incident.assignee` · `incident.host` · `incident.username` · `incident.os` | Who has it · the host · the user · the OS |
| `incident.created` · `incident.modified` | When it was created · last changed |

During the run, `{{ incident.… }}` (without `trigger.`) reads every field of the incident as it is now, your own fields included ([Playbook nodes](playbook-nodes.md#the-context-of-an-incident)).

## Incidents

### incident.created

**An incident is created**: by hand, by the API, fetched by a connector, made by a playbook. The run works on the incident.

Fields: `incident.…`.

### incident.updated

**An incident changes**: one of its fields changes.

| Field | Holds |
| --- | --- |
| `incident.…` | The incident after the change |
| `changed` | The names of the fields that changed, sorted |

### sla.breached

**A timer of an incident passes its time**. Said once for each timer.

| Field | Holds |
| --- | --- |
| `timer.field` | `time_to_assign`, `time_to_contain`, `time_to_close`, or a timer field of yours |
| `timer.label` | Its label |
| `timer.due_minutes` · `timer.elapsed_minutes` | Minutes allowed · minutes elapsed |
| `incident.…` | The incident |

## Indicators

### ioc.verdict_changed

**An indicator's verdict changes**: what the sources say of it, taken together. A first answer that says nothing is not a change.

| Field | Holds |
| --- | --- |
| `ioc.kind` | `ip`, `domain`, `url`, `email`, `md5`, `sha1` or `sha256` |
| `ioc.value` | The indicator |
| `ioc.old` · `ioc.new` | The verdict before · now (`malicious`, `suspicious`, `harmless`, `unknown`, or empty) |
| `ioc.sources` | The sources behind the change |
| `ioc.verdict` · `ioc.score` | The verdict and score as they are now |
| `ioc.tlp` · `ioc.tags` · `ioc.lists` | Its TLP · tags · names of its lists |
| `ioc.incidents` | In how many incidents it was seen |
| `ioc.private` · `ioc.allowlisted` | A private address or internal name · on the allowlist |

### ioc.watch_hit

**An incident holds a watched indicator**: an incident comes to hold indicators of a watched list. The run works on the incident.

| Field | Holds |
| --- | --- |
| `ioc.…` | The first hit, with the fields above (but `old`, `new`, `sources`) |
| `list.id` · `list.name` | The list of the first hit |
| `hits` | Every hit (200 at most), each with `type`, `value`, `list`, `incident` |
| `incident.…` | The incident |

### indicators.found

**Indicators are found in an incident**: a reading kept indicators the incident did not hold. Once per reading, never per indicator; nothing for a reading that found nothing new. The run works on the incident.

| Field | Holds |
| --- | --- |
| `found.count` | How many were kept |
| `found.door` | How the reading came: `fetch`, `api`, `hand`, `playbook`, `mirror`, `asked` |
| `found.by_type.ip` (`.domain`, `.url`, `.email`, `.md5`, `.sha1`, `.sha256`) | How many of each type |
| `found.indicators` | The first 100, each `{type, value, path}` |
| `found.values` | Their values alone |
| `found.cut` · `found.more` | Whether the list was cut · by how many |
| `found.kept` | How many found indicators the incident holds after this reading (the cap of **Indicators found** counts these) |
| `incident.…` | The incident |

## Analyses

An analysis a playbook's own step started says which run caused it: that playbook does not start again on it.

### mail.analysed

**An e-mail is analysed**: uploaded alone or in an incident, analysed again, imported from a mailbox.

| Field | Holds |
| --- | --- |
| `mail.sha256` | The SHA-256 of the message |
| `mail.subject` | Its subject |
| `mail.sender` · `mail.sender_domain` | The sender's address · its domain |
| `mail.sender_sha256` | The SHA-256 of the sender's address |
| `mail.verdict` · `mail.score` | `phishing`, `suspicious` or `clean` · 0 to 100 |
| `mail.urls` | Where its links lead |
| `mail.attachments` | Each `{name, sha256, size}` |
| `mail.artifact_id` · `mail.url` | Its id as an artifact · its address in Nik |
| `from_mailbox` | The id of the mailbox it was imported from, or empty |
| `incident.…` | When it was analysed in an incident |

### file.analysed

**A file is analysed**: the analysis of a file ends (an upload, a file taken out of an e-mail or a capture, analysed again).

| Field | Holds |
| --- | --- |
| `file.sha256` · `file.name` · `file.size` · `file.type` | The file |
| `file.verdict` | `high`, `medium` or empty |
| `file.yara` | The names of the YARA rules that matched |
| `file.artifact_id` · `file.url` | Its id as an artifact · its address in Nik |
| `incident.…` | When it was analysed in an incident |

### code.analysed

**The disassembly of a file ends**, done or failed: after an upload, **Disassemble**, **Re-analyse** or a node, once for each run of it.

| Field | Holds |
| --- | --- |
| `file.…` | As for `file.analysed` |
| `code.status` | `done`, or `error` |
| `code.error` | What the worker said |
| `code.functions` · `code.imports` | How many functions · imported functions |

### capabilities.analysed

**capa ends on a file**, done or failed. A file capa does not read starts no event.

| Field | Holds |
| --- | --- |
| `file.…` | As for `file.analysed` |
| `capabilities.status` · `capabilities.error` | `done` or `error` · what the worker said |
| `capabilities.count` · `capabilities.names` | How many · their names |
| `capabilities.attack` | Their ATT&CK techniques (`T1055`…) |

### capture.analysed

**The analysis of a capture ends**, ready or failed: an upload, **Re-analyse**, new TLS keys, a file analysed as a capture, the log of a closed isolated browser session.

| Field | Holds |
| --- | --- |
| `capture.id` · `capture.name` · `capture.size` · `capture.sha256` | The capture |
| `capture.kind` | `pcap`, or `browser` for an isolated browser session |
| `capture.status` · `capture.error` | `ready` or `error` · what the worker said |
| `capture.packets` | How many packets |
| `capture.hosts` · `capture.domains` | The public addresses · the names |
| `capture.posts` · `capture.beacons` · `capture.objects` | How many POST requests · beacon-like connections · files |
| `capture.artifact_id` · `capture.url` | Its id as an artifact · its address in Nik |
| `incident.…` | When the capture is in an incident |

### url.analysed

**An address is scanned**: the scan of an address ends.

| Field | Holds |
| --- | --- |
| `scan.id` · `scan.url` · `scan.final_url` · `scan.host` | The scan, the address, where it led, its host |
| `scan.verdict` · `scan.score` | `phishing`, `suspicious` or `clean` · 0 to 100 |
| `scan.artifact_id` · `scan.page` | Its id as an artifact · its address in Nik |

## The system

### storage.low

**The disk is nearly full**: the disk that holds the evidence has less than a tenth free. Once a day while it stays so.

| Field | Holds |
| --- | --- |
| `disk.total` · `disk.used` · `disk.free` | Bytes |
| `disk.free_percent` | Free, in percent |

### artifact.expiring · artifact.expired

**An artifact with a date is a week from being deleted** (said once) · **An artifact was deleted because its date came**.

| Field | Holds |
| --- | --- |
| `artifact.id` · `artifact.kind` · `artifact.name` · `artifact.ref` | The artifact |
| `artifact.size` | Bytes |
| `artifact.expires_at` · `artifact.days_left` | Its date · days left |
| `artifact.url` | Its address in Nik |

## Other ways to start

| Started by | Fields |
| --- | --- |
| A person (**Run a playbook…**, **Run…**) | `actor` (who started it), and the fields of what it was run on: `incident.…`, `mail.…`, `file.…`, `scan.…` or `ioc.…` |
| A schedule | `at` (when it fired), `cron`, `due` (when it was due), `late_seconds`, `missed` (other times passed without a run) |
| A request from outside | `body` (an object for JSON, text otherwise), `headers` (content type, user agent, the sender's `X-` headers), `query` |

!!! info "Webhooks"
    Nik can also send events to an address of yours, signed, with no playbook: `/api/webhooks` in the [API](api.md).

## Related

- [Triggers and events](../guide/triggers.md)
- [Playbook nodes and expressions](playbook-nodes.md)
- [Your first playbook](../guide/playbooks.md)
- [API](api.md)
