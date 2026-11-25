# Playbook nodes and expressions

Every node of the canvas with its fields and outputs, the expression language, the context of an incident, and the playbook file.

For a guided start, see [Your first playbook](../guide/playbooks.md). Events are in [Events](events.md).

## Every node

Every node but the trigger has, in the inspector:

| Field | |
| --- | --- |
| **Name** | What the canvas shows (80 characters at most) |
| **Id** | What expressions call it: `{{ id.… }}`. A lower-case letter, then letters, digits or `_`, 32 at most; not a reserved name (`trigger`, `run`, `inputs`, `item`, `index`, `context`, `incident`). Renaming it updates the expressions that read it. |
| **Phase** | Groups the step in the work plan of an incident (*Triage*, *Containment*…) |
| **Goes to** | Its lines, port by port |
| **Gives** | Its outputs |

Nodes that can fail (actions, scripts, **Run another playbook**) also have **If it fails** (**Stop at once**, or **Try again** 1 to 100 times) and an **on error** port. A node of a connector has **Instance**. A node that changes something outside has **Approval before this node** (**Ask a person before this node runs**). **HTTP request** alone has **After a restart › Safe to repeat**.

## Flow nodes

### Trigger

Exactly one per playbook. See [Triggers and events](../guide/triggers.md).

| Field | Config key | |
| --- | --- | --- |
| **On an event** | `event` | One of the [events](events.md) |
| **Only when the event matches** | `conditions` | Comparisons, as a condition |
| **On a schedule** | `cron` | Five cron fields; every 5 minutes at most |
| **Time zone of the schedule** | `timezone` | Empty is UTC |
| **Starts from outside** | `webhook` | A `POST` to the playbook's address |
| **Can be run by hand** | `manual` | Offered in **Run a playbook…** |

Port: out.

### Condition

**All of** or **any of** a list of comparisons (left side, operator, right side). Ports: **yes**, **no**. Gives `result`.

| Operator | Key | Holds when |
| --- | --- | --- |
| **is** · **is not** | `eq` · `ne` | Equal; text without regard to case, `"82"` is `82` |
| **is more than** · **is at least** · **is less than** · **is at most** | `gt` · `gte` · `lt` · `lte` | As numbers when both read as numbers, as text otherwise |
| **contains** | `contains` | A text holds the other text, or a list holds an equal item |
| **is one of** | `in` | Equals one of the values on the right (commas, or a list) |
| **matches the pattern** | `matches` | A regular expression of 500 characters at most; one that takes too long counts as not matching |
| **is there** · **is empty** | `exists` · `empty` | Exists and not null · missing, null, empty text, list or object |

### For each

| Field | Key | |
| --- | --- | --- |
| **For each item of** | `items` | An expression giving a list |
| **At most** | `max` | 1 to 500; a longer list is cut |
| **Go on with the other items when one fails** | `continue_on_item_error` | Otherwise the loop fails |

Ports: **for each item** (the body, five items at a time), **when done**, **on error**. Inside the body: `{{ item }}`, `{{ index }}` (from 0). Gives `count`, `failed`, `results` (what the body's last step gave for each item). A for each cannot hold another for each, an approval, a task or a question. A step of the body is not readable after the loop: read `results`.

### Wait

**Wait for** a time (1 minute to 30 days, `seconds`), or **Wait until** a condition holds (`until`), looked at **Look again every** (`every`), up to **Give up after** (`timeout`). Gives `waited` (seconds), `timed_out`. A waiting run holds no worker.

### Approval

| Field | Key | |
| --- | --- | --- |
| **Question** | `question` | Required |
| **Detail** | `detail` | Shown under it |
| **Waits** | `wait_seconds` | **Without limit**, or **For** a time |
| **When the wait ends** | `on_expire` | **go on as refused** (`skip`), **refuse**, **stop the run** |

Ports: **approved**, **refused**. Gives `answer` (`approved`, `refused`, `expired`), `by`, `at`, `comment`. Never taken as approved by itself.

### Task

Gives a person something to do and waits until it is done.

| Field | |
| --- | --- |
| **What to do** | The title |
| **Instructions** | Markdown, shown on the task |
| **For** | A user, a role, or the owner of the incident (whoever has it when it is done) |
| **Fields to fill** | Fields of the incident, checked and written when it is done |
| **Due** | `30m`, `2h`, `3d`, seconds, or an expression giving one or a date (90 days at most) |
| **Reminder** | Tells again at this interval (5 minutes at least) |

Ports: **when done**, **when overdue** (the task stays to do). Gives `by`, `at`, `comment`, `fields`, `skipped`, `overdue`, `task`. A dry run takes **when done**.

### Question

Asks a person to choose, or fill a small form. **Question**, **Instructions**, **For** (a user, a role, the owner, anyone who works incidents), **Choices** (six at most, one port each; none: **answered**), **Asks for** (up to ten values: text, number, yes/no, read as `{{ node.values.name }}`), **Fields to fill**, **Waits**. Port **no answer** when the wait ends. Gives `choice`, `values`, `fields`, `by`, `at`, `comment`, `skipped`, `task`. A dry run takes the first choice.

### Run another playbook

**Playbook** (its name), **Inputs given to it**, **Wait for it to finish** (on by default). Gives `run` and `result` (the outputs the other declares). Five deep at most; a circle is refused at saving. A playbook's own **Inputs** (`{name, type, required}`) and **Outputs** (`{name, from}`) are set with no node selected.

### End

**The run ends as** done or failed, with a **Message** shown on the run. A run also ends, done, when no step is left.

## What a playbook does in Nik

The group **Nik** of the library. Each is also a [War Room command](../guide/commands.md#the-commands-nik-ships): the id with a dash for the dot.

| Node · id | Takes | Gives |
| --- | --- | --- |
| **Get an incident** · `nik.get-incident` | `incident` (the run's when empty) | `incident` (id, url, name, ticket, status, severity, assignee, host, username, os, created, modified), `fields` |
| **Add a note** · `nik.add-note` | `incident`, `text` | `note` |
| **Set the status** · `nik.set-status` | `incident`, `status` (open, in_progress, closed) | `incident` |
| **Assign the incident** · `nik.set-assignee` | `incident`, `assignee` (empty: nobody) | `incident` |
| **Set a field of the incident** · `nik.set-incident-field` | `incident`, `field`, `value` | `incident` |
| **Tag the incident** · `nik.add-incident-tags` | `incident`, `tags` | `tags`, `changed` |
| **Take tags off the incident** · `nik.remove-incident-tags` | `incident`, `tags` | `tags`, `changed` |
| **Create an incident** · `nik.create-incident` | `title`, `ticketId`, `host`, `username`, `severity` | `incident` |
| **Add indicators** · `nik.add-indicators` | `indicators`, `tags`, `note` | `added`, `known` |
| **Make indicators of a text** · `nik.make-indicators` | `text`, `type`, `tags`, `note`, `leave_out_harmless`, `incident` | `indicators` (`{type, value, new, marks}`), `created`, `linked`, `not_recognised` |
| **Tag indicators** · `nik.add-tags` | `indicators`, `tags` | `tagged` |
| **Add to a list** · `nik.add-to-ioc-list` | `list` (a watch list; made if missing), `indicators` | `added` |
| **Remove from a list** · `nik.remove-from-ioc-list` | `list`, `indicators` | `removed` |
| **Get the lists** · `nik.get-ioc-lists` | `watched` | `lists`, `names`, `count` |
| **Check a list again** · `nik.recheck-list` | `list`, `force` (on), `wait_minutes` (120) | `before`, `after`, `total`, `asked`, `finished`, `check` |
| **Get an indicator** · `nik.get-indicator` | `value`, `type` | `found`, `verdict`, `score`, `tags`, `lists`, `incidents`, `allowlisted` |
| **Reputation of an indicator** · `nik.reputation` | `kind` (ip, domain, url, file, email), `value` | `verdict`, `score`, `kind`, `value`, `sources`, `skipped` |
| **Scan an address** · `nik.scan-url` | `url`, `incident`, `again` | `scanned`, `verdict`, `score`, `url`, `final_url`, `redirected`, `redirects`, `title`, `password_form`, `findings`, `indicators`, `scan`, `artifact`, `page`, `summary` |
| **Read a list** · `list.get` | `list` | `items`, `count` |
| **Is it in a list?** · `list.contains` | `list`, `value` | `found` |
| **Add to a list** · `list.add` | `list`, `value`, `data`, `note`, `expires_minutes` | `added`, `count` |
| **Remove from a list** · `list.remove` | `list`, `value` | `removed` |
| **Set a list** · `list.set` | `list`, `items` | `count` |
| **Start a timer** · `timer.start` | `timer`, `incident`, `minutes`, `business_hours`, `restart` | `state`, `elapsed_minutes`, `due_minutes`, `breached` |
| **Pause a timer** · `timer.pause` · **Stop a timer** · `timer.stop` | `timer`, `incident` | as above |

- `nik.*-ioc-list` nodes work on the watch lists of the Indicators page; `list.*` nodes on the lists of **Platform settings › Lists**, and write only to a list marked *Playbooks may write to this list*.
- Tags of an incident follow the rules of a tag; done twice, nothing changes the second time.
- **Scan an address** visits only http(s), never a private address or internal name; the data guard judges the address; it waits for the visit (five seconds between looks, five minutes at most) without holding a worker. It needs the isolated browser (`BROWSER_URL`).

### Files and artifacts

Nothing is run or opened. A file is passed by reference: an argument `artifact` takes an id (`file-…`, `mail-…`, `pcap-…`, `url-…`), a SHA-256, or what a node gave (`{{ add_file }}`).

| Node · id | Takes | Gives |
| --- | --- | --- |
| **Add a file** · `nik.add-file` | `incident`; `artifact` (and `attachment` for an e-mail), or `content` with `encoding` (text, base64), `name`, `type`, `as` (file, mail) | `artifact`, `kind`, `name`, `type`, `size`, `sha256`, `verdict`, `score`, `tags`, `page`, `linked`, `known` |
| **Download a file** · `nik.download-file` | `url`, `incident`, `name`, `timeout` (120; 300 at most) | the artifact, `linked`, `status`, `content_type` |
| **Unpack an archive** · `nik.unpack-artifact` | `artifact` (a zip), `password`, `incident` | `artifact`, `files`, `count`, `skipped` |
| **Add host evidence** · `nik.add-evidence` | `incident`, `kind` (eventlogs, browser, commands, endpoint), `artifact` or `content`, `browser`, `profile`, `source`, `shell`, `category` | `rows`, `format`, `target` |
| **Link an artifact** · `nik.link-artifact` | `artifact`, `incident` | `linked` |
| **Take an artifact out of the incident** · `nik.unlink-artifact` | `artifact`, `incident` | `removed` |
| **List the artifacts of an incident** · `nik.list-artifacts` | `incident`, `kind`, `name` (`*.docx`) | `artifacts`, `ids`, `count`, `total` (200 at most) |
| **Get an artifact** · `nik.get-artifact` | `artifact` | `found`, the artifact, `incidents`, `expires`, `parents`, `children` |
| **Analyse an artifact** · `nik.analyse-artifact` | `artifact`, `as` (mail, capture), `incident`, `analysis` (static, code, capabilities), `wait` (on), `wait_minutes` (15; 1 to 120) | `asked`, `finished`, `started`, `skipped`, `verdict`, `artifact`, `kind`, `made`, `page`, `summary` |
| **Read an analysis** · `nik.get-analysis` | `artifact` | `found`, `status`, `verdict`, `score`, `summary`, `indicators`, `indicator_count`, `artifact`, `kind`, `name`, `page`, `file`, `mail`, `capture`, `scan` |
| **Tag an artifact** · `nik.add-artifact-tags` · **Take tags off an artifact** · `nik.remove-artifact-tags` | `artifact`, `tags` | `tags`, `changed` |
| **Set the expiry of an artifact** · `nik.set-artifact-expiry` | `artifact`, `expires` (a day, a number of days, or empty) | `expires`, `changed` |

??? info "Read an analysis: the four objects"
    Lists are cut at 100 items (50 attachments). The four objects are always there, empty for the other kinds.

    | Under | Holds |
    | --- | --- |
    | `file` | `sha256`, `sha1`, `md5`, `size`, `type`, `entropy`, `packed`, `yara`, `yara_severity`, `strings`, `code_status`, `functions`, `capabilities_status`, `capabilities`, `attack` |
    | `mail` | `subject`, `sender`, `sender_domain`, `spf`, `dkim`, `dmarc`, `findings`, `urls`, `attachments` (`{name, sha256, size, type, place}`) |
    | `capture` | `status`, `error`, `packets`, `hosts`, `domains`, `posts`, `beacons`, `objects` |
    | `scan` | `url`, `final_url`, `redirected`, `title`, `password_form`, `findings` |

A file is as large as an upload at most (`SAMPLE_MAX_MB`). **Download a file** is a `GET` with no credentials, to a host the playbook may reach (three redirects, each checked). An archive: zip only (plain, ZipCrypto, AES), 200 files at most. A dry run keeps nothing and starts nothing.

### Host evidence

Two read-only nodes of the group **Host evidence** (7.0) give a playbook the files and records of [host evidence](../guide/host.md). They change nothing, in a dry run too. A script cannot read Nik: the playbook reads, and hands the result to the script as arguments.

| Node · id · command | Takes | Gives |
| --- | --- | --- |
| **List the host evidence files of an incident** · `nik.list-evidence-files` · `nik-list-evidence-files` | `incident`; `kind` (eventlog, disk, endpoint, browser, commands, syslog, collection; empty for all); `partial` (only files read in part or failed) | `files` (each: `file`, `kind`, `name`, `size`, `sha256`, `host`, `user`, `state`, `read`, counts, `report`), `ids`, `count`, `total`, `records` |
| **Read host evidence records** · `nik.get-evidence-records` · `nik-get-evidence-records` | `incident`; filters `kind`, `type`, `file`, `source`, `host`, `username`, `channel`, `event_id`, `level` (1 to 5), `rule`, `flagged`, `q`, `from`, `to`; `order` (time, -time, file); `limit`; `cursor`; `fields` | `records`, `returned`, `next`, `count`, `count_capped` |

| Limit | Value |
| --- | --- |
| Files listed | 200 at most; `total` says how many matched |
| Records a page | 100 by default, 500 at most. `next` is the cursor to give back as `cursor`; it is empty at the end |
| `count` | Given on the first page; it stops at 100,001 (`count_capped`) |
| Data of a record | Not given unless `fields` names its keys: 12 at most, each value cut at 500 characters |

An incident that is archived has no records loaded: the node refuses it with a sentence. Take it out of the archive first. The values these nodes give carry the classes of internal names (a host, a user, a summary, the fields of a record), so a later [HTTP request](#http-request) that sends them out is held back by the data guard, as for any private value.

Example, in the War Room of an incident: its records with a detection of level high or critical, with two of their fields.

```text
!nik-get-evidence-records level=4 fields=CommandLine,ParentImage limit=50
```

### HTTP request

`http.request`: `method` (GET, POST, PUT, PATCH, DELETE), `url`, `headers`, `query`, `json` or `body`, `timeout` (60; 300 at most), `fail_on_error` (on). Gives `status`, `ok`, `json`, `text`. An answer over 5 MB is refused; three redirects, each checked. Anything but a GET asks for approval by default and is not repeated after a restart unless **Safe to repeat** is on.

### Commands of connectors

Each command of an installed connector is a node `<connector>.<command>`, with the arguments and outputs its file declares, and an **Instance**. A command marked *changes* asks first and is never sent in a dry run (the step gives its `sample`). See [Connector and pack format](connector-format.md).

The node **Send an e-mail** (`email.send`) is kept in the playbooks that have it and is not offered for new ones: use the commands of the Mail connector. The playbooks Nik ships use `mail.send` since 6.10.2; a copy added by an earlier release keeps its node, which still works.

## Expressions

Every text field takes values from the run between `{{ }}`. Type `{{` for suggestions, or press **{ }** (**Pick a value**).

```text
{{ trigger.incident.name }}
{{ search.recipients[*].office | unique | join(", ") }}
{{ args.urgency | default("3") }}
Phishing: {{ trigger.incident.name }} ({{ lookup.score }})
```

- **A path** starts with a name: `trigger`, a node's id, `item` and `index` in a for each, `inputs`, `run` (`id`, `url`, `playbook`, `started_at`, `dry_run`), and for a run on an incident `incident` and `context`.
- Then `.name`, `[0]` (`[-1]` the last), `["a key"]`, or `[*]` for every item (`recipients[*].office`).
- A field that is exactly one expression keeps its type (a number, a list). Mixed with text it is text; a list or object is written as JSON.
- A path that leads nowhere **fails the step**, unless `| default(…)` follows, or it is in `first_of(…)` or the condition of `if(…)`.
- A node reads only what is sure to have run before it: the trigger, and nodes every path to it passes through.
- An expression has at most 200 parts and 40 levels of parentheses; numbers stay within 10<sup>15</sup>.

### Filters

| Filter | Gives |
| --- | --- |
| `default("x")` · `default(other.path)` | The value, or the fallback when missing or null |
| `length` · `count` · `count("vip")` · `count("status", "gte", 400)` | How many items (characters, keys) · whose field is set · whose field compares so |
| `first` · `last` · `unique` · `sort` · `limit(10)` | Of a list (`limit` also of a text) |
| `join(", ")` · `split(",")` | A list as text · a text as a list |
| `pluck("name")` · `pick(name="attributes.name", id="id")` | A field of every item · new objects from fields |
| `where("vip")` · `where("size", "gt", 100)` | Items whose field is set · compares so (`eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `contains`, `in`, `exists`, `empty`) |
| `sort_by("date")` · `sort_by("score", "desc")` | Items in the order of a field |
| `get("a.b")` · `keys` · `values` · `entries` | A field by path · keys · values · `{key, value}` list |
| `has_any([...])` · `has_all([...])` · `intersect([...])` · `without([...])` · `union([...])` | Comparing lists, regardless of case |
| `lower` · `upper` · `trim` · `replace("a", "b")` · `starts_with("x")` · `ends_with("x")` | Of a text |
| `regex_extract("INC[0-9]+")` · `regex_extract("user=(\w+)", 1)` | The part a pattern finds, or one group |
| `map(high="1", low="3", else="2")` · `map("1", "open", "2", "closed")` | Another value for each value named |
| `int` · `float` · `bool` · `json` | Conversions (`"no"`, `"0"`, `"off"` are false) |
| `round` · `round(2)` · `abs` · `add(1)` · `sum` · `min` · `max` · `percent(total)` | Numbers |
| `plural("report")` · `plural("entry", "entries")` | `1 report`, `2 reports` |
| `date` · `date("%d/%m/%Y")` · `timestamp` · `date_diff(other, "hours")` · `date_add(-90, "minutes")` | Dates (ISO 8601 or seconds since 1970, UTC) |
| `severity` · `severity("inverse")` | Another product's severity as Nik's (`low`…`critical`); a word, 1–5, or 0–100 |
| `urlencode` · `base64url` · `sha256` · `defang` | For addresses and APIs; `defang` gives `hxxp[://]evil[.]example` |
| `in_list("internal_domains")` | Whether the value is in a list of **Lists** |

### Deciding and counting

| Written | Gives |
| --- | --- |
| `==` `!=` `<` `<=` `>` `>=` | True or false, compared as a condition does. One comparison at a time |
| `and` · `or` · `not` | `a or b` is `a` when it counts as yes, else `b` |
| `x in [...]` · `x not in [...]` | Item of a list, part of a text, key of an object |
| `+` `-` `*` `/` `( )` | Numbers only (a number that came as text goes through the `int` filter first). Dividing by zero fails the step |
| `a ~ b` | Text joined |
| `if(cond, then, otherwise)` | Only the chosen value is read |
| `first_of(a, b, "x")` | The first value not missing, null or empty |
| `min(a, b)` · `max(a, b)` | Of several numbers, or of a list |

```text
{{ if(response.stats.malicious >= 3, "malicious", "unknown") }}
{{ response.stats.malicious }}/{{ response.stats | values | sum }} engines flag it
{{ first_of(response.malware, response.threat_type, "known IOC") }}
```

A filter applies to the value just before it: `a + b | round` rounds `b`; `(a + b) | round` rounds the sum. What an expression computes carries the classes of data of everything it was computed from.

## The context of an incident

A run on an incident reads `{{ incident.… }}` (its fields by name: `incident.severity`, `incident.tags`, `incident.business_unit`) and `{{ context.… }}`, in Nik's common schema. `{{ trigger.incident.… }}` is the incident as it was when the run started. The **Context** tab of an incident shows both, with **Copy the path**.

| Entity | Keys | Told apart by |
| --- | --- | --- |
| `File` | `Name`, `Size`, `Type`, `MD5`, `SHA1`, `SHA256`, `Path`, `Verdict`, `Score` | `SHA256` |
| `Mail` | `MessageID`, `Subject`, `From`, `To`, `Date`, `Verdict`, `Score`, `Recipients` | `MessageID` |
| `URL` | `Data`, `Host`, `Verdict`, `Score` | `Data` |
| `IP` | `Address`, `ASN`, `Geo`, `Verdict`, `Score` | `Address` |
| `Domain` | `Name`, `Registrar`, `Created`, `Verdict`, `Score` | `Name` |
| `Host` | `Name`, `IP`, `OS`, `Domain`, `AgentID`, `Isolated` | `Name` |
| `Account` | `Username`, `Email`, `DisplayName`, `Disabled` | `Username` |
| `Ticket` | `ID`, `Number`, `System`, `URL`, `Status` | `ID` |
| `Alert` | `ID`, `Name`, `Severity`, `Source`, `URL`, `Time` | `ID` |
| `Process` | `Name`, `PID`, `CommandLine`, `Host`, `SHA256` | `PID` and `Host` |
| `Rule` | `Name`, `ID` | `Name` |

A connector's own values go under `context.ext.<connector>.<name>`. A key not in the table is refused.

A command or a script writes to the context with a **context path**:

| Path | Does |
| --- | --- |
| `Ticket` | Adds the object; merged over the item with the same telling key |
| `Ticket(val.Number == obj.Number)` | The same, told apart by the key named (several joined by `&&`) |
| `Ticket.Status` | Sets one key on the item, when there is exactly one |
| `ext.<connector>.<name>` | A value of that connector's own |
| `incident.<field>` | Sets a field of the incident, through the registry |

Nothing is written in a dry run, or by a run on no incident. A context is 4 MB at most.

## The playbook file

**Export** gives this JSON; **Import** brings it back as a draft, off.

```json
{
  "app": "Nik", "type": "playbook", "version": 1,
  "playbook": {
    "name": "Note on high", "description": "",
    "maxRunsPerHour": 60, "onePerObject": true, "maxSeconds": 86400, "approvalDefault": true,
    "graph": {
      "nodes": [
        { "id": "start", "kind": "trigger", "name": "Trigger", "position": { "x": 40, "y": 40 },
          "config": { "event": "incident.created", "manual": true } },
        { "id": "check", "kind": "condition", "name": "High?", "position": { "x": 40, "y": 150 },
          "config": { "all": [{ "left": "{{ trigger.incident.severity }}", "op": "in", "right": ["high", "critical"] }] } },
        { "id": "note", "kind": "action", "name": "Add a note", "position": { "x": 40, "y": 260 },
          "config": { "action": "nik.add-note", "args": { "text": "Severity {{ trigger.incident.severity }}" } } }
      ],
      "edges": [
        { "from": "start", "to": "check" },
        { "from": "check", "port": "yes", "to": "note" }
      ],
      "inputs": [], "outputs": []
    }
  }
}
```

| Key | Meaning |
| --- | --- |
| `nodes[].kind` | `trigger`, `condition`, `for_each`, `wait`, `approval`, `task`, `ask`, `action`, `script`, `playbook`, `end` |
| `config` of an action | `action`, `args`, `on_error` (`{"mode": "stop"}` or `{"mode": "retry", "times": 3}`), `approval` (`{"ask": true, "wait_seconds": 3600, "on_expire": "skip"}`), `safe_to_repeat` (`http.request` only) |
| `config` of a script | `script`, `script_version`, `args`, `on_error` |
| `config` of a playbook node | `playbook`, `args`, `wait`, `on_error` |
| `config` of an end | `status` (`done`, `failed`), `message` |
| `edges[]` | `from`, `to`, `port`: `out` (left out), `yes`/`no`, `each`/`done`, `approved`/`refused`, `done`/`overdue`, an answer of a question/`timeout`, `error` |

A script file has `"type": "script"` and, under `script`: `name`, `description`, `code`, `arguments`, `outputs`, `test` (`args`, `expect`). Everything here is also in the [API](api.md).

## Related

- [Your first playbook](../guide/playbooks.md)
- [Triggers and events](../guide/triggers.md)
- [Events](events.md)
- [Connector and pack format](connector-format.md)
- [Scripts and the Playground](../guide/scripts.md)
