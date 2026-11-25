# Developer guide

Run Nik from source, run its checks, and extend it: a parser of host evidence, Sigma rules and log sources, a tab, automation, connectors.

!!! warning "Never run a sample"
    Nothing in this project executes evidence. Never run a sample to see what it does, on your machine or on a server that runs Nik.

## Local development

You need **Python 3.12** and **Node.js 22.12 or later** (20.19 also works). No database server: the backend defaults to a SQLite file. The PDF report needs the Pango libraries (Debian/Ubuntu: `apt install libpango-1.0-0 libpangoft2-1.0-0`; Fedora/RHEL: `dnf install pango`; macOS: `brew install pango`); everything else works without them.

=== "Backend (terminal 1)"

    ```sh
    cd backend
    python -m venv .venv
    source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
    pip install -r requirements-dev.txt
    cp .env.example .env               # then set COOKIE_SECURE=false in it
    uvicorn app.main:app --reload --port 8000
    ```

    `curl http://localhost:8000/api/health` answers `{"status":"ok"}`. Without `COOKIE_SECURE=false` the browser drops the cookie over plain HTTP and sign-in does not stick.

=== "Frontend (terminal 2)"

    ```sh
    cd frontend
    npm ci
    npm run dev                        # http://localhost:5173
    ```

    Vite proxies `/api` to `http://127.0.0.1:8000`. Create the first account on first load: it becomes the admin.

`AUTOMATION_WORKER=inline` in `backend/.env` runs playbooks inside the API process.

??? info "A worker in development"
    Each worker is a container. For the Code view:

    ```sh
    docker build -t nik-analyzer workers/analyzer
    docker run -d --name nik-analyzer -p 127.0.0.1:8700:8700 -e ANALYZER_TOKEN=dev-token nik-analyzer
    # backend/.env: ANALYZER_URL=http://127.0.0.1:8700  ANALYZER_TOKEN=dev-token
    ```

    For capabilities:

    ```sh
    docker build -t nik-capa workers/capa
    docker run -d --name nik-capa -p 127.0.0.1:8710:8710 --read-only --tmpfs /tmp -e CAPA_TOKEN=dev-capa-token nik-capa
    # backend/.env: CAPA_URL=http://127.0.0.1:8710  CAPA_TOKEN=dev-capa-token
    ```

    The others follow the same pattern (`docview` 8720, `browser` 8730, `pcap` 8740, `sandbox` 8750, `forensics` 8760 with `FORENSICS_TOKEN`; the backend's `.env` then has `FORENSICS_URL` and `FORENSICS_TOKEN`: without them host evidence is kept and not read). Each worker has its own checks: `cd workers/<name> && ruff check . && python -m pytest tests`.

## Checks

A change is done when all of this passes, as CI runs it:

```sh
# Backend
cd backend && ruff check . && ruff format --check . && pytest -q

# Frontend
cd frontend && npm run lint && npm run format:check && npm test && npm run build
npm run test:e2e        # the whole app in a browser (needs the backend's venv on PATH)
```

| Script (`frontend/`) | Does |
| --- | --- |
| `npm run dev` / `build` / `preview` | Dev server; production build in `dist/`; serve the build |
| `npm test` | Unit tests (Node's built-in runner) |
| `npm run lint` | ESLint; must report nothing |
| `npm run format` / `format:check` | Prettier on the app, `docs/`, `.github/` and the Compose file |
| `npm run test:e2e` | Playwright: first-run setup, sign-in, a new incident, the fixtures of `frontend/e2e/fixtures/` dropped on the app |

The end-to-end test needs `npm run build`, the backend's dependencies and `npx playwright install chromium`. With a worker running and its pair set (`E2E_ANALYZER_URL` / `E2E_ANALYZER_TOKEN`, and the same for `CAPA`, `DOCVIEW`, `BROWSER`, `PCAP`, `SANDBOX`), it also checks that view against the real worker; without them it checks the "not configured" messages.

**CI** (`.github/workflows/ci.yml`) runs on every pull request: `lint` (Ruff on the backend and workers), `backend-tests` (SQLite) and `backend-postgres` (PostgreSQL 18 after `alembic upgrade head`), `frontend-build`, `stack` (`.github/scripts/stack-smoke.sh`: the real stack, HTTPS redirect, headers, unprivileged backend, refusal of example secrets), and `e2e` (the five worker images, their tests inside them, then the end-to-end suite). **Audit** (`.github/workflows/audit.yml`) runs `pip-audit`, `npm audit --audit-level=high` and `shellcheck` on every pull request and every Monday, and a Trivy scan of every image on Mondays.

Line endings are LF everywhere (`.gitattributes`). Formatting is enforced: run the formatters before committing.

## A change

- **Tests** for what it adds or fixes; a fix comes with the test that failed before it.
- **Documentation in the same change**: this site (MkDocs, under `docs/`; preview with `pip install -r requirements-docs.txt && mkdocs serve`) and the README.
- **A changelog entry** under `[Unreleased]` in `CHANGELOG.md`.
- **English** everywhere. No new dependency without a reason (why, maintained, licence).
- A commit message is a plain sentence that says what changed. One pull request does one thing; it is squashed.
- A vulnerability is not an issue: see [Reporting a vulnerability](security.md#reporting-a-vulnerability).

## Writing a migration

In the container, migrations run through `python -m app.backups.upgrade`: snapshot, rehearsal on a copy, then the database ([Upgrades](../admin/upgrades.md#what-happens-at-start)). So:

1. A migration adds only what is missing, so it can run twice.
2. A column added to a table with rows is nullable or has a server default.
3. A migration does not touch the files of the store. One that must says so in its docstring and the release notes, sets `touchesStore` in the facts the upgrade records (`_snapshot` in `backend/app/backups/upgrade.py`) and takes the snapshot as a full backup; otherwise `deploy/rollback.sh` refuses to put the database back alone.
4. A migration that adds a view, a trigger or a function also teaches the backups to carry it (`backend/app/backups/database.py`).

## Add a parser of host evidence

A parser is a module of the forensics worker: `workers/forensics/nik_forensics/parsers/<name>.py`. The worker runs each file in a process of its own and streams what the parser says; the backend turns it into rows and into the parse report. Read `parsers/__init__.py` (the interface), `context.py` (what a parser can say) and one parser near yours: `evtx.py` for a binary format with a scanner and a viewer, `endpoint.py` for CSV and SQLite artifacts, `history.py` for a text log.

| A module has | What it is |
| --- | --- |
| `NAME`, `VERSION` | Its name (what `evidence_sources.parser` keeps) and a text that **changes when what it gives for the same file changes**: a file read by an older version offers **Analyse again** |
| `KIND` | The section its records show in: `eventlog`, `endpoint`, `browser`, `commands`, `disk`, `syslog` |
| `SOURCES` | Every source it reads, as the section names them (`windows.execution.prefetch`) |
| `sniff(path, name, head)` | The source the file is, from its first 4,096 bytes and its name, or `None`. Content first, name second; cheap, never raises; **never guess a CSV** |
| `parse(path, ctx, source)` | Read the file and tell `ctx`: `ctx.source(…)` first, then `ctx.record(…)`, `ctx.skip(…)`, `ctx.note(…)`, and `ctx.end(in_file=…)` |
| `view(path, source, loc)` | Show the piece of the original a record came from, from the `loc` the parser wrote for it: `{"kind": "xml" \| "fields" \| "text" \| "json", "title", "where", …}`. Read around the place, never the whole file when the format lets it be found |

Add the name to `NAMES` in `parsers/__init__.py`, in the order files are tried when they come with no source. A parser imports a heavy library inside its functions: when it is missing, only that parser fails to load.

### What a parser must do

The integrity contract of 7.0: a file is never reported as read when it was not.

1. **Count what is in the file by a means independent of the library** when the format allows (a scanner over the structure: entries, cells, records) and give it to `ctx.end(in_file=…)`. What the library drops silently is found by comparing the counts, and said.
2. **`ctx.skip(reason, offset=, length=, lost=, detail=)` only when data was lost** (an unreadable record, a damaged block, a limit hit): the file becomes **read in part**. **`ctx.note(reason, count=, detail=)`** for what loses nothing (rows without a time, empty slots, a state that is dirty but readable). A reason is a short lower-case sentence an analyst understands; reuse the words of the existing parsers.
3. **Keys are stable natural keys**: the same record read twice, or from an overlapping file, has the same key (`mft:<volume or host>:<entry>:<sequence>`, `usn:<host>:<usn>`, `reg:<host>:<hive>:<key path>:<value>`). Never a counter of the run. 300 characters at most (`ctx.key_of`). Flags and notes are kept by key.
4. **Times** are epoch milliseconds, UTC. A record with several times uses the one that matters most for a timeline as `ts` and keeps the others in `data` under clear names.
5. **`loc`** is what `view` needs to find the record again (offsets, entry numbers, a key path): small.
6. **Indicators** only from fields that are indicators (`ioc=[[type, value]]`: hashes of an Amcache, addresses and domains of a network record), never from free text.
7. **Limits.** A job has memory and CPU limits ([`FORENSICS_JOB_MEMORY_MB`](configuration.md#FORENSICS_JOB_MEMORY_MB)): stream, never load a whole large file (`mmap`, chunked reads), and when a cap is hit, `skip` with what was left out.
8. **Every source gets its hint**: where the file is on the system and how to collect it. The pages show it in the empty state ("where to find these files").
9. A parser that cannot go on raises: what it said is kept, and the file is reported read in part.
10. A record that also is a process or a logon is said with `ctx.process(…)` and `ctx.logon(…)` (stage 7 parsers: evtx, syslog); the backend links them.

### Tests and fixtures

- Tests are in `workers/forensics/tests/test_<name>.py`; run them with the worker's checks: `cd workers/forensics && ruff check . && python -m pytest tests`, in a container for the worker's own dependencies.
- **Generated fixtures only**, built by the test or by a small generator kept in `tests/` (`artifact_gen.py`, `hive_builder.py`, `ntfs_fixtures.py`), or a tiny real sample with a permissive licence recorded in `tests/fixtures/README.md` (name, origin, licence, how it was made). No network in tests. Never execute a sample.
- Test the contract, not only the happy path: the count in the file against the records read, a damaged block that makes a `skip`, a stable key when the file is read twice, `view` from a `loc`, and a record cut by `MAX_VALUE`.
- **No GPL or AGPL dependency**, and none of the `dissect.*` packages. A new library needs a permissive or LGPL licence, wheels for x86_64 and aarch64, and a line in the changelog.
- Say in the page's box **What Nik has and has not been tried on** whether the parser was proved on real files or on generated ones.

The page that shows the records is not a new tab: it reads the tables with the shared components (`Tabs`, `SourceFiles`, `ServerTable`, the source viewer, `StackPanel`) and the API under [Host evidence](api.md#host-evidence).

## Add a tab for another kind of data

Evidence that is not host evidence (a kind of your own that lives in the incident document) is registered in `frontend/src/config/tabs.js`. Example: "DNS Logs".

1. **Create the component** `frontend/src/components/tabs/DnsLogsTab.jsx`. It receives the incident and stores its data with `updateTabData`:

    ```jsx
    import { useIncidents } from '../../context/IncidentContext.jsx'
    import { generateId } from '../../lib/id.js'
    import { Card, DataTable, EmptyState } from '../ui/index.js'
    import { formatDateTime, anyToMs } from '../../lib/time.js'

    export default function DnsLogsTab({ incident }) {
      const { updateTabData } = useIncidents()
      const dns = incident.data.dns ?? { queries: [], meta: null }

      async function handleFile(file) {
        const rows = JSON.parse(await file.text()) // [{ timestamp, domain, type, client }]
        const queries = rows.filter((r) => r.domain).map((r) => ({
          id: generateId(), domain: r.domain, type: r.type ?? 'A',
          client: r.client ?? null, timestamp: anyToMs(r.timestamp),
        }))
        updateTabData(incident.id, 'dns', {
          queries,
          meta: { fileName: file.name, format: 'json', rows: queries.length, importedAt: new Date().toISOString() },
        })
      }

      if (dns.queries.length === 0) return <EmptyState title="No DNS logs loaded" /* … upload button calling handleFile */ />
      return (
        <Card title="DNS queries">
          <DataTable
            data={dns.queries}
            searchKeys={['domain', 'client']}
            defaultSort={{ key: 'timestamp', dir: 'desc' }}
            columns={[
              { key: 'timestamp', label: 'Date/Time', sortable: true, render: (row) => formatDateTime(row.timestamp) },
              { key: 'domain', label: 'Domain', sortable: true },
              { key: 'client', label: 'Client' },
            ]}
          />
        </Card>
      )
    }
    ```

2. **Register it** in `frontend/src/config/tabs.js`, inside `ANALYSIS_TABS`:

    ```js
    const DnsLogsTab = lazy(() => import('../components/tabs/DnsLogsTab.jsx'))

    {
      id: 'dns',              // unique: also the address of the kind
      evidence: true,         // listed in the Evidence tab (without it: a tab of the bar)
      label: 'DNS Logs',
      group: 'threats',       // 'threats' | 'host'
      icon: Network,          // a lucide-react icon
      component: DnsLogsTab,  // lazy: a separate build chunk
      dataKey: 'dns',         // key under incident.data
      defaultData: { queries: [], meta: null },
    },
    ```

3. **Nothing else is needed.** New incidents get the `dataKey`; existing ones get `defaultData` when loaded (`normalizeIncident()`), with no migration. To show a count under the kind's name, add it to `ITEMS` or `COUNTS` in `frontend/src/domain/evidence.js`.

!!! note "A tab is not the way for a big file"
    Data in the incident document is read and written whole with the document. A file that is large, that must keep its original, or that needs a report and a viewer is **host evidence**: a parser, above.

## Sigma rules and log sources

Detection on host evidence is Sigma, run by the worker (`workers/forensics/nik_forensics/sigma/`). Analysts write rules in **Settings › Rule sets › Sigma rules**; the rules Nik ships are the files of `backend/app/sigma/pack/` (the **Nik** pack) and `backend/app/sigma/pack_chains/` (**Nik process chains**).

A built-in rule is a Sigma YAML file with a fixed `id` (a UUID: it is how a rule is found again), a `title`, a `level` (`informational` to `critical`; none means medium), and `logsource`. A correlation rule names the rules it counts by a `name` they carry.

| Part | Where | What it does |
| --- | --- | --- |
| `sigma/logsource.py` | the worker | Which records a `logsource` applies to: `CATEGORY` (Sigma categories to a channel and event ids), `SERVICE` (services to channels), the products `windows`, `linux`, `macos` and Nik's own `nik` (`commands`, `endpoint`, `browser`, `process-chain`). A record is placed by `(kind, channel, event_id)` |
| `sigma/compile.py`, `engine.py` | the worker | pySigma parses a rule; Nik's evaluator compiles the detection to checks on the record's fields and runs it. The field `NikOffHours` is true outside the working hours |
| `sigma/correlate.py` | the worker | The correlations `event_count`, `value_count`, `temporal` and `temporal_ordered`, one level of nesting, per file |
| `backend/app/sigma/` | the backend | The rules in the database, the packs, the `try` and the `recheck`, and the detections it writes |

To add a **log source**:

1. In `logsource.py`, add the category or service to its table with the channels and event ids (or the `extra` condition on a field) a record has. A log source whose records Nik cannot make raises `NoRecords` with the sentence an analyst reads in the list of rules that cannot run.
2. If the records come from a new parser, make sure it gives the fields the rules name, with the names of Sigma (the evaluator gives a Security event the field names of the Sysmon event it is equivalent to, so one rule serves both).
3. Add rules to the pack, a test in `tests/test_sigma_*.py` that runs one record through the rule and one that must not match, and, if the pack grows, the count in the pack test.
4. **A rule that is a Sigma rule of SigmaHQ is not copied into the repository**: its licence (Detection Rule License 1.1) asks that its author be named. It is a content pack to install, with a `notice`.

A **content pack** carries Sigma rules in a `sigma/` folder, one rule document in each `.yml` ([The pack format](connector-format.md#the-pack-format), `packs/README.md`).

## Extend automation

| To add | Where |
| --- | --- |
| An action inside Nik | A function in `backend/app/automation/nik_actions.py` under `@action("nik.<verb>", …)`. It gets a `Call` and returns a `Result`; in a dry run it changes nothing and says what it would do. The node form is built from its `arguments` |
| Anything that connects | Through `automation/egress.py`, after `guard.check` on what it sends. A test fails if another module opens a socket |
| A connector | `packs/<pack>/connectors/<id>/connector.yml` in the [connector format](connector-format.md); raise the pack's `version` in `pack.yml`. For each command, `backend/tests/data/connectors/<id>/<command>.json` records the exchange, and `connection.json` the test connection; `tests/test_shipped_connectors.py` fails for a command without one. Keep `verified: false` until run against the product |
| A fetch or a mirror | The keys `fetch`, `schema`, `mirror` in the connector file, a mapper in `packs/<pack>/mappers/<id>.json`, and `fetch.json` beside the command fixtures |
| A shipped playbook, script or dashboard | `backend/app/automation/seed/playbooks/`, `seed/scripts/` (with a `test`), `seed/dashboards/`; each is exercised by the suite |
| A system field or field type | `SYSTEM_FIELDS` / `TYPES` in `backend/app/fields.py`; in the frontend `domain/fields.js` and `components/fields/FieldInput.jsx` |
| An entity of the context | `SCHEMA` and `CLASSES` in `backend/app/context.py`; a product's own names go under `ext` |
| A node a person answers | `PORTS` in `backend/app/automation/graph.py` and `frontend/src/domain/automation/graph.js`, checks in `_check_node`, a branch of `_perform` returning `Outcome(wait=…)` |
| A setting that is a list | `BUILTIN` in `backend/app/lists.py`, read with `lists.settings_value` |
| A widget | `TYPES` and `GROUPS` in `backend/app/dashboards.py` and `frontend/src/domain/dashboards.js`, drawn in `components/dashboards/Widget.jsx` |
| An entity of the query language | An `Entity` in `backend/app/query/entities.py`, and its entry in `ENTITIES` of `domain/dashboards.js` |
| A kind of pack item | `KINDS`, `LABELS` and the branches of `backend/app/packs.py` |
| An event | A builder in `payloads.py`, a function in `triggers.py`, its name in `graph.EVENTS`, `events.KNOWN_EVENTS` and `frontend/src/domain/automation/catalog.js` ([Events](events.md)) |
| A filter of the expression language | Both `backend/app/automation/expressions.py` and `frontend/src/domain/automation/expressions.js`, with vectors in `backend/tests/data/expressions.json` |
| A route | A line in `backend/tests/test_permissions_matrix.py`: the suite walks every route with a key of each role |

The engine's tests move the clock themselves (`worker.drain(now)`) and need no worker running.

??? info "Browsers, parsers and timestamps"
    Browsers are a registry in `frontend/src/config/browsers.js`: an entry of `BROWSERS` (`id`, `label`, `icon`, `engine` `chromium` | `firefox` | `safari`, `platforms`, `profilePaths`, `sources`) wires the sub-tab, upload and path hints. A Chromium browser can reuse `chromiumSources(bases)`; a new engine also needs a parser branch, and one in `backend/app/parsing/` for API uploads.

    All parsing goes through `parseBrowserSource(file, engine, source)` in `frontend/src/parsers/fileParsers.js`: SQLite (detected by magic) to `sqliteParser.js`, property lists to `plistParser.js` and `safariParser.js`, otherwise JSON or CSV. Field mapping takes aliases (extend the `*_ALIASES` chains); a new format is a branch before the CSV fallback.

    Mind the engine's time: Chromium uses µs since 1601 (`webkitToMs`), Firefox µs since 1970 (`firefoxToMs`), Safari seconds since 2001 (`macToMs`). The wrong helper shifts dates by about 369 years.

## The UI kit

Components live in `frontend/src/components/ui/`, re-exported from `index.js`:

```js
import { Button, Card, Badge, Modal, DataTable, EmptyState, ErrorBoundary,
         SearchInput, Select, StatCard, AsciiSkull, MicroSkull } from '../ui/index.js'
```

| Component | Use |
| --- | --- |
| `DataTable` | Every table: `columns`, `data`, `searchKeys`, `defaultSort`, `defaultPageSize`, `rowClassName`, `toolbar`, `emptyMessage`. Filter, sort and paginate inside |
| `Button` | `variant` `primary` \| `secondary` \| `ghost` \| `danger`; `size` `md` \| `sm` \| `xs`; `icon` |
| `Card`, `Modal`, `EmptyState` | A titled panel; a dialog (Escape and backdrop close it); an empty state with an icon or a skull |
| `Badge` | `color` `slate` (neutral), `cyan` (info), `red` (HIGH), `amber` (MED), `emerald` (ok), `violet` |
| `ErrorBoundary` | Keeps a rendering error inside its view, with a **Reload this view** button; pass a `resetKey` |
| `AsciiSkull`, `MicroSkull` | Loading, error and empty states |

Colours are tokens declared once in `frontend/src/index.css` (`@theme`): `sunken`, `canvas`, `panel`, `raised` (surfaces), `line`, `fg`, `fg-muted`, `fg-subtle`, `accent` (the green prompt), `link`, `info`, `high`, `med`, `violet`. Use the token utilities (`bg-panel`, `text-fg-muted`), never raw palette classes. Corners are square; JetBrains Mono for data and labels, Inter for prose; both fonts are bundled. A flagged row uses the accent, a detection its severity, so a flag never looks like a detection.

## The incident JSON format

**Export** (`exportIncident(id)`, the incident's export button) downloads `nik-<name>.json`:

```json
{
  "app": "Nik",
  "version": 4,
  "exportedAt": "2026-07-07T11:30:00.000Z",
  "incident": {
    "id": "b3f1c9e2-…",
    "host": "WKS-FINANCE-01",
    "username": "m.rossi",
    "name": "WKS-FINANCE-01 - m.rossi",
    "suspiciousStart": 1751871120000,
    "suspiciousEnd": 1751899999000,
    "createdAt": "2026-07-01T09:00:00.000Z",
    "updatedAt": "2026-07-07T11:29:58.000Z",
    "createdBy": "analyst",
    "data": {
      "browser": {
        "activeBrowser": "chrome",
        "browsers": {
          "chrome": { "activeProfile": "default", "profiles": { "default": {
            "id": "default", "name": "Default",
            "history":   [ { "id": "…", "url": "https://…", "title": "…", "visitTime": 1751871120000 } ],
            "downloads": [], "bookmarks": [], "shortcuts": [],
            "meta": { "history": { "fileName": "History", "format": "sqlite", "rows": 1240 } }
          } } }
        }
      },
      "network": {}, "endpoint": {}
    },
    "flags": { "<eventId>": { "flaggedAt": "…", "flaggedBy": "…", "comments": [] } },
    "notes": [ { "id": "…", "text": "…", "createdAt": "…", "author": "…" } ]
  }
}
```

`data` has one key per kind of evidence (`dataKey` in `tabs.js`). Every entry timestamp is Unix epoch in milliseconds.

**Import** (`importIncidentFromFile(file)`) accepts that envelope (version 4, or 3 and older, whose browser data lands in a "Default" profile) or a bare incident. The incident always gets a **new id** (importing twice makes two copies), is filled with the defaults of newer kinds, saved with `POST /api/incidents`, and recorded as `incident.import`. It is an exchange format between installations, not a backup ([Backups](../admin/backups.md)).

## Related

- [Architecture](architecture.md) — what runs where, the data model
- [Connector and pack format](connector-format.md)
- [Playbook nodes and expressions](playbook-nodes.md)
- [API](api.md)
- [Security](security.md) — what a change must not weaken
