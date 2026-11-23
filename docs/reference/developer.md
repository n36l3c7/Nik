# Developer guide

Run Nik from source, run its checks, and extend it: a new kind of evidence, detection rules, automation, connectors.

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

    The others follow the same pattern (`docview` 8720, `browser` 8730, `pcap` 8740, `sandbox` 8750). Each worker has its own checks: `cd workers/<name> && ruff check . && python -m pytest tests`.

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

## Add a new kind of evidence

`frontend/src/config/tabs.js` is the only existing file to change. Example: "DNS Logs".

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

3. **Nothing else is needed.** New incidents get the `dataKey`; existing ones get `defaultData` when loaded (`normalizeIncident()`), with no migration. To show a count under the kind's name, add it to `ITEMS` or `COUNTS` in `frontend/src/domain/evidence.js`. For uploads through the API, add a parser in `backend/app/parsing/`.

## Detection rules

Analysts edit keyword rules and business hours in the app. In code, the engine has three parts:

| File | Holds |
| --- | --- |
| `frontend/src/config/detectionRules.js` | Factory defaults: `DEFAULT_SUSPICIOUS_KEYWORDS`, `DEFAULT_BUSINESS_HOURS` (8 to 18, weekends outside) |
| `frontend/src/context/SettingsContext.jsx` | Runtime state (`useSettings()`) and `useSocEngine()` |
| `frontend/src/domain/soc.js` | `createSocEngine({ keywords, businessHours })` and `engine.analyze(entry)` |

A default keyword rule is an object; the regex is case-insensitive and applied to URL, title and file name:

```js
{
  id: 'rat-tools',
  label: 'RAT / C2',
  pattern: '\\brat\\b|cobalt[-_ ]?strike|meterpreter|\\bc2\\b',  // \\b avoids "administrator"
  severity: 'high',   // 'high' (red) | 'medium' (amber)
  description: 'References to a Remote Access Trojan or a C2 framework.',
},
```

A new kind of detection is a function in `soc.js`, included in `analyze()`, and shown as a badge in `EventsSection.jsx` (and in `computeSocStats` if it should count).

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
