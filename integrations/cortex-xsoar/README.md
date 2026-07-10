# Nik — Cortex XSOAR integration

A custom Cortex XSOAR / XSIAM integration that drives the **Nik** forensic
analysis platform through its REST API. Use it to query and manage incidents,
add/remove notes, upload artifact files for server-side parsing, and read the
audit log and detection settings — and optionally pull Nik incidents into XSOAR.

Files in this folder:

| File | Purpose |
|---|---|
| `Nik.py` | Integration code (the `Client` + command handlers). |
| `Nik.yml` | Integration definition: configuration, commands, **arguments** and **outputs** (context paths). |
| `README.md` | This document. |

## Install

Cortex XSOAR wants a **single YAML** that embeds the script. Two options:

- **Recommended (demisto-sdk):** from this folder run
  `demisto-sdk unify -i .` to produce `integration-Nik.yml` with the code
  inlined, then upload it (*Settings → Integrations → Import*), **or**
- **Manual:** in *Settings → Integrations → BYOI → Create*, paste the contents
  of `Nik.yml` into the details and `Nik.py` into the code editor.

Target Cortex XSOAR **6.5+** (or XSIAM). The script runs on the `demisto/python3`
Docker image; no extra Python packages are needed.

## Configure an instance

| Parameter | Description |
|---|---|
| **Server URL** | Base URL of the Nik web app, e.g. `https://nik.example.internal:8443`. The API is served under `/api` on the same host. |
| **API Key** | A Nik API key (create it in Nik under *Settings → API keys*). Sent as the `X-API-Key` header. |
| **Trust any certificate** | Enable when Nik uses a self-signed certificate. |
| **Use system proxy** | Route calls through XSOAR's proxy. |
| **Fetch incidents / First fetch / Max per fetch** | Optional: pull Nik incidents into XSOAR (see *Fetch* below). |

### Permissions (which key to use)

A Nik key carries a **role** and **scopes** chosen at creation:

- An **analyst** key (read+write) covers everything below except `nik-get-audit`
  cleanup and any future admin-only endpoint. This is the right key for most
  playbooks.
- A **read-only** key (`scopes: ["read"]`) can run only the `nik-get-*` commands;
  write commands (create/update/delete/note/upload) return `403`.
- An **admin** key is required only if you later call admin-data endpoints
  (users/backup). None of the commands here need admin except reading is always
  allowed. Prefer the **least-privilege** key that a given playbook needs, and
  set an **expiry** on it.

Run **Test** after configuring — it performs an authenticated request and
reports clearly if the URL or key is wrong.

## Commands

All outputs are written under the `Nik.*` context prefix (see `Nik.yml` for the
exact `contextPath`, type and description of every field).

### `nik-get-incidents`
List incidents, newest-updated first.

| Argument | Description |
|---|---|
| `query` | Match name/host/username (free text). |
| `host`, `username` | Filter by host / username (substring). |
| `view` | `summary` (light rows, default) or `full` (whole documents). |
| `limit`, `offset` | Pagination. |

**Context:** `Nik.Incident` (array) — `id`, `name`, `host`, `username`, `os`,
`createdAt`, `updatedAt` (with `view=full` also `flags`, `notes`, `data`, …).

### `nik-get-incident`
Return one incident's **full document**.

| Argument | Description |
|---|---|
| `incident_id` *(required)* | The incident id. |

**Context:** `Nik.Incident` — full document including `suspiciousStart/End`,
`createdBy`, `flags`, `notes` and parsed `data`.

### `nik-create-incident`
Create an incident (the server assigns a UUID v4 id).

| Argument | Description |
|---|---|
| `name` | Display name (derived from host/username if omitted). |
| `host`, `username` | Identity. |
| `os` | `windows` / `macos` / `linux` (default `windows`). |

**Context:** `Nik.Incident` — `id`, `name`, `os`, `createdAt`.

### `nik-update-incident`
Edit identity / suspicious-window fields.

| Argument | Description |
|---|---|
| `incident_id` *(required)* | The incident id. |
| `host`, `username`, `os` | New values. |
| `suspicious_start`, `suspicious_end` | Unix epoch **milliseconds**. |

**Context:** `Nik.Incident` — `id`, `updatedAt`.

### `nik-delete-incident`
Delete an incident. Argument: `incident_id` *(required)*. No context output.

### `nik-add-note`
Append a note to the incident timeline.

| Argument | Description |
|---|---|
| `incident_id` *(required)* | The incident id. |
| `text` *(required)* | Note text. |

**Context:** `Nik.Note` — `id`, `incidentId`, `text`, `author`, `createdAt`.

### `nik-delete-note`
Remove a note. Arguments: `incident_id`, `note_id` *(both required)*.

### `nik-upload-artifact`
Upload a raw artifact **file entry** (from the War Room) to an incident; Nik
parses it server-side and merges the result.

| Argument | Description |
|---|---|
| `incident_id` *(required)* | The incident id. |
| `entry_id` *(required)* | War Room entry id of the file. |
| `tab` *(required)* | `browser` / `commands` / `endpoint`. |
| `browser` | tab=browser: `chrome`/`firefox`/`edge`/`brave`/`opera`. |
| `shell` | tab=commands: `bash`/`zsh`/`fish`/`powershell`. |
| `category` | tab=endpoint: `execution`/`persistence`/`fileaccess`/`usb`. |
| `source` | Source key (browser/endpoint), e.g. `history`, `places`, `cron`. |

**Context:** `Nik.Upload` — `incidentId`, `rows`, `format`, `target`.

Example (upload a collected Chrome `History` DB stored in the War Room):

```
!nik-upload-artifact incident_id=<id> entry_id=<entryId> tab=browser browser=chrome source=history
```

### `nik-get-audit`
Read the global audit log, newest-first.

| Argument | Description |
|---|---|
| `query` | Match actor/action/details/incident. |
| `actor`, `incident_id` | Filters. |
| `limit` | Max entries (default 100). |

**Context:** `Nik.AuditEntry` — `id`, `at`, `actor`, `action`, `details`,
`incidentId`, `incidentName`.

### `nik-get-settings`
Read the shared detection keywords and business hours.

**Context:** `Nik.Settings` — `keywords[]` (label/pattern/severity/description)
and `businessHours` (startHour/endHour/flagWeekends).

## Fetch incidents (optional)

Enable **Fetch incidents** to import Nik incidents as XSOAR incidents. The
integration pulls the summary list, keeps an `updatedAt` high-water mark, and
imports incidents updated after it (so an edited incident re-fetches). Each
XSOAR incident's `rawJSON` is the Nik summary; use a classifier/mapper to map
`id`, `name`, `host`, `username`, `os`, `updatedAt` onto your incident fields.
Tune **First fetch time** and **Maximum incidents per fetch**.

## Error handling & idempotency

- Auth failures surface as a clear message on **Test** and as `403` on write
  commands run with a read-only key.
- The Nik API also supports request-level `Idempotency-Key` and `If-Match`
  (ETag) headers for safe retries and optimistic concurrency; the built-in
  commands don't set them, but you can add them in a custom fork if a playbook
  needs exactly-once semantics.
