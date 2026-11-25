# Environment variables

Every environment variable Nik reads, with its default and what it does.

Nik is configured with environment variables. The Compose file reads the `.env` beside it (made by `deploy/init-env.sh`) and passes each container what it uses; the secrets are files of `NIK_SECRETS_DIR` ([Keys and secrets](../admin/secrets.md)). A change is read when the containers are made again: `docker compose up -d` (or `podman compose up -d`).

In the tables, **`.env`** means the Compose file passes the variable from `.env`. **Override** means it does not: add it to the `environment` of that service in a Compose override file. **Fixed** means the Compose file sets it itself.

How to use them is in [Configuration](../admin/configuration.md). Settings an administrator changes in the app (sign-in policy, backup schedule, bulk limits…) are not variables: they are kept in the database.

## Backend

Read by the `api` container (and by `automation`, which runs the same image). Outside containers they can also come from `backend/.env` ([backend/.env.example](https://github.com/n36l3c7/Nik/blob/main/backend/.env.example)).

### Database

| Variable | Default | Compose | Meaning |
| --- | --- | --- | --- |
| <a id="DATABASE_URL"></a>`DATABASE_URL` | `sqlite:///./nik.db` | override | SQLAlchemy URL, used as it is. Production: `postgresql+psycopg://nik:PASS@host/nik` (the password URL-encoded). |
| <a id="DB_PASSWORD"></a>`DB_PASSWORD` | required | `.env` / secret | PostgreSQL password, shared by `db`, `api` and `automation`. Set when the database is first created; to change it later, change it in PostgreSQL first. When `DATABASE_URL` is not set, the backend builds the URL from it, escaping the password. |
| <a id="DB_USER"></a>`DB_USER`, `DB_HOST`, `DB_PORT`, `DB_NAME` | `nik`, `localhost`, `5432`, `nik` | `DB_HOST` fixed (`db`) | The other parts of that URL. |
| <a id="DB_POOL_SIZE"></a>`DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_RECYCLE` | 5, 10, 1800 | override | Connections kept per backend process, extra ones under load, their lifetime in seconds. |
| <a id="DB_STATEMENT_TIMEOUT_MS"></a>`DB_STATEMENT_TIMEOUT_MS` | 30000 | override | A query running longer is cancelled (PostgreSQL only). |
| <a id="RUN_CREATE_ALL"></a>`RUN_CREATE_ALL` | `true` (`false` in the image) | override | Create the tables at start without Alembic: for development on SQLite only. |

### Keys and secrets

Every secret can also be given as a file: see `<NAME>_FILE`.

| Variable | Default | Compose | Meaning |
| --- | --- | --- | --- |
| <a id="SECRET_KEY"></a>`SECRET_KEY` | `dev-insecure-change-me` | `.env` / secret | Encrypts the secrets stored in the database (credentials of instances, second factors, the backup passphrase, TLS key logs). The container refuses the default and any value under 16 characters. Changed with `deploy/secrets.sh rotate secret-key`. |
| <a id="SECRET_KEY_PREVIOUS"></a>`SECRET_KEY_PREVIOUS` | — | `.env` / secret | Earlier values of `SECRET_KEY`, separated by commas or lines, kept while it changes. Set and removed by `deploy/secrets.sh`. |
| <a id="STORE_KEY"></a>`STORE_KEY` | `dev-insecure-store-key-change-me` | `.env` / secret | Seals every file of the store on disk. In no database and no backup. Given to `api` only. The container refuses the default and any value under 32 characters; without it the server stays up and says so. |
| <a id="STORE_KEY_PREVIOUS"></a>`STORE_KEY_PREVIOUS` | — | `.env` / secret | Earlier store keys, kept while the store key changes. |
| <a id="AUDIT_KEY"></a>`AUDIT_KEY` | made by `init-env.sh` on a new install; otherwise derived from `SECRET_KEY` | `.env` / secret | Signs every entry of the audit log. Given to `api` and `automation` only. `hex:…` for a key written as bytes. Set or changed with `deploy/secrets.sh rotate audit-key`. |
| <a id="AUDIT_KEY_PREVIOUS"></a>`AUDIT_KEY_PREVIOUS` | — | `.env` / secret | Earlier audit keys, separated by commas or lines, so the entries they signed can still be checked. |
| <a id="NAME_FILE"></a>`<NAME>_FILE` | — | fixed | For every secret (`SECRET_KEY`, `STORE_KEY`, their `_PREVIOUS`, `AUDIT_KEY`, its `_PREVIOUS`, `DB_PASSWORD`, the worker tokens, `METRICS_TOKEN`): a file read in place of the variable. An empty file counts as none. A secret given both ways, or in a file that cannot be read, stops the server with a sentence naming it. |
| <a id="STORE_SEAL_MBPS"></a>`STORE_SEAL_MBPS` | 40 | `.env` | How fast a store from before 6.8 is sealed, in MB read a second (0: as fast as the disk). |
| <a id="METRICS_TOKEN"></a>`METRICS_TOKEN` | — | `.env` / secret | A bearer token `/api/metrics` accepts beside the scrape token made on the Health page. With neither, nobody reads the metrics. |
| <a id="NIK_NO_STORE_KEY"></a>`NIK_NO_STORE_KEY`, `NIK_STORE_API_URL` | — | fixed (`automation`) | The container holds neither the store nor its key (`1`) and asks the backend at this address for the files a step needs. |
| <a id="NIK_SKIP_MIGRATIONS"></a>`NIK_SKIP_MIGRATIONS` | — | fixed (`automation`) | `1`: leave migrations and the store-key check to the backend. Never set it for the backend. |

### Sign-in, sessions and the client's address

| Variable | Default | Compose | Meaning |
| --- | --- | --- | --- |
| <a id="COOKIE_SECURE"></a>`COOKIE_SECURE` | `true` | `.env` | Secure flag on the session cookie. Set `false` only for plain-HTTP local development. |
| <a id="SESSION_TTL_HOURS"></a>`SESSION_TTL_HOURS` | 12 | `.env` | The longest a session lasts, until an admin sets another in **Sign-in and sessions** (what is set there wins). |
| <a id="TRUSTED_PROXIES"></a>`TRUSTED_PROXIES` | empty (`web` in Compose) | `.env` | Who `X-Forwarded-For` is believed from: host names, addresses or networks, comma-separated. From anybody else the header is ignored. |
| <a id="FORWARDED_ALLOW_IPS"></a>`FORWARDED_ALLOW_IPS` | `127.0.0.1` (empty in Compose) | fixed | gunicorn's own list of trusted proxies. Leave it empty: the backend decides itself (`TRUSTED_PROXIES`). Never `*`. |
| <a id="RATE_LIMIT_DEFAULT"></a>`RATE_LIMIT_DEFAULT` | `600/minute` | override | Requests each client address may make (slowapi notation). Signing in has its own limit, 10 a minute. |
| <a id="RATE_LIMIT_STORAGE_URI"></a>`RATE_LIMIT_STORAGE_URI` | `memory://` | override | Where rate-limit counters are kept; a Redis URL shares them between processes and hosts. |

### Files and size limits

| Variable | Default | Compose | Meaning |
| --- | --- | --- | --- |
| <a id="SAMPLE_STORE"></a>`SAMPLE_STORE` | `./samples` | fixed (`/app/samples`) | Directory of the store of files (samples, e-mails, captures, mailboxes), each sealed under `STORE_KEY`. |
| <a id="SAMPLE_MAX_MB"></a>`SAMPLE_MAX_MB` | 100 | `.env` | Largest sample or e-mail upload, in MB. |
| <a id="ARTIFACT_MAX_MB"></a>`ARTIFACT_MAX_MB` | 500 | `.env` | Largest evidence file `POST /api/incidents/{id}/upload` takes (the old route, kept for scripts); larger is refused with 413. |
| <a id="EVIDENCE_MAX_MB"></a>`EVIDENCE_MAX_MB` | 8192 | `.env` | Largest file of host evidence sent in parts (`/api/uploads`, what the app uses): a `$MFT`, a `$J`, a large log. The free room of the store is checked before the transfer. |
| <a id="COLLECTION_MAX_MB"></a>`COLLECTION_MAX_MB` | 20480 | `.env` | Largest collection (a KAPE or Velociraptor zip) sent in parts. The Compose file hands the same value to the worker (`FORENSICS_COLLECTION_MB`) as the bound on what it unpacks. |
| <a id="PCAP_MAX_MB"></a>`PCAP_MAX_MB` | 500 | `.env` | Largest packet capture, in MB. |
| <a id="MAILBOX_MAX_MB"></a>`MAILBOX_MAX_MB` | 2048 | `.env` | Largest mailbox (mbox, or a zip or tar of a Maildir), in MB. |
| <a id="PST_MAX_MB"></a>`PST_MAX_MB` | 4096 | `.env` | Largest Outlook PST, in MB. Converted by `docview` on its `pst-work` volume, which needs about 2.5 times the PST free. The shipped nginx lets 4200 MB through for mailboxes: to raise this or `MAILBOX_MAX_MB` beyond it, raise `client_max_body_size` of the mailbox location in `frontend/nginx/nginx.conf` too. |
| <a id="YARA_RULES"></a>`YARA_RULES` | `app/malware/yara` | override | Directory of the built-in YARA rules (`*.yar`). Rules added by admins live in the database. |

### Workers

| Variable | Default | Compose | Meaning |
| --- | --- | --- | --- |
| <a id="ANALYZER_URL"></a>`ANALYZER_URL`, `ANALYZER_TOKEN` | — | URL fixed, token `.env` / secret | The rizin worker and its shared secret. Without them the Code view says "not configured". |
| <a id="ANALYZER_TIMEOUT"></a>`ANALYZER_TIMEOUT` | 600 | `.env` | Seconds rizin may spend on one sample. |
| <a id="CAPA_URL"></a>`CAPA_URL`, `CAPA_TOKEN` | — | URL fixed, token `.env` / secret | The capa worker and its secret. Without them the Capabilities view says "not configured". |
| <a id="CAPA_TIMEOUT"></a>`CAPA_TIMEOUT` | 1800 | `.env` | Seconds capa may spend on one sample. |
| <a id="DOCVIEW_URL"></a>`DOCVIEW_URL`, `DOCVIEW_TOKEN` | — | URL fixed, token `.env` / secret | The document viewer (previews, PST). Without them **Preview** is disabled. |
| <a id="BROWSER_URL"></a>`BROWSER_URL`, `BROWSER_TOKEN` | — | URL fixed, token `.env` / secret | The isolated browser. Without them HTML attachments and links do not open. |
| <a id="PCAP_URL"></a>`PCAP_URL`, `PCAP_TOKEN` | — | URL fixed, token `.env` / secret | The packet capture worker. Without them captures are stored, not analysed. |
| <a id="FORENSICS_URL"></a>`FORENSICS_URL`, <a id="FORENSICS_TOKEN"></a>`FORENSICS_TOKEN` | empty, — | URL fixed (`http://forensics:8760`), token `.env` / secret | The forensics worker, which reads the files of host evidence and runs the Sigma rules. With no URL the originals are kept and wait to be read. The token is made by `deploy/init-env.sh`. |
| <a id="SANDBOX_URL"></a>`SANDBOX_URL`, `SANDBOX_TOKEN` | — | URL fixed, token `.env` / secret | The script sandbox. Without it a script step fails, saying the sandbox is not configured. |
| <a id="SANDBOX_TIMEOUT"></a>`SANDBOX_TIMEOUT`, `SANDBOX_MAX_TIMEOUT` | 10, 60 | `.env` | How long a script may run, in seconds: by default, and at most (600 at the very most). |

### Background work and automation

| Variable | Default | Compose | Meaning |
| --- | --- | --- | --- |
| <a id="AUTOMATION_WORKER"></a>`AUTOMATION_WORKER` | `container` | `.env` | Where playbooks run: `container` (the `automation` service), `inline` (a thread of the backend, for an install without that container) or `off` (no event recorded, nothing runs). |
| <a id="AUTOMATION_CONCURRENCY"></a>`AUTOMATION_CONCURRENCY` | 4 | `.env` | Playbook steps run side by side (1 to 32). |
| <a id="AUTOMATION_MAX_ACTIVE_RUNS"></a>`AUTOMATION_MAX_ACTIVE_RUNS` | 200 | `.env` | Runs in progress at once on the server; more are refused. |
| <a id="AUTOMATION_RUNS_KEPT"></a>`AUTOMATION_RUNS_KEPT` | 500 | `.env` | Finished runs each playbook keeps (at least 10). |
| <a id="AUTOMATION_HTTPS_PROXY"></a>`AUTOMATION_HTTPS_PROXY`, `AUTOMATION_NO_PROXY` | empty | `.env` | A proxy for what playbooks send out, and the hosts reached without it. |
| <a id="ENRICHMENT_WORKER"></a>`ENRICHMENT_WORKER` | `true` | override | The thread of automatic threat-intelligence look-ups and bulk checks. `false` turns it off (**Check now** still works). |
| <a id="API_BACKGROUND"></a>`API_BACKGROUND` | `true` | override | The backend's own threads: the watch of the workers and the address scans playbooks ask for. `false` turns both off. |

### Content packs

| Variable | Default | Compose | Meaning |
| --- | --- | --- | --- |
| <a id="NIK_PACKS_CATALOGUE"></a>`NIK_PACKS_CATALOGUE` | the release packs of Nik's repository | `.env` | Address (https) of the catalogue index, until an admin sets another in the app. Empty: no catalogue, packs come as files. |
| <a id="NIK_PACKS_DIR"></a>`NIK_PACKS_DIR` | empty | `.env` | A folder inside the `api` container whose packs are installed at start when missing or older. Mount it read-only with an override. Not checked against a signature. |

### Backups, recovery and the standby

| Variable | Default | Compose | Meaning |
| --- | --- | --- | --- |
| <a id="NIK_BACKUP_DIR"></a>`NIK_BACKUP_DIR` | the volume `backups` | `.env` | A host directory for the backups, in place of the volume: another disk than the data. Inside the containers it is `/app/backups` (`BACKUP_DIR`, which an install without containers sets). |
| <a id="NIK_UPGRADE_REHEARSAL"></a>`NIK_UPGRADE_REHEARSAL` | `true` | `.env` | `false` skips the rehearsal of migrations on a copy (never the snapshot), for a database too large to copy at every upgrade. |
| <a id="NIK_WAL_ARCHIVE"></a>`NIK_WAL_ARCHIVE` | `on` | `.env` (`db`) | The archive of the PostgreSQL log. `off`: no recovery to a moment, no standby. |
| <a id="NIK_ARCHIVE_TIMEOUT"></a>`NIK_ARCHIVE_TIMEOUT` | 300 | `.env` | Seconds after which PostgreSQL closes a log segment while something is written: the most lost when the host dies. Counted as at least 10. |
| <a id="NIK_WAL_ARCHIVE_DIR"></a>`NIK_WAL_ARCHIVE_DIR` | the volume `wal-archive` | `.env` | A host directory for the archive and the base backups (in clear). Inside the backend it is `/app/wal-archive` (`WAL_ARCHIVE_DIR`). |
| <a id="NIK_STANDBY_INBOX"></a>`NIK_STANDBY_INBOX` | empty | `.env` | On a standby: the directory the first host sends to. Written by `deploy/standby.sh init` and `rejoin`; do not set by hand. |
| <a id="NIK_SERVER_NAME"></a>`NIK_SERVER_NAME` | `TLS_HOSTNAME` | `.env` | What this server calls itself to the other host of a pair (120 characters at most). A name set on the Backup page wins; with neither, the machine name. |

### Operations

| Variable | Default | Compose | Meaning |
| --- | --- | --- | --- |
| <a id="LOG_LEVEL"></a>`LOG_LEVEL` | `INFO` | override | Verbosity of the backend log. |
| <a id="WEB_CONCURRENCY"></a>`WEB_CONCURRENCY` | 2 (in the image) | override | Backend processes (gunicorn). |
| <a id="API_STOP_GRACE"></a>`API_STOP_GRACE` | 20 | override | Seconds the backend gives requests in flight when asked to stop. Must stay under the `stop_grace_period` of `api` (40 s). |
| <a id="NIK_COPY"></a>`NIK_COPY`, `NIK_COPY_OF` | `false`, empty | `.env` | This stack is a copy of another server, restored from its backup to try a release: it reaches nothing outside itself (no fetch, mirror, mail, webhook, playbook that starts by itself, copy off the server, shipping to a standby, syslog forwarding). `NIK_COPY_OF` is the name the banner **COPY of** shows (120 characters at most). Set by `deploy/restore.sh --as-copy`; never on a real server. See [Try a release on a copy](../admin/try-on-a-copy.md). |
| <a id="NIK_WEB_TLS"></a>`NIK_WEB_TLS` | `web:443` | override | Where the backend reads the web certificate for the Health page. Empty when there is none; the host and port of your own proxy on a manual install. |
| <a id="PROMETHEUS_MULTIPROC_DIR"></a>`PROMETHEUS_MULTIPROC_DIR` | `/tmp/nik-metrics` (in the image) | override | Where the backend processes add up their request counts, so `/api/metrics` gives the same totals whichever answers. |

## Compose

Read by `docker-compose.yml` itself, from `.env`. The variables marked required have no default: Compose stops when one is not named at all (its line may be empty when the value is in a file of `NIK_SECRETS_DIR`).

| Variable | Default | Meaning |
| --- | --- | --- |
| <a id="NIK_SECRETS_DIR"></a>`NIK_SECRETS_DIR` | — (`./secrets` on a new install) | The directory of the secrets as files, each mounted into the containers that use it. Unset on a server that keeps its secrets in `.env`. |
| `DB_PASSWORD`, `SECRET_KEY`, `ANALYZER_TOKEN`, `CAPA_TOKEN`, `DOCVIEW_TOKEN`, `BROWSER_TOKEN`, `PCAP_TOKEN`, `SANDBOX_TOKEN`, `FORENSICS_TOKEN` | required | The secrets (see above). Each worker token is different, long and random. |
| <a id="WEB_TLS_PORT"></a>`WEB_TLS_PORT` | 8443 | Host port of the app (HTTPS). |
| <a id="WEB_PORT"></a>`WEB_PORT` | 8080 | Host port for plain HTTP: only redirects to HTTPS. |
| <a id="TLS_HOSTNAME"></a>`TLS_HOSTNAME` | `localhost` | Name in the self-signed certificate (CN and SAN): what users type. |
| <a id="PCAP_MEMORY_FILE_MB"></a>`PCAP_MEMORY_FILE_MB` | 64 | A capture this size or smaller stays in the memory of `pcap`; a larger one goes to its `pcap-work` volume while open. |

### Limits of the containers

| Variable | Default | Container |
| --- | --- | --- |
| <a id="API_MEMORY"></a>`API_MEMORY`, `API_CPUS` | 4g, 4 | `api` (parses the evidence) |
| <a id="WEB_MEMORY"></a>`WEB_MEMORY` | 512m | `web` |
| <a id="AUTOMATION_MEMORY"></a>`AUTOMATION_MEMORY`, `AUTOMATION_CPUS` | 1g, 2 | `automation` |
| <a id="SANDBOX_MEMORY"></a>`SANDBOX_MEMORY`, `SANDBOX_CPUS` | 512m, 1 | `sandbox` |
| <a id="RECOVERY_MEMORY"></a>`RECOVERY_MEMORY`, `RECOVERY_CPUS` | 1g, 2 | `recovery` |
| <a id="ANALYZER_MEMORY"></a>`ANALYZER_MEMORY`, `ANALYZER_CPUS` | 4g, 2 | `analyzer` |
| <a id="CAPA_MEMORY"></a>`CAPA_MEMORY`, `CAPA_CPUS` | 4g, 2 | `capa` |
| <a id="DOCVIEW_MEMORY"></a>`DOCVIEW_MEMORY`, `DOCVIEW_CPUS` | 2g, 1 | `docview` |
| <a id="BROWSER_MEMORY"></a>`BROWSER_MEMORY`, `BROWSER_CPUS` | 2g, 2 | `browser` |
| <a id="PCAP_MEMORY"></a>`PCAP_MEMORY`, `PCAP_CPUS` | 4g, 2 | `pcap` (sharkd keeps an open capture in memory: a few times its size) |
| <a id="FORENSICS_MEMORY"></a>`FORENSICS_MEMORY`, `FORENSICS_CPUS` | 4g, 2 | `forensics` (each file is read in a process of its own, under `FORENSICS_JOB_MEMORY_MB`) |

Container logs are rotated at 20 MB.

## Tuning and worker variables

Rarely needed; the defaults suit a single server. Read by the worker containers (and `TLS_SELFSIGNED_DAYS` by `web`). The ones marked **`.env`** are passed by the Compose file; the others need an override.

| Variable | Default | Meaning |
| --- | --- | --- |
| <a id="ANALYZER_DECOMPILE_SECONDS"></a>`ANALYZER_DECOMPILE_SECONDS` | 300 (`.env`) | Part of the analysis spent decompiling functions up front; the rest are decompiled when opened. |
| <a id="ANALYZER_MAX_FUNCTIONS"></a>`ANALYZER_MAX_FUNCTIONS` | 20000 (`.env`) | Safety cap on functions listed per sample. |
| <a id="ANALYZER_WARM_SESSIONS"></a>`ANALYZER_WARM_SESSIONS`, `ANALYZER_WARM_IDLE` | 1, 600 (`.env`) | Analysed sessions kept open so decompiling on demand takes seconds (0 disables; about 1 GB each on a large binary), and how long an unused one stays. |
| <a id="MAX_JOBS"></a>`ANALYZER_MAX_JOBS`, `CAPA_MAX_JOBS`, `DOCVIEW_MAX_JOBS`, `PCAP_MAX_JOBS`, `SANDBOX_MAX_JOBS` | 2, 1, 2, 2, 4 | Jobs each worker runs at once; more are answered "busy". `ANALYZER_MAX_JOBS` is passed from `.env`. |
| <a id="FILES_MB"></a>`ANALYZER_FILES_MB`, `CAPA_FILES_MB`, `PCAP_FILES_MB` | 1024, 1024, 16384 | MB of sent files each worker holds; a single larger file is refused. |
| <a id="DOCVIEW_TIMEOUT"></a>`DOCVIEW_TIMEOUT`, `DOCVIEW_MAX_PAGES`, `DOCVIEW_MAX_MB` | 90, 20, 50 | Seconds a preview may take, pages rendered, largest document in MB. |
| <a id="DOCVIEW_PST_TIMEOUT"></a>`DOCVIEW_PST_TIMEOUT` | 3600 | Seconds for one PST conversion. The backend waits 3900 seconds for it. |
| <a id="DOCVIEW_PST_TMP_MAX_MB"></a>`DOCVIEW_PST_TMP_MAX_MB` | 500 | Largest PST converted in memory when the worker has no writable `pst-work` volume. |
| <a id="BROWSER_MAX_SESSIONS"></a>`BROWSER_MAX_SESSIONS` | 3 (`.env`) | Isolated browser sessions open at once. |
| <a id="BROWSER_IDLE"></a>`BROWSER_IDLE`, `BROWSER_LIFETIME` | 300, 1800 | Seconds a session lasts without an action, and in all. |
| <a id="PCAP_TIMEOUT"></a>`PCAP_TIMEOUT`, `PCAP_RPC_TIMEOUT`, `PCAP_MAX_SESSIONS`, `PCAP_SESSION_IDLE` | 900, 300, 2, 900 | Seconds to summarise a capture and to answer one question; captures open at once; idle time before one closes. |
| <a id="SANDBOX_MEMORY_MB"></a>`SANDBOX_MEMORY_MB` | 256 (`.env`) | Memory one script may use, in MB. |
| <a id="STOP_GRACE"></a>`ANALYZER_STOP_GRACE`, `CAPA_STOP_GRACE`, `DOCVIEW_STOP_GRACE`, `PCAP_STOP_GRACE` | 20 each | Seconds a worker gives its jobs when asked to stop. Must stay under the service's `stop_grace_period` (30 s). |
| <a id="TLS_SELFSIGNED_DAYS"></a>`TLS_SELFSIGNED_DAYS` | 825 | Validity of the self-signed certificate. Read only when the certificate is made. |

### The forensics worker

Read by the `forensics` container. The first two are passed from `.env` by the Compose file; the others need an override of the service.

| Variable | Default | Meaning |
| --- | --- | --- |
| <a id="FORENSICS_MAX_JOBS"></a>`FORENSICS_MAX_JOBS` (`.env`) | 2 | Files read at once; another request is answered busy and waits. |
| <a id="FORENSICS_JOB_MEMORY_MB"></a>`FORENSICS_JOB_MEMORY_MB` (`.env`) | 1536 | Memory one file may use (its process is bounded by `RLIMIT_DATA`); a file made to exceed it ends that process, and is reported as read in part. |
| <a id="FORENSICS_JOB_SECONDS"></a>`FORENSICS_JOB_SECONDS` | 21600 | CPU seconds one file may use. |
| <a id="FORENSICS_SIGMA_SECONDS"></a>`FORENSICS_SIGMA_SECONDS` | 120 | Seconds a check or a try of Sigma rules may take. |
| <a id="FORENSICS_FILES_MB"></a>`FORENSICS_FILES_MB` | 49152 | MB of originals the worker holds at once, in clear, on its volume `forensics-work`. |
| <a id="FORENSICS_FILE_IDLE"></a>`FORENSICS_FILE_IDLE` | 900 | Seconds an original is kept after the last request for it. The volume is emptied when the worker starts. |
| <a id="FORENSICS_STOP_GRACE"></a>`FORENSICS_STOP_GRACE` | 20 | Seconds the worker gives the files it reads when asked to stop. Must stay under the service's `stop_grace_period` (30 s). |
| <a id="FORENSICS_PORT"></a>`FORENSICS_PORT`, `FORENSICS_WORK_DIR` | 8760, `/work` | Its port and its work folder: leave them. |

### Read by the scripts

Read from the environment of the shell that runs a script of `deploy/`, never from `.env`.

| Variable | Default | Read by | Meaning |
| --- | --- | --- | --- |
| <a id="NIK_DIR"></a>`NIK_DIR` | the script's `../` | every script | The repository root with `docker-compose.yml`. |
| <a id="ENGINE"></a>`ENGINE`, `COMPOSE` | `podman` if installed, else `docker`; `$ENGINE compose` | every script | The container engine and compose command. |
| <a id="NIK_BACKUP_PASSPHRASE"></a>`NIK_BACKUP_PASSPHRASE`, `NIK_BACKUP_PASSPHRASE_FILE` | — | `restore.sh`, `rollback.sh`, `standby.sh` | The backup passphrase (or a file holding it), for a run nobody attends. Never on the command line. |
| <a id="NIK_TRANSFER_PASSPHRASE"></a>`NIK_TRANSFER_PASSPHRASE` | — | `standby.sh secrets export/import` | The passphrase of the file of keys (12 characters or more). Never in `.env`. |
| <a id="NIK_RECOVERY_WAIT"></a>`NIK_RECOVERY_WAIT` | 3600 | `restore.sh --to`, `standby.sh` | Seconds a replay of the log is waited for. |
| <a id="NIK_BACKUP_WAIT"></a>`NIK_BACKUP_WAIT` | 21600 | `backup.sh` | Seconds to wait for the backup it asked for. |
| <a id="NIK_ROTATE_WAIT"></a>`NIK_ROTATE_WAIT` | 21600 | `secrets.sh` | Seconds to wait for a change of key to be verified. |
| <a id="NIK_EXISTING_INSTALL"></a>`NIK_EXISTING_INSTALL` | detected | `init-env.sh` | `1` says Nik already ran here (keeps the old database password and key), `0` that it is new, when the script cannot see the database volume. |
| <a id="NIK_SECRETS"></a>`NIK_SECRETS` | files | `init-env.sh` | `env` writes the secrets into `.env` instead of files. |
| <a id="NIK_AUDIT_KEYS"></a>`NIK_AUDIT_KEYS` | — | `verifier.py` | The audit keys, to check signatures (or `--keys FILE`). |

## Related

- [Configuration](../admin/configuration.md) — what to set before the first start
- [Keys and secrets](../admin/secrets.md) — the secrets as files
- [Install in production](../admin/install.md) — ports, TLS, the services
- [Backups and restore](../admin/backups.md) and [Recovery](../admin/recovery.md)
