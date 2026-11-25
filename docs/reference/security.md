# Security

How Nik keeps hostile evidence from doing harm, what leaves the server and when, how accounts and secrets are protected, what to check, and where the limits are.

Nik is where a team puts its worst files: live malware, phishing mail, captures of an attack, the addresses of the attacker's servers. This page is the reference; the operator's steps are in [Run the server](../admin/index.md).

## What Nik defends against

**The content is the adversary.** Nik assumes that:

- every evidence file may be built to attack whatever opens it: a sample, a document with an exploit, a database with a hostile schema, a capture that crashes a dissector, a file name that is a path;
- every string from evidence (a URL, a subject, a host name) may be markup, a script, or a lure for a click;
- every page the isolated browser visits is run by the attacker and will try to reach your network through the server;
- analysts are trusted colleagues with accounts, not administrators: what each does is recorded, and what decides where data goes is an admin's to set.

It does not defend against an attacker who already controls the server's host, nor against an administrator.

## How hostile content is contained {#containment}

Samples are **never executed**: there is no detonation sandbox. They are read, disassembled and matched against rules. Each kind of content is handled by the part with the least access that can do the job.

| Container | Handles | Network | Can read |
| --- | --- | --- | --- |
| `analyzer` (rizin) | Disassembly, decompilation | Internal only | Only the sample it is sent |
| `capa` | Capabilities of samples | Internal only | Only the sample it is sent |
| `docview` (LibreOffice, pdfium) | Document previews (macros disabled, links never updated); PST conversion on a volume of its own | Internal only | Only the document it is sent |
| `pcap` (tshark, sharkd) | Packet captures | Internal only | Only the capture it is sent |
| `forensics` | Files of host evidence (event logs, registry hives, a `$MFT`, browser databases, histories, collections), the Sigma rules, the viewer of an original | Internal only | Only the file it is sent, on its own volume `forensics-work`; a process for each file |
| `browser` (Chromium) | HTML attachments and addresses | Its own network to the backend, and the internet through a filtering proxy; none shared with other workers | Only the page it is sent |
| `sandbox` | Python scripts of playbooks | Internal only, no volume | The arguments of its node |
| `api` | Everything else: e-mails, static analysis, reports | Database, workers; outside only for threat-intelligence look-ups | The store, read-write, and its key |

Every container runs as an unprivileged user on a read-only filesystem, with all capabilities dropped, `no-new-privileges`, and memory, CPU and process limits. A worker is reached with a token of its own, compared in constant time; none can reach the database.

The **isolated browser** is the one part that runs attacker code on purpose. Without network (the default) only the attachment loads. With network, Chromium's only route is a proxy inside the worker that resolves each name itself, refuses unless every address is public, and connects to the address it checked: a redirect to `10.0.0.1`, DNS rebinding, a cloud metadata address all go nowhere. What a page submits is held until the analyst releases it. Downloads are refused, dialogs dismissed, permissions denied.

### Limits on what a file can make the server do

- **Size**: every upload has a limit, enforced while reading ([`SAMPLE_MAX_MB`](configuration.md#SAMPLE_MAX_MB), [`ARTIFACT_MAX_MB`](configuration.md#ARTIFACT_MAX_MB), [`PCAP_MAX_MB`](configuration.md#PCAP_MAX_MB), [`EVIDENCE_MAX_MB`](configuration.md#EVIDENCE_MAX_MB), [`COLLECTION_MAX_MB`](configuration.md#COLLECTION_MAX_MB)…). A file sent in parts is checked against its SHA-256 and against the free room before it is accepted.
- **Time**: an analysis that stalls is killed with everything it started.
- **SQLite files** are opened read-only, schema untrusted, with a time budget and a row limit.
- **Names** from evidence never become paths or commands: files are stored under their SHA-256 or an id; download names are cleaned.
- **E-mail**: HTML sanitised on the server; only the first five DKIM signatures verified; an image declaring a huge size refused before decoding.
- **Reports**: every value escaped; the PDF renderer fetches nothing.
- **Script signatures**: a pattern too slow on hostile text is refused when saved; a match stops after half a second.
- **Host evidence is read in a process of its own for each file**, with its memory and CPU time bounded, in a container with no route out, a read-only root and no capabilities. A file made to crash a parser ends that process: the file is reported as read in part, with what was read before, and the worker goes on.
- **Untrusted YAML and zips are handled in child processes with limits**, never in the server. The YAML of a Sigma rule is read by pySigma in a short process of its own, with a time bound, when it is checked or tried. A collection (a KAPE or Velociraptor zip) is opened only by the worker, in a process of its own: no member's name is ever a path (members are written under a number), a symbolic link is skipped, a member above its size limit or one that expands more than 2,000 times is skipped, an archive inside it is listed and not opened, an encrypted member is skipped, 20,000 members at most. What was not read is said in the report.
- **A search in a file** (text or hex) has a time budget and a limit of matches; the answer says when it stopped short.
- **Archives** unpacked by a playbook: in memory, 200 members at most, never written to disk or opened; a member's name is never a path.
- **Content packs**: at most 20 MB and 2,000 files, 100 MB unpacked, no path leaving the pack, YAML read without building objects. A pack never carries an instance, a credential, an allowed host or an opened class of data.
- **The pack catalogue** is read only when its index carries an Ed25519 signature of the key Nik holds; each pack must match the size and SHA-256 of the signed index. Packs from `NIK_PACKS_DIR` are not checked.

### What reaches the analyst's browser

- **A picture, not the page**: the isolated browser sends screenshots; documents are page images.
- **Hostile HTML** (an e-mail body, a captured page) is drawn in a frame that runs no script and loads nothing. Remote images load only when asked, tracking pixels never.
- **Addresses** are not links: opening one asks first and shows it defanged.
- **Samples** are downloaded only inside a password-protected zip (`infected` by default). So is **the original of a file of host evidence**, which can hold credentials, mail and history: it needs its own permission, `evidence.download` (the role **evidence**), and every download is in the audit log.
- The app sends a Content-Security-Policy that runs only its own scripts (no WebAssembly: 7.0 took `'wasm-unsafe-eval'` out) and talks only to its own origin, plus `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and HSTS. The session cookie is `HttpOnly`, `Secure`, `SameSite=Lax`. The pages load nothing from outside: no CDN, no fonts, no telemetry.

## What leaves the server

Nothing, unless one of these is turned on or asked for.

| What | When | What is sent |
| --- | --- | --- |
| Threat-intelligence look-ups | A source's connector has an instance that is on, and someone asks (**Check now**, a bulk check, a playbook) or automatic look-ups are on for that type | The indicator, to the source's hosts, with the instance's key. Never a private or internal value, an allowlisted one, or one of a TLP:RED incident. The data guard holds values that carry an e-mail address, an internal name or address, or an allowlisted name, until an admin opens that class |
| The isolated browser with network | An analyst opens a session with network, or scans an address | Ordinary web requests; submissions only if released |
| Mail authentication | An e-mail is uploaded or re-analysed | DNS queries for SPF, DKIM, DMARC |
| Webhooks | An admin subscribed an address | The event, signed |
| Playbook nodes (connectors, HTTP, e-mail) | A run reaches the node, after approval if asked | The request, to the instance's host or a host the playbook may reach, if the classes of data it holds may leave |
| Backup copies and archive | A destination is set | Sealed files over SFTP to the pinned host |
| The audit log | Forwarding is set | Each entry to the syslog receiver |

A server that is a **copy** of another (`NIK_COPY=true`, for [trying a release](../admin/try-on-a-copy.md)) sends none of these: every door to the outside is shut where it would open, and the screens say **COPY of** the name of the original.

Indicators Nik finds by itself as incidents come in start no look-up unless an admin allows it in **Indicators found**. The data guard reads addresses, names and e-mail addresses: a token or customer number in the path of a link has no class and leaves with the link.

## Playbooks and scripts

A playbook is code your team writes that runs by itself, so who may write it, where it may connect, and what it may send are kept apart.

- **Who.** Building playbooks and scripts is the role **playbooks**; running one and answering an approval is **analyst**. Only an **admin** chooses the hosts a playbook reaches, lets it reach any host, opens a class of data, or sets the SMTP server. A playbook from a file arrives off, with nothing opened.
- **One way out.** Playbooks run in the `automation` container, which publishes no port. A single module opens connections (`backend/app/automation/egress.py`; a test fails if another opens a socket). It resolves the name, checks the address, connects to that address, and checks every redirect (three at most).
- **Where.** By default only the hosts listed for the playbook and for every playbook. Private, loopback, link-local and carrier-grade ranges, the stack's containers and the metadata address are refused unless that host is listed by name.
- **What.** Values carry a class from where they were read through filters, texts and scripts. A node sends only when every class it holds always leaves, or was opened for that playbook by an admin (a box and the class name typed). TLP:RED data cannot be opened.
- **Never twice by accident.** A step that changes another system records that it is about to, and that it is done, in separate commits. After a restart between the two it is done again only when that is harmless; otherwise it waits for a person.
- **Scripts** are free Python, made safe by where they run: the `sandbox` container holds Python and nothing else, has no route out and no volume; each script runs in a new process with an empty environment, 256 MB of memory, 16 open files, 1 MB of result and a time limit. What it returns carries the classes of what it was given.
- **Secrets.** Credentials of instances and stored credentials are encrypted under `SECRET_KEY` and never returned by the API; a value equal to a secret is blanked wherever it would be shown. A playbook cannot read a credential.
- **Connectors are data, not code**: YAML read with a safe loader, checked against a fixed format. Every request goes to the instance's host.
- **The inbound hook** `POST /api/automation/hooks/<token>` is the only automation route that needs no account: the token is 32 random bytes stored as its SHA-256; 256 kB per request, 60 requests a minute per token; every refusal is the same 404. Treat the address as a password.
- **Floods.** Changes can start other playbooks three deep; each playbook has a ceiling of runs an hour; the server a ceiling of runs in progress; **Stop all** stops everything.
- **The record.** What a playbook changes is signed `nik-automation`, an account that cannot sign in, with the run and who approved.

## Accounts, sessions and the audit log

- Passwords are hashed with bcrypt. Sessions are random 256-bit tokens kept on the server. API keys are stored as digests, carry roles and an optional expiry, and are shown once.
- **Roles add up**, and every route asks for a permission ([API](api.md#roles-and-permissions)). A test walks every route with a key of each role. Roles are read at every request. Nobody removes the admin role from themselves or from the last admin; nobody can write an audit entry by hand.
- Changes by two people to the same incident are merged or refused, never silently overwritten.
- Analysts can read every incident: there is no per-incident access control.

### A second factor

A time-based code (TOTP, six digits, thirty seconds). An admin can require it of administrators; others choose.

- The right password of an account with a second factor opens no session: only a five-minute ticket for the code step.
- A code is accepted once. The secret is encrypted under `SECRET_KEY`. Ten single-use recovery codes, stored hashed.
- Required of administrators: an Admin without one reaches only the set-up routes (403 `second_factor_required`), with no grace period.
- Turning it off, making new recovery codes or changing the password asks for the password and a current code.
- API keys are not asked for a code. Passkeys and single sign-on are not part of Nik.

### Sessions and failed sign-ins

| Rule | Default |
| --- | --- |
| A session ends after no use | 8 hours; 30 minutes for an administrator |
| A session ends at most after | 12 hours |
| Requests the page makes by itself | Do not count as use |
| A new password, other roles, disabling, a change of second factor | End the account's other sessions |
| Failures before a wait (per account and per address) | 5; then 30 seconds, doubling up to 15 minutes |
| Administrators told after | 10 failures in a row |

A sign-in always makes a new session id. A change sent by another site (`Sec-Fetch-Site`) is refused. A wait never locks the owner out from the addresses they last used. An account that does not exist is answered exactly like a wrong password.

**Administrators' networks**: accounts and keys with the Admin role can be held to listed networks, checked after the password and code. This and the per-address waits need the client's address, which the backend takes from `X-Forwarded-For` only from [`TRUSTED_PROXIES`](configuration.md#TRUSTED_PROXIES). Under rootless Podman and Docker Desktop it cannot be known: the policy page says so and refuses the list ([The client's address](../admin/configuration.md#the-clients-address)).

### The audit log is a chain

An audit log in the database it describes can be changed by whoever can change that database. So:

- **Every entry is linked** to the one before by a SHA-256 hash, numbered from 1 with no gap. The format is specified at the top of `backend/app/auditlog/verifier.py`, which needs nothing of Nik.
- **Every entry is signed** with an HMAC under [`AUDIT_KEY`](configuration.md#AUDIT_KEY), a key not in the database (or one derived from `SECRET_KEY` on a server without one). Whoever rewrites the database cannot make the signatures without the key.
- **The server walks the chain** every five minutes and names the first thing that does not hold: an entry edited, entries missing or reordered, a log cut at its end. Entries whose key the server cannot make are "cannot be checked", never "tampered".
- **Only the oldest entries can be removed**, by a signed-in admin, and the chain keeps an entry saying so.
- **Entries imported** from another server are marked `origin: import`; entries found without a number (after a restore, or inserted by hand) are marked `origin: outside`.
- **What a chain cannot show alone**: the newest entries removed, or the whole log rewritten by somebody with the database and the key. Only a copy off the server shows that: **forward the log to syslog** ([Health and audit](../admin/health.md#forward-the-audit-log-to-syslog)). TLS (RFC 5425) is the one to use; the receiver's certificate is always verified. A checkpoint every five minutes lets the receiver tell silence from a cut line.

### What is in the audit log

**Recorded:** sign-ins, sign-outs and failed sign-ins (the first of a run, then each past the threshold); administrators refused for their network; second factors turned on, off, reset, wrong codes, recovery codes used and made; sessions ended; accounts created, changed, deleted; API keys; the sign-in policy; every change of settings; backups (settings, passphrase, runs, tests, copies, downloads, deletions); the content export and import; the data guard opened and closed; hosts a playbook may reach; playbooks created, versioned, enabled, run by a person, stopped, deleted, imported; approvals; connectors, instances, credentials; packs; evidence uploaded, deleted, downloaded; incident exports and reports; webhooks; indicator tags, notes, TLP and expiry; bulk actions with each row they changed; the audit log itself (verified, entries removed, forwarding changed and tested, a restore); the Health thresholds and the scrape token.

**Not recorded:** what is only read (an incident opened, a query, the audit log itself); the use of an API key; a session that ends for lack of use; the start of a second-factor enrolment (its confirmation is); runs started by schedule, trigger or hook (they are in the runs); playbook drafts saved without a version; tests of an instance; saved filters and dashboards created; tasks given to someone else; exports of a playbook, script, dashboard or list. Old values are not kept: an entry says what changed, not what it was.

### Bulk actions, health and metrics

- A bulk action is not another way in: each row is changed by the function that changes one alone, with its checks, and the permission is read again for every row. Deleting, and closing more than 100 incidents, wait for typed words, which the server checks too.
- `/api/health` says only that the process is up. `/api/metrics` answers only to the scrape token (kept as a hash), never to a session cookie; no metric label carries an account, an incident or anything typed.

## Secrets and backups

The stack does not start without `DB_PASSWORD`, `SECRET_KEY`, `STORE_KEY` and a token per worker, and refuses example values. Where each secret is and which container holds it: [Keys and secrets](../admin/secrets.md#the-secrets). On a new install each secret is a file mounted only into the containers that use it, never in an environment.

### The store of files, encrypted

Samples, e-mails, **the originals of host evidence**, captures, mailboxes, previews, screenshots and rule files are encrypted on disk.

- **How.** Each file has its own random key; content in 64 KB chunks with AES-256-GCM; the file key wrapped in the file's head under a key derived from `STORE_KEY` (HKDF-SHA256). Primitives from the `cryptography` package.
- **A changed file is not served.** Each chunk is authenticated with its position, whether it is last, and the file's path: a byte changed, a chunk moved, a file cut or swapped all fail. The answer is an error (`file_damaged`), the audit log gets `store.damaged`, admins are told.
- **Who holds the key: the backend alone.** Workers never mount the store; the backend sends the file a job needs, kept in memory (the forensics worker keeps it on its work volume, below). The `automation` worker asks the backend for a file with a short-lived proof.
- **What is in clear, and where:** a sample in a worker's memory while analysed; a capture over 64 MB on `pcap-work` while open; **an original of host evidence on `forensics-work` while the forensics worker reads or shows it, and until nobody has asked for it for 15 minutes** (`FORENSICS_FILE_IDLE`), emptied when the worker starts; a PST on `pst-work` while converted; an upload in the backend's memory before it is sealed. A host with swap may write memory to disk: encrypt the swap.
- **What whoever has the disk still learns:** how many files, of which kind, their sizes and dates, and the SHA-256 of samples and e-mails (their file names). **The database is not encrypted by Nik**: incidents, analysis results and the audit log are in PostgreSQL in clear. Encrypt the host disk to cover them.
- **The key must not sit on the disk it protects**: point `NIK_SECRETS_DIR` elsewhere when a stolen host is the fear.
- **Deleting** removes the file and its key with it; it does not promise the blocks are unrecoverable on an SSD.

### Changing a key

Asked for in the app by a signed-in admin (password and code again), carried out on the host by `deploy/secrets.sh rotate`: the new key is made by the server and written straight into place, never shown. Both keys are held until everything is under the new one and read back with it alone; only then is the earlier key taken away. A key is spoken of by its fingerprint (eight characters); no route returns a key. Steps: [Change a key](../admin/secrets.md#change-a-key).

### Backups

- **Always encrypted**: AES-256-GCM in 1 MB authenticated chunks, under a key derived with scrypt from the backup passphrase. A changed, reordered or truncated file is refused before anything is restored.
- **The passphrase is not `SECRET_KEY`**: a backup is readable on a host that never had the server's keys. It is kept in the database under `SECRET_KEY` so scheduled backups can run; no route returns it.
- **The pool** (7.0): the samples, e-mails and originals named by their SHA-256 are written once, in a folder `pool-<id>` beside the backups, each as a file in the backup's format, encrypted under a key of the pool. The key is made by the server, kept under `SECRET_KEY` and carried by each backup that names the pool, so the backup, its passphrase and the folder are all a restore needs. Another passphrase starts another pool: a passphrase given up cannot open what is written after it. A restore refuses before changing anything when a file the backup names is not in the folder.
- **A backup does not need the store key**: files are decrypted as read and encrypted again under the passphrase. A restore seals them under the restoring server's key.
- **Including `SECRET_KEY`** (off by default) trades one risk for another: a backup and its passphrase then read every stored secret.
- **The copy off the server** goes from `automation` over SFTP to a host whose key an admin pinned; no trust on first use. The second host can delete or withhold a backup, not read one.
- **Restoring is not a route**: it is done on the host, by someone with a shell, the file and its passphrase. An admin's API key can read the state, ask for a backup or a test, nothing more.
- **A restored server starts with nobody signed in.**
- The restore test and the upgrade rehearsal use scratch databases whose names the code checks (`nik_scratch_…`, `nik_rehearsal_…`), never the live one.

### Recovery and the standby

- **Nothing new listens.** The first host connects out over SSH to the backups' SFTP account; the second never connects to the first; there is no streaming replication.
- **On the server the archive is in clear**, like the database: the host and its disk encryption protect it. The databases a recovery keeps aside are in clear too.
- **On the second host** the log segments and base backups are sealed under the backup passphrase, the store files under `STORE_KEY`. The account learns names, sizes, times and sample hashes, no content.
- **The second host cannot stop the first by writing there**: `superseded.json` and `heartbeat.json` carry an HMAC under a key derived from `SECRET_KEY`. An unsigned file is never obeyed and the admins are told.
- **The `recovery` service has no network** (`network_mode: none`); it reaches PostgreSQL through a socket and holds no password.
- **A standby holds every key of the first host** and is as sensitive as the server.
- **Never two servers**: each promotion adds one to a generation number; a server that finds a later one stops serving. A server that cannot reach the second host cannot know: keeping the old host off the network is the operator's part.
- **Nothing on a screen promotes, recovers or exports a key**: those are commands on the host.

## Hardening checklist

- Create the first account yourself, at once: whoever reaches a new install first becomes its admin.
- Publish the HTTPS port only where analysts are (a management network, a VPN); replace the self-signed certificate; set `TLS_HOSTNAME`.
- Decide whether the server may reach the internet at all. Without it, look-ups, sessions with network and address scans do not work; everything else does.
- On the host firewall, keep the `browser-egress` and `automation-egress` networks away from your internal ranges and the cloud metadata address.
- Exclude the store volume from the host's antivirus (it would quarantine the evidence), and nothing else.
- Set the backup passphrase, write it down away from the server, send copies to a second host, keep `./secrets` elsewhere, and restore once on the second host to know how long it takes.
- If the second host is a standby, treat it as the server. Encrypt the disks that hold the archive, on both hosts.
- Send the audit log to a syslog receiver on another machine, over TLS, where Nik's admins cannot change it. Alert when checkpoints stop.
- Give each person an account; disable, do not delete, the account of someone who leaves.
- Turn on **Administrators must have a second factor**; ask everybody else to set one up. Set up your own first.
- List the administrators' networks only after checking the address the server sees you at.
- Give accounts and keys the narrowest roles (**viewer** for a key that only reads) and keys an expiry. Keep **admin** for the few who run the platform.
- Give **playbooks** only to those who write automation. Read the audit log for `automation.egress.open` and `automation.data.open`.
- Give the role **evidence** (download of an original) and **archive** only to those who need them. Read the audit log for `evidence.*` entries.
- Keep the `pool-*` folders with the backups wherever you copy them, and try a release on [a copy](../admin/try-on-a-copy.md) before the real server changes.
- Upgrade regularly: rebuilding the images brings the fixes of LibreOffice, Wireshark and Chromium.

## Known limits

- Chromium runs with `--no-sandbox`: its sandbox needs privileges the container does not give, so the container is the sandbox.
- The backend parses some formats itself (e-mails, PE headers, YARA, QR codes) in a hardened but not disposable container that holds the database password. Host evidence is not one of them: the forensics worker holds no password and has no route to the database.
- In a browser session without network, requests are refused by the interception, not the proxy.
- A backup is as recent as the schedule; the archive closes the gap only once it leaves the host. No streaming replication.
- The archive and base backups on the server are in clear. A standby holds every key. A server that cannot reach the second host cannot know it was replaced, and one that takes over does not know what the other did in other systems in its last moments.
- A store file rewritten in place exists in one version: a recovery brings the database of the moment and the latest content of such a file.
- The store is encrypted at rest; the database is not.
- The store key protects against whoever has the disk and not the key: on the same disk, it does not protect a host stolen whole.
- Large captures and PSTs are in clear on a work volume while read, and so is an original of host evidence, on the work volume of the forensics worker, for as long as it is used and 15 minutes after.
- A host evidence parser is a hardened process, not a proof: a flaw in a library (EVTX, registry, NTFS, SQLite…) is contained to the process and the container, which has no route out. Results of a parser are checked against what the file holds by a count of its own, and what could not be read is said; Nik has been tried on real files for EVTX, `$MFT`, hives, Prefetch, LNK, jump lists and SRUM, and on generated ones for the others (the guide's host pages say which).
- A copy of a server holds the real data and every stored secret it can read: it reaches nothing, and it must be thrown away and its backup file removed when the test is done.
- There is no client for an external secrets manager (`backend/app/core/keys.py` is where one would go).
- A database holding anything Nik does not make (a view, a trigger of yours) is refused by the backups.
- Under rootless Podman and Docker Desktop, administrators' networks cannot be used and failures are counted per account only.
- A second factor protects neither an API key nor the server: whoever runs commands in the backend container can reset any second factor.
- The audit chain shows a change to what is there; without a copy off the server it cannot show the newest entries removed or a log recomputed by somebody holding the database and the key. Anybody who can write the database can add entries.
- Over plain TCP and UDP the audit log is in clear and the receiver unauthenticated; UDP can lose and shorten messages.
- A script can read the token the engine presents to the sandbox; it opens nothing else.
- The data guard knows the class of what Nik gave a playbook, not what a person types or another system answers.
- A playbook allowed any host with a class opened can send that data anywhere a node says.

## Reporting a vulnerability

Report it **privately**, through a [GitHub security advisory](https://github.com/n36l3c7/Nik/security/advisories/new), not in a public issue. Say:

- the version (at the top of `/api/docs`) and how Nik is deployed;
- what you did, what happened and what you expected;
- a file, page or request that triggers it; malware shared as any sample, in a password-protected archive.

A fix is published as a release with a **Security** entry in the changelog, and the advisory with it. The latest release is the supported one; fixes are not back-ported.

**In scope:** content from evidence that makes the server, a worker or a browser do what it should not; a way for an account or key to exceed its role, or for one user's change to destroy another's silently; a secret in a log, a response or the repository. **Not in scope:** attacks needing control of the host, the container runtime or an administrator account; the self-signed certificate of a fresh install; a deployment not configured as this documentation says. A way to turn a known limit into a compromise is still welcome.

## Related

- [Keys and secrets](../admin/secrets.md) — the operator's side of the secrets
- [Health and audit](../admin/health.md) — the chain and syslog forwarding
- [Configuration](../admin/configuration.md#sign-in-and-sessions) — the sign-in policy
- [Architecture](architecture.md) — what runs where
- [API](api.md#authentication)
