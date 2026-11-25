# Upgrades

Move Nik to a new release with a snapshot taken and the migrations rehearsed first, and come back if it goes wrong.

!!! note "You need"
    A shell on the host, in the folder of the Nik clone. For a pair of hosts, read [Upgrading a pair](recovery.md#upgrading-a-pair) first: the standby is upgraded before the server.

## Upgrade

=== "Docker"

    ```sh
    cd /opt/Nik
    git pull                        # or: git checkout vX.Y.Z
    docker compose up -d --build    # rebuild the images, recreate the containers, keep the data
    ```

=== "Podman"

    ```sh
    cd /opt/Nik
    git pull                        # or: git checkout vX.Y.Z
    podman compose up -d --build
    ```

1. Read the section of every release you pass, [below](#release-notes). Some ask for a step before or after.
2. Run the commands. Follow the backend with `docker compose logs -f api`: it says each step.
3. Sign in and look at the latest incidents, **Platform settings › System › Health** and **Workers**.

!!! warning "The oldest version an upgrade may start from is 6.0.0"
    An installation older than that goes to **6.9.0** first (`git checkout v6.9.0`, then the command above, following the old release notes of the versions it passes), is started once so that it migrates, and only then to the current version. A newer release started on an older database changes nothing: the page and the log of `api` name the version to go through.

Rebuilding the images also brings the current fixes of LibreOffice, Wireshark and Chromium: upgrade regularly.

## What happens at start

When a release changes the database, the `api` container does this before it serves anything:

1. **Lock and check.** A second instance waits and no backup starts. The database must be at a revision it knows, not from before 6.0.0, on a PostgreSQL it runs on, with room in the backup directory.
2. **Snapshot.** The database is written to the backup directory as `nik-upgrade-….nikbak`, marked **Before the upgrade from X to Y**, encrypted with the backup passphrase (or a key derived from `SECRET_KEY` while none is set). The store of files is not in it: no migration touches it.
3. **Rehearsal.** The snapshot is restored into a scratch database (`nik_rehearsal_…`) and the migrations run there.
4. **Migration.** Only then are the migrations run on the database itself.

The snapshot and the rehearsal add about the time of a backup of the database and of its restore: two seconds in all for a small database on the test machine; for 1.3 GB, about 9 seconds for the snapshot and 16 for the rehearsal.

- On a database too large to copy at every upgrade, [`NIK_UPGRADE_REHEARSAL=false`](../reference/configuration.md#NIK_UPGRADE_REHEARSAL) skips step 3, never the snapshot.
- If the database role may not create a database (an external PostgreSQL), the rehearsal is skipped with a warning; `ALTER ROLE nik CREATEDB` gives it back.
- During a long upgrade `api` does not answer its health check, and Compose may call it unhealthy: it is not restarted. `automation` waits until the database is at its code's revision.
- The kept snapshots count apart from the backups (**Snapshots from before upgrades**, 3) and are copied to the second host once the server is up.

## An upgrade went wrong

When the rehearsal or the migrations fail, `api` stays up, writes `NIK DID NOT START: THE UPGRADE WAS STOPPED` in its log, and the page shows a sentence in place of the sign-in.

1. Read the reason: `docker compose logs api`. It says which case this is.
2. **The rehearsal failed:** the database was never touched. Go back to the version that worked and start it, then report the log lines:

    ```sh
    git checkout v<the version that worked> && docker compose up -d --build
    ```

3. **The migrations failed on the database**, or the new version runs and you want the old one: put back the snapshot.

    ```sh
    deploy/rollback.sh                                # lists the snapshots and their versions
    deploy/rollback.sh nik-upgrade-20261120-101500    # puts that one back
    ```

    It stops the stack, verifies the snapshot, replaces the database (one transaction), checks out the tag the snapshot names when the folder is a clean git clone (otherwise it says which version to put there and stops), starts the stack and checks it answers. It can be run twice.
4. Sign in again (a database put back keeps no session) and look at the latest incidents. **What was written after the upgrade is lost.**

| Option of `rollback.sh` | Effect |
| --- | --- |
| `--no-checkout` | Never touch the code: say which version goes with the snapshot |
| `--no-start` | Leave the stack stopped |
| `--yes` | Do not ask before replacing the database |

A snapshot taken while no passphrase was set is read with this server's `SECRET_KEY`; otherwise the script asks for the backup passphrase (or reads [`NIK_BACKUP_PASSPHRASE`](../reference/configuration.md#NIK_BACKUP_PASSPHRASE)).

??? info "Rolling back across 6.8 or 6.9"
    - **Back below 6.8**, which reads its store in clear and its secrets in `.env`: the script first unseals every file of the store (each compared before it replaces the sealed one; it stops before touching the database if one cannot be opened), and puts the secrets back into `.env` if they had been moved.
    - **Back below 6.9**, which has no archive: the `recovery` container is removed and PostgreSQL starts without archiving. The volumes `wal-archive` and `db-socket` are left; the script says how to remove them. A standby of this server follows nothing any more: stop it, and make it again after the next upgrade.
    - Files deleted since the snapshot, kept under `.kept/` on a server with an archive, are moved back to their places.

## Release notes

What each release asks of an administrator. The full list of changes is in the [Changelog](../changelog.md). An [install without containers](manual-install.md#update-to-a-new-version) has its own steps.

### Upgrading to 7.0 {#upgrading-to-70}

A major release: host evidence is kept as it was given and read by a new container. Read this section whole before you start, and [try the release on a copy](try-on-a-copy.md) first.

!!! warning "A backup made by 7.0 is not read by 6.x"
    The first start moves the old host evidence in the background and needs a new container. The way back is the backup you take now.

#### Before you start

1. **Be on 6.11** (6.0.0 or later will do: an older install goes to 6.9.0 first, [see above](#upgrade)).
2. **Back up with 6.11.** **Platform settings › System › Backup › Back up now**, then check it passed its test. Keep the `.nikbak` and the passphrase off the server: a 7.0 backup is not read by 6.x, so this is the one that takes you back ([Going back from 7.0](#going-back-from-70)).
3. **Check the room.** Look at **System › Storage** and at the free space of the volumes of the database, the store (`sample-store`) and the backups.
    - Host evidence becomes one row per record in the database, more than the incident document held.
    - Each file imported again from now on keeps its original in the store. A backup writes it once, in a folder `pool-<id>` beside the backups: it takes room there too ([Backups](backups.md#the-pool-beside-the-backups)).
    - The new container keeps the file it is reading, in clear, on its volume `forensics-work`: up to 48 GB (`FORENSICS_FILES_MB`, 49152).
4. **Try it on a copy** with your own data: [Try a release on a copy](try-on-a-copy.md). It is the only way to know how long the move takes on your server.
5. **Tell the analysts.** Files of host evidence now go to the server, are read there and stay there as they were given. Until 6.11 they were read on the analyst's machine and never left it.

#### Upgrade

1. In the folder of the Nik clone:

    ```sh
    git pull                        # or: git checkout v7.0.0
    deploy/init-env.sh              # adds FORENSICS_TOKEN; changes nothing else
    ```

2. Start it with the command of your engine ([Upgrade](#upgrade)): `docker compose up -d --build` or `podman compose up -d --build`. It builds the `forensics` image too.
3. Follow `docker compose logs -f api`: the snapshot, the rehearsal, then the migrations `0056_evidence`, `0057_sigma`, `0058_collections` and `0059_processes`. One line says it all: `upgrade: The database is at the revision 0059_processes (was: 0055_bulk). Seconds: snapshot …, rehearsal …, migration …`.
4. Sign in. **Platform settings › System › Workers** lists the **forensics worker** and it must be up; **Health** must be green.
5. Set what [needs setting](#what-to-set-for-70).

#### What happens at the first start

| What | How you see it |
| --- | --- |
| The snapshot, the rehearsal and the migrations, as for any upgrade. `0056` makes the tables of evidence (sources, records, marks, detections, processes, logons), those of the uploads in parts, the Sigma rules, the time zone of an incident, the archive columns and the two tables of the backup pool. `0057` adds to the rules and turns the keywords into rules. `0058` and `0059` add collections, processes and logons | `docker compose logs api` |
| **The old host evidence moves to the tables**, in the background, one incident at a time, by the `api` process (one instance does it, under a lease). Each file becomes a source **imported before 7.0**: no original, no parse report. Records, flags and notes follow. An incident written or imported meanwhile is moved at that moment | The log line `Host evidence of before 7.0: every incident was looked at (N moved)` when it ends. A document that could not be moved is named in the log (`could not be moved`), stays as it was and is moved the next time it is written |
| **The indicators of the old host evidence are read again** as found indicators (source `found:evidence.*`), by the setting of the found indicators: private and reserved addresses and benign names are left out by default, and 500 are kept for an incident. 6.x listed them all. To keep them, turn off **leave out private** and **leave out benign** before the upgrade | The indicators of an old incident: the private addresses its event logs named are no longer listed |
| **Your keywords become Sigma rules** (`0057`): the entries you added or changed, those Nik did not ship, are written as rules on the records of browsers, stored as not checked. The list of suspicious keywords and `keywords` of the settings are gone. The malware keywords of the Malware tab stay | **Platform settings › Rule sets › Sigma rules**: the pack **written here** |
| **The worker checks the rules** when it answers: each rule stored as not checked is read, gets its level and log source and, if Nik cannot run it, the reason | The count of rules **not checked** (`unchecked` in `GET /api/sigma/rules/summary`) goes to zero. It stays up while the `forensics` container is not |
| The two built-in packs, **Nik** (60 rules) and **Nik process chains** (16), are added | The same page |

How long the move takes depends on how much host evidence you hold: measure it on a copy.

!!! note "Old files are not read again"
    Nothing is parsed again at the upgrade: 6.x kept no original. To have the report, the original and the viewer for an old file, import the file again. An event-log record meets its old self as a duplicate (same key) and the flags and notes it carries stay. Records of browsers, histories and artifacts had only an id made at each import, so they are not recognised and are added again: delete the old source after that.

#### What to set for 7.0 {#what-to-set-for-70}

1. **The forensics worker** needs `FORENSICS_TOKEN`. `deploy/init-env.sh` makes it as it makes the others: a file `forensics_token` in `./secrets` (or `FORENSICS_TOKEN=` in `.env` on an install that keeps its secrets there). The Compose file gives it to `api` and `forensics` only. `deploy/secrets.sh rotate tokens` rotates it with the others ([Keys and secrets](secrets.md)).
2. **The time zone of the working hours**, in **Platform settings › Analysis › Business hours**. It is UTC until set, and the rule for remote logons outside working hours and the timers read it. An incident can have its own.
3. **Roles.** Two are new: **archive** (archive an incident, take it out, the rule that does it) and **evidence** (download the original of a file). An administrator has both; no other role does. Give them in **Access › Accounts and roles**. Whoever edits Sigma rules needs **rules**.
4. **Archiving** is off. To archive the incidents closed for N days by itself, set it in **Incidents › Archiving**.
5. **The new variables of `.env`**, all optional:

| Variable | Default | What it does |
| --- | --- | --- |
| [`EVIDENCE_MAX_MB`](../reference/configuration.md#EVIDENCE_MAX_MB) | 8192 | The largest file of host evidence sent in parts (`/api/uploads`) |
| [`COLLECTION_MAX_MB`](../reference/configuration.md#COLLECTION_MAX_MB) | 20480 | The largest collection (a KAPE or Velociraptor zip); the worker takes the same bound |
| [`FORENSICS_TOKEN`](../reference/configuration.md#FORENSICS_TOKEN) | made by `init-env.sh` | The secret between `api` and `forensics` |
| [`FORENSICS_URL`](../reference/configuration.md#FORENSICS_URL) | empty in the code; `http://forensics:8760` in Compose | Where `api` finds the worker. Empty: files are kept and wait |
| [`FORENSICS_MEMORY`, `FORENSICS_CPUS`](../reference/configuration.md#limits-of-the-containers) | 4g, 2 | The limits of the container |
| [`FORENSICS_MAX_JOBS`](../reference/configuration.md#FORENSICS_MAX_JOBS) | 2 | Files read at once; more are answered busy and wait |
| [`FORENSICS_JOB_MEMORY_MB`](../reference/configuration.md#FORENSICS_JOB_MEMORY_MB) | 1536 | What one file may use, in its own process |
| [`NIK_COPY`, `NIK_COPY_OF`](../reference/configuration.md#NIK_COPY) | `false`, empty | A copy of another server: [Try a release on a copy](try-on-a-copy.md). Never on the real server |

Rarely needed, in an override of the `forensics` service: `FORENSICS_JOB_SECONDS` (21600), `FORENSICS_SIGMA_SECONDS` (120), `FORENSICS_FILES_MB` (49152), `FORENSICS_FILE_IDLE` (900) and `FORENSICS_STOP_GRACE` (20). See [Environment variables](../reference/configuration.md#the-forensics-worker).

#### What breaks

| What | What to do |
| --- | --- |
| A script or an integration that reads `data.eventlogs`, `data.endpoint`, `data.browser` or `data.commands` of an incident | They are empty once the incident has moved. Read `/api/incidents/{id}/evidence/records` and the other routes of the [API](../reference/api.md#host-evidence) |
| A client that sends evidence with `POST /api/incidents/{id}/upload` | It works as before (same parameters, 500 MB) and now keeps the original. A file the incident already holds is answered as already imported. For large files use `/api/uploads` |
| `nik.add-evidence` in a playbook | The same parameters: it keeps the original and the worker reads it |
| An incident export of 6.x | It imports. A 7.0 export has no records and no originals: its files show **original absent** until given again |
| `keywords` in `GET /api/settings` | Gone; `PUT` ignores it. The Cortex XSOAR integration's `nik-get-settings` no longer returns `Nik.Settings.keywords` |
| Detection rules you kept in the browser's settings | They are Sigma rules now: **Rule sets › Sigma rules** |
| The content security policy | `'wasm-unsafe-eval'` is gone, and so is the `.wasm` type of nginx. A reverse proxy of yours that copies the policy, and an install without containers, drop it too ([the server block](manual-install.md#step-7-nginx-server-block)) |
| Deleting, archiving or analysing again a file with millions of records | No longer cut by the 30 s statement limit; it takes about a minute per million records |
| An incident deleted in another window | The person goes back to the list and sees "The incident was deleted" |
| Playbooks and scripts that need host evidence | Two read-only nodes, **List the host evidence files of an incident** and **Read host evidence records** ([Playbook nodes](../reference/playbook-nodes.md#host-evidence)); a script cannot read Nik, the playbook hands it the result |
| Files stay waiting | The `forensics` container is not up or `FORENSICS_URL` is empty: a file is kept and read when the worker answers |
| An analyst cannot download an original | They need the **evidence** role |
| A PDF report requested by a script | `detections` in the request is ignored: the server reads them from the tables |

#### Going back from 7.0 {#going-back-from-70}

- **A backup made by 7.0 is not read by 6.x.** The way back is the 6.11 backup you took before starting, or the snapshot the upgrade took (**Snapshots from before upgrades**): [`deploy/rollback.sh`](#an-upgrade-went-wrong) puts it back as for any upgrade, and what was written after the upgrade is lost.
- The originals stored since the upgrade, under `_evidence/` in the store, are not named by the old database, and 6.x does not use them.
- Keep the `pool-*` folders with the 7.0 backups, wherever you copy them. A backup restored without its pool folder is refused before anything is changed ([Backups](backups.md#the-pool-beside-the-backups)).
- On a pair of hosts, the standby goes first ([Upgrading a pair](recovery.md#upgrading-a-pair)).

More: [Try a release on a copy](try-on-a-copy.md), [Backups](backups.md), [Keys and secrets](secrets.md), [the host evidence guide](../guide/host.md) and the [Changelog](../changelog.md).

### Upgrading to 6.11.0 {#upgrading-to-6110}

`git pull`, then `docker compose up -d --build`. No migration, nothing to set.

- The SentinelOne EDR pack goes to 1.3.0: update it from **Content packs**. Its instances gain **Note authors that are automations**, Hyperautomation when left empty. A closed incident mirrored in takes as close notes the last note a person wrote on the threat, at its next read: a closed incident is read for a day after closing, so older ones are not filled. Close notes written in Nik stay.
- The comments a mirror brings in move from the **Automation** chip of the War Room to **Notes**.

### Upgrading to 6.10.2 {#upgrading-to-6102}

`git pull`, then `docker compose up -d --build`. No migration, nothing to set.

- The playbooks Nik ships that send e-mail use the Mail connector's `send` command. A server that has them already keeps its copies, with the older node, which still works (a shipped playbook is added once, and is not added again once deleted). To take the new one, change the node by hand, or **Import** the file from `backend/app/automation/seed/playbooks/` on the list of playbooks: it arrives as a draft, with " (2)" after its name while the old one is there.
- A node of a connector left with no instance named now sends through the only instance that is on. A playbook whose node names none, on a connector with two instances or more, still has to name one.

### Upgrading to 6.10.1 {#upgrading-to-6101}

`git pull`, then `docker compose up -d --build`. No migration, nothing to set.

- Nik is under [PolyForm Shield 1.0.0](https://github.com/n36l3c7/Nik/blob/main/LICENSE) from this release: free to use, change and share, in a company too, but not to offer a product or service that competes with it. 6.10.0 and before stay under MIT.
- An install without containers that followed the old page of the manual install may have no `STORE_KEY` in its `.env`: its store is then sealed with the public key of development, which anyone can read in the source. Look in `.env`. The rotation of [Keys and secrets](secrets.md#change-a-key) puts the store under a key of its own; its script is written for the containers, so on such a server keep a backup and a copy of the store volume before you try it.

### Upgrading to 6.10 {#upgrading-to-610}

`git pull`, then `docker compose up -d --build`. Migrations `0054_indicators_found` and `0055_bulk` run after the snapshot and the rehearsal.

- From before 6.0.0: go to 6.9.0 first, start it once, then 6.10.
- **Update Nik first, then the packs** Jira Cloud, Jira Data Center, ServiceNow, SentinelOne and SentinelOne SIEM from **Platform settings › Automation › Content packs**: they need 6.10. Updating Jira or ServiceNow sets their instances that said None to In, so tickets go on being mirrored.
- Every other instance starts at mirroring None; existing mirrors go on as they were. The mail connector is brought to version 4 at start and mirrors nothing until an instance is set to In.
- Indicators are found in incidents that come in after the upgrade (up to 500 each). Older incidents are read only when someone presses **Find indicators now**.
- Choosing Out or In-out now needs the permission to run playbooks as well as to manage connectors.
- An install without containers sets the mailbox location of its nginx to `4200m` ([the server block](manual-install.md#step-7-nginx-server-block)).

### Upgrading to 6.9 {#upgrading-to-69}

`git pull`, then `docker compose up -d --build`. Migrations `0052_recovery` and `0053_jobs` run after the snapshot and the rehearsal; every image is rebuilt and PostgreSQL restarts once with its new settings.

- **The archive turns on by itself**: a new service `recovery` and the volumes `wal-archive` and `db-socket`; a base backup is taken at once and then every day. It uses disk; `NIK_WAL_ARCHIVE=off` turns it off. If you start a subset of services, add `recovery`. See [Recovery and standby](recovery.md).
- Work in flight: playbook steps that may be repeated are done again, the others wait for a person (look at **Automations › Runs** afterwards). Analyses, scans and mailboxes start again by themselves; a file being parsed after its upload ends in error and is uploaded again.
- The copies off the host need what the backups already have (a passphrase and a destination) and go under `recovery/` there.
- The stack now stops politely, in at most a minute. An install without containers changes its unit: gunicorn runs with `-k app.serving.Worker`.
- Going back below 6.9: see [Rolling back across 6.8 or 6.9](#an-upgrade-went-wrong).

### Upgrading to 6.8 {#upgrading-to-68}

`git pull`, then **`deploy/init-env.sh`**, then `docker compose up -d --build`. The script adds the store key `STORE_KEY` to an existing install and changes nothing else; a server started without it stays up and says the key is missing. Migration `0051_audit_chain` runs after the snapshot and the rehearsal.

- **Keep a copy of `STORE_KEY` off the server**, apart from the backups. The store cannot be read without it; the backups can.
- The store is sealed in the background, about half a minute per gigabyte, shown in **System › Storage**. Files from before stay in clear until it ends.
- The existing audit log entries are linked and signed once, about a minute per million. To send the log to syslog, set it in **System › Audit log** ([Health and audit](health.md#forward-the-audit-log-to-syslog)).
- To take the secrets out of `.env`, run `deploy/secrets.sh move` when it suits ([Keys and secrets](secrets.md#a-server-that-keeps-them-in-env)).
- The workers no longer mount the store; a volume `pcap-work` is new.
- `/api/metrics` answers 401 without a scrape token made in **System › Health**; the `path` label of request metrics now begins with `/api`.
- Going back below 6.8: `deploy/rollback.sh` unseals the store and puts the secrets back in `.env` first.

### Upgrading to 6.7 {#upgrading-to-67}

`git pull`, then `docker compose up -d --build`. The Compose file gains the volume `backups`; to keep backups on another disk, set [`NIK_BACKUP_DIR`](../reference/configuration.md#NIK_BACKUP_DIR) before starting. Migrations `0048_backups` and `0049_two_factor` run after the first snapshot.

- **Set the backup passphrase** in **System › Backup** and write it down. No backup is taken until it is set. Then set the second host ([Backups](backups.md#set-up-the-backups)).
- An administrator's session unused for 30 minutes now ends (a warning comes a minute before); everyone else's after 8 hours. Nobody is asked for a second factor until **Administrators must have a second factor** is on: set up your own first.
- A change of an account's roles signs it out. The five-minute lock after ten wrong passwords is replaced by waits that grow.
- Remove any override that sets `FORWARDED_ALLOW_IPS=*`: the Compose file trusts the web container only.
- Run `sudo deploy/install-systemd.sh` again to remove the old nightly backup timer, or two backups are taken each night. `deploy/backup.sh` no longer reads `BACKUP_DIR` or `KEEP_DAYS`.
- **Full backup** is now **Export as one file**, and importing one adds to the server instead of replacing it.
- After a restore or a rollback everybody signs in again.
- 6.7.1: after a restart of the host the server waits for the database. A 6.7.0 server that shows "the upgrade was stopped" after a reboot, with no snapshot or migration in the log above, only needs `docker compose restart api automation`.

### Upgrading to 6.6 {#upgrading-to-66}

`git pull`, then `docker compose up -d --build`. Migrations `0046_credentials` and `0047_playbook_files` add three tables and change nothing stored.

- **Look-ups that were sent before may now be held.** **Check now**, bulk checks and automatic look-ups no longer send a value that carries an e-mail address, a name under your own domains (or a private address inside a link), or an allowlisted name inside a longer value, until an administrator opens that class in **Platform settings › Indicators › Threat intelligence**. All classes are closed after the upgrade.
- **Update Nik first, then the packs**: SentinelOne EDR and SIEM 1.1.0 and Shodan, Google Safe Browsing and GreyNoise 1.1.1 need 6.6. Stored keys are kept.
- A SentinelOne action whose id comes out empty now fails before it is sent.
- The rail entry of Settings is named **Platform settings**: scripts that drive the interface follow.

## Related

- [Try a release on a copy](try-on-a-copy.md) — rehearse an upgrade on your own data
- [Changelog](../changelog.md) — every change of every release
- [Backups and restore](backups.md) — the passphrase that encrypts the snapshots
- [Recovery and standby](recovery.md#upgrading-a-pair) — upgrading a pair
- [Install without containers](manual-install.md#update-to-a-new-version) — the manual steps
