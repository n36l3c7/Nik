# Try a release on a copy

Restore a production backup into a second stack on the same server, start the new release on it, and check it on your own data before the real server changes.

!!! note "You need"
    A shell on the host, the passphrase of a recent backup, and room for a second stack: disk for the database and the store, memory for the containers, and two free ports.

!!! info "How to read the steps"
    **[script]** marks what was checked by reading `deploy/restore.sh`, `deploy/init-env.sh`, `docker-compose.yml` and `backend/app/core/copy.py`. **[yours]** marks what depends on your server: the engine, the network, the firewall, your backup layout. Nothing here was run against your server.

## Why a copy does nothing outward

A restored backup holds the real server's connections, schedules, webhooks, mail settings and the destination of its backups. Started as it is, the copy would:

- fetch from the real systems and write back to them (mirroring, instance actions);
- run the schedules and the playbooks that start by themselves, send mail and call webhooks;
- apply its **retention to the off-site backups**: it would delete the real backups on the SFTP host;
- ship the archive of the database log to the real standby.

So a stack with `NIK_COPY=true` shuts every door to the outside where it would open, and says so with one sentence **[script]**:

| A copy does not | Where it says so |
| --- | --- |
| Fetch, mirror, run an action of a connector, read a mailbox | The automation worker skips what is due and leaves it due; a request to another system is refused |
| Send mail, call a webhook | `This server is a copy of <name>: it does not send mail`; the log line `Webhook … not sent: this server is a copy` |
| Run a playbook that starts by itself (schedule, event, hook) | Nothing starts. A run by hand is refused with `This server is a copy: a playbook runs here only as a dry run, which sends nothing` (409): run it as a dry run |
| Copy a backup off the server, apply its retention there | `This server is a copy: it does not reach the destination of the backups` |
| Ship to the standby or the archive destination | Nothing is sent |
| Forward the audit log to syslog | Nothing is sent |
| Ask the threat-intelligence sources, scan an address | Refused: the look-ups of a copy are not made |
| Archive closed incidents by the rule of **Archiving** | The rule does not run; archive by hand to test |

What stays is what a copy is for: everything a person does in it, the analysis workers, the local backups, the restore.

**[script]** Once you are signed in, every page shows a banner, **COPY of** the name you gave, from `GET /api/auth/me` (`server.copy`, `server.copyOf`). The sign-in page does not show it. The Health page shows no row for it: the banner is the sign.

!!! warning "The old version must never start on the copy"
    6.11 and earlier know nothing of `NIK_COPY`. A 6.x stack started on the restored backup would do all of the above. That is why the steps below never start the old version: the restore is done with the **new** version's `deploy/restore.sh` (only it has `--as-copy`), which reads a backup of an older version, and the first start is the new version's.

## The steps

### 1. A folder, a project, ports

Clone Nik to a folder of its own, at the release you want to try. Do not use the folder of the real server.

```sh
git clone https://github.com/n36l3c7/Nik.git /opt/nik-copy
cd /opt/nik-copy
git checkout v7.0.0            # the tag, or the release candidate branch
deploy/init-env.sh             # a .env and fresh secrets of its own
```

The scripts use Podman when it is installed, else Docker (`ENGINE=docker` or `ENGINE=podman` chooses; `COMPOSE` sets the compose command).

**[script]** `deploy/init-env.sh` makes `.env` and `./secrets` of this folder, with every key new: `SECRET_KEY`, `STORE_KEY`, `AUDIT_KEY`, the worker tokens, `DB_PASSWORD`. The copy shares none of the real server's.

Then edit `.env`:

```sh
COMPOSE_PROJECT_NAME=nik-copy     # its own containers, networks and volumes
WEB_TLS_PORT=9443                 # not the real server's 8443
WEB_PORT=9080                     # not 8080
TLS_HOSTNAME=nik-copy.example.org # what you will type in the browser
```

**[script]** `restore.sh --as-copy` refuses, and changes nothing, when:

- `COMPOSE_PROJECT_NAME` is empty or `nik`;
- `.env` sets `NIK_BACKUP_DIR`, `NIK_WAL_ARCHIVE_DIR` or `NIK_STANDBY_INBOX`. Those are directories of the host that the copy would share with the real server. Leave them out: the copy keeps its own in its volumes.

**[yours]** A second stack needs its own free ports. Under rootless Podman a port under 1024 is not available ([Install](install.md#ports)). Where the server's firewall allows it, **block the copy's outbound traffic as well**: Nik refuses to reach out, but a firewall rule does not depend on Nik being right.

### 2. Bring the backup

Copy the `.nikbak` of a recent backup of the real server to the copy's host, with its `.json` beside it if you like.

- **[script]** The file must be readable by every user of the host and its folder open (`chmod o+r` and `chmod 755`): the restore runs in a container as a user that is nobody on the host. It is encrypted.
- **[script]** A backup made by 7.0 names files in a folder `pool-<id>` beside it: copy that folder next to the file, or the restore refuses before anything is changed. A 6.11 backup has none.
- **[yours]** The passphrase of the backup, which you give when asked, or in `NIK_BACKUP_PASSPHRASE_FILE`.

### 3. Restore it, as a copy, without starting

```sh
NIK_COPY_OF=nik-prod deploy/restore.sh --as-copy --no-start /srv/copy/nik-20261124-023000.nikbak
```

**[script]** What this does, in order:

1. Writes `NIK_COPY=true` and `NIK_COPY_OF=<name>` into `.env` **before anything else**. The name is `NIK_COPY_OF` or, if you do not give one, the name of the backup. It is what the banner says.
2. Stops the stack of this project, starts the database alone, reads the whole file and checks every checksum. Nothing changes before that passes.
3. Restores the database and the store into the copy's volumes, each file sealed under the copy's own store key.
4. With `--no-start`, stops there: the stack is not started.

The `api` image is built from the folder's code, so it is the new version that restores. An older backup is migrated at the first start, after a snapshot and a rehearsal, as at any upgrade.

Two things to decide, **[yours]**:

- **The keys of the original.** Without `--secret-key` the copy has its own `SECRET_KEY`: what the database holds encrypted under the real one (the credentials of instances, second factors, the backup passphrase) cannot be read on the copy. That is the safest copy, and the one the guards were written for. With `--secret-key` (the backup must have been taken with **Include SECRET_KEY**) the copy reads them all, and the guards still stop it using them. Without it, add the real `AUDIT_KEY` and its `AUDIT_KEY_PREVIOUS` to the copy's `AUDIT_KEY_PREVIOUS` to see the audit log chain as valid (`restore.sh --help` says how). How an account with a second factor signs in when its secret cannot be read was not checked in the code: try it, and if it is blocked, use `docker compose exec api python -m app.account reset-second-factor <username>` on the copy.
- **The passphrase of the copy's own backups.** The one the database holds is unreadable without `--secret-key`: set one in **System › Backup** when you test a backup.

### 4. Start it as the new version

=== "Docker"

    ```sh
    docker compose up -d --build
    docker compose logs -f api
    ```

=== "Podman"

    ```sh
    podman compose up -d --build
    podman compose logs -f api
    ```

**[script]** This is the first start of the restored database, by the new version: the snapshot, the rehearsal, migrations `0056` to `0059`, and the move of the old host evidence in the background ([Upgrading to 7.0](upgrades.md#what-happens-at-the-first-start)). One log line gives the seconds of the first three (`upgrade: The database is at the revision 0059_processes (was: 0055_bulk). Seconds: snapshot …, rehearsal …, migration …`); the move ends with its own line. Time each, to know what the real upgrade will take.

Open `https://<host>:9443`. **[script]** After you sign in, the banner **COPY of nik-prod** is on every page. If it is not, stop the stack at once (`docker compose down`, or `podman compose down`) and look at `NIK_COPY` in `.env`.

### 5. Check that nothing leaves

1. The banner is there after you sign in.
2. Take a backup in **System › Backup**: it stays on the copy. A copy off the server is not made, whatever the restored settings say.
3. Run a playbook of yours as a normal run: it is refused with the sentence above. As a **dry run** it works.
4. Look in the log of the worker for refusals: `docker compose logs automation | grep -i copy`.
5. **[yours]** Look from outside: the real SFTP host's log shows no connection from the copy; the real systems see no request from it. Where you can, watch the copy's outbound traffic during the first hour (a firewall counter).

### 6. The checklist for 7.0

Run it on the copy. Each line is a finding to record, with the time it took.

| Check | What to look at |
| --- | --- |
| **The upgrade completes** | `docker compose logs api` ends with the server up; **System › Health** has no row in need of attention (without the real `AUDIT_KEY` in `AUDIT_KEY_PREVIOUS`, **Keys of the server** says `A key of the audit log is missing`: expected); **System › Workers** lists the **forensics worker** as up |
| **The old evidence moved** | The log line `Host evidence of before 7.0: every incident was looked at (N moved)`. Open an incident that had host evidence: its files say **imported before 7.0** and the counts equal those on the real server |
| **Keywords became rules** | **Rule sets › Sigma rules**, pack **written here**: one rule per entry you had added; none left **not checked** |
| **Originals re-imported** | Import again one file of an old incident: it gets its original, a report and the viewer; the event-log records meet the old ones as duplicates and keep their flags |
| **An event log, a hive, a `$MFT`** | Add one of each to an incident. Each has a report; open a record in the viewer; check the counts against what you know of the file. A `$MFT` of a few hundred thousand entries takes minutes |
| **Detections** | A log with something your rules should find: the **Detections** tab, the level, the line in the War Room |
| **A collection** | A KAPE or Velociraptor zip: the listing, then the import of some of its files |
| **Archive one incident** | Close one, archive it, see it leave the lists, open it by its address, take it out and see the files read again |
| **A backup and a restore of the copy** | **Back up now** (it stays on the copy). A folder `pool-<id>` appears beside it in the copy's backup volume. Restore it into the copy with `deploy/restore.sh --replace` and check that nothing is lost |
| **The forensics worker's limits** | Send a file larger than `EVIDENCE_MAX_MB` (refused with a sentence); `docker compose stop forensics` during an import (the file is kept and waits) and start it again; look at the worker's memory with `docker stats` while it reads the largest file you have |
| **Disk** | `df` and `docker system df` before and after: the database, the store and the work volume of the worker |

If something fails, keep the copy as it is, copy the log lines and report them ([Security](../reference/security.md#reporting-a-vulnerability) says where for a security problem; an issue on GitHub for the rest).

### 7. Throw the copy away

**[script]** The copy's containers, networks and volumes are all under its project name, so this removes only them:

=== "Docker"

    ```sh
    cd /opt/nik-copy
    grep COMPOSE_PROJECT_NAME .env     # make sure it is nik-copy, not the real server's
    docker compose down -v             # stops it and deletes ITS volumes
    cd / && rm -rf /opt/nik-copy
    ```

=== "Podman"

    ```sh
    cd /opt/nik-copy
    grep COMPOSE_PROJECT_NAME .env     # make sure it is nik-copy, not the real server's
    podman compose down -v             # stops it and deletes ITS volumes
    cd / && rm -rf /opt/nik-copy
    ```

Delete the copy of the backup you brought: it holds the real data. **[yours]** Remove the built images if you need the disk (`docker image prune`, `podman image prune`), and the firewall rule you added.

## When it is time for the real upgrade

With the copy's findings in hand, follow [Upgrading to 7.0](upgrades.md#upgrading-to-70) on the real server, and take a new backup first: the copy tested the backup you restored, not what was written since.

## Related

- [Upgrades](upgrades.md) — the snapshot, the rehearsal and how to roll back
- [Backups and restore](backups.md#restore-a-backup) — `restore.sh` and its options
- [Recovery and standby](recovery.md) — a new host, a standby
- [Environment variables](../reference/configuration.md#NIK_COPY) — `NIK_COPY` and `NIK_COPY_OF`
