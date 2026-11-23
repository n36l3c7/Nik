# Run the server

Install Nik for a team, keep it safe and backed up, bring it back after a failure, and upgrade it.

!!! note "You need"
    A shell on the host that runs Nik, and an account with the **Admin** role for the screens under **Platform settings › System**.

<div class="grid cards" markdown>

-   :material-server-network: **[Install in production](install.md)**

    ---

    Docker or Podman, rootless, behind a proxy, your own TLS certificate, start on boot. The services and their ports.

-   :material-tune: **[Configuration](configuration.md)**

    ---

    The `.env` file, what to set before the first start, and the system settings an administrator changes in the app.

-   :material-key-variant: **[Keys and secrets](secrets.md)**

    ---

    The secrets as files, the store key, changing a key with `deploy/secrets.sh`, and what to keep off the server.

-   :material-backup-restore: **[Backups and restore](backups.md)**

    ---

    The backups Nik takes and tests by itself, the copy to a second host, restoring, and the export of content.

-   :material-history: **[Recovery and standby](recovery.md)**

    ---

    Go back to any moment, keep a standby host, promote it when the first host dies. What is lost and how long it takes.

-   :material-update: **[Upgrades](upgrades.md)**

    ---

    How an upgrade runs (snapshot, rehearsal, migrations), how to roll back, and what each release asks of you.

-   :material-heart-pulse: **[Health and audit](health.md)**

    ---

    The Health page, workers, storage, Prometheus metrics, the audit log chain, syslog forwarding, and **Stop all**.

-   :material-linux: **[Install without containers](manual-install.md)**

    ---

    A manual install on RHEL 8 or 9 with PostgreSQL, systemd and nginx.

</div>

## The short version

```sh
git clone https://github.com/n36l3c7/Nik.git && cd Nik
deploy/init-env.sh                 # .env and the secrets, each in a file of ./secrets
docker compose up -d --build       # or: podman compose up -d --build
```

Then, in this order:

1. Open `https://<host>:8443` and create the first account at once: it becomes the admin. See [First sign-in](../get-started/first-sign-in.md).
2. Copy the `./secrets` directory somewhere off the server ([Keys and secrets](secrets.md#what-to-keep-off-the-server)).
3. Set a backup passphrase and a second host in **Platform settings › System › Backup** ([Backups](backups.md#set-up-the-backups)).
4. Turn on **Administrators must have a second factor** and send the audit log to syslog ([Hardening checklist](../reference/security.md#hardening-checklist)).

## Related

- [Get started: Install](../get-started/install.md) — a first try on one machine
- [Environment variables](../reference/configuration.md) — every variable, with its default
- [Security](../reference/security.md) — the threat model and the hardening checklist
- [Architecture](../reference/architecture.md) — what runs where
