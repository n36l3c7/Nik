# Install in production

Run the whole Nik stack on one Linux host with Docker or Podman Compose, served over HTTPS.

!!! note "You need"
    - A Linux host with Docker Engine and Compose, or Podman with `podman compose` / `podman-compose`, and `git`.
    - Memory for the workers: each runs under its own limit (4 GB for the analyzer, capa and packet capture workers by default, see [Limits of the containers](../reference/configuration.md#limits-of-the-containers)).
    - Disk for the store of files, the backups and the archive of the database log ([Backups](backups.md#where-backups-go), [Recovery](recovery.md#what-it-takes-on-the-disk)).

## Install

=== "Docker"

    ```sh
    git clone https://github.com/n36l3c7/Nik.git /opt/Nik && cd /opt/Nik
    deploy/init-env.sh                # writes .env and the secrets, each a file of ./secrets
    $EDITOR .env                      # TLS_HOSTNAME, the ports (below)
    docker compose up -d --build      # builds the images and starts the stack
    ```

=== "Podman"

    ```sh
    git clone https://github.com/n36l3c7/Nik.git /opt/Nik && cd /opt/Nik
    deploy/init-env.sh                # writes .env and the secrets, each a file of ./secrets
    $EDITOR .env                      # TLS_HOSTNAME, the ports (below)
    podman compose up -d --build      # or: podman-compose up -d --build
    ```

    Rootless Podman works: run every command as the user that will own the stack.

1. Run `deploy/init-env.sh` as the user that runs the stack. It creates `.env` from `.env.example` and a fresh random value for every secret. It is safe to run again: it only adds what is missing.
2. Set `TLS_HOSTNAME` to the name users type in the browser. Change `WEB_TLS_PORT` / `WEB_PORT` if 8443 / 8080 are taken.
3. Start the stack. The `api` container creates the database schema and migrates it at every start.
4. Open `https://<TLS_HOSTNAME>:8443` and **create the first account at once**: whoever creates it becomes the admin. See [First sign-in](../get-started/first-sign-in.md).
5. Copy `./secrets` off the server ([Keys and secrets](secrets.md#what-to-keep-off-the-server)), then [set up the backups](backups.md#set-up-the-backups).

!!! warning "The stack refuses example secrets"
    The stack does not start without `DB_PASSWORD`, `SECRET_KEY`, `STORE_KEY` and one token per worker, and refuses the values printed in `.env.example` (they are public). If the page says a key is missing or wrong, see [Nik did not start](secrets.md#nik-did-not-start-a-key-is-missing-or-wrong).

Day-to-day commands (replace `docker` with `podman` as needed):

```sh
docker compose ps              # state of every container
docker compose logs -f api     # follow the backend
docker compose down            # stop; the volumes stay
docker compose down -v         # stop AND delete every volume: database, files, backups, certificate
```

## The services

| Service | What it does | Network |
| --- | --- | --- |
| `web` | nginx: serves the app over HTTPS, redirects HTTP, proxies `/api/` to `api`, sends the security headers | the only published ports |
| `api` | The backend (FastAPI): the API, the analyses it does itself, the store of files, the backups | database, workers, sandbox |
| `db` | PostgreSQL 18; archives its write-ahead log | stack only |
| `recovery` | Takes the base backups and proves the archive, for the backend | none at all (a shared socket) |
| `automation` | Runs playbooks, fetching and mirroring; sends backup copies and the audit log out | the one way out for playbooks |
| `sandbox` | Runs the Python scripts of playbooks | internal, no route out |
| `analyzer` | Disassembly and decompilation of samples (rizin) | internal, no route out |
| `capa` | Capabilities of samples (capa) | internal, no route out |
| `docview` | Previews of documents (LibreOffice, pdfium); converts Outlook PST files | internal, no route out |
| `pcap` | Packet captures (Wireshark's engine) | internal, no route out |
| `browser` | The isolated browser (Chromium) for HTML attachments and addresses | a filtered way out of its own |

Only the `api` container mounts the store of files and holds its key. The [Architecture](../reference/architecture.md) page shows how they connect; [Security](../reference/security.md#containment) says how each is locked down.

??? info "Running without some services"
    - **No playbooks:** set `AUTOMATION_WORKER=off` in `.env` and stop `automation` and `sandbox`. The Automations area then says the worker is not answering.
    - **No analysis workers:** each view that needs one (Code, Capabilities, previews, the isolated browser, Network Analysis) says "not configured"; everything else works.
    - **Starting a subset of services** by name: include `recovery` with `db`.

## Ports

| Port on the host | Variable | Default | Serves |
| --- | --- | --- | --- |
| HTTPS | `WEB_TLS_PORT` | 8443 | The app and the API |
| HTTP | `WEB_PORT` | 8080 | Only a redirect to HTTPS |

Nothing else is published: not the database, not the workers. Ports below 1024 need rootful Podman (or a lower `net.ipv4.ip_unprivileged_port_start`).

## TLS certificates

=== "Self-signed (default)"

    On its first start the `web` container makes a certificate for `TLS_HOSTNAME` (valid `TLS_SELFSIGNED_DAYS`, 825 days) in the `web-certs` volume. Browsers warn until they trust it.

    To make it again, for example after changing `TLS_HOSTNAME`:

    ```sh
    docker compose down
    docker volume rm nik_web-certs     # <project>_web-certs
    docker compose up -d
    ```

=== "Your own certificate"

    Recommended. Put a certificate from your internal CA or Let's Encrypt as `nik.crt` and `nik.key` in `/etc/nginx/certs` of the `web` container. The start-up script never overwrites an existing pair.

    The easiest way: in `docker-compose.yml`, replace the `web-certs` volume with a bind mount:

    ```yaml
    web:
      volumes:
        - ./certs:/etc/nginx/certs     # nik.crt and nik.key; add :Z under SELinux
    ```

The Health page warns 30 days before the certificate expires ([Health](health.md#the-health-page)).

## Behind a reverse proxy

You can put a proxy that terminates TLS (nginx, Caddy, Traefik) in front of the stack:

1. Proxy to `https://127.0.0.1:8443` and tell the proxy to accept the self-signed upstream certificate.
2. Bind the two published ports to `127.0.0.1` in `docker-compose.yml` (`"127.0.0.1:8443:443"`).

!!! warning "The client's address is lost"
    The `web` container replaces `X-Forwarded-For` with the address it saw, on purpose. Behind a host proxy, every request seems to come from that proxy: the waits after failed sign-ins and the administrators' networks cannot work per address. See [The client's address](configuration.md#the-clients-address).

## Behind an outgoing proxy

- **Playbooks and connectors** leave through the `automation` container. With an explicit proxy, set `AUTOMATION_HTTPS_PROXY` (and `AUTOMATION_NO_PROXY`) in `.env`. A transparent proxy needs nothing.
- **The content-pack catalogue** is read by the `api` container from `github.com`, `objects.githubusercontent.com` and `release-assets.githubusercontent.com` over HTTPS, directly or through `HTTPS_PROXY` given to that container in a Compose override. Without them, install packs from a file or from `NIK_PACKS_DIR` ([Content packs](../guide/packs.md)).
- Behind a proxy that inspects TLS, its certificate authority must be trusted by the containers that go out.
- **Backup copies and syslog** do not go through an HTTP proxy: the second host and the syslog receiver must be reachable directly from `automation`.

## Rootless Podman and SELinux

- Rootless works for ports 8080/8443. Under rootless Podman (and Docker Desktop) the server cannot see client addresses ([The client's address](configuration.md#the-clients-address)).
- Named volumes are relabeled for SELinux automatically. A bind mount needs `:Z`. A host directory used for backups, the archive or secrets needs a label once: `chcon -Rt container_file_t /srv/nik-backups`.
- Every image names its registry (`docker.io/...`), so Podman never asks `registry.redhat.io` for credentials. `deploy/check-images.sh` (run by CI) fails on a short image name.

## Start on boot

`restart: unless-stopped` does not bring a `podman-compose` stack back after a reboot. Install the systemd unit:

```sh
sudo deploy/install-systemd.sh
```

It installs and enables `nik.service`: `compose up -d` at boot, `compose down` at shutdown, with `TimeoutStopSec=300` so every container can stop politely.

| Option | Effect |
| --- | --- |
| `--dir PATH` | The repository root (default: the current repository) |
| `--compose "CMD"` | The compose command (default: `podman compose`, else `docker compose`) |
| `--uninstall` | Stop, disable and remove the unit |

## Stopping and restarting

Nothing is lost by a restart, and nothing is done twice. Playbook steps, analyses, fetches and bulk jobs are taken back by the process that starts next.

- A polite stop (`compose restart`, `up -d --build`, a host shutdown) gives work in flight 20 to 25 seconds; the whole stack stops in under three minutes.
- After a kill or a power cut, allow about a minute after the containers are up for work to be taken back.
- An upload still arriving fails with a sentence and can be tried again.

??? info "What a restart does to each kind of work"
    | In progress | After the restart |
    | --- | --- |
    | A playbook step that may be repeated | Done again; the run goes on |
    | A step that changes another system and may not be repeated | Waits for a person to say whether it happened |
    | A wait, a schedule, an SLA timer | Waits on; a missed time is acted on once |
    | A fetch | Goes on from where it was |
    | An analysis on a worker | Started again from the stored file within a minute |
    | An upload being received or parsed | Fails; the transfers tray offers **Try again** |

    Work interrupted three times is set aside as failed. The [Health page](health.md#work-in-progress) counts it.

## Related

- [Configuration](configuration.md) — what to set in `.env` and in the app
- [Keys and secrets](secrets.md) — where the secrets are and how to change them
- [Backups and restore](backups.md) — set them up on day one
- [Install without containers](manual-install.md) — RHEL with systemd and nginx
- [Environment variables](../reference/configuration.md) — the full list
