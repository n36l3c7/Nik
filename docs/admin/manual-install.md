# Install without containers

Install Nik by hand on RHEL 8 or 9 (the same steps work on Rocky Linux and AlmaLinux): PostgreSQL, the backend under systemd, nginx in front.

!!! warning "Prefer the Compose stack"
    This install has **no analysis workers** and **no archive of the database log**. The Code and Capabilities views, document previews, the isolated browser, Network Analysis and address scans say "not configured"; samples and e-mails are still analysed statically and every other tab works. There is no recovery to a moment and no standby. Unless you must avoid containers on the host, use [Install in production](install.md): it is the supported way and the one that isolates hostile files.

    The workers can still run with the Compose file beside a manual backend: put their `*_URL` and `*_TOKEN` in `nik.env`.

nginx serves the app and proxies `/api/` to the backend, so the browser talks to one origin. Every command assumes a sudo-capable user.

## Step 1: build the static app

On the RHEL host or any machine with Node 22.12 or later (or 20.19), then copy `frontend/dist/` over. To install Node on RHEL:

```sh
curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash -
sudo dnf install -y nodejs
```

From the project's `frontend/` folder:

```sh
npm ci            # clean install from package-lock.json
npm run build     # writes the static site to dist/
```

## Step 2: PostgreSQL

Any PostgreSQL from 14 on works (CI tests 18).

```sh
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql

sudo -u postgres createuser --pwprompt nik
sudo -u postgres createdb -O nik nik
```

A fresh RHEL cluster uses ident/peer for local TCP, which refuses the `nik` login. In `/var/lib/pgsql/data/pg_hba.conf`, make the local lines use `scram-sha-256`:

```text
# TYPE  DATABASE  USER  ADDRESS         METHOD
host    nik       nik   127.0.0.1/32    scram-sha-256
host    nik       nik   ::1/128         scram-sha-256
```

Then `sudo systemctl reload postgresql`. The service creates and upgrades the tables itself (step 3).

## Step 3: the backend under systemd

The backend needs **Python 3.12**; RHEL's default `python3` is older.

```sh
sudo dnf install -y python3.12 python3.12-pip pango
sudo useradd --system --home /opt/nik --shell /sbin/nologin nik

sudo mkdir -p /opt/nik
sudo cp -r backend /opt/nik/backend
cd /opt/nik/backend
sudo python3.12 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install -r requirements.txt
sudo mkdir -p /var/lib/nik/samples /var/lib/nik/backups   # the store: exclude it from the antivirus
sudo chown -R nik:nik /opt/nik /var/lib/nik
```

Keep the settings in `/etc/nik/nik.env`, readable only by root and the service. One setting a line, **no comment after a value** (systemd would take it as part of the value):

```sh
sudo mkdir -p /etc/nik
sudo tee /etc/nik/nik.env >/dev/null <<EOF
DATABASE_URL=postgresql+psycopg://nik:STRONG_PASSWORD@localhost/nik
SECRET_KEY=$(openssl rand -hex 32)
STORE_KEY=$(openssl rand -hex 32)
COOKIE_SECURE=true
SAMPLE_STORE=/var/lib/nik/samples
BACKUP_DIR=/var/lib/nik/backups
RUN_CREATE_ALL=false
AUTOMATION_WORKER=inline
NIK_WEB_TLS=
EOF
sudo chmod 640 /etc/nik/nik.env
sudo chown root:nik /etc/nik/nik.env
```

Keep a copy of `SECRET_KEY` and `STORE_KEY` off the server ([Keys and secrets](secrets.md#what-to-keep-off-the-server)). Every variable is in [Environment variables](../reference/configuration.md).

Create `/etc/systemd/system/nik-api.service`. The API listens on loopback only:

```ini
[Unit]
Description=Nik FastAPI backend (gunicorn/uvicorn)
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=nik
Group=nik
WorkingDirectory=/opt/nik/backend
EnvironmentFile=/etc/nik/nik.env
# Snapshot, rehearsal, then migrations: what the container does at every start.
ExecStartPre=/opt/nik/backend/.venv/bin/python -m app.backups.upgrade
ExecStart=/opt/nik/backend/.venv/bin/gunicorn \
    -k app.serving.Worker --graceful-timeout 30 \
    app.main:app \
    --bind 127.0.0.1:8000 \
    --workers 3
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now nik-api.service
curl -s http://127.0.0.1:8000/api/health      # {"status":"ok"}
```

??? info "Settings in this unit"
    - `python -m app.backups.upgrade` takes a snapshot of the database into `BACKUP_DIR` and rehearses the migrations before running them, as the container does ([Upgrades](upgrades.md#what-happens-at-start)). A bare `alembic upgrade head` also works, without the snapshot.
    - `AUTOMATION_WORKER=inline` runs playbooks, fetching and the backup copy inside the API process. `off` runs nothing.
    - `NIK_WEB_TLS` empty: the Health page does not read a certificate. Set it to `127.0.0.1:443` to have it read nginx's.
    - `FORWARDED_ALLOW_IPS` stays unset: gunicorn then believes `X-Forwarded-For` from `127.0.0.1` only, which is this nginx. Never set it to `*`.

## Step 4: nginx and the static files

```sh
sudo dnf install -y nginx
sudo systemctl enable --now nginx
sudo mkdir -p /var/www/nik
sudo cp -r dist/* /var/www/nik/
```

## Step 5: SELinux

```sh
# a) let nginx connect to the backend (otherwise /api/ answers 502 and the audit log has "AVC denied … name_connect")
sudo setsebool -P httpd_can_network_connect 1

# b) label the static files (otherwise nginx answers 403)
sudo dnf install -y policycoreutils-python-utils
sudo semanage fcontext -a -t httpd_sys_content_t "/var/www/nik(/.*)?"
sudo restorecon -Rv /var/www/nik
```

## Step 6: TLS certificate

For an internal host a self-signed certificate is enough. Replace the names with yours:

```sh
sudo mkdir -p /etc/pki/nginx/private
sudo openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout /etc/pki/nginx/private/nik.key \
  -out    /etc/pki/nginx/nik.crt \
  -subj "/CN=nik.example.internal" \
  -addext "subjectAltName=DNS:nik.example.internal,IP:10.0.0.10"
```

For an internet-facing host use a real certificate (for example `sudo dnf install -y certbot python3-certbot-nginx`).

## Step 7: the .wasm type

The app loads a WebAssembly module. RHEL 9's nginx maps it already; on RHEL 8 add this line to the `types { … }` block of `/etc/nginx/mime.types` if missing:

```text
application/wasm  wasm;
```

## Step 8: nginx server block

Create `/etc/nginx/conf.d/nik.conf`:

```nginx
server {
    listen 80;
    server_name nik.example.internal;
    return 308 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name nik.example.internal;

    ssl_certificate     /etc/pki/nginx/nik.crt;
    ssl_certificate_key /etc/pki/nginx/private/nik.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Large uploads (captures up to PCAP_MAX_MB, incidents with parsed artifacts).
    client_max_body_size 600m;

    root  /var/www/nik;
    index index.html;
    include /etc/nginx/snippets/nik-headers-page.conf;

    # A mailbox (mbox, Maildir archive, PST) can be gigabytes: only its upload
    # may be that large, unbuffered. Covers MAILBOX_MAX_MB and PST_MAX_MB.
    location = /api/artifacts/mailboxes {
        client_max_body_size 4200m;
        proxy_request_buffering off;
        proxy_read_timeout 900s;
        proxy_send_timeout 900s;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        include /etc/nginx/snippets/nik-headers-api.conf;
    }

    # What the processes of the server ask each other never comes through nginx.
    location /api/internal/ {
        return 404;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_read_timeout 330s;      # opening a large capture takes minutes
        proxy_send_timeout 330s;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;   # sign-in limits go by it
        proxy_set_header X-Forwarded-Proto $scheme;
        include /etc/nginx/snippets/nik-headers-api.conf;
    }

    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        include /etc/nginx/snippets/nik-headers-page.conf;
    }

    location = /index.html {
        add_header Cache-Control "no-cache";
        include /etc/nginx/snippets/nik-headers-page.conf;
    }

    location / {
        try_files $uri /index.html;
    }
}
```

The security headers live in two snippet files, the same the Compose image sends. Write both from the repository with:

```sh
sudo mkdir -p /etc/nginx/snippets
node frontend/security-headers.js /etc/nginx/snippets
```

??? info "What the two snippets hold"
    `/etc/nginx/snippets/nik-headers-page.conf`, sent with the app's pages and assets:

    ```nginx
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https: http:; font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; frame-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" always;
    add_header X-Frame-Options "DENY" always;
    add_header Strict-Transport-Security "max-age=31536000" always;
    ```

    `/etc/nginx/snippets/nik-headers-api.conf`, sent with what the API answers (PDF reports, `/api/docs`):

    ```nginx
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Strict-Transport-Security "max-age=31536000" always;
    ```

    Make them again with `node frontend/security-headers.js` after each update.

!!! tip "502 Bad Gateway"
    Usually SELinux: check step 5a, and that the backend runs (`curl http://127.0.0.1:8000/api/health`).

## Step 9: firewall

Only 80 and 443 are open; the backend stays on `127.0.0.1:8000`.

```sh
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --reload
sudo nginx -t
sudo systemctl reload nginx
```

Open `https://nik.example.internal` and **create the first account at once**: it becomes the admin.

## Backups

The backups of **Platform settings › System › Backup** work the same here, into `BACKUP_DIR` ([Backups](backups.md)); with `AUTOMATION_WORKER=inline` the copy off the server leaves from the API process. `deploy/restore.sh` and `deploy/rollback.sh` are written for the Compose stack. Here, stop the service and run, from `/opt/nik/backend` as the `nik` user:

```sh
sudo systemctl stop nik-api.service
cd /opt/nik/backend
# the settings of nik.env in the environment, then: inspect first, restore second
sudo -u nik bash -c 'set -a; . /etc/nik/nik.env; .venv/bin/python -m app.backups.restore inspect /var/lib/nik/backups/nik-20261120-023000.nikbak'
sudo -u nik bash -c 'set -a; . /etc/nik/nik.env; .venv/bin/python -m app.backups.restore restore /var/lib/nik/backups/nik-20261120-023000.nikbak'
sudo systemctl start nik-api.service
```

The module also has `list [DIRECTORY]`, `secret-key FILE` and `audit-keys FILE` (print the keys a backup holds when it includes them).

## Update to a new version

```sh
# Frontend: rebuild and replace the static files
(cd frontend && npm ci && npm run build)
sudo rm -rf /var/www/nik/*
sudo cp -r frontend/dist/* /var/www/nik/
sudo restorecon -Rv /var/www/nik

# Backend: code and dependencies, then restart (the unit migrates at start)
sudo cp -r backend/* /opt/nik/backend/
sudo /opt/nik/backend/.venv/bin/pip install -r /opt/nik/backend/requirements.txt
sudo chown -R nik:nik /opt/nik
sudo systemctl restart nik-api.service
```

Then compare your server block and header snippets with step 8: a release may change them (6.10 raised the mailbox location to `4200m`). Read the [release notes](upgrades.md#release-notes) of every version you pass.

## Related

- [Install in production](install.md) — the supported Compose stack
- [Environment variables](../reference/configuration.md) — what goes in `nik.env`
- [Upgrades](upgrades.md) — snapshot, rehearsal and release notes
- [Security](../reference/security.md#hardening-checklist) — the hardening checklist
