#!/bin/sh
# Container entrypoint: drop privileges, check the secrets, apply the database
# migrations, then serve.
set -e

# The server never runs as root. The container starts as root only for this:
# a sample store created by a release before 3.0.0 belongs to root, and has to
# be handed to the unprivileged user once. Then the entrypoint starts again as
# that user, for good.
if [ "$(id -u)" = "0" ]; then
    store="${SAMPLE_STORE:-/app/samples}"
    mkdir -p "$store"
    if [ "$(stat -c %U "$store")" != "nik" ]; then
        echo "entrypoint: handing the sample store to the unprivileged user (once)…" >&2
        chown -R nik:nik "$store"
    fi
    # The backup directory is a volume, or a directory of the host: the server
    # writes its backups there as the unprivileged user. Only the directory
    # itself changes hands: what an operator put inside stays as it is.
    backups="${BACKUP_DIR:-/app/backups}"
    if [ -d "$backups" ] && [ "$(stat -c %U "$backups")" != "nik" ]; then
        chown nik:nik "$backups" 2>/dev/null ||
            echo "entrypoint: the backup directory $backups is not writable by the server (uid 10001)" >&2
    fi
    exec setpriv --reuid=nik --regid=nik --init-groups --no-new-privs "$0" "$@"
fi

# Refuses to start with secrets that are missing, publicly known, given twice
# or unreadable. The API container does not exit on that (it would only
# restart, and the page would show nothing): it stays up and answers every
# request with what is wrong (app/stopped.py). The automation container
# shares this image and serves nothing: it exits, and tries again.
if [ "${NIK_SKIP_MIGRATIONS:-}" != "1" ]; then
    python -m app.preflight --serve
else
    python -m app.preflight
fi

# The migrations (app/backups/upgrade.py). On a database that is already at
# this version it does nothing; on a new one it creates the schema. When a
# release has migrations to run it first takes a snapshot of the database into
# the backup directory and tries the migrations on a copy; if they fail it
# does not exit (the container would restart and try for ever) but stays up
# and answers every request with what happened, until an operator acts.
# The automation container shares this image: the backend applies the
# migrations, and two containers applying them at once would trip over each other.
if [ "${NIK_SKIP_MIGRATIONS:-}" != "1" ]; then
    echo "entrypoint: bringing the database to this version (snapshot, rehearsal, migrations)…" >&2
    python -m app.backups.upgrade
    # The store key against the store it is given: a key that is not the one the
    # files are sealed under would write files nobody can read beside files it
    # cannot open. The server stays up and says so instead of starting.
    python -m app.preflight --store
fi

exec "$@"
