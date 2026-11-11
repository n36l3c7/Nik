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
    exec setpriv --reuid=nik --regid=nik --init-groups --no-new-privs "$0" "$@"
fi

# Refuses to start with secrets that are missing or publicly known.
python -m app.preflight

# `alembic upgrade head` is idempotent — on a fresh database it creates the
# schema and stamps it; on an already-migrated one it is a no-op. The baseline
# also adopts a database whose tables were created by an earlier create_all.
echo "entrypoint: applying database migrations (alembic upgrade head)…" >&2
alembic upgrade head

exec "$@"
