#!/bin/sh
# Container entrypoint: apply DB migrations, then serve.
# `alembic upgrade head` is idempotent — on a fresh database it creates the
# schema and stamps it; on an already-migrated one it is a no-op. The baseline
# also adopts a database whose tables were created by an earlier create_all.
set -e

echo "entrypoint: applying database migrations (alembic upgrade head)…" >&2
alembic upgrade head

exec "$@"
