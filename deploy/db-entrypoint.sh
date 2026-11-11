#!/bin/sh
# Entry point of the `db` service: refuses to start an empty PostgreSQL 18
# cluster while the PostgreSQL 16 data of a release before 2.12.2 is still
# there, unmigrated.
#
# PostgreSQL 18 cannot open a version 16 data directory, so 2.12.2 keeps its
# data on a new volume (db-data-18). Without this check, `compose up` after
# the update would initialise an EMPTY database next to the old one and the
# app would greet you with its first-run screen. deploy/upgrade-postgres.sh
# moves the data (dump and restore) and sets NIK_PG_UPGRADE=1 for the first
# start of the new cluster. Once the new cluster exists this check passes.
set -eu

OLD=/var/lib/postgresql-16

if [ ! -s "$PGDATA/PG_VERSION" ] && [ -s "$OLD/PG_VERSION" ] && [ "${NIK_PG_UPGRADE:-}" != "1" ]; then
  echo "nik: PostgreSQL $(cat "$OLD/PG_VERSION") data found on the old volume, none for PostgreSQL 18." >&2
  echo "nik: run deploy/upgrade-postgres.sh to move it (the deployment guide (Upgrading to PostgreSQL 18), \"Upgrading to PostgreSQL 18\")." >&2
  exit 1
fi

exec docker-entrypoint.sh "$@"
