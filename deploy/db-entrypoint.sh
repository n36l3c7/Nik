#!/bin/sh
# Entry point of the `db` service.
#
# 1. It refuses to start an empty PostgreSQL 18 cluster while the PostgreSQL 16
#    data of a release before 2.12.2 is still there, unmigrated.
#
#    PostgreSQL 18 cannot open a version 16 data directory, so 2.12.2 keeps its
#    data on a new volume (db-data-18). Without this check, `compose up` after
#    the update would initialise an EMPTY database next to the old one and the
#    app would greet you with its first-run screen. deploy/upgrade-postgres.sh
#    moves the data (dump and restore) and sets NIK_PG_UPGRADE=1 for the first
#    start of the new cluster. Once the new cluster exists this check passes.
#
# 2. It gives PostgreSQL its password from where it is kept. The password is
#    needed once, to create the database: from the file DB_PASSWORD_FILE names
#    when that file holds it (the secrets directory), else from the environment
#    (.env). A database that exists is started with no password in the
#    environment of its processes at all.
set -eu

OLD=/var/lib/postgresql-16

if [ ! -s "$PGDATA/PG_VERSION" ] && [ -s "$OLD/PG_VERSION" ] && [ "${NIK_PG_UPGRADE:-}" != "1" ]; then
  echo "nik: PostgreSQL $(cat "$OLD/PG_VERSION") data found on the old volume, none for PostgreSQL 18." >&2
  echo "nik: run deploy/upgrade-postgres.sh to move it (the deployment guide (Upgrading to PostgreSQL 18), \"Upgrading to PostgreSQL 18\")." >&2
  exit 1
fi

if [ -s "$PGDATA/PG_VERSION" ]; then
  unset POSTGRES_PASSWORD POSTGRES_PASSWORD_FILE
elif [ -n "${DB_PASSWORD_FILE:-}" ] && [ -s "$DB_PASSWORD_FILE" ]; then
  if [ -n "${POSTGRES_PASSWORD:-}" ]; then
    echo "nik: DB_PASSWORD is given twice, in the file $DB_PASSWORD_FILE and in the environment: keep one." >&2
    exit 1
  fi
  unset POSTGRES_PASSWORD
  export POSTGRES_PASSWORD_FILE="$DB_PASSWORD_FILE"
elif [ -z "${POSTGRES_PASSWORD:-}" ]; then
  echo "nik: DB_PASSWORD is not set: run deploy/init-env.sh." >&2
  exit 1
fi
unset DB_PASSWORD_FILE

exec docker-entrypoint.sh "$@"
