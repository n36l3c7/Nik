#!/bin/sh
# Entry point of the `db` service.
#
# 1. It refuses to start an empty PostgreSQL 18 cluster while the PostgreSQL 16
#    data of a release before 2.12.2 is still there, unmigrated.
#
#    PostgreSQL 18 cannot open a version 16 data directory, so 2.12.2 keeps its
#    data on a new volume (db-data-18). Without this check, `compose up` after
#    the update would initialise an EMPTY database next to the old one and the
#    app would greet you with its first-run screen. This version does not move
#    that data: an installation that old is updated to 6.9.0 first, whose
#    deploy/upgrade-postgres.sh does. Once the new cluster exists this check
#    passes.
#
# 2. It gives PostgreSQL its password from where it is kept. The password is
#    needed once, to create the database: from the file DB_PASSWORD_FILE names
#    when that file holds it (the secrets directory), else from the environment
#    (.env). A database that exists is started with no password in the
#    environment of its processes at all.
#
# 3. It turns on the archive of the log (6.9). Every finished segment of the
#    write-ahead log is kept in the archive volume (deploy/db/wal-archive.sh),
#    and one is finished at least every NIK_ARCHIVE_TIMEOUT seconds while
#    something is written: with the base backups the `recovery` service takes,
#    that is what brings the database back to any moment
#    (deploy/restore.sh --to) and what a standby replays (deploy/standby.sh).
#    The settings are given on the command line of PostgreSQL, so they hold on
#    a database made by any earlier release and nothing is written into its
#    configuration. NIK_WAL_ARCHIVE=off in .env turns the archive off.
#
# 4. It lets a restore say how far to replay. deploy/db/pitr.sh leaves
#    recovery.signal and nik-recovery.conf in the data directory; the lines of
#    that file are settings of this one start, and it is removed once the
#    recovery is over.
set -eu

OLD=/var/lib/postgresql-16

if [ ! -s "$PGDATA/PG_VERSION" ] && [ -s "$OLD/PG_VERSION" ]; then
  echo "nik: PostgreSQL $(cat "$OLD/PG_VERSION") data found on the old volume, none for PostgreSQL 18." >&2
  echo "nik: this installation is older than Nik 6.0.0. Update it to Nik 6.9.0 first (git checkout v6.9.0)," >&2
  echo "nik: move its data there with deploy/upgrade-postgres.sh, then come back to this version." >&2
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

ARCHIVE=/wal-archive
LIB=/usr/local/lib/nik

if [ "${1:-}" = "postgres" ] && [ "${NIK_WAL_ARCHIVE:-on}" != "off" ] && [ -d "$ARCHIVE" ]; then
  # The folders of the archive volume, with the owners its three users need.
  sh "$LIB/prepare-archive.sh"
  timeout=${NIK_ARCHIVE_TIMEOUT:-300}
  case "$timeout" in
    *[!0-9]* | "") timeout=300 ;;
  esac
  set -- "$@" -c archive_mode=on -c "archive_command=sh $LIB/wal-archive.sh %p %f" -c "archive_timeout=$timeout" -c "restore_command=sh $LIB/wal-restore.sh %f %p" -c hot_standby=on
fi

if [ "${1:-}" = "postgres" ] && [ -f "$PGDATA/nik-recovery.conf" ]; then
  if [ -f "$PGDATA/recovery.signal" ]; then
    while IFS= read -r line; do
      case "$line" in
        recovery_target_time=* | recovery_target_action=*) set -- "$@" -c "$line" ;;
      esac
    done <"$PGDATA/nik-recovery.conf"
  else
    rm -f "$PGDATA/nik-recovery.conf"
  fi
fi

exec docker-entrypoint.sh "$@"
