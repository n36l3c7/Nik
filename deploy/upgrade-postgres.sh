#!/usr/bin/env bash
# Nik: move the database from PostgreSQL 16 to PostgreSQL 18 (release 2.12.2).
#
#   cd /opt/Nik && git pull     # the new docker-compose.yml, NOT `up` yet
#   sudo deploy/upgrade-postgres.sh
#
# PostgreSQL 18 cannot open a version 16 data directory, so the data is moved
# with a dump and a restore:
#   1. full backup with deploy/backup.sh, from the stack still running 16;
#   2. the number of rows of every table is noted;
#   3. the stack is stopped; PostgreSQL 18 starts on the new db-data-18 volume;
#   4. the dump is restored and the row counts are compared;
#   5. the whole stack starts again on the new release.
# The old db-data volume is left untouched (mounted read-only) for a rollback:
# remove it after 14 days. The api and the sample store are not affected.
# If `compose up` already ran on the new release (its db then refuses to
# start), or a previous run stopped after starting PostgreSQL 18, the old
# volume is dumped with a temporary PostgreSQL 16 instead. Running the script
# again is always safe.
#
# Settings (environment): NIK_DIR, ENGINE, BACKUP_DIR as for backup.sh.
set -euo pipefail

NIK_DIR=${NIK_DIR:-$(cd "$(dirname "$0")/.." && pwd)}
if [ -z "${ENGINE:-}" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman; else ENGINE=docker; fi
fi
COMPOSE=${COMPOSE:-"$ENGINE compose"}
export NIK_DIR ENGINE

log() { printf '%s nik-upgrade: %s\n' "$(date '+%F %T')" "$*" >&2; }
die() {
  log "$*"
  exit 1
}

PG18_IMAGE=docker.io/library/postgres:18-alpine

# Name of this project's container of a Compose service (running; any state with -a).
container_for() {
  $ENGINE ps ${2:+"$2"} --filter "label=com.docker.compose.service=$1" \
    --filter "label=com.docker.compose.project.working_dir=$NIK_DIR" --format '{{.Names}}' | head -n 1
}

# Name of the volume a container mounts at a path.
mounted_volume() {
  $ENGINE inspect "$1" --format "{{range .Mounts}}{{if eq .Destination \"$2\"}}{{.Name}}{{end}}{{end}}"
}

# psql in the db container: one value per line, no headers.
sql() { $ENGINE exec -i "$1" psql -U nik -d nik -v ON_ERROR_STOP=1 -Atc "$2"; }

# "table count" lines, one per table of the public schema, sorted.
row_counts() {
  local db=$1 table
  for table in $(sql "$db" "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1"); do
    printf '%s %s\n' "$table" "$(sql "$db" "SELECT count(*) FROM \"$table\"")"
  done
}

# Ready = accepting TCP connections. On a new volume the image first creates
# the database with a temporary server that listens on the Unix socket only,
# then restarts: a socket check would catch that temporary server.
wait_ready() {
  local db=$1
  for _ in $(seq 1 "${2:-60}"); do
    if $ENGINE exec "$db" pg_isready -h 127.0.0.1 -p 5432 -U nik -d nik >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  return 1
}

cd "$NIK_DIR"
grep -q 'postgres:18' docker-compose.yml || die "docker-compose.yml is not the 2.12.2 one: run git pull first"
backup_dir=${BACKUP_DIR:-/var/backups/nik}

# A db container that answers: the previous release still running (16), or
# PostgreSQL 18 — upgraded already, or left empty by an interrupted run. One
# that does not answer is the new release's, refusing to start until the data
# is moved.
db=$(container_for db)
if [ -n "$db" ]; then wait_ready "$db" 10 || true; fi
version=$([ -n "$db" ] && sql "$db" "SHOW server_version_num" 2>/dev/null || true)
if [ -n "$version" ] && [ "$version" -ge 180000 ]; then
  if [ -n "$(sql "$db" "SELECT 1 FROM pg_tables WHERE schemaname = 'public' LIMIT 1")" ]; then
    log "the database already runs PostgreSQL $(sql "$db" 'SHOW server_version'): nothing to do"
    exit 0
  fi
  log "PostgreSQL 18 is running with an empty database (an interrupted upgrade): resuming"
  version=""
fi

if [ -n "$version" ]; then
  # The previous release is still running (the documented order): a full
  # backup with backup.sh, from the running PostgreSQL 16.
  old_volume=$(mounted_volume "$db" /var/lib/postgresql/data)
  log "PostgreSQL $(sql "$db" 'SHOW server_version') on volume ${old_volume:-?}"
  log "step 1/5: full backup"
  "$NIK_DIR/deploy/backup.sh"
  dump=$(find "$backup_dir" -maxdepth 1 -type d -name 'nik-*' ! -name '*.partial' | sort | tail -n 1)/db.dump
  [ -s "$dump" ] || die "backup not found in $backup_dir"
  log "step 2/5: counting rows"
  before=$(row_counts "$db")
  $COMPOSE down
else
  # `compose up` already ran on the new release: its db container refuses to
  # start (deploy/db-entrypoint.sh) but mounts the old volume read-only. Dump
  # it with a temporary container of the PostgreSQL version that wrote it.
  stopped=$(container_for db -a)
  [ -n "$stopped" ] || die "no 'db' container for $NIK_DIR: start the previous release first"
  old_volume=$(mounted_volume "$stopped" /var/lib/postgresql-16)
  [ -n "$old_volume" ] || die "no PostgreSQL 16 volume mounted by $stopped"
  old_version=$($ENGINE run --rm -v "$old_volume:/old:ro" "$PG18_IMAGE" cat /old/PG_VERSION 2>/dev/null || true)
  [ -n "$old_version" ] || die "volume $old_volume holds no PostgreSQL data"
  log "PostgreSQL $old_version data on volume $old_volume (the stack is not running it)"
  $COMPOSE down
  log "step 1/5: dump with a temporary PostgreSQL $old_version"
  temp=$($ENGINE run -d --rm -e POSTGRES_PASSWORD=unused -v "$old_volume:/var/lib/postgresql/data" \
    "docker.io/library/postgres:$old_version-alpine")
  trap '$ENGINE stop "$temp" >/dev/null 2>&1 || true' EXIT
  wait_ready "$temp" || die "the temporary PostgreSQL $old_version did not start"
  target="$backup_dir/nik-$(date '+%Y%m%d-%H%M%S')-pg$old_version"
  (umask 077 && mkdir -p "$target")
  $ENGINE exec -i "$temp" pg_dump -U nik -d nik -Fc >"$target/db.dump"
  dump="$target/db.dump"
  log "backup: $dump"
  log "step 2/5: counting rows"
  before=$(row_counts "$temp")
  $ENGINE stop "$temp" >/dev/null
  trap - EXIT
fi

log "step 3/5: starting PostgreSQL 18 on a new volume"
NIK_PG_UPGRADE=1 $COMPOSE up -d db
new_db=$(container_for db)
[ -n "$new_db" ] || die "PostgreSQL 18 did not start: $COMPOSE logs db"
wait_ready "$new_db" || die "PostgreSQL 18 is not ready: $COMPOSE logs db"
new_version=$(sql "$new_db" 'SHOW server_version_num' || true)
[ -n "$new_version" ] && [ "$new_version" -ge 180000 ] || die "the new db container is not PostgreSQL 18"
[ -z "$(sql "$new_db" "SELECT 1 FROM pg_tables WHERE schemaname = 'public' LIMIT 1")" ] ||
  die "the PostgreSQL 18 database is not empty: was the upgrade already run?"

log "step 4/5: restoring the dump"
$ENGINE exec -i "$new_db" pg_restore -U nik -d nik --no-owner --exit-on-error <"$dump"
after=$(row_counts "$new_db")
if [ "$before" != "$after" ]; then
  diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") >&2 || true
  die "row counts differ after the restore. Nothing was deleted: see README § 2.1 to roll back"
fi
log "row counts match ($(printf '%s\n' "$after" | wc -l) tables)"

log "step 5/5: starting the whole stack"
$COMPOSE up -d --build

log "done: PostgreSQL 18 is running."
log "the PostgreSQL 16 data stays on volume ${old_volume:-db-data} for a rollback; after 14 days:"
log "  $ENGINE volume rm ${old_volume:-<project>_db-data}"
