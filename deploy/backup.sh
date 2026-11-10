#!/usr/bin/env bash
# Nik backup: PostgreSQL dump, sample store and .env in one timestamped directory.
#
#   deploy/backup.sh                       # from the repository root
#   BACKUP_DIR=/srv/nik-backups KEEP_DAYS=30 deploy/backup.sh
#
# Settings (environment):
#   NIK_DIR     repository root with docker-compose.yml   (default: this script's ../)
#   ENGINE      container engine: podman or docker         (default: podman if installed, else docker)
#   BACKUP_DIR  where backups go                           (default: /var/backups/nik)
#   KEEP_DAYS   delete backups older than this many days   (default: 14; 0 keeps everything)
#
# Each run writes BACKUP_DIR/nik-YYYYMMDD-HHMMSS/ with db.dump (pg_dump custom
# format), samples.tar (the raw malware samples: live malware, keep the
# directory private), env (the .env secrets) and SHA256SUMS. The directory is
# readable by root only. Restore steps: README § 2.1 "Backups & restore".
#
# The containers are found by the labels both `docker compose` and
# `podman-compose` set (service name + project directory) and reached with
# `$ENGINE exec`: `podman-compose` prints diagnostics on stdout, which would end
# up inside the dump if it ran the commands itself.
set -euo pipefail

NIK_DIR=${NIK_DIR:-$(cd "$(dirname "$0")/.." && pwd)}
BACKUP_DIR=${BACKUP_DIR:-/var/backups/nik}
KEEP_DAYS=${KEEP_DAYS:-14}
if [ -z "${ENGINE:-}" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman; else ENGINE=docker; fi
fi

log() { printf '%s nik-backup: %s\n' "$(date '+%F %T')" "$*" >&2; }

# Name of the running container of a Compose service of this project.
container_for() {
  local name
  name=$($ENGINE ps --filter "label=com.docker.compose.service=$1" \
    --filter "label=com.docker.compose.project.working_dir=$NIK_DIR" --format '{{.Names}}' | head -n 1)
  if [ -z "$name" ]; then
    log "no running '$1' container for $NIK_DIR (is the stack up?)"
    return 1
  fi
  printf '%s' "$name"
}

cd "$NIK_DIR"
umask 077
mkdir -p "$BACKUP_DIR"
target="$BACKUP_DIR/nik-$(date '+%Y%m%d-%H%M%S')"
partial="$target.partial"
mkdir "$partial"
trap 'rm -rf "$partial"; log "failed, partial backup removed"' ERR

db=$(container_for db)
api=$(container_for api)

log "dumping the database ($db)"
$ENGINE exec -i "$db" pg_dump -U nik -d nik -Fc >"$partial/db.dump"

log "archiving the sample store ($api)"
$ENGINE exec -i "$api" tar -C /app/samples -cf - . >"$partial/samples.tar"

if [ -f .env ]; then cp .env "$partial/env"; fi

(cd "$partial" && sha256sum -- * >SHA256SUMS)
mv "$partial" "$target"
trap - ERR
log "done: $target ($(du -sh "$target" | cut -f1))"

if [ "$KEEP_DAYS" -gt 0 ]; then
  find "$BACKUP_DIR" -maxdepth 1 -type d -name 'nik-*' -mtime "+$KEEP_DAYS" -print0 |
    while IFS= read -r -d '' old; do
      rm -rf -- "$old"
      log "removed old backup $old"
    done
fi
