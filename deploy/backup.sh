#!/usr/bin/env bash
# Nik: take a backup now, from the command line.
#
#   deploy/backup.sh
#
# Since 6.7 the server takes its backups by itself (Settings → Backup): one
# encrypted file with the database and the store of files, on a schedule, each
# one tested by restoring it, with a copy sent off the server. This script
# asks the running server for one more, exactly as "Back up now" does on that
# screen, waits for it and for its restore test, and says how it went. So
# there is one way of making a backup, and one place where backups are kept
# and removed.
#
# It needs the stack running and a backup passphrase set. It exits 0 for a
# backup that passed its restore test, 1 otherwise.
#
# Settings (environment):
#   NIK_DIR          repository root with docker-compose.yml   (default: this script's ../)
#   ENGINE           container engine: podman or docker         (default: podman if installed, else docker)
#   NIK_BACKUP_WAIT  seconds to wait for the backup              (default: 21600)
#
# Before 6.7 this script wrote a directory with db.dump, samples.tar and a copy
# of .env, and BACKUP_DIR and KEEP_DAYS said where and for how long. Those two
# are not read any more: where backups go is NIK_BACKUP_DIR in .env (the
# deployment guide), how long they are kept is set on the screen. The
# directories written before stay where they are; the guide says how to
# restore one ("A backup taken before 6.7").
set -euo pipefail

NIK_DIR=${NIK_DIR:-$(cd "$(dirname "$0")/.." && pwd)}
if [ -z "${ENGINE:-}" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman; else ENGINE=docker; fi
fi

log() { printf '%s nik-backup: %s\n' "$(date '+%F %T')" "$*" >&2; }

if [ -n "${BACKUP_DIR:-}" ] || [ -n "${KEEP_DAYS:-}" ]; then
  log "BACKUP_DIR and KEEP_DAYS are not read since 6.7: the server keeps its backups itself (Settings → Backup)"
fi

# The containers are found by the labels both `docker compose` and
# `podman-compose` set (service name + project directory).
api=$($ENGINE ps --filter "label=com.docker.compose.service=api" \
  --filter "label=com.docker.compose.project.working_dir=$NIK_DIR" --format '{{.Names}}' | head -n 1)
if [ -z "$api" ]; then
  log "no running 'api' container for $NIK_DIR (is the stack up?)"
  exit 1
fi

exec "$ENGINE" exec -e NIK_BACKUP_WAIT="${NIK_BACKUP_WAIT:-21600}" "$api" python -m app.backups.now
