#!/usr/bin/env bash
# Install the Nik systemd unit: start on boot (nik.service). Run as root from
# the repository root:
#
#   sudo deploy/install-systemd.sh
#
# Options:
#   --dir PATH          repository root            (default: the current repository)
#   --compose "CMD"     compose command            (default: podman compose, else docker compose)
#   --uninstall         stop, disable and remove the unit
#
# Before 6.7 this also installed a nightly backup (nik-backup.timer). The
# server now takes its backups by itself, on the schedule set in Settings →
# Backup, so that timer is removed where an earlier run installed it: two
# schedules would take two backups. The options it had (--backup-dir,
# --keep-days, --backup-time, --no-backup) are accepted and ignored.
set -euo pipefail

NIK_DIR=$(cd "$(dirname "$0")/.." && pwd)
COMPOSE=""
UNINSTALL=0
UNIT_DIR=${UNIT_DIR:-/etc/systemd/system}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) NIK_DIR=$(cd "$2" && pwd); shift 2 ;;
    --compose) COMPOSE=$2; shift 2 ;;
    --backup-dir | --keep-days | --backup-time)
      echo "$1 is not used any more: backups are set in Settings → Backup (and NIK_BACKUP_DIR in .env)." >&2
      shift 2
      ;;
    --no-backup) shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h | --help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ] && [ "$UNIT_DIR" = /etc/systemd/system ]; then
  echo "Run as root: the units go to $UNIT_DIR." >&2
  exit 1
fi

if [ "$UNINSTALL" -eq 1 ]; then
  systemctl disable --now nik-backup.timer nik.service 2>/dev/null || true
  rm -f "$UNIT_DIR/nik.service" "$UNIT_DIR/nik-backup.service" "$UNIT_DIR/nik-backup.timer"
  systemctl daemon-reload
  echo "Removed the Nik unit. The containers and their data are untouched."
  exit 0
fi

if command -v podman >/dev/null 2>&1; then ENGINE=$(command -v podman); else ENGINE=$(command -v docker); fi
if [ -z "$COMPOSE" ]; then COMPOSE="$ENGINE compose"; fi
[ -f "$NIK_DIR/docker-compose.yml" ] || { echo "No docker-compose.yml in $NIK_DIR" >&2; exit 1; }

render() {
  sed -e "s#@NIK_DIR@#$NIK_DIR#g" -e "s#@COMPOSE@#$COMPOSE#g" "$NIK_DIR/deploy/systemd/$1" >"$UNIT_DIR/$1"
  chmod 0644 "$UNIT_DIR/$1"
  echo "installed $UNIT_DIR/$1"
}

render nik.service
# The nightly backup of releases before 6.7: the server takes its backups itself now.
old_timer=0
if [ -e "$UNIT_DIR/nik-backup.timer" ] || [ -e "$UNIT_DIR/nik-backup.service" ]; then
  old_timer=1
  if [ "$UNIT_DIR" = /etc/systemd/system ]; then systemctl disable --now nik-backup.timer 2>/dev/null || true; fi
  rm -f "$UNIT_DIR/nik-backup.service" "$UNIT_DIR/nik-backup.timer"
fi

if [ "$UNIT_DIR" = /etc/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable nik.service
  systemctl start nik.service
  echo
  systemctl --no-pager --lines=0 status nik.service || true
fi
echo
echo "Nik now starts at boot ($COMPOSE in $NIK_DIR)."
if [ "$old_timer" -eq 1 ]; then
  echo "The nightly nik-backup.timer of earlier releases was removed: backups are taken by the server (Settings → Backup)."
fi
exit 0
