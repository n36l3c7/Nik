#!/usr/bin/env bash
# Install the Nik systemd units: start on boot (nik.service) and nightly backups
# (nik-backup.timer). Run as root from the repository root:
#
#   sudo deploy/install-systemd.sh
#   sudo deploy/install-systemd.sh --backup-dir /srv/nik-backups --keep-days 30 --backup-time 03:15
#
# Options:
#   --dir PATH          repository root            (default: the current repository)
#   --compose "CMD"     compose command            (default: podman compose, else docker compose)
#   --backup-dir PATH   backup destination         (default: /var/backups/nik)
#   --keep-days N       backup retention in days   (default: 14)
#   --backup-time HH:MM nightly backup time        (default: 02:30)
#   --no-backup         install start-on-boot only
#   --uninstall         stop, disable and remove the units
set -euo pipefail

NIK_DIR=$(cd "$(dirname "$0")/.." && pwd)
COMPOSE=""
BACKUP_DIR=/var/backups/nik
KEEP_DAYS=14
BACKUP_TIME=02:30
WITH_BACKUP=1
UNINSTALL=0
UNIT_DIR=${UNIT_DIR:-/etc/systemd/system}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) NIK_DIR=$(cd "$2" && pwd); shift 2 ;;
    --compose) COMPOSE=$2; shift 2 ;;
    --backup-dir) BACKUP_DIR=$2; shift 2 ;;
    --keep-days) KEEP_DAYS=$2; shift 2 ;;
    --backup-time) BACKUP_TIME=$2; shift 2 ;;
    --no-backup) WITH_BACKUP=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h | --help) sed -n '2,20p' "$0"; exit 0 ;;
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
  echo "Removed the Nik units. The containers and their data are untouched."
  exit 0
fi

if command -v podman >/dev/null 2>&1; then ENGINE=$(command -v podman); else ENGINE=$(command -v docker); fi
if [ -z "$COMPOSE" ]; then COMPOSE="$ENGINE compose"; fi
case "$BACKUP_TIME" in [0-2][0-9]:[0-5][0-9]) ;; *) echo "--backup-time must be HH:MM" >&2; exit 2 ;; esac
case "$KEEP_DAYS" in '' | *[!0-9]*) echo "--keep-days must be a number" >&2; exit 2 ;; esac
[ -f "$NIK_DIR/docker-compose.yml" ] || { echo "No docker-compose.yml in $NIK_DIR" >&2; exit 1; }

render() {
  sed -e "s#@NIK_DIR@#$NIK_DIR#g" -e "s#@COMPOSE@#$COMPOSE#g" -e "s#@ENGINE@#$ENGINE#g" -e "s#@BACKUP_DIR@#$BACKUP_DIR#g" \
    -e "s#@KEEP_DAYS@#$KEEP_DAYS#g" -e "s#@BACKUP_TIME@#$BACKUP_TIME:00#g" "$NIK_DIR/deploy/systemd/$1" >"$UNIT_DIR/$1"
  chmod 0644 "$UNIT_DIR/$1"
  echo "installed $UNIT_DIR/$1"
}

render nik.service
units=(nik.service)
if [ "$WITH_BACKUP" -eq 1 ]; then
  render nik-backup.service
  render nik-backup.timer
  chmod 0755 "$NIK_DIR/deploy/backup.sh"
  units+=(nik-backup.timer)
fi

if [ "$UNIT_DIR" = /etc/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable "${units[@]}"
  systemctl start nik.service
  [ "$WITH_BACKUP" -eq 1 ] && systemctl start nik-backup.timer
  echo
  systemctl --no-pager --lines=0 status "${units[@]}" || true
fi
echo
echo "Nik now starts at boot ($COMPOSE in $NIK_DIR)."
[ "$WITH_BACKUP" -eq 1 ] && echo "Backups: every night at $BACKUP_TIME into $BACKUP_DIR, kept $KEEP_DAYS days."
exit 0
