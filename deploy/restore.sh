#!/usr/bin/env bash
# Nik: put a backup back. On the server it was taken on, or on a new host.
#
#   deploy/restore.sh nik-20261120-023000              # a backup of the backup directory of this stack
#   deploy/restore.sh /mnt/usb/nik-20261120-023000.nikbak   # a file brought from elsewhere
#   deploy/restore.sh --inspect <backup>               # read the whole file, say what it holds, change nothing
#
# What it does, in order:
#   1. asks for the backup passphrase (never on the command line);
#   2. stops the stack, starts the database alone;
#   3. reads the whole file and compares every checksum: nothing is changed
#      before that has passed, and nothing at all if it does not;
#   4. restores the database (in one transaction) and the store of files;
#   5. starts the stack and checks that the server answers.
#
# It refuses a database or a store that is not empty: add --replace to put the
# backup in their place (what they hold is then gone).
#
# Options:
#   --replace          replace a database and a store that are not empty
#   --database-only    leave the store of files as it is
#   --secret-key       first write the SECRET_KEY the backup holds where the keys of this stack are
#                      kept (a backup taken with "Include SECRET_KEY"): into .env, the file as it was
#                      being kept as .env.before-restore; or into the secrets directory, the key as it
#                      was being kept beside it as secret_key.before-restore
#   --inspect          only read the file and say what it holds
#   --no-start         leave the stack stopped at the end
#   --yes              do not ask before stopping the stack and before replacing
#
# Settings (environment):
#   NIK_DIR     repository root with docker-compose.yml   (default: this script's ../)
#   ENGINE      container engine: podman or docker         (default: podman if installed, else docker)
#   COMPOSE     compose command                            (default: "$ENGINE compose")
#   NIK_BACKUP_PASSPHRASE        the passphrase, for a restore nobody attends
#   NIK_BACKUP_PASSPHRASE_FILE   or a file that holds it
#
# On a new host: clone the repository at the version that took the backup (or a
# later one), run deploy/init-env.sh, put the SECRET_KEY of the old server where
# the keys are kept (or use --secret-key), then run this. The store key of the
# old server is not needed: a backup holds the files themselves, under its
# passphrase, and each is sealed here under the store key init-env.sh just made.
# The deployment guide has the whole procedure ("The first host is gone").
set -euo pipefail

NIK_DIR=${NIK_DIR:-$(cd "$(dirname "$0")/.." && pwd)}
if [ -z "${ENGINE:-}" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman; else ENGINE=docker; fi
fi
COMPOSE=${COMPOSE:-"$ENGINE compose"}

log() { printf 'nik-restore: %s\n' "$*" >&2; }
die() {
  log "$*"
  exit 1
}

REPLACE=0
DATABASE_ONLY=0
WITH_KEY=0
INSPECT=0
START=1
YES=0
BACKUP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --replace) REPLACE=1 ;;
    --database-only) DATABASE_ONLY=1 ;;
    --secret-key) WITH_KEY=1 ;;
    --inspect) INSPECT=1 ;;
    --no-start) START=0 ;;
    --yes) YES=1 ;;
    -h | --help)
      sed -n '2,42p' "$0"
      exit 0
      ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *)
      [ -z "$BACKUP" ] || die "one backup at a time"
      BACKUP=$1
      ;;
  esac
  shift
done
[ -n "$BACKUP" ] || die "name the backup: a file, or the name of a backup of this stack (see --help)"

cd "$NIK_DIR"
[ -f docker-compose.yml ] || die "no docker-compose.yml in $NIK_DIR"
[ -f .env ] || die "no .env in $NIK_DIR: on a new host run deploy/init-env.sh first, then put the SECRET_KEY of the old server where it keeps the keys (or use --secret-key)"

# Where the keys of this stack are kept: the secrets directory .env names, or .env itself.
secrets_dir=$(sed -n 's/^NIK_SECRETS_DIR=//p' .env | tail -n 1)
case "$secrets_dir" in
  "" | /* | ?:*) ;;
  *) secrets_dir="$NIK_DIR/${secrets_dir#./}" ;;
esac

# The file: one of the host (its folder is mounted read-only for the restore),
# or the name of a backup in the backup directory of the stack.
mounts=()
if [ -f "$BACKUP" ]; then
  folder=$(cd "$(dirname "$BACKUP")" && pwd)
  # The restore runs in a container as an unprivileged user that is nobody on the host: it reads
  # the file only if everybody may. The file is encrypted; its folder need not be anybody's home.
  case "$(stat -c '%A' "$BACKUP" 2>/dev/null || true)" in
    ???????r?? | "") ;;
    *) die "the backup must be readable by every user of the host for the restore (it is encrypted): chmod o+r $BACKUP" ;;
  esac
  case "$(stat -c '%A' "$folder" 2>/dev/null || true)" in
    ???????r?[xt] | "") ;;
    *) die "the folder of the backup is closed to other users, and the restore runs as one: copy or link the file into a folder that is open (chmod 755), then run this again" ;;
  esac
  mounts+=(-v "$folder:/restore:ro,z")
  target="/restore/$(basename "$BACKUP")"
else
  case "$BACKUP" in
    */*) die "there is no file $BACKUP" ;;
  esac
  target=${BACKUP%.nikbak}
fi

# The passphrase: from the environment, from a file, or asked for. It reaches
# the container through its environment, never through a command line.
if [ -n "${NIK_BACKUP_PASSPHRASE_FILE:-}" ]; then
  [ -f "$NIK_BACKUP_PASSPHRASE_FILE" ] || die "no passphrase file at $NIK_BACKUP_PASSPHRASE_FILE"
  NIK_BACKUP_PASSPHRASE=$(head -n 1 "$NIK_BACKUP_PASSPHRASE_FILE")
elif [ -z "${NIK_BACKUP_PASSPHRASE:-}" ]; then
  if [ -t 0 ]; then
    printf 'Backup passphrase (empty for a snapshot taken under SECRET_KEY): ' >&2
    IFS= read -rs NIK_BACKUP_PASSPHRASE
    printf '\n' >&2
  else
    NIK_BACKUP_PASSPHRASE=""
  fi
fi
export NIK_BACKUP_PASSPHRASE

# One command of the restore, in a container of the api service: its image,
# its environment (the database, SECRET_KEY), its volumes (the store, the
# backup directory). The entrypoint must not migrate anything here.
tool() {
  # shellcheck disable=SC2086 # COMPOSE is a command with its arguments
  $COMPOSE run --rm --no-deps -T -e NIK_SKIP_MIGRATIONS=1 -e NIK_BACKUP_PASSPHRASE "${mounts[@]}" api \
    python -m app.backups.restore "$@"
}

if [ "$INSPECT" -eq 1 ]; then
  tool inspect "$target"
  exit $?
fi

confirm() { # $1 = question, $2 = the word to type
  [ "$YES" -eq 1 ] && return 0
  [ -t 0 ] || die "$1 Run it again with --yes to go on without being asked."
  printf '%s Type %s to go on: ' "$1" "$2" >&2
  IFS= read -r typed
  [ "$typed" = "$2" ] || die "nothing was changed."
}

if [ "$REPLACE" -eq 1 ]; then
  what="the database"
  [ "$DATABASE_ONLY" -eq 1 ] || what="the database and the store of files"
  confirm "This REPLACES $what of the Nik in $NIK_DIR with what the backup holds." "replace"
else
  confirm "This stops the Nik in $NIK_DIR and restores the backup into it (it must be empty)." "restore"
fi

if [ "$WITH_KEY" -eq 1 ]; then
  log "reading the SECRET_KEY the backup holds"
  key=$(tool secret-key "$target" | sed -n 's/^SECRET_KEY=//p' | tail -n 1)
  [ -n "$key" ] || die "the backup gave no SECRET_KEY: nothing was changed"
  if [ -n "$secrets_dir" ]; then
    if [ "$(tr -d '\r\n' <"$secrets_dir/secret_key" 2>/dev/null || true)" = "$key" ]; then
      log "$secrets_dir already holds that SECRET_KEY"
    else
      (umask 077 && cp "$secrets_dir/secret_key" "$secrets_dir/secret_key.before-restore")
      printf '%s\n' "$key" >"$secrets_dir/secret_key"
      log "SECRET_KEY of the backup written to $secrets_dir/secret_key (the key as it was: secret_key.before-restore beside it, to remove once all is well)"
    fi
  elif [ "$(sed -n 's/^SECRET_KEY=//p' .env | tail -n 1)" = "$key" ]; then
    log ".env already holds that SECRET_KEY"
  else
    (umask 077 && cp .env .env.before-restore)
    # Written by a program that takes the value as it is: no character of the key means anything to it.
    KEY="$key" awk 'BEGIN { done = 0 } /^SECRET_KEY=/ { print "SECRET_KEY=" ENVIRON["KEY"]; done = 1; next } { print }
      END { if (!done) print "SECRET_KEY=" ENVIRON["KEY"] }' .env.before-restore >.env.restoring
    chmod 600 .env.restoring
    mv .env.restoring .env
    log "SECRET_KEY of the backup written to .env (the file as it was: .env.before-restore, to remove once all is well)"
  fi
  unset key
fi

log "stopping the stack; the database alone is started"
# shellcheck disable=SC2086
$COMPOSE stop >/dev/null
# shellcheck disable=SC2086
$COMPOSE up -d db >/dev/null
db=""
for _ in $(seq 1 60); do
  db=$($ENGINE ps --filter "label=com.docker.compose.service=db" \
    --filter "label=com.docker.compose.project.working_dir=$NIK_DIR" --format '{{.Names}}' | head -n 1)
  if [ -n "$db" ] && $ENGINE exec "$db" pg_isready -U nik -d nik >/dev/null 2>&1; then break; fi
  sleep 2
done
[ -n "$db" ] || die "the database container did not start: $COMPOSE logs db"
$ENGINE exec "$db" pg_isready -U nik -d nik >/dev/null 2>&1 || die "the database is not ready: $COMPOSE logs db"

options=()
[ "$REPLACE" -eq 1 ] && options+=(--replace)
[ "$DATABASE_ONLY" -eq 1 ] && options+=(--database-only)
started=$(date +%s)
if ! tool restore "$target" "${options[@]}"; then
  die "the restore did not happen (see above). The stack is stopped, the database container is up."
fi
log "restored in $(($(date +%s) - started)) seconds"

if [ "$START" -eq 0 ]; then
  log "the stack is left stopped (--no-start): start it with: $COMPOSE up -d"
  exit 0
fi

log "starting the stack"
# shellcheck disable=SC2086
$COMPOSE up -d >/dev/null
answer=""
for _ in $(seq 1 90); do
  api=$($ENGINE ps --filter "label=com.docker.compose.service=api" \
    --filter "label=com.docker.compose.project.working_dir=$NIK_DIR" --format '{{.Names}}' | head -n 1)
  if [ -n "$api" ]; then
    answer=$($ENGINE exec "$api" python -c \
      "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).read().decode())" \
      2>/dev/null || true)
    [ -n "$answer" ] && break
  fi
  sleep 2
done
case "$answer" in
  *'"ok"'*) log "the server answers. Sign in and check what the lines above name." ;;
  *upgrade-stopped*) die "the server started but stopped its upgrade of the restored database: $COMPOSE logs api" ;;
  *'"stopped"'*) die "the server did not start: a key is missing or is not the right one. $COMPOSE logs api says which" ;;
  *) die "the server does not answer yet: $COMPOSE ps, $COMPOSE logs api" ;;
esac
