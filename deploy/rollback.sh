#!/usr/bin/env bash
# Nik: come back from an upgrade that went wrong.
#
#   deploy/rollback.sh                                 # lists the snapshots taken before upgrades
#   deploy/rollback.sh nik-upgrade-20261120-101500     # puts that one back
#
# Before a release changes the database, the server takes a snapshot of it into
# the backup directory. This puts one back:
#   1. stops the stack, starts the database alone;
#   2. reads the whole snapshot and compares every checksum, then replaces the
#      database with it (in one transaction: it is the old one or the new one);
#   3. checks out the version of the code the snapshot was taken from (its
#      tag), when the folder is a git clone with nothing uncommitted; otherwise
#      it says exactly which version to put there, and stops;
#   4. starts the stack on that version and checks that the server answers.
#
# What was written after the upgrade is not in the snapshot: it is lost. The
# store of files is not touched: no upgrade of Nik changes the files that are
# there (one that ever did would say so, and this would refuse).
#
# Running it twice does no harm: the same snapshot gives the same database.
#
# Options:
#   --no-checkout   do not touch the code: say which version goes with the snapshot
#   --no-start      leave the stack stopped at the end
#   --yes           do not ask before replacing the database
#
# Settings (environment): NIK_DIR, ENGINE, COMPOSE, NIK_BACKUP_PASSPHRASE,
# NIK_BACKUP_PASSPHRASE_FILE, as for deploy/restore.sh. A snapshot taken while
# no backup passphrase was set is read with the SECRET_KEY of .env.
set -euo pipefail

NIK_DIR=${NIK_DIR:-$(cd "$(dirname "$0")/.." && pwd)}
if [ -z "${ENGINE:-}" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman; else ENGINE=docker; fi
fi
COMPOSE=${COMPOSE:-"$ENGINE compose"}

log() { printf 'nik-rollback: %s\n' "$*" >&2; }
die() {
  log "$*"
  exit 1
}

CHECKOUT=1
START=1
YES=0
NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-checkout) CHECKOUT=0 ;;
    --no-start) START=0 ;;
    --yes) YES=1 ;;
    -h | --help)
      sed -n '2,31p' "$0"
      exit 0
      ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *)
      [ -z "$NAME" ] || die "one snapshot at a time"
      NAME=${1%.nikbak}
      ;;
  esac
  shift
done

cd "$NIK_DIR"
[ -f docker-compose.yml ] || die "no docker-compose.yml in $NIK_DIR"
[ -f .env ] || die "no .env in $NIK_DIR"

tool() {
  # shellcheck disable=SC2086 # COMPOSE is a command with its arguments
  $COMPOSE run --rm --no-deps -T -e NIK_SKIP_MIGRATIONS=1 -e NIK_BACKUP_PASSPHRASE api \
    python -m app.backups.restore "$@"
}

# name, kind, taken, bytes, version of Nik that took it, tag, revision, how its key is derived, label
export NIK_BACKUP_PASSPHRASE=${NIK_BACKUP_PASSPHRASE:-}
snapshots=$(tool list --kind upgrade | grep '^nik-upgrade-' || true)

if [ -z "$NAME" ]; then
  if [ -z "$snapshots" ]; then
    log "no snapshot taken before an upgrade is in the backup directory of this stack."
    exit 0
  fi
  printf 'Snapshots taken before upgrades, the latest first:\n\n'
  printf '%s\n' "$snapshots" | while IFS="$(printf '\t')" read -r name _kind taken size _nik tag revision _key label; do
    printf '  %s\n      %s\n      taken %s, %s bytes; code: %s (revision %s)\n\n' \
      "$name" "$label" "$taken" "$size" "$tag" "$revision"
  done
  printf 'Put one back with: deploy/rollback.sh <name>\n'
  exit 0
fi

line=$(printf '%s\n' "$snapshots" | awk -F '\t' -v name="$NAME" '$1 == name { print; exit }')
[ -n "$line" ] || die "there is no snapshot named $NAME (deploy/rollback.sh lists them)"
IFS="$(printf '\t')" read -r _name _kind taken _size _nik tag revision key_from label <<EOF
$line
EOF

log "$NAME: $label (taken $taken)"
if [ "$tag" != "-" ]; then
  log "the code that goes with it: $tag"
else
  log "the code that goes with it: the version whose migrations end at the revision $revision"
fi

if [ "$key_from" = "passphrase" ] && [ -z "$NIK_BACKUP_PASSPHRASE" ]; then
  if [ -n "${NIK_BACKUP_PASSPHRASE_FILE:-}" ]; then
    [ -f "$NIK_BACKUP_PASSPHRASE_FILE" ] || die "no passphrase file at $NIK_BACKUP_PASSPHRASE_FILE"
    NIK_BACKUP_PASSPHRASE=$(head -n 1 "$NIK_BACKUP_PASSPHRASE_FILE")
  elif [ -t 0 ]; then
    printf 'Backup passphrase: ' >&2
    IFS= read -rs NIK_BACKUP_PASSPHRASE
    printf '\n' >&2
  else
    die "this snapshot is encrypted with the backup passphrase: give it in NIK_BACKUP_PASSPHRASE or NIK_BACKUP_PASSPHRASE_FILE"
  fi
  export NIK_BACKUP_PASSPHRASE
fi

if [ "$YES" -eq 0 ]; then
  [ -t 0 ] || die "this replaces the database: run it again with --yes to go on without being asked."
  printf 'This REPLACES the database of the Nik in %s with the snapshot. What was written since %s is lost.\nType rollback to go on: ' \
    "$NIK_DIR" "$taken" >&2
  IFS= read -r typed
  [ "$typed" = "rollback" ] || die "nothing was changed."
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

# With the code that is here now (the newer one): it reads every earlier snapshot.
if ! tool restore "$NAME" --replace --database-only; then
  die "the snapshot was not put back (see above): the database is as it was. The stack is stopped."
fi
log "the database is as it was before the upgrade"

# The code. A tag is checked out only into a clean clone: nothing of the operator's is ever overwritten.
code_ready=0
if [ "$tag" = "-" ]; then
  log "this snapshot does not name a tag. Put the version of Nik whose migrations end at $revision in $NIK_DIR,"
  log "then start it: $COMPOSE up -d --build"
elif [ "$CHECKOUT" -eq 0 ]; then
  log "the code was not touched (--no-checkout). Put $tag in $NIK_DIR: git checkout $tag"
  log "then start it: $COMPOSE up -d --build"
elif ! git -C "$NIK_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  log "$NIK_DIR is not a git clone. Put the release $tag there, then start it: $COMPOSE up -d --build"
elif [ "$(git -C "$NIK_DIR" describe --tags --exact-match 2>/dev/null || true)" = "$tag" ]; then
  log "the code is already $tag"
  code_ready=1
elif [ -n "$(git -C "$NIK_DIR" status --porcelain --untracked-files=no)" ]; then
  log "$NIK_DIR has changes that are not committed: the code was not touched."
  log "Keep them aside, then: git checkout $tag && $COMPOSE up -d --build"
elif ! git -C "$NIK_DIR" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  log "the tag $tag is not in this clone: git fetch --tags, then git checkout $tag && $COMPOSE up -d --build"
else
  git -C "$NIK_DIR" checkout --quiet "$tag"
  log "checked out $tag (to come back to the latest later: git checkout main)"
  code_ready=1
fi

if [ "$code_ready" -eq 0 ]; then
  log "the stack is left stopped: started on the newer code, it would only try the same upgrade again."
  exit 0
fi
if [ "$START" -eq 0 ]; then
  log "the stack is left stopped (--no-start): start it with: $COMPOSE up -d --build"
  exit 0
fi

log "starting the stack on $tag (the images are built again)"
# shellcheck disable=SC2086
$COMPOSE up -d --build >/dev/null
answer=""
for _ in $(seq 1 120); do
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
  *'"ok"'*) log "the server answers on $tag. Sign in and look at the latest incidents." ;;
  *) die "the server does not answer yet: $COMPOSE ps, $COMPOSE logs api" ;;
esac
