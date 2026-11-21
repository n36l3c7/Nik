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
# store of files is not touched: no upgrade of Nik changes what the files that
# are there hold (one that ever did would say so, and this would refuse).
#
# Coming back to a version before 6.8, which reads its store in clear and its
# secrets in .env, two more things are done first, with the code that is here:
# every file of the store is unsealed (decrypted in place, one at a time, each
# compared with what was read before it takes the place of the sealed one),
# and the secrets are put back into .env if they had been moved to files
# (deploy/secrets.sh back). Neither loses anything; if a file cannot be
# unsealed this stops before the database is touched, and says which.
#
# Files deleted since the snapshot was taken, which a server that archives its
# log keeps for a while (6.9), are moved back to their places: the database
# that comes back names them again.
#
# Coming back to a version before 6.9, which has no archive of the log of the
# database, no recovery service and no standby: the `recovery` container is
# removed, and PostgreSQL starts without archiving on the older version. The
# archive volume is left as it is (nothing reads it any more: the last lines
# say how to remove it). Nothing of 6.9 is left in the database, which is the
# one of before the upgrade: a step of a playbook that was running when the
# snapshot was taken is handled as that version does. A standby of this
# server follows nothing from then on: stop its stack, and make it again
# after the next upgrade.
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
# no backup passphrase was set is read with the SECRET_KEY of this server.
set -euo pipefail

NIK_DIR=${NIK_DIR:-$(cd "$(dirname "$0")/.." && pwd)}
# Step 3 checks out another version of the code, and with it another version of this very file, while
# it runs: a shell reads its script as it goes, and would go on in the middle of the other one. So the
# script runs from a copy of itself, which nothing replaces.
if [ -z "${NIK_ROLLBACK_RUNNING:-}" ]; then
  NIK_ROLLBACK_RUNNING=$(mktemp "${TMPDIR:-/tmp}/nik-rollback.XXXXXX")
  cat "$0" >"$NIK_ROLLBACK_RUNNING"
  export NIK_DIR NIK_ROLLBACK_RUNNING
  exec bash "$NIK_ROLLBACK_RUNNING" "$@"
fi
trap 'rm -f "$NIK_ROLLBACK_RUNNING"' EXIT
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
      sed -n '2,52p' "$0"
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

# The version the snapshot goes with: before 6.8, the store is read in clear and the secrets in .env.
before_68=0
case "${tag#v}" in
  [0-5].* | 6.[0-7] | 6.[0-7].*) before_68=1 ;;
esac
# Before 6.9: no archive of the log, no recovery service.
before_69=0
case "${tag#v}" in
  [0-5].* | 6.[0-8] | 6.[0-8].*) before_69=1 ;;
esac

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

if [ "$before_68" -eq 1 ]; then
  log "$tag reads its store in clear: unsealing the files of the store with the code that is here"
  # shellcheck disable=SC2086
  if ! $COMPOSE run --rm --no-deps -T -e NIK_SKIP_MIGRATIONS=1 api python -m app.store_seal unseal; then
    die "some files of the store could not be unsealed (above): the database was not touched. The stack is stopped; started again on this version it seals the store again by itself."
  fi
fi

# With the code that is here now (the newer one): it reads every earlier snapshot.
if ! tool restore "$NAME" --replace --database-only; then
  die "the snapshot was not put back (see above): the database is as it was. The stack is stopped."
fi
log "the database is as it was before the upgrade"

if [ "$before_68" -eq 1 ] && grep -q '^NIK_SECRETS_DIR=.' .env; then
  log "$tag reads its secrets in .env: putting them back there (deploy/secrets.sh back)"
  export NIK_DIR ENGINE COMPOSE
  deploy/secrets.sh back --no-start --yes
fi

if [ "$before_69" -eq 1 ]; then
  log "$tag has no recovery service and keeps no archive of the log of the database: that container is removed"
  # shellcheck disable=SC2086
  $COMPOSE rm -sf recovery >/dev/null 2>&1 || true
  log "the volumes wal-archive and db-socket of this stack are left as they are; $tag does not use them."
  log "Once you are sure not to come back to 6.9 with this archive: $ENGINE volume ls, then $ENGINE volume rm <project>_wal-archive <project>_db-socket"
  log "if this server had a standby: stop the stack of the standby, it follows nothing any more."
fi

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
