#!/usr/bin/env bash
# Nik: bring the database back to a moment. Run through deploy/restore.sh:
#
#   deploy/restore.sh --to "2026-11-21 14:03:00+00"
#   deploy/restore.sh --to latest [--from /srv/nik-copies]
#
# deploy/restore.sh --help says what it does and lists the options; this file
# is that part of it, and reads what was asked from the environment
# (PITR_TO, PITR_FROM, PITR_REPLACE, PITR_ASIDE, PITR_START, PITR_YES,
# PITR_ASIDES, PITR_DROP_ASIDE, PITR_PUT_BACK).
#
# In order:
#   1. the plan: which base backup, whether the log reaches the moment.
#      Nothing is touched if there is none; what will be lost is said;
#   2. with --from, the base backup and the log that came from the other host
#      are opened with the backup passphrase (every checksum is compared);
#   3. the stack is stopped;
#   4. the base backup is put in the place of the data directory. A database
#      that is there is kept aside under a name that says when (--replace),
#      never written over;
#   5. the database is started alone and replays its log to the moment;
#   6. what came back is checked: the revision, the audit log against its
#      chain, every file the database names (those deleted since are put back);
#   7. the stack is started.
#
# Run twice, it does the same thing twice: the second run keeps the database
# of the first aside and recovers again.
set -euo pipefail

NIK_SAYS=nik-restore
# shellcheck source=deploy/recovery-lib.sh
. "$(dirname "$0")/recovery-lib.sh"

TO=${PITR_TO:-}
FROM=${PITR_FROM:-}
REPLACE=${PITR_REPLACE:-0}
ASIDE=${PITR_ASIDE:-1}
START=${PITR_START:-1}
YES=${PITR_YES:-0}

cd "$NIK_DIR"
[ -f docker-compose.yml ] || die "no docker-compose.yml in $NIK_DIR"
[ -f .env ] || die "no .env in $NIK_DIR: on a new host run deploy/init-env.sh first, then put the keys of the old server where it keeps them (deploy/standby.sh secrets import)"

# On a new host no database has started yet: the folders of the archive volume are made first.
dbtool prepare

# ----- the databases kept aside ----- #
if [ "${PITR_ASIDES:-0}" -eq 1 ]; then
  found=$(dbtool state | sed -n 's/^aside=//p')
  if [ -z "$found" ]; then
    log "no database is kept aside"
  else
    log "databases kept aside by earlier runs (name, MB):"
    printf '%s\n' "$found" | while read -r name size; do printf '  %s  %s\n' "$name" "$((size / 1024))" >&2; done
    log "remove one with: deploy/restore.sh --drop-aside <name>; put one back with: deploy/restore.sh --put-back <name>"
  fi
  exit 0
fi
if [ -n "${PITR_DROP_ASIDE:-}" ]; then
  confirm "This removes for good the database kept aside as $PITR_DROP_ASIDE." "remove" "$YES"
  dbtool drop-aside "$PITR_DROP_ASIDE"
  exit 0
fi
if [ -n "${PITR_PUT_BACK:-}" ]; then
  confirm "This stops the Nik in $NIK_DIR and puts the database kept aside as $PITR_PUT_BACK back in its place (the one that is there is kept aside)." "put back" "$YES"
  # shellcheck disable=SC2086
  $COMPOSE stop >/dev/null
  dbtool put-back "$PITR_PUT_BACK"
  if [ "$START" -eq 1 ]; then
    # shellcheck disable=SC2086
    $COMPOSE up -d >/dev/null
    log "the stack is starting: $COMPOSE ps"
  fi
  exit 0
fi

# ----- 1. the plan ----- #
source_args=()
if [ -n "$FROM" ]; then
  [ -d "$FROM" ] || die "there is no directory $FROM"
  FROM=$(cd "$FROM" && pwd)
  readable_by_all "$FROM"
  TOOL_MOUNTS=(-v "$FROM:/restore:ro,z")
  source_args=(--from /restore)
  ask_passphrase
fi

plan=$(rtool plan --to "$TO" "${source_args[@]}") || die "nothing was changed."
label=$(printf '%s\n' "$plan" | sed -n 's/^label=//p')
place=$(printf '%s\n' "$plan" | sed -n 's/^place=//p')
target=$(printf '%s\n' "$plan" | sed -n 's/^target=//p')
newest=$(printf '%s\n' "$plan" | sed -n 's/^newest=//p')
[ -n "$label" ] && [ -n "$place" ] || die "the plan of the recovery could not be read: nothing was changed."

state=$(dbtool state)
case "$state" in
  *data=empty*) held=0 ;;
  *) held=1 ;;
esac
if [ "$held" -eq 1 ] && [ "$REPLACE" -eq 0 ]; then
  die "the stack in $NIK_DIR holds a database: nothing was changed. Add --replace to keep it aside and put the recovered one in its place."
fi
if [ "$held" -eq 1 ]; then
  confirm "This stops the Nik in $NIK_DIR and REPLACES its database with the one of that moment (the one that is there is kept aside)." "replace" "$YES"
else
  confirm "This stops the Nik in $NIK_DIR and recovers the database of that moment into it." "recover" "$YES"
fi

# ----- 2. what came from the other host ----- #
if [ -n "$FROM" ]; then
  log "opening the base backup and its log (the passphrase is checked first, then every checksum)"
  rtool fetch --label "$label" --from /restore >/dev/null || die "what the other host sent could not be opened: nothing was changed."
fi

# ----- 3, 4. the base backup in the place of the database ----- #
started=$(date +%s)
log "stopping the stack"
# shellcheck disable=SC2086
$COMPOSE stop >/dev/null
options=()
[ "$REPLACE" -eq 1 ] && options+=(--replace)
[ "$ASIDE" -eq 0 ] && options+=(--no-aside)
NIK_TARGET_TIME="$target" dbtool restore "/wal-archive/$place/$label" pitr "${options[@]}" ||
  die "the base backup was not put in place (see above). The stack is stopped: $COMPOSE up -d starts it as it was."

# ----- 5. the replay ----- #
log "the database replays its log${target:+ to $target}"
if ! start_database; then
  log "The replay did not finish. If the lines above say the recovery ended before its target was reached, the"
  log "archive does not hold that moment: run again with an earlier one, or with --to latest."
  log "The database that was there before this run is kept aside: deploy/restore.sh --asides lists it, and"
  die "deploy/restore.sh --put-back <name> puts it back."
fi

# ----- 6. what came back ----- #
after_args=()
[ -n "$FROM" ] && after_args=(--replaced)
said=$(rtool after --to "$TO" --label "$label" --newest "$newest" "${after_args[@]}") ||
  die "the database is back but could not be checked (see above). The stack is stopped; the database container is up."
if [ -n "$FROM" ]; then
  # Recovered from the copies of another host: this server takes its place. The file that tells
  # the old one so, should it come back and still send its copies there, is left beside them.
  marker=$(printf '%s\n' "$said" | sed -n 's/^marker=//p')
  beside=$FROM
  [ -d "$FROM/recovery" ] && beside="$FROM/recovery"
  if [ -n "$marker" ] && printf '%s\n' "$marker" >"$beside/superseded.json" 2>/dev/null; then
    chmod 644 "$beside/superseded.json" 2>/dev/null || true
    log "this server takes the place of the one the copies came from: $beside/superseded.json says so to that"
    log "server, which serves nothing more once it reads it. (A rehearsal on a copy of the directory tells nobody.)"
  elif [ -n "$marker" ]; then
    log "This server takes the place of the one the copies came from, but the file that tells it so could NOT be"
    log "written. If the old server can ever come back, write it yourself where it sends its copies"
    log "(<directory>/recovery/superseded.json), with this one line:  $marker"
  fi
fi
log "recovered in $(($(date +%s) - started)) seconds"
log "the database that was there is kept aside, if there was one: deploy/restore.sh --asides lists what to remove once all is well"

# ----- 7. the stack ----- #
if [ "$START" -eq 0 ]; then
  log "the stack is left stopped (--no-start): start it with: $COMPOSE up -d"
  exit 0
fi
log "starting the stack"
# shellcheck disable=SC2086
$COMPOSE up -d >/dev/null
answer=$(wait_for_api 240 || true)
case "$answer" in
  ok)
    log "the server answers. Check before anybody works on it:"
    log "  - sign in, open the incident you came back for, and one file of the store;"
    log "  - Settings → System → Audit log: the chain verifies and its last entries are those of the moment;"
    log "  - Settings → Backup: a new base backup is being taken (the database writes a new timeline);"
    log "  - Automations: after going back to a moment you named, the general switch is off (see above). Turn it"
    log "    on once you have looked at what the other systems hold since that moment: connectors that fetch then"
    log "    start again from where they were, and what they fetched since comes in again."
    ;;
  upgrade-stopped) die "the server started but stopped its upgrade of the recovered database: $COMPOSE logs api" ;;
  stopped) die "the server did not start: a key is missing or is not the right one. $COMPOSE logs api says which" ;;
  superseded) die "the database that came back says this server was replaced by its standby: it serves nothing. $COMPOSE logs api" ;;
  standby) die "the database that came back is a standby: deploy/standby.sh status" ;;
  *) die "the server does not answer yet: $COMPOSE ps, $COMPOSE logs api" ;;
esac
