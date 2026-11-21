#!/usr/bin/env bash
# Nik: a second host kept ready to take over, and the command that makes it the server.
#
#   deploy/standby.sh status                    # either host: the role, how far behind, what a promotion would lose
#   deploy/standby.sh secrets export FILE       # first host: the keys the second one needs, sealed under a passphrase
#   deploy/standby.sh secrets import FILE       # second host: put them where this stack keeps its keys
#   deploy/standby.sh init --inbox DIR          # second host: become the standby of the host that sends into DIR
#   deploy/standby.sh promote                   # second host: become the server
#   deploy/standby.sh rejoin --inbox DIR        # the old first host, repaired: become the standby of the new server
#
# How a pair works. The first host sends, over the SFTP account of its
# backups (Settings → Backup), every segment of the log of its database and
# its base backups, sealed under the backup passphrase, and the files of its
# store, sealed under its store key, into a directory of the second host: DIR.
# The stack of the second host mounts DIR; its database replays the log as it
# arrives and stays read-only, and its containers serve nothing: the page says
# "This server is the standby". No port is opened between the two hosts but
# the SSH one the backups already use, and the first host is the only one that
# connects.
#
# Setting up (the deployment guide has it as numbered steps, "A standby host"):
#   on the first host   Settings → Backup: a passphrase, the destination (this
#                       second host, a directory of it, its host key pinned);
#                       deploy/standby.sh secrets export nik-keys.txt
#   carry the file      it is sealed under the passphrase you typed; any channel
#   on the second host  git clone at the same version, deploy/init-env.sh,
#                       deploy/standby.sh secrets import nik-keys.txt,
#                       deploy/standby.sh init --inbox DIR
#
# promote says first what would be lost (what the first host wrote after the
# last segment that arrived) and asks; then it has PostgreSQL leave recovery,
# makes this server the server (a generation later than the first host's),
# leaves in DIR the file that tells the first host it was replaced, starts
# the whole stack and waits until it answers. It never runs by itself: nothing
# on a screen promotes, and nothing promotes when the first host stops
# answering. Somebody who can see both hosts decides.
#
# Options:
#   --inbox DIR   the directory of this host the other one sends its copies to
#   --replace     (init) this stack holds a database: keep it aside and put the standby in its place
#   --name NAME   (promote) what this server calls itself to the other host (default: NIK_SERVER_NAME, the host name)
#   --force       (promote) go on although not everything that arrived could be replayed
#   --yes         do not ask
#
# Settings (environment): NIK_DIR, ENGINE, COMPOSE, NIK_BACKUP_PASSPHRASE or
# NIK_BACKUP_PASSPHRASE_FILE, NIK_TRANSFER_PASSPHRASE (secrets export and
# import, when nobody attends), NIK_RECOVERY_WAIT: see deploy/recovery-lib.sh.
set -euo pipefail

NIK_SAYS=nik-standby
# shellcheck source=deploy/recovery-lib.sh
. "$(dirname "$0")/recovery-lib.sh"

COMMAND=${1:-}
[ $# -gt 0 ] && shift
SUB=""
FILE=""
INBOX=""
NAME=""
REPLACE=0
FORCE=0
YES=0
if [ "$COMMAND" = secrets ]; then
  SUB=${1:-}
  FILE=${2:-}
  [ $# -ge 2 ] || die "usage: deploy/standby.sh secrets export FILE | secrets import FILE"
  shift 2
fi
while [ $# -gt 0 ]; do
  case "$1" in
    --inbox)
      [ $# -ge 2 ] || die "--inbox needs the directory the other host sends its copies to"
      INBOX=$2
      shift
      ;;
    --name)
      [ $# -ge 2 ] || die "--name needs a name"
      NAME=$2
      shift
      ;;
    --replace) REPLACE=1 ;;
    --force) FORCE=1 ;;
    --yes) YES=1 ;;
    -h | --help)
      sed -n '2,51p' "$0"
      exit 0
      ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

cd "$NIK_DIR"
[ -f docker-compose.yml ] || die "no docker-compose.yml in $NIK_DIR"

need_env() {
  [ -f .env ] || die "no .env in $NIK_DIR: run deploy/init-env.sh first"
}

# The transfer passphrase: typed twice when it seals, once when it opens.
ask_transfer() { # $1 = 1 to ask twice
  if [ -z "${NIK_TRANSFER_PASSPHRASE:-}" ]; then
    [ -t 0 ] || die "a passphrase for the transfer is needed: give it in NIK_TRANSFER_PASSPHRASE"
    printf 'Passphrase for this transfer (12 characters or more): ' >&2
    IFS= read -rs NIK_TRANSFER_PASSPHRASE
    printf '\n' >&2
    if [ "${1:-0}" -eq 1 ]; then
      printf 'Once more: ' >&2
      IFS= read -rs again
      printf '\n' >&2
      [ "$again" = "$NIK_TRANSFER_PASSPHRASE" ] || die "the two are not the same: nothing was written."
    fi
  fi
  export NIK_TRANSFER_PASSPHRASE
}

# Where the keys of this stack are kept: the secrets directory .env names, or .env itself.
secrets_dir() {
  local found
  found=$(env_value NIK_SECRETS_DIR)
  case "$found" in
    "" | /* | ?:*) ;;
    *) found="$NIK_DIR/${found#./}" ;;
  esac
  printf '%s' "$found"
}

keep_secret() { # $1 = NAME, $2 = value: written where this stack keeps its keys
  local dir file
  dir=$(secrets_dir)
  if [ -n "$dir" ]; then
    file="$dir/$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    if [ -s "$file" ] && [ ! -e "$file.before-standby" ]; then
      (umask 077 && cp "$file" "$file.before-standby")
    fi
    printf '%s\n' "$2" >"$file"
    chmod 644 "$file"
  else
    [ -e .env.before-standby ] || (umask 077 && cp .env .env.before-standby)
    set_env_value "$1" "$2"
  fi
}

become_standby() { # the base backup that arrived, in the place of the database; the standby started
  local inbox=$1 plan label state held options=() answer
  [ -d "$inbox" ] || die "there is no directory $inbox"
  inbox=$(cd "$inbox" && pwd)
  [ -d "$inbox/recovery/base" ] || die "nothing has arrived in $inbox yet. On the other host: Settings → Backup, the destination set to this host and this directory; then wait until deploy/standby.sh status there says a base backup was sent, and run this again."
  readable_by_all "$inbox"
  readable_by_all "$inbox/recovery"
  TOOL_MOUNTS=(-v "$inbox:/restore:ro,z")
  ask_passphrase
  # No database has started on a new host yet: the folders of the archive volume are made first.
  dbtool prepare
  plan=$(rtool plan --to latest --from /restore) || die "nothing was changed."
  label=$(printf '%s\n' "$plan" | sed -n 's/^label=//p')
  [ -n "$label" ] || die "no base backup could be chosen: nothing was changed."
  state=$(dbtool state)
  case "$state" in
    *data=empty*) held=0 ;;
    *) held=1 ;;
  esac
  if [ "$held" -eq 1 ] && [ "$REPLACE" -eq 0 ]; then
    die "the stack in $NIK_DIR holds a database: nothing was changed. Add --replace to keep it aside and put the standby in its place."
  fi
  confirm "This stops the Nik in $NIK_DIR and makes it the standby of the host that sends into $inbox." "standby" "$YES"
  log "opening the base backup $label and the log after it"
  rtool fetch --label "$label" --from /restore >/dev/null || die "what the other host sent could not be opened: nothing was changed."
  [ "$(env_value NIK_STANDBY_INBOX)" = "$inbox" ] || set_env_value NIK_STANDBY_INBOX "$inbox"
  log "stopping the stack"
  # shellcheck disable=SC2086
  $COMPOSE stop >/dev/null
  [ "$held" -eq 1 ] && options+=(--replace)
  dbtool restore "/wal-archive/restore/$label" standby "${options[@]}" || die "the base backup was not put in place (see above)."
  log "starting the database as a standby"
  start_database standby || die "the database did not start as a standby (see above)."
  # The database, the recovery service, the backend (which takes in what arrives and says what this
  # server is) and the web server that shows it. Nothing else runs on a standby.
  # shellcheck disable=SC2086
  $COMPOSE up -d db recovery api web >/dev/null
  answer=$(wait_for_api 180 || true)
  case "$answer" in
    standby) ;;
    "") die "the backend does not answer. If its log says the password of the database is refused, the keys of the other host are not in place: deploy/standby.sh secrets import. $COMPOSE logs api" ;;
    *) die "the backend answers \"$answer\", not \"standby\": $COMPOSE logs api" ;;
  esac
  log "this host is the standby. It follows the other host and serves nothing."
  rtool_live status >&2 || true
}

case "$COMMAND" in
  status)
    need_env
    if [ -z "$(container_of api)" ]; then
      die "the api container of this stack is not running: nothing can be said from here ($COMPOSE ps)"
    fi
    rtool_live status
    ;;

  secrets)
    need_env
    case "$SUB" in
      export)
        [ -n "$FILE" ] || die "name the file to write"
        [ ! -e "$FILE" ] || die "$FILE is there already: nothing was written."
        ask_transfer 1
        api=$(container_of api)
        [ -n "$api" ] || die "the api container of this stack is not running: $COMPOSE up -d"
        sealed=$("$ENGINE" exec -u nik -e NIK_TRANSFER_PASSPHRASE "$api" python -m app.recovery.tool pack-secrets) ||
          die "the keys could not be sealed (see above): nothing was written."
        (umask 077 && printf '%s\n' "$sealed" >"$FILE")
        log "written to $FILE, sealed under the passphrase you typed. Carry it to the second host, then:"
        log "  deploy/standby.sh secrets import $(basename "$FILE")"
        log "and remove the file from both hosts once the standby is up."
        ;;
      import)
        [ -f "$FILE" ] || die "there is no file $FILE"
        ask_transfer 0
        folder=$(cd "$(dirname "$FILE")" && pwd)
        readable_by_all "$folder"
        chmod o+r "$FILE" 2>/dev/null || true
        TOOL_MOUNTS=(-v "$folder:/restore:ro,z")
        lines=$(rtool unpack-secrets --file "/restore/$(basename "$FILE")") || die "the file could not be opened: nothing was changed."
        count=0
        while IFS= read -r line; do
          name=${line%%=*}
          value=${line#*=}
          case "$name" in
            DB_PASSWORD | SECRET_KEY | SECRET_KEY_PREVIOUS | STORE_KEY | STORE_KEY_PREVIOUS | AUDIT_KEY | AUDIT_KEY_PREVIOUS)
              keep_secret "$name" "$value"
              count=$((count + 1))
              ;;
          esac
        done <<EOF
$lines
EOF
        unset lines line value
        [ "$count" -gt 0 ] || die "the file held no key: nothing was changed."
        log "$count keys of the first host are in place (the ones that were here are kept beside them as *.before-standby)."
        log "This host can now open what the first one sends: deploy/standby.sh init --inbox <directory>"
        ;;
      *) die "usage: deploy/standby.sh secrets export FILE | secrets import FILE" ;;
    esac
    ;;

  init)
    need_env
    [ -n "$INBOX" ] || die "name the directory the first host sends its copies to: --inbox DIR"
    become_standby "$INBOX"
    ;;

  rejoin)
    need_env
    [ -n "$INBOX" ] || die "name the directory the new server sends its copies to: --inbox DIR"
    log "This host was the server. Its database is kept aside (deploy/restore.sh --asides) and replaced by a"
    log "base backup of the new server: what was written here after the last copy reached the other host stays"
    log "in the database kept aside and nowhere else."
    REPLACE=1
    become_standby "$INBOX"
    ;;

  promote)
    need_env
    api=$(container_of api)
    db=$(container_of db)
    [ -n "$api" ] && [ -n "$db" ] || die "the database and the backend of this stack must be running: $COMPOSE ps"
    started=$(date +%s)
    if [ "$(sql "$db" "select pg_is_in_recovery()")" = "t" ]; then
      rtool_live status >&2 || true
      confirm "This makes THIS host the server. The other host must be down, or off the network: two servers must never work at once." "promote" "$YES"
      started=$(date +%s)
      log "taking in everything that arrived"
      drain_args=(--wait 120 --promoting)
      [ "$FORCE" -eq 1 ] && drain_args+=(--force)
      # The mark of a promotion that starts is left by this step: until the last one removes it the
      # backend does not start as the server, whatever happens in between.
      rtool_live drain "${drain_args[@]}" ||
        die "not everything that arrived could be replayed (see above). Nothing was changed. --force promotes with what was replayed."
      log "promoting the database"
      promote_database "$db" || die "PostgreSQL did not leave recovery: $COMPOSE logs db. Run this again once it has."
    elif rtool_live promoting; then
      log "a promotion was started here and not finished: finishing it"
    else
      die "this server is not a standby: there is nothing to promote."
    fi
    name_args=()
    [ -n "$NAME" ] && name_args=(--name "$NAME")
    said=$(rtool_live promoted "${name_args[@]}") || die "the database is promoted but this server could not be made the server (see above): $COMPOSE logs api"
    marker=$(printf '%s\n' "$said" | sed -n 's/^marker=//p')
    if [ "$(printf '%s\n' "$said" | sed -n 's/^marker_written=//p')" != "1" ]; then
      inbox=$(env_value NIK_STANDBY_INBOX)
      if [ -n "$inbox" ] && printf '%s\n' "$marker" >"$inbox/recovery/superseded.json" 2>/dev/null; then
        chmod 644 "$inbox/recovery/superseded.json" 2>/dev/null || true
      else
        log "The file that tells the old server it was replaced could NOT be written. Write it yourself, as the"
        log "account the other host signs in with: $inbox/recovery/superseded.json, with this one line:"
        log "  $marker"
      fi
    fi
    log "starting the stack"
    # shellcheck disable=SC2086
    $COMPOSE up -d >/dev/null
    answer=$(wait_for_api 300 || true)
    [ "$answer" = ok ] || die "the server does not answer \"ok\" (it says \"$answer\"): $COMPOSE ps, $COMPOSE logs api"
    log "this host is the server: it answers after $(($(date +%s) - started)) seconds."
    log "What to do now:"
    log "  1. point the users at this host: the name they type must reach it (DNS, or the address of the proxy"
    log "     in front). Nik cannot move an address. Its certificate must carry that name (TLS_HOSTNAME in .env)."
    log "  2. keep the old host off, or off the network, until it is made the standby: started as it is and"
    log "     able to reach this host, it finds out it was replaced and serves nothing; unable to reach it, it"
    log "     cannot know. On the old host, once repaired: deploy/standby.sh rejoin --inbox <directory>."
    log "  3. Settings → Backup here: the destination is still this host itself, and nothing is sent until you"
    log "     set the old host (its SFTP account and directory) as the destination. Until then there is no standby."
    log "  4. sign in and check the last incidents: what the old host wrote after the moment said above is not here."
    ;;

  "" | -h | --help)
    sed -n '2,51p' "$0"
    ;;
  *) die "unknown command: $COMMAND (see --help)" ;;
esac
