# shellcheck shell=bash
# Nik: what deploy/recover-to.sh and deploy/standby.sh share. Sourced, never run.
#
# Both do on the host what only the host can do (stop and start containers,
# put a base backup in the place of the data directory) and leave everything
# that reads the archive or the database to a command of the backend
# (python -m app.recovery.tool), run in a container of the stack.
#
# Settings (environment), as for the other scripts of deploy/:
#   NIK_DIR     repository root with docker-compose.yml   (default: the parent of deploy/)
#   ENGINE      container engine: podman or docker         (default: podman if installed, else docker)
#   COMPOSE     compose command                            (default: "$ENGINE compose")
#   NIK_BACKUP_PASSPHRASE / NIK_BACKUP_PASSPHRASE_FILE     the backup passphrase, when nobody attends
#   NIK_RECOVERY_WAIT   seconds a replay is waited for      (default: 3600)

NIK_DIR=${NIK_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
if [ -z "${ENGINE:-}" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman; else ENGINE=docker; fi
fi
COMPOSE=${COMPOSE:-"$ENGINE compose"}
NIK_RECOVERY_WAIT=${NIK_RECOVERY_WAIT:-3600}
TOOL_MOUNTS=()

log() { printf '%s: %s\n' "${NIK_SAYS:-nik-recovery}" "$*" >&2; }
die() {
  log "$*"
  exit 1
}

confirm() { # $1 = question, $2 = the word to type, $3 = 1 when nobody is to be asked
  [ "${3:-0}" -eq 1 ] && return 0
  [ -t 0 ] || die "$1 Run it again with --yes to go on without being asked."
  printf '%s Type %s to go on: ' "$1" "$2" >&2
  IFS= read -r typed
  [ "$typed" = "$2" ] || die "nothing was changed."
}

# The backup passphrase: from the environment, from a file, or asked for. It reaches a container
# through its environment, never through a command line.
ask_passphrase() {
  if [ -n "${NIK_BACKUP_PASSPHRASE_FILE:-}" ]; then
    [ -f "$NIK_BACKUP_PASSPHRASE_FILE" ] || die "no passphrase file at $NIK_BACKUP_PASSPHRASE_FILE"
    NIK_BACKUP_PASSPHRASE=$(head -n 1 "$NIK_BACKUP_PASSPHRASE_FILE")
  elif [ -z "${NIK_BACKUP_PASSPHRASE:-}" ]; then
    [ -t 0 ] || die "the backup passphrase is needed to open what the other host sent: give it in NIK_BACKUP_PASSPHRASE or NIK_BACKUP_PASSPHRASE_FILE"
    printf 'Backup passphrase: ' >&2
    IFS= read -rs NIK_BACKUP_PASSPHRASE
    printf '\n' >&2
  fi
  [ -n "$NIK_BACKUP_PASSPHRASE" ] || die "no backup passphrase was given"
  export NIK_BACKUP_PASSPHRASE
}

# A directory of the host that a container of the backend must read (the copies of the other
# host). The backend runs as a user that is nobody on the host: it reads what everybody may.
readable_by_all() {
  case "$(stat -c '%A' "$1" 2>/dev/null || true)" in
    ???????r?[xt] | "") ;;
    *) die "$1 is closed to other users, and the backend reads it as one: what is in it is sealed, so open it (chmod -R o+rX $1), then run this again" ;;
  esac
}

# One command of the recovery, in a container of the api service: its image, its environment (the
# database, the keys), its volumes (the archive, the store). The entrypoint migrates nothing here.
rtool() {
  # shellcheck disable=SC2086 # COMPOSE is a command with its arguments
  $COMPOSE run --rm --no-deps -T -e NIK_SKIP_MIGRATIONS=1 -e NIK_BACKUP_PASSPHRASE -e NIK_TRANSFER_PASSPHRASE \
    "${TOOL_MOUNTS[@]}" api python -m app.recovery.tool "$@"
}

# The same command in the api container that is running (a standby, a server).
rtool_live() {
  local api
  api=$(container_of api)
  [ -n "$api" ] || die "the api container of this stack is not running: $COMPOSE up -d"
  # As the user the server runs as: what it writes (the store, the archive volume) is the server's.
  "$ENGINE" exec -u nik -e NIK_BACKUP_PASSPHRASE "$api" python -m app.recovery.tool "$@"
}

# The data directory of PostgreSQL, handled by a container of the db service that does not
# start PostgreSQL (deploy/db/pitr.sh).
dbtool() {
  # shellcheck disable=SC2086
  $COMPOSE run --rm --no-deps -T -e NIK_TARGET_TIME --entrypoint sh db /usr/local/lib/nik/pitr.sh "$@"
}

# The containers are found by the labels both `docker compose` and `podman-compose` set.
container_of() { # $1 = service
  "$ENGINE" ps --filter "label=com.docker.compose.service=$1" \
    --filter "label=com.docker.compose.project.working_dir=$NIK_DIR" --format '{{.Names}}' | head -n 1
}

sql() { # $1 = container of the database, $2 = a query; prints its answer, or nothing
  "$ENGINE" exec "$1" psql -U nik -d nik -AtXc "$2" 2>/dev/null || true
}

# Start the database alone and wait until it has finished replaying: "f" from pg_is_in_recovery().
# With $1 = standby, wait instead until it answers as a standby ("t").
start_database() {
  local wanted=f db="" answer="" waited=0 said=0
  [ "${1:-}" = standby ] && wanted=t
  # shellcheck disable=SC2086
  $COMPOSE up -d db >/dev/null
  while [ "$waited" -lt "$NIK_RECOVERY_WAIT" ]; do
    db=$(container_of db)
    if [ -n "$db" ]; then
      answer=$(sql "$db" "select pg_is_in_recovery()")
      [ "$answer" = "$wanted" ] && return 0
      if [ "$wanted" = f ] && [ $((waited - said)) -ge 15 ]; then
        said=$waited
        log "replaying the log… $(sql "$db" "select 'the last change replayed was made at ' || pg_last_xact_replay_timestamp()")"
      fi
    else
      # Not running: PostgreSQL refused the data it was given and the container went away.
      if [ "$waited" -ge 20 ]; then break; fi
    fi
    sleep 2
    waited=$((waited + 2))
  done
  log "the database did not come up as expected. Its last lines:"
  # shellcheck disable=SC2086
  $COMPOSE logs --tail 25 db >&2 || true
  return 1
}

# Have PostgreSQL leave recovery, and wait until it has. Asked of the server itself, not with a
# query: a query on a standby holds back the replay it conflicts with, and is cancelled for it.
promote_database() { # $1 = container of the database
  local waited=0
  # shellcheck disable=SC2016 # PGDATA is the container's
  "$ENGINE" exec -u postgres "$1" sh -c 'pg_ctl promote -D "$PGDATA" -w -t 120' >/dev/null 2>&1 || true
  while [ "$waited" -lt 120 ]; do
    [ "$(sql "$1" "select pg_is_in_recovery()")" = "f" ] && return 0
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

# Wait for the health check of the api container: prints the word it answers ("ok", "standby" …).
wait_for_api() { # $1 = seconds
  local api answer="" waited=0
  while [ "$waited" -lt "${1:-180}" ]; do
    api=$(container_of api)
    if [ -n "$api" ]; then
      answer=$("$ENGINE" exec "$api" python -c \
        "import json, urllib.request; print(json.loads(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).read()).get('status', ''))" \
        2>/dev/null || true)
      case "$answer" in
        "" | checking | promoting) ;;
        *)
          printf '%s\n' "$answer"
          return 0
          ;;
      esac
    fi
    sleep 2
    waited=$((waited + 2))
  done
  printf '%s\n' "$answer"
  return 1
}

# A value of .env (the last line that sets it) without the quotes around it, or nothing: read as
# value_of reads it in deploy/secrets.sh and deploy/init-env.sh.
env_value() {
  sed -n "s/^$1=//p" "$NIK_DIR/.env" 2>/dev/null | tail -n 1 | sed "s/^['\"]//; s/['\"]\$//"
}

# Set a value of .env, keeping the file as it was beside it the first time this run changes it.
set_env_value() { # $1 = name, $2 = value
  local file="$NIK_DIR/.env"
  NAME="$1" VALUE="$2" awk 'BEGIN { done = 0 }
    index($0, ENVIRON["NAME"] "=") == 1 { print ENVIRON["NAME"] "=" ENVIRON["VALUE"]; done = 1; next } { print }
    END { if (!done) print ENVIRON["NAME"] "=" ENVIRON["VALUE"] }' "$file" >"$file.changing"
  chmod 600 "$file.changing"
  mv "$file.changing" "$file"
}
