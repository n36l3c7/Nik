#!/usr/bin/env bash
# Nik: where the secrets of the stack are kept, and changing a key.
#
#   deploy/secrets.sh status               # where each secret is, and where a change of key stands
#   deploy/secrets.sh move                 # take the secrets out of .env, into files
#   deploy/secrets.sh rotate secret-key    # change SECRET_KEY
#   deploy/secrets.sh rotate store-key     # change STORE_KEY
#   deploy/secrets.sh rotate tokens        # change the tokens of the workers
#   deploy/secrets.sh back                 # put the secrets back into .env (to return to a version before 6.8)
#
# It never prints a secret, and it is safe to run again: every command looks at
# what is there and goes on from it.
#
# move. A stack from before 6.8 keeps its secrets in .env, so in the environment
# of its containers: `inspect` shows them and every process inherits them. This
# writes each one into a file of ./secrets (a directory only you can enter),
# keeps the .env as it was in .env.before-secrets, writes an .env that names
# the directory and holds no secret, starts the stack on it and checks that the
# server answers and reads its keys from the files. If it does not, the .env
# is put back as it was and the stack is started on it again. At the end
# .env.before-secrets still holds every secret in clear: destroy it (shred -u)
# or lock it away, once you have seen the server work.
#
# rotate secret-key | store-key. The new key is made by the running server and
# written straight into the place the keys are kept, never shown; the key in
# use until now is kept beside it as the earlier key; the containers that hold
# the key are restarted (the stack is down for the time of a restart: about a
# minute). The server then puts everything under the new key and reads it back
# with the new key alone; this waits for that, shows how far it is, and only
# when the server says it is verified does it take the earlier key away (it is
# moved to a file of ./secrets/retired, which nothing reads: see the end of
# the output for what to do with it) and restart the same containers once
# more. Stopped at any moment, it is run again and goes on. A change should
# first be asked for in Nik (Settings → Keys → Rotate…) by an administrator
# who gives the password again; when nobody did, this says so and asks.
#
# Options:
#   --yes          do not ask (before changing a key nobody asked for in Nik; before stopping)
#   --no-start     with move and back: write the files, do not restart the stack
#
# Settings (environment):
#   NIK_DIR     repository root with docker-compose.yml   (default: this script's ../)
#   ENGINE      container engine: podman or docker         (default: podman if installed, else docker)
#   COMPOSE     compose command                            (default: "$ENGINE compose")
#   NIK_ROTATE_WAIT   seconds to wait for a change of key to be verified   (default: 21600)
set -euo pipefail

NIK_DIR=${NIK_DIR:-$(cd "$(dirname "$0")/.." && pwd)}
if [ -z "${ENGINE:-}" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman; else ENGINE=docker; fi
fi
COMPOSE=${COMPOSE:-"$ENGINE compose"}
WAIT=${NIK_ROTATE_WAIT:-21600}

log() { printf 'nik-secrets: %s\n' "$*" >&2; }
die() {
  log "$*"
  exit 1
}

TOKENS="ANALYZER_TOKEN CAPA_TOKEN DOCVIEW_TOKEN BROWSER_TOKEN PCAP_TOKEN SANDBOX_TOKEN"
SECRETS="DB_PASSWORD SECRET_KEY STORE_KEY $TOKENS SECRET_KEY_PREVIOUS STORE_KEY_PREVIOUS METRICS_TOKEN"

YES=0
START=1
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1 ;;
    --no-start) START=0 ;;
    -h | --help)
      sed -n '2,45p' "$0"
      exit 0
      ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done
COMMAND=${ARGS[0]:-}
[ -n "$COMMAND" ] || die "say what to do: status, move, rotate secret-key, rotate store-key, rotate tokens, back (see --help)"

cd "$NIK_DIR"
[ -f docker-compose.yml ] || die "no docker-compose.yml in $NIK_DIR"
ENV_FILE=$NIK_DIR/.env
[ -f "$ENV_FILE" ] || die "no .env in $NIK_DIR: run deploy/init-env.sh first"
umask 077

# --------------------------------------------------------------------------- #
# The env file and the secrets directory                                      #
# --------------------------------------------------------------------------- #
value_of() { # NAME [file]: its value in the env file, without quotes ("" when absent)
  sed -n "s/^$1=//p" "${2:-$ENV_FILE}" | tail -n 1 | sed "s/^['\"]//; s/['\"]\$//"
}

set_value() { # NAME VALUE [file]: the value goes through the environment of awk, never its arguments
  local file=${3:-$ENV_FILE}
  if grep -q "^$1=" "$file"; then
    NIK_VALUE="$2" awk -v name="$1" \
      'index($0, name "=") == 1 { print name "=" ENVIRON["NIK_VALUE"]; next } { print }' "$file" >"$file.tmp.$$"
    cat "$file.tmp.$$" >"$file"
    rm -f "$file.tmp.$$"
  else
    printf '%s=%s\n' "$1" "$2" >>"$file"
  fi
}

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

secrets_dir() { # the directory the env file names, as a path of the host ("" when it names none)
  local named
  named=$(value_of NIK_SECRETS_DIR)
  case "$named" in
    "") printf '' ;;
    /* | ?:*) printf '%s' "$named" ;;
    *) printf '%s/%s' "$NIK_DIR" "${named#./}" ;;
  esac
}

SECRETS_DIR=$(secrets_dir)
if [ -n "$SECRETS_DIR" ]; then MODE="files"; else MODE="env"; fi

file_of() { printf '%s/%s' "$SECRETS_DIR" "$(lower "$1")"; }

get() { # NAME: the secret, from where this stack keeps its secrets
  if [ "$MODE" = files ]; then
    if [ -f "$(file_of "$1")" ]; then tr -d '\r\n' <"$(file_of "$1")"; fi
  else
    value_of "$1"
  fi
}

put() { # NAME VALUE: written in place (a container that has the file mounted sees it after a restart)
  if [ "$MODE" = files ]; then
    printf '%s\n' "$2" >"$(file_of "$1")"
    chmod 644 "$(file_of "$1")"
  else
    set_value "$1" "$2"
  fi
}

clear() { # NAME: no value any more
  if [ "$MODE" = files ]; then
    : >"$(file_of "$1")"
  else
    set_value "$1" ""
  fi
}

# --------------------------------------------------------------------------- #
# The stack                                                                   #
# --------------------------------------------------------------------------- #
container() { # the name of the running container of a service ("" when it is not running)
  $ENGINE ps --filter "label=com.docker.compose.service=$1" \
    --filter "label=com.docker.compose.project.working_dir=$NIK_DIR" --format '{{.Names}}' | head -n 1
}

in_api() { # a command of the backend, in the running api container; its output is the caller's
  local api
  api=$(container api)
  [ -n "$api" ] || return 1
  $ENGINE exec -i "$api" "$@"
}

health() {
  in_api python -c \
    "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).read().decode())" \
    2>/dev/null || true
}

wait_for_server() { # until the server answers; says what it answered
  local answer=""
  for _ in $(seq 1 150); do
    answer=$(health)
    [ -n "$answer" ] && break
    sleep 2
  done
  printf '%s' "$answer"
}

compose() { # what Compose says while it works is kept, and shown only when it fails
  local said
  # shellcheck disable=SC2086 # COMPOSE is a command with its arguments
  if ! said=$($COMPOSE "$@" 2>&1); then
    printf '%s\n' "$said" >&2
    return 1
  fi
}

restart() { # the services that hold what changed
  if [ "$MODE" = files ]; then
    # The files are the same files with another content: a restart reads them again.
    compose restart "$@"
  else
    # The environment of a container is fixed when it is made: it is made again.
    compose up -d "$@"
  fi
}

confirm() { # $1 = question, $2 = the word to type
  [ "$YES" -eq 1 ] && return 0
  [ -t 0 ] || die "$1 Run it again with --yes to go on without being asked."
  printf '%s Type %s to go on: ' "$1" "$2" >&2
  IFS= read -r typed
  [ "$typed" = "$2" ] || die "nothing was changed."
}

new_key() { # a new key on standard output: made by the running server, or here when it is not running
  if ! in_api python -m app.key_rotation new-key 2>/dev/null; then
    if command -v openssl >/dev/null 2>&1; then
      openssl rand -hex 32
    else
      od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
      printf '\n'
    fi
  fi
}

# --------------------------------------------------------------------------- #
# status                                                                      #
# --------------------------------------------------------------------------- #
status() {
  if [ "$MODE" = files ]; then
    log "the secrets of this stack are in files: $SECRETS_DIR"
    case "$(stat -c '%a' "$SECRETS_DIR" 2>/dev/null || echo 700)" in
      700) ;;
      *) log "  the directory can be entered by other users of this host: chmod 700 $SECRETS_DIR" ;;
    esac
  else
    log "the secrets of this stack are in $ENV_FILE, so in the environment of its containers (deploy/secrets.sh move takes them out)"
  fi
  for name in $SECRETS; do
    if [ -n "$(get "$name")" ]; then
      printf '  %-22s set\n' "$name" >&2
    else
      case "$name" in
        *_PREVIOUS | METRICS_TOKEN) printf '  %-22s -\n' "$name" >&2 ;;
        *) printf '  %-22s MISSING\n' "$name" >&2 ;;
      esac
    fi
  done
  if [ -n "$(container api)" ]; then
    for name in SECRET_KEY STORE_KEY; do
      log "$name: $(in_api python -m app.key_rotation status "$name" 2>/dev/null | head -n 1 || echo unknown)"
    done
  else
    log "the stack is not running: where a change of key stands is not known"
  fi
}

# --------------------------------------------------------------------------- #
# move, back                                                                  #
# --------------------------------------------------------------------------- #
verify_files() { # the stack runs and reads its keys from the files
  local answer sources
  answer=$(wait_for_server)
  case "$answer" in
    *'"ok"'*) ;;
    *) return 1 ;;
  esac
  sources=$(in_api python -c "from app.core import keys; print(keys.source('SECRET_KEY'), keys.source('STORE_KEY'), keys.source('DB_PASSWORD'))" 2>/dev/null || true)
  [ "$sources" = "file file file" ]
}

move() {
  if [ "$MODE" = files ]; then
    for name in $SECRETS; do
      [ -f "$(file_of "$name")" ] || die "$SECRETS_DIR lacks the file $(lower "$name"): run deploy/init-env.sh, which makes what is missing"
    done
    if [ "$START" -eq 0 ]; then
      log "the secrets are in $SECRETS_DIR already. Start the stack: $COMPOSE up -d"
      return 0
    fi
    # Moved already, or stopped just after the env file was written: the stack is started on the files.
    compose up -d
    verify_files || die "the stack does not answer on the secrets of $SECRETS_DIR: $COMPOSE ps, $COMPOSE logs api. The .env as it was before the move is .env.before-secrets"
    log "the secrets are in $SECRETS_DIR and the server reads them from there: nothing to do"
    return 0
  fi
  for name in DB_PASSWORD SECRET_KEY STORE_KEY $TOKENS; do
    [ -n "$(get "$name")" ] || die "$name is not set in $ENV_FILE: run deploy/init-env.sh first"
  done
  local target=$NIK_DIR/secrets
  log "writing the secrets of $ENV_FILE into files of $target"
  mkdir -p "$target"
  chmod 700 "$target"
  for name in $SECRETS; do
    printf '%s' "$(value_of "$name")" >"$target/$(lower "$name")"
    [ -s "$target/$(lower "$name")" ] && printf '\n' >>"$target/$(lower "$name")"
    chmod 644 "$target/$(lower "$name")"
  done
  cp "$ENV_FILE" "$NIK_DIR/.env.before-secrets"
  chmod 600 "$NIK_DIR/.env.before-secrets"
  # The new env file is written whole beside the old one and takes its place in one move.
  cp "$ENV_FILE" "$ENV_FILE.moving"
  for name in $SECRETS; do
    if grep -q "^$name=" "$ENV_FILE.moving"; then set_value "$name" "" "$ENV_FILE.moving"; fi
  done
  set_value NIK_SECRETS_DIR ./secrets "$ENV_FILE.moving"
  chmod 600 "$ENV_FILE.moving"
  mv "$ENV_FILE.moving" "$ENV_FILE"
  SECRETS_DIR=$target
  MODE=files
  if [ "$START" -eq 0 ]; then
    log "done, and the stack was not restarted (--no-start): $COMPOSE up -d starts it on the files."
    log "$NIK_DIR/.env.before-secrets holds every secret in clear: destroy it (shred -u) or lock it away once the server works."
    return 0
  fi
  log "starting the stack on the files (its containers are made again: about a minute)"
  if compose up -d && verify_files; then
    log "the server answers and reads its keys from the files."
    log "$NIK_DIR/.env.before-secrets holds every secret in clear: destroy it (shred -u) or lock it away, now that the server works."
    log "Keep a copy of $target away from this server (SECRET_KEY with the backups, STORE_KEY apart from them)."
    return 0
  fi
  log "the stack did not come up on the files: putting the .env back as it was"
  cp "$NIK_DIR/.env.before-secrets" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  compose up -d || true
  die "nothing was moved: the stack runs on its .env as before ($COMPOSE logs api says why it did not start on the files). $target can be removed."
}

back() {
  if [ "$MODE" = env ]; then
    log "the secrets of this stack are in $ENV_FILE already: nothing to do"
    return 0
  fi
  cp "$ENV_FILE" "$NIK_DIR/.env.before-back"
  chmod 600 "$NIK_DIR/.env.before-back"
  cp "$ENV_FILE" "$ENV_FILE.moving"
  for name in $SECRETS; do
    value=$(get "$name")
    if [ -n "$value" ] || grep -q "^$name=" "$ENV_FILE.moving"; then set_value "$name" "$value" "$ENV_FILE.moving"; fi
  done
  unset value
  grep -v '^NIK_SECRETS_DIR=' "$ENV_FILE.moving" >"$ENV_FILE.moving2"
  rm -f "$ENV_FILE.moving"
  chmod 600 "$ENV_FILE.moving2"
  mv "$ENV_FILE.moving2" "$ENV_FILE"
  log "the secrets are in $ENV_FILE again. $SECRETS_DIR still holds them: destroy it once the stack works (rm -r), or keep it locked away."
  if [ "$START" -eq 1 ]; then
    compose up -d
    case "$(wait_for_server)" in
      *'"ok"'*) log "the server answers." ;;
      *) die "the server does not answer yet: $COMPOSE ps, $COMPOSE logs api" ;;
    esac
  fi
}

# --------------------------------------------------------------------------- #
# rotate                                                                      #
# --------------------------------------------------------------------------- #
retire() { # NAME: the earlier key leaves the place keys are read from, into a file nothing reads
  local earlier folder file
  earlier=$(get "${1}_PREVIOUS")
  [ -n "$earlier" ] || return 0
  if [ "$MODE" = files ]; then folder=$SECRETS_DIR/retired; else folder=$NIK_DIR/secrets-retired; fi
  mkdir -p "$folder"
  chmod 700 "$folder"
  file=$folder/$(lower "$1")-until-$(date +%Y%m%d-%H%M%S)
  printf '%s\n' "$earlier" >"$file"
  chmod 600 "$file"
  unset earlier
  clear "${1}_PREVIOUS"
  RETIRED=$file
}

rotate_key() { # SECRET_KEY | STORE_KEY, and the services that hold it
  local name=$1
  shift
  local services=("$@")
  local state line
  [ -n "$(container api)" ] || die "the stack is not running: start it first ($COMPOSE up -d). A key is changed on a running server, which puts everything under the new one."
  [ -n "$(get "$name")" ] || die "$name is not set where this stack keeps its secrets: run deploy/init-env.sh first"
  state=$(in_api python -m app.key_rotation status "$name" | head -n 1)
  case "$state" in
    idle)
      if [ -n "$(get "${name}_PREVIOUS")" ]; then
        if [ "$(get "${name}_PREVIOUS")" = "$(get "$name")" ]; then
          # A run of this script stopped between its two writes: the key in use was noted as the
          # earlier one and no new key was written. Nothing changed for the server.
          clear "${name}_PREVIOUS"
        else
          die "${name}_PREVIOUS is set and the server does not read it: restart the stack ($COMPOSE up -d) and run this again"
        fi
      fi
      if asked=$(in_api python -m app.key_rotation requested "$name" 2>/dev/null); then
        log "$name: the change was $asked"
      else
        confirm "No administrator asked for $name to be changed in Nik (Settings → Keys → Rotate…)." "rotate"
      fi
      log "$name: a new key is made by the server and written where the keys are kept (it is never shown)"
      # The key in use becomes the earlier key first: whatever stops next, the server reads everything.
      put "${name}_PREVIOUS" "$(get "$name")"
      new_key | {
        IFS= read -r made
        [ "${#made}" -ge 32 ] || die "no new key was made: nothing was changed but ${name}_PREVIOUS, which holds the key in use (harmless)"
        put "$name" "$made"
      }
      log "$name: restarting ${services[*]} (the server is down for the time of a restart)"
      restart "${services[@]}"
      ;;
    running | failed) log "$name: a change is in progress ($state): going on with it" ;;
    verified) log "$name: the change is verified: taking the earlier key away" ;;
    *) die "the server did not say where the change of $name stands ($state): $COMPOSE logs api" ;;
  esac

  case "$(wait_for_server)" in
    *'"ok"'*) ;;
    *) die "the server does not answer after the restart: $COMPOSE logs api. Both keys are where the keys are kept: nothing is lost. Run this again once it answers." ;;
  esac
  log "$name: the server puts everything under the new key, then reads it back with the new key alone"
  local waited=0 last=""
  while :; do
    state=$(in_api python -m app.key_rotation status "$name" 2>/dev/null || true)
    line=$(printf '%s\n' "$state" | sed -n '2p')
    case "$(printf '%s\n' "$state" | head -n 1)" in
      verified) break ;;
      failed)
        printf '%s\n' "$state" | sed -n '2,12p' >&2
        die "$name: the server could not put everything under the new key (above; Settings → Keys has the list). The earlier key stays where it is and nothing is lost. Set right what failed, then run this again."
        ;;
    esac
    if [ "$line" != "$last" ] && [ -n "$line" ]; then
      log "  $line"
      last=$line
    fi
    waited=$((waited + 5))
    [ "$waited" -lt "$WAIT" ] || die "$name: not verified after $WAIT seconds. The earlier key stays where it is and nothing is lost: run this again later, it goes on."
    sleep 5
  done
  RETIRED=""
  retire "$name"
  log "$name: verified. Restarting ${services[*]} once more, without the earlier key"
  restart "${services[@]}"
  case "$(wait_for_server)" in
    *'"ok"'*) log "$name: the change is over and the server answers." ;;
    *) die "the server does not answer after the last restart: $COMPOSE ps, $COMPOSE logs api" ;;
  esac
  if [ -n "$RETIRED" ]; then
    log "the earlier key is in $RETIRED (nothing reads it)."
    if [ "$name" = SECRET_KEY ]; then
      log "Backups taken before now hold their secrets under it: store it with them, and destroy it (shred -u) when they are gone."
    else
      log "No backup of Nik needs it. Destroy it (shred -u), unless you keep copies of the store volume made before now."
    fi
  fi
  log "Keep a copy of the new key away from this server."
}

rotate_tokens() {
  confirm "This writes new tokens for the workers and restarts the whole stack (about a minute down)." "tokens"
  for name in $TOKENS; do
    new_key | {
      IFS= read -r made
      [ "${#made}" -ge 32 ] || die "no new token was made for $name"
      put "$name" "$made"
    }
  done
  compose up -d --force-recreate
  case "$(wait_for_server)" in
    *'"ok"'*) log "the workers have new tokens and the server answers (Settings → System → Workers shows each one)." ;;
    *) die "the server does not answer yet: $COMPOSE ps, $COMPOSE logs api" ;;
  esac
}

case "$COMMAND" in
  status) status ;;
  move) move ;;
  back) back ;;
  rotate)
    case "${ARGS[1]:-}" in
      secret-key) rotate_key SECRET_KEY api automation ;;
      store-key) rotate_key STORE_KEY api ;;
      tokens) rotate_tokens ;;
      *) die "rotate what: secret-key, store-key or tokens" ;;
    esac
    ;;
  *) die "unknown command: $COMMAND (see --help)" ;;
esac
