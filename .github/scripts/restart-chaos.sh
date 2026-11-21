#!/usr/bin/env bash
# Work in progress across restarts, proven on a running stack: start one of every kind of work,
# stop things at the worst moments, and check at the end that nothing was lost and nothing was
# done twice.
#
#   .github/scripts/restart-chaos.sh          # builds, runs, checks, removes everything
#
#   CHAOS_ROUNDS=11      how many rounds (each starts work, then stops something)
#   CHAOS_SEED=1234      the seed of what is stopped when: a run that failed is run again with it
#   CHAOS_PROJECT=...    the Compose project name (its own containers, volumes and networks)
#   CHAOS_KEEP=1         leave the stack up at the end, to look at it
#   CHAOS_LOGS=file      add the logs of every container to this file before they are lost
#
# What a round does: it starts playbook runs that call another system (a stub that counts every
# call, by class: one that only reads, one that may be repeated, one that may not, one that sends
# an idempotency key), a run that waits on a timer, an incident (which starts a playbook by its
# event), a file (static analysis, disassembly, capa), a capture, a mailbox, a scan of an
# address and an upload parsed in the background; a fetch runs all along. While that is in
# flight it does one of: kill the API, kill the automation worker, kill an analysis worker (the
# analyzer, capa, the capture worker, the document worker, the isolated browser, the script
# sandbox), kill the database, restart the whole stack at once, or bring the stack up again on
# rebuilt images, as an upgrade does.
#
# What must be true at the end (restart_chaos.py verify, and the database itself):
#  - every run and every job reached an end, or waited for a person who was then answered;
#  - a call that may not be repeated reached the other system once at most (plus once for each
#    "it did not happen, do it again" a person answered); a keyed call carried one key;
#  - an incident a playbook makes was made once; an event started its playbook once; an alert
#    was fetched once;
#  - no step is running with nobody holding it, no job is held or waits, nothing is half sent;
#  - the chain of the audit log verifies;
#  - the log of the database holds no error for a lease that was merely taken.
#
# It uses its own project name and publishes no port, so it never touches a stack that is
# already running on the machine. It needs about 8 GB of memory and Docker (or a Compose that
# understands the same commands).
set -euo pipefail

cd "$(dirname "$0")/../.."
PROJECT=${CHAOS_PROJECT:-restartchaos}
ROUNDS=${CHAOS_ROUNDS:-11}
SEED=${CHAOS_SEED:-$(date +%s)}
RANDOM=$SEED
SERVICES=(db api automation sandbox analyzer capa docview pcap browser)
ACTIONS=(api automation analyzer capa pcap docview browser sandbox db restart-all upgrade)

# Git Bash on Windows rewrites what looks like a path: the names inside containers are not paths
# of this machine, and the two files Compose reads are given in the form it understands.
export MSYS_NO_PATHCONV=1
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

ENV_FILE=$(mktemp)
ENV_NATIVE=$(native "$ENV_FILE")
# The database of the test gets a limit of memory too (the stack sets none for it).
LIMITS="$ENV_FILE.limits.yml"
printf '%s\n' 'services:' '  db:' '    mem_limit: 1g' >"$LIMITS"
COMPOSE=(docker compose -p "$PROJECT" --env-file "$ENV_NATIVE" -f docker-compose.yml -f "$(native "$LIMITS")")
CHAOS="$PROJECT-chaos"
done_actions=()

# The logs of the containers, added to the file CHAOS_LOGS names (a container that is made again
# takes its log with it: they are kept before that happens, and at the end).
keep_logs() {
  if [ -n "${CHAOS_LOGS:-}" ]; then
    "${COMPOSE[@]}" logs --no-color >>"$CHAOS_LOGS" 2>&1 || true
  fi
}

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "== failed (seed $SEED): the state of the stack, and the end of its logs" >&2
    "${COMPOSE[@]}" ps >&2 || true
    "${COMPOSE[@]}" logs --tail 40 api automation >&2 || true
  fi
  keep_logs
  if [ "${CHAOS_KEEP:-}" != "1" ]; then
    docker rm -f "$CHAOS" >/dev/null 2>&1 || true
    "${COMPOSE[@]}" down -v --remove-orphans --rmi local >/dev/null 2>&1 || true
    rm -rf "$ENV_FILE" "$ENV_FILE.secrets" "$LIMITS"
  fi
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "FAILED: $*" >&2
  exit 1
}

sql() { "${COMPOSE[@]}" exec -T db psql -U nik -d nik -Atc "$1" 2>/dev/null | tr -d '\r' || true; }
driver() { docker exec "$CHAOS" python /chaos/restart_chaos.py "$@"; }
pause() { sleep $((RANDOM % ($2 - $1 + 1) + $1)); }
container_of() { "${COMPOSE[@]}" ps -aq "$1" | head -n 1; }

up() {
  # Everything runs again (what was killed is started; what runs is left alone), and the two
  # services that say when they are ready are waited for.
  "${COMPOSE[@]}" up -d --no-build "${SERVICES[@]}" >/dev/null 2>&1 || true
  for _ in $(seq 1 90); do
    healthy=0
    for service in db api; do
      id=$(container_of "$service")
      [ -n "$id" ] && [ "$(docker inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null)" = healthy ] && healthy=$((healthy + 1))
    done
    [ "$healthy" -eq 2 ] && return 0
    sleep 2
  done
  fail "the stack did not come back (db and api healthy) within three minutes"
}

# ---------------------------------------------------------------------------
# The stack, small: every container with a limit, no web server, no port.
# ---------------------------------------------------------------------------
rm -f "$ENV_FILE"
NIK_EXISTING_INSTALL=0 deploy/init-env.sh "$ENV_FILE" >/dev/null
SECRETS_NATIVE=$(native "$ENV_FILE.secrets")
grep -v '^NIK_SECRETS_DIR=' "$ENV_FILE" >"$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
{
  echo "NIK_SECRETS_DIR=$SECRETS_NATIVE"
  echo "API_MEMORY=1500m"
  echo "AUTOMATION_MEMORY=512m"
  echo "SANDBOX_MEMORY=256m"
  echo "ANALYZER_MEMORY=1g"
  echo "CAPA_MEMORY=2g"
  echo "DOCVIEW_MEMORY=512m"
  echo "PCAP_MEMORY=512m"
  echo "BROWSER_MEMORY=1g"
} >>"$ENV_FILE"

echo "== restart chaos: project $PROJECT, $ROUNDS rounds, seed $SEED"
"${COMPOSE[@]}" build --quiet "${SERVICES[@]}"
"${COMPOSE[@]}" up -d --no-build "${SERVICES[@]}"
up

# The other system and the driver: one small container on the network of the stack (to reach the
# API) and on the one playbooks leave by (to be reached as the other system).
docker rm -f "$CHAOS" >/dev/null 2>&1 || true
docker run -d --name "$CHAOS" --memory 256m --network "${PROJECT}_default" --network-alias chaos \
  docker.io/library/python:3.12-slim \
  sh -c 'while [ ! -f /chaos/ready ]; do sleep 0.2; done; exec python /chaos/restart_chaos.py stub' >/dev/null
docker network connect --alias chaos "${PROJECT}_automation-egress" "$CHAOS"
docker exec "$CHAOS" mkdir -p /chaos
docker cp .github/scripts/restart_chaos.py "$CHAOS:/chaos/restart_chaos.py"
docker cp workers/pcap/tests/fixtures/phish.pcapng "$CHAOS:/chaos/phish.pcapng"
docker exec "$CHAOS" touch /chaos/ready
for _ in $(seq 1 30); do
  docker exec "$CHAOS" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8099/health', timeout=2)" 2>/dev/null && break
  sleep 1
done
driver setup

hold() {
  docker exec "$CHAOS" python -c "
import json, urllib.request
urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8099/hold', data=json.dumps({'seconds': $1}).encode(), method='POST'), timeout=5)"
}

chaos() {
  case "$1" in
    restart-all)
      echo "   restart of the whole stack at once"
      "${COMPOSE[@]}" restart "${SERVICES[@]}" >/dev/null 2>&1 || true
      ;;
    upgrade)
      echo "   up -d --build: every container made again from rebuilt images"
      keep_logs
      "${COMPOSE[@]}" up -d --build --force-recreate "${SERVICES[@]:1}" >/dev/null 2>&1 || true
      ;;
    *)
      echo "   kill -9 of $1"
      docker kill "$(container_of "$1")" >/dev/null 2>&1 || true
      ;;
  esac
  done_actions+=("$1")
}

# ---------------------------------------------------------------------------
# The rounds
# ---------------------------------------------------------------------------
# The first rounds do each thing once, in an order the seed decides; after that, anything.
order=("${ACTIONS[@]}")
for ((i = ${#order[@]} - 1; i > 0; i--)); do
  j=$((RANDOM % (i + 1)))
  swap=${order[$i]}
  order[i]=${order[$j]}
  order[j]=$swap
done

for round in $(seq 1 "$ROUNDS"); do
  action=${order[$(((round - 1) % ${#order[@]}))]}
  [ "$round" -gt "${#order[@]}" ] && action=${ACTIONS[$((RANDOM % ${#ACTIONS[@]}))]}
  echo "== round $round"
  # The other system keeps each call a few seconds: whatever is killed is killed while a call is out.
  hold $((RANDOM % 6 + 3))
  driver start "$round"
  pause 1 9
  chaos "$action"
  pause 2 8
  up
  # And, every other round, the automation worker is killed once more while the runs that
  # were taken back are in the middle of their calls.
  if [ $((round % 2)) -eq 0 ]; then
    pause 3 12
    chaos automation
    pause 1 4
    up
  fi
done

# ---------------------------------------------------------------------------
# The end: everything settles, a person answers what waits, and the checks
# ---------------------------------------------------------------------------
echo "== settling"
hold 0
up
driver settle

echo "== what the database says"
quiet=""
for _ in $(seq 1 60); do
  running=$(sql "SELECT count(*) FROM run_steps WHERE status = 'running'")
  held=$(sql "SELECT count(*) FROM work_claims WHERE state IN ('held', 'wanted')")
  jobs=$(sql "SELECT count(*) FROM artifact_jobs WHERE status IN ('queued', 'running')")
  sending=$(sql "SELECT count(*) FROM mirror_queue WHERE status = 'sending'")
  events=$(sql "SELECT count(*) FROM automation_events WHERE done = false")
  quiet="steps running: $running, work held or wanted: $held, artifact jobs: $jobs, being sent: $sending, events waiting: $events"
  [ "$running$held$jobs$sending$events" = "00000" ] && break
  sleep 3
done
echo "   $quiet"
[ "$running$held$jobs$sending$events" = "00000" ] || fail "something is still claimed, held or waiting ($quiet)"
[ "$(sql "SELECT count(*) FROM run_steps WHERE status = 'interrupted'")" = 0 ] || fail "a step still waits for a person"
[ "$(sql "SELECT count(*) FROM runs WHERE status NOT IN ('done', 'failed', 'stopped')")" = 0 ] || fail "a run has not ended"
twice=$(sql "SELECT count(*) FROM (SELECT event_key FROM runs WHERE event_key IS NOT NULL GROUP BY 1 HAVING count(*) > 1) AS twice")
[ "$twice" = 0 ] || fail "an event started the same playbook twice"

echo "== the chain of the audit log"
docker exec "$(container_of api)" python -m app.auditlog verify-audit --full || fail "the chain of the audit log does not verify"

echo "== the log of the database"
# Read whole, then searched (a grep that stops at its first match cuts the pipe of a long log).
db_log=$("${COMPOSE[@]}" logs --no-color db 2>&1 || true)
if grep -q 'leases_pkey' <<<"$db_log"; then fail "taking a lease is an error in the log of the database"; fi

echo "== what the other system saw, and what Nik holds"
driver verify

echo "restart chaos passed: seed $SEED, $ROUNDS rounds (${done_actions[*]})"
