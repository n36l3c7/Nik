#!/usr/bin/env bash
# Start the database, the backend and the web server of the Compose stack as an
# operator would, and check what only the running stack can show: the nginx
# configuration, the entrypoints, the container options, the security headers.
# The unit and end-to-end suites never start these images.
#
#   .github/scripts/stack-smoke.sh            # builds, checks, removes everything
#
# Uses its own project name, ports and env file, so it never touches a stack
# that is already running on the machine.
set -euo pipefail

cd "$(dirname "$0")/../.."
PROJECT=${SMOKE_PROJECT:-nik-smoke}
HTTP_PORT=${SMOKE_HTTP_PORT:-18080}
TLS_PORT=${SMOKE_TLS_PORT:-18443}
ENV_FILE=$(mktemp)
# The database of the test gets a limit of memory (the stack sets none for it). Git Bash on
# Windows needs the two files Compose reads in the form Compose understands there.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
LIMITS="$ENV_FILE.limits.yml"
printf '%s\n' 'services:' '  db:' '    mem_limit: 1g' >"$LIMITS"
COMPOSE=(docker compose -p "$PROJECT" --env-file "$(native "$ENV_FILE")" -f docker-compose.yml -f "$(native "$LIMITS")")

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    "${COMPOSE[@]}" ps || true
    "${COMPOSE[@]}" logs --tail 60 db recovery api web automation sandbox || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker rm -f "$PROJECT-stopped" >/dev/null 2>&1 || true
  rm -rf "$ENV_FILE" "$ENV_FILE.secrets" "$LIMITS"
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "FAILED: $*" >&2
  exit 1
}

# The env file an operator gets: the example, and every secret generated into a file of its own
# (a new install keeps no secret in the env file).
rm -f "$ENV_FILE"
NIK_EXISTING_INSTALL=0 deploy/init-env.sh "$ENV_FILE"
grep -Eq '^(SECRET_KEY|STORE_KEY|DB_PASSWORD|[A-Z]+_TOKEN)=.' "$ENV_FILE" &&
  fail "init-env.sh left a secret, or a placeholder, in the env file of a new install"
SECRETS_DIR="$ENV_FILE.secrets"
for name in db_password secret_key store_key audit_key analyzer_token capa_token docview_token browser_token pcap_token sandbox_token; do
  [ "$(wc -c <"$SECRETS_DIR/$name")" -eq 65 ] || fail "init-env.sh did not write the secret $name as a 64-character value"
done
if command -v cygpath >/dev/null 2>&1; then
  # Git Bash on Windows: the engine mounts the secrets by the path Windows knows them under.
  grep -v '^NIK_SECRETS_DIR=' "$ENV_FILE" >"$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
  echo "NIK_SECRETS_DIR=$(native "$SECRETS_DIR")" >>"$ENV_FILE"
fi
{
  echo "WEB_PORT=$HTTP_PORT"
  echo "WEB_TLS_PORT=$TLS_PORT"
} >>"$ENV_FILE"

# Without its secrets the stack must not even start.
if docker compose -p "$PROJECT-none" --env-file /dev/null config >/dev/null 2>&1; then
  fail "compose accepts a configuration with no secrets"
fi

# The recovery service is part of the server as it is shipped: without it no base backup is taken.
"${COMPOSE[@]}" up -d --build --wait db recovery api web automation sandbox

base="https://127.0.0.1:$TLS_PORT"
get() { curl -sk --max-time 20 "$@"; }

echo "== the backend answers through nginx"
[ "$(get "$base/api/health")" = '{"status":"ok"}' ] || fail "/api/health"
get "$base/api/ready" | grep -q ready || fail "/api/ready (database)"

echo "== plain HTTP only redirects, keeping the address"
location=$(curl -s --max-time 20 -o /dev/null -D - "http://127.0.0.1:$HTTP_PORT/incident/abc?x=1" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')
[ "$location" = "https://127.0.0.1:$TLS_PORT/incident/abc?x=1" ] || fail "redirect goes to '$location'"

echo "== pages carry the security headers, the API the generic ones"
page=$(get -o /dev/null -D - "$base/" | tr -d '\r')
for header in "Content-Security-Policy: default-src 'self'" "X-Content-Type-Options: nosniff" "X-Frame-Options: DENY" \
  "Strict-Transport-Security: max-age=" "Referrer-Policy: no-referrer"; do
  grep -qi "^$header" <<<"$page" || fail "the page lacks '$header'"
done
grep -qi '^Server: nginx$' <<<"$page" || fail "nginx announces its version"
api=$(get -o /dev/null -D - "$base/api/health" | tr -d '\r')
grep -qi '^X-Content-Type-Options: nosniff' <<<"$api" || fail "the API lacks nosniff"
grep -qi '^Content-Security-Policy' <<<"$api" && fail "the API carries the app's policy (it breaks /api/docs)"

echo "== the metrics answer to their scrape token only"
[ "$(get -o /dev/null -w '%{http_code}' "$base/api/metrics")" = 401 ] || fail "/api/metrics answers without a token"
[ "$(get -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer not-the-token' "$base/api/metrics")" = 401 ] ||
  fail "/api/metrics answers to a token that is not the one"

echo "== the first account, a Secure session cookie, and a sign-in limit counted per client"
[ "$(get -o /dev/null -w '%{http_code}' -X POST "$base/api/users" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"smoke-test-password"}')" = 201 ] || fail "first-run account"
cookie=$(get -o /dev/null -D - -X POST "$base/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"smoke-test-password"}' | tr -d '\r' | grep -i '^set-cookie:')
grep -qi 'HttpOnly' <<<"$cookie" || fail "the session cookie is not HttpOnly"
grep -qi 'Secure' <<<"$cookie" || fail "the session cookie is not Secure"

echo "== the automation worker is alive, unprivileged, and applies no migration"
jar=$(mktemp)
get -o /dev/null -c "$jar" -X POST "$base/api/auth/login" -H 'Content-Type: application/json'   -d '{"username":"admin","password":"smoke-test-password"}'
alive=""
for _ in $(seq 1 20); do
  alive=$(get -b "$jar" "$base/api/automation/state")
  grep -q '"workerAlive":true' <<<"$alive" && break
  sleep 2
done
grep -q '"workerAlive":true' <<<"$alive" || fail "the automation worker does not report in ($alive)"

echo "== a signed-in administrator's cookie does not open the metrics; the token made on the health page does"
[ "$(get -o /dev/null -w '%{http_code}' -b "$jar" "$base/api/metrics")" = 401 ] ||
  fail "/api/metrics answers to a session cookie"
token=$(get -b "$jar" -X POST "$base/api/health/metrics-token" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
[ -n "$token" ] || fail "no scrape token was made"
# Read whole, then searched: under pipefail a grep -q that stops at its first match cuts the pipe of
# a long answer, and the cut reads as a failure.
metrics=$(get -H "Authorization: Bearer $token" "$base/api/metrics")
grep -q '^nik_health_state{' <<<"$metrics" || fail "/api/metrics does not answer to its scrape token"

echo "== a script runs in the sandbox, which has no way out"
script=$(get -b "$jar" -X POST "$base/api/automation/scripts" -H 'Content-Type: application/json' -d '{"name":"SmokeTest"}')
script_id=$(grep -o '"id":"[0-9a-f]*"' <<<"$script" | head -n 1 | cut -d'"' -f4)
[ -n "$script_id" ] || fail "the script was not created ($script)"
tested=$(get -b "$jar" -X POST "$base/api/automation/scripts/$script_id/test" -H 'Content-Type: application/json' -d '{}')
grep -q '"passed":true' <<<"$tested" || fail "the script's test did not pass in the sandbox ($tested)"
get -b "$jar" -X POST "$base/api/automation/scripts/$script_id/versions" -H 'Content-Type: application/json' -d '{}' |
  grep -q '"version":1' || fail "the script's version was not saved"
echo "== a backup is taken, encrypted, passes its restore test, and leaves no scratch database"
[ "$(get -o /dev/null -w '%{http_code}' -b "$jar" -X PUT "$base/api/backups/passphrase" -H 'Content-Type: application/json' \
  -d '{"passphrase":"smoke-test-passphrase"}')" = 200 ] || fail "the backup passphrase was not set"
get -b "$jar" -X POST "$base/api/backups/run" | grep -q '"state":"queued"' || fail "the backup was not asked for"
backups=""
for _ in $(seq 1 40); do
  backups=$(get -b "$jar" "$base/api/backups")
  grep -Eq '"verifyState":"(passed|failed)"|"state":"failed"' <<<"$backups" && break
  sleep 3
done
grep -q '"verifyState":"passed"' <<<"$backups" || fail "the backup did not pass its restore test ($backups)"
backup_api=$("${COMPOSE[@]}" ps -q api)
docker exec "$backup_api" sh -c 'head -c 7 /app/backups/nik-*.nikbak' | grep -q NIKBAK || fail "no backup in the backup directory"
docker exec "$backup_api" sh -c 'grep -c SmokeTest /app/backups/nik-*.nikbak || true' | grep -qx 0 ||
  fail "the backup is readable without its passphrase"
[ "$("${COMPOSE[@]}" exec -T db psql -U nik -d nik -Atc "SELECT count(*) FROM pg_database WHERE datname LIKE 'nik\_scratch%'")" = 0 ] ||
  fail "the restore test left a scratch database"
# The copies off the server leave from the automation worker: it reads the backups, and cannot write one.
docker exec "$("${COMPOSE[@]}" ps -q automation)" sh -c 'ls /app/backups/*.nikbak >/dev/null && ! touch /app/backups/probe 2>/dev/null' ||
  fail "the automation worker does not see the backup directory read-only"

echo "== the log of the database is archived, and the recovery service takes a base backup"
dbsql() { "${COMPOSE[@]}" exec -T db psql -U nik -d nik -Atc "$1" | tr -d '\r'; }
[ "$(dbsql "SHOW archive_mode")" = on ] || fail "PostgreSQL does not archive its log"
dbsql "SELECT pg_switch_wal()" >/dev/null
archived=0
for _ in $(seq 1 30); do
  archived=$(dbsql "SELECT archived_count FROM pg_stat_archiver")
  [ "${archived:-0}" -gt 0 ] && break
  sleep 1
done
[ "${archived:-0}" -gt 0 ] || fail "no segment of the log reached the archive ($(dbsql "SELECT last_failed_wal FROM pg_stat_archiver"))"
[ "$(dbsql "SELECT failed_count FROM pg_stat_archiver")" = 0 ] || fail "PostgreSQL failed to archive a segment"
recovery_container=$("${COMPOSE[@]}" ps -q recovery)
docker exec "$recovery_container" sh -c 'ls /wal-archive/wal/*.gz >/dev/null' || fail "the archive volume holds no segment"
# The first base backup is asked for by the server itself, as soon as the recovery service answers.
recovery=""
for _ in $(seq 1 60); do
  recovery=$(get -b "$jar" "$base/api/recovery")
  grep -Eq '"state":"(done|failed)"' <<<"$recovery" && break
  sleep 3
done
grep -q '"state":"done"' <<<"$recovery" || fail "no base backup was taken ($recovery)"
grep -q '"verified":true' <<<"$recovery" || fail "the base backup was not checked against its manifest"
docker exec "$recovery_container" sh -c 'ls /wal-archive/base/base-*/base.tar.gz >/dev/null' || fail "no base backup in the archive volume"
# The service that runs the tools of PostgreSQL has no network, no capability and no password.
recovery_status=$(docker exec "$recovery_container" cat /proc/1/status)
grep -q '^CapEff:[[:space:]]*0000000000000000' <<<"$recovery_status" || fail "the recovery service holds capabilities"
[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$recovery_container")" = none ] || fail "the recovery service has a network"
docker exec "$recovery_container" sh -c 'test -e /run/secrets/db_password' && fail "the recovery service is given the password of the database"
docker exec "$recovery_container" sh -c 'touch /probe 2>/dev/null' && fail "the filesystem of the recovery service is writable"
rm -f "$jar"
sandbox_container=$("${COMPOSE[@]}" ps -q sandbox)
sandbox_status=$(docker exec "$sandbox_container" cat /proc/1/status)
grep -q '^Uid:[[:space:]]*10001' <<<"$sandbox_status" || fail "the sandbox is not the unprivileged user"
grep -q '^CapEff:[[:space:]]*0000000000000000' <<<"$sandbox_status" || fail "the sandbox holds capabilities"
docker exec "$sandbox_container" sh -c 'touch /opt/nik-sandbox/probe 2>/dev/null' && fail "the sandbox's filesystem is writable"
# No route outside: an address on the internet cannot even be tried.
docker exec "$sandbox_container" python3 -c "import socket; socket.create_connection(('1.1.1.1', 443), 3)" 2>/dev/null &&
  fail "the sandbox can reach the internet"
worker_container=$("${COMPOSE[@]}" ps -q automation)
worker_status=$(docker exec "$worker_container" cat /proc/1/status)
grep -q '^Uid:[[:space:]]*10001' <<<"$worker_status" || fail "the automation worker is not the unprivileged user"
grep -q '^CapEff:[[:space:]]*0000000000000000' <<<"$worker_status" || fail "the automation worker holds capabilities"
worker_log=$("${COMPOSE[@]}" logs automation 2>&1)
grep -q "bringing the database to this version" <<<"$worker_log" && fail "the automation worker applied migrations"

codes=""
# The limit (10 a minute) is counted by each backend process, and there are two:
# thirty attempts are over it however they are shared out.
for attempt in $(seq 1 30); do
  # A forwarded address the client makes up must not buy it a fresh allowance.
  codes+=$(get -o /dev/null -w '%{http_code} ' -X POST "$base/api/auth/login" -H "X-Forwarded-For: 198.51.100.$attempt" \
    -H 'Content-Type: application/json' -d '{"username":"nobody","password":"x"}')
done
grep -q 429 <<<"$codes" || fail "the sign-in limit can be dodged with X-Forwarded-For ($codes)"

echo "== no secret is in the environment of a container; each container is given only its own"
for service in db api automation sandbox web; do
  described=$(docker inspect "$("${COMPOSE[@]}" ps -q "$service")")
  for name in db_password secret_key store_key audit_key sandbox_token; do
    grep -qF "$(cat "$SECRETS_DIR/$name")" <<<"$described" && fail "the $name is in what inspect shows of $service"
  done
done
api_container=$("${COMPOSE[@]}" ps -q api)
# (Reading the environment of another process takes privileges the container itself does not have.)
docker exec --privileged -u 0 "$api_container" sh -c 'cat /proc/[0-9]*/environ | tr "\0" "\n"' >"$ENV_FILE.environ"
grep -q "^SECRET_KEY_FILE=" "$ENV_FILE.environ" || fail "the environment of the server processes could not be read"
for name in db_password secret_key store_key audit_key; do
  grep -qF "$(cat "$SECRETS_DIR/$name")" "$ENV_FILE.environ" && fail "the $name is in the environment of a server process"
done
rm -f "$ENV_FILE.environ"
docker exec "$api_container" sh -c 'test -s /run/secrets/store_key && test -s /run/secrets/secret_key' ||
  fail "the backend is not given its keys as files"
# The automation worker has a way out: it holds neither the store nor its key.
docker exec "$worker_container" sh -c 'test ! -e /run/secrets/store_key && ! grep -q " /app/samples " /proc/mounts' ||
  fail "the automation worker is given the store of files or its key"
docker exec "$sandbox_container" sh -c 'test ! -e /run/secrets/secret_key && test ! -e /run/secrets/db_password && test ! -e /run/secrets/audit_key' ||
  fail "the sandbox is given a key it has no use for"
# The two processes that write entries of the audit log sign them with the same key, a key of its
# own on a new install: with different keys each would say the entries of the other cannot be checked.
signs_api=$(docker exec "$api_container" python -m app.auditlog key | sed -n 1p)
signs_worker=$(docker exec "$worker_container" python -m app.auditlog key | sed -n 1p)
grep -q "signed with the key set-" <<<"$signs_api" || fail "the audit log is not signed with the key init-env.sh made ($signs_api)"
[ "$signs_api" = "$signs_worker" ] || fail "the backend and the automation worker do not sign the audit log with the same key"
[ "$(docker exec "$api_container" python -m app.key_rotation audit-unchecked)" = 0 ] ||
  fail "entries of the audit log cannot be checked on a new install"

echo "== the backend is unprivileged, on a read-only filesystem"
api_container=$("${COMPOSE[@]}" ps -q api)
status=$(docker exec "$api_container" cat /proc/1/status)
grep -q '^Uid:[[:space:]]*10001' <<<"$status" || fail "the server process is not the unprivileged user"
grep -q '^CapEff:[[:space:]]*0000000000000000' <<<"$status" || fail "the server process holds capabilities"
grep -q '^NoNewPrivs:[[:space:]]*1' <<<"$status" || fail "no-new-privileges is off"
docker exec "$api_container" sh -c 'touch /app/probe 2>/dev/null' && fail "the backend's filesystem is writable"

echo "== the image refuses the example secrets, and a server without its store key says so instead of starting"
image=$(docker inspect --format '{{.Image}}' "$api_container")
# A container that serves nothing (the automation worker) exits.
if docker run --rm -e NIK_SKIP_MIGRATIONS=1 -e SECRET_KEY=please-change-this-secret "$image" true >/dev/null 2>&1; then
  fail "the backend image starts with the example SECRET_KEY"
fi
# The server stays up and answers every request with what is missing.
docker run -d --name "$PROJECT-stopped" -e SECRET_KEY="$(cat "$SECRETS_DIR/secret_key")" "$image" >/dev/null
said=""
for _ in $(seq 1 20); do
  said=$(docker exec "$PROJECT-stopped" python -c "
import urllib.request, urllib.error
try:
    urllib.request.urlopen('http://127.0.0.1:8000/api/ready', timeout=3)
except urllib.error.HTTPError as error:
    print(error.code, error.read().decode())" 2>/dev/null || true)
  [ -n "$said" ] && break
  sleep 1
done
grep -q "^503 .*Nik did not start: STORE_KEY is not set" <<<"$said" ||
  fail "a server without its store key does not say so ($said)"
docker rm -f "$PROJECT-stopped" >/dev/null

echo "== the stack stops politely: every container within its time, the log handed to the archive"
dbsql "SELECT pg_switch_wal()" >/dev/null
stopped=()
for service in db recovery api web automation sandbox; do
  stopped+=("$service=$("${COMPOSE[@]}" ps -q "$service")")
done
before=$(date +%s)
"${COMPOSE[@]}" stop >/dev/null 2>&1
took=$(($(date +%s) - before))
# The times add up to under three minutes when each container uses all of its own; a stack that
# does nothing in particular stops in seconds.
[ "$took" -le 150 ] || fail "the stack took $took seconds to stop"
for entry in "${stopped[@]}"; do
  code=$(docker inspect -f '{{.State.ExitCode}}' "${entry#*=}")
  # 137 is a container the engine had to kill at the end of its time.
  [ "$code" != 137 ] || fail "the container of ${entry%%=*} did not stop in its time and was killed"
done
db_container=""
for entry in "${stopped[@]}"; do [ "${entry%%=*}" = db ] && db_container=${entry#*=}; done
left=$(docker run --rm --volumes-from "$db_container" --entrypoint sh docker.io/library/postgres:18-alpine -c \
  'ls /var/lib/postgresql/18/docker/pg_wal/archive_status 2>/dev/null | grep -c "\.ready$" || true')
[ "$left" = 0 ] || fail "PostgreSQL stopped with $left finished segment(s) it had not handed to the archive"
echo "   stopped in $took seconds"

echo "stack smoke test passed"
