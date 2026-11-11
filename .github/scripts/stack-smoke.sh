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
PROJECT=nik-smoke
HTTP_PORT=${SMOKE_HTTP_PORT:-18080}
TLS_PORT=${SMOKE_TLS_PORT:-18443}
ENV_FILE=$(mktemp)
COMPOSE=(docker compose -p "$PROJECT" --env-file "$ENV_FILE")

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    "${COMPOSE[@]}" ps || true
    "${COMPOSE[@]}" logs --tail 60 db api web || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$ENV_FILE"
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "FAILED: $*" >&2
  exit 1
}

# The env file an operator gets: the example, with every secret generated.
rm -f "$ENV_FILE"
deploy/init-env.sh "$ENV_FILE"
grep -Eq '^(SECRET_KEY|DB_PASSWORD|[A-Z]+_TOKEN)=(please-change|change-this)' "$ENV_FILE" &&
  fail "init-env.sh left a placeholder secret"
{
  echo "WEB_PORT=$HTTP_PORT"
  echo "WEB_TLS_PORT=$TLS_PORT"
} >>"$ENV_FILE"

# Without its secrets the stack must not even start.
if docker compose -p "$PROJECT-none" --env-file /dev/null config >/dev/null 2>&1; then
  fail "compose accepts a configuration with no secrets"
fi

"${COMPOSE[@]}" up -d --build --wait db api web

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

echo "== metrics are not published"
[ "$(get -o /dev/null -w '%{http_code}' "$base/api/metrics")" = 404 ] || fail "/api/metrics is reachable through nginx"

echo "== the first account, a Secure session cookie, and a sign-in limit counted per client"
[ "$(get -o /dev/null -w '%{http_code}' -X POST "$base/api/users" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"smoke-test-password"}')" = 201 ] || fail "first-run account"
cookie=$(get -o /dev/null -D - -X POST "$base/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"smoke-test-password"}' | tr -d '\r' | grep -i '^set-cookie:')
grep -qi 'HttpOnly' <<<"$cookie" || fail "the session cookie is not HttpOnly"
grep -qi 'Secure' <<<"$cookie" || fail "the session cookie is not Secure"
codes=""
# The limit (10 a minute) is counted by each backend process, and there are two:
# thirty attempts are over it however they are shared out.
for attempt in $(seq 1 30); do
  # A forwarded address the client makes up must not buy it a fresh allowance.
  codes+=$(get -o /dev/null -w '%{http_code} ' -X POST "$base/api/auth/login" -H "X-Forwarded-For: 198.51.100.$attempt" \
    -H 'Content-Type: application/json' -d '{"username":"nobody","password":"x"}')
done
grep -q 429 <<<"$codes" || fail "the sign-in limit can be dodged with X-Forwarded-For ($codes)"

echo "== the backend is unprivileged, on a read-only filesystem"
api_container=$("${COMPOSE[@]}" ps -q api)
status=$(docker exec "$api_container" cat /proc/1/status)
grep -q '^Uid:[[:space:]]*10001' <<<"$status" || fail "the server process is not the unprivileged user"
grep -q '^CapEff:[[:space:]]*0000000000000000' <<<"$status" || fail "the server process holds capabilities"
grep -q '^NoNewPrivs:[[:space:]]*1' <<<"$status" || fail "no-new-privileges is off"
docker exec "$api_container" sh -c 'touch /app/probe 2>/dev/null' && fail "the backend's filesystem is writable"

echo "== the image refuses the example secrets"
image=$(docker inspect --format '{{.Image}}' "$api_container")
if docker run --rm -e SECRET_KEY=please-change-this-secret "$image" true >/dev/null 2>&1; then
  fail "the backend image starts with the example SECRET_KEY"
fi

echo "stack smoke test passed"
