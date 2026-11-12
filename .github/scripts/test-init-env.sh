#!/usr/bin/env bash
# Tests of deploy/init-env.sh: what it writes for a new install, for an
# existing one with an .env, and for an existing one that never had an .env.
# The container engine is a stand-in that lists the volumes each case needs.
set -euo pipefail

cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
  echo "FAILED: $*" >&2
  exit 1
}
value() { sed -n "s/^$2=//p" "$1" | tail -n 1; }

# A fake `docker` (and no podman) that lists the volumes named in $VOLUMES.
mkdir "$work/bin"
cat >"$work/bin/docker" <<'EOF'
#!/bin/sh
[ "$1 $2" = "volume ls" ] && printf '%s\n' $VOLUMES
exit 0
EOF
cp "$work/bin/docker" "$work/bin/podman"
chmod +x "$work/bin/docker" "$work/bin/podman"
run() { PATH="$work/bin:$PATH" COMPOSE_PROJECT_NAME=nik deploy/init-env.sh "$@" >/dev/null; }

echo "== a new install: everything is generated"
VOLUMES="other_db-data-18 nikola_db-data" run "$work/new.env"
for name in SECRET_KEY DB_PASSWORD ANALYZER_TOKEN CAPA_TOKEN DOCVIEW_TOKEN BROWSER_TOKEN PCAP_TOKEN; do
  [ "$(value "$work/new.env" "$name" | wc -c)" -eq 65 ] || fail "new install: $name is not a 64-character random value"
done
grep -q '^SECRET_KEY_PREVIOUS=' "$work/new.env" && fail "new install: a previous key was written"
before=$(cat "$work/new.env")
VOLUMES="" run "$work/new.env"
[ "$before" = "$(cat "$work/new.env")" ] || fail "a second run changed the file"

echo "== an existing install that never had an .env: its database and its stored secrets stay reachable"
for volumes in "nik_db-data-18" "nik_db-data"; do
  rm -f "$work/bare.env"
  VOLUMES="$volumes" run "$work/bare.env"
  [ "$(value "$work/bare.env" DB_PASSWORD)" = "nik" ] || fail "no .env, volume $volumes: DB_PASSWORD is not the old default"
  [ "$(value "$work/bare.env" SECRET_KEY_PREVIOUS)" = "please-change-this-secret" ] ||
    fail "no .env, volume $volumes: the old default key is not kept as SECRET_KEY_PREVIOUS"
  [ "$(value "$work/bare.env" SECRET_KEY | wc -c)" -eq 65 ] || fail "no .env: SECRET_KEY was not generated"
  [ "$(value "$work/bare.env" PCAP_TOKEN | wc -c)" -eq 65 ] || fail "no .env: the worker tokens were not generated"
done

echo "== an existing install with a partial .env: only what is missing is written"
printf 'DB_PASSWORD=my-own-password\nSECRET_KEY=change-this-to-a-long-random-string\nANALYZER_TOKEN=kept\n' >"$work/partial.env"
VOLUMES="" run "$work/partial.env"
[ "$(value "$work/partial.env" DB_PASSWORD)" = "my-own-password" ] || fail "partial: DB_PASSWORD was changed"
[ "$(value "$work/partial.env" ANALYZER_TOKEN)" = "kept" ] || fail "partial: a token that was set was changed"
[ "$(value "$work/partial.env" SECRET_KEY_PREVIOUS)" = "change-this-to-a-long-random-string" ] ||
  fail "partial: the key that was in use is not kept as SECRET_KEY_PREVIOUS"
printf 'SECRET_KEY=%s\n' "$(printf 'k%.0s' $(seq 1 40))" >"$work/nodb.env"
VOLUMES="" run "$work/nodb.env"
[ "$(value "$work/nodb.env" DB_PASSWORD)" = "nik" ] || fail "an .env without DB_PASSWORD: not written as the old default"
grep -q '^SECRET_KEY_PREVIOUS=' "$work/nodb.env" && fail "a good SECRET_KEY was replaced"

echo "== the operator's word wins over what the script can see"
rm -f "$work/forced.env"
VOLUMES="" NIK_EXISTING_INSTALL=1 run "$work/forced.env"
[ "$(value "$work/forced.env" DB_PASSWORD)" = "nik" ] || fail "NIK_EXISTING_INSTALL=1 was ignored"
rm -f "$work/fresh.env"
VOLUMES="nik_db-data-18" NIK_EXISTING_INSTALL=0 run "$work/fresh.env"
[ "$(value "$work/fresh.env" DB_PASSWORD | wc -c)" -eq 65 ] || fail "NIK_EXISTING_INSTALL=0 was ignored"

echo "init-env tests passed"
