#!/usr/bin/env bash
# Tests of deploy/init-env.sh: what it writes for a new install, for an
# existing one with an .env, and for an existing one that never had an .env.
# And that every script of deploy/ reads a value of the env file alike.
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

echo "== a new install: everything is generated, each secret into a file of its own, none into the env file"
VOLUMES="other_db-data-18 nikola_db-data" run "$work/new.env"
secrets="$work/new.env.secrets"
[ "$(value "$work/new.env" NIK_SECRETS_DIR)" = "$secrets" ] || fail "new install: the env file does not name the secrets directory"
for name in SECRET_KEY STORE_KEY AUDIT_KEY DB_PASSWORD ANALYZER_TOKEN CAPA_TOKEN DOCVIEW_TOKEN BROWSER_TOKEN PCAP_TOKEN SANDBOX_TOKEN; do
  file="$secrets/$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
  [ "$(wc -c <"$file")" -eq 65 ] || fail "new install: $name is not a 64-character random value in its file"
  grep -q "^$name=\$" "$work/new.env" || fail "new install: $name is not named, empty, in the env file"
done
[ "$(sort "$secrets"/*_token "$secrets"/*_key "$secrets"/db_password | uniq -d | grep -c .)" -eq 0 ] || fail "new install: two secrets are the same value"
for name in secret_key_previous store_key_previous audit_key_previous metrics_token; do
  [ -f "$secrets/$name" ] && [ ! -s "$secrets/$name" ] || fail "new install: $name is not an empty file"
done
[ "$(stat -c '%a' "$secrets")" = 700 ] || fail "new install: the secrets directory can be entered by others"
before=$(cat "$work/new.env" "$secrets"/*)
VOLUMES="" run "$work/new.env"
[ "$before" = "$(cat "$work/new.env" "$secrets"/*)" ] || fail "a second run changed the env file or a secret"
# A secret written into the env file of a stack that keeps its secrets in files is not taken silently.
cp "$work/new.env" "$work/both.env"
sed -i "s|^NIK_SECRETS_DIR=.*|NIK_SECRETS_DIR=$secrets|; s|^SECRET_KEY=\$|SECRET_KEY=typed-here-by-hand-0123456789|" "$work/both.env"
if PATH="$work/bin:$PATH" deploy/init-env.sh "$work/both.env" >/dev/null 2>&1; then
  fail "a secret in the env file beside a secrets directory was accepted"
fi

echo "== a new install that keeps its secrets in the env file, when asked to"
VOLUMES="" NIK_SECRETS=env run "$work/inenv.env"
for name in SECRET_KEY STORE_KEY AUDIT_KEY DB_PASSWORD ANALYZER_TOKEN CAPA_TOKEN DOCVIEW_TOKEN BROWSER_TOKEN PCAP_TOKEN SANDBOX_TOKEN; do
  [ "$(value "$work/inenv.env" "$name" | wc -c)" -eq 65 ] || fail "NIK_SECRETS=env: $name is not a 64-character random value"
done
grep -q '^NIK_SECRETS_DIR=' "$work/inenv.env" && fail "NIK_SECRETS=env: a secrets directory was named"
[ ! -e "$work/inenv.env.secrets" ] || fail "NIK_SECRETS=env: a secrets directory was made"
grep -q '^SECRET_KEY_PREVIOUS=' "$work/inenv.env" && fail "new install: a previous key was written"
before=$(cat "$work/inenv.env")
VOLUMES="" run "$work/inenv.env"
[ "$before" = "$(cat "$work/inenv.env")" ] || fail "a second run changed the file"

echo "== an existing install that never had an .env: its database and its stored secrets stay reachable"
for volumes in "nik_db-data-18" "nik_db-data"; do
  rm -f "$work/bare.env"
  VOLUMES="$volumes" run "$work/bare.env"
  [ "$(value "$work/bare.env" DB_PASSWORD)" = "nik" ] || fail "no .env, volume $volumes: DB_PASSWORD is not the old default"
  [ "$(value "$work/bare.env" SECRET_KEY_PREVIOUS)" = "please-change-this-secret" ] ||
    fail "no .env, volume $volumes: the old default key is not kept as SECRET_KEY_PREVIOUS"
  [ "$(value "$work/bare.env" SECRET_KEY | wc -c)" -eq 65 ] || fail "no .env: SECRET_KEY was not generated"
  [ "$(value "$work/bare.env" PCAP_TOKEN | wc -c)" -eq 65 ] || fail "no .env: the worker tokens were not generated"
  # An existing install keeps its secrets where they were: in the env file.
  grep -q '^NIK_SECRETS_DIR=' "$work/bare.env" && fail "no .env, volume $volumes: the secrets were moved to files"
  [ "$(value "$work/bare.env" STORE_KEY | wc -c)" -eq 65 ] || fail "no .env: STORE_KEY was not generated"
  # Its audit log is signed with the key derived from SECRET_KEY until the operator chooses otherwise.
  [ -z "$(value "$work/bare.env" AUDIT_KEY)" ] || fail "no .env, volume $volumes: an existing install was given an audit key nobody chose"
done

echo "== an existing install with a partial .env: only what is missing is written"
printf 'DB_PASSWORD=my-own-password\nSECRET_KEY=change-this-to-a-long-random-string\nANALYZER_TOKEN=kept\n' >"$work/partial.env"
VOLUMES="" run "$work/partial.env"
[ "$(value "$work/partial.env" DB_PASSWORD)" = "my-own-password" ] || fail "partial: DB_PASSWORD was changed"
[ "$(value "$work/partial.env" ANALYZER_TOKEN)" = "kept" ] || fail "partial: a token that was set was changed"
# An .env written by a release before 4.1 has no SANDBOX_TOKEN: the upgrade adds it.
[ "$(value "$work/partial.env" SANDBOX_TOKEN | wc -c)" -eq 65 ] || fail "partial: the token of a new worker was not added"
[ "$(value "$work/partial.env" SECRET_KEY_PREVIOUS)" = "change-this-to-a-long-random-string" ] ||
  fail "partial: the key that was in use is not kept as SECRET_KEY_PREVIOUS"
# An .env written by a release before 6.8 has no STORE_KEY: the upgrade adds it, there and nowhere else.
[ "$(value "$work/partial.env" STORE_KEY | wc -c)" -eq 65 ] || fail "partial: STORE_KEY was not added"
grep -q '^NIK_SECRETS_DIR=' "$work/partial.env" && fail "partial: the secrets of an existing install were moved to files"
grep -q '^STORE_KEY_PREVIOUS=' "$work/partial.env" && fail "partial: an earlier store key was written, and there never was one"
[ -z "$(value "$work/partial.env" AUDIT_KEY)" ] || fail "partial: an existing install was given an audit key nobody chose"
store_key=$(value "$work/partial.env" STORE_KEY)
VOLUMES="" run "$work/partial.env"
[ "$(value "$work/partial.env" STORE_KEY)" = "$store_key" ] || fail "partial: a second run changed STORE_KEY"
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
[ "$(wc -c <"$work/fresh.env.secrets/db_password")" -eq 65 ] || fail "NIK_EXISTING_INSTALL=0 was ignored"

echo "== a value of the env file is read alike by init-env.sh, secrets.sh and recovery-lib.sh"
mkdir "$work/stack"
cat >"$work/stack/.env" <<'EOF'
PLAIN=/srv/nik secrets
SINGLE='/srv/nik secrets'
DOUBLE="/srv/nik secrets"
HASH='with # and $ inside'
TWICE=first
TWICE='second'
EMPTY=
EOF
# The function as one script defines it, alone: the scripts themselves do their work when run.
reader() { sed -n "/^$2() *{/,/^}/p" "$1"; }
for name in PLAIN SINGLE DOUBLE HASH TWICE EMPTY ABSENT; do
  case "$name" in
    HASH) expected='with # and $ inside' ;;
    TWICE) expected=second ;;
    EMPTY | ABSENT) expected="" ;;
    *) expected="/srv/nik secrets" ;;
  esac
  from_init=$(ENV_FILE="$work/stack/.env" sh -c "$(reader deploy/init-env.sh value_of); value_of $name")
  from_secrets=$(ENV_FILE="$work/stack/.env" bash -c "$(reader deploy/secrets.sh value_of); value_of $name")
  from_recovery=$(NIK_DIR="$work/stack" ENGINE=docker bash -c ". deploy/recovery-lib.sh; env_value $name")
  [ "$from_init" = "$expected" ] || fail "init-env.sh reads $name as '$from_init'"
  [ "$from_secrets" = "$expected" ] || fail "secrets.sh reads $name as '$from_secrets'"
  [ "$from_recovery" = "$expected" ] || fail "recovery-lib.sh reads $name as '$from_recovery'"
done

echo "init-env tests passed"
