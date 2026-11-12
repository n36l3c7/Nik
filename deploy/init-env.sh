#!/bin/sh
# Create or complete the .env file of the Compose stack.
#
#   deploy/init-env.sh            # the .env next to docker-compose.yml
#   deploy/init-env.sh path/.env  # another file
#
# The stack does not start without its secrets, and refuses the example values
# (they are public). This script writes what is missing, each a fresh random
# value, and leaves every setting that is already good untouched. It is safe
# to run again: a second run changes nothing.
#
# What it writes depends on whether Nik already ran here:
#
#  - New install: every secret is generated.
#  - Existing install, with or WITHOUT an .env (a stack from before 3.0.0 could
#    run on the built-in defaults, with no .env at all). Its database was
#    created with a password and its stored secrets were encrypted with a key,
#    and a fresh random value for either would lock the stack out of its own
#    data. So:
#      - a missing DB_PASSWORD is written as the old default, which is what the
#        existing database uses. To have another, change it in PostgreSQL first
#        (ALTER ROLE nik PASSWORD '…');
#      - a replaced SECRET_KEY is kept as SECRET_KEY_PREVIOUS, so the provider
#        API keys and TLS key logs already stored are re-encrypted at the next
#        start instead of being lost.
#
# An existing install is recognised by its .env, or by the database volume of
# the Compose project (docker or podman). Say so yourself when the script
# cannot see it (another user's podman, a remote engine):
#
#   NIK_EXISTING_INSTALL=1 deploy/init-env.sh     # or =0 to say it is new
set -eu

NIK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${1:-$NIK_DIR/.env}"
EXAMPLE="$NIK_DIR/.env.example"
OLD_SECRET_KEY_DEFAULT="please-change-this-secret"
OLD_DB_PASSWORD_DEFAULT="nik"

random() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    fi
}

# The value of a variable in the file ("" when absent), without quotes.
value_of() {
    sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1 | sed "s/^['\"]//; s/['\"]\$//"
}

is_placeholder() {
    case "$1" in
        "" | please-change-this* | change-this* | dev-insecure-change-me) return 0 ;;
        *) return 1 ;;
    esac
}

# Set NAME=VALUE: replace the line when the variable is there, append otherwise.
set_value() {
    if grep -q "^$1=" "$ENV_FILE"; then
        tmp="$ENV_FILE.tmp.$$"
        awk -v name="$1" -v value="$2" 'index($0, name "=") == 1 { print name "=" value; next } { print }' "$ENV_FILE" > "$tmp"
        cat "$tmp" > "$ENV_FILE"
        rm -f "$tmp"
    else
        printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
    fi
}

# True when a database volume of this Compose project exists: Nik ran here
# before, whatever the .env says. The project is named after the directory
# unless COMPOSE_PROJECT_NAME says otherwise, as Compose does.
has_database_volume() {
    project=${COMPOSE_PROJECT_NAME:-$(basename "$NIK_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')}
    for engine in podman docker; do
        command -v "$engine" >/dev/null 2>&1 || continue
        if "$engine" volume ls --format '{{.Name}}' 2>/dev/null | grep -Eq "^${project}_db-data(-18)?\$"; then
            return 0
        fi
    done
    return 1
}

had_env=1
[ -f "$ENV_FILE" ] || had_env=0

case "${NIK_EXISTING_INSTALL:-}" in
    1) existing=1 ;;
    0) existing=0 ;;
    *)
        existing=$had_env
        if [ "$existing" -eq 0 ] && has_database_volume; then
            existing=1
            echo "init-env: a database volume of this stack exists: treating this as an existing install"
        fi
        ;;
esac

if [ "$had_env" -eq 0 ]; then
    if [ -f "$EXAMPLE" ]; then
        cp "$EXAMPLE" "$ENV_FILE"
    else
        : > "$ENV_FILE"
    fi
    echo "init-env: created $ENV_FILE"
fi
chmod 600 "$ENV_FILE"

changed=0

current=$(value_of SECRET_KEY)
if is_placeholder "$current"; then
    if [ "$existing" -eq 1 ]; then
        # What the running server encrypted with: the value its .env had, or the
        # old built-in default when it had no .env (the example's placeholder,
        # just copied, was never in use).
        previous=$OLD_SECRET_KEY_DEFAULT
        if [ "$had_env" -eq 1 ] && [ -n "$current" ]; then previous=$current; fi
        set_value SECRET_KEY_PREVIOUS "$previous"
        echo "init-env: SECRET_KEY replaced; the old one is kept as SECRET_KEY_PREVIOUS so stored secrets are re-encrypted at the next start (remove it afterwards)"
    fi
    set_value SECRET_KEY "$(random)"
    changed=1
fi

current=$(value_of DB_PASSWORD)
if [ "$existing" -eq 1 ]; then
    # The existing database keeps the password it was created with.
    if [ "$had_env" -eq 0 ] || [ -z "$current" ]; then
        set_value DB_PASSWORD "$OLD_DB_PASSWORD_DEFAULT"
        echo "init-env: DB_PASSWORD written as the old default, which the existing database uses"
        changed=1
    fi
elif is_placeholder "$current"; then
    set_value DB_PASSWORD "$(random)"
    changed=1
fi

for name in ANALYZER_TOKEN CAPA_TOKEN DOCVIEW_TOKEN BROWSER_TOKEN PCAP_TOKEN; do
    if is_placeholder "$(value_of "$name")"; then
        set_value "$name" "$(random)"
        changed=1
    fi
done

if [ "$changed" -eq 1 ]; then
    echo "init-env: secrets written to $ENV_FILE (keep this file with your backups: SECRET_KEY decrypts what the database stores)"
else
    echo "init-env: $ENV_FILE already has every secret, nothing changed"
fi
