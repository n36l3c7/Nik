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
#  - New install: every secret is generated.
#  - Existing install (an .env from before 3.0.0, possibly with secrets left
#    at their defaults): the missing ones are added. A replaced SECRET_KEY is
#    kept as SECRET_KEY_PREVIOUS, so the provider API keys and TLS key logs
#    already stored are re-encrypted at the next start instead of being lost.
#    A missing DB_PASSWORD is written as the old default, which is what the
#    existing database was created with: change it in PostgreSQL first if you
#    want another.
set -eu

ENV_FILE="${1:-$(cd "$(dirname "$0")/.." && pwd)/.env}"
EXAMPLE="$(cd "$(dirname "$0")/.." && pwd)/.env.example"
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

new_install=0
if [ ! -f "$ENV_FILE" ]; then
    new_install=1
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
    if [ "$new_install" -eq 0 ]; then
        # What the running server encrypted with: the value in the file, or the
        # old built-in default when the file had none.
        previous="${current:-$OLD_SECRET_KEY_DEFAULT}"
        set_value SECRET_KEY_PREVIOUS "$previous"
        echo "init-env: SECRET_KEY replaced; the old one is kept as SECRET_KEY_PREVIOUS so stored secrets are re-encrypted at the next start (remove it afterwards)"
    fi
    set_value SECRET_KEY "$(random)"
    changed=1
fi

current=$(value_of DB_PASSWORD)
if [ "$new_install" -eq 1 ]; then
    if is_placeholder "$current"; then
        set_value DB_PASSWORD "$(random)"
        changed=1
    fi
elif [ -z "$current" ]; then
    set_value DB_PASSWORD "$OLD_DB_PASSWORD_DEFAULT"
    echo "init-env: DB_PASSWORD was not set; written as the old default, which the existing database uses"
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
