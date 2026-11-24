#!/bin/sh
# Create or complete the settings and the secrets of the Compose stack.
#
#   deploy/init-env.sh            # the .env next to docker-compose.yml
#   deploy/init-env.sh path/.env  # another file
#
# The stack does not start without its secrets, and refuses the example values
# (they are public). This script writes what is missing, each a fresh random
# value, and leaves every setting that is already good untouched. It is safe
# to run again: a second run changes nothing. It never prints a secret.
#
# Where the secrets go:
#
#  - New install: into files, one for each secret, in a directory only you can
#    enter (./secrets beside docker-compose.yml; <file>.secrets beside another
#    env file). The .env names that directory (NIK_SECRETS_DIR) and holds no
#    secret. Each container is given the files it uses and no other, and a
#    secret is then not in the environment of any container. To have them in
#    the .env instead, as before 6.8: NIK_SECRETS=env deploy/init-env.sh
#  - A stack whose .env names a secrets directory: into that directory.
#  - Existing install whose secrets are in its .env: they stay there, and what
#    is missing is added there (6.8 adds STORE_KEY). deploy/secrets.sh move
#    takes them out of the .env when you choose to.
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
#    STORE_KEY is new in 6.8 and nothing was ever written under an earlier one:
#    it is generated. Every file of the store is sealed under it from the next
#    start on. It is in no backup: keep a copy of it away from the server.
#    AUDIT_KEY (the key that signs the audit log) is generated on a new
#    install only. An existing install keeps signing with the key derived
#    from its SECRET_KEY until you give the log a key of its own:
#    deploy/secrets.sh rotate audit-key. Nothing is lost either way.
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
TOKENS="ANALYZER_TOKEN CAPA_TOKEN DOCVIEW_TOKEN BROWSER_TOKEN PCAP_TOKEN SANDBOX_TOKEN FORENSICS_TOKEN"
# Every secret of the stack; those after the tokens are empty unless something fills them
# (AUDIT_KEY is filled here on a new install, and by deploy/secrets.sh rotate audit-key).
SECRETS="DB_PASSWORD SECRET_KEY STORE_KEY $TOKENS SECRET_KEY_PREVIOUS STORE_KEY_PREVIOUS METRICS_TOKEN AUDIT_KEY AUDIT_KEY_PREVIOUS"

random() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    fi
}

# The value of a variable in the env file ("" when absent), without quotes.
value_of() {
    sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1 | sed "s/^['\"]//; s/['\"]\$//"
}

is_placeholder() {
    case "$1" in
        "" | please-change-this* | change-this* | dev-insecure-change-me) return 0 ;;
        *) return 1 ;;
    esac
}

# Set NAME=VALUE in the env file: replace the line when the variable is there,
# append otherwise. The value goes through the environment of awk, never
# through its arguments, which every user of the host can read.
set_value() {
    if grep -q "^$1=" "$ENV_FILE"; then
        tmp="$ENV_FILE.tmp.$$"
        NIK_VALUE="$2" awk -v name="$1" \
            'index($0, name "=") == 1 { print name "=" ENVIRON["NIK_VALUE"]; next } { print }' "$ENV_FILE" > "$tmp"
        cat "$tmp" > "$ENV_FILE"
        rm -f "$tmp"
    else
        printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
    fi
}

file_of() {
    printf '%s/%s' "$SECRETS_DIR" "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
}

# The secret NAME, from where this stack keeps its secrets.
get() {
    if [ "$mode" = files ]; then
        if [ -f "$(file_of "$1")" ]; then tr -d '\r\n' < "$(file_of "$1")"; fi
    else
        value_of "$1"
    fi
}

# Write the secret NAME where this stack keeps its secrets.
put() {
    if [ "$mode" = files ]; then
        printf '%s\n' "$2" > "$(file_of "$1")"
        chmod 644 "$(file_of "$1")"
    else
        set_value "$1" "$2"
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

# Where the secrets of this stack are kept.
named=$(value_of NIK_SECRETS_DIR)
if [ -n "$named" ]; then
    mode=files
elif [ "$existing" -eq 0 ] && [ "${NIK_SECRETS:-files}" != "env" ]; then
    mode=files
    if [ "$(cd "$(dirname "$ENV_FILE")" && pwd)/$(basename "$ENV_FILE")" = "$NIK_DIR/.env" ]; then
        named=./secrets
    else
        named="$(cd "$(dirname "$ENV_FILE")" && pwd)/$(basename "$ENV_FILE").secrets"
    fi
    set_value NIK_SECRETS_DIR "$named"
else
    mode="env"
fi

if [ "$mode" = files ]; then
    case "$named" in
        /* | ?:*) SECRETS_DIR=$named ;;
        *) SECRETS_DIR="$NIK_DIR/${named#./}" ;;
    esac
    mkdir -p "$SECRETS_DIR"
    # Only who runs the stack enters the directory. The files in it are readable by the users the
    # containers run as (each container is given only its own): what protects them is the directory.
    chmod 700 "$SECRETS_DIR"
    for name in $SECRETS; do
        [ -f "$(file_of "$name")" ] || : > "$(file_of "$name")"
        chmod 644 "$(file_of "$name")"
        # In the .env the variable stays, empty: Compose asks for it by name, the value is in its file.
        if [ -n "$(value_of "$name")" ] && ! is_placeholder "$(value_of "$name")"; then
            echo "init-env: $name is in $ENV_FILE and the secrets are kept in $SECRETS_DIR: run deploy/secrets.sh move, which takes the values out of the env file" >&2
            exit 1
        fi
        case "$name" in
            *_PREVIOUS | METRICS_TOKEN | AUDIT_KEY) grep -q "^$name=" "$ENV_FILE" && set_value "$name" "" ;;
            *) set_value "$name" "" ;;
        esac
    done
fi

changed=0

current=$(get SECRET_KEY)
if is_placeholder "$current"; then
    if [ "$existing" -eq 1 ]; then
        # What the running server encrypted with: the value its .env had, or the
        # old built-in default when it had no .env (the example's placeholder,
        # just copied, was never in use).
        previous=$OLD_SECRET_KEY_DEFAULT
        if [ "$had_env" -eq 1 ] && [ -n "$current" ]; then previous=$current; fi
        put SECRET_KEY_PREVIOUS "$previous"
        echo "init-env: SECRET_KEY replaced; the old one is kept as SECRET_KEY_PREVIOUS so stored secrets are re-encrypted at the next start (Settings → Keys says when it can go)"
    fi
    put SECRET_KEY "$(random)"
    changed=1
fi

current=$(get DB_PASSWORD)
if [ "$existing" -eq 1 ]; then
    # The existing database keeps the password it was created with.
    if [ "$had_env" -eq 0 ] || [ -z "$current" ]; then
        put DB_PASSWORD "$OLD_DB_PASSWORD_DEFAULT"
        echo "init-env: DB_PASSWORD written as the old default, which the existing database uses"
        changed=1
    fi
elif is_placeholder "$current"; then
    put DB_PASSWORD "$(random)"
    changed=1
fi

if is_placeholder "$(get STORE_KEY)"; then
    put STORE_KEY "$(random)"
    changed=1
    if [ "$existing" -eq 1 ]; then
        echo "init-env: STORE_KEY written: from the next start every file of the store is sealed under it, and the files that are there are sealed one after the other (Settings → Storage shows how far). It is in no backup: keep a copy of it away from this server"
    fi
fi

# The key that signs the audit log. A new install gets its own. An existing one signs with the
# key derived from its SECRET_KEY, and a key written here would start signing without anybody
# having chosen it: deploy/secrets.sh rotate audit-key is how it is given one.
if [ "$existing" -eq 0 ] && [ -z "$(get AUDIT_KEY)" ]; then
    put AUDIT_KEY "$(random)"
    changed=1
fi

for name in $TOKENS; do
    if is_placeholder "$(get "$name")"; then
        put "$name" "$(random)"
        changed=1
    fi
done

if [ "$mode" = files ]; then
    where="$SECRETS_DIR (a file for each; $ENV_FILE names the directory and holds no secret)"
else
    where="$ENV_FILE"
fi
if [ "$changed" -eq 1 ]; then
    echo "init-env: secrets written to $where. Keep a copy away from this server: SECRET_KEY decrypts what the database stores (keep it with the backups), AUDIT_KEY signs the audit log (keep it where that copy of SECRET_KEY is), STORE_KEY opens the files of the store (keep it apart from them)"
else
    echo "init-env: $where already has every secret, nothing changed"
fi
if [ "$mode" = env ] && [ "$existing" -eq 1 ]; then
    echo "init-env: the secrets of this stack are in $ENV_FILE, so in the environment of its containers. deploy/secrets.sh move puts them in files when you choose to"
fi
