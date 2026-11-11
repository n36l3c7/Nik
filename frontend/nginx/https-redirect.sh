#!/bin/sh
# Runs from /docker-entrypoint.d/ before nginx starts (official-image hook).
# Port 80 answers every request with a redirect to HTTPS. The address to
# redirect to needs the HTTPS port as published on the host (TLS_PORT, set by
# docker-compose.yml from WEB_TLS_PORT): the container only knows its own 443.
set -eu

PORT="${TLS_PORT:-443}"
case "$PORT" in
    443) SUFFIX="" ;;
    *[!0-9]* | "")
        echo "https-redirect: TLS_PORT must be a port number, got '$PORT'" >&2
        exit 1
        ;;
    *) SUFFIX=":$PORT" ;;
esac

# shellcheck disable=SC2016  # $host and $request_uri are nginx variables.
printf 'return 308 https://$host%s$request_uri;\n' "$SUFFIX" > /tmp/nik-redirect.conf
echo "https-redirect: plain HTTP redirects to https://<host>$SUFFIX" >&2
