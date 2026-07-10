#!/bin/sh
# Runs from /docker-entrypoint.d/ before nginx starts (official-image hook).
# The 443 listener in nginx.conf always needs a certificate: use the one the
# operator mounted at /etc/nginx/certs if present, otherwise self-sign one.
# The key is generated at runtime into the certs volume — never baked into
# the image — so every deployment gets its own.
set -eu

CERT_DIR=/etc/nginx/certs
CRT="$CERT_DIR/nik.crt"
KEY="$CERT_DIR/nik.key"
HOST="${TLS_HOSTNAME:-localhost}"
DAYS="${TLS_SELFSIGNED_DAYS:-825}"

if [ -s "$CRT" ] && [ -s "$KEY" ]; then
    echo "gen-selfsigned: certificate already present at $CRT, leaving it alone" >&2
    exit 0
fi

# Browsers validate the SAN, not the CN: names need a DNS: entry, IPs an IP: one.
case "$HOST" in
    localhost) SAN="DNS:localhost,IP:127.0.0.1" ;;
    127.0.0.1) SAN="IP:127.0.0.1,DNS:localhost" ;;
    *[!0-9.]*) SAN="DNS:$HOST,DNS:localhost,IP:127.0.0.1" ;;
    *)         SAN="IP:$HOST,DNS:localhost,IP:127.0.0.1" ;;
esac

echo "gen-selfsigned: no certificate mounted, self-signing one for '$HOST' (valid $DAYS days)" >&2
mkdir -p "$CERT_DIR"
openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$KEY" -out "$CRT" -days "$DAYS" \
    -subj "/CN=$HOST" -addext "subjectAltName=$SAN"
chmod 600 "$KEY"
