#!/bin/sh
# The archive volume as its three users need it.
#
# PostgreSQL and the recovery service (the same user) own it; the backend
# (another user) leaves its requests in requests/ and puts what came from
# another host in incoming/ and restore/: those three take files from anybody,
# and only the owner of a file or of the folder removes it.
#
# Run as root by the entrypoint of the database each time it starts, and by
# deploy/db/pitr.sh before anything is opened into a volume that no database
# has started on yet (a new host).
set -eu

archive=${NIK_ARCHIVE:-/wal-archive}
[ -d "$archive" ] || exit 0
[ "$(id -u)" = "0" ] || exit 0

mkdir -p "$archive/wal" "$archive/base" "$archive/results" "$archive/requests" "$archive/incoming" "$archive/restore"
chown postgres:postgres "$archive" "$archive/wal" "$archive/base" "$archive/results" "$archive/requests"   "$archive/incoming" "$archive/restore"
chmod 755 "$archive" "$archive/wal" "$archive/base" "$archive/results"
chmod 1777 "$archive/requests" "$archive/incoming" "$archive/restore"
