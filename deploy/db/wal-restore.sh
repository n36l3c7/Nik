#!/bin/sh
# The restore_command of PostgreSQL: give back one segment of the archive.
#
#   sh wal-restore.sh %f %p
#
# Asked by a server that is recovering (deploy/restore.sh --to), by a standby
# (deploy/standby.sh) and by the scratch server of the recovery test. A
# segment is looked for where this server archived it (wal/) and where the
# segments that came from another host are put once they are opened
# (incoming/). Exits 1 when it is not there: PostgreSQL asks for files that
# do not exist as a matter of course, and a standby asks again later.
set -eu

name=$1
path=$2
archive=${NIK_ARCHIVE:-/wal-archive}

for folder in "$archive/wal" "$archive/incoming"; do
  if [ -f "$folder/$name.gz" ]; then
    # Written beside its place: PostgreSQL must never read half a segment.
    if gzip -dc "$folder/$name.gz" >"$path.nik"; then
      mv "$path.nik" "$path"
      exit 0
    fi
    rm -f "$path.nik"
    echo "nik: $folder/$name.gz does not expand: the archive holds a damaged segment" >&2
    exit 1
  fi
done
exit 1
