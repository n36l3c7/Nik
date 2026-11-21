#!/bin/sh
# The archive_command of PostgreSQL: keep one finished segment of its log.
#
#   sh wal-archive.sh %p %f
#
# PostgreSQL calls this for every segment it has finished (and at least every
# archive_timeout seconds while something was written), and for the small
# files that describe a timeline or a base backup. The segment is compressed
# into the archive volume as wal/<name>.gz: written beside its place, flushed
# to the disk, then moved there, so a file of the archive is whole or absent.
#
# It never writes over a file that is there. The same segment offered again
# (PostgreSQL does that after a crash) is accepted when the content is the
# same, and refused when it is not: two servers must never archive into one
# place.
#
# Any failure exits non-zero and says why on the log of the database.
# PostgreSQL then keeps the segment and tries again: nothing is lost, but its
# own log directory grows until the archive works again, which the server
# watches and tells the administrators about.
set -eu

path=$1
name=$2
archive=${NIK_ARCHIVE:-/wal-archive}
folder=$archive/wal
target=$folder/$name.gz

if [ ! -d "$folder" ]; then
  echo "nik: the archive directory $folder is not there: $name is kept by PostgreSQL" >&2
  exit 1
fi

if [ -e "$target" ]; then
  if gzip -dc "$target" 2>/dev/null | cmp -s - "$path"; then
    exit 0
  fi
  echo "nik: $name is in the archive already with another content: it is not written over" >&2
  exit 1
fi

# A disk that is nearly full is left its last megabytes: a refused segment stays in pg_wal and
# is archived when there is room again.
free=$(df -Pk "$folder" | awk 'NR == 2 { print $4 }')
if [ "${free:-0}" -lt "${NIK_ARCHIVE_MIN_FREE_KB:-65536}" ]; then
  echo "nik: the archive volume has ${free:-0} KB free: $name is kept by PostgreSQL until there is room" >&2
  exit 1
fi

part=$folder/.$name.$$.part
trap 'rm -f "$part"' EXIT
gzip -1 -c "$path" >"$part"
chmod 644 "$part"
sync "$part"
mv "$part" "$target"
sync "$folder"
