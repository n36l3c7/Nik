#!/bin/sh
# Put a base backup in the place of the data directory of PostgreSQL.
#
# Run by deploy/restore.sh --to and deploy/standby.sh in a container of the
# `db` service that does not start PostgreSQL (the stack is stopped):
#
#   pitr.sh prepare                       make the folders of the archive volume (a new host)
#   pitr.sh state                         what the data directory holds, and the copies kept aside
#   pitr.sh restore <folder> pitr|standby [--replace] [--no-aside]
#   pitr.sh drop-aside <name>             remove a copy kept aside
#   pitr.sh put-back <name>               put a copy kept aside back (what is there is kept aside)
#
# <folder> holds what pg_basebackup wrote: base.tar.gz, pg_wal.tar.gz and
# backup_manifest. It is a folder of base/ (a base backup of this server) or
# of restore/ (one that came from another host and was opened) in the archive
# volume.
#
# `pitr` leaves the server to replay its log to a moment and then open as a
# server of its own: NIK_TARGET_TIME names the moment (empty: to the end of
# the log). `standby` leaves it to replay for as long as log arrives.
#
# A data directory that is there is never written over. With --replace it is
# moved aside first, under a name that says when (a rename: instant, and no
# byte is copied), and it stays there until an operator removes it; when the
# disk has no room for both, the restore stops and says so, unless --no-aside
# says the old data may go.
set -eu

archive=${NIK_ARCHIVE:-/wal-archive}
data=${PGDATA:?PGDATA is not set}
parent=$(dirname "$data")
leaf=$(basename "$data")

say() { printf 'nik-recovery: %s\n' "$*" >&2; }
die() {
  say "$*"
  exit 1
}

asides() {
  for path in "$parent/$leaf".before-*; do
    [ -d "$path" ] && printf '%s %s\n' "$(basename "$path")" "$(du -sk "$path" | awk '{ print $1 }')"
  done
  return 0
}

# The room of the disk the data directory is on: asked of the nearest folder that exists (on a
# new host the volume is empty).
free_kb() {
  place=$parent
  while [ ! -d "$place" ] && [ "$place" != "/" ]; do place=$(dirname "$place"); done
  df -Pk "$place" | awk 'NR == 2 { print $4 }'
}

case "${1:-}" in
  prepare)
    sh "$(dirname "$0")/prepare-archive.sh"
    ;;

  state)
    if [ -s "$data/PG_VERSION" ]; then
      role=server
      [ -f "$data/standby.signal" ] && role=standby
      [ -f "$data/recovery.signal" ] && role=recovering
      echo "data=$role"
      echo "data_kb=$(du -sk "$data" | awk '{ print $1 }')"
    else
      echo "data=empty"
    fi
    echo "free_kb=$(free_kb)"
    asides | while read -r name size; do echo "aside=$name $size"; done
    ;;

  drop-aside)
    name=${2:-}
    case "$name" in
      "$leaf".before-[0-9]*) ;;
      *) die "that is not the name of a copy kept aside" ;;
    esac
    case "$name" in */* | *..*) die "that is not the name of a copy kept aside" ;; esac
    [ -d "$parent/$name" ] || die "there is no copy named $name"
    rm -rf "${parent:?}/$name"
    say "removed $name"
    ;;

  put-back)
    name=${2:-}
    case "$name" in
      "$leaf".before-[0-9]*) ;;
      *) die "that is not the name of a copy kept aside" ;;
    esac
    case "$name" in */* | *..*) die "that is not the name of a copy kept aside" ;; esac
    [ -d "$parent/$name" ] || die "there is no copy named $name"
    if [ -d "$data" ] && [ -n "$(ls -A "$data" 2>/dev/null)" ]; then
      kept="$parent/$leaf.before-$(date -u +%Y%m%d-%H%M%S)"
      [ ! -e "$kept" ] || die "a copy was kept aside this very second: run this again"
      mv "$data" "$kept"
      say "the database that was there is kept aside as $(basename "$kept")"
    else
      rm -rf "$data"
    fi
    mv "$parent/$name" "$data"
    sync
    say "$name is back in the place of the database"
    ;;

  restore)
    folder=${2:-}
    mode=${3:-}
    replace=0
    aside=1
    shift 3 || die "restore needs the folder of the base backup and pitr or standby"
    for option in "$@"; do
      case "$option" in
        --replace) replace=1 ;;
        --no-aside) aside=0 ;;
        *) die "unknown option: $option" ;;
      esac
    done
    case "$mode" in pitr | standby) ;; *) die "the mode is pitr or standby" ;; esac
    case "$folder" in
      "$archive"/base/base-[0-9]* | "$archive"/restore/base-[0-9]*) ;;
      *) die "the base backup is a folder of $archive/base or $archive/restore" ;;
    esac
    case "$folder" in *..*) die "the base backup is a folder of $archive/base or $archive/restore" ;; esac
    [ -f "$folder/base.tar.gz" ] && [ -f "$folder/pg_wal.tar.gz" ] ||
      die "$folder does not hold a base backup (base.tar.gz, pg_wal.tar.gz)"
    target=${NIK_TARGET_TIME:-}
    case "$target" in *[!0-9T:+.\ -]*) die "the moment is written like 2026-11-21 14:03:00+00" ;; esac

    # Both tar files are read to their end before anything is touched.
    gzip -t "$folder/base.tar.gz" "$folder/pg_wal.tar.gz" || die "the base backup in $folder is damaged: nothing was changed"

    if [ -s "$data/PG_VERSION" ]; then
      [ "$replace" -eq 1 ] || die "the data directory holds a database: nothing was changed (--replace puts the base backup in its place)"
      free=$(free_kb)
      held=$(du -sk "$data" | awk '{ print $1 }')
      if [ "$aside" -eq 1 ]; then
        # The database that comes back takes about what the one that is there takes.
        if [ "$free" -lt $((held + 262144)) ]; then
          die "the disk has $((free / 1024)) MB free and the database $((held / 1024)) MB: there is no room to keep it aside while the base backup is put back. Nothing was changed. Free some room, or run again with --no-aside (the database that is there is then removed first)"
        fi
        kept="$parent/$leaf.before-$(date -u +%Y%m%d-%H%M%S)"
        mv "$data" "$kept"
        say "the database that was there is kept aside as $(basename "$kept") ($((held / 1024)) MB)"
      else
        rm -rf "$data"
        say "the database that was there is removed (--no-aside)"
      fi
    elif [ -d "$data" ] && [ -n "$(ls -A "$data" 2>/dev/null)" ]; then
      die "the data directory is not empty and is not a database: nothing was changed"
    fi

    mkdir -p "$data"
    chmod 700 "$data"
    tar -xzf "$folder/base.tar.gz" -C "$data"
    tar -xzf "$folder/pg_wal.tar.gz" -C "$data/pg_wal"
    rm -f "$data/nik-recovery.conf" "$data/standby.signal" "$data/recovery.signal"
    if [ "$mode" = standby ]; then
      : >"$data/standby.signal"
    else
      : >"$data/recovery.signal"
      {
        [ -n "$target" ] && echo "recovery_target_time=$target"
        echo "recovery_target_action=promote"
      } >"$data/nik-recovery.conf"
    fi
    chown -R postgres:postgres "$data"
    sync
    say "the base backup of $(basename "$folder") is in place ($mode)"
    ;;

  *)
    die "usage: pitr.sh state | restore <folder> pitr|standby [--replace] [--no-aside] | drop-aside <name> | put-back <name>"
    ;;
esac
