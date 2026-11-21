#!/bin/sh
# The `recovery` service: the tools of PostgreSQL, run for the server.
#
# The backend has no PostgreSQL client and no way to run one; the tools that
# make a physical copy of the database and replay its log are in the image of
# the database. This container is that image with this script: it does three
# things when the backend asks, and nothing by itself.
#
#   base-<label>.req    take a base backup (pg_basebackup) into base/<label>/
#   test-<id>.req       prove the archive: bring the base backup named in the
#                       request up as a scratch server inside this container,
#                       replay the log to the moment named, say what it holds
#   prune-<id>.req      remove the segments and the base backups named
#
# A request is a file the backend writes in requests/ of the archive volume;
# the answer is <name>.result in results/, lines of key=value. Nothing else
# passes between the two: this container has no network port and takes no
# command. It reaches the database through its socket, on a volume the two
# share, and so needs no password.
#
# The scratch server of the recovery test lives in scratch/ of the archive
# volume and listens on a socket in /tmp of this container only. It never
# archives anything and never sees the data directory of the database, which
# this container does not mount.
set -u

archive=${NIK_ARCHIVE:-/wal-archive}
socket=${NIK_DB_SOCKET:-/var/run/postgresql}
user=${POSTGRES_USER:-nik}
database=${POSTGRES_DB:-nik}
every=${NIK_AGENT_EVERY:-5}
lib=$(cd "$(dirname "$0")" && pwd)
scratch=$archive/scratch
scratch_socket=/tmp/nik-scratch

say() { printf 'nik-recovery: %s\n' "$*" >&2; }

# One line of at most 600 characters out of whatever a tool printed.
one_line() { tr '\n\r' '  ' | cut -c1-600; }

result() { # $1 = name of the request, then the lines of the answer
  name=$1
  shift
  part=$archive/results/.$name.part
  : >"$part"
  for line in "$@"; do printf '%s\n' "$line" >>"$part"; done
  chmod 644 "$part"
  mv "$part" "$archive/results/$name.result"
}

free_kb() { df -Pk "$1" | awk 'NR == 2 { print $4 }'; }

before() { # whether $1 sorts before $2, as text
  awk -v a="$1" -v b="$2" 'BEGIN { exit !((a "") < (b "")) }'
}

# --------------------------------------------------------------------------- #
# A base backup                                                               #
# --------------------------------------------------------------------------- #
take_base() {
  label=$1
  out=$archive/base/$label
  part=$out.partial
  log=$archive/results/.$label.log
  if [ -d "$out" ]; then
    result "$label" "state=ok" "bytes=$(du -sk "$out" | awk '{ print $1 * 1024 }')" "seconds=0" "verified=1"
    return
  fi
  rm -rf "$part"
  started=$(date +%s)
  say "taking the base backup $label"
  # Two tar files (the data, and the log written while it was copied) and the manifest that
  # lists every file with its checksum; a checkpoint is asked for at once instead of waited for.
  if pg_basebackup -h "$socket" -U "$user" -D "$part" -Ft -z -Z 1 -X stream -c fast -l "$label" >"$log" 2>&1 &&
    pg_verifybackup -n -q "$part" >>"$log" 2>&1; then
    chmod 755 "$part"
    chmod 644 "$part"/*
    bytes=$(du -sk "$part" | awk '{ print $1 * 1024 }')
    mv "$part" "$out"
    sync "$archive/base"
    result "$label" "state=ok" "bytes=$bytes" "seconds=$(($(date +%s) - started))" "verified=1"
    say "the base backup $label is taken and checked against its manifest ($bytes bytes)"
  else
    error=$(tail -c 800 "$log" | one_line)
    rm -rf "$part"
    result "$label" "state=failed" "error=${error:-pg_basebackup failed and said nothing}"
    say "the base backup $label failed: $error"
  fi
  rm -f "$log"
}

# --------------------------------------------------------------------------- #
# The recovery test                                                           #
# --------------------------------------------------------------------------- #
ask() { psql -h "$scratch_socket" -p 5499 -U "$user" -d "$database" -AtX -c "$1" 2>/dev/null; }

stop_scratch() {
  if [ -f "$scratch/data/postmaster.pid" ]; then
    pg_ctl -D "$scratch/data" -m immediate -w -t 30 stop >/dev/null 2>&1 || true
  fi
  rm -rf "$scratch" "$scratch_socket"
}

test_recovery() {
  id=$1
  request=$2
  base=$(sed -n 's/^base=//p' "$request" | head -n 1)
  target=$(sed -n 's/^target=//p' "$request" | head -n 1)
  wait=$(sed -n 's/^wait=//p' "$request" | head -n 1)
  case "$base" in base-[0-9]*) ;; *) base="" ;; esac
  case "$base" in */* | *..*) base="" ;; esac
  case "$target" in *[!0-9T:+.\ -]* | "") target="" ;; esac
  case "$wait" in *[!0-9]* | "") wait=600 ;; esac
  source=$archive/base/$base
  if [ -z "$base" ] || [ -z "$target" ] || [ ! -f "$source/base.tar.gz" ]; then
    result "test-$id" "state=failed" "error=the request names no base backup of this archive, or no moment"
    return
  fi
  started=$(date +%s)
  deadline=$((started + wait))
  stop_scratch
  # The scratch server needs the data expanded and the log it replays: refused before it starts
  # rather than filling the volume the archive lives on.
  packed=$(du -sk "$source" | awk '{ print $1 }')
  need=$((packed * 12 + 262144))
  free=$(free_kb "$archive")
  if [ "${free:-0}" -lt "$need" ]; then
    result "test-$id" "state=failed" "error=the archive volume has ${free:-0} KB free and the test needs about $need KB"
    return
  fi
  say "recovery test $id: $base replayed to $target"
  mkdir -p "$scratch/data" "$scratch_socket"
  chmod 700 "$scratch/data"
  if ! { tar -xzf "$source/base.tar.gz" -C "$scratch/data" && tar -xzf "$source/pg_wal.tar.gz" -C "$scratch/data/pg_wal"; } 2>"$scratch/expand.log"; then
    error=$(one_line <"$scratch/expand.log")
    stop_scratch
    result "test-$id" "state=failed" "error=the base backup $base does not expand: $error"
    return
  fi
  : >"$scratch/data/standby.signal"
  # The last word on every setting: this server replays to the moment and waits there, read-only,
  # listens on a socket of this container alone, and archives nothing.
  cat >>"$scratch/data/postgresql.auto.conf" <<EOF
restore_command = 'sh $lib/wal-restore.sh %f %p'
recovery_target_time = '$target'
recovery_target_action = 'pause'
hot_standby = on
archive_mode = off
listen_addresses = ''
unix_socket_directories = '$scratch_socket'
port = 5499
shared_buffers = 32MB
logging_collector = off
EOF
  if ! pg_ctl -D "$scratch/data" -l "$scratch/log" -w -t "$wait" start >/dev/null 2>&1; then
    error=$(tail -c 800 "$scratch/log" 2>/dev/null | one_line)
    stop_scratch
    result "test-$id" "state=failed" "error=the scratch server did not start: $error"
    return
  fi
  reached=0
  position=""
  moved=$(date +%s)
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ "$(ask 'select pg_get_wal_replay_pause_state()')" = "paused" ]; then
      reached=1
      break
    fi
    # A replay that stands still has read all the archive holds: a segment is missing, or the
    # archive ends before the moment. It is not waited for to the end of the time allowed.
    now_at=$(ask 'select pg_last_wal_replay_lsn()')
    if [ "$now_at" != "$position" ]; then
      position=$now_at
      moved=$(date +%s)
    elif [ $(($(date +%s) - moved)) -ge "${NIK_TEST_STALL:-90}" ]; then
      break
    fi
    sleep 2
  done
  replayed=$(ask "select coalesce(extract(epoch from pg_last_xact_replay_timestamp())::text, '')")
  revision=$(ask "select version_num from alembic_version limit 1")
  audit_seq=$(ask "select seq from audit_chain where id = 1")
  audit_hash=$(ask "select hash from audit_chain where id = 1")
  stop_scratch
  seconds=$(($(date +%s) - started))
  if [ "$reached" -eq 1 ]; then
    result "test-$id" "state=ok" "base=$base" "target=$target" "replayed=$replayed" "revision=$revision" \
      "audit_seq=$audit_seq" "audit_hash=$audit_hash" "seconds=$seconds"
    say "recovery test $id: the moment was reached in $seconds seconds"
  else
    result "test-$id" "state=failed" "base=$base" "target=$target" "replayed=$replayed" "seconds=$seconds" \
      "error=the archive does not reach the moment asked for: the log was replayed up to what it holds and stopped short"
    say "recovery test $id: the archive does not reach $target"
  fi
}

# --------------------------------------------------------------------------- #
# Removing what the retention no longer keeps                                 #
# --------------------------------------------------------------------------- #
prune() {
  id=$1
  request=$2
  limit=$(sed -n 's/^wal_before=//p' "$request" | head -n 1)
  case "$limit" in *[!0-9A-F]*) limit="" ;; esac
  segments=0
  bases=0
  if [ "${#limit}" -eq 24 ]; then
    for path in "$archive"/wal/*.gz; do
      [ -f "$path" ] || continue
      name=$(basename "$path" .gz)
      # A segment, or the small file a base backup leaves beside its first segment. The files
      # that describe a timeline (<number>.history) are kept for ever: a recovery reads them all.
      case "$name" in
        [0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]????????????????*) ;;
        *) continue ;;
      esac
      if before "$(printf '%s' "$name" | cut -c1-24)" "$limit"; then
        rm -f "$path" && segments=$((segments + 1))
      fi
    done
  fi
  if grep -q '^keep=' "$request"; then
    for path in "$archive"/base/base-*; do
      [ -d "$path" ] || continue
      label=$(basename "$path")
      case "$label" in *.partial) continue ;; esac
      if ! grep -qx "keep=$label" "$request"; then
        rm -rf "$path" && bases=$((bases + 1))
      fi
    done
  fi
  result "prune-$id" "state=ok" "segments=$segments" "bases=$bases"
}

# --------------------------------------------------------------------------- #
# The loop                                                                    #
# --------------------------------------------------------------------------- #
# The backend reads from this file that the service is there. Written by a loop of its own:
# a base backup or a test may take a long while, and the service is there all along.
(
  while :; do
    if [ -d "$archive/results" ]; then
      date +%s >"$archive/results/.alive.part" 2>/dev/null && mv "$archive/results/.alive.part" "$archive/results/alive"
    fi
    sleep 5
  done
) &
beat=$!
trap 'kill "$beat" 2>/dev/null; stop_scratch; exit 0' TERM INT

if [ ! -d "$archive/requests" ] || [ ! -d "$archive/results" ]; then
  say "the archive volume is not prepared (the database container does that when it starts): waiting"
fi
# What a run that was killed left behind.
rm -rf "$archive"/base/*.partial "$scratch" 2>/dev/null
find "$archive/wal" -name '.*.part' -mmin +10 -exec rm -f {} + 2>/dev/null
say "ready: requests are read from $archive/requests"

while :; do
  # Answers nobody reads any more.
  find "$archive/results" -name '*.result' -mtime +7 -exec rm -f {} + 2>/dev/null
  for request in "$archive"/requests/*.req; do
    [ -f "$request" ] || continue
    name=$(basename "$request" .req)
    case "$name" in
      *[!a-z0-9-]*) rm -f "$request" ;;
      base-[0-9]*)
        take_base "$name"
        rm -f "$request"
        ;;
      test-*)
        test_recovery "${name#test-}" "$request"
        rm -f "$request"
        ;;
      prune-*)
        prune "${name#prune-}" "$request"
        rm -f "$request"
        ;;
      *) rm -f "$request" ;;
    esac
  done
  sleep "$every" &
  wait $!
done
