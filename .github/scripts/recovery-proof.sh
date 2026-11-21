#!/usr/bin/env bash
# Prove, on a real PostgreSQL 18, what the unit tests of the recovery cannot:
# the scripts of deploy/db. A database is started as the stack starts it
# (deploy/db-entrypoint.sh), with the recovery service beside it, and then:
#
#   1. the log is archived, a segment closed by the timer is small once
#      compressed, and a segment is never written over;
#   2. a base backup is taken and checked against its manifest;
#   3. the recovery test replays to a named moment: what was written before
#      it is there, what was written after is not;
#   4. the same test fails, and soon, when a segment is removed from the archive;
#   5. the retention removes the log before a segment and nothing else;
#   6. the base backup is put in the place of the data directory and the
#      database comes back at the moment asked for (deploy/db/pitr.sh), the
#      one that was there kept aside.
#
#   .github/scripts/recovery-proof.sh         # builds nothing; removes everything it started
#
# Its own container and volume names, a memory limit on each container. It is
# not run by the workflows: the service containers of CI cannot share a volume
# with a second container of the same image.
set -euo pipefail

cd "$(dirname "$0")/../.."
ENGINE=${ENGINE:-docker}
NAME=${PROOF_NAME:-nikproof-recovery}
IMAGE=docker.io/library/postgres:18-alpine
export MSYS_NO_PATHCONV=1
TREE=$(pwd -W 2>/dev/null || pwd)

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    "$ENGINE" logs --tail 30 "$NAME-db" 2>&1 || true
    "$ENGINE" logs --tail 30 "$NAME-agent" 2>&1 || true
  fi
  "$ENGINE" rm -f "$NAME-db" "$NAME-agent" >/dev/null 2>&1 || true
  "$ENGINE" volume rm "$NAME-data" "$NAME-archive" "$NAME-socket" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "FAILED: $*" >&2
  exit 1
}

volumes=(-v "$NAME-data:/var/lib/postgresql" -v "$NAME-archive:/wal-archive" -v "$NAME-socket:/var/run/postgresql"
  -v "$TREE/deploy/db-entrypoint.sh:/usr/local/bin/nik-db-entrypoint.sh:ro" -v "$TREE/deploy/db:/usr/local/lib/nik:ro")

start_db() {
  "$ENGINE" run -d --name "$NAME-db" --memory 1g -e POSTGRES_USER=nik -e POSTGRES_PASSWORD=proof -e POSTGRES_DB=nik \
    -e NIK_ARCHIVE_TIMEOUT=10 "${volumes[@]}" --entrypoint /usr/local/bin/nik-db-entrypoint.sh "$IMAGE" postgres >/dev/null
}
ready() {
  for _ in $(seq 1 60); do
    if "$ENGINE" exec "$NAME-db" pg_isready -U nik -d nik >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "the database did not start"
}
q() { "$ENGINE" exec "$NAME-db" psql -U nik -d nik -AtX -c "$1"; }
ask() { # $1 = name of the request, $2 = its lines; waits for the answer and prints it
  "$ENGINE" exec -u 10001 "$NAME-db" sh -c "printf '%b' '$2' > /wal-archive/requests/$1.req"
  for _ in $(seq 1 "${3:-120}"); do
    if "$ENGINE" exec "$NAME-db" test -f "/wal-archive/results/$1.result"; then
      "$ENGINE" exec "$NAME-db" cat "/wal-archive/results/$1.result"
      return 0
    fi
    sleep 1
  done
  fail "the recovery service did not answer $1"
}

start_db
# The first start creates the database, stops PostgreSQL and starts it again: ready is the second time.
for _ in $(seq 1 60); do
  if "$ENGINE" logs "$NAME-db" 2>&1 | grep -q "PostgreSQL init process complete"; then break; fi
  sleep 1
done
sleep 2
ready
"$ENGINE" run -d --name "$NAME-agent" --memory 1g --network none --user postgres --read-only --tmpfs /tmp --cap-drop ALL \
  -e POSTGRES_USER=nik -e POSTGRES_DB=nik -e NIK_AGENT_EVERY=1 -e NIK_TEST_STALL=20 \
  -v "$NAME-archive:/wal-archive" -v "$NAME-socket:/var/run/postgresql" -v "$TREE/deploy/db:/usr/local/lib/nik:ro" \
  --entrypoint sh "$IMAGE" /usr/local/lib/nik/recovery-agent.sh >/dev/null

[ "$(q 'show archive_mode')" = "on" ] || fail "the entrypoint did not turn the archive on"
q "create table alembic_version(version_num text); insert into alembic_version values ('proof');
   create table audit_chain(id int primary key, seq bigint, hash text); insert into audit_chain values (1, 1, 'one');
   create table work(id serial, note text)" >/dev/null
q "insert into work(note) select repeat('x', 400) from generate_series(1, 5000)" >/dev/null

echo "2. a base backup"
answer=$(ask base-20260101-000001 "")
case "$answer" in *state=ok*verified=1*) ;; *) fail "the base backup: $answer" ;; esac

echo "3. the recovery test to a moment"
q "update audit_chain set seq = 2, hash = 'two'; insert into work(note) values ('before the moment')" >/dev/null
sleep 2
moment=$(q "select now()")
sleep 2
q "update audit_chain set seq = 3, hash = 'three'; insert into work(note) values ('after the moment')" >/dev/null
q "select pg_switch_wal()" >/dev/null
sleep 3
q "insert into work(note) values ('later')" >/dev/null
q "select pg_switch_wal()" >/dev/null
sleep 3
answer=$(ask test-one "base=base-20260101-000001\ntarget=$moment\nwait=120\n")
case "$answer" in *state=ok*audit_seq=2*audit_hash=two*) ;; *) fail "the recovery test did not find the moment: $answer" ;; esac

echo "1. the archive"
sleep 12 # one more segment, closed by the timer
"$ENGINE" exec "$NAME-db" sh -c 'ls /wal-archive/wal' >/dev/null
small=$("$ENGINE" exec "$NAME-db" sh -c 'ls -S /wal-archive/wal/*.gz | tail -n 1 | xargs wc -c | cut -d" " -f1')
[ "$small" -lt 200000 ] || fail "a segment closed by the timer takes $small bytes once compressed"
[ "$(q 'select failed_count from pg_stat_archiver')" = "0" ] || fail "the archiver failed"
first=$("$ENGINE" exec "$NAME-db" sh -c 'ls /wal-archive/wal | grep -E "^[0-9A-F]{24}\.gz$" | head -n 1')
if "$ENGINE" exec -u postgres "$NAME-db" sh -c "echo other > /tmp/other && sh /usr/local/lib/nik/wal-archive.sh /tmp/other ${first%.gz}" 2>/dev/null; then
  fail "a segment of the archive was written over"
fi

echo "4. the recovery test on a broken archive"
for _ in 1 2 3; do
  q "insert into work(note) values ('more'); select pg_switch_wal()" >/dev/null
  sleep 2
done
last=$("$ENGINE" exec "$NAME-db" sh -c 'ls /wal-archive/wal | grep -E "^[0-9A-F]{24}\.gz$" | tail -n 2 | head -n 1')
"$ENGINE" exec "$NAME-db" sh -c "mv /wal-archive/wal/$last /wal-archive/$last.aside"
started=$(date +%s)
answer=$(ask test-two "base=base-20260101-000001\ntarget=$(q 'select now()')\nwait=300\n" 200)
case "$answer" in *state=failed*"does not reach the moment"*) ;; *) fail "the test passed on a broken archive: $answer" ;; esac
[ $(($(date +%s) - started)) -lt 120 ] || fail "the test on a broken archive took too long"
"$ENGINE" exec "$NAME-db" sh -c "mv /wal-archive/$last.aside /wal-archive/wal/$last"

echo "6. the base backup in the place of the database, replayed to the moment"
"$ENGINE" rm -f "$NAME-db" >/dev/null
tool=("$ENGINE" run --rm --memory 1g -e NIK_TARGET_TIME "${volumes[@]}" --entrypoint sh "$IMAGE" /usr/local/lib/nik/pitr.sh)
if "${tool[@]}" restore /wal-archive/base/base-20260101-000001 pitr 2>/dev/null; then
  fail "a database that is there was written over without --replace"
fi
NIK_TARGET_TIME="$moment" "${tool[@]}" restore /wal-archive/base/base-20260101-000001 pitr --replace
"${tool[@]}" state | grep -q '^aside=' || fail "the database that was there was not kept aside"
start_db
for _ in $(seq 1 90); do
  [ "$(q 'select pg_is_in_recovery()' 2>/dev/null || true)" = "f" ] && break
  sleep 1
done
[ "$(q 'select pg_is_in_recovery()')" = "f" ] || fail "the database did not finish its replay"
[ "$(q "select count(*) from work where note = 'before the moment'")" = "1" ] || fail "what was written before the moment is missing"
[ "$(q "select count(*) from work where note in ('after the moment', 'later')")" = "0" ] || fail "what was written after the moment is there"
[ "$(q 'select seq from audit_chain')" = "2" ] || fail "the head of the audit log is not the one of the moment"
[ "$(q 'select timeline_id from pg_control_checkpoint()')" = "2" ] || fail "the recovered database is not on a new timeline"

echo "5. the retention"
q "insert into work(note) values ('on the new timeline')" >/dev/null
q "select pg_switch_wal()" >/dev/null
sleep 5
keep=$("$ENGINE" exec "$NAME-db" sh -c 'ls /wal-archive/wal | grep -E "^00000002[0-9A-F]{16}\.gz$" | head -n 1')
[ -n "$keep" ] || fail "the new timeline was not archived"
answer=$(ask prune-one "wal_before=${keep%.gz}\nkeep=base-20260101-000001\n")
case "$answer" in *state=ok*) ;; *) fail "the pruning: $answer" ;; esac
left=$("$ENGINE" exec "$NAME-db" sh -c 'ls /wal-archive/wal | grep -cE "^00000001[0-9A-F]{16}\.gz$" || true')
[ "$left" = "0" ] || fail "$left segments before the limit are still in the archive"
"$ENGINE" exec "$NAME-db" test -f /wal-archive/wal/00000002.history.gz || fail "the file of the new timeline was removed"
"$ENGINE" exec "$NAME-db" test -d /wal-archive/base/base-20260101-000001 || fail "a base backup that is kept was removed"

echo "recovery-proof: all six hold"
