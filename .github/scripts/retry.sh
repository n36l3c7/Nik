#!/usr/bin/env bash
# retry.sh <attempts> <command> [arguments...]
#
# Run a command that depends on the network (a package mirror, a registry, a
# browser download) and try again, after a growing pause, when it fails. The
# runners' DNS and the distribution mirrors fail for a few seconds now and
# then: that is not a reason to fail a build whose code is fine.
set -euo pipefail

attempts=$1
shift
for attempt in $(seq 1 "$attempts"); do
  if "$@"; then
    exit 0
  fi
  if [ "$attempt" -lt "$attempts" ]; then
    pause=$((attempt * 20))
    echo "::warning::attempt $attempt of $attempts failed: $1 … (trying again in ${pause}s)"
    sleep "$pause"
  fi
done
echo "::error::failed after $attempts attempts: $*"
exit 1
