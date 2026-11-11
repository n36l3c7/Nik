#!/usr/bin/env bash
# apt-install.sh <package>...: refresh the package index and install, with apt's
# own retries on each download. Wrapped in retry.sh by the workflows, because a
# mirror whose name does not resolve fails before apt's retries apply.
set -euo pipefail

sudo apt-get update -qq -o Acquire::Retries=5
sudo apt-get install -y --no-install-recommends -o Acquire::Retries=5 "$@"
