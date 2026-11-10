#!/bin/sh
# Every container image is named with its registry (docker.io/…).
#
# Docker reads a short name such as `python:3.12-slim` as docker.io, but
# Podman resolves it through /etc/containers/registries.conf: on RHEL the
# first registry is registry.redhat.io, which needs Red Hat credentials and
# does not host these images, so `podman compose up --build` fails. Fully
# qualified names build the same way with both engines.
#
# Usage: deploy/check-images.sh (from the repository root; CI runs it).
set -eu

qualified='^[a-z0-9.-]+\.[a-z]{2,}(:[0-9]+)?/[^[:space:]]+$'
status=0

check() { # $1 = where, $2 = image
  if ! printf '%s\n' "$2" | grep -Eq "$qualified"; then
    echo "$1: $2 does not name its registry" >&2
    status=1
  fi
}

files=$(git ls-files '*Dockerfile' '*.Dockerfile')
while IFS= read -r file; do
  [ -n "$file" ] || continue
  stages=' '
  # FROM [--platform=…] image [AS stage]  →  image|stage
  entries=$(sed -nE 's/^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?([^[:space:]]+)([[:space:]]+[Aa][Ss][[:space:]]+([^[:space:]]+))?.*/\2|\4/Ip' "$file")
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    image=${entry%%|*}
    stage=${entry#*|}
    case "$stages" in
      *" $image "*) ;; # a previous build stage, not an image
      *) check "$file: FROM" "$image" ;;
    esac
    if [ -n "$stage" ]; then stages="$stages$stage "; fi
  done <<ENTRIES
$entries
ENTRIES
done <<FILES
$files
FILES

images=$(sed -nE 's/^[[:space:]]+image:[[:space:]]*([^[:space:]]+).*/\1/p' docker-compose.yml)
while IFS= read -r image; do
  [ -n "$image" ] || continue
  check "docker-compose.yml: image" "$image"
done <<IMAGES
$images
IMAGES

exit "$status"
