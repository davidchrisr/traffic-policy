#!/bin/bash
# Prints the stack's controller state for verification, one JSON object per line; read-only.
#   nerdctl compose --env-file <file> exec controller /src/dev/docker/inspect.sh <view>
set -euo pipefail
# shellcheck source=lib.sh
. /src/dev/docker/lib.sh

usage() {
  printf 'Usage: inspect.sh status|conditions|instances|requests\n' >&2
  exit 2
}

if [[ $# -ne 1 ]]; then
  usage
fi

case $1 in
  status | conditions | instances | requests) ;;
  *) usage ;;
esac

# The service account reads the database, as the controller does.
exec "${as_service[@]}" "$bun" --no-install /src/dev/docker/inspect.js "$1"
