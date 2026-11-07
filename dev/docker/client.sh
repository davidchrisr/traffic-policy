#!/bin/bash
# A managed client: its only route and resolver are the gateway. Use it to generate traffic, for
# example `compose exec client curl -sI https://example.com`.
set -euo pipefail
# shellcheck source=lib.sh
. /src/dev/docker/lib.sh

trap 'exit 143' TERM
trap 'exit 130' INT

# The gateway's address changes when it restarts, so the route and resolver follow it.
current=''

while true; do
  if gateway="$(resolve gateway)" && [[ $gateway != "$current" ]]; then
    ip route replace default via "$gateway"
    printf 'nameserver %s\n' "$gateway" >/etc/resolv.conf
    current=$gateway
    printf 'Client %s via gateway %s\n' \
      "$(ip -o -4 addr show scope global | awk 'NR == 1 {print $4}')" "$gateway"
  fi

  # Waiting on a background sleep lets the traps run without waiting out the interval.
  sleep 5 &
  wait "$!"
done
