#!/bin/bash
# Runs tp-controller and tp-controller-machine as their units do, with a config for this stack.
set -euo pipefail
# shellcheck source=lib.sh
. /src/dev/docker/lib.sh
stop_on_signals

: "${TP_ORIGIN:?Set TP_ORIGIN}"
: "${TP_BROWSER_TRANSPORT:?Set TP_BROWSER_TRANSPORT}"
wait_for /work/.built "the build service" || exit 1
wait_for /config/.initialized "the init service" || exit 1

address="$(ip -o -4 addr show scope global | awk 'NR == 1 {print $4}')"

if [[ -z $address ]]; then
  printf 'The controller has no IPv4 address\n' >&2
  exit 1
fi

mkdir -p /etc/traffic-policy
cat >/etc/traffic-policy/controller.json <<EOF
{
  "database": "/var/lib/traffic-policy/controller/controller.sqlite3",
  "listenAddress": "${address%/*}",
  "browserListenAddress": "0.0.0.0",
  "browserPort": 9444,
  "machinePort": 9445,
  "browserTransport": "$TP_BROWSER_TRANSPORT",
  "publicOrigin": "$TP_ORIGIN",
  "gatewayUrl": "https://gateway:9443",
  "gatewayIdentity": "traffic-policy-gateway",
  "tls": {
    "ca": "/config/tls/ca.crt",
    "certificate": "/config/tls/controller.crt",
    "key": "/config/tls/controller.key"
  }
}
EOF
chmod 0644 /etc/traffic-policy/controller.json

install -d -m 0755 /run/tp-dev
# A restarted container keeps /run; status must not report the last run's PIDs.
rm -f -- /run/tp-dev/*.pid

export TP_CONTROLLER_CONFIG=/etc/traffic-policy/controller.json NODE_ENV=production
export BUN_RUNTIME_TRANSPILER_CACHE_PATH=0
umask 0077
start_unit tp-controller-machine.service \
  "${as_service[@]}" "$bun" --no-install /work/dist/controller-machine.mjs
start_unit tp-controller.service \
  "${as_service[@]}" "$bun" --no-install /work/dist/controller-runtime.mjs \
  /work/apps/controller/build/handler.js
supervise
