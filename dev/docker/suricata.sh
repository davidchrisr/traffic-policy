#!/bin/bash
# Starts Suricata as tp-suricata.service would (its own account, CAP_NET_RAW only) and records its
# PID for the systemctl stand-in. gateway.sh writes the capture settings to suricata.env. Output
# goes to the container's log, which the runtime bounds, through PID 1's descriptors rather than the
# caller's, so a restart from suricata-rotate does not hold its output pipe open.
set -euo pipefail
# shellcheck source=/dev/null
. /run/tp-dev/suricata.env

: "${TP_SURICATA_INTERFACE:?Missing TP_SURICATA_INTERFACE in suricata.env}"
: "${TP_HOME_NET:?Missing TP_HOME_NET in suricata.env}"

(
  umask 0027
  exec setpriv --reuid=traffic-policy-suricata --regid=traffic-policy-suricata --init-groups \
    --inh-caps=-all,+net_raw --ambient-caps=-all,+net_raw --bounding-set=-all,+net_raw -- \
    suricata --af-packet="$TP_SURICATA_INTERFACE" --runmode=single \
    -c /etc/suricata/suricata.yaml --set "vars.address-groups.HOME_NET=[$TP_HOME_NET]" \
    -l /var/lib/traffic-policy/suricata
) >/proc/1/fd/1 2>/proc/1/fd/2 &

printf '%s\n' "$!" >/run/tp-dev/tp-suricata.service.pid
chmod 0644 /run/tp-dev/tp-suricata.service.pid
