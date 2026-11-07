#!/bin/bash
# Runs the gateway role as its units do: forward guard, enforcement, Suricata, gateway, and
# rotation, in that order, with configs for this stack's addresses.
set -euo pipefail
# shellcheck source=lib.sh
. /src/dev/docker/lib.sh
stop_on_signals

: "${TP_CONTROLLER_ADDRESS:?Set TP_CONTROLLER_ADDRESS}"
: "${TP_DNS_RECEIVE_BUFFER_BYTES:?Set TP_DNS_RECEIVE_BUFFER_BYTES}"
wait_for /work/.built "the build service" || exit 1
wait_for /config/.initialized "the init service" || exit 1

# The controller's fixed address, which enforcement exempts. It is only on the upstream network,
# so its route names the upstream interface; the other interface faces the clients.
controller=$TP_CONTROLLER_ADDRESS
upstream="$(interface_for "$controller")"
clients="$(ip -o -4 addr show scope global | awk -v up="$upstream" '$2 != up {print $2; exit}')"

if [[ -z $upstream || -z $clients ]]; then
  printf 'Cannot find the upstream and clients interfaces (route to %s)\n' "$controller" >&2
  exit 1
fi

upstream_address="$(address_on "$upstream")"
clients_address="$(address_on "$clients")"
clients_network="$(ip -o -4 route show dev "$clients" scope link | awk 'NR == 1 {print $1}')"
resolver="$(awk '$1 == "nameserver" {print $2; exit}' /etc/resolv.conf)"
group="$(getent group traffic-policy | cut -d: -f3)"

if [[ -z $upstream_address || -z $clients_address || -z $clients_network || -z $resolver ]]; then
  printf 'Missing an interface address, the clients network, or a resolver\n' >&2
  exit 1
fi

# Runtimes that ignore `internal` add a default route on the clients network too; the gateway's own
# traffic leaves upstream only.
if [[ -n "$(ip -4 route show default dev "$clients")" ]]; then
  ip route del default dev "$clients"
fi

# Host routing a deployment provides itself (SETUP.md): clients' DNS to the gate's port, and NAT
# for client traffic leaving upstream.
nft -f - <<EOF
table ip tp_dev_nat
delete table ip tp_dev_nat
table ip tp_dev_nat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "$clients" udp dport 53 redirect to :5353
    iifname "$clients" tcp dport 53 redirect to :5353
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $clients_network oifname "$upstream" masquerade
  }
}
EOF

mkdir -p /etc/traffic-policy
cp -- /work/packaging/linux/forward-guard.nft /etc/traffic-policy/forward-guard.nft
cat >/etc/traffic-policy/enforcement.json <<EOF
{
  "socketPath": "/run/traffic-policy/enforcement.sock",
  "stateDirectory": "/var/lib/traffic-policy/enforcement",
  "groupId": $group,
  "dnsPort": 5353,
  "upstreamInterfaces": ["$upstream"],
  "controllerAddresses": ["$controller"],
  "machinePort": 9443,
  "controllerPort": 9445,
  "upstreamDns": { "address": "$resolver", "port": 53 }
}
EOF
cat >/etc/traffic-policy/gateway.json <<EOF
{
  "gatewayId": "$(cat /config/gateway-id)",
  "listenAddress": "${upstream_address%/*}",
  "machinePort": 9443,
  "controllerUrl": "https://controller:9445",
  "controllerIdentity": "traffic-policy-controller",
  "dnsListenAddresses": ["${clients_address%/*}"],
  "dnsPort": 5353,
  "dnsReceiveBufferBytes": $TP_DNS_RECEIVE_BUFFER_BYTES,
  "upstreamDns": { "address": "$resolver", "port": 53 },
  "enforcementSocket": "/run/traffic-policy/enforcement.sock",
  "stateDirectory": "/var/lib/traffic-policy/gateway",
  "collectorBytes": "134217728",
  "tls": {
    "ca": "/config/tls/ca.crt",
    "certificate": "/config/tls/gateway.crt",
    "key": "/config/tls/gateway.key"
  },
  "suricataFile": "/var/lib/traffic-policy/suricata/eve.json"
}
EOF
chmod 0644 /etc/traffic-policy/*.json /etc/traffic-policy/forward-guard.nft

# Directories and modes from SETUP.md. Runtimes create volume roots as 0700 root.
state=/var/lib/traffic-policy
chmod 0755 "$state"
install -d -o traffic-policy -g traffic-policy -m 0750 "$state/gateway"
install -d -o root -g traffic-policy -m 0750 "$state/enforcement"
install -d -o traffic-policy-suricata -g traffic-policy -m 2770 "$state/suricata"
install -d -o root -g traffic-policy -m 0750 /run/traffic-policy
install -d -m 0755 /run/tp-dev
# A restarted container keeps /run; readiness below must not see the last run's socket or PIDs.
rm -f -- /run/traffic-policy/enforcement.sock /run/tp-dev/*.pid
printf 'TP_SURICATA_INTERFACE=%s\nTP_HOME_NET=%s\n' "$clients" "$clients_network" \
  >/run/tp-dev/suricata.env

export BUN_RUNTIME_TRANSPILER_CACHE_PATH=0
umask 0077

# tp-forward-guard.service: root with CAP_NET_ADMIN only.
setpriv --bounding-set=-all,+net_admin --inh-caps=-all -- \
  "$bun" --no-install /work/dist/forward-guard.mjs

# tp-enforcement.service: root, group traffic-policy, CAP_NET_ADMIN only.
start_unit tp-enforcement.service \
  setpriv --regid=traffic-policy --clear-groups --bounding-set=-all,+net_admin --inh-caps=-all -- \
  "$bun" --no-install /work/dist/enforcement.mjs /etc/traffic-policy/enforcement.json
wait_for /run/traffic-policy/enforcement.sock "the enforcement service" || exit 1

systemctl start tp-suricata.service

# tp-gateway.service: the service account with no capabilities.
start_unit tp-gateway.service \
  "${as_service[@]}" "$bun" --no-install /work/dist/gateway.mjs /etc/traffic-policy/gateway.json

# tp-suricata-rotate.service runs as root with three capabilities. Here it keeps the gateway
# container's set, because the systemctl stand-in signals and restarts Suricata from its process.
umask 0027
start_unit tp-suricata-rotate.service \
  setpriv --regid=traffic-policy --clear-groups -- \
  "$bun" --no-install /work/dist/suricata-rotate.mjs

printf 'Gateway: upstream %s %s, clients %s %s\n' \
  "$upstream" "$upstream_address" "$clients" "$clients_address"
supervise
