# Shared helpers for the development stack's entry scripts. Sourced by Bash; sets no shell options.

# shellcheck disable=SC2034 # Used by the scripts that source this file.
readonly bun=/opt/traffic-policy/runtime/bin/bun

# Processes start_unit launched and their units, in start order.
tp_dev_pids=()
tp_dev_units=()

# Waits up to ten minutes for a file another service writes.
wait_for() {
  local tries=0

  until [[ -e $1 ]]; do
    tries=$((tries + 1))

    if ((tries > 600)); then
      printf 'Timed out waiting for %s\n' "$2" >&2
      return 1
    fi

    sleep 1
  done
}

# The interface that routes to an address, and an interface's IPv4 address with its prefix.
interface_for() {
  ip -o -4 route get "$1" | sed -n 's/.* dev \([^ ]*\).*/\1/p'
}

address_on() {
  ip -o -4 addr show dev "$1" | awk 'NR == 1 {print $4}'
}

# The first IPv4 address a name resolves to; fails when it does not resolve.
resolve() {
  local address
  address="$(getent ahostsv4 "$1" | awk 'NR == 1 {print $1}')"
  [[ -n $address ]] && printf '%s\n' "$address"
}

# Prefix that runs a command as the service account with no capabilities, as the units' empty
# bounding set does. An array rather than a function, so start_unit records the process itself.
# shellcheck disable=SC2034 # Used by the scripts that source this file.
readonly -a as_service=(
  setpriv --reuid=traffic-policy --regid=traffic-policy --init-groups
  --inh-caps=-all --bounding-set=-all --no-new-privs --
)

# Starts a process in the background and records its PID as the unit's, for the systemctl
# stand-in. /run/tp-dev stays readable so the service accounts can read service status.
start_unit() {
  local unit=$1
  shift
  "$@" &
  tp_dev_pids+=("$!")
  tp_dev_units+=("$unit")
  printf '%s\n' "$!" >"/run/tp-dev/$unit.pid"
  chmod 0644 "/run/tp-dev/$unit.pid"
}

# Whether a process still runs; an exited one awaiting its parent's reaping does not.
running() {
  [[ -r /proc/$1/status ]] && ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status"
}

# Stops Suricata, which the systemctl stand-in starts outside start_unit, and waits up to 20 seconds
# for it to flush and exit.
stop_suricata() {
  local pid tries=0

  if ! pid="$(cat /run/tp-dev/tp-suricata.service.pid 2>/dev/null)" || ! running "$pid"; then
    return 0
  fi

  kill -s TERM "$pid"

  while running "$pid" && ((tries < 100)); do
    sleep 0.2
    tries=$((tries + 1))
  done
}

# Stops the started processes in reverse start order, waiting for each, as systemd stops units
# after the ones that depend on them. Suricata started right after enforcement, so it stops right
# before it. A stopped process's own status is not reported.
stop_units() {
  local index pid

  for ((index = ${#tp_dev_pids[@]} - 1; index >= 0; index--)); do
    if [[ ${tp_dev_units[index]} == tp-enforcement.service ]]; then
      stop_suricata
    fi

    pid=${tp_dev_pids[index]}

    if running "$pid"; then
      kill -s TERM "$pid"

      if ! wait "$pid"; then
        continue
      fi
    fi
  done
}

# Stops whatever has started when the runtime sends TERM or INT. Bash as PID 1 ignores signals it
# has no trap for, so entry scripts install this before their first wait.
stop_on_signals() {
  trap 'stop_units; exit 143' TERM
  trap 'stop_units; exit 130' INT
}

# Runs until the runtime stops the container or a started process exits. Either way the rest are
# stopped; an unexpected exit ends the container with that process's status, or 1 if it was 0.
supervise() {
  local status=0

  wait -n || status=$?
  trap - TERM INT
  printf 'A supervised process exited with status %s; stopping\n' "$status" >&2
  stop_units
  exit $((status == 0 ? 1 : status))
}
