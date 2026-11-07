#!/bin/bash
# One-time stack setup: a private CA, the two role certificates, the gateway ID, and Admin with the
# admin_password secret. Later runs keep everything; remove the stack's volumes to start over.
set -euo pipefail
# shellcheck source=lib.sh
. /src/dev/docker/lib.sh

readonly secret=/run/secrets/admin_password
readonly state=/var/lib/traffic-policy/controller

if [[ -e /config/.initialized ]]; then
  printf 'Already initialized\n'
  exit 0
fi

if [[ ! -s $secret ]]; then
  printf 'The admin_password secret is missing or empty\n' >&2
  exit 1
fi

# Init can read the mounted secret with its preserved host ownership; setup-admin runs as the
# service account and reads a private copy that is removed on every exit path.
password=''

cleanup() {
  if [[ -n $password ]]; then
    rm -f -- "$password"
  fi
}

handle_exit() {
  local exit_status=$?
  trap - EXIT HUP INT TERM
  cleanup
  exit "$exit_status"
}

# Exits with the conventional status rather than re-raising: bash as PID 1 ignores a signal it has
# no handler for, so a re-raised one would let the script continue.
handle_signal() {
  trap - EXIT HUP INT TERM
  cleanup
  exit "$1"
}

trap handle_exit EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

wait_for /work/.built "the build service" || exit 1

umask 0077
mkdir -p /config/tls
cd /config/tls

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -subj "/CN=Traffic Policy development CA" -keyout ca.key -out ca.crt 2>/dev/null

# Machine API names are the Compose service names; Common Names match the peer identity fields.
for role in controller gateway; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=traffic-policy-$role" -keyout "$role.key" -out "$role.csr" 2>/dev/null
  openssl x509 -req -in "$role.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
    -out "$role.crt" -extfile /dev/stdin 2>/dev/null <<EOF
subjectAltName=DNS:$role
extendedKeyUsage=serverAuth,clientAuth
keyUsage=digitalSignature
EOF
  rm -f -- "$role.csr"
done

rm -f -- ca.key ca.srl
chown root:traffic-policy controller.key gateway.key
chmod 0640 controller.key gateway.key
chmod 0644 ca.crt controller.crt gateway.crt
chmod 0755 /config /config/tls
cat /proc/sys/kernel/random/uuid >/config/gateway-id
chmod 0644 /config/gateway-id

# Runtimes create volume roots as 0700 root; the service account must traverse it.
chmod 0755 /var/lib/traffic-policy
mkdir -p "$state"
chown traffic-policy:traffic-policy "$state"
chmod 0700 "$state"

password="$(mktemp)"
cp -- "$secret" "$password"
chown traffic-policy "$password"
"${as_service[@]}" "$bun" --no-install /work/dist/setup-admin.mjs \
  --database "$state/controller.sqlite3" --password-file "$password" \
  --settings-file /work/examples/settings.json --initialize

touch /config/.initialized
printf 'Initialized\n'
