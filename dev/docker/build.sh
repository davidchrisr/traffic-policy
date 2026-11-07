#!/bin/bash
# Copies the mounted source into this stack's work volume, installs dependencies from the shared
# cache, and builds for this stack's browser origin. Services wait for /work/.built.
set -euo pipefail

: "${TP_ORIGIN:?Set TP_ORIGIN}"
readonly bun=/opt/traffic-policy/runtime/bin/bun

rm -f -- /work/.built

# Ownership is not copied, so the build needs no CAP_CHOWN.
rsync -rlpt --delete \
  --exclude=node_modules --exclude=.git --exclude=.tmp --exclude=.local \
  --exclude=/dist --exclude=/apps/controller/build --exclude=.svelte-kit \
  /src/ /work/

cd /work
export BUN_INSTALL_CACHE_DIR=/cache
"$bun" install --frozen-lockfile
TP_PUBLIC_ORIGIN="$TP_ORIGIN" "$bun" run build

date -u +%FT%TZ >/work/.built
printf 'Built for %s\n' "$TP_ORIGIN"
