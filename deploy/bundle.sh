#!/usr/bin/env bash
# Packs a wasp release for a cPanel host: the static binary, the theme, the
# start shim, the deploy notes, the example configuration, and the systemd
# and launchd files for a server you run yourself, in
# wasp-<name>-x86_64-linux-musl.tar.gz, with its .sha256 beside it.
#
# Usage: deploy/bundle.sh <path to the built wasp binary> <name> <output folder>
# Run it from the repository's root.
set -eu
BIN="${1:?the built wasp binary}"
NAME="wasp-${2:?a name, such as the commit}-x86_64-linux-musl"
OUT="${3:?an output folder}"
[ -x "$BIN" ] || { echo "not an executable: $BIN" >&2; exit 1; }
[ -f deploy/wasp.conf.example ] || { echo "run from the repository's root" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME/themes" "$OUT"
cp "$BIN" "$STAGE/$NAME/wasp"
chmod 755 "$STAGE/$NAME/wasp"
cp -R themes/default "$STAGE/$NAME/themes/default"
cp deploy/passenger/app.js "$STAGE/$NAME/app.js"
cp deploy/README.md "$STAGE/$NAME/DEPLOY.md"
cp deploy/CPANEL.md "$STAGE/$NAME/CPANEL.md"
cp deploy/wasp.conf.example "$STAGE/$NAME/wasp.conf.example"
mkdir -p "$STAGE/$NAME/service"
cp deploy/systemd/wasp.service "$STAGE/$NAME/service/wasp.service"
cp deploy/launchd/com.example.wasp.plist "$STAGE/$NAME/service/com.example.wasp.plist"

tar -C "$STAGE" -czf "$OUT/$NAME.tar.gz" "$NAME"
( cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )
echo "$OUT/$NAME.tar.gz"
cat "$OUT/$NAME.tar.gz.sha256"
