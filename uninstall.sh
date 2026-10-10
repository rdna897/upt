#!/bin/sh
set -eu
PREFIX=${PREFIX:-/usr/local}
rm -f "$PREFIX/bin/upt" "$PREFIX/bin/upt-web" "$PREFIX/bin/upt-agent" "$PREFIX/bin/check-updates"
rm -rf "$PREFIX/lib/docker-update-manager"
printf '%s\n' 'Executable removed. Configuration and state/backups were deliberately preserved.'

