#!/usr/bin/env sh
# Selbsttest der Telemetrie: Beispiel-Payload an aimonitor senden.
# Standardmaessig mit dry_run=1. "--live" sendet echt.
set -u

cd "$(dirname "$0")/.."

DOCKER="docker"
docker compose ps >/dev/null 2>&1 || DOCKER="sudo docker"

$DOCKER compose exec -T gateway python -m gw --aimon-test "$@"
