#!/bin/sh
set -e

# Stop and disable every unit this package owns. Each is independent — a host may be
# running only one of them — so each is handled on its own and a missing unit is not an
# error.
if ! command -v systemctl >/dev/null 2>&1; then
    exit 0
fi

for unit in siem-api siem-ingest siem-processor; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        systemctl stop "$unit"
    fi
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        systemctl disable "$unit"
    fi
done

# /etc/siem/env and /var/lib/siem are deliberately left in place. They hold the
# operator's secrets and state, and a package removal is not consent to destroy them.
