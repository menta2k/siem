#!/bin/sh
set -e

# The unit files are gone by now, so systemd's view has to be refreshed or it keeps
# reporting units that no longer exist.
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed 2>/dev/null || true
