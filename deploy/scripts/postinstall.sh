#!/bin/sh
set -e

# A dedicated unprivileged account. The units run as this user, and /etc/siem/env holds
# the ClickHouse password and the JWT signing key — so the directory is readable only by
# it, never by the world.
if ! getent group siem >/dev/null 2>&1; then
    groupadd --system siem
fi
if ! getent passwd siem >/dev/null 2>&1; then
    useradd --system --gid siem --home-dir /var/lib/siem \
        --shell /usr/sbin/nologin --comment "SIEM platform" siem
fi

install -d -o siem -g siem -m 0750 /var/lib/siem
install -d -o root -g siem -m 0750 /etc/siem

# Created on first install only, never overwritten: an upgrade must not blank out an
# operator's secrets. It starts empty-but-present so systemd's EnvironmentFile= does not
# fail the unit before anyone has had a chance to fill it in.
if [ ! -e /etc/siem/env ]; then
    if [ -r /usr/share/siem/env.example ]; then
        cp /usr/share/siem/env.example /etc/siem/env
    else
        # Never fail the install over a missing template: an empty file still satisfies
        # systemd's EnvironmentFile= and leaves the operator a place to write.
        : > /etc/siem/env
    fi
fi
chown root:siem /etc/siem/env
chmod 0640 /etc/siem/env

# Tolerated failure: the package is also installed into container images during a
# build, where systemd is not PID 1 and daemon-reload cannot work. Failing the install
# there would break image builds for a reload that has nothing to reload.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Deliberately NOT enabled or started. Every service exits immediately without a
# configured ClickHouse address, broker and signing key, so enabling them here would
# hand the operator three crash-looping units and a restart-limit lockout as the first
# thing they see after an install.
cat <<'EOM'

SIEM installed.

Next steps:
  1. Fill in /etc/siem/env  (template: /usr/share/siem/env.example)
     At minimum: CLICKHOUSE_ADDR, CLICKHOUSE_PASSWORD, REDPANDA_BROKERS,
                 REDIS_ADDR, JWT_SIGNING_KEY
  2. Apply the schema with golang-migrate against your ClickHouse:
       migrate -path /usr/share/siem/migrations -database "$CLICKHOUSE_URL" up
  3. Enable the services this host should run — they are independent:
       systemctl enable --now siem-api        # API and query surface
       systemctl enable --now siem-ingest     # vendor log intake
       systemctl enable --now siem-processor  # normalize, correlate, alert, retain
  4. Create the first tenant and admin:  siem-seed

The web UI is served from /usr/share/siem/frontend — point a web server at it and
proxy /api to the API service. An example nginx config is in
/usr/share/siem/nginx.conf.example.

EOM
