#!/usr/bin/env bash
# Sets up an SSH MCP server so Claude Code can operate a remote host.
#
# Run this on the WORKSTATION, not on the server. It generates a dedicated key, prints
# the one line to install on the server, verifies the connection, and registers the MCP
# server with Claude Code.
#
#   ./setup-ssh-mcp.sh <name> <host> <user> [port]
#
# Example:
#   ./setup-ssh-mcp.sh siem-prod siem01.example.com claude-ops 22
#
# The key is dedicated to this host on purpose. Reusing one key across servers means a
# single compromised host yields access to all of them, and it removes the ability to
# revoke access to one server without cutting off the rest.

set -euo pipefail

NAME="${1:?usage: setup-ssh-mcp.sh <name> <host> <user> [port]}"
HOST="${2:?missing host}"
USER_NAME="${3:?missing user}"
PORT="${4:-22}"

KEY="$HOME/.ssh/claude_${NAME//-/_}"

if [ ! -f "$KEY" ]; then
    echo "==> generating a dedicated key at $KEY"
    ssh-keygen -t ed25519 -f "$KEY" -N '' -C "claude-code@${NAME}"
else
    echo "==> reusing the existing key at $KEY"
fi
chmod 600 "$KEY"

cat <<EOF

────────────────────────────────────────────────────────────────────────
Install this public key on ${HOST} for the '${USER_NAME}' account.

On the server, as root or with sudo:

  useradd --create-home --shell /bin/bash ${USER_NAME} 2>/dev/null || true
  install -d -m 700 -o ${USER_NAME} -g ${USER_NAME} /home/${USER_NAME}/.ssh
  echo '$(cat "${KEY}.pub")' \\
    >> /home/${USER_NAME}/.ssh/authorized_keys
  chown ${USER_NAME}:${USER_NAME} /home/${USER_NAME}/.ssh/authorized_keys
  chmod 600 /home/${USER_NAME}/.ssh/authorized_keys

Grant sudo. This project's operator chose unrestricted sudo for this account;
narrow it later by replacing the rule with the specific commands needed:

  echo '${USER_NAME} ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/${USER_NAME}
  chmod 440 /etc/sudoers.d/${USER_NAME}
  visudo -c
────────────────────────────────────────────────────────────────────────

EOF

read -r -p "Press enter once the key is installed, to test the connection… " _

echo "==> testing"
if ! ssh -i "$KEY" -p "$PORT" \
        -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
        "${USER_NAME}@${HOST}" 'echo "connected as $(whoami)@$(hostname)"'; then
    echo "ERROR: could not connect. Fix the key or the account, then re-run." >&2
    exit 1
fi

echo "==> registering the MCP server as '${NAME}'"
# Written straight into ~/.claude.json rather than via `claude mcp add`. The server
# takes its host as -h, and `claude` captures that as its own --help before `--` can
# protect it — the add silently turns into a help dump and registers nothing.
CONFIG="$HOME/.claude.json"
NAME="$NAME" HOST="$HOST" PORT="$PORT" USER_NAME="$USER_NAME" KEY="$KEY" \
CONFIG="$CONFIG" python3 - <<'PY'
import json, os, shutil, tempfile

config = os.environ["CONFIG"]
name, host, port = os.environ["NAME"], os.environ["HOST"], os.environ["PORT"]
user, key = os.environ["USER_NAME"], os.environ["KEY"]

shutil.copy2(config, config + ".bak")

with open(config) as fh:
    cfg = json.load(fh)

cfg.setdefault("mcpServers", {})[f"ssh-{name}"] = {
    "type": "stdio",
    "command": "npx",
    "args": [
        "-y", "@fangjunjie/ssh-mcp-server@latest",
        "-h", host, "-p", port, "-u", user, "-k", key,
    ],
    "description": f"SSH to {host} as {user}",
}

# Written to a temp file in the same directory and renamed into place. A partial write
# to the live config would leave Claude Code unable to start at all.
directory = os.path.dirname(config)
with tempfile.NamedTemporaryFile("w", dir=directory, delete=False) as tmp:
    json.dump(cfg, tmp, indent=2)
    staged = tmp.name

with open(staged) as fh:      # parse-check before it goes live
    json.load(fh)
os.replace(staged, config)

print(f"  registered ssh-{name}; previous config saved to {config}.bak")
PY

cat <<EOF

Done. Restart Claude Code, then check with:  claude mcp list

The tools appear as mcp__ssh-${NAME}__execute-command / __upload / __download.
Revoke at any time by removing the key line from
/home/${USER_NAME}/.ssh/authorized_keys on the server.
EOF
