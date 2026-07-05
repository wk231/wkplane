#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root." >&2
  exit 1
fi

systemctl disable --now wkplane.service 2>/dev/null || true
rm -f /etc/systemd/system/wkplane.service
systemctl daemon-reload
rm -rf /opt/wkplane

echo "WkPlane service and app files removed."
echo "Config kept at /etc/port-panel/config.json"
echo "iptables rules were not changed."
