#!/usr/bin/env bash
set -euo pipefail

REPO_RAW="${WKPLANE_RAW:-https://raw.githubusercontent.com/wk231/wkplane/main}"
APP_DIR="/opt/wkplane"
CONFIG_DIR="/etc/port-panel"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SERVICE_FILE="/etc/systemd/system/wkplane.service"
RESTORE_SERVICE="/etc/systemd/system/wkplane-iptables-restore.service"
USERNAME="${WKPLANE_USER:-admin}"
PASSWORD="${WKPLANE_PASSWORD:-}"
PORT="${WKPLANE_PORT:-8086}"
PATH_TOKEN="${WKPLANE_PATH:-}"
FORCE="${WKPLANE_FORCE:-0}"

usage() {
  cat <<'USAGE'
Usage:
  bash install.sh [--user admin] [--password pass] [--port 8086] [--path random-path] [--force]

Environment variables:
  WKPLANE_USER      Login username, default: admin
  WKPLANE_PASSWORD  Login password, random if empty
  WKPLANE_PORT      Listen port, default: 8086
  WKPLANE_PATH      Secret URL path, random if empty
  WKPLANE_FORCE     Overwrite existing config when set to 1

Examples:
  bash <(curl -Ls https://raw.githubusercontent.com/wk231/wkplane/main/install.sh)
  bash <(curl -Ls https://raw.githubusercontent.com/wk231/wkplane/main/install.sh) -- --user admin --password 'change-me' --port 8086
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) USERNAME="${2:?missing value}"; shift 2 ;;
    --password) PASSWORD="${2:?missing value}"; shift 2 ;;
    --port) PORT="${2:?missing value}"; shift 2 ;;
    --path) PATH_TOKEN="${2:?missing value}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --) shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Please run as root." >&2
    exit 1
  fi
}

valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -ge 1 ]] && [[ "$1" -le 65535 ]]
}

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 24 | tr -dc 'A-Za-z0-9@#%+=_' | head -c 18
  else
    tr -dc 'A-Za-z0-9@#%+=_' </dev/urandom | head -c 18
  fi
}

install_pkg() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$@"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$@"
  else
    echo "Unsupported package manager. Please install: $*" >&2
    exit 1
  fi
}

ensure_deps() {
  command -v python3 >/dev/null 2>&1 || install_pkg python3
  command -v curl >/dev/null 2>&1 || install_pkg curl
  command -v iptables >/dev/null 2>&1 || install_pkg iptables
  command -v systemctl >/dev/null 2>&1 || { echo "systemd is required." >&2; exit 1; }
}

port_free() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ! ss -lnt "( sport = :${port} )" | grep -q ":${port}"
  else
    ! netstat -lnt 2>/dev/null | grep -q ":${port} "
  fi
}

public_ip() {
  curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}'
}

install_files() {
  mkdir -p "$APP_DIR" "$CONFIG_DIR"
  curl -fsSL "${REPO_RAW}/wkplane.py" -o "${APP_DIR}/wkplane.py"
  chmod 0755 "${APP_DIR}/wkplane.py"
  cat > "$SERVICE_FILE" <<'SERVICE'
[Unit]
Description=WkPlane Port Forwarding Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/wkplane/wkplane.py
Restart=on-failure
RestartSec=3
User=root
WorkingDirectory=/opt/wkplane

[Install]
WantedBy=multi-user.target
SERVICE
}

enable_forwarding() {
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wkplane-forward.conf
}

install_restore_service() {
  cat > "$RESTORE_SERVICE" <<'SERVICE'
[Unit]
Description=Restore iptables rules for WkPlane
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
ConditionPathExists=/etc/iptables.up.rules

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/sbin/iptables-restore < /etc/iptables.up.rules'

[Install]
WantedBy=multi-user.target
SERVICE
  systemctl enable wkplane-iptables-restore.service >/dev/null
}

write_config() {
  if [[ -z "$PASSWORD" ]]; then
    PASSWORD="$(random_secret)"
  fi
  if [[ -z "$PATH_TOKEN" ]]; then
    PATH_TOKEN="$(random_secret)"
  fi
  if [[ "$FORCE" != "1" && -f "$CONFIG_FILE" ]]; then
    echo "Existing config found: $CONFIG_FILE"
    echo "Use --force or WKPLANE_FORCE=1 to overwrite it." >&2
    exit 1
  fi
  python3 "${APP_DIR}/wkplane.py" init-config "$USERNAME" "$PASSWORD" "$PORT" "$PATH_TOKEN" >/tmp/wkplane-init.json
  chmod 0600 "$CONFIG_FILE"
}

main() {
  need_root
  valid_port "$PORT" || { echo "Invalid port: $PORT" >&2; exit 1; }
  ensure_deps
  if [[ "$FORCE" != "1" ]] && ! port_free "$PORT"; then
    echo "Port $PORT is already in use. Use --port to choose another port." >&2
    exit 1
  fi
  install_files
  write_config
  enable_forwarding
  install_restore_service
  iptables-save > /etc/iptables.up.rules || true
  systemctl daemon-reload
  systemctl enable --now wkplane.service >/dev/null
  sleep 1
  systemctl is-active --quiet wkplane.service || {
    journalctl -u wkplane.service -n 40 --no-pager
    exit 1
  }

  local ip
  ip="$(public_ip)"
  echo
  echo "WkPlane installed successfully."
  echo "URL: http://${ip}:${PORT}/${PATH_TOKEN}/"
  echo "Username: ${USERNAME}"
  echo "Password: ${PASSWORD}"
  echo
  echo "Service: systemctl status wkplane"
  echo "Config:  ${CONFIG_FILE}"
}

main "$@"
