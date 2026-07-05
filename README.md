# WkPlane

Lightweight web panel for Linux iptables port forwarding.

## Features

- Manage TCP/UDP port forwarding rules from a web panel.
- Add, edit, delete forwarding rules.
- Optional rule name field for easier identification.
- Conflict check for duplicated protocol + listen port.
- Realtime server bandwidth, traffic totals, connection states, memory, disk, load.
- Random secret URL path.
- Persistent signed login cookie.
- No database required.
- Python standard library only.
- Does not depend on any existing `iptables-pf.sh` script.

## One-click install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/wk231/wkplane/main/install.sh)
```

The installer prints the URL, username, and password after installation.

Default values:

- username: `admin`
- password: random
- port: `8086`
- secret path: random

## Custom install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/wk231/wkplane/main/install.sh) -- --user admin --password 'your-password' --port 8086
```

Or use environment variables:

```bash
WKPLANE_USER=admin \
WKPLANE_PASSWORD='your-password' \
WKPLANE_PORT=8086 \
bash <(curl -Ls https://raw.githubusercontent.com/wk231/wkplane/main/install.sh)
```

Overwrite existing config:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/wk231/wkplane/main/install.sh) -- --force
```

## Files

- app: `/opt/wkplane/wkplane.py`
- config: `/etc/port-panel/config.json`
- service: `/etc/systemd/system/wkplane.service`
- iptables backup: `/etc/iptables.up.rules`
- ip forwarding: `/etc/sysctl.d/99-wkplane-forward.conf`

## Commands

```bash
systemctl status wkplane
systemctl restart wkplane
journalctl -u wkplane -f
```

## Uninstall

```bash
bash <(curl -Ls https://raw.githubusercontent.com/wk231/wkplane/main/uninstall.sh)
```

Uninstall removes the WkPlane service and app files only. It does not clear existing iptables rules.

## Notes

WkPlane directly manages iptables rules:

- `nat PREROUTING` DNAT
- `nat POSTROUTING` SNAT
- `INPUT` ACCEPT for listen ports

It saves current rules to `/etc/iptables.up.rules` for restore on reboot.
