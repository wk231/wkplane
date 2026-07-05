#!/usr/bin/env python3
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import urllib.parse
import sys
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_DIR = "/opt/port-panel"
CONFIG_PATH = "/etc/port-panel/config.json"
IPTABLES_BACKUP = "/etc/iptables.up.rules"
SYSCTL_FORWARD = "/etc/sysctl.d/99-port-panel-forward.conf"
DEFAULT_USER = "admin"
DEFAULT_PORT = 8086
SESSIONS = {}
BANDWIDTH_STATE = {"time": 0.0, "rx": 0, "tx": 0, "rx_rate": 0.0, "tx_rate": 0.0}
TCP_STATE_NAMES = {
    "ESTAB": "已连接",
    "LISTEN": "监听中",
    "TIME-WAIT": "等待释放",
    "CLOSE-WAIT": "等待本机关闭",
    "FIN-WAIT-1": "关闭中1",
    "FIN-WAIT-2": "关闭中2",
    "LAST-ACK": "最后确认",
    "SYN-SENT": "正在发起连接",
    "SYN-RECV": "正在接收连接",
    "CLOSING": "关闭中",
    "CLOSED": "已关闭",
}


def run(cmd, check=False):
    p = subprocess.run(cmd, text=True, capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "command failed").strip())
    return p


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
    return "pbkdf2_sha256$200000$%s$%s" % (
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password, stored):
    try:
        algo, rounds, salt_b64, digest_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def load_config():
    if not os.path.exists(CONFIG_PATH):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        password = secrets.token_urlsafe(16)
        cfg = {
            "listen_host": "0.0.0.0",
            "listen_port": DEFAULT_PORT,
            "username": DEFAULT_USER,
            "password_hash": hash_password(password),
            "path_token": secrets.token_urlsafe(18).replace("-", "").replace("_", ""),
            "secret_key": secrets.token_urlsafe(32),
            "rule_names": {},
        }
        save_config(cfg)
        print("WkPlane config was missing; generated random password:", password, flush=True)
        return cfg
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if not cfg.get("path_token"):
        cfg["path_token"] = secrets.token_urlsafe(18).replace("-", "").replace("_", "")
        save_config(cfg)
    if not cfg.get("secret_key"):
        cfg["secret_key"] = secrets.token_urlsafe(32)
        save_config(cfg)
    if "rule_names" not in cfg or not isinstance(cfg.get("rule_names"), dict):
        cfg["rule_names"] = {}
        save_config(cfg)
    return cfg


def make_session_cookie(cfg, username, ttl=604800):
    exp = int(time.time()) + ttl
    payload = f"{username}|{exp}"
    sig = hmac.new(cfg["secret_key"].encode(), payload.encode(), hashlib.sha256).hexdigest()
    raw = f"{payload}|{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode()


def verify_session_cookie(value, cfg):
    try:
        raw = base64.urlsafe_b64decode(value.encode()).decode()
        username, exp, sig = raw.rsplit("|", 2)
        payload = f"{username}|{exp}"
        expected = hmac.new(cfg["secret_key"].encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        if username != cfg.get("username"):
            return False
        return int(exp) > time.time()
    except Exception:
        return False


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)


def init_config(username, password, port, path_token=""):
    cfg = {
        "listen_host": "0.0.0.0",
        "listen_port": int(port),
        "username": username,
        "password_hash": hash_password(password),
        "path_token": path_token or secrets.token_urlsafe(18).replace("-", "").replace("_", ""),
        "secret_key": secrets.token_urlsafe(32),
        "rule_names": {},
    }
    save_config(cfg)
    return cfg


def shell_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def validate_port(value):
    try:
        port = int(value)
    except Exception:
        raise ValueError("端口必须是数字")
    if port < 1 or port > 65535:
        raise ValueError("端口范围必须是 1-65535")
    return port


def validate_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except Exception:
        raise ValueError("目标 IP 格式不正确")


def clean_name(value):
    return value.strip()[:64]


def rule_key(proto, listen_port, target_ip, target_port):
    return f"{proto}|{listen_port}|{target_ip}|{target_port}"


def get_rule_name(cfg, proto, listen_port, target_ip, target_port):
    return cfg.get("rule_names", {}).get(rule_key(proto, listen_port, target_ip, target_port), "")


def set_rule_name(proto, listen_port, target_ip, target_port, name):
    cfg = load_config()
    cfg.setdefault("rule_names", {})
    key = rule_key(proto, listen_port, target_ip, target_port)
    name = clean_name(name)
    if name:
        cfg["rule_names"][key] = name
    else:
        cfg["rule_names"].pop(key, None)
    save_config(cfg)


def remove_rule_name(proto, listen_port, target_ip, target_port):
    cfg = load_config()
    cfg.setdefault("rule_names", {})
    cfg["rule_names"].pop(rule_key(proto, listen_port, target_ip, target_port), None)
    save_config(cfg)


def current_source_ip(rules=None):
    rules = rules if rules is not None else list_forward_rules()
    for r in rules:
        if r.get("to_source"):
            return r["to_source"]
    route = run(["ip", "-4", "route", "get", "1.1.1.1"]).stdout
    m = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", route)
    if m:
        return m.group(1)
    return ""


def parse_nat_rules():
    pre = run(["iptables", "-t", "nat", "-S", "PREROUTING"]).stdout.splitlines()
    post = run(["iptables", "-t", "nat", "-S", "POSTROUTING"]).stdout.splitlines()
    rules = []
    pre_re = re.compile(
        r"^-A PREROUTING -p (tcp|udp).* --dport (\d+) -j DNAT --to-destination ([0-9.]+):(\d+)"
    )
    post_re = re.compile(
        r"^-A POSTROUTING -d ([0-9.]+)(?:/32)? -p (tcp|udp).* --dport (\d+) -j SNAT --to-source ([0-9.]+)"
    )
    posts = []
    for line in post:
        m = post_re.search(line)
        if m:
            posts.append(
                {
                    "target_ip": m.group(1),
                    "proto": m.group(2),
                    "target_port": int(m.group(3)),
                    "to_source": m.group(4),
                }
            )
    for line in pre:
        m = pre_re.search(line)
        if not m:
            continue
        proto, listen_port, target_ip, target_port = m.groups()
        rule = {
            "proto": proto,
            "listen_port": int(listen_port),
            "target_ip": target_ip,
            "target_port": int(target_port),
            "to_source": "",
            "pkts": 0,
            "bytes": 0,
        }
        for p in posts:
            if (
                p["proto"] == proto
                and p["target_ip"] == target_ip
                and p["target_port"] == int(target_port)
            ):
                rule["to_source"] = p["to_source"]
                break
        rules.append(rule)
    attach_counters(rules)
    return rules


def attach_counters(rules):
    out = run(["iptables", "-t", "nat", "-vnL", "PREROUTING"]).stdout.splitlines()
    for line in out:
        if "DNAT" not in line or "dpt:" not in line or "to:" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[3]
        m_dpt = re.search(r"\bdpt:(\d+)", line)
        m_to = re.search(r"\bto:([0-9.]+):(\d+)", line)
        if not m_dpt or not m_to:
            continue
        for rule in rules:
            if (
                rule["proto"] == proto
                and rule["listen_port"] == int(m_dpt.group(1))
                and rule["target_ip"] == m_to.group(1)
                and rule["target_port"] == int(m_to.group(2))
            ):
                rule["pkts"] = parse_counter(parts[0])
                rule["bytes"] = parse_counter(parts[1])


def parse_counter(value):
    value = value.strip()
    m = re.match(r"^([0-9.]+)([KMGTP]?)$", value, re.I)
    if not m:
        return 0
    num = float(m.group(1))
    unit = m.group(2).upper()
    scale = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4, "P": 1024**5}[unit]
    return int(num * scale)


def list_forward_rules():
    return sorted(
        parse_nat_rules(),
        key=lambda r: (r["listen_port"], r["proto"], r["target_ip"], r["target_port"]),
    )


def iptables_exists(args):
    return run(["iptables"] + args).returncode == 0


def iptables_ensure(check_args, add_args):
    if not iptables_exists(check_args):
        run(["iptables"] + add_args, check=True)


def set_ip_forward():
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    os.makedirs(os.path.dirname(SYSCTL_FORWARD), exist_ok=True)
    with open(SYSCTL_FORWARD, "w", encoding="utf-8") as f:
        f.write("net.ipv4.ip_forward=1\n")


def add_forward(proto, listen_port, target_ip, target_port):
    src_ip = current_source_ip()
    if not src_ip:
        raise RuntimeError("无法自动获取本机 SNAT 源 IP")
    check_forward_conflict(proto, listen_port, target_ip, target_port)
    set_ip_forward()
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    for p in protos:
        pre = ["-t", "nat", "-C", "PREROUTING", "-p", p, "--dport", str(listen_port), "-j", "DNAT", "--to-destination", f"{target_ip}:{target_port}"]
        pre_add = ["-t", "nat", "-A", "PREROUTING", "-p", p, "--dport", str(listen_port), "-j", "DNAT", "--to-destination", f"{target_ip}:{target_port}"]
        post = ["-t", "nat", "-C", "POSTROUTING", "-p", p, "-d", target_ip, "--dport", str(target_port), "-j", "SNAT", "--to-source", src_ip]
        post_add = ["-t", "nat", "-A", "POSTROUTING", "-p", p, "-d", target_ip, "--dport", str(target_port), "-j", "SNAT", "--to-source", src_ip]
        inp = ["-C", "INPUT", "-m", "state", "--state", "NEW", "-m", p, "-p", p, "--dport", str(listen_port), "-j", "ACCEPT"]
        inp_add = ["-I", "INPUT", "1", "-m", "state", "--state", "NEW", "-m", p, "-p", p, "--dport", str(listen_port), "-j", "ACCEPT"]
        iptables_ensure(pre, pre_add)
        iptables_ensure(post, post_add)
        iptables_ensure(inp, inp_add)
    persist_rules()


def check_forward_conflict(proto, listen_port, target_ip, target_port, ignore=None):
    ignore = ignore or []
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    for rule in list_forward_rules():
        rule_key = (
            rule["proto"],
            rule["listen_port"],
            rule["target_ip"],
            rule["target_port"],
        )
        if rule_key in ignore:
            continue
        if rule["proto"] in protos and rule["listen_port"] == listen_port:
            same_target = rule["target_ip"] == target_ip and rule["target_port"] == target_port
            if not same_target:
                raise ValueError(
                    f"{rule['proto'].upper()} 监听端口 {listen_port} 已转发到 {rule['target_ip']}:{rule['target_port']}，不能重复指向不同目标"
                )


def delete_forward(proto, listen_port, target_ip, target_port, to_source):
    to_source = to_source or current_source_ip()
    pre = ["-t", "nat", "-D", "PREROUTING", "-p", proto, "--dport", str(listen_port), "-j", "DNAT", "--to-destination", f"{target_ip}:{target_port}"]
    post = ["-t", "nat", "-D", "POSTROUTING", "-p", proto, "-d", target_ip, "--dport", str(target_port), "-j", "SNAT", "--to-source", to_source]
    inp = ["-D", "INPUT", "-m", "state", "--state", "NEW", "-m", proto, "-p", proto, "--dport", str(listen_port), "-j", "ACCEPT"]
    for args in (pre, post, inp):
        run(["iptables"] + args)
    persist_rules()


def persist_rules():
    saved = run(["iptables-save"], check=True).stdout
    with open(IPTABLES_BACKUP, "w", encoding="utf-8") as f:
        f.write(saved)


def fmt_bytes(value):
    value = float(value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def fmt_rate(value):
    return fmt_bytes(value) + "/s"


def fmt_mbps(value):
    return f"{value * 8 / 1000 / 1000:.2f} Mbps"


def metrics():
    mem = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            k, v = line.split(":", 1)
            mem[k] = int(v.strip().split()[0]) * 1024
    disk = shutil.disk_usage("/")
    rx = tx = 0
    with open("/proc/net/dev", "r", encoding="utf-8") as f:
        for line in f.readlines()[2:]:
            name, data = line.split(":", 1)
            if name.strip() == "lo":
                continue
            vals = data.split()
            rx += int(vals[0])
            tx += int(vals[8])
    states = {}
    ss = run(["ss", "-Hant"]).stdout.splitlines()
    for line in ss:
        state = line.split()[0] if line.split() else "UNKNOWN"
        states[state] = states.get(state, 0) + 1
    uptime = int(float(open("/proc/uptime", "r", encoding="utf-8").read().split()[0]))
    now = time.time()
    if BANDWIDTH_STATE["time"] <= 0:
        BANDWIDTH_STATE["time"] = now
        BANDWIDTH_STATE["rx"] = rx
        BANDWIDTH_STATE["tx"] = tx
    else:
        elapsed = now - BANDWIDTH_STATE["time"]
        if elapsed >= 1.5:
            BANDWIDTH_STATE["rx_rate"] = max(rx - BANDWIDTH_STATE["rx"], 0) / elapsed
            BANDWIDTH_STATE["tx_rate"] = max(tx - BANDWIDTH_STATE["tx"], 0) / elapsed
            BANDWIDTH_STATE["time"] = now
            BANDWIDTH_STATE["rx"] = rx
            BANDWIDTH_STATE["tx"] = tx
    return {
        "load": os.getloadavg(),
        "mem_used": mem.get("MemTotal", 0) - mem.get("MemAvailable", 0),
        "mem_total": mem.get("MemTotal", 0),
        "disk_used": disk.used,
        "disk_total": disk.total,
        "rx": rx,
        "tx": tx,
        "rx_rate": BANDWIDTH_STATE["rx_rate"],
        "tx_rate": BANDWIDTH_STATE["tx_rate"],
        "conn_states": states,
        "uptime": uptime,
    }


def status_payload():
    m = metrics()
    state_items = [
        f"{TCP_STATE_NAMES.get(k, k)}: {v}" for k, v in sorted(m["conn_states"].items())
    ]
    states = "，".join(state_items) or "无"
    state_html = "".join(
        f'<span class="state-pill">{html.escape(item)}</span>' for item in state_items
    ) or '<span class="state-pill">无</span>'
    return {
        "load": f"{m['load'][0]:.2f} / {m['load'][1]:.2f} / {m['load'][2]:.2f}",
        "memory": f"{fmt_bytes(m['mem_used'])} / {fmt_bytes(m['mem_total'])}",
        "disk": f"{fmt_bytes(m['disk_used'])} / {fmt_bytes(m['disk_total'])}",
        "traffic": f"入 {fmt_bytes(m['rx'])}<br>出 {fmt_bytes(m['tx'])}",
        "rx_rate": fmt_rate(m["rx_rate"]),
        "tx_rate": fmt_rate(m["tx_rate"]),
        "total_rate": fmt_rate(m["rx_rate"] + m["tx_rate"]),
        "rx_mbps": fmt_mbps(m["rx_rate"]),
        "tx_mbps": fmt_mbps(m["tx_rate"]),
        "total_mbps": fmt_mbps(m["rx_rate"] + m["tx_rate"]),
        "rx_total": "累计 " + fmt_bytes(m["rx"]),
        "tx_total": "累计 " + fmt_bytes(m["tx"]),
        "conn_states": states,
        "conn_states_html": state_html,
        "conn_total": sum(m["conn_states"].values()),
        "uptime": f"{m['uptime']//86400} 天 {(m['uptime']%86400)//3600} 小时",
        "updated_at": time.strftime("%H:%M:%S"),
    }


def page(title, body, user="", base="", shell=True):
    if not shell:
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录</title>
<style>
body{{margin:0;background:#f5f7fb;color:#111827;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;box-shadow:0 1px 2px #0000000d}}
input{{height:36px;border:1px solid #d1d5db;border-radius:6px;padding:0 10px;width:100%;box-sizing:border-box}}button{{height:36px;border:0;border-radius:6px;background:#2563eb;color:white;padding:0 14px;cursor:pointer}}label{{display:flex;flex-direction:column;gap:6px;font-size:13px;color:#374151}}
</style></head><body>{body}</body></html>"""
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>管理面板</title>
<style>
body{{margin:0;background:#eef1f6;color:#171b26;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}}
header{{height:52px;background:#111827;color:#fff;display:flex;align-items:center;justify-content:flex-end;padding:0 22px;position:sticky;top:0;z-index:3;border-bottom:1px solid #202a3a}}
.layout{{display:grid;grid-template-columns:210px 1fr;min-height:calc(100vh - 52px)}}
aside{{background:#151c2c;color:#cbd5e1;padding:18px 14px;position:sticky;top:52px;height:calc(100vh - 88px)}}
.brand{{font-size:13px;color:#94a3b8;margin:0 0 16px 10px}}nav a{{display:block;color:#cbd5e1;text-decoration:none;padding:11px 12px;border-radius:8px;margin-bottom:7px;font-weight:600}}nav a:hover{{background:#233047;color:#fff}}.stamp{{color:#94a3b8;font-size:12px;margin:18px 10px}}
main{{max-width:1120px;width:100%;margin:0 auto;padding:22px 16px 40px}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card{{background:#fff;border:1px solid #e7eaf0;border-radius:8px;padding:16px;box-shadow:0 1px 2px #1018280a}}
.hero{{margin-bottom:14px;background:linear-gradient(135deg,#ffffff,#eef4ff);border-color:#dbe7ff}}.hero .value{{font-size:30px;color:#111827}}.node{{border-radius:12px;background:#fff;border:1px solid #e7eaf0;padding:18px;margin-top:14px;box-shadow:0 10px 24px #1018280a}}.node-head{{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}}.badge{{background:#dcfce7;color:#16a34a;border-radius:999px;padding:5px 10px;font-weight:700;font-size:13px}}.stats3{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:12px 0}}.tile{{background:#f7f9fc;border:1px solid #e8edf5;border-radius:9px;padding:11px}}.tile.primary{{background:#eef3ff;border-color:#c9d8ff;color:#1d4ed8}}.band{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:12px 0}}.band .tile{{display:flex;justify-content:space-between;align-items:center}}.band .value{{font-size:20px;color:#111827}}.progress{{height:7px;background:#e5e7eb;border-radius:999px;overflow:hidden;margin:8px 0 12px}}.progress span{{display:block;height:100%;background:#2563eb;border-radius:999px}}.state-list{{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}}.state-pill{{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:999px;padding:6px 10px;font-size:13px;color:#334155}}
.rule-card{{background:#fff;border:1px solid #e7eaf0;border-radius:12px;overflow:hidden;box-shadow:0 10px 24px #1018280a}}table{{width:100%;border-collapse:collapse}}th,td{{padding:13px 12px;border-bottom:1px solid #eef2f7;text-align:left;font-size:14px}}th{{background:#f8fafc;color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}tbody tr:hover{{background:#fbfdff}}.proto{{display:inline-flex;align-items:center;border-radius:999px;background:#eff6ff;color:#1d4ed8;font-weight:800;padding:5px 9px;text-transform:uppercase;font-size:12px}}.target{{font-weight:700;color:#111827}}.edit-row{{display:none;background:#f8fbff}}.edit-row.open{{display:table-row}}.edit-box{{display:flex;gap:10px;align-items:end;flex-wrap:wrap;padding:12px 0}}.ghost{{background:#eef2ff;color:#1d4ed8}}input,select{{height:36px;border:1px solid #d1d5db;border-radius:6px;padding:0 10px}}button,.btn{{height:36px;border:0;border-radius:6px;background:#1f5eff;color:white;padding:0 14px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;font-weight:700}}.danger{{background:#dc2626}}.muted{{color:#6b7280}}.value{{margin:6px 0 0;font-size:22px;line-height:1.25;font-weight:800}}.small{{font-size:12px;color:#8a94a6}}form.inline{{display:inline}}.row{{display:flex;gap:10px;flex-wrap:wrap;align-items:end}}label{{display:flex;flex-direction:column;gap:6px;font-size:13px;color:#374151}}.msg{{padding:10px 12px;background:#ecfdf5;color:#065f46;border:1px solid #a7f3d0;border-radius:8px;margin-bottom:12px}}section{{scroll-margin-top:76px}}@media(max-width:800px){{.layout{{grid-template-columns:1fr}}aside{{position:static;height:auto}}.grid,.stats3,.band{{grid-template-columns:1fr}}th:nth-child(5),td:nth-child(5),th:nth-child(6),td:nth-child(6),th:nth-child(7),td:nth-child(7){{display:none}}}}
</style></head><body><header><div>{html.escape(user)} <a style="color:#bfdbfe;margin-left:16px" href="{base}/logout">退出</a></div></header><div class="layout"><aside><p class="brand">SERVER</p><nav><a href="#overview">实时概览</a><a href="#rules">端口转发</a><a href="#add">新增规则</a><a href="#settings">面板设置</a></nav><p class="stamp">最后更新：<span id="updated_at">--</span></p></aside><main>{body}</main></div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_html(self, content, code=200):
        data = content.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, payload, code=200):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def not_found(self):
        self.send_html("404", 404)

    def redirect(self, path):
        self.send_response(302)
        self.send_header("Location", path)
        self.end_headers()

    def base(self):
        token = load_config().get("path_token", "")
        return "/" + token.strip("/")

    def routed_path(self):
        raw = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        base = self.base()
        if raw == base:
            return "/", base
        if raw.startswith(base + "/"):
            sub = raw[len(base):]
            return sub.rstrip("/") or "/", base
        return None, base

    def form(self):
        size = int(self.headers.get("Content-Length", "0") or 0)
        return urllib.parse.parse_qs(self.rfile.read(size).decode("utf-8"), keep_blank_values=True)

    def field(self, form, name, default=""):
        return form.get(name, [default])[0].strip()

    def authed(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        sid = c.get("sid")
        return bool(sid and verify_session_cookie(sid.value, load_config()))

    def require_auth(self):
        if not self.authed():
            self.redirect(self.base() + "/login")
            return False
        return True

    def do_GET(self):
        path, base = self.routed_path()
        if path is None:
            self.not_found()
            return
        if path == "/login":
            body = f"""<div class="card" style="max-width:360px;margin:80px auto"><h2>登录</h2><form method="post" action="{base}/login"><label>账号<input name="username" autofocus></label><br><label>密码<input name="password" type="password"></label><br><button>登录</button></form></div>"""
            self.send_html(page("登录", body, "", base, shell=False))
            return
        if path == "/logout":
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            if c.get("sid"):
                SESSIONS.pop(c["sid"].value, None)
            self.send_response(302)
            self.send_header("Location", base + "/login")
            self.send_header("Set-Cookie", "sid=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
            self.end_headers()
            return
        if not self.require_auth():
            return
        if path == "/api/status":
            self.send_json(status_payload())
            return
        cfg = load_config()
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg = html.escape(query.get("msg", [""])[0])
        rules = list_forward_rules()
        s = status_payload()
        row_parts = []
        for idx, r in enumerate(rules):
            rid = f"edit-{idx}"
            target_ip = html.escape(r["target_ip"])
            to_source = html.escape(r.get("to_source", ""))
            rule_name = html.escape(get_rule_name(cfg, r["proto"], r["listen_port"], r["target_ip"], r["target_port"]))
            name_cell = rule_name or '<span class="muted">未命名</span>'
            row_parts.append(f"""<tr><td><strong>{name_cell}</strong></td><td><span class="proto">{r['proto']}</span></td><td><strong>{r['listen_port']}</strong></td><td><span class="target">{target_ip}:{r['target_port']}</span></td><td>{to_source}</td><td>{r['pkts']}</td><td>{fmt_bytes(r['bytes'])}</td><td><button class="ghost" type="button" onclick="toggleEdit('{rid}')">编辑</button> <form class="inline" method="post" action="{base}/delete"><input type="hidden" name="proto" value="{r['proto']}"><input type="hidden" name="listen_port" value="{r['listen_port']}"><input type="hidden" name="target_ip" value="{target_ip}"><input type="hidden" name="target_port" value="{r['target_port']}"><input type="hidden" name="to_source" value="{to_source}"><button class="danger" onclick="return confirm('确认删除这条规则？')">删除</button></form></td></tr>""")
            row_parts.append(f"""<tr id="{rid}" class="edit-row"><td colspan="8"><form method="post" action="{base}/edit" class="edit-box">
<input type="hidden" name="old_proto" value="{r['proto']}"><input type="hidden" name="old_listen_port" value="{r['listen_port']}"><input type="hidden" name="old_target_ip" value="{target_ip}"><input type="hidden" name="old_target_port" value="{r['target_port']}"><input type="hidden" name="old_to_source" value="{to_source}">
<label>名称<input name="name" value="{rule_name}" placeholder="例如 香港转发"></label>
<label>协议<select name="proto"><option value="tcp" {'selected' if r['proto'] == 'tcp' else ''}>TCP</option><option value="udp" {'selected' if r['proto'] == 'udp' else ''}>UDP</option></select></label>
<label>监听端口<input name="listen_port" value="{r['listen_port']}" required></label>
<label>目标 IP<input name="target_ip" value="{target_ip}" required></label>
<label>目标端口<input name="target_port" value="{r['target_port']}" required></label>
<button>保存</button><button class="ghost" type="button" onclick="toggleEdit('{rid}')">取消</button>
</form></td></tr>""")
        rows = "".join(row_parts)
        body = (f'<div class="msg" style="display:{"block" if msg else "none"}">{msg}</div>'
                f"""<section id="overview">
<div class="card hero"><div class="muted">服务器实时带宽</div><div class="value" id="total_rate">{html.escape(s['total_rate'])}</div><div class="small">约 <span id="total_mbps">{html.escape(s['total_mbps'])}</span>，上行 + 下行，每 2 秒自动刷新</div></div>
<div class="node">
  <div class="node-head"><div><div class="small"># 当前服务器</div><h2 style="margin:8px 0 0">转发节点 <span class="muted" style="font-size:16px">在线</span></h2></div><span class="badge">● 在线</span></div>
  <div class="stats3">
    <div class="tile"><div class="small">监听规则</div><div class="value">{len(rules)}</div></div>
    <div class="tile primary"><div class="small">活跃连接</div><div class="value" id="conn_total">{s['conn_total']}</div></div>
    <div class="tile"><div class="small">运行时间</div><div class="value" id="uptime">{html.escape(s['uptime'])}</div></div>
  </div>
  <div class="band">
    <div class="tile"><div><strong>↑ 实时上行</strong><div class="small" id="tx_total">{html.escape(s['tx_total'])}</div><div class="small" id="tx_mbps">{html.escape(s['tx_mbps'])}</div></div><div class="value" id="tx_rate">{html.escape(s['tx_rate'])}</div></div>
    <div class="tile"><div><strong>↓ 实时下行</strong><div class="small" id="rx_total">{html.escape(s['rx_total'])}</div><div class="small" id="rx_mbps">{html.escape(s['rx_mbps'])}</div></div><div class="value" id="rx_rate">{html.escape(s['rx_rate'])}</div></div>
  </div>
  <div class="tile"><div style="display:flex;justify-content:space-between"><span>负载</span><strong id="load">{html.escape(s['load'])}</strong></div><div class="progress"><span style="width:35%"></span></div>
  <div style="display:flex;justify-content:space-between"><span>内存</span><strong id="memory">{html.escape(s['memory'])}</strong></div><div class="progress"><span style="width:19%"></span></div>
  <div style="display:flex;justify-content:space-between"><span>磁盘</span><strong id="disk">{html.escape(s['disk'])}</strong></div><div class="progress"><span style="width:4%"></span></div></div>
  <div class="card" style="margin-top:12px;box-shadow:none"><strong>连接状态</strong><div class="state-list" id="conn_states_html">{s['conn_states_html']}</div><p class="muted">累计流量：<span id="traffic">{s['traffic']}</span></p></div>
</div></section>
<section id="rules"><h2>端口转发规则</h2><div class="rule-card"><table><thead><tr><th>名称</th><th>协议</th><th>监听端口</th><th>转发目标</th><th>SNAT 源</th><th>包数</th><th>字节</th><th>操作</th></tr></thead><tbody>{rows or '<tr><td colspan="8">暂无规则</td></tr>'}</tbody></table></div></section>
<section id="add" class="card" style="margin-top:16px"><h3>新增转发</h3><form method="post" action="{base}/add" class="row"><label>名称<input name="name" placeholder="例如 香港转发"></label><label>协议<select name="proto"><option value="both">TCP+UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label>监听端口<input name="listen_port" required></label><label>目标 IP<input name="target_ip" required></label><label>目标端口<input name="target_port" required></label><button>添加</button></form></section>
<section id="settings" class="card" style="margin-top:16px"><h3>面板设置</h3><form method="post" action="{base}/settings" class="row"><label>账号<input name="username" value="{html.escape(cfg.get('username','admin'))}"></label><label>监听端口<input name="listen_port" value="{int(cfg.get('listen_port', DEFAULT_PORT))}"></label><button>保存设置</button><span class="muted">端口修改后需要重启服务生效。</span></form><hr><form method="post" action="{base}/password" class="row"><label>新密码<input type="password" name="password" required></label><button>修改密码</button></form></section>
<script>
function toggleEdit(id) {{
  const row = document.getElementById(id);
  if (row) row.classList.toggle("open");
}}
async function refreshStatus() {{
  try {{
    const res = await fetch("{base}/api/status", {{cache: "no-store"}});
    if (!res.ok) return;
    const s = await res.json();
    for (const id of ["load", "memory", "disk", "traffic", "conn_states_html", "uptime", "updated_at", "rx_rate", "tx_rate", "total_rate", "rx_mbps", "tx_mbps", "total_mbps", "rx_total", "tx_total", "conn_total"]) {{
      const el = document.getElementById(id);
      if (el && s[id] !== undefined) el.innerHTML = s[id];
    }}
  }} catch (e) {{}}
}}
refreshStatus();
setInterval(refreshStatus, 2000);
if (window.location.search.includes("msg=")) {{
  const cleanUrl = window.location.pathname + window.location.hash;
  window.history.replaceState(null, "", cleanUrl);
}}
</script>""")
        self.send_html(page("管理面板", body, cfg.get("username", ""), base))

    def do_POST(self):
        cfg = load_config()
        path, base = self.routed_path()
        if path is None:
            self.not_found()
            return
        if path == "/login":
            form = self.form()
            if self.field(form, "username") == cfg.get("username") and verify_password(self.field(form, "password"), cfg.get("password_hash", "")):
                sid = make_session_cookie(cfg, cfg.get("username", DEFAULT_USER))
                self.send_response(302)
                self.send_header("Location", base + "/")
                self.send_header("Set-Cookie", f"sid={sid}; Max-Age=604800; HttpOnly; SameSite=Lax; Path=/")
                self.end_headers()
            else:
                self.redirect(base + "/login?err=1")
            return
        if not self.require_auth():
            return
        try:
            form = self.form()
            if path == "/add":
                proto = self.field(form, "proto")
                if proto not in ("tcp", "udp", "both"):
                    raise ValueError("协议不正确")
                listen_port = validate_port(self.field(form, "listen_port"))
                target_ip = validate_ip(self.field(form, "target_ip"))
                target_port = validate_port(self.field(form, "target_port"))
                add_forward(proto, listen_port, target_ip, target_port)
                name = clean_name(self.field(form, "name"))
                if name:
                    for p in (["tcp", "udp"] if proto == "both" else [proto]):
                        set_rule_name(p, listen_port, target_ip, target_port, name)
                self.redirect(base + "/?msg=" + urllib.parse.quote("添加成功"))
            elif path == "/delete":
                proto = self.field(form, "proto")
                listen_port = validate_port(self.field(form, "listen_port"))
                target_ip = validate_ip(self.field(form, "target_ip"))
                target_port = validate_port(self.field(form, "target_port"))
                delete_forward(proto, listen_port, target_ip, target_port, self.field(form, "to_source"))
                remove_rule_name(proto, listen_port, target_ip, target_port)
                self.redirect(base + "/?msg=" + urllib.parse.quote("删除成功"))
            elif path == "/edit":
                old_proto = self.field(form, "old_proto")
                old_listen_port = validate_port(self.field(form, "old_listen_port"))
                old_target_ip = validate_ip(self.field(form, "old_target_ip"))
                old_target_port = validate_port(self.field(form, "old_target_port"))
                old_to_source = self.field(form, "old_to_source")
                proto = self.field(form, "proto")
                if proto not in ("tcp", "udp"):
                    raise ValueError("协议不正确")
                listen_port = validate_port(self.field(form, "listen_port"))
                target_ip = validate_ip(self.field(form, "target_ip"))
                target_port = validate_port(self.field(form, "target_port"))
                name = clean_name(self.field(form, "name"))
                check_forward_conflict(
                    proto,
                    listen_port,
                    target_ip,
                    target_port,
                    ignore=[(old_proto, old_listen_port, old_target_ip, old_target_port)],
                )
                delete_forward(old_proto, old_listen_port, old_target_ip, old_target_port, old_to_source)
                remove_rule_name(old_proto, old_listen_port, old_target_ip, old_target_port)
                add_forward(proto, listen_port, target_ip, target_port)
                set_rule_name(proto, listen_port, target_ip, target_port, name)
                self.redirect(base + "/?msg=" + urllib.parse.quote("编辑成功"))
            elif path == "/settings":
                cfg["username"] = self.field(form, "username") or cfg.get("username", DEFAULT_USER)
                cfg["listen_port"] = validate_port(self.field(form, "listen_port"))
                save_config(cfg)
                self.redirect(base + "/?msg=" + urllib.parse.quote("设置已保存，端口修改后重启服务生效"))
            elif path == "/password":
                cfg["password_hash"] = hash_password(self.field(form, "password"))
                save_config(cfg)
                self.redirect(base + "/?msg=" + urllib.parse.quote("密码已修改"))
            else:
                self.redirect(base + "/")
        except Exception as e:
            self.redirect(base + "/?msg=" + urllib.parse.quote("操作失败：" + str(e)))


def main():
    cfg = load_config()
    try:
        set_ip_forward()
        persist_rules()
    except Exception:
        pass
    server = ThreadingHTTPServer((cfg.get("listen_host", "0.0.0.0"), int(cfg.get("listen_port", DEFAULT_PORT))), Handler)
    server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "init-config":
        if len(sys.argv) < 5:
            print("usage: wkplane.py init-config <username> <password> <port> [path_token]", file=sys.stderr)
            sys.exit(2)
        cfg = init_config(sys.argv[2], sys.argv[3], validate_port(sys.argv[4]), sys.argv[5] if len(sys.argv) > 5 else "")
        print(json.dumps({
            "username": cfg["username"],
            "port": cfg["listen_port"],
            "path_token": cfg["path_token"],
        }, ensure_ascii=False))
        sys.exit(0)
    main()
