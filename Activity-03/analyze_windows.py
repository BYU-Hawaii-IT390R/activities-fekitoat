"""Windows Admin Toolkit – updated version
------------------------------------------
Requires pywin32 (pip install pywin32) and works on Win10/11.

Tasks:
- win-events: Failed & successful logons from Security log
- win-pkgs: Lists installed software (DisplayName + Version)
- win-services: Checks / auto-restarts critical services
- win-startup: Lists startup items from registry (NEW)
- win-firewall: Shows inbound firewall rules allowing 0.0.0.0/0 (NEW)

Example:
    python analyze_windows.py --task win-startup
    python analyze_windows.py --task win-firewall
"""

from __future__ import annotations
import argparse
import collections
import csv
import datetime as _dt
import io
import re
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    import win32evtlog  # type: ignore
    import winreg
except ImportError:
    sys.stderr.write("pywin32 required → pip install pywin32\n")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────
SECURITY_CHANNEL = "Security"
EVENT_FAILED = "4625"
EVENT_SUCCESS = "4624"
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

def _print_counter(counter: dict, h1: str, h2: str):
    if not counter:
        print("(no data)\n")
        return
    width = max(len(str(k)) for k in counter)
    print(f"{h1:<{width}} {h2:>8}")
    print("-" * (width + 9))
    for k, v in sorted(counter.items(), key=lambda item: item[1], reverse=True):
        print(f"{k:<{width}} {v:>8}")
    print()

# ── Task 1: Event log analysis ────────────────────────────────────────────
def _query_security_xml(hours_back: int):
    delta_sec = hours_back * 3600
    q = (
        f"*[(System/TimeCreated[timediff(@SystemTime) <= {delta_sec}] "
        f"and (System/EventID={EVENT_FAILED} or System/EventID={EVENT_SUCCESS}))]"
    )
    try:
        h = win32evtlog.EvtQuery(SECURITY_CHANNEL, win32evtlog.EvtQueryReverseDirection, q)
    except Exception as e:
        if getattr(e, "winerror", None) == 5:
            sys.exit("❌ Access denied – run as Administrator or add to Event Log Readers.")
        raise
    while True:
        try:
            ev = win32evtlog.EvtNext(h, 1)[0]
        except IndexError:
            break
        yield win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)

def _parse_event(xml_str: str):
    root = ET.fromstring(xml_str)
    eid = root.findtext("./System/EventID")
    data = {n.attrib.get("Name"): n.text for n in root.findall("./EventData/Data")}
    user = data.get("TargetUserName") or data.get("SubjectUserName") or "?"
    ip = data.get("IpAddress") or "?"
    if ip == "?":
        m = IP_RE.search(xml_str)
        if m:
            ip = m.group()
    return eid, user, ip

def win_events(hours_back: int, min_count: int):
    failed = collections.Counter()
    success = collections.defaultdict(set)
    for xml_str in _query_security_xml(hours_back):
        eid, user, ip = _parse_event(xml_str)
        if eid == EVENT_FAILED and ip != "?":
            failed[ip] += 1
        elif eid == EVENT_SUCCESS and user not in ("-", "?"):
            success[user].add(ip)

    print(f"\n❌ Failed logons ≥{min_count} (last {hours_back}h)")
    _print_counter({ip: c for ip, c in failed.items() if c >= min_count}, "Source IP", "Count")

    print(f"✅ Successful logons ≥{min_count} IPs (last {hours_back}h)")
    succ = {u: ips for u, ips in success.items() if len(ips) >= min_count}
    width = max((len(u) for u in succ), default=8)
    print(f"{'Username':<{width}} {'IPs':>8}")
    print("-" * (width + 9))
    for user, ips in sorted(succ.items(), key=lambda item: len(item[1]), reverse=True):
        print(f"{user:<{width}} {len(ips):>8}")
    print()

# ── Task 2: Installed software ────────────────────────────────────────────
UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
]

def win_pkgs(csv_path: str | None):
    rows = []
    for root, path in UNINSTALL_PATHS:
        try:
            hive = winreg.OpenKey(root, path)
        except FileNotFoundError:
            continue
        for i in range(winreg.QueryInfoKey(hive)[0]):
            try:
                sub = winreg.OpenKey(hive, winreg.EnumKey(hive, i))
                name, _ = winreg.QueryValueEx(sub, "DisplayName")
                ver, _ = winreg.QueryValueEx(sub, "DisplayVersion")
                rows.append((name, ver))
            except FileNotFoundError:
                continue
    print(f"\n🗃 Installed software ({len(rows)} entries)")
    width = max(len(n) for n, _ in rows)
    print(f"{'DisplayName':<{width}} Version")
    print("-" * (width + 8))
    for name, ver in sorted(rows):
        print(f"{name:<{width}} {ver}")
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)
        print(f"📑 CSV exported → {csv_path}")

# ── Task 3: Service status ────────────────────────────────────────────────
COLOR_OK = "\033[92m"
COLOR_BAD = "\033[91m"
COLOR_RESET = "\033[0m"

def _service_state(name: str) -> str:
    out = subprocess.check_output(["sc", "query", name], text=True, stderr=subprocess.STDOUT)
    return "RUNNING" if "RUNNING" in out else "STOPPED"

def win_services(watch: list[str], auto_fix: bool):
    if not watch:
        watch = ["Spooler", "wuauserv"]
    print("\n🩺 Service status")
    for svc in watch:
        state = _service_state(svc)
        ok = state == "RUNNING"
        colour = COLOR_OK if ok else COLOR_BAD
        print(f"{svc:<20} {colour}{state}{COLOR_RESET}")
        if not ok and auto_fix:
            print(f"  ↳ attempting to start {svc} …", end="")
            subprocess.call(["sc", "start", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            state = _service_state(svc)
            print("done" if state == "RUNNING" else "failed")

# ── Task 4: Startup programs (NEW) ─────────────────────────────────────────
def win_startup():
    print("\n🚀 Startup items (HKCU\\...\\Run)")
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    except PermissionError:
        print("❌ Access denied – run as Administrator.")
        return
    except FileNotFoundError:
        print("(No startup items found)")
        return
    items = []
    for i in range(winreg.QueryInfoKey(key)[1]):
        try:
            name, value, _ = winreg.EnumValue(key, i)
            items.append((name, value))
        except OSError:
            continue
    if not items:
        print("(No startup items found)")
    else:
        width = max(len(name) for name, _ in items)
        print(f"{'Name':<{width}} Command")
        print("-" * (width + 8))
        for name, cmd in items:
            print(f"{name:<{width}} {cmd}")

# Copilot snippet: used winreg to enumerate registry values under Run key

# ── Task 5: Firewall rules (NEW) ───────────────────────────────────────────
def win_firewall():
    print("\n🛡️ Inbound firewall rules allowing 0.0.0.0/0")
    try:
        result = subprocess.check_output(
            ["powershell", "-Command",
             "Get-NetFirewallRule -Direction Inbound | "
             "Where-Object { $_.Enabled -eq 'True' } | "
             "Get-NetFirewallAddressFilter | "
             "Where-Object { $_.RemoteAddress -eq '0.0.0.0/0' } | "
             "Format-Table -AutoSize"],
            text=True, stderr=subprocess.STDOUT
        )
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to query firewall rules: {e}")

# Copilot snippet: PowerShell firewall rule query using Get-NetFirewallRule

# ── CLI ───────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="Windows admin toolkit (IT 390R)")
    p.add_argument("--task", required=True,
               choices=["win-events", "win-pkgs", "win-services", "win-startup", "win-firewall"],
               help="Which analysis to run")
    p.add_argument("--hours", type=int, default=24,
                   help="Look-back window (win-events)")
    p.add_argument("--min-count", type=int, default=1,
                   help="Min count to show (win-events)")
    p.add_argument("--csv", metavar="FILE", default=None,
                   help="Export to CSV (win-pkgs)")
    p.add_argument("--watch", nargs="*", metavar="SVC", default=[],
                   help="Service names to check (win-services)")
    p.add_argument("--fix", action="store_true",
                   help="Attempt to start stopped services (win-services)")
    args = p.parse_args()

    if args.task == "win-events":
        win_events(args.hours, args.min_count)
    elif args.task == "win-pkgs":
        win_pkgs(args.csv)
    elif args.task == "win-services":
        win_services(args.watch, args.fix)
    elif args.task == "win-startup":
        win_startup()
    elif args.task == "win-firewall":
        win_firewall()

if __name__ == "__main__":
    main()
