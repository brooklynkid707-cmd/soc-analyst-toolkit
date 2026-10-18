#!/usr/bin/env python3
"""Generate every synthetic dataset used by soctk.

All addresses are RFC 5737 documentation ranges or RFC 1918 private space;
all domains are example.com / example.net / invented lookalikes. The random
seed is fixed so the committed samples are reproducible.

Usage:
    python scripts/generate_sample_data.py [--out data] [--seed 42] [--alerts 60]
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import random
import zipfile
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

BASE = datetime(2026, 10, 14, 6, 0, 0, tzinfo=timezone.utc)

HOSTS = {
    "WS-FIN-017": ("high", "finance"), "WS-FIN-022": ("high", "finance"), "WS-ENG-104": ("medium", "engineering"),
    "WS-ENG-118": ("medium", "engineering"), "WS-HR-003": ("medium", "hr"), "WS-MKT-041": ("low", "marketing"),
    "WS-MKT-045": ("low", "marketing"), "LT-EXEC-001": ("crown-jewel", "executive"), "LT-SALES-071": ("low", "sales"),
    "SRV-DC-01": ("crown-jewel", "it"), "SRV-FILE-02": ("high", "it"), "SRV-WEB-03": ("high", "it"),
    "SRV-DB-04": ("crown-jewel", "it"), "SRV-JUMP-05": ("high", "it"), "SRV-BKP-06": ("crown-jewel", "it"),
}
USERS = {
    "mrivera": ("medium", "finance"), "jchen": ("low", "finance"), "akowalski": ("low", "engineering"),
    "dpatel": ("low", "engineering"), "sokafor": ("medium", "hr"), "lnguyen": ("low", "marketing"),
    "bthompson": ("low", "marketing"), "ceo.vharlan": ("high", "executive"), "tgarcia": ("low", "sales"),
    "svc_backup": ("high", "it"), "svc_sql": ("high", "it"), "admin.rfoster": ("high", "it"), "helpdesk1": ("medium", "it"),
}
EXTERNAL_IPS = ["203.0.113.45", "203.0.113.77", "198.51.100.23", "198.51.100.90", "192.0.2.15", "192.0.2.200", "203.0.113.9"]
BAD_IPS = ["203.0.113.45", "198.51.100.23", "192.0.2.200"]
BAD_DOMAINS = ["update-service.example.net", "cdn-assets-example.com", "secure-login-example.com", "micros0ft-support.com"]

RULES = [
    # (rule, severity, confidence, technique, needs_external_ip, description)
    ("Brute force: 20+ failed logons from single source", "high", 0.85, "T1110", True, "Repeated 4625 events from one external IP against multiple accounts"),
    ("Impossible travel: logon from two countries in 1h", "high", 0.7, "T1078", True, "Successful logons from geographically distant IPs"),
    ("Suspicious PowerShell: encoded command", "high", 0.8, "T1059.001", False, "powershell.exe -enc with hidden window and bypass"),
    ("Office spawned shell process", "critical", 0.9, "T1204.002", False, "WINWORD.EXE spawned cmd.exe / powershell.exe"),
    ("EDR: credential dumping tool detected", "critical", 0.95, "T1003.001", False, "LSASS access by non-system process"),
    ("Outbound connection to known C2 indicator", "critical", 0.9, "T1071.001", True, "Beaconing to IP on threat feed"),
    ("Large outbound transfer to cloud storage", "medium", 0.6, "T1567.002", True, "> 500 MB to unsanctioned storage provider"),
    ("New scheduled task created", "medium", 0.5, "T1053.005", False, "schtasks /create by non-admin user"),
    ("Local admin group modified", "high", 0.75, "T1098", False, "net localgroup administrators /add"),
    ("Antivirus signature disabled", "high", 0.8, "T1562.001", False, "Defender real-time protection turned off"),
    ("Mass file rename with unusual extension", "critical", 0.9, "T1486", False, "500+ renames to .lockd in 60s on file share"),
    ("Volume shadow copy deletion", "critical", 0.95, "T1490", False, "vssadmin delete shadows /all /quiet"),
    ("Phishing e-mail reported by user", "medium", 0.5, "T1566.002", True, "User-reported message quarantined for review"),
    ("Port scan from internal host", "medium", 0.6, "T1046", False, "> 200 distinct ports in 30s"),
    ("Password spray: 1 failure per account across 50 accounts", "high", 0.8, "T1110.003", True, "Low-and-slow spray against OWA"),
    ("USB mass storage device connected", "low", 0.4, "T1052.001", False, "Removable media mounted"),
    ("DNS query to newly registered domain", "low", 0.45, "T1071.004", True, "Domain registered < 7 days ago"),
    ("Logon outside business hours", "low", 0.3, "T1078", False, "Interactive logon at 02:00-05:00 local"),
    ("Service account interactive logon", "medium", 0.65, "T1078.002", False, "svc_* account used for interactive logon"),
    ("Informational: software inventory change", "informational", 0.2, None, False, "New application installed"),
]


def write_lookups(out: Path) -> None:
    with (out / "assets.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["hostname", "criticality", "owner", "ip", "os"])
        for i, (h, (crit, owner)) in enumerate(HOSTS.items()):
            os_name = "Windows Server 2022" if h.startswith("SRV") else "Windows 11"
            w.writerow([h, crit, owner, f"10.10.{1 if h.startswith('SRV') else 20}.{10 + i}", os_name])
    with (out / "users.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["username", "risk", "department", "title", "mfa_enrolled"])
        for u, (risk, dept) in USERS.items():
            title = "Service account" if u.startswith("svc_") else "Chief Executive" if u.startswith("ceo") else "Domain admin" if u.startswith("admin") else "Analyst"
            w.writerow([u, risk, dept, title, "false" if u.startswith("svc_") else "true"])
    (out / "protected_domains.txt").write_text(
        "# Domains the organisation and its key vendors send mail from; lookalikes of these are flagged\n"
        "example.com\ncorp.example.com\nexample-bank.com\nmicrosoft.com\npaypal.com\ndocusign.com\nokta.com\n"
    )
    (out / "vips.txt").write_text(
        "# Executives and roles whose display names are commonly impersonated in BEC\n"
        "Victoria Harlan\nV. Harlan\nRaymond Foster\nMaria Rivera\n"
    )


def write_threat_intel(out: Path) -> None:
    ti = out / "threat_intel"
    ti.mkdir(exist_ok=True)
    rows = [
        ("203.0.113.45", "ipv4", "malicious", "internal-honeypot", "c2,cobalt-strike", "2026-10-01"),
        ("198.51.100.23", "ipv4", "malicious", "partner-isac", "brute-force,scanner", "2026-09-28"),
        ("192.0.2.200", "ipv4", "suspicious", "open-feed", "tor-exit", "2026-10-10"),
        ("update-service.example.net", "domain", "malicious", "internal-honeypot", "c2,dga", "2026-10-03"),
        ("cdn-assets-example.com", "domain", "malicious", "partner-isac", "phishing,credential-harvest", "2026-10-05"),
        ("secure-login-example.com", "domain", "malicious", "user-report", "phishing", "2026-10-12"),
        ("micros0ft-support.com", "domain", "malicious", "user-report", "phishing,lookalike", "2026-10-12"),
        ("hxxp://update-service[.]example[.]net/gate.php", "url", "malicious", "sandbox", "c2-checkin", "2026-10-03"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256", "benign", "nsrl", "empty-file", "2020-01-01"),
        ("44d88612fea8a8f36de82e1278abb02f", "md5", "malicious", "eicar", "test-file", "2020-01-01"),
        ("3395856ce81f2b7382dee72602f798b642f14140", "sha1", "malicious", "eicar", "test-file", "2020-01-01"),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256", "malicious", "eicar", "test-file", "2020-01-01"),
        ("invoice-team@cdn-assets-example.com", "email", "malicious", "user-report", "phishing-sender", "2026-10-05"),
        ("CVE-2024-21413", "cve", "exploited", "cisa-kev", "outlook,monikerlink", "2024-02-13"),
    ]
    with (ti / "feed.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["indicator", "type", "verdict", "source", "tags", "first_seen"])
        w.writerows(rows)


def write_alerts(out: Path, rng: random.Random, n: int) -> None:
    hosts = list(HOSTS)
    users = list(USERS)
    alerts = []
    aid = 1000

    def mk(ts: datetime, rule_idx: int, host: str | None, user: str | None, src_ip: str | None = None, dst_ip: str | None = None, conf: float | None = None) -> dict:
        nonlocal aid
        rule, sev, c, tech, _, desc = RULES[rule_idx]
        aid += 1
        return {
            "id": f"ALT-{aid}", "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "rule": rule, "severity": sev,
            "confidence": round(conf if conf is not None else min(1.0, max(0.1, c + rng.uniform(-0.1, 0.1))), 2),
            "host": host, "user": user, "src_ip": src_ip, "dst_ip": dst_ip, "attack_technique": tech, "description": desc,
            "source": "EDR" if rule_idx in (2, 3, 4, 9, 10, 11) else "SIEM",
        }

    # Scenario 1: phishing -> macro -> PowerShell -> C2 -> cred dump on a finance workstation (should group)
    t = BASE + timedelta(hours=2, minutes=14)
    alerts += [
        mk(t, 12, "WS-FIN-017", "mrivera", "203.0.113.77"),
        mk(t + timedelta(minutes=9), 3, "WS-FIN-017", "mrivera"),
        mk(t + timedelta(minutes=10), 2, "WS-FIN-017", "mrivera"),
        mk(t + timedelta(minutes=12), 5, "WS-FIN-017", "mrivera", "10.10.20.10", "203.0.113.45"),
        mk(t + timedelta(minutes=13), 5, "WS-FIN-017", "mrivera", "10.10.20.10", "203.0.113.45"),  # dup
        mk(t + timedelta(minutes=14), 5, "WS-FIN-017", "mrivera", "10.10.20.10", "203.0.113.45"),  # dup
        mk(t + timedelta(minutes=41), 4, "WS-FIN-017", "mrivera"),
        mk(t + timedelta(minutes=55), 8, "WS-FIN-017", "mrivera"),
    ]
    # Scenario 2: brute force from external IP against DC then a success + impossible travel (groups via IP + user)
    t = BASE + timedelta(hours=1, minutes=3)
    for k in range(6):  # noisy rule - same key within 10 min -> de-dup
        alerts.append(mk(t + timedelta(minutes=k), 0, "SRV-DC-01", None, "198.51.100.23"))
    alerts.append(mk(t + timedelta(minutes=25), 14, "SRV-DC-01", None, "198.51.100.23"))
    alerts.append(mk(t + timedelta(minutes=58), 1, None, "tgarcia", "198.51.100.23"))
    # Scenario 3: ransomware precursors on file server (crown-jewel-adjacent)
    t = BASE + timedelta(hours=4, minutes=30)
    alerts += [
        mk(t, 18, "SRV-FILE-02", "svc_backup"),
        mk(t + timedelta(minutes=6), 9, "SRV-FILE-02", "svc_backup"),
        mk(t + timedelta(minutes=8), 11, "SRV-FILE-02", "svc_backup"),
        mk(t + timedelta(minutes=9), 10, "SRV-FILE-02", "svc_backup"),
    ]
    # Scenario 4: exfil from exec laptop
    t = BASE + timedelta(hours=3, minutes=5)
    alerts += [
        mk(t, 16, "LT-EXEC-001", "ceo.vharlan", "10.10.20.17", "192.0.2.200"),
        mk(t + timedelta(minutes=20), 6, "LT-EXEC-001", "ceo.vharlan", "10.10.20.17", "192.0.2.200"),
    ]
    # Background noise: low-value alerts spread across the day
    # Users log on to machines owned by their own department, so pick a host and
    # then a user from the same department (service accounts stay on servers).
    noise_rules = [15, 16, 17, 19, 13, 7, 12]
    benign_ext = [ip for ip in EXTERNAL_IPS if ip not in BAD_IPS]
    while len(alerts) < n:
        ts = BASE + timedelta(minutes=rng.randint(0, 600))
        ri = rng.choice(noise_rules)
        host = rng.choice(hosts)
        dept = HOSTS[host][1]
        user = rng.choice([u for u, (_, d) in USERS.items() if d == dept] or users)
        ext = rng.choice(benign_ext) if RULES[ri][4] else None
        alerts.append(mk(ts, ri, host, user, src_ip=ext))
    alerts.sort(key=lambda a: a["timestamp"])
    (out / "alerts.json").write_text(json.dumps(alerts, indent=2) + "\n")


def write_logs(out: Path, rng: random.Random) -> None:
    logs = out / "logs"
    logs.mkdir(exist_ok=True)
    t0 = BASE + timedelta(hours=2)
    auth, proc, net, edr = [], [], [], []
    # Brute force then success against DC
    for i in range(12):
        auth.append({"timestamp": (BASE + timedelta(hours=1, minutes=3, seconds=i * 7)).isoformat(), "host": "SRV-DC-01",
                     "user": rng.choice(["administrator", "jchen", "tgarcia", "backup"]), "src_ip": "198.51.100.23",
                     "event_id": 4625, "logon_type": "Network", "outcome": "failure", "reason": "bad password"})
    auth.append({"timestamp": (BASE + timedelta(hours=2, minutes=1)).isoformat(), "host": "SRV-DC-01", "user": "tgarcia",
                 "src_ip": "198.51.100.23", "event_id": 4624, "logon_type": "Network", "outcome": "success", "reason": ""})
    # Phishing chain on WS-FIN-017
    auth.append({"timestamp": (t0 + timedelta(minutes=5)).isoformat(), "host": "WS-FIN-017", "user": "mrivera", "src_ip": "10.10.20.10",
                 "event_id": 4624, "logon_type": "Interactive", "outcome": "success", "reason": ""})
    proc += [
        {"timestamp": (t0 + timedelta(minutes=23)).isoformat(), "host": "WS-FIN-017", "user": "mrivera", "parent": "explorer.exe", "image": "OUTLOOK.EXE", "command_line": "OUTLOOK.EXE"},
        {"timestamp": (t0 + timedelta(minutes=23, seconds=40)).isoformat(), "host": "WS-FIN-017", "user": "mrivera", "parent": "OUTLOOK.EXE", "image": "WINWORD.EXE", "command_line": "WINWORD.EXE /n \"C:\\Users\\mrivera\\Downloads\\Invoice_Q3_8812.docm\""},
        {"timestamp": (t0 + timedelta(minutes=24, seconds=2)).isoformat(), "host": "WS-FIN-017", "user": "mrivera", "parent": "WINWORD.EXE", "image": "cmd.exe", "command_line": "cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "severity": "high"},
        {"timestamp": (t0 + timedelta(minutes=24, seconds=3)).isoformat(), "host": "WS-FIN-017", "user": "mrivera", "parent": "cmd.exe", "image": "powershell.exe", "command_line": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "severity": "high"},
        {"timestamp": (t0 + timedelta(minutes=26)).isoformat(), "host": "WS-FIN-017", "user": "mrivera", "parent": "powershell.exe", "image": "rundll32.exe", "command_line": "rundll32.exe C:\\Users\\Public\\upd.dll,Start", "severity": "high"},
        {"timestamp": (t0 + timedelta(minutes=55)).isoformat(), "host": "WS-FIN-017", "user": "mrivera", "parent": "rundll32.exe", "image": "schtasks.exe", "command_line": "schtasks /create /tn OneDriveUpd /tr C:\\Users\\Public\\upd.dll /sc minute /mo 15", "severity": "medium"},
    ]
    net += [
        {"timestamp": (t0 + timedelta(minutes=23, seconds=50)).isoformat(), "host": "WS-FIN-017", "src_ip": "10.10.20.10", "dst_ip": "203.0.113.77", "dst_port": 443, "proto": "tcp", "bytes_out": 1200, "domain": "cdn-assets-example.com", "action": "allow"},
        {"timestamp": (t0 + timedelta(minutes=26, seconds=5)).isoformat(), "host": "WS-FIN-017", "src_ip": "10.10.20.10", "dst_ip": "203.0.113.45", "dst_port": 443, "proto": "tcp", "bytes_out": 2210, "domain": "update-service.example.net", "action": "allow"},
    ]
    for k in range(1, 3):  # beaconing every 15 min until the host is isolated at 08:58Z
        net.append({"timestamp": (t0 + timedelta(minutes=26 + 15 * k, seconds=5 + rng.randint(-3, 3))).isoformat(), "host": "WS-FIN-017", "src_ip": "10.10.20.10", "dst_ip": "203.0.113.45", "dst_port": 443, "proto": "tcp", "bytes_out": 1800 + rng.randint(-50, 50), "domain": "update-service.example.net", "action": "allow"})
    edr += [
        {"timestamp": (t0 + timedelta(minutes=24, seconds=5)).isoformat(), "host": "WS-FIN-017", "user": "mrivera", "action": "detection", "detection": "Suspicious Office child process", "file": "C:\\Users\\mrivera\\Downloads\\Invoice_Q3_8812.docm", "sha256": "9f2c1e8ab7d64c3f0a5e2b19d8c7f6a4e3b2c1d0f9e8d7c6b5a4f3e2d1c0b9a8", "severity": "high"},
        {"timestamp": (t0 + timedelta(minutes=41)).isoformat(), "host": "WS-FIN-017", "user": "mrivera", "action": "detection", "detection": "Credential dumping - LSASS handle from rundll32.exe", "file": "C:\\Users\\Public\\upd.dll", "sha256": "4b1d0e8c6f2a9b3c7d5e1f0a8b6c4d2e9f7a5b3c1d0e8f6a4b2c0d8e6f4a2b1c", "severity": "critical"},
        {"timestamp": (t0 + timedelta(minutes=58)).isoformat(), "host": "WS-FIN-017", "user": "mrivera", "action": "quarantine", "detection": "Host network-isolated by analyst", "file": "", "sha256": "", "severity": "info"},
    ]
    # Unrelated background
    for i in range(10):
        ts = BASE + timedelta(minutes=rng.randint(0, 540))
        h = rng.choice([x for x in HOSTS if x not in ("WS-FIN-017", "SRV-DC-01")])
        u = rng.choice([x for x, (_, d) in USERS.items() if d == HOSTS[h][1]])
        auth.append({"timestamp": ts.isoformat(), "host": h, "user": u, "src_ip": f"10.10.20.{rng.randint(10, 60)}", "event_id": 4624, "logon_type": "Interactive", "outcome": "success", "reason": ""})
        net.append({"timestamp": ts.isoformat(), "host": h, "src_ip": f"10.10.20.{rng.randint(10, 60)}", "dst_ip": rng.choice(["192.0.2.15", "203.0.113.9"]), "dst_port": 443, "proto": "tcp", "bytes_out": rng.randint(500, 90000), "domain": "www.example.com", "action": "allow"})

    def dump(name: str, rows: list[dict]) -> None:
        rows.sort(key=lambda r: r["timestamp"])
        (logs / name).write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    dump("auth_events.jsonl", auth)
    dump("process_events.jsonl", proc)
    dump("network_flows.jsonl", net)
    dump("edr_detections.jsonl", edr)
    # A CSV source too, to show format flexibility
    with (logs / "auth_vpn.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "host", "user", "src_ip", "event_id", "logon_type", "outcome", "reason"])
        w.writerow([(BASE + timedelta(hours=1, minutes=59)).isoformat(), "VPN-GW-01", "tgarcia", "198.51.100.23", "VPN", "VPN", "success", "geo=RO"])
        w.writerow([(BASE + timedelta(hours=0, minutes=40)).isoformat(), "VPN-GW-01", "tgarcia", "203.0.113.9", "VPN", "VPN", "success", "geo=US"])


def write_case(out: Path) -> None:
    cases = out / "cases"
    cases.mkdir(exist_ok=True)
    case = """# Synthetic incident case file consumed by `python -m soctk report`
id: INC-2026-0142
title: Macro phishing leading to credential dumping on WS-FIN-017
severity: high
status: Closed - eradicated
classification: TLP:AMBER
incident_type: Phishing -> malware execution -> credential access
analyst: J. Scirica (Tier 2)
detection_source: EDR (Suspicious Office child process) + user phishing report

summary: |
  On 2026-10-14 a finance analyst (mrivera) opened a macro-enabled invoice attached to
  a phishing e-mail impersonating a vendor. The macro launched an encoded PowerShell
  loader that retrieved a DLL from update-service.example.net and established a 15-minute
  HTTPS beacon to 203.0.113.45. EDR observed the DLL opening a handle to LSASS and the host
  was network-isolated 44 minutes after initial execution. No lateral movement or data
  exfiltration was identified. The user's credentials were reset and the host reimaged.

impact: |
  One finance workstation compromised; one user credential presumed exposed and rotated.
  No evidence of access to finance systems with the exposed credential. Business impact: ~4h
  of analyst downtime.

root_cause: |
  Macro execution was permitted for files downloaded from the internet because the
  Mark-of-the-Web blocking policy was not enforced on the finance OU.

key_times:
  first_activity: "2026-10-14T08:14:00Z"
  detected: "2026-10-14T08:24:05Z"
  contained: "2026-10-14T08:58:00Z"
  eradicated: "2026-10-14T11:30:00Z"
  recovered: "2026-10-14T13:05:00Z"
  closed: "2026-10-16T16:00:00Z"

affected_assets:
  - {host: WS-FIN-017, user: mrivera, criticality: high, status: reimaged}

timeline:
  - {time: "2026-10-14T08:14:00Z", source: mail-gateway, event: "Phishing e-mail 'Invoice Q3-8812 overdue' delivered from invoice-team@cdn-assets-example.com", entity: mrivera}
  - {time: "2026-10-14T08:23:40Z", source: process, event: "WINWORD.EXE opened Invoice_Q3_8812.docm from Downloads", entity: WS-FIN-017}
  - {time: "2026-10-14T08:24:02Z", source: process, event: "WINWORD.EXE -> cmd.exe -> powershell.exe -enc (hidden window)", entity: WS-FIN-017}
  - {time: "2026-10-14T08:24:05Z", source: edr, event: "Detection: Suspicious Office child process (alert ALT-1002)", entity: WS-FIN-017}
  - {time: "2026-10-14T08:26:05Z", source: network, event: "HTTPS to 203.0.113.45 (update-service.example.net), first beacon", entity: WS-FIN-017}
  - {time: "2026-10-14T08:41:00Z", source: edr, event: "Detection: LSASS handle opened by rundll32.exe (upd.dll)", entity: WS-FIN-017}
  - {time: "2026-10-14T08:55:00Z", source: process, event: "schtasks /create OneDriveUpd every 15 min (persistence)", entity: WS-FIN-017}
  - {time: "2026-10-14T08:58:00Z", source: edr, event: "Host network-isolated by Tier 2", entity: WS-FIN-017}
  - {time: "2026-10-14T09:10:00Z", source: idp, event: "Password reset + sessions revoked for mrivera", entity: mrivera}

iocs:
  - {type: email, value: invoice-team@cdn-assets-example.com, context: Phishing sender, action: Blocked at gateway}
  - {type: domain, value: cdn-assets-example.com, context: Phishing landing / payload host, action: DNS sinkhole}
  - {type: domain, value: update-service.example.net, context: C2 domain, action: DNS sinkhole + proxy block}
  - {type: ipv4, value: 203.0.113.45, context: C2 server (beacon every 15 min), action: Firewall block}
  - {type: sha256, value: 9f2c1e8ab7d64c3f0a5e2b19d8c7f6a4e3b2c1d0f9e8d7c6b5a4f3e2d1c0b9a8, context: Invoice_Q3_8812.docm, action: EDR blocklist}
  - {type: sha256, value: 4b1d0e8c6f2a9b3c7d5e1f0a8b6c4d2e9f7a5b3c1d0e8f6a4b2c0d8e6f4a2b1c, context: upd.dll loader, action: EDR blocklist}

attack:
  - {tactic: TA0001, technique: T1566.001, name: "Phishing: Spearphishing Attachment", evidence: "Macro-enabled .docm from lookalike vendor domain"}
  - {tactic: TA0002, technique: T1204.002, name: "User Execution: Malicious File", evidence: "User enabled macros"}
  - {tactic: TA0002, technique: T1059.001, name: "Command and Scripting Interpreter: PowerShell", evidence: "-enc -w hidden -nop loader"}
  - {tactic: TA0005, technique: T1218.011, name: "System Binary Proxy Execution: Rundll32", evidence: "rundll32.exe upd.dll,Start"}
  - {tactic: TA0011, technique: T1071.001, name: "Application Layer Protocol: Web Protocols", evidence: "HTTPS beacon every 15 min to 203.0.113.45"}
  - {tactic: TA0006, technique: T1003.001, name: "OS Credential Dumping: LSASS Memory", evidence: "EDR LSASS handle detection"}
  - {tactic: TA0003, technique: T1053.005, name: "Scheduled Task/Job: Scheduled Task", evidence: "OneDriveUpd task"}

response:
  detection_analysis:
    - "Triaged ALT-1002 (P1) with `soctk triage`; grouped with 6 related alerts into INC-2026-0001"
    - "Analysed reported e-mail with `soctk phish` - score 100/100, lookalike domain + macro attachment"
    - "Built host timeline with `soctk timeline --pivot WS-FIN-017` to establish execution chain"
    - "Extracted IOCs with `soctk ioc`; 3 matched the internal threat feed"
  containment:
    - "EDR network isolation of WS-FIN-017 at 08:58Z"
    - "Firewall block 203.0.113.45; DNS sinkhole for both domains"
    - "Password reset and token revocation for mrivera; MFA re-enrolment"
  eradication:
    - "Removed scheduled task OneDriveUpd and C:\\\\Users\\\\Public\\\\upd.dll (hash preserved)"
    - "Full EDR scan of finance OU for both hashes - no further hits"
    - "Host reimaged from gold image rather than cleaned in place"
  recovery:
    - "Host returned to user 13:05Z after reimage and EDR re-enrolment"
    - "Enhanced monitoring on mrivera and finance share for 14 days"

evidence:
  - "Original .eml (sha256 recorded in evidence log), EDR process tree export, network flow export (08:00-10:00Z)"
  - "Memory image of WS-FIN-017 captured before isolation release"
  - "Copy of upd.dll and Invoice_Q3_8812.docm in malware share (password-protected)"

lessons_learned:
  - "Mark-of-the-Web macro blocking was not applied to the finance OU - policy gap, not user failure"
  - "User reported the e-mail 9 minutes after opening it; report button worked as designed"
  - "Beacon interval (15 min, low jitter) was visible in proxy logs - candidate for a new detection"

recommendations:
  - "Enforce 'Block macros from the internet' GPO across all OUs (owner: Endpoint Eng, due 2026-10-31)"
  - "Add proxy beaconing detection: same dst, fixed interval, < 10% jitter, > 4 connections"
  - "Add cdn-assets-example.com pattern to mail gateway lookalike rules"
"""
    (cases / "INC-2026-0142.yaml").write_text(case)


# --------------------------------------------------------------------------
# E-mail samples
# --------------------------------------------------------------------------

def _docm_with_macro() -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0SYNTHETIC-MACRO-PLACEHOLDER" + b"\x00" * 64)
    return buf.getvalue()


def _fake_pe() -> bytes:
    return b"MZ\x90\x00" + b"SYNTHETIC-NOT-A-REAL-EXECUTABLE " * 8


def write_emls(out: Path) -> None:
    d = out / "samples" / "eml"
    d.mkdir(parents=True, exist_ok=True)

    def b64(data: bytes) -> str:
        enc = base64.b64encode(data).decode()
        return "\n".join(enc[i:i + 76] for i in range(0, len(enc), 76))

    benign = """Return-Path: <notifications@corp.example.com>
Received: from mail-out.corp.example.com (mail-out.corp.example.com [203.0.113.10])
 by mx.example.com (Postfix) with ESMTPS id 7A1B2C3D4E
 for <mrivera@example.com>; Tue, 14 Oct 2026 07:58:11 +0000
Received: from app-01.corp.example.com (app-01.corp.example.com [10.10.1.22])
 by mail-out.corp.example.com (Postfix) with ESMTP id 5F6E7D8C9B;
 Tue, 14 Oct 2026 07:58:09 +0000
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=corp.example.com;
 dkim=pass header.d=corp.example.com; dmarc=pass header.from=corp.example.com
From: "Expense System" <notifications@corp.example.com>
To: mrivera@example.com
Subject: Your expense report ER-2291 was approved
Date: Tue, 14 Oct 2026 07:58:09 +0000
Message-ID: <er-2291.approval@app-01.corp.example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi Maria,

Your expense report ER-2291 (USD 142.50, client lunch) was approved by J. Chen.
Reimbursement will appear on the next payroll run.

You can view the report at https://expenses.corp.example.com/reports/2291

Thanks,
Expense System
"""

    cred_phish = """Return-Path: <bounce-1182@mailer.cdn-assets-example.com>
Received: from mailer.cdn-assets-example.com (unknown [203.0.113.77])
 by mx.example.com (Postfix) with ESMTP id 1A2B3C4D5E
 for <mrivera@example.com>; Tue, 14 Oct 2026 08:14:00 +0000
Received: from [192.168.1.44] (unknown [192.168.1.44])
 by mailer.cdn-assets-example.com (Postfix) with ESMTPA id 9F8E7D6C5B;
 Tue, 14 Oct 2026 08:13:51 +0000
Authentication-Results: mx.example.com; spf=softfail smtp.mailfrom=cdn-assets-example.com;
 dkim=none; dmarc=fail header.from=example-bank.com
From: "Example Bank Security" <alerts@example-bank.com>
Reply-To: verify@cdn-assets-example.com
To: mrivera@example.com
Subject: Action Required: Unusual sign-in detected - verify your account within 24 hours
Date: Tue, 14 Oct 2026 08:13:51 +0000
Message-ID: <20261014081351.1182@mailer.cdn-assets-example.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b1"

--b1
Content-Type: text/plain; charset="utf-8"

We detected an unusual sign-in to your Example Bank account from a new device.
To keep your account secure, please verify your identity immediately:

https://secure-login-example.com/account/verify?id=1182

If you do not confirm your account within 24 hours it will be suspended.

Example Bank Security Team

--b1
Content-Type: text/html; charset="utf-8"

<html><body>
<p>We detected an unusual sign-in to your Example Bank account from a new device.</p>
<p>To keep your account secure, please <a href="http://203.0.113.77/login/verify.php?id=1182">https://www.example-bank.com/verify</a> immediately.</p>
<p>If you do not confirm your account within 24 hours it will be suspended.</p>
<p>Example Bank Security Team</p>
</body></html>

--b1--
"""

    bec = """Return-Path: <victoria.harlan.ceo@gmail.com>
Received: from mail-sor-f41.example.net (mail-sor-f41.example.net [198.51.100.41])
 by mx.example.com (Postfix) with ESMTPS id 2B3C4D5E6F
 for <jchen@example.com>; Tue, 14 Oct 2026 09:02:33 +0000
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=gmail.com;
 dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com
From: "Victoria Harlan (CEO)" <victoria.harlan.ceo@gmail.com>
To: jchen@example.com
Subject: Quick favor - are you available?
Date: Tue, 14 Oct 2026 09:02:30 +0000
Message-ID: <CAB12xyz@mail.example.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

James,

I'm in a board meeting and can't talk. I need you to process an urgent wire
to a new vendor before noon today - this is confidential, please do not share
with anyone else on the team until I announce it.

Reply here with your mobile number and I'll send the banking details.
Kindly treat this as top priority.

Sent from my iPhone
Victoria
"""

    malware = f"""Return-Path: <invoice-team@cdn-assets-example.com>
Received: from mailer.cdn-assets-example.com (unknown [203.0.113.77])
 by mx.example.com (Postfix) with ESMTP id 3C4D5E6F7A
 for <mrivera@example.com>; Tue, 14 Oct 2026 08:14:00 +0000
Received: from WIN-7KQ2 (unknown [203.0.113.45])
 by mailer.cdn-assets-example.com (Postfix) with ESMTPA id 0A1B2C3D4E;
 Tue, 14 Oct 2026 08:13:12 +0000
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=cdn-assets-example.com;
 dkim=fail header.d=cdn-assets-example.com; dmarc=none header.from=cdn-assets-example.com
From: "Accounts Payable - Example Corp" <invoice-team@cdn-assets-example.com>
To: mrivera@example.com
Subject: Invoice Q3-8812 overdue - immediate payment required
Date: Tue, 14 Oct 2026 08:13:12 +0000
Message-ID: <inv8812@cdn-assets-example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="m1"

--m1
Content-Type: text/plain; charset="utf-8"

Dear Maria,

Please find attached the overdue invoice Q3-8812. Payment is required within
24 hours to avoid service suspension. Enable editing to view the document.

Regards,
Accounts Payable

--m1
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Invoice_Q3_8812.docm"
Content-Disposition: attachment; filename="Invoice_Q3_8812.docm"
Content-Transfer-Encoding: base64

{b64(_docm_with_macro())}

--m1
Content-Type: application/octet-stream; name="Invoice_Q3_8812.pdf.exe"
Content-Disposition: attachment; filename="Invoice_Q3_8812.pdf.exe"
Content-Transfer-Encoding: base64

{b64(_fake_pe())}

--m1--
"""

    lookalike = """Return-Path: <support@micros0ft-support.com>
Received: from vps-2231.hosting.example.net (vps-2231.hosting.example.net [192.0.2.200])
 by mx.example.com (Postfix) with ESMTPS id 4D5E6F7A8B
 for <akowalski@example.com>; Tue, 14 Oct 2026 10:41:19 +0000
Received: from localhost (localhost [127.0.0.1])
 by vps-2231.hosting.example.net (Postfix) with ESMTP id 1F2E3D4C5B;
 Tue, 14 Oct 2026 10:41:15 +0000
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=micros0ft-support.com;
 dkim=pass header.d=micros0ft-support.com; dmarc=pass header.from=micros0ft-support.com
From: "Microsoft 365 Support" <support@micros0ft-support.com>
To: akowalski@example.com
Subject: Your password expires today - keep your current password
Date: Tue, 14 Oct 2026 10:41:15 +0000
Message-ID: <pw-expiry-4471@micros0ft-support.com>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Your Microsoft 365 password expires today.</p>
<p><a href="https://login.rnicrosoft-online.example.net/common/oauth2/reset">Keep my current password</a></p>
<p>Microsoft 365 Support</p>
</body></html>
"""

    internal_fwd = """Return-Path: <helpdesk@example.com>
Received: from exch-01.corp.example.com (exch-01.corp.example.com [10.10.1.30])
 by mx.example.com (Postfix) with ESMTP id 5E6F7A8B9C
 for <sokafor@example.com>; Tue, 14 Oct 2026 11:05:02 +0000
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com;
 dkim=pass header.d=example.com; dmarc=pass header.from=example.com
From: "IT Helpdesk" <helpdesk@example.com>
To: sokafor@example.com
Subject: Ticket #44819 - your VPN certificate renewal is scheduled
Date: Tue, 14 Oct 2026 11:05:00 +0000
Message-ID: <44819.renewal@exch-01.corp.example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi Samuel,

Your VPN certificate will be renewed automatically on Friday during the
maintenance window. No action is needed on your side.

For status see https://helpdesk.example.com/tickets/44819

IT Helpdesk
"""
    (d / "01_benign_expense_approval.eml").write_text(benign)
    (d / "02_credential_phish_bank.eml").write_text(cred_phish)
    (d / "03_bec_ceo_fraud.eml").write_text(bec)
    (d / "04_malware_invoice_attachment.eml").write_text(malware)
    (d / "05_lookalike_m365_password.eml").write_text(lookalike)
    (d / "06_benign_internal_helpdesk.eml").write_text(internal_fwd)

    # A pasted-notes file for the ioc command
    (out / "samples" / "analyst_notes.txt").write_text("""Analyst notes - INC-2026-0142 (pasted from chat, defanged)

User mrivera reported mail from invoice-team@cdn-assets-example[.]com at 08:14Z.
Macro doc Invoice_Q3_8812.docm sha256 9f2c1e8ab7d64c3f0a5e2b19d8c7f6a4e3b2c1d0f9e8d7c6b5a4f3e2d1c0b9a8
Loader upd.dll sha256 4b1d0e8c6f2a9b3c7d5e1f0a8b6c4d2e9f7a5b3c1d0e8f6a4b2c0d8e6f4a2b1c, md5 44d88612fea8a8f36de82e1278abb02f
Beacon: hxxp://update-service[.]example[.]net/gate.php every 15 min -> 203[.]0[.]113[.]45:443
Second stage pulled from hxxps://cdn-assets-example(.)com/assets/upd.bin
Workstation 10.10.20.10 (WS-FIN-017), DC at 10.10.1.10, loopback test 127.0.0.1
Brute force source earlier today: 198.51.100.23 against SRV-DC-01
IPv6 seen in proxy logs: 2001:db8:85a3::8a2e:370:7334 and fe80::1
Possibly related to CVE-2024-21413 (Outlook MonikerLink) - unconfirmed
Mention of eicar test sha1 3395856ce81f2b7382dee72602f798b642f14140 from AV logs
Also saw www.example.com (corporate site, benign) and secure-login-example.com
Timestamps 08:24:05 and 09:10:00 are not IPs. svchost.exe and report.pdf are filenames.
""")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--alerts", type=int, default=60)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    write_lookups(out)
    write_threat_intel(out)
    write_alerts(out, rng, args.alerts)
    write_logs(out, rng)
    write_case(out)
    write_emls(out)
    print(f"Synthetic data written under {out}/ (seed={args.seed})")
    for p in sorted(out.rglob("*")):
        if p.is_file():
            print(f"  {p}  ({p.stat().st_size} B)")


if __name__ == "__main__":
    main()
