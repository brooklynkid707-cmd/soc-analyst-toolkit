"""Alert triage: de-duplicate, enrich, prioritise and group a SIEM alert queue.

Pipeline
--------
1. **Ingest** a JSON list of alerts (see ``scripts/generate_sample_data.py``).
2. **De-duplicate** alerts that share the same rule + entity tuple inside a
   short window (noisy detections fire many times for one event).
3. **Enrich** each alert with asset criticality (``assets.csv``) and user risk
   (``users.csv``).
4. **Score** priority = severity x asset criticality x confidence, modulated by
   user risk, into a 0-100 scale and a P1-P4 band.
5. **Group** related alerts into incidents when they share a host, user or
   external IP inside a time window (union-find over entities).
6. **Report** a prioritised worklist as JSON and Markdown.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

from .common import is_routable, iso, md_table, parse_timestamp, write_text

SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2, "informational": 1}
CRITICALITY_WEIGHT = {"crown-jewel": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}
USER_RISK_BONUS = {"high": 1.25, "medium": 1.1, "low": 1.0}
PRIORITY_BANDS = ((80, "P1"), (55, "P2"), (30, "P3"), (0, "P4"))
LOW_SEVERITIES = {"low", "informational"}


@dataclass
class Alert:
    """One SIEM/EDR alert after normalisation."""

    id: str
    timestamp: datetime
    rule: str
    severity: str
    confidence: float          # 0.0 - 1.0 from the detection source
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    description: str = ""
    attack_technique: str | None = None
    # enrichment
    asset_criticality: str = "medium"
    asset_owner: str = ""
    user_risk: str = "low"
    user_dept: str = ""
    duplicates: int = 0
    priority_score: float = 0.0
    priority: str = "P4"
    incident_id: str | None = None

    def entities(self) -> set[str]:
        """Entity keys used for incident grouping (host/user/external IPs)."""
        ents = set()
        if self.host:
            ents.add(f"host:{self.host.lower()}")
        if self.user:
            ents.add(f"user:{self.user.lower()}")
        for ip in (self.src_ip, self.dst_ip):
            if ip and is_routable(ip):  # internal IPs are too common to link on
                ents.add(f"ip:{ip}")
        return ents


@dataclass
class Incident:
    """A cluster of alerts linked by a shared entity within the grouping window."""

    id: str
    alerts: list[Alert] = field(default_factory=list)

    @property
    def start(self) -> datetime:
        return min(a.timestamp for a in self.alerts)

    @property
    def end(self) -> datetime:
        return max(a.timestamp for a in self.alerts)

    @property
    def priority_score(self) -> float:
        # Highest alert score, plus a small bump per extra distinct rule (kill-chain breadth).
        rules = {a.rule for a in self.alerts}
        return min(100.0, max(a.priority_score for a in self.alerts) + 3 * (len(rules) - 1))

    @property
    def priority(self) -> str:
        return band(self.priority_score)

    @property
    def entities(self) -> set[str]:
        s: set[str] = set()
        for a in self.alerts:
            s |= a.entities()
        return s

    @property
    def techniques(self) -> list[str]:
        return sorted({a.attack_technique for a in self.alerts if a.attack_technique})


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def load_alerts(path: str | Path) -> list[Alert]:
    """Load alerts from a JSON file (list of dicts)."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    alerts = []
    for r in raw:
        alerts.append(Alert(
            id=str(r["id"]),
            timestamp=parse_timestamp(r["timestamp"]),
            rule=r["rule"],
            severity=str(r.get("severity", "medium")).lower(),
            confidence=float(r.get("confidence", 0.5)),
            host=r.get("host"),
            user=r.get("user"),
            src_ip=r.get("src_ip"),
            dst_ip=r.get("dst_ip"),
            description=r.get("description", ""),
            attack_technique=r.get("attack_technique"),
        ))
    return sorted(alerts, key=lambda a: a.timestamp)


def load_csv_lookup(path: str | Path, key: str) -> dict[str, dict[str, str]]:
    """Load a CSV into ``{row[key].lower(): row}``. Missing file -> empty dict."""
    p = Path(path)
    if not p.exists():
        return {}
    with p.open(newline="", encoding="utf-8") as fh:
        return {row[key].lower(): row for row in csv.DictReader(fh)}


# --------------------------------------------------------------------------
# Pipeline steps
# --------------------------------------------------------------------------

def deduplicate(alerts: Iterable[Alert], window_minutes: int = 10) -> list[Alert]:
    """Collapse alerts with the same (rule, host, user, src_ip) within ``window_minutes``.

    The first alert is kept and its ``duplicates`` counter records how many
    were folded into it. Confidence is raised slightly for repeated firings.
    """
    kept: list[Alert] = []
    last_by_key: dict[tuple, Alert] = {}
    window = timedelta(minutes=window_minutes)
    for a in sorted(alerts, key=lambda x: x.timestamp):
        key = (a.rule, a.host, a.user, a.src_ip)
        prev = last_by_key.get(key)
        if prev and a.timestamp - prev.timestamp <= window:
            prev.duplicates += 1
            prev.confidence = min(1.0, prev.confidence + 0.02)
            continue
        last_by_key[key] = a
        kept.append(a)
    return kept


def enrich(alerts: Iterable[Alert], assets: dict[str, dict[str, str]], users: dict[str, dict[str, str]]) -> list[Alert]:
    """Attach asset criticality/owner and user risk/department from lookups."""
    out = []
    for a in alerts:
        if a.host and a.host.lower() in assets:
            row = assets[a.host.lower()]
            a.asset_criticality = row.get("criticality", "medium").lower()
            a.asset_owner = row.get("owner", "")
        if a.user and a.user.lower() in users:
            row = users[a.user.lower()]
            a.user_risk = row.get("risk", "low").lower()
            a.user_dept = row.get("department", "")
        out.append(a)
    return out


def band(score: float) -> str:
    for threshold, label in PRIORITY_BANDS:
        if score >= threshold:
            return label
    return "P4"


def score_alert(a: Alert) -> float:
    """Priority = severity x asset criticality x confidence (x user-risk bonus), scaled 0-100.

    severity(1-10) x criticality(0.3-1.0) x confidence(0-1) gives 0-10; multiply
    by 10 for a 0-100 scale. The user-risk bonus (up to x1.25) can push a score
    above 100, so it is capped.
    """
    sev = SEVERITY_WEIGHT.get(a.severity, 4)
    crit = CRITICALITY_WEIGHT.get(a.asset_criticality, 0.5)
    conf = max(0.0, min(1.0, a.confidence))
    bonus = USER_RISK_BONUS.get(a.user_risk, 1.0)
    raw = sev * crit * conf * bonus
    return round(min(100.0, raw * 10), 1)


def prioritize(alerts: Iterable[Alert]) -> list[Alert]:
    out = []
    for a in alerts:
        a.priority_score = score_alert(a)
        a.priority = band(a.priority_score)
        out.append(a)
    return sorted(out, key=lambda x: (-x.priority_score, x.timestamp))


def group_incidents(alerts: list[Alert], window_minutes: int = 60, prefix: str = "INC") -> list[Incident]:
    """Union alerts that share an entity (host/user/external IP) within the window.

    Low / informational alerts may *attach* to a group through a shared entity
    but never act as a bridge between two other alerts; otherwise a busy user
    with a few USB and after-hours logon alerts would chain every incident on
    the board into one. Alerts without any entity become single-alert incidents.
    """
    alerts = sorted(alerts, key=lambda a: a.timestamp)
    parent = list(range(len(alerts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        parent[find(i)] = find(j)

    window = timedelta(minutes=window_minutes)
    last_seen: dict[str, int] = {}   # entity -> index of most recent alert with that entity
    for idx, a in enumerate(alerts):
        anchor = a.severity not in LOW_SEVERITIES
        for ent in a.entities():
            prev = last_seen.get(ent)
            if prev is not None and a.timestamp - alerts[prev].timestamp <= window:
                union(idx, prev)
            if anchor:
                last_seen[ent] = idx

    groups: dict[int, list[Alert]] = defaultdict(list)
    for idx, a in enumerate(alerts):
        groups[find(idx)].append(a)

    incidents = [Incident(id="", alerts=g) for g in groups.values()]
    incidents.sort(key=lambda i: (-i.priority_score, i.start))
    year = alerts[0].timestamp.year if alerts else datetime.now().year
    for n, inc in enumerate(incidents, 1):
        inc.id = f"{prefix}-{year}-{n:04d}"
        for a in inc.alerts:
            a.incident_id = inc.id
    return incidents


def run_pipeline(alerts: list[Alert], assets: dict, users: dict,
                 dedupe_window: int = 10, group_window: int = 60) -> tuple[list[Alert], list[Incident]]:
    """Full triage pipeline; returns (prioritised alerts, incidents)."""
    alerts = deduplicate(alerts, dedupe_window)
    alerts = enrich(alerts, assets, users)
    alerts = prioritize(alerts)
    incidents = group_incidents(alerts, group_window)
    return alerts, incidents


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def incident_to_dict(inc: Incident) -> dict:
    return {
        "id": inc.id,
        "priority": inc.priority,
        "priority_score": round(inc.priority_score, 1),
        "start": iso(inc.start),
        "end": iso(inc.end),
        "alert_count": len(inc.alerts),
        "entities": sorted(inc.entities),
        "techniques": inc.techniques,
        "rules": sorted({a.rule for a in inc.alerts}),
        "alerts": [alert_to_dict(a) for a in inc.alerts],
    }


def alert_to_dict(a: Alert) -> dict:
    d = asdict(a)
    d["timestamp"] = iso(a.timestamp)
    return d


def worklist_markdown(incidents: list[Incident], alerts: list[Alert], raw_count: int) -> str:
    lines = ["# Triage worklist", ""]
    lines.append(f"- Raw alerts ingested: **{raw_count}**")
    lines.append(f"- After de-duplication: **{len(alerts)}**")
    lines.append(f"- Incidents formed: **{len(incidents)}**")
    counts = defaultdict(int)
    for inc in incidents:
        counts[inc.priority] += 1
    lines.append("- By priority: " + ", ".join(f"{p}={counts[p]}" for p in ("P1", "P2", "P3", "P4")))
    lines += ["", "## Incidents (work top-down)", ""]
    rows = []
    for inc in incidents:
        rows.append((
            inc.id, inc.priority, f"{inc.priority_score:.0f}", len(inc.alerts),
            iso(inc.start)[11:16] + "-" + iso(inc.end)[11:16],
            ", ".join(sorted(inc.entities))[:70],
            ", ".join(inc.techniques) or "-",
            " / ".join(sorted({a.rule for a in inc.alerts}))[:80],
        ))
    lines.append(md_table(["Incident", "Pri", "Score", "Alerts", "Window (UTC)", "Entities", "ATT&CK", "Rules"], rows))
    lines += ["", "## Alert detail", ""]
    rows = [
        (a.id, a.incident_id, a.priority, f"{a.priority_score:.0f}", iso(a.timestamp)[11:19], a.severity,
         a.host or "-", a.asset_criticality, a.user or "-", a.user_risk, a.rule, a.duplicates)
        for a in alerts
    ]
    lines.append(md_table(["Alert", "Incident", "Pri", "Score", "Time", "Sev", "Host", "Asset crit", "User", "User risk", "Rule", "Dups"], rows))
    return "\n".join(lines) + "\n"


def run_cli(args) -> int:
    raw = load_alerts(args.alerts)
    assets = load_csv_lookup(args.assets, "hostname")
    users = load_csv_lookup(args.users, "username")
    alerts, incidents = run_pipeline(raw, assets, users, args.dedupe_window, args.group_window)

    print(f"Ingested {len(raw)} alerts -> {len(alerts)} after de-dup -> {len(incidents)} incidents")
    print()
    print(f"{'Incident':<14}{'Pri':<5}{'Score':<7}{'Alerts':<8}{'Window (UTC)':<14}{'ATT&CK':<24}Entities")
    print("-" * 110)
    for inc in incidents[: args.top]:
        ents = ", ".join(sorted(inc.entities))
        print(f"{inc.id:<14}{inc.priority:<5}{inc.priority_score:<7.0f}{len(inc.alerts):<8}"
              f"{iso(inc.start)[11:16]}-{iso(inc.end)[11:16]}    {', '.join(inc.techniques)[:22]:<24}{ents[:60]}")
        for a in inc.alerts:
            dup = f" (+{a.duplicates} dup)" if a.duplicates else ""
            print(f"    {a.priority} {a.priority_score:>5.0f}  {iso(a.timestamp)[11:19]}  {a.severity:<8} {a.rule}{dup}")
    if len(incidents) > args.top:
        print(f"... {len(incidents) - args.top} lower-priority incidents omitted (use --top)")

    out_json = Path(args.out_dir) / "worklist.json"
    out_md = Path(args.out_dir) / "worklist.md"
    write_text(out_json, json.dumps({
        "generated": iso(datetime.now().astimezone()),
        "raw_alerts": len(raw),
        "deduplicated_alerts": len(alerts),
        "incidents": [incident_to_dict(i) for i in incidents],
    }, indent=2))
    write_text(out_md, worklist_markdown(incidents, alerts, len(raw)))
    print(f"\nWritten: {out_json}\nWritten: {out_md}")
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser("triage", help="De-dup, enrich, score and group an alert queue into a worklist")
    p.add_argument("alerts", nargs="?", default="data/alerts.json", help="Alert queue JSON")
    p.add_argument("--assets", default="data/assets.csv", help="Asset inventory CSV (hostname,criticality,owner)")
    p.add_argument("--users", default="data/users.csv", help="User directory CSV (username,risk,department)")
    p.add_argument("--dedupe-window", type=int, default=10, help="Minutes for de-dup collapsing (default 10)")
    p.add_argument("--group-window", type=int, default=60, help="Minutes for incident grouping (default 60)")
    p.add_argument("--top", type=int, default=10, help="Incidents to print on the console")
    p.add_argument("--out-dir", default="output", help="Where to write worklist.json / worklist.md")
    p.set_defaults(func=run_cli)
