"""Incident report generator.

Reads a YAML case file (see ``data/cases/``) and renders a Markdown incident
report from ``templates/incident_report.md``. The template uses simple
``{{placeholder}}`` tokens; every section (executive summary, timeline, IOCs,
ATT&CK mapping, NIST SP 800-61 containment / eradication / recovery, lessons
learned) is built here from the structured case data so the YAML stays the
single source of truth.

The timeline and IOC sections can optionally be regenerated from the
``timeline`` and ``ioc`` modules when the case file points at log files.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .common import defang, iso, md_table, parse_timestamp, write_text

DEFAULT_TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "incident_report.md"

ATTACK_TACTICS = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery", "TA0008": "Lateral Movement",
    "TA0009": "Collection", "TA0010": "Exfiltration", "TA0011": "Command and Control", "TA0040": "Impact",
    "TA0043": "Reconnaissance", "TA0042": "Resource Development",
}


def load_case(path: str | Path) -> dict:
    """Load and lightly validate a YAML case file."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    required = ("id", "title", "severity", "status", "summary")
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(f"Case file missing required keys: {', '.join(missing)}")
    return data


def _bullets(items: list | None, empty: str = "- None recorded") -> str:
    if not items:
        return empty
    return "\n".join(f"- {i}" for i in items)


def _timeline_table(case: dict) -> str:
    rows = []
    for ev in case.get("timeline", []):
        ts = parse_timestamp(str(ev["time"]))
        rows.append((iso(ts), ev.get("source", "-"), ev.get("event", ""), ev.get("entity", "-")))
    rows.sort(key=lambda r: r[0])
    return md_table(["Time (UTC)", "Source", "Event", "Entity"], rows) if rows else "_No timeline entries._"


def _ioc_table(case: dict) -> str:
    rows = []
    for i in case.get("iocs", []):
        rows.append((i.get("type", "-"), defang(str(i.get("value", ""))), i.get("context", "-"), i.get("action", "-")))
    return md_table(["Type", "Indicator (defanged)", "Context", "Action taken"], rows) if rows else "_No IOCs recorded._"


def _attack_table(case: dict) -> str:
    rows = []
    for t in case.get("attack", []):
        tactic = t.get("tactic", "")
        tactic_name = ATTACK_TACTICS.get(tactic, tactic)
        rows.append((tactic, tactic_name, t.get("technique", ""), t.get("name", ""), t.get("evidence", "-")))
    return md_table(["Tactic ID", "Tactic", "Technique", "Name", "Evidence"], rows) if rows else "_No ATT&CK mapping._"


def _affected_table(case: dict) -> str:
    rows = []
    for a in case.get("affected_assets", []):
        rows.append((a.get("host", "-"), a.get("user", "-"), a.get("criticality", "-"), a.get("status", "-")))
    return md_table(["Host", "User", "Criticality", "Status"], rows) if rows else "_None._"


def _metrics(case: dict) -> dict[str, str]:
    """Compute dwell time / MTTD / MTTR style metrics from key timestamps."""
    out = {}
    stamps = {}
    for key in ("first_activity", "detected", "contained", "eradicated", "recovered", "closed"):
        v = case.get("key_times", {}).get(key)
        if v:
            stamps[key] = parse_timestamp(str(v))
    def delta(a: str, b: str) -> str:
        if a in stamps and b in stamps:
            secs = (stamps[b] - stamps[a]).total_seconds()
            h, rem = divmod(int(secs), 3600)
            return f"{h}h {rem // 60}m"
        return "n/a"
    out["dwell_time"] = delta("first_activity", "detected")
    out["time_to_contain"] = delta("detected", "contained")
    out["time_to_recover"] = delta("detected", "recovered")
    out["key_times_table"] = md_table(["Milestone", "Time (UTC)"], [(k.replace("_", " ").title(), iso(v)) for k, v in stamps.items()]) if stamps else "_Not recorded._"
    return out


def build_context(case: dict) -> dict[str, str]:
    """Flatten the case into template placeholders."""
    phases = case.get("response", {})
    ctx = {
        "id": case["id"],
        "title": case["title"],
        "severity": str(case["severity"]).upper(),
        "status": case["status"],
        "analyst": case.get("analyst", "SOC"),
        "generated": iso(datetime.now(timezone.utc)),
        "classification": case.get("classification", "TLP:AMBER"),
        "incident_type": case.get("incident_type", "Unspecified"),
        "executive_summary": case["summary"].strip(),
        "detection_source": case.get("detection_source", "Unknown"),
        "affected_table": _affected_table(case),
        "timeline_table": _timeline_table(case),
        "ioc_table": _ioc_table(case),
        "attack_table": _attack_table(case),
        "detection_analysis": _bullets(phases.get("detection_analysis")),
        "containment": _bullets(phases.get("containment")),
        "eradication": _bullets(phases.get("eradication")),
        "recovery": _bullets(phases.get("recovery")),
        "lessons_learned": _bullets(case.get("lessons_learned")),
        "recommendations": _bullets(case.get("recommendations")),
        "evidence": _bullets(case.get("evidence")),
        "root_cause": case.get("root_cause", "Under investigation").strip(),
        "impact": case.get("impact", "Under assessment").strip(),
    }
    ctx.update(_metrics(case))
    return ctx


def render(template_text: str, ctx: dict[str, str]) -> str:
    """Substitute ``{{name}}`` tokens; unknown tokens are left visible for review."""
    def sub(m: re.Match) -> str:
        key = m.group(1).strip()
        return str(ctx.get(key, m.group(0)))
    return re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", sub, template_text)


def generate(case_path: str | Path, template_path: str | Path | None = None) -> str:
    case = load_case(case_path)
    template = Path(template_path or DEFAULT_TEMPLATE).read_text(encoding="utf-8")
    return render(template, build_context(case))


def run_cli(args) -> int:
    text = generate(args.case, args.template)
    if args.out:
        write_text(args.out, text)
        print(f"Report written: {args.out} ({len(text.splitlines())} lines)")
        print()
        print("\n".join(text.splitlines()[: args.preview]))
        if len(text.splitlines()) > args.preview:
            print(f"... ({len(text.splitlines()) - args.preview} more lines)")
    else:
        print(text)
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser("report", help="Render an incident report from a YAML case file")
    p.add_argument("case", help="YAML case file")
    p.add_argument("--template", help="Markdown template (default: templates/incident_report.md)")
    p.add_argument("--out", help="Write the report here (otherwise print to stdout)")
    p.add_argument("--preview", type=int, default=30, help="Lines to echo when --out is used")
    p.set_defaults(func=run_cli)
