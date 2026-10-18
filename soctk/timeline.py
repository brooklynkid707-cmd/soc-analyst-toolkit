"""Incident timeline builder.

Merges heterogeneous log sources (authentication, process creation, network
flow, EDR detections) into one normalised, time-sorted timeline. Each source
has its own field names; a small adapter maps them onto a common ``Event``
shape so the analyst can pivot on a host, user or IP and export a Markdown
table for the incident report.

Supported input formats: JSON array, JSON-lines (``.jsonl``), CSV. The source
type is taken from the ``--source`` flag or inferred from the filename
(``auth_*.jsonl`` -> auth, ``proc_*`` -> process, ``net_*`` -> network,
``edr_*`` -> edr).
"""
from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .common import iso, md_table, parse_timestamp, write_text

SOURCE_TYPES = ("auth", "process", "network", "edr", "generic")


@dataclass
class Event:
    """A single normalised timeline entry."""

    timestamp: datetime
    source: str
    action: str
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    detail: str = ""
    severity: str = "info"
    raw: dict = field(default_factory=dict)

    def entities(self) -> set[str]:
        s = set()
        for v in (self.host, self.user, self.src_ip, self.dst_ip):
            if v:
                s.add(str(v).lower())
        return s


# --------------------------------------------------------------------------
# Adapters: raw dict -> Event
# --------------------------------------------------------------------------

def _get(r: dict, *keys: str, default: str | None = None) -> str | None:
    for k in keys:
        if k in r and r[k] not in (None, ""):
            return str(r[k])
    return default


def adapt_auth(r: dict) -> Event:
    outcome = _get(r, "outcome", "result", "status", default="?")
    return Event(
        timestamp=parse_timestamp(_get(r, "timestamp", "time", "@timestamp")),
        source="auth",
        action=f"logon_{outcome}".lower(),
        host=_get(r, "host", "hostname", "computer"),
        user=_get(r, "user", "username", "account"),
        src_ip=_get(r, "src_ip", "source_ip", "ip"),
        detail=f"{_get(r, 'logon_type', 'method', default='')} event_id={_get(r, 'event_id', default='-')} {_get(r, 'reason', default='')}".strip(),
        severity="medium" if outcome.lower() in ("failure", "failed", "fail") else "info",
        raw=r,
    )


def adapt_process(r: dict) -> Event:
    cmd = _get(r, "command_line", "cmdline", "cmd", default="")
    return Event(
        timestamp=parse_timestamp(_get(r, "timestamp", "time", "@timestamp")),
        source="process",
        action="process_create",
        host=_get(r, "host", "hostname", "computer"),
        user=_get(r, "user", "username"),
        detail=f"{_get(r, 'parent', 'parent_image', default='?')} -> {_get(r, 'image', 'process', default='?')} :: {cmd[:160]}",
        severity=_get(r, "severity", default="info"),
        raw=r,
    )


def adapt_network(r: dict) -> Event:
    proto = _get(r, "proto", "protocol", default="tcp")
    dport = _get(r, "dst_port", "dport", default="?")
    byts = _get(r, "bytes_out", "bytes", default="0")
    return Event(
        timestamp=parse_timestamp(_get(r, "timestamp", "time", "@timestamp")),
        source="network",
        action=f"conn_{_get(r, 'action', default='allow')}".lower(),
        host=_get(r, "host", "hostname"),
        user=_get(r, "user"),
        src_ip=_get(r, "src_ip", "source_ip"),
        dst_ip=_get(r, "dst_ip", "dest_ip", "destination_ip"),
        detail=f"{proto}/{dport} bytes_out={byts} {_get(r, 'domain', 'dns', default='')}".strip(),
        severity=_get(r, "severity", default="info"),
        raw=r,
    )


def adapt_edr(r: dict) -> Event:
    return Event(
        timestamp=parse_timestamp(_get(r, "timestamp", "time", "@timestamp")),
        source="edr",
        action=_get(r, "action", "event_type", default="detection"),
        host=_get(r, "host", "hostname", "device"),
        user=_get(r, "user", "username"),
        src_ip=_get(r, "src_ip"),
        dst_ip=_get(r, "dst_ip"),
        detail=f"{_get(r, 'detection', 'name', 'rule', default='')} {_get(r, 'file', 'path', default='')} {_get(r, 'sha256', default='')}".strip(),
        severity=_get(r, "severity", default="high"),
        raw=r,
    )


def adapt_generic(r: dict) -> Event:
    return Event(
        timestamp=parse_timestamp(_get(r, "timestamp", "time", "@timestamp")),
        source=_get(r, "source", default="generic"),
        action=_get(r, "action", "event", default="event"),
        host=_get(r, "host"), user=_get(r, "user"), src_ip=_get(r, "src_ip"), dst_ip=_get(r, "dst_ip"),
        detail=_get(r, "detail", "message", default=""), severity=_get(r, "severity", default="info"), raw=r,
    )


ADAPTERS = {"auth": adapt_auth, "process": adapt_process, "network": adapt_network, "edr": adapt_edr, "generic": adapt_generic}


def infer_source(path: Path) -> str:
    name = path.name.lower()
    for key in ("auth", "process", "proc", "network", "net", "edr"):
        if name.startswith(key):
            return {"proc": "process", "net": "network"}.get(key, key)
    return "generic"


def read_records(path: str | Path) -> list[dict]:
    """Read JSON array, JSON-lines or CSV into a list of dicts."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix == ".csv":
        return list(csv.DictReader(text.splitlines()))
    if p.suffix == ".jsonl":
        return [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    data = json.loads(text)
    return data if isinstance(data, list) else data.get("events", [])


def load_source(path: str | Path, source: str | None = None) -> list[Event]:
    p = Path(path)
    src = source or infer_source(p)
    adapter = ADAPTERS.get(src, adapt_generic)
    return [adapter(r) for r in read_records(p)]


# --------------------------------------------------------------------------
# Merge / pivot
# --------------------------------------------------------------------------

def merge(sources: Iterable[list[Event]]) -> list[Event]:
    """Flatten and sort all events chronologically (stable on source name)."""
    events = [e for src in sources for e in src]
    return sorted(events, key=lambda e: (e.timestamp, e.source))


def pivot(events: Iterable[Event], entity: str) -> list[Event]:
    """Keep only events that reference ``entity`` (host, user or IP; case-insensitive)."""
    ent = entity.lower()
    return [e for e in events if ent in e.entities()]


def window(events: Iterable[Event], start: datetime | None = None, end: datetime | None = None) -> list[Event]:
    return [e for e in events if (start is None or e.timestamp >= start) and (end is None or e.timestamp <= end)]


def to_markdown(events: list[Event], title: str = "Incident timeline") -> str:
    rows = [
        (iso(e.timestamp), e.source, e.severity, e.action, e.host or "-", e.user or "-",
         (e.src_ip or "-") + (" -> " + e.dst_ip if e.dst_ip else ""), e.detail)
        for e in events
    ]
    header = [f"# {title}", "", f"{len(events)} events"]
    if events:
        header.append(f" from {iso(events[0].timestamp)} to {iso(events[-1].timestamp)}")
    return "\n".join(header) + "\n\n" + md_table(["Time (UTC)", "Source", "Sev", "Action", "Host", "User", "Network", "Detail"], rows) + "\n"


def run_cli(args) -> int:
    sources = []
    for spec in args.logs:
        if ":" in spec and not Path(spec).exists():
            src, _, path = spec.partition(":")
        else:
            src, path = None, spec
        p = Path(path)
        files = sorted(p.glob("*")) if p.is_dir() else [p]
        for f in files:
            if f.suffix in (".json", ".jsonl", ".csv"):
                sources.append(load_source(f, src))
    events = merge(sources)
    total = len(events)
    if args.pivot:
        events = pivot(events, args.pivot)
    start = parse_timestamp(args.start) if args.start else None
    end = parse_timestamp(args.end) if args.end else None
    events = window(events, start, end)

    print(f"Merged {total} events from {len(sources)} source files"
          + (f"; pivot on '{args.pivot}' -> {len(events)} events" if args.pivot else ""))
    print()
    print(f"{'Time (UTC)':<21}{'Src':<9}{'Sev':<9}{'Action':<18}{'Host':<16}{'User':<15}Detail")
    print("-" * 120)
    for e in events[: args.limit]:
        print(f"{iso(e.timestamp):<21}{e.source:<9}{e.severity:<9}{e.action:<18}{(e.host or '-'):<16}{(e.user or '-'):<15}{e.detail[:60]}")
    if len(events) > args.limit:
        print(f"... {len(events) - args.limit} more (use --limit)")
    if args.out:
        write_text(args.out, to_markdown(events, title=f"Incident timeline" + (f" - pivot {args.pivot}" if args.pivot else "")))
        print(f"\nMarkdown written: {args.out}")
    if args.json:
        write_text(args.json, json.dumps([{**asdict(e), "timestamp": iso(e.timestamp)} for e in events], indent=2, default=str))
        print(f"JSON written: {args.json}")
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser("timeline", help="Merge auth/process/network/EDR logs into one sorted timeline")
    p.add_argument("logs", nargs="+", help="Log files or directories; prefix with type: (e.g. auth:file.csv) to force an adapter")
    p.add_argument("--pivot", help="Entity to pivot on (host, user or IP)")
    p.add_argument("--start", help="Only events at/after this timestamp")
    p.add_argument("--end", help="Only events at/before this timestamp")
    p.add_argument("--limit", type=int, default=40, help="Rows to print")
    p.add_argument("--out", help="Write Markdown table here")
    p.add_argument("--json", help="Write normalised JSON here")
    p.set_defaults(func=run_cli)
