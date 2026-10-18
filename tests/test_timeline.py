"""Timeline: adapters, chronological merge across sources, pivoting, Markdown export."""
import json

from soctk.timeline import adapt_auth, adapt_network, load_source, merge, pivot, to_markdown, window
from soctk.common import parse_timestamp


def test_adapters_normalise_fields() -> None:
    e = adapt_auth({"timestamp": "2026-10-14T08:00:00Z", "host": "DC1", "user": "bob", "src_ip": "203.0.113.1", "event_id": 4625, "outcome": "failure"})
    assert e.action == "logon_failure" and e.severity == "medium" and "4625" in e.detail
    n = adapt_network({"time": "2026-10-14 08:00:01", "src_ip": "10.0.0.1", "dest_ip": "203.0.113.2", "dport": 443, "bytes": 10})
    assert n.dst_ip == "203.0.113.2" and n.action == "conn_allow" and "tcp/443" in n.detail


def test_merge_orders_chronologically_across_sources(data_dir) -> None:
    logs = data_dir / "logs"
    sources = [load_source(logs / "auth_events.jsonl"), load_source(logs / "process_events.jsonl"),
               load_source(logs / "network_flows.jsonl"), load_source(logs / "edr_detections.jsonl"), load_source(logs / "auth_vpn.csv")]
    events = merge(sources)
    stamps = [e.timestamp for e in events]
    assert stamps == sorted(stamps)
    assert {e.source for e in events} == {"auth", "process", "network", "edr"}
    assert any(e.host == "VPN-GW-01" for e in events)  # CSV source inferred as auth via filename


def test_pivot_and_window(data_dir) -> None:
    events = merge([load_source(p) for p in sorted((data_dir / "logs").glob("*.jsonl"))])
    host_events = pivot(events, "ws-fin-017")
    assert host_events and all("ws-fin-017" in e.entities() for e in host_events)
    actions = [e.action for e in host_events]
    assert actions.index("process_create") < actions.index("detection")
    ip_events = pivot(events, "198.51.100.23")
    assert all(e.src_ip == "198.51.100.23" for e in ip_events) and len(ip_events) >= 12
    start = parse_timestamp("2026-10-14T08:24:00Z")
    end = parse_timestamp("2026-10-14T08:30:00Z")
    narrowed = window(host_events, start, end)
    assert narrowed and all(start <= e.timestamp <= end for e in narrowed)


def test_markdown_export(data_dir) -> None:
    events = pivot(merge([load_source(data_dir / "logs" / "edr_detections.jsonl")]), "WS-FIN-017")
    md = to_markdown(events, "t")
    assert md.startswith("# t") and "| Time (UTC) |" in md
    assert md.count("\n| 2026-") == len(events)
