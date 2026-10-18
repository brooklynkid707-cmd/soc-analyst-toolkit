"""Triage: de-duplication, enrichment, scoring and incident grouping."""
from datetime import datetime, timedelta, timezone

from soctk.triage import (
    Alert, band, deduplicate, enrich, group_incidents, load_alerts, load_csv_lookup, prioritize, run_pipeline, score_alert,
)

T0 = datetime(2026, 10, 14, 8, 0, tzinfo=timezone.utc)


def mk(i: int, minutes: int, rule: str = "r", sev: str = "high", conf: float = 0.8, host=None, user=None, src=None, dst=None) -> Alert:
    return Alert(id=f"A{i}", timestamp=T0 + timedelta(minutes=minutes), rule=rule, severity=sev, confidence=conf,
                 host=host, user=user, src_ip=src, dst_ip=dst)


def test_dedupe_collapses_same_key_within_window() -> None:
    alerts = [mk(1, 0, host="H", src="203.0.113.1"), mk(2, 3, host="H", src="203.0.113.1"), mk(3, 8, host="H", src="203.0.113.1"),
              mk(4, 30, host="H", src="203.0.113.1"), mk(5, 1, host="H2", src="203.0.113.1")]
    kept = deduplicate(alerts, window_minutes=10)
    assert [a.id for a in kept] == ["A1", "A5", "A4"]
    assert kept[0].duplicates == 2
    assert kept[0].confidence > 0.8  # repeated firing nudges confidence up


def test_scoring_formula_and_bands() -> None:
    a = mk(1, 0, sev="critical", conf=1.0, host="H", user="U")
    a.asset_criticality, a.user_risk = "crown-jewel", "low"
    assert score_alert(a) == 100.0
    a.asset_criticality = "low"
    assert score_alert(a) == 30.0
    b = mk(2, 0, sev="low", conf=0.5)
    assert score_alert(b) == 5.0 and band(score_alert(b)) == "P4"
    c = mk(3, 0, sev="high", conf=0.9)
    c.asset_criticality, c.user_risk = "high", "high"
    assert score_alert(c) == 63.0 and band(63.0) == "P2"
    assert band(80) == "P1" and band(79.9) == "P2" and band(30) == "P3"


def test_enrich_from_lookups(data_dir) -> None:
    assets = load_csv_lookup(data_dir / "assets.csv", "hostname")
    users = load_csv_lookup(data_dir / "users.csv", "username")
    a = mk(1, 0, host="srv-dc-01", user="SVC_BACKUP")
    unknown = mk(2, 0, host="nope", user="nobody")
    enrich([a, unknown], assets, users)
    assert a.asset_criticality == "crown-jewel" and a.user_risk == "high" and a.user_dept == "it"
    assert unknown.asset_criticality == "medium" and unknown.user_risk == "low"


def test_grouping_by_shared_entity_within_window() -> None:
    alerts = [
        mk(1, 0, rule="phish", sev="medium", host="WS1", user="u1"),
        mk(2, 10, rule="ps", sev="high", host="WS1"),
        mk(3, 20, rule="c2", sev="critical", host="WS1", src="10.0.0.5", dst="203.0.113.45"),
        mk(4, 25, rule="c2-other", sev="critical", host="WS9", dst="203.0.113.45"),  # linked via external IP
        mk(5, 200, rule="late", sev="high", host="WS1"),                              # outside window -> new incident
        mk(6, 30, rule="bf", sev="high", host="DC1", src="198.51.100.23"),
        mk(7, 31, rule="internal", sev="high", host="WS2", src="10.0.0.9"),            # private IP never links
    ]
    incidents = group_incidents(prioritize(alerts), window_minutes=60)
    by_alert = {a.id: a.incident_id for inc in incidents for a in inc.alerts}
    assert by_alert["A1"] == by_alert["A2"] == by_alert["A3"] == by_alert["A4"]
    assert by_alert["A5"] != by_alert["A1"]
    assert len({by_alert["A6"], by_alert["A7"], by_alert["A1"]}) == 3
    top = incidents[0]
    assert top.id.startswith("INC-2026-0001") and len(top.alerts) == 4
    assert top.priority_score >= max(a.priority_score for a in top.alerts)


def test_low_severity_alerts_attach_but_never_bridge() -> None:
    alerts = [
        mk(1, 0, rule="c2", sev="critical", host="WS1", user="alice"),
        mk(2, 5, rule="usb", sev="low", host="WS1", user="bob"),      # attaches to WS1 incident...
        mk(3, 10, rule="spray", sev="high", host="DC1", user="bob"),  # ...but must not be pulled in through bob
    ]
    incidents = group_incidents(prioritize(alerts), window_minutes=60)
    by_alert = {a.id: a.incident_id for inc in incidents for a in inc.alerts}
    assert by_alert["A1"] == by_alert["A2"]
    assert by_alert["A3"] != by_alert["A1"]


def test_full_pipeline_on_sample_data(data_dir) -> None:
    raw = load_alerts(data_dir / "alerts.json")
    alerts, incidents = run_pipeline(raw, load_csv_lookup(data_dir / "assets.csv", "hostname"), load_csv_lookup(data_dir / "users.csv", "username"))
    assert len(alerts) < len(raw)
    assert incidents[0].priority == "P1"
    fin = next(i for i in incidents if "host:ws-fin-017" in i.entities)
    assert "T1003.001" in fin.techniques and "T1059.001" in fin.techniques
    assert all(a.incident_id for a in alerts)
    # Incidents are sorted by score then start time
    scores = [i.priority_score for i in incidents]
    assert scores == sorted(scores, reverse=True)
