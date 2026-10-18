"""Report: YAML case loading, metrics, template rendering."""
import pytest
import yaml

from soctk.report import build_context, generate, load_case, render


def test_generate_from_sample_case(data_dir) -> None:
    text = generate(data_dir / "cases" / "INC-2026-0142.yaml")
    assert "# Incident Report INC-2026-0142" in text
    for heading in ("Executive summary", "Timeline of events", "Indicators of compromise", "MITRE ATT&CK mapping",
                    "Containment", "Eradication", "Recovery", "Lessons learned"):
        assert heading in text
    assert "| ipv4 | 203[.]0[.]113[.]45 |" in text  # IOC table is defanged
    assert "| sha256 | 9f2c1e8ab7d64c3f0a5e2b19d8c7f6a4e3b2c1d0f9e8d7c6b5a4f3e2d1c0b9a8 |" in text
    assert "| TA0006 | Credential Access | T1003.001 |" in text
    assert "{{" not in text  # every placeholder resolved


def test_metrics_and_timeline_sorting(data_dir) -> None:
    case = load_case(data_dir / "cases" / "INC-2026-0142.yaml")
    ctx = build_context(case)
    assert ctx["dwell_time"] == "0h 10m" and ctx["time_to_contain"] == "0h 33m"
    rows = [l for l in ctx["timeline_table"].splitlines() if l.startswith("| 2026")]
    assert rows == sorted(rows)


def test_render_leaves_unknown_tokens_visible() -> None:
    assert render("a {{known}} b {{unknown}}", {"known": "X"}) == "a X b {{unknown}}"


def test_missing_required_keys(tmp_path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump({"id": "X", "title": "t"}))
    with pytest.raises(ValueError, match="severity"):
        load_case(p)
