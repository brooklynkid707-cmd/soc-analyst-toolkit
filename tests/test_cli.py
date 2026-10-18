"""End-to-end CLI smoke tests via ``python -m soctk``."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "soctk", *args], cwd=ROOT, capture_output=True, text=True)


def test_help_lists_all_subcommands() -> None:
    r = run("--help")
    assert r.returncode == 0
    for cmd in ("triage", "phish", "ioc", "timeline", "report"):
        assert cmd in r.stdout


def test_triage_writes_outputs(tmp_path) -> None:
    r = run("triage", "data/alerts.json", "--out-dir", str(tmp_path), "--top", "2")
    assert r.returncode == 0, r.stderr
    data = json.loads((tmp_path / "worklist.json").read_text())
    assert data["incidents"][0]["priority"] == "P1"
    assert (tmp_path / "worklist.md").exists()


def test_ioc_stdin_and_exports(tmp_path) -> None:
    r = subprocess.run([sys.executable, "-m", "soctk", "ioc", "-", "--csv", str(tmp_path / "i.csv"), "--exclude-private"],
                       cwd=ROOT, input="see 10.0.0.1 and 203[.]0[.]113[.]45\n", capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "203[.]0[.]113[.]45" in r.stdout and "10[.]0[.]0[.]1" not in r.stdout


def test_phish_timeline_report(tmp_path) -> None:
    assert run("phish", "data/samples/eml/04_malware_invoice_attachment.eml").stdout.count("MALICIOUS") >= 1
    t = run("timeline", "data/logs", "--pivot", "WS-FIN-017", "--out", str(tmp_path / "t.md"))
    assert t.returncode == 0 and (tmp_path / "t.md").exists()
    rp = run("report", "data/cases/INC-2026-0142.yaml", "--out", str(tmp_path / "r.md"))
    assert rp.returncode == 0 and "Incident Report" in (tmp_path / "r.md").read_text()


def test_missing_file_exit_code() -> None:
    r = run("report", "does-not-exist.yaml")
    assert r.returncode == 2 and "not found" in r.stderr
