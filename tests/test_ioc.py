"""IOC extraction: every type, defang/refang round trip, de-dup, private flagging, enrichment, exports."""
import csv
import json

from soctk.common import refang
from soctk.ioc import IOC, enrich, extract_iocs, load_threat_feed, to_csv, to_stix

SAMPLE = """
C2 at hxxp://update-service[.]example[.]net/gate.php and hxxps://cdn-assets-example(.)com/x
Same C2 again: http://update-service.example.net/gate.php
IPs 203[.]0[.]113[.]45 203.0.113.45 10.10.20.10 127.0.0.1 2001:db8:85a3::8a2e:370:7334 fe80::1
sha256 9f2c1e8ab7d64c3f0a5e2b19d8c7f6a4e3b2c1d0f9e8d7c6b5a4f3e2d1c0b9a8
sha1 3395856ce81f2b7382dee72602f798b642f14140 md5 44d88612fea8a8f36de82e1278abb02f
mail attacker@evil[.]example[.]org, CVE-2024-21413 and cve-2021-44228
files svchost.exe report.pdf and times 08:24:05 09:10:00 mac aa:bb:cc:dd:ee:ff
domain www.example.com ends sentence.
"""


def _by_type(iocs: list[IOC]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for i in iocs:
        out.setdefault(i.type, set()).add(i.value)
    return out


def test_extract_all_types_and_refang() -> None:
    got = _by_type(extract_iocs(SAMPLE))
    assert got["url"] == {"http://update-service.example.net/gate.php", "https://cdn-assets-example.com/x"}
    assert got["ipv4"] == {"203.0.113.45", "10.10.20.10", "127.0.0.1"}
    assert got["ipv6"] == {"2001:db8:85a3::8a2e:370:7334", "fe80::1"}
    assert got["sha256"] == {"9f2c1e8ab7d64c3f0a5e2b19d8c7f6a4e3b2c1d0f9e8d7c6b5a4f3e2d1c0b9a8"}
    assert got["sha1"] == {"3395856ce81f2b7382dee72602f798b642f14140"}
    assert got["md5"] == {"44d88612fea8a8f36de82e1278abb02f"}
    assert got["email"] == {"attacker@evil.example.org"}
    assert got["cve"] == {"CVE-2024-21413", "CVE-2021-44228"}
    assert got["domain"] == {"www.example.com"}  # URL hosts and e-mail domains are not re-extracted


def test_no_false_positives_from_filenames_times_macs() -> None:
    iocs = extract_iocs(SAMPLE)
    values = {i.value for i in iocs}
    assert "svchost.exe" not in values and "report.pdf" not in values
    assert not any(v.startswith("08:24") or v.startswith("aa:bb") for v in values)


def test_dedupe_counts_defanged_and_plain_as_one() -> None:
    iocs = {i.value: i for i in extract_iocs(SAMPLE)}
    assert iocs["203.0.113.45"].count == 2
    assert iocs["http://update-service.example.net/gate.php"].count == 2


def test_private_flagging_and_defanged_output() -> None:
    iocs = {i.value: i for i in extract_iocs(SAMPLE)}
    assert iocs["10.10.20.10"].routable is False and iocs["10.10.20.10"].classification == "private"
    assert iocs["127.0.0.1"].classification == "loopback"
    assert iocs["203.0.113.45"].routable is True
    assert iocs["203.0.113.45"].defanged == "203[.]0[.]113[.]45"
    assert iocs["http://update-service.example.net/gate.php"].defanged == "hxxp://update-service[.]example[.]net/gate[.]php"
    for i in iocs.values():
        assert refang(i.defanged) == i.value  # round trip for every indicator


def test_hash_regex_does_not_split_longer_hashes() -> None:
    iocs = extract_iocs("hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert [i.type for i in iocs] == ["sha256"]


def test_enrichment_and_exports(tmp_path, data_dir) -> None:
    feed = load_threat_feed(data_dir / "threat_intel" / "feed.csv")
    assert "203.0.113.45" in feed and "http://update-service.example.net/gate.php" in feed
    iocs = enrich(extract_iocs(SAMPLE), feed)
    hits = {i.value: i.threat_intel for i in iocs if i.is_known_bad}
    assert hits["203.0.113.45"]["verdict"] == "malicious"
    assert hits["https://cdn-assets-example.com/x"]["tags"]  # URL matched via its host
    assert "10.10.20.10" not in hits

    csv_path = to_csv(iocs, tmp_path / "out.csv")
    rows = list(csv.DictReader(csv_path.open()))
    assert len(rows) == len(iocs)
    assert any(r["ti_verdict"] == "malicious" for r in rows)

    bundle = to_stix(iocs)
    assert bundle["type"] == "bundle"
    patterns = {o["pattern"] for o in bundle["objects"]}
    assert "[ipv4-addr:value = '203.0.113.45']" in patterns
    assert "[file:hashes.'SHA-256' = '9f2c1e8ab7d64c3f0a5e2b19d8c7f6a4e3b2c1d0f9e8d7c6b5a4f3e2d1c0b9a8']" in patterns
    json.dumps(bundle)  # serialisable
