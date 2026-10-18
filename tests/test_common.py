"""Tests for soctk.common: defang/refang round-trip, IP classification, timestamps, Levenshtein."""
from datetime import timezone

import pytest

from soctk.common import classify_ip, defang, is_routable, levenshtein, md_table, parse_timestamp, refang


@pytest.mark.parametrize("fanged,defanged", [
    ("http://evil.example.com/x", "hxxp://evil[.]example[.]com/x"),
    ("https://evil.example.com", "hxxps://evil[.]example[.]com"),
    ("203.0.113.5", "203[.]0[.]113[.]5"),
    ("user@evil.example.com", "user@evil[.]example[.]com"),
])
def test_defang_refang_round_trip(fanged: str, defanged: str) -> None:
    assert defang(fanged) == defanged
    assert refang(defanged) == fanged
    assert defang(defang(fanged)) == defanged  # idempotent


@pytest.mark.parametrize("text,expected", [
    ("hxxp://a[.]b[.]com", "http://a.b.com"),
    ("hXXps://a(.)b(.)com", "https://a.b.com"),
    ("a{.}b{.}com", "a.b.com"),
    ("a[dot]b[dot]com", "a.b.com"),
    ("203[.]0[.]113[.]45[:]443", "203.0.113.45:443"),
    ("user[@]evil[.]com", "user@evil.com"),
    ("fxp://files[.]example[.]net", "ftp://files.example.net"),
])
def test_refang_variants(text: str, expected: str) -> None:
    assert refang(text) == expected


@pytest.mark.parametrize("ip,cls,routable", [
    ("10.1.2.3", "private", False),
    ("192.168.0.1", "private", False),
    ("172.16.5.5", "private", False),
    ("127.0.0.1", "loopback", False),
    ("169.254.1.1", "link-local", False),
    ("203.0.113.45", "documentation", True),
    ("198.51.100.1", "documentation", True),
    ("8.8.8.8", "public", True),
    ("224.0.0.1", "multicast", False),
    ("::1", "loopback", False),
    ("fe80::1", "link-local", False),
    ("2001:db8::1", "documentation", True),
    ("not-an-ip", "invalid", False),
])
def test_classify_ip(ip: str, cls: str, routable: bool) -> None:
    assert classify_ip(ip) == cls
    assert is_routable(ip) is routable


def test_parse_timestamp_formats() -> None:
    a = parse_timestamp("2026-10-14T08:24:05Z")
    b = parse_timestamp("2026-10-14 08:24:05")
    c = parse_timestamp("2026-10-14T10:24:05+02:00")
    d = parse_timestamp("14/Oct/2026:08:24:05 +0000")
    assert a == b == c == d
    assert a.tzinfo == timezone.utc
    syslog = parse_timestamp("Oct 14 08:24:05", default_year=2026)
    assert syslog == a
    with pytest.raises(ValueError):
        parse_timestamp("yesterday-ish")


def test_levenshtein() -> None:
    assert levenshtein("", "") == 0
    assert levenshtein("abc", "") == 3
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("paypal", "paypai") == 1
    assert levenshtein("example", "exampel") == 2


def test_md_table_escapes_pipes() -> None:
    out = md_table(["a", "b"], [("x|y", "z\nw")])
    assert "x\\|y" in out and "z w" in out
    assert out.splitlines()[1] == "| --- | --- |"
