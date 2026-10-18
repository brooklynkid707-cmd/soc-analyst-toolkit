"""Phishing analyser: header parsing, Authentication-Results, alignment, lookalikes, attachments, scoring."""
import email
import email.policy
from pathlib import Path

import pytest

from soctk.phish import (
    DEFAULT_PROTECTED, analyze, analyze_attachments, extract_urls, lookalike_check,
    normalize_homoglyphs, parse_auth_results, parse_received_chain,
)

PROTECTED = ["example.com", "example-bank.com", "microsoft.com", "paypal.com", "okta.com"]


def _msg(raw: str):
    return email.message_from_string(raw, policy=email.policy.default)


def test_received_chain_oldest_first_and_deltas() -> None:
    msg = _msg(
        "Received: from mx2.example.com (mx2.example.com [203.0.113.10]) by mx.example.com; Tue, 14 Oct 2026 08:00:30 +0000\n"
        "Received: from sender.example.net (sender.example.net [198.51.100.5]) by mx2.example.com; Tue, 14 Oct 2026 08:00:00 +0000\n"
        "Subject: x\n\nbody\n"
    )
    hops = parse_received_chain(msg)
    assert [h.from_host for h in hops] == ["sender.example.net", "mx2.example.com"]
    assert hops[0].ip == "198.51.100.5" and hops[1].ip == "203.0.113.10"
    assert hops[0].delta_seconds is None and hops[1].delta_seconds == 30


@pytest.mark.parametrize("header,expected", [
    ("mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
     {"spf": "pass", "dkim": "pass", "dmarc": "pass", "dkim_domain": "example.com", "dmarc_header_from": "example.com", "spf_mailfrom": "example.com"}),
    ("mx.example.com; spf=softfail smtp.mailfrom=bad.example.net;\n dkim=none; dmarc=fail header.from=example-bank.com",
     {"spf": "softfail", "dkim": "none", "dmarc": "fail", "dmarc_header_from": "example-bank.com", "spf_mailfrom": "bad.example.net"}),
    ("mx.example.com; dkim=fail (bad signature) header.d=evil.example.org", {"spf": "missing", "dkim": "fail", "dmarc": "missing", "dkim_domain": "evil.example.org"}),
])
def test_parse_auth_results(header: str, expected: dict) -> None:
    msg = _msg(f"Authentication-Results: {header}\nSubject: x\n\nbody\n")
    got = parse_auth_results(msg)
    for k, v in expected.items():
        assert got[k] == v


def test_received_spf_fallback() -> None:
    msg = _msg("Received-SPF: Fail (sender IP is 203.0.113.9)\nSubject: x\n\nbody\n")
    assert parse_auth_results(msg)["spf"] == "fail"


@pytest.mark.parametrize("domain,expect_hit,reason_fragment", [
    ("example.com", False, ""),
    ("mail.example.com", False, ""),
    ("micros0ft-support.com", True, "homoglyph"),
    ("rnicrosoft.com", True, "homoglyph"),
    ("login.rnicrosoft-online.example.net", True, "homoglyph"),
    ("paypai.com", True, "edit distance 1"),
    ("exampel.com", True, "character swap"),
    ("examp1e.com", True, "homoglyph"),
    ("exarnple.com", True, "homoglyph"),
    ("example.com.login-portal.net", True, "sub-label"),
    ("example-com.net", True, "TLD folded"),
    ("secure-login-example.com", True, "hyphen padding"),
    ("example-secure.com", True, "hyphen padding"),
    ("gmail.com", False, ""),
    ("totally-unrelated.org", False, ""),
    ("okta.com", False, ""),
    ("data.net", False, ""),  # short labels never trigger the edit-distance rule
])
def test_lookalike_check(domain: str, expect_hit: bool, reason_fragment: str) -> None:
    hit = lookalike_check(domain, PROTECTED)
    assert bool(hit) is expect_hit, hit
    if hit:
        assert reason_fragment in hit[1]


def test_normalize_homoglyphs() -> None:
    assert normalize_homoglyphs("rnicr0s0ft") == "microsoft"
    assert normalize_homoglyphs("pаypаl") == "paypal"  # Cyrillic a


def test_extract_urls_and_link_mismatch() -> None:
    html = '<p>Go to <a href="http://203.0.113.77/login">https://www.example-bank.com/verify</a> or <a href="https://ok.example.com/">here</a></p>'
    urls, mism = extract_urls("plain https://a.example.net/x.", html)
    assert "http://203.0.113.77/login" in urls and "https://ok.example.com/" in urls and "https://a.example.net/x" in urls
    assert mism == [("https://www.example-bank.com/verify", "http://203.0.113.77/login")]


def test_attachment_flags(eml_dir: Path) -> None:
    from soctk.phish import load_eml
    atts = {a.filename: a for a in analyze_attachments(load_eml(eml_dir / "04_malware_invoice_attachment.eml"))}
    docm = atts["Invoice_Q3_8812.docm"]
    exe = atts["Invoice_Q3_8812.pdf.exe"]
    assert len(docm.sha256) == 64 and docm.size > 0
    assert any("VBA" in f for f in docm.flags) and any("macro" in f for f in docm.flags)
    assert any("double extension" in f for f in exe.flags)
    assert any("dangerous extension .exe" in f for f in exe.flags)
    assert any("MZ" in f for f in exe.flags)


def test_sample_verdicts(eml_dir: Path) -> None:
    protected = [l.strip() for l in (eml_dir.parent.parent / "protected_domains.txt").read_text().splitlines() if l.strip() and not l.startswith("#")]
    vips = ["Victoria Harlan"]
    expected = {
        "01_benign_expense_approval.eml": "LIKELY BENIGN",
        "02_credential_phish_bank.eml": "MALICIOUS",
        "03_bec_ceo_fraud.eml": "MALICIOUS",
        "04_malware_invoice_attachment.eml": "MALICIOUS",
        "05_lookalike_m365_password.eml": "MALICIOUS",
        "06_benign_internal_helpdesk.eml": "LIKELY BENIGN",
    }
    for name, verdict in expected.items():
        r = analyze(eml_dir / name, protected, vips)
        assert r.verdict == verdict, (name, r.score, [f.message for f in r.findings])
        for u in r.urls:
            assert "[.]" in u  # URLs are always defanged in output


def test_sender_alignment_findings(eml_dir: Path) -> None:
    r = analyze(eml_dir / "02_credential_phish_bank.eml", DEFAULT_PROTECTED)
    cats = {(f.category, f.message.split(" ")[0]) for f in r.findings}
    msgs = " | ".join(f.message for f in r.findings)
    assert "Reply-To" in msgs and "Return-Path domain" in msgs
    assert "DMARC fail" in msgs and "SPF softfail" in msgs
    assert "Link text" in msgs
    assert ("auth", "DMARC") in cats


def test_bec_without_vip_list_is_still_suspicious(eml_dir: Path) -> None:
    r = analyze(eml_dir / "03_bec_ceo_fraud.eml", DEFAULT_PROTECTED)
    assert r.verdict in ("SUSPICIOUS", "MALICIOUS")
    assert any("claims an internal role" in f.message for f in r.findings)
    assert any("Urgency" in f.message for f in r.findings)
