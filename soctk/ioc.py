"""IOC extraction, classification and offline enrichment.

Pulls IPv4/IPv6 addresses, domains, URLs, file hashes, e-mail addresses and
CVE identifiers out of arbitrary text (tickets, e-mails, pasted logs), refangs
any defanged indicators first, de-duplicates, flags non-routable IPs and looks
every indicator up in a local CSV threat-intel feed.

Exports to CSV or a STIX-2.1-style JSON bundle of ``indicator`` objects.
"""
from __future__ import annotations

import csv
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .common import classify_ip, defang, is_routable, iso, md_table, refang, write_text

# Order matters: URLs first so their host/path pieces are not re-matched as
# bare domains or IPs (we track consumed spans).
_URL_RE = re.compile(
    r"\b(?:hxxps?|https?|fxp|ftp)://[^\s<>\"'\)\]]+", re.IGNORECASE
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
# Pragmatic IPv6: grab any hex/colon run with >= 2 colons, then validate with ipaddress.
_IPV6_RE = re.compile(r"(?<![\w:.])[0-9a-f:]{2,39}(?![\w:.])", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?P<tld>[a-z]{2,24})\b", re.IGNORECASE
)

# Common file extensions that look like domains in logs ("report.pdf", "svchost.exe").
_FILE_EXT_TLDS = {
    "exe", "dll", "pdf", "doc", "docx", "xls", "xlsx", "zip", "rar", "txt", "log",
    "js", "ps1", "bat", "cmd", "py", "sh", "json", "yaml", "yml", "csv", "html", "htm",
    "jpg", "png", "gif", "iso", "img", "vbs", "scr", "lnk", "jar", "msi", "hta",
}

IOC_TYPES = ("url", "email", "ipv4", "ipv6", "domain", "sha256", "sha1", "md5", "cve")


@dataclass
class IOC:
    """A single extracted indicator with context."""

    type: str
    value: str
    defanged: str
    classification: str = ""        # e.g. public / private / documentation (IPs), tld (domains)
    routable: bool | None = None    # only for IPs
    count: int = 1
    threat_intel: dict[str, str] = field(default_factory=dict)

    @property
    def is_known_bad(self) -> bool:
        return bool(self.threat_intel)


def _mask(text: str, spans: list[tuple[int, int]]) -> str:
    """Blank out already-consumed spans so sub-matches are not extracted twice."""
    chars = list(text)
    for a, b in spans:
        for i in range(a, b):
            chars[i] = " "
    return "".join(chars)


def extract_iocs(text: str) -> list[IOC]:
    """Extract and de-duplicate all IOC types from ``text``.

    The text is refanged before matching so ``hxxp://evil[.]example[.]com``
    and ``http://evil.example.com`` collapse into one indicator.
    """
    working = refang_text(text)
    found: dict[tuple[str, str], IOC] = {}

    def add(kind: str, raw: str, **extra: object) -> None:
        value = raw.strip().rstrip(".,;:")
        if kind in ("domain", "email"):
            value = value.lower()
        if kind in ("md5", "sha1", "sha256"):
            value = value.lower()
        if kind == "cve":
            value = value.upper()
        key = (kind, value)
        if key in found:
            found[key].count += 1
            return
        found[key] = IOC(type=kind, value=value, defanged=defang(value), **extra)  # type: ignore[arg-type]

    consumed: list[tuple[int, int]] = []

    for m in _URL_RE.finditer(working):
        add("url", m.group(0))
        consumed.append(m.span())
    working = _mask(working, consumed)
    consumed = []

    for m in _EMAIL_RE.finditer(working):
        add("email", m.group(0))
        consumed.append(m.span())
    working = _mask(working, consumed)
    consumed = []

    # Hashes: longest first so a SHA-256 never yields an embedded "MD5".
    for kind, rx in (("sha256", _SHA256_RE), ("sha1", _SHA1_RE), ("md5", _MD5_RE)):
        for m in rx.finditer(working):
            add(kind, m.group(0))
            consumed.append(m.span())
        working = _mask(working, consumed)
        consumed = []

    for m in _CVE_RE.finditer(working):
        add("cve", m.group(0))
        consumed.append(m.span())
    working = _mask(working, consumed)
    consumed = []

    for m in _IPV4_RE.finditer(working):
        ip = m.group(0)
        add("ipv4", ip, classification=classify_ip(ip), routable=is_routable(ip))
        consumed.append(m.span())
    working = _mask(working, consumed)
    consumed = []

    for m in _IPV6_RE.finditer(working):
        candidate = m.group(0)
        if candidate.count(":") < 2 or classify_ip(candidate) == "invalid":
            continue
        add("ipv6", candidate, classification=classify_ip(candidate), routable=is_routable(candidate))
        consumed.append(m.span())
    working = _mask(working, consumed)

    for m in _DOMAIN_RE.finditer(working):
        tld = m.group("tld").lower()
        if tld in _FILE_EXT_TLDS:
            continue
        add("domain", m.group(0), classification=f"tld:{tld}")

    return sorted(found.values(), key=lambda i: (IOC_TYPES.index(i.type), i.value))


def refang_text(text: str) -> str:
    """Refang every token in a block of text (used before regex extraction)."""
    return refang(text)


# --------------------------------------------------------------------------
# Threat-intel enrichment (offline CSV feed)
# --------------------------------------------------------------------------

def load_threat_feed(path: str | Path) -> dict[str, dict[str, str]]:
    """Load a CSV feed with at least ``indicator`` and ``type`` columns.

    Returns a mapping of lower-cased indicator -> row.
    """
    feed: dict[str, dict[str, str]] = {}
    p = Path(path)
    if not p.exists():
        return feed
    with p.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            feed[refang(row["indicator"]).lower()] = row
    return feed


def enrich(iocs: Iterable[IOC], feed: dict[str, dict[str, str]]) -> list[IOC]:
    """Attach feed rows to matching IOCs. URLs also match on their host."""
    out = []
    for ioc in iocs:
        hit = feed.get(ioc.value.lower())
        if not hit and ioc.type == "url":
            host = re.sub(r"^[a-z]+://", "", ioc.value, flags=re.IGNORECASE).split("/")[0].split(":")[0]
            hit = feed.get(host.lower())
        if hit:
            ioc.threat_intel = {k: v for k, v in hit.items() if k != "indicator"}
        out.append(ioc)
    return out


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------

def to_csv(iocs: Iterable[IOC], path: str | Path) -> Path:
    """Write IOCs as CSV (defanged value included for safe sharing)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["type", "value", "defanged", "classification", "routable", "count", "ti_verdict", "ti_source", "ti_tags"])
        for i in iocs:
            w.writerow([
                i.type, i.value, i.defanged, i.classification,
                "" if i.routable is None else str(i.routable).lower(), i.count,
                i.threat_intel.get("verdict", ""), i.threat_intel.get("source", ""), i.threat_intel.get("tags", ""),
            ])
    return p


_STIX_PATTERN = {
    "ipv4": "[ipv4-addr:value = '{v}']",
    "ipv6": "[ipv6-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "email": "[email-addr:value = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "cve": "[vulnerability:name = '{v}']",
}


def to_stix(iocs: Iterable[IOC], source_name: str = "soctk") -> dict:
    """Build a STIX-2.1-style bundle of ``indicator`` objects.

    Not a full STIX implementation; it follows the object shape closely enough
    to be ingested by tooling that accepts ``indicator`` patterns.
    """
    now = iso(datetime.now(timezone.utc))
    objects = []
    for i in iocs:
        labels = ["malicious-activity"] if i.is_known_bad else ["anomalous-activity"]
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, i.type + ':' + i.value)}",
            "created": now,
            "modified": now,
            "name": f"{i.type}: {i.defanged}",
            "pattern": _STIX_PATTERN[i.type].format(v=i.value.replace("'", "\\'")),
            "pattern_type": "stix",
            "valid_from": now,
            "labels": labels,
        }
        if i.threat_intel:
            obj["description"] = f"Matched local feed: {i.threat_intel}"
        objects.append(obj)
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
        "x_soctk_source": source_name,
    }


def to_markdown(iocs: Iterable[IOC]) -> str:
    rows = [
        (i.type, i.defanged, i.classification or "-", i.count,
         i.threat_intel.get("verdict", "-"), i.threat_intel.get("tags", "-"))
        for i in iocs
    ]
    return md_table(["Type", "Indicator (defanged)", "Class", "Seen", "TI verdict", "TI tags"], rows)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def run_cli(args) -> int:
    text = Path(args.input).read_text(encoding="utf-8", errors="replace") if args.input != "-" else __import__("sys").stdin.read()
    iocs = extract_iocs(text)
    feed = load_threat_feed(args.threat_feed) if args.threat_feed else {}
    iocs = enrich(iocs, feed)
    if args.types:
        wanted = set(args.types.split(","))
        iocs = [i for i in iocs if i.type in wanted]
    if args.exclude_private:
        iocs = [i for i in iocs if i.routable is not False]

    print(f"Extracted {len(iocs)} unique indicators from {args.input}")
    by_type: dict[str, int] = {}
    for i in iocs:
        by_type[i.type] = by_type.get(i.type, 0) + 1
    print("  " + ", ".join(f"{k}={v}" for k, v in by_type.items()))
    hits = [i for i in iocs if i.is_known_bad]
    if feed:
        print(f"  Threat-intel matches: {len(hits)}")
    print()
    print(to_markdown(iocs))

    if args.csv:
        print(f"\nCSV written: {to_csv(iocs, args.csv)}")
    if args.stix:
        write_text(args.stix, json.dumps(to_stix(iocs), indent=2))
        print(f"STIX bundle written: {args.stix}")
    if args.json:
        write_text(args.json, json.dumps([asdict(i) for i in iocs], indent=2))
        print(f"JSON written: {args.json}")
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser("ioc", help="Extract, defang/refang, classify and enrich IOCs from text")
    p.add_argument("input", help="Text file to scan ('-' for stdin)")
    p.add_argument("--threat-feed", default="data/threat_intel/feed.csv", help="Local CSV threat-intel feed")
    p.add_argument("--types", help="Comma-separated subset of types to keep (e.g. ipv4,domain)")
    p.add_argument("--exclude-private", action="store_true", help="Drop private/loopback/reserved IPs")
    p.add_argument("--csv", help="Write CSV export here")
    p.add_argument("--stix", help="Write STIX-like JSON bundle here")
    p.add_argument("--json", help="Write raw JSON here")
    p.set_defaults(func=run_cli)
