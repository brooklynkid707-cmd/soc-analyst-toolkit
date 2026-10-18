"""Shared helpers used by every soctk module.

Everything here is standard library only: timestamp parsing, defang/refang,
Markdown table rendering, IP classification and Levenshtein distance.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

# --------------------------------------------------------------------------
# Time handling
# --------------------------------------------------------------------------

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%d/%b/%Y:%H:%M:%S %z",  # Apache / nginx access log style
    "%b %d %H:%M:%S",        # syslog (no year)
)


def parse_timestamp(value: str | datetime, default_year: int | None = None) -> datetime:
    """Parse a timestamp in any of the common log formats into an aware UTC datetime.

    Naive timestamps are assumed to be UTC. Syslog-style timestamps without a
    year use ``default_year`` (or the current year).
    """
    if isinstance(value, datetime):
        dt = value
    else:
        text = value.strip().replace("Z", "+00:00")
        dt = None
        for fmt in _TS_FORMATS:
            try:
                if fmt == "%b %d %H:%M:%S":  # syslog: supply the year explicitly
                    year = default_year or datetime.now(timezone.utc).year
                    dt = datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
                else:
                    dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            try:
                dt = datetime.fromisoformat(text)
            except ValueError as exc:
                raise ValueError(f"Unrecognised timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    """Render a datetime as a compact ISO-8601 UTC string (``2026-10-17T08:15:00Z``)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Defang / refang
# --------------------------------------------------------------------------

def defang(value: str) -> str:
    """Make an indicator safe to paste into tickets and chat.

    ``http://evil.example.com/x`` -> ``hxxp://evil[.]example[.]com/x``
    ``203.0.113.5``               -> ``203[.]0[.]113[.]5``
    ``user@evil.example.com``     -> ``user@evil[.]example[.]com``
    """
    if "[.]" in value or value.lower().startswith("hxxp"):
        return value  # already defanged; never double-process
    out = re.sub(r"(?i)^http", "hxxp", value)
    out = re.sub(r"(?i)^ftp", "fxp", out)
    return out.replace(".", "[.]")


def refang(value: str) -> str:
    """Reverse any common defanging convention so the indicator is machine-usable.

    Handles ``hxxp``, ``fxp``, ``[.]``, ``(.)``, ``{.}``, ``[dot]``, ``[://]``,
    ``[:]`` and ``[@]``.
    """
    out = value.strip()
    out = re.sub(r"(?i)hxxps?", lambda m: m.group(0).lower().replace("xx", "tt"), out)
    out = re.sub(r"(?i)^fxp", "ftp", out)
    out = re.sub(r"\[\s*://\s*\]", "://", out)
    out = re.sub(r"\[\s*:\s*\]", ":", out)
    out = re.sub(r"\[\s*@\s*\]", "@", out)
    out = re.sub(r"[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]", ".", out, flags=re.IGNORECASE)
    out = re.sub(r"\s+dot\s+", ".", out, flags=re.IGNORECASE)
    return out


# --------------------------------------------------------------------------
# IP classification
# --------------------------------------------------------------------------

def classify_ip(ip: str) -> str:
    """Return ``public``, ``private``, ``loopback``, ``link-local``, ``reserved``,
    ``documentation`` or ``multicast`` for an IPv4/IPv6 string.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        # RFC 5737 documentation ranges are flagged is_private by Python; split them out
        doc_nets = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24") if isinstance(addr, ipaddress.IPv4Address) else ("2001:db8::/32",)
        for net in doc_nets:
            if addr in ipaddress.ip_network(net):
                return "documentation"
        return "private"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"


def is_routable(ip: str) -> bool:
    """True for addresses an attacker could actually sit behind on the internet.

    Documentation ranges (RFC 5737) are treated as routable so synthetic data
    behaves like real external traffic.
    """
    return classify_ip(ip) in {"public", "documentation"}


# --------------------------------------------------------------------------
# String similarity
# --------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Classic edit distance (insert/delete/substitute, each cost 1)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# --------------------------------------------------------------------------
# Markdown rendering
# --------------------------------------------------------------------------

def md_table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    """Render a GitHub-flavoured Markdown table. Pipes in cells are escaped."""
    def cell(v: object) -> str:
        return str(v).replace("|", "\\|").replace("\n", " ")

    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(" --- " for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(cell(v) for v in row) + " |")
    return "\n".join(lines)


def write_text(path: str | Path, text: str) -> Path:
    """Write text to ``path``, creating parent directories. Returns the Path."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p
