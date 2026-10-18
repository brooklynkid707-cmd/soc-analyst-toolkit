"""Phishing e-mail analysis from a raw ``.eml`` file.

Uses only the standard-library ``email`` package. Produces a list of weighted
findings and a 0-100 score:

* **Header analysis** - Received chain walk (hop count, originating IP,
  private-IP origin, hop time anomalies), ``Authentication-Results`` parsing
  for SPF / DKIM / DMARC, From vs Return-Path vs Reply-To alignment,
  display-name spoofing (name says "CEO" but address is webmail), and
  lookalike-domain detection (Levenshtein distance + homoglyph normalisation)
  against a protected-domains list.
* **Body analysis** - URL extraction (defanged in output), link-text vs href
  mismatch, urgency / credential keywords.
* **Attachment analysis** - SHA-256 of every part, dangerous extensions,
  double extensions, macro-enabled Office formats.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

from .common import classify_ip, defang, levenshtein, md_table, write_text

DEFAULT_PROTECTED = ["example.com", "corp.example.com", "example-bank.com", "microsoft.com", "paypal.com", "docusign.com"]
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "protonmail.com", "icloud.com", "aol.com", "mail.com"}
EXEC_TITLES = ("ceo", "cfo", "coo", "cto", "ciso", "president", "chief", "director", "it support", "helpdesk", "help desk", "it department", "security team", "payroll", "hr department")
DANGEROUS_EXT = {".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".hta", ".lnk", ".msi", ".iso", ".img", ".jar", ".cpl", ".reg", ".dll"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".xla", ".doc", ".xls"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tar", ".ace", ".arj", ".cab"}
URGENCY_WORDS = ("urgent", "immediately", "within 24 hours", "account will be", "suspended", "verify your", "confirm your", "action required", "final notice", "password expire", "unusual sign-in", "wire", "gift card", "confidential", "do not share", "are you available", "quick favor", "kindly")
CRED_WORDS = ("password", "login", "sign in", "verify", "credentials", "one-time", "mfa", "2fa", "reset")

HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ı": "i", "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ẟ": "d",
})
_MULTI_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))

_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'\)\]]+")
_HREF_RE = re.compile(r"(?is)<a\b[^>]*href\s*=\s*[\"']?([^\"'\s>]+)[^>]*>(.*?)</a>")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TAG_RE = re.compile(r"<[^>]+>")


@dataclass
class Finding:
    """A single weighted observation."""

    category: str   # header / auth / sender / lookalike / body / attachment
    severity: str   # info / low / medium / high / critical
    weight: int
    message: str


@dataclass
class Hop:
    index: int
    from_host: str
    by_host: str
    ip: str | None
    timestamp: str | None
    delta_seconds: float | None


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    flags: list[str] = field(default_factory=list)


@dataclass
class PhishReport:
    file: str
    subject: str
    from_header: str
    from_addr: str
    from_domain: str
    return_path: str
    reply_to: str
    date: str
    message_id: str
    hops: list[Hop]
    auth: dict[str, str]
    urls: list[str]               # defanged
    attachments: list[Attachment]
    findings: list[Finding]
    score: int
    verdict: str


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------

def load_eml(path: str | Path) -> EmailMessage:
    """Parse an ``.eml`` file with the modern (``default``) e-mail policy."""
    with Path(path).open("rb") as fh:
        return email.message_from_binary_file(fh, policy=email.policy.default)  # type: ignore[return-value]


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip("<>") if "@" in addr else ""


def parse_received_chain(msg: EmailMessage) -> list[Hop]:
    """Walk ``Received`` headers oldest-first and compute inter-hop timing.

    Received headers are prepended by each MTA, so the last one in the file is
    the first hop (closest to the sender).
    """
    headers = list(msg.get_all("Received", []))
    hops: list[Hop] = []
    prev_dt: datetime | None = None
    for idx, raw in enumerate(reversed(headers), 1):
        text = " ".join(str(raw).split())
        m_from = re.search(r"from\s+([^\s;()]+)", text, re.IGNORECASE)
        m_by = re.search(r"\bby\s+([^\s;()]+)", text, re.IGNORECASE)
        ips = _IP_RE.findall(text.split(" by ")[0]) if " by " in text else _IP_RE.findall(text)
        ts_text = text.rsplit(";", 1)[1].strip() if ";" in text else None
        dt: datetime | None = None
        if ts_text:
            try:
                dt = parsedate_to_datetime(ts_text)
            except (TypeError, ValueError):
                dt = None
        delta = (dt - prev_dt).total_seconds() if (dt and prev_dt) else None
        hops.append(Hop(
            index=idx,
            from_host=m_from.group(1) if m_from else "?",
            by_host=m_by.group(1) if m_by else "?",
            ip=ips[0] if ips else None,
            timestamp=dt.isoformat() if dt else ts_text,
            delta_seconds=delta,
        ))
        if dt:
            prev_dt = dt
    return hops


def parse_auth_results(msg: EmailMessage) -> dict[str, str]:
    """Parse ``Authentication-Results`` (and legacy ``Received-SPF``) into
    ``{"spf": "pass", "dkim": "fail", "dmarc": "none", ...}``.

    Values are normalised to lower-case; absent mechanisms are reported as
    ``"missing"``.
    """
    result = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    for raw in msg.get_all("Authentication-Results", []):
        text = " ".join(str(raw).split())
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}\s*=\s*([a-z]+)", text, re.IGNORECASE)
            if m:
                result[mech] = m.group(1).lower()
        m = re.search(r"header\.from=([\w.-]+)", text, re.IGNORECASE)
        if m:
            result["dmarc_header_from"] = m.group(1).lower()
        m = re.search(r"header\.d=([\w.-]+)", text, re.IGNORECASE)
        if m:
            result["dkim_domain"] = m.group(1).lower()
        m = re.search(r"smtp\.mailfrom=([\w.@-]+)", text, re.IGNORECASE)
        if m:
            result["spf_mailfrom"] = m.group(1).lower()
    if result["spf"] == "missing":
        rs = msg.get("Received-SPF")
        if rs:
            result["spf"] = str(rs).split()[0].lower()
    return result


def normalize_homoglyphs(label: str) -> str:
    """Map look-alike characters to their ASCII target so ``rn`` ~ ``m``, ``0`` ~ ``o``."""
    out = label.lower().translate(HOMOGLYPHS)
    for multi, single in _MULTI_HOMOGLYPHS:
        out = out.replace(multi, single)
    return out


def _is_transposition(a: str, b: str) -> bool:
    """True when ``a`` equals ``b`` with exactly one pair of adjacent characters swapped."""
    if len(a) != len(b) or a == b:
        return False
    diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]


def lookalike_check(domain: str, protected: list[str], max_distance: int | None = None) -> tuple[str, str] | None:
    """Return ``(protected_domain, reason)`` when ``domain`` impersonates a protected one.

    Every DNS label and every hyphen-separated token of the domain is compared
    with the registrable label of each protected domain:

    * homoglyph-normalised equality  (``micros0ft`` / ``rnicrosoft`` -> ``microsoft``)
    * Levenshtein distance 1 (or 2 for labels of 8+ chars) on labels of 5+ chars
      (``exampel.com``, ``paypai.com``)
    * protected domain embedded as a sub-label (``example.com.login-portal.net``)
    * hyphen padding / TLD folded into the label (``example-com.net``, ``secure-login-example.com``)

    Exact matches and genuine sub-domains of a protected domain return ``None``.
    """
    domain = domain.lower().strip().rstrip(".")
    if not domain or "." not in domain:
        return None
    for p in protected:
        p = p.lower()
        if domain == p or domain.endswith("." + p):
            return None  # legitimate
    labels = domain.split(".")
    registrable = labels[-2]
    tokens = {lbl for lbl in labels[:-1]} | {t for lbl in labels[:-1] for t in lbl.split("-") if t}
    for p in protected:
        p = p.lower()
        p_reg = p.split(".")[-2] if "." in p else p
        if domain.startswith(p + ".") or f".{p}." in domain:
            return p, "protected domain used as a sub-label"
        if registrable.replace("-", "") == p.replace(".", ""):
            return p, "TLD folded into label"
        if registrable != p_reg and (registrable.startswith(p_reg + "-") or registrable.endswith("-" + p_reg)):
            return p, "hyphen padding around protected name"
        for tok in tokens:
            if tok == p_reg:
                continue
            if normalize_homoglyphs(tok) == normalize_homoglyphs(p_reg):
                return p, f"homoglyph substitution ('{tok}' ~ '{p_reg}')"
            if len(tok) >= 5 and len(p_reg) >= 5:
                allowed = max_distance if max_distance is not None else (2 if len(p_reg) >= 8 else 1)
                dist = levenshtein(tok, p_reg)
                if _is_transposition(tok, p_reg):
                    return p, f"adjacent character swap of '{p_reg}'"
                if 0 < dist <= allowed:
                    return p, f"edit distance {dist} from '{p_reg}'"
    return None


def body_text(msg: EmailMessage) -> tuple[str, str]:
    """Return ``(plain_text, html)`` bodies (either may be empty)."""
    plain, html = "", ""
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain" and not plain:
            plain = part.get_content()
        elif ctype == "text/html" and not html:
            html = part.get_content()
    return plain, html


def extract_urls(plain: str, html: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Return ``(unique_urls, mismatches)`` where mismatches are ``(link_text, href)``
    pairs whose visible host differs from the real target.
    """
    urls: list[str] = []
    mismatches: list[tuple[str, str]] = []
    for href, inner in _HREF_RE.findall(html):
        urls.append(href)
        visible = _TAG_RE.sub("", inner).strip()
        vis_url = _URL_RE.search(visible)
        if vis_url:
            vhost = re.sub(r"^(?:https?://|www\.)", "", vis_url.group(0), flags=re.IGNORECASE).split("/")[0]
            hhost = re.sub(r"^(?:https?://|www\.)", "", href, flags=re.IGNORECASE).split("/")[0]
            if vhost.lower() != hhost.lower():
                mismatches.append((visible, href))
    for src in (plain, _TAG_RE.sub(" ", html)):
        urls.extend(_URL_RE.findall(src))
    seen: list[str] = []
    for u in urls:
        u = u.rstrip(".,;:)")
        if u not in seen:
            seen.append(u)
    return seen, mismatches


def analyze_attachments(msg: EmailMessage) -> list[Attachment]:
    out: list[Attachment] = []
    for part in msg.iter_attachments():
        name = part.get_filename() or "(unnamed)"
        payload = part.get_payload(decode=True) or b""
        flags: list[str] = []
        lower = name.lower()
        suffixes = [s for s in Path(lower).suffixes if len(s) <= 6]
        ext = suffixes[-1] if suffixes else ""
        if ext in DANGEROUS_EXT:
            flags.append(f"dangerous extension {ext}")
        if ext in MACRO_EXT:
            flags.append(f"macro-capable Office format {ext}")
        if ext in ARCHIVE_EXT:
            flags.append(f"archive {ext} (may hide executables / bypass AV)")
        if len(suffixes) >= 2 and suffixes[-2] in {".pdf", ".doc", ".docx", ".xls", ".jpg", ".png", ".txt"}:
            flags.append(f"double extension {''.join(suffixes)}")
        if payload[:2] == b"MZ":
            flags.append("PE executable magic bytes (MZ)")
        if payload[:4] == b"PK\x03\x04" and ext in MACRO_EXT | {".docx", ".xlsx"}:
            if b"vbaProject.bin" in payload:
                flags.append("contains vbaProject.bin (VBA macro)")
        out.append(Attachment(
            filename=name, content_type=part.get_content_type(), size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(), flags=flags,
        ))
    return out


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def analyze(path: str | Path, protected: list[str] | None = None, vips: list[str] | None = None) -> PhishReport:
    """Run every check against one ``.eml`` and return a scored report.

    ``protected`` is the list of domains to defend against lookalikes and
    ``vips`` a list of executive display names that attackers impersonate.
    """
    protected = protected or DEFAULT_PROTECTED
    vips = vips or []
    msg = load_eml(path)
    findings: list[Finding] = []

    def add(cat: str, sev: str, weight: int, text: str) -> None:
        findings.append(Finding(cat, sev, weight, text))

    from_hdr = str(msg.get("From", ""))
    from_name, from_addr = parseaddr(from_hdr)
    from_domain = domain_of(from_addr)
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    reply_to = parseaddr(str(msg.get("Reply-To", "")))[1]
    subject = str(msg.get("Subject", ""))

    # --- Received chain
    hops = parse_received_chain(msg)
    if not hops:
        add("header", "medium", 10, "No Received headers - message did not traverse normal MTAs (or was injected)")
    else:
        origin = hops[0]
        if origin.ip:
            cls = classify_ip(origin.ip)
            if cls in ("private", "loopback"):
                add("header", "low", 3, f"Originating hop IP {origin.ip} is {cls} (internal submission or stripped headers)")
            else:
                add("header", "info", 0, f"Originating hop IP {defang(origin.ip)} ({cls}) via {origin.from_host}")
        for h in hops:
            if h.delta_seconds is not None and h.delta_seconds < -60:
                add("header", "medium", 8, f"Hop {h.index} timestamp goes backwards by {abs(h.delta_seconds):.0f}s (forged Received header?)")
            if h.delta_seconds is not None and h.delta_seconds > 6 * 3600:
                add("header", "low", 3, f"Hop {h.index} delayed {h.delta_seconds / 3600:.1f}h (queued/relayed)")
        if len(hops) > 8:
            add("header", "low", 3, f"Unusually long Received chain ({len(hops)} hops)")
        ext_hosts = [h.from_host for h in hops if h.ip and classify_ip(h.ip) in ("public", "documentation")]
        if from_domain and ext_hosts and not any(from_domain.split(".")[-2] in h for h in ext_hosts):
            add("header", "medium", 8, f"No external hop belongs to sender domain {from_domain} (sent via unrelated infrastructure)")

    # --- Authentication-Results
    auth = parse_auth_results(msg)
    for mech, weight_fail in (("spf", 15), ("dkim", 12), ("dmarc", 20)):
        v = auth.get(mech, "missing")
        if v == "pass":
            add("auth", "info", 0, f"{mech.upper()} pass")
        elif v in ("fail", "softfail", "permerror"):
            add("auth", "high", weight_fail, f"{mech.upper()} {v}")
        elif v in ("none", "missing", "neutral", "temperror"):
            add("auth", "low", 4, f"{mech.upper()} {v} (no policy / not evaluated)")
    dkim_dom = auth.get("dkim_domain")
    if dkim_dom and from_domain and auth.get("dkim") == "pass" and not (dkim_dom == from_domain or from_domain.endswith("." + dkim_dom)):
        add("auth", "medium", 10, f"DKIM signed by {dkim_dom}, not by From domain {from_domain} (not aligned)")

    # --- Sender alignment
    rp_domain = domain_of(return_path)
    rt_domain = domain_of(reply_to)
    if return_path and rp_domain and rp_domain != from_domain and not rp_domain.endswith("." + from_domain):
        add("sender", "medium", 10, f"Return-Path domain {rp_domain} != From domain {from_domain}")
    if reply_to and rt_domain and rt_domain != from_domain:
        sev, w = ("high", 15) if rt_domain in FREE_MAIL else ("medium", 10)
        add("sender", sev, w, f"Reply-To {defang(reply_to)} differs from From {defang(from_addr)}")
    if from_domain in FREE_MAIL:
        add("sender", "low", 5, f"Sender uses free webmail domain {from_domain}")
    name_l = from_name.lower()
    if any(t in name_l for t in EXEC_TITLES) and (from_domain in FREE_MAIL or from_domain not in protected):
        add("sender", "high", 15, f"Display name '{from_name}' claims an internal role but address is {defang(from_addr)}")
    for vip in vips:
        if vip.lower() in name_l and from_domain not in protected:
            add("sender", "critical", 20, f"Display name matches VIP '{vip}' but sender domain {defang(from_domain)} is external")
            break
    m_embedded = re.search(r"[\w.+-]+@[\w.-]+", from_name)
    if m_embedded and m_embedded.group(0).lower() != from_addr.lower():
        add("sender", "high", 15, f"Display name contains a different e-mail address ({defang(m_embedded.group(0))}) than the real sender")

    # --- Lookalike domains
    for label, dom in (("From", from_domain), ("Reply-To", rt_domain), ("Return-Path", rp_domain)):
        if not dom:
            continue
        hit = lookalike_check(dom, protected)
        if hit:
            add("lookalike", "critical", 25, f"{label} domain {defang(dom)} impersonates {hit[0]} ({hit[1]})")

    # --- Body
    plain, html = body_text(msg)
    urls, mismatches = extract_urls(plain, html)
    for text, href in mismatches:
        add("body", "high", 15, f"Link text '{text[:40]}' points to {defang(href)[:80]}")
    for u in urls:
        host = re.sub(r"^(?:https?://|www\.)", "", u, flags=re.IGNORECASE).split("/")[0].split(":")[0]
        if _IP_RE.fullmatch(host):
            add("body", "medium", 8, f"URL uses a bare IP address: {defang(u)[:80]}")
        hit = lookalike_check(host, protected)
        if hit:
            add("lookalike", "critical", 20, f"URL host {defang(host)} impersonates {hit[0]} ({hit[1]})")
        if re.search(r"(?i)(login|signin|verify|secure|account|update|password)", u) and host.lower() not in protected:
            add("body", "medium", 6, f"Credential-themed URL path: {defang(u)[:80]}")
    corpus = (subject + " " + plain + " " + _TAG_RE.sub(" ", html)).lower()
    urg = [w for w in URGENCY_WORDS if w in corpus]
    if urg:
        add("body", "medium" if len(urg) >= 2 else "low", min(12, 4 * len(urg)), f"Urgency/pressure language: {', '.join(urg[:5])}")
    cred = [w for w in CRED_WORDS if w in corpus]
    if cred and urls:
        add("body", "medium", 6, f"Credential keywords with links present: {', '.join(cred[:4])}")

    # --- Attachments
    attachments = analyze_attachments(msg)
    for a in attachments:
        for f in a.flags:
            sev, w = ("critical", 25) if ("PE executable" in f or "dangerous" in f or "double" in f or "VBA" in f) else ("high", 12)
            add("attachment", sev, w, f"{a.filename}: {f}")

    score = min(100, sum(f.weight for f in findings))
    verdict = "MALICIOUS" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LIKELY BENIGN"
    return PhishReport(
        file=str(path), subject=subject, from_header=from_hdr, from_addr=from_addr, from_domain=from_domain,
        return_path=return_path, reply_to=reply_to, date=str(msg.get("Date", "")), message_id=str(msg.get("Message-ID", "")),
        hops=hops, auth=auth, urls=[defang(u) for u in urls], attachments=attachments,
        findings=sorted(findings, key=lambda f: -f.weight), score=score, verdict=verdict,
    )


# --------------------------------------------------------------------------
# Rendering / CLI
# --------------------------------------------------------------------------

def report_markdown(r: PhishReport) -> str:
    lines = [f"# Phishing analysis: {Path(r.file).name}", ""]
    lines.append(f"**Verdict: {r.verdict}** (score {r.score}/100)")
    lines += ["", "## Envelope", ""]
    lines.append(md_table(["Field", "Value"], [
        ("Subject", r.subject), ("From", defang(r.from_header)), ("Return-Path", defang(r.return_path) or "-"),
        ("Reply-To", defang(r.reply_to) or "-"), ("Date", r.date), ("Message-ID", r.message_id),
        ("SPF / DKIM / DMARC", f"{r.auth.get('spf')} / {r.auth.get('dkim')} / {r.auth.get('dmarc')}"),
    ]))
    lines += ["", "## Received chain (oldest first)", ""]
    lines.append(md_table(["#", "From", "By", "IP", "Timestamp", "Delta (s)"], [
        (h.index, h.from_host, h.by_host, defang(h.ip) if h.ip else "-", h.timestamp or "-",
         f"{h.delta_seconds:.0f}" if h.delta_seconds is not None else "-") for h in r.hops
    ]))
    lines += ["", "## Findings", ""]
    lines.append(md_table(["Weight", "Severity", "Category", "Finding"], [(f.weight, f.severity, f.category, f.message) for f in r.findings]))
    lines += ["", "## URLs (defanged)", ""]
    lines += [f"- {u}" for u in r.urls] or ["- none"]
    lines += ["", "## Attachments", ""]
    lines.append(md_table(["Filename", "Type", "Bytes", "SHA-256", "Flags"], [
        (a.filename, a.content_type, a.size, a.sha256, "; ".join(a.flags) or "-") for a in r.attachments
    ]) if r.attachments else "- none")
    return "\n".join(lines) + "\n"


def load_list(path: str | None, default: list[str]) -> list[str]:
    """Read a one-entry-per-line text file, skipping blanks and ``#`` comments."""
    if path and Path(path).exists():
        return [ln.strip() for ln in Path(path).read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    return default


def run_cli(args) -> int:
    protected = [d.lower() for d in load_list(args.protected_domains, DEFAULT_PROTECTED)]
    vips = load_list(args.vips, [])
    paths = [Path(p) for p in args.eml]
    expanded: list[Path] = []
    for p in paths:
        expanded.extend(sorted(p.glob("*.eml")) if p.is_dir() else [p])
    summary_rows = []
    for p in expanded:
        r = analyze(p, protected, vips)
        summary_rows.append((p.name, r.verdict, r.score))
        print(f"=== {p.name} ===")
        print(f"  Verdict : {r.verdict}  (score {r.score}/100)")
        print(f"  Subject : {r.subject}")
        print(f"  From    : {defang(r.from_header)}")
        print(f"  Auth    : SPF={r.auth.get('spf')} DKIM={r.auth.get('dkim')} DMARC={r.auth.get('dmarc')}")
        print(f"  Hops    : {len(r.hops)}" + (f"  origin={defang(r.hops[0].ip)}" if r.hops and r.hops[0].ip else ""))
        for f in r.findings:
            if f.weight > 0 or args.verbose:
                print(f"  [{f.weight:>2}] {f.severity:<8} {f.category:<10} {f.message}")
        if r.urls:
            print("  URLs    : " + "; ".join(r.urls[:4]))
        for a in r.attachments:
            print(f"  Attach  : {a.filename} ({a.size} B) sha256={a.sha256[:16]}... {'; '.join(a.flags) or 'no flags'}")
        if args.out_dir:
            out = Path(args.out_dir) / (p.stem + ".md")
            write_text(out, report_markdown(r))
            write_text(out.with_suffix(".json"), json.dumps(asdict(r), indent=2, default=str))
            print(f"  Report  : {out}")
        print()
    if len(expanded) > 1:
        print("Summary:")
        for name, verdict, score in summary_rows:
            print(f"  {score:>3}  {verdict:<14} {name}")
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser("phish", help="Analyse .eml files: headers, auth results, lookalikes, URLs, attachments")
    p.add_argument("eml", nargs="+", help=".eml file(s) or a directory of them")
    p.add_argument("--protected-domains", default="data/protected_domains.txt", help="Domains to defend against lookalikes")
    p.add_argument("--vips", default="data/vips.txt", help="Executive display names to watch for impersonation")
    p.add_argument("--out-dir", help="Write Markdown + JSON reports here")
    p.add_argument("-v", "--verbose", action="store_true", help="Show zero-weight informational findings")
    p.set_defaults(func=run_cli)
