# Alert tuning log

Every change to a detection rule, suppression, threshold, or scoring weight is recorded here **before** it is applied. Tuning without a record is how detection coverage silently disappears. Review the log monthly; every suppression has an expiry.

## Principles

1. Tune on **evidence** (ticket IDs, counts, false-positive rate over a stated window), never on annoyance.
2. Prefer **enrichment** (asset criticality, user risk, allow-listed parent process) over blanket suppression.
3. Suppressions name a specific entity or pattern and carry an **expiry date**; the rule itself is not disabled.
4. Every change states the **ATT&CK coverage impact** - what would we no longer see?
5. A rule with a true-positive rate below 5 % over 30 days is a candidate for redesign, not for lowering severity.

## Log

| Date | Rule / weight | Change | Evidence | Coverage impact | Expiry / review | Requested by | Approved by | Ticket |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-10-14 | `Outbound connection to known C2 indicator` | De-dup window raised from 5 to 10 min (`--dedupe-window 10`) | 3 identical firings in 2 min on INC-2026-0001 created 3 tickets | None - first firing still alerts, duplicates counted | Review 2026-11-14 | J. Scirica | SOC lead | TUNE-0041 |
| 2026-10-14 | `Suspicious PowerShell: encoded command` | Suppress when parent process is `CcmExec.exe` **and** signer is the endpoint-management vendor | 212 firings / 30 d, 0 true positives, all SCCM | Encoded PowerShell launched by a *spoofed* SCCM parent would be missed; mitigated by EDR parent-integrity check | 2026-12-31 | Tier 1 | Detection eng. | TUNE-0042 |
| 2026-10-14 | `Impossible travel` | Add corporate VPN egress ranges as named locations in the IdP | 38 firings / 30 d, 31 were VPN egress | None (named locations are evaluated, not ignored) | Review quarterly | Tier 2 | Identity team | TUNE-0043 |
| 2026-10-15 | Triage weight `CRITICALITY_WEIGHT["crown-jewel"]` | Confirm 1.0; add SRV-BKP-06 to `assets.csv` as `crown-jewel` | Backup server was `high`; ransomware playbook requires P1 on any backup-server alert | Raises priority only | Permanent | IR lead | SOC lead | TUNE-0044 |
| 2026-10-16 | `Large outbound transfer to cloud storage` | Baseline per department; marketing threshold 2 GB, others 500 MB | 14 of 17 firings were marketing video uploads to the sanctioned tenant | Marketing exfil under 2 GB missed - DLP content rules still apply | 2026-12-31 | Tier 1 | Detection eng. | TUNE-0045 |
| | | | | | | | | |

## Monthly review checklist

- [ ] Every suppression past its expiry re-justified or removed
- [ ] True-positive rate per rule computed from closed-ticket dispositions
- [ ] New ATT&CK techniques seen in incidents mapped to at least one rule
- [ ] Scoring weights in `soctk/triage.py` still reflect the asset inventory
