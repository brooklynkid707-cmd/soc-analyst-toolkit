# Escalation matrix

Who to involve, how fast, and through which channel. Priorities match `python -m soctk triage` (P1 >= 80, P2 >= 55, P3 >= 30, P4 < 30) and the playbooks' severity matrices.

## Response targets

| Priority | Acknowledge | Initial triage complete | Containment decision | Update cadence | Hours |
| --- | --- | --- | --- | --- | --- |
| P1 | 15 min | 1 h | 1 h | every 1 h to IR lead, every 4 h to management | 24x7, on-call paged |
| P2 | 30 min | 4 h | 4 h | every 4 h | 24x7 |
| P3 | 4 h | 1 business day | 2 business days | daily | business hours |
| P4 | next shift | 3 business days | n/a (tuning / hygiene) | weekly summary | business hours |

## Who gets involved

| Role | P1 | P2 | P3 | P4 | Channel |
| --- | --- | --- | --- | --- | --- |
| Tier 1 analyst | works under Tier 2 direction | owns triage, escalates on criteria | owns | owns | ticket |
| Tier 2 analyst | owns investigation | owns | consulted | - | ticket + chat |
| IR lead | incident commander; declares incident | informed, consulted on containment | - | - | page + bridge |
| SOC manager | informed within 1 h | informed daily | weekly report | weekly report | phone / e-mail |
| IT operations / desktop | executes isolation, reimage, resets | as needed | as needed | - | ticket |
| Identity / AD team | credential resets, krbtgt, conditional access | as needed | - | - | ticket + chat |
| Network team | perimeter blocks, segmentation | blocks | - | - | ticket |
| Legal / privacy | if regulated data or insider | if regulated data | - | - | phone (IR lead) |
| HR | insider cases, any employee discipline | insider cases | - | - | phone (IR lead) |
| Communications | if customer / public impact | - | - | - | via SOC manager |
| Executive leadership | ransomware, confirmed breach, major outage | - | - | - | via SOC manager |
| Cyber insurance / law enforcement | ransomware, extortion, confirmed breach (per policy) | - | - | - | via legal |

## Hard escalation triggers (Tier 1 -> Tier 2 immediately, regardless of score)

- Credential dumping, LSASS / NTDS access, Kerberoasting
- Confirmed C2 or beaconing
- Any alert on a `crown-jewel` asset or a domain admin / service account
- `vssadmin` / `wbadmin` / `bcdedit` recovery tampering, mass file renames, ransom notes
- Credentials entered on a phishing page
- Successful logon following brute force / spray from the same source
- Confirmed data movement of regulated data
- Anything the analyst cannot explain within the triage SLA

## Hard incident-declaration triggers (Tier 2 -> IR lead, crisis bridge opened)

- Ransomware precursor stages >= 2, or any impact / inhibit-recovery stage
- Domain controller or identity provider compromise
- More than 3 hosts with the same malicious indicator
- Confirmed exfiltration of regulated data
- Active attacker interaction observed (hands-on-keyboard)

## Communication rules

- One incident, one ticket, one chat thread; the ticket is the system of record
- Defang every indicator in chat and e-mail (`soctk ioc` output is already defanged)
- Never contact a suspected insider or a compromised user's mailbox about the investigation - use phone
- Status updates follow the template: *what we know / what we are doing / what we need / next update at*
