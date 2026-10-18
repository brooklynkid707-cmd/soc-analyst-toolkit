# Playbook: Brute Force / Password Spray / Credential Stuffing

**NIST SP 800-61 phase:** Detection & Analysis -> Containment
**Security+ domain:** 2.4 Indicators of malicious activity (password attacks), 4.6 Identity and access management
**ATT&CK:** T1110.001 Password Guessing, T1110.003 Password Spraying, T1110.004 Credential Stuffing, T1078 Valid Accounts (on success), T1021 Remote Services

## Trigger

- SIEM: *Brute force: 20+ failed logons from single source* (Windows 4625 / 4771, Linux `sshd` failed password, VPN / OWA / IdP failures)
- SIEM: *Password spray: 1 failure per account across 50 accounts* (low-and-slow pattern)
- IdP "unfamiliar sign-in properties" or lockout storm (4740)
- WAF / API gateway: many 401s on `/login` with rotating usernames and the same User-Agent

Distinguish the three patterns early - they need different containment:

| Pattern | Shape | Source of creds |
| --- | --- | --- |
| Brute force | many passwords, one or few accounts, one source | none |
| Password spray | one or two passwords, many accounts, one or few sources, slow | none |
| Credential stuffing | one password per account, many accounts, many sources, high success rate | breach dumps |

## Severity matrix

| Factor | P1 | P2 | P3 | P4 |
| --- | --- | --- | --- | --- |
| Any success after failures | privileged / service account | standard user | - | - |
| Target | DC, VPN, IdP admin portal | OWA / M365 / SaaS | internal app | honeypot / lab |
| Accounts touched | > 100 | 20-100 | < 20 | 1 |
| Source | internal host (lateral movement) | external, on threat feed | external, unknown | known scanner noise |

## Triage steps

1. Triage the queue so repeated firings collapse and the spray + any later success on the same IP or user group together:
   ```bash
   python -m soctk triage data/alerts.json --dedupe-window 10 --group-window 60
   ```
   A brute-force alert followed by *Impossible travel* or *Logon success* in the same incident is the key signal.
2. Check the source against intel:
   ```bash
   echo "198.51.100.23" | python -m soctk ioc - --threat-feed data/threat_intel/feed.csv
   ```
   `tor-exit`, `scanner`, `brute-force` tags mean commodity; absence of tags does not mean benign.
3. Build the source-IP timeline across auth logs to count attempts, distinct accounts, and - critically - any `logon_success`:
   ```bash
   python -m soctk timeline logs/ --pivot 198.51.100.23 --limit 200 --out case/bf_timeline.md
   ```
4. In the SIEM, for the same window: distinct accounts targeted, failure reason breakdown (bad password vs unknown user - unknown users imply a purchased list), User-Agent string, and whether lockouts occurred.
5. For every account with a success: pivot on the user, check what the session did (mailbox rules, MFA registration, file access), where else it logged on, and whether MFA was satisfied or bypassed (legacy auth / IMAP / SMTP-AUTH).
6. Check whether the targeted accounts have MFA. No MFA + success = assume compromise.

## Escalation criteria

- Any successful authentication from the attacking source
- Target is a domain controller, VPN concentrator, IdP admin role, or service account
- Lockout storm affecting > 50 users (availability impact; notify service desk)
- Source is an *internal* host (this is lateral movement, not an internet scan -> [Malware on endpoint](malware_on_endpoint.md))

## Containment

| Action | Who | Notes |
| --- | --- | --- |
| Block source IP / ASN at perimeter and IdP | Tier 1 | Note that stuffing rotates IPs; blocking is a speed bump |
| Enable / verify lockout and smart-lockout policy | Tier 2 | Spray is built to stay under threshold - lower the threshold temporarily |
| Force password reset + revoke sessions for compromised accounts | Tier 2 | Reset *before* unblocking |
| Disable legacy auth protocols for the tenant / app | Tier 2 + identity team | The usual MFA bypass |
| Geo / impossible-travel conditional access | Identity team | |

## Evidence to collect

- Export of authentication events for the source (all results, not just failures)
- Account list targeted, with success/failure counts
- IdP sign-in detail for successes (IP, UA, MFA result, device)
- WAF / proxy logs for the login endpoint
- Threat-intel lookup result and timestamp

## Eradication and recovery

- Rotate credentials for compromised accounts; check for persistence they may have set (inbox rules, OAuth, new MFA devices, SSH keys)
- If a password list was used, check the organisation's domain in breach-notification data and force resets for matching users
- Tune: raise `confidence` for the spray rule when the source is on the feed; record in `docs/alert_tuning_log.md`

## False positives

- Misconfigured service with a stale password hammering a DC (one account, internal source, fixed interval): still a ticket, but to the app owner
- Vulnerability scanner authenticated scans
- Mobile device with an old cached credential after a password change (one user, one device)
