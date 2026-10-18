# Playbook: Impossible Travel / Anomalous Sign-in

**NIST SP 800-61 phase:** Detection & Analysis -> Containment
**Security+ domain:** 2.4 Indicators (account compromise: impossible travel, concurrent sessions), 4.6 Identity and access management, 3.3 Zero trust / conditional access
**ATT&CK:** T1078 Valid Accounts, T1078.004 Cloud Accounts, T1550.004 Web Session Cookie (token theft), T1114.003 Email Forwarding Rule, T1098.005 Device Registration

## Trigger

- IdP / CASB: *Impossible travel: logon from two countries in 1 h* (two successful sign-ins whose distance / time delta exceeds plausible speed, typically > 900 km/h)
- SIEM: successful VPN logon from a country where the organisation has no staff
- "Unfamiliar sign-in properties" / "anonymous IP" (Tor, commercial VPN) risk detections
- User reports an MFA prompt they did not initiate (MFA fatigue - treat as a credential already known to the attacker)

## Severity matrix

| Factor | P1 | P2 | P3 | P4 |
| --- | --- | --- | --- | --- |
| Account | admin / executive / finance / service account | standard user | standard user, VPN provider explains it | - |
| MFA | satisfied by a *new* method or bypassed via legacy auth | satisfied | satisfied, known device | - |
| Post-logon activity | inbox rule, MFA device added, OAuth consent, mass download | mailbox read only | nothing | nothing |
| Source | threat-feed hit, Tor, hosting ASN | residential foreign | corporate VPN egress | known travel |

## Triage steps

1. Triage: an impossible-travel alert that groups with a prior brute-force / spray on the same user or source IP is a confirmed-credential case, not an anomaly:
   ```bash
   python -m soctk triage data/alerts.json --group-window 60
   ```
2. Build the user's authentication timeline across IdP, VPN and Windows logs:
   ```bash
   python -m soctk timeline data/logs --pivot tgarcia --out case/auth_timeline.md
   ```
   Note every source IP, device, UA, MFA result and application for 48 h.
3. Check both IPs:
   ```bash
   printf "198.51.100.23\n203.0.113.9\n" | python -m soctk ioc - --exclude-private
   ```
   Hosting / VPN / Tor tags on the anomalous one shift this from "travel" to "compromise".
4. Rule out the benign explanations *quickly* (5 minutes, not 50): mobile device on a carrier that egresses abroad, corporate VPN with foreign egress, user actually travelling (ask the manager, not the user, if compromise is suspected), cloud mail client pre-fetching.
5. Check for post-authentication abuse, which decides containment: new inbox rules (especially forward/delete), new MFA methods, OAuth app consents, password changes, SharePoint/OneDrive mass downloads, sent mail to external recipients.
6. If MFA was satisfied from the anomalous location, determine *how* - a new device registered minutes before is attacker-registered; approval via push is MFA fatigue; no MFA at all is legacy auth.

## Escalation criteria

- Any post-authentication change (rules, MFA devices, consents, password)
- Privileged, executive or finance account
- Token / cookie theft indicators (same session ID from two IPs, "device code" sign-ins)
- Sign-in source on the threat feed or an anonymising service
- Preceded by phishing or spray against the same user

## Containment

| Action | Who | Notes |
| --- | --- | --- |
| Revoke all refresh tokens / sign out everywhere | Tier 1 | Do this first; a password reset alone does not kill tokens |
| Reset password | Tier 1 | Communicate out-of-band (phone), not via the possibly-compromised mailbox |
| Remove attacker MFA devices, re-enrol user MFA | Tier 2 | |
| Remove inbox rules and OAuth consents (after screenshot) | Tier 2 | |
| Block source IP at IdP | Tier 1 | Low value - attackers rotate |
| Temporarily disable account | Tier 2 | If privileged or activity unknown |

## Evidence to collect

- IdP sign-in logs (interactive and non-interactive) for the user, 7 days
- Audit log of mailbox changes (rules, forwarding, delegate access), MFA changes, consents
- Mailbox audit: items accessed / sent during the anomalous session
- File access / download logs for the session
- Threat-intel lookups for both IPs with timestamps

## Eradication and recovery

- Confirm no residual forwarding, delegates or consents
- Notify recipients of any mail the attacker sent
- If the session accessed sensitive data, open a data-handling review with legal / privacy
- Conditional access: require compliant device, block legacy auth, enable risk-based re-authentication

## False positives and tuning

- Mobile carriers and privacy relays (e.g. consumer "private relay" features) routinely egress from another country - add known provider ranges to a suppression list with an expiry date
- Corporate VPN egress nodes - map them in the IdP's named locations
- Record every suppression in `docs/alert_tuning_log.md` with evidence
