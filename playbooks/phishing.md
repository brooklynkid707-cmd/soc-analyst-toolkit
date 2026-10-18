# Playbook: Phishing

**NIST SP 800-61 phase:** Detection & Analysis -> Containment, Eradication & Recovery
**Security+ domain:** 2.2 Social engineering (phishing, BEC, pretexting), 4.8 Incident response
**ATT&CK:** T1566.001 Spearphishing Attachment, T1566.002 Spearphishing Link, T1204.001/002 User Execution, T1598 Phishing for Information, T1534 Internal Spearphishing (if a compromised mailbox sends internally)

## Trigger

- User clicks "Report phishing" (mail arrives in the SOC abuse mailbox as an `.eml` attachment)
- Mail gateway alert: DMARC fail + lookalike domain, URL rewrite detonation verdict, attachment sandbox verdict
- SIEM rule *Phishing e-mail reported by user* (`T1566.002`)
- EDR alert with a mail client (Outlook) as the parent process - handle with [Malware on endpoint](malware_on_endpoint.md) in parallel

## Severity matrix

| Factor | Raises priority when... |
| --- | --- |
| Interaction | user clicked / opened attachment / entered credentials (P1 if creds entered on an external site) |
| Recipients | > 10 recipients or any VIP / finance / IT admin (one band up) |
| Payload | macro / executable / ISO attachment, or credential harvesting page (P2 minimum) |
| Authentication | SPF/DKIM/DMARC all pass on a lookalike domain = attacker-owned infrastructure, not spoofing (treat as targeted) |
| BEC | wire / gift-card / payroll change request from an executive display name (P2 even with zero technical indicators) |

Default: reported-but-not-clicked, single recipient, generic lure = **P3**. Clicked + credentials entered = **P1**.

## Triage steps

1. Pull the original message as `.eml` (not a forward - forwarding destroys the Received chain). Save it to the case folder.
2. Run the analyser:
   ```bash
   python -m soctk phish case/reported.eml --out-dir case/phish
   ```
   Read, in order: verdict and score; `Auth` line (SPF/DKIM/DMARC); lookalike findings; link-text mismatches; attachment flags.
3. Extract and enrich indicators from the e-mail and the analyser's Markdown report:
   ```bash
   python -m soctk ioc case/phish/reported.md --csv case/iocs.csv --stix case/iocs.json
   ```
   Any `TI verdict = malicious` hit means this is a known campaign: search the gateway for the sender, subject and URL host across **all** mailboxes for the last 7 days.
4. Determine blast radius in the mail gateway / M365 message trace: who else received it, who clicked (URL rewrite logs), who opened the attachment.
5. For each clicker, check the identity provider for a sign-in from a new IP/device within 30 minutes of the click, new inbox rules, new MFA devices, and OAuth consents.
6. If an attachment was opened, pivot to the endpoint:
   ```bash
   python -m soctk timeline logs/ --pivot WS-FIN-017 --start 2026-10-14T08:00:00Z --out case/timeline.md
   ```
   Look for the mail client spawning Office, Office spawning a shell, and the first outbound connection after that.
7. Record the triage decision and the score in the ticket; attach `case/phish/*.md`.

## Escalation criteria (Tier 1 -> Tier 2 / IR lead)

- Credentials entered on an attacker page (assume compromise: go to [Impossible travel](impossible_travel.md) steps 5-7)
- Attachment executed and EDR shows any child process of the document reader
- More than 25 recipients, or any VIP from `data/vips.txt`
- BEC with an actual payment or payroll change in progress -> IR lead **and** finance controller immediately
- Internal mailbox is the *sender* (account already compromised)

## Containment

| Action | Who may do it | Notes |
| --- | --- | --- |
| Purge message from all mailboxes (soft delete) | Tier 1 | Record message IDs purged |
| Block sender domain / URL host at gateway and proxy | Tier 1 | Use the defanged IOC list; refang with `soctk ioc` before pasting into the console |
| Sinkhole lookalike domain in DNS | Tier 2 | |
| Reset password, revoke sessions and tokens, re-enrol MFA | Tier 2 | For every user who entered credentials |
| Remove malicious inbox rules / OAuth consents | Tier 2 | Screenshot first |
| Network-isolate endpoint | Tier 2 | Only if execution confirmed; see Malware playbook |

## Evidence to collect

- Original `.eml` with full headers (hash it, note hash in ticket)
- Analyser JSON/Markdown output; gateway trace export; URL-click report
- Screenshot of the landing page from a sandbox / isolated browser (never from an analyst workstation)
- Attachment sample stored password-protected in the malware share, SHA-256 recorded
- IdP sign-in logs for every clicker, 24 h before and after

## Eradication and recovery

- Confirm no remaining copies in mailboxes after purge; confirm the user's credentials were rotated before re-enabling
- Submit lookalike domain for takedown (registrar abuse) and to the mail provider's abuse desk
- Add the campaign's subject / sender patterns to the gateway rule set; record in `docs/alert_tuning_log.md`

## Post-incident

- Was the report button used? How long from delivery to report? (target < 30 min)
- Did the gateway have the data to block it (DMARC fail, lookalike) and why did it not?
- Feed lures into the next awareness simulation
