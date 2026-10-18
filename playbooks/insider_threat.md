# Playbook: Insider Threat

**NIST SP 800-61 phase:** Detection & Analysis (with HR / legal coordination) -> Containment
**Security+ domain:** 2.1 Threat actors (insider: malicious vs unintentional), 5.1/5.3 Governance, acceptable-use policy, evidence handling, 5.6 Awareness
**ATT&CK:** T1052.001 Exfiltration over USB, T1567 Exfiltration to Web Service, T1530 Data from Cloud Storage, T1114 Email Collection, T1078 Valid Accounts, T1070 Indicator Removal (log clearing), T1485 Data Destruction

> Insider cases are different from every other playbook: the "attacker" is an authorised user, evidence may be needed for HR or court, and the person must usually **not** be alerted during investigation. Involve HR and legal before any action the user could notice.

## Trigger

- HR notification: resignation, termination pending, performance management, access to a sensitive project ending
- UEBA / SIEM: *USB mass storage device connected* + large file copy, *Large outbound transfer* to personal cloud/e-mail, *Logon outside business hours* with file-share access, mass download from SharePoint / source repo, printing spikes
- DLP: internal classified documents sent to a personal address
- Peer or manager report
- Log tampering or audit-policy changes by an admin

## Severity matrix

| Factor | Raises priority when... |
| --- | --- |
| Access level | admin / DBA / developer with production or source access = P1 |
| Data | trade secrets, customer PII, M&A, source code = P1; personal files = P4 |
| Trigger context | HR flag + any data movement = P2 minimum |
| Volume / pattern | mass copy across many projects (not their own) = one band up |
| Destruction | deletion of data, backups, logs = P1 and immediate containment regardless of HR timing |

## Triage steps

1. Confirm authority: open the ticket as **restricted** (SOC lead + HR + legal only). Do not use the user's name in Slack / broad channels; use the case ID.
2. Triage and group the user's alerts - insiders generate many low-severity alerts that are individually ignorable:
   ```bash
   python -m soctk triage data/alerts.json --group-window 240 --top 10
   ```
   A wider grouping window is appropriate here; insider activity is spread over hours or days.
3. Build the user's activity timeline across every source:
   ```bash
   python -m soctk timeline data/logs --pivot ceo.vharlan --start 2026-10-01T00:00:00Z --out case/insider_timeline.md
   ```
   Look for: access to data outside the user's role, out-of-hours access, USB events, personal cloud / webmail uploads, archive creation, printing, log clearing.
4. Baseline: compare the last 30 days with the previous 90 (file access count, distinct shares, bytes out). The change, not the absolute number, is the signal.
5. Enumerate destinations and media:
   ```bash
   python -m soctk ioc case/insider_timeline.md --exclude-private --csv case/destinations.csv
   ```
6. Preserve first, then analyse: request mailbox and OneDrive litigation hold, EDR telemetry retention extension, and a forensic image if HR/legal indicate a possible dismissal or prosecution.
7. Document *facts* only in the ticket; conclusions about intent belong to HR / legal.

## Escalation criteria

- Any confirmed movement of confidential data to personal control
- Privileged user, or any sign of covering tracks (log clearing, audit policy changes, disabling EDR)
- Destruction of data or backups -> immediate containment, HR timing no longer applies
- Threats or safety concerns -> security / facilities and HR immediately

## Containment (coordinated with HR / legal - timing is their call unless destruction is in progress)

| Action | Who | Notes |
| --- | --- | --- |
| Silent monitoring: enhanced logging, DLP in audit mode for the user | Tier 2 | Does not alert the user |
| Block USB / personal cloud for the user (policy) | Tier 2 | May tip them off - get approval |
| Disable account, revoke tokens, badge, VPN, SaaS - *simultaneously*, at the agreed time | Tier 2 + IT + HR | Usually timed with the HR conversation |
| Collect company devices | HR / IT | Chain of custody form |
| Revoke share links, rotate secrets the user had | Tier 2 | After offboarding |

## Evidence to collect (chain of custody applies)

- Timeline export and the raw logs behind it (hashed)
- File-access audit, DLP incidents, USB device IDs and serials, print logs
- Mailbox / cloud storage audit and hold confirmation
- Forensic image of endpoint(s) with acquisition hashes
- Written HR notification and legal authorisation for monitoring

## Eradication and recovery

- Offboarding checklist completed and verified (accounts, keys, tokens, shared mailboxes, API keys, repo access)
- Rotate shared credentials the person knew
- Assess what was taken and inform data owners; legal decides on external action
- Post-incident: was the HR -> SOC notification timely? Were access rights excessive (least privilege review)?

## False positives

- Legitimate project hand-over before departure (confirm with manager; the destination should be corporate)
- Backups to an approved personal device under a BYOD policy
- Power users whose normal baseline is high - compare to self, not to peers
