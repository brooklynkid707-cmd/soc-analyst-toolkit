# Playbook: Ransomware Early Indicators

**NIST SP 800-61 phase:** Detection & Analysis -> **immediate** Containment (minutes matter) -> Eradication & Recovery
**Security+ domain:** 2.4 Indicators (ransomware), 3.4 Resilience and recovery (backups, RPO/RTO), 4.8 Incident response, 5.2 Risk / business continuity
**ATT&CK:** T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery (vssadmin, bcdedit, wbadmin), T1562.001 Impair Defenses, T1489 Service Stop, T1021.002 SMB/Admin Shares, T1078.002 Domain Accounts, T1047 WMI, T1053.005 Scheduled Task, T1567 / T1048 Exfiltration (double extortion), T1018 Remote System Discovery, T1482 Domain Trust Discovery

> The goal of this playbook is to act in the **precursor window** - the hours between initial access and the encryption command - when the EDR / SIEM shows discovery, credential theft, defence evasion and backup tampering but nothing is encrypted yet.

## Trigger (precursors, in rough kill-chain order)

| Stage | Indicator | Example rule |
| --- | --- | --- |
| Discovery | `nltest /dclist`, `net group "domain admins"`, AD enumeration tools, mass port scans from one host | *Port scan from internal host* |
| Credential access | LSASS access, NTDS.dit copy, Kerberoasting bursts | *EDR: credential dumping tool detected* |
| Lateral movement | PsExec / WMI / RDP fan-out from one host, service-account interactive logons | *Service account interactive logon* |
| Defence evasion | Defender / EDR disabled, GPO changes pushing "disable AV", event log clearing | *Antivirus signature disabled* |
| Inhibit recovery | `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no`, backup-server logons / job deletions | *Volume shadow copy deletion* |
| Impact | mass renames with a new extension, ransom-note file creation, canary file modified | *Mass file rename with unusual extension* |

Any **two** stages on the same host or user within 24 h is a P1. Inhibit-recovery or impact alone is a P1.

## Severity matrix

| Factor | P1 (declare incident) | P2 |
| --- | --- | --- |
| Stage | inhibit recovery, impact, defence evasion on a server, credential dumping on a DC | discovery or single lateral-movement alert |
| Scope | > 1 host, any server, backup infrastructure, domain controller | single workstation, contained by EDR |
| Backups | backup server touched or backup jobs modified | untouched and verified |
| Data | exfil indicators before encryption (double extortion) | none |

## Triage steps (target: decision in 15 minutes)

1. Triage and group - the precursor alerts should cluster on the host/user:
   ```bash
   python -m soctk triage data/alerts.json --top 3
   ```
   If the top incident contains `T1490` or `T1486`, stop triaging and start containing (step 5) while someone else continues analysis.
2. Build the timeline for the first host and the account used:
   ```bash
   python -m soctk timeline data/logs --pivot SRV-FILE-02 --out case/rw_timeline.md
   python -m soctk timeline data/logs --pivot svc_backup --out case/rw_account_timeline.md
   ```
   Identify: patient zero, the account driving lateral movement, every host that account touched, and whether the backup server appears.
3. Extract and distribute indicators (the ransom note, extension, tooling hashes, C2) to EDR and the network team:
   ```bash
   python -m soctk ioc case/rw_timeline.md --csv case/rw_iocs.csv --stix case/rw_iocs.json
   ```
4. Hunt fleet-wide for the same tooling hashes, the same service-account logons, and `vssadmin` / `wbadmin` / `bcdedit` executions in the last 24 h.
5. **Contain now** (see below). Do not wait for full scope.
6. Check backups *independently* of the production domain: are the last good backups intact, offline / immutable, and restorable? Ask the backup owner to verify in writing.
7. Check for exfiltration preceding the activity (double extortion) - run the [Data exfiltration](data_exfiltration.md) triage steps on the same hosts.

## Escalation criteria

- Any inhibit-recovery or impact indicator: declare a P1 incident, page the IR lead, inform management and open the crisis bridge
- Backup infrastructure touched
- Domain admin / service account compromise
- More than one host - this is the point where "an alert" becomes "an incident"
- Ransom note observed: legal, communications and (per policy) cyber-insurance / law enforcement notifications start now

## Containment (parallel, not sequential)

| Action | Who | Notes |
| --- | --- | --- |
| EDR network-isolate affected hosts | Tier 1/2 - pre-approved for this playbook | Keep powered on for memory capture; isolate, do not shut down |
| Disable the compromised accounts (especially service / admin), reset krbtgt twice if DC compromise is suspected | Tier 2 + AD team | krbtgt reset breaks attacker golden tickets; do it carefully (two resets, 10 h apart) |
| Block C2 and tooling download hosts at the perimeter | Tier 1 | |
| Disconnect / protect backup server and verify immutability | Backup owner | Do not log in with domain admin from a possibly compromised host |
| Disable SMB admin shares / RDP via GPO or firewall between workstations and servers | Network team | Stops fan-out |
| Enable EDR "block mode" / hardened policy fleet-wide | Endpoint engineering | |
| If encryption is active: segment at the switch / firewall level (VLAN isolation) | Network team | Faster than per-host |

## Evidence to collect

- Memory capture from patient zero and one encrypting host (if any) before isolation release
- EDR process trees and command lines for all precursor alerts
- Ransom note(s), encrypted file sample + original if available (for decryptor identification), new extension
- AD change audit: group membership changes, GPO modifications, new accounts
- Backup server audit logs and job history
- Network flows to C2 and any exfil destinations
- Timeline exports and the alert worklist JSON

## Eradication and recovery

- Rebuild (not clean) every host the attacker controlled; reimage from gold images
- Reset all privileged credentials, service accounts, and krbtgt; rotate secrets stored on affected hosts
- Restore from verified-clean backups in a staged, monitored environment; scan before reconnecting
- Confirm initial-access vector is closed (phishing, exposed RDP/VPN, unpatched edge device - check CVEs with `soctk ioc` on the vendor advisory)
- Business recovery prioritised by `data/assets.csv` criticality

## Post-incident

- Time from first precursor alert to containment (the number that matters)
- Which precursor alerts were P3/P4 in the queue and why; re-score them (`SEVERITY_WEIGHT`, asset criticality) and document in `docs/alert_tuning_log.md`
- Backup immutability, offline copies and restore testing cadence
- Tabletop the scenario with IT operations within 30 days
