# Playbook: Data Exfiltration

**NIST SP 800-61 phase:** Detection & Analysis -> Containment -> Post-incident (regulatory notification decision)
**Security+ domain:** 2.4 Indicators (unusual outbound traffic, DLP), 4.4 Monitoring (NetFlow, proxy, DLP), 5.1 Data classification and legal/regulatory notification
**ATT&CK:** T1567.002 Exfiltration to Cloud Storage, T1048 Exfiltration Over Alternative Protocol, T1041 Exfiltration Over C2 Channel, T1030 Data Transfer Size Limits, T1560 Archive Collected Data, T1074 Data Staged, T1020 Automated Exfiltration

## Trigger

- SIEM: *Large outbound transfer to cloud storage* (> 500 MB to unsanctioned storage, or > 3x the host's 30-day baseline)
- DLP: classified data pattern leaving via e-mail, web upload, USB
- NetFlow / firewall: sustained outbound from a server that normally only receives; DNS TXT/long-label query volume (DNS tunnelling); outbound SSH/FTP/SMB to the internet
- EDR: archive creation (`7z a -p`, `rar a -hp`) followed by network activity
- Preceding incidents: C2 beacon ([Malware](malware_on_endpoint.md)) or compromised account ([Impossible travel](impossible_travel.md)) - exfil is usually the *last* step, so check whether an earlier incident exists for the same entity

## Severity matrix

| Factor | Raises priority when... |
| --- | --- |
| Data classification | confidential / regulated (PII, PHI, PCI, source code) = P1 |
| Volume | > 1 GB or > 10x baseline = one band up |
| Destination | threat-feed hit, personal cloud storage, Tor, foreign hosting = one band up; sanctioned corporate SaaS = tune |
| Source asset | file server, database, backup server, executive laptop = P1 |
| Context | preceded by malware / compromise = P1; HR-flagged user = see [Insider threat](insider_threat.md) |

## Triage steps

1. Triage the queue; an exfil alert that groups with a prior C2 or anomalous sign-in on the same host/user is the end of a kill chain, not a standalone event:
   ```bash
   python -m soctk triage data/alerts.json --top 10
   ```
2. Build the host's timeline and look *backwards* from the transfer for staging (archive creation, mass file reads from a share, database export) and for the initial access:
   ```bash
   python -m soctk timeline data/logs --pivot LT-EXEC-001 --out case/exfil_timeline.md
   ```
3. Characterise the destination:
   ```bash
   echo "192.0.2.200" | python -m soctk ioc - --threat-feed data/threat_intel/feed.csv
   ```
   Then in the proxy logs: destination hostname, SNI, HTTP method (PUT/POST), content type, User-Agent, session duration, total bytes.
4. Quantify: bytes out vs the host's and the user's 30-day baseline; number of files (DLP / file-access logs); what share or system the data came from.
5. Identify *what* left: DLP match details, file names from file-audit logs, database audit for bulk SELECT/export. If you cannot name the data, say so explicitly in the ticket - "unknown" drives the legal decision.
6. Check for the same destination from other hosts (campaign vs single user).

## Escalation criteria

- Regulated or confidential data confirmed or plausibly involved -> IR lead **and** legal / privacy officer (notification clocks may start now)
- Volume > 1 GB, or destination on the threat feed
- Source is a server or a privileged user
- Preceded by compromise indicators on the same entity
- Potential insider (data matches the user's own project but destination is personal) -> HR + legal before any contact with the user

## Containment

| Action | Who | Notes |
| --- | --- | --- |
| Block destination at proxy / firewall / DNS | Tier 1 | Capture flow logs first |
| EDR isolate host | Tier 2 | If transfer is ongoing and the host is compromised |
| Disable user account / revoke tokens | Tier 2 | If account compromise is suspected |
| Revoke cloud-storage share links / OAuth app | Tier 2 + SaaS admin | |
| Preserve (do not wipe) the host | Everyone | Legal hold may apply |

## Evidence to collect

- NetFlow / firewall / proxy logs for the host and destination (full window, not just the alert)
- DLP incident detail and matched content samples
- File-audit logs (4663 / SACL, SharePoint audit) listing files read
- Staging artefacts: archives, temp directories, their hashes and sizes
- Cloud provider audit logs if a corporate SaaS tenant was the destination
- Chain-of-custody record if legal is involved

## Eradication and recovery

- Remove the exfil channel (malware, OAuth app, share link) and the access that enabled it
- Rotate any credentials or keys contained in the exfiltrated data
- Legal / privacy determine notification obligations; the SOC provides the facts: what, how much, when, to where, confidence
- Add destination and pattern to detections; adjust DLP policy if it missed the content

## False positives and tuning

- Backup jobs to a sanctioned cloud (verify the destination tenant and the schedule)
- Developers pushing large repos / artefacts to approved registries
- Video uploads by marketing - baseline per department, not per organisation
- Record the baseline exception in `docs/alert_tuning_log.md`
