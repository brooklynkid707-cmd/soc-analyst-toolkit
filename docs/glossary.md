# Glossary

Terms used across the toolkit, the playbooks and the Security+ (SY0-701) objectives they map to.

| Term | Meaning in this toolkit |
| --- | --- |
| **Alert** | A single detection event from a SIEM, EDR, IdP or mail gateway. Input to `soctk triage`. |
| **AMSI** | Antimalware Scan Interface; Windows hook that lets AV inspect script content at run time. Bypassing it is a high-severity PowerShell indicator. |
| **Asset criticality** | Business value of a host (`low`, `medium`, `high`, `crown-jewel`) from `data/assets.csv`; multiplies alert priority. |
| **ATT&CK** | MITRE's matrix of adversary tactics (TA....) and techniques (T....). Every alert, playbook and report row carries technique IDs. |
| **Authentication-Results** | Mail header written by the receiving MTA recording SPF, DKIM and DMARC outcomes. Parsed by `soctk phish`. |
| **BEC** | Business E-mail Compromise: fraud using a spoofed or compromised executive / vendor identity, typically with no malware. |
| **Beaconing** | Periodic outbound connections from an implant to its C2 at a fixed interval with small jitter. |
| **C2** | Command and control infrastructure the attacker uses to task malware. |
| **Containment** | NIST 800-61 phase: stopping the spread / impact (isolate, block, disable) without yet removing the cause. |
| **Crown jewel** | The highest asset tier - domain controllers, databases, backup servers, executive devices. |
| **Defang** | Rewriting an indicator so it cannot be clicked or resolved: `hxxp://evil[.]example[.]com`. `soctk` output is always defanged; `soctk ioc` refangs on input. |
| **DKIM** | DomainKeys Identified Mail: a cryptographic signature over selected headers/body, keyed to a `header.d=` domain. |
| **DMARC** | Policy layer over SPF/DKIM that requires *alignment* of the authenticated domain with the visible `From:` domain and tells receivers what to do on failure. |
| **Dwell time** | Time from first attacker activity to detection. Computed in `soctk report` from `key_times`. |
| **EDR** | Endpoint Detection and Response: agent telemetry (process, file, network, registry) plus response actions (isolate, kill, quarantine). |
| **Eradication** | NIST 800-61 phase: removing the cause - malware, persistence, attacker accounts - after containment. |
| **Homoglyph** | A character that looks like another (`0`/`o`, `rn`/`m`, Cyrillic `а`/Latin `a`). `soctk phish` normalises these before comparing domains. |
| **Impossible travel** | Two successful sign-ins whose locations could not both be reached by the user in the elapsed time. |
| **Incident** | One or more related alerts confirmed to represent a security event. `soctk triage` groups alerts into candidate incidents by shared entity. |
| **IOC** | Indicator of Compromise: IP, domain, URL, hash, e-mail or CVE associated with malicious activity. |
| **IdP** | Identity provider (SSO / directory) issuing authentication decisions and tokens. |
| **Levenshtein distance** | Minimum single-character edits between two strings; used for lookalike-domain detection. |
| **Lookalike domain** | A domain registered to resemble a protected one (`micros0ft-support.com`, `secure-login-example.com`). |
| **LSASS** | Windows Local Security Authority process holding credentials in memory; reading it is credential dumping (T1003.001). |
| **Mark of the Web (MotW)** | Zone identifier on files downloaded from the internet that lets Office block macros. |
| **MTA / hop** | Mail Transfer Agent; each MTA prepends a `Received:` header, forming the hop chain analysed by `soctk phish`. |
| **NIST SP 800-61** | *Computer Security Incident Handling Guide*. Lifecycle: Preparation -> Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity. |
| **Password spray** | One or two common passwords tried against many accounts, slowly, to stay under lockout thresholds. |
| **Pivot** | Filtering all events to a single entity (host, user, IP) to follow one thread; `soctk timeline --pivot`. |
| **Playbook / runbook** | Step-by-step procedure for one alert type, with severity criteria, commands, and escalation rules. |
| **Priority (P1-P4)** | Work order from the triage score: P1 >= 80, P2 >= 55, P3 >= 30, P4 < 30. |
| **Recovery** | NIST 800-61 phase: restoring systems to normal operation and verifying they stay clean. |
| **Refang** | Reversing defanging so a tool can use the indicator. |
| **Return-Path** | Envelope sender (SMTP `MAIL FROM`) where bounces go; SPF is evaluated against this domain, not the visible `From:`. |
| **Reply-To** | Header that redirects replies; a different domain from `From:` is a classic BEC / phishing sign. |
| **RFC 5737** | Reserved documentation IPv4 ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) used as "external" addresses in all synthetic data here. |
| **SIEM** | Security Information and Event Management: central log collection, correlation and alerting. |
| **SPF** | Sender Policy Framework: DNS record listing hosts allowed to send for a domain, checked against the connecting IP and `Return-Path` domain. |
| **STIX** | Structured Threat Information Expression; `soctk ioc --stix` emits STIX-2.1-style `indicator` objects. |
| **Tier 1 / Tier 2** | Tier 1: alert triage, enrichment, playbook execution, escalation. Tier 2: investigation, containment decisions, forensics, tuning. |
| **TLP** | Traffic Light Protocol sharing restriction on reports (`TLP:AMBER` = limited distribution). |
| **True positive / false positive / benign true positive** | Correct detection of malicious activity / incorrect detection / correct detection of activity that was authorised (e.g. pen test). Dispositions drive the tuning log. |
| **UEBA** | User and Entity Behaviour Analytics; baselining to flag deviations (insider threat, compromised accounts). |
| **VIP** | Executives and roles whose names are impersonated in BEC; listed in `data/vips.txt`. |
