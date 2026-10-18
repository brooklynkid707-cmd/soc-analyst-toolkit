# Playbooks

Runbooks for the alert types a Tier 1 / Tier 2 analyst sees most. Every playbook follows the same shape so a new analyst can work any of them under pressure:

| Section | What it answers |
| --- | --- |
| Trigger | Which alert / report / rule starts this playbook |
| Severity matrix | How to pick P1-P4 from the facts you have in the first five minutes |
| Triage steps | Exact `soctk` commands and SIEM questions, in order |
| Escalation criteria | Hard lines where Tier 1 hands to Tier 2 / IR lead |
| Containment | What you may do yourself, what needs approval |
| Evidence to collect | What must be preserved before anything is "fixed" |
| ATT&CK | Techniques to tag on the ticket |
| NIST SP 800-61 phase | Where this playbook sits in the incident lifecycle |

| Playbook | Typical source | Primary ATT&CK |
| --- | --- | --- |
| [Phishing](phishing.md) | User report, mail gateway | T1566, T1204 |
| [Brute force / credential stuffing](brute_force_credential_stuffing.md) | SIEM 4625 / IdP failures | T1110.x |
| [Malware on endpoint](malware_on_endpoint.md) | EDR / AV | T1204, T1059, T1105 |
| [Suspicious PowerShell](suspicious_powershell.md) | EDR / Sysmon 1 / 4104 | T1059.001 |
| [Impossible travel](impossible_travel.md) | IdP / CASB | T1078, T1078.004 |
| [Data exfiltration](data_exfiltration.md) | Proxy / DLP / NetFlow | T1567, T1048, T1041 |
| [Insider threat](insider_threat.md) | DLP / HR / UEBA | T1052, T1567, T1530 |
| [Ransomware early indicators](ransomware_early_indicators.md) | EDR / file server / backup | T1486, T1490, T1562 |

Severity bands used throughout (they match `soctk triage`):

| Band | Score | Response target | Who |
| --- | --- | --- | --- |
| P1 | 80-100 | Acknowledge 15 min, contain 1 h, 24x7 | IR lead + Tier 2, management informed |
| P2 | 55-79 | Acknowledge 30 min, contain 4 h | Tier 2 |
| P3 | 30-54 | Acknowledge 4 h, resolve 2 business days | Tier 1 / Tier 2 |
| P4 | 0-29 | Next shift, batch tuning review | Tier 1 |
