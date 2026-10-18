# SOC shift handoff

Copy this file per shift (`handoffs/2026-10-14_day.md`). Fill every section - "nothing" is a valid answer, a blank is not. The incoming analyst reads it before touching the queue; the outgoing analyst walks through the open incidents verbally.

| | |
| --- | --- |
| **Shift** | Day / Swing / Night, YYYY-MM-DD, HH:MM-HH:MM UTC |
| **Outgoing analyst(s)** | |
| **Incoming analyst(s)** | |
| **Handoff time** | |
| **Tier 2 / IR lead on call** | name, contact |
| **Threat level / notes from management** | e.g. elevated: phishing campaign active |

## 1. Queue state at handoff

Paste the header of `python -m soctk triage` (raw -> de-dup -> incidents, by priority):

```
Ingested __ alerts -> __ after de-dup -> __ incidents
P1=_ P2=_ P3=_ P4=_
```

| Metric | Value |
| --- | --- |
| Alerts closed this shift | |
| Alerts escalated | |
| Oldest unacknowledged alert (age) | |
| SLA breaches this shift (P1/P2) | |

## 2. Open incidents (highest priority first)

| Incident | Pri | Status | What happened so far | Next action + owner | Waiting on |
| --- | --- | --- | --- | --- | --- |
| INC-2026-0001 | P1 | Contained | Macro phish -> cred dump on WS-FIN-017; host isolated 08:58Z | Reimage; confirm no lateral use of mrivera creds - Tier 2 | Desktop team ticket #____ |
| | | | | | |

## 3. Incidents closed this shift

| Incident | Pri | Disposition (true positive / false positive / benign true positive) | Tuning follow-up? |
| --- | --- | --- | --- |
| | | | |

## 4. Watch items (not incidents yet)

- Entities to keep an eye on (user, host, IP, domain) and why
- Threat-intel updates applied to `data/threat_intel/feed.csv` this shift
- Scheduled changes / maintenance that will generate noise (with change ticket numbers)

## 5. Tooling / data-source health

| Source | Status | Notes |
| --- | --- | --- |
| EDR telemetry | OK / degraded / down | |
| Firewall / proxy logs | | |
| IdP sign-in logs | | |
| Mail gateway | | |
| SIEM ingestion lag | | |

## 6. Tuning requests raised

Link to the row(s) added in `docs/alert_tuning_log.md`.

## 7. Anything else the next shift must know

- Phone calls expected, vendors engaged, management asks, pending approvals

---
Outgoing signature: ____________  Incoming acknowledgement: ____________
