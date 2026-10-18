# Incident Report {{id}}: {{title}}

| | |
| --- | --- |
| **Classification** | {{classification}} |
| **Severity** | {{severity}} |
| **Status** | {{status}} |
| **Incident type** | {{incident_type}} |
| **Lead analyst** | {{analyst}} |
| **Detection source** | {{detection_source}} |
| **Report generated** | {{generated}} |

## 1. Executive summary

{{executive_summary}}

**Impact:** {{impact}}

**Root cause:** {{root_cause}}

## 2. Key times and metrics

{{key_times_table}}

| Metric | Value |
| --- | --- |
| Dwell time (first activity -> detection) | {{dwell_time}} |
| Time to contain (detection -> containment) | {{time_to_contain}} |
| Time to recover (detection -> recovery) | {{time_to_recover}} |

## 3. Affected assets and accounts

{{affected_table}}

## 4. Timeline of events

{{timeline_table}}

## 5. Indicators of compromise

All indicators are defanged. Refang with `python -m soctk ioc <file>` before blocking.

{{ioc_table}}

## 6. MITRE ATT&CK mapping

{{attack_table}}

## 7. Response (NIST SP 800-61 lifecycle)

### 7.1 Detection and analysis

{{detection_analysis}}

### 7.2 Containment

{{containment}}

### 7.3 Eradication

{{eradication}}

### 7.4 Recovery

{{recovery}}

## 8. Evidence collected

{{evidence}}

## 9. Post-incident activity

### Lessons learned

{{lessons_learned}}

### Recommendations

{{recommendations}}

---
_Generated with soctk report. Review and edit before distribution._
