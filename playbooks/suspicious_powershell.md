# Playbook: Suspicious PowerShell

**NIST SP 800-61 phase:** Detection & Analysis
**Security+ domain:** 2.4 Indicators of malicious activity (fileless / living-off-the-land), 4.4 Security alerting and monitoring (log sources: Sysmon, PowerShell 4104)
**ATT&CK:** T1059.001 PowerShell, T1027.010 Command Obfuscation, T1105 Ingress Tool Transfer, T1562.001 Disable or Modify Tools (AMSI/Defender), T1218 System Binary Proxy Execution, T1047 WMI

## Trigger

- SIEM: *Suspicious PowerShell: encoded command* - `-enc`/`-EncodedCommand`, `-w hidden`, `-nop`, `-ep bypass`, `IEX`, `DownloadString`, `FromBase64String`, `Invoke-Expression`, `Net.WebClient`, `-noni`
- Sysmon Event 1 / Windows 4688 with PowerShell parent = Office, browser, `wscript`, `mshta`, `rundll32`, or a service
- PowerShell 4104 script block logging matching known offensive frameworks (Invoke-Mimikatz, PowerView, Empire stagers, AMSI bypass strings)
- EDR behavioural alert naming PowerShell

## Severity matrix

| Factor | Raises priority when... |
| --- | --- |
| Parent | Office / mail / browser / script host parent = P2 minimum (user execution chain) |
| Content | decoded command downloads and executes (`IEX (New-Object Net.WebClient).DownloadString`) = P1; AMSI bypass = P1; recon only (`whoami`, `net group`) = P3 |
| Network | outbound to a non-corporate destination right after = one band up |
| User / asset | admin user or server = one band up; sysadmin running a known deployment script from a management host = tune |
| Scope | same script on multiple hosts within minutes = P1 (worm / mass deployment) unless it is the SCCM/Intune agent |

## Triage steps

1. Decode the command yourself before reading anyone else's summary. Encoded PowerShell is UTF-16LE base64:
   ```bash
   echo 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' | base64 -d | iconv -f UTF-16LE -t UTF-8
   ```
   Paste the decoded text into the ticket. Expect nested layers (gzip, `-join`, char-code arrays); keep decoding until you reach plain text.
2. Pull every indicator from the decoded script:
   ```bash
   python -m soctk ioc case/decoded.ps1 --csv case/iocs.csv
   ```
3. Build the process chain and network context for the host:
   ```bash
   python -m soctk timeline data/logs --pivot WS-FIN-017 --start 2026-10-14T08:20:00Z --end 2026-10-14T09:00:00Z
   ```
   Confirm the parent (Office? explorer? a service?), what PowerShell spawned next (`rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`), and the first outbound connection.
4. In the SIEM, search for the same encoded string / script hash across the fleet (last 7 days) and for the same parent-child pattern on other hosts.
5. Determine the user context: interactive user vs SYSTEM vs service account. Check if the user has local admin.
6. Decide: known admin script (check the change calendar and the management server as the parent), or malicious. If it downloads and executes anything, it is malicious until proven otherwise.

## Escalation criteria

- Decoded content downloads, decompresses, or reflectively loads code
- AMSI / Defender tampering, event log clearing, or `Set-MpPreference -Disable*`
- Credential-access modules (Mimikatz, `Invoke-Kerberoast`, DCSync strings)
- Execution on a server, DC, or by a privileged account
- Any lateral-movement cmdlets (`Invoke-Command -ComputerName`, `Enter-PSSession`, WMI to other hosts)

## Containment

| Action | Who | Notes |
| --- | --- | --- |
| EDR isolate host | Tier 1 for workstation, Tier 2 for server | |
| Block download host / C2 at proxy and DNS | Tier 1 | |
| Kill the PowerShell process tree | Tier 1 | After capturing command line and memory |
| Disable user account | Tier 2 | If credential theft content was present |
| Constrained Language Mode / AppLocker policy push | Endpoint engineering | Longer-term |

## Evidence to collect

- Full command line (4688 with command-line auditing, Sysmon 1), decoded content, and 4104 script blocks
- Downloaded payloads (hash + sample)
- Process tree export with parent chain back to the originating user action
- PowerShell transcript / console history (`ConsoleHost_history.txt`) for the user
- Network connections for the PowerShell PID

## Eradication and recovery

- Remove any persistence created by the script (scheduled tasks, WMI subscriptions, run keys, profile scripts `profile.ps1`)
- Rotate credentials exposed in script memory
- Confirm script block logging, module logging and transcription are enabled fleet-wide; without 4104 you cannot do step 1 reliably

## False positives and tuning

- SCCM / Intune / RMM agents routinely run encoded commands from `ccmexec.exe` or the agent service - whitelist by parent process and signer, never by the `-enc` flag alone
- Admin one-liners from the jump host - verify the user and record the pattern in `docs/alert_tuning_log.md`
- Developer tooling (VS Code tasks, build scripts) on engineering hosts
