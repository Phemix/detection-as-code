# MITRE ATT&CK Coverage Report

> Generated: 2026-06-18 10:12 UTC

## Summary

| Metric | Count |
|--------|-------|
| Total Rules | 2 |
| Splunk (SPL) Coverage | 2 rules |
| Sentinel (KQL) Coverage | 1 rules |
| Both Backends | 1 rules |
| Techniques Covered | 2 |

## Coverage by Tactic

| Tactic | Techniques Covered | Splunk | Sentinel |
|--------|-------------------|--------|----------|
| Initial Access | 0 | 0 rules | 0 rules |
| Execution | 0 | 0 rules | 0 rules |
| Persistence | 0 | 0 rules | 0 rules |
| Privilege Escalation | 0 | 0 rules | 0 rules |
| Defense Evasion | 0 | 0 rules | 0 rules |
| Credential Access | 1 | 1 rules | 1 rules |
| Discovery | 0 | 0 rules | 0 rules |
| Lateral Movement | 1 | 1 rules | 0 rules |
| Collection | 0 | 0 rules | 0 rules |
| Exfiltration | 0 | 0 rules | 0 rules |
| Command and Control | 0 | 0 rules | 0 rules |
| Impact | 0 | 0 rules | 0 rules |

## Technique Detail

| Technique | Rules | Splunk | Sentinel | Severity |
|-----------|-------|--------|----------|----------|
| T1003.001 | `DET-00001` LSASS Memory Dump via ProcDump or comsvcs.dll | ✓ | ✓ | critical |
| T1021.002 | `DET-00003` PsExec Lateral Movement via Admin Shares | ✓ | ✗ | high |