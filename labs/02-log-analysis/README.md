# Lab 2 – Security event log analysis

Event log analysis on Windows: reading the Security log, filtering it server-side,
and turning a generic event dump into named detections.

## Contents

```
labs/02-log-analysis/
└── README.md
```

The full write-up is
[docs/reports/cyb631-lab2-puwar.pdf](../../docs/reports/cyb631-lab2-puwar.pdf).

No scripts from this lab were committed. `sys_admin.ps1`, `Get-DiskUsage.ps1`,
`showtoday.ps1` and `Show-Today.psm1` are described in the report but exist only
as screenshots inside it.

## What replaced it

The generic event dump this lab produced is superseded by named detections in
[`src/WinSecKit`](../../src/WinSecKit): `Get-SecurityEventRecord` acquires records
and `Test-SecurityDetection` evaluates them against the definitions in
`Data/detections.psd1`.

`sys_admin.ps1` itself was not recovered. Its source appears in the report only as
a shrunken editor pane that does not resolve at any extraction resolution, so the
detections were written to the behavioural specification on page 34 and to the
output format visible in Figures 30 and 31 — not reconstructed from the original
code. Nothing here claims to be that script.

## Detections and ATT&CK mapping

| ID | Detection | Log | Event | Technique |
|---|---|---|---|---|
| WSK0001 | Failed logon burst (5 in 5 min, per account) | Security | 4625 | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force |
| WSK0002 | Local account created | Security | 4720 | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account |
| WSK0003 | Member added to security-enabled group | Security | 4732 | [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation |
| WSK0004 | Suspicious script block content | PowerShell/Operational | 4104 | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell |
| WSK0005 | Service installed | System | 7045 | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Create or Modify System Process: Windows Service |
| WSK0006 | Audit log cleared | Security | 1102 | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs |

Note the log column. Only four of the six live in Security: 4104 is written to
`Microsoft-Windows-PowerShell/Operational` and 7045 to `System`. A detection that
matches on event id alone will silently return nothing for those two, which is why
`Test-SecurityDetection` requires the log name to match as well and why there is a
test asserting a 4104 raised in the Security log does not match.

`Get-WinEvent` is used throughout rather than `Get-EventLog`. `Get-EventLog` reads
only the classic logs, so it cannot see the PowerShell operational log at all, and
it was removed in PowerShell 6.

## Verification

The detection logic is evaluated against synthetic records, so the threshold,
grouping, window-boundary and wrong-log cases are all covered without needing a
machine that happens to have been attacked. Live acquisition through
`Get-SecurityEventRecord` is exercised against the real System log on the CI
runner. See [tests/Detection.Tests.ps1](../../tests/Detection.Tests.ps1).

---

## What the original lab got wrong

Two things worth stating, because the code here exists to correct them.

It used `Get-EventLog`. That reads only the classic logs, so it cannot see
`Microsoft-Windows-PowerShell/Operational` at all — two of the six detections below
would have been impossible. It was also removed in PowerShell 6, so anything built
on it stops running on a modern host.

It filtered client-side. `Get-EventLog | Where-Object` pulls every record across
the wire and discards most of them. `Get-WinEvent -FilterXPath` pushes the
predicate into the event log service, which is the difference between a bounded
query and reading an entire Security log to find five entries.

## References
- Holmes, L. (2021). *Windows PowerShell Cookbook* (4th ed.). O’Reilly Media.  
- Microsoft. (2023). [Table of basic PowerShell commands](https://devblogs.microsoft.com/scripting/table-of-basic-powershell-commands/)  
- Pace University. (2025). *CYB 631 Lab 2: Analyzing Logs and Other Administrators’ Tasks*
