# Lab 2 – Analyzing Logs and Other Administrators’ Tasks

This lab builds upon the basics from Lab 1 and introduces more advanced **PowerShell scripting** concepts such as arrays, modules, event logs, and system administration automation.

---

## Lab Objectives
This lab focused on expanding PowerShell capabilities to support **system administration and security monitoring**:

1. **PowerShell Objects and Data Structures**
   - Worked with variables, arrays, and hashtables  
   - Created multidimensional arrays and sorted string arrays  
   - Practiced static methods from .NET classes

2. **Files and Directories**
   - Explored directory contents with `Get-ChildItem`  
   - Compared files using `Compare-Object`  
   - Filtered files modified in the last 10 days and sorted by size  

3. **Parameterized Scripts**
   - Reviewed and tested `Get-DiskUsage.ps1`  
   - Added recursive directory size calculations with `-IncludeSubdirectories`  
   - Created `showtoday.ps1` to display the date with optional `-ShowWeek` parameter  

4. **Modules**
   - Converted scripts into reusable PowerShell modules (`Show-Today.psm1`)  
   - Verified module import and execution  

5. **Event Logs**
   - Used `Get-EventLog` and `Get-WinEvent` to analyze logs  
   - Retrieved Security log entries and filtered system events  
   - Emphasized the importance of log analysis for host security and compliance  

6. **System Services**
   - Listed running services with `Get-Service`  
   - Sorted services by dependency count  
   - Highlighted security implications of unnecessary/rogue services  

7. **Administrative Script Development**
   - Built **`sys_admin.ps1`** to automate host information collection:
     - Records date/time and machine info  
     - Summarizes Security log events  
     - Optional `-ShowService` parameter lists top 5 services by dependency  
   - Outputs reports to a `Reports/` directory with timestamped filenames  

---

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

## Reflection
- **What I liked:**  
  The lab connected multiple scripting techniques into a structured workflow. Creating `sys_admin.ps1` showed how small scripts can be combined into powerful automation tools.  

- **Challenges:**  
  - Managing execution policies (needed process-scoped bypass)  
  - Accessing Security event logs required elevated privileges  
  - Handling `DependentServices.Count` null values in the script  

- **Takeaway:**  
  This lab demonstrated how PowerShell can be used for **log analysis, service monitoring, and automated reporting**—skills directly applicable to system hardening, incident response, and compliance.  

---

## References
- Holmes, L. (2021). *Windows PowerShell Cookbook* (4th ed.). O’Reilly Media.  
- Microsoft. (2023). [Table of basic PowerShell commands](https://devblogs.microsoft.com/scripting/table-of-basic-powershell-commands/)  
- Pace University. (2025). *CYB 631 Lab 2: Analyzing Logs and Other Administrators’ Tasks*
