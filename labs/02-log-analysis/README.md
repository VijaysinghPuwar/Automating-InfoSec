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
