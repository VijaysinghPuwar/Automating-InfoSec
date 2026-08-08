# Lab 1 – PowerShell Basics and Gathering Host Information

This lab is to build a foundation in **PowerShell scripting** for system administration, host monitoring, and security automation.

---

## Lab Objectives
This lab introduced me to the fundamentals of PowerShell by covering:

1. **PowerShell Basics**
   - Launching and navigating the PowerShell environment  
   - Verifying user context (`whoami`) and directories (`pwd`, `Get-Location`)  
   - Creating and managing files with `New-Item`, `attrib`, and `Get-Content`  
   - Example file: `.-nametest1.txt` → contains `Hello! World`

2. **Object Operations**
   - Demonstrated how PowerShell treats everything as an object  
   - Used string methods (`.Length`, `.ToLower()`)  
   - Inspected object members using `Get-Member`

3. **Process Information**
   - Listed all active processes with `Get-Process`  
   - Filtered by name prefix (`gps -n w*`)  
   - Stored and terminated Notepad processes using `.Kill()`  
   - Queried processes with IDs ≥ 10,000 using pipelines

4. **Useful Commands**
   - Explored built-in help (`Get-Help`)  
   - Listed available commands (`Get-Command`)  
   - Investigated properties and methods of the `System.Diagnostics.Process` object

5. **First PowerShell Script**
   - Script to calculate the **sum of handles** for processes starting with "N":
     ```powershell
     $hcount = 0
     foreach ($process in Get-Process -Name n* -ErrorAction SilentlyContinue) {
         $hcount += $process.Handles
     }
     $hcount
     ```
   - Saved as `script1.ps1`  
   - Verified with `Measure-Object` for accuracy  

6. **CPU Monitoring Script**
   - Wrote `cputime.ps1` to display the **top 5 CPU-consuming processes**  
   - Output included process ID, name, and CPU usage  

---

## Contents

```
labs/01-powershell-fundamentals/
├── README.md
└── scripts/
    └── script1.ps1        # Sums handles across processes whose name starts with N
```

The full write-up is
[docs/reports/cyb631-lab1-puwar.pdf](../../docs/reports/cyb631-lab1-puwar.pdf).

`cputime.ps1` and the scratch files created during the exercises are described in
the report but were never committed.

---

## Reflection
- **What I liked:**  
  The lab progressed logically from basic commands → object operations → scripting. It showed how even simple scripts can be powerful for monitoring and automation.  

- **Challenges:**  
  Faced issues with **execution policies**, requiring a process-scoped bypass to run scripts securely. Learned how PowerShell enforces script execution rules to balance automation with security.  

- **Takeaway:**  
  This lab provided a solid foundation in PowerShell, emphasizing automation for **system administration, performance monitoring, and cybersecurity tasks**.  

---

## References
- Holmes, L. (2021). *Windows PowerShell Cookbook* (4th ed.). O’Reilly Media.  
- Microsoft. (2023). [Table of basic PowerShell commands](https://devblogs.microsoft.com/scripting/table-of-basic-powershell-commands/)  
- Pace University. (2023). *CYB 631 Lab 1: PowerShell Basics and Gathering Host Information*  
