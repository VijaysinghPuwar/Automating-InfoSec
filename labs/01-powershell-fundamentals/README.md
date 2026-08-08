# Lab 1 – PowerShell fundamentals

Introductory lab: the PowerShell object pipeline, process inspection, and a first
script. This is the foundation the later labs build on and the least interesting
of the four; the working code in this repository lives in
[`src/WinSecKit`](../../src/WinSecKit).

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

## What it covered

Everything in PowerShell is an object, not text: `Get-Process` returns
`System.Diagnostics.Process` instances whose properties can be filtered and
aggregated in the pipeline rather than parsed out of formatted output. `script1.ps1`
is the smallest demonstration of that — it sums a property across a filtered set:

```powershell
$hcount = 0
foreach ($process in Get-Process -Name n* -ErrorAction SilentlyContinue) {
    $hcount += $process.Handles
}
$hcount
```

The one thing here with lasting consequence is the **execution policy**. Running
even this required a process-scoped bypass, which is the same mechanism Lab 4
returns to when it signs scripts so they run under `AllSigned` — the policy is not
a security boundary against an attacker, but it is the control that makes code
signing meaningful.

## References

- Holmes, L. (2021). *Windows PowerShell Cookbook* (4th ed.). O'Reilly Media.
- Microsoft. [Table of basic PowerShell commands](https://devblogs.microsoft.com/scripting/table-of-basic-powershell-commands/)
- Pace University. *CYB 631 Lab 1: PowerShell Basics and Gathering Host Information*
