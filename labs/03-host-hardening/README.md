# Lab 3 – Host hardening

Windows hardening with PowerShell: registry, WMI/CIM, and firewall configuration.
The lab applied controls by hand, one command at a time; the code here turns that
into a declarative baseline that can be audited, remediated and re-run.

## Contents

```
labs/03-host-hardening/
└── README.md
```

The full write-up is
[docs/reports/cyb631-lab3-puwar.pdf](../../docs/reports/cyb631-lab3-puwar.pdf).

No scripts from this lab were committed. The `New-NetFirewallRule` and
`Set-NetFirewallProfile` commands are legible in the report's screenshots
(pages 24-27) but were never saved to a file.

## What replaced it

The one-off firewall commands became a declarative baseline in
[`src/WinSecKit`](../../src/WinSecKit). Controls live as data in
`Data/baseline.psd1`; `Test-SecurityBaseline` audits and never writes, and
`Invoke-SecurityBaseline` remediates with `-WhatIf` support and a rollback record.

| ID | Control | Type | CIS |
|---|---|---|---|
| WSB0001 | PowerShell script block logging enabled | Registry | — |
| WSB0002 | Do not display last signed-in user | Registry | — |
| WSB0003 | SMBv1 server disabled | Registry | — |
| WSB0004 | Windows Firewall enabled on all profiles | FirewallProfile | — |
| WSB0005 | Inbound SSH (TCP 22) blocked | FirewallRule | — |
| WSB0006 | Inbound DNS (TCP 53) blocked | FirewallRule | — |

**The CIS column is empty on purpose.** CIS Benchmarks require registration, so no
control number here has been read from the benchmark itself. An unverified ID that
looks authoritative is worse than a blank field, because nobody can tell it is
wrong. These stay empty until the benchmark is obtained and each mapping confirmed
against it.

WSB0001 exists because of Lab 2: without script block logging enabled, event 4104
is never written and detection WSK0004 has nothing to read. The hardening baseline
and the detection set are the same system.

## Not covered

The AD LDS work in this lab is **not** implemented and not verified. AD LDS,
Group Policy and domain password policy all require a domain, and the only Windows
machine available for verification is an ephemeral standalone CI runner. Rather
than ship controls that cannot be tested, they are absent from the baseline. They
are not reported as passing, skipped silently, or stubbed.

## Verification

`Test-SecurityBaseline` and `Invoke-SecurityBaseline` are exercised on a real
Windows runner in CI, which creates the firewall rules, asserts the audit agrees,
applies the baseline a second time and asserts nothing changed. That second run is
the idempotency proof. Rules and registry values are restored afterwards.

What this proves is that the code executes correctly against a live Windows
firewall and registry on a **standalone Windows Server runner**. It does not prove
the baseline results are representative of a real workstation: a fresh CI image is
not a machine anyone works on, and its starting compliance state says nothing about
yours. See [tests/Baseline.Windows.Tests.ps1](../../tests/Baseline.Windows.Tests.ps1).

---

## Why declarative

The lab's firewall work was a sequence of `New-NetFirewallRule` calls typed at a
prompt. That is fine once. It does not tell you whether a machine is currently
compliant, it cannot be run twice safely, and it has no way to report drift.

Separating the control *definition* from the *check* and the *fix* gets all three:
`Test-SecurityBaseline` answers "is this host compliant" without touching anything,
`Invoke-SecurityBaseline` converges it and reports what it changed, and running the
second one twice produces no changes the second time. Adding a control is an edit
to `Data/baseline.psd1`, not a new function.

## References
- Microsoft. [Active Directory Lightweight Directory Services Overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-lds/active-directory-lightweight-directory-services-overview)  
- Microsoft. [Windows PowerShell commands for managing Windows Firewall](https://learn.microsoft.com/en-us/powershell/module/netsecurity)  
- Microsoft. [Windows Management Instrumentation (WMI)](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)  
- Microsoft. [Windows registry information for advanced users](https://support.microsoft.com/help/256986/windows-registry-information-for-advanced-users)  
- NinjaOne. [Configure firewall exceptions with PowerShell](https://www.ninjaone.com/script-hub/configure-firewall-exceptions-with-powershell)  
- Woshub. [Manage Windows Defender Firewall with PowerShell](https://woshub.com/manage-windows-firewall-powershell)  
- Wong, J. (2021). *Managing Windows Firewall Rules with PowerShell: Beyond the GUI*. ITPro Today.
