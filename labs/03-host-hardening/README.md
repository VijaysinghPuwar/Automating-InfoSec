# Lab 3 – Managing and Hardening Hosts

This lab focused on **Windows host hardening** using PowerShell, covering directory services, registry, WMI/CIM, and firewall configuration through both manual and automated methods.

---

## Lab Objectives
The lab introduced a series of exercises to explore **system administration and security automation**:

1. **Environment Setup**
   - Launched PowerShell ISE with administrator privileges  
   - Configured execution policies (`RemoteSigned`, `Unrestricted`)  

2. **Active Directory Lightweight Directory Services (AD LDS)**
   - Installed and configured AD LDS via Server Manager  
   - Created a unique instance with default ports  
   - Added users and explored directory partitions  

3. **Testing AD LDS with PowerShell**
   - Verified ADAM instance and ADWS services  
   - Queried containers, domains, and user information  

4. **Windows Registry**
   - Viewed registry hive keys with `regedit`  
   - Retrieved keys and values via PowerShell commands  
   - Focused on **HKCU** for user-specific data  

5. **Windows Management Instrumentation (WMI) and CIM**
   - Queried logical disks with `WMIC` and `Get-CimInstance`  
   - Explored CIM classes and executed WQL queries  
   - Retrieved system and process information  
   - Launched a process with `Invoke-CimMethod`  

6. **Firewall Configuration (Manual)**
   - Used `New-NetFirewallRule` to block HTTP/HTTPS inbound traffic  
   - Tested connectivity to confirm firewall effectiveness  
   - Modified and removed firewall rules when needed  

7. **Firewall Configuration with PowerShell**
   - Automated firewall setup via script:
     - Enabled firewall on all profiles (`Domain`, `Private`, `Public`)  
     - Blocked **SSH (TCP 22)** inbound traffic  
     - Blocked **DNS (TCP/UDP 53)** inbound traffic  
   - Verified rules were created successfully  
   - Explained benefits of scripting: **scalability, repeatability, compliance, and reduced human error**  

---

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

## Reflection
- **What I liked:**  
  The lab tied together multiple Windows hardening techniques, showing both manual and automated approaches. Automating firewall rules with PowerShell demonstrated the efficiency of scripting in enterprise environments.  

- **Challenges:**  
  - Running AD LDS setup required elevated privileges and correct VM environment  
  - Debugging execution policy errors  
  - Ensuring firewall rules applied to the right profiles (Domain vs Public)  

- **Takeaway:**  
  This lab highlighted the importance of **automation in host hardening**. Using PowerShell ensures consistent, scalable, and auditable security configurations across Windows systems.  

---

## References
- Microsoft. [Active Directory Lightweight Directory Services Overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-lds/active-directory-lightweight-directory-services-overview)  
- Microsoft. [Windows PowerShell commands for managing Windows Firewall](https://learn.microsoft.com/en-us/powershell/module/netsecurity)  
- Microsoft. [Windows Management Instrumentation (WMI)](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)  
- Microsoft. [Windows registry information for advanced users](https://support.microsoft.com/help/256986/windows-registry-information-for-advanced-users)  
- NinjaOne. [Configure firewall exceptions with PowerShell](https://www.ninjaone.com/script-hub/configure-firewall-exceptions-with-powershell)  
- Woshub. [Manage Windows Defender Firewall with PowerShell](https://woshub.com/manage-windows-firewall-powershell)  
- Wong, J. (2021). *Managing Windows Firewall Rules with PowerShell: Beyond the GUI*. ITPro Today.
