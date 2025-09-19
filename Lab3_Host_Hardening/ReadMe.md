# Lab 3 – Managing and Hardening Hosts

This repository contains the work for **Lab 3** of *CYB 631: Automating Information Security with Python and Shell Scripting* at Pace University.  
The lab focused on **Windows host hardening** using PowerShell, covering directory services, registry, WMI/CIM, and firewall configuration through both manual and automated methods.

---

## 📘 Course Information
- **Course:** CYB 631 – Automating Information Security with Python and Shell Scripting  
- **Instructor:** Prof. Alex Tsekhansky  
- **Student:** Vijaysingh Puwar  
- **Date:** September 2025  

---

## 🔑 Lab Objectives
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

## 📂 Repository Contents
```

Lab3\_Managing\_Hosts/
├── firewall\_ReadMe.md        # Short Info here
└── CYB631-Lab3\_Puwar.pdf      # Full lab report

```

---

## 📝 Reflection
- **What I liked:**  
  The lab tied together multiple Windows hardening techniques, showing both manual and automated approaches. Automating firewall rules with PowerShell demonstrated the efficiency of scripting in enterprise environments.  

- **Challenges:**  
  - Running AD LDS setup required elevated privileges and correct VM environment  
  - Debugging execution policy errors  
  - Ensuring firewall rules applied to the right profiles (Domain vs Public)  

- **Takeaway:**  
  This lab highlighted the importance of **automation in host hardening**. Using PowerShell ensures consistent, scalable, and auditable security configurations across Windows systems.  

---

## 📚 References
- Microsoft. [Active Directory Lightweight Directory Services Overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-lds/active-directory-lightweight-directory-services-overview)  
- Microsoft. [Windows PowerShell commands for managing Windows Firewall](https://learn.microsoft.com/en-us/powershell/module/netsecurity)  
- Microsoft. [Windows Management Instrumentation (WMI)](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)  
- Microsoft. [Windows registry information for advanced users](https://support.microsoft.com/help/256986/windows-registry-information-for-advanced-users)  
- NinjaOne. [Configure firewall exceptions with PowerShell](https://www.ninjaone.com/script-hub/configure-firewall-exceptions-with-powershell)  
- Woshub. [Manage Windows Defender Firewall with PowerShell](https://woshub.com/manage-windows-firewall-powershell)  
- Wong, J. (2021). *Managing Windows Firewall Rules with PowerShell: Beyond the GUI*. ITPro Today.  

---


Do you want me to **also add snippets of the firewall script** (like the actual `New-NetFirewallRule` commands) in the README so recruiters see working code right away?
