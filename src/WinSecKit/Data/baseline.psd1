<#
    Declarative host baseline evaluated by Test-SecurityBaseline and applied by
    Invoke-SecurityBaseline.

    CisId is empty on every control. CIS Benchmarks are distributed under terms
    that require registration, so no CIS control number here has been read from
    the benchmark itself. An unverified ID is worse than no ID: it looks
    authoritative and cannot be checked. These stay empty until the benchmark is
    obtained and each mapping confirmed against it.

    Every control is deliberately standalone: registry values under HKLM and
    Windows Firewall state, both settable on a workgroup machine. Controls that
    would need a domain -- Group Policy application, AD LDS, domain password
    policy -- are out of scope for this module and are listed as such in the
    lab README rather than stubbed here.

    CheckType determines how a control is evaluated:
      Registry        - value at Path\Name equals ExpectedValue
      FirewallProfile - the named profile has Enabled = True
      FirewallRule    - an enabled inbound Block rule exists for Protocol/LocalPort
#>
@{
    SchemaVersion = 1

    Controls = @(
        @{
            Id            = 'WSB0001'
            Name          = 'PowerShell script block logging enabled'
            CheckType     = 'Registry'
            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Name_         = 'EnableScriptBlockLogging'
            ExpectedValue = 1
            ValueKind     = 'DWord'
            Severity      = 'High'
            CisId         = ''
            Rationale     = 'Without this, event 4104 is never written and detection WSK0004 has nothing to read.'
        }
        @{
            Id            = 'WSB0002'
            Name          = 'Do not display last signed-in user'
            CheckType     = 'Registry'
            Path          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Name_         = 'DontDisplayLastUserName'
            ExpectedValue = 1
            ValueKind     = 'DWord'
            Severity      = 'Medium'
            CisId         = ''
            Rationale     = 'Hides a valid username from anyone with physical or console access.'
        }
        @{
            Id            = 'WSB0003'
            Name          = 'SMBv1 server disabled'
            CheckType     = 'Registry'
            Path          = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Name_         = 'SMB1'
            ExpectedValue = 0
            ValueKind     = 'DWord'
            Severity      = 'High'
            CisId         = ''
            Rationale     = 'SMBv1 is unauthenticated, unencrypted and the transport EternalBlue used.'
        }
        @{
            Id            = 'WSB0004'
            Name          = 'Windows Firewall enabled on all profiles'
            CheckType     = 'FirewallProfile'
            Profile       = @('Domain', 'Private', 'Public')
            Severity      = 'Critical'
            CisId         = ''
            Rationale     = 'A disabled profile silently voids every rule defined for it.'
        }
        @{
            Id            = 'WSB0005'
            Name          = 'Inbound SSH (TCP 22) blocked'
            CheckType     = 'FirewallRule'
            DisplayName   = 'WinSecKit - Block inbound SSH (TCP 22)'
            Protocol      = 'TCP'
            LocalPort     = '22'
            Severity      = 'Medium'
            CisId         = ''
            Rationale     = 'Reproduces the Lab 3 exercise: SSH has no role on a default Windows host.'
        }
        @{
            Id            = 'WSB0006'
            Name          = 'Inbound DNS (TCP 53) blocked'
            CheckType     = 'FirewallRule'
            DisplayName   = 'WinSecKit - Block inbound DNS (TCP 53)'
            Protocol      = 'TCP'
            LocalPort     = '53'
            Severity      = 'Medium'
            CisId         = ''
            Rationale     = 'Reproduces the Lab 3 exercise: inbound DNS should not be served by a workstation.'
        }
    )
}
