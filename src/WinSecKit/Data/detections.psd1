<#
    Detection definitions evaluated by Test-SecurityDetection.

    Note the LogName values differ per detection and are not all Security. Two of
    these are commonly misattributed:
      - 4104 (ScriptBlock logging) is in Microsoft-Windows-PowerShell/Operational
      - 7045 (service installed)   is in System
    Getting this wrong yields a query that returns nothing and a detection that
    looks like it passed.

    Strategy determines how Test-SecurityDetection evaluates matching records:
      Presence  - any matching record is a finding
      Threshold - >= MinimumCount matching records within WindowMinutes,
                  grouped by GroupBy, is a finding
      Content   - a matching record whose Message matches any PatternList entry
#>
@{
    SchemaVersion = 1

    Detections = @(
        @{
            Id             = 'WSK0001'
            Name           = 'Failed logon burst'
            LogName        = 'Security'
            EventId        = @(4625)
            Strategy       = 'Threshold'
            MinimumCount   = 5
            WindowMinutes  = 5
            GroupBy        = 'TargetUserName'
            Severity       = 'High'
            Technique      = 'T1110'
            TechniqueName  = 'Brute Force'
            Description    = 'Repeated failed logons for one account in a short window, consistent with password guessing.'
        }
        @{
            Id             = 'WSK0002'
            Name           = 'Local account created'
            LogName        = 'Security'
            EventId        = @(4720)
            Strategy       = 'Presence'
            Severity       = 'Medium'
            Technique      = 'T1136.001'
            TechniqueName  = 'Create Account: Local Account'
            Description    = 'A local user account was created. Expected during provisioning, suspicious otherwise.'
        }
        @{
            Id             = 'WSK0003'
            Name           = 'Member added to security-enabled group'
            LogName        = 'Security'
            EventId        = @(4732)
            Strategy       = 'Presence'
            Severity       = 'High'
            Technique      = 'T1098'
            TechniqueName  = 'Account Manipulation'
            Description    = 'An account was added to a security-enabled local group, a common privilege-escalation step.'
        }
        @{
            Id             = 'WSK0004'
            Name           = 'Suspicious PowerShell script block'
            LogName        = 'Microsoft-Windows-PowerShell/Operational'
            EventId        = @(4104)
            Strategy       = 'Content'
            PatternList    = @(
                '-enc(odedcommand)?\s',
                'FromBase64String',
                'DownloadString',
                'DownloadFile',
                'IEX\s*\(',
                'Invoke-Expression',
                'System\.Net\.WebClient',
                'Bypass\s+-Scope',
                'HiddenWindowStyle|-w\s+hidden'
            )
            Severity       = 'High'
            Technique      = 'T1059.001'
            TechniqueName  = 'Command and Scripting Interpreter: PowerShell'
            Description    = 'Script block content matching common download-and-execute or obfuscation patterns.'
        }
        @{
            Id             = 'WSK0005'
            Name           = 'Service installed'
            LogName        = 'System'
            EventId        = @(7045)
            Strategy       = 'Presence'
            Severity       = 'Medium'
            Technique      = 'T1543.003'
            TechniqueName  = 'Create or Modify System Process: Windows Service'
            Description    = 'A new service was installed, a durable persistence mechanism.'
        }
        @{
            Id             = 'WSK0006'
            Name           = 'Audit log cleared'
            LogName        = 'Security'
            EventId        = @(1102)
            Strategy       = 'Presence'
            Severity       = 'Critical'
            Technique      = 'T1070.001'
            TechniqueName  = 'Indicator Removal: Clear Windows Event Logs'
            Description    = 'The Security audit log was cleared. Rare in normal operation and destroys evidence.'
        }
    )
}
