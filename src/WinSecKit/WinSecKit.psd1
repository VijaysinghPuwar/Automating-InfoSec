@{
    RootModule        = 'WinSecKit.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b3f1c2a4-5d6e-4f70-8a91-2c3d4e5f6a7b'
    Author            = 'Vijaysingh Puwar'
    Description       = 'Windows security auditing helpers: Security event log detections, a declarative host baseline, and Authenticode checks. Emits objects for reporting.'

    # 5.1 is the target: it ships on every Windows 10/11/Server 2016+ host with
    # nothing installed, and it is what the source labs ran on. Code written for
    # 5.1 also runs on 7; the reverse is not true. CI exercises both.
    PowerShellVersion = '5.1'

    # Windows only. Get-WinEvent, the NetSecurity cmdlets and Authenticode do not
    # exist on macOS or Linux. Declared so PowerShellGet refuses to install this
    # where it cannot work.
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @(
        'Get-SecurityEventRecord'
        'Get-SecurityDetection'
        'Test-SecurityDetection'
        'Get-SecurityBaseline'
        'Test-SecurityBaseline'
        'Invoke-SecurityBaseline'
        'Test-ScriptSignature'
        'Invoke-ScriptSigning'
        'Export-SecurityReport'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Security', 'Windows', 'EventLog', 'Hardening', 'ATTACK')
            LicenseUri = 'https://github.com/VijaysinghPuwar/Automating-InfoSec/blob/main/LICENSE'
            ProjectUri = 'https://github.com/VijaysinghPuwar/Automating-InfoSec'
        }
    }
}
