#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Remediation paths with every setter mocked, so nothing on the host changes.
    Needs Windows only because Pester can mock a command only where it exists.
#>

# $env:OS, not $IsWindows: the latter does not exist in Windows PowerShell 5.1.
$script:IsWindowsHost = ($env:OS -eq 'Windows_NT')

Describe 'SMBv1 remediation (mocked)' -Tag 'Windows' -Skip:(-not $script:IsWindowsHost) {

    BeforeAll {
        $moduleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src/WinSecKit'
        Import-Module (Join-Path $moduleRoot 'WinSecKit.psd1') -Force
        $script:Smb = Get-SecurityBaseline -Id 'WSB0003'
    }

    It 'disables SMBv1 when it is enabled' {
        $script:smbOn = $true
        Mock Get-SmbServerConfiguration -ModuleName WinSecKit { [PSCustomObject]@{ EnableSMB1Protocol = $script:smbOn } }
        Mock Set-SmbServerConfiguration -ModuleName WinSecKit { $script:smbOn = $false }

        $r = $Smb | Invoke-SecurityBaseline -Confirm:$false
        Should -Invoke Set-SmbServerConfiguration -ModuleName WinSecKit -Times 1 -Exactly -ParameterFilter {
            $EnableSMB1Protocol -eq $false
        }
        $r.WasCompliant | Should -BeFalse
        $r.Changed      | Should -BeTrue
        $r.Compliant    | Should -BeTrue
    }

    It 'changes nothing when SMBv1 is already off' {
        Mock Get-SmbServerConfiguration -ModuleName WinSecKit { [PSCustomObject]@{ EnableSMB1Protocol = $false } }
        Mock Set-SmbServerConfiguration -ModuleName WinSecKit { }

        $r = $Smb | Invoke-SecurityBaseline -Confirm:$false
        Should -Invoke Set-SmbServerConfiguration -ModuleName WinSecKit -Times 0 -Exactly
        $r.Changed   | Should -BeFalse
        $r.Compliant | Should -BeTrue
    }

    It 'writes nothing under -WhatIf' {
        Mock Get-SmbServerConfiguration -ModuleName WinSecKit { [PSCustomObject]@{ EnableSMB1Protocol = $true } }
        Mock Set-SmbServerConfiguration -ModuleName WinSecKit { }

        $null = $Smb | Invoke-SecurityBaseline -WhatIf
        Should -Invoke Set-SmbServerConfiguration -ModuleName WinSecKit -Times 0 -Exactly
    }

    It 'reports non-compliant when the configuration cannot be read' {
        Mock Get-SmbServerConfiguration -ModuleName WinSecKit { throw 'access denied' }
        $r = $Smb | Test-SecurityBaseline
        $r.Compliant | Should -BeFalse
        $r.Detail    | Should -Match 'unreadable'
    }
}
