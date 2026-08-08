function Get-SecurityBaseline {
    <#
    .SYNOPSIS
        Returns the baseline control definitions.

    .DESCRIPTION
        Loads Data/baseline.psd1 and emits one object per control. Reads data
        only, so it runs anywhere PowerShell does and needs no privilege.

        CisId is empty on every control by design. See the header comment in
        Data/baseline.psd1: no CIS number here has been read from the benchmark,
        and an unverified control ID that looks authoritative is worse than none.

    .PARAMETER Id
        Return only controls with these ids. Accepts wildcards.

    .PARAMETER CheckType
        Return only controls of these types: Registry, FirewallProfile, FirewallRule.

    .EXAMPLE
        PS> Get-SecurityBaseline | Format-Table Id, Name, CheckType, Severity

        Lists the baseline.

    .EXAMPLE
        PS> Get-SecurityBaseline -CheckType Registry | Select-Object Id, Path, ValueName

        Shows just the registry controls and the values they assert.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [SupportsWildcards()]
        [string[]]$Id,

        [ValidateSet('Registry', 'FirewallProfile', 'FirewallRule')]
        [string[]]$CheckType
    )

    begin {
        $dataPath = Join-Path $script:ModuleRoot 'Data/baseline.psd1'
    }

    process {
        $data = Import-PowerShellDataFile -Path $dataPath

        foreach ($c in $data.Controls) {
            if ($Id) {
                $matched = $false
                foreach ($pattern in $Id) {
                    if ($c.Id -like $pattern) { $matched = $true; break }
                }
                if (-not $matched) { continue }
            }

            if ($CheckType -and $c.CheckType -notin $CheckType) { continue }

            # Values computed before the literal: an `if` expression inside a
            # hashtable literal parses differently across PowerShell versions and
            # this module targets 5.1.
            $path = $null; $valueName = $null; $expected = $null; $kind = $null
            $profiles = @(); $displayName = $null; $protocol = $null; $localPort = $null

            if ($c.ContainsKey('Path'))          { $path        = [string]$c.Path }
            # 'Name' is the control's own title, so the registry value name is
            # stored as Name_ in the data file to avoid the collision.
            if ($c.ContainsKey('Name_'))         { $valueName   = [string]$c.Name_ }
            if ($c.ContainsKey('ExpectedValue')) { $expected    = $c.ExpectedValue }
            if ($c.ContainsKey('ValueKind'))     { $kind        = [string]$c.ValueKind }
            if ($c.ContainsKey('Profile'))       { $profiles    = [string[]]$c.Profile }
            if ($c.ContainsKey('DisplayName'))   { $displayName = [string]$c.DisplayName }
            if ($c.ContainsKey('Protocol'))      { $protocol    = [string]$c.Protocol }
            if ($c.ContainsKey('LocalPort'))     { $localPort   = [string]$c.LocalPort }

            [PSCustomObject]@{
                PSTypeName    = 'WinSecKit.BaselineControl'
                Id            = $c.Id
                Name          = $c.Name
                CheckType     = $c.CheckType
                Severity      = $c.Severity
                CisId         = $c.CisId
                Rationale     = $c.Rationale
                Path          = $path
                ValueName     = $valueName
                ExpectedValue = $expected
                ValueKind     = $kind
                Profile       = $profiles
                DisplayName   = $displayName
                Protocol      = $protocol
                LocalPort     = $localPort
            }
        }
    }
}
