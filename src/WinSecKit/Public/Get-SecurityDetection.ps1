function Get-SecurityDetection {
    <#
    .SYNOPSIS
        Returns the detection definitions this module evaluates.

    .DESCRIPTION
        Loads Data/detections.psd1 and emits one object per detection. Use it to
        review what is checked, to filter a subset before passing to
        Test-SecurityDetection, or to build the ATT&CK coverage table.

        Reads data only. Touches no event log and requires no privilege, so it
        runs anywhere PowerShell does.

    .PARAMETER Id
        Return only detections with these ids. Accepts wildcards.

    .PARAMETER Technique
        Return only detections mapped to these MITRE ATT&CK technique ids.

    .EXAMPLE
        PS> Get-SecurityDetection | Format-Table Id, Name, LogName, Technique

        Lists every detection with the log it reads and its ATT&CK mapping.

    .EXAMPLE
        PS> Get-SecurityDetection -Technique T1110 | Select-Object -ExpandProperty Description

        Shows why the brute-force detection exists.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [SupportsWildcards()]
        [string[]]$Id,

        [string[]]$Technique
    )

    begin {
        $dataPath = Join-Path $script:ModuleRoot 'Data/detections.psd1'
    }

    process {
        $data = Import-PowerShellDataFile -Path $dataPath

        foreach ($d in $data.Detections) {
            if ($Id) {
                $matched = $false
                foreach ($pattern in $Id) {
                    if ($d.Id -like $pattern) { $matched = $true; break }
                }
                if (-not $matched) { continue }
            }

            if ($Technique -and $d.Technique -notin $Technique) { continue }

            # Computed ahead of the literal rather than inline. An `if` expression
            # inside a hashtable literal parses differently across PowerShell
            # versions, and this module targets 5.1 while being developed on 7.
            $minimumCount  = $null
            $windowMinutes = $null
            $groupBy       = $null
            $patternList   = @()
            if ($d.ContainsKey('MinimumCount'))  { $minimumCount  = [int]$d.MinimumCount }
            if ($d.ContainsKey('WindowMinutes')) { $windowMinutes = [int]$d.WindowMinutes }
            if ($d.ContainsKey('GroupBy'))       { $groupBy       = [string]$d.GroupBy }
            if ($d.ContainsKey('PatternList'))   { $patternList   = [string[]]$d.PatternList }

            [PSCustomObject]@{
                PSTypeName    = 'WinSecKit.Detection'
                Id            = $d.Id
                Name          = $d.Name
                LogName       = $d.LogName
                EventId       = [int[]]$d.EventId
                Strategy      = $d.Strategy
                Severity      = $d.Severity
                Technique     = $d.Technique
                TechniqueName = $d.TechniqueName
                Description   = $d.Description
                MinimumCount  = $minimumCount
                WindowMinutes = $windowMinutes
                GroupBy       = $groupBy
                PatternList   = $patternList
            }
        }
    }
}
