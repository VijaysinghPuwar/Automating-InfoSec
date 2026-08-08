function Test-SecurityDetection {
    <#
    .SYNOPSIS
        Evaluates event records against detection definitions and emits findings.

    .DESCRIPTION
        Pure evaluation: takes records in, emits findings out, reads no log and
        changes nothing. All Windows-specific acquisition lives in
        Get-SecurityEventRecord, which keeps this logic testable against synthetic
        records on any platform and keeps the untestable surface small.

        A record matches a detection when both its EventId and LogName match. The
        LogName check matters: event id 4104 in the Security log is not a
        PowerShell script block, and matching on id alone would report it as one.

        Three strategies, per the definition:
          Presence  - every matching record is a finding.
          Threshold - a finding when MinimumCount records sharing the same GroupBy
                      value fall inside any WindowMinutes-wide window. Evaluated as
                      a sliding window over the sorted timestamps, not by bucketing
                      into fixed intervals, which would miss a burst straddling a
                      bucket boundary.
          Content   - a matching record whose Message matches any PatternList entry.

    .PARAMETER Record
        Event records to evaluate. Accepts pipeline input from Get-SecurityEventRecord.
        Each record needs TimeCreated, Id, LogName and Message; Data is a hashtable
        of the event's named fields and is required for Threshold grouping.

    .PARAMETER Detection
        Detection definitions to apply. Defaults to all of Get-SecurityDetection.

    .EXAMPLE
        PS> Get-SecurityEventRecord -LogName Security -MaxEvents 5000 | Test-SecurityDetection

        Evaluates the last 5000 Security records against every detection.

    .EXAMPLE
        PS> $records | Test-SecurityDetection -Detection (Get-SecurityDetection -Id WSK0001)

        Runs only the failed-logon-burst detection.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(ValueFromPipeline)]
        [PSObject[]]$Record,

        [PSObject[]]$Detection
    )

    begin {
        if (-not $PSBoundParameters.ContainsKey('Detection')) {
            $Detection = @(Get-SecurityDetection)
        }
        $collected = [System.Collections.Generic.List[PSObject]]::new()
    }

    process {
        if ($Record) {
            foreach ($r in $Record) { $collected.Add($r) }
        }
    }

    end {
        foreach ($det in $Detection) {

            $matching = @($collected | Where-Object {
                $_.Id -in $det.EventId -and $_.LogName -eq $det.LogName
            })

            if (-not $matching) { continue }

            switch ($det.Strategy) {

                'Presence' {
                    foreach ($m in $matching) {
                        ConvertTo-WinSecKitFinding -Detection $det -Count 1 `
                            -FirstSeen $m.TimeCreated -LastSeen $m.TimeCreated `
                            -MachineName $m.MachineName -Key '' -Evidence $m.Message
                    }
                }

                'Content' {
                    foreach ($m in $matching) {
                        $hit = $null
                        foreach ($pattern in $det.PatternList) {
                            if ($m.Message -match $pattern) { $hit = $pattern; break }
                        }
                        if ($hit) {
                            ConvertTo-WinSecKitFinding -Detection $det -Count 1 `
                                -FirstSeen $m.TimeCreated -LastSeen $m.TimeCreated `
                                -MachineName $m.MachineName -Key $hit -Evidence $m.Message
                        }
                    }
                }

                'Threshold' {
                    $groups = $matching | Group-Object -Property {
                        Get-WinSecKitRecordField -Record $_ -Name $det.GroupBy
                    }

                    foreach ($group in $groups) {
                        $times = @($group.Group.TimeCreated | Sort-Object)
                        if ($times.Count -lt $det.MinimumCount) { continue }

                        $window = [timespan]::FromMinutes($det.WindowMinutes)
                        $start  = 0

                        for ($end = 0; $end -lt $times.Count; $end++) {
                            while (($times[$end] - $times[$start]) -gt $window) { $start++ }

                            $inWindow = $end - $start + 1
                            if ($inWindow -ge $det.MinimumCount) {
                                $sample = @($group.Group)[0]
                                ConvertTo-WinSecKitFinding -Detection $det -Count $inWindow `
                                    -FirstSeen $times[$start] -LastSeen $times[$end] `
                                    -MachineName $sample.MachineName `
                                    -Key $group.Name -Evidence $sample.Message
                                break   # one finding per group, not one per window position
                            }
                        }
                    }
                }

                default {
                    Write-Warning "Detection $($det.Id) has unknown strategy '$($det.Strategy)'; skipped."
                }
            }
        }
    }
}
