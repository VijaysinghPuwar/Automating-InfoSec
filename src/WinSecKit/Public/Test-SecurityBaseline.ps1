function Test-SecurityBaseline {
    <#
    .SYNOPSIS
        Audits the host against the baseline and reports drift. Changes nothing.

    .DESCRIPTION
        Emits one compliance object per control. This function never writes: it
        has no ShouldProcess and calls no setter. Remediation is a separate verb,
        Invoke-SecurityBaseline, so that running an audit can never be the thing
        that changed a machine.

        WINDOWS ONLY. Reads HKLM and the NetSecurity cmdlets. On a workgroup
        machine the Domain firewall profile still exists and is still readable,
        so WSB0004 evaluates normally without a domain.

        NOT COVERED: controls requiring Group Policy, AD LDS or domain password
        policy. Those cannot be verified on a standalone host and are absent from
        the baseline rather than reported as passing.

    .PARAMETER Control
        Controls to audit. Defaults to all of Get-SecurityBaseline.

    .PARAMETER NonCompliantOnly
        Emit only failing controls.

    .EXAMPLE
        PS> Test-SecurityBaseline | Format-Table Id, Name, Compliant, Detail

        Full compliance report.

    .EXAMPLE
        PS> Test-SecurityBaseline -NonCompliantOnly | Export-SecurityReport -Path drift.html

        Renders only the drift to a self-contained HTML report.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(ValueFromPipeline)]
        [PSObject[]]$Control,

        [switch]$NonCompliantOnly
    )

    begin {
        $all = [System.Collections.Generic.List[PSObject]]::new()
    }

    process {
        if ($Control) { foreach ($c in $Control) { $all.Add($c) } }
    }

    end {
        if ($all.Count -eq 0) { $all = [System.Collections.Generic.List[PSObject]](@(Get-SecurityBaseline)) }

        foreach ($c in $all) {
            $result = Test-WinSecKitControl -Control $c

            if ($NonCompliantOnly -and $result.Compliant) { continue }

            [PSCustomObject]@{
                PSTypeName  = 'WinSecKit.BaselineResult'
                Id          = $c.Id
                Name        = $c.Name
                CheckType   = $c.CheckType
                Severity    = $c.Severity
                CisId       = $c.CisId
                Compliant   = $result.Compliant
                ActualValue = $result.ActualValue
                Detail      = $result.Detail
                Rationale   = $c.Rationale
                MachineName = $env:COMPUTERNAME
                CheckedAt   = Get-Date
            }
        }
    }
}
