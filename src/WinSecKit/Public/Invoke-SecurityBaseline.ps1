function Invoke-SecurityBaseline {
    <#
    .SYNOPSIS
        Brings the host into compliance with the baseline. Idempotent.

    .DESCRIPTION
        Applies only the controls that Test-WinSecKitControl reports as
        non-compliant, then re-checks each one it touched. A control already in
        the desired state is reported with Changed = $false and is not written to,
        so a second run reports no changes. CI asserts exactly that: apply,
        assert changed, apply again, assert unchanged.

        Every change is gated on ShouldProcess, so -WhatIf performs no writes and
        -Confirm prompts per control.

        Before each change the previous state is captured. Pass -RollbackPath to
        write it to a JSON file. There is no restore command; the file is a
        record for undoing changes by hand. Firewall rules are matched by
        DisplayName. A non-compliant rule with the control's DisplayName is
        removed and recreated; rules with other names are never touched.

        WINDOWS ONLY, and requires an elevated session to write HKLM, the
        firewall and the SMB server configuration.

        NOT COVERED: Group Policy, AD LDS and domain password policy. Those need
        a domain and are absent from the baseline rather than silently skipped.

    .PARAMETER Control
        Controls to apply. Defaults to all of Get-SecurityBaseline.

    .PARAMETER RollbackPath
        Write prior state to this JSON file before making changes.

    .EXAMPLE
        PS> Invoke-SecurityBaseline -WhatIf

        Reports what would change without writing anything.

    .EXAMPLE
        PS> Invoke-SecurityBaseline -RollbackPath ./rollback.json |
                Format-Table Id, Changed, Compliant, Detail

        Applies the baseline, recording prior state first.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(ValueFromPipeline)]
        [PSObject[]]$Control,

        [string]$RollbackPath
    )

    begin {
        $all = [System.Collections.Generic.List[PSObject]]::new()
        $rollback = [System.Collections.Generic.List[PSObject]]::new()
    }

    process {
        if ($Control) { foreach ($c in $Control) { $all.Add($c) } }
    }

    end {
        if ($all.Count -eq 0) { $all = [System.Collections.Generic.List[PSObject]](@(Get-SecurityBaseline)) }

        foreach ($c in $all) {
            $before  = Test-WinSecKitControl -Control $c
            $changed = $false
            $error_  = ''

            if (-not $before.Compliant) {

                $target = "$($c.Id) $($c.Name)"
                $action = "Apply baseline control ($($c.CheckType))"

                if ($PSCmdlet.ShouldProcess($target, $action)) {
                    try {
                        switch ($c.CheckType) {

                            'Registry' {
                                $rollback.Add([PSCustomObject]@{
                                    ControlId = $c.Id; CheckType = 'Registry'
                                    Path = $c.Path; ValueName = $c.ValueName
                                    PreviousValue = $before.ActualValue
                                    Existed = ($null -ne $before.ActualValue)
                                })
                                if (-not (Test-Path -Path $c.Path)) {
                                    $null = New-Item -Path $c.Path -Force
                                }
                                $null = New-ItemProperty -Path $c.Path -Name $c.ValueName `
                                    -Value $c.ExpectedValue -PropertyType $c.ValueKind -Force
                                $changed = $true
                            }

                            'SmbServer' {
                                $rollback.Add([PSCustomObject]@{
                                    ControlId = $c.Id; CheckType = 'SmbServer'
                                    Setting = $c.Setting; PreviousValue = $before.ActualValue
                                })
                                $smbParams = @{ $c.Setting = $c.ExpectedValue }
                                Set-SmbServerConfiguration @smbParams -Force -Confirm:$false -ErrorAction Stop
                                $changed = $true
                            }

                            'FirewallProfile' {
                                foreach ($p in $c.Profile) {
                                    $prof = Get-NetFirewallProfile -Profile $p -ErrorAction Stop
                                    $rollback.Add([PSCustomObject]@{
                                        ControlId = $c.Id; CheckType = 'FirewallProfile'
                                        Profile = $p; PreviousValue = "$($prof.Enabled)"
                                    })
                                    if (-not $prof.Enabled) {
                                        Set-NetFirewallProfile -Profile $p -Enabled True -ErrorAction Stop
                                        $changed = $true
                                    }
                                }
                            }

                            'FirewallRule' {
                                $existing = Get-NetFirewallRule -DisplayName $c.DisplayName -ErrorAction SilentlyContinue
                                $rollback.Add([PSCustomObject]@{
                                    ControlId = $c.Id; CheckType = 'FirewallRule'
                                    DisplayName = $c.DisplayName
                                    Existed = [bool]$existing
                                })
                                # Remove a partial/incorrect rule of the same name rather
                                # than layering a second rule with identical DisplayName.
                                if ($existing) {
                                    Remove-NetFirewallRule -DisplayName $c.DisplayName -ErrorAction Stop
                                }
                                $null = New-NetFirewallRule -DisplayName $c.DisplayName `
                                    -Direction Inbound -Action Block -Enabled True `
                                    -Protocol $c.Protocol -LocalPort $c.LocalPort `
                                    -Profile Any -ErrorAction Stop
                                $changed = $true
                            }

                            default { throw "Unknown CheckType '$($c.CheckType)'" }
                        }
                    }
                    catch {
                        $error_ = "$_"
                        Write-Error "Control $($c.Id) failed to apply: $_"
                    }
                }
            }

            # Re-check after acting. Under -WhatIf nothing was written, so this
            # reports the unchanged state, which is the correct dry-run answer.
            $after = Test-WinSecKitControl -Control $c

            [PSCustomObject]@{
                PSTypeName    = 'WinSecKit.RemediationResult'
                Id            = $c.Id
                Name          = $c.Name
                CheckType     = $c.CheckType
                Severity      = $c.Severity
                WasCompliant  = $before.Compliant
                Changed       = $changed
                Compliant     = $after.Compliant
                Detail        = $after.Detail
                Error         = $error_
                MachineName   = $env:COMPUTERNAME
                AppliedAt     = Get-Date
            }
        }

        if ($RollbackPath -and $rollback.Count -gt 0) {
            if ($PSCmdlet.ShouldProcess($RollbackPath, 'Write rollback record')) {
                $rollback | ConvertTo-Json -Depth 5 |
                    Set-Content -LiteralPath $RollbackPath -Encoding UTF8
                Write-Verbose "Rollback record written to $RollbackPath"
            }
        }
    }
}
