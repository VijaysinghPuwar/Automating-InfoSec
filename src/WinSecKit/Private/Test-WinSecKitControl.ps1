function Test-WinSecKitControl {
    <#
        Evaluates one baseline control and reports compliance plus the observed value.

        Private, and shared by Test-SecurityBaseline and Invoke-SecurityBaseline so
        the audit and the remediation can never disagree about what compliant
        means. Invoke- calls this before acting and again afterwards; a remediation
        that does not flip this function's verdict is a failed remediation.

        WINDOWS ONLY. Reads HKLM and the NetSecurity cmdlets.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][PSObject]$Control
    )

    $compliant = $false
    $actual    = $null
    $detail    = ''

    switch ($Control.CheckType) {

        'Registry' {
            try {
                $item = Get-ItemProperty -Path $Control.Path -Name $Control.ValueName -ErrorAction Stop
                $actual = $item.$($Control.ValueName)
                $compliant = ($actual -eq $Control.ExpectedValue)
                $detail = "$($Control.Path)\$($Control.ValueName) = $actual (expected $($Control.ExpectedValue))"
            }
            catch {
                $actual = $null
                $compliant = $false
                $detail = "$($Control.Path)\$($Control.ValueName) is not set (expected $($Control.ExpectedValue))"
            }
        }

        'FirewallProfile' {
            $disabled = [System.Collections.Generic.List[string]]::new()
            foreach ($p in $Control.Profile) {
                try {
                    $prof = Get-NetFirewallProfile -Profile $p -ErrorAction Stop
                    if (-not $prof.Enabled) { $disabled.Add($p) }
                }
                catch {
                    $disabled.Add("$p (unreadable)")
                }
            }
            $compliant = ($disabled.Count -eq 0)
            $actual    = ($Control.Profile | Where-Object { $_ -notin $disabled }) -join ','
            if ($compliant) {
                $detail = "All profiles enabled: $($Control.Profile -join ', ')"
            }
            else {
                $detail = "Disabled or unreadable: $($disabled -join ', ')"
            }
        }

        'FirewallRule' {
            $rule = Get-NetFirewallRule -DisplayName $Control.DisplayName -ErrorAction SilentlyContinue
            if (-not $rule) {
                $compliant = $false
                $detail = "No rule named '$($Control.DisplayName)'"
            }
            else {
                # Enabled is an enum, not a bool, on the NetSecurity cmdlets.
                $isEnabled = ("$($rule.Enabled)" -eq 'True')
                $isBlock   = ("$($rule.Action)" -eq 'Block')
                $isInbound = ("$($rule.Direction)" -eq 'Inbound')

                $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $portOk = $false
                if ($portFilter) {
                    $portOk = (("$($portFilter.Protocol)" -eq $Control.Protocol) -and
                               ("$($portFilter.LocalPort)" -eq $Control.LocalPort))
                }

                $compliant = ($isEnabled -and $isBlock -and $isInbound -and $portOk)
                $actual    = "Enabled=$isEnabled Action=$($rule.Action) Direction=$($rule.Direction)"
                $detail    = "$actual PortMatch=$portOk"
            }
        }

        default {
            $compliant = $false
            $detail = "Unknown CheckType '$($Control.CheckType)'"
        }
    }

    [PSCustomObject]@{
        Compliant   = $compliant
        ActualValue = $actual
        Detail      = $detail
    }
}
