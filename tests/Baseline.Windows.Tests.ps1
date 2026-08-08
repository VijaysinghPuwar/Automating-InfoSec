#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Destructive. Applies the baseline to the machine running it, then restores
    what it changed. Intended for the ephemeral windows-latest CI runner, which
    is administrative and discarded after the job.

    Tagged 'Windows' and 'Destructive'. Skipped automatically off Windows.
#>

$script:IsWindowsHost = $IsWindows -or ($PSVersionTable.PSEdition -eq 'Desktop')

Describe 'Security baseline on Windows' -Tag 'Windows', 'Destructive' -Skip:(-not $script:IsWindowsHost) {

    BeforeAll {
        $moduleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src/WinSecKit'
        Import-Module (Join-Path $moduleRoot 'WinSecKit.psd1') -Force

        # Firewall-rule controls are the safest destructive surface: they create
        # named rules that did not exist and can be removed cleanly afterwards.
        $script:RuleControls = @(Get-SecurityBaseline -Id 'WSB0005', 'WSB0006')
        $script:RegControl   = Get-SecurityBaseline -Id 'WSB0001'

        # Capture prior registry state so AfterAll can restore it.
        $script:RegExisted = $false
        $script:RegPrior   = $null
        try {
            $item = Get-ItemProperty -Path $RegControl.Path -Name $RegControl.ValueName -ErrorAction Stop
            $script:RegPrior   = $item.$($RegControl.ValueName)
            $script:RegExisted = $true
        }
        catch {
            Write-Verbose "Control value not currently set: $_"
        }

        foreach ($c in $RuleControls) {
            Remove-NetFirewallRule -DisplayName $c.DisplayName -ErrorAction SilentlyContinue
        }
    }

    AfterAll {
        foreach ($c in $script:RuleControls) {
            Remove-NetFirewallRule -DisplayName $c.DisplayName -ErrorAction SilentlyContinue
        }
        if ($script:RegExisted) {
            Set-ItemProperty -Path $script:RegControl.Path -Name $script:RegControl.ValueName `
                -Value $script:RegPrior -ErrorAction SilentlyContinue
        }
        else {
            Remove-ItemProperty -Path $script:RegControl.Path -Name $script:RegControl.ValueName `
                -ErrorAction SilentlyContinue
        }
    }

    Context 'Test-SecurityBaseline audits without changing anything' {

        It 'returns a result for every control' {
            $results = @(Test-SecurityBaseline)
            $results.Count | Should -Be @(Get-SecurityBaseline).Count
        }

        It 'reports the absent firewall rules as non-compliant' {
            $r = @($RuleControls | Test-SecurityBaseline)
            $r.Compliant | Should -Not -Contain $true
        }

        It 'does not create the rules it audited' {
            # The audit must be inert. If merely looking created the rule, the
            # remediation test below would pass for the wrong reason.
            foreach ($c in $RuleControls) {
                Get-NetFirewallRule -DisplayName $c.DisplayName -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty
            }
        }
    }

    Context '-WhatIf changes nothing' {

        It 'reports intent without creating the rule' {
            $RuleControls | Invoke-SecurityBaseline -WhatIf | Out-Null
            foreach ($c in $RuleControls) {
                Get-NetFirewallRule -DisplayName $c.DisplayName -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty
            }
        }

        It 'leaves the registry value untouched' {
            $before = $null
            try { $before = (Get-ItemProperty -Path $RegControl.Path -Name $RegControl.ValueName -ErrorAction Stop).$($RegControl.ValueName) } catch { Write-Verbose 'not set before' }
            $RegControl | Invoke-SecurityBaseline -WhatIf | Out-Null
            $after = $null
            try { $after = (Get-ItemProperty -Path $RegControl.Path -Name $RegControl.ValueName -ErrorAction Stop).$($RegControl.ValueName) } catch { Write-Verbose 'not set after' }
            $after | Should -Be $before
        }
    }

    Context 'Idempotency' {

        It 'first apply changes the machine and reaches compliance' {
            $first = @($RuleControls | Invoke-SecurityBaseline -Confirm:$false)
            $first.Count | Should -Be 2
            foreach ($r in $first) {
                $r.WasCompliant | Should -BeFalse
                $r.Changed      | Should -BeTrue
                $r.Compliant    | Should -BeTrue -Because "$($r.Id) should be compliant after remediation: $($r.Detail)"
            }
        }

        It 'second apply changes nothing and stays compliant' {
            # The idempotency proof: same command, no writes, same end state.
            $second = @($RuleControls | Invoke-SecurityBaseline -Confirm:$false)
            foreach ($r in $second) {
                $r.WasCompliant | Should -BeTrue
                $r.Changed      | Should -BeFalse -Because "$($r.Id) was already compliant and must not be rewritten"
                $r.Compliant    | Should -BeTrue
            }
        }

        It 'is idempotent for registry controls too' {
            $one = @($RegControl | Invoke-SecurityBaseline -Confirm:$false)
            $one[0].Compliant | Should -BeTrue
            $two = @($RegControl | Invoke-SecurityBaseline -Confirm:$false)
            $two[0].Changed   | Should -BeFalse
            $two[0].Compliant | Should -BeTrue
        }

        It 'audit agrees with remediation about the end state' {
            $audit = @($RuleControls | Test-SecurityBaseline)
            foreach ($a in $audit) { $a.Compliant | Should -BeTrue }
        }
    }

    Context 'Rollback record' {

        It 'writes prior state when -RollbackPath is given' {
            foreach ($c in $RuleControls) {
                Remove-NetFirewallRule -DisplayName $c.DisplayName -ErrorAction SilentlyContinue
            }
            $path = Join-Path $env:TEMP "wsk-rollback-$PID.json"
            Remove-Item $path -ErrorAction SilentlyContinue

            $RuleControls | Invoke-SecurityBaseline -RollbackPath $path -Confirm:$false | Out-Null

            Test-Path $path | Should -BeTrue
            $json = Get-Content $path -Raw | ConvertFrom-Json
            @($json).Count | Should -BeGreaterOrEqual 2
            @($json)[0].ControlId | Should -Match '^WSB'

            Remove-Item $path -ErrorAction SilentlyContinue
        }
    }

    Context 'Live event log access' {

        It 'reads the System log through Get-SecurityEventRecord' {
            # System rather than Security: readable without further privilege and
            # never empty on a booted machine.
            $recs = @(Get-SecurityEventRecord -LogName System -MaxEvents 10)
            $recs.Count | Should -BeGreaterThan 0
            $recs[0].TimeCreated | Should -BeOfType [datetime]
            $recs[0].LogName | Should -Be 'System'
        }

        It 'flattens named EventData fields into the Data hashtable' {
            $recs = @(Get-SecurityEventRecord -LogName System -MaxEvents 50)
            $withData = @($recs | Where-Object { $_.Data.Keys.Count -gt 0 })
            $withData.Count | Should -BeGreaterThan 0 -Because 'some System events carry named EventData'
        }

        It 'compiles an XPath filter that the log service accepts' {
            { Get-SecurityEventRecord -LogName System -EventId 7045 -MaxEvents 5 -ErrorAction Stop } |
                Should -Not -Throw
        }

        It 'returns nothing rather than throwing when no events match' {
            $recs = @(Get-SecurityEventRecord -LogName System -EventId 999999 -MaxEvents 5)
            $recs.Count | Should -Be 0
        }

        It 'feeds real records through the detection pipeline' {
            $findings = @(Get-SecurityEventRecord -LogName System -MaxEvents 200 | Test-SecurityDetection)
            # Assert it runs and returns well-formed objects, not that a clean
            # runner is compromised.
            foreach ($f in $findings) { $f.DetectionId | Should -Match '^WSK' }
        }
    }
}
