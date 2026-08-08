#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src/WinSecKit'
    Import-Module (Join-Path $moduleRoot 'WinSecKit.psd1') -Force

    # Synthetic records. Deliberately built by hand rather than captured from a
    # real log, so these tests run without a Security log or an elevated session
    # and cover cases a live log will not reliably produce on demand.
    function MakeTestRecord {
        param(
            [int]$Id,
            [string]$LogName,
            [datetime]$TimeCreated,
            [string]$Message = '',
            [string]$TargetUserName
        )
        $data = @{}
        if ($PSBoundParameters.ContainsKey('TargetUserName')) {
            $data['TargetUserName'] = $TargetUserName
        }
        [PSCustomObject]@{
            TimeCreated = $TimeCreated
            Id          = $Id
            LogName     = $LogName
            MachineName = 'TESTHOST'
            Message     = $Message
            Data        = $data
        }
    }

    $script:Base = Get-Date '2025-01-01T10:00:00'
}

Describe 'Get-SecurityDetection' {

    It 'returns every detection by default' {
        (Get-SecurityDetection).Count | Should -Be 6
    }

    It 'maps each detection to a MITRE ATT&CK technique id' {
        foreach ($d in Get-SecurityDetection) {
            $d.Technique | Should -Match '^T\d{4}(\.\d{3})?$'
        }
    }

    It 'gives every detection a unique id' {
        $ids = (Get-SecurityDetection).Id
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
    }

    It 'filters by id with wildcards' {
        (Get-SecurityDetection -Id 'WSK000[13]').Id | Should -Be @('WSK0001', 'WSK0003')
    }

    It 'filters by technique' {
        (Get-SecurityDetection -Technique 'T1110').Id | Should -Be 'WSK0001'
    }

    It 'records the correct log for each event id' {
        # These two are the ones commonly misattributed to Security.
        (Get-SecurityDetection -Id WSK0004).LogName | Should -Be 'Microsoft-Windows-PowerShell/Operational'
        (Get-SecurityDetection -Id WSK0005).LogName | Should -Be 'System'
    }
}

Describe 'Test-SecurityDetection threshold strategy' {

    BeforeAll { $script:Burst = Get-SecurityDetection -Id WSK0001 }

    It 'reports a burst that meets the threshold inside the window' {
        $recs = 0..4 | ForEach-Object {
            MakeTestRecord -Id 4625 -LogName Security -TimeCreated $Base.AddMinutes($_) -TargetUserName 'bob'
        }
        $f = @($recs | Test-SecurityDetection -Detection $Burst)
        $f.Count | Should -Be 1
        $f[0].Count | Should -Be 5
        $f[0].Key | Should -Be 'bob'
    }

    It 'stays silent one event below the threshold' {
        $recs = 0..3 | ForEach-Object {
            MakeTestRecord -Id 4625 -LogName Security -TimeCreated $Base.AddMinutes($_) -TargetUserName 'bob'
        }
        @($recs | Test-SecurityDetection -Detection $Burst).Count | Should -Be 0
    }

    It 'stays silent when the same count is spread beyond the window' {
        $recs = 0..4 | ForEach-Object {
            MakeTestRecord -Id 4625 -LogName Security -TimeCreated $Base.AddMinutes($_ * 10) -TargetUserName 'bob'
        }
        @($recs | Test-SecurityDetection -Detection $Burst).Count | Should -Be 0
    }

    It 'detects a burst straddling a fixed-interval boundary' {
        # 10:58 - 11:02. Bucketing by clock hour splits this and misses it;
        # a sliding window does not. This is the regression this test exists for.
        $times = @('10:58', '10:59', '11:00', '11:01', '11:02')
        $recs = $times | ForEach-Object {
            MakeTestRecord -Id 4625 -LogName Security -TimeCreated ([datetime]"2025-01-01T$_`:00") -TargetUserName 'bob'
        }
        $f = @($recs | Test-SecurityDetection -Detection $Burst)
        $f.Count | Should -Be 1
        $f[0].Count | Should -Be 5
    }

    It 'groups by account so one noisy user does not mask another' {
        $bob = 0..4 | ForEach-Object {
            MakeTestRecord -Id 4625 -LogName Security -TimeCreated $Base.AddMinutes($_) -TargetUserName 'bob'
        }
        $eve = 0..4 | ForEach-Object {
            MakeTestRecord -Id 4625 -LogName Security -TimeCreated $Base.AddMinutes($_ * 10) -TargetUserName 'eve'
        }
        $f = @(($bob + $eve) | Test-SecurityDetection -Detection $Burst)
        $f.Count | Should -Be 1
        $f[0].Key | Should -Be 'bob'
    }

    It 'emits one finding per group, not one per sliding window position' {
        $recs = 0..20 | ForEach-Object {
            MakeTestRecord -Id 4625 -LogName Security -TimeCreated $Base.AddSeconds($_ * 10) -TargetUserName 'bob'
        }
        @($recs | Test-SecurityDetection -Detection $Burst).Count | Should -Be 1
    }

    It 'falls back to a single bucket when the grouping field is absent' {
        $recs = 0..4 | ForEach-Object {
            MakeTestRecord -Id 4625 -LogName Security -TimeCreated $Base.AddMinutes($_)
        }
        $f = @($recs | Test-SecurityDetection -Detection $Burst)
        $f.Count | Should -Be 1
        $f[0].Key | Should -Be '<unknown>'
    }
}

Describe 'Test-SecurityDetection log discrimination' {

    It 'does not match a 4104 raised in the wrong log' {
        # Matching on event id alone would report this as a PowerShell script block.
        $r = MakeTestRecord -Id 4104 -LogName 'Security' -TimeCreated $Base `
            -Message 'IEX (New-Object System.Net.WebClient).DownloadString("x")'
        @($r | Test-SecurityDetection -Detection (Get-SecurityDetection -Id WSK0004)).Count | Should -Be 0
    }

    It 'matches the same content in the correct log' {
        $r = MakeTestRecord -Id 4104 -LogName 'Microsoft-Windows-PowerShell/Operational' -TimeCreated $Base `
            -Message 'IEX (New-Object System.Net.WebClient).DownloadString("x")'
        @($r | Test-SecurityDetection -Detection (Get-SecurityDetection -Id WSK0004)).Count | Should -Be 1
    }
}

Describe 'Test-SecurityDetection content strategy' {

    BeforeAll { $script:Content = Get-SecurityDetection -Id WSK0004 }

    It 'does not fire on benign script block content' {
        $r = MakeTestRecord -Id 4104 -LogName 'Microsoft-Windows-PowerShell/Operational' `
            -TimeCreated $Base -Message 'Get-ChildItem C:\temp | Sort-Object Name'
        @($r | Test-SecurityDetection -Detection $Content).Count | Should -Be 0
    }

    It 'fires on each suspicious pattern' -ForEach @(
        @{ Text = 'powershell -enc SQBFAFgA' }
        @{ Text = '[Convert]::FromBase64String($x)' }
        @{ Text = '(New-Object Net.WebClient).DownloadFile($a,$b)' }
        @{ Text = 'Invoke-Expression $payload' }
    ) {
        $r = MakeTestRecord -Id 4104 -LogName 'Microsoft-Windows-PowerShell/Operational' `
            -TimeCreated $Base -Message $Text
        @($r | Test-SecurityDetection -Detection $Content).Count | Should -Be 1
    }
}

Describe 'Test-SecurityDetection presence strategy' {

    It 'reports a cleared audit log as Critical' {
        $r = MakeTestRecord -Id 1102 -LogName Security -TimeCreated $Base -Message 'The audit log was cleared'
        $f = @($r | Test-SecurityDetection -Detection (Get-SecurityDetection -Id WSK0006))
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'Critical'
        $f[0].Technique | Should -Be 'T1070.001'
    }

    It 'returns nothing for an empty record set' {
        @(Test-SecurityDetection -Record @()).Count | Should -Be 0
    }
}

Describe 'Test-SecurityDetection does not mutate input' {

    It 'leaves the input records untouched' {
        $r = MakeTestRecord -Id 1102 -LogName Security -TimeCreated $Base -Message 'cleared'
        $before = $r.PSObject.Copy()
        $null = @($r | Test-SecurityDetection)
        $r.Id | Should -Be $before.Id
        $r.Message | Should -Be $before.Message
    }
}
