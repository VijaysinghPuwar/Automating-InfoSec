#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $moduleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src/WinSecKit'
    Import-Module (Join-Path $moduleRoot 'WinSecKit.psd1') -Force

    $script:OutDir = Join-Path ([IO.Path]::GetTempPath()) "wsk-report-tests-$PID"
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

    function MakeOutPath { Join-Path $OutDir ("r{0}.html" -f [guid]::NewGuid().ToString('N')) }
}

AfterAll {
    Remove-Item -LiteralPath $OutDir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Export-SecurityReport' {

    It 'writes nothing under -WhatIf' {
        $p = MakeOutPath
        [PSCustomObject]@{ Id = 'X'; Compliant = $true } | Export-SecurityReport -Path $p -WhatIf
        Test-Path $p | Should -BeFalse
    }

    It 'writes a file for real' {
        $p = MakeOutPath
        [PSCustomObject]@{ Id = 'X'; Compliant = $true } | Export-SecurityReport -Path $p
        Test-Path $p | Should -BeTrue
        (Get-Item $p).Length | Should -BeGreaterThan 0
    }

    It 'produces a self-contained page with no external references' {
        # A report that pulls a stylesheet from a CDN stops rendering the moment
        # it is opened offline, which is exactly when incident reports get read.
        $p = MakeOutPath
        [PSCustomObject]@{ Id = 'X'; Compliant = $true } | Export-SecurityReport -Path $p
        $html = Get-Content $p -Raw
        $html | Should -Not -Match '(src|href)\s*=\s*"https?:'
        $html | Should -Not -Match '<script'
    }

    It 'HTML-encodes attacker-controlled text' {
        # Event log messages contain text an attacker chose. Rendering it raw
        # turns the report into the delivery vehicle.
        $p = MakeOutPath
        [PSCustomObject]@{ Evidence = '<script>alert(1)</script>' } | Export-SecurityReport -Path $p
        $html = Get-Content $p -Raw
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;alert'
    }

    It 'unions columns across a mixed result set' {
        $p = MakeOutPath
        @(
            [PSCustomObject]@{ Alpha = 1 }
            [PSCustomObject]@{ Beta  = 2 }
        ) | Export-SecurityReport -Path $p
        $html = Get-Content $p -Raw
        $html | Should -Match '<th>Alpha</th>'
        $html | Should -Match '<th>Beta</th>'
    }

    It 'warns and writes nothing for an empty result set' {
        $p = MakeOutPath
        @() | Export-SecurityReport -Path $p -WarningAction SilentlyContinue
        Test-Path $p | Should -BeFalse
    }

    It 'passes objects through with -PassThru' {
        $p = MakeOutPath
        $out = @([PSCustomObject]@{ Id = 'X' } | Export-SecurityReport -Path $p -PassThru)
        $out.Count | Should -Be 1
        $out[0].Id | Should -Be 'X'
    }

    It 'renders a real detection finding end to end' {
        $rec = [PSCustomObject]@{
            TimeCreated = Get-Date '2025-01-01T10:00:00'
            Id          = 1102
            LogName     = 'Security'
            MachineName = 'TESTHOST'
            Message     = 'The audit log was cleared'
            Data        = @{}
        }
        $p = MakeOutPath
        $rec | Test-SecurityDetection | Export-SecurityReport -Path $p -Title 'Findings'
        $html = Get-Content $p -Raw
        $html | Should -Match 'WSK0006'
        $html | Should -Match 'T1070\.001'
        $html | Should -Match '<title>Findings</title>'
    }
}
