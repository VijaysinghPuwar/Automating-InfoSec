#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Discovery-time. Pester evaluates -ForEach while discovering tests, which happens
# before any BeforeAll runs, so a -ForEach referencing a variable set in BeforeAll
# silently iterates $null instead of failing. Read the manifest directly here.
$script:ManifestPath  = Join-Path (Split-Path $PSScriptRoot -Parent) 'src/WinSecKit/WinSecKit.psd1'
$script:ExportedNames = (Import-PowerShellDataFile -Path $script:ManifestPath).FunctionsToExport

BeforeAll {
    $script:RepoRoot   = Split-Path $PSScriptRoot -Parent
    $script:ModuleRoot = Join-Path $RepoRoot 'src/WinSecKit'
    Import-Module (Join-Path $ModuleRoot 'WinSecKit.psd1') -Force
    $script:Module = Get-Module WinSecKit
}

Describe 'Module manifest' {

    It 'is a valid manifest' {
        { Test-ModuleManifest -Path (Join-Path $ModuleRoot 'WinSecKit.psd1') -ErrorAction Stop } |
            Should -Not -Throw
    }

    It 'targets Windows PowerShell 5.1' {
        $Module.PowerShellVersion | Should -Be ([version]'5.1')
    }

    It 'exports exactly the functions the manifest lists' {
        $manifest = Import-PowerShellDataFile (Join-Path $ModuleRoot 'WinSecKit.psd1')
        ($Module.ExportedFunctions.Keys | Sort-Object) |
            Should -Be ($manifest.FunctionsToExport | Sort-Object)
    }

    It 'exports no aliases, cmdlets or variables' {
        $Module.ExportedAliases.Count   | Should -Be 0
        $Module.ExportedCmdlets.Count   | Should -Be 0
        $Module.ExportedVariables.Count | Should -Be 0
    }
}

Describe 'Function contract' {

    It 'uses only approved verbs' {
        $approved = (Get-Verb).Verb
        foreach ($name in $Module.ExportedFunctions.Keys) {
            ($name -split '-')[0] | Should -BeIn $approved -Because "$name must use an approved verb"
        }
    }

    It 'gives <_> a synopsis and at least one example' -ForEach $ExportedNames {
        $help = Get-Help $_
        $help.Synopsis | Should -Not -BeNullOrEmpty
        # Get-Help falls back to the syntax line when the help block fails to
        # parse, which is what a missing blank line after #Requires produces.
        $help.Synopsis | Should -Not -Match '^\s*\S+\.ps1'
        @($help.Examples.Example).Count | Should -BeGreaterOrEqual 1
    }

    It 'declares SupportsShouldProcess on every state-changing function' -ForEach @(
        'Invoke-SecurityBaseline', 'Invoke-ScriptSigning', 'Export-SecurityReport'
    ) {
        (Get-Command $_).Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }

    It 'does not declare SupportsShouldProcess on read-only functions' -ForEach @(
        'Get-SecurityDetection', 'Get-SecurityBaseline', 'Test-SecurityBaseline',
        'Test-SecurityDetection', 'Test-ScriptSignature', 'Get-SecurityEventRecord'
    ) {
        # An audit that can prompt "are you sure" is an audit that writes.
        (Get-Command $_).Parameters.ContainsKey('WhatIf') | Should -BeFalse
    }

    It 'contains no Write-Host anywhere in the module' {
        $hits = Get-ChildItem -Path $ModuleRoot -Filter '*.ps1' -Recurse |
            Select-String -Pattern '\bWrite-Host\b'
        $hits | Should -BeNullOrEmpty
    }
}

Describe 'Parameter validation' {

    It 'rejects an empty log name' {
        { Get-SecurityEventRecord -LogName '' } | Should -Throw
    }

    It 'rejects an out-of-range MaxEvents' {
        { Get-SecurityEventRecord -LogName Security -MaxEvents 0 } | Should -Throw
    }

    It 'rejects an unknown baseline check type' {
        { Get-SecurityBaseline -CheckType 'Nonsense' } | Should -Throw
    }

    It 'requires a path for Export-SecurityReport' {
        { [PSCustomObject]@{ A = 1 } | Export-SecurityReport -Path '' } | Should -Throw
    }
}

Describe 'Baseline definitions' {

    It 'gives every control a unique id' {
        $ids = (Get-SecurityBaseline).Id
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
    }

    It 'leaves every CIS id empty until verified against the benchmark' {
        # Deliberate. An unverified control number that looks authoritative is
        # worse than an empty field. See Data/baseline.psd1.
        foreach ($c in Get-SecurityBaseline) {
            $c.CisId | Should -BeNullOrEmpty
        }
    }

    It 'gives every control a rationale' {
        foreach ($c in Get-SecurityBaseline) {
            $c.Rationale | Should -Not -BeNullOrEmpty
        }
    }

    It 'uses only implemented check types' {
        foreach ($c in Get-SecurityBaseline) {
            $c.CheckType | Should -BeIn @('Registry', 'FirewallProfile', 'FirewallRule')
        }
    }
}
