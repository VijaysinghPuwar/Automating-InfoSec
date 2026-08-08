#Requires -Version 5.1

<#
.SYNOPSIS
    Runs the Pester suite for one CI leg and writes results plus a job summary.

.DESCRIPTION
    Shared by both matrix legs so Windows PowerShell 5.1 and PowerShell 7 execute
    the identical code path. That is the point of the matrix: the module targets
    5.1 and claims to run on 7, and running two different scripts would not test
    that claim.

    The Windows-tagged tests are destructive by design. They create and remove
    firewall rules, write HKLM, and sign files with a throwaway certificate. This
    is intended only for the ephemeral CI runner.

.PARAMETER Suffix
    Short leg identifier used in the results filename, e.g. ps51.

.PARAMETER LegName
    Human-readable leg name for the job summary.

.PARAMETER PesterVersion
    Pester version to import, matching what Install-TestDependency.ps1 installed.

.EXAMPLE
    PS> ./.github/scripts/Invoke-TestSuite.ps1 -Suffix ps51 -LegName 'Windows PowerShell 5.1' -PesterVersion 5.7.1
    Runs the suite and exits non-zero if any test fails.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Suffix,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LegName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$PesterVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Get-Module Pester | Remove-Module -Force
Import-Module Pester -RequiredVersion $PesterVersion -Force

$config = New-PesterConfiguration
$config.Run.Path                  = './tests'
$config.Run.PassThru              = $true
$config.Output.Verbosity          = 'Detailed'
$config.TestResult.Enabled        = $true
$config.TestResult.OutputFormat   = 'NUnitXml'
$config.TestResult.OutputPath     = "testresults-$Suffix.xml"

$result = Invoke-Pester -Configuration $config

if ($env:GITHUB_STEP_SUMMARY) {
    # Add-Content -Encoding utf8, not Out-File: Windows PowerShell 5.1 defaults
    # Out-File to UTF-16, which GitHub renders as mojibake. The 7 leg would have
    # looked fine and the 5.1 leg would not, for no reason visible in the log.
    @(
        "## Pester: $LegName"
        ''
        "- Passed: $($result.PassedCount)"
        "- Failed: $($result.FailedCount)"
        "- Skipped: $($result.SkippedCount)"
        "- Duration: $($result.Duration)"
    ) | Add-Content -Path $env:GITHUB_STEP_SUMMARY -Encoding utf8
}

Write-Output "Passed: $($result.PassedCount)  Failed: $($result.FailedCount)  Skipped: $($result.SkippedCount)"

if ($result.FailedCount -gt 0) {
    foreach ($test in $result.Failed) {
        Write-Output "FAILED: $($test.ExpandedPath)"
        Write-Output "        $($test.ErrorRecord)"
    }
    exit 1
}

exit 0
