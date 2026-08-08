#Requires -Version 5.1

<#
.SYNOPSIS
    Fails the build when a CI gate inspected fewer inputs than expected.

.DESCRIPTION
    A gate reporting no failures has proved nothing unless it also processed
    something. This asserts the second half: that the gate's observed input count
    meets the floor in tools/gate-coverage.psd1, and is never zero.

    Three gates in this repository once reported clean while silently skipping
    their inputs -- PSScriptAnalyzer not descending into .github, Pester counting
    discovery failures as success, and a secret scan that could have been narrowed
    until it stopped finding real secrets. Each would have tripped this check. See
    the named section at the top of docs/engineering-notes.md.

    Zero always fails, regardless of the configured floor, because a gate that
    processed nothing is the failure mode this exists to catch.

.PARAMETER Gate
    Gate key from tools/gate-coverage.psd1, e.g. PSScriptAnalyzer.Files.

.PARAMETER Observed
    Number of inputs the gate actually processed.

.PARAMETER CoverageFile
    Path to the floors file. Defaults to gate-coverage.psd1 beside this script.

.EXAMPLE
    PS> ./tools/Assert-GateCoverage.ps1 -Gate 'Pester.Tests' -Observed 88
    Passes: 88 meets the floor of 80.

.EXAMPLE
    PS> ./tools/Assert-GateCoverage.ps1 -Gate 'Pester.WindowsTagged' -Observed 0
    Fails: a gate that processed zero inputs proved nothing.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Gate,

    [Parameter(Mandatory)]
    [int]$Observed,

    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CoverageFile = (Join-Path $PSScriptRoot 'gate-coverage.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$gates = (Import-PowerShellDataFile -Path $CoverageFile).Gates

if (-not $gates.ContainsKey($Gate)) {
    [Console]::Error.WriteLine("Unknown gate '$Gate'. Known: $(($gates.Keys | Sort-Object) -join ', ')")
    exit 2
}

$minimum = [int]$gates[$Gate]

if ($Observed -le 0) {
    [Console]::Error.WriteLine(
        "GATE COVERAGE FAILURE: '$Gate' processed $Observed inputs. " +
        'A gate that inspected nothing cannot report clean.')
    exit 1
}

if ($Observed -lt $minimum) {
    [Console]::Error.WriteLine(
        "GATE COVERAGE FAILURE: '$Gate' processed $Observed inputs, floor is $minimum. " +
        'Either the gate stopped seeing files it used to see, or the floor is stale. ' +
        'Investigate before lowering it -- see docs/engineering-notes.md.')
    exit 1
}

Write-Output "gate coverage OK: $Gate processed $Observed (floor $minimum)"
exit 0
