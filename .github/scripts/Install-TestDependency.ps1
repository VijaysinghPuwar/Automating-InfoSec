#Requires -Version 5.1

<#
.SYNOPSIS
    Installs the pinned Pester version for a CI test leg.

.DESCRIPTION
    Runs under both Windows PowerShell 5.1 and PowerShell 7, so the bootstrap
    lives in one place instead of being duplicated per matrix leg.

    Windows PowerShell 5.1 needs two things PowerShell 7 does not: TLS 1.2
    enabled, because it defaults to TLS 1.0 which PSGallery refuses, and the
    NuGet package provider bootstrapped before Install-Module will work. It also
    ships Pester 3.4.0 in-box, which cannot run Pester 5 syntax, so the pinned
    version must be installed and imported explicitly rather than relying on
    whatever Import-Module resolves.

.PARAMETER PesterVersion
    Exact Pester version to install.

.EXAMPLE
    PS> ./.github/scripts/Install-TestDependency.ps1 -PesterVersion 5.7.1
    Installs Pester 5.7.1 for the current PowerShell host.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PesterVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Output "Host: PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"

[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Get-PackageProvider -Name NuGet -ForceBootstrap | Out-Null
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

Install-Module -Name Pester -RequiredVersion $PesterVersion `
    -Scope CurrentUser -Force -SkipPublisherCheck

# Remove the in-box Pester 3.4 from the session before importing the pinned one,
# otherwise 5.1 can resolve the older module first.
Get-Module Pester | Remove-Module -Force
Import-Module Pester -RequiredVersion $PesterVersion -Force

$loaded = (Get-Module Pester).Version.ToString()
Write-Output "Pester loaded: $loaded"

if ($loaded -ne $PesterVersion) {
    throw "Expected Pester $PesterVersion but loaded $loaded."
}
