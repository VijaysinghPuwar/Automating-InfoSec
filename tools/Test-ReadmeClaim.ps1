#Requires -Version 5.1

<#
.SYNOPSIS
    Fails if a README claims a file or directory that does not exist.

.DESCRIPTION
    Every README in this repository once described scripts that were never
    committed. A reader who cloned it found the interesting parts missing. This
    check makes that failure mode impossible to reintroduce quietly.

    Two classes of claim are checked:

      1. Relative markdown links -- [text](path). External links, anchors and
         mailto: are ignored.
      2. Entries in a fenced directory tree that immediately follows a
         '## Contents' heading.

    Deliberately NOT checked: paths inside other fenced code blocks. Those are
    commands a reader runs, and the files they name -- keyfile.bin, report.html --
    are outputs the command produces, not repository contents. Failing on those
    would force the docs to stop showing what the code does.

.PARAMETER Path
    Repository root to scan. Defaults to the parent of this script's directory.

.EXAMPLE
    PS> ./tools/Test-ReadmeClaim.ps1
    Exits 0 when every claimed path exists.

.EXAMPLE
    PS> ./tools/Test-ReadmeClaim.ps1 -Path . ; if ($LASTEXITCODE) { 'broken claims' }
    Reports offenders on stderr and yields a non-zero exit code.
#>
[CmdletBinding()]
param(
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$Path = (Split-Path $PSScriptRoot -Parent)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root      = (Resolve-Path -LiteralPath $Path).Path
$offenders = [System.Collections.Generic.List[PSObject]]::new()

# Names present anywhere in the repo, for validating bare tree entries.
$allNames = [System.Collections.Generic.HashSet[string]]::new()
Get-ChildItem -LiteralPath $root -Recurse -Force |
    Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
    ForEach-Object { [void]$allNames.Add($_.Name) }

$readmes = Get-ChildItem -LiteralPath $root -Recurse -Filter '*.md' |
    Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }

foreach ($md in $readmes) {
    $text = Get-Content -LiteralPath $md.FullName -Raw

    # --- 1. relative markdown links -----------------------------------------
    foreach ($m in [regex]::Matches($text, '\[[^\]]*\]\(([^)]+)\)')) {
        $target = $m.Groups[1].Value.Split('#')[0].Trim()
        if (-not $target) { continue }
        if ($target -match '^(https?:|mailto:|#)') { continue }

        $candidate = Join-Path $md.DirectoryName $target
        if (-not (Test-Path -LiteralPath $candidate)) {
            $offenders.Add([PSCustomObject]@{
                File   = $md.FullName.Substring($root.Length + 1)
                Claim  = $target
                Reason = 'Relative link does not resolve'
            })
        }
    }

    # --- 2. fenced tree under a '## Contents' heading ------------------------
    foreach ($block in [regex]::Matches($text, '(?ms)^##\s+Contents\s*$.*?^```\s*$(.*?)^```\s*$')) {
        foreach ($line in $block.Groups[1].Value -split "`r?`n") {
            # Strip tree-drawing characters and any trailing '# comment'.
            # Restricted to the Unicode box-drawing block: a looser class that
            # included '-' silently rewrote lab04-transcript.ps1 to
            # 'lab04 transcript.ps1' and reported every hyphenated name as missing.
            $entry = ($line -replace '[\u2500-\u257F|]', ' ').Trim()
            if ($entry -match '^#') { continue }
            $entry = ($entry -split '\s+#')[0].Trim()
            if (-not $entry) { continue }

            $leaf = ($entry -replace '/+$', '').Split('/')[-1]
            if (-not $leaf) { continue }
            # Directory headers like 'labs/04-confidentiality/' resolve by name too.
            if (-not $allNames.Contains($leaf)) {
                $offenders.Add([PSCustomObject]@{
                    File   = $md.FullName.Substring($root.Length + 1)
                    Claim  = $entry
                    Reason = 'Contents entry not found in repository'
                })
            }
        }
    }
}

if ($offenders.Count -gt 0) {
    $offenders |
        Format-Table File, Claim, Reason -AutoSize |
        Out-String -Width 200 |
        ForEach-Object { [Console]::Error.Write($_) }
    [Console]::Error.WriteLine("$($offenders.Count) unmet README claim(s).")
    exit 1
}

Write-Output "INPUTS_CHECKED=$(@($readmes).Count)"
[Console]::Error.WriteLine("README claims OK: $(@($readmes).Count) file(s) checked.")
exit 0
