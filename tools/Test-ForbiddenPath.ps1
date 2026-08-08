#Requires -Version 5.1

<#
.SYNOPSIS
    Fails if any tracked file matches a forbidden-path pattern.

.DESCRIPTION
    Key material has no reliable content signature -- a raw 16-byte AES key is
    just 16 bytes -- so it has to be caught by filename. gitleaks 8.30.1 drops
    path-based rules when its default ruleset is extended, so this check lives
    outside gitleaks and runs alongside it in CI and in the pre-commit hook.

    Patterns come from tools/forbidden-paths.txt, shared with .githooks/pre-commit
    so the local hook and CI cannot disagree about what is forbidden.

    Writes a Path/Pattern table to stderr naming every offending file and the
    pattern it tripped, then exits 1. Exits 0 and prints nothing when clean.

    This is a CI guard, not a pipeline source: it signals through the exit code
    and reports on stderr, so it composes with `if`/`&&` in a workflow step
    rather than with the object pipeline.

.PARAMETER PatternFile
    Path to the pattern list. Defaults to tools/forbidden-paths.txt beside this script.

.EXAMPLE
    PS> ./tools/Test-ForbiddenPath.ps1
    Scans every tracked file and exits 0 when the repository is clean.

.EXAMPLE
    PS> ./tools/Test-ForbiddenPath.ps1; if ($LASTEXITCODE) { 'blocked' }
    Reports offenders on stderr and yields a non-zero exit code to the caller.
#>
[CmdletBinding()]
param(
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PatternFile = (Join-Path $PSScriptRoot 'forbidden-paths.txt')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$patterns = Get-Content -LiteralPath $PatternFile |
    Where-Object { $_ -notmatch '^\s*(#|$)' }

if (-not $patterns) {
    throw "No patterns loaded from '$PatternFile'."
}

# git ls-files rather than Get-ChildItem: only tracked content can leak, and it
# keeps ignored/untracked scratch files from failing a developer's local run.
$tracked = & git ls-files
if ($LASTEXITCODE -ne 0) {
    throw 'git ls-files failed; is this a git repository?'
}

$offenders = foreach ($file in $tracked) {
    foreach ($pattern in $patterns) {
        if ($file -match $pattern) {
            [PSCustomObject]@{
                Path    = $file
                Pattern = $pattern
            }
            break
        }
    }
}

# Emitted so CI can assert this gate actually inspected files rather than
# reporting clean over an empty set.
Write-Output "INPUTS_CHECKED=$(@($tracked).Count)"

if ($offenders) {
    # Written to stderr, not Write-Error: $ErrorActionPreference is 'Stop', so
    # Write-Error would terminate and discard the formatter's buffered output --
    # the run would fail with no indication of which file tripped it. Emitting
    # the objects to stdout has the same problem, because `exit` below ends the
    # process before the default formatter flushes.
    $offenders |
        Format-Table Path, Pattern -AutoSize |
        Out-String -Width 200 |
        ForEach-Object { [Console]::Error.Write($_) }
    [Console]::Error.WriteLine(
        "$(@($offenders).Count) forbidden path(s) tracked. See SECURITY.md.")
    exit 1
}

exit 0
