<#
    Minimum input counts per CI gate.

    A gate that finds no failures has proved nothing unless it also looked at
    something. These floors turn "no findings" into "no findings across at least
    N inputs", which is a claim that can actually fail.

    Three separate gates in this repository once reported clean while silently
    processing far fewer inputs than intended -- see the named section at the top
    of docs/engineering-notes.md. Each of those would have tripped these floors.

    Floors, not exact counts: ordinary growth should not cause churn, while a
    collapse in coverage still fails the build. When adding files, raise the
    relevant floor in the same commit. Lowering one to make a build pass is the
    exact move this file exists to prevent -- fix the gate instead.
#>
@{
    Gates = @{

        # *.ps1/*.psm1/*.psd1 analysed, excluding the two documented evidence files.
        # Was 26 while .github/scripts was invisible to the linter; is 28 with it.
        # Set to 28, not lower: a floor of 25 would have let the very regression
        # this file exists to catch sail straight through at 26. A floor has to be
        # tight enough to fail on the actual historical bad value.
        'PSScriptAnalyzer.Files' = 28

        # Total tests executed in one Pester leg.
        'Pester.Tests' = 80

        # Windows-tagged tests. The 5.1 leg once ran 0 of these and passed.
        'Pester.WindowsTagged' = 20

        # Commits gitleaks walked. Falling far below this means the scan was
        # scoped down, which is how a secret scan goes quiet without going clean.
        'Gitleaks.Commits' = 30

        # Tracked files checked for forbidden paths.
        'ForbiddenPath.Files' = 40

        # Markdown files checked for unmet claims.
        'ReadmeClaim.Files' = 6
    }
}
