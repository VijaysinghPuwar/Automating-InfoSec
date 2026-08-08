<#
    PSScriptAnalyzer configuration.

    No rules are disabled and no findings are suppressed. Two files are excluded
    from analysis entirely, because neither can be edited without destroying what
    it is committed to prove:

      labs/04-confidentiality/evidence/myscript.ps1
          Carries an Authenticode signature. Changing a single byte -- including
          replacing its Write-Host -- invalidates the signature, and a test in
          tests/Signing.Windows.Tests.ps1 asserts that signature is still intact.
          Linting it would mean choosing between a clean report and the evidence.

      labs/04-confidentiality/scripts/lab04-transcript.ps1
          A verbatim record of the commands run during the lab, kept to match the
          graded report. Editing it to satisfy a linter would falsify the record.

    Everything else in the repository is analysed, and findings are fixed rather
    than excluded. If a third file ever appears here, it needs the same kind of
    justification.
#>
@{
    ExcludeRules = @()

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
