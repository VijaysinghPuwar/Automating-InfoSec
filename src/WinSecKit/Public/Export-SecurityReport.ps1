function Export-SecurityReport {
    <#
    .SYNOPSIS
        Renders result objects to a self-contained HTML report.

    .DESCRIPTION
        Accepts any of this module's result objects -- findings, baseline results,
        remediation results, signature results -- and renders them to a single
        HTML file with no external CSS, fonts or scripts, so it survives being
        emailed as an attachment or opened from a share.

        Columns are derived from the objects themselves rather than hard-coded per
        type, which is why every result object is built through one construction
        site. Property values are HTML-encoded; event log messages contain
        attacker-controlled text and a report that renders it raw is an injection
        vector into whoever opens the report.

        Runs anywhere PowerShell does: it reads objects, not Windows.

    .PARAMETER InputObject
        Result objects to render.

    .PARAMETER Path
        Output HTML file.

    .PARAMETER Title
        Report heading. Defaults to 'Security Report'.

    .PARAMETER PassThru
        Emit the input objects so the report can sit mid-pipeline.

    .EXAMPLE
        PS> Test-SecurityBaseline | Export-SecurityReport -Path baseline.html

        Renders a compliance report.

    .EXAMPLE
        PS> Get-SecurityEventRecord -LogName Security -EventId 4625 |
                Test-SecurityDetection |
                Export-SecurityReport -Path findings.html -Title 'Logon anomalies'

        Renders detection findings.
    #>
    # OutputType is PSObject, not PSCustomObject: the only thing this function
    # emits is the -PassThru echo of whatever came in, which may be any of the
    # module's result types.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]]$InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [string]$Title = 'Security Report',

        [switch]$PassThru
    )

    begin {
        $rows = [System.Collections.Generic.List[PSObject]]::new()
    }

    process {
        foreach ($o in $InputObject) { $rows.Add($o) }
    }

    end {
        if ($rows.Count -eq 0) {
            Write-Warning 'No objects to report; nothing written.'
            return
        }

        # Union of properties across all rows, first-seen order, so a mixed result
        # set does not silently drop the columns of whichever type came second.
        $columns = [System.Collections.Generic.List[string]]::new()
        foreach ($row in $rows) {
            foreach ($prop in $row.PSObject.Properties.Name) {
                if (-not $columns.Contains($prop)) { $columns.Add($prop) }
            }
        }

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
        [void]$sb.AppendLine("<title>$([System.Net.WebUtility]::HtmlEncode($Title))</title>")
        [void]$sb.AppendLine(@'
<style>
 body{font-family:Segoe UI,-apple-system,sans-serif;margin:2rem;color:#1a1a1a;background:#fff}
 h1{font-size:1.4rem;margin:0 0 .25rem}
 .meta{color:#555;font-size:.85rem;margin-bottom:1.5rem}
 table{border-collapse:collapse;width:100%;font-size:.85rem}
 th,td{border:1px solid #d0d0d0;padding:.4rem .6rem;text-align:left;vertical-align:top}
 th{background:#f2f2f2;font-weight:600}
 tr:nth-child(even) td{background:#fafafa}
 td.f{color:#8a1f11;font-weight:600}
 td.t{color:#1a6b2f;font-weight:600}
 .wrap{max-width:60ch;overflow-wrap:anywhere}
 @media print{body{margin:0}}
</style></head><body>
'@)
        [void]$sb.AppendLine("<h1>$([System.Net.WebUtility]::HtmlEncode($Title))</h1>")
        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
        [void]$sb.AppendLine("<p class=""meta"">$($rows.Count) row(s) &middot; generated $stamp &middot; $env:COMPUTERNAME</p>")
        [void]$sb.AppendLine('<table><thead><tr>')
        foreach ($c in $columns) {
            [void]$sb.Append("<th>$([System.Net.WebUtility]::HtmlEncode($c))</th>")
        }
        [void]$sb.AppendLine('</tr></thead><tbody>')

        foreach ($row in $rows) {
            [void]$sb.Append('<tr>')
            foreach ($c in $columns) {
                $value = ''
                if ($row.PSObject.Properties.Name -contains $c) {
                    $raw = $row.$c
                    if ($raw -is [System.Collections.IEnumerable] -and $raw -isnot [string]) {
                        $value = ($raw | ForEach-Object { "$_" }) -join ', '
                    }
                    else {
                        $value = "$raw"
                    }
                }

                # Colour only the booleans that carry a pass/fail meaning.
                $class = ''
                if ($c -in @('Compliant', 'IsValid') -and $value -eq 'True')  { $class = ' class="t"' }
                if ($c -in @('Compliant', 'IsValid') -and $value -eq 'False') { $class = ' class="f"' }
                if ($c -eq 'Evidence' -or $c -eq 'Detail') { $class = ' class="wrap"' }

                [void]$sb.Append("<td$class>$([System.Net.WebUtility]::HtmlEncode($value))</td>")
            }
            [void]$sb.AppendLine('</tr>')
        }

        [void]$sb.AppendLine('</tbody></table></body></html>')

        if ($PSCmdlet.ShouldProcess($Path, 'Write HTML report')) {
            Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
            Write-Verbose "Wrote $($rows.Count) row(s) to $Path"
        }

        # Emitted one at a time rather than as the List. PowerShell unrolls a
        # collection on output either way, but emitting the elements is what makes
        # the declared OutputType statically true rather than incidentally true.
        if ($PassThru) {
            foreach ($row in $rows) { $row }
        }
    }
}
