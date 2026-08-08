function ConvertTo-WinSecKitFinding {
    <#
        Builds the finding object emitted by Test-SecurityDetection.

        Private: one construction site means every finding carries the same
        property set, which is what lets Export-SecurityReport render a mixed
        result set without special-casing per detection.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][PSObject]$Detection,
        [Parameter(Mandatory)][int]$Count,
        [datetime]$FirstSeen,
        [datetime]$LastSeen,
        [string]$MachineName,
        [string]$Key,
        [string]$Evidence
    )

    # Event messages can run to several KB and are rendered into HTML reports.
    $trimmed = $Evidence
    if ($trimmed -and $trimmed.Length -gt 500) {
        $trimmed = $trimmed.Substring(0, 500) + '...'
    }

    [PSCustomObject]@{
        PSTypeName    = 'WinSecKit.Finding'
        DetectionId   = $Detection.Id
        Name          = $Detection.Name
        Severity      = $Detection.Severity
        Technique     = $Detection.Technique
        TechniqueName = $Detection.TechniqueName
        LogName       = $Detection.LogName
        Key           = $Key
        Count         = $Count
        FirstSeen     = $FirstSeen
        LastSeen      = $LastSeen
        MachineName   = $MachineName
        Evidence      = $trimmed
    }
}
