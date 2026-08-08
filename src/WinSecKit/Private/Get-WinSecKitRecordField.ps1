function Get-WinSecKitRecordField {
    <#
        Reads a named field from a record's Data hashtable.

        Private. Exists so Threshold grouping degrades to a single '<unknown>'
        bucket instead of throwing when a record lacks the field, which happens
        with hand-built test records and with events whose schema varies by
        Windows version. Grouping everything into one bucket is conservative: it
        can over-report a burst, never hide one.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][PSObject]$Record,
        [Parameter(Mandatory)][string]$Name
    )

    $data = $null
    if ($Record.PSObject.Properties.Name -contains 'Data') {
        $data = $Record.Data
    }

    if ($data -is [System.Collections.IDictionary] -and $data.Contains($Name)) {
        $value = $data[$Name]
        if ($null -ne $value -and "$value".Trim()) { return "$value" }
    }

    return '<unknown>'
}
