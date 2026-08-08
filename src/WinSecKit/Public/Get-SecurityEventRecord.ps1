function Get-SecurityEventRecord {
    <#
    .SYNOPSIS
        Reads Windows event log records and normalizes them for Test-SecurityDetection.

    .DESCRIPTION
        Wraps Get-WinEvent and flattens each record's EventData into a Data
        hashtable keyed by the schema's field names, so downstream logic can ask
        for 'TargetUserName' rather than indexing Properties[5] and hoping the
        schema did not shift between Windows versions.

        Get-WinEvent rather than Get-EventLog: Get-EventLog reads only the classic
        logs, so it cannot see Microsoft-Windows-PowerShell/Operational at all,
        which two of the detections depend on. It was also removed in PowerShell 6,
        so code built on it cannot run on 7. Get-WinEvent additionally pushes
        filtering into the event log service via XPath instead of returning every
        record for client-side filtering, which is the difference between a
        bounded query and reading an entire Security log over the wire.

        WINDOWS ONLY. Get-WinEvent does not exist on macOS or Linux. Reading the
        Security log additionally requires an elevated session.

    .PARAMETER LogName
        Log to read, e.g. Security, System, Microsoft-Windows-PowerShell/Operational.

    .PARAMETER EventId
        Event ids to return. Compiled into an XPath predicate so the filtering
        happens in the log service.

    .PARAMETER MaxEvents
        Cap on records returned. Defaults to 1000.

    .PARAMETER StartTime
        Only return records at or after this time.

    .EXAMPLE
        PS> Get-SecurityEventRecord -LogName Security -EventId 4625 -MaxEvents 500

        Returns up to 500 failed-logon records with named fields flattened.

    .EXAMPLE
        PS> Get-SecurityEventRecord -LogName Security -StartTime (Get-Date).AddHours(-1) |
                Test-SecurityDetection

        Evaluates the last hour of Security events against every detection.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$LogName,

        [int[]]$EventId,

        [ValidateRange(1, 1000000)]
        [int]$MaxEvents = 1000,

        [datetime]$StartTime
    )

    begin {
        if (-not (Get-Command -Name Get-WinEvent -ErrorAction SilentlyContinue)) {
            throw 'Get-WinEvent is unavailable. Get-SecurityEventRecord requires Windows.'
        }
    }

    process {
        $predicates = [System.Collections.Generic.List[string]]::new()

        if ($EventId) {
            $ids = ($EventId | ForEach-Object { "EventID=$_" }) -join ' or '
            $predicates.Add("($ids)")
        }

        if ($PSBoundParameters.ContainsKey('StartTime')) {
            # XPath timediff works in milliseconds relative to now.
            $ms = [int64]((Get-Date) - $StartTime).TotalMilliseconds
            if ($ms -lt 0) { $ms = 0 }
            $predicates.Add("timediff(@SystemTime) <= $ms")
        }

        $xpath = '*'
        if ($predicates.Count) {
            $xpath = '*[System[' + ($predicates -join ' and ') + ']]'
        }

        Write-Verbose "XPath: $xpath"

        $params = @{
            LogName     = $LogName
            FilterXPath = $xpath
            MaxEvents   = $MaxEvents
            ErrorAction = 'Stop'
        }

        try {
            $events = Get-WinEvent @params
        }
        catch [System.Exception] {
            # 'No events were found' is a normal empty result, not a failure.
            if ($_.Exception.Message -match 'No events were found') {
                Write-Verbose "No events matched in '$LogName'."
                return
            }
            throw
        }

        foreach ($e in $events) {
            $data = @{}
            try {
                $xml = [xml]$e.ToXml()
                foreach ($node in $xml.Event.EventData.Data) {
                    if ($node.Name) { $data[$node.Name] = $node.'#text' }
                }
            }
            catch {
                # Some providers emit EventData without a named schema. The record
                # is still usable for Presence and Content detections; only
                # Threshold grouping degrades, which Get-WinSecKitRecordField handles.
                Write-Verbose "Could not parse EventData for record $($e.RecordId): $_"
            }

            [PSCustomObject]@{
                PSTypeName   = 'WinSecKit.EventRecord'
                TimeCreated  = $e.TimeCreated
                Id           = $e.Id
                LogName      = $e.LogName
                MachineName  = $e.MachineName
                ProviderName = $e.ProviderName
                RecordId     = $e.RecordId
                Message      = $e.Message
                Data         = $data
            }
        }
    }
}
