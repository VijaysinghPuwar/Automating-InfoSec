function ConvertFrom-WinSecKitEventXml {
    <#
        Flattens an event's EventData into a hashtable keyed by field name.

        Private. Split out of Get-SecurityEventRecord so the parsing can be tested
        against synthetic XML on any platform.

        Uses the DOM (GetAttribute, InnerText) rather than PowerShell's XML
        property adapter. Under StrictMode the adapter throws on an empty
        <Data Name='X'/> element because it has no '#text' property, which
        aborted the loop and dropped every later field. It also returns a plain
        string instead of an element when EventData has a single child.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Xml
    )

    $data = @{}
    if (-not $Xml) { return $data }

    $doc = [xml]$Xml
    foreach ($eventData in $doc.GetElementsByTagName('EventData')) {
        foreach ($node in $eventData.ChildNodes) {
            if ($node -isnot [System.Xml.XmlElement]) { continue }
            $name = $node.GetAttribute('Name')
            if ($name) { $data[$name] = $node.InnerText }
        }
    }

    return $data
}
