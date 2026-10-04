#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# $env:OS, not $IsWindows: the latter does not exist in Windows PowerShell 5.1.
$script:IsWindowsHost = ($env:OS -eq 'Windows_NT')

BeforeAll {
    $moduleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src/WinSecKit'
    Import-Module (Join-Path $moduleRoot 'WinSecKit.psd1') -Force
}

Describe 'EventData parsing' {

    It 'keeps every named field when one of them is empty' {
        # An empty <Data/> element made the old parser throw under StrictMode
        # and drop every field after it. TargetUserName is the WSK0001 group key.
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4625</EventID></System>
  <EventData>
    <Data Name="SubjectUserName">-</Data>
    <Data Name="SubjectDomainName"/>
    <Data Name="TargetUserName">bob</Data>
  </EventData>
</Event>
'@
        $data = InModuleScope WinSecKit -Parameters @{ X = $xml } { param($X) ConvertFrom-WinSecKitEventXml -Xml $X }
        $data.Count | Should -Be 3
        $data['TargetUserName'] | Should -Be 'bob'
        $data['SubjectDomainName'] | Should -Be ''
    }

    It 'reads a single named field' {
        # PowerShell's XML adapter returns a string, not an element, for one child.
        $xml = '<Event><EventData><Data Name="ServiceName">evil</Data></EventData></Event>'
        $data = InModuleScope WinSecKit -Parameters @{ X = $xml } { param($X) ConvertFrom-WinSecKitEventXml -Xml $X }
        $data['ServiceName'] | Should -Be 'evil'
    }

    It 'ignores unnamed fields and events without EventData' {
        $xml = '<Event><EventData><Data>a</Data><Data>b</Data></EventData></Event>'
        $data = InModuleScope WinSecKit -Parameters @{ X = $xml } { param($X) ConvertFrom-WinSecKitEventXml -Xml $X }
        $data.Count | Should -Be 0
        $empty = InModuleScope WinSecKit { ConvertFrom-WinSecKitEventXml -Xml '<Event><UserData/></Event>' }
        $empty.Count | Should -Be 0
    }
}

Describe 'Get-SecurityEventRecord query building' -Tag 'Windows' -Skip:(-not $script:IsWindowsHost) {

    It 'scopes the StartTime predicate to TimeCreated' {
        # @SystemTime lives on TimeCreated. Unscoped, the filter matched nothing.
        Mock Get-WinEvent -ModuleName WinSecKit { }
        Get-SecurityEventRecord -LogName System -StartTime (Get-Date).AddHours(-1)
        Should -Invoke Get-WinEvent -ModuleName WinSecKit -Times 1 -ParameterFilter {
            $FilterXPath -match 'TimeCreated\[timediff\(@SystemTime\) <= \d+\]'
        }
    }

    It 'treats a localized no-events error as an empty result' {
        # Matched on the error id. The message text differs per Windows language.
        Mock Get-WinEvent -ModuleName WinSecKit {
            throw [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('Es wurden keine Ereignisse gefunden.'),
                'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand',
                [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
        }
        @(Get-SecurityEventRecord -LogName System -EventId 1).Count | Should -Be 0
    }

    It 'still throws on a real error' {
        Mock Get-WinEvent -ModuleName WinSecKit { throw 'access denied' }
        { Get-SecurityEventRecord -LogName Security } | Should -Throw
    }
}
