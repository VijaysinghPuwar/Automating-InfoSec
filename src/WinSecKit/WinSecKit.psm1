#Requires -Version 5.1

Set-StrictMode -Version Latest

# Public functions resolve their data files against this rather than $PSScriptRoot,
# which inside a dot-sourced file points at Public/ instead of the module root.
$script:ModuleRoot = $PSScriptRoot

$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)
$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to import $($file.FullName): $_"
    }
}

Export-ModuleMember -Function $public.BaseName
