#Requires -Version 5.1

<#
.SYNOPSIS
    Regenerates the Lab 4 key and ciphertext artifacts locally from throwaway values.

.DESCRIPTION
    The original keyfile.bin, keyfile.txt, password.txt and secret.enc were removed
    from this repository and purged from its history: the AES key was committed
    alongside the ciphertext it decrypted, which made the password recoverable by
    anyone who cloned. See SECURITY.md.

    This script rebuilds equivalent artifacts so the exercise stays reproducible
    without shipping a secret. The demo secret is generated at random on each run
    and is never a real credential, so the output is safe to inspect and pointless
    to steal. The generated files are covered by .gitignore and by the pre-commit
    hook; both will refuse to let them back into the repository.

    Uses ConvertFrom-SecureString -Key (explicit AES) rather than the parameterless
    form, which is DPAPI-backed and therefore Windows-only and machine-bound.

.PARAMETER Path
    Directory to write the artifacts into. Defaults to the script's own directory.

.PARAMETER KeyByteLength
    AES key size in bytes. ConvertFrom-SecureString accepts 16, 24 or 32 only.

.EXAMPLE
    PS> ./generate-lab4-artifacts.ps1
    Writes keyfile.bin, keyfile.txt, secret.enc and password.txt into the script's
    directory and returns a summary object for each.

.EXAMPLE
    PS> ./generate-lab4-artifacts.ps1 -WhatIf
    Reports what would be written without creating anything.

.EXAMPLE
    PS> ./generate-lab4-artifacts.ps1 -Path ./scratch -KeyByteLength 32
    Writes a 32-byte-key variant into ./scratch.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Path = $PSScriptRoot,

    [ValidateSet(16, 24, 32)]
    [int]$KeyByteLength = 16
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path)) {
    if ($PSCmdlet.ShouldProcess($Path, 'Create directory')) {
        $null = New-Item -ItemType Directory -Path $Path -Force
    }
}

$keyBinPath   = Join-Path $Path 'keyfile.bin'
$keyTxtPath   = Join-Path $Path 'keyfile.txt'
$secretPath   = Join-Path $Path 'secret.enc'
$passwordPath = Join-Path $Path 'password.txt'

# Random per run. Nothing here is reused anywhere, so a leak of these files is
# uninteresting -- which is the entire point of generating rather than committing.
$key = [byte[]]::new($KeyByteLength)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)

$demoSecret   = 'demo-secret-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$demoUser     = 'demo-user'
$demoPassword = 'demo-pw-' + [guid]::NewGuid().ToString('N').Substring(0, 12)

$results = [System.Collections.Generic.List[object]]::new()

function AddResult {
    param([string]$File, [string]$Description, [int]$Bytes)
    $results.Add([PSCustomObject]@{
        File        = $File
        Description = $Description
        Bytes       = $Bytes
    })
}

function NewSecureString {
    # Built a character at a time rather than via
    # ConvertTo-SecureString -AsPlainText -Force. The -Force form takes the secret
    # as an ordinary [string], which is immutable and stays in managed memory
    # until the GC happens to collect it. This keeps the value out of a String
    # entirely, which is the practice the lab is meant to demonstrate.
    param([char[]]$Character)
    $secure = [System.Security.SecureString]::new()
    foreach ($c in $Character) { $secure.AppendChar($c) }
    $secure.MakeReadOnly()
    $secure
}

if ($PSCmdlet.ShouldProcess($keyBinPath, 'Write raw AES key')) {
    # WriteAllBytes rather than Set-Content -Encoding Byte: the -Encoding Byte
    # parameter was removed in PowerShell 6+, so the original lab line does not
    # run on anything current.
    [System.IO.File]::WriteAllBytes($keyBinPath, $key)
    AddResult -File $keyBinPath -Description 'Raw AES key' -Bytes $key.Length
}

if ($PSCmdlet.ShouldProcess($keyTxtPath, 'Write decimal-byte AES key')) {
    # The lab also kept the key as one decimal byte per line, which is what
    # Get-Content feeds back to -Key. Same key, second encoding.
    Set-Content -LiteralPath $keyTxtPath -Value $key -Encoding utf8
    AddResult -File $keyTxtPath -Description 'Decimal-byte AES key' `
        -Bytes ((Get-Item -LiteralPath $keyTxtPath).Length)
}

if ($PSCmdlet.ShouldProcess($secretPath, 'Write encrypted SecureString')) {
    $secure = NewSecureString -Character $demoSecret.ToCharArray()
    $cipher = ConvertFrom-SecureString -SecureString $secure -Key $key
    Set-Content -LiteralPath $secretPath -Value $cipher -NoNewline
    AddResult -File $secretPath -Description 'Encrypted SecureString' `
        -Bytes ((Get-Item -LiteralPath $secretPath).Length)
}

if ($PSCmdlet.ShouldProcess($passwordPath, 'Write encrypted credential password')) {
    $securePw = NewSecureString -Character $demoPassword.ToCharArray()
    $cred     = [System.Management.Automation.PSCredential]::new($demoUser, $securePw)
    $cipherPw = ConvertFrom-SecureString -SecureString $cred.Password -Key $key
    Set-Content -LiteralPath $passwordPath -Value $cipherPw -NoNewline
    AddResult -File $passwordPath -Description 'Encrypted credential password' `
        -Bytes ((Get-Item -LiteralPath $passwordPath).Length)
}

$results
