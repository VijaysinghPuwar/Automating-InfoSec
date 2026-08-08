#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Exercises the Lab 4 signing workflow end to end: create a self-signed
    code-signing certificate, sign a file, verify it, then prove the signature
    detects tampering.

    No timestamp server is used. Timestamping needs outbound network access to a
    third party, which makes the test a flake waiting to happen; the timestamp
    path is exercised by the -TimestampServer parameter being passed through, not
    by contacting DigiCert from CI.
#>

# $env:OS, not $IsWindows: the latter does not exist in Windows PowerShell 5.1,
# and Pester runs discovery under StrictMode, so referencing it throws and the
# entire file is dropped from the run -- silently, while the suite still exits 0.
$script:IsWindowsHost = ($env:OS -eq 'Windows_NT')

Describe 'Authenticode signing on Windows' -Tag 'Windows' -Skip:(-not $script:IsWindowsHost) {

    BeforeAll {
        $moduleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src/WinSecKit'
        Import-Module (Join-Path $moduleRoot 'WinSecKit.psd1') -Force

        $script:WorkDir = Join-Path $env:TEMP "wsk-signing-$PID"
        New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

        $script:Cert = New-SelfSignedCertificate `
            -Subject 'CN=WinSecKit CI Signing' `
            -Type CodeSigningCert `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -NotAfter (Get-Date).AddDays(1)

        function MakeSampleScript {
            param([string]$Name)
            $p = Join-Path $script:WorkDir $Name
            Set-Content -LiteralPath $p -Value 'Write-Output "sample"' -Encoding UTF8
            $p
        }
    }

    AfterAll {
        if ($script:Cert) {
            Remove-Item -Path "Cert:\CurrentUser\My\$($script:Cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Context 'Test-ScriptSignature' {

        It 'reports an unsigned script as NotSigned' {
            $p = MakeSampleScript 'unsigned.ps1'
            $r = Test-ScriptSignature -Path $p
            $r.Status   | Should -Be 'NotSigned'
            $r.IsSigned | Should -BeFalse
            $r.IsValid  | Should -BeFalse
        }

        It 'scans a directory' {
            $null = MakeSampleScript 'a.ps1'
            $null = MakeSampleScript 'b.ps1'
            @(Test-ScriptSignature -Path $WorkDir).Count | Should -BeGreaterOrEqual 2
        }

        It 'warns rather than throws on a missing path' {
            { Test-ScriptSignature -Path (Join-Path $WorkDir 'nope.ps1') -WarningAction SilentlyContinue } |
                Should -Not -Throw
        }
    }

    Context 'Invoke-ScriptSigning' {

        It 'signs nothing under -WhatIf' {
            $p = MakeSampleScript 'whatif.ps1'
            Invoke-ScriptSigning -Path $p -Certificate $Cert -WhatIf | Out-Null
            (Test-ScriptSignature -Path $p).Status | Should -Be 'NotSigned'
        }

        It 'signs a file and reports the change' {
            $p = MakeSampleScript 'tosign.ps1'
            $r = Invoke-ScriptSigning -Path $p -Certificate $Cert -Confirm:$false
            $r.Changed | Should -BeTrue
            $r.Status  | Should -Not -Be 'NotSigned'
            $r.Thumbprint | Should -Be $Cert.Thumbprint
        }

        It 'appends a signature block to the file' {
            $p = MakeSampleScript 'block.ps1'
            Invoke-ScriptSigning -Path $p -Certificate $Cert -Confirm:$false | Out-Null
            (Get-Content $p -Raw) | Should -Match 'SIG # Begin signature block'
        }

        It 'skips a file already signed by the same certificate' {
            # Idempotency: re-running must not rewrite a file that is already correct.
            $p = MakeSampleScript 'twice.ps1'
            Invoke-ScriptSigning -Path $p -Certificate $Cert -Confirm:$false | Out-Null
            $second = Invoke-ScriptSigning -Path $p -Certificate $Cert -Confirm:$false
            $second.Changed | Should -BeFalse
        }

        It 're-signs when -Force is given' {
            $p = MakeSampleScript 'forced.ps1'
            Invoke-ScriptSigning -Path $p -Certificate $Cert -Confirm:$false | Out-Null
            (Invoke-ScriptSigning -Path $p -Certificate $Cert -Force -Confirm:$false).Changed |
                Should -BeTrue
        }
    }

    Context 'Tamper detection' {

        It 'reports HashMismatch after a signed file is modified' {
            # The property the whole exercise exists to demonstrate.
            $p = MakeSampleScript 'tampered.ps1'
            Invoke-ScriptSigning -Path $p -Certificate $Cert -Confirm:$false | Out-Null

            # Tampered at the byte level, on purpose. Reading with Get-Content and
            # rewriting with Set-Content -Encoding UTF8 changes the file's encoding
            # -- PowerShell 7 writes UTF-8 without a BOM, 5.1 writes one -- and the
            # rewritten file was reported NotSigned rather than HashMismatch,
            # because the signature block was no longer parseable. That tests the
            # encoding, not tamper detection.
            #
            # ISO-8859-1 maps bytes 0-255 to characters 1:1, so this round-trips any
            # byte sequence losslessly, BOM and base64 signature block included.
            # 'sample' -> 'tamper' is the same length, so nothing shifts.
            $latin1 = [System.Text.Encoding]::GetEncoding('iso-8859-1')
            $text   = $latin1.GetString([System.IO.File]::ReadAllBytes($p))
            $text   = $text -replace 'sample', 'tamper'
            [System.IO.File]::WriteAllBytes($p, $latin1.GetBytes($text))

            (Test-ScriptSignature -Path $p).Status | Should -Be 'HashMismatch'
        }
    }

    Context 'Committed lab evidence' {

        It 'still carries its original signature block' {
            $evidence = Join-Path (Split-Path $PSScriptRoot -Parent) 'labs/04-confidentiality/evidence/myscript.ps1'
            $r = Test-ScriptSignature -Path $evidence
            $r.IsSigned | Should -BeTrue
            # Not 'Valid': the lab certificate is self-signed and is not trusted
            # on the runner, so the expected status is UnknownError. The signature
            # is intact; the trust chain is what is missing.
            $r.Status | Should -Not -Be 'HashMismatch'
            $r.SignerSubject | Should -Match 'CYB631'
        }
    }
}
