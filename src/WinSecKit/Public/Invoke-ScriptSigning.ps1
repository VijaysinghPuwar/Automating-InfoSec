function Invoke-ScriptSigning {
    <#
    .SYNOPSIS
        Signs PowerShell files with an Authenticode code-signing certificate.

    .DESCRIPTION
        The write half of the Lab 4 signing exercise. Signs each file with
        Set-AuthenticodeSignature and re-checks the result, so a reported success
        means the signature was verified after writing rather than assumed from a
        lack of exception.

        Idempotent in the sense that matters: a file already carrying a valid
        signature from the same certificate is skipped and reported with
        Changed = $false. Pass -Force to re-sign regardless.

        Timestamping is optional and off by default because it requires outbound
        network access. Without it a signature stops validating once the signing
        certificate expires; with it the signature remains valid for files signed
        while the certificate was current.

        WINDOWS ONLY, and gated on ShouldProcess: -WhatIf signs nothing.

    .PARAMETER Path
        Files to sign, or directories to search for *.ps1, *.psm1 and *.psd1.

    .PARAMETER Certificate
        Code-signing certificate. Get one with
        Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert.

    .PARAMETER TimestampServer
        Optional RFC 3161 timestamp URL, e.g. http://timestamp.digicert.com.

    .PARAMETER Recurse
        Recurse into subdirectories.

    .PARAMETER Force
        Re-sign files that already carry a valid signature.

    .EXAMPLE
        PS> $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
        PS> Invoke-ScriptSigning -Path ./build -Certificate $cert -WhatIf

        Reports which files would be signed without writing to any of them.

    .EXAMPLE
        PS> Invoke-ScriptSigning -Path ./build/deploy.ps1 -Certificate $cert `
                -TimestampServer http://timestamp.digicert.com

        Signs one file and timestamps it.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string[]]$Path,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [string]$TimestampServer,

        [switch]$Recurse,

        [switch]$Force
    )

    begin {
        if (-not (Get-Command -Name Set-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
            throw 'Set-AuthenticodeSignature is unavailable. Invoke-ScriptSigning requires Windows.'
        }
        $extensions = @('.ps1', '.psm1', '.psd1')
    }

    process {
        foreach ($p in $Path) {
            if (-not (Test-Path -LiteralPath $p)) {
                Write-Warning "Path not found: $p"
                continue
            }

            $files = @()
            if (Test-Path -LiteralPath $p -PathType Container) {
                $files = Get-ChildItem -LiteralPath $p -File -Recurse:$Recurse |
                    Where-Object { $_.Extension -in $extensions }
            }
            else {
                $files = @(Get-Item -LiteralPath $p)
            }

            foreach ($file in $files) {
                $before  = Get-AuthenticodeSignature -LiteralPath $file.FullName
                $changed = $false
                $err     = ''

                # Intact and signed by this certificate -- deliberately NOT
                # "Status -eq 'Valid'". Valid additionally requires the signing
                # certificate to chain to a trusted root on this machine, which a
                # self-signed certificate never does, so keying idempotency on it
                # meant every run re-signed every file. Trust is a property of the
                # verifying machine; whether this file already carries this
                # signature is a property of the file.
                $intact = ("$($before.Status)" -notin @('NotSigned', 'HashMismatch'))
                $alreadyGood = ($intact -and
                                $before.SignerCertificate -and
                                $before.SignerCertificate.Thumbprint -eq $Certificate.Thumbprint)

                if ($alreadyGood -and -not $Force) {
                    Write-Verbose "Already signed by this certificate, skipping: $($file.Name)"
                }
                elseif ($PSCmdlet.ShouldProcess($file.FullName, 'Apply Authenticode signature')) {
                    try {
                        $params = @{
                            LiteralPath = $file.FullName
                            Certificate = $Certificate
                            ErrorAction = 'Stop'
                        }
                        if ($TimestampServer) { $params['TimestampServer'] = $TimestampServer }

                        $null = Set-AuthenticodeSignature @params
                        $changed = $true
                    }
                    catch {
                        $err = "$_"
                        Write-Error "Failed to sign $($file.FullName): $_"
                    }
                }

                # Re-read rather than trusting the return value of the setter.
                $after = Get-AuthenticodeSignature -LiteralPath $file.FullName

                [PSCustomObject]@{
                    PSTypeName    = 'WinSecKit.SigningResult'
                    FilePath      = $file.FullName
                    FileName      = $file.Name
                    Changed       = $changed
                    Status        = "$($after.Status)"
                    IsValid       = ("$($after.Status)" -eq 'Valid')
                    SignerSubject = $(if ($after.SignerCertificate) { $after.SignerCertificate.Subject } else { '' })
                    Thumbprint    = $(if ($after.SignerCertificate) { $after.SignerCertificate.Thumbprint } else { '' })
                    Timestamped   = [bool]$after.TimeStamperCertificate
                    Error         = $err
                    SignedAt      = Get-Date
                }
            }
        }
    }
}
