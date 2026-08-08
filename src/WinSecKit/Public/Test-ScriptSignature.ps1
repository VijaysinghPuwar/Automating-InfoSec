function Test-ScriptSignature {
    <#
    .SYNOPSIS
        Reports the Authenticode signature status of PowerShell files.

    .DESCRIPTION
        Turns the one-off signature check from Lab 4 into a supply-chain sweep:
        point it at a tree and it reports which scripts are signed, by whom, and
        whether the signature still validates.

        Status values come from Get-AuthenticodeSignature and are worth reading
        carefully. 'Valid' means the file is unmodified AND the signing
        certificate chains to a trusted root on THIS machine. A self-signed lab
        certificate that has not been imported into the local trust stores yields
        'UnknownError', not 'Valid' -- the signature is intact, the trust is not.
        'HashMismatch' means the file changed after signing, which is the case
        this check exists to catch.

        WINDOWS ONLY. Get-AuthenticodeSignature is not available on macOS or Linux.

    .PARAMETER Path
        Files or directories to check. Directories are searched for *.ps1, *.psm1
        and *.psd1.

    .PARAMETER Recurse
        Recurse into subdirectories.

    .PARAMETER UnsignedOnly
        Emit only files with no signature or an invalid one.

    .EXAMPLE
        PS> Test-ScriptSignature -Path ./src -Recurse | Format-Table FilePath, Status, SignerSubject

        Reports signature status across the module tree.

    .EXAMPLE
        PS> Test-ScriptSignature -Path ./labs -Recurse -UnsignedOnly

        Lists only files that are unsigned or whose signature no longer validates.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string[]]$Path,

        [switch]$Recurse,

        [switch]$UnsignedOnly
    )

    begin {
        if (-not (Get-Command -Name Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
            throw 'Get-AuthenticodeSignature is unavailable. Test-ScriptSignature requires Windows.'
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
                $sig = Get-AuthenticodeSignature -LiteralPath $file.FullName

                $subject   = ''
                $thumb     = ''
                $notAfter  = $null
                if ($sig.SignerCertificate) {
                    $subject  = $sig.SignerCertificate.Subject
                    $thumb    = $sig.SignerCertificate.Thumbprint
                    $notAfter = $sig.SignerCertificate.NotAfter
                }

                $isSigned = ("$($sig.Status)" -ne 'NotSigned')
                $isValid  = ("$($sig.Status)" -eq 'Valid')

                if ($UnsignedOnly -and $isValid) { continue }

                [PSCustomObject]@{
                    PSTypeName        = 'WinSecKit.SignatureResult'
                    FilePath          = $file.FullName
                    FileName          = $file.Name
                    Status            = "$($sig.Status)"
                    StatusMessage     = $sig.StatusMessage
                    IsSigned          = $isSigned
                    IsValid           = $isValid
                    SignerSubject     = $subject
                    Thumbprint        = $thumb
                    CertNotAfter      = $notAfter
                    TimeStamperCert   = $(if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { '' })
                    CheckedAt         = Get-Date
                }
            }
        }
    }
}
