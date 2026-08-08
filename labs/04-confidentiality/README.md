# Lab 4: Confidentiality (PowerShell + X.509)

Hands-on lab demonstrating confidentiality and integrity controls on Windows using PowerShell. You’ll see how to hash and verify files, protect secrets with `SecureString` + AES keys, sign scripts with a self-signed **Code Signing** certificate, and encrypt/decrypt messages with **CMS** (`Protect-CmsMessage` / `Unprotect-CmsMessage`).

> **Author:** Vijaysingh Puwar

---

## What this lab covers

* **File Integrity**

  * Generate hashes with `Get-FileHash` (MD5/SHA-256).
  * Build a tidy two-column “File | Hash” report.
  * Validate a vendor download by comparing the computed hash vs the published hash.

* **Secret Handling**

  * Capture secrets as `SecureString`.
  * Convert to/from AES-encrypted text using explicit 16/24/32-byte keys.
  * Store/load a raw keyfile safely and round-trip decrypt to prove correctness.

* **Script Trust (Code Signing)**

  * Create a **self-signed Code Signing** certificate.
  * Sign a PowerShell script with `Set-AuthenticodeSignature`.
  * Verify signature status and run under stricter execution policies.

* **Public-Key Encryption (CMS)**

  * Generate a **Document Encryption** certificate.
  * Encrypt plaintext with `Protect-CmsMessage` to the cert’s **public key**.
  * Decrypt with `Unprotect-CmsMessage` using the owner’s **private key**.

---

## Contents

```
labs/04-confidentiality/
├─ README.md
├─ scripts/
│  ├─ lab04-transcript.ps1          # The commands as run during the lab
│  └─ generate-lab4-artifacts.ps1   # Regenerates key/ciphertext demo files locally
└─ evidence/
   ├─ myscript.ps1                  # Authenticode-signed script (signature block intact)
   ├─ cyberusr.cer                  # Exported public certificate, no private key
   └─ p1.txt                        # CMS ciphertext encrypted to that certificate
```

`lab04-transcript.ps1` is a record of the session, not a runnable program: it
contains interactive prompts and one `certmgr.msc` launch. The full write-up is
[docs/reports/cyb631-lab4-puwar.pdf](../../docs/reports/cyb631-lab4-puwar.pdf).

The key and ciphertext artifacts the lab produced are deliberately absent —
they were removed and purged from history because the key was committed next to
the ciphertext it decrypted. Run `scripts/generate-lab4-artifacts.ps1` to rebuild
equivalents locally from throwaway values. See [SECURITY.md](../../SECURITY.md).

---

## Quick start

> Run PowerShell **as Administrator**.

### 1) Hashing & report

```powershell
# Create test files
1..5 | ForEach-Object { Set-Content -Path "HashTest$_.txt" -Value "Line $_" }

# Two-column SHA-256 report (sorted)
Get-ChildItem -Filter 'HashTest*.txt' |
  Sort-Object Name |
  ForEach-Object {
    $h = Get-FileHash -Algorithm SHA256 -Path $_.FullName
    '{0,-24} {1}' -f $_.Name, $h.Hash
  } | Tee-Object -FilePath .\evidence\hashes.txt
```

### 2) Verify a download (integrity)

```powershell
$pkgUrl        = 'https://example.com/package.exe'    # replace with actual vendor URL
$publishedHash = 'ABCDEF...1234'                      # paste vendor's SHA-256 (hex)

$wc      = New-Object Net.WebClient
$stream  = $wc.OpenRead($pkgUrl)
$sha256  = [System.Security.Cryptography.SHA256]::Create()
$hex     = -join ($sha256.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') })
$match   = ($hex -ieq $publishedHash)

"Computed : $hex"
"Published: $publishedHash"
"Match    : $match"
$stream.Close()
```

### 3) SecureString + AES key (round-trip)

Use the generator rather than the lab's original commands:

```powershell
./scripts/generate-lab4-artifacts.ps1 -WhatIf   # dry run
./scripts/generate-lab4-artifacts.ps1
```

The original lab commands are not reproduced here, for two reasons.

They no longer run. `Set-Content -Encoding Byte` was removed in PowerShell 6, so
the key-writing line fails on anything current. The generator uses
`[System.IO.File]::WriteAllBytes` instead.

More importantly, the lab's final step printed the decrypted plaintext to the
console to prove the round-trip worked. That is what put a live credential into
Figures 11 and 14 of the report, and the screenshot outlived the exercise by
eleven months. Proving a decrypt succeeded does not require rendering the secret:
compare lengths, compare a hash, or check that `ConvertTo-SecureString` returned
without throwing. The generator emits only file names and byte counts.

### 4) Code signing and 5) CMS

Both are now module functions rather than loose commands, which is the point of
the exercise surviving past the lab:

```powershell
Import-Module ./src/WinSecKit/WinSecKit.psd1

# Audit signatures across a tree -- the supply-chain check the lab implies
Test-ScriptSignature -Path ./src -Recurse | Format-Table FileName, Status, SignerSubject

# Sign, with a dry run first
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Invoke-ScriptSigning -Path ./build -Certificate $cert -WhatIf
```

Reading `Status` correctly matters more than it looks. `Valid` means the file is
unmodified **and** the signing certificate chains to a root trusted on the machine
doing the checking. A self-signed lab certificate never satisfies the second, so
the honest expected result for `evidence/myscript.ps1` is `UnknownError`, not
`Valid` — the signature is intact, the trust is not. `HashMismatch` is the one that
means tampering. Conflating those two is a real bug this module had: idempotency
was keyed on `Valid`, so every run re-signed every file.

The CMS exercise produced `evidence/p1.txt`, encrypted to `cyberusr`'s public key.
It cannot be decrypted from this repository, because the private key never left the
certificate store of the machine that generated it. That is the property being
demonstrated, not a limitation.

## Security notes & gotchas

* **Figures 11 and 14 of the report PDF in this repo were redacted after publication**: both showed a decrypted plaintext credential in console output, and the repo's copy now has that value blacked out in the underlying bitmap — see [SECURITY.md](../../SECURITY.md).
* **Never commit** private keys, `*.pfx`, or raw AES keys (`keyfile.bin`) to Git.
* Export **public** certs only (`.cer`) when sharing for CMS encryption.
* AES keys must be **16/24/32 bytes**; enforce length checks.
* If signature status is `Unknown`, ensure the cert is in the correct store and that you used a **timestamp server**.
* On Windows Server 2022, PowerShell ISE may be missing—prefer **VS Code** or add the ISE feature.

---

## Requirements

* Windows 10/11 or Windows Server 2022 (Admin PowerShell)
* PowerShell 5.1+ (or 7.x with compatible modules)
* Internet access for timestamping and sample download verification

---

## Evidence

* `evidence/myscript.ps1` — signed with `Set-AuthenticodeSignature` and a DigiCert
  timestamp; the signature block is intact, so `Get-AuthenticodeSignature` still
  reports on it. The signer is a self-signed lab certificate, so expect
  `UnknownError` unless that certificate is trusted on the machine checking it.
* `evidence/cyberusr.cer` — exported public certificate, no private key.
* `evidence/p1.txt` — CMS ciphertext encrypted to `cyberusr`. It cannot be
  decrypted from this repository: the private key stayed in the certificate store
  of the machine that generated it, which is the property the exercise
  demonstrates.
