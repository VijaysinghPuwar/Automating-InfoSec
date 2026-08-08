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

```powershell
# Prompt secret
$secure = Read-Host "Enter secret" -AsSecureString

# Generate a 16-byte key and save as raw bytes
$rkey = New-Object byte[] 16
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rkey)
Set-Content .\keyfile.bin -Value $rkey -Encoding Byte

# Encrypt SecureString with explicit key
[byte[]]$keyIn = Get-Content .\keyfile.bin -Encoding Byte
$cipher = ConvertFrom-SecureString -SecureString $secure -Key $keyIn
Set-Content .\secret.enc -Value $cipher -NoNewline

# Decrypt back
$secure2  = Get-Content .\secret.enc -Raw | ConvertTo-SecureString -Key $keyIn
$bstr2    = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure2)
$plain    = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr2)
"Decrypted plaintext: $plain"
```

### 4) Code signing

```powershell
# Create a Code Signing cert
$cert = New-SelfSignedCertificate -Subject "CN=CYB631 Code Signing" `
  -Type CodeSigningCert -CertStoreLocation "Cert:\CurrentUser\My"

# Sign a script and timestamp it (internet required)
Set-AuthenticodeSignature .\scripts\sign_me.ps1 $cert `
  -TimestampServer http://timestamp.digicert.com

# Verify signature
Get-AuthenticodeSignature .\scripts\sign_me.ps1
```

### 5) CMS encryption (public key)

```powershell
# Make a Document Encryption certificate
$cms = New-SelfSignedCertificate -DnsName 'cyberusr' `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyUsage KeyEncipherment,DataEncipherment,KeyAgreement `
  -Type DocumentEncryptionCert

# Encrypt to public key → p1.txt
"This is a secret!" | Protect-CmsMessage -To $cms -OutFile .\evidence\p1.txt

# Decrypt (must be same profile that holds the private key)
Unprotect-CmsMessage -Path .\evidence\p1.txt
```

---

## Learning outcomes

* Explain where hashing fits in **integrity** controls and prove equality via SHA-256.
* Compare **DPAPI-style** implicit encryption vs explicit AES key management.
* Understand Windows **execution policies**, script signing, and trust chains.
* Apply **public-key cryptography** for at-rest/in-transit confidentiality with CMS.
* Document security tasks with **reproducible commands** and concise evidence.

---

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
