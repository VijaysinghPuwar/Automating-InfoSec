$wc = [System.Net.WebClient]::new()
$pkgurl = 'https://github.com/PowerShell/PowerShell/releases/download/v6.2.4/powershell_6.2.4-1.debian.9_amd64.deb'
$publishedHash = '8E28E54D601F0751922DE24632C1E716B4684876255CF82304A9B19E89A9CCAC'

$FileHash = Get-FileHash -InputStream ($wc.OpenRead($pkgurl))


$result = $FileHash.Hash -eq $publishedHash
Write-Host "The result of file intergrity check is ", $result


$secure = Read-Host -AsSecureString
$secure

$encrypted = ConvertFrom-SecureString -SecureString $secure
$encrypted

$decrypted = $encrypted | ConvertTo-SecureString
$decrypted

$bstr     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$unsecure = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
$unsecure



[Byte[]]$key = (1..16)
$encryptedwithkey = $secure | ConvertFrom-SecureString -Key $key
$encryptedwithkey




# === Generate a 16-byte AES key and save as raw bytes ===
$rkey = New-Object byte[] 16
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rkey)
Set-Content -Path .\keyfile.bin -Value $rkey -Encoding Byte   # <-- raw bytes

# === Read the key back as bytes (must be 16/24/32) ===
[byte[]]$keyIn = Get-Content -Path .\keyfile.bin -Encoding Byte
if ($keyIn.Length -notin 16,24,32) { throw "Key must be 16, 24, or 32 bytes." }

# === Encrypt your SecureString with the key ===
$cipher = ConvertFrom-SecureString -SecureString $secure -Key $keyIn
Set-Content -Path .\secret.enc -Value $cipher -NoNewline       # avoid extra newline/BOM

# === Decrypt back to SecureString with the same key ===
$secure2 = Get-Content -Path .\secret.enc -Raw | ConvertTo-SecureString -Key $keyIn

# === (Optional) show plaintext to prove success ===
$bstr2     = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure2)
$plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr2)
Write-Host "Decrypted plaintext: $plaintext"







$mycred = Get-Credential
$mycred


$mycred = Get-Credential
$mycred

$kfile = ".\keyfile.txt"
$mycred.Password | ConvertFrom-SecureString -Key (Get-Content $kfile) | Out-File ".\password.txt"
[byte[]]$keyIn = Get-Content ".\keyfile.bin" -Encoding Byte
$mycred.Password | ConvertFrom-SecureString -Key $keyIn | Set-Content ".\password.txt" -NoNewline



$selfcert = New-SelfSignedCertificate -Subject "CYB631 Authentication" -CertStoreLocation Cert:\LocalMachine\My -Type CodeSigningCert


$rootstore = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root","LocalMachine")
$rootstore.Open("ReadWrite")
$rootstore.Add($selfcert)
$rootstore.Close()

$publisherstore = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPublisher","LocalMachine")
$publisherstore.Open("ReadWrite")
$publisherstore.Add($selfcert)
$publisherstore.Close()


certmgr.msc


Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=CYB631 Authentication" }
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -eq "CN=CYB631 Authentication" }
Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Subject -eq "CN=CYB631 Authentication" }


Write-Host "I am on cloud nine!"


$codecertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=CYB631 Authentication" }
$codecertificate

Set-AuthenticodeSignature -FilePath .\myscript.ps1 -Certificate $codecertificate -TimestampServer http://timestamp.digicert.com






$codecertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=CYB631 Authentication" }
$codecertificate

Set-AuthenticodeSignature -FilePath .\myscript.ps1 -Certificate $codecertificate -TimestampServer http://timestamp.digicert.com




# Grab exactly one cert (pick the newest if duplicates exist)
$codecertificate = Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.Subject -eq "CN=CYB631 Authentication" } |
  Sort-Object NotBefore -Descending |
  Select-Object -First 1

# Confirm it's a single cert
$codecertificate | Format-List Subject, Thumbprint, NotBefore, NotAfter

# Sign the script
Set-AuthenticodeSignature -FilePath .\myscript.ps1 -Certificate $codecertificate -TimestampServer http://timestamp.digicert.com



notepad .\myscript.ps1

Get-AuthenticodeSignature -FilePath .\myscript.ps1 | Select-Object Status, StatusMessage, SignerCertificate

.\myscript.ps1


# See what's enforcing the block
Get-ExecutionPolicy -List

# Allow only signed scripts for THIS PowerShell session (safest for the lab)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy AllSigned -Force

# (If the file was downloaded or copied from the internet, clear Zone.Identifier)
Unblock-File .\myscript.ps1

# Run again
.\myscript.ps1


powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\myscript.ps1






New-SelfSignedCertificate -DnsName cyberusr -CertStoreLocation "cert:\CurrentUser\My" -KeyUsage KeyEncipherment, DataEncipherment, KeyAgreement -Type DocumentEncryptionCert



Get-ChildItem -Path Cert:\CurrentUser\My -DocumentEncryptionCert

"This is a secret!" | Protect-CmsMessage -To CN=cyberusr -OutFile p1.txt


$encCert = Get-ChildItem Cert:\CurrentUser\My -DocumentEncryptionCert | Where-Object { $_.Subject -eq "CN=cyberusr" }
Export-Certificate -Cert $encCert -FilePath .\cyberusr.cer


Unprotect-CmsMessage -Path p1.txt




$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=cyberusr" }

$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root","CurrentUser"
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close()


