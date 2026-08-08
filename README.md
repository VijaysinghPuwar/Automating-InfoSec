# Automating InfoSec

Windows security automation in PowerShell, with the lab reports that produced it.

This began as coursework for Pace University CYB 631: four labs covering PowerShell
fundamentals, Security event log analysis, host hardening, and confidentiality
controls. The reports under `docs/reports/` are the graded submissions and are kept
unmodified, apart from one redaction described below. Everything under `tools/` and
`labs/*/scripts/` is code, and is expected to run.

## Repository layout

```
labs/
  01-powershell-fundamentals/   README + the handle-counting script
  02-log-analysis/              README (report only; no scripts were committed)
  03-host-hardening/            README (report only; no scripts were committed)
  04-confidentiality/           README, lab transcript, artifact generator, signed evidence
docs/
  reports/                      The four graded lab reports, one copy each
  engineering-notes.md          Failure modes worth writing down
tools/                          Repository checks that run in CI and pre-commit
SECURITY.md                     A credential was leaked here; what happened and what stops it
```

Labs 2 and 3 have no scripts. That is not an oversight in this README — the scripts
those reports describe were never committed, and each lab README says so plainly
rather than listing files that do not exist.

## Security tooling

A previous version of this repository committed an AES key alongside the ciphertext
it decrypted, which made the password trivially recoverable by anyone who cloned it.
The credentials have been rotated and the artifacts purged from history. Three
controls now prevent a recurrence, described in [SECURITY.md](SECURITY.md).

To enable them locally:

```bash
git config core.hooksPath .githooks
brew install gitleaks
```

The path guard refuses key material by filename, which is the only way to catch it —
a raw 16-byte AES key has no content signature to match on:

```
$ ./tools/Test-ForbiddenPath.ps1

Path        Pattern
----        -------
keyfile.bin (^|/)keyfile\.[^/]+$
secret.enc  (^|/)secret\.enc$

2 forbidden path(s) tracked. See SECURITY.md.
$ echo $?
1
```

gitleaks covers the other half — content — and catches an exported credential even
after it has been renamed to something innocuous.

## Reproducing Lab 4 without secrets

```powershell
./labs/04-confidentiality/scripts/generate-lab4-artifacts.ps1 -WhatIf   # dry run
./labs/04-confidentiality/scripts/generate-lab4-artifacts.ps1
```

Generates a fresh AES key and matching ciphertext from values invented at random per
run, so the exercise stays reproducible without anything sensitive entering the
repository. The files it writes are ignored and blocked by the pre-commit hook.

## Requirements

Windows PowerShell 5.1 or later on Windows. The lab material uses `Get-WinEvent`,
the `NetSecurity` cmdlets, and Authenticode, none of which exist on macOS or Linux.
`tools/Test-ForbiddenPath.ps1` is the exception and runs anywhere PowerShell does.

## A note on the reports

Figures 11 and 14 of the Lab 4 report showed a decrypted plaintext credential in
console output. This repository's copy has that value blacked out in the underlying
bitmap. The graded submission to Pace was made before the redaction and is
unaffected. No other content in any report was altered.

## License

[MIT](LICENSE) for the code. The lab reports are academic coursework and are not
covered by it.
