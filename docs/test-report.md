# Test report: Windows verification

Date: 2026-10-04

The module was run on a real Windows 11 machine and on GitHub's Windows CI runners.
This found 10 bugs. All 10 are fixed, and each fix has a test that fails on the old code.

Host names, user names, SIDs and file paths are left out of this report on purpose.

## Summary

| | Before | After |
|---|---|---|
| Pester tests per PowerShell version (CI) | 88 passed | 103 passed |
| Windows-only tests (CI) | 26 | 30 |
| PSScriptAnalyzer findings | 0 in 30 files | 0 in 33 files |
| Repo check scripts on Windows PowerShell 5.1 | Not run | Run in CI |
| gitleaks over full history | no leaks | no leaks |
| Known bugs | 10 | 0 |

## Where it was tested

| | Local Windows machine | GitHub CI runner |
|---|---|---|
| OS | Windows 11 Pro, build 26200 | windows-latest |
| PowerShell | 5.1.26100 and 7.6.6 | 5.1 and 7 |
| Pester | 5.7.1 (also 6.2.0) | 5.7.1 |
| Elevated | No | Yes |
| Tests run | Everything that does not change the machine | Everything, including tests that write the registry, firewall and certificate store |

The local machine was not changed. Nothing was installed. PowerShell 7, Pester 5.7.1 and
gitleaks were run as portable copies from a temp folder. The tests that write to the system
ran only on the CI runner, which is deleted after each job. The SMBv1 setting was read before
and after the local runs and did not change.

## What was tested

| Area | How | Result |
|---|---|---|
| Unit tests (detections, report, manifest, parsing) | Pester on 5.1 and 7, local and CI | Pass |
| Baseline audit and remediation, idempotency, rollback file | Pester, CI only (writes the system) | Pass |
| Signing, tamper detection | Pester, CI only (creates a certificate) | Pass |
| Live event logs: System, PowerShell/Operational | Local, read only | Pass after fixes |
| Live baseline audit, `Invoke-SecurityBaseline -WhatIf` | Local, read only | Pass after fixes |
| HTML report from live data | Local | Pass after fixes |
| Lint, forbidden paths, README links, secret scan | Local and CI | Pass after fix |
| pre-commit hook | Local, in a throwaway clone | Pass after fix |
| Pester 6 compatibility | Local | Pass |

## Bugs found and fixed

| # | Bug | Effect | Fix |
|---|---|---|---|
| 1 | `Get-SecurityEventRecord -StartTime` built an XPath filter on the wrong element | Always returned 0 events. On the test machine, Windows had 274 System events in the last 24 hours and the module returned 0 | Filter now targets `TimeCreated` |
| 2 | Empty event fields made the parser throw under StrictMode | Every field after the empty one was dropped. 177 of 3000 System events lost fields. On a 4625 event this can drop `TargetUserName`, which the brute force rule groups by | New parser `ConvertFrom-WinSecKitEventXml` reads the XML directly |
| 3 | "No events found" was detected by English error text | On a non-English Windows, an empty result threw an error | Checks the error ID instead |
| 4 | WSB0003 (SMBv1) checked a registry value that Windows 10 1709+ and 11 do not set | Reported non-compliant on every modern host, including one where SMBv1 is off | Reads `Get-SmbServerConfiguration`; fixes with `Set-SmbServerConfiguration` |
| 5 | `Export-SecurityReport` printed hashtables as `System.Collections.Hashtable` | The `Data` column of event records was useless | Prints `key=value` pairs |
| 6 | Firewall profile check listed an unreadable profile as enabled | Wrong `ActualValue` in reports | Lists only profiles read as enabled |
| 7 | pre-commit hook only checked added and modified files | `git mv notes.txt keyfile.bin` got past the hook. Confirmed in a test clone | Also checks renamed and copied files |
| 8 | CI Windows test count included skipped tests | A Windows test file skipped in full could still pass the gate | Counts passed tests only |
| 9 | Forbidden path check ran `git ls-files` from the current folder | Run from a subfolder, it checked only that subfolder | Runs from the repo root |
| 10 | `Test-ReadmeClaim.ps1` read files with the default encoding | On Windows PowerShell 5.1 it reported 13 false failures. CI only ran it on Linux with PowerShell 7, so it was never seen | Reads as UTF-8; CI now also runs it on 5.1 |

Also corrected:

- `Invoke-SecurityBaseline` help described a restore command that does not exist, and said
  existing firewall rules are never changed. A rule with the same name is replaced.
- The manifest comment said `CompatiblePSEditions` blocks install on macOS and Linux. It does not.
- Setup docs only said `brew install gitleaks`. Added `winget install Gitleaks.Gitleaks` for Windows.
- CI actions moved to versions that run on Node 24. Node 20 is deprecated on GitHub runners.
- Gate floors raised to match the new file and test counts, as `gate-coverage.psd1` asks.

## Results on the local machine

These are read-only results from a normal desktop, not a hardened server.

| Check | Result |
|---|---|
| Baseline | 2 of 6 compliant (firewall profiles, SMBv1 off). Before fix 4 it showed 1 of 6 |
| Detections over 2000 System and 500 PowerShell events | WSK0005 (service installed) and WSK0004 (`FromBase64String`) fired. Both patterns are common in normal use, so expect noise on admin machines |
| Security log, not elevated | Access denied, as documented. Run elevated to read it |

## Not fixed, worth knowing

- The certificate that signed `labs/04-confidentiality/evidence/myscript.ps1` expired on
  2026-09-30. The signature is still intact and the tests still pass. The file was not timestamped,
  so it will never show as `Valid` again. This is lab evidence and was left as is.
- WSK0004 does not catch short forms of `-EncodedCommand` such as `-e` or `-ec`.
- The Security log needs an elevated session, so detections WSK0001 to WSK0003 and WSK0006
  were tested with synthetic events, not live ones.

## How to repeat

```powershell
# Safe on any machine: changes nothing
Invoke-Pester ./tests/Module.Tests.ps1, ./tests/Detection.Tests.ps1, ./tests/Report.Tests.ps1, ./tests/EventRecord.Tests.ps1, ./tests/Remediation.Tests.ps1

# Changes the machine. Run only on a throwaway VM or CI runner, elevated
Invoke-Pester ./tests/Baseline.Windows.Tests.ps1, ./tests/Signing.Windows.Tests.ps1
```
