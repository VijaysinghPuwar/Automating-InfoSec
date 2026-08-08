# Engineering notes

Failure modes worth writing down. Each entry is symptom, cause, fix.

The first section is the one that matters. Everything under it is an individual
bug; that section is a *pattern*, and it bit this project three times in a single
working session.

---

# Gates that report clean while skipping their inputs

**The pattern.** A quality gate returns success not because the thing it checks is
sound, but because it never looked at it. Exit code 0. Green tick. Nothing in the
log that reads as wrong. The gate has quietly converted *unverified* into
*verified* on the dashboard while changing nothing about the code.

This is worse than a gate that fails incorrectly. A false failure gets
investigated within minutes because it blocks someone. A false pass is load-bearing
for as long as anyone trusts it, and the moment you rely on it is the moment it
is already wrong. Every one of the three below was caught by accident — a file
count that did not move, a test total that differed between two legs, an
uncomfortable impulse to reach for a config flag. None was caught by the gate.

## Instance 1 — PSScriptAnalyzer skipped `.github/` and reported clean

Two CI scripts were added under `.github/scripts/`. PSScriptAnalyzer reported
"clean across 26 files" — the same count as before those files existed.

`Get-ChildItem -Recurse` does not descend into dot-directories without `-Force`.
`.github/` is a dot-directory, so the scripts that drive the entire test matrix
were invisible to the linter that was supposed to check them.

**Fix.** `-Force` on discovery plus an explicit `.git` filter. File count went
26 → 28 and stayed clean. Caught only because the count did not move after adding
two files.

## Instance 2 — Pester counted discovery failures as success

The Windows PowerShell 5.1 leg reported `Passed: 63, Failed: 0` and exited 0. The
PowerShell 7 leg ran 88 tests. Both Windows test files had thrown during Pester's
discovery phase and been dropped from the run entirely.

`$IsWindows` does not exist in Windows PowerShell 5.1, and Pester runs discovery
under `StrictMode`, so referencing it threw. A file that fails discovery
contributes no tests *and no failures*, so `FailedCount` stayed 0 and the runner
called it a pass.

**Fix.** Three layers, because the guard alone would not have caught the next
variation:
1. Key the platform check on `$env:OS`, which exists everywhere.
2. Fail the run on `FailedContainersCount`, not just `FailedCount`.
3. Assert that Windows-tagged tests actually executed on a Windows host, so an
   entire category cannot vanish silently for some *other* reason.

Caught only because the two legs disagreed about the test total.

## Instance 3 — the temptation to narrow a secret scan until it went quiet

gitleaks failed CI with four findings. They were real: `actions/checkout` with
`fetch-depth: 0` fetches every ref, so the scan was reading the unpurged history
still live on `origin/main` and correctly reporting the secrets GitHub was serving.

The available "fix" was a scope flag — restrict the scan to the branch under test
and CI goes green immediately. It would have looked principled. It would have
meant a repository with published secrets and a green secret-scanning badge.

**Fix.** Leave the scan as written and fix the actual condition: purge `main`.
gitleaks went from 56 commits scanned with 4 leaks to 38 scanned with none, and
now passes because the secrets are gone rather than because it stopped looking.

This instance is the reason the pattern is worth naming. The first two were
accidents. This one was a decision, and the wrong version of it was the
convenient one.

## The countermeasure

Every gate in this repository asserts it processed a non-zero, expected number of
inputs — not merely that it found no failures.

- `tools/gate-coverage.psd1` — the expected minimum input count per gate.
- `tools/Assert-GateCoverage.ps1` — fails the build when a gate's observed input
  count falls below its minimum, and always fails on zero.

Wired into every job in `.github/workflows/ci.yml`. A gate that suddenly inspects
far fewer files than it used to now fails loudly instead of passing quietly.

The minimums are deliberately a floor rather than an exact count, so ordinary
growth does not cause churn, while a collapse in coverage still trips it. When
adding files, raise the floor.

**The general lesson:** a passing gate is a claim about coverage as much as about
correctness. Ask what it processed, not just what it found. Count the inputs, not
the exit code.

---

# Individual notes

## Authenticode `Status -eq 'Valid'` conflates trust with identity

**Symptom.** `Invoke-ScriptSigning` re-signed every file on every run, so it was
never idempotent, and the test asserting a second run made no change failed.

**Cause.** The skip condition was `Status -eq 'Valid'`. `Valid` requires both that
the file is unmodified *and* that the signing certificate chains to a root trusted
**on the machine doing the checking**. A self-signed certificate never satisfies the
second, so the condition was permanently false.

**Fix.** Split the two ideas. *Is this file intact and signed by this certificate*
is a property of the file — thumbprint match, and status not `NotSigned` or
`HashMismatch`. *Is the signer trusted* is a property of the verifying machine, and
irrelevant to whether signing again would change anything. Only the first belongs
in an idempotency check.

## gitleaks drops path-based rules when the default ruleset is extended

**Symptom.** A rule matching `keyfile.(bin|txt)` by path found nothing, while the
same rule in isolation found both files. No warning, no config error, exit 0.

**Cause.** `[extend] useDefault = true`. Reproduced on gitleaks 8.30.1: 2 findings
with the rule alone, 0 once `useDefault` was set, with or without an accompanying
`regex`. Adding a `regex` to a path rule breaks it independently, because gitleaks
requires both to match and a raw 16-byte AES key has no text to match against.

**Fix.** Keep `useDefault = true` for content detection and move filename detection
to `tools/Test-ForbiddenPath.ps1`. Giving up the entire default ruleset to regain
one path rule was the worse trade.

## GitHub rejects `shell:` with an expression, before any job starts

**Symptom.** A run failed in 0 seconds with no jobs, no logs and no annotation
beyond "This run likely failed because of a workflow file issue". It reads like an
outage rather than a syntax error.

**Cause.** `shell: ${{ matrix.shell }}`. The `shell:` key accepts no contexts, so
the file is rejected at parse time and nothing is scheduled. A YAML parser
validates it happily — it *is* valid YAML. The violation is of the Actions schema.

**Fix.** Keep `shell:` static and select the interpreter inside the step, where
`matrix` is available. Validate workflows with `actionlint`, not a YAML parser.

## Pester evaluates `-ForEach` before `BeforeAll` runs

**Symptom.** A test generating one case per exported function produced a single
case named `gives System.Collections.Hashtable a synopsis`, which failed on an
empty synopsis.

**Cause.** Pester discovers the whole file before executing any `BeforeAll`, so
`-ForEach $Module.ExportedFunctions.Keys` was evaluated while `$Module` was unset.
Iterating `$null` yields one meaningless case rather than an error.

**Fix.** Read the manifest at file scope, outside `BeforeAll`. Anything feeding
`-ForEach`, `-TestCases` or a `Describe` name must exist at discovery time.

## `$ErrorActionPreference = 'Stop'` makes `Write-Error` discard buffered output

**Symptom.** The forbidden-path check exited 1 correctly but printed nothing about
*which* file tripped it, despite the objects being built and non-empty.

**Cause.** `Stop` promotes `Write-Error` to a terminating error, which fired before
the default formatter flushed the objects emitted on the preceding line. Emitting
to stdout has the same problem, because `exit` ends the process first.

**Fix.** Write the offender table to stderr through `[Console]::Error.Write`, which
is unbuffered, before exiting. The "emits one object per file" claim was removed
from the script's help rather than left describing behaviour it did not have.

## A regex character class silently ate hyphens from filenames

**Symptom.** The README claims checker reported every hyphenated file as missing:
`lab04-transcript.ps1` reported as `lab04 transcript.ps1` not found.

**Cause.** The class stripping box-drawing characters was written as
`` [─-╿|`+\\-] ``. The trailing `-` was read as a literal class member, so every
hyphen in every filename became a space before the lookup.

**Fix.** Restrict to the Unicode box-drawing block, written as escapes so the file
stays pure ASCII. A class assembled from several ranges plus loose literals is
worth writing as explicit escapes: the failure is silent and looks like a missing
file rather than a bad pattern.

## Path-based enumeration missed secrets that a rename had moved

**Symptom.** A `git filter-repo` run against an explicit list of six paths reported
success. A follow-up check found the same secrets still in history.

**Cause.** The repository had been reorganised twice, so the artifacts existed
under two layouts — `Lab 4: Confidentiality/Files/` and
`Lab_4_Confidentiality/Script/`. The earlier path contains spaces, and the command
enumerating blobs split on whitespace, truncating it to `Lab`, which read as noise.

**Fix.** Re-run with `--path-glob` on filenames rather than full paths, so renames
cannot hide an artifact. Verification is now content-based: every blob in history
is grepped for the key bytes, the SecureString header and the known plaintexts.
Enumerating paths only proves something about the paths you enumerated.
