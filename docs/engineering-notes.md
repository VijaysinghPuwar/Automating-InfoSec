# Engineering notes

Things that cost time and were not obvious from the documentation. Each entry is
symptom, cause, fix. Written down because the failure modes below are all silent —
every one produced a green-looking result that was wrong.

---

## gitleaks drops path-based rules when the default ruleset is extended

**Symptom.** A custom rule matching `keyfile.(bin|txt)` by path found nothing, while
the same rule in isolation found both files. No warning, no config error, exit 0.

**Cause.** `[extend] useDefault = true` in `.gitleaks.toml`. Reproduced on gitleaks
8.30.1: 2 findings with the rule alone, 0 findings once `useDefault` was set —
with or without an accompanying `regex`. Adding a `regex` to a path rule also
breaks it independently, because gitleaks requires both to match and a raw 16-byte
AES key has no text to match against.

**Fix.** Kept `useDefault = true` for content detection, which is what catches an
exported credential, and moved filename detection to `tools/Test-ForbiddenPath.ps1`.
Giving up the entire default ruleset to regain one path rule was the worse trade.
Patterns live in `tools/forbidden-paths.txt`, shared by the pre-commit hook and CI.

---

## Comment-based help needs a blank line after `#Requires`

**Symptom.** `Get-Help ./tools/Test-ForbiddenPath.ps1` returned the syntax line
instead of the synopsis, and `.Examples.Example.Count` was 0. The help block was
present, correctly delimited, and had valid keywords.

**Cause.** `#Requires -Version 5.1` sat on the line immediately above `<#`. With no
blank line between them, PowerShell does not associate the comment block with the
script. Confirmed with a two-file minimal repro differing only in that blank line:
0 examples parsed vs 1.

**Fix.** Blank line after every `#Requires`. Applies to every script and module file
in this repository; a help block that does not parse is worse than none, because
`Get-Help` still returns something that looks like an answer.

---

## `$ErrorActionPreference = 'Stop'` makes `Write-Error` discard buffered output

**Symptom.** The forbidden-path check exited 1 correctly but printed nothing about
*which* file tripped it. The objects were built and non-empty — the error message
even reported the right count.

**Cause.** `Set-StrictMode` and `$ErrorActionPreference = 'Stop'` promote
`Write-Error` to a terminating error. It terminated before the default formatter
flushed the objects emitted on the preceding line. Emitting to stdout instead has
the same problem, because `exit` ends the process before the formatter runs.

**Fix.** Wrote the offender table to stderr through `[Console]::Error.Write`, which
is unbuffered, before exiting. Also deleted the "emits one object per offending
file" claim from the script's help: the script is a CI guard that signals through
its exit code, and documenting pipeline behaviour it does not have is the same
class of error as the leaked-secret README claiming files that were never committed.

---

## Pester evaluates `-ForEach` before `BeforeAll` runs

**Symptom.** A test generating one case per exported function produced a single
case named `gives System.Collections.Hashtable a synopsis`, which then failed on
an empty synopsis. The function list was correct everywhere else in the file.

**Cause.** Pester runs a discovery pass over the whole file before executing any
`BeforeAll`. `-ForEach $Module.ExportedFunctions.Keys` was therefore evaluated
while `$Module` was still unset, and iterating `$null` yields one meaningless
case rather than an error.

**Fix.** Read the manifest at file scope, outside `BeforeAll`, and drive
`-ForEach` from that. Anything feeding `-ForEach`, `-TestCases` or a `Describe`
name has to exist at discovery time.

---

## A regex character class silently ate hyphens from filenames

**Symptom.** The README claims checker reported every hyphenated file as missing:
`lab04-transcript.ps1` was reported as `lab04 transcript.ps1` not found. The files
existed and the paths were correct.

**Cause.** The class stripping box-drawing characters from directory-tree lines was
written as `[─-╿|`+\\-]`. The trailing `-` was read as a literal member of the
class, so every hyphen in every filename was replaced with a space before the
lookup.

**Fix.** Restricted the class to the Unicode box-drawing block, `[─-╿|]`,
expressed as escapes so the file stays pure ASCII — which also cleared a
`PSUseBOMForUnicodeEncodedFile` warning. The lesson is narrower than "be careful
with regex": a character class assembled from several ranges plus loose literals
is worth writing as explicit escapes, because the failure is silent and looks like
a missing file rather than a bad pattern.

---

## Path-based enumeration missed secrets that a rename had moved

**Symptom.** A `git filter-repo` run against an explicit list of six secret paths
reported success. A follow-up check found the same secrets still present in history.

**Cause.** The repository had been reorganised twice, so the artifacts existed under
two directory layouts — `Lab 4: Confidentiality/Files/` and
`Lab_4_Confidentiality/Script/`. The earlier path contains spaces. The command used
to enumerate blobs split its output on whitespace, truncating that path to `Lab`,
which read as noise in a long listing.

**Fix.** Re-ran with `--path-glob` on the filenames rather than full paths, so
renames cannot hide an artifact. Verification is now content-based: every blob in
history is grepped for the key bytes, the SecureString header, and the known
plaintexts. Enumerating paths only proves something about the paths you enumerated.
