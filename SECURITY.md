# Security

## A credential was committed to this repository

The Lab 4 exercise writes an AES key to disk and uses it to encrypt a SecureString.
Both the key (`keyfile.bin`, and the same key again as decimal bytes in
`keyfile.txt`) and the ciphertext it decrypted (`password.txt`, `secret.enc`) were
committed to this public repository, in the same directory. Anyone who cloned the
repository could recover the plaintext with a single `ConvertTo-SecureString -Key`
call; encryption provides nothing when the key ships next to the ciphertext. One of
the two recovered values was also legible in a console screenshot inside the Lab 4
report PDF. The affected credentials have been rotated, the four artifacts have been
removed from the working tree and purged from git history with `git filter-repo`,
and the two figures in the PDF have been redacted at the bitmap level. Because the
repository was public before remediation, the original values are treated as
permanently disclosed rather than merely deleted — rotation, not deletion, is what
actually closed this.

## What prevents a recurrence

Three independent controls, because no single one covers both failure modes. Key
material has no content signature — a raw 16-byte AES key is just 16 bytes — so it
has to be caught by filename. An exported credential does have a content signature,
so it can be caught even if the file is renamed to something innocuous.

| Control | Catches | Runs |
|---|---|---|
| `.gitignore` | Key material and ciphertext by name, before staging | Locally, always |
| `tools/Test-ForbiddenPath.ps1` | Forbidden paths among tracked files | Pre-commit hook and CI |
| `gitleaks` (`.gitleaks.toml`) | Secrets by content, including renamed SecureString exports | Pre-commit hook and CI |

Patterns for the path check live in `tools/forbidden-paths.txt` and are read by both
the hook and CI, so the two cannot drift apart.

`.gitleaks.toml` adds a rule for the header `ConvertFrom-SecureString` writes ahead
of its base64 payload. Verified against the pre-remediation history: the rule fires
on all four occurrences of the exported credential, across both directory layouts
the repository used over its history.

Note that gitleaks 8.30.1 silently drops path-based rules when `useDefault = true`
is set. That is why filename detection lives in `Test-ForbiddenPath.ps1` rather than
in the gitleaks config: keeping it there would have meant giving up the entire
default ruleset to gain one path rule.

### Enabling the hook

The hook is not active until you point git at it. This is per-clone:

```bash
git config core.hooksPath .githooks
brew install gitleaks    # the hook warns and skips the content scan without it
```

## Reproducing the lab without secrets

`Lab_4_Confidentiality/Script/generate-lab4-artifacts.ps1` regenerates equivalent
key and ciphertext artifacts locally from values invented at random on each run, so
the exercise stays reproducible without anything sensitive entering the repository.
The files it writes are covered by all three controls above.

## What is deliberately still committed

Not everything that looks like a secret is one:

- `cyberusr.cer` — a certificate export. Public key only; this is the artifact the
  CMS exercise exists to share.
- `p1.txt` — CMS ciphertext encrypted to that certificate's public key. Inert
  without the private key, which never left the signer's certificate store.
- The Authenticode signature block in `myscript.ps1` — a detached signature plus
  its public certificate chain, appended by `Set-AuthenticodeSignature`.

## Reporting

This is coursework, not a deployed service. If you find something here that is still
sensitive, please open an issue without including the value itself.
