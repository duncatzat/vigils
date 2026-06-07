# Verifying your download

> 🌐 中文版：[验证你的下载](./verifying-downloads.zh-CN.md)

Vigils sits in front of your secrets, so you shouldn't have to take our word that a
download is genuine. Every release artifact is **independently verifiable**. This page
shows how — and is honest about what each check does and doesn't prove.

## TL;DR

```bash
# The strongest check: proves the file was built by THIS repo's CI from THIS repo's
# source. Works for every artifact — CLI archives, desktop installers, extension zip.
gh attestation verify <downloaded-file> --repo duncatzat/vigils
```

A ✓ with a matching source repository and workflow means the binary is authentic;
nothing else is strictly required. The sections below add complementary checks and
explain the current absence of OS code-signing.

## 1. Build provenance — recommended, covers everything

Every downloadable artifact ships with a [SLSA](https://slsa.dev) build-provenance
attestation, signed through GitHub's Sigstore-backed infrastructure (no key for you to
manage, nothing to trust besides GitHub and the public source):

- CLI archives — `vigils-cli-linux-x64.tar.gz`, `vigils-cli-macos-arm64.tar.gz`, `vigils-cli-windows-x64.zip`
- Desktop installers — `.exe`, `.msi`, `.dmg`, `.deb`, `.rpm`, `.AppImage`
- Browser extension — `vigils-chrome-extension.zip`

Verify with the [GitHub CLI](https://cli.github.com/):

```bash
gh attestation verify Vigils_0.1.7_amd64.deb --repo duncatzat/vigils
```

A pass proves the file was produced by **this** repository's release workflow from a
specific commit — i.e. it wasn't swapped out, rebuilt by someone else, or altered after
the build. This is a stronger statement about *origin* than a code-signing certificate
alone, because it binds the binary to the exact public source commit and CI run you can
go read.

> Air-gapped? Download the artifact's attestation bundle from the release and verify
> offline with `gh attestation verify <file> --bundle <bundle.jsonl> --repo duncatzat/vigils`.

## 2. Checksums — CLI archives

Each CLI archive is published next to a `.sha256` file. The [one-line installer](./installation.md)
checks it for you; to verify by hand:

```bash
# macOS / Linux — the .sha256 holds "<hash>  <filename>"
shasum -a 256 -c vigils-cli-linux-x64.tar.gz.sha256
```

```powershell
# Windows — compare against the published hash in vigils-cli-windows-x64.zip.sha256
(Get-FileHash -Algorithm SHA256 vigils-cli-windows-x64.zip).Hash
```

A checksum only proves the bytes you got match the bytes the release published (it
catches truncation / transport corruption). It is **not** a signature — use provenance
(§1) for authenticity. Desktop installers rely on provenance rather than a separate
`.sha256`.

## 3. The install script

The one-liner is a plain, readable shell/PowerShell script — read it before running.
Note it verifies the archive checksum for you:

```bash
curl -fsSL https://vigils.ai/install.sh          # read it first
curl -fsSL https://vigils.ai/install.sh | sh     # then run
```

```powershell
irm https://vigils.ai/install.ps1                # read it first
irm https://vigils.ai/install.ps1 | iex          # then run
```

## 4. About the "unsigned app" warning

Vigils installers are **not yet OS-code-signed or notarized** — that requires a paid,
identity-verified certificate from Apple and a Windows CA, which isn't in place yet. So
on first run your OS will warn you:

- **macOS** — Gatekeeper blocks the app. Verify provenance (§1) first, then clear the
  quarantine flag: `xattr -d com.apple.quarantine /Applications/Vigils.app`.
- **Windows** — SmartScreen warns. Verify provenance (§1) first, then *More info →
  Run anyway*.

Until code-signing lands, **build provenance is the verification path** — and for
proving a binary really came from this open source, it's the stronger guarantee anyway.

## 5. Auto-updates are signed

Once installed, the desktop app's auto-updater only accepts updates carrying a valid
signature from the project's minisign key (the `.sig` files in each release), so the
update channel is authenticated end-to-end with no action from you. See
[Auto-Update](../ops/auto-update.md).
