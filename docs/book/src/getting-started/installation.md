# Install Vigils

> 简体中文：[安装 Vigils](./installation.zh-CN.md)

## 1. Which download do I want?

| I want to… | Download | Where |
|---|---|---|
| **Use the app** — see activity, approve actions (a window/GUI) | the **desktop installer** for my OS | [§2](#2-desktop-app) |
| **Guard my AI coding agent** — Claude Code / Codex / Cursor / Zed | the **CLI** (`vigils-cli-…`) | [§3](#3-cli--guard-your-coding-agent-30-seconds) |
| **Guard pasting into AI websites** — ChatGPT / Claude / Gemini | the **browser extension** | [§4](#4-browser-extension-chrome) |

Most people want the **desktop app**. Developers wiring up an agent want the **CLI**.
All files live on the [**Releases page**](https://github.com/duncatzat/vigils/releases/latest)
(replace `<version>` below with the one you grabbed, e.g. `0.3.0`).

---

## 2. Desktop app

Pick your OS, download, run. First launch shows a one-time "unknown developer" prompt
(we're not OS-code-signed yet) — the steps to allow it are below.

### Windows
1. Download **`Vigils_<version>_x64-setup.exe`** → double-click.
2. If a blue **"Windows protected your PC"** box appears → **More info → Run anyway**.
3. Done. *(The warning fades on its own as more people install.)*

### macOS
1. Download the dmg for your chip — **Apple Silicon**: `Vigils_<version>_aarch64.dmg`;
   **Intel**: `Vigils_<version>_x64.dmg` *(not sure? Apple menu → About This Mac — "Apple M…" means
   Apple Silicon)* → open it → drag **Vigils** to **Applications**.
2. First launch is blocked ("Apple could not verify…"). To allow it **once**:
   **  System Settings → Privacy & Security → scroll down → "Open Anyway" → confirm with Touch ID / password.**
3. Done — it won't ask again.

> *Terminal alternative (power users):* `xattr -dr com.apple.quarantine /Applications/Vigils.app`
> This is the standard one-time step for any not-yet-notarized app; signing is planned.

### Linux  (Ubuntu 22.04+ / Debian 12+)
```bash
sudo dpkg -i Vigils_<version>_amd64.deb            # Debian / Ubuntu
sudo rpm  -i Vigils-<version>-1.x86_64.rpm          # Fedora / RHEL
chmod +x Vigils_<version>_amd64.AppImage && ./Vigils_<version>_amd64.AppImage   # portable, any distro
```
> **On an older distro** (the desktop GUI needs glibc ≥ 2.35)? Use the **[CLI](#3-cli--guard-your-coding-agent-30-seconds)**
> instead — it runs on practically any Linux (glibc ≥ 2.17).

---

## 3. CLI — guard your coding agent (30 seconds)

Install it with one line:
```bash
curl -fsSL https://vigils.ai/install.sh | sh        # macOS / Linux
```
```powershell
irm https://vigils.ai/install.ps1 | iex             # Windows (PowerShell)
```
*(Or download `vigils-cli-<os>` from Releases and unpack it — it contains `vigil-hub`.)*

Then turn on protection:
```bash
vigil-hub setup       # auto-detects Claude Code / Codex / Cursor and wires the guard
```
Restart your agent — that's it. Raw secrets are now blocked from its tool calls, and every
block is recorded in a tamper-evident local ledger. Kick the tires with **`vigil-hub demo`**
(zero setup). Per-agent details: [Agent Integration](./agent-integration.md)
([中文](./agent-integration.zh-CN.md)).

> **ML variant** (optional, semantic PII + prompt-injection detection): download
> `vigils-cli-ml-<os>` instead and run `vigil-hub serve --engine ml`. Floors: Linux glibc ≥ 2.28,
> macOS ≥ 14, Apple Silicon only (upstream onnxruntime dropped x86_64 macOS; Intel macs use the
> default hard-fingerprint engine). See [Privacy Filter](../concepts/privacy-filter.md).

---

## 4. Browser extension (Chrome)

Redacts secrets / PII before you paste or submit on AI sites. Install
[**Vigils Browser Guard**](https://chromewebstore.google.com/detail/vigils-browser-guard/ffmgaglmcimapacgmoejaobfjdpmopch)
from the Chrome Web Store — consumer mode works out of the box, no desktop app required.
Optional deep redaction: install the Vigils CLI, register the native messaging host
(`vigil-native-host install --extension-id <ID>`, ID shown in the extension's Options),
then pick "Local Vigils engine" under enterprise mode in Options — checks route to the
local engine (hard fingerprints + ML PII when the daemon runs); raw text never leaves
the device. Dev builds:
`chrome://extensions` → **Developer mode** → **Load unpacked** → pick `extensions/chrome-mv3/`.

---

**Worried it's authentic?** Every download has a SHA-256 checksum and a cryptographic build
attestation — [Verifying your download](./verifying-downloads.md)
([中文](./verifying-downloads.zh-CN.md)).
Building Vigils into your own Rust app? [SDK Quickstart](./sdk-quickstart.md).
