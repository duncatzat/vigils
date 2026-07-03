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

### macOS (Apple Silicon)
1. Download **`Vigils_<version>_aarch64.dmg`** → open it → drag **Vigils** to **Applications**.
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
> macOS ≥ 14. See [Privacy Filter](../concepts/privacy-filter.md).

---

## 4. Browser extension (Chrome)

Redacts secrets / PII before you paste or submit on AI sites. Load it via
`chrome://extensions` → **Developer mode** → **Load unpacked** → pick `extensions/chrome-mv3/`.
*(It pairs with the desktop app's native host, registered by the desktop installer.)*

---

**Worried it's authentic?** Every download has a SHA-256 checksum and a cryptographic build
attestation — [Verifying your download](./verifying-downloads.md)
([中文](./verifying-downloads.zh-CN.md)).
Building Vigils into your own Rust app? [SDK Quickstart](./sdk-quickstart.md).
