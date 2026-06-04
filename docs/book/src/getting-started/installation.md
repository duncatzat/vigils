# Installation

Download the latest installers from the
[**Releases page**](https://github.com/duncatzat/vigils/releases/latest). Replace
`<version>` below with the release you downloaded (e.g. `0.1.7`).

> Early releases are unsigned; your OS may show a Gatekeeper / SmartScreen prompt on first run.

## Desktop app (end users)

The installed program is **Vigils** (executable `vigils` / `vigils.exe`).

### Linux

```bash
sudo dpkg -i Vigils_<version>_amd64.deb           # Debian / Ubuntu
sudo rpm -i  Vigils-<version>-1.x86_64.rpm         # Fedora / RHEL
chmod +x Vigils_<version>_amd64.AppImage && ./Vigils_<version>_amd64.AppImage   # portable
```

### Windows

- **NSIS**: double-click `Vigils_<version>_x64-setup.exe` (SmartScreen → *More info* → *Run anyway*).
- **MSI**: `msiexec /i Vigils_<version>_x64_en-US.msi`

### macOS (Apple Silicon)

Open `Vigils_<version>_aarch64.dmg`, drag **Vigils** to *Applications*, then clear the
quarantine flag (unsigned build):

```bash
xattr -d com.apple.quarantine /Applications/Vigils.app
```

### Auto-update

Installed apps check for updates over the Tauri auto-updater (Ed25519-signed). See
[Auto-Update](../ops/auto-update.md).

## Rust SDK (developers)

```toml
[dependencies]
vigil-sdk = "0.1"
```

Published on [crates.io](https://crates.io/crates/vigil-sdk) /
[docs.rs](https://docs.rs/vigil-sdk). See [SDK Quickstart](./sdk-quickstart.md).

## Browser extension (Chrome MV3)

Redacts secrets / PII before paste or submit on AI sites (ChatGPT / Claude / Gemini /
Perplexity):

1. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select
   `extensions/chrome-mv3/`.
2. The extension talks to the desktop app's **native host** (registered by the desktop
   installer / `vigil-native-host install`).

## CLI agent gateway

For embedding Vigils as an MCP gateway in front of your agent (Claude Code / Codex /
Cursor / Zed):

- **Prebuilt**: download `vigils-cli-<target>.tar.gz` (or `.zip` on Windows) from the
  release — it contains `vigil-hub` and `vigil-native-host`.
- **From source**: `cargo install --path apps/vigil-hub-cli`

```bash
vigil-hub serve --stdio    # MCP agent entry point
```

See the [Agent Integration & Test guide](./agent-integration.md) for per-agent config
([中文](./agent-integration.zh-CN.md)).
