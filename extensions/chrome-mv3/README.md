# Vigils Browser Guard

[English](README.md) | [中文](README.zh-CN.md)

## Overview

Vigils Browser Guard is a Chrome MV3 extension that checks sensitive content when you paste, type, or submit it to AI websites.

In the default consumer mode, it does not require a Native Host, desktop app, or terminal setup. Detection runs inside the browser. When Vigils finds risky content, it prompts you to either continue with a redacted version or block the action.

## Highlights

- **Built for everyday users**: Install the extension and start using it without setting up a local service.
- **Browser-local scanning**: Uses lightweight JavaScript rules to detect common secrets and tokens.
- **Paste and submit guardrails**: Covers paste, debounced input, submit, and common contenteditable Enter flows.
- **Contextual page prompt**: Risk prompts appear near the active input instead of being hidden in a page corner.
- **One-click site protection**: The popup shows the current page status and lets you add custom HTTPS sites.
- **Safe event history**: The popup shows only risk type, website, and action metadata. It does not store original text.
- **Enterprise backend (optional)**: route checks to the locally installed Vigils engine over Native Host — the first shipped enterprise provider. Localhost agent, HTTPS API, and Wasm remain planned interfaces.

## Use Cases

Vigils is useful when you often paste code, config, logs, or environment variables into AI tools:

- Avoid accidentally sending GitHub Tokens, OpenAI API Keys, or database URLs to ChatGPT, Claude, Gemini, Perplexity, and similar tools.
- Detect sensitive values before pasting `.env` files, logs, or config snippets.
- Get low-friction protection with local scanning and explicit confirmation.

## Supported Websites

The extension is injected into these sites by default:

- ChatGPT
- Claude
- Gemini
- Perplexity
- DeepSeek
- Doubao
- Kimi
- Tongyi / Qianwen
- Zhipu
- Tencent Yuanbao
- Wenxin Yiyan
- iFlytek Spark

You can also add other HTTPS websites in the extension options. Vigils will request permission for that site and dynamically inject the generic guard script.

## Detectable Risk Types

Consumer mode currently detects and redacts:

- OpenAI API Key
- Anthropic API Key
- Google API Key
- GitHub Token
- GitLab Personal Access Token
- Slack Webhook
- Stripe Secret Key
- AWS Access Key ID
- JWT
- Database URL
- `.env`-style assignment
- PEM private key
- Custom prefix-based risk rules configured in Advanced settings

Most tokens and connection strings trigger a "continue with redaction" prompt. High-risk content such as PEM private keys is blocked directly.

Paste and submit checks run before the original content is inserted or sent. Manual input checks run after a short debounce and are a best-effort cleanup layer; pages that read typed text immediately can still observe it before the debounce finishes.

## Privacy and Security Promises

Consumer mode follows these rules:

- Original text is not written to `chrome.storage`
- Original text is not written to `console.log`
- Original text is not attached to `window.*` or other page globals
- Popup event history stores only metadata such as risk type, website, time, and action
- Page prompts are rendered with DOM APIs and `textContent`, not `innerHTML`
- Unknown or invalid decisions fail closed and are blocked by default

Enterprise mode is optional and off by default. Its first shipped backend is the **local Vigils
engine** over Native Host: install the Vigils CLI, register the host with your extension ID
(`vigil-native-host install --extension-id <ID>` — the ID is shown under Options → Advanced),
then pick "Local Vigils engine" in the enterprise section of Options. Checks then run in a local
process (hard fingerprints, plus ML PII when the daemon runs); raw text never leaves the device,
and an unreachable host blocks instead of silently downgrading.

## Install and Try

Install from the Chrome Web Store (see below), or load the directory as a development build:

1. Open Chrome `chrome://extensions/`
2. Enable Developer mode
3. Click Load unpacked
4. Select this directory: `extensions/chrome-mv3/`
5. Open a protected AI website
6. Paste a test token, for example:

```text
token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ
```

Expected behavior:

- A risk prompt appears near the input box
- You can choose to continue with redaction or block the action
- The redacted text no longer contains the original token

## Chrome Web Store

The extension is live on the Chrome Web Store as [**Vigils Browser Guard**](https://chromewebstore.google.com/detail/vigils-browser-guard/ffmgaglmcimapacgmoejaobfjdpmopch).
Install directly from the store — one click, no manual loading required. (The store build can lag
this directory by a review cycle; load unpacked for the latest.)

## Popup

The popup is designed for everyday users and focuses on:

- Whether the current page is protected
- Whether the current page needs permission
- The "Protect current site" button
- Recent safety events
- First-use onboarding

It does not expose Native Host, provider, or policy-tier concepts by default.

## Options

The options page keeps the default experience simple:

- Recommended protection
- Protected websites
- Add custom websites
- Privacy notes

Enterprise connection, custom risk types, extension ID, and technical permission details live under Advanced settings.

## Project Structure

```text
extensions/chrome-mv3/
├── icons/
├── manifest.json
├── background.js
├── content-script.js
├── custom-sites.js
├── popup.html
├── popup.js
├── popup.css
├── options.html
├── options.js
├── options.css
├── redaction-rules.js
├── risk-decision.js
├── scanner-pipeline.js
├── providers/
│   ├── consumer-js-provider.js
│   └── native-host-provider.js
└── tests/
```

Core layers:

- `content-script.js`: Listens to paste, debounced input, submit, and contenteditable Enter events, then shows in-page risk prompts.
- `background.js`: Handles message routing, mode management, custom-site permissions, and safety event caching.
- `custom-sites.js`: Normalizes user-provided HTTPS domains for optional protection.
- `redaction-rules.js`: Browser-local detection, redaction, and custom prefix-based risk rules.
- `risk-decision.js`: Converts scan results into `allow`, `confirm_redact`, or `block`.
- `scanner-pipeline.js`: Combines the consumer provider and enterprise providers (e.g. the Native Host provider).

## Development and Tests

Run the Chrome extension tests:

```bash
node --test extensions/chrome-mv3/tests/*.test.mjs
```

The extension has no frontend build step. It uses native MV3, HTML, CSS, and JavaScript.

## Enterprise Provider Interface

Everyday users do not need an enterprise provider. The first real backend is available now:

- **Local Vigils engine (Native Host)** — implemented. In Options, switch to enterprise
  mode and pick "Local Vigils engine". Requires the Vigils CLI/desktop install with the
  native messaging host registered (see the user guide's Browser extension section; the
  registration command needs the extension ID shown in Options). Checks are then routed
  to the local `vigil-native-host` process: hard-fingerprint detection (13 credential
  classes), plus semantic PII detection (email / person / phone / …) when the local ML
  daemon is running. Raw text goes to the **local process only** and never leaves the
  device (it stays in host memory and is dropped after classification). If the host is
  enabled but unreachable, checks fail closed to block rather than silently downgrading.
- localhost agent — planned
- Enterprise HTTPS API — planned
- Browser-side Wasm — planned

The goal is to let organizations move scanning and policy decisions into a controlled environment while preserving the zero-setup consumer experience.

## Roadmap

- Add more token and cloud credential types
- Improve deep input adapters for more AI websites
- Add fuller E2E test coverage
- Improve safety event explanations and risk education
- ~~Add the first enterprise provider (local Vigils engine via Native Host)~~ ✅ Done
- ~~Package and publish to the Chrome Web Store~~ ✅ Done

## License

See the repository root license.
