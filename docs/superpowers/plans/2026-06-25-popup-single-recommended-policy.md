# Popup Single Recommended Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Simplify the Chrome extension ordinary-user UI to one fixed recommended protection policy and remove `strict / balanced / recall-first` controls from popup/options.

**Architecture:** Consumer mode should behave like the current `balanced` policy without exposing a tier selector. The background service worker should stop reading or honoring `vigilTier` for ordinary checks, while popup/options become status/configuration surfaces only. Existing scanner/redaction behavior stays unchanged: `allow`, `confirm_redact`, and `block` remain the only user-facing actions.

**Tech Stack:** Chrome MV3, vanilla HTML/CSS/JS, ES modules in service worker/options, Node `node:test`, no npm/build chain.

## Global Constraints

- 普通用户界面采用单一默认策略：**推荐保护**。
- 用户不需要理解或选择 `strict / balanced / recall-first`。
- 默认行为等同当前 `balanced`：安全文本直接放行；可脱敏 secret/token/JWT/`.env`/数据库连接串提示“脱敏后继续 / 阻断”；高风险 PEM 私钥直接阻断。
- Popup 不展示 `strict / balanced / recall-first` 三档按钮。
- Options 不展示“守门档位”区域。
- 普通用户路径不得提供修改 `vigilTier` 的 UI 或 runtime 入口。
- 不增加 allow-once、临时豁免、站点级绕过等放行能力。
- 不要求普通用户理解 Native Host、企业 provider 或数据策略。
- 普通模式在浏览器内检测；原文不写入 storage、console 或页面全局对象。
- 自动测试通过：`node --test extensions/chrome-mv3/tests/*.test.mjs`。

---

## File Structure

- `extensions/chrome-mv3/background.js`: remove tier storage/runtime handling from the ordinary check path; keep scanner pipeline and mode handling.
- `extensions/chrome-mv3/popup.html`: remove tier button markup.
- `extensions/chrome-mv3/popup.js`: remove popup tier state, storage writes, runtime tier messages, and interval refresh calls.
- `extensions/chrome-mv3/popup.css`: remove tier selector styles and any stale removed-section styles.
- `extensions/chrome-mv3/options.html`: remove the “守门档位” section.
- `extensions/chrome-mv3/options.js`: remove tier DOM references, storage reads/writes, and runtime tier messages.
- `extensions/chrome-mv3/tests/background-consumer-mode.test.mjs`: add source guards that consumer checks do not call `applyTierDecision` or expose tier runtime messages.
- `extensions/chrome-mv3/tests/ui-copy-source.test.mjs`: add source guards that popup/options do not expose tier controls or `vigil_set_tier`.
- `extensions/chrome-mv3/tests/tier-decision.test.mjs`: delete if `tier-decision.js` becomes unused in this implementation; otherwise narrow to future-reserved behavior and keep it out of consumer path.
- `extensions/chrome-mv3/README.md`: update current scope/roadmap wording from “档位” to “推荐保护” where needed.

---

### Task 1: Fix Background To Recommended Policy

**Files:**
- Modify: `extensions/chrome-mv3/background.js`
- Modify: `extensions/chrome-mv3/tests/background-consumer-mode.test.mjs`
- Delete: `extensions/chrome-mv3/tests/tier-decision.test.mjs` only if no runtime code imports `tier-decision.js` after this task
- Optional Delete: `extensions/chrome-mv3/tier-decision.js` only if no runtime/test code imports it after this task

**Interfaces:**
- Consumes: `checkWithScannerPipeline(request, { mode, enterprise })` from `scanner-pipeline.js`
- Produces: `vigil_check` response still has `{ action, findings, redacted_text?, _error? }`
- Produces: `vigil_get_mode` and `vigil_set_mode` stay unchanged
- Removes: `vigil_get_tier`, `vigil_set_tier`, `vigilTier` storage participation in ordinary checks

- [ ] **Step 1: Write source guard tests for fixed recommended policy**

Edit `extensions/chrome-mv3/tests/background-consumer-mode.test.mjs` and add:

```js
test("consumer checks no longer apply user-selectable tier overrides", () => {
    assert.doesNotMatch(
        backgroundSource,
        /applyTierDecision/,
        "ordinary consumer checks must use the scanner result directly",
    );
    assert.doesNotMatch(
        backgroundSource,
        /vigilTier/,
        "ordinary consumer mode must not read a user-selectable tier from storage",
    );
});

test("background no longer exposes tier runtime messages", () => {
    assert.doesNotMatch(backgroundSource, /vigil_get_tier/);
    assert.doesNotMatch(backgroundSource, /vigil_set_tier/);
});
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
node --test extensions/chrome-mv3/tests/background-consumer-mode.test.mjs
```

Expected: FAIL because `background.js` still imports `applyTierDecision`, stores `vigilTier`, and exposes `vigil_get_tier` / `vigil_set_tier`.

- [ ] **Step 3: Remove tier imports and state from `background.js`**

In `extensions/chrome-mv3/background.js`, replace:

```js
import {
    TIER_VALUES,
    TIER_DEFAULT,
    applyTierDecision,
} from "./tier-decision.js";
```

with no tier import.

Remove these constants/state:

```js
const TIER_STORAGE_KEY = "vigilTier";
let currentTier = TIER_DEFAULT;
```

Remove `TIER_VALUES` / `TIER_DEFAULT` references in storage bootstrap and `chrome.storage.onChanged`.

- [ ] **Step 4: Route checks directly through the scanner result**

In the `vigil_check` handler, replace:

```js
return checkWithScannerPipeline(
    {
        request_id: crypto.randomUUID(),
        origin: msg.origin,
        event_kind: msg.event_kind,
        text: msg.text,
    },
    {
        mode: currentMode,
        enterprise: { dataPolicy: "local_only" },
    },
)
    .then((rawResp) => applyTierDecision(rawResp, currentTier))
    .then((resp) => {
```

with:

```js
return checkWithScannerPipeline(
    {
        request_id: crypto.randomUUID(),
        origin: msg.origin,
        event_kind: msg.event_kind,
        text: msg.text,
    },
    {
        mode: currentMode,
        enterprise: { dataPolicy: "local_only" },
    },
)
    .then((resp) => {
```

- [ ] **Step 5: Remove tier runtime message handlers**

Delete the full `if (msg.type === "vigil_get_tier")` and `if (msg.type === "vigil_set_tier")` blocks from `extensions/chrome-mv3/background.js`.

- [ ] **Step 6: Delete or isolate unused tier-decision code**

Run:

```bash
rg -n "tier-decision|applyTierDecision|TIER_VALUES|TIER_DEFAULT|vigilTier|vigil_get_tier|vigil_set_tier" extensions/chrome-mv3
```

Expected after Tasks 1-3 are complete: matches only in tests/docs that intentionally mention removed behavior. If `extensions/chrome-mv3/tier-decision.js` has no runtime importer, delete `extensions/chrome-mv3/tier-decision.js` and `extensions/chrome-mv3/tests/tier-decision.test.mjs` in this task to avoid dead code.

- [ ] **Step 7: Run focused background tests**

Run:

```bash
node --test extensions/chrome-mv3/tests/background-consumer-mode.test.mjs
```

Expected: PASS.

- [ ] **Step 8: Commit Task 1**

```bash
git add extensions/chrome-mv3/background.js \
  extensions/chrome-mv3/tests/background-consumer-mode.test.mjs \
  extensions/chrome-mv3/tier-decision.js \
  extensions/chrome-mv3/tests/tier-decision.test.mjs
git commit -m "fix: use fixed recommended consumer policy"
```

If `tier-decision.js` or `tier-decision.test.mjs` was deleted, `git add` will stage the deletion.

---

### Task 2: Simplify Popup UI

**Files:**
- Modify: `extensions/chrome-mv3/popup.html`
- Modify: `extensions/chrome-mv3/popup.js`
- Modify: `extensions/chrome-mv3/popup.css`
- Modify: `extensions/chrome-mv3/tests/ui-copy-source.test.mjs`

**Interfaces:**
- Consumes: `vigil_recent_findings`, `vigil_clear_findings`, `vigil_get_mode`
- Produces: popup still renders mode label, status pill, recent record count, refresh, clear, options link, and findings list
- Removes: tier buttons, tier hint, `vigilTier` storage access, `vigil_set_tier`

- [ ] **Step 1: Write popup UI source guard tests**

Edit `extensions/chrome-mv3/tests/ui-copy-source.test.mjs` and add:

```js
test("popup no longer exposes tier controls", () => {
    const html = read("extensions/chrome-mv3/popup.html");
    const js = read("extensions/chrome-mv3/popup.js");
    const css = read("extensions/chrome-mv3/popup.css");
    const popupSource = [html, js, css].join("\n");
    assert.doesNotMatch(html, /data-tier=/);
    assert.doesNotMatch(html, /保护档位/);
    assert.doesNotMatch(popupSource, /recall-first/);
    assert.doesNotMatch(popupSource, /vigil_set_tier/);
    assert.doesNotMatch(popupSource, /vigilTier/);
});
```

- [ ] **Step 2: Run the focused UI tests and verify they fail**

Run:

```bash
node --test extensions/chrome-mv3/tests/ui-copy-source.test.mjs
```

Expected: FAIL because popup still has tier controls and JS.

- [ ] **Step 3: Remove tier markup from popup**

In `extensions/chrome-mv3/popup.html`, delete:

```html
    <div class="tier-switch" aria-label="保护档位">
      <div class="tier-buttons" role="group" aria-label="快速切换保护档位">
        <button type="button" class="tier-btn" data-tier="strict">strict</button>
        <button type="button" class="tier-btn" data-tier="balanced">balanced</button>
        <button type="button" class="tier-btn" data-tier="recall-first">recall-first</button>
      </div>
      <span id="tier-hint" class="tier-hint" aria-live="polite"></span>
    </div>
```

- [ ] **Step 4: Remove tier JS from popup**

In `extensions/chrome-mv3/popup.js`, delete:

```js
// ISS-007:tier 快速切换;复用 options 页同一 SW 消息,不新增权限 / storage。
const tierButtons = Array.from(document.querySelectorAll(".tier-btn"));
const tierHintEl = document.getElementById("tier-hint");
let currentTier = null;
let tierSwitchPending = false;
const TIER_STORAGE_KEY = "vigilTier";
const TIER_DEFAULT = "balanced";
const TIER_VALUES = ["strict", "balanced", "recall-first"];
```

Delete the functions `setTierHint`, `renderTier`, `refreshTier`, `setTier`, and the `for (const btn of tierButtons)` event binding block.

Remove `refreshTier();` from refresh button, initial render, and the interval callback.

- [ ] **Step 5: Remove tier CSS**

In `extensions/chrome-mv3/popup.css`, delete the style blocks:

```css
.tier-switch { ... }
.tier-buttons { ... }
.tier-btn { ... }
.tier-btn-active { ... }
.tier-btn:disabled { ... }
.tier-hint { ... }
.tier-hint-warn { ... }
```

Also delete stale removed-section styles if present:

```css
.exempt-section { ... }
.exempt-status { ... }
#exempt-label { ... }
#exempt-label.exempt-active { ... }
.exempt-remaining { ... }
.exempt-actions { ... }
.exempt-actions button { ... }
#exempt-clear-btn { ... }
#exempt-clear-btn:hover { ... }
```

- [ ] **Step 6: Run focused popup tests**

Run:

```bash
node --test extensions/chrome-mv3/tests/ui-copy-source.test.mjs
```

Expected: PASS.

- [ ] **Step 7: Commit Task 2**

```bash
git add extensions/chrome-mv3/popup.html \
  extensions/chrome-mv3/popup.js \
  extensions/chrome-mv3/popup.css \
  extensions/chrome-mv3/tests/ui-copy-source.test.mjs
git commit -m "fix: simplify popup policy controls"
```

---

### Task 3: Remove Options Tier Settings

**Files:**
- Modify: `extensions/chrome-mv3/options.html`
- Modify: `extensions/chrome-mv3/options.js`
- Modify: `extensions/chrome-mv3/tests/ui-copy-source.test.mjs`

**Interfaces:**
- Consumes: `vigil_get_mode`, `vigil_set_mode`, custom site messages
- Produces: options still supports mode selection, enterprise provider preview, custom protected sites, and permission copy
- Removes: options tier fieldset, `vigilTier` storage access, `vigil_set_tier`

- [ ] **Step 1: Write options UI source guard test**

Edit `extensions/chrome-mv3/tests/ui-copy-source.test.mjs` and add:

```js
test("options no longer exposes tier settings", () => {
    const html = read("extensions/chrome-mv3/options.html");
    const js = read("extensions/chrome-mv3/options.js");
    const optionsSource = [html, js].join("\n");
    assert.doesNotMatch(html, /守门档位/);
    assert.doesNotMatch(html, /name="tier"/);
    assert.doesNotMatch(optionsSource, /recall-first/);
    assert.doesNotMatch(optionsSource, /vigil_set_tier/);
    assert.doesNotMatch(optionsSource, /vigilTier/);
});
```

- [ ] **Step 2: Run focused UI tests and verify they fail**

Run:

```bash
node --test extensions/chrome-mv3/tests/ui-copy-source.test.mjs
```

Expected: FAIL because options still has the tier section and JS.

- [ ] **Step 3: Remove tier section from options HTML**

In `extensions/chrome-mv3/options.html`, delete the full section:

```html
  <section class="section">
    <h2>守门档位(ISS-007)</h2>
    <p class="desc">
      决定命中硬指纹后 Vigils 的行为。默认 <strong>balanced</strong>;
      in-memory 会话级设置(浏览器重启恢复默认)。
    </p>
    <fieldset class="tier-fieldset" id="tier-fieldset">
      <legend class="visually-hidden">tier</legend>
      <label class="tier-row">
        <input type="radio" name="tier" value="strict" />
        <span class="tier-label">
          <strong>strict</strong> — 公开 AI 网站;命中 secret 一律阻断
        </span>
      </label>
      <label class="tier-row">
        <input type="radio" name="tier" value="balanced" />
        <span class="tier-label">
          <strong>balanced</strong>(默认)— 脱敏后继续,最佳 UX
        </span>
      </label>
      <label class="tier-row">
        <input type="radio" name="tier" value="recall-first" />
        <span class="tier-label">
          <strong>recall-first</strong> — 企业外发 / 工单;多类 PII 命中也阻断
        </span>
      </label>
    </fieldset>
    <p id="tier-hint" class="copy-hint"></p>
  </section>
```

- [ ] **Step 4: Remove tier JS from options**

In `extensions/chrome-mv3/options.js`, delete constants and DOM references related to tier:

```js
const TIER_STORAGE_KEY = "vigilTier";
const TIER_DEFAULT = "balanced";
const TIER_VALUES = ["strict", "balanced", "recall-first"];
```

Delete functions that only support tier UI, including `setCheckedTier`, `renderTierHint`, `loadTier`, and tier radio event bindings. Remove `loadTier();` from initialization.

Keep all mode and custom site logic unchanged.

- [ ] **Step 5: Run focused UI tests**

Run:

```bash
node --test extensions/chrome-mv3/tests/ui-copy-source.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

```bash
git add extensions/chrome-mv3/options.html \
  extensions/chrome-mv3/options.js \
  extensions/chrome-mv3/tests/ui-copy-source.test.mjs
git commit -m "fix: remove options tier settings"
```

---

### Task 4: Documentation And Final Verification

**Files:**
- Modify: `extensions/chrome-mv3/README.md`
- Modify: `docs/superpowers/specs/2026-06-25-popup-single-recommended-policy-design.md` only if implementation reveals a wording mismatch

**Interfaces:**
- Consumes: completed Tasks 1-3 behavior
- Produces: updated documentation and final verification evidence

- [ ] **Step 1: Update README current scope**

In `extensions/chrome-mv3/README.md`, ensure the current scope describes recommended protection without user tier controls. Add or update a bullet similar to:

```md
- ✅ popup/options: 普通用户只看到推荐保护状态、最近记录、模式和网站权限；不暴露 `strict / balanced / recall-first` 档位选择
```

Remove or rewrite any current-scope/roadmap wording that says ordinary users can switch `strict / balanced / recall-first`.

- [ ] **Step 2: Run whole extension tests**

Run:

```bash
node --test extensions/chrome-mv3/tests/*.test.mjs
```

Expected: PASS.

- [ ] **Step 3: Run source scans for removed controls**

Run:

```bash
rg -n "recall-first|vigil_set_tier|vigil_get_tier|vigilTier|守门档位|data-tier=" extensions/chrome-mv3 --glob '!tests/**'
```

Expected: no output.

Run:

```bash
rg -n "allow_exempt|vigil_set_exempt|vigil_get_exempt|注册 Native Host|com\\.vigil\\.host" extensions/chrome-mv3/manifest.json extensions/chrome-mv3/popup.html extensions/chrome-mv3/options.html extensions/chrome-mv3/background.js
```

Expected: no output, except `Native Host` may remain in `options.html` only inside the enterprise provider dropdown if that dropdown still uses the visible future provider label.

- [ ] **Step 4: Check repository status**

Run:

```bash
git status --short
```

Expected: only intended documentation files are modified before commit.

- [ ] **Step 5: Commit Task 4**

```bash
git add extensions/chrome-mv3/README.md \
  docs/superpowers/specs/2026-06-25-popup-single-recommended-policy-design.md
git commit -m "docs: describe recommended popup policy"
```

If the spec did not need changes, only stage `README.md`.

- [ ] **Step 6: Final verification**

Run:

```bash
node --test extensions/chrome-mv3/tests/*.test.mjs
git status --short --branch
```

Expected:

```text
all extension tests pass
## codex/chrome-consumer-copy-paste-extension
```

Manual Chrome smoke test is optional but recommended:

1. Load unpacked extension from `/Users/wengzhenqi/code/vigils/.worktrees/chrome-consumer-copy-paste-extension/extensions/chrome-mv3`.
2. Open popup.
3. Expected: no `strict / balanced / recall-first` controls.
4. Paste `OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890` into a protected AI site.
5. Expected: page prompt offers “脱敏后继续 / 阻断”.
6. Paste a PEM private key block.
7. Expected: block prompt appears and no continue button is shown.

---

## Self-Review

Spec coverage:

- Single recommended policy: Task 1 fixes background behavior and removes runtime tier control.
- Popup no tier controls: Task 2 removes markup, JS, CSS, and adds source tests.
- Options no tier settings: Task 3 removes section, JS, and adds source tests.
- No allow-once/exemption/Native Host regressions: Task 4 source scans include existing forbidden paths.
- Recommended behavior remains current balanced behavior: Task 1 routes scanner result directly, preserving `confirm_redact` and `block`.
- Old `vigilTier` values ignored: Task 1 removes background reads and writes for `vigilTier`.

Placeholder scan:

- No placeholder markers or unspecified “add tests” language.
- Each task has exact files, commands, expected outcomes, and commit messages.

Type consistency:

- Runtime messages retained: `vigil_recent_findings`, `vigil_clear_findings`, `vigil_get_mode`, `vigil_set_mode`.
- Runtime messages removed: `vigil_get_tier`, `vigil_set_tier`.
- Storage key removed from ordinary path: `vigilTier`.
