# Consumer Copy/Paste Chrome Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将现有 Chrome MV3 扩展改成默认无需 Native Host 的普通用户复制粘贴守门插件，同时保留企业 provider 接口。

**Architecture:** `content-script.js` 继续负责页面事件拦截和 DOM 写回；`background.js` 改为调用 `scannerPipeline.check()`，不再默认直连 `connectNative`。扫描能力拆成浏览器本地 `consumerJsProvider` 和可插拔 `enterpriseProvider`，pipeline 按 `block > confirm_redact > allow` 合并结果。

**Tech Stack:** Chrome MV3、vanilla ES modules、Node built-in `node:test` / `node:assert`、无 npm 依赖、无构建步骤。

## Global Constraints

- 普通用户安装扩展后即可使用，不需要 Native Host 注册、桌面应用或终端命令。
- 普通模式不得把 raw text 发送到设备外。
- 扩展 storage 不得保存页面原文、脱敏后全文、原始命中值或可被字典攻击反查的全文 hash。
- 普通模式默认开启；企业模式默认关闭。
- 企业模式必须通过 provider 接口扩展，不得被硬编码成 Native Host 模式。
- 第一版只实现“脱敏后继续”和高危阻断；“本次允许”延后。
- 继续保持 vanilla JS 和 MV3 CSP 友好，不引入 npm 构建链。

---

## File Structure

- Create `extensions/chrome-mv3/redaction-rules.js`  
  本地 JS 规则、finding 元数据、脱敏和复扫 helper。

- Create `extensions/chrome-mv3/risk-decision.js`  
  将 rule findings 归一化为 `allow | confirm_redact | block`。

- Create `extensions/chrome-mv3/scanner-pipeline.js`  
  provider 链、模式配置、企业数据策略校验、结果合并。

- Create `extensions/chrome-mv3/providers/consumer-js-provider.js`  
  普通模式本地扫描 provider。

- Create `extensions/chrome-mv3/providers/enterprise-provider.js`  
  企业 provider 抽象入口，第一版实现 `disabled` 状态和策略错误。

- Create `extensions/chrome-mv3/tests/redaction-rules.test.mjs`  
  规则检测和脱敏纯函数测试。

- Create `extensions/chrome-mv3/tests/scanner-pipeline.test.mjs`  
  pipeline 合并、模式和企业数据策略测试。

- Create `extensions/chrome-mv3/tests/content-script-source.test.mjs`  
  对 content script 的关键源码不变量做轻量守门。

- Modify `extensions/chrome-mv3/background.js`  
  从 Native Host 默认路径切到 scanner pipeline；保留企业 provider 未来入口。

- Modify `extensions/chrome-mv3/content-script.js`  
  支持 `confirm_redact` 页面内确认弹窗和高危阻断弹窗。

- Modify `extensions/chrome-mv3/options.html`, `options.js`, `options.css`  
  将 Native Host 安装助手改成普通/企业模式设置。

- Modify `extensions/chrome-mv3/popup.html`, `popup.js`, `popup.css`  
  展示普通/企业模式状态和最近 findings 元数据。

- Modify `extensions/chrome-mv3/README.md`  
  更新普通用户安装体验和企业 provider 说明。

---

### Task 1: 本地规则和风险决策

**Files:**
- Create: `extensions/chrome-mv3/redaction-rules.js`
- Create: `extensions/chrome-mv3/risk-decision.js`
- Create: `extensions/chrome-mv3/tests/redaction-rules.test.mjs`

**Interfaces:**
- Produces:
  - `scanText(text: string): Array<{kind:string,severity:"medium"|"high",redactable:boolean}>`
  - `redactText(text: string, findings?: Array<object>): string`
  - `hasFindings(text: string): boolean`
  - `decideRisk(request: {request_id:string,text:string}, findings: Array<object>): {request_id:string,action:"allow"|"confirm_redact"|"block",findings:Array<object>,redacted_text?:string,source:"consumer_js",error?:string}`
- Consumes: none.

- [ ] **Step 1: Write failing rule tests**

Create `extensions/chrome-mv3/tests/redaction-rules.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import {
    scanText,
    redactText,
    hasFindings,
} from "../redaction-rules.js";
import { decideRisk } from "../risk-decision.js";

const REQUEST_ID = "11111111-1111-4111-8111-111111111111";

test("scanText detects and redacts common consumer secrets", () => {
    const text = [
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890",
        "DATABASE_URL=postgres://user:p%40ssword@example.com/db",
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ].join("\n");

    const findings = scanText(text);
    assert.deepEqual(
        findings.map((f) => f.kind).sort(),
        ["database_url", "env_assignment", "jwt", "openai_api_key"].sort(),
    );
    assert.equal(findings.every((f) => f.redactable), true);

    const redacted = redactText(text, findings);
    assert.match(redacted, /\[REDACTED openai_api_key\]/);
    assert.match(redacted, /\[REDACTED database_url\]/);
    assert.match(redacted, /\[REDACTED jwt\]/);
    assert.equal(redacted.includes("sk-proj-abcdefghijklmnopqrstuvwxyz"), false);
    assert.equal(redacted.includes("p%40ssword"), false);
    assert.equal(hasFindings(redacted), false);
});

test("decideRisk returns confirm_redact for redactable findings", () => {
    const text = "token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD";
    const findings = scanText(text);

    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.equal(result.request_id, REQUEST_ID);
    assert.equal(result.action, "confirm_redact");
    assert.deepEqual(result.findings.map((f) => f.kind), ["github_token"]);
    assert.match(result.redacted_text, /\[REDACTED github_token\]/);
});

test("PEM private key is block-only", () => {
    const text = [
        "-----BEGIN PRIVATE KEY-----",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        "-----END PRIVATE KEY-----",
    ].join("\n");

    const findings = scanText(text);
    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.equal(findings[0].kind, "pem_private_key");
    assert.equal(findings[0].severity, "high");
    assert.equal(findings[0].redactable, false);
    assert.equal(result.action, "block");
    assert.equal(result.redacted_text, undefined);
});

test("safe text is allowed", () => {
    const text = "Please summarize this public README section.";
    const findings = scanText(text);
    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.deepEqual(findings, []);
    assert.deepEqual(result, {
        request_id: REQUEST_ID,
        action: "allow",
        findings: [],
        source: "consumer_js",
    });
});
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
node --test extensions/chrome-mv3/tests/redaction-rules.test.mjs
```

Expected: FAIL with `Cannot find module` for `redaction-rules.js` or missing exports.

- [ ] **Step 3: Implement `redaction-rules.js`**

Create `extensions/chrome-mv3/redaction-rules.js`:

```js
const RULES = Object.freeze([
    {
        kind: "pem_private_key",
        severity: "high",
        redactable: false,
        pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    },
    {
        kind: "openai_api_key",
        severity: "medium",
        redactable: true,
        pattern: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        kind: "anthropic_api_key",
        severity: "medium",
        redactable: true,
        pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        kind: "google_api_key",
        severity: "medium",
        redactable: true,
        pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    },
    {
        kind: "github_token",
        severity: "medium",
        redactable: true,
        pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g,
    },
    {
        kind: "gitlab_pat",
        severity: "medium",
        redactable: true,
        pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        kind: "slack_webhook",
        severity: "medium",
        redactable: true,
        pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/+_-]+\/[A-Za-z0-9/+_-]+\/[A-Za-z0-9/+_-]+/g,
    },
    {
        kind: "stripe_secret_key",
        severity: "medium",
        redactable: true,
        pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    },
    {
        kind: "aws_access_key_id",
        severity: "medium",
        redactable: true,
        pattern: /\bA[KS]IA[0-9A-Z]{16}\b/g,
    },
    {
        kind: "jwt",
        severity: "medium",
        redactable: true,
        pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    },
    {
        kind: "database_url",
        severity: "medium",
        redactable: true,
        pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^:\s/@]+:[^@\s]+@[^\s]+/gi,
    },
    {
        kind: "env_assignment",
        severity: "medium",
        redactable: true,
        pattern: /\b[A-Z][A-Z0-9_]{2,}=(?!(?:true|false|null)\b)[^\s"'`]{6,}/g,
    },
]);

export function scanText(text) {
    if (typeof text !== "string" || text.length === 0) return [];
    const seen = new Set();
    const findings = [];
    for (const rule of RULES) {
        rule.pattern.lastIndex = 0;
        if (!rule.pattern.test(text)) continue;
        if (seen.has(rule.kind)) continue;
        seen.add(rule.kind);
        findings.push({
            kind: rule.kind,
            severity: rule.severity,
            redactable: rule.redactable,
        });
    }
    return findings;
}

export function redactText(text) {
    if (typeof text !== "string" || text.length === 0) return "";
    let redacted = text;
    for (const rule of RULES) {
        if (!rule.redactable) continue;
        rule.pattern.lastIndex = 0;
        redacted = redacted.replace(rule.pattern, `[REDACTED ${rule.kind}]`);
    }
    return redacted;
}

export function hasFindings(text) {
    return scanText(text).length > 0;
}
```

- [ ] **Step 4: Implement `risk-decision.js`**

Create `extensions/chrome-mv3/risk-decision.js`:

```js
import { hasFindings, redactText } from "./redaction-rules.js";

export function decideRisk(request, findings) {
    const requestId = request && typeof request.request_id === "string"
        ? request.request_id
        : "";
    const text = request && typeof request.text === "string" ? request.text : "";
    const cleanFindings = Array.isArray(findings) ? findings : [];

    if (cleanFindings.length === 0) {
        return {
            request_id: requestId,
            action: "allow",
            findings: [],
            source: "consumer_js",
        };
    }

    if (cleanFindings.some((finding) => finding.redactable !== true)) {
        return {
            request_id: requestId,
            action: "block",
            findings: cleanFindings,
            source: "consumer_js",
        };
    }

    const redactedText = redactText(text, cleanFindings);
    if (!redactedText || redactedText === text || hasFindings(redactedText)) {
        return {
            request_id: requestId,
            action: "block",
            findings: cleanFindings,
            source: "consumer_js",
            error: "redaction_failed",
        };
    }

    return {
        request_id: requestId,
        action: "confirm_redact",
        findings: cleanFindings,
        redacted_text: redactedText,
        source: "consumer_js",
    };
}
```

- [ ] **Step 5: Run tests and verify they pass**

Run:

```bash
node --test extensions/chrome-mv3/tests/redaction-rules.test.mjs
```

Expected: PASS, 4 tests passing.

- [ ] **Step 6: Commit**

```bash
git add extensions/chrome-mv3/redaction-rules.js \
  extensions/chrome-mv3/risk-decision.js \
  extensions/chrome-mv3/tests/redaction-rules.test.mjs
git commit -m "feat: add browser local redaction rules"
```

---

### Task 2: Scanner Pipeline 和 Provider 接口

**Files:**
- Create: `extensions/chrome-mv3/providers/consumer-js-provider.js`
- Create: `extensions/chrome-mv3/providers/enterprise-provider.js`
- Create: `extensions/chrome-mv3/scanner-pipeline.js`
- Create: `extensions/chrome-mv3/tests/scanner-pipeline.test.mjs`

**Interfaces:**
- Consumes:
  - `scanText(text)` and `decideRisk(request, findings)` from Task 1.
- Produces:
  - `createConsumerJsProvider(): { name:string, check(request): Promise<ScanResult> }`
  - `createEnterpriseProvider(config): { name:string, check(request, context): Promise<ScanResult> }`
  - `mergeScanResults(requestId, results): ScanResult`
  - `checkWithScannerPipeline(request, options): Promise<ScanResult>`

- [ ] **Step 1: Write failing pipeline tests**

Create `extensions/chrome-mv3/tests/scanner-pipeline.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import {
    checkWithScannerPipeline,
    mergeScanResults,
} from "../scanner-pipeline.js";

function request(text) {
    return {
        request_id: "22222222-2222-4222-8222-222222222222",
        origin: "https://chatgpt.com",
        event_kind: "paste",
        text,
    };
}

test("consumer mode uses local JS provider and returns confirm_redact", async () => {
    const result = await checkWithScannerPipeline(
        request("token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
        { mode: "consumer" },
    );

    assert.equal(result.action, "confirm_redact");
    assert.equal(result.source, "consumer_js");
    assert.deepEqual(result.findings.map((f) => f.kind), ["github_token"]);
});

test("mergeScanResults keeps the strictest action", () => {
    const merged = mergeScanResults("rid", [
        { request_id: "rid", action: "allow", findings: [], source: "consumer_js" },
        {
            request_id: "rid",
            action: "block",
            findings: [{ kind: "policy_block", severity: "high", redactable: false }],
            source: "enterprise",
        },
    ]);

    assert.equal(merged.action, "block");
    assert.equal(merged.source, "pipeline");
    assert.deepEqual(merged.findings.map((f) => f.kind), ["policy_block"]);
});

test("enterprise metadata_only policy does not pass raw text", async () => {
    let observedRequest;
    const provider = {
        name: "enterprise_test",
        async check(req) {
            observedRequest = req;
            return {
                request_id: req.request_id,
                action: "allow",
                findings: [],
                source: "enterprise",
            };
        },
    };

    const result = await checkWithScannerPipeline(
        request("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890"),
        {
            mode: "enterprise",
            enterprise: { provider, dataPolicy: "metadata_only" },
        },
    );

    assert.equal(result.action, "confirm_redact");
    assert.equal(Object.hasOwn(observedRequest, "text"), false);
    assert.equal(observedRequest.origin, "https://chatgpt.com");
    assert.deepEqual(observedRequest.local_findings, ["openai_api_key", "env_assignment"]);
});

test("configured but unavailable enterprise provider fails closed", async () => {
    const provider = {
        name: "enterprise_down",
        async check() {
            throw new Error("connection refused");
        },
    };

    const result = await checkWithScannerPipeline(
        request("plain text"),
        {
            mode: "enterprise",
            enterprise: { provider, dataPolicy: "raw_allowed" },
        },
    );

    assert.equal(result.action, "block");
    assert.equal(result.error, "enterprise_provider_failed");
});
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
node --test extensions/chrome-mv3/tests/scanner-pipeline.test.mjs
```

Expected: FAIL with `Cannot find module` for `scanner-pipeline.js`.

- [ ] **Step 3: Implement consumer provider**

Create `extensions/chrome-mv3/providers/consumer-js-provider.js`:

```js
import { scanText } from "../redaction-rules.js";
import { decideRisk } from "../risk-decision.js";

export function createConsumerJsProvider() {
    return {
        name: "consumer_js",
        async check(request) {
            const findings = scanText(request && request.text);
            return decideRisk(request, findings);
        },
    };
}
```

- [ ] **Step 4: Implement enterprise provider disabled state**

Create `extensions/chrome-mv3/providers/enterprise-provider.js`:

```js
export const ENTERPRISE_DATA_POLICIES = Object.freeze([
    "local_only",
    "metadata_only",
    "raw_allowed",
]);

export function createEnterpriseProvider(config = {}) {
    if (config.provider) return config.provider;
    return {
        name: "enterprise_disabled",
        async check(request) {
            return {
                request_id: request.request_id,
                action: "allow",
                findings: [],
                source: "enterprise",
                error: "enterprise_not_configured",
            };
        },
    };
}
```

- [ ] **Step 5: Implement scanner pipeline**

Create `extensions/chrome-mv3/scanner-pipeline.js`:

```js
import { createConsumerJsProvider } from "./providers/consumer-js-provider.js";
import { createEnterpriseProvider } from "./providers/enterprise-provider.js";

const ACTION_RANK = Object.freeze({
    allow: 0,
    confirm_redact: 1,
    redact: 1,
    block: 2,
});

export function mergeScanResults(requestId, results) {
    const valid = Array.isArray(results) ? results.filter(Boolean) : [];
    let strictest = {
        request_id: requestId,
        action: "allow",
        findings: [],
        source: "pipeline",
    };
    const findingsByKind = new Map();

    for (const result of valid) {
        for (const finding of Array.isArray(result.findings) ? result.findings : []) {
            if (finding && typeof finding.kind === "string") {
                findingsByKind.set(finding.kind, finding);
            }
        }
        const normalizedAction = result.action === "redact" ? "confirm_redact" : result.action;
        const nextRank = Object.hasOwn(ACTION_RANK, normalizedAction)
            ? ACTION_RANK[normalizedAction]
            : 2;
        const currentRank = Object.hasOwn(ACTION_RANK, strictest.action)
            ? ACTION_RANK[strictest.action]
            : 0;
        if (nextRank >= currentRank) {
            strictest = {
                ...result,
                action: normalizedAction,
                source: "pipeline",
            };
        }
    }

    return {
        ...strictest,
        request_id: requestId,
        findings: Array.from(findingsByKind.values()),
    };
}

function metadataOnlyRequest(request, localResult) {
    return {
        request_id: request.request_id,
        origin: request.origin,
        event_kind: request.event_kind,
        length_bucket: lengthBucket(request.text.length),
        local_findings: (localResult.findings || []).map((finding) => finding.kind),
    };
}

function lengthBucket(length) {
    if (length <= 100) return "0-100";
    if (length <= 500) return "100-500";
    if (length <= 2000) return "500-2000";
    return "2000+";
}

export async function checkWithScannerPipeline(request, options = {}) {
    const mode = options.mode === "enterprise" ? "enterprise" : "consumer";
    const consumerProvider = options.consumerProvider || createConsumerJsProvider();
    const localResult = await consumerProvider.check(request);
    const results = [localResult];

    if (mode === "enterprise") {
        const enterpriseConfig = options.enterprise || {};
        const dataPolicy = enterpriseConfig.dataPolicy || "local_only";
        const enterpriseProvider = createEnterpriseProvider(enterpriseConfig);
        try {
            let enterpriseRequest;
            if (dataPolicy === "raw_allowed") {
                enterpriseRequest = request;
            } else if (dataPolicy === "metadata_only") {
                enterpriseRequest = metadataOnlyRequest(request, localResult);
            } else {
                enterpriseRequest = metadataOnlyRequest(request, localResult);
                enterpriseRequest.local_only = true;
            }
            results.push(await enterpriseProvider.check(enterpriseRequest, { dataPolicy }));
        } catch {
            results.push({
                request_id: request.request_id,
                action: "block",
                findings: [],
                source: "enterprise",
                error: "enterprise_provider_failed",
            });
        }
    }

    return mergeScanResults(request.request_id, results);
}
```

- [ ] **Step 6: Run pipeline tests**

Run:

```bash
node --test extensions/chrome-mv3/tests/scanner-pipeline.test.mjs
```

Expected: PASS, 4 tests passing.

- [ ] **Step 7: Run Task 1 tests again**

Run:

```bash
node --test extensions/chrome-mv3/tests/redaction-rules.test.mjs
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add extensions/chrome-mv3/providers/consumer-js-provider.js \
  extensions/chrome-mv3/providers/enterprise-provider.js \
  extensions/chrome-mv3/scanner-pipeline.js \
  extensions/chrome-mv3/tests/scanner-pipeline.test.mjs
git commit -m "feat: add scanner provider pipeline"
```

---

### Task 3: Background 默认接入本地 Pipeline

**Files:**
- Modify: `extensions/chrome-mv3/background.js`
- Modify: `extensions/chrome-mv3/manifest.json`
- Create: `extensions/chrome-mv3/tests/background-consumer-mode.test.mjs`
- Modify: `extensions/chrome-mv3/tests/background-security.test.mjs`

**Interfaces:**
- Consumes:
  - `checkWithScannerPipeline(request, options)` from Task 2.
- Produces:
  - `vigil_check` 默认通过 scanner pipeline 响应。
  - `vigil_get_mode` / `vigil_set_mode` runtime messages for popup/options.

- [ ] **Step 1: Write failing source-level background tests**

Create `extensions/chrome-mv3/tests/background-consumer-mode.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const backgroundSource = readFileSync(
    resolve(repoRoot, "extensions/chrome-mv3/background.js"),
    "utf8",
);
const manifestSource = readFileSync(
    resolve(repoRoot, "extensions/chrome-mv3/manifest.json"),
    "utf8",
);

test("background imports scanner pipeline", () => {
    assert.match(
        backgroundSource,
        /import\s+\{\s*checkWithScannerPipeline\s*\}\s+from\s+"\.\/scanner-pipeline\.js"/,
    );
});

test("vigil_check no longer calls checkWithHost directly", () => {
    assert.doesNotMatch(
        backgroundSource,
        /return\s+checkWithHost\(\{\s*origin:\s*msg\.origin/s,
    );
    assert.match(backgroundSource, /checkWithScannerPipeline\(\s*\{/);
});

test("nativeMessaging permission is not required for consumer default", () => {
    const manifest = JSON.parse(manifestSource);
    assert.equal(
        manifest.permissions.includes("nativeMessaging"),
        false,
        "consumer default extension must not require nativeMessaging permission",
    );
});

test("mode runtime messages exist", () => {
    assert.match(backgroundSource, /msg\.type\s*===\s*"vigil_get_mode"/);
    assert.match(backgroundSource, /msg\.type\s*===\s*"vigil_set_mode"/);
});
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
node --test extensions/chrome-mv3/tests/background-consumer-mode.test.mjs
```

Expected: FAIL because `background.js` has not imported `scanner-pipeline.js`, and `manifest.json` still includes `nativeMessaging`.

- [ ] **Step 3: Update imports and mode constants in `background.js`**

Modify the import section near the top of `extensions/chrome-mv3/background.js`:

```js
import {
    TIER_VALUES,
    TIER_DEFAULT,
    applyTierDecision,
} from "./tier-decision.js";
import { normalizeCustomSiteInput } from "./custom-sites.js";
import { checkWithScannerPipeline } from "./scanner-pipeline.js";
```

Add mode constants near existing storage keys:

```js
const MODE_STORAGE_KEY = "vigilMode";
const MODE_VALUES = Object.freeze(["consumer", "enterprise"]);
const MODE_DEFAULT = "consumer";
```

Add in-memory mode state near `currentTier`:

```js
let currentMode = MODE_DEFAULT;
```

Add a loader near `loadStoredTier()`:

```js
async function loadStoredMode() {
    const got = await storageGet({ [MODE_STORAGE_KEY]: MODE_DEFAULT });
    const mode = got[MODE_STORAGE_KEY];
    currentMode = MODE_VALUES.includes(mode) ? mode : MODE_DEFAULT;
}
```

- [ ] **Step 4: Replace `vigil_check` Host call with pipeline call**

In the `msg.type === "vigil_check"` branch, replace the `checkWithHost({...}).then(...)` block with:

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
        recordFinding({
            ts: Date.now(),
            origin: msg.origin || "?",
            event_kind: msg.event_kind || "?",
            action: resp.action,
            findings: (resp.findings || []).map((finding) =>
                typeof finding === "string" ? finding : finding.kind,
            ),
        });
        sendResponse(resp);
    });
```

Keep `checkWithHost()` temporarily if enterprise Native Host reintroduction will use it later, but do not call it from consumer default. If it remains unused, add a comment:

```js
// Reserved for a future enterprise native_host provider. Consumer mode does not call this path.
```

- [ ] **Step 5: Add mode runtime messages**

Add before the tier message handlers:

```js
if (msg.type === "vigil_get_mode") {
    sendResponse({
        mode: currentMode,
        default: MODE_DEFAULT,
        values: MODE_VALUES.slice(),
    });
    return false;
}

if (msg.type === "vigil_set_mode") {
    const next = typeof msg.mode === "string" ? msg.mode : "";
    if (!MODE_VALUES.includes(next)) {
        sendResponse({ ok: false, _error: "invalid_mode" });
        return false;
    }
    currentMode = next;
    storageSet({ [MODE_STORAGE_KEY]: currentMode }).catch(() => {});
    sendResponse({ ok: true, mode: currentMode });
    return false;
}
```

Update startup:

```js
loadStoredMode().catch(() => {});
loadStoredTier().catch(() => {});
```

Update activate `Promise.all`:

```js
Promise.all([
    self.clients.claim(),
    loadStoredMode(),
    loadStoredTier(),
    syncCustomContentScripts(),
]).catch(() => {})
```

Update storage change listener:

```js
if (areaName === "local" && changes[MODE_STORAGE_KEY]) {
    const next = changes[MODE_STORAGE_KEY].newValue;
    currentMode = MODE_VALUES.includes(next) ? next : MODE_DEFAULT;
}
```

- [ ] **Step 6: Remove default `nativeMessaging` permission**

Modify `extensions/chrome-mv3/manifest.json` permissions array from:

```json
"permissions": [
  "nativeMessaging",
  "activeTab",
  "storage",
  "scripting"
]
```

to:

```json
"permissions": [
  "activeTab",
  "storage",
  "scripting"
]
```

- [ ] **Step 7: Run background tests**

Run:

```bash
node --test extensions/chrome-mv3/tests/background-consumer-mode.test.mjs
node --test extensions/chrome-mv3/tests/background-security.test.mjs
```

Expected: both PASS. If `background-security.test.mjs` still assumes Native Host fail-closed wording, update only that assertion to require `vigil_check unexpected errors must fail closed`, not Native Host-specific behavior.

- [ ] **Step 8: Run prior tests**

Run:

```bash
node --test extensions/chrome-mv3/tests/redaction-rules.test.mjs
node --test extensions/chrome-mv3/tests/scanner-pipeline.test.mjs
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add extensions/chrome-mv3/background.js \
  extensions/chrome-mv3/manifest.json \
  extensions/chrome-mv3/tests/background-consumer-mode.test.mjs \
  extensions/chrome-mv3/tests/background-security.test.mjs
git commit -m "feat: route extension checks through local scanner"
```

---

### Task 4: Content Script 页面内确认弹窗

**Files:**
- Modify: `extensions/chrome-mv3/content-script.js`
- Create: `extensions/chrome-mv3/tests/content-script-source.test.mjs`

**Interfaces:**
- Consumes:
  - Background response action `allow | confirm_redact | block`.
  - `redacted_text` for `confirm_redact`.
- Produces:
  - Inline confirmation UI with buttons `脱敏后继续` and `阻断`.
  - High-risk block UI without continue action.

- [ ] **Step 1: Write failing content-script source tests**

Create `extensions/chrome-mv3/tests/content-script-source.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const source = readFileSync(
    resolve(repoRoot, "extensions/chrome-mv3/content-script.js"),
    "utf8",
);

test("content script handles confirm_redact responses", () => {
    assert.match(source, /confirm_redact/);
    assert.match(source, /showRiskPrompt/);
    assert.match(source, /脱敏后继续/);
});

test("risk prompt uses textContent and not innerHTML", () => {
    assert.match(source, /textContent\s*=/);
    assert.doesNotMatch(source, /\.innerHTML\s*=/);
});

test("block-only UI does not include allow-once wording", () => {
    assert.match(source, /showBlockPrompt/);
    assert.doesNotMatch(source, /本次允许/);
});
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
node --test extensions/chrome-mv3/tests/content-script-source.test.mjs
```

Expected: FAIL because `confirm_redact`, `showRiskPrompt`, and `showBlockPrompt` are not present.

- [ ] **Step 3: Add prompt helpers to `content-script.js`**

Inside the IIFE, near toast helpers, add:

```js
let riskPromptEl = null;

function closeRiskPrompt() {
    if (riskPromptEl) {
        riskPromptEl.remove();
        riskPromptEl = null;
    }
}

function findingLabel(finding) {
    const kind = typeof finding === "string" ? finding : finding && finding.kind;
    const labels = {
        openai_api_key: "OpenAI API key",
        anthropic_api_key: "Anthropic API key",
        google_api_key: "Google API key",
        github_token: "GitHub token",
        gitlab_pat: "GitLab token",
        slack_webhook: "Slack webhook",
        stripe_secret_key: "Stripe secret key",
        aws_access_key_id: "AWS access key",
        jwt: "JWT",
        env_assignment: ".env 变量",
        database_url: "数据库连接串",
        pem_private_key: "私钥",
    };
    return labels[kind] || String(kind || "未知风险");
}

function mountPromptBase(title, findings) {
    closeRiskPrompt();
    const parent = document.body || document.documentElement;
    if (!parent) return null;

    const box = document.createElement("div");
    box.setAttribute("data-vigil-safe-prompt", "");
    Object.assign(box.style, {
        position: "fixed",
        right: "16px",
        bottom: "16px",
        zIndex: "2147483647",
        width: "min(380px, calc(100vw - 32px))",
        padding: "14px",
        borderRadius: "8px",
        background: "#ffffff",
        color: "#111827",
        boxShadow: "0 18px 48px rgba(15, 23, 42, 0.28)",
        fontFamily: "system-ui, -apple-system, sans-serif",
        fontSize: "13px",
        lineHeight: "1.45",
        border: "1px solid rgba(15, 23, 42, 0.12)",
    });

    const heading = document.createElement("div");
    heading.style.fontWeight = "700";
    heading.style.marginBottom = "8px";
    heading.textContent = title;
    box.appendChild(heading);

    const body = document.createElement("div");
    body.textContent = `检测到：${(findings || []).map(findingLabel).join("、") || "风险内容"}`;
    box.appendChild(body);

    const privacy = document.createElement("div");
    privacy.style.marginTop = "6px";
    privacy.style.color = "#4b5563";
    privacy.textContent = "原文未离开你的浏览器。";
    box.appendChild(privacy);

    const actions = document.createElement("div");
    actions.style.display = "flex";
    actions.style.gap = "8px";
    actions.style.marginTop = "12px";
    actions.style.justifyContent = "flex-end";
    box.appendChild(actions);

    parent.appendChild(box);
    riskPromptEl = box;
    return actions;
}

function promptButton(label, tone) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    Object.assign(btn.style, {
        border: "0",
        borderRadius: "6px",
        padding: "8px 10px",
        cursor: "pointer",
        fontWeight: "700",
        color: "#ffffff",
        background: tone === "primary" ? "#2563eb" : "#374151",
    });
    return btn;
}

function showRiskPrompt(response, onRedact) {
    const actions = mountPromptBase("Vigils 发现风险内容", response.findings || []);
    if (!actions) return;
    const redactBtn = promptButton("脱敏后继续", "primary");
    redactBtn.addEventListener("click", () => {
        closeRiskPrompt();
        onRedact(response.redacted_text || "");
    });
    const blockBtn = promptButton("阻断", "secondary");
    blockBtn.addEventListener("click", closeRiskPrompt);
    actions.append(redactBtn, blockBtn);
}

function showBlockPrompt(response) {
    const actions = mountPromptBase("Vigils 已阻断高危内容", response.findings || []);
    if (!actions) return;
    const closeBtn = promptButton("关闭", "secondary");
    closeBtn.addEventListener("click", closeRiskPrompt);
    actions.appendChild(closeBtn);
}
```

- [ ] **Step 4: Wire response handling**

Find the response handling paths that currently branch on `resp.action === "redact"` and add `confirm_redact` as the user-confirmed redaction path.

For paste handling, use this shape:

```js
if (resp.action === "confirm_redact") {
    event.preventDefault();
    showRiskPrompt(resp, (redactedText) => {
        applyTextToTarget(target, redactedText);
        showToast("Vigils: 已脱敏后写入", "info");
    });
    return;
}
```

For submit handling, use this shape:

```js
if (resp.action === "confirm_redact") {
    event.preventDefault();
    showRiskPrompt(resp, (redactedText) => {
        if (primaryInput) {
            setElementText(primaryInput, redactedText);
            continueSubmit(form, submitter);
        } else {
            showToast("Vigils: 无法定位输入框，已阻断", "error");
        }
    });
    return;
}
```

Use existing local helper names for text writeback and submit continuation. If current helper names differ, preserve existing behavior and only insert the `showRiskPrompt` gate before writeback/submit.

For block handling:

```js
if (resp.action === "block") {
    event.preventDefault();
    showBlockPrompt(resp);
    return;
}
```

- [ ] **Step 5: Run content-script source test**

Run:

```bash
node --test extensions/chrome-mv3/tests/content-script-source.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Run all extension Node tests so far**

Run:

```bash
node --test \
  extensions/chrome-mv3/tests/redaction-rules.test.mjs \
  extensions/chrome-mv3/tests/scanner-pipeline.test.mjs \
  extensions/chrome-mv3/tests/background-consumer-mode.test.mjs \
  extensions/chrome-mv3/tests/background-security.test.mjs \
  extensions/chrome-mv3/tests/content-script-source.test.mjs
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add extensions/chrome-mv3/content-script.js \
  extensions/chrome-mv3/tests/content-script-source.test.mjs
git commit -m "feat: add inline redaction confirmation"
```

---

### Task 5: Options 和 Popup 的普通/企业模式 UI

**Files:**
- Modify: `extensions/chrome-mv3/options.html`
- Modify: `extensions/chrome-mv3/options.js`
- Modify: `extensions/chrome-mv3/options.css`
- Modify: `extensions/chrome-mv3/popup.html`
- Modify: `extensions/chrome-mv3/popup.js`
- Modify: `extensions/chrome-mv3/popup.css`
- Create: `extensions/chrome-mv3/tests/ui-copy-source.test.mjs`

**Interfaces:**
- Consumes:
  - Runtime messages `vigil_get_mode` and `vigil_set_mode` from Task 3.
- Produces:
  - Options mode toggle.
  - Enterprise connection section hidden/collapsed unless enterprise mode is enabled.
  - Popup mode status text.

- [ ] **Step 1: Write failing UI copy source tests**

Create `extensions/chrome-mv3/tests/ui-copy-source.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");

function read(rel) {
    return readFileSync(resolve(repoRoot, rel), "utf8");
}

test("options no longer centers native host install as default path", () => {
    const html = read("extensions/chrome-mv3/options.html");
    const js = read("extensions/chrome-mv3/options.js");
    assert.match(html, /普通模式/);
    assert.match(html, /企业模式/);
    assert.match(html, /企业连接/);
    assert.doesNotMatch(js, /vigil-native-host install --extension-id/);
});

test("options uses mode runtime messages", () => {
    const js = read("extensions/chrome-mv3/options.js");
    assert.match(js, /vigil_get_mode/);
    assert.match(js, /vigil_set_mode/);
});

test("popup displays consumer and enterprise mode labels", () => {
    const html = read("extensions/chrome-mv3/popup.html");
    const js = read("extensions/chrome-mv3/popup.js");
    assert.match(html + js, /普通保护/);
    assert.match(html + js, /企业保护/);
});
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
node --test extensions/chrome-mv3/tests/ui-copy-source.test.mjs
```

Expected: FAIL because options still contains Native Host install helper copy and no mode UI.

- [ ] **Step 3: Update options HTML**

In `extensions/chrome-mv3/options.html`, replace the Native Host install command panel with:

```html
<section class="panel">
  <h2>保护模式</h2>
  <div class="mode-row">
    <label>
      <input type="radio" name="vigil-mode" value="consumer">
      普通模式
    </label>
    <p>检测在浏览器内完成，原文不会离开浏览器。</p>
  </div>
  <div class="mode-row">
    <label>
      <input type="radio" name="vigil-mode" value="enterprise">
      企业模式
    </label>
    <p>启用企业 provider 接口。第一版未配置 provider 时仍使用普通保护。</p>
  </div>
  <p id="mode-hint" class="hint"></p>
</section>

<section id="enterprise-section" class="panel hidden">
  <h2>企业连接</h2>
  <label for="enterprise-provider-type">Provider 类型</label>
  <select id="enterprise-provider-type" disabled>
    <option value="disabled">尚未配置</option>
    <option value="native_host">Native Host</option>
    <option value="localhost">Localhost Agent</option>
    <option value="https_api">企业 HTTPS API</option>
    <option value="wasm">浏览器内 Wasm</option>
  </select>

  <label for="enterprise-data-policy">数据策略</label>
  <select id="enterprise-data-policy" disabled>
    <option value="local_only">local_only：不发送原文</option>
    <option value="metadata_only">metadata_only：只发送元数据</option>
    <option value="raw_allowed">raw_allowed：允许发送原文</option>
  </select>
  <p class="hint">企业连接能力已预留，真实 provider 将在后续版本接入。</p>
</section>
```

Keep the existing custom protected sites section.

- [ ] **Step 4: Update options JS**

In `extensions/chrome-mv3/options.js`, remove command construction for `vigil-native-host install` and add:

```js
const modeInputs = Array.from(document.querySelectorAll("input[name='vigil-mode']"));
const modeHint = document.getElementById("mode-hint");
const enterpriseSection = document.getElementById("enterprise-section");

function setEnterpriseVisible(mode) {
    if (!enterpriseSection) return;
    enterpriseSection.classList.toggle("hidden", mode !== "enterprise");
}

async function refreshMode() {
    const resp = await sendRuntimeMessage({ type: "vigil_get_mode" });
    const mode = resp && resp.mode === "enterprise" ? "enterprise" : "consumer";
    for (const input of modeInputs) {
        input.checked = input.value === mode;
    }
    setEnterpriseVisible(mode);
    if (modeHint) {
        modeHint.textContent = mode === "enterprise"
            ? "企业模式已开启。未配置 provider 时仍使用普通保护。"
            : "普通模式保护中：检测在浏览器内完成。";
    }
}

for (const input of modeInputs) {
    input.addEventListener("change", async () => {
        if (!input.checked) return;
        const resp = await sendRuntimeMessage({
            type: "vigil_set_mode",
            mode: input.value,
        });
        if (!resp || !resp.ok) {
            flashCustomSiteHint(`模式切换失败:${resp && resp._error}`, "warn");
            await refreshMode();
            return;
        }
        await refreshMode();
    });
}
```

Call `refreshMode()` during page initialization next to `refreshCustomSites()`.

- [ ] **Step 5: Update popup mode display**

In `extensions/chrome-mv3/popup.html`, add a mode label near the status pill:

```html
<div class="mode-line">
  <span>模式</span>
  <strong id="mode-label">普通保护</strong>
</div>
```

In `extensions/chrome-mv3/popup.js`, add:

```js
const modeLabel = document.getElementById("mode-label");

function refreshMode() {
    chrome.runtime.sendMessage({ type: "vigil_get_mode" }, (resp) => {
        if (chrome.runtime.lastError) return;
        const mode = resp && resp.mode === "enterprise" ? "enterprise" : "consumer";
        if (modeLabel) {
            modeLabel.textContent = mode === "enterprise" ? "企业保护" : "普通保护";
        }
    });
}
```

Call `refreshMode()` where popup currently calls `refresh()`, `refreshExempt()`, and `refreshTier()`.

- [ ] **Step 6: Add CSS**

In `options.css`:

```css
.mode-row {
  display: grid;
  gap: 4px;
  margin: 12px 0;
}

.mode-row label {
  font-weight: 700;
}

.hint {
  color: #64748b;
  font-size: 12px;
}
```

In `popup.css`:

```css
.mode-line {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin: 8px 0 12px;
  font-size: 12px;
}
```

- [ ] **Step 7: Run UI tests**

Run:

```bash
node --test extensions/chrome-mv3/tests/ui-copy-source.test.mjs
```

Expected: PASS.

- [ ] **Step 8: Run all extension tests**

Run:

```bash
node --test extensions/chrome-mv3/tests/*.test.mjs
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add extensions/chrome-mv3/options.html \
  extensions/chrome-mv3/options.js \
  extensions/chrome-mv3/options.css \
  extensions/chrome-mv3/popup.html \
  extensions/chrome-mv3/popup.js \
  extensions/chrome-mv3/popup.css \
  extensions/chrome-mv3/tests/ui-copy-source.test.mjs
git commit -m "feat: add consumer and enterprise mode UI"
```

---

### Task 6: README、最终验证和手工检查

**Files:**
- Modify: `extensions/chrome-mv3/README.md`
- Modify: `docs/superpowers/specs/2026-06-24-consumer-copy-paste-extension-design.md` only if implementation reveals a spec wording mismatch.

**Interfaces:**
- Consumes: completed extension behavior from Tasks 1-5.
- Produces: updated developer/user documentation and final verification evidence.

- [ ] **Step 1: Update README consumer path**

In `extensions/chrome-mv3/README.md`, replace the opening scope paragraph with:

```md
# chrome-mv3 — Vigils Browser Guard Extension

Chrome MV3 扩展，默认提供普通用户可直接使用的复制粘贴守门能力。普通模式在浏览器内用轻量 JS 规则检测常见密钥、token、JWT、`.env` 和数据库连接串；不需要 Native Host、不需要 Vigils 桌面应用、不需要终端命令。

企业模式保留 provider 接口，后续可以接 Native Host、localhost agent、企业 HTTPS API、浏览器内 Wasm 或其他受管 provider。Native Host 是企业 provider 的一种未来实现，不是普通用户默认依赖。
```

- [ ] **Step 2: Update README local loading section**

Replace Native Host-required local loading wording with:

```md
## 本地加载

1. Chrome `chrome://extensions/` → 打开 Developer mode。
2. Load unpacked → 选择 `extensions/chrome-mv3/`。
3. 打开受保护 AI 网站，粘贴含测试 token 的文本。
4. 普通风险应出现“脱敏后继续 / 阻断”页面内确认；PEM 私钥应被强阻断。

普通模式不需要注册 `com.vigil.host`。企业模式的真实 provider 接入留给后续版本。
```

- [ ] **Step 3: Run all extension tests**

Run:

```bash
node --test extensions/chrome-mv3/tests/*.test.mjs
```

Expected: PASS.

- [ ] **Step 4: Run repository status checks**

Run:

```bash
git status --short
```

Expected: only README and any intended documentation files are modified before commit.

- [ ] **Step 5: Optional manual Chrome smoke test**

Load unpacked extension from:

```text
/Users/wengzhenqi/code/vigils/.worktrees/chrome-consumer-copy-paste-extension/extensions/chrome-mv3
```

Manual scenarios:

```text
1. Open https://chatgpt.com/.
2. Paste: OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890
3. Expected: inline prompt appears with “脱敏后继续” and “阻断”.
4. Click “脱敏后继续”.
5. Expected: input text contains [REDACTED openai_api_key].
6. Paste a PEM private key block.
7. Expected: high-risk block prompt appears and no continue button is shown.
```

If Chrome manual testing is not available, record that it was not run and rely on Node tests plus source guards.

- [ ] **Step 6: Commit docs**

```bash
git add extensions/chrome-mv3/README.md \
  docs/superpowers/specs/2026-06-24-consumer-copy-paste-extension-design.md
git commit -m "docs: update chrome extension consumer mode guide"
```

- [ ] **Step 7: Final verification command**

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

No uncommitted changes should remain unless manual test notes were intentionally left for review.

---

## Self-Review

Spec coverage:

- 默认普通模式、无需 Native Host：Task 3 removes default `nativeMessaging` and routes through pipeline; Task 6 updates docs.
- 浏览器本地 JS 规则：Task 1 and Task 2 implement rules/provider.
- 企业 provider 接口：Task 2 defines enterprise provider and data policy behavior; Task 5 exposes mode UI.
- 页面内确认弹窗：Task 4 implements `confirm_redact` and block-only prompts.
- 不保存原文：Task 1 avoids raw span persistence; Task 3 logs finding kinds only; Task 5 UI displays metadata only.
- 测试边界：Tasks 1-6 include Node tests and final extension test command.

Red-flag scan:

- No unfinished-marker text, vague error-handling instructions, or cross-task shorthand is intentionally present.

Type consistency:

- `confirm_redact` is introduced in Task 1, merged in Task 2, returned from background in Task 3, handled by content script in Task 4, and documented in Task 6.
- `consumerJsProvider`, `enterpriseProvider`, and `scannerPipeline.check` naming is consistent across tasks.
