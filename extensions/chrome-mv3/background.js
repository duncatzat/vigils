// Chrome MV3 service worker —— Vigils Browser Guard 编排层。
//
// 默认架构(普通用户路径):
//   content-script.js  ──sendMessage(event)──▶  background.js
//                                                   │ checkWithScannerPipeline()
//                                                   ▼
//                                      browser-local consumer JS provider
//                                                   │
//                                      ◀──BrowserCheckResponse───────────────
//
// 企业 provider 接口保留 Native Host / localhost agent / HTTPS API / Wasm 等未来实现,
// 但普通模式默认不要求 Native Host、桌面 app 或终端注册步骤。
//
// 响应协议:
//   Request  : { request_id, origin, event_kind: "paste"|"input"|"submit", text }
//   Response : { request_id, action: "allow"|"confirm_redact"|"block", findings: [...], redacted_text? }
//
// 安全契约(ADR 0009 §I-9):
//   §I-9.1  text 永不入 chrome.storage / console.log / window.*
//   §I-9.3  特权 scheme 由 service worker fail-closed 早退
//   §I-9.5  本层做 32 MB 明显超大早退,避免扩展消息处理异常影响 SW 存活

import { normalizeCustomSiteInput } from "./custom-sites.js";
import { checkWithScannerPipeline } from "./scanner-pipeline.js";
import { normalizeCustomRiskRuleInput, normalizeCustomRiskRules } from "./redaction-rules.js";

const MAX_TEXT_CHARS = 32 * 1024 * 1024; // 32 MB 字符早退,避免超大文本拖垮 SW 消息处理
const CUSTOM_SITES_STORAGE_KEY = "customProtectedSites";
const CUSTOM_RISK_RULES_STORAGE_KEY = "customRiskRules";
const CUSTOM_CONTENT_SCRIPT_ID = "vigil-custom-protected-sites";
const MODE_STORAGE_KEY = "vigilMode";
const MODE_VALUES = Object.freeze(["consumer", "enterprise"]);
const MODE_DEFAULT = "consumer";
const EXTENSION_ORIGIN = `chrome-extension://${chrome.runtime.id}`;
/** @type {string} 当前模式,in-memory session 级 */
let currentMode = MODE_DEFAULT;

// ───────────────────────── 自定义目标网站白名单 ─────────────────────────
//
// 用户在 options 页添加域名后,options 先在点击手势内请求 host permission,再让
// SW 做持久化 + 动态 content script 注册。storage 中只存 host/pattern 元数据,不存页面原文。

function storageGet(defaults) {
    return new Promise((resolve) => {
        chrome.storage.local.get(defaults, (value) => resolve(value || defaults));
    });
}

function storageSet(value) {
    return new Promise((resolve, reject) => {
        chrome.storage.local.set(value, () => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
            } else {
                resolve();
            }
        });
    });
}

async function loadStoredMode() {
    const got = await storageGet({ [MODE_STORAGE_KEY]: MODE_DEFAULT });
    const mode = got[MODE_STORAGE_KEY];
    currentMode = MODE_VALUES.includes(mode) ? mode : MODE_DEFAULT;
}

async function loadCustomSites() {
    const got = await storageGet({ [CUSTOM_SITES_STORAGE_KEY]: [] });
    const rawSites = got[CUSTOM_SITES_STORAGE_KEY];
    if (!Array.isArray(rawSites)) return [];
    const clean = [];
    const seen = new Set();
    for (const site of rawSites) {
        if (!site || typeof site.host !== "string") continue;
        const normalized = normalizeCustomSiteInput(site.host);
        if (!normalized.ok || seen.has(normalized.pattern)) continue;
        seen.add(normalized.pattern);
        clean.push({
            host: normalized.host,
            pattern: normalized.pattern,
            addedAt:
                typeof site.addedAt === "number" && Number.isFinite(site.addedAt)
                    ? site.addedAt
                    : Date.now(),
        });
    }
    return clean;
}

async function saveCustomSites(sites) {
    await storageSet({ [CUSTOM_SITES_STORAGE_KEY]: sites });
}

async function loadCustomRiskRules() {
    const got = await storageGet({ [CUSTOM_RISK_RULES_STORAGE_KEY]: [] });
    return normalizeCustomRiskRules(got[CUSTOM_RISK_RULES_STORAGE_KEY]);
}

async function saveCustomRiskRules(rules) {
    await storageSet({ [CUSTOM_RISK_RULES_STORAGE_KEY]: normalizeCustomRiskRules(rules) });
}

function permissionsContains(origins) {
    return new Promise((resolve) => {
        chrome.permissions.contains({ origins }, (allowed) => {
            resolve(Boolean(allowed));
        });
    });
}

function permissionsRemove(origins) {
    return new Promise((resolve) => {
        chrome.permissions.remove({ origins }, (removed) => resolve(Boolean(removed)));
    });
}

function patternForOrigin(origin) {
    try {
        const url = new URL(origin);
        if (url.protocol !== "https:" && url.protocol !== "http:") return null;
        return `${url.origin}/*`;
    } catch {
        return null;
    }
}

async function isProtectedOrigin(origin) {
    const pattern = patternForOrigin(origin);
    if (!pattern) return false;
    if (isRequiredHostPattern(pattern)) return true;
    return Promise.race([
        permissionsContains([pattern]),
        new Promise((resolve) => setTimeout(() => resolve(true), 500)),
    ]);
}

function isRequiredHostPattern(pattern) {
    const manifest = chrome.runtime.getManifest();
    const hostPermissions = Array.isArray(manifest.host_permissions)
        ? manifest.host_permissions
        : [];
    return hostPermissions.includes(pattern);
}

function isTrustedExtensionSender(sender) {
    if (!sender) return false;
    if (sender.id === chrome.runtime.id) return true;
    if (typeof sender.url === "string" && sender.url.startsWith(`${EXTENSION_ORIGIN}/`)) {
        return true;
    }
    return false;
}

function unregisterCustomContentScript() {
    return new Promise((resolve) => {
        if (!chrome.scripting || !chrome.scripting.unregisterContentScripts) {
            resolve();
            return;
        }
        chrome.scripting.unregisterContentScripts(
            { ids: [CUSTOM_CONTENT_SCRIPT_ID] },
            () => {
                // Idempotent sync: Chrome sets lastError when the script id has never
                // been registered. Reading it prevents "Unchecked runtime.lastError".
                void chrome.runtime.lastError;
                resolve();
            },
        );
    });
}

function registerCustomContentScript(matches) {
    return new Promise((resolve, reject) => {
        chrome.scripting.registerContentScripts(
            [
                {
                    id: CUSTOM_CONTENT_SCRIPT_ID,
                    matches,
                    js: ["content-script.js"],
                    runAt: "document_idle",
                    allFrames: true,
                    persistAcrossSessions: true,
                },
            ],
            () => {
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                } else {
                    resolve();
                }
            },
        );
    });
}

let customContentScriptSyncTail = Promise.resolve();

async function syncCustomContentScriptsNow() {
    const sites = await loadCustomSites();
    const matches = [];
    for (const site of sites) {
        if (await permissionsContains([site.pattern])) {
            matches.push(site.pattern);
        }
    }
    await unregisterCustomContentScript();
    if (matches.length === 0) return;
    await registerCustomContentScript(matches);
}

function syncCustomContentScripts() {
    const run = customContentScriptSyncTail
        .catch(() => {})
        .then(syncCustomContentScriptsNow);
    customContentScriptSyncTail = run.catch(() => {});
    return run;
}

function tabsQuery(queryInfo) {
    return new Promise((resolve) => {
        chrome.tabs.query(queryInfo, (tabs) => resolve(Array.isArray(tabs) ? tabs : []));
    });
}

function executeContentScript(tabId) {
    return new Promise((resolve) => {
        chrome.scripting.executeScript(
            {
                target: { tabId, allFrames: true },
                files: ["content-script.js"],
            },
            () => resolve(),
        );
    });
}

function sendDisableGuardMessage(tabId, origin) {
    return new Promise((resolve) => {
        chrome.tabs.sendMessage(tabId, { type: "vigil_disable_guard", origin }, () => {
            void chrome.runtime.lastError;
            resolve();
        });
    });
}

function sendEnableGuardMessage(tabId, origin) {
    return new Promise((resolve) => {
        chrome.tabs.sendMessage(tabId, { type: "vigil_enable_guard", origin }, () => {
            void chrome.runtime.lastError;
            resolve();
        });
    });
}

function forceDisableGuard(tabId, origin) {
    return new Promise((resolve) => {
        chrome.scripting.executeScript(
            {
                target: { tabId, allFrames: true },
                args: [origin],
                func: (expectedOrigin) => {
                    if (location.origin !== expectedOrigin) return;
                    globalThis.__vigilBrowserGuardDisabled = true;
                    for (const el of document.querySelectorAll(
                        "[data-vigil-toast], [data-vigil-safe-prompt]",
                    )) {
                        el.remove();
                    }
                },
            },
            () => {
                void chrome.runtime.lastError;
                resolve();
            },
        );
    });
}

async function injectCustomSiteIntoOpenTabs(pattern) {
    if (!chrome.tabs || !chrome.scripting) return;
    const tabs = await tabsQuery({ url: pattern });
    const origin = pattern.endsWith("/*") ? pattern.slice(0, -2) : "";
    for (const tab of tabs) {
        if (typeof tab.id === "number") {
            await executeContentScript(tab.id);
            await sendEnableGuardMessage(tab.id, origin);
        }
    }
}

async function disableCustomSiteInOpenTabs(pattern, origin) {
    if (!chrome.tabs || !chrome.scripting) return;
    const tabs = await tabsQuery({ url: pattern });
    for (const tab of tabs) {
        if (typeof tab.id === "number") {
            await sendDisableGuardMessage(tab.id, origin);
            await forceDisableGuard(tab.id, origin);
        }
    }
}

async function listCustomSitesWithPermissions() {
    const sites = await loadCustomSites();
    const enriched = [];
    for (const site of sites) {
        enriched.push({
            ...site,
            hasPermission: await permissionsContains([site.pattern]),
        });
    }
    return enriched;
}

async function addCustomSite(site) {
    const normalized = normalizeCustomSiteInput(site && (site.host || site.pattern));
    if (!normalized.ok) return { ok: false, _error: normalized.error };
    const allowed = await permissionsContains([normalized.pattern]);
    if (!allowed) return { ok: false, _error: "permission_missing" };

    const sites = await loadCustomSites();
    const existing = sites.find((it) => it.pattern === normalized.pattern);
    const next = existing
        ? sites
        : sites.concat([
              {
                  host: normalized.host,
                  pattern: normalized.pattern,
                  addedAt: Date.now(),
              },
          ]);
    if (!existing) await saveCustomSites(next);
    await syncCustomContentScripts();
    await injectCustomSiteIntoOpenTabs(normalized.pattern);
    return { ok: true, site: existing || next[next.length - 1] };
}

async function removeCustomSite(input) {
    const normalized = normalizeCustomSiteInput(input);
    if (!normalized.ok) return { ok: false, _error: normalized.error };
    const sites = await loadCustomSites();
    const next = sites.filter((site) => site.pattern !== normalized.pattern);
    if (!isRequiredHostPattern(normalized.pattern)) {
        await disableCustomSiteInOpenTabs(normalized.pattern, `https://${normalized.host}`);
    }
    await saveCustomSites(next);
    await permissionsRemove([normalized.pattern]);
    await syncCustomContentScripts();
    return { ok: true };
}

async function addCustomRiskRule(input) {
    const normalized = normalizeCustomRiskRuleInput(input);
    if (!normalized.ok) return { ok: false, _error: normalized.error };
    const rules = await loadCustomRiskRules();
    const next = rules.filter((rule) => rule.id !== normalized.id).concat([normalized]);
    await saveCustomRiskRules(next);
    return { ok: true, rule: normalized };
}

async function removeCustomRiskRule(id) {
    const targetId = typeof id === "string" ? id : "";
    if (!targetId) return { ok: false, _error: "id_required" };
    const rules = await loadCustomRiskRules();
    await saveCustomRiskRules(rules.filter((rule) => rule.id !== targetId));
    return { ok: true };
}

async function setCustomRiskRuleEnabled(id, enabled) {
    const targetId = typeof id === "string" ? id : "";
    if (!targetId) return { ok: false, _error: "id_required" };
    const rules = await loadCustomRiskRules();
    const next = rules.map((rule) =>
        rule.id === targetId ? { ...rule, enabled: enabled !== false } : rule,
    );
    await saveCustomRiskRules(next);
    return { ok: true };
}

// α3:popup 展示用的最近 findings 环形队列(in-memory,SW 生命周期内有效)。
// findings 不落 chrome.storage,不记原文(ADR §I-9.1);
// storage 权限仅用于自定义保护网站 host/pattern 元数据。
// 仅保留"脱敏元数据" —— origin + event_kind + action + findings(enum 字面量列表) +
// timestamp(ms epoch)。SW 被 Chrome 杀掉后清零(轻量隐私 + 符合"原文仅 Host 内存停留"语义)。
const FINDINGS_LOG_MAX = 32;
/** @type {Array<{ts: number, origin: string, event_kind: string, action: string, findings: string[]}>} */
const findingsLog = [];
function recordFinding(entry) {
    findingsLog.unshift(entry);
    if (findingsLog.length > FINDINGS_LOG_MAX) {
        findingsLog.length = FINDINGS_LOG_MAX;
    }
}

// ───────────────────────── content script 消息入口 ─────────────────────────

/**
 * 消息入口。content-script.js 用 `chrome.runtime.sendMessage({ type: "vigil_check", ... })`
 * 调 check API;popup 用其它 type 拉取状态。
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || typeof msg.type !== "string") return false;

    // VIGIL-SEC-006(security audit defense-in-depth):只接受本扩展自身(content scripts /
    // popup / options)的消息。manifest 无 externally_connectable,web 页本就无法 sendMessage;
    // 此守门把该信任假设显式化,防止未来误加 externally_connectable 后外部 web 源操纵
    // 模式状态。sender.id 由 Chrome 运行时填充,不可由发送方伪造。
    if (!isTrustedExtensionSender(sender)) return false;

    // content-script → scanner pipeline check
    if (msg.type === "vigil_check") {
        isProtectedOrigin(msg.origin)
            .then((isProtected) => {
                if (!isProtected) {
                    sendResponse({
                        action: "allow",
                        findings: [],
                        _disabled: true,
                    });
                    return null;
                }
                return loadCustomRiskRules().then((customRiskRules) => checkWithScannerPipeline(
                    {
                        request_id: crypto.randomUUID(),
                        origin: msg.origin,
                        event_kind: msg.event_kind,
                        text: msg.text,
                    },
                    {
                        mode: currentMode,
                        consumer: { customRiskRules },
                        enterprise: { dataPolicy: "local_only" },
                    },
                ))
                    .then((resp) => {
                        recordFinding({
                            ts: Date.now(),
                            origin: msg.origin || "?",
                            event_kind: msg.event_kind || "?",
                            action: resp.action,
                            findings: (resp.findings || []).map((finding) =>
                                typeof finding === "string" ? finding : finding.label || finding.kind,
                            ),
                        });
                        sendResponse(resp);
                    });
            })
            .catch(() => {
                sendResponse({ action: "block", findings: [], _error: "guard_error" });
            });
        return true; // 异步响应(MV3 要求 listener return true 保持 sendResponse 有效)
    }

    // 自定义目标网站:options 页先请求 host permission,SW 负责校验 + 持久化 + 动态注册。
    if (msg.type === "vigil_normalize_custom_site") {
        sendResponse(normalizeCustomSiteInput(msg.input));
        return false;
    }

    if (msg.type === "vigil_list_custom_sites") {
        listCustomSitesWithPermissions()
            .then((sites) => sendResponse({ sites }))
            .catch((err) => sendResponse({ sites: [], _error: String(err) }));
        return true;
    }

    if (msg.type === "vigil_add_custom_site") {
        addCustomSite(msg.site)
            .then(sendResponse)
            .catch((err) => sendResponse({ ok: false, _error: String(err) }));
        return true;
    }

    if (msg.type === "vigil_remove_custom_site") {
        removeCustomSite(msg.input)
            .then(sendResponse)
            .catch((err) => sendResponse({ ok: false, _error: String(err) }));
        return true;
    }

    if (msg.type === "vigil_list_custom_risk_rules") {
        loadCustomRiskRules()
            .then((rules) => sendResponse({ rules }))
            .catch((err) => sendResponse({ rules: [], _error: String(err) }));
        return true;
    }

    if (msg.type === "vigil_add_custom_risk_rule") {
        addCustomRiskRule(msg.rule)
            .then(sendResponse)
            .catch((err) => sendResponse({ ok: false, _error: String(err) }));
        return true;
    }

    if (msg.type === "vigil_remove_custom_risk_rule") {
        removeCustomRiskRule(msg.id)
            .then(sendResponse)
            .catch((err) => sendResponse({ ok: false, _error: String(err) }));
        return true;
    }

    if (msg.type === "vigil_set_custom_risk_rule_enabled") {
        setCustomRiskRuleEnabled(msg.id, msg.enabled)
            .then(sendResponse)
            .catch((err) => sendResponse({ ok: false, _error: String(err) }));
        return true;
    }

    // α3 新增:popup 拉取最近 findings(in-memory 环形队列,最多 FINDINGS_LOG_MAX 条)
    if (msg.type === "vigil_recent_findings") {
        // 返回**副本**,避免 popup 侧意外修改污染 SW 状态
        sendResponse({ findings: findingsLog.slice() });
        return false; // 同步响应
    }

    // α3 新增:popup "清空" 按钮
    if (msg.type === "vigil_clear_findings") {
        findingsLog.length = 0;
        sendResponse({ ok: true });
        return false;
    }

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

    return false; // 未识别消息:让其它可能的 listener 处理或自然 timeout
});

chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local" && changes[CUSTOM_SITES_STORAGE_KEY]) {
        syncCustomContentScripts().catch(() => {});
    }
    if (areaName === "local" && changes[MODE_STORAGE_KEY]) {
        const next = changes[MODE_STORAGE_KEY].newValue;
        currentMode = MODE_VALUES.includes(next) ? next : MODE_DEFAULT;
    }
});

if (chrome.permissions && chrome.permissions.onRemoved) {
    chrome.permissions.onRemoved.addListener((permissions) => {
        if (permissions && Array.isArray(permissions.origins)) {
            syncCustomContentScripts().catch(() => {});
        }
    });
}

// ───────────────────────── service worker 生命周期 ─────────────────────────

loadStoredMode().catch(() => {});
syncCustomContentScripts().catch(() => {});

self.addEventListener("install", () => {
    // MV3 service worker 在 install 中调 skipWaiting,让新版本立即接管
    if (typeof self.skipWaiting === "function") {
        self.skipWaiting();
    }
});

self.addEventListener("activate", (event) => {
    if (self.clients && typeof self.clients.claim === "function") {
        event.waitUntil(
            Promise.all([
                self.clients.claim(),
                loadStoredMode(),
                syncCustomContentScripts(),
            ]).catch(() => {}),
        );
    }
});
