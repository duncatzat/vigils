// I09b-α1 service worker —— Vigil Native Host 桥接层。
//
// 架构(MV3 long-lived port + pending-request map):
//   content-script.js  ──sendMessage(event)──▶  background.js
//                                                   │
//                                                   ▼
//                                     chrome.runtime.connectNative("com.vigil.host")
//                                                   │
//                                                   ▼
//                                          Native Host(Rust, vigil-native-host)
//                                                   │
//                                     ◀──postMessage(BrowserCheckResponse)────
//
// 协议严格对齐 `crates/vigil-browser/src/protocol.rs`:
//   Request  : { request_id, origin, event_kind: "paste"|"input"|"submit", text }
//   Response : { request_id, action: "allow"|"redact"|"block", findings: [...], redacted_text? }
//   Error    : { error: "too_large"|"bad_json"|"origin_denied"|"bad_request_id"|"internal",
//                request_id? }
//
// 安全契约(ADR 0009 §I-9):
//   §I-9.1  text 永不入 chrome.storage / console.log(原文只经 port 转发给 Host,Host 内存 drop)
//   §I-9.3  特权 scheme 由 Native Host fail-closed(origin_denied);service worker 层做早退
//           剥 `file://` / `chrome://`,避免往 Host 发明显无效请求
//   §I-9.5  单帧 1 MB 上限由 Native Host framing 层守,本层做 32 MB 明显超大早退,
//           避免 port.postMessage 抛未捕获异常影响 SW 存活
//
// 容错:
//   - Native Host 未安装 / 崩溃 → port.onDisconnect;所有 pending request fail 为
//     { action: "block" }(fail-closed;MV3 没法在浏览器层做 redact,block 是安全兜底)
//   - request_id 碰撞防御:UUIDv4 + per-request Map,TTL 10s 自动 GC 清孤儿

// ISS-007:3 档策略决策纯函数从 tier-decision.js 导入,SW + Node 单测共用模块
import {
    TIER_VALUES,
    TIER_DEFAULT,
    applyTierDecision,
} from "./tier-decision.js";

const NATIVE_HOST_NAME = "com.vigil.host";
const MAX_TEXT_CHARS = 32 * 1024 * 1024; // 32 MB 字符早退;Host 1 MB 帧上限由 Host 自己规范化拒绝
const REQUEST_TTL_MS = 10_000;

// ───────────────────────── v0.4 / ISS-007:3 档策略决策层 ─────────────────────────
//
// Native Host 返回的原始 action 是硬指纹层(vigil-redaction HARD_RULES)裁决结果:
//   - "allow" = 无任何 finding → 放行(tier 不 override)
//   - "redact" = 命中某 finding → 已返 redacted_text(tier 按策略 override 为 block 或放行)
//   - "block" = 无法 redact / 严重拒绝 → block(tier 不 override,已是最严)
//
// 三档语义(Round 2 roadmap §Stage 1 MVP):
//   - strict (公开 AI 网站 / 最严):命中 secret 一律 block(不接受 redact 继续 paste)
//   - balanced (默认):NH redact 直接通过(脱敏后继续,最佳 UX)
//   - recall-first (企业外发 / 工单 / 邮件 / 最宽谨慎):多类命中(≥2 distinct)或 secret 均 block
//
// **重要**:3 档策略**只收紧**,**绝不放宽**。即:
//   - NH 返 block → 任何档仍 block(不 override)
//   - NH 返 allow → 任何档仍 allow(tier 不改放行)
//   - NH 返 redact → tier 仅能 override 为 block(不能 override 为 allow)
// 这保证 tier 是**纵深防御**一层,而不是 tier 本身就是漏洞。
//
// 持久化:tier 存 SW in-memory,浏览器重启恢复 default "balanced"。
// **不加 storage permission**(继续 α4 最小权限原则);Stage 2+ 可用 Native Host config
// 持久化(RPC 启动时拉一次);当前 MVP 接受 session 级设置 + 持续设置留给后续 ISS。
//
// `TIER_VALUES` / `TIER_DEFAULT` / `applyTierDecision` 从 `tier-decision.js` 导入,
// 跟 Node 单测共用同一实现(与 feedback_production_logic_testable 纪律一致)。

/** @type {string} 当前档位,in-memory session 级 */
let currentTier = TIER_DEFAULT;

// α3:popup 展示用的最近 findings 环形队列(in-memory,SW 生命周期内有效)。
// 不落 chrome.storage(需要 storage permission,违最小权限 β1 教训),不记原文(ADR §I-9.1),
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

// α4:session-scoped 豁免。用户在 popup 点"豁免 N 分钟"后,**仅本 tab + 仅本 origin**
// 的 paste/input/submit 直接 allow,不走 Native Host 分类器。
//
// 安全权衡:
//   - **硬上限** 10 分钟(`EXEMPT_MAX_MS`):防用户误点长时间失守;超限 clamp 不 panic
//   - **in-memory only**:SW 生命周期内有效;Chrome 杀 SW 自动清零(重启浏览器即恢复守门)
//   - **tab+origin 双绑**:key 是 `${tab_id}|${origin}`,避免"单 tab 但多 origin"场景漏放
//   - **最小权限**:用 `activeTab` 而非 `tabs`;popup 用 chrome.tabs.query 只需 activeTab
//   - **exempt 也记 findings log**:action 字段标 `"allow_exempt"` 便于审计员在 popup 识别
//     (与 Rust 的 `BrowserAction` enum 不冲突 —— 这是 UI 端本地增强元数据,不回流 Host)
const EXEMPT_MAX_MS = 10 * 60 * 1000;
const EXEMPT_MIN_MS = 30 * 1000;
/** @type {Map<string, number>} key = `${tab_id}|${origin}`,value = 过期 ms epoch */
const exemptMap = new Map();

function exemptKey(tabId, origin) {
    return `${tabId}|${origin}`;
}

/** 当前 {tab_id, origin} 是否在豁免期内?同时 lazy 清理过期项。 */
function isExempt(tabId, origin) {
    if (typeof tabId !== "number" || typeof origin !== "string") return false;
    const key = exemptKey(tabId, origin);
    const until = exemptMap.get(key);
    if (until === undefined) return false;
    if (Date.now() >= until) {
        exemptMap.delete(key);
        return false;
    }
    return true;
}

/** 设置豁免;返回实际过期时间(ms epoch)用于 popup 显示。 */
function setExempt(tabId, origin, durationMs) {
    if (typeof tabId !== "number" || typeof origin !== "string") return 0;
    const clamped = Math.max(EXEMPT_MIN_MS, Math.min(durationMs, EXEMPT_MAX_MS));
    const until = Date.now() + clamped;
    exemptMap.set(exemptKey(tabId, origin), until);
    return until;
}

function clearExempt(tabId, origin) {
    if (typeof tabId !== "number" || typeof origin !== "string") return;
    exemptMap.delete(exemptKey(tabId, origin));
}

// ───────────────────────── Native port 管理(lazy + 自动重连) ─────────────────────────

/** 单例 port;首次用到时建立,disconnect 时置 null 下次重新建 */
let nativePort = null;
/** pending 请求表:request_id → { resolve, createdAt } */
const pending = new Map();

function getNativePort() {
    if (nativePort !== null) return nativePort;
    try {
        nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);
    } catch (err) {
        // connectNative 不可用(权限 / 名字未注册)—— 同步抛给调用方
        nativePort = null;
        throw new Error(`nativeMessaging unavailable: ${String(err)}`);
    }
    nativePort.onMessage.addListener(onHostMessage);
    nativePort.onDisconnect.addListener(onHostDisconnect);
    return nativePort;
}

function onHostMessage(msg) {
    // 协议按 request_id 路由 Response / 按 error 路由 ErrorFrame。
    // ErrorFrame 的 request_id 在 Rust `BrowserErrorFrame` 是 Option,可能缺省
    // (如 BadJson 解帧失败时 Host 尚未拿到有效 request_id) —— 必须**不依赖 request_id 存在**
    // 即可走 fail-closed 路径。R1 MUST-FIX 2 修复:下面顺序调整为先看 error,再看 request_id。
    if (!msg || typeof msg !== "object") return;

    // (A) ErrorFrame 优先分流(协议错误是 Host 端信号,无论 request_id 是否存在都要 fail-closed)
    if (typeof msg.error === "string") {
        const reqId = typeof msg.request_id === "string" ? msg.request_id : null;
        if (reqId !== null) {
            const slot = pending.get(reqId);
            if (slot) {
                pending.delete(reqId);
                slot.resolve({ action: "block", findings: [], _error: msg.error });
            }
            // 有 request_id 但未命中 pending(孤儿错误)——忽略即可
            return;
        }
        // ErrorFrame 无 request_id(Host 根本没解出 request):**所有** pending 立即 fail-closed block;
        // 这是最谨慎的选择(stream-level 协议错误可能意味着 Host state 不可信),
        // 代价是"全 pending 连坐 block 一次"而非"全部等 TTL"
        const globalReason = `protocol_error:${msg.error}`;
        for (const [, slot] of pending) {
            slot.resolve({ action: "block", findings: [], _error: globalReason });
        }
        pending.clear();
        return;
    }

    // (B) 正常 Response(要求 request_id 存在)
    const reqId = msg.request_id;
    if (typeof reqId !== "string") return; // 非法消息,丢弃(上游 TTL 兜底)
    const slot = pending.get(reqId);
    if (!slot) return; // 孤儿响应,丢弃
    pending.delete(reqId);
    slot.resolve({
        action: msg.action,
        findings: Array.isArray(msg.findings) ? msg.findings : [],
        redacted_text: msg.redacted_text,
    });
}

function onHostDisconnect() {
    const reason =
        (chrome.runtime.lastError && chrome.runtime.lastError.message) ||
        "host_disconnected";
    // 所有 pending 请求立即 fail-closed(block)
    for (const [, slot] of pending) {
        slot.resolve({ action: "block", findings: [], _error: reason });
    }
    pending.clear();
    nativePort = null;
}

// ───────────────────────── 单 request 辅助 ─────────────────────────

/**
 * 向 Native Host 发一次 check 请求,返回 Promise<Response>。
 * Response shape: `{ action, findings, redacted_text?, _error? }`;
 * `_error` 表示协议层错误,`action` 已被置为 `"block"`(fail-closed)。
 */
function checkWithHost({ origin, event_kind, text }) {
    // 早退 1:空文本直接 allow,不打扰 Host
    if (typeof text !== "string" || text.length === 0) {
        return Promise.resolve({ action: "allow", findings: [] });
    }
    // 早退 2:明显超大 —— 不发给 Host,本层直接 block(§I-9.5 边界兜底)
    if (text.length > MAX_TEXT_CHARS) {
        return Promise.resolve({
            action: "block",
            findings: [],
            _error: "too_large_sw",
        });
    }
    // 早退 3:origin 非 http(s) 立即拒(Host 也会拒;本层快速失败免 RTT)
    if (
        typeof origin !== "string" ||
        !(origin.startsWith("https://") || origin.startsWith("http://"))
    ) {
        return Promise.resolve({
            action: "block",
            findings: [],
            _error: "origin_denied_sw",
        });
    }
    // 早退 4:event_kind 协议白名单(只有 "paste" / "input" / "submit" 三值,Rust 端 serde 反序列也会拒其它)
    if (event_kind !== "paste" && event_kind !== "input" && event_kind !== "submit") {
        return Promise.resolve({
            action: "block",
            findings: [],
            _error: "bad_event_kind_sw",
        });
    }

    return new Promise((resolve) => {
        let port;
        try {
            port = getNativePort();
        } catch (err) {
            resolve({ action: "block", findings: [], _error: String(err) });
            return;
        }
        const request_id = crypto.randomUUID();
        // α3:resolve 时先入队最近 findings,再转给 caller;保证 popup 能观察到事件流
        pending.set(request_id, {
            resolve: (resp) => {
                recordFinding({
                    ts: Date.now(),
                    origin,
                    event_kind,
                    action: resp.action,
                    findings: resp.findings || [],
                });
                resolve(resp);
            },
            createdAt: Date.now(),
        });
        try {
            port.postMessage({ request_id, origin, event_kind, text });
        } catch (err) {
            pending.delete(request_id);
            // port 失效触发 onDisconnect;同步 resolve 避免挂起
            recordFinding({
                ts: Date.now(),
                origin,
                event_kind,
                action: "block",
                findings: [],
            });
            resolve({ action: "block", findings: [], _error: String(err) });
        }
    });
}

// 定期 GC pending(Host 挂掉但 onDisconnect 没触发时兜底)
setInterval(() => {
    const now = Date.now();
    for (const [id, slot] of pending) {
        if (now - slot.createdAt > REQUEST_TTL_MS) {
            pending.delete(id);
            slot.resolve({ action: "block", findings: [], _error: "timeout" });
        }
    }
}, REQUEST_TTL_MS);

// ───────────────────────── content script 消息入口 ─────────────────────────

/**
 * 消息入口。content-script.js 用 `chrome.runtime.sendMessage({ type: "vigil_check", ... })`
 * 调 check API;popup 用其它 type 拉取状态 / 设置豁免。
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || typeof msg.type !== "string") return false;

    // VIGIL-SEC-006(security audit defense-in-depth):只接受本扩展自身(content scripts /
    // popup / options)的消息。manifest 无 externally_connectable,web 页本就无法 sendMessage;
    // 此守门把该信任假设显式化,防止未来误加 externally_connectable 后外部 web 源操纵 tier /
    // 豁免状态。sender.id 由 Chrome 运行时填充,不可由发送方伪造。
    if (!sender || sender.id !== chrome.runtime.id) return false;

    // α1 基线 + α4 豁免短路:content-script → Host check
    if (msg.type === "vigil_check") {
        // α4:tab_id 来自 sender.tab.id(chrome 运行时元数据,不伪造);
        // 若 exempt 命中,直接 allow 不调 Host(但仍 recordFinding 让 popup 可见)
        const tabId =
            sender && sender.tab && typeof sender.tab.id === "number"
                ? sender.tab.id
                : -1;
        if (tabId !== -1 && isExempt(tabId, msg.origin)) {
            const resp = { action: "allow", findings: [], _exempt: true };
            recordFinding({
                ts: Date.now(),
                origin: msg.origin || "?",
                event_kind: msg.event_kind || "?",
                action: "allow_exempt",
                findings: [],
            });
            sendResponse(resp);
            return false; // 同步响应
        }
        checkWithHost({
            origin: msg.origin,
            event_kind: msg.event_kind,
            text: msg.text,
        })
            .then((rawResp) => applyTierDecision(rawResp, currentTier))
            .then(sendResponse);
        return true; // 异步响应(MV3 要求 listener return true 保持 sendResponse 有效)
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

    // α4 新增:popup 查询当前 tab+origin 豁免状态
    //
    // popup 不能从 sender.tab 直接拿当前激活 tab(sender 是 popup 本身,`sender.tab` undefined)。
    // 由 popup 通过 chrome.tabs.query({active:true, currentWindow:true}) 解出 tab_id + origin
    // 再传过来。SW 本身不做 activeTab 查询(分离职责)。
    if (msg.type === "vigil_get_exempt") {
        const tabId = typeof msg.tab_id === "number" ? msg.tab_id : -1;
        const origin = typeof msg.origin === "string" ? msg.origin : "";
        const key = exemptKey(tabId, origin);
        const until = exemptMap.get(key);
        if (until !== undefined && Date.now() < until) {
            sendResponse({ exempt: true, until });
        } else {
            // 顺手清理过期
            if (until !== undefined) exemptMap.delete(key);
            sendResponse({ exempt: false, until: 0 });
        }
        return false;
    }

    // α4 新增:popup 设置豁免(duration_ms 被 clamp 到 [EXEMPT_MIN_MS, EXEMPT_MAX_MS])
    //
    // SW defense-in-depth:**即使 popup UI 禁用了非 http(s) 按钮,SW 仍做最小 origin 校验**
    // —— popup 被绕过 / 恶意调用时,`file://` / `chrome://` / 空串等都直接 invalid_params。
    // content-script 本身在 chrome-extension:// 等 scheme 不会被注入,"假豁免"对实际 `vigil_check`
    // 路径也无影响(isExempt 查不到对应 key);但本守门让"豁免表"不被污染。
    if (msg.type === "vigil_set_exempt") {
        const tabId = typeof msg.tab_id === "number" ? msg.tab_id : -1;
        const origin = typeof msg.origin === "string" ? msg.origin : "";
        const duration = typeof msg.duration_ms === "number" ? msg.duration_ms : 0;
        const isHttpOrigin =
            origin.startsWith("https://") || origin.startsWith("http://");
        if (tabId === -1 || !isHttpOrigin || duration <= 0) {
            sendResponse({ ok: false, _error: "invalid_params" });
            return false;
        }
        const until = setExempt(tabId, origin, duration);
        sendResponse({ ok: true, until });
        return false;
    }

    // α4 新增:popup 立即清除豁免
    if (msg.type === "vigil_clear_exempt") {
        const tabId = typeof msg.tab_id === "number" ? msg.tab_id : -1;
        const origin = typeof msg.origin === "string" ? msg.origin : "";
        clearExempt(tabId, origin);
        sendResponse({ ok: true });
        return false;
    }

    // ISS-007:popup/options 查询当前档位
    if (msg.type === "vigil_get_tier") {
        sendResponse({ tier: currentTier, default: TIER_DEFAULT, values: TIER_VALUES.slice() });
        return false;
    }

    // ISS-007:popup/options 切换档位;白名单校验,非法值拒绝(不 fall-back 到 default,
    // 让调用方感知错误)
    if (msg.type === "vigil_set_tier") {
        const next = typeof msg.tier === "string" ? msg.tier : "";
        if (!TIER_VALUES.includes(next)) {
            sendResponse({ ok: false, _error: "invalid_tier" });
            return false;
        }
        currentTier = next;
        sendResponse({ ok: true, tier: currentTier });
        return false;
    }

    return false; // 未识别消息:让其它可能的 listener 处理或自然 timeout
});

// α4:tab 关闭时自动清除该 tab 的豁免(避免 tab_id 复用后豁免"迁移"到新 tab)。
chrome.tabs.onRemoved.addListener((tabId) => {
    for (const key of Array.from(exemptMap.keys())) {
        if (key.startsWith(`${tabId}|`)) {
            exemptMap.delete(key);
        }
    }
});

// ───────────────────────── service worker 生命周期 ─────────────────────────

self.addEventListener("install", () => {
    // MV3 service worker 在 install 中调 skipWaiting,让新版本立即接管
    if (typeof self.skipWaiting === "function") {
        self.skipWaiting();
    }
});

self.addEventListener("activate", (event) => {
    if (self.clients && typeof self.clients.claim === "function") {
        event.waitUntil(self.clients.claim());
    }
});
