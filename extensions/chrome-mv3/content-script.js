// I09b-α1/α2 content script —— paste / input / submit 守门。
//
// 职责:
//   - 监听 document 级 `paste` 事件(捕获阶段,拦下纯文本粘贴前 dispatch)
//   - 监听 document 级 `input` 事件(防抖后检查手动输入,命中后回写脱敏文本)
//   - 监听 `submit` 事件(form submit + contenteditable Enter + button[type=submit])
//   - 将候选文本 + origin + event_kind 送到 background service worker,
//     收到 Response 后按 action 执行:
//       "allow"  → 放行
//       "redact" → 阻断原事件,用 Response.redacted_text 替换输入框文本,重新 dispatch 同类事件
//       "block"  → 阻断事件,短暂提示用户
//
// 安全契约(ADR 0009 §I-9):
//   §I-9.1  原文仅通过 chrome.runtime.sendMessage 送 SW,再由 SW 转给 Native Host;
//           content script 本身不存 text 到 chrome.storage / window.*(进程短寿命 GC)
//   §I-9.3  origin 来自 `location.origin`,特权 scheme(chrome-extension/file)不在
//           manifest matches 里,本 script 不会被注入这些页面
//   §D6     三态必须按 Response.action 原样执行;非法值(未来扩展)按 fail-closed block
//
// α2 新增(相对 α1):
//   - **站点深度选择器**:`siteAdapters` 注册表按 hostname 分流,为 ChatGPT / Claude /
//     Gemini / Perplexity 提供精确 `findPrimaryInput(form)` —— **scope 到被提交的 form**
//     (R1 BLOCKER 修复;绝不在 document 全局搜以免"决策元素 ≠ 提交元素"bypass);
//     在 form 子树内找不到主输入时降级 α1 通用聚合(primaryInput=null)
//   - **form-level redact 真写**:`collectSubmitPayload` 返回 `{ text, primaryInput }`,
//     redact 路径直接写回 primaryInput(α1 降级 block 的场景现在能真 redact)
//   - primaryInput 不可定位时(heterogeneous form)仍降级 block,保留 fail-safe 语义
//
// 已知简化(留给 α3 / β):
//   - α3:popup 展示最近 N 条 finding + 用户临时豁免
//   - β:Enter submit allow 后走真实 trusted submit event(当前仍 `execCommand insertLineBreak`,
//     R1 标为可接受 MVP 折衷,β Playwright E2E 覆盖后再换)

(() => {
    "use strict";

    const ORIGIN = location.origin;
    const INPUT_DEBOUNCE_MS = 700;

    // ───────────────────────── 极简通知 UI(固定在页面顶部) ─────────────────────────

    let toastEl = null;
    function ensureToastMounted() {
        const parent = document.body || document.documentElement;
        if (!parent) return false;
        if (!toastEl) {
            toastEl = document.createElement("div");
            toastEl.setAttribute("data-vigil-toast", "");
            toastEl.setAttribute("role", "status");
            toastEl.setAttribute("aria-live", "polite");
            // 样式 inline,避免被站点 CSS 覆盖
            Object.assign(toastEl.style, {
                position: "fixed",
                right: "16px",
                bottom: "16px",
                zIndex: "2147483647",
                maxWidth: "min(420px, calc(100vw - 32px))",
                padding: "10px 14px",
                borderRadius: "6px",
                boxShadow: "0 12px 32px rgba(15, 23, 42, 0.28)",
                fontFamily: "system-ui, -apple-system, sans-serif",
                fontSize: "13px",
                lineHeight: "1.45",
                fontWeight: "600",
                color: "#fff",
                pointerEvents: "none",
                transition: "opacity 0.2s, transform 0.2s",
                opacity: "0",
                transform: "translateY(8px)",
                whiteSpace: "normal",
            });
        }
        if (!toastEl.isConnected) {
            parent.appendChild(toastEl);
        }
        return true;
    }

    function showToast(message, tone /* "info" | "warn" | "error" */) {
        // 懒创建;Vue / naive 那一套不可用(content script 是独立 JS world)
        if (!ensureToastMounted()) return;
        const color =
            tone === "error" ? "#b91c1c" : tone === "warn" ? "#b45309" : "#1e40af";
        toastEl.style.background = color;
        // 用 textContent(Vue 默认插值同效),杜绝站点 HTML 注入 contaminate Vigil 提示
        toastEl.textContent = message;
        toastEl.style.opacity = "1";
        toastEl.style.transform = "translateY(0)";
        clearTimeout(showToast._t);
        showToast._t = setTimeout(() => {
            if (toastEl) {
                toastEl.style.opacity = "0";
                toastEl.style.transform = "translateY(8px)";
            }
        }, 4000);
    }

    let safePromptEl = null;
    let dismissSafePrompt = null;

    function ensureSafePromptMounted() {
        const parent = document.body || document.documentElement;
        if (!parent) return false;
        if (!safePromptEl) {
            safePromptEl = document.createElement("div");
            safePromptEl.setAttribute("data-vigil-safe-prompt", "");
            safePromptEl.setAttribute("role", "dialog");
            safePromptEl.setAttribute("aria-live", "polite");
            Object.assign(safePromptEl.style, {
                position: "fixed",
                right: "16px",
                bottom: "16px",
                zIndex: "2147483647",
                width: "min(420px, calc(100vw - 32px))",
                padding: "14px",
                borderRadius: "8px",
                border: "1px solid rgba(148, 163, 184, 0.45)",
                boxShadow: "0 18px 46px rgba(15, 23, 42, 0.3)",
                fontFamily: "system-ui, -apple-system, sans-serif",
                fontSize: "13px",
                lineHeight: "1.45",
                color: "#0f172a",
                background: "#fff",
            });
        }
        if (!safePromptEl.isConnected) {
            parent.appendChild(safePromptEl);
        }
        return true;
    }

    function makePromptButton(label, variant) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = label;
        Object.assign(btn.style, {
            border: "1px solid #cbd5e1",
            borderRadius: "6px",
            padding: "7px 10px",
            font: "inherit",
            fontWeight: "650",
            cursor: "pointer",
            background: "#fff",
            color: "#0f172a",
        });
        if (variant === "primary") {
            btn.style.borderColor = "#1d4ed8";
            btn.style.background = "#1d4ed8";
            btn.style.color = "#fff";
        }
        return btn;
    }

    function closeSafePrompt() {
        if (safePromptEl) {
            safePromptEl.replaceChildren();
            safePromptEl.remove();
        }
        dismissSafePrompt = null;
    }

    function showSafeVersionPrompt({ findings, onUse, onCancel }) {
        if (dismissSafePrompt) dismissSafePrompt();
        if (!ensureSafePromptMounted()) return;

        const kinds = formatFindingList(findings);
        const title = document.createElement("div");
        title.textContent = "Vigil 检测到敏感内容，已生成安全版本";
        Object.assign(title.style, {
            fontWeight: "750",
            fontSize: "14px",
            marginBottom: "4px",
        });

        const desc = document.createElement("div");
        desc.textContent = `检测到 ${kinds}。你可以一键替换为脱敏后的安全版本。`;
        Object.assign(desc.style, {
            color: "#475569",
            marginBottom: "10px",
        });

        const changes = document.createElement("div");
        changes.hidden = true;
        Object.assign(changes.style, {
            margin: "0 0 10px",
            padding: "8px",
            borderRadius: "6px",
            background: "#f8fafc",
            color: "#334155",
        });

        const changesLabel = document.createElement("div");
        changesLabel.textContent = "改动类型";
        Object.assign(changesLabel.style, {
            fontWeight: "700",
            marginBottom: "4px",
        });
        changes.appendChild(changesLabel);

        const list = document.createElement("div");
        const findingLabels = Array.isArray(findings)
            ? findings.map(formatFindingLabel)
            : [];
        for (const label of Array.from(new Set(findingLabels))) {
            const code = document.createElement("code");
            code.textContent = label;
            Object.assign(code.style, {
                display: "inline-block",
                margin: "0 6px 6px 0",
                padding: "2px 6px",
                borderRadius: "5px",
                background: "#e2e8f0",
            });
            list.appendChild(code);
        }
        if (!list.childNodes.length) {
            const fallback = document.createElement("code");
            fallback.textContent = "敏感内容";
            list.appendChild(fallback);
        }
        changes.appendChild(list);

        const actions = document.createElement("div");
        Object.assign(actions.style, {
            display: "flex",
            flexWrap: "wrap",
            gap: "8px",
        });

        const useBtn = makePromptButton("使用安全版本", "primary");
        const viewBtn = makePromptButton("查看改动", "secondary");
        const cancelBtn = makePromptButton("取消", "secondary");
        actions.append(useBtn, viewBtn, cancelBtn);

        useBtn.addEventListener("click", () => {
            closeSafePrompt();
            onUse();
        });
        viewBtn.addEventListener("click", () => {
            changes.hidden = !changes.hidden;
            viewBtn.textContent = changes.hidden ? "查看改动" : "收起改动";
        });
        cancelBtn.addEventListener("click", () => {
            closeSafePrompt();
            if (typeof onCancel === "function") onCancel();
        });

        safePromptEl.replaceChildren(title, desc, changes, actions);
        dismissSafePrompt = closeSafePrompt;
    }

    // ───────────────────────── SW 请求 ─────────────────────────

    /**
     * 向 service worker 发 vigil_check 请求。
     * 返回 `{ action, findings, redacted_text?, _error? }`;
     * SW 不响应 / chrome.runtime 异常视为 fail-closed block。
     */
    function callBackground(event_kind, text) {
        return new Promise((resolve) => {
            let replied = false;
            try {
                // runtime 缺失守门:扩展上下文失效(reload/更新/卸载)时 chrome.runtime 可能
                // 为 undefined。显式 fail-closed,而非依赖属性访问抛错(行为等价但更清晰)。
                const runtime =
                    typeof chrome === "object" && chrome ? chrome.runtime : undefined;
                if (!runtime || typeof runtime.sendMessage !== "function") {
                    replied = true;
                    resolve({ action: "block", findings: [], _error: "no_runtime" });
                    return;
                }
                runtime.sendMessage(
                    { type: "vigil_check", origin: ORIGIN, event_kind, text },
                    (resp) => {
                        try {
                            if (replied) return;
                            replied = true;
                            if (runtime.lastError) {
                                resolve({
                                    action: "block",
                                    findings: [],
                                    _error: runtime.lastError.message,
                                });
                                return;
                            }
                            resolve(
                                resp || { action: "block", findings: [], _error: "no_response" },
                            );
                        } catch (err) {
                            resolve({ action: "block", findings: [], _error: String(err) });
                            return;
                        }
                    },
                );
            } catch (err) {
                if (!replied) {
                    replied = true;
                    resolve({ action: "block", findings: [], _error: String(err) });
                }
            }
            // 安全兜底超时 —— 超 SW 的 10s TTL 略长,防 content script 永久挂
            setTimeout(() => {
                if (!replied) {
                    replied = true;
                    resolve({ action: "block", findings: [], _error: "cs_timeout" });
                }
            }, 12_000);
        });
    }

    // ───────────────────────── α2:站点深度选择器 ─────────────────────────
    //
    // 每个 adapter 有一个 `findPrimaryInput(root)`,返回页面主输入元素(LLM prompt
    // textarea / contenteditable editor)或 `null`。选择器会随站点版本漂移,因此:
    //   - 有多个候选 selector(主 + 兜底)
    //   - 找不到任一候选 → 返 null,caller 回退到 α1 通用聚合
    // 选择器来自 2026-04 时 DOM 快照(ChatGPT / Claude.ai / Gemini / Perplexity);
    // 站点改版时应按 β 的 Playwright E2E 触发回归,再更新此处。

    /**
     * @typedef {Object} SiteAdapter
     * @property {string} label —— 日志 / toast 用
     * @property {(root: ParentNode) => Element | null} findPrimaryInput
     *   **R1 BLOCKER 修复**:`root` 必须是**被提交的 form**(或其他 scope 元素),
     *   **不能是 document**。在 document 全局搜会导致"决策元素 ≠ 提交元素"——
     *   被评估的文本来自页面其它 editor,但浏览器仍提交原 form,造成 bypass / redact 错字段。
     *   要求 findPrimaryInput 返回值必须在 `root` 子树内(`root.querySelector` 天然满足)。
     */

    /** @type {Record<string, SiteAdapter>} */
    const siteAdapters = {
        "chatgpt.com": {
            label: "ChatGPT",
            findPrimaryInput: (root) =>
                root.querySelector("#prompt-textarea") ||
                // 新版改为 ProseMirror contenteditable
                root.querySelector('div[contenteditable="true"].ProseMirror') ||
                root.querySelector('div[role="textbox"][contenteditable="true"]'),
        },
        "claude.ai": {
            label: "Claude",
            findPrimaryInput: (root) =>
                root.querySelector('div[contenteditable="true"].ProseMirror') ||
                root.querySelector('div[contenteditable="true"][role="textbox"]') ||
                root.querySelector("div.ProseMirror"),
        },
        "gemini.google.com": {
            label: "Gemini",
            findPrimaryInput: (root) =>
                // Gemini 用 rich-textarea web component,最终渲染为内部 contenteditable
                root.querySelector('rich-textarea div[contenteditable="true"]') ||
                root.querySelector('div.ql-editor[contenteditable="true"]') ||
                root.querySelector('div[contenteditable="true"][role="textbox"]'),
        },
        "www.perplexity.ai": {
            label: "Perplexity",
            findPrimaryInput: (root) =>
                root.querySelector('textarea[placeholder*="Ask"]') ||
                root.querySelector("main textarea") ||
                root.querySelector('div[contenteditable="true"]'),
        },
    };

    /**
     * 按当前 hostname 取站点特异 adapter(仅用于 form-submit 主输入的精确定位)。
     *
     * **覆盖模型(adversarial review #2,显式声明防"静默漂移")**:manifest 注入的**所有**
     * host 都受**通用** paste/input/keydown 守门保护 —— 这些路径基于 `adaptTarget` 作用于事件
     * target,与站点无关,是**主要**保护层。`siteAdapters` 只是 form-submit 路径的深选择器
     * **优化**。已核验深选择器的有 chatgpt/claude/gemini/perplexity 4 站;国内 AI 站点
     * (deepseek/豆包/kimi/通义/智谱/元宝/文心/星火)目前**仅靠通用守门**覆盖(深选择器待真
     * 站点 DOM 核验后补)。未注册 host 返 null → `collectSubmitPayload` 走 α1 form 聚合 / 降级
     * block(fail-safe,绝不自动外发原文)。**此处对国内站点返回 null 是有意设计,非配置漂移。**
     */
    function getSiteAdapter() {
        const host = location.hostname;
        return siteAdapters[host] || null;
    }

    // ───────────────────────── 输入目标抽象 ─────────────────────────

    /**
     * 从事件 target 提取可替换文本元素 + get/set 适配器。
     *
     * 返回 `{ getText, setText }` 或 `null`(非文本输入,放弃守门)。
     */
    function adaptTarget(target) {
        if (!target) return null;
        // target 可能是 contenteditable 内部子节点(文本节点 / <span> 等)——上溯到可编辑宿主,
        // 让 paste/input 落到正确的编辑器元素(富文本 / web component 内部结构常见)。
        if (
            !(target instanceof HTMLTextAreaElement) &&
            !(target instanceof HTMLInputElement) &&
            target instanceof Element
        ) {
            const editable = target.closest('[contenteditable="true"]');
            if (editable instanceof HTMLElement) target = editable;
        }
        // 1) <textarea> / <input type=text|search|url|email|password>(password 跳过 —— 不读明文)
        if (target instanceof HTMLTextAreaElement) {
            return {
                getText: () => target.value,
                setText: (v) => {
                    target.value = v;
                    target.dispatchEvent(new Event("input", { bubbles: true }));
                },
                // 在光标/选区处插入(setRangeText),保留框内既有内容(修"粘贴脱敏覆盖整框")。
                insertText: (v) => {
                    const start =
                        typeof target.selectionStart === "number"
                            ? target.selectionStart
                            : target.value.length;
                    const end =
                        typeof target.selectionEnd === "number"
                            ? target.selectionEnd
                            : start;
                    target.setRangeText(v, start, end, "end");
                    target.dispatchEvent(new Event("input", { bubbles: true }));
                },
                captureSelection: () => ({
                    start:
                        typeof target.selectionStart === "number"
                            ? target.selectionStart
                            : target.value.length,
                    end:
                        typeof target.selectionEnd === "number"
                            ? target.selectionEnd
                            : target.value.length,
                }),
            };
        }
        if (target instanceof HTMLInputElement) {
            const t = (target.type || "").toLowerCase();
            if (t === "password" || t === "hidden" || t === "file") return null;
            if (["text", "search", "url", "email", "tel", ""].includes(t)) {
                return {
                    getText: () => target.value,
                    setText: (v) => {
                        target.value = v;
                        target.dispatchEvent(new Event("input", { bubbles: true }));
                    },
                    insertText: (v) => {
                        const start =
                            typeof target.selectionStart === "number"
                                ? target.selectionStart
                                : target.value.length;
                        const end =
                            typeof target.selectionEnd === "number"
                                ? target.selectionEnd
                                : start;
                        target.setRangeText(v, start, end, "end");
                        target.dispatchEvent(new Event("input", { bubbles: true }));
                    },
                    captureSelection: () => ({
                        start:
                            typeof target.selectionStart === "number"
                                ? target.selectionStart
                                : target.value.length,
                        end:
                            typeof target.selectionEnd === "number"
                                ? target.selectionEnd
                                : target.value.length,
                    }),
                };
            }
            return null;
        }
        // 2) contenteditable(ChatGPT / Claude / Gemini 的富文本编辑器)
        if (
            target instanceof HTMLElement &&
            (target.isContentEditable || target.contentEditable === "true")
        ) {
            return {
                getText: () => target.textContent || "",
                setText: (v) => {
                    // execCommand 非标准但在 Chromium 仍可用;I09b-α2 换 Selection/Range 精确替换
                    target.focus();
                    document.execCommand("selectAll", false, undefined);
                    document.execCommand("insertText", false, v);
                },
                // 光标处插入(不 selectAll),保留既有内容。
                insertText: (v) => {
                    target.focus();
                    document.execCommand("insertText", false, v);
                },
                // 计算光标/选区在纯文本里的偏移(用 Range 量度 target 内文本长度)。
                captureSelection: () => {
                    const sel = window.getSelection();
                    const text = target.textContent || "";
                    if (
                        !sel ||
                        sel.rangeCount === 0 ||
                        !sel.anchorNode ||
                        !sel.focusNode ||
                        !target.contains(sel.anchorNode) ||
                        !target.contains(sel.focusNode)
                    ) {
                        return { start: text.length, end: text.length };
                    }
                    const selected = sel.getRangeAt(0);
                    const beforeStart = document.createRange();
                    beforeStart.selectNodeContents(target);
                    beforeStart.setEnd(selected.startContainer, selected.startOffset);
                    const beforeEnd = document.createRange();
                    beforeEnd.selectNodeContents(target);
                    beforeEnd.setEnd(selected.endContainer, selected.endOffset);
                    return {
                        start: beforeStart.toString().length,
                        end: beforeEnd.toString().length,
                    };
                },
            };
        }
        return null;
    }

    /**
     * 从事件取可适配的输入元素 —— 优先用 composedPath()(穿透 open shadow DOM /
     * web component 内部),回退 ev.target。
     */
    function adaptEventTarget(ev) {
        if (ev && typeof ev.composedPath === "function") {
            for (const node of ev.composedPath()) {
                const adapter = adaptTarget(node);
                if (adapter) return { target: node, adapter };
            }
        }
        const target = ev ? ev.target : null;
        const adapter = adaptTarget(target);
        return adapter ? { target, adapter } : null;
    }

    // ───────────────────────── 显示归一 + 友好提示 ─────────────────────────
    //
    // 后端 redacted_text 形如 `[REDACTED env_assignment]` / `[REDACTED len=12 by_key=k]`。
    // 写回输入框 / 提示用户时归一为通用 `[REDACTED]`,并把 finding 规则名翻成友好标签。
    // 注意:这是**显示侧**美化,真正脱敏已由后端完成;此处不参与任何安全决策。

    function toDisplayRedactedText(text) {
        return text
            .replace(
                /\[REDACTED (?:len=\d+ by_key=[A-Za-z0-9_.-]+|[a-z_]+)\]/g,
                "[REDACTED]",
            )
            // 兜底清理历史破碎占位符(`[REDACTED] github_token]`);master 后端已不产出,留作纵深。
            .replace(/\[REDACTED\]\s+[a-z_]+\]/g, "[REDACTED]");
    }

    function formatFindingLabel(kind) {
        const labels = {
            aws_access_key_id: "AWS Access Key",
            aws_access_key: "AWS Access Key",
            github_token: "GitHub Token",
            anthropic_api_key: "Anthropic API Key",
            anthropic_key: "Anthropic API Key",
            openai_api_key: "OpenAI API Key",
            openai_key: "OpenAI API Key",
            pem_private_key: "私钥",
            jwt: "JWT",
            env_assignment: "疑似密钥赋值",
            slack_webhook: "Slack Webhook",
            stripe_secret_key: "Stripe Secret Key",
            google_api_key: "Google API Key",
            gitlab_pat: "GitLab PAT",
            database_url: "数据库连接密钥",
            email: "邮箱地址",
            internal_ipv4: "内网地址",
        };
        return labels[kind] || "敏感内容";
    }

    function formatFindingList(findings) {
        const labels = Array.from(
            new Set(
                (Array.isArray(findings) ? findings : [])
                    .map(formatFindingLabel)
                    .filter(Boolean),
            ),
        );
        if (labels.length === 0) return "敏感内容";
        if (labels.length === 1) return labels[0];
        return `${labels.slice(0, -1).join("、")} 和 ${labels[labels.length - 1]}`;
    }

    // ───────────────────────── manual input 监听 ─────────────────────────
    //
    // 手动输入已进入 DOM,无法像 paste 那样在写入前 preventDefault。这里是**尽力而为的事后
    // 清理**:用户停顿(防抖)后把输入框全文交 Native Host,命中即回写 redacted_text。
    //
    // ⚠️ 安全边界(Codex review):防抖窗口(~700ms)内未脱敏文本仍在 DOM,页面 JS 可在此期间
    // 读取并经 fetch/XHR/WebSocket/autosave 外发,**绕过**本清理(无 DOM submit)。真正的硬保证在
    // paste 的写入前 preventDefault 与 submit 守门;manual input 守门只是纵深防御的补充层,
    // **不**作"完整泄漏防护"承诺。不落 storage / console,只保留 per-element timer 与序号。

    const inputChecks = new WeakMap();

    // 先登记"扩展写入的确切值"再 setText —— 若 setText 触发同步 input 事件,
    // scheduleInputCheck 能据此精确识别为自写而跳过,避免无限 input→redact 循环。
    function writeFieldByExtension(target, adapter, value) {
        const st = inputChecks.get(target);
        if (st) st.lastWritten = value;
        adapter.setText(value);
    }

    // 粘贴写回:有选区快照时在快照位置精确替换(保留框内既有内容,修"脱敏覆盖整框"),
    // 并把"扩展写入的确切全文"登记进 inputChecks.lastWritten —— 让随后由 setText 触发的
    // input 事件被 scheduleInputCheck 的**精确匹配**(text === lastWritten)识别为自写而跳过,
    // 不引入"包含 [REDACTED] 即跳过"的可绕过逻辑。无快照时退化为光标处 insertText。
    function insertAtPasteSnapshot(target, adapter, value, snapshot) {
        if (
            snapshot &&
            typeof snapshot.text === "string" &&
            typeof snapshot.start === "number" &&
            typeof snapshot.end === "number"
        ) {
            const start = Math.max(0, Math.min(snapshot.start, snapshot.text.length));
            const end = Math.max(start, Math.min(snapshot.end, snapshot.text.length));
            const next =
                snapshot.text.slice(0, start) + value + snapshot.text.slice(end);
            if (target instanceof Element) {
                const st = inputChecks.get(target);
                if (st) {
                    st.lastWritten = next;
                } else {
                    inputChecks.set(target, {
                        seq: 0,
                        timer: 0,
                        lastText: "",
                        lastWritten: next,
                    });
                }
            }
            adapter.setText(next);
            return;
        }
        adapter.insertText(value);
    }

    function scheduleInputCheck(target, adapter) {
        adapter = adapter || adaptTarget(target);
        if (!adapter || !(target instanceof Element)) return;
        const text = adapter.getText();
        if (!text) return;

        const prev = inputChecks.get(target) || {
            seq: 0,
            timer: 0,
            lastText: "",
            lastWritten: null,
        };
        // Codex review NEEDS-FIX:仅当全文 === 扩展上次写入的**确切值**才跳过(防循环)。
        // **不**用包含式 redaction 标记匹配 —— 否则用户在普通文本里手打 `[REDACTED ...]`
        // 即可诱导跳过分类,绕过守门。绝不信任用户控制的文本内容。
        if (text === prev.lastWritten) return;

        if (prev.timer) clearTimeout(prev.timer);
        const next = {
            seq: prev.seq + 1,
            timer: 0,
            lastText: text,
            lastWritten: prev.lastWritten,
        };
        next.timer = setTimeout(async () => {
            const current = inputChecks.get(target);
            if (!current || current.seq !== next.seq) return;
            const ad = adaptTarget(target);
            if (!ad) return;
            const latest = ad.getText();
            if (!latest || latest !== next.lastText) return;

            const resp = await callBackground("input", latest);
            const after = inputChecks.get(target);
            if (!after || after.seq !== next.seq) return;
            const latestAdapter = adaptTarget(target);
            if (!latestAdapter) return;
            const latestAgain = latestAdapter.getText();
            if (latestAgain !== latest) return;

            if (resp.action === "allow") return;
            if (resp.action === "redact" && typeof resp.redacted_text === "string") {
                const safeText = toDisplayRedactedText(resp.redacted_text);
                showSafeVersionPrompt({
                    findings: resp.findings,
                    onUse: () => {
                        const currentAdapter = adaptTarget(target);
                        if (!currentAdapter) return;
                        if (currentAdapter.getText() !== latestAgain) {
                            showToast("Vigil: 输入内容已变化,请重新触发安全检查。", "warn");
                            return;
                        }
                        // 经 writeFieldByExtension 登记 lastWritten,随后的自写 input 事件
                        // 按精确匹配跳过,保留 master 的防绕过语义。
                        writeFieldByExtension(target, currentAdapter, safeText);
                        showToast("Vigil 已使用安全版本替换输入内容。", "info");
                    },
                    onCancel: () => {
                        showToast("Vigil 已取消本次安全替换。", "info");
                    },
                });
                return;
            }

            writeFieldByExtension(target, latestAdapter, "");
            const reason = resp._error || (resp.findings || []).join(", ") || "block";
            showToast(`Vigil: 输入内容被阻断(${reason})`, "error");
        }, INPUT_DEBOUNCE_MS);
        inputChecks.set(target, next);
    }

    document.addEventListener(
        "input",
        (ev) => {
            try {
                const adapted = adaptEventTarget(ev);
                if (adapted) scheduleInputCheck(adapted.target, adapted.adapter);
            } catch (_) {
                // 守住 paste/submit 稳定路径:input 增强失败时只放弃本次手动输入检查。
            }
        },
        true,
    );

    // ───────────────────────── paste 监听 ─────────────────────────

    document.addEventListener(
        "paste",
        async (ev) => {
            const adapted = adaptEventTarget(ev);
            if (!adapted) return; // 非文本输入,放行
            const { target, adapter } = adapted;

            const clip = ev.clipboardData;
            if (!clip) return;
            const text = clip.getData("text/plain") || "";
            if (text.length === 0) {
                // text/plain 为空但剪贴板含 text/html → 原生富文本粘贴会把(可能带密钥的)
                // 文本绕过"写入前 preventDefault"硬保证(adversarial review MEDIUM)。
                // fail-closed:拦截原生粘贴 + 提示改纯文本。图片/文件(Files)非文本密钥威胁,
                // 放行以免误伤截图粘贴。
                const hasHtml =
                    clip.types &&
                    Array.prototype.indexOf.call(clip.types, "text/html") !== -1;
                if (hasHtml) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    showToast(
                        "Vigil: 富文本粘贴已拦截,请用纯文本粘贴(Ctrl+Shift+V)再试",
                        "warn",
                    );
                }
                return;
            }
            // preventDefault 前抓取选区快照(光标/选中范围)——用于在原位精确插入,
            // 而非整框替换(修"粘贴脱敏覆盖整框")。
            const selection =
                typeof adapter.captureSelection === "function"
                    ? adapter.captureSelection()
                    : null;
            const pasteSnapshot = selection
                ? { text: adapter.getText(), start: selection.start, end: selection.end }
                : null;

            // 先 preventDefault,避免在 check 期间原文已进入 DOM
            ev.preventDefault();
            ev.stopPropagation();

            const resp = await callBackground("paste", text);
            if (resp.action === "allow") {
                // 允许 —— 在快照位置插入原文(Plain text;保留框内既有内容)
                insertAtPasteSnapshot(target, adapter, text, pasteSnapshot);
                return;
            }
            if (resp.action === "redact" && typeof resp.redacted_text === "string") {
                const safeText = toDisplayRedactedText(resp.redacted_text);
                showSafeVersionPrompt({
                    findings: resp.findings,
                    onUse: () => {
                        const currentAdapter = adaptTarget(target);
                        if (!currentAdapter) return;
                        if (
                            pasteSnapshot &&
                            currentAdapter.getText() !== pasteSnapshot.text
                        ) {
                            showToast("Vigil: 输入内容已变化,请重新粘贴安全版本。", "warn");
                            return;
                        }
                        // 在快照位置插入显示归一后的脱敏文本(不抹掉框内既有内容)
                        insertAtPasteSnapshot(target, currentAdapter, safeText, pasteSnapshot);
                        showToast("Vigil 已插入安全版本。", "info");
                    },
                    onCancel: () => {
                        showToast("Vigil 已取消本次粘贴。", "info");
                    },
                });
                return;
            }
            // block / 未知 action / 协议错误 —— fail-closed
            const reason = resp._error || (resp.findings || []).join(", ") || "block";
            showToast(`Vigil: 粘贴被阻断(${reason})`, "error");
        },
        true, // 捕获阶段,抢先拿到 event
    );

    // ───────────────────────── submit 监听 ─────────────────────────

    /**
     * 取"即将被提交"的输入文本 + **primaryInput**(供 form-level redact 回写)。
     *
     * α2 策略:
     *   1. 优先问站点 adapter —— 找到"主输入"就用它(ChatGPT prompt textarea 等)
     *   2. 否则走 α1 降级:form.elements 逐个聚合文本 + primaryInput=null
     *   3. contenteditable 事件(keydown Enter 路径)直接用 target 本身
     *
     * @returns {{ text: string, primaryInput: Element | null }}
     *   primaryInput 非空时可被 redact 回写;为 null 时 caller 应降级 block
     */
    function collectSubmitPayload(target) {
        // 站点 adapter 优先(仅 form submit 路径用;keydown 路径直接 target)
        if (target instanceof HTMLFormElement) {
            const site = getSiteAdapter();
            if (site) {
                // R1 BLOCKER 修复:scope 到 **被提交的 form**,不再全局搜。
                // `findPrimaryInput(form)` 用 `form.querySelector` 保证返回元素在 form 子树内,
                // 避免"决策文本来自页面其它 editor 但浏览器仍提交原 form"的 bypass。
                const primary = site.findPrimaryInput(target);
                // 二次 sanity:确实在 form 子树内(防 findPrimaryInput 将来扩展外部查)
                if (primary && target.contains(primary)) {
                    const ad = adaptTarget(primary);
                    if (ad) {
                        const v = ad.getText();
                        if (v) return { text: v, primaryInput: primary };
                    }
                }
                // 站点 adapter 在本 form 内找不到 prompt 主输入:**不回退 document 全局搜**
                // (Codex R1 要求);直接走 α1 form-scoped 降级聚合
            }
            // α1 降级:form.elements 全量聚合,primaryInput=null 禁 redact 回写
            const parts = [];
            for (const el of target.elements) {
                const ad = adaptTarget(el);
                if (ad) {
                    const v = ad.getText();
                    if (v) parts.push(v);
                }
            }
            return { text: parts.join("\n"), primaryInput: null };
        }
        // contenteditable Enter 路径:target 就是主输入
        const ad = adaptTarget(target);
        if (ad && target instanceof Element) {
            return { text: ad.getText(), primaryInput: target };
        }
        return { text: "", primaryInput: null };
    }

    // R1 MUST-FIX 1:`form.submit()` 会绕过 HTML validation 与所有 `submit` 监听器 ——
    // 对站点业务代码(ChatGPT/Claude 等依赖 submit event)是 behavioral regression。
    // 改为 **allow-once WeakSet 标记 + `form.requestSubmit(submitter)`**:
    //   - 原 ev 记住 submitter 引用
    //   - 标 form 为 allow-once → 在本 listener 再被触发时直接放行(不调 background)
    //   - 用 `requestSubmit` 而非 `submit()`:保留 HTML validation,触发 submit event,
    //     其他站点 listener 正常参与。本 listener 检查 allow-once 即短路
    const allowedOnce = new WeakSet();

    document.addEventListener(
        "submit",
        async (ev) => {
            const form = ev.target;
            if (!(form instanceof HTMLFormElement)) return;
            // allow-once 短路(R1 MUST-FIX 1)
            if (allowedOnce.has(form)) {
                allowedOnce.delete(form); // 消费一次性标记
                return;
            }
            const { text, primaryInput } = collectSubmitPayload(form);
            if (text.length === 0) return;
            // 记住 submitter(button 触发时需要,决定 formaction / formmethod 等)
            const submitter =
                ev.submitter instanceof HTMLElement ? ev.submitter : null;
            ev.preventDefault();
            ev.stopPropagation();
            const resp = await callBackground("submit", text);
            if (resp.action === "allow") {
                // 允许 —— 标 allow-once 并重新触发,保留站点 validation + 其他 listener
                allowedOnce.add(form);
                if (typeof form.requestSubmit === "function") {
                    form.requestSubmit(submitter);
                } else {
                    // 极旧浏览器 fallback(MV3 要求 Chrome 120+,requestSubmit 一定有)
                    form.submit();
                }
                return;
            }
            if (resp.action === "redact" && typeof resp.redacted_text === "string") {
                // α2:form-level redact 真写 —— 仅在 primaryInput 明确定位时执行,
                // primaryInput=null(heterogeneous form)仍降级 block + 提示,保留 fail-safe
                if (primaryInput) {
                    const ad = adaptTarget(primaryInput);
                    if (ad) {
                        const safeText = toDisplayRedactedText(resp.redacted_text);
                        const originalText = ad.getText();
                        const site = getSiteAdapter();
                        const siteLabel = site ? `[${site.label}] ` : "";
                        showSafeVersionPrompt({
                            findings: resp.findings,
                            onUse: () => {
                                const currentAdapter = adaptTarget(primaryInput);
                                if (!currentAdapter) return;
                                if (currentAdapter.getText() !== originalText) {
                                    showToast(
                                        "Vigil: 提交内容已变化,请重新触发安全检查。",
                                        "warn",
                                    );
                                    return;
                                }
                                writeFieldByExtension(primaryInput, currentAdapter, safeText);
                                showToast(
                                    `Vigil 已为${siteLabel || "当前输入"}应用安全版本，请确认后再提交。`,
                                    "info",
                                );
                            },
                            onCancel: () => {
                                showToast("Vigil 已取消本次提交。", "info");
                            },
                        });
                        return;
                    }
                }
                // primaryInput 不可用 → 降级 block
                showToast(
                    `Vigil 检测到 ${formatFindingList(resp.findings)}，但无法定位具体输入框完成脱敏。请手工清理后再提交。`,
                    "warn",
                );
                return;
            }
            const reason = resp._error || (resp.findings || []).join(", ") || "block";
            showToast(`Vigil: 提交被阻断(${reason})`, "error");
        },
        true,
    );

    // contenteditable Enter 提交(ChatGPT / Claude 等富文本常见 UX)
    document.addEventListener(
        "keydown",
        async (ev) => {
            if (ev.key !== "Enter" || ev.shiftKey || ev.isComposing) return;
            const target = ev.target;
            if (!(target instanceof HTMLElement)) return;
            if (!(target.isContentEditable || target.contentEditable === "true"))
                return;
            const text = target.textContent || "";
            if (text.length === 0) return;
            ev.preventDefault();
            ev.stopPropagation();
            const resp = await callBackground("submit", text);
            if (resp.action === "allow") {
                // 放行 —— 重新 dispatch 一个 Enter(避免触发本 listener 递归:dispatch 的事件
                // 在 capture 阶段也会到本 handler,但 isTrusted=false,站点代码未必处理;
                // MVP 简化:直接调用 document.execCommand("insertLineBreak") 让用户手动 submit)
                document.execCommand("insertLineBreak");
                return;
            }
            if (resp.action === "redact" && typeof resp.redacted_text === "string") {
                const ad = adaptTarget(target);
                if (ad) {
                    const safeText = toDisplayRedactedText(resp.redacted_text);
                    const originalText = ad.getText();
                    showSafeVersionPrompt({
                        findings: resp.findings,
                        onUse: () => {
                            const currentAdapter = adaptTarget(target);
                            if (!currentAdapter) return;
                            if (currentAdapter.getText() !== originalText) {
                                showToast(
                                    "Vigil: 提交内容已变化,请重新触发安全检查。",
                                    "warn",
                                );
                                return;
                            }
                            writeFieldByExtension(target, currentAdapter, safeText);
                            showToast("Vigil 已应用安全版本，请确认后再提交。", "info");
                        },
                        onCancel: () => {
                            showToast("Vigil 已取消本次提交。", "info");
                        },
                    });
                }
                return;
            }
            const reason = resp._error || (resp.findings || []).join(", ") || "block";
            showToast(`Vigil: 提交被阻断(${reason})`, "error");
        },
        true,
    );
})();
