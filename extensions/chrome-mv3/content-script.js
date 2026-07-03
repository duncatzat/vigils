// I09b-α1/α2 content script —— paste / input / submit 守门。
//
// 职责:
//   - 监听 document 级 `paste` 事件(捕获阶段,拦下纯文本粘贴前 dispatch)
//   - 监听 document 级 `input` 事件(防抖后检查手动输入,命中后回写脱敏文本)
//   - 监听 `submit` 事件(form submit + contenteditable Enter + button[type=submit])
//   - 将候选文本 + origin + event_kind 送到 background service worker,
//     收到 Response 后按 action 执行:
//       "allow"  → 放行
//       "confirm_redact" → 阻断原事件,待用户确认后用 Response.redacted_text 继续
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
//   - α3:popup 展示最近 N 条 finding
//   - β:contenteditable Enter 提交仍缺可靠的自动续发原语;当前 confirm/allow 均 fail-closed
//     给出显式 toast,用户确认后需手动再次触发发送

(() => {
    "use strict";

    if (globalThis.__vigilBrowserGuardLoaded) {
        globalThis.__vigilBrowserGuardDisabled = false;
        return;
    }
    globalThis.__vigilBrowserGuardLoaded = true;
    globalThis.__vigilBrowserGuardDisabled = false;

    const ORIGIN = location.origin;
    const INPUT_DEBOUNCE_MS = 700;

    function isGuardDisabled() {
        return globalThis.__vigilBrowserGuardDisabled === true;
    }

    function disableGuard() {
        globalThis.__vigilBrowserGuardDisabled = true;
        closeSafePrompt();
        closeRiskPrompt();
        if (toastEl) toastEl.remove();
        for (const frame of document.querySelectorAll("[data-vigil-input-ring]")) {
            if (frame instanceof HTMLElement) clearInputVigilFrame(frame);
        }
    }

    function enableGuard() {
        globalThis.__vigilBrowserGuardDisabled = false;
        for (const el of document.querySelectorAll(
            "input, textarea, [contenteditable='true'], [role='textbox']",
        )) {
            if (el instanceof HTMLElement && adaptTarget(el)) {
                setInputVigilState(el, "guarded");
            }
        }
    }

    chrome.runtime.onMessage.addListener((msg) => {
        if (!msg || typeof msg.type !== "string") return false;
        if (typeof msg.origin === "string" && msg.origin !== ORIGIN) return false;
        if (msg.type === "vigil_disable_guard") {
            disableGuard();
            return false;
        }
        if (msg.type === "vigil_enable_guard") {
            enableGuard();
            return false;
        }
        return false;
    });

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
                maxWidth: "min(320px, calc(100vw - 32px))",
                padding: "10px 14px",
                borderRadius: "12px",
                boxShadow: "0 12px 32px rgba(15, 23, 42, 0.28)",
                fontFamily: "system-ui, -apple-system, sans-serif",
                fontSize: "13px",
                lineHeight: "1.45",
                fontWeight: "600",
                color: "#fff",
                pointerEvents: "none",
                transition: "opacity 0.25s ease, transform 0.25s ease",
                opacity: "0",
                transform: "translateX(12px) translateY(8px)",
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
        const colorMap = {
            error: "var(--vigil-toast-bg-error)",
            warn: "var(--vigil-toast-bg-warn)",
            info: "var(--vigil-toast-bg-info)",
        };
        toastEl.style.background = colorMap[tone] || colorMap.info;
        // 用 textContent(Vue 默认插值同效),杜绝站点 HTML 注入 contaminate Vigil 提示
        toastEl.textContent = message;
        toastEl.style.opacity = "1";
        toastEl.style.transform = "translateX(0) translateY(0)";
        clearTimeout(showToast._t);
        showToast._t = setTimeout(() => {
            if (toastEl) {
                toastEl.style.opacity = "0";
                toastEl.style.transform = "translateX(12px) translateY(4px)";
            }
        }, 3500);
    }

    let riskPromptEl = null;
    let riskPromptTarget = null;
    let riskPromptArrowEl = null;
    function closeRiskPrompt() {
        if (riskPromptEl) {
            riskPromptEl.remove();
            riskPromptEl = null;
        }
        riskPromptTarget = null;
        riskPromptArrowEl = null;
    }

    function findingLabel(finding) {
        if (finding && typeof finding === "object" && typeof finding.label === "string") {
            return finding.label;
        }
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

    function primaryFindingLabel(findings) {
        const first = findings && findings.length > 0 ? findings[0] : null;
        return findingLabel(first || "风险内容");
    }

    function clampNumber(value, min, max) {
        return Math.max(min, Math.min(value, max));
    }

    function positionRiskPrompt() {
        if (!riskPromptEl) return;
        const margin = 14;
        const gap = 14;
        const promptWidth = Math.min(
            riskPromptEl.offsetWidth || 300,
            window.innerWidth - margin * 2,
        );
        const promptHeight = riskPromptEl.offsetHeight || 150;

        riskPromptEl.style.right = "auto";
        riskPromptEl.style.bottom = "auto";

        let left = window.innerWidth - promptWidth - margin;
        let top = window.innerHeight - promptHeight - margin;
        let placement = "fallback";

        if (riskPromptTarget) {
            const rect = riskPromptTarget.getBoundingClientRect();
            if (rect.width > 0 && rect.height > 0) {
                const fitsAbove = rect.top - gap - promptHeight >= margin;
                const fitsRight = rect.right + gap + promptWidth <= window.innerWidth - margin;
                const fitsBelow = rect.bottom + gap + promptHeight <= window.innerHeight - margin;

                // 首选：输入框右上角（右对齐，上方）
                if (fitsAbove) {
                    placement = "above";
                    left = rect.right - promptWidth;
                    top = rect.top - promptHeight - gap;
                } else if (fitsRight) {
                    // 上方没空间，放右侧
                    placement = "right";
                    left = rect.right + gap;
                    top = rect.top;
                } else if (fitsBelow) {
                    // 右侧也没空间，放下方右对齐
                    placement = "below";
                    left = rect.right - promptWidth;
                    top = rect.bottom + gap;
                }
            }
        }

        left = clampNumber(left, margin, window.innerWidth - promptWidth - margin);
        top = clampNumber(top, margin, window.innerHeight - promptHeight - margin);
        riskPromptEl.style.left = `${left}px`;
        riskPromptEl.style.top = `${top}px`;
        riskPromptEl.setAttribute("data-vigil-placement", placement);

        if (riskPromptArrowEl) {
            Object.assign(riskPromptArrowEl.style, {
                display: placement === "fallback" ? "none" : "block",
                left: "auto",
                right: "auto",
                top: "auto",
                bottom: "auto",
                transform: "rotate(45deg)",
                border: "0",
            });
            if (placement === "right") {
                Object.assign(riskPromptArrowEl.style, {
                    left: "-6px",
                    top: "calc(50% - 6px)",
                    borderLeft: "1px solid var(--vigil-prompt-border)",
                    borderBottom: "1px solid var(--vigil-prompt-border)",
                });
            } else if (placement === "above") {
                Object.assign(riskPromptArrowEl.style, {
                    bottom: "-6px",
                    left: "calc(50% - 6px)",
                    borderRight: "1px solid var(--vigil-prompt-border)",
                    borderBottom: "1px solid var(--vigil-prompt-border)",
                });
            } else if (placement === "below") {
                Object.assign(riskPromptArrowEl.style, {
                    top: "-6px",
                    left: "calc(50% - 6px)",
                    borderLeft: "1px solid var(--vigil-prompt-border)",
                    borderTop: "1px solid var(--vigil-prompt-border)",
                });
            }
        }
    }

    function mountPromptBase(title, findings, anchor) {
        closeSafePrompt();
        closeRiskPrompt();
        const parent = document.body || document.documentElement;
        if (!parent) return null;

        const box = document.createElement("div");
        box.setAttribute("data-vigil-risk-prompt", "");
        box.setAttribute("role", "dialog");
        box.setAttribute("aria-live", "polite");
        Object.assign(box.style, {
            position: "fixed",
            zIndex: "2147483647",
            width: "min(300px, calc(100vw - 32px))",
            padding: "14px",
            borderRadius: "14px",
            background: "var(--vigil-prompt-bg)",
            color: "var(--vigil-prompt-fg)",
            boxShadow: "var(--vigil-prompt-shadow)",
            fontFamily: "system-ui, -apple-system, sans-serif",
            fontSize: "13px",
            lineHeight: "1.45",
            border: "1px solid var(--vigil-prompt-border)",
            boxSizing: "border-box",
            animation: "vigil-prompt-in 0.25s cubic-bezier(0.4, 0, 0.2, 1) forwards, vigil-prompt-pulse 1.8s ease-in-out 0.3s 1",
            transition: "opacity 0.2s ease, transform 0.2s ease",
        });

        const arrow = document.createElement("div");
        arrow.setAttribute("data-vigil-risk-arrow", "");
        Object.assign(arrow.style, {
            position: "absolute",
            width: "12px",
            height: "12px",
            background: "var(--vigil-prompt-bg)",
            boxSizing: "border-box",
        });
        box.appendChild(arrow);

        const heading = document.createElement("div");
        heading.style.fontWeight = "750";
        heading.style.marginBottom = "6px";
        heading.style.fontSize = "13px";
        heading.textContent = title;
        box.appendChild(heading);

        const body = document.createElement("div");
        body.style.color = "var(--vigil-prompt-muted)";
        body.textContent = "建议先脱敏再发送。";
        box.appendChild(body);

        const privacy = document.createElement("div");
        privacy.style.marginTop = "6px";
        privacy.style.color = "var(--vigil-prompt-muted)";
        privacy.style.opacity = "0.7";
        privacy.textContent = "原文未离开你的浏览器。";
        box.appendChild(privacy);

        const actions = document.createElement("div");
        actions.style.display = "flex";
        actions.style.gap = "8px";
        actions.style.marginTop = "14px";
        actions.style.justifyContent = "flex-end";
        box.appendChild(actions);

        parent.appendChild(box);
        riskPromptEl = box;
        riskPromptArrowEl = arrow;
        riskPromptTarget = getInputFrameTarget(anchor) || anchor;
        positionRiskPrompt();
        return actions;
    }

    function promptButton(label, tone) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = label;
        Object.assign(btn.style, {
            border: "1px solid transparent",
            borderRadius: "8px",
            padding: "7px 12px",
            cursor: "pointer",
            fontWeight: "700",
            fontSize: "12px",
            transition: "background 0.15s ease, border-color 0.15s ease, transform 0.1s ease, box-shadow 0.15s ease, filter 0.15s ease",
        });
        if (tone === "primary") {
            Object.assign(btn.style, {
                color: "var(--vigil-btn-primary-fg)",
                background: "var(--vigil-btn-primary-bg)",
                borderColor: "var(--vigil-btn-primary-border)",
            });
            btn.addEventListener("mouseenter", () => {
                btn.style.filter = "brightness(1.08)";
                btn.style.boxShadow = "0 2px 8px rgba(245, 158, 11, 0.30)";
            });
            btn.addEventListener("mouseleave", () => {
                btn.style.filter = "none";
                btn.style.boxShadow = "none";
            });
        } else {
            Object.assign(btn.style, {
                color: "var(--vigil-btn-secondary-fg)",
                background: "var(--vigil-btn-secondary-bg)",
                borderColor: "var(--vigil-btn-secondary-border)",
            });
            btn.addEventListener("mouseenter", () => {
                btn.style.background = "rgba(255,255,255,0.95)";
                btn.style.borderColor = "#d97706";
            });
            btn.addEventListener("mouseleave", () => {
                btn.style.background = "var(--vigil-btn-secondary-bg)";
                btn.style.borderColor = "var(--vigil-btn-secondary-border)";
            });
        }
        btn.addEventListener("mousedown", () => { btn.style.transform = "scale(0.96)"; });
        btn.addEventListener("mouseup", () => { btn.style.transform = "scale(1)"; });
        return btn;
    }

    function showRiskPrompt(response, anchor, onRedact) {
        const findings = response.findings || [];
        const actions = mountPromptBase(`检测到 ${primaryFindingLabel(findings)}`, findings, anchor);
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

    function showBlockPrompt(response, anchor) {
        const findings = response.findings || [];
        const actions = mountPromptBase(`已阻断 ${primaryFindingLabel(findings)}`, findings, anchor);
        if (!actions) return;
        const closeBtn = promptButton("关闭", "secondary");
        closeBtn.addEventListener("click", closeRiskPrompt);
        actions.appendChild(closeBtn);
    }

    let safePromptEl = null;
    let promptTarget = null;
    let promptRepositionTimer = 0;
    const frameBaseShadow = new WeakMap();
    const frameBaseAnimation = new WeakMap();
    const targetActiveFrame = new WeakMap();
    let vigilStyleEl = null;

    function setInputVigilState(target, state /* "guarded" | "redact" | "block" */) {
        const frame = getInputFrameTarget(target);
        if (!frame) return;
        ensureVigilStyleMounted();

        const prevFrame = targetActiveFrame.get(target);
        if (prevFrame && prevFrame !== frame) clearInputVigilFrame(prevFrame);
        if (target !== frame) clearInputVigilFrame(target);
        clearNestedInputVigilFrames(frame);
        targetActiveFrame.set(target, frame);

        const colors = {
            guarded: "#60a5fa",
            redact: "#f59e0b",
            block: "#dc2626",
        };
        const color = colors[state] || colors.guarded;
        const radius = getFrameRadius(frame, target);

        if (!frameBaseShadow.has(frame)) {
            const currentShadow = window.getComputedStyle(frame).boxShadow;
            frameBaseShadow.set(
                frame,
                currentShadow && currentShadow !== "none" ? currentShadow : "",
            );
        }
        if (!frameBaseAnimation.has(frame)) {
            frameBaseAnimation.set(frame, frame.style.animation || "");
        }

        const baseShadow = frameBaseShadow.get(frame);
        const baseAnimation = frameBaseAnimation.get(frame);
        const ringShadow = [
            `inset 0 0 0 2px ${color}`,
            `0 0 0 2px ${hexToRgba(color, state === "guarded" ? 0.08 : 0.12)}`,
        ].join(", ");
        const fullRingShadow = baseShadow ? `${ringShadow}, ${baseShadow}` : ringShadow;

        frame.style.setProperty("--vigil-ring-shadow", fullRingShadow);
        frame.style.setProperty("--vigil-ring-glow-alpha", "0");
        frame.style.setProperty("outline", "none", "important");
        frame.style.setProperty("border-radius", radius, "important");
        frame.style.setProperty(
            "box-shadow",
            `var(--vigil-ring-shadow), 0 0 12px rgba(245, 158, 11, var(--vigil-ring-glow-alpha))`,
            "important",
        );
        frame.style.setProperty(
            "transition",
            appendTransition(frame.style.transition),
            "important",
        );

        if (state === "redact" && !prefersReducedMotion()) {
            frame.style.setProperty(
                "animation",
                "vigil-redact-ring-breathe 1.6s ease-in-out infinite",
                "important",
            );
        } else if (baseAnimation) {
            frame.style.setProperty("animation", baseAnimation);
        } else {
            frame.style.removeProperty("animation");
        }
        frame.setAttribute("data-vigil-input-ring", "");
    }

    function ensureVigilStyleMounted() {
        if (vigilStyleEl && vigilStyleEl.isConnected) return;
        const parent = document.head || document.documentElement;
        if (!parent) return;
        vigilStyleEl = document.createElement("style");
        vigilStyleEl.setAttribute("data-vigil-style", "");
        const prefersDark =
            typeof window.matchMedia === "function" &&
            window.matchMedia("(prefers-color-scheme: dark)").matches;
        const isDark = prefersDark ? true : false;
        vigilStyleEl.textContent = [
            /* ring animation (existing) */
            "@property --vigil-ring-glow-alpha {",
            "  syntax: '<number>';",
            "  inherits: false;",
            "  initial-value: 0;",
            "}",
            "@keyframes vigil-redact-ring-breathe {",
            "  0%, 100% { --vigil-ring-glow-alpha: 0; }",
            "  50% { --vigil-ring-glow-alpha: 0.55; }",
            "}",
            /* toast animation */
            "@keyframes vigil-toast-in {",
            "  from { opacity: 0; transform: translateX(-12px) translateY(8px); }",
            "  to   { opacity: 1; transform: translateX(0) translateY(0); }",
            "}",
            "@keyframes vigil-toast-out {",
            "  from { opacity: 1; transform: translateX(0) translateY(0); }",
            "  to   { opacity: 0; transform: translateX(-12px) translateY(4px); }",
            "}",
            /* prompt slide-in */
            "@keyframes vigil-prompt-in {",
            "  from { opacity: 0; transform: translateY(10px) scale(0.97); }",
            "  to   { opacity: 1; transform: translateY(0) scale(1); }",
            "}",
            /* prompt arrow pulse for attention */
            "@keyframes vigil-prompt-pulse {",
            "  0%, 100% { box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.35); }",
            "  50%  { box-shadow: 0 0 0 6px rgba(245, 158, 11, 0); }",
            "}",
            /* shared CSS variables */
            ":root {",
            "  --vigil-toast-bg-info: " + (isDark ? "#1e3a8a" : "#1e40af") + ";",
            "  --vigil-toast-bg-warn: " + (isDark ? "#7c2d12" : "#b45309") + ";",
            "  --vigil-toast-bg-error: " + (isDark ? "#7f1d1d" : "#b91c1c") + ";",
            "  --vigil-prompt-bg: " + (isDark ? "#0f172a" : "#ffffff") + ";",
            "  --vigil-prompt-fg: " + (isDark ? "#f8fafc" : "#111827") + ";",
            "  --vigil-prompt-muted: " + (isDark ? "#94a3b8" : "#374151") + ";",
            "  --vigil-prompt-border: " + (isDark ? "rgba(245, 158, 11, 0.45)" : "rgba(245, 158, 11, 0.30)") + ";",
            "  --vigil-prompt-shadow: " + (isDark ? "0 20px 48px rgba(0, 0, 0, 0.50)" : "0 16px 36px rgba(15, 23, 42, 0.18)") + ";",
            "  --vigil-btn-primary-bg: " + (isDark ? "#f59e0b" : "#f59e0b") + ";",
            "  --vigil-btn-primary-fg: " + (isDark ? "#0f172a" : "#111827") + ";",
            "  --vigil-btn-primary-border: " + (isDark ? "#d97706" : "#d97706") + ";",
            "  --vigil-btn-secondary-bg: " + (isDark ? "rgba(255,255,255,0.08)" : "rgba(255,255,255,0.72)") + ";",
            "  --vigil-btn-secondary-fg: " + (isDark ? "#e2e8f0" : "#44403c") + ";",
            "  --vigil-btn-secondary-border: " + (isDark ? "rgba(255,255,255,0.12)" : "#d6d3d1") + ";",
            "  --vigil-safe-bg: " + (isDark ? "rgba(245, 158, 11, 0.10)" : "rgba(255, 251, 235, 0.92)") + ";",
            "}",
        ].join("\n");
        parent.appendChild(vigilStyleEl);
    }

    function prefersReducedMotion() {
        return (
            typeof window.matchMedia === "function" &&
            window.matchMedia("(prefers-reduced-motion: reduce)").matches
        );
    }

    function clearInputVigilFrame(frame) {
        if (
            !frame.hasAttribute("data-vigil-input-ring") &&
            !frameBaseShadow.has(frame) &&
            !frameBaseAnimation.has(frame)
        ) {
            return;
        }
        const baseShadow = frameBaseShadow.get(frame);
        const baseAnimation = frameBaseAnimation.get(frame);
        frame.style.removeProperty("outline");
        frame.style.removeProperty("box-shadow");
        frame.style.removeProperty("animation");
        frame.style.removeProperty("--vigil-ring-shadow");
        frame.style.removeProperty("--vigil-ring-glow-alpha");
        frame.removeAttribute("data-vigil-input-ring");
        if (baseShadow) frame.style.setProperty("box-shadow", baseShadow, "important");
        if (baseAnimation) frame.style.setProperty("animation", baseAnimation);
    }

    function clearNestedInputVigilFrames(frame) {
        for (const el of frame.querySelectorAll("[data-vigil-input-ring]")) {
            if (el !== frame) clearInputVigilFrame(el);
        }
    }

    function getFrameRadius(frame, target) {
        const frameRadius = window.getComputedStyle(frame).borderRadius;
        if (frameRadius && frameRadius !== "0px") return frameRadius;
        if (target instanceof HTMLElement) {
            const targetRadius = window.getComputedStyle(target).borderRadius;
            if (targetRadius && targetRadius !== "0px") return targetRadius;
        }
        return "12px";
    }

    function getInputFrameTarget(target) {
        if (!(target instanceof HTMLElement)) return null;

        const existingFrame = getExistingInputRingFrame(target);
        if (existingFrame) return existingFrame;

        const targetRect = target.getBoundingClientRect();
        let node = target.parentElement;
        let depth = 0;
        while (node && depth < 7) {
            if (isUsableFrame(node, targetRect) && isVisualInputFrame(node)) {
                return node;
            }
            node = node.parentElement;
            depth += 1;
        }

        const form = target.closest("form");
        if (form instanceof HTMLElement && isUsableFrame(form, targetRect)) {
            return form;
        }

        return target;
    }

    function getExistingInputRingFrame(target) {
        let best = null;
        let bestArea = 0;
        for (const frame of document.querySelectorAll("[data-vigil-input-ring]")) {
            if (!(frame instanceof HTMLElement) || !frame.contains(target)) continue;
            const rect = frame.getBoundingClientRect();
            const area = rect.width * rect.height;
            if (area > bestArea) {
                best = frame;
                bestArea = area;
            }
        }
        return best;
    }

    function isVisualInputFrame(node) {
        const style = window.getComputedStyle(node);
        const hasRadius = style.borderRadius && style.borderRadius !== "0px";
        const hasBorder = style.borderStyle !== "none" && style.borderWidth !== "0px";
        const hasShadow = style.boxShadow && style.boxShadow !== "none";
        const hasBackground =
            style.backgroundColor &&
            style.backgroundColor !== "rgba(0, 0, 0, 0)" &&
            style.backgroundColor !== "transparent";
        return hasRadius || hasBorder || hasShadow || hasBackground;
    }

    function isUsableFrame(node, targetRect) {
        const rect = node.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        if (rect.width < targetRect.width || rect.height < targetRect.height) return false;
        if (rect.width > window.innerWidth - 8) return false;
        if (rect.height > 280) return false;
        return rect.width >= targetRect.width + 4 || rect.height >= targetRect.height + 4;
    }

    function hexToRgba(hex, alpha) {
        const value = hex.replace("#", "");
        const r = parseInt(value.slice(0, 2), 16);
        const g = parseInt(value.slice(2, 4), 16);
        const b = parseInt(value.slice(4, 6), 16);
        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    }

    function appendTransition(existing) {
        const extra = "outline-color 0.16s, box-shadow 0.16s, border-color 0.16s";
        if (!existing) return extra;
        if (existing.includes("outline-color") || existing.includes("box-shadow")) {
            return existing;
        }
        return `${existing}, ${extra}`;
    }

    function ensureSafePromptMounted(target) {
        const parent = document.body || document.documentElement;
        if (!parent) return false;
        if (!safePromptEl) {
            safePromptEl = document.createElement("div");
            safePromptEl.setAttribute("data-vigil-safe-prompt", "");
            safePromptEl.setAttribute("role", "dialog");
            safePromptEl.setAttribute("aria-live", "polite");
            Object.assign(safePromptEl.style, {
                position: "fixed",
                zIndex: "2147483647",
                maxWidth: "min(360px, calc(100vw - 32px))",
                padding: "8px 12px",
                borderRadius: "12px",
                border: "1px solid var(--vigil-prompt-border)",
                boxShadow: "var(--vigil-prompt-shadow)",
                fontFamily: "system-ui, -apple-system, sans-serif",
                fontSize: "12px",
                lineHeight: "1.45",
                fontWeight: "600",
                letterSpacing: "0",
                color: "var(--vigil-prompt-fg)",
                background: "var(--vigil-safe-bg)",
                backdropFilter: "blur(10px) saturate(1.6)",
                WebkitBackdropFilter: "blur(10px) saturate(1.6)",
                userSelect: "none",
                pointerEvents: "auto",
                animation: "vigil-prompt-in 0.25s cubic-bezier(0.4, 0, 0.2, 1) forwards",
                transition: "opacity 0.2s ease, transform 0.2s ease",
            });
        }
        if (!safePromptEl.isConnected) parent.appendChild(safePromptEl);
        promptTarget = getInputFrameTarget(target);
        positionSafePrompt();
        return true;
    }

    function positionSafePrompt() {
        if (!safePromptEl || !promptTarget) return;
        const rect = promptTarget.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return;
        const promptWidth = Math.min(safePromptEl.offsetWidth || 360, window.innerWidth - 32);
        const promptHeight = safePromptEl.offsetHeight || 40;
        const gap = 10;
        const margin = 16;

        let left;
        let top;
        let placement = "above";

        // 首选：输入框右上角（右对齐，上方）
        if (rect.top - gap - promptHeight >= margin) {
            placement = "above";
            top = rect.top - gap - promptHeight;
            left = rect.right - promptWidth;
        } else if (rect.right + gap + promptWidth <= window.innerWidth - margin) {
            // 上方没空间，放右侧
            placement = "right";
            top = rect.top;
            left = rect.right + gap;
        } else if (rect.bottom + gap + promptHeight <= window.innerHeight - margin) {
            // 右侧也没空间，放下方右对齐
            placement = "below";
            top = rect.bottom + gap;
            left = rect.right - promptWidth;
        } else {
            // fallback：紧贴上方
            placement = "above";
            top = Math.max(margin, rect.top - promptHeight - 4);
            left = rect.right - promptWidth;
        }

        left = clampNumber(left, margin, window.innerWidth - promptWidth - margin);
        top = clampNumber(top, margin, window.innerHeight - promptHeight - margin);

        safePromptEl.style.left = `${left}px`;
        safePromptEl.style.top = `${top}px`;
        safePromptEl.setAttribute("data-vigil-placement", placement);
    }

    function closeSafePrompt() {
        if (safePromptEl) {
            safePromptEl.replaceChildren();
            safePromptEl.remove();
        }
        promptTarget = null;
    }

    function showSafeVersionPrompt({ target, findings, onUse, onCancel }) {
        closeSafePrompt();
        if (target instanceof HTMLElement) setInputVigilState(target, "redact");
        if (!ensureSafePromptMounted(target)) return;

        const message = document.createElement("span");
        message.textContent = "已检测到敏感字符是否脱敏";
        Object.assign(message.style, {
            color: "#111827",
            fontWeight: "700",
            whiteSpace: "nowrap",
        });

        const sr = document.createElement("span");
        sr.textContent = `，检测到 ${formatFindingList(findings)}`;
        Object.assign(sr.style, {
            position: "absolute",
            width: "1px",
            height: "1px",
            padding: "0",
            margin: "-1px",
            overflow: "hidden",
            clip: "rect(0, 0, 0, 0)",
            whiteSpace: "nowrap",
            border: "0",
        });

        const confirmBtn = makeSafePromptButton("确认", "primary");
        const cancelBtn = makeSafePromptButton("取消", "secondary");

        const useSafeVersion = () => {
            closeSafePrompt();
            onUse();
            if (target instanceof HTMLElement) setInputVigilState(target, "guarded");
        };
        const cancelSafeVersion = () => {
            closeSafePrompt();
            if (target instanceof HTMLElement) setInputVigilState(target, "guarded");
            if (typeof onCancel === "function") onCancel();
        };

        confirmBtn.addEventListener("click", (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            useSafeVersion();
        });
        cancelBtn.addEventListener("click", (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            cancelSafeVersion();
        });

        Object.assign(safePromptEl.style, {
            display: "flex",
            alignItems: "center",
            gap: "8px",
        });
        safePromptEl.replaceChildren(message, confirmBtn, cancelBtn, sr);
        safePromptEl.setAttribute(
            "aria-label",
            `已检测到敏感字符是否脱敏，检测到 ${formatFindingList(findings)}`,
        );
        positionSafePrompt();
    }

    function makeSafePromptButton(label, variant) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = label;
        Object.assign(btn.style, {
            borderRadius: "8px",
            padding: "4px 10px",
            font: "inherit",
            fontWeight: variant === "primary" ? "750" : "650",
            lineHeight: "1.3",
            cursor: "pointer",
            whiteSpace: "nowrap",
            transition: "background 0.15s ease, border-color 0.15s ease, transform 0.1s ease, box-shadow 0.15s ease",
        });
        if (variant === "primary") {
            Object.assign(btn.style, {
                border: "1px solid var(--vigil-btn-primary-border)",
                background: "var(--vigil-btn-primary-bg)",
                color: "var(--vigil-btn-primary-fg)",
            });
            btn.addEventListener("mouseenter", () => {
                btn.style.filter = "brightness(1.1)";
                btn.style.boxShadow = "0 2px 8px rgba(245, 158, 11, 0.35)";
            });
            btn.addEventListener("mouseleave", () => {
                btn.style.filter = "none";
                btn.style.boxShadow = "none";
            });
            btn.addEventListener("mousedown", () => { btn.style.transform = "scale(0.96)"; });
            btn.addEventListener("mouseup", () => { btn.style.transform = "scale(1)"; });
        } else {
            Object.assign(btn.style, {
                border: "1px solid var(--vigil-btn-secondary-border)",
                background: "var(--vigil-btn-secondary-bg)",
                color: "var(--vigil-btn-secondary-fg)",
            });
            btn.addEventListener("mouseenter", () => {
                btn.style.background = "rgba(255,255,255,0.95)";
                btn.style.borderColor = "#d97706";
            });
            btn.addEventListener("mouseleave", () => {
                btn.style.background = "var(--vigil-btn-secondary-bg)";
                btn.style.borderColor = "var(--vigil-btn-secondary-border)";
            });
            btn.addEventListener("mousedown", () => { btn.style.transform = "scale(0.96)"; });
            btn.addEventListener("mouseup", () => { btn.style.transform = "scale(1)"; });
        }
        return btn;
    }

    window.addEventListener(
        "scroll",
        () => {
            clearTimeout(promptRepositionTimer);
            promptRepositionTimer = setTimeout(() => {
                positionSafePrompt();
                positionRiskPrompt();
            }, 16);
        },
        true,
    );
    window.addEventListener("resize", () => {
        positionSafePrompt();
        positionRiskPrompt();
    });

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
                if (isGuardDisabled()) {
                    replied = true;
                    resolve({ action: "allow", findings: [], _disabled: true });
                    return;
                }
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
        if (kind && typeof kind === "object" && typeof kind.label === "string") {
            return kind.label;
        }
        kind = typeof kind === "string" ? kind : kind && kind.kind;
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
        if (isGuardDisabled()) return;
        adapter = adapter || adaptTarget(target);
        if (!adapter || !(target instanceof Element)) return;
        if (target instanceof HTMLElement) setInputVigilState(target, "guarded");
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
            if (isGuardDisabled()) return;
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

            if (resp.action === "allow") {
                if (target instanceof HTMLElement) setInputVigilState(target, "guarded");
                return;
            }
            if (
                resp.action === "confirm_redact" &&
                typeof resp.redacted_text === "string"
            ) {
                const safeText = toDisplayRedactedText(resp.redacted_text);
                showRiskPrompt(resp, target, () => {
                    const currentAdapter = adaptTarget(target);
                    if (!currentAdapter) return;
                    if (currentAdapter.getText() !== latestAgain) {
                        showToast("Vigils: 输入内容已变化,请重新触发安全检查。", "warn");
                        return;
                    }
                    writeFieldByExtension(target, currentAdapter, safeText);
                    showToast("Vigils: 已脱敏后写入", "info");
                });
                return;
            }

            writeFieldByExtension(target, latestAdapter, "");
            if (target instanceof HTMLElement) setInputVigilState(target, "block");
            showBlockPrompt(resp, target);
        }, INPUT_DEBOUNCE_MS);
        inputChecks.set(target, next);
    }

    document.addEventListener(
        "input",
        (ev) => {
            if (isGuardDisabled()) return;
            try {
                const adapted = adaptEventTarget(ev);
                if (adapted) {
                    if (adapted.target instanceof HTMLElement) {
                        setInputVigilState(adapted.target, "guarded");
                    }
                    scheduleInputCheck(adapted.target, adapted.adapter);
                }
            } catch (_) {
                // 守住 paste/submit 稳定路径:input 增强失败时只放弃本次手动输入检查。
            }
        },
        true,
    );

    document.addEventListener(
        "focusin",
        (ev) => {
            if (isGuardDisabled()) return;
            const adapted = adaptEventTarget(ev);
            if (adapted && adapted.target instanceof HTMLElement) {
                setInputVigilState(adapted.target, "guarded");
            }
        },
        true,
    );

    // ───────────────────────── paste 监听 ─────────────────────────

    document.addEventListener(
        "paste",
        async (ev) => {
            if (isGuardDisabled()) return;
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
                        "Vigils: 富文本粘贴已拦截,请用纯文本粘贴(Ctrl+Shift+V)再试",
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
                if (target instanceof HTMLElement) setInputVigilState(target, "guarded");
                return;
            }
            if (
                resp.action === "confirm_redact" &&
                typeof resp.redacted_text === "string"
            ) {
                showRiskPrompt(resp, target, (redactedText) => {
                    const currentAdapter = adaptTarget(target);
                    if (!currentAdapter) return;
                    if (pasteSnapshot && currentAdapter.getText() !== pasteSnapshot.text) {
                        showToast("Vigils: 输入内容已变化,请重新粘贴安全版本。", "warn");
                        return;
                    }
                    insertAtPasteSnapshot(
                        target,
                        currentAdapter,
                        toDisplayRedactedText(redactedText),
                        pasteSnapshot,
                    );
                    showToast("Vigils: 已脱敏后写入", "info");
                });
                return;
            }
            if (target instanceof HTMLElement) setInputVigilState(target, "block");
            showBlockPrompt(resp, target);
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

    function continueSubmit(form, submitter) {
        allowedOnce.add(form);
        if (typeof form.requestSubmit === "function") {
            form.requestSubmit(submitter);
        } else {
            form.submit();
        }
    }

    function continueContenteditableSubmit(target, message) {
        if (target instanceof HTMLElement) setInputVigilState(target, "block");
        showToast(
            message ||
                "Vigils: 当前页面无法自动继续发送，请确认内容后手动再次发送。",
            "warn",
        );
    }

    document.addEventListener(
        "submit",
        async (ev) => {
            if (isGuardDisabled()) return;
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
                continueSubmit(form, submitter);
                return;
            }
            if (
                resp.action === "confirm_redact" &&
                typeof resp.redacted_text === "string"
            ) {
                if (primaryInput) {
                    const ad = adaptTarget(primaryInput);
                    const originalText = ad ? ad.getText() : "";
                    showRiskPrompt(resp, primaryInput, (redactedText) => {
                        if (primaryInput) {
                            const currentAdapter = adaptTarget(primaryInput);
                            if (!currentAdapter) return;
                            if (currentAdapter.getText() !== originalText) {
                                showToast(
                                    "Vigils: 提交内容已变化,请重新触发安全检查。",
                                    "warn",
                                );
                                return;
                            }
                            writeFieldByExtension(
                                primaryInput,
                                currentAdapter,
                                toDisplayRedactedText(redactedText),
                            );
                            continueSubmit(form, submitter);
                            showToast("Vigils: 已脱敏后写入", "info");
                        } else {
                            showToast("Vigils: 无法定位输入框，已阻断", "error");
                        }
                    });
                    return;
                }
                showToast("Vigils: 无法定位输入框，已阻断", "error");
                return;
            }
            if (primaryInput instanceof HTMLElement) setInputVigilState(primaryInput, "block");
            showBlockPrompt(resp, primaryInput);
        },
        true,
    );

    // contenteditable Enter 提交(ChatGPT / Claude 等富文本常见 UX)
    document.addEventListener(
        "keydown",
        async (ev) => {
            if (isGuardDisabled()) return;
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
                continueContenteditableSubmit(
                    target,
                    "Vigils: 已允许本次内容，请确认内容后手动再次发送。",
                );
                return;
            }
            if (
                resp.action === "confirm_redact" &&
                typeof resp.redacted_text === "string"
            ) {
                const ad = adaptTarget(target);
                const originalText = ad ? ad.getText() : "";
                showRiskPrompt(resp, target, (redactedText) => {
                    const currentAdapter = adaptTarget(target);
                    if (!currentAdapter) return;
                    if (currentAdapter.getText() !== originalText) {
                        showToast("Vigils: 提交内容已变化,请重新触发安全检查。", "warn");
                        return;
                    }
                    writeFieldByExtension(
                        target,
                        currentAdapter,
                        toDisplayRedactedText(redactedText),
                    );
                    continueContenteditableSubmit(
                        target,
                        "Vigils: 已脱敏后写入，请确认内容后手动再次发送。",
                    );
                });
                return;
            }
            if (target instanceof HTMLElement) setInputVigilState(target, "block");
            showBlockPrompt(resp, target);
        },
        true,
    );
})();
