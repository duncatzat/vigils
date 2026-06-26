import { normalizeCustomSiteInput } from "./custom-sites.js";

// 普通用户版 popup:当前页面保护状态 + 安全事件摘要。
// 安全契约:只展示 origin / action / finding 类型等元数据,不读取或保存页面原文。
(() => {
    "use strict";

    const ONBOARDING_KEY = "vigilPopupOnboarded";

    const listEl = document.getElementById("findings-list");
    const emptyHintEl = document.getElementById("empty-hint");
    const countLabel = document.getElementById("count-label");
    const clearBtn = document.getElementById("clear-btn");
    const optionsLink = document.getElementById("options-link");
    const statusPill = document.getElementById("status-pill");
    const statusLabel = document.getElementById("status-label");
    const onboardingCard = document.getElementById("onboarding-card");
    const onboardingDoneBtn = document.getElementById("onboarding-done-btn");
    const pageStatusTitle = document.getElementById("page-status-title");
    const pageStatusDetail = document.getElementById("page-status-detail");
    const protectCurrentBtn = document.getElementById("protect-current-btn");

    let currentPageSite = null;
    let lastRenderedFindings = "";

    function fmtTs(ts) {
        try {
            return new Date(ts).toLocaleTimeString();
        } catch {
            return String(ts || "");
        }
    }

    function sendRuntimeMessage(msg) {
        return new Promise((resolve) => {
            chrome.runtime.sendMessage(msg, (resp) => {
                if (chrome.runtime.lastError) {
                    resolve({ ok: false, _error: chrome.runtime.lastError.message });
                    return;
                }
                resolve(resp || {});
            });
        });
    }

    function queryActiveTab() {
        return new Promise((resolve) => {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (chrome.runtime.lastError) {
                    resolve(null);
                    return;
                }
                resolve(Array.isArray(tabs) && tabs.length > 0 ? tabs[0] : null);
            });
        });
    }

    function permissionsContains(pattern) {
        return new Promise((resolve) => {
            chrome.permissions.contains({ origins: [pattern] }, (allowed) => {
                if (chrome.runtime.lastError) {
                    resolve(false);
                    return;
                }
                resolve(Boolean(allowed));
            });
        });
    }

    function requestOriginPermission(pattern) {
        return new Promise((resolve) => {
            chrome.permissions.request({ origins: [pattern] }, (granted) => {
                if (chrome.runtime.lastError) {
                    resolve({ granted: false, _error: chrome.runtime.lastError.message });
                    return;
                }
                resolve({ granted: Boolean(granted) });
            });
        });
    }

    function setHeaderStatus(label, tone) {
        if (!statusPill || !statusLabel) return;
        statusLabel.textContent = label;
        statusPill.classList.toggle("status-pill-warn", tone === "warn");
        statusPill.classList.toggle("status-pill-muted", tone === "muted");
    }

    function setPageStatus(title, detail, tone, canProtect) {
        pageStatusTitle.textContent = title;
        pageStatusDetail.textContent = detail;
        protectCurrentBtn.classList.toggle("hidden", !canProtect);
        setHeaderStatus(title, tone);
    }

    function eventKindLabel(kind) {
        const labels = {
            paste: "粘贴时",
            input: "输入时",
            submit: "发送前",
        };
        return labels[kind] || "操作时";
    }

    function actionLabel(action) {
        const labels = {
            allow: "已放行",
            confirm_redact: "已建议脱敏",
            block: "已阻断",
        };
        return labels[action] || "已拦截";
    }

    function findingLabel(kind) {
        const labels = {
            openai_api_key: "OpenAI API Key",
            anthropic_api_key: "Anthropic API Key",
            google_api_key: "Google API Key",
            github_token: "GitHub Token",
            gitlab_pat: "GitLab Token",
            slack_webhook: "Slack Webhook",
            stripe_secret_key: "Stripe Secret Key",
            aws_access_key_id: "AWS Access Key",
            jwt: "JWT",
            env_assignment: ".env 变量",
            database_url: "数据库连接串",
            pem_private_key: "私钥",
        };
        return labels[kind] || String(kind || "风险内容");
    }

    function renderFindings(items) {
        const hash = JSON.stringify(items);
        if (hash === lastRenderedFindings) return;
        lastRenderedFindings = hash;

        listEl.replaceChildren();

        if (!Array.isArray(items) || items.length === 0) {
            emptyHintEl.classList.remove("hidden");
            listEl.classList.add("hidden");
            countLabel.textContent = "最近 0 条";
            return;
        }

        emptyHintEl.classList.add("hidden");
        listEl.classList.remove("hidden");
        countLabel.textContent = `最近 ${items.length} 条`;

        for (const it of items) {
            const li = document.createElement("li");
            li.classList.add("vigil-animate-in");

            const tag = document.createElement("span");
            tag.className = `tag tag-${it.action || "block"}`;
            tag.textContent = actionLabel(it.action);

            const col = document.createElement("div");

            const title = document.createElement("strong");
            const findingNames = Array.isArray(it.findings) && it.findings.length > 0
                ? it.findings.map(findingLabel).join("、")
                : "风险内容";
            title.textContent = `${eventKindLabel(it.event_kind)}检测到 ${findingNames}`;
            col.appendChild(title);

            const metaLine = document.createElement("div");
            metaLine.className = "meta-line";
            metaLine.textContent = `${it.origin || "当前网站"} · ${fmtTs(it.ts)}`;
            col.appendChild(metaLine);

            li.append(tag, col);
            listEl.appendChild(li);
        }
    }

    async function refreshEvents() {
        const resp = await sendRuntimeMessage({ type: "vigil_recent_findings" });
        renderFindings((resp && resp.findings) || []);
    }

    async function refreshModeLabel() {
        const resp = await sendRuntimeMessage({ type: "vigil_get_mode" });
        const mode = resp && resp.mode === "enterprise" ? "enterprise" : "consumer";
        if (mode === "enterprise") {
            setHeaderStatus("企业保护", "ok");
        }
    }

    async function refreshCurrentPage() {
        const tab = await queryActiveTab();
        const url = tab && typeof tab.url === "string" ? tab.url : "";
        let parsed = null;
        try {
            parsed = new URL(url);
        } catch {
            parsed = null;
        }

        if (!parsed || !["http:", "https:"].includes(parsed.protocol)) {
            currentPageSite = null;
            setPageStatus(
                "未保护",
                "当前页面不是普通网页，Vigils 不会在这里读取输入内容。",
                "muted",
                false,
            );
            return;
        }

        currentPageSite = normalizeCustomSiteInput(parsed.hostname);
        const pattern = currentPageSite && currentPageSite.ok
            ? currentPageSite.pattern
            : `${parsed.origin}/*`;
        const allowed = await permissionsContains(pattern);
        if (allowed) {
            setPageStatus(
                "已保护",
                `${parsed.hostname} 的复制、粘贴和发送会被本地检查。`,
                "ok",
                false,
            );
            return;
        }

        setPageStatus(
            "需要授权",
            `${parsed.hostname} 尚未加入保护范围。`,
            "warn",
            Boolean(currentPageSite && currentPageSite.ok),
        );
    }

    async function protectCurrentSite() {
        if (!currentPageSite || !currentPageSite.ok) return;
        protectCurrentBtn.disabled = true;
        try {
            const permission = await requestOriginPermission(currentPageSite.pattern);
            if (!permission.granted) {
                setPageStatus("需要授权", "你取消了该网站权限请求。", "warn", true);
                return;
            }
            const added = await sendRuntimeMessage({
                type: "vigil_add_custom_site",
                site: currentPageSite,
            });
            if (!added || !added.ok) {
                setPageStatus("需要授权", "权限已授权，但保存保护网站失败。", "warn", true);
                return;
            }
            setPageStatus(
                "已保护",
                `${currentPageSite.host} 已加入保护范围。刷新页面后生效。`,
                "ok",
                false,
            );
        } finally {
            protectCurrentBtn.disabled = false;
        }
    }

    function refreshOnboarding() {
        chrome.storage.local.get([ONBOARDING_KEY], (got) => {
            if (chrome.runtime.lastError) return;
            onboardingCard.classList.toggle("hidden", Boolean(got && got[ONBOARDING_KEY]));
        });
    }

    onboardingDoneBtn.addEventListener("click", () => {
        chrome.storage.local.set({ [ONBOARDING_KEY]: true }, () => {
            onboardingCard.classList.add("hidden");
        });
    });

    clearBtn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "vigil_clear_findings" }, () => {
            lastRenderedFindings = "";
            refreshEvents();
        });
    });

    protectCurrentBtn.addEventListener("click", protectCurrentSite);

    optionsLink.addEventListener("click", (ev) => {
        ev.preventDefault();
        if (chrome.runtime.openOptionsPage) {
            chrome.runtime.openOptionsPage();
        }
    });

    (() => {
        setHeaderStatus("检查中", "muted");
        refreshOnboarding();
        refreshEvents();
        refreshCurrentPage();
        refreshModeLabel();
    })();

    setInterval(() => {
        refreshEvents();
        refreshCurrentPage();
    }, 2000);
})();
