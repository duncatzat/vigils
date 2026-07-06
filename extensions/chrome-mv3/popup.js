import { normalizeCustomSiteInput } from "./custom-sites.js";

// 普通用户版 popup:当前页面保护状态 + 安全事件摘要。
// 安全契约:只展示 origin / action / finding 类型等元数据,不读取或保存页面原文。
(() => {
    "use strict";

    const listEl = document.getElementById("findings-list");
    const emptyStateEl = document.getElementById("empty-state");
    const clearBtn = document.getElementById("clear-btn");
    const optionsLink = document.getElementById("options-link");
    const headerStatus = document.getElementById("header-status");
    const statusText = document.getElementById("status-text");
    const statusDomain = document.getElementById("status-domain");
    const banner = document.getElementById("banner");
    const bannerDomain = document.getElementById("banner-domain");
    const protectBtn = document.getElementById("protect-btn");
    const foldHeader = document.getElementById("fold-header");
    const foldBody = document.getElementById("fold-body");
    const eventCount = document.getElementById("event-count");

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

    function setHeaderStatus(tone) {
        if (!headerStatus) return;
        headerStatus.className = "header-status";
        if (tone === "warn") {
            headerStatus.classList.add("warn");
        } else if (tone === "muted") {
            headerStatus.classList.add("muted");
        }
    }

    function setPageStatus(title, domain, tone, canProtect) {
        if (statusText) statusText.textContent = title;
        if (statusDomain) statusDomain.textContent = domain ? `· ${domain}` : "";
        setHeaderStatus(tone);

        if (banner) {
            banner.classList.toggle("hidden", !canProtect);
            if (canProtect && bannerDomain) {
                bannerDomain.textContent = domain || "当前网站";
            }
        }
    }

    function eventKindLabel(kind) {
        const labels = {
            paste: "粘贴时",
            input: "输入时",
            submit: "发送前",
        };
        return labels[kind] || "操作时";
    }

    function actionIconClass(action) {
        if (action === "block") return "block";
        if (action === "allow") return "allow";
        return "warn";
    }

    function actionIconText(action) {
        if (action === "block") return "✕";
        if (action === "allow") return "✓";
        return "⚠️";
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
            emptyStateEl.classList.remove("hidden");
            listEl.classList.add("hidden");
            if (eventCount) {
                eventCount.classList.add("hidden");
                eventCount.textContent = "0";
            }
            return;
        }

        emptyStateEl.classList.add("hidden");
        listEl.classList.remove("hidden");
        if (eventCount) {
            eventCount.classList.remove("hidden");
            eventCount.textContent = String(items.length);
        }

        for (const it of items) {
            const li = document.createElement("li");
            li.classList.add("event-row");

            const iconClass = actionIconClass(it.action);
            const iconText = actionIconText(it.action);
            const findingNames = Array.isArray(it.findings) && it.findings.length > 0
                ? it.findings.map(findingLabel).join("、")
                : "风险内容";

            li.innerHTML = `
                <div class="event-row-icon ${iconClass}">${iconText}</div>
                <div class="event-row-body">
                    <div class="title">${eventKindLabel(it.event_kind)}检测到 ${findingNames}</div>
                    <div class="meta">${it.origin || "当前网站"} · ${fmtTs(it.ts)}</div>
                </div>
                <div class="event-row-arrow">›</div>
            `;

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
            // 企业模式:标出实际扫描后端(本机引擎 = 检查在本机 Vigils 进程完成)。
            const backendResp = await sendRuntimeMessage({ type: "vigil_get_enterprise_backend" });
            const backend =
                backendResp && backendResp.backend === "native_host" ? "native_host" : "none";
            if (statusText) {
                statusText.textContent =
                    backend === "native_host" ? "企业保护 · 本机引擎" : "企业保护";
            }
            setHeaderStatus("ok");
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
            setPageStatus("未保护", "", "muted", false);
            return;
        }

        currentPageSite = normalizeCustomSiteInput(parsed.hostname);
        const pattern = currentPageSite && currentPageSite.ok
            ? currentPageSite.pattern
            : `${parsed.origin}/*`;
        const allowed = await permissionsContains(pattern);
        if (allowed) {
            setPageStatus("保护中", parsed.hostname, "ok", false);
            return;
        }

        setPageStatus(
            "待授权",
            parsed.hostname,
            "warn",
            Boolean(currentPageSite && currentPageSite.ok),
        );
    }

    async function protectCurrentSite() {
        if (!currentPageSite || !currentPageSite.ok) return;
        protectBtn.disabled = true;
        try {
            const permission = await requestOriginPermission(currentPageSite.pattern);
            if (!permission.granted) {
                setPageStatus("待授权", currentPageSite.host, "warn", true);
                return;
            }
            const added = await sendRuntimeMessage({
                type: "vigil_add_custom_site",
                site: currentPageSite,
            });
            if (!added || !added.ok) {
                setPageStatus("待授权", "保存保护网站失败", "warn", true);
                return;
            }
            setPageStatus("保护中", currentPageSite.host, "ok", false);
        } finally {
            protectBtn.disabled = false;
        }
    }

    clearBtn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "vigil_clear_findings" }, () => {
            lastRenderedFindings = "";
            refreshEvents();
        });
    });

    // 折叠事件列表
    if (foldHeader) {
        foldHeader.addEventListener("click", () => {
            foldHeader.classList.toggle("open");
            foldBody.classList.toggle("open");
        });
    }

    protectBtn.addEventListener("click", protectCurrentSite);

    optionsLink.addEventListener("click", (ev) => {
        ev.preventDefault();
        if (chrome.runtime.openOptionsPage) {
            chrome.runtime.openOptionsPage();
        }
    });

    (() => {
        setHeaderStatus("muted");
        refreshEvents();
        refreshCurrentPage();
        refreshModeLabel();
    })();

    setInterval(() => {
        refreshEvents();
        refreshCurrentPage();
    }, 2000);
})();
