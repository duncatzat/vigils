import { normalizeCustomSiteInput } from "./custom-sites.js";
import { normalizeCustomRiskRuleInput } from "./redaction-rules.js";

(() => {
    "use strict";

    const idEl = document.getElementById("extension-id");
    const copyIdBtn = document.getElementById("copy-id-btn");
    const extensionIdHint = document.getElementById("extension-id-hint");
    const customSiteForm = document.getElementById("custom-site-form");
    const customSiteInput = document.getElementById("custom-site-input");
    const customSiteAddBtn = document.getElementById("custom-site-add-btn");
    const customSiteHint = document.getElementById("custom-site-hint");
    const customSiteList = document.getElementById("custom-site-list");
    const customSiteEmpty = document.getElementById("custom-site-empty");
    const modeInputs = Array.from(document.querySelectorAll("input[name='vigil-mode']"));
    const modeHint = document.getElementById("mode-hint");
    const enterpriseSection = document.getElementById("enterprise-section");
    const customRiskForm = document.getElementById("custom-risk-form");
    const customRiskName = document.getElementById("custom-risk-name");
    const customRiskPrefix = document.getElementById("custom-risk-prefix");
    const customRiskMinLength = document.getElementById("custom-risk-min-length");
    const customRiskAction = document.getElementById("custom-risk-action");
    const customRiskAddBtn = document.getElementById("custom-risk-add-btn");
    const customRiskExampleFillBtn = document.getElementById("custom-risk-example-fill-btn");
    const customRiskHint = document.getElementById("custom-risk-hint");
    const customRiskList = document.getElementById("custom-risk-list");
    const customRiskEmpty = document.getElementById("custom-risk-empty");

    const extId = chrome.runtime.id;
    idEl.textContent = extId || "(无法获取)";

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            try {
                const ta = document.createElement("textarea");
                ta.value = text;
                ta.setAttribute("readonly", "");
                ta.style.position = "fixed";
                ta.style.left = "-9999px";
                document.body.appendChild(ta);
                ta.select();
                const ok = document.execCommand("copy");
                document.body.removeChild(ta);
                return ok;
            } catch {
                return false;
            }
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

    function flashExtensionIdHint(msg, tone /* "ok" | "warn" */) {
        if (!extensionIdHint) return;
        extensionIdHint.textContent = msg;
        extensionIdHint.style.color = tone === "warn" ? "#b45309" : "#15803d";
        extensionIdHint.classList.remove("fade");
        clearTimeout(flashExtensionIdHint._t);
        flashExtensionIdHint._t = setTimeout(() => {
            extensionIdHint.classList.add("fade");
        }, 1800);
    }

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

    function removeOriginPermission(pattern) {
        return new Promise((resolve) => {
            chrome.permissions.remove({ origins: [pattern] }, () => {
                void chrome.runtime.lastError;
                resolve();
            });
        });
    }

    const customSiteErrorLabels = {
        empty: "请输入域名",
        wildcard_not_allowed: "不支持通配符",
        userinfo_not_allowed: "不允许包含用户名或密码",
        domain_only: "只支持域名,不支持路径或查询参数",
        invalid_host: "域名格式无效",
        https_only: "仅支持 HTTPS 网站",
        permission_missing: "站点权限未授权",
    };

    const customRiskErrorLabels = {
        name_required: "请输入类型名称",
        prefix_required: "请输入前缀",
        min_length_range: "最小长度需在 6 到 256 之间",
        id_required: "规则 ID 无效",
    };

    function flashCustomSiteHint(msg, tone /* "ok" | "warn" */) {
        customSiteHint.textContent = msg;
        customSiteHint.style.color = tone === "warn" ? "#b45309" : "#15803d";
        customSiteHint.classList.remove("fade");
        clearTimeout(flashCustomSiteHint._t);
        flashCustomSiteHint._t = setTimeout(() => {
            customSiteHint.classList.add("fade");
        }, 2200);
    }

    function customSiteErrorMessage(code) {
        return customSiteErrorLabels[code] || String(code || "unknown");
    }

    function flashCustomRiskHint(msg, tone /* "ok" | "warn" */) {
        customRiskHint.textContent = msg;
        customRiskHint.style.color = tone === "warn" ? "#b45309" : "#15803d";
        customRiskHint.classList.remove("fade");
        clearTimeout(flashCustomRiskHint._t);
        flashCustomRiskHint._t = setTimeout(() => {
            customRiskHint.classList.add("fade");
        }, 2200);
    }

    function customRiskErrorMessage(code) {
        return customRiskErrorLabels[code] || String(code || "unknown");
    }

    function renderCustomSites(sites) {
        customSiteList.replaceChildren();
        const items = Array.isArray(sites) ? sites : [];
        customSiteEmpty.classList.toggle("hidden", items.length !== 0);

        for (const site of items) {
            const li = document.createElement("li");
            li.className = "custom-site-row";

            const host = document.createElement("code");
            host.className = "custom-site-host";
            host.textContent = site.host || site.pattern || "?";
            host.title = site.pattern || site.host || "";

            const status = document.createElement("span");
            status.className = "custom-site-status";
            if (site.hasPermission) {
                status.textContent = "已授权";
            } else {
                status.textContent = "缺权限";
                status.classList.add("custom-site-status-missing");
            }

            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.className = "custom-site-remove";
            removeBtn.textContent = "删除";
            removeBtn.addEventListener("click", async () => {
                removeBtn.disabled = true;
                const resp = await sendRuntimeMessage({
                    type: "vigil_remove_custom_site",
                    input: site.host || site.pattern,
                });
                if (!resp || !resp.ok) {
                    flashCustomSiteHint(
                        `删除失败:${customSiteErrorMessage(resp && resp._error)}`,
                        "warn",
                    );
                    removeBtn.disabled = false;
                    return;
                }
                flashCustomSiteHint("已删除并释放站点权限");
                await refreshCustomSites();
            });

            li.replaceChildren(host, status, removeBtn);
            customSiteList.appendChild(li);
        }
    }

    async function refreshCustomSites() {
        const resp = await sendRuntimeMessage({ type: "vigil_list_custom_sites" });
        renderCustomSites(resp && resp.sites);
    }

    function renderCustomRiskRules(rules) {
        customRiskList.replaceChildren();
        const items = Array.isArray(rules) ? rules : [];
        customRiskEmpty.classList.toggle("hidden", items.length !== 0);

        for (const rule of items) {
            const li = document.createElement("li");
            li.className = "custom-risk-row";

            const main = document.createElement("div");
            main.className = "custom-risk-main";

            const name = document.createElement("strong");
            name.textContent = rule.name || "自定义类型";

            const meta = document.createElement("span");
            meta.textContent = `${rule.prefix || ""} + ${rule.minLength || 0} 位以上 · ${
                rule.action === "block" ? "直接阻断" : "建议脱敏"
            }`;
            main.replaceChildren(name, meta);

            const enabledLabel = document.createElement("label");
            enabledLabel.className = "custom-risk-enabled";
            const enabledInput = document.createElement("input");
            enabledInput.type = "checkbox";
            enabledInput.checked = rule.enabled !== false;
            enabledInput.addEventListener("change", async () => {
                enabledInput.disabled = true;
                const resp = await sendRuntimeMessage({
                    type: "vigil_set_custom_risk_rule_enabled",
                    id: rule.id,
                    enabled: enabledInput.checked,
                });
                if (!resp || !resp.ok) {
                    flashCustomRiskHint(`更新失败:${customRiskErrorMessage(resp && resp._error)}`, "warn");
                    enabledInput.checked = !enabledInput.checked;
                } else {
                    flashCustomRiskHint(enabledInput.checked ? "已启用" : "已停用");
                }
                enabledInput.disabled = false;
            });
            enabledLabel.append(enabledInput, "启用");

            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.className = "custom-risk-remove";
            removeBtn.textContent = "删除";
            removeBtn.addEventListener("click", async () => {
                removeBtn.disabled = true;
                const resp = await sendRuntimeMessage({
                    type: "vigil_remove_custom_risk_rule",
                    id: rule.id,
                });
                if (!resp || !resp.ok) {
                    flashCustomRiskHint(`删除失败:${customRiskErrorMessage(resp && resp._error)}`, "warn");
                    removeBtn.disabled = false;
                    return;
                }
                flashCustomRiskHint("已删除自定义风险类型");
                await refreshCustomRiskRules();
            });

            li.replaceChildren(main, enabledLabel, removeBtn);
            customRiskList.appendChild(li);
        }
    }

    async function refreshCustomRiskRules() {
        const resp = await sendRuntimeMessage({ type: "vigil_list_custom_risk_rules" });
        renderCustomRiskRules(resp && resp.rules);
    }

    copyIdBtn.addEventListener("click", async () => {
        const ok = await copyText(extId);
        flashExtensionIdHint(ok ? "ID 已复制" : "复制失败(请手工选中)", ok ? "ok" : "warn");
    });

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

    customSiteForm.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const input = customSiteInput.value;
        customSiteAddBtn.disabled = true;
        try {
            const normalized = normalizeCustomSiteInput(input);
            if (!normalized || !normalized.ok) {
                flashCustomSiteHint(
                    `添加失败:${customSiteErrorMessage(normalized && normalized.error)}`,
                    "warn",
                );
                return;
            }

            const permission = await requestOriginPermission(normalized.pattern);
            if (!permission.granted) {
                flashCustomSiteHint(
                    permission._error
                        ? `授权失败:${permission._error}`
                        : "用户未授权该网站权限",
                    "warn",
                );
                return;
            }

            const added = await sendRuntimeMessage({
                type: "vigil_add_custom_site",
                site: normalized,
            });
            if (!added || !added.ok) {
                await removeOriginPermission(normalized.pattern);
                flashCustomSiteHint(
                    `保存失败:${customSiteErrorMessage(added && added._error)}`,
                    "warn",
                );
                return;
            }

            customSiteInput.value = "";
            flashCustomSiteHint(`已保护 ${normalized.host}`);
            await refreshCustomSites();
        } finally {
            customSiteAddBtn.disabled = false;
        }
    });

    customRiskForm.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        customRiskAddBtn.disabled = true;
        try {
            const normalized = normalizeCustomRiskRuleInput({
                name: customRiskName.value,
                prefix: customRiskPrefix.value,
                minLength: Number(customRiskMinLength.value),
                action: customRiskAction.value,
                enabled: true,
            });
            if (!normalized || !normalized.ok) {
                flashCustomRiskHint(
                    `添加失败:${customRiskErrorMessage(normalized && normalized.error)}`,
                    "warn",
                );
                return;
            }
            const added = await sendRuntimeMessage({
                type: "vigil_add_custom_risk_rule",
                rule: normalized,
            });
            if (!added || !added.ok) {
                flashCustomRiskHint(`保存失败:${customRiskErrorMessage(added && added._error)}`, "warn");
                return;
            }
            customRiskName.value = "";
            customRiskPrefix.value = "";
            customRiskMinLength.value = "24";
            customRiskAction.value = "confirm_redact";
            flashCustomRiskHint(`已添加 ${normalized.name}`);
            await refreshCustomRiskRules();
        } finally {
            customRiskAddBtn.disabled = false;
        }
    });

    if (customRiskExampleFillBtn) {
        customRiskExampleFillBtn.addEventListener("click", () => {
            customRiskName.value = "公司内部 Token";
            customRiskPrefix.value = "corp_";
            customRiskMinLength.value = "12";
            customRiskAction.value = "confirm_redact";
            customRiskName.focus();
            flashCustomRiskHint("已填入案例,确认后点击添加类型");
        });
    }

    refreshMode();
    refreshCustomSites();
    refreshCustomRiskRules();
})();
