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
    assert.doesNotMatch(html, /注册 Native Host/);
    assert.doesNotMatch(html, /nativeMessaging<\/code>.*本机 Host/);
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

test("consumer UI does not expose native host install copy as the default path", () => {
    const manifest = read("extensions/chrome-mv3/manifest.json");
    const popup = read("extensions/chrome-mv3/popup.html");
    const options = read("extensions/chrome-mv3/options.html");
    const consumerCopy = [manifest, popup, options].join("\n");
    assert.match(manifest, /浏览器内检测/);
    assert.doesNotMatch(consumerCopy, /注册 Native Host/);
    assert.doesNotMatch(consumerCopy, /com\.vigil\.host/);
    assert.doesNotMatch(consumerCopy, /原文仅在本机 Native Host/);
    assert.doesNotMatch(consumerCopy, /nativeMessaging<\/code>.*运行期敏感权限/);
});

test("consumer UI and background do not expose page exemption bypass", () => {
    const popupHtml = read("extensions/chrome-mv3/popup.html");
    const popupJs = read("extensions/chrome-mv3/popup.js");
    const background = read("extensions/chrome-mv3/background.js");
    const source = [popupHtml, popupJs, background].join("\n");
    assert.doesNotMatch(source, /vigil_get_exempt/);
    assert.doesNotMatch(source, /vigil_set_exempt/);
    assert.doesNotMatch(source, /vigil_clear_exempt/);
    assert.doesNotMatch(source, /allow_exempt/);
    assert.doesNotMatch(source, /豁免/);
});

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

test("popup is centered on ordinary user page protection status", () => {
    const html = read("extensions/chrome-mv3/popup.html");
    const js = read("extensions/chrome-mv3/popup.js");
    const source = [html, js].join("\n");
    assert.match(html, /当前页面/);
    assert.match(html, /保护当前网站/);
    assert.match(html, /开始使用/);
    assert.match(js, /chrome\.tabs\.query/);
    assert.match(js, /normalizeCustomSiteInput/);
    assert.match(js, /vigil_add_custom_site/);
    assert.doesNotMatch(html, /刷新/);
});

test("popup renders safety events in plain language", () => {
    const js = read("extensions/chrome-mv3/popup.js");
    assert.match(js, /eventKindLabel/);
    assert.match(js, /actionLabel/);
    assert.match(js, /findingLabel/);
    assert.match(js, /已建议脱敏/);
    assert.doesNotMatch(js, /toUpperCase\(\)/);
});

test("options defaults to consumer settings and hides enterprise diagnostics as advanced", () => {
    const html = read("extensions/chrome-mv3/options.html");
    assert.match(html, /推荐保护/);
    assert.match(html, /已保护网站/);
    assert.match(html, /隐私说明/);
    assert.match(html, /高级设置/);
    assert.match(html, /<details[^>]*id="advanced-settings"/);
    assert.doesNotMatch(html, /<section[^>]*>\s*<h2>企业连接<\/h2>/);
    assert.doesNotMatch(html, /<section[^>]*>\s*<h2>扩展 ID<\/h2>/);
});

test("options exposes custom risk types only inside advanced settings", () => {
    const html = read("extensions/chrome-mv3/options.html");
    const js = read("extensions/chrome-mv3/options.js");
    const source = [html, js].join("\n");
    assert.match(html, /自定义风险类型/);
    assert.match(html, /custom-risk-form/);
    assert.match(html, /前缀/);
    assert.match(html, /最小长度/);
    assert.match(html, /建议脱敏/);
    assert.match(html, /直接阻断/);
    assert.match(source, /vigil_list_custom_risk_rules/);
    assert.match(source, /vigil_add_custom_risk_rule/);
    assert.match(source, /vigil_remove_custom_risk_rule/);
    assert.doesNotMatch(html, /正则表达式/);
});
