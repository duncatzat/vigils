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

test("content script rejects legacy redact action aliases", () => {
    assert.doesNotMatch(source, /resp\.action === "redact"/);
});

test("contenteditable confirm-redact continuation does not insert a line break", () => {
    assert.doesNotMatch(
        source,
        /showRiskPrompt\(resp,\s*\(redactedText\)\s*=>\s*\{[\s\S]{0,1200}?insertLineBreak/,
    );
});

test("risk prompt anchors to the active input when available", () => {
    assert.match(source, /function positionRiskPrompt\(\)/);
    assert.match(source, /riskPromptTarget\s*=\s*getInputFrameTarget\(anchor\)\s*\|\|\s*anchor/);
    assert.match(source, /data-vigil-risk-arrow/);
    assert.match(source, /showRiskPrompt\(resp,\s*target,\s*(?:async\s*)?\(/);
    assert.match(source, /showBlockPrompt\(resp,\s*target\)/);
    assert.match(source, /showRiskPrompt\(resp,\s*primaryInput,\s*(?:async\s*)?\(/);
});

// 防回归:弹卡回调的写回**不得**再用「当前文本 === 检查/提交时刻文本」严格相等守门
// (富文本框架异步 normalize 会让相等恒失败 → 写回被拒/检查被弃)。TOCTOU 改为
// 以「写回前对当前文本重新送检(recheck)」收口:写回的永远是当前内容的最新裁决。
test("write-back guards recheck current text instead of strict equality", () => {
    assert.doesNotMatch(source, /getText\(\)\s*!==\s*originalText/);
    assert.doesNotMatch(source, /getText\(\)\s*!==\s*latestAgain/);
    assert.doesNotMatch(source, /getText\(\)\s*!==\s*pasteSnapshot\.text/);
    const rechecks = source.match(/const recheck = await callBackground\(/g) || [];
    assert.ok(rechecks.length >= 3, `expect >=3 recheck sites, got ${rechecks.length}`);
});

// 防回归:input 检查往返**后**不得再用 `after.seq !== next.seq` 放弃弹卡 —— 真实站点
// (ChatGPT ProseMirror)在往返期间 re-render 会派发额外 input 使 seq 递增,该守卫会把弹卡
// 静默杀掉。弹卡须无条件基于 SW 判定(与移除 latestAgain 同类)。
test("prompt is unconditional after check roundtrip (no after.seq gate)", () => {
    assert.doesNotMatch(source, /after\.seq\s*!==\s*next\.seq/);
});

// 构建标记必须存在,供排查时确认用户装的是最新版(区分「代码 bug」vs「装的是旧版」)。
test("content script writes a build marker for version confirmation", () => {
    assert.match(source, /data-vigil-build/);
    assert.match(source, /VIGIL_BUILD\s*=\s*"20\d\d-\d\d-\d\d/);
});

// 防回归:手动输入的防抖检查**不得**再用「fire 时刻文本 === 排程时刻文本」的严格比较
// 来跳过 —— 真实富文本框架(ProseMirror 类)在防抖窗口内异步 normalize 文本会让二者不等,
// 导致手动输入永不弹卡(用户报告的「粘贴弹卡、手动输入不提醒」根因,已 Edge 真机正反对照
// 坐实)。自写循环防护仍用 `lastWritten` 精确匹配守住。
test("manual-input debounce does not skip on framework text mutation", () => {
    // 旧 bug 形态:`latest !== next.lastText` 直接 return。这行不得复现。
    assert.doesNotMatch(source, /latest\s*!==\s*next\.lastText/);
    // 修复形态:以 fire 时刻当前文本为准检查;仅对「扩展自写值」精确匹配跳过防循环。
    assert.match(source, /if\s*\(latest\s*===\s*current\.lastWritten\)\s*return;/);
});
