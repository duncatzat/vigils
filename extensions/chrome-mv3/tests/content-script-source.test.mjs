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
    assert.match(source, /showRiskPrompt\(resp,\s*target,\s*\(/);
    assert.match(source, /showBlockPrompt\(resp,\s*target\)/);
    assert.match(source, /showRiskPrompt\(resp,\s*primaryInput,\s*\(/);
});
