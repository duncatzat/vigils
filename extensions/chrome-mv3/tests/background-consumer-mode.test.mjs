import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const backgroundSource = readFileSync(
    resolve(repoRoot, "extensions/chrome-mv3/background.js"),
    "utf8",
);
const manifestSource = readFileSync(
    resolve(repoRoot, "extensions/chrome-mv3/manifest.json"),
    "utf8",
);

test("background imports scanner pipeline", () => {
    assert.match(
        backgroundSource,
        /import\s+\{\s*checkWithScannerPipeline\s*\}\s+from\s+"\.\/scanner-pipeline\.js"/,
    );
});

test("vigil_check no longer calls checkWithHost directly", () => {
    assert.doesNotMatch(
        backgroundSource,
        /return\s+checkWithHost\(\{\s*origin:\s*msg\.origin/s,
    );
    assert.match(backgroundSource, /checkWithScannerPipeline\(\s*\{/);
});

test("nativeMessaging permission is not required for consumer default", () => {
    const manifest = JSON.parse(manifestSource);
    assert.equal(
        manifest.permissions.includes("nativeMessaging"),
        false,
        "consumer default extension must not require nativeMessaging permission",
    );
});

test("mode runtime messages exist", () => {
    assert.match(backgroundSource, /msg\.type\s*===\s*"vigil_get_mode"/);
    assert.match(backgroundSource, /msg\.type\s*===\s*"vigil_set_mode"/);
});

test("consumer checks no longer apply user-selectable tier overrides", () => {
    assert.doesNotMatch(
        backgroundSource,
        /applyTierDecision/,
        "ordinary consumer checks must use the scanner result directly",
    );
    assert.doesNotMatch(
        backgroundSource,
        /vigilTier/,
        "ordinary consumer mode must not read a user-selectable tier from storage",
    );
});

test("background no longer exposes tier runtime messages", () => {
    assert.doesNotMatch(backgroundSource, /vigil_get_tier/);
    assert.doesNotMatch(backgroundSource, /vigil_set_tier/);
});
