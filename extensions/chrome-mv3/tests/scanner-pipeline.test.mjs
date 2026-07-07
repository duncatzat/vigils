import test from "node:test";
import assert from "node:assert/strict";
import {
    checkWithScannerPipeline,
    mergeScanResults,
} from "../scanner-pipeline.js";

function request(text) {
    return {
        request_id: "22222222-2222-4222-8222-222222222222",
        origin: "https://chatgpt.com",
        event_kind: "paste",
        text,
    };
}

test("consumer mode uses local JS provider and returns confirm_redact", async () => {
    const result = await checkWithScannerPipeline(
        request("token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
        { mode: "consumer" },
    );

    assert.equal(result.action, "confirm_redact");
    assert.equal(result.source, "consumer_js");
    assert.deepEqual(result.findings.map((f) => f.kind), ["github_token"]);
});

test("consumer mode offers redaction confirmation for token assignments", async () => {
    const result = await checkWithScannerPipeline(
        request("token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"),
        { mode: "consumer" },
    );

    assert.equal(result.action, "confirm_redact");
    assert.equal(result.source, "consumer_js");
    assert.deepEqual(result.findings.map((f) => f.kind), ["github_token"]);
    assert.equal(result.redacted_text, "token=[REDACTED github_token]");
});

test("consumer mode applies custom risk rules", async () => {
    const result = await checkWithScannerPipeline(
        request("token corp_abcdefghijklmnop"),
        {
            mode: "consumer",
            consumer: {
                customRiskRules: [
                    {
                        id: "corp-token",
                        name: "公司内部 Token",
                        prefix: "corp_",
                        minLength: 12,
                        action: "confirm_redact",
                        enabled: true,
                    },
                ],
            },
        },
    );

    assert.equal(result.action, "confirm_redact");
    assert.deepEqual(result.findings.map((f) => f.kind), ["custom:corp-token"]);
    assert.equal(result.findings[0].label, "公司内部 Token");
    assert.equal(result.redacted_text, "token [REDACTED 公司内部 Token]");
});

test("consumer mode blocks custom rules marked as block", async () => {
    const result = await checkWithScannerPipeline(
        request("root_abcdefghijkl"),
        {
            mode: "consumer",
            consumer: {
                customRiskRules: [
                    {
                        id: "internal-root",
                        name: "内部 Root Key",
                        prefix: "root_",
                        minLength: 10,
                        action: "block",
                        enabled: true,
                    },
                ],
            },
        },
    );

    assert.equal(result.action, "block");
    assert.deepEqual(result.findings.map((f) => f.kind), ["custom:internal-root"]);
});

test("mergeScanResults keeps the strictest action", () => {
    const merged = mergeScanResults("rid", [
        { request_id: "rid", action: "allow", findings: [], source: "consumer_js" },
        {
            request_id: "rid",
            action: "block",
            findings: [{ kind: "policy_block", severity: "high", redactable: false }],
            source: "enterprise",
        },
    ]);

    assert.equal(merged.action, "block");
    assert.equal(merged.source, "pipeline");
    assert.deepEqual(merged.findings.map((f) => f.kind), ["policy_block"]);
});

test("enterprise metadata_only policy does not pass raw text", async () => {
    let observedRequest;
    const provider = {
        name: "enterprise_test",
        async check(req) {
            observedRequest = req;
            return {
                request_id: req.request_id,
                action: "allow",
                findings: [],
                source: "enterprise",
            };
        },
    };

    const result = await checkWithScannerPipeline(
        request("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890"),
        {
            mode: "enterprise",
            enterprise: { provider, dataPolicy: "metadata_only" },
        },
    );

    assert.equal(result.action, "confirm_redact");
    assert.equal(Object.hasOwn(observedRequest, "text"), false);
    assert.equal(observedRequest.origin, "https://chatgpt.com");
    assert.deepEqual(observedRequest.local_findings, ["openai_api_key", "env_assignment"]);
});

test("enterprise local_only policy does not pass raw text and is flagged", async () => {
    let observedRequest;
    const provider = {
        name: "enterprise_test",
        async check(req) {
            observedRequest = req;
            return {
                request_id: req.request_id,
                action: "allow",
                findings: [],
                source: "enterprise",
            };
        },
    };

    const result = await checkWithScannerPipeline(
        request("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890"),
        {
            mode: "enterprise",
            enterprise: { provider, dataPolicy: "local_only" },
        },
    );

    assert.equal(result.action, "confirm_redact");
    assert.equal(Object.hasOwn(observedRequest, "text"), false);
    assert.equal(observedRequest.local_only, true);
    assert.equal(observedRequest.origin, "https://chatgpt.com");
    assert.deepEqual(observedRequest.local_findings, ["openai_api_key", "env_assignment"]);
});

test("configured but unavailable enterprise provider fails closed", async () => {
    const provider = {
        name: "enterprise_down",
        async check() {
            throw new Error("connection refused");
        },
    };

    const result = await checkWithScannerPipeline(
        request("plain text"),
        {
            mode: "enterprise",
            enterprise: { provider, dataPolicy: "raw_allowed" },
        },
    );

    assert.equal(result.action, "block");
    assert.equal(result.error, "enterprise_provider_failed");
});

// ── native host 后端(raw_allowed = 本机进程,原文不出设备)集成 ──

function nativeHostLikeProvider(overrides = {}) {
    return {
        name: "native_host",
        seen: [],
        async check(request) {
            this.seen.push(request);
            if (overrides.throwError) throw new Error("host_disconnected");
            return {
                request_id: request.request_id,
                action: overrides.action || "redact",
                findings: overrides.findings || [
                    { kind: "github_token", source: "native_host" },
                    { kind: "private_email", source: "native_host_ml" },
                ],
                redacted_text: overrides.redacted_text,
                source: "native_host",
            };
        },
    };
}

test("enterprise raw_allowed passes full text to the local native host backend", async () => {
    const provider = nativeHostLikeProvider({ action: "allow", findings: [] });
    await checkWithScannerPipeline(request("plain text with alice@example.com"), {
        mode: "enterprise",
        enterprise: { provider, dataPolicy: "raw_allowed" },
    });
    assert.equal(provider.seen.length, 1);
    assert.equal(
        provider.seen[0].text,
        "plain text with alice@example.com",
        "raw_allowed(本机 native host)必须收到全文才能分类",
    );
});

test("enterprise native host block wins over consumer confirm_redact", async () => {
    const provider = nativeHostLikeProvider({
        action: "block",
        findings: [{ kind: "pem_private_key", source: "native_host" }],
    });
    const result = await checkWithScannerPipeline(
        request("token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
        { mode: "enterprise", enterprise: { provider, dataPolicy: "raw_allowed" } },
    );
    assert.equal(result.action, "block", "后端 block 必须胜过本地 confirm_redact(取最严)");
    const kinds = result.findings.map((f) => f.kind);
    assert.ok(kinds.includes("github_token"), "本地 findings 保留");
    assert.ok(kinds.includes("pem_private_key"), "后端 findings 并入");
});

test("enterprise native host redaction (hardfp+ML) overrides consumer redaction on tie", async () => {
    const provider = nativeHostLikeProvider({
        action: "redact",
        redacted_text: "token [REDACTED github_token] mail [REDACTED private_email]",
    });
    const result = await checkWithScannerPipeline(
        request("token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD mail alice@example.com"),
        { mode: "enterprise", enterprise: { provider, dataPolicy: "raw_allowed" } },
    );
    assert.equal(result.action, "confirm_redact", "host 的 redact 归一为 confirm_redact");
    assert.match(
        result.redacted_text,
        /\[REDACTED private_email\]/,
        "同级最严时后端(hardfp+ML 更全)的 redacted_text 胜出",
    );
    assert.ok(
        result.findings.some((f) => f.kind === "private_email"),
        "ML 语义标签并入 findings",
    );
});

test("enterprise native host failure fails closed to block with local findings kept", async () => {
    const provider = nativeHostLikeProvider({ throwError: true });
    const result = await checkWithScannerPipeline(
        request("token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
        { mode: "enterprise", enterprise: { provider, dataPolicy: "raw_allowed" } },
    );
    assert.equal(result.action, "block", "已启用的后端不可达必须 fail-closed(不静默降级)");
    assert.equal(result.error, "enterprise_provider_failed");
    assert.ok(result.findings.some((f) => f.kind === "github_token"), "本地 findings 保留");
});

// ───────────── Phase 2「策略+观测」:applyPostureTier 姿态跟随(只收紧) ─────────────

import { applyPostureTier } from "../scanner-pipeline.js";

function resultOf(action, extra = {}) {
    return { request_id: "r", action, findings: [], source: "pipeline", ...extra };
}

test("applyPostureTier: strict escalates confirm_redact to block and marks it", () => {
    const out = applyPostureTier(resultOf("confirm_redact"), "strict", "hardfp+ml");
    assert.equal(out.action, "block");
    assert.equal(out.posture_escalated, true);
    assert.equal(out.posture_tier, "strict");
    assert.equal(out.engine, "hardfp+ml");
});

test("applyPostureTier: never loosens — allow and block untouched under any tier", () => {
    for (const tier of ["strict", "balanced", "paranoid", null, undefined]) {
        assert.equal(applyPostureTier(resultOf("allow"), tier).action, "allow");
        assert.equal(applyPostureTier(resultOf("block"), tier).action, "block");
    }
});

test("applyPostureTier: balanced / invalid / missing tier keep confirm_redact as-is", () => {
    assert.equal(applyPostureTier(resultOf("confirm_redact"), "balanced").action, "confirm_redact");
    assert.equal(applyPostureTier(resultOf("confirm_redact"), "paranoid").action, "confirm_redact");
    assert.equal(applyPostureTier(resultOf("confirm_redact"), null).action, "confirm_redact");
    // 非闭集值不得附着
    assert.equal(
        Object.hasOwn(applyPostureTier(resultOf("confirm_redact"), "paranoid"), "posture_tier"),
        false,
    );
});

test("enterprise pipeline: host posture strict escalates merged confirm_redact to block", async () => {
    // 本地 consumer 命中 github_token → confirm_redact;enterprise(本机引擎)allow 但携
    // posture_tier=strict → 姿态独立于「谁更严」生效,最终 block。
    const enterpriseProvider = {
        name: "native_host",
        async check() {
            return {
                request_id: "22222222-2222-4222-8222-222222222222",
                action: "allow",
                findings: [],
                source: "native_host",
                posture_tier: "strict",
                engine: "hardfp",
            };
        },
    };
    const result = await checkWithScannerPipeline(
        request("token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
        {
            mode: "enterprise",
            enterprise: { provider: enterpriseProvider, dataPolicy: "raw_allowed" },
        },
    );
    assert.equal(result.action, "block");
    assert.equal(result.posture_escalated, true);
    assert.equal(result.posture_tier, "strict");
    assert.deepEqual(result.findings.map((f) => f.kind), ["github_token"]);
});

test("enterprise pipeline: balanced posture keeps confirm_redact flow", async () => {
    const enterpriseProvider = {
        name: "native_host",
        async check() {
            return {
                request_id: "22222222-2222-4222-8222-222222222222",
                action: "allow",
                findings: [],
                source: "native_host",
                posture_tier: "balanced",
                engine: "hardfp+ml",
            };
        },
    };
    const result = await checkWithScannerPipeline(
        request("token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
        {
            mode: "enterprise",
            enterprise: { provider: enterpriseProvider, dataPolicy: "raw_allowed" },
        },
    );
    assert.equal(result.action, "confirm_redact");
    assert.equal(Object.hasOwn(result, "posture_escalated"), false);
    assert.equal(result.posture_tier, "balanced");
    assert.equal(result.engine, "hardfp+ml");
});

test("enterprise pipeline: legacy host without posture_tier behaves exactly as before", async () => {
    const enterpriseProvider = {
        name: "native_host",
        async check() {
            return {
                request_id: "22222222-2222-4222-8222-222222222222",
                action: "allow",
                findings: [],
                source: "native_host",
            };
        },
    };
    const result = await checkWithScannerPipeline(
        request("token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
        {
            mode: "enterprise",
            enterprise: { provider: enterpriseProvider, dataPolicy: "raw_allowed" },
        },
    );
    assert.equal(result.action, "confirm_redact");
    assert.equal(Object.hasOwn(result, "posture_tier"), false);
    assert.equal(Object.hasOwn(result, "posture_escalated"), false);
});
