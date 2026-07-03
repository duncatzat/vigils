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
