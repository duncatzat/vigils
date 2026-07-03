import test from "node:test";
import assert from "node:assert/strict";
import {
    scanText,
    redactText,
    hasFindings,
    normalizeCustomRiskRuleInput,
} from "../redaction-rules.js";
import { decideRisk } from "../risk-decision.js";

const REQUEST_ID = "11111111-1111-4111-8111-111111111111";

test("scanText detects and redacts common consumer secrets", () => {
    const text = [
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890",
        "DATABASE_URL=postgres://user:p%40ssword@example.com/db",
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ].join("\n");

    const findings = scanText(text);
    assert.deepEqual(
        findings.map((f) => f.kind).sort(),
        ["database_url", "env_assignment", "jwt", "openai_api_key"].sort(),
    );
    assert.equal(findings.every((f) => f.redactable), true);

    const redacted = redactText(text, findings);
    assert.match(redacted, /\[REDACTED openai_api_key\]/);
    assert.match(redacted, /\[REDACTED database_url\]/);
    assert.match(redacted, /\[REDACTED jwt\]/);
    assert.equal(redacted.includes("sk-proj-abcdefghijklmnopqrstuvwxyz"), false);
    assert.equal(redacted.includes("p%40ssword"), false);
    assert.equal(hasFindings(redacted), false);
});

test("redactText only redacts the selected finding kinds", () => {
    const text = [
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890",
        "token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD",
    ].join(" ");

    const redacted = redactText(text, [
        { kind: "github_token", severity: "medium", redactable: true },
    ]);

    assert.match(redacted, /\[REDACTED github_token\]/);
    assert.equal(redacted.includes("ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"), false);
    assert.equal(redacted.includes("sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890"), true);
});

test("redactText with an explicit empty findings array leaves text unchanged", () => {
    const text = "token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD";

    const redacted = redactText(text, []);

    assert.equal(redacted, text);
});

test("env_assignment-only findings redact as env_assignment", () => {
    const text = "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890";

    const redacted = redactText(text, [
        { kind: "env_assignment", severity: "medium", redactable: true },
    ]);

    assert.match(redacted, /\[REDACTED env_assignment\]/);
    assert.equal(redacted.includes("[REDACTED openai_api_key]"), false);
});

test("decideRisk returns confirm_redact for redactable findings", () => {
    const text = "token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD";
    const findings = scanText(text);

    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.equal(result.request_id, REQUEST_ID);
    assert.equal(result.action, "confirm_redact");
    assert.deepEqual(result.findings.map((f) => f.kind), ["github_token"]);
    assert.match(result.redacted_text, /\[REDACTED github_token\]/);
});

test("medium non-redactable findings block as redaction failures", () => {
    const text = "legacy token with no safe rewrite";
    const findings = [
        { kind: "legacy_secret", severity: "medium", redactable: false },
    ];

    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.equal(result.action, "block");
    assert.equal(result.error, "redaction_failed");
    assert.equal(result.redacted_text, undefined);
});

test("PEM private key is block-only", () => {
    const text = [
        "-----BEGIN PRIVATE KEY-----",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        "-----END PRIVATE KEY-----",
    ].join("\n");

    const findings = scanText(text);
    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.equal(findings[0].kind, "pem_private_key");
    assert.equal(findings[0].severity, "high");
    assert.equal(findings[0].redactable, false);
    assert.equal(result.action, "block");
    assert.equal(result.redacted_text, undefined);
    assert.equal(result.error, "high_risk");
});

test("mixed high-risk and redactable findings block without redacted text", () => {
    const text = [
        "-----BEGIN PRIVATE KEY-----",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        "-----END PRIVATE KEY-----",
        " token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD",
    ].join("\n");

    const findings = scanText(text);
    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.equal(findings.some((finding) => finding.kind === "pem_private_key"), true);
    assert.equal(findings.some((finding) => finding.kind === "github_token"), true);
    assert.equal(result.action, "block");
    assert.equal(result.redacted_text, undefined);
    assert.equal(result.error, "high_risk");
});

test("safe text is allowed", () => {
    const text = "Please summarize this public README section.";
    const findings = scanText(text);
    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.deepEqual(findings, []);
    assert.deepEqual(result, {
        request_id: REQUEST_ID,
        action: "allow",
        findings: [],
        source: "consumer_js",
    });
});

test("custom prefix rules detect and redact user-defined risk types", () => {
    const rules = [
        normalizeCustomRiskRuleInput({
            id: "corp-token",
            name: "公司内部 Token",
            prefix: "corp_",
            minLength: 12,
            action: "confirm_redact",
            enabled: true,
        }),
    ];
    const text = "token corp_abcdefghijklmnop";

    const findings = scanText(text, rules);
    const result = decideRisk({ request_id: REQUEST_ID, text }, findings, rules);

    assert.deepEqual(findings.map((f) => f.kind), ["custom:corp-token"]);
    assert.equal(findings[0].label, "公司内部 Token");
    assert.equal(result.action, "confirm_redact");
    assert.equal(result.redacted_text, "token [REDACTED 公司内部 Token]");
});

test("custom prefix rules can be configured as block-only", () => {
    const rules = [
        normalizeCustomRiskRuleInput({
            id: "internal-root",
            name: "内部 Root Key",
            prefix: "root_",
            minLength: 10,
            action: "block",
            enabled: true,
        }),
    ];

    const findings = scanText("root_abcdefghijkl", rules);
    const result = decideRisk(
        { request_id: REQUEST_ID, text: "root_abcdefghijkl" },
        findings,
        rules,
    );

    assert.equal(findings[0].kind, "custom:internal-root");
    assert.equal(findings[0].redactable, false);
    assert.equal(result.action, "block");
    assert.equal(result.error, "high_risk");
});

test("custom risk rule normalization rejects unsafe broad rules", () => {
    assert.deepEqual(
        normalizeCustomRiskRuleInput({ name: "bad", prefix: "", minLength: 12 }),
        { ok: false, error: "prefix_required" },
    );
    assert.deepEqual(
        normalizeCustomRiskRuleInput({ name: "bad", prefix: "x", minLength: 2 }),
        { ok: false, error: "min_length_range" },
    );
});
