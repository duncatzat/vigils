const RULES = Object.freeze([
    {
        kind: "pem_private_key",
        severity: "high",
        redactable: false,
        pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    },
    {
        kind: "openai_api_key",
        severity: "medium",
        redactable: true,
        pattern: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        kind: "anthropic_api_key",
        severity: "medium",
        redactable: true,
        pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        kind: "google_api_key",
        severity: "medium",
        redactable: true,
        pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    },
    {
        kind: "github_token",
        severity: "medium",
        redactable: true,
        pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g,
    },
    {
        kind: "gitlab_pat",
        severity: "medium",
        redactable: true,
        pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        kind: "slack_webhook",
        severity: "medium",
        redactable: true,
        pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/+_-]+\/[A-Za-z0-9/+_-]+\/[A-Za-z0-9/+_-]+/g,
    },
    {
        kind: "stripe_secret_key",
        severity: "medium",
        redactable: true,
        pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    },
    {
        kind: "aws_access_key_id",
        severity: "medium",
        redactable: true,
        pattern: /\bA[KS]IA[0-9A-Z]{16}\b/g,
    },
    {
        kind: "jwt",
        severity: "medium",
        redactable: true,
        pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    },
    {
        kind: "database_url",
        severity: "medium",
        redactable: true,
        pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^:\s/@]+:[^@\s]+@[^\s]+/gi,
    },
    {
        kind: "env_assignment",
        severity: "medium",
        redactable: true,
        pattern: /\b[A-Z][A-Z0-9_]{2,}=(?!(?:true|false|null)\b)[^\s"'`]{6,}/g,
    },
]);

const CUSTOM_RULE_LIMIT = 20;
const CUSTOM_MIN_LENGTH_MIN = 6;
const CUSTOM_MIN_LENGTH_MAX = 256;
const CUSTOM_PREFIX_MAX = 64;
const CUSTOM_NAME_MAX = 48;

function slugifyId(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 48);
}

function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function normalizeCustomRiskRuleInput(input) {
    const raw = input && typeof input === "object" ? input : {};
    const name = String(raw.name || "").trim().slice(0, CUSTOM_NAME_MAX);
    const prefix = String(raw.prefix || "").trim().slice(0, CUSTOM_PREFIX_MAX);
    const minLength = Number(raw.minLength);
    const action = raw.action === "block" ? "block" : "confirm_redact";
    const id = slugifyId(raw.id || name || prefix);

    if (!name) return { ok: false, error: "name_required" };
    if (!prefix) return { ok: false, error: "prefix_required" };
    if (!Number.isInteger(minLength) || minLength < CUSTOM_MIN_LENGTH_MIN || minLength > CUSTOM_MIN_LENGTH_MAX) {
        return { ok: false, error: "min_length_range" };
    }
    if (!id) return { ok: false, error: "id_required" };

    return {
        ok: true,
        id,
        name,
        prefix,
        minLength,
        action,
        enabled: raw.enabled !== false,
    };
}

export function normalizeCustomRiskRules(rules) {
    const clean = [];
    const seen = new Set();
    for (const rule of Array.isArray(rules) ? rules : []) {
        if (clean.length >= CUSTOM_RULE_LIMIT) break;
        const normalized = normalizeCustomRiskRuleInput(rule);
        if (!normalized.ok || seen.has(normalized.id)) continue;
        seen.add(normalized.id);
        clean.push(normalized);
    }
    return clean;
}

function customRuleToRuntimeRule(rule) {
    if (!rule || rule.enabled === false) return null;
    const normalized = normalizeCustomRiskRuleInput(rule);
    if (!normalized.ok) return null;
    return {
        kind: `custom:${normalized.id}`,
        label: normalized.name,
        severity: normalized.action === "block" ? "high" : "medium",
        redactable: normalized.action !== "block",
        pattern: new RegExp(
            `\\b${escapeRegExp(normalized.prefix)}[A-Za-z0-9_-]{${normalized.minLength},}\\b`,
            "g",
        ),
    };
}

function allRules(customRules) {
    return RULES.concat(
        normalizeCustomRiskRules(customRules)
            .map(customRuleToRuntimeRule)
            .filter(Boolean),
    );
}

function findRule(kind) {
    return RULES.find((rule) => rule.kind === kind) || null;
}

function replaceAll(text, pattern, replacer) {
    pattern.lastIndex = 0;
    return text.replace(pattern, replacer);
}

function selectedKindsFor(text, findings) {
    if (Array.isArray(findings)) {
        return new Set(
            findings
                .map((finding) => finding && finding.kind)
                .filter((kind) => typeof kind === "string" && kind.length > 0),
        );
    }

    return new Set(scanText(text).map((finding) => finding.kind));
}

function patternMatches(pattern, text) {
    pattern.lastIndex = 0;
    const matched = pattern.test(text);
    pattern.lastIndex = 0;
    return matched;
}

function redactAssignment(match, selectedKinds) {
    const equalIndex = match.indexOf("=");
    if (equalIndex < 0) return "[REDACTED env_assignment]";

    if (selectedKinds.size === 1 && selectedKinds.has("env_assignment")) {
        return "[REDACTED env_assignment]";
    }

    const key = match.slice(0, equalIndex);
    const value = match.slice(equalIndex + 1);
    const nestedRule = RULES.find(
        (rule) => rule.redactable && rule.kind !== "env_assignment" && patternMatches(rule.pattern, value),
    );
    if (nestedRule) {
        return `${key}=\n[REDACTED ${nestedRule.kind}]`;
    }

    return `${key}=\n[REDACTED env_assignment]`;
}

export function scanText(text, customRules = []) {
    if (typeof text !== "string" || text.length === 0) return [];

    const seen = new Set();
    const findings = [];

    for (const rule of allRules(customRules)) {
        if (!patternMatches(rule.pattern, text)) continue;
        if (seen.has(rule.kind)) continue;
        seen.add(rule.kind);
        findings.push({
            kind: rule.kind,
            label: rule.label,
            severity: rule.severity,
            redactable: rule.redactable,
        });
    }

    return findings;
}

export function redactText(text, findings, customRules = []) {
    if (typeof text !== "string" || text.length === 0) return "";

    let redacted = text;
    const kinds = selectedKindsFor(text, findings);

    const envRule = findRule("env_assignment");
    if (envRule && kinds.has(envRule.kind)) {
        redacted = replaceAll(redacted, envRule.pattern, (match) => redactAssignment(match, kinds));
    }

    for (const rule of allRules(customRules)) {
        if (!rule.redactable || rule.kind === "env_assignment" || !kinds.has(rule.kind)) continue;
        redacted = replaceAll(redacted, rule.pattern, `[REDACTED ${rule.label || rule.kind}]`);
    }

    return redacted;
}

export function hasFindings(text, customRules = []) {
    return scanText(text, customRules).length > 0;
}
