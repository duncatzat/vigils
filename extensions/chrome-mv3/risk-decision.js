import { hasFindings, redactText } from "./redaction-rules.js";

export function decideRisk(request, findings, customRules = []) {
    const requestId =
        request && typeof request.request_id === "string" ? request.request_id : "";
    const text = request && typeof request.text === "string" ? request.text : "";
    const cleanFindings = Array.isArray(findings) ? findings : [];
    const hasHighRiskFinding = cleanFindings.some((finding) => finding && finding.severity === "high");

    if (cleanFindings.length === 0) {
        return {
            request_id: requestId,
            action: "allow",
            findings: [],
            source: "consumer_js",
        };
    }

    if (hasHighRiskFinding) {
        return {
            request_id: requestId,
            action: "block",
            findings: cleanFindings,
            source: "consumer_js",
            error: "high_risk",
        };
    }

    const redactedText = redactText(text, cleanFindings, customRules);
    if (!redactedText || redactedText === text || hasFindings(redactedText, customRules)) {
        return {
            request_id: requestId,
            action: "block",
            findings: cleanFindings,
            source: "consumer_js",
            error: "redaction_failed",
        };
    }

    return {
        request_id: requestId,
        action: "confirm_redact",
        findings: cleanFindings,
        redacted_text: redactedText,
        source: "consumer_js",
    };
}
