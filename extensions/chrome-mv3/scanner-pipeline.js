import { createConsumerJsProvider } from "./providers/consumer-js-provider.js";
import { createEnterpriseProvider } from "./providers/enterprise-provider.js";

const ACTION_RANK = Object.freeze({
    allow: 0,
    confirm_redact: 1,
    redact: 1,
    block: 2,
});

function actionRank(action) {
    return Object.hasOwn(ACTION_RANK, action) ? ACTION_RANK[action] : ACTION_RANK.block;
}

function normalizeAction(action) {
    return action === "redact" ? "confirm_redact" : action || "allow";
}

function emptyResult(requestId) {
    return {
        request_id: requestId,
        action: "allow",
        findings: [],
        source: "pipeline",
    };
}

export function mergeScanResults(requestId, results) {
    const mergedFindings = new Map();
    let strictest = emptyResult(requestId);

    for (const result of Array.isArray(results) ? results : []) {
        if (!result || typeof result !== "object") continue;

        for (const finding of Array.isArray(result.findings) ? result.findings : []) {
            if (finding && typeof finding.kind === "string" && !mergedFindings.has(finding.kind)) {
                mergedFindings.set(finding.kind, finding);
            }
        }

        const candidateAction = normalizeAction(result.action);
        if (actionRank(candidateAction) >= actionRank(strictest.action)) {
            strictest = {
                ...result,
                request_id: requestId,
                action: candidateAction,
                source: "pipeline",
            };
        }
    }

    return {
        ...strictest,
        request_id: requestId,
        findings: Array.from(mergedFindings.values()),
    };
}

function lengthBucket(text) {
    const length = typeof text === "string" ? text.length : 0;
    if (length <= 100) return "0-100";
    if (length <= 500) return "100-500";
    if (length <= 2000) return "500-2000";
    return "2000+";
}

function metadataOnlyRequest(request, localResult) {
    return {
        request_id: request && request.request_id ? request.request_id : "",
        origin: request && request.origin ? request.origin : "",
        event_kind: request && request.event_kind ? request.event_kind : "",
        length_bucket: lengthBucket(request && request.text),
        local_findings: Array.isArray(localResult && localResult.findings)
            ? localResult.findings.map((finding) => finding.kind).filter((kind) => typeof kind === "string")
            : [],
    };
}

export async function checkWithScannerPipeline(request, options = {}) {
    const consumerProvider = options.consumerProvider || createConsumerJsProvider(options.consumer || {});
    const localResult = await consumerProvider.check(request);

    if (options.mode !== "enterprise") {
        return localResult;
    }

    const enterpriseConfig = options.enterprise || {};
    const enterpriseProvider = enterpriseConfig.provider || createEnterpriseProvider(enterpriseConfig);
    const dataPolicy = enterpriseConfig.dataPolicy || "local_only";

    let enterpriseRequest = metadataOnlyRequest(request, localResult);
    if (dataPolicy === "local_only") {
        enterpriseRequest = {
            ...enterpriseRequest,
            local_only: true,
        };
    } else if (dataPolicy === "raw_allowed") {
        enterpriseRequest = request;
    }

    try {
        const enterpriseResult = await enterpriseProvider.check(enterpriseRequest, {
            dataPolicy,
            localResult,
        });
        return mergeScanResults(request && request.request_id ? request.request_id : "", [
            localResult,
            enterpriseResult,
        ]);
    } catch {
        return {
            request_id: request && request.request_id ? request.request_id : "",
            action: "block",
            findings: Array.isArray(localResult && localResult.findings) ? localResult.findings : [],
            source: "pipeline",
            error: "enterprise_provider_failed",
        };
    }
}
