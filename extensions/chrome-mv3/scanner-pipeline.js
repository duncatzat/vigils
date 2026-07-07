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

/**
 * 姿态跟随(Phase 2「策略+观测」):把 enterprise provider(本机引擎)带回的系统姿态
 * 建议档应用到**合并后的最终决策**上。纯函数,只收紧:
 *
 *   - `postureTier === "strict"` 且最终 action 为 confirm_redact → 升级 block
 *     (系统姿态严格 = 命中即阻断,不走用户确认;posture.json medium/high 由 host 侧
 *     映射为 strict);
 *   - allow(无命中)与 block(已最严)在任何姿态下都**不动**——姿态绝不放宽;
 *   - `postureTier` 非闭集成员(null / 旧 host 缺省 / 漂移值)→ 原样返回 = 现状行为。
 *
 * 同时把 posture_tier / engine 附着到结果上(观测:popup 企业标注 / options 状态行),
 * 无论是否发生升级 —— 附着基于 provider 实际回报,不基于本函数是否收紧。
 */
export function applyPostureTier(result, postureTier, engine) {
    if (!result || typeof result !== "object") return result;
    const annotated = { ...result };
    if (postureTier === "balanced" || postureTier === "strict") {
        annotated.posture_tier = postureTier;
    }
    if (engine === "hardfp" || engine === "hardfp+ml") {
        annotated.engine = engine;
    }
    if (annotated.posture_tier === "strict" && annotated.action === "confirm_redact") {
        return { ...annotated, action: "block", posture_escalated: true };
    }
    return annotated;
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
        const merged = mergeScanResults(request && request.request_id ? request.request_id : "", [
            localResult,
            enterpriseResult,
        ]);
        // 姿态跟随:从 enterprise 结果**独立**取姿态档再应用到合并结果 —— 不依赖
        // enterprise 恰好是 merge 的最严者(本地更严时姿态升级依然要生效)。
        return applyPostureTier(
            merged,
            enterpriseResult && enterpriseResult.posture_tier,
            enterpriseResult && enterpriseResult.engine,
        );
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
