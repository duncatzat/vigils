// Native Host enterprise provider —— 把检查路由到本机 Vigils 引擎
// (`vigil-native-host`:硬指纹分类 + 可选 daemon ML 语义 PII 增强,见 ADR 0009/0024)。
//
// 数据边界:原文经 Chrome Native Messaging 送**本机进程**,仅在其内存停留(ADR 0009
// §I-9.1,分类完立即丢弃,绝不落盘)——不出设备。与远程企业端点不同,本 provider
// 需要全文才能分类;pipeline 的 dataPolicy 应配 "raw_allowed",UI 呈现为「本机引擎」。
//
// fail-closed:host 未注册 / 断连 / 超时 / 协议错 → check() reject,由
// scanner-pipeline 的 catch 收敛为 block(enterprise_provider_failed)。

export const NATIVE_HOST_NAME = "com.vigil.host";
const REQUEST_TTL_MS = 10_000;
const MAX_FINDING_KIND_CHARS = 64;

/**
 * 创建 Native Host provider。`options.chromeApi` 供 node 测试注入 mock;
 * `options.hostName` / `options.ttlMs` 同理。
 */
export function createNativeHostProvider(options = {}) {
    const hostName = typeof options.hostName === "string" ? options.hostName : NATIVE_HOST_NAME;
    const ttlMs = typeof options.ttlMs === "number" && options.ttlMs > 0 ? options.ttlMs : REQUEST_TTL_MS;
    const chromeApi = options.chromeApi || globalThis.chrome;

    /** 单例 port;断连置 null,下次 check 重连(host 崩溃后可自愈)。 */
    let port = null;
    /** pending 请求表:request_id → { deliver, fail }(均已含 TTL timer 清理)。 */
    const pending = new Map();

    function failAll(reason) {
        for (const [, slot] of pending) {
            slot.fail(new Error(reason));
        }
        pending.clear();
    }

    function onHostMessage(msg) {
        if (!msg || typeof msg !== "object") return;
        // ErrorFrame 优先分流(协议错误无论 request_id 是否存在都必须 fail-closed;
        // 语义对齐既有 host 协议:无 request_id 的流级错误 → 全 pending 连坐)。
        if (typeof msg.error === "string") {
            const reqId = typeof msg.request_id === "string" ? msg.request_id : null;
            if (reqId !== null) {
                const slot = pending.get(reqId);
                if (slot) {
                    pending.delete(reqId);
                    slot.fail(new Error(`host_error:${msg.error}`));
                }
                return;
            }
            failAll(`host_protocol_error:${msg.error}`);
            return;
        }
        const reqId = msg.request_id;
        if (typeof reqId !== "string") return;
        const slot = pending.get(reqId);
        if (!slot) return; // 孤儿响应(已超时清理)
        pending.delete(reqId);
        slot.deliver(msg);
    }

    function onHostDisconnect() {
        const reason =
            (chromeApi.runtime.lastError && chromeApi.runtime.lastError.message) ||
            "host_disconnected";
        failAll(reason);
        port = null;
    }

    function getPort() {
        if (port !== null) return port;
        port = chromeApi.runtime.connectNative(hostName);
        port.onMessage.addListener(onHostMessage);
        port.onDisconnect.addListener(onHostDisconnect);
        return port;
    }

    /** host BrowserCheckResponse → pipeline provider result(findings 统一 {kind} 形状)。 */
    function toProviderResult(requestId, resp) {
        const findings = [];
        const pushKind = (value, source) => {
            if (typeof value !== "string" || value.length === 0) return;
            findings.push({ kind: value.slice(0, MAX_FINDING_KIND_CHARS), source });
        };
        for (const kind of Array.isArray(resp.findings) ? resp.findings : []) {
            pushKind(kind, "native_host");
        }
        // daemon ML 语义 PII 标签(host 侧已 sanitize 闭集)并入 findings 供展示/审计。
        for (const label of Array.isArray(resp.ml_labels) ? resp.ml_labels : []) {
            pushKind(label, "native_host_ml");
        }
        // action 白名单;未知值 fail-closed 收敛 block。"redact" 由 pipeline
        // normalizeAction 归一为 confirm_redact(保留用户确认交互)。
        const action =
            resp.action === "allow" || resp.action === "redact" || resp.action === "block"
                ? resp.action
                : "block";
        const result = {
            request_id: requestId,
            action,
            findings,
            source: "native_host",
        };
        if (typeof resp.redacted_text === "string") {
            result.redacted_text = resp.redacted_text;
        }
        return result;
    }

    return {
        name: "native_host",
        async check(request) {
            const requestId =
                request && typeof request.request_id === "string" && request.request_id
                    ? request.request_id
                    : crypto.randomUUID();
            const text = request && typeof request.text === "string" ? request.text : "";
            if (
                !chromeApi ||
                !chromeApi.runtime ||
                typeof chromeApi.runtime.connectNative !== "function"
            ) {
                // nativeMessaging 权限缺失 / 非扩展环境 → reject(pipeline 收敛 block)。
                throw new Error("native_messaging_unavailable");
            }
            return new Promise((resolve, reject) => {
                let activePort;
                try {
                    activePort = getPort();
                } catch (err) {
                    reject(new Error(`connect_failed:${String(err && err.message ? err.message : err)}`));
                    return;
                }
                const timer = setTimeout(() => {
                    if (pending.has(requestId)) {
                        pending.delete(requestId);
                        reject(new Error("host_timeout"));
                    }
                }, ttlMs);
                pending.set(requestId, {
                    deliver: (resp) => {
                        clearTimeout(timer);
                        resolve(toProviderResult(requestId, resp));
                    },
                    fail: (err) => {
                        clearTimeout(timer);
                        reject(err);
                    },
                });
                try {
                    activePort.postMessage({
                        request_id: requestId,
                        origin: request && typeof request.origin === "string" ? request.origin : "",
                        event_kind:
                            request && typeof request.event_kind === "string"
                                ? request.event_kind
                                : "paste",
                        text,
                    });
                } catch (err) {
                    clearTimeout(timer);
                    pending.delete(requestId);
                    reject(new Error(`post_failed:${String(err && err.message ? err.message : err)}`));
                }
            });
        },
    };
}
