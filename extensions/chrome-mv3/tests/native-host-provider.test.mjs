import test from "node:test";
import assert from "node:assert/strict";
import { createNativeHostProvider, NATIVE_HOST_NAME } from "../providers/native-host-provider.js";

function fakeChrome() {
    const state = {
        posted: [],
        connectCalls: 0,
        messageListeners: [],
        disconnectListeners: [],
        lastError: null,
    };
    const port = {
        onMessage: { addListener: (fn) => state.messageListeners.push(fn) },
        onDisconnect: { addListener: (fn) => state.disconnectListeners.push(fn) },
        postMessage: (msg) => state.posted.push(msg),
    };
    const chromeApi = {
        runtime: {
            get lastError() {
                return state.lastError;
            },
            connectNative: (name) => {
                state.connectCalls += 1;
                state.connectedName = name;
                return port;
            },
        },
    };
    return {
        chromeApi,
        state,
        emit: (msg) => state.messageListeners.forEach((fn) => fn(msg)),
        disconnect: () => state.disconnectListeners.forEach((fn) => fn()),
    };
}

function request(text) {
    return {
        request_id: "33333333-3333-4333-8333-333333333333",
        origin: "https://chatgpt.com",
        event_kind: "paste",
        text,
    };
}

test("round trip maps host response into pipeline provider shape", async () => {
    const fake = fakeChrome();
    const provider = createNativeHostProvider({ chromeApi: fake.chromeApi });
    const checking = provider.check(request("token ghp_x alice@example.com"));

    assert.equal(fake.state.connectedName, NATIVE_HOST_NAME);
    assert.equal(fake.state.posted.length, 1);
    assert.equal(fake.state.posted[0].request_id, "33333333-3333-4333-8333-333333333333");
    assert.equal(fake.state.posted[0].event_kind, "paste");

    fake.emit({
        request_id: "33333333-3333-4333-8333-333333333333",
        action: "redact",
        findings: ["github_token"],
        ml_labels: ["private_email"],
        redacted_text: "token [REDACTED github_token] [REDACTED private_email]",
    });
    const result = await checking;
    assert.equal(result.action, "redact");
    assert.equal(result.source, "native_host");
    assert.deepEqual(result.findings, [
        { kind: "github_token", source: "native_host" },
        { kind: "private_email", source: "native_host_ml" },
    ]);
    assert.match(result.redacted_text, /\[REDACTED github_token\]/);
});

test("unknown host action fails closed to block", async () => {
    const fake = fakeChrome();
    const provider = createNativeHostProvider({ chromeApi: fake.chromeApi });
    const checking = provider.check(request("hello"));
    fake.emit({
        request_id: "33333333-3333-4333-8333-333333333333",
        action: "totally_new_action",
        findings: [],
    });
    const result = await checking;
    assert.equal(result.action, "block");
});

test("host error frame with request_id rejects that request", async () => {
    const fake = fakeChrome();
    const provider = createNativeHostProvider({ chromeApi: fake.chromeApi });
    const checking = provider.check(request("hello"));
    fake.emit({ error: "too_large", request_id: "33333333-3333-4333-8333-333333333333" });
    await assert.rejects(checking, /host_error:too_large/);
});

test("host error frame without request_id fails all pending", async () => {
    const fake = fakeChrome();
    const provider = createNativeHostProvider({ chromeApi: fake.chromeApi });
    const checking = provider.check(request("hello"));
    fake.emit({ error: "bad_json" });
    await assert.rejects(checking, /host_protocol_error:bad_json/);
});

test("disconnect rejects pending and next check reconnects", async () => {
    const fake = fakeChrome();
    const provider = createNativeHostProvider({ chromeApi: fake.chromeApi });
    const checking = provider.check(request("hello"));
    fake.disconnect();
    await assert.rejects(checking, /host_disconnected/);

    const again = provider.check(request("hello again"));
    assert.equal(fake.state.connectCalls, 2, "断连后下次 check 应重连(自愈)");
    fake.emit({
        request_id: "33333333-3333-4333-8333-333333333333",
        action: "allow",
        findings: [],
    });
    const result = await again;
    assert.equal(result.action, "allow");
});

test("timeout rejects when host never answers", async () => {
    const fake = fakeChrome();
    const provider = createNativeHostProvider({ chromeApi: fake.chromeApi, ttlMs: 20 });
    await assert.rejects(provider.check(request("hello")), /host_timeout/);
});

test("missing nativeMessaging capability rejects unavailable", async () => {
    const provider = createNativeHostProvider({ chromeApi: { runtime: {} } });
    await assert.rejects(provider.check(request("hello")), /native_messaging_unavailable/);
});

test("malformed finding entries are dropped and kinds are length-capped", async () => {
    const fake = fakeChrome();
    const provider = createNativeHostProvider({ chromeApi: fake.chromeApi });
    const checking = provider.check(request("hello"));
    fake.emit({
        request_id: "33333333-3333-4333-8333-333333333333",
        action: "redact",
        findings: ["github_token", 42, null, ""],
        ml_labels: ["x".repeat(200)],
        redacted_text: "[REDACTED github_token]",
    });
    const result = await checking;
    assert.deepEqual(
        result.findings.map((f) => f.kind),
        ["github_token", "x".repeat(64)],
        "非字符串/空条目丢弃;超长 kind 截断",
    );
});
