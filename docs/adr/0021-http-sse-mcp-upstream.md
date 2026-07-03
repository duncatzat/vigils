# ADR 0021 — HTTP/SSE MCP Upstream Transport Coverage(把远端 MCP server 放进 Vigil 网关）

**Status**: Accepted-design(2026-06-08，research + design only，**未实施**；对抗安全审查 ACCEPT-with-changes → 5 MUST-FIX 已并入,见 §9）
**Iteration**: M2 多切片特性（非 one-shot；本 ADR 拆 5 个可发货切片，Slice 1 即可独立交付价值）
**Supersedes/Extends**: ADR 0004（Hub + namespacing + stdio upstream）、ADR 0011（HTTP Auth / `add-remote-mcp` OAuth），复用其 `HttpUpstream` / `TokenStore` / `AuthorizedSender` 资产。

## 1. Problem & Scope（问题与范围）

### 1.1 现状缺口

今天 Vigil 网关（`vigil-hub serve` / `vigil-hub wrap`）**只能挂 stdio 上游**。证据链：

- `attach_stdio_upstream`（`apps/vigil-hub-cli/src/serve.rs:453`）**硬编码** `transport: TransportKind::Stdio`（`serve.rs:484`），`UpstreamEntry` 结构只有 `name` + `argv` 两字段（`serve.rs:140-145`），无 URL 形态。
- `build_hub_with_config` 的 upstream 装配循环（`serve.rs:360-364`）对每个 entry **只调** `attach_stdio_upstream`，没有 HTTP 分支。
- `serve.rs` 模块 doc（`serve.rs:27-29`）明确写："本模块**不**做 HTTP transport（MCP 规范 2025-03 SSE / HTTP stream 留后续）"，HTTP 用户被引导去走 `add-remote-mcp` 完成 OAuth —— 但**那条路只持久化 token，从不把该 server attach 进 Hub**（见 `add_remote.rs` 全程无 `attach_*` 调用，只 `ts.put_access_token`）。

**后果**：任何只说 MCP HTTP 传输的远端 server（GitHub remote MCP、Linear、Sentry、Cloudflare 的托管 MCP、企业内网 HTTP MCP……）**无法被 Vigil 的 firewall（default-deny）/ redaction（secret/PII）/ audit（防篡改链）/ approval 保护**。这是网关覆盖面的硬空白：Vigil 的核心承诺是"**每一次** tool call 都被守护"，但该承诺当前只对 stdio 传输成立。

### 1.2 范围定义

"HTTP/SSE upstream coverage" = 让一个**说 MCP HTTP 传输的远端 server** 能作为 `Arc<dyn McpUpstream>` 挂进 `Hub.upstreams`，从而 **与 stdio 上游走完全相同的安全决策路径**。需覆盖两种 MCP 传输修订：

- **Streamable HTTP**（2025-03-26，现行）：单一 MCP endpoint。客户端 `POST` 一条 JSON-RPC，server **要么**返 `Content-Type: application/json`（单条响应），**要么**返 `Content-Type: text/event-stream`（一个 SSE 流，可含 0..N 条 server→client message + 最终响应）。可选 `Mcp-Session-Id` 响应头（server 分配会话 id，客户端后续请求回带）。可选 `GET` 打开一条独立 SSE 流收 server-initiated 消息。
- **Legacy HTTP+SSE**（2024-11-05）：双 endpoint。client→server 走 `POST /message`，server→client 走一条长连 `GET /sse`（SSE）。握手时 server 经一个 `endpoint` SSE event 告知 POST URL。

### 1.3 安全不变量（本 ADR 的验收底线）

不论传输是 stdio 还是 HTTP/SSE，下列必须**逐字成立**（均已在 Hub 的传输无关层实现，HTTP 上游"免费"继承——见 §2.3）：

1. **Firewall default-deny**：每次 `tools/call` 先过 `Firewall` 决策；无匹配 Allow 规则 → deny（`JsonRpcError::VIGIL_DENIED = 32001`）。
2. **Redaction 双向**：入站 args 的 `secret://<alias>` 仅在工具边界 detokenize（`hub.rs:1225`）；出站 result 命中硬指纹 → 审计 +（`redact_tool_results` 开）in-band 脱敏（`hub.rs:1259-1295`）。
3. **Audit 每调用**：`ToolCallSpan` 三段式（opened→decided→executed）写防篡改链（`hub.rs:1242-1245`）。
4. **Approval 风险路径**：风险调用走 ApprovalBroker / monitor 放行 + 审计。
5. **No token passthrough to model**：上游鉴权 token（Bearer）**绝不**出现在返给 agent/LLM 的任何字段或错误里。

## 2. Where it plugs in（插入点：增量、不扰 stdio）

### 2.1 关键洞察——chokepoint 已是传输无关的

Hub 与上游之间**唯一**的调用面是 `McpUpstream` trait（`crates/vigil-mcp/src/upstream.rs:72`）：

```rust
pub trait McpUpstream: Send + Sync + std::fmt::Debug {
    fn server_id(&self) -> &str;
    fn transport(&self) -> TransportKind;
    fn call(&self, method: &str, params: Option<Value>, timeout: Duration) -> Result<Value, UpstreamError>;
    fn shutdown(&self);
}
```

`Hub.upstreams: Mutex<HashMap<String, Arc<dyn McpUpstream>>>`（`hub.rs:323`）。在 `invoke_upstream` 里，**所有安全逻辑（firewall 决策、detokenize、leak scan、redaction、audit span）都发生在 `up.call("tools/call", …)`（`hub.rs:1251`）这一行的*周围***，与 `up` 的具体实现无关。`tools/list` 聚合同理走 `up.call("tools/list", …)`（`hub.rs:736`）。

> 这意味着：**只要一个 HTTP/SSE 上游实现了 `McpUpstream` 并被 attach 进 `Hub.upstreams`，它自动获得全部安全不变量**——无需改 Hub 决策代码。这是本特性低风险的根因。

### 2.2 已有资产——`HttpUpstream`（α2 遗产，OAuth-unary）

`crates/vigil-http-transport/src/upstream.rs` 已有一个 `HttpUpstream`，**已 impl `McpUpstream`**（`upstream.rs:182`），`transport()` 返 `TransportKind::Http`（`upstream.rs:188`）。它的 `call_once`（`upstream.rs:236`）：

1. `TokenStore::resolve_access_token`（sealed，issuer/audience/scope 校验在内）。
2. `plan_authorized_request(incoming_headers=&[], …)` —— planner 类型上保证 **无 header passthrough**（`upstream.rs:259`）。
3. `AuthorizedSender::send_authorized_with_timeout`（per-call timeout 生效，`upstream.rs:271`）。
4. 200 → 解析 JSON-RPC result；401→`Unauthorized`，403→`Forbidden`；上游 `error` message 折叠为 `message_sha256`（`upstream.rs:281-289`，不泄漏明文）。

**它已做对的（直接复用）**：

- 单条 `POST` JSON-RPC + per-call timeout（`McpUpstream::call` 契约）。
- 鉴权 token 走 sealed `TokenStore` + planner，**类型上不可能透传 Bearer**（§1.3 不变量 5 被类型系统保证）。
- 上游错误 message sha256 化（不泄漏）。

**它缺的（本 ADR 要补的）**：

| 缺口 | 说明 |
|---|---|
| **未 wired** | `serve.rs` 从不构造/attach `HttpUpstream`。这是最大的"最后一公里"——已有引擎没接油路。 |
| **仅 OAuth** | 强绑 `TokenStore`（OAuth access token）。很多托管 MCP 用**静态 Bearer / PAT**（如 `GITHUB_TOKEN`）；当前无路径喂一个 plain Bearer。 |
| **无 Streamable-HTTP 语义** | `POST` 只接受 `application/json` 响应；**不识别** `text/event-stream` 响应 → server 若回 SSE 流则解析失败。无 `Mcp-Session-Id` 头处理。 |
| **无 SSE 流** | 无 server→client SSE 消费（既无 Streamable-HTTP 的 SSE 响应，也无 legacy `GET /sse`）。 |
| **无生命周期** | 无 `initialize` 握手（stdio 上游有 `initialize_handshake`，`stdio.rs:493`）；无会话/重连。 |

### 2.3 增量形状——新 `StreamableHttpUpstream`，不动 stdio，不破 α2

**不改 `McpUpstream` trait 签名**（避免触 stdio 实现 + 全部 mock）。新增传输实现并行存在：

```text
                       Arc<dyn McpUpstream>
                      /         |            \
        StdioUpstream    HttpUpstream(α2,     StreamableHttpUpstream(本 ADR 新增)
        (stdio.rs)       OAuth-unary，保留)    POST→JSON|SSE + session + (可选)plain Bearer
```

- **Slice 1 决策**：**新建** `StreamableHttpUpstream`，**不就地改** α2 `HttpUpstream`（α2 已 Codex ACCEPT + 有 OAuth 测试矩阵，避免回归）。新类型可在初期复用 α2 的 OAuth 鉴权路径，也支持 plain Bearer（见 §3.3）。α2 `HttpUpstream` 保留给 `add-remote-mcp` OAuth-only 场景；待新类型成熟后**可选**收敛（非本 ADR 范围）。
- **`UpstreamEntry` 扩 enum**（`serve.rs:140`）——这是 schema 的**加性**改动，stdio 形态保持默认：

```rust
// serve.rs —— 兼容旧 JSON（仅 name+argv = stdio），新增 url 形态。
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]              // 旧 {name,argv} 仍命中 Stdio 变体 → 零破坏
pub enum UpstreamEntry {
    Stdio { name: String, argv: Vec<String> },
    Http  {
        name: String,
        url: String,                       // MCP endpoint（Streamable HTTP 单 endpoint）
        #[serde(default)] auth: HttpAuth,   // None | Bearer{env|keyring} | OAuth{resource,client_id}
        #[serde(default)] transport_hint: Option<HttpTransportHint>, // streamable(默认) | legacy_sse
    },
}
```

- **新 attach 函数** `attach_http_upstream`（`serve.rs`，与 `attach_stdio_upstream` 并列）：构造 `ServerProfile { transport: Http, url: Some(...), command: None, .. }`（`ServerProfile.url` 字段已存在，`vigil-types/src/server.rs:16`）→ `register_server`（幂等）→ `approve_server(Limited)` → 构造 `StreamableHttpUpstream` → `hub.attach_upstream(name, &[], upstream)`（`hub.rs:525`，HTTP 无 argv-drift，传空 argv slice；drift gate 对空 argv 是 no-op）。
- `build_hub_with_config` 装配循环（`serve.rs:360`）按 entry 变体分派 stdio / http。**stdio 路径一字不改**。

### 2.4 为何不在 `McpUpstream` 上加 streaming 方法

`McpUpstream::call` 是**同步 unary**（`upstream.rs:71` 注释 "I04 全同步模型"）。MCP 的 `tools/call` 语义本身是 **请求→单一最终响应**（即便走 SSE 流，流里的中间 message 是 progress/log notification，**最终仍是一条 response**）。因此：

- SSE 流在 `StreamableHttpUpstream::call` **内部**被消费 + 折叠为那一条最终 JSON-RPC response 返回。Hub 看到的仍是 `Result<Value, UpstreamError>`，**契约不变**。
- 流中的 server→client notification（progress / logging / `tools/list_changed`）在 M2 范围内**只记审计 + 丢弃**（不回放给 agent）。真正的 server-initiated → agent 双向通知是独立的大特性（需 Hub→agent 反向通道），明确 **out-of-scope**，记为后续。

## 3. Transport details（传输细节）

### 3.1 同步模型与 SSE 的张力——本 ADR 的核心工程抉择

现有 HTTP 栈是 `reqwest::blocking` + rustls + webpki-roots，`connect_timeout=5s` / `timeout=30s` / `min_tls_version=1.2` / `no_proxy`（`crates/vigil-http-transport/src/client.rs:18-76`）。`McpUpstream::call` 同步。

SSE 是一条**长连流**。在 blocking 模型下消费 SSE：`reqwest::blocking::Response` 实现 `std::io::Read`，可对其 `BufReader` **逐行读 SSE 帧**（`data:` / `event:` / `\n\n` 分隔），**无需引入 async/tokio 到调用路径**。这与 stdio 上游逐行读 NDJSON（`stdio.rs` reader 线程）是同构的 I/O 模式。

> **抉择**：SSE 用 **blocking streaming read**（`Read` + 手写极简 SSE 行解析器），**不引入** async runtime 到 `McpUpstream::call`、**不引入** `rmcp`/`eventsource-client`（见 §6 替代分析）。per-call timeout 通过 reqwest 的 request-level `timeout` + 一个 **读空闲看门狗**（见 §3.4）共同约束。

SSE 行解析器是约 50 行的纯函数（按 SSE 规范：`data:` 行累积、空行 dispatch、忽略注释 `:` 行），可独立单测，**不依赖网络**。

### 3.2 Streamable HTTP（2025-03，Slice 1+2 主线）

单 endpoint `POST <url>`，请求头：

- `Content-Type: application/json`
- `Accept: application/json, text/event-stream`（声明两种都收——这是 Streamable HTTP 客户端的正确行为）
- `Authorization: Bearer <token>`（由鉴权层注入，见 §3.3）
- `Mcp-Session-Id: <sid>`（若已有会话，Slice 4）
- `MCP-Protocol-Version: 2025-03-26`（spec 要求带版本头）

响应分流（按 `Content-Type`）：

- `application/json` → 直接 `serde_json` 解析 JSON-RPC response（= α2 现有路径，Slice 1）。
- `text/event-stream` → 进 SSE 读循环（Slice 2）：累积 `data:` 行 → 每个完整 SSE event 解析为一条 JSON-RPC message → 凡是 `id` 匹配本次请求且含 `result`/`error` 的即**最终响应**，读到即关流返回；其它（notification）记审计后丢弃。
- 首个响应若带 `Mcp-Session-Id` 响应头 → 存入 `StreamableHttpUpstream` 的会话状态（Slice 4），后续请求回带。
- `202 Accepted`（server 对 notification 的合法响应）/ 4xx / 5xx → 投影到 `UpstreamError`（复用 α2 `map_auth_error` + status 分流，`upstream.rs:293-298`）。

### 3.3 鉴权——两条并存的 token 来源

不变量：**token 经 planner 注入，类型上不可能 passthrough**（§1.3.5）。两种来源：

1. **OAuth（复用 α2 全链）**：`auth = OAuth{resource, client_id}` → `token_ref_for_access(resource, client_id)`（与 `add-remote-mcp` 持久化 key 一致，`add_remote.rs:211`）→ sealed `TokenStore::resolve_access_token` → planner。**`add-remote-mcp` 与 attach 在此闭环**：先 `add-remote-mcp` 拿 token，再在 upstream config 里以 `OAuth{resource,client_id}` 引用它。auto-refresh 复用 `AutoRefreshConfig`（`upstream.rs:53`）。
2. **Plain Bearer（新增，覆盖 PAT/静态 token 的托管 MCP）**：`auth = Bearer{ source: "env:GITHUB_TOKEN" | "keyring:svc/acct" }`。**复用 `serve.rs` 既有的 `resolve_secret_source`**（`serve.rs:397`，已支持 `env:` / `keyring:`、**拒 `literal:`**、错误不回显真值）在**启动期**读出 token 真值 → 包成一个**最小 `AuthorizedSender` 适配器**，它在 send 时拼 `Authorization: Bearer <value>`。**该 token 绝不入审计、绝不入错误**（与 OAuth 路径同一不泄漏纪律）。

> **⚠ 审查更正（§9 MF#1）**：原稿称 `AuthorizedHttpRequest` 是"只能由 planner / sealed 构造器产出"的封印类型——**与代码不符**：`planner.rs:23-33` 的 `AuthorizedHttpRequest` **全 `pub` 字段且非 `#[non_exhaustive]`**，任意 crate 可用结构体字面量自拼任意 `headers`，**类型层面零强制**。故 plain Bearer 的"不可 passthrough"目前**不靠类型**。**Slice 1 前置 MF#1**：先**真封印** `AuthorizedHttpRequest`（字段私有 + `#[non_exhaustive]` + crate-内 sealed 构造器；改后重验 α2 编译 + 测试），恢复"upstream 请求必经 authorized 类型"的真不变量；**且**加专测:plain-Bearer token 在审计 payload / 任何 agent-facing 字段 / 错误里**都不出现**。**关键铁律**：plain Bearer token 只活内存 `SecretValue`（Zeroizing、非 Debug），错误 `reason_code` 稳定枚举、绝不含 token。

URL gate（与 `add-remote-mcp` 一致，`add_remote.rs:87`）：**生产只接受 `https://`**；`http://` 仅 loopback（本地 mock，复用 `is_safe_token_endpoint` 思路，`upstream.rs:96`）放行，其余 fail-closed。

### 3.4 超时 / 重连 / 会话生命周期

- **per-call timeout**：`McpUpstream::call(timeout)` 的 `timeout`（Hub 传 `upstream_call_timeout` 默认 30s，`hub.rs:141`）作用于"发请求→拿到最终 JSON-RPC response"全程。SSE 读循环额外加**空闲看门狗**：若 `idle > timeout` 内无任何字节到达 → `UpstreamError::TimedOut`（防 server 开了流但永不推最终响应而吊死）。
- **`initialize` 握手**：HTTP 上游 attach 时 best-effort 跑一次 MCP `initialize`（POST，等 result）+ 记录 server 协商版本 + 抓 `Mcp-Session-Id`。失败 **非致命**（与 stdio 上游同 posture，`hub.rs:644-656`：log + 仍 attach，其工具不可用直到初始化成功）。
- **会话（Slice 4）**：`Mcp-Session-Id` 存 `Mutex<Option<String>>`；后续请求回带。Server 返 `404`（会话失效）→ 清会话 + 重跑 initialize 一次再重试该请求（一次性，避免风暴）。
- **重连（Slice 4）**：SSE 流断（EOF / reset）→ Streamable HTTP 的请求-响应是**短生命**（每个 `tools/call` 一条流），断了即该 call 失败返 `TransportIo`，下一个 call 重新发起，**不维护跨 call 的常驻流**（M2 简化：避免重连风暴 + last-event-id 复杂度）。legacy `GET /sse` 常驻流（Slice 5）才需要 `Last-Event-ID` 续传，故 legacy 优先级最低。
- **连接池**：复用 `reqwest::blocking::Client` 内部池；`shutdown()` 是 no-op（drop 自动 flush，同 α2 `upstream.rs:230`）。

### 3.5 Legacy HTTP+SSE（2024-11，Slice 5，最低优先级）

双 endpoint + 常驻 `GET /sse` 流（需后台读线程把 server→client 消息按 `id` 投递给 pending 表，结构同 `stdio.rs` 的 reader 线程 + `PendingTable`）。复杂度显著高于 Streamable HTTP（常驻流 + `Last-Event-ID` 续传 + endpoint 发现）。**仅当真实目标 server 只支持 legacy 时才做**；多数现代托管 MCP 已是 Streamable HTTP。

## 4. Security analysis（安全分析）

### 4.1 继承的不变量（传输无关层免费获得）

挂进 `Hub.upstreams` 后，HTTP 上游与 stdio 上游共享**同一** `invoke_upstream`（`hub.rs:1192`）：

- **Default-deny**：firewall 决策在 `up.call` 之前；HTTP 不绕过（决策不看 transport）。✅
- **Args detokenize**：`secret://<alias>` 仅在工具边界替真值（`hub.rs:1225`），且 alias 限定 `server`（跨 server 解析 deny）。HTTP 上游同样受用——远端 LLM 只见占位符，真值在 Vigil→HTTP-server 边界注入。✅
- **Result leak scan + redaction**：上游 result 命中硬指纹 → 审计 + in-band 脱敏（`hub.rs:1259-1295`），与 transport 无关。✅
- **Audit 链**：`ToolCallSpan`（`hub.rs:1242`）。✅
- **上游错误不泄漏**：α2 已把 JSON-RPC `error.message` sha256 化（`upstream.rs:281-289`）；HTTP transport 层错误只映射稳定 reason code（`client.rs:172` `map_reqwest_error`，**不透传** underlying message）。✅

### 4.2 新增攻击面与缓解（HTTP 特有）

| 攻击面 | 风险 | 缓解 |
|---|---|---|
| **SSRF**（upstream URL 指向内网/元数据端点）| upstream config 的 `url` 由用户写，但若来自不可信 onboarding（未来 setup-mcp 自动导入），恶意 URL 可让 Vigil 打内网 / `169.254.169.254` 云元数据 | (a) **生产仅 `https://`**（loopback `http` 仅本地 mock）；(b) **可选 SSRF 防护**：拒私网/链路本地/保留段（`10/8`、`172.16/12`、`192.168/16`、`127/8` 非显式允许、`169.254/16`、`::1` 等）——除非用户**显式** opt-in 内网（企业内网 MCP 合法用例，故是 opt-in 而非硬拒）；(c) DNS 解析后**对解析出的 IP** 复核（防 DNS rebinding）——M2 列为 Slice 3 加固项。`reqwest` 已 `no_proxy`（`client.rs:71`）杜绝 token 漏给 corp proxy。|
| **TLS 验证削弱** | 中间人窃 token / 篡改 result | 复用 `ReqwestHttpClient`：webpki-roots（**不**信系统根，跨平台一致，`client.rs:9`）、`min_tls_version=1.2`、自签 CA 能力**只在** test crate（`client.rs:49-57` 已删生产入口）。HTTP 上游**禁止**任何 `--allow-insecure`/skip-verify 生产开关。|
| **Header / response 注入** | 恶意 server 经响应头（`Mcp-Session-Id`、`Set-Cookie`）注入 / 污染 | (a) cookies feature 未启（`client.rs:62-65`，无 cookie jar，不存 server cookie）；(b) `Mcp-Session-Id` 取值**白名单字符集**（`[A-Za-z0-9._-]`、限长），异常即拒（防把恶意串回带进后续请求头触发 header 注入）；(c) 只读我们需要的响应头，其余忽略。|
| **Token passthrough** | agent 传入的 header 被透传到上游 / 上游 token 回流给 agent | planner `incoming_headers=&[]` 强制空（`upstream.rs:259`），类型上 `AuthorizedHttpRequest` 只能由 planner/sealed 构造 → **不可能**自拼 Authorization 或透传 client header。plain Bearer 的 token 只活内存、不入审计/错误（§3.3）。|
| **SSE 资源耗尽** | 恶意 server 开流后无限推数据 / 永不给最终响应 | (a) per-call timeout + **空闲看门狗**（§3.4）；(b) **流总字节上限**（如 8MB）超限即断流返错；(c) **单 message 行长上限**（防单行无界累积撑爆内存）。|
| **未初始化/降级协议** | server 协商出不支持的 MCP 版本 | 复用 stdio 的版本协商纪律（`stdio.rs:506-512` `SUPPORTED_PROTOCOL_VERSIONS`）：HTTP `initialize` 响应版本不在支持集 → fail-closed（非致命 attach，工具不可用）。|

### 4.3 不退步检查（与既有审计口径一致）

- 不引入"信任任意 server 证书"的生产可达入口（ADR 0011 §I-11.3 / `client.rs:49`）。
- 不把上游 URL / token / 响应原文写进审计 payload（沿用 sha256 / reason-code 纪律）。
- 不盲目透传 env（HTTP 上游根本不 spawn 子进程，无 env 注入面；plain Bearer 只从**显式** `env:KEY` 读单个值）。

## 5. Bounded implementation slices（可发货切片）

每片独立可测、独立 ACCEPT；mock 优先，真 E2E 留关键里程碑。

### Slice 1 — Streamable HTTP **非流式 POST** 上游接入网关（MVP，独立交付价值）

把"远端 HTTP MCP（JSON 响应）放进 firewall"打通端到端：`UpstreamEntry::Http` schema + `attach_http_upstream` + `StreamableHttpUpstream`（仅处理 `application/json` 响应，SSE 响应暂返 `Unsupported` 明确错误）+ plain Bearer & OAuth 两鉴权来源 + URL https gate。

> **实施状态（2026-06，Slice 1 交付）**：None / plain Bearer / **OAuth** 三鉴权来源**全部已接线 + 测试 + hostile review SHIP**；SSE 解析（Slice 2）+ SSRF denylist & `redirect(Policy::none())`（Slice 3 核心）**已前置落地**。
>
> **OAuth serve 期接线**（`serve.rs::build_oauth_upstream`）：从 `add-remote-mcp` 已落库 token metadata（`get_metadata` → issuer / `authorization_server` / scope）**重建** `ExpectedBinding`——经 AS re-discovery（`HttpJwksSource::fetch_as_metadata`）拿 `jwks_uri` → 建 `JwksSignatureVerifier`（§3.3 原设想低估了 `ExpectedBinding.key_verifier` 必填且 store 不持久化 JWKS，故须 re-discovery）。**无需浏览器**（token 已在库）。这是安全最敏感的一环（错误 verifier = 接受伪造 token），hostile review 后**fail-closed 全覆盖**：未 onboard / `resource` 与 `mcp_url` 异源（audience）/ `authorization_server`|`jwks_uri` 命中 SSRF denylist（`assert_url_safe` 复用，**不只 gate mcp url**）/ AS 不可达 / **issuer 漂移**（AS 改 issuer = 可疑）→ 绝不 attach 未验证上游。仅支持 JWT（`introspection=None`，opaque 留后续）。DI seam 供 mock-AS 单测（positive / issuer-drift / SSRF-reject）。
>
> **tracked follow-up**：`oauth_token_metadata` 行是整条验证信任链的根，但未进 `vigil-audit` 哈希链（hostile review Finding 7，本地 DB+keyring 双写威胁）——审计链绑定 / 行 MAC 是跨 onboarding + audit 的独立 slice。

- **Mock**：`MockHttpClient`/`AuthorizedSender`（`vigil-http-auth` 已有，`client.rs:96`）录 `initialize` + `tools/list` + `tools/call` JSON 响应。
- **验收**（mock，无网络）：
  - attach 一个 mock HTTP 上游 → `tools/list` 聚合到其工具（namespaced `<server>__<tool>`）。
  - `tools/call` 命中 default-deny → 返 `32001`（**证 firewall 对 HTTP 生效**）。
  - allow 规则下 `tools/call` → 转发 + 审计 span 落链 + result 命中硬指纹被 in-band 脱敏（**证 redaction 对 HTTP 生效**）。
  - args 带 `secret://alias` → 上游收到真值、agent 侧只见占位符（**证 detokenize 对 HTTP 生效**）。
  - 上游返 401 → `Unauthorized`；上游 `error.message` 不出现在返给 agent 的响应里（**证不泄漏**）。
  - `http://`（非 loopback）URL → attach fail-closed。
- **真 E2E**（1 个，可选）：对一个公开/本地托管的 Streamable-HTTP MCP（JSON 模式）跑 `serve` + 真 agent（Codex/Claude）一次 `tools/call`，账本无明文 token。

### Slice 2 — SSE 响应解析（Streamable HTTP 的 `text/event-stream` 分支）

`StreamableHttpUpstream::call` 识别 `Content-Type: text/event-stream` → blocking SSE 读循环 → 折叠为最终 JSON-RPC response。含 SSE 行解析器纯函数 + 流字节/行长上限 + 空闲看门狗。

- **Mock**：一个本地 loopback HTTP server（`tiny_http` 或手搓 `TcpListener`，test-only dep）按 `Accept` 返 `text/event-stream`，推若干 `data:` 帧（中间 notification + 最终 response）。
- **验收**：
  - SSE 流含 2 条 progress notification + 1 条最终 response → `call` 返最终 result，notification 记审计后丢弃。
  - 流在给最终响应前 EOF → `TransportIo`（不吊死）。
  - 流空闲超 timeout → `TimedOut`（空闲看门狗）。
  - 流超字节上限 → 断流 + 错误（资源耗尽防护）。
  - SSE 行解析器单测：`data:` 多行累积、`:` 注释忽略、`\n\n` dispatch、非 JSON data 行 fail-closed。

### Slice 3 — SSRF / 网络加固

私网/链路本地/保留 IP 段拒绝（默认）+ 显式 `allow_private_network` opt-in（企业内网）+ DNS 解析后 IP 复核（防 rebinding）+ `Mcp-Session-Id` 字符集白名单 + 响应头处理收敛。

- **验收**（纯单元，无真网络）：URL 指向 `169.254.169.254` / `10.x` / `127.0.0.1`（非 opt-in）→ 拒；opt-in 后 `10.x` 放行；`Mcp-Session-Id` 含非法字符 → 拒。

### Slice 4 — 会话与重连（Streamable HTTP `Mcp-Session-Id`）

`initialize` 抓 `Mcp-Session-Id` → 后续请求回带；server `404`（会话失效）→ 清会话 + 重 initialize + 一次性重试。

- **Mock/loopback**：server 首请求发 session id，校验后续请求回带；模拟 `404` 触发重建。
- **验收**：会话 id 正确回带；失效后自动重建一次；重建失败不无限重试。

### Slice 5 —（可选，按需）Legacy HTTP+SSE 双 endpoint

仅当出现只支持 legacy 的真实目标 server。常驻 `GET /sse` 读线程 + `endpoint` event 发现 + `Last-Event-ID` 续传。

- **验收**：endpoint 发现握手 + 双 endpoint 收发 + 流断续传。

> **建议落地顺序**：Slice 1 → 2 → 3 →（4 视真实 server 是否要求 session）→（5 仅按需）。Slice 1+2+3 即覆盖绝大多数现代托管 Streamable-HTTP MCP。

## 6. Alternatives & risks（替代与风险）

### 6.1 替代方案

| 方案 | 优点 | 缺点 | 取舍 |
|---|---|---|---|
| **A. 手搓 Streamable-HTTP 客户端（复用现有 reqwest::blocking + 极简 SSE 解析）**（本 ADR）| 零新重依赖；与现有 blocking + rustls + webpki-roots + planner 安全栈一致；`McpUpstream` 同步契约不变；SSE 解析器可独立单测 | 自己维护 SSE 解析 + session/重连 ~50-150 行 | ✅ 选 |
| B. 引入 `rmcp`（官方 Rust MCP SDK）做 HTTP 传输 | 协议正确性外包；跟进 spec | 重引入 async/tokio 到调用路径（与 I04 全同步模型冲突）；自带 HTTP/TLS 栈**绕过** Vigil 的 planner / webpki-roots / no-proxy 不变量（安全栈失控）；SDK 演进可能破 SemVer；体量大 | ❌ 安全栈失控 + 同步模型冲突 |
| C. 引入 `eventsource-client` 仅做 SSE | SSE 解析现成 | 多数 async；仍需自己接 planner/鉴权/session；为 ~50 行解析引入一个依赖 ROI 低 | ❌ ROI 低 |
| D. 不做 HTTP 上游，仅靠浏览器扩展覆盖远端 | 零新代码 | 浏览器扩展只覆盖**浏览器内**流量，覆盖不到 CLI agent 的 HTTP MCP——不解决问题 | ❌ 不解决问题 |

**核心理由**：Vigil 的差异化在于"**每次 tool call 经我们的安全栈**"。方案 B/C 的现成 HTTP 栈会**绕过** Vigil 自己的 planner（无 header passthrough）/ webpki-roots（不信系统根）/ no-proxy（不漏 token 给 corp proxy）/ 错误脱敏不变量——把安全核心外包给第三方 = 自毁卖点。手搓（复用既有 `AuthorizedSender` + `ReqwestHttpClient`）保持安全栈**完全自控**，且 SSE 那点协议解析风险通过纯函数单测可控。

### 6.2 风险与诚实工作量

- **工作量估计（诚实）**：这是 **M2 多切片特性**，非 one-shot。
  - Slice 1（MVP wired + JSON-only + 双鉴权 + schema）：**中**。最大工作量在"接油路"（schema enum + attach 分派 + plain Bearer 适配器 + 测试矩阵），引擎（α2 unary POST）已存在。
  - Slice 2（SSE）：**中**。SSE 解析器 + blocking 流读 + 看门狗 + loopback test server。
  - Slice 3（SSRF）：**小-中**。IP 段判定纯函数 + DNS 复核。
  - Slice 4（session/重连）：**小-中**。
  - Slice 5（legacy）：**中-大**，**按需**才做。
  - **建议先发 Slice 1**（独立交付"远端 JSON-RPC HTTP MCP 进 firewall"的真价值），再按真实目标 server 是否用 SSE/session 决定 2/4 节奏。
- **风险**：
  - **blocking SSE 占线程**：每个 in-flight HTTP `tools/call` 占一个 OS 线程读流。Vigil 当前请求模型本就串行（stdio 主循环逐条处理，`serve.rs:513`），并发上游调用极少，可接受；若未来高并发再评估 async（独立决策）。
  - **协议漂移**：MCP HTTP 传输仍在演进（2024-11→2025-03→未来）。缓解：`MCP-Protocol-Version` 头 + 版本协商 fail-closed（§4.2），新增修订在 `SUPPORTED_PROTOCOL_VERSIONS` 登记（`stdio.rs:116` SSOT 思路延用）。
  - **α2 `HttpUpstream` 与新类型并存**短期有两套 HTTP 上游：明确分工（α2=OAuth-only-unary 给 `add-remote-mcp`，新=通用 Streamable）；收敛是后续可选清理，不阻塞本特性。
  - **真 E2E 依赖外部 server**：托管 MCP 需账号/网络。缓解：mock + 本地 loopback test server 覆盖协议逻辑，真 E2E 仅作里程碑冒烟（参 `feedback_verify_against_real_dependency`：root-cause 须真依赖复测，但**协议正确性**可 loopback 覆盖）。

## 7. Consequences（后果）

- **传输无关安全层零改动**：`invoke_upstream` / firewall / redaction / audit span **不动**（`hub.rs:1192` 周边）→ 不回归已验证的安全核心；HTTP 上游"挂上即受保护"。
- **加性 schema**：`UpstreamEntry` 改 `#[serde(untagged)]` enum，旧 `{name,argv}` JSON 仍解析为 Stdio → **零破坏现有 config / `wrap` 路径**（`wrap.rs:124` 构造 stdio entry 不变）。
- **新公开 API**：`StreamableHttpUpstream`、`attach_http_upstream`、`UpstreamEntry::Http`、plain-Bearer 适配器。`McpUpstream` trait **签名不变**（SemVer 安全）。`TransportKind::Http` 已存在（`server.rs:36`），无需改枚举。
- **新依赖**：仅 test-only（loopback test server，如 `tiny_http`）；生产**零新依赖**（复用 `reqwest`/`rustls`/`webpki-roots`/planner）。
- **`add-remote-mcp` 闭环补全**：从"只存 token"升级为"存 token + 可被 upstream config 以 `OAuth{resource,client_id}` 引用并 attach"，OAuth 远端 MCP 首次真正进网关。
- **文档**：mdBook 加"远端 HTTP/SSE MCP 上游"页（双语，参 `feedback_bilingual_docs_no_interleave`）；诚实口径：明示**生产仅 https**、SSRF opt-in 边界、server-initiated 通知**不**回放（M2 范围）。

## 8. 实施期必含的不变量测试（killer 对照）

1. **firewall 对 HTTP 生效**：mock HTTP 上游 + default-deny `tools/call` → `32001`（与 stdio 同行为）。
2. **redaction 对 HTTP 生效**：HTTP 上游 result 含 `ghp_…` → 审计 `secret.leak_detected` + （开关下）result 被脱敏，agent 收不到原文。
3. **detokenize 对 HTTP 生效**：args `secret://k` → 上游收真值、agent 侧占位符；跨 server alias → deny。
4. **token 不泄漏**：plain Bearer 与 OAuth 两路径下，token 既不入审计 payload，也不入返给 agent 的任何字段/错误（断言响应/错误串不含 token）。
5. **no passthrough**：agent 传入伪 `Authorization` header → 不出现在上游请求（planner 空 incoming headers）。
6. **SSE 折叠正确**：含中间 notification 的 SSE 流 → `call` 返最终 result（Slice 2）。
7. **资源/超时 fail-closed**：SSE 永不给最终响应 → 空闲看门狗 `TimedOut`；超字节上限 → 断流报错（Slice 2）。
8. **URL gate**：`http://`（非 loopback）/ 私网 IP（非 opt-in）→ fail-closed（Slice 1/3）。

## 9. 安全审查解决（round 1，2026-06-08，对抗安全审查 ACCEPT-with-changes → 已并入）

独立 hostile security reviewer 抓出 5 项(我与设计 agent 自审均漏的真实问题——印证安全核心设计先行 + 对抗审查的价值)。逐条解决:

| MF | 审查发现(真问题) | 解决(并入设计) |
|---|---|---|
| **#1 BLOCKER** | §3.3/§4.2 称 `AuthorizedHttpRequest` "sealed 只能 planner 构造"**与代码不符**：`planner.rs:23-33` 全 `pub` 字段 + 非 non_exhaustive → 任意 crate 自拼任意 header,**类型零强制** | **Slice 1 前置**:真封印 `AuthorizedHttpRequest`(私有字段 + `#[non_exhaustive]` + crate-内 sealed 构造器,重验 α2)+ plain-Bearer token-non-leak 专测(审计/agent-facing/错误皆无 token)。§3.3 已更正口径。 |
| **#2 BLOCKER** | **SSRF**:Slice 1 发带 auth token 的 HTTP client 打用户/导入控制 URL,**仅 https scheme 检查**,私网/元数据 denylist 推 Slice 3 → `https://169.254.169.254` 过 gate = token 外泄 | **私网/链路本地/元数据 denylist(对 DNS 解析出的 IP)移入 Slice 1**(拒 `10/8`·`172.16/12`·`192.168/16`·`127/8`·`169.254/16`·`::1` 等,除非显式 opt-in 内网)。DNS-rebind 复核留 Slice 3。https-only 是必要非充分。`is_safe_token_endpoint` **只**作 loopback **allow**,**不**复用为 SSRF deny。 |
| **#3** | `UpstreamEntry` struct→enum **编译破坏 `wrap.rs:124`**(struct 字面量 `UpstreamEntry{name,argv}`);untagged 把 `{name,argv,url}` 静默路由 Stdio | Slice 1 显式迁移 `wrap.rs:124` → `UpstreamEntry::Stdio{..}`;每变体 `#[serde(deny_unknown_fields)]` 使 `{name,argv,url}` 两变体皆不匹配 → **报错而非静默 Stdio**;加该歧义拒绝测试。("wrap 不变"原稿删除。) |
| **#4** | mock-only 验收**绕过真实 AuthorizedSender/TLS/SSRF 面**(mock 载不动这些 bug) | token-non-leak + https/IP-gate 验收**改跑真 `ReqwestHttpClient`+真 AuthorizedSender**(loopback 测试 server 驱动),非仅 MockHttpClient([[feedback_verify_against_real_dependency]]/[[feedback_production_logic_testable]])。 |
| **#5(低)** | (a) `tools/list` 聚合(`hub.rs:736`)对 descriptor 内容**不**leak-scan → 恶意 HTTP server 的 tool description/schema 含 secret 原文直达 agent(stdio 已有,HTTP 扩到远端攻击者控制)。(b) 新 `StreamableHttpUpstream` 须复现 α2 的 error.message sha256 folding(`upstream.rs:281-289`),非假定继承 | (a) **文档化为已知 gap**(§4 新增):descriptor 内容泄漏是 transport 无关的既存限制,HTTP 放大它;后续可加 descriptor leak-scan(独立增量)。(b) 新类型的 error sha256 folding 列为 **Slice 1 显式不变量测试**(§8.4 已含 token-non-leak,补 error-message-non-leak)。 |

**Q1 PASS(核心架构对)**:reviewer 实证 `invoke_upstream`(`hub.rs:1192-1320`)transport-blind,无路径因 transport 改安全决策——chokepoint 复用是对的,B/C 替代(外包安全栈)拒绝合理。**结论**:核心架构 ACCEPT;修上面 2 个夸大声明(封印、SSRF)+ wrap 破坏 + 真实测试,即可作 slice plan 实施。**Slice 1 现含**:MF#1 封印 + MF#2 私网 denylist + MF#3 wrap 迁移/歧义拒 + MF#4 真 client 测试 + MF#5(b) error sha256 测试。
