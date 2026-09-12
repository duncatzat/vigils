# 出站闸门(outbound gate,可选开启)

> 一句话:开启后,Claude Code / Codex 发往模型 API 的**请求体**会先经过本机 `127.0.0.1` 上的一个代理,裸凭据在离开这台机器**之前**被换成 `[REDACTED …]`;响应原样流回,不缓冲、不落盘。默认**关闭**,一条命令开、一条命令关。

## 它补的是哪个洞

Vigil 原有两条腿都在**入口**:hook 看 agent 的工具调用,MCP 网关看工具结果。两者都看不到这些东西进上下文:

| 进模型的内容 | hook / 网关 | 出站闸门 |
|---|---|---|
| 工具入参、工具结果 | ✅ | ✅ |
| 提示词里的裸凭据 | ✅ | ✅ |
| `@文件` 直接内联(不走 Read 工具) | ❌ | ✅ |
| `CLAUDE.md` / `AGENTS.md` 等记忆文件 | ❌ | ✅ |
| 压缩摘要、模型自己复述出来的凭据 | ❌ | ✅ |

Claude Code 的上下文是 append-only:一个密钥进去了,**这个会话后面每一次**模型调用都带着它。入口拦截管不到已经进去的内容,出站闸门管得到。

## 开启

```console
$ vigil-hub outbound on
出站闸门:已开启(http://127.0.0.1:8445)
  claude  已生效(经闸门) [已写入, backup C:\Users\you\.claude\settings.json.vigil-bak]
  codex   已生效(经闸门) [已写入, backup C:\Users\you\.codex\config.toml.vigil-bak]
  闸门:   未运行 —— 用 `vigil-hub daemon start`(或 `vigil-hub outbound serve`)启动;启动前指向它的 agent 会 fail-closed
  下一步:重启已打开的 agent 会话(base URL 在启动时读取)
```

闸门**本体随 daemon 运行**:

```console
$ vigil-hub daemon start
vigil-hub daemon:出站闸门监听 http://127.0.0.1:8445(路由:/anthropic /codex /openai /gemini)
```

没装 daemon 也行,`vigil-hub outbound serve` 前台跑一个。桌面版在「设置 → outbound · gate」有同一个开关。

关闭:`vigil-hub outbound off`(还原 agent 配置,只动 Vigil 写进去的键)。

## 它改了你的哪两行配置

| agent | 文件 | 写入 |
|---|---|---|
| Claude Code | `~/.claude/settings.json` | `env.ANTHROPIC_BASE_URL` = `http://127.0.0.1:8445/anthropic`;`env.ENABLE_TOOL_SEARCH` = `"true"` |
| Codex CLI | `<CODEX_HOME>/config.toml` | `model_provider = "vigil"` + `[model_providers.vigil]`(`base_url` / `wire_api = "responses"` / `requires_openai_auth = true`) |

- 改写前**先备份**(`.vigil-bak`),原子替换,读取到写入之间文件被别人改过就中止不写。其它键一律不碰,键序与 TOML 注释都保留。
- `off` 只在值**仍是**闸门地址时才还原;你自己改过就原样留着。
- 你原本把 `ANTHROPIC_BASE_URL` 指向自家网关(LiteLLM / Portkey …)?闸门会**串在它前面**:记住原地址当上游,`off` 时还原回去。
- `ENABLE_TOOL_SEARCH` 是必须的:Claude Code 一旦发现 base URL 不是一方地址,会默认**关掉** MCP tool search。闸门原样透传 `tool_reference`,所以显式开回来(你自己设过就不动)。

订阅登录(Claude Pro / Max、ChatGPT 套餐)照常工作 —— 闸门原样转发 `Authorization` / `x-api-key` / `ChatGPT-Account-ID`,不改一个字节,也不记录它们。

## 请求体怎么被处理

1. **读完整请求体**,超过 64 MiB 直接 413 拒绝。
2. **不是 JSON 就拒绝**(415),压缩过的请求体也拒绝(400 类):看不懂的体一律不放行,而不是放行了假装看过。只读方法(GET / HEAD / OPTIONS / DELETE)没有体,直通。
3. **逐个字符串叶子扫硬指纹**(与 hook / 网关同一套 17 类规则,含 base64 载荷),命中的字节段换成 `[REDACTED <规则名>]`。
4. **协议信封不碰**:`id` / `*_id` / `model` / `role` / `signature` / `encrypted_content` / `thinking` 等键的字符串值跳过 —— 改它们要么破坏协议,要么毫无意义。**内联图片 / 音视频 / PDF 的 base64 不设例外**:媒体类型是请求方自称的,认它就等于给凭据开了一扇「套层外衣即免检」的后门;真实图片解出来不是文本,本来就不会命中规则。
5. **在真正要发的字节上再查一遍**。改写作用于解析后的 JSON 树,上行的是字节 —— 信封键跳过的位置、重复 JSON 键、占位符口径差,都可能让凭据活到最后一刻。此时仍命中即 **422 拒绝转发**,不发出去。
6. **转发**,请求头原样带上(去掉逐跳头)。
7. **响应按块直通**,不缓冲、不解析、不改写 —— 流式输出的手感与直连一致。

改了什么会记进本地账本(`outbound.request.redacted`),payload 只有**规则名和条数**,没有任何原文。

一次真实的改写:

```jsonc
// 你的 agent 发出的
{"messages":[{"role":"user","content":"deploy with ghp_1234567890abcdef1234567890abcdef12345678"}]}
// 实际离开本机的
{"messages":[{"role":"user","content":"deploy with [REDACTED github_token]"}]}
```

## 诚实边界

**这不是 maskit 那种可逆脱敏代理。** 它只处理**凭据类硬指纹**,而且**不还原**:模型看到的就是 `[REDACTED …]`,响应里也不会被换回去。代价是模型拿不到真值(对密钥而言这正是我们要的),好处是本机**不存**任何明文映射表,也不需要解析 SSE 去做还原。要可逆的 PII 脱敏,请用专门做这件事的工具,两者可以叠。

其它边界,请先读再依赖:

- **只管模型 API 这条腿**。agent 用工具访问别的主机(curl、git push、MCP server)不经过闸门 —— 那些归 hook 与网关管。
- **只认硬指纹**。人名、邮箱之类语义 PII 不在此列(那是 ML 引擎的事)。刻意用 hex / `String.fromCharCode` / 跨多次调用分段外泄的内容,闸门同样看不出来。
- **字节自检不是第二套独立检测器**。它跑的是同一套规则,所以继承同一批盲区:base64 段有 256 段的
  扫描预算(可被大量非凭据的 base64 长串吃干)、只解一层(套两层 base64 的看不出)、只认解码后是
  文本的载荷(DER 私钥、原始二进制密钥永远不命中)。它兜住的是「改写结果与真正上行的字节不一致」
  那一类,**不是**覆盖面的保证。
- **一个已知、可构造的缺口,现在就点名**:请求体里若先出现大量**非凭据**的长 base64 串(解出来不是
  文本即可,例如随机二进制),再在后面放一段**base64 编码过的凭据**,前面那些会把扫描预算吃光,
  后面那段就扫不到 —— 结果是**放行**。填充与载荷**不必在同一个字段里**。这不是理论推演:仓库里有一条
  写死 422 断言、当前**确实红着**的测试钉着它(`cross_leaf_base64_padding_…`,标了 `#[ignore]`
  以便缺口可见而非被默认已覆盖),修法在共用的 `vigil-redaction`,见 ADR 0025 §6。
  **普通流量不受影响,但请不要把闸门当成「凭据一定出不去」的保证。**
- **响应不扫**。模型复述出来的内容原样回到你的终端(它本来就在你机器上)。
- **Bedrock / Vertex / Foundry 模式会被拒绝开启**:那些模式不走 `ANTHROPIC_BASE_URL`,Bedrock 还对整个请求体签名,改体即破签。
- **Codex 已有自定义 `model_provider` 时拒绝接管**,不抢你的网关配置。
- **Codex 的压缩 / 记忆等 backend 路由不经闸门**:Codex 只对内置 `OpenAI` provider(且 URL 以
  `/backend-api/codex` 结尾)走那条路,我们的 provider 叫别的名字,所以拿不到它们。**采样请求**
  (真正带上下文的那些)仍然经闸门。
- **Codex 侧的 `requires_openai_auth = true` 覆盖的是「经 `codex login` 认证过」的用户**(订阅登录或
  API key 登录都算)。只在环境变量里放了 `OPENAI_API_KEY`、从未登录过的用户,Codex 会要求先登录。
- **Gemini CLI 暂未接线**:API key 模式可走 `GOOGLE_GEMINI_BASE_URL`,但 Google 登录走的是另一个端点,留到下一批。
- **云端 / 远程会话看不到**:流量不在这台机器上。
- **闸门没起来时 agent 会 fail-closed**:指向它的调用直接失败(附一行说明),而不是绕过它直连。这是刻意的 —— 安全功能宁可显眼地坏掉,也不要静默地不生效。

## 排查

```console
$ vigil-hub outbound status
出站闸门:开启
  监听:    http://127.0.0.1:8445
  闸门:    运行中 (requests 42, rewritten 3, blocked 0)
  Claude:  已生效(经闸门)
  Codex:   不支持: model_provider `litellm` is in use; …
  Gemini:  暂不支持
  配置:    C:\Users\you\AppData\Local\Vigil\outbound.json
```

`--json` 给机器可读版本(schema 稳定、与界面语言无关),桌面版与脚本都用它。

| 症状 | 原因 | 处理 |
|---|---|---|
| agent 报连接失败 / 502 | 闸门没在跑 | `vigil-hub daemon start` |
| 开了但 `status` 显示 agent「未配置」 | 会话仍在用旧的 base URL | 重启 agent 会话 |
| `status` 显示「陈旧」 | 换过监听端口 | `vigil-hub outbound off` 再 `on` |
| MCP 工具变多、上下文变大 | tool search 被关 | 确认 `settings.json` 里 `ENABLE_TOOL_SEARCH` 为 `"true"` |
| 同一会话**每次**请求都 422 `residual_secret` | 凭据落进了受签名保护的推理块(`thinking`),改它会破坏协议,只能拒;而该块此后每轮都会回传 | 错误里会报出**结构位置**(如 `messages[0].content[1].thinking`,只报位置不报内容):裁掉那一个 assistant 轮次即可,不必丢整段上下文;并清掉 agent 正在读的那个凭据来源 |

监听地址**必须是环回**(`127.0.0.1` / `[::1]`):闸门透传你的 API 凭据,绝不能挂到局域网上。配置里写了非环回地址,会被当作损坏配置、按关闭处理。
