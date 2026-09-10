> English version: [update-check.md](./update-check.md)

# 每日更新检查(version ping)

> 一句话:`vigil-hub serve` / `vigil-hub daemon start` 每天最多向 `vigils.ai` 发**一次** `GET`,只带**平台**和**本机版本号**,用来提醒你有新版本;服务端把这些请求按天计数,这就是 Vigils 唯一的采用度量。没有任何标识,可以一条命令关掉,`hook` 路径永远不发。

## 为什么有它

- **更新提醒**:CLI 没有自动更新,用户需要知道有新版本(尤其是安全修复)。
- **采用度量**:Vigils 不做产品遥测(不采集使用行为、不上报事件)。项目要判断该不该继续投入,只需要一个数字——**每天有多少安装在跑**。把「真实更新检查」按天计数得到的就是 ADI(Active Daily Installs,Firefox 2008–2020 用同样口径),这也是项目 FAQ 早已对外承诺的唯一出站流量。
- 这不是「遥测 opt-in」原则的例外:那条原则管的是崩溃上报(带堆栈),从未实装;更新检查是另一件事。

## 到底发了什么

每次就是下面这一条请求,没有别的:

```http
GET /desktop-updates/windows-x86_64/0.7.1.json HTTP/1.1
Host: vigils.ai
User-Agent: vigil-hub/0.7.1
```

- 路径里的 `windows-x86_64` = 平台(`darwin-aarch64` / `linux-x86_64` …),`0.7.1` = 本机 vigil-hub 版本。
- `User-Agent` = 产品名 + 版本号(桌面版另用 `vigils-desktop/<版本>`)。
- **没有**:设备 ID、随机 ID、周桶、盐、机器名、用户名、路径、账本内容、任何配置、任何 query 参数、任何 body。
- 不跟随跳转;清单最大读 64 KB;响应只取 `version` 字段并按 SemVer 子集校验后才会展示。

集成测试 `apps/vigil-hub-cli/tests/update_check.rs` 用本地一次性 HTTP 服务器抓包断言以上每一条(只发一次、只这两项、无多余请求头、三种关闭方式零出站)。

## 什么时候发

| 入口 | 行为 |
|---|---|
| `vigil-hub serve --stdio` | 启动时判断,后台线程发;stdout 一个字节不碰(那是 MCP 协议通道),只在 stderr 打行 |
| `vigil-hub daemon start` | 同上,在模型暖载之后 |
| `vigil-hub hook`(每次工具调用) | **永不发**。短进程 + 延迟预算;`tests/update_check.rs` 用源码守门断言 `hook.rs` / `command_guard.rs` / `posture.rs` 不引用更新检查 |
| 其它子命令 | 不发 |

- **每 24 小时最多一次**(按安装计):本地只落一个节流文件 `<data_local>/Vigil/update-check.last`(内容 = 上次尝试的 Unix 秒)。这是本功能**唯一**的本地落盘,而且**先记时间再发请求**——离线 / 失败也不会在 24h 内重发。
- **事前告知**:`vigil-hub setup`(apply 类操作)动手前在 stderr 打一行说明;`serve` / `daemon` 第一次尝试前也打一行。之后不再重复。
- 拿不到本地数据目录(无法节流)→ 不发。宁可少测,不多发。

有新版本时 stderr 会多一行:

```
vigil-hub 0.7.1: a newer release 0.8.0 is available -> https://github.com/duncatzat/vigils/releases/latest
```

## 怎么关

三种方式任一即生效,且**优先于一切**:

| 方式 | 说明 |
|---|---|
| `vigil-hub version-ping off` | 写入 `<data_local>/Vigil/version-ping.off`;`on` 删除它 |
| `VIGIL_NO_VERSION_PING=1` | 产品专属环境变量(任何非 `0` / `false` / `off` / `no` 的非空值) |
| `DO_NOT_TRACK=1` | 行业通用约定(<https://consoledonottrack.com>) |

手动检查一次并看清结果(含失败原因;关闭状态下拒绝执行,不例外):`vigil-hub version-ping check`。

查看状态:

```
$ vigil-hub version-ping status
version ping: enabled
  what:     one GET per day from `serve` / `daemon start`, to notice a newer release
  sends:    platform + version only, no identifiers
  request:  GET https://vigils.ai/desktop-updates/windows-x86_64/0.7.1.json
  last try: 3h ago
  turn off: vigil-hub version-ping off   (or VIGIL_NO_VERSION_PING=1 / DO_NOT_TRACK=1)
```

`vigil-hub version-ping status --json` 输出稳定 schema(与界面语言无关):`enabled` / `disabled_by`(`env:VIGIL_NO_VERSION_PING` / `env:DO_NOT_TRACK` / `marker` / `no-state-dir` / `null`)/ `endpoint` / `user_agent` / `sends` / `last_attempt_unix` / `min_interval_secs`。

自托管或内网镜像:`VIGIL_UPDATE_ENDPOINT=https://mirror.example.com`(基址;路径规则不变)。

## 服务端留什么

- 源站是 `vigils.ai`(nginx,Cloudflare 前置)。`/desktop-updates/*` 是 `no-cache`,每条请求都到源站。
- nginx 用默认 `combined` 访问日志:时间、请求行、状态码、UA,以及**连接方 IP——经 Cloudflare 代理后这是 Cloudflare 边缘节点的 IP,不是你的 IP**(源站没有开启 real-IP 还原,也不记录 `CF-Connecting-IP`)。日志按天轮转,保留 14 天。
- 聚合脚本(`/opt/vigils/ota-adoption.py`,每日一次)只输出**计数**:按 `(日, 平台, 版本)` 的请求数、7 天 ADI 均值、平台 / 版本分布。落盘的报告与历史里没有 IP、没有 UA 原文。
- 聚合结果计划公开在 `https://vigils.ai/stats/adoption.json`(与 Homebrew / Fedora 的做法一致:被计数的人能看到数字)。

## 法务口径(GDPR / ePrivacy)

- 客户端只落一个节流时间戳,它是「更新检查」这个用户可感功能自身的严格必要存储;不落盐、ID、桶(EDPB Guidelines 2/2023 v2.0 把写入终端设备的任何信息都纳入 ePrivacy 5(3),所以设计上把「存储」收窄到这一个文件)。
- 服务端瞬时看到的连接 IP 走 GDPR 第 6 条 (1)(f) 正当利益;正当利益评估(LIA)摘要:**目的** = 更新提醒与安装计数;**必要性** = 已是最小数据(平台 + 版本);**权衡** = 无标识、可关闭、事前告知、聚合结果公开、日志 14 天即删。
- 对外措辞统一为:「**无使用行为遥测;仅一个可关闭的计数式更新检查**」,不再写「零网络请求」之类的简写。

## 版本与范围

- 引入版本:下一个发布版(在前一版 release notes 预告后才启用)。
- 本轮只接 CLI(`serve` / `daemon`);桌面版在 Settings 加开关后再接(桌面 UA 为 `vigils-desktop/<版本>`)。
- 相关代码:策略层 `crates/vigil-update-check`(纯逻辑,无网络,可离线测试);接线 `apps/vigil-hub-cli/src/update_check.rs`;测试 `apps/vigil-hub-cli/tests/update_check.rs`。
