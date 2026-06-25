//! Vigil 常驻 daemon(ADR 0024):暖载 ML 模型 + 本地 IPC,让 hook 主防护路径低延迟跑 ML。
//!
//! # 为何需要(ADR 0024 §0/§1)
//!
//! hook 是每次工具调用一次性子进程,冷载 738MB+ORT ≈ 7s 不可行。daemon 常驻持暖
//! `OrtEngine`(PII NER)+ `InjectionClassifier`(DeBERTa),hook 退化为**瘦客户端**经本地
//! IPC(UDS / Windows named pipe)查询。
//!
//! # 模块结构(沿 ort + 平台边界切分)
//!
//! - [`protocol`]:线协议(serde 类型 + 长度前缀帧)。**零 ort,默认构建** —— daemon 服务端与
//!   hook 瘦客户端共享。故**小 hook 二进制(无 ort)可经 IPC 用 ort daemon 的 ML**。
//! - [`client`]:`daemon.json` 契约(读/写)+ fail-closed 握手/请求序列(`exchange`)。**零 ort**。
//! - [`server`]:服务端**单连接处理逻辑**(`handle_connection`,可单测)+ fail-closed 握手 +
//!   model-less dispatch。**零 ort / 零平台**。
//! - [`transport`]:`interprocess` 本地 socket + **R1** peer-credential + **R2** 总读截止 +
//!   单实例(bind 失败守门)。**零 ort**;`query_daemon`(hook 端)+ `bind`/`serve`(daemon 端)。
//!
//! **已落**:ort 暖载层(`lifecycle::run_start` 暖载 PII scanner + 注入分类器 + R3 绑定自有 canonical
//! ledger;dispatch 出真 findings / 软信号 risk bump)、`daemon start|stop|status` 子命令、hook 接
//! `query_daemon`(PostToolUse PII 再脱敏 + 注入 fire-forget,fail-closed)。后续:F2 bounded executor
//! (thread-per-conn × thread-per-classify 上限)、R6 socket 权限硬化。
//!
//! # 不变量(ADR 0024 Revised,实施前必决 R1–R6 已落决策)
//!
//! daemon = **无状态推理 oracle**(D2:返 findings,merge/decision 全留 hook)→ 缺/超时/冒充/
//! 畸形响应 **只抑制 ML recall**,动不了硬指纹 deny 与 PostToolUse withhold → **永不 fail-open**。

pub mod client;
pub mod lifecycle;
pub mod protocol;
pub mod server;
pub mod transport;
