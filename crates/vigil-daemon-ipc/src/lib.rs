//! Vigil daemon 本地 IPC —— 协议 + 瘦客户端(ADR 0024)。
//!
//! daemon 常驻持暖 ML 模型(PII NER + 注入分类器),各**瘦客户端**经本地 socket
//! (UDS / Windows named pipe)查询;任何异常(缺席/超时/版本不符/畸形帧)一律
//! fail-closed 降级为「无 ML」,由调用方的硬指纹底座兜底,**永不 fail-open**。
//!
//! 本 crate 从 `vigil-hub-cli` 的 `daemon::{protocol,client,transport}` 抽出(纯移动,
//! 逻辑与安全不变量不变),使 daemon 客户端不再绑定 Hub CLI 的完整依赖图 —— 首个受益方
//! 是 `vigil-native-host`(浏览器扩展的本机进程,Chrome 常驻,须保持轻量)。
//!
//! # 模块
//! - [`protocol`]:线协议(serde 类型 + `u32 LE` 长度前缀帧)。零 ort。
//! - [`client`]:`daemon.json` 发现契约(读/写)+ fail-closed 握手/请求序列。
//! - [`transport`]:`interprocess` 本地 socket + **R1** peer-credential + **R2** 总读截止
//!   + 单实例 bind 守门。服务端 accept 循环(需持模型的 `DaemonCaps`)留在 `vigil-hub-cli`。
//! - [`wire`]:daemon [`protocol::WireFinding`] 的**安全应用原语**(span 校验/并集合并/
//!   受保护区减法/label sanitize)—— hook 与 native-host 共用,防各自重实现漂移。
//!
//! # 安全不变量(ADR 0024 Revised)
//! daemon = 无状态推理 oracle:返 findings,merge/decision 全留客户端 → 缺/冒充/畸形
//! **只抑制 ML recall**,动不了调用方的硬指纹底线。

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod client;
pub mod protocol;
pub mod transport;
pub mod wire;
