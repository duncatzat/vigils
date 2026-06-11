//! RiskScorer —— ADR 0003 §D4 权重表实装。

use std::collections::HashSet;

use vigil_types::{EffectKind, EffectVector};

/// 描述 descriptor 审批/漂移状态,影响风险加分。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DescriptorStatus {
    /// 已审批且 hash 未变
    ApprovedStable,
    /// 首次见到,未审批
    FirstSeen,
    /// descriptor hash 发生漂移
    Drifted,
}

/// I04 §D8:把 descriptor 状态决策的权威来源收窄为一个 trait,
/// 避免 firewall 自己猜测或从外部参数直接传入。
///
/// 实现方:
/// - 生产环境:`vigil-mcp::ServerRegistry`(对齐 pinning 状态机)
/// - 测试:`StaticDescriptorOracle`(本模块下方提供)
pub trait DescriptorOracle: Send + Sync {
    /// 查询一次工具调用对应的 descriptor 当前信任状态。
    fn status(&self, server_id: &str, tool_name: &str, descriptor_hash: &str) -> DescriptorStatus;
}

/// 测试用常量 oracle:不管输入一律返回固定状态。
///
/// 实际 firewall 的 evaluate 签名改为拿 trait 对象后,老的"直接传 status"
/// 这种调用方式就统一经此小工具桥接;测试代码改动量最小。
#[derive(Debug, Clone, Copy)]
pub struct StaticDescriptorOracle(pub DescriptorStatus);

impl DescriptorOracle for StaticDescriptorOracle {
    fn status(&self, _server: &str, _tool: &str, _hash: &str) -> DescriptorStatus {
        self.0
    }
}

/// 评分器。无状态,线程安全。
#[derive(Debug, Default)]
pub struct RiskScorer {
    /// 已知 "安全 host" 白名单;未在其中的 NetOutbound 会被加 +20
    pub allowed_hosts: HashSet<String>,
    /// 项目根前缀(POSIX 规范化过),用于检测"越界写"
    pub project_roots: Vec<String>,
}

impl RiskScorer {
    /// 构造。
    pub fn new(allowed_hosts: Vec<String>, project_roots: Vec<String>) -> Self {
        Self {
            allowed_hosts: allowed_hosts.into_iter().collect(),
            project_roots,
        }
    }

    /// 评分 + reasons。返回 clamp 到 0..=100。
    pub fn score(&self, effects: &EffectVector, descriptor: DescriptorStatus) -> (u8, Vec<String>) {
        let mut s: i32 = 0;
        let mut reasons: Vec<(i32, String)> = Vec::new();

        match descriptor {
            DescriptorStatus::FirstSeen => {
                s += 15;
                reasons.push((15, "first-seen MCP server".into()));
            }
            DescriptorStatus::Drifted => {
                s += 25;
                reasons.push((25, "descriptor hash drifted since last approval".into()));
            }
            DescriptorStatus::ApprovedStable => {}
        }

        if effects.effects.contains(&EffectKind::FsWrite) {
            s += 20;
            reasons.push((
                20,
                format!("writes local files: {}", effects.paths_write.len()),
            ));
            // DEF-004:空 roots 时无法断言"项目外",跳过越界加分——否则所有写
            // 都被 +30 且 reason 谎称 OUTSIDE(与 policy Outside 守门同语义)。
            if !self.project_roots.is_empty() {
                let outside: Vec<&String> = effects
                    .paths_write
                    .iter()
                    .filter(|p| !self.under_any_root(p))
                    .collect();
                if !outside.is_empty() {
                    s += 30;
                    reasons.push((30, format!("writes OUTSIDE project: {}", outside[0])));
                }
            }
        }

        if effects.effects.contains(&EffectKind::NetOutbound) {
            s += 15;
            reasons.push((15, format!("outbound network: {:?}", effects.network_hosts)));
            let unknown: Vec<&String> = effects
                .network_hosts
                .iter()
                .filter(|h| !self.allowed_hosts.contains(*h))
                .collect();
            if !unknown.is_empty() {
                s += 20;
                reasons.push((20, format!("unknown host: {}", unknown[0])));
            }
        }

        if effects.effects.contains(&EffectKind::SecretUse) {
            s += 25;
            reasons.push((
                25,
                format!("uses credential lease: {:?}", effects.secret_refs),
            ));
        }

        if effects.effects.contains(&EffectKind::ExecNative) {
            s += 30;
            reasons.push((30, "runs native subprocess".into()));
        }

        if effects.destructive {
            s += 35;
            reasons.push((35, "destructive operation detected".into()));
        }

        if effects.effects.contains(&EffectKind::CommSend)
            || effects.effects.contains(&EffectKind::BrowserSubmit)
        {
            s += 25;
            reasons.push((
                25,
                format!(
                    "sends to recipients / submits form: {}",
                    effects.recipients.len()
                ),
            ));
        }

        // clamp
        let score = s.clamp(0, 100) as u8;
        // 按权重降序排列 reason(v0.13 clippy 1.95 用 sort_by_key + Reverse 表达更短)
        reasons.sort_by_key(|r| std::cmp::Reverse(r.0));
        let reasons = reasons.into_iter().map(|(_, s)| s).collect();
        (score, reasons)
    }

    fn under_any_root(&self, p: &str) -> bool {
        // DEF-004:与 vigil-policy `is_under` 同语义 —— Windows 路径大小写不敏感。
        // 不存在的写目标走 manual_normalize 保留调用方原始盘符大小写(如 `d:/...`),
        // 若此处大小写敏感比较,会对项目内写误报 "writes OUTSIDE project" +30。
        #[cfg(target_os = "windows")]
        let p = &p.to_ascii_lowercase();
        self.project_roots.iter().any(|r| {
            #[cfg(target_os = "windows")]
            let r = &r.to_ascii_lowercase();
            if p == r {
                return true;
            }
            let prefix = if r.ends_with('/') {
                r.clone()
            } else {
                format!("{}/", r)
            };
            p.starts_with(&prefix)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs_write(path: &str) -> EffectVector {
        EffectVector {
            effects: vec![EffectKind::FsWrite],
            paths_write: vec![path.to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn inside_project_write_is_moderate() {
        let s = RiskScorer::new(vec![], vec!["/proj".into()]);
        let (score, reasons) = s.score(
            &fs_write("/proj/src/main.rs"),
            DescriptorStatus::ApprovedStable,
        );
        assert_eq!(score, 20);
        assert!(reasons.iter().any(|r| r.contains("writes local files")));
    }

    #[test]
    fn outside_project_write_is_higher() {
        let s = RiskScorer::new(vec![], vec!["/proj".into()]);
        let (score, _) = s.score(&fs_write("/etc/hosts"), DescriptorStatus::ApprovedStable);
        assert!(score >= 50);
    }

    #[test]
    fn destructive_exec_pushes_toward_top() {
        let s = RiskScorer::new(vec![], vec!["/proj".into()]);
        let eff = EffectVector {
            effects: vec![EffectKind::ExecNative],
            destructive: true,
            ..Default::default()
        };
        let (score, reasons) = s.score(&eff, DescriptorStatus::ApprovedStable);
        assert!(score >= 65);
        assert!(reasons[0].contains("destructive") || reasons[0].contains("native"));
    }

    #[test]
    fn first_seen_adds_descriptor_risk() {
        let s = RiskScorer::new(vec![], vec!["/proj".into()]);
        let (score, reasons) = s.score(&fs_write("/proj/src/a.rs"), DescriptorStatus::FirstSeen);
        assert!(score >= 35);
        assert!(reasons.iter().any(|r| r.contains("first-seen")));
    }
}
