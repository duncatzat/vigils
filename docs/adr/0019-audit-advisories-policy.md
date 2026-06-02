# ADR 0019 — Audit Advisories Policy(deny.toml allowlist + review schedule)

**Status**: Adopted(2026-05-16)
**Context**: v0.12.1 后 `cargo audit` 报 1 vuln(rsa dev-only)+ 19 unmaintained warnings。所有都 triage 过(per `feedback_audit_dev_dep_triage`):无 production runtime exposure,但 audit CI 输出每次都报警混淆真新发漏洞。

## 1. Problem

`cargo audit` 默认报全部 advisories。Vigil 当前 20 entries(1 vuln + 19 unmaintained):
- 全部已 triage,**0 production binary exposure**(dev-only / build-time / transitive 跟 Tauri ecosystem)
- 但每轮 audit 都报警 → 无法区分"新发漏洞"vs"已知 baseline"
- v0.12.1 `feedback_audit_dev_dep_triage` 已固化:audit 漏洞数 ≠ production 风险,必 triage dep kind

## 2. Decision

`deny.toml [advisories] ignore` 显式 allowlist 20 个已知 entries。每条:
- **`id`**:RUSTSEC ID
- **`reason`**:dep kind(dev / build-time / transitive)+ root cause + re-evaluation trigger

未来 `cargo deny check` 检测到 advisory **不在** allowlist → fail CI,强制 triage。

### 2.1 Allowlist 分类(v0.13.2,2026-05-16)

| 类别 | 数量 | Crates | Re-evaluation trigger |
|---|---|---|---|
| Dev-only(rsa)| 1 | RUSTSEC-2023-0071 | RustCrypto/RSA 出 constant-time impl |
| gtk-rs GTK3 stack(Tauri 2)| 9 | RUSTSEC-2024-0411/0412/0413/0415/0416/0418/0419/0420/0429 | Tauri 2 → GTK4 migration |
| unic-* Unicode | 5 | RUSTSEC-2025-0075/0080/0081/0098/0100 | markdown/tracing migrate to icu_* |
| Build-time / proc-macro / hash | 5 | RUSTSEC-2024-0370/2024-0436/2025-0057/2025-0134/2026-0097 | upstream successor crates |

### 2.2 严格反例:不在 allowlist

- 任何 production runtime binary 漏洞 — 必须立即 P1 修(per v0.12 wasmtime 25→43 实证)
- 任何 default feature 启 dep 的漏洞
- 任何 SDK 公开 surface 的漏洞

## 3. Review schedule

| Cadence | Action |
|---|---|
| Per release | 跑 `cargo audit` + `cargo deny check`(已在 ci.yml deny job)|
| Quarterly | 全 ignore list re-evaluate,看 trigger 是否触发 |
| Annual | Audit policy ADR 本文 review,更新 trigger 标准 |

## 4. Tooling

```bash
# 当前 audit(看真新漏洞):
cargo deny check advisories
# 若有 ignore list 之外的 advisory → fail,强制 ADR 0019 流程

# Bypass(仅 dev iter):
cargo audit  # 仍报全部,不 fail
```

## 5. Trigger 触发后流程

任一 ignore entry trigger 触发(e.g. Tauri 2 升 GTK4):
1. 升 dep version
2. 从 `deny.toml [advisories] ignore` 删 entry
3. `cargo deny check advisories` 必须 0 advisory
4. commit 标 `audit: clear RUSTSEC-XXXX-YYYY(<crate> upgrade)`

## 6. Alternatives Considered

| Option | Pros | Cons | 选择 |
|---|---|---|---|
| **A. deny.toml ignore 显式 allowlist + ADR**(本 ADR)| 透明 / 强制 triage / CI 守门 | 维护成本 | ✅ |
| B. cargo audit `--ignore` CLI flag | 不写文件 | CI 易漂移 | ❌ |
| C. 接受所有 audit 报警,人工 distinguish | 0 维护 | 噪音淹没真漏洞 | ❌ |
| D. 升级所有 dep 到 fixed 版本 | 真清 | 不可行(Tauri 等 upstream)| ❌ |

## 7. Implementation

- `deny.toml [advisories] ignore = [...]`(20 entries with reason)
- 本 ADR 文档化
- 后续:加入 ci.yml 跑 `cargo deny check`(随 CI 工作流上线)

## 8. Verification

- `cargo deny check advisories`(若 cargo-deny 装):报 0 critical
- `cargo audit`(unchanged):仍报 20 entries(正常,deny.toml ignore 仅影响 cargo-deny 不影响 cargo-audit)
- production binary 实测:0 CVE(per v0.11.1 audit + v0.12.1 audit + v0.13 audit 一致结论)

## 9. Memory cross-ref

- `feedback_audit_dev_dep_triage` — audit 三层 triage(dev-deps / optional / feature-gated)
- v0.11.1 audit 报告:`docs/operations/v0.11-roadmap/v0.11.1-post-release-audit.md`
- v0.13.1 candidate doc:`docs/operations/v0.13-roadmap/v0.13.1-candidates.md` C4 项
