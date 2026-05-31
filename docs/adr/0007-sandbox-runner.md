# ADR 0007 — Sandbox Runner(I07 + I07.5 + I07.5+)

- 状态:**Accepted**(I07 R3 ACCEPT 2026-04-20 / I07.5 R3 ACCEPT 2026-04-22 / I07.5+ R1 ACCEPT 2026-04-22;详见 `STATUS.md`)
- 日期:2026-04-20(初版)/ 2026-04-22(I07.5 Landlock + I07.5+ helper 抽取 修订)
- 依赖:ADR 0001 / 0002 / 0003 / 0004 / 0005 / 0006

## 1. 背景与范围

主方案 §8:firewall 是逻辑边界,sandbox 是物理边界。I07 交付统一的执行计划抽象
(`ExecutionPlan`)+ 两个 runner(Wasm + Native)+ 与 I04 StdioUpstream 和 I06
PreparedChildEnv 的集成,保证:
- env_clear 有**唯一**的 spawn 后端(不再有两份实现漂移)
- 真 Wasm sandbox(wasmtime + WASI preopen)保证 guest 不能越界读写
- 预检 + 超时 + stdout/stderr 最早处脱敏 + 审计

**I07 范围**(Windows 开发机可完成 + 三端可测):
- `ExecutionPlan` / `RunnerKind` / `RunnerSpecific` / `ExecutionResult` 类型
- `SandboxProfile` 内存 struct + JSON round-trip(**不持久化**,持久化延 I08)
- `NativeSpawnBackend`:统一 env_clear / cwd / capture / timeout;
  `StdioUpstream::spawn` 复用此 backend
- `WasmRunner`:wasmtime + WASI preopen + env none + fuel/epoch 限制 + smoke guest
- `PreparedChildEnv` 集成:`runner.spawn(plan, prepared_env)` 入参,紧邻 `Command::envs()` 处 `take_env()`
- stdout/stderr 脱敏 pipeline(内置默认 redactor + 可替换 ScrubCallback)
- 5 条审计事件:`runner.started / completed / killed_by_timeout / io_error / rejected`
- 预检拒绝(path allowlist / profile deny)返 `RunnerError::Rejected` + `runner.rejected` 审计
- §8.7 验收 7 条(§8.7-4 native repo 外写拦截 I07 走**预检**,真 Landlock 延 I07.5)

**I07 不包含 → I07.5(Linux 强隔离专项)**:
- Linux Landlock 文件边界
- Linux seccomp syscall filter
- Linux no_new_privs + RLIMIT_CPU

**I07 不包含 → I08**:
- macOS App Sandbox entitlement
- Windows AppContainer / restricted token
- SandboxProfile SQLite 持久化(`sandbox_profiles` 表)
- `server_profiles.sandbox_profile_id` 的真实消费

**诚实隔离等级(§8.5)**:
- Wasm:**Strong**(I07 落地)
- Linux native:**Weak**(I07)→ **Strong**(I07.5)
- macOS native:**Weak**(I07)→ **Medium**(I08)
- Windows native:**Weak**(I07)→ **Medium**(I08)

## 2. 关键决策(Codex 协作)

### D1 — Wasm runner 范围

**决策**:真闭环最小集 —— wasmtime + WASI preopen + env none + fuel/epoch 限制 +
内嵌 smoke guest(手写 wasm 或预编译 wat:读一个 preopen 文件写 stdout)。

**理由**:没有真 Wasm 就无法验证 §8.7-1/2(preopen 外不可读);完整 guest 生态过大。

### D2 — Native 跨平台范围

**决策**:三端 MVP 统一做 `env_clear + timeout + cwd + capture`;Linux Landlock
延至 **I07.5**(独立小迭代,在 Linux SSH 测试环境完成)。
§8.7-4 走**预检拒绝**(Rust 侧检查 path 是否在 allowlist 内,不在就返 `RunnerError::Rejected` + 审计 `runner.rejected`)。ADR 明确声明 isolation level=Weak,不冒充 Strong。

### D3 — ExecutionPlan 形状

**决策**:统一 `ExecutionPlan` + `RunnerSpecific::{Wasm, Native}` 枚举。

```rust
pub struct ExecutionPlan {
    pub runner_kind: RunnerKind,
    pub cwd: PathBuf,
    pub read_dirs: Vec<PathBuf>,
    pub write_dirs: Vec<PathBuf>,
    pub allowed_hosts: Vec<String>,      // I07 仅记录,网络真隔离延后
    pub env_leases: Vec<String>,         // metadata:此 plan 需哪些 alias
    pub cpu_ms: u64,                     // 软 budget(I07 仅记录)
    pub wall_ms: u64,                    // 真 timeout 源
    pub memory_mb: u32,                  // wasm fuel 换算;native 仅记录
    pub capture_stdout: bool,
    pub capture_stderr: bool,
    pub runner_specific: RunnerSpecific,
}

pub enum RunnerKind { Wasm, Native }

pub enum RunnerSpecific {
    Wasm { fuel_units: u64, epoch_deadline_ms: u64 },
    Native { /* 预留 rlimit 占位 */ },
}
```

### D4 — 与 StdioUpstream 的关系

**决策**:抽共享 `NativeSpawnBackend`(Builder / 静态 fn),`StdioUpstream::spawn` 内部改调用此 backend。StdioUpstream 长驻语义不变。

### D5 — 与 PreparedChildEnv 集成

**决策**:`runner.spawn(plan, argv, prepared_env: PreparedChildEnv)` 直接吃 RAII 句柄;函数内紧邻 `Command::envs()` 处 `take_env()`。ExecutionPlan.env_leases 只存 alias metadata,不存真值。

### D6 — Timeout kill 策略

**决策**:`tokio::process::Child + timeout(wall_ms, child.wait) + kill_on_drop(true)`;OS 原生(Linux RLIMIT_CPU / Windows Job / macOS helper)延 I07.5。

### D7 — 脱敏 pipeline

**决策**:runner 内最早处脱敏。`ExecutionRunner` 持 `scrub: Arc<dyn Fn(&str) -> String + Send + Sync>`,默认 `vigil_redaction::scrub_text`。capture loop 每 read 一行 → scrub → append。原始 bytes 不穿过 trace / panic / audit。

### D8 — SandboxProfile 持久化

**决策**:I07 **不建** SQLite 表;`SandboxProfile` 为内存 struct + `serde_json` round-trip 测试。`server_profiles.sandbox_profile_id` 保持占位。持久化延 I08 UI 时做。

### D9 — 审计事件

**决策**:5 条 `runner.*` 事件:

| 事件 | 触发 | payload |
|------|------|---------|
| `runner.started` | spawn 成功 | `{runner_kind, server_id, wall_ms, env_keys, cwd}` |
| `runner.completed` | 正常退出 | `{exit_code, wall_elapsed_ms, stdout_bytes, stderr_bytes}` |
| `runner.killed_by_timeout` | wall_ms 耗尽 | `{wall_ms, pid}` |
| `runner.io_error` | stdin/stdout pipe 失败 | `{phase, reason_code}` |
| `runner.rejected` | 预检失败 | `{reason_code, field}` |

## 3. 数据模型

```rust
pub struct SandboxProfile {
    pub id: String,
    pub read_dirs: Vec<PathBuf>,
    pub write_dirs: Vec<PathBuf>,
    pub allow_hosts: Vec<String>,
    pub env_inherit: bool,               // 必须 false(AGENTS §7)
    pub wall_ms: u64,
    pub memory_mb: u32,
}

pub enum RunnerError {
    Rejected { field: RejectField, reason_code: &'static str },
    Timeout { wall_ms: u64 },
    Io { phase: &'static str, reason_code: &'static str },
    WasmTrap(String),                    // 已脱敏
    Internal(&'static str),
}

// I07.5:新增 `Sandbox` 变体 + `#[non_exhaustive]`,对应 Linux Landlock 失败路径。
#[non_exhaustive]
pub enum RejectField { Cwd, ReadDir, WriteDir, ProfileId, Argv, Runner, Sandbox }

pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub wall_elapsed_ms: u64,
    pub stdout: Vec<u8>,                 // 已脱敏
    pub stderr: Vec<u8>,                 // 已脱敏
}
```

## 4. 运行时流程

```rust
// 1. 构造 plan(预检 path allowlist,否则 Rejected)
let plan = ExecutionPlan::native(profile, argv)?;

// 2. I06 broker 准备 env
let prepared = broker.prepare_child_env(&ctx, approval_id, ttl)?;

// 3. Spawn(紧邻 take_env)
let result = native_runner.spawn(&plan, &argv, prepared).await?;

// 4. 审计由 runner 内部产

// 5. prepared 在函数返回后 Drop → revoke lease
```

## 5. 安全不变量

- **I-7.1**:**一次性** native spawn 必须走 `NativeSpawnBackend`;**长驻** stdio spawn 见
  `StdioUpstream`(I04 已实装 env_clear + envs),两者共享"env_clear + envs + 无继承"契约。
  **I07.5+ 完成**:两份实现的 helper 抽取 —— `vigil_runner::apply_native_env_policy(cmd, user_env)`
  封装原子三步(env_clear → Windows `RESERVED_SYSTEM_ENV_KEYS` 注入 → envs);`spawn_native`
  和 `StdioUpstream::spawn` 都调用此 helper,消除历史漂移(此前 StdioUpstream 缺 Windows
  SystemRoot 注入 → cmd.exe 作为 MCP server 启动失败)
- **I-7.2**:`ExecutionPlan` 构建必须经 `plan.validate()` 预检(path canonicalize + 在 allowlist 内)
- **I-7.3**:`runner.spawn` 内 `take_env()` 与 `Command::envs()` 之间不得插入任何
  log / Debug / audit 调用(pattern 由 code review 把关)
- **I-7.4**:`scrub` 必须在 read → buffer 阶段同步调用,原始 bytes 不持久化
- **I-7.5**:Wasm engine 必须 env_clear 等价(WASI `inherit_env=false`)+ 默认 network=off
- **I-7.6**:所有 `RunnerError` 路径必须产审计事件,不得静默失败
- **I-7.7**(I07.5 新增):**Linux Native spawn 必须走 Landlock**。
  `spawn_native` 在 `Command::spawn` 前调用 `LandlockPolicy::install_into(cmd)`,
  父进程构造 `RulesetCreated`(失败 → `RunnerError::Rejected { field: Sandbox }`,
  `reason_code ∈ { landlock_kernel_unsupported, landlock_path_open_failed,
  landlock_ruleset_build_failed, landlock_unknown_install_error }`);
  pre_exec 闭包调 `restrict_self()`,`RulesetStatus != FullyEnforced` → fail-closed `EPROTO`。
  **Linux 从 I07 的 "Weak"(env_clear + cwd + timeout)收敛为 I07.5 的 "Strong"(上述 + kernel-enforced FS 白名单)**
- **I-7.8**(I07.5 新增):**unsafe_code 集中**。Landlock 需要 `CommandExt::pre_exec`(unsafe API),
  全项目唯一 unsafe 暴露点在 `vigil-sandbox-linux::LandlockPolicy::install_into`,
  其 crate-level `unsafe_code = "deny"` + 局部 `#[allow(unsafe_code)]`;所有其他
  vigil-* crate 保持 workspace `unsafe_code = "forbid"` 不变
- **I-7.9**(I07.5 新增):**pre_exec 闭包必须 async-signal-safe**。
  - 禁止 `format!` / `to_string()` / `io::Error::new(str)` / 任何分配
  - 失败必须通过 `std::io::Error::from_raw_os_error(LANDLOCK_PRE_EXEC_ERRNO)` 传回
    (`pub const LANDLOCK_PRE_EXEC_ERRNO: i32 = libc::EPROTO`)
  - 父进程 `spawn_native` 在 `Command::spawn` 失败时检查 `raw_os_error() == LANDLOCK_PRE_EXEC_ERRNO`,
    映射到 `Rejected { Sandbox, reason_code: "landlock_restrict_self_failed" }`,否则走 `command_spawn_failed`
  - **已知限制 / TOCTOU**:`plan.validate()` 后、`install_into` 前存在 symlink-swap 理论窗口,
    landlock 0.4 未暴露 `openat2 + RESOLVE_NO_SYMLINKS` + fstat 校验。**留待 I07.6 / 升 landlock 0.5+**

## 6. 测试与验收(§8.7 映射)

| # | 验收 | 测试 | I07 范围 |
|---|------|------|---------|
| 1 | Wasm 不能读任意文件 | `wasm_cannot_read_outside_preopen` | 是 |
| 2 | Wasm 只能读 preopen | `wasm_preopen_grants_read_access` | 是 |
| 3 | Native 子进程不继承 env | `native_spawn_env_is_cleared` | 是 |
| 4 | Native 写 repo 外被拦 | `native_write_outside_allowlist_rejected`(预检;I07.5 补 Landlock) | 预检 |
| 5 | 超时进程被 kill | `native_sleep_over_wall_ms_is_killed` | 是 |
| 6 | stdout/stderr 脱敏 capture | `capture_scrubs_sentinel_in_stdout` | 是 |
| 7 | 子进程结束后 lease revoked | `prepared_env_drop_revokes_lease_after_spawn` | 是 |

### 失败 + 边界

- `plan_rejects_cwd_outside_allowlist`
- `wasm_fuel_exhaustion_returns_trap`
- `native_broken_pipe_returns_io_error`
- `native_argv_missing_binary_rejected`
- `stdio_upstream_uses_shared_backend`(I04 回归)

## 7. 跨版本契约

- `ExecutionPlan` / `RunnerKind` / `RunnerSpecific` / `ExecutionResult` 稳定
- `NativeSpawnBackend::spawn(plan, argv, prepared_env) -> Result<ExecutionResult, RunnerError>`
- `WasmRunner::run(plan, wasm_module, input) -> Result<ExecutionResult, RunnerError>`
- 审计事件前缀:`runner.*`(非 `RESERVED_EVENT_PREFIXES`)
- `scrub: Arc<dyn Fn(&str) -> String + Send + Sync>`

## 8. 延后项

| 延后项 | 目标迭代 | 原因 |
|--------|---------|------|
| Linux Landlock 文件边界 | I07.5 | Linux SSH 交叉测试 |
| Linux seccomp | I07.5+ | 同上 |
| macOS App Sandbox | I08 | 需 entitlement profile + helper process |
| Windows AppContainer | I08 | 需 COM + restricted token |
| SandboxProfile SQLite 持久化 | I08 | 需 UI 绑定 |
| allowed_hosts 真网络隔离 | I07.5 / I08 | Linux netns / Windows WFP |
| RLIMIT_CPU / Job Object / Mach | I07.5 / I08 | OS 原生硬限制 |

---

## § Revised v0.12 P1(2026-05-13)— wasmtime 25 → 43.0.2 升级

**驱动**:v0.11.1 post-release `cargo audit` 报 wasmtime 25.0.3 含 **15 RUSTSEC**
漏洞(sandbox escape / panic / data leakage / memory miscompile)。Sprint 6
Codex evidence-based PARK 后,清债优先级 P1。

### Breaking changes(25 → 43.0.2)

| 维度 | wasmtime 25 | wasmtime 43.0.2 | Vigil 处理 |
|---|---|---|---|
| `wasmtime-wasi` feature | `preview1` | `p1`(短形式)| Cargo.toml 改 `features = ["p1"]` |
| WASIp1 入口 module | `wasmtime_wasi::preview1` | `wasmtime_wasi::p1` | `wasm.rs` import 改 |
| `MemoryOutputPipe` 位置 | `wasmtime_wasi::pipe` | `wasmtime_wasi::p2::pipe` | `wasm.rs` import 改 |
| `WasiCtxBuilder` / `DirPerms` / `FilePerms` | root re-export | **root re-export(保留)** | 无变化 |
| `add_to_linker_sync` / `preopened_dir(4 args)` / `build_p1` | 同 | **签名相同** | 无变化 |
| `Engine` / `Store` / `Linker` / `Module` 核心 API | preview1 path | **稳定** | 无变化 |

**workspace 升级**:rustc 1.91.0 兼容 wasmtime 43.x;44.0.1 起需 rustc 1.92.0,
选 **43.0.2**(在 RUSTSEC fix range `>= 43.0.2, <44.0.0` 内 + 不破 rust-toolchain)。

### 验证

| Gate | Result |
|---|---|
| `cargo check -p vigil-runner --features wasm` | ✅ |
| `cargo test -p vigil-runner --features wasm` | ✅ 6/6 PASS |
| `cargo check --workspace --all-targets` | ✅ |
| `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings` | ✅ |
| `cargo clippy --workspace --features ort --all-targets -- -D warnings` | ✅ |
| `cargo audit` | **16 → 1**(剩 `rsa 0.9.10` dev-dep,no fixed upgrade,known dev-only) |

### 不变量影响

不变量 1-9(ADR § 5)**未受影响**:
- `inherit_env = false` 仍 default 行为
- `fuel + epoch` 双限制 API 兼容(`Store::set_fuel` / `set_epoch_deadline` / `Engine::increment_epoch`)
- preopen 仅 `plan.read_dirs`(write 走 `plan.write_dirs` 交集)
- Codex R1 BLOCKER "每次 run 独立 Engine"(`build_engine()` 每次构造)— 保留

### 修复的 RUSTSEC(15 wasmtime 漏洞)

RUSTSEC-2025-0046/0118 + RUSTSEC-2026-0020/0021/0085/0086/0087/0088/0089/
0091/0092/0093/0094/0095/0096 — sandbox escape / panic / data leakage /
memory miscompile 全部修。

### 后续

- wasmtime 44.0.1 升级留 v0.13(待 rust-toolchain 升 1.92)
- 19 unmaintained warnings(gtk-rs / paste / unic-* / glib / rand):follow Tauri
  ecosystem upgrade,非 P1

---

## Amendment (2026-06-01) — O3: stdio upstream PATH resolution under env_clear

**Status**: Implemented (Codex design ACCEPT, session 019e7f1e). Code review pending on next collaborative pass.

### Context
`§I-7.1` `apply_native_env_policy` does `env_clear()`, which strips `PATH`. `StdioUpstream::spawn`
built `Command::new(&argv[0])` with a **bare** command (e.g. `node`/`npx`/`python`, the MCP
ecosystem convention). On Unix, `std::process::Command` resolves a bare program name against the
command's (now-empty) env → `Spawn(NotFound)`. Windows `CreateProcess` masks it via its own search
order. Net effect: bare-command stdio upstreams failed on Linux/macOS.

### Decision (O3 — resolve before clear)
`StdioUpstream::spawn` now calls `resolve_program(&argv[0])` **before** building the `Command`,
resolving the bare command to an **absolute path** using the **host (parent) PATH**
(Unix: `X_OK`; Windows: `PATHEXT`). The child is then launched with `env_clear` as before.

**§I-7.1 invariant preserved**: the child environment is still fully cleared (no `PATH` leaks to the
child). Only *program location* uses the parent PATH, in the parent. `argv[1..]` is never resolved.
`argv[0]` containing a path separator is treated as a path (canonicalize), not PATH-searched.
Resolution failure returns the distinct `StdioError::ProgramNotFound` (fail-closed), not a generic
`Spawn`.

### Deferred (V1.1, requires Codex code review)
Per Codex review, descriptor pinning / audit `command_hash` should be computed over the **resolved
absolute path** (not the bare name) so that drift detection catches `node` resolving to a different
binary, and the audit records the approved-bare → executed-absolute mapping. This is a drift
state-machine semantic change (touches `compute_argv_hash` + drift tests) and is staged as a
separate iteration. TOCTOU (resolve-time vs exec-time binary replacement) is out of scope for V1
(no inode/hash pinning) per the same review.
