-- vigil-audit I01 schema。幂等:重复 open 不再执行 CREATE。
-- 跨 crate/跨版本契约见 ADR 0002。

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  source     TEXT NOT NULL,
  app_name   TEXT,
  started_at INTEGER NOT NULL,
  ended_at   INTEGER,
  risk_score INTEGER NOT NULL DEFAULT 0
);

-- events 是 append-only 账本;其他表(decisions/invocations/leases/approvals)是投影表。
-- event_hash 由 vigil-audit::hash::compute_event_hash 按 ADR 0002 §D3 计算。
CREATE TABLE IF NOT EXISTS events (
  event_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id    TEXT NOT NULL,
  event_type    TEXT NOT NULL,
  payload_json  TEXT NOT NULL,   -- JCS 规范化后的 JSON 字符串
  redacted_text TEXT,             -- 供 FTS5 搜索的已脱敏摘要
  prev_hash     TEXT NOT NULL,    -- 空串表示 genesis
  event_hash    TEXT NOT NULL,    -- sha256(...) hex-lower
  created_at    INTEGER NOT NULL,
  -- VIGIL-SEC-001:chain 摘要版本。1=v1(legacy,仅 prev/payload/created_at);
  -- 2=v2(额外绑定 session_id/event_type/redacted_text)。新事件写 2;verify_chain 按列分派。
  chain_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);

CREATE TABLE IF NOT EXISTS decisions (
  decision_id     TEXT PRIMARY KEY,
  invocation_id   TEXT NOT NULL,
  session_id      TEXT NOT NULL,
  decision        TEXT NOT NULL,   -- Allow / Deny / Approve
  risk_score      INTEGER NOT NULL,
  reasons_json    TEXT NOT NULL,
  policy_ids_json TEXT NOT NULL,
  created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invocations (
  invocation_id      TEXT PRIMARY KEY,
  session_id         TEXT NOT NULL,
  server_id          TEXT NOT NULL,
  tool_name          TEXT NOT NULL,
  args_redacted_json TEXT NOT NULL,
  args_hash          TEXT NOT NULL,
  descriptor_hash    TEXT NOT NULL,
  created_at         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS leases (
  lease_id         TEXT PRIMARY KEY,
  secret_ref       TEXT NOT NULL,
  session_id       TEXT NOT NULL,
  server_id        TEXT NOT NULL,
  tool_name        TEXT NOT NULL,
  approval_id      TEXT,
  injection_method TEXT NOT NULL,
  expires_at       INTEGER NOT NULL,
  created_at       INTEGER NOT NULL,
  revoked_at       INTEGER
);

-- I01 仅建 schema + 直接插入/查询原语。
-- I02+I03 扩展:新增 invocation_id(ADR 0003 §D6:Once scope 绑 invocation)。
-- I04 扩展:新增 scope 列(ADR 0004 §F1:ThisSession scope 持久化)。
CREATE TABLE IF NOT EXISTS approvals (
  approval_id   TEXT PRIMARY KEY,
  decision_id   TEXT NOT NULL,
  invocation_id TEXT NOT NULL DEFAULT '',
  session_id    TEXT NOT NULL,
  title         TEXT NOT NULL,
  summary       TEXT NOT NULL,
  effect_json   TEXT NOT NULL,
  status        TEXT NOT NULL,  -- Pending / Approved / Denied / Expired / Cancelled
  scope         TEXT,           -- NULL | Once | ThisSession | ...(仅 Approved 状态有值)
  args_hash     TEXT,           -- 首次命中时记录的 args_hash,供 ThisSession 查询(I04+)
  server_id     TEXT,           -- 同上,ThisSession 命中需要 (server, tool, args_hash) 三元组
  tool_name     TEXT,
  expires_at    INTEGER NOT NULL,
  created_at    INTEGER NOT NULL,
  resolved_at   INTEGER,
  resolved_by   TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_session_scope
  ON approvals(session_id, status, scope);

-- I04 Outbox(ADR 0004 §D7)
CREATE TABLE IF NOT EXISTS outbox_items (
  outbox_id     TEXT PRIMARY KEY,
  invocation_id TEXT NOT NULL,
  session_id    TEXT NOT NULL,
  kind          TEXT NOT NULL,   -- http_post | email | browser_submit
  preview_json  TEXT NOT NULL,   -- 已脱敏的预览
  approval_id   TEXT,
  status        TEXT NOT NULL,   -- Drafted | PendingApproval | Approved | Denied | Expired | Executed | Cancelled | Failed
  created_at    INTEGER NOT NULL,
  approved_at   INTEGER,
  executed_at   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_outbox_session_status
  ON outbox_items(session_id, status);

-- I04 Server Registry(ADR 0004 §D6)+ I05 drift(ADR 0005 §D2)
CREATE TABLE IF NOT EXISTS server_profiles (
  server_id            TEXT PRIMARY KEY,
  transport            TEXT NOT NULL,    -- Stdio | Http
  command_json         TEXT,             -- Vec<String> JCS,仅 Stdio 有
  url                  TEXT,             -- 仅 Http 有
  first_seen_at        INTEGER NOT NULL,
  command_hash         TEXT,             -- sha256(JCS(command_json))—— 当前已批准版
  descriptor_hash      TEXT,             -- 聚合所有工具 descriptor_hash
  trust_level          TEXT NOT NULL,    -- Untrusted | Limited | Trusted
  sandbox_profile_id   TEXT,
  -- I05 新增:drift 检测(ADR 0005 §D2)
  pending_command_hash TEXT,             -- 与 command_hash 不等的新 argv hash
  last_drift_at        INTEGER,
  -- I08 新增(Codex R1 BLOCKER):drift 批准后必须能让 UI 展示新 argv 文本,
  -- 仅有 hash 会让 §4.7 "exact argv 可见" 失真。Caller(Hub)写 drift 时同时传 argv JSON。
  pending_command_json TEXT,
  -- V1.1 新增(ADR 0007 §I-7.1 / ADR 0005 第二独立 drift 维度):裸 argv[0] 经宿主 PATH
  -- 解析后的**本机绝对路径**。与 command_hash(argv 文本)正交 —— argv 不变但解析二进制变
  -- (PATH shadow / 重定位)时由本列检测。per-machine 本地基线,非可移植 descriptor identity。
  resolved_program_path         TEXT,    -- 已 pin 的本机解析路径(首见即信任建立基线)
  pending_resolved_program_path TEXT      -- 与 resolved_program_path 不等的新解析路径(待审批)
);

CREATE INDEX IF NOT EXISTS idx_server_trust ON server_profiles(trust_level);
CREATE INDEX IF NOT EXISTS idx_server_drift
  ON server_profiles(pending_command_hash) WHERE pending_command_hash IS NOT NULL;
-- V1.1 注:不在此为 pending_resolved_program_path 建索引 —— 该列经 COLUMN_MIGRATIONS 添加,
-- 而 SCHEMA_SQL(含 CREATE INDEX)在 ledger.rs:217 先于迁移(:222)执行,旧库升级时列尚不存在
-- 会 "no such column" 失败(同理 pending_command_json 也无索引)。当前无 list_resolved_drifted
-- 查询消费该索引(YAGNI);未来若加 list API,改在迁移后以编程方式建索引。

-- I04 per-tool descriptor pinning(ADR 0004 §D6)+ I05 drift 状态机(ADR 0005 §D1)
CREATE TABLE IF NOT EXISTS tool_descriptors (
  server_id       TEXT NOT NULL,
  tool_name       TEXT NOT NULL,
  descriptor_hash TEXT NOT NULL,       -- 当前已批准 hash
  first_seen_at   INTEGER NOT NULL,
  approved_at     INTEGER,             -- NULL = untrusted pinned(AGENTS §5 默认)
  -- I05 新增:drift 支持
  pending_hash    TEXT,                 -- tools/list 见到的新 hash(若与 descriptor_hash 不等)
  last_seen_hash  TEXT NOT NULL DEFAULT '',
  last_seen_at    INTEGER NOT NULL DEFAULT 0,
  last_drift_at   INTEGER,
  PRIMARY KEY (server_id, tool_name)
);

CREATE INDEX IF NOT EXISTS idx_tool_drift
  ON tool_descriptors(pending_hash) WHERE pending_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tool_pending_approval
  ON tool_descriptors(approved_at) WHERE approved_at IS NULL;

-- F1 覆盖索引(ADR 0004 §F1 + Codex NICE-TO-HAVE-1)
CREATE INDEX IF NOT EXISTS idx_approvals_scope_lookup
  ON approvals(session_id, server_id, tool_name, args_hash, status, scope, expires_at);

-- I10 OAuth Token Metadata(ADR 0010 §D4)
-- 仅存 metadata,**不**存 token value。真值在 vigil-lease::SecretStore。
CREATE TABLE IF NOT EXISTS oauth_token_metadata (
  token_ref            TEXT PRIMARY KEY,     -- SecretStore key: token://oauth/{kind}/<res_hash>/<client_hash>
  resource             TEXT NOT NULL,
  authorization_server TEXT NOT NULL,
  scope_set_json       TEXT NOT NULL,        -- JCS 规范化的 Vec<String>
  token_kind           TEXT NOT NULL,        -- 'access' | 'refresh'
  expires_at           INTEGER,              -- NULL = 不过期
  created_at           INTEGER NOT NULL,
  -- I10b-α1(ADR 0011 §α1-D1):JWT `iss` 校验必需的 AS issuer 字符串。
  -- 新库直接带列;legacy I10a 磁盘行通过 COLUMN_MIGRATIONS ADD COLUMN 后为 NULL,
  -- 读侧统一 fail-closed(TokenStoreError "issuer_missing_legacy_row")。
  -- 刻意 nullable(**不**得改 NOT NULL)—— ADD COLUMN NOT NULL 对非空表会失败。
  issuer               TEXT,
  -- Finding 7(hostile review):本行安全字段绑定到的审计事件 event_id(oauth.token_metadata_bound)。
  -- 读侧按**此特定 id** 取事件 + verify_chain 校验,使行获得与账本其余状态同级篡改可检测性。
  -- nullable:legacy(本特性前 onboard)行 NULL → 读侧放行(无法回溯);新行恒带有效 id。
  binding_event_id     INTEGER
);

-- I08 Sandbox profile 持久化(ADR 0008 §D6)
-- profile_json 是 serde_jcs 规范化后的 JSON;profile_hash = sha256(profile_json)
-- 算法口径与 I04 command_hash / I04 descriptor_hash 一致。
CREATE TABLE IF NOT EXISTS sandbox_profiles (
  profile_id   TEXT PRIMARY KEY,
  profile_json TEXT NOT NULL,
  profile_hash TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);

-- I06 Secret refs + tool-secret bindings(ADR 0006 §3)
-- 严格不变量:secret_refs 不得包含真实 value,fingerprint 只对 alias 做域分离 hash。
CREATE TABLE IF NOT EXISTS secret_refs (
  secret_ref    TEXT PRIMARY KEY,     -- 'secret://github/repo-write'
  display_name  TEXT NOT NULL,
  provider      TEXT NOT NULL,
  fingerprint   TEXT NOT NULL,        -- SHA-256(domain_tag || normalized_secret_ref)
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER                -- 每次 mint_lease 更新
);

CREATE TABLE IF NOT EXISTS tool_secret_bindings (
  server_id         TEXT NOT NULL,
  tool_name         TEXT NOT NULL,   -- '*' = server 级绑定(全 tool 可用)
  secret_ref        TEXT NOT NULL REFERENCES secret_refs(secret_ref),
  injection_method  TEXT NOT NULL,   -- 'ChildEnv' | 'HttpHeader' | 'Pipe' | 'TempFile'
  env_var_name      TEXT,            -- ChildEnv 专用;其他注入方式为 NULL
  created_at        INTEGER NOT NULL,
  PRIMARY KEY (server_id, tool_name, secret_ref, injection_method)
);
CREATE INDEX IF NOT EXISTS idx_bindings_server ON tool_secret_bindings(server_id);

-- FTS5:只索引 redacted_text,不索引 payload_json,避免误将已脱敏字段里残留的
-- 字面字符被意外搜出。rowid == events.event_id。
-- tokenchars 保留 `_ - .`:让 `github__create_issue` / `inv-1` / `tool_call.decided`
-- 作为完整 token 存在。`:` **不**作为 tokenchar —— 让 FTS5 的 column:term 语法保留
-- 给真实 FTS 列名,同时让 `finding:github_token` 被拆成 `finding` 与 `github_token`
-- 两个独立 token,查询 `github_token` 能命中。
CREATE VIRTUAL TABLE IF NOT EXISTS event_fts USING fts5(
  session_id,
  event_type,
  redacted_text,
  tokenize = "unicode61 remove_diacritics 2 tokenchars '_-.'"
);

-- ISS-011 Stage 2:T0 redaction scan 审计两表。ADR 0013 / ISS-005 依赖。
-- **核心不变量:绝不存原文**。text 长度用位数量化(u64::BITS - leading_zeros,
-- 0 特判为 0),等价于"最高有效位位号";指纹用 sha256(input) 前 16 字节 hex-lower
-- (32 char)。严禁出现任何指代明文内容的字段名;具体禁字段集合见守门测试
-- `test_schema_forbids_plaintext_columns`(在 tests/redaction_schema.rs),任何
-- 存原文字段的改动必然触发该测试失败。
CREATE TABLE IF NOT EXISTS redaction_scans (
  scan_id             TEXT PRIMARY KEY,
  session_id          TEXT NOT NULL,
  ts                  INTEGER NOT NULL,            -- Unix epoch 秒
  source              TEXT NOT NULL,               -- paste | tool_arg | tool_output | export
  text_length_bucket  INTEGER NOT NULL,            -- bit_width_bucket(len):len 的位宽(MSB 1-based),0→0
  fingerprint         TEXT NOT NULL                -- sha256(input)[..16] hex-lower(严格 32 字符 [0-9a-f])
);
CREATE INDEX IF NOT EXISTS idx_redaction_scans_session ON redaction_scans(session_id);
CREATE INDEX IF NOT EXISTS idx_redaction_scans_ts      ON redaction_scans(ts);

CREATE TABLE IF NOT EXISTS redaction_findings (
  finding_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id        TEXT NOT NULL,
  label          TEXT NOT NULL,       -- secret | account_number | email | phone | person | address | date | url(与 ISS-005 PrivacyLabel::as_str() 对齐)
  offset_bucket  INTEGER NOT NULL,    -- bit_width_bucket(offset):offset 的位宽(MSB 1-based)
  placeholder    TEXT NOT NULL,       -- 由 audit 内部派生 `[{REDACTED|BLOCKED|ALLOWED_ONCE} <label>]`;caller 不传
  fingerprint    TEXT NOT NULL,       -- sha256(原 span 文本)[..16] hex-lower(32 字符),用于跨 scan 溯源但不泄漏原文
  action_taken   TEXT NOT NULL,       -- redacted | blocked | allowed_once
  FOREIGN KEY (scan_id) REFERENCES redaction_scans(scan_id)
);
CREATE INDEX IF NOT EXISTS idx_redaction_findings_scan  ON redaction_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_redaction_findings_label ON redaction_findings(label);
