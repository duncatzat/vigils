<script setup lang="ts">
/**
 * Protection Overview —— 桌面 GUI 的"Vigil 拦下了什么"防护成效旗舰页(R2 Aegis 指挥舱)。
 *
 * = CLI `vigil-hub inspect protection` 的 GUI 等价物。只读 `protection_summary()` +
 * `guardian_status()`;**fail-closed**:`chain_intact=false`(账本篡改)时 Rust 端强制
 * `recent=[]`(绝不回显可能被注入 secret 的明细),计数仍保留。
 *
 * 安全契约:所有 text 经 `{{ }}` 插值(含 redacted_text);i18n 仅纯 `{named}`(CSP-safe)。
 * 错误态**设计化**(不裸露 TypeError 当首屏),浏览器预览无 Tauri 后端时降级为干净空态。
 */
import { computed, onMounted, ref } from "vue";
import { NButton } from "naive-ui";
import { useI18n } from "vue-i18n";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";
import {
  protectionSummary,
  type ProtectionSummary,
  guardianStatus,
  deployGuardian,
  type GuardianStatus,
  enginePresent,
  downloadMlEngine,
  browserGuardStatus,
  type BrowserGuardStatus,
} from "@/api/ipc";
import OrbitalDefense from "@/components/OrbitalDefense.vue";
import WindowCard from "@/components/WindowCard.vue";
import StatusPill from "@/components/StatusPill.vue";

const { t } = useI18n();
const summary = ref<ProtectionSummary | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);

const guardian = ref<GuardianStatus | null>(null);
const guardianError = ref<string | null>(null);
const deploying = ref(false);

// ③ 缺失引擎:检测 + 安全自动下载
const engineMissing = ref(false);
const downloadingEngine = ref(false);
const engineError = ref<string | null>(null);

// 浏览器防线卡(扩展体系 Phase 2「策略+观测」):native host 注册态 + 24h 守门统计。
const browserGuard = ref<BrowserGuardStatus | null>(null);
const browserGuardError = ref<string | null>(null);

async function loadBrowserGuard(): Promise<void> {
  browserGuardError.value = null;
  try {
    browserGuard.value = await browserGuardStatus();
  } catch (e) {
    browserGuardError.value = String(e);
  }
}

async function refresh(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    summary.value = await protectionSummary();
  } catch (e) {
    error.value = String(e);
  } finally {
    loading.value = false;
  }
}

async function loadGuardian(): Promise<void> {
  guardianError.value = null;
  try {
    guardian.value = await guardianStatus();
  } catch (e) {
    guardianError.value = String(e);
  }
}

async function doDeploy(): Promise<void> {
  deploying.value = true;
  guardianError.value = null;
  try {
    guardian.value = await deployGuardian();
    await refresh();
  } catch (e) {
    guardianError.value = String(e);
  } finally {
    deploying.value = false;
  }
}

// 受保护 = 守卫真生效 且 审计链完整(任一不满足都不该亮绿)。
const isProtected = computed(
  () => (guardian.value?.protected ?? false) && (summary.value?.chain_intact ?? true),
);

// 防御环"激活"层:由真账本信号点亮(刚发生防护动作的层)。
const activeKeys = computed<string[]>(() => {
  const s = summary.value;
  if (!s) return [];
  const keys: string[] = [];
  if (s.raw_secrets_blocked > 0) keys.push("firewall");
  if (s.tool_result_leaks_detected > 0) keys.push("lock");
  if (s.secret_aliases_unresolved > 0) keys.push("approval");
  if (s.total_events_audited > 0) keys.push("audit");
  return keys;
});

const guardedAgents = computed(() =>
  (guardian.value?.agents ?? [])
    .filter((a) => a.status === "active")
    .map((a) => a.display_name),
);

// codex trust 诚实化:任一已检测 agent 处于 pending_trust(配置在位但 codex 侧未信任,
// hook 不会执行)→ 卡片尾部显示一次性 /hooks 授权引导。
const hasPendingTrust = computed(() =>
  (guardian.value?.agents ?? []).some((a) => a.detected && a.status === "pending_trust"),
);

const heroSubtitle = computed(() =>
  guardedAgents.value.length > 0
    ? t("protection.hero.subtitle", { agents: guardedAgents.value.join(" · ") })
    : t("protection.hero.subtitle_none"),
);

// hero 标题随保护状态切换:未保护时「你的 AI 正在被守护」与页内一排「未保护」徽章直接
// 矛盾(安全产品的陈述必须由真实状态驱动)——改祈使句(让你的 AI 被 守护),高亮词不变。
const heroTitlePre = computed(() =>
  isProtected.value ? t("protection.hero.title_pre") : t("protection.hero.title_pre_unprotected"),
);

// guardian 后端错误映射:已知 ENGINE_NOT_FOUND 是英文技术文案(面向打包者),对用户
// 显示本地化自救指引;未知错误原样透传(已在后端脱敏)。
const guardianErrorDisplay = computed(() => {
  const e = guardianError.value ?? "";
  if (e.includes("vigil-hub engine not found")) return t("guardian.hub_missing");
  return e;
});

const metrics = computed(() => {
  const s = summary.value;
  return [
    { key: "secrets.blocked", n: s?.raw_secrets_blocked ?? 0, label: t("protection.secrets_blocked"), tone: "cyan" },
    { key: "leaks.detected", n: s?.tool_result_leaks_detected ?? 0, label: t("protection.leaks_detected"), tone: "white" },
    { key: "creds.withheld", n: s?.secret_aliases_unresolved ?? 0, label: t("protection.aliases_withheld"), tone: "green" },
    { key: "events.audited", n: s?.total_events_audited ?? 0, label: t("protection.events_audited"), tone: "cyan" },
  ];
});

function fmtTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleTimeString("zh-CN");
}

/** 事件类型 → 语义色(deny=红 / redact=青 / allow=绿 / 其它=中性)。 */
function eventTone(eventType: string): "deny" | "redact" | "allow" | "info" {
  const x = eventType.toLowerCase();
  if (x.includes("deny") || x.includes("block")) return "deny";
  if (x.includes("redact")) return "redact";
  if (x.includes("approv") || x.includes("allow") || x.includes("mint")) return "allow";
  return "info";
}

async function checkEngine(): Promise<void> {
  try {
    engineMissing.value = !(await enginePresent());
  } catch {
    // 检测失败保守不弹下载(避免误导);引擎真缺时 deploy 仍会给明确错误。
    engineMissing.value = false;
  }
}

// GUI-01(审核 ISS-20260702-018 关联):缺失卡走 download_ml_engine —— 签名清单驱动
// (minisign 验签 + per-platform SHA-pin),装的是完整 vigil-hub(ML 变体),默认配置下
// 真实可用。旧 download_engine 默认无 pinned SHA 必 fail-closed 报错(发布形态待
// reconcile,后端保留不动),用户最需要时点它 100% 失败,故前端入口切换。
async function doDownloadEngine(): Promise<void> {
  downloadingEngine.value = true;
  engineError.value = null;
  try {
    await downloadMlEngine();
    engineMissing.value = !(await enginePresent());
    await loadGuardian();
    await refresh();
  } catch (e) {
    engineError.value = String(e);
  } finally {
    downloadingEngine.value = false;
  }
}

// 浏览器守门事件也是 ledger 事件 —— live 更新时一并刷新 24h 统计。
useLedgerLiveUpdates({
  onChange: () => {
    refresh();
    loadBrowserGuard();
  },
});
onMounted(() => {
  refresh();
  loadGuardian();
  checkEngine();
  loadBrowserGuard();
});
</script>

<template>
  <div class="protect">
    <!-- 顶部细条:页名 + 全局状态 + 刷新 -->
    <div class="phead">
      <span class="ptitle">{{ t("protection.page_title") }}</span>
      <span class="pright">
        <StatusPill :tone="isProtected ? 'green' : 'yellow'">
          {{ isProtected ? t("protection.hero.guarding") : t("protection.hero.unprotected") }}
        </StatusPill>
        <NButton
          :loading="loading"
          size="small"
          quaternary
          data-testid="refresh-protection"
          @click="refresh()"
        >
          {{ t("common.refresh") }}
        </NButton>
      </span>
    </div>

    <!-- 八重纵深防御轨道 hero -->
    <OrbitalDefense :is-protected="isProtected" :active-keys="activeKeys" />

    <!-- 人话标题 -->
    <div class="headline">
      <h1>
        {{ heroTitlePre }}
        <span class="hl">{{ t("protection.hero.title_hl") }}</span>
      </h1>
      <p>{{ heroSubtitle }}</p>
    </div>

    <!-- ③ 引擎缺失:提醒 + 一键安全下载 -->
    <WindowCard
      v-if="engineMissing"
      title="engine · missing"
      class="block"
      data-testid="engine-missing-card"
    >
      <div class="grow">
        <div>
          <div class="g-title">⚠ {{ t("engine.missing_title") }}</div>
          <div class="g-sub">{{ t("engine.missing_body") }}</div>
        </div>
        <NButton
          type="primary"
          size="large"
          :loading="downloadingEngine"
          data-testid="download-engine"
          @click="doDownloadEngine()"
        >
          {{ downloadingEngine ? t("engine.downloading") : t("engine.download") }}
        </NButton>
      </div>
      <div v-if="engineError" class="errline">
        ⚠ {{ t("engine.download_failed") }} — {{ engineError }}
      </div>
    </WindowCard>

    <!-- 守卫部署卡 -->
    <WindowCard title="guardian · aegis" class="block" data-testid="guardian-card">
      <div class="grow">
        <div>
          <div class="g-title">{{ t("guardian.title") }}</div>
          <div class="g-sub">{{ t("guardian.subtitle") }}</div>
        </div>
        <NButton
          type="primary"
          size="large"
          :loading="deploying"
          data-testid="deploy-guardian"
          @click="doDeploy()"
        >
          {{ guardian && guardian.protected ? t("guardian.redeploy") : t("guardian.deploy") }}
        </NButton>
      </div>
      <div v-if="guardianError" class="errline">
        ⚠ {{ t("guardian.error_title") }} — {{ guardianErrorDisplay }}
      </div>
      <div v-if="guardian" class="agents" data-testid="guardian-agents">
        <div v-for="a in guardian.agents" :key="a.agent" class="agent-row">
          <span class="agent-name">{{ a.display_name }}</span>
          <span v-if="!a.detected" class="agent-dim">{{ t("guardian.not_detected") }}</span>
          <StatusPill v-else-if="a.status === 'active'" tone="green">{{ t("guardian.protected") }}</StatusPill>
          <StatusPill v-else-if="a.status === 'stale'" tone="yellow">{{ t("guardian.stale") }}</StatusPill>
          <StatusPill
            v-else-if="a.status === 'pending_trust'"
            tone="yellow"
            data-testid="agent-pending-trust"
            >{{ t("guardian.pending_trust") }}</StatusPill
          >
          <StatusPill v-else tone="red">{{ t("guardian.not_installed") }}</StatusPill>
        </div>
      </div>
      <!-- codex trust 引导:配置在位但 codex 未信任 = 防护未生效,如实引导一次性 /hooks 授权 -->
      <div v-if="hasPendingTrust" class="trust-hint" data-testid="guardian-pending-trust-hint">
        {{ t("guardian.pending_trust_hint") }}
      </div>
    </WindowCard>

    <!-- 浏览器防线卡(扩展体系 Phase 2「策略+观测」)-->
    <WindowCard title="browser · guard" class="block" data-testid="browser-guard-card">
      <div class="grow">
        <div>
          <div class="g-title">{{ t("browser_guard.title") }}</div>
          <div class="g-sub">{{ t("browser_guard.subtitle") }}</div>
        </div>
        <StatusPill
          v-if="browserGuard"
          :tone="browserGuard.registered ? 'green' : 'yellow'"
          data-testid="browser-guard-state"
        >
          {{ browserGuard.registered ? t("browser_guard.registered") : t("browser_guard.not_registered") }}
        </StatusPill>
      </div>
      <div v-if="browserGuard && !browserGuard.registered" class="g-sub bg-hint">
        {{ t("browser_guard.register_hint") }}
      </div>
      <div v-if="browserGuard" class="bg-stats" data-testid="browser-guard-stats">
        <span class="bg-stat"
          ><strong>{{ browserGuard.checks_24h }}</strong> {{ t("browser_guard.checks_24h") }}</span
        >
        <span class="bg-stat"
          ><strong class="bg-red">{{ browserGuard.blocked_24h }}</strong> {{ t("browser_guard.blocked_24h") }}</span
        >
        <span class="bg-stat"
          ><strong class="bg-cyan">{{ browserGuard.redacted_24h }}</strong> {{ t("browser_guard.redacted_24h") }}</span
        >
      </div>
      <div v-if="browserGuardError" class="errline">⚠ {{ browserGuardError }}</div>
    </WindowCard>

    <!-- 证据数字卡 -->
    <div class="metrics">
      <WindowCard v-for="m in metrics" :key="m.key" :title="m.key">
        <div class="metric">
          <div class="num" :class="`n-${m.tone}`">{{ m.n }}</div>
          <div class="mlabel"><span class="bk">[</span> {{ m.label }} <span class="bk">]</span></div>
        </div>
      </WindowCard>
    </div>

    <!-- 实时拦截 feed(链坏时 Rust 端已强制为空)-->
    <WindowCard :title="t('protection.hero.recent_title')" class="block">
      <template v-if="summary && summary.recent.length">
        <div
          v-for="ev in summary.recent"
          :key="ev.event_id"
          class="logline"
          data-testid="protection-event-item"
        >
          <span class="ts">{{ fmtTs(ev.created_at) }}</span>
          <span class="verb" :class="eventTone(ev.event_type)">{{ ev.event_type }}</span>
          <span class="desc">{{ ev.redacted_text || "—" }}</span>
        </div>
      </template>
      <div v-else class="empty" data-testid="protection-recent-empty">
        {{ summary && !summary.chain_intact
          ? t("protection.recent_suppressed")
          : t("protection.recent_empty") }}
      </div>
    </WindowCard>

    <!-- 错误态(设计化,不裸露 TypeError 当首屏)-->
    <div v-if="error" class="errcard" data-testid="protection-load-failed">
      <span class="ei">⚠</span>
      <div class="ec">
        <div class="et">{{ t("protection.loading_failed") }}</div>
        <div class="ed">{{ error }}</div>
      </div>
      <NButton size="small" @click="refresh()">{{ t("common.refresh") }}</NButton>
    </div>
  </div>
</template>

<style scoped>
.protect {
  max-width: 1080px;
  margin: 0 auto;
  padding: 18px 28px 40px;
}
.phead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 2px;
}
.ptitle {
  font-family: var(--vigil-mono);
  font-size: 13px;
  letter-spacing: 1px;
  color: var(--vigil-text-secondary);
}
.pright {
  display: inline-flex;
  align-items: center;
  gap: 12px;
}

.headline {
  text-align: center;
  margin: 2px 0 18px;
}
.headline h1 {
  font-size: 25px;
  font-weight: 700;
  letter-spacing: 0.3px;
  color: var(--vigil-text);
  margin: 0;
}
.headline h1 .hl {
  color: var(--vigil-accent);
}
.headline p {
  margin: 6px 0 0;
  font-family: var(--vigil-mono);
  font-size: 12.5px;
  color: var(--vigil-text-secondary);
}

.block {
  margin-top: 14px;
}
.grow {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.g-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--vigil-text);
}
.g-sub {
  margin-top: 3px;
  font-size: 12px;
  color: var(--vigil-text-secondary);
}
.errline {
  margin-top: 12px;
  font-size: 12.5px;
  color: var(--vigil-red);
}
.agents {
  margin-top: 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.agent-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 13.5px;
}
.agent-name {
  color: var(--vigil-text);
}
.agent-dim {
  font-family: var(--vigil-mono);
  font-size: 11px;
  color: var(--vigil-text-muted);
}
.trust-hint {
  margin-top: 10px;
  font-size: 12.5px;
  color: var(--vigil-text-muted);
}

/* 浏览器防线卡:24h 统计行 + 未注册指引 */
.bg-hint {
  margin-top: 10px;
}
.bg-stats {
  margin-top: 14px;
  display: flex;
  gap: 22px;
  font-size: 12.5px;
  color: var(--vigil-text-secondary);
}
.bg-stat strong {
  font-family: var(--vigil-mono);
  font-size: 16px;
  color: var(--vigil-text);
  margin-right: 4px;
}
.bg-stat strong.bg-red {
  color: var(--vigil-red);
}
.bg-stat strong.bg-cyan {
  color: var(--vigil-cyan);
}

.metrics {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
  margin-top: 14px;
}
.metric .num {
  font-family: var(--vigil-mono);
  font-size: 34px;
  font-weight: 800;
  line-height: 1;
  letter-spacing: -1px;
}
.metric .mlabel {
  margin-top: 8px;
  font-family: var(--vigil-mono);
  font-size: 11px;
  letter-spacing: 0.5px;
  color: var(--vigil-text-secondary);
}
.metric .mlabel .bk {
  color: var(--vigil-accent);
  opacity: 0.55;
}
.n-cyan {
  color: var(--vigil-accent);
}
.n-green {
  color: var(--vigil-green);
}
.n-white {
  color: var(--vigil-text);
}
.n-red {
  color: var(--vigil-red);
}

.logline {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 10px 2px;
  font-family: var(--vigil-mono);
  font-size: 12.5px;
  border-bottom: 1px solid rgba(35, 40, 55, 0.6);
}
.logline:last-child {
  border-bottom: 0;
}
.logline .ts {
  color: var(--vigil-text-muted);
  flex: 0 0 auto;
}
.logline .verb {
  font-weight: 700;
  min-width: 150px;
  flex: 0 0 auto;
}
.logline .verb.deny {
  color: var(--vigil-red);
}
.logline .verb.redact {
  color: var(--vigil-accent);
}
.logline .verb.allow {
  color: var(--vigil-green);
}
.logline .verb.info {
  color: var(--vigil-text-secondary);
}
.logline .desc {
  color: var(--vigil-text);
  white-space: pre-wrap;
  word-break: break-all;
}
.empty {
  padding: 14px 2px;
  font-size: 13px;
  color: var(--vigil-text-secondary);
}

.errcard {
  margin-top: 14px;
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px 16px;
  border: 1px solid rgba(255, 42, 109, 0.3);
  border-radius: 12px;
  background: rgba(255, 42, 109, 0.05);
}
.errcard .ei {
  font-size: 18px;
}
.errcard .ec {
  flex: 1;
}
.errcard .et {
  font-size: 13.5px;
  color: var(--vigil-text);
}
.errcard .ed {
  margin-top: 3px;
  font-family: var(--vigil-mono);
  font-size: 11px;
  color: var(--vigil-text-muted);
  word-break: break-all;
}
</style>
