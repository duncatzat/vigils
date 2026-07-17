<script setup lang="ts">
/**
 * I08b-α5 Session Replay 页面(方案 §9 / ADR 0002 hash chain)。
 *
 * 布局:
 *   左:session 列表(risk_score 排序 + 过滤)
 *   右:选中 session 的完整事件流(时间顺序 + 每条 payload 可展开)+ chain verify badge
 *
 * 安全契约:
 * - replay events payload 走 `<pre>{{ JSON.stringify }}`(Vue 插值转义 XSS)
 * - ChainVerifyReport.message 经后端脱敏,可直接插值
 * - **hash chain 是 ledger 级语义**:UI 明示 "ledger-wide chain verify"
 *
 * 不做:
 * - verify_chain 失败后的自动修复(设计上 ledger 不变,仅提示 `chain_broken_at`)
 * - 多 session 对比(仅单 session 重放 MVP)
 */
import { computed, h, onMounted, ref } from "vue";
import {
  NButton,
  NInput,
  NTag,
  NTimeline,
  NTimelineItem,
  NDataTable,
  NEmpty,
  NCheckbox,
  NDescriptions,
  NDescriptionsItem,
  type DataTableColumns,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { useSessionsStore } from "@/stores/sessions";
import { persistedRef, clearPersistedFilters } from "@/utils/persistedRef";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";
import {
  exportSessionReplay,
  type EventDetail,
  type ExportFormat,
  type SessionView,
} from "@/api/ipc";
import WindowCard from "@/components/WindowCard.vue";
import StatusPill from "@/components/StatusPill.vue";
import { EMBLEM } from "@/brand";

const { t, locale } = useI18n();
const store = useSessionsStore();

// ─────────────────────────── UI state ───────────────────────────

// v0.14 Theme F:filter 持久化(reload 后恢复)
const sourceFilter = persistedRef<string>("sessions:sourceFilter", "");
const verifyOnReplay = ref<boolean>(true);

/** v0.14 Theme F:reset source filter + 重新拉列表 */
function resetSessionFilters(): void {
  sourceFilter.value = "";
  clearPersistedFilters(["sessions:sourceFilter"]);
  store.refreshList({ source: null, limit: 100 });
}

// 展开的事件 id(同时只展开一条,减少 DOM 压力)
const expandedEventId = ref<number | null>(null);

// ─────────────────────────── ISS-018 Safe Export 状态 ───────────────────────────

const exportingFormat = ref<ExportFormat | null>(null);
const exportError = ref<string | null>(null);

/** ISS-018 — 把 SessionExportDto 触发浏览器下载。
 *  Tauri 进程不直接写文件(避免提权 FS write);走 Blob + `<a download>`,
 *  保留浏览器原生 OS 保存对话框。 */
async function safeExport(format: ExportFormat) {
  if (!store.selectedSessionId) return;
  exportingFormat.value = format;
  exportError.value = null;
  try {
    const dto = await exportSessionReplay({
      session_id: store.selectedSessionId,
      format,
    });
    const blob = new Blob([dto.content], {
      type: format === "md" ? "text/markdown;charset=utf-8" : "text/html;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement("a");
      // 文件名同时含 session 与时戳,便于用户区分多次导出
      a.href = url;
      a.download = `vigil-${dto.session_id}-${dto.generated_at}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } finally {
      URL.revokeObjectURL(url);
    }
  } catch (e) {
    exportError.value = String(e);
  } finally {
    exportingFormat.value = null;
  }
}

// ─────────────────── v0.15 Theme G:real-time 列表刷新(替代 5s poll)───────────────────
// 新 session 的首条 event 即 event-backed → ledger-events-changed listener 刷列表。
// replay 加载中不刷(避免列表抖动);Tauri event 不可用降级 setInterval。
// 注(spike § 3.2.1):零事件 session 在首 event 前不会触发刷新,可接受(无重放价值)。
useLedgerLiveUpdates({
  onChange: () => {
    if (!store.replayLoading) {
      store.refreshList({ source: sourceFilter.value || null, limit: 100 });
    }
  },
});

onMounted(() => {
  store.refreshList({ source: sourceFilter.value || null, limit: 100 });
});

// ─────────────────────────── Handlers ───────────────────────────

async function onPickSession(s: SessionView): Promise<void> {
  expandedEventId.value = null;
  await store.loadReplay({ session_id: s.session_id, verify: verifyOnReplay.value });
}

function onSourceFilterBlur(): void {
  store.refreshList({ source: sourceFilter.value || null, limit: 100 });
}

function toggleEvent(ev: EventDetail): void {
  expandedEventId.value = expandedEventId.value === ev.event_id ? null : ev.event_id;
}

function payloadPretty(ev: EventDetail): string {
  if (ev.payload === null || ev.payload === undefined) return "";
  try {
    return JSON.stringify(ev.payload, null, 2);
  } catch {
    return String(ev.payload);
  }
}

// ─────────────────────────── Formatters ───────────────────────────

function fmtTs(ts: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString(locale.value === "zh-CN" ? "zh-CN" : "en-US");
}

function riskTagType(score: number): "default" | "warning" | "error" {
  if (score >= 70) return "error";
  if (score >= 30) return "warning";
  return "default";
}

// ─────────────────────────── Session table ───────────────────────────

// computed:列标题随 locale 切换(与 ServerRegistry 同模式;此前硬编码英文 = zh 页表头漏翻)。
const sessionsColumns = computed<DataTableColumns<SessionView>>(() => [
  {
    title: t("session.col_session"),
    key: "session_id",
    render: (row) => h("code", { class: "text-xs font-mono" }, row.session_id),
  },
  {
    title: t("session.col_source"),
    key: "source",
    render: (row) => h(NTag, { size: "small" }, { default: () => row.source }),
  },
  {
    title: t("session.col_app"),
    key: "app_name",
    render: (row) => row.app_name ?? "—",
  },
  {
    title: t("session.col_started"),
    key: "started_at",
    render: (row) => fmtTs(row.started_at),
  },
  {
    title: t("session.col_ended"),
    key: "ended_at",
    // ended_at 缺失 ≠ 会话存活 —— 没有心跳无从判定,一周前的死会话曾被标 "live"(审计
    // 页面的事实性错误)。中性灰 tag 如实展示「未记录」。
    render: (row) =>
      row.ended_at
        ? fmtTs(row.ended_at)
        : h(NTag, { size: "tiny" }, { default: () => t("session.no_end_record") }),
  },
  {
    title: t("session.col_risk"),
    key: "risk_score",
    render: (row) =>
      h(NTag, { size: "small", type: riskTagType(row.risk_score) }, { default: () => String(row.risk_score) }),
  },
  {
    title: t("session.col_action"),
    key: "__actions",
    render: (row) =>
      h(
        NButton,
        {
          size: "tiny",
          type: "primary",
          "data-testid": `replay-${row.session_id}`,
          loading: store.replayLoading && store.selectedSessionId === row.session_id,
          onClick: () => onPickSession(row),
        },
        { default: () => t("session.replay_button") },
      ),
  },
]);

// ─────────────────────────── Chain verify badge ───────────────────────────

/**
 * Chain verify badge 文案计算。
 *
 * R1 MUST-FIX(Codex):**所有状态都必须明示 "ledger-wide"** —— 不能仅在 OK 分支
 * 出现 "ledger-wide"、broken 分支只显示 `chain_broken_at=N`。否则用户会误读为
 * "本 session 子链坏"而不是"整个 ledger 全局链坏"。
 */
const chainBadge = computed<{
  text: string;
  type: "success" | "error" | "default";
  detail: string;
}>(() => {
  const v = store.replay?.chain_verified;
  if (!v) {
    return {
      text: t("session.badge_not_verified"),
      type: "default",
      detail: t("session.badge_not_verified_detail"),
    };
  }
  if (v.ok) {
    return {
      text: t("session.badge_chain_ok"),
      type: "success",
      detail: t("session.badge_chain_ok_detail"),
    };
  }
  const reason = v.message ?? t("session.chain_verify_failed");
  return {
    text: t("session.badge_chain_broken"),
    type: "error",
    detail: t("session.badge_chain_broken_detail", { reason }),
  };
});

async function onStandaloneVerify(): Promise<void> {
  await store.runStandaloneVerify();
}

// ─────────────────── 展示辅助:badge.type → StatusPill tone(纯样式映射)───────────────────
const chainPillTone = computed<"green" | "red" | "cyan">(() =>
  chainBadge.value.type === "success" ? "green" : chainBadge.value.type === "error" ? "red" : "cyan",
);

/** event_type → 语义色类(deny=红 / redact=青 / allow=绿 / 其它=中性),对齐 Protection feed。 */
function eventTone(eventType: string): "deny" | "redact" | "allow" | "info" {
  const x = (eventType ?? "").toLowerCase();
  if (x.includes("deny") || x.includes("block")) return "deny";
  if (x.includes("redact")) return "redact";
  if (x.includes("approv") || x.includes("allow") || x.includes("mint")) return "allow";
  return "info";
}
</script>

<template>
  <div class="replay">
    <!-- 顶部细条:emblem + 页名 + 全局 chain 状态 + verify/refresh -->
    <div class="rhead">
      <span class="rtitle">
        <img class="emblem" :src="EMBLEM('replay')" alt="" width="18" height="18" />
        {{ t("session.page_title") }}
        <span class="rcount">{{ t("session.count", { n: store.sessions.length }) }}</span>
      </span>
      <span class="rright">
        <NButton
          :loading="store.verifyLoading"
          size="small"
          quaternary
          data-testid="verify-chain-standalone"
          @click="onStandaloneVerify"
        >
          {{ t("session.verify_chain_button") }}
        </NButton>
        <NButton
          :loading="store.listLoading"
          size="small"
          quaternary
          data-testid="refresh-sessions"
          @click="store.refreshList({ source: sourceFilter || null, limit: 100 })"
        >
          {{ t("common.refresh") }}
        </NButton>
      </span>
    </div>

    <!-- IPC 错误(设计化条,不裸露 TypeError)-->
    <div v-if="store.error" class="errcard" data-testid="ipc-error-banner">
      <span class="ei">⚠</span>
      <div class="ec">
        <div class="et">{{ t("common.ipc_error") }}</div>
        <div class="ed">{{ store.error }}</div>
      </div>
      <NButton size="small" quaternary @click="store.error = null">{{ t("common.close") }}</NButton>
    </div>

    <!-- standalone verify 结果(按钮触发时展示)-->
    <div
      v-if="store.standaloneVerify"
      class="verifycard"
      :class="store.standaloneVerify.ok ? 'ok' : 'bad'"
    >
      <StatusPill :tone="store.standaloneVerify.ok ? 'green' : 'red'">
        {{ store.standaloneVerify.ok ? t("session.chain_ok") : t("session.chain_broken") }}
      </StatusPill>
      <div v-if="!store.standaloneVerify.ok" class="vbody">
        <div>{{ store.standaloneVerify.message ?? t("session.chain_verify_failed") }}</div>
        <div v-if="store.standaloneVerify.broken_at_event_id" class="vmono">
          {{ t("session.first_broken_event", { id: store.standaloneVerify.broken_at_event_id }) }}
        </div>
      </div>
      <NButton class="vclose" size="small" quaternary @click="store.standaloneVerify = null">
        {{ t("common.close") }}
      </NButton>
    </div>

    <!-- 过滤 + verify 开关 -->
    <WindowCard title="filter · sessions" class="block">
      <div class="filterbar">
        <NInput
          v-model:value="sourceFilter"
          :placeholder="t('session.source_filter_placeholder')"
          clearable
          style="width: 320px;"
          data-testid="source-filter"
          @blur="onSourceFilterBlur"
        />
        <NCheckbox v-model:checked="verifyOnReplay" data-testid="verify-on-replay">
          {{ t("session.verify_on_replay") }}
        </NCheckbox>
        <!-- v0.14 Theme F:显式 reset(只显示在有 filter 时,减少视觉噪声)-->
        <NButton
          v-if="sourceFilter"
          size="small"
          quaternary
          data-testid="reset-session-filters"
          @click="resetSessionFilters"
        >
          {{ t("session.reset_filters") }}
        </NButton>
      </div>
    </WindowCard>

    <!-- Sessions 列表 -->
    <WindowCard :title="t('session.sessions_card_title')" class="block">
      <div class="nu-table">
        <NDataTable
          :columns="sessionsColumns"
          :data="store.sessions"
          :bordered="false"
          :pagination="{ pageSize: 15 }"
          data-testid="sessions-table"
        >
          <template #empty>
            <NEmpty :show-icon="false" :description="t('session.empty_no_sessions')" data-testid="sessions-empty">
              <template #extra>
                <div class="empty-extra">
                  {{ t("session.empty_sessions_extra") }}
                </div>
              </template>
            </NEmpty>
          </template>
        </NDataTable>
      </div>
    </WindowCard>

    <!-- Replay 结果 -->
    <WindowCard
      v-if="store.selectedSessionId || store.replayLoading"
      title="replay · timeline"
      class="block"
    >
      <template #chrome-right>
        <div class="export-row">
          <!-- ISS-018 Safe Export buttons:payload 已脱敏 + Blob download(无 FS write 提权) -->
          <NButton
            size="tiny"
            quaternary
            :loading="exportingFormat === 'md'"
            :disabled="exportingFormat !== null"
            data-testid="safe-export-md"
            :title="t('session.export_md')"
            @click="safeExport('md')"
          >
            {{ t("session.export_md") }}
          </NButton>
          <NButton
            size="tiny"
            quaternary
            :loading="exportingFormat === 'html'"
            :disabled="exportingFormat !== null"
            data-testid="safe-export-html"
            :title="t('session.export_html')"
            @click="safeExport('html')"
          >
            {{ t("session.export_html") }}
          </NButton>
          <NButton size="tiny" quaternary @click="store.clearReplay()">{{ t("common.close") }}</NButton>
        </div>
      </template>

      <!-- replay 头:session_id(mono)+ ledger-wide chain pill + 明细 -->
      <div class="replay-head">
        <span class="rh-id">replay: <code class="mono">{{ store.selectedSessionId }}</code></span>
        <StatusPill :tone="chainPillTone" data-testid="chain-badge">{{ chainBadge.text }}</StatusPill>
        <span class="rh-detail">{{ chainBadge.detail }}</span>
      </div>

      <div v-if="exportError" class="errline" data-testid="export-error-line">
        ⚠ {{ t("session.export_error", { msg: exportError }) }}
        <NButton size="tiny" quaternary @click="exportError = null">{{ t("common.close") }}</NButton>
      </div>

      <div v-if="store.replayLoading" class="loading">{{ t("session.replay_loading") }}</div>
      <div
        v-else-if="!store.replay || store.replay.events.length === 0"
        class="empty"
      >
        {{ t("session.replay_no_events") }}
      </div>
      <template v-else>
        <!-- ledger-wide chain 摘要(mono 仪表行)-->
        <div class="nu-desc">
          <NDescriptions label-placement="left" :column="3" size="small">
            <NDescriptionsItem :label="t('session.desc_event_count')">
              {{ store.replay.event_count }}
            </NDescriptionsItem>
            <NDescriptionsItem :label="t('session.desc_chain')">
              <!-- R1 MUST-FIX:broken 态文案也明示 "ledger-wide",避免被读作本 session 子链 -->
              <template v-if="!store.replay.chain_verified">
                <span class="chain-na">— (verify=false, ledger chain not checked)</span>
              </template>
              <template v-else-if="store.replay.chain_verified.ok">
                <span class="chain-ok">ledger-wide OK</span>
              </template>
              <template v-else>
                <span class="chain-bad">ledger-wide BROKEN</span>
              </template>
            </NDescriptionsItem>
            <NDescriptionsItem
              v-if="store.replay.chain_verified?.broken_at_event_id"
              :label="t('session.desc_broken_at')"
            >
              <span class="mono">event_id = {{ store.replay.chain_verified.broken_at_event_id }}</span>
            </NDescriptionsItem>
          </NDescriptions>
        </div>

        <!-- 链节点时间线:每节点 event_type 语义色 + mono hash + 青色辉光链点 -->
        <div class="nu-timeline">
          <NTimeline>
            <NTimelineItem
              v-for="ev in store.replay.events"
              :key="ev.event_id"
              :type="eventTone(ev.event_type) === 'deny'
                ? 'error'
                : eventTone(ev.event_type) === 'allow'
                  ? 'success'
                  : eventTone(ev.event_type) === 'redact'
                    ? 'info'
                    : 'default'"
              :time="fmtTs(ev.created_at)"
              data-testid="replay-event"
            >
              <template #header>
                <span class="ev-type" :class="eventTone(ev.event_type)">{{ ev.event_type }}</span>
              </template>
              <div class="ev-body">
                <div class="ev-meta">
                  <span class="mono">event_id={{ ev.event_id }}</span>
                  <span class="ev-dot">·</span>
                  <span class="mono break">event_hash={{ ev.event_hash.slice(0, 12) }}…</span>
                </div>
                <div
                  v-if="ev.redacted_text"
                  class="ev-text"
                >
                  {{ ev.redacted_text }}
                </div>
                <NButton
                  size="tiny"
                  text
                  class="ev-toggle"
                  :data-testid="`toggle-${ev.event_id}`"
                  @click="toggleEvent(ev)"
                >
                  {{ expandedEventId === ev.event_id ? t("session.hide_payload") : t("session.show_payload") }}
                </NButton>
                <div v-if="expandedEventId === ev.event_id" class="ev-payload">
                  <div class="ev-prev">
                    prev_hash: <code class="break">{{ ev.prev_hash }}</code>
                  </div>
                  <pre
                    class="payload-pre"
                    :data-testid="`payload-${ev.event_id}`"
                  >{{ payloadPretty(ev) }}</pre>
                </div>
              </div>
            </NTimelineItem>
          </NTimeline>
        </div>
      </template>
    </WindowCard>
  </div>
</template>

<style scoped>
.replay {
  max-width: 1080px;
  margin: 0 auto;
  padding: 18px 28px 40px;
}

/* ── 顶部细条 ── */
.rhead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}
.rtitle {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  font-family: var(--vigil-mono);
  font-size: 13px;
  letter-spacing: 1px;
  color: var(--vigil-text-secondary);
}
.rtitle .emblem {
  display: block;
  filter: drop-shadow(0 0 5px rgba(45, 212, 191, 0.55));
}
.rcount {
  font-size: 11px;
  letter-spacing: 0.5px;
  color: var(--vigil-text-muted);
}
.rright {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.block {
  margin-top: 14px;
}

/* ── 错误条(设计化)── */
.errcard {
  margin-top: 14px;
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 13px 16px;
  border: 1px solid rgba(255, 42, 109, 0.3);
  border-radius: 12px;
  background: rgba(255, 42, 109, 0.05);
}
.errcard .ei {
  font-size: 17px;
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

/* ── standalone verify 结果卡 ── */
.verifycard {
  margin-top: 14px;
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 13px 16px;
  border-radius: 12px;
  border: 1px solid;
}
.verifycard.ok {
  border-color: rgba(0, 255, 157, 0.28);
  background: rgba(0, 255, 157, 0.05);
}
.verifycard.bad {
  border-color: rgba(255, 42, 109, 0.3);
  background: rgba(255, 42, 109, 0.05);
}
.verifycard .vbody {
  flex: 1;
  font-size: 13px;
  color: var(--vigil-text);
}
.verifycard .vmono {
  margin-top: 4px;
  font-family: var(--vigil-mono);
  font-size: 11px;
  color: var(--vigil-text-muted);
  word-break: break-all;
}
.verifycard .vclose {
  margin-left: auto;
}

/* ── 过滤栏 ── */
.filterbar {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
}

/* ── 空态 ── */
.empty-extra {
  margin-top: 6px;
  font-family: var(--vigil-mono);
  font-size: 11px;
  text-align: center;
  color: var(--vigil-text-muted);
}
.empty {
  padding: 18px 2px;
  font-size: 13px;
  text-align: center;
  color: var(--vigil-text-secondary);
}
.loading {
  padding: 18px 2px;
  font-family: var(--vigil-mono);
  font-size: 12.5px;
  color: var(--vigil-text-secondary);
}

/* ── replay 头 ── */
.replay-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  padding-bottom: 12px;
  margin-bottom: 4px;
  border-bottom: 1px solid rgba(35, 40, 55, 0.6);
}
.rh-id {
  font-size: 13px;
  color: var(--vigil-text);
}
.rh-detail {
  font-family: var(--vigil-mono);
  font-size: 11px;
  color: var(--vigil-text-muted);
}

.export-row {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

/* ── export 错误行 ── */
.errline {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 10px 0 4px;
  font-size: 12.5px;
  color: var(--vigil-red);
}

/* ── mono 工具类 ── */
.mono {
  font-family: var(--vigil-mono);
}
.break {
  word-break: break-all;
}

/* ── ledger-wide chain 摘要色 ── */
.chain-ok {
  color: var(--vigil-green);
  font-family: var(--vigil-mono);
}
.chain-bad {
  color: var(--vigil-red);
  font-family: var(--vigil-mono);
}
.chain-na {
  color: var(--vigil-text-muted);
  font-family: var(--vigil-mono);
}

/* ── timeline 节点 ── */
.ev-type {
  font-family: var(--vigil-mono);
  font-size: 12.5px;
  font-weight: 700;
  letter-spacing: 0.3px;
}
.ev-type.deny {
  color: var(--vigil-red);
}
.ev-type.redact {
  color: var(--vigil-accent);
}
.ev-type.allow {
  color: var(--vigil-green);
}
.ev-type.info {
  color: var(--vigil-text-secondary);
}
.ev-body {
  font-size: 13px;
}
.ev-meta {
  font-family: var(--vigil-mono);
  font-size: 11.5px;
  color: var(--vigil-text-muted);
}
.ev-dot {
  margin: 0 8px;
}
.ev-text {
  margin-top: 5px;
  color: var(--vigil-text);
  white-space: pre-wrap;
  word-break: break-all;
}
.ev-toggle {
  margin-top: 5px;
}
.ev-payload {
  margin-top: 9px;
}
.ev-prev {
  font-family: var(--vigil-mono);
  font-size: 11px;
  color: var(--vigil-text-muted);
  margin-bottom: 5px;
}
.payload-pre {
  margin: 0;
  font-family: var(--vigil-mono);
  font-size: 11.5px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 20rem;
  overflow: auto;
  padding: 12px;
  border-radius: 10px;
  border: 1px solid var(--vigil-border);
  background: var(--vigil-bg);
  color: var(--vigil-text);
}

/* ─────────── naive-ui 容器深色收敛(只重皮,不改功能)─────────── */

/* DataTable → 透明 + 品牌色头/行/分页 */
.nu-table :deep(.n-data-table) {
  --n-th-color: transparent;
  --n-td-color: transparent;
  --n-merged-th-color: transparent;
  --n-merged-td-color: transparent;
  background: transparent;
  font-size: 13px;
}
.nu-table :deep(.n-data-table-th) {
  background: rgba(13, 15, 22, 0.7);
  color: var(--vigil-text-secondary);
  font-family: var(--vigil-mono);
  font-size: 10.5px;
  letter-spacing: 0.6px;
  text-transform: uppercase;
  border-color: var(--vigil-border);
}
.nu-table :deep(.n-data-table-td) {
  color: var(--vigil-text);
  border-color: rgba(35, 40, 55, 0.55);
}
.nu-table :deep(.n-data-table-tr:hover .n-data-table-td) {
  background: rgba(5, 217, 232, 0.05);
}
.nu-table :deep(.n-data-table code) {
  font-family: var(--vigil-mono);
  color: var(--vigil-accent-light);
}

/* Descriptions → mono 仪表行 */
.nu-desc {
  margin-bottom: 4px;
}
.nu-desc :deep(.n-descriptions-table-header),
.nu-desc :deep(.n-descriptions-table-content) {
  background: transparent;
}
.nu-desc :deep(.n-descriptions-table-header) {
  font-family: var(--vigil-mono);
  font-size: 11px;
  color: var(--vigil-text-secondary);
}
.nu-desc :deep(.n-descriptions-table-content) {
  color: var(--vigil-text);
}

/* Timeline → 链节点青色辉光 */
.nu-timeline :deep(.n-timeline-item-timeline__line) {
  background: linear-gradient(
    to bottom,
    rgba(5, 217, 232, 0.45),
    rgba(35, 40, 55, 0.7)
  );
}
.nu-timeline :deep(.n-timeline-item-timeline__circle) {
  box-shadow: 0 0 9px -1px rgba(5, 217, 232, 0.65);
}
.nu-timeline :deep(.n-timeline-item-content__time) {
  font-family: var(--vigil-mono);
  font-size: 10.5px;
  color: var(--vigil-text-muted);
}
</style>
