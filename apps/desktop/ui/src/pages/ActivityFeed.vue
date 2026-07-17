<script setup lang="ts">
/**
 * I08b-α3 Activity Feed 页面(方案 §9.4 / §14 "看见 agent 做了什么")。
 *
 * - 最近事件流(mono log-line feed —— 品牌签名审计流)
 * - session / event_type 多选筛选
 * - FTS 搜索切换(searchActive 时显示 hits,否则显示 feed)
 * - 5s polling(tab hidden 暂停,复用 α2 pattern)
 * - 点击 item → 弹 EventDetailModal
 *
 * 安全契约:所有 text 经 `{{ }}` 插值,payload 走 EventDetailModal 的 `<pre>{{ }}`。
 */
import { computed, onMounted, ref } from "vue";
import {
  NButton,
  NInput,
  NSelect,
  NAlert,
  type SelectOption,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { useEventsStore } from "@/stores/events";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";
import type { EventSummary } from "@/api/ipc";
import EventDetailModal from "@/components/EventDetailModal.vue";
import WindowCard from "@/components/WindowCard.vue";
import StatusPill from "@/components/StatusPill.vue";
import { EMBLEM } from "@/brand";

const { t } = useI18n();
const store = useEventsStore();
const modalOpen = ref(false);

// ─────────────────────── v0.15 Theme G:real-time(替代 5s poll)───────────────────────
// events 表写入即 event-backed → ledger-events-changed listener。搜索模式不刷 feed
// (searchActive 时跳过,延续原 poll 守门);Tauri event 不可用降级 setInterval。
useLedgerLiveUpdates({
  onChange: () => {
    if (!store.searchActive) store.refresh();
  },
});

onMounted(() => {
  store.refresh();
});

// ─────────────────────── Filter options ───────────────────────

/**
 * R1 BLOCKER 修复 + R2 MUST-FIX 修复:白名单严格对齐 workspace Rust 真实
 * `append_event(...)` 写入点的字面量(grep 确认存在且有实际写入处)。来源:
 * - `crates/vigil-audit/src/span.rs`:tool_call.{opened,decided,executed,execute_failed,abandoned}
 * - `crates/vigil-audit/src/approvals.rs`:decision.recorded / approval.{created,resolved,note}
 *   / lease.{minted,revoked}
 * - `crates/vigil-audit/src/registry.rs`:tool_approval.{first_approved,re_approved,drift_rejected}
 *   / server.{command_re_approved,command_drift_rejected}
 * - `crates/vigil-mcp/src/hub.rs`:server.command_drifted
 *
 * **R2 移除**:`runner.rejected` / `runner.killed_by_timeout` / `runner.io_error`
 * 在 workspace 仅作为 `vigil-runner` 错误注释/plan 注释存在,未找到实际
 * `append_event("runner.*")` 写入点。若未来 Hub 接入 runner 事件写入,再补回
 * 这三条(同步本文件 + typeTagType errorExact)。
 *
 * 用户可能有自定义类型(session 里 `append_event` 传任意字符串);UI 筛选仅列常用。
 */
const EVENT_TYPE_OPTIONS: SelectOption[] = [
  // tool_call.* (vigil-audit/src/span.rs)
  { label: "tool_call.opened", value: "tool_call.opened" },
  { label: "tool_call.decided", value: "tool_call.decided" },
  { label: "tool_call.executed", value: "tool_call.executed" },
  { label: "tool_call.execute_failed", value: "tool_call.execute_failed" },
  { label: "tool_call.abandoned", value: "tool_call.abandoned" },
  // decision / approval / lease (vigil-audit/src/approvals.rs)
  { label: "decision.recorded", value: "decision.recorded" },
  { label: "approval.created", value: "approval.created" },
  { label: "approval.resolved", value: "approval.resolved" },
  { label: "approval.note", value: "approval.note" },
  { label: "lease.minted", value: "lease.minted" },
  { label: "lease.revoked", value: "lease.revoked" },
  // tool_approval / server (vigil-audit/src/registry.rs + vigil-mcp/src/hub.rs)
  { label: "tool_approval.first_approved", value: "tool_approval.first_approved" },
  { label: "tool_approval.re_approved", value: "tool_approval.re_approved" },
  { label: "tool_approval.drift_rejected", value: "tool_approval.drift_rejected" },
  { label: "server.command_drifted", value: "server.command_drifted" },
  { label: "server.command_re_approved", value: "server.command_re_approved" },
  { label: "server.command_drift_rejected", value: "server.command_drift_rejected" },
  // browser.* (crates/vigil-browser/src/audit.rs EVENT_PASTE/INPUT/SUBMIT,
  // 写入点 = apps/native-host handle_one;Phase 2「策略+观测」收编浏览器防线事件)
  { label: "browser.paste_checked", value: "browser.paste_checked" },
  { label: "browser.input_checked", value: "browser.input_checked" },
  { label: "browser.submit_checked", value: "browser.submit_checked" },
];

// ─────────────────────── Formatters ───────────────────────

function fmtTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}

/**
 * 事件类型 tag 颜色启发式。
 *
 * R1 MUST-FIX 2 修复 + R2 移除 runner.*:扩展 error 类型命中清单 —— 失败/拒绝/漂移事件
 * 是用户最需醒目看到的风险信号,不能默认色稀释。命中集合(与 Rust 真实事件名对齐):
 *   - tool_call.execute_failed
 *   - tool_call.abandoned
 *   - server.command_drifted / command_drift_rejected
 *   - tool_approval.drift_rejected
 *   - 任何 `*.denied` / `*.failed` / `*.timeout` / `*.drift_rejected` 后缀(含 runner
 *     若未来接入时通过 `.io_error` / `.rejected` 后缀兜底命中)
 */
function typeTagType(
  eventType: string,
): "default" | "info" | "success" | "warning" | "error" {
  // 高优先级 — error(失败 / 拒绝 / 超时 / 漂移拒绝)
  const errorExact = [
    "tool_call.execute_failed",
    "tool_call.abandoned",
    "server.command_drifted",
    "server.command_drift_rejected",
    "tool_approval.drift_rejected",
  ];
  if (errorExact.includes(eventType)) return "error";
  if (
    eventType.endsWith(".denied") ||
    eventType.endsWith(".failed") ||
    eventType.endsWith(".timeout") ||
    eventType.endsWith(".drift_rejected") ||
    eventType.endsWith(".execute_failed") ||
    eventType.endsWith(".io_error") ||
    eventType.endsWith(".rejected") ||
    eventType.endsWith(".killed_by_timeout")
  ) {
    return "error";
  }
  // warning — approval / re-approved / command drift(非 rejected)
  if (eventType.startsWith("approval.")) return "warning";
  if (eventType === "tool_approval.re_approved") return "warning";
  if (eventType === "server.command_re_approved") return "warning";
  // info — lease / decision(中性记录)
  if (eventType.startsWith("lease.")) return "info";
  if (eventType === "decision.recorded") return "info";
  // success — 正常完成 / 首次批准
  if (eventType === "tool_call.executed") return "success";
  if (eventType === "tool_approval.first_approved") return "success";
  // browser.*_checked 是中性观测记录(拦截/脱敏动作在 payload.action,类型层不区分)
  if (eventType.startsWith("browser.")) return "info";
  return "default";
}

/**
 * 事件类型 → 品牌 log-line 语义色 class(纯展示,对齐 ProtectionOverview 的 `eventTone`)。
 * deny/block→红 / redact→青 / approve·allow·mint→绿 / 其它→中性。
 * 仅决定 CSS 色类,不参与任何 IPC / 数据流逻辑。
 */
function eventTone(eventType: string): "deny" | "redact" | "allow" | "info" {
  const x = eventType.toLowerCase();
  if (
    x.includes("deny") ||
    x.includes("block") ||
    x.includes("reject") ||
    x.includes("fail") ||
    x.includes("abandon") ||
    x.includes("revoke") ||
    x.includes("drift")
  ) {
    return "deny";
  }
  if (x.includes("redact")) return "redact";
  if (
    x.includes("approv") ||
    x.includes("allow") ||
    x.includes("mint") ||
    x.includes("executed")
  ) {
    return "allow";
  }
  return "info";
}

// ─────────────────────── Feed view ───────────────────────

/** 当前展示的事件列表:searchActive 时是搜索结果,否则是 feed */
const currentList = computed<EventSummary[]>(() =>
  store.searchActive ? store.searchHits : store.events,
);

function handleItemClick(row: EventSummary): void {
  store.loadDetail(row.event_id);
  modalOpen.value = true;
}

// ─────────────────────── Search ───────────────────────
const searchInput = ref<string>("");

async function onSearchSubmit(): Promise<void> {
  await store.search(searchInput.value);
}

function onSearchClear(): void {
  searchInput.value = "";
  store.clearSearch();
  store.refresh(); // 回到 feed
}

// ─────────────────────── Filter handlers ───────────────────────
function onSessionFilterBlur(): void {
  // N-input onBlur 时触发 refresh
  store.refresh();
}
function onTypeFilterUpdate(v: string[]): void {
  store.setTypeFilters(v);
  store.refresh();
}

// v0.14 Theme F:计算是否有非默认 filter,用于显示 reset 按钮
const hasActiveFilter = computed(() =>
  store.sessionFilter !== null || store.typeFilters.length > 0,
);

function onResetFilters(): void {
  store.resetFilters();
  store.refresh();
}
</script>

<template>
  <div class="feed">
    <!-- 顶部细条:官方徽记 + 页名 + 计数/状态 + 刷新(对齐 ProtectionOverview .phead) -->
    <div class="phead">
      <span class="ptitle-wrap">
        <img :src="EMBLEM('audit')" class="page-emblem" alt="" />
        <span class="ptitle">{{ t("activity.page_title") }}</span>
        <StatusPill :tone="store.searchActive ? 'purple' : 'cyan'">
          {{ store.searchActive
            ? t("activity.count_search", { count: store.count })
            : t("activity.count_live", { count: store.count }) }}
        </StatusPill>
      </span>
      <NButton
        :loading="store.loading"
        size="small"
        quaternary
        data-testid="refresh-feed"
        @click="store.refresh()"
      >
        {{ t("common.refresh") }}
      </NButton>
    </div>

    <!-- 检索 + 筛选控制台 -->
    <WindowCard title="audit · query" class="block">
      <div class="ctl">
        <div class="ctl-row">
          <!-- v0.14 Theme B:data-shortcut="search" 让 `/` 全局快捷键 focus 本框
               外层 div 标记(NInput input-props 类型受限,wrapper 更稳)-->
          <div class="ctl-grow" data-shortcut-wrapper="search">
            <NInput
              v-model:value="searchInput"
              :placeholder="t('activity.search_placeholder')"
              clearable
              data-testid="fts-input"
              @keydown.enter="onSearchSubmit"
            />
          </div>
          <NButton
            :loading="store.searchLoading"
            type="primary"
            data-testid="fts-search-btn"
            @click="onSearchSubmit"
          >
            {{ t("activity.search_button") }}
          </NButton>
          <NButton
            v-if="store.searchActive"
            size="small"
            data-testid="fts-clear-btn"
            @click="onSearchClear"
          >
            {{ t("activity.back_to_feed") }}
          </NButton>
        </div>

        <div
          v-if="store.searchError"
          class="ctl-err"
          data-testid="fts-error"
        >
          ⚠ {{ t("activity.search_error", { msg: store.searchError }) }}
        </div>

        <!-- Filters(仅 feed 模式)-->
        <div v-if="!store.searchActive" class="ctl-row ctl-filters">
          <div class="ctl-grow">
            <NInput
              :value="store.sessionFilter ?? ''"
              :placeholder="t('activity.session_filter_placeholder')"
              clearable
              data-testid="session-filter"
              @update:value="(v: string) => store.setSessionFilter(v)"
              @blur="onSessionFilterBlur"
            />
          </div>
          <div class="ctl-grow ctl-grow-wide">
            <NSelect
              :value="store.typeFilters"
              multiple
              clearable
              :options="EVENT_TYPE_OPTIONS"
              :placeholder="t('activity.type_filter_placeholder')"
              data-testid="type-filter"
              @update:value="onTypeFilterUpdate"
            />
          </div>
          <!-- v0.14 Theme F:显式 reset(只显示在有非默认 filter 时,减少视觉噪声)-->
          <NButton
            v-if="hasActiveFilter"
            size="small"
            quaternary
            data-testid="reset-feed-filters"
            @click="onResetFilters"
          >
            {{ t("activity.reset_filters") }}
          </NButton>
        </div>
      </div>
    </WindowCard>

    <!-- IPC 错误态(保留 NAlert 功能契约)-->
    <NAlert
      v-if="store.error"
      type="error"
      :title="t('common.ipc_error')"
      closable
      class="block"
      @close="store.error = null"
    >
      {{ store.error }}
    </NAlert>

    <!-- 审计流:mono log-line feed(品牌签名)-->
    <WindowCard :title="store.searchActive ? 'audit · hits' : 'audit · live'" class="block">
      <template #chrome-right>
        <StatusPill :tone="store.searchActive ? 'purple' : 'green'">
          {{ store.searchActive ? "SEARCH" : "LIVE" }}
        </StatusPill>
      </template>

      <!-- v0.14 Theme A:empty state —— 品牌化空态 + contextual CTA copy -->
      <div
        v-if="currentList.length === 0 && !store.loading"
        class="empty"
        data-testid="activity-empty"
      >
        <div class="empty-title">
          {{ store.searchActive
            ? t("activity.empty_no_hits")
            : t("activity.empty_no_events") }}
        </div>
        <div class="empty-extra">
          {{ store.searchActive
            ? t("activity.empty_hits_extra")
            : t("activity.empty_events_extra") }}
        </div>
      </div>

      <div v-else class="loglist">
        <button
          v-for="ev in currentList"
          :key="ev.event_id"
          type="button"
          class="logline"
          data-testid="event-item"
          :data-event-severity="typeTagType(ev.event_type)"
          @click="handleItemClick(ev)"
        >
          <span class="row-top">
            <span class="ts">{{ fmtTs(ev.created_at) }}</span>
            <span class="verb" :class="eventTone(ev.event_type)">{{ ev.event_type }}</span>
            <span class="desc">{{ ev.redacted_text || "—" }}</span>
          </span>
          <span class="row-meta">
            <span class="sid">{{ ev.session_id }}</span>
            <span class="sep">·</span>
            <span class="eid">event_id={{ ev.event_id }}</span>
          </span>
        </button>
      </div>
    </WindowCard>

    <EventDetailModal
      v-model:show="modalOpen"
      :detail="store.detail"
      :loading="store.detailLoading"
    />
  </div>
</template>

<style scoped>
.feed {
  max-width: 1080px;
  margin: 0 auto;
  padding: 18px 28px 40px;
}

/* ── 顶部细条(对齐 ProtectionOverview .phead)── */
.phead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}
.ptitle-wrap {
  display: inline-flex;
  align-items: center;
  gap: 12px;
}
.page-emblem {
  width: 28px;
  height: 28px;
  display: block;
  filter: drop-shadow(0 0 6px rgba(5, 217, 232, 0.55));
}
.ptitle {
  font-family: var(--vigil-mono);
  font-size: 13px;
  letter-spacing: 1px;
  color: var(--vigil-text-secondary);
}

.block {
  margin-top: 14px;
}

/* ── 检索 + 筛选控制台 ── */
.ctl {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.ctl-row {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.ctl-grow {
  flex: 1 1 280px;
  min-width: 220px;
}
.ctl-grow-wide {
  flex: 1.4 1 360px;
}
.ctl-filters {
  padding-top: 12px;
  border-top: 1px solid var(--vigil-border);
}
.ctl-err {
  font-family: var(--vigil-mono);
  font-size: 12px;
  color: var(--vigil-red);
}

/* ── mono log-line feed(品牌签名,对齐 ProtectionOverview .logline)── */
.loglist {
  display: flex;
  flex-direction: column;
}
.logline {
  display: flex;
  flex-direction: column;
  gap: 4px;
  width: 100%;
  padding: 11px 4px;
  border: 0;
  border-bottom: 1px solid rgba(35, 40, 55, 0.6);
  background: transparent;
  text-align: left;
  cursor: pointer;
  font-family: var(--vigil-mono);
  transition: background 0.12s ease;
}
.logline:hover {
  background: rgba(5, 217, 232, 0.04);
}
.logline:last-child {
  border-bottom: 0;
}
.logline:focus-visible {
  outline: 1px solid rgba(5, 217, 232, 0.5);
  outline-offset: -1px;
  border-radius: 4px;
}
.row-top {
  display: flex;
  align-items: baseline;
  gap: 14px;
  font-size: 12.5px;
}
.row-top .ts {
  color: var(--vigil-text-muted);
  flex: 0 0 auto;
}
.row-top .verb {
  font-weight: 700;
  min-width: 210px;
  flex: 0 0 auto;
}
.row-top .verb.deny {
  color: var(--vigil-red);
}
.row-top .verb.redact {
  color: var(--vigil-accent);
}
.row-top .verb.allow {
  color: var(--vigil-green);
}
.row-top .verb.info {
  color: var(--vigil-text-secondary);
}
.row-top .desc {
  color: var(--vigil-text);
  white-space: pre-wrap;
  word-break: break-all;
}
.row-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  padding-left: 2px;
  font-size: 11px;
  color: var(--vigil-text-muted);
}
.row-meta .sep {
  opacity: 0.5;
}

/* ── 品牌化空态(替代 NEmpty 默认装饰)── */
.empty {
  padding: 26px 4px;
  text-align: center;
}
.empty-title {
  font-size: 13.5px;
  color: var(--vigil-text-secondary);
}
.empty-extra {
  margin-top: 6px;
  font-family: var(--vigil-mono);
  font-size: 11.5px;
  color: var(--vigil-text-muted);
}
</style>
