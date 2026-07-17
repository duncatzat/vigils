<script setup lang="ts">
/**
 * I08b-α4 Server Registry 页面(方案 §9 / ADR 0005 / 0008)。
 *
 * 3 Tab:
 *   1. Servers      —— 已审批 servers(StoredServerProfile)
 *   2. Pending tools —— 首次 pin 的 tool approval 卡片(approved_at == null)
 *   3. Drift        —— Drifted tools + Drifted servers(pending_command_hash 非空)
 *
 * 点击任何 server 行 → 弹 ServerOnboardingCard(argv / env keys / drift diff)。
 *
 * 安全契约:
 * - argv 逐元素渲染(ServerOnboardingCard 已守)
 * - 所有写操作走 store action(capability=Write 在 Rust 层显式);UI 侧 dialog 二次确认
 * - 轮询 5s + hidden/modal 暂停(复用 α2/α3)
 *
 * R2 Aegis 指挥舱外观:每个 Tab 内容裹进 WindowCard;表格走品牌化(header bg #13131b
 * mono-uppercase muted、行 hover、mono ID/hash);trust/transport NTag 经 scoped deep
 * 选择器收敛到 Aegis 语义色。<script> 逻辑/列定义/数据流零改动(契约)。
 */
import { onMounted, onUnmounted, ref, computed, h } from "vue";
import {
  NButton,
  NTabs,
  NTabPane,
  NDataTable,
  NEmpty,
  NTag,
  NSpace,
  NModal,
  NBadge,
  useDialog,
  type DataTableColumns,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { useServersStore } from "@/stores/servers";
import type { StoredServerProfile, ToolApprovalCard, ServerOnboardingData } from "@/api/ipc";
import ServerOnboardingCard from "@/components/ServerOnboardingCard.vue";
import WindowCard from "@/components/WindowCard.vue";
import StatusPill from "@/components/StatusPill.vue";
import { EMBLEM } from "@/brand";

const { t } = useI18n();
const store = useServersStore();
const dialog = useDialog();
const activeTab = ref<"servers" | "pending" | "drift">("servers");

// Modal
const detailOpen = ref(false);
const detailShowDriftActions = ref(false);

// ─────────────────────────── Polling(保留;非完全 event-backed)───────────────────────────
// Codex code review R1:Server Registry **不接** ledger-events-changed 实时刷新 —— pendingTools
// 来自 listPendingToolApprovals,而 first-seen tool descriptor(registry.rs PinOutcome::FirstSeen)
// 直写 tool_descriptors **不 append event**(且生产 auto_approve_first_seen_tools=false),
// MAX(event_id) 锚点不覆盖"新待审工具"。故保留 5s fallback poll(同 PrivacyFindings 决策)。
const POLL_INTERVAL_MS = 5000;
let pollTimer: ReturnType<typeof setInterval> | null = null;

onMounted(() => {
  store.refresh();
  pollTimer = setInterval(() => {
    // modal 打开时暂停 polling,避免用户看卡片时被刷新抢走 detail
    if (!document.hidden && !detailOpen.value) {
      store.refresh();
    }
  }, POLL_INTERVAL_MS);
});
onUnmounted(() => {
  if (pollTimer !== null) clearInterval(pollTimer);
  pollTimer = null;
});

// ─────────────────────────── Formatters ───────────────────────────
function fmtTs(ts: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}
function trustTagType(t: StoredServerProfile["trust_level"]): "success" | "default" | "warning" {
  if (t === "Trusted") return "success";
  if (t === "Limited") return "default";
  return "warning"; // Untrusted
}

// ─────────────────────────── Row click → open detail ───────────────────────────

async function openServerDetail(server_id: string, withDriftActions: boolean): Promise<void> {
  detailShowDriftActions.value = withDriftActions;
  detailOpen.value = true;
  await store.loadDetail(server_id);
}

function closeDetail(): void {
  detailOpen.value = false;
  store.clearDetail();
}

// ─────────────────────────── Write action handlers ───────────────────────────

// GUI-02(审核 ISS-20260702-004):弹窗/表头全部走 t(),随 locale 切换;此前为硬编码
// 混合语言字面量(英文标题+中文正文),语言切换对本页无效。
function confirmApproveTool(card: ToolApprovalCard): void {
  dialog.info({
    title: t("server.confirm_approve_title"),
    content: t("server.confirm_approve_body", {
      tool: card.tool_name,
      server: card.server_id,
      hash: card.current_hash,
    }),
    positiveText: t("server.approve"),
    negativeText: t("common.cancel"),
    onPositiveClick: async () => {
      await store.approveToolAction({ server_id: card.server_id, tool_name: card.tool_name });
    },
  });
}
function confirmApproveDriftTool(card: ToolApprovalCard): void {
  if (!card.proposed_hash) return;
  const newHash = card.proposed_hash;
  dialog.warning({
    title: t("server.confirm_approve_drift_title"),
    content: t("server.confirm_approve_drift_body", {
      tool: card.tool_name,
      new_hash: newHash,
      old_hash: card.current_hash,
    }),
    positiveText: t("server.approve_drift"),
    negativeText: t("common.cancel"),
    onPositiveClick: async () => {
      await store.approveToolDriftAction({
        server_id: card.server_id,
        tool_name: card.tool_name,
        new_hash: newHash,
      });
    },
  });
}
function confirmRejectDriftTool(card: ToolApprovalCard): void {
  dialog.error({
    title: t("server.confirm_reject_drift_title"),
    content: t("server.confirm_reject_drift_body", {
      tool: card.tool_name,
      hash: card.current_hash,
    }),
    positiveText: t("server.reject"),
    negativeText: t("common.cancel"),
    onPositiveClick: async () => {
      await store.rejectToolDriftAction({
        server_id: card.server_id,
        tool_name: card.tool_name,
      });
    },
  });
}

async function onApproveServerDrift(server_id: string): Promise<void> {
  await store.approveServerCommandDriftAction({ server_id });
}
async function onRejectServerDrift(server_id: string): Promise<void> {
  await store.rejectServerCommandDriftAction({ server_id });
}

// ─────────────────────────── Table columns ───────────────────────────

// GUI-02:列定义为 computed(title 依赖 locale,切换语言时表头随之更新)。
const serversColumns = computed<DataTableColumns<StoredServerProfile>>(() => [
  {
    title: t("server.col_server"),
    key: "server_id",
    render: (row) =>
      h("code", { class: "text-xs font-mono" }, row.server_id),
  },
  {
    title: t("server.col_transport"),
    key: "transport",
    render: (row) =>
      h(
        NTag,
        { size: "small", type: row.transport === "Stdio" ? "info" : "success" },
        { default: () => row.transport },
      ),
  },
  {
    title: t("server.col_trust"),
    key: "trust_level",
    render: (row) =>
      h(NTag, { size: "small", type: trustTagType(row.trust_level) }, {
        default: () => row.trust_level,
      }),
  },
  {
    title: t("server.col_first_seen"),
    key: "first_seen_at",
    render: (row) => fmtTs(row.first_seen_at),
  },
  {
    title: t("server.col_drift"),
    key: "pending_command_hash",
    render: (row) =>
      row.pending_command_hash
        ? h(
            NTag,
            { size: "small", type: "warning" },
            { default: () => t("server.drift_pending") },
          )
        : h("span", { class: "text-gray-500" }, "—"),
  },
  {
    title: t("server.col_actions"),
    key: "__actions",
    render: (row) =>
      h(
        NButton,
        {
          size: "tiny",
          "data-testid": `server-detail-${row.server_id}`,
          onClick: () => openServerDetail(row.server_id, false),
        },
        { default: () => t("server.detail_btn") },
      ),
  },
]);

// Pending tools 表(approved_at === null 的 ToolApprovalCard)
const pendingColumns = computed<DataTableColumns<ToolApprovalCard>>(() => [
  {
    title: t("server.col_server"),
    key: "server_id",
    render: (row) => h("code", { class: "text-xs font-mono" }, row.server_id),
  },
  {
    title: t("server.col_tool"),
    key: "tool_name",
    render: (row) =>
      h("code", { class: "text-xs font-mono font-semibold" }, row.tool_name),
  },
  {
    title: t("server.col_descriptor_hash"),
    key: "current_hash",
    render: (row) =>
      h("code", { class: "text-xs font-mono break-all" }, row.current_hash),
  },
  {
    title: t("server.col_first_seen"),
    key: "first_seen_at",
    render: (row) => fmtTs(row.first_seen_at),
  },
  {
    title: t("server.col_action"),
    key: "__actions",
    render: (row) =>
      h(
        NButton,
        {
          size: "tiny",
          type: "primary",
          "data-testid": `approve-tool-${row.tool_name}`,
          onClick: () => confirmApproveTool(row),
        },
        { default: () => t("server.approve") },
      ),
  },
]);

// Drifted tools 表(proposed_hash 非 null)
const driftedToolsColumns = computed<DataTableColumns<ToolApprovalCard>>(() => [
  {
    title: t("server.col_server"),
    key: "server_id",
    render: (row) => h("code", { class: "text-xs font-mono" }, row.server_id),
  },
  {
    title: t("server.col_tool"),
    key: "tool_name",
    render: (row) =>
      h("code", { class: "text-xs font-mono font-semibold" }, row.tool_name),
  },
  {
    title: t("server.col_current_hash"),
    key: "current_hash",
    render: (row) => h("code", { class: "text-xs break-all" }, row.current_hash),
  },
  {
    title: t("server.col_proposed_hash"),
    key: "proposed_hash",
    render: (row) =>
      h(
        "code",
        { class: "text-xs break-all text-yellow-400" },
        row.proposed_hash ?? "—",
      ),
  },
  {
    title: t("server.col_last_drift"),
    key: "last_drift_at",
    render: (row) => fmtTs(row.last_drift_at),
  },
  {
    title: t("server.col_actions"),
    key: "__actions",
    render: (row) =>
      h(NSpace, { size: "small" }, () => [
        h(
          NButton,
          {
            size: "tiny",
            type: "warning",
            "data-testid": `approve-drift-${row.tool_name}`,
            onClick: () => confirmApproveDriftTool(row),
          },
          { default: () => t("server.approve") },
        ),
        h(
          NButton,
          {
            size: "tiny",
            type: "error",
            "data-testid": `reject-drift-${row.tool_name}`,
            onClick: () => confirmRejectDriftTool(row),
          },
          { default: () => t("server.reject") },
        ),
      ]),
  },
]);

// Drifted servers 表(ServerOnboardingData,pending_command_hash 非 null)
const driftedServersColumns = computed<DataTableColumns<ServerOnboardingData>>(() => [
  {
    title: t("server.col_server"),
    key: "server_id",
    render: (row) => h("code", { class: "text-xs font-mono" }, row.server_id),
  },
  {
    title: t("server.col_old_hash"),
    key: "command_hash",
    render: (row) => h("code", { class: "text-xs break-all" }, row.command_hash ?? "—"),
  },
  {
    title: t("server.col_pending_hash"),
    key: "pending_command_hash",
    render: (row) =>
      h(
        "code",
        { class: "text-xs break-all text-yellow-400" },
        row.pending_command_hash ?? "—",
      ),
  },
  {
    title: t("server.col_first_seen"),
    key: "first_seen_at",
    render: (row) => fmtTs(row.first_seen_at),
  },
  {
    title: t("server.col_actions"),
    key: "__actions",
    render: (row) =>
      h(
        NButton,
        {
          size: "tiny",
          "data-testid": `server-drift-detail-${row.server_id}`,
          onClick: () => openServerDetail(row.server_id, true),
        },
        { default: () => t("server.detail_drift_actions") },
      ),
  },
]);

const driftCount = computed(() => store.driftedCount);
</script>

<template>
  <div class="registry">
    <!-- 顶部细条:页徽 + 页名 + 计数 pill + 刷新 -->
    <div class="phead">
      <span class="ptitle">
        <img class="emblem" :src="EMBLEM('gateway')" alt="" />
        <span class="ptitle-text">{{ t("server.page_title") }}</span>
      </span>
      <span class="pright">
        <StatusPill tone="cyan">{{ t("server.tab_servers") }} {{ store.servers.length }}</StatusPill>
        <StatusPill tone="yellow">{{ t("server.pending_tools_tab") }} {{ store.pendingCount }}</StatusPill>
        <StatusPill :tone="driftCount > 0 ? 'red' : 'cyan'">{{ t("server.tab_drift") }} {{ driftCount }}</StatusPill>
        <NButton
          :loading="store.loading"
          size="small"
          quaternary
          data-testid="refresh-servers"
          @click="store.refresh()"
        >
          {{ t("common.refresh") }}
        </NButton>
      </span>
    </div>

    <!-- 人话标题 -->
    <div class="headline">
      <h1>
        {{ t("server.page_title") }}
        <span class="count">
          ({{ t("server.count_summary", {
            approved: store.servers.length,
            pending: store.pendingCount,
            drifted: driftCount,
          }) }})
        </span>
      </h1>
    </div>

    <!-- 错误态(设计化,不裸露 IPC 错误当首屏)-->
    <div v-if="store.error" class="errcard" data-testid="server-load-failed">
      <span class="ei">!</span>
      <div class="ec">
        <div class="et">{{ t("common.ipc_error") }}</div>
        <div class="ed">{{ store.error }}</div>
      </div>
      <NButton size="small" @click="store.error = null">{{ t("common.refresh") }}</NButton>
    </div>

    <!-- Tab 容器:整段裹进一个 WindowCard,内部表格再各自分卡 -->
    <WindowCard title="registry · gateway" class="block">
      <NTabs v-model:value="activeTab" type="line" animated class="vtabs">
        <!-- Tab 1 · Servers -->
        <NTabPane name="servers" :tab="t('server.tab_servers')">
          <div class="vtable">
            <NDataTable
              :columns="serversColumns"
              :data="store.servers"
              :bordered="false"
              :pagination="{ pageSize: 20 }"
              data-testid="servers-table"
            >
              <template #empty>
                <NEmpty :description="t('server.empty_no_servers')" data-testid="servers-empty">
                  <template #icon>
                    <img class="empty-emblem" :src="EMBLEM('gateway')" alt="" />
                  </template>
                  <template #extra>
                    <div class="empty-cta">
                      {{ t("server.servers_register_cta") }}
                    </div>
                  </template>
                </NEmpty>
              </template>
            </NDataTable>
          </div>
        </NTabPane>

        <!-- Tab 2 · Pending tools -->
        <NTabPane name="pending">
          <template #tab>
            <NBadge :value="store.pendingCount" :max="99" :show="store.pendingCount > 0">
              {{ t("server.pending_tools_tab") }}
            </NBadge>
          </template>
          <div class="vtable">
            <NDataTable
              :columns="pendingColumns"
              :data="store.pendingTools"
              :bordered="false"
              :pagination="{ pageSize: 20 }"
              data-testid="pending-tools-table"
            />
          </div>
        </NTabPane>

        <!-- Tab 3 · Drift -->
        <NTabPane name="drift">
          <template #tab>
            <NBadge :value="driftCount" :max="99" :show="driftCount > 0" type="warning">
              {{ t("server.tab_drift") }}
            </NBadge>
          </template>
          <div class="drift-stack">
            <section class="drift-sec">
              <div class="sec-label">
                <span class="bk">[</span> {{ t("server.drifted_tools_label") }} <span class="bk">]</span>
              </div>
              <div class="vtable">
                <NDataTable
                  :columns="driftedToolsColumns"
                  :data="store.driftedTools"
                  :bordered="false"
                  :pagination="{ pageSize: 10 }"
                  data-testid="drifted-tools-table"
                />
              </div>
            </section>
            <section class="drift-sec">
              <div class="sec-label">
                <span class="bk">[</span> {{ t("server.drifted_servers_label") }} <span class="bk">]</span>
              </div>
              <div class="vtable">
                <NDataTable
                  :columns="driftedServersColumns"
                  :data="store.driftedServers"
                  :bordered="false"
                  :pagination="{ pageSize: 10 }"
                  data-testid="drifted-servers-table"
                />
              </div>
            </section>
          </div>
        </NTabPane>
      </NTabs>
    </WindowCard>

    <!-- Onboarding 抽屉(naive modal · 受保护 argv 逐元素由 ServerOnboardingCard 渲染) -->
    <NModal
      :show="detailOpen"
      preset="card"
      :title="t('server.onboarding_title')"
      :bordered="false"
      size="huge"
      class="vmodal"
      style="max-width: 800px;"
      @update:show="(v: boolean) => { if (!v) closeDetail(); }"
    >
      <div v-if="store.detailLoading" class="modal-hint">{{ t("server.onboarding_loading") }}</div>
      <div v-else-if="!store.onboardingDetail" class="modal-hint">
        {{ t("server.onboarding_no_data") }}
      </div>
      <ServerOnboardingCard
        v-else
        :data="store.onboardingDetail"
        :show-drift-actions="detailShowDriftActions"
        @approve-drift="onApproveServerDrift"
        @reject-drift="onRejectServerDrift"
      />
    </NModal>
  </div>
</template>

<style scoped>
.registry {
  max-width: 1080px;
  margin: 0 auto;
  padding: 18px 28px 40px;
}

/* ── 顶部细条 ───────────────────────────────────────────── */
.phead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 2px;
}
.ptitle {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  font-family: var(--vigil-mono);
  font-size: 13px;
  letter-spacing: 1px;
  color: var(--vigil-text-secondary);
}
.emblem {
  width: 19px;
  height: 19px;
  display: block;
  filter: drop-shadow(0 0 5px rgba(59, 130, 246, 0.6));
}
.ptitle-text {
  text-transform: lowercase;
}
.pright {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}

/* ── 人话标题 ───────────────────────────────────────────── */
.headline {
  text-align: center;
  margin: 8px 0 18px;
}
.headline h1 {
  font-size: 25px;
  font-weight: 700;
  letter-spacing: 0.3px;
  color: var(--vigil-text);
  margin: 0;
}
.headline h1 .count {
  font-family: var(--vigil-mono);
  font-size: 13px;
  font-weight: 400;
  color: var(--vigil-text-secondary);
  margin-left: 8px;
}

/* ── 区块 ───────────────────────────────────────────────── */
.block {
  margin-top: 14px;
}

/* ── Drift Tab 内分段 ───────────────────────────────────── */
.drift-stack {
  display: flex;
  flex-direction: column;
  gap: 22px;
  padding-top: 6px;
}
.drift-sec {
  display: block;
}
.sec-label {
  font-family: var(--vigil-mono);
  font-size: 11px;
  letter-spacing: 0.8px;
  text-transform: uppercase;
  color: var(--vigil-text-secondary);
  margin-bottom: 10px;
}
.sec-label .bk {
  color: var(--vigil-accent);
  opacity: 0.55;
}

/* ── 错误卡 ─────────────────────────────────────────────── */
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
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  flex: 0 0 auto;
  font-family: var(--vigil-mono);
  font-weight: 700;
  color: var(--vigil-red);
  border: 1px solid rgba(255, 42, 109, 0.45);
  background: rgba(255, 42, 109, 0.08);
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

/* ── Empty state（品牌化 NEmpty）──────────────────────────── */
.empty-emblem {
  width: 44px;
  height: 44px;
  display: block;
  margin: 0 auto;
  opacity: 0.7;
  filter: drop-shadow(0 0 8px rgba(59, 130, 246, 0.4)) grayscale(0.2);
}
.empty-cta {
  font-family: var(--vigil-mono);
  font-size: 12px;
  letter-spacing: 0.3px;
  color: var(--vigil-text-secondary);
  text-align: center;
}

/* ── Modal hint ─────────────────────────────────────────── */
.modal-hint {
  font-family: var(--vigil-mono);
  font-size: 12.5px;
  color: var(--vigil-text-secondary);
  padding: 6px 0;
}

/* ════════════════════════════════════════════════════════════
   naive-ui deep 收敛（保留功能组件，restyle 至 Aegis token）
   —— Tabs / DataTable header & rows / Tag 语义色 / Modal chrome
   ════════════════════════════════════════════════════════════ */

/* Tabs：下划线主色、激活态高亮、闲置 muted */
.vtabs :deep(.n-tabs-tab) {
  font-family: var(--vigil-mono);
  font-size: 12.5px;
  letter-spacing: 0.4px;
  color: var(--vigil-text-secondary);
}
.vtabs :deep(.n-tabs-tab.n-tabs-tab--active) {
  color: var(--vigil-text);
}
.vtabs :deep(.n-tabs-bar) {
  background-color: var(--vigil-accent) !important;
  box-shadow: 0 0 10px -2px rgba(5, 217, 232, 0.6);
}
.vtabs :deep(.n-tabs-nav) {
  --n-tab-border-color: var(--vigil-border);
}

/* DataTable 整体：透明底，行/线收敛到品牌深色 */
.vtable :deep(.n-data-table) {
  --n-td-color: transparent;
  --n-td-color-hover: rgba(5, 217, 232, 0.05);
  --n-merged-td-color: transparent;
  --n-merged-th-color: #13131b;
  background: transparent;
  font-size: 13px;
}
.vtable :deep(.n-data-table-wrapper) {
  background: transparent;
}

/* Header：#13131b 底 + mono uppercase muted */
.vtable :deep(.n-data-table-th) {
  background-color: #13131b !important;
  border-bottom: 1px solid var(--vigil-border) !important;
  font-family: var(--vigil-mono);
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: 0.8px;
  text-transform: uppercase;
  color: var(--vigil-text-secondary) !important;
}

/* Body cells：mono ID/hash 质感 + 行 hover 青晕 */
.vtable :deep(.n-data-table-td) {
  background-color: transparent !important;
  border-bottom: 1px solid rgba(35, 40, 55, 0.5) !important;
  color: var(--vigil-text);
}
.vtable :deep(.n-data-table-tr:hover .n-data-table-td) {
  background-color: rgba(5, 217, 232, 0.05) !important;
}
.vtable :deep(code) {
  font-family: var(--vigil-mono);
  color: var(--vigil-text);
}
.vtable :deep(.text-yellow-400) {
  color: var(--vigil-yellow) !important;
}
.vtable :deep(.text-gray-500) {
  color: var(--vigil-text-muted) !important;
}

/* Pagination：收敛到品牌色 */
.vtable :deep(.n-pagination) {
  --n-item-text-color-active: var(--vigil-accent);
  --n-item-border-active: 1px solid var(--vigil-accent);
  font-family: var(--vigil-mono);
}

/* Tag → Aegis 语义胶囊（替换 naive 默认 chrome；保留 type 驱动配色）
   info = transport Stdio / cyan，success = Trusted / transport Http、绿，
   warning = drift pending / Untrusted、黄，default = Limited、中性 */
.vtable :deep(.n-tag) {
  font-family: var(--vigil-mono);
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: 0.4px;
  border-radius: 999px;
  border: 1px solid;
  background: transparent;
}
.vtable :deep(.n-tag.n-tag--info) {
  color: var(--vigil-accent);
  border-color: rgba(5, 217, 232, 0.4) !important;
  background: rgba(5, 217, 232, 0.07) !important;
}
.vtable :deep(.n-tag.n-tag--success) {
  color: var(--vigil-green);
  border-color: rgba(0, 255, 157, 0.42) !important;
  background: rgba(0, 255, 157, 0.07) !important;
}
.vtable :deep(.n-tag.n-tag--warning) {
  color: var(--vigil-yellow);
  border-color: rgba(250, 204, 21, 0.42) !important;
  background: rgba(250, 204, 21, 0.07) !important;
}
.vtable :deep(.n-tag.n-tag--default) {
  color: var(--vigil-text-secondary);
  border-color: var(--vigil-border) !important;
  background: rgba(100, 116, 139, 0.08) !important;
}
</style>
