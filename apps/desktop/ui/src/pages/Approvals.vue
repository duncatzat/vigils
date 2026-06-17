<script setup lang="ts">
/**
 * Approval Queue — rewritten to match the desktop prototype.
 *
 * Layout:
 *   - Page header + refresh
 *   - Three tabs: Pending Tool Calls / Tool Drift / Command Drift
 *   - Pending Tool Calls: main table (TIME / TOOL / SERVER / SCOPE / RISK)
 *     plus an inline right-hand "Approval Detail" panel.
 *
 * Data adaptations (backend does not expose every prototype field):
 *   - TIME uses expires_at formatted as HH:MM:SS (closest available timestamp).
 *   - TOOL uses approval.title.
 *   - SERVER / SCOPE / RISK are not present on ApprovalSummary, so the table
 *     renders "—" as a placeholder.
 *   - Detail "Risk score" is derived from the effect_vector heuristically.
 *   - Detail "Scope" shows the default "Once" scope (the user still chooses the
 *     real scope in the approve modal before resolving).
 */
import { computed, defineComponent, h, onMounted, onUnmounted, ref, watch } from "vue";
import {
  NButton,
  NDataTable,
  NSpace,
  NTag,
  NAlert,
  NEmpty,
  NModal,
  NRadio,
  NRadioGroup,
  NTabs,
  NTabPane,
  useDialog,
  type DataTableColumns,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { useApprovalsStore } from "@/stores/approvals";
import { useServersStore } from "@/stores/servers";
import type {
  ApprovalSummary,
  ApprovalAction,
  ApprovalScope,
  ApprovalDetailDto,
  EffectKind,
  ToolApprovalCard,
  ServerOnboardingData,
} from "@/api/ipc";
import { isEditingTarget } from "@/composables/useGlobalShortcuts";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";
import PanelCard from "@/components/PanelCard.vue";

const DetailRow = defineComponent({
  props: {
    label: { type: String, required: true },
  },
  setup(props, { slots }) {
    return () =>
      h("div", { class: "space-y-1" }, [
        h(
          "div",
          { class: "text-xs text-vigils-text-secondary uppercase tracking-wider" },
          props.label,
        ),
        h("div", { class: "leading-relaxed" }, slots.default?.()),
      ]);
  },
});

const { t } = useI18n();
const store = useApprovalsStore();
const serversStore = useServersStore();
const dialog = useDialog();

type TabKey = "pending" | "toolDrift" | "commandDrift";
const activeTab = ref<TabKey>("pending");

// ─────────────────────── Selection / navigation ───────────────────────
const selectedIndex = ref<number>(-1);

const selectedApproval = computed<ApprovalSummary | null>(() => {
  const idx = selectedIndex.value;
  if (idx < 0 || idx >= store.approvals.length) return null;
  return store.approvals[idx];
});

function clampSelectedIndex(): void {
  const n = store.approvals.length;
  if (n === 0) selectedIndex.value = -1;
  else if (selectedIndex.value >= n) selectedIndex.value = n - 1;
  else if (selectedIndex.value < 0) selectedIndex.value = 0;
}

function moveSelection(delta: number): void {
  const n = store.approvals.length;
  if (n === 0) {
    selectedIndex.value = -1;
    return;
  }
  if (selectedIndex.value < 0) {
    selectedIndex.value = delta > 0 ? 0 : n - 1;
    return;
  }
  selectedIndex.value = Math.max(0, Math.min(n - 1, selectedIndex.value + delta));
}

function selectRow(row: ApprovalSummary, index: number): void {
  selectedIndex.value = index;
  store.loadDetail(row.approval_id);
}

watch(() => store.approvals.length, clampSelectedIndex);

// Auto-select first row on first load so the detail panel is populated.
const hasAutoSelected = ref(false);
watch(
  () => store.approvals.length,
  (n) => {
    if (!hasAutoSelected.value && n > 0) {
      hasAutoSelected.value = true;
      selectedIndex.value = 0;
      store.loadDetail(store.approvals[0].approval_id);
    }
  },
);

// ─────────────────────── Approve scope modal ───────────────────────
const approveModalOpen = ref(false);
const approveModalApprovalId = ref<string | null>(null);
const approveScope = ref<ApprovalScope>("Once");

function openApproveModal(approval_id: string): void {
  approveModalApprovalId.value = approval_id;
  approveScope.value = "Once";
  approveModalOpen.value = true;
}

async function confirmApproveWithScope(): Promise<void> {
  approveModalOpen.value = false;
  const id = approveModalApprovalId.value;
  if (!id) return;
  dialog.warning({
    title: t("approval.confirm_approve_title"),
    content: t("approval.confirm_approve_content", { id, scope: approveScope.value }),
    positiveText: t("common.approve"),
    negativeText: t("common.rethink"),
    onPositiveClick: async () => {
      await store.resolve(id, "approve", { scope: approveScope.value });
    },
  });
}

// ─────────────────────── Deny / Cancel confirmations ───────────────────────
function confirmDenyOrCancel(
  approvalId: string,
  action: Exclude<ApprovalAction, "approve">,
): void {
  const title =
    action === "deny"
      ? t("approval.confirm_deny_title")
      : t("approval.confirm_cancel_title");
  const positiveText = action === "deny" ? t("common.deny") : t("common.cancel");
  dialog.warning({
    title,
    content: t("approval.confirm_deny_content", { id: approvalId }),
    positiveText,
    negativeText: t("common.rethink"),
    onPositiveClick: async () => {
      await store.resolve(approvalId, action);
    },
  });
}

// ─────────────────────── Detail panel helpers ───────────────────────
const isPendingDetail = computed(
  () => store.detail?.request.status === "Pending",
);

function computeRisk(detail: ApprovalDetailDto | null): {
  score: number;
  label: "high" | "medium" | "low";
  color: "red" | "yellow" | "green";
} {
  if (!detail) return { score: 0, label: "low", color: "green" };
  const ev = detail.request.effect_vector;
  let score = 0;
  if (ev.destructive) score += 30;
  if (ev.secret_refs.length > 0) score += 25;
  if (ev.network_hosts.length > 0 || ev.recipients.length > 0) score += 20;
  const writeExecKinds: EffectKind[] = ["FsWrite", "DbWrite", "ExecWasm", "ExecNative"];
  if (ev.effects.some((k) => writeExecKinds.includes(k))) score += 15;
  if (detail.privacy_findings.length > 0) score += 10;
  score = Math.min(100, score);

  if (score >= 70) return { score, label: "high", color: "red" };
  if (score >= 40) return { score, label: "medium", color: "yellow" };
  return { score, label: "low", color: "green" };
}

const riskMeta = computed(() => computeRisk(store.detail));

const effectsText = computed(() => {
  const effects = store.detail?.request.effect_vector.effects ?? [];
  return effects.length > 0 ? effects.join(", ") : "—";
});

const piiDetected = computed(() => {
  if (!store.detail) return null;
  const findings = store.detail.privacy_findings;
  if (findings.length > 0) return findings[0].label;
  const secrets = store.detail.request.effect_vector.secret_refs;
  if (secrets.length > 0) return secrets[0];
  return null;
});

// ─────────────────────── Formatters ───────────────────────
function fmtTime(ts: number): string {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("zh-CN", { hour12: false });
}

function fmtDateTime(ts: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}

// ─────────────────────── Columns: Pending Tool Calls ───────────────────────
const pendingColumns = computed<DataTableColumns<ApprovalSummary>>(() => [
  {
    title: t("approval.col_time"),
    key: "expires_at",
    width: 90,
    render: (row) => h("span", { class: "font-mono text-xs" }, fmtTime(row.expires_at)),
  },
  {
    title: t("approval.col_tool"),
    key: "title",
    ellipsis: { tooltip: true },
    render: (row) => h("span", { class: "font-mono text-sm" }, row.title),
  },
  {
    title: t("approval.col_server"),
    key: "server",
    width: 140,
    ellipsis: { tooltip: true },
    render: () => h("span", { class: "text-vigils-text-secondary" }, "—"),
  },
  {
    title: t("approval.col_scope"),
    key: "scope",
    width: 110,
    render: () => h("span", { class: "text-vigils-text-secondary" }, "—"),
  },
  {
    title: t("approval.col_risk"),
    key: "risk",
    width: 80,
    align: "right",
    render: () => h("span", { class: "text-vigils-text-secondary" }, "—"),
  },
]);

const rowProps = (row: ApprovalSummary) => ({
  style: "cursor: pointer;",
  onClick: () => selectRow(row, store.approvals.indexOf(row)),
});

function rowKey(row: ApprovalSummary): string {
  return row.approval_id;
}

function rowClassName(_row: ApprovalSummary, index: number): string {
  return index === selectedIndex.value ? "row-selected" : "";
}

// ─────────────────────── Columns: Tool Drift ───────────────────────
function approvePendingTool(card: ToolApprovalCard): void {
  dialog.info({
    title: t("approval.confirm_approve_title"),
    content: `${card.server_id} / ${card.tool_name}`,
    positiveText: t("common.approve"),
    negativeText: t("common.cancel"),
    onPositiveClick: async () => {
      try {
        await serversStore.approveToolAction({
          server_id: card.server_id,
          tool_name: card.tool_name,
        });
      } catch (e) {
        serversStore.error = String(e);
      }
    },
  });
}

const toolDriftColumns = computed<DataTableColumns<ToolApprovalCard>>(() => [
  {
    title: t("approval.col_tool"),
    key: "tool_name",
    render: (row) => h("span", { class: "font-mono text-sm" }, row.tool_name),
  },
  {
    title: t("approval.col_server"),
    key: "server_id",
    render: (row) => h("span", { class: "font-mono text-xs" }, row.server_id),
  },
  {
    title: t("approval.col_first_seen"),
    key: "first_seen_at",
    width: 160,
    render: (row) => fmtDateTime(row.first_seen_at),
  },
  {
    title: t("approval.col_actions"),
    key: "__actions",
    width: 110,
    render: (row) =>
      h(
        NButton,
        { size: "small", type: "primary", onClick: () => approvePendingTool(row) },
        { default: () => t("common.approve") },
      ),
  },
]);

// ─────────────────────── Columns: Command Drift ───────────────────────
function approveServerDrift(row: ServerOnboardingData): void {
  dialog.warning({
    title: t("onboardingCard.confirm_approve_title"),
    content: t("onboardingCard.confirm_approve_content", {
      serverId: row.server_id,
      hash: row.pending_command_hash ?? "pending",
    }),
    positiveText: t("onboardingCard.approve_drift"),
    negativeText: t("common.cancel"),
    onPositiveClick: async () => {
      try {
        await serversStore.approveServerCommandDriftAction({ server_id: row.server_id });
      } catch (e) {
        serversStore.error = String(e);
      }
    },
  });
}

function rejectServerDrift(row: ServerOnboardingData): void {
  dialog.error({
    title: t("onboardingCard.confirm_reject_title"),
    content: t("onboardingCard.confirm_reject_content", {
      serverId: row.server_id,
      hash: row.command_hash ?? "old",
    }),
    positiveText: t("onboardingCard.reject_drift"),
    negativeText: t("common.cancel"),
    onPositiveClick: async () => {
      try {
        await serversStore.rejectServerCommandDriftAction({ server_id: row.server_id });
      } catch (e) {
        serversStore.error = String(e);
      }
    },
  });
}

const commandDriftColumns = computed<DataTableColumns<ServerOnboardingData>>(() => [
  {
    title: t("approval.col_server"),
    key: "server_id",
    render: (row) => h("span", { class: "font-mono text-xs" }, row.server_id),
  },
  {
    title: t("server.col_transport"),
    key: "transport",
    width: 100,
    render: (row) =>
      h(
        NTag,
        { size: "small", type: row.transport === "Stdio" ? "info" : "success" },
        { default: () => row.transport },
      ),
  },
  {
    title: t("approval.col_first_seen"),
    key: "first_seen_at",
    width: 160,
    render: (row) => fmtDateTime(row.first_seen_at),
  },
  {
    title: t("approval.col_actions"),
    key: "__actions",
    width: 180,
    render: (row) =>
      h(NSpace, { size: "small" }, () => [
        h(
          NButton,
          { size: "small", type: "primary", onClick: () => approveServerDrift(row) },
          { default: () => t("onboardingCard.approve_drift") },
        ),
        h(
          NButton,
          { size: "small", type: "error", onClick: () => rejectServerDrift(row) },
          { default: () => t("onboardingCard.reject_drift") },
        ),
      ]),
  },
]);

// ─────────────────────── Lifecycle / updates ───────────────────────
useLedgerLiveUpdates({ onChange: () => store.refresh() });

onMounted(() => {
  store.refresh();
  serversStore.refresh();
  window.addEventListener("keydown", onPageKeyDown);
});

onUnmounted(() => {
  window.removeEventListener("keydown", onPageKeyDown);
});

function onPageKeyDown(ev: KeyboardEvent): void {
  if (ev.key === "Escape" && approveModalOpen.value) {
    approveModalOpen.value = false;
    ev.preventDefault();
    return;
  }
  if (activeTab.value !== "pending") return;
  if (isEditingTarget(ev.target)) return;
  if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
  if (approveModalOpen.value) return;

  switch (ev.key) {
    case "j":
    case "ArrowDown":
      moveSelection(1);
      ev.preventDefault();
      break;
    case "k":
    case "ArrowUp":
      moveSelection(-1);
      ev.preventDefault();
      break;
    case "Enter": {
      const row = selectedApproval.value;
      if (row) {
        store.loadDetail(row.approval_id);
        ev.preventDefault();
      }
      break;
    }
    case "a": {
      const row = selectedApproval.value;
      if (row) {
        openApproveModal(row.approval_id);
        ev.preventDefault();
      }
      break;
    }
    case "d": {
      const row = selectedApproval.value;
      if (row) {
        confirmDenyOrCancel(row.approval_id, "deny");
        ev.preventDefault();
      }
      break;
    }
    case "c": {
      const row = selectedApproval.value;
      if (row) {
        confirmDenyOrCancel(row.approval_id, "cancel");
        ev.preventDefault();
      }
      break;
    }
  }
}

// Refresh drift data when switching to those tabs.
function onTabChange(tab: TabKey): void {
  activeTab.value = tab;
  if (tab === "toolDrift" || tab === "commandDrift") {
    serversStore.refresh();
  }
}
</script>

<template>
  <div class="p-6 space-y-4 h-full flex flex-col">
    <!-- Header -->
    <NSpace justify="end" align="center">
      <NButton
        :loading="store.loading || serversStore.loading"
        size="small"
        data-testid="refresh-approvals"
        @click="activeTab === 'pending' ? store.refresh() : serversStore.refresh()"
      >
        {{ t("common.refresh") }}
      </NButton>
    </NSpace>

    <!-- Errors -->
    <NAlert
      v-if="store.error"
      type="error"
      :title="t('common.ipc_error')"
      closable
      @close="store.error = null"
    >
      {{ store.error }}
    </NAlert>
    <NAlert
      v-if="serversStore.error"
      type="error"
      :title="t('common.ipc_error')"
      closable
      @close="serversStore.error = null"
    >
      {{ serversStore.error }}
    </NAlert>

    <!-- Tabs -->
    <NTabs
      :value="activeTab"
      type="line"
      animated
      class="approvals-tabs"
      @update:value="(v: TabKey) => onTabChange(v)"
    >
      <NTabPane name="pending" :tab="t('approval.tab_pending_tool_calls')">
        <div class="flex gap-4">
          <!-- Main table -->
          <div class="flex-1 min-w-0">
            <PanelCard>
              <template #header>
                <h3 class="text-sm font-semibold text-vigils-text-primary uppercase tracking-wide">
                  {{ t("approval.pending_approvals") }}
                </h3>
              </template>

              <NDataTable
                :columns="pendingColumns"
                :data="store.approvals"
                :loading="store.loading"
                :row-props="rowProps"
                :row-key="rowKey"
                :row-class-name="rowClassName"
                :pagination="{ pageSize: 20 }"
                :bordered="false"
                size="small"
                data-testid="approvals-table"
              >
                <template #empty>
                  <NEmpty
                    :description="t('approval.empty_description')"
                    data-testid="approvals-empty"
                  >
                    <template #extra>
                      <div class="text-xs opacity-60 text-center">
                        {{ t("approval.empty_extra") }}
                      </div>
                    </template>
                  </NEmpty>
                </template>
              </NDataTable>
            </PanelCard>
          </div>

          <!-- Detail panel -->
          <div class="w-80 shrink-0">
            <PanelCard class="h-full">
              <template #header>
                <h3 class="text-sm font-semibold text-vigils-text-primary uppercase tracking-wide">
                  {{ t("approval.approval_detail") }}
                </h3>
              </template>

              <div v-if="!store.detail" class="text-sm text-vigils-text-secondary">
                {{ t("approval.select_row_hint") }}
              </div>
              <div v-else class="space-y-5">
                <DetailRow :label="t('approval.detail_tool')">
                  <span class="font-mono text-sm text-vigils-text-primary">
                    {{ store.detail.request.title }}
                  </span>
                </DetailRow>

                <DetailRow :label="t('approval.detail_server')">
                  <span class="font-mono text-xs text-vigils-text-secondary">—</span>
                </DetailRow>

                <DetailRow :label="t('approval.detail_session')">
                  <span class="font-mono text-xs text-vigils-text-primary">
                    {{ store.detail.request.session_id }}
                  </span>
                </DetailRow>

                <DetailRow :label="t('approval.detail_risk_score')">
                  <span
                    class="font-mono text-sm font-semibold"
                    :class="
                      riskMeta.color === 'red'
                        ? 'text-vigils-red'
                        : riskMeta.color === 'yellow'
                          ? 'text-vigils-yellow'
                          : 'text-vigils-green'
                    "
                  >
                    {{ riskMeta.score }} / 100
                  </span>
                  <span class="text-xs text-vigils-text-secondary ml-2">
                    ({{ t(`common.${riskMeta.label}`) }})
                  </span>
                </DetailRow>

                <DetailRow :label="t('approval.detail_scope')">
                  <span class="text-sm text-vigils-cyan">{{ t("approval.scope_once") }}</span>
                </DetailRow>

                <DetailRow :label="t('approval.detail_effects')">
                  <span class="font-mono text-xs text-vigils-text-primary">{{ effectsText }}</span>
                </DetailRow>

                <DetailRow :label="t('approval.detail_pii_detected')">
                  <span v-if="piiDetected" class="font-mono text-xs text-vigils-red">
                    {{ t("approval.pii_in_args", { label: piiDetected }) }}
                  </span>
                  <span v-else class="font-mono text-xs text-vigils-text-secondary">—</span>
                </DetailRow>

                <NSpace v-if="isPendingDetail" class="pt-2">
                  <NButton
                    type="primary"
                    :loading="store.resolving"
                    data-testid="action-approve"
                    @click="openApproveModal(store.detail.request.approval_id)"
                  >
                    {{ t("common.approve") }}
                  </NButton>
                  <NButton
                    type="error"
                    ghost
                    :loading="store.resolving"
                    data-testid="action-deny"
                    @click="confirmDenyOrCancel(store.detail.request.approval_id, 'deny')"
                  >
                    {{ t("common.deny") }}
                  </NButton>
                </NSpace>
              </div>
            </PanelCard>
          </div>
        </div>
      </NTabPane>

      <NTabPane name="toolDrift" :tab="t('approval.tab_tool_drift')">
        <PanelCard>
          <template #header>
            <h3 class="text-sm font-semibold text-vigils-text-primary uppercase tracking-wide">
              {{ t("approval.tab_tool_drift") }}
            </h3>
          </template>
          <NDataTable
            :columns="toolDriftColumns"
            :data="serversStore.pendingTools"
            :loading="serversStore.loading"
            :bordered="false"
            :pagination="{ pageSize: 20 }"
            size="small"
            data-testid="tool-drift-table"
          >
            <template #empty>
              <NEmpty :description="t('approval.empty_tool_drift')" data-testid="tool-drift-empty" />
            </template>
          </NDataTable>
        </PanelCard>
      </NTabPane>

      <NTabPane name="commandDrift" :tab="t('approval.tab_command_drift')">
        <PanelCard>
          <template #header>
            <h3 class="text-sm font-semibold text-vigils-text-primary uppercase tracking-wide">
              {{ t("approval.tab_command_drift") }}
            </h3>
          </template>
          <NDataTable
            :columns="commandDriftColumns"
            :data="serversStore.driftedServers"
            :loading="serversStore.loading"
            :bordered="false"
            :pagination="{ pageSize: 20 }"
            size="small"
            data-testid="command-drift-table"
          >
            <template #empty>
              <NEmpty :description="t('approval.empty_command_drift')" data-testid="command-drift-empty" />
            </template>
          </NDataTable>
        </PanelCard>
      </NTabPane>
    </NTabs>

    <!-- Approve scope modal -->
    <NModal
      v-model:show="approveModalOpen"
      preset="card"
      :title="t('approval.scope_modal_title')"
      :bordered="false"
      size="small"
      style="width: 480px;"
    >
      <NSpace vertical :size="16">
        <div class="text-sm opacity-70">
          {{ t("approval.scope_modal_hint_single") }}
        </div>
        <NRadioGroup v-model:value="approveScope">
          <NSpace vertical :size="8">
            <NRadio value="Once">
              <strong>{{ t("approval.scope_once") }}</strong> —
              <span class="text-sm opacity-70">{{ t("approval.scope_once_desc") }}</span>
            </NRadio>
            <NRadio value="ThisSession">
              <strong>{{ t("approval.scope_this_session") }}</strong> —
              <span class="text-sm opacity-70">{{ t("approval.scope_this_session_desc") }}</span>
            </NRadio>
          </NSpace>
        </NRadioGroup>
        <NSpace justify="end">
          <NButton @click="approveModalOpen = false">{{ t("common.cancel") }}</NButton>
          <NButton
            type="primary"
            data-testid="confirm-approve-scope"
            @click="confirmApproveWithScope"
          >
            {{ t("common.next_step") }}({{ t("common.second_confirm") }})
          </NButton>
        </NSpace>
      </NSpace>
    </NModal>
  </div>
</template>

<style scoped>
/* Keyboard-selected row highlight. */
:deep(.n-data-table-tr.row-selected) {
  background-color: rgba(5, 217, 232, 0.12);
}
:deep(.n-data-table-tr.row-selected .n-data-table-td) {
  background-color: rgba(5, 217, 232, 0.12);
}

/* Cyan active tab underline to match the prototype accent. */
:deep(.approvals-tabs .n-tabs-nav.n-tabs-nav--line-type .n-tabs-bar) {
  background-color: #05d9e8;
}
:deep(.approvals-tabs .n-tabs-tab--active) {
  color: #05d9e8;
}

/* Prototype-style table headers: muted, uppercase, compact. */
:deep(.n-data-table-thead .n-data-table-th) {
  font-size: 0.65rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: #64748b;
  background-color: transparent;
}
:deep(.n-data-table-td) {
  border-bottom: 1px solid #1e1e28;
}
:deep(.n-data-table-table) {
  border-collapse: separate;
}
</style>
