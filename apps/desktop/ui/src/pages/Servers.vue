<script setup lang="ts">
/**
 * Servers page — Server Registry layout matching prototype 05_servers.png.
 *
 * Layout:
 * - Left: Registered MCP Servers table (SERVER / TRANSPORT / STATUS / TOOLS).
 * - Right: Add Server form + Drift Detections cards.
 *
 * Data comes from the servers Pinia store. The backend does not expose health
 * status or per-server tool counts, so status is inferred from pending command
 * drift and the tools column renders "—". Server registration via UI is not
 * yet backed by an IPC command, so the form shows a not-implemented notice.
 */
import { onMounted, onUnmounted, ref, h } from "vue";
import {
  NButton,
  NDataTable,
  NInput,
  NTag,
  NAlert,
  useDialog,
  type DataTableColumns,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { useServersStore } from "@/stores/servers";
import type { StoredServerProfile, ToolApprovalCard } from "@/api/ipc";
import PanelCard from "@/components/PanelCard.vue";

const { t } = useI18n();
const store = useServersStore();
const dialog = useDialog();

const POLL_INTERVAL_MS = 5000;
let pollTimer: ReturnType<typeof setInterval> | null = null;

onMounted(() => {
  store.refresh();
  pollTimer = setInterval(() => {
    if (!document.hidden) {
      store.refresh();
    }
  }, POLL_INTERVAL_MS);
});

onUnmounted(() => {
  if (pollTimer !== null) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
});

// Add Server form (local state; backend registration not available yet)
const newServerName = ref("");
const newServerCommand = ref("");

function onRegister(): void {
  dialog.info({
    title: t("server.register_not_implemented_title"),
    content: t("server.register_not_implemented_body"),
    positiveText: t("common.confirm"),
  });
}

// Drift approval handler
function confirmApproveDriftTool(card: ToolApprovalCard): void {
  const proposedHash = card.proposed_hash;
  if (!proposedHash) return;
  dialog.warning({
    title: t("server.confirm_approve_drift_title"),
    content: t("server.confirm_approve_drift_content", {
      serverId: card.server_id,
      tool: card.tool_name,
    }),
    positiveText: t("common.approve"),
    negativeText: t("common.cancel"),
    onPositiveClick: async () => {
      await store.approveToolDriftAction({
        server_id: card.server_id,
        tool_name: card.tool_name,
        new_hash: proposedHash,
      });
    },
  });
}

// ─────────────────────────── Table columns ───────────────────────────

const serversColumns: DataTableColumns<StoredServerProfile> = [
  {
    title: () => t("server.col_server"),
    key: "server_id",
    render: (row) =>
      h("code", { class: "text-sm font-mono text-vigils-text-primary" }, row.server_id),
  },
  {
    title: () => t("server.col_transport"),
    key: "transport",
    render: (row) =>
      h(
        NTag,
        { size: "small", type: row.transport === "Stdio" ? "default" : "info" },
        { default: () => row.transport.toLowerCase() },
      ),
  },
  {
    title: () => t("server.col_status"),
    key: "status",
    render: (row) => {
      const isPaused = row.pending_command_hash != null;
      return h(
        "span",
        {
          class: isPaused
            ? "text-sm font-medium text-vigils-yellow"
            : "text-sm font-medium text-vigils-green",
        },
        t(isPaused ? "server.status_paused" : "server.status_healthy"),
      );
    },
  },
  {
    title: () => t("server.col_tools"),
    key: "tools",
    align: "right",
    render: () => h("span", { class: "text-sm text-vigils-text-muted" }, "—"),
  },
];
</script>

<template>
  <div class="p-6">
    <NAlert
      v-if="store.error"
      type="error"
      :title="t('common.ipc_error')"
      closable
      class="mb-6"
      @close="store.error = null"
    >
      {{ store.error }}
    </NAlert>

    <div class="grid grid-cols-1 xl:grid-cols-3 gap-6">
      <!-- Registered MCP Servers -->
      <PanelCard class="xl:col-span-2" :padded="false">
        <template #header>
          <h3 class="text-sm font-semibold text-vigils-text-primary">
            {{ t("server.registered_mcp_servers") }}
          </h3>
        </template>
        <NDataTable
          :columns="serversColumns"
          :data="store.servers"
          :bordered="false"
          :single-line="false"
          :pagination="{ pageSize: 20 }"
          data-testid="servers-table"
        >
          <template #empty>
            <div class="py-12 text-center">
              <div class="text-sm text-vigils-text-secondary">
                {{ t("server.empty_no_servers") }}
              </div>
              <div class="text-xs text-vigils-text-muted mt-2">
                {{ t("server.empty_servers_extra") }}
              </div>
            </div>
          </template>
        </NDataTable>
      </PanelCard>

      <!-- Sidebar -->
      <div class="space-y-6">
        <!-- Add Server -->
        <PanelCard>
          <template #header>
            <h3 class="text-sm font-semibold text-vigils-text-primary">
              {{ t("server.add_server") }}
            </h3>
          </template>
          <div class="space-y-4">
            <div>
              <label class="block text-xs text-vigils-text-secondary mb-2">
                {{ t("server.form_name") }}
              </label>
              <NInput
                v-model:value="newServerName"
                :placeholder="t('server.name_placeholder')"
                data-testid="add-server-name"
              />
            </div>
            <div>
              <label class="block text-xs text-vigils-text-secondary mb-2">
                {{ t("server.form_command_or_url") }}
              </label>
              <NInput
                v-model:value="newServerCommand"
                :placeholder="t('server.command_placeholder')"
                data-testid="add-server-command"
              />
            </div>
            <NButton
              type="primary"
              class="w-full !bg-vigils-cyan !text-vigils-bg-deep hover:!bg-vigils-cyan/90"
              data-testid="register-server"
              @click="onRegister"
            >
              {{ t("server.register") }}
            </NButton>
          </div>
        </PanelCard>

        <!-- Drift Detections -->
        <PanelCard>
          <template #header>
            <h3 class="text-sm font-semibold text-vigils-text-primary">
              {{ t("server.drift_detections") }}
            </h3>
          </template>
          <div v-if="store.driftedTools.length === 0" class="text-sm text-vigils-text-muted">
            {{ t("server.empty_no_drift") }}
          </div>
          <div v-else class="space-y-3">
            <div
              v-for="card in store.driftedTools"
              :key="`${card.server_id}-${card.tool_name}`"
              class="bg-vigils-bg-tertiary border border-vigils-border rounded-lg p-4 flex items-center justify-between gap-4"
            >
              <div class="min-w-0">
                <div class="text-sm font-mono font-semibold text-vigils-text-primary truncate">
                  {{ card.server_id }} · {{ card.tool_name }}
                </div>
                <div class="text-xs text-vigils-text-secondary mt-1">
                  {{
                    card.proposed_hash
                      ? t("server.drift_tool_descriptor_changed")
                      : t("server.drift_resolved_program")
                  }}
                </div>
              </div>
              <NButton
                size="small"
                type="primary"
                ghost
                :disabled="!card.proposed_hash"
                :data-testid="`approve-drift-${card.tool_name}`"
                @click="confirmApproveDriftTool(card)"
              >
                {{ t("common.approve") }}
              </NButton>
            </div>
          </div>
        </PanelCard>
      </div>
    </div>
  </div>
</template>
