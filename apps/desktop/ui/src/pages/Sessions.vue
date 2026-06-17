<script setup lang="ts">
/**
 * Sessions page — matches the 04_sessions prototype.
 *
 * Layout:
 *   Left: active sessions table (session id, started time, event count).
 *   Right top: timeline of the selected session replay.
 *   Right bottom: per-session risk summary + export replay.
 */
import { computed, h, onMounted, ref } from "vue";
import { NAlert, NButton, NDataTable, NEmpty, type DataTableColumns } from "naive-ui";
import { useI18n } from "vue-i18n";
import { useSessionsStore } from "@/stores/sessions";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";
import {
  exportSessionReplay,
  listRecentEvents,
  type EventSummary,
  type ExportFormat,
  type SessionView,
} from "@/api/ipc";
import PanelCard from "@/components/PanelCard.vue";

const { t } = useI18n();
const store = useSessionsStore();

const recentEvents = ref<EventSummary[]>([]);
const exportingFormat = ref<ExportFormat | null>(null);
const exportError = ref<string | null>(null);

async function refreshAll(): Promise<void> {
  await store.refreshList({ limit: 100 });
  try {
    recentEvents.value = await listRecentEvents({ limit: 1000 });
  } catch {
    // Event counts are best-effort; failures should not block the page.
    recentEvents.value = [];
  }

  if (!store.selectedSessionId && store.sessions.length > 0) {
    const first = sessionRows.value[0];
    if (first) {
      await onPickSession(first);
    }
  }
}

onMounted(refreshAll);

useLedgerLiveUpdates({
  onChange: () => {
    if (!store.replayLoading) {
      void refreshAll();
    }
  },
});

// ─────────────────────────── Derived session rows ───────────────────────────

const eventCounts = computed<Map<string, number>>(() => {
  const map = new Map<string, number>();
  for (const ev of recentEvents.value) {
    map.set(ev.session_id, (map.get(ev.session_id) ?? 0) + 1);
  }
  return map;
});

interface SessionRow extends SessionView {
  event_count: number;
}

const sessionRows = computed<SessionRow[]>(() =>
  store.sessions.map((s) => ({
    ...s,
    event_count: eventCounts.value.get(s.session_id) ?? 0,
  })),
);

const selectedSession = computed<SessionRow | null>(
  () => sessionRows.value.find((s) => s.session_id === store.selectedSessionId) ?? null,
);

async function onPickSession(s: SessionRow): Promise<void> {
  await store.loadReplay({ session_id: s.session_id, verify: false });
}

// ─────────────────────────── Formatters ───────────────────────────

function formatTime(ts: number | null): string {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

function eventDisplay(ev: { event_type: string; redacted_text: string | null }): string {
  const type = ev.event_type.toLowerCase();
  const redacted = ev.redacted_text;

  if (redacted && /^(ALLOW|DENY|APPROVE)\b/.test(redacted)) {
    return redacted;
  }

  const verb = type.includes("deny")
    ? "DENY"
    : type.includes("allow")
      ? "ALLOW"
      : type.includes("approve") || type.includes("approval")
        ? "APPROVE"
        : ev.event_type.toUpperCase();

  const rest = redacted ?? ev.event_type;
  return `${verb} ${rest}`;
}

function eventDotColor(eventType: string): string {
  const lower = eventType.toLowerCase();
  if (lower.includes("session_start")) return "bg-vigils-cyan";
  if (lower.includes("allow")) return "bg-vigils-green";
  if (lower.includes("deny")) return "bg-vigils-red";
  if (lower.includes("approve") || lower.includes("approval")) return "bg-vigils-yellow";
  return "bg-vigils-cyan";
}

// ─────────────────────────── Timeline ───────────────────────────

interface TimelineItem {
  event_id: number;
  event_type: string;
  redacted_text: string | null;
  created_at: number;
  is_start: boolean;
}

const timelineEvents = computed<TimelineItem[]>(() => {
  const items: TimelineItem[] = [];
  if (store.replay) {
    for (const ev of [...store.replay.events].reverse()) {
      items.push({
        event_id: ev.event_id,
        event_type: ev.event_type,
        redacted_text: ev.redacted_text,
        created_at: ev.created_at,
        is_start: false,
      });
    }
  }
  if (selectedSession.value) {
    items.push({
      event_id: -1,
      event_type: "session_start",
      redacted_text: null,
      created_at: selectedSession.value.started_at,
      is_start: true,
    });
  }
  return items;
});

// ─────────────────────────── Risk summary ───────────────────────────

const riskSummary = computed(() => {
  const events = store.replay?.events ?? [];
  let allowed = 0;
  let denied = 0;
  let approvals = 0;
  let secrets = 0;

  for (const ev of events) {
    const text = eventDisplay(ev).toLowerCase();
    if (text.includes("allow")) allowed++;
    if (text.includes("deny")) denied++;
    if (text.includes("approve") || text.includes("approval")) approvals++;
    if (text.includes("secret") || text.includes("leak") || text.includes("pii")) secrets++;
  }

  return {
    total: events.length,
    allowed,
    denied,
    approvals,
    secrets,
    highest: selectedSession.value?.risk_score ?? 0,
  };
});

// ─────────────────────────── Export replay ───────────────────────────

async function exportReplay(): Promise<void> {
  if (!store.selectedSessionId) return;
  exportingFormat.value = "md";
  exportError.value = null;
  try {
    const dto = await exportSessionReplay({ session_id: store.selectedSessionId, format: "md" });
    const blob = new Blob([dto.content], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement("a");
      a.href = url;
      a.download = `vigil-${dto.session_id}-${dto.generated_at}.md`;
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

// ─────────────────────────── Session table ───────────────────────────

const sessionsColumns: DataTableColumns<SessionRow> = [
  {
    title: t("session.col_session"),
    key: "session_id",
    render: (row) =>
      h(
        "button",
        {
          type: "button",
          class: "text-vigils-cyan font-mono text-sm bg-transparent border-0 p-0 cursor-pointer hover:opacity-80 text-left",
          "data-testid": `replay-${row.session_id}`,
          onClick: (e: MouseEvent) => {
            e.stopPropagation();
            void onPickSession(row);
          },
        },
        row.session_id,
      ),
  },
  {
    title: t("session.col_started"),
    key: "started_at",
    render: (row) => h("span", { class: "text-vigils-text-secondary text-sm" }, formatTime(row.started_at)),
  },
  {
    title: t("session.col_events"),
    key: "event_count",
    align: "right",
    render: (row) => h("span", { class: "text-vigils-text-secondary text-sm font-mono" }, row.event_count),
  },
];

function rowClassName(row: SessionRow): string {
  return row.session_id === store.selectedSessionId ? "bg-vigils-bg-tertiary" : "";
}

function rowProps(row: SessionRow) {
  return {
    style: { cursor: "pointer" },
    onClick: () => {
      void onPickSession(row);
    },
  };
}
</script>

<template>
  <div class="p-6">
    <NAlert
      v-if="store.error"
      type="error"
      :title="t('common.ipc_error')"
      closable
      class="mb-4"
      @close="store.error = null"
    >
      {{ store.error }}
    </NAlert>

    <div class="grid grid-cols-12 gap-6">
      <!-- Active sessions -->
      <div class="col-span-12 lg:col-span-7">
        <PanelCard :padded="false" class="h-full flex flex-col">
          <template #header>
            <span class="text-sm font-semibold text-vigils-text-primary">
              {{ t("session.active_sessions") }}
            </span>
          </template>

          <div class="flex-1 overflow-auto">
            <NDataTable
              :columns="sessionsColumns"
              :data="sessionRows"
              :bordered="false"
              :pagination="false"
              :loading="store.listLoading"
              :row-class-name="rowClassName"
              :row-props="rowProps"
              data-testid="sessions-table"
            >
              <template #empty>
                <NEmpty :description="t('session.empty_no_sessions')" data-testid="sessions-empty">
                  <template #extra>
                    <div class="text-xs text-vigils-text-muted text-center">
                      {{ t("session.empty_sessions_extra") }}
                    </div>
                  </template>
                </NEmpty>
              </template>
            </NDataTable>
          </div>
        </PanelCard>
      </div>

      <!-- Timeline + risk summary -->
      <div class="col-span-12 lg:col-span-5 flex flex-col gap-6">
        <!-- Timeline -->
        <PanelCard>
          <template #header>
            <span class="text-sm font-semibold text-vigils-text-primary">
              {{ t("session.session_timeline") }}:
              <span v-if="selectedSession" class="font-mono text-vigils-cyan ml-1">
                {{ selectedSession.session_id }}
              </span>
              <span v-else class="text-vigils-text-muted ml-1">—</span>
            </span>
          </template>

          <div v-if="!selectedSession" class="text-sm text-vigils-text-muted py-4">
            {{ t("session.no_session_selected") }}
          </div>

          <div v-else-if="store.replayLoading" class="text-sm text-vigils-text-muted py-4">
            {{ t("session.replay_loading") }}
          </div>

          <div v-else-if="timelineEvents.length === 0" class="text-sm text-vigils-text-muted py-4">
            {{ t("session.replay_no_events") }}
          </div>

          <div v-else class="relative pl-4">
            <div
              v-for="ev in timelineEvents"
              :key="`${ev.event_id}-${ev.created_at}`"
              class="relative pl-6 pb-5 last:pb-0 border-l border-vigils-border last:border-transparent"
              data-testid="replay-event"
            >
              <span
                class="absolute left-[-5px] top-1.5 w-[9px] h-[9px] rounded-full"
                :class="eventDotColor(ev.event_type)"
              />
              <div class="text-xs text-vigils-text-muted font-mono">
                {{ formatTime(ev.created_at) }}
              </div>
              <div
                class="text-sm text-vigils-text-primary mt-0.5"
                :class="ev.is_start ? 'font-semibold uppercase' : ''"
              >
                {{ ev.is_start ? t("session.session_start") : eventDisplay(ev) }}
              </div>
            </div>
          </div>
        </PanelCard>

        <!-- Risk summary -->
        <PanelCard>
          <template #header>
            <span class="text-sm font-semibold text-vigils-text-primary">
              {{ t("session.session_risk_summary") }}
            </span>
          </template>

          <div class="space-y-4">
            <div class="flex items-center justify-between text-sm">
              <span class="text-vigils-text-secondary">{{ t("session.total_tool_calls") }}</span>
              <span class="text-vigils-text-primary font-mono font-semibold">{{ riskSummary.total }}</span>
            </div>
            <div class="flex items-center justify-between text-sm">
              <span class="text-vigils-text-secondary">{{ t("session.allowed") }}</span>
              <span class="text-vigils-text-primary font-mono font-semibold">{{ riskSummary.allowed }}</span>
            </div>
            <div class="flex items-center justify-between text-sm">
              <span class="text-vigils-text-secondary">{{ t("session.denied") }}</span>
              <span class="text-vigils-text-primary font-mono font-semibold">{{ riskSummary.denied }}</span>
            </div>
            <div class="flex items-center justify-between text-sm">
              <span class="text-vigils-text-secondary">{{ t("session.approvals_requested") }}</span>
              <span class="text-vigils-text-primary font-mono font-semibold">{{ riskSummary.approvals }}</span>
            </div>
            <div class="flex items-center justify-between text-sm">
              <span class="text-vigils-text-secondary">{{ t("session.secret_leak_detected") }}</span>
              <span class="text-vigils-text-primary font-mono font-semibold">{{ riskSummary.secrets }}</span>
            </div>
            <div class="flex items-center justify-between text-sm">
              <span class="text-vigils-text-secondary">{{ t("session.highest_risk_score") }}</span>
              <span class="text-vigils-text-primary font-mono font-semibold">
                {{ riskSummary.highest }} / 100
              </span>
            </div>
          </div>

          <NAlert
            v-if="exportError"
            type="error"
            class="mt-4"
            closable
            :title="t('common.ipc_error')"
            @close="exportError = null"
          >
            {{ exportError }}
          </NAlert>

          <NButton
            class="mt-6 w-full"
            type="primary"
            :loading="exportingFormat === 'md'"
            :disabled="!store.selectedSessionId || exportingFormat !== null"
            data-testid="safe-export-md"
            @click="exportReplay"
          >
            {{ t("session.export_replay") }}
          </NButton>
        </PanelCard>
      </div>
    </div>
  </div>
</template>
