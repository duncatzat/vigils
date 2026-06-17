<script setup lang="ts">
/**
 * Activity Feed page —— matches the 03_activity prototype.
 *
 * Layout:
 *   - Top filter bar: FTS search + type / decision / time-range filters.
 *   - Left: Event Feed table (TIME / TYPE / DECISION / TOOL).
 *   - Right: Event Detail panel with payload JSON and a "Verify chain" button.
 *
 * Data comes from the existing `useEventsStore` + `verifyChain` IPC wrapper.
 *
 * Safe guards:
 *   - All text uses `{{ }}` interpolation; payload is JSON.stringified into `<pre>`.
 *   - Decision / risk / tool are derived from available data; the TOOL column falls
 *     back to "—" because EventSummary does not carry a tool name.
 */
import { computed, h, onMounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NEmpty,
  NInput,
  NSelect,
  NSpace,
  type DataTableColumns,
  type SelectOption,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { useEventsStore } from "@/stores/events";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";
import { verifyChain, type EventSummary, type EventDetail, type ChainVerifyReport } from "@/api/ipc";
import PanelCard from "@/components/PanelCard.vue";

const { t } = useI18n();
const store = useEventsStore();

// ─────────────────────────── Live updates ───────────────────────────

useLedgerLiveUpdates({
  onChange: () => {
    if (!store.searchActive) store.refresh();
  },
});

onMounted(() => {
  store.refresh();
});

// ─────────────────────────── UI state ───────────────────────────

const searchInput = ref<string>("");
const selectedEventId = ref<number | null>(null);
const decisionFilter = ref<string | null>(null);
const timeFilter = ref<string | null>("24h");
const verifyLoading = ref<boolean>(false);
const verifyReport = ref<ChainVerifyReport | null>(null);

type DecisionKey = "allow" | "approve" | "deny" | "monitor";

// ─────────────────────────── Filter options ───────────────────────────

const EVENT_TYPE_OPTIONS: SelectOption[] = [
  { label: "tool_call.opened", value: "tool_call.opened" },
  { label: "tool_call.decided", value: "tool_call.decided" },
  { label: "tool_call.executed", value: "tool_call.executed" },
  { label: "tool_call.execute_failed", value: "tool_call.execute_failed" },
  { label: "tool_call.abandoned", value: "tool_call.abandoned" },
  { label: "decision.recorded", value: "decision.recorded" },
  { label: "approval.created", value: "approval.created" },
  { label: "approval.resolved", value: "approval.resolved" },
  { label: "approval.note", value: "approval.note" },
  { label: "lease.minted", value: "lease.minted" },
  { label: "lease.revoked", value: "lease.revoked" },
  { label: "tool_approval.first_approved", value: "tool_approval.first_approved" },
  { label: "tool_approval.re_approved", value: "tool_approval.re_approved" },
  { label: "tool_approval.drift_rejected", value: "tool_approval.drift_rejected" },
  { label: "server.command_drifted", value: "server.command_drifted" },
  { label: "server.command_re_approved", value: "server.command_re_approved" },
  { label: "server.command_drift_rejected", value: "server.command_drift_rejected" },
];

const decisionOptions: SelectOption[] = [
  { label: t("activity.decision_allow"), value: "allow" },
  { label: t("activity.decision_approve"), value: "approve" },
  { label: t("activity.decision_deny"), value: "deny" },
  { label: t("activity.decision_monitor"), value: "monitor" },
];

const timeOptions: SelectOption[] = [
  { label: t("activity.time_range_24h"), value: "24h" },
  { label: t("activity.time_range_7d"), value: "7d" },
  { label: t("activity.time_range_all"), value: "all" },
];

// ─────────────────────────── Formatters / derived display ───────────────────────────

function fmtTime(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleTimeString("en-GB", { hour12: false });
}

function displayType(eventType: string): string {
  // Strip the canonical suffix so the table reads like the prototype.
  return eventType.replace(
    /\.(opened|decided|executed|execute_failed|abandoned|recorded|created|resolved|note|minted|revoked|first_approved|re_approved|drift_rejected|command_drifted|command_re_approved|command_drift_rejected)$/,
    "",
  );
}

function decisionKeyFromType(eventType: string): DecisionKey {
  if (eventType.endsWith(".created")) return "approve";
  if (eventType.endsWith(".leak")) return "deny";
  if (eventType.endsWith(".drift") || eventType.endsWith(".opened")) return "monitor";
  if (
    eventType.endsWith(".denied") ||
    eventType.endsWith(".rejected") ||
    eventType.endsWith(".failed") ||
    eventType.endsWith(".abandoned")
  ) {
    return "deny";
  }
  if (
    eventType.endsWith(".executed") ||
    eventType.endsWith(".first_approved") ||
    eventType.endsWith(".registered") ||
    eventType.endsWith(".anchored") ||
    eventType.endsWith(".resolved") ||
    eventType.endsWith(".re_approved") ||
    eventType.endsWith(".minted")
  ) {
    return "allow";
  }
  return "allow";
}

function decisionKeyFromPayload(payload: unknown): DecisionKey | null {
  if (!payload || typeof payload !== "object") return null;
  const p = payload as Record<string, unknown>;
  if (typeof p.decision === "string") {
    const map: Record<string, DecisionKey> = {
      allow: "allow",
      approve: "approve",
      deny: "deny",
      monitor: "monitor",
      block: "deny",
    };
    return map[p.decision.toLowerCase()] ?? null;
  }
  return null;
}

function isEventDetail(ev: EventSummary | EventDetail): ev is EventDetail {
  return "payload" in ev;
}

function decisionKey(ev: EventSummary | EventDetail): DecisionKey {
  if (isEventDetail(ev)) {
    const fromPayload = decisionKeyFromPayload(ev.payload);
    if (fromPayload) return fromPayload;
  }
  return decisionKeyFromType(ev.event_type);
}

function decisionLabel(key: DecisionKey): string {
  return t(`activity.decision_${key}`);
}

const decisionTextClass: Record<DecisionKey, string> = {
  allow: "text-vigils-green",
  approve: "text-vigils-yellow",
  deny: "text-vigils-red",
  monitor: "text-vigils-cyan",
};

function riskScoreFromPayload(payload: unknown): number | null {
  if (!payload || typeof payload !== "object") return null;
  const p = payload as Record<string, unknown>;
  if (typeof p.risk_score === "number") return p.risk_score;
  if (typeof p.risk === "number") return p.risk;
  return null;
}

// ─────────────────────────── List + filters ───────────────────────────

const currentList = computed<EventSummary[]>(() => {
  const base = store.searchActive ? store.searchHits : store.events;
  let list = base;

  if (store.typeFilters.length > 0) {
    list = list.filter(
      (ev) =>
        store.typeFilters.includes(ev.event_type) ||
        store.typeFilters.some((tf) => ev.event_type.startsWith(`${tf}.`)),
    );
  }

  if (decisionFilter.value) {
    list = list.filter((ev) => decisionKey(ev) === decisionFilter.value);
  }

  if (timeFilter.value && timeFilter.value !== "all") {
    const nowSec = Date.now() / 1000;
    const cutoff = timeFilter.value === "24h" ? nowSec - 86400 : nowSec - 7 * 86400;
    list = list.filter((ev) => ev.created_at >= cutoff);
  }

  return list;
});

// ─────────────────────────── Table ───────────────────────────

const columns = computed<DataTableColumns<EventSummary>>(() => [
  {
    title: t("activity.col_time"),
    key: "created_at",
    width: 90,
    render: (row) => h("span", { class: "font-mono text-vigils-text-secondary" }, fmtTime(row.created_at)),
  },
  {
    title: t("activity.col_type"),
    key: "event_type",
    render: (row) => displayType(row.event_type),
  },
  {
    title: t("activity.col_decision"),
    key: "decision",
    width: 110,
    render: (row) => {
      const key = decisionKey(row);
      return h("span", { class: `font-semibold ${decisionTextClass[key]}` }, decisionLabel(key));
    },
  },
  {
    title: t("activity.col_tool"),
    key: "tool",
    width: 170,
    render: () => "—",
  },
]);

function rowProps(row: EventSummary) {
  return {
    style: "cursor: pointer;",
    class: selectedEventId.value === row.event_id ? "bg-vigils-bg-surface" : "",
    "data-testid": "event-item",
    onClick: () => selectEvent(row),
  };
}

async function selectEvent(row: EventSummary): Promise<void> {
  selectedEventId.value = row.event_id;
  await store.loadDetail(row.event_id);
}

// ─────────────────────────── Detail panel ───────────────────────────

const detailEvent = computed<EventSummary | EventDetail | null>(() => {
  if (store.detail?.event_id === selectedEventId.value) {
    return store.detail;
  }
  return (
    currentList.value.find((ev) => ev.event_id === selectedEventId.value) ?? null
  );
});

const detailPayloadPretty = computed<string>(() => {
  const ev = detailEvent.value;
  if (!ev || !isEventDetail(ev)) return "";
  const p = ev.payload;
  if (p === null || p === undefined) return "";
  try {
    return JSON.stringify(p, null, 2);
  } catch {
    return String(p);
  }
});

const detailRiskScore = computed<string>(() => {
  const ev = detailEvent.value;
  if (!ev || !isEventDetail(ev)) return "—";
  const score = riskScoreFromPayload(ev.payload);
  return score !== null ? `${score} / 100` : "—";
});

// ─────────────────────────── Search handlers ───────────────────────────

async function onSearchSubmit(): Promise<void> {
  await store.search(searchInput.value);
}

function onSearchClear(): void {
  searchInput.value = "";
  store.clearSearch();
  store.refresh();
}

function onTypeFilterUpdate(v: string[]): void {
  store.setTypeFilters(v);
  if (!store.searchActive) store.refresh();
}

// ─────────────────────────── Chain verify ───────────────────────────

async function runVerify(): Promise<void> {
  verifyLoading.value = true;
  try {
    verifyReport.value = await verifyChain();
  } catch (e) {
    verifyReport.value = {
      ok: false,
      broken_at_event_id: null,
      message: String(e),
    };
  } finally {
    verifyLoading.value = false;
  }
}
</script>

<template>
  <div class="p-6 space-y-4 max-w-[1600px] mx-auto">
    <!-- Filter bar -->
    <PanelCard :padded="false">
      <div class="px-5 py-4">
        <NSpace align="center" :wrap="true" :size="12">
          <NInput
            v-model:value="searchInput"
            :placeholder="t('activity.search_placeholder')"
            clearable
            style="width: 360px;"
            data-testid="fts-input"
            @keydown.enter="onSearchSubmit"
          />
          <NButton
            :loading="store.searchLoading"
            type="primary"
            data-testid="fts-search-btn"
            @click="onSearchSubmit"
          >
            {{ t("common.search") }}
          </NButton>
          <NButton
            v-if="store.searchActive"
            size="small"
            data-testid="fts-clear-btn"
            @click="onSearchClear"
          >
            {{ t("activity.back_to_feed") }}
          </NButton>

          <div class="w-px h-6 bg-vigils-border" />

          <NSelect
            :value="store.typeFilters"
            multiple
            clearable
            :options="EVENT_TYPE_OPTIONS"
            :placeholder="t('activity.filter_all_types')"
            style="width: 220px;"
            @update:value="onTypeFilterUpdate"
          />
          <NSelect
            v-model:value="decisionFilter"
            clearable
            :options="decisionOptions"
            :placeholder="t('activity.filter_all_decisions')"
            style="width: 150px;"
          />
          <NSelect
            v-model:value="timeFilter"
            :options="timeOptions"
            style="width: 140px;"
          />
        </NSpace>

        <div
          v-if="store.searchError"
          class="text-vigils-red mt-2 text-sm"
          data-testid="fts-error"
        >
          {{ t("activity.search_error", { msg: store.searchError }) }}
        </div>
      </div>
    </PanelCard>

    <NAlert
      v-if="store.error"
      type="error"
      :title="t('common.ipc_error')"
      closable
      @close="store.error = null"
    >
      {{ store.error }}
    </NAlert>

    <!-- Main content -->
    <div class="grid grid-cols-1 xl:grid-cols-[1fr_360px] gap-4">
      <!-- Event feed -->
      <PanelCard :padded="false">
        <template #header>
          <span class="text-base font-semibold text-vigils-text-primary">
            {{ t("activity.event_feed") }}
          </span>
        </template>
        <NDataTable
          :columns="columns"
          :data="currentList"
          :bordered="false"
          :loading="store.loading"
          :row-props="rowProps"
          data-testid="activity-table"
        >
          <template #empty>
            <NEmpty
              :description="store.searchActive
                ? t('activity.empty_no_hits')
                : t('activity.empty_no_events')"
              data-testid="activity-empty"
              class="py-8"
            >
              <template #extra>
                <div class="text-xs opacity-60 text-center">
                  {{
                    store.searchActive
                      ? t("activity.empty_hits_extra")
                      : t("activity.empty_events_extra")
                  }}
                </div>
              </template>
            </NEmpty>
          </template>
        </NDataTable>
      </PanelCard>

      <!-- Event detail -->
      <PanelCard>
        <template #header>
          <span class="text-base font-semibold text-vigils-text-primary">
            {{ t("activity.event_detail") }}
          </span>
        </template>

        <div v-if="store.detailLoading" class="text-vigils-text-secondary text-sm">
          {{ t("common.loading") }}
        </div>

        <template v-else-if="detailEvent">
          <div class="space-y-3 text-sm">
            <div class="flex justify-between gap-4">
              <span class="text-vigils-text-secondary shrink-0">{{ t("activity.label_event_id") }}</span>
              <code class="font-mono text-xs break-all text-right">{{ detailEvent.event_id }}</code>
            </div>
            <div class="flex justify-between gap-4">
              <span class="text-vigils-text-secondary shrink-0">{{ t("activity.label_type") }}</span>
              <span class="text-right">{{ displayType(detailEvent.event_type) }}</span>
            </div>
            <div class="flex justify-between gap-4">
              <span class="text-vigils-text-secondary shrink-0">{{ t("activity.label_decision") }}</span>
              <span
                class="font-semibold text-right"
                :class="decisionTextClass[decisionKey(detailEvent)]"
              >
                {{ decisionLabel(decisionKey(detailEvent)) }}
              </span>
            </div>
            <div class="flex justify-between gap-4">
              <span class="text-vigils-text-secondary shrink-0">{{ t("activity.label_risk_score") }}</span>
              <span class="text-right">{{ detailRiskScore }}</span>
            </div>
            <div class="flex justify-between gap-4">
              <span class="text-vigils-text-secondary shrink-0">{{ t("activity.label_session") }}</span>
              <code class="font-mono text-xs text-vigils-cyan break-all text-right">{{ detailEvent.session_id }}</code>
            </div>
          </div>

          <div class="mt-5">
            <div class="text-xs text-vigils-text-secondary mb-2">
              {{ t("activity.label_payload") }}
            </div>
            <pre
              class="text-xs whitespace-pre-wrap break-all max-h-[24rem] overflow-auto font-mono bg-vigils-bg-deep p-3 rounded border border-vigils-bg-surface"
              data-testid="payload-pre"
            >{{ detailPayloadPretty }}</pre>
          </div>

          <NButton
            class="mt-5 w-full"
            :loading="verifyLoading"
            data-testid="verify-chain-btn"
            @click="runVerify"
          >
            {{ t("activity.verify_chain") }}
          </NButton>

          <NAlert
            v-if="verifyReport"
            class="mt-3"
            :type="verifyReport.ok ? 'success' : 'error'"
            :title="verifyReport.ok ? t('protection.chain_valid') : t('protection.chain_invalid')"
            closable
            @close="verifyReport = null"
          >
            <div v-if="verifyReport.message">{{ verifyReport.message }}</div>
            <div v-if="!verifyReport.ok && verifyReport.broken_at_event_id" class="text-xs mt-1">
              broken_at_event_id = {{ verifyReport.broken_at_event_id }}
            </div>
          </NAlert>
        </template>

        <div v-else class="text-vigils-text-secondary text-sm">
          {{ t("activity.no_event_selected") }}
        </div>
      </PanelCard>
    </div>
  </div>
</template>
