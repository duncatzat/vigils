<script setup lang="ts">
/**
 * Protection Overview — dashboard layout matched to prototype 01_dashboard.png.
 *
 * Data sources:
 * - protectionSummary() IPC for top-line counters + chain_intact.
 * - approvals store for pending count.
 * - listRecentEvents() IPC for the recent-events table.
 * - listSessions() store for active/idle session counts.
 * - listServers() store for registered server count.
 * - listPrivacyFindings() IPC for the privacy-findings side panel.
 * - verifyChain() / exportSessionReplay() IPC for quick actions.
 *
 * Where the backend does not expose an exact metric (e.g. per-event decision / risk),
 * the UI derives a best-effort value from event_type or falls back to "—".
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { useRouter } from "vue-router";
import { NAlert, NButton, NEmpty } from "naive-ui";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";
import {
  exportSessionReplay,
  listPrivacyFindings,
  listRecentEvents,
  protectionSummary,
  verifyChain,
  type ChainVerifyReport,
  type EventSummary,
  type PrivacyFindingDto,
  type ProtectionSummary,
  type SessionView,
} from "@/api/ipc";
import { useApprovalsStore } from "@/stores/approvals";
import { useSessionsStore } from "@/stores/sessions";
import { useServersStore } from "@/stores/servers";
import PanelCard from "@/components/PanelCard.vue";
import ProgressBar from "@/components/ProgressBar.vue";
import StatCard from "@/components/StatCard.vue";

const { t } = useI18n();
const router = useRouter();
const approvalsStore = useApprovalsStore();
const sessionsStore = useSessionsStore();
const serversStore = useServersStore();

// ─────────────────────────── State ───────────────────────────
const summary = ref<ProtectionSummary | null>(null);
const summaryLoading = ref(false);
const recentEvents = ref<EventSummary[]>([]);
const recentEventsLoading = ref(false);
const privacyFindings = ref<PrivacyFindingDto[]>([]);
const privacyLoading = ref(false);
const chainReport = ref<ChainVerifyReport | null>(null);
const chainVerifyLoading = ref(false);
const lastVerifiedAt = ref<number>(Date.now());
const exportLoading = ref<string | null>(null);
const error = ref<string | null>(null);

// ─────────────────────────── Loaders ───────────────────────────
async function loadSummary(): Promise<void> {
  summaryLoading.value = true;
  try {
    summary.value = await protectionSummary();
  } catch (e) {
    error.value = String(e);
  } finally {
    summaryLoading.value = false;
  }
}

async function loadRecentEvents(): Promise<void> {
  recentEventsLoading.value = true;
  try {
    recentEvents.value = await listRecentEvents({ limit: 100 });
  } catch (e) {
    // non-fatal: the table just stays empty
    console.error("listRecentEvents failed", e);
  } finally {
    recentEventsLoading.value = false;
  }
}

async function loadPrivacyFindings(): Promise<void> {
  privacyLoading.value = true;
  try {
    const dto = await listPrivacyFindings({ limit_recent_scans: 0 });
    privacyFindings.value = dto.by_label_total;
  } catch (e) {
    console.error("listPrivacyFindings failed", e);
  } finally {
    privacyLoading.value = false;
  }
}

async function loadAll(): Promise<void> {
  error.value = null;
  await Promise.all([
    loadSummary(),
    approvalsStore.refresh(),
    sessionsStore.refreshList({ limit: 100 }),
    serversStore.refresh(),
    loadRecentEvents(),
    loadPrivacyFindings(),
  ]);
  // Treat the moment we first load as the last verification timestamp
  lastVerifiedAt.value = Date.now();
}

useLedgerLiveUpdates({ onChange: () => loadAll() });
onMounted(() => loadAll());

// ─────────────────────────── Derived metrics ───────────────────────────
const blockedAttempts = computed(() => summary.value?.raw_secrets_blocked ?? 0);
const chainIntact = computed(() => chainReport.value?.ok ?? summary.value?.chain_intact ?? true);

const activeSessions = computed(
  () => sessionsStore.sessions.filter((s: SessionView) => s.ended_at === null).length,
);
const idleSessions = computed(
  () => sessionsStore.sessions.filter((s: SessionView) => s.ended_at !== null).length,
);

const privacyFindingTotal = computed(() =>
  privacyFindings.value.reduce((sum, f) => sum + f.count, 0),
);

const latestSessions = computed(() =>
  [...sessionsStore.sessions]
    .sort((a, b) => b.started_at - a.started_at)
    .slice(0, 2),
);

// ─────────────────────────── Protection-status bars ───────────────────────────
type DecisionKey = "allow" | "deny" | "approve" | "monitor";

function inferDecision(eventType: string): DecisionKey | null {
  if (
    eventType.startsWith("tool_call.executed") ||
    eventType.startsWith("tool_call.opened") ||
    eventType === "tool_call.decided"
  ) {
    return "allow";
  }
  if (eventType === "approval.created") return "approve";
  if (
    eventType.endsWith(".denied") ||
    eventType.endsWith(".rejected") ||
    eventType.includes("drift_rejected") ||
    eventType.includes("secret")
  ) {
    return "deny";
  }
  if (eventType.includes("drift")) return "monitor";
  return null;
}

const decisionCounts = computed(() => {
  const counts: Record<DecisionKey, number> = { allow: 0, deny: 0, approve: 0, monitor: 0 };
  for (const ev of recentEvents.value) {
    const d = inferDecision(ev.event_type);
    if (d) counts[d]++;
  }
  return counts;
});

const decisionTotal = computed(() =>
  Object.values(decisionCounts.value).reduce((a, b) => a + b, 0),
);

function decisionPercent(key: DecisionKey): number {
  if (decisionTotal.value === 0) return 0;
  return Math.round((decisionCounts.value[key] / decisionTotal.value) * 100);
}

// ─────────────────────────── Recent-events table helpers ───────────────────────────
type RiskKey = "critical" | "high" | "medium" | "low";

interface DashboardRow {
  event_id: number;
  time: string;
  type: string;
  toolServer: string;
  decision: DecisionKey | "—";
  risk: RiskKey | "—";
}

function inferRisk(eventType: string): RiskKey | "—" {
  if (eventType.includes("secret")) return "critical";
  if (
    eventType.endsWith(".denied") ||
    eventType.endsWith(".rejected") ||
    eventType.includes("execute_failed") ||
    eventType.includes("abandoned")
  ) {
    return "high";
  }
  if (eventType.includes("drift")) return "medium";
  if (eventType.startsWith("tool_call")) return "low";
  return "—";
}

function inferToolServer(eventType: string, redacted: string | null): string {
  if (redacted) {
    const first = redacted.split(/\s+/)[0];
    if (first && first.length > 0 && !first.startsWith("[")) return first.slice(0, 30);
  }
  return eventType;
}

function fmtTime(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleTimeString("en-GB", { hour12: false });
}

function decisionLabel(d: DecisionKey | "—"): string {
  if (d === "—") return "—";
  return t(`protection.decision_${d}`);
}

function riskLabel(r: RiskKey | "—"): string {
  if (r === "—") return "—";
  return t(`common.${r}`);
}

const tableRows = computed<DashboardRow[]>(() =>
  recentEvents.value.slice(0, 5).map((ev) => ({
    event_id: ev.event_id,
    time: fmtTime(ev.created_at),
    type: ev.event_type,
    toolServer: inferToolServer(ev.event_type, ev.redacted_text),
    decision: inferDecision(ev.event_type) ?? "—",
    risk: inferRisk(ev.event_type),
  })),
);

const decisionTextColor: Record<DecisionKey, string> = {
  allow: "text-vigils-green",
  approve: "text-vigils-yellow",
  deny: "text-vigils-red",
  monitor: "text-vigils-cyan",
};

const riskTextColor: Record<RiskKey, string> = {
  critical: "text-vigils-red",
  high: "text-vigils-yellow",
  medium: "text-vigils-yellow",
  low: "text-vigils-green",
};

// ─────────────────────────── Actions ───────────────────────────
async function runVerify(): Promise<void> {
  chainVerifyLoading.value = true;
  try {
    chainReport.value = await verifyChain();
    lastVerifiedAt.value = Date.now();
  } catch (e) {
    error.value = String(e);
  } finally {
    chainVerifyLoading.value = false;
  }
}

function openApprovals(): void {
  router.push({ name: "approvals" });
}

async function exportSession(sessionId: string): Promise<void> {
  exportLoading.value = sessionId;
  try {
    const dto = await exportSessionReplay({ session_id: sessionId, format: "md" });
    const blob = new Blob([dto.content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${dto.session_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    error.value = String(e);
  } finally {
    exportLoading.value = null;
  }
}
</script>

<template>
  <div class="p-6 space-y-5">
    <NAlert
      v-if="error"
      type="error"
      :title="t('common.ipc_error')"
      closable
      @close="error = null"
    >
      {{ error }}
    </NAlert>

    <!-- KPI stat cards -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        :label="t('protection.stat_pending_approvals')"
        :value="approvalsStore.count"
        color="yellow"
        :subtext="t('protection.stat_pending_approvals_subtext')"
      />
      <StatCard
        :label="t('protection.stat_recent_events')"
        :value="recentEvents.length"
        color="cyan"
        :subtext="t('protection.stat_recent_events_subtext')"
      />
      <StatCard
        :label="t('protection.stat_active_sessions')"
        :value="activeSessions"
        color="purple"
        :subtext="t('protection.stat_active_sessions_subtext', { count: idleSessions })"
      />
      <StatCard
        :label="t('protection.stat_blocked_attempts')"
        :value="blockedAttempts"
        color="red"
      />
    </div>

    <!-- Middle row: Protection status / Chain integrity / Privacy findings -->
    <div class="grid grid-cols-1 xl:grid-cols-12 gap-4">
      <!-- Protection status -->
      <PanelCard class="xl:col-span-5">
        <template #header>
          <h2 class="text-base font-semibold text-vigils-text-primary">
            {{ t("protection.section_protection_status") }}
          </h2>
        </template>
        <div class="space-y-5">
          <ProgressBar
            :label="t('protection.decision_allow')"
            :percent="decisionPercent('allow')"
            color="green"
          />
          <ProgressBar
            :label="t('protection.decision_deny')"
            :percent="decisionPercent('deny')"
            color="red"
          />
          <ProgressBar
            :label="t('protection.decision_approve')"
            :percent="decisionPercent('approve')"
            color="yellow"
          />
          <div class="pt-2 space-y-1 text-sm">
            <div class="flex justify-between">
              <span class="text-vigils-text-secondary">{{ t("protection.rules_active", { count: "—" }) }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-vigils-text-secondary">{{ t("protection.servers_registered", { count: serversStore.servers.length }) }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-vigils-text-secondary">{{ t("protection.privacy_findings_count", { count: privacyFindingTotal }) }}</span>
            </div>
          </div>
        </div>
      </PanelCard>

      <!-- Chain integrity -->
      <PanelCard class="xl:col-span-3">
        <template #header>
          <h2 class="text-base font-semibold text-vigils-text-primary">
            {{ t("protection.section_chain_integrity") }}
          </h2>
        </template>
        <div class="space-y-4">
          <div class="flex items-center gap-2">
            <div
              class="w-3 h-3 rounded-sm"
              :class="chainIntact ? 'bg-vigils-green' : 'bg-vigils-red'"
            />
            <span
              class="text-sm font-medium"
              :class="chainIntact ? 'text-vigils-green' : 'text-vigils-red'"
            >
              {{ chainIntact ? t("protection.chain_valid") : t("protection.chain_invalid") }}
            </span>
          </div>
          <div class="text-sm text-vigils-text-secondary">
            {{ t("protection.last_verified", { time: fmtTime(lastVerifiedAt) }) }}
          </div>
          <NButton
            block
            quaternary
            :loading="chainVerifyLoading"
            class="!justify-start !rounded-lg !border !border-vigils-cyan/30 !bg-vigils-cyan/5 !text-vigils-cyan hover:!bg-vigils-cyan/10 hover:!border-vigils-cyan/60 active:!bg-vigils-cyan/15 transition-colors"
            @click="runVerify"
          >
            <svg
              class="w-4 h-4 mr-2 flex-shrink-0"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path d="M9 12l2 2 4-4" />
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            {{ t("protection.verify_now") }}
          </NButton>
        </div>
      </PanelCard>

      <!-- Privacy findings -->
      <PanelCard class="xl:col-span-4">
        <template #header>
          <h2 class="text-base font-semibold text-vigils-text-primary">
            {{ t("protection.section_privacy_findings") }}
          </h2>
        </template>
        <div v-if="privacyFindings.length === 0" class="text-sm text-vigils-text-secondary py-2">
          {{ t("privacy.empty") }}
        </div>
        <div v-else class="space-y-3">
          <div
            v-for="finding in privacyFindings.slice(0, 8)"
            :key="finding.label"
            class="flex items-center justify-between text-sm"
          >
            <span class="text-vigils-text-secondary">{{ finding.label }}</span>
            <span class="text-vigils-red font-mono">{{ finding.count }}</span>
          </div>
        </div>
      </PanelCard>
    </div>

    <!-- Bottom row: Recent events table / Quick actions -->
    <div class="grid grid-cols-1 xl:grid-cols-12 gap-4">
      <!-- Recent events -->
      <PanelCard class="xl:col-span-9" :padded="false">
        <template #header>
          <h2 class="text-base font-semibold text-vigils-text-primary">
            {{ t("protection.section_recent_events") }}
          </h2>
        </template>
        <NEmpty
          v-if="tableRows.length === 0 && !recentEventsLoading"
          :description="t('activity.empty_no_events')"
          class="py-8"
        />
        <table v-else class="w-full text-left text-sm border-collapse">
          <thead>
            <tr class="border-b border-vigils-border text-vigils-text-secondary uppercase text-xs">
              <th class="py-3 px-5 font-medium">{{ t("protection.col_time") }}</th>
              <th class="py-3 px-5 font-medium">{{ t("protection.col_type") }}</th>
              <th class="py-3 px-5 font-medium">{{ t("protection.col_tool_server") }}</th>
              <th class="py-3 px-5 font-medium">{{ t("protection.col_decision") }}</th>
              <th class="py-3 px-5 font-medium">{{ t("protection.col_risk") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in tableRows"
              :key="row.event_id"
              class="border-b border-vigils-border last:border-b-0"
            >
              <td class="py-3 px-5 text-vigils-text-secondary font-mono">{{ row.time }}</td>
              <td class="py-3 px-5 text-vigils-text-secondary">{{ row.type }}</td>
              <td class="py-3 px-5 text-vigils-text-primary">{{ row.toolServer }}</td>
              <td class="py-3 px-5">
                <span
                  v-if="row.decision !== '—'"
                  class="font-mono font-medium"
                  :class="decisionTextColor[row.decision]"
                >
                  {{ decisionLabel(row.decision) }}
                </span>
                <span v-else class="text-vigils-text-muted">—</span>
              </td>
              <td class="py-3 px-5">
                <span
                  v-if="row.risk !== '—'"
                  class="font-mono"
                  :class="riskTextColor[row.risk]"
                >
                  {{ riskLabel(row.risk) }}
                </span>
                <span v-else class="text-vigils-text-muted">—</span>
              </td>
            </tr>
          </tbody>
        </table>
      </PanelCard>

      <!-- Quick actions -->
      <PanelCard class="xl:col-span-3">
        <template #header>
          <h2 class="text-base font-semibold text-vigils-text-primary">
            {{ t("protection.quick_actions") }}
          </h2>
        </template>
        <div class="space-y-3">
          <NButton
            block
            quaternary
            class="!justify-start text-vigils-cyan hover:text-vigils-cyan/80"
            @click="openApprovals"
          >
            {{ t("protection.open_approval_queue") }}
          </NButton>
          <NButton
            block
            quaternary
            :loading="chainVerifyLoading"
            class="!justify-start text-vigils-cyan hover:text-vigils-cyan/80"
            @click="runVerify"
          >
            {{ t("protection.run_chain_verify") }}
          </NButton>
          <NButton
            block
            quaternary
            :disabled="latestSessions.length === 0"
            :loading="exportLoading === latestSessions[0]?.session_id"
            class="!justify-start text-vigils-cyan hover:text-vigils-cyan/80"
            @click="latestSessions[0] && exportSession(latestSessions[0].session_id)"
          >
            {{ t("protection.export_session") }}
          </NButton>
          <div class="pt-2 space-y-1">
            <div
              v-for="s in latestSessions"
              :key="s.session_id"
              class="text-xs font-mono text-vigils-text-muted hover:text-vigils-cyan cursor-pointer truncate"
              @click="exportSession(s.session_id)"
            >
              {{ s.session_id }}
            </div>
          </div>
        </div>
      </PanelCard>
    </div>
  </div>
</template>
