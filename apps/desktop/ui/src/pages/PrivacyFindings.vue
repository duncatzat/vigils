<script setup lang="ts">
/**
 * Privacy Findings 页面 — 匹配原型 06_privacy.png。
 *
 * 布局:
 *   1) 顶部:4 个统计卡片(Total Findings / Github Tokens / OpenAI Keys / Blocked Leaks)
 *   2) 下方:左右分栏
 *      - 左侧:Findings 表格(TIME / LABEL / SOURCE / SESSION)
 *      - 右侧:Finding Detail 面板
 *
 * 数据适配说明:
 *   - 后端 `listPrivacyFindings` 返回 scan 级摘要,不含单条 finding 的 label/tool。
 *   - LABEL 列展示 scan 的 source 类型(唯一可用的分类字段),SOURCE 列因无具体工具名展示 "—"。
 *   - Detail 中的 Redacted snippet 同理以 "—" 占位。
 *   - Blocked Leaks 统计取全部 finding 总数(所有命中均视为已拦截)。
 *
 * 安全契约(延续 ISS-017):
 *   - 不展示原文;fingerprint 仅展示前 8 位。
 *   - session_id / scan_id 缩短显示。
 *   - 所有字符串 `{{ }}` 插值,无 v-html。
 */
import { computed, h, onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NDataTable,
  NEmpty,
  NSpin,
  NTag,
  type DataTableColumns,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import {
  listPrivacyFindings,
  type PrivacyFindingsDto,
  type RedactionScanSummaryDto,
} from "@/api/ipc";
import StatCard from "@/components/StatCard.vue";
import PanelCard from "@/components/PanelCard.vue";

const { t } = useI18n();

const data = ref<PrivacyFindingsDto | null>(null);
const loading = ref(true);
const errorMsg = ref<string | null>(null);
const selectedScanId = ref<string | null>(null);

async function refresh(): Promise<void> {
  loading.value = true;
  errorMsg.value = null;
  try {
    data.value = await listPrivacyFindings({ limit_recent_scans: 100 });
    // 若当前选中的 scan 已被刷新掉,清空选中态
    if (
      selectedScanId.value &&
      !data.value.recent_scans.some((s) => s.scan_id === selectedScanId.value)
    ) {
      selectedScanId.value = null;
    }
    // 默认选中第一条
    if (!selectedScanId.value && data.value.recent_scans.length > 0) {
      selectedScanId.value = data.value.recent_scans[0].scan_id;
    }
  } catch (e) {
    errorMsg.value = String(e);
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);

// 30s 自动刷新
const refreshTimer = setInterval(refresh, 30_000);
onUnmounted(() => clearInterval(refreshTimer));

// ─────────────────────────── 统计卡片 ───────────────────────────

const totalFindings = computed<number>(() =>
  data.value?.by_label_total.reduce((sum, item) => sum + item.count, 0) ?? 0,
);

function countByLabel(label: string): number {
  return (
    data.value?.by_label_total.find((item) => item.label === label)?.count ?? 0
  );
}

const githubTokenCount = computed<number>(() => countByLabel("github_token"));
const openaiKeyCount = computed<number>(() => countByLabel("openai_key"));

// 所有命中均视为已拦截的泄漏
const blockedLeaksCount = computed<number>(() => totalFindings.value);

// ─────────────────────────── 格式化 ───────────────────────────

/** Unix 秒 → HH:MM:SS */
function formatTime(ts: number): string {
  if (!ts || ts <= 0) return "—";
  return new Date(ts * 1000).toLocaleTimeString("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

/** Unix 秒 → 本地日期时间字符串 */
function formatDateTime(ts: number): string {
  if (!ts || ts <= 0) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}

/** UUID/Hex 缩短:首 8 + … + 末 4 */
function shortId(id: string): string {
  if (id.length <= 14) return id;
  return `${id.slice(0, 8)}…${id.slice(-4)}`;
}

// ─────────────────────────── 表格 ───────────────────────────

const selectedScan = computed<RedactionScanSummaryDto | null>(() => {
  if (!selectedScanId.value || !data.value) return null;
  return (
    data.value.recent_scans.find((s) => s.scan_id === selectedScanId.value) ??
    null
  );
});

function onRowClick(row: RedactionScanSummaryDto): void {
  selectedScanId.value = row.scan_id;
}

const columns = computed<DataTableColumns<RedactionScanSummaryDto>>(() => [
  {
    title: t("privacy.col_time"),
    key: "ts",
    width: 100,
    render: (row) =>
      h("span", { class: "text-vigils-text-primary" }, formatTime(row.ts)),
  },
  {
    title: t("privacy.col_label"),
    key: "label",
    width: 160,
    render: (row) =>
      h(
        NTag,
        { size: "small", type: "error", bordered: false },
        { default: () => row.source },
      ),
  },
  {
    title: t("privacy.col_source"),
    key: "source",
    width: 160,
    render: () => h("span", { class: "text-vigils-text-secondary" }, "—"),
  },
  {
    title: t("privacy.col_session"),
    key: "session_id",
    render: (row) =>
      h(
        "code",
        {
          class:
            "text-xs font-mono text-vigils-cyan cursor-pointer hover:underline",
          title: row.session_id,
        },
        shortId(row.session_id),
      ),
  },
]);

const tableData = computed<RedactionScanSummaryDto[]>(
  () => data.value?.recent_scans ?? [],
);

const rowKey = (row: RedactionScanSummaryDto): string => row.scan_id;

const rowProps = (row: RedactionScanSummaryDto) => ({
  style: { cursor: "pointer" },
  onClick: () => onRowClick(row),
  class:
    selectedScanId.value === row.scan_id
      ? "bg-vigils-bg-surface/60"
      : undefined,
});
</script>

<template>
  <div class="p-6 h-full overflow-auto">
    <NAlert
      v-if="errorMsg"
      type="error"
      class="mb-4"
      :title="t('common.ipc_error')"
      closable
      @close="errorMsg = null"
    >
      {{ errorMsg }}
    </NAlert>

    <NSpin :show="loading">
      <!-- 顶部统计卡片 -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          :label="t('privacy.stat_total_findings')"
          :value="totalFindings"
          color="red"
          data-testid="privacy-stat-total"
        />
        <StatCard
          :label="t('privacy.stat_github_tokens')"
          :value="githubTokenCount"
          color="yellow"
          data-testid="privacy-stat-github"
        />
        <StatCard
          :label="t('privacy.stat_openai_keys')"
          :value="openaiKeyCount"
          color="yellow"
          data-testid="privacy-stat-openai"
        />
        <StatCard
          :label="t('privacy.stat_blocked_leaks')"
          :value="blockedLeaksCount"
          color="green"
          data-testid="privacy-stat-blocked"
        />
      </div>

      <!-- 下方左右分栏 -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- 左侧:Findings 表格 -->
        <PanelCard class="lg:col-span-2">
          <template #header>
            <h2 class="text-base font-semibold text-vigils-text-primary">
              {{ t("privacy.findings") }}
            </h2>
          </template>

          <NDataTable
            :columns="columns"
            :data="tableData"
            :row-key="rowKey"
            :row-props="rowProps"
            :bordered="false"
            size="small"
            :max-height="640"
            virtual-scroll
            data-testid="privacy-findings-table"
          >
            <template #empty>
              <NEmpty :description="t('privacy.empty')" data-testid="privacy-empty" />
            </template>
          </NDataTable>
        </PanelCard>

        <!-- 右侧:Finding Detail -->
        <PanelCard>
          <template #header>
            <h2 class="text-base font-semibold text-vigils-text-primary">
              {{ t("privacy.finding_detail") }}
            </h2>
          </template>

          <div
            v-if="!selectedScan"
            class="text-sm text-vigils-text-secondary py-8 text-center"
          >
            {{ t("privacy.empty") }}
          </div>

          <div v-else class="space-y-5">
            <div>
              <div class="text-xs text-vigils-text-secondary mb-1">
                {{ t("privacy.label") }}
              </div>
              <NTag size="small" type="error" :bordered="false">
                {{ selectedScan.source }}
              </NTag>
            </div>

            <div>
              <div class="text-xs text-vigils-text-secondary mb-1">
                {{ t("privacy.source_tool") }}
              </div>
              <div class="text-sm text-vigils-text-secondary">—</div>
            </div>

            <div>
              <div class="text-xs text-vigils-text-secondary mb-1">
                {{ t("privacy.count") }}
              </div>
              <div class="text-sm text-vigils-text-primary">
                {{ selectedScan.finding_count }}
              </div>
            </div>

            <div>
              <div class="text-xs text-vigils-text-secondary mb-1">
                {{ t("privacy.first_seen") }}
              </div>
              <div class="text-sm text-vigils-text-primary">
                {{ formatDateTime(selectedScan.ts) }}
              </div>
            </div>

            <div>
              <div class="text-xs text-vigils-text-secondary mb-1">
                {{ t("privacy.redacted_snippet") }}
              </div>
              <div
                class="text-sm font-mono text-vigils-text-primary break-all bg-vigils-bg-deep px-3 py-2 rounded border border-vigils-border"
              >
                —
              </div>
            </div>

            <div>
              <div class="text-xs text-vigils-text-secondary mb-1">
                {{ t("privacy.fingerprint") }}
              </div>
              <div class="text-sm font-mono text-vigils-text-primary break-all">
                {{ selectedScan.fingerprint.slice(0, 8) }}
              </div>
            </div>
          </div>
        </PanelCard>
      </div>
    </NSpin>
  </div>
</template>
