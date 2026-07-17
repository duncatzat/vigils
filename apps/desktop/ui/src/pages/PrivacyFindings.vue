<script setup lang="ts">
/**
 * ISS-017 — Privacy Findings 聚合面板(R2 Aegis 指挥舱)。
 *
 * 视图布局:
 *   1) 顶部:全局 label × count 标签徽章("一眼看到今天拦了哪些 PII")
 *   2) 下方:最近 N 条 scans 表格(ts / source / scan_id 缩短 / fingerprint 缩短 / finding 数)
 *      - 行点击预留(phase 2 加溯源 drawer)
 *
 * **绝不展原文**:DTO 仅含 metadata 类字段。fingerprint 显示 8 字符前缀(可识别但
 * 不可逆),session_id / scan_id 缩短到首 8 字符 + 末 4 字符。
 *
 * 安全契约(延续 ApprovalDetailDrawer α3):
 *   - 所有字符串 `{{ }}` 插值,Vue 默认转义,XSS 安全
 *   - 不引入 v-html / innerHTML
 *   - 后端 ipc.listPrivacyFindings 失败 → 显示 error 提示,不崩页
 */
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  NDataTable,
  NTag,
  NSpin,
  type DataTableColumns,
} from "naive-ui";
import { h } from "vue";
import { useI18n } from "vue-i18n";
import {
  listPrivacyFindings,
  type PrivacyFindingDto,
  type PrivacyFindingsDto,
  type RedactionScanSummaryDto,
} from "@/api/ipc";
import WindowCard from "@/components/WindowCard.vue";
import StatusPill from "@/components/StatusPill.vue";
import { EMBLEM } from "@/brand";

const { t } = useI18n();
const data = ref<PrivacyFindingsDto | null>(null);
const loading = ref(true);
const errorMsg = ref<string | null>(null);

async function refresh() {
  loading.value = true;
  errorMsg.value = null;
  try {
    data.value = await listPrivacyFindings({ limit_recent_scans: 100 });
  } catch (e) {
    errorMsg.value = String(e);
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);

// 30s 自动刷新(轻量轮询;UI 长时间打开仍跟踪新 scan)。
const refreshTimer = setInterval(refresh, 30_000);
onUnmounted(() => clearInterval(refreshTimer));

/** Label 徽章颜色映射 — 与 ApprovalDetailDrawer.privacyTagType 同源(ISS-014)。
 *  字面量与 vigil_redaction::PrivacyLabel::as_str() 对齐(无 `private_` 前缀)。 */
function privacyTagType(
  label: string,
): "default" | "warning" | "success" | "error" | "info" {
  switch (label) {
    case "secret":
    case "account_number":
      return "error";
    case "email":
    case "phone":
    case "person":
    case "address":
    case "url":
    case "date":
      return "warning";
    default:
      return "default";
  }
}

/** Source 标签:tool_arg(firewall preflight) / paste(扩展粘贴) / tool_output(回吐) / export */
function sourceTagType(
  source: string,
): "default" | "warning" | "success" | "error" | "info" {
  switch (source) {
    case "tool_arg":
      return "info";
    case "paste":
      return "default";
    case "tool_output":
      return "warning";
    case "export":
      return "success";
    default:
      return "default";
  }
}

/** UUID/Hex 缩短显示:首 8 + … + 末 4(总 14 字符,适合表格列宽)。 */
function shortId(id: string): string {
  if (id.length <= 14) return id;
  return `${id.slice(0, 8)}…${id.slice(-4)}`;
}

/** Unix 秒 → 本地时间字符串 */
function formatTs(ts: number): string {
  if (!ts || ts <= 0) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}

const columns = computed<DataTableColumns<RedactionScanSummaryDto>>(() => [
  {
    title: t("privacy.col_time"),
    key: "ts",
    width: 170,
    render: (row) => formatTs(row.ts),
  },
  {
    title: t("privacy.col_source"),
    key: "source",
    width: 110,
    render: (row) =>
      h(
        NTag,
        { size: "small", type: sourceTagType(row.source), bordered: false },
        () => row.source,
      ),
  },
  {
    title: t("privacy.col_findings"),
    key: "finding_count",
    width: 100,
    render: (row) => `${row.finding_count}`,
  },
  {
    title: t("privacy.col_scan_id"),
    key: "scan_id",
    width: 160,
    render: (row) =>
      h(
        "code",
        { class: "text-xs", title: row.scan_id },
        shortId(row.scan_id),
      ),
  },
  {
    title: t("privacy.col_session"),
    key: "session_id",
    width: 160,
    render: (row) =>
      h(
        "code",
        { class: "text-xs opacity-70", title: row.session_id },
        shortId(row.session_id),
      ),
  },
  {
    title: t("privacy.col_fingerprint"),
    key: "fingerprint",
    render: (row) =>
      h(
        "code",
        { class: "text-xs opacity-50", title: row.fingerprint },
        row.fingerprint.slice(0, 8),
      ),
  },
]);
</script>

<template>
  <div class="privacy">
    <!-- 顶部细条:页名 + 元数据契约徽 + 刷新 -->
    <div class="phead">
      <span class="ptitle">{{ t("privacy.page_title") }}</span>
      <span class="pright">
        <StatusPill tone="cyan">{{ t("privacy.page_subtitle_strong") }}</StatusPill>
      </span>
    </div>

    <!-- 人话标题:盾徽 + 短标题 + 小副标(精简,不再把整段描述塞进 h1)-->
    <div class="headline">
      <h1>
        <img class="emblem" :src="EMBLEM('lock')" alt="" />
        {{ t("privacy.hero_title") }}
      </h1>
      <p>{{ t("privacy.hero_subtitle") }}</p>
    </div>

    <!-- 错误态(设计化,不裸露 TypeError 当首屏)-->
    <div v-if="errorMsg" class="errcard" data-testid="privacy-load-failed">
      <span class="ei">!</span>
      <div class="ec">
        <div class="et">{{ t("privacy.load_error", { msg: errorMsg }) }}</div>
      </div>
    </div>

    <NSpin :show="loading">
      <!-- 顶部:全局 label 聚合(彩色计数胶囊)-->
      <WindowCard
        title="findings · by label"
        class="block"
        data-testid="privacy-findings-by-label"
      >
        <div class="card-head">
          <span class="ch-title">{{ t("privacy.by_label_title") }}</span>
        </div>
        <div
          v-if="!data || data.by_label_total.length === 0"
          class="empty"
        >
          {{ t("privacy.by_label_empty") }}
        </div>
        <div v-else class="chips">
          <StatusPill
            v-for="f in (data.by_label_total as PrivacyFindingDto[])"
            :key="f.label"
            :tone="
              privacyTagType(f.label) === 'error'
                ? 'red'
                : privacyTagType(f.label) === 'warning'
                  ? 'yellow'
                  : privacyTagType(f.label) === 'success'
                    ? 'green'
                    : 'cyan'
            "
            :data-testid="`privacy-by-label-${f.label}`"
          >
            {{ f.label }} <span class="x">×</span> {{ f.count }}
          </StatusPill>
        </div>
      </WindowCard>

      <!-- 下方:最近 N 条 scans(品牌化表格)-->
      <WindowCard
        title="findings · recent scans"
        class="block"
        data-testid="privacy-findings-recent-scans"
      >
        <div class="card-head">
          <span class="ch-title">{{ t("privacy.recent_scans_title") }}</span>
        </div>
        <div class="ndt-brand">
          <NDataTable
            :columns="columns"
            :data="data?.recent_scans ?? []"
            :bordered="false"
            size="small"
            :max-height="600"
            virtual-scroll
          />
        </div>
      </WindowCard>
    </NSpin>
  </div>
</template>

<style scoped>
.privacy {
  max-width: 1080px;
  margin: 0 auto;
  padding: 18px 28px 40px;
}

/* 顶部细条 */
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

/* 人话标题 */
.headline {
  text-align: center;
  margin: 8px 0 20px;
}
.headline h1 {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  font-size: 24px;
  font-weight: 700;
  letter-spacing: 0.3px;
  color: var(--vigil-text);
  margin: 0;
}
.headline p {
  margin: 6px 0 0;
  font-family: var(--vigil-mono);
  font-size: 12.5px;
  color: var(--vigil-text-secondary);
}
.headline .emblem {
  width: 30px;
  height: 30px;
  display: block;
  filter: drop-shadow(0 0 6px rgba(244, 114, 182, 0.55));
}

.block {
  margin-top: 14px;
}

/* 卡内标题条 */
.card-head {
  display: flex;
  align-items: center;
  margin-bottom: 14px;
}
.ch-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--vigil-text);
}

/* by-label 彩色计数胶囊 */
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}
.chips .x {
  opacity: 0.5;
  margin: 0 0.1em;
}

/* 空态 */
.empty {
  padding: 10px 2px;
  font-family: var(--vigil-mono);
  font-size: 12.5px;
  color: var(--vigil-text-secondary);
}

/* 错误态卡 */
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
  font-family: var(--vigil-mono);
  font-weight: 800;
  font-size: 16px;
  color: var(--vigil-red);
}
.errcard .ec {
  flex: 1;
}
.errcard .et {
  font-size: 13px;
  color: var(--vigil-text);
  word-break: break-all;
}

/* NDataTable 品牌化:深色面板 + 等宽 ID/fingerprint + 收敛分隔线 */
.ndt-brand :deep(.n-data-table) {
  --n-th-color: transparent;
  --n-td-color: transparent;
  --n-merged-th-color: transparent;
  --n-merged-td-color: transparent;
  background: transparent;
  font-size: 12.5px;
}
.ndt-brand :deep(.n-data-table-th) {
  background: rgba(13, 15, 22, 0.6);
  color: var(--vigil-text-secondary);
  font-family: var(--vigil-mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.5px;
  border-bottom: 1px solid var(--vigil-border);
}
.ndt-brand :deep(.n-data-table-td) {
  background: transparent;
  color: var(--vigil-text);
  border-bottom: 1px solid rgba(35, 40, 55, 0.6);
}
.ndt-brand :deep(.n-data-table-tr:hover .n-data-table-td) {
  background: rgba(5, 217, 232, 0.05);
}
/* scan_id / session_id / fingerprint 等宽 + 青调,呼应 protection logline */
.ndt-brand :deep(code) {
  font-family: var(--vigil-mono);
  color: var(--vigil-accent-light);
  font-size: 11.5px;
  letter-spacing: 0.3px;
}
</style>
