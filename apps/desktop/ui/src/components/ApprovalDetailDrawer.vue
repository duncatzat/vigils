<script setup lang="ts">
/**
 * I08b-α2 Approval detail drawer(R1 BLOCKER 修订版)。
 *
 * **R1 修订**:
 * - `ApprovalRequest` 真实字段是 `effect_vector`(EffectVector struct)而非 `effects_json`
 * - 删除 `resolved_by / resolved_at / resolution_note / scope` 字段访问(这些在
 *   `ApprovalResolution` 而非 `ApprovalRequest` 里;α2 MVP 不展示 resolution 信息)
 * - status 对比使用 PascalCase("Pending" / "Approved" / ...)
 *
 * **安全契约**:
 * - `<pre>{{ effectVectorPretty }}</pre>` Vue 插值默认转义,杜绝 XSS
 * - 任何字符串字段严格走 `{{ }}` 渲染,禁 v-html(ESLint 守)
 * - Approve/Deny/Cancel emit 到 parent,二次确认 dialog 在 parent 做
 */
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import {
  NButton,
  NCard,
  NDrawer,
  NDrawerContent,
  NDescriptions,
  NDescriptionsItem,
  NTag,
  NSpace,
} from "naive-ui";
import { effectKindTagMeta } from "@/api/ipc";
import type { ApprovalDetailDto, ApprovalStatus, EffectKind } from "@/api/ipc";

const { t } = useI18n();

interface Props {
  show: boolean;
  detail: ApprovalDetailDto | null;
  resolving: boolean;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: "update:show", value: boolean): void;
  (e: "approve", approvalId: string): void;
  (e: "deny", approvalId: string): void;
  (e: "cancel", approvalId: string): void;
}>();

const statusTagType = computed<"default" | "warning" | "success" | "error" | "info">(
  () => {
    const s = props.detail?.request.status;
    switch (s) {
      case "Pending":
        return "warning";
      case "Approved":
        return "success";
      case "Denied":
      case "Cancelled":
      case "Expired":
        return "error";
      default:
        return "default";
    }
  },
);

const isPending = computed(() => props.detail?.request.status === "Pending");

/**
 * ISS-014 — PrivacyLabel 字面量到 NTag 颜色的映射。
 * 高风险(secret / account_number)→ error 红;
 * PII(email/phone/person/address/url/date)→ warning 橙;
 * 兜底 default 灰。
 *
 * 字面量集合与 Rust `vigil_redaction::PrivacyLabel::as_str()`(无 `private_` 前缀)
 * + `vigil_audit::ALLOWED_REDACTION_LABELS` 对齐(ISS-021 跨 crate 矩阵 golden 守);
 * 未识别字面量降级 default。
 */
function privacyTagType(label: string): "default" | "warning" | "success" | "error" | "info" {
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

const expiresAtDisplay = computed(() => {
  const ts = props.detail?.request.expires_at;
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
});

/**
 * 把 `effect_vector` 渲染为 pretty-printed JSON —— 保留原文用作透明性附注;
 * 结构化展示走顶部的 typed tags / 列表区(见 template)。
 * Vue `{{ }}` 默认转义,即使字段含恶意 HTML 也只显示为文本。
 */
const effectVectorPretty = computed(() => {
  const ev = props.detail?.request.effect_vector;
  if (!ev) return "";
  try {
    return JSON.stringify(ev, null, 2);
  } catch {
    // EffectVector 是 struct,JSON.stringify 理论不会失败;兜底
    return String(ev);
  }
});

/** β3:`effect_vector.effects` 强类型化为 `EffectKind[]`,UI 按类别渲染 NTag。 */
const effectKinds = computed<EffectKind[]>(
  () => props.detail?.request.effect_vector.effects ?? [],
);

/**
 * 非空副作用列表(paths_read / paths_write / network_hosts / secret_refs / recipients)
 * 的结构化展示数据。仅在非空时显示,空的不渲染节省屏幕空间。
 */
interface EffectListSection {
  key: string;
  label: string;
  items: string[];
  /** NTag 颜色类别 */
  tone: "info" | "warning" | "error" | "default";
}
const effectLists = computed<EffectListSection[]>(() => {
  const ev = props.detail?.request.effect_vector;
  if (!ev) return [];
  const sections: EffectListSection[] = [
    { key: "paths_read", label: t("detail.effect_paths_read"), items: ev.paths_read, tone: "info" },
    { key: "paths_write", label: t("detail.effect_paths_write"), items: ev.paths_write, tone: "warning" },
    { key: "network_hosts", label: t("detail.effect_network_hosts"), items: ev.network_hosts, tone: "warning" },
    { key: "secret_refs", label: t("detail.effect_secret_refs"), items: ev.secret_refs, tone: "error" },
    { key: "recipients", label: t("detail.effect_recipients"), items: ev.recipients, tone: "error" },
  ];
  return sections.filter((s) => s.items.length > 0);
});

function statusLabel(s: ApprovalStatus): string {
  const map: Record<ApprovalStatus, string> = {
    Pending: t("detail.status_pending"),
    Approved: t("detail.status_approved"),
    Denied: t("detail.status_denied"),
    Cancelled: t("detail.status_cancelled"),
    Expired: t("detail.status_expired"),
  };
  return map[s] ?? s;
}
</script>

<template>
  <NDrawer
    :show="show"
    :width="640"
    placement="right"
    @update:show="(v: boolean) => emit('update:show', v)"
  >
    <NDrawerContent :title="t('detail.drawer_title')" closable>
      <div v-if="!detail" class="text-gray-500">{{ t("detail.loading") }}</div>
      <NSpace v-else vertical :size="16">
        <NTag :type="statusTagType">
          {{ statusLabel(detail.request.status) }}
        </NTag>

        <NDescriptions label-placement="left" :column="1" bordered>
          <NDescriptionsItem :label="t('detail.label_approval_id')">
            <code class="text-xs">{{ detail.request.approval_id }}</code>
          </NDescriptionsItem>
          <NDescriptionsItem :label="t('detail.label_session')">
            <code class="text-xs">{{ detail.request.session_id }}</code>
          </NDescriptionsItem>
          <NDescriptionsItem :label="t('detail.label_decision_id')">
            <code class="text-xs">{{ detail.decision_id }}</code>
          </NDescriptionsItem>
          <NDescriptionsItem :label="t('detail.label_invocation_id')">
            <code class="text-xs">{{ detail.invocation_id }}</code>
          </NDescriptionsItem>
          <NDescriptionsItem :label="t('detail.label_title')">
            {{ detail.request.title }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="t('detail.label_summary')">
            {{ detail.request.summary }}
          </NDescriptionsItem>
          <NDescriptionsItem :label="t('detail.label_expires_at')">
            {{ expiresAtDisplay }}
          </NDescriptionsItem>
        </NDescriptions>

        <!--
          ISS-014 (Stage 3 wave-4):Privacy Findings 区块。展 `{label} × {count}`
          标签徽章 —— **绝不展原文**(原文按 ADR §I-9.1 永不入 ledger)。
          空 → 整块隐藏(零 PII 命中是正常状态,不应给用户视觉负担)。
          非空 → 用 NTag 展每个 label,type 按敏感度映射(secret 红 / 其它中性)。
        -->
        <NCard
          v-if="detail.privacy_findings && detail.privacy_findings.length > 0"
          :title="t('detail.privacy_findings_title')"
          size="small"
          data-testid="privacy-findings-card"
        >
          <NSpace>
            <NTag
              v-for="f in detail.privacy_findings"
              :key="f.label"
              size="small"
              :type="privacyTagType(f.label)"
              :bordered="false"
              :data-testid="`privacy-finding-${f.label}`"
            >
              {{ f.label }} × {{ f.count }}
            </NTag>
          </NSpace>
          <div class="text-xs opacity-60 mt-2">
            {{ t("detail.privacy_findings_note") }}
          </div>
        </NCard>

        <!--
          β3:EffectVector 结构化展示。上半 typed tags + destructive/reversible 徽章 +
          分段路径/hosts/secret 列表;下半保留 JSON pretty-print 作为透明性附注。
          所有字符串 `{{ }}` 插值,Vue 默认转义(XSS 安全)。
        -->
        <NCard :title="t('detail.effect_vector_title')" size="small">
          <NSpace vertical :size="12">
            <!-- 1) 副作用种类标签 + destructive/reversible 徽章 -->
            <div>
              <div class="text-xs opacity-70 mb-2">{{ t("detail.effect_kinds_label") }}</div>
              <NSpace>
                <NTag
                  v-for="k in effectKinds"
                  :key="k"
                  size="small"
                  :type="effectKindTagMeta(k).type"
                  :bordered="false"
                  :data-testid="`effect-kind-${k}`"
                >
                  {{ effectKindTagMeta(k).label }}
                  <span class="opacity-60 ml-1 text-[10px]">{{ k }}</span>
                </NTag>
                <NTag
                  v-if="detail.request.effect_vector.destructive"
                  size="small"
                  type="error"
                  data-testid="effect-destructive"
                >
                  {{ t("detail.effect_destructive") }}
                </NTag>
                <NTag
                  v-if="detail.request.effect_vector.reversible"
                  size="small"
                  type="info"
                  data-testid="effect-reversible"
                >
                  {{ t("detail.effect_reversible") }}
                </NTag>
                <span v-if="effectKinds.length === 0" class="text-gray-500 text-sm">
                  {{ t("detail.effect_none") }}
                </span>
              </NSpace>
            </div>

            <!-- 2) 分段列表:仅显示非空部分 -->
            <div v-for="sec in effectLists" :key="sec.key">
              <div class="text-xs opacity-70 mb-1">{{ sec.label }} ({{ sec.items.length }})</div>
              <NSpace>
                <NTag
                  v-for="item in sec.items"
                  :key="item"
                  size="small"
                  :type="sec.tone"
                  :bordered="false"
                  :data-testid="`effect-${sec.key}-item`"
                >
                  <code class="text-xs">{{ item }}</code>
                </NTag>
              </NSpace>
            </div>

            <!-- 3) 原始 JSON 透明附注(便于排错 / 审计员核对字段级细节) -->
            <details>
              <summary class="text-xs opacity-60 cursor-pointer select-none">
                {{ t("detail.effect_raw_summary") }}
              </summary>
              <pre
                class="mt-2 text-xs whitespace-pre-wrap break-all max-h-96 overflow-auto font-mono bg-vigils-bg-deep p-3 rounded border border-vigils-bg-surface"
                data-testid="effect-vector-pre"
              >{{ effectVectorPretty }}</pre>
            </details>
          </NSpace>
        </NCard>

        <!-- 动作按钮:仅 Pending 状态可操作 -->
        <NSpace v-if="isPending" justify="end">
          <NButton
            type="error"
            :disabled="resolving"
            data-testid="action-deny"
            @click="emit('deny', detail.request.approval_id)"
          >
            {{ t("common.deny") }}
          </NButton>
          <NButton
            :disabled="resolving"
            data-testid="action-cancel"
            @click="emit('cancel', detail.request.approval_id)"
          >
            {{ t("common.cancel") }}
          </NButton>
          <NButton
            type="primary"
            :loading="resolving"
            data-testid="action-approve"
            @click="emit('approve', detail.request.approval_id)"
          >
            {{ t("common.approve") }}
          </NButton>
        </NSpace>

        <!-- 非 Pending(已解析):α2 MVP 不展示 resolution 细节
             (ApprovalRequest 不带 resolved_by/scope/note;那些在 ApprovalResolution 里,
              后续 α 通过独立 IPC 拉取并显示) -->
        <NTag v-else type="info" size="small">
          {{ t("detail.resolved_note") }}
        </NTag>
      </NSpace>
    </NDrawerContent>
  </NDrawer>
</template>
