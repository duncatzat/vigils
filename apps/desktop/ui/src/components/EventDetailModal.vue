<script setup lang="ts">
/**
 * I08b-α3 Event detail modal。
 *
 * 展示 EventDetail 的完整 payload(serde_json::Value)+ hash chain。
 * **安全契约**:payload 经 `JSON.stringify(payload, null, 2)` 后走 `<pre>{{ }}`,Vue
 * 默认转义杜绝 XSS;payload 本身已脱敏(vigil-audit 写入时守门)。
 */
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { NModal, NDescriptions, NDescriptionsItem, NCard, NSpace, NTag } from "naive-ui";
import type { EventDetail } from "@/api/ipc";

const { t } = useI18n();

interface Props {
  show: boolean;
  detail: EventDetail | null;
  loading: boolean;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: "update:show", value: boolean): void;
}>();

const createdAtDisplay = computed(() => {
  const ts = props.detail?.created_at;
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
});

const payloadPretty = computed(() => {
  const p = props.detail?.payload;
  if (p === undefined || p === null) return "";
  try {
    return JSON.stringify(p, null, 2);
  } catch {
    return String(p);
  }
});
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    :title="t('eventModal.title')"
    :bordered="false"
    size="huge"
    style="max-width: 800px;"
    @update:show="(v: boolean) => emit('update:show', v)"
  >
    <div v-if="loading" class="text-gray-500">{{ t("eventModal.loading") }}</div>
    <div v-else-if="!detail" class="text-gray-500">{{ t("eventModal.no_event") }}</div>
    <NSpace v-else vertical :size="16">
      <NDescriptions label-placement="left" :column="1" bordered>
        <NDescriptionsItem :label="t('eventModal.label_event_id')">
          <code class="text-xs">{{ detail.event_id }}</code>
        </NDescriptionsItem>
        <NDescriptionsItem :label="t('eventModal.label_session')">
          <code class="text-xs">{{ detail.session_id }}</code>
        </NDescriptionsItem>
        <NDescriptionsItem :label="t('eventModal.label_type')">
          <NTag size="small">{{ detail.event_type }}</NTag>
        </NDescriptionsItem>
        <NDescriptionsItem :label="t('eventModal.label_created_at')">
          {{ createdAtDisplay }}
        </NDescriptionsItem>
        <NDescriptionsItem :label="t('eventModal.label_prev_hash')">
          <code class="text-xs break-all">{{ detail.prev_hash }}</code>
        </NDescriptionsItem>
        <NDescriptionsItem :label="t('eventModal.label_event_hash')">
          <code class="text-xs break-all">{{ detail.event_hash }}</code>
        </NDescriptionsItem>
      </NDescriptions>

      <NCard v-if="detail.redacted_text" :title="t('eventModal.redacted_summary_title')" size="small">
        <div class="text-sm whitespace-pre-wrap break-all">
          {{ detail.redacted_text }}
        </div>
      </NCard>

      <!-- Payload JSON pretty-print;{{ }} 插值天然转义 XSS -->
      <NCard :title="t('eventModal.payload_title')" size="small">
        <pre
          class="text-xs whitespace-pre-wrap break-all max-h-[32rem] overflow-auto font-mono bg-vigils-bg-deep p-3 rounded border border-vigils-bg-surface"
          data-testid="payload-pre"
        >{{ payloadPretty }}</pre>
      </NCard>
    </NSpace>
  </NModal>
</template>
