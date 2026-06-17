<script setup lang="ts">
/**
 * I08b-α2 NotImplemented 占位页 — router 里未实装的路由显式落到这里,
 * 避免 "功能已存在" 的错觉(R1 NICE 修复)。
 */
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { NCard, NSpace, NTag } from "naive-ui";
import { useRoute } from "vue-router";

const { t } = useI18n();
const route = useRoute();
const title = computed<string>(() => {
  const metaTitle = route.meta?.title;
  return typeof metaTitle === "string" ? metaTitle : (route.name as string) ?? "Not implemented";
});
</script>

<template>
  <div class="p-6">
    <NCard class="bg-vigils-bg-panel border-vigils-bg-surface">
      <NSpace vertical :size="12">
        <NTag type="warning">{{ t("notImplemented.badge") }}</NTag>
        <h2 class="text-lg font-semibold text-vigils-text-primary">{{ title }}</h2>
        <p class="text-sm opacity-70">
          {{ t("notImplemented.body") }}
        </p>
      </NSpace>
    </NCard>
  </div>
</template>
