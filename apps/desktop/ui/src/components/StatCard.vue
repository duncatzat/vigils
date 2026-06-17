<script setup lang="ts">
type ColorKey = "cyan" | "green" | "red" | "yellow" | "purple";

interface Props {
  label: string;
  value: string | number;
  subtext?: string;
  color: ColorKey;
}

defineProps<Props>();

const textColor: Record<ColorKey, string> = {
  cyan: "text-vigils-cyan",
  green: "text-vigils-green",
  red: "text-vigils-red",
  yellow: "text-vigils-yellow",
  purple: "text-vigils-purple",
};
</script>

<template>
  <div class="bg-vigils-bg-panel border border-vigils-border rounded-xl p-5">
    <div class="text-xs text-vigils-text-secondary uppercase tracking-wider mb-3">{{ label }}</div>
    <div class="text-4xl font-bold font-mono" :class="textColor[color]">{{ value }}</div>
    <div v-if="subtext" class="text-xs text-vigils-text-muted mt-2">{{ subtext }}</div>
  </div>
</template>
