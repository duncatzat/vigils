<script setup lang="ts">
type ColorKey = "cyan" | "green" | "red" | "yellow" | "purple";

interface Props {
  label: string;
  percent: number;
  color: ColorKey;
}

defineProps<Props>();

const barColor: Record<ColorKey, string> = {
  cyan: "bg-vigils-cyan",
  green: "bg-vigils-green",
  red: "bg-vigils-red",
  yellow: "bg-vigils-yellow",
  purple: "bg-vigils-purple",
};

const textColor: Record<ColorKey, string> = {
  cyan: "text-vigils-cyan",
  green: "text-vigils-green",
  red: "text-vigils-red",
  yellow: "text-vigils-yellow",
  purple: "text-vigils-purple",
};
</script>

<template>
  <div class="space-y-2">
    <div class="flex justify-between text-sm">
      <span class="text-vigils-text-secondary">{{ label }}</span>
      <span class="font-mono font-medium" :class="textColor[color]">{{ percent }}%</span>
    </div>
    <div class="h-2 bg-vigils-bg-tertiary rounded-full overflow-hidden">
      <div
        class="h-full rounded-full transition-all duration-500"
        :class="barColor[color]"
        :style="{ width: Math.max(0, Math.min(100, percent)) + '%' }"
      />
    </div>
  </div>
</template>
