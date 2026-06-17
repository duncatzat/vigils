<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    :stroke-width="stroke"
    stroke-linecap="round"
    stroke-linejoin="round"
  >
    <polyline points="6 9 12 15 18 9" />
  </svg>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ size?: number; stroke?: number }>(), { size: 14, stroke: 2 });
</script>
