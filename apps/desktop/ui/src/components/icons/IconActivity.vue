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
    <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
  </svg>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ size?: number; stroke?: number }>(), { size: 18, stroke: 2 });
</script>
