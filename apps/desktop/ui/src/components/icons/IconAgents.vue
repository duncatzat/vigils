<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="2"
    stroke-linecap="round"
    stroke-linejoin="round"
  >
    <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
    <line x1="4" y1="9" x2="20" y2="9" />
    <line x1="9" y1="15" x2="15" y2="15" />
  </svg>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ size?: number }>(), { size: 20 });
</script>
