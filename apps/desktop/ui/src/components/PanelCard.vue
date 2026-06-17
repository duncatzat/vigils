<script setup lang="ts">
withDefaults(defineProps<{ padded?: boolean }>(), { padded: true });
</script>

<template>
  <div class="bg-vigils-bg-panel border border-vigils-border rounded-xl overflow-hidden">
    <div
      v-if="$slots.header"
      class="px-5 py-4 border-b border-vigils-border flex items-center justify-between"
    >
      <slot name="header" />
    </div>
    <div :class="padded ? 'p-5' : ''">
      <slot />
    </div>
  </div>
</template>
