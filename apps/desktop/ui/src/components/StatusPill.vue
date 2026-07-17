<script setup lang="ts">
/** 品牌状态胶囊 —— 描边色 + 括号等宽(对齐官网 [ Stable v0.3.0 ] / [ PROTECTED ])。 */
withDefaults(
  defineProps<{
    tone?: "green" | "cyan" | "red" | "yellow" | "purple";
    bracket?: boolean;
  }>(),
  { tone: "cyan", bracket: true },
);
</script>

<template>
  <span class="status-pill" :class="`tone-${tone}`">
    <span v-if="bracket" class="bk">[</span><slot /><span v-if="bracket" class="bk">]</span>
  </span>
</template>

<style scoped>
.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 26px;
  padding: 0 12px;
  border-radius: 999px;
  font-family: var(--vigil-mono);
  font-size: 11.5px;
  font-weight: 600;
  letter-spacing: 0.6px;
  border: 1px solid;
  white-space: nowrap;
}
.bk {
  opacity: 0.55;
  font-weight: 400;
  margin: 0 0.15em;
}
.tone-green {
  color: var(--vigil-green);
  border-color: rgba(0, 255, 157, 0.42);
  background: rgba(0, 255, 157, 0.07);
  box-shadow: 0 0 12px -5px rgba(0, 255, 157, 0.5);
}
.tone-cyan {
  color: var(--vigil-accent);
  border-color: rgba(5, 217, 232, 0.4);
  background: rgba(5, 217, 232, 0.07);
}
.tone-red {
  color: var(--vigil-red);
  border-color: rgba(255, 42, 109, 0.42);
  background: rgba(255, 42, 109, 0.07);
  box-shadow: 0 0 12px -5px rgba(255, 42, 109, 0.5);
}
.tone-yellow {
  color: var(--vigil-yellow);
  border-color: rgba(250, 204, 21, 0.42);
  background: rgba(250, 204, 21, 0.07);
}
.tone-purple {
  color: var(--vigil-purple);
  border-color: rgba(168, 85, 247, 0.42);
  background: rgba(168, 85, 247, 0.07);
}
</style>
