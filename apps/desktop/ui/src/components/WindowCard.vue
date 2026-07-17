<script setup lang="ts">
/** 设备 mock 窗钮卡片 —— mac 三点 + 标题条 + 主体(对齐官网产品卡的"活设备"质感)。 */
defineProps<{ title?: string }>();
</script>

<template>
  <div class="wcard">
    <div class="chrome">
      <i class="d d1" /><i class="d d2" /><i class="d d3" />
      <span v-if="title" class="ctitle">{{ title }}</span>
      <span class="cright"><slot name="chrome-right" /></span>
    </div>
    <div class="wbody"><slot /></div>
  </div>
</template>

<style scoped>
.wcard {
  background: rgba(17, 17, 24, 0.94);
  border: 1px solid var(--vigil-border);
  border-radius: 14px;
  box-shadow:
    0 1px 0 0 rgba(255, 255, 255, 0.05) inset,
    0 14px 34px -18px rgba(0, 0, 0, 0.8);
  overflow: hidden;
}
.chrome {
  height: 32px;
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 0 13px;
  border-bottom: 1px solid var(--vigil-border);
  background: #0d0f16;
}
.d {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: block;
}
.d1 {
  background: #ff5f57;
}
.d2 {
  background: #febc2e;
}
.d3 {
  background: #28c840;
}
.ctitle {
  margin-left: 7px;
  font-family: var(--vigil-mono);
  font-size: 10.5px;
  color: var(--vigil-text-muted);
  letter-spacing: 0.5px;
}
.cright {
  margin-left: auto;
}
.wbody {
  padding: 16px;
}
</style>
