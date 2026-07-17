<script setup lang="ts">
/**
 * 八重纵深防御轨道 hero —— Protection 首页核心(对齐官网"引力纵深·八重环防")。
 *
 * 中央 = 官方 logo 盾(呼吸辉光)+ 守护状态胶囊;8 枚官方徽记环绕,每模块语义色。
 * **辉光双态**:静息 = 柔光小灯(在线不抢眼)/ 激活 = 点亮大灯 + 辉光增强 + 脉冲环(用户可感知)。
 * 纯 SVG + CSS(无 WebGL),`prefers-reduced-motion` 下停动画。
 */
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { DEFENSE_RING, EMBLEM, LOGO } from "@/brand";
import StatusPill from "@/components/StatusPill.vue";

const props = withDefaults(
  defineProps<{
    /** 是否受保护(中央状态)。 */
    isProtected: boolean;
    /** "激活"的防御层 key 列表(刚动作 / 告警 → 点亮)。 */
    activeKeys?: string[];
  }>(),
  { activeKeys: () => [] },
);

const { t } = useI18n();

const R = 150;
const CY = 176;

const nodes = computed(() =>
  DEFENSE_RING.map((layer, i) => {
    const a = ((-90 + i * 45) * Math.PI) / 180;
    return {
      ...layer,
      dx: Math.round(Math.cos(a) * R),
      dy: Math.round(Math.sin(a) * R),
      active: props.activeKeys.includes(layer.key),
    };
  }),
);
</script>

<template>
  <section class="orbital" data-testid="orbital-defense">
    <svg class="rings" width="370" height="370" viewBox="0 0 370 370" aria-hidden="true">
      <circle cx="185" cy="185" r="150" fill="none" stroke="rgba(5,217,232,.16)" stroke-width="1" stroke-dasharray="3 7" />
      <circle cx="185" cy="185" r="104" fill="none" stroke="rgba(35,40,55,.9)" stroke-width="1" stroke-dasharray="2 8" />
    </svg>

    <div class="core" :style="{ top: CY + 'px' }">
      <img :src="LOGO" alt="Vigils" />
    </div>
    <div class="corepill" :style="{ top: CY + 70 + 'px' }">
      <StatusPill :tone="isProtected ? 'green' : 'yellow'">
        {{ isProtected ? t("protection.hero.guarding") : t("protection.hero.unprotected") }}
      </StatusPill>
    </div>

    <div
      v-for="n in nodes"
      :key="n.key"
      class="node"
      :class="{ active: n.active }"
      :style="{ '--c': n.color, left: `calc(50% + ${n.dx}px)`, top: `${CY + n.dy}px` }"
    >
      <div class="em">
        <img :src="EMBLEM(n.key)" alt="" />
        <span class="s" />
      </div>
      <div class="lbl">{{ t(`protection.ring.${n.key}`) }}</div>
    </div>
  </section>
</template>

<style scoped>
.orbital {
  position: relative;
  height: 372px;
}
.rings {
  position: absolute;
  left: 50%;
  top: 176px;
  transform: translate(-50%, -50%);
  pointer-events: none;
}
.core {
  position: absolute;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 96px;
  height: 96px;
  display: grid;
  place-items: center;
}
.core::after {
  content: "";
  position: absolute;
  inset: -10px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(5, 217, 232, 0.2), transparent 70%);
}
.core img {
  width: 90px;
  height: 90px;
  position: relative;
  filter: drop-shadow(0 0 9px rgba(5, 217, 232, 0.55));
  animation: breathe 4s ease-in-out infinite;
}
.corepill {
  position: absolute;
  left: 50%;
  transform: translateX(-50%);
  z-index: 4;
}
.node {
  position: absolute;
  transform: translate(-50%, -50%);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  width: 74px;
}
.node .em {
  position: relative;
  width: 46px;
  height: 46px;
  display: grid;
  place-items: center;
}
.node .em::after {
  content: "";
  position: absolute;
  inset: -7px;
  border-radius: 50%;
  background: radial-gradient(circle, var(--c), transparent 66%);
  opacity: 0.13;
  z-index: 0;
}
.node .em img {
  width: 46px;
  height: 46px;
  position: relative;
  z-index: 1;
  filter: drop-shadow(0 0 4px var(--c));
}
.node .em .s {
  position: absolute;
  right: 0;
  top: 0;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--c);
  opacity: 0.5;
  border: 1.5px solid #0a0a0f;
  z-index: 2;
}
.node .lbl {
  font-family: var(--vigil-mono);
  font-size: 10px;
  letter-spacing: 0.5px;
  color: var(--c);
  opacity: 0.62;
}
.node.active .em::after {
  inset: -11px;
  opacity: 0.34;
}
.node.active .em::before {
  content: "";
  position: absolute;
  inset: -5px;
  border-radius: 50%;
  border: 1.5px solid var(--c);
  opacity: 0.45;
  z-index: 0;
  animation: pulse 1.8s ease-out infinite;
}
.node.active .em img {
  filter: drop-shadow(0 0 13px var(--c));
}
.node.active .em .s {
  width: 10px;
  height: 10px;
  opacity: 1;
  box-shadow:
    0 0 11px var(--c),
    0 0 3px #fff;
}
.node.active .lbl {
  opacity: 1;
  text-shadow: 0 0 8px var(--c);
}
@keyframes breathe {
  0%,
  100% {
    transform: scale(1);
  }
  50% {
    transform: scale(1.04);
  }
}
@keyframes pulse {
  0% {
    transform: scale(1);
    opacity: 0.45;
  }
  100% {
    transform: scale(1.5);
    opacity: 0;
  }
}
@media (prefers-reduced-motion: reduce) {
  .core img,
  .node.active .em::before {
    animation: none;
  }
}
</style>
