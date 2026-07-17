<script setup lang="ts">
/**
 * App shell — 指挥舱侧栏 + router-view。
 *
 * 安全契约(AGENTS.md + ADR 0008):
 * - NConfigProvider 深色优先(darkTheme + 品牌 themeOverrides),对齐官网 vigils.ai 视觉
 * - NDialogProvider + NMessageProvider 供子组件 useDialog / useMessage
 * - 禁 v-html / innerHTML(ESLint rule 守门;<img> 为静态模板标记)
 *
 * UI 全改(2026-06 R2):官方品牌资产(logo + 22 徽记)替手画 SVG;IA 三层分组
 * (Protection 家 / 监控 / 进阶);深色优先(撤 v0.14 三态 toggle,根治 theme bug)。
 */
import {
  NConfigProvider,
  NLayout,
  NLayoutSider,
  NMenu,
  NDialogProvider,
  NMessageProvider,
  NButton,
  darkTheme,
  zhCN,
  dateZhCN,
  type GlobalThemeOverrides,
} from "naive-ui";
import { RouterLink, RouterView, useRoute, useRouter } from "vue-router";
import { computed, h, ref, onMounted } from "vue";
import { useI18n } from "vue-i18n";
import { useGlobalShortcuts } from "@/composables/useGlobalShortcuts";
import ShortcutHelpModal from "@/components/ShortcutHelpModal.vue";
import { LOGO, navEmblemIcon } from "@/brand";
import { setLocale, SUPPORTED_LOCALES, type SupportedLocale } from "@/i18n";

const route = useRoute();
const router = useRouter();
const { t, locale } = useI18n();

// Naive UI 内建文案随 app locale(空表 "No Data"、分页等;null = 默认英文)。
const naiveLocale = computed(() => (locale.value === "zh-CN" ? zhCN : null));
const naiveDateLocale = computed(() => (locale.value === "zh-CN" ? dateZhCN : null));

// 语言切换(zh-CN ↔ en-US 二态循环)
function cycleLocale(): void {
  const idx = SUPPORTED_LOCALES.findIndex((l) => l.code === locale.value);
  const next = SUPPORTED_LOCALES[(idx + 1) % SUPPORTED_LOCALES.length];
  setLocale(next.code as SupportedLocale);
}
const currentLocaleShort = computed(() => {
  const entry = SUPPORTED_LOCALES.find((l) => l.code === locale.value);
  return entry?.short ?? "EN";
});
const currentLocaleLabel = computed(() => {
  const entry = SUPPORTED_LOCALES.find((l) => l.code === locale.value);
  return entry?.label ?? "English";
});

// 全局快捷键(g-chord 导航 / `/` 搜索 / `?` 帮助)
const shortcutHelpOpen = ref(false);
useGlobalShortcuts({ router, helpOpen: shortcutHelpOpen });

// ─────────────── 深色优先:固定 darkTheme + 品牌 themeOverrides ───────────────
const themeOverrides: GlobalThemeOverrides = {
  common: {
    primaryColor: "#05d9e8",
    primaryColorHover: "#67e8f9",
    primaryColorPressed: "#04b4c4",
    primaryColorSuppl: "#05d9e8",
    infoColor: "#05d9e8",
    successColor: "#00ff9d",
    warningColor: "#facc15",
    errorColor: "#ff2a6d",
    bodyColor: "#0a0a0f",
    cardColor: "#111118",
    modalColor: "#13131b",
    popoverColor: "#1a1f2e",
    tableHeaderColor: "#13131b",
    inputColor: "rgba(255, 255, 255, 0.03)",
    borderColor: "#232837",
    dividerColor: "#232837",
    textColorBase: "#e2e8f0",
    textColor1: "#e2e8f0",
    textColor2: "#cbd5e1",
    textColor3: "#64748b",
    borderRadius: "10px",
    borderRadiusSmall: "8px",
    fontFamily:
      '"Inter", system-ui, -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
    fontFamilyMono:
      'ui-monospace, "JetBrains Mono", "SF Mono", "Cascadia Code", Consolas, monospace',
  },
  Menu: {
    itemColorActive: "rgba(5, 217, 232, 0.10)",
    itemColorActiveHover: "rgba(5, 217, 232, 0.16)",
    itemColorActiveCollapsed: "rgba(5, 217, 232, 0.10)",
    itemTextColorActive: "#05d9e8",
    itemTextColorActiveHover: "#67e8f9",
    itemTextColorHover: "#e2e8f0",
    itemHeight: "42px",
    borderRadius: "10px",
  },
  Layout: {
    color: "transparent",
    siderColor: "rgba(13, 16, 24, 0.62)",
  },
};

// 菜单:Protection(家)+ 监控组 + 进阶组。icon = 官方徽记(每模块色辉光)。
const menuOptions = computed(() => [
  {
    label: () => h(RouterLink, { to: "/protection" }, () => t("nav.protection")),
    key: "protection",
    icon: navEmblemIcon("protection"),
  },
  {
    type: "group" as const,
    key: "g-monitor",
    label: t("nav.group_monitor"),
    children: [
      {
        label: () => h(RouterLink, { to: "/approvals" }, () => t("nav.approvals")),
        key: "approvals",
        icon: navEmblemIcon("approvals"),
      },
      {
        label: () => h(RouterLink, { to: "/activity" }, () => t("nav.activity")),
        key: "activity",
        icon: navEmblemIcon("activity"),
      },
      {
        label: () => h(RouterLink, { to: "/privacy" }, () => t("nav.privacy")),
        key: "privacy",
        icon: navEmblemIcon("privacy"),
      },
    ],
  },
  {
    type: "group" as const,
    key: "g-advanced",
    label: t("nav.group_advanced"),
    children: [
      {
        label: () => h(RouterLink, { to: "/servers" }, () => t("nav.servers")),
        key: "servers",
        icon: navEmblemIcon("servers"),
      },
      {
        label: () => h(RouterLink, { to: "/sessions" }, () => t("nav.sessions")),
        key: "sessions",
        icon: navEmblemIcon("sessions"),
      },
    ],
  },
  {
    type: "group" as const,
    key: "g-system",
    label: t("nav.group_system"),
    children: [
      {
        label: () => h(RouterLink, { to: "/settings" }, () => t("nav.settings")),
        key: "settings",
        icon: navEmblemIcon("settings"),
      },
    ],
  },
]);

const selectedKey = computed(() => {
  const name = (route.name as string | undefined) ?? "protection";
  return name;
});

onMounted(() => {
  document.documentElement.dataset.theme = "dark";
});
</script>

<template>
  <NConfigProvider
    :theme="darkTheme"
    :theme-overrides="themeOverrides"
    :locale="naiveLocale"
    :date-locale="naiveDateLocale"
  >
    <NMessageProvider>
      <NDialogProvider>
        <NLayout has-sider class="h-screen">
          <NLayoutSider bordered :width="212" class="vigil-sider">
            <!-- 品牌头:官方 logo 徽记 + VIGILS 字标 -->
            <div class="brand">
              <img class="brand-logo" :src="LOGO" alt="Vigils" />
              <div class="brand-text">
                <div class="brand-name">VIGILS</div>
                <div class="brand-sub">{{ t("sidebar.app_subtitle") }}</div>
              </div>
            </div>

            <NMenu
              :options="menuOptions"
              :value="selectedKey"
              :indent="18"
              class="vigil-menu"
            />

            <!-- 底部:快捷键 + 语言 -->
            <div class="sidebar-footer">
              <NButton
                size="small"
                quaternary
                block
                data-testid="shortcut-help-toggle"
                title="Keyboard shortcuts (press ?)"
                @click="shortcutHelpOpen = true"
              >
                <span class="footer-btn">⌘ {{ t("sidebar.shortcuts_button") }}</span>
              </NButton>
              <NButton
                size="small"
                quaternary
                block
                data-testid="locale-toggle"
                :title="t('sidebar.language_tooltip', { label: currentLocaleLabel })"
                @click="cycleLocale"
              >
                <span class="footer-btn">🌐 {{ currentLocaleShort }}</span>
              </NButton>
            </div>
          </NLayoutSider>

          <NLayout class="vigil-main">
            <RouterView />
          </NLayout>
        </NLayout>

        <ShortcutHelpModal v-model:show="shortcutHelpOpen" />
      </NDialogProvider>
    </NMessageProvider>
  </NConfigProvider>
</template>

<style scoped>
.vigil-sider {
  position: relative;
  backdrop-filter: blur(8px);
}
.brand {
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 16px 16px 14px;
  border-bottom: 1px solid var(--vigil-border);
}
.brand-logo {
  width: 34px;
  height: 34px;
  flex: 0 0 34px;
  filter: drop-shadow(0 0 6px rgba(5, 217, 232, 0.55));
}
.brand-name {
  font-family: var(--vigil-mono);
  font-weight: 700;
  letter-spacing: 3.5px;
  font-size: 15px;
  line-height: 1.1;
  color: var(--vigil-text);
}
.brand-sub {
  margin-top: 3px;
  font-size: 10.5px;
  letter-spacing: 0.3px;
  color: var(--vigil-text-secondary);
}
.vigil-menu {
  padding: 8px 8px;
}
.sidebar-footer {
  position: absolute;
  bottom: 10px;
  left: 8px;
  right: 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.footer-btn {
  font-family: var(--vigil-mono);
  font-size: 11px;
  letter-spacing: 0.4px;
}
</style>
