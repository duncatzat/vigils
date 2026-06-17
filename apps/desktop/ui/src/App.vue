<script setup lang="ts">
/**
 * Vigils Desktop — App shell (原型图风格)。
 *
 * - 左侧图标 + 文字导航
 * - 顶栏: Logo / 页面标题 / 状态 pill / 语言选择
 * - 主题/语言详情进 Settings 页
 */
import {
  NConfigProvider,
  NDialogProvider,
  NMessageProvider,
  darkTheme,
  lightTheme,
  NSelect,
} from "naive-ui";
import { RouterLink, RouterView, useRoute, useRouter } from "vue-router";
import { computed, ref, onMounted, onUnmounted, type Component } from "vue";
import { useI18n } from "vue-i18n";
import { useSettingsStore } from "@/stores/settings";
import { useGlobalShortcuts } from "@/composables/useGlobalShortcuts";
import ShortcutHelpModal from "@/components/ShortcutHelpModal.vue";

const router = useRouter();

import IconProtection from "@/components/icons/IconProtection.vue";
import IconApprovals from "@/components/icons/IconApprovals.vue";
import IconActivity from "@/components/icons/IconActivity.vue";
import IconSessions from "@/components/icons/IconSessions.vue";
import IconServers from "@/components/icons/IconServers.vue";
import IconPrivacy from "@/components/icons/IconPrivacy.vue";
import IconSandbox from "@/components/icons/IconSandbox.vue";
import IconSettings from "@/components/icons/IconSettings.vue";

const route = useRoute();
const { t } = useI18n();
const settings = useSettingsStore();
const helpOpen = ref(false);
useGlobalShortcuts({ router, helpOpen });

// Naive UI 主题跟随 settings.effectiveTheme(dark/light/system)
const activeTheme = computed(() => (settings.effectiveTheme === "light" ? lightTheme : darkTheme));

const themeOverrides = computed(() => ({
  common: {
    primaryColor: "#05D9E8",
    primaryColorHover: "#67E8F9",
    primaryColorPressed: "#04B6C2",
    primaryColorSuppl: "#05D9E8",
    infoColor: "#05D9E8",
    infoColorHover: "#67E8F9",
    successColor: "#00FF9D",
    successColorHover: "#33FFB1",
    warningColor: "#FACC15",
    errorColor: "#FF2A6D",
    errorColorHover: "#FF5589",
    bodyColor: settings.isLight ? "#ffffff" : "#0B0B0F",
    cardColor: settings.isLight ? "#f8fafc" : "#13131A",
    modalColor: settings.isLight ? "#ffffff" : "#13131A",
    popoverColor: settings.isLight ? "#ffffff" : "#13131A",
    tableColor: settings.isLight ? "#ffffff" : "#13131A",
    tableHeaderColor: settings.isLight ? "#f1f5f9" : "#1A1A24",
    tagColor: settings.isLight ? "#e2e8f0" : "#1A1A24",
    textColorBase: settings.isLight ? "#0f172a" : "#E2E8F0",
    textColor1: settings.isLight ? "#0f172a" : "#E2E8F0",
    textColor2: settings.isLight ? "#334155" : "#94a3b8",
    textColor3: settings.isLight ? "#64748b" : "#64748B",
    borderColor: settings.isLight ? "#e2e8f0" : "#1E1E28",
    dividerColor: settings.isLight ? "#e2e8f0" : "#1E1E28",
  },
}));

// system 模式下监听系统主题变化,实时切换
let mediaQueryList: MediaQueryList | null = null;
const onSystemThemeChange = (): void => {
  if (settings.themeMode === "system") {
    settings.applyTheme();
  }
};
onMounted(() => {
  if (typeof window !== "undefined" && typeof window.matchMedia === "function") {
    mediaQueryList = window.matchMedia("(prefers-color-scheme: dark)");
    mediaQueryList.addEventListener("change", onSystemThemeChange);
  }
});
onUnmounted(() => {
  if (mediaQueryList) {
    mediaQueryList.removeEventListener("change", onSystemThemeChange);
    mediaQueryList = null;
  }
});

// 顶栏主题下拉选项
const themeOptions = computed(() => [
  { label: t("theme.dark"), value: "dark" },
  { label: t("theme.light"), value: "light" },
  { label: t("theme.system"), value: "system" },
]);

interface NavItem {
  key: string;
  name: string;
  label: string;
  icon: Component;
}

const navItems = computed<NavItem[]>(() => [
  { key: "protection", name: "protection", label: t("nav.protection"), icon: IconProtection },
  { key: "approvals", name: "approvals", label: t("nav.approvals"), icon: IconApprovals },
  { key: "activity", name: "activity", label: t("nav.activity"), icon: IconActivity },
  { key: "sessions", name: "sessions", label: t("nav.sessions"), icon: IconSessions },
  { key: "servers", name: "servers", label: t("nav.servers"), icon: IconServers },
  { key: "privacy", name: "privacy", label: t("nav.privacy"), icon: IconPrivacy },
  { key: "sandbox", name: "sandbox", label: t("nav.sandbox"), icon: IconSandbox },
  { key: "settings", name: "settings", label: t("nav.settings"), icon: IconSettings },
]);

const activeNav = computed(() => (route.name as string | undefined) ?? "protection");

const pageTitle = computed(() => {
  const metaTitle = route.meta.title as string | undefined;
  return metaTitle ? t(metaTitle) : "Vigils";
});

const languageOptions = [
  { label: "English", value: "en-US" },
  { label: "中文", value: "zh-CN" },
];

function navClass(name: string): string {
  const base =
    "flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors duration-200";
  if (activeNav.value === name) {
    return `${base} bg-vigils-cyan/10 text-vigils-cyan border-l-2 border-vigils-cyan`;
  }
  return `${base} text-vigils-text-secondary hover:bg-vigils-bg-tertiary hover:text-vigils-text-primary`;
}
</script>

<template>
  <NConfigProvider :theme="activeTheme" :theme-overrides="themeOverrides">
    <NMessageProvider>
      <NDialogProvider>
        <div class="flex h-screen bg-vigils-bg-page text-vigils-text-primary overflow-hidden">
          <!-- Sidebar -->
          <aside class="w-56 flex-shrink-0 flex flex-col bg-vigils-bg-deep border-r border-vigils-border">
            <div class="h-14 flex items-center gap-3 px-5 border-b border-vigils-border">
              <img src="/logo.png" alt="Vigils" class="h-8 w-8 rounded-lg object-contain" />
              <span class="text-sm font-bold tracking-widest text-vigils-text-primary">VIGILS</span>
            </div>

            <nav class="flex-1 overflow-y-auto p-3 space-y-1">
              <RouterLink
                v-for="item in navItems"
                :key="item.key"
                :to="{ name: item.name }"
                :class="navClass(item.name)"
              >
                <span class="flex items-center justify-center w-5 h-5">
                  <component :is="item.icon" />
                </span>
                <span>{{ item.label }}</span>
              </RouterLink>
            </nav>
          </aside>

          <!-- Main -->
          <main class="flex-1 flex flex-col min-w-0 bg-vigils-bg-page">
            <header
              class="h-14 flex items-center justify-between px-6 border-b border-vigils-border bg-vigils-bg-deep/50 backdrop-blur"
            >
              <h1 class="text-base font-semibold text-vigils-text-primary">{{ pageTitle }}</h1>

              <div class="flex items-center gap-4">
                <!-- Status pill -->
                <div
                  class="flex items-center gap-2 px-3 py-1 rounded-full border border-vigils-border bg-vigils-bg-panel text-xs font-medium text-vigils-cyan"
                >
                  <span class="w-1.5 h-1.5 rounded-full bg-vigils-cyan animate-pulse" />
                  <span class="uppercase tracking-wider">{{ t(`settings.posture_${settings.defaultPosture}_label`) }}</span>
                </div>

                <!-- Theme selector -->
                <NSelect
                  :value="settings.themeMode"
                  :options="themeOptions"
                  size="small"
                  style="width: 90px;"
                  @update:value="settings.setTheme"
                />

                <!-- Language selector -->
                <NSelect
                  :value="settings.locale"
                  :options="languageOptions"
                  size="small"
                  style="width: 100px;"
                  @update:value="settings.setLocaleCode"
                />
              </div>
            </header>

            <div class="flex-1 overflow-auto p-6">
              <RouterView />
            </div>
          </main>
        </div>

        <ShortcutHelpModal v-model:show="helpOpen" />
      </NDialogProvider>
    </NMessageProvider>
  </NConfigProvider>
</template>

<style scoped>
/* RouterLink 下划线由全局 tailwind.css 统一去除 */
</style>
