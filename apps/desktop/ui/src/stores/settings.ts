/**
 * Vigils Desktop — 用户偏好设置 store。
 *
 * 持久化键:
 * - `vigils-theme-mode`: dark | light | system
 * - `vigil-locale`: zh-CN | en-US
 * - `vigils-default-posture`: monitor | enforce
 * - `vigils-auto-approve-first-seen`: boolean
 * - `vigils-redact-tool-results`: boolean
 * - `vigils-polling-interval-ms`: number
 */
import { defineStore } from "pinia";
import { ref, computed } from "vue";
import { setLocale, type SupportedLocale, SUPPORTED_LOCALES } from "@/i18n";

type ThemeMode = "dark" | "light" | "system";
type DefaultPosture = "monitor" | "enforce";

function systemPrefersLight(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return !window.matchMedia("(prefers-color-scheme: dark)").matches;
  } catch {
    return false;
  }
}

function applyRootThemeClass(isLight: boolean): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  if (isLight) {
    root.classList.add("light");
  } else {
    root.classList.remove("light");
  }
}

function readStoredString<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    if (v && (allowed as readonly string[]).includes(v)) return v as T;
  } catch { /* ignore */ }
  return fallback;
}

function writeStoredString(key: string, v: string): void {
  try {
    localStorage.setItem(key, v);
  } catch { /* ignore */ }
}

function readStoredBool(key: string, fallback: boolean): boolean {
  try {
    const v = localStorage.getItem(key);
    if (v === "true") return true;
    if (v === "false") return false;
  } catch { /* ignore */ }
  return fallback;
}

function writeStoredBool(key: string, v: boolean): void {
  writeStoredString(key, String(v));
}

function readStoredNumber(key: string, fallback: number): number {
  try {
    const v = localStorage.getItem(key);
    const n = v ? Number(v) : NaN;
    if (!Number.isNaN(n)) return n;
  } catch { /* ignore */ }
  return fallback;
}

function writeStoredNumber(key: string, v: number): void {
  writeStoredString(key, String(v));
}

export const useSettingsStore = defineStore("settings", () => {
  const themeMode = ref<ThemeMode>(readStoredString("vigils-theme-mode", ["dark", "light", "system"] as const, "dark"));
  const locale = ref<SupportedLocale>(readStoredString("vigil-locale", ["zh-CN", "en-US"] as const, "en-US"));

  const defaultPosture = ref<DefaultPosture>(readStoredString("vigils-default-posture", ["monitor", "enforce"] as const, "monitor"));
  const autoApproveFirstSeen = ref<boolean>(readStoredBool("vigils-auto-approve-first-seen", false));
  const redactToolResults = ref<boolean>(readStoredBool("vigils-redact-tool-results", true));
  const pollingIntervalMs = ref<number>(readStoredNumber("vigils-polling-interval-ms", 1000));

  const currentLocaleLabel = computed(() =>
    SUPPORTED_LOCALES.find((l) => l.code === locale.value)?.label ?? "English",
  );
  const currentLocaleShort = computed(() =>
    SUPPORTED_LOCALES.find((l) => l.code === locale.value)?.short ?? "EN",
  );

  const effectiveTheme = computed<"dark" | "light">(() =>
    themeMode.value === "system" ? (systemPrefersLight() ? "light" : "dark") : themeMode.value,
  );
  const isLight = computed(() => effectiveTheme.value === "light");

  function applyTheme(): void {
    applyRootThemeClass(isLight.value);
  }

  function setTheme(mode: ThemeMode): void {
    themeMode.value = mode;
    writeStoredString("vigils-theme-mode", mode);
    applyTheme();
  }

  function cycleTheme(): void {
    const order: ThemeMode[] = ["dark", "light", "system"];
    const next = order[(order.indexOf(themeMode.value) + 1) % order.length];
    setTheme(next);
  }

  function setLocaleCode(code: SupportedLocale): void {
    locale.value = code;
    setLocale(code);
    writeStoredString("vigil-locale", code);
  }

  function cycleLocale(): void {
    const codes: SupportedLocale[] = ["zh-CN", "en-US"];
    const next = codes[(codes.indexOf(locale.value) + 1) % codes.length];
    setLocaleCode(next);
  }

  // 启动时同步 i18n locale(处理从 localStorage 恢复的偏好)
  setLocaleCode(locale.value);
  // 启动时应用主题类到 <html>
  applyTheme();

  function setDefaultPosture(v: DefaultPosture): void {
    defaultPosture.value = v;
    writeStoredString("vigils-default-posture", v);
  }

  function setAutoApproveFirstSeen(v: boolean): void {
    autoApproveFirstSeen.value = v;
    writeStoredBool("vigils-auto-approve-first-seen", v);
  }

  function setRedactToolResults(v: boolean): void {
    redactToolResults.value = v;
    writeStoredBool("vigils-redact-tool-results", v);
  }

  function setPollingIntervalMs(v: number): void {
    pollingIntervalMs.value = v;
    writeStoredNumber("vigils-polling-interval-ms", v);
  }

  return {
    themeMode,
    effectiveTheme,
    isLight,
    locale,
    currentLocaleLabel,
    currentLocaleShort,
    defaultPosture,
    autoApproveFirstSeen,
    redactToolResults,
    pollingIntervalMs,
    setTheme,
    cycleTheme,
    applyTheme,
    setLocaleCode,
    cycleLocale,
    setDefaultPosture,
    setAutoApproveFirstSeen,
    setRedactToolResults,
    setPollingIntervalMs,
  };
});
