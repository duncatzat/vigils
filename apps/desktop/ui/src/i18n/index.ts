/**
 * v0.14 Theme D — i18n setup(zh-CN + en-US bilingual)。
 *
 * 设计:
 * - vue-i18n v9 composition mode(`legacy: false`)
 * - 默认 locale = localStorage 'vigil-locale' 或 navigator.language 推断
 * - fallback = 'en-US'(保证未翻译键不报错,展示英文回落)
 * - Naive UI 自带 i18n 由 NConfigProvider :locale 设置(后续扩展;
 *   首批仅替换 page-level 字符串,Naive UI 内置按钮文案沿用默认)
 *
 * 渐进迁移:
 * - First cut(alpha.6):common + approval page 字符串
 * - 后续:activity / sessions / servers / privacy 逐页迁
 */
import { createI18n, type MessageCompiler, type MessageContext } from "vue-i18n";
import zhCN from "./locales/zh-CN.json";
import enUS from "./locales/en-US.json";

// CSP 安全的消息编译器:vue-i18n 默认编译器用 `new Function` 把消息字符串编译成渲染函数,
// 在严格 CSP(`script-src 'self'`,无 'unsafe-eval')下被浏览器拦截 → 桌面 GUI(Tauri
// WebView2)渲染时抛 EvalError、渲染中断 → 黑屏。本编译器只做纯字符串 `{named}` 插值,
// 零 eval,完全 CSP 安全。本项目消息均为简单 UI 串(无 plural `|` / linked `@:` 语法),足够覆盖。
const cspSafeMessageCompiler: MessageCompiler = (message) => {
  const template = typeof message === "string" ? message : String(message);
  return (ctx: MessageContext) =>
    template.replace(/\{(\w+)\}/g, (_m, key: string) => {
      const value = ctx.named(key);
      return value === undefined || value === null ? `{${key}}` : String(value);
    });
};

export type SupportedLocale = "zh-CN" | "en-US";

const LOCALE_STORAGE_KEY = "vigil-locale";
const SUPPORTED: SupportedLocale[] = ["zh-CN", "en-US"];

function detectInitialLocale(): SupportedLocale {
  try {
    const stored = localStorage.getItem(LOCALE_STORAGE_KEY);
    if (stored && SUPPORTED.includes(stored as SupportedLocale)) {
      return stored as SupportedLocale;
    }
  } catch {
    // localStorage disabled — 用 navigator 兜底
  }
  // 默认 en-US,与原型图语言保持一致;用户可在顶栏语言选择器切换。
  return "en-US";
}

export const i18n = createI18n({
  legacy: false,
  // CSP 安全:用自定义编译器替代默认(默认走 new Function,违反 script-src 'self')
  messageCompiler: cspSafeMessageCompiler,
  locale: detectInitialLocale(),
  fallbackLocale: "en-US",
  messages: {
    "zh-CN": zhCN,
    "en-US": enUS,
  },
  // 缺键时 silent(避免 console 噪声);开发模式可打开 missing handler
  missingWarn: false,
  fallbackWarn: false,
});

/** 切换 locale + 持久化 */
export function setLocale(locale: SupportedLocale): void {
  i18n.global.locale.value = locale;
  try {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  } catch {
    // ignore
  }
}

/** 暴露 supported list 供 toggle button */
export const SUPPORTED_LOCALES: ReadonlyArray<{
  code: SupportedLocale;
  label: string;
  short: string;
}> = [
  { code: "zh-CN", label: "中文", short: "中" },
  { code: "en-US", label: "English", short: "EN" },
];
