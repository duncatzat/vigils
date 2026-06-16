import { useTranslation } from "react-i18next";
import { useUiStore } from "@/stores/themeStore";

export function TopBar() {
  const { locale, setLocale, theme, setTheme, posture } = useUiStore();
  const { t, i18n } = useTranslation();

  const handleLocaleChange = (value: "zh-CN" | "en-US") => {
    setLocale(value);
    i18n.changeLanguage(value);
  };

  const postureColor = posture === "monitor" ? "text-vigils-cyan" : "text-vigils-red";
  const postureKey = posture === "monitor" ? "posture.monitor" : "posture.enforce";

  return (
    <header className="flex h-16 items-center justify-between border-b border-vigils-bg-surface bg-vigils-bg-panel px-6">
      <h1 className="text-lg font-semibold text-vigils-text-primary">
        {t("appName")}
      </h1>
      <div className="flex items-center gap-3">
        <span className={`rounded-full bg-vigils-bg-tertiary px-3 py-1 text-xs font-mono ${postureColor}`}>
          ● {t(postureKey)}
        </span>
        <select
          value={locale}
          onChange={(e) => handleLocaleChange(e.target.value as "zh-CN" | "en-US")}
          className="rounded-md border border-vigils-bg-surface bg-vigils-bg-tertiary px-2 py-1 text-sm text-vigils-text-secondary outline-none"
        >
          <option value="zh-CN">中</option>
          <option value="en-US">EN</option>
        </select>
        <select
          value={theme}
          onChange={(e) => setTheme(e.target.value as "dark" | "light" | "system")}
          className="rounded-md border border-vigils-bg-surface bg-vigils-bg-tertiary px-2 py-1 text-sm text-vigils-text-secondary outline-none"
        >
          <option value="system">{t("theme.system")}</option>
          <option value="dark">{t("theme.dark")}</option>
          <option value="light">{t("theme.light")}</option>
        </select>
      </div>
    </header>
  );
}
