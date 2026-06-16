import { RouterProvider } from "react-router-dom";
import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useTranslation } from "react-i18next";
import { queryClient } from "./lib/queryClient";
import { router } from "./routes";
import { useUiStore, resolveTheme, type ThemeMode } from "./stores/themeStore";

function ThemeInitializer() {
  const { theme } = useUiStore();

  useEffect(() => {
    const apply = (mode: ThemeMode) => {
      const resolved = resolveTheme(mode);
      document.documentElement.classList.remove("dark", "light");
      document.documentElement.classList.add(resolved);
      document.documentElement.style.colorScheme = resolved;
    };

    apply(theme);

    if (theme === "system") {
      const mq = window.matchMedia("(prefers-color-scheme: dark)");
      const handler = () => apply("system");
      mq.addEventListener("change", handler);
      return () => mq.removeEventListener("change", handler);
    }
  }, [theme]);

  return null;
}

function I18nInitializer() {
  const { locale } = useUiStore();
  const { i18n } = useTranslation();

  useEffect(() => {
    if (i18n.language !== locale) {
      i18n.changeLanguage(locale);
    }
  }, [locale, i18n]);

  return null;
}

function LedgerEventsListener() {
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen("ledger-events-changed", () => {
      queryClient.invalidateQueries({ queryKey: ["recentEvents"] });
      queryClient.invalidateQueries({ queryKey: ["pendingApprovals"] });
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      queryClient.invalidateQueries({ queryKey: ["servers"] });
      queryClient.invalidateQueries({ queryKey: ["protectionSummary"] });
      queryClient.invalidateQueries({ queryKey: ["sandboxProfiles"] });
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, []);

  return null;
}

export default function App() {
  return (
    <>
      <ThemeInitializer />
      <I18nInitializer />
      <LedgerEventsListener />
      <RouterProvider router={router} />
    </>
  );
}
