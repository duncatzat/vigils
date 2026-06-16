import { create } from "zustand";
import { persist } from "zustand/middleware";

export type ThemeMode = "dark" | "light" | "system";
export type Locale = "zh-CN" | "en-US";
export type ProtectionPosture = "monitor" | "enforce";

interface UiState {
  theme: ThemeMode;
  locale: Locale;
  sidebarCollapsed: boolean;
  posture: ProtectionPosture;
  autoApproveFirstSeenTools: boolean;
  redactToolResults: boolean;
  outboxEnabled: boolean;
  approvalWaitSecs: number;
  upstreamListTimeoutSecs: number;
  upstreamCallTimeoutSecs: number;
  pollingIntervalMs: number;
  setTheme: (theme: ThemeMode) => void;
  setLocale: (locale: Locale) => void;
  toggleSidebar: () => void;
  setPosture: (posture: ProtectionPosture) => void;
  setAutoApproveFirstSeenTools: (enabled: boolean) => void;
  setRedactToolResults: (enabled: boolean) => void;
  setOutboxEnabled: (enabled: boolean) => void;
  setApprovalWaitSecs: (secs: number) => void;
  setUpstreamListTimeoutSecs: (secs: number) => void;
  setUpstreamCallTimeoutSecs: (secs: number) => void;
  setPollingIntervalMs: (ms: number) => void;
}

export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      theme: "system",
      locale: "zh-CN",
      sidebarCollapsed: false,
      // 与 vigil-mcp::HubConfig 默认值保持一致,避免启动前后端/前端状态分叉。
      posture: "enforce",
      autoApproveFirstSeenTools: false,
      redactToolResults: false,
      outboxEnabled: true,
      approvalWaitSecs: 300,
      upstreamListTimeoutSecs: 10,
      upstreamCallTimeoutSecs: 30,
      pollingIntervalMs: 1000,
      setTheme: (theme) => set({ theme }),
      setLocale: (locale) => set({ locale }),
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setPosture: (posture) => set({ posture }),
      setAutoApproveFirstSeenTools: (enabled) => set({ autoApproveFirstSeenTools: enabled }),
      setRedactToolResults: (enabled) => set({ redactToolResults: enabled }),
      setOutboxEnabled: (enabled) => set({ outboxEnabled: enabled }),
      setApprovalWaitSecs: (secs) => set({ approvalWaitSecs: Math.max(1, Math.min(3600, secs)) }),
      setUpstreamListTimeoutSecs: (secs) => set({ upstreamListTimeoutSecs: Math.max(1, Math.min(300, secs)) }),
      setUpstreamCallTimeoutSecs: (secs) => set({ upstreamCallTimeoutSecs: Math.max(1, Math.min(300, secs)) }),
      setPollingIntervalMs: (ms) => set({ pollingIntervalMs: Math.max(500, Math.min(30000, ms)) }),
    }),
    { name: "vigils-ui" }
  )
);

export function resolveTheme(mode: ThemeMode): "dark" | "light" {
  if (mode !== "system") return mode;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function usePollInterval() {
  return useUiStore((s) => s.pollingIntervalMs);
}
