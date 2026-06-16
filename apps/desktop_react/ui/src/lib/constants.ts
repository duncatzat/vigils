export const APP_NAME = "Vigils";

export const NAV_ITEMS = [
  { id: "protection", icon: "Shield" },
  { id: "approvals", icon: "CheckCircle" },
  { id: "activity", icon: "Activity" },
  { id: "sessions", icon: "Monitor" },
  { id: "servers", icon: "Server" },
  { id: "privacy", icon: "EyeOff" },
  { id: "sandbox", icon: "Box" },
  { id: "settings", icon: "Settings" },
] as const;

export type NavId = (typeof NAV_ITEMS)[number]["id"];

export const POLL_INTERVAL_MS = 1000;

export const DECISION_COLORS: Record<string, string> = {
  ALLOW: "text-vigils-green",
  DENY: "text-vigils-red",
  APPROVE: "text-vigils-yellow",
  MONITOR: "text-vigils-cyan",
};

export const RISK_COLORS: Record<string, string> = {
  low: "text-vigils-green",
  medium: "text-vigils-yellow",
  high: "text-vigils-red",
  critical: "text-vigils-red",
};
