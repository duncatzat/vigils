import { Link, useLocation } from "react-router-dom";
import {
  Shield,
  CheckCircle,
  Activity,
  Monitor,
  Server,
  EyeOff,
  Box,
  Settings,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { NAV_ITEMS, type NavId } from "@/lib/constants";
import { useUiStore } from "@/stores/themeStore";

const iconMap: Record<NavId, React.ElementType> = {
  protection: Shield,
  approvals: CheckCircle,
  activity: Activity,
  sessions: Monitor,
  servers: Server,
  privacy: EyeOff,
  sandbox: Box,
  settings: Settings,
};

export function Sidebar() {
  const location = useLocation();
  const { t } = useTranslation();
  const { sidebarCollapsed } = useUiStore();
  const activeId = location.pathname.replace("/", "") || "protection";

  return (
    <aside
      className={`flex h-full flex-col border-r border-vigils-bg-surface bg-vigils-bg-panel transition-all ${
        sidebarCollapsed ? "w-16" : "w-56"
      }`}
    >
      <div className="flex h-16 items-center gap-3 px-4">
        <div className="flex h-8 w-8 items-center justify-center rounded-full border-2 border-vigils-cyan">
          <span className="text-xs font-bold text-vigils-cyan">V</span>
        </div>
        {!sidebarCollapsed && (
          <span className="font-mono text-sm font-bold tracking-wider text-vigils-text-primary">
            VIGILS
          </span>
        )}
      </div>

      <nav className="flex-1 space-y-1 px-2 py-4">
        {NAV_ITEMS.map((item) => {
          const Icon = iconMap[item.id];
          const isActive = activeId === item.id;
          return (
            <Link
              key={item.id}
              to={`/${item.id}`}
              className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors ${
                isActive
                  ? "bg-vigils-bg-tertiary text-vigils-cyan"
                  : "text-vigils-text-secondary hover:bg-vigils-bg-tertiary hover:text-vigils-text-primary"
              }`}
            >
              <Icon size={18} />
              {!sidebarCollapsed && <span>{t(`nav.${item.id}`)}</span>}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
