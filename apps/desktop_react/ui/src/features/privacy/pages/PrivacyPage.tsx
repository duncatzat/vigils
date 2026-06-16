import { useQuery } from "@tanstack/react-query";
import { listPrivacyFindings } from "@/lib/tauri";
import { usePollInterval } from "@/stores/themeStore";
import { useTranslation } from "react-i18next";

export function PrivacyPage() {
  const { t } = useTranslation();
  const pollMs = usePollInterval();
  const { data: findings } = useQuery({
    queryKey: ["privacyFindings"],
    queryFn: () => listPrivacyFindings({ limit_recent_scans: 50 }),
    refetchInterval: pollMs,
  });

  const total = findings?.by_label_total.reduce((sum, f) => sum + f.count, 0) ?? 0;

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: t("privacy.totalFindings"), value: total, color: "text-vigils-red" },
          { label: t("privacy.recentScans"), value: findings?.recent_scans.length ?? 0, color: "text-vigils-cyan" },
          { label: t("protection.topLabel"), value: findings?.by_label_total[0]?.label ?? "-", color: "text-vigils-yellow" },
          { label: t("privacy.topCount"), value: findings?.by_label_total[0]?.count ?? 0, color: "text-vigils-red" },
        ].map((kpi) => (
          <div key={kpi.label} className="vigil-card p-4">
            <div className="text-xs font-medium uppercase tracking-wider text-vigils-text-secondary">{kpi.label}</div>
            <div className={`mt-2 text-3xl font-bold ${kpi.color}`}>{kpi.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="vigil-card p-5">
          <h3 className="text-sm font-bold text-vigils-text-primary">{t("privacy.findingsByLabel")}</h3>
          <table className="mt-4 w-full">
            <thead>
              <tr>
                {[t("privacy.label"), t("privacy.count")].map((h) => (
                  <th key={h} className="vigil-table-header pb-2 text-left">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-vigils-bg-surface">
              {findings?.by_label_total.map((f) => (
                <tr key={f.label}>
                  <td className="vigil-table-cell font-bold text-vigils-red">{f.label}</td>
                  <td className="vigil-table-cell">{f.count}</td>
                </tr>
              )) ?? (
                <tr>
                  <td colSpan={2} className="py-6 text-center text-sm text-vigils-text-muted">{t("privacy.noFindings")}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="vigil-card p-5">
          <h3 className="text-sm font-bold text-vigils-text-primary">{t("privacy.recentScans")}</h3>
          <div className="mt-4 space-y-3">
            {findings?.recent_scans.slice(0, 5).map((scan) => (
              <div key={scan.scan_id} className="rounded-lg bg-vigils-bg-tertiary p-3">
                <div className="text-sm font-bold text-vigils-text-primary">{scan.scan_id.slice(0, 8)}</div>
                <div className="text-xs text-vigils-text-secondary">
                  {scan.session_id} · {scan.source} · {t("privacy.findingsCount", { count: scan.finding_count })}
                </div>
              </div>
            )) ?? (
              <div className="text-sm text-vigils-text-muted">{t("privacy.noRecentScans")}</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
