import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Shield, Activity, Monitor, Server } from "lucide-react";
import { protectionSummary, listPrivacyFindings, verifyChain } from "@/lib/tauri";
import { usePollInterval } from "@/stores/themeStore";

function KpiCard({ label, value, sub, colorClass, icon: Icon }: any) {
  return (
    <div className="vigil-card vigil-card-hover p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wider text-vigils-text-secondary">{label}</span>
        <Icon size={16} className={colorClass} />
      </div>
      <div className={`mt-2 text-3xl font-bold ${colorClass}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-vigils-text-muted">{sub}</div>}
    </div>
  );
}

export function ProtectionPage() {
  const { t } = useTranslation();
  const pollMs = usePollInterval();
  const qc = useQueryClient();
  const [verifyStatus, setVerifyStatus] = useState<string | null>(null);
  const { data: summary } = useQuery({ queryKey: ["protectionSummary"], queryFn: protectionSummary, refetchInterval: pollMs });
  const { data: findings } = useQuery({ queryKey: ["privacyFindings"], queryFn: () => listPrivacyFindings({ limit_recent_scans: 50 }), refetchInterval: pollMs });

  const handleVerify = () => {
    setVerifyStatus(t("protection.verifying"));
    verifyChain()
      .then((report) => {
        qc.invalidateQueries({ queryKey: ["protectionSummary"] });
        setVerifyStatus(report.ok ? t("protection.verifySuccess") : t("protection.verifyFailed", { message: report.message ?? "" }));
        setTimeout(() => setVerifyStatus(null), 3000);
      })
      .catch((err: Error) => setVerifyStatus(t("protection.verifyError", { message: err.message })));
  };

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard label={t("protection.rawSecretsBlocked")} value={summary?.raw_secrets_blocked ?? "-"} sub="input-side hard deny" colorClass="text-vigils-red" icon={Shield} />
        <KpiCard label={t("protection.eventsAudited")} value={summary?.total_events_audited ?? "-"} sub="Last 24h" colorClass="text-vigils-cyan" icon={Activity} />
        <KpiCard label={t("protection.sessionsCovered")} value={summary?.sessions_covered ?? "-"} sub="distinct session_id" colorClass="text-vigils-purple" icon={Monitor} />
        <KpiCard label={t("protection.leaksDetected")} value={summary?.tool_result_leaks_detected ?? "-"} sub="tool result side" colorClass="text-vigils-yellow" icon={Server} />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="vigil-card p-5 lg:col-span-2">
          <h3 className="text-sm font-bold text-vigils-text-primary">{t("protection.recentEvents")}</h3>
          <table className="mt-4 w-full">
            <thead>
              <tr>
                {[t("activity.time"), t("common.type"), t("common.summary")].map((h) => (
                  <th key={h} className="vigil-table-header pb-2 text-left">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-vigils-bg-surface">
              {summary?.recent?.map((e) => (
                <tr key={e.event_id}>
                  <td className="vigil-table-cell">{new Date(e.created_at * 1000).toLocaleTimeString()}</td>
                  <td className="vigil-table-cell">{e.event_type}</td>
                  <td className="vigil-table-cell text-vigils-text-primary">{e.redacted_text ?? "-"}</td>
                </tr>
              )) ?? (
                <tr>
                  <td colSpan={3} className="py-4 text-center text-sm text-vigils-text-muted">{t("activity.noEvents")}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="space-y-6">
          <div className="vigil-card p-5">
            <h3 className="text-sm font-bold text-vigils-text-primary">{t("protection.chainIntegrity")}</h3>
            <div className={`mt-4 flex items-center gap-2 ${summary?.chain_intact ? "text-vigils-green" : "text-vigils-red"}`}>
              <span className="text-lg">{summary?.chain_intact ? "✓" : "✗"}</span>
              <span className="font-bold">{summary?.chain_intact ? "Hash chain valid" : t("protection.chainBroken")}</span>
            </div>
            {verifyStatus && <div className="mt-3 text-xs text-vigils-text-secondary">{verifyStatus}</div>}
            <button onClick={handleVerify} className="vigil-btn-ghost mt-3 w-full text-center text-sm">{t("protection.verifyNow")}</button>
          </div>

          <div className="vigil-card p-5">
            <h3 className="text-sm font-bold text-vigils-text-primary">{t("protection.privacyFindings")}</h3>
            <div className="mt-4 space-y-3">
              {findings?.by_label_total?.slice(0, 5).map((f) => (
                <div key={f.label} className="flex items-center justify-between text-sm">
                  <span className="text-vigils-text-secondary">{f.label}</span>
                  <span className="font-bold text-vigils-red">{f.count}</span>
                </div>
              )) ?? <div className="text-sm text-vigils-text-muted">{t("common.noData")}</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
