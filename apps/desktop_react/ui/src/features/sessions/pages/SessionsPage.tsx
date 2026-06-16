import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { listSessions, replaySession, exportSessionReplay } from "@/lib/tauri";
import { usePollInterval } from "@/stores/themeStore";

export function SessionsPage() {
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportedContent, setExportedContent] = useState<string | null>(null);
  const { t } = useTranslation();
  const pollMs = usePollInterval();
  const { data: sessions } = useQuery({ queryKey: ["sessions"], queryFn: () => listSessions({ limit: 50 }), refetchInterval: pollMs });
  const { data: replay } = useQuery({ queryKey: ["replaySession", selectedSession], queryFn: () => replaySession({ session_id: selectedSession!, verify: false }), enabled: !!selectedSession });

  const exportReplay = useMutation({
    mutationFn: () => exportSessionReplay({ session_id: selectedSession!, format: "md" }),
    onSuccess: (dto) => {
      setExportError(null);
      setExportedContent(dto.content);
      const blob = new Blob([dto.content], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${dto.session_id}-replay.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    },
    onError: (err: Error) => { setExportError(err.message); setExportedContent(null); },
  });

  const selected = sessions?.find((s) => s.session_id === selectedSession);

  return (
    <div className="grid h-full grid-cols-1 gap-6 lg:grid-cols-2 animate-fade-in-up">
      <div className="vigil-card p-5">
        <h3 className="text-sm font-bold text-vigils-text-primary">{t("sessions.title")}</h3>
        <table className="mt-4 w-full">
          <thead>
            <tr>
              {[t("sessions.sessionHeader"), t("sessions.source"), t("sessions.riskHeader"), t("sessions.startedHeader")].map((h) => (
                <th key={h} className="vigil-table-header pb-2 text-left">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-vigils-bg-surface">
            {sessions?.map((s) => (
              <tr key={s.session_id} onClick={() => setSelectedSession(s.session_id)} className={`cursor-pointer ${selectedSession === s.session_id ? "bg-vigils-bg-tertiary/50" : ""}`}>
                <td className="vigil-table-cell text-vigils-cyan">{s.session_id}</td>
                <td className="vigil-table-cell">{s.source}</td>
                <td className="vigil-table-cell">{s.risk_score}</td>
                <td className="vigil-table-cell">{new Date(s.started_at * 1000).toLocaleTimeString()}</td>
              </tr>
            )) ?? (
              <tr><td colSpan={4} className="py-6 text-center text-sm text-vigils-text-muted">{t("sessions.noSessions")}</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="space-y-6">
        <div className="vigil-card p-5">
          <h3 className="text-sm font-bold text-vigils-text-primary">{t("sessions.sessionTimeline")}: {selectedSession ?? "-"}</h3>
          <div className="mt-4 space-y-4">
            {replay ? (
              <pre className="max-h-[260px] overflow-auto rounded-md bg-vigils-bg-deep p-3 text-xs text-vigils-text-secondary">{JSON.stringify(replay, null, 2)}</pre>
            ) : (
              <div className="text-sm text-vigils-text-muted">{t("sessions.selectSession")}</div>
            )}
          </div>
        </div>

        <div className="vigil-card p-5">
          <h3 className="text-sm font-bold text-vigils-text-primary">{t("sessions.sessionSummary")}</h3>
          <div className="mt-4 space-y-3 text-sm">
            {[[t("sessions.sessionId"), selected?.session_id ?? "-"], [t("sessions.source"), selected?.source ?? "-"], [t("sessions.app"), selected?.app_name ?? "-"], [t("sessions.riskScore"), selected?.risk_score.toString() ?? "-"], [t("sessions.status"), selected?.ended_at ? t("sessions.statusEnded") : t("sessions.statusActive")]].map(([k, v]) => (
              <div key={k as string} className="flex justify-between"><span className="text-vigils-text-secondary">{k}</span><span className="text-vigils-text-primary">{v}</span></div>
            ))}
          </div>
          {exportedContent && (
            <div className="mt-4">
              <div className="text-xs text-vigils-text-muted mb-1">{t("sessions.exportedPreview")}</div>
              <pre className="max-h-32 overflow-auto rounded-md bg-vigils-bg-deep p-2 text-xs text-vigils-text-secondary">{exportedContent.slice(0, 800)}{exportedContent.length > 800 ? "…" : ""}</pre>
            </div>
          )}
          {exportError && <div className="mt-3 text-xs text-vigils-red">{t("sessions.exportError", { message: exportError })}</div>}
          <button
            onClick={() => { setExportError(null); setExportedContent(null); selectedSession && exportReplay.mutate(); }}
            disabled={!selectedSession || exportReplay.isPending}
            className="vigil-btn-ghost mt-5 w-full disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {exportReplay.isPending ? t("sessions.exporting") : t("sessions.exportReplay")}
          </button>
        </div>
      </div>
    </div>
  );
}
