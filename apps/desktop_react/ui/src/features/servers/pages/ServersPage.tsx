import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listServers, registerServer } from "@/lib/tauri";
import { usePollInterval } from "@/stores/themeStore";
import { useTranslation } from "react-i18next";

export function ServersPage() {
  const [name, setName] = useState("");
  const [cmd, setCmd] = useState("");
  const [transport, setTransport] = useState<"stdio" | "http">("stdio");
  const [error, setError] = useState<string | null>(null);
  const qc = useQueryClient();
  const { t } = useTranslation();
  const pollMs = usePollInterval();
  const { data: servers } = useQuery({
    queryKey: ["servers"],
    queryFn: listServers,
    refetchInterval: pollMs,
  });
  const register = useMutation({
    mutationFn: registerServer,
    onSuccess: () => {
      setName("");
      setCmd("");
      setError(null);
      qc.invalidateQueries({ queryKey: ["servers"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const healthColor: Record<string, string> = {
    healthy: "text-vigils-green",
    pending: "text-vigils-yellow",
    untrusted: "text-vigils-red",
  };

  return (
    <div className="grid h-full grid-cols-1 gap-6 lg:grid-cols-3 animate-fade-in-up">
      <div className="vigil-card p-5 lg:col-span-2">
        <h3 className="text-sm font-bold text-vigils-text-primary">{t("servers.title")}</h3>
        <table className="mt-4 w-full">
          <thead>
            <tr>
              {[t("servers.server"), t("servers.transport"), t("servers.trust"), t("servers.commandUrl")].map((h) => (
                <th key={h} className="vigil-table-header pb-2 text-left">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-vigils-bg-surface">
            {servers?.map((s) => (
              <tr key={s.server_id}>
                <td className="vigil-table-cell text-vigils-text-primary">{s.server_id}</td>
                <td className="vigil-table-cell">{s.transport}</td>
                <td className={`vigil-table-cell font-bold ${healthColor[s.trust_level] ?? "text-vigils-text-secondary"}`}>
                  {s.trust_level}
                </td>
                <td className="vigil-table-cell max-w-xs truncate">
                  {s.url ?? s.command?.join(" ") ?? "-"}
                </td>
              </tr>
            )) ?? (
              <tr>
                <td colSpan={4} className="py-6 text-center text-sm text-vigils-text-muted">{t("servers.noServers")}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="space-y-6">
        <div className="vigil-card p-5">
          <h3 className="text-sm font-bold text-vigils-text-primary">{t("servers.addServer")}</h3>
          <div className="mt-4 space-y-3">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t("servers.serverName")}
              className="vigil-input w-full"
            />
            <select
              value={transport}
              onChange={(e) => setTransport(e.target.value as "stdio" | "http")}
              className="vigil-input w-full"
            >
              <option value="stdio">{t("servers.transportStdio")}</option>
              <option value="http">{t("servers.transportHttp")}</option>
            </select>
            <input
              value={cmd}
              onChange={(e) => setCmd(e.target.value)}
              placeholder={transport === "stdio" ? t("servers.commandPlaceholder") : t("servers.urlPlaceholder")}
              className="vigil-input w-full"
            />
            {error && (
              <div className="text-xs text-vigils-red">{error}</div>
            )}
            <button
              onClick={() => {
                const isHttp = transport === "http";
                const trimmedCmd = cmd.trim();
                if (!name.trim()) {
                  setError(t("servers.nameRequired"));
                  return;
                }
                if (!trimmedCmd) {
                  setError(isHttp ? t("servers.urlRequired") : t("servers.commandRequired"));
                  return;
                }
                register.mutate({
                  server_id: name.trim(),
                  transport,
                  command: isHttp ? null : trimmedCmd.split(/\s+/),
                  url: isHttp ? trimmedCmd : null,
                });
              }}
              disabled={register.isPending}
              className="vigil-btn-primary w-full disabled:opacity-50"
            >
              {register.isPending ? t("servers.registering") : t("servers.register")}
            </button>
          </div>
        </div>

        <div className="vigil-card p-5">
          <h3 className="text-sm font-bold text-vigils-text-primary">{t("servers.driftDetections")}</h3>
          <div className="mt-4 space-y-3">
            {servers?.filter((s) => s.pending_command_hash).map((s) => (
              <div key={s.server_id} className="rounded-lg bg-vigils-bg-tertiary p-3">
                <div className="text-sm font-bold text-vigils-text-primary">{s.server_id}</div>
                <div className="text-xs text-vigils-yellow">{t("servers.commandDriftDetected")}</div>
              </div>
            )) ?? (
              <div className="text-sm text-vigils-text-muted">{t("servers.noDrift")}</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
