import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listPendingApprovals,
  getApprovalDetail,
  resolveApproval,
  listPendingToolApprovals,
  listDriftedTools,
  listDriftedServers,
  ToolApprovalCard,
  ApprovalSummary,
} from "@/lib/tauri";
import { usePollInterval } from "@/stores/themeStore";
import { useTranslation } from "react-i18next";

type ApprovalTab = "pending" | "tool-drift" | "server-drift";

interface ApprovalRow {
  id: string;
  title: string;
  sessionId?: string;
  status?: string;
  expiresAt?: number;
  subtitle?: string;
}

function toApprovalRows(
  tab: ApprovalTab,
  pending: ApprovalSummary[] | undefined,
  toolCards: ToolApprovalCard[] | undefined,
  serverCards: ToolApprovalCard[] | undefined
): ApprovalRow[] {
  if (tab === "pending") {
    return (
      pending?.map((a) => ({
        id: a.approval_id,
        title: a.title,
        sessionId: a.session_id,
        status: a.status,
        expiresAt: a.expires_at,
      })) ?? []
    );
  }
  const cards = tab === "tool-drift" ? toolCards : serverCards;
  return (
    cards?.map((c) => ({
      id: `${c.server_id}::${c.tool_name}`,
      title: c.tool_name,
      sessionId: c.server_id,
      subtitle: c.proposed_hash
        ? `hash drift: ${c.current_hash.slice(0, 8)}… → ${c.proposed_hash.slice(0, 8)}…`
        : `first seen: ${c.current_hash.slice(0, 8)}…`,
      status: c.approved_at ? "approved" : c.proposed_hash ? "drifted" : "pending",
      expiresAt: c.last_drift_at ?? c.first_seen_at,
    })) ?? []
  );
}

export function ApprovalsPage() {
  const [activeTab, setActiveTab] = useState<ApprovalTab>("pending");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const qc = useQueryClient();
  const pollMs = usePollInterval();
  const { t } = useTranslation();

  const { data: approvals } = useQuery({
    queryKey: ["pendingApprovals"],
    queryFn: () => listPendingApprovals({}),
    refetchInterval: pollMs,
  });
  useQuery({
    queryKey: ["pendingToolApprovals"],
    queryFn: listPendingToolApprovals,
    refetchInterval: pollMs,
    enabled: activeTab === "tool-drift" || activeTab === "pending",
  });
  const { data: driftedTools } = useQuery({
    queryKey: ["driftedTools"],
    queryFn: listDriftedTools,
    refetchInterval: pollMs,
    enabled: activeTab === "tool-drift",
  });
  const { data: driftedServers } = useQuery({
    queryKey: ["driftedServers"],
    queryFn: listDriftedServers,
    refetchInterval: pollMs,
    enabled: activeTab === "server-drift",
  });

  const { data: detail } = useQuery({
    queryKey: ["approvalDetail", selectedId],
    queryFn: () => getApprovalDetail({ approval_id: selectedId! }),
    enabled: activeTab === "pending" && selectedId !== null,
  });

  const resolve = useMutation({
    mutationFn: resolveApproval,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["pendingApprovals"] });
      setSelectedId(null);
    },
  });

  const statusColor: Record<string, string> = {
    pending: "text-vigils-yellow",
    approved: "text-vigils-green",
    denied: "text-vigils-red",
    expired: "text-vigils-text-muted",
    drifted: "text-vigils-red",
  };

  const rows = toApprovalRows(activeTab, approvals, driftedTools, driftedServers);

  const tabs: { key: ApprovalTab; label: string }[] = [
    { key: "pending", label: t("approvals.title") },
    { key: "tool-drift", label: t("approvals.driftedTools") },
    { key: "server-drift", label: t("approvals.driftedServers") },
  ];

  return (
    <div className="grid h-full grid-cols-1 gap-6 lg:grid-cols-3 animate-fade-in-up">
      <div className="vigil-card p-5 lg:col-span-2">
        <div className="flex gap-4 border-b border-vigils-bg-surface pb-3 text-sm font-bold">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => {
                setActiveTab(tab.key);
                setSelectedId(null);
              }}
              className={`pb-2 transition-colors ${
                activeTab === tab.key
                  ? "text-vigils-cyan border-b-2 border-vigils-cyan"
                  : "text-vigils-text-secondary hover:text-vigils-text-primary"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <table className="mt-4 w-full">
          <thead>
            <tr>
              {[t("approvals.titleHeader"), t("approvals.sessionHeader"), t("approvals.statusHeader"), t("approvals.expiresHeader")].map((h) => (
                <th key={h} className="vigil-table-header pb-2 text-left">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-vigils-bg-surface">
            {rows.map((a) => (
              <tr
                key={a.id}
                onClick={() => setSelectedId(a.id)}
                className={`cursor-pointer ${selectedId === a.id ? "bg-vigils-bg-tertiary/50" : ""}`}
              >
                <td className="vigil-table-cell text-vigils-text-primary">
                  <div>{a.title}</div>
                  {a.subtitle && <div className="text-xs text-vigils-text-muted">{a.subtitle}</div>}
                </td>
                <td className="vigil-table-cell text-vigils-cyan">{a.sessionId}</td>
                <td className={`vigil-table-cell font-bold ${statusColor[a.status ?? ""] ?? "text-vigils-text-secondary"}`}>
                  {a.status}
                </td>
                <td className="vigil-table-cell">
                  {a.expiresAt ? new Date(a.expiresAt * 1000).toLocaleTimeString() : "-"}
                </td>
              </tr>
            )) ?? (
              <tr>
                <td colSpan={4} className="py-6 text-center text-sm text-vigils-text-muted">
                  {t("approvals.noPending")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="vigil-card p-5">
        <h3 className="text-sm font-bold text-vigils-text-primary">{t("approvals.approvalDetail")}</h3>
        {activeTab !== "pending" ? (
          <div className="mt-8 text-center text-sm text-vigils-text-muted">
            {t("approvals.driftNoAction")}
          </div>
        ) : detail ? (
          <div className="mt-4 space-y-4">
            <div>
              <div className="text-xs text-vigils-text-muted">{t("approvals.invocationId")}</div>
              <div className="text-sm text-vigils-text-primary">{detail.invocation_id}</div>
            </div>
            <div>
              <div className="text-xs text-vigils-text-muted">{t("approvals.decisionId")}</div>
              <div className="text-sm text-vigils-text-primary">{detail.decision_id}</div>
            </div>
            <div>
              <div className="text-xs text-vigils-text-muted">{t("approvals.request")}</div>
              <pre className="mt-1 max-h-48 overflow-auto rounded-md bg-vigils-bg-deep p-2 text-xs text-vigils-text-secondary">
                {JSON.stringify(detail.request, null, 2)}
              </pre>
            </div>
            <div className="flex gap-3 pt-2">
              <button
                onClick={() =>
                  selectedId &&
                  resolve.mutate({
                    approval_id: selectedId,
                    action: "approve",
                    resolved_by: "desktop-user",
                  })
                }
                className="vigil-btn-primary flex-1"
              >
                {t("approvals.approve")}
              </button>
              <button
                onClick={() =>
                  selectedId &&
                  resolve.mutate({
                    approval_id: selectedId,
                    action: "deny",
                    resolved_by: "desktop-user",
                  })
                }
                className="vigil-btn-ghost flex-1 text-vigils-red hover:text-vigils-red"
              >
                {t("approvals.deny")}
              </button>
            </div>
          </div>
        ) : (
          <div className="mt-8 text-center text-sm text-vigils-text-muted">
            {t("approvals.selectApproval")}
          </div>
        )}
      </div>
    </div>
  );
}
