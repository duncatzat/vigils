import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { anchorCheckpoint, updateHubConfig } from "@/lib/tauri";
import { useUiStore, ProtectionPosture } from "@/stores/themeStore";
import { OnnxModelManager } from "./OnnxModelManager";

export function SettingsPage() {
  const { t, i18n } = useTranslation();
  const [anchorStatus, setAnchorStatus] = useState<string | null>(null);
  const [syncStatus, setSyncStatus] = useState<string | null>(null);
  const [showOnnxManager, setShowOnnxManager] = useState(false);

  const store = useUiStore();
  const {
    theme, setTheme, locale, setLocale,
    posture, setPosture,
    autoApproveFirstSeenTools, setAutoApproveFirstSeenTools,
    redactToolResults, setRedactToolResults,
    outboxEnabled, setOutboxEnabled,
    approvalWaitSecs, setApprovalWaitSecs,
    upstreamListTimeoutSecs, setUpstreamListTimeoutSecs,
    upstreamCallTimeoutSecs, setUpstreamCallTimeoutSecs,
    pollingIntervalMs, setPollingIntervalMs,
  } = store;

  const handleLocaleChange = (value: "zh-CN" | "en-US") => {
    setLocale(value);
    i18n.changeLanguage(value);
  };

  const syncMutation = useMutation({
    mutationFn: updateHubConfig,
    onMutate: () => setSyncStatus(t("settings.syncing")),
    onSuccess: () => {
      setSyncStatus(t("settings.synced"));
      setTimeout(() => setSyncStatus(null), 2000);
    },
    onError: (err: Error) => setSyncStatus(t("settings.syncFailed", { message: err.message })),
  });

  const buildPayload = () => ({
    monitor_mode: store.posture === "monitor",
    auto_approve_first_seen_tools: store.autoApproveFirstSeenTools,
    redact_tool_results: store.redactToolResults,
    outbox_enabled: store.outboxEnabled,
    approval_wait_secs: store.approvalWaitSecs,
    upstream_list_timeout_secs: store.upstreamListTimeoutSecs,
    upstream_call_timeout_secs: store.upstreamCallTimeoutSecs,
  });

  const pushHubConfig = () => syncMutation.mutate(buildPayload());

  useEffect(() => {
    pushHubConfig();
  }, []);

  const handlePostureChange = (value: ProtectionPosture) => {
    setPosture(value);
    setTimeout(() => syncMutation.mutate({ ...buildPayload(), monitor_mode: value === "monitor" }), 0);
  };

  const handleToggle = (
    current: boolean,
    setter: (v: boolean) => void,
    key: "auto_approve_first_seen_tools" | "redact_tool_results" | "outbox_enabled"
  ) => {
    const next = !current;
    setter(next);
    setTimeout(() => syncMutation.mutate({ ...buildPayload(), [key]: next }), 0);
  };

  const handleNumberChange = (
    setter: (v: number) => void,
    key: "approval_wait_secs" | "upstream_list_timeout_secs" | "upstream_call_timeout_secs",
    raw: string
  ) => {
    const parsed = Number(raw);
    if (Number.isNaN(parsed)) return;
    setter(parsed);
    setTimeout(() => syncMutation.mutate({ ...buildPayload(), [key]: parsed }), 0);
  };

  const anchor = useMutation({
    mutationFn: anchorCheckpoint,
    onSuccess: (dto) => {
      if (dto) {
        setAnchorStatus(t("settings.anchored", { eventId: dto.event_id, time: new Date(dto.anchored_at * 1000).toLocaleString() }));
      } else {
        setAnchorStatus(t("settings.nothingToAnchor"));
      }
    },
    onError: (err: Error) => setAnchorStatus(t("settings.anchorFailed", { message: err.message })),
  });

  return (
    <div className="mx-auto max-w-5xl space-y-4 animate-fade-in-up">
      {syncStatus && (
        <div className="vigil-card px-4 py-2 text-xs text-vigils-text-secondary">{syncStatus}</div>
      )}

      <div className="vigil-card p-5">
        <h3 className="text-sm font-bold text-vigils-text-primary">{t("settings.general")}</h3>
        <div className="mt-4 space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.theme")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.themeHint")}</div>
            </div>
            <select value={theme} onChange={(e) => setTheme(e.target.value as any)} className="vigil-input w-48">
              <option value="system">{t("theme.system")}</option>
              <option value="dark">{t("theme.dark")}</option>
              <option value="light">{t("theme.light")}</option>
            </select>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.language")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.languageHint")}</div>
            </div>
            <select value={locale} onChange={(e) => handleLocaleChange(e.target.value as any)} className="vigil-input w-48">
              <option value="zh-CN">中文</option>
              <option value="en-US">English</option>
            </select>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.ledgerPath")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.ledgerPathHint")}</div>
            </div>
            <span className="font-mono text-xs text-vigils-text-secondary">~/Library/Application Support/Vigil/ledger.sqlite3</span>
          </div>
        </div>
      </div>

      <div className="vigil-card p-5">
        <h3 className="text-sm font-bold text-vigils-text-primary">{t("settings.protection")}</h3>
        <div className="mt-4 space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.defaultPosture")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.postureHint")}</div>
            </div>
            <select value={posture} onChange={(e) => handlePostureChange(e.target.value as ProtectionPosture)} className="vigil-input w-48">
              <option value="monitor">{t("settings.postureMonitor")}</option>
              <option value="enforce">{t("settings.postureEnforce")}</option>
            </select>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.autoApproveFirstSeen")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.autoApproveHint")}</div>
            </div>
            <Toggle on={autoApproveFirstSeenTools} onToggle={() => handleToggle(autoApproveFirstSeenTools, setAutoApproveFirstSeenTools, "auto_approve_first_seen_tools")} />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.redactToolResults")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.redactHint")}</div>
            </div>
            <Toggle on={redactToolResults} onToggle={() => handleToggle(redactToolResults, setRedactToolResults, "redact_tool_results")} />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.outboxEnabled")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.outboxHint")}</div>
            </div>
            <Toggle on={outboxEnabled} onToggle={() => handleToggle(outboxEnabled, setOutboxEnabled, "outbox_enabled")} />
          </div>
        </div>
      </div>

      <div className="vigil-card p-5">
        <h3 className="text-sm font-bold text-vigils-text-primary">{t("settings.advanced")}</h3>
        <div className="mt-4 space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.approvalWait")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.approvalWaitHint")}</div>
            </div>
            <NumberInput value={approvalWaitSecs} onChange={(v) => handleNumberChange(setApprovalWaitSecs, "approval_wait_secs", v)} unit="s" min={1} max={3600} />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.upstreamListTimeout")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.upstreamListTimeoutHint")}</div>
            </div>
            <NumberInput value={upstreamListTimeoutSecs} onChange={(v) => handleNumberChange(setUpstreamListTimeoutSecs, "upstream_list_timeout_secs", v)} unit="s" min={1} max={300} />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.upstreamCallTimeout")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.upstreamCallTimeoutHint")}</div>
            </div>
            <NumberInput value={upstreamCallTimeoutSecs} onChange={(v) => handleNumberChange(setUpstreamCallTimeoutSecs, "upstream_call_timeout_secs", v)} unit="s" min={1} max={300} />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.pollingInterval")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.pollingIntervalHint")}</div>
            </div>
            <div className="flex items-center gap-3 w-48">
              <input type="range" min={500} max={10000} step={500} value={pollingIntervalMs} onChange={(e) => setPollingIntervalMs(Number(e.target.value))} className="flex-1 accent-vigils-cyan" />
              <span className="text-sm text-vigils-text-primary w-20 text-right">{pollingIntervalMs} ms</span>
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.onnxPiiModel")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.onnxHint")}</div>
            </div>
            <button className="vigil-btn-ghost text-sm" onClick={() => setShowOnnxManager(true)}>{t("settings.onnxManage")}</button>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-vigils-text-primary">{t("settings.checkpointAnchor")}</div>
              <div className="text-xs text-vigils-text-muted">{t("settings.anchorHint")}</div>
            </div>
            <div className="flex items-center gap-3">
              {anchorStatus && <span className="text-xs text-vigils-text-secondary">{anchorStatus}</span>}
              <button className="vigil-btn-ghost text-sm disabled:opacity-50" onClick={() => anchor.mutate()} disabled={anchor.isPending}>{anchor.isPending ? "..." : t("settings.anchorNow")}</button>
            </div>
          </div>
        </div>
      </div>

      {showOnnxManager && <OnnxModelManager onClose={() => setShowOnnxManager(false)} />}
    </div>
  );
}

function Toggle({ on, onToggle }: { on: boolean; onToggle: () => void }) {
  return (
    <button onClick={onToggle} type="button" className={`relative h-6 w-11 rounded-full transition-colors ${on ? "bg-vigils-green" : "bg-vigils-bg-surface"}`} aria-pressed={on}>
      <span className={`absolute top-1 h-4 w-4 rounded-full bg-vigils-text-primary transition-all ${on ? "left-6" : "left-1"}`} />
    </button>
  );
}

function NumberInput({ value, onChange, unit, min, max }: { value: number; onChange: (value: string) => void; unit: string; min: number; max: number }) {
  return (
    <div className="flex items-center gap-2 w-48">
      <input type="number" min={min} max={max} value={value} onChange={(e) => onChange(e.target.value)} className="vigil-input flex-1 text-right" />
      <span className="text-sm text-vigils-text-primary w-6">{unit}</span>
    </div>
  );
}
