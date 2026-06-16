import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { ensureOnnxModel, listOnnxModels, OnnxModelInfo } from "@/lib/tauri";

interface OnnxModelProgress {
  model_id: string;
  phase: "started" | "completed" | "failed";
  message?: string | null;
}

export function OnnxModelManager({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const [progress, setProgress] = useState<Record<string, OnnxModelProgress>>({});

  const modelsQuery = useQuery({
    queryKey: ["onnx-models"],
    queryFn: listOnnxModels,
    refetchInterval: 5000,
  });

  const ensureMutation = useMutation({
    mutationFn: ensureOnnxModel,
    onSuccess: (_, req) => {
      setProgress((p) => ({
        ...p,
        [req.model_id]: { model_id: req.model_id, phase: "started" },
      }));
    },
    onError: (err: Error, req) => {
      setProgress((p) => ({
        ...p,
        [req.model_id]: { model_id: req.model_id, phase: "failed", message: err.message },
      }));
    },
  });

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    listen<OnnxModelProgress>("onnx-model-progress", (event) => {
      setProgress((p) => ({ ...p, [event.payload.model_id]: event.payload }));
      if (event.payload.phase === "completed" || event.payload.phase === "failed") {
        modelsQuery.refetch();
      }
    }).then((u) => {
      unlisten = u;
    });
    return () => {
      if (unlisten) unlisten();
    };
  }, [modelsQuery]);

  const models = modelsQuery.data ?? [];

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "—";
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
    return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="vigil-card w-full max-w-2xl max-h-[80vh] flex flex-col">
        <div className="flex items-center justify-between p-5 border-b border-vigils-bg-surface">
          <h2 className="text-lg font-bold text-vigils-text-primary">
            {t("settings.onnxTitle")}
          </h2>
          <button
            onClick={onClose}
            className="text-vigils-text-secondary hover:text-vigils-text-primary"
          >
            ✕
          </button>
        </div>

        <div className="overflow-y-auto p-5 space-y-4">
          {modelsQuery.isLoading && (
            <div className="text-sm text-vigils-text-secondary">{t("common.loading")}</div>
          )}
          {models.map((m) => (
            <ModelRow
              key={m.model_id}
              model={m}
              progress={progress[m.model_id]}
              onDownload={() => ensureMutation.mutate({ model_id: m.model_id })}
              formatBytes={formatBytes}
            />
          ))}
        </div>

        <div className="p-5 border-t border-vigils-bg-surface text-right">
          <button onClick={onClose} className="vigil-btn-ghost text-sm">
            {t("common.close")}
          </button>
        </div>
      </div>
    </div>
  );
}

function ModelRow({
  model,
  progress,
  onDownload,
  formatBytes,
}: {
  model: OnnxModelInfo;
  progress?: OnnxModelProgress;
  onDownload: () => void;
  formatBytes: (b: number) => string;
}) {
  const { t } = useTranslation();
  const busy = model.busy || progress?.phase === "started" || progress?.phase === "completed";

  return (
    <div className="vigil-card p-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-bold text-vigils-text-primary">{model.display_name}</div>
          <div className="text-xs text-vigils-text-muted">
            {model.model_id} · v{model.version} · {formatBytes(model.size_bytes)}
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span
            className={`text-xs px-2 py-1 rounded ${
              model.installed
                ? "bg-vigils-green/20 text-vigils-green"
                : "bg-vigils-bg-surface text-vigils-text-secondary"
            }`}
          >
            {model.installed ? t("settings.onnxInstalled") : t("settings.onnxNotInstalled")}
          </span>
          <button
            onClick={onDownload}
            disabled={busy}
            className="vigil-btn-ghost text-sm disabled:opacity-50"
          >
            {busy
              ? t("settings.onnxDownloading")
              : model.installed
              ? t("settings.onnxReverify")
              : t("settings.onnxDownload")}
          </button>
        </div>
      </div>
      {progress?.phase === "started" && (
        <div className="mt-2 text-xs text-vigils-cyan">{t("settings.onnxDownloadStarted")}</div>
      )}
      {progress?.phase === "completed" && (
        <div className="mt-2 text-xs text-vigils-green">{t("settings.onnxDownloadCompleted")}</div>
      )}
      {progress?.phase === "failed" && (
        <div className="mt-2 text-xs text-red-400">
          {t("settings.onnxDownloadFailed")}: {progress.message || ""}
        </div>
      )}
    </div>
  );
}
