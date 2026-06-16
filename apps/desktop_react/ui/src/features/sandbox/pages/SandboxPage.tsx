import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listSandboxProfiles, upsertSandboxProfile } from "@/lib/tauri";
import { usePollInterval } from "@/stores/themeStore";
import { useTranslation } from "react-i18next";
import type { SandboxProfile } from "@/lib/tauri";

const EMPTY_PROFILE: SandboxProfile = {
  id: "",
  read_dirs: [],
  write_dirs: [],
  allow_hosts: [],
  env_inherit: false,
  wall_ms: 5000,
  memory_mb: 64,
};

export function SandboxPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<SandboxProfile>(EMPTY_PROFILE);
  const [error, setError] = useState<string | null>(null);
  const qc = useQueryClient();
  const { t } = useTranslation();
  const pollMs = usePollInterval();

  const { data: profiles } = useQuery({
    queryKey: ["sandboxProfiles"],
    queryFn: listSandboxProfiles,
    refetchInterval: pollMs,
  });

  const selected = profiles?.find((p) => p.id === selectedId);

  const save = useMutation({
    mutationFn: upsertSandboxProfile,
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["sandboxProfiles"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const startNew = () => {
    setSelectedId(null);
    setDraft({ ...EMPTY_PROFILE, id: "new-profile" });
    setError(null);
  };

  const editSelected = () => {
    if (selected) {
      setDraft({ ...selected });
      setError(null);
    }
  };

  const updateField = <K extends keyof SandboxProfile>(
    key: K,
    value: SandboxProfile[K]
  ) => {
    setDraft((d) => ({ ...d, [key]: value }));
  };

  const updateList = (key: "read_dirs" | "write_dirs" | "allow_hosts", raw: string) => {
    const values = raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    setDraft((d) => ({ ...d, [key]: values }));
  };

  const canSave = draft.id.trim().length > 0;

  return (
    <div className="grid h-full grid-cols-1 gap-6 lg:grid-cols-3 animate-fade-in-up">
      <div className="vigil-card p-5 lg:col-span-2">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-vigils-text-primary">{t("sandbox.title")}</h3>
          <button onClick={startNew} className="vigil-btn-primary text-xs">
            {t("sandbox.newProfile")}
          </button>
        </div>
        <table className="mt-4 w-full">
          <thead>
            <tr>
              {[t("sandbox.name"), t("sandbox.readDirsShort"), t("sandbox.writeDirsShort"), t("sandbox.networkHosts"), t("sandbox.wallMsShort")].map((h) => (
                <th key={h} className="vigil-table-header pb-2 text-left">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-vigils-bg-surface">
            {profiles?.map((p) => (
              <tr
                key={p.id}
                onClick={() => {
                  setSelectedId(p.id);
                  setDraft({ ...p });
                  setError(null);
                }}
                className={`cursor-pointer ${
                  selectedId === p.id ? "bg-vigils-bg-tertiary/50" : ""
                }`}
              >
                <td className="vigil-table-cell text-vigils-text-primary">{p.id}</td>
                <td className="vigil-table-cell">{p.read_dirs.length}</td>
                <td className="vigil-table-cell">{p.write_dirs.length}</td>
                <td className="vigil-table-cell">{p.allow_hosts.length}</td>
                <td className="vigil-table-cell">{p.wall_ms}</td>
              </tr>
            )) ?? (
              <tr>
                <td colSpan={5} className="py-6 text-center text-sm text-vigils-text-muted">
                  {t("sandbox.noProfiles")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="vigil-card p-5">
        <h3 className="text-sm font-bold text-vigils-text-primary">
          {selected ? t("sandbox.editProfile", { id: selected.id }) : t("sandbox.newProfileTitle")}
        </h3>
        <div className="mt-4 space-y-4">
          <Field label={t("sandbox.profileId")}>
            <input
              value={draft.id}
              onChange={(e) => updateField("id", e.target.value)}
              placeholder={t("sandbox.profileIdPlaceholder")}
              className="vigil-input mt-1 w-full"
            />
          </Field>

          <Field label={t("sandbox.readDirs")}>
            <input
              value={draft.read_dirs.join(", ")}
              onChange={(e) => updateList("read_dirs", e.target.value)}
              placeholder={t("sandbox.readDirsPlaceholder")}
              className="vigil-input mt-1 w-full"
            />
          </Field>

          <Field label={t("sandbox.writeDirs")}>
            <input
              value={draft.write_dirs.join(", ")}
              onChange={(e) => updateList("write_dirs", e.target.value)}
              placeholder={t("sandbox.writeDirsPlaceholder")}
              className="vigil-input mt-1 w-full"
            />
          </Field>

          <Field label={t("sandbox.allowHosts")}>
            <input
              value={draft.allow_hosts.join(", ")}
              onChange={(e) => updateList("allow_hosts", e.target.value)}
              placeholder={t("sandbox.allowHostsPlaceholder")}
              className="vigil-input mt-1 w-full"
            />
          </Field>

          <div className="grid grid-cols-2 gap-3">
            <Field label={t("sandbox.wallMs")}>
              <input
                type="number"
                min={100}
                step={100}
                value={draft.wall_ms}
                onChange={(e) => updateField("wall_ms", Math.max(100, Number(e.target.value)))}
                className="vigil-input mt-1 w-full"
              />
            </Field>
            <Field label={t("sandbox.memoryMb")}>
              <input
                type="number"
                min={16}
                step={16}
                value={draft.memory_mb}
                onChange={(e) => updateField("memory_mb", Math.max(16, Number(e.target.value)))}
                className="vigil-input mt-1 w-full"
              />
            </Field>
          </div>

          {error && <div className="text-xs text-vigils-red">{error}</div>}

          <div className="flex gap-3 pt-2">
            {selected && selected.id !== draft.id && (
              <button
                onClick={editSelected}
                className="vigil-btn-ghost flex-1 text-sm"
              >
                {t("sandbox.reset")}
              </button>
            )}
            <button
              onClick={() => save.mutate({ profile: draft })}
              disabled={!canSave || save.isPending}
              className="vigil-btn-primary flex-1 disabled:opacity-50"
            >
              {save.isPending ? t("sandbox.saving") : t("sandbox.saveProfile")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="text-xs text-vigils-text-muted">{label}</label>
      {children}
    </div>
  );
}
