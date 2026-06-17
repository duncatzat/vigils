<script setup lang="ts">
/**
 * Sandbox Profiles page (I08b-α6).
 *
 * Layout matches the prototype: a left "Profiles" table and a right
 * "Profile Editor" form. Data is kept in local reactive state with sample
 * profiles because the backend sandbox configuration API is not yet wired
 * to the desktop UI.
 */
import { computed, h, reactive, ref } from "vue";
import {
  NButton,
  NCard,
  NDataTable,
  NEmpty,
  NInput,
  NSelect,
  NSpace,
  NTag,
  type DataTableColumns,
  type SelectOption,
} from "naive-ui";
import { useI18n } from "vue-i18n";

type RunnerKind = "native" | "wasm";
type NetPolicy = "allow" | "deny";

interface SandboxProfile {
  id: string;
  name: string;
  runner: RunnerKind;
  network: NetPolicy;
  readDirs: string[];
  writeDirs: string[];
  envAllowlist: string[];
}

interface ServerBinding {
  serverId: string;
  profileId: string;
}

const { t } = useI18n();

const profiles = reactive<SandboxProfile[]>([
  {
    id: "default",
    name: "default",
    runner: "native",
    network: "deny",
    readDirs: ["/tmp"],
    writeDirs: [],
    envAllowlist: ["PATH"],
  },
  {
    id: "trusted-fs",
    name: "trusted-fs",
    runner: "native",
    network: "deny",
    readDirs: ["/Users/alice/project", "/tmp"],
    writeDirs: ["/Users/alice/project"],
    envAllowlist: ["PATH", "HOME"],
  },
  {
    id: "networked",
    name: "networked",
    runner: "native",
    network: "allow",
    readDirs: ["/Users/alice/project"],
    writeDirs: ["/Users/alice/project"],
    envAllowlist: ["PATH", "HOME"],
  },
  {
    id: "wasm-isolated",
    name: "wasm-isolated",
    runner: "wasm",
    network: "deny",
    readDirs: [],
    writeDirs: [],
    envAllowlist: [],
  },
]);

const bindings = reactive<ServerBinding[]>([
  { serverId: "filesystem", profileId: "trusted-fs" },
  { serverId: "github-server", profileId: "default" },
]);

const selectedId = ref<string>("trusted-fs");

const selected = computed<SandboxProfile>(
  () => profiles.find((p) => p.id === selectedId.value) ?? profiles[0],
);

const networkOptions: SelectOption[] = [
  { label: "true", value: "allow" },
  { label: "false", value: "deny" },
];

const runnerOptions: SelectOption[] = [
  { label: "native", value: "native" },
  { label: "wasm", value: "wasm" },
];

const columns = computed<DataTableColumns<SandboxProfile>>(() => [
  {
    title: t("sandbox.col_name"),
    key: "name",
    render: (row) =>
      h("span", { class: "font-medium text-vigils-text-primary" }, row.name),
  },
  {
    title: t("sandbox.col_runner"),
    key: "runner",
    render: (row) =>
      h(
        NTag,
        {
          size: "small",
          type: row.runner === "native" ? "default" : "info",
          bordered: false,
        },
        { default: () => row.runner },
      ),
  },
  {
    title: t("sandbox.col_net"),
    key: "network",
    render: (row) =>
      h(
        "span",
        {
          class:
            row.network === "allow"
              ? "text-vigils-green"
              : "text-vigils-red",
        },
        row.network,
      ),
  },
  {
    title: t("sandbox.col_read_dirs"),
    key: "readDirs",
    render: (row) => String(row.readDirs.length),
  },
]);

function selectProfile(row: SandboxProfile): void {
  selectedId.value = row.id;
}

function commaList(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function joinList(value: string[]): string {
  return value.join(", ");
}

function saveProfile(): void {
  // Placeholder: when the backend exposes sandbox profile management,
  // this will call the IPC API. For now the form edits the local state.
}
</script>

<template>
  <div class="p-6 h-full overflow-auto">
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Profiles table -->
      <NCard
        class="bg-vigils-bg-panel border-vigils-bg-surface lg:col-span-2"
        :bordered="true"
        :title="t('sandbox.profiles')"
        size="small"
      >
        <NDataTable
          :columns="columns"
          :data="profiles"
          :bordered="false"
          size="small"
          :row-props="(row: SandboxProfile) => ({ onClick: () => selectProfile(row), class: 'cursor-pointer hover:bg-vigils-bg-tertiary/50' })"
          data-testid="sandbox-profiles-table"
        >
          <template #empty>
            <NEmpty :description="t('sandbox.empty')" data-testid="sandbox-empty" />
          </template>
        </NDataTable>
      </NCard>

      <!-- Profile editor -->
      <NCard
        class="bg-vigils-bg-panel border-vigils-bg-surface"
        :bordered="true"
        :title="t('sandbox.profile_editor')"
        size="small"
      >
        <NSpace vertical :size="16">
          <div>
            <label class="block text-xs text-vigils-text-secondary mb-1.5">
              {{ t("sandbox.form_name") }}
            </label>
            <NInput
              :value="selected.name"
              size="small"
              placeholder="profile name"
              data-testid="sandbox-name-input"
              @update:value="(v: string) => { selected.name = v; }"
            />
          </div>

          <div>
            <label class="block text-xs text-vigils-text-secondary mb-1.5">
              {{ t("sandbox.runner_kind") }}
            </label>
            <NSelect
              :value="selected.runner"
              :options="runnerOptions"
              size="small"
              data-testid="sandbox-runner-select"
              @update:value="(v: RunnerKind) => { selected.runner = v; }"
            />
          </div>

          <div>
            <label class="block text-xs text-vigils-text-secondary mb-1.5">
              {{ t("sandbox.network_allowed") }}
            </label>
            <NSelect
              :value="selected.network"
              :options="networkOptions"
              size="small"
              data-testid="sandbox-network-select"
              @update:value="(v: NetPolicy) => { selected.network = v; }"
            />
          </div>

          <div>
            <label class="block text-xs text-vigils-text-secondary mb-1.5">
              {{ t("sandbox.read_directories") }}
            </label>
            <NInput
              :value="joinList(selected.readDirs)"
              size="small"
              placeholder="/path/a, /path/b"
              data-testid="sandbox-read-dirs-input"
              @update:value="(v: string) => { selected.readDirs = commaList(v); }"
            />
          </div>

          <div>
            <label class="block text-xs text-vigils-text-secondary mb-1.5">
              {{ t("sandbox.write_directories") }}
            </label>
            <NInput
              :value="joinList(selected.writeDirs)"
              size="small"
              placeholder="/path/a, /path/b"
              data-testid="sandbox-write-dirs-input"
              @update:value="(v: string) => { selected.writeDirs = commaList(v); }"
            />
          </div>

          <div>
            <label class="block text-xs text-vigils-text-secondary mb-1.5">
              {{ t("sandbox.env_allowlist") }}
            </label>
            <NInput
              :value="joinList(selected.envAllowlist)"
              size="small"
              placeholder="PATH, HOME"
              data-testid="sandbox-env-input"
              @update:value="(v: string) => { selected.envAllowlist = commaList(v); }"
            />
          </div>

          <div>
            <label class="block text-xs text-vigils-text-secondary mb-1.5">
              {{ t("sandbox.server_bindings") }}
            </label>
            <div class="space-y-1.5">
              <div
                v-for="binding in bindings"
                :key="binding.serverId"
                class="text-sm"
              >
                <span class="text-vigils-text-secondary">{{ binding.serverId }}</span>
                <span class="mx-1.5 text-vigils-text-muted">→</span>
                <span
                  :class="
                    binding.profileId === selected.id
                      ? 'text-vigils-cyan'
                      : 'text-vigils-text-primary'
                  "
                >
                  {{ binding.profileId }}
                </span>
              </div>
            </div>
          </div>

          <NButton
            type="primary"
            size="medium"
            class="w-full"
            data-testid="sandbox-save-profile"
            @click="saveProfile"
          >
            {{ t("sandbox.save_profile") }}
          </NButton>
        </NSpace>
      </NCard>
    </div>
  </div>
</template>
