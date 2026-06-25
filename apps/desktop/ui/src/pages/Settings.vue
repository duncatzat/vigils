<script setup lang="ts">
/**
 * Settings —— 桌面客户端偏好设置。
 *
 * 配置全部来自 `useSettingsStore`,只做 UI 绑定与持久化(localStorage),
 * 不新增后端命令。ONNX / Checkpoint 管理按钮当前为占位操作。
 */
import { computed, onMounted, ref } from "vue";
import {
  NButton,
  NInputNumber,
  NSelect,
  NSlider,
  NSwitch,
  NTag,
  useMessage,
} from "naive-ui";
import type { SelectOption } from "naive-ui";
import { useI18n } from "vue-i18n";
import { invoke } from "@tauri-apps/api/core";
import { useSettingsStore } from "@/stores/settings";
import {
  daemonStatus,
  daemonStart,
  daemonStop,
  modelStatus,
  modelInstall,
  type DaemonStatus,
  type ModelStatus,
} from "@/api/ipc";
import PanelCard from "@/components/PanelCard.vue";

const { t } = useI18n();
const settings = useSettingsStore();
const message = useMessage();

// ─── ML 控制平面（ADR 0024）：常驻 daemon 生命周期 + ML 模型安装（经 vigil-hub CLI shell-out）───
const daemon = ref<DaemonStatus | null>(null);
const model = ref<ModelStatus | null>(null);
// busy 标记当前进行中的写操作（'daemon:start' | 'daemon:stop' | 'model:install'），驱动按钮 loading 态。
const busy = ref<string | null>(null);

const modelInstalled = computed<boolean>(
  () => !!model.value?.privacy_installed && !!model.value?.injection_installed,
);

async function refreshMlControl(): Promise<void> {
  try {
    const [d, m] = await Promise.all([daemonStatus(), modelStatus()]);
    daemon.value = d;
    model.value = m;
  } catch (e) {
    message.error(t("common.ipc_error") + ": " + String(e));
  }
}

async function startDaemon(): Promise<void> {
  if (busy.value) return;
  busy.value = "daemon:start";
  try {
    daemon.value = await daemonStart();
  } catch (e) {
    message.error(t("settings.daemon.error", { msg: String(e) }));
  } finally {
    busy.value = null;
  }
}

async function stopDaemon(): Promise<void> {
  if (busy.value) return;
  busy.value = "daemon:stop";
  try {
    daemon.value = await daemonStop();
  } catch (e) {
    message.error(t("settings.daemon.error", { msg: String(e) }));
  } finally {
    busy.value = null;
  }
}

async function installModel(): Promise<void> {
  if (busy.value) return;
  busy.value = "model:install";
  try {
    model.value = await modelInstall();
  } catch (e) {
    message.error(t("settings.model.error", { msg: String(e) }));
  } finally {
    busy.value = null;
  }
}

onMounted(() => {
  void refreshMlControl();
});

async function handleAnchorCheckpoint(): Promise<void> {
  try {
    const eventId = await invoke<Option<number>>("anchor_checkpoint");
    if (eventId != null) {
      message.success(t("settings.anchor_success", { eventId }));
    } else {
      message.info(t("settings.anchor_no_new_event"));
    }
  } catch (e) {
    message.error(t("settings.anchor_error", { msg: String(e) }));
  }
}

type Option<T> = T | null;

async function handleOnnxManage(): Promise<void> {
  // 当前桌面端未接入真实 ONNX 模型镜像;给出明确提示而非静默无响应。
  message.info(t("settings.onnx_not_implemented"));
}

const themeOptions = computed<SelectOption[]>(() => [
  { label: t("theme.dark"), value: "dark" },
  { label: t("theme.light"), value: "light" },
  { label: t("theme.system"), value: "system" },
]);

const localeOptions = computed<SelectOption[]>(() => [
  { label: t("settings.lang_zh"), value: "zh-CN" },
  { label: t("settings.lang_en"), value: "en-US" },
]);

const postureOptions = computed<SelectOption[]>(() => [
  { label: t("settings.posture_monitor_label"), value: "monitor" },
  { label: t("settings.posture_enforce_label"), value: "enforce" },
]);

const ledgerPath = "~/Library/Application Support/Vigil/ledger.sqlite3";

function updatePollingInterval(v: number | null): void {
  if (typeof v === "number" && !Number.isNaN(v) && v >= 100) {
    settings.setPollingIntervalMs(v);
  }
}
</script>

<template>
  <div class="p-6 space-y-5 max-w-4xl mx-auto">
    <!-- General -->
    <PanelCard>
      <template #header>
        <h2 class="text-base font-semibold text-vigils-text-primary">
          {{ t("settings.section_general") }}
        </h2>
      </template>

      <div class="space-y-5">
        <div class="flex items-center justify-between gap-4">
          <div>
            <div class="text-sm font-medium text-vigils-text-primary">
              {{ t("settings.theme_label") }}
            </div>
            <div class="text-xs text-vigils-text-muted mt-0.5">
              {{ t("settings.theme_desc") }}
            </div>
          </div>
          <NSelect
            :value="settings.themeMode"
            :options="themeOptions"
            size="small"
            class="w-48"
            @update:value="settings.setTheme"
          />
        </div>

        <div class="h-px bg-vigils-border" />

        <div class="flex items-center justify-between gap-4">
          <div>
            <div class="text-sm font-medium text-vigils-text-primary">
              {{ t("settings.language_label") }}
            </div>
            <div class="text-xs text-vigils-text-muted mt-0.5">
              {{ t("settings.language_desc") }}
            </div>
          </div>
          <NSelect
            :value="settings.locale"
            :options="localeOptions"
            size="small"
            class="w-48"
            @update:value="settings.setLocaleCode"
          />
        </div>

        <div class="h-px bg-vigils-border" />

        <div class="flex items-center justify-between gap-4">
          <div>
            <div class="text-sm font-medium text-vigils-text-primary">
              {{ t("settings.ledger_path") }}
            </div>
            <div class="text-xs text-vigils-text-muted mt-0.5">
              {{ t("settings.ledger_readonly") }}
            </div>
          </div>
          <div class="text-sm font-mono text-vigils-text-secondary truncate max-w-md text-right">
            {{ ledgerPath }}
          </div>
        </div>
      </div>
    </PanelCard>

    <!-- Protection -->
    <PanelCard>
      <template #header>
        <h2 class="text-base font-semibold text-vigils-text-primary">
          {{ t("settings.section_protection") }}
        </h2>
      </template>

      <div class="space-y-5">
        <div class="flex items-center justify-between gap-4">
          <div>
            <div class="text-sm font-medium text-vigils-text-primary">
              {{ t("settings.default_posture") }}
            </div>
            <div class="text-xs text-vigils-text-muted mt-0.5">
              {{ t("settings.posture_monitor") }}
            </div>
          </div>
          <NSelect
            :value="settings.defaultPosture"
            :options="postureOptions"
            size="small"
            class="w-48"
            @update:value="settings.setDefaultPosture"
          />
        </div>

        <div class="h-px bg-vigils-border" />

        <div class="flex items-center justify-between gap-4">
          <div class="text-sm font-medium text-vigils-text-primary">
            {{ t("settings.auto_approve_first_seen") }}
          </div>
          <NSwitch
            :value="settings.autoApproveFirstSeen"
            @update:value="settings.setAutoApproveFirstSeen"
          />
        </div>

        <div class="h-px bg-vigils-border" />

        <div class="flex items-center justify-between gap-4">
          <div class="text-sm font-medium text-vigils-text-primary">
            {{ t("settings.redact_tool_results") }}
          </div>
          <NSwitch
            :value="settings.redactToolResults"
            @update:value="settings.setRedactToolResults"
          />
        </div>
      </div>
    </PanelCard>

    <!-- AI Model (ADR 0024 — ML 模型安装) -->
    <PanelCard>
      <template #header>
        <h2 class="text-base font-semibold text-vigils-text-primary">
          {{ t("settings.model.title") }}
        </h2>
        <NTag size="small" :bordered="false" type="info">
          {{ t("settings.model.phase2") }}
        </NTag>
      </template>

      <div class="space-y-5">
        <div class="flex items-start justify-between gap-4">
          <div class="flex-1">
            <div class="text-sm font-medium text-vigils-text-primary">
              {{ t("settings.model.title") }}
            </div>
            <div class="text-xs text-vigils-text-muted mt-0.5">
              {{ t("settings.model.subtitle") }}
            </div>
          </div>
          <div class="flex items-center gap-3 shrink-0">
            <NTag
              v-if="model && !model.ml_supported"
              size="small"
              :bordered="false"
              type="warning"
              data-testid="model-state"
            >
              {{ t("settings.model.unsupported") }}
            </NTag>
            <NTag
              v-else-if="modelInstalled"
              size="small"
              :bordered="false"
              type="success"
              data-testid="model-state"
            >
              {{ t("settings.model.installed") }}
            </NTag>
            <NTag
              v-else-if="model"
              size="small"
              :bordered="false"
              type="info"
              data-testid="model-state"
            >
              {{ t("settings.model.not_installed") }}
            </NTag>
            <NTag v-else size="small" :bordered="false" data-testid="model-state">
              {{ t("settings.model.status_unknown") }}
            </NTag>
            <NButton
              size="small"
              tertiary
              :loading="busy === 'model:install'"
              :disabled="
                busy !== null ||
                !model?.engine_present ||
                !model?.ml_supported ||
                modelInstalled
              "
              data-testid="model-install"
              @click="installModel()"
            >
              {{ t("settings.model.install") }}
            </NButton>
          </div>
        </div>
      </div>
    </PanelCard>

    <!-- Daemon (ADR 0024 — 常驻引擎生命周期) -->
    <PanelCard>
      <template #header>
        <h2 class="text-base font-semibold text-vigils-text-primary">
          {{ t("settings.daemon.title") }}
        </h2>
      </template>

      <div class="space-y-5">
        <div class="flex items-start justify-between gap-4">
          <div class="flex-1">
            <div class="text-sm font-medium text-vigils-text-primary">
              {{ t("settings.daemon.title") }}
            </div>
            <div class="text-xs text-vigils-text-muted mt-0.5">
              {{ t("settings.daemon.subtitle") }}
            </div>
          </div>
          <div class="flex items-center gap-3 shrink-0">
            <NTag
              v-if="daemon?.running"
              size="small"
              :bordered="false"
              type="success"
              data-testid="daemon-state"
            >
              {{
                daemon.pii_loaded
                  ? t("settings.daemon.status_ml")
                  : t("settings.daemon.status_running")
              }}
            </NTag>
            <NTag
              v-else
              size="small"
              :bordered="false"
              type="warning"
              data-testid="daemon-state"
            >
              {{ t("settings.daemon.status_stopped") }}
            </NTag>
            <NButton
              v-if="!daemon?.running"
              size="small"
              tertiary
              :loading="busy === 'daemon:start'"
              :disabled="busy !== null || !daemon?.engine_present"
              data-testid="daemon-start"
              @click="startDaemon()"
            >
              {{ t("settings.daemon.start") }}
            </NButton>
            <NButton
              v-else
              size="small"
              tertiary
              :loading="busy === 'daemon:stop'"
              :disabled="busy !== null || !daemon?.engine_present"
              data-testid="daemon-stop"
              @click="stopDaemon()"
            >
              {{ t("settings.daemon.stop") }}
            </NButton>
          </div>
        </div>
      </div>
    </PanelCard>

    <!-- Advanced -->
    <PanelCard>
      <template #header>
        <h2 class="text-base font-semibold text-vigils-text-primary">
          {{ t("settings.section_advanced") }}
        </h2>
      </template>

      <div class="space-y-5">
        <div class="flex items-center justify-between gap-4">
          <div>
            <div class="text-sm font-medium text-vigils-text-primary">
              {{ t("settings.polling_interval") }}
            </div>
            <div class="text-xs text-vigils-text-muted mt-0.5">
              {{ t("settings.polling_slider") }}
            </div>
          </div>
          <div class="w-48 space-y-2">
            <NInputNumber
              :value="settings.pollingIntervalMs"
              :min="100"
              :max="10000"
              :step="100"
              size="small"
              @update:value="updatePollingInterval"
            >
              <template #suffix>
                <span class="text-vigils-text-muted">ms</span>
              </template>
            </NInputNumber>
            <NSlider
              :value="settings.pollingIntervalMs"
              :min="100"
              :max="5000"
              :step="100"
              @update:value="updatePollingInterval"
            />
          </div>
        </div>

        <div class="h-px bg-vigils-border" />

        <div class="flex items-center justify-between gap-4">
          <div>
            <div class="text-sm font-medium text-vigils-text-primary">
              {{ t("settings.onnx_pii_model") }}
            </div>
            <div class="text-xs text-vigils-text-muted mt-0.5">
              {{ t("settings.onnx_bootstrap") }}
            </div>
          </div>
          <NButton size="small" tertiary @click="handleOnnxManage">
            {{ t("common.manage") }}
          </NButton>
        </div>

        <div class="h-px bg-vigils-border" />

        <div class="flex items-center justify-between gap-4">
          <div>
            <div class="text-sm font-medium text-vigils-text-primary">
              {{ t("settings.checkpoint_anchor") }}
            </div>
            <div class="text-xs text-vigils-text-muted mt-0.5">
              {{ t("settings.anchor_button") }}
            </div>
          </div>
          <NButton size="small" tertiary @click="handleAnchorCheckpoint">
            {{ t("common.manage") }}
          </NButton>
        </div>
      </div>
    </PanelCard>
  </div>
</template>
