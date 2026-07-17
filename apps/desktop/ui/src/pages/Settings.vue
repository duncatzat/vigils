<script setup lang="ts">
/**
 * Settings —— 系统设置中枢(R3 Phase 1 引擎模式 + 姿态;Phase 2 模型安装 + 常驻 daemon 已接活)。
 *
 * - 引擎模式(hardfp/ml/auto)+ 安全姿态(low/medium/high):经 vigil-hub CLI 落盘读写
 *   (engine.json / posture.json)。**姿态即时生效**(hook 每次工具调用消费 posture)。
 * - 模型安装(`model install/status`)+ 常驻 daemon 生命周期(`daemon start/stop/status`,ADR 0024):
 *   经 vigil-hub CLI shell-out。turnkey:装模型 → 启 daemon(暖载)→ 引擎设 ml → hook 主路径跑 ML。
 *   daemon 独立于 GUI 生命周期(detached;为 agent hook 服务,不随关窗而停)。
 *
 * 安全契约:文案经 i18n 纯 {named} 插值(CSP-safe),禁 v-html;写入值后端 whitelist 校验。
 */
import { onMounted, onUnmounted, ref } from "vue";
import { NButton } from "naive-ui";
import { useI18n } from "vue-i18n";
import { useRouter } from "vue-router";
import { getVersion } from "@tauri-apps/api/app";
import {
  settingsGet,
  setPosture,
  setEngineMode,
  daemonStatus,
  daemonStart,
  daemonStop,
  modelStatus,
  modelInstall,
  downloadMlEngine,
  guardianStatus,
  anchorCheckpoint,
  type SettingsStatus,
  type DaemonStatus,
  type ModelStatus,
} from "@/api/ipc";
import WindowCard from "@/components/WindowCard.vue";
import StatusPill from "@/components/StatusPill.vue";

const { t } = useI18n();
const router = useRouter();

const ENGINE_MODES = ["hardfp", "ml", "auto"] as const;
const POSTURES = ["low", "medium", "high"] as const;

const settings = ref<SettingsStatus | null>(null);
const daemon = ref<DaemonStatus | null>(null);
const model = ref<ModelStatus | null>(null);
const loading = ref(false);
const busy = ref<string | null>(null); // 正在写入的项 key(防并发点击)
const error = ref<string | null>(null);
// about 卡事实(此前只有「将在此显示」占位句,版本/账本从未真正渲染)
const appVersion = ref<string>("");
const ledgerPath = ref<string>("");

async function refresh(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    const [s, d, m] = await Promise.all([
      settingsGet(),
      daemonStatus(),
      modelStatus(),
    ]);
    settings.value = s;
    daemon.value = d;
    model.value = m;
    // 账本路径来自 guardian 聚合状态;best-effort,失败不阻塞设置页主体。
    try {
      ledgerPath.value = (await guardianStatus()).ledger;
    } catch {
      /* 保持上次值 */
    }
  } catch (e) {
    error.value = String(e);
  } finally {
    loading.value = false;
  }
}

async function pickEngine(mode: string): Promise<void> {
  if (busy.value || settings.value?.engine_mode === mode) return;
  busy.value = `engine:${mode}`;
  error.value = null;
  try {
    settings.value = await setEngineMode(mode);
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = null;
  }
}

async function pickPosture(profile: string): Promise<void> {
  if (busy.value || settings.value?.posture === profile) return;
  busy.value = `posture:${profile}`;
  error.value = null;
  try {
    settings.value = await setPosture(profile);
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = null;
  }
}

// GUI-06(审核 ISS-20260702-008):daemon_start 后端只等 800ms,cached-model 暖载可能
// 更久 —— 启动后短时轮询(1s × ≤60 次,覆盖 ~45s 的 ort 暖载上限)至 pii_loaded/停止,
// 让 pill 从「启动中(暖载)」自动走到「运行中 · ML 已暖」,不再需要手动刷新。
// 只读轮询,不占 busy 锁。
let warmPollTimer: ReturnType<typeof setInterval> | null = null;
function stopWarmPoll(): void {
  if (warmPollTimer !== null) clearInterval(warmPollTimer);
  warmPollTimer = null;
}
function startWarmPoll(): void {
  stopWarmPoll();
  let ticks = 0;
  warmPollTimer = setInterval(async () => {
    ticks += 1;
    try {
      const d = await daemonStatus();
      daemon.value = d;
      // warming(暖载窗口)期间继续轮;彻底停止 / 已暖 / 超时上限才收手。
      if ((!d.running && !d.warming) || d.pii_loaded || ticks >= 60) stopWarmPoll();
    } catch {
      stopWarmPoll(); // 查询失败不重试轰炸;用户可手动刷新
    }
  }, 1000);
}
onUnmounted(stopWarmPoll);

async function startDaemon(): Promise<void> {
  if (busy.value) return;
  busy.value = "daemon:start";
  error.value = null;
  try {
    daemon.value = await daemonStart();
    // running(快速就绪但 ML 未暖)或 warming(暖载窗口)都继续轮询到就绪。
    if (daemon.value && !daemon.value.pii_loaded && (daemon.value.running || daemon.value.warming))
      startWarmPoll();
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = null;
  }
}

async function stopDaemon(): Promise<void> {
  if (busy.value) return;
  busy.value = "daemon:stop";
  error.value = null;
  try {
    daemon.value = await daemonStop();
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = null;
  }
}

async function installModel(): Promise<void> {
  if (busy.value) return;
  busy.value = "model:install";
  error.value = null;
  try {
    model.value = await modelInstall();
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = null;
  }
}

// 手动锚定审计检查点(公开版既有功能):成功显示锚点 event id,链头未前进则如实提示。
const anchorResult = ref<string | null>(null);
async function handleAnchorCheckpoint(): Promise<void> {
  if (busy.value) return;
  busy.value = "checkpoint:anchor";
  error.value = null;
  anchorResult.value = null;
  try {
    const eventId = await anchorCheckpoint();
    anchorResult.value =
      eventId != null
        ? t("settings.checkpoint.anchored", { eventId })
        : t("settings.checkpoint.no_new_event");
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = null;
  }
}

// 装 ML 引擎变体（让 ml_supported 翻 true，再可装模型）。出厂硬指纹引擎无 ort，必经此步。
// 该安装自带完整引擎（不要求本机已有引擎）；装好后全量 refresh —— engine_present 翻 true,
// 引擎模式/姿态/daemon 等控件的门禁随之解锁（GUI-01 鸡生蛋修复的收尾）。
async function installMlEngine(): Promise<void> {
  if (busy.value) return;
  busy.value = "ml-engine:install";
  error.value = null;
  try {
    model.value = await downloadMlEngine();
    await refresh();
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = null;
  }
}

onMounted(() => {
  void refresh();
  // 应用版本(Tauri core API,静态一次即可;失败保持 "—")。
  getVersion()
    .then((v) => {
      appVersion.value = v;
    })
    .catch(() => {});
});
</script>

<template>
  <div class="settings">
    <div class="phead">
      <span class="ptitle">{{ t("settings.page_title") }}</span>
      <StatusPill v-if="settings && !settings.engine_present" tone="yellow">
        {{ t("settings.engine_absent") }}
      </StatusPill>
      <!-- GUI-04(审核 ISS-20260702-006):引擎缺失时本页给出前进路径,不再全灰无解 -->
      <NButton
        v-if="settings && !settings.engine_present"
        size="tiny"
        type="primary"
        data-testid="engine-absent-cta"
        @click="router.push('/protection')"
      >
        {{ t("settings.engine_absent_cta") }}
      </NButton>
    </div>

    <!-- 1. AI 引擎与模型 -->
    <WindowCard title="engine · model" class="block" data-testid="settings-engine-card">
      <div class="sec-head">
        <div>
          <div class="s-title">{{ t("settings.engine.title") }}</div>
          <div class="s-sub">{{ t("settings.engine.subtitle") }}</div>
        </div>
      </div>
      <div class="modes">
        <button
          v-for="m in ENGINE_MODES"
          :key="m"
          type="button"
          class="mode"
          :class="{ on: settings?.engine_mode === m, busy: busy === `engine:${m}` }"
          :disabled="!!busy || loading || !settings?.engine_present"
          :data-testid="`engine-mode-${m}`"
          @click="pickEngine(m)"
        >
          <div class="mode-name">{{ t(`settings.engine.mode_${m}`) }}</div>
          <div class="mode-desc">{{ t(`settings.engine.mode_${m}_desc`) }}</div>
        </button>
      </div>
      <div class="row">
        <div>
          <div class="s-title sm">{{ t("settings.model.title") }}</div>
          <div class="s-sub">{{ t("settings.model.subtitle") }}</div>
        </div>
        <div class="ctl">
          <StatusPill
            v-if="model && !model.ml_supported"
            tone="yellow"
            data-testid="model-state"
          >
            {{ t("settings.model.unsupported") }}
          </StatusPill>
          <StatusPill
            v-else-if="model?.privacy_installed && model?.injection_installed"
            tone="green"
            data-testid="model-state"
          >
            {{ t("settings.model.installed") }}
          </StatusPill>
          <StatusPill v-else tone="cyan" data-testid="model-state">
            {{ t("settings.model.not_installed") }}
          </StatusPill>
          <!-- 安装 ML 引擎变体自带完整引擎(ort vigil-hub + ONNX Runtime),不依赖既有引擎:
               故此按钮不受 engine_present 门禁约束(否则无引擎首启用户无自救路径,鸡生蛋)。 -->
          <NButton
            v-if="model && !model.ml_supported"
            size="small"
            type="primary"
            :loading="busy === 'ml-engine:install'"
            :disabled="!!busy || loading"
            data-testid="ml-engine-install"
            @click="installMlEngine()"
          >
            {{ t("settings.model.install_ml_engine") }}
          </NButton>
          <NButton
            size="small"
            type="primary"
            :loading="busy === 'model:install'"
            :disabled="
              !!busy ||
              loading ||
              !settings?.engine_present ||
              !model?.ml_supported ||
              !!(model?.privacy_installed && model?.injection_installed)
            "
            data-testid="model-install"
            @click="installModel()"
          >
            {{ t("settings.model.install") }}
          </NButton>
        </div>
      </div>
    </WindowCard>

    <!-- 2. 安全姿态(即时生效:hook 消费) -->
    <WindowCard title="posture" class="block" data-testid="settings-posture-card">
      <div class="sec-head">
        <div>
          <div class="s-title">{{ t("settings.posture.title") }}</div>
          <div class="s-sub">{{ t("settings.posture.subtitle") }}</div>
        </div>
      </div>
      <div class="modes">
        <button
          v-for="p in POSTURES"
          :key="p"
          type="button"
          class="mode"
          :class="{ on: settings?.posture === p, busy: busy === `posture:${p}` }"
          :disabled="!!busy || loading || !settings?.engine_present"
          :data-testid="`posture-${p}`"
          @click="pickPosture(p)"
        >
          <div class="mode-name">{{ t(`settings.posture.${p}`) }}</div>
          <div class="mode-desc">{{ t(`settings.posture.${p}_desc`) }}</div>
        </button>
      </div>
    </WindowCard>

    <!-- 3. 守护进程(ADR 0024:暖载 ML 供 hook 主路径) -->
    <WindowCard title="daemon · aegis" class="block" data-testid="settings-daemon-card">
      <div class="row first">
        <div>
          <div class="s-title">{{ t("settings.daemon.title") }}</div>
          <!-- 模型未装时如实降级承诺:此时启动的 daemon 两个模型都不加载,hook 走硬指纹底座。 -->
          <div class="s-sub">{{
            model && !(model.privacy_installed || model.injection_installed)
              ? t("settings.daemon.subtitle_no_model")
              : t("settings.daemon.subtitle")
          }}</div>
        </div>
        <div class="ctl">
          <StatusPill v-if="daemon?.running" tone="green" data-testid="daemon-state">
            {{
              daemon.pii_loaded
                ? t("settings.daemon.status_ml")
                : t("settings.daemon.status_running")
            }}
          </StatusPill>
          <StatusPill v-else-if="daemon?.warming" tone="yellow" data-testid="daemon-state">
            {{ t("settings.daemon.status_warming") }}
          </StatusPill>
          <StatusPill v-else tone="yellow" data-testid="daemon-state">
            {{ t("settings.daemon.status_stopped") }}
          </StatusPill>
          <NButton
            v-if="!daemon?.running && !daemon?.warming"
            size="small"
            type="primary"
            :loading="busy === 'daemon:start'"
            :disabled="!!busy || loading || !settings?.engine_present"
            data-testid="daemon-start"
            @click="startDaemon()"
          >
            {{ t("settings.daemon.start") }}
          </NButton>
          <NButton
            v-else
            size="small"
            :loading="busy === 'daemon:stop'"
            :disabled="!!busy || loading"
            data-testid="daemon-stop"
            @click="stopDaemon()"
          >
            {{ t("settings.daemon.stop") }}
          </NButton>
        </div>
      </div>
    </WindowCard>

    <!-- 4. 关于(版本 + 账本路径自动加载,不再是「将在此显示」的占位) -->
    <WindowCard
      title="audit · checkpoint"
      class="block"
      data-testid="settings-checkpoint-card"
    >
      <div class="row first">
        <div>
          <div class="s-title">{{ t("settings.checkpoint.title") }}</div>
          <div class="s-sub">{{ t("settings.checkpoint.note") }}</div>
          <div v-if="anchorResult" class="s-sub" data-testid="checkpoint-anchor-result">
            {{ anchorResult }}
          </div>
        </div>
        <NButton
          size="small"
          tertiary
          :loading="busy === 'checkpoint:anchor'"
          data-testid="checkpoint-anchor-btn"
          @click="handleAnchorCheckpoint"
        >
          {{ t("settings.checkpoint.anchor_now") }}
        </NButton>
      </div>
    </WindowCard>

    <WindowCard title="about" class="block" data-testid="settings-about-card">
      <div class="row first">
        <div>
          <div class="s-sub">{{ t("settings.about.note") }}</div>
          <div class="about-facts">
            <div>
              <span class="af-label">{{ t("settings.about.version_label") }}</span>
              <span class="af-val" data-testid="about-version">{{ appVersion || "—" }}</span>
            </div>
            <div>
              <span class="af-label">{{ t("settings.about.ledger_label") }}</span>
              <span class="af-val" data-testid="about-ledger">{{ ledgerPath || "—" }}</span>
            </div>
          </div>
        </div>
        <NButton size="small" quaternary :loading="loading" @click="refresh()">
          {{ t("common.refresh") }}
        </NButton>
      </div>
    </WindowCard>

    <div v-if="error" class="errline" data-testid="settings-error">⚠ {{ error }}</div>
  </div>
</template>

<style scoped>
.settings {
  max-width: 1080px;
  margin: 0 auto;
  padding: 18px 28px 40px;
}
.phead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}
.ptitle {
  font-family: var(--vigil-mono);
  font-size: 13px;
  letter-spacing: 1px;
  color: var(--vigil-text-secondary);
}
.block {
  margin-top: 14px;
}
.sec-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.s-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--vigil-text);
}
.s-title.sm {
  font-size: 13.5px;
}
.s-sub {
  margin-top: 3px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--vigil-text-secondary);
}
.modes {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-top: 14px;
}
.mode {
  -webkit-appearance: none;
  appearance: none;
  width: 100%;
  text-align: left;
  padding: 12px 14px;
  border: 1px solid var(--vigil-border);
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.02);
  color: inherit;
  font-family: inherit;
  cursor: pointer;
  opacity: 0.78;
  transition:
    border-color 0.15s ease,
    background 0.15s ease,
    opacity 0.15s ease;
}
.mode:hover:not(:disabled):not(.on) {
  opacity: 1;
  border-color: rgba(5, 217, 232, 0.25);
}
.mode.on {
  border-color: rgba(5, 217, 232, 0.45);
  background: rgba(5, 217, 232, 0.07);
  opacity: 1;
}
.mode.busy {
  opacity: 0.55;
}
.mode:disabled {
  cursor: default;
}
.mode-name {
  font-family: var(--vigil-mono);
  font-size: 13px;
  font-weight: 700;
  color: var(--vigil-text);
}
.mode-desc {
  margin-top: 5px;
  font-size: 11.5px;
  line-height: 1.5;
  color: var(--vigil-text-secondary);
}
.row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-top: 14px;
}
.row.first {
  margin-top: 0;
}
.ctl {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}
.errline {
  margin-top: 14px;
  font-size: 12.5px;
  color: var(--vigil-red);
}

/* about 卡事实行(版本 / 账本路径,mono 仪表风) */
.about-facts {
  margin-top: 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-family: var(--vigil-mono);
  font-size: 11.5px;
}
.about-facts .af-label {
  color: var(--vigil-text-muted);
  margin-right: 10px;
}
.about-facts .af-val {
  color: var(--vigil-text);
  word-break: break-all;
}
</style>
