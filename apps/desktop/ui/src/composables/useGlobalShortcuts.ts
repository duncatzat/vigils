/**
 * v0.14 Theme B — Global keyboard shortcuts(productivity layer)。
 *
 * 设计取舍:
 * - **零 npm 依赖**:vanilla `keydown` listener,不引 mousetrap/hotkeys-js
 * - **chord 模式**:`g` 是 prefix,1.2s 内按下导航键(a/q/s/r/p)生效
 * - **input 守门**:focus 在 `<input>` / `<textarea>` / contenteditable 时
 *   所有快捷键禁用(避免劫持输入),但 `Escape` 例外(收起 modal)
 * - **router 解耦**:hook 接收 router 实例由调用方注入,便于 unit test
 * - **help modal**:`?` 切换显示,由调用方传入 `helpOpen` ref 控制
 *
 * 不实现(留 alpha.5 后续):
 * - per-page row navigation(j/k + Enter/Esc)— 与 NDataTable 深度集成,
 *   需统一抽象 selectedRow store,留下一 iter
 * - ApprovalQueue `a/r/d` action 快捷键 — 同上,需 selectedRow 上下文
 */
import { onMounted, onUnmounted, type Ref } from "vue";
import type { Router } from "vue-router";

/** g-prefix chord 映射:key → route name */
const NAV_CHORDS: Record<string, string> = {
  a: "activity",
  q: "approvals",
  s: "servers",
  r: "sessions",
  p: "privacy",
};

const CHORD_TIMEOUT_MS = 1200;

/**
 * 判定 event 是否发生在编辑控件内 — 这些控件应保留原生输入行为,
 * 不让快捷键劫持。Exported for page-level shortcut hooks reuse.
 */
export function isEditingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  if (target.isContentEditable) return true;
  // Naive UI NInput 内部 wrapper:.n-input__input-el 是真实 <input>
  // 上面已经覆盖;此处保留显式注释作为契约
  return false;
}

/**
 * `/` 焦点目标查找:
 * - 直接标记的元素 `[data-shortcut="search"]`(原生 input/textarea)
 * - 或 wrapper 标记 `[data-shortcut-wrapper="search"]` 内部第一个 input
 *   (Naive UI 等组件库 input-props 类型受限,wrapper 模式更稳)
 */
function focusFirstSearchInput(): boolean {
  const direct = document.querySelector<HTMLInputElement>("[data-shortcut=\"search\"]");
  const target = direct ??
    document.querySelector<HTMLInputElement>(
      "[data-shortcut-wrapper=\"search\"] input",
    );
  if (target && typeof target.focus === "function") {
    target.focus();
    if (typeof target.select === "function") target.select();
    return true;
  }
  return false;
}

export function useGlobalShortcuts(opts: {
  router: Router;
  helpOpen: Ref<boolean>;
}): void {
  const { router, helpOpen } = opts;
  let pendingG = false;
  let pendingTimer: ReturnType<typeof setTimeout> | null = null;

  function clearPending(): void {
    pendingG = false;
    if (pendingTimer !== null) {
      clearTimeout(pendingTimer);
      pendingTimer = null;
    }
  }

  function onKeyDown(ev: KeyboardEvent): void {
    // Escape 永远响应(收起 modal),即便在 input 内
    if (ev.key === "Escape") {
      if (helpOpen.value) {
        helpOpen.value = false;
        ev.preventDefault();
      }
      clearPending();
      return;
    }

    // 在 input/textarea/contenteditable 内禁用,避免劫持输入
    if (isEditingTarget(ev.target)) {
      clearPending();
      return;
    }

    // 修饰键:不接管系统/浏览器组合(Ctrl/Cmd/Alt + key)
    if (ev.ctrlKey || ev.metaKey || ev.altKey) {
      clearPending();
      return;
    }

    // chord 后续:g + nav-key
    if (pendingG) {
      const key = ev.key.toLowerCase();
      const target = NAV_CHORDS[key];
      clearPending();
      if (target) {
        ev.preventDefault();
        router.push({ name: target }).catch(() => {
          // 同路由 navigation 会 throw NavigationDuplicated,忽略
        });
      }
      return;
    }

    // `?`(Shift+/):toggle help modal
    if (ev.key === "?") {
      ev.preventDefault();
      helpOpen.value = !helpOpen.value;
      return;
    }

    // `/`:focus search input(若当前页有 data-shortcut=search 标记)
    if (ev.key === "/") {
      if (focusFirstSearchInput()) {
        ev.preventDefault();
      }
      return;
    }

    // `g`:进入 chord 等待
    if (ev.key === "g") {
      pendingG = true;
      pendingTimer = setTimeout(clearPending, CHORD_TIMEOUT_MS);
      return;
    }
  }

  onMounted(() => {
    window.addEventListener("keydown", onKeyDown);
  });

  onUnmounted(() => {
    window.removeEventListener("keydown", onKeyDown);
    clearPending();
  });
}

/**
 * 暴露 chord 映射,供 help modal 渲染。
 *
 * v0.14 Theme D:`descKey` / `groupKey` 存 i18n key,由 ShortcutHelpModal 调
 * `t(...)` 翻译(`keys` 是物理按键,不翻译)。
 */
export const SHORTCUT_REFERENCE = [
  // ── Navigation ──
  { keys: "g a", descKey: "shortcuts.go_activity", groupKey: "shortcuts.group_navigation" },
  { keys: "g q", descKey: "shortcuts.go_approvals", groupKey: "shortcuts.group_navigation" },
  { keys: "g s", descKey: "shortcuts.go_servers", groupKey: "shortcuts.group_navigation" },
  { keys: "g r", descKey: "shortcuts.go_sessions", groupKey: "shortcuts.group_navigation" },
  { keys: "g p", descKey: "shortcuts.go_privacy", groupKey: "shortcuts.group_navigation" },
  // ── Global ──
  { keys: "/", descKey: "shortcuts.focus_search", groupKey: "shortcuts.group_global" },
  { keys: "?", descKey: "shortcuts.toggle_help", groupKey: "shortcuts.group_global" },
  { keys: "Esc", descKey: "shortcuts.close", groupKey: "shortcuts.group_global" },
  // ── ApprovalQueue page ──
  { keys: "j / ↓", descKey: "shortcuts.next_approval", groupKey: "shortcuts.group_approval_queue" },
  { keys: "k / ↑", descKey: "shortcuts.prev_approval", groupKey: "shortcuts.group_approval_queue" },
  { keys: "Enter", descKey: "shortcuts.open_drawer", groupKey: "shortcuts.group_approval_queue" },
  { keys: "a", descKey: "shortcuts.approve_selected", groupKey: "shortcuts.group_approval_queue" },
  { keys: "d", descKey: "shortcuts.deny_selected", groupKey: "shortcuts.group_approval_queue" },
  { keys: "c", descKey: "shortcuts.cancel_selected", groupKey: "shortcuts.group_approval_queue" },
] as const;
