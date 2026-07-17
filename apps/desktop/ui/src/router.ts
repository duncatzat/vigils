import { createRouter, createWebHashHistory, type RouteRecordRaw } from "vue-router";

/**
 * Router(I08b-α2 起演进)。
 *
 * 全部 8 条路由均映射真实页面,当前无未实装占位(早期 α3/α4/α5 的 NotImplemented
 * 占位已全部被真实页面取代并删除 —— 审核 ISS-20260702-007)。
 *
 * 用 hash history(Tauri 打包 SPA 本地路径友好,避免 file:// 协议冲突)。
 */
const routes: RouteRecordRaw[] = [
  {
    // D19:默认落地 = Protection Overview(首屏即见"Vigil 拦下了什么",面向采用)。
    path: "/",
    redirect: "/protection",
  },
  // D19 — Protection Overview(= CLI inspect protection 的 GUI 等价物)
  {
    path: "/protection",
    name: "protection",
    component: () => import("@/pages/ProtectionOverview.vue"),
    meta: { title: "Protection Overview" },
  },
  {
    path: "/approvals",
    name: "approvals",
    component: () => import("@/pages/ApprovalQueue.vue"),
    meta: { title: "Approval Queue" },
  },
  {
    path: "/activity",
    name: "activity",
    component: () => import("@/pages/ActivityFeed.vue"),
    meta: { title: "Activity Feed" },
  },
  {
    path: "/servers",
    name: "servers",
    component: () => import("@/pages/ServerRegistry.vue"),
    meta: { title: "Server Registry" },
  },
  {
    path: "/sessions",
    name: "sessions",
    component: () => import("@/pages/SessionReplay.vue"),
    meta: { title: "Session Replay" },
  },
  // ISS-017 — Privacy Findings 聚合面板
  {
    path: "/privacy",
    name: "privacy",
    component: () => import("@/pages/PrivacyFindings.vue"),
    meta: { title: "Privacy Findings" },
  },
  // R3 — Settings(系统设置中枢:AI 引擎/模型 + 姿态 + daemon + 关于)
  {
    path: "/settings",
    name: "settings",
    component: () => import("@/pages/Settings.vue"),
    meta: { title: "Settings" },
  },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});
