import { createRouter, createWebHashHistory, type RouteRecordRaw } from "vue-router";

/**
 * Vigils Desktop — 路由结构(与原型图导航一一对应)。
 */
const routes: RouteRecordRaw[] = [
  {
    path: "/",
    redirect: { name: "protection" },
  },
  {
    path: "/protection",
    name: "protection",
    component: () => import("@/pages/ProtectionOverview.vue"),
    meta: { title: "protection.page_title" },
  },
  {
    path: "/approvals",
    name: "approvals",
    component: () => import("@/pages/Approvals.vue"),
    meta: { title: "approval.page_title" },
  },
  {
    path: "/activity",
    name: "activity",
    component: () => import("@/pages/ActivityFeed.vue"),
    meta: { title: "activity.page_title" },
  },
  {
    path: "/sessions",
    name: "sessions",
    component: () => import("@/pages/Sessions.vue"),
    meta: { title: "session.page_title" },
  },
  {
    path: "/servers",
    name: "servers",
    component: () => import("@/pages/Servers.vue"),
    meta: { title: "server.page_title" },
  },
  {
    path: "/privacy",
    name: "privacy",
    component: () => import("@/pages/PrivacyFindings.vue"),
    meta: { title: "privacy.page_title" },
  },
  {
    path: "/sandbox",
    name: "sandbox",
    component: () => import("@/pages/Sandbox.vue"),
    meta: { title: "sandbox.page_title" },
  },
  {
    path: "/settings",
    name: "settings",
    component: () => import("@/pages/Settings.vue"),
    meta: { title: "settings.page_title" },
  },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});
