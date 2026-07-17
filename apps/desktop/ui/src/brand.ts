import { h, type VNode } from "vue";

/**
 * Vigils 品牌资产映射 —— 官方 logo + 22 枚 3D 徽记(public/brand/),对齐官网 vigils.ai。
 *
 * 徽记按 module 配**语义色**(呼应官网八环多色,破单色压抑感):
 * 🔴firewall 🟢approval 🟡policy 🔵sandbox 🟣lease 粉lock 蓝gateway 橙audit。
 */
export const LOGO = "/brand/logo.png";
export const EMBLEM = (name: string): string => `/brand/icons/${name}.png`;

/** module → 语义色 */
export const MODULE_COLOR: Record<string, string> = {
  firewall: "#ff4d6d",
  approval: "#00ff9d",
  policy: "#facc15",
  sandbox: "#05d9e8",
  lease: "#a855f7",
  lock: "#f472b6",
  gateway: "#3b82f6",
  audit: "#fb923c",
  replay: "#2dd4bf",
};

/** 导航路由 → 官方徽记 + 色(替代手画 SVG)。 */
export const NAV_EMBLEM: Record<string, { icon: string; color: string }> = {
  protection: { icon: "firewall", color: "#ff4d6d" },
  approvals: { icon: "approval", color: "#00ff9d" },
  activity: { icon: "audit", color: "#fb923c" },
  privacy: { icon: "lock", color: "#f472b6" },
  servers: { icon: "gateway", color: "#3b82f6" },
  sessions: { icon: "replay", color: "#2dd4bf" },
  // 系统设置:中性 slate 色(区别于八防御模块的鲜色)+ desktop 徽记(无 gear 资产时的最近语义)。
  settings: { icon: "desktop", color: "#94a3b8" },
};

/** 八重纵深防御层(顺时针自顶,用于 Protection 首页轨道 hero)。label 走 i18n `protection.ring.<key>`。 */
export const DEFENSE_RING: { key: string; color: string }[] = [
  { key: "firewall", color: "#ff4d6d" },
  { key: "approval", color: "#00ff9d" },
  { key: "policy", color: "#facc15" },
  { key: "sandbox", color: "#05d9e8" },
  { key: "lease", color: "#a855f7" },
  { key: "lock", color: "#f472b6" },
  { key: "gateway", color: "#3b82f6" },
  { key: "audit", color: "#fb923c" },
];

/** NMenu `option.icon` 渲染函数:官方徽记 <img> + 每模块色辉光(继承品牌)。 */
export function navEmblemIcon(route: string): () => VNode {
  const e = NAV_EMBLEM[route] ?? { icon: "target", color: "#05d9e8" };
  return () =>
    h("img", {
      src: EMBLEM(e.icon),
      width: 21,
      height: 21,
      alt: "",
      style: `display:block;filter:drop-shadow(0 0 4px ${e.color})`,
    });
}
