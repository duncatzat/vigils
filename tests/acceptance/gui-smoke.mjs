// gui-smoke.mjs — 桌面 GUI 深冒烟(Windows WebView2 CDP;对**已安装的发布版**)。
//
// 结构无关设计(不硬编码页面/testid,新旧 UI 代都能吃):
//   G1 CDP 可达 + 首屏真渲染(htmlLen/可见元素阈值 —— 白屏检验)
//   G2 动态收集侧栏 hash 路由并逐页遍历:每页可见元素 > 阈值 + 逐页截图
//   G3 双语翻转:localStorage['vigil-locale'] 反转 + reload → 正文 CJK 占比显著变化(再还原)
//   G4 全程零未捕获异常 / console error
//
// 前置:vigils.exe 以
//   WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=<port> --remote-allow-origins=* --user-data-dir=<fresh-empty-dir>"
// 启动。**`--user-data-dir` 指向一个新建空目录是必需的**:当前版本 Edge/WebView2 在存在既有
// 用户配置时不再开放远程调试端口(端口静默不开,连不上 CDP)——专用空 profile 才恢复。缺它会让
// desktop-smoke 门在 runner Edge 自升级后整体失效。用法: node gui-smoke.mjs <port> <out-dir>
import { writeFileSync, mkdirSync } from "node:fs";

const PORT = process.argv[2] || "9222";
const OUT = process.argv[3] || "gui-shots";
const BASE = `http://127.0.0.1:${PORT}`;
mkdirSync(OUT, { recursive: true });

let P = 0, F = 0;
const ok = (m) => { console.log(`  PASS ${m}`); P++; };
const no = (m) => { console.log(`  FAIL ${m}`); F++; };

async function connect() {
  let targets;
  for (let i = 0; i < 60; i++) {
    try {
      targets = await (await fetch(`${BASE}/json`)).json();
      if (targets?.some((t) => t.type === "page")) break;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  const page = (targets || []).find((t) => t.type === "page");
  if (!page) throw new Error("no CDP page target (WebView2 debug port not open?)");
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error("ws fail")); });
  let nextId = 1;
  const pending = new Map();
  const errors = [];
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    if (m.method === "Runtime.exceptionThrown") {
      const d = m.params?.exceptionDetails;
      errors.push("EXC: " + (d?.exception?.description || d?.text || "?").slice(0, 160));
    }
    if (m.method === "Runtime.consoleAPICalled" && m.params?.type === "error") {
      errors.push("CONSOLE: " + (m.params.args || []).map((a) => a.value || a.description || "").join(" ").slice(0, 160));
    }
  };
  const send = (method, params = {}) =>
    new Promise((res) => { const id = nextId++; pending.set(id, res); ws.send(JSON.stringify({ id, method, params })); });
  return { ws, send, errors };
}

async function evalJson(send, expr) {
  const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true });
  try { return JSON.parse(r?.result?.result?.value ?? "null"); } catch { return null; }
}

const FACTS = `JSON.stringify((() => {
  const text = ((document.body && document.body.innerText) || "").replace(/\\s+/g, " ").trim();
  const cjk = (text.match(/[\\u4e00-\\u9fff]/g) || []).length;
  return {
    hash: location.hash,
    htmlLen: document.documentElement.outerHTML.length,
    visibleEls: [...document.querySelectorAll("button,a,h1,h2,div,span,img")].filter(el => el.getClientRects().length).length,
    links: [...new Set([...document.querySelectorAll("a[href^='#/']")].map(a => a.getAttribute("href")))].slice(0, 12),
    cjkRatio: text.length ? cjk / text.length : 0,
    sample: text.slice(0, 120),
  };
})())`;

async function shot(send, name) {
  const s = await send("Page.captureScreenshot", { format: "png" });
  if (s?.result?.data) writeFileSync(`${OUT}/${name}.png`, Buffer.from(s.result.data, "base64"));
}

async function main() {
  const { ws, send, errors } = await connect();
  await send("Page.enable");
  await send("Runtime.enable");
  await new Promise((r) => setTimeout(r, 4000)); // 首屏挂载

  // G1 首屏真渲染(白屏检验)
  const f0 = await evalJson(send, FACTS);
  console.log("== G1 first paint ==");
  console.log(`  facts: ${JSON.stringify({ ...f0, links: (f0?.links || []).length })}`);
  f0 && f0.htmlLen > 800 ? ok(`htmlLen=${f0.htmlLen} (>800, not a blank shell)`) : no(`htmlLen=${f0?.htmlLen} (blank screen?)`);
  f0 && f0.visibleEls > 10 ? ok(`visibleEls=${f0.visibleEls} (>10)`) : no(`visibleEls=${f0?.visibleEls}`);
  await shot(send, "initial");

  // G2 动态路由遍历(从真实 DOM 收集,不硬编码页面集)
  console.log("== G2 route walk ==");
  const links = f0?.links || [];
  links.length >= 3 ? ok(`discovered ${links.length} hash routes from the sidebar`) : no(`only ${links.length} hash routes discovered`);
  for (const href of links) {
    const route = href.replace(/^#/, "");
    await send("Runtime.evaluate", { expression: `location.hash=${JSON.stringify(href.slice(1) ? "#" + href.slice(1) : href)}` });
    await send("Runtime.evaluate", { expression: `location.hash=${JSON.stringify(href)}` });
    await new Promise((r) => setTimeout(r, 1800));
    const f = await evalJson(send, FACTS);
    const slug = route.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "") || "root";
    f && f.visibleEls > 5 ? ok(`${route} renders (visibleEls=${f.visibleEls})`) : no(`${route} looks blank (visibleEls=${f?.visibleEls})`);
    await shot(send, `page-${slug}`);
  }

  // G3 双语翻转(vigil-locale)
  console.log("== G3 locale flip ==");
  const orig = await evalJson(send, `JSON.stringify(localStorage.getItem('vigil-locale'))`);
  const before = (await evalJson(send, FACTS))?.cjkRatio ?? 0;
  const target = before > 0.05 ? "en-US" : "zh-CN";
  await send("Runtime.evaluate", { expression: `localStorage.setItem('vigil-locale','${target}'); location.reload()` });
  await new Promise((r) => setTimeout(r, 3500));
  const after = (await evalJson(send, FACTS))?.cjkRatio ?? 0;
  const flipped = target === "zh-CN" ? after > before + 0.05 : after < before - 0.05;
  flipped ? ok(`locale flip works (cjkRatio ${before.toFixed(2)} -> ${after.toFixed(2)})`) : no(`locale flip had no effect (${before.toFixed(2)} -> ${after.toFixed(2)})`);
  await shot(send, `locale-${target}`);
  const restore = orig ? `localStorage.setItem('vigil-locale',${JSON.stringify(orig)})` : `localStorage.removeItem('vigil-locale')`;
  await send("Runtime.evaluate", { expression: `${restore}; location.reload()` });
  await new Promise((r) => setTimeout(r, 1500));

  // G4 零 console error / 未捕获异常
  console.log("== G4 console hygiene ==");
  errors.length === 0 ? ok("zero console errors / uncaught exceptions across the walk") : no(`${errors.length} console errors, first: ${errors[0]}`);

  ws.close();
  console.log(`\n========== GUI-SMOKE SUMMARY: ${P} passed, ${F} failed ==========`);
  process.exit(F === 0 ? 0 : 1);
}
main().catch((e) => { console.error("gui-smoke error:", e.message); process.exit(2); });
