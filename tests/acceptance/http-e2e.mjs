// http-e2e.mjs — 远程 MCP(Streamable HTTP upstream)防护不变量 e2e。
//
// core-e2e.mjs 验证的是 stdio upstream;本脚本把**同一组安全不变量**推到 HTTP 传输上:
//   H1 tools/list:HTTP upstream 的工具经网关命名空间化暴露
//   H2 Bearer 注入:配置 `auth:{bearer:{source:"env:..."}}` 的**真值 token**到达 upstream
//        的 Authorization 头(sideband 观测),且 token 不回显客户端、不入审计
//   H3 密钥租约四段(HTTP 版):args secret://alias → 工具边界收到真值 → 客户端无明文
//   H4 SSE 折叠 + 结果再脱敏:upstream 以 text/event-stream 响应吐 secret → 客户端看不到明文
//   H5 裸 secret 拦截:明文 key 不被转发到 HTTP upstream
//   H6 审计无明文:ledger 全文不含 lease 真值 / bearer token / 裸 key 任何一个
//
// 老版本(serve 不支持 `{name,url}` upstream 或无 --monitor)优雅 SKIP(exit 0)。
// 用法: HUB=/path/to/vigil-hub node http-e2e.mjs
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HUB = process.env.HUB;
if (!HUB) { console.error("set HUB=path to vigil-hub"); process.exit(2); }

try {
  const help = execFileSync(HUB, ["serve", "--help"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (!help.includes("--monitor")) {
    console.log("SKIP http-e2e: this vigil-hub build has no `serve --monitor` (pre-dates it).");
    process.exit(0);
  }
} catch (e) {
  console.log("SKIP http-e2e: `serve --help` probe failed (" + e.message + ")");
  process.exit(0);
}

const MOCK = join(import.meta.dirname, "mock-http-upstream.mjs");
const SBX = mkdtempSync(join(tmpdir(), "vigil-http-"));
const LEDGER = join(SBX, "ledger.sqlite3");
const SIDEBAND = join(SBX, "upstream-received.txt");
const PORTFILE = join(SBX, "port.txt");
// 三个都用真实指纹形态:lease 真值、bearer token、裸 key——各是一条独立的不泄漏不变量。
const REAL_SECRET = "ghp_realleased1234567890abcdef1234567890";
const HTTP_TOKEN = "ghp_httpbearer567890abcdef1234567890abcd";
const RAW_KEY = "AKIAIOSFODNN7EXAMPLE";

let P = 0, F = 0;
const ok = (m) => { console.log(`  PASS ${m}`); P++; };
const no = (m) => { console.log(`  FAIL ${m}`); F++; };

const mock = spawn(process.execPath, [MOCK, SIDEBAND, PORTFILE], { stdio: ["ignore", "ignore", "pipe"] });
let mockErr = "";
mock.stderr.on("data", (d) => { mockErr += d.toString(); });

async function waitPort() {
  for (let i = 0; i < 50; i++) {
    if (existsSync(PORTFILE)) { const p = readFileSync(PORTFILE, "utf8").trim(); if (p) return p; }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("mock http upstream did not report a port");
}

let hub = null;
let stderrBuf = "";
let idc = 0;
const pending = new Map();
let rxBuf = "";
const rpc = (method, params) => new Promise((res, rej) => {
  const id = ++idc; pending.set(id, res);
  hub.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  setTimeout(() => { if (pending.has(id)) { pending.delete(id); rej(new Error(`timeout ${method}`)); } }, 30000);
});
const notify = (method, params) => hub.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
const textOf = (r) => (r?.result?.content || []).map((c) => c.text || "").join(" ");
const cleanup = () => { try { hub?.kill(); } catch {} try { mock.kill(); } catch {} try { rmSync(SBX, { recursive: true, force: true }); } catch {} };

async function main() {
  const port = await waitPort();
  const cfg = {
    upstreams: [{ name: "mockhttp", url: `http://127.0.0.1:${port}/mcp`, auth: { bearer: { source: "env:VIGIL_E2E_HTTP_TOKEN" } } }],
    secrets: { ghlease: { source: "env:VIGIL_E2E_SECRET", server: "mockhttp" } },
  };
  const cfgPath = join(SBX, "upstreams.json");
  writeFileSync(cfgPath, JSON.stringify(cfg));

  hub = spawn(HUB, [
    "serve", "--stdio",
    "--upstream-config", cfgPath,
    "--ledger", LEDGER,
    "--redact-tool-results",
    "--monitor",
    "--auto-approve-first-seen",
  ], {
    env: { ...process.env, VIGIL_E2E_SECRET: REAL_SECRET, VIGIL_E2E_HTTP_TOKEN: HTTP_TOKEN, VIGIL_LEDGER_PATH: LEDGER, VIGIL_LANG: "en" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  hub.stderr.on("data", (d) => { stderrBuf += d.toString(); });
  hub.stdout.on("data", (d) => {
    rxBuf += d.toString();
    let nl;
    while ((nl = rxBuf.indexOf("\n")) >= 0) {
      const line = rxBuf.slice(0, nl).trim(); rxBuf = rxBuf.slice(nl + 1);
      if (!line) continue;
      let m; try { m = JSON.parse(line); } catch { continue; }
      if (m.id != null && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    }
  });

  // 早退探测:老 build 不认 `{name,url}` upstream(deny_unknown_fields / needs argv)会启动即报错退出。
  const early = await new Promise((res) => {
    const t = setTimeout(() => res(null), 2500);
    hub.once("exit", (code) => { clearTimeout(t); res(code ?? 1); });
  });
  if (early !== null) {
    if (/unknown field|needs either|invalid upstream|url/i.test(stderrBuf)) {
      console.log("SKIP http-e2e: this vigil-hub build has no HTTP upstream support (pre-dates it).");
      cleanup(); process.exit(0);
    }
    no("serve exited early (code " + early + "): " + stderrBuf.slice(-300));
    console.log(`\n========== HTTP-E2E SUMMARY: ${P} passed, ${F} failed ==========`);
    cleanup(); process.exit(1);
  }

  const init = await rpc("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "http-e2e", version: "1" } });
  init?.result ? ok("initialize handshake") : no("initialize failed: " + JSON.stringify(init).slice(0, 120));
  notify("notifications/initialized");

  // H1 tools/list via HTTP upstream
  const tl = await rpc("tools/list", {});
  const names = (tl?.result?.tools || []).map((t) => t.name);
  names.some((n) => n.includes("echo")) ? ok(`H1 tools/list via HTTP upstream (${names.join(",")})`) : no("H1 echo not exposed: " + names.join(",") + " stderr=" + stderrBuf.slice(-200));
  const echoTool = names.find((n) => n.includes("echo"));
  const leakyTool = names.find((n) => n.includes("leaky"));

  // H2+H3 echo call: bearer header + lease four-leg over HTTP
  console.log("== H2 bearer injection / H3 lease four-leg (HTTP) ==");
  const r2 = await rpc("tools/call", { name: echoTool, arguments: { text: "auth secret://ghlease done" } });
  const out2 = textOf(r2);
  await new Promise((r) => setTimeout(r, 400));
  let received = "";
  try { received = readFileSync(SIDEBAND, "utf8"); } catch {}
  received.includes("AUTH:Bearer " + HTTP_TOKEN) ? ok("H2: real Bearer token reached the upstream Authorization header") : no("H2: bearer token missing at upstream (sideband=" + JSON.stringify(received.trim()).slice(0, 160) + ")");
  out2.includes(HTTP_TOKEN) ? no("H2: bearer token LEAKED into client-visible result") : ok("H2: bearer token not in client-visible result");
  received.includes("TEXT:") && received.includes(REAL_SECRET) ? ok("H3 leg3: upstream received the REAL lease secret at the tool boundary") : no("H3 leg3: upstream did NOT receive real lease value");
  out2.includes(REAL_SECRET) ? no("H3 leg4: lease secret LEAKED back to the client") : ok("H3 leg4: client result carries no plaintext lease secret");

  // H4 SSE-collapsed leaky result is re-redacted
  if (leakyTool) {
    console.log("== H4 SSE response collapse + re-redaction ==");
    const r4 = await rpc("tools/call", { name: leakyTool, arguments: {} });
    const out4 = textOf(r4);
    if (!r4?.result) no("H4: leaky (SSE) call failed: " + JSON.stringify(r4).slice(0, 160));
    else {
      out4.includes("ghp_leakABCDEF") ? no("H4: SSE leaky secret reached client unredacted") : ok("H4: SSE-collapsed leaky secret redacted before client");
      out4.length > 0 ? ok("H4: SSE response collapsed to a usable result") : no("H4: SSE response collapsed to empty result");
    }
  } else no("H4: leaky tool not exposed");

  // H5 raw secret in args must not reach the HTTP upstream
  console.log("== H5 raw-secret arg not forwarded over HTTP ==");
  const before = (() => { try { return readFileSync(SIDEBAND, "utf8"); } catch { return ""; } })();
  await rpc("tools/call", { name: echoTool, arguments: { text: `key ${RAW_KEY}` } }).catch(() => ({}));
  await new Promise((r) => setTimeout(r, 400));
  const after = (() => { try { return readFileSync(SIDEBAND, "utf8"); } catch { return ""; } })();
  after.slice(before.length).includes(RAW_KEY) ? no("H5: raw key was forwarded to HTTP upstream") : ok("H5: raw key NOT forwarded to HTTP upstream");

  try { await rpc("shutdown", {}); } catch {}
  hub.stdin.end();
  await new Promise((r) => setTimeout(r, 800));
  try { hub.kill(); } catch {}

  // H6 ledger has no plaintext of ANY of the three sensitive values
  console.log("== H6 audit ledger has no plaintext ==");
  try {
    const hay = readFileSync(LEDGER).toString("latin1");
    const leaks = [["lease", REAL_SECRET], ["bearer", HTTP_TOKEN], ["raw", RAW_KEY]].filter(([, v]) => hay.includes(v));
    leaks.length === 0 ? ok("H6: no plaintext secret (lease/bearer/raw) anywhere in the ledger") : no("H6: PLAINTEXT FOUND in ledger: " + leaks.map(([k]) => k).join(","));
  } catch (e) { no("H6: could not read ledger: " + e.message); }

  console.log(`\n========== HTTP-E2E SUMMARY: ${P} passed, ${F} failed ==========`);
  cleanup();
  process.exit(F === 0 ? 0 : 1);
}
main().catch((e) => { console.error("http-e2e error:", e.message); console.error((stderrBuf + "\n" + mockErr).slice(-600)); cleanup(); process.exit(2); });
