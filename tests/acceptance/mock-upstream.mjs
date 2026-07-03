// mock-upstream.mjs — 极简 stdio MCP upstream(供核心功能 e2e attach）。
// 工具:
//   echo   —— 把 text 原样返回(观测 Vigil 在工具边界注入的**真值**是否到达)
//   leaky  —— 无视入参,结果里**吐出一个 secret**(观测 Vigil 的结果再脱敏)
// 协议:JSON-RPC 2.0 NDJSON。仅最小 MCP 集。
import readline from "node:readline";
import { appendFileSync } from "node:fs";
// argv[2] = sideband 文件路径(测试用 upstream-config 的 argv **逐字**转发过来——不经 Vigil 的
// env 白名单/脱敏)。echo 把**实际收到**的 text 追加到此,测试据此确认工具边界拿到的真值,
// 绕开 Vigil 对 upstream **stderr** 的 scrub 转发(那是正确的纵深防御,不适合当观测点)。
const SIDEBAND = process.argv[2] || null;
const SERVER = { name: "mock-upstream", version: "1.0.0" };
const TOOLS = [
  { name: "echo", description: "echo text back", inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } },
  { name: "leaky", description: "returns a secret in its output", inputSchema: { type: "object", properties: {} } },
];
const w = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  const l = line.trim(); if (!l) return;
  let req; try { req = JSON.parse(l); } catch { return; }
  const { id, method, params } = req;
  if (method === "initialize") w({ jsonrpc: "2.0", id, result: { protocolVersion: "2025-03-26", capabilities: { tools: { listChanged: false } }, serverInfo: SERVER } });
  else if (method === "notifications/initialized" || method === "initialized") { /* notif */ }
  else if (method === "ping") w({ jsonrpc: "2.0", id, result: {} });
  else if (method === "tools/list") w({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
  else if (method === "tools/call") {
    const name = params?.name; const args = params?.arguments ?? {};
    if (name === "echo") {
      // 把工具**实际收到**的 text 写旁路文件(测试据此断言真值到达工具边界),并原样返回
      // (经 Vigil 的 injected 逆替换后客户端侧应无明文)。
      const got = String(args.text ?? "");
      if (SIDEBAND) { try { appendFileSync(SIDEBAND, got + "\n"); } catch {} }
      w({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: got }] } });
    } else if (name === "leaky") {
      w({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: "here is a token ghp_leakABCDEF1234567890abcdef1234567890 ok" }] } });
    } else w({ jsonrpc: "2.0", id, error: { code: -32601, message: "unknown tool: " + name } });
  } else if (method === "shutdown") { w({ jsonrpc: "2.0", id, result: null }); process.exit(0); }
  else w({ jsonrpc: "2.0", id, error: { code: -32601, message: "not implemented: " + method } });
});
rl.on("close", () => process.exit(0));
process.stderr.write("[upstream] ready\n");
