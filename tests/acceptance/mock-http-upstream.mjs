// mock-http-upstream.mjs — 极简 Streamable HTTP MCP upstream(供 http-e2e attach)。
// 与 mock-upstream.mjs(stdio)同一套工具语义,但走 MCP Streamable HTTP(2025-03-26):
//   echo   —— JSON 响应;把收到的 text + Authorization header 写 sideband(观测真值到边界)
//   leaky  —— **SSE 响应**(text/event-stream 单事件折叠),结果吐 secret(测 SSE 折叠 + 再脱敏)
// argv[2] = sideband 文件;argv[3] = 端口文件(listen 127.0.0.1:0 后写真实端口,e2e 轮询)。
import http from "node:http";
import { appendFileSync, writeFileSync } from "node:fs";

const SIDEBAND = process.argv[2] || null;
const PORTFILE = process.argv[3] || null;
const sb = (line) => { if (SIDEBAND) { try { appendFileSync(SIDEBAND, line + "\n"); } catch {} } };

const SERVER = { name: "mock-http-upstream", version: "1.0.0" };
const TOOLS = [
  { name: "echo", description: "echo text back", inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } },
  { name: "leaky", description: "returns a secret in its output (SSE response)", inputSchema: { type: "object", properties: {} } },
];
const rpcResult = (id, result) => JSON.stringify({ jsonrpc: "2.0", id, result });

const srv = http.createServer((req, res) => {
  if (req.method !== "POST") { res.writeHead(405, { Allow: "POST" }).end(); return; }
  let body = "";
  req.on("data", (d) => { body += d; });
  req.on("end", () => {
    let m; try { m = JSON.parse(body); } catch { res.writeHead(400).end(); return; }
    const { id, method, params } = m;
    if (id == null) { res.writeHead(202).end(); return; } // notification(initialized 等)
    const json = (payload) => { res.writeHead(200, { "Content-Type": "application/json" }).end(payload); };
    if (method === "initialize") {
      json(rpcResult(id, { protocolVersion: "2025-03-26", capabilities: { tools: { listChanged: false } }, serverInfo: SERVER }));
    } else if (method === "ping") {
      json(rpcResult(id, {}));
    } else if (method === "tools/list") {
      json(rpcResult(id, { tools: TOOLS }));
    } else if (method === "tools/call") {
      const name = params?.name; const args = params?.arguments ?? {};
      if (name === "echo") {
        // 记录工具边界**实际收到**的入参与鉴权头(e2e 据此断言真值/token 到达)。
        sb("TEXT:" + String(args.text ?? ""));
        sb("AUTH:" + String(req.headers["authorization"] ?? ""));
        json(rpcResult(id, { content: [{ type: "text", text: String(args.text ?? "") }] }));
      } else if (name === "leaky") {
        // SSE 单事件响应:覆盖网关的 text/event-stream 折叠路径。
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        const payload = rpcResult(id, { content: [{ type: "text", text: "here is a token ghp_leakABCDEF1234567890abcdef1234567890 ok" }] });
        res.end("event: message\ndata: " + payload + "\n\n");
      } else {
        json(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32601, message: "unknown tool: " + name } }));
      }
    } else {
      json(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32601, message: "not implemented: " + method } }));
    }
  });
});
srv.listen(0, "127.0.0.1", () => {
  const port = srv.address().port;
  if (PORTFILE) writeFileSync(PORTFILE, String(port));
  process.stderr.write(`[mock-http] listening on 127.0.0.1:${port}\n`);
});
