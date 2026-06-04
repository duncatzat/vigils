// Strict stdio MCP server(回归测试用)——— 严格执行 MCP 客户端生命周期。
//
// 与宽松版 mock-mcp-server.mjs 的关键区别:在收到 `initialize`(并回响应)+
// `notifications/initialized` 之前,对 `tools/list` / `tools/call` 一律返
// JSON-RPC error(-32002 "server not initialized")—— 这正是 @modelcontextprotocol
// 官方 SDK server(filesystem 等)的真实行为。
//
// 用途:守住 vigil-hub 的 `initialize_handshake` 回归。若 Hub 在 attach 上游时漏掉握手
// (历史 bug:spawn 了 upstream 却从不 initialize),严格 server 会拒绝 tools/list →
// Hub 聚合 0 工具 → 对应的 Rust 测试(serve_smoke.rs)断言失败。
//
// 协议:JSON-RPC 2.0 NDJSON(每行一个 JSON)。

import readline from 'node:readline';

const SERVER_INFO = { name: 'strict-mcp-server', version: '1.0.0' };

const TOOLS = [
  {
    name: 'strict_tool',
    description: 'A tool only reachable after the MCP initialize handshake',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string' } },
      required: ['text'],
    },
  },
];

// 生命周期状态:必须 initialize(回响应)+ initialized 之后才进入 operational。
let sawInitialize = false;
let initialized = false;

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

function write(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

function errorResp(id, code, message) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

// 未完成握手时调用普通方法 → fail-closed 错误(官方 SDK server 的真实行为)。
function notInitialized(id) {
  return errorResp(id, -32002, 'server not initialized: complete the MCP handshake first');
}

rl.on('line', (line) => {
  const l = line.trim();
  if (!l) return;
  let req;
  try {
    req = JSON.parse(l);
  } catch (e) {
    process.stderr.write(`[strict-upstream] bad json: ${l}\n`);
    return;
  }
  const { id, method, params } = req;

  switch (method) {
    case 'initialize':
      sawInitialize = true;
      write({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2025-06-18',
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
        },
      });
      break;

    case 'initialized':
    case 'notifications/initialized':
      // 必须先见过 initialize 请求才认这条 notification(严格)
      if (sawInitialize) initialized = true;
      // notification,不响应
      break;

    case 'ping':
      write({ jsonrpc: '2.0', id, result: {} });
      break;

    case 'tools/list':
      if (!initialized) {
        write(notInitialized(id));
        process.stderr.write('[strict-upstream] REJECTED tools/list before handshake\n');
        break;
      }
      write({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
      break;

    case 'tools/call': {
      if (!initialized) {
        write(notInitialized(id));
        break;
      }
      const name = params?.name;
      const args = params?.arguments ?? {};
      if (name === 'strict_tool') {
        const text = String(args.text ?? '');
        write({
          jsonrpc: '2.0',
          id,
          result: { content: [{ type: 'text', text: `strict: ${text}` }] },
        });
      } else {
        write(errorResp(id, -32601, `unknown tool: ${name}`));
      }
      break;
    }

    case 'shutdown':
      write({ jsonrpc: '2.0', id, result: null });
      process.exit(0);
      break;

    default:
      write(errorResp(id, -32601, `method not implemented: ${method}`));
  }
});

rl.on('close', () => {
  process.stderr.write('[strict-upstream] stdin closed\n');
  process.exit(0);
});

process.stderr.write(`[strict-upstream] ready (pid=${process.pid})\n`);
