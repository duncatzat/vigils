// Mock **现代专属**(2026-07-28+)stdio MCP server(测试用)。
//
// 行为按 2026-07-28 spec「Backward Compatibility」:
//   - `initialize`      → JSON-RPC error(现代服务器没有握手方法;错误码实现自定义,此处 -32601)
//   - `server/discover` → DiscoverResult(supportedVersions 只列现代版本)
//   - 其它              → -32601
//
// 用途:验证 vigil-hub 作为旧时代客户端遇到现代专属上游时,能用 discover 探针**确定性**判出
// 「modern-era only」并给出可操作诊断(P0-3a),而不是笼统的 protocol 错误。
//
// 协议:JSON-RPC 2.0 NDJSON(每行一个 JSON)。

import readline from 'node:readline';

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

function write(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

function errorResp(id, code, message) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

rl.on('line', (line) => {
  const l = line.trim();
  if (!l) return;
  let msg;
  try {
    msg = JSON.parse(l);
  } catch {
    write(errorResp(null, -32700, 'parse error'));
    return;
  }
  const { id, method } = msg;
  if (id === undefined) return; // notification:忽略

  if (method === 'server/discover') {
    write({
      jsonrpc: '2.0',
      id,
      result: {
        resultType: 'complete',
        supportedVersions: ['2026-07-28'],
        capabilities: { tools: { listChanged: false } },
        cacheScope: 'public',
        ttlMs: 60000,
        _meta: {
          'io.modelcontextprotocol/serverInfo': { name: 'mock-mcp-modern-only', version: '1.0.0' },
        },
      },
    });
    return;
  }
  if (method === 'initialize') {
    // 现代专属服务器不认识 initialize;按 spec 建议在错误里点名支持的版本
    write(errorResp(id, -32601, 'Method not found: initialize (this server supports 2026-07-28 only)'));
    return;
  }
  write(errorResp(id, -32601, `Method not found: ${method}`));
});
