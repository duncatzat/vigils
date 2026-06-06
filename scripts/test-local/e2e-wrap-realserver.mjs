// 评估用 E2E:`vigil-hub wrap` 包裹一个**真实第三方 MCP server**(@modelcontextprotocol/server-filesystem
// via npx),而非简单 mock。目的:用真实 server 暴露集成问题(真 MCP 协议握手 / npx 经 wrap 的 env 透传
// [env_clear bug 类] / 真实工具形态)。这正是 `setup --mcp --apply` 包裹一个常见 server 的真实运行形态。
//
// 验证:
//  1. wrap 经 npx 起真 filesystem server 并聚合其**真实工具**(tools/list 非空 = 握手+env 透传成功)
//  2. MONITOR 下调一个只读工具(list/read)→ 经网关放行 + 真 server 真执行(返回真实内容)
//  3. 审计账本真实写入

import { spawn } from 'node:child_process';
import { once } from 'node:events';
import readline from 'node:readline';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

const WRAP_BIN = process.argv[2] || path.resolve('target/debug/vigil-hub.exe');
const OUT = path.resolve('dist/test-results/e2e-wrap-realserver');
fs.mkdirSync(OUT, { recursive: true });

// 真 server 的 allowed dir:临时目录放一个已知文件,list/read 应能看到。
const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-fs-e2e-'));
fs.writeFileSync(path.join(SANDBOX, 'hello.txt'), 'vigil real-server e2e marker\n');
console.log(`[rs-e2e] wrap=${WRAP_BIN}`);
console.log(`[rs-e2e] sandbox=${SANDBOX}`);

const INIT = { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'rs-e2e', version: '1' } };

function startWrap(ledger) {
  // monitor:无 desktop resolver 时让风险/未知 effect 自动放行+审计(否则阻塞 ~300s)。
  const args = [
    'wrap', '--server-id', 'fs', '--monitor', '--ledger', ledger,
    '--', 'npx', '-y', '@modelcontextprotocol/server-filesystem', SANDBOX,
  ];
  const proc = spawn(WRAP_BIN, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  proc.stderr.on('data', (b) => process.stderr.write(`[wrap-stderr] ${b}`));
  proc.on('error', (e) => { console.error('[rs-e2e] spawn error:', e); process.exit(2); });
  const rl = readline.createInterface({ input: proc.stdout, crlfDelay: Infinity });
  const pending = new Map();
  rl.on('line', (line) => {
    const l = line.trim();
    if (!l) return;
    let o;
    try { o = JSON.parse(l); } catch { return; }
    if (o.id != null && pending.has(o.id)) { pending.get(o.id)(o); pending.delete(o.id); }
  });
  const call = (id, method, params) =>
    new Promise((res, rej) => {
      pending.set(id, res);
      proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) }) + '\n');
      setTimeout(() => { if (pending.has(id)) { pending.delete(id); rej(new Error(`timeout ${method}`)); } }, 30000);
    });
  return { proc, call };
}

async function main() {
  const fails = [];
  const summary = { sandbox: SANDBOX };
  const ledger = path.join(OUT, 'fs.sqlite');
  try { fs.unlinkSync(ledger); } catch {}

  const w = startWrap(ledger);
  // npx 首次解析/启动较慢 + initialize 握手:给足时间。
  await new Promise((r) => setTimeout(r, 8000));

  const init = await w.call(1, 'initialize', INIT);
  if (init.result?.serverInfo?.name !== 'vigil-hub') {
    fails.push(`initialize 非 vigil-hub: ${JSON.stringify(init).slice(0, 200)}`);
  }

  const list = await w.call(2, 'tools/list');
  const tools = (list.result?.tools || []).map((t) => t.name);
  console.log('[rs-e2e] tools/list:', tools);
  summary.tools = tools;
  // 关键:真 filesystem server 经 npx 起来了吗?(空 = 握手/env 透传失败 = env_clear bug 类)
  if (tools.length === 0) {
    fails.push('CRITICAL: wrap 经 npx 起真 filesystem server 后 tools/list 为空 —— 握手或 env(PATH)透传失败');
  }
  // 找一个只读列目录/读文件工具(真 server 工具名:list_directory / read_text_file 等)
  const readTool = tools.find((t) => /list_directory|directory|read_text_file|read_file|list/i.test(t));
  summary.read_tool = readTool || null;

  if (readTool) {
    // 经网关调真工具。list_directory 取 path 参数;read_text_file 取 path。先试 list_directory 形态。
    const isList = /list|directory/i.test(readTool);
    const args = isList ? { path: SANDBOX } : { path: path.join(SANDBOX, 'hello.txt') };
    const r = await w.call(3, 'tools/call', { name: readTool, arguments: args });
    const text = JSON.stringify(r);
    console.log(`[rs-e2e] call ${readTool}:`, text.slice(0, 300));
    if (r.error) {
      // 网关 deny(monitor 下不应 deny 只读)或上游错误 —— 记录但不一定是 fail(看 code)
      fails.push(`MONITOR 下只读工具 ${readTool} 返 error(应放行): ${JSON.stringify(r.error).slice(0, 200)}`);
    } else {
      const got = text.includes('hello.txt') || text.includes('marker') || (r.result?.content && r.result.content.length > 0);
      if (!got) fails.push(`只读工具返回但内容不含预期(hello.txt/marker): ${text.slice(0, 200)}`);
      else { console.log(`[rs-e2e] ${readTool} ALLOWED + 真 server 真执行 OK`); summary.read_ok = true; }
    }
  } else if (tools.length > 0) {
    fails.push(`未找到 list/read 工具(真 server 工具名未识别): ${tools.join(',')}`);
  }

  w.proc.stdin.end();
  await once(w.proc, 'exit').catch(() => {});

  const lok = fs.existsSync(ledger) && fs.statSync(ledger).size >= 8000;
  if (!lok) fails.push(`ledger 未真实写入: ${fs.existsSync(ledger) ? fs.statSync(ledger).size + 'B' : 'missing'}`);
  else { console.log(`[rs-e2e] ledger ${fs.statSync(ledger).size}B OK`); summary.ledger_bytes = fs.statSync(ledger).size; }

  try { fs.rmSync(SANDBOX, { recursive: true, force: true }); } catch {}
  fs.writeFileSync(path.join(OUT, 'summary.json'), JSON.stringify({ ...summary, fails }, null, 2));
  if (fails.length) {
    console.error('[rs-e2e] FAIL:');
    fails.forEach((f) => console.error('  -', f));
    process.exit(1);
  }
  console.log('[rs-e2e] ALL REAL-SERVER WRAP E2E CHECKS PASS');
  console.log(JSON.stringify(summary, null, 2));
}

main().catch((e) => { console.error('[rs-e2e] fatal:', e); process.exit(2); });
