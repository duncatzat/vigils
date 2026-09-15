// outbound-e2e.mjs — 出站 LLM-API 闸门(opt-in)验收 e2e。
//
// 与 `crates/vigil-outbound/tests/gate_e2e.rs` **互补而非重复**:那套在进程内直接构造
// `GateConfig` 驱动引擎;本脚本走用户真正走的那条链路 ——
//   磁盘上的 `outbound.json` → CLI `outbound serve` → **已发布的二进制** → 真 TCP → 真上游。
// 判据始终是「**上游实际收到的字节**」,不是「配置在位」。(v0.8.0-beta.1 发布时
// `grep -i outbound tests/acceptance/` 零命中 —— 头牌功能当时没有任何验收覆盖。)
//
// 覆盖:
//   O1  磁盘配置经**产品自己的解析器**回读一致(无 warning / `enabled` / `listen` / upstreams
//       确实指向 mock);闸门起得来;每条请求**恰好**产生一条上游请求(多/少都判红,不让
//       重复与缺失互相抵消)
//   O2  硬指纹矩阵(github_token / aws_access_key_id / anthropic_api_key / openai_api_key):
//       离开本机的字节里**没有原值**,出现 `[REDACTED`,**且请求结构存活**(见下)
//   O3  长度边界:`ghp_`+36 命中;+34 不命中且**原值原样抵达**(只验"没脱敏"不够 ——
//       上游收到 `{}` 也满足"没脱敏");+35 只记录不判定
//   O4  无凭据请求**逐字节原样**转发(不是"含某个子串":那样删掉 model/max_tokens 也能蒙混)
//   O5  鉴权头逐字节透传(订阅登录不被闸门破坏)
//   O6  非 JSON 体 → 415,且**不到达上游**
//   O7  浏览器来源(`Origin`)→ 403,且不到达上游
//   O8  未知路由前缀 → 404,且不到达上游
//   O9  `/vigil/healthz` 可读;带 `Origin` → 403
//   O10 healthz 自述与上游侧实测**互证**(一致性),**并**钉死绝对值 —— 只有等式的话,改写器
//       全线 no-op 时两边都是 0 也相等
//   O11 静置后上游**恰好**收到 N 条 —— 多了=拒绝漏了(含"先拒绝再延迟转发"),少了=链路断了
//   O12 闸门自身日志里不出现任何凭据**或鉴权头**(在 kill 并排空输出**之后**才查)
//   O13 审计账本**确实被写了**(含 `outbound.request.redacted`)且**不含任何明文**:
//       `Ledger::open(..).ok()` 打不开会**静默**退化成 NoopAudit —— 不把账本读回来,
//       「一条审计都没记」和「记得好好的」在外面长得一模一样
//   O14 **四条 vendor 腿的路由身份**:`/openai` `/gemini` `/codex` 各发一条,rest 路径逐字透传;
//       `/codex` 按 `is_chatgpt_auth` 分流(带 `chatgpt-account-id` → `codex_chatgpt`,否则
//       → `openai`),两条必须落在**不同的** mock 上。为此 `codex_chatgpt` 单独指向第二个 mock ——
//       四个上游全写同一个 URL 的话,路由身份在观测面上**根本不存在**,分流写反也看不见
//   O15 **出站字节自检**(最后一道底线):重复 JSON 键 —— `serde_json` 只留最后一个,改写走的是
//       解析后的树因此不命中,**原字节直通**时前一个值里的凭据仍在 → 必须 422 `residual_secret`
//       且**不出境**。改写是尽力而为,这一道才是兜底;删掉它,上面所有断言照样全绿
//   O16 **响应方向**:转发成功时上游响应体必须**原样**回到客户端。照常回 200 却截断/弄乱响应体的
//       闸门会让所有真实用户立刻不可用,而只看请求方向的话这里是全绿
//
// 不在本脚本范围内(**别把 O1 的绿读成这条**):`enabled` 开关的**行为**。`outbound serve`
// 从不读它(只有 daemon 路径的 `spawn_for_daemon` 读),所以「opt-in 就是 opt-in」要在
// daemon 测试里验;这里只证明它经产品解析器往返一致。
//
// 配置定位:**问产品,不猜**。`outbound serve` 只有 `--listen`(且刻意不传,见下),配置固定
// 来自 `dirs::data_local_dir()/Vigil/outbound.json`;与其在这里重新实现一遍平台规则,不如用
// **同一份 env** 跑 `outbound status --json` 拿它自己报的 `config_path`。
//
// 沙箱纪律:Linux/macOS 靠 `HOME`/`XDG_DATA_HOME` 重定向 → **零足迹**,并在写盘前**硬验**
// `config_path` 确实落在沙箱内(重定向若悄悄失效,下一步就是写用户的真配置)。Windows 的
// `dirs` 走 Known Folder API 不认 env,只能写真实位置,故按 `win-acceptance.ps1` 的同一纪律
// **快照 → 写 → 还原**,并额外把原字节落成 `outbound.json.acc-backup` 旁份 —— 进程被
// SIGKILL / 强杀时内存里的备份会一起消失,旁份是那种情况下唯一能捞回用户配置的东西。
// 旁份用 `wx`(独占创建)兼作**锁**:已存在就中止 —— 那说明上一次没走完还原,那个文件就是
// 用户配置的唯一副本,照常往下跑会拿测试态把它覆盖掉再删掉,然后报绿。
// 还原是**有条件**的:只有当前文件**逐字节**等于我们写下去的那份才回滚。用户在跑测期间执行
// `outbound on` 或拨了桌面开关的话,还原会静默抹掉他刚做的决定 —— 宁可不还原、留旁份、大声说。
// 只删本次新建的文件;目录只在**本次新建且为空**时用非递归 `rmdir` 收掉(递归删会把运行期间
// 别的进程新建的文件一起连坐)。账本走 `VIGIL_LEDGER_PATH`,不落真实数据目录。
// `outbound serve` 不是更新检查入口(`update_check::spawn_daily` 只挂 `serve --stdio` 与
// `daemon start`),故本脚本不产生 ADI ping、不写 `update-check.last`。
//
// 凭据夹具一律复用仓内**已提交**的字面量(push protection 已放行过的形态);长度边界的 35/34
// 变体按构造就不匹配扫描器(`GITHUB_TOKEN_PATTERN` body 下限 36)。
//
// 用法: HUB=/path/to/vigil-hub node outbound-e2e.mjs
import { spawn, execFileSync } from "node:child_process";
import http from "node:http";
import net from "node:net";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmdirSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const HUB = process.env.HUB;
if (!HUB) { console.error("set HUB=path to vigil-hub"); process.exit(2); }

let P = 0, F = 0;
const ok = (m) => { console.log(`  PASS ${m}`); P++; };
const no = (m) => { console.log(`  FAIL ${m}`); F++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const summary = (code) => { console.log(`\n========== OUTBOUND-E2E SUMMARY: ${P} passed, ${F} failed ==========`); process.exit(code); };

// 出站闸门是 v0.8.0 才有的第三条腿,值守套件每周对 Latest 复跑、也可 dispatch 回测历史 tag,
// 所以要能对**早于该功能**的构建优雅 SKIP。但 SKIP 的判据必须是「这个构建**应不应该**有闸门」,
// 不能只是「它有没有」:某次重构误删 `outbound serve`、或 feature gate 配错导致它没编进发布
// 产物,只看"有没有"的话每周只会打印一行 SKIP 然后 **exit 0 —— 整条 job 绿**,旗舰功能整个
// 消失却无人知晓。而「二进制跑不起来」更是产物缺陷,绝不能翻译成绿色。版本号本来就在手里。
const VER = (() => {
  try { return execFileSync(HUB, ["--version"], { encoding: "utf8", timeout: 30000, env: { ...process.env, VIGIL_LANG: "en" }, stdio: ["ignore", "pipe", "pipe"] }).trim(); }
  catch { return ""; }
})();
const vp = (VER.split(/\s+/)[1] || "").split(/[.-]/);
const vmaj = Number(vp[0]), vmin = Number(vp[1]);
// `0.0.x`(未打戳的本地构建 / CI 占位版本)**解析得很干净**,"读不出即 FAIL"兜不住它。
// 所以默认反过来:只有**正向命中**已知的 pre-gate 区间(0.1 ~ 0.7)才 SKIP,其余一律 FAIL。
const preGate = Number.isFinite(vmaj) && Number.isFinite(vmin) && vmaj === 0 && vmin >= 1 && vmin < 8;
const skipOrFail = (what) => {
  if (preGate) {
    console.log(`SKIP outbound-e2e: ${VER} pre-dates the outbound gate (${what}).`);
    process.exit(0);
  }
  no(`${VER || "(version unreadable)"} should ship the outbound gate, but ${what}`);
  summary(1);
};

let help = "";
try {
  help = execFileSync(HUB, ["outbound", "--help"], { encoding: "utf8", timeout: 30000, env: { ...process.env, VIGIL_LANG: "en" }, stdio: ["ignore", "pipe", "pipe"] });
} catch (e) {
  const out = `${e.stdout || ""}${e.stderr || ""}`;
  const ran = typeof e.status === "number";
  if (ran && /unrecognized subcommand|invalid subcommand|unexpected argument/i.test(out)) skipOrFail("it has no `outbound` subcommand");
  no(`published binary could not run \`outbound --help\` (${ran ? `exit ${e.status}` : e.code || e.message})`);
  console.log("  ---- " + (out.trim() || "(no output)").slice(0, 600));
  summary(1);
}
if (!help.includes("serve")) skipOrFail("it has no `outbound serve`");

// (kind, value, expectRedacted) — expectRedacted=null 表示只记录实际行为、不判定(长度边界)。
// ★不变量:`CASES` 里每一条都**必须出境**(脱敏与否都出境)。要加「预期被拒」的用例,它属于
//  `refusals`,不能加进这里。出境总数不再用常量算,而是由每个调用点自己 `expectEgress++`。
const GH36 = "ghp_" + "leakABCDEF1234567890abcdef1234567890";   // 36 → 命中
const CASES = [
  { kind: "github_token/36", value: GH36, expect: true },
  { kind: "github_token/35", value: GH36.slice(0, -1), expect: null },
  { kind: "github_token/34", value: GH36.slice(0, -2), expect: false },
  { kind: "aws_access_key_id", value: "AKIAIOSFODNN7EXAMPLE", expect: true },
  { kind: "anthropic_api_key", value: "sk-ant-ProductLevelKeyABCDEFGHIJKLMNOP", expect: true },
  { kind: "openai_api_key", value: "sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890", expect: true },
];
const PLACEHOLDER = "[REDACTED";
const UPSTREAM_REPLY = '{"ok":true}';
// 矩阵请求的固定前后缀。既用来造 body,也用来验**改写后结构是否存活** —— 单一真源。
const PROMPT_HEAD = "please use my token ";
const PROMPT_TAIL = " to fetch the repo";
// 「凭据没了」只是**现象**;「除了凭据,别的都没变」才是**不变量**。出站改写器里存在一条
// **整串替换**路径(`crates/vigil-outbound/src/rewrite.rs`:凭据**键名**下的字符串值整段换成
// `[REDACTED env_assignment]`,并照样 `report.bump()`)。于是一个「命中就把整个 body 毁掉」的
// 闸门能让 O2 四条全 PASS、O3 的 36 字符条 PASS、O10 计数全对 —— 而唯一逐字节比对的 O4b
// 只覆盖**干净**请求,干净请求按定义永不触发改写。所以被改写的那些请求必须单独验结构。
const structureIntact = (raw) => {
  let j;
  try { j = JSON.parse(raw); } catch { return false; }
  const m = j && Array.isArray(j.messages) ? j.messages[0] : null;
  const c = m && m.content;
  return j.model === "claude-sonnet-5" && j.max_tokens === 16 && m && m.role === "user"
    && typeof c === "string" && c.startsWith(PROMPT_HEAD) && c.endsWith(PROMPT_TAIL);
};
// 鉴权头故意用**真像凭据**的形态:用户真实的 x-api-key 就长这样,而 O5 要证明的正是
// 「闸门不去动鉴权头」(订阅登录不被破坏)。拿一眼就假的值去测,等于没测到那条路。
// 字面量复用仓内已提交的样本(crates/vigil-browser/tests/rule_sync.rs)—— 新造的凭据
// 形态可能被 GitHub push protection 拦下,而被拦后只能重做 commit,追加无效。
const AUTH = "sk-ant-0123456789abcdefghijKLMNOPQR";

const freePort = () => new Promise((res, rej) => {
  const s = net.createServer();
  s.on("error", rej);
  s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); });
});
const waitListen = async (port, budgetMs = 25000) => {
  const end = Date.now() + budgetMs;
  while (Date.now() < end) {
    const up = await new Promise((res) => {
      const c = net.connect({ host: "127.0.0.1", port });
      const done = (v) => { c.destroy(); res(v); };
      c.on("connect", () => done(true));
      c.on("error", () => done(false));
      setTimeout(() => done(false), 500);
    });
    if (up) return true;
    await sleep(250);
  }
  return false;
};

// ── mock 上游:**进程内**记录实际收到的 body/headers ────────────────────────────
// 刻意不用旁路文件:上一版工装在 Windows 上两次因「捕获传不回断言端」打出
// "raw credential left the machine" 这句最重的安全指控,两次都是工装坏了、产品没坏。
// 同进程持有捕获字节,这条故障模式从结构上消失。
// **两个**上游而不是一个:`codex_chatgpt` 单独指向 B。四个上游全写同一个 URL 的话,闸门选了
// 哪条腿在观测面上根本不存在 —— `/codex` 的 `is_chatgpt_auth` 分流写反(ChatGPT 登录的流量被
// 发去 API-key 端点)本套件会完全看不见,而负向对照照样红,给出「路由有覆盖」的假印象。
const captured = [];
const mkUpstream = (tag) => http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (d) => chunks.push(d));
  req.on("end", () => {
    captured.push({ up: tag, path: req.url, headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": String(UPSTREAM_REPLY.length) });
    res.end(UPSTREAM_REPLY);
  });
});
const upA = mkUpstream("A");
const upB = mkUpstream("B");

const WIN = process.platform === "win32";
const SBX = mkdtempSync(join(tmpdir(), "vigil-outb-"));
const HOME = join(SBX, "home");
const LEDGER = join(SBX, "ledger.sqlite3");
mkdirSync(HOME, { recursive: true });

const env = { ...process.env, VIGIL_LANG: "en", VIGIL_LEDGER_PATH: LEDGER };
if (!WIN) {
  env.HOME = HOME;
  env.XDG_DATA_HOME = join(HOME, ".local", "share");
  env.XDG_CONFIG_HOME = join(HOME, ".config");
  env.XDG_CACHE_HOME = join(HOME, ".cache");
}

// 配置位置**问产品要**(用的是等会儿交给闸门的同一份 env),不在这里重新实现一遍
// `dirs::data_local_dir()` 的平台规则 —— 猜错就会备份/写/还原一个闸门根本不读的文件。
let CFG;
try {
  const st = JSON.parse(execFileSync(HUB, ["outbound", "status", "--json"], { encoding: "utf8", timeout: 30000, env, stdio: ["ignore", "pipe", "pipe"] }));
  CFG = st.config_path;
} catch (e) {
  no(`could not ask the binary for its config path (\`outbound status --json\`): ${e.message}`);
  try { rmSync(SBX, { recursive: true, force: true }); } catch {}
  summary(1);
}
if (typeof CFG !== "string" || !CFG) {
  no("`outbound status --json` did not report a config_path");
  try { rmSync(SBX, { recursive: true, force: true }); } catch {}
  summary(1);
}
const CFG_DIR = dirname(CFG);
const BACKUP_SIDECAR = CFG + ".acc-backup";

// unix 上重定向若悄悄失效(env 没被继承、产品改了解析规则),下一步就是覆盖用户的真配置。
// 写盘**之前**硬验一次;不在沙箱内就中止,绝不"先写了再说"。
if (!WIN && !CFG.startsWith(SBX)) {
  no(`sandbox escape: config_path ${CFG} is outside ${SBX} — refusing to touch a real user config`);
  try { rmSync(SBX, { recursive: true, force: true }); } catch {}
  summary(1);
}

// 旁份必须是本次运行独占的。已经存在 = 上一次没能走完还原,那个文件就是用户配置的唯一副本。
// (真正的互斥靠下面 `wx` 的独占创建;这一步只是为了给人一句看得懂的话。)
if (existsSync(BACKUP_SIDECAR)) {
  no(`a previous run left ${BACKUP_SIDECAR} behind. THAT FILE IS YOUR ORIGINAL ${CFG}.`);
  console.log("  ---- restore it by hand (and delete the sidecar) before re-running; refusing to overwrite it.");
  try { rmSync(SBX, { recursive: true, force: true }); } catch {}
  summary(1);
}
let sidecarWritten = false;

// 快照:原文件字节(没有则 null)+ 目录是否本来就在。还原只依赖这两个事实 + 我们写下去的字节。
const cfgDirPreExisted = existsSync(CFG_DIR);
const cfgBackup = existsSync(CFG) ? readFileSync(CFG) : null;
let cfgWritten = false;     // 「我们**动过**这个文件」——必须在写之前置位,不是写成功之后:
                            // 截断后写失败也算动过,那正是最需要还原的一种情况。
let wroteBytes = null;      // 我们写下去的确切内容;还原前拿它跟磁盘现状比对
let restored = false;
let restoreFailed = false;  // 只在**第一次**失败时计红:SUMMARY 打印后再 F++ 会与已输出的那行对不上
function restore() {
  if (restored) return;
  let hardFailure = null;
  try {
    if (cfgWritten) {
      // 还原是**有条件**的。用户可能在跑测期间执行了 `outbound on` 或拨了桌面开关
      // (`store_outbound` 走 tmp+rename 换掉了文件)—— 无条件写回等于**静默抹掉他刚做的
      // 决定**,而且会被记成还原成功。所以:磁盘现状必须逐字节等于我们写下去的那份才回滚。
      const current = existsSync(CFG) ? readFileSync(CFG, "utf8") : null;
      if (current !== null && wroteBytes !== null && current !== wroteBytes) {
        F++;
        console.log(`  FAIL ${CFG} changed on disk during the run — it is no longer the bytes we wrote.`);
        console.log("  ---- NOT rolling it back (that would revert whatever you just did).");
        if (cfgBackup !== null) console.log(`  ---- the pre-test bytes are kept at ${BACKUP_SIDECAR}; delete it once you have decided.`);
        restored = true;   // 已做出决定,exit 钩子不必再来一次
        try { rmSync(SBX, { recursive: true, force: true }); } catch {}
        return;
      }
      // 原字节放回,并**镜像产品自己的原子写**(`store_outbound`:同目录 tmp + rename)。
      // 裸 `writeFileSync` 是截断覆盖:还原中途断电 / 被强杀会把用户配置写成**截断态** ——
      // 那比停在测试态更糟,`load_outbound` 会走 fail_closed,闸门静默不启动而 agent 仍指向
      // 它,正是 route.rs 注释里说的「极难自查的砖化」。产品都不敢裸写这个文件。
      if (cfgBackup !== null) { const t = CFG + ".acc-tmp"; writeFileSync(t, cfgBackup); renameSync(t, CFG); }
      else if (existsSync(CFG)) unlinkSync(CFG);                      // 只删本次新建的那一个
    }
    // 只删**本次**写的那份:别人留下的旁份是某次事故里用户配置的唯一副本。
    if (sidecarWritten && existsSync(BACKUP_SIDECAR)) unlinkSync(BACKUP_SIDECAR);
    // 目录只在**本次新建**时收掉,且用**非递归** rmdir:非空即失败。递归删会把运行期间别的
    // 进程在同目录新建的文件(ledger / posture / engine)一起连坐。
    if (!cfgDirPreExisted && existsSync(CFG_DIR) && readdirSync(CFG_DIR).length === 0) rmdirSync(CFG_DIR);
  } catch (e) {
    hardFailure = e;
  }
  if (hardFailure) {
    // 还原失败必须响、必须计红、且**不置 restored** —— 后面的 exit 钩子要能再试一次。
    if (!restoreFailed) { restoreFailed = true; F++; }
    console.log(`  FAIL could not restore ${CFG}: ${hardFailure.message}`);
    if (cfgBackup !== null) console.log(`  ---- original bytes remain at ${BACKUP_SIDECAR} — restore by hand`);
    return;
  }
  restored = true;
  try { rmSync(SBX, { recursive: true, force: true }); } catch {}
}
process.on("exit", restore);
// Windows 上 `SIGTERM` 根本投递不了;Ctrl-Break 是 `SIGBREAK`,关掉控制台窗口是 `SIGHUP`。
// 不注册这两个,Node 直接终止、`exit` 钩子不跑,用户的真实配置就停在测试态(`enabled:true`
// + upstreams 指向一个已经死掉的回环端口 = 他的 LLM 流量当场断),而且屏幕上一个字都不会说。
// (实测 `process.on` 在 linux 与 win32 上都接受这四个名字,不抛。)
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"]) {
  try { process.on(sig, () => { restore(); process.exit(130); }); } catch {}
}
// 看门狗。`waitListen` 只证明 TCP **连得上**,不证明会**回** —— 闸门接了连接却永不应答
// (死锁 / 上游流卡住)时脚本会永久挂起,那时 `exit` 钩子永远不跑,Windows 上用户的真实
// `outbound.json` 就**无限期**停在测试态,旁份也一起吊着,直到有人手动杀 job。
const WATCHDOG = setTimeout(() => {
  no("watchdog: run exceeded its 240s budget — aborting so the config gets restored");
  restore();
  summary(1);
}, 240000);
WATCHDOG.unref();

let gate = null;
let gateLog = "";
let expectEgress = 0;   // 每个**预期出境**的调用点自增一次;O11 拿它比对,不用会静默过期的常量

async function main() {
  const portA = await freePort();
  await new Promise((r) => upA.listen(portA, "127.0.0.1", r));
  const portB = await freePort();
  await new Promise((r) => upB.listen(portB, "127.0.0.1", r));
  const UP = `http://127.0.0.1:${portA}`;
  const UP2 = `http://127.0.0.1:${portB}`;
  const gatePort = await freePort();
  console.log(`### outbound gate e2e — ${VER} ###`);
  console.log(`  ---- mock upstreams A=127.0.0.1:${portA} (anthropic/openai/gemini) B=127.0.0.1:${portB} (codex_chatgpt), gate 127.0.0.1:${gatePort}`);
  console.log(`  ---- config (reported by the binary): ${CFG}`);
  if (WIN) console.log(`  ---- windows: cannot sandbox dirs::data_local_dir(); snapshot taken (pre-existing=${cfgBackup !== null}), restored on exit`);

  mkdirSync(CFG_DIR, { recursive: true });
  // 旁份先落盘,再动原文件:进程被强杀时内存备份一起没,旁份是唯一能捞回来的东西。
  // 用 `wx`(独占创建)兼作锁:同一台机器上并发跑两份时,`existsSync` 那道检查可能在对方写下
  // 旁份**之前**就通过,两个都往下走,后还原的那个把对方的测试态留给用户。`wx` 没有这个窗口。
  // 用户本来就没有 `outbound.json`(全新机器)时也要写一个**零字节**锁 —— 否则那种机器上并发裸奔。
  try {
    writeFileSync(BACKUP_SIDECAR, cfgBackup !== null ? cfgBackup : Buffer.alloc(0), { flag: "wx" });
    sidecarWritten = true;
  } catch (e) {
    no(`another run holds ${BACKUP_SIDECAR} (${e.code || e.message}) — refusing to run concurrently`);
    return;
  }
  cfgWritten = true;
  wroteBytes = JSON.stringify({
    version: 1,
    enabled: true,
    listen: `127.0.0.1:${gatePort}`,
    upstreams: { anthropic: UP, openai: UP, codex_chatgpt: UP2, gemini: UP },
    agents: { claude: null, codex: null },
  }, null, 2);
  writeFileSync(CFG, wroteBytes);

  // 回读并**硬中止**。这不只是"证明配置被吃进去了":`load_outbound` 在文件版本号上调、或新增
  // 一个非 `#[serde(default)]` 字段时会 fail-closed 成 `OutboundFile::default()`,而 default 的
  // upstreams 是**真实的** api.anthropic.com / api.openai.com。`run_serve` 又不读 `enabled`,
  // 闸门照常起来 —— 那时这一串带凭据形态夹具的请求就会打到真第三方 API,屏幕上滚满
  // 「raw credential left the machine」,而那是**真的**出境了。
  // 所以这里最要紧的是 `upstreams` 全部指向 mock:流量只可能去 mock。不符即停。
  let rb;
  try {
    rb = JSON.parse(execFileSync(HUB, ["outbound", "status", "--json"], { encoding: "utf8", timeout: 30000, env, stdio: ["ignore", "pipe", "pipe"] }));
  } catch (e) { no(`O1a config read-back failed: ${e.message}`); return; }
  const rbBad = [];
  if (rb.warning) rbBad.push(`product reports a config warning: ${String(rb.warning).slice(0, 120)}`);
  if (rb.enabled !== true) rbBad.push(`enabled=${rb.enabled}`);
  if (rb.listen !== `127.0.0.1:${gatePort}`) rbBad.push(`listen=${rb.listen}`);
  const u = rb.upstreams || {};
  if (u.anthropic !== UP || u.openai !== UP || u.gemini !== UP || u.codex_chatgpt !== UP2) {
    rbBad.push(`upstreams=${JSON.stringify(u)} (want anthropic/openai/gemini=${UP}, codex_chatgpt=${UP2})`);
  }
  if (rbBad.length) {
    no(`O1a on-disk config did NOT round-trip -- refusing to run (fixtures could reach a REAL API): ${rbBad.join("; ")}`);
    return;
  }
  ok("O1a on-disk config round-trips through the product's own parser (no warning, enabled, listen, all four upstreams -> mocks)");

  // 刻意**不传** `--listen`:`run_serve` 会用该 flag 覆盖文件里的 `listen`(outbound.rs
  // `file.listen = l`),传了就等于把配置文件里最后一个承重字段也架空 —— 一个彻底无视
  // `outbound.json` 的 `listen` 的构建照样能全绿。不传,绑定地址就只能来自磁盘上那份配置。
  gate = spawn(HUB, ["outbound", "serve"], { env, stdio: ["ignore", "pipe", "pipe"] });
  gate.stdout.on("data", (d) => { gateLog += d.toString(); });
  gate.stderr.on("data", (d) => { gateLog += d.toString(); });

  if (!(await waitListen(gatePort))) {
    no("O1 gate failed to start listening");
    console.log("  ---- gate output:\n" + gateLog.slice(0, 2000));
    return;
  }
  const BASE = `http://127.0.0.1:${gatePort}`;
  const MSG = `${BASE}/anthropic/v1/messages`;

  const body = (text) => JSON.stringify({ model: "claude-sonnet-5", max_tokens: 16, messages: [{ role: "user", content: text }] });
  // 返回 {status, gained, capture, text}:`gained` 是本次**新增**的上游请求数。断言一律用
  // 「恰好 +1」/「恰好 +0」,不用「比之前多」—— 后者让重复与缺失互相抵消(总数还对)。
  // `text` 是客户端**实际收到**的响应体:只看请求方向的话,一个照常回 200 却截断/弄乱响应的
  // 闸门(所有真实用户立刻不可用)在这里会是全绿。
  const send = async (url, payload, ctype, extra) => {
    const before = captured.length;
    // 每个请求都要有超时:没有的话,闸门"接了连接但不回"会让整个脚本永久挂起(见看门狗注释)。
    const res = await fetch(url, { method: "POST", headers: { "Content-Type": ctype, "x-api-key": AUTH, ...extra }, body: payload, signal: AbortSignal.timeout(20000) });
    const text = await res.text();
    await sleep(120);
    const gained = captured.length - before;
    return { status: res.status, gained, capture: gained > 0 ? captured[captured.length - 1] : null, text };
  };
  let respIntact = true;   // O16:每一次转发成功的响应体都必须原样回来

  // ── O1/O2/O3 脱敏矩阵:判据 = 上游实际收到的字节 ────────────────────────────
  console.log("== O1/O2/O3 redaction matrix (verdict = bytes the upstream actually received) ==");
  console.log(`  ${"kind".padEnd(20)}${"len".padEnd(6)}${"expect".padEnd(9)}${"redacted".padEnd(10)}verdict`);
  let observedRedactions = 0;
  let boundaryRedacted = false;   // 35 位那条的**实测**行为;O10b 的绝对值据此推导,不硬编码
  for (const c of CASES) {
    expectEgress++;
    const r = await send(MSG, body(`${PROMPT_HEAD}${c.value}${PROMPT_TAIL}`), "application/json");
    const got = r.capture ? r.capture.body : "";
    const leaked = got.includes(c.value);
    const redacted = got.includes(PLACEHOLDER) && !leaked;
    if (redacted) observedRedactions++;
    if (r.status === 200 && r.text !== UPSTREAM_REPLY) respIntact = false;
    let verdict;
    if (r.status !== 200) { verdict = `FAIL (gate returned ${r.status})`; F++; }
    else if (r.gained !== 1) { verdict = `FAIL (upstream saw ${r.gained} requests, want exactly 1)`; F++; }
    else if (c.expect === null) { boundaryRedacted = redacted; verdict = `(boundary: ${redacted ? "redacted" : "passed through"})`; }
    else if (c.expect) {
      if (!redacted) { verdict = "FAIL <-- raw credential left the machine"; F++; }
      else if (!structureIntact(got)) { verdict = "FAIL (credential removed but the REQUEST WAS DESTROYED)"; F++; }
      else { verdict = "PASS"; P++; }
    }
    // 阈值以下不只是"没被脱敏",而是**原值原样抵达**:只验 !redacted 的话,上游收到 `{}`
    // 或任何不含占位符的替换内容都能蒙混过关。
    else if (leaked && !redacted) { verdict = "PASS (below threshold, forwarded verbatim)"; P++; }
    else { verdict = `FAIL (below threshold but value not forwarded intact: ${got.slice(0, 80)})`; F++; }
    console.log(`  ${c.kind.padEnd(20)}${String(c.value.length).padEnd(6)}${String(c.expect).padEnd(9)}${String(redacted).padEnd(10)}${verdict}`);
    if (c.expect === true && !redacted) console.log("        upstream saw: " + got.slice(0, 180));
  }

  // ── O4/O5 干净请求逐字节原样;鉴权头逐字节透传 ─────────────────────────────
  console.log("== O4/O5 clean request byte-identical + auth header verbatim ==");
  const cleanPayload = body("what is the capital of France?");
  expectEgress++;
  const rc = await send(MSG, cleanPayload, "application/json");
  if (rc.status === 200 && rc.text !== UPSTREAM_REPLY) respIntact = false;
  rc.status === 200 && rc.gained === 1 ? ok("O4a clean request reaches upstream exactly once (200)") : no(`O4a clean request status=${rc.status} gained=${rc.gained}`);
  // 逐字节比,不比子串:子串相等而结构被改(model/max_tokens 被删)也会被抓住。
  rc.capture && rc.capture.body === cleanPayload
    ? ok("O4b clean body forwarded byte-identical (no false positive, no reshaping)")
    : no(`O4b clean body altered:\n        sent: ${cleanPayload}\n        got : ${rc.capture ? rc.capture.body : "(not received)"}`);
  const authOk = captured.length > 0 && captured.every((c) => c.headers["x-api-key"] === AUTH);
  authOk ? ok("O5 auth header forwarded verbatim on every captured request") : no("O5 auth header altered or missing upstream");

  // ── O14 四条 vendor 腿的路由身份 + rest 逐字透传 ───────────────────────────
  console.log("== O14 per-vendor routing (identity is observable because codex_chatgpt has its own mock) ==");
  const routes = [
    ["/openai", "/v1/chat/completions", {}, "A"],
    ["/gemini", "/v1beta/models/gemini-2.5-pro:generateContent", {}, "A"],
    // `is_chatgpt_auth`:带 `chatgpt-account-id` 头(或 Bearer 是 JWT)→ codex_chatgpt,否则 → openai。
    // 这条分支一旦写反,ChatGPT 登录的 Codex 流量会被发去 API-key 端点 —— 两条必须落在**不同**的 mock。
    ["/codex", "/v1/responses", {}, "A"],
    ["/codex", "/v1/responses", { "chatgpt-account-id": "acc-not-real" }, "B"],
  ];
  const landed = [];
  for (const [prefix, rest, extra, wantUp] of routes) {
    expectEgress++;
    const r = await send(`${BASE}${prefix}${rest}`, body("hello"), "application/json", extra);
    if (r.status === 200 && r.text !== UPSTREAM_REPLY) respIntact = false;
    const label = `${prefix}${Object.keys(extra).length ? " +chatgpt-account-id" : ""}`;
    if (r.status !== 200 || r.gained !== 1) { no(`O14 ${label}: status=${r.status} gained=${r.gained}`); landed.push(null); continue; }
    landed.push(r.capture.up);
    r.capture.up === wantUp
      ? ok(`O14 ${label} -> mock ${r.capture.up}`)
      : no(`O14 ${label} landed on mock ${r.capture.up}, want ${wantUp}`);
    r.capture.path === rest
      ? ok(`O14 ${label} rest path forwarded verbatim (${rest})`)
      : no(`O14 ${label} rest path mangled: got ${r.capture.path}, want ${rest}`);
  }
  landed[2] && landed[3] && landed[2] !== landed[3]
    ? ok("O14 the two /codex variants land on DIFFERENT upstreams (is_chatgpt_auth actually splits)")
    : no(`O14 both /codex variants landed on the same upstream (${landed[2]}/${landed[3]}) — the auth split is not working`);

  // ── O6/O7/O8 三种拒绝 + O15 出站字节自检:状态码正确,且**一条都不许出境** ──
  console.log("== O6/O7/O8/O15 refusals never egress ==");
  // O15:重复 JSON 键。`serde_json` 只留最后一个,所以改写走的**解析后的树**里没有凭据、
  // 不命中 → 原字节直通(server.rs),而原字节里前一个 `dup` 的凭据还在 → 出站字节自检
  // 必须命中并 422。改写是尽力而为,**这一道才是底线**;删掉它,上面所有断言照样全绿。
  const dupKeyBody = `{"model":"claude-sonnet-5","max_tokens":16,"dup":"${GH36}","dup":"ok","messages":[{"role":"user","content":"hi"}]}`;
  const refusals = [
    ["O6 non-JSON body", 415, () => send(MSG, "not json at all", "text/plain")],
    ["O7 browser Origin", 403, () => send(MSG, body("hello"), "application/json", { Origin: "https://evil.example" })],
    ["O8 unknown route prefix", 404, () => send(`${BASE}/bogusvendor/v1/messages`, body("hello"), "application/json")],
    ["O15 duplicate JSON key (residual-secret byte self-check)", 422, () => send(MSG, dupKeyBody, "application/json")],
  ];
  for (const [label, want, fire] of refusals) {
    const r = await fire();
    r.status === want ? ok(`${label} refused with ${want}`) : no(`${label}: status=${r.status} want=${want} body=${r.text.slice(0, 160)}`);
    r.gained === 0 ? ok(`${label} never reached upstream`) : no(`${label} REACHED upstream (${r.gained})`);
  }

  // ── O16 响应方向 ──────────────────────────────────────────────────────────
  respIntact ? ok("O16 upstream response body relayed intact on every forwarded request") : no("O16 a forwarded response body came back altered");

  // ── O9/O10 healthz ────────────────────────────────────────────────────────
  console.log("== O9/O10 healthz + self-report cross-check ==");
  const hz = await fetch(`${BASE}/vigil/healthz`, { signal: AbortSignal.timeout(20000) });
  const hzBody = await hz.text();
  hz.status === 200 ? ok("O9a healthz readable") : no(`O9a healthz status=${hz.status}`);
  const hzOrigin = await fetch(`${BASE}/vigil/healthz`, { headers: { Origin: "https://evil.example" }, signal: AbortSignal.timeout(20000) });
  await hzOrigin.text();
  hzOrigin.status === 403 ? ok("O9b healthz refused for browser Origin") : no(`O9b healthz+Origin status=${hzOrigin.status}`);
  let hzJson = null;
  try { hzJson = JSON.parse(hzBody); } catch {}
  if (hzJson) {
    console.log("  ---- healthz: " + hzBody.slice(0, 220));
    // 绝对值跟着**实测**边界走。硬编码 4 的话,规则一旦从 `{36,}` 收紧到 `{35,}`,O10b 会红在
    // 一个矩阵按设计「只记录不判定」的行为上 —— 红得毫无信息量,还自相矛盾。
    const mustRedact = CASES.filter((c) => c.expect === true).length + (boundaryRedacted ? 1 : 0);
    // 闸门自述与上游侧实测必须一致 —— 两条独立观测路径互证。只信其中一条,工装坏掉时
    // 就会拿自己写错的脚本去冤枉产品。(一致性校验;充分性由 O2 的矩阵与下面的绝对值承担。)
    hzJson.rewritten === observedRedactions
      ? ok(`O10a gate self-report rewritten=${hzJson.rewritten} matches upstream-observed redactions`)
      : no(`O10a rewritten=${hzJson.rewritten} but upstream showed ${observedRedactions} redacted bodies`);
    // 等式只是**一致性**校验:改写器全线 no-op 时 0 === 0 照样过,恰好在它声称覆盖的失败里绿。
    hzJson.rewritten === mustRedact
      ? ok(`O10b rewritten=${hzJson.rewritten} equals the ${mustRedact} must-redact cases (absolute, not just self-consistent)`)
      : no(`O10b rewritten=${hzJson.rewritten}, want exactly ${mustRedact}`);
    // 精确值可知(mock 上游下只有那几种拒绝)。用 `>=` 的话,退化成「什么都拒」的闸门也能全绿:
    // `blocked` 在 Gate::block() 里统一自增,只增不减 —— 422 residual_secret 也走这条。
    // ★ 顺序依赖:`hzBody` 在 O9b 那次带 Origin 的 healthz **之前**取样,而 Origin 检查排在
    //   healthz 之前且计入 blocked —— 调换这两次 fetch 会让期望值多 1。
    hzJson.blocked === refusals.length
      ? ok(`O10c blocked=${hzJson.blocked} equals the ${refusals.length} refusals exactly`)
      : no(`O10c blocked=${hzJson.blocked}, want exactly ${refusals.length}`);
    hzJson.upstream_errors === 0 ? ok("O10d no upstream errors") : no(`O10d upstream_errors=${hzJson.upstream_errors}`);
    // 账本写不进去时请求**仍会放行**,`audit_dropped` 是把「没有改写」与「改写了但没记上」
    // 区分开的唯一外部观测面(server.rs `dropped_events` 的文档如是说)。不断言它就白设了。
    hzJson.audit_dropped === 0 ? ok("O10e audit_dropped=0 (no rewrite went unrecorded)") : no(`O10e audit_dropped=${hzJson.audit_dropped}`);
  } else no("O10 healthz body is not JSON: " + hzBody.slice(0, 160));

  // ── O11 静置后再数:抓「先拒绝、再延迟转发」这种迟到的出境 ──────────────────
  await sleep(1000);
  if (captured.length === expectEgress) {
    ok(`O11 exactly ${expectEgress} requests reached the upstreams after settling (refusals never egressed)`);
  } else {
    no(`O11 upstreams saw ${captured.length} requests, want exactly ${expectEgress}`);
    // 归因:逐条那道 `gained` 判定用的是 send() 里 120ms 的窗口,「先拒绝、再延迟转发」会让
    // O6/O7/O8/O15 全绿而只有这里报数不对 —— 知道漏了却不知道哪条漏的。把多出来的打出来。
    for (const c of captured.slice(expectEgress)) console.log(`  ---- late/extra egress: [${c.up}] ${c.path} ${c.body.slice(0, 80)}`);
  }

  // ── O12 闸门自身日志无凭据 —— 先停进程并排空输出再查,否则缓冲里的行会漏检 ──
  // 等 `'close'` 而不是 `'exit'`:`'exit'` 只保证进程终止,`'close'` 才保证 stdio 流已关闭
  // (输出排空)。靠 `'exit'` + 一个 sleep 凑的话,闸门在关停路径上打出带凭据的行没刷完时,
  // O12 会**判绿而日志里真有凭据**。
  if (gate && gate.exitCode === null) {
    gate.kill();
    await new Promise((r) => { const t = setTimeout(r, 5000); gate.once("close", () => { clearTimeout(t); r(); }); });
  }
  // 扫**全部**夹具,不只 must-redact 那四条:35/34 两个变体本来就原样出境,它们出现在闸门
  // 日志里同样是泄漏。AUTH 也在内 —— 它本身就是硬指纹形态的凭据。
  const mustNotAppear = [...CASES.map((c) => [c.kind, c.value]), ["auth header", AUTH]];
  const leakedInLog = mustNotAppear.filter(([, v]) => gateLog.includes(v)).map(([k]) => k);
  leakedInLog.length === 0 ? ok("O12 no credential or auth header appears in the gate's own log") : no(`O12 gate log contains: ${leakedInLog.join(", ")}`);

  // ── O13 审计账本:既要**写了**,又要**没写明文** ────────────────────────────
  // `run_serve` 用 `Ledger::open(..).ok()` 接账本 —— 打不开就静默退化成 NoopAudit(其
  // `dropped_events()` 恒为 0),于是「一条审计都没记」与「记得好好的」在 healthz 上完全同形。
  // 唯一的破法是把账本读回来。kill 不走干净关闭,WAL 里可能还压着数据,故两个文件一起读。
  let ledgerBytes = "";
  for (const p of [LEDGER, LEDGER + "-wal"]) {
    try { ledgerBytes += readFileSync(p).toString("latin1"); } catch {}
  }
  if (!ledgerBytes) no("O13a the gate wrote no audit ledger at all (Ledger::open failed -> silent NoopAudit?)");
  else {
    ledgerBytes.includes("outbound.request.redacted")
      ? ok("O13a redaction events were actually recorded in the audit ledger")
      : no("O13a ledger exists but holds no `outbound.request.redacted` event");
    const inLedger = mustNotAppear.filter(([, v]) => ledgerBytes.includes(v)).map(([k]) => k);
    inLedger.length === 0 ? ok("O13b no credential or auth header anywhere in the ledger file") : no(`O13b ledger contains plaintext: ${inLedger.join(", ")}`);
  }
}

main()
  .catch((e) => { console.error("outbound-e2e error: " + e.message); F++; })
  .finally(async () => {
    // 等它真的退出再清:闸门可能仍持着沙箱账本的句柄,Windows 上 `rmSync(SBX)` 会撞 EBUSY,
    // 而那句是 `catch {}` 吞掉的 —— 每一次失败的运行都会往 %TEMP% 漏一份沙箱。
    if (gate && gate.exitCode === null) {
      gate.kill();
      await new Promise((r) => { const t = setTimeout(r, 5000); gate.once("close", () => { clearTimeout(t); r(); }); });
    }
    for (const s of [upA, upB]) await new Promise((r) => s.close(r));
    restore();
    summary(F === 0 ? 0 : 1);
  });
