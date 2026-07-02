# Troubleshooting — 常见问题

## 安装阶段

### Q1: `.\vigil-native-host.exe install --extension-id XXX` 报 `invalid extension id: <id> (must be 32 chars in a-p)`

Chrome 扩展 ID 只含 `a-p` 小写字母,**32 字符**。如果你输入的 ID 含数字或其他字母,说明复制错了。

**定位**:`chrome://extensions` → Vigil 项 → 展开详情 → "ID: ahvzoxrk...(32 字符)"。复制的是**这个**字符串,不是扩展名。

### Q2: Chrome 扩展加载后,service worker 报 "Specified native messaging host not found"

**原因**:
- `vigil-native-host install` 没跑 / 跑了但 `--extension-id` 错
- Windows:HKCU 注册表未写入(极少发生,通常权限问题)
- Linux/macOS:manifest 目录不存在或不可读

**修**:
```powershell
.\vigil-native-host.exe status  # 应显示 installed: true
.\vigil-native-host.exe uninstall
.\vigil-native-host.exe install --extension-id <正确ID>
# 重启 Chrome(service worker 不重载 Native Host 连接)
```

### Q3: Linux `vigil-native-host install` 报 `Permission denied: /etc/opt/chrome/...`

Linux 用户级 manifest 路径是 `~/.config/google-chrome/NativeMessagingHosts/`(用户级,**不**需要 sudo)。如果你被指向 `/etc/opt/chrome/` 那是**系统级**,只有给所有用户装才需要。

**修**:以**非 root** 用户跑 `vigil-native-host install`,不要加 `sudo`。

## 运行时

### Q4: 在 ChatGPT 粘贴 token,没有 toast,内容直接进对话框

**诊断步骤**:
1. Chrome `chrome://extensions` → Vigil → service worker → Console:有无红色 error?
2. 展开 service worker 看 network:粘贴时应看到 `com.vigil.host` 连接
3. 手动触发:在 ChatGPT 页面 DevTools Console 跑 `navigator.clipboard.readText()` 看是否能读(扩展不依赖 clipboard API,但验证一下)

**常见原因**:
- Native Host 未注册(回 Q2)
- Chrome 使用了 profile 级限制扩展(企业托管 Chrome 某些策略会禁 Native Messaging) → 用普通 profile 测
- 输入框是 shadow DOM / 奇怪 web component(Claude 偶尔变更) → `docs/adr/0009-browser-extension-mvp.md` 的 §R4 注明 "找不到 primary input 会降级 block",不会 bypass

### Q5: Desktop UI 启动但 Activity Feed 始终空

**原因**:
- Ledger 文件位置错:默认 `%LOCALAPPDATA%\Vigil\ledger.sqlite3`(Windows,**不是** `%APPDATA%`/Roaming,文件名带 `3`),`~/.local/share/Vigil/ledger.sqlite3` (Linux),`~/Library/Application Support/Vigil/ledger.sqlite3` (macOS)
- Chrome 扩展的事件没写进同一个 ledger(可能 Native Host 和 Desktop 看向不同文件)

**修**:
```powershell
# 打开 Desktop 时指定 ledger 路径
.\vigil-desktop.exe --ledger %LOCALAPPDATA%\Vigil\ledger.sqlite3
# CLI / hook / serve / Native Host 也用同路径(环境变量 VIGIL_LEDGER_PATH,或不设时都落上面的默认 canonical 路径)
```

设 `VIGIL_LEDGER_PATH` 让所有组件(CLI、hook、serve、Desktop、Native Host)指向同一账本;不设时它们都用上面的默认 canonical 路径。

### Q6: Desktop 启动报 `failed to enable WAL journal mode`

**原因**:ledger 文件所在盘不支持 WAL(NTFS 上极少,FAT32 / 网络驱动器会触发)。

**修**:把 ledger 移到本地 SSD,`%APPDATA%` 通常是 C:\Users\<you>\AppData\Roaming\,不会有问题。

### Q7: 扩展 popup 的"最近 findings"列表始终空

**原因**:
- 扩展在 MV3 下 service worker 可能被 Chrome 休眠,`findingsLog` 内存队列清空
- 这是 **by design**(ADR 0009 §I-9.1:findings 不落 chrome.storage,重启扩展清零)

**不是 bug**。如果需要持久,打开 Desktop Activity Feed(审计链写 SQLite)。

## 性能

### Q8: bench 基线偏离参考值 >2x

**排查**:
- 本机 CPU 是 ARM? 与 x86_64 基线不可直接比
- 是否开了 Windows Defender 实时扫描 target/ 目录? 加排除目录
- SSD 还是 HDD?ledger bench 有大量 SQLite IO,HDD 会显著慢
- 并发跑了其他 cargo build 吗?cold 阶段会争资源

### Q9: 100 KB scrub 超过 10 ms

参考基线 32 µs(300× 余量)。如果你看到 10 ms 以上说明:
- regex 重新编译(不应发生,`Lazy<Vec<Rule>>` 只编一次) → 提 issue
- 文本非常特殊(大量连续 secret 触发 N 条 rule 全扫) → 提样本

## 审计 / 合规

### Q10: 如何证明"ledger 没被篡改"?

```powershell
.\vigil-hub.exe verify
# 输出(示例):
# ✓ the audit chain is internally consistent AND anchored: N checkpoint(s), through event #M
# (每条 event 的 content_hash + prev_hash 闭合;链完整则退出码 0)
```

如果报 `✗ the audit chain is BROKEN at event #NNNN — tampering detected`(退出码非 0):
- 该 event 之后的链都失真
- **不要自己改数据库修**,上报 incident

### Q11: 想审计某段时间的 findings

Vigil CLI **没有** `ledger query` 子命令。查历史 findings 用以下任一方式:

- **桌面 Activity Feed**:内置 FTS5 搜索框,按 event_type / 时间 / 关键词过滤,最直观。
- **直接查 SQLite**(高级):
  ```powershell
  sqlite3 %LOCALAPPDATA%\Vigil\ledger.sqlite3 "SELECT * FROM events WHERE event_type LIKE 'browser.paste.%' ORDER BY id DESC LIMIT 10;"
  ```

## 仍然不行?

1. 跑 `scripts/test-local/quick.sh` 看 workspace 测试是否全绿(绿 = 你的 binary 一致,问题在 setup)
2. 跑 `bash scripts/test-local/scenario.sh` 看 PS-001 是否通过
3. 把 service worker Console + `vigil-desktop.exe --log-level debug` 的输出打包上报
