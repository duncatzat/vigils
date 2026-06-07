# 验证你的下载

> 🌐 English: [Verifying your download](./verifying-downloads.md)

Vigils 守在你的密钥前面，所以你不该仅凭我们一句话就相信某个下载是正版。每一个发布产物
都是**可独立验证**的。本页说明怎么验证——并诚实交代每种方法**能证明什么、不能证明什么**。

## 速览

```bash
# 最强校验：证明该文件由「本仓库」的 CI 从「本仓库」的源码构建。
# 适用于全部产物——CLI 压缩包、桌面安装包、扩展 zip。
gh attestation verify <下载的文件> --repo duncatzat/vigils
```

输出 ✓ 且源仓库 / workflow 匹配，即说明二进制是正版；严格来说无需更多步骤。下面各节是
互补校验，并解释当前为何还没有操作系统级代码签名。

## 1. 构建溯源（Build provenance）——推荐，覆盖全部产物

每个可下载产物都附带一份 [SLSA](https://slsa.dev) 构建溯源证明，由 GitHub 背后的
Sigstore 基础设施签发（你无需自管密钥，除 GitHub 与公开源码外无需信任其他方）：

- CLI 压缩包——`vigils-cli-linux-x64.tar.gz`、`vigils-cli-macos-arm64.tar.gz`、`vigils-cli-windows-x64.zip`
- 桌面安装包——`.exe`、`.msi`、`.dmg`、`.deb`、`.rpm`、`.AppImage`
- 浏览器扩展——`vigils-chrome-extension.zip`

用 [GitHub CLI](https://cli.github.com/) 验证：

```bash
gh attestation verify Vigils_0.1.7_amd64.deb --repo duncatzat/vigils
```

通过即证明该文件由「本仓库」的发布流水线、从某个具体 commit 构建——也就是说它没有被
掉包、没有被第三方重新构建、构建后也没有被篡改。这对「来源」的证明强于单纯的代码签名
证书，因为它把二进制绑定到了你可以亲自去读的那个公开源码 commit 和 CI 运行。

> 离线 / 隔离网环境？从 release 下载该产物的 attestation bundle，离线验证：
> `gh attestation verify <文件> --bundle <bundle.jsonl> --repo duncatzat/vigils`。

## 2. 校验和（Checksum）——CLI 压缩包

每个 CLI 压缩包旁边都发布了 `.sha256` 文件。[一行安装器](./installation.md)会自动校验；
手动验证：

```bash
# macOS / Linux —— .sha256 内容格式为 "<hash>  <文件名>"
shasum -a 256 -c vigils-cli-linux-x64.tar.gz.sha256
```

```powershell
# Windows —— 与 vigils-cli-windows-x64.zip.sha256 中发布的 hash 比对
(Get-FileHash -Algorithm SHA256 vigils-cli-windows-x64.zip).Hash
```

校验和只能证明你下到的字节和 release 发布的字节一致（用于发现截断 / 传输损坏），它
**不是签名**——认证真伪请用溯源（§1）。桌面安装包依赖溯源，不另发 `.sha256`。

## 3. 安装脚本

一行安装命令是一个朴素、可读的 shell / PowerShell 脚本——运行前先读它。注意它会替你
校验压缩包的校验和：

```bash
curl -fsSL https://vigils.ai/install.sh          # 先读
curl -fsSL https://vigils.ai/install.sh | sh     # 再运行
```

```powershell
irm https://vigils.ai/install.ps1                # 先读
irm https://vigils.ai/install.ps1 | iex          # 再运行
```

## 4. 关于「未签名应用」警告

Vigils 安装包**尚未做操作系统级代码签名 / 公证**——那需要 Apple 与 Windows CA 颁发的、
付费且经身份核验的证书，目前还没有到位。因此首次运行时系统会警告：

- **macOS**——Gatekeeper 会拦截。先验证溯源（§1），再清除隔离标记：
  `xattr -d com.apple.quarantine /Applications/Vigils.app`。
- **Windows**——SmartScreen 会提示。先验证溯源（§1），再点 *More info → Run anyway*。

在代码签名落地之前，**构建溯源就是验证路径**——而对「证明二进制确实来自这份开源代码」
而言，它本就是更强的保证。

## 5. 自动更新是签名的

安装后，桌面应用的自动更新器只接受携带项目 minisign 密钥有效签名的更新（每个 release
里的 `.sig` 文件），因此更新通道无需你任何操作即端到端可信。见
[自动更新](../ops/auto-update.md)。
