#!/usr/bin/env python3
"""发布静态审计门(maskit 竞品对照吸收,2026-09-12)。

只审 `git ls-files` 的**已跟踪**文件 —— 不看工作树里没进库的东西,只看会被 tag / 移植 / 打包带走的内容。

FAIL(退出码 1):
  1. credential-file   凭据类文件名:`.env*`(`.env.example` 类除外)/ `*.pem` / `*.key` / `*.p12` / `*.pfx` /
                       `*.jks` / `*.keystore` / `id_rsa*` / `id_ed25519*` / `credentials.json` / `.npmrc` / `.netrc` …
  2. runtime-artifact  运行时产物:`*.db` / `*.sqlite*` / `*.log` / `*.pyc` / `*.orig` / `*.rej` / `.DS_Store` /
                       `Thumbs.db`,以及 `__pycache__` / `node_modules` / `target` / `.venv` 目录下任何文件
  3. ignored-tracked   被 `.gitignore` 忽略却已跟踪(`git ls-files -i -c`,通常是 `git add -f` 手滑)
  4. dev-path          开发者本机路径:`C:\\Users\\<name>` / `/Users/<name>` / `/home/<name>`,`<name>` 不是
                       通用占位名(user / you / alice / runner …)—— 泄露的是维护者身份与机器布局
  5. control-char      控制字符(除 TAB / LF / CR)混进文本文件
WARN(不阻断):
  6. symlink           已跟踪的符号链接(Windows 检出 / zip 发布不可靠)
  7. large-file        单文件 > 2 MiB(clone 成本;图标源件之类若有意为之,入 allowlist)
  8. non-utf8-path     路径不是合法 UTF-8(跨平台检出 / 归档工具乱码)
  9. private-ip        `--public` 模式:RFC 1918 内网地址 —— 公开仓不应携带内部基础设施拓扑

例外:`scripts/audit-public-release.allow`,每行 `<rule> <glob>`(`#` 注释;glob 用 fnmatch 匹配仓库相对
路径,`/` 分隔,`*` 可跨目录)。用途是给"知道自己在干什么"的既有例外留门,而不是让门禁静默 —— 每条例外
都要写清楚为什么。纯标准库,跨平台(py3)。
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOW_FILE = ROOT / "scripts" / "audit-public-release.allow"
LARGE_FILE_BYTES = 2 * 1024 * 1024

CREDENTIAL_FILE_GLOBS = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "id_rsa", "id_rsa.*", "id_ed25519", "id_ed25519.*", "id_ecdsa", "id_ecdsa.*",
    "credentials.json", "service-account*.json", "*.token", ".npmrc", ".pypirc",
    ".netrc", "_netrc", "*.kdbx", "*.ovpn",
)
CREDENTIAL_FILE_EXEMPT = (".env.example", ".env.sample", ".env.template", "*.pub")
RUNTIME_ARTIFACT_GLOBS = (
    "*.db", "*.sqlite", "*.sqlite3", "*.db-wal", "*.db-shm", "*.log", "*.pyc", "*.pyo",
    "*.orig", "*.rej", "*.swp", "*.swo", ".DS_Store", "Thumbs.db", "desktop.ini",
)
RUNTIME_ARTIFACT_DIRS = {
    "__pycache__", "node_modules", "target", ".venv", "venv", ".pytest_cache", ".mypy_cache",
}
BINARY_SUFFIXES = {
    ".png", ".ico", ".icns", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".woff", ".woff2", ".ttf",
    ".otf", ".eot", ".wasm", ".onnx", ".bin", ".zip", ".gz", ".tgz", ".xz", ".bz2", ".7z", ".pdf",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib", ".jar", ".class", ".msi", ".dmg", ".crx",
    ".asar", ".mp3", ".mp4", ".wav", ".ogg", ".pyc",
}

DEV_PATH_RE = re.compile(
    r"(?:[A-Za-z]:[\\/]+Users[\\/]+|/Users/|/home/)([A-Za-z0-9_-][A-Za-z0-9._-]*)"
)
PLACEHOLDER_USERS = {
    "user", "users", "username", "you", "me", "name", "example", "alice", "bob", "carol", "dave",
    "jordan", "runner", "runneradmin", "ci", "u", "x", "admin", "administrator", "root", "test",
    "tester", "dev",
    "developer", "public", "default", "someone", "yourname", "your-name", "yourusername",
    "seluser", "ubuntu", "debian", "node", "app", "vigil", "vigils", "foo", "bar",
}
CONTROL_RE = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PRIVATE_IP_RE = re.compile(
    rb"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    rb"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
PUBLIC_SCAN_SUFFIXES = {
    ".md", ".yml", ".yaml", ".toml", ".json", ".sh", ".ps1", ".mjs", ".js", ".py", ".txt", ".cfg",
    ".ini", ".html", ".css",
}

FAILS: list[str] = []
WARNS: list[str] = []
ALLOWED = 0


def load_allowlist() -> list[tuple[str, str]]:
    if not ALLOW_FILE.is_file():
        return []
    out = []
    for ln in ALLOW_FILE.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split(None, 1)
        if len(parts) != 2:
            print(f"  [WARN] allowlist 行格式错(应为 `<rule> <glob>`): {ln!r}")
            continue
        out.append((parts[0], parts[1].strip()))
    return out


ALLOW = load_allowlist()


def emit(level: str, rule: str, path: str, detail: str) -> None:
    global ALLOWED
    if any(r == rule and fnmatch.fnmatchcase(path, g) for r, g in ALLOW):
        ALLOWED += 1
        return
    msg = f"{rule}: {path}: {detail}"
    (FAILS if level == "FAIL" else WARNS).append(msg)
    print(f"  [{level}] {msg}")


def git_lines(*args: str) -> list[bytes]:
    out = subprocess.run(
        ["git", *args, "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    return [e for e in out.split(b"\0") if e]


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def audit_file(mode: str, path: str, public: bool) -> None:
    base = path.rsplit("/", 1)[-1]
    parents = path.split("/")[:-1]
    if mode == "120000":
        emit("WARN", "symlink", path, "已跟踪的符号链接")
        return
    if mode == "160000":  # submodule
        return
    if any(fnmatch.fnmatchcase(base, g) for g in CREDENTIAL_FILE_GLOBS) and not any(
        fnmatch.fnmatchcase(base, g) for g in CREDENTIAL_FILE_EXEMPT
    ):
        emit("FAIL", "credential-file", path, "凭据类文件名")
    if any(fnmatch.fnmatchcase(base, g) for g in RUNTIME_ARTIFACT_GLOBS) or any(
        p in RUNTIME_ARTIFACT_DIRS for p in parents
    ):
        emit("FAIL", "runtime-artifact", path, "运行时产物 / 构建输出")

    fs = ROOT / path
    if not fs.is_file():
        return  # 已跟踪但工作树里被删,内容无从审
    size = fs.stat().st_size
    if size > LARGE_FILE_BYTES:
        emit("WARN", "large-file", path, f"{size / 1024 / 1024:.1f} MiB")
    suffix = "." + base.rsplit(".", 1)[-1].lower() if "." in base else ""
    if suffix in BINARY_SUFFIXES:
        return

    data = fs.read_bytes()
    text = data.decode("utf-8", "replace")
    m = CONTROL_RE.search(data)
    if m:
        line = data.count(b"\n", 0, m.start()) + 1
        emit("FAIL", "control-char", path, f"第 {line} 行含控制字符 0x{m.group(0)[0]:02x}")
    for m in DEV_PATH_RE.finditer(text):
        name = m.group(1)
        if name.lower() in PLACEHOLDER_USERS or name.startswith("."):
            continue
        emit("FAIL", "dev-path", path, f"第 {line_of(text, m.start())} 行 `{m.group(0)}`")
        break  # 每文件报一条即可
    if public and suffix in PUBLIC_SCAN_SUFFIXES:
        m = PRIVATE_IP_RE.search(data)
        if m:
            line = data.count(b"\n", 0, m.start()) + 1
            emit("WARN", "private-ip", path, f"第 {line} 行 `{m.group(0).decode()}`")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):  # Windows 控制台默认 GBK,中文报告会乱码
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--public", action="store_true", help="公开仓模式:另查内网地址(WARN)")
    args = ap.parse_args()

    for e in git_lines("ls-files", "-i", "-c", "--exclude-standard"):
        emit("FAIL", "ignored-tracked", e.decode("utf-8", "replace"), "被 .gitignore 忽略却已跟踪")

    entries = git_lines("ls-files", "-s")
    print(f"audit-public-release: {len(entries)} 个已跟踪文件"
          f"{'(--public)' if args.public else ''},{len(ALLOW)} 条例外")
    for entry in entries:
        meta, _, path_b = entry.partition(b"\t")
        mode = meta.split()[0].decode()
        try:
            path = path_b.decode("utf-8")
        except UnicodeDecodeError:
            path = path_b.decode("utf-8", "replace")
            emit("WARN", "non-utf8-path", path, "路径不是合法 UTF-8")
            continue
        audit_file(mode, path, args.public)

    print(f"结果: {len(FAILS)} FAIL / {len(WARNS)} WARN / {ALLOWED} 例外放行")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
