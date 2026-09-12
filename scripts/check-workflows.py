#!/usr/bin/env python3
"""Workflow 静态校验门(maskit 竞品对照吸收,2026-09-12)。

对 `.github/workflows/*.yml` 与 `.gitea/workflows/*.yml` 做发布前 fail-fast 校验,抓 YAML 层面
"能解析但错"的漂移(本仓踩过:`run: |` 块内 heredoc 落第 0 列静默截断,见 feedback_ci_yaml_run_block):

1. 严格 YAML 解析:**重复键**报错(PyYAML 默认静默取后者,会让两段同名 job / step 之一悄悄消失)
2. 结构:顶层 `on` / `jobs`;每个 job 有 `runs-on` + 非空 `steps`;每步 `uses` / `run` 二选一
3. `needs` 引用的 job 必须存在(悬空 needs = 整个 job 永不执行,GitHub 直接拒绝 workflow)
4. 表达式注入:`run:` 里直接内插 `${{ github.event.* }}` / `github.head_ref`(PR 标题、分支名、评论体、
   issue 字段等**任何人可控**字段进 shell)→ FAIL;`workflow_dispatch` 的 `github.event.inputs.*` /
   `inputs.*` 只有写权限者能触发,不构成提权 → WARN。两者的正确做法都是先赋给 `env:` 再用 `"$VAR"`
5. `pull_request_target` + checkout PR 头(`github.event.pull_request.head.*` / `github.head_ref`)→ FAIL
   (经典 pwn request:不可信代码拿到带写权限的仓库 token)
6. `uses:` 引用:浮动分支(`@main` / `@master` / 无 ref)→ FAIL;tag 引用(`@v4`)→ WARN(未 SHA 钉扎)。
   例外:`dtolnay/rust-toolchain` 这类**把分支名当 API**(`@stable` / `@master` + `toolchain:` 输入)
   的 action,浮动引用降为 WARN

退出码:任一 FAIL → 1;仅 WARN → 0。缺 PyYAML 时打印显式 WARNING 并退出 0(gitea 镜像无 pip;GitHub 侧
CI 先 `pip install pyyaml` 再跑,所以那边永远是真校验)。除 PyYAML 外纯标准库,跨平台(py3)。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIRS = (".github/workflows", ".gitea/workflows")

# 任何人可控的上下文直接内插进 shell(GitHub 官方 "script injection" 清单的核心项)→ FAIL
INJECTION_RE = re.compile(
    r"\$\{\{[^}]*\b(?:github\.event\.(?!inputs\.)[A-Za-z_.]+|github\.head_ref)\b"
)
# workflow_dispatch 输入:只有写权限者能触发,不是提权 → WARN(仍建议走 env)
DISPATCH_INPUT_RE = re.compile(r"\$\{\{[^}]*\b(?:github\.event\.inputs\.|inputs\.)[A-Za-z_]+\b")
FLOATING_REFS = {"main", "master", "develop", "latest", "HEAD"}
# 把分支名当 API 的 action(`@stable` / `@master` 是文档用法,没有版本 tag)
BRANCH_REF_IS_API = {"dtolnay/rust-toolchain"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

FAILS: list[str] = []
WARNS: list[str] = []
UNPINNED: dict[str, list[str]] = {}  # uses 字面量 → 出现位置(去重后统一报,免刷屏)


def fail(msg: str) -> None:
    FAILS.append(msg)
    print(f"  [FAIL] {msg}")


def warn(msg: str) -> None:
    WARNS.append(msg)
    print(f"  [WARN] {msg}")


def load_yaml_strict(text: str):
    """SafeLoader + 重复键报错(PyYAML 默认静默取后者)。"""
    import yaml

    class StrictLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    StrictLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    return yaml.load(text, Loader=StrictLoader)


def trigger_names(triggers) -> set[str]:
    if isinstance(triggers, str):
        return {triggers}
    if isinstance(triggers, list):
        return {str(t) for t in triggers}
    if isinstance(triggers, dict):
        return {str(k) for k in triggers}
    return set()


def check_uses(sloc: str, uses: str, prt: bool, step: dict) -> None:
    if uses.startswith("./") or uses.startswith("docker://"):
        return
    if "@" not in uses:
        fail(f"{sloc}: `uses: {uses}` 无版本引用(浮动到默认分支)")
        return
    action, ref = uses.rsplit("@", 1)
    if ref in FLOATING_REFS and action not in BRANCH_REF_IS_API:
        fail(f"{sloc}: `uses: {uses}` 引用浮动分支 —— 上游可随时替换内容(供应链)")
    elif not SHA_RE.match(ref):
        UNPINNED.setdefault(uses, []).append(sloc)
    if prt and action.endswith("checkout"):
        ref_expr = str((step.get("with") or {}).get("ref", ""))
        if "pull_request.head" in ref_expr or "head_ref" in ref_expr:
            fail(
                f"{sloc}: pull_request_target 下检出 PR 头 —— 不可信代码拿到仓库 token(pwn request)"
            )


def check_workflow(path: Path) -> None:
    rel = path.relative_to(ROOT).as_posix()
    try:
        doc = load_yaml_strict(path.read_text(encoding="utf-8"))
    except Exception as e:  # yaml.YAMLError / 重复键 / 编码
        fail(f"{rel}: YAML 解析失败: {e}")
        return
    if not isinstance(doc, dict):
        fail(f"{rel}: 顶层不是 mapping")
        return
    # PyYAML(YAML 1.1)把裸 `on` 解析成布尔 True
    triggers = doc.get("on", doc.get(True))
    if triggers is None:
        fail(f"{rel}: 缺 `on:` 触发器")
    if not doc.get("name"):
        warn(f"{rel}: 缺 `name:`")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        fail(f"{rel}: 缺 `jobs:` 或为空")
        return
    prt = "pull_request_target" in trigger_names(triggers)

    for job_id, job in jobs.items():
        loc = f"{rel} jobs.{job_id}"
        if not isinstance(job, dict):
            fail(f"{loc}: 不是 mapping")
            continue
        if "uses" in job:  # reusable workflow 调用,无 steps
            continue
        if "runs-on" not in job:
            fail(f"{loc}: 缺 `runs-on`")
        needs = job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]
        for n in needs:
            if n not in jobs:
                fail(f"{loc}: `needs` 引用了不存在的 job {n!r}")
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            fail(f"{loc}: 缺 `steps` 或为空")
            continue
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                fail(f"{loc}.steps[{i}]: 不是 mapping")
                continue
            name = step.get("name")
            sloc = f"{loc}.steps[{i}]" + (f" ({name})" if name else "")
            has_uses, has_run = "uses" in step, "run" in step
            if has_uses == has_run:
                fail(f"{sloc}: 须且只须 `uses` / `run` 之一")
            if has_run:
                run = str(step["run"])
                m = INJECTION_RE.search(run)
                if m:
                    fail(
                        f"{sloc}: `run:` 直接内插攻击者可控上下文 `{m.group(0)}` —— 先赋 `env:` 再引用"
                    )
                m = DISPATCH_INPUT_RE.search(run)
                if m:
                    warn(
                        f"{sloc}: `run:` 直接内插 workflow_dispatch 输入 `{m.group(0)}`(写权限者才能触发,"
                        "非提权;仍建议先赋 `env:` 再引用)"
                    )
            if has_uses:
                check_uses(sloc, str(step["uses"]), prt, step)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):  # Windows 控制台默认 GBK,中文报告会乱码
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        import yaml  # noqa: F401
    except ImportError:
        print(
            "[WARN] PyYAML 不可用:workflow 校验跳过(GitHub 侧 CI 已 pip install pyyaml,"
            "此处通常是 gitea 无 pip 镜像)"
        )
        return 0
    files = sorted(
        p for d in WORKFLOW_DIRS for p in (ROOT / d).glob("*.y*ml") if p.is_file()
    )
    if not files:
        print("[WARN] 未找到任何 workflow 文件")
        return 0
    print(f"check-workflows: {len(files)} 个 workflow")
    for f in files:
        check_workflow(f)
    for uses, locs in sorted(UNPINNED.items()):
        warn(f"`uses: {uses}` 未 SHA 钉扎(tag 可被上游移动),{len(locs)} 处,如 {locs[0]}")
    print(f"结果: {len(FAILS)} FAIL / {len(WARNS)} WARN")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
