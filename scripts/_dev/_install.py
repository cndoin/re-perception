#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨平台技能安装器 —— 把本技能装到各 AI 运行时能识别的目录里。

支持的运行时（各自的技能目录是**官方文档写死的**，不要凭印象猜）：

| 运行时        | 个人级目录                    | 项目级目录            |
|---------------|-------------------------------|-----------------------|
| Claude Code   | `~/.claude/skills/`           | `.claude/skills/`     |
| Codex CLI     | `$CODEX_HOME/skills/`         | `.codex/skills/`      |
|               | (默认 `~/.codex/skills/`)     | `.agents/skills/`     |
| Hermes        | `~/.hermes/skills/`           | ——                    |
| OpenClaw      | `~/.openclaw/skills/`         | `.openclaw/skills/`   |
| Cursor        | 仅项目级                      | `.cursor/skills/`     |
| Gemini CLI    | `~/.gemini/skills/`           | `.gemini/skills/`     |
| WorkBuddy     | `~/.workbuddy/skills/`        | ——                    |

设计要点（为什么这么写）：

1. **不猜、只问环境**。Codex 的目录受 `CODEX_HOME` 影响，Hermes 受 profile 影响。
   所以目录解析一律「先读环境变量，再退回默认值」，并且解析结果要能打印出来给人看。

2. **安装完必须自验**。装完只打印"成功"是**假成功**（本项目最恨的缺陷类型）。
   所以 `--verify` 会真的回去检查 SKILL.md 存在、frontmatter 能被解析、必填字段齐全、
   `name` 与目录名一致、以及被引用到的 `scripts/re.py` 等入口文件是否可达。

3. **符号链接优先，复制兜底**。开发期用 symlink 能让改一处即生效；
   Windows 无权限建 symlink 时（普通用户默认禁止）自动降级为复制并明确告知。

4. **搬之前先侦察**。目标目录已存在同名技能时默认拒绝覆盖，
   除非显式 `--force`，且覆盖前把旧目录备份到 `.bak-<时间戳>`。

退出码：`0` 成功 / `1` 有失败项 / `2` 用法错误。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time

# 本技能自身根目录（scripts/_dev/ 往上两级）
SELF_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKILL_NAME = "reverse-engineering"

# 运行时 → (个人级路径解析函数, 项目级相对路径 or None, 说明)
_RUNTIME_DOC = {
    "claude-code": ("~/.claude/skills", ".claude/skills", "Claude Code (Anthropic)"),
    "codex": (None, ".codex/skills", "Codex CLI (OpenAI)"),
    "codex-agents": (None, ".agents/skills", "Codex CLI 可移植约定（.agents/）"),
    "hermes": ("~/.hermes/skills", None, "Hermes Agent (Nous Research)"),
    "openclaw": ("~/.openclaw/skills", ".openclaw/skills", "OpenClaw"),
    "cursor": (None, ".cursor/skills", "Cursor（仅项目级）"),
    "gemini": ("~/.gemini/skills", ".gemini/skills", "Gemini CLI (Google)"),
    "workbuddy": (None, None, "WorkBuddy（本机装它的目录）"),
}


def _home() -> str:
    return _skill_home()


# 允许用环境变量覆盖「技能家目录」，用于：
#   1) 自动化测试 —— 否则会把用例真的装到开发者的 ~/.claude 里（真发生过）
#   2) 绿色/便携安装 —— 想把技能装到非默认根的用户
# 生产使用不设该变量时，行为与直接读 ~ 完全一致。
HOME_ENV = "RE_SKILL_HOME"


def _skill_home() -> str:
    """技能家目录：RE_SKILL_HOME 优先，否则 ~。"""
    v = os.environ.get(HOME_ENV, "").strip()
    if v:
        return os.path.abspath(v)
    return os.path.expanduser("~")


def _codex_home() -> str:
    """Codex 的 home 受 CODEX_HOME 环境变量影响，不能硬编码 ~/.codex。"""
    v = os.environ.get("CODEX_HOME", "").strip()
    return v if v else os.path.join(_home(), ".codex")


def personal_dir(rt: str) -> str | None:
    """返回某个运行时在**本机**的个人级技能目录（绝对路径），无则 None。"""
    if rt == "claude-code":
        return os.path.join(_home(), ".claude", "skills")
    if rt == "codex":
        return os.path.join(_codex_home(), "skills")
    if rt == "hermes":
        return os.path.join(_home(), ".hermes", "skills")
    if rt == "openclaw":
        return os.path.join(_home(), ".openclaw", "skills")
    if rt == "gemini":
        return os.path.join(_home(), ".gemini", "skills")
    if rt == "workbuddy":
        # 本技能当前所在位置就是 WorkBuddy 的技能根
        return os.path.dirname(SELF_ROOT)
    return None


def project_dir(rt: str, project_root: str) -> str | None:
    rel = _RUNTIME_DOC[rt][1]
    if not rel:
        return None
    return os.path.join(project_root, *rel.split("/"))


# ---------------------------------------------------------------- 侦察

def detect_installed(rt: str, scope: str, project_root: str):
    """返回目标目录，无论它当前是否已存在。"""
    if scope == "personal":
        return personal_dir(rt)
    return project_dir(rt, project_root)


def runtime_present(rt: str) -> tuple[bool, str]:
    """判断某运行时在本机是否装了 —— 用于 --auto 只装存在的。

    判据优先级：可执行文件在 PATH > 配置目录/家目录存在。
    只读判断，绝不启动任何东西。
    """
    exe_map = {
        "claude-code": ["claude"],
        "codex": ["codex"],
        "hermes": ["hermes"],
        "openclaw": ["openclaw"],
        "cursor": ["cursor", "cursor-agent"],
        "gemini": ["gemini"],
        "workbuddy": [],
    }
    for exe in exe_map.get(rt, []):
        if shutil.which(exe):
            return True, f"PATH 中找到 {exe}"
    # 退回看配置目录
    probes = {
        "claude-code": os.path.join(_home(), ".claude"),
        "codex": _codex_home(),
        "hermes": os.path.join(_home(), ".hermes"),
        "openclaw": os.path.join(_home(), ".openclaw"),
        "cursor": os.path.join(_home(), ".cursor"),
        "gemini": os.path.join(_home(), ".gemini"),
        "workbuddy": os.path.join(_home(), ".workbuddy"),
    }
    p = probes.get(rt)
    if p and os.path.isdir(p):
        return True, f"配置目录存在 {p}"
    if rt == "workbuddy":
        return True, "本技能自身就装在 WorkBuddy 技能目录下"
    return False, "未发现安装痕迹"


# ---------------------------------------------------------------- 动作

# 安装时**必须排除**的路径（相对技能根，正斜杠）。
#
# 这些是开发/合规产物，装上没有价值、只会占体积或引入许可风险：
#   .git/            版本控制库，用户装的是技能不是仓库
#   _ref/            325KB LLVM 版权源码，仅作 demangle 实现的**参考**，
#                    运行时不读它；随技能分发等于把别人的版权源码再散一遍
#   _dev/            开发脚手架（lint/fuzz/e2e/审计器），面向贡献者不面向用户
#   __pycache__/     .pyc 编译产物，跨机器可能不兼容
# 安装时**必须排除**的目录名（**任意层级**匹配，不是只看顶层）。
#
# 为什么强调"任意层级"：_dev/ 和 _ref/ 实际位于 scripts/ 之下，
# 只比对顶层名字的话它们会被原样拷进去（这里踩过，被
# `安装：复制可用且裁剪开发产物` 用例当场抓到）。
_EXCLUDE_DIRS = {
    ".git", "__pycache__", ".pytest_cache",
    ".github",   # CI / issue 模板，面向仓库贡献者而非技能使用者
    "_dev",      # 开发脚手架（lint/fuzz/e2e/审计器），面向贡献者
    "_ref",      # LLVM 版权源码，仅作 demangle 参考，运行时不读
}


def _slim_ignore(dir_path: str, names: list[str]) -> set[str]:
    """copytree 忽略回调：按目录名（任意层级）+ .pyc 后缀裁剪。"""
    dropped = set()
    for n in names:
        if n in _EXCLUDE_DIRS or n.endswith(".pyc"):
            dropped.add(n)
    return dropped


def _copy_tree(src: str, dst: str) -> None:
    """复制技能树，排除开发与合规敏感产物（见 _EXCLUDE_DIRS 注释）。"""
    shutil.copytree(src, dst, ignore=_slim_ignore)


def install_one(rt: str, scope: str, project_root: str, mode: str,
                force: bool) -> tuple[bool, str]:
    """把技能装到单个运行时。返回 (是否成功, 人话说明)。"""
    target_root = detect_installed(rt, scope, project_root)
    if not target_root:
        return False, f"{rt} 不支持 {scope} 级安装"

    dest = os.path.join(target_root, SKILL_NAME)

    # 已存在且指向自己 → 幂等
    if os.path.islink(dest):
        try:
            if os.path.realpath(dest) == os.path.realpath(SELF_ROOT):
                return True, f"已就绪（符号链接）→ {dest}"
        except OSError:
            pass

    if os.path.exists(dest) and not force:
        return False, (f"目标已存在，未覆盖：{dest}（要覆盖加 --force，"
                       f"会先备份成 .bak-<时间戳>）")

    backup = None
    if os.path.exists(dest) and force:
        backup = f"{dest}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        try:
            if os.path.isdir(dest) and not os.path.islink(dest):
                shutil.move(dest, backup)
            else:
                os.remove(dest)
        except OSError as e:
            return False, f"备份旧版本失败：{e}"

    try:
        os.makedirs(target_root, exist_ok=True)
    except OSError as e:
        return False, f"创建目录失败 {target_root}：{e}"

    # 尝试 symlink（开发期改一处即生效），失败/无效退回复制。
    #
    # ⚠️ 这里必须**验证链接真的能用**，不能只看 os.symlink 有没有抛异常。
    # 实测：Windows 上 os.symlink 会「成功返回但造出一个不是链接的空目录」
    # （junction/重定向行为不一致），于是 SKILL.md 根本读不到 ——
    # 如果只看返回值，就会把一个实际不可用的安装上报成成功。
    # 这正是本项目最忌讳的"失败被上报为成功"，所以判据是：
    #   islink() 为真 且 通过该路径能读到 SKILL.md，两者都满足才算成功。
    if mode in ("link", "auto"):
        link_err = None
        try:
            os.symlink(SELF_ROOT, dest, target_is_directory=True)
        except (OSError, NotImplementedError) as e:
            link_err = e
        else:
            if os.path.islink(dest) and os.path.isfile(
                    os.path.join(dest, "SKILL.md")):
                note = f"符号链接 → {dest}"
                if backup:
                    note += f"（旧版备份在 {os.path.basename(backup)}）"
                return True, note
            # 造出来的东西不可用：清掉残骸再退复制，别留半个安装
            link_err = "os.symlink 未抛异常但链接不可解析（Windows 上常见）"
            try:
                if os.path.islink(dest):
                    os.remove(dest)
                elif os.path.isdir(dest):
                    shutil.rmtree(dest, ignore_errors=True)
                else:
                    os.remove(dest)
            except OSError:
                pass

        if mode == "link":
            return False, (f"建符号链接失败：{link_err}；"
                           f"改用 --mode copy（或 --mode auto）")
    else:
        link_err = None

    try:
        _copy_tree(SELF_ROOT, dest)
    except OSError as e:
        return False, f"复制失败：{e}"
    note = f"复制 → {dest}"
    if link_err is not None:
        note += f"（未用符号链接：{link_err}）"
    if backup:
        note += f"（旧版备份在 {os.path.basename(backup)}）"
    return True, note


# ---------------------------------------------------------------- 自验

def verify_one(rt: str, scope: str, project_root: str) -> tuple[bool, list[str]]:
    """真的回去检查装完的东西能不能被 runtime 发现。"""
    problems: list[str] = []
    target_root = detect_installed(rt, scope, project_root)
    if not target_root:
        return False, [f"{rt} 不支持 {scope} 级安装"]
    dest = os.path.join(target_root, SKILL_NAME)

    if not os.path.exists(dest):
        return False, [f"目标不存在：{dest}"]

    skill_md = os.path.join(dest, "SKILL.md")
    if not os.path.isfile(skill_md):
        return False, [f"缺 SKILL.md：{skill_md}"]

    try:
        with open(skill_md, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        return False, [f"SKILL.md 不可读：{e}"]

    # frontmatter 结构与字段约束
    if not text.startswith("---"):
        problems.append("SKILL.md 未以 --- 开头（无 YAML frontmatter）")
    else:
        end = text.find("\n---", 3)
        if end < 0:
            problems.append("frontmatter 没有结束的 ---")
        else:
            fm = text[3:end]
            fields = {}
            for line in fm.splitlines():
                if ":" in line and not line.startswith((" ", "\t")):
                    k, v = line.split(":", 1)
                    fields[k.strip()] = v.strip()
            if not fields.get("name"):
                problems.append("frontmatter 缺必填字段 name")
            elif fields["name"] != SKILL_NAME:
                problems.append(
                    f"name({fields['name']}) 与目录名({SKILL_NAME}) 不一致")
            elif len(fields["name"]) > 64:
                problems.append(f"name 超过 64 字符（{len(fields['name'])}）")
            d = fields.get("description", "")
            if not d:
                problems.append("frontmatter 缺必填字段 description")
            elif len(d) > 1024:
                problems.append(f"description 超过 1024 字符（{len(d)}）")
            comp = fields.get("compatibility", "")
            if comp and len(comp) > 500:
                problems.append(f"compatibility 超过 500 字符（{len(comp)}）")

    # 入口脚本可达（文档承诺 python re.py 能跑，装完必须真在）
    for rel in ("scripts/re.py", "scripts/selftest.py"):
        if not os.path.isfile(os.path.join(dest, rel)):
            problems.append(f"缺入口文件 {rel}")

    return (not problems), problems


# ---------------------------------------------------------------- CLI

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="_install.py",
        description="把 reverse-engineering 技能装到各 AI 运行时的技能目录",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("设计要点")[0],
    )
    ap.add_argument("--runtime", "-r", action="append", default=None,
                    help="目标运行时，可重复；省略则用 --auto 或全部")
    ap.add_argument("--scope", choices=["personal", "project"], default="personal")
    ap.add_argument("--project-root", default=os.getcwd(),
                    help="project 级安装的仓库根（默认当前目录）")
    ap.add_argument("--mode", choices=["auto", "link", "copy"], default="auto",
                    help="auto=先试符号链接后退复制（默认）")
    ap.add_argument("--force", action="store_true", help="已存在时先备份再覆盖")
    ap.add_argument("--verify", action="store_true", help="只检查，不安装")
    ap.add_argument("--auto", action="store_true",
                    help="自动探测本机已装的运行时并只装这些")
    ap.add_argument("--list", action="store_true", help="列出支持的运行时与路径")
    args = ap.parse_args()

    if args.list:
        print("运行时            个人级目录                        项目级目录")
        print("-" * 78)
        for rt, (_p, proj, desc) in _RUNTIME_DOC.items():
            pd = personal_dir(rt) or "（不支持）"
            print(f"{rt:<17} {pd:<34} {proj or '（不支持）'}")
            print(f"{'':<17} └ {desc}")
        return 0

    runtimes = args.runtime or []
    if args.auto and not runtimes:
        runtimes = []
        for rt in _RUNTIME_DOC:
            ok, why = runtime_present(rt)
            if ok:
                runtimes.append(rt)
                print(f"[探测] {rt}: {why}")
        if not runtimes:
            print("[错误] 没探测到任何运行时；用 --runtime 显式指定", file=sys.stderr)
            return 2
    if not runtimes:
        print("[错误] 需要 --runtime <名> 或 --auto（--list 看全部）", file=sys.stderr)
        return 2

    bad = [r for r in runtimes if r not in _RUNTIME_DOC]
    if bad:
        print(f"[错误] 未知运行时：{', '.join(bad)}", file=sys.stderr)
        print(f"可用：{', '.join(_RUNTIME_DOC)}", file=sys.stderr)
        return 2

    print(f"技能源：{SELF_ROOT}")
    print(f"模式：{'只验证' if args.verify else '安装'} / {args.scope} 级")
    print("-" * 78)

    n_fail = 0
    for rt in runtimes:
        if args.verify:
            ok, problems = verify_one(rt, args.scope, args.project_root)
            if ok:
                print(f"  [通过] {rt:<12} {_RUNTIME_DOC[rt][2]}")
            else:
                n_fail += 1
                print(f"  [失败] {rt:<12} {_RUNTIME_DOC[rt][2]}")
                for p in problems:
                    print(f"           - {p}")
        else:
            ok, msg = install_one(rt, args.scope, args.project_root,
                                  args.mode, args.force)
            if not ok:
                n_fail += 1
                print(f"  [失败] {rt:<12} {msg}")
                continue
            # 装完立刻回验 —— 只报"成功"不算成功。
            # 回验不过就**改判为失败**（而不是既打 [成功] 又计入失败数，
            # 那种自相矛盾的输出会让人以为装好了）。
            vok, problems = verify_one(rt, args.scope, args.project_root)
            if vok:
                print(f"  [成功] {rt:<12} {msg}")
            else:
                n_fail += 1
                print(f"  [失败] {rt:<12} {msg}")
                print(f"           写入完成但安装后自验未通过：")
                for p in problems:
                    print(f"             - {p}")

    print("-" * 78)
    verb = "验证" if args.verify else "安装"
    if n_fail:
        print(f"{verb}完成：{len(runtimes) - n_fail} 成功 / {n_fail} 失败")
        return 1
    print(f"{verb}完成：{len(runtimes)}/{len(runtimes)} 全部通过")
    if not args.verify:
        print("提示：多数运行时的技能在**新会话**才加载；装完请重开一次会话。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
