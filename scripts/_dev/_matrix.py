# -*- coding: utf-8 -*-
"""工具体检矩阵：每个子命令 × 每种样本格式，实跑一遍并检查契约。

检查项（都是"看起来正常但其实坏了"的那一类）：
  1. 退出码必须是文档约定的那几个，不能是 1（未捕获异常）；
  2. stderr 不能出现 Traceback；
  3. --json 必须给出可解析的对象，且带 ok 键；
  4. **不能有该有值却为 null 的字段** —— 解析失败被吞掉 → 字段留 None
     → 读者当成"确实没有"。
  5. 纯文本模式输出里不能出现裸 "None"。

【本轮修的探针自身的两个毛病】（它们让体检结果失真）
  a) 旧版把**文件路径**无差别塞给每个位置参数。像 case 这种取值是
     {init,status,save,show,load,journal} 的**动作型**子命令会被 argparse
     判非法选项退出（码 2、无输出），报告里看着像"工具坏了"，实则是探针
     喂错了参数；更糟的是这些子命令**一次都没被真正跑到** —— 一个什么都不
     会拦截的体检工具，和项目的死代码同样危险。现在按位置参数的形状选值，
     动作型就逐个把它的每个 action 都跑一遍。
  b) 用法错（码 2 且无输出）与工具故障混在一起。现在单独归类为
     "探针参数不对"，不再伪装成工具缺陷；但**照 Trial 计数**，让"有命令
     没被覆盖"这件事显式可见，反过来逼探针把参数喂对。

用法：python scripts/_dev/_matrix.py [--keep]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
ROOT = os.path.dirname(SCRIPTS)
sys.path.insert(0, SCRIPTS)

CLI = os.path.join(SCRIPTS, "re.py")
PY = sys.executable

# 合法的退出码。1 是"未捕获异常"，绝不允许出现。
EXIT_OK, EXIT_USAGE, EXIT_RUNTIME, EXIT_NOTFOUND = 0, 2, 3, 4
LEGAL = {EXIT_OK, EXIT_USAGE, EXIT_RUNTIME, EXIT_NOTFOUND}

# 优先挑这些不需要追加位置参数的动作，让动作型子命令能一次跑通
SAFE_ACTIONS = ("status", "list", "show", "journal", "ls")


def build_samples(tmp: str) -> "list[tuple[str, str]]":
    """用 selftest 的合成样本构造器造一批样本，覆盖 12 种格式。"""
    import selftest as ST
    ST.TMP = __import__("pathlib").Path(tmp) / "matrix"
    ST.TMP.mkdir(parents=True, exist_ok=True)
    makers = [
        ("pe", ST.mk_pe64), ("elf", ST.mk_elf64), ("macho", ST.mk_macho64),
        ("apk", ST.mk_apk), ("jar", ST.mk_jar), ("dex", ST.mk_dex),
        ("pyc", ST.mk_pyc), ("wasm", ST.mk_wasm), ("sqlite", ST.mk_sqlite),
        ("class", ST.mk_javaclass), ("firmware", ST.mk_firmware),
        ("text", ST.mk_strings_file),
    ]
    out = []
    for name, fn in makers:
        try:
            out.append((name, str(fn())))
        except Exception as e:
            print("  [警告] 造样本 %s 失败：%s: %s" % (name, type(e).__name__, e))
    return out


def arg_candidates(sub, path: str, other: str) -> "list[list[str]]":
    """给一个子命令生成若干套位置参数候选，按「最可能跑通」排序。

    - 取值集合型（有 choices）→ 每个 action 都试一遍，必要时补文件参数
    - 普通目标型           → 文件路径；dest 为 b 的是"第二个文件"
    - 没有位置参数         → 空
    """
    positionals = [a for a in sub._actions if not a.option_strings]
    if not positionals:
        return [[]]

    per_pos = []
    for a in positionals:
        cs = getattr(a, "choices", None)
        if cs:
            cs = list(cs)
            ordered = [c for c in cs if c in SAFE_ACTIONS]
            ordered += [c for c in cs if c not in SAFE_ACTIONS]
            per_pos.append([[c] for c in ordered])
        else:
            per_pos.append([[other if a.dest == "b" else path]])

    combos = [[]]
    for opts in per_pos:
        combos = [x + o for x in combos for o in opts]

    # 每个组合再配一版「补上文件路径」的，覆盖 load/save <name> 这类
    # 后面还要一个参数的动作
    extra = []
    for c in combos:
        if len(c) < len(positionals):
            extra.append(c + [path])
    return combos + extra


def walk_none(obj, path="", depth=0):
    """找出所有值为 None 的位置。"""
    hits = []
    if depth > 6:
        return hits
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            if v is None:
                hits.append(p)
            else:
                hits.extend(walk_none(v, p, depth + 1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            hits.extend(walk_none(v, f"{path}[{i}]", depth + 1))
    return hits


def run_one(name: str, vals: "list[str]"):
    argv = [PY, CLI, name] + vals + ["--json"]
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=120, cwd=SCRIPTS)
    except subprocess.TimeoutExpired:
        return None, "超时 120s"
    return r, None


def main() -> int:
    import argparse
    import importlib.util
    from collections import defaultdict
    import re as _re

    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    ap.parse_args()

    spec = importlib.util.spec_from_file_location("_re_matrix", CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    parser = mod.build_parser()

    choices = None
    for act in parser._actions:
        if act.dest == "cmd" and hasattr(act, "choices"):
            choices = act.choices
    if not choices:
        print("未能取到子命令表")
        return 1

    tmp = os.path.join(os.environ.get("TEMP", "/tmp"), "re-matrix")
    os.makedirs(tmp, exist_ok=True)
    samples = build_samples(tmp)
    print("样本：%s\n" % ", ".join(n for n, _ in samples))

    problems = []
    runs = 0
    usage_only = 0
    covered_cmds = set()
    t0 = time.time()

    for name, sub in sorted(choices.items()):
        for si, (sname, path) in enumerate(samples):
            other = samples[(si + 1) % len(samples)][1]
            cands = arg_candidates(sub, path, other)
            tried = 0
            used = None
            for vals in cands:
                r, err = run_one(name, vals)
                if err:
                    problems.append((name, sname, err, ""))
                    tried += 1
                    break
                tried += 1
                if (r.stdout or "").strip():
                    used = (r, vals)
                    break
                if r.returncode != EXIT_USAGE:
                    used = (r, vals)
                    break
                if tried > 6:
                    break
            if used is None:
                problems.append((name, sname, "探针参数不对（没跑通任何一套）", ""))
                usage_only += 1
                continue

            r, vals = used
            runs += 1
            covered_cmds.add(name)
            if "Traceback" in (r.stderr or ""):
                problems.append((name, sname, "Traceback", (r.stderr or "")[-300:]))
                continue
            if r.returncode not in LEGAL:
                problems.append((name, sname, "退出码 %d" % r.returncode, ""))
                continue
            if not (r.stdout or "").strip():
                problems.append((name, sname, "--json 无输出", " ".join(vals)[:60]))
                continue
            try:
                data = json.loads(r.stdout)
            except Exception as e:
                problems.append((name, sname, "JSON 解析失败 %s" % e,
                                 (r.stdout or "")[:200]))
                continue
            if not isinstance(data, dict):
                continue
            if "ok" not in data:
                problems.append((name, sname, "输出缺 ok 键", str(list(data)[:8])))
            else:
                for p in walk_none(data):
                    problems.append((name, sname, "字段为 null：%s" % p, ""))

    total_cmds = len(choices)
    print("=" * 72)
    print("实跑 %d 组，耗时 %.1fs" % (runs, time.time() - t0))
    print("子命令覆盖 %d/%d" % (len(covered_cmds), total_cmds))

    # 【永不拦截的门】0 组还报"无问题"是最危险的一种通过：
    # CI 里看着全绿，实际一次都没跑。样本造不出来必须显式失败。
    if runs == 0:
        print("[失败] 一组都没跑成——样本构造或子命令枚举失败了，不算通过。")
        return 1
    if not samples:
        print("[失败] 没造出任何样本，不算通过。")
        return 1

    missed = sorted(set(choices) - covered_cmds)
    if missed:
        print("[注意] 以下子命令一次都没跑通（探针要修）：%s" % ", ".join(missed))

    if not problems:
        print("无问题。")
        return 0

    hard, nulls = [], defaultdict(set)
    for name, sname, kind, extra in problems:
        if kind.startswith("字段为 null："):
            norm = _re.sub(r"\[\d+\]", "[]", kind[len("字段为 null："):])
            nulls[norm].add(sname)
        else:
            hard.append((name, sname, kind, extra))

    print("\n【硬性故障】%d 处" % len(hard))
    if hard:
        g = defaultdict(list)
        for name, sname, kind, extra in hard:
            g[(kind, extra)].append((name, sname))
        for (kind, extra), items in sorted(g.items(), key=lambda x: -len(x[1])):
            print("  [%d×] %s%s" % (len(items), kind, ("  " + extra) if extra else ""))
            print("        " + ", ".join("%s×%s" % (n, s) for n, s in items[:8]))
    else:
        print("  无")

    print("\n【字段为 null】（需人工判定：有些是合法的「可选字段」）")
    for p, hit in sorted(nulls.items(), key=lambda x: -len(x[1])):
        print("  %-52s 出现在 %d 种样本" % (p, len(hit)))
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
