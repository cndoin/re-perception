# -*- coding: utf-8 -*-
"""开源合规与文档一致性审计（只报告，不修改）。"""
import io
import os
import re
import subprocess
import sys

# 仓库根 = 本文件的上上级目录，不写死路径（否则这份审计器自己就是
# "硬编码本机路径"的样本，会被 _lint 正当地拦下来）。
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
findings = []


def rep(cat, sev, where, msg):
    findings.append((cat, sev, where, msg))


def read(p):
    return io.open(os.path.join(ROOT, p), encoding="utf-8").read()


# ---------------------------------------------------------------- 1. 真实事实采集
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import lib_agent as AG
import lib_tools as LT

CATALOG_N = len(AG.CATALOG)

# CLI 实际注册的子命令数。
# 注意：re.py 用的是本地 helper `add("name", ...)`，不是 `add_parser("name")`。
# 所以要走 CLI 自省（--help 是权威），不要正则猜源码。
def _cli_subcommands():
    p = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "re.py"),
                        "--help"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60)
    txt = p.stdout + p.stderr
    # argparse 把子命令列在 "{a,b,c}" 里
    m = re.search(r"\{([a-z_][\w,-]*)\}", txt)
    if m:
        return sorted(set(m.group(1).split(",")))
    return []

subs = _cli_subcommands()
CLI_N = len(subs)

# selftest 实际用例数：用 --json 跑一次太慢，直接从源码的 cases 列表数
st_src = read("scripts/selftest.py")
# 注意：文件里有多个 `cases = [`（有些是测试用例内部的局部变量），
# 必须锚定 main() 里那一个 —— 否则会数到错误的块（实测踩过）。
i_main = st_src.index("def main():")
i0 = st_src.index("    cases = [", i_main)
i1 = st_src.index("    t0 = time.time()", i0)
cases_block = st_src[i0:i1]
SELFTEST_N = len(re.findall(r'^\s*\(\"', cases_block, re.M))

# 外部工具数
try:
    tools = LT.TOOLS if hasattr(LT, "TOOLS") else None
    if tools is None:
        for cand in ("TOOL_TABLE", "TOOLS_TABLE", "CATALOG"):
            if hasattr(LT, cand):
                tools = getattr(LT, cand)
                break
    TOOLS_N = len(tools) if tools is not None else "?"
except Exception as e:
    TOOLS_N = "ERR:%s" % e

print("=== 实测事实 ===")
print("  CATALOG 条目（编排层）:", CATALOG_N)
print("  CLI 子命令（re.py 注册）:", CLI_N, sorted(subs))
print("  selftest 用例:", SELFTEST_N)
print("  外部工具表条目:", TOOLS_N)
print()

# ---------------------------------------------------------------- 2. 文档声明 vs 实测
DOCS = ["README.md", "CONTRIBUTING.md", "SKILL.md", "CHANGELOG.md",
        "scripts/_dev/README.md"]

# 允许出现的"历史数字"位置：CHANGELOG 是历史记录，旧数字是正常的
HISTORY_OK = {"CHANGELOG.md"}

claims = {
    # (文档里的数字正则, 实测值, 说明)
    "selftest 用例数": (r"(\d+)\s*个自检用例", SELFTEST_N),
    "selftest 全量用例": (r"全量自检（约 \d+ 秒，(\d+) 个用例）", SELFTEST_N),
    "子命令数": (r"(\d+)\s*个子命令", CLI_N),
}

for doc in DOCS:
    if not os.path.isfile(os.path.join(ROOT, doc)):
        continue
    txt = read(doc)
    for label, (pat, real) in claims.items():
        for m in re.finditer(pat, txt):
            got = int(m.group(1))
            if got != real and doc not in HISTORY_OK:
                ln = txt[:m.start()].count("\n") + 1
                rep("文档数字过期", "高", "%s:%d" % (doc, ln),
                    "%s 写的是 %d，实际 %d（%r）" % (label, got, real, m.group(0)))

# 命令数表格行数（README "命令一览"）
# 从标题扫到下一个同级标题为止 —— 不假设"标题后紧跟空行+表格"这种脆弱排版。
_cm = re.search(r"^## 命令一览\s*$", read("README.md"), re.M)
if _cm:
    _rest = read("README.md")[_cm.end():]
    _nxt = re.search(r"^## ", _rest, re.M)
    _sec = _rest[:_nxt.start()] if _nxt else _rest
    rows = len(re.findall(r"^\|\s*`", _sec, re.M))
    if rows != CLI_N:
        rep("文档数字过期", "中", "README.md 命令一览",
            "表格 %d 行，CLI 实际 %d 个子命令" % (rows, CLI_N))

# 工具数
for doc in DOCS:
    if not os.path.isfile(os.path.join(ROOT, doc)):
        continue
    txt = read(doc)
    for m in re.finditer(r"(\d+)\s*个外部工具", txt):
        got = int(m.group(1))
        if isinstance(TOOLS_N, int) and got != TOOLS_N and doc not in HISTORY_OK:
            ln = txt[:m.start()].count("\n") + 1
            rep("文档数字过期", "中", "%s:%d" % (doc, ln),
                "外部工具写 %d，实际 %d" % (got, TOOLS_N))

# ---------------------------------------------------------------- 2.6 生产模块是否被文档覆盖
# 反向检查：旧审计器只查"文档引用的文件在不在"（防多余），这里补"存在的
# 生产模块有没有被文档提到"（防缺失）。两个方向都查才算完整。
_SCRIPTS_DIR = os.path.join(ROOT, "scripts")
_prod_mods = sorted(
    f[:-3] for f in os.listdir(_SCRIPTS_DIR)
    if f.endswith(".py") and not f.startswith("__")
    and f not in ("re.py", "selftest.py")
)
# 文档可能只提 SKILL.md / README.md 之一；两处都提过就算覆盖。
_doc_text = ""
for _d in ("SKILL.md", "README.md", "CONTRIBUTING.md"):
    _p = os.path.join(ROOT, _d)
    if os.path.isfile(_p):
        _doc_text += read(_d)
for _m in _prod_mods:
    # 允许 "lib_x86" 或 "lib_x86.py" 任一写法；下划线前缀模块（_quirk）同理
    if _m not in _doc_text:
        rep("生产模块未进文档", "中", "scripts/%s.py" % _m,
            "生产模块未在任何文档中出现（README 目录结构 / SKILL.md 模块表应有它）")

# ---------------------------------------------------------------- 3. 失效的相对链接
for f in ["README.md", "CONTRIBUTING.md", "CHANGELOG.md", "SKILL.md"] + \
         ["references/" + x for x in os.listdir(os.path.join(ROOT, "references"))] + \
         ["scripts/_dev/README.md"]:
    p = os.path.join(ROOT, f)
    if not os.path.isfile(p):
        continue
    txt = io.open(p, encoding="utf-8").read()
    for m in re.finditer(r"\[([^\]]*)\]\(([^)#\s]+)(#[^)\s]*)?\)", txt):
        tgt = m.group(2)
        if tgt.startswith(("http://", "https://", "mailto:")):
            continue
        cand = os.path.normpath(os.path.join(os.path.dirname(p), tgt))
        if not os.path.exists(cand):
            ln = txt[:m.start()].count("\n") + 1
            rep("失效链接", "高", "%s:%d" % (f, ln),
                "[%s](%s) -> 目标不存在" % (m.group(1), tgt))

# ---------------------------------------------------------------- 4. 文档提到的脚本是否真实存在
for f in ["README.md", "CONTRIBUTING.md", "SKILL.md", "scripts/_dev/README.md"]:
    p = os.path.join(ROOT, f)
    if not os.path.isfile(p):
        continue
    txt = io.open(p, encoding="utf-8").read()
    for m in re.finditer(r"`([\w/]+\.py)`", txt):
        rel = m.group(1)
        # 文档里可能写相对仓库根（scripts/x.py）也可能写相对 scripts/（x.py），
        # 也可能写相对 _dev/（_lint.py）。三种都试，都对不上才算失效。
        base = os.path.dirname(p)
        cands = [
            os.path.join(ROOT, rel),                      # 相对仓库根
            os.path.join(ROOT, "scripts", rel),           # 相对 scripts/
            os.path.join(ROOT, "scripts", "_dev", rel),   # 相对 scripts/_dev/
            os.path.join(base, rel),                      # 相对当前文件
        ]
        if not any(os.path.exists(c) for c in cands):
            ln = txt[:m.start()].count("\n") + 1
            rep("文档引用不存在的脚本", "高", "%s:%d" % (f, ln), rel)

# ---------------------------------------------------------------- 5. 敏感信息泄漏


def _skip_lines(txt, is_py):
    """返回"不该拿去匹配密钥/路径"的行号集合（1 基）。

    .py：注释行 + docstring 行。Python 的 tokenize 能给出注释行号，但它在
    语法错误时会抛异常；这里用 AST 拿 docstring，用逐行前缀判断拿注释 ——
    两者都不需要文件语法完全正确（AST 失败就只做注释豁免）。
    """
    skip = set()
    if not is_py:
        return skip
    # 注释行：去掉前导空白后以 # 开头
    for i, line in enumerate(txt.splitlines(), 1):
        if line.lstrip().startswith("#"):
            skip.add(i)
    # docstring 行：复用 _lint.py 的同款做法
    try:
        import ast as _ast
        tree = _ast.parse(txt)
    except Exception:
        return skip
    for node in _ast.walk(tree):
        if not isinstance(node, (_ast.Module, _ast.FunctionDef,
                                 _ast.AsyncFunctionDef, _ast.ClassDef)):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if (isinstance(first, _ast.Expr)
                and isinstance(first.value, _ast.Constant)
                and isinstance(first.value.value, str)):
            start = first.lineno
            end = getattr(first, "end_lineno", start) or start
            for ln in range(start, end + 1):
                skip.add(ln)
    return skip


SECRET_PAT = [
    (r"\b(?:sk|pk)-[A-Za-z0-9]{20,}", "疑似 API key"),
    (r"\bghp_[A-Za-z0-9]{30,}", "疑似 GitHub token"),
    (r"\bAKIA[0-9A-Z]{16}\b", "疑似 AWS key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "私钥"),
    (r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b", "邮箱地址"),
    (r"[Cc]:\\Users\\[A-Za-z0-9_.-]+", "本机绝对路径（含用户名）"),
    (r"/Users/[A-Za-z0-9_.-]+/", "本机绝对路径（macOS）"),
    (r"/home/[A-Za-z0-9_.-]+/", "本机绝对路径（Linux）"),
]
SKIP_DIRS = {"__pycache__", "_ref", ".git"}
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in filenames:
        if not fn.endswith((".py", ".md", ".js", ".yml", ".yaml", ".txt", ".json")):
            continue
        fp = os.path.join(dirpath, fn)
        rel = os.path.relpath(fp, ROOT).replace("\\", "/")
        try:
            txt = io.open(fp, encoding="utf-8").read()
        except Exception:
            continue
        # 公开的占位/示例值白名单（AWS 官方文档就用 AKIAIOSFODNN7EXAMPLE）
        FALSE_POS = ("AKIAIOSFODNN7EXAMPLE", "sk-xxxxxxxx", "AKIAIOSFODNN7EXAMPL")
        # 注释与 docstring 里出现路径是在**解释这个坑**，不是泄漏；
        # 与 _lint.py 的守卫保持同一套判断标准（两个工具不一致＝我们自己的 bug）。
        _exempt = _skip_lines(txt, fn.endswith(".py"))
        for pat, kind in SECRET_PAT:
            for m in re.finditer(pat, txt):
                if any(v in m.group(0) for v in FALSE_POS):
                    continue
                ln = txt[:m.start()].count("\n") + 1
                if ln in _exempt:
                    continue
                # 邮箱：只在明显是个人邮箱时报
                if kind == "邮箱地址":
                    v = m.group(0).lower()
                    if v.endswith(("@example.com", "@users.noreply.github.com",
                                    "@email.com")) or "example" in v:
                        continue
                    if "noreply" in v or "github" in v:
                        continue
                rep("敏感信息/隐私", "中" if "路径" in kind or kind == "邮箱地址" else "高",
                    "%s:%d" % (rel, ln), "%s：%s" % (kind, m.group(0)[:70]))

# ---------------------------------------------------------------- 6. 开源标配文件
MUST = {
    "LICENSE": "高", "README.md": "高", "CHANGELOG.md": "中",
    "CONTRIBUTING.md": "中", ".gitignore": "中", "SKILL.md": "高",
}
OPT = {
    "CODE_OF_CONDUCT.md": "行为准则（社区健康度）",
    "SECURITY.md": "安全披露政策（安全类项目强烈建议）",
    ".github/workflows": "CI（自动跑自检，开源项目基本标配）",
    ".github/ISSUE_TEMPLATE": "issue 模板",
    ".github/PULL_REQUEST_TEMPLATE.md": "PR 模板",
    ".editorconfig": "编辑器统一配置",
    "Makefile": "常用命令入口",
}
for f, sev in MUST.items():
    if not os.path.exists(os.path.join(ROOT, f)):
        rep("缺少必备文件", sev, f, "开源标配文件缺失")
for f, why in OPT.items():
    if not os.path.exists(os.path.join(ROOT, f)):
        rep("缺少建议文件", "低", f, why)

# ---------------------------------------------------------------- 7. 版权/署名一致性
lic = read("LICENSE")
ski = read("SKILL.md")
m_lic = re.search(r"Copyright \(c\) (\d{4}) (.+)", lic)
m_aut = re.search(r"author:\s*(.+)", ski)
if m_lic and m_aut:
    lic_name = m_lic.group(2).strip()
    ski_name = m_aut.group(1).strip()
    if ski_name not in lic_name:
        rep("署名不一致", "中", "LICENSE vs SKILL.md",
            "LICENSE=%r，SKILL.md author=%r" % (lic_name, ski_name))

# ---------------------------------------------------------------- 8. 项目自身是否 git 仓库
try:
    p = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"],
                       cwd=ROOT, capture_output=True, text=True, timeout=20)
    is_git = p.returncode == 0 and p.stdout.strip() == "true"
except Exception:
    is_git = False
if not is_git:
    rep("仓库状态", "高", ROOT,
        "不是 git 仓库 —— 无法提交/推送/打标签/被 clone，开源流程无法启动")

# ---------------------------------------------------------------- 输出
print("=" * 72)
order = {"高": 0, "中": 1, "低": 2}
findings.sort(key=lambda x: (order.get(x[1], 3), x[0], x[2]))
cur = None
for cat, sev, where, msg in findings:
    if cat != cur:
        print("\n[%s]" % cat)
        cur = cat
    print("  (%s) %-42s %s" % (sev, where, msg))
print("\n" + "=" * 72)
_n_high = sum(1 for f in findings if f[1] == "高")
_n_mid = sum(1 for f in findings if f[1] == "中")
_n_low = sum(1 for f in findings if f[1] == "低")
print("合计 %d 项（高 %d / 中 %d / 低 %d）" % (len(findings), _n_high, _n_mid, _n_low))

# 退出码契约（供 CI 当门禁用）：
#   0 无高危项 / 1 存在高危项 / 2 审计器自身出错
# 早期版本永远返回 0 —— 装进 CI 后等于一道永不拦截的门，属于"失败被上报
# 为成功"，只不过犯错的是我们自己的审计工具。这里补上。
if _n_high:
    print("存在高危项，退出码 1")
sys.exit(1 if _n_high else 0)
