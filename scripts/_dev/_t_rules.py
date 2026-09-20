# -*- coding: utf-8 -*-
"""
对真实 PE 跑一遍规则引擎，验证「特征提取 -> 匹配」全链路。

注意：这里的流程必须与 re.py 的 cmd_semantics 保持一致。
第一版测试脚本自己拼流程，漏了 str_map、用了不存在的 iat_map 字段，
结果全部 api 特征为空、规则 0 命中 —— 看起来像引擎坏了，其实是喂错了数据。
所以现在统一走 D.resolve_iat / S.string_vma_map / S.resolve_thunks。

用法：
    python _dev/_t_rules.py [目标文件]
"""
import sys
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
SKILL = os.path.dirname(SCRIPTS)
sys.path.insert(0, SCRIPTS)

import lib_rules as R
import lib_formats as F
import lib_disasm as D
import lib_semantics as S

target = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\notepad.exe"
print("目标：%s" % target)
print()

t0 = time.time()
rules, errs = R.load_rules(os.path.join(SKILL, "rules"))
print("规则：%d 条" % len(rules))
if errs:
    print("规则加载错误：")
    for e in errs:
        print("  !", e)
else:
    print("规则加载错误：无")

ident = F.identify(target, deep=True)
print("格式：%s（%s），arch=%s bits=%s"
      % (ident.get("format"), ident.get("label"), ident.get("arch"), ident.get("bits")))

an = D.analyze_file(target, ident, max_insns=300000)
if not an.get("ok"):
    print("分析失败：%s" % an.get("error"))
    sys.exit(1)

idx = an.get("_idx")
funcs = an.get("functions") or []
print("函数：%d 个，覆盖率 %s" % (len(funcs), an.get("coverage")))
if an.get("truncated"):
    print("!! 指令预算用尽，规则结果可能不完整")

# ---- 严格照 cmd_semantics 的顺序准备入参 ----
from lib_code import find_functions
if idx is not None and (not funcs or not funcs[0].get("_offs")):
    funcs = find_functions(idx, seeds=D.entry_points(ident),
                           symbols=D.symbols_from(ident))

iat = D.resolve_iat(ident)
str_map = {}
if idx is not None:
    try:
        str_map = S.string_vma_map(target, ident)
    except Exception as e:
        print("字符串映射失败：%s: %s" % (type(e).__name__, e))

sem = None
try:
    thunks = S.resolve_thunks(idx, funcs, iat)
    sem = {"functions": S.summarize_functions(idx, funcs, iat, str_map,
                                              limit=400, thunk_map=thunks)}
except Exception as e:
    print("语义层失败（api 特征会缺失）：%s" % e)

print("IAT 解析 %d 项，字符串映射 %d 条" % (len(iat), len(str_map)))

feats = R.build_features(target, ident, idx, funcs, iat_map=iat, sem=sem)
ff = feats["file"]
print("文件特征：section=%d import=%d export=%d string=%d os=%s arch=%s"
      % (len(ff["section"]), len(ff["import"]), len(ff["export"]),
         len(ff["string"]), sorted(ff["os"]), sorted(ff["arch"])))
print("函数特征：%d 个函数" % len(feats["functions"]))
if feats.get("errors"):
    print("特征抽取错误：")
    for e in feats["errors"]:
        print("  !", e)

n_api = sum(len(f["api"]) for f in feats["functions"].values())
n_tag = sum(len(f["tag"]) for f in feats["functions"].values())
n_mn = sum(len(f["mnemonic"]) for f in feats["functions"].values())
n_num = sum(len(f["number"]) for f in feats["functions"].values())
print("函数特征合计：api=%d tag=%d mnemonic=%d number=%d"
      % (n_api, n_tag, n_mn, n_num))

res = R.match_rules(rules, feats)
print()
print("命中 %d 条，命名空间 %d 个，耗时 %.2fs"
      % (len(res["hits"]), len(res["by_namespace"]), time.time() - t0))
for ns, names in sorted(res["by_namespace"].items()):
    print("  [%s]" % ns)
    for n in names:
        print("      -", n)
if res.get("att_ck"):
    print("ATT&CK:")
    for a in res["att_ck"]:
        print("  *", a)
if res.get("errors"):
    print("匹配错误：")
    for e in res["errors"][:10]:
        print("  !", e)

# 命中位置样例
locs = {}
for h in res["hits"]:
    locs.setdefault(h["rule"], []).append(h.get("location"))
print()
print("命中位置（前 6 条规则）：")
for k, v in list(locs.items())[:6]:
    print("  %s @ %s" % (k, ", ".join(x for x in v[:3] if x)))

# 未命中但已加载的规则，明确列出来 —— 避免"0 命中"被误读成"引擎坏了"
hit_names = {h["rule"] for h in res["hits"]}
missed = [r.name for r in rules if r.name not in hit_names]
if missed:
    print()
    print("未命中 %d 条：%s" % (len(missed), ", ".join(missed)))
