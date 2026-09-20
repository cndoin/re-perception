# -*- coding: utf-8 -*-
"""
对抗性压力测试：专打"合法输入但极端形状"的路径。

普通 fuzz 喂随机字节；这里喂**结构合法但深度/宽度极端**的输入。
这类输入不会触发任何 lint，但会让递归爆栈、循环卡死、内存吃光。
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
PY = sys.executable
CLI = os.path.join(SCRIPTS, "re.py")
sys.path.insert(0, SCRIPTS)

TMP = tempfile.mkdtemp(prefix="re-adversarial-")
FAILS: list[str] = []
NOTES: list[str] = []


def ok(name: str, detail: str = "") -> None:
    print(f"  [PASS] {name}  {detail}")


def bad(name: str, detail: str) -> None:
    print(f"  [FAIL] {name}  {detail}")
    FAILS.append(f"{name}: {detail}")


def note(name: str, detail: str) -> None:
    print(f"  [NOTE] {name}  {detail}")
    NOTES.append(f"{name}: {detail}")


def run(args, timeout=120, stdin=None):
    p = subprocess.run([PY, CLI, *args], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout,
                       input=stdin, cwd=SCRIPTS)
    return p.returncode, p.stdout, p.stderr


# ---------------------------------------------------------------- 1. 深度嵌套规则

def t_deep_nested_rule():
    """
    深嵌套规则 → 递归爆栈？

    这是**真实攻击面**：规则库在 rules/*.yml，用户可以自己往里加。
    匹配器与 YAML 解析器都是**递归**实现的，深嵌套会一路加深调用栈。

    两层风险都要测：
      1. YAML 解析阶段（parse_block/parse_list 互相递归）
      2. 规则匹配阶段（eval_node 递归）

    判定标准不是"必须成功"，而是**不许把 RecursionError 泄漏成崩溃**：
    要么受控报错（结构化 JSON + ok=false），要么正常处理完。

    注意 depth 的选择：每层缩进 2 空格，depth=5000 会生成 25MB YAML，
    跑一次要几分钟。1200 层已经远超 Python 默认递归上限（1000）触发的需要，
    足以覆盖这条攻击面，同时保持测试快速。
    """
    depth = 1200
    lines = ["rule:", "  meta:", "    name: deepnested", "    scope: file",
             "  features:"]
    for i in range(depth):
        lines.append(" " * (2 + i * 2) + "- and:")
    lines.append(" " * (2 + depth * 2) + "- match: no_such_rule")
    yml = "\n".join(lines) + "\n"

    rp = os.path.join(TMP, "deep_rule.yml")
    with io.open(rp, "w", encoding="utf-8") as f:
        f.write(yml)

    pe = os.path.join(TMP, "deep_target.bin")
    with open(pe, "wb") as f:
        f.write(b"MZ" + b"\x00" * 2048)

    try:
        code, out, err = run(["capability", pe, "--rules", rp, "--json"],
                             timeout=240)
    except subprocess.TimeoutExpired:
        bad("深嵌套规则(%d层)" % depth, "超时 240s —— 疑似指数级展开")
        return

    # 【关键】不许有未捕获异常逃逸到 stderr。
    # 判定只看真正的栈帧标记，不看错误**文本**里是否出现关键字——
    # 错误信息里写"递归深度过大"是**正确行为**，不能算失败。
    if "Traceback (most recent call last)" in err:
        last = [l for l in err.strip().splitlines() if l.strip()][-1:]
        bad("深嵌套规则(%d层)" % depth,
            f"未捕获异常逃逸：{last[0][:150] if last else '?'}")
        return
    if "RecursionError" in err and "Traceback" in err:
        bad("深嵌套规则(%d层)" % depth, f"递归爆栈未被拦截：{err[:150]}")
        return

    try:
        d = json.loads(out)
    except Exception:
        bad("深嵌套规则(%d层)" % depth, f"非 JSON 输出：{out[:120]}")
        return
    if "ok" not in d:
        bad("深嵌套规则(%d层)" % depth, "缺顶层 ok")
        return
    if code not in (0, 2, 3, 4):
        bad("深嵌套规则(%d层)" % depth, f"退出码 {code}")
        return

    # 报告实际结论：是"处理完了"还是"受控拒绝了"
    if d.get("ok"):
        detail = f"正常处理完（rules={d.get('rule_count') or len(d.get('rules') or [])}）"
    else:
        reason = str(d.get("error") or "")[:80]
        detail = f"受控拒绝：{reason}"
    ok("深嵌套规则(%d层)" % depth, f"退出码 {code}，{detail}")


# ---------------------------------------------------------------- 2. 空/零长度分母

def t_zero_denominator():
    """
    打所有用 len() 做分母的路径：喂 0 长度输入。

    典型来源：空文件、空字符串集合、空 insn 列表。
    """
    empty = os.path.join(TMP, "empty.bin")
    open(empty, "wb").close()
    cases = [
        (["sim", empty, empty], "sim 同空文件"),
        (["semantics", empty], "semantics 空文件"),
        (["funcs", empty], "funcs 空文件"),
        (["entropy", empty], "entropy 空文件"),
        (["symbols", empty], "symbols 空文件"),
        (["obfstr", empty], "obfstr 空文件"),
        (["strings", empty], "strings 空文件"),
        (["triage", empty], "triage 空文件"),
    ]
    for args, label in cases:
        code, out, err = run([*args, "--json"], timeout=90)
        if "Traceback (most recent call last)" in (out + err):
            last = [l for l in err.strip().splitlines() if l.strip()][-1:]
            bad(f"零分母 {label}", f"Traceback：{last[0][:120] if last else '?'}")
            continue
        try:
            d = json.loads(out)
        except Exception:
            bad(f"零分母 {label}", f"非 JSON 输出：{out[:100]}")
            continue
        if "ok" not in d:
            bad(f"零分母 {label}", "输出缺顶层 ok")
            continue
        ok(f"零分母 {label}", f"ok={d['ok']}")


# ---------------------------------------------------------------- 3. 超长路径/文件名

def t_extreme_paths():
    """超长路径、深层目录、Unicode 名、Windows 保留名。"""
    cases = {
        "超长文件名": "a" * 250 + ".bin",
        "Unicode": "逆向测试_日本語_한국어_🎯.bin",
        "空格与括号": "my file (1) [copy].bin",
        "点开头": ".hidden.bin",
        "全点": "...",
    }
    for label, name in cases.items():
        try:
            p = os.path.join(TMP, name)
            with open(p, "wb") as f:
                f.write(b"MZ" + b"\x00" * 100)
        except OSError as e:
            note(f"路径 {label}", f"本机建不出来，跳过（{type(e).__name__}）")
            continue
        code, out, err = run(["identify", p, "--json"], timeout=60)
        if "Traceback (most recent call last)" in (out + err):
            bad(f"路径 {label}", "Traceback")
            continue
        try:
            d = json.loads(out)
            if "ok" not in d:
                bad(f"路径 {label}", "缺 ok")
                continue
        except Exception:
            bad(f"路径 {label}", f"非 JSON：{out[:80]}")
            continue
        ok(f"路径 {label}", f"ok={d['ok']}")

    # 目录当文件
    code, out, err = run(["identify", TMP, "--json"], timeout=60)
    if "Traceback (most recent call last)" in (out + err):
        bad("目录当文件", "Traceback")
    else:
        try:
            d = json.loads(out)
            handled = (d.get("ok") is False) or d.get("error")
            ok("目录当文件", f"受控：ok={d.get('ok')} err={str(d.get('error'))[:50]}"
               if handled else f"ok={d.get('ok')}（未明确报错，需确认）")
        except Exception:
            bad("目录当文件", f"非 JSON：{out[:80]}")

    # 不存在的路径
    code, out, err = run(["identify", os.path.join(TMP, "nope.bin"), "--json"], timeout=60)
    if code != 3:
        bad("不存在的路径", f"退出码应为 3，得到 {code}")
    else:
        ok("不存在的路径", "退出码 3")


# ---------------------------------------------------------------- 4. 编号极大/负值地址

def t_extreme_addresses():
    """给 cfg/xref 喂极端地址：0、-1、0xFFFFFFFFFFFFFFFFFF（超 64 位）。"""
    pe = os.path.join(TMP, "s.bin")
    with open(pe, "wb") as f:
        f.write(b"MZ" + b"\x00" * 4096)
    for addr in ("0", "-1", "ffffffffffffffffff", "8000000000000000", "zzz"):
        for cmd in ("cfg", "xref"):
            args = [cmd, pe, addr, "--json"] if cmd == "cfg" else [cmd, pe, "--addr", addr, "--json"]
            code, out, err = run(args, timeout=90)
            if "Traceback (most recent call last)" in (out + err):
                bad(f"{cmd} 地址={addr}", "Traceback")
                continue
            try:
                d = json.loads(out)
                if "ok" not in d:
                    bad(f"{cmd} 地址={addr}", "缺 ok")
                    continue
            except Exception:
                bad(f"{cmd} 地址={addr}", f"非 JSON：{out[:80]}")
                continue
            ok(f"{cmd} 地址={addr}", f"ok={d['ok']}")


# ---------------------------------------------------------------- 5. 超深 CFG / 长跳转链

def t_cfg_bomb():
    """
    构造大量无条件 jmp 串成的长链 → CFG 遍历会不会 O(N²) 或卡死？

    做法：在 x86-64 里塞 N 条 `jmp rel8` 互指（EB FE = jmp self，
    E9 xx = jmp rel32）。这里用 EB 00 链式推进。
    """
    import struct
    n = 20000
    code = bytearray()
    # jmp rel8 = EB <disp>；用 disp=0 走进下一条（填充 NOP）
    for _ in range(n):
        code += b"\xeb\x00"
    pe = os.path.join(TMP, "jmpchain.bin")
    with open(pe, "wb") as f:
        f.write(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40) + b"\x00" * 2)
        f.write(b"\x00" * (0x40 - 64))
        f.write(b"\x90" * 64)
        f.write(bytes(code))
    t0 = time.time()
    try:
        code_rc, out, err = run(["funcs", pe, "--json"], timeout=150)
    except subprocess.TimeoutExpired:
        bad("CFG 长跳转链(20000)", "超时 150s —— 疑似 O(N²)")
        return
    dt = round(time.time() - t0, 2)
    if "Traceback (most recent call last)" in (out + err):
        bad("CFG 长跳转链(20000)", "Traceback")
    elif code_rc not in (0, 2, 3, 4):
        bad("CFG 长跳转链(20000)", f"退出码 {code_rc}")
    else:
        ok("CFG 长跳转链(20000)", f"退出码 {code_rc}，耗时 {dt}s")


# ---------------------------------------------------------------- 6. case 目录对抗

def t_case_adversarial():
    """手工破坏 case 目录的各种方式 → 必须受控。"""
    import lib_agent as AG
    for label, mutate in [
        ("manifest 非 JSON", lambda d: open(os.path.join(d, "manifest.json"), "w").write("{bad")),
        ("index 非 JSON", lambda d: open(os.path.join(d, "index.json"), "w").write("[[[")),
        ("index 是数组", lambda d: open(os.path.join(d, "index.json"), "w").write("[]")),
        ("index.artifacts 是字符串", lambda d: open(os.path.join(d, "index.json"), "w").write('{"artifacts":"x"}')),
        ("entry 不是 dict", lambda d: open(os.path.join(d, "index.json"), "w").write('{"artifacts":{"triage":123}}')),
        ("artifact 路径穿越", lambda d: open(os.path.join(d, "index.json"), "w").write(
            '{"artifacts":{"triage":{"artifact":"../../etc/passwd"}}}')),
        ("journal 是垃圾", lambda d: open(os.path.join(d, "journal.jsonl"), "w").write("not json\n" * 5)),
    ]:
        d = tempfile.mkdtemp(prefix="re-casedmg-", dir=TMP)
        tgt = os.path.join(d, "t.bin")
        open(tgt, "wb").write(b"MZ" + b"\x00" * 100)
        AG.case_init(d, tgt)
        AG.case_save(d, "triage", {"ok": True, "count": 1}, target=tgt)
        try:
            mutate(d)
        except Exception as e:
            note(f"case 破坏 {label}", f"构造失败 {e}")
            continue
        # status 必须受控，且**必须如实报告索引损坏**
        try:
            st = AG.case_status(d, target=tgt)
            if not isinstance(st, dict) or "ok" not in st:
                bad(f"case 破坏 {label}", f"case_status 返回异常：{str(st)[:80]}")
                continue
        except Exception as e:
            bad(f"case 破坏 {label}", f"case_status 抛 {type(e).__name__}: {e}")
            continue
        # load 必须受控
        try:
            ld = AG.case_load(d, "triage", target=tgt, allow_stale=True)
            if not isinstance(ld, dict) or "ok" not in ld:
                bad(f"case 破坏 {label}", f"case_load 返回异常：{str(ld)[:80]}")
                continue
        except Exception as e:
            bad(f"case 破坏 {label}", f"case_load 抛 {type(e).__name__}: {e}")
            continue
        # flow 必须受控
        try:
            fl = AG.flow(case_dir=d, target=tgt)
            if not isinstance(fl, dict) or "ok" not in fl:
                bad(f"case 破坏 {label}", f"flow 返回异常：{str(fl)[:80]}")
                continue
        except Exception as e:
            bad(f"case 破坏 {label}", f"flow 抛 {type(e).__name__}: {e}")
            continue
        # toolgraph 必须受控
        try:
            tg = AG.toolgraph("triage", case_dir=d)
            if not isinstance(tg, dict) or "ok" not in tg:
                bad(f"case 破坏 {label}", f"toolgraph 返回异常：{str(tg)[:80]}")
                continue
        except Exception as e:
            bad(f"case 破坏 {label}", f"toolgraph 抛 {type(e).__name__}: {e}")
            continue

        # 【关键断言】索引真被改坏时，status 必须报 ok=False + 给出原因。
        # 否则调用方看到 ok 就会以为"确实只有这些结果"——
        # 而真相是"索引读不全"，两者导出的下一步决策完全相反。
        if label.startswith("index") or label.startswith("entry"):
            if st.get("ok") is not False:
                bad(f"case 破坏 {label}",
                    f"索引损坏但 status 仍报 ok=True（st={str(st)[:90]}）")
                continue
            if not st.get("warnings") and not st.get("reason"):
                bad(f"case 破坏 {label}", "索引损坏但没说明原因")
                continue
            # load 也应说明是索引问题，而不是"没有这条记录"
            if ld.get("ok") is False:
                err = str(ld.get("error") or "")
                if "索引" not in err and "损坏" not in err:
                    bad(f"case 破坏 {label}",
                        f"load 把索引损坏报成了普通缺失：{err[:90]}")
                    continue
        ok(f"case 破坏 {label}", "status/load/flow/toolgraph 全部受控")


# ---------------------------------------------------------------- 7. require 对抗输入

def t_require_adversarial():
    """意图检索喂极端字符串 → 不崩、不超时。"""
    import lib_agent as AG
    cases = {
        "超长意图": "加壳" * 20000,
        "纯符号": "!@#$%^&*(){}[]|\\:;\"'<>,.?/~`" * 100,
        "单个字符": "熵",
        "空白": "   \t\n  ",
        "emoji": "🎯" * 500,
        "超长单词": "a" * 100000,
        "混合": "加壳" * 50 + "a" * 5000 + "🎯" * 50,
    }
    for label, q in cases.items():
        t0 = time.time()
        try:
            r = AG.recommend(q, top_k=6)
            dt = round(time.time() - t0, 2)
        except Exception as e:
            bad(f"require {label}", f"抛 {type(e).__name__}: {e}")
            continue
        if not isinstance(r, dict) or "ok" not in r:
            bad(f"require {label}", f"返回异常：{str(r)[:80]}")
            continue
        if dt > 5:
            bad(f"require {label}", f"耗时 {dt}s 过长（疑似 O(N²)）")
            continue
        ok(f"require {label}", f"ok={r['ok']} n={len(r.get('recommendations') or [])} {dt}s")


# ---------------------------------------------------------------- 8. result 对抗输入

def t_result_adversarial():
    """result 喂各种畸形 JSON → 受控。"""
    cases = {
        "空对象": "{}",
        "数组": "[1,2,3]",
        "字符串": '"hello"',
        "数字": "42",
        "null": "null",
        "true": "true",
        "超深嵌套": "[" * 2000 + "]" * 2000,
        "自引用式大对象": json.dumps({f"k{i}": i for i in range(50000)}),
        "ok 是字符串": '{"ok":"false"}',
        "count 是负数": '{"ok":true,"count":-5}',
        "count 是字符串": '{"ok":true,"count":"abc"}',
    }
    for label, raw in cases.items():
        try:
            code, out, err = run(["result", "--stdin", "--json"], timeout=60, stdin=raw)
        except subprocess.TimeoutExpired:
            bad(f"result {label}", "超时")
            continue
        if "Traceback (most recent call last)" in (out + err):
            last = [l for l in err.strip().splitlines() if l.strip()][-1:]
            bad(f"result {label}", f"Traceback：{last[0][:100] if last else '?'}")
            continue
        try:
            d = json.loads(out)
        except Exception:
            bad(f"result {label}", f"非 JSON：{out[:80]}")
            continue
        if "ok" not in d:
            bad(f"result {label}", "缺顶层 ok")
            continue
        ok(f"result {label}", f"ok={d['ok']} kind={d.get('kind')}")


def main() -> int:
    print(f"对抗性压力测试 · 临时目录 {TMP}\n")
    tests = [
        ("深度嵌套规则", t_deep_nested_rule),
        ("零分母路径", t_zero_denominator),
        ("极端路径名", t_extreme_paths),
        ("极端地址", t_extreme_addresses),
        ("CFG 长链性能", t_cfg_bomb),
        ("case 目录对抗", t_case_adversarial),
        ("require 对抗输入", t_require_adversarial),
        ("result 对抗输入", t_result_adversarial),
    ]
    for name, fn in tests:
        print(f"--- {name}")
        try:
            fn()
        except Exception as e:
            bad(name, f"测试自身异常 {type(e).__name__}: {e}")
        print()

    print("=" * 72)
    print(f"失败 {len(FAILS)} 项，提示 {len(NOTES)} 项")
    for f in FAILS:
        print(f"  ✗ {f}")
    print("=" * 72)
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
