# -*- coding: utf-8 -*-
"""快速验证 lib_rules 的 YAML 子集解析器。"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lib_rules as R

DOC = """
# 顶层注释
rule:
  meta:
    name: 创建进程          # 行尾注释
    namespace: host-interaction/process/create
    scope: function
    authors:
      - william
      - joakim
    att_ck:
      - Execution::Command and Scripting Interpreter [T1059]
    description: 创建新进程
    references:
      - https://example.com/x
  features:
    - or:
      - api: kernel32.CreateProcess
      - api: kernel32.WinExec
      - and:
        - number: 0x08000000
        - mnemonic: call
"""

fails = []
def ck(name, got, want):
    if got != want:
        fails.append("%s: got %r want %r" % (name, got, want))

d = R.yaml_load(DOC)
try:
    rule = R.Rule(d, "inline")
except Exception as e:
    print("解析规则失败:", type(e).__name__, e)
    sys.exit(1)

ck("name", rule.name, "创建进程")
ck("namespace", rule.namespace, "host-interaction/process/create")
ck("scope", rule.scope, "function")
ck("authors", rule.authors, ["william", "joakim"])
ck("att_ck", rule.att_ck, ["Execution::Command and Scripting Interpreter [T1059]"])
ck("refs", rule.references, ["https://example.com/x"])
ck("feat_type", type(rule.features).__name__, "list")

# 标量类型
d2 = R.yaml_load("""
a: 123
b: 0x10
c: -5
d: 3.5
e: true
f: false
g: null
h: "quoted # not comment"
i: plain string
j: 1_000
""")
ck("int", d2["a"], 123)
ck("hex", d2["b"], 16)
ck("neg", d2["c"], -5)
ck("float", d2["d"], 3.5)
ck("true", d2["e"], True)
ck("false", d2["f"], False)
ck("null", d2["g"], None)
ck("quoted", d2["h"], "quoted # not comment")
ck("plain", d2["i"], "plain string")
ck("underscore_int", d2["j"], 1000)

# 列表里放映射
d3 = R.yaml_load("""
items:
  - name: a
    val: 1
  - name: b
    val: 2
""")
ck("list_of_maps", d3["items"], [{"name": "a", "val": 1}, {"name": "b", "val": 2}])

# 不支持的语法必须报错，不能静默
for bad, why in [("a: &anchor b", "锚点"), ("a: |\n  x", "多行块"),
                 ("a: {x: 1}", "流式集合"), ("a: *ref", "别名")]:
    try:
        R.yaml_load(bad)
        fails.append("应报错但没报：%s" % why)
    except R.YamlError:
        pass

# 未知特征类型必须报错
try:
    R.Rule(R.yaml_load("rule:\n  meta:\n    name: x\n  features:\n    - bogus: 1\n"))
    fails.append("未知特征类型应报错")
except R.RuleError:
    pass

# 缺 name 必须报错
try:
    R.Rule(R.yaml_load("rule:\n  meta:\n    scope: file\n  features:\n    - os: windows\n"))
    fails.append("缺 name 应报错")
except R.RuleError:
    pass

# 坏 scope 必须报错
try:
    R.Rule(R.yaml_load("rule:\n  meta:\n    name: x\n    scope: nope\n  features:\n    - os: windows\n"))
    fails.append("坏 scope 应报错")
except R.RuleError:
    pass

if fails:
    print("FAIL")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("OK  全部 %d 项断言通过" % 24)
