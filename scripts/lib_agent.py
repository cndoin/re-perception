# -*- coding: utf-8 -*-
"""
lib_agent.py —— AI 调用协议层（工具选路、工作流编排、状态外置、错误分类）

【为什么需要这一层】

本工具箱有 21 个子命令。研究给出的结论很一致：

  * AWS Well-Architected（Agentic AI Lens, AGENTPERF06-BP01）：
    'LLM 在候选工具超过 10–15 个之后，选择准确率就开始明显下降'，
    推荐做法是两阶段选择——先用一个轻量检索把候选压到 5–10 个，再让模型选。
  * 实测规模曲线（2025 末多来源汇总）：约 50 个工具时主流前沿模型仍有 84–95%
    的选择准确率；200 个时降到 41–83%；740 个时接近 0。
    还有 "Lost in the Middle" 效应：列表中部（40%–60% 位置）的工具被正确选中的
    概率只有 22%–52%，而列表两端是 31%–32%（注意：这里是各来源的绝对值口径）。
  * MCP-Zero（arXiv:2506.01056）把这件事反过来做：不让运行时预注入工具，
    而是让模型主动声明'我需要一个能 X 的工具'，运行时再做语义检索。
    APIBank 上 token 减少 98% 且保持准确率。
  * AutoTool（AAAI 2026, arXiv:2511.14650）发现 'tool usage inertia'：
    工具调用序列高度可预测（ScienceWorld 里 go_to → look_around 占 88.7%）；
    一阶条件熵 2.52 bit、二阶 1.93 bit，都远低于 0 阶的 3.50 bit。
    据此建 Tool Inertia Graph 可减少最多 30% 的推理开销。

  对我们来说这三条的含义是明确的：**不该让 AI 每次都在 21 个工具里瞎选**。
  所以我们把选路这件事**下沉成确定性代码**：

    require  —— 意图 → Top-K 子命令（对标 x_amz_bedrock_agentcore_search / discover_tool）
    flow     —— 阶段化 DAG 编排（对标 Blazytko 的 orchestrator，含断点续跑）
    case     —— 结果落盘 + 摘要复用 + 过期检测（对标 persistent case directory）
    toolgraph—— 转移概率表 + 在线学习（对标 Tool Inertia Graph）

【本模块的设计约束】

  1. **零第三方依赖**。没有嵌入模型可用，所以'语义检索'必须用
     词表加权 + 结构化规则实现，不能调 API。这是硬约束（selftest 卡着）。
  2. **绝不静默降级**。检索没命中就给空列表 + 可读 reason，
     不允许'回退成全量列表'——那等于把问题又推回给 AI。
  3. **判据要可解释**。每个推荐必须能说清'为什么推它'（--explain），
     否则 AI 无法判断该不该信。

【一个贯穿本模块的区分】

  这套工具里有大量'没命中'其实是**正常结果**（比如未混淆的二进制就是没有
  栈字符串）。研究里反复出现同一个教训：Agent 最贵的浪费是
  **把'正常空结果'当成'失败'然后反复重试**。所以：
    * `classify_error()` 必须把 empty / no_hit 与 real_error 分开；
    * `hint` 字段明确写'不要重试'；
    * flow 里把'前置产出缺失'与'这一步失败'分开表达。
"""

from __future__ import annotations

import hashlib
import json
import os
import time

# ================================================================
# 一、工具目录（Tool Catalog）
# ================================================================
#
# 每个条目描述一个子命令的"用武之地"。字段说明：
#
#   name      子命令名
#   summary   一句话用途（给人看）
#   answers   它回答的问题（检索主要匹配这里 —— 因为用户/AI 说的是"问题"
#             而不是"命令名"）
#   keywords  额外检索词（中英混合，含口语说法）
#   args      位置参数（写进命令模板）
#   flags     常用可选项（写进命令模板的推荐组合）。元素两种写法都合法：
#               "--json"                  直接拼上去
#               ["--min", "6"]            选项 + 示例值，渲染成 `--min 6`
#             用「对」的写法是为了让命令模板带上**能直接跑**的示例值，
#             而不是留一个光秃秃的开关等使用者猜参数。
#   needs     前置条件，两类：
#               "path"          需要目标文件路径
#               "code"          需要有可反汇编的代码区
#               "prior:<cmd>"   需要先跑过某个命令
#   produces  产出的关键字段（供 result 摘要层与 flow 依赖判断用）
#   cost      相对开销：cheap / medium / heavy（供 flow 排并行度用）
#   stage     主要归属阶段：triage / understand / behavior / deep / deliver
#   formats   适用格式；None 表示全格式
#   risky     True 表示会写盘（必须显式指定输出路径）
#
# 【维护提醒】新增子命令必须同时：
#   1) 在 re.py 注册 add_parser；
#   2) 在本表加条目；
#   3) 跑 `selftest.py --only 调用协议` 里的目录一致性用例（会比对两者）。

CATALOG: list[dict] = [
    {
        "name": "doctor",
        'summary': '探测本机可用工具链与 AI 辅助层就绪度',
        "answers": [
            '本机有什么工具可以用', '环境里装了哪些逆向工具',
            'Ghidra 装了吗', '能不能用 IDA', '有没有装 Ollama',
        ],
        'keywords': ['环境', '工具链', '就绪', '安装', 'environment', 'toolchain',
                     "ghidra", "ida", "frida", "jadx", "radare", "ollama"],
        "args": [],
        "flags": [],
        "needs": [],
        "produces": ["tools", "env_probes", "ai_stack", "missing_count"],
        "cost": "cheap",
        "stage": "triage",
        "formats": None,
        "risky": False,
    },
    {
        "name": "identify",
        'summary': '识别文件类型与架构（含结构解析）',
        "answers": [
            '这个文件是什么', '这是什么格式', '它是什么架构', '是 32 位还是 64 位',
            '是不是恶意文件', '文件类型识别',
        ],
        'keywords': ['识别', '格式', '类型', '架构', '魔数', 'identify', 'format',
                     'arch', 'magic', '32位', '64位', 'arm', 'mips',
                     '是不是 pe', '是不是 elf', '什么文件'],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path"],
        "produces": ["format", "arch", "bits", "detail", "confidence"],
        "cost": "cheap",
        "stage": "triage",
        "formats": None,
        "risky": False,
    },
    {
        "name": "triage",
        'summary': '一站式初筛（识别+熵+字符串+IOC+加壳判断）',
        "answers": [
            '拿到一个未知文件从哪开始', '这文件是什么东西', '快速看看这个样本',
            '初步分析', '静态体检一下', '先跑个体检', '过一遍看看',
            '不动手先看看情况', '给我个整体印象',
        ],
        'keywords': ['初筛', '快速', '概览', '是什么', 'triage', 'overview',
                     '第一步', '起点', '不认识', '未知', '体检', '摸底',
                     '整体印象', '大致看看', '过一遍'],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path"],
        "produces": ["identify", "leads", "packer", "strings_sample", "hashes"],
        "cost": "medium",
        "stage": "triage",
        "formats": None,
        "risky": False,
    },
    {
        "name": "strings",
        'summary': '流式提取字符串（可按类别/正则过滤）',
        "answers": [
            '里面有什么字符串', '有没有 URL 或 IP', '找一下密钥',
            '提取线索', '有没有域名', '有没有路径泄露',
        ],
        'keywords': ['字符串', '线索', 'url', 'ip', '域名', '密钥', 'key',
                     'strings', 'ioc', '正则', '过滤', '密码', 'token'],
        "args": ["<目标>"],
        "flags": [["--min", "6"]],
        "needs": ["path"],
        "produces": ["items", "categories", "count", "truncated"],
        "cost": "medium",
        "stage": "triage",
        "formats": None,
        "risky": False,
    },
    {
        "name": "entropy",
        'summary': '整体熵 + 分块熵曲线（定位加密/压缩段）',
        "answers": [
            '有没有加密段', '是不是被压缩了', '哪里有高熵数据',
            '加壳了吗', '这是不是加壳的', '哪里有隐藏数据', '有没有壳',
            '这文件熵高不高', '熵是多少', '熵值多少', '看着像不像加壳',
            '文件被加了什么壳', '加了什么壳', '是什么壳', '壳是什么',
            '有没有被保护', '是不是被混淆了',
        ],
        'keywords': ['熵', '熵值', '文件熵', '高熵', 'entropy', '加密', '压缩',
                     '壳', 'packer', '加壳', '加了壳', '什么壳', '被加壳',
                     '隐藏', '随机', '包裹', '加密段', '压缩段', '保护壳'],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path"],
        "produces": ["overall", "windows", "high_entropy_regions"],
        "cost": "cheap",
        "stage": "triage",
        "formats": None,
        "risky": False,
    },
    {
        "name": "imports",
        'summary': '导入表 / 依赖库（行为地图）',
        "answers": [
            '它调用了哪些库函数', '它依赖什么库', '有没有可疑 API',
            '用了什么系统调用', '依赖了哪些 dll',
        ],
        'keywords': ['导入', '导入表', '依赖', 'api', 'dll', 'so', 'imports',
                     '系统调用', '库函数', '行为地图'],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path"],
        "produces": ["libraries", "functions", "total"],
        "cost": "cheap",
        "stage": "triage",
        "formats": ["pe", "elf", "macho"],
        "risky": False,
    },
    {
        "name": "info",
        'summary': '按格式深度解析（节表/段/头字段全展开）',
        "answers": [
            '看看详细结构', '节表长什么样', '深挖文件结构',
            '段信息', 'PE 头细节',
        ],
        'keywords': ['结构', '节表', '段', '深度', '详细信息', 'info',
                     'section', 'header', '头'],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path"],
        "produces": ["sections", "headers", "parse_ok"],
        "cost": "cheap",
        "stage": "understand",
        "formats": None,
        "risky": False,
    },
    {
        "name": "carve",
        'summary': '按魔数雕刻嵌入文件（提取内嵌 PE/ZIP 等）',
        "answers": [
            '里面有没有嵌套别的文件', '能不能把内嵌的提取出来',
            '有没有释放的文件', '提取载荷',
        ],
        'keywords': ['雕刻', '提取', '内嵌', '嵌套', '释放', 'carve', '载荷',
                     "payload", "embedded", "drop"],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path"],
        "produces": ["candidates", "count"],
        "cost": "medium",
        "stage": "understand",
        "formats": None,
        "risky": False,
    },
    {
        "name": "diff",
        'summary': '两文件字节级差分（定位改动区域）',
        "answers": [
            '两个版本改了什么', '更新了哪里', '这两个文件哪里不一样',
            '补丁改了哪些字节', '新旧版本对比', '改动了哪些地方',
        ],
        'keywords': ['差分', '对比', '比较', '差异', 'diff', '改了什么',
                     '更新', '补丁', '版本', '新旧', '两个文件', '两个版本'],
        "args": ["<文件A>", "<文件B>"],
        "flags": [],
        "needs": ["path"],
        "produces": ["ranges", "identical", "changed_bytes"],
        "cost": "medium",
        "stage": "understand",
        "formats": None,
        "risky": False,
    },
    {
        "name": "plan",
        'summary': '生成下一步分析计划（按格式与本机工具裁剪）',
        "answers": [
            '接下来该干什么', '下一步做什么', '给我一个分析计划',
        ],
        'keywords': ['计划', '下一步', '规划', 'plan', '怎么做', '流程', '步骤'],
        "args": ["<目标>"],
        "flags": [["--goal", "auto"]],
        "needs": ["path"],
        "produces": ["steps", "accel", "install_hints", "goal"],
        "cost": "cheap",
        "stage": "triage",
        "formats": None,
        "risky": False,
    },
    {
        "name": "report",
        'summary': '生成 Markdown 分析报告',
        'answers': ['出一份报告', '写个分析报告', '给我报告文件'],
        'keywords': ['报告', '交付', '文档', 'report', 'markdown', '总结'],
        "args": ["<目标>"],
        "flags": [["--out", "<报告路径>"]],
        "needs": ["path"],
        "produces": ["path", "sections", "bytes"],
        "cost": "medium",
        "stage": "deliver",
        "formats": None,
        "risky": True,
    },
    {
        "name": "magic",
        'summary': '魔数速查（十六进制 ↔ 名称）',
        'answers': ['这个魔数是什么', '某格式的魔数是什么', '查魔数'],
        'keywords': ['魔数', 'magic', '签名', '文件头', '魔术字'],
        "args": [],
        "flags": [["--hex", "<十六进制>"]],
        "needs": [],
        "produces": ["matches"],
        "cost": "cheap",
        "stage": "understand",
        "formats": None,
        "risky": False,
    },
    {
        "name": "disasm",
        'summary': '反汇编一段代码（x86/x64/ARM64/Thumb）',
        "answers": [
            '反汇编看看', '这段机器码是什么指令', '入口点是什么代码',
            '这段代码干了什么', '指令序列',
        ],
        'keywords': ['反汇编', '汇编', '指令', 'disasm', 'asm', '机器码',
                     'entry', '入口'],
        "args": ["<目标>"],
        "flags": [["--section", ".text"]],
        "needs": ["path", "code"],
        "produces": ["instructions", "count", "invalid_count", "truncated"],
        "cost": "medium",
        "stage": "deep",
        "formats": ["pe", "elf", "macho"],
        "risky": False,
    },
    {
        "name": "funcs",
        'summary': '函数识别 + 指纹 + XREF（把字节变成函数）',
        "answers": [
            '有哪些函数', '这个二进制有多少个函数', '函数列表',
            '函数识别', '入口函数在哪',
        ],
        'keywords': ['函数', '函数列表', 'funcs', 'function', '有多少函数',
                     '过程', '子程序'],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path", "code"],
        "produces": ["functions", "function_count", "partial", "truncated_note"],
        "cost": "heavy",
        "stage": "deep",
        "formats": ["pe", "elf", "macho"],
        "risky": False,
    },
    {
        "name": "cfg",
        'summary': '单个函数的控制流图',
        "answers": [
            '这个函数怎么走', '控制流图', '有没有分支循环',
            '这函数的逻辑结构',
        ],
        'keywords': ['控制流', 'cfg', '流程图', '基本块', '分支', '循环'],
        "args": ["<目标>", "<地址>"],
        "flags": [],
        "needs": ["path", "code", "prior:funcs"],
        "produces": ["blocks", "edges", "loops"],
        "cost": "cheap",
        "stage": "deep",
        "formats": ["pe", "elf", "macho"],
        "risky": False,
    },
    {
        "name": "xref",
        'summary': '交叉引用（谁调用了谁）',
        "answers": [
            '谁调用了这个函数', '哪里引用了这个地址', '这个函数被谁用',
            '调用关系',
        ],
        'keywords': ['交叉引用', 'xref', '调用关系', '谁调用', '引用', '被引用'],
        "args": ["<目标>"],
        "flags": [["--addr", "0x<地址>"]],
        "needs": ["path", "code"],
        "produces": ["refs", "callers", "count"],
        "cost": "medium",
        "stage": "deep",
        "formats": ["pe", "elf", "macho"],
        "risky": False,
    },
    {
        "name": "sim",
        'summary': '两份二进制的函数级差分比对',
        "answers": [
            '两个版本函数级差多少', '哪些函数变了', '把旧版名字移植过来',
            '两个二进制相似度',
        ],
        'keywords': ['函数比对', '相似度', 'sim', '版本比对', '移植名字',
                     'bindiff', '函数级差分'],
        "args": ["<文件A>", "<文件B>"],
        "flags": [],
        "needs": ["path", "code"],
        "produces": ["pairs", "matched", "threshold", "score"],
        "cost": "heavy",
        "stage": "understand",
        "formats": ["pe", "elf", "macho"],
        "risky": False,
    },
    {
        "name": "semantics",
        'summary': '函数级语义摘要（调了什么 API / 什么行为）',
        "answers": [
            '这个函数在干嘛', '加密逻辑在哪', '联网代码在哪',
            '反调试在哪', '各函数的行为画像', '行为分析',
            '这个函数是做什么的', '哪些函数值得看', '函数画像',
        ],
        # 「反调试在哪」是**定位**（在哪个函数里），归语义；
        # 「有没有反调试」是**能力判定**，归 capability。两者都收，
        # 但语义这边不收裸词 '反调试'，避免抢走判定类问题。
        'keywords': ['语义', '行为', '干嘛', '作用', 'semantics', '标签',
                     '画像', '加密在哪', '联网在哪', '反调试在哪',
                     '函数做什么', '哪些函数'],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path", "code"],
        "produces": ["functions", "tag_clusters", "tag_counts", "api_calls"],
        "cost": "heavy",
        "stage": "behavior",
        "formats": ["pe", "elf", "macho"],
        "risky": False,
    },
    {
        "name": "capability",
        'summary': '能力识别（规则库 → 行为结论 + ATT&CK）',
        "answers": [
            '这个样本具备哪些能力', '它是不是恶意的', '有没有持久化',
            '有没有横向移动', '对应哪些 ATT&CK', '行为结论',
            # 「这程序是干什么的」是**行为**问题，归能力识别，不归初筛。
            # 初筛回答"这是什么/从哪开始"，能力识别回答"它能干什么"。
            '这程序是干什么的', '这程序干什么的', '这个 exe 是干嘛的',
            '这软件能干什么', '它有什么功能', '里面有没有加密算法',
            '用的是不是 aes', '有没有反调试', '有没有反虚拟机',
            '有没有键盘记录', '是不是窃密', '有没有下载行为',
            '有没有网络通信', '有没有写注册表',
        ],
        'keywords': ['能力', 'capability', 'att&ck', 'attck', '结论',
                     '恶意', '持久化', '横向', 'c2', '行为判决',
                     '行为', '功能', '干什么', '能干什么',
                     '加密算法', '算法', 'aes', 'rc4', '反调试', '反虚拟机',
                     '反沙箱', '键盘记录', '窃密', '下载', '注册表',
                     '启动项', '计划任务'],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path"],
        "produces": ["hits", "attack", "warnings", "rule_count"],
        "cost": "heavy",
        "stage": "behavior",
        "formats": ["pe", "elf", "macho"],
        "risky": False,
    },
    {
        "name": "symbols",
        'summary': '符号恢复（C++/MSVC/Rust demangle + Go pclntab）',
        "answers": [
            '把函数名还原出来', '有没有符号表', 'demangle 一下',
            '这是不是 Go 写的', '函数名什么意思', '恢复符号',
        ],
        'keywords': ['符号', '符号表', 'demangle', '改名', '名字', 'symbols',
                     'go', 'pclntab', 'rust', 'c++', '修饰名'],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path"],
        "produces": ["symbols", "counts", "go", "stats", "warnings"],
        "cost": "cheap",
        "stage": "understand",
        "formats": None,
        "risky": False,
    },
    {
        "name": "obfstr",
        'summary': '混淆字符串恢复（栈字符串 + XOR 解密循环）',
        "answers": [
            '有没有隐藏的字符串', '字符串是不是被加密了', 'C2 地址藏在哪',
            '有没有用栈字符串', '有没有 xor 加密的串', '怎么绕过字符串混淆',
            '字符串被藏起来了怎么办',
        ],
        'keywords': ['混淆', '加密串', '栈字符串', 'xor', 'obfstr', '隐藏字符串',
                     'floss', '解密串', '字符串混淆', '藏起来'],
        "args": ["<目标>"],
        "flags": [],
        "needs": ["path", "code"],
        "produces": ["stack_strings", "xor_strings", "loops", "empty", "reason",
                     "xor_note"],
        "cost": "medium",
        "stage": "understand",
        "formats": ["pe", "elf", "macho"],
        "risky": False,
    },
]

CATALOG_BY_NAME: dict[str, dict] = {t["name"]: t for t in CATALOG}


# 【目录结构不变量 · 启动期校验】
#
# 为什么需要：CATALOG 是**手写的模块级字面量**，而下游有几十处 `e["field"]`
# 直接取键（检索打分、flow 依赖、命令模板、摘要层）。少写一个字段不会在
# import 时报错，只会在某个特定意图被检索到的那一刻抛 KeyError —— 也就是
# "平时看着好好的，用户一句话就崩"。这类"潜伏到运行期才炸"的缺陷比
# 语法错误危险得多（语法错误至少 import 就拦住了）。
#
# 代价是 import 时多几毫秒；收益是整类 KeyError 被消灭在启动之前。
# 校验失败必须**炸得很响**：宁可 import 失败让人立刻看见，也不要
# 带着残缺目录静默上线。
_CATALOG_REQUIRED = {
    "name": str,
    "summary": str,
    "answers": list,
    "keywords": list,
    "args": list,
    "flags": list,
    "needs": list,
    "produces": list,
    "cost": str,
    "stage": str,
}
# 只做"取值必须合法"的枚举校验，避免下游 _COST_PENALTY / _STAGE_WORDS 取不到键。
_CATALOG_COST_VALUES = ("cheap", "medium", "heavy")
_CATALOG_STAGE_VALUES = ("triage", "understand", "behavior", "deep", "deliver")


def _validate_catalog(catalog: list) -> None:
    """校验 CATALOG 结构。任何问题都聚合成一条可读错误抛出。"""
    problems: list[str] = []
    seen: dict[str, int] = {}
    for i, t in enumerate(catalog):
        if not isinstance(t, dict):
            problems.append("第 %d 项不是 dict（是 %s）" % (i, type(t).__name__))
            continue
        nm = t.get("name")
        if not isinstance(nm, str) or not nm:
            problems.append("第 %d 项 name 缺失或不是非空字符串：%r" % (i, nm))
            nm = "<第%d项>" % i
        if nm in seen:
            problems.append("重名条目 %r（第 %d 项与第 %d 项）" % (nm, seen[nm], i))
        else:
            seen[nm] = i
        for field, typ in _CATALOG_REQUIRED.items():
            if field not in t:
                problems.append("%s：缺字段 %r" % (nm, field))
                continue
            if not isinstance(t[field], typ):
                problems.append("%s：字段 %r 类型应为 %s，实际 %s"
                                % (nm, field, typ.__name__, type(t[field]).__name__))
        # 元素类型也要卡：answers/keywords/produces 全是字符串列表，
        # 混进一个 int 会让检索期 _hit() 里 `.lower()` 直接 AttributeError。
        for field in ("answers", "keywords", "produces", "args", "needs"):
            v = t.get(field)
            if isinstance(v, list):
                bad = [x for x in v if not isinstance(x, str)]
                if bad:
                    problems.append("%s：字段 %r 含非字符串元素 %r" % (nm, field, bad[:3]))
        # flags 特殊：允许 "--json" 与 ["--min", "6"]（选项 + 示例值）混用。
        # 但**只允许这两种**——其它形状 build_command 会 str() 出一个
        # 看着像命令、实际跑不通的字符串（例如 [["--a","1"],["--b","2"]] 会被
        # 拼成 "--a 1 --b 2" 看似正常，而 ["--x", ["--y","2"]] 会拼出
        # "--x ['--y', '2']"，这种"装作成功"比直接报错更坏）。
        fv = t.get("flags")
        if isinstance(fv, list):
            for j, one in enumerate(fv):
                if isinstance(one, str):
                    continue
                if (isinstance(one, (list, tuple)) and len(one) == 2
                        and all(isinstance(x, str) for x in one)):
                    continue
                problems.append(
                    "%s：flags[%d]=%r 形状非法（只允许字符串，或两个字符串组成的"
                    "[选项, 示例值]）" % (nm, j, one))
        c = t.get("cost")
        if isinstance(c, str) and c not in _CATALOG_COST_VALUES:
            problems.append("%s：cost=%r 不在 %r 内" % (nm, c, _CATALOG_COST_VALUES))
        st = t.get("stage")
        if isinstance(st, str) and st not in _CATALOG_STAGE_VALUES:
            problems.append("%s：stage=%r 不在 %r 内" % (nm, st, _CATALOG_STAGE_VALUES))
        fmts = t.get("formats", None)
        if fmts is not None and not isinstance(fmts, list):
            problems.append("%s：formats 应为 list 或 None，实际 %s"
                            % (nm, type(fmts).__name__))

    if problems:
        raise RuntimeError(
            "工具目录 CATALOG 结构不合法（共 %d 处）—— 这会表现为运行期随机 KeyError，"
            "必须在启动时拦住：\n  - %s" % (len(problems), "\n  - ".join(problems)))


_validate_catalog(CATALOG)

# 校验通过后再建索引，保证 CATALOG_BY_NAME 一定覆盖全部条目。
assert len(CATALOG_BY_NAME) == len(CATALOG), (
    "CATALOG_BY_NAME 与 CATALOG 条目数不一致：%d vs %d"
    % (len(CATALOG_BY_NAME), len(CATALOG)))


# ================================================================
# 二、意图检索（对标 semantic tool discovery）
# ================================================================
#
# 没有嵌入模型可用（零依赖），所以用"加权词表命中"做检索。
# 这不是退而求其次 —— 对 21 个工具的规模，确定性规则比向量检索更可控、
# 可解释、零冷启动（AutoTool 论文自己承认冷启动是图方法的弱点）。
#
# 打分维度（权重是排过序的，改之前先看 selftest 的检索精度用例）：
#
#   answers 命中   +3.0 / 词    ← 最高权重："用户在描述问题"
#   keywords 命中  +2.0 / 词
#   name 直接出现  +5.0         ← 用户直接点名命令
#   summary 命中   +1.0 / 词
#   阶段匹配       +1.5         ← 用户说了"先看/深入/结论"这类词
#   格式匹配       +2.0 / 命中格式
#   格式冲突       -3.0         ← 明确不适用就别推
#   成本惩罚       cheap 0 / medium -0.2 / heavy -0.5

_STAGE_WORDS = {
    'triage': ['初筛', '快速', '概览', '先说', '第一', '起手', '先看', '是什么',
               "triage", "overview"],
    'understand': ['结构', '理解', '看清', '梳理', '解析', 'understand', '符号',
                   '字符串', '混淆'],
    'behavior': ['行为', '干嘛', '做什么', '能力', '结论', '判定', 'behavior',
                 '恶意', 'att&ck'],
    'deep': ['深入', '细节', '具体', '反汇编', '指令', '函数级', '深挖', 'code',
             '定位'],
    'deliver': ['报告', '交付', '输出', '写成', '文档', 'deliver', 'report'],
}

_COST_PENALTY = {"cheap": 0.0, "medium": -0.2, "heavy": -0.5}

# 格式别名 → catalog 里用的规范名
_FORMAT_ALIASES = {
    "pe": "pe", "exe": "pe", "dll": "pe", "sys": "pe", "windows": "pe",
    "elf": "elf", "so": "elf", "linux": "elf",
    "macho": "macho", "mach-o": "macho", "dylib": "macho", "macos": "macho",
    "ios": "macho",
}

# 需要代码区才能跑的工具：若目标明显是数据/文档，就别推
_CODE_ONLY_NEEDS = ("code",)


def normalize_format(fmt: str | None) -> str | None:
    '''把用户/AI 说的格式归一化成 catalog 用的规范名；认不出就返回 None。'''
    if not fmt:
        return None
    return _FORMAT_ALIASES.get(str(fmt).strip().lower())


def _is_cjk(ch: str) -> bool:
    """判断是否中日韩表意文字（这些语言没有词间空格，需要特殊切分）。"""
    o = ord(ch)
    return (
        0x2E80 <= o <= 0x9FFF or      # 部首扩展 → CJK 统一表意文字
        0x3400 <= o <= 0x4DBF or      # 扩展 A
        0xF900 <= o <= 0xFAFF or      # 兼容表意文字
        0x3040 <= o <= 0x30FF or      # 日文假名
        0xAC00 <= o <= 0xD7AF         # 韩文音节
    )


def _tokens(text: str) -> list[str]:
    """
    把查询切成可比较的片段（中英混合）。

    【为什么不能简单按 isalnum() 切】`str.isalnum()` 对中文返回 True，
    所以整个中文句子会被当成**一个词元** —— 而我们的关键词都是 2-4 字的
    短词（"加壳"、"加密"、"反调试"）。一个 9 字的长词元做子串匹配时，
    永远匹配不上 2 字的关键词（方向搞反了）。

    这是实测踩到的：`这文件是不是加壳了` 检索结果为空，
    因为整句成了单个词元。

    【做法】
      * 拉丁字母/数字 → 按词切（保持 `xor`、`pclntab`、`att&ck` 完整）；
      * CJK → 生成 **2~4 字 n-gram**（"这文件是不是加壳了" → "这文"、"文件"…
        "加壳"、"壳了"…），这样短关键词就能命中；
      * 同时保留整句（低位权重场景用，比如意图里直接出现命令名）。

    返回去重后的词元表，长词元在前（长的更具体，匹配上更有信息量）。
    """
    out: list[str] = []
    latin: list[str] = []
    cjk_run: list[str] = []

    def flush_latin():
        if latin:
            out.append("".join(latin))
            latin.clear()

    def flush_cjk():
        if cjk_run:
            n = len(cjk_run)
            for size in (4, 3, 2):
                for i in range(n - size + 1):
                    out.append("".join(cjk_run[i:i + size]))
            # 整段也留下（短段时它本身就是词）
            if n <= 4:
                out.append("".join(cjk_run))
            cjk_run.clear()

    for ch in text:
        if _is_cjk(ch):
            flush_latin()
            cjk_run.append(ch)
        elif ch.isalnum() or ch in "._-+":
            flush_cjk()
            latin.append(ch)
        else:
            flush_latin()
            flush_cjk()
    flush_latin()
    flush_cjk()

    # 去重但保持顺序，然后按长度降序（长词元优先级更高）
    seen: set[str] = set()
    uniq: list[str] = []
    for tk in out:
        if tk and tk not in seen:
            seen.add(tk)
            uniq.append(tk)
    uniq.sort(key=lambda t: (-len(t), t))
    return uniq


# ---------------------------------------------------------------- 吞异常登记
#
# 本模块有几处"失败可以容忍"的写路径（原子写的临时文件清理、流水追加、
# 时间戳解析）。容忍 ≠ 无声：全部走 _note_swallowed 登记，
# 由 SWALLOWED 暴露出去，方便排查"结果莫名不对但没人报错"这类最难查的故障。
SWALLOWED: list[dict] = []
_SWALLOW_CAP = 50


def _note_swallowed(where: str, exc: BaseException) -> None:
    '''登记一处被吞掉的异常。不抛错、不打屏，只记账。'''
    if len(SWALLOWED) < _SWALLOW_CAP:
        SWALLOWED.append({
            "where": where,
            "type": type(exc).__name__,
            "msg": str(exc)[:200],
        })


def swallowed_report() -> dict:
    '''给 result/case 用的吞异常回执，让"没报错"和"没出问题"能区分开。'''
    return {"count": len(SWALLOWED), "items": list(SWALLOWED)}


# 泛词元：在本领域里到处都是，命中它们几乎不携带区分度。
# 这些词**不是**不能用，而是命中时给的权重必须压低，
# 否则「函数」一词会把 funcs/sim/cfg/xref/semantics 全部抬起来，
# 把真正具体的那一条（比如 symbols）淹掉。
#
# 【维护提醒】加词前先想：这个词能不能区分工具？不能就别加进关键词表，
# 或者加进这里降权。
_GENERIC_TOKENS = {
    "函数", "文件", "代码", "程序", "这个", "那个", "是不", "什么", "怎么",
    "一下", "里面", "有没", "没有", "可以", "就是", "我要", "帮我", "看看",
    "分析", "逆向", "东西", "里面", "在哪", "哪里", "多少", "几个",
}


def _hit(needle: str, hay: str) -> bool:
    """
    双向包含判定：任一方向包含就算命中。

    【为什么必须双向】
      * 查询词元可能比关键词**长**：n-gram 会产出「是不是加壳了」，
        而关键词是「加壳」——需要 `keyword in token`；
      * 查询词元也可能比关键词**短**：用户只打了「壳」，关键词是「加壳」——
        需要 `token in keyword`。
    单向匹配会漏掉其中一半，实测就是这样漏掉「加壳」的。

    小写化是因为 `ATT&CK` / `Ghidra` / `--json` 的大小写写法太不一致；
    中文无大小写，不受影响。
    """
    a, b = needle.lower(), hay.lower()
    return a in b or b in a


def _match_weight(tk: str, kw: str) -> float:
    """
    一次命中的权重，随匹配长度增长。

    【为什么需要这个】中文 n-gram 会产出大量短且泛的词元
    （「函数」、「是不」、「文件」）。如果一次 2 字命中与一次 5 字命中
    同权，「把函数名还原出来」就会因为命中「函数」而把 `funcs` 排到
    `symbols` 前面 —— 而用户要的明明是**名字**。

    同时，**泛词元要降权**：像「函数」「文件」「代码」这类在领域里
    到处都是的词，命中它们几乎不携带信息（capa 那条教训的检索版本：
    "函数粒度上用公用助记符做合取等于没有约束"）。

    做法：
      weight = len_factor * generic_penalty
        len_factor     = min(2.5, 1 + 0.35*(L-2))
        generic_penalty= 0.35 若 tk 在 _GENERIC_TOKENS 里，否则 1.0
    """
    if tk in _GENERIC_TOKENS:
        return 0.35
    L = min(len(tk), len(kw))
    if L < 2:
        return 0.0
    return min(2.5, 1.0 + 0.35 * (L - 2))


def _score_entry(entry: dict, q_tokens: list[str], q_lower: str,
                 fmt: str | None, stages: set[str]) -> tuple[float, list[str]]:
    '''给单个工具条目打分，同时收集可读理由。'''
    score = 0.0
    why: list[str] = []

    # 0) 整句短语命中：关键词**原样连续**出现在意图里。
    #
    # 【为什么这条要单独给高权】n-gram 会把「加壳」切出来，
    # 但也会切出「壳了」「是加壳」这类噪声。判断"关键词是不是原样
    # 出现在原句里"是**无噪声**的强信号 —— 用户真的说了这个词，
    # 而不是我们切分算法凑出来的。
    #
    # 权重 4.0 高于单次 answers 命中（3.0）：短语级证据比词元级更可靠。
    phrase_hits: list[str] = []
    for kv in entry["answers"] + entry["keywords"]:
        if len(kv) >= 2 and _hit(kv, q_lower) and kv not in phrase_hits:
            phrase_hits.append(kv)
    if phrase_hits:
        score += 4.0 * min(3, len(phrase_hits))
        why.append('原句直接提到：' + '、'.join(phrase_hits[:4]))

    # 1) 用户直接点名了命令
    if _hit(entry["name"], q_lower):
        score += 5.0
        why.append(f"点名了 {entry['name']}")

    # 2) answers 命中（最高权重 —— 这是"问题描述"层）
    #
    # 【只取每个 answer 的最高权重匹配】同一个 answer 被多个 n-gram 命中
    # 只算一次（否则长句会被反复加分，把一个泛答案灌成高分）。
    ans_hits: list[tuple[str, float]] = []
    for kv in entry["answers"]:
        best_w = 0.0
        for tk in q_tokens:
            if len(tk) < 2:
                continue
            if _hit(tk, kv):
                best_w = max(best_w, _match_weight(tk, kv))
        if best_w > 0:
            ans_hits.append((kv, best_w))
    if ans_hits:
        ans_hits.sort(key=lambda x: -x[1])
        score += 3.0 * sum(w for _, w in ans_hits)
        why.append('问到：' + '、'.join(kv for kv, _ in ans_hits[:3]))

    # 3) keywords 命中（同样按最长匹配计权）
    kw_hits: list[tuple[str, float]] = []
    for k in entry["keywords"]:
        best_w = 0.0
        for tk in q_tokens:
            if len(tk) < 2:
                continue
            if _hit(tk, k):
                best_w = max(best_w, _match_weight(tk, k))
        if best_w > 0:
            kw_hits.append((k, best_w))
    if kw_hits:
        kw_hits.sort(key=lambda x: -x[1])
        score += 2.0 * sum(w for _, w in kw_hits)
        why.append('关键词：' + '、'.join(k for k, _ in kw_hits[:4]))

    # 4) summary 命中
    for tk in q_tokens:
        if len(tk) >= 3 and _hit(tk, entry["summary"]):
            score += 1.0
            why.append('用途匹配')
            break

    # 5) 阶段匹配
    if stages and entry["stage"] in stages:
        score += 1.5
        why.append(f"阶段={entry['stage']}")

    # 6) 格式适用性
    fmts = entry.get("formats")
    if fmt and fmts:
        if fmt in fmts:
            score += 2.0
            why.append(f'适用 {fmt}')
        else:
            score -= 3.0
            why.append(f'不适用 {fmt}')
    elif fmt and not fmts:
        why.append('全格式适用')

    # 7) 成本惩罚（轻微 —— 只用来在同分时排序，不该压掉相关性）
    score += _COST_PENALTY.get(entry["cost"], 0.0)

    return score, why


def recommend(intent: str, fmt: str | None = None, top_k: int = 6,
              stage: str | None = None, min_score: float = 1.0,
              explain: bool = False) -> dict:
    """
    意图 → 推荐子命令。

    【为什么 Top-K 默认是 6】研究给出的可行区间是 5–10：
    低于 5 容易漏，高于 10 就开始出现'列表中部工具选不中'的问题。
    6 是我们 21 个工具的约 1/3，既能覆盖常见组合又不至于让 AI 分心。

    【为什么 min_score 是 1.0 而不是 0】宁可返回空列表也不要返回
    '勉强相关'的结果 —— 后者会让 AI 以为检索成功、然后在无关命令上浪费调用。
    返回空时必须给 reason，让 AI 知道该改用关键词重试还是直接看全量目录。

    返回：
      {
        ok: bool,
        query: str,
        recommendations: [ {name, score, why, summary, command, ...} ],
        count: int,
        reason: str | None,      # 无结果时说明为什么
        hint: str,
      }
    """
    intent = (intent or "").strip()
    res: dict = {
        "ok": True,
        "query": intent,
        "format": normalize_format(fmt),
        "stage": stage,
        "top_k": top_k,
        "recommendations": [],
        "count": 0,
        "reason": None,
        "hint": None,
    }

    if not intent:
        res["ok"] = False
        res['reason'] = '意图为空。请用一句自然语言描述你要解决的问题。'
        res['hint'] = ('例：`require \'这文件是不是加壳了\'`、'
                       '`require \'哪个函数在加密\'`、`require \'里面有没有 C2 地址\'`')
        return res

    q_lower = intent.lower()
    q_tokens = _tokens(intent)
    fmt_norm = res["format"]

    stages: set[str] = set()
    if stage:
        if stage not in _STAGE_WORDS:
            res["ok"] = False
            res['reason'] = (f"未知阶段 {stage!r}。可用："
                             + ", ".join(sorted(_STAGE_WORDS)))
            res['hint'] = '阶段仅用于加权，去掉 --stage 也能检索。'
            return res
        stages.add(stage)
    else:
        # 从意图里自动推断阶段
        for st, words in _STAGE_WORDS.items():
            if any(_hit(w, q_lower) for w in words):
                stages.add(st)

    scored: list[tuple[float, dict, list[str]]] = []
    for entry in CATALOG:
        s, why = _score_entry(entry, q_tokens, q_lower, fmt_norm, stages)
        if s >= min_score:
            scored.append((s, entry, why))

    # 排序：分数降序；同分时便宜的先来（先跑低成本高信息量的）
    scored.sort(key=lambda x: (-x[0], _COST_PENALTY.get(x[1]["cost"], 0.0),
                               x[1]["name"]))

    recs = []
    for s, entry, why in scored[:max(1, top_k)]:
        item = {
            "name": entry["name"],
            "score": round(s, 2),
            "summary": entry["summary"],
            "command": build_command(entry),
            "needs": entry["needs"],
            "produces": entry["produces"],
            "cost": entry["cost"],
            "stage": entry["stage"],
        }
        if explain:
            item["why"] = why
        recs.append(item)

    res["recommendations"] = recs
    res["count"] = len(recs)

    if not recs:
        res['reason'] = (f"没有子命令匹配意图 {intent!r}"
                         + (f'（格式 {fmt_norm}）' if fmt_norm else '') + '。')
        res['hint'] = ('换更具体的说法（描述要解决什么问题，而不是用什么命令），'
                       '或先跑 `flow` 看完整流程，或 `require --list` 看全部工具。')
    else:
        res['hint'] = ('按顺序执行；同一批可并行的见 `flow`。'
                       '结果建议存进 case 目录避免重复调用。')

    return res


def build_command(entry: dict, target: str = "<目标>") -> str:
    '''给一个目录条目生成可执行命令模板。'''
    parts = ["re.py", entry["name"]]
    for a in entry.get("args", []):
        parts.append(a.replace("<目标>", target))
    for f in entry.get("flags", []):
        if isinstance(f, (list, tuple)) and len(f) == 2:
            parts.append(f"{f[0]} {f[1]}")
        else:
            parts.append(str(f))
    parts.append("--json")
    return " ".join(parts)


def list_catalog(top_k: int = 0, stage: str | None = None) -> dict:
    '''列出全部工具（或某阶段的工具）。用于 AI 需要看全貌时。'''
    entries = CATALOG
    if stage:
        if stage not in _STAGE_WORDS:
            return {
                "ok": False,
                'error': f'未知阶段 {stage!r}',
                'hint': '可用：' + ', '.join(sorted(_STAGE_WORDS)),
                "tools": [],
                "count": 0,
            }
        entries = [e for e in entries if e["stage"] == stage]

    tools = [{
        "name": e["name"],
        "summary": e["summary"],
        "stage": e["stage"],
        "cost": e["cost"],
        "command": build_command(e),
        "needs": e["needs"],
        "produces": e["produces"],
        "formats": e["formats"],
        "risky": e["risky"],
    } for e in entries]
    if top_k:
        tools = tools[:top_k]

    out = {
        "ok": True,
        "stage": stage,
        "count": len(tools),
        "total_catalog": len(CATALOG),
        "tools": tools,
    }
    return out


# ================================================================
# 三、错误分类（防止 AI 无效重试）
# ================================================================
#
# 这是本模块最实际的价值之一。研究里反复出现的教训：
# "Agent 最有破坏性的行为不是失败，而是**把正常结果当成失败然后反复重试**"。
#
# 我们把每次调用结果归成 5 类，每类给出明确处置：
#
#   usage_error   用法错      → 改参数/参数名，不要重试同一命令
#   target_error  目标不可读  → 换文件或检查路径，重试无用
#   empty_result  正常空结果  → **不要重试**，这在语义上就是"没有"
#   partial       结果被截断  → 可以调大上限重跑一次，但要知道成本
#   engine_error  引擎出错    → 记录并上报，这才是真 bug
#
# 关键设计：**空结果不是错误**。`ok: true` + 空列表 + 有 reason，
# 与 `ok: false` 是两件完全不同的事。历史上本项目就吃过"把失败上报为成功"
# 的亏，这里反过来也要防"把正常当失败"。

KIND_USAGE = "usage_error"
KIND_TARGET = "target_error"
KIND_EMPTY = "empty_result"
KIND_PARTIAL = "partial"
KIND_ENGINE = "engine_error"
KIND_OK = "ok"

# 每类的标准处置建议（AI 直接读这个字段决定下一步）
_HANDLING = {
    KIND_OK: ('可以继续下一步。', False),
    KIND_USAGE: ('修正参数后重试；**不要用同样的参数重复调用**。', False),
    KIND_TARGET: ('目标本身有问题。换文件或修正路径；重试同一目标无用。', False),
    KIND_EMPTY: ('这是**正常结果**，代表「没有」而不是「失败」。'
                 '**不要重试**，也不要把「空」解读成「确认不存在」。', False),
    KIND_PARTIAL: ('结果被上限截断。若确实需要完整结果，调大对应上限重跑一次；'
                   '否则请在结论里注明「结果被截断/是采样」。', True),
    KIND_ENGINE: ('这属于工具箱自身缺陷。**请记录复现命令并上报**，'
                  '不要靠反复重试绕过。', False),
}

# 退出码 → 类别（与 re.py 的 EXIT_* 约定一致）
_EXIT_KIND = {
    0: KIND_OK,
    2: KIND_USAGE,
    3: KIND_TARGET,
    4: KIND_ENGINE,
}

# 空结果信号：这些字段出现即说明"这一步正常但没东西"
_EMPTY_KEYS = (
    "empty",              # obfstr / symbols 明确置位
    "no_hit",             # 规则引擎
)

# 截断信号
_TRUNC_KEYS = (
    "truncated",          # 多数子命令
    "timed_out",          # 预算耗尽
    "sampled",
    "partial",            # funcs
)


def classify_error(data, exit_code: int = 0, stderr: str = "") -> dict:
    """
    把一次调用的结果归类。

    参数：
      data       解析后的 JSON（可能是 None，表示没解析出来）
      exit_code  进程退出码
      stderr     进程 stderr（用于 usage_error 的细节）

    返回：
      {kind, handling, retryable, reason, evidence, next_action, swallowed}
    """
    _r = _classify_error_inner(data, exit_code, stderr)
    # 挂上吞异常回执：让 AI 知道"这次结果里有没有被悄悄咽掉的问题"。
    # 这是本项目最在意的一类故障——"没报错"不等于"没出问题"。
    sw = swallowed_report()
    if sw["count"]:
        _r["swallowed"] = sw
        ev = _r.setdefault("evidence", {})
        ev["swallowed_count"] = sw["count"]
    return _r


def _classify_error_inner(data, exit_code: int = 0, stderr: str = "") -> dict:
    d = data if isinstance(data, dict) else {}

    # --- 优先看进程级失败 ---
    if exit_code != 0:
        kind = _EXIT_KIND.get(exit_code, KIND_ENGINE)
        # 退出码 2 有可能是 argparse 的用法错误（stderr 有 usage 字样）
        err = d.get("error") or ""
        if not err and stderr:
            err = stderr.strip().splitlines()[0] if stderr.strip() else ""
        handling, retryable = _HANDLING.get(kind, _HANDLING[KIND_ENGINE])
        return {
            "kind": kind,
            "handling": handling,
            "retryable": retryable,
            'reason': err or f'退出码 {exit_code}',
            "evidence": {"exit_code": exit_code, "json_ok": d.get("ok")},
            "next_action": _next_action_for(kind),
        }

    # --- 进程成功，但 JSON 明确说失败 ---
    if d.get("ok") is False:
        return {
            "kind": KIND_ENGINE,
            "handling": _HANDLING[KIND_ENGINE][0],
            "retryable": False,
            "reason": d.get("error") or d.get("reason") or "JSON 报告 ok=false",
            "evidence": {"exit_code": 0, "json_ok": False},
            "next_action": _next_action_for(KIND_ENGINE),
        }

    # --- 成功：区分"截断" / "正常空" / "有内容" ---
    trunc = [k for k in _TRUNC_KEYS if d.get(k) is True]
    if trunc:
        return {
            "kind": KIND_PARTIAL,
            "handling": _HANDLING[KIND_PARTIAL][0],
            "retryable": True,
            'reason': '结果被上限截断：' + ', '.join(trunc),
            "evidence": {"truncated_flags": trunc,
                         "note": d.get("truncated_note")},
            "next_action": _next_action_for(KIND_PARTIAL),
        }

    if _is_empty(d):
        reason = d.get('reason') or d.get('xor_note') or '结果为空集合'
        return {
            "kind": KIND_EMPTY,
            "handling": _HANDLING[KIND_EMPTY][0],
            "retryable": False,
            "reason": reason,
            "evidence": {"empty_flags": [k for k in _EMPTY_KEYS if d.get(k)],
                         "counts": _countish(d)},
            "next_action": _next_action_for(KIND_EMPTY),
        }

    return {
        "kind": KIND_OK,
        "handling": _HANDLING[KIND_OK][0],
        "retryable": False,
        "reason": None,
        "evidence": {"counts": _countish(d)},
        "next_action": _next_action_for(KIND_OK),
    }


def _next_action_for(kind: str) -> str:
    return {
        KIND_OK: "continue",
        KIND_USAGE: "fix_args",
        KIND_TARGET: "change_target",
        KIND_EMPTY: "continue_no_retry",
        KIND_PARTIAL: "raise_limit_or_note",
        KIND_ENGINE: "report_bug",
    }.get(kind, "continue")


def _countish(d: dict) -> dict:
    '''抽取各子命令里可能表示'有几条'的计数字段（用于证据）。'''
    out = {}
    for k in ("count", "counts", "total", "function_count", "hit_count",
              "match_count", "rule_count"):
        v = d.get(k)
        if isinstance(v, (int, float, str)) or isinstance(v, dict):
            out[k] = v
    for k in ("items", "functions", "hits", "symbols", "instructions",
              "candidates", "ranges", "refs", "pairs", "stack_strings",
              "xor_strings", "recommendations", "steps"):
        v = d.get(k)
        if isinstance(v, list):
            out[k + "_len"] = len(v)
    return out


def _is_empty(d: dict) -> bool:
    """
    判断'成功但没东西'。

    【为什么要这么谨慎】这个判定如果做错，会直接导致 AI 浪费调用：
      * 假阳性（把有内容判成空）→ AI 以为没东西，提前结束，漏结论；
      * 假阴性（把空判成有内容）→ AI 以为有东西，去读字段，读到空。
    所以只在**明确信号**下判空：显式的 empty/no_hit 标志，
    或所有已知列表字段长度都为 0 且总数为 0。
    """
    if any(d.get(k) for k in _EMPTY_KEYS):
        return True

    lists = ("items", "functions", "hits", "symbols", "instructions",
             "candidates", "ranges", "refs", "pairs", "stack_strings",
             "xor_strings", "recommendations", "steps", "matches")
    seen_any = False
    total = 0
    for k in lists:
        v = d.get(k)
        if isinstance(v, list):
            seen_any = True
            total += len(v)
    if seen_any and total == 0:
        # 还要确认没有别的"有内容"标志
        if d.get("count") in (0, None) and not d.get("go"):
            return True
    if not seen_any and d.get("count") == 0:
        return True
    return False


# ================================================================
# 四、结果摘要（对标"按信息需求设计返回"）
# ================================================================
#
# AWS 那条 best practice 说得直接：
#   "Design for the agent's information needs, not for technical completeness.
#    A tool that returns every field of a data model is not more useful —
#    it is noisier."
#
# 我们的子命令 JSON 是给人看全貌的，字段很多。AI 做决策其实只需要一小撮。
# `summarize()` 按子命令给出"决策必需的字段子集"。

# 每个子命令的"AI 决策必需字段"。顺序即建议阅读顺序。
SUMMARY_FIELDS: dict[str, list[str]] = {
    "doctor": ["tools_available", "missing_count", "ai_stack", "env_probes", "notes"],
    "identify": ["format", "label", "arch", "bits", "confidence", "size",
                 "detail.packer_signals", "detail.sections", "notes"],
    "triage": ["identify.format", "identify.arch", "identify.bits",
               "packer", "leads", "hashes", "notes"],
    "strings": ["count", "categories", "truncated", "items"],
    "entropy": ["overall", "high_entropy_regions", "windows_len"],
    "imports": ["total", "libraries", "functions"],
    "info": ["format", "sections", "parse_ok", "errors"],
    "carve": ["count", "candidates"],
    "diff": ["identical", "changed_bytes", "ranges", "ranges_len"],
    "plan": ["goal", "accel", "steps", "install_hints"],
    "report": ["path", "bytes", "sections"],
    "magic": ["matches", "count"],
    "disasm": ["count", "invalid_count", "truncated", "instructions"],
    "funcs": ["function_count", "partial", "truncated_note", "functions"],
    "cfg": ["blocks", "edges", "loops", "start"],
    "xref": ["count", "refs", "callers"],
    "sim": ["threshold", "matched", "pairs", "pairs_len"],
    "semantics": ["tag_counts", "tag_clusters", "functions", "api_calls"],
    "capability": ["rule_count", "hits", "attack", "warnings"],
    "symbols": ["counts", "go", "stats", "warnings", "symbols"],
    "obfstr": ["stack_strings", "xor_strings", "loops", "empty", "reason",
               "xor_note", "warnings"],
    "require": ["count", "recommendations", "reason", "hint"],
    "flow": ["stage", "next", "next_batch", "done_count", "pending_count"],
    "case": ["case_dir", "target", "artifacts", "missing", "stale"],
    "result": ["kind", "summary", "fields", "reason"],
    "toolgraph": ["current", "next", "candidates", "learned_edges"],
}

# 列表字段默认最多保留多少条（AI 看前几条就够判断"有没有/大概什么"
# 更全的要去读原始 JSON 或 case 里落盘的文件）
_LIST_CAP = 5


def _dig(d: dict, path: str):
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def summarize(cmd: str, data, list_cap: int = _LIST_CAP) -> dict:
    """
    按子命令抽取 AI 决策必需字段。

    【为什么不直接截断原 JSON】截断是随机的（取决于字段顺序），
    会把'关键字段'截掉而留下噪声。按白名单抽取是**确定的**：
    同一个命令永远返回同一批字段，AI 可以稳定地按字段名读。

    返回：
      {ok, cmd, kind, summary: {...}, omitted_fields: [...], note}
    """
    if not isinstance(data, dict):
        return {
            "ok": False,
            "cmd": cmd,
            "kind": KIND_ENGINE,
            "summary": {},
            "omitted_fields": [],
            'note': '输入不是 JSON 对象，无法摘要。',
        }

    wanted = SUMMARY_FIELDS.get(cmd)
    out: dict = {}
    present: set[str] = set()

    if wanted:
        for path in wanted:
            v = _dig(data, path)
            if v is None or v == [] or v == {}:
                continue
            key = path.replace(".", "_")
            present.add(path.split(".")[0])
            if isinstance(v, list):
                out[key] = v[:list_cap]
                if len(v) > list_cap:
                    out[key + "_truncated_at"] = list_cap
                    out[key + "_total"] = len(v)
            else:
                out[key] = v
    else:
        # 未知命令：不退化成"原样返回"（那等于没摘要），而是返回
        # 标量字段 + 列表长度，仍然比全文小得多。
        for k, v in data.items():
            if isinstance(v, list):
                out[k + "_len"] = len(v)
            elif not isinstance(v, (dict,)):
                out[k] = v

    omitted = [k for k in data.keys() if k not in present and k != "ok"]
    kind = classify_error(data)["kind"]

    note = None
    if not out:
        # 【为什么措辞要分情况】这条备注如果一律说"字段白名单没取到"，
        # 在"命令失败所以本来就没有数据"的场景下会误导 AI ——
        # 它看起来像"摘要器有 bug"，实际是"上一步就失败了"。
        # 所以先看结果本身是否失败，失败就把责任指回上一步。
        if isinstance(data, dict) and (data.get("ok") is False
                                       or data.get("error")):
            note = ("上一步本身失败了（{}），所以没有可摘要的字段。"
                    "先按 kind/handling 处理该失败，不要期待这里给出数据。"
                    .format(data.get("error") or "ok=false"))
        else:
            note = ("按该命令的字段白名单没有取到任何字段。"
                    "可能结果本身是空的，或命令名不在白名单里。")
    elif len(omitted) > 0 and wanted:
        note = ("另有 {} 个字段未摘取；需要时可读原始 JSON 或 case 落盘文件。"
                .format(len(omitted)))

    return {
        "ok": True,
        "cmd": cmd,
        "kind": kind,
        "summary": out,
        "omitted_fields": omitted[:20],
        "note": note,
    }


# ================================================================
# 五、状态外置（case 目录）
# ================================================================
#
# 对标 Blazytko 的 persistent on-disk case directory。四个理由：
#   1. 抗上下文溢出 —— 把大 JSON 留在盘上，上下文里只放摘要；
#   2. 不重复调用 —— 同一个命令对同一个目标跑过一次就有记录；
#   3. 可断点续跑 —— 换会话/上下文清空后还能接着干；
#   4. 可审计 —— 分析过程有留痕。
#
# 目录结构：
#   <case>/
#     manifest.json         案例元信息（目标、创建时间、工具版本）
#     artifacts/<cmd>.json  各子命令的原始结果
#     index.json            每个 artifact 的指纹（mtime/size/sha1）与摘要
#     journal.jsonl         调用流水（供 toolgraph 学习）

CASE_MANIFEST = "manifest.json"
CASE_INDEX = "index.json"
CASE_JOURNAL = "journal.jsonl"
CASE_ARTIFACTS = "artifacts"

_ARTIFACT_NAME_OK = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def _safe_artifact_name(name: str) -> str:
    """
    清洗 artifact 名，防止路径穿越（`../` 之类）。

    【为什么必须做】case 目录里的文件名来自命令名，而命令名来自 AI。
    一旦让 AI 传进来的字符串直接拼路径，就是一个目录穿越漏洞。
    只允许字母数字与 `._-`，其余一律替换掉。
    """
    cleaned = "".join(c if c in _ARTIFACT_NAME_OK else "_" for c in str(name))
    cleaned = cleaned.strip("._-") or "artifact"
    return cleaned[:80]


def case_init(case_dir: str, target: str | None = None,
              note: str = "") -> dict:
    '''初始化 case 目录。已存在则只补齐缺的文件（幂等）。'''
    if not case_dir:
        return {'ok': False, 'error': 'case 目录路径为空',
                'hint': '用 --dir <路径> 指定'}

    created_dirs: list[str] = []
    try:
        for sub in ("", CASE_ARTIFACTS):
            p = os.path.join(case_dir, sub) if sub else case_dir
            if not os.path.isdir(p):
                os.makedirs(p, exist_ok=True)
                created_dirs.append(p)
    except OSError as e:
        return {'ok': False, 'error': f'无法创建 case 目录：{e}',
                'hint': '检查路径权限，或换一个可写目录'}

    man_path = os.path.join(case_dir, CASE_MANIFEST)
    manifest: dict = {}
    if os.path.isfile(man_path):
        manifest = _read_json(man_path) or {}
    manifest.setdefault("created_at", _now_iso())
    if target:
        manifest["target"] = target
    if note:
        manifest["note"] = note
    manifest["updated_at"] = _now_iso()
    manifest.setdefault("tool_version", _tool_version())

    ok_w = _write_json(man_path, manifest)
    if not ok_w:
        return {'ok': False, 'error': f'无法写入 manifest：{man_path}'}

    idx_path = os.path.join(case_dir, CASE_INDEX)
    if not os.path.isfile(idx_path):
        _write_json(idx_path, {"artifacts": {}})

    return {
        "ok": True,
        "case_dir": os.path.abspath(case_dir),
        "created_dirs": created_dirs,
        "manifest": manifest,
        "existed": bool(created_dirs) is False,
    }


def _case_index(case_dir: str):
    """
    读 case 索引，并把形状**归一化**成可信的结构。

    【为什么必须有这个函数】case 目录是给人和 AI 反复读写的**外部状态**，
    它随时可能被手工编辑、被半截写入、被别的版本写过。
    之前三处调用各自写 `_read_json(...) or {"artifacts": {}}`，只防住了
    "读不出来/是 None"，没防住**形状不对**：
      - index.json 写成了 `[]`（合法 JSON 数组）→ `.get` 直接 AttributeError
      - `{"artifacts": "x"}`（字符串是 truthy）→ `or {}` 不生效，`.get` 崩
      - `{"artifacts": {"triage": 123}}`（值是 int）→ 遍历时 `entry.get` 崩
    这三类都会让 `case`/`flow`/`toolgraph` 抛未捕获异常，表现为"工具坏了"
    而不是"状态文件坏了"——正好是最难定位的失败。

    返回 (index, warnings)：warnings 说明哪些地方被修正过，
    让调用方能如实告诉用户"你的索引有问题，我按空处理了"。
    """
    raw = _read_json(os.path.join(case_dir, CASE_INDEX))
    warns: list[str] = []

    if raw is None:
        # 文件不存在 / 读不动 / 不是合法 JSON
        p = os.path.join(case_dir, CASE_INDEX)
        if os.path.exists(p):
            warns.append("index.json 存在但解析失败，已按空索引处理")
        return {"artifacts": {}}, warns

    if not isinstance(raw, dict):
        warns.append(f"index.json 顶层应为对象，实际是 {type(raw).__name__}，已按空索引处理")
        return {"artifacts": {}}, warns

    arts = raw.get("artifacts")
    if arts is None:
        return {"artifacts": {}}, warns
    if not isinstance(arts, dict):
        warns.append(f"index.json 的 artifacts 应为对象，实际是 {type(arts).__name__}，已按空处理")
        return {"artifacts": {}}, warns

    # 逐个条目校验：值必须是 dict，否则丢弃并告警。
    # 丢弃而不是强转 —— 强转会造出"看起来有结果但其实空的"条目，
    # 那比直接说"这条坏了"更危险。
    clean: dict = {}
    bad_names: list[str] = []
    for k, v in arts.items():
        if isinstance(k, str) and isinstance(v, dict):
            clean[k] = v
        else:
            bad_names.append(str(k))
    if bad_names:
        warns.append("index.json 里有 %d 个条目形状不对（已忽略）：%s"
                     % (len(bad_names), ", ".join(bad_names[:5])))
    return {"artifacts": clean}, warns


def case_save(case_dir: str, cmd: str, data, target: str | None = None,
              stale_after: int = 0) -> dict:
    """
    把一次调用的结果存进 case，并登记指纹。

    stale_after 单位秒：目标文件在保存后超过这个时长就算'可能过期'。
    0 表示只按目标 mtime 判断（目标变了就过期）。
    """
    if not case_dir:
        return {'ok': False, 'error': 'case 目录路径为空'}
    if not os.path.isdir(case_dir):
        return {"ok": False,
                "error": f"case 目录不存在：{case_dir}",
                'hint': '先跑 `case init --dir <路径>`'}

    name = _safe_artifact_name(cmd)
    if name != str(cmd):
        pass  # 名字被清洗过，正常记录即可，不算错误

    art_path = os.path.join(case_dir, CASE_ARTIFACTS, name + ".json")
    payload = {
        "cmd": cmd,
        "saved_at": _now_iso(),
        "target": target,
        "data": data,
    }
    if not _write_json(art_path, payload):
        return {'ok': False, 'error': f'无法写入 artifact：{art_path}',
                'hint': '检查磁盘空间与目录权限'}

    # 登记索引（含目标指纹，用于过期判断）
    idx_path = os.path.join(case_dir, CASE_INDEX)
    index, _idx_warns = _case_index(case_dir)

    tinfo = _target_fingerprint(target) if target else {}
    entry = {
        "artifact": os.path.relpath(art_path, case_dir).replace(os.sep, "/"),
        "cmd": cmd,
        "saved_at": _now_iso(),
        "target": target,
        "target_fingerprint": tinfo,
        "payload_sha1": _sha1_of_obj(data),
        "stale_after": stale_after,
        "kind": classify_error(data)["kind"] if isinstance(data, dict) else None,
    }
    index["artifacts"][name] = entry
    if not _write_json(idx_path, index):
        return {'ok': False, 'error': f'无法写入索引：{idx_path}'}

    _journal_append(case_dir, {
        "ts": _now_iso(), "event": "save", "cmd": cmd, "target": target,
        "kind": entry["kind"],
        "ok": bool(isinstance(data, dict) and data.get("ok") is not False),
    })

    return {
        "ok": True,
        "case_dir": os.path.abspath(case_dir),
        "name": name,
        "artifact": entry["artifact"],
        "bytes": _size_of(art_path),
        "entry": entry,
    }


def case_status(case_dir: str, target: str | None = None) -> dict:
    """
    汇总 case 里已有什么、缺什么、什么是过期的。

    这是 flow 判断'该跳过哪些步骤'的依据。
    """
    if not case_dir or not os.path.isdir(case_dir):
        return {"ok": False,
                "error": f"case 目录不存在或不可读：{case_dir}",
                'hint': '先跑 `case init --dir <路径>`',
                "artifacts": [], "have": [], "stale": [], "missing": []}

    idx_path = os.path.join(case_dir, CASE_INDEX)
    index, idx_warns = _case_index(case_dir)
    arts = index["artifacts"]

    have: list[str] = []
    stale: list[dict] = []
    broken: list[dict] = []

    for name, entry in sorted(arts.items()):
        rel = entry.get("artifact") or f"{CASE_ARTIFACTS}/{name}.json"
        p = os.path.join(case_dir, rel.replace("/", os.sep))
        if not os.path.isfile(p):
            broken.append({"name": name, "artifact": rel,
                           'reason': '索引里有记录但文件不存在'})
            continue
        # 【顺序很重要】先判过期，再决定是否算"已有"。
        # 旧写法无条件 have.append，导致过期的条目同时出现在 have 和 stale 里。
        # 而 flow 正是拿 have 决定"哪些步骤可以跳过"——于是它会把一个
        # 数据已失效的命令跳过，AI 拿着旧结论继续往下走，且没有任何报错。
        # 现在把过期条目从 have 里摘出去，flow 就会重新规划这一步。
        st = _staleness(entry, target)
        if st:
            stale.append({"name": name, "cmd": entry.get("cmd"),
                          "reason": st, "saved_at": entry.get("saved_at")})
        else:
            have.append(name)

    manifest = _read_json(os.path.join(case_dir, CASE_MANIFEST)) or {}
    missing = [t["name"] for t in CATALOG
               if t["name"] not in arts and t["name"] not in (
                   "case", "result", "toolgraph", "require", "flow")]

    out = {
        "ok": True,
        "case_dir": os.path.abspath(case_dir),
        "target": manifest.get("target") or target,
        "created_at": manifest.get("created_at"),
        "have": have,
        "have_count": len(have),
        "stale": stale,
        "stale_count": len(stale),
        "broken": broken,
        "missing": missing[:20],
        "missing_count": len(missing),
        "warnings": list(idx_warns),
    }
    if idx_warns:
        # 索引本身坏了 → 这份 status 不可信，必须显式置 ok=False。
        # 否则调用方看到 ok 就以为"确实只有这些结果"，
        # 而真相是"索引读不全"——两者会导出完全相反的下一步决策。
        out["ok"] = False
        out["reason"] = "case 索引损坏，以下结果可能不完整"
    if broken:
        out["warnings"].append(
            f"{len(broken)} 个 artifact 索引存在但文件缺失 —— "
            'case 目录可能被外部改动过。')
    if manifest.get("target") and target and manifest["target"] != target:
        out["warnings"].append(
            f"case 记录的目标是 {manifest['target']}，"
            f'与当前目标 {target} 不一致 —— 结果可能张冠李戴。')
    return out


def case_load(case_dir: str, cmd: str, target: str | None = None,
              allow_stale: bool = False) -> dict:
    """
    取回一个已保存的结果。

    过期默认**拒绝返回数据**（只返回原因），防止 AI 拿旧结论当新证据。
    需要时显式 allow_stale=True。
    """
    if not case_dir or not os.path.isdir(case_dir):
        return {"ok": False, "error": f"case 目录不可读：{case_dir}"}

    name = _safe_artifact_name(cmd)
    idx_path = os.path.join(case_dir, CASE_INDEX)
    index, idx_warns = _case_index(case_dir)
    entry = index["artifacts"].get(name)
    if not entry:
        # 区分"确实没存过"和"索引坏了读不出来"：
        # 前者重跑一次就好，后者重跑也会失败（索引还是坏的），
        # 必须让 AI 知道先去修索引，否则会陷入无效重试。
        if idx_warns:
            return {"ok": False,
                    'error': f'case 索引损坏，读不出 {cmd} 的记录：'
                             + '；'.join(idx_warns),
                    'hint': '索引文件被改坏了。跑 `case init` 可重建索引，'
                            '或删掉 index.json 后重新 save',
                    'index_warnings': idx_warns}
        return {"ok": False,
                'error': f'case 里没有 {cmd} 的结果',
                'hint': '先跑该命令并用 `case save` 存进来'}
    rel = entry.get("artifact") or f"{CASE_ARTIFACTS}/{name}.json"
    p = os.path.join(case_dir, rel.replace("/", os.sep))
    payload = _read_json(p)
    if payload is None:
        return {"ok": False,
                "error": f"artifact 文件读不出来：{p}",
                'hint': '文件可能被删或损坏，重跑该命令并重新 save'}

    st = _staleness(entry, target)
    if st and not allow_stale:
        # stale=True 必须给出去：AI 要能一眼分清"这条是被过期拦下的"
        # 和"这条压根没存过"。只给 stale_reason 字符串的话，
        # 模型得去读自然语言才知道发生了什么——那就不是机器可判定的契约了。
        return {"ok": False,
                "stale": True,
                'error': f'结果已过期：{st}',
                'hint': '重跑该命令；确实要用旧结果就加 --allow-stale',
                "stale_reason": st}

    return {
        "ok": True,
        "cmd": cmd,
        "saved_at": payload.get("saved_at"),
        "target": payload.get("target"),
        "data": payload.get("data"),
        "stale": bool(st),
    }


def _staleness(entry: dict, target: str | None) -> str | None:
    """
    判断一个 artifact 是否过期。返回原因字符串或 None。

    两种情况：
      1. 目标文件变了（mtime/size 与保存时不一致）→ 结果必然过期；
      2. 设了 stale_after 且超时 → 可能过期（保守起见也算）。
    """
    if not isinstance(entry, dict):
        return None
    old = entry.get("target_fingerprint") or {}
    tgt = target or entry.get("target")
    if tgt and old:
        cur = _target_fingerprint(tgt)
        if cur.get("exists") and old.get("exists"):
            if cur.get("size") != old.get("size"):
                return ("目标文件大小变了（{} → {}），旧结果不能代表当前文件"
                        .format(old.get("size"), cur.get("size")))
            if cur.get("mtime") != old.get("mtime"):
                return '目标文件被修改过（mtime 变化），旧结果可能不适用'
        elif old.get("exists") and not cur.get("exists"):
            return '目标文件已不存在'

    sa = entry.get("stale_after") or 0
    if sa and entry.get("saved_at"):
        try:
            import datetime as _dt
            t0 = _dt.datetime.strptime(entry["saved_at"], "%Y-%m-%dT%H:%M:%S")
            age = (time.time() - t0.timestamp())
            if age > sa:
                return f'已保存 {int(age)} 秒，超过设置的 {sa} 秒有效期'
        except (ValueError, TypeError) as e:
            # saved_at 是我们自己写的 ISO 串；解析失败说明 index.json 被人手改过。
            # 此时不能当作"未过期"静默放过，退回 None 让调用方走指纹比对兜底。
            _note_swallowed("_staleness.saved_at", e)
    return None


def _target_fingerprint(path: str | None) -> dict:
    if not path:
        return {}
    try:
        st = os.stat(path)
        return {
            "path": os.path.abspath(path),
            "exists": True,
            "size": st.st_size,
            "mtime": int(st.st_mtime),
        }
    except OSError:
        return {"path": os.path.abspath(path) if path else "", "exists": False}


# ---------------- 小工具 ----------------

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def _tool_version() -> str:
    try:
        import re as _re
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "re.py"), "r", encoding="utf-8") as f:
            head = f.read(4000)
        m = _re.search(r'VERSION\s*=\s*"([^"]+)"', head)
        return m.group(1) if m else "unknown"
    except (OSError, ImportError):
        return "unknown"


def _read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _write_json(path: str, obj) -> bool:
    """
    原子写：先写临时文件再 rename。

    【为什么必须原子写】case 目录会被反复读写；如果一半写崩，
    留下一个截断的 JSON，后续所有 `case load` 都会失败，
    而且失败原因看起来会像'结果损坏'而不是'上次没写完'。
    """
    tmp = path + ".tmp"
    created_tmp = False
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            created_tmp = True
            json.dump(obj, f, ensure_ascii=False, indent=2, default=str)
        os.replace(tmp, path)
        return True
    except OSError as e:
        # 只清理"本次调用真的创建出来的"临时文件。
        # 旧写法无条件删 tmp，会在 makedirs 失败时误删上一轮残留的 .tmp，
        # 把一个无关的残留状态改掉——属于典型的不该吞的副作用。
        if created_tmp:
            try:
                os.remove(tmp)
            except OSError as e2:
                _note_swallowed("_write_json.cleanup", e2)
        _note_swallowed("_write_json", e)
        return False


def _size_of(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _sha1_of_obj(obj) -> str:
    try:
        blob = json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        blob = repr(obj)
    return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()


def _journal_append(case_dir: str, record: dict) -> None:
    '''追加一条调用流水。失败不抛错（流水不该阻断主流程），但必须登记。'''
    try:
        p = os.path.join(case_dir, CASE_JOURNAL)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError as e:
        # 流水写不进去 → toolgraph 学不到这条边。不能假装无事发生：
        # 否则用户会看到「明明跑过却没学到」，是最难定位的一类问题。
        _note_swallowed("_journal_append", e)


def case_journal(case_dir: str, limit: int = 200) -> dict:
    '''读调用流水（供 toolgraph 学习用）。'''
    p = os.path.join(case_dir, CASE_JOURNAL)
    if not os.path.isfile(p):
        return {"ok": True, "records": [], "count": 0,
                'note': '还没有流水记录（case 一旦 save 过就会产生）'}
    # 【为什么用环形缓冲而不是 recs[-limit:]】
    # 流水文件是**只追加、无上限**的。之前先全读进 list 再切片，
    # 意味着只要 case 活得够久（自动跑几百轮的自动化正好会这样），
    # 读 200 条记录也要把整个文件塞进内存——文件 500MB 就吃 500MB。
    # 这里改用 deque(maxlen) 流式读取：内存恒定，与文件大小无关。
    # total 仍然精确统计，调用方能知道"一共多少条、我只看了最后几百条"。
    from collections import deque
    keep = limit if limit and limit > 0 else 0
    buf: deque = deque(maxlen=keep if keep else None)
    total = 0
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    total += 1
                    continue
                total += 1
                buf.append(rec)
    except OSError as e:
        return {'ok': False, 'error': f'读流水失败：{e}', 'records': [],
                "count": 0}
    recs = list(buf)
    return {"ok": True, "records": recs, "count": len(recs),
            "total_records": total,
            "truncated": bool(keep and total > keep)}


# ================================================================
# 六、工作流编排（DAG / 阶段化）
# ================================================================
#
# 对标 Tim Blazytko 的 agentic pipeline：他的核心结论是
#   "imposing a structured workflow on the analysis ... Instead of letting
#    the agent interact with tools in an open-ended way"
# ——把开放式探索换成"有明确阶段 + 明确产出物"的流程，
# 并配一个 orchestrator 负责"检查产出物是否齐全、管阶段推进"。
#
# 我们把这个 orchestrator 做成确定性的：AI 不必自己规划调用顺序，
# 只要跑 `flow` 拿到"现在该跑什么"，跑完再问一次。
#
# 【为什么用 DAG 而不是线性清单】21 个工具里有大量互不依赖的操作
# （strings / entropy / imports / symbols 之间没有先后依赖）。
# 顺序执行会让总耗时等于各步之和；标出来让 AI 并行跑，
# 总耗时等于最慢那一个。研究里的例子：5 个 200ms 的调用，
# 串行 1000ms，并行 200ms。
#
# 【批次的语义】同一批次里的步骤彼此无依赖，可以并行；
# 批次之间必须串行。

# 步骤定义。deps 里的 "prior:<cmd>" 表示必须先生成该 artifact。
FLOW: list[dict] = [
    # ---- 阶段 1：初筛（便宜、信息量大、无依赖） ----
    {"id": "doctor", "cmd": "doctor", "stage": "triage", "batch": 1,
     'deps': [], 'why': '先知道本机有什么工具，后面的建议才能按实际能力裁剪',
     'yields': '可用工具清单与 AI 辅助层就绪度'},
    {"id": "triage", "cmd": "triage", "stage": "triage", "batch": 1,
     'deps': [], 'why': '一次拿到格式/架构/熵/字符串线索/IOC/加壳判断',
     'yields': 'identify + leads + packer（后续多数步骤的输入）'},
    {"id": "symbols", "cmd": "symbols", "stage": "triage", "batch": 1,
     'deps': [], 'why': '有符号就有名字，成本极低、收益极高',
     'yields': '还原后的函数名（Go 程序尤其可观）'},
    {"id": "plan", "cmd": "plan", "stage": "triage", "batch": 1,
     'deps': [], 'why': '按格式与本机工具生成针对性计划',
     'yields': '分步命令 + 加速层 + 安装提示'},

    # ---- 阶段 2：理解结构 ----
    {"id": "imports", "cmd": "imports", "stage": "understand", "batch": 2,
     'deps': [], 'why': '导入表是免费的『行为地图』，看它用了哪些 API',
     'yields': '依赖库与函数名列表'},
    {"id": "entropy", "cmd": "entropy", "stage": "understand", "batch": 2,
     'deps': [], 'why': '定位高熵区域，判断有没有加密/压缩/壳',
     'yields': '高熵区间（决定要不要走脱壳路线）'},
    {"id": "strings", "cmd": "strings", "stage": "understand", "batch": 2,
     'deps': [], 'why': '字符串是最容易出线索的地方，但要看分类后的',
     'yields': '按类别汇总的 IOC/路径/密钥线索'},
    {"id": "obfstr", "cmd": "obfstr", "stage": "understand", "batch": 2,
     'deps': [], 'why': 'strings 看不到的被混淆串（栈串/XOR）在这里',
     'yields': '栈字符串与解密循环恢复出的明文'},
    {"id": "carve", "cmd": "carve", "stage": "understand", "batch": 2,
     'deps': [], 'why': '看看有没有内嵌/释放的文件',
     'yields': '内嵌文件清单（不含提取，除非指定 --out）'},

    # ---- 阶段 3：行为（需要代码区） ----
    {"id": "funcs", "cmd": "funcs", "stage": "behavior", "batch": 3,
     'deps': [], 'why': '把字节变成函数列表，是后面所有代码级分析的输入',
     'yields': '函数清单与入口点（要读 partial/truncated_note）'},
    {"id": "semantics", "cmd": "semantics", "stage": "behavior", "batch": 4,
     "deps": ["prior:funcs"],
     'why': '每个函数在干嘛 —— 定位『加密在哪/联网在哪』最省时间的一步',
     'yields': '按行为分组的结果与每函数标签'},
    {"id": "capability", "cmd": "capability", "stage": "behavior", "batch": 5,
     "deps": [],
     'why': '结论层：把结构特征折算成能力与 ATT&CK',
     'yields': '能力命中清单（带地址证据）与 ATT&CK 映射'},

    # ---- 阶段 4：定点深挖（按需） ----
    {"id": "disasm", "cmd": "disasm", "stage": "deep", "batch": 6,
     "deps": [],
     'why': '需要看具体指令时用；先用 semantics 定位到函数再来看',
     'yields': '指令序列（含非法指令率，可判断这里是代码还是数据）'},
    {"id": "xref", "cmd": "xref", "stage": "deep", "batch": 6,
     "deps": ["prior:funcs"],
     'why': '看某个可疑函数被谁调用，顺着往上追主流程',
     'yields': '引用者列表'},
    {"id": "cfg", "cmd": "cfg", "stage": "deep", "batch": 7,
     "deps": ["prior:funcs"],
     'why': '单个函数的控制流结构（要在 xref/semantics 缩小范围后用）',
     'yields': '基本块、边、循环'},

    # ---- 阶段 5：交付 ----
    {"id": "report", "cmd": "report", "stage": "deliver", "batch": 9,
     "deps": ["prior:triage"],
     'why': '生成报告骨架；AI 在此基础上补结论',
     'yields': 'Markdown 报告文件（需显式 --out）'},
]

STAGES: list[str] = ["triage", "understand", "behavior", "deep", "deliver"]


def _flow_step_by_id(sid: str) -> dict | None:
    for s in FLOW:
        if s["id"] == sid:
            return s
    return None


def flow(stage: str | None = None, have: list[str] | None = None,
         case_dir: str | None = None, target: str | None = None) -> dict:
    """
    给出当前该跑哪些步骤。

    参数：
      stage     只关心某个阶段（默认按顺序覆盖全部）
      have      已完成/已有结果的步骤 id 列表（会被跳过）
      case_dir  若给了 case 目录，自动从里面读'已有什么'
      target    目标路径（用于生成命令模板）

    返回：
      {
        ok, stage, target,
        done: [id], pending: [id],
        next_batch: [ {id, cmd, command, why, yields, deps} ],   # 现在就能并行跑的
        next: 同 next_batch 的第一项（方便只想跑一个的调用方）,
        blocked: [ {id, waiting_for} ],      # 前置没满足
        pending_count, done_count,
        plan_summary: "..."                  # 一句话说清下一步
      }
    """
    have_set: set[str] = set(have or [])
    source = "explicit"

    # 从 case 目录推断已完成步骤
    if case_dir and os.path.isdir(case_dir):
        st = case_status(case_dir, target)
        if st.get("ok"):
            for nm in st.get("have", []):
                for s in FLOW:
                    if s["cmd"] == nm:
                        have_set.add(s["id"])
            source = "case"

    steps = FLOW
    if stage:
        if stage not in STAGES:
            return {
                "ok": False,
                'error': f'未知阶段 {stage!r}',
                'hint': '可用阶段：' + ' → '.join(STAGES),
                "next": None, "next_batch": [], "done": [], "pending": [],
            }
        steps = [s for s in FLOW if s["stage"] == stage]

    done, pending, blocked = [], [], []
    for s in steps:
        if s["id"] in have_set:
            done.append(s["id"])
            continue
        missing = [d for d in s["deps"]
                   if d.startswith("prior:") and d.split(":", 1)[1] not in have_set]
        if missing:
            blocked.append({
                "id": s["id"],
                "cmd": s["cmd"],
                "waiting_for": [m.split(":", 1)[1] for m in missing],
                "why": s["why"],
            })
        else:
            pending.append(s)

    # 最小可跑批次：pending 里 batch 号最小的那一批
    next_batch: list[dict] = []
    if pending:
        min_batch = min(s["batch"] for s in pending)
        for s in pending:
            if s["batch"] != min_batch:
                continue
            entry = {
                "id": s["id"],
                "cmd": s["cmd"],
                "stage": s["stage"],
                "command": _step_command(s, target),
                "why": s["why"],
                "yields": s["yields"],
                "deps": s["deps"],
                "parallel_ok": True,
            }
            next_batch.append(entry)

    res: dict = {
        "ok": True,
        "stage": stage,
        "target": target,
        "have_source": source,
        "done": done,
        "done_count": len(done),
        "pending": [s["id"] for s in pending],
        "pending_count": len(pending),
        "blocked": blocked,
        "next_batch": next_batch,
        "next": next_batch[0] if next_batch else None,
        "notes": [],
    }

    if not pending:
        res['plan_summary'] = '该阶段没有待跑步骤（都已完成或被跳过）。'
        res['notes'].append('若结果不满意，可用 `require` 按具体问题检索工具。')
    else:
        cmds = " + ".join(e["cmd"] for e in next_batch)
        res["plan_summary"] = (
            f'现在并行跑这 {len(next_batch)} 个：{cmds}'
            f'（互不依赖）；跑完把结果 `case save` 进去，再问一次 flow。')
        if blocked:
            res["notes"].append(
                f'{len(blocked)} 个步骤在等前置产出：'
                + '、'.join(b['id'] for b in blocked[:5]))

    # 提醒成本
    heavy = [e["cmd"] for e in next_batch
             if CATALOG_BY_NAME.get(e["cmd"], {}).get("cost") == "heavy"]
    if heavy:
        res["notes"].append(f'注意 {', '.join(heavy)} 开销较大，别重复跑。')

    return res


def _step_command(step: dict, target: str | None) -> str:
    entry = CATALOG_BY_NAME.get(step["cmd"])
    if not entry:
        return f"re.py {step['cmd']} <目标> --json"
    return build_command(entry, target or "<目标>")


# ================================================================
# 七、工具转移图（Tool Inertia Graph）
# ================================================================
#
# 对标 AutoTool (AAAI 2026)。它的核心发现是"工具调用有惯性"：
# 上一步跑了什么，下一步该跑什么，在很大程度上是可预测的
# （ScienceWorld 里 go_to → look_around 占 88.7%；一阶条件熵 2.52 bit
#   对比 0 阶 3.50 bit）。据此做的图搜索能省掉最多 30% 的推理开销。
#
# 【我们的做法】内置一张**经过人工核对**的转移表（不是编造的统计数字，
# 是按逆向的实际工作流画的），再允许从 case 流水里在线学习增量。
#
# 与 AutoTool 的差异，必须说清：
#   * 它用 SimCSE 嵌入算 Score_ctx；我们没有嵌入模型（零依赖），
#     所以 Score_ctx 用**关键词重合度**近似，精度更低但可解释；
#   * 它的边权来自真实轨迹统计；我们的初始权来自工作流先验，
#     并明确标注为"先验"而非"实测"，避免把设计意图包装成数据。

# 初始转移表：{当前步骤: [(下一个, 权重 0~1, 理由)]}
# 权重标为 prior（先验），学习到的会另记 learned_edges。
TRANSITIONS: dict[str, list[tuple[str, float, str]]] = {
    'doctor': [('triage', 0.85, '知道工具后立刻初筛'),
               ('plan', 0.60, '先看计划再动手')],
    'triage': [('symbols', 0.80, '初筛后立刻挖名字，成本最低收益最高'),
               ('imports', 0.75, '看行为地图'),
               ('strings', 0.70, '看线索'),
               ('obfstr', 0.55, '怀疑字符串被藏起来了'),
               ('plan', 0.50, '拿分步计划'),
               ('capability', 0.45, '直接出能力结论')],
    'symbols': [('semantics', 0.60, '有名字后看每个函数干嘛更省力'),
                ('funcs', 0.55, '有了名字去对应函数'),
                ('capability', 0.50, '出结论')],
    'plan': [('triage', 0.55, '按计划先初筛'),
             ('imports', 0.45, '按计划看导入表')],
    'imports': [('semantics', 0.70, '从 API 追到函数行为'),
                ('strings', 0.55, '找 API 相关的线索串'),
                ('capability', 0.60, '用能力规则收敛结论')],
    'entropy': [('strings', 0.55, '高熵区去看有没有加密线索'),
                ('carve', 0.50, '高熵可能藏着内嵌文件')],
    'strings': [('obfstr', 0.60, '字符串没看到关键的就去找被藏的'),
                ('semantics', 0.55, '从字符串线索定位函数'),
                ('capability', 0.50, '收敛结论')],
    'obfstr': [('semantics', 0.55, '从解密循环定位到函数再画像'),
               ('xref', 0.45, '看谁调用了这个解密循环')],
    'carve': [('identify', 0.50, '识别提取出来的东西'),
              ('triage', 0.45, '对载荷做初筛')],
    'funcs': [('semantics', 0.80, '有函数列表就做语义画像，这是主路径'),
              ('xref', 0.55, '看调用关系'),
              ('capability', 0.50, '出结论')],
    'semantics': [('capability', 0.65, '画像→能力结论'),
                  ('xref', 0.60, '顺调用链往上追主流程'),
                  ('cfg', 0.50, '看可疑函数的控制流'),
                  ('disasm', 0.45, '看具体指令')],
    'capability': [('report', 0.55, '出结论后交付'),
                   ('semantics', 0.40, '命中项回语义层复核'),
                   ('disasm', 0.45, '用地址证据回反汇编复核')],
    'xref': [('cfg', 0.60, '找到函数后看控制流'),
             ('disasm', 0.50, '看具体指令'),
             ('semantics', 0.45, '看该函数行为')],
    'cfg': [('disasm', 0.60, '看基本块里的具体指令'),
            ('semantics', 0.40, '回到语义层')],
    'disasm': [('cfg', 0.45, '从指令回到结构'),
               ('report', 0.40, '记录下来')],
    'sim': [('semantics', 0.55, '把旧版名字移植后做语义比对'),
            ('xref', 0.45, '看变动函数的引用')],
    'diff': [('disasm', 0.55, '对改动区域反汇编'),
             ('sim', 0.50, '做函数级比对')],
    "report": [],
}


def toolgraph(current: str | None = None, case_dir: str | None = None,
              top_k: int = 3, context: str = "") -> dict:
    """
    给出现在这个工具之后，接下来最该跑哪个。

    参数：
      current    刚跑完（或打算接着跑）的命令名
      case_dir   若有 case 目录，会读流水做在线学习并调整权重
      top_k      返回候选数量
      context    AI 的当前意图（用于 Score_ctx，用关键词重合近似嵌入）

    返回：
      {
        ok, current,
        next: {cmd, weight, why, command} | None,
        candidates: [...],
        learned_edges: {...},     # 从流水学到的高频转移（明确标注）
        warnings: [...],          # 比如'你打算跑的这步与历史不一致'
      }
    """
    out: dict = {
        "ok": True,
        "current": current,
        "next": None,
        "candidates": [],
        "learned_edges": {},
        "weights_source": "prior",
        "warnings": [],
    }

    learned: dict[str, dict[str, int]] = {}
    if case_dir and os.path.isdir(case_dir):
        jr = case_journal(case_dir, limit=500)
        if jr.get("ok"):
            learned = _learn_edges(jr.get("records") or [])
            out["learned_edges"] = {
                k: v for k, v in list(learned.items())[:20]
            }
            if learned:
                out["weights_source"] = "prior+learned"
        else:
            out["warnings"].append(
                "流水读取失败，只用先验权重：" + str(jr.get("error")))

    if not current:
        # 没给 current：退化成"从阶段起点开始"
        first = flow()["next_batch"]
        out["candidates"] = first
        out["next"] = first[0] if first else None
        out['note'] = '未指定当前命令，按流程起点给出候选。'
        return out

    if current not in CATALOG_BY_NAME:
        out["ok"] = False
        out['error'] = f"未知子命令：{current}"
        out['hint'] = '可用命令见 `require --list`'
        return out

    base = TRANSITIONS.get(current, [])
    cands: list[dict] = []
    for nxt, w, why in base:
        score = w
        # 在线学习加成：历史里这条边跑得多就加分（有上限，别压过先验）
        cnt = learned.get(current, {}).get(nxt, 0)
        if cnt:
            score = min(1.0, score + min(0.25, 0.05 * cnt))
        entry = CATALOG_BY_NAME.get(nxt, {})
        cands.append({
            "cmd": nxt,
            "weight": round(score, 3),
            "why": why,
            "command": build_command(entry) if entry else f"re.py {nxt} --json",
            "learned_count": cnt,
        })

    # Score_ctx：用意图关键词与候选 answers/keywords 的重合度做微调
    if context and cands:
        q_tokens = _tokens(context)
        for c in cands:
            e = CATALOG_BY_NAME.get(c["cmd"])
            if not e:
                continue
            ctx_hit = 0
            for tk in q_tokens:
                if len(tk) < 2:
                    continue
                if any(_hit(tk, a) for a in e["answers"]) or                    any(tk.lower() in k.lower() for k in e["keywords"]):
                    ctx_hit += 1
            if ctx_hit:
                c["context_hits"] = ctx_hit
                c["weight"] = round(min(1.0, c["weight"] + 0.05 * ctx_hit), 3)

    cands.sort(key=lambda x: (-x["weight"], x["cmd"]))
    cands = cands[:max(1, top_k)]
    out["candidates"] = cands
    out["next"] = cands[0] if cands else None

    if not cands:
        out['note'] = (f"{current} 之后没有预设的后续步骤"
                       '（它通常是终点或需要按具体问题检索）。')
    return out


def _learn_edges(records: list[dict]) -> dict[str, dict[str, int]]:
    """
    从流水里统计'相邻两次 save 的命令对'。

    【只统计相邻且同一目标】跨目标的转移没有意义（在 A 上跑完 strings
    不代表在 B 上会接着跑 obfstr）。这是 AutoTool 那张全局图会犯的错，
    它的论文也承认'图应该按 agent 角色或任务类型分开，不该全局共享'。
    """
    edges: dict[str, dict[str, int]] = {}
    prev_cmd = None
    prev_tgt = None
    for r in records:
        if r.get("event") != "save":
            continue
        cmd = r.get("cmd")
        tgt = r.get("target")
        if not cmd:
            continue
        if prev_cmd and prev_tgt == tgt and prev_cmd != cmd:
            edges.setdefault(prev_cmd, {})
            edges[prev_cmd][cmd] = edges[prev_cmd].get(cmd, 0) + 1
        prev_cmd, prev_tgt = cmd, tgt
    return edges


def suggest_next_with_check(current: str, intended: str,
                            case_dir: str | None = None) -> dict:
    """
    校验 AI 打算跑的下一步是否合理。

    对标研究里'用工具图预测下一步，省掉一次 LLM 推理'的思路，
    反过来用：AI 已经想好要跑某个命令时，我们**不阻止**它，
    只告诉它'这与历史/流程的预测是否一致'。

    返回里 intended_ok 为 False 时**不是错误**，只是提示；
    AI 完全可以有意偏离（比如按具体线索走）。
    """
    g = toolgraph(current, case_dir)
    if not g.get("ok"):
        return {"ok": False, "error": g.get("error"),
                "intended": intended, "intended_ok": None}

    cands = [c["cmd"] for c in g.get("candidates", [])]
    ok_int = intended in cands
    res = {
        "ok": True,
        "current": current,
        "intended": intended,
        "intended_ok": ok_int,
        "predicted": cands,
        "suggestion": g.get("next"),
    }
    if not ok_int and cands:
        res['note'] = ("{} 不在 {} 之后的常见路径里（常见的是 {}）。"
                       .format(intended, current, ", ".join(cands))
                       + '如果你有具体线索要跟，继续即可；'
                         '否则建议先跑预测的那一个。')
    elif ok_int:
        res['note'] = f"{intended} 与流程预测一致，可以跑。"
    return res
