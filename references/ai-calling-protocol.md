# AI 调用协议（ai-calling-protocol）

> 本文回答一个问题：**工具这么多，AI 怎么才能"挑得准、跑得快、不出错"？**
>
> 结论不是"让模型更聪明"，而是**把可确定的部分从模型脑子里搬进代码**。
> 模型只保留它真正擅长的部分：读懂证据、下结论、写给人看的报告。

---

## 0. 为什么需要这份协议

### 问题：工具数量一旦上去，模型的挑工具能力会崩

这不是感觉，是有测量数据的。AWS Well-Architected 的 Agentic AI Lens 里
有一条专门的最佳实践 `AGENTPERF06-BP01`，原话是：

> LLM 的候选工具集一旦超过 **10–15 个**，工具选择质量就开始明显下降；
> 建议做**两段式选择**——先用确定性的方式筛到 5–10 个，再让模型在这几个里挑。

公开的测量曲线大致是：

| 候选工具数 | 选择准确率 |
|---|---|
| ~50 | 84–95% |
| ~200 | 41–83% |
| ~740 | 接近 0 |

还有"Lost in the Middle"效应：正确答案如果排在第 40–60% 的位置，
命中率会从 22% 掉到 52%（相对于首尾位置）。

本工具箱有 **21 个分析子命令**，正好落在"开始变差"的区间。

### 另一类更贵的浪费：把正常结果当成失败

比"挑错工具"更常见的浪费是**重试语义搞错**：

- `obfstr` 在没混淆的样本上返回空 —— 这是**正常结论**（"没有"就是答案），
  但 Agent 常把它当失败，换个参数再来一遍。参数怎么换结果都是空的。
- 反过来，真正因为上限截断（`truncated`）而少拿了数据时，
  它又不重试了 —— 这时重试（放宽上限）是真的能拿到更多。

**所以"哪些该重试、哪些不该"必须由契约写死，不能靠模型猜。**

---

## 1. 解法总览：把四件事挪出模型

| 原来由模型做的事 | 现在由谁做 | 命令 |
|---|---|---|
| 我有 21 个工具，选哪个？ | 确定性检索（关键词 + 整句命中打分） | `require` |
| 选完按什么顺序跑？哪些能并行？ | 手写的 DAG（批次 + 依赖） | `flow` |
| 上一步的结果太长 / 下次还要用 | 落盘 + 字段白名单摘要 | `case`、`result` |
| 这次算成功还是失败？要不要重试？ | 退出码 + 标志位 → 6 类归类 | `result` |
| 这一步完了下一步通常跑什么？ | 先验转移表 + 在线学习 | `toolgraph` |

**分工原则**（这条比任何具体命令都重要）：

> 脚本产出**事实**，模型产出**判断**。
> 凡是"看几个字段就能决定"的事，都不该让模型决定。

---

## 2. 标准调用流程（照这个顺序走）

### 第一步：先问"该用什么"，别自己挑

```bash
python re.py require "这文件是不是加壳了" --json
```

返回按相关度排序的候选（默认 top-6，正好在 5–10 的甜点区）。每条带：
- `name` / `summary` —— 是什么
- `why` —— **为什么推荐它**（命中了你原话里的哪个词），加 `--explain` 看
- `command` —— 可直接复制的命令骨架
- `cost` —— `cheap` / `medium` / `heavy`（用来决定要不要放最后跑）

**不要跳过这一步去猜命令名。** 猜错的代价是一次 `usage_error` + 一次重试，
正好抵消掉编排层省下的时间。

### 第二步：拿流程规划，把能并行的并发发出去

```bash
python re.py flow --json                    # 全新目标
python re.py flow --case ./case-xxx --json  # 已有进度，自动跳过跑过的
```

返回：
- `next_batch` —— **本次该跑的一组命令**。同批次之间**无依赖，可以并发调用**。
- `pending` / `done` / `blocked` —— 全局进度
- `plan_summary` —— 一句话说清整体路线

⚠️ 同批次的命令用**一次并发**全发出去。串行等 4 个来回 vs 并发 1 个来回，
在网络/进程启动开销上是 4 倍差距。这是最容易被忽略的提速点。

### 第三步：结果进 case 目录，不要把大 JSON 塞回上下文

```bash
python re.py triage target.bin --json > /tmp/t.json
python re.py case init  --dir ./case-x --target ./target.bin --json
python re.py case save  --dir ./case-x --cmd triage --from-file /tmp/t.json --target ./target.bin --json
python re.py case show  --dir ./case-x --cmd triage --json      # ← 看这个，不看原始 JSON
```

**为什么必须这样**：实测一个真实 PE 的 `triage` 原始 JSON 是 **247,966 字节**；
经 `case show` 摘要后是 **6 行、约 2.6 KB**（压到 1.4%）。
直接把原始 JSON 塞进上下文，两三个命令就把窗口吃光了，
而且真正有用的字段会被淹没在噪声里（这正好是 AWS 那条
"按 Agent 的信息需求设计，而不是按技术完备性"说的）。

### 第四步：用 result 判定成败，按 next_action 走

```bash
python re.py triage target.bin --json | python re.py result --stdin --cmd triage --json
```

返回的 `kind` + `next_action` 就是明确指令：

| `kind` | 含义 | `retryable` | `next_action` | AI 该做什么 |
|---|---|---|---|---|
| `ok` | 正常拿到内容 | false | `continue` | 继续下一步 |
| `empty_result` | **正常跑完，结果就是空的** | **false** | `continue_no_retry` | **继续，不要重试** |
| `usage_error` | 参数/用法不对 | false | `fix_args` | 改参数，不是换目标 |
| `target_error` | 目标不可读 | false | `change_target` | 换目标，不是改参数 |
| `partial` | 被上限截断 | **true** | `raise_limit_or_note` | 放宽上限**能**拿到更多，可重试 |
| `engine_error` | 工具自身出错 | false | `report_bug` | 报告，不要盲目重试 |

`swallowed` 字段（如果有）说明这次结果里有没有被静默咽掉的异常 ——
"没报错"不等于"没出问题"，看到它要留意。

### 第五步：卡住时问图，不要瞎试

```bash
python re.py toolgraph --cmd triage --case ./case-x --json
```

给出"按历史经验，跑完 triage 通常接什么"。权重分两来源：
- `weights_source: "prior"` —— 手写的先验表（人定的，可能不完美，但诚实标注）
- `weights_source: "prior+learned"` —— 叠加了 case 流水里统计出的实际共现

**从没见过的边**才需要模型自己判断；见过的边直接照图走。

---

## 3. 一页速查：意图 → 该跑什么

| 你想知道 | 命令 |
|---|---|
| 手上有什么工具 | `doctor` |
| 该用什么工具（**不确定就先问**） | `require "<你的原话>"` |
| 整体流程怎么走 | `flow` |
| 这文件是什么 | `identify` / `triage` |
| 有没有加壳 / 熵高不高 | `entropy` |
| 有什么字符串 / 找线索 | `strings` |
| 有加密串被藏起来了 | `obfstr` |
| 调了哪些库函数 | `imports` |
| 有哪些函数 | `funcs` |
| 这函数在干嘛 | `semantics` |
| 这样本能做什么（结论层） | `capability` |
| 符号名还原 | `symbols` |
| 控制流图 | `cfg` |
| 谁调用了它 | `xref` |
| 反汇编 | `disasm` |
| 两个版本差异 | `diff` |
| 结果太长 → 摘要 | `case save` 然后 `case show` |
| 这次算成功吗 → 判定 | `result` |
| 下一步跑什么 | `toolgraph` |

---

## 4. 硬性纪律（违反这些就是 bug，不是风格问题）

1. **AI 决策一律加 `--json`。** 人类可读输出是给人看的，字段不稳定。
2. **先 `require` 再动手。** 别凭印象拼命令名。
3. **同批次的 `flow.next_batch` 必须并发发。** 串行就是白扔 4 倍时间。
4. **不要把原始 JSON 整段回读进上下文。** 走 `case save` → `case show`。
5. **`empty_result` 不许重试。** 这是最贵的浪费来源。
6. **`partial` 应当重试（放宽上限）。** 和上一条正好相反，别搞混。
7. **拿过期结果 = 拿错结论。** `case show` 报过期就重跑，除非你明确知道旧数据够用
   （这时才加 `--allow-stale`，并且要在报告里说明）。
8. **退出码只看 0/2/3/4。** 其它值一律当 `engine_error` 处理。
9. **每一步的事实必须来自脚本输出。** 脚本没给的字段，就说"没测出来"，不要补全。

---

## 5. 为什么这样设计（依据）

| 设计选择 | 依据 |
|---|---|
| 把候选压到 top-6 | AWS `AGENTPERF06-BP01`：5–10 是甜点区 |
| 检索放在确定性代码里，不用 embedding | 项目约束：零第三方依赖（`selftest` 有 `t_no_third_party` 守门）。所以用"整句命中加权 + 泛词降权 + 长度缩放"的纯字符串打分 |
| 意图检索用整句命中给高分 | 整句出现是噪声最少的强信号；n-gram 会命中太多泛词 |
| 泛词降权（`_GENERIC_TOKENS`） | 对标 capa 的教训：在函数粒度上用公用助记符做合取等于没有约束 |
| 中文必须做 n-gram 切分 | `str.isalnum()` 对汉字返回 `True`，整句会被当成一个词元，永远匹配不上 2 字关键词 |
| 空的意图/无命中**不兜底返回全表** | 那就是 fail-open，等于把问题原样退回给模型 |
| `empty_result` 归为不可重试 | 研究里反复出现的 Agent 浪费模式 |
| case 落盘 + 过期拒绝 | 借鉴 Tim Blazytko 的 agentic malware analysis 流水线："把状态外化到磁盘"；且逆向场景里用旧样本结论回答新样本，比报错危险得多 |
| 转移图按目标/任务分开学，不做全局图 | AutoTool（arXiv:2511.14650）自己承认全局图是错的，应该按 agent 角色 / 任务类型分开 |
| 同批次并行 | 5 个调用 × 200ms：串行 1000ms，并发约 200ms |
| 先验权重与学习权重分开标注 | 把手写意图伪装成实测数据是不诚实的；`weights_source` 让两者的可信度可区分 |

---

## 6. 参考

- AWS Well-Architected Framework — Agentic AI Lens，`AGENTPERF06-BP01`
  （工具数量与选择质量、两段式选择）
- *MCP-Zero: Active Tool Discovery for Autonomous LLM Agents*，arXiv:2506.01056
  （反转注入：模型主动声明"我需要一个能做 X 的工具"，由运行时做分层语义路由；
  APIBank 上 token 降约 98%）
- *AutoTool: Efficient Tool Discovery for Autonomous Agents*，AAAI 2026，arXiv:2511.14650
  （工具惯性图 + CIPS 打分；条件熵 0 阶 3.50 bit → 1 阶 2.52 → 2 阶 1.93；
  推理成本最多降 30%）
- Tim Blazytko, *Agentic Malware Analysis Pipeline*，synthesis.to，2026-03-18
  （四原则：先做宽指纹、原始证据与高层推理分离、明确分阶段、**状态外化到磁盘**；
  orchestrator / planner / reporter 三角色）
- *Lost in the Middle: How Language Models Use Long Contexts*
  （中间位置信息利用率显著下降）

---

## 附：自检覆盖

协议不是靠文档约束的，是靠 `selftest.py` 里的用例守住的：

| 用例 | 守什么 |
|---|---|
| `编排：目录与子命令一致` | `CATALOG` 与 CLI 真实子命令不许漂移 |
| `编排：意图检索准确率` | top-1 ≥ 70%、top-3 ≥ 95%（实测 84% / 100%） |
| `编排：无命中不退化全表` | 空意图/无关意图必须返回 0 候选，不许 fail-open |
| `编排：错误分类与重试语义` | 6 类归类 × 退出码 0/2/3/4；`empty_result` 必须不可重试 |
| `编排：摘要层真的压小` | 摘要必须压到 10% 以下，且留住决策字段 |
| `编排：case 存取与过期拒绝` | 过期必须拒绝返回；过期条目不许留在 `have` |
| `编排：case 目录穿越防护` | 来自 AI 的目录名不许穿越 |
| `编排：flow 批次与依赖` | 依赖必须指向更早批次；首批必须可并行 |
| `编排：toolgraph 先验与学习` | 先验表自洽；流水能真的改变权重 |
| `编排：5 命令 CLI 契约` | 退出码/`ok` 字段/优雅降级/不污染目录 |
