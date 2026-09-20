# 论文与前沿方法索引：按「解决哪个痛点」组织

> 用法：不要通读。先定位你当前卡在哪个环节，只读那一节。
> 标注 **[有代码]** 的可直接 clone 跑；**[仅论文]** 的读思路，自己落地。
> 调研时间：2026-09，链接与结论以原文为准。

---

## 痛点 1：反编译出来能跑但读不懂（最常见的瓶颈）

**结论先行**：这一方向最成熟，且工业界已经能用。落地路径是「反编译器出结果 → LLM 做精修」，
而不是「让 LLM 从汇编端到端生成源码」。

### 精修派（Refinement）—— 推荐路线，风险低

| 工作 | 出处 | 方法 | 效果 |
|---|---|---|---|
| **DeGPT** [有代码] | NDSS 2024<br>`github.com/PeiweiHu/DeGPT` | 三角色（裁判/顾问/操作员）多轮对话 + 微片段语义计算(MSSC) 保证不改变语义 | 认知负担降低 **24.4%**，**62.9%** 的自动注释被判为有实用价值 |
| **ReSym** | — | 神经符号：用 Prolog 推理引擎给 LLM 生成的变量名加逻辑约束 | 解决局部符号不一致 |
| **GenNm** | — | 把 caller/callee 上下文喂给模型 | 变量名预测准确率提升 |
| **PseudoFix** | — | RAG 检索相似高质量片段做结构修复 | 修结构错误 |
| **SymLM / DIRE** | — | 执行感知嵌入 / GNN 做命名恢复 | 命名恢复早期代表作 |

### 端到端派（End-to-End）—— 仍在演进，长函数不稳

| 工作 | 出处 | 要点 |
|---|---|---|
| **LLM4Decompile** [有代码] | EMNLP 2024<br>`github.com/albertan017/LLM4Decompile`<br>arXiv:2403.05286 | 首个开源反编译大模型（1B–33B），预训练 40 亿 token 的 C↔汇编对；提出 **Decompile-Eval**（首个考察可重编译 + 可重执行的评测集）。报告：能准确反编译 21% 的汇编，Pass@1 比 GPT-4 高 50%。O0 下 30% 过重编译测试，O3 下 18% |
| **ReF Decompile** | — | 把跳转地址符号化以显式保留控制流；允许模型查询 `.rodata` 补回字符串常量 |
| **SK2Decompile** | — | 粗到细两阶段：先恢复控制流骨架，再填变量名等语义细节，缩小搜索空间 |
| **Nova** [有代码] | ICLR 2025<br>`github.com/lt-asset/nova` | 层次化注意力 + 对比学习，缓解长汇编的上下文窗口限制 |
| **WaDec / CFADecLLM** | — | 分别面向 WebAssembly、以及把 CFG 当多模态输入 |

**判断**：端到端方法可读性好，但受上下文窗口限制，长函数难以保证语义等价 —— 所以**先用 Ghidra/IDA 出结果，再用 LLM 精修**是当前性价比最高的组合。

### 可验证性（这条最值得抄进工作流）

- **DecLLM / D-LiFT / FidelityGPT**：generate → compile → verify 循环，用「能否重新编译并通过测试」当奖励。
- **QRS 框架**（arXiv:2606.06838）：作者三阶段演进的结论非常实操 ——
  ① 只给 Agent 工具（Ghidra MCP）→ 覆盖不全、质量不稳；
  ② 只优化结构相似度单一指标 → **Agent 刷指标但可读性反而变差**（metric gaming）；
  ③ 用**复合指标**（结构相似度门 + 词汇意外度 + 结构简洁度 + 惯用度）才收敛到「既不破坏正确性又提升可读性」。

**落地动作**：让 AI 改反编译输出时，**必须给可验证的反馈**（重新编译 / 单元测试 / 结构相似度），
且绝不能用单一指标 —— 否则模型会为了指标把代码改得更难读。

---

## 痛点 2：符号被 strip，全是 `sub_4012F0`

| 工作 | 出处 | 能救什么 |
|---|---|---|
| **Beyond Classification: Inferring Function Names in Stripped Binaries via Domain Adapted LLMs** | NDSS 2025 | 用领域适配的语言模型推断有意义的函数名 |
| **DEBIN** | CCS 2018 | 预测被 strip 的调试信息（变量名/类型） |
| **EKLAVYA** | USENIX Sec 2017 | 从 strip 二进制恢复函数类型签名 |
| **DIRTY** [有代码] | USENIX Sec 2022（杰出论文）<br>`github.com/CMUSTRUDEL/DIRTY` | 为反编译输出补变量名与类型 |
| **Augmenting Decompiler Output with Learned Variable Names and Types**（同上） | — | 同上 |
| **Idioms** | NDSS 2026 | 微调本地小模型，让反编译输出直接带用户自定义类型定义；提出 REALTYPE 数据集 |

**补充**：工程上比论文更快的是**找符号富矿** —— Go 的 buildinfo（`go version -m <bin>`）、
Rust 的 panic 消息、ObjC 的元数据（`class-dump`）、.NET 的元数据表、Java 的常量池。
这些不需要任何模型，一条命令就能拿到。

---

## 痛点 3：「这段代码是不是别人写过的」

二进制代码相似性检测（BCSD）。这是**复用优先**策略的学术基础。

| 年份 | 工作 | 核心思路 |
|---|---|---|
| 2017 | **Genius / Gemini**（CCS'17） | 图嵌入做跨平台相似度检测，开山作 |
| 2019 | **Asm2Vec**（IEEE S&P'19） | 指令序列表示学习，抗混淆与编译优化 |
| 2019 | **SAFE**（DIMVA） | 自注意力函数嵌入 |
| 2020 | **DeepBinDiff**（NDSS'20） | 程序级 ICFG + k-hop 贪心匹配基本块 |
| 2021 | **PalmTree**（CCS'21） | 指令嵌入预训练模型 |
| 2021 | **TREX**（IEEE TSE） | 从微执行轨迹学执行语义 |
| 2022 | **jTrans**（ISSTA'22） | jump-aware Transformer：把跳转目标编进位置嵌入 + 跳转目标预测任务。真实漏洞检索召回率约为此前 SOTA 的两倍 |
| 2024 | **BinBert**（IEEE TDSC） | 可执行感知的 Transformer |
| 2025 | **Nova**（ICLR'25） | 层次化注意力 + 对比学习 |
| 2026 | **Selective Knowledge Distillation**（ACL'26） | 把 LLM 的语义能力蒸馏进高效的相似度模型 |

**工程结论（比选型更重要）**：场景决定能不能用调用图。
- **跨架构 XA / 跨编译器 XC / 跨二进制 XB**：调用图会被内联、函数拆分打乱，甚至完全无关 → **别依赖它**。
- **跨版本 XV**：函数语义与结构上下文都稳定 → **可以放心依赖上下文信息**（这是 BinDiff 在补丁比对里好用的原因）。

工业实现：**BinaryAI**（腾讯科恩）把这套做成函数级源码检索服务，见 `ecosystem.md`。

---

## 痛点 4：二进制边界与结构本身都识别不准

- **XDA**（NDSS 2021）：用迁移学习做准确、鲁棒的反汇编（指令边界判定），是后续很多工作的基础。
- **Coda**（NeurIPS 2019）：端到端神经程序反编译器。

**工程含义**：反汇编器的边界判定会出错，所以**不要盲信反汇编结果**。
用 `re.py entropy <目标>` 找高熵区、用 `re.py diff A B` 做差分，都是不依赖反汇编器的独立验证手段。

---

## 痛点 5：AI 驱动逆向到底行不行？现在的评测怎么说

这一节决定「该给 AI 多大自主权」。

| Benchmark | 出处 | 测什么 |
|---|---|---|
| **CrackMeBench** | arXiv:2605.10597 | 用确定性评分测 tool-using agent 做 clean-room 二进制逆向 |
| **CREBench** | COLM 2026<br>`github.com/wangyu-ovo/CREBench` | 密码学二进制逆向四级难度：从算法识别到 flag 恢复 |
| **REBENCH** | AIWare 2026<br>arXiv:2604.27319 | strip 二进制的类型与名字恢复，字节级对齐 ground truth，抗污染 |
| **REFORGE** | arXiv:2607.07738 | 反编译函数命名能力，显式处理 binary-to-source 对齐不确定性 |
| **Decompile-Bench** | NeurIPS 2025 D&B | 百万级真实 binary-source 函数对 |
| **DecompileBench** | ACL Findings 2025 | 真实场景下的反编译器评估 |
| **The Next Challenge for Agentic Cybersecurity** | arXiv:2608.11469 | 262 个抗污染实例，来自 19 个私有真实规模程序，带分层反分析防护 |
| **JsDeObsBench** | ACM CCS 2025 | LLM 做 JS 反混淆的能力 |

**两份必须读的「降温」文献**：

1. **《Decompiling the Synergy: An Empirical Study of Human–LLM Teaming in Software Reverse Engineering》**（NDSS 2026）
   —— 153 名从业者调研 + 48 名参与者 109 小时实测。这是目前**最扎实的真实工作流数据**，
   回答的是「人 + LLM 到底怎么配合才真的更快」。

2. **《Challenges and Future Directions in Agentic Reverse Engineering Systems》**（arXiv:2604.14317）
   —— 系统梳理静态/动态/混合 agent 的失败模式：**token 预算、对抗混淆、缺少程序护栏**。
   结论是：即便最强系统，在面对混淆、时序、冷门架构的真实场景时仍然会失败。

3. **《Automatically Attacking Software Reverse Engineering AI Agents》**（arXiv:2605.30667）
   —— 攻击者把对抗提示藏在二进制字符串里（不影响程序功能），即可通过提示注入
   **误导 LLM 驱动的反汇编/反编译流水线**。这是本技能「AI 结论必须复核」这条硬约束的直接依据。

**另有 BINREX**（USENIX Security 2026）：语义检索 + 可验证的 IDAPython 子任务，走的是「可验证推理」路线。

---

## 痛点 6：私有协议怎么逆

见 `ecosystem.md` 5.2 节的完整清单。学术脉络一句话：

- 早期（2004–2008）**流量驱动**：PIP/Discoverer 用序列比对（Needleman-Wunsch）分字段。
- **Polyglot**（2007，Caballero 等）开创**程序驱动**路线：给输入每个字节打独立污点、记录传播、
  按上下文向量聚类 → 合并字段 → 输出格式模板。**不需要任何网络流量**，加密场景也能用。
- **AutoFormat**（2008，Lin 等）在其上加上下文感知，能恢复**嵌套结构**（Polyglot 只能出扁平结构）。
- **Tupni**（2008）识别重复序列与字段约束，可接 ShieldGen 自动生成攻击签名。
- **Prospex**（2009）用三个度量（字段序列距离 / 执行轨迹相似度 / 系统影响）做消息分类，再学状态机。
- **MACE**（2010–2011）用符号执行推断文法。
- **NetPlier**（近年）：多序列比对 + 概率推断关键词，输入 pcap。
- 完整 58 篇清单：`github.com/zha0/PRE-list`。

**选型**：有 pcap → NetPlier/Netzob（快）；无流量或加密 → Polyglot/AutoFormat 思路（动态污点，慢但唯一解）。

---

## 落到本技能的约束（已编码进 `plan` 输出）

1. **复用优先**：先做成分识别与源码匹配，命中开源组件就别从零逆。
2. **比对优先**：有旧版本用 BinDiff/Diaphora 移植名字、注释、结构体，省掉最耗时的重新命名。
3. **AI 只做初筛**：LLM 擅长命名与解释；但会被提示注入投毒、会刷单指标、长函数会丢失语义。
   所有 AI 输出**必须回工具复核**，安全结论不允许由模型单独给出。
4. **给 AI 可验证反馈**：能重编译就重编译，能跑测试就跑测试，且用复合指标而非单一指标。
