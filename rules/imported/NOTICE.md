# 第三方规则来源声明（NOTICE）

本目录下的检测规则由 `scripts/_dev/_capa_import.py` 从以下开源规则库**翻译生成**：

## mandiant/capa-rules

- 来源：https://github.com/mandiant/capa-rules
- 许可证：Apache License 2.0
- 版权：Copyright Mandiant, Inc. 及 capa-rules 各规则原作者
- 处理方式：**机器翻译 + 语义保持化简**，非逐字复制。
  本引擎求不了值的特征按「恒假」参与逻辑化简（绝不放宽 and 语义）；
  不可表达的指令级/基本块级约束降级为函数级**近似求值并逐条标注**
  （见各规则 description 末尾的「近似求值」字样）。
- 署名义务：每条规则保留原作者（meta.authors），并在 meta.references
  中带来源仓库 URL。Apache-2.0 许可证全文见
  https://www.apache.org/licenses/LICENSE-2.0

## 使用注意

1. **近似标注不可忽略**：description 末尾带「近似求值」的规则，其匹配
   范围比原规则宽（指令级/基本块级共现约束被放宽到函数级）。做精确结论
   时应回看原规则的约束条件。
2. 本目录为**生成物**，可由 `_capa_import.py` 重新生成；对翻译结果的
   人工修正请改翻译器而不是直接改本目录，否则重新生成时会丢失。
