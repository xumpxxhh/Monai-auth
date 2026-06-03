---
name: git-commit
description: >
  当用户要求生成 git commit message、写提交信息、帮我提交代码、或描述改动并需要生成符合规范的 commit 时使用。
  **触发条件**：用户说"帮我写个 commit"、"生成 commit message"、"git commit"、"提交代码"、
  "帮我写提交信息"，或通过 git diff / git status 提供改动内容并要求生成 commit。
  **不要触发**：纯粹的 git 操作咨询（如"怎么回退 commit"）、代码审查（使用 /code-review）、
  通用写作任务、或不涉及生成 commit message 的 git 操作。
---

# Git Commit 生成

根据用户提供的代码改动（git diff、git status、文件变更描述），分析改动内容并生成符合规范的 git commit message。

## 工作流程

1. **收集改动信息**：接收用户的改动描述、git diff 输出、或 git status 文件列表。
   若用户未提供足够信息，主动运行 `git diff --staged` 和 `git diff` 获取暂存区和工作区的变更。

2. **分析改动内容**：从改动中提取：
   - 改动涉及的功能模块或文件路径
   - 改动的类型（新增功能、修复、重构、配置变更、文档更新等）
   - 改动的核心意图和影响范围
   - 关联的功能或需求背景

3. **确定 type 和 scope**：
   - 根据改动性质匹配 type（feat/fix/chore/docs/refactor/temp）
   - 从文件路径或模块名推断 scope（如 auth、config、ip、static 等）
   - 若无法确定明显的模块归属，可省略 scope

4. **撰写 subject**：
   - 用简洁中文描述改动结果
   - 说明"做了什么"，不写"在做什么"
   - 长度控制在 8~30 个字
   - 术语可保留英文（如 token、CORS、API）
   - 不加句号、感叹号等结尾标点

5. **生成并确认**：输出候选 commit message，询问用户是否需要调整措辞或 type/scope。

## Commit 格式规范

所有生成的 commit message 必须严格遵循以下格式：

```
<type>(<scope>): <subject>
```

详细规范见 `references/commit-rules.md`，核心约束：

| 字段 | 要求 |
|------|------|
| type | 必填，小写英文：feat / fix / chore / docs / refactor / temp |
| scope | 建议填写，使用真实模块名，与目录/包名一致；无明确归属时可省略 |
| subject | 必填，简洁中文，8~30 字，说明改动结果，无结尾标点 |
| 冒号 | 半角 `:` 后跟一个空格 |
| 一次提交 | 只表达一个主要意图 |

## 推荐示例

- `feat(auth): 增加 PKCE 保护并完善授权码流程`
- `feat(ip): 调整 IP 访问限制规则`
- `feat(static): 增加跨域缓存头配置`
- `fix(auth): 修复密码重置邮件偶发收不到的问题`
- `chore(config): 调整环境与服务配置`
- `docs: 更新 API 文档`
- `refactor(auth): 抽取 token 解析逻辑`

## 注意事项

- 生成前必须查看改动内容，不要凭空猜测 commit message。
- 若改动涉及多个不相关的意图，建议拆分为多个 commit 分别提交。
- 历史笔误纠偏：若仓库历史中出现过 `ath`（应为 `auth`）、`doce`（应为 `docs`）、全角冒号等，生成时统一纠正。
- 如用户已有 `git add` 暂存的内容，优先分析暂存区（`--staged`）。
- 若用户要求直接提交，使用 `git commit -m "<message>"` 执行，提交前展示 message 供确认。
