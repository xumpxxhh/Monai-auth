#!/usr/bin/env node
/**
 * Git Commit Skill 质量门禁脚本
 *
 * 检查 skill 包的结构完整性和最小质量标准。
 * 用法: node skill_quality_gate.js [skill_directory]
 */

const fs = require("node:fs");
const path = require("node:path");

const COLORS = {
  RED: "\x1b[91m",
  GREEN: "\x1b[92m",
  YELLOW: "\x1b[93m",
  CYAN: "\x1b[96m",
  RESET: "\x1b[0m",
  BOLD: "\x1b[1m",
};

function ok(msg) {
  return `${COLORS.GREEN}[PASS]${COLORS.RESET} ${msg}`;
}

function fail(msg) {
  return `${COLORS.RED}[FAIL]${COLORS.RESET} ${msg}`;
}

function warn(msg) {
  return `${COLORS.YELLOW}[WARN]${COLORS.RESET} ${msg}`;
}

function info(msg) {
  return `${COLORS.CYAN}[INFO]${COLORS.RESET} ${msg}`;
}

class QualityGate {
  constructor(skillDir) {
    this.skillDir = path.resolve(skillDir);
    this.errors = [];
    this.warnings = [];
    this.passes = [];
  }

  checkSkillMd() {
    const skillMd = path.join(this.skillDir, "SKILL.md");
    if (!fs.existsSync(skillMd)) {
      this.errors.push(fail("SKILL.md 不存在"));
      return false;
    }

    const content = fs.readFileSync(skillMd, "utf8");
    const fmMatch = content.match(/^---\s*\r?\n([\s\S]*?)\r?\n---/);
    if (!fmMatch) {
      this.errors.push(fail("SKILL.md 缺少 YAML frontmatter"));
      return false;
    }

    const fm = fmMatch[1];
    const checks = {
      name: /^name:\s*\S/m,
      description: /^description:\s*\S/m,
    };

    let allOk = true;
    for (const [field, pattern] of Object.entries(checks)) {
      if (!pattern.test(fm)) {
        this.errors.push(fail(`SKILL.md frontmatter 缺少 '${field}' 字段`));
        allOk = false;
      }
    }

    if (allOk) {
      this.passes.push(ok("SKILL.md 格式正确，包含必要元数据"));
    }

    // 检查 description 中是否包含触发和反触发规则
    const desc = fm.match(/^description:\s*>?\s*(.+)$/m)?.[1] ?? "";
    const fullDesc = content.match(/^description:\s*>\s*\n([\s\S]*?)(?=\n\S|$)/m)?.[1] ?? desc;

    if (content.includes("触发条件") || content.includes("should trigger")) {
      this.passes.push(ok("description 包含正向触发规则"));
    } else {
      this.warnings.push(warn("description 建议明确正向触发条件"));
    }

    if (content.includes("不要触发") || content.includes("Do not use")) {
      this.passes.push(ok("description 包含负向触发边界"));
    } else {
      this.warnings.push(warn("description 建议包含负向触发边界"));
    }

    // 检查必要章节
    const requiredSections = ["工作流程", "Commit 格式规范", "注意事项"];
    for (const section of requiredSections) {
      if (content.includes(section)) {
        this.passes.push(ok(`SKILL.md 包含 '${section}' 章节`));
      } else {
        this.warnings.push(warn(`SKILL.md 建议包含 '${section}' 章节`));
      }
    }

    // 检查格式规范是否完整
    const formatChecks = ["type", "scope", "subject", "feat", "chore", "docs", "fix", "refactor"];
    const missingFormat = formatChecks.filter((term) => !content.includes(term));
    if (missingFormat.length > 0) {
      this.warnings.push(warn(`格式规范可能缺少关键术语: ${missingFormat.join(", ")}`));
    } else {
      this.passes.push(ok("格式规范包含所有 type 定义"));
    }

    return allOk;
  }

  checkCommitRules() {
    const rulesMd = path.join(this.skillDir, "references", "commit-rules.md");
    if (!fs.existsSync(rulesMd)) {
      this.errors.push(fail("references/commit-rules.md 不存在"));
      return false;
    }

    const content = fs.readFileSync(rulesMd, "utf8");

    const requiredSections = [
      "格式约束",
      "type 取值",
      "scope 命名",
      "subject 编写规范",
    ];
    const missing = requiredSections.filter((sec) => !content.includes(sec));
    if (missing.length > 0) {
      this.warnings.push(warn(`commit-rules.md 缺少章节: ${missing.join(", ")}`));
    } else {
      this.passes.push(ok("commit-rules.md 包含所有必要章节"));
    }

    // 检查是否包含纠偏说明
    if (content.includes("ath") && content.includes("auth")) {
      this.passes.push(ok("commit-rules.md 包含历史笔误纠偏说明"));
    } else {
      this.warnings.push(warn("commit-rules.md 建议包含历史笔误纠偏说明"));
    }

    // 检查 good/bad subject 示例
    if (content.includes("好的 subject") || content.includes("不好的 subject")) {
      this.passes.push(ok("commit-rules.md 包含 subject 正反示例"));
    } else {
      this.warnings.push(warn("commit-rules.md 建议包含 subject 正反示例"));
    }

    return true;
  }

  checkRubric() {
    const rubricMd = path.join(this.skillDir, "references", "rubric.md");
    if (!fs.existsSync(rubricMd)) {
      this.errors.push(fail("references/rubric.md 不存在"));
      return false;
    }

    const content = fs.readFileSync(rubricMd, "utf8");

    const requiredDims = [
      "格式规范性",
      "type 准确性",
      "scope 合理性",
      "subject 质量",
      "意图单一性",
    ];
    const missing = requiredDims.filter((dim) => !content.includes(dim));
    if (missing.length > 0) {
      this.warnings.push(warn(`评分标准可能缺少维度: ${missing.join(", ")}`));
    } else {
      this.passes.push(ok("评分标准包含全部五个评估维度"));
    }

    if (content.includes("4 分") && content.includes("0 分")) {
      this.passes.push(ok("评分标准包含完整的 0-4 分等级描述"));
    }

    if (content.includes("通过标准")) {
      this.passes.push(ok("评分标准定义了通过标准"));
    } else {
      this.warnings.push(warn("建议明确'通过标准'"));
    }

    if (content.includes("纠偏检查项")) {
      this.passes.push(ok("评分标准包含纠偏检查项"));
    }

    return true;
  }

  checkEvalCases() {
    const casesFile = path.join(this.skillDir, "assets", "eval-cases.json");
    if (!fs.existsSync(casesFile)) {
      this.errors.push(fail("assets/eval-cases.json 不存在"));
      return false;
    }

    let data;
    try {
      data = JSON.parse(fs.readFileSync(casesFile, "utf8"));
    } catch (error) {
      this.errors.push(fail(`eval-cases.json JSON 解析失败: ${error.message}`));
      return false;
    }

    // 检查 positive_cases
    for (const key of ["positive_cases", "negative_cases", "eval_cases"]) {
      if (!data[key] || !Array.isArray(data[key]) || data[key].length === 0) {
        this.errors.push(fail(`${key} 缺失或为空`));
      } else {
        this.passes.push(ok(`${key} 存在 (${data[key].length} 条)`));
      }
    }

    const cases = data.eval_cases ?? [];

    // 检查 eval_cases 结构
    const requiredFields = ["id", "name", "input", "checks"];
    const idsSeen = new Set();
    let allOk = true;

    for (let i = 0; i < cases.length; i += 1) {
      const c = cases[i];
      for (const field of requiredFields) {
        if (!(field in c)) {
          this.errors.push(fail(`用例 #${i + 1} 缺少 '${field}' 字段`));
          allOk = false;
        }
      }

      const caseId = c.id ?? "";
      if (idsSeen.has(caseId)) {
        this.errors.push(fail(`用例 ID '${caseId}' 重复`));
        allOk = false;
      }
      idsSeen.add(caseId);

      const checks = c.checks ?? {};
      if (!("format_check" in checks)) {
        this.warnings.push(warn(`用例 '${caseId}' 建议添加 format_check（正则格式校验）`));
      }
    }

    if (allOk) {
      this.passes.push(ok("所有评测用例结构完整，ID 唯一"));
    }

    // 统计难度分布
    const difficulties = cases.map((c) => c.difficulty ?? "unknown");
    const diffCounts = {};
    for (const d of difficulties) {
      diffCounts[d] = (diffCounts[d] ?? 0) + 1;
    }
    this.passes.push(ok(`难度分布: ${JSON.stringify(diffCounts)}`));

    // 检查是否有覆盖纠偏场景的用例
    const hasTypoCase = cases.some((c) =>
      (c.checks.type_must_not_be && c.checks.type_must_not_be.includes("ath")) ||
      (c.checks.no_fullwidth_colon === true && c.name && c.name.includes("笔误"))
    );
    if (hasTypoCase) {
      this.passes.push(ok("包含历史笔误纠偏测试用例"));
    } else {
      this.warnings.push(warn("建议添加笔误纠偏场景的评测用例"));
    }

    // 检查多意图拆分用例
    const hasMultiIntentCase = cases.some((c) => c.checks.should_warn_split === true);
    if (hasMultiIntentCase) {
      this.passes.push(ok("包含多意图拆分建议测试用例"));
    } else {
      this.warnings.push(warn("建议添加多意图拆分场景的评测用例"));
    }

    return allOk;
  }

  run() {
    console.log(`\n${COLORS.BOLD}=== Git Commit Skill 质量门禁 ===${COLORS.RESET}\n`);
    console.log(info(`检查目录: ${this.skillDir}\n`));

    console.log(`${COLORS.BOLD}[1/4] 检查 SKILL.md${COLORS.RESET}`);
    this.checkSkillMd();
    console.log("");

    console.log(`${COLORS.BOLD}[2/4] 检查 commit-rules.md${COLORS.RESET}`);
    this.checkCommitRules();
    console.log("");

    console.log(`${COLORS.BOLD}[3/4] 检查评分标准 (rubric.md)${COLORS.RESET}`);
    this.checkRubric();
    console.log("");

    console.log(`${COLORS.BOLD}[4/4] 检查评测用例 (eval-cases.json)${COLORS.RESET}`);
    this.checkEvalCases();
    console.log("");

    console.log(`${COLORS.BOLD}${"─".repeat(50)}${COLORS.RESET}`);
    console.log(`${COLORS.BOLD}检查结果汇总${COLORS.RESET}`);
    console.log("─".repeat(50));

    for (const p of this.passes) {
      console.log(`  ${p}`);
    }
    for (const w of this.warnings) {
      console.log(`  ${w}`);
    }
    for (const e of this.errors) {
      console.log(`  ${e}`);
    }

    console.log(`\n  通过: ${this.passes.length}`);
    console.log(`  警告: ${this.warnings.length}`);
    console.log(`  错误: ${this.errors.length}`);

    if (this.errors.length > 0) {
      console.log(`\n${COLORS.RED}${COLORS.BOLD}质量门禁未通过！请修复以上错误后重试。${COLORS.RESET}`);
      return 1;
    }

    console.log(`\n${COLORS.GREEN}${COLORS.BOLD}质量门禁通过！${COLORS.RESET}`);
    return 0;
  }
}

function main() {
  const skillDir = process.argv[2] ?? path.resolve(__dirname, "..");
  const gate = new QualityGate(skillDir);
  process.exit(gate.run());
}

main();
