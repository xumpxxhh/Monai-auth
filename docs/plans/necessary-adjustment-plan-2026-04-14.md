# monai-auth 必要调整计划

## 1. 目标与范围

### 1.1 目标

- 在不扩展新业务功能的前提下，优先消除上线阻断风险（安全、可测试、可运维）。
- 建立最小可持续交付基线：代码可测、文档一致、发布可回归。

### 1.2 范围

- 纳入：鉴权主链路（登录、刷新、SSO 换码）、测试与 CI 基线。
- 暂不纳入：完整 gRPC 能力建设、新业务接口扩展、大规模架构重构。

## 2. 分阶段执行计划

## 2.1 P0

### 任务 P0-1：`client_secret` 改常量时间比较

- 原因：当前普通字符串比较存在时序攻击风险。
- 目标：所有敏感密钥比较统一使用 `crypto/subtle.ConstantTimeCompare`。
- 主要改动：
  - `internal/transport/http/handlers.go`
- 验收标准：
  - `TokenHandler` 中不再出现普通 `==` 比较 `client_secret`。
  - 正确密钥通过，错误密钥返回 `401 INVALID_CLIENT`。

### 任务 P0-2：文档与接口参数对齐

- 原因：SSO 文档与实现存在偏差，尤其是 `/request-login` 的 PKCE 参数、`/token-by-code` 的 `redirect_uri` 与 `code_verifier`。
- 目标：接口文档与代码行为一致，避免联调失败。
- 主要改动：
  - `docs/apis/api.md`
- 验收标准：
  - 文档示例包含完整必填字段与 PKCE 参数。
  - 按文档请求可直接通过接口校验。

## 2.2 P1

### 任务 P1-1：恢复 `go test ./...` 可执行

- 原因：`scripts` 下多个 `main` 同包导致全量测试失败。
- 目标：全仓 `go test ./...` 成功执行。
- 主要改动（二选一）：
  - 方案 A：将 `scripts` 中每个脚本拆分为独立子目录。
  - 方案 B：为脚本添加 build tag，使其不进入默认测试构建。
- 验收标准：
  - 根目录执行 `go test ./...` 通过。
  - 脚本仍可通过指定方式手动执行。

### 任务 P1-2：补最小回归测试

- 原因：当前关键鉴权逻辑无自动化测试，回归风险高。
- 目标：覆盖主路径和关键失败分支。
- 主要改动建议：
  - 新增 `internal/transport/http/*_test.go`
  - 新增 `internal/auth/*_test.go`
- 最小覆盖点：
  - 登录成功/失败
  - refresh 轮换成功/失败
  - SSO 授权码兑换（含 PKCE 失败）
  - `redirect_uri` 白名单拒绝
- 验收标准：
  - 新增测试可稳定通过并在回归中拦截典型错误。

### 任务 P1-3：建立最小 CI 检查

- 目标：所有提交至少经过基础质量门禁。
- 内容：
  - `go test ./...`
  - `go vet ./...`
  - （可选）`golangci-lint run`
- 验收标准：
  - CI 失败可阻断不合格变更合入。

### 任务 P1-4：启动与发布说明标准化

- 目标：降低环境差异导致的启动失败。
- 主要改动：
  - 新增或更新 `README.md`（若暂未维护则新增）
  - 统一 `start.sh/restart.sh/stop.sh` 使用约束（Linux 场景）
  - 补充 Windows 本地开发命令说明
- 验收标准：
  - 新成员按文档可在本地完成启动、登录、刷新链路验证。

## 2.3 P2

### 任务 P2-1：角色模型持久化

- 目标：将 `role` 从硬编码改为数据库真实字段，支持 RBAC 扩展。
- 主要改动：
  - `internal/repository/mysql/model.go`
  - `internal/repository/mysql/user_repo.go`
  - 对应数据库迁移脚本

### 任务 P2-2：JWT 标准声明增强

- 目标：补充 `iss/aud/jti`，为跨服务校验与撤销机制打基础。
- 主要改动：
  - `internal/auth/token.go`
  - `internal/auth/service.go`（如需接入黑名单校验）

### 任务 P2-3：gRPC 能力决策

- 目标：避免长期“空占位”。
- 选项：
  - 真正落地 proto + server + 验证接口；
  - 若短期无需求，移除占位代码与文档声明。
- 相关文件：
  - `internal/transport/grpc/server.go`
  - `api/proto/auto.proto`

### 任务 P2-4：State/Code Store 可扩展化

- 目标：支持多实例部署，避免内存存储导致 SSO 随机失败。
- 主要改动：
  - `internal/auth/statestore.go`
  - `internal/auth/codestore.go`
  - 增加 Redis 实现与配置项

## 3. 验收清单（上线前）

- 安全：
  - `client_secret` 比较为常量时间实现。
- 工程：
  - `go test ./...` 通过。
  - 关键鉴权链路存在自动化测试。
  - CI 质量门禁生效。
- 联调：
  - 登录、刷新、SSO 授权码兑换、上传链路全部通过。
  - 文档示例可直接复现成功请求。

## 5. 风险与回滚策略

- 风险 1：测试改造影响脚本执行习惯。
  - 策略：在文档中明确脚本新入口与兼容命令。

## 6. 计划完成定义（DoD）

- P0 全部完成并通过预发验证，方可进入上线窗口。
- P1 全部完成并稳定运行至少 1 个迭代，方可进入 P2 架构改造。
- 任何新增接口或安全改动，必须同步更新 `docs/apis/api.md`。
