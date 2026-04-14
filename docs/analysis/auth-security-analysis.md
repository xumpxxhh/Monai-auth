# 鉴权逻辑安全分析报告

> 分析时间：2026-03-19  
> 分析范围：`monai-auth` 项目全部鉴权相关代码

---

## 一、整体架构概览

项目采用标准的分层架构，鉴权逻辑职责清晰：

```
HTTP 请求
    │
    ▼
internal/transport/http/handlers.go   ← HTTP 传输层（请求解析、Cookie、响应）
    │
    ▼
internal/auth/service.go              ← 业务逻辑层（登录/注册/Token 签发/Refresh 轮换）
    │       auth/token.go             ← JWT 签发与验证
    │       auth/statestore.go        ← SSO State 内存存储（带 TTL）
    │       auth/codestore.go         ← SSO 授权码内存存储（带 TTL）
    ▼
internal/domain/                      ← 领域模型层（接口契约、DTO、错误定义）
    │
    ▼
internal/repository/mysql/            ← 数据持久化层（GORM + MySQL）
```

**核心鉴权机制**：

- **双 Token 机制**：Access Token（JWT，2 小时）+ Refresh Token（32 字节随机 hex，7 天）
- **SSO 授权码流程**：仿 OAuth2 Authorization Code Flow，支持子应用单点登录
- **Token 轮换（Rotation）**：每次刷新销毁旧 Refresh Token，生成新的，防止重放攻击

---

## 二、设计合理之处

### 2.1 Cookie 安全属性完整

Access Token 和 Refresh Token 均以 `HttpOnly + Secure + SameSite=Lax` 设置，有效防御 XSS 窃取 Cookie 和 CSRF 跨站请求伪造。

Refresh Token Cookie 额外限制 `Path=/api/v1/auth/refresh`，仅在刷新接口时浏览器才会携带，进一步缩小暴露面。

### 2.2 Refresh Token 轮换正确实现

每次调用 `/refresh` 接口时：

1. 从数据库查找并验证旧 Refresh Token（含过期校验）
2. 签发新的 Access Token
3. **物理删除**旧 Refresh Token
4. 生成并持久化新的 Refresh Token

轮换机制可检测 Token 重放：若旧 Token 被攻击者先于用户使用，用户下一次刷新时会因 Token 已不存在而被强制登出。

### 2.3 bcrypt 密码哈希

注册时使用 `bcrypt.GenerateFromPassword(DefaultCost)` 哈希，登录时 `bcrypt.CompareHashAndPassword()` 验证，符合业界标准。密码最短 6 位校验，邮箱格式正则校验。

### 2.4 SSO 授权码一次性消费

`StateStore.GetAndConsume()` 和 `CodeStore.GetAndConsume()` 取出即删除，State TTL 10 分钟，Code TTL 5 分钟，有效防止授权码重放攻击。

### 2.5 CORS 来源白名单

`CORSMiddleware` 基于配置的 `allowed_origins` 列表校验请求来源，而非开放 `*`（静态资源路由除外，详见问题 1）。

### 2.6 文件上传路径安全处理

上传接口通过 `filepath.Base()` 提取文件名、`safeUsernameRe` 正则清洗用户名，防止路径穿越攻击写入任意目录。

---

## 三、风险与现状

### ✅ 已修复或已缓解项

#### 问题 1：静态文件服务暴露整个工作目录（已修复）

**位置**：`cmd/auth-server/server.go`

历史风险是 `http.FileServer(http.Dir("."))` 以进程当前工作目录为根目录，可能公开配置和源码文件。当前代码已改为仅暴露 `uploads` 目录：

```go
staticHandler := http.StripPrefix("/static/uploads", cacheControlHandler(
    http.FileServer(http.Dir("./uploads")),
    staticCacheMaxAge,
))
r.Handle("/static/uploads/*", staticCORSHandler(staticHandler))
```

当前对外只开放 `/static/uploads/*`，不会直接暴露 `configs`、`go.mod` 等工作目录文件。

---

#### 问题 2：SSO 流程中 `redirect_uri` 未校验白名单（已修复）

**位置**：`internal/transport/http/handlers.go` — `SSORequestLoginHandler`

历史风险是攻击者可伪造请求，将受害者的授权码重定向到恶意域名，例如：

```
GET /api/v1/auth/request-login?client_id=mark-live&redirect_uri=https://evil.com/steal
```

用户登录后授权码会被发送至 `evil.com`，攻击者随即可用 code 换取 token。

当前实现已在写入 `StateStore` 之前校验 `redirect_uri` 是否命中对应客户端白名单：

```go
var client *Client
for i := range h.Clients {
    if h.Clients[i].ClientID == clientID {
        client = &h.Clients[i]
        break
    }
}
if client == nil {
    writeError(w, "INVALID_CLIENT", "unknown client_id", http.StatusBadRequest, "")
    return
}
if !h.isRedirectURIAllowed(clientID, redirectURI) {
    writeError(w, "INVALID_REDIRECT_URI", "redirect_uri is not allowed for this client", http.StatusBadRequest, "")
    return
}
```

---

#### 问题 3：敏感配置明文存储（可能随代码库泄露）

**位置**：`configs/config.yaml`

```yaml
jwt_secret: "your_very_secret_key_for_jwt_signing"
client_secret: "your_client_secret_for_money"
password: admin222333
```

JWT 密钥、客户端密钥、数据库密码均以明文写入配置文件。若该文件被提交至代码仓库，所有密钥将完全暴露。

**修复方案**：通过环境变量覆盖敏感字段，并在 `.gitignore` 中排除包含真实密钥的配置文件：

```bash
# .env（加入 .gitignore）
MONAI_JWT_SECRET=<真实密钥>
MONAI_DB_PASSWORD=<真实密码>
MONAI_CLIENT_SECRET_MARK_LIVE=<真实客户端密钥>
```

配置加载时优先读取环境变量（Viper 已内置支持 `viper.AutomaticEnv()`）。

---

### 🟠 仍需处理的风险

#### 问题 4：`/token-by-code` 无 client_secret 且无 PKCE 保护（已修复）

**位置**：`internal/transport/http/handlers.go` — `TokenByCodeHandler`

当前实现已经引入 PKCE：`/request-login` 必带 `code_challenge`，`/token-by-code` 必带 `code_verifier`，服务端会校验两者是否匹配。公共客户端不再仅凭 `client_id + code` 换取 token。

剩余建议：若后续要对接更多三方客户端，可补充更明确的 PKCE 文档与联调示例，减少接入错误。

---

#### 问题 5：`client_secret` 比较使用普通字符串比较（时序攻击）

**位置**：`internal/transport/http/handlers.go`

```go
// 当前代码
if client == nil || client.ClientSecret != clientSecret {
```

普通字符串比较的耗时随共同前缀长度增加，攻击者可通过测量响应时间逐字符猜测密钥。

**修复方案**：

```go
import "crypto/subtle"

if client == nil || subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
```

---

#### 问题 6：所有接口均无速率限制（已缓解）

当前路由层已经增加基于 IP 的固定窗口限流：敏感接口使用更严格的频率限制，普通接口使用较宽松阈值，已对暴力破解和撞库风险形成基础防护。

当前实现示意：

```go
sensitive := httptransport.RateLimitMiddleware(10, 15*time.Minute)
r.With(sensitive).Post("/api/v1/auth/login", h.LoginHandler)
```

---

### 🟡 设计缺陷（建议改进）

#### 问题 7：用户角色（Role）无法持久化

**位置**：`internal/auth/service.go`、`internal/repository/mysql/model.go`

注册时 Role 硬编码为 `"standard"`，且 `UserGORM` 模型中缺少 `role` 字段，`mapGORMToDomain()` 始终返回 `"standard"`。这使得 RBAC 权限体系无法实现。

**修复方案**：在 `UserGORM` 和 `users` 表中添加 `role` 字段，允许管理员通过接口修改用户角色。

---

#### 问题 8：StateStore / CodeStore 仅为内存实现，不支持水平扩展

**位置**：`internal/auth/statestore.go`、`internal/auth/codestore.go`

多实例部署时，请求被负载均衡到不同节点，内存中的 state/code 无法共享，SSO 流程将随机失败。

**修复方案**：提供基于 Redis 的实现，通过接口替换：

```go
type RedisStateStore struct { client *redis.Client; ttl time.Duration }
// 实现 StateStore 接口
```

---

#### 问题 9：Refresh Token 明文存储在数据库（已修复）

**位置**：`internal/repository/mysql/refresh_token_repo.go`

当前实现已将 Refresh Token 做 SHA-256 后再入库，不再明文持久化。数据库泄露时，攻击者无法直接复用表中的值作为原始 token。

当前实现示意：

```go
import "crypto/sha256"
import "encoding/hex"

func hashRefreshToken(plain string) string {
    sum := sha256.Sum256([]byte(plain))
    return hex.EncodeToString(sum[:])
}
```

---

#### 问题 10：JWT 缺少标准声明（`iss`、`aud`、`jti`）

**位置**：`internal/auth/token.go`

当前 JWT 仅包含 `user_id`、`role`、`exp`、`iat`，缺少：

- `iss`（颁发者）：多服务环境下无法区分 token 来源，其他服务签发的 token 可能被错误接受
- `aud`（受众）：无法限制 token 的使用范围
- `jti`（JWT ID）：无法实现单个 Access Token 的撤销（黑名单机制前提）

---

#### 问题 11：登出后 Access Token 在过期前仍然有效

`LogoutHandler` 只删除 Refresh Token，Access Token（JWT）是无状态的，无法撤销，登出后最长仍可使用 2 小时。

**缓解方案**：维护一个基于 Redis 的 `jti` 黑名单，`ValidateToken` 时额外检查 `jti` 是否在黑名单中。代价是每次验证多一次 Redis 查询。

---

## 四、综合评分

| 维度               | 状态        | 说明                                  |
| ------------------ | ----------- | ------------------------------------- |
| 整体架构分层       | ✅ 合理     | 职责清晰，接口抽象到位                |
| Cookie 安全属性    | ✅ 完整     | HttpOnly / Secure / SameSite=Lax 齐备 |
| 密码存储           | ✅ 安全     | bcrypt DefaultCost                    |
| Token 轮换         | ✅ 正确     | 旧 Token 物理删除                     |
| 授权码一次性       | ✅ 正确     | GetAndConsume 取出即删                |
| 静态文件服务       | ✅ 已修复   | 当前仅暴露 `/static/uploads/*`        |
| redirect_uri 校验  | ✅ 已修复   | 已校验客户端白名单                    |
| 敏感配置管理       | 🔴 高风险   | 明文密钥可能随代码库泄露              |
| 速率限制           | ✅ 已缓解   | 已增加基于 IP 的基础限流              |
| client_secret 比较 | 🟠 时序漏洞 | 应使用常量时间比较                    |
| 公共客户端安全     | ✅ 已修复   | token-by-code 已接入 PKCE             |
| 角色持久化         | 🟡 不可用   | Role 字段未入库                       |
| 水平扩展能力       | 🟡 受限     | 内存 Store 限制单节点                 |
| Refresh Token 存储 | ✅ 已修复   | 已改为哈希后存储                      |
| JWT 标准声明       | 🟡 不完整   | 缺少 iss / aud / jti                  |
| Access Token 撤销  | 🟡 不支持   | 登出后仍有效，需 jti 黑名单           |

---

## 五、修复优先级建议

```
立即修复（上线前必须）
└── 问题 3：敏感配置改用环境变量

短期修复（1-2 周内）
└── 问题 5：client_secret 常量时间比较

中期改进（架构迭代时）
├── 问题 7：Role 字段持久化
├── 问题 8：StateStore/CodeStore 改为 Redis
├── 问题 10：JWT 添加 iss/aud/jti 声明
└── 问题 11：实现 jti 黑名单支持 Access Token 撤销
```
