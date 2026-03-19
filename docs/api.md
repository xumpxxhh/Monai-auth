# Monai Auth Service API 文档

## 基础信息

- **Base URL**: `http://localhost:8888`（本地环境，默认端口来自 `configs/config.yaml`，以实际配置为准）
- **Content-Type**: 请求/响应均使用 `application/json`（除空响应）
- **鉴权方式**: JWT，默认通过 **HttpOnly Cookie** 传递，同时兼容 `Authorization: Bearer <token>` 头部

### Cookie 说明

| Cookie 名       | 说明                                                            | Path                   |
| --------------- | --------------------------------------------------------------- | ---------------------- |
| `auth_token`    | Access Token（JWT），有效期 2 小时（可配置），用于实际鉴权      | `/`                    |
| `refresh_token` | Refresh Token，有效期 7 天（可配置），仅用于换发新 Access Token | `/api/v1/auth/refresh` |

两个 Cookie 均为 `HttpOnly; Secure; SameSite=Lax`，不可被 JavaScript 读取。`refresh_token` 的 `Path` 限制为 `/api/v1/auth/refresh`，其他接口不会携带，最大程度减少泄露面。

---

## 统一错误响应

所有错误响应均为 JSON：

```json
{
  "code": "SOME_CODE",
  "message": "Human readable message"
}
```

常见 `code`（以接口实际返回为准）：

- `INVALID_REQUEST` / `INVALID_CLIENT` / `INVALID_GRANT`
- `INVALID_CREDENTIALS`
- `UNAUTHORIZED`
- `INVALID_TOKEN`
- `EMAIL_EXISTS`
- `INVALID_EMAIL`
- `PASSWORD_TOO_SHORT`
- `INTERNAL_ERROR`

---

## 接口一览

| 方法 | 路径                       | 说明                                                 |
| ---- | -------------------------- | ---------------------------------------------------- |
| GET  | /api/v1/auth/request-login | 获取登录页完整 URL（SSO）                            |
| POST | /api/v1/auth/login         | 登录，下发 access_token + refresh_token Cookie       |
| POST | /api/v1/auth/logout        | 登出，吊销 refresh_token，清除两个 Cookie            |
| POST | /api/v1/auth/refresh       | 用 refresh_token 换发新的 access_token（Token 轮换） |
| GET  | /api/v1/auth/validate      | 校验 token，返回 id、role                            |
| GET  | /api/v1/auth/me            | 当前用户基本信息                                     |
| POST | /api/v1/auth/token         | 授权码换 token（子应用后端，需 client_secret）       |
| POST | /api/v1/auth/token-by-code | 授权码换 token（前端直连，无 client_secret）         |
| POST | /api/v1/auth/upload        | 上传静态资源（需鉴权，保存至 uploads/用户名/文件名） |
| POST | /api/v1/auth/register      | 注册                                                 |

---

## 双 Token 认证机制

本服务采用 **Access Token + Refresh Token** 双 Token 方案：

```
登录成功
  │
  ├─ access_token (JWT, 2h)   → Cookie: auth_token     Path=/
  └─ refresh_token (随机串, 7d) → Cookie: refresh_token  Path=/api/v1/auth/refresh

正常请求：携带 auth_token Cookie，服务端验证 JWT

access_token 过期后（服务端返回 401）：
  │
  └─ 前端自动 POST /api/v1/auth/refresh（浏览器自动携带 refresh_token Cookie）
        │
        ├─ 成功：返回新的 auth_token + refresh_token（Token 轮换），重试原请求
        └─ 失败：refresh_token 已过期或被吊销，跳转登录页

主动登出：
  └─ POST /api/v1/auth/logout → 服务端从数据库删除 refresh_token → 清除两个 Cookie
```

**前端无感刷新示例（axios）**：

```javascript
axios.interceptors.response.use(null, async (error) => {
  if (error.response?.status === 401 && !error.config._retry) {
    error.config._retry = true;
    try {
      await axios.post("/api/v1/auth/refresh", {}, { withCredentials: true });
      return axios(error.config);
    } catch {
      window.location.href = "/login";
    }
  }
  return Promise.reject(error);
});
```

---

## 0) 单点登录（SSO）— 跨域授权码流程

### 0.1 子应用请求登录

- **URL**: `GET /api/v1/auth/request-login`
- **说明**: 子应用发现用户未登录时调用此接口，获取认证中心登录页的**完整 URL**；**不**做 302 重定向，仅返回 JSON。`state` 由服务端生成并绑定本次请求。

### Query 参数

| 参数         | 必填 | 说明                                 |
| ------------ | ---- | ------------------------------------ |
| client_id    | 是   | 在认证中心注册的客户端 ID            |
| redirect_uri | 是   | 登录成功后要重定向回的子应用回调地址 |

### Success Response

- **200 OK**

```json
{
  "login_url": "/monai/login?client_id=xxx&redirect_uri=xxx&state=xxx"
}
```

- `login_url` 为认证中心登录页的完整路径，其中 `state` 由服务端生成（约 10 分钟有效），子应用或前端需跳转到该 URL 让用户登录；登录页提交时需将 URL 中的 `state` 以 `server_state` 字段提交给 `POST /api/v1/auth/login`。

### 错误响应

- **400**：缺少 `client_id` 或 `redirect_uri`。

---

### 0.2 认证中心登录

用户在认证中心登录页（即 0.1 返回的 `login_url`）输入账号密码，提交到 `POST /api/v1/auth/login`。请求体需包含：

- `email`、`password`
- **SSO 必带**：`server_state`（登录页 URL 中的 `state` 参数，供服务端取回 client_id/redirect_uri）

登录成功后，认证中心**不**做 302，而是返回 JSON，包含子应用回调的完整 URL：`{ "redirect_url": "https://子应用/callback?code=xxx&state=xxx" }`，其中 `state` 与登录页 URL 中的一致；前端或子应用收到后自行跳转。**不**在 URL 中带 token，仅带一次性授权码。

---

### 0.3 用授权码换取 Token（仅子应用后端调用）

- **URL**: `POST /api/v1/auth/token`
- **说明**: **必须由子应用的服务端调用**，禁止由前端/浏览器直接请求。前端只负责把回调 URL 中的 `code` 交给子应用后端（例如请求子应用自己的 `/api/callback?code=xxx`）；子应用后端再携带 `client_secret` 请求本接口换取 `access_token` 和 `user_id`，并在自身域名下写 Cookie 或把 JWT 返回给前端。`client_secret` 仅子应用后端持有，不得暴露给前端。

### Request Body（application/x-www-form-urlencoded 或 application/json）

| 参数          | 必填 | 说明                                                           |
| ------------- | ---- | -------------------------------------------------------------- |
| grant_type    | 是   | 固定为 `authorization_code`                                    |
| code          | 是   | 前端从回调 URL 取到后交给后端的授权码（一次性、约 5 分钟有效） |
| client_id     | 是   | 客户端 ID                                                      |
| client_secret | 是   | 客户端密钥（**仅子应用后端持有并在此请求中携带**，前端不参与） |
| redirect_uri  | 否   | 若传则需与颁发 code 时的 redirect_uri 一致                     |

### Success Response

- **200 OK**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 7200,
  "user_id": 123
}
```

### 错误响应

- **400**：`grant_type` 非 `authorization_code`，或缺少必填参数，或 `code` 无效/过期、`redirect_uri` 不匹配等（`INVALID_GRANT`）。
- **401**：`client_id` / `client_secret` 错误（`INVALID_CLIENT`）。

---

### 0.4 前端直连：用 code 换 token（无子应用后端时）

- **URL**: `POST /api/v1/auth/token-by-code`
- **说明**: 没有子应用后端时，前端可直接用登录成功后拿到的凭证换取 token。登录接口在 SSO 流程下会返回 `{"redirect_url": "https://xxx/callback?code=xxx&state=xxx"}`，前端从 `redirect_url` 中解析出 `code`，再携带 `client_id` 和 `code` 调用本接口，**无需** `client_secret`。成功后设置 `auth_token` 和 `refresh_token` 两个 **HttpOnly Cookie**，token 不通过 body 返回；若需用户信息可再调 `GET /api/v1/auth/me`。

### Request Body

```json
{
  "client_id": "mark-live",
  "code": "从 redirect_url 的 query 中解析出的 code"
}
```

### Success Response

- **200 OK**

```json
{ "status": "ok" }
```

响应头会设置两个 Cookie：`auth_token`（access token）和 `refresh_token`。

### 错误响应

- **400**：缺少 `client_id` 或 `code`，或 `code` 无效/过期、或 `code` 并非该 `client_id` 颁发（`INVALID_GRANT`）。

---

## 1) 用户登录

- **URL**: `POST /api/v1/auth/login`
- **说明**: 邮箱+密码登录。若请求体带 **server_state**（SSO 流程），登录成功后在 **body** 中返回子应用回调地址 `redirect_url`（不 302）；否则设置 `auth_token` 和 `refresh_token` 两个 **HttpOnly Cookie** 并返回 `{"status": "ok"}`。

### Request Body

```json
{
  "email": "user@example.com",
  "password": "password123",
  "username": "optional",
  "server_state": "SSO 时必带，即登录页 URL 中的 state 参数"
}
```

### Success Response（非 SSO）

- **200 OK**

```json
{ "status": "ok" }
```

同时设置 Cookie：

- `auth_token=<jwt>`（HttpOnly, Secure, Path=/，有效期 2 小时）
- `refresh_token=<token>`（HttpOnly, Secure, Path=/api/v1/auth/refresh，有效期 7 天）

### Success Response（SSO，请求体带 server_state）

- **200 OK**

```json
{ "redirect_url": "https://子应用/callback?code=xxx&state=xxx" }
```

- 不 302，前端或子应用根据 `redirect_url` 自行跳转。子应用有后端时可调 `POST /api/v1/auth/token`（带 client_secret）换 token；无后端时前端可调 `POST /api/v1/auth/token-by-code`（带 client_id + code）换 token。

### Error Responses

- **400 Bad Request**（请求体无法解析）

```json
{ "code": "INVALID_REQUEST", "message": "Invalid request body" }
```

- **401 Unauthorized**（账号或密码错误）

```json
{ "code": "INVALID_CREDENTIALS", "message": "Invalid credentials" }
```

- **500 Internal Server Error**（服务端错误）

```json
{ "code": "INTERNAL_ERROR", "message": "Server error" }
```

---

## 2) 用户注册

- **URL**: `POST /api/v1/auth/register`
- **说明**: 注册新用户。`username` 可选；若为空，服务端会回退使用 `email` 作为 `username`。

### Request Body

```json
{
  "username": "optional",
  "email": "newuser@example.com",
  "password": "password123"
}
```

### Success Response

- **201 Created**
- **Body**: 空

### Error Responses

- **400 Bad Request**（请求体无法解析）

```json
{ "code": "INVALID_REQUEST", "message": "Invalid request body" }
```

- **400 Bad Request**（邮箱格式不合法）

```json
{ "code": "INVALID_EMAIL", "message": "Invalid email format" }
```

- **400 Bad Request**（密码太短，最少 6 位）

```json
{ "code": "PASSWORD_TOO_SHORT", "message": "Password too short" }
```

- **409 Conflict**（邮箱已存在）

```json
{ "code": "EMAIL_EXISTS", "message": "Email already registered" }
```

- **500 Internal Server Error**

```json
{ "code": "INTERNAL_ERROR", "message": "User registration failed" }
```

---

## 3) 登出

- **URL**: `POST /api/v1/auth/logout`
- **说明**: 登出当前用户。服务端会从数据库中**吊销 refresh_token**（防止 refresh_token 被继续使用），并清除 `auth_token` 和 `refresh_token` 两个 Cookie。

### Request

- 无需 Body；需携带 `auth_token` 和 `refresh_token` Cookie（浏览器同域自动带上）。

### Success Response

- **200 OK**

```json
{ "status": "ok" }
```

### 说明

- 不校验 access_token 是否有效，只要调用即清除 Cookie 并返回成功。
- `refresh_token` 在数据库中被物理删除，即使 Cookie 仍被持有也无法再使用。

---

## 4) 刷新 Access Token

- **URL**: `POST /api/v1/auth/refresh`
- **说明**: 用 `refresh_token` Cookie 换发新的 `access_token`，同时**轮换 refresh_token**（旧 token 删除，响应写入新 token）。前端通常不需要主动调用此接口，而是在收到 401 时由拦截器自动触发。

### Request

- 无需 Body；需携带 `refresh_token` Cookie（浏览器在访问 `/api/v1/auth/refresh` 路径时会自动带上）。

### Success Response

- **204 No Content**
- **Body**: 空

同时更新 Cookie：

- `auth_token=<新jwt>`（重置有效期）
- `refresh_token=<新token>`（轮换，旧 token 立即失效）

### Error Responses

- **401 Unauthorized**（缺少、无效或已过期的 refresh_token）

```json
{ "code": "UNAUTHORIZED", "message": "Missing refresh token" }
```

```json
{ "code": "INVALID_TOKEN", "message": "Invalid or expired refresh token" }
```

---

## 5) 校验 Token / 获取用户信息

- **URL**: `GET /api/v1/auth/validate`
- **说明**: 用于其他服务验证 JWT；成功返回用户 `id` 和 `role`。

### Headers

- **Cookie**: `auth_token=<token>`（浏览器同域会自动携带）
- 或 **Authorization**: `Bearer <token>`

### Success Response

- **200 OK**

```json
{
  "id": 123,
  "role": "standard"
}
```

### Error Responses

- **401 Unauthorized**（缺少或无效 token）

```json
{ "code": "UNAUTHORIZED", "message": "Missing or invalid token" }
```

- **401 Unauthorized**（token 无效或过期）

```json
{ "code": "INVALID_TOKEN", "message": "Token validation failed" }
```

---

## 6) 获取当前用户基本信息

- **URL**: `GET /api/v1/auth/me`
- **说明**: 根据当前请求的 token 返回登录用户的基本信息。鉴权方式同 validate（Cookie 或 Authorization 头）。

### Headers

- **Cookie**: `auth_token=<token>`（浏览器同域会自动携带）
- 或 **Authorization**: `Bearer <token>`

### Success Response

- **200 OK**

```json
{
  "id": 123,
  "username": "user@example.com",
  "email": "user@example.com",
  "role": "standard",
  "created_at": "2025-01-15T08:00:00Z"
}
```

### Error Responses

- **401 Unauthorized**：未提供或无效 token（同「5) 校验 Token」的 401 响应）。

---

## 7) 上传静态资源

- **URL**: `POST /api/v1/auth/upload`
- **说明**: 上传文件，需鉴权。通过 token 获取当前用户，文件保存至 `uploads/<用户名>/<文件名>`；用户名会做安全替换（仅保留字母数字、下划线、横线、点）。上传成功后返回资源访问路径与完整 URL。

### Headers

- **Cookie**: `auth_token=<token>` 或 **Authorization**: `Bearer <token>`

### Request Body（multipart/form-data）

| 字段     | 类型   | 必填 | 说明                                   |
| -------- | ------ | ---- | -------------------------------------- |
| fileName | string | 是   | 文件名（仅使用 basename，禁止含 `..`） |
| file     | file   | 是   | 文件内容                               |

### Success Response

- **200 OK**

```json
{
  "path": "uploads/user_example_com/avatar.jpg",
  "route": "/static/uploads/user_example_com/avatar.jpg",
  "access_url": "/static/uploads/user_example_com/avatar.jpg"
}
```

- **path**：相对路径，服务端存储路径。
- **route**：静态资源路由，同源下可直接用于前端（如 `<img src="/static/...">`）。
- **access_url**：完整可访问 URL，可直接用于跨域或分享；协议会根据请求（含 `X-Forwarded-Proto`）自动判断。

### 静态资源访问

上传后的文件可通过 `GET /static/uploads/<用户名>/<文件名>` 访问（或使用返回的 `access_url`）。

### Error Responses

- **400**：缺少 `fileName` 或 `file`、或 `fileName` 不合法。
- **401**：未提供或无效 token（同「5) 校验 Token」）。

---

## 配置说明

配置文件路径：`configs/config.yaml`

| 配置项                             | 说明                                          | 默认值         |
| ---------------------------------- | --------------------------------------------- | -------------- |
| `server.port`                      | 监听端口                                      | `8888`         |
| `server.jwt_secret`                | JWT 签名密钥（必填，生产环境请使用强随机值）  | —              |
| `server.jwt_expiration_hours`      | access_token 有效期（小时），取值 1~720       | `2`            |
| `server.refresh_token_expiry_days` | refresh_token 有效期（天）                    | `7`            |
| `server.allowed_origins`           | 允许跨域的前端域名列表                        | `[]`           |
| `server.auth_base_url`             | 认证中心对外完整 base URL，用于拼接登录页地址 | `/`            |
| `server.login_page_path`           | SSO 登录页路径                                | `/monai/login` |
| `server.clients`                   | 子应用客户端列表（SSO 授权码流程）            | `[]`           |
| `database.host`                    | MySQL 主机                                    | —              |
| `database.port`                    | MySQL 端口                                    | `3306`         |
| `database.user`                    | 数据库用户名                                  | —              |
| `database.password`                | 数据库密码                                    | —              |
| `database.dbname`                  | 数据库名                                      | —              |

---

## 数据库表

### users

用户表，由 GORM AutoMigrate 维护（对应 `internal/repository/mysql/model.go`）。

### refresh_tokens

Refresh Token 存储表，启动时自动创建。建表脚本见 `scripts/create_refresh_tokens.sql`。

| 字段       | 类型                  | 说明                    |
| ---------- | --------------------- | ----------------------- |
| id         | BIGINT AUTO_INCREMENT | 主键                    |
| user_id    | BIGINT                | 所属用户，关联 users.id |
| token      | VARCHAR(128) UNIQUE   | 64 位十六进制随机串     |
| expires_at | DATETIME              | Token 过期时间          |
| created_at | DATETIME              | 签发时间                |

---

## 示例调用

### 注册

```bash
curl -X POST "/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"newuser@example.com","password":"password123"}'
```

### 登录

```bash
curl -X POST "/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"newuser@example.com","password":"password123"}' \
  -c cookies.txt -i
```

响应头中会同时下发 `auth_token` 和 `refresh_token` 两个 Cookie，保存到 `cookies.txt`。

### 刷新 Access Token

```bash
curl -X POST "/api/v1/auth/refresh" \
  -b cookies.txt -c cookies.txt -i
```

成功后 `cookies.txt` 中的两个 Cookie 自动更新。

### 登出

```bash
curl -X POST "/api/v1/auth/logout" \
  -b cookies.txt -i
```

### 校验 Token

```bash
curl -X GET "/api/v1/auth/validate" \
  -b cookies.txt
```

### 获取当前用户信息

```bash
curl -X GET "/api/v1/auth/me" \
  -b cookies.txt
```

### 请求登录（SSO）

```bash
curl -X GET "/api/v1/auth/request-login?client_id=mark-live&redirect_uri=http://localhost:5174/callback"
```

### 前端用 code 换 token

```bash
curl -X POST "/api/v1/auth/token-by-code" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"mark-live","code":"从 redirect_url 解析的 code"}' \
  -c cookies.txt -b cookies.txt
```

### 上传静态资源

```bash
curl -X POST "/api/v1/auth/upload" \
  -b cookies.txt \
  -F "fileName=avatar.jpg" \
  -F "file=@./local-avatar.jpg"
```
