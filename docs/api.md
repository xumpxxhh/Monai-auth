# Monai Auth Service API 文档

## 基础信息

- **Base URL**: `http://localhost:8888`（默认端口来自 `configs/config.yaml`，以实际配置为准）
- **Content-Type**: 请求/响应均使用 `application/json`（除空响应）
- **鉴权方式**: JWT，默认通过 **HttpOnly Cookie** 传递（`auth_token`），同时兼容 `Authorization: Bearer <token>` 头部

## 统一错误响应

所有错误响应均为 JSON：

```json
{
  "code": "SOME_CODE",
  "message": "Human readable message"
}
```

常见 `code`（以接口实际返回为准）：

- `INVALID_REQUEST`
- `INVALID_CREDENTIALS`
- `UNAUTHORIZED`
- `INVALID_TOKEN`
- `EMAIL_EXISTS`
- `INVALID_EMAIL`
- `PASSWORD_TOO_SHORT`
- `INTERNAL_ERROR`

---

## 1) 用户登录

- **URL**: `POST /api/v1/auth/login`
- **说明**: 使用邮箱+密码登录，成功后后端会在响应中设置一个名为 `auth_token` 的 **HttpOnly Cookie**，前端 JS 无法直接访问该 Token。

### Request Body

```json
{
  "email": "user@example.com",
  "password": "password123",
  "username": "optional"
}
```

> 备注：当前实现以 `email` + `password` 为准，`username` 字段即使传入也不会参与登录校验。

### Success Response

- **200 OK**

```json
{ "status": "ok" }
```

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

- **400 Bad Request**（密码太短）

```json
{ "code": "PASSWORD_TOO_SHORT", "message": "Password too short" }
```

- **409 Conflict**（邮箱已存在）

```json
{ "code": "EMAIL_EXISTS", "message": "Email already registered" }
```

- **500 Internal Server Error**（服务端错误）

```json
{ "code": "INTERNAL_ERROR", "message": "User registration failed" }
```

---

## 3) 登出

- **URL**: `POST /api/v1/auth/logout`
- **说明**: 登出当前用户。服务端会清除 `auth_token` Cookie（浏览器随之删除），客户端无需再持有 token；若前端有额外保存 token，也应在此处一并清理。

### Request

- 无需 Body；若使用 Cookie 鉴权，需携带当前域下的 `auth_token` Cookie（浏览器会自动带上）。

### Success Response

- **200 OK**

```json
{ "status": "ok" }
```

### 说明

- 不校验 token 是否有效，只要调用即清除 Cookie 并返回成功，便于客户端统一做“登出”体验。

---

## 4) 校验 Token / 获取用户信息

- **URL**: `GET /api/v1/auth/validate`
- **说明**: 用于其他服务验证 JWT；成功返回用户 `id` 和 `role`。

### Headers

- 默认情况下，服务会从 **HttpOnly Cookie `auth_token`** 中读取 token；
- 也兼容通过 Header 传递：
  - **Authorization**: `Bearer <token>`

### Success Response

- **200 OK**

```json
{
  "id": 123,
  "role": "standard"
}
```

### Error Responses

- **401 Unauthorized**（缺少/非法 Authorization 头）

```json
{ "code": "UNAUTHORIZED", "message": "Missing or invalid Authorization header" }
```

- **401 Unauthorized**（token 无效或过期）

```json
{ "code": "INVALID_TOKEN", "message": "Token validation failed" }
```

---

## 示例调用

### 注册

```bash
curl -X POST "http://localhost:8888/api/v1/auth/register" ^
  -H "Content-Type: application/json" ^
  -d "{\"email\":\"newuser@example.com\",\"password\":\"password123\"}"
```

### 登录

```bash
curl -X POST "http://localhost:8888/api/v1/auth/login" ^
  -H "Content-Type: application/json" ^
  -d "{\"email\":\"newuser@example.com\",\"password\":\"password123\"}" ^
  -i
```

### 登出

```bash
curl -X POST "http://localhost:8888/api/v1/auth/logout" ^
  --cookie "auth_token=<your_token_here>"
```

### 校验

```bash
curl -X GET "http://localhost:8888/api/v1/auth/validate" ^
  --cookie "auth_token=<your_token_here>"
```

