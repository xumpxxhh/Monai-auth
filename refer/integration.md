# monai-infra 业务接入指南

本文说明各业务仓库（如 `monai-auth`、`mark-live`、`devops`）如何接入平台基础设施。

**前提：** 运维已在目标环境启动 `monai-infra`（提供 Docker 网络、共享数据库与 HTTP 网关）。业务仓库独立部署，代码不放入 infra 仓库。

---

## 平台架构

各业务仓库与 `monai-infra` **分仓、分 compose、独立启停**。容器之间通过 Docker 网络 `monai_net` 互通；对外 HTTP 经 `monai-nginx` 统一入口（路径转发到各业务后端）。

```mermaid
flowchart TB
  Client[客户端 / 浏览器]
  Nginx[monai-nginx :80]
  Auth[业务: auth :8888]
  Mark[业务: mark-live 等]
  Dev[业务: devops 等]
  MySQL[(mysql :3306)]
  PG[(postgresql :5432)]

  Client --> Nginx
  Nginx --> Auth
  Nginx -.-> Mark
  Nginx -.-> Dev
  Auth --> MySQL
  Mark --> MySQL
  Dev --> PG
```

| 组件          | compose 服务名 | 典型用途                                          |
| ------------- | -------------- | ------------------------------------------------- |
| MySQL 8       | `mysql`        | 认证、直播等业务的共享关系库（如 `identity_db`）  |
| PostgreSQL 16 | `postgresql`   | DevOps 等需要 PG 的业务                           |
| Nginx         | `nginx`        | 按 URL 前缀反向代理到业务容器                     |
| 网络          | `monai_net`    | infra 创建；业务 compose 以 `external: true` 接入 |

Infra 侧 compose 服务名即 Docker DNS 名（上表「compose 服务名」）。业务侧 **compose 的 service 名**（如 `auth`）须与网关转发配置中的主机名一致。

---

## 1. 接入约定（速查）

| 用途           | 业务容器内连接主机名            | 端口        | 说明                                                      |
| -------------- | ------------------------------- | ----------- | --------------------------------------------------------- |
| MySQL          | `mysql`                         | `3306`      | 库名、root 密码以实际部署为准（见下文「Infra 环境参数」） |
| PostgreSQL     | `postgresql`                    | `5432`      | 用户、库名以实际部署为准                                  |
| 经网关访问 API | 宿主机 IP 或域名 + 网关映射端口 | 常见为 `80` | 路径见「网关路由」                                        |
| 加入网络       | —                               | —           | 网络名 `monai_net`，`external: true`                      |

在 `monai_net` 内访问 infra 服务时，**禁止**用 `localhost`、`127.0.0.1`、`host.docker.internal` 代替上表主机名。

### Infra 环境参数（与业务对齐）

业务配置中的数据库密码、库名须与 **运行 monai-infra 时使用的环境变量** 一致。未单独约定时，开发环境常见默认值为：

| 变量                  | 常见默认值    | 业务侧用途                                                                     |
| --------------------- | ------------- | ------------------------------------------------------------------------------ |
| `MYSQL_ROOT_PASSWORD` | `123456`      | MySQL root 密码                                                                |
| `MYSQL_DATABASE`      | `identity_db` | 认证等默认库名                                                                 |
| `POSTGRES_USER`       | `devops`      | PostgreSQL 用户                                                                |
| `POSTGRES_PASSWORD`   | `devops_pass` | PostgreSQL 密码                                                                |
| `POSTGRES_DB`         | `devops_db`   | PostgreSQL 库名                                                                |
| `NGINX_HTTP_PORT`     | `80`          | 宿主机访问网关的端口（仅影响从宿主机/局域网访问，不影响容器内 `auth:8888` 等） |

生产或共享环境务必使用非默认凭据；业务 `.env` 与 infra 部署凭据不一致会导致连库失败。

### 网关路由（当前）

| 对外路径前缀   | 上游（monai_net 内） | 说明         |
| -------------- | -------------------- | ------------ |
| `/api/v1/auth` | `http://auth:8888`   | 认证 API     |
| `/static/`     | `http://auth:8888`   | 认证静态资源 |
| `/`            | —                    | 网关探活文本 |

规划中的前缀（接入时在 infra 中增加对应 `location` 后生效）：`/api/v1/mark-live` → `mark-live` 服务、`/api/v1/devops` → `devops` 服务；前端路径前缀 `/auth/`、`/mark/`、`/devops/` 等可代理到各 `*-web` 静态服务。

---

## 2. Compose：加入 `monai_net`

在业务仓库的 `docker-compose.yml` 中：

```yaml
services:
  auth:
    # build / image ...
    # 进程须监听 0.0.0.0:8888，不能只绑 127.0.0.1
    networks:
      - monai_net

networks:
  monai_net:
    external: true
    name: monai_net
```

要点：

- Nginx 解析的是 **service 名**（上例 `auth`），与 `container_name` 无关。
- **service 名 + 端口** 须与网关表一致（auth 为 `8888`）。
- 业务侧不要为 `monai_net` 声明 `driver`，只声明 `external: true`。

---

## 3. 数据库连接

### 3.1 MySQL（容器内）

```yaml
environment:
  DB_HOST: mysql
  DB_PORT: "3306"
  DB_USER: root
  DB_PASSWORD: <与 infra 部署中 MYSQL_ROOT_PASSWORD 相同>
  DB_NAME: identity_db
```

```text
mysql://root:<password>@mysql:3306/identity_db
```

### 3.2 PostgreSQL（容器内）

```text
postgresql://devops:devops_pass@postgresql:5432/devops_db
```

将用户、密码、库名替换为实际部署中的 `POSTGRES_USER`、`POSTGRES_PASSWORD`、`POSTGRES_DB`。

### 3.3 需要新的 MySQL 库

由 infra 维护者在 `monai-infra` 的 `mysql/init/` 中增加初始化 SQL，例如：

```sql
CREATE DATABASE IF NOT EXISTS mark_live_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

MySQL 数据卷**只在首次创建时**执行 init 脚本；已有实例上也可直接执行 `CREATE DATABASE` 或走迁移流程。

---

## 4. 经 Nginx 暴露 API

业务容器已加入 `monai_net` 且监听约定端口后，客户端经网关访问，例如：

```text
http://<宿主机或域名>:<NGINX_HTTP_PORT>/api/v1/auth/...
http://<宿主机或域名>:<NGINX_HTTP_PORT>/static/...
```

新业务对外路径：在 infra 的 `nginx/default.conf` 中按 auth 现有写法增加 `location`（主机名使用业务 **service 名**，配合 Docker 内置 DNS 的变量 `proxy_pass`），并重启 `nginx` 服务。业务仓库内不需要维护 nginx 配置。

网关在未配置上游路径时仍可探活；上游未启动时，对应 API 路径会返回 502。

---

## 5. 启动顺序

1. 环境内 `monai-infra` 已运行（`monai_net`、数据库、网关可用）。
2. 启动本业务 compose，确认相关服务 attached 到 `monai_net`，且应用监听 `0.0.0.0`。

---

## 6. 联调常见问题

**连不上 MySQL / PostgreSQL**

- 执行 `docker network inspect monai_net`，确认业务容器在成员列表中。
- 主机名是否为 `mysql` / `postgresql`，端口是否为容器内 **3306 / 5432**（不是宿主机映射端口）。

**网关 502**

- 业务未启动或未加入 `monai_net`。
- compose **service 名**或监听端口与网关表不一致。
- 应用只监听 `127.0.0.1`，应改为 `0.0.0.0`。

**密码或库名错误**

- 与 infra 实际部署的 `MYSQL_ROOT_PASSWORD`、`MYSQL_DATABASE`、`POSTGRES_*` 逐项核对，勿沿用已过期的本地默认值。

---

接入只需：**external 网络** `monai_net` **+ 正确的 service 名/端口 + 与 infra 一致的库连接信息**；共享网关与数据库实例由 `monai-infra` 统一维护。
