# OpenAI 自动注册系统 v2

自动化注册 OpenAI 账号的 Web UI 系统，支持多种邮箱服务、并发批量注册、代理管理和账号管理。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)

AI 站长交流群：https://t.me/vpsbbq

## 功能特性

- **🌟 [核心强推] 全自动监控与守护机制 (完全无人值守)**
  - 🛡️ **智能体检与剔除：** 后台定时（支持自定义分钟级间隔）满速穿透探测目标 CPA (目前支持 CLIProxy) 接口下凭证的存活状态，**仅测试与清理 `type/provider=codex` 的凭证**，精准发现失效报错坏号并立刻调用接口自动剔除。
  - 🚀 **触底爆发式补货：** 智能预警级余量检测，当确认当前可用活号低出您设定的 **安全供给阈值** 时，引擎立即接管分配并发注册，无需干预即可源源不断输出新号上传，彻底实现从生产、质检到补库的一条龙**断网不断供保障**。

- **🤖 完美全真模拟浏览器注册机制 (最新集成)**
  - 🖥️ **底层内核升级：** 全面弃用易被拦截的传统接口形式，采用 `curl_cffi` 结合 TLS 指纹混淆，注入真实 Chrome 指纹环境 (含完全对应的 Sec-Ch-Ua 与 Platform 级联特征)，避免风控阻断。
  - 🧩 **本地化原生 PoW 求解：** 系统内置由纯 Python 实现的 Sentinel Token 求解器 (`SentinelTokenGenerator`)，不仅免去了沉重的浏览器依赖（如 Playwright），且能自动获取并求解授权及建号双阶段 Sentinel Token，提升请求合法度。
  - 🔄 **原汁原味的跳转链路：** 100% 还原官方真实访问流，从访问 `chatgpt.com` 首页获取初始 CSRF，无缝转交 `signin/openai`，再跟随跳转到 `auth.openai.com` 授权。全自动化的跳转控制使成功率飙升。

- **多邮箱服务支持**
  - Tempmail.lol（临时邮箱，无需配置）
  - Generator.email（临时邮箱，无需配置）
  - Outlook（IMAP + XOAUTH2，支持批量导入）
  - 自定义域名（两种子类型）
    - **MoeMail**：标准 REST API，配置 API 地址 + API 密钥
    - **TempMail**：自部署 Cloudflare Worker 临时邮箱，配置 Worker 地址 + Admin 密码
  - DuckMail
    - **DuckMail API**：兼容 DuckMail 接口，手动填写 API 地址、默认域名，可选 API Key
  - 支持**多选邮箱服务轮询**，自动在所选服务间分配请求，降低单服务 429 风险

- **注册模式**
  - 单次注册
  - 批量注册（可配置数量和间隔时间）
  - Outlook 批量注册（指定账户逐一注册）

- **全新流式高匿取 Token 链路**
  - 新老账号完美融合与适配：走完全真实的建号步骤或遇已注册号自动转入二次验证，直接携带解算的 Sentinel Token 无感进行 OTP 校验。
  - **支持两种 Token 获取方式**：
    - **OAuth 登录流程（含 refresh_token）**：使用登录 + 授权 + 回调链路获取完整 token。
    - **Session 提取**：注册/登录完成后直接从 `/api/auth/session` 抽取 token。
  - **自动模式**：默认优先 OAuth，失败自动回退 Session，可在 UI 中切换。

- **并发控制**
  - 流水线模式（Pipeline）：每隔 interval 秒启动新任务，限制最大并发数
  - 并行模式（Parallel）：所有任务同时提交，Semaphore 控制最大并发
  - 并发数可在 UI 自定义（1-50）
  - 日志混合显示，带 `[任务N]` 前缀区分

- **实时监控**
  - WebSocket 实时日志推送
  - 全频道 💻 系统监控台轮询展示后台动态（如：批处理测活进度、剔除明细）
  - 跨页面导航后自动重连
  - 降级轮询备用方案

- **代理管理**
  - 动态代理（通过 API 每次获取新 IP）
  - 代理列表（随机选取，支持设置默认代理，记录使用时间）

- **账号管理**
  - 查看、删除、批量操作
  - Token 刷新与验证
  - 订阅状态管理（手动标记 / 自动检测 plus/team/free）
  - 导出格式：JSON / CSV / CPA 格式 / Sub2API 格式
    - 单个账号导出为独立 `.json` 文件
    - 多个 CPA 账号打包为 `.zip`，每个账号一个独立文件
    - Sub2API 格式所有账号合并为单个 JSON
  - 上传目标（直连不走代理）：
    - **CPA**：支持多服务配置，上传时选择目标服务
    - **Sub2API**：支持多服务配置，标准 sub2api-data 格式
    - **Team Manager**：支持多服务配置

- **支付升级**
  - 为账号生成 ChatGPT Plus 或 Team 订阅支付链接
  - 后端命令行以无痕模式自动打开 Chrome/Edge
  - Team 套餐支持自定义工作区名称、座位数、计费周期

- **系统设置**
  - 代理配置（动态代理 + 代理列表，支持设默认）
  - CPA 服务列表管理（多服务，连接测试）
  - Sub2API 服务列表管理（多服务，连接测试）
  - Team Manager 服务列表管理（多服务，连接测试）
  - Outlook OAuth 参数
  - 注册参数（超时、重试、密码长度等）
  - 验证码等待配置
  - 数据库管理（备份、清理）
  - 支持远程 PostgreSQL

## 快速开始

### 环境要求

- Python 3.10+
- [uv](https://github.com/astral-sh/uv)（推荐）或 pip

### 安装依赖

```bash
# 使用 uv（推荐）
uv sync

# 或使用 pip
pip install -r requirements.txt
```

### 环境变量配置（可选）

复制 `.env.example` 为 `.env`，按需填写：

```bash
cp .env.example .env
```

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_HOST` | 监听主机 | `0.0.0.0` |
| `APP_PORT` | 监听端口 | `8000` |
| `APP_ACCESS_PASSWORD` | Web UI 访问密钥 | `admin123` |
| `APP_DATABASE_URL` | 数据库连接字符串 | `data/database.db` |
| `APP_UPDATE_REPOSITORY` | 更新检查仓库 | `moeacgx/codex-manager` |

> 优先级：命令行参数 > 环境变量（`.env`）> 数据库设置 > 默认值

### 启动 Web UI

```bash
# 默认启动（127.0.0.1:8000）
python webui.py

# 指定地址和端口
python webui.py --host 0.0.0.0 --port 8080

# 调试模式（热重载）
python webui.py --debug

# 设置 Web UI 访问密钥
python webui.py --access-password mypassword

# 组合参数
python webui.py --host 0.0.0.0 --port 8080 --access-password mypassword
```

### 守护进程模式（源码/单机推荐）

```bash
# 启用守护进程（更新后自动拉起）
python webui.py --guardian

# 可调参数（默认：5 次 / 300 秒 / 2 秒重启间隔）
python webui.py --guardian --guardian-max-restarts 5 --guardian-window-seconds 300 --guardian-restart-delay 2
```

> `--access-password` 优先级高于数据库中保存的密钥设置，每次启动时生效。打包后的 exe 同样支持此参数：
> ```bash
> codex-register.exe --access-password mypassword
> ```

### 使用远程 PostgreSQL

通过环境变量指定数据库连接字符串：

```bash
export APP_DATABASE_URL="postgresql://user:password@host:5432/dbname"
python webui.py
```

也支持 `DATABASE_URL`，优先级低于 `APP_DATABASE_URL`。

启动后访问 http://127.0.0.1:8000

## 打包为可执行文件

```bash
# Windows
build.bat

# Linux/macOS
bash build.sh
```

打包后生成 `codex-register.exe`（Windows）或 `codex-register`（Unix），双击或直接运行即可，无需安装 Python 环境。

## 项目结构

```
codex-manager/
├── webui.py            # Web UI 入口
├── build.bat           # Windows 打包脚本
├── build.sh            # Linux/macOS 打包脚本
├── src/
│   ├── config/         # 配置管理（Pydantic Settings）
│   ├── core/
│   │   ├── openai/     # OAuth、Token 刷新、支付核心
│   │   └── upload/     # CPA / Sub2API / Team Manager 上传模块
│   ├── database/       # 数据库（SQLAlchemy + SQLite/PostgreSQL）
│   ├── services/       # 邮箱服务实现
│   └── web/
│       ├── app.py      # 应用入口、路由挂载
│       ├── task_manager.py  # 任务/日志/WebSocket 管理
│       └── routes/     # API 路由
│           └── upload/ # CPA / Sub2API / TM 服务管理路由
├── templates/          # Jinja2 HTML 模板
├── static/             # 静态资源（CSS / JS）
└── data/               # 运行时数据目录（数据库、日志）
```

## 技术栈

| 层级 | 技术 |
|------|------|
| Web 框架 | FastAPI + Uvicorn |
| 数据库 | SQLAlchemy + SQLite / PostgreSQL |
| 模板引擎 | Jinja2 |
| HTTP 客户端 | curl_cffi（浏览器指纹模拟） |
| 实时通信 | WebSocket |
| 并发 | asyncio Semaphore + ThreadPoolExecutor |
| 前端 | 原生 JavaScript（无框架） |
| 打包 | PyInstaller |

## API 端点

### 注册任务

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/registration/start` | 启动注册任务 |
| GET | `/api/registration/tasks` | 任务列表 |
| GET | `/api/registration/tasks/{uuid}/logs` | 任务日志 |
| POST | `/api/registration/tasks/{uuid}/cancel` | 取消任务 |
| GET | `/api/registration/available-services` | 可用邮箱服务 |

### 账号管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/accounts` | 账号列表（支持分页、筛选、搜索） |
| GET | `/api/accounts/{id}` | 账号详情 |
| PATCH | `/api/accounts/{id}` | 更新账号（状态/cookies） |
| DELETE | `/api/accounts/{id}` | 删除账号 |
| POST | `/api/accounts/batch-delete` | 批量删除 |
| POST | `/api/accounts/export/json` | 导出 JSON |
| POST | `/api/accounts/export/csv` | 导出 CSV |
| POST | `/api/accounts/export/cpa` | 导出 CPA 格式（单文件或 ZIP） |
| POST | `/api/accounts/export/sub2api` | 导出 Sub2API 格式 |
| POST | `/api/accounts/{id}/refresh` | 刷新 Token |
| POST | `/api/accounts/batch-refresh` | 批量刷新 Token |
| POST | `/api/accounts/{id}/validate` | 验证 Token |
| POST | `/api/accounts/batch-validate` | 批量验证 Token |
| POST | `/api/accounts/{id}/upload-cpa` | 上传单账号到 CPA |
| POST | `/api/accounts/batch-upload-cpa` | 批量上传到 CPA |
| POST | `/api/accounts/{id}/upload-sub2api` | 上传单账号到 Sub2API |
| POST | `/api/accounts/batch-upload-sub2api` | 批量上传到 Sub2API |

### 支付升级

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/payment/generate` | 生成 Plus/Team 支付链接 |
| POST | `/api/payment/open` | 后端无痕模式打开浏览器 |
| POST | `/api/payment/accounts/{id}/mark-subscription` | 手动标记订阅类型 |
| POST | `/api/payment/accounts/batch-check-subscription` | 批量检测订阅状态 |
| POST | `/api/payment/accounts/{id}/upload-tm` | 上传单账号到 Team Manager |
| POST | `/api/payment/accounts/batch-upload-tm` | 批量上传到 Team Manager |

### 邮箱服务

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/email-services` | 服务列表 |
| POST | `/api/email-services` | 添加服务 |
| PATCH | `/api/email-services/{id}` | 更新服务 |
| DELETE | `/api/email-services/{id}` | 删除服务 |
| POST | `/api/email-services/{id}/test` | 测试服务 |
| POST | `/api/email-services/outlook/batch-import` | 批量导入 Outlook |

### 上传服务管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET/POST | `/api/cpa-services` | CPA 服务列表/创建 |
| PUT/DELETE | `/api/cpa-services/{id}` | 更新/删除 CPA 服务 |
| POST | `/api/cpa-services/{id}/test` | 测试 CPA 连接 |
| GET/POST | `/api/sub2api-services` | Sub2API 服务列表/创建 |
| PUT/DELETE | `/api/sub2api-services/{id}` | 更新/删除 Sub2API 服务 |
| POST | `/api/sub2api-services/{id}/test` | 测试 Sub2API 连接 |
| GET/POST | `/api/tm-services` | Team Manager 服务列表/创建 |
| PUT/DELETE | `/api/tm-services/{id}` | 更新/删除 TM 服务 |
| POST | `/api/tm-services/{id}/test` | 测试 TM 连接 |

### 设置

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings` | 获取所有设置 |
| POST | `/api/settings/proxy/dynamic` | 更新动态代理设置 |
| GET/POST/DELETE | `/api/settings/proxies` | 代理列表管理 |
| POST | `/api/settings/proxies/{id}/set-default` | 设为默认代理 |
| GET | `/api/settings/database` | 数据库信息 |

### WebSocket

| 路径 | 说明 |
|------|------|
|| `ws://host/api/ws/logs/{uuid}` | 实时日志流 |

## Docker 部署

### 环境要求

- Docker
- Docker Compose

### 快速部署

```bash
# 克隆项目
git clone https://github.com/moeacgx/codex-manager.git
cd codex-manager

# 启动服务
docker-compose up -d
```

服务启动后访问 http://localhost:8000

### 配置说明

**端口映射**：默认 `8000` 端口，可在 `docker-compose.yml` 中修改。

**数据持久化**：
```yaml
volumes:
  - ./data:/app/data
  - ./logs:/app/logs
```

**环境变量配置**：
```yaml
environment:
  - APP_ACCESS_PASSWORD=mypassword
  - APP_HOST=0.0.0.0
  - APP_PORT=8000
```

### 常用命令

```bash
# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down

# 更新代码并重建容器
git pull
docker-compose up -d --build --force-recreate
```

> 说明：仅执行 `docker-compose build --no-cache` 只会重建镜像，
> **不会自动替换正在运行的旧容器**。更新后请使用
> `docker-compose up -d --build --force-recreate` 让新代码生效。

## 注意事项

- 首次运行会自动创建 `data/` 目录和 SQLite 数据库
- 所有账号和设置数据存储在 `data/register.db`
- 日志文件写入 `logs/` 目录
- 纯源码或单机运行且需要自更新时，建议使用 `--guardian` 守护模式
- 代理优先级：动态代理 > 代理列表（随机/默认） > 直连
- CPA / Sub2API / Team Manager 上传始终直连，不走代理
- 注册时自动随机生成用户名和生日（年龄范围 18-45 岁）
- Token 获取方式支持 OAuth 登录流程或 Session 提取；自动模式默认优先 OAuth，失败回退 Session
- 支付链接生成使用账号 access_token 鉴权，走全局代理配置
- 无痕浏览器优先使用 playwright（注入 cookie 直达支付页）；未安装时降级为系统 Chrome/Edge 无痕模式
- 安装完整支付功能：`pip install ".[payment]" && playwright install chromium`（可选）
- 订阅状态自动检测调用 `chatgpt.com/backend-api/me`，走全局代理
- 批量注册并发数上限为 50，线程池大小已相应调整

## License

[MIT](LICENSE)
