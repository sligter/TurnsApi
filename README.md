# TurnsAPI - 多提供商 API 代理服务

TurnsAPI 是一个高性能多提供商 API 代理服务，支持 OpenAI、Google Gemini、Anthropic Claude、Azure OpenAI 等多个大模型提供商。

## 🚀 主要特性

- **多提供商支持**: OpenAI、Google Gemini、Anthropic Claude、Azure OpenAI 等
- **完整工具调用**: 支持 Function Calling、tool_choice、并行工具调用
- **智能路由**: 自动故障转移和重试机制，支持多种轮询策略
- **模型重命名**: 支持模型别名映射，统一不同分组的模型名称
- **参数覆盖**: 分组级别的请求参数覆盖（temperature、max_tokens等）
- **流式响应**: 完全支持 SSE 流式响应和原生接口格式
- **OpenAI Responses API**: OpenAI 分组可选使用 `/v1/responses` 作为上游（仍对外保持 Chat Completions 兼容格式）
  - 部分 OpenAI-compatible 网关可能要求 `HTTP-Referer` / `X-Title` / `Origin` 等头；TurnsAPI 支持在分组 `headers` 配置，或从客户端请求头转发（不会覆盖分组已配置值）
- **实时监控**: Web 界面监控 API 密钥状态和服务性能
- **日志分析**: 完整的请求日志记录和统计分析
- **安全认证**: 内置认证系统保护 API 和管理界面

![image](https://img.pub/p/be300f485a8220427425.png)

![image](https://img.pub/p/1815af8a0a8bc2f278d0.png)

## 🛠️ 快速开始

### Docker 运行（推荐）

```bash
# 1) 创建配置（推荐从示例复制）
mkdir -p config logs data
cp config/config.example.yaml config/config.yaml

# 2) 启动（包含 turnsapi + postgres）
docker compose up --build -d

# turnsapi 默认映射端口：6001 -> 8080
# postgres 默认映射端口：5435 -> 5432（防止与本机其它 postgres 冲突）
```

> 提示：容器内 turnsapi 连接数据库请使用 `postgres:5432`（服务名+容器端口）；如果你在宿主机直连数据库，请使用 `localhost:5435`。

### 本地运行

```bash
git clone <repository-url>
cd TurnsApi
go mod tidy
# go.mod 需要 Go 1.24+（Dockerfile 也已使用 golang:1.24-alpine）
go run ./cmd/turnsapi -config config/config.yaml
```

### 验证安装

访问 http://localhost:6001 查看管理界面（本地运行则为 http://localhost:8080）

## 🔧 配置说明

### 基本配置

```yaml
server:
  port: "8080"
  mode: "release"  # debug, release, test

auth:
  enabled: true
  username: "admin"
  password: "turnsapi123"  # 请修改默认密码
  session_timeout: "24h"
```

### 分组配置示例

```yaml
user_groups:
  openai_official:
    name: "OpenAI Official"
    provider_type: "openai"
    base_url: "https://api.openai.com/v1"
    enabled: true
    rotation_strategy: "round_robin"  # round_robin, random, least_used
    api_keys:
      - "sk-your-openai-key"
    models:
      - "gpt-5"
    # 可选：模型重命名
    model_mappings:
      gpt4: "gpt-5"
    # 可选：参数覆盖
    request_params:
      temperature: 0.7
      max_tokens: 2000
      # 强制覆盖客户端同名字段（包括 stream），也支持覆盖未建模字段（如 response_format 等）
      # stream: false
      # response_format:
      #   type: "json_object"
    # 可选：RPM限制
    rpm_limit: 60
    # 可选：启用 OpenAI Responses API（/v1/responses），默认 false
    use_responses_api: false

  google_gemini:
    name: "Google Gemini"
    provider_type: "gemini"
    base_url: "https://generativelanguage.googleapis.com/v1beta"
    enabled: true
    api_keys:
      - "your-gemini-api-key"
    models:
      - "gemini-pro"
      - "gemini-2.5-pro"
    use_native_response: true  # 启用原生响应格式
```

### 数据库与高并发写入（Postgres 推荐）

```yaml
database:
  driver: "postgres"
  # docker-compose 内使用 postgres 服务名（容器内端口固定为 5432）
  dsn: "postgres://turnsapi:turnsapi@postgres:5432/turnsapi?sslmode=disable"

# 高并发推荐开启：请求日志异步批量写入（降低请求阻塞与锁竞争）
request_logs:
  async_write: true
  buffer: 10000
  batch_size: 200
  flush_interval: "200ms"
```

## 📡 API 使用

### 基本用法

```bash
# 聊天完成
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-access-token" \
  -d '{
    "model": "gpt-5",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": false
  }'

# 指定提供商分组
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "X-Provider-Group: openai_official" \
  -d '...'

# 流式响应
curl -X POST http://localhost:8080/v1/chat/completions \
  -d '{"model": "gpt-5", "messages": [...], "stream": true}'
```

### 认证

```bash
# 登录获取令牌
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "turnsapi123"}'
```

### 工具调用 (Function Calling)

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-access-token" \
  -d '{
    "model": "gpt-5",
    "messages": [{"role": "user", "content": "What is the weather in NYC?"}],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "get_weather",
          "description": "Get current weather",
          "parameters": {
            "type": "object",
            "properties": {
              "location": {"type": "string", "description": "City name"}
            },
            "required": ["location"]
          }
        }
      }
    ],
    "tool_choice": "auto"
  }'
```

## 🖥️ Web 界面

访问 http://localhost:8080 查看管理界面

### 功能特性
- 多提供商管理和实时监控
- 分组配置和密钥管理
- 模型重命名和参数覆盖设置
- 请求日志查看和统计分析
- 配置导出/导入功能

## 🔍 监控和管理

```bash
# 健康检查
curl http://localhost:8080/health

# 服务状态
curl http://localhost:8080/admin/status

# 请求日志
curl http://localhost:8080/admin/logs
```

## 🚨 故障排除

### 常见问题
1. **服务启动失败**: 检查配置文件格式和端口占用
2. **API请求失败**: 验证API密钥有效性和网络连接
3. **Docker问题**: 检查容器日志 `docker logs turnsapi`

### 日志查看
```bash
# 查看实时日志
tail -f logs/turnsapi.log

# 查看错误日志
grep "ERROR" logs/turnsapi.log
```

## 📄 许可证

MIT License
