# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TurnsAPI is a multi-provider API proxy service written in Go that provides a unified OpenAI-compatible interface for multiple LLM providers (OpenAI, Google Gemini, Anthropic Claude, Azure OpenAI, OpenRouter).

## Build and Run Commands

```bash
# Install dependencies
go mod tidy

# Run locally
go run cmd/turnsapi/main.go -config config/config.yaml

# Build binary
go build -o turnsapi ./cmd/turnsapi

# Run tests
go test ./...

# Run single test file
go test ./internal/providers/providers_test.go

# Run with specific config and database paths
./turnsapi -config config/config.yaml -db data/turnsapi.db

# Docker build
docker build -t turnsapi .

# Docker run
docker run -d -p 8080:8080 -v $(pwd)/config:/app/config turnsapi
```

## Architecture

### Entry Point
- [cmd/turnsapi/main.go](cmd/turnsapi/main.go) - Application entry point with graceful shutdown handling

### Core Components

**Provider System** (`internal/providers/`):
- [interface.go](internal/providers/interface.go) - Defines `Provider` interface that all providers implement
- [openai.go](internal/providers/openai.go) - OpenAI/OpenRouter provider
- [gemini.go](internal/providers/gemini.go) - Google Gemini provider
- [anthropic.go](internal/providers/anthropic.go) - Anthropic Claude provider
- [factory.go](internal/providers/factory.go) - Provider factory for creating providers by type

**API Layer** (`internal/api/`):
- [multi_provider_server.go](internal/api/multi_provider_server.go) - Main HTTP server handling multi-provider routing
- [server.go](internal/api/server.go) - Base server implementation

**Proxy Layer** (`internal/proxy/`):
- [multi_provider_proxy.go](internal/proxy/multi_provider_proxy.go) - Multi-provider proxy with failover logic
- [proxy.go](internal/proxy/proxy.go) - Base proxy implementation

**Key Management** (`internal/keymanager/`):
- [multi_group_manager.go](internal/keymanager/multi_group_manager.go) - Manages API keys across multiple provider groups with rotation strategies (round_robin, random, least_used)

**Configuration** (`internal/`):
- [config.go](internal/config.go) - Configuration structures
- [config_manager.go](internal/config_manager.go) - Hot-reload configuration management

**Other Components**:
- [internal/router/provider_router.go](internal/router/provider_router.go) - Routes requests to appropriate provider groups
- [internal/auth/auth.go](internal/auth/auth.go) - Session-based authentication
- [internal/database/groups.go](internal/database/groups.go) - SQLite database for group and key state persistence
- [internal/logger/](internal/logger/) - Request logging
- [internal/ratelimit/](internal/ratelimit/) - RPM rate limiting per group

### Web Interface
- [web/templates/](web/templates/) - HTML templates for the admin dashboard

### Configuration
- [config/config.yaml](config/config.yaml) - Main configuration file
- [config/config.example.yaml](config/config.example.yaml) - Example configuration with all options documented

## Key Concepts

**Provider Groups**: Each group (`user_groups` in config) defines a provider connection with:
- Provider type (openai, gemini, anthropic, azure_openai)
- Base URL and API keys (supports multiple keys for rotation)
- Model mappings for aliasing
- Request parameter overrides (temperature, max_tokens, etc.)
- RPM limits and rotation strategies

**Request Flow**:
1. Request hits API server → Router selects provider group by model or `X-Provider-Group` header
2. KeyManager selects API key using rotation strategy
3. Provider transforms request to provider-specific format
4. Response transformed back to OpenAI-compatible format

**Streaming**: Full SSE streaming support with `ChatCompletionStream` and `ChatCompletionStreamNative` methods. Native mode returns provider's original response format.

## Supported Provider Types
- `openai` - OpenAI API and compatible services (including OpenRouter)
- `gemini` - Google Gemini API
- `anthropic` - Anthropic Claude API
- `azure_openai` - Azure OpenAI Service
