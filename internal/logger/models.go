package logger

import (
	"time"
)

// RequestLog 请求日志结构
type RequestLog struct {
	ID              int64  `json:"id" db:"id"`
	ProxyKeyName    string `json:"proxy_key_name" db:"proxy_key_name"` // 代理服务API密钥名称
	ProxyKeyID      string `json:"proxy_key_id" db:"proxy_key_id"`     // 代理服务API密钥ID
	ProviderGroup   string `json:"provider_group" db:"provider_group"` // 提供商分组
	OpenRouterKey   string `json:"openrouter_key" db:"openrouter_key"` // 使用的OpenRouter密钥（脱敏）
	Model           string `json:"model" db:"model"`
	RequestBody     string `json:"request_body" db:"request_body"`
	ResponseBody    string `json:"response_body" db:"response_body"`
	StatusCode      int    `json:"status_code" db:"status_code"`
	IsStream        bool   `json:"is_stream" db:"is_stream"`
	Duration        int64  `json:"duration" db:"duration"` // 毫秒
	TokensUsed      int    `json:"tokens_used" db:"tokens_used"`
	TokensEstimated bool   `json:"tokens_estimated" db:"tokens_estimated"` // 是否使用了备用估算方法
	Error           string `json:"error" db:"error"`
	ClientIP        string `json:"client_ip" db:"client_ip"` // 客户端IP地址
	// 工具调用相关字段
	HasToolCalls   bool      `json:"has_tool_calls" db:"has_tool_calls"`     // 是否包含工具调用
	ToolCallsCount int       `json:"tool_calls_count" db:"tool_calls_count"` // 工具调用数量
	ToolNames      string    `json:"tool_names" db:"tool_names"`             // 工具名称列表（逗号分隔）
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// RequestLogSummary 请求日志摘要（用于列表显示）
type RequestLogSummary struct {
	ID              int64  `json:"id"`
	ProxyKeyName    string `json:"proxy_key_name"`
	ProxyKeyID      string `json:"proxy_key_id"`
	ProviderGroup   string `json:"provider_group"`
	OpenRouterKey   string `json:"openrouter_key"`
	Model           string `json:"model"`
	StatusCode      int    `json:"status_code"`
	IsStream        bool   `json:"is_stream"`
	Duration        int64  `json:"duration"`
	TokensUsed      int    `json:"tokens_used"`
	TokensEstimated bool   `json:"tokens_estimated"`
	Error           string `json:"error"`
	ClientIP        string `json:"client_ip"`
	// 工具调用相关字段
	HasToolCalls   bool      `json:"has_tool_calls"`
	ToolCallsCount int       `json:"tool_calls_count"`
	ToolNames      string    `json:"tool_names"`
	CreatedAt      time.Time `json:"created_at"`
}

// ProxyKey 代理服务API密钥结构
type ProxyKey struct {
	ID                   string     `json:"id" db:"id"`
	Name                 string     `json:"name" db:"name"`
	Description          string     `json:"description" db:"description"`
	Key                  string     `json:"key" db:"key"`
	AllowedGroups        []string   `json:"allowed_groups" db:"allowed_groups"`                 // 允许访问的分组ID列表
	GroupSelectionConfig string     `json:"group_selection_config" db:"group_selection_config"` // 分组选择配置JSON字符串
	IsActive             bool       `json:"is_active" db:"is_active"`
	UsageCount           int64      `json:"usage_count" db:"usage_count"` // 使用次数
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
	LastUsedAt           *time.Time `json:"last_used_at" db:"last_used_at"`
}

// ProxyKeyStats 代理密钥统计
type ProxyKeyStats struct {
	ProxyKeyName    string  `json:"proxy_key_name"`
	ProxyKeyID      string  `json:"proxy_key_id"`
	TotalRequests   int64   `json:"total_requests"`
	SuccessRequests int64   `json:"success_requests"`
	ErrorRequests   int64   `json:"error_requests"`
	TotalTokens     int64   `json:"total_tokens"`
	AvgDuration     float64 `json:"avg_duration"`
}

// ModelStats 模型统计
type ModelStats struct {
	Model         string  `json:"model"`
	TotalRequests int64   `json:"total_requests"`
	TotalTokens   int64   `json:"total_tokens"`
	AvgDuration   float64 `json:"avg_duration"`
}

// LogFilter 日志筛选条件
type LogFilter struct {
	ProxyKeyName  string `json:"proxy_key_name"`
	ProviderGroup string `json:"provider_group"`
	Model         string `json:"model"`
	Status        string `json:"status"` // "200" 或 "error"
	Stream        string `json:"stream"` // "true" 或 "false"
	Limit         int    `json:"limit"`
	Offset        int    `json:"offset"`
	// 新增时间范围筛选：包含起止时间（闭区间），为空则不限制
	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
}

// TotalTokensStats 总token数统计结构
type TotalTokensStats struct {
	TotalTokens     int64 `json:"total_tokens"`
	SuccessTokens   int64 `json:"success_tokens"`
	TotalRequests   int64 `json:"total_requests"`
	SuccessRequests int64 `json:"success_requests"`
}

// StatusStats 状态分布聚合
type StatusStats struct {
	Success int64 `json:"success"`
	Error   int64 `json:"error"`
}

// TimelinePoint tokens 时间序列点
type TimelinePoint struct {
	Date    string `json:"date"`    // "YYYY-MM-DD" 或 "YYYY-MM-DD HH:00"
	Total   int64  `json:"total"`   // 总 tokens
	Success int64  `json:"success"` // 成功 tokens
}

// GroupTokensStat 分组 tokens 聚合
type GroupTokensStat struct {
	Group   string `json:"group"`
	Total   int64  `json:"total"`
	Success int64  `json:"success"`
}

// NOTE: duplicate TotalTokensStats definition removed
