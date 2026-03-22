package logger

import "time"

// RequestLog stores a full request log row.
type RequestLog struct {
	ID              int64     `json:"id" db:"id"`
	ProxyKeyName    string    `json:"proxy_key_name" db:"proxy_key_name"`
	ProxyKeyID      string    `json:"proxy_key_id" db:"proxy_key_id"`
	ProviderGroup   string    `json:"provider_group" db:"provider_group"`
	OpenRouterKey   string    `json:"openrouter_key" db:"openrouter_key"`
	Model           string    `json:"model" db:"model"`
	RequestBody     string    `json:"request_body" db:"request_body"`
	ResponseBody    string    `json:"response_body" db:"response_body"`
	StatusCode      int       `json:"status_code" db:"status_code"`
	IsStream        bool      `json:"is_stream" db:"is_stream"`
	Duration        int64     `json:"duration" db:"duration"`
	TokensUsed      int       `json:"tokens_used" db:"tokens_used"`
	TokensEstimated bool      `json:"tokens_estimated" db:"tokens_estimated"`
	Error           string    `json:"error" db:"error"`
	ClientIP        string    `json:"client_ip" db:"client_ip"`
	HasToolCalls    bool      `json:"has_tool_calls" db:"has_tool_calls"`
	ToolCallsCount  int       `json:"tool_calls_count" db:"tool_calls_count"`
	ToolNames       string    `json:"tool_names" db:"tool_names"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

// RequestLogSummary stores list page fields for a request log.
type RequestLogSummary struct {
	ID              int64     `json:"id"`
	ProxyKeyName    string    `json:"proxy_key_name"`
	ProxyKeyID      string    `json:"proxy_key_id"`
	ProviderGroup   string    `json:"provider_group"`
	OpenRouterKey   string    `json:"openrouter_key"`
	Model           string    `json:"model"`
	StatusCode      int       `json:"status_code"`
	IsStream        bool      `json:"is_stream"`
	Duration        int64     `json:"duration"`
	TokensUsed      int       `json:"tokens_used"`
	TokensEstimated bool      `json:"tokens_estimated"`
	Error           string    `json:"error"`
	ClientIP        string    `json:"client_ip"`
	HasToolCalls    bool      `json:"has_tool_calls"`
	ToolCallsCount  int       `json:"tool_calls_count"`
	ToolNames       string    `json:"tool_names"`
	CreatedAt       time.Time `json:"created_at"`
}

// ProxyKey stores a proxy key row.
type ProxyKey struct {
	ID                   string     `json:"id" db:"id"`
	Name                 string     `json:"name" db:"name"`
	Description          string     `json:"description" db:"description"`
	Key                  string     `json:"key" db:"key"`
	AllowedGroups        []string   `json:"allowed_groups" db:"allowed_groups"`
	GroupSelectionConfig string     `json:"group_selection_config" db:"group_selection_config"`
	IsActive             bool       `json:"is_active" db:"is_active"`
	EnforceModelMappings bool       `json:"enforce_model_mappings" db:"enforce_model_mappings"`
	UsageCount           int64      `json:"usage_count" db:"usage_count"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
	LastUsedAt           *time.Time `json:"last_used_at" db:"last_used_at"`
}

// ProxyKeyStats stores aggregated proxy key stats.
type ProxyKeyStats struct {
	ProxyKeyName    string  `json:"proxy_key_name"`
	ProxyKeyID      string  `json:"proxy_key_id"`
	TotalRequests   int64   `json:"total_requests"`
	SuccessRequests int64   `json:"success_requests"`
	ErrorRequests   int64   `json:"error_requests"`
	TotalTokens     int64   `json:"total_tokens"`
	AvgDuration     float64 `json:"avg_duration"`
}

// ModelStats stores aggregated model stats.
type ModelStats struct {
	Model         string  `json:"model"`
	TotalRequests int64   `json:"total_requests"`
	TotalTokens   int64   `json:"total_tokens"`
	AvgDuration   float64 `json:"avg_duration"`
}

// LogFilter stores request log filter fields.
type LogFilter struct {
	ProxyKeyName  string     `json:"proxy_key_name"`
	ProviderGroup string     `json:"provider_group"`
	Model         string     `json:"model"`
	Status        string     `json:"status"`
	Stream        string     `json:"stream"`
	Limit         int        `json:"limit"`
	Offset        int        `json:"offset"`
	StartTime     *time.Time `json:"start_time"`
	EndTime       *time.Time `json:"end_time"`
}

// LogFilterOptions stores distinct filter options.
type LogFilterOptions struct {
	ProxyKeys      []string `json:"proxy_keys"`
	ProviderGroups []string `json:"provider_groups"`
	Models         []string `json:"models"`
}

// TotalTokensStats stores token totals.
type TotalTokensStats struct {
	TotalTokens     int64 `json:"total_tokens"`
	SuccessTokens   int64 `json:"success_tokens"`
	TotalRequests   int64 `json:"total_requests"`
	SuccessRequests int64 `json:"success_requests"`
}

// StatusStats stores success and error counts.
type StatusStats struct {
	Success int64 `json:"success"`
	Error   int64 `json:"error"`
}

// TimelinePoint stores a tokens timeline point.
type TimelinePoint struct {
	Date    string `json:"date"`
	Total   int64  `json:"total"`
	Success int64  `json:"success"`
}

// GroupTokensStat stores group token totals.
type GroupTokensStat struct {
	Group   string `json:"group"`
	Total   int64  `json:"total"`
	Success int64  `json:"success"`
}

// LogOverviewStats stores overview metrics for logs.
type LogOverviewStats struct {
	TotalRequests   int64   `json:"total_requests"`
	SuccessRequests int64   `json:"success_requests"`
	ErrorRequests   int64   `json:"error_requests"`
	TotalTokens     int64   `json:"total_tokens"`
	AvgDuration     float64 `json:"avg_duration"`
}
