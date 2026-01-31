package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"turnsapi/internal/netutil"
)

// ToolCallError 工具调用相关的错误类型
type ToolCallError struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ToolCallError) Error() string {
	return e.Message
}

// ChatMessage 聊天消息结构，支持多模态内容和工具调用
type ChatMessage struct {
	Role       string      `json:"role"`
	Content    interface{} `json:"content"`                // 支持字符串或多模态内容数组
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`   // 工具调用（assistant消息）
	ToolCallID string      `json:"tool_call_id,omitempty"` // 工具调用ID（tool消息）
}

// MessageContent 消息内容结构（用于多模态）
type MessageContent struct {
	Type     string           `json:"type"` // "text" 或 "image_url"
	Text     string           `json:"text,omitempty"`
	ImageURL *MessageImageURL `json:"image_url,omitempty"`
}

// MessageImageURL 图像URL结构
type MessageImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"` // "low", "high", "auto"
}

// Tool 工具定义结构
type Tool struct {
	Type     string    `json:"type"` // "function"
	Function *Function `json:"function,omitempty"`
}

// Function 函数定义结构
type Function struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// ToolChoice 工具选择策略
// 可以是字符串 ("none", "auto", "required") 或 ToolChoiceFunction 结构
type ToolChoice interface{}

// ToolChoiceFunction 指定特定函数的工具选择
type ToolChoiceFunction struct {
	Type     string          `json:"type"` // "function"
	Function *ToolChoiceFunc `json:"function"`
}

// ToolChoiceFunc 工具选择函数
type ToolChoiceFunc struct {
	Name string `json:"name"`
}

// ToolCall 工具调用结构
type ToolCall struct {
	ID       string        `json:"id"`
	Type     string        `json:"type"` // "function"
	Function *FunctionCall `json:"function,omitempty"`
}

// FunctionCall 函数调用结构
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatCompletionRequest 聊天完成请求结构
type ChatCompletionRequest struct {
	Model             string        `json:"model"`
	Messages          []ChatMessage `json:"messages"`
	Temperature       *float64      `json:"temperature,omitempty"`
	MaxTokens         *int          `json:"max_tokens,omitempty"`
	Stream            bool          `json:"stream,omitempty"`
	TopP              *float64      `json:"top_p,omitempty"`
	Stop              []string      `json:"stop,omitempty"`
	Tools             []Tool        `json:"tools,omitempty"`
	ToolChoice        ToolChoice    `json:"tool_choice,omitempty"`
	ParallelToolCalls *bool         `json:"parallel_tool_calls,omitempty"`

	// Extra keeps unmodeled top-level JSON fields (and forced overrides).
	Extra map[string]interface{} `json:"-"`
}

func (req ChatCompletionRequest) MarshalJSON() ([]byte, error) {
	type alias ChatCompletionRequest

	baseBytes, err := json.Marshal(alias(req))
	if err != nil {
		return nil, err
	}

	if len(req.Extra) == 0 {
		return baseBytes, nil
	}

	var m map[string]interface{}
	if err := json.Unmarshal(baseBytes, &m); err != nil {
		return nil, err
	}

	for k, v := range req.Extra {
		if _, exists := m[k]; exists {
			continue // typed fields win for known keys
		}
		m[k] = v
	}

	return json.Marshal(m)
}

// ApplyRequestParams 应用请求参数覆盖
func (req *ChatCompletionRequest) ApplyRequestParams(params map[string]interface{}) {
	if params == nil {
		return
	}

	if req.Extra == nil {
		req.Extra = make(map[string]interface{})
	}

	toFloat64 := func(v interface{}) (float64, bool) {
		switch n := v.(type) {
		case float64:
			return n, true
		case float32:
			return float64(n), true
		case int:
			return float64(n), true
		case int64:
			return float64(n), true
		case uint64:
			return float64(n), true
		case json.Number:
			f, err := n.Float64()
			return f, err == nil
		case string:
			f, err := strconv.ParseFloat(n, 64)
			return f, err == nil
		default:
			return 0, false
		}
	}

	toInt := func(v interface{}) (int, bool) {
		switch n := v.(type) {
		case int:
			return n, true
		case int64:
			return int(n), true
		case uint64:
			return int(n), true
		case float64:
			return int(n), true
		case json.Number:
			i, err := n.Int64()
			return int(i), err == nil
		case string:
			i, err := strconv.Atoi(n)
			return i, err == nil
		default:
			return 0, false
		}
	}

	toBool := func(v interface{}) (bool, bool) {
		switch b := v.(type) {
		case bool:
			return b, true
		case string:
			parsed, err := strconv.ParseBool(b)
			return parsed, err == nil
		default:
			return false, false
		}
	}

	// 应用温度参数
	if temp, ok := params["temperature"]; ok {
		if tempFloat, ok := toFloat64(temp); ok {
			req.Temperature = &tempFloat
			delete(req.Extra, "temperature")
		}
	}

	// 应用最大token数
	if maxTokens, ok := params["max_tokens"]; ok {
		if maxTokensInt, ok := toInt(maxTokens); ok {
			req.MaxTokens = &maxTokensInt
			delete(req.Extra, "max_tokens")
		}
	}

	// 应用top_p参数
	if topP, ok := params["top_p"]; ok {
		if topPFloat, ok := toFloat64(topP); ok {
			req.TopP = &topPFloat
			delete(req.Extra, "top_p")
		}
	}

	// 应用stop参数
	if stop, ok := params["stop"]; ok {
		if stopSlice, ok := stop.([]interface{}); ok {
			stopStrings := make([]string, 0, len(stopSlice))
			for _, s := range stopSlice {
				if str, ok := s.(string); ok {
					stopStrings = append(stopStrings, str)
				}
			}
			req.Stop = stopStrings
			delete(req.Extra, "stop")
		} else if stopSlice, ok := stop.([]string); ok {
			req.Stop = stopSlice
			delete(req.Extra, "stop")
		} else if stopStr, ok := stop.(string); ok {
			req.Stop = []string{stopStr}
			delete(req.Extra, "stop")
		}
	}

	// stream mode can be forced per-group
	if stream, ok := params["stream"]; ok {
		if streamBool, ok := toBool(stream); ok {
			req.Stream = streamBool
			delete(req.Extra, "stream")
		}
	}

	// Force override any other top-level JSON fields (unmodeled).
	for k, v := range params {
		switch k {
		case "temperature", "max_tokens", "top_p", "stop", "stream":
			continue
		default:
			req.Extra[k] = v
		}
	}
}

// ChatCompletionChoice 聊天完成选择结构
type ChatCompletionChoice struct {
	Index        int                   `json:"index"`
	Message      ChatCompletionMessage `json:"message"`
	FinishReason string                `json:"finish_reason"`
}

// ChatCompletionMessage 聊天完成消息结构
type ChatCompletionMessage struct {
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

// Usage 使用情况统计
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatCompletionResponse 聊天完成响应结构
type ChatCompletionResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Created int64                  `json:"created"`
	Model   string                 `json:"model"`
	Choices []ChatCompletionChoice `json:"choices"`
	Usage   Usage                  `json:"usage"`
}

// StreamResponse 流式响应结构
type StreamResponse struct {
	Data  []byte
	Error error
	Done  bool
}

// ProviderConfig 提供商配置
type ProviderConfig struct {
	BaseURL       string
	APIKey        string
	Timeout       time.Duration
	MaxRetries    int
	Headers       map[string]string
	ProviderType  string
	RequestParams map[string]interface{} // JSON请求参数覆盖
}

// Provider 提供商接口
type Provider interface {
	// GetProviderType 获取提供商类型
	GetProviderType() string

	// ChatCompletion 发送聊天完成请求
	ChatCompletion(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error)

	// ChatCompletionStream 发送流式聊天完成请求
	ChatCompletionStream(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error)

	// ChatCompletionStreamNative 发送原生格式流式聊天完成请求
	ChatCompletionStreamNative(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error)

	// GetModels 获取可用模型列表
	GetModels(ctx context.Context) (interface{}, error)

	// HealthCheck 健康检查
	HealthCheck(ctx context.Context) error

	// TransformRequest 将标准请求转换为提供商特定格式
	TransformRequest(req *ChatCompletionRequest) (interface{}, error)

	// TransformResponse 将提供商响应转换为标准格式
	TransformResponse(resp interface{}) (*ChatCompletionResponse, error)

	// CreateHTTPRequest 创建HTTP请求
	CreateHTTPRequest(ctx context.Context, endpoint string, body interface{}) (*http.Request, error)

	// ParseHTTPResponse 解析HTTP响应
	ParseHTTPResponse(resp *http.Response) (interface{}, error)
}

// ProviderFactory 提供商工厂接口
type ProviderFactory interface {
	CreateProvider(config *ProviderConfig) (Provider, error)
	GetSupportedTypes() []string
}

// BaseProvider 基础提供商实现
type BaseProvider struct {
	Config     *ProviderConfig
	HTTPClient *http.Client
}

// NewBaseProvider 创建基础提供商
func NewBaseProvider(config *ProviderConfig) *BaseProvider {
	return &BaseProvider{
		Config:     config,
		HTTPClient: netutil.NewClient(config.Timeout),
	}
}

// GetProviderType 获取提供商类型
func (bp *BaseProvider) GetProviderType() string {
	return bp.Config.ProviderType
}

// CreateHTTPRequest 创建HTTP请求
func (bp *BaseProvider) CreateHTTPRequest(ctx context.Context, endpoint string, body interface{}) (*http.Request, error) {
	var bodyReader io.Reader

	if body != nil {
		// 这里需要根据具体实现来序列化body
		// 在具体的提供商实现中会重写这个方法
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bodyReader)
	if err != nil {
		return nil, err
	}

	// 设置通用头部
	for key, value := range bp.Config.Headers {
		req.Header.Set(key, value)
	}

	return req, nil
}

// HealthCheck 默认健康检查实现
func (bp *BaseProvider) HealthCheck(ctx context.Context) error {
	// 默认实现，具体提供商可以重写
	return nil
}

// ChatCompletionStreamNative 默认原生流式响应实现
func (bp *BaseProvider) ChatCompletionStreamNative(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 默认实现：调用标准流式响应
	// 具体提供商可以重写此方法来提供真正的原生响应
	return bp.ChatCompletionStream(ctx, req)
}

// ChatCompletionStream 默认流式响应实现
func (bp *BaseProvider) ChatCompletionStream(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 默认实现，具体提供商需要重写
	return nil, fmt.Errorf("streaming not implemented for this provider")
}
