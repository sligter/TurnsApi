package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// AnthropicProvider Anthropic Claude提供商
type AnthropicProvider struct {
	*BaseProvider
}

// AnthropicRequest Anthropic API请求结构
type AnthropicRequest struct {
	Model         string                   `json:"model"`
	MaxTokens     int                      `json:"max_tokens"`
	Messages      []AnthropicMessage       `json:"messages"`
	System        interface{}              `json:"system,omitempty"`         // 支持字符串或数组格式
	Temperature   *float64                 `json:"temperature,omitempty"`
	TopP          *float64                 `json:"top_p,omitempty"`
	TopK          *int                     `json:"top_k,omitempty"`
	StopSequences []string                 `json:"stop_sequences,omitempty"`
	Stream        bool                     `json:"stream,omitempty"`
	Tools         []AnthropicTool          `json:"tools,omitempty"`
	ToolChoice    *AnthropicToolChoice     `json:"tool_choice,omitempty"`
	Thinking      *AnthropicThinkingConfig `json:"thinking,omitempty"`
}

// AnthropicThinkingConfig 思考配置
type AnthropicThinkingConfig struct {
	Type         string `json:"type"`                    // "enabled" 或 "disabled"
	BudgetTokens int    `json:"budget_tokens,omitempty"` // 思考token预算 (>=1024)
}

// AnthropicTool Anthropic工具定义
type AnthropicTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"input_schema"`
	Type        string                 `json:"type,omitempty"`         // "custom" 或内置类型
	CacheControl *AnthropicCacheControl `json:"cache_control,omitempty"`
}

// AnthropicCacheControl 缓存控制
type AnthropicCacheControl struct {
	Type string `json:"type"` // "ephemeral"
	TTL  string `json:"ttl,omitempty"` // "5m" 或 "1h"
}

// AnthropicToolChoice 工具选择策略
type AnthropicToolChoice struct {
	Type                   string `json:"type"`                               // "auto", "any", "tool", "none"
	Name                   string `json:"name,omitempty"`                     // 当type为"tool"时使用
	DisableParallelToolUse bool   `json:"disable_parallel_tool_use,omitempty"`
}

// AnthropicMessage Anthropic消息结构
type AnthropicMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // 可以是字符串或内容块数组
}

// AnthropicContentBlock Anthropic内容块
type AnthropicContentBlock struct {
	Type      string                 `json:"type"`                 // "text", "image", "tool_use", "tool_result", "thinking"
	Text      string                 `json:"text,omitempty"`       // for text type
	ID        string                 `json:"id,omitempty"`         // for tool_use type
	Name      string                 `json:"name,omitempty"`       // for tool_use type
	Input     map[string]interface{} `json:"input,omitempty"`      // for tool_use type
	ToolUseID string                 `json:"tool_use_id,omitempty"` // for tool_result type
	Content   interface{}            `json:"content,omitempty"`    // for tool_result type (可以是字符串或内容块数组)
	IsError   bool                   `json:"is_error,omitempty"`   // for tool_result type
	Thinking  string                 `json:"thinking,omitempty"`   // for thinking type
	Signature string                 `json:"signature,omitempty"`  // for thinking type
	Source    *AnthropicImageSource  `json:"source,omitempty"`     // for image type
}

// AnthropicImageSource 图像来源
type AnthropicImageSource struct {
	Type      string `json:"type"`       // "base64" 或 "url"
	MediaType string `json:"media_type,omitempty"` // 媒体类型
	Data      string `json:"data,omitempty"`       // base64数据
	URL       string `json:"url,omitempty"`        // URL
}

// AnthropicResponse Anthropic API响应结构
type AnthropicResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"`
	Role         string                  `json:"role"`
	Content      []AnthropicContentBlock `json:"content"`
	Model        string                  `json:"model"`
	StopReason   string                  `json:"stop_reason"`
	StopSequence string                  `json:"stop_sequence"`
	Usage        AnthropicUsage          `json:"usage"`
}

// AnthropicUsage Anthropic使用统计
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
}

// NewAnthropicProvider 创建Anthropic提供商
func NewAnthropicProvider(config *ProviderConfig) *AnthropicProvider {
	return &AnthropicProvider{
		BaseProvider: NewBaseProvider(config),
	}
}

// getEndpoint 获取API端点URL
func (p *AnthropicProvider) getEndpoint(path string) string {
	baseURL := strings.TrimRight(p.Config.BaseURL, "/")
	if strings.HasSuffix(baseURL, "/v1") {
		return baseURL + path
	}
	return baseURL + "/v1" + path
}

// ChatCompletion 发送聊天完成请求
func (p *AnthropicProvider) ChatCompletion(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	// 转换请求格式
	anthropicReq, err := p.transformToAnthropicRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to transform request: %w", err)
	}

	endpoint := p.getEndpoint("/messages")

	log.Printf("🔧 Anthropic ChatCompletion - Endpoint: %s, APIKey: %s****", endpoint, p.Config.APIKey[:4])

	reqBody, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 设置Anthropic特定的头部
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.Config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	// 设置自定义头部
	for key, value := range p.Config.Headers {
		if key != "x-api-key" {
			httpReq.Header.Set(key, value)
		}
	}

	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var anthropicResp AnthropicResponse
	if err := json.Unmarshal(bodyBytes, &anthropicResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// 转换响应格式
	return p.transformFromAnthropicResponse(&anthropicResp)
}

// ChatCompletionStream 发送流式聊天完成请求
func (p *AnthropicProvider) ChatCompletionStream(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 转换请求格式并设置stream为true
	anthropicReq, err := p.transformToAnthropicRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to transform request: %w", err)
	}
	anthropicReq.Stream = true

	endpoint := p.getEndpoint("/messages")

	reqBody, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 设置头部
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.Config.APIKey)
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Cache-Control", "no-cache")
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	// 设置自定义头部
	for key, value := range p.Config.Headers {
		if key != "x-api-key" {
			httpReq.Header.Set(key, value)
		}
	}

	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	streamChan := make(chan StreamResponse, 10)

	go func() {
		defer close(streamChan)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		// 增加缓冲区大小以处理大型响应
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		var currentToolCall *ToolCall
		var toolCallIndex int = 0

		for scanner.Scan() {
			line := scanner.Text()

			// Anthropic使用Server-Sent Events格式
			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimPrefix(line, "data: ")

				// 检查是否为结束标记
				if data == "[DONE]" {
					streamChan <- StreamResponse{
						Data: []byte("data: [DONE]\n\n"),
						Done: true,
					}
					return
				}

				// 解析Anthropic流式数据并转换为OpenAI格式
				var anthropicEvent map[string]interface{}
				if err := json.Unmarshal([]byte(data), &anthropicEvent); err == nil {
					eventType, _ := anthropicEvent["type"].(string)

					switch eventType {
					case "content_block_start":
						// 处理内容块开始
						if contentBlock, ok := anthropicEvent["content_block"].(map[string]interface{}); ok {
							blockType, _ := contentBlock["type"].(string)
							if blockType == "tool_use" {
								// 开始新的工具调用
								toolID, _ := contentBlock["id"].(string)
								toolName, _ := contentBlock["name"].(string)
								currentToolCall = &ToolCall{
									ID:   toolID,
									Type: "function",
									Function: &FunctionCall{
										Name:      toolName,
										Arguments: "",
									},
								}

								// 发送工具调用开始的chunk
								openaiData := map[string]interface{}{
									"id":      fmt.Sprintf("chatcmpl-%d", time.Now().Unix()),
									"object":  "chat.completion.chunk",
									"created": time.Now().Unix(),
									"model":   req.Model,
									"choices": []map[string]interface{}{
										{
											"index": 0,
											"delta": map[string]interface{}{
												"tool_calls": []map[string]interface{}{
													{
														"index": toolCallIndex,
														"id":    toolID,
														"type":  "function",
														"function": map[string]interface{}{
															"name":      toolName,
															"arguments": "",
														},
													},
												},
											},
											"finish_reason": nil,
										},
									},
								}

								if jsonData, err := json.Marshal(openaiData); err == nil {
									streamChan <- StreamResponse{
										Data: []byte("data: " + string(jsonData) + "\n\n"),
										Done: false,
									}
								}
							}
						}

					case "content_block_delta":
						if delta, ok := anthropicEvent["delta"].(map[string]interface{}); ok {
							deltaType, _ := delta["type"].(string)

							switch deltaType {
							case "text_delta":
								// 文本内容
								if text, ok := delta["text"].(string); ok {
									openaiData := map[string]interface{}{
										"id":      fmt.Sprintf("chatcmpl-%d", time.Now().Unix()),
										"object":  "chat.completion.chunk",
										"created": time.Now().Unix(),
										"model":   req.Model,
										"choices": []map[string]interface{}{
											{
												"index": 0,
												"delta": map[string]interface{}{
													"content": text,
												},
												"finish_reason": nil,
											},
										},
									}

									if jsonData, err := json.Marshal(openaiData); err == nil {
										streamChan <- StreamResponse{
											Data: []byte("data: " + string(jsonData) + "\n\n"),
											Done: false,
										}
									}
								}

							case "input_json_delta":
								// 工具调用参数增量
								if partialJSON, ok := delta["partial_json"].(string); ok && currentToolCall != nil {
									currentToolCall.Function.Arguments += partialJSON

									openaiData := map[string]interface{}{
										"id":      fmt.Sprintf("chatcmpl-%d", time.Now().Unix()),
										"object":  "chat.completion.chunk",
										"created": time.Now().Unix(),
										"model":   req.Model,
										"choices": []map[string]interface{}{
											{
												"index": 0,
												"delta": map[string]interface{}{
													"tool_calls": []map[string]interface{}{
														{
															"index": toolCallIndex,
															"function": map[string]interface{}{
																"arguments": partialJSON,
															},
														},
													},
												},
												"finish_reason": nil,
											},
										},
									}

									if jsonData, err := json.Marshal(openaiData); err == nil {
										streamChan <- StreamResponse{
											Data: []byte("data: " + string(jsonData) + "\n\n"),
											Done: false,
										}
									}
								}

							case "thinking_delta":
								// 思考内容 - 可以选择性地转发或忽略
								// 当前实现：忽略思考内容（符合OpenAI格式）
							}
						}

					case "content_block_stop":
						// 内容块结束
						if currentToolCall != nil {
							toolCallIndex++
							currentToolCall = nil
						}

					case "message_delta":
						// 消息级别的增量更新
						if delta, ok := anthropicEvent["delta"].(map[string]interface{}); ok {
							if stopReason, ok := delta["stop_reason"].(string); ok && stopReason != "" {
								finishReason := p.convertStopReason(stopReason)
								openaiData := map[string]interface{}{
									"id":      fmt.Sprintf("chatcmpl-%d", time.Now().Unix()),
									"object":  "chat.completion.chunk",
									"created": time.Now().Unix(),
									"model":   req.Model,
									"choices": []map[string]interface{}{
										{
											"index":         0,
											"delta":         map[string]interface{}{},
											"finish_reason": finishReason,
										},
									},
								}

								if jsonData, err := json.Marshal(openaiData); err == nil {
									streamChan <- StreamResponse{
										Data: []byte("data: " + string(jsonData) + "\n\n"),
										Done: false,
									}
								}
							}
						}

					case "message_stop":
						// 发送结束标记
						streamChan <- StreamResponse{
							Data: []byte("data: [DONE]\n\n"),
							Done: true,
						}
						return
					}
				}
			}
		}

		if err := scanner.Err(); err != nil {
			streamChan <- StreamResponse{
				Error: err,
				Done:  true,
			}
		}
	}()

	return streamChan, nil
}

// ChatCompletionStreamNative 发送原生格式流式聊天完成请求
func (p *AnthropicProvider) ChatCompletionStreamNative(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 转换请求格式并设置stream为true
	anthropicReq, err := p.transformToAnthropicRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to transform request: %w", err)
	}
	anthropicReq.Stream = true

	endpoint := p.getEndpoint("/messages")

	reqBody, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 设置头部
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.Config.APIKey)
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Cache-Control", "no-cache")
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	// 设置自定义头部
	for key, value := range p.Config.Headers {
		if key != "x-api-key" {
			httpReq.Header.Set(key, value)
		}
	}

	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	streamChan := make(chan StreamResponse, 10)

	go func() {
		defer close(streamChan)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			line := scanner.Text()

			// 发送原始Anthropic SSE数据
			streamChan <- StreamResponse{
				Data: []byte(line + "\n"),
				Done: false,
			}

			// 检查是否结束
			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimPrefix(line, "data: ")
				if data == "[DONE]" {
					streamChan <- StreamResponse{
						Done: true,
					}
					return
				}

				// 解析事件类型以检查是否结束
				var event map[string]interface{}
				if err := json.Unmarshal([]byte(data), &event); err == nil {
					if eventType, ok := event["type"].(string); ok && eventType == "message_stop" {
						streamChan <- StreamResponse{
							Done: true,
						}
						return
					}
				}
			}
		}

		if err := scanner.Err(); err != nil {
			streamChan <- StreamResponse{
				Error: err,
				Done:  true,
			}
		}
	}()

	return streamChan, nil
}

// GetModels 获取可用模型列表
func (p *AnthropicProvider) GetModels(ctx context.Context) (interface{}, error) {
	endpoint := p.getEndpoint("/models")

	httpReq, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("x-api-key", p.Config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("Content-Type", "application/json")

	for key, value := range p.Config.Headers {
		httpReq.Header.Set(key, value)
	}

	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var anthropicResp struct {
		Data []struct {
			ID          string `json:"id"`
			Type        string `json:"type"`
			DisplayName string `json:"display_name"`
			CreatedAt   string `json:"created_at"`
		} `json:"data"`
		HasMore bool `json:"has_more"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&anthropicResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// 转换为标准OpenAI格式
	models := map[string]interface{}{
		"object": "list",
		"data":   []map[string]interface{}{},
	}

	data := models["data"].([]map[string]interface{})
	for _, model := range anthropicResp.Data {
		var created int64
		if parsedTime, err := time.Parse(time.RFC3339, model.CreatedAt); err == nil {
			created = parsedTime.Unix()
		} else {
			created = time.Now().Unix()
		}

		// 推断模型能力
		capabilities := inferAnthropicCapabilities(model.ID)

		// 推断上下文窗口
		contextWindow := inferAnthropicContextWindow(model.ID)

		data = append(data, map[string]interface{}{
			"id":             model.ID,
			"object":         "model",
			"created":        created,
			"owned_by":       "anthropic",
			"display_name":   model.DisplayName,
			"capabilities":   capabilities,
			"context_window": contextWindow,
		})
	}
	models["data"] = data

	return models, nil
}

// inferAnthropicCapabilities 根据模型ID推断能力
func inferAnthropicCapabilities(modelID string) []string {
	capabilities := []string{"chat"}

	// Claude 3 系列支持视觉和函数调用
	if strings.Contains(modelID, "claude-3") {
		capabilities = append(capabilities, "vision", "function_calling")
	}

	// Claude 3.5 系列也支持视觉和函数调用
	if strings.Contains(modelID, "claude-3-5") || strings.Contains(modelID, "claude-3.5") {
		capabilities = append(capabilities, "vision", "function_calling")
	}

	return capabilities
}

// inferAnthropicContextWindow 根据模型ID推断上下文窗口
func inferAnthropicContextWindow(modelID string) int {
	// Claude 3 Opus: 200K tokens
	if strings.Contains(modelID, "claude-3-opus") {
		return 200000
	}

	// Claude 3.5 Sonnet: 200K tokens
	if strings.Contains(modelID, "claude-3-5-sonnet") || strings.Contains(modelID, "claude-3.5-sonnet") {
		return 200000
	}

	// Claude 3 Sonnet: 200K tokens
	if strings.Contains(modelID, "claude-3-sonnet") {
		return 200000
	}

	// Claude 3 Haiku: 200K tokens
	if strings.Contains(modelID, "claude-3-haiku") {
		return 200000
	}

	// 默认值
	return 200000
}

// HealthCheck 健康检查
func (p *AnthropicProvider) HealthCheck(ctx context.Context) error {
	endpoint := p.getEndpoint("/models")

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("x-api-key", p.Config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	for key, value := range p.Config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send health check request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("health check failed with status %d: %s", resp.StatusCode, string(body))
}

// TransformRequest 转换请求为Anthropic格式
func (p *AnthropicProvider) TransformRequest(req *ChatCompletionRequest) (interface{}, error) {
	return p.transformToAnthropicRequest(req)
}

// TransformResponse 转换Anthropic响应为标准格式
func (p *AnthropicProvider) TransformResponse(resp interface{}) (*ChatCompletionResponse, error) {
	if anthropicResp, ok := resp.(*AnthropicResponse); ok {
		return p.transformFromAnthropicResponse(anthropicResp)
	}
	return nil, fmt.Errorf("invalid response type")
}

// transformToAnthropicRequest 将标准请求转换为Anthropic格式
func (p *AnthropicProvider) transformToAnthropicRequest(req *ChatCompletionRequest) (*AnthropicRequest, error) {
	messages := make([]AnthropicMessage, 0, len(req.Messages))
	var systemContent interface{}

	for _, msg := range req.Messages {
		switch msg.Role {
		case "system":
			// 系统消息作为单独的参数传递
			systemContent = p.extractContentForAnthropic(msg.Content)

		case "user", "assistant":
			content := p.convertMessageContent(msg)
			messages = append(messages, AnthropicMessage{
				Role:    msg.Role,
				Content: content,
			})

		case "tool":
			// 工具结果消息 - 转换为tool_result内容块
			content := []AnthropicContentBlock{
				{
					Type:      "tool_result",
					ToolUseID: msg.ToolCallID,
					Content:   p.extractTextContent(msg.Content),
				},
			}
			messages = append(messages, AnthropicMessage{
				Role:    "user",
				Content: content,
			})
		}
	}

	// Anthropic要求必须有max_tokens
	maxTokens := 4096
	if req.MaxTokens != nil {
		maxTokens = *req.MaxTokens
	}

	anthropicReq := &AnthropicRequest{
		Model:     req.Model,
		MaxTokens: maxTokens,
		Messages:  messages,
	}

	// 设置系统提示
	if systemContent != nil {
		anthropicReq.System = systemContent
	}

	// 设置可选参数
	if req.Temperature != nil {
		anthropicReq.Temperature = req.Temperature
	}
	if req.TopP != nil {
		anthropicReq.TopP = req.TopP
	}
	if len(req.Stop) > 0 {
		anthropicReq.StopSequences = req.Stop
	}

	// 转换工具定义
	if len(req.Tools) > 0 {
		tools, err := p.convertToolsToAnthropic(req.Tools)
		if err != nil {
			return nil, fmt.Errorf("failed to convert tools: %w", err)
		}
		anthropicReq.Tools = tools

		// 转换tool_choice
		if req.ToolChoice != nil {
			toolChoice := p.convertToolChoice(req.ToolChoice)
			if toolChoice != nil {
				anthropicReq.ToolChoice = toolChoice
			}
		}
	}

	return anthropicReq, nil
}

// convertMessageContent 转换消息内容为Anthropic格式
func (p *AnthropicProvider) convertMessageContent(msg ChatMessage) interface{} {
	// 如果有工具调用，转换为tool_use内容块
	if len(msg.ToolCalls) > 0 {
		content := make([]AnthropicContentBlock, 0)

		// 先添加文本内容（如果有）
		textContent := p.extractTextContent(msg.Content)
		if textContent != "" {
			content = append(content, AnthropicContentBlock{
				Type: "text",
				Text: textContent,
			})
		}

		// 添加工具调用
		for _, tc := range msg.ToolCalls {
			var input map[string]interface{}
			if tc.Function != nil && tc.Function.Arguments != "" {
				json.Unmarshal([]byte(tc.Function.Arguments), &input)
			}

			content = append(content, AnthropicContentBlock{
				Type:  "tool_use",
				ID:    tc.ID,
				Name:  tc.Function.Name,
				Input: input,
			})
		}

		return content
	}

	// 处理普通内容
	return p.extractContentForAnthropic(msg.Content)
}

// extractContentForAnthropic 提取并格式化内容为Anthropic格式
func (p *AnthropicProvider) extractContentForAnthropic(content interface{}) interface{} {
	switch v := content.(type) {
	case string:
		return v
	case []interface{}:
		// 多模态内容
		result := make([]AnthropicContentBlock, 0)
		for _, item := range v {
			if itemMap, ok := item.(map[string]interface{}); ok {
				itemType, _ := itemMap["type"].(string)
				switch itemType {
				case "text":
					text, _ := itemMap["text"].(string)
					result = append(result, AnthropicContentBlock{
						Type: "text",
						Text: text,
					})
				case "image_url":
					if imageURL, ok := itemMap["image_url"].(map[string]interface{}); ok {
						url, _ := imageURL["url"].(string)
						// 检查是否是base64编码
						if strings.HasPrefix(url, "data:") {
							parts := strings.SplitN(url, ",", 2)
							if len(parts) == 2 {
								mediaType := strings.TrimPrefix(strings.Split(parts[0], ";")[0], "data:")
								result = append(result, AnthropicContentBlock{
									Type: "image",
									Source: &AnthropicImageSource{
										Type:      "base64",
										MediaType: mediaType,
										Data:      parts[1],
									},
								})
							}
						} else {
							result = append(result, AnthropicContentBlock{
								Type: "image",
								Source: &AnthropicImageSource{
									Type: "url",
									URL:  url,
								},
							})
						}
					}
				}
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	// 默认返回字符串
	return fmt.Sprintf("%v", content)
}

// convertToolsToAnthropic 转换OpenAI工具格式为Anthropic格式
func (p *AnthropicProvider) convertToolsToAnthropic(tools []Tool) ([]AnthropicTool, error) {
	result := make([]AnthropicTool, 0, len(tools))

	for _, tool := range tools {
		if tool.Type != "function" || tool.Function == nil {
			continue
		}

		anthropicTool := AnthropicTool{
			Name:        tool.Function.Name,
			Description: tool.Function.Description,
			InputSchema: tool.Function.Parameters,
		}

		// 确保input_schema有基本结构
		if anthropicTool.InputSchema == nil {
			anthropicTool.InputSchema = map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			}
		}

		result = append(result, anthropicTool)
	}

	return result, nil
}

// convertToolChoice 转换tool_choice为Anthropic格式
func (p *AnthropicProvider) convertToolChoice(toolChoice interface{}) *AnthropicToolChoice {
	switch v := toolChoice.(type) {
	case string:
		switch v {
		case "none":
			return &AnthropicToolChoice{Type: "none"}
		case "auto":
			return &AnthropicToolChoice{Type: "auto"}
		case "required":
			return &AnthropicToolChoice{Type: "any"}
		}
	case map[string]interface{}:
		if t, ok := v["type"].(string); ok && t == "function" {
			if fn, ok := v["function"].(map[string]interface{}); ok {
				if name, ok := fn["name"].(string); ok {
					return &AnthropicToolChoice{
						Type: "tool",
						Name: name,
					}
				}
			}
		}
	case ToolChoiceFunction:
		if v.Function != nil {
			return &AnthropicToolChoice{
				Type: "tool",
				Name: v.Function.Name,
			}
		}
	}
	return nil
}

// transformFromAnthropicResponse 将Anthropic响应转换为标准格式
func (p *AnthropicProvider) transformFromAnthropicResponse(anthropicResp *AnthropicResponse) (*ChatCompletionResponse, error) {
	response := &ChatCompletionResponse{
		ID:      anthropicResp.ID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   anthropicResp.Model,
		Choices: make([]ChatCompletionChoice, 1),
	}

	var content strings.Builder
	var toolCalls []ToolCall

	for _, contentBlock := range anthropicResp.Content {
		switch contentBlock.Type {
		case "text":
			content.WriteString(contentBlock.Text)
		case "tool_use":
			// 转换工具调用
			argsJSON, _ := json.Marshal(contentBlock.Input)
			toolCalls = append(toolCalls, ToolCall{
				ID:   contentBlock.ID,
				Type: "function",
				Function: &FunctionCall{
					Name:      contentBlock.Name,
					Arguments: string(argsJSON),
				},
			})
		case "thinking":
			// 思考内容 - 可以选择性地包含或忽略
			// 当前实现：忽略（符合OpenAI格式）
		}
	}

	response.Choices[0] = ChatCompletionChoice{
		Index: 0,
		Message: ChatCompletionMessage{
			Role:      "assistant",
			Content:   content.String(),
			ToolCalls: toolCalls,
		},
		FinishReason: p.convertStopReason(anthropicResp.StopReason),
	}

	// 设置使用统计
	response.Usage.PromptTokens = anthropicResp.Usage.InputTokens
	response.Usage.CompletionTokens = anthropicResp.Usage.OutputTokens
	response.Usage.TotalTokens = anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens

	return response, nil
}

// convertStopReason 转换停止原因
func (p *AnthropicProvider) convertStopReason(stopReason string) string {
	switch stopReason {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "stop_sequence":
		return "stop"
	case "tool_use":
		return "tool_calls"
	default:
		return stopReason
	}
}

// extractTextContent 从多模态内容中提取文本内容
func (p *AnthropicProvider) extractTextContent(content interface{}) string {
	switch v := content.(type) {
	case string:
		return v
	case []interface{}:
		var textParts []string
		for _, item := range v {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if itemType, ok := itemMap["type"].(string); ok && itemType == "text" {
					if text, ok := itemMap["text"].(string); ok {
						textParts = append(textParts, text)
					}
				}
			}
		}
		return strings.Join(textParts, " ")
	case []MessageContent:
		var textParts []string
		for _, item := range v {
			if item.Type == "text" {
				textParts = append(textParts, item.Text)
			}
		}
		return strings.Join(textParts, " ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// CreateHTTPRequest 创建HTTP请求
func (p *AnthropicProvider) CreateHTTPRequest(ctx context.Context, endpoint string, body interface{}) (*http.Request, error) {
	var bodyReader io.Reader

	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.Config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	for key, value := range p.Config.Headers {
		if key != "x-api-key" {
			req.Header.Set(key, value)
		}
	}

	return req, nil
}

// ParseHTTPResponse 解析HTTP响应
func (p *AnthropicProvider) ParseHTTPResponse(resp *http.Response) (interface{}, error) {
	var response AnthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &response, nil
}
