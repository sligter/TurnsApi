package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// OpenAIProvider OpenAI格式提供商
type OpenAIProvider struct {
	*BaseProvider
}

// NewOpenAIProvider 创建OpenAI提供商
func NewOpenAIProvider(config *ProviderConfig) *OpenAIProvider {
	return &OpenAIProvider{
		BaseProvider: NewBaseProvider(config),
	}
}

// ChatCompletion 发送聊天完成请求
func (p *OpenAIProvider) ChatCompletion(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	// 验证工具调用相关参数
	if err := p.validateToolCallRequest(req); err != nil {
		return nil, fmt.Errorf("tool call validation failed: %w", err)
	}
	
	// OpenAI格式不需要转换，直接使用
	endpoint := fmt.Sprintf("%s/chat/completions", p.Config.BaseURL)
	
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// 设置头部
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.Config.APIKey)
	
	// 设置自定义头部
	for key, value := range p.Config.Headers {
		if key != "Authorization" { // 避免覆盖Authorization头
			httpReq.Header.Set(key, value)
		}
	}
	
	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, p.handleAPIError(resp.StatusCode, body)
	}
	
	var response ChatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return &response, nil
}

// ChatCompletionStream 发送流式聊天完成请求
func (p *OpenAIProvider) ChatCompletionStream(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 验证工具调用相关参数
	if err := p.validateToolCallRequest(req); err != nil {
		return nil, fmt.Errorf("tool call validation failed: %w", err)
	}
	
	// 确保设置stream为true
	req.Stream = true
	
	endpoint := fmt.Sprintf("%s/chat/completions", p.Config.BaseURL)
	
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// 设置头部
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.Config.APIKey)
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Cache-Control", "no-cache")
	
	// 设置自定义头部
	for key, value := range p.Config.Headers {
		if key != "Authorization" {
			httpReq.Header.Set(key, value)
		}
	}
	
	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, p.handleAPIError(resp.StatusCode, body)
	}
	
	streamChan := make(chan StreamResponse, 10)
	
	go func() {
		defer close(streamChan)
		defer resp.Body.Close()
		
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			
			// 发送原始数据行
			streamChan <- StreamResponse{
				Data: []byte(line + "\n"),
				Done: false,
			}
			
			// 检查是否结束
			if strings.Contains(line, "[DONE]") {
				streamChan <- StreamResponse{
					Done: true,
				}
				return
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
func (p *OpenAIProvider) ChatCompletionStreamNative(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// OpenAI格式本身就是标准格式，直接调用标准流式方法
	return p.ChatCompletionStream(ctx, req)
}

// GetModels 获取可用模型列表
func (p *OpenAIProvider) GetModels(ctx context.Context) (interface{}, error) {
	endpoint := fmt.Sprintf("%s/models", p.Config.BaseURL)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.Config.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	// 添加自定义头
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
		return nil, p.handleAPIError(resp.StatusCode, body)
	}

	var models interface{}
	if err := json.NewDecoder(resp.Body).Decode(&models); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return models, nil
}

// HealthCheck 健康检查
func (p *OpenAIProvider) HealthCheck(ctx context.Context) error {
	// 创建一个简单的健康检查请求，只检查连接性
	req, err := http.NewRequestWithContext(ctx, "GET", p.Config.BaseURL+"/models", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	// 添加认证头
	req.Header.Set("Authorization", "Bearer "+p.Config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	// 添加自定义头
	for key, value := range p.Config.Headers {
		req.Header.Set(key, value)
	}

	// 发送请求
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send health check request: %w", err)
	}
	defer resp.Body.Close()

	// 只要返回状态码是 2xx 就认为健康
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// 如果状态码不是 2xx，读取错误信息
	body, _ := io.ReadAll(resp.Body)
	return p.handleAPIError(resp.StatusCode, body)
}

// TransformRequest OpenAI格式不需要转换
func (p *OpenAIProvider) TransformRequest(req *ChatCompletionRequest) (interface{}, error) {
	return req, nil
}

// TransformResponse OpenAI格式不需要转换
func (p *OpenAIProvider) TransformResponse(resp interface{}) (*ChatCompletionResponse, error) {
	if response, ok := resp.(*ChatCompletionResponse); ok {
		return response, nil
	}
	return nil, fmt.Errorf("invalid response type")
}

// CreateHTTPRequest 创建HTTP请求
func (p *OpenAIProvider) CreateHTTPRequest(ctx context.Context, endpoint string, body interface{}) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+p.Config.APIKey)
	
	for key, value := range p.Config.Headers {
		if key != "Authorization" {
			req.Header.Set(key, value)
		}
	}
	
	return req, nil
}

// ParseHTTPResponse 解析HTTP响应
func (p *OpenAIProvider) ParseHTTPResponse(resp *http.Response) (interface{}, error) {
	var response ChatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &response, nil
}

// validateToolCallRequest 验证工具调用请求参数
func (p *OpenAIProvider) validateToolCallRequest(req *ChatCompletionRequest) error {
	// 验证消息序列中的工具调用逻辑
	if err := p.validateMessageSequence(req.Messages); err != nil {
		return err
	}
	
	// 如果没有工具定义，无需验证工具相关参数
	if len(req.Tools) == 0 {
		return nil
	}
	
	// 验证工具数量限制
	if len(req.Tools) > 12800 {
		return &ToolCallError{
			Type:    "validation_error",
			Code:    "too_many_tools",
			Message: fmt.Sprintf("too many tools provided: %d, maximum allowed is 12800", len(req.Tools)),
		}
	}
	
	// 验证工具定义
	toolNames := make(map[string]bool)
	for i, tool := range req.Tools {
		if tool.Type != "function" {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_tool_type",
				Message: fmt.Sprintf("tool[%d]: unsupported tool type '%s', only 'function' is supported", i, tool.Type),
			}
		}
		
		if tool.Function == nil {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "missing_function_definition",
				Message: fmt.Sprintf("tool[%d]: function definition is required", i),
			}
		}
		
		if tool.Function.Name == "" {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "missing_function_name",
				Message: fmt.Sprintf("tool[%d]: function name is required", i),
			}
		}
		
		// 验证函数名称格式
		if !isValidFunctionName(tool.Function.Name) {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_function_name",
				Message: fmt.Sprintf("tool[%d]: function name '%s' is invalid, must contain only letters, numbers, underscores, and hyphens, and be 1-64 characters long", i, tool.Function.Name),
			}
		}
		
		// 检查函数名称重复
		if toolNames[tool.Function.Name] {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "duplicate_function_name",
				Message: fmt.Sprintf("tool[%d]: duplicate function name '%s'", i, tool.Function.Name),
			}
		}
		toolNames[tool.Function.Name] = true
		
		// 函数描述长度不设限制，允许用户自由定义
		
		// 验证参数schema
		if err := p.validateFunctionParameters(tool.Function, i); err != nil {
			return err
		}
	}
	
	// 验证tool_choice参数
	if req.ToolChoice != nil {
		if err := p.validateToolChoice(req.ToolChoice, toolNames); err != nil {
			return err
		}
	}
	
	// 验证parallel_tool_calls参数
	if req.ParallelToolCalls != nil && len(req.Tools) == 1 {
		// 如果只有一个工具，parallel_tool_calls应该为false或nil
		if *req.ParallelToolCalls {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_parallel_tool_calls",
				Message: "parallel_tool_calls cannot be true when only one tool is provided",
			}
		}
	}
	
	return nil
}

// validateFunctionParameters 验证函数参数schema
func (p *OpenAIProvider) validateFunctionParameters(function *Function, toolIndex int) error {
	if function.Parameters == nil {
		return nil
	}
	
	// 验证parameters是否为有效的JSON Schema
	parametersBytes, err := json.Marshal(function.Parameters)
	if err != nil {
		return &ToolCallError{
			Type:    "validation_error",
			Code:    "invalid_parameters_schema",
			Message: fmt.Sprintf("tool[%d]: function parameters must be valid JSON: %v", toolIndex, err),
		}
	}
	
	// 验证参数schema大小
	if len(parametersBytes) > 100*1024 { // 100KB limit
		return &ToolCallError{
			Type:    "validation_error",
			Code:    "parameters_schema_too_large",
			Message: fmt.Sprintf("tool[%d]: function parameters schema is too large (%d bytes), maximum allowed is 100KB", toolIndex, len(parametersBytes)),
		}
	}
	
	return nil
}

// validateToolChoice 验证tool_choice参数
func (p *OpenAIProvider) validateToolChoice(toolChoice interface{}, availableTools map[string]bool) error {
	switch choice := toolChoice.(type) {
	case string:
		// 验证字符串类型的tool_choice
		validChoices := []string{"none", "auto", "required"}
		valid := false
		for _, validChoice := range validChoices {
			if choice == validChoice {
				valid = true
				break
			}
		}
		if !valid {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_tool_choice",
				Message: fmt.Sprintf("invalid tool_choice string: '%s', must be one of: none, auto, required", choice),
			}
		}
	case map[string]interface{}:
		// 验证对象类型的tool_choice
		if toolType, ok := choice["type"].(string); !ok || toolType != "function" {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_tool_choice_type",
				Message: "tool_choice object must have type 'function'",
			}
		}
		
		if function, ok := choice["function"].(map[string]interface{}); ok {
			if name, ok := function["name"].(string); !ok || name == "" {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "missing_tool_choice_function_name",
					Message: "tool_choice function must have a valid name",
				}
			} else {
				// 验证指定的函数是否存在
				if !availableTools[name] {
					return &ToolCallError{
						Type:    "validation_error",
						Code:    "unknown_tool_choice_function",
						Message: fmt.Sprintf("tool_choice function '%s' is not defined in tools", name),
					}
				}
			}
		} else {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "missing_tool_choice_function",
				Message: "tool_choice object must have a function field",
			}
		}
	case ToolChoiceFunction:
		// 验证结构体类型的tool_choice
		if choice.Type != "function" {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_tool_choice_type",
				Message: "tool_choice type must be 'function'",
			}
		}
		if choice.Function == nil || choice.Function.Name == "" {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "missing_tool_choice_function_name",
				Message: "tool_choice function must have a valid name",
			}
		} else {
			// 验证指定的函数是否存在
			if !availableTools[choice.Function.Name] {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "unknown_tool_choice_function",
					Message: fmt.Sprintf("tool_choice function '%s' is not defined in tools", choice.Function.Name),
				}
			}
		}
	default:
		return &ToolCallError{
			Type:    "validation_error",
			Code:    "invalid_tool_choice_type",
			Message: fmt.Sprintf("invalid tool_choice type: %T", choice),
		}
	}
	
	return nil
}

// isValidFunctionName 验证函数名称格式
func isValidFunctionName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	
	return true
}

// handleAPIError 处理API错误响应
func (p *OpenAIProvider) handleAPIError(statusCode int, body []byte) error {
	// 尝试解析OpenAI错误格式
	var apiError struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	
	if err := json.Unmarshal(body, &apiError); err == nil && apiError.Error.Message != "" {
		// 根据错误类型返回相应的ToolCallError
		switch apiError.Error.Type {
		case "invalid_request_error":
			// 检查是否是工具调用相关的错误
			if strings.Contains(apiError.Error.Message, "tool") ||
			   strings.Contains(apiError.Error.Message, "function") {
				return &ToolCallError{
					Type:    "tool_call_error",
					Code:    apiError.Error.Code,
					Message: apiError.Error.Message,
				}
			}
			return &ToolCallError{
				Type:    "validation_error",
				Code:    apiError.Error.Code,
				Message: apiError.Error.Message,
			}
		case "rate_limit_exceeded":
			return &ToolCallError{
				Type:    "rate_limit_error",
				Code:    "rate_limit_exceeded",
				Message: apiError.Error.Message,
			}
		case "insufficient_quota":
			return &ToolCallError{
				Type:    "quota_error",
				Code:    "insufficient_quota",
				Message: apiError.Error.Message,
			}
		case "server_error":
			return &ToolCallError{
				Type:    "server_error",
				Code:    "internal_server_error",
				Message: apiError.Error.Message,
			}
		default:
			return &ToolCallError{
				Type:    "api_error",
				Code:    apiError.Error.Code,
				Message: apiError.Error.Message,
			}
		}
	}
	
	// 如果无法解析错误格式，根据状态码返回通用错误
	switch statusCode {
	case 400:
		return &ToolCallError{
			Type:    "validation_error",
			Code:    "bad_request",
			Message: fmt.Sprintf("Bad request: %s", string(body)),
		}
	case 401:
		return &ToolCallError{
			Type:    "authentication_error",
			Code:    "unauthorized",
			Message: "Invalid API key or authentication failed",
		}
	case 403:
		return &ToolCallError{
			Type:    "permission_error",
			Code:    "forbidden",
			Message: "Access forbidden - insufficient permissions",
		}
	case 404:
		return &ToolCallError{
			Type:    "not_found_error",
			Code:    "not_found",
			Message: "The requested resource was not found",
		}
	case 429:
		return &ToolCallError{
			Type:    "rate_limit_error",
			Code:    "rate_limit_exceeded",
			Message: "Rate limit exceeded - please try again later",
		}
	case 500, 502, 503, 504:
		return &ToolCallError{
			Type:    "server_error",
			Code:    "internal_server_error",
			Message: fmt.Sprintf("Server error (status %d) - please try again later", statusCode),
		}
	default:
		return &ToolCallError{
			Type:    "api_error",
			Code:    "unknown_error",
			Message: fmt.Sprintf("API request failed with status %d: %s", statusCode, string(body)),
		}
	}
}

// validateMessageSequence 验证消息序列中的工具调用逻辑
func (p *OpenAIProvider) validateMessageSequence(messages []ChatMessage) error {
	for i, msg := range messages {
		switch msg.Role {
		case "tool":
			// tool消息必须跟在带有tool_calls的assistant消息后面（可能中间有其他tool消息）
			if i == 0 {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "invalid_message_sequence",
					Message: "messages with role \"tool\" must be a response to a preceding message with \"tool_calls\"",
				}
			}
			
			// 向前查找最近的assistant消息
			var assistantMsg *ChatMessage
			for j := i - 1; j >= 0; j-- {
				if messages[j].Role == "assistant" {
					assistantMsg = &messages[j]
					break
				} else if messages[j].Role != "tool" {
					// 如果遇到非tool、非assistant的消息，停止查找
					break
				}
			}
			
			// 检查是否找到了assistant消息且包含tool_calls
			if assistantMsg == nil || len(assistantMsg.ToolCalls) == 0 {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "invalid_message_sequence",
					Message: "messages with role \"tool\" must be a response to a preceding message with \"tool_calls\"",
				}
			}
			
			// 验证tool消息必须有tool_call_id
			if msg.ToolCallID == "" {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "missing_tool_call_id",
					Message: "messages with role \"tool\" must have a \"tool_call_id\"",
				}
			}
			
			// 验证tool_call_id是否对应前面的tool_calls
			validToolCallID := false
			for _, toolCall := range assistantMsg.ToolCalls {
				if toolCall.ID == msg.ToolCallID {
					validToolCallID = true
					break
				}
			}
			if !validToolCallID {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "invalid_tool_call_id",
					Message: fmt.Sprintf("tool_call_id \"%s\" does not match any tool_calls in the preceding assistant message", msg.ToolCallID),
				}
			}
			
		case "assistant":
			// 如果assistant消息包含tool_calls，验证其格式
			if len(msg.ToolCalls) > 0 {
				for j, toolCall := range msg.ToolCalls {
					if toolCall.ID == "" {
						return &ToolCallError{
							Type:    "validation_error",
							Code:    "missing_tool_call_id",
							Message: fmt.Sprintf("tool_calls[%d] must have an \"id\"", j),
						}
					}
					
					if toolCall.Type != "function" {
						return &ToolCallError{
							Type:    "validation_error",
							Code:    "invalid_tool_call_type",
							Message: fmt.Sprintf("tool_calls[%d] type must be \"function\"", j),
						}
					}
					
					if toolCall.Function == nil {
						return &ToolCallError{
							Type:    "validation_error",
							Code:    "missing_function_call",
							Message: fmt.Sprintf("tool_calls[%d] must have a \"function\"", j),
						}
					}
					
					if toolCall.Function.Name == "" {
						return &ToolCallError{
							Type:    "validation_error",
							Code:    "missing_function_name",
							Message: fmt.Sprintf("tool_calls[%d].function must have a \"name\"", j),
						}
					}
				}
			}
		}
	}
	
	return nil
}
