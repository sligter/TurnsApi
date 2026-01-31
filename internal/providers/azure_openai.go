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

// AzureOpenAIProvider Azure OpenAI 提供商
type AzureOpenAIProvider struct {
	*BaseProvider
	APIVersion string
}

// NewAzureOpenAIProvider 创建 Azure OpenAI 提供商
func NewAzureOpenAIProvider(config *ProviderConfig) *AzureOpenAIProvider {
	// 从 Headers 中获取 api-version，如果没有则使用默认值
	apiVersion := "2024-02-15-preview"
	if version, ok := config.Headers["api-version"]; ok && version != "" {
		apiVersion = version
	}

	return &AzureOpenAIProvider{
		BaseProvider: NewBaseProvider(config),
		APIVersion:   apiVersion,
	}
}

// buildAzureEndpoint 构建 Azure OpenAI 端点 URL
// Azure OpenAI URL 格式:
// https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version={version}
func (p *AzureOpenAIProvider) buildAzureEndpoint(operation string) string {
	baseURL := strings.TrimSuffix(p.Config.BaseURL, "/")
	return fmt.Sprintf("%s/%s?api-version=%s", baseURL, operation, p.APIVersion)
}

// ChatCompletion 发送聊天完成请求
func (p *AzureOpenAIProvider) ChatCompletion(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	endpoint := p.buildAzureEndpoint("chat/completions")

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 设置 Azure OpenAI 特定的头部
	p.setAzureHeaders(httpReq)

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
func (p *AzureOpenAIProvider) ChatCompletionStream(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 确保设置 stream 为 true
	req.Stream = true

	endpoint := p.buildAzureEndpoint("chat/completions")

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 设置 Azure OpenAI 特定的头部
	p.setAzureHeaders(httpReq)
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Cache-Control", "no-cache")

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
func (p *AzureOpenAIProvider) ChatCompletionStreamNative(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// Azure OpenAI 格式与标准 OpenAI 格式相同，直接调用标准流式方法
	return p.ChatCompletionStream(ctx, req)
}

// GetModels 获取可用模型列表
func (p *AzureOpenAIProvider) GetModels(ctx context.Context) (interface{}, error) {
	// Azure OpenAI 模型列表端点不同于标准 OpenAI
	// 对于 deployment 级别的 URL，无法直接获取模型列表
	// 返回预定义的 Azure OpenAI 模型列表
	predefinedModels := map[string]interface{}{
		"object": "list",
		"data": []map[string]interface{}{
			{
				"id":       "gpt-35-turbo",
				"object":   "model",
				"owned_by": "azure",
			},
			{
				"id":       "gpt-35-turbo-16k",
				"object":   "model",
				"owned_by": "azure",
			},
			{
				"id":       "gpt-4",
				"object":   "model",
				"owned_by": "azure",
			},
			{
				"id":       "gpt-4-32k",
				"object":   "model",
				"owned_by": "azure",
			},
			{
				"id":       "gpt-4-turbo",
				"object":   "model",
				"owned_by": "azure",
			},
			{
				"id":       "gpt-4o",
				"object":   "model",
				"owned_by": "azure",
			},
		},
	}

	return predefinedModels, nil
}

// HealthCheck 健康检查
func (p *AzureOpenAIProvider) HealthCheck(ctx context.Context) error {
	// 发送一个简单的请求来验证连接
	endpoint := p.buildAzureEndpoint("chat/completions")

	// 创建一个最小的请求体
	reqBody := map[string]interface{}{
		"messages": []map[string]string{
			{"role": "user", "content": "hi"},
		},
		"max_tokens": 1,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to create health check request body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	p.setAzureHeaders(httpReq)

	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	// 2xx 状态码表示健康
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// 读取错误信息
	body, _ := io.ReadAll(resp.Body)
	return p.handleAPIError(resp.StatusCode, body)
}

// TransformRequest Azure OpenAI 格式与标准 OpenAI 格式相同
func (p *AzureOpenAIProvider) TransformRequest(req *ChatCompletionRequest) (interface{}, error) {
	return req, nil
}

// TransformResponse Azure OpenAI 格式与标准 OpenAI 格式相同
func (p *AzureOpenAIProvider) TransformResponse(resp interface{}) (*ChatCompletionResponse, error) {
	if response, ok := resp.(*ChatCompletionResponse); ok {
		return response, nil
	}
	return nil, fmt.Errorf("invalid response type")
}

// CreateHTTPRequest 创建 HTTP 请求
func (p *AzureOpenAIProvider) CreateHTTPRequest(ctx context.Context, endpoint string, body interface{}) (*http.Request, error) {
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

	p.setAzureHeaders(req)

	return req, nil
}

// ParseHTTPResponse 解析 HTTP 响应
func (p *AzureOpenAIProvider) ParseHTTPResponse(resp *http.Response) (interface{}, error) {
	var response ChatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &response, nil
}

// setAzureHeaders 设置 Azure OpenAI 特定的请求头
func (p *AzureOpenAIProvider) setAzureHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")

	// Azure OpenAI 使用 api-key 头部进行认证，而不是 Authorization: Bearer
	req.Header.Set("api-key", p.Config.APIKey)

	// 设置自定义头部，但跳过 api-key 和 api-version（已处理）
	for key, value := range p.Config.Headers {
		lowerKey := strings.ToLower(key)
		if lowerKey != "api-key" && lowerKey != "api-version" && lowerKey != "authorization" {
			req.Header.Set(key, value)
		}
	}
}

// handleAPIError 处理 API 错误响应
func (p *AzureOpenAIProvider) handleAPIError(statusCode int, body []byte) error {
	// 尝试解析 Azure OpenAI 错误格式
	var apiError struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &apiError); err == nil && apiError.Error.Message != "" {
		return &ToolCallError{
			Type:    "api_error",
			Code:    apiError.Error.Code,
			Message: apiError.Error.Message,
		}
	}

	// 根据状态码返回通用错误
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
			Message: "The requested deployment or resource was not found",
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
