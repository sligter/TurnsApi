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
	Temperature   *float64                 `json:"temperature,omitempty"`
	TopP          *float64                 `json:"top_p,omitempty"`
	StopSequences []string                 `json:"stop_sequences,omitempty"`
	Stream        bool                     `json:"stream,omitempty"`
}

// AnthropicMessage Anthropic消息结构
type AnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AnthropicResponse Anthropic API响应结构
type AnthropicResponse struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Role         string                 `json:"role"`
	Content      []AnthropicContent     `json:"content"`
	Model        string                 `json:"model"`
	StopReason   string                 `json:"stop_reason"`
	StopSequence string                 `json:"stop_sequence"`
	Usage        AnthropicUsage         `json:"usage"`
}

// AnthropicContent Anthropic内容结构
type AnthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// AnthropicUsage Anthropic使用统计
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// NewAnthropicProvider 创建Anthropic提供商
func NewAnthropicProvider(config *ProviderConfig) *AnthropicProvider {
	return &AnthropicProvider{
		BaseProvider: NewBaseProvider(config),
	}
}

// ChatCompletion 发送聊天完成请求
func (p *AnthropicProvider) ChatCompletion(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	// 转换请求格式
	anthropicReq, err := p.transformToAnthropicRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to transform request: %w", err)
	}

	// 构建端点URL - 检查BaseURL是否已经包含路径
	baseURL := strings.TrimRight(p.Config.BaseURL, "/")
	var endpoint string
	if strings.HasSuffix(baseURL, "/v1") {
		// 如果BaseURL以/v1结尾，直接拼接messages
		endpoint = baseURL + "/messages"
	} else {
		// 否则拼接完整的/v1/messages路径
		endpoint = baseURL + "/v1/messages"
	}

	log.Printf("🔧 Anthropic ChatCompletion - BaseURL: %s, Endpoint: %s, APIKey: %s****", p.Config.BaseURL, endpoint, p.Config.APIKey[:4])

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
	httpReq.Header.Set("anthropic-version", "2023-06-01") // 使用默认版本
	
	// 设置自定义头部
	for key, value := range p.Config.Headers {
		if key != "x-api-key" { // 避免覆盖API key头
			httpReq.Header.Set(key, value)
		}
	}
	
	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应体以供日志使用
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// 记录详细错误信息
		return nil, fmt.Errorf("API request failed with status %d: %s. Headers: %v", resp.StatusCode, string(bodyBytes), httpReq.Header)
	}
	
	var anthropicResp AnthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&anthropicResp); err != nil {
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

	// 构建端点URL - 检查BaseURL是否已经包含路径
	baseURL := strings.TrimRight(p.Config.BaseURL, "/")
	var endpoint string
	if strings.HasSuffix(baseURL, "/v1") {
		// 如果BaseURL以/v1结尾，直接拼接messages
		endpoint = baseURL + "/messages"
	} else {
		// 否则拼接完整的/v1/messages路径
		endpoint = baseURL + "/v1/messages"
	}
	
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
	httpReq.Header.Set("anthropic-version", "2023-06-01") // 使用默认版本
	
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

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// 记录详细错误信息
		resp.Body.Close()
		return nil, fmt.Errorf("API request failed with status %d: %s. Headers: %v", resp.StatusCode, string(bodyBytes), httpReq.Header)
	}
	
	streamChan := make(chan StreamResponse, 10)
	
	go func() {
		defer close(streamChan)
		defer resp.Body.Close()
		
		scanner := bufio.NewScanner(resp.Body)
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
					// 转换为OpenAI格式的流式数据
					if eventType, ok := anthropicEvent["type"].(string); ok {
						switch eventType {
						case "content_block_delta":
							if delta, ok := anthropicEvent["delta"].(map[string]interface{}); ok {
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
							}
						case "message_stop":
							// 发送结束标记
							openaiData := map[string]interface{}{
								"id":      fmt.Sprintf("chatcmpl-%d", time.Now().Unix()),
								"object":  "chat.completion.chunk",
								"created": time.Now().Unix(),
								"model":   req.Model,
								"choices": []map[string]interface{}{
									{
										"index":         0,
										"delta":         map[string]interface{}{},
										"finish_reason": "stop",
									},
								},
							}
							
							if jsonData, err := json.Marshal(openaiData); err == nil {
								streamChan <- StreamResponse{
									Data: []byte("data: " + string(jsonData) + "\n\n"),
									Done: false,
								}
							}
							
							streamChan <- StreamResponse{
								Data: []byte("data: [DONE]\n\n"),
								Done: true,
							}
							return
						}
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

	// 构建端点URL - 检查BaseURL是否已经包含路径
	baseURL := strings.TrimRight(p.Config.BaseURL, "/")
	var endpoint string
	if strings.HasSuffix(baseURL, "/v1") {
		// 如果BaseURL以/v1结尾，直接拼接messages
		endpoint = baseURL + "/messages"
	} else {
		// 否则拼接完整的/v1/messages路径
		endpoint = baseURL + "/v1/messages"
	}
	
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

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// 记录详细错误信息
		resp.Body.Close()
		return nil, fmt.Errorf("API request failed with status %d: %s. Headers: %v", resp.StatusCode, string(bodyBytes), httpReq.Header)
	}
	
	streamChan := make(chan StreamResponse, 10)
	
	go func() {
		defer close(streamChan)
		defer resp.Body.Close()
		
		scanner := bufio.NewScanner(resp.Body)
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
	// 使用Anthropic官方的模型列表API
	baseURL := strings.TrimRight(p.Config.BaseURL, "/")
	var endpoint string
	if strings.HasSuffix(baseURL, "/v1") {
		// 如果BaseURL以/v1结尾，直接拼接models
		endpoint = baseURL + "/models"
	} else {
		// 否则拼接完整的/v1/models路径
		endpoint = baseURL + "/v1/models"
	}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 设置必需的头部
	httpReq.Header.Set("x-api-key", p.Config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("Content-Type", "application/json")

	// 设置自定义头部
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

	// 解析Anthropic API响应
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
		// 解析创建时间
		var created int64
		if parsedTime, err := time.Parse(time.RFC3339, model.CreatedAt); err == nil {
			created = parsedTime.Unix()
		} else {
			created = time.Now().Unix()
		}

		data = append(data, map[string]interface{}{
			"id":      model.ID,
			"object":  "model",
			"created": created,
			"owned_by": "anthropic",
		})
	}
	models["data"] = data

	return models, nil
}

// HealthCheck 健康检查
func (p *AnthropicProvider) HealthCheck(ctx context.Context) error {
	// 使用模型列表API进行健康检查，这是一个轻量级的操作
	baseURL := strings.TrimRight(p.Config.BaseURL, "/")
	var endpoint string
	if strings.HasSuffix(baseURL, "/v1") {
		// 如果BaseURL以/v1结尾，直接拼接models
		endpoint = baseURL + "/models"
	} else {
		// 否则拼接完整的/v1/models路径
		endpoint = baseURL + "/v1/models"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	// 添加认证头
	req.Header.Set("x-api-key", p.Config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
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

	// 其他状态码认为不健康
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

	for _, msg := range req.Messages {
		// 跳过system消息，Anthropic在messages中不支持system角色
		if msg.Role == "system" {
			continue
		}

		// 提取文本内容
		content := p.extractTextContent(msg.Content)

		message := AnthropicMessage{
			Role:    msg.Role,
			Content: content,
		}
		messages = append(messages, message)
	}

	// Anthropic要求必须有max_tokens
	maxTokens := 4096 // 默认值
	if req.MaxTokens != nil {
		maxTokens = *req.MaxTokens
	}

	anthropicReq := &AnthropicRequest{
		Model:     req.Model,
		MaxTokens: maxTokens,
		Messages:  messages,
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

	return anthropicReq, nil
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

	// 合并所有内容块的文本
	var content strings.Builder
	for _, contentBlock := range anthropicResp.Content {
		if contentBlock.Type == "text" {
			content.WriteString(contentBlock.Text)
		}
	}

	response.Choices[0] = ChatCompletionChoice{
		Index: 0,
		Message: ChatCompletionMessage{
			Role:    "assistant",
			Content: content.String(),
		},
		FinishReason: anthropicResp.StopReason,
	}

	// 设置使用统计
	response.Usage.PromptTokens = anthropicResp.Usage.InputTokens
	response.Usage.CompletionTokens = anthropicResp.Usage.OutputTokens
	response.Usage.TotalTokens = anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens

	return response, nil
}

// extractTextContent 从多模态内容中提取文本内容
func (p *AnthropicProvider) extractTextContent(content interface{}) string {
	switch v := content.(type) {
	case string:
		return v
	case []interface{}:
		// 多模态内容，提取所有文本部分
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
		// 结构化多模态内容
		var textParts []string
		for _, item := range v {
			if item.Type == "text" {
				textParts = append(textParts, item.Text)
			}
		}
		return strings.Join(textParts, " ")
	default:
		// 尝试转换为字符串
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
	req.Header.Set("anthropic-version", "2023-06-01") // 使用默认版本

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
