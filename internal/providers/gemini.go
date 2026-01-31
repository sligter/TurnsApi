package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"turnsapi/internal/netutil"

	"google.golang.org/genai"
)

// GeminiQuotaManager 配额管理器
type GeminiQuotaManager struct {
	mu              sync.RWMutex
	lastQuotaError  time.Time
	quotaErrorCount int
	backoffDuration time.Duration
}

// NewGeminiQuotaManager 创建配额管理器
func NewGeminiQuotaManager() *GeminiQuotaManager {
	return &GeminiQuotaManager{
		backoffDuration: time.Minute, // 默认1分钟退避
	}
}

// ShouldSkipRequest 检查是否应该跳过请求（由于配额限制）
func (qm *GeminiQuotaManager) ShouldSkipRequest() bool {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	if qm.quotaErrorCount == 0 {
		return false
	}

	// 如果最近有配额错误，且在退避期内，跳过请求
	return time.Since(qm.lastQuotaError) < qm.backoffDuration
}

// RecordQuotaError 记录配额错误
func (qm *GeminiQuotaManager) RecordQuotaError() {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	qm.lastQuotaError = time.Now()
	qm.quotaErrorCount++

	// 指数退避，最大30分钟
	qm.backoffDuration = time.Duration(qm.quotaErrorCount) * time.Minute
	if qm.backoffDuration > 30*time.Minute {
		qm.backoffDuration = 30 * time.Minute
	}
}

// RecordSuccess 记录成功请求
func (qm *GeminiQuotaManager) RecordSuccess() {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	// 成功后重置错误计数
	qm.quotaErrorCount = 0
	qm.backoffDuration = time.Minute
}

// GeminiProvider Google Gemini提供商，使用官方Google AI Go SDK
type GeminiProvider struct {
	*BaseProvider
	client       *genai.Client
	quotaManager *GeminiQuotaManager
}

// NewGeminiProvider 创建Gemini提供商
func NewGeminiProvider(config *ProviderConfig) *GeminiProvider {
	// 创建官方Google AI Go SDK客户端
	ctx := context.Background()

	// 根据文档，Google AI Go SDK 的正确配置方式
	clientConfig := &genai.ClientConfig{
		APIKey: config.APIKey,
	}

	// 设置 HTTP 选项，包括 API 版本
	if config.BaseURL != "" {
		// 对于 Gemini API，通常使用 v1beta 版本
		clientConfig.HTTPOptions = genai.HTTPOptions{
			APIVersion: "v1beta",
		}

		// 如果 BaseURL 不是默认的，可能需要特殊处理
		// 但是 Google AI Go SDK 通常会自动处理 BaseURL
		// 这里我们主要依赖 APIKey 和 APIVersion
	} else {
		// 使用默认配置
		clientConfig.HTTPOptions = genai.HTTPOptions{
			APIVersion: "v1beta",
		}
	}

	client, err := genai.NewClient(ctx, clientConfig)
	if err != nil {
		// 如果创建失败，返回一个带有错误的提供商
		// 错误将在实际调用时返回
		return &GeminiProvider{
			BaseProvider: NewBaseProvider(config),
			client:       nil,
			quotaManager: NewGeminiQuotaManager(),
		}
	}
	return &GeminiProvider{
		BaseProvider: NewBaseProvider(config),
		client:       client,
		quotaManager: NewGeminiQuotaManager(),
	}
}

// ChatCompletion 发送聊天完成请求
func (p *GeminiProvider) ChatCompletion(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	// 验证客户端
	if p.client == nil {
		return nil, fmt.Errorf("Gemini client not initialized, check API key")
	}

	// 检查配额限制
	if p.quotaManager.ShouldSkipRequest() {
		return nil, fmt.Errorf("Gemini API quota exceeded, skipping request (will retry after backoff period)")
	}

	// 转换消息格式为官方SDK格式
	contents, err := p.convertToGenaiContents(req.Messages)
	if err != nil {
		return nil, fmt.Errorf("failed to convert messages: %w", err)
	}

	// 创建生成配置
	genConfig := &genai.GenerateContentConfig{}

	// 设置温度，默认为1.0以获得更有创意的回答
	if req.Temperature != nil {
		temperature := float32(*req.Temperature)
		genConfig.Temperature = &temperature
	} else {
		temperature := float32(1.0)
		genConfig.Temperature = &temperature
	}

	// 设置最大token数
	if req.MaxTokens != nil {
		maxTokens := int32(*req.MaxTokens)
		genConfig.MaxOutputTokens = maxTokens
	}

	// 设置TopP
	if req.TopP != nil {
		topP := float32(*req.TopP)
		genConfig.TopP = &topP
	}

	// 设置停止序列
	if len(req.Stop) > 0 {
		genConfig.StopSequences = req.Stop
	}

	// 转换工具定义为Gemini格式
	if len(req.Tools) > 0 {
		tools, err := p.convertToolsToGeminiFormat(req.Tools)
		if err != nil {
			return nil, fmt.Errorf("failed to convert tools: %w", err)
		}
		genConfig.Tools = tools
	}

	// 启用思考模式 - 对于Gemini 2.5系列模型启用思考功能
	// 但在转换为OpenAI格式时不包含思考内容
	genConfig.ThinkingConfig = &genai.ThinkingConfig{
		IncludeThoughts: false, // 转换为OpenAI格式时不包含思考内容
		ThinkingBudget:  nil,   // 使用默认的动态思考预算
	}

	// 调用官方SDK
	result, err := p.client.Models.GenerateContent(ctx, req.Model, contents, genConfig)

	if err != nil {
		// 检查是否是配额错误
		if p.isQuotaExceededError(err) {
			p.quotaManager.RecordQuotaError()
		}
		return nil, p.handleGeminiError(err)
	}

	// 记录成功请求
	p.quotaManager.RecordSuccess()

	// 转换为OpenAI格式的响应
	return p.convertGenaiToOpenAIResponse(result, req.Model)
}

// ChatCompletionStream 发送流式聊天完成请求
func (p *GeminiProvider) ChatCompletionStream(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 验证客户端
	if p.client == nil {
		return nil, fmt.Errorf("Gemini client not initialized, check API key")
	}

	// 检查配额限制
	if p.quotaManager.ShouldSkipRequest() {
		return nil, fmt.Errorf("Gemini API quota exceeded, skipping request (will retry after backoff period)")
	}

	// 转换消息格式为官方SDK格式
	contents, err := p.convertToGenaiContents(req.Messages)
	if err != nil {
		return nil, fmt.Errorf("failed to convert messages: %w", err)
	}

	// 创建生成配置
	genConfig := &genai.GenerateContentConfig{}

	// 设置温度，默认为1.0以获得更有创意的回答
	if req.Temperature != nil {
		temperature := float32(*req.Temperature)
		genConfig.Temperature = &temperature
	} else {
		temperature := float32(1.0)
		genConfig.Temperature = &temperature
	}

	// 设置最大token数
	if req.MaxTokens != nil {
		maxTokens := int32(*req.MaxTokens)
		genConfig.MaxOutputTokens = maxTokens
	}

	// 设置TopP
	if req.TopP != nil {
		topP := float32(*req.TopP)
		genConfig.TopP = &topP
	}

	// 设置停止序列
	if len(req.Stop) > 0 {
		genConfig.StopSequences = req.Stop
	}

	// 转换工具定义为Gemini格式
	if len(req.Tools) > 0 {
		tools, err := p.convertToolsToGeminiFormat(req.Tools)
		if err != nil {
			return nil, fmt.Errorf("failed to convert tools: %w", err)
		}
		genConfig.Tools = tools
	}

	// 启用思考模式 - 对于Gemini 2.5系列模型启用思考功能
	// 但在转换为OpenAI格式时不包含思考内容
	genConfig.ThinkingConfig = &genai.ThinkingConfig{
		IncludeThoughts: false, // 转换为OpenAI格式时不包含思考内容
		ThinkingBudget:  nil,   // 使用默认的动态思考预算
	}

	streamChan := make(chan StreamResponse, 10)

	go func() {
		defer close(streamChan)

		// 生成响应ID
		responseID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
		created := time.Now().Unix()

		// 使用官方SDK的真正流式功能
		stream := p.client.Models.GenerateContentStream(ctx, req.Model, contents, genConfig)

		// 处理流式响应 - 使用Go 1.23的迭代器语法
		for chunk, err := range stream {
			if err != nil {
				// 检查是否是配额错误
				if p.isQuotaExceededError(err) {
					p.quotaManager.RecordQuotaError()
				}
				streamChan <- StreamResponse{
					Error: p.handleGeminiError(err),
					Done:  true,
				}
				return
			}

			if chunk == nil {
				continue
			}

			// 处理工具调用和文本内容
			if len(chunk.Candidates) > 0 && len(chunk.Candidates[0].Content.Parts) > 0 {
				for _, part := range chunk.Candidates[0].Content.Parts {
					// 处理文本内容
					if part.Text != "" && !part.Thought {
						// 转义并创建OpenAI格式的流式数据
						escapedContent := escapeJSONString(part.Text)
						streamData := fmt.Sprintf("data: {\"id\":\"%s\",\"object\":\"chat.completion.chunk\",\"created\":%d,\"model\":\"%s\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"%s\"},\"finish_reason\":null}]}\n\n",
							responseID, created, req.Model, escapedContent)

						select {
						case streamChan <- StreamResponse{
							Data: []byte(streamData),
							Done: false,
						}:
						case <-ctx.Done():
							return
						}
					}

					// 处理工具调用
					if part.FunctionCall != nil {
						toolCallData := p.convertGeminiFunctionCallToOpenAI(part.FunctionCall, responseID, created, req.Model)
						select {
						case streamChan <- StreamResponse{
							Data: []byte(toolCallData),
							Done: false,
						}:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}

		// 记录成功请求
		p.quotaManager.RecordSuccess()

		// 发送结束标记
		endData := fmt.Sprintf("data: {\"id\":\"%s\",\"object\":\"chat.completion.chunk\",\"created\":%d,\"model\":\"%s\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
			responseID, created, req.Model)
		streamChan <- StreamResponse{
			Data: []byte(endData),
			Done: false,
		}

		streamChan <- StreamResponse{
			Data: []byte("data: [DONE]\n\n"),
			Done: true,
		}
	}()

	return streamChan, nil
}

// ChatCompletionStreamNative 发送原生格式流式聊天完成请求
func (p *GeminiProvider) ChatCompletionStreamNative(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 验证客户端
	if p.client == nil {
		return nil, fmt.Errorf("Gemini client not initialized, check API key")
	}

	// 检查配额限制
	if p.quotaManager.ShouldSkipRequest() {
		return nil, fmt.Errorf("Gemini API quota exceeded, skipping request (will retry after backoff period)")
	}

	// 转换消息格式为官方SDK格式
	contents, err := p.convertToGenaiContents(req.Messages)
	if err != nil {
		return nil, fmt.Errorf("failed to convert messages: %w", err)
	}

	// 创建生成配置
	genConfig := &genai.GenerateContentConfig{}

	// 设置温度，默认为1.0以获得更有创意的回答
	if req.Temperature != nil {
		temperature := float32(*req.Temperature)
		genConfig.Temperature = &temperature
	} else {
		temperature := float32(1.0)
		genConfig.Temperature = &temperature
	}

	// 设置最大token数
	if req.MaxTokens != nil {
		maxTokens := int32(*req.MaxTokens)
		genConfig.MaxOutputTokens = maxTokens
	}

	// 设置TopP
	if req.TopP != nil {
		topP := float32(*req.TopP)
		genConfig.TopP = &topP
	}

	// 设置停止序列
	if len(req.Stop) > 0 {
		genConfig.StopSequences = req.Stop
	}

	// 启用思考模式 - 对于Gemini 2.5系列模型启用思考功能
	// 原生格式保留思考内容
	genConfig.ThinkingConfig = &genai.ThinkingConfig{
		IncludeThoughts: true, // 原生格式包含思考内容
		ThinkingBudget:  nil,  // 使用默认的动态思考预算
	}

	streamChan := make(chan StreamResponse, 10)

	go func() {
		defer close(streamChan)

		// 使用官方SDK的真正流式功能
		stream := p.client.Models.GenerateContentStream(ctx, req.Model, contents, genConfig)

		// 处理流式响应 - 使用Go 1.23的迭代器语法，返回Gemini原生格式
		for chunk, err := range stream {
			if err != nil {
				// 检查是否是配额错误
				if p.isQuotaExceededError(err) {
					p.quotaManager.RecordQuotaError()
				}
				streamChan <- StreamResponse{
					Error: p.handleGeminiError(err),
					Done:  true,
				}
				return
			}

			if chunk == nil {
				continue
			}

			// 将Gemini原生响应转换为SSE格式
			if chunkData, err := p.convertGeminiChunkToSSE(chunk); err == nil {
				select {
				case streamChan <- StreamResponse{
					Data: chunkData,
					Done: false,
				}:
				case <-ctx.Done():
					return
				}
			}
		}

		// 记录成功请求
		p.quotaManager.RecordSuccess()

		// Gemini原生流式响应不需要[DONE]标记，直接结束
		streamChan <- StreamResponse{
			Done: true,
		}
	}()

	return streamChan, nil
}

// GetModels 获取可用模型列表
func (p *GeminiProvider) GetModels(ctx context.Context) (interface{}, error) {
	// 如果客户端未初始化，返回默认模型列表
	if p.client == nil {
		return p.getDefaultModels(), nil
	}

	// 尝试从Google API获取模型列表
	models, err := p.fetchModelsFromAPI(ctx)
	if err != nil {
		// 如果API调用失败，返回默认模型列表
		return p.getDefaultModels(), nil
	}

	return map[string]interface{}{
		"object": "list",
		"data":   models,
	}, nil
}

// getDefaultModels 获取默认模型列表
func (p *GeminiProvider) getDefaultModels() map[string]interface{} {
	models := []map[string]interface{}{
		{
			"id":             "gemini-2.5-flash",
			"object":         "model",
			"created":        time.Now().Unix(),
			"owned_by":       "google",
			"display_name":   "Gemini 2.5 Flash",
			"capabilities":   []string{"chat", "vision", "function_calling"},
			"context_window": 1000000,
		},
		{
			"id":             "gemini-2.5-pro",
			"object":         "model",
			"created":        time.Now().Unix(),
			"owned_by":       "google",
			"display_name":   "Gemini 2.5 Pro",
			"capabilities":   []string{"chat", "vision", "function_calling"},
			"context_window": 2000000,
		},
		{
			"id":             "gemini-2.0-flash-exp",
			"object":         "model",
			"created":        time.Now().Unix(),
			"owned_by":       "google",
			"display_name":   "Gemini 2.0 Flash (Experimental)",
			"capabilities":   []string{"chat", "vision", "function_calling"},
			"context_window": 1000000,
		},
		{
			"id":             "gemini-pro",
			"object":         "model",
			"created":        time.Now().Unix(),
			"owned_by":       "google",
			"display_name":   "Gemini Pro",
			"capabilities":   []string{"chat"},
			"context_window": 32000,
		},
		{
			"id":             "gemini-pro-vision",
			"object":         "model",
			"created":        time.Now().Unix(),
			"owned_by":       "google",
			"display_name":   "Gemini Pro Vision",
			"capabilities":   []string{"chat", "vision"},
			"context_window": 16000,
		},
	}

	return map[string]interface{}{
		"object": "list",
		"data":   models,
	}
}

// fetchModelsFromAPI 从Google API获取模型列表
func (p *GeminiProvider) fetchModelsFromAPI(ctx context.Context) ([]map[string]interface{}, error) {
	// 使用HTTP客户端调用Google API
	url := fmt.Sprintf("%s/v1beta/models?key=%s", p.Config.BaseURL, p.Config.APIKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := netutil.NewClient(10 * time.Second)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch models: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var apiResponse struct {
		Models []struct {
			Name                       string   `json:"name"`
			BaseModelID                string   `json:"baseModelId"`
			Version                    string   `json:"version"`
			DisplayName                string   `json:"displayName"`
			Description                string   `json:"description"`
			InputTokenLimit            int      `json:"inputTokenLimit"`
			OutputTokenLimit           int      `json:"outputTokenLimit"`
			SupportedGenerationMethods []string `json:"supportedGenerationMethods"`
			Temperature                float64  `json:"temperature"`
			MaxTemperature             float64  `json:"maxTemperature"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// 转换为OpenAI格式
	var models []map[string]interface{}
	for _, model := range apiResponse.Models {
		// 只包含支持generateContent的模型
		supportsGeneration := false
		for _, method := range model.SupportedGenerationMethods {
			if method == "generateContent" {
				supportsGeneration = true
				break
			}
		}

		if supportsGeneration {
			// 提取模型ID（去掉"models/"前缀）
			modelID := model.Name
			if strings.HasPrefix(modelID, "models/") {
				modelID = strings.TrimPrefix(modelID, "models/")
			}

			// 推断模型能力
			capabilities := inferGeminiCapabilities(modelID, model.SupportedGenerationMethods)

			// 使用API返回的token限制
			contextWindow := model.InputTokenLimit
			if contextWindow == 0 {
				contextWindow = inferGeminiContextWindow(modelID)
			}

			models = append(models, map[string]interface{}{
				"id":             modelID,
				"object":         "model",
				"created":        time.Now().Unix(),
				"owned_by":       "google",
				"display_name":   model.DisplayName,
				"description":    model.Description,
				"capabilities":   capabilities,
				"context_window": contextWindow,
			})
		}
	}

	return models, nil
}

// inferGeminiCapabilities 根据模型ID和支持的方法推断能力
func inferGeminiCapabilities(modelID string, supportedMethods []string) []string {
	capabilities := []string{"chat"}

	// 检查是否支持视觉
	if strings.Contains(modelID, "vision") || strings.Contains(modelID, "gemini-2") || strings.Contains(modelID, "gemini-1.5") {
		capabilities = append(capabilities, "vision")
	}

	// Gemini 1.5 和 2.x 系列支持函数调用
	if strings.Contains(modelID, "gemini-1.5") || strings.Contains(modelID, "gemini-2") {
		capabilities = append(capabilities, "function_calling")
	}

	return capabilities
}

// inferGeminiContextWindow 根据模型ID推断上下文窗口
func inferGeminiContextWindow(modelID string) int {
	// Gemini 2.5 Pro: 2M tokens
	if strings.Contains(modelID, "gemini-2.5-pro") {
		return 2000000
	}

	// Gemini 2.5 Flash: 1M tokens
	if strings.Contains(modelID, "gemini-2.5-flash") {
		return 1000000
	}

	// Gemini 2.0 Flash: 1M tokens
	if strings.Contains(modelID, "gemini-2.0-flash") {
		return 1000000
	}

	// Gemini 1.5 Pro: 2M tokens
	if strings.Contains(modelID, "gemini-1.5-pro") {
		return 2000000
	}

	// Gemini 1.5 Flash: 1M tokens
	if strings.Contains(modelID, "gemini-1.5-flash") {
		return 1000000
	}

	// Gemini Pro Vision: 16K tokens
	if strings.Contains(modelID, "gemini-pro-vision") {
		return 16000
	}

	// Gemini Pro: 32K tokens
	if strings.Contains(modelID, "gemini-pro") {
		return 32000
	}

	// 默认值
	return 32000
}

// HealthCheck 健康检查
func (p *GeminiProvider) HealthCheck(ctx context.Context) error {
	// 验证客户端
	if p.client == nil {
		return fmt.Errorf("Gemini client not initialized, check API key")
	}

	// 检查配额限制 - 如果在退避期内，跳过健康检查
	if p.quotaManager.ShouldSkipRequest() {
		return fmt.Errorf("Gemini API quota exceeded, skipping health check (will retry after backoff period)")
	}

	// 创建一个短超时的context来避免长时间等待
	healthCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// 发送一个非常简单的测试请求
	contents := []*genai.Content{
		genai.NewContentFromParts([]*genai.Part{
			genai.NewPartFromText("hi"),
		}, genai.RoleUser),
	}

	genConfig := &genai.GenerateContentConfig{
		Temperature:     func() *float32 { t := float32(0.1); return &t }(), // 健康检查使用低温度确保稳定性
		MaxOutputTokens: int32(100),                                         // 限制输出以节省配额
		// 健康检查不需要思考功能，保持简单
		ThinkingConfig: &genai.ThinkingConfig{
			IncludeThoughts: false, // 健康检查不包含思考内容
			ThinkingBudget:  nil,
		},
	}

	_, err := p.client.Models.GenerateContent(healthCtx, "gemini-1.5-flash", contents, genConfig)

	if err != nil {
		// 检查是否是配额限制错误
		if p.isQuotaExceededError(err) {
			p.quotaManager.RecordQuotaError()
			return fmt.Errorf("quota exceeded: %w", err)
		}
		// 检查是否是认证错误
		if p.isAuthError(err) {
			return fmt.Errorf("authentication failed: %w", err)
		}
		return fmt.Errorf("health check failed: %w", err)
	}

	// 记录成功请求
	p.quotaManager.RecordSuccess()
	return nil
}

// CreateHTTPRequest 创建HTTP请求（langchaingo内部处理，这里提供兼容性）
func (p *GeminiProvider) CreateHTTPRequest(ctx context.Context, endpoint string, body interface{}) (*http.Request, error) {
	return nil, fmt.Errorf("CreateHTTPRequest not supported with langchaingo implementation")
}

// ParseHTTPResponse 解析HTTP响应（langchaingo内部处理，这里提供兼容性）
func (p *GeminiProvider) ParseHTTPResponse(resp *http.Response) (interface{}, error) {
	return nil, fmt.Errorf("ParseHTTPResponse not supported with langchaingo implementation")
}

// TransformRequest 转换请求格式（langchaingo内部处理，这里提供兼容性）
func (p *GeminiProvider) TransformRequest(req *ChatCompletionRequest) (interface{}, error) {
	return req, nil // 直接返回原请求，langchaingo内部会处理转换
}

// TransformResponse 转换响应格式（官方SDK内部处理，这里提供兼容性）
func (p *GeminiProvider) TransformResponse(resp interface{}) (*ChatCompletionResponse, error) {
	if response, ok := resp.(*genai.GenerateContentResponse); ok {
		return p.convertGenaiToOpenAIResponse(response, "gemini-2.5-flash")
	}
	return nil, fmt.Errorf("invalid response type for Gemini provider")
}

// convertToGenaiContents 转换消息格式为官方SDK格式，支持多模态和工具调用
func (p *GeminiProvider) convertToGenaiContents(messages []ChatMessage) ([]*genai.Content, error) {
	var contents []*genai.Content

	for _, msg := range messages {
		switch msg.Role {
		case "user":
			// 处理用户消息
			parts, err := p.convertMessageContentToParts(msg.Content)
			if err != nil {
				return nil, fmt.Errorf("failed to convert user message content: %w", err)
			}
			content := genai.NewContentFromParts(parts, genai.RoleUser)
			contents = append(contents, content)

		case "assistant":
			// 处理助手消息，可能包含工具调用
			if len(msg.ToolCalls) > 0 {
				// 如果包含工具调用，需要特殊处理
				parts, err := p.convertAssistantMessageWithToolCalls(msg)
				if err != nil {
					return nil, fmt.Errorf("failed to convert assistant message with tool calls: %w", err)
				}
				content := genai.NewContentFromParts(parts, genai.RoleModel)
				contents = append(contents, content)
			} else {
				// 普通助手消息
				parts, err := p.convertMessageContentToParts(msg.Content)
				if err != nil {
					return nil, fmt.Errorf("failed to convert assistant message content: %w", err)
				}
				content := genai.NewContentFromParts(parts, genai.RoleModel)
				contents = append(contents, content)
			}

		case "tool":
			// 处理工具消息，需要转换为用户消息格式
			parts, err := p.convertToolMessageToParts(msg)
			if err != nil {
				return nil, fmt.Errorf("failed to convert tool message: %w", err)
			}
			content := genai.NewContentFromParts(parts, genai.RoleUser)
			contents = append(contents, content)

		case "system":
			// 系统消息作为用户消息处理
			parts, err := p.convertMessageContentToParts(msg.Content)
			if err != nil {
				return nil, fmt.Errorf("failed to convert system message content: %w", err)
			}
			content := genai.NewContentFromParts(parts, genai.RoleUser)
			contents = append(contents, content)

		default:
			// 未知角色，作为用户消息处理
			parts, err := p.convertMessageContentToParts(msg.Content)
			if err != nil {
				return nil, fmt.Errorf("failed to convert message content for role %s: %w", msg.Role, err)
			}
			content := genai.NewContentFromParts(parts, genai.RoleUser)
			contents = append(contents, content)
		}
	}

	return contents, nil
}

// convertMessageContentToParts 将消息内容转换为Genai Parts，支持多模态
func (p *GeminiProvider) convertMessageContentToParts(content interface{}) ([]*genai.Part, error) {
	var parts []*genai.Part

	switch v := content.(type) {
	case string:
		// 简单文本消息
		parts = append(parts, genai.NewPartFromText(v))

	case []interface{}:
		// 多模态消息数组
		for _, item := range v {
			if itemMap, ok := item.(map[string]interface{}); ok {
				part, err := p.convertContentItemToPart(itemMap)
				if err != nil {
					return nil, err
				}
				if part != nil {
					parts = append(parts, part)
				}
			}
		}

	case []MessageContent:
		// 结构化多模态消息
		for _, item := range v {
			part, err := p.convertMessageContentToPart(item)
			if err != nil {
				return nil, err
			}
			if part != nil {
				parts = append(parts, part)
			}
		}

	default:
		// 尝试将其他类型转换为字符串
		if str := fmt.Sprintf("%v", v); str != "" {
			parts = append(parts, genai.NewPartFromText(str))
		}
	}

	if len(parts) == 0 {
		// 如果没有有效的parts，添加一个空文本part
		parts = append(parts, genai.NewPartFromText(""))
	}

	return parts, nil
}

// convertContentItemToPart 将map格式的内容项转换为Genai Part
func (p *GeminiProvider) convertContentItemToPart(item map[string]interface{}) (*genai.Part, error) {
	contentType, ok := item["type"].(string)
	if !ok {
		return nil, fmt.Errorf("content item missing type field")
	}

	switch contentType {
	case "text":
		if text, ok := item["text"].(string); ok {
			return genai.NewPartFromText(text), nil
		}
		return nil, fmt.Errorf("text content item missing text field")

	case "image_url":
		imageURL, ok := item["image_url"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("image_url content item missing image_url field")
		}

		url, ok := imageURL["url"].(string)
		if !ok {
			return nil, fmt.Errorf("image_url missing url field")
		}

		return p.createImagePart(url)

	default:
		return nil, fmt.Errorf("unsupported content type: %s", contentType)
	}
}

// convertMessageContentToPart 将结构化MessageContent转换为Genai Part
func (p *GeminiProvider) convertMessageContentToPart(content MessageContent) (*genai.Part, error) {
	switch content.Type {
	case "text":
		return genai.NewPartFromText(content.Text), nil

	case "image_url":
		if content.ImageURL == nil {
			return nil, fmt.Errorf("image_url content missing image_url field")
		}
		return p.createImagePart(content.ImageURL.URL)

	default:
		return nil, fmt.Errorf("unsupported content type: %s", content.Type)
	}
}

// createImagePart 创建图像Part，支持base64和URL格式
func (p *GeminiProvider) createImagePart(imageURL string) (*genai.Part, error) {
	// 检查是否是base64格式的图像
	if strings.HasPrefix(imageURL, "data:image/") {
		return p.createBase64ImagePart(imageURL)
	}

	// 对于URL格式的图像，需要下载并转换为base64
	// 这里暂时不支持URL下载，返回错误提示
	return nil, fmt.Errorf("URL-based images not supported yet, please use base64 format: data:image/jpeg;base64,...")
}

// createBase64ImagePart 从base64数据创建图像Part
func (p *GeminiProvider) createBase64ImagePart(dataURL string) (*genai.Part, error) {
	// 解析data URL格式: data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQ...
	parts := strings.Split(dataURL, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid base64 image format")
	}

	// 提取MIME类型
	header := parts[0]
	base64Data := parts[1]

	var mimeType string
	if strings.Contains(header, "image/jpeg") || strings.Contains(header, "image/jpg") {
		mimeType = "image/jpeg"
	} else if strings.Contains(header, "image/png") {
		mimeType = "image/png"
	} else if strings.Contains(header, "image/gif") {
		mimeType = "image/gif"
	} else if strings.Contains(header, "image/webp") {
		mimeType = "image/webp"
	} else {
		return nil, fmt.Errorf("unsupported image format, supported: jpeg, png, gif, webp")
	}

	// 解码base64数据
	imageData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 image: %w", err)
	}

	// 创建图像Part
	return &genai.Part{
		InlineData: &genai.Blob{
			MIMEType: mimeType,
			Data:     imageData,
		},
	}, nil
}

// convertGenaiToOpenAIResponse 转换官方SDK响应为OpenAI格式
func (p *GeminiProvider) convertGenaiToOpenAIResponse(result *genai.GenerateContentResponse, model string) (*ChatCompletionResponse, error) {
	if result == nil {
		return nil, fmt.Errorf("empty response from Gemini")
	}

	// 生成响应ID
	responseID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())

	// 提取文本内容，过滤掉思考内容
	content := p.extractNonThoughtContent(result)

	// 提取工具调用
	toolCalls := p.extractToolCalls(result)

	// 构建OpenAI格式的响应
	message := ChatCompletionMessage{
		Role:    "assistant",
		Content: content,
	}

	// 如果有工具调用，添加到消息中
	if len(toolCalls) > 0 {
		message.ToolCalls = toolCalls
	}

	openaiResp := &ChatCompletionResponse{
		ID:      responseID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []ChatCompletionChoice{
			{
				Index:        0,
				Message:      message,
				FinishReason: "stop",
			},
		},
		Usage: Usage{
			PromptTokens:     0, // 官方SDK可能提供token计数，这里暂时设为0
			CompletionTokens: 0,
			TotalTokens:      0,
		},
	}

	// 如果有使用统计信息，更新token计数
	if result.UsageMetadata != nil {
		openaiResp.Usage.PromptTokens = int(result.UsageMetadata.PromptTokenCount)
		openaiResp.Usage.CompletionTokens = int(result.UsageMetadata.CandidatesTokenCount)
		openaiResp.Usage.TotalTokens = int(result.UsageMetadata.TotalTokenCount)
	}

	return openaiResp, nil
}

// extractNonThoughtContent 从Gemini响应中提取非思考内容
func (p *GeminiProvider) extractNonThoughtContent(result *genai.GenerateContentResponse) string {
	var content strings.Builder

	// 遍历所有候选响应
	for _, candidate := range result.Candidates {
		if candidate.Content != nil {
			// 遍历内容部分，只提取非思考内容
			for _, part := range candidate.Content.Parts {
				// 只添加非思考的文本内容
				if part.Text != "" && !part.Thought {
					content.WriteString(part.Text)
				}
			}
		}
	}

	return content.String()
}

// isQuotaExceededError 检查是否是配额超限错误
func (p *GeminiProvider) isQuotaExceededError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "429") ||
		strings.Contains(errStr, "Quota exceeded") ||
		strings.Contains(errStr, "RATE_LIMIT_EXCEEDED")
}

// isAuthError 检查是否是认证错误
func (p *GeminiProvider) isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "API key") ||
		strings.Contains(errStr, "authentication")
}

// handleGeminiError 处理Gemini特定的错误
func (p *GeminiProvider) handleGeminiError(err error) error {
	if err == nil {
		return nil
	}

	if p.isQuotaExceededError(err) {
		return fmt.Errorf("Gemini API quota exceeded - please check your quota limits or try again later: %w", err)
	}

	if p.isAuthError(err) {
		return fmt.Errorf("Gemini API authentication failed - please check your API key: %w", err)
	}

	// 其他错误
	return fmt.Errorf("Gemini API error: %w", err)
}

// escapeJSONString 正确转义JSON字符串中的特殊字符
func escapeJSONString(s string) string {
	// 使用Go标准库的JSON编码来正确转义字符串
	encoded, err := json.Marshal(s)
	if err != nil {
		// 如果JSON编码失败，手动转义关键字符
		s = strings.ReplaceAll(s, "\\", "\\\\")
		s = strings.ReplaceAll(s, "\"", "\\\"")
		s = strings.ReplaceAll(s, "\n", "\\n")
		s = strings.ReplaceAll(s, "\r", "\\r")
		s = strings.ReplaceAll(s, "\t", "\\t")
		return s
	}
	// 移除JSON编码添加的外层引号
	return string(encoded[1 : len(encoded)-1])
}

// convertGeminiChunkToSSE 将Gemini原生响应块转换为SSE格式
func (p *GeminiProvider) convertGeminiChunkToSSE(chunk *genai.GenerateContentResponse) ([]byte, error) {
	// 构造Gemini原生响应格式
	nativeResponse := map[string]interface{}{
		"candidates": []map[string]interface{}{},
	}

	// 处理候选响应
	for i, candidate := range chunk.Candidates {
		candidateData := map[string]interface{}{
			"content": map[string]interface{}{
				"parts": []map[string]interface{}{},
				"role":  "model",
			},
			"index": i,
		}

		// 处理内容部分
		if candidate.Content != nil {
			for _, part := range candidate.Content.Parts {
				if part.Text != "" {
					partData := map[string]interface{}{
						"text": part.Text,
					}

					// 如果这是思考内容，添加thought字段
					if part.Thought {
						partData["thought"] = true
					}

					candidateData["content"].(map[string]interface{})["parts"] = append(
						candidateData["content"].(map[string]interface{})["parts"].([]map[string]interface{}),
						partData,
					)
				}
			}
		}

		// 处理完成原因
		candidateData["finishReason"] = candidate.FinishReason

		nativeResponse["candidates"] = append(
			nativeResponse["candidates"].([]map[string]interface{}),
			candidateData,
		)
	}

	// 处理使用统计
	if chunk.UsageMetadata != nil {
		usageMetadata := map[string]interface{}{
			"promptTokenCount":     chunk.UsageMetadata.PromptTokenCount,
			"candidatesTokenCount": chunk.UsageMetadata.CandidatesTokenCount,
			"totalTokenCount":      chunk.UsageMetadata.TotalTokenCount,
		}

		// 如果有思考token计数，添加到响应中
		if chunk.UsageMetadata.ThoughtsTokenCount > 0 {
			usageMetadata["thoughtsTokenCount"] = chunk.UsageMetadata.ThoughtsTokenCount
		}

		nativeResponse["usageMetadata"] = usageMetadata
	}

	// 序列化为JSON
	jsonData, err := json.Marshal(nativeResponse)
	if err != nil {
		return nil, err
	}

	// 格式化为SSE
	return []byte(fmt.Sprintf("data: %s\n\n", string(jsonData))), nil
}

// convertAssistantMessageWithToolCalls 转换包含工具调用的助手消息
func (p *GeminiProvider) convertAssistantMessageWithToolCalls(msg ChatMessage) ([]*genai.Part, error) {
	var parts []*genai.Part

	// 如果有文本内容，先添加文本部分
	if msg.Content != nil {
		textParts, err := p.convertMessageContentToParts(msg.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to convert assistant message content: %w", err)
		}
		parts = append(parts, textParts...)
	}

	// 添加工具调用信息作为文本描述
	// 注意：Gemini不直接支持OpenAI格式的工具调用，我们将其转换为文本描述
	for _, toolCall := range msg.ToolCalls {
		toolCallText := fmt.Sprintf("Tool call: %s(%s)", toolCall.Function.Name, toolCall.Function.Arguments)
		parts = append(parts, genai.NewPartFromText(toolCallText))
	}

	// 如果没有任何内容，添加一个空文本part
	if len(parts) == 0 {
		parts = append(parts, genai.NewPartFromText(""))
	}

	return parts, nil
}

// convertToolMessageToParts 转换工具消息为Parts
func (p *GeminiProvider) convertToolMessageToParts(msg ChatMessage) ([]*genai.Part, error) {
	var parts []*genai.Part

	// 工具消息转换为用户消息，包含工具执行结果
	toolResultText := fmt.Sprintf("Tool result for call %s: %v", msg.ToolCallID, msg.Content)
	parts = append(parts, genai.NewPartFromText(toolResultText))

	return parts, nil
}

// convertToolsToGeminiFormat 转换OpenAI格式的工具定义为Gemini格式
func (p *GeminiProvider) convertToolsToGeminiFormat(tools []Tool) ([]*genai.Tool, error) {
	var geminiTools []*genai.Tool

	for _, tool := range tools {
		if tool.Type != "function" {
			continue // Gemini只支持函数工具
		}

		if tool.Function == nil {
			continue
		}

		// 创建Gemini函数声明
		funcDecl := &genai.FunctionDeclaration{
			Name:        tool.Function.Name,
			Description: tool.Function.Description,
		}

		// 转换参数schema
		if tool.Function.Parameters != nil {
			// 将map[string]interface{}转换为genai.Schema
			schema := &genai.Schema{}
			if schemaBytes, err := json.Marshal(tool.Function.Parameters); err == nil {
				json.Unmarshal(schemaBytes, schema)
			}
			funcDecl.Parameters = schema
		}

		// 创建Gemini工具
		geminiTool := &genai.Tool{
			FunctionDeclarations: []*genai.FunctionDeclaration{funcDecl},
		}

		geminiTools = append(geminiTools, geminiTool)
	}

	return geminiTools, nil
}

// convertGeminiFunctionCallToOpenAI 转换Gemini函数调用为OpenAI格式的流式数据
func (p *GeminiProvider) convertGeminiFunctionCallToOpenAI(funcCall *genai.FunctionCall, responseID string, created int64, model string) string {
	// 生成工具调用ID
	toolCallID := fmt.Sprintf("call_%d", time.Now().UnixNano())

	// 转换参数为JSON字符串
	argsBytes, _ := json.Marshal(funcCall.Args)
	argsStr := string(argsBytes)

	// 创建OpenAI格式的工具调用流式数据
	toolCallData := fmt.Sprintf(`data: {"id":"%s","object":"chat.completion.chunk","created":%d,"model":"%s","choices":[{"index":0,"delta":{"tool_calls":[{"id":"%s","type":"function","function":{"name":"%s","arguments":"%s"}}]},"finish_reason":null}]}

`,
		responseID, created, model, toolCallID, funcCall.Name, escapeJSONString(argsStr))

	return toolCallData
}

// extractToolCalls 从Gemini响应中提取工具调用
func (p *GeminiProvider) extractToolCalls(result *genai.GenerateContentResponse) []ToolCall {
	var toolCalls []ToolCall

	// 遍历所有候选响应
	for _, candidate := range result.Candidates {
		if candidate.Content != nil {
			// 遍历内容部分，查找函数调用
			for _, part := range candidate.Content.Parts {
				if part.FunctionCall != nil {
					// 生成工具调用ID
					toolCallID := fmt.Sprintf("call_%d", time.Now().UnixNano())

					// 转换参数为JSON字符串
					argsBytes, err := json.Marshal(part.FunctionCall.Args)
					if err != nil {
						// 如果序列化失败，使用空对象
						argsBytes = []byte("{}")
					}

					toolCall := ToolCall{
						ID:   toolCallID,
						Type: "function",
						Function: &FunctionCall{
							Name:      part.FunctionCall.Name,
							Arguments: string(argsBytes),
						},
					}

					toolCalls = append(toolCalls, toolCall)
				}
			}
		}
	}

	return toolCalls
}
