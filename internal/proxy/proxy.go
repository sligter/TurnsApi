package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"turnsapi/internal"
	"turnsapi/internal/keymanager"
	"turnsapi/internal/logger"
	"turnsapi/internal/netutil"

	"github.com/gin-gonic/gin"
)

// ChatCompletionRequest OpenRouter聊天完成请求结构
type ChatCompletionRequest struct {
	Model       string                 `json:"model"`
	Messages    []ChatMessage          `json:"messages"`
	Stream      bool                   `json:"stream,omitempty"`
	Temperature float64                `json:"temperature,omitempty"`
	MaxTokens   int                    `json:"max_tokens,omitempty"`
	TopP        float64                `json:"top_p,omitempty"`
	Stop        interface{}            `json:"stop,omitempty"`
	Extra       map[string]interface{} `json:"-"`
}

// ChatMessage 聊天消息结构
type ChatMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // 支持字符串或数组格式
}

// OpenRouterProxy OpenRouter代理
type OpenRouterProxy struct {
	config        *internal.Config
	keyManager    *keymanager.KeyManager
	httpClient    *http.Client
	requestLogger *logger.RequestLogger
}

// NewOpenRouterProxy 创建新的OpenRouter代理
func NewOpenRouterProxy(config *internal.Config, keyManager *keymanager.KeyManager, requestLogger *logger.RequestLogger) *OpenRouterProxy {
	return &OpenRouterProxy{
		config:        config,
		keyManager:    keyManager,
		requestLogger: requestLogger,
		httpClient:    netutil.NewClient(config.OpenRouter.Timeout),
	}
}

// getProxyKeyInfo 从上下文中获取代理密钥信息
func (p *OpenRouterProxy) getProxyKeyInfo(c *gin.Context) (string, string) {
	proxyKeyName, exists1 := c.Get("proxy_key_name")
	proxyKeyID, exists2 := c.Get("proxy_key_id")

	if !exists1 || !exists2 {
		return "Unknown", "unknown"
	}

	name, ok1 := proxyKeyName.(string)
	id, ok2 := proxyKeyID.(string)

	if !ok1 || !ok2 {
		return "Unknown", "unknown"
	}

	return name, id
}

// HandleChatCompletions 处理聊天完成请求
func (p *OpenRouterProxy) HandleChatCompletions(c *gin.Context) {
	// 解析请求体
	var req ChatCompletionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": "Invalid request format",
				"type":    "invalid_request_error",
				"code":    "invalid_request",
			},
		})
		return
	}

	// 执行请求转发，带重试机制
	if req.Stream {
		p.handleStreamingRequestWithRetry(c, &req)
	} else {
		p.handleNonStreamingRequestWithRetry(c, &req)
	}
}

// handleNonStreamingRequestWithRetry 处理非流式请求（带重试）
func (p *OpenRouterProxy) handleNonStreamingRequestWithRetry(c *gin.Context, req *ChatCompletionRequest) {
	maxRetries := p.config.OpenRouter.MaxRetries

	// 获取API密钥（只获取一次）
	apiKey, err := p.keyManager.GetNextKey()
	if err != nil {
		log.Printf("Failed to get API key: %v", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": gin.H{
				"message": "No available API keys",
				"type":    "service_unavailable",
				"code":    "no_api_keys",
			},
		})
		return
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// 尝试请求（使用同一个API密钥）
		success := p.handleNonStreamingRequest(c, req, apiKey)
		if success {
			return
		}

		// 如果不是最后一次尝试，等待一段时间后重试
		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt+1) * time.Second)
			log.Printf("Retrying request with same API key (attempt %d/%d)", attempt+2, maxRetries+1)
		}
	}
}

// handleStreamingRequestWithRetry 处理流式请求（带重试）
func (p *OpenRouterProxy) handleStreamingRequestWithRetry(c *gin.Context, req *ChatCompletionRequest) {
	// 获取API密钥（只获取一次）
	apiKey, err := p.keyManager.GetNextKey()
	if err != nil {
		log.Printf("Failed to get API key: %v", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": gin.H{
				"message": "No available API keys",
				"type":    "service_unavailable",
				"code":    "no_api_keys",
			},
		})
		return
	}

	// 尝试流式请求（流式请求不支持重试，因为响应已经开始发送）
	p.handleStreamingRequest(c, req, apiKey)
}

// handleNonStreamingRequest 处理非流式请求
func (p *OpenRouterProxy) handleNonStreamingRequest(c *gin.Context, req *ChatCompletionRequest, apiKey string) bool {
	startTime := time.Now()

	// 序列化请求
	reqBody, err := json.Marshal(req)
	if err != nil {
		log.Printf("Failed to marshal request: %v", err)
		// 记录日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 500, false, time.Since(startTime), err)
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Internal server error",
				"type":    "internal_error",
			},
		})
		return false
	}

	// 创建HTTP请求
	url := fmt.Sprintf("%s/chat/completions", p.config.OpenRouter.BaseURL)
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		// 记录日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 500, false, time.Since(startTime), err)
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Internal server error",
				"type":    "internal_error",
			},
		})
		return false
	}

	// 设置请求头
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	httpReq.Header.Set("User-Agent", "TurnsAPI/1.0")

	// 复制原始请求的其他头部（如果需要）
	for key, values := range c.Request.Header {
		if key != "Authorization" && key != "Content-Length" && key != "Host" {
			for _, value := range values {
				httpReq.Header.Add(key, value)
			}
		}
	}

	// 发送请求
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		log.Printf("Request failed: %v", err)
		p.keyManager.ReportError(apiKey, err.Error())
		// 记录日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 502, false, time.Since(startTime), err)
		}
		c.JSON(http.StatusBadGateway, gin.H{
			"error": gin.H{
				"message": "Failed to connect to OpenRouter API",
				"type":    "connection_error",
			},
		})
		return false
	}
	defer resp.Body.Close()

	// 检查响应是否使用gzip压缩并读取响应
	var bodyReader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Printf("Failed to create gzip reader: %v", err)
			p.keyManager.ReportError(apiKey, err.Error())
			// 记录日志
			if p.requestLogger != nil {
				proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
				providerGroup := p.getProviderGroup(c, req.Model)
				clientIP := logger.GetClientIP(c)
				p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 502, false, time.Since(startTime), err)
			}
			c.JSON(http.StatusBadGateway, gin.H{
				"error": gin.H{
					"message": "Failed to decompress response",
					"type":    "response_error",
				},
			})
			return false
		}
		defer gzipReader.Close()
		bodyReader = gzipReader
	}

	// 读取响应
	respBody, err := io.ReadAll(bodyReader)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
		p.keyManager.ReportError(apiKey, err.Error())
		// 记录日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 502, false, time.Since(startTime), err)
		}
		c.JSON(http.StatusBadGateway, gin.H{
			"error": gin.H{
				"message": "Failed to read response from OpenRouter API",
				"type":    "response_error",
			},
		})
		return false
	}

	duration := time.Since(startTime)

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		log.Printf("OpenRouter API returned status %d: %s", resp.StatusCode, string(respBody))
		p.keyManager.ReportError(apiKey, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(respBody)))

		// 记录日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			requestErr := fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), string(respBody), clientIP, resp.StatusCode, false, duration, requestErr)
		}

		// 转发错误响应
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
		return false
	}

	// 报告成功
	p.keyManager.ReportSuccess(apiKey)

	// 记录成功日志
	if p.requestLogger != nil {
		proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
		providerGroup := p.getProviderGroup(c, req.Model)
		clientIP := logger.GetClientIP(c)
		p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), string(respBody), clientIP, resp.StatusCode, false, duration, nil)
	}

	// 转发成功响应
	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
	return true
}

// handleStreamingRequest 处理流式请求
func (p *OpenRouterProxy) handleStreamingRequest(c *gin.Context, req *ChatCompletionRequest, apiKey string) bool {
	startTime := time.Now()

	// 序列化请求
	reqBody, err := json.Marshal(req)
	if err != nil {
		log.Printf("Failed to marshal request: %v", err)
		// 记录日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 500, true, time.Since(startTime), err)
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Internal server error",
				"type":    "internal_error",
			},
		})
		return false
	}

	// 创建HTTP请求
	url := fmt.Sprintf("%s/chat/completions", p.config.OpenRouter.BaseURL)
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		// 记录日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 500, true, time.Since(startTime), err)
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Internal server error",
				"type":    "internal_error",
			},
		})
		return false
	}

	// 设置请求头
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	httpReq.Header.Set("User-Agent", "TurnsAPI/1.0")
	httpReq.Header.Set("Accept", "text/event-stream")

	// 复制原始请求的其他头部
	for key, values := range c.Request.Header {
		if key != "Authorization" && key != "Content-Length" && key != "Host" {
			for _, value := range values {
				httpReq.Header.Add(key, value)
			}
		}
	}

	// 为流式请求创建专用的HTTP客户端，使用更长的超时时间
	streamingClient := p.httpClient

	// 发送请求
	resp, err := streamingClient.Do(httpReq)
	if err != nil {
		log.Printf("Streaming request failed: %v", err)
		p.keyManager.ReportError(apiKey, err.Error())
		// 记录日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 502, true, time.Since(startTime), err)
		}
		c.JSON(http.StatusBadGateway, gin.H{
			"error": gin.H{
				"message": "Failed to connect to OpenRouter API",
				"type":    "connection_error",
			},
		})
		return false
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("OpenRouter API returned status %d: %s", resp.StatusCode, string(respBody))
		p.keyManager.ReportError(apiKey, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(respBody)))

		// 记录日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			requestErr := fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), string(respBody), clientIP, resp.StatusCode, true, time.Since(startTime), requestErr)
		}

		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
		return false
	}

	// 设置SSE响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")

	// 检查响应是否使用gzip压缩
	var bodyReader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Printf("Failed to create gzip reader: %v", err)
			p.keyManager.ReportError(apiKey, err.Error())
			// 记录日志
			if p.requestLogger != nil {
				proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
				providerGroup := p.getProviderGroup(c, req.Model)
				clientIP := logger.GetClientIP(c)
				p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 502, true, time.Since(startTime), err)
			}
			c.JSON(http.StatusBadGateway, gin.H{
				"error": gin.H{
					"message": "Failed to decompress response",
					"type":    "response_error",
				},
			})
			return false
		}
		defer gzipReader.Close()
		bodyReader = gzipReader
	}

	// 创建缓冲读取器
	reader := bufio.NewReader(bodyReader)

	// 获取响应写入器
	w := c.Writer
	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("Streaming not supported")
		// 记录日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			streamErr := fmt.Errorf("streaming not supported")
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 500, true, time.Since(startTime), streamErr)
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Streaming not supported",
				"type":    "internal_error",
			},
		})
		return false
	}

	// 流式转发响应
	hasData := false
	var responseBuffer strings.Builder
	lastLines := make([]string, 0, 20) // 保存最后20行用于token提取

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading stream: %v", err)
			if !hasData {
				// 只有在没有接收到任何数据时才报告错误
				p.keyManager.ReportError(apiKey, err.Error())
				// 记录日志
				if p.requestLogger != nil {
					proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
					providerGroup := p.getProviderGroup(c, req.Model)
					clientIP := logger.GetClientIP(c)
					// 构建完整响应用于日志
					fullResponse := responseBuffer.String()
					for _, lastLine := range lastLines {
						fullResponse += lastLine
					}
					p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), fullResponse, clientIP, 502, true, time.Since(startTime), err)
				}
				return false
			}
			// 如果已经接收到数据，即使后续出现错误也认为是成功的
			log.Printf("Stream ended with error after receiving data, treating as success")
			break
		}

		hasData = true

		// 转发数据行
		if strings.HasPrefix(line, "data: ") || strings.HasPrefix(line, "event: ") || line == "\n" {
			w.Write([]byte(line))
			flusher.Flush()

			// 收集响应数据用于日志记录
			if responseBuffer.Len() < 5000 { // 减少前面内容的记录
				responseBuffer.WriteString(line)
			}

			// 保存最后的行，用于token提取
			lastLines = append(lastLines, line)
			if len(lastLines) > 20 {
				lastLines = lastLines[1:] // 保持最后20行
			}
		}
	}

	// 将最后的行添加到响应缓冲区，确保包含token信息
	for _, lastLine := range lastLines {
		responseBuffer.WriteString(lastLine)
	}

	duration := time.Since(startTime)

	// 如果接收到数据，报告成功
	if hasData {
		p.keyManager.ReportSuccess(apiKey)
		// 记录成功日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			providerGroup := p.getProviderGroup(c, req.Model)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), responseBuffer.String(), clientIP, 200, true, duration, nil)
		}
		return true
	}

	// 没有接收到任何数据，报告错误
	p.keyManager.ReportError(apiKey, "No data received from stream")
	// 记录日志
	if p.requestLogger != nil {
		proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
		providerGroup := p.getProviderGroup(c, req.Model)
		clientIP := logger.GetClientIP(c)
		streamErr := fmt.Errorf("no data received from stream")
		p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, providerGroup, apiKey, req.Model, string(reqBody), "", clientIP, 502, true, duration, streamErr)
	}
	return false
}

// HandleModels 处理模型列表请求
func (p *OpenRouterProxy) HandleModels(c *gin.Context) {
	// 获取API密钥
	apiKey, err := p.keyManager.GetNextKey()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": gin.H{
				"message": "No available API keys",
				"type":    "service_unavailable",
				"code":    "no_api_keys",
			},
		})
		return
	}

	// 创建请求到OpenRouter
	req, err := http.NewRequest("GET", p.config.OpenRouter.BaseURL+"/models", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Failed to create request",
				"type":    "internal_error",
				"code":    "request_creation_failed",
			},
		})
		return
	}

	// 设置请求头
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := p.httpClient
	resp, err := client.Do(req)
	if err != nil {
		p.keyManager.ReportError(apiKey, err.Error())
		c.JSON(http.StatusBadGateway, gin.H{
			"error": gin.H{
				"message": "Failed to connect to OpenRouter",
				"type":    "connection_error",
				"code":    "upstream_connection_failed",
			},
		})
		return
	}
	defer resp.Body.Close()

	// 检查响应是否使用gzip压缩并读取响应
	var bodyReader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Printf("Failed to create gzip reader: %v", err)
			p.keyManager.ReportError(apiKey, err.Error())
			c.JSON(http.StatusBadGateway, gin.H{
				"error": gin.H{
					"message": "Failed to decompress response",
					"type":    "response_error",
					"code":    "response_decompress_failed",
				},
			})
			return
		}
		defer gzipReader.Close()
		bodyReader = gzipReader
	}

	// 读取响应
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		p.keyManager.ReportError(apiKey, err.Error())
		c.JSON(http.StatusBadGateway, gin.H{
			"error": gin.H{
				"message": "Failed to read response",
				"type":    "response_error",
				"code":    "response_read_failed",
			},
		})
		return
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		p.keyManager.ReportError(apiKey, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)))
		c.Data(resp.StatusCode, "application/json", body)
		return
	}

	// 报告成功
	p.keyManager.ReportSuccess(apiKey)

	// 获取允许的模型列表
	allowedModels := p.keyManager.GetAllAllowedModels()

	// 如果没有模型限制（空列表表示无限制），直接返回原始响应
	if len(allowedModels) == 0 {
		c.Data(http.StatusOK, "application/json", body)
		return
	}

	// 解析响应以过滤模型
	var modelsResponse struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &modelsResponse); err != nil {
		// 如果解析失败，返回原始响应
		c.Data(http.StatusOK, "application/json", body)
		return
	}

	// 创建允许模型的映射以便快速查找
	allowedSet := make(map[string]bool)
	for _, model := range allowedModels {
		allowedSet[model] = true
	}

	// 过滤模型列表
	var filteredModels []interface{}
	var originalResponse map[string]interface{}
	if err := json.Unmarshal(body, &originalResponse); err == nil {
		if dataArray, ok := originalResponse["data"].([]interface{}); ok {
			for _, modelData := range dataArray {
				if modelMap, ok := modelData.(map[string]interface{}); ok {
					if modelID, ok := modelMap["id"].(string); ok && allowedSet[modelID] {
						filteredModels = append(filteredModels, modelData)
					}
				}
			}
			// 构建过滤后的响应
			filteredResponse := map[string]interface{}{
				"data": filteredModels,
			}
			c.JSON(http.StatusOK, filteredResponse)
			return
		}
	}

	// 如果过滤失败，返回原始响应
	c.Data(http.StatusOK, "application/json", body)
}

// getProviderGroup 获取提供商分组信息
func (p *OpenRouterProxy) getProviderGroup(c *gin.Context, model string) string {
	// 尝试从上下文中获取分组信息
	if groupID, exists := c.Get("provider_group"); exists {
		if groupStr, ok := groupID.(string); ok {
			return groupStr
		}
	}

	// 如果上下文中没有，尝试根据模型推断分组
	if group, groupID := p.config.GetGroupByModel(model); group != nil {
		return groupID
	}

	// 默认返回空字符串
	return ""
}
