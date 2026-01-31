package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkoukk/tiktoken-go"

	"turnsapi/internal/storage"
)

// RequestLogger 请求日志记录器
type RequestLogger struct {
	db *Database

	asyncEnabled  bool
	writeCh       chan *RequestLog
	batchSize     int
	flushInterval time.Duration
	wg            sync.WaitGroup
	closeOnce     sync.Once
}

// NewRequestLogger 创建新的请求日志记录器
func NewRequestLogger(dbPath string) (*RequestLogger, error) {
	db, err := NewDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	return &RequestLogger{
		db: db,
	}, nil
}

func NewRequestLoggerWithConfig(dbCfg storage.DatabaseConfig, logsCfg storage.RequestLogsConfig) (*RequestLogger, error) {
	db, err := NewDatabaseWithConfig(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	r := &RequestLogger{db: db}

	if logsCfg.Buffer <= 0 {
		logsCfg.Buffer = 10000
	}
	if logsCfg.BatchSize <= 0 {
		logsCfg.BatchSize = 200
	}
	if logsCfg.FlushInterval <= 0 {
		logsCfg.FlushInterval = 200 * time.Millisecond
	}

	if logsCfg.AsyncWrite {
		r.asyncEnabled = true
		r.batchSize = logsCfg.BatchSize
		r.flushInterval = logsCfg.FlushInterval
		r.writeCh = make(chan *RequestLog, logsCfg.Buffer)
		r.wg.Add(1)
		go r.runWriter()
	}

	return r, nil
}

// Close 关闭日志记录器
func (r *RequestLogger) Close() error {
	if r == nil {
		return nil
	}

	r.closeOnce.Do(func() {
		if r.asyncEnabled && r.writeCh != nil {
			close(r.writeCh)
		}
	})

	r.wg.Wait()
	return r.db.Close()
}

// LogRequest 记录请求日志
func (r *RequestLogger) LogRequest(
	proxyKeyName, proxyKeyID, providerGroup, openRouterKey, model, requestBody, responseBody, clientIP string,
	statusCode int, isStream bool, duration time.Duration, err error,
) {
	// 提取token使用量
	tokensUsed := r.extractTokensUsed(responseBody)
	tokensEstimated := false

	// 如果响应中没有token信息且请求成功，尝试基于请求和响应内容估算
	if tokensUsed == 0 && statusCode == 200 {
		estimatedTokens := r.estimateTokensFromRequestAndResponseWithModel(requestBody, responseBody, model)
		if estimatedTokens > 0 {
			tokensUsed = estimatedTokens
			tokensEstimated = true
			log.Printf("Using comprehensive token estimation for model %s: %d tokens (request + response)", model, tokensUsed)
		}
	}

	// 提取工具调用信息
	hasToolCalls, toolCallsCount, toolNames := r.extractToolCallInfo(requestBody, responseBody)

	maskedKey := r.maskAPIKey(openRouterKey)
	requestBody = r.redactSecret(requestBody, openRouterKey, maskedKey)
	responseBody = r.redactSecret(responseBody, openRouterKey, maskedKey)

	// 创建日志记录
	requestLog := &RequestLog{
		ProxyKeyName:    proxyKeyName,
		ProxyKeyID:      proxyKeyID,
		ProviderGroup:   providerGroup,
		OpenRouterKey:   maskedKey,
		Model:           model,
		RequestBody:     requestBody,
		ResponseBody:    responseBody,
		StatusCode:      statusCode,
		IsStream:        isStream,
		Duration:        duration.Milliseconds(),
		TokensUsed:      tokensUsed,
		TokensEstimated: tokensEstimated,
		ClientIP:        clientIP,
		CreatedAt:       time.Now(),
		HasToolCalls:    hasToolCalls,
		ToolCallsCount:  toolCallsCount,
		ToolNames:       toolNames,
	}

	// 如果有错误，记录错误信息
	if err != nil {
		requestLog.Error = err.Error()
	}

	// 插入数据库
	if r.asyncEnabled && r.writeCh != nil {
		select {
		case r.writeCh <- requestLog:
			return
		default:
			// channel is full - fall back to synchronous insert to avoid dropping logs
		}
	}

	if insertErr := r.db.InsertRequestLog(requestLog); insertErr != nil {
		log.Printf("Failed to insert request log: %v", insertErr)
	}
}

func (r *RequestLogger) redactSecret(text, secret, replacement string) string {
	if text == "" || secret == "" || replacement == "" {
		return text
	}

	text = strings.ReplaceAll(text, secret, replacement)
	text = strings.ReplaceAll(text, "Bearer "+secret, "Bearer "+replacement)
	return text
}

func (r *RequestLogger) runWriter() {
	defer r.wg.Done()

	if r.writeCh == nil {
		return
	}

	ticker := time.NewTicker(r.flushInterval)
	defer ticker.Stop()

	batch := make([]*RequestLog, 0, r.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}

		if err := r.db.InsertRequestLogsBatch(batch); err != nil {
			log.Printf("Failed to batch insert request logs (len=%d): %v", len(batch), err)
			for _, row := range batch {
				if insertErr := r.db.InsertRequestLog(row); insertErr != nil {
					log.Printf("Failed to insert request log (fallback): %v", insertErr)
				}
			}
		}

		batch = batch[:0]
	}

	for {
		select {
		case row, ok := <-r.writeCh:
			if !ok {
				flush()
				return
			}
			batch = append(batch, row)
			if len(batch) >= r.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// GetRequestLogs 获取请求日志列表
func (r *RequestLogger) GetRequestLogs(proxyKeyName, providerGroup string, limit, offset int) ([]*RequestLogSummary, error) {
	return r.db.GetRequestLogs(proxyKeyName, providerGroup, limit, offset)
}

// GetRequestLogsWithFilter 根据筛选条件获取请求日志列表
func (r *RequestLogger) GetRequestLogsWithFilter(filter *LogFilter) ([]*RequestLogSummary, error) {
	return r.db.GetRequestLogsWithFilter(filter)
}

// GetRequestCountWithFilter 根据筛选条件获取请求总数
func (r *RequestLogger) GetRequestCountWithFilter(filter *LogFilter) (int64, error) {
	return r.db.GetRequestCountWithFilter(filter)
}

// GetRequestLogDetail 获取请求日志详情
func (r *RequestLogger) GetRequestLogDetail(id int64) (*RequestLog, error) {
	return r.db.GetRequestLogDetail(id)
}

// GetProxyKeyStats 获取代理密钥统计
func (r *RequestLogger) GetProxyKeyStats() ([]*ProxyKeyStats, error) {
	return r.db.GetProxyKeyStats()
}

// GetModelStats 获取模型统计
func (r *RequestLogger) GetModelStats() ([]*ModelStats, error) {
	return r.db.GetModelStats()
}

// GetModelStatsWithFilter 获取模型统计（支持筛选与时间范围）
func (r *RequestLogger) GetModelStatsWithFilter(filter *LogFilter) ([]*ModelStats, error) {
	return r.db.GetModelStatsWithFilter(filter)
}

// GetStatusStats 获取状态分布聚合（支持筛选与时间范围）
func (r *RequestLogger) GetStatusStats(filter *LogFilter) (*StatusStats, error) {
	return r.db.GetStatusStats(filter)
}

// GetTokensTimeline 获取tokens时间序列（支持筛选与时间范围）
func (r *RequestLogger) GetTokensTimeline(filter *LogFilter) ([]*TimelinePoint, error) {
	return r.db.GetTokensTimeline(filter)
}

// GetGroupTokensStats 获取按分组聚合的tokens（支持筛选与时间范围）
func (r *RequestLogger) GetGroupTokensStats(filter *LogFilter) ([]*GroupTokensStat, error) {
	return r.db.GetGroupTokensStats(filter)
}

// GetRequestCount 获取请求总数
func (r *RequestLogger) GetRequestCount(proxyKeyName, providerGroup string) (int64, error) {
	return r.db.GetRequestCount(proxyKeyName, providerGroup)
}

// GetTotalTokensStats 获取总token数统计
func (r *RequestLogger) GetTotalTokensStats() (*TotalTokensStats, error) {
	return r.db.GetTotalTokensStats()
}

// InsertProxyKey 插入代理密钥
func (r *RequestLogger) InsertProxyKey(key *ProxyKey) error {
	return r.db.InsertProxyKey(key)
}

// GetProxyKey 根据密钥获取代理密钥信息
func (r *RequestLogger) GetProxyKey(keyValue string) (*ProxyKey, error) {
	return r.db.GetProxyKey(keyValue)
}

// GetAllProxyKeys 获取所有代理密钥
func (r *RequestLogger) GetAllProxyKeys() ([]*ProxyKey, error) {
	return r.db.GetAllProxyKeys()
}

// UpdateProxyKey 更新代理密钥信息
func (r *RequestLogger) UpdateProxyKey(key *ProxyKey) error {
	return r.db.UpdateProxyKey(key)
}

// UpdateProxyKeyLastUsed 更新代理密钥最后使用时间
func (r *RequestLogger) UpdateProxyKeyLastUsed(keyID string) error {
	return r.db.UpdateProxyKeyLastUsed(keyID)
}

// UpdateProxyKeyUsage 更新代理密钥使用次数
func (r *RequestLogger) UpdateProxyKeyUsage(keyID string) error {
	return r.db.UpdateProxyKeyUsage(keyID)
}

// DeleteProxyKey 删除代理密钥
func (r *RequestLogger) DeleteProxyKey(keyID string) error {
	return r.db.DeleteProxyKey(keyID)
}

// CleanupOldLogs 清理旧日志
func (r *RequestLogger) CleanupOldLogs(retentionDays int) error {
	return r.db.CleanupOldLogs(retentionDays)
}

// DeleteRequestLogs 批量删除请求日志
func (r *RequestLogger) DeleteRequestLogs(ids []int64) (int64, error) {
	return r.db.DeleteRequestLogs(ids)
}

// ClearAllRequestLogs 清空所有请求日志
func (r *RequestLogger) ClearAllRequestLogs() (int64, error) {
	return r.db.ClearAllRequestLogs()
}

// ClearErrorRequestLogs 清空错误请求日志
func (r *RequestLogger) ClearErrorRequestLogs() (int64, error) {
	return r.db.ClearErrorRequestLogs()
}

// GetAllRequestLogsForExport 获取所有请求日志用于导出
func (r *RequestLogger) GetAllRequestLogsForExport(proxyKeyName, providerGroup string) ([]*RequestLog, error) {
	return r.db.GetAllRequestLogsForExport(proxyKeyName, providerGroup)
}

// GetAllRequestLogsForExportWithFilter 根据筛选条件获取所有请求日志用于导出
func (r *RequestLogger) GetAllRequestLogsForExportWithFilter(filter *LogFilter) ([]*RequestLog, error) {
	return r.db.GetAllRequestLogsForExportWithFilter(filter)
}

// maskAPIKey 遮蔽API密钥敏感信息
func (r *RequestLogger) maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return strings.Repeat("*", len(apiKey))
	}
	return apiKey[:4] + strings.Repeat("*", len(apiKey)-8) + apiKey[len(apiKey)-4:]
}

// extractTokensUsed 从响应中提取使用的token数量
func (r *RequestLogger) extractTokensUsed(responseBody string) int {
	if responseBody == "" {
		return 0
	}

	// 首先尝试解析JSON响应（非流式）
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(responseBody), &response); err == nil {
		// 查找usage字段
		if usage, ok := response["usage"].(map[string]interface{}); ok {
			if totalTokens, ok := usage["total_tokens"].(float64); ok {
				if totalTokens > 0 {
					return int(totalTokens)
				}
			}
		}
		// 如果token数为0，尝试使用备用估算方法
		if estimatedTokens := r.estimateTokensFromResponse(responseBody); estimatedTokens > 0 {
			log.Printf("Using fallback token estimation: %d tokens", estimatedTokens)
			return estimatedTokens
		}
		return 0
	}

	// 如果JSON解析失败，尝试从流式响应中提取token数
	tokens := r.extractTokensFromStream(responseBody)

	// 如果流式响应也没有token信息，使用备用估算方法
	if tokens == 0 {
		if estimatedTokens := r.estimateTokensFromResponse(responseBody); estimatedTokens > 0 {
			log.Printf("Using fallback token estimation for stream: %d tokens", estimatedTokens)
			return estimatedTokens
		}
	}

	return tokens
}

// extractTokensFromStream 从流式响应中提取token数量
func (r *RequestLogger) extractTokensFromStream(streamBody string) int {
	if streamBody == "" {
		return 0
	}

	lines := strings.Split(streamBody, "\n")
	totalTokens := 0

	// 从后往前遍历，因为token统计通常在最后几个chunk中
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])

		// 跳过非数据行
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		dataStr := strings.TrimPrefix(line, "data: ")

		// 跳过[DONE]标记、空行和处理状态信息
		if dataStr == "[DONE]" || dataStr == "" ||
			strings.Contains(dataStr, "OPENROUTER PROCESSING") ||
			strings.Contains(dataStr, "PROCESSING") {
			continue
		}

		// 尝试解析JSON数据
		var chunkData map[string]interface{}
		if err := json.Unmarshal([]byte(dataStr), &chunkData); err != nil {
			// 如果JSON解析失败，记录调试信息但继续处理
			log.Printf("Failed to parse JSON chunk: %s, error: %v", dataStr[:min(100, len(dataStr))], err)
			continue
		}

		// 查找usage字段（OpenAI格式）
		if usage, ok := chunkData["usage"].(map[string]interface{}); ok {
			if tokens, ok := usage["total_tokens"].(float64); ok {
				totalTokens = int(tokens)
				log.Printf("Found tokens in stream: %d", totalTokens)
				break // 找到token统计就退出
			}
		}

		// 查找Gemini原生格式的usageMetadata字段
		if usageMetadata, ok := chunkData["usageMetadata"].(map[string]interface{}); ok {
			if tokens, ok := usageMetadata["totalTokenCount"].(float64); ok {
				totalTokens = int(tokens)
				log.Printf("Found Gemini tokens in stream: %d", totalTokens)
				break // 找到token统计就退出
			}
		}

		// 查找Anthropic格式的usage字段
		if usage, ok := chunkData["usage"].(map[string]interface{}); ok {
			if inputTokens, ok1 := usage["input_tokens"].(float64); ok1 {
				if outputTokens, ok2 := usage["output_tokens"].(float64); ok2 {
					totalTokens = int(inputTokens + outputTokens)
					log.Printf("Found Anthropic tokens in stream: %d", totalTokens)
					break
				}
			}
		}
	}

	if totalTokens == 0 {
		log.Printf("No tokens found in stream response, response length: %d", len(streamBody))
	}

	return totalTokens
}

// estimateTokensFromResponse 备用方法：基于响应内容估算token数量
func (r *RequestLogger) estimateTokensFromResponse(responseBody string) int {
	if responseBody == "" {
		return 0
	}

	// 尝试从响应中提取文本内容进行估算
	var totalText strings.Builder

	// 首先尝试解析为JSON并提取文本内容
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(responseBody), &response); err == nil {
		// 提取choices中的content
		if choices, ok := response["choices"].([]interface{}); ok {
			for _, choice := range choices {
				if choiceMap, ok := choice.(map[string]interface{}); ok {
					// 非流式响应的message.content
					if message, ok := choiceMap["message"].(map[string]interface{}); ok {
						if content, ok := message["content"].(string); ok {
							totalText.WriteString(content)
						}
					}
					// 流式响应的delta.content
					if delta, ok := choiceMap["delta"].(map[string]interface{}); ok {
						if content, ok := delta["content"].(string); ok {
							totalText.WriteString(content)
						}
					}
				}
			}
		}
	} else {
		// 如果不是JSON，可能是流式响应，尝试提取data行中的内容
		lines := strings.Split(responseBody, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data: ") && !strings.Contains(line, "[DONE]") {
				dataContent := strings.TrimPrefix(line, "data: ")

				// 跳过处理状态信息
				if strings.Contains(dataContent, "OPENROUTER PROCESSING") ||
					strings.Contains(dataContent, "PROCESSING") {
					continue
				}

				var chunkData map[string]interface{}
				if err := json.Unmarshal([]byte(dataContent), &chunkData); err == nil {
					if choices, ok := chunkData["choices"].([]interface{}); ok {
						for _, choice := range choices {
							if choiceMap, ok := choice.(map[string]interface{}); ok {
								if delta, ok := choiceMap["delta"].(map[string]interface{}); ok {
									if content, ok := delta["content"].(string); ok {
										totalText.WriteString(content)
									}
								}
								// 也检查message.content（某些情况下可能存在）
								if message, ok := choiceMap["message"].(map[string]interface{}); ok {
									if content, ok := message["content"].(string); ok {
										totalText.WriteString(content)
									}
								}
							}
						}
					}
				} else {
					// 如果JSON解析失败，记录调试信息
					log.Printf("Failed to parse chunk for token estimation: %s", dataContent[:min(100, len(dataContent))])
				}
			}
		}
	}

	// 基于提取的文本内容估算token数
	text := totalText.String()
	if text == "" {
		return 0
	}

	estimatedTokens := r.estimateTokensFromTextWithModel(text, "gpt-3.5-turbo")
	log.Printf("Extracted text length: %d characters, estimated tokens: %d", len(text), estimatedTokens)
	return estimatedTokens
}

// estimateTokensFromResponseWithModel 备用方法：基于响应内容估算token数量（支持指定模型）
func (r *RequestLogger) estimateTokensFromResponseWithModel(responseBody, model string) int {
	if responseBody == "" {
		return 0
	}

	// 尝试从响应中提取文本内容进行估算
	var totalText strings.Builder

	// 首先尝试解析为JSON并提取文本内容
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(responseBody), &response); err == nil {
		// 提取choices中的content
		if choices, ok := response["choices"].([]interface{}); ok {
			for _, choice := range choices {
				if choiceMap, ok := choice.(map[string]interface{}); ok {
					// 非流式响应的message.content
					if message, ok := choiceMap["message"].(map[string]interface{}); ok {
						if content, ok := message["content"].(string); ok {
							totalText.WriteString(content)
						}
					}
					// 流式响应的delta.content
					if delta, ok := choiceMap["delta"].(map[string]interface{}); ok {
						if content, ok := delta["content"].(string); ok {
							totalText.WriteString(content)
						}
					}
				}
			}
		}
	} else {
		// 如果不是JSON，可能是流式响应，尝试提取data行中的内容
		lines := strings.Split(responseBody, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data: ") && !strings.Contains(line, "[DONE]") {
				dataContent := strings.TrimPrefix(line, "data: ")

				// 跳过处理状态信息
				if strings.Contains(dataContent, "OPENROUTER PROCESSING") ||
					strings.Contains(dataContent, "PROCESSING") {
					continue
				}

				var chunkData map[string]interface{}
				if err := json.Unmarshal([]byte(dataContent), &chunkData); err == nil {
					if choices, ok := chunkData["choices"].([]interface{}); ok {
						for _, choice := range choices {
							if choiceMap, ok := choice.(map[string]interface{}); ok {
								if delta, ok := choiceMap["delta"].(map[string]interface{}); ok {
									if content, ok := delta["content"].(string); ok {
										totalText.WriteString(content)
									}
								}
								// 也检查message.content（某些情况下可能存在）
								if message, ok := choiceMap["message"].(map[string]interface{}); ok {
									if content, ok := message["content"].(string); ok {
										totalText.WriteString(content)
									}
								}
							}
						}
					}
				} else {
					// 如果JSON解析失败，记录调试信息
					log.Printf("Failed to parse chunk for token estimation: %s", dataContent[:min(100, len(dataContent))])
				}
			}
		}
	}

	// 基于提取的文本内容估算token数
	text := totalText.String()
	if text == "" {
		return 0
	}

	estimatedTokens := r.estimateTokensFromTextWithModel(text, model)
	log.Printf("Extracted text length: %d characters, estimated tokens for model %s: %d", len(text), model, estimatedTokens)
	return estimatedTokens
}

// estimateTokensFromTextWithModel 基于文本内容估算token数量（支持指定模型）
func (r *RequestLogger) estimateTokensFromTextWithModel(text, model string) int {
	if text == "" {
		return 0
	}

	// 移除多余的空白字符
	text = strings.TrimSpace(text)

	// 首先尝试使用tiktoken进行精确计算
	if tokens := r.calculateTokensWithTiktoken(text, model); tokens > 0 {
		log.Printf("Using tiktoken for model %s: %d tokens for %d characters", model, tokens, len([]rune(text)))
		return tokens
	}

	// 如果tiktoken失败，使用备用估算方法
	log.Printf("Tiktoken failed for model %s, using fallback estimation method", model)
	return r.estimateTokensWithFallback(text)
}

// estimateTokensFromRequestAndResponse 基于请求和响应内容综合估算token数量（兼容性方法）
func (r *RequestLogger) estimateTokensFromRequestAndResponse(requestBody, responseBody string) int {
	return r.estimateTokensFromRequestAndResponseWithModel(requestBody, responseBody, "gpt-3.5-turbo")
}

// estimateTokensFromRequestAndResponseWithModel 基于请求和响应内容综合估算token数量（支持指定模型）
func (r *RequestLogger) estimateTokensFromRequestAndResponseWithModel(requestBody, responseBody, model string) int {
	var totalTokens int

	// 估算请求中的token数（输入token）
	inputTokens := 0
	if requestBody != "" {
		inputTokens = r.estimateTokensFromRequestWithModel(requestBody, model)
		totalTokens += inputTokens
		log.Printf("Estimated input tokens for model %s: %d", model, inputTokens)
	}

	// 估算响应中的token数（输出token）
	outputTokens := 0
	if responseBody != "" {
		outputTokens = r.estimateTokensFromResponseWithModel(responseBody, model)
		totalTokens += outputTokens
		log.Printf("Estimated output tokens for model %s: %d", model, outputTokens)
	}

	// 添加系统开销估算（通常占总token的5-10%）
	systemOverhead := int(float64(totalTokens) * 0.1)
	totalTokens += systemOverhead

	log.Printf("Token estimation breakdown for model %s: input=%d, output=%d, overhead=%d, total=%d",
		model, inputTokens, outputTokens, systemOverhead, totalTokens)

	return totalTokens
}

// estimateTokensFromRequest 从请求体中估算输入token数量（兼容性方法）
func (r *RequestLogger) estimateTokensFromRequest(requestBody string) int {
	return r.estimateTokensFromRequestWithModel(requestBody, "gpt-3.5-turbo")
}

// estimateTokensFromRequestWithModel 从请求体中估算输入token数量（支持指定模型）
func (r *RequestLogger) estimateTokensFromRequestWithModel(requestBody, model string) int {
	if requestBody == "" {
		return 0
	}

	var totalText strings.Builder

	// 解析请求JSON，提取messages中的内容
	var request map[string]interface{}
	if err := json.Unmarshal([]byte(requestBody), &request); err == nil {
		if messages, ok := request["messages"].([]interface{}); ok {
			for _, message := range messages {
				if msgMap, ok := message.(map[string]interface{}); ok {
					// 提取content字段
					if content, ok := msgMap["content"].(string); ok {
						totalText.WriteString(content)
						totalText.WriteString(" ") // 添加分隔符
					}
					// 处理content为数组的情况（多模态内容）
					if contentArray, ok := msgMap["content"].([]interface{}); ok {
						for _, contentItem := range contentArray {
							if contentMap, ok := contentItem.(map[string]interface{}); ok {
								if text, ok := contentMap["text"].(string); ok {
									totalText.WriteString(text)
									totalText.WriteString(" ")
								}
							}
						}
					}
				}
			}
		}

		// 也考虑系统提示词等其他字段
		if systemPrompt, ok := request["system"].(string); ok {
			totalText.WriteString(systemPrompt)
			totalText.WriteString(" ")
		}
	}

	text := strings.TrimSpace(totalText.String())
	if text == "" {
		return 0
	}

	inputTokens := r.estimateTokensFromTextWithModel(text, model)
	log.Printf("Request text length: %d characters, estimated input tokens for model %s: %d", len([]rune(text)), model, inputTokens)
	return inputTokens
}

// estimateTokensFromText 基于文本内容估算token数量
func (r *RequestLogger) estimateTokensFromText(text string) int {
	if text == "" {
		return 0
	}

	// 移除多余的空白字符
	text = strings.TrimSpace(text)

	// 首先尝试使用tiktoken进行精确计算
	if tokens := r.calculateTokensWithTiktoken(text, "gpt-3.5-turbo"); tokens > 0 {
		log.Printf("Using tiktoken for accurate token count: %d tokens for %d characters", tokens, len([]rune(text)))
		return tokens
	}

	// 如果tiktoken失败，使用备用估算方法
	log.Printf("Tiktoken failed, using fallback estimation method")
	return r.estimateTokensWithFallback(text)
}

// calculateTokensWithTiktoken 使用tiktoken库进行精确的token计算
func (r *RequestLogger) calculateTokensWithTiktoken(text, model string) int {
	if text == "" {
		return 0
	}

	// 尝试获取指定模型的编码器
	enc, err := tiktoken.EncodingForModel(model)
	if err != nil {
		// 如果指定模型失败，尝试使用通用编码器
		enc, err = tiktoken.GetEncoding("cl100k_base") // GPT-4和GPT-3.5-turbo使用的编码
		if err != nil {
			log.Printf("Failed to get tiktoken encoding: %v", err)
			return 0
		}
	}

	// 编码文本并计算token数
	tokens := enc.Encode(text, nil, nil)
	return len(tokens)
}

// estimateTokensWithFallback 备用的token估算方法
func (r *RequestLogger) estimateTokensWithFallback(text string) int {
	if text == "" {
		return 0
	}

	// 改进的token估算规则：
	// 1. 中文字符：每个字符约等于1个token（更准确的估算）
	// 2. 英文单词：平均每个单词约1.3个token
	// 3. 数字和标点：按字符数/4计算

	var tokenCount float64

	// 统计中文字符数
	chineseCount := 0
	englishWordCount := 0
	otherCharCount := 0

	// 分析文本内容
	runes := []rune(text)
	inWord := false

	for _, r := range runes {
		if r >= 0x4e00 && r <= 0x9fff {
			// 中文字符
			chineseCount++
			inWord = false
		} else if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			// 英文字母
			if !inWord {
				englishWordCount++
				inWord = true
			}
		} else {
			// 其他字符（数字、标点、空格等）
			otherCharCount++
			inWord = false
		}
	}

	// 估算token数
	// 中文字符：每个字符约1个token
	tokenCount += float64(chineseCount) * 1.0

	// 英文单词：每个单词约1.3个token
	tokenCount += float64(englishWordCount) * 1.3

	// 其他字符：每4个字符约1个token
	tokenCount += float64(otherCharCount) / 4.0

	// 确保至少返回1个token（如果有内容的话）
	if tokenCount < 1 && len(runes) > 0 {
		tokenCount = 1
	}

	result := int(tokenCount + 0.5) // 四舍五入

	// 调试信息
	log.Printf("Fallback token estimation: %d Chinese chars, %d English words, %d other chars -> %d tokens",
		chineseCount, englishWordCount, otherCharCount, result)

	return result
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetClientIP 获取客户端真实IP地址
func GetClientIP(c *gin.Context) string {
	// 优先从X-Forwarded-For头获取
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For可能包含多个IP，取第一个
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// 从X-Real-IP头获取
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 从RemoteAddr获取
	if ip := c.ClientIP(); ip != "" {
		return ip
	}

	// 最后从Request.RemoteAddr获取
	if remoteAddr := c.Request.RemoteAddr; remoteAddr != "" {
		if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
			return remoteAddr[:idx]
		}
		return remoteAddr
	}

	return "unknown"
}

// extractToolCallInfo 从请求和响应中提取工具调用信息
func (r *RequestLogger) extractToolCallInfo(requestBody, responseBody string) (bool, int, string) {
	requestHasTools := false
	toolCallsCountFromResponse := 0
	var toolNames []string

	// 从请求中检查是否包含工具定义
	if requestBody != "" {
		var request map[string]interface{}
		if err := json.Unmarshal([]byte(requestBody), &request); err == nil {
			// 检查tools字段
			if tools, ok := request["tools"].([]interface{}); ok && len(tools) > 0 {
				requestHasTools = true
				for _, tool := range tools {
					if toolMap, ok := tool.(map[string]interface{}); ok {
						if function, ok := toolMap["function"].(map[string]interface{}); ok {
							if name, ok := function["name"].(string); ok {
								if name == "" {
									continue
								}
								toolNames = append(toolNames, name)
							}
						}
					}
				}
			}
		}
	}

	// 从响应中检查实际的工具调用
	if responseBody != "" {
		// 尝试解析非流式响应
		var response map[string]interface{}
		if err := json.Unmarshal([]byte(responseBody), &response); err == nil {
			if choices, ok := response["choices"].([]interface{}); ok {
				for _, choice := range choices {
					if choiceMap, ok := choice.(map[string]interface{}); ok {
						if message, ok := choiceMap["message"].(map[string]interface{}); ok {
							if toolCalls, ok := message["tool_calls"].([]interface{}); ok {
								toolCallsCountFromResponse += len(toolCalls)
								// 提取实际调用的工具名称
								for _, toolCall := range toolCalls {
									if tcMap, ok := toolCall.(map[string]interface{}); ok {
										if function, ok := tcMap["function"].(map[string]interface{}); ok {
											if name, ok := function["name"].(string); ok {
												if name == "" {
													continue
												}
												// 避免重复添加工具名称
												found := false
												for _, existingName := range toolNames {
													if existingName == name {
														found = true
														break
													}
												}
												if !found {
													toolNames = append(toolNames, name)
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		} else {
			// 尝试解析流式响应
			toolCallsCountFromResponse += r.extractToolCallsFromStream(
				responseBody,
				&toolNames,
			)
		}
	}

	hasToolCalls := requestHasTools || toolCallsCountFromResponse > 0
	toolCallsCount := toolCallsCountFromResponse

	// 将工具名称列表转换为逗号分隔的字符串
	toolNamesStr := strings.Join(toolNames, ",")

	if toolCallsCount > 0 {
		log.Printf("Detected tool calls: count=%d, tools=%s", toolCallsCount, toolNamesStr)
	} else if requestHasTools && toolNamesStr != "" {
		log.Printf("Detected tools definition: tools=%s", toolNamesStr)
	}

	return hasToolCalls, toolCallsCount, toolNamesStr
}

// extractToolCallsFromStream 从流式响应中提取工具调用信息
func (r *RequestLogger) extractToolCallsFromStream(streamBody string, toolNames *[]string) int {
	if streamBody == "" {
		return 0
	}

	toolCallsCount := 0
	lines := strings.Split(streamBody, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过非数据行
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		dataStr := strings.TrimPrefix(line, "data: ")

		// 跳过[DONE]标记、空行和处理状态信息
		if dataStr == "[DONE]" || dataStr == "" ||
			strings.Contains(dataStr, "OPENROUTER PROCESSING") ||
			strings.Contains(dataStr, "PROCESSING") {
			continue
		}

		// 尝试解析JSON数据
		var chunkData map[string]interface{}
		if err := json.Unmarshal([]byte(dataStr), &chunkData); err != nil {
			continue
		}

		// 查找choices中的tool_calls
		if choices, ok := chunkData["choices"].([]interface{}); ok {
			for _, choice := range choices {
				if choiceMap, ok := choice.(map[string]interface{}); ok {
					// 检查delta中的tool_calls
					if delta, ok := choiceMap["delta"].(map[string]interface{}); ok {
						if toolCalls, ok := delta["tool_calls"].([]interface{}); ok {
							toolCallsCount += len(toolCalls)
							// 提取工具名称
							for _, toolCall := range toolCalls {
								if tcMap, ok := toolCall.(map[string]interface{}); ok {
									if function, ok := tcMap["function"].(map[string]interface{}); ok {
										if name, ok := function["name"].(string); ok && name != "" {
											// 避免重复添加工具名称
											found := false
											for _, existingName := range *toolNames {
												if existingName == name {
													found = true
													break
												}
											}
											if !found {
												*toolNames = append(*toolNames, name)
											}
										}
									}
								}
							}
						}
					}
					// 也检查message中的tool_calls（某些情况下可能存在）
					if message, ok := choiceMap["message"].(map[string]interface{}); ok {
						if toolCalls, ok := message["tool_calls"].([]interface{}); ok {
							toolCallsCount += len(toolCalls)
							// 提取工具名称
							for _, toolCall := range toolCalls {
								if tcMap, ok := toolCall.(map[string]interface{}); ok {
									if function, ok := tcMap["function"].(map[string]interface{}); ok {
										if name, ok := function["name"].(string); ok && name != "" {
											// 避免重复添加工具名称
											found := false
											for _, existingName := range *toolNames {
												if existingName == name {
													found = true
													break
												}
											}
											if !found {
												*toolNames = append(*toolNames, name)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return toolCallsCount
}
