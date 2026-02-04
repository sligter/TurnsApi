package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"turnsapi/internal"
	"turnsapi/internal/database"
	"turnsapi/internal/keymanager"
	"turnsapi/internal/logger"
	"turnsapi/internal/providers"
	"turnsapi/internal/proxykey"
	"turnsapi/internal/ratelimit"
	"turnsapi/internal/router"

	"github.com/gin-gonic/gin"
)

// MultiProviderProxy 多提供商代理
type MultiProviderProxy struct {
	config          *internal.Config
	keyManager      *keymanager.MultiGroupKeyManager
	proxyKeyManager *proxykey.Manager
	providerManager *providers.ProviderManager
	providerRouter  *router.ProviderRouter
	requestLogger   *logger.RequestLogger
	rpmLimiter      *ratelimit.RPMLimiter
	database        *database.GroupsDB
}

func hasHeaderKey(m map[string]string, key string) bool {
	for k := range m {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

func (p *MultiProviderProxy) applyForwardHeaders(c *gin.Context, cfg *providers.ProviderConfig) {
	if c == nil || cfg == nil {
		return
	}
	if cfg.Headers == nil {
		cfg.Headers = make(map[string]string)
	}

	// Forward a small allowlist of non-sensitive headers that some OpenAI-compatible gateways require.
	// Prefer incoming `HTTP-Referer`, fallback to standard `Referer`.
	if !hasHeaderKey(cfg.Headers, "HTTP-Referer") {
		ref := strings.TrimSpace(c.GetHeader("HTTP-Referer"))
		if ref == "" {
			ref = strings.TrimSpace(c.GetHeader("Referer"))
		}
		if ref != "" {
			cfg.Headers["HTTP-Referer"] = ref
		}
	}

	if !hasHeaderKey(cfg.Headers, "Referer") {
		if ref := strings.TrimSpace(c.GetHeader("Referer")); ref != "" {
			cfg.Headers["Referer"] = ref
		}
	}

	if !hasHeaderKey(cfg.Headers, "Origin") {
		if origin := strings.TrimSpace(c.GetHeader("Origin")); origin != "" {
			cfg.Headers["Origin"] = origin
		}
	}

	if !hasHeaderKey(cfg.Headers, "X-Title") {
		if v := strings.TrimSpace(c.GetHeader("X-Title")); v != "" {
			cfg.Headers["X-Title"] = v
		}
	}

	// Browser-like headers (optional; forwarded only when present).
	for _, h := range []string{
		"Accept",
		"Accept-Language",
		"Priority",
		"Sec-CH-UA",
		"Sec-CH-UA-Mobile",
		"Sec-CH-UA-Platform",
		"Sec-Fetch-Dest",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Site",
		"User-Agent",
	} {
		if hasHeaderKey(cfg.Headers, h) {
			continue
		}
		if v := strings.TrimSpace(c.GetHeader(h)); v != "" {
			cfg.Headers[h] = v
		}
	}
}

// NewMultiProviderProxy 创建多提供商代理
func NewMultiProviderProxy(
	config *internal.Config,
	keyManager *keymanager.MultiGroupKeyManager,
	requestLogger *logger.RequestLogger,
) *MultiProviderProxy {
	// 创建提供商管理器
	factory := providers.NewDefaultProviderFactory()
	providerManager := providers.NewProviderManager(factory)

	// 创建提供商路由器
	providerRouter := router.NewProviderRouter(config, providerManager)

	// 创建RPM限制器并初始化分组限制
	rpmLimiter := ratelimit.NewRPMLimiter()
	if config.UserGroups != nil {
		for groupID, group := range config.UserGroups {
			if group.RPMLimit > 0 {
				rpmLimiter.SetLimit(groupID, group.RPMLimit)
			}
		}
	}

	return &MultiProviderProxy{
		config:          config,
		keyManager:      keyManager,
		providerManager: providerManager,
		providerRouter:  providerRouter,
		requestLogger:   requestLogger,
		rpmLimiter:      rpmLimiter,
	}
}

// NewMultiProviderProxyWithProxyKey 创建带代理密钥管理器的多提供商代理
func NewMultiProviderProxyWithProxyKey(
	config *internal.Config,
	keyManager *keymanager.MultiGroupKeyManager,
	proxyKeyManager *proxykey.Manager,
	requestLogger *logger.RequestLogger,
) *MultiProviderProxy {
	factory := providers.NewDefaultProviderFactory()
	providerManager := providers.NewProviderManager(factory)
	providerRouter := router.NewProviderRouterWithProxyKey(config, providerManager, proxyKeyManager)

	// 创建RPM限制器
	rpmLimiter := ratelimit.NewRPMLimiter()

	// 为每个分组设置RPM限制
	for groupID, group := range config.UserGroups {
		if group.RPMLimit > 0 {
			rpmLimiter.SetLimit(groupID, group.RPMLimit)
		}
	}

	// 初始化数据库连接
	groupsDB, err := database.NewGroupsDBWithConfig(config.Database)
	if err != nil {
		log.Printf("Failed to initialize database for proxy: %v", err)
	}

	return &MultiProviderProxy{
		config:          config,
		keyManager:      keyManager,
		proxyKeyManager: proxyKeyManager,
		providerManager: providerManager,
		providerRouter:  providerRouter,
		requestLogger:   requestLogger,
		rpmLimiter:      rpmLimiter,
		database:        groupsDB,
	}
}

// RemoveProvider 从提供商管理器中移除分组
func (mp *MultiProviderProxy) RemoveProvider(groupID string) {
	mp.providerManager.RemoveProvider(groupID)
	// 同时移除RPM限制
	mp.rpmLimiter.RemoveLimit(groupID)
}

// UpdateRPMLimit 更新分组的RPM限制
func (mp *MultiProviderProxy) UpdateRPMLimit(groupID string, limit int) {
	mp.rpmLimiter.SetLimit(groupID, limit)
}

// GetRPMStats 获取RPM统计信息
func (mp *MultiProviderProxy) GetRPMStats() map[string]map[string]int {
	return mp.rpmLimiter.GetAllStats()
}

// shouldUseNativeResponse 检查是否应该使用原生响应格式
func (p *MultiProviderProxy) shouldUseNativeResponse(groupID string, c *gin.Context) bool {
	// 检查是否强制使用原生响应
	if forceNative, exists := c.Get("force_native_response"); exists {
		if force, ok := forceNative.(bool); ok && force {
			return true
		}
	}

	// 检查分组配置
	if p.config.UserGroups == nil {
		return false
	}

	group, exists := p.config.UserGroups[groupID]
	if !exists {
		return false
	}

	return group.UseNativeResponse
}

// getNativeResponse 获取提供商的原生响应格式
func (p *MultiProviderProxy) getNativeResponse(provider providers.Provider, standardResponse *providers.ChatCompletionResponse) (interface{}, error) {
	// 根据提供商类型返回相应的原生格式
	switch provider.GetProviderType() {
	case "gemini":
		return p.convertToGeminiNativeResponse(standardResponse)
	case "anthropic":
		return p.convertToAnthropicNativeResponse(standardResponse)
	case "openai", "azure_openai":
		// OpenAI格式本身就是标准格式，直接返回
		return standardResponse, nil
	default:
		// 对于未知提供商，返回标准格式
		return standardResponse, nil
	}
}

// convertToGeminiNativeResponse 转换为Gemini原生响应格式
func (p *MultiProviderProxy) convertToGeminiNativeResponse(response *providers.ChatCompletionResponse) (interface{}, error) {
	// 构造Gemini原生响应格式
	nativeResponse := map[string]interface{}{
		"candidates": []map[string]interface{}{
			{
				"content": map[string]interface{}{
					"parts": []map[string]interface{}{
						{
							"text": response.Choices[0].Message.Content,
						},
					},
					"role": "model",
				},
				"finishReason": response.Choices[0].FinishReason,
				"index":        response.Choices[0].Index,
			},
		},
		"usageMetadata": map[string]interface{}{
			"promptTokenCount":     response.Usage.PromptTokens,
			"candidatesTokenCount": response.Usage.CompletionTokens,
			"totalTokenCount":      response.Usage.TotalTokens,
		},
	}

	return nativeResponse, nil
}

// convertToAnthropicNativeResponse 转换为Anthropic原生响应格式
func (p *MultiProviderProxy) convertToAnthropicNativeResponse(response *providers.ChatCompletionResponse) (interface{}, error) {
	// 构造Anthropic原生响应格式
	nativeResponse := map[string]interface{}{
		"id":   response.ID,
		"type": "message",
		"role": "assistant",
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": response.Choices[0].Message.Content,
			},
		},
		"model":       response.Model,
		"stop_reason": response.Choices[0].FinishReason,
		"usage": map[string]interface{}{
			"input_tokens":  response.Usage.PromptTokens,
			"output_tokens": response.Usage.CompletionTokens,
		},
	}

	return nativeResponse, nil
}

// HandleChatCompletion 处理聊天完成请求
func (p *MultiProviderProxy) HandleChatCompletion(c *gin.Context) {
	startTime := time.Now()

	// 解析请求 - 优先从上下文获取预设请求
	var req providers.ChatCompletionRequest
	if presetReq, exists := c.Get("chat_request"); exists {
		if chatReq, ok := presetReq.(*providers.ChatCompletionRequest); ok {
			req = *chatReq
		} else {
			log.Printf("Invalid preset request type")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": gin.H{
					"message": "Internal server error",
					"type":    "internal_error",
				},
			})
			return
		}
	} else {
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			log.Printf("Failed to read request body: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": gin.H{
					"message": "Invalid request format",
					"type":    "invalid_request_error",
					"code":    "invalid_json",
				},
			})
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		var raw map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &raw); err != nil {
			log.Printf("Failed to parse request json: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": gin.H{
					"message": "Invalid request format",
					"type":    "invalid_request_error",
					"code":    "invalid_json",
				},
			})
			return
		}

		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			log.Printf("Failed to parse request: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": gin.H{
					"message": "Invalid request format",
					"type":    "invalid_request_error",
					"code":    "invalid_json",
				},
			})
			return
		}

		if len(raw) > 0 {
			knownKeys := map[string]struct{}{
				"model":               {},
				"messages":            {},
				"temperature":         {},
				"max_tokens":          {},
				"stream":              {},
				"top_p":               {},
				"stop":                {},
				"tools":               {},
				"tool_choice":         {},
				"parallel_tool_calls": {},
			}

			extra := make(map[string]interface{})
			for k, v := range raw {
				if _, ok := knownKeys[k]; ok {
					continue
				}
				extra[k] = v
			}

			if len(extra) > 0 {
				req.Extra = extra
			}
		}
	}

	// 检查必需字段
	if req.Model == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": "Model is required",
				"type":    "invalid_request_error",
				"code":    "missing_model",
			},
		})
		return
	}

	if len(req.Messages) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": "Messages are required",
				"type":    "invalid_request_error",
				"code":    "missing_messages",
			},
		})
		return
	}

	// 获取代理密钥信息以检查权限
	var allowedGroups []string
	var proxyKeyID string
	if keyInfo, exists := c.Get("key_info"); exists {
		if proxyKey, ok := keyInfo.(*logger.ProxyKey); ok {
			allowedGroups = proxyKey.AllowedGroups
			proxyKeyID = proxyKey.ID
		}
	}

	// 路由到合适的提供商
	routeReq := &router.RouteRequest{
		Model:         req.Model,
		AllowedGroups: allowedGroups, // 传递代理密钥的权限限制
		ProxyKeyID:    proxyKeyID,    // 传递代理密钥ID用于分组选择
	}

	// 检查是否有显式指定的提供商分组
	if providerGroup := c.GetHeader("X-Provider-Group"); providerGroup != "" {
		routeReq.ProviderGroup = providerGroup
	}

	// 检查是否强制指定提供商类型
	if targetProvider, exists := c.Get("target_provider"); exists {
		if providerType, ok := targetProvider.(string); ok {
			routeReq.ForceProviderType = providerType
		}
	}

	// 使用智能路由重试机制
	success := p.handleRequestWithRetry(c, &req, routeReq, startTime)
	if !success {
		// 如果所有重试都失败了，返回错误
		c.JSON(http.StatusBadGateway, gin.H{
			"error": gin.H{
				"message": "All provider groups failed to process the request",
				"type":    "service_unavailable",
				"code":    "all_providers_failed",
			},
		})
	}
}

// handleRequestWithRetry 处理请求并支持智能重试
func (p *MultiProviderProxy) handleRequestWithRetry(
	c *gin.Context,
	req *providers.ChatCompletionRequest,
	routeReq *router.RouteRequest,
	startTime time.Time,
) bool {
	// 智能故障转移：优先在分组间轮换重试，最多重试3个密钥
	return p.handleRequestWithSmartFailover(c, req, routeReq, startTime)
}

// handleRequestWithSmartFailover 实现智能故障转移机制
// 新策略：优先在分组间轮换重试，最后再在分组内重试，最多重试3个密钥即停止
func (p *MultiProviderProxy) handleRequestWithSmartFailover(
	c *gin.Context,
	req *providers.ChatCompletionRequest,
	routeReq *router.RouteRequest,
	startTime time.Time,
) bool {
	// 获取支持该模型的所有分组
	candidateGroups := p.providerRouter.GetGroupsForModel(req.Model, routeReq.AllowedGroups)
	if len(candidateGroups) == 0 {
		log.Printf("没有可用分组支持模型 %s", req.Model)
		return false
	}

	log.Printf("开始分组间轮换重试，支持模型 %s 的分组: %v", req.Model, candidateGroups)

	// 使用新的分组间轮换重试策略，最多重试3个密钥
	return p.tryGroupRotationWithLimit(c, req, routeReq, candidateGroups, startTime, 3)
}

// tryGroupRotationWithLimit 分组间轮换重试，最多重试指定数量的密钥
func (p *MultiProviderProxy) tryGroupRotationWithLimit(
	c *gin.Context,
	req *providers.ChatCompletionRequest,
	routeReq *router.RouteRequest,
	candidateGroups []string,
	startTime time.Time,
	maxRetries int,
) bool {
	// 为每个分组准备密钥列表
	groupKeys := make(map[string][]string)
	totalAvailableKeys := 0

	for _, groupID := range candidateGroups {
		// 检查RPM限制
		if !p.rpmLimiter.Allow(groupID) {
			log.Printf("分组 %s 超出RPM限制，跳过", groupID)
			continue
		}

		// 获取分组的所有可用密钥状态
		groupStatus, exists := p.keyManager.GetGroupStatus(groupID)
		if !exists {
			log.Printf("分组 %s 不存在或未启用，跳过", groupID)
			continue
		}

		groupInfo := groupStatus.(map[string]interface{})
		keyStatuses, ok := groupInfo["key_statuses"].(map[string]*keymanager.KeyStatus)
		if !ok {
			log.Printf("无法获取分组 %s 的密钥状态，跳过", groupID)
			continue
		}

		// 按优先级排序密钥：活跃且有效的密钥优先
		sortedKeys := p.sortKeysByPriority(keyStatuses)
		if len(sortedKeys) > 0 {
			groupKeys[groupID] = sortedKeys
			totalAvailableKeys += len(sortedKeys)

			// 显示密钥详细信息
			keyDetails := make([]string, len(sortedKeys))
			for i, key := range sortedKeys {
				keyDetails[i] = p.maskKey(key)
			}
			log.Printf("分组 %s 有 %d 个可用密钥: [%s]", groupID, len(sortedKeys), strings.Join(keyDetails, ", "))
		} else {
			log.Printf("分组 %s 没有可用密钥，跳过（总密钥数: %d）", groupID, len(keyStatuses))
		}
	}

	if len(groupKeys) == 0 {
		log.Printf("没有可用的分组和密钥")
		return false
	}

	// 获取实际可用的分组列表（有密钥的分组）
	availableGroups := make([]string, 0, len(groupKeys))
	for _, groupID := range candidateGroups {
		if _, exists := groupKeys[groupID]; exists {
			availableGroups = append(availableGroups, groupID)
		}
	}

	log.Printf("开始分组间轮换重试，候选分组: %v，可用分组: %v，总可用密钥: %d，最多重试 %d 个密钥",
		candidateGroups, availableGroups, totalAvailableKeys, maxRetries)

	// 分组间轮换重试逻辑
	retryCount := 0
	keyIndex := 0

	for retryCount < maxRetries {
		// 检查当前轮次是否还有可用密钥
		hasKeysInCurrentRound := false
		for _, groupID := range availableGroups {
			if keys, exists := groupKeys[groupID]; exists && keyIndex < len(keys) {
				hasKeysInCurrentRound = true
				break
			}
		}

		if !hasKeysInCurrentRound {
			log.Printf("当前轮次 %d 没有任何分组有可用密钥，停止重试", keyIndex+1)
			break
		}

		// 轮换尝试每个可用分组的第keyIndex个密钥
		for _, groupID := range availableGroups {
			keys, exists := groupKeys[groupID]
			if !exists || keyIndex >= len(keys) {
				log.Printf("分组 %s 没有第 %d 个密钥，跳过", groupID, keyIndex+1)
				continue // 该分组没有更多密钥
			}

			apiKey := keys[keyIndex]
			retryCount++

			log.Printf("轮换重试第 %d/%d 次：尝试分组 %s 的第 %d 个密钥: %s",
				retryCount, maxRetries, groupID, keyIndex+1, p.maskKey(apiKey))

			// 为该分组创建路由请求
			groupRouteReq := &router.RouteRequest{
				Model:         req.Model,
				ProviderGroup: groupID,
				AllowedGroups: routeReq.AllowedGroups,
				ProxyKeyID:    routeReq.ProxyKeyID,
			}

			// 获取该分组的路由结果
			routeResult, err := p.providerRouter.RouteWithRetry(groupRouteReq)
			if err != nil {
				log.Printf("分组 %s 路由失败: %v，跳过该分组", groupID, err)
				continue
			}

			// 更新提供商配置中的API密钥
			p.providerRouter.UpdateProviderConfig(routeResult.ProviderConfig, apiKey)

			// Forward allowlisted request headers into provider headers (if not configured at group-level).
			p.applyForwardHeaders(c, routeResult.ProviderConfig)

			// 获取与该 API Key 对应的提供商实例（避免在并发场景下共享可变的 Config）
			if provider, err := p.providerManager.GetProvider(groupID, routeResult.ProviderConfig); err == nil {
				routeResult.Provider = provider
			} else {
				log.Printf("获取提供商实例失败: group=%s key=%s err=%v", groupID, p.maskKey(apiKey), err)
				continue
			}

			// 尝试处理请求（按分组强制覆盖 request_params；每次尝试都使用独立副本，避免跨分组污染）
			attemptReq := *req
			if req.Extra != nil {
				attemptReq.Extra = make(map[string]interface{}, len(req.Extra))
				for k, v := range req.Extra {
					attemptReq.Extra[k] = v
				}
			}
			attemptReq.ApplyRequestParams(routeResult.ProviderConfig.RequestParams)

			var success bool
			if attemptReq.Stream {
				success = p.handleStreamingRequest(c, &attemptReq, routeResult, apiKey, startTime)
			} else {
				success = p.handleNonStreamingRequest(c, &attemptReq, routeResult, apiKey, startTime)
			}

			if success {
				log.Printf("分组间轮换重试成功：分组 %s 密钥 %s", groupID, p.maskKey(apiKey))
				// 报告成功使用
				p.keyManager.ReportSuccess(groupID, apiKey)
				// 实时更新数据库状态
				p.updateKeyStatusInDatabase(groupID, apiKey, true, "")
				return true
			} else {
				log.Printf("分组间轮换重试失败：分组 %s 密钥 %s", groupID, p.maskKey(apiKey))
				// 报告使用失败
				p.keyManager.ReportError(groupID, apiKey, "请求失败")
				// 实时更新数据库状态
				p.updateKeyStatusInDatabase(groupID, apiKey, false, "请求失败")
			}

			// 如果已达到最大重试次数，停止
			if retryCount >= maxRetries {
				log.Printf("已达到最大重试次数 %d，停止重试", maxRetries)
				return false
			}
		}

		// 进入下一轮（尝试每个分组的下一个密钥）
		keyIndex++

		// 检查是否所有可用分组都没有更多密钥
		hasMoreKeys := false
		for _, groupID := range availableGroups {
			if keys, exists := groupKeys[groupID]; exists && keyIndex < len(keys) {
				hasMoreKeys = true
				break
			}
		}

		if !hasMoreKeys {
			log.Printf("所有可用分组都没有更多密钥可尝试，当前轮次: %d", keyIndex+1)
			break
		} else {
			log.Printf("进入下一轮重试，轮次: %d", keyIndex+1)
		}
	}

	log.Printf("分组间轮换重试完成，共尝试 %d 次，全部失败", retryCount)
	return false
}

// tryGroupWithAllKeys 在指定分组内尝试所有可用密钥（保留原函数用于其他地方调用）
func (p *MultiProviderProxy) tryGroupWithAllKeys(
	c *gin.Context,
	req *providers.ChatCompletionRequest,
	routeResult *router.RouteResult,
	startTime time.Time,
) bool {
	// 检查RPM限制
	if !p.rpmLimiter.Allow(routeResult.GroupID) {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": gin.H{
				"message": "Rate limit exceeded for the selected provider group",
				"type":    "rate_limit_error",
				"code":    "rpm_limit_exceeded",
			},
		})
		return false
	}

	// 获取分组的所有可用密钥状态
	groupStatus, exists := p.keyManager.GetGroupStatus(routeResult.GroupID)
	if !exists {
		log.Printf("分组 %s 不存在或未启用", routeResult.GroupID)
		return false
	}

	groupInfo := groupStatus.(map[string]interface{})
	keyStatuses, ok := groupInfo["key_statuses"].(map[string]*keymanager.KeyStatus)
	if !ok {
		log.Printf("无法获取分组 %s 的密钥状态", routeResult.GroupID)
		return false
	}

	// 按优先级排序密钥：活跃且有效的密钥优先
	sortedKeys := p.sortKeysByPriority(keyStatuses)

	log.Printf("分组 %s 内开始尝试 %d 个可用密钥", routeResult.GroupID, len(sortedKeys))

	// 依次尝试每个密钥
	for i, apiKey := range sortedKeys {
		log.Printf("尝试分组 %s 内第 %d/%d 个密钥: %s", routeResult.GroupID, i+1, len(sortedKeys), p.maskKey(apiKey))

		// 更新提供商配置中的API密钥
		p.providerRouter.UpdateProviderConfig(routeResult.ProviderConfig, apiKey)

		// Forward allowlisted request headers into provider headers (if not configured at group-level).
		p.applyForwardHeaders(c, routeResult.ProviderConfig)

		// 获取与该 API Key 对应的提供商实例（避免在并发场景下共享可变的 Config）
		if provider, err := p.providerManager.GetProvider(routeResult.GroupID, routeResult.ProviderConfig); err == nil {
			routeResult.Provider = provider
		} else {
			log.Printf("获取提供商实例失败: group=%s key=%s err=%v", routeResult.GroupID, p.maskKey(apiKey), err)
			continue
		}

		// 尝试处理请求（按分组强制覆盖 request_params；每次尝试都使用独立副本，避免跨分组污染）
		attemptReq := *req
		if req.Extra != nil {
			attemptReq.Extra = make(map[string]interface{}, len(req.Extra))
			for k, v := range req.Extra {
				attemptReq.Extra[k] = v
			}
		}
		attemptReq.ApplyRequestParams(routeResult.ProviderConfig.RequestParams)

		var success bool
		if attemptReq.Stream {
			success = p.handleStreamingRequest(c, &attemptReq, routeResult, apiKey, startTime)
		} else {
			success = p.handleNonStreamingRequest(c, &attemptReq, routeResult, apiKey, startTime)
		}

		if success {
			log.Printf("分组 %s 密钥 %s 请求成功", routeResult.GroupID, p.maskKey(apiKey))
			// 报告成功使用
			p.keyManager.ReportSuccess(routeResult.GroupID, apiKey)
			// 实时更新数据库状态
			p.updateKeyStatusInDatabase(routeResult.GroupID, apiKey, true, "")
			return true
		} else {
			log.Printf("分组 %s 密钥 %s 请求失败，尝试下一个", routeResult.GroupID, p.maskKey(apiKey))
			// 报告使用失败
			p.keyManager.ReportError(routeResult.GroupID, apiKey, "请求失败")
			// 实时更新数据库状态
			p.updateKeyStatusInDatabase(routeResult.GroupID, apiKey, false, "请求失败")
		}
	}

	log.Printf("分组 %s 内所有 %d 个密钥均已尝试，全部失败", routeResult.GroupID, len(sortedKeys))
	return false
}

// sortKeysByPriority 按优先级排序密钥
func (p *MultiProviderProxy) sortKeysByPriority(keyStatuses map[string]*keymanager.KeyStatus) []string {
	type keyPriority struct {
		key      string
		priority int
		lastUsed time.Time
	}

	var priorities []keyPriority
	now := time.Now()

	for key, status := range keyStatuses {
		if !status.IsActive {
			continue // 跳过非活跃密钥
		}

		// 跳过在限流冷却期内的密钥
		if !status.RateLimitUntil.IsZero() && now.Before(status.RateLimitUntil) {
			continue
		}

		priority := 0

		// 有效的密钥优先级更高
		if status.IsValid != nil && *status.IsValid {
			priority += 100
		}

		// 错误较少的密钥优先级更高
		priority -= int(status.ErrorCount) * 5

		// 限流次数较少的密钥优先级更高（但不如错误那么严重）
		priority -= int(status.RateLimitCount) * 2

		// 最近使用较少的密钥优先级更高（负载均衡）
		if time.Since(status.LastUsed) > time.Hour {
			priority += 10
		}

		// 最近没有被限流的密钥优先级更高
		if !status.LastRateLimitAt.IsZero() && time.Since(status.LastRateLimitAt) < 30*time.Minute {
			priority -= 20 // 最近30分钟内被限流过，降低优先级
		}

		priorities = append(priorities, keyPriority{
			key:      key,
			priority: priority,
			lastUsed: status.LastUsed,
		})
	}

	// 按优先级排序（高优先级在前）
	for i := 0; i < len(priorities)-1; i++ {
		for j := i + 1; j < len(priorities); j++ {
			if priorities[i].priority < priorities[j].priority {
				priorities[i], priorities[j] = priorities[j], priorities[i]
			}
		}
	}

	var sortedKeys []string
	for _, p := range priorities {
		sortedKeys = append(sortedKeys, p.key)
	}

	return sortedKeys
}

// updateKeyStatusInDatabase 实时更新数据库中的密钥状态
func (p *MultiProviderProxy) updateKeyStatusInDatabase(groupID, apiKey string, isSuccess bool, errorMsg string) {
	if p.database == nil {
		return
	}

	go func() {
		if err := p.database.UpdateAPIKeyUsageStats(groupID, apiKey, isSuccess, 0, errorMsg); err != nil {
			log.Printf("Failed to update key status in database: %v", err)
		}
	}()
}

// maskKey 掩码显示密钥
func (p *MultiProviderProxy) maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// handleNonStreamingRequestWithRetry 处理非流式请求（支持重试）
func (p *MultiProviderProxy) handleNonStreamingRequestWithRetry(
	c *gin.Context,
	req *providers.ChatCompletionRequest,
	routeResult *router.RouteResult,
	apiKey string,
	startTime time.Time,
) bool {
	return p.handleNonStreamingRequest(c, req, routeResult, apiKey, startTime)
}

// handleNonStreamingRequest 处理非流式请求
func (p *MultiProviderProxy) handleNonStreamingRequest(
	c *gin.Context,
	req *providers.ChatCompletionRequest,
	routeResult *router.RouteResult,
	apiKey string,
	startTime time.Time,
) bool {
	// 创建带有长超时的context，避免请求超时
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// 应用模型名称映射
	originalModel := req.Model
	req.Model = p.providerRouter.ResolveModelName(req.Model, routeResult.GroupID)

	// 输出详细的API调用信息用于调试
	log.Printf("🚀 发送API请求 - 分组: %s, 模型: %s, BaseURL: %s, ProviderType: %s",
		routeResult.GroupID, req.Model, routeResult.ProviderConfig.BaseURL, routeResult.ProviderConfig.ProviderType)
	log.Printf("📋 请求参数 - MaxTokens: %v, Temperature: %v, TopP: %v, Messages: %d",
		req.MaxTokens, req.Temperature, req.TopP, len(req.Messages))
	log.Printf("🔑 Headers - %v", routeResult.ProviderConfig.Headers)

	// 发送请求到提供商
	response, err := routeResult.Provider.ChatCompletion(ctx, req)

	// 恢复原始模型名称用于日志记录
	req.Model = originalModel
	if err != nil {
		log.Printf("Provider request failed: %v", err)
		p.keyManager.ReportError(routeResult.GroupID, apiKey, err.Error())

		// 记录错误日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			reqBody, _ := json.Marshal(req)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, routeResult.GroupID, apiKey, req.Model, string(reqBody), "", clientIP, 502, false, time.Since(startTime), err)
		}

		c.JSON(http.StatusBadGateway, gin.H{
			"error": gin.H{
				"message": "Failed to connect to provider",
				"type":    "connection_error",
				"code":    "upstream_error",
			},
		})
		return false
	}

	// 报告成功
	p.keyManager.ReportSuccess(routeResult.GroupID, apiKey)

	// 检查是否需要返回原生响应格式
	var finalResponse interface{} = response
	if p.shouldUseNativeResponse(routeResult.GroupID, c) {
		// 获取原生响应
		nativeResponse, err := p.getNativeResponse(routeResult.Provider, response)
		if err != nil {
			log.Printf("Failed to get native response: %v", err)
			// 如果获取原生响应失败，仍然返回标准格式
		} else {
			finalResponse = nativeResponse
		}
	}

	// 记录成功日志
	if p.requestLogger != nil {
		proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
		reqBody, _ := json.Marshal(req)
		respBody, _ := json.Marshal(finalResponse)
		clientIP := logger.GetClientIP(c)
		p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, routeResult.GroupID, apiKey, req.Model, string(reqBody), string(respBody), clientIP, 200, false, time.Since(startTime), nil)
	}

	// 返回响应
	c.JSON(http.StatusOK, finalResponse)
	return true
}

// handleStreamingRequestWithRetry 处理流式请求（支持重试）
func (p *MultiProviderProxy) handleStreamingRequestWithRetry(
	c *gin.Context,
	req *providers.ChatCompletionRequest,
	routeResult *router.RouteResult,
	apiKey string,
	startTime time.Time,
) bool {
	return p.handleStreamingRequest(c, req, routeResult, apiKey, startTime)
}

// handleStreamingRequest 处理流式请求
func (p *MultiProviderProxy) handleStreamingRequest(
	c *gin.Context,
	req *providers.ChatCompletionRequest,
	routeResult *router.RouteResult,
	apiKey string,
	startTime time.Time,
) bool {
	// 创建带有长超时的context，避免流式请求超时
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// 应用模型名称映射
	originalModel := req.Model
	req.Model = p.providerRouter.ResolveModelName(req.Model, routeResult.GroupID)

	// 设置流式响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")

	// 根据配置选择流式响应类型
	var streamChan <-chan providers.StreamResponse
	var err error

	if p.shouldUseNativeResponse(routeResult.GroupID, c) {
		// 使用原生格式流式响应
		streamChan, err = routeResult.Provider.ChatCompletionStreamNative(ctx, req)
	} else {
		// 使用标准格式流式响应
		streamChan, err = routeResult.Provider.ChatCompletionStream(ctx, req)
	}

	// 恢复原始模型名称用于日志记录
	req.Model = originalModel
	if err != nil {
		log.Printf("Provider streaming request failed: %v", err)
		p.keyManager.ReportError(routeResult.GroupID, apiKey, err.Error())

		// 记录错误日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			reqBody, _ := json.Marshal(req)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, routeResult.GroupID, apiKey, req.Model, string(reqBody), "", clientIP, 502, true, time.Since(startTime), err)
		}

		c.JSON(http.StatusBadGateway, gin.H{
			"error": gin.H{
				"message": "Failed to connect to provider",
				"type":    "connection_error",
				"code":    "upstream_error",
			},
		})
		return false
	}

	// 获取响应写入器
	w := c.Writer
	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("Streaming not supported")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Streaming not supported",
				"type":    "internal_error",
			},
		})
		return false
	}

	// 处理流式数据
	hasData := false
	responseBuffer := make([]byte, 0, 1024)
	lastChunks := make([][]byte, 0, 10) // 保存最后10个chunk用于token提取

	for streamResp := range streamChan {
		if streamResp.Error != nil {
			log.Printf("Stream error: %v", streamResp.Error)
			p.keyManager.ReportError(routeResult.GroupID, apiKey, streamResp.Error.Error())
			break
		}

		if len(streamResp.Data) > 0 {
			hasData = true
			w.Write(streamResp.Data)
			flusher.Flush()

			// 收集响应数据用于日志记录
			if len(responseBuffer) < 5000 { // 减少前面内容的记录
				responseBuffer = append(responseBuffer, streamResp.Data...)
			}

			// 保存最后的chunk，用于token提取
			lastChunks = append(lastChunks, streamResp.Data)
			if len(lastChunks) > 10 {
				lastChunks = lastChunks[1:] // 保持最后10个chunk
			}
		}

		if streamResp.Done {
			break
		}
	}

	// 将最后的chunk添加到响应缓冲区，确保包含token信息
	for _, chunk := range lastChunks {
		responseBuffer = append(responseBuffer, chunk...)
	}

	duration := time.Since(startTime)

	// 如果接收到数据，报告成功
	if hasData {
		p.keyManager.ReportSuccess(routeResult.GroupID, apiKey)

		// 记录成功日志
		if p.requestLogger != nil {
			proxyKeyName, proxyKeyID := p.getProxyKeyInfo(c)
			reqBody, _ := json.Marshal(req)
			clientIP := logger.GetClientIP(c)
			p.requestLogger.LogRequest(proxyKeyName, proxyKeyID, routeResult.GroupID, apiKey, req.Model, string(reqBody), string(responseBuffer), clientIP, 200, true, duration, nil)
		}
		return true
	}

	return false
}

// getProxyKeyInfo 获取代理密钥信息
func (p *MultiProviderProxy) getProxyKeyInfo(c *gin.Context) (string, string) {
	// 首先尝试从上下文中获取已设置的代理密钥信息
	if name, exists := c.Get("proxy_key_name"); exists {
		if nameStr, ok := name.(string); ok {
			if id, exists := c.Get("proxy_key_id"); exists {
				if idStr, ok := id.(string); ok {
					return nameStr, idStr
				}
			}
			return nameStr, "unknown"
		}
	}

	// 如果上下文中没有，尝试从key_info中获取
	if keyInfo, exists := c.Get("key_info"); exists {
		if proxyKey, ok := keyInfo.(*logger.ProxyKey); ok {
			// 设置到上下文中以便后续使用
			c.Set("proxy_key_name", proxyKey.Name)
			c.Set("proxy_key_id", proxyKey.ID)

			// 更新代理密钥使用次数
			if p.proxyKeyManager != nil {
				p.proxyKeyManager.UpdateUsage(proxyKey.Key)
			}

			return proxyKey.Name, proxyKey.ID
		}
	}

	return "Unknown", "unknown"
}

// GetProviderRouter 获取提供商路由器
func (p *MultiProviderProxy) GetProviderRouter() *router.ProviderRouter {
	return p.providerRouter
}

// GetProviderManager 获取提供商管理器
func (p *MultiProviderProxy) GetProviderManager() *providers.ProviderManager {
	return p.providerManager
}

// HandleModels 处理模型列表请求
func (p *MultiProviderProxy) HandleModels(c *gin.Context) {
	// 检查是否指定了特定的提供商分组
	groupID := c.Query("provider_group")

	if groupID != "" {
		// 获取特定分组的模型
		p.handleGroupModels(c, groupID)
	} else {
		// 获取所有分组的模型
		p.handleAllModels(c)
	}
}

// handleGroupModels 处理特定分组的模型列表请求
func (p *MultiProviderProxy) handleGroupModels(c *gin.Context, groupID string) {
	// 获取分组信息
	group, exists := p.providerRouter.GetGroupInfo(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"error": gin.H{
				"message": fmt.Sprintf("Provider group '%s' not found", groupID),
				"type":    "invalid_request_error",
				"code":    "group_not_found",
			},
		})
		return
	}

	if !group.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": fmt.Sprintf("Provider group '%s' is disabled", groupID),
				"type":    "invalid_request_error",
				"code":    "group_disabled",
			},
		})
		return
	}

	// 获取API密钥
	apiKey, err := p.keyManager.GetNextKeyForGroup(groupID)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": gin.H{
				"message": "No available API keys for this group",
				"type":    "service_unavailable",
				"code":    "no_api_keys",
			},
		})
		return
	}

	// 创建提供商配置
	providerConfig := &providers.ProviderConfig{
		BaseURL:         group.BaseURL,
		APIKey:          apiKey,
		Timeout:         group.Timeout,
		MaxRetries:      group.MaxRetries,
		Headers:         group.Headers,
		ProviderType:    group.ProviderType,
		RequestParams:   group.RequestParams,
		UseResponsesAPI: group.UseResponsesAPI,
	}

	// 获取提供商实例
	provider, err := p.providerManager.GetProvider(groupID, providerConfig)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Failed to get provider instance",
				"type":    "internal_error",
				"code":    "provider_error",
			},
		})
		return
	}

	// 获取模型列表
	ctx := c.Request.Context()
	rawModels, err := provider.GetModels(ctx)
	if err != nil {
		log.Printf("Failed to get models from provider %s: %v", groupID, err)
		p.keyManager.ReportError(groupID, apiKey, err.Error())
		c.JSON(http.StatusBadGateway, gin.H{
			"error": gin.H{
				"message": "Failed to get models from provider",
				"type":    "connection_error",
				"code":    "upstream_error",
			},
		})
		return
	}

	// 报告成功
	p.keyManager.ReportSuccess(groupID, apiKey)

	// 标准化模型数据格式
	standardizedModels := p.standardizeModelsResponse(rawModels, group.ProviderType)

	// 添加模型别名到模型列表中
	var enhancedModels interface{}
	if modelSlice, ok := standardizedModels.([]map[string]interface{}); ok {
		enhancedModels = p.addModelAliases(modelSlice, groupID)
	} else {
		enhancedModels = standardizedModels
	}

	// 为了与前端期望的格式一致，将单个提供商的响应包装成与所有提供商相同的格式
	response := gin.H{
		"object": "list",
		"data": map[string]interface{}{
			groupID: map[string]interface{}{
				"group_name":    group.Name,
				"provider_type": group.ProviderType,
				"models":        enhancedModels,
			},
		},
	}

	// 返回模型列表
	c.JSON(http.StatusOK, response)
}

// handleAllModels 处理所有分组的模型列表请求
func (p *MultiProviderProxy) handleAllModels(c *gin.Context) {
	allModels := make(map[string]interface{})

	// 获取所有启用的分组
	enabledGroups := p.providerRouter.GetAvailableGroups()

	for groupID, group := range enabledGroups {
		// 获取API密钥
		apiKey, err := p.keyManager.GetNextKeyForGroup(groupID)
		if err != nil {
			log.Printf("Failed to get API key for group %s: %v", groupID, err)
			continue
		}

		// 创建提供商配置
		providerConfig := &providers.ProviderConfig{
			BaseURL:         group.BaseURL,
			APIKey:          apiKey,
			Timeout:         group.Timeout,
			MaxRetries:      group.MaxRetries,
			Headers:         group.Headers,
			ProviderType:    group.ProviderType,
			RequestParams:   group.RequestParams,
			UseResponsesAPI: group.UseResponsesAPI,
		}

		// 获取提供商实例
		provider, err := p.providerManager.GetProvider(groupID, providerConfig)
		if err != nil {
			log.Printf("Failed to get provider for group %s: %v", groupID, err)
			continue
		}

		// 获取模型列表
		ctx := c.Request.Context()
		rawModels, err := provider.GetModels(ctx)
		if err != nil {
			log.Printf("Failed to get models from provider %s: %v", groupID, err)
			p.keyManager.ReportError(groupID, apiKey, err.Error())
			continue
		}

		// 报告成功
		p.keyManager.ReportSuccess(groupID, apiKey)

		// 标准化模型数据格式
		standardizedModels := p.standardizeModelsResponse(rawModels, group.ProviderType)

		// 添加模型别名到模型列表中
		var enhancedModels interface{}
		if modelSlice, ok := standardizedModels.([]map[string]interface{}); ok {
			enhancedModels = p.addModelAliases(modelSlice, groupID)
		} else {
			enhancedModels = standardizedModels
		}

		// 添加到结果中
		allModels[groupID] = map[string]interface{}{
			"group_name":    group.Name,
			"provider_type": group.ProviderType,
			"models":        enhancedModels,
		}
	}

	// 返回所有模型
	c.JSON(http.StatusOK, gin.H{
		"object": "list",
		"data":   allModels,
	})
}

// StandardizeModelsResponse 标准化不同提供商的模型响应格式（公开方法）
func (p *MultiProviderProxy) StandardizeModelsResponse(rawModels interface{}, providerType string) interface{} {
	return p.standardizeModelsResponse(rawModels, providerType)
}

// standardizeModelsResponse 标准化不同提供商的模型响应格式
func (p *MultiProviderProxy) standardizeModelsResponse(rawModels interface{}, providerType string) interface{} {
	switch providerType {
	case "openai", "azure_openai":
		// OpenAI格式已经是标准格式
		return rawModels

	case "gemini":
		// Gemini格式需要转换
		return p.standardizeGeminiModels(rawModels)

	case "anthropic":
		// Anthropic格式需要转换
		return p.standardizeAnthropicModels(rawModels)

	default:
		// 默认尝试OpenAI格式
		return rawModels
	}
}

// standardizeGeminiModels 标准化Gemini模型响应
func (p *MultiProviderProxy) standardizeGeminiModels(rawModels interface{}) interface{} {
	// 尝试解析Gemini响应格式
	if modelsMap, ok := rawModels.(map[string]interface{}); ok {
		// 检查是否有data字段（Gemini提供商返回的格式）
		if modelsArray, exists := modelsMap["data"]; exists {
			// 尝试多种类型断言
			var models []map[string]interface{}
			var ok bool

			// 首先尝试 []map[string]interface{}
			if typedModels, typeOk := modelsArray.([]map[string]interface{}); typeOk {
				models = typedModels
				ok = true
			} else if interfaceModels, typeOk := modelsArray.([]interface{}); typeOk {
				// 如果是 []interface{}，尝试转换每个元素
				models = make([]map[string]interface{}, 0, len(interfaceModels))
				for _, item := range interfaceModels {
					if modelMap, mapOk := item.(map[string]interface{}); mapOk {
						models = append(models, modelMap)
					}
				}
				ok = len(models) > 0
			}

			if ok && len(models) > 0 {
				// 转换为OpenAI格式
				standardModels := make([]map[string]interface{}, 0)
				for _, modelMap := range models {
					// 提取模型ID - Gemini提供商已经处理过了，直接使用id字段
					var modelID string
					if id, exists := modelMap["id"]; exists {
						if idStr, idOk := id.(string); idOk {
							modelID = idStr
						}
					}

					if modelID != "" {
						standardModel := map[string]interface{}{
							"id":       modelID,
							"object":   "model",
							"owned_by": "google",
						}

						// 添加其他可用信息
						if created, exists := modelMap["created"]; exists {
							standardModel["created"] = created
						}

						standardModels = append(standardModels, standardModel)
					}
				}

				return map[string]interface{}{
					"object": "list",
					"data":   standardModels,
				}
			}
		} else {
			// 检查是否有models字段（原始Google API格式）
			if modelsArray, exists := modelsMap["models"]; exists {
				if models, ok := modelsArray.([]interface{}); ok {
					// 转换为OpenAI格式
					standardModels := make([]map[string]interface{}, 0)
					for _, model := range models {
						if modelMap, ok := model.(map[string]interface{}); ok {
							// 提取模型名称
							var modelID string
							if name, exists := modelMap["name"]; exists {
								if nameStr, ok := name.(string); ok {
									// Gemini模型名称格式: "models/gemini-pro"
									parts := strings.Split(nameStr, "/")
									if len(parts) > 1 {
										modelID = parts[len(parts)-1]
									} else {
										modelID = nameStr
									}
								}
							}

							if modelID != "" {
								standardModel := map[string]interface{}{
									"id":       modelID,
									"object":   "model",
									"owned_by": "google",
								}

								// 添加其他可用信息
								if displayName, exists := modelMap["displayName"]; exists {
									standardModel["display_name"] = displayName
								}
								if description, exists := modelMap["description"]; exists {
									standardModel["description"] = description
								}

								standardModels = append(standardModels, standardModel)
							}
						}
					}

					return map[string]interface{}{
						"object": "list",
						"data":   standardModels,
					}
				}
			}
		}
	}

	// 如果解析失败，返回空列表
	return map[string]interface{}{
		"object": "list",
		"data":   []interface{}{},
	}
}

// standardizeAnthropicModels 标准化Anthropic模型响应
func (p *MultiProviderProxy) standardizeAnthropicModels(rawModels interface{}) interface{} {
	// Anthropic通常不提供模型列表API，返回预定义的模型
	predefinedModels := []map[string]interface{}{
		{
			"id":       "claude-3-sonnet-20240229",
			"object":   "model",
			"owned_by": "anthropic",
		},
		{
			"id":       "claude-3-opus-20240229",
			"object":   "model",
			"owned_by": "anthropic",
		},
		{
			"id":       "claude-3-haiku-20240307",
			"object":   "model",
			"owned_by": "anthropic",
		},
		{
			"id":       "claude-2.1",
			"object":   "model",
			"owned_by": "anthropic",
		},
		{
			"id":       "claude-2.0",
			"object":   "model",
			"owned_by": "anthropic",
		},
	}

	return map[string]interface{}{
		"object": "list",
		"data":   predefinedModels,
	}
}

// getProviderGroup 获取提供商分组信息
func (p *MultiProviderProxy) getProviderGroup(c *gin.Context, model string) string {
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

// addModelAliases 为模型列表添加别名信息
func (p *MultiProviderProxy) addModelAliases(models []map[string]interface{}, groupID string) []map[string]interface{} {
	group, exists := p.config.UserGroups[groupID]
	if !exists || len(group.ModelMappings) == 0 {
		return models
	}

	var enhancedModels []map[string]interface{}

	// 处理每个原始模型
	for _, model := range models {
		modelID, ok := model["id"].(string)
		if !ok {
			enhancedModels = append(enhancedModels, model)
			continue
		}

		// 检查是否有别名映射到这个原始模型
		var aliases []string
		for alias, originalModel := range group.ModelMappings {
			if originalModel == modelID {
				aliases = append(aliases, alias)
			}
		}

		if len(aliases) > 0 {
			// 如果有别名，为每个别名创建条目
			for _, alias := range aliases {
				aliasModel := make(map[string]interface{})
				for k, v := range model {
					aliasModel[k] = v
				}
				aliasModel["id"] = alias
				aliasModel["original_model"] = modelID
				aliasModel["is_alias"] = true
				enhancedModels = append(enhancedModels, aliasModel)
			}

			// 也保留原始模型，但标记它有别名
			originalModel := make(map[string]interface{})
			for k, v := range model {
				originalModel[k] = v
			}
			originalModel["has_aliases"] = aliases
			originalModel["is_original"] = true
			enhancedModels = append(enhancedModels, originalModel)
		} else {
			// 没有别名的模型直接添加
			enhancedModels = append(enhancedModels, model)
		}
	}

	// 添加那些没有对应原始模型的别名（可能是跨分组映射）
	for alias, originalModel := range group.ModelMappings {
		// 检查原始模型是否在当前模型列表中
		found := false
		for _, model := range models {
			if modelID, ok := model["id"].(string); ok && modelID == originalModel {
				found = true
				break
			}
		}

		// 如果原始模型不在当前列表中，创建一个别名条目
		if !found {
			aliasModel := map[string]interface{}{
				"id":             alias,
				"object":         "model",
				"created":        0,
				"owned_by":       "alias",
				"original_model": originalModel,
				"is_alias":       true,
				"cross_group":    true, // 标记为跨分组映射
			}
			enhancedModels = append(enhancedModels, aliasModel)
		}
	}

	return enhancedModels
}
