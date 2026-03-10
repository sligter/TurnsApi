package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"turnsapi/internal"
	"turnsapi/internal/auth"
	"turnsapi/internal/cache"
	"turnsapi/internal/health"
	"turnsapi/internal/keymanager"
	"turnsapi/internal/logger"
	"turnsapi/internal/providers"
	"turnsapi/internal/proxy"
	"turnsapi/internal/proxykey"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// MultiProviderServer 多提供商HTTP服务器
type MultiProviderServer struct {
	configManager   *internal.ConfigManager
	config          *internal.Config
	keyManager      *keymanager.MultiGroupKeyManager
	proxy           *proxy.MultiProviderProxy
	authManager     *auth.AuthManager
	proxyKeyManager *proxykey.Manager
	requestLogger   *logger.RequestLogger
	healthChecker   *health.MultiProviderHealthChecker
	modelCache      *cache.ModelCache
	router          *gin.Engine
	httpServer      *http.Server
	startTime       time.Time
}

// configManagerAdapter 配置管理器适配器
type configManagerAdapter struct {
	configManager *internal.ConfigManager
}

func parseOptionalJSONInt(value interface{}, defaultValue int, fieldName string) (int, error) {
	switch v := value.(type) {
	case nil:
		return defaultValue, nil
	case int:
		return v, nil
	case int32:
		return int(v), nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return defaultValue, nil
		}
		parsed, err := strconv.Atoi(trimmed)
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", fieldName)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("%s must be an integer", fieldName)
	}
}

// GetEnabledGroups 实现ConfigProvider接口
func parseOptionalJSONFloat64(value interface{}, defaultValue float64, fieldName string) (float64, error) {
	switch v := value.(type) {
	case nil:
		return defaultValue, nil
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return defaultValue, nil
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, fmt.Errorf("%s must be a number", fieldName)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("%s must be a number", fieldName)
	}
}

func (cma *configManagerAdapter) GetEnabledGroups() map[string]interface{} {
	enabledGroups := cma.configManager.GetEnabledGroups()
	result := make(map[string]interface{})
	for groupID := range enabledGroups {
		result[groupID] = struct{}{}
	}
	return result
}

// NewMultiProviderServer 创建新的多提供商服务器
func NewMultiProviderServer(configManager *internal.ConfigManager, keyManager *keymanager.MultiGroupKeyManager) *MultiProviderServer {
	config := configManager.GetConfig()

	log.Printf("=== 快速创建MultiProviderServer ===")
	log.Printf("配置的服务器模式: '%s'", config.Server.Mode)

	// 设置Gin模式（快速设置）
	var ginMode string
	switch config.Server.Mode {
	case "debug":
		ginMode = gin.DebugMode
	case "release":
		ginMode = gin.ReleaseMode
	case "test":
		ginMode = gin.TestMode
	default:
		ginMode = gin.ReleaseMode // 默认生产模式
	}

	os.Setenv("GIN_MODE", ginMode)
	gin.SetMode(ginMode)

	// 创建请求日志记录器
	requestLogger, err := logger.NewRequestLoggerWithConfig(config.Database, config.RequestLogs)
	if err != nil {
		log.Fatalf("Failed to create request logger: %v", err)
	}

	// 创建代理密钥管理器
	configProvider := &configManagerAdapter{configManager: configManager}
	proxyKeyManager := proxykey.NewManagerWithConfig(requestLogger, configProvider)

	server := &MultiProviderServer{
		configManager:   configManager,
		config:          config,
		keyManager:      keyManager,
		authManager:     auth.NewAuthManager(config),
		proxyKeyManager: proxyKeyManager,
		requestLogger:   requestLogger,
		modelCache:      cache.NewModelCache(5 * time.Minute), // 5 minute TTL
		router:          gin.New(),
		startTime:       time.Now(),
	}

	// 创建多提供商代理
	server.proxy = proxy.NewMultiProviderProxyWithProxyKey(config, keyManager, proxyKeyManager, requestLogger)

	// 延迟初始化健康检查器（异步创建，避免启动时网络检查）
	go func() {
		time.Sleep(5 * time.Second) // 延迟5秒初始化
		log.Printf("开始异步初始化健康检查器...")
		factory := providers.NewDefaultProviderFactory()
		providerManager := providers.NewProviderManager(factory)
		server.healthChecker = health.NewMultiProviderHealthChecker(config, keyManager, providerManager, server.proxy.GetProviderRouter())
	}()

	// 设置代理密钥管理器到认证管理器
	server.authManager.SetProxyKeyManager(server.proxyKeyManager)

	// 设置中间件
	server.setupMiddleware()

	// 设置路由
	server.setupRoutes()

	// log.Printf("MultiProviderServer快速创建完成")
	return server
}

// setupMiddleware 设置中间件
func (s *MultiProviderServer) setupMiddleware() {
	// 日志中间件
	s.router.Use(gin.Logger())
	s.router.Use(gin.Recovery())

	// CORS中间件
	s.router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Referer, Content-Type, Authorization, X-Provider-Group, HTTP-Referer, X-Title, Accept, Accept-Language, Priority, Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
}

// setupRoutes 设置路由
func (s *MultiProviderServer) setupRoutes() {
	// API路由（需要API密钥认证）
	api := s.router.Group("/v1")
	api.Use(s.authManager.APIKeyAuthMiddleware())
	{
		api.POST("/chat/completions", s.handleChatCompletions)
		api.GET("/models", s.handleModels)

		// 测试路由
		api.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "test endpoint works"})
		})
	}

	// Gemini 原生 API 路由 /v1beta
	v1betaGroup := s.router.Group("/v1beta")
	{
		// 根路径信息端点（不需要认证）
		v1betaGroup.GET("/", s.handleGeminiBetaInfo)

		// 需要认证的端点
		v1betaAuthenticated := v1betaGroup.Group("/")
		v1betaAuthenticated.Use(s.geminiAPIKeyAuthMiddleware())
		{
			v1betaAuthenticated.GET("/models", s.handleGeminiNativeModels)
			// 支持Gemini原生格式 /models/model:method 使用通配符匹配（必须放在具体路由之前）
			v1betaAuthenticated.POST("/models/*path", s.handleGeminiNativeMethodDispatch)
		}
	}

	// 兼容OpenAI API路径
	s.router.POST("/chat/completions", s.authManager.APIKeyAuthMiddleware(), s.handleChatCompletions)
	s.router.GET("/models", s.authManager.APIKeyAuthMiddleware(), s.handleModels)

	// 管理API（需要HTTP Basic认证）
	admin := s.router.Group("/admin")
	admin.Use(s.authManager.AuthMiddleware())
	{
		// 系统状态
		admin.GET("/status", s.handleStatus)

		// 健康检查
		admin.GET("/health/system", s.handleSystemHealth)
		admin.GET("/health/providers", s.handleProvidersHealth)
		admin.GET("/health/providers/:groupId", s.handleProviderHealth)

		// 密钥管理
		admin.GET("/groups", s.handleGroupsStatus)
		admin.GET("/groups/:groupId/keys", s.handleGroupKeysStatus)

		// 模型管理
		admin.GET("/models", s.handleAllModels)
		admin.GET("/models/:groupId", s.handleGroupModels)
		admin.POST("/models/test", s.handleTestModels)
		admin.GET("/models/available/:groupId", s.handleAvailableModels)
		admin.POST("/models/available/by-type", s.handleAvailableModelsByType)
		admin.POST("/keys/validate/:groupId", s.handleValidateKeys)
		admin.POST("/keys/validate", s.handleValidateKeysWithoutGroup)
		admin.GET("/keys/status", s.handleKeysStatus)
		admin.GET("/keys/validation/:groupId", s.handleGetKeyValidationStatus)

		// 日志管理
		admin.GET("/logs", s.handleLogs)
		admin.GET("/logs/filters", s.handleLogFilterOptions)
		admin.GET("/logs/stats/filters", s.handleLogFilterOptions)
		admin.GET("/logs/:id", s.handleLogDetail)
		admin.DELETE("/logs/batch", s.handleDeleteLogs)
		admin.DELETE("/logs/clear", s.handleClearAllLogs)
		admin.DELETE("/logs/clear-errors", s.handleClearErrorLogs)
		admin.GET("/logs/export", s.handleExportLogs)
		admin.GET("/logs/stats/overview", s.handleLogsOverviewStats)
		admin.GET("/logs/stats/charts", s.handleLogsChartsStats)
		admin.GET("/logs/stats/api-keys", s.handleAPIKeyStats)
		admin.GET("/logs/stats/models", s.handleModelStats)
		admin.GET("/logs/stats/tokens", s.handleTotalTokensStats)
		// 新增聚合统计端点（前端图表使用）
		admin.GET("/logs/stats/status", s.handleStatusDistribution)
		admin.GET("/logs/stats/tokens-timeline", s.handleTokensTimeline)
		admin.GET("/logs/stats/group-tokens", s.handleGroupTokens)

		// 代理密钥管理
		admin.GET("/proxy-keys", s.handleProxyKeys)
		admin.POST("/proxy-keys", s.handleGenerateProxyKey)
		admin.PUT("/proxy-keys/:id", s.handleUpdateProxyKey)
		admin.DELETE("/proxy-keys/:id", s.handleDeleteProxyKey)
		admin.GET("/proxy-keys/:id/group-stats", s.handleProxyKeyGroupStats)

		// 健康检查手动刷新
		admin.POST("/health/refresh", s.handleRefreshHealth)
		admin.POST("/health/refresh/:groupId", s.handleRefreshGroupHealth)

		// 分组管理
		admin.GET("/groups/manage", s.handleGroupsManage)
		admin.POST("/groups", s.handleCreateGroup)
		admin.PUT("/groups/:groupId", s.handleUpdateGroup)
		admin.DELETE("/groups/:groupId", s.handleDeleteGroup)
		admin.POST("/groups/:groupId/toggle", s.handleToggleGroup)
		admin.POST("/groups/export", s.handleExportGroups)
		admin.POST("/groups/import", s.handleImportGroups)

		// 密钥管理新功能
		admin.POST("/groups/:groupId/keys/force-status", s.handleForceKeyStatus)
		admin.DELETE("/groups/:groupId/keys/invalid", s.handleDeleteInvalidKeys)
	}

	// Web认证
	s.router.GET("/auth/login", s.authManager.HandleLoginPage)
	s.router.POST("/auth/login", s.authManager.HandleLogin)
	s.router.POST("/auth/logout", s.authManager.HandleLogout)

	// 静态文件
	s.router.Static("/static", "./web/static")
	s.router.LoadHTMLGlob("web/templates/*")

	// SVG文件直接访问（用于logo和favicon）
	s.router.StaticFile("/logo.svg", "./web/templates/logo.svg")
	s.router.StaticFile("/favicon.svg", "./web/templates/favicon.svg")

	// Web界面（需要Web认证）
	s.router.GET("/", s.authManager.WebAuthMiddleware(), s.handleIndex)
	s.router.GET("/dashboard", s.authManager.WebAuthMiddleware(), s.handleMultiProviderDashboard)
	s.router.GET("/logs", s.authManager.WebAuthMiddleware(), s.handleLogsPage)
	s.router.GET("/groups", s.authManager.WebAuthMiddleware(), s.handleGroupsManagePage)

	// 健康检查（不需要认证）
	s.router.GET("/health", s.handleHealth)
}

// handleChatCompletions 处理聊天完成请求
func (s *MultiProviderServer) handleChatCompletions(c *gin.Context) {
	// 增加请求计数
	s.healthChecker.IncrementRequestCount()
	s.proxy.HandleChatCompletion(c)
}

// handleModels 处理模型列表请求
func (s *MultiProviderServer) handleModels(c *gin.Context) {
	// 获取代理密钥信息
	keyInfo, exists := c.Get("key_info")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": gin.H{
				"message": "Authentication required",
				"type":    "authentication_error",
				"code":    "missing_key_info",
			},
		})
		return
	}

	// 转换为ProxyKey类型
	proxyKey, ok := keyInfo.(*logger.ProxyKey)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Invalid key information",
				"type":    "internal_error",
				"code":    "invalid_key_info",
			},
		})
		return
	}

	// 检查是否指定了特定的提供商分组
	groupID := c.Query("provider_group")

	if groupID != "" {
		// 检查代理密钥是否有访问指定分组的权限
		if !s.hasGroupAccess(proxyKey, groupID) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": gin.H{
					"message": fmt.Sprintf("Access denied to provider group '%s'", groupID),
					"type":    "permission_error",
					"code":    "group_access_denied",
				},
			})
			return
		}
	}

	// 获取并返回标准OpenAI格式的模型列表
	s.handleOpenAIModels(c, proxyKey, groupID)
}

// handleOpenAIModels 处理OpenAI格式的模型列表请求
// handleOpenAIModels 处理OpenAI格式的模型列表请求
func (s *MultiProviderServer) handleOpenAIModels(c *gin.Context, proxyKey *logger.ProxyKey, groupID string) {
	// 调试日志
	log.Printf("代理密钥权限: ID=%s, AllowedGroups=%v", proxyKey.ID, proxyKey.AllowedGroups)

	// 获取所有启用的分组
	enabledGroups := s.proxy.GetProviderRouter().GetAvailableGroups()
	log.Printf("启用的分组: %v", func() []string {
		var groups []string
		for id := range enabledGroups {
			groups = append(groups, id)
		}
		return groups
	}())

	// 根据代理密钥权限和查询参数过滤分组
	var accessibleGroups map[string]*internal.UserGroup

	if groupID != "" {
		// 如果指定了特定分组，只返回该分组的模型
		if group, exists := enabledGroups[groupID]; exists {
			accessibleGroups = map[string]*internal.UserGroup{groupID: group}
		} else {
			c.JSON(http.StatusNotFound, gin.H{
				"error": gin.H{
					"message": fmt.Sprintf("Provider group '%s' not found", groupID),
					"type":    "not_found",
					"code":    "group_not_found",
				},
			})
			return
		}
	} else {
		// 根据代理密钥权限过滤分组
		accessibleGroups = make(map[string]*internal.UserGroup)

		if len(proxyKey.AllowedGroups) == 0 {
			// 如果没有限制，可以访问所有启用的分组
			accessibleGroups = enabledGroups
		} else {
			// 只包含有权限访问的分组
			for _, allowedGroupID := range proxyKey.AllowedGroups {
				if group, exists := enabledGroups[allowedGroupID]; exists {
					accessibleGroups[allowedGroupID] = group
				}
			}
		}
	}

	// 收集所有可访问分组的模型，使用map进行去重
	modelMap := make(map[string]map[string]interface{})

	for currentGroupID, group := range accessibleGroups {
		models := s.getModelsForGroup(currentGroupID, group)
		// 将模型添加到map中，以id为key进行去重
		for _, model := range models {
			if id, ok := model["id"].(string); ok {
				modelMap[id] = model
			}
		}
	}

	// 将map转换为slice
	var allModels []map[string]interface{}
	for _, model := range modelMap {
		allModels = append(allModels, model)
	}

	// 返回标准OpenAI格式
	c.JSON(http.StatusOK, gin.H{
		"object": "list",
		"data":   allModels,
	})
}

// getModelsForGroup 获取指定分组的模型列表
func (s *MultiProviderServer) getModelsForGroup(groupID string, group *internal.UserGroup) []map[string]interface{} {
	var models []map[string]interface{}

	// 如果分组配置了特定的模型列表，使用配置的模型
	if len(group.Models) > 0 {
		log.Printf("分组 %s 配置了 %d 个特定模型: %v", groupID, len(group.Models), group.Models)
		for _, modelID := range group.Models {
			models = append(models, map[string]interface{}{
				"id":       modelID,
				"object":   "model",
				"created":  1640995200, // 默认时间戳
				"owned_by": s.getOwnerByModelID(modelID),
			})
		}

		// 应用模型别名映射
		models = s.applyModelMappings(models, group)
		return models
	}

	// 如果没有配置特定模型，动态从提供商端点获取模型列表
	log.Printf("分组 %s 没有配置特定模型，尝试从提供商端点获取模型列表", groupID)

	// 尝试动态获取模型列表
	dynamicModels := s.getDynamicModelsForGroup(groupID, group)
	if len(dynamicModels) > 0 {
		models = append(models, dynamicModels...)
	} else {
		// 如果动态获取失败，返回一个通用占位符，表示支持所有模型
		log.Printf("分组 %s 动态获取模型失败，返回通用占位符", groupID)
		models = append(models, map[string]interface{}{
			"id":       "all-models-supported",
			"object":   "model",
			"created":  1640995200,
			"owned_by": s.getProviderOwner(group.ProviderType),
			"note":     "This provider supports all available models. Please check the provider's documentation for the complete list.",
		})
	}

	// 应用模型别名映射
	models = s.applyModelMappings(models, group)
	return models
}

// getDynamicModelsForGroup 动态从提供商端点获取模型列表
func (s *MultiProviderServer) getDynamicModelsForGroup(groupID string, group *internal.UserGroup) []map[string]interface{} {
	// 创建提供商配置
	providerConfig, err := s.proxy.GetProviderRouter().CreateProviderConfig(groupID, group)
	if err != nil {
		log.Printf("创建分组 %s 的提供商配置失败: %v", groupID, err)
		return nil
	}

	// 获取提供商实例
	provider, err := s.proxy.GetProviderRouter().GetProviderManager().GetProvider(groupID, providerConfig)
	if err != nil {
		log.Printf("获取分组 %s 的提供商实例失败: %v", groupID, err)
		return nil
	}

	// 调用提供商的GetModels方法
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	modelsResponse, err := provider.GetModels(ctx)
	if err != nil {
		log.Printf("从分组 %s 获取模型列表失败: %v", groupID, err)
		return nil
	}

	// 解析响应
	var models []map[string]interface{}

	// 处理不同的响应格式
	switch response := modelsResponse.(type) {
	case map[string]interface{}:
		// OpenAI格式: {"object": "list", "data": [...]}
		if data, exists := response["data"]; exists {
			if modelList, ok := data.([]interface{}); ok {
				for _, model := range modelList {
					if modelMap, ok := model.(map[string]interface{}); ok {
						models = append(models, modelMap)
					}
				}
			}
		}
	case []interface{}:
		// 直接的模型数组
		for _, model := range response {
			if modelMap, ok := model.(map[string]interface{}); ok {
				models = append(models, modelMap)
			}
		}
	case []map[string]interface{}:
		// 已经是正确格式的模型数组
		models = response
	default:
		log.Printf("分组 %s 返回了未知的模型响应格式: %T", groupID, modelsResponse)
		return nil
	}

	log.Printf("从分组 %s 动态获取到 %d 个模型", groupID, len(models))
	return models
}

// getOwnerByModelID 根据模型ID推断所有者
func (s *MultiProviderServer) getOwnerByModelID(modelID string) string {
	if strings.Contains(modelID, "qwen") {
		return "alibaba"
	}
	if strings.Contains(modelID, "moonshotai") || strings.Contains(modelID, "kimi") {
		return "moonshot"
	}
	if strings.Contains(modelID, "deepseek") {
		return "deepseek"
	}
	if strings.Contains(modelID, "gpt") || strings.Contains(modelID, "openai") {
		return "openai"
	}
	if strings.Contains(modelID, "claude") || strings.Contains(modelID, "anthropic") {
		return "anthropic"
	}
	if strings.Contains(modelID, "gemini") || strings.Contains(modelID, "google") {
		return "google"
	}
	if strings.Contains(modelID, "llama") || strings.Contains(modelID, "meta") {
		return "meta"
	}

	// 默认返回openai
	return "openai"
}

// getOpenAIModels 获取OpenAI模型列表
func (s *MultiProviderServer) getOpenAIModels() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"id":       "gpt-3.5-turbo",
			"object":   "model",
			"created":  1640995200, // 2022-01-01
			"owned_by": "openai",
		},
		{
			"id":       "gpt-3.5-turbo-16k",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "openai",
		},
		{
			"id":       "gpt-4",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "openai",
		},
		{
			"id":       "gpt-4-turbo",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "openai",
		},
		{
			"id":       "gpt-4o",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "openai",
		},
		{
			"id":       "gpt-4o-mini",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "openai",
		},
	}
}

// getOpenRouterModels 获取OpenRouter模型列表
func (s *MultiProviderServer) getOpenRouterModels() []map[string]interface{} {
	// OpenRouter支持大量模型，这里返回一些常用的
	return []map[string]interface{}{
		{
			"id":       "openai/gpt-3.5-turbo",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "openai",
		},
		{
			"id":       "openai/gpt-4",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "openai",
		},
		{
			"id":       "openai/gpt-4-turbo",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "openai",
		},
		{
			"id":       "anthropic/claude-3-sonnet",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "anthropic",
		},
		{
			"id":       "anthropic/claude-3-opus",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "anthropic",
		},
		{
			"id":       "google/gemini-pro",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "google",
		},
	}
}

// getAnthropicModels 获取Anthropic模型列表
func (s *MultiProviderServer) getAnthropicModels() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"id":       "claude-3-sonnet-20240229",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "anthropic",
		},
		{
			"id":       "claude-3-opus-20240229",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "anthropic",
		},
		{
			"id":       "claude-3-haiku-20240307",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "anthropic",
		},
		{
			"id":       "claude-3-5-sonnet-20241022",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "anthropic",
		},
		{
			"id":       "claude-2.1",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "anthropic",
		},
		{
			"id":       "claude-2.0",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "anthropic",
		},
	}
}

// getGeminiModels 获取Gemini模型列表
func (s *MultiProviderServer) getGeminiModels() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"id":       "gemini-2.5-flash",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "google",
		},
		{
			"id":       "gemini-2.5-pro",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "google",
		},
		{
			"id":       "gemini-1.5-flash",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "google",
		},
		{
			"id":       "gemini-1.5-pro",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "google",
		},
		{
			"id":       "gemini-pro",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "google",
		},
		{
			"id":       "gemini-pro-vision",
			"object":   "model",
			"created":  1640995200,
			"owned_by": "google",
		},
	}
}

// hasGroupAccess 检查代理密钥是否有访问指定分组的权限
func (s *MultiProviderServer) hasGroupAccess(proxyKey *logger.ProxyKey, groupID string) bool {
	// 如果AllowedGroups为空，表示可以访问所有分组
	if len(proxyKey.AllowedGroups) == 0 {
		return true
	}

	// 检查是否在允许的分组列表中
	for _, allowedGroup := range proxyKey.AllowedGroups {
		if allowedGroup == groupID {
			return true
		}
	}

	return false
}

// applyModelMappings 应用模型别名映射到模型列表
func (s *MultiProviderServer) applyModelMappings(models []map[string]interface{}, group *internal.UserGroup) []map[string]interface{} {
	if len(group.ModelMappings) == 0 {
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

			// 同时保留原始模型
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
				"created":        1640995200,
				"owned_by":       s.getOwnerByModelID(originalModel),
				"original_model": originalModel,
				"is_alias":       true,
				"cross_group":    true, // 标记为跨分组映射
			}
			enhancedModels = append(enhancedModels, aliasModel)
		}
	}

	return enhancedModels
}

// handleSystemHealth 处理系统健康检查
func (s *MultiProviderServer) handleSystemHealth(c *gin.Context) {
	health := s.healthChecker.GetSystemHealth()
	if s.requestLogger != nil {
		if stats, err := s.requestLogger.GetTotalTokensStats(); err == nil && stats != nil {
			health.TotalRequests = stats.TotalRequests
		}
	}
	c.JSON(http.StatusOK, health)
}

// handleProvidersHealth 处理所有提供商健康检查
func (s *MultiProviderServer) handleProvidersHealth(c *gin.Context) {
	health := s.healthChecker.GetSystemHealth()
	c.JSON(http.StatusOK, health)
}

// handleProviderHealth 处理特定提供商健康检查
func (s *MultiProviderServer) handleProviderHealth(c *gin.Context) {
	groupID := c.Param("groupId")
	health := s.healthChecker.CheckProviderHealth(groupID)
	c.JSON(http.StatusOK, health)
}

// handleStatus 处理状态查询
func (s *MultiProviderServer) handleStatus(c *gin.Context) {
	systemHealth := s.healthChecker.GetSystemHealth()
	if s.requestLogger != nil {
		if stats, err := s.requestLogger.GetTotalTokensStats(); err == nil && stats != nil {
			systemHealth.TotalRequests = stats.TotalRequests
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":          systemHealth.Status,
		"timestamp":       time.Now(),
		"uptime":          systemHealth.Uptime,
		"total_groups":    systemHealth.TotalGroups,
		"enabled_groups":  systemHealth.EnabledGroups,
		"disabled_groups": systemHealth.DisabledGroups,
		"total_keys":      systemHealth.TotalKeys,
		"active_keys":     systemHealth.ActiveKeys,
		"total_requests":  systemHealth.TotalRequests,
	})
}

// handleGroupsStatus 处理分组状态查询
func (s *MultiProviderServer) handleGroupsStatus(c *gin.Context) {
	// 从数据库获取分组信息（包含创建时间，按创建时间倒序）
	groupsWithMetadata, err := s.configManager.GetGroupsWithMetadata()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to load groups: " + err.Error(),
		})
		return
	}

	groups := make(map[string]interface{})

	for groupID, groupInfo := range groupsWithMetadata {
		// 添加总密钥数
		if apiKeys, ok := groupInfo["api_keys"].([]string); ok {
			groupInfo["total_keys"] = len(apiKeys)
		} else {
			groupInfo["total_keys"] = 0
		}

		// 获取健康状态，如果没有健康检查记录则默认为健康
		if healthStatus, exists := s.healthChecker.GetProviderHealth(groupID); exists {
			groupInfo["healthy"] = healthStatus.Healthy
			groupInfo["last_error"] = healthStatus.LastError
		} else {
			// 新分组默认为健康状态
			groupInfo["healthy"] = true
			groupInfo["last_check"] = nil
			groupInfo["response_time"] = 0
			groupInfo["last_error"] = ""
		}

		groups[groupID] = groupInfo
	}

	c.JSON(http.StatusOK, gin.H{
		"groups": groups,
	})
}

// handleGroupKeysStatus 处理特定分组的密钥状态查询
func (s *MultiProviderServer) handleGroupKeysStatus(c *gin.Context) {
	groupID := c.Param("groupId")

	groupStatus, exists := s.keyManager.GetGroupStatus(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Group not found",
		})
		return
	}

	c.JSON(http.StatusOK, groupStatus)
}

// handleAllModels 处理所有模型列表请求 - 返回分组配置中选择的模型
func (s *MultiProviderServer) handleAllModels(c *gin.Context) {
	allGroups := s.configManager.GetAllGroups()
	allModels := make(map[string]interface{})

	for groupID, group := range allGroups {
		if !group.Enabled {
			continue // 跳过禁用的分组
		}

		// 构建模型列表 - 使用分组配置中的模型
		var modelList []map[string]interface{}

		if len(group.Models) > 0 {
			// 如果分组配置了特定模型，使用配置的模型
			for _, modelID := range group.Models {
				modelList = append(modelList, map[string]interface{}{
					"id":       modelID,
					"object":   "model",
					"owned_by": s.getProviderOwner(group.ProviderType),
				})
			}
		} else {
			// 如果没有配置特定模型，表示支持所有模型，返回一个通用提示
			modelList = append(modelList, map[string]interface{}{
				"id":       "all-models-supported",
				"object":   "model",
				"owned_by": s.getProviderOwner(group.ProviderType),
				"note":     "This provider supports all available models",
			})
		}

		// 添加到结果中
		allModels[groupID] = map[string]interface{}{
			"group_name":    group.Name,
			"provider_type": group.ProviderType,
			"models": map[string]interface{}{
				"object": "list",
				"data":   modelList,
			},
		}
	}

	// 返回所有模型
	c.JSON(http.StatusOK, gin.H{
		"object": "list",
		"data":   allModels,
	})
}

// handleGroupModels 处理特定分组的模型列表请求 - 返回分组配置中选择的模型
func (s *MultiProviderServer) handleGroupModels(c *gin.Context) {
	groupID := c.Param("groupId")

	group, exists := s.configManager.GetGroup(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"error": gin.H{
				"message": "Group not found",
				"type":    "not_found",
				"code":    "group_not_found",
			},
		})
		return
	}

	// 构建模型列表 - 使用分组配置中的模型
	var modelList []map[string]interface{}

	if len(group.Models) > 0 {
		// 如果分组配置了特定模型，使用配置的模型
		for _, modelID := range group.Models {
			modelList = append(modelList, map[string]interface{}{
				"id":       modelID,
				"object":   "model",
				"owned_by": s.getProviderOwner(group.ProviderType),
			})
		}
	} else {
		// 如果没有配置特定模型，表示支持所有模型，返回一个通用提示
		modelList = append(modelList, map[string]interface{}{
			"id":       "all-models-supported",
			"object":   "model",
			"owned_by": s.getProviderOwner(group.ProviderType),
			"note":     "This provider supports all available models",
		})
	}

	// 为了与前端期望的格式一致，将单个提供商的响应包装成与所有提供商相同的格式
	response := gin.H{
		"object": "list",
		"data": map[string]interface{}{
			groupID: map[string]interface{}{
				"group_name":    group.Name,
				"provider_type": group.ProviderType,
				"models": map[string]interface{}{
					"object": "list",
					"data":   modelList,
				},
			},
		},
	}

	c.JSON(http.StatusOK, response)
}

// getProviderOwner 根据提供商类型返回所有者信息
func (s *MultiProviderServer) getProviderOwner(providerType string) string {
	switch providerType {
	case "openai":
		return "openai"
	case "azure_openai":
		return "openai"
	case "anthropic":
		return "anthropic"
	case "gemini":
		return "google"
	case "openrouter":
		return "openrouter"
	default:
		return providerType
	}
}

// handleAvailableModels 处理获取提供商所有可用模型的请求（用于分组管理页面的模型选择）
func (s *MultiProviderServer) handleAvailableModels(c *gin.Context) {
	groupID := c.Param("groupId")

	// 获取分组配置
	group, exists := s.configManager.GetGroup(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"error": gin.H{
				"message": "Group not found",
				"type":    "not_found",
				"code":    "group_not_found",
			},
		})
		return
	}

	// 检查分组是否启用
	if !group.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": "Group is disabled",
				"type":    "group_disabled",
				"code":    "group_disabled",
			},
		})
		return
	}

	// 检查是否有API密钥
	if len(group.APIKeys) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": "No API keys configured for this group",
				"type":    "no_api_keys",
				"code":    "no_api_keys",
			},
		})
		return
	}

	// 检查是否强制刷新（绕过缓存）
	forceRefresh := c.Query("refresh") == "true"

	// 生成缓存键
	cacheKey := cache.GenerateCacheKey(group.ProviderType, group.BaseURL, group.APIKeys[0])

	// 如果不是强制刷新，尝试从缓存获取
	if !forceRefresh {
		if cachedData, found := s.modelCache.Get(cacheKey); found {
			c.JSON(http.StatusOK, cachedData)
			return
		}
	}

	// 创建提供商配置
	providerConfig := &providers.ProviderConfig{
		BaseURL:         group.BaseURL,
		APIKey:          group.APIKeys[0], // 使用第一个API密钥
		Timeout:         group.Timeout,
		MaxRetries:      group.MaxRetries,
		Headers:         group.Headers,
		ProviderType:    group.ProviderType,
		UseResponsesAPI: group.UseResponsesAPI,
	}

	// 创建提供商实例
	factory := providers.NewDefaultProviderFactory()
	provider, err := factory.CreateProvider(providerConfig)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Failed to create provider: " + err.Error(),
				"type":    "provider_creation_failed",
				"code":    "provider_creation_failed",
			},
		})
		return
	}

	// 获取模型列表
	ctx := c.Request.Context()
	rawModels, err := provider.GetModels(ctx)
	if err != nil {
		errorMsg := "Failed to get models: " + err.Error()
		suggestedAction := ""

		// 提供具体的建议
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			suggestedAction = "The request timed out. Try increasing the timeout value or check your network connection."
		} else if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "Unauthorized") {
			suggestedAction = "Authentication failed. Please verify your API key is correct and has the necessary permissions."
		} else if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "rate limit") {
			suggestedAction = "Rate limit exceeded. Please wait a moment and try again."
		} else if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
			suggestedAction = "Cannot connect to the API endpoint. Please verify the Base URL is correct."
		}

		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": gin.H{
				"message":    errorMsg,
				"type":       "models_fetch_failed",
				"code":       "models_fetch_failed",
				"suggestion": suggestedAction,
			},
		})
		return
	}

	// 标准化模型数据格式
	standardizedModels := s.proxy.StandardizeModelsResponse(rawModels, group.ProviderType)

	// 构建响应
	response := gin.H{
		"object": "list",
		"data": map[string]interface{}{
			groupID: map[string]interface{}{
				"group_name":    group.Name,
				"provider_type": group.ProviderType,
				"models":        standardizedModels,
			},
		},
	}

	// 缓存结果
	s.modelCache.Set(cacheKey, response)

	// 返回结果
	c.JSON(http.StatusOK, response)
}

// handleAvailableModelsByType 根据提供商类型和配置获取可用模型（用于新建分组时的模型选择）
func (s *MultiProviderServer) handleAvailableModelsByType(c *gin.Context) {
	var req struct {
		ProviderType string            `json:"provider_type" binding:"required"`
		BaseURL      string            `json:"base_url" binding:"required"`
		APIKeys      []string          `json:"api_keys" binding:"required"`
		MaxRetries   interface{}       `json:"max_retries"`
		Timeout      interface{}       `json:"timeout_seconds"`
		Headers      map[string]string `json:"headers"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request: " + err.Error(),
		})
		return
	}

	// 验证API密钥不为空
	validKeys := make([]string, 0)
	for _, key := range req.APIKeys {
		if strings.TrimSpace(key) != "" {
			validKeys = append(validKeys, strings.TrimSpace(key))
		}
	}

	if len(validKeys) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "At least one valid API key is required",
		})
		return
	}

	maxRetries, err := parseOptionalJSONInt(req.MaxRetries, 3, "max_retries")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request: " + err.Error(),
		})
		return
	}

	timeoutSeconds, err := parseOptionalJSONInt(req.Timeout, 30, "timeout_seconds")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request: " + err.Error(),
		})
		return
	}

	// 检查是否强制刷新（绕过缓存）
	forceRefresh := c.Query("refresh") == "true"

	// 生成缓存键
	cacheKey := cache.GenerateCacheKey(req.ProviderType, req.BaseURL, validKeys[0])

	// 如果不是强制刷新，尝试从缓存获取
	if !forceRefresh {
		if cachedData, found := s.modelCache.Get(cacheKey); found {
			c.JSON(http.StatusOK, cachedData)
			return
		}
	}

	// 创建临时分组配置
	tempGroup := &internal.UserGroup{
		Name:         "temp-test-group",
		ProviderType: req.ProviderType,
		BaseURL:      req.BaseURL,
		APIKeys:      validKeys,
		Enabled:      true,
		Timeout:      time.Duration(timeoutSeconds) * time.Second,
		MaxRetries:   maxRetries,
		Headers:      req.Headers,
	}

	// 创建临时提供商实例
	factory := providers.NewDefaultProviderFactory()
	config := &providers.ProviderConfig{
		BaseURL:      tempGroup.BaseURL,
		APIKey:       tempGroup.APIKeys[0], // 使用第一个API密钥进行测试
		Timeout:      tempGroup.Timeout,
		MaxRetries:   tempGroup.MaxRetries,
		Headers:      tempGroup.Headers,
		ProviderType: tempGroup.ProviderType,
	}

	provider, err := factory.CreateProvider(config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create provider: " + err.Error(),
		})
		return
	}

	// 获取模型列表
	ctx := c.Request.Context()
	rawModels, err := provider.GetModels(ctx)
	if err != nil {
		errorMsg := "Failed to get models: " + err.Error()
		suggestedAction := ""

		// 提供具体的建议
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			suggestedAction = "The request timed out. Try increasing the timeout value or check your network connection."
		} else if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "Unauthorized") {
			suggestedAction = "Authentication failed. Please verify your API key is correct and has the necessary permissions."
		} else if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "rate limit") {
			suggestedAction = "Rate limit exceeded. Please wait a moment and try again."
		} else if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
			suggestedAction = "Cannot connect to the API endpoint. Please verify the Base URL is correct."
		}

		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":      errorMsg,
			"suggestion": suggestedAction,
		})
		return
	}

	// 标准化模型数据格式
	standardizedModels := s.proxy.StandardizeModelsResponse(rawModels, tempGroup.ProviderType)

	// 返回模型列表，格式与其他API保持一致
	response := gin.H{
		"object": "list",
		"data": map[string]interface{}{
			"temp-group": map[string]interface{}{
				"group_name":    "临时测试分组",
				"provider_type": tempGroup.ProviderType,
				"models":        standardizedModels,
			},
		},
	}

	// 缓存结果
	s.modelCache.Set(cacheKey, response)

	c.JSON(http.StatusOK, response)
}

// handleValidateKeys 处理密钥有效性验证请求
func (s *MultiProviderServer) handleValidateKeys(c *gin.Context) {
	groupID := c.Param("groupId")

	group, exists := s.configManager.GetGroup(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "Group not found",
		})
		return
	}

	// 获取要验证的密钥列表
	var req struct {
		APIKeys []string `json:"api_keys"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request data: " + err.Error(),
		})
		return
	}

	// 选择用于测试的模型（优先使用配置的第一个模型，否则使用默认模型）
	var testModel string
	if len(group.Models) > 0 {
		testModel = group.Models[0]
	} else {
		// 根据提供商类型选择默认测试模型
		switch group.ProviderType {
		case "openai", "azure_openai":
			testModel = "gpt-3.5-turbo"
		case "anthropic":
			testModel = "claude-3-haiku-20240307"
		case "gemini":
			testModel = "gemini-2.5-flash"
		default:
			testModel = "gpt-3.5-turbo" // 默认模型
		}
	}

	log.Printf("🔍 开始批量验证密钥: 分组=%s, 提供商=%s, 密钥数量=%d, 测试模型=%s",
		groupID, group.ProviderType, len(req.APIKeys), testModel)

	// 使用批量验证模式，提高效率
	results := make([]map[string]interface{}, len(req.APIKeys))
	log.Printf("⚙️ 采用批量验证模式，批次大小=8，无固定延迟，提高验证效率")

	// 批量验证API密钥
	s.validateKeysInBatches(groupID, req.APIKeys, testModel, group, results)

	// 所有验证已完成（顺序执行）
	log.Printf("✅ 所有密钥验证已完成")

	// 统计结果
	validCount := 0
	invalidCount := 0
	unknownCount := 0
	for _, result := range results {
		status, _ := result["status"].(string)
		switch status {
		case string(KeyValidationValid):
			validCount++
		case string(KeyValidationInvalid):
			invalidCount++
		default:
			unknownCount++
		}
	}

	log.Printf("📊 验证结果统计: 总计=%d, 有效=%d, 无效=%d, 未知=%d, 成功率=%.1f%%",
		len(req.APIKeys), validCount, invalidCount,
		unknownCount,
		float64(validCount)/float64(len(req.APIKeys))*100)

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"test_model":   testModel,
		"total_keys":   len(req.APIKeys),
		"valid_keys":   validCount,
		"invalid_keys": invalidCount,
		"unknown_keys": unknownCount,
		"results":      results,
	})
}

// validateKeyWithRetry 带重试机制的密钥验证
func (s *MultiProviderServer) validateKeyWithRetry(groupID, apiKey, testModel string, group *internal.UserGroup, maxRetries int) (bool, error) {
	var lastErr error
	maskedKey := s.maskKey(apiKey)

	log.Printf("🔑 开始验证密钥: %s (分组: %s, 提供商: %s, 模型: %s)", maskedKey, groupID, group.ProviderType, testModel)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("🔄 密钥验证尝试 %d/%d: %s", attempt, maxRetries, maskedKey)

		// 创建提供商配置，强制使用300秒超时进行验证
		providerConfig := &providers.ProviderConfig{
			BaseURL:         group.BaseURL,
			APIKey:          apiKey,
			Timeout:         time.Duration(300) * time.Second, // 强制300秒超时，忽略分组配置
			MaxRetries:      1,
			Headers:         group.Headers,
			ProviderType:    group.ProviderType,
			UseResponsesAPI: group.UseResponsesAPI,
		}

		log.Printf("📋 提供商配置: BaseURL=%s, ProviderType=%s, Timeout=300s (强制设置)",
			func() string {
				if group.BaseURL != "" {
					return group.BaseURL
				}
				return "默认"
			}(), group.ProviderType)
		log.Printf("📝 注意: 分组原始超时=%v, 验证时强制使用300s", group.Timeout)

		// 获取提供商实例
		providerID := fmt.Sprintf("%s_validate_%s_%d", groupID, apiKey[:min(8, len(apiKey))], attempt)
		log.Printf("🏭 创建提供商实例: %s", providerID)

		provider, err := s.proxy.GetProviderManager().GetProvider(providerID, providerConfig)
		if err != nil {
			lastErr = fmt.Errorf("failed to create provider (attempt %d/%d): %w", attempt, maxRetries, err)
			log.Printf("❌ 创建提供商失败 (尝试 %d/%d): %v", attempt, maxRetries, err)
			continue
		}

		log.Printf("✅ 提供商实例创建成功")

		// 验证密钥
		log.Printf("🚀 发送测试请求到 %s 模型...", testModel)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)

		startTime := time.Now()
		response, err := provider.ChatCompletion(ctx, &providers.ChatCompletionRequest{
			Model:    testModel,
			Messages: []providers.ChatMessage{{Role: "user", Content: "test"}},
			// 移除MaxTokens限制，让提供商使用默认值
		})
		duration := time.Since(startTime)
		cancel()

		if err == nil {
			// 验证成功
			log.Printf("✅ 密钥验证成功: %s (耗时: %v)", maskedKey, duration)
			if response != nil && len(response.Choices) > 0 {
				log.Printf("📝 响应内容长度: %d 字符", len(response.Choices[0].Message.Content))
			}
			return true, nil
		}

		lastErr = fmt.Errorf("validation failed (attempt %d/%d): %w", attempt, maxRetries, err)
		log.Printf("❌ 密钥验证失败 (尝试 %d/%d, 耗时: %v): %v", attempt, maxRetries, duration, err)

		// 如果不是最后一次尝试，等待一小段时间再重试
		if attempt < maxRetries {
			waitTime := time.Duration(attempt) * 500 * time.Millisecond
			log.Printf("⏳ 等待 %v 后重试...", waitTime)
			time.Sleep(waitTime) // 递增等待时间
		}
	}

	// 所有重试都失败
	log.Printf("💥 密钥验证最终失败: %s (已尝试 %d 次)", maskedKey, maxRetries)
	return false, lastErr
}

// validateKeysInBatches 批量验证API密钥，提高验证效率
func (s *MultiProviderServer) validateKeysInBatches(groupID string, apiKeys []string, testModel string, group *internal.UserGroup, results []map[string]interface{}) {
	const batchSize = 8 // 每批处理8个密钥

	// 分批处理API密钥
	for batchStart := 0; batchStart < len(apiKeys); batchStart += batchSize {
		batchEnd := batchStart + batchSize
		if batchEnd > len(apiKeys) {
			batchEnd = len(apiKeys)
		}

		currentBatch := apiKeys[batchStart:batchEnd]
		log.Printf("🔄 开始处理批次 %d-%d/%d", batchStart+1, batchEnd, len(apiKeys))

		// 并发验证当前批次的密钥
		s.validateBatchConcurrently(groupID, currentBatch, batchStart, testModel, group, results)

		log.Printf("✅ 批次 %d-%d/%d 验证完成", batchStart+1, batchEnd, len(apiKeys))
	}
}

// validateBatchConcurrently 并发验证一个批次的API密钥
func (s *MultiProviderServer) validateBatchConcurrently(groupID string, batch []string, batchStartIndex int, testModel string, group *internal.UserGroup, results []map[string]interface{}) {
	var wg sync.WaitGroup

	// 为每个密钥启动一个goroutine进行验证
	for i, apiKey := range batch {
		wg.Add(1)
		go func(index int, key string) {
			defer wg.Done()

			actualIndex := batchStartIndex + index

			// 检查空密钥
			if strings.TrimSpace(key) == "" {
				log.Printf("⚠️ 跳过空密钥 (索引: %d)", actualIndex)
				results[actualIndex] = map[string]interface{}{
					"index":   actualIndex,
					"api_key": key,
					"status":  string(KeyValidationInvalid),
					"valid":   false,
					"error":   "Empty API key",
				}
				return
			}

			log.Printf("🎯 开始验证密钥 %d/%d: %s", actualIndex+1, len(results), s.maskKey(key))

			// 验证密钥，最多重试3次
			valid, err := s.validateKeyWithRetry(groupID, key, testModel, group, 3)

			validationError := ""
			if err != nil {
				validationError = err.Error()
			}

			status := KeyValidationUnknown
			var persistIsValid *bool
			if valid {
				status = KeyValidationValid
				isValid := true
				persistIsValid = &isValid
				log.Printf("✅ 密钥验证成功 %d/%d: %s", actualIndex+1, len(results), s.maskKey(key))
			} else {
				status, persistIsValid = classifyKeyValidation(err)
				log.Printf("❌ 密钥验证失败 %d/%d: %s (status=%s) - %s", actualIndex+1, len(results), s.maskKey(key), status, validationError)
			}

			// 异步更新数据库，避免阻塞验证流程
			if groupID != "temp" { // 只有非临时分组才更新数据库
				go func(gID, apiKey string, isValid *bool, errMsg string) {
					if updateErr := s.configManager.UpdateAPIKeyValidation(gID, apiKey, isValid, errMsg); updateErr != nil {
						log.Printf("❌ 更新数据库验证状态失败 %s: %v", s.maskKey(apiKey), updateErr)
					} else {
						isValidStr := "unknown"
						if isValid != nil {
							isValidStr = fmt.Sprintf("%v", *isValid)
						}
						log.Printf("💾 数据库验证状态已更新: %s (is_valid=%s)", s.maskKey(apiKey), isValidStr)
					}
				}(groupID, key, persistIsValid, validationError)
			}

			results[actualIndex] = map[string]interface{}{
				"index":   actualIndex,
				"api_key": key,
				"status":  string(status),
				"valid":   status == KeyValidationValid,
				"error":   validationError,
			}
		}(i, apiKey)
	}

	// 等待当前批次的所有验证完成
	wg.Wait()
}

// maskKey 遮蔽API密钥的敏感部分
func (s *MultiProviderServer) maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// handleKeysStatus 处理获取所有分组密钥状态的请求
func (s *MultiProviderServer) handleKeysStatus(c *gin.Context) {
	allGroups := s.configManager.GetAllGroups()
	groupsStatus := make(map[string]interface{})

	for groupID, group := range allGroups {
		if !group.Enabled {
			continue // 跳过禁用的分组
		}

		// 选择用于测试的模型
		var testModel string
		if len(group.Models) > 0 {
			testModel = group.Models[0]
		} else {
			// 根据提供商类型选择默认测试模型
			switch group.ProviderType {
			case "openai", "azure_openai":
				testModel = "gpt-3.5-turbo"
			case "anthropic":
				testModel = "claude-3-haiku-20240307"
			case "gemini":
				testModel = "gemini-2.5-flash"
			default:
				testModel = "gpt-3.5-turbo"
			}
		}

		// 验证每个密钥
		validCount := 0
		invalidCount := 0
		keyResults := make([]map[string]interface{}, 0, len(group.APIKeys))

		for i, apiKey := range group.APIKeys {
			if strings.TrimSpace(apiKey) == "" {
				invalidCount++
				keyResults = append(keyResults, map[string]interface{}{
					"index": i,
					"valid": false,
					"error": "Empty API key",
				})
				continue
			}

			// 创建提供商配置
			providerConfig := &providers.ProviderConfig{
				BaseURL:         group.BaseURL,
				APIKey:          apiKey,
				Timeout:         10 * time.Minute, // 使用10分钟超时
				MaxRetries:      1,
				Headers:         group.Headers,
				ProviderType:    group.ProviderType,
				UseResponsesAPI: group.UseResponsesAPI,
			}

			// 获取提供商实例
			provider, err := s.proxy.GetProviderManager().GetProvider(fmt.Sprintf("%s_status_%d", groupID, i), providerConfig)
			if err != nil {
				invalidCount++
				keyResults = append(keyResults, map[string]interface{}{
					"index": i,
					"valid": false,
					"error": "Failed to create provider: " + err.Error(),
				})
				continue
			}

			// 验证密钥
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			_, err = provider.ChatCompletion(ctx, &providers.ChatCompletionRequest{
				Model:    testModel,
				Messages: []providers.ChatMessage{{Role: "user", Content: "test"}},
				// 移除MaxTokens限制，让提供商使用默认值
			})
			cancel()

			if err != nil {
				invalidCount++
				keyResults = append(keyResults, map[string]interface{}{
					"index": i,
					"valid": false,
					"error": err.Error(),
				})
			} else {
				validCount++
				keyResults = append(keyResults, map[string]interface{}{
					"index": i,
					"valid": true,
					"error": "",
				})
			}
		}

		groupsStatus[groupID] = map[string]interface{}{
			"group_name":    group.Name,
			"provider_type": group.ProviderType,
			"test_model":    testModel,
			"total_keys":    len(group.APIKeys),
			"valid_keys":    validCount,
			"invalid_keys":  invalidCount,
			"key_results":   keyResults,
			"last_checked":  time.Now().Format("2006-01-02 15:04:05"),
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    groupsStatus,
	})
}

// handleTestModels 处理测试模型加载请求
func (s *MultiProviderServer) handleTestModels(c *gin.Context) {
	var testGroup struct {
		Name             string   `json:"name"`
		ProviderType     string   `json:"provider_type"`
		BaseURL          string   `json:"base_url"`
		Enabled          bool     `json:"enabled"`
		Timeout          int      `json:"timeout"`
		MaxRetries       int      `json:"max_retries"`
		RotationStrategy string   `json:"rotation_strategy"`
		APIKeys          []string `json:"api_keys"`
	}

	if err := c.ShouldBindJSON(&testGroup); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request data: " + err.Error(),
		})
		return
	}

	// 验证必需字段
	if testGroup.ProviderType == "" || testGroup.BaseURL == "" || len(testGroup.APIKeys) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Provider type, base URL, and at least one API key are required",
		})
		return
	}

	// 创建临时的UserGroup配置
	tempGroup := &internal.UserGroup{
		Name:             testGroup.Name,
		ProviderType:     testGroup.ProviderType,
		BaseURL:          testGroup.BaseURL,
		Enabled:          testGroup.Enabled,
		Timeout:          time.Duration(testGroup.Timeout) * time.Second,
		MaxRetries:       testGroup.MaxRetries,
		RotationStrategy: testGroup.RotationStrategy,
		APIKeys:          testGroup.APIKeys,
	}

	// 使用第一个API密钥来测试模型加载
	if len(testGroup.APIKeys) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "No API keys provided",
		})
		return
	}

	// 创建提供商配置
	providerConfig := &providers.ProviderConfig{
		BaseURL:      tempGroup.BaseURL,
		APIKey:       testGroup.APIKeys[0], // 使用第一个密钥进行测试
		Timeout:      tempGroup.Timeout,
		MaxRetries:   tempGroup.MaxRetries,
		ProviderType: tempGroup.ProviderType,
	}

	// 获取提供商实例
	provider, err := s.proxy.GetProviderManager().GetProvider("test", providerConfig)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to create provider instance: " + err.Error(),
		})
		return
	}

	// 获取模型列表
	ctx := c.Request.Context()
	rawModels, err := provider.GetModels(ctx)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"success": false,
			"message": "Failed to load models: " + err.Error(),
		})
		return
	}

	// 标准化模型数据格式
	standardizedModels := s.proxy.StandardizeModelsResponse(rawModels, tempGroup.ProviderType)

	// 返回模型列表
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"models":  standardizedModels,
	})
}

// handleIndex 处理首页
func (s *MultiProviderServer) handleIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "TurnsAPI - 多提供商代理服务",
	})
}

// handleMultiProviderDashboard 处理多提供商仪表板页面
func (s *MultiProviderServer) handleMultiProviderDashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "multi_provider_dashboard.html", gin.H{
		"title": "多提供商仪表板 - TurnsAPI",
	})
}

// handleHealth 处理健康检查
func (s *MultiProviderServer) handleHealth(c *gin.Context) {
	systemHealth := s.healthChecker.GetSystemHealth()

	status := "healthy"
	if systemHealth.Status != "healthy" {
		status = systemHealth.Status
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    status,
		"timestamp": time.Now(),
	})
}

// Start 启动服务器
func (s *MultiProviderServer) Start() error {
	s.httpServer = &http.Server{
		Addr:              s.config.GetAddress(),
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("Starting multi-provider server on %s", s.config.GetAddress())
	return s.httpServer.ListenAndServe()
}

// Stop 停止服务器
func (s *MultiProviderServer) Stop(ctx context.Context) error {
	// 关闭健康检查器
	if s.healthChecker != nil {
		s.healthChecker.Close()
	}

	// 关闭密钥管理器
	if s.keyManager != nil {
		s.keyManager.Close()
	}

	// 关闭请求日志记录器
	if s.requestLogger != nil {
		if err := s.requestLogger.Close(); err != nil {
			log.Printf("Failed to close request logger: %v", err)
		}
	}

	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// handleLogs 处理日志查询
func (s *MultiProviderServer) handleLogs(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	// 构建筛选条件
	filter := &logger.LogFilter{
		ProxyKeyName:  c.Query("proxy_key_name"),
		ProviderGroup: c.Query("provider_group"),
		Model:         c.Query("model"),
		Status:        c.Query("status"),
		Stream:        c.Query("stream"),
		Limit:         50,
		Offset:        0,
	}

	// 解析分页参数
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			filter.Limit = l
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			filter.Offset = o
		}
	}

	// 获取日志列表
	logs, err := s.requestLogger.GetRequestLogsWithFilter(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to get logs: " + err.Error(),
		})
		return
	}

	// 获取总数
	totalCount, err := s.requestLogger.GetRequestCountWithFilter(filter)
	if err != nil {
		log.Printf("Failed to get logs count: %v", err)
		totalCount = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"logs":        logs,
		"total_count": totalCount,
	})
}

// handleLogFilterOptions 处理日志筛选项查询
func (s *MultiProviderServer) handleLogFilterOptions(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	options, err := s.requestLogger.GetLogFilterOptions()
	if err != nil {
		log.Printf("Failed to get log filter options: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to get log filter options",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"options": options,
	})
}

// handleLogDetail 处理日志详情查询
func (s *MultiProviderServer) handleLogDetail(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	idStr := c.Param("id")
	if idStr == "filters" {
		s.handleLogFilterOptions(c)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid log ID",
		})
		return
	}

	logDetail, err := s.requestLogger.GetRequestLogDetail(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Log not found: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"log":     logDetail,
	})
}

// handleAPIKeyStats 处理API密钥统计
func (s *MultiProviderServer) handleAPIKeyStats(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	stats, err := s.requestLogger.GetProxyKeyStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to get API key stats: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

func (s *MultiProviderServer) handleLogsOverviewStats(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	stats, err := s.requestLogger.GetLogOverviewStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to get logs overview stats: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

func (s *MultiProviderServer) handleLogsChartsStats(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	filter := s.parseLogFilterWithRange(c)

	var (
		statusStats   *logger.StatusStats
		modelStats    []*logger.ModelStats
		tokenTimeline []*logger.TimelinePoint
		groupTokens   []*logger.GroupTokensStat
		firstErr      error
		errMu         sync.Mutex
		wg            sync.WaitGroup
	)

	setErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

	wg.Add(4)

	go func() {
		defer wg.Done()
		stats, err := s.requestLogger.GetStatusStats(filter)
		if err != nil {
			setErr(fmt.Errorf("failed to get status stats: %w", err))
			return
		}
		statusStats = stats
	}()

	go func() {
		defer wg.Done()
		stats, err := s.requestLogger.GetModelStatsWithFilter(filter)
		if err != nil {
			setErr(fmt.Errorf("failed to get model stats: %w", err))
			return
		}
		if len(stats) > 10 {
			stats = stats[:10]
		}
		modelStats = stats
	}()

	go func() {
		defer wg.Done()
		points, err := s.requestLogger.GetTokensTimeline(filter)
		if err != nil {
			setErr(fmt.Errorf("failed to get tokens timeline: %w", err))
			return
		}
		tokenTimeline = points
	}()

	go func() {
		defer wg.Done()
		stats, err := s.requestLogger.GetGroupTokensStats(filter)
		if err != nil {
			setErr(fmt.Errorf("failed to get group tokens: %w", err))
			return
		}
		if len(stats) > 10 {
			stats = stats[:10]
		}
		groupTokens = stats
	}()

	wg.Wait()

	if firstErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   firstErr.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"status":         statusStats,
			"models":         modelStats,
			"token_timeline": tokenTimeline,
			"group_tokens":   groupTokens,
		},
	})
}

// handleModelStats 处理模型统计
func (s *MultiProviderServer) handleModelStats(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	filter := s.parseLogFilterWithRange(c)
	stats, err := s.requestLogger.GetModelStatsWithFilter(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to get model stats: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

// handleStatusDistribution 处理状态分布统计（简版：当前不支持时间/筛选）
func (s *MultiProviderServer) handleStatusDistribution(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "Request logger not available"})
		return
	}

	filter := s.parseLogFilterWithRange(c)
	stats, err := s.requestLogger.GetStatusStats(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to get status stats: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"success": stats.Success,
			"error":   stats.Error,
		},
	})
}

// handleTokensTimeline 处理Tokens时间线统计（简版：临时基于总量返回单点）
func (s *MultiProviderServer) handleTokensTimeline(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "Request logger not available"})
		return
	}

	filter := s.parseLogFilterWithRange(c)
	points, err := s.requestLogger.GetTokensTimeline(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to get tokens timeline: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    points,
	})
}

// handleGroupTokens 处理按分组统计tokens（简版：基于导出查询粗聚合）
func (s *MultiProviderServer) handleGroupTokens(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "Request logger not available"})
		return
	}

	filter := s.parseLogFilterWithRange(c)
	stats, err := s.requestLogger.GetGroupTokensStats(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to get group tokens: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}

// handleTotalTokensStats 处理总token数统计
func (s *MultiProviderServer) handleTotalTokensStats(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	stats, err := s.requestLogger.GetTotalTokensStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to get total tokens stats: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

// handleDeleteLogs 处理批量删除日志
func (s *MultiProviderServer) handleDeleteLogs(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	if len(req.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "No log IDs provided",
		})
		return
	}

	deletedCount, err := s.requestLogger.DeleteRequestLogs(req.IDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to delete logs: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"deleted_count": deletedCount,
		"message":       fmt.Sprintf("Successfully deleted %d log records", deletedCount),
	})
}

// handleClearAllLogs 处理清空所有日志
func (s *MultiProviderServer) handleClearAllLogs(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	deletedCount, err := s.requestLogger.ClearAllRequestLogs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to clear all logs: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"deleted_count": deletedCount,
		"message":       fmt.Sprintf("Successfully cleared all logs, deleted %d records", deletedCount),
	})
}

// handleClearErrorLogs 处理清空错误日志
func (s *MultiProviderServer) handleClearErrorLogs(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	deletedCount, err := s.requestLogger.ClearErrorRequestLogs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to clear error logs: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"deleted_count": deletedCount,
		"message":       fmt.Sprintf("Successfully cleared error logs, deleted %d records", deletedCount),
	})
}

// handleExportLogs 处理导出日志
func (s *MultiProviderServer) handleExportLogs(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Request logger not available",
		})
		return
	}

	// 构建筛选条件
	filter := &logger.LogFilter{
		ProxyKeyName:  c.Query("proxy_key_name"),
		ProviderGroup: c.Query("provider_group"),
		Model:         c.Query("model"),
		Status:        c.Query("status"),
		Stream:        c.Query("stream"),
	}
	format := c.DefaultQuery("format", "csv") // 支持csv和json格式

	// 获取所有日志数据
	logs, err := s.requestLogger.GetAllRequestLogsForExportWithFilter(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to export logs: " + err.Error(),
		})
		return
	}

	if format == "csv" {
		// 导出为CSV格式
		var buf bytes.Buffer
		writer := csv.NewWriter(&buf)

		// 写入CSV头部
		headers := []string{
			"ID", "代理密钥名称", "代理密钥ID", "提供商分组", "OpenRouter密钥", "模型",
			"状态码", "是否流式", "响应时间(ms)", "Token使用量", "错误信息", "创建时间",
		}
		if err := writer.Write(headers); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Failed to write CSV headers: " + err.Error(),
			})
			return
		}

		// 写入数据行
		for _, log := range logs {
			record := []string{
				fmt.Sprintf("%d", log.ID),
				log.ProxyKeyName,
				log.ProxyKeyID,
				log.ProviderGroup,
				log.OpenRouterKey,
				log.Model,
				fmt.Sprintf("%d", log.StatusCode),
				fmt.Sprintf("%t", log.IsStream),
				fmt.Sprintf("%d", log.Duration),
				fmt.Sprintf("%d", log.TokensUsed),
				log.Error,
				log.CreatedAt.Format("2006-01-02 15:04:05"),
			}
			if err := writer.Write(record); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"error":   "Failed to write CSV record: " + err.Error(),
				})
				return
			}
		}

		writer.Flush()
		if err := writer.Error(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Failed to flush CSV writer: " + err.Error(),
			})
			return
		}

		// 设置响应头
		filename := fmt.Sprintf("request_logs_%s.csv", time.Now().Format("20060102_150405"))
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Data(http.StatusOK, "text/csv", buf.Bytes())
	} else {
		// 导出为JSON格式
		filename := fmt.Sprintf("request_logs_%s.json", time.Now().Format("20060102_150405"))
		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"logs":    logs,
			"count":   len(logs),
		})
	}
}

// sortProxyKeys 对代理密钥列表进行排序
func (s *MultiProviderServer) sortProxyKeys(keys []*proxykey.ProxyKey, sortBy string) {
	switch sortBy {
	case "created_time_desc":
		// 按创建时间倒序排列（默认）
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].CreatedAt.After(keys[j].CreatedAt)
		})
	case "created_time_asc":
		// 按创建时间正序排列
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].CreatedAt.Before(keys[j].CreatedAt)
		})
	case "usage_count_desc":
		// 按使用次数最多排列
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].UsageCount > keys[j].UsageCount
		})
	case "usage_count_asc":
		// 按使用次数最少排列
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].UsageCount < keys[j].UsageCount
		})
	case "name_asc":
		// 按名称正序排列
		sort.Slice(keys, func(i, j int) bool {
			return strings.ToLower(keys[i].Name) < strings.ToLower(keys[j].Name)
		})
	case "name_desc":
		// 按名称倒序排列
		sort.Slice(keys, func(i, j int) bool {
			return strings.ToLower(keys[i].Name) > strings.ToLower(keys[j].Name)
		})
	default:
		// 默认按创建时间倒序排列
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].CreatedAt.After(keys[j].CreatedAt)
		})
	}
}

// handleProxyKeys 处理代理密钥列表查询（支持分页、搜索和排序）
func (s *MultiProviderServer) handleProxyKeys(c *gin.Context) {
	// 获取查询参数
	page := 1
	pageSize := 10
	search := c.Query("search")
	sortBy := c.DefaultQuery("sort_by", "created_time_desc") // 默认按创建时间倒序

	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	// 获取所有密钥
	log.Printf("handleProxyKeys: Getting all keys from proxy key manager")
	allKeys := s.proxyKeyManager.GetAllKeys()
	log.Printf("handleProxyKeys: Retrieved %d keys from manager", len(allKeys))

	// 搜索过滤
	var filteredKeys []*proxykey.ProxyKey
	if search != "" {
		searchLower := strings.ToLower(search)
		for _, key := range allKeys {
			if strings.Contains(strings.ToLower(key.Name), searchLower) ||
				strings.Contains(strings.ToLower(key.Description), searchLower) ||
				strings.Contains(strings.ToLower(key.Key), searchLower) {
				filteredKeys = append(filteredKeys, key)
			}
		}
	} else {
		filteredKeys = allKeys
	}

	// 排序处理
	s.sortProxyKeys(filteredKeys, sortBy)

	// 计算分页
	total := len(filteredKeys)
	totalPages := (total + pageSize - 1) / pageSize

	// 计算起始和结束索引
	start := (page - 1) * pageSize
	end := start + pageSize

	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	// 获取当前页的数据
	var pageKeys []*proxykey.ProxyKey
	if start < end {
		pageKeys = filteredKeys[start:end]
	} else {
		pageKeys = []*proxykey.ProxyKey{}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"keys":    pageKeys,
		"pagination": gin.H{
			"page":        page,
			"page_size":   pageSize,
			"total":       total,
			"total_pages": totalPages,
			"has_prev":    page > 1,
			"has_next":    page < totalPages,
		},
		"search":  search,
		"sort_by": sortBy,
	})
}

// handleGenerateProxyKey 处理生成代理密钥
func (s *MultiProviderServer) handleGenerateProxyKey(c *gin.Context) {
	var req struct {
		Name                 string                         `json:"name" binding:"required"`
		Description          string                         `json:"description"`
		AllowedGroups        []string                       `json:"allowedGroups"`        // 允许访问的分组ID列表
		GroupSelectionConfig *proxykey.GroupSelectionConfig `json:"groupSelectionConfig"` // 分组选择配置
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	key, err := s.proxyKeyManager.GenerateKeyWithConfig(req.Name, req.Description, req.AllowedGroups, req.GroupSelectionConfig)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate key",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"key":     key,
	})
}

// handleUpdateProxyKey 处理更新代理密钥
func (s *MultiProviderServer) handleUpdateProxyKey(c *gin.Context) {
	keyID := c.Param("id")

	var req struct {
		Name                 string                         `json:"name" binding:"required"`
		Description          string                         `json:"description"`
		IsActive             *bool                          `json:"is_active"`
		AllowedGroups        []string                       `json:"allowedGroups"`        // 保持与生成时一致的字段名
		GroupSelectionConfig *proxykey.GroupSelectionConfig `json:"groupSelectionConfig"` // 分组选择配置
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// 如果没有提供 IsActive，默认为 true
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	// 如果没有提供 AllowedGroups，默认为空数组
	allowedGroups := req.AllowedGroups
	if allowedGroups == nil {
		allowedGroups = []string{}
	}

	if err := s.proxyKeyManager.UpdateKeyWithConfig(keyID, req.Name, req.Description, isActive, allowedGroups, req.GroupSelectionConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理密钥更新成功",
	})
}

// handleDeleteProxyKey 处理删除代理密钥
func (s *MultiProviderServer) handleDeleteProxyKey(c *gin.Context) {
	id := c.Param("id")

	err := s.proxyKeyManager.DeleteKey(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Key not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
	})
}

// handleProxyKeyGroupStats 处理获取代理密钥分组使用统计
func (s *MultiProviderServer) handleProxyKeyGroupStats(c *gin.Context) {
	keyID := c.Param("id")

	stats, err := s.proxyKeyManager.GetGroupUsageStats(keyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

// handleLogsPage 处理日志页面
func (s *MultiProviderServer) handleLogsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "logs.html", gin.H{
		"title": "请求日志 - TurnsAPI",
	})
}

// handleGroupsManagePage 处理分组管理页面
func (s *MultiProviderServer) handleGroupsManagePage(c *gin.Context) {
	c.HTML(http.StatusOK, "groups_manage.html", gin.H{
		"title": "分组管理 - TurnsAPI",
	})
}

// handleGroupsManage 处理分组管理API
func (s *MultiProviderServer) handleGroupsManage(c *gin.Context) {
	groups := make(map[string]interface{})

	allGroups := s.configManager.GetAllGroups()
	for groupID, group := range allGroups {
		groupInfo := map[string]interface{}{
			"group_id":              groupID,
			"group_name":            group.Name,
			"provider_type":         group.ProviderType,
			"base_url":              group.BaseURL,
			"api_version":           group.APIVersion,
			"enabled":               group.Enabled,
			"timeout":               group.Timeout.Seconds(),
			"max_retries":           group.MaxRetries,
			"rotation_strategy":     group.RotationStrategy,
			"api_keys":              group.APIKeys,
			"models":                group.Models,
			"headers":               group.Headers,
			"request_params":        group.RequestParams,
			"model_mappings":        group.ModelMappings,
			"use_native_response":   group.UseNativeResponse,
			"use_responses_api":     group.UseResponsesAPI,
			"rpm_limit":             group.RPMLimit,
			"disable_permanent_ban": group.DisablePermanentBan,
			"max_error_count":       group.MaxErrorCount,
			"rate_limit_cooldown":   group.RateLimitCooldown,
		}

		// 获取健康状态，如果没有健康检查记录则默认为健康
		if healthStatus, exists := s.healthChecker.GetProviderHealth(groupID); exists {
			groupInfo["healthy"] = healthStatus.Healthy
			groupInfo["last_error"] = healthStatus.LastError
		} else {
			// 新分组默认为健康状态
			groupInfo["healthy"] = true
			groupInfo["last_check"] = nil
			groupInfo["response_time"] = 0
			groupInfo["last_error"] = ""
		}

		groups[groupID] = groupInfo
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"groups":  groups,
	})
}

// handleCreateGroup 处理创建分组
func (s *MultiProviderServer) handleCreateGroup(c *gin.Context) {
	var req struct {
		GroupID             string                 `json:"group_id" binding:"required"`
		Name                string                 `json:"name" binding:"required"`
		ProviderType        string                 `json:"provider_type" binding:"required"`
		BaseURL             string                 `json:"base_url" binding:"required"`
		APIVersion          string                 `json:"api_version"`
		Enabled             bool                   `json:"enabled"`
		Timeout             interface{}            `json:"timeout"`
		MaxRetries          interface{}            `json:"max_retries"`
		RotationStrategy    string                 `json:"rotation_strategy"`
		APIKeys             []string               `json:"api_keys"`
		Models              []string               `json:"models"`
		Headers             map[string]string      `json:"headers"`
		RequestParams       map[string]interface{} `json:"request_params"`
		ModelMappings       map[string]string      `json:"model_mappings"`
		UseNativeResponse   bool                   `json:"use_native_response"`
		UseResponsesAPI     bool                   `json:"use_responses_api"`
		RPMLimit            interface{}            `json:"rpm_limit"`
		DisablePermanentBan bool                   `json:"disable_permanent_ban"`
		MaxErrorCount       interface{}            `json:"max_error_count"`
		RateLimitCooldown   interface{}            `json:"rate_limit_cooldown"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format: " + err.Error(),
		})
		return
	}
	timeoutSeconds, err := parseOptionalJSONFloat64(req.Timeout, 30, "timeout")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format: " + err.Error(),
		})
		return
	}

	maxRetries, err := parseOptionalJSONInt(req.MaxRetries, 3, "max_retries")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format: " + err.Error(),
		})
		return
	}

	rpmLimit, err := parseOptionalJSONInt(req.RPMLimit, 0, "rpm_limit")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format: " + err.Error(),
		})
		return
	}

	maxErrorCount, err := parseOptionalJSONInt(req.MaxErrorCount, 10, "max_error_count")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format: " + err.Error(),
		})
		return
	}

	rateLimitCooldown, err := parseOptionalJSONInt(req.RateLimitCooldown, 0, "rate_limit_cooldown")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format: " + err.Error(),
		})
		return
	}

	// 检查分组ID是否已存在
	if _, exists := s.configManager.GetGroup(req.GroupID); exists {
		c.JSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "Group ID already exists",
		})
		return
	}

	// 验证提供商类型
	supportedTypes := []string{"openai", "gemini", "anthropic", "azure_openai"}
	supported := false
	for _, supportedType := range supportedTypes {
		if req.ProviderType == supportedType {
			supported = true
			break
		}
	}

	if !supported {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("Unsupported provider type: %s", req.ProviderType),
		})
		return
	}

	// 设置默认值
	if req.RotationStrategy == "" {
		req.RotationStrategy = "round_robin"
	}
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}
	if req.Headers["Content-Type"] == "" {
		req.Headers["Content-Type"] = "application/json"
	}
	if req.RequestParams == nil {
		req.RequestParams = make(map[string]interface{})
	}
	if req.ModelMappings == nil {
		req.ModelMappings = make(map[string]string)
	}

	// 创建新的用户分组，直接使用提供的密钥（前端已去重）
	newGroup := &internal.UserGroup{
		Name:                req.Name,
		ProviderType:        req.ProviderType,
		BaseURL:             req.BaseURL,
		APIVersion:          req.APIVersion,
		Enabled:             req.Enabled,
		Timeout:             time.Duration(timeoutSeconds * float64(time.Second)),
		MaxRetries:          maxRetries,
		RotationStrategy:    req.RotationStrategy,
		APIKeys:             req.APIKeys, // 直接使用前端提供的密钥
		Models:              req.Models,
		Headers:             req.Headers,
		RequestParams:       req.RequestParams,
		ModelMappings:       req.ModelMappings,
		UseNativeResponse:   req.UseNativeResponse,
		UseResponsesAPI:     req.UseResponsesAPI,
		RPMLimit:            rpmLimit,
		DisablePermanentBan: req.DisablePermanentBan,
		MaxErrorCount:       maxErrorCount,
		RateLimitCooldown:   rateLimitCooldown,
	}

	// 保存到配置管理器（会同时更新数据库和内存）
	if err := s.configManager.SaveGroup(req.GroupID, newGroup); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to save group: " + err.Error(),
		})
		return
	}

	// 更新密钥管理器
	if err := s.keyManager.UpdateGroupConfig(req.GroupID, newGroup); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to update key manager: " + err.Error(),
		})
		return
	}

	// 更新RPM限制
	s.proxy.UpdateRPMLimit(req.GroupID, rpmLimit)

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"message":  "Group created successfully",
		"group_id": req.GroupID,
	})
}

// handleUpdateGroup 处理更新分组
func (s *MultiProviderServer) handleUpdateGroup(c *gin.Context) {
	groupID := c.Param("groupId")

	// 检查分组是否存在
	existingGroup, exists := s.configManager.GetGroup(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "Group not found",
		})
		return
	}

	var req struct {
		Name                string                 `json:"name"`
		ProviderType        string                 `json:"provider_type"`
		BaseURL             string                 `json:"base_url"`
		APIVersion          string                 `json:"api_version"`
		Enabled             *bool                  `json:"enabled"`
		Timeout             interface{}            `json:"timeout"`
		MaxRetries          interface{}            `json:"max_retries"`
		RotationStrategy    string                 `json:"rotation_strategy"`
		APIKeys             []string               `json:"api_keys"`
		Models              []string               `json:"models"`
		Headers             map[string]string      `json:"headers"`
		RequestParams       map[string]interface{} `json:"request_params"`
		ModelMappings       map[string]string      `json:"model_mappings"`
		UseNativeResponse   *bool                  `json:"use_native_response"`
		UseResponsesAPI     *bool                  `json:"use_responses_api"`
		RPMLimit            interface{}            `json:"rpm_limit"`
		DisablePermanentBan *bool                  `json:"disable_permanent_ban"`
		MaxErrorCount       interface{}            `json:"max_error_count"`
		RateLimitCooldown   interface{}            `json:"rate_limit_cooldown"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format: " + err.Error(),
		})
		return
	}

	// 更新字段（只更新提供的字段）
	var err error
	var parsedTimeoutSeconds float64
	if req.Timeout != nil {
		parsedTimeoutSeconds, err = parseOptionalJSONFloat64(
			req.Timeout,
			existingGroup.Timeout.Seconds(),
			"timeout",
		)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "Invalid request format: " + err.Error(),
			})
			return
		}
	}

	var parsedMaxRetries int
	if req.MaxRetries != nil {
		parsedMaxRetries, err = parseOptionalJSONInt(
			req.MaxRetries,
			existingGroup.MaxRetries,
			"max_retries",
		)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "Invalid request format: " + err.Error(),
			})
			return
		}
	}

	var parsedRPMLimit int
	if req.RPMLimit != nil {
		parsedRPMLimit, err = parseOptionalJSONInt(
			req.RPMLimit,
			existingGroup.RPMLimit,
			"rpm_limit",
		)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "Invalid request format: " + err.Error(),
			})
			return
		}
	}

	var parsedMaxErrorCount int
	if req.MaxErrorCount != nil {
		parsedMaxErrorCount, err = parseOptionalJSONInt(
			req.MaxErrorCount,
			existingGroup.MaxErrorCount,
			"max_error_count",
		)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "Invalid request format: " + err.Error(),
			})
			return
		}
	}

	var parsedRateLimitCooldown int
	if req.RateLimitCooldown != nil {
		parsedRateLimitCooldown, err = parseOptionalJSONInt(
			req.RateLimitCooldown,
			existingGroup.RateLimitCooldown,
			"rate_limit_cooldown",
		)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "Invalid request format: " + err.Error(),
			})
			return
		}
	}

	if req.Name != "" {
		existingGroup.Name = req.Name
	}
	if req.ProviderType != "" {
		// 验证提供商类型
		supportedTypes := []string{"openai", "gemini", "anthropic", "azure_openai"}
		supported := false
		for _, supportedType := range supportedTypes {
			if req.ProviderType == supportedType {
				supported = true
				break
			}
		}

		if !supported {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": fmt.Sprintf("Unsupported provider type: %s", req.ProviderType),
			})
			return
		}
		existingGroup.ProviderType = req.ProviderType
	}
	if req.BaseURL != "" {
		existingGroup.BaseURL = req.BaseURL
	}
	// api_version 可以是空字符串（对于非 Azure 提供商），所以总是更新它
	existingGroup.APIVersion = req.APIVersion
	if req.Enabled != nil {
		existingGroup.Enabled = *req.Enabled
	}
	if req.Timeout != nil {
		existingGroup.Timeout = time.Duration(parsedTimeoutSeconds * float64(time.Second))
	}
	if req.MaxRetries != nil {
		existingGroup.MaxRetries = parsedMaxRetries
	}
	if req.RotationStrategy != "" {
		existingGroup.RotationStrategy = req.RotationStrategy
	}
	if req.APIKeys != nil {
		existingGroup.APIKeys = req.APIKeys // 直接使用前端提供的密钥（前端已去重）
	}
	if req.Models != nil {
		existingGroup.Models = req.Models
	}
	if req.Headers != nil {
		existingGroup.Headers = req.Headers
	}
	if req.RequestParams != nil {
		existingGroup.RequestParams = req.RequestParams
	}
	if req.ModelMappings != nil {
		existingGroup.ModelMappings = req.ModelMappings
	}
	if req.UseNativeResponse != nil {
		existingGroup.UseNativeResponse = *req.UseNativeResponse
	}
	if req.UseResponsesAPI != nil {
		existingGroup.UseResponsesAPI = *req.UseResponsesAPI
	}
	if req.RPMLimit != nil {
		existingGroup.RPMLimit = parsedRPMLimit
	}
	if req.DisablePermanentBan != nil {
		existingGroup.DisablePermanentBan = *req.DisablePermanentBan
	}
	if req.MaxErrorCount != nil {
		existingGroup.MaxErrorCount = parsedMaxErrorCount
	}
	if req.RateLimitCooldown != nil {
		existingGroup.RateLimitCooldown = parsedRateLimitCooldown
	}

	// 保存到配置管理器
	if err := s.configManager.UpdateGroup(groupID, existingGroup); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to update group: " + err.Error(),
		})
		return
	}

	// 清理该分组的已缓存提供商实例，使配置变更立即生效
	s.proxy.RemoveProvider(groupID)

	// 更新密钥管理器
	if err := s.keyManager.UpdateGroupConfig(groupID, existingGroup); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to update key manager: " + err.Error(),
		})
		return
	}

	// 更新RPM限制
	s.proxy.UpdateRPMLimit(groupID, existingGroup.RPMLimit)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Group updated successfully",
	})
}

// handleDeleteGroup 处理删除分组
func (s *MultiProviderServer) handleDeleteGroup(c *gin.Context) {
	groupID := c.Param("groupId")

	// 检查分组是否存在
	_, exists := s.configManager.GetGroup(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "Group not found",
		})
		return
	}

	// 检查是否是最后一个启用的分组
	enabledCount := s.configManager.GetEnabledGroupCount()
	currentGroup, _ := s.configManager.GetGroup(groupID)

	if enabledCount <= 1 && currentGroup.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Cannot delete the last enabled group",
		})
		return
	}

	// 从配置管理器中删除（会同时删除数据库和内存中的数据）
	if err := s.configManager.DeleteGroup(groupID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to delete group: " + err.Error(),
		})
		return
	}

	// 更新密钥管理器（传递nil表示删除）
	if err := s.keyManager.UpdateGroupConfig(groupID, nil); err != nil {
		log.Printf("警告: 删除分组 %s 时更新密钥管理器失败: %v", groupID, err)
	}

	// 同步清理代理密钥中的分组权限
	updatedProxyKeys := 0
	disabledProxyKeys := 0
	if s.proxyKeyManager != nil {
		updatedCount, disabledCount, err := s.proxyKeyManager.RemoveGroupFromAllKeys(groupID)
		if err != nil {
			log.Printf("警告: 删除分组 %s 时同步代理密钥权限失败: %v", groupID, err)
		} else {
			updatedProxyKeys = updatedCount
			disabledProxyKeys = disabledCount
		}
	}

	// 从健康检查器中移除分组
	s.healthChecker.RemoveGroup(groupID)

	// 从提供商管理器中移除分组
	s.proxy.RemoveProvider(groupID)

	c.JSON(http.StatusOK, gin.H{
		"success":                true,
		"message":                "Group deleted successfully",
		"updated_proxy_keys":     updatedProxyKeys,
		"disabled_proxy_keys":    disabledProxyKeys,
		"deleted_provider_group": groupID,
	})
}

// handleExportGroups 处理导出分组配置
func (s *MultiProviderServer) handleExportGroups(c *gin.Context) {
	var req struct {
		GroupIDs []string `json:"group_ids"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	// 获取要导出的分组配置
	exportConfig := make(map[string]*internal.UserGroup)

	for _, groupID := range req.GroupIDs {
		group, exists := s.configManager.GetGroup(groupID)
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error":   fmt.Sprintf("Group not found: %s", groupID),
			})
			return
		}
		exportConfig[groupID] = group
	}

	// 生成YAML配置
	yamlData, err := s.generateGroupsYAML(exportConfig)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to generate YAML: " + err.Error(),
		})
		return
	}

	// 设置响应头
	c.Header("Content-Type", "application/x-yaml")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=groups_config_%s.yaml",
		time.Now().Format("2006-01-02")))

	c.Data(http.StatusOK, "application/x-yaml", yamlData)
}

// handleImportGroups 处理导入分组配置
func (s *MultiProviderServer) handleImportGroups(c *gin.Context) {
	file, header, err := c.Request.FormFile("config_file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Failed to get uploaded file: " + err.Error(),
		})
		return
	}
	defer file.Close()

	// 检查文件类型
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".yaml") &&
		!strings.HasSuffix(strings.ToLower(header.Filename), ".yml") {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Only YAML files are supported",
		})
		return
	}

	// 读取文件内容
	fileContent, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to read file: " + err.Error(),
		})
		return
	}

	// 解析YAML配置
	importedGroups, err := s.parseGroupsYAML(fileContent)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Failed to parse YAML: " + err.Error(),
		})
		return
	}

	// 导入分组配置
	importedCount := 0
	errors := []string{}

	for groupID, group := range importedGroups {
		if err := s.configManager.SaveGroup(groupID, group); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to import group %s: %v", groupID, err))
			continue
		}

		// 更新密钥管理器
		if s.keyManager != nil {
			if err := s.keyManager.UpdateGroupConfig(groupID, group); err != nil {
				log.Printf("警告: 导入分组 %s 时更新密钥管理器失败: %v", groupID, err)
			}
		}

		importedCount++
	}

	response := gin.H{
		"success":        true,
		"imported_count": importedCount,
		"total_groups":   len(importedGroups),
	}

	if len(errors) > 0 {
		response["errors"] = errors
	}

	c.JSON(http.StatusOK, response)
}

// generateGroupsYAML 生成分组配置的YAML
func (s *MultiProviderServer) generateGroupsYAML(groups map[string]*internal.UserGroup) ([]byte, error) {
	// 创建导出配置结构
	exportConfig := struct {
		UserGroups map[string]*internal.UserGroup `yaml:"user_groups"`
	}{
		UserGroups: groups,
	}

	return yaml.Marshal(exportConfig)
}

// parseGroupsYAML 解析分组配置的YAML
func (s *MultiProviderServer) parseGroupsYAML(yamlData []byte) (map[string]*internal.UserGroup, error) {
	var importConfig struct {
		UserGroups map[string]*internal.UserGroup `yaml:"user_groups"`
	}

	if err := yaml.Unmarshal(yamlData, &importConfig); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if importConfig.UserGroups == nil {
		return nil, fmt.Errorf("no user_groups found in YAML")
	}

	// 验证导入的分组配置
	for groupID, group := range importConfig.UserGroups {
		if group == nil {
			return nil, fmt.Errorf("group %s is nil", groupID)
		}

		if group.Name == "" {
			return nil, fmt.Errorf("group %s has empty name", groupID)
		}

		if group.ProviderType == "" {
			return nil, fmt.Errorf("group %s has empty provider type", groupID)
		}

		if len(group.APIKeys) == 0 {
			return nil, fmt.Errorf("group %s has no API keys", groupID)
		}
	}

	return importConfig.UserGroups, nil
}

// handleToggleGroup 处理切换分组启用状态
func (s *MultiProviderServer) handleToggleGroup(c *gin.Context) {
	groupID := c.Param("groupId")

	// 使用配置管理器的切换方法（包含所有业务逻辑和数据库更新）
	if err := s.configManager.ToggleGroup(groupID); err != nil {
		if err.Error() == "group not found: "+groupID {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"message": "Group not found",
			})
		} else if err.Error() == "cannot disable the last enabled group" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "Cannot disable the last enabled group",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "Failed to toggle group: " + err.Error(),
			})
		}
		return
	}

	// 获取更新后的分组状态
	group, _ := s.configManager.GetGroup(groupID)

	// 更新密钥管理器
	if err := s.keyManager.UpdateGroupConfig(groupID, group); err != nil {
		log.Printf("警告: 切换分组 %s 状态时更新密钥管理器失败: %v", groupID, err)
	}

	action := "enabled"
	if !group.Enabled {
		action = "disabled"
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Group %s successfully", action),
		"enabled": group.Enabled,
	})
}

// handleValidateKeysWithoutGroup 处理不需要groupId的密钥验证请求（用于编辑分组时）
func (s *MultiProviderServer) handleValidateKeysWithoutGroup(c *gin.Context) {
	// 获取要验证的分组配置和密钥列表
	var req struct {
		Name             string            `json:"name"`
		ProviderType     string            `json:"provider_type"`
		BaseURL          string            `json:"base_url"`
		Enabled          bool              `json:"enabled"`
		Timeout          interface{}       `json:"timeout"`
		MaxRetries       interface{}       `json:"max_retries"`
		RotationStrategy string            `json:"rotation_strategy"`
		APIKeys          []string          `json:"api_keys"`
		Headers          map[string]string `json:"headers"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request data: " + err.Error(),
		})
		return
	}

	// 验证必需字段
	if req.ProviderType == "" || req.BaseURL == "" || len(req.APIKeys) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Provider type, base URL, and at least one API key are required",
		})
		return
	}

	maxRetries, err := parseOptionalJSONInt(req.MaxRetries, 3, "max_retries")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request data: " + err.Error(),
		})
		return
	}

	if _, err := parseOptionalJSONInt(req.Timeout, 30, "timeout"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request data: " + err.Error(),
		})
		return
	}

	// 创建临时的UserGroup配置
	tempGroup := &internal.UserGroup{
		Name:             req.Name,
		ProviderType:     req.ProviderType,
		BaseURL:          req.BaseURL,
		Enabled:          req.Enabled,
		Timeout:          10 * time.Minute, // 设置为10分钟超时
		MaxRetries:       maxRetries,
		RotationStrategy: req.RotationStrategy,
		APIKeys:          req.APIKeys,
		Headers:          req.Headers,
	}

	// 获取测试模型
	var testModel string
	// 根据提供商类型选择默认测试模型
	switch req.ProviderType {
	case "openai", "azure_openai":
		testModel = "gpt-3.5-turbo"
	case "anthropic":
		testModel = "claude-3-haiku-20240307"
	case "gemini":
		testModel = "gemini-2.5-flash"
	default:
		testModel = "gpt-3.5-turbo" // 默认模型
	}

	log.Printf("🔍 开始临时分组密钥验证: 名称=%s, 提供商=%s, 密钥数量=%d, 测试模型=%s",
		req.Name, req.ProviderType, len(req.APIKeys), testModel)

	// 使用批量验证模式，提高效率
	results := make([]map[string]interface{}, len(req.APIKeys))
	log.Printf("⚙️ 采用批量验证模式，批次大小=8，无固定延迟，提高验证效率")

	// 批量验证API密钥
	s.validateKeysInBatches("temp", req.APIKeys, testModel, tempGroup, results)

	// 所有验证已完成（顺序执行）
	log.Printf("✅ 所有临时分组密钥验证已完成")

	// 统计结果
	validCount := 0
	invalidCount := 0
	unknownCount := 0
	for _, result := range results {
		status, _ := result["status"].(string)
		switch status {
		case string(KeyValidationValid):
			validCount++
		case string(KeyValidationInvalid):
			invalidCount++
		default:
			unknownCount++
		}
	}

	log.Printf("📊 临时分组验证结果统计: 总计=%d, 有效=%d, 无效=%d, 未知=%d, 成功率=%.1f%%",
		len(req.APIKeys), validCount, invalidCount,
		unknownCount,
		float64(validCount)/float64(len(req.APIKeys))*100)

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"test_model":   testModel,
		"total_keys":   len(req.APIKeys),
		"valid_keys":   validCount,
		"invalid_keys": invalidCount,
		"unknown_keys": unknownCount,
		"results":      results,
	})
}

// handleGetKeyValidationStatus 获取API密钥验证状态
func (s *MultiProviderServer) handleGetKeyValidationStatus(c *gin.Context) {
	groupID := c.Param("groupId")

	// 检查分组是否存在
	_, exists := s.configManager.GetGroup(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "Group not found",
		})
		return
	}

	// 获取验证状态
	validationStatus, err := s.configManager.GetAPIKeyValidationStatus(groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to get validation status: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":           true,
		"group_id":          groupID,
		"validation_status": validationStatus,
	})
}

// handleGeminiNativeChat 处理Gemini原生聊天完成请求
func (s *MultiProviderServer) handleGeminiNativeChat(c *gin.Context) {
	// 尝试从上下文获取模型名称（通过分发器设置）
	model, exists := c.Get("model")
	var modelStr string
	if exists {
		modelStr, _ = model.(string)
	}

	// 如果上下文中没有，尝试从URL参数获取
	if modelStr == "" {
		modelStr = c.Param("model")
	}

	// 解析Gemini原生请求格式
	var nativeReq map[string]interface{}
	if err := c.ShouldBindJSON(&nativeReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": "Invalid request format: " + err.Error(),
				"code":    "invalid_request",
			},
		})
		return
	}

	// 转换为标准请求格式
	standardReq, err := s.convertGeminiNativeToStandard(nativeReq, modelStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": "Failed to convert request: " + err.Error(),
				"code":    "conversion_error",
			},
		})
		return
	}

	// 强制使用原生响应格式
	c.Set("force_native_response", true)
	c.Set("target_provider", "gemini")

	// 确保代理密钥信息正确传递到上下文中
	s.ensureProxyKeyInfoInContext(c)

	// 调用标准聊天完成处理
	s.handleChatCompletionsWithRequest(c, standardReq)
}

// handleGeminiNativeStreamChat 处理Gemini原生流式聊天完成请求
func (s *MultiProviderServer) handleGeminiNativeStreamChat(c *gin.Context) {
	// 尝试从上下文获取模型名称（通过分发器设置）
	model, exists := c.Get("model")
	var modelStr string
	if exists {
		modelStr, _ = model.(string)
	}

	// 如果上下文中没有，尝试从URL参数获取
	if modelStr == "" {
		modelStr = c.Param("model")
	}

	// 解析Gemini原生请求格式
	var nativeReq map[string]interface{}
	if err := c.ShouldBindJSON(&nativeReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": "Invalid request format",
				"code":    "invalid_request",
			},
		})
		return
	}

	// 转换为标准请求格式
	standardReq, err := s.convertGeminiNativeToStandard(nativeReq, modelStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": "Failed to convert request: " + err.Error(),
				"code":    "conversion_error",
			},
		})
		return
	}

	// 强制启用流式响应和原生格式
	standardReq.Stream = true
	c.Set("force_native_response", true)
	c.Set("target_provider", "gemini")

	// 确保代理密钥信息正确传递到上下文中
	s.ensureProxyKeyInfoInContext(c)

	// 调用标准聊天完成处理
	s.handleChatCompletionsWithRequest(c, standardReq)
}

// handleGeminiNativeModels 处理Gemini原生模型列表请求
func (s *MultiProviderServer) handleGeminiNativeModels(c *gin.Context) {
	// 获取密钥信息
	keyInfo, exists := c.Get("key_info")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": gin.H{
				"message": "Authentication required",
				"code":    "unauthenticated",
			},
		})
		return
	}

	keyInfoStruct, ok := keyInfo.(*logger.ProxyKey)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"message": "Invalid key information",
				"code":    "internal_error",
			},
		})
		return
	}

	// 获取可访问的分组
	allowedGroups := keyInfoStruct.AllowedGroups
	if len(allowedGroups) == 0 {
		c.JSON(http.StatusForbidden, gin.H{
			"error": gin.H{
				"message": "No accessible groups",
				"code":    "permission_denied",
			},
		})
		return
	}

	// 收集所有Gemini模型
	var geminiModels []map[string]interface{}

	for _, groupID := range allowedGroups {
		group, exists := s.configManager.GetConfig().UserGroups[groupID]
		if !exists || !group.Enabled {
			continue
		}

		// 只处理Gemini提供商
		if group.ProviderType != "gemini" {
			continue
		}

		// 获取分组的模型列表
		for _, model := range group.Models {
			geminiModel := map[string]interface{}{
				"name":                       fmt.Sprintf("models/%s", model),
				"baseModelId":                model,
				"version":                    "001",
				"displayName":                model,
				"description":                fmt.Sprintf("Google %s model", model),
				"inputTokenLimit":            1048576, // 1M tokens
				"outputTokenLimit":           8192,
				"supportedGenerationMethods": []string{"generateContent", "streamGenerateContent"},
				"temperature":                0.9,
				"maxTemperature":             2.0,
				"topP":                       1.0,
				"topK":                       40,
			}
			geminiModels = append(geminiModels, geminiModel)
		}
	}

	// 返回Gemini原生格式
	c.JSON(http.StatusOK, gin.H{
		"models": geminiModels,
	})
}

// convertGeminiNativeToStandard 将Gemini原生请求格式转换为标准格式
func (s *MultiProviderServer) convertGeminiNativeToStandard(nativeReq map[string]interface{}, model string) (*providers.ChatCompletionRequest, error) {
	standardReq := &providers.ChatCompletionRequest{
		Model:  model,
		Stream: false,
	}

	// 解析contents字段
	if contents, ok := nativeReq["contents"].([]interface{}); ok {
		for _, content := range contents {
			if contentMap, ok := content.(map[string]interface{}); ok {
				message := providers.ChatMessage{}

				// 解析role
				if role, ok := contentMap["role"].(string); ok {
					if role == "user" {
						message.Role = "user"
					} else if role == "model" {
						message.Role = "assistant"
					} else {
						message.Role = role
					}
				}

				// 解析parts
				if parts, ok := contentMap["parts"].([]interface{}); ok {
					var contentText string
					for _, part := range parts {
						if partMap, ok := part.(map[string]interface{}); ok {
							if text, ok := partMap["text"].(string); ok {
								contentText += text
							}
						}
					}
					message.Content = contentText
				}

				standardReq.Messages = append(standardReq.Messages, message)
			}
		}
	}

	// 解析generationConfig
	if genConfig, ok := nativeReq["generationConfig"].(map[string]interface{}); ok {
		if temp, ok := genConfig["temperature"].(float64); ok {
			standardReq.Temperature = &temp
		}
		if maxTokens, ok := genConfig["maxOutputTokens"].(float64); ok {
			maxTokensInt := int(maxTokens)
			standardReq.MaxTokens = &maxTokensInt
		}
		if topP, ok := genConfig["topP"].(float64); ok {
			standardReq.TopP = &topP
		}
		if stopSequences, ok := genConfig["stopSequences"].([]interface{}); ok {
			for _, stop := range stopSequences {
				if stopStr, ok := stop.(string); ok {
					standardReq.Stop = append(standardReq.Stop, stopStr)
				}
			}
		}
	}

	return standardReq, nil
}

// ensureProxyKeyInfoInContext 确保代理密钥信息正确传递到上下文中
func (s *MultiProviderServer) ensureProxyKeyInfoInContext(c *gin.Context) {
	// 检查是否已经有代理密钥信息
	if _, exists := c.Get("proxy_key_name"); exists {
		return // 已经有了，不需要重复设置
	}

	// 从key_info中获取代理密钥信息
	if keyInfo, exists := c.Get("key_info"); exists {
		if proxyKey, ok := keyInfo.(*logger.ProxyKey); ok {
			// 设置代理密钥信息到上下文中
			c.Set("proxy_key_name", proxyKey.Name)
			c.Set("proxy_key_id", proxyKey.ID)

			// 更新代理密钥使用次数
			if s.proxyKeyManager != nil {
				s.proxyKeyManager.UpdateUsage(proxyKey.Key)
			}
		}
	}
}

// handleChatCompletionsWithRequest 使用指定请求处理聊天完成
func (s *MultiProviderServer) handleChatCompletionsWithRequest(c *gin.Context, req *providers.ChatCompletionRequest) {
	// 将请求设置到上下文中，这样代理可以直接使用
	c.Set("chat_request", req)

	// 调用标准聊天完成处理
	s.handleChatCompletions(c)
}

// handleGeminiBetaInfo 处理Gemini Beta API信息请求
func (s *MultiProviderServer) handleGeminiBetaInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"name":        "Gemini API (Beta)",
		"version":     "v1beta",
		"description": "Google Gemini native API endpoints",
		"endpoints": map[string]interface{}{
			"models": map[string]interface{}{
				"GET /v1/beta/models": "List available Gemini models",
			},
			"generateContent": map[string]interface{}{
				"POST /v1/beta/models/{model}/generateContent": "Generate content using Gemini native format",
			},
			"streamGenerateContent": map[string]interface{}{
				"POST /v1/beta/models/{model}/streamGenerateContent": "Generate content with streaming using Gemini native format",
			},
		},
		"documentation": "https://ai.google.dev/api/rest",
		"supported_models": []string{
			"gemini-2.5-pro",
			"gemini-2.5-flash",
			"gemini-1.5-pro",
			"gemini-1.5-flash",
		},
		"note": "This endpoint requires a valid API key and a Gemini provider group with use_native_response enabled",
	})
}

// handleGeminiNativeMethodDispatch 处理Gemini原生方法分发
func (s *MultiProviderServer) handleGeminiNativeMethodDispatch(c *gin.Context) {
	path := c.Param("path")

	// 解析路径格式: /model:method 或 /model/method
	var model, method string

	// 移除开头的斜杠
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}

	// 检查是否是冒号格式 (model:method)
	if strings.Contains(path, ":") {
		parts := strings.SplitN(path, ":", 2)
		if len(parts) == 2 {
			model = parts[0]
			method = parts[1]
		}
	} else {
		// 检查是否是斜杠格式 (model/method)
		parts := strings.SplitN(path, "/", 2)
		if len(parts) == 2 {
			model = parts[0]
			method = parts[1]
		}
	}

	if model == "" || method == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"message": fmt.Sprintf("Invalid path format. Expected /models/model:method or /models/model/method. Got: %s", path),
				"code":    "invalid_path",
			},
		})
		return
	}

	// 设置模型参数到上下文中
	c.Set("model", model)

	// 根据方法分发到相应的处理函数
	switch method {
	case "generateContent":
		s.handleGeminiNativeChat(c)
	case "streamGenerateContent":
		s.handleGeminiNativeStreamChat(c)
	default:
		c.JSON(http.StatusNotFound, gin.H{
			"error": gin.H{
				"message": fmt.Sprintf("Unknown method: %s", method),
				"code":    "method_not_found",
			},
		})
	}
}

// geminiAPIKeyAuthMiddleware Gemini API密钥认证中间件，支持x-goog-api-key头
// handleRefreshHealth 手动刷新所有分组的健康状态
func (s *MultiProviderServer) handleRefreshHealth(c *gin.Context) {
	if s.healthChecker == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":  "Health checker not initialized yet",
			"status": "initializing",
		})
		return
	}

	log.Printf("收到手动刷新健康状态请求")

	// 异步执行健康检查，避免阻塞请求
	go s.healthChecker.PerformHealthCheck()

	c.JSON(http.StatusOK, gin.H{
		"message": "Health check refresh initiated",
		"status":  "refreshing",
	})
}

// handleRefreshGroupHealth 手动刷新指定分组的健康状态
func (s *MultiProviderServer) handleRefreshGroupHealth(c *gin.Context) {
	if s.healthChecker == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":  "Health checker not initialized yet",
			"status": "initializing",
		})
		return
	}

	groupID := c.Param("groupId")

	// 检查分组是否存在
	_, exists := s.config.GetGroupByID(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	log.Printf("收到手动刷新分组 %s 健康状态请求", groupID)

	// 异步执行指定分组的健康检查
	go s.healthChecker.PerformInitialHealthCheck(groupID)

	c.JSON(http.StatusOK, gin.H{
		"message":  fmt.Sprintf("Health check refresh initiated for group %s", groupID),
		"status":   "refreshing",
		"group_id": groupID,
	})
}

func (s *MultiProviderServer) parseLogFilterWithRange(c *gin.Context) *logger.LogFilter {
	// 解析通用筛选
	f := &logger.LogFilter{
		ProxyKeyName:  c.Query("proxy_key_name"),
		ProviderGroup: c.Query("provider_group"),
		Model:         c.Query("model"),
		Status:        c.Query("status"),
		Stream:        c.Query("stream"),
	}

	// 解析 range: 支持 1h,6h,24h,7d,30d
	rangeStr := strings.TrimSpace(c.DefaultQuery("range", ""))
	now := time.Now()
	var start *time.Time
	var end *time.Time

	if rangeStr != "" {
		lower := strings.ToLower(rangeStr)
		switch lower {
		case "1h":
			st := now.Add(-1 * time.Hour)
			start, end = &st, &now
		case "6h":
			st := now.Add(-6 * time.Hour)
			start, end = &st, &now
		case "24h":
			st := now.Add(-24 * time.Hour)
			start, end = &st, &now
		case "7d":
			st := now.AddDate(0, 0, -7)
			start, end = &st, &now
		case "30d":
			st := now.AddDate(0, 0, -30)
			start, end = &st, &now
		}
	}

	// 显式起止时间（优先于range），格式：YYYY-MM-DD HH:MM:SS 或 YYYY-MM-DD
	parseTime := func(s string) *time.Time {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}
		layouts := []string{"2006-01-02 15:04:05", "2006-01-02", time.RFC3339}
		for _, layout := range layouts {
			if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
				return &t
			}
		}
		return nil
	}
	if qs := c.Query("start"); qs != "" {
		if t := parseTime(qs); t != nil {
			start = t
		}
	}
	if qe := c.Query("end"); qe != "" {
		if t := parseTime(qe); t != nil {
			end = t
		}
	}

	f.StartTime = start
	f.EndTime = end
	return f
}

func (s *MultiProviderServer) geminiAPIKeyAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var apiKey string

		// 首先尝试从x-goog-api-key头获取（Gemini原生API方式）
		if googAPIKey := c.GetHeader("x-goog-api-key"); googAPIKey != "" {
			apiKey = googAPIKey
		} else {
			// 然后尝试从Authorization头获取（标准Bearer方式）
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": gin.H{
						"message": "Missing API key. Use 'x-goog-api-key' header or 'Authorization: Bearer <key>' header",
						"type":    "authentication_error",
						"code":    "missing_api_key",
					},
				})
				c.Abort()
				return
			}

			// 检查Bearer格式
			const bearerPrefix = "Bearer "
			if !strings.HasPrefix(authHeader, bearerPrefix) {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": gin.H{
						"message": "Invalid Authorization header format. Use 'Authorization: Bearer <key>' or 'x-goog-api-key: <key>'",
						"type":    "authentication_error",
						"code":    "invalid_auth_format",
					},
				})
				c.Abort()
				return
			}

			apiKey = strings.TrimPrefix(authHeader, bearerPrefix)
		}

		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"message": "Empty API key",
					"type":    "authentication_error",
					"code":    "empty_api_key",
				},
			})
			c.Abort()
			return
		}

		// 验证API密钥
		if s.authManager == nil || s.proxyKeyManager == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": gin.H{
					"message": "Authentication system not configured",
					"type":    "internal_error",
					"code":    "auth_system_missing",
				},
			})
			c.Abort()
			return
		}

		keyInfo, valid := s.proxyKeyManager.ValidateKey(apiKey)
		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"message": "Invalid API key",
					"type":    "authentication_error",
					"code":    "invalid_api_key",
				},
			})
			c.Abort()
			return
		}

		// 将密钥信息存储到上下文中
		c.Set("key_info", keyInfo)
		c.Next()
	}
}

// handleForceKeyStatus 处理强行设置密钥有效状态
func (s *MultiProviderServer) handleForceKeyStatus(c *gin.Context) {
	groupID := c.Param("groupId")

	var req struct {
		APIKey   string `json:"api_key" binding:"required"`
		IsValid  bool   `json:"is_valid"`
		ForceSet bool   `json:"force_set"` // 是否强制设置，忽略实际验证
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format: " + err.Error(),
		})
		return
	}

	// 检查分组是否存在
	group, exists := s.configManager.GetGroup(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "Group not found",
		})
		return
	}

	// 检查API密钥是否属于该分组
	keyExists := false
	for _, key := range group.APIKeys {
		if key == req.APIKey {
			keyExists = true
			break
		}
	}

	if !keyExists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "API key not found in this group",
		})
		return
	}

	// 更新数据库中的验证状态
	validationError := ""
	if !req.IsValid {
		if req.ForceSet {
			validationError = "Manually set as invalid by administrator"
		} else {
			validationError = "Key validation failed"
		}
	}

	isValid := req.IsValid
	err := s.configManager.UpdateAPIKeyValidation(groupID, req.APIKey, &isValid, validationError)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to update key status: " + err.Error(),
		})
		return
	}

	// 更新密钥管理器中的状态
	if s.keyManager != nil {
		s.keyManager.UpdateKeyStatus(groupID, req.APIKey, req.IsValid, validationError)
	}

	action := "valid"
	if !req.IsValid {
		action = "invalid"
	}

	log.Printf("管理员强制设置密钥状态: 分组=%s, 密钥=%s, 状态=%s",
		groupID, s.maskKey(req.APIKey), action)

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"message":  fmt.Sprintf("API key status has been set to %s", action),
		"api_key":  s.maskKey(req.APIKey),
		"is_valid": req.IsValid,
	})
}

// handleDeleteInvalidKeys 处理一键删除失效密钥
func (s *MultiProviderServer) handleDeleteInvalidKeys(c *gin.Context) {
	groupID := c.Param("groupId")

	// 检查分组是否存在
	group, exists := s.configManager.GetGroup(groupID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "Group not found",
		})
		return
	}

	// 获取该分组的密钥验证状态
	validationStatus, err := s.configManager.GetAPIKeyValidationStatus(groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to get key validation status: " + err.Error(),
		})
		return
	}

	// 找出所有无效的密钥
	var invalidKeys []string
	var validKeys []string

	for _, apiKey := range group.APIKeys {
		if status, exists := validationStatus[apiKey]; exists {
			if isValid, ok := status["is_valid"].(*bool); ok && isValid != nil && !*isValid {
				invalidKeys = append(invalidKeys, apiKey)
			} else {
				validKeys = append(validKeys, apiKey)
			}
		} else {
			// 如果没有验证状态记录，默认认为是有效的
			validKeys = append(validKeys, apiKey)
		}
	}

	if len(invalidKeys) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success":         true,
			"message":         "No invalid keys found to delete",
			"deleted_count":   0,
			"remaining_count": len(validKeys),
		})
		return
	}

	// 检查删除后是否还有有效密钥
	if len(validKeys) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success":       false,
			"message":       "Cannot delete all keys. At least one valid key must remain in the group",
			"invalid_count": len(invalidKeys),
		})
		return
	}

	// 更新分组配置，移除无效密钥
	updatedGroup := *group // 创建副本
	updatedGroup.APIKeys = validKeys

	// 保存更新后的分组配置
	err = s.configManager.UpdateGroup(groupID, &updatedGroup)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to update group configuration: " + err.Error(),
		})
		return
	}

	// 更新密钥管理器
	if s.keyManager != nil {
		err = s.keyManager.UpdateGroupConfig(groupID, &updatedGroup)
		if err != nil {
			log.Printf("警告: 更新密钥管理器失败: %v", err)
		}
	}

	// 记录删除的密钥（用于日志）
	maskedInvalidKeys := make([]string, len(invalidKeys))
	for i, key := range invalidKeys {
		maskedInvalidKeys[i] = s.maskKey(key)
	}

	log.Printf("管理员删除失效密钥: 分组=%s, 删除数量=%d, 剩余数量=%d, 删除的密钥=%v",
		groupID, len(invalidKeys), len(validKeys), maskedInvalidKeys)

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"message":         fmt.Sprintf("Successfully deleted %d invalid keys", len(invalidKeys)),
		"deleted_count":   len(invalidKeys),
		"remaining_count": len(validKeys),
		"deleted_keys":    maskedInvalidKeys,
	})
}
