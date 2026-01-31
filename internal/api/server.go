package api

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"turnsapi/internal"
	"turnsapi/internal/auth"
	"turnsapi/internal/keymanager"
	"turnsapi/internal/logger"
	"turnsapi/internal/providers"
	"turnsapi/internal/proxy"
	"turnsapi/internal/proxykey"

	"github.com/gin-gonic/gin"
)

// Server HTTP服务器
type Server struct {
	config          *internal.Config
	keyManager      *keymanager.KeyManager
	proxy           *proxy.OpenRouterProxy
	authManager     *auth.AuthManager
	proxyKeyManager *proxykey.Manager
	requestLogger   *logger.RequestLogger
	router          *gin.Engine
	httpServer      *http.Server

	// 模型列表缓存
	modelsCacheData []byte
	modelsCacheTime time.Time
	modelsCacheTTL  time.Duration

	// 服务器启动时间
	startTime time.Time
}

// NewServer 创建新的HTTP服务器
func NewServer(config *internal.Config, keyManager *keymanager.KeyManager) *Server {
	// 设置Gin模式
	// 优先使用Server.Mode配置，如果未设置则根据日志级别判断
	switch config.Server.Mode {
	case "debug":
		gin.SetMode(gin.DebugMode)
	case "release":
		gin.SetMode(gin.ReleaseMode)
	case "test":
		gin.SetMode(gin.TestMode)
	default:
		// 向后兼容：如果Mode未设置或无效，则根据日志级别判断
		if config.Logging.Level == "debug" {
			gin.SetMode(gin.DebugMode)
		} else {
			gin.SetMode(gin.ReleaseMode)
		}
	}

	// 创建请求日志记录器
	requestLogger, err := logger.NewRequestLogger(config.Database.Path)
	if err != nil {
		log.Printf("Failed to create request logger: %v", err)
		// 继续运行，但不记录请求日志
		requestLogger = nil
	}

	// 创建带数据库支持的代理密钥管理器
	var proxyKeyManager *proxykey.Manager
	if requestLogger != nil {
		proxyKeyManager = proxykey.NewManagerWithDB(requestLogger)
	} else {
		proxyKeyManager = proxykey.NewManager()
	}

	server := &Server{
		config:          config,
		keyManager:      keyManager,
		authManager:     auth.NewAuthManager(config),
		proxyKeyManager: proxyKeyManager,
		requestLogger:   requestLogger,
		router:          gin.New(),
		modelsCacheTTL:  10 * time.Minute, // 模型列表缓存10分钟
		startTime:       time.Now(),       // 记录服务器启动时间
	}

	// 创建代理
	server.proxy = proxy.NewOpenRouterProxy(config, keyManager, requestLogger)

	// 设置代理密钥管理器到认证管理器
	server.authManager.SetProxyKeyManager(server.proxyKeyManager)

	// 设置中间件
	server.setupMiddleware()

	// 设置路由
	server.setupRoutes()

	return server
}

// setupMiddleware 设置中间件
func (s *Server) setupMiddleware() {
	// 日志中间件
	s.router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))

	// 恢复中间件
	s.router.Use(gin.Recovery())

	// CORS中间件
	s.router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 认证路由（不需要认证）
	auth := s.router.Group("/auth")
	{
		auth.GET("/login", s.handleLoginPage)
		auth.POST("/login", s.handleLogin)
		auth.POST("/logout", s.handleLogout)
	}

	// API路由组（需要API密钥认证）
	api := s.router.Group("/api/v1")
	api.Use(s.authManager.APIKeyAuthMiddleware())
	{
		// OpenRouter兼容的聊天完成端点
		api.POST("/chat/completions", s.handleChatCompletions)
		// 模型列表端点
		api.GET("/models", s.handleModels)
	}

	// Gemini原生API路由组（需要API密钥认证）
	geminiAPI := s.router.Group("/v1/beta")
	geminiAPI.Use(s.authManager.APIKeyAuthMiddleware())
	{
		// Gemini原生聊天完成端点
		geminiAPI.POST("/models/:model/generateContent", s.handleGeminiNativeChat)
		geminiAPI.POST("/models/:model/streamGenerateContent", s.handleGeminiNativeStreamChat)
		// Gemini模型列表端点
		geminiAPI.GET("/models", s.handleGeminiNativeModels)
	}

	// 管理路由组（需要认证）
	admin := s.router.Group("/admin")
	admin.Use(s.authManager.AuthMiddleware())
	{
		admin.GET("/status", s.handleStatus)
		admin.GET("/keys", s.handleKeysStatus)
		// API密钥管理
		admin.POST("/keys", s.handleAddKey)
		admin.POST("/keys/batch", s.handleAddKeysBatch)
		admin.PUT("/keys/:id", s.handleUpdateKey)
		admin.DELETE("/keys/:id", s.handleDeleteKey)
		// 代理服务API密钥管理
		admin.GET("/proxy-keys", s.handleProxyKeys)
		admin.POST("/proxy-keys", s.handleGenerateProxyKey)
		admin.PUT("/proxy-keys/:id", s.handleUpdateProxyKey)
		admin.DELETE("/proxy-keys/:id", s.handleDeleteProxyKey)
		// 获取完整模型列表（用于管理界面）
		admin.GET("/available-models", s.handleAvailableModels)
		// 请求日志管理
		admin.GET("/logs", s.handleRequestLogs)
		admin.GET("/logs/:id", s.handleRequestLogDetail)
		admin.GET("/logs/stats/api-keys", s.handleAPIKeyStats)
		admin.GET("/logs/stats/models", s.handleModelStats)
		admin.GET("/logs/stats/tokens", s.handleTotalTokensStats)
		// 新增聚合统计端点（与多提供商模式保持一致）
		admin.GET("/logs/stats/status", s.handleStatusDistribution)
		admin.GET("/logs/stats/tokens-timeline", s.handleTokensTimeline)
		admin.GET("/logs/stats/group-tokens", s.handleGroupTokens)
	}

	// 静态文件
	s.router.Static("/static", "./web/static")
	s.router.LoadHTMLGlob("web/templates/*")

	// Web界面（需要Web认证）
	s.router.GET("/", s.authManager.WebAuthMiddleware(), s.handleIndex)
	s.router.GET("/dashboard", s.authManager.WebAuthMiddleware(), s.handleDashboard)
	s.router.GET("/logs", s.authManager.WebAuthMiddleware(), s.handleLogsPage)

	// 健康检查（不需要认证）
	s.router.GET("/health", s.handleHealth)
}

// handleChatCompletions 处理聊天完成请求
func (s *Server) handleChatCompletions(c *gin.Context) {
	s.proxy.HandleChatCompletions(c)
}

// handleModels 处理模型列表请求
func (s *Server) handleModels(c *gin.Context) {
	s.proxy.HandleModels(c)
}

// handleLoginPage 显示登录页面
func (s *Server) handleLoginPage(c *gin.Context) {
	// 如果认证未启用，重定向到首页
	if !s.config.Auth.Enabled {
		c.Redirect(http.StatusFound, "/")
		return
	}

	// 如果已经登录，重定向到仪表板
	if token, err := c.Cookie("auth_token"); err == nil && token != "" {
		if _, valid := s.authManager.ValidateToken(token); valid {
			c.Redirect(http.StatusFound, "/dashboard")
			return
		}
	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "TurnsAPI - 登录",
	})
}

// handleLogin 处理登录请求
func (s *Server) handleLogin(c *gin.Context) {
	if !s.config.Auth.Enabled {
		c.JSON(http.StatusOK, gin.H{"success": true})
		return
	}

	var loginReq struct {
		Username string `json:"username" form:"username"`
		Password string `json:"password" form:"password"`
	}

	if err := c.ShouldBind(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "invalid_request",
		})
		return
	}

	session, err := s.authManager.Login(loginReq.Username, loginReq.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid username or password",
			"code":  "invalid_credentials",
		})
		return
	}

	// 设置cookie
	s.authManager.SetAuthCookie(c, session.Token)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"token":   session.Token,
		"expires": session.ExpiresAt,
	})
}

// handleLogout 处理登出请求
func (s *Server) handleLogout(c *gin.Context) {
	token, err := c.Cookie("auth_token")
	if err == nil && token != "" {
		s.authManager.Logout(token)
	}

	// 清除cookie
	s.authManager.ClearAuthCookie(c)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
	})
}

// handleAddKey 添加API密钥
func (s *Server) handleAddKey(c *gin.Context) {
	var req struct {
		Key           string   `json:"key" binding:"required"`
		Name          string   `json:"name"`
		Description   string   `json:"description"`
		AllowedModels []string `json:"allowed_models"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "invalid_request",
		})
		return
	}

	// 添加密钥到密钥管理器
	if err := s.keyManager.AddKey(req.Key, req.Name, req.Description, req.AllowedModels); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  "add_key_failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "API密钥添加成功",
	})
}

// handleAddKeysBatch 批量添加API密钥
func (s *Server) handleAddKeysBatch(c *gin.Context) {
	var req struct {
		Keys []string `json:"keys" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "invalid_request",
		})
		return
	}

	if len(req.Keys) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "密钥列表不能为空",
			"code":  "empty_keys",
		})
		return
	}

	// 批量添加密钥
	addedCount, errors, err := s.keyManager.AddKeysInBatch(req.Keys)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
			"code":  "batch_add_failed",
		})
		return
	}

	response := gin.H{
		"success":       true,
		"message":       fmt.Sprintf("批量添加完成，成功添加 %d 个密钥", addedCount),
		"added_count":   addedCount,
		"total_count":   len(req.Keys),
		"skipped_count": len(req.Keys) - addedCount,
	}

	if len(errors) > 0 {
		response["errors"] = errors
	}

	c.JSON(http.StatusOK, response)
}

// handleUpdateKey 更新API密钥
func (s *Server) handleUpdateKey(c *gin.Context) {
	keyID := c.Param("id")
	var req struct {
		Key           string   `json:"key"` // 新增：支持更新密钥本身
		Name          string   `json:"name"`
		Description   string   `json:"description"`
		IsActive      *bool    `json:"is_active"`
		AllowedModels []string `json:"allowed_models"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "invalid_request",
		})
		return
	}

	// 如果提供了新的密钥，使用UpdateKeyWithNewKey方法
	if req.Key != "" && req.Key != keyID {
		if err := s.keyManager.UpdateKeyWithNewKey(keyID, req.Key, req.Name, req.Description, req.IsActive, req.AllowedModels); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
				"code":  "update_key_failed",
			})
			return
		}
	} else {
		// 否则只更新其他信息
		if err := s.keyManager.UpdateKey(keyID, req.Name, req.Description, req.IsActive, req.AllowedModels); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
				"code":  "update_key_failed",
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "API密钥更新成功",
	})
}

// handleDeleteKey 删除API密钥
func (s *Server) handleDeleteKey(c *gin.Context) {
	keyID := c.Param("id")

	if err := s.keyManager.DeleteKey(keyID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  "delete_key_failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "API密钥删除成功",
	})
}

// handleProxyKeys 获取代理服务API密钥列表
func (s *Server) handleProxyKeys(c *gin.Context) {
	keys := s.proxyKeyManager.GetAllKeys()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"keys":    keys,
	})
}

// handleGenerateProxyKey 生成代理服务API密钥
func (s *Server) handleGenerateProxyKey(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "invalid_request",
		})
		return
	}

	key, err := s.proxyKeyManager.GenerateKey(req.Name, req.Description, []string{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate proxy key",
			"code":  "generate_key_failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"key":     key,
		"message": "代理服务API密钥生成成功",
	})
}

// handleUpdateProxyKey 更新代理服务API密钥
func (s *Server) handleUpdateProxyKey(c *gin.Context) {
	keyID := c.Param("id")

	var req struct {
		Name          string   `json:"name" binding:"required"`
		Description   string   `json:"description"`
		IsActive      *bool    `json:"is_active"`
		AllowedGroups []string `json:"allowed_groups"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "invalid_request",
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

	if err := s.proxyKeyManager.UpdateKey(keyID, req.Name, req.Description, isActive, allowedGroups); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  "update_proxy_key_failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理服务API密钥更新成功",
	})
}

// handleDeleteProxyKey 删除代理服务API密钥
func (s *Server) handleDeleteProxyKey(c *gin.Context) {
	keyID := c.Param("id")

	if err := s.proxyKeyManager.DeleteKey(keyID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  "delete_proxy_key_failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理服务API密钥删除成功",
	})
}

// handleStatus 处理状态查询
func (s *Server) handleStatus(c *gin.Context) {
	keyStatuses := s.keyManager.GetKeyStatuses()

	activeCount := 0
	totalCount := len(keyStatuses)

	for _, status := range keyStatuses {
		if status.IsActive {
			activeCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      "ok",
		"timestamp":   time.Now(),
		"active_keys": activeCount,
		"total_keys":  totalCount,
		"uptime":      time.Since(s.startTime), // 使用实际的启动时间
	})
}

// handleKeysStatus 处理密钥状态查询
func (s *Server) handleKeysStatus(c *gin.Context) {
	keyStatusesMap := s.keyManager.GetKeyStatuses()

	// 将map转换为数组
	keyStatuses := make([]*keymanager.KeyStatus, 0, len(keyStatusesMap))
	for _, status := range keyStatusesMap {
		keyStatuses = append(keyStatuses, status)
	}

	c.JSON(http.StatusOK, gin.H{
		"keys": keyStatuses,
	})
}

// handleIndex 处理首页
func (s *Server) handleIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "TurnsAPI - OpenRouter Proxy",
	})
}

// handleDashboard 处理仪表板页面
func (s *Server) handleDashboard(c *gin.Context) {
	keyStatuses := s.keyManager.GetKeyStatuses()

	activeCount := 0
	totalUsage := int64(0)
	totalErrors := int64(0)

	for _, status := range keyStatuses {
		if status.IsActive {
			activeCount++
		}
		totalUsage += status.UsageCount
		totalErrors += status.ErrorCount
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title":        "Dashboard - TurnsAPI",
		"keys":         keyStatuses,
		"active_count": activeCount,
		"total_count":  len(keyStatuses),
		"total_usage":  totalUsage,
		"total_errors": totalErrors,
	})
}

// handleHealth 处理健康检查
func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now(),
	})
}

// Start 启动服务器
func (s *Server) Start() error {
	s.httpServer = &http.Server{
		Addr:    s.config.GetAddress(),
		Handler: s.router,
	}

	log.Printf("Starting server on %s", s.config.GetAddress())
	return s.httpServer.ListenAndServe()
}

// Stop 停止服务器
func (s *Server) Stop(ctx context.Context) error {
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

// handleAvailableModels 获取完整的模型列表（用于管理界面）
func (s *Server) handleAvailableModels(c *gin.Context) {
	// 检查缓存
	if s.modelsCacheData != nil && time.Since(s.modelsCacheTime) < s.modelsCacheTTL {
		c.Data(http.StatusOK, "application/json", s.modelsCacheData)
		return
	}

	// 获取API密钥
	apiKey, err := s.keyManager.GetNextKey()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "No available API keys",
			"code":  "no_api_keys",
		})
		return
	}

	// 创建请求到OpenRouter
	req, err := http.NewRequest("GET", s.config.OpenRouter.BaseURL+"/models", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create request",
			"code":  "request_creation_failed",
		})
		return
	}

	// 设置请求头
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		s.keyManager.ReportError(apiKey, err.Error())
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "Failed to connect to OpenRouter",
			"code":  "upstream_connection_failed",
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
			s.keyManager.ReportError(apiKey, err.Error())
			c.JSON(http.StatusBadGateway, gin.H{
				"error": "Failed to decompress response",
				"code":  "response_decompress_failed",
			})
			return
		}
		defer gzipReader.Close()
		bodyReader = gzipReader
	}

	// 读取响应
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		s.keyManager.ReportError(apiKey, err.Error())
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "Failed to read response",
			"code":  "response_read_failed",
		})
		return
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		s.keyManager.ReportError(apiKey, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)))
		c.Data(resp.StatusCode, "application/json", body)
		return
	}

	// 报告成功
	s.keyManager.ReportSuccess(apiKey)

	// 更新缓存
	s.modelsCacheData = body
	s.modelsCacheTime = time.Now()

	// 返回完整的模型列表（不过滤）
	c.Data(http.StatusOK, "application/json", body)
}

// handleRequestLogs 获取请求日志列表
func (s *Server) handleRequestLogs(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Request logging is not available",
			"code":  "logging_unavailable",
		})
		return
	}

	// 解析查询参数
	proxyKeyName := c.Query("proxy_key_name")
	providerGroup := c.Query("provider_group")
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 1000 {
		limit = 50
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	// 获取日志列表
	logs, err := s.requestLogger.GetRequestLogs(proxyKeyName, providerGroup, limit, offset)
	if err != nil {
		log.Printf("Failed to get request logs: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get request logs",
			"code":  "get_logs_failed",
		})
		return
	}

	// 获取总数
	totalCount, err := s.requestLogger.GetRequestCount(proxyKeyName, providerGroup)
	if err != nil {
		log.Printf("Failed to get request count: %v", err)
		totalCount = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"logs":        logs,
		"total_count": totalCount,
		"limit":       limit,
		"offset":      offset,
	})
}

// handleRequestLogDetail 获取请求日志详情
func (s *Server) handleRequestLogDetail(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Request logging is not available",
			"code":  "logging_unavailable",
		})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid log ID",
			"code":  "invalid_log_id",
		})
		return
	}

	// 获取日志详情
	logDetail, err := s.requestLogger.GetRequestLogDetail(id)
	if err != nil {
		log.Printf("Failed to get request log detail: %v", err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Request log not found",
			"code":  "log_not_found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"log":     logDetail,
	})
}

// handleAPIKeyStats 获取代理密钥统计
func (s *Server) handleAPIKeyStats(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Request logging is not available",
			"code":  "logging_unavailable",
		})
		return
	}

	// 获取代理密钥统计
	stats, err := s.requestLogger.GetProxyKeyStats()
	if err != nil {
		log.Printf("Failed to get proxy key stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get proxy key stats",
			"code":  "get_stats_failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

// handleModelStats 获取模型统计
func (s *Server) parseLogFilterWithRange(c *gin.Context) *logger.LogFilter {
	// 解析通用筛选
	f := &logger.LogFilter{
		ProxyKeyName:  c.Query("proxy_key_name"),
		ProviderGroup: c.Query("provider_group"),
		Model:         c.Query("model"),
		Status:        c.Query("status"),
		Stream:        c.Query("stream"),
	}
	// 解析 range: 支持 1h,6h,24h,7d,30d
	rangeStr := c.DefaultQuery("range", "")
	now := time.Now()
	var start *time.Time
	var end *time.Time
	switch strings.ToLower(strings.TrimSpace(rangeStr)) {
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
	// 显式起止时间（优先于range）
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

func (s *Server) handleModelStats(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Request logging is not available",
			"code":  "logging_unavailable",
		})
		return
	}

	// 解析筛选条件和时间范围
	filter := s.parseLogFilterWithRange(c)

	// 获取模型统计（支持筛选）
	stats, err := s.requestLogger.GetModelStatsWithFilter(filter)
	if err != nil {
		log.Printf("Failed to get model stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get model stats",
			"code":  "get_stats_failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

// handleTotalTokensStats 获取总token数统计
func (s *Server) handleStatusDistribution(c *gin.Context) {
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

func (s *Server) handleTokensTimeline(c *gin.Context) {
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

func (s *Server) handleGroupTokens(c *gin.Context) {
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

func (s *Server) handleTotalTokensStats(c *gin.Context) {
	if s.requestLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Request logging is not available",
			"code":  "logging_unavailable",
		})
		return
	}

	// 获取总token数统计
	stats, err := s.requestLogger.GetTotalTokensStats()
	if err != nil {
		log.Printf("Failed to get total tokens stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get total tokens stats",
			"code":  "get_stats_failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

// handleLogsPage 处理日志页面
func (s *Server) handleLogsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "logs.html", gin.H{
		"title": "请求日志 - TurnsAPI",
	})
}

// handleGeminiNativeChat 处理Gemini原生聊天完成请求
func (s *Server) handleGeminiNativeChat(c *gin.Context) {
	model := c.Param("model")

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
	standardReq, err := s.convertGeminiNativeToStandard(nativeReq, model)
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

	// 调用标准聊天完成处理
	s.handleChatCompletionsWithRequest(c, standardReq)
}

// handleGeminiNativeStreamChat 处理Gemini原生流式聊天完成请求
func (s *Server) handleGeminiNativeStreamChat(c *gin.Context) {
	model := c.Param("model")

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
	standardReq, err := s.convertGeminiNativeToStandard(nativeReq, model)
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

	// 调用标准聊天完成处理
	s.handleChatCompletionsWithRequest(c, standardReq)
}

// handleGeminiNativeModels 处理Gemini原生模型列表请求
func (s *Server) handleGeminiNativeModels(c *gin.Context) {
	// 强制使用Gemini提供商
	c.Set("target_provider", "gemini")
	c.Set("force_native_response", true)

	// 调用标准模型列表处理
	s.handleModels(c)
}

// convertGeminiNativeToStandard 将Gemini原生请求格式转换为标准格式
func (s *Server) convertGeminiNativeToStandard(nativeReq map[string]interface{}, model string) (*providers.ChatCompletionRequest, error) {
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

// handleChatCompletionsWithRequest 使用指定请求处理聊天完成
func (s *Server) handleChatCompletionsWithRequest(c *gin.Context, req *providers.ChatCompletionRequest) {
	// 将请求设置到上下文中，这样代理可以直接使用
	c.Set("chat_request", req)

	// 调用标准聊天完成处理
	s.handleChatCompletions(c)
}
