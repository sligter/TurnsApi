package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"turnsapi/internal"
	"turnsapi/internal/logger"

	"github.com/gin-gonic/gin"
)

// Session 会话信息
type Session struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ProxyKeyValidator 代理密钥验证器接口
type ProxyKeyValidator interface {
	ValidateKey(key string) (interface{}, bool)
	UpdateUsage(key string)
}

// AuthManager 认证管理器
type AuthManager struct {
	config          *internal.Config
	sessions        map[string]*Session
	proxyKeyManager ProxyKeyValidator
	mutex           sync.RWMutex
}

// NewAuthManager 创建认证管理器
func NewAuthManager(config *internal.Config) *AuthManager {
	am := &AuthManager{
		config:   config,
		sessions: make(map[string]*Session),
	}

	// 启动会话清理器
	go am.startSessionCleaner()

	return am
}

func (am *AuthManager) isSecureRequest(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}

	if proto := c.GetHeader("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}

	if ssl := c.GetHeader("X-Forwarded-Ssl"); strings.EqualFold(ssl, "on") {
		return true
	}

	return false
}

func (am *AuthManager) SetAuthCookie(c *gin.Context, token string) {
	maxAge := int(am.config.Auth.SessionTimeout.Seconds())
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   am.isSecureRequest(c),
		SameSite: http.SameSiteLaxMode,
	})
}

func (am *AuthManager) ClearAuthCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   am.isSecureRequest(c),
		SameSite: http.SameSiteLaxMode,
	})
}

// generateToken 生成随机token
func (am *AuthManager) generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Login 用户登录
func (am *AuthManager) Login(username, password string) (*Session, error) {
	if !am.config.Auth.Enabled {
		return nil, nil
	}

	if username != am.config.Auth.Username || password != am.config.Auth.Password {
		return nil, gin.Error{Err: http.ErrNotSupported, Type: gin.ErrorTypePublic}
	}

	token := am.generateToken()
	session := &Session{
		Token:     token,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(am.config.Auth.SessionTimeout),
	}

	am.mutex.Lock()
	am.sessions[token] = session
	am.mutex.Unlock()

	return session, nil
}

// ValidateToken 验证token
func (am *AuthManager) ValidateToken(token string) (*Session, bool) {
	if !am.config.Auth.Enabled {
		return nil, true // 如果认证未启用，直接通过
	}

	am.mutex.RLock()
	session, exists := am.sessions[token]
	am.mutex.RUnlock()

	if !exists {
		return nil, false
	}

	if time.Now().After(session.ExpiresAt) {
		am.mutex.Lock()
		delete(am.sessions, token)
		am.mutex.Unlock()
		return nil, false
	}

	return session, true
}

// Logout 用户登出
func (am *AuthManager) Logout(token string) {
	am.mutex.Lock()
	delete(am.sessions, token)
	am.mutex.Unlock()
}

// RefreshSession 刷新会话
func (am *AuthManager) RefreshSession(token string) bool {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	session, exists := am.sessions[token]
	if !exists {
		return false
	}

	session.ExpiresAt = time.Now().Add(am.config.Auth.SessionTimeout)
	return true
}

// startSessionCleaner 启动会话清理器
func (am *AuthManager) startSessionCleaner() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		am.cleanExpiredSessions()
	}
}

// cleanExpiredSessions 清理过期会话
func (am *AuthManager) cleanExpiredSessions() {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	now := time.Now()
	for token, session := range am.sessions {
		if now.After(session.ExpiresAt) {
			delete(am.sessions, token)
		}
	}
}

// AuthMiddleware 认证中间件
func (am *AuthManager) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !am.config.Auth.Enabled {
			c.Next()
			return
		}

		// 从cookie或header获取token
		token := c.GetHeader("Authorization")
		if token == "" {
			if cookie, err := c.Cookie("auth_token"); err == nil {
				token = cookie
			}
		} else {
			// 移除 "Bearer " 前缀
			if len(token) > 7 && token[:7] == "Bearer " {
				token = token[7:]
			}
		}

		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
				"code":  "auth_required",
			})
			c.Abort()
			return
		}

		session, valid := am.ValidateToken(token)
		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
				"code":  "invalid_token",
			})
			c.Abort()
			return
		}

		// 刷新会话
		am.RefreshSession(token)

		// 将用户信息存储到上下文
		c.Set("user", session.Username)
		c.Set("session", session)

		c.Next()
	}
}

// WebAuthMiddleware Web界面认证中间件
func (am *AuthManager) WebAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !am.config.Auth.Enabled {
			c.Next()
			return
		}

		// 从cookie获取token
		token, err := c.Cookie("auth_token")
		if err != nil || token == "" {
			c.Redirect(http.StatusFound, "/auth/login")
			c.Abort()
			return
		}

		_, valid := am.ValidateToken(token)
		if !valid {
			am.ClearAuthCookie(c)
			c.Redirect(http.StatusFound, "/auth/login")
			c.Abort()
			return
		}

		// 刷新会话
		am.RefreshSession(token)

		c.Next()
	}
}

// GetActiveSessions 获取活跃会话数量
func (am *AuthManager) GetActiveSessions() int {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	count := 0
	now := time.Now()
	for _, session := range am.sessions {
		if now.Before(session.ExpiresAt) {
			count++
		}
	}

	return count
}

// SetProxyKeyManager 设置代理密钥管理器
func (am *AuthManager) SetProxyKeyManager(pkm ProxyKeyValidator) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	am.proxyKeyManager = pkm
}

// APIKeyAuthMiddleware API密钥认证中间件
func (am *AuthManager) APIKeyAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从Authorization头获取API密钥
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"message": "Missing Authorization header",
					"type":    "authentication_error",
					"code":    "missing_auth_header",
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
					"message": "Invalid Authorization header format",
					"type":    "authentication_error",
					"code":    "invalid_auth_format",
				},
			})
			c.Abort()
			return
		}

		// 提取API密钥
		apiKey := strings.TrimPrefix(authHeader, bearerPrefix)
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
		if am.proxyKeyManager == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": gin.H{
					"message": "Proxy key manager not configured",
					"type":    "internal_error",
					"code":    "proxy_key_manager_missing",
				},
			})
			c.Abort()
			return
		}

		keyInfo, valid := am.proxyKeyManager.ValidateKey(apiKey)
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

		// 更新使用统计
		am.proxyKeyManager.UpdateUsage(apiKey)

		// 将密钥信息存储到上下文中
		c.Set("api_key", apiKey)
		c.Set("key_info", keyInfo)

		// 如果keyInfo是ProxyKey类型，提取名称和ID
		if proxyKey, ok := keyInfo.(*logger.ProxyKey); ok {
			c.Set("proxy_key_name", proxyKey.Name)
			c.Set("proxy_key_id", proxyKey.ID)
		} else {
			// 兼容旧的代理密钥管理器
			c.Set("proxy_key_name", "Unknown")
			c.Set("proxy_key_id", "unknown")
		}

		c.Next()
	}
}

// HandleLogin 处理登录请求
func (am *AuthManager) HandleLogin(c *gin.Context) {
	if !am.config.Auth.Enabled {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Authentication disabled",
		})
		return
	}

	var loginReq struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format",
		})
		return
	}

	// 使用Login方法创建会话
	session, err := am.Login(loginReq.Username, loginReq.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "Invalid username or password",
		})
		return
	}

	token := session.Token

	// 设置cookie
	am.SetAuthCookie(c, token)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Login successful",
		"token":   token,
	})
}

// HandleLogout 处理登出请求
func (am *AuthManager) HandleLogout(c *gin.Context) {
	// 从cookie获取token
	token, err := c.Cookie("auth_token")
	if err == nil && token != "" {
		// 删除会话
		am.mutex.Lock()
		delete(am.sessions, token)
		am.mutex.Unlock()
	}

	// 清除cookie
	am.ClearAuthCookie(c)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Logout successful",
	})
}

// HandleLoginPage 处理登录页面
func (am *AuthManager) HandleLoginPage(c *gin.Context) {
	if !am.config.Auth.Enabled {
		c.Redirect(http.StatusFound, "/")
		return
	}

	// 检查是否已经登录
	token, err := c.Cookie("auth_token")
	if err == nil && token != "" {
		_, valid := am.ValidateToken(token)
		if valid {
			c.Redirect(http.StatusFound, "/")
			return
		}
	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "登录 - TurnsAPI",
	})
}
