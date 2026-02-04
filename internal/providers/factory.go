package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// DefaultProviderFactory 默认提供商工厂
type DefaultProviderFactory struct{}

// NewDefaultProviderFactory 创建默认提供商工厂
func NewDefaultProviderFactory() *DefaultProviderFactory {
	return &DefaultProviderFactory{}
}

// CreateProvider 创建提供商实例
func (f *DefaultProviderFactory) CreateProvider(config *ProviderConfig) (Provider, error) {
	switch config.ProviderType {
	case "openai":
		return NewOpenAIProvider(config), nil
	case "openrouter":
		// OpenRouter使用OpenAI格式，但是独立的提供商类型
		return NewOpenAIProvider(config), nil
	case "gemini":
		return NewGeminiProvider(config), nil
	case "anthropic":
		return NewAnthropicProvider(config), nil
	case "azure_openai":
		// Azure OpenAI 使用专用的 Azure 提供商，处理特殊的认证和 URL 格式
		return NewAzureOpenAIProvider(config), nil
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", config.ProviderType)
	}
}

// GetSupportedTypes 获取支持的提供商类型
func (f *DefaultProviderFactory) GetSupportedTypes() []string {
	return []string{"openai", "openrouter", "gemini", "anthropic", "azure_openai"}
}

// ProviderManager 提供商管理器
type ProviderManager struct {
	factory   ProviderFactory
	providers map[string]Provider
	mutex     sync.RWMutex
}

func providerCacheKey(groupID string, config *ProviderConfig) string {
	if config == nil {
		return groupID
	}

	keyHash := sha256.Sum256([]byte(config.APIKey))

	headersBytes, _ := json.Marshal(config.Headers) // stable key order in encoding/json
	headersHash := sha256.Sum256(headersBytes)

	return strings.Join([]string{
		groupID,
		config.ProviderType,
		config.BaseURL,
		config.Timeout.String(),
		fmt.Sprintf("%d", config.MaxRetries),
		fmt.Sprintf("%t", config.UseResponsesAPI),
		hex.EncodeToString(headersHash[:8]),
		hex.EncodeToString(keyHash[:8]),
	}, "|")
}

// NewProviderManager 创建提供商管理器
func NewProviderManager(factory ProviderFactory) *ProviderManager {
	return &ProviderManager{
		factory:   factory,
		providers: make(map[string]Provider),
	}
}

// GetProvider 获取提供商实例
func (pm *ProviderManager) GetProvider(groupID string, config *ProviderConfig) (Provider, error) {
	cacheKey := providerCacheKey(groupID, config)

	// 先尝试读锁检查是否已存在
	pm.mutex.RLock()
	if provider, exists := pm.providers[cacheKey]; exists {
		pm.mutex.RUnlock()
		return provider, nil
	}
	pm.mutex.RUnlock()

	// 使用写锁创建新实例
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// 双重检查，防止在获取写锁期间其他goroutine已经创建了实例
	if provider, exists := pm.providers[cacheKey]; exists {
		return provider, nil
	}

	// 创建新的提供商实例
	provider, err := pm.factory.CreateProvider(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider for group %s: %w", groupID, err)
	}

	// 缓存提供商实例
	pm.providers[cacheKey] = provider

	return provider, nil
}

// RemoveProvider 移除提供商实例
func (pm *ProviderManager) RemoveProvider(groupID string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	delete(pm.providers, groupID)
	prefix := groupID + "|"
	for k := range pm.providers {
		if strings.HasPrefix(k, prefix) {
			delete(pm.providers, k)
		}
	}
}

// GetAllProviders 获取所有提供商实例
func (pm *ProviderManager) GetAllProviders() map[string]Provider {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// 创建副本以避免并发修改
	result := make(map[string]Provider)
	for k, v := range pm.providers {
		result[k] = v
	}
	return result
}

// UpdateProvider 更新提供商配置
func (pm *ProviderManager) UpdateProvider(groupID string, config *ProviderConfig) error {
	// 移除旧的提供商实例
	pm.RemoveProvider(groupID)

	// 创建新的提供商实例
	_, err := pm.GetProvider(groupID, config)
	return err
}

// ValidateProviderConfig 验证提供商配置
func ValidateProviderConfig(config *ProviderConfig) error {
	if config == nil {
		return fmt.Errorf("provider config cannot be nil")
	}

	if config.ProviderType == "" {
		return fmt.Errorf("provider type cannot be empty")
	}

	if config.BaseURL == "" {
		return fmt.Errorf("base URL cannot be empty")
	}

	if config.APIKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}

	// 验证提供商类型
	factory := NewDefaultProviderFactory()
	supportedTypes := factory.GetSupportedTypes()

	supported := false
	for _, supportedType := range supportedTypes {
		if config.ProviderType == supportedType {
			supported = true
			break
		}
	}

	if !supported {
		return fmt.Errorf("unsupported provider type: %s, supported types: %v", config.ProviderType, supportedTypes)
	}

	return nil
}

// CreateProviderConfigFromUserGroup 从用户分组创建提供商配置
func CreateProviderConfigFromUserGroup(groupID string, userGroup interface{}) (*ProviderConfig, error) {
	// 这里需要根据实际的UserGroup结构来实现
	// 由于我们在interface.go中没有导入internal包，这里使用interface{}

	// 这个函数将在实际使用时由调用方实现类型转换
	return nil, fmt.Errorf("not implemented - should be implemented by caller with proper type conversion")
}
