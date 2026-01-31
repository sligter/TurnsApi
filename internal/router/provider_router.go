package router

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"turnsapi/internal"
	"turnsapi/internal/providers"
	"turnsapi/internal/proxykey"
)

// ProviderRouter 提供商路由器
type ProviderRouter struct {
	config          *internal.Config
	providerManager *providers.ProviderManager
	proxyKeyManager *proxykey.Manager
	mutex           sync.RWMutex
}

// NewProviderRouter 创建提供商路由器
func NewProviderRouter(config *internal.Config, providerManager *providers.ProviderManager) *ProviderRouter {
	return &ProviderRouter{
		config:          config,
		providerManager: providerManager,
	}
}

// NewProviderRouterWithProxyKey 创建带代理密钥管理器的提供商路由器
func NewProviderRouterWithProxyKey(config *internal.Config, providerManager *providers.ProviderManager, proxyKeyManager *proxykey.Manager) *ProviderRouter {
	return &ProviderRouter{
		config:          config,
		providerManager: providerManager,
		proxyKeyManager: proxyKeyManager,
	}
}

// RouteRequest 路由请求结构
type RouteRequest struct {
	Model             string   `json:"model"`
	ProviderGroup     string   `json:"provider_group,omitempty"`     // 可选的显式提供商分组
	AllowedGroups     []string `json:"allowed_groups,omitempty"`     // 代理密钥允许访问的分组
	ProxyKeyID        string   `json:"proxy_key_id,omitempty"`       // 代理密钥ID，用于分组选择
	ForceProviderType string   `json:"force_provider_type,omitempty"` // 强制指定提供商类型
}

// RouteResult 路由结果
type RouteResult struct {
	GroupID      string
	Group        *internal.UserGroup
	Provider     providers.Provider
	ProviderConfig *providers.ProviderConfig
}

// Route 根据请求路由到合适的提供商
func (pr *ProviderRouter) Route(req *RouteRequest) (*RouteResult, error) {
	var group *internal.UserGroup
	var groupID string

	// 1. 如果显式指定了提供商分组，优先使用
	if req.ProviderGroup != "" {
		var exists bool
		group, exists = pr.config.GetGroupByID(req.ProviderGroup)
		if !exists {
			return nil, fmt.Errorf("specified provider group '%s' not found", req.ProviderGroup)
		}
		if !group.Enabled {
			return nil, fmt.Errorf("specified provider group '%s' is disabled", req.ProviderGroup)
		}

		// 检查代理密钥是否有权限访问指定分组
		if !pr.hasGroupAccess(req.AllowedGroups, req.ProviderGroup) {
			return nil, fmt.Errorf("access denied to provider group '%s'", req.ProviderGroup)
		}

		groupID = req.ProviderGroup
	} else {
		// 2. 根据模型名称和代理密钥权限自动路由
		if req.ProxyKeyID != "" && pr.proxyKeyManager != nil {
			// 使用代理密钥的分组选择策略
			selectedGroupID, err := pr.proxyKeyManager.SelectGroupForKey(req.ProxyKeyID)
			if err != nil {
				return nil, fmt.Errorf("failed to select group for proxy key: %w", err)
			}

			// 验证选择的分组是否存在且启用
			selectedGroup, exists := pr.config.GetGroupByID(selectedGroupID)
			if !exists {
				return nil, fmt.Errorf("selected group '%s' not found", selectedGroupID)
			}
			if !selectedGroup.Enabled {
				return nil, fmt.Errorf("selected group '%s' is disabled", selectedGroupID)
			}

			group = selectedGroup
			groupID = selectedGroupID
		} else {
			// 传统的模型匹配路由
			group, groupID = pr.routeByModelWithPermissions(req.Model, req.AllowedGroups)
			if group == nil {
				return nil, fmt.Errorf("no suitable provider group found for model '%s' with current permissions", req.Model)
			}
		}
	}

	// 3. 创建提供商配置
	providerConfig, err := pr.createProviderConfig(groupID, group)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider config for group '%s': %w", groupID, err)
	}

	// 4. 获取提供商实例
	provider, err := pr.providerManager.GetProvider(groupID, providerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider for group '%s': %w", groupID, err)
	}

	return &RouteResult{
		GroupID:        groupID,
		Group:          group,
		Provider:       provider,
		ProviderConfig: providerConfig,
	}, nil
}

// routeByModel 根据模型名称路由
func (pr *ProviderRouter) routeByModel(modelName string) (*internal.UserGroup, string) {
	// 1. 首先检查是否有分组明确支持该模型
	for groupID, group := range pr.config.UserGroups {
		if !group.Enabled {
			continue
		}
		
		// 如果分组指定了模型列表，检查是否包含该模型
		if len(group.Models) > 0 {
			for _, model := range group.Models {
				if model == modelName {
					return group, groupID
				}
			}
		}
	}

	// 2. 如果没有明确支持，尝试基于模型名称的模式匹配
	return pr.routeByModelPattern(modelName)
}

// routeByModelPattern 根据模型名称模式路由
func (pr *ProviderRouter) routeByModelPattern(modelName string) (*internal.UserGroup, string) {
	modelLower := strings.ToLower(modelName)

	// 定义模型名称模式到提供商类型的映射
	patterns := map[string]string{
		"gpt":     "openai",
		"claude":  "anthropic",
		"gemini":  "gemini",
		"o1":      "openai",
		"davinci": "openai",
		"turbo":   "openai",
	}

	// 查找匹配的模式
	var targetProviderType string
	for pattern, providerType := range patterns {
		if strings.Contains(modelLower, pattern) {
			targetProviderType = providerType
			break
		}
	}

	if targetProviderType == "" {
		// 如果没有匹配的模式，返回第一个启用的分组
		return pr.getFirstEnabledGroup()
	}

	// 查找匹配提供商类型的分组
	for groupID, group := range pr.config.UserGroups {
		if group.Enabled && group.ProviderType == targetProviderType {
			// 如果分组没有指定模型列表，或者模型列表为空，则认为支持所有该类型的模型
			if len(group.Models) == 0 {
				return group, groupID
			}
		}
	}

	// 如果没有找到匹配的分组，返回第一个启用的分组
	return pr.getFirstEnabledGroup()
}

// getFirstEnabledGroup 获取第一个启用的分组
func (pr *ProviderRouter) getFirstEnabledGroup() (*internal.UserGroup, string) {
	for groupID, group := range pr.config.UserGroups {
		if group.Enabled {
			return group, groupID
		}
	}
	return nil, ""
}

// createProviderConfig 创建提供商配置
func (pr *ProviderRouter) createProviderConfig(groupID string, group *internal.UserGroup) (*providers.ProviderConfig, error) {
	if len(group.APIKeys) == 0 {
		return nil, fmt.Errorf("no API keys configured for group '%s'", groupID)
	}

	// 这里暂时使用第一个API密钥，实际使用时会通过KeyManager获取
	apiKey := group.APIKeys[0]

	config := &providers.ProviderConfig{
		BaseURL:       group.BaseURL,
		APIKey:        apiKey,
		Timeout:       group.Timeout,
		MaxRetries:    group.MaxRetries,
		Headers:       make(map[string]string),
		ProviderType:  group.ProviderType,
		RequestParams: make(map[string]interface{}),
	}

	// 复制头部信息
	for key, value := range group.Headers {
		config.Headers[key] = value
	}

	// 复制请求参数覆盖
	for key, value := range group.RequestParams {
		config.RequestParams[key] = value
	}

	return config, nil
}

// GetGroupsForModel 获取支持特定模型的所有分组（按优先级排序，仅限于允许的分组范围内）
func (pr *ProviderRouter) GetGroupsForModel(modelName string, allowedGroups []string) []string {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	var candidateGroups []string

	// 获取有权限访问的分组列表
	accessibleGroups := pr.getAccessibleGroups(allowedGroups)
	if len(accessibleGroups) == 0 {
		return candidateGroups // 返回空列表
	}

	// 1. 首先检查明确支持该模型的分组（仅在允许的分组范围内）
	for _, groupID := range accessibleGroups {
		group := pr.config.UserGroups[groupID]
		if !group.Enabled {
			continue
		}

		// 检查是否明确支持该模型（原始模型名称）
		modelSupported := false
		if len(group.Models) > 0 {
			for _, model := range group.Models {
				if model == modelName {
					modelSupported = true
					break
				}
			}
		}

		// 检查是否有别名映射到该模型
		if !modelSupported {
			for alias, actualModel := range group.ModelMappings {
				if alias == modelName || actualModel == modelName {
					modelSupported = true
					break
				}
			}
		}

		if modelSupported {
			candidateGroups = append(candidateGroups, groupID)
		}
	}

	// 2. 如果没有明确支持的分组，尝试基于模型名称的模式匹配（仅在允许的分组范围内）
	if len(candidateGroups) == 0 {
		targetProviderType := pr.inferProviderTypeFromModel(modelName)
		if targetProviderType != "" {
			for _, groupID := range accessibleGroups {
				group := pr.config.UserGroups[groupID]
				if !group.Enabled {
					continue
				}

				if group.ProviderType == targetProviderType {
					// 如果分组没有指定模型列表，或者模型列表为空，则认为支持所有该类型的模型
					if len(group.Models) == 0 {
						candidateGroups = append(candidateGroups, groupID)
					}
				}
			}
		}
	}

	// 3. 按失败次数排序（失败次数少的优先）
	return pr.sortGroupsByFailureCount(modelName, candidateGroups)
}

// getAccessibleGroups 获取有权限访问的分组列表（按分组ID排序保证一致性）
func (pr *ProviderRouter) getAccessibleGroups(allowedGroups []string) []string {
	var accessibleGroups []string

	// 如果allowedGroups为空或nil，表示可以访问所有分组
	if len(allowedGroups) == 0 {
		for groupID, group := range pr.config.UserGroups {
			if group.Enabled {
				accessibleGroups = append(accessibleGroups, groupID)
			}
		}
		// 排序保证一致的分组顺序，用于分组间轮换
		sort.Strings(accessibleGroups)
		return accessibleGroups
	}

	// 否则只返回允许访问的分组（保持allowedGroups的顺序）
	for _, groupID := range allowedGroups {
		if group, exists := pr.config.UserGroups[groupID]; exists && group.Enabled {
			accessibleGroups = append(accessibleGroups, groupID)
		}
	}

	return accessibleGroups
}

// ResolveModelName 解析模型名称，将别名转换为实际的模型名称
func (pr *ProviderRouter) ResolveModelName(modelName, groupID string) string {
	if group, exists := pr.config.UserGroups[groupID]; exists {
		// 检查是否有模型映射
		if actualModel, hasMapped := group.ModelMappings[modelName]; hasMapped {
			return actualModel
		}
	}
	// 如果没有映射，返回原始模型名称
	return modelName
}

// GetModelAliases 获取分组中所有模型的别名列表（用于前端显示）
func (pr *ProviderRouter) GetModelAliases(groupID string) []string {
	if group, exists := pr.config.UserGroups[groupID]; exists {
		var aliases []string

		// 添加原始模型名称
		aliases = append(aliases, group.Models...)

		// 添加别名
		for alias := range group.ModelMappings {
			aliases = append(aliases, alias)
		}

		// 去重
		seen := make(map[string]bool)
		var uniqueAliases []string
		for _, alias := range aliases {
			if !seen[alias] {
				seen[alias] = true
				uniqueAliases = append(uniqueAliases, alias)
			}
		}

		return uniqueAliases
	}
	return []string{}
}

// sortGroupsByFailureCount 按失败次数对分组进行排序（已移除失败跟踪，现在只返回原始顺序）
func (pr *ProviderRouter) sortGroupsByFailureCount(modelName string, groups []string) []string {
	// 不再进行失败次数排序，直接返回原始分组顺序
	return groups
}

// RouteWithRetry 智能路由，支持失败重试
func (pr *ProviderRouter) RouteWithRetry(req *RouteRequest) (*RouteResult, error) {
	// 如果强制指定了提供商类型，优先处理
	if req.ForceProviderType != "" {
		return pr.routeByForceProviderType(req)
	}

	// 如果显式指定了提供商分组，直接使用
	if req.ProviderGroup != "" {
		group, exists := pr.config.UserGroups[req.ProviderGroup]
		if !exists {
			return nil, fmt.Errorf("specified provider group '%s' not found", req.ProviderGroup)
		}
		if !group.Enabled {
			return nil, fmt.Errorf("specified provider group '%s' is disabled", req.ProviderGroup)
		}

		// 创建提供商配置
		providerConfig, err := pr.createProviderConfig(req.ProviderGroup, group)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider config for group '%s': %w", req.ProviderGroup, err)
		}

		// 获取提供商实例
		provider, err := pr.providerManager.GetProvider(req.ProviderGroup, providerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to get provider for group '%s': %w", req.ProviderGroup, err)
		}

		return &RouteResult{
			GroupID:        req.ProviderGroup,
			Group:          group,
			Provider:       provider,
			ProviderConfig: providerConfig,
		}, nil
	}

	// 获取支持该模型的所有分组（按优先级排序）
	candidateGroups := pr.GetGroupsForModel(req.Model, req.AllowedGroups)
	if len(candidateGroups) == 0 {
		return nil, fmt.Errorf("no suitable provider group found for model '%s' with current permissions", req.Model)
	}

	// 尝试每个候选分组
	for _, groupID := range candidateGroups {
		group := pr.config.UserGroups[groupID]

		// 创建提供商配置
		providerConfig, err := pr.createProviderConfig(groupID, group)
		if err != nil {
			continue
		}

		// 获取提供商实例
		provider, err := pr.providerManager.GetProvider(groupID, providerConfig)
		if err != nil {
			continue
		}

		return &RouteResult{
			GroupID:        groupID,
			Group:          group,
			Provider:       provider,
			ProviderConfig: providerConfig,
		}, nil
	}

	return nil, fmt.Errorf("no suitable provider group found for model '%s'", req.Model)
}



// GetAvailableGroups 获取所有可用的分组
func (pr *ProviderRouter) GetAvailableGroups() map[string]*internal.UserGroup {
	return pr.config.GetEnabledGroups()
}

// GetGroupInfo 获取分组信息
func (pr *ProviderRouter) GetGroupInfo(groupID string) (*internal.UserGroup, bool) {
	return pr.config.GetGroupByID(groupID)
}

// ValidateModel 验证模型是否被任何分组支持
func (pr *ProviderRouter) ValidateModel(modelName string) bool {
	group, _ := pr.routeByModel(modelName)
	return group != nil
}

// hasGroupAccess 检查代理密钥是否有权限访问指定分组
func (pr *ProviderRouter) hasGroupAccess(allowedGroups []string, groupID string) bool {
	// 如果没有限制，可以访问所有分组
	if len(allowedGroups) == 0 {
		return true
	}

	// 检查分组是否在允许列表中
	for _, allowedGroup := range allowedGroups {
		if allowedGroup == groupID {
			return true
		}
	}

	return false
}

// routeByModelWithPermissions 根据模型名称和权限路由
func (pr *ProviderRouter) routeByModelWithPermissions(modelName string, allowedGroups []string) (*internal.UserGroup, string) {
	// 首先尝试精确匹配模型
	for groupID, group := range pr.config.UserGroups {
		if !group.Enabled {
			continue
		}

		// 检查权限
		if !pr.hasGroupAccess(allowedGroups, groupID) {
			continue
		}

		// 检查模型是否在分组的模型列表中
		for _, model := range group.Models {
			if model == modelName {
				return group, groupID
			}
		}
	}

	// 如果没有精确匹配，尝试根据模型名称推断提供商类型
	targetProviderType := pr.inferProviderTypeFromModel(modelName)
	if targetProviderType == "" {
		// 如果无法推断，返回第一个有权限的启用分组
		return pr.getFirstEnabledGroupWithPermissions(allowedGroups)
	}

	// 查找匹配提供商类型的分组
	for groupID, group := range pr.config.UserGroups {
		if !group.Enabled {
			continue
		}

		// 检查权限
		if !pr.hasGroupAccess(allowedGroups, groupID) {
			continue
		}

		if group.ProviderType == targetProviderType {
			// 如果分组没有指定模型列表，或者模型列表为空，则认为支持所有该类型的模型
			if len(group.Models) == 0 {
				return group, groupID
			}
		}
	}

	// 如果没有找到匹配的分组，返回第一个有权限的启用分组
	return pr.getFirstEnabledGroupWithPermissions(allowedGroups)
}

// getFirstEnabledGroupWithPermissions 获取第一个有权限的启用分组
func (pr *ProviderRouter) getFirstEnabledGroupWithPermissions(allowedGroups []string) (*internal.UserGroup, string) {
	for groupID, group := range pr.config.UserGroups {
		if group.Enabled && pr.hasGroupAccess(allowedGroups, groupID) {
			return group, groupID
		}
	}
	return nil, ""
}

// inferProviderTypeFromModel 从模型名称推断提供商类型
func (pr *ProviderRouter) inferProviderTypeFromModel(modelName string) string {
	modelLower := strings.ToLower(modelName)

	// 定义模型名称模式到提供商类型的映射
	patterns := map[string]string{
		"gpt":     "openai",
		"claude":  "anthropic",
		"gemini":  "gemini",
		"o1":      "openai",
		"davinci": "openai",
		"turbo":   "openai",
	}

	// 查找匹配的模式
	for pattern, providerType := range patterns {
		if strings.Contains(modelLower, pattern) {
			return providerType
		}
	}

	return ""
}

// GetSupportedModels 获取所有支持的模型列表
func (pr *ProviderRouter) GetSupportedModels() []string {
	modelSet := make(map[string]bool)
	
	for _, group := range pr.config.UserGroups {
		if !group.Enabled {
			continue
		}
		
		// 如果分组指定了模型列表，添加这些模型
		if len(group.Models) > 0 {
			for _, model := range group.Models {
				modelSet[model] = true
			}
		}
	}
	
	// 转换为切片
	models := make([]string, 0, len(modelSet))
	for model := range modelSet {
		models = append(models, model)
	}
	
	return models
}

// GetProviderTypeForGroup 获取分组的提供商类型
func (pr *ProviderRouter) GetProviderTypeForGroup(groupID string) (string, error) {
	group, exists := pr.config.GetGroupByID(groupID)
	if !exists {
		return "", fmt.Errorf("group '%s' not found", groupID)
	}
	
	return group.ProviderType, nil
}

// UpdateProviderConfig 更新提供商配置中的API密钥
func (pr *ProviderRouter) UpdateProviderConfig(config *providers.ProviderConfig, apiKey string) {
	config.APIKey = apiKey
}

// CreateProviderConfig 创建提供商配置（公开方法）
func (pr *ProviderRouter) CreateProviderConfig(groupID string, group *internal.UserGroup) (*providers.ProviderConfig, error) {
	return pr.createProviderConfig(groupID, group)
}

// GetProviderManager 获取提供商管理器（公开方法）
func (pr *ProviderRouter) GetProviderManager() *providers.ProviderManager {
	return pr.providerManager
}

// routeByForceProviderType 根据强制指定的提供商类型路由
func (pr *ProviderRouter) routeByForceProviderType(req *RouteRequest) (*RouteResult, error) {
	// 获取有权限访问的分组列表
	accessibleGroups := pr.getAccessibleGroups(req.AllowedGroups)
	if len(accessibleGroups) == 0 {
		return nil, fmt.Errorf("no accessible groups for current permissions")
	}

	// 查找匹配指定提供商类型的分组
	for _, groupID := range accessibleGroups {
		group := pr.config.UserGroups[groupID]
		if !group.Enabled {
			continue
		}

		// 检查提供商类型是否匹配
		if group.ProviderType == req.ForceProviderType {
			// 创建提供商配置
			providerConfig, err := pr.createProviderConfig(groupID, group)
			if err != nil {
				continue
			}

			// 获取提供商实例
			provider, err := pr.providerManager.GetProvider(groupID, providerConfig)
			if err != nil {
				continue
			}

			return &RouteResult{
				GroupID:        groupID,
				Group:          group,
				Provider:       provider,
				ProviderConfig: providerConfig,
			}, nil
		}
	}

	return nil, fmt.Errorf("no suitable provider group found for forced provider type '%s' with current permissions", req.ForceProviderType)
}
