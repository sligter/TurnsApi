package proxykey

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sort"
	"sync"
	"time"

	"turnsapi/internal/logger"
)

// GroupSelectionStrategy 分组选择策略
type GroupSelectionStrategy string

const (
	GroupSelectionRoundRobin GroupSelectionStrategy = "round_robin" // 分组间轮询
	GroupSelectionWeighted   GroupSelectionStrategy = "weighted"    // 按权重选择分组
	GroupSelectionRandom     GroupSelectionStrategy = "random"      // 随机选择分组
	GroupSelectionFailover   GroupSelectionStrategy = "failover"    // 故障转移（优先级顺序）
)

// GroupWeight 分组权重配置
type GroupWeight struct {
	GroupID string `json:"group_id"` // 分组ID
	Weight  int    `json:"weight"`   // 权重值，越大优先级越高
}

// GroupSelectionConfig 分组选择配置
type GroupSelectionConfig struct {
	Strategy     GroupSelectionStrategy `json:"strategy"`      // 选择策略
	GroupWeights []GroupWeight          `json:"group_weights"` // 分组权重配置（仅在weighted策略下使用）
}

// ProxyKey 代理服务API密钥
type ProxyKey struct {
	ID                   string                `json:"id"`
	Key                  string                `json:"key"`
	Name                 string                `json:"name"`
	Description          string                `json:"description"`
	AllowedGroups        []string              `json:"allowed_groups"`         // 允许访问的分组ID列表
	GroupSelectionConfig *GroupSelectionConfig `json:"group_selection_config"` // 分组间请求设置
	CreatedAt            time.Time             `json:"created_at"`
	LastUsed             time.Time             `json:"last_used"`
	UsageCount           int64                 `json:"usage_count"`
	IsActive             bool                  `json:"is_active"`
	EnforceModelMappings bool                  `json:"enforce_model_mappings"`
}

// ConfigProvider 配置提供者接口
type ConfigProvider interface {
	GetEnabledGroups() map[string]interface{} // 返回启用的分组ID列表
}

// Manager 代理密钥管理器
type Manager struct {
	keys           map[string]*ProxyKey
	groupSelectors map[string]*GroupSelector // 每个代理密钥的分组选择器
	requestLogger  *logger.RequestLogger
	configProvider ConfigProvider // 配置提供者，用于获取启用的分组
	mu             sync.RWMutex
}

// NewManager 创建新的代理密钥管理器
func NewManager() *Manager {
	return &Manager{
		keys:           make(map[string]*ProxyKey),
		groupSelectors: make(map[string]*GroupSelector),
	}
}

// NewManagerWithDB 创建带数据库支持的代理密钥管理器
func NewManagerWithDB(requestLogger *logger.RequestLogger) *Manager {
	return NewManagerWithConfig(requestLogger, nil)
}

// NewManagerWithConfig 创建带配置提供者的代理密钥管理器
func NewManagerWithConfig(requestLogger *logger.RequestLogger, configProvider ConfigProvider) *Manager {
	m := &Manager{
		keys:           make(map[string]*ProxyKey),
		groupSelectors: make(map[string]*GroupSelector),
		requestLogger:  requestLogger,
		configProvider: configProvider,
	}

	// 从数据库加载现有密钥
	log.Println("Attempting to load proxy keys from database...")
	if err := m.loadKeysFromDB(); err != nil {
		log.Printf("ERROR: Failed to load proxy keys from database: %v", err)
	} else {
		log.Println("Database loading process completed")
	}

	return m
}

// loadKeysFromDB 从数据库加载代理密钥
func (m *Manager) loadKeysFromDB() error {
	if m.requestLogger == nil {
		log.Println("Warning: requestLogger is nil, skipping proxy key loading")
		return nil
	}

	log.Println("Loading proxy keys from database...")
	dbKeys, err := m.requestLogger.GetAllProxyKeys()
	if err != nil {
		log.Printf("ERROR: Database query failed: %v", err)
		return fmt.Errorf("failed to get proxy keys from database: %w", err)
	}

	log.Printf("Found %d proxy keys in database", len(dbKeys))

	if len(dbKeys) == 0 {
		log.Println("WARNING: No proxy keys found in database - this might be the root cause")
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, dbKey := range dbKeys {
		// 转换数据库模型到内存模型
		key := &ProxyKey{
			ID:                   dbKey.ID,
			Key:                  dbKey.Key,
			Name:                 dbKey.Name,
			Description:          dbKey.Description,
			AllowedGroups:        dbKey.AllowedGroups,
			EnforceModelMappings: dbKey.EnforceModelMappings,
			CreatedAt:            dbKey.CreatedAt,
			IsActive:             dbKey.IsActive,
			UsageCount:           dbKey.UsageCount, // 添加使用次数字段
		}

		// 解析分组选择配置
		if dbKey.GroupSelectionConfig != "" {
			var config GroupSelectionConfig
			if err := json.Unmarshal([]byte(dbKey.GroupSelectionConfig), &config); err != nil {
				log.Printf("Warning: Failed to parse GroupSelectionConfig for key %s: %v", dbKey.ID, err)
				log.Printf("Raw GroupSelectionConfig: %s", dbKey.GroupSelectionConfig)
			} else {
				key.GroupSelectionConfig = &config
			}
		}

		if dbKey.LastUsedAt != nil {
			key.LastUsed = *dbKey.LastUsedAt
		}

		m.keys[key.ID] = key
		log.Printf("Loaded proxy key: %s (%s)", key.Name, key.ID)
		m.refreshSelectorLocked(key.ID, key)
	}

	log.Printf("Successfully loaded %d proxy keys from database", len(m.keys))
	return nil
}

// GenerateKey 生成新的代理API密钥
func (m *Manager) GenerateKey(name, description string, allowedGroups []string) (*ProxyKey, error) {
	return m.GenerateKeyWithPolicy(name, description, allowedGroups, nil, false)
}

// GenerateKeyWithConfig 生成带分组选择配置的代理API密钥
func (m *Manager) GenerateKeyWithConfig(name, description string, allowedGroups []string, groupSelectionConfig *GroupSelectionConfig) (*ProxyKey, error) {
	return m.GenerateKeyWithPolicy(name, description, allowedGroups, groupSelectionConfig, false)
}

// GenerateKeyWithPolicy 生成带模型映射策略的代理API密钥
func (m *Manager) GenerateKeyWithPolicy(name, description string, allowedGroups []string, groupSelectionConfig *GroupSelectionConfig, enforceModelMappings bool) (*ProxyKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 生成随机密钥
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	keyStr := "tapi-" + hex.EncodeToString(keyBytes)
	id := generateID()
	now := time.Now()

	// 确定是否需要分组选择配置
	needsGroupSelection := false
	if len(allowedGroups) == 0 {
		// 空分组列表表示可以访问所有分组
		if m.configProvider != nil {
			enabledGroups := m.getSortedEnabledGroupIDs()
			if len(enabledGroups) > 1 {
				needsGroupSelection = true
			}
		}
	} else if len(allowedGroups) > 1 {
		// 多个指定分组
		needsGroupSelection = true
	}

	// 如果需要分组选择但没有指定配置，使用默认的轮询策略
	if needsGroupSelection && groupSelectionConfig == nil {
		groupSelectionConfig = &GroupSelectionConfig{
			Strategy: GroupSelectionRoundRobin,
		}
	}

	key := &ProxyKey{
		ID:                   id,
		Key:                  keyStr,
		Name:                 name,
		Description:          description,
		AllowedGroups:        allowedGroups,
		GroupSelectionConfig: groupSelectionConfig,
		EnforceModelMappings: enforceModelMappings,
		CreatedAt:            now,
		IsActive:             true,
	}

	// 保存到数据库
	if m.requestLogger != nil {
		// 序列化分组选择配置
		var groupSelectionConfigJSON string
		if groupSelectionConfig != nil {
			if configBytes, err := json.Marshal(groupSelectionConfig); err == nil {
				groupSelectionConfigJSON = string(configBytes)
			}
		}

		dbKey := &logger.ProxyKey{
			ID:                   id,
			Name:                 name,
			Description:          description,
			Key:                  keyStr,
			AllowedGroups:        allowedGroups,
			GroupSelectionConfig: groupSelectionConfigJSON,
			IsActive:             true,
			EnforceModelMappings: enforceModelMappings,
			CreatedAt:            now,
			UpdatedAt:            now,
		}

		if err := m.requestLogger.InsertProxyKey(dbKey); err != nil {
			return nil, fmt.Errorf("failed to save proxy key to database: %w", err)
		}
	}

	m.keys[id] = key
	if needsGroupSelection {
		m.refreshSelectorLocked(id, key)
	}
	return key, nil
}

// ValidateKey 验证代理API密钥
func (m *Manager) ValidateKey(keyStr string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, key := range m.keys {
		if key.Key == keyStr && key.IsActive {
			// 返回logger.ProxyKey类型以便认证中间件使用
			dbKey := &logger.ProxyKey{
				ID:                   key.ID,
				Name:                 key.Name,
				Description:          key.Description,
				Key:                  key.Key,
				AllowedGroups:        key.AllowedGroups,
				IsActive:             key.IsActive,
				EnforceModelMappings: key.EnforceModelMappings,
				CreatedAt:            key.CreatedAt,
				UpdatedAt:            key.CreatedAt,
			}
			if !key.LastUsed.IsZero() {
				dbKey.LastUsedAt = &key.LastUsed
			}
			return dbKey, true
		}
	}
	return nil, false
}

// ValidateKeyForGroup 验证代理API密钥是否可以访问指定分组
func (m *Manager) ValidateKeyForGroup(keyStr, groupID string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, key := range m.keys {
		if key.Key == keyStr && key.IsActive {
			// 检查分组访问权限
			if len(key.AllowedGroups) > 0 {
				hasAccess := false
				for _, allowedGroup := range key.AllowedGroups {
					if allowedGroup == groupID {
						hasAccess = true
						break
					}
				}
				if !hasAccess {
					return nil, false // 没有访问权限
				}
			}
			// 如果AllowedGroups为空，表示可以访问所有分组

			// 返回logger.ProxyKey类型以便认证中间件使用
			dbKey := &logger.ProxyKey{
				ID:                   key.ID,
				Name:                 key.Name,
				Description:          key.Description,
				Key:                  key.Key,
				AllowedGroups:        key.AllowedGroups,
				IsActive:             key.IsActive,
				EnforceModelMappings: key.EnforceModelMappings,
				CreatedAt:            key.CreatedAt,
				UpdatedAt:            key.CreatedAt,
			}
			if !key.LastUsed.IsZero() {
				dbKey.LastUsedAt = &key.LastUsed
			}
			return dbKey, true
		}
	}
	return nil, false
}

// UpdateUsage 更新密钥使用统计
func (m *Manager) UpdateUsage(keyStr string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, key := range m.keys {
		if key.Key == keyStr {
			key.LastUsed = time.Now()
			key.UsageCount++

			// 更新数据库中的使用次数和最后使用时间
			if m.requestLogger != nil {
				if err := m.requestLogger.UpdateProxyKeyUsage(key.ID); err != nil {
					log.Printf("Failed to update proxy key usage in database: %v", err)
				}
			}
			break
		}
	}
}

// GetAllKeys 获取所有代理密钥
func (m *Manager) GetAllKeys() []*ProxyKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	log.Printf("GetAllKeys called: found %d keys in memory", len(m.keys))
	for id, key := range m.keys {
		log.Printf("  - Key ID: %s, Name: %s, Active: %t, EnforceModelMappings: %t", id, key.Name, key.IsActive, key.EnforceModelMappings)
	}

	keys := make([]*ProxyKey, 0, len(m.keys))
	for _, key := range m.keys {
		keys = append(keys, key)
	}
	return keys
}

// GetKey 获取单个代理密钥的只读副本
func (m *Manager) GetKey(id string) (*ProxyKey, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, exists := m.keys[id]
	if !exists {
		return nil, false
	}

	keyCopy := *key
	if key.AllowedGroups != nil {
		keyCopy.AllowedGroups = append([]string(nil), key.AllowedGroups...)
	}
	if key.GroupSelectionConfig != nil {
		configCopy := *key.GroupSelectionConfig
		if key.GroupSelectionConfig.GroupWeights != nil {
			configCopy.GroupWeights = append([]GroupWeight(nil), key.GroupSelectionConfig.GroupWeights...)
		}
		keyCopy.GroupSelectionConfig = &configCopy
	}

	return &keyCopy, true
}

// DeleteKey 删除代理密钥
func (m *Manager) DeleteKey(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[id]; !exists {
		return fmt.Errorf("key not found")
	}

	// 从数据库删除
	if m.requestLogger != nil {
		if err := m.requestLogger.DeleteProxyKey(id); err != nil {
			return fmt.Errorf("failed to delete proxy key from database: %w", err)
		}
	}

	delete(m.keys, id)
	delete(m.groupSelectors, id)
	return nil
}

// UpdateKey 更新代理密钥信息
func (m *Manager) UpdateKey(id string, name, description string, isActive bool, allowedGroups []string) error {
	return m.UpdateKeyWithPolicy(id, name, description, isActive, allowedGroups, nil, false)
}

// UpdateKeyWithConfig 更新带分组选择配置的代理密钥信息
func (m *Manager) UpdateKeyWithConfig(id string, name, description string, isActive bool, allowedGroups []string, groupSelectionConfig *GroupSelectionConfig) error {
	return m.UpdateKeyWithPolicy(id, name, description, isActive, allowedGroups, groupSelectionConfig, false)
}

// UpdateKeyWithPolicy 更新带模型映射策略的代理密钥信息
func (m *Manager) UpdateKeyWithPolicy(id string, name, description string, isActive bool, allowedGroups []string, groupSelectionConfig *GroupSelectionConfig, enforceModelMappings bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, exists := m.keys[id]
	if !exists {
		return fmt.Errorf("key not found")
	}

	// 如果有多个允许分组但没有指定分组选择配置，保持现有配置或使用默认轮询策略
	if len(allowedGroups) > 1 && groupSelectionConfig == nil && key.GroupSelectionConfig == nil {
		groupSelectionConfig = &GroupSelectionConfig{
			Strategy: GroupSelectionRoundRobin,
		}
	}

	// 更新内存中的密钥信息
	key.Name = name
	key.Description = description
	key.IsActive = isActive
	key.AllowedGroups = allowedGroups
	key.EnforceModelMappings = enforceModelMappings
	if groupSelectionConfig != nil {
		key.GroupSelectionConfig = groupSelectionConfig
	}

	// 更新数据库中的密钥信息
	if m.requestLogger != nil {
		// 序列化分组选择配置
		var groupSelectionConfigJSON string
		if key.GroupSelectionConfig != nil {
			if configBytes, err := json.Marshal(key.GroupSelectionConfig); err == nil {
				groupSelectionConfigJSON = string(configBytes)
			}
		}

		dbKey := &logger.ProxyKey{
			ID:                   key.ID,
			Name:                 name,
			Description:          description,
			Key:                  key.Key,
			AllowedGroups:        allowedGroups,
			GroupSelectionConfig: groupSelectionConfigJSON,
			IsActive:             isActive,
			EnforceModelMappings: enforceModelMappings,
			CreatedAt:            key.CreatedAt,
			UpdatedAt:            time.Now(),
		}

		if err := m.requestLogger.UpdateProxyKey(dbKey); err != nil {
			return fmt.Errorf("failed to update proxy key in database: %w", err)
		}
	}

	m.refreshSelectorLocked(id, key)

	log.Printf("Successfully loaded %d proxy keys from database", len(m.keys))
	return nil
}

// SelectGroupForKey 为指定的代理密钥选择分组
// RemoveGroupFromAllKeys removes a deleted group from all proxy key permissions.
// It updates in-memory data, group selectors, and persists changes to database.
// If a key had explicit group permissions and becomes empty after removal, the key is disabled
// to avoid unintentionally expanding permission to "all groups".
func (m *Manager) RemoveGroupFromAllKeys(groupID string) (updatedCount int, disabledCount int, err error) {
	if groupID == "" {
		return 0, 0, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for keyID, key := range m.keys {
		// Empty allowed groups means "all groups"; this key has no explicit reference to groupID.
		if len(key.AllowedGroups) == 0 {
			continue
		}

		filteredGroups, removed := removeGroupFromList(key.AllowedGroups, groupID)
		if !removed {
			continue
		}

		key.AllowedGroups = filteredGroups
		key.GroupSelectionConfig = sanitizeGroupSelectionConfig(filteredGroups, key.GroupSelectionConfig)

		// Explicit permissions became empty after group deletion: disable key for safety.
		if len(filteredGroups) == 0 && key.IsActive {
			key.IsActive = false
			key.GroupSelectionConfig = nil
			disabledCount++
		}

		if err := m.persistKeyLocked(key); err != nil {
			return updatedCount, disabledCount, err
		}

		m.refreshSelectorLocked(keyID, key)
		updatedCount++
	}

	return updatedCount, disabledCount, nil
}

func removeGroupFromList(groups []string, target string) ([]string, bool) {
	if len(groups) == 0 {
		return groups, false
	}

	filtered := make([]string, 0, len(groups))
	removed := false
	for _, g := range groups {
		if g == target {
			removed = true
			continue
		}
		filtered = append(filtered, g)
	}
	return filtered, removed
}

func sanitizeGroupSelectionConfig(allowedGroups []string, cfg *GroupSelectionConfig) *GroupSelectionConfig {
	if len(allowedGroups) <= 1 || cfg == nil {
		return nil
	}

	sanitized := &GroupSelectionConfig{
		Strategy: cfg.Strategy,
	}
	if sanitized.Strategy == "" {
		sanitized.Strategy = GroupSelectionRoundRobin
	}

	if sanitized.Strategy != GroupSelectionWeighted {
		return sanitized
	}

	allowedSet := make(map[string]struct{}, len(allowedGroups))
	for _, groupID := range allowedGroups {
		allowedSet[groupID] = struct{}{}
	}

	for _, weight := range cfg.GroupWeights {
		if _, ok := allowedSet[weight.GroupID]; !ok {
			continue
		}
		if weight.Weight <= 0 {
			continue
		}
		sanitized.GroupWeights = append(sanitized.GroupWeights, weight)
	}

	// Keep weighted strategy valid by providing default weights for missing groups.
	if len(sanitized.GroupWeights) == 0 {
		for _, groupID := range allowedGroups {
			sanitized.GroupWeights = append(sanitized.GroupWeights, GroupWeight{
				GroupID: groupID,
				Weight:  1,
			})
		}
	}

	return sanitized
}

func (m *Manager) persistKeyLocked(key *ProxyKey) error {
	if m.requestLogger == nil {
		return nil
	}

	var groupSelectionConfigJSON string
	if key.GroupSelectionConfig != nil {
		configBytes, err := json.Marshal(key.GroupSelectionConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal group selection config: %w", err)
		}
		groupSelectionConfigJSON = string(configBytes)
	}

	dbKey := &logger.ProxyKey{
		ID:                   key.ID,
		Name:                 key.Name,
		Description:          key.Description,
		Key:                  key.Key,
		AllowedGroups:        key.AllowedGroups,
		GroupSelectionConfig: groupSelectionConfigJSON,
		IsActive:             key.IsActive,
		EnforceModelMappings: key.EnforceModelMappings,
		UsageCount:           key.UsageCount,
		CreatedAt:            key.CreatedAt,
		UpdatedAt:            time.Now(),
	}

	if err := m.requestLogger.UpdateProxyKey(dbKey); err != nil {
		return fmt.Errorf("failed to update proxy key in database: %w", err)
	}

	return nil
}

func (m *Manager) refreshSelectorLocked(keyID string, key *ProxyKey) {
	selectableGroups := m.selectableGroupsForKeyLocked(key)
	if len(selectableGroups) <= 1 || !key.IsActive {
		delete(m.groupSelectors, keyID)
		return
	}

	if selector, exists := m.groupSelectors[keyID]; exists {
		if selectorMatches(selector, selectableGroups, key.GroupSelectionConfig) {
			return
		}
		selector.UpdateAllowedGroups(selectableGroups)
		selector.UpdateConfig(key.GroupSelectionConfig)
		return
	}

	m.groupSelectors[keyID] = NewGroupSelector(selectableGroups, key.GroupSelectionConfig)
}

func (m *Manager) SelectGroupForKey(keyID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, exists := m.keys[keyID]
	if !exists {
		return "", fmt.Errorf("key not found")
	}

	if !key.IsActive {
		return "", fmt.Errorf("key is not active")
	}

	selectableGroups := m.selectableGroupsForKeyLocked(key)
	if len(selectableGroups) == 0 {
		return "", fmt.Errorf("no enabled groups available")
	}
	if len(selectableGroups) == 1 {
		return selectableGroups[0], nil
	}

	if selector := m.ensureSelectorLocked(keyID, key); selector != nil {
		return selector.SelectGroup()
	}

	return "", fmt.Errorf("no group selector found for key")
}

// GetGroupUsageStats 获取代理密钥的分组使用统计
// SelectGroupForKeyFromCandidates 为代理密钥在候选分组子集中选择分组。
func (m *Manager) SelectGroupForKeyFromCandidates(keyID string, candidates []string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, exists := m.keys[keyID]
	if !exists {
		return "", fmt.Errorf("key not found")
	}
	if !key.IsActive {
		return "", fmt.Errorf("key is not active")
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no candidate groups available")
	}

	selectableGroups := m.selectableGroupsForKeyLocked(key)
	if len(selectableGroups) == 0 {
		return "", fmt.Errorf("no enabled groups available")
	}

	candidateSet := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidateSet[candidate] = struct{}{}
	}

	filteredCandidates := make([]string, 0, len(candidates))
	for _, groupID := range selectableGroups {
		if _, ok := candidateSet[groupID]; ok {
			filteredCandidates = append(filteredCandidates, groupID)
		}
	}

	if len(filteredCandidates) == 0 {
		return "", fmt.Errorf("no candidate groups match allowed groups")
	}
	if len(selectableGroups) == 1 {
		return filteredCandidates[0], nil
	}

	if selector := m.ensureSelectorLocked(keyID, key); selector != nil {
		return selector.SelectGroupFromCandidates(filteredCandidates)
	}

	return filteredCandidates[0], nil
}

func (m *Manager) GetGroupUsageStats(keyID string) (map[string]GroupUsageStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, exists := m.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found")
	}

	m.refreshSelectorLocked(keyID, key)

	if selector, exists := m.groupSelectors[keyID]; exists {
		return selector.GetUsageStats(), nil
	}

	return nil, fmt.Errorf("no group selector found for key")
}

// generateID 生成唯一ID
// getSortedEnabledGroupIDs returns enabled group IDs in a stable order.
func (m *Manager) getSortedEnabledGroupIDs() []string {
	if m.configProvider == nil {
		return nil
	}

	enabledGroups := m.configProvider.GetEnabledGroups()
	groupIDs := make([]string, 0, len(enabledGroups))
	for groupID := range enabledGroups {
		groupIDs = append(groupIDs, groupID)
	}
	sort.Strings(groupIDs)
	return groupIDs
}

// RefreshSelectors rebuilds cached group selectors against the latest enabled-group config.
func (m *Manager) RefreshSelectors() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for keyID, key := range m.keys {
		m.refreshSelectorLocked(keyID, key)
	}
}

func (m *Manager) ensureSelectorLocked(keyID string, key *ProxyKey) *GroupSelector {
	m.refreshSelectorLocked(keyID, key)
	return m.groupSelectors[keyID]
}

func (m *Manager) selectableGroupsForKeyLocked(key *ProxyKey) []string {
	if key == nil || !key.IsActive {
		return nil
	}

	if len(key.AllowedGroups) == 0 {
		return append([]string(nil), m.getSortedEnabledGroupIDs()...)
	}

	if m.configProvider == nil {
		return append([]string(nil), key.AllowedGroups...)
	}

	enabledSet := make(map[string]struct{})
	for _, groupID := range m.getSortedEnabledGroupIDs() {
		enabledSet[groupID] = struct{}{}
	}

	selectable := make([]string, 0, len(key.AllowedGroups))
	for _, groupID := range key.AllowedGroups {
		if _, ok := enabledSet[groupID]; ok {
			selectable = append(selectable, groupID)
		}
	}
	return selectable
}

func selectorMatches(selector *GroupSelector, allowedGroups []string, config *GroupSelectionConfig) bool {
	if selector == nil {
		return false
	}

	selector.mutex.RLock()
	defer selector.mutex.RUnlock()

	return stringSlicesEqual(selector.allowedGroups, allowedGroups) &&
		groupSelectionConfigEqual(selector.config, config)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func groupSelectionConfigEqual(a, b *GroupSelectionConfig) bool {
	normalizedA := normalizedGroupSelectionConfig(a)
	normalizedB := normalizedGroupSelectionConfig(b)
	return reflect.DeepEqual(normalizedA, normalizedB)
}

func normalizedGroupSelectionConfig(cfg *GroupSelectionConfig) GroupSelectionConfig {
	if cfg == nil {
		return GroupSelectionConfig{Strategy: GroupSelectionRoundRobin}
	}

	normalized := GroupSelectionConfig{
		Strategy: cfg.Strategy,
	}
	if normalized.Strategy == "" {
		normalized.Strategy = GroupSelectionRoundRobin
	}
	if len(cfg.GroupWeights) > 0 {
		normalized.GroupWeights = append([]GroupWeight(nil), cfg.GroupWeights...)
	}
	return normalized
}

// generateID generates a unique ID.
func generateID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
