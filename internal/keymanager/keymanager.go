package keymanager

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"turnsapi/internal/database"

	"gopkg.in/yaml.v3"
)

// KeyStatus API密钥状态
type KeyStatus struct {
	Key             string     `json:"key"`
	KeyID           string     `json:"key_id,omitempty"` // 原始密钥ID，用于删除和编辑
	Name            string     `json:"name,omitempty"`
	Description     string     `json:"description,omitempty"`
	IsActive        bool       `json:"is_active"`
	IsValid         *bool      `json:"is_valid,omitempty"` // 密钥有效性状态
	LastUsed        time.Time  `json:"last_used"`
	LastValidated   *time.Time `json:"last_validated,omitempty"` // 最后验证时间
	UsageCount      int64      `json:"usage_count"`
	ErrorCount      int64      `json:"error_count"`
	LastError       string     `json:"last_error,omitempty"`
	LastErrorTime   time.Time  `json:"last_error_time,omitempty"`
	ValidationError string     `json:"validation_error,omitempty"` // 验证错误信息
	UpdatedAt       time.Time  `json:"updated_at"`                 // 状态更新时间
	AllowedModels   []string   `json:"allowed_models,omitempty"`
}

// KeyInfo API密钥信息
type KeyInfo struct {
	Key           string   `json:"key"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	IsActive      bool     `json:"is_active"`
	AllowedModels []string `json:"allowed_models"`
}

// KeyManager API密钥管理器
type KeyManager struct {
	keys             []string
	keyInfos         map[string]*KeyInfo
	keyStatuses      map[string]*KeyStatus
	rotationStrategy string
	currentIndex     int
	mutex            sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	configPath       string             // 配置文件路径
	database         *database.GroupsDB // 新增：数据库连接
}

// NewKeyManager 创建新的密钥管理器
func NewKeyManager(keys []string, rotationStrategy string, healthCheckInterval time.Duration, configPath string) *KeyManager {
	ctx, cancel := context.WithCancel(context.Background())

	// 初始化数据库连接
	var db *database.GroupsDB
	if configPath != "" {
		// 从配置路径推断数据库路径
		dbPath := "data/turnsapi.db"
		if dbConn, err := database.NewGroupsDB(dbPath); err == nil {
			db = dbConn
		} else {
			log.Printf("Failed to initialize database: %v", err)
		}
	}

	km := &KeyManager{
		keys:             keys,
		keyInfos:         make(map[string]*KeyInfo),
		keyStatuses:      make(map[string]*KeyStatus),
		rotationStrategy: rotationStrategy,
		currentIndex:     0,
		ctx:              ctx,
		cancel:           cancel,
		configPath:       configPath,
		database:         db,
	}

	// 初始化密钥信息和状态
	for _, key := range keys {
		km.keyInfos[key] = &KeyInfo{
			Key:           key,
			Name:          fmt.Sprintf("Key-%s", getSafeKeySuffix(key)), // 使用密钥后8位作为默认名称
			Description:   "",
			IsActive:      true,
			AllowedModels: []string{}, // 空数组表示允许所有模型
		}
		km.keyStatuses[key] = &KeyStatus{
			Key:             key,
			Name:            km.keyInfos[key].Name,
			Description:     km.keyInfos[key].Description,
			IsActive:        true,
			IsValid:         nil, // 初始状态未验证
			LastUsed:        time.Time{},
			LastValidated:   nil,
			UsageCount:      0,
			ErrorCount:      0,
			ValidationError: "",
			UpdatedAt:       time.Now(),
			AllowedModels:   km.keyInfos[key].AllowedModels,
		}
	}

	// 移除了定时健康检查

	return km
}

// GetNextKey 获取下一个可用的API密钥
func (km *KeyManager) GetNextKey() (string, error) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	activeKeys := km.getActiveKeys()
	if len(activeKeys) == 0 {
		return "", fmt.Errorf("no active API keys available")
	}

	var selectedKey string

	switch km.rotationStrategy {
	case "round_robin":
		selectedKey = km.roundRobinSelection(activeKeys)
	case "random":
		selectedKey = km.randomSelection(activeKeys)
	case "least_used":
		selectedKey = km.leastUsedSelection(activeKeys)
	default:
		selectedKey = km.roundRobinSelection(activeKeys)
	}

	// 更新使用统计
	if status, exists := km.keyStatuses[selectedKey]; exists {
		status.LastUsed = time.Now()
		status.UsageCount++
	}

	return selectedKey, nil
}

// getActiveKeys 获取所有活跃的密钥
func (km *KeyManager) getActiveKeys() []string {
	var activeKeys []string
	for _, key := range km.keys {
		if status, exists := km.keyStatuses[key]; exists && status.IsActive {
			activeKeys = append(activeKeys, key)
		}
	}
	return activeKeys
}

// roundRobinSelection 轮询选择
func (km *KeyManager) roundRobinSelection(activeKeys []string) string {
	// activeKeys 会动态变化（禁用/失效/恢复），这里以 km.keys 为基准做环形扫描，
	// 从 currentIndex 开始找下一个 IsActive 的 key，确保真正轮询且能跳过不可用 key。
	if len(activeKeys) == 0 || len(km.keys) == 0 {
		return ""
	}

	startIndex := km.currentIndex
	if startIndex < 0 || startIndex >= len(km.keys) {
		startIndex = 0
	}

	for offset := 0; offset < len(km.keys); offset++ {
		idx := (startIndex + offset) % len(km.keys)
		key := km.keys[idx]
		if status, exists := km.keyStatuses[key]; exists && status.IsActive {
			km.currentIndex = (idx + 1) % len(km.keys)
			return key
		}
	}

	return ""
}

// randomSelection 随机选择
func (km *KeyManager) randomSelection(activeKeys []string) string {
	if len(activeKeys) == 0 {
		return ""
	}
	return activeKeys[rand.Intn(len(activeKeys))]
}

// leastUsedSelection 最少使用选择
func (km *KeyManager) leastUsedSelection(activeKeys []string) string {
	if len(activeKeys) == 0 {
		return ""
	}

	var leastUsedKey string
	var minUsage int64 = -1

	for _, key := range activeKeys {
		if status, exists := km.keyStatuses[key]; exists {
			if minUsage == -1 || status.UsageCount < minUsage {
				minUsage = status.UsageCount
				leastUsedKey = key
			}
		}
	}

	return leastUsedKey
}

// ReportError 报告密钥使用错误
func (km *KeyManager) ReportError(apiKey string, errorMsg string) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	if status, exists := km.keyStatuses[apiKey]; exists {
		now := time.Now()
		status.ErrorCount++
		status.LastError = errorMsg
		status.LastErrorTime = now
		status.LastValidated = &now
		status.UpdatedAt = now
		status.UsageCount++

		// 根据错误类型判断密钥有效性
		isKeyInvalid := km.isKeyInvalidError(errorMsg)
		if isKeyInvalid {
			isValid := false
			status.IsValid = &isValid
			status.ValidationError = errorMsg
			status.IsActive = false
			log.Printf("API key %s marked as invalid: %s", km.maskKey(apiKey), errorMsg)
		} else {
			log.Printf("API key %s temporary error: %s (error count: %d)", km.maskKey(apiKey), errorMsg, status.ErrorCount)
		}

		// 如果错误次数过多，暂时禁用密钥
		if status.ErrorCount >= 5 && !isKeyInvalid {
			status.IsActive = false
			log.Printf("API key %s disabled due to too many errors", km.maskKey(apiKey))
		}

		// 实时更新数据库状态
		if km.database != nil {
			var isValidPtr *bool
			if isKeyInvalid {
				isValid := false
				isValidPtr = &isValid
			}
			if err := km.database.UpdateAPIKeyValidation("default", apiKey, isValidPtr, errorMsg); err != nil {
				log.Printf("Failed to update API key validation in database: %v", err)
			}
		}
	}
}

// ReportSuccess 报告密钥成功使用
func (km *KeyManager) ReportSuccess(key string) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	if status, exists := km.keyStatuses[key]; exists {
		now := time.Now()

		// 成功使用后，如果密钥被禁用，可以重新启用
		if !status.IsActive && status.ErrorCount > 0 {
			status.IsActive = true
			status.ErrorCount = 0
			status.LastError = ""
			log.Printf("API key re-enabled after successful use: %s", km.maskKey(key))
		}

		// 更新状态字段
		status.LastUsed = now
		status.UsageCount++
		status.UpdatedAt = now

		// 标记为有效
		isValid := true
		status.IsValid = &isValid
		status.ValidationError = ""
		status.LastValidated = &now

		// 实时更新数据库状态
		if km.database != nil {
			go func() {
				isValid := true
				if err := km.database.UpdateAPIKeyValidation("default", key, &isValid, ""); err != nil {
					log.Printf("Failed to update API key validation in database: %v", err)
				}
			}()
		}
	}
}

// GetKeyStatuses 获取所有密钥状态
func (km *KeyManager) GetKeyStatuses() map[string]*KeyStatus {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	// 创建副本以避免并发访问问题
	statuses := make(map[string]*KeyStatus)
	for key, status := range km.keyStatuses {
		statusCopy := *status
		statusCopy.Key = km.maskKey(key) // 隐藏密钥的敏感部分
		statusCopy.KeyID = key           // 保留原始密钥用于删除和编辑
		statuses[km.maskKey(key)] = &statusCopy
	}

	return statuses
}

// maskKey 隐藏密钥的敏感部分
func (km *KeyManager) maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// 移除了定时健康检查方法

// AddKey 添加新的API密钥
func (km *KeyManager) AddKey(key, name, description string, allowedModels []string) error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	// 检查密钥是否已存在
	if duplicates := km.checkKeyDuplication([]string{key}); len(duplicates) > 0 {
		return fmt.Errorf("API密钥已存在")
	}

	// 添加密钥到列表
	km.keys = append(km.keys, key)

	// 如果没有提供名称，使用默认名称
	if name == "" {
		name = fmt.Sprintf("Key-%s", getSafeKeySuffix(key))
	}

	// 初始化密钥信息
	km.keyInfos[key] = &KeyInfo{
		Key:           key,
		Name:          name,
		Description:   description,
		IsActive:      true,
		AllowedModels: allowedModels,
	}

	// 初始化密钥状态
	km.keyStatuses[key] = &KeyStatus{
		Key:           key,
		Name:          name,
		Description:   description,
		IsActive:      true,
		LastUsed:      time.Time{},
		UsageCount:    0,
		ErrorCount:    0,
		AllowedModels: allowedModels,
	}

	log.Printf("添加新的API密钥: %s (名称: %s)", km.maskKey(key), name)

	// 更新配置文件
	if err := km.updateConfigFile(); err != nil {
		log.Printf("更新配置文件失败: %v", err)
	}

	return nil
}

// AddKeysInBatch 批量添加API密钥
func (km *KeyManager) AddKeysInBatch(keys []string) (int, []string, error) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	var addedKeys []string
	var errors []string
	addedCount := 0

	// 首先检查所有密钥的重复情况
	duplicates := km.checkKeyDuplication(keys)
	duplicateSet := make(map[string]bool)
	for _, dup := range duplicates {
		duplicateSet[dup] = true
	}

	// 检查输入列表内部的重复
	keySet := make(map[string]int)               // 记录每个密钥第一次出现的位置
	internalDuplicates := make(map[string][]int) // 记录内部重复的位置

	for i, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		if firstIndex, exists := keySet[key]; exists {
			// 内部重复
			if _, dupExists := internalDuplicates[key]; !dupExists {
				internalDuplicates[key] = []int{firstIndex + 1} // 转换为1基索引
			}
			internalDuplicates[key] = append(internalDuplicates[key], i+1)
		} else {
			keySet[key] = i
		}
	}

	for i, key := range keys {
		key = strings.TrimSpace(key)
		// 跳过空密钥
		if key == "" {
			continue
		}

		// 检查是否与现有密钥重复
		if duplicateSet[key] {
			errors = append(errors, fmt.Sprintf("密钥 %d: 与现有密钥重复", i+1))
			continue
		}

		// 检查是否为内部重复（跳过非首次出现的）
		if positions, exists := internalDuplicates[key]; exists {
			if positions[0] != i+1 { // 不是第一次出现
				errors = append(errors, fmt.Sprintf("密钥 %d: 与输入列表中的密钥 %d 重复", i+1, positions[0]))
				continue
			}
			// 如果是第一次出现，记录重复信息但继续处理
			errors = append(errors, fmt.Sprintf("密钥 %d: 在输入列表中重复出现于位置 %v", i+1, positions[1:]))
		}

		// 添加密钥到列表
		km.keys = append(km.keys, key)

		// 生成默认名称
		name := fmt.Sprintf("Key-%s", getSafeKeySuffix(key))

		// 初始化密钥信息
		km.keyInfos[key] = &KeyInfo{
			Key:           key,
			Name:          name,
			Description:   fmt.Sprintf("批量添加的密钥 #%d", i+1),
			IsActive:      true,
			AllowedModels: []string{}, // 空表示允许所有模型
		}

		// 初始化密钥状态
		km.keyStatuses[key] = &KeyStatus{
			Key:           key,
			Name:          name,
			Description:   fmt.Sprintf("批量添加的密钥 #%d", i+1),
			IsActive:      true,
			LastUsed:      time.Time{},
			UsageCount:    0,
			ErrorCount:    0,
			AllowedModels: []string{},
		}

		addedKeys = append(addedKeys, key)
		addedCount++
		log.Printf("批量添加API密钥: %s (名称: %s)", km.maskKey(key), name)
	}

	// 如果有密钥被添加，更新配置文件
	if addedCount > 0 {
		if err := km.updateConfigFile(); err != nil {
			log.Printf("批量添加后更新配置文件失败: %v", err)
		}
	}

	return addedCount, errors, nil
}

// UpdateKey 更新API密钥信息
func (km *KeyManager) UpdateKey(keyID, name, description string, isActive *bool, allowedModels []string) error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	// 在这个简单实现中，keyID就是密钥本身
	// 在更复杂的实现中，可能需要维护ID到密钥的映射
	if status, exists := km.keyStatuses[keyID]; exists {
		if info, infoExists := km.keyInfos[keyID]; infoExists {
			// 更新密钥信息
			if name != "" {
				info.Name = name
				status.Name = name
			}
			if description != "" {
				info.Description = description
				status.Description = description
			}
			if allowedModels != nil {
				info.AllowedModels = allowedModels
				status.AllowedModels = allowedModels
			}
			if isActive != nil {
				info.IsActive = *isActive
				status.IsActive = *isActive
				log.Printf("更新API密钥状态: %s, 活跃: %v", km.maskKey(keyID), *isActive)
			}
			log.Printf("更新API密钥信息: %s (名称: %s)", km.maskKey(keyID), info.Name)
		}
		return nil
	}

	return fmt.Errorf("API密钥不存在")
}

// UpdateKeyWithNewKey 更新API密钥，包括密钥本身
func (km *KeyManager) UpdateKeyWithNewKey(oldKeyID, newKey, name, description string, isActive *bool, allowedModels []string) error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	// 检查旧密钥是否存在
	oldStatus, exists := km.keyStatuses[oldKeyID]
	if !exists {
		return fmt.Errorf("原API密钥不存在")
	}

	oldInfo, infoExists := km.keyInfos[oldKeyID]
	if !infoExists {
		return fmt.Errorf("原API密钥信息不存在")
	}

	// 如果新密钥与旧密钥相同，只更新其他信息
	if newKey == oldKeyID {
		return km.UpdateKey(oldKeyID, name, description, isActive, allowedModels)
	}

	// 检查新密钥是否已存在
	if _, exists := km.keyStatuses[newKey]; exists {
		return fmt.Errorf("新API密钥已存在")
	}

	// 从keys切片中找到并替换旧密钥
	for i, key := range km.keys {
		if key == oldKeyID {
			km.keys[i] = newKey
			break
		}
	}

	// 创建新的密钥信息和状态
	newInfo := &KeyInfo{
		Key:           newKey,
		Name:          name,
		Description:   description,
		IsActive:      oldInfo.IsActive,
		AllowedModels: allowedModels,
	}

	newStatus := &KeyStatus{
		Key:           newKey,
		KeyID:         newKey,
		Name:          name,
		Description:   description,
		IsActive:      oldStatus.IsActive,
		LastUsed:      oldStatus.LastUsed,
		UsageCount:    oldStatus.UsageCount,
		ErrorCount:    oldStatus.ErrorCount,
		LastError:     oldStatus.LastError,
		LastErrorTime: oldStatus.LastErrorTime,
		AllowedModels: allowedModels,
	}

	// 应用状态更新
	if isActive != nil {
		newInfo.IsActive = *isActive
		newStatus.IsActive = *isActive
	}

	// 添加新密钥信息
	km.keyInfos[newKey] = newInfo
	km.keyStatuses[newKey] = newStatus

	// 删除旧密钥信息
	delete(km.keyInfos, oldKeyID)
	delete(km.keyStatuses, oldKeyID)

	log.Printf("API密钥已更新: %s -> %s (名称: %s)", km.maskKey(oldKeyID), km.maskKey(newKey), name)

	// 更新配置文件
	if err := km.updateConfigFile(); err != nil {
		log.Printf("更新配置文件失败: %v", err)
	}

	return nil
}

// DeleteKey 删除API密钥
func (km *KeyManager) DeleteKey(keyID string) error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	// 查找并删除密钥
	for i, key := range km.keys {
		if key == keyID {
			// 从切片中删除
			km.keys = append(km.keys[:i], km.keys[i+1:]...)
			// 删除状态和信息
			delete(km.keyStatuses, keyID)
			delete(km.keyInfos, keyID)
			log.Printf("删除API密钥: %s", km.maskKey(keyID))

			// 更新配置文件
			if err := km.updateConfigFile(); err != nil {
				log.Printf("更新配置文件失败: %v", err)
			}

			return nil
		}
	}

	return fmt.Errorf("API密钥不存在")
}

// IsModelAllowed 检查指定密钥是否允许使用指定模型
func (km *KeyManager) IsModelAllowed(key, model string) bool {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	if info, exists := km.keyInfos[key]; exists {
		// 如果AllowedModels为空，表示允许所有模型
		if len(info.AllowedModels) == 0 {
			return true
		}
		// 检查模型是否在允许列表中
		for _, allowedModel := range info.AllowedModels {
			if allowedModel == model {
				return true
			}
		}
		return false
	}
	// 如果密钥不存在，默认不允许
	return false
}

// GetAllAllowedModels 获取所有密钥允许的模型列表（去重）
func (km *KeyManager) GetAllAllowedModels() []string {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	modelSet := make(map[string]bool)
	hasUnlimitedKey := false

	for _, info := range km.keyInfos {
		if !info.IsActive {
			continue
		}
		// 如果有密钥允许所有模型，则返回空列表表示无限制
		if len(info.AllowedModels) == 0 {
			hasUnlimitedKey = true
			break
		}
		for _, model := range info.AllowedModels {
			modelSet[model] = true
		}
	}

	// 如果有无限制的密钥，返回空列表
	if hasUnlimitedKey {
		return []string{}
	}

	// 转换为切片
	models := make([]string, 0, len(modelSet))
	for model := range modelSet {
		models = append(models, model)
	}
	return models
}

// isKeyInvalidError 判断错误是否表示密钥无效
func (km *KeyManager) isKeyInvalidError(errorMsg string) bool {
	invalidErrorPatterns := []string{
		"401", "unauthorized", "invalid api key", "invalid_api_key",
		"authentication failed", "api key not found", "forbidden",
		"account deactivated", "insufficient credits", "quota exceeded permanently",
	}

	errorLower := strings.ToLower(errorMsg)
	for _, pattern := range invalidErrorPatterns {
		if strings.Contains(errorLower, pattern) {
			return true
		}
	}
	return false
}

// GetKeyValidationStats 获取密钥验证统计
func (km *KeyManager) GetKeyValidationStats() map[string]interface{} {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_keys":    len(km.keys),
		"active_keys":   0,
		"valid_keys":    0,
		"invalid_keys":  0,
		"untested_keys": 0,
	}

	for _, status := range km.keyStatuses {
		if status.IsActive {
			stats["active_keys"] = stats["active_keys"].(int) + 1
		}

		if status.IsValid == nil {
			stats["untested_keys"] = stats["untested_keys"].(int) + 1
		} else if *status.IsValid {
			stats["valid_keys"] = stats["valid_keys"].(int) + 1
		} else {
			stats["invalid_keys"] = stats["invalid_keys"].(int) + 1
		}
	}

	return stats
}

// Close 关闭密钥管理器
func (km *KeyManager) Close() {
	if km.cancel != nil {
		km.cancel()
	}
	if km.database != nil {
		km.database.Close()
	}
}

// ConfigFile 配置文件结构
type ConfigFile struct {
	APIKeys struct {
		Keys []string `yaml:"keys"`
	} `yaml:"api_keys"`
}

// updateConfigFile 更新配置文件
func (km *KeyManager) updateConfigFile() error {
	if km.configPath == "" {
		return fmt.Errorf("配置文件路径未设置")
	}

	// 读取现有配置文件
	data, err := os.ReadFile(km.configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析YAML到通用结构
	var config yaml.Node
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 将当前密钥列表转换为YAML节点
	var keysNode yaml.Node
	keysNode.Kind = yaml.SequenceNode
	for _, key := range km.keys {
		var keyNode yaml.Node
		keyNode.Kind = yaml.ScalarNode
		keyNode.Value = key
		keysNode.Content = append(keysNode.Content, &keyNode)
	}

	// 查找并更新api_keys.keys节点
	if config.Kind == yaml.DocumentNode && len(config.Content) > 0 {
		root := config.Content[0]
		if root.Kind == yaml.MappingNode {
			for i := 0; i < len(root.Content); i += 2 {
				if root.Content[i].Value == "api_keys" {
					apiKeysNode := root.Content[i+1]
					if apiKeysNode.Kind == yaml.MappingNode {
						for j := 0; j < len(apiKeysNode.Content); j += 2 {
							if apiKeysNode.Content[j].Value == "keys" {
								apiKeysNode.Content[j+1] = &keysNode
								break
							}
						}
					}
					break
				}
			}
		}
	}

	// 写回配置文件
	newData, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("序列化配置文件失败: %v", err)
	}

	if err := os.WriteFile(km.configPath, newData, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	log.Printf("配置文件已更新: %s，当前密钥数量: %d", km.configPath, len(km.keys))
	return nil
}

// checkKeyDuplication 检查密钥是否重复（内部方法，调用时需要已获得锁）
func (km *KeyManager) checkKeyDuplication(newKeys []string) []string {
	var duplicates []string

	for _, newKey := range newKeys {
		if strings.TrimSpace(newKey) == "" {
			continue
		}

		for _, existingKey := range km.keys {
			if existingKey == newKey {
				duplicates = append(duplicates, newKey)
				break
			}
		}
	}

	return duplicates
}

// CheckKeyDuplication 公开的密钥重复检查方法
func (km *KeyManager) CheckKeyDuplication(newKeys []string) []string {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	return km.checkKeyDuplication(newKeys)
}
