package keymanager

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"turnsapi/internal"
	"turnsapi/internal/database"
)

// DuplicateKeyInfo 重复密钥信息
type DuplicateKeyInfo struct {
	Key            string `json:"key"`             // 重复的密钥
	KeySuffix      string `json:"key_suffix"`      // 密钥后缀（用于显示）
	ConflictGroup  string `json:"conflict_group"`  // 冲突的分组ID
	OriginalIndex  int    `json:"original_index"`  // 原始索引位置
	DuplicateIndex int    `json:"duplicate_index"` // 重复索引位置（用于内部重复）
}

// GroupKeyManager 分组密钥管理器
type GroupKeyManager struct {
	groupID             string
	groupName           string
	keys                []string
	keyInfos            map[string]*KeyInfo
	keyStatuses         map[string]*KeyStatus
	rotationStrategy    string
	currentIndex        int
	mutex               sync.RWMutex
	// 密钥管理策略配置
	disablePermanentBan bool // 禁用永久禁用策略
	maxErrorCount       int  // 触发禁用的最大错误次数
	rateLimitCooldown   int  // 自定义限流冷却时间（秒）
}

// GroupKeyManagerConfig 分组密钥管理器配置
type GroupKeyManagerConfig struct {
	GroupID             string
	GroupName           string
	Keys                []string
	RotationStrategy    string
	DisablePermanentBan bool
	MaxErrorCount       int
	RateLimitCooldown   int
}

// NewGroupKeyManager 创建分组密钥管理器（保持向后兼容）
func NewGroupKeyManager(groupID, groupName string, keys []string, rotationStrategy string) *GroupKeyManager {
	return NewGroupKeyManagerWithConfig(GroupKeyManagerConfig{
		GroupID:             groupID,
		GroupName:           groupName,
		Keys:                keys,
		RotationStrategy:    rotationStrategy,
		DisablePermanentBan: false,
		MaxErrorCount:       10,
		RateLimitCooldown:   0, // 使用默认渐进策略
	})
}

// NewGroupKeyManagerWithConfig 使用配置创建分组密钥管理器
func NewGroupKeyManagerWithConfig(config GroupKeyManagerConfig) *GroupKeyManager {
	// 设置默认值
	maxErrorCount := config.MaxErrorCount
	if maxErrorCount <= 0 {
		maxErrorCount = 10
	}

	gkm := &GroupKeyManager{
		groupID:             config.GroupID,
		groupName:           config.GroupName,
		keys:                config.Keys,
		keyInfos:            make(map[string]*KeyInfo),
		keyStatuses:         make(map[string]*KeyStatus),
		rotationStrategy:    config.RotationStrategy,
		currentIndex:        0,
		disablePermanentBan: config.DisablePermanentBan,
		maxErrorCount:       maxErrorCount,
		rateLimitCooldown:   config.RateLimitCooldown,
	}

	// 初始化密钥信息和状态
	for _, key := range config.Keys {
		gkm.keyInfos[key] = &KeyInfo{
			Key:           key,
			Name:          fmt.Sprintf("%s-Key-%s", config.GroupName, getSafeKeySuffix(key)),
			Description:   fmt.Sprintf("密钥来自分组: %s", config.GroupName),
			IsActive:      true,
			AllowedModels: []string{},
		}
		gkm.keyStatuses[key] = &KeyStatus{
			Key:           key,
			Name:          gkm.keyInfos[key].Name,
			Description:   gkm.keyInfos[key].Description,
			IsActive:      true,
			LastUsed:      time.Time{},
			UsageCount:    0,
			ErrorCount:    0,
			AllowedModels: gkm.keyInfos[key].AllowedModels,
		}
	}

	return gkm
}

// GetNextKey 获取下一个可用的API密钥
func (gkm *GroupKeyManager) GetNextKey() (string, error) {
	gkm.mutex.Lock()
	defer gkm.mutex.Unlock()

	activeKeys := gkm.getActiveKeys()
	if len(activeKeys) == 0 {
		return "", fmt.Errorf("no active API keys available in group %s", gkm.groupID)
	}

	var selectedKey string

	switch gkm.rotationStrategy {
	case "round_robin":
		selectedKey = gkm.roundRobinSelection(activeKeys)
	case "random":
		selectedKey = gkm.randomSelection(activeKeys)
	case "least_used":
		selectedKey = gkm.leastUsedSelection(activeKeys)
	default:
		selectedKey = gkm.roundRobinSelection(activeKeys)
	}

	// 更新使用统计
	if status, exists := gkm.keyStatuses[selectedKey]; exists {
		status.LastUsed = time.Now()
		status.UsageCount++
	}

	return selectedKey, nil
}

// getActiveKeys 获取所有活跃的密钥（排除在限流冷却期内的密钥）
func (gkm *GroupKeyManager) getActiveKeys() []string {
	var activeKeys []string
	now := time.Now()
	for _, key := range gkm.keys {
		if status, exists := gkm.keyStatuses[key]; exists && status.IsActive {
			// 检查是否在限流冷却期内
			if !status.RateLimitUntil.IsZero() && now.Before(status.RateLimitUntil) {
				continue // 跳过在限流冷却期内的密钥
			}
			activeKeys = append(activeKeys, key)
		}
	}
	return activeKeys
}

// roundRobinSelection 轮询选择
func (gkm *GroupKeyManager) roundRobinSelection(activeKeys []string) string {
	// activeKeys 会动态变化（禁用/失效/恢复），这里以 gkm.keys 为基准做环形扫描，
	// 从 currentIndex 开始找下一个 IsActive 的 key，确保真正轮询且能跳过不可用 key。
	if len(activeKeys) == 0 || len(gkm.keys) == 0 {
		return ""
	}

	startIndex := gkm.currentIndex
	if startIndex < 0 || startIndex >= len(gkm.keys) {
		startIndex = 0
	}

	for offset := 0; offset < len(gkm.keys); offset++ {
		idx := (startIndex + offset) % len(gkm.keys)
		key := gkm.keys[idx]
		if status, exists := gkm.keyStatuses[key]; exists && status.IsActive {
			gkm.currentIndex = (idx + 1) % len(gkm.keys)
			return key
		}
	}

	return ""
}

// randomSelection 随机选择
func (gkm *GroupKeyManager) randomSelection(activeKeys []string) string {
	if len(activeKeys) == 0 {
		return ""
	}
	return activeKeys[randomInt(len(activeKeys))]
}

// leastUsedSelection 最少使用选择
func (gkm *GroupKeyManager) leastUsedSelection(activeKeys []string) string {
	if len(activeKeys) == 0 {
		return ""
	}

	var leastUsedKey string
	var minUsage int64 = -1

	for _, key := range activeKeys {
		if status, exists := gkm.keyStatuses[key]; exists {
			if minUsage == -1 || status.UsageCount < minUsage {
				minUsage = status.UsageCount
				leastUsedKey = key
			}
		}
	}

	return leastUsedKey
}

// ReportSuccess 报告密钥使用成功
func (gkm *GroupKeyManager) ReportSuccess(apiKey string) {
	gkm.mutex.Lock()
	defer gkm.mutex.Unlock()

	if status, exists := gkm.keyStatuses[apiKey]; exists {
		status.LastUsed = time.Now()
		// 成功使用后重置错误计数，让密钥可以继续正常使用
		if status.ErrorCount > 0 {
			log.Printf("密钥 %s (分组: %s) 恢复正常，重置错误计数（之前: %d）", gkm.maskKey(apiKey), gkm.groupID, status.ErrorCount)
			status.ErrorCount = 0
			status.LastError = ""
		}
		// 成功使用后清除限流冷却时间（但保留限流计数，用于优先级排序）
		if !status.RateLimitUntil.IsZero() {
			log.Printf("密钥 %s (分组: %s) 限流冷却已解除", gkm.maskKey(apiKey), gkm.groupID)
			status.RateLimitUntil = time.Time{}
		}
		// 如果密钥之前被禁用，成功后恢复活跃状态
		if !status.IsActive {
			status.IsActive = true
			log.Printf("密钥 %s (分组: %s) 已重新激活", gkm.maskKey(apiKey), gkm.groupID)
		}
	}
}

// ReportError 报告密钥使用错误
func (gkm *GroupKeyManager) ReportError(apiKey string, errorMsg string) {
	gkm.mutex.Lock()
	defer gkm.mutex.Unlock()

	if status, exists := gkm.keyStatuses[apiKey]; exists {
		status.LastError = errorMsg
		status.LastErrorTime = time.Now()

		// 判断是否为限流错误
		isRateLimit := isRateLimitError(errorMsg)

		if isRateLimit {
			// 限流错误：增加限流计数，设置冷却时间
			status.RateLimitCount++
			status.LastRateLimitAt = time.Now()

			// 计算冷却时间
			var cooldownDuration time.Duration
			if gkm.rateLimitCooldown > 0 {
				// 使用自定义冷却时间
				cooldownDuration = time.Duration(gkm.rateLimitCooldown) * time.Second
			} else {
				// 使用渐进策略：第1次：1分钟，第2次：5分钟，第3次：15分钟，之后：1小时
				switch {
				case status.RateLimitCount <= 1:
					cooldownDuration = 1 * time.Minute
				case status.RateLimitCount <= 2:
					cooldownDuration = 5 * time.Minute
				case status.RateLimitCount <= 3:
					cooldownDuration = 15 * time.Minute
				default:
					cooldownDuration = 1 * time.Hour
				}
			}
			status.RateLimitUntil = time.Now().Add(cooldownDuration)

			log.Printf("密钥 %s (分组: %s) 被限流，冷却 %v（限流次数: %d）",
				gkm.maskKey(apiKey), gkm.groupID, cooldownDuration, status.RateLimitCount)

			// 限流不禁用密钥，只是暂时跳过
		} else {
			// 其他错误：增加错误计数
			status.ErrorCount++

			log.Printf("密钥 %s (分组: %s) 发生错误: %s (错误次数: %d/%d)",
				gkm.maskKey(apiKey), gkm.groupID, errorMsg, status.ErrorCount, gkm.maxErrorCount)

			// 根据配置决定是否禁用密钥
			if !gkm.disablePermanentBan && status.ErrorCount >= int64(gkm.maxErrorCount) {
				status.IsActive = false
				log.Printf("密钥 %s (分组: %s) 因连续错误过多被禁用（已达到阈值 %d）",
					gkm.maskKey(apiKey), gkm.groupID, gkm.maxErrorCount)
			} else if gkm.disablePermanentBan {
				log.Printf("密钥 %s (分组: %s) 永久禁用策略已关闭，密钥保持活跃",
					gkm.maskKey(apiKey), gkm.groupID)
			}
		}
	}
}

// ReportRateLimit 专门报告限流错误
func (gkm *GroupKeyManager) ReportRateLimit(apiKey string, retryAfterSeconds int) {
	gkm.mutex.Lock()
	defer gkm.mutex.Unlock()

	if status, exists := gkm.keyStatuses[apiKey]; exists {
		status.RateLimitCount++
		status.LastRateLimitAt = time.Now()
		status.LastError = "rate_limit"
		status.LastErrorTime = time.Now()

		// 如果API返回了重试时间，使用它；否则使用默认策略
		var cooldownDuration time.Duration
		if retryAfterSeconds > 0 {
			cooldownDuration = time.Duration(retryAfterSeconds) * time.Second
		} else {
			// 默认冷却策略
			switch {
			case status.RateLimitCount <= 1:
				cooldownDuration = 1 * time.Minute
			case status.RateLimitCount <= 2:
				cooldownDuration = 5 * time.Minute
			case status.RateLimitCount <= 3:
				cooldownDuration = 15 * time.Minute
			default:
				cooldownDuration = 1 * time.Hour
			}
		}
		status.RateLimitUntil = time.Now().Add(cooldownDuration)

		log.Printf("密钥 %s (分组: %s) 被限流，冷却 %v（限流次数: %d）",
			gkm.maskKey(apiKey), gkm.groupID, cooldownDuration, status.RateLimitCount)
	}
}

// isRateLimitError 判断错误消息是否为限流错误
func isRateLimitError(errorMsg string) bool {
	lowerMsg := strings.ToLower(errorMsg)
	rateLimitKeywords := []string{
		"rate limit",
		"rate_limit",
		"ratelimit",
		"too many requests",
		"429",
		"quota exceeded",
		"quota_exceeded",
		"requests per minute",
		"rpm limit",
		"tokens per minute",
		"tpm limit",
	}
	for _, keyword := range rateLimitKeywords {
		if strings.Contains(lowerMsg, keyword) {
			return true
		}
	}
	return false
}

// IsKeyAvailable 检查密钥是否可用（考虑限流冷却）
func (gkm *GroupKeyManager) IsKeyAvailable(apiKey string) bool {
	gkm.mutex.RLock()
	defer gkm.mutex.RUnlock()

	status, exists := gkm.keyStatuses[apiKey]
	if !exists {
		return false
	}

	// 检查是否被禁用
	if !status.IsActive {
		return false
	}

	// 检查是否在限流冷却期内
	if !status.RateLimitUntil.IsZero() && time.Now().Before(status.RateLimitUntil) {
		return false
	}

	return true
}

// ResetDailyRateLimits 重置当天的限流计数（应在每天凌晨调用）
func (gkm *GroupKeyManager) ResetDailyRateLimits() {
	gkm.mutex.Lock()
	defer gkm.mutex.Unlock()

	resetCount := 0
	for _, status := range gkm.keyStatuses {
		if status.RateLimitCount > 0 {
			status.RateLimitCount = 0
			status.RateLimitUntil = time.Time{}
			resetCount++
		}
	}

	if resetCount > 0 {
		log.Printf("分组 %s 已重置 %d 个密钥的限流计数", gkm.groupID, resetCount)
	}
}

// GetKeyStatuses 获取所有密钥状态
func (gkm *GroupKeyManager) GetKeyStatuses() map[string]*KeyStatus {
	gkm.mutex.RLock()
	defer gkm.mutex.RUnlock()

	statuses := make(map[string]*KeyStatus)
	for key, status := range gkm.keyStatuses {
		// 创建副本以避免并发修改
		statusCopy := *status
		statuses[key] = &statusCopy
	}
	return statuses
}

// GetGroupInfo 获取分组信息
func (gkm *GroupKeyManager) GetGroupInfo() map[string]interface{} {
	gkm.mutex.RLock()
	defer gkm.mutex.RUnlock()

	activeCount := 0
	totalCount := len(gkm.keys)

	for _, status := range gkm.keyStatuses {
		if status.IsActive {
			activeCount++
		}
	}

	return map[string]interface{}{
		"group_id":          gkm.groupID,
		"group_name":        gkm.groupName,
		"total_keys":        totalCount,
		"active_keys":       activeCount,
		"rotation_strategy": gkm.rotationStrategy,
	}
}

// maskKey 掩码密钥显示
func (gkm *GroupKeyManager) maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// getSafeKeySuffix 安全地获取密钥后缀，避免数组越界
func getSafeKeySuffix(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[len(key)-8:]
}

// randomInt 生成随机整数
func randomInt(max int) int {
	return int(time.Now().UnixNano()) % max
}

// MultiGroupKeyManager 多分组密钥管理器
type MultiGroupKeyManager struct {
	config        *internal.Config
	groupManagers map[string]*GroupKeyManager
	database      *database.GroupsDB // 添加数据库连接
	mutex         sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewMultiGroupKeyManager 创建多分组密钥管理器
func NewMultiGroupKeyManager(config *internal.Config) *MultiGroupKeyManager {
	return NewMultiGroupKeyManagerWithDB(config, nil)
}

// NewMultiGroupKeyManagerWithDB 创建带数据库连接的多分组密钥管理器
func NewMultiGroupKeyManagerWithDB(config *internal.Config, db *database.GroupsDB) *MultiGroupKeyManager {
	ctx, cancel := context.WithCancel(context.Background())

	mgkm := &MultiGroupKeyManager{
		config:        config,
		groupManagers: make(map[string]*GroupKeyManager),
		database:      db,
		ctx:           ctx,
		cancel:        cancel,
	}

	// 初始化所有分组的密钥管理器
	for groupID, group := range config.UserGroups {
		if group.Enabled && len(group.APIKeys) > 0 {
			groupManager := NewGroupKeyManagerWithConfig(GroupKeyManagerConfig{
				GroupID:             groupID,
				GroupName:           group.Name,
				Keys:                group.APIKeys,
				RotationStrategy:    group.RotationStrategy,
				DisablePermanentBan: group.DisablePermanentBan,
				MaxErrorCount:       group.MaxErrorCount,
				RateLimitCooldown:   group.RateLimitCooldown,
			})

			// 如果有数据库连接，从数据库加载密钥验证状态
			if db != nil {
				mgkm.loadKeyValidationStatusFromDB(groupID, groupManager)
			}

			mgkm.groupManagers[groupID] = groupManager
		}
	}

	// 启动定时重置限流计数的后台任务
	go mgkm.startRateLimitResetScheduler()

	return mgkm
}

// startRateLimitResetScheduler 启动限流计数定时重置任务
func (mgkm *MultiGroupKeyManager) startRateLimitResetScheduler() {
	// 计算距离下一个凌晨的时间
	now := time.Now()
	nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	durationUntilMidnight := nextMidnight.Sub(now)

	log.Printf("限流计数重置任务已启动，将在 %v 后首次执行（%s）", durationUntilMidnight, nextMidnight.Format("2006-01-02 15:04:05"))

	// 首次等待到凌晨
	select {
	case <-time.After(durationUntilMidnight):
		mgkm.resetAllDailyRateLimits()
	case <-mgkm.ctx.Done():
		return
	}

	// 之后每24小时执行一次
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mgkm.resetAllDailyRateLimits()
		case <-mgkm.ctx.Done():
			return
		}
	}
}

// resetAllDailyRateLimits 重置所有分组的每日限流计数
func (mgkm *MultiGroupKeyManager) resetAllDailyRateLimits() {
	mgkm.mutex.RLock()
	defer mgkm.mutex.RUnlock()

	log.Printf("开始每日限流计数重置...")

	for groupID, groupManager := range mgkm.groupManagers {
		groupManager.ResetDailyRateLimits()
		log.Printf("已重置分组 %s 的限流计数", groupID)
	}

	log.Printf("每日限流计数重置完成")
}

// GetNextKeyForGroup 获取指定分组的下一个可用密钥
func (mgkm *MultiGroupKeyManager) GetNextKeyForGroup(groupID string) (string, error) {
	mgkm.mutex.RLock()
	groupManager, exists := mgkm.groupManagers[groupID]
	mgkm.mutex.RUnlock()

	if !exists {
		return "", fmt.Errorf("group %s not found or not enabled", groupID)
	}

	return groupManager.GetNextKey()
}

// GetNextKeyForModel 根据模型名称获取合适分组的下一个可用密钥
func (mgkm *MultiGroupKeyManager) GetNextKeyForModel(modelName string) (string, string, error) {
	// 查找支持该模型的分组
	group, groupID := mgkm.config.GetGroupByModel(modelName)
	if group == nil {
		return "", "", fmt.Errorf("no enabled group found for model %s", modelName)
	}

	key, err := mgkm.GetNextKeyForGroup(groupID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get key for group %s: %w", groupID, err)
	}

	return key, groupID, nil
}

// ReportSuccess 报告密钥使用成功
func (mgkm *MultiGroupKeyManager) ReportSuccess(groupID, apiKey string) {
	mgkm.mutex.RLock()
	groupManager, exists := mgkm.groupManagers[groupID]
	mgkm.mutex.RUnlock()

	if exists {
		groupManager.ReportSuccess(apiKey)
	}
}

// ReportError 报告密钥使用错误
func (mgkm *MultiGroupKeyManager) ReportError(groupID, apiKey string, errorMsg string) {
	mgkm.mutex.RLock()
	groupManager, exists := mgkm.groupManagers[groupID]
	mgkm.mutex.RUnlock()

	if exists {
		groupManager.ReportError(apiKey, errorMsg)
	}
}

// GetAllGroupStatuses 获取所有分组的状态
func (mgkm *MultiGroupKeyManager) GetAllGroupStatuses() map[string]interface{} {
	mgkm.mutex.RLock()
	defer mgkm.mutex.RUnlock()

	statuses := make(map[string]interface{})

	for groupID, groupManager := range mgkm.groupManagers {
		groupInfo := groupManager.GetGroupInfo()
		groupInfo["key_statuses"] = groupManager.GetKeyStatuses()
		statuses[groupID] = groupInfo
	}

	return statuses
}

// GetGroupStatus 获取指定分组的状态
func (mgkm *MultiGroupKeyManager) GetGroupStatus(groupID string) (interface{}, bool) {
	mgkm.mutex.RLock()
	groupManager, exists := mgkm.groupManagers[groupID]
	mgkm.mutex.RUnlock()

	if !exists {
		return nil, false
	}

	groupInfo := groupManager.GetGroupInfo()
	groupInfo["key_statuses"] = groupManager.GetKeyStatuses()
	return groupInfo, true
}

// UpdateGroupConfig 更新分组配置
func (mgkm *MultiGroupKeyManager) UpdateGroupConfig(groupID string, group *internal.UserGroup) error {
	mgkm.mutex.Lock()
	defer mgkm.mutex.Unlock()

	if group == nil {
		// 删除分组管理器
		delete(mgkm.groupManagers, groupID)
		log.Printf("删除分组 %s 的密钥管理器", groupID)
	} else if group.Enabled && len(group.APIKeys) > 0 {
		// 创建或更新分组管理器
		groupManager := NewGroupKeyManagerWithConfig(GroupKeyManagerConfig{
			GroupID:             groupID,
			GroupName:           group.Name,
			Keys:                group.APIKeys,
			RotationStrategy:    group.RotationStrategy,
			DisablePermanentBan: group.DisablePermanentBan,
			MaxErrorCount:       group.MaxErrorCount,
			RateLimitCooldown:   group.RateLimitCooldown,
		})
		mgkm.groupManagers[groupID] = groupManager
		log.Printf("更新分组 %s 的密钥管理器", groupID)
	} else {
		// 删除分组管理器（禁用或无密钥）
		delete(mgkm.groupManagers, groupID)
		log.Printf("删除分组 %s 的密钥管理器（禁用或无密钥）", groupID)
	}

	return nil
}

// UpdateKeyStatus 实时更新密钥状态（基于实际请求结果）
func (mgkm *MultiGroupKeyManager) UpdateKeyStatus(groupID, apiKey string, isSuccess bool, errorMsg string) {
	mgkm.mutex.RLock()
	groupManager, exists := mgkm.groupManagers[groupID]
	mgkm.mutex.RUnlock()

	if exists {
		if isSuccess {
			groupManager.ReportSuccess(apiKey)
		} else {
			groupManager.ReportError(apiKey, errorMsg)
		}
	}
}

// ForceSetKeyStatus 强制设置密钥状态（管理员功能）
func (mgkm *MultiGroupKeyManager) ForceSetKeyStatus(groupID, apiKey string, isValid bool, reason string) error {
	mgkm.mutex.RLock()
	groupManager, exists := mgkm.groupManagers[groupID]
	mgkm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("group %s not found", groupID)
	}

	groupManager.mutex.Lock()
	defer groupManager.mutex.Unlock()

	// 检查密钥是否存在
	if status, exists := groupManager.keyStatuses[apiKey]; exists {
		// 更新密钥状态
		status.IsValid = &isValid
		status.ValidationError = reason
		status.UpdatedAt = time.Now()

		// 如果设置为有效，清除错误信息并激活密钥
		if isValid {
			status.IsActive = true
			status.ErrorCount = 0
			status.LastError = ""
		}

		log.Printf("强制设置密钥状态: 分组=%s, 密钥=%s, 有效=%v, 原因=%s",
			groupID, groupManager.maskKey(apiKey), isValid, reason)

		return nil
	}

	return fmt.Errorf("API key not found in group %s", groupID)
}

// GetInvalidKeys 获取指定分组中的所有无效密钥
func (mgkm *MultiGroupKeyManager) GetInvalidKeys(groupID string) ([]string, error) {
	mgkm.mutex.RLock()
	groupManager, exists := mgkm.groupManagers[groupID]
	mgkm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("group %s not found", groupID)
	}

	groupManager.mutex.RLock()
	defer groupManager.mutex.RUnlock()

	var invalidKeys []string
	for _, key := range groupManager.keys {
		if status, exists := groupManager.keyStatuses[key]; exists {
			if status.IsValid != nil && !*status.IsValid {
				invalidKeys = append(invalidKeys, key)
			}
		}
	}

	return invalidKeys, nil
}

// GetValidKeys 获取指定分组中的所有有效密钥
func (mgkm *MultiGroupKeyManager) GetValidKeys(groupID string) ([]string, error) {
	mgkm.mutex.RLock()
	groupManager, exists := mgkm.groupManagers[groupID]
	mgkm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("group %s not found", groupID)
	}

	groupManager.mutex.RLock()
	defer groupManager.mutex.RUnlock()

	var validKeys []string
	for _, key := range groupManager.keys {
		if status, exists := groupManager.keyStatuses[key]; exists {
			// 如果没有验证状态或验证状态为有效，则认为是有效密钥
			if status.IsValid == nil || *status.IsValid {
				validKeys = append(validKeys, key)
			}
		}
	}

	return validKeys, nil
}

// GetKeyValidationSummary 获取分组密钥验证状态摘要
func (mgkm *MultiGroupKeyManager) GetKeyValidationSummary(groupID string) (map[string]interface{}, error) {
	mgkm.mutex.RLock()
	groupManager, exists := mgkm.groupManagers[groupID]
	mgkm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("group %s not found", groupID)
	}

	groupManager.mutex.RLock()
	defer groupManager.mutex.RUnlock()

	validCount := 0
	invalidCount := 0
	unknownCount := 0
	totalCount := len(groupManager.keys)

	for _, key := range groupManager.keys {
		if status, exists := groupManager.keyStatuses[key]; exists {
			if status.IsValid == nil {
				unknownCount++
			} else if *status.IsValid {
				validCount++
			} else {
				invalidCount++
			}
		} else {
			unknownCount++
		}
	}

	return map[string]interface{}{
		"group_id":     groupID,
		"group_name":   groupManager.groupName,
		"total_keys":   totalCount,
		"valid_keys":   validCount,
		"invalid_keys": invalidCount,
		"unknown_keys": unknownCount,
	}, nil
}

// GetKeyHealthStatus 获取密钥健康状态统计
func (mgkm *MultiGroupKeyManager) GetKeyHealthStatus() map[string]interface{} {
	mgkm.mutex.RLock()
	defer mgkm.mutex.RUnlock()

	stats := make(map[string]interface{})
	totalKeys := 0
	totalActiveKeys := 0

	for groupID, groupManager := range mgkm.groupManagers {
		groupInfo := groupManager.GetGroupInfo()
		totalKeys += groupInfo["total_keys"].(int)
		totalActiveKeys += groupInfo["active_keys"].(int)

		stats[groupID] = map[string]interface{}{
			"group_name":   groupInfo["group_name"],
			"total_keys":   groupInfo["total_keys"],
			"active_keys":  groupInfo["active_keys"],
			"key_statuses": groupManager.GetKeyStatuses(),
		}
	}

	stats["summary"] = map[string]interface{}{
		"total_keys":        totalKeys,
		"total_active_keys": totalActiveKeys,
		"total_groups":      len(mgkm.groupManagers),
	}

	return stats
}

// CheckKeyDuplication 检查密钥是否在所有分组中重复
func (mgkm *MultiGroupKeyManager) CheckKeyDuplication(newKeys []string) map[string][]string {
	mgkm.mutex.RLock()
	defer mgkm.mutex.RUnlock()

	duplicates := make(map[string][]string)

	for _, newKey := range newKeys {
		if strings.TrimSpace(newKey) == "" {
			continue
		}

		var foundInGroups []string

		// 检查所有分组中的密钥
		for groupID, groupManager := range mgkm.groupManagers {
			for _, existingKey := range groupManager.keys {
				if existingKey == newKey {
					foundInGroups = append(foundInGroups, groupID)
					break
				}
			}
		}

		if len(foundInGroups) > 0 {
			duplicates[newKey] = foundInGroups
		}
	}

	return duplicates
}

// CheckSingleKeyDuplication 检查单个密钥是否重复
func (mgkm *MultiGroupKeyManager) CheckSingleKeyDuplication(newKey string) []string {
	if strings.TrimSpace(newKey) == "" {
		return nil
	}

	duplicates := mgkm.CheckKeyDuplication([]string{newKey})
	if foundInGroups, exists := duplicates[newKey]; exists {
		return foundInGroups
	}
	return nil
}

// GetAllKeysAcrossGroups 获取所有分组中的密钥列表（用于去重检查）
func (mgkm *MultiGroupKeyManager) GetAllKeysAcrossGroups() map[string][]string {
	mgkm.mutex.RLock()
	defer mgkm.mutex.RUnlock()

	allKeys := make(map[string][]string)

	for groupID, groupManager := range mgkm.groupManagers {
		for _, key := range groupManager.keys {
			if existingGroups, exists := allKeys[key]; exists {
				allKeys[key] = append(existingGroups, groupID)
			} else {
				allKeys[key] = []string{groupID}
			}
		}
	}

	return allKeys
}

// ValidateKeysForGroup 验证要添加到分组的密钥，只检查分组内重复
func (mgkm *MultiGroupKeyManager) ValidateKeysForGroup(groupID string, newKeys []string) (validKeys []string, groupDuplicates []DuplicateKeyInfo, internalDuplicates []DuplicateKeyInfo) {
	mgkm.mutex.RLock()
	defer mgkm.mutex.RUnlock()

	validKeys = make([]string, 0)
	groupDuplicates = make([]DuplicateKeyInfo, 0)
	internalDuplicates = make([]DuplicateKeyInfo, 0)

	// 获取目标分组现有密钥
	var existingKeys map[string]bool
	if groupManager, exists := mgkm.groupManagers[groupID]; exists {
		existingKeys = make(map[string]bool)
		for _, key := range groupManager.keys {
			existingKeys[key] = true
		}
	} else {
		existingKeys = make(map[string]bool)
	}

	// 用于跟踪输入列表中的重复
	seenInInput := make(map[string]int) // key -> first occurrence index

	for i, key := range newKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		// 检查输入列表内部重复
		if firstIndex, exists := seenInInput[key]; exists {
			internalDuplicates = append(internalDuplicates, DuplicateKeyInfo{
				Key:            key,
				KeySuffix:      getSafeKeySuffix(key),
				OriginalIndex:  firstIndex,
				DuplicateIndex: i,
			})
			continue
		}
		seenInInput[key] = i

		// 检查与分组内现有密钥的重复
		if existingKeys[key] {
			groupDuplicates = append(groupDuplicates, DuplicateKeyInfo{
				Key:           key,
				KeySuffix:     getSafeKeySuffix(key),
				ConflictGroup: groupID,
				OriginalIndex: i,
			})
			continue
		}

		// 密钥有效，添加到结果中
		validKeys = append(validKeys, key)
	}

	return validKeys, groupDuplicates, internalDuplicates
}

// loadKeyValidationStatusFromDB 从数据库加载密钥验证状态
func (mgkm *MultiGroupKeyManager) loadKeyValidationStatusFromDB(groupID string, groupManager *GroupKeyManager) {
	validationStatus, err := mgkm.database.GetAPIKeyValidationStatus(groupID)
	if err != nil {
		log.Printf("警告: 无法从数据库加载分组 %s 的密钥验证状态: %v", groupID, err)
		return
	}

	// 更新密钥状态
	validCount := 0
	invalidCount := 0
	for apiKey, status := range validationStatus {
		if keyStatus, exists := groupManager.keyStatuses[apiKey]; exists {
			// 更新验证状态
			if isValid, ok := status["is_valid"].(*bool); ok && isValid != nil {
				keyStatus.IsValid = isValid
				// 重要：只有当密钥有效时才设置为活跃状态，无效的密钥保持活跃以便重试
				if *isValid {
					keyStatus.IsActive = true
					validCount++
				} else {
					// 无效的密钥仍然保持活跃状态，但标记为无效
					keyStatus.IsActive = true
					invalidCount++
				}
			}

			// 更新验证错误信息
			if validationError, ok := status["validation_error"].(*string); ok && validationError != nil {
				keyStatus.ValidationError = *validationError
			}

			// 更新最后验证时间
			if lastValidatedAt, ok := status["last_validated_at"].(*string); ok && lastValidatedAt != nil {
				if parsedTime, err := time.Parse("2006-01-02 15:04:05", *lastValidatedAt); err == nil {
					keyStatus.LastValidated = &parsedTime
				}
			}

			keyStatus.UpdatedAt = time.Now()
		}
	}

	log.Printf("已从数据库加载分组 %s 的密钥验证状态，共 %d 个密钥（有效: %d，无效: %d）",
		groupID, len(validationStatus), validCount, invalidCount)
}

// Close 关闭管理器
func (mgkm *MultiGroupKeyManager) Close() {
	if mgkm.cancel != nil {
		mgkm.cancel()
	}
}
