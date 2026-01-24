package internal

import (
	"fmt"
	"log"
	"sync"

	"turnsapi/internal/database"
)

// 转换函数：从internal.UserGroup转换为database.UserGroup
func toDBUserGroup(group *UserGroup) *database.UserGroup {
	return &database.UserGroup{
		Name:              group.Name,
		ProviderType:      group.ProviderType,
		BaseURL:           group.BaseURL,
		Enabled:           group.Enabled,
		Timeout:           group.Timeout,
		MaxRetries:        group.MaxRetries,
		RotationStrategy:  group.RotationStrategy,
		APIKeys:           group.APIKeys,
		Models:            group.Models,
		Headers:           group.Headers,
		RequestParams:     group.RequestParams,
		ModelMappings:     group.ModelMappings,
		UseNativeResponse: group.UseNativeResponse,
		RPMLimit:          group.RPMLimit,
	}
}

// 转换函数：从database.UserGroup转换为internal.UserGroup
func fromDBUserGroup(dbGroup *database.UserGroup) *UserGroup {
	return &UserGroup{
		Name:              dbGroup.Name,
		ProviderType:      dbGroup.ProviderType,
		BaseURL:           dbGroup.BaseURL,
		Enabled:           dbGroup.Enabled,
		Timeout:           dbGroup.Timeout,
		MaxRetries:        dbGroup.MaxRetries,
		RotationStrategy:  dbGroup.RotationStrategy,
		APIKeys:           dbGroup.APIKeys,
		Models:            dbGroup.Models,
		Headers:           dbGroup.Headers,
		RequestParams:     dbGroup.RequestParams,
		ModelMappings:     dbGroup.ModelMappings,
		UseNativeResponse: dbGroup.UseNativeResponse,
		RPMLimit:          dbGroup.RPMLimit,
	}
}

// ConfigManager 配置管理器，整合YAML配置和数据库存储
type ConfigManager struct {
	config   *Config
	groupsDB *database.GroupsDB
	mutex    sync.RWMutex
}

// NewConfigManager 创建新的配置管理器
func NewConfigManager(configPath string, dbPath string) (*ConfigManager, error) {
	// 加载YAML配置
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// 初始化数据库
	groupsDB, err := database.NewGroupsDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize groups database: %w", err)
	}

	cm := &ConfigManager{
		config:   config,
		groupsDB: groupsDB,
	}

	// 初始化数据库数据
	if err := cm.initializeDatabase(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	return cm, nil
}

// initializeDatabase 初始化数据库数据
func (cm *ConfigManager) initializeDatabase() error {
	// 检查数据库中是否已有数据
	count, err := cm.groupsDB.GetGroupCount()
	if err != nil {
		return fmt.Errorf("failed to get group count: %w", err)
	}

	// 如果数据库为空，从YAML配置导入数据
	if count == 0 {
		log.Println("数据库为空，从YAML配置导入分组数据...")
		for groupID, group := range cm.config.UserGroups {
			dbGroup := toDBUserGroup(group)
			if err := cm.groupsDB.SaveGroup(groupID, dbGroup); err != nil {
				log.Printf("警告: 导入分组 %s 失败: %v", groupID, err)
			} else {
				log.Printf("已导入分组: %s (%s)", groupID, group.Name)
			}
		}
		log.Printf("完成从YAML配置导入 %d 个分组", len(cm.config.UserGroups))
	} else {
		log.Printf("数据库中已有 %d 个分组，跳过导入", count)
	}

	// 从数据库加载所有分组配置
	return cm.reloadFromDatabase()
}

// reloadFromDatabase 从数据库重新加载分组配置
func (cm *ConfigManager) reloadFromDatabase() error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	dbGroups, err := cm.groupsDB.LoadAllGroups()
	if err != nil {
		return fmt.Errorf("failed to load groups from database: %w", err)
	}

	// 转换数据库格式到内部格式
	groups := make(map[string]*UserGroup)
	for groupID, dbGroup := range dbGroups {
		groups[groupID] = fromDBUserGroup(dbGroup)
	}

	// 更新内存中的配置
	cm.config.UserGroups = groups
	log.Printf("从数据库加载了 %d 个分组配置", len(groups))

	return nil
}

// GetConfig 获取当前配置
func (cm *ConfigManager) GetConfig() *Config {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	return cm.config
}

// SaveGroup 保存分组配置到数据库
func (cm *ConfigManager) SaveGroup(groupID string, group *UserGroup) error {
	// 转换为数据库格式并保存
	dbGroup := toDBUserGroup(group)
	if err := cm.groupsDB.SaveGroup(groupID, dbGroup); err != nil {
		return fmt.Errorf("failed to save group to database: %w", err)
	}

	// 更新内存中的配置
	cm.mutex.Lock()
	cm.config.UserGroups[groupID] = group
	cm.mutex.Unlock()

	log.Printf("分组 %s 已保存", groupID)
	return nil
}

// UpdateGroup 更新分组配置
func (cm *ConfigManager) UpdateGroup(groupID string, group *UserGroup) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// 检查分组是否存在
	if _, exists := cm.config.UserGroups[groupID]; !exists {
		return fmt.Errorf("group not found: %s", groupID)
	}

	// 转换为数据库格式并保存
	dbGroup := toDBUserGroup(group)
	if err := cm.groupsDB.SaveGroup(groupID, dbGroup); err != nil {
		return fmt.Errorf("failed to update group in database: %w", err)
	}

	// 更新内存中的配置
	cm.config.UserGroups[groupID] = group

	log.Printf("分组 %s 已更新", groupID)
	return nil
}

// DeleteGroup 删除分组配置
func (cm *ConfigManager) DeleteGroup(groupID string) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// 检查分组是否存在
	if _, exists := cm.config.UserGroups[groupID]; !exists {
		return fmt.Errorf("group not found: %s", groupID)
	}

	// 从数据库删除
	if err := cm.groupsDB.DeleteGroup(groupID); err != nil {
		return fmt.Errorf("failed to delete group from database: %w", err)
	}

	// 从内存中删除
	delete(cm.config.UserGroups, groupID)

	log.Printf("分组 %s 已删除", groupID)
	return nil
}

// GetGroup 获取单个分组配置
func (cm *ConfigManager) GetGroup(groupID string) (*UserGroup, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	group, exists := cm.config.UserGroups[groupID]
	return group, exists
}

// GetAllGroups 获取所有分组配置
func (cm *ConfigManager) GetAllGroups() map[string]*UserGroup {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	// 创建副本以避免并发修改
	groups := make(map[string]*UserGroup)
	for k, v := range cm.config.UserGroups {
		groups[k] = v
	}
	return groups
}

// GetGroupsWithMetadata 获取分组配置及元数据（包括创建时间）
func (cm *ConfigManager) GetGroupsWithMetadata() (map[string]map[string]interface{}, error) {
	return cm.groupsDB.GetGroupsWithMetadata()
}

// GetEnabledGroups 获取启用的分组
func (cm *ConfigManager) GetEnabledGroups() map[string]*UserGroup {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	enabledGroups := make(map[string]*UserGroup)
	for groupID, group := range cm.config.UserGroups {
		if group.Enabled {
			enabledGroups[groupID] = group
		}
	}
	return enabledGroups
}

// GetGroupByModel 根据模型名称获取分组
func (cm *ConfigManager) GetGroupByModel(model string) (*UserGroup, string) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	return cm.config.GetGroupByModel(model)
}

// IsLegacyConfig 检查是否为旧版配置
func (cm *ConfigManager) IsLegacyConfig() bool {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	return cm.config.IsLegacyConfig()
}

// GetGroupCount 获取分组总数
func (cm *ConfigManager) GetGroupCount() int {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	return len(cm.config.UserGroups)
}

// GetEnabledGroupCount 获取启用的分组数量
func (cm *ConfigManager) GetEnabledGroupCount() int {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	count := 0
	for _, group := range cm.config.UserGroups {
		if group.Enabled {
			count++
		}
	}
	return count
}

// ToggleGroup 切换分组启用状态
func (cm *ConfigManager) ToggleGroup(groupID string) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	group, exists := cm.config.UserGroups[groupID]
	if !exists {
		return fmt.Errorf("group not found: %s", groupID)
	}

	// 如果要禁用分组，检查是否是最后一个启用的分组
	if group.Enabled {
		enabledCount := 0
		for _, g := range cm.config.UserGroups {
			if g.Enabled {
				enabledCount++
			}
		}

		if enabledCount <= 1 {
			return fmt.Errorf("cannot disable the last enabled group")
		}
	}

	// 切换状态
	group.Enabled = !group.Enabled

	// 转换为数据库格式并保存
	dbGroup := toDBUserGroup(group)
	if err := cm.groupsDB.SaveGroup(groupID, dbGroup); err != nil {
		// 回滚状态
		group.Enabled = !group.Enabled
		return fmt.Errorf("failed to toggle group in database: %w", err)
	}

	action := "enabled"
	if !group.Enabled {
		action = "disabled"
	}
	log.Printf("分组 %s 已%s", groupID, action)

	return nil
}

// Reload 重新加载配置
func (cm *ConfigManager) Reload() error {
	return cm.reloadFromDatabase()
}

// Close 关闭配置管理器
func (cm *ConfigManager) Close() error {
	if cm.groupsDB != nil {
		return cm.groupsDB.Close()
	}
	return nil
}

// ExportToYAML 导出配置到YAML文件（备份用）
func (cm *ConfigManager) ExportToYAML(filePath string) error {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	// TODO: 实现配置导出功能
	log.Printf("配置导出功能暂未实现: %s", filePath)
	return nil
}

// GetDatabaseStats 获取数据库统计信息
func (cm *ConfigManager) GetDatabaseStats() (map[string]interface{}, error) {
	totalGroups, err := cm.groupsDB.GetGroupCount()
	if err != nil {
		return nil, err
	}

	enabledGroups, err := cm.groupsDB.GetEnabledGroupCount()
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_groups":    totalGroups,
		"enabled_groups":  enabledGroups,
		"disabled_groups": totalGroups - enabledGroups,
	}

	return stats, nil
}

// UpdateAPIKeyValidation 更新API密钥的验证状态
// isValid 为 nil 时表示“未知/不变”，不会覆盖数据库中已有的 is_valid 值。
func (cm *ConfigManager) UpdateAPIKeyValidation(groupID, apiKey string, isValid *bool, validationError string) error {
	return cm.groupsDB.UpdateAPIKeyValidation(groupID, apiKey, isValid, validationError)
}

// GetAPIKeyValidationStatus 获取API密钥的验证状态
func (cm *ConfigManager) GetAPIKeyValidationStatus(groupID string) (map[string]map[string]interface{}, error) {
	return cm.groupsDB.GetAPIKeyValidationStatus(groupID)
}
