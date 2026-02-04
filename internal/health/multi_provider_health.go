package health

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"turnsapi/internal"
	"turnsapi/internal/keymanager"
	"turnsapi/internal/providers"
	"turnsapi/internal/router"

	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

// ProviderHealthStatus 提供商健康状态
type ProviderHealthStatus struct {
	GroupID      string                 `json:"group_id"`
	GroupName    string                 `json:"group_name"`
	ProviderType string                 `json:"provider_type"`
	BaseURL      string                 `json:"base_url"`
	Enabled      bool                   `json:"enabled"`
	Healthy      bool                   `json:"healthy"`
	LastError    string                 `json:"last_error,omitempty"`
	TotalKeys    int                    `json:"total_keys"`
	ActiveKeys   int                    `json:"active_keys"`
	KeyStatuses  map[string]interface{} `json:"key_statuses,omitempty"`
}

// SystemHealthStatus 系统健康状态
type SystemHealthStatus struct {
	Status         string                           `json:"status"`
	Timestamp      time.Time                        `json:"timestamp"`
	Uptime         time.Duration                    `json:"uptime"`
	StartTime      time.Time                        `json:"start_time"`
	TotalGroups    int                              `json:"total_groups"`
	EnabledGroups  int                              `json:"enabled_groups"`
	DisabledGroups int                              `json:"disabled_groups"`
	TotalKeys      int                              `json:"total_keys"`
	ActiveKeys     int                              `json:"active_keys"`
	TotalRequests  int64                            `json:"total_requests"`
	CPUUsage       float64                          `json:"cpu_usage"`
	MemoryUsage    float64                          `json:"memory_usage"`
	Version        string                           `json:"version"`
	GroupStatuses  map[string]*ProviderHealthStatus `json:"group_statuses"`
}

// MultiProviderHealthChecker 多提供商健康检查器
type MultiProviderHealthChecker struct {
	config          *internal.Config
	keyManager      *keymanager.MultiGroupKeyManager
	providerManager *providers.ProviderManager
	providerRouter  *router.ProviderRouter
	startTime       time.Time

	// 健康状态缓存
	healthStatuses  map[string]*ProviderHealthStatus
	lastSystemCheck time.Time
	mutex           sync.RWMutex

	// 系统资源监控
	totalRequests int64
	cpuUsage      float64
	memoryUsage   float64
	lastCPUTime   time.Time
	lastCPUStats  runtime.MemStats

	// 健康检查配置
	checkTimeout time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewMultiProviderHealthChecker 创建多提供商健康检查器
func NewMultiProviderHealthChecker(
	config *internal.Config,
	keyManager *keymanager.MultiGroupKeyManager,
	providerManager *providers.ProviderManager,
	providerRouter *router.ProviderRouter,
) *MultiProviderHealthChecker {
	ctx, cancel := context.WithCancel(context.Background())

	checker := &MultiProviderHealthChecker{
		config:          config,
		keyManager:      keyManager,
		providerManager: providerManager,
		providerRouter:  providerRouter,
		startTime:       time.Now(),
		healthStatuses:  make(map[string]*ProviderHealthStatus),
		checkTimeout:    10 * time.Second, // 默认10秒超时
		ctx:             ctx,
		cancel:          cancel,
	}

	return checker
}

// GetSystemHealth 获取系统健康状态
func (hc *MultiProviderHealthChecker) GetSystemHealth() *SystemHealthStatus {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	// 移除自动触发逻辑，只返回缓存的状态
	// 健康检查现在只在手动刷新或首次添加分组时执行

	totalGroups := len(hc.config.UserGroups)
	enabledGroups := 0
	disabledGroups := 0
	totalKeys := 0
	activeKeys := 0

	// 统计分组状态
	for _, group := range hc.config.UserGroups {
		if group.Enabled {
			enabledGroups++
		} else {
			disabledGroups++
		}
	}

	// 只包含当前配置中存在的分组的健康状态
	currentGroupStatuses := make(map[string]*ProviderHealthStatus)

	// 统计密钥状态，只包含当前配置中的分组
	for groupID, status := range hc.healthStatuses {
		// 检查分组是否仍然存在于配置中
		if _, exists := hc.config.UserGroups[groupID]; !exists {
			continue // 跳过已删除的分组
		}

		currentGroupStatuses[groupID] = status

		if status.Enabled {
			totalKeys += status.TotalKeys
			activeKeys += status.ActiveKeys
		}
	}

	// 系统状态始终为运行状态
	overallStatus := "running"

	// 更新系统指标
	hc.updateSystemMetrics()

	return &SystemHealthStatus{
		Status:         overallStatus,
		Timestamp:      time.Now(),
		Uptime:         time.Since(hc.startTime),
		StartTime:      hc.startTime,
		TotalGroups:    totalGroups,
		EnabledGroups:  enabledGroups,
		DisabledGroups: disabledGroups,
		TotalKeys:      totalKeys,
		ActiveKeys:     activeKeys,
		TotalRequests:  hc.totalRequests,
		CPUUsage:       hc.cpuUsage,
		MemoryUsage:    hc.memoryUsage,
		Version:        "v2.2.0",
		GroupStatuses:  currentGroupStatuses,
	}
}

// GetProviderHealth 获取特定提供商的健康状态
func (hc *MultiProviderHealthChecker) GetProviderHealth(groupID string) (*ProviderHealthStatus, bool) {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	status, exists := hc.healthStatuses[groupID]
	return status, exists
}

// CheckProviderHealth 检查特定提供商的健康状态
func (hc *MultiProviderHealthChecker) CheckProviderHealth(groupID string) *ProviderHealthStatus {
	group, exists := hc.config.GetGroupByID(groupID)
	if !exists {
		return &ProviderHealthStatus{
			GroupID:   groupID,
			Enabled:   false,
			Healthy:   false,
			LastError: "Group not found",
		}
	}

	status := &ProviderHealthStatus{
		GroupID:      groupID,
		GroupName:    group.Name,
		ProviderType: group.ProviderType,
		BaseURL:      group.BaseURL,
		Enabled:      group.Enabled,
	}

	if !group.Enabled {
		status.Healthy = false
		status.LastError = "Group is disabled"
		return status
	}

	// 获取密钥状态
	groupStatus, exists := hc.keyManager.GetGroupStatus(groupID)
	if exists {
		if groupInfo, ok := groupStatus.(map[string]interface{}); ok {
			if totalKeys, ok := groupInfo["total_keys"].(int); ok {
				status.TotalKeys = totalKeys
			}
			if activeKeys, ok := groupInfo["active_keys"].(int); ok {
				status.ActiveKeys = activeKeys
			}
			if keyStatuses, ok := groupInfo["key_statuses"]; ok {
				status.KeyStatuses = map[string]interface{}{"keys": keyStatuses}
			}
		}
	}

	if status.ActiveKeys == 0 {
		status.Healthy = false
		status.LastError = "No active API keys"
		return status
	}

	// 执行实际的健康检查
	err := hc.performProviderHealthCheck(groupID, group)

	if err != nil {
		// 检查是否是配额限制错误
		if hc.isQuotaExceededError(err) {
			// 配额限制不视为错误，而是一种特殊的健康状态
			status.Healthy = true
			status.LastError = "配额限制中 (Quota Limited)"
			log.Printf("Health check for group %s: quota limited (not an error): %v", groupID, err)
		} else {
			status.Healthy = false
			status.LastError = err.Error()
			log.Printf("Health check failed for group %s: %v", groupID, err)
		}
	} else {
		status.Healthy = true
		status.LastError = ""
	}

	return status
}

// isQuotaExceededError 检查是否是配额超限错误
func (hc *MultiProviderHealthChecker) isQuotaExceededError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "429") ||
		strings.Contains(errStr, "Quota exceeded") ||
		strings.Contains(errStr, "RATE_LIMIT_EXCEEDED") ||
		strings.Contains(errStr, "quota exceeded")
}

// performProviderHealthCheck 执行提供商健康检查
func (hc *MultiProviderHealthChecker) performProviderHealthCheck(groupID string, group *internal.UserGroup) error {
	// 获取API密钥
	apiKey, err := hc.keyManager.GetNextKeyForGroup(groupID)
	if err != nil {
		return fmt.Errorf("failed to get API key: %w", err)
	}

	// 创建提供商配置
	providerConfig := &providers.ProviderConfig{
		BaseURL:         group.BaseURL,
		APIKey:          apiKey,
		Timeout:         group.Timeout,
		MaxRetries:      1, // 健康检查只尝试一次
		Headers:         group.Headers,
		ProviderType:    group.ProviderType,
		UseResponsesAPI: group.UseResponsesAPI,
	}

	// 获取提供商实例
	provider, err := hc.providerManager.GetProvider(groupID, providerConfig)
	if err != nil {
		return fmt.Errorf("failed to get provider: %w", err)
	}

	// 执行健康检查
	ctx, cancel := context.WithTimeout(hc.ctx, hc.checkTimeout)
	defer cancel()

	err = provider.HealthCheck(ctx)
	if err != nil {
		hc.keyManager.ReportError(groupID, apiKey, err.Error())
		return err
	}

	hc.keyManager.ReportSuccess(groupID, apiKey)
	return nil
}

// Stop 停止健康检查器
func (hc *MultiProviderHealthChecker) Stop() {
	if hc.cancel != nil {
		hc.cancel()
	}
}

// PerformHealthCheck 手动执行健康检查（移除了定时逻辑）
func (hc *MultiProviderHealthChecker) PerformHealthCheck() {
	log.Println("手动执行多提供商健康检查...")

	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	hc.lastSystemCheck = time.Now()

	// 清理已删除分组的健康状态
	for groupID := range hc.healthStatuses {
		if _, exists := hc.config.UserGroups[groupID]; !exists {
			delete(hc.healthStatuses, groupID)
			log.Printf("清理已删除分组的健康状态: %s", groupID)
		}
	}

	// 并发检查所有启用的分组
	var wg sync.WaitGroup
	statusChan := make(chan *ProviderHealthStatus, len(hc.config.UserGroups))

	for groupID := range hc.config.UserGroups {
		wg.Add(1)
		go func(gid string) {
			defer wg.Done()
			status := hc.CheckProviderHealth(gid)
			statusChan <- status
		}(groupID)
	}

	// 等待所有检查完成
	go func() {
		wg.Wait()
		close(statusChan)
	}()

	// 收集结果
	for status := range statusChan {
		hc.healthStatuses[status.GroupID] = status
	}

	// 统计结果
	healthy := 0
	total := 0
	for _, status := range hc.healthStatuses {
		if status.Enabled {
			total++
			if status.Healthy {
				healthy++
			}
		}
	}

	log.Printf("手动健康检查完成: %d/%d 个提供商分组健康", healthy, total)
}

// PerformInitialHealthCheck 首次添加分组时执行健康检查
func (hc *MultiProviderHealthChecker) PerformInitialHealthCheck(groupID string) {
	log.Printf("为新分组 %s 执行初始健康检查", groupID)

	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	status := hc.CheckProviderHealth(groupID)
	hc.healthStatuses[groupID] = status

	log.Printf("分组 %s 初始健康检查完成: %t", groupID, status.Healthy)
}

// IncrementRequestCount 增加请求计数
func (hc *MultiProviderHealthChecker) IncrementRequestCount() {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	hc.totalRequests++
}

// updateSystemMetrics 更新系统指标
func (hc *MultiProviderHealthChecker) updateSystemMetrics() {
	// 获取CPU使用率（简化实现，实际项目中可以使用更精确的方法）
	hc.cpuUsage = hc.getCPUUsage()

	// 获取内存使用率
	hc.memoryUsage = hc.getMemoryUsage()
}

// getCPUUsage 获取本程序的CPU使用率（相对于系统总CPU）
func (hc *MultiProviderHealthChecker) getCPUUsage() float64 {
	// 获取当前进程
	pid := os.Getpid()
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		// 如果无法获取进程信息，返回基于runtime的估算
		return hc.getCPUUsageFallback()
	}

	// 获取CPU使用率
	cpuPercent, err := proc.CPUPercent()
	if err != nil {
		// 如果无法获取CPU使用率，返回基于runtime的估算
		return hc.getCPUUsageFallback()
	}

	return cpuPercent
}

// getCPUUsageFallback CPU使用率获取的备用方法
func (hc *MultiProviderHealthChecker) getCPUUsageFallback() float64 {
	// 获取当前时间
	now := time.Now()

	// 如果是第一次调用，初始化
	if hc.lastCPUTime.IsZero() {
		hc.lastCPUTime = now
		return 0.1 // 返回一个小的基础值
	}

	// 计算时间差
	timeDiff := now.Sub(hc.lastCPUTime).Seconds()
	if timeDiff < 1.0 {
		// 时间间隔太短，返回上次的值
		return hc.cpuUsage
	}

	// 基于程序活动估算CPU使用率
	uptime := time.Since(hc.startTime).Seconds()

	// 1. 基于请求处理活动
	requestRate := 0.0
	if uptime > 0 {
		requestRate = float64(hc.totalRequests) / uptime
	}

	// 2. 基于Goroutine数量（反映并发活动）
	goroutineCount := float64(runtime.NumGoroutine())

	// 3. 基于GC活动
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	gcRate := 0.0
	if uptime > 0 {
		gcRate = float64(m.NumGC) / uptime
	}

	// 综合计算本程序的CPU使用率估算
	usage := 0.1                    // 基础值
	usage += requestRate * 0.02     // 请求处理贡献
	usage += goroutineCount * 0.005 // Goroutine贡献
	usage += gcRate * 0.1           // GC活动贡献

	// 限制在合理范围内
	if usage > 5.0 {
		usage = 5.0
	}
	if usage < 0.1 {
		usage = 0.1
	}

	// 更新记录
	hc.lastCPUTime = now

	return usage
}

// getMemoryUsage 获取本程序的内存使用率（相对于系统总内存）
func (hc *MultiProviderHealthChecker) getMemoryUsage() float64 {
	// 获取系统内存信息
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		// 如果无法获取系统内存信息，使用备用方法
		return hc.getMemoryUsageFallback()
	}

	// 获取当前程序的内存使用量
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 计算内存使用率：程序使用的内存 / 系统总内存 * 100
	usage := float64(m.Alloc) / float64(vmStat.Total) * 100

	return usage
}

// getMemoryUsageFallback 内存使用率获取的备用方法
func (hc *MultiProviderHealthChecker) getMemoryUsageFallback() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 获取当前分配的内存（字节）
	allocMB := float64(m.Alloc) / 1024 / 1024 // 转换为MB

	// 假设系统有8GB内存作为基准
	systemMemoryMB := 8 * 1024.0 // 8GB
	usage := (allocMB / systemMemoryMB) * 100

	// 确保至少显示一些使用率
	if usage < 0.01 {
		usage = 0.01
	}

	return usage
}

// Close 关闭健康检查器
func (hc *MultiProviderHealthChecker) Close() {
	if hc.cancel != nil {
		hc.cancel()
	}
}

// RemoveGroup 移除分组的健康状态
func (hc *MultiProviderHealthChecker) RemoveGroup(groupID string) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	delete(hc.healthStatuses, groupID)
	// log.Printf("已从健康检查器中移除分组: %s", groupID)
}
