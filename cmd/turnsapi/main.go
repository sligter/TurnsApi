package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"turnsapi/internal"
	"turnsapi/internal/api"
	"turnsapi/internal/database"
	"turnsapi/internal/keymanager"
	"turnsapi/internal/logger"
)

var (
	configPath = flag.String("config", "config/config.yaml", "配置文件路径")
	dbPath     = flag.String("db", "", "数据库文件路径 (override; empty uses config.database)")
	version    = "2.0.0"
)

func main() {
	flag.Parse()

	log.Printf("TurnsAPI Multi-Provider v%s 快速启动中...", version)

	// 创建配置管理器
	configManager, err := internal.NewConfigManager(*configPath, *dbPath)
	if err != nil {
		log.Fatalf("配置管理器初始化失败: %v", err)
	}
	defer configManager.Close()

	// 获取配置
	config := configManager.GetConfig()

	// 基本配置验证（最小化验证，提高启动速度）
	if len(config.UserGroups) == 0 {
		log.Fatal("配置文件中未找到任何用户分组")
	}

	enabledGroups := config.GetEnabledGroups()
	if len(enabledGroups) == 0 {
		log.Fatal("没有启用的提供商分组")
	}

	log.Printf("加载了 %d 个分组，其中 %d 个已启用", len(config.UserGroups), len(enabledGroups))

	// 延迟创建日志目录（异步）
	go func() {
		if config.Logging.File != "" {
			if err := os.MkdirAll("logs", 0755); err != nil {
				log.Printf("创建日志目录失败: %v", err)
			}
		}
	}()

	// 创建多分组密钥管理器（快速初始化，无网络检查）
	// 初始化数据库连接用于密钥管理器
	groupsDB, err := database.NewGroupsDBWithConfig(config.Database)
	var keyManager *keymanager.MultiGroupKeyManager
	if err != nil {
		log.Printf("警告: 无法初始化数据库连接用于密钥管理器: %v", err)
		keyManager = keymanager.NewMultiGroupKeyManager(config)
	} else {
		keyManager = keymanager.NewMultiGroupKeyManagerWithDB(config, groupsDB)
		defer groupsDB.Close()
	}
	defer keyManager.Close()

	log.Printf("密钥管理器快速初始化完成")

	// 延迟启动日志清理任务（5分钟后启动）
	go func() {
		time.Sleep(5 * time.Minute)
		startLogCleanupTask(config)
	}()

	// 创建多提供商HTTP服务器
	server := api.NewMultiProviderServer(configManager, keyManager)

	// 启动服务器
	go func() {
		log.Printf("HTTP服务器启动在 %s", config.GetAddress())
		if err := server.Start(); err != nil {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	// 延迟执行完整的密钥验证（异步，不阻塞启动）
	go func() {
		time.Sleep(10 * time.Second) // 10秒后开始验证
		// log.Printf("开始后台验证API密钥...")
		validateAPIKeysInBackground(enabledGroups)
	}()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("正在关闭服务器...")

	// 优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		log.Printf("服务器关闭失败: %v", err)
	} else {
		log.Println("服务器已优雅关闭")
	}
}

// startLogCleanupTask 启动日志清理任务
func startLogCleanupTask(config *internal.Config) {
	log.Printf("启动日志清理任务")
	// 每天凌晨2点执行清理任务
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// 延迟首次清理，避免启动时执行
	time.Sleep(1 * time.Hour)
	performLogCleanup(config)

	for {
		select {
		case <-ticker.C:
			performLogCleanup(config)
		}
	}
}

// performLogCleanup 执行日志清理
func performLogCleanup(config *internal.Config) {
	if config.Database.RetentionDays <= 0 {
		return // 如果保留天数为0或负数，不执行清理
	}

	cleanupLogsCfg := config.RequestLogs
	cleanupLogsCfg.AsyncWrite = false
	requestLogger, err := logger.NewRequestLoggerWithConfig(config.Database, cleanupLogsCfg)
	if err != nil {
		log.Printf("Failed to create request logger for cleanup: %v", err)
		return
	}
	defer requestLogger.Close()

	if err := requestLogger.CleanupOldLogs(config.Database.RetentionDays); err != nil {
		log.Printf("Failed to cleanup old logs: %v", err)
	} else {
		log.Printf("Log cleanup completed successfully")
	}
}

// validateAPIKeysInBackground 后台验证API密钥
func validateAPIKeysInBackground(enabledGroups map[string]*internal.UserGroup) {
	totalValidKeys := 0
	for groupID, group := range enabledGroups {
		validKeys := make([]string, 0)
		for _, key := range group.APIKeys {
			if key != "" && len(key) > 10 {
				validKeys = append(validKeys, key)
			}
		}

		if len(validKeys) == 0 {
			log.Printf("警告: 分组 %s (%s) 没有有效的API密钥", groupID, group.Name)
		} else {
			log.Printf("分组 %s (%s) 验证了 %d 个API密钥", groupID, group.Name, len(validKeys))
			totalValidKeys += len(validKeys)
		}
	}

	if totalValidKeys == 0 {
		log.Printf("警告: 所有启用的分组都没有有效的API密钥")
	} else {
		log.Printf("后台验证完成: 总共 %d 个有效API密钥，分布在 %d 个分组中", totalValidKeys, len(enabledGroups))
	}
}

// printStartupInfo 打印启动信息
func printStartupInfo(config *internal.Config) {
	log.Println("=== TurnsAPI Multi-Provider 启动信息 ===")
	log.Printf("版本: %s", version)
	log.Printf("监听地址: %s", config.GetAddress())
	log.Printf("配置的分组数量: %d", len(config.UserGroups))

	enabledGroups := config.GetEnabledGroups()
	log.Printf("启用的分组数量: %d", len(enabledGroups))

	for groupID, group := range enabledGroups {
		log.Printf("  - %s (%s): %s, %d个密钥",
			groupID, group.Name, group.ProviderType, len(group.APIKeys))
	}

	if config.Auth.Enabled {
		log.Printf("认证: 已启用")
	} else {
		log.Printf("认证: 已禁用")
	}

	if config.Monitoring != nil && config.Monitoring.Enabled {
		log.Printf("监控: 已启用 (%s)", config.Monitoring.MetricsEndpoint)
	}

	log.Println("=====================================")
}

// validateConfiguration 验证配置
func validateConfiguration(config *internal.Config) error {
	// 验证基本配置
	if config.Server.Port == "" {
		return fmt.Errorf("server port is required")
	}

	// 验证分组配置
	for groupID, group := range config.UserGroups {
		if group.Name == "" {
			return fmt.Errorf("group %s: name is required", groupID)
		}

		if group.ProviderType == "" {
			return fmt.Errorf("group %s: provider_type is required", groupID)
		}

		if group.BaseURL == "" {
			return fmt.Errorf("group %s: base_url is required", groupID)
		}

		if group.Enabled && len(group.APIKeys) == 0 {
			return fmt.Errorf("group %s: enabled group must have at least one API key", groupID)
		}

		// 验证提供商类型
		supportedTypes := []string{"openai", "gemini", "anthropic", "azure_openai", "openrouter"}
		supported := false
		for _, supportedType := range supportedTypes {
			if group.ProviderType == supportedType {
				supported = true
				break
			}
		}

		if !supported {
			return fmt.Errorf("group %s: unsupported provider_type '%s', supported types: %v",
				groupID, group.ProviderType, supportedTypes)
		}
	}

	return nil
}

// showUsage 显示使用说明
func showUsage() {
	log.Println("TurnsAPI Multi-Provider - 多提供商API代理服务")
	log.Println("")
	log.Println("使用方法:")
	log.Printf("  %s [选项]", os.Args[0])
	log.Println("")
	log.Println("选项:")
	flag.PrintDefaults()
	log.Println("")
	log.Println("支持的提供商类型:")
	log.Println("  - openai: OpenAI API 和兼容服务")
	log.Println("  - openrouter: OpenRouter API (兼容 OpenAI 格式)")
	log.Println("  - gemini: Google Gemini API")
	log.Println("  - anthropic: Anthropic Claude API")
	log.Println("  - azure_openai: Azure OpenAI 服务")
	log.Println("")
	log.Println("配置文件示例: config/config.example.yaml")
}
