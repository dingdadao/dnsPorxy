package main

import (
	"log"
	"os"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/recovery"
	"dnsPorxy/internal/utils"
)

func main() {
	// 打开本地 SQLite 配置库
	store, err := config.OpenStore(config.DefaultStorePath)
	if err != nil {
		log.Fatalf("打开配置库失败: %v", err)
	}
	defer store.Close()

	// 加载配置（库中无配置时使用内置默认值并持久化）
	cfg, err := store.LoadConfig()
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	if err := config.ValidateConfig(cfg); err != nil {
		log.Fatalf("配置无效: %v", err)
	}

	// 自动初始化资源文件和目录
	if err := utils.InitResourceFiles(cfg); err != nil {
		log.Printf("资源初始化失败: %v", err)
	}

	// 创建日志系统
	logger := utils.NewEnhancedLogger(cfg.LogLevel, "dns-proxy", cfg.LogFormat == "json")

	// 文件日志定时清理：按查询日志保留时长换算天数，兜底 7 天
	retentionDays := int(cfg.QueryLog.Retention.Hours() / 24)
	if retentionDays < 1 {
		retentionDays = 7
	}
	logger.StartFileLogCleanup(retentionDays)

	logger.Info("🚀 [正在启动DNS代理服务] ", map[string]interface{}{
		"rule": "MAIN_START",
		"pid":  os.Getpid(),
		"port": cfg.ListenPort,
	})

	// 创建panic恢复管理器
	recoveryManager := recovery.NewRecoveryManager(cfg, logger, store)

	// 启动带panic恢复的服务
	if err := recoveryManager.Start(); err != nil {
		logger.Error("❌ [恢复管理器启动失败] ", map[string]interface{}{
			"rule":  "RECOVERY_MANAGER_START_FAILED",
			"error": err.Error(),
		})
		os.Exit(1)
	}

	logger.Info("💪 [DNS代理服务正常退出] ", map[string]interface{}{
		"rule": "MAIN_EXIT",
	})
}
