package dns

import (
	"context"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"
)

// TaskScheduler 处理定时任务调度
type TaskScheduler struct {
	config        *config.Config
	logger        *utils.EnhancedLogger
	fileLoader    *FileLoader
	cloudDetector *CloudDetector
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewTaskScheduler 创建新的任务调度器
func NewTaskScheduler(
	config *config.Config,
	logger *utils.EnhancedLogger,
	fileLoader *FileLoader,
	cloudDetector *CloudDetector,
) *TaskScheduler {
	ctx, cancel := context.WithCancel(context.Background())

	return &TaskScheduler{
		config:        config,
		logger:        logger,
		fileLoader:    fileLoader,
		cloudDetector: cloudDetector,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// StartBackgroundTasks 启动后台任务
func (ts *TaskScheduler) StartBackgroundTasks() {
	// 延迟启动定时任务，避免与DNS服务器启动冲突
	go func() {
		time.Sleep(2 * time.Second) // 等待DNS服务器启动完成

		// 各分流列表的定时刷新任务
		for i, l := range ts.config.SplitLists {
			if !l.Enabled || l.DomainFile == "" || l.DomainURL == "" || l.Refresh <= 0 {
				ts.logger.Info("⏭️ [分流列表定时刷新已禁用] ", map[string]interface{}{
					"rule":    "SPLIT_LIST_REFRESH_SKIPPED",
					"list":    l.Name,
					"enabled": l.Enabled,
					"file":    l.DomainFile,
					"url":     l.DomainURL,
					"refresh": l.Refresh.String(),
				})
				continue
			}
			ts.logger.Info("🔄 [分流列表定时刷新启动] ", map[string]interface{}{
				"rule":     "SPLIT_LIST_REFRESH_TASK",
				"list":     l.Name,
				"interval": l.Refresh.String(),
			})
			go ts.SplitListRefreshTask(i, l.Refresh)
		}

		// 网络段刷新任务（仅在启用云服务检查时启动）
		if (ts.config.EnableCloudflareCheck || ts.config.EnableAWSCheck) && ts.config.NetworkRefreshInterval > 0 {
			ts.logger.Info("🔄 [网络段定时刷新启动] ", map[string]interface{}{
				"rule":       "NETWORK_REFRESH_TASK",
				"interval":   ts.config.NetworkRefreshInterval.String(),
				"enable_cf":  ts.config.EnableCloudflareCheck,
				"enable_aws": ts.config.EnableAWSCheck,
			})
			go ts.NetworkRefreshTask()
		} else {
			ts.logger.Info("⏭️ [网络段定时刷新已禁用] ", map[string]interface{}{
				"rule":       "NETWORK_REFRESH_SKIPPED",
				"enable_cf":  ts.config.EnableCloudflareCheck,
				"enable_aws": ts.config.EnableAWSCheck,
			})
		}
	}()
}

// SplitListRefreshTask 第 index 条分流列表的定时刷新任务
func (ts *TaskScheduler) SplitListRefreshTask(index int, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := ts.fileLoader.ForceDownloadAndReloadSplitList(index); err != nil {
				ts.logger.Error("❌ [分流列表刷新失败] ", map[string]interface{}{
					"rule":  "SPLIT_LIST_REFRESH_FAILED",
					"index": index,
					"error": err.Error(),
				})
			} else {
				ts.logger.Info("✅ [分流列表刷新成功] ", map[string]interface{}{
					"rule":  "SPLIT_LIST_REFRESH_SUCCESS",
					"index": index,
				})
			}
		case <-ts.ctx.Done():
			ts.logger.Info("📋 [分流列表刷新任务停止] ", map[string]interface{}{
				"rule":  "SPLIT_LIST_REFRESH_STOPPED",
				"index": index,
			})
			return
		}
	}
}

// NetworkRefreshTask 网络段刷新任务
func (ts *TaskScheduler) NetworkRefreshTask() {
	ticker := time.NewTicker(ts.config.NetworkRefreshInterval)
	defer ticker.Stop()

	ts.logger.Info("🔄 [网络段定时刷新启动] ", map[string]interface{}{
		"rule":     "NETWORK_REFRESH_TASK",
		"interval": ts.config.NetworkRefreshInterval.String(),
	})

	for {
		select {
		case <-ticker.C:
			// 根据开关决定传递哪些文件路径
			cfFile4 := ""
			cfFile6 := ""
			awsFile := ""
			if ts.config.EnableCloudflareCheck {
				cfFile4 = ts.config.CloudflareNetFile
				cfFile6 = ts.config.CloudflareNetFile6
			}
			if ts.config.EnableAWSCheck {
				awsFile = ts.config.AWSNetFile
			}
			ts.logger.Debug("开始定时网络段刷新", map[string]interface{}{
				"cloudflare_v4": cfFile4,
				"cloudflare_v6": cfFile6,
				"aws_file":      awsFile,
			})
			if err := ts.cloudDetector.LoadNetworkRanges(
				cfFile4,
				cfFile6,
				awsFile,
			); err != nil {
				ts.logger.Error("❌ [网络段刷新失败] ", map[string]interface{}{
					"rule":  "NETWORK_REFRESH_FAILED",
					"error": err.Error(),
				})
			} else {
				ts.logger.Info("✅ [网络段刷新成功] ", map[string]interface{}{
					"rule": "NETWORK_REFRESH_SUCCESS",
				})
			}
		case <-ts.ctx.Done():
			ts.logger.Info("📋 [网络段刷新任务停止] ", map[string]interface{}{
				"rule": "NETWORK_REFRESH_STOPPED",
			})
			return
		}
	}
}

// Stop 停止所有定时任务
func (ts *TaskScheduler) Stop() {
	ts.cancel()
}
