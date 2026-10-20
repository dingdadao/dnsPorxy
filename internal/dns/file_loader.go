package dns

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"
)

// FileLoader 处理文件加载相关功能
type FileLoader struct {
	config         *config.Config
	logger         *utils.EnhancedLogger
	cloudDetector  *CloudDetector // 直接使用cloudDetector
	matcherHandler *MatcherHandler
}

// NewFileLoader 创建新的文件加载处理器
func NewFileLoader(config *config.Config, logger *utils.EnhancedLogger, cloudDetector *CloudDetector, matcherHandler *MatcherHandler) *FileLoader {
	return &FileLoader{
		config:         config,
		logger:         logger,
		cloudDetector:  cloudDetector,
		matcherHandler: matcherHandler,
	}
}

// LoadAllData 加载所有数据
func (fl *FileLoader) LoadAllData() error {
	fl.loadCloudData(true)
	fl.loadAllSplitLists()
	return nil
}

// LoadSelectiveData 根据开关选择性加载数据
func (fl *FileLoader) LoadSelectiveData(loadCloudServices bool) error {
	fl.loadCloudData(loadCloudServices)
	fl.loadAllSplitLists()
	return nil
}

// loadAllSplitLists 加载所有启用中的分流列表
func (fl *FileLoader) loadAllSplitLists() {
	for i, l := range fl.config.SplitLists {
		if !l.Enabled {
			fl.logger.Info("⏭️ 分流列表已禁用，跳过加载", map[string]interface{}{
				"list": l.Name,
			})
			continue
		}
		if err := fl.LoadSplitList(i); err != nil {
			fl.logger.Error("❌ 分流列表加载失败", map[string]interface{}{
				"list":  l.Name,
				"error": err.Error(),
			})
			// 继续执行，不返回错误，确保服务可用
		}
	}
}

// loadCloudData 按开关加载云服务网段
func (fl *FileLoader) loadCloudData(loadCloudServices bool) {
	if !loadCloudServices {
		fl.logger.Info("⏭️ 云服务检查已禁用，跳过加载", map[string]interface{}{
			"enable_cloudflare": fl.config.EnableCloudflareCheck,
			"enable_aws":        fl.config.EnableAWSCheck,
		})
		return
	}

	if !fl.shouldLoadCloudFiles() {
		fl.logger.Info("📋 云服务网段文件不存在，等待定时任务下载", map[string]interface{}{
			"cloudflare_v4": fl.config.CloudflareNetFile,
			"cloudflare_v6": fl.config.CloudflareNetFile6,
			"aws_file":      fl.config.AWSNetFile,
		})
		return
	}

	// 根据具体开关决定传递哪些文件路径
	cfFile4 := ""
	cfFile6 := ""
	awsFile := ""
	if fl.config.EnableCloudflareCheck {
		cfFile4 = fl.config.CloudflareNetFile
		cfFile6 = fl.config.CloudflareNetFile6
	}
	if fl.config.EnableAWSCheck {
		awsFile = fl.config.AWSNetFile
	}

	if err := fl.cloudDetector.LoadNetworkRanges(cfFile4, cfFile6, awsFile); err != nil {
		fl.logger.Error("❌ 云服务网段加载失败", map[string]interface{}{
			"error": err.Error(),
		})
		// 继续执行，不返回错误，确保服务可用
	}
}

// splitList 返回第 i 条分流列表配置（越界返回 nil）
func (fl *FileLoader) splitList(i int) *config.SplitList {
	if i < 0 || i >= len(fl.config.SplitLists) {
		return nil
	}
	return &fl.config.SplitLists[i]
}

// shouldLoadCloudFiles 检查是否应该加载云服务文件
func (fl *FileLoader) shouldLoadCloudFiles() bool {
	// 检查云服务相关开关，如果都禁用则直接返回false
	if !fl.config.EnableCloudflareCheck && !fl.config.EnableAWSCheck {
		return false
	}

	// 检查任一云服务文件是否存在
	if fl.config.CloudflareNetFile != "" {
		if _, err := os.Stat(fl.config.CloudflareNetFile); err == nil {
			return true
		}
	}
	if fl.config.CloudflareNetFile6 != "" {
		if _, err := os.Stat(fl.config.CloudflareNetFile6); err == nil {
			return true
		}
	}
	if fl.config.AWSNetFile != "" {
		if _, err := os.Stat(fl.config.AWSNetFile); err == nil {
			return true
		}
	}
	return false
}

// downloadFile 下载文件
func (fl *FileLoader) downloadFile(url, targetFile string) error {
	// 创建目录
	dir := filepath.Dir(targetFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 创建临时文件
	tempFile := targetFile + ".tmp"

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 发起GET请求
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("下载请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	// 创建临时文件
	out, err := os.Create(tempFile)
	if err != nil {
		return err
	}
	defer out.Close()

	// 将响应内容写入文件
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	// 检查下载的文件是否有效
	if !fl.isFileValid(tempFile) {
		// 删除无效的临时文件
		os.Remove(tempFile)
		return fmt.Errorf("下载的文件内容无效")
	}

	// 替换原文件
	return os.Rename(tempFile, targetFile)
}

// LoadSplitList 加载第 i 条分流列表（文件不存在时按 URL 下载）
func (fl *FileLoader) LoadSplitList(i int) error {
	list := fl.splitList(i)
	if list == nil {
		return nil
	}
	if list.DomainFile == "" {
		fl.logger.Info("📋 分流列表文件路径为空，跳过加载", map[string]interface{}{
			"list": list.Name,
		})
		return nil
	}

	_, statErr := os.Stat(list.DomainFile)
	needDownload := os.IsNotExist(statErr)

	// 文件缺失，或已存在但内容无效（如上次下载失败留下的空文件）时，都按 URL 重新下载
	if !needDownload && !fl.isFileValid(list.DomainFile) {
		fl.logger.Warn("⚠️ 分流列表文件内容无效，尝试重新下载", map[string]interface{}{
			"list": list.Name,
			"file": list.DomainFile,
			"url":  list.DomainURL,
		})
		needDownload = true
	}

	if needDownload {
		fl.logger.Info("📋 分流列表文件不存在或无效，开始下载", map[string]interface{}{
			"list": list.Name,
			"file": list.DomainFile,
			"url":  list.DomainURL,
		})

		if list.DomainURL == "" {
			fl.logger.Warn("⚠️ 分流列表URL未配置", map[string]interface{}{
				"list": list.Name,
				"file": list.DomainFile,
			})
			return nil
		}

		if err := fl.downloadWithRetry(list.DomainURL, list.DomainFile); err != nil {
			fl.logger.Error("❌ 下载分流列表文件失败，创建空文件", map[string]interface{}{
				"list":  list.Name,
				"file":  list.DomainFile,
				"url":   list.DomainURL,
				"error": err.Error(),
			})
			// 下载失败时留下占位文件，下次启动会因内容无效而重新尝试下载
			if createErr := fl.createEmptyFile(list.DomainFile); createErr != nil {
				fl.logger.Error("❌ 创建空文件失败", map[string]interface{}{
					"file":  list.DomainFile,
					"error": createErr.Error(),
				})
			}
			return err
		}
		fl.logger.Info("✅ 下载分流列表文件成功", map[string]interface{}{
			"list": list.Name,
			"file": list.DomainFile,
		})
	} else {
		fl.logger.Info("📋 分流列表文件已存在，直接加载", map[string]interface{}{
			"list": list.Name,
			"file": list.DomainFile,
		})
	}

	if !fl.isFileValid(list.DomainFile) {
		fl.logger.Warn("⚠️ 分流列表文件内容无效，跳过加载", map[string]interface{}{
			"list": list.Name,
			"file": list.DomainFile,
		})
		return nil
	}

	matcher := fl.matcherHandler.MatcherFor(i)
	if matcher == nil {
		return fmt.Errorf("分流列表匹配器不存在: index=%d", i)
	}
	if err := matcher.LoadYAMLConfig(list.DomainFile); err != nil {
		return fmt.Errorf("加载分流列表 %q 失败: %w", list.Name, err)
	}

	fl.logger.Info("✅ 分流列表加载完成", map[string]interface{}{
		"list": list.Name,
		"file": list.DomainFile,
	})
	return nil
}

// ForceDownloadAndReloadSplitList 强制下载并重新加载第 i 条分流列表（用于异步刷新）
func (fl *FileLoader) ForceDownloadAndReloadSplitList(i int) error {
	list := fl.splitList(i)
	if list == nil {
		return nil
	}
	if list.DomainFile == "" || list.DomainURL == "" {
		fl.logger.Warn("⚠️ 分流列表文件路径或URL为空，跳过下载", map[string]interface{}{
			"list": list.Name,
			"file": list.DomainFile,
			"url":  list.DomainURL,
		})
		return nil
	}

	fl.logger.Info("🔄 强制下载分流列表文件", map[string]interface{}{
		"list": list.Name,
		"file": list.DomainFile,
		"url":  list.DomainURL,
	})

	if err := fl.downloadWithRetry(list.DomainURL, list.DomainFile); err != nil {
		fl.logger.Error("❌ 强制下载分流列表文件失败", map[string]interface{}{
			"list":  list.Name,
			"file":  list.DomainFile,
			"url":   list.DomainURL,
			"error": err.Error(),
		})
		return err
	}

	if !fl.isFileValid(list.DomainFile) {
		fl.logger.Warn("⚠️ 下载的分流列表文件内容无效，跳过加载", map[string]interface{}{
			"list": list.Name,
			"file": list.DomainFile,
		})
		return fmt.Errorf("下载的分流列表文件内容无效: %s", list.DomainFile)
	}

	matcher := fl.matcherHandler.MatcherFor(i)
	if matcher == nil {
		return fmt.Errorf("分流列表匹配器不存在: index=%d", i)
	}
	if err := matcher.LoadYAMLConfig(list.DomainFile); err != nil {
		return fmt.Errorf("重新加载分流列表 %q 失败: %w", list.Name, err)
	}

	fl.logger.Info("✅ 分流列表重新加载完成", map[string]interface{}{
		"list": list.Name,
		"file": list.DomainFile,
	})
	return nil
}

// downloadWithRetry 带重试的下载功能
func (fl *FileLoader) downloadWithRetry(url, targetFile string) error {
	// 重试次数
	maxRetries := 3
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		fl.logger.Debug("尝试下载文件", map[string]interface{}{
			"url":     url,
			"file":    targetFile,
			"attempt": i + 1,
		})

		if err := fl.downloadFile(url, targetFile); err != nil {
			lastErr = err
			fl.logger.Warn("下载失败，准备重试", map[string]interface{}{
				"url":         url,
				"file":        targetFile,
				"attempt":     i + 1,
				"max_retries": maxRetries,
				"error":       err.Error(),
			})
			// 等待一段时间再重试
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}

		// 下载成功，检查文件内容是否有效
		if fl.isFileValid(targetFile) {
			fl.logger.Info("下载成功且文件内容有效", map[string]interface{}{
				"url":  url,
				"file": targetFile,
			})
			return nil
		} else {
			lastErr = fmt.Errorf("下载的文件内容无效")
			fl.logger.Warn("下载的文件内容无效，准备重试", map[string]interface{}{
				"url":         url,
				"file":        targetFile,
				"attempt":     i + 1,
				"max_retries": maxRetries,
			})
			// 等待一段时间再重试
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}

	return fmt.Errorf("下载失败，已重试 %d 次: %w", maxRetries, lastErr)
}

// isFileValid 检查文件内容是否有效
func (fl *FileLoader) isFileValid(filePath string) bool {
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}

	// 读取文件内容
	content, err := os.ReadFile(filePath)
	if err != nil {
		fl.logger.Warn("读取文件失败", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return false
	}

	// 检查文件是否为空
	if len(content) == 0 {
		fl.logger.Debug("文件为空", map[string]interface{}{
			"file": filePath,
		})
		return false
	}

	// 检查文件内容是否包含有效数据（非纯空白字符）
	trimmedContent := strings.TrimSpace(string(content))
	if len(trimmedContent) == 0 {
		fl.logger.Debug("文件内容为空白字符", map[string]interface{}{
			"file": filePath,
		})
		return false
	}

	return true
}

// createEmptyFile 创建空文件
func (fl *FileLoader) createEmptyFile(filePath string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	// 创建基本的YAML结构，避免完全空文件
	emptyContent := []byte("# Empty domain split list configuration\npayload: []\n")
	return os.WriteFile(filePath, emptyContent, 0644)
}
