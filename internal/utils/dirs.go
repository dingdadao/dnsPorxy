package utils

import (
	"dnsPorxy/internal/config"
	"fmt"
	"os"
	"path/filepath"
)

func InitResourceFiles(cfg *config.Config) error {
	dataDir := "data"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("无法创建data目录: %w", err)
		}
		fmt.Println("已创建data目录")
	}

	// 仅确保各分流列表的域名文件所在目录存在；
	// 文件本身交由 FileLoader.LoadSplitList 处理（缺失时按 URL 下载）。
	// 此处预创建空文件会让加载器误判「文件已存在」从而跳过下载。
	for _, l := range cfg.SplitLists {
		f := l.DomainFile
		if f == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(f), 0755); err != nil {
			fmt.Printf("无法创建目录: %v\n", err)
		}
	}

	return nil
}
