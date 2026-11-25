package config

import "testing"

// validBaseConfig 返回一份能通过校验的基线配置（只保留一条最小分流列表，便于按用例覆盖）
func validBaseConfig() *Config {
	cfg := DefaultConfig()
	cfg.SplitLists = []SplitList{{
		Name: "base", Enabled: true,
		DNS:        []string{"udp://127.0.0.1:53"},
		DomainFile: "./data/x.yaml",
	}}
	return cfg
}

// 自动模式（auto=true）不需要线路类型与地址段：前缀来自真实客户端 IP。
func TestValidateECSAutoSkipsManualFields(t *testing.T) {
	cfg := validBaseConfig()
	cfg.SplitLists = []SplitList{{
		Name: "auto", Enabled: true,
		DNS:        []string{"udp://127.0.0.1:53"},
		DomainFile: "./data/x.yaml",
		ECS:        ECSPolicy{Enabled: true, Auto: true},
	}}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("自动模式不该要求手填 isp_type/subnet: %v", err)
	}
}

// 手动模式缺字段必须拦下：运行时 Resolve() 会静默返回 false，等于 ECS 没生效。
func TestValidateECSManualRequiresFields(t *testing.T) {
	cfg := validBaseConfig()
	cfg.SplitLists = []SplitList{{
		Name: "manual", Enabled: true,
		DNS:        []string{"udp://127.0.0.1:53"},
		DomainFile: "./data/x.yaml",
		ECS:        ECSPolicy{Enabled: true},
	}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("手动模式缺 isp_type/subnet 时应报错")
	}

	cfg.SplitLists[0].ECS.ISPType = "bogus"
	cfg.SplitLists[0].ECS.Subnet = "1.1.1.0/24"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("非法 isp_type 应被拦截")
	}

	cfg.SplitLists[0].ECS.ISPType = "telecom"
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("合法手动配置不应报错: %v", err)
	}
}

// 分流列表的 ECS 以前完全没有校验，isp_type 写成任意值都能保存、运行时静默不注入。
func TestValidateSplitListECSCaught(t *testing.T) {
	cfg := validBaseConfig()
	cfg.SplitLists = []SplitList{{
		Name: "bad", Enabled: true,
		DNS:        []string{"udp://127.0.0.1:53"},
		DomainFile: "./data/x.yaml",
		ECS:        ECSPolicy{Enabled: true, ISPType: "bogus", Subnet: "1.1.1.0/24"},
	}}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("分流列表里非法的 ecs.isp_type 应被拦截")
	}
}
