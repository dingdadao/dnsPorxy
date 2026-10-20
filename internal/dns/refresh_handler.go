package dns

import (
	"fmt"
	"runtime/debug"
	"sync"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// getConfig 获取当前配置（web保存后热切换）
func (rh *RefreshHandler) getConfig() *config.Config {
	rh.cfgMu.RLock()
	defer rh.cfgMu.RUnlock()
	return rh.config
}

// UpdateConfig 热更新配置引用
func (rh *RefreshHandler) UpdateConfig(cfg *config.Config) {
	rh.cfgMu.Lock()
	rh.config = cfg
	rh.cfgMu.Unlock()
}

// RefreshHandler 处理异步刷新相关功能
type RefreshHandler struct {
	cfgMu          sync.RWMutex
	config         *config.Config
	logger         *utils.EnhancedLogger
	cacheManager   *CacheManager
	cloudDetector  *CloudDetector
	queryOptimizer interface{}
	matcherHandler *MatcherHandler
	proxyQuery     func(*dns.Msg, []string) (*dns.Msg, error)
	// rebuildCloud 云域名刷新时重建与查询路径一致的替换响应（保持上游结构，仅替换IP）
	rebuildCloud func(originalResp *dns.Msg, domain string, qtype uint16, cloudType int) *dns.Msg
}

// NewRefreshHandler 创建新的刷新处理器
func NewRefreshHandler(
	config *config.Config,
	logger *utils.EnhancedLogger,
	cacheManager *CacheManager,
	cloudDetector *CloudDetector,
	queryOptimizer interface{},
	matcherHandler *MatcherHandler,
	proxyQuery func(*dns.Msg, []string) (*dns.Msg, error),
	rebuildCloud func(originalResp *dns.Msg, domain string, qtype uint16, cloudType int) *dns.Msg,
) *RefreshHandler {
	return &RefreshHandler{
		config:         config,
		logger:         logger,
		cacheManager:   cacheManager,
		cloudDetector:  cloudDetector,
		queryOptimizer: queryOptimizer,
		matcherHandler: matcherHandler,
		proxyQuery:     proxyQuery,
		rebuildCloud:   rebuildCloud,
	}
}

// RefreshDNSRecord 刷新DNS记录（缓存回调）
func (rh *RefreshHandler) RefreshDNSRecord(domain string, qtype uint16) error {
	// 添加顶层panic恢复机制
	defer func() {
		if r := recover(); r != nil {
			// 记录panic信息
			if rh != nil && rh.logger != nil {
				rh.logger.Error("💥 [异步刷新panic] ", map[string]interface{}{
					"rule":        "REFRESH_RECORD_PANIC",
					"domain":      domain,
					"qtype":       dns.TypeToString[qtype],
					"panic_msg":   fmt.Sprintf("%v", r),
					"stack_trace": string(debug.Stack()),
				})
			}

			// 即使发生panic，也要尝试延长缓存TTL以防止频繁刷新
			if rh != nil && rh.cacheManager != nil {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.getConfig().Cache.TTL/2)
			}
		}
	}()

	// 添加空指针检查
	if rh == nil {
		return fmt.Errorf("refresh handler is nil")
	}

	if rh.logger == nil {
		return fmt.Errorf("logger is nil")
	}

	// 检查是否为替换域名，如果是则直接返回，避免套娃
	if rh.cloudDetector.IsReplaceDomain(domain) {
		rh.logger.Debug("⏭️ 跳过异步刷新（替换域名）", map[string]interface{}{
			"domain": domain,
		})
		return nil
	}

	rh.logger.Info("🔄 [异步刷新开始] ", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
	})

	// 分流决策：一次匹配同时得出上游 DNS 与 ECS 策略（与查询路径保持同一套判定）
	decision := rh.matcherHandler.MatchDomain(domain)

	// 确定应该使用的上游DNS服务器（遵循相同的优先级规则）
	upstreams := rh.upstreamsFor(domain, decision)

	// 添加上游服务器检查
	if len(upstreams) == 0 {
		rh.logger.Warn("⚠️ [异步刷新警告] 未找到有效的上游服务器", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		if rh.cacheManager != nil {
			// 检查域名级别的云服务状态来判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := rh.getConfig().Cache.TTL // 默认使用缓存TTL
				if rh.getConfig().ReplaceCacheTime > 0 {
					replaceCacheTime = rh.getConfig().ReplaceCacheTime
				}
				rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.getConfig().Cache.TTL)
			}
		}
		return fmt.Errorf("no valid upstream servers found")
	}

	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), qtype)
	// 命中分流列表时按列表 ECS 策略处理请求副本，避免无 ECS 的结果回写覆盖带 ECS 的缓存
	reqUpstream := applySplitECS(req, decision)

	// 添加请求检查
	if req == nil {
		rh.logger.Error("❌ [异步刷新失败] 请求对象为空", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		if rh.cacheManager != nil {
			// 检查域名级别的云服务状态来判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 检查是否为替换域名，替换域名使用替换缓存时间，普通云域名使用普通缓存时间
				if rh.cloudDetector.IsReplaceDomain(domain) {
					// 替换域名使用替换缓存时间
					replaceCacheTime := rh.getConfig().Cache.TTL // 默认使用缓存TTL
					if rh.getConfig().ReplaceCacheTime > 0 {
						replaceCacheTime = rh.getConfig().ReplaceCacheTime
					}
					rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
				} else {
					// 普通云域名使用普通缓存时间
					rh.cacheManager.ExtendTTL(domain, qtype, rh.getConfig().Cache.TTL)
				}
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.getConfig().Cache.TTL)
			}
		}
		return fmt.Errorf("request object is nil")
	}

	// 使用类型断言调用不同类型的查询优化器
	var result *ConcurrentQueryResult
	if rh.queryOptimizer == nil {
		rh.logger.Error("❌ [异步刷新失败] 查询优化器未初始化", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		if rh.cacheManager != nil {
			// 检查域名级别的云服务状态来判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := rh.getConfig().Cache.TTL // 默认使用缓存TTL
				if rh.getConfig().ReplaceCacheTime > 0 {
					replaceCacheTime = rh.getConfig().ReplaceCacheTime
				}
				rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.getConfig().Cache.TTL)
			}
		}
		return fmt.Errorf("query optimizer is nil")
	}

	if modernOptimizer, ok := rh.queryOptimizer.(*SimpleModernOptimizer); ok {
		// 使用现代查询优化器
		result = modernOptimizer.Query(reqUpstream, upstreams)
	} else if traditionalOptimizer, ok := rh.queryOptimizer.(*FastQueryOptimizer); ok {
		// 使用传统查询优化器
		result = traditionalOptimizer.Query(reqUpstream, upstreams)
	} else {
		rh.logger.Error("❌ [异步刷新失败] ", map[string]interface{}{
			"domain": domain,
			"error":  "unknown query optimizer type",
		})
		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		// 延长时间为配置TTL的一半，避免过于频繁的刷新
		if rh.cacheManager != nil {
			// 检查域名级别的云服务状态来判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := rh.getConfig().Cache.TTL // 默认使用缓存TTL
				if rh.getConfig().ReplaceCacheTime > 0 {
					replaceCacheTime = rh.getConfig().ReplaceCacheTime
				}
				rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.getConfig().Cache.TTL)
			}
		}
		return fmt.Errorf("unknown query optimizer type")
	}

	if result == nil {
		rh.logger.Error("❌ [异步刷新失败] 查询结果为空", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		if rh.cacheManager != nil {
			// 检查域名级别的云服务状态来判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := rh.getConfig().Cache.TTL // 默认使用缓存TTL
				if rh.getConfig().ReplaceCacheTime > 0 {
					replaceCacheTime = rh.getConfig().ReplaceCacheTime
				}
				rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.getConfig().Cache.TTL)
			}
		}
		return fmt.Errorf("query result is nil")
	}

	if result.FastestResult == nil || result.FastestResult.Error != nil {
		errorMsg := "all upstream queries failed"
		if result.FastestResult != nil && result.FastestResult.Error != nil {
			errorMsg = result.FastestResult.Error.Error()
		}
		rh.logger.Error("❌ [异步刷新失败] ", map[string]interface{}{
			"domain": domain,
			"error":  errorMsg,
		})
		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		// 延长时间为配置TTL的一半，避免过于频繁的刷新
		if rh.cacheManager != nil {
			// 直接从缓存中获取云域名信息，判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := rh.getConfig().Cache.TTL // 默认使用缓存TTL
				if rh.getConfig().ReplaceCacheTime > 0 {
					replaceCacheTime = rh.getConfig().ReplaceCacheTime
				}
				rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.getConfig().Cache.TTL)
			}
		}
		return fmt.Errorf(errorMsg)
	}

	// 验证查询结果：必须有成功响应且包含实际答案记录
	if result.HasSuccess && result.SuccessResult != nil &&
		result.SuccessResult.Response != nil &&
		result.SuccessResult.Response.Rcode == dns.RcodeSuccess {

		// 添加缓存管理器检查
		if rh.cacheManager == nil {
			rh.logger.Error("❌ [异步刷新失败] 缓存管理器未初始化", map[string]interface{}{
				"domain": domain,
				"qtype":  dns.TypeToString[qtype],
			})
			return fmt.Errorf("cache manager is nil")
		}

		// 检查是否命中分流列表（列表未开启云检测时跳过云服务检测）
		if decision.Matched && !decision.EnableCloudCheck {
			rh.logger.Info("🎯 [异步刷新-分流列表域名处理开始] ", map[string]interface{}{
				"domain":      domain,
				"list":        decision.ListName,
				"dns_servers": decision.DNS,
			})

			// 对于分流列表域名，跳过云服务检测
			rh.logger.Info("⏭️ [异步刷新-跳过云服务检测] ", map[string]interface{}{
				"domain": domain,
				"reason": "split_list",
				"list":   decision.ListName,
			})

			// 缓存原始上游响应（遵循上游TTL并按缓存时长递减，不再改写owner/裁剪RRset）
			rh.cacheManager.Set(domain, qtype, result.SuccessResult.Response, false, 0)

			rh.logger.Debug("🔄 [异步刷新完成-分流列表] ", map[string]interface{}{
				"domain":       domain,
				"qtype":        dns.TypeToString[qtype],
				"source":       decision.ListName,
				"answer_count": len(result.SuccessResult.Response.Answer),
				"upstreams":    decision.DNS,
			})
		} else {
			rh.logger.Info("🌐 [异步刷新-普通域名处理开始] ", map[string]interface{}{
				"domain": domain,
			})

			// 添加云检测器检查
			if rh.cloudDetector == nil {
				rh.logger.Error("❌ [异步刷新失败] 云检测器未初始化", map[string]interface{}{
					"domain": domain,
					"qtype":  dns.TypeToString[qtype],
				})
				rh.cacheManager.ExtendTTL(domain, qtype, rh.getConfig().Cache.TTL/2)
				return fmt.Errorf("cloud detector is nil")
			}

			// 检查是否为云服务
			rh.logger.Info("🔍 [异步刷新-云服务检测开始] ", map[string]interface{}{
				"domain": domain,
			})
			detection := rh.cloudDetector.DetectCloudService(result.SuccessResult.Response, domain)
			isCloud := detection.Type != CloudTypeNone
			cloudType := int(detection.Type)

			if isCloud {
				rh.logger.Info("☁️ [异步刷新-云服务检测结果] ", map[string]interface{}{
					"domain":     domain,
					"cloud_type": detection.Type,
				})

				// 将整个域名标记为云服务域名（确保A/AAAA记录一致性）
				rh.cacheManager.MarkDomainAsCloud(domain, qtype, cloudType)

				// 检查是否为替换域名，替换域名使用替换缓存时间，普通云域名使用普通缓存时间
				replaceCacheTime := rh.getConfig().Cache.TTL
				if rh.cloudDetector.IsReplaceDomain(domain) && rh.getConfig().ReplaceCacheTime > 0 {
					replaceCacheTime = rh.getConfig().ReplaceCacheTime
				}

				// 通过回调重建与查询路径一致的云替换响应（保持上游结构，仅替换IP值）
				processedResponse := rh.rebuildCloud(result.SuccessResult.Response, domain, qtype, cloudType)
				if processedResponse == nil {
					rh.logger.Error("❌ [异步刷新-云替换响应重建失败] ", map[string]interface{}{
						"domain": domain,
						"qtype":  dns.TypeToString[qtype],
					})
					return fmt.Errorf("rebuild cloud response failed")
				}
				// 只更新云响应缓存，不更新普通缓存
				rh.cacheManager.SetCloudResponse(domain, qtype, processedResponse, cloudType, replaceCacheTime)

				rh.logger.Debug("🔄 [异步刷新完成-云域名] ", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"source":       "cloud",
					"cloud_type":   detection.Type,
					"answer_count": len(processedResponse.Answer),
					"upstreams":    upstreams,
				})
			} else {
				rh.logger.Info("❌ [异步刷新-非云服务域名] ", map[string]interface{}{
					"domain": domain,
				})

				// 对于普通域名，缓存原始上游响应
				rh.cacheManager.Set(domain, qtype, result.SuccessResult.Response, false, 0)

				rh.logger.Debug("🔄 [异步刷新完成-普通域名] ", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"source":       "normal",
					"answer_count": len(result.SuccessResult.Response.Answer),
					"upstreams":    upstreams,
				})
			}
		}
	} else {
		// 记录详细的失败原因
		failureReason := "unknown_error"
		if result.FastestResult != nil && result.FastestResult.Error != nil {
			failureReason = result.FastestResult.Error.Error()
		} else if !result.HasSuccess {
			failureReason = "no_successful_response"
		} else if result.SuccessResult == nil {
			failureReason = "success_result_is_nil"
		} else if result.SuccessResult.Response == nil {
			failureReason = "response_is_nil"
		} else if result.SuccessResult.Response.Rcode != dns.RcodeSuccess {
			failureReason = fmt.Sprintf("non_success_rcode: %s", dns.RcodeToString[result.SuccessResult.Response.Rcode])
		} else if len(result.SuccessResult.Response.Answer) == 0 {
			failureReason = "no_answer_records"
		}

		rh.logger.Warn("⚠️ [异步刷新跳过] ", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"reason": failureReason,
		})

		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		// 这样可以避免缓存立即过期导致的查询失败
		// 延长时间为配置TTL的一半，避免过于频繁的刷新
		if rh.cacheManager != nil {
			rh.cacheManager.ExtendTTL(domain, qtype, rh.getConfig().Cache.TTL/2)
		}
	}

	return nil
}

// upstreamsFor 由分流决策得出上游DNS服务器（未命中分流列表时回退全局上游）
func (rh *RefreshHandler) upstreamsFor(domain string, d SplitDecision) []string {
	if d.Matched {
		rh.logger.Debug("异步刷新：命中分流列表", map[string]interface{}{
			"domain":      domain,
			"list":        d.ListName,
			"dns_servers": d.DNS,
		})
		return d.DNS
	}

	// 如果没有匹配到任何配置，使用上游DNS作为备用
	rh.logger.Debug("异步刷新：使用上游DNS作为备用", map[string]interface{}{
		"domain":    domain,
		"upstreams": rh.getConfig().Upstream,
	})
	return rh.getConfig().Upstream
}

// 原 CNAME 递归改写 / ensureMinimumTTL 抬高 TTL 等辅助函数已删除：
// 缓存现在直接保存上游原始响应（见 handler.writeResponse / optimized_cache.decrementTTLs），
// 云替换响应统一由 rebuildCloud 回调（cloud_handler.buildCloudResponse）重建。
