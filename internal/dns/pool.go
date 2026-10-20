package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"dnsPorxy/internal/config"

	"github.com/miekg/dns"
)

// ===== DoT 连接池实现 =====

// DoTConnPool DoT连接池
type DoTConnPool struct {
	mu       sync.RWMutex
	conns    map[string][]*DoTConn
	maxConns int
	timeout  time.Duration

	// resolver 用于解析 DoT 服务器主机名。
	// 默认 nil 时走系统 /etc/resolv.conf；DNS 服务器自身解析上游不应依赖系统 DNS，
	// 通过 SetBootstrapResolver 注入配置里的 UDP 上游作为 bootstrap。
	resolver *net.Resolver

	// 监控指标
	metrics struct {
		TotalConnsCreated int64
		TotalConnsClosed  int64
		TotalConnsReused  int64
		ActiveConns       int64
	}
}

// DoTConn 单个DoT连接
type DoTConn struct {
	conn     net.Conn
	tlsConn  *tls.Conn
	lastUsed time.Time
	created  time.Time // 连接建立时间：用于主动轮换
	inUse    bool
	server   string
}

// dotConnLifetime 单条 DoT 连接的最大寿命（安全轮换上限）。
// 实测阿里 DoT 对空闲连接约 5s 即 EOF 断开（由 timeout 控制），
// 但对持续使用的连接可存活 30s 以上；40s 上限用于主动轮换长期连续使用的连接。
const dotConnLifetime = 40 * time.Second

// maxDoTConnsPerServer 单个上游允许保留的最大空闲 DoT 连接数。
// 仅用于裁剪「空闲」连接：在用连接既不计入该上限，也不会被关闭。
const maxDoTConnsPerServer = 5

// NewDoTConnPool 创建新的DoT连接池
func NewDoTConnPool() *DoTConnPool {
	pool := &DoTConnPool{
		conns:    make(map[string][]*DoTConn),
		maxConns: 20,              // 增加每个服务器的最大连接数到20
		timeout:  4 * time.Second, // 空闲连接过期时间：实测阿里 DoT 空闲约 5s 即 EOF 断开，取 4s 保证只复用仍然存活的连接，避免复用死连接
	}

	// 启动健康检查协程
	go pool.healthCheckRoutine()

	return pool
}

// SetBootstrapResolver 用配置里的 UDP 上游作为 bootstrap DNS 解析 DoT 服务器主机名。
// 避免 DNS 服务器解析自己上游时依赖系统 /etc/resolv.conf（如内网 DNS 不可达会导致
// tls:// 上游连接报 lookup i/o timeout）。
// 仅当上游是 IP（非域名）时才可用作 bootstrap 服务器。
func (p *DoTConnPool) SetBootstrapResolver(upstreams []string) {
	for _, u := range upstreams {
		host, _, err := net.SplitHostPort(config.UpstreamDialAddr(u))
		if err != nil || net.ParseIP(host) == nil {
			continue
		}
		addr := config.UpstreamDialAddr(u)
		p.mu.Lock()
		p.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", addr)
			},
		}
		p.mu.Unlock()
		return
	}
}

// GetConn 获取DoT连接（优先复用池中仍存活的空闲连接）
func (p *DoTConnPool) GetConn(ctx context.Context, server string) (*DoTConn, error) {
	return p.getConn(ctx, server, true)
}

// GetFreshConn 强制新建一条 DoT 连接，不复用池中空闲连接。
// 用于复用连接失败后的重试：池中可能还残留其它同样已被服务端断开的死连接，
// 若继续走 GetConn 复用它们，重试会以完全相同的方式再次失败。
func (p *DoTConnPool) GetFreshConn(ctx context.Context, server string) (*DoTConn, error) {
	return p.getConn(ctx, server, false)
}

// getConn 取连接：reusePooled 为 true 时优先复用空闲连接，为 false 时跳过复用直接新建。
// 无论是否复用，都会顺带清理池中过期的空闲连接。
//
// 实现上分三段，确保网络 I/O 不持锁：
//  1. 锁内查找可复用连接、清理过期空闲连接（纯簿记）；
//  2. 锁外进行 TCP 拨号 + TLS 握手（慢操作，并发时互不阻塞）；
//  3. 锁内登记新连接并按上限裁剪「空闲」连接（绝不关闭在用连接）。
//
// 旧实现在一把全局锁内完成建连，任何一次慢握手都会把全部并发查询串行拖死。
func (p *DoTConnPool) getConn(ctx context.Context, server string, reusePooled bool) (*DoTConn, error) {
	if reusePooled {
		if conn := p.acquireIdleConn(server); conn != nil {
			return conn, nil
		}
	} else {
		p.pruneExpiredIdle(server)
	}

	conn, err := p.dialAndHandshake(ctx, server)
	if err != nil {
		return nil, err
	}

	p.registerConn(conn)
	return conn, nil
}

// acquireIdleConn 在锁内查找一条可复用的空闲连接；找不到则返回 nil（调用方转去新建）。
// 命中复用时会标记在用并更新 lastUsed；未命中时顺带清理过期空闲连接。
func (p *DoTConnPool) acquireIdleConn(server string) *DoTConn {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.conns[server] {
		if !conn.inUse && time.Since(conn.lastUsed) < p.timeout &&
			time.Since(conn.created) < dotConnLifetime {
			conn.inUse = true
			conn.lastUsed = time.Now()
			p.metrics.TotalConnsReused++
			p.metrics.ActiveConns++
			log.Printf("[DoT连接池] 复用现有连接: %s", server)
			return conn
		}
	}

	p.pruneExpiredIdleLocked(server)
	return nil
}

// pruneExpiredIdle 清理指定服务器上过期的空闲连接（自行加锁）。
func (p *DoTConnPool) pruneExpiredIdle(server string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneExpiredIdleLocked(server)
}

// pruneExpiredIdleLocked 关闭并移除空闲超时或超过最大寿命的空闲连接（寿命到期前主动轮换，
// 避免阿里 DoT 到点统一断开导致查询失败）。只处理空闲连接，在用连接不动。调用方须持 p.mu。
func (p *DoTConnPool) pruneExpiredIdleLocked(server string) {
	connList, ok := p.conns[server]
	if !ok {
		return
	}
	alive := connList[:0]
	for _, conn := range connList {
		if !conn.inUse && (time.Since(conn.lastUsed) >= p.timeout ||
			time.Since(conn.created) >= dotConnLifetime) {
			log.Printf("[DoT连接池] 连接已过期，关闭: %s", server)
			conn.Close()
			p.metrics.TotalConnsClosed++
			if p.metrics.ActiveConns > 0 {
				p.metrics.ActiveConns--
			}
			continue
		}
		alive = append(alive, conn)
	}
	if len(alive) == 0 {
		delete(p.conns, server)
		return
	}
	p.conns[server] = alive
}

// bootstrapResolver 在锁内取当前的 bootstrap resolver（可能为 nil，此时走系统 DNS）。
func (p *DoTConnPool) bootstrapResolver() *net.Resolver {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resolver
}

// dialAndHandshake 建立一条新的 DoT 连接（TCP 拨号 + TLS 握手）。
// 不访问连接池状态、无需持锁，因此并发建连互不阻塞。返回的连接处于在用状态。
func (p *DoTConnPool) dialAndHandshake(ctx context.Context, server string) (*DoTConn, error) {
	// 创建TCP连接（优先用 bootstrap resolver 解析主机名，避免依赖系统 DNS；
	// bootstrap 解析失败时回退到系统 resolver，保证 tls:// 上游不被单点拖死）
	// 归一化为 host:port：tls://dns.google → dns.google:853（缺端口时 dial 会报 missing port）
	serverAddr := config.UpstreamDialAddr(server)
	resolver := p.bootstrapResolver()
	log.Printf("[DoT连接池] 开始连接TCP: %s", serverAddr)
	var tcpConn net.Conn
	var err error
	// 优先 IPv4：实测部分 DoT 上游（如阿里）IPv6 链路空闲断开更频繁（broken pipe），
	// IPv4 更稳定；IPv4 失败时回退 IPv6，避免 IPv6-only 上游连不上。
	// 网络族顺序：tcp4 → tcp6 → tcp（系统默认）
	dialNetworks := []string{"tcp4", "tcp6"}
	for _, network := range dialNetworks {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		if resolver != nil {
			dialer.Resolver = resolver
		}
		tcpConn, err = dialer.DialContext(ctx, network, serverAddr)
		if err == nil {
			break
		}
		log.Printf("[DoT连接池] TCP连接失败(%s): %s, 错误: %v", network, serverAddr, err)
	}
	// 前两轮都失败且系统解析可用时，最后再按系统默认网络试一次
	if err != nil && resolver != nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		tcpConn, err = dialer.DialContext(ctx, "tcp", serverAddr)
	}
	if err != nil {
		log.Printf("[DoT连接池] TCP连接失败: %s, 错误: %v", serverAddr, err)
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}
	log.Printf("[DoT连接池] TCP连接成功: %s", serverAddr)

	// 设置TCP保活
	if tcpConn, ok := tcpConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetLinger(0) // 立即关闭
	}

	// 创建TLS连接
	// ServerName 必须取纯主机名：strings.Split(addr, ":")[0] 对 IPv6 字面量（[::1]:853）会取到 "["
	serverName := serverAddr
	if host, _, err := net.SplitHostPort(serverAddr); err == nil {
		serverName = host
	}
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)

	// 设置TLS握手超时
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second) // 增加TLS握手超时到10秒
	defer cancel()

	log.Printf("[DoT连接池] 开始TLS握手: %s", serverAddr)
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		log.Printf("[DoT连接池] TLS握手失败: %s, 错误: %v", serverAddr, err)
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	log.Printf("[DoT连接池] TLS握手成功: %s", serverAddr)

	return &DoTConn{
		conn:     tcpConn,
		tlsConn:  tlsConn,
		lastUsed: time.Now(),
		created:  time.Now(),
		inUse:    true,
		server:   server,
	}, nil
}

// registerConn 把新建连接登记进池（自行加锁），并按上限裁剪空闲连接。
func (p *DoTConnPool) registerConn(conn *DoTConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.conns[conn.server] = append(p.conns[conn.server], conn)
	p.metrics.TotalConnsCreated++
	p.metrics.ActiveConns++

	p.trimServerIdleLocked(conn.server, maxDoTConnsPerServer)
	p.trimTotalIdleLocked()
}

// trimServerIdleLocked 把指定服务器的空闲连接裁剪到 keep 条，多余的关闭。
// 只统计/关闭空闲连接：在用连接既不计入上限，也不会被关闭。调用方须持 p.mu。
func (p *DoTConnPool) trimServerIdleLocked(server string, keep int) {
	connList, ok := p.conns[server]
	if !ok {
		return
	}
	idle := 0
	for _, conn := range connList {
		if !conn.inUse {
			idle++
		}
	}
	if idle <= keep {
		return
	}

	excess := idle - keep
	alive := connList[:0]
	for _, conn := range connList {
		if excess > 0 && !conn.inUse {
			log.Printf("[DoT连接池] 空闲连接超上限，关闭空闲连接: %s", server)
			conn.Close()
			p.metrics.TotalConnsClosed++
			if p.metrics.ActiveConns > 0 {
				p.metrics.ActiveConns--
			}
			excess--
			continue
		}
		alive = append(alive, conn)
	}
	if len(alive) == 0 {
		delete(p.conns, server)
		return
	}
	p.conns[server] = alive
}

// trimTotalIdleLocked 全局空闲连接数超过 p.maxConns 时，跨服务器关闭多余的空闲连接。
// 在用连接数不受 p.maxConns 约束，避免把在途查询的连接误杀。调用方须持 p.mu。
func (p *DoTConnPool) trimTotalIdleLocked() {
	totalIdle := 0
	for _, connList := range p.conns {
		for _, conn := range connList {
			if !conn.inUse {
				totalIdle++
			}
		}
	}
	if totalIdle <= p.maxConns {
		return
	}

	excess := totalIdle - p.maxConns
	for server, connList := range p.conns {
		if excess <= 0 {
			break
		}
		alive := connList[:0]
		for _, conn := range connList {
			if excess > 0 && !conn.inUse {
				log.Printf("[DoT连接池] 总空闲连接超上限，关闭空闲连接: %s", server)
				conn.Close()
				p.metrics.TotalConnsClosed++
				if p.metrics.ActiveConns > 0 {
					p.metrics.ActiveConns--
				}
				excess--
				continue
			}
			alive = append(alive, conn)
		}
		if len(alive) == 0 {
			delete(p.conns, server)
		} else {
			p.conns[server] = alive
		}
	}
}

// PutConn 归还DoT连接
func (p *DoTConnPool) PutConn(conn *DoTConn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	conn.inUse = false
	conn.lastUsed = time.Now()
	if p.metrics.ActiveConns > 0 {
		p.metrics.ActiveConns--
	}
}

// DiscardConn 丢弃DoT连接：查询失败（写入/读取出错）时调用。
// 若继续 PutConn 归还，死连接会被后续查询复用导致同样的失败，形成错误风暴；
// 这里把连接从池中剔除并关闭，下一次 GetConn 会新建连接。
func (p *DoTConnPool) DiscardConn(conn *DoTConn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	conn.inUse = false
	if p.metrics.ActiveConns > 0 {
		p.metrics.ActiveConns--
	}
	connList := p.conns[conn.server]
	for i, c := range connList {
		if c == conn {
			conn.Close()
			p.metrics.TotalConnsClosed++
			connList = append(connList[:i], connList[i+1:]...)
			break
		}
	}
	if len(connList) == 0 {
		delete(p.conns, conn.server)
	} else {
		p.conns[conn.server] = connList
	}
}

// Close 关闭连接池中的所有连接
func (p *DoTConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, connList := range p.conns {
		for _, conn := range connList {
			conn.Close()
		}
	}
	p.conns = make(map[string][]*DoTConn)
}

// Close 关闭单个DoT连接
func (c *DoTConn) Close() {
	if c.tlsConn != nil {
		c.tlsConn.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

// healthCheckRoutine 健康检查协程
func (p *DoTConnPool) healthCheckRoutine() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		for server, connList := range p.conns {
			for i := len(connList) - 1; i >= 0; i-- {
				conn := connList[i]
				// 只检查空闲连接
				if !conn.inUse {
					// 检查连接是否过期
					if time.Since(conn.lastUsed) > p.timeout {
						log.Printf("[DoT连接池] 健康检查：连接已过期，关闭: %s", server)
						conn.Close()
						p.metrics.TotalConnsClosed++
						if p.metrics.ActiveConns > 0 {
							p.metrics.ActiveConns--
						}
						// 从列表中移除
						connList = append(connList[:i], connList[i+1:]...)
					} else {
						// 尝试发送一个简单的DNS查询来检查连接是否健康
						// 注意：写入后必须读取并丢弃响应，否则残留数据会污染
						// 下一次真实查询的 ReadMsg；且能确认对端仍存活。
						// 用常见公网域名而非 healthcheck.local.：部分 DoT 上游
						// 对未知 TLD 直接断开连接，导致健康检查误杀正常连接。
						req := new(dns.Msg)
						req.SetQuestion("www.baidu.com.", dns.TypeA)
						req.RecursionDesired = true

						// 使用连接发送查询
						dnsConn := &dns.Conn{Conn: conn.tlsConn}
						err := dnsConn.SetDeadline(time.Now().Add(2 * time.Second))
						if err != nil {
							log.Printf("[DoT连接池] 健康检查：设置超时失败: %v", err)
							conn.Close()
							p.metrics.TotalConnsClosed++
							if p.metrics.ActiveConns > 0 {
								p.metrics.ActiveConns--
							}
							connList = append(connList[:i], connList[i+1:]...)
							continue
						}

						err = dnsConn.WriteMsg(req)
						if err != nil {
							log.Printf("[DoT连接池] 健康检查：写入失败: %v, 关闭连接: %s", err, server)
							conn.Close()
							p.metrics.TotalConnsClosed++
							if p.metrics.ActiveConns > 0 {
								p.metrics.ActiveConns--
							}
							connList = append(connList[:i], connList[i+1:]...)
							continue
						}

						// 读取并丢弃响应，避免脏数据留在读缓冲
						if _, err := dnsConn.ReadMsg(); err != nil {
							log.Printf("[DoT连接池] 健康检查：读取响应失败: %v, 关闭连接: %s", err, server)
							conn.Close()
							p.metrics.TotalConnsClosed++
							if p.metrics.ActiveConns > 0 {
								p.metrics.ActiveConns--
							}
							connList = append(connList[:i], connList[i+1:]...)
							continue
						}
						// 恢复读/写超时
						conn.tlsConn.SetDeadline(time.Time{})
					}
				}
			}
			if len(connList) == 0 {
				delete(p.conns, server)
			} else {
				p.conns[server] = connList
			}
		}
		p.mu.Unlock()
	}
}

// GetMetrics 获取连接池指标
func (p *DoTConnPool) GetMetrics() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 计算当前连接数
	totalConns := 0
	for _, connList := range p.conns {
		totalConns += len(connList)
	}

	return map[string]interface{}{
		"total_connections":  totalConns,
		"active_connections": p.metrics.ActiveConns,
		"total_created":      p.metrics.TotalConnsCreated,
		"total_closed":       p.metrics.TotalConnsClosed,
		"total_reused":       p.metrics.TotalConnsReused,
		"max_connections":    p.maxConns,
		"connection_timeout": p.timeout.String(),
		"servers_count":      len(p.conns),
	}
}

// ===== UDP/TCP 连接池实现 =====

// UDPConnPool UDP连接池
type UDPConnPool struct {
	mu       sync.RWMutex
	clients  map[string][]*UDPClientInfo
	maxConns int
	timeout  time.Duration

	// 监控指标
	metrics struct {
		TotalClientsCreated int64
		TotalClientsClosed  int64
		TotalClientsReused  int64
		ActiveClients       int64
	}
}

// UDPClientInfo 包含DNS客户端和相关信息
type UDPClientInfo struct {
	client   *dns.Client
	lastUsed time.Time
	inUse    bool
	addr     string
}

// NewUDPConnPool 创建新的UDP连接池
func NewUDPConnPool() *UDPConnPool {
	pool := &UDPConnPool{
		clients:  make(map[string][]*UDPClientInfo),
		maxConns: 50,               // 限制最大连接数
		timeout:  60 * time.Second, // 连接超时时间
	}

	// 启动健康检查协程
	go pool.healthCheckRoutine()

	return pool
}

// GetClient 获取UDP客户端
func (p *UDPConnPool) GetClient(addr string, timeout time.Duration) *dns.Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查现有客户端
	if clientList, ok := p.clients[addr]; ok {
		// 先找可复用客户端（过期清理放到循环外一次性完成，
		// 否则边 range 边删元素会让后续迭代下标越界 panic）
		for _, clientInfo := range clientList {
			if !clientInfo.inUse && time.Since(clientInfo.lastUsed) < p.timeout {
				clientInfo.inUse = true
				clientInfo.lastUsed = time.Now()
				p.metrics.TotalClientsReused++
				p.metrics.ActiveClients++
				return clientInfo.client
			}
		}
		// 清理过期的空闲客户端
		alive := clientList[:0]
		for _, clientInfo := range clientList {
			if !clientInfo.inUse && time.Since(clientInfo.lastUsed) >= p.timeout {
				p.metrics.TotalClientsClosed++
				if p.metrics.ActiveClients > 0 {
					p.metrics.ActiveClients--
				}
				continue
			}
			alive = append(alive, clientInfo)
		}
		p.clients[addr] = alive
	}

	// 创建新客户端
	client := &dns.Client{
		Net:            "udp",
		Timeout:        timeout,
		DialTimeout:    timeout,
		ReadTimeout:    timeout,
		WriteTimeout:   timeout,
		SingleInflight: true, // 对于相同的查询只允许一次飞行中的请求
	}

	clientInfo := &UDPClientInfo{
		client:   client,
		lastUsed: time.Now(),
		inUse:    true,
		addr:     addr,
	}

	// 检查服务器客户端数，如果超过限制则清理旧客户端
	if clientList, ok := p.clients[addr]; ok && len(clientList) >= 10 { // 每个服务器最多10个客户端
		// 清理最旧的客户端
		oldestIdx := 0
		oldestTime := clientList[0].lastUsed
		for i, clientInfo := range clientList {
			if clientInfo.lastUsed.Before(oldestTime) {
				oldestIdx = i
				oldestTime = clientInfo.lastUsed
			}
		}
		clientList = append(clientList[:oldestIdx], clientList[oldestIdx+1:]...)
		p.clients[addr] = clientList
	}

	// 检查总连接池大小，如果超过限制则清理旧连接
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	if totalClients >= p.maxConns {
		p.cleanupOldConnections()
	}

	// 添加到客户端列表
	if _, ok := p.clients[addr]; !ok {
		p.clients[addr] = []*UDPClientInfo{}
	}
	p.clients[addr] = append(p.clients[addr], clientInfo)
	p.metrics.TotalClientsCreated++
	p.metrics.ActiveClients++
	return client
}

// PutClient 归还UDP客户端
func (p *UDPConnPool) PutClient(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if clientList, ok := p.clients[addr]; ok {
		// 找到第一个使用中的客户端并归还
		for _, clientInfo := range clientList {
			if clientInfo.inUse {
				clientInfo.inUse = false
				clientInfo.lastUsed = time.Now()
				if p.metrics.ActiveClients > 0 {
					p.metrics.ActiveClients--
				}
				break
			}
		}
	}
}

// cleanupOldConnections 清理旧连接
func (p *UDPConnPool) cleanupOldConnections() {
	var oldestAddr string
	var oldestIdx int
	var oldestTime time.Time

	for addr, clientList := range p.clients {
		for i, clientInfo := range clientList {
			if oldestAddr == "" || clientInfo.lastUsed.Before(oldestTime) {
				oldestAddr = addr
				oldestIdx = i
				oldestTime = clientInfo.lastUsed
			}
		}
	}

	if oldestAddr != "" {
		clientList := p.clients[oldestAddr]
		clientList = append(clientList[:oldestIdx], clientList[oldestIdx+1:]...)
		p.metrics.TotalClientsClosed++
		if p.metrics.ActiveClients > 0 {
			p.metrics.ActiveClients--
		}
		if len(clientList) == 0 {
			delete(p.clients, oldestAddr)
		} else {
			p.clients[oldestAddr] = clientList
		}
	}
}

// Close 关闭连接池中的所有连接
func (p *UDPConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.clients = make(map[string][]*UDPClientInfo)
}

// healthCheckRoutine 健康检查协程
func (p *UDPConnPool) healthCheckRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		for addr, clientList := range p.clients {
			for i := len(clientList) - 1; i >= 0; i-- {
				clientInfo := clientList[i]
				// 只检查空闲客户端
				if !clientInfo.inUse {
					// 检查客户端是否过期
					if time.Since(clientInfo.lastUsed) > p.timeout {
						log.Printf("[UDP连接池] 健康检查：客户端已过期，删除: %s", addr)
						// 从列表中移除
						clientList = append(clientList[:i], clientList[i+1:]...)
						p.metrics.TotalClientsClosed++
						if p.metrics.ActiveClients > 0 {
							p.metrics.ActiveClients--
						}
					}
				}
			}
			if len(clientList) == 0 {
				delete(p.clients, addr)
			} else {
				p.clients[addr] = clientList
			}
		}
		p.mu.Unlock()
	}
}

// GetMetrics 获取连接池指标
func (p *UDPConnPool) GetMetrics() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 计算当前客户端数
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}

	return map[string]interface{}{
		"total_clients":  totalClients,
		"active_clients": p.metrics.ActiveClients,
		"total_created":  p.metrics.TotalClientsCreated,
		"total_closed":   p.metrics.TotalClientsClosed,
		"total_reused":   p.metrics.TotalClientsReused,
		"max_clients":    p.maxConns,
		"client_timeout": p.timeout.String(),
		"servers_count":  len(p.clients),
	}
}

// ===== TCP 连接池实现 =====

// TCPConnPool TCP连接池
type TCPConnPool struct {
	mu       sync.RWMutex
	clients  map[string][]*TCPClientInfo
	maxConns int
	timeout  time.Duration

	// 监控指标
	metrics struct {
		TotalClientsCreated int64
		TotalClientsClosed  int64
		TotalClientsReused  int64
		ActiveClients       int64
	}
}

// NewTCPConnPool 创建新的TCP连接池
func NewTCPConnPool() *TCPConnPool {
	pool := &TCPConnPool{
		clients:  make(map[string][]*TCPClientInfo),
		maxConns: 50,               // 限制最大连接数
		timeout:  60 * time.Second, // 连接超时时间
	}

	// 启动健康检查协程
	go pool.healthCheckRoutine()

	return pool
}

// TCPClientInfo 包含TCP DNS客户端和相关信息
type TCPClientInfo struct {
	client   *dns.Client
	lastUsed time.Time
	inUse    bool
	addr     string
}

// GetClient 获取TCP客户端
func (p *TCPConnPool) GetClient(addr string, timeout time.Duration) *dns.Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查现有客户端
	if clientList, ok := p.clients[addr]; ok {
		// 先找可复用客户端（过期清理放到循环外一次性完成，
		// 否则边 range 边删元素会让后续迭代下标越界 panic）
		for _, clientInfo := range clientList {
			if !clientInfo.inUse && time.Since(clientInfo.lastUsed) < p.timeout {
				clientInfo.inUse = true
				clientInfo.lastUsed = time.Now()
				p.metrics.TotalClientsReused++
				p.metrics.ActiveClients++
				return clientInfo.client
			}
		}
		// 清理过期的空闲客户端
		alive := clientList[:0]
		for _, clientInfo := range clientList {
			if !clientInfo.inUse && time.Since(clientInfo.lastUsed) >= p.timeout {
				p.metrics.TotalClientsClosed++
				if p.metrics.ActiveClients > 0 {
					p.metrics.ActiveClients--
				}
				continue
			}
			alive = append(alive, clientInfo)
		}
		p.clients[addr] = alive
	}

	// 创建新客户端
	client := &dns.Client{
		Net:            "tcp",
		Timeout:        timeout,
		DialTimeout:    timeout,
		ReadTimeout:    timeout,
		WriteTimeout:   timeout,
		SingleInflight: true, // 对于相同的查询只允许一次飞行中的请求
	}

	clientInfo := &TCPClientInfo{
		client:   client,
		lastUsed: time.Now(),
		inUse:    true,
		addr:     addr,
	}

	// 检查服务器客户端数，如果超过限制则清理旧客户端
	if clientList, ok := p.clients[addr]; ok && len(clientList) >= 10 { // 每个服务器最多10个客户端
		// 清理最旧的客户端
		oldestIdx := 0
		oldestTime := clientList[0].lastUsed
		for i, clientInfo := range clientList {
			if clientInfo.lastUsed.Before(oldestTime) {
				oldestIdx = i
				oldestTime = clientInfo.lastUsed
			}
		}
		clientList = append(clientList[:oldestIdx], clientList[oldestIdx+1:]...)
		p.clients[addr] = clientList
	}

	// 检查总连接池大小，如果超过限制则清理旧连接
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	if totalClients >= p.maxConns {
		p.cleanupOldConnections()
	}

	// 添加到客户端列表
	if _, ok := p.clients[addr]; !ok {
		p.clients[addr] = []*TCPClientInfo{}
	}
	p.clients[addr] = append(p.clients[addr], clientInfo)
	p.metrics.TotalClientsCreated++
	p.metrics.ActiveClients++
	return client
}

// PutClient 归还TCP客户端
func (p *TCPConnPool) PutClient(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if clientList, ok := p.clients[addr]; ok {
		// 找到第一个使用中的客户端并归还
		for _, clientInfo := range clientList {
			if clientInfo.inUse {
				clientInfo.inUse = false
				clientInfo.lastUsed = time.Now()
				if p.metrics.ActiveClients > 0 {
					p.metrics.ActiveClients--
				}
				break
			}
		}
	}
}

// cleanupOldConnections 清理旧连接
func (p *TCPConnPool) cleanupOldConnections() {
	var oldestAddr string
	var oldestIdx int
	var oldestTime time.Time

	for addr, clientList := range p.clients {
		for i, clientInfo := range clientList {
			if oldestAddr == "" || clientInfo.lastUsed.Before(oldestTime) {
				oldestAddr = addr
				oldestIdx = i
				oldestTime = clientInfo.lastUsed
			}
		}
	}

	if oldestAddr != "" {
		clientList := p.clients[oldestAddr]
		clientList = append(clientList[:oldestIdx], clientList[oldestIdx+1:]...)
		p.metrics.TotalClientsClosed++
		if p.metrics.ActiveClients > 0 {
			p.metrics.ActiveClients--
		}
		if len(clientList) == 0 {
			delete(p.clients, oldestAddr)
		} else {
			p.clients[oldestAddr] = clientList
		}
	}
}

// Close 关闭连接池中的所有连接
func (p *TCPConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.clients = make(map[string][]*TCPClientInfo)
}

// healthCheckRoutine 健康检查协程
func (p *TCPConnPool) healthCheckRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		for addr, clientList := range p.clients {
			for i := len(clientList) - 1; i >= 0; i-- {
				clientInfo := clientList[i]
				// 只检查空闲客户端
				if !clientInfo.inUse {
					// 检查客户端是否过期
					if time.Since(clientInfo.lastUsed) > p.timeout {
						log.Printf("[TCP连接池] 健康检查：客户端已过期，删除: %s", addr)
						// 从列表中移除
						clientList = append(clientList[:i], clientList[i+1:]...)
						p.metrics.TotalClientsClosed++
						if p.metrics.ActiveClients > 0 {
							p.metrics.ActiveClients--
						}
					}
				}
			}
			if len(clientList) == 0 {
				delete(p.clients, addr)
			} else {
				p.clients[addr] = clientList
			}
		}
		p.mu.Unlock()
	}
}

// GetMetrics 获取连接池指标
func (p *TCPConnPool) GetMetrics() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 计算当前客户端数
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}

	return map[string]interface{}{
		"total_clients":  totalClients,
		"active_clients": p.metrics.ActiveClients,
		"total_created":  p.metrics.TotalClientsCreated,
		"total_closed":   p.metrics.TotalClientsClosed,
		"total_reused":   p.metrics.TotalClientsReused,
		"max_clients":    p.maxConns,
		"client_timeout": p.timeout.String(),
		"servers_count":  len(p.clients),
	}
}

// ===== DoH 连接池实现 =====

// DoHConnPool DoH连接池
type DoHConnPool struct {
	mu               sync.RWMutex
	clients          map[string][]*http.Client
	maxClients       int
	timeout          time.Duration
	clientsPerServer int

	// 监控指标
	metrics struct {
		TotalClientsCreated int64
		TotalClientsClosed  int64
		TotalClientsUsed    int64
		ActiveClients       int64
	}
}

// NewDoHConnPool 创建新的DoH连接池
func NewDoHConnPool() *DoHConnPool {
	pool := &DoHConnPool{
		clients:          make(map[string][]*http.Client),
		maxClients:       50,               // 总客户端数上限
		timeout:          90 * time.Second, // 增加超时时间到90秒
		clientsPerServer: 5,                // 每个服务器最多5个客户端
	}

	// 启动健康检查协程
	go pool.healthCheckRoutine()

	return pool
}

// GetClient 获取DoH客户端
func (p *DoHConnPool) GetClient(server string) *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查现有客户端
	if clientList, ok := p.clients[server]; ok && len(clientList) > 0 {
		// 简单轮询选择客户端
		client := clientList[len(clientList)-1]
		// 将选中的客户端移到列表开头，实现简单的轮询
		clientList = append([]*http.Client{client}, clientList[:len(clientList)-1]...)
		p.clients[server] = clientList
		p.metrics.TotalClientsUsed++
		p.metrics.ActiveClients++
		return client
	}

	// 检查服务器客户端数，如果超过限制则清理旧客户端
	if clientList, ok := p.clients[server]; ok && len(clientList) >= p.clientsPerServer {
		// 清理最旧的客户端
		clientList[0].CloseIdleConnections()
		clientList = clientList[1:]
		p.clients[server] = clientList
		p.metrics.TotalClientsClosed++
		if p.metrics.ActiveClients > 0 {
			p.metrics.ActiveClients--
		}
	}

	// 检查总连接池大小，如果超过限制则清理旧客户端
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	if totalClients >= p.maxClients {
		p.cleanupOldClients()
	}

	// 创建新的HTTP客户端，启用连接复用
	client := &http.Client{
		Timeout: p.timeout,
		Transport: &http.Transport{
			MaxIdleConns:        200,              // 增加最大空闲连接数
			MaxIdleConnsPerHost: 20,               // 增加每个主机的最大空闲连接数
			IdleConnTimeout:     90 * time.Second, // 增加空闲连接超时时间
			TLSHandshakeTimeout: 10 * time.Second, // 增加TLS握手超时
			DisableCompression:  true,
		},
	}

	// 添加到客户端列表
	if _, ok := p.clients[server]; !ok {
		p.clients[server] = []*http.Client{}
	}
	p.clients[server] = append(p.clients[server], client)
	p.metrics.TotalClientsCreated++
	p.metrics.ActiveClients++
	return client
}

// cleanupOldClients 清理旧客户端
func (p *DoHConnPool) cleanupOldClients() {
	// 简单策略：找到客户端数最多的服务器，清理一个客户端
	var maxServer string
	maxClients := 0

	for server, clientList := range p.clients {
		if len(clientList) > maxClients {
			maxServer = server
			maxClients = len(clientList)
		}
	}

	if maxServer != "" {
		clientList := p.clients[maxServer]
		if len(clientList) > 0 {
			// 清理最旧的客户端
			clientList[0].CloseIdleConnections()
			clientList = clientList[1:]
			log.Printf("[DoH连接池] 清理旧客户端: %s", maxServer)
			p.metrics.TotalClientsClosed++
			if p.metrics.ActiveClients > 0 {
				p.metrics.ActiveClients--
			}
			if len(clientList) == 0 {
				delete(p.clients, maxServer)
			} else {
				p.clients[maxServer] = clientList
			}
		}
	}
}

// Close 关闭连接池中的所有客户端
func (p *DoHConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, clientList := range p.clients {
		for _, client := range clientList {
			client.CloseIdleConnections()
		}
	}
	p.clients = make(map[string][]*http.Client)
}

// healthCheckRoutine 健康检查协程
func (p *DoHConnPool) healthCheckRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		for server, clientList := range p.clients {
			for i := len(clientList) - 1; i >= 0; i-- {
				client := clientList[i]
				// 关闭空闲连接，保持连接池健康
				client.CloseIdleConnections()
				// 这里可以添加更复杂的健康检查逻辑
				// 例如，发送一个简单的HTTP请求来检查连接是否有效
			}
			if len(clientList) == 0 {
				delete(p.clients, server)
			} else {
				p.clients[server] = clientList
			}
		}
		p.mu.Unlock()
	}
}

// GetMetrics 获取连接池指标
func (p *DoHConnPool) GetMetrics() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 计算当前客户端数
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}

	return map[string]interface{}{
		"total_clients":      totalClients,
		"active_clients":     p.metrics.ActiveClients,
		"total_created":      p.metrics.TotalClientsCreated,
		"total_closed":       p.metrics.TotalClientsClosed,
		"total_used":         p.metrics.TotalClientsUsed,
		"max_clients":        p.maxClients,
		"client_timeout":     p.timeout.String(),
		"clients_per_server": p.clientsPerServer,
		"servers_count":      len(p.clients),
	}
}
