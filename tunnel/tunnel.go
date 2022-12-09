package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/defaultinbound"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/adapter/outboundgroup"
	aprovider "github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/component/nat"
	P "github.com/Dreamacro/clash/component/process"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	icontext "github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel/statistic"

	"go.uber.org/atomic"
)

var (
	tcpQueue  = make(chan C.ConnContext, 200)
	udpQueue  = make(chan *defaultinbound.PacketAdapter, 200)
	natTable  = nat.New()
	rules     []C.Rule
	proxies   = make(map[string]C.Proxy)
	providers map[string]provider.ProxyProvider
	configMux sync.RWMutex

	// Outbound Rule
	mode = Rule

	// 默认
	defaultProxy = "REJECT"

	// default timeout for UDP session
	udpTimeout = 60 * time.Second

	LocalDNS *atomic.Bool = atomic.NewBool(false)
)

func init() {
	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
	go process()
}

// TCPIn return fan-in queue
func TCPIn() chan<- C.ConnContext {
	return tcpQueue
}

// UDPIn return fan-in udp queue
func UDPIn() chan<- *defaultinbound.PacketAdapter {
	return udpQueue
}

// Rules return all rules
func Rules() []C.Rule {
	return rules
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule) {
	configMux.Lock()
	rules = newRules
	configMux.Unlock()
}

// Proxies return all proxies
func Proxies() map[string]C.Proxy {
	configMux.RLock()
	result := make(map[string]C.Proxy, len(proxies))
	for name, proxy := range proxies {
		result[name] = proxy
	}
	configMux.RUnlock()
	return result
}

func GetProxy(name string) (C.Proxy, bool) {
	configMux.RLock()
	proxy, exist := proxies[name]
	configMux.RUnlock()
	return proxy, exist
}

// Providers return all compatible providers
func Providers() map[string]provider.ProxyProvider {
	return providers
}

// UpdateProxies handle update proxies
func UpdateProxies(newProxies map[string]C.Proxy, newProviders map[string]provider.ProxyProvider) {
	configMux.Lock()
	proxies = newProxies
	providers = newProviders
	configMux.Unlock()
}

// Mode return current mode
func Mode() TunnelMode {
	return mode
}

// SetMode change the mode of tunnel
func SetMode(m TunnelMode) {
	mode = m
}

// processUDP starts a loop to handle udp packet
func processUDP() {
	queue := udpQueue
	for conn := range queue {
		handleUDPConn(conn)
	}
}

func process() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}
	for i := 0; i < numUDPWorkers; i++ {
		go processUDP()
	}

	queue := tcpQueue
	for conn := range queue {
		go handleTCPConn(conn)
	}
}

func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP != nil
}

func preHandleMetadata(metadata *C.Metadata) error {
	// handle IP string on host
	if ip := net.ParseIP(metadata.Host); ip != nil {
		metadata.DstIP = ip
		metadata.Host = ""
	}

	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP)
		if exist {
			metadata.Host = host
			metadata.DNSMode = C.DNSMapping
			if resolver.FakeIPEnabled() {
				metadata.DstIP = nil
				metadata.DNSMode = C.DNSFakeIP
			} else if node := resolver.DefaultHosts.Search(host); node != nil {
				// redir-host should lookup the hosts
				metadata.DstIP = node.Data.(net.IP)
			}
		} else if resolver.IsFakeIP(metadata.DstIP) {
			return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	}

	return nil
}

func resolveMetadata(ctx C.PlainContext, metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	switch mode {
	case Direct:
		proxy, _ = GetProxy("DIRECT")
	case Global:
		proxy, _ = GetProxy("GLOBAL")
	// Rule
	default:
		proxy, rule, err = match(metadata)
	}
	return
}

func handleUDPConn(packet *defaultinbound.PacketAdapter) {
	metadata := packet.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	// make a fAddr if request ip is fakeip
	var fAddr netip.Addr
	if resolver.IsExistFakeIP(metadata.DstIP) {
		fAddr, _ = netip.AddrFromSlice(metadata.DstIP)
		fAddr = fAddr.Unmap()
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	// local resolve UDP dns
	if !metadata.Resolved() {
		ips, err := resolver.LookupIP(context.Background(), metadata.Host)
		if err != nil {
			return
		} else if len(ips) == 0 {
			return
		}
		metadata.DstIP = ips[0]
	}

	key := packet.LocalAddr().String()
	handle := func() bool {
		pc := natTable.Get(key)
		if pc != nil {
			handleUDPToRemote(packet, pc, metadata)
			return true
		}
		return false
	}

	if handle() {
		return
	}

	lockKey := key + "-lock"
	cond, loaded := natTable.GetOrCreateLock(lockKey)

	go func() {
		if loaded {
			cond.L.Lock()
			cond.Wait()
			handle()
			cond.L.Unlock()
			return
		}

		defer func() {
			natTable.Delete(lockKey)
			cond.Broadcast()
		}()

		pCtx := icontext.NewPacketConnContext(metadata)
		proxy, rule, err := resolveMetadata(pCtx, metadata)
		if err != nil {
			log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
		defer cancel()
		rawPc, err := proxy.ListenPacketContext(ctx, metadata.Pure())
		if err != nil {
			if rule == nil {
				log.Warnln(
					"[UDP] dial %s %s --> %s error: %s",
					proxy.Name(),
					metadata.SourceAddress(),
					metadata.RemoteAddress(),
					err.Error(),
				)
			} else {
				log.Warnln("[UDP] dial %s (match %s/%s) %s --> %s error: %s", proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceAddress(), metadata.RemoteAddress(), err.Error())
			}
			return
		}
		pCtx.InjectPacketConn(rawPc)
		pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule)

		switch true {
		case rule != nil:
			log.Infoln(
				"[UDP] %s --> %s match %s(%s) using %s",
				metadata.SourceAddress(),
				metadata.RemoteAddress(),
				rule.RuleType().String(),
				rule.Payload(),
				rawPc.Chains().String(),
			)
		case mode == Global:
			log.Infoln("[UDP] %s --> %s using GLOBAL", metadata.SourceAddress(), metadata.RemoteAddress())
		case mode == Direct:
			log.Infoln("[UDP] %s --> %s using DIRECT", metadata.SourceAddress(), metadata.RemoteAddress())
		default:
			log.Infoln(
				"[UDP] %s --> %s doesn't match any rule using %s",
				metadata.SourceAddress(),
				metadata.RemoteAddress(),
				defaultProxy,
			)
		}

		oAddr, _ := netip.AddrFromSlice(metadata.DstIP)
		oAddr = oAddr.Unmap()
		go handleUDPToLocal(packet.UDPPacket, pc, key, oAddr, fAddr)
		natTable.Set(key, pc)
		handle()
	}()
}

func handleTCPConn(connCtx C.ConnContext) {
	defer connCtx.Conn().Close()

	metadata := connCtx.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	proxy, rule, err := resolveMetadata(connCtx, metadata)
	if err != nil {
		log.Warnln("[Metadata] parse failed: %s", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	remoteConn, err := proxy.DialContext(ctx, metadata.Pure())
	if err != nil {
		if rule == nil {
			log.Warnln(
				"[TCP] dial %s %s --> %s error: %s",
				proxy.Name(),
				metadata.SourceAddress(),
				metadata.RemoteAddress(),
				err.Error(),
			)
		} else {
			log.Warnln("[TCP] dial %s (match %s/%s) %s --> %s error: %s", proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceAddress(), metadata.RemoteAddress(), err.Error())
		}
		return
	}
	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule)
	defer remoteConn.Close()

	switch true {
	case rule != nil:
		log.Infoln(
			"[TCP] %s --> %s match %s(%s) using %s",
			metadata.SourceAddress(),
			metadata.RemoteAddress(),
			rule.RuleType().String(),
			rule.Payload(),
			remoteConn.Chains().String(),
		)
	case mode == Global:
		log.Infoln("[TCP] %s --> %s using GLOBAL", metadata.SourceAddress(), metadata.RemoteAddress())
	case mode == Direct:
		log.Infoln("[TCP] %s --> %s using DIRECT", metadata.SourceAddress(), metadata.RemoteAddress())
	default:
		log.Infoln(
			"[TCP] %s --> %s doesn't match any rule using DIRECT",
			metadata.SourceAddress(),
			metadata.RemoteAddress(),
		)
	}

	handleSocket(connCtx, remoteConn)
}

func shouldResolveIP(rule C.Rule, metadata *C.Metadata) bool {
	return rule.ShouldResolveIP() && metadata.Host != "" && metadata.DstIP == nil
}

func match(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	configMux.RLock()
	defer configMux.RUnlock()

	var resolved bool
	var processFound bool

	if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
		ip := node.Data.(net.IP)
		metadata.DstIP = ip
		resolved = true
	}

	if LocalDNS.Load() && metadata.Host != "" && metadata.DstIP == nil {
		ip, err := resolver.ResolveIP(metadata.Host)
		if err != nil {
			log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
		} else {
			log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
			metadata.DstIP = ip
			metadata.Host = ip.String()
		}
		resolved = true
	}

	for _, rule := range rules {
		if !resolved && shouldResolveIP(rule, metadata) {
			ip, err := resolver.ResolveIP(metadata.Host)
			if err != nil {
				log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
			} else {
				log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
				metadata.DstIP = ip
			}
			resolved = true
		}

		if !processFound && rule.ShouldFindProcess() {
			processFound = true

			srcPort, err := strconv.ParseUint(metadata.SrcPort, 10, 16)
			if err == nil {
				path, err := P.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, int(srcPort))
				if err != nil {
					log.Debugln("[Process] find process %s: %v", metadata.String(), err)
				} else {
					log.Debugln("[Process] %s from process %s", metadata.String(), path)
					metadata.ProcessPath = path
				}
			}
		}
		if rule.Match(metadata) {
			adapter, ok := proxies[rule.Adapter()]
			if !ok {
				break
			}

			if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
				log.Debugln("%s UDP is not supported", adapter.Name())
				break
			}
			return adapter, rule, nil
		}
	}
	if _, ok := proxies[defaultProxy]; !ok {
		defaultProxy = "REJECT"
	}
	return proxies[defaultProxy], nil, nil
}

func SetDefaultProxy(proxyName string) bool {
	if _, ok := GetProxy(proxyName); !ok {
		return false
	}
	defaultProxy = proxyName
	return true
}

func AddOutbounds(ps []C.Proxy) (err error) {
	configMux.Lock()
	defer configMux.Unlock()

	// 如果线路列表为空，添加 DIRECT 和 Reject
	if len(proxies) == 0 {
		ps = append(ps, adapter.NewProxy(outbound.NewDirect()), adapter.NewProxy(outbound.NewReject()))
	}
	// 检查后再赋值,让update是一个整体,一起失败/成功
	check := map[string]C.Proxy{}
	for _, p := range ps {
		if p.Name() == "" {
			err = errors.New("proxy name is required")
			break
		}
		if _, ok := proxies[p.Name()]; ok {
			err = fmt.Errorf("proxy already [%s] exist", p.Name())
			break
		}
		check[p.Name()] = p
	}
	if err != nil {
		return err
	}
	for name := range check {
		proxies[name] = check[name]
	}

	ReNewGlobalOutbound()
	return
}

func ReNewGlobalOutbound() {
	ps := []C.Proxy{}
	for name, v := range proxies {
		if name != "GLOBAL" {
			ps = append(ps, v)
		}
	}

	if len(ps) == 0 {
		return
	}

	hc := aprovider.NewHealthCheck(ps, "", 0, true)
	pd, _ := aprovider.NewCompatibleProvider(aprovider.ReservedName, ps, hc)

	global := outboundgroup.NewSelector(
		&outboundgroup.GroupCommonOption{
			Name: "GLOBAL",
		},
		[]provider.ProxyProvider{pd},
	)
	proxies["GLOBAL"] = adapter.NewProxy(global)
}

func DeleteOutbounds(params []string) {
	configMux.Lock()
	defer configMux.Unlock()

	for _, param := range params {
		if param == "DIRECT" || param == "REJECT" {
			log.Errorln("can not delete %s", param)
		}
		delete(proxies, param)
	}
	ReNewGlobalOutbound()
}

func AddOutboundGroups(params []outboundgroup.GroupCommonOption) (err error) {
	configMux.Lock()
	defer configMux.Unlock()
	check := map[string]C.Proxy{}
	for _, param := range params {
		if param.Name == "" {
			err = errors.New("proxy name is required")
			break
		}
		if _, ok := proxies[param.Name]; ok {
			err = fmt.Errorf("proxy group [%s] already exist", param.Name)
			break
		}
		group, err := outboundgroup.ParseProxyGroup(param, proxies, make(map[string]provider.ProxyProvider))
		if err != nil {
			break
		}
		check[group.Name()] = adapter.NewProxy(group)
	}
	if err != nil {
		return err
	}
	for name := range check {
		proxies[name] = check[name]
	}
	ReNewGlobalOutbound()
	return
}

func UpdateOutboundGroup(param outboundgroup.GroupCommonOption) error {
	configMux.Lock()
	defer configMux.Unlock()

	group, err := outboundgroup.ParseProxyGroup(param, proxies, make(map[string]provider.ProxyProvider))
	if err != nil {
		return err
	}
	proxies[param.Name] = adapter.NewProxy(group)
	ReNewGlobalOutbound()
	return nil
}
