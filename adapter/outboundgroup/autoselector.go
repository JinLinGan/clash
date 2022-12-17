package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/singledo"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/log"
)

var (
	defaultBlockTime = time.Minute
	defaultTimeout   = time.Second * 7
)

type AutoSelector struct {
	*outbound.Base
	providers []provider.ProxyProvider
	single    *singledo.Single

	// failedProxies 存储所有近期失败过的代理，当所有代理近期都失败过时，逐一尝试所有代理
	failedProxies sync.Map

	// blockTime 代理失败后被关小黑屋的时长
	blockTime time.Duration
}

func (a *AutoSelector) Alive() bool {
	return true
}

func (a *AutoSelector) DelayHistory() []C.DelayHistory {
	return make([]C.DelayHistory, 0)
}

func (a *AutoSelector) LastDelay() uint16 {
	proxies := a.FindCandidatesProxy()
	if len(proxies) == 0 {
		return 0
	}
	for _, proxy := range proxies {
		d := proxy.LastDelay()
		return d
	}

	return 0
}

func (a *AutoSelector) URLTest(ctx context.Context, url string) (uint16, error) {
	proxies := a.FindCandidatesProxy()
	if len(proxies) == 0 {
		return 0, errors.New("no available proxies")
	}
	for _, proxy := range proxies {
		t, err := proxy.URLTest(ctx, url)
		if err == nil {
			return t, nil
		}
		a.failedProxies.Store(proxy.Name(), time.Now())
		a.single.Reset()
	}

	return 0, errors.New("no available proxies")
}

func (a *AutoSelector) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	proxies := a.FindCandidatesProxy()
	if len(proxies) == 0 {
		return nil, errors.New("no available proxies")
	}
	for _, proxy := range proxies {
		ch := make(chan dialResult, 1)
		dialCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
		// defer cancel()
		go func() {
			defer func() {
				cancel()
				close(ch)
			}()
			var r dialResult
			r.conn, r.err = proxy.DialContext(dialCtx, metadata, a.Base.DialOptions(opts...)...)
			select {
			case <-ctx.Done():
				if r.conn != nil {
					r.conn.Close()
				}
			default:
				ch <- r
			}
		}()

		var err error
		select {
		case r := <-ch:
			if err = r.err; err == nil {
				return r.conn, nil
			}
		case <-dialCtx.Done():
			err = dialCtx.Err()
		}
		a.failedProxies.Store(proxy.Name(), time.Now())
		// 出现新的关小黑屋,需要重置FindCandidatesProxy
		a.single.Reset()
		log.Infoln("autoSelector '%s' DialContext failed. try next: %v", proxy.Name(), err)
	}

	return nil, errors.New("no available proxies")
}

// ListenPacketContext implements C.ProxyAdapter
func (a *AutoSelector) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	proxies := a.FindCandidatesProxy()
	if len(proxies) == 0 {
		return nil, errors.New("no available proxies")
	}
	for _, proxy := range proxies {
		if proxy.SupportUDP() {
			ch := make(chan listenPacketRes, 1)
			dialCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
			go func() {
				defer func() {
					cancel()
					close(ch)
				}()
				pc, err := proxy.ListenPacketContext(dialCtx, metadata, a.Base.DialOptions(opts...)...)
				select {
				case <-ctx.Done():
					if pc != nil {
						pc.Close()
					}
				default:
					ch <- listenPacketRes{
						conn: pc,
						err:  err,
					}
				}
			}()
			var err error
			select {
			case r := <-ch:
				if err = r.err; err == nil {
					return r.conn, nil
				}
			case <-dialCtx.Done():
				err = dialCtx.Err()
			}
			a.failedProxies.Store(proxy.Name(), time.Now())
			a.single.Reset()
			log.Infoln("autoSelector '%s' ListenPacketContext failed. try next: %v", proxy.Name(), err)
		}
	}

	return nil, errors.New("no available proxies")
}

// Deprecated: use DialContext instead.
func (a *AutoSelector) Dial(metadata *C.Metadata) (C.Conn, error) {
	proxies := a.FindCandidatesProxy()
	if len(proxies) == 0 {
		return nil, errors.New("no available proxies")
	}
	for _, proxy := range proxies {
		conn, err := proxy.Dial(metadata)
		if err == nil {
			return conn, nil
		}
		a.failedProxies.Store(proxy.Name(), time.Now())
		a.single.Reset()
	}

	return nil, errors.New("no available proxies")
}

// Deprecated: use DialPacketConn instead.
func (a *AutoSelector) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	proxies := a.FindCandidatesProxy()
	if len(proxies) == 0 {
		return nil, errors.New("no available proxies")
	}
	for _, proxy := range proxies {
		conn, err := proxy.DialUDP(metadata)
		if err == nil {
			return conn, nil
		}
		a.failedProxies.Store(proxy.Name(), time.Now())
		a.single.Reset()
	}

	return nil, errors.New("no available proxies")
}

func (a *AutoSelector) Now() string {
	c := a.FindCandidatesProxy()
	if len(c) > 0 {
		return c[0].Name()
	}

	return ""
}

func (a *AutoSelector) FindCandidatesProxy() []C.Proxy {
	elem, _, _ := a.single.Do(func() (any, error) {
		var (
			all       = getProvidersProxies(a.providers, true)
			result    = make([]C.Proxy, 0, len(all))
			hasFailed []C.Proxy
		)

		// 被关小黑屋的时间只要在此之前就放出来
		allowedLastFailedTime := time.Now().Add(-a.blockTime)
		for _, proxy := range all {
			proxy := proxy
			if blockTime, ok := a.failedProxies.Load(proxy.Name()); ok {
				// 出狱的放入hasFailed
				if blockTime.(time.Time).Before(allowedLastFailedTime) {
					hasFailed = append(hasFailed, proxy)
				}
				// 不能出狱,跳过
				continue
			}
			// 没进过小黑屋,加入结果集
			result = append(result, proxy)
		}
		// 出狱的append在没进过小黑屋的后方
		result = append(result, hasFailed...)
		// 没有结果,返回全部
		if len(result) == 0 {
			result = all
		}
		return result, nil
	})
	return elem.([]C.Proxy)
}

// Unwrap
func (a *AutoSelector) Unwrap(metadata *C.Metadata) C.Proxy {
	return a
}

// MarshalJSON implements C.ProxyAdapter
func (a *AutoSelector) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range getProvidersProxies(a.providers, false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": a.Type().String(),
		"now":  a.Now(),
		"all":  all,
	})
}

func NewAutoSelector(option *GroupCommonOption, providers []provider.ProxyProvider) *AutoSelector {
	as := &AutoSelector{
		Base: outbound.NewBase(outbound.BaseOption{
			Name:        option.Name,
			Type:        C.AutoSelector,
			Interface:   option.Interface,
			RoutingMark: option.RoutingMark,
		}),
		providers: providers,
		single:    singledo.NewSingle(time.Second * 10),
		blockTime: option.BlockTime,
	}
	if as.blockTime <= 0 {
		as.blockTime = defaultBlockTime
	}

	return as
}

type dialResult struct {
	conn C.Conn
	err  error
}

type listenPacketRes struct {
	conn C.PacketConn
	err  error
}
