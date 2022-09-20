package controller

// 增删改查 inbounds,outbounds,outbound-groups,rules

import (
	"github.com/Dreamacro/clash/adapter/outboundgroup"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/hub/route"

	P "github.com/Dreamacro/clash/listener"
	T "github.com/Dreamacro/clash/tunnel"
)

// GetInbounds 获取全部inbounds
func GetInbounds() map[string]C.Inbound {
	return P.GetInbounds()
}

// AddInbounds 新增inbound
func AddInbounds(params []config.InboundConfig) error {
	return P.AddInbounds(params)
}

// DeleteInbounds 删除inbound
func DeleteInbounds(inboundNames []string) {
	P.DeleteInbounds(inboundNames)
}

// GetProxies 获取全部outbound (proxy和proxy-group)
func GetProxies() map[string]C.Proxy {
	return T.Proxies()
}

// AddProxies 新增outbound (proxy)
func AddProxies(params []config.ProxyConfig) error {
	var ps []C.Proxy
	for _, param := range params {
		if proxy, err := config.ParseProxy(param); err != nil {
			ps = append(ps, proxy)
		}
	}

	return T.AddOutbounds(ps)
}

// DeleteProxies 删除outbound/outbound-group 需注意:删除outbound不会影响到outbound-group
func DeleteProxies(proxyNames []string) {
	T.DeleteOutbounds(proxyNames)
}

// AddProxyGroups 新增outbound-group
func AddProxyGroups(groups []outboundgroup.GroupCommonOption) error {
	return T.AddOutboundGroups(groups)
}

// GetRules 获取全部规则
func GetRules() []C.Rule {
	return T.Rules()
}

// UpdateRules 更新全部rules
func UpdateRules(params []config.RuleConfig) error {
	rules, err := config.ParseRules(params, T.Proxies())
	if err != nil {
		return err
	}
	T.UpdateRules(rules)
	return nil
}

// StartApi 开启api服务,需go StartApi
func StartApi(addr, secret string) error {
	return route.Start(addr, secret)
}

// StopApi 关闭
func StopApi() {
	route.Shutdown()
}
