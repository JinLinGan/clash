package outboundgroup

import (
	"errors"
	"fmt"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/adapter/provider"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"
)

var (
	errFormat            = errors.New("format error")
	errType              = errors.New("unsupport type")
	errMissProxy         = errors.New("`use` or `proxies` missing")
	errMissHealthCheck   = errors.New("`url` or `interval` missing")
	errDuplicateProvider = errors.New("duplicate provider name")
)

type GroupCommonOption struct {
	outbound.BasicOption
	Name       string   `json:"name" yaml:"name"`
	Type       string   `json:"type" yaml:"type"`
	Proxies    []string `json:"proxies,omitempty" yaml:"proxies,omitempty"`
	Use        []string `json:"use,omitempty" yaml:"use,omitempty"`
	URL        string   `json:"url,omitempty" yaml:"url,omitempty"`
	Interval   int      `json:"interval,omitempty" yaml:"interval,omitempty"`
	Lazy       bool     `json:"lazy,omitempty" default:"true" yaml:"lazy,omitempty"`
	DisableUDP bool     `json:"disable-udp,omitempty" yaml:"disable-udp,omitempty"`
	Tolerance  int      `json:"tolerance,omitempty" yaml:"tolerance,omitempty"`
	Strategy   string   `json:"strategy,omitempty" yaml:"strategy,omitempty"`
}

func ParseProxyGroup(config GroupCommonOption, proxyMap map[string]C.Proxy, providersMap map[string]types.ProxyProvider) (C.ProxyAdapter, error) {
	if config.Type == "" || config.Name == "" {
		return nil, errFormat
	}

	groupName := config.Name

	providers := []types.ProxyProvider{}

	if len(config.Proxies) == 0 && len(config.Use) == 0 {
		return nil, errMissProxy
	}

	if len(config.Proxies) != 0 {
		ps, err := getProxies(proxyMap, config.Proxies)
		if err != nil {
			return nil, err
		}

		if _, ok := providersMap[groupName]; ok {
			return nil, errDuplicateProvider
		}

		// select don't need health check
		if config.Type == "select" || config.Type == "relay" {
			hc := provider.NewHealthCheck(ps, "", 0, true)
			pd, err := provider.NewCompatibleProvider(groupName, ps, hc)
			if err != nil {
				return nil, err
			}

			providers = append(providers, pd)
			providersMap[groupName] = pd
		} else {
			if config.URL == "" || config.Interval == 0 {
				return nil, errMissHealthCheck
			}

			hc := provider.NewHealthCheck(ps, config.URL, uint(config.Interval), config.Lazy)
			pd, err := provider.NewCompatibleProvider(groupName, ps, hc)
			if err != nil {
				return nil, err
			}

			providers = append(providers, pd)
			providersMap[groupName] = pd
		}
	}

	if len(config.Use) != 0 {
		list, err := getProviders(providersMap, config.Use)
		if err != nil {
			return nil, err
		}
		providers = append(providers, list...)
	}

	var group C.ProxyAdapter
	switch config.Type {
	case "url-test":
		opts := parseURLTestOption(config.Tolerance)
		group = NewURLTest(&config, providers, opts...)
	case "select":
		group = NewSelector(&config, providers)
	case "fallback":
		group = NewFallback(&config, providers)
	case "load-balance":
		strategy := parseStrategy(config.Strategy)
		return NewLoadBalance(&config, providers, strategy)
	case "relay":
		group = NewRelay(&config, providers)
	default:
		return nil, fmt.Errorf("%w: %s", errType, config.Type)
	}

	return group, nil
}

func getProxies(mapping map[string]C.Proxy, list []string) ([]C.Proxy, error) {
	var ps []C.Proxy
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func getProviders(mapping map[string]types.ProxyProvider, list []string) ([]types.ProxyProvider, error) {
	var ps []types.ProxyProvider
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}

		if p.VehicleType() == types.Compatible {
			return nil, fmt.Errorf("proxy group %s can't contains in `use`", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}
