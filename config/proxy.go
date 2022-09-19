package config

import (
	"encoding/json"
	"errors"

	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"

	"gopkg.in/yaml.v3"
)

type ProxyConfig struct {
	Name               string                      `yaml:"name" json:"name"`
	Type               C.ProxyType                 `yaml:"type" json:"type"`
	HttpOption         outbound.HttpOption         `yaml:"-" json:"-"`
	ShadowSocksOption  outbound.ShadowSocksOption  `yaml:"-" json:"-"`
	ShadowSocksROption outbound.ShadowSocksROption `yaml:"-" json:"-"`
	SnellOption        outbound.SnellOption        `yaml:"-" json:"-"`
	Socks5Option       outbound.Socks5Option       `yaml:"-" json:"-"`
	TrojanOption       outbound.TrojanOption       `yaml:"-" json:"-"`
	VmessOption        outbound.VmessOption        `yaml:"-" json:"-"`
}

type _Proxy ProxyConfig

func (p *ProxyConfig) MarshalJSON() ([]byte, error) {
	var v any
	switch p.Type {
	case C.ProxyTypeHttp:
		v = &p.HttpOption
	case C.ProxyTypeShadowSocks:
		v = &p.ShadowSocksOption
	case C.ProxyTypeShadowSocksR:
		v = &p.ShadowSocksROption
	case C.ProxyTypeSnell:
		v = &p.SnellOption
	case C.ProxyTypeSocks5:
		v = &p.Socks5Option
	case C.ProxyTypeTrojan:
		v = &p.TrojanOption
	case C.ProxyTypeVmess:
		v = &p.VmessOption
	default:
		return nil, errors.New("unknown proxy type")
	}
	return MarshalObjects(p, v)
}

func (p *ProxyConfig) UnmarshalJSON(b []byte) error {
	err := json.Unmarshal(b, (*_Proxy)(p))
	if err != nil {
		return err
	}
	var v any
	switch p.Type {
	case C.ProxyTypeHttp:
		v = &p.HttpOption
	case C.ProxyTypeShadowSocks:
		v = &p.ShadowSocksOption
	case C.ProxyTypeShadowSocksR:
		v = &p.ShadowSocksROption
	case C.ProxyTypeSnell:
		v = &p.SnellOption
	case C.ProxyTypeSocks5:
		v = &p.Socks5Option
	case C.ProxyTypeTrojan:
		v = &p.TrojanOption
	case C.ProxyTypeVmess:
		p.VmessOption.HTTPOpts = outbound.HTTPOptions{
			Method: "GET",
			Path:   []string{"/"},
		}
		v = &p.VmessOption
	default:
		return errors.New("unknown proxy type")
	}
	return json.Unmarshal(b, v)
}

func (p *ProxyConfig) UnmarshalYAML(node *yaml.Node) error {
	return UnmarshalYAML(node, p)
}
