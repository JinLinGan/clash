package config

import (
	"encoding/json"
	"errors"

	"github.com/Dreamacro/clash/adapter/outbound"
)

type Proxy struct {
	Name              string                     `yaml:"name" json:"name"`
	Type              ProxyType                  `yaml:"type" json:"type"`
	HttpOption        outbound.HttpOption        `yaml:"-" json:"-"`
	ShadowSocksOption outbound.ShadowSocksOption `yaml:"-" json:"-"`
	SnellOption       outbound.SnellOption       `yaml:"-" json:"-"`
	Socks5Option      outbound.Socks5Option      `yaml:"-" json:"-"`
	TrojanOption      outbound.TrojanOption      `yaml:"-" json:"-"`
	VmessOption       outbound.VmessOption       `yaml:"-" json:"-"`
}

type _Proxy Proxy

func (p *Proxy) MarshalJSON() ([]byte, error) {
	var v any
	switch p.Type {
	case HttpProxy:
		v = &p.HttpOption
	case ShadowSocksProxy, ShadowSocksRProxy:
		v = &p.ShadowSocksOption
	case SnellProxy:
		v = &p.SnellOption
	case Socks5Proxy:
		v = &p.Socks5Option
	case TrojanProxy:
		v = &p.TrojanOption
	case VmessProxy:
		v = &p.VmessOption
	default:
		return nil, errors.New("unknown proxy type")
	}
	return MarshalObjects(p, v)
}

func (p *Proxy) UnmarshalJSON(b []byte) error {
	err := json.Unmarshal(b, (*_Proxy)(p))
	if err != nil {
		return err
	}
	var v any
	switch p.Type {
	case HttpProxy:
		v = &p.HttpOption
	case ShadowSocksProxy, ShadowSocksRProxy:
		v = &p.ShadowSocksOption
	case SnellProxy:
		v = &p.SnellOption
	case Socks5Proxy:
		v = &p.Socks5Option
	case TrojanProxy:
		v = &p.TrojanOption
	case VmessProxy:
		v = &p.VmessOption
	default:
		return errors.New("unknown proxy type")
	}
	return json.Unmarshal(b, v)
}

type ProxyType uint8

const (
	DirectTProxy ProxyType = iota
	HttpProxy
	RejectProxy
	ShadowSocksProxy
	ShadowSocksRProxy
	SnellProxy
	Socks5Proxy
	TrojanProxy
	VmessProxy
)
