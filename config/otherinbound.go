package config

import (
	"encoding/json"
	"errors"

	"github.com/Dreamacro/clash/adapter/otherinbound"
	"gopkg.in/yaml.v3"
)

/*
	implement
		json.Marshaler
		json.Unmarshaler
		yaml.Unmarshaler
*/

type OtherInbound struct {
	Name         string                    `yaml:"name" json:"name"`
	Type         InboundType               `yaml:"type" json:"type"`
	HttpOption   otherinbound.HttpOption   `yaml:"-" json:"-"`
	SocksOption  otherinbound.SocksOption  `yaml:"-" json:"-"`
	DirectOption otherinbound.DirectOption `yaml:"-" json:"-"`
}

type _OtherInbound OtherInbound

func (i *OtherInbound) UnmarshalJSON(b []byte) error {
	err := json.Unmarshal(b, (*_OtherInbound)(i))
	if err != nil {
		return err
	}
	var v any
	switch i.Type {
	case HTTPInbound:
		v = &i.HttpOption
	case SOCKSInbound:
		v = &i.SocksOption
	case DIRECTInbound:
		v = &i.DirectOption
	default:
		return errors.New("unknown inbound type")
	}
	return json.Unmarshal(b, v)
}

func (i *OtherInbound) UnmarshalYAML(value *yaml.Node) error {
	var m map[string]any
	err := value.Decode(&m)
	if err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, i)
}

func (i *OtherInbound) MarshalJSON() ([]byte, error) {
	var v any
	switch i.Type {
	case HTTPInbound:
		v = &i.HttpOption
	case SOCKSInbound:
		v = &i.SocksOption
	case DIRECTInbound:
		v = &i.DirectOption
	default:
		return nil, errors.New("unknown inbound type")
	}
	return MarshalObjects((*_OtherInbound)(i), v)
}

type InboundType uint8

const (
	HTTPInbound InboundType = iota
	SOCKSInbound
	DIRECTInbound

	MaxIType = DIRECTInbound // 最大,新增inboundType时需修改该值
)

var (
	inboundToString = []string{
		"http",
		"socks",
		"direct",
	}
	inboundToInt = map[string]InboundType{
		"http":   HTTPInbound,
		"socks":  SOCKSInbound,
		"direct": DIRECTInbound,
	}
)

func (t InboundType) String() string {
	if t > MaxIType {
		return "unknown"
	}
	return inboundToString[t]
}

func (t InboundType) MarshalJSON() ([]byte, error) {
	if t.String() == "unknown" {
		return nil, errors.New("unknown inbound type")
	}
	return json.Marshal(t.String())
}

func (t *InboundType) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	*t = inboundToInt[s]
	return nil
}
