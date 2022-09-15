package otherinbound

import "github.com/Dreamacro/clash/constant"

type Base struct {
	addr        string
	inboundName string
	inboundType constant.OtherInboundType
}

func (b Base) Name() string {
	return b.inboundName
}

func (b Base) Type() constant.OtherInboundType {
	return b.inboundType
}

func (b Base) RawAddress() string {
	return b.addr
}