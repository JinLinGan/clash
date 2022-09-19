package inbound

import C "github.com/Dreamacro/clash/constant"

type Base struct {
	addr        string
	inboundName string
	inboundType C.InboundType
}

func (b Base) Name() string {
	return b.inboundName
}

func (b Base) Type() C.InboundType {
	return b.inboundType
}

func (b Base) RawAddress() string {
	return b.addr
}

func (b Base) NewMetadata() {

}
