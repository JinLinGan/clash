package rules

import (
	C "github.com/Dreamacro/clash/constant"
)

type Inbound struct {
	inbound string
	adapter string
}

func (i Inbound) RuleType() C.RuleType {
	return C.RuleTypeInbound
}

func (i Inbound) Match(metadata *C.Metadata) bool {
	return metadata.Inbound == i.inbound
}

func (i Inbound) Adapter() string {
	return i.adapter
}

func (i Inbound) Payload() string {
	return i.inbound
}

func (i Inbound) ShouldResolveIP() bool {
	return false
}

func (i Inbound) ShouldFindProcess() bool {
	return false
}

func NewInbound(inbound string, adapter string) *Inbound {
	return &Inbound{
		inbound: inbound,
		adapter: adapter,
	}
}
