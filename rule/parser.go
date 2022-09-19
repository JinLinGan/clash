package rules

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"
)

func ParseRule(tp C.RuleType, payload, target string, params []string) (C.Rule, error) {
	var (
		parseErr error
		parsed   C.Rule
	)

	switch tp {
	case C.RuleTypeDomain:
		parsed = NewDomain(payload, target)
	case C.RuleTypeDomainSuffix:
		parsed = NewDomainSuffix(payload, target)
	case C.RuleTypeDomainKeyword:
		parsed = NewDomainKeyword(payload, target)
	case C.RuleTypeGEOIP:
		noResolve := HasNoResolve(params)
		parsed = NewGEOIP(payload, target, noResolve)
	case C.RuleTypeIPCIDR:
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewIPCIDR(payload, target, WithIPCIDRNoResolve(noResolve))
	case C.RuleTypeSrcIPCIDR:
		parsed, parseErr = NewIPCIDR(payload, target, WithIPCIDRSourceIP(true), WithIPCIDRNoResolve(true))
	case C.RuleTypeSrcPort:
		parsed, parseErr = NewPort(payload, target, true)
	case C.RuleTypeDstPort:
		parsed, parseErr = NewPort(payload, target, false)
	case C.RuleTypeProcess:
		parsed, parseErr = NewProcess(payload, target, true)
	case C.RuleTypeProcessPath:
		parsed, parseErr = NewProcess(payload, target, false)
	case C.RuleTypeMATCH:
		parsed = NewMatch(target)
	case C.RuleTypeInbound:
		parsed = NewInbound(payload, target)
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	return parsed, parseErr
}
