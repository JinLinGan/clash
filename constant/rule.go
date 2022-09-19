package constant

// Rule Type
const (
	RuleTypeDomain RuleType = iota
	RuleTypeDomainSuffix
	RuleTypeDomainKeyword
	RuleTypeGEOIP
	RuleTypeIPCIDR
	RuleTypeSrcIPCIDR
	RuleTypeSrcPort
	RuleTypeDstPort
	RuleTypeProcess
	RuleTypeProcessPath
	RuleTypeMATCH
	RuleTypeInbound
)

type RuleType int

func (rt RuleType) String() string {
	switch rt {
	case RuleTypeDomain:
		return "DOMAIN"
	case RuleTypeDomainSuffix:
		return "DOMAIN-SUFFIX"
	case RuleTypeDomainKeyword:
		return "DOMAIN-KEYWORD"
	case RuleTypeGEOIP:
		return "GEOIP"
	case RuleTypeIPCIDR:
		return "IP-CIDR"
	case RuleTypeSrcIPCIDR:
		return "SRC-IP-CIDR"
	case RuleTypeSrcPort:
		return "SRC-PORT"
	case RuleTypeDstPort:
		return "DST-PORT"
	case RuleTypeProcess:
		return "PROCESS-NAME"
	case RuleTypeProcessPath:
		return "PROCESS-PATH"
	case RuleTypeMATCH:
		return "MATCH"
	case RuleTypeInbound:
		return "INBOUND"
	default:
		return "Unknown"
	}
}

func (rt RuleType) FormatString(kind string) RuleType {
	return map[string]RuleType{
		"DOMAIN":         RuleTypeDomain,
		"DOMAIN-SUFFIX":  RuleTypeDomainSuffix,
		"DOMAIN-KEYWORD": RuleTypeDomainKeyword,
		"GEOIP":          RuleTypeGEOIP,
		"IP-CIDR":        RuleTypeIPCIDR,
		"IP-CIDR6":       RuleTypeIPCIDR,
		"SRC-IP-CIDR":    RuleTypeSrcIPCIDR,
		"SRC-PORT":       RuleTypeSrcPort,
		"DST-PORT":       RuleTypeDstPort,
		"PROCESS-NAME":   RuleTypeProcess,
		"PROCESS-PATH":   RuleTypeProcessPath,
		"MATCH":          RuleTypeMATCH,
		"INBOUND":        RuleTypeInbound,
	}[kind]
}

type Rule interface {
	RuleType() RuleType
	Match(metadata *Metadata) bool
	Adapter() string
	Payload() string
	ShouldResolveIP() bool
	ShouldFindProcess() bool
}
