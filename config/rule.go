package config

import (
	"encoding/json"
	"fmt"
	"strings"

	C "github.com/Dreamacro/clash/constant"
	"gopkg.in/yaml.v3"
)

type RuleConfig struct {
	RuleType C.RuleType
	Payload  string   // 与ruleType组合成规则
	Target   string   // outbound name
	Params   []string // 额外参数
}

func (r *RuleConfig) UnmarshalJSON(b []byte) error {
	var line string
	err := json.Unmarshal(b, &line)
	if err != nil {
		return err
	}
	rule := trimArr(strings.Split(line, ","))
	var (
		payload string
		target  string
		params  []string
	)

	switch l := len(rule); {
	case l == 2:
		target = rule[1]
	case l == 3:
		payload = rule[1]
		target = rule[2]
	case l >= 4:
		payload = rule[1]
		target = rule[2]
		params = rule[3:]
	default:
		return fmt.Errorf("rules [%s] error: format invalid", line)
	}

	rule = trimArr(rule)
	params = trimArr(params)

	r.RuleType = r.RuleType.FormatString(rule[0])
	r.Payload = payload
	r.Target = target
	r.Params = params
	return nil
}

func (r *RuleConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *RuleConfig) String() string {
	var rule = []string{r.RuleType.String()}
	if r.Payload != "" {
		rule = append(rule, r.Payload)
	}
	rule = append(rule, r.Target)
	rule = append(rule, r.Params...)
	return strings.Join(rule, ",")
}

func (r *RuleConfig) UnmarshalYAML(node *yaml.Node) error {
	var line string
	err := node.Decode(&line)
	if err != nil {
		return err
	}
	bt, err := json.Marshal(line)
	if err != nil {
		return err
	}
	return json.Unmarshal(bt, r)
}
